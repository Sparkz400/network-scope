// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! The Windows Service Control Manager side of `service`: raw FFI in the style of
//! `attach_parent_console` in `src/lib.rs` (no extra crates). Installing needs an elevated
//! prompt. Windows only; the command-line building and its tests are in `service.rs`.
//!
//! How a service run works: `run` hands the process to `StartServiceCtrlDispatcherW`, the SCM
//! calls `service_main` on a new thread, which registers `control_handler`, reports RUNNING and
//! calls the monitor loop. A STOP or SHUTDOWN control sets the stop flag the loop watches, so the
//! loop ends cleanly (the scan in progress is cancelled and saved as partial), and `service_main`
//! then reports STOPPED. Lifecycle lines and errors go to `service.log` next to the database,
//! because a service has no console.
use std::{
    ffi::c_void,
    path::PathBuf,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicIsize, AtomicU32, Ordering},
    },
};

/// The monitor loop the service runs; the argument is the flag a stop request sets.
pub(super) type Body = Box<dyn FnOnce(Arc<AtomicBool>) -> Result<(), String> + Send>;

#[repr(C)]
struct ServiceStatus {
    service_type: u32,
    current_state: u32,
    controls_accepted: u32,
    win32_exit_code: u32,
    service_specific_exit_code: u32,
    check_point: u32,
    wait_hint: u32,
}
#[repr(C)]
struct ServiceTableEntry {
    name: *const u16,
    proc: Option<unsafe extern "system" fn(u32, *mut *mut u16)>,
}
#[repr(C)]
struct ScAction {
    kind: u32,
    delay_ms: u32,
}
#[repr(C)]
struct FailureActions {
    reset_period_s: u32,
    reboot_msg: *mut u16,
    command: *mut u16,
    actions: u32,
    action_list: *mut ScAction,
}
#[repr(C)]
struct ServiceDescription {
    description: *mut u16,
}
#[repr(C)]
struct DelayedAutoStart {
    delayed: i32,
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenSCManagerW(machine: *const u16, database: *const u16, access: u32) -> isize;
    fn CreateServiceW(
        manager: isize,
        name: *const u16,
        display_name: *const u16,
        access: u32,
        service_type: u32,
        start_type: u32,
        error_control: u32,
        binary_path: *const u16,
        load_order_group: *const u16,
        tag_id: *mut u32,
        dependencies: *const u16,
        start_name: *const u16,
        password: *const u16,
    ) -> isize;
    fn OpenServiceW(manager: isize, name: *const u16, access: u32) -> isize;
    fn DeleteService(service: isize) -> i32;
    fn ControlService(service: isize, control: u32, status: *mut ServiceStatus) -> i32;
    fn QueryServiceStatus(service: isize, status: *mut ServiceStatus) -> i32;
    fn ChangeServiceConfig2W(service: isize, level: u32, info: *mut c_void) -> i32;
    fn CloseServiceHandle(handle: isize) -> i32;
    fn StartServiceCtrlDispatcherW(table: *const ServiceTableEntry) -> i32;
    fn RegisterServiceCtrlHandlerExW(
        name: *const u16,
        handler: unsafe extern "system" fn(u32, u32, *mut c_void, *mut c_void) -> u32,
        context: *mut c_void,
    ) -> isize;
    fn SetServiceStatus(handle: isize, status: *const ServiceStatus) -> i32;
}
unsafe extern "system" {
    fn GetLastError() -> u32;
}

const SC_MANAGER_CONNECT: u32 = 0x1;
const SC_MANAGER_CREATE_SERVICE: u32 = 0x2;
const SERVICE_QUERY_STATUS: u32 = 0x4;
const SERVICE_STOP: u32 = 0x20;
const SERVICE_CHANGE_CONFIG: u32 = 0x2;
const DELETE: u32 = 0x10000;
const SERVICE_ALL_ACCESS: u32 = 0xF01FF;
const SERVICE_WIN32_OWN_PROCESS: u32 = 0x10;
const SERVICE_AUTO_START: u32 = 2;
const SERVICE_ERROR_NORMAL: u32 = 1;
const SERVICE_CONFIG_DESCRIPTION: u32 = 1;
const SERVICE_CONFIG_FAILURE_ACTIONS: u32 = 2;
const SERVICE_CONFIG_DELAYED_AUTO_START_INFO: u32 = 3;
const SERVICE_CONFIG_FAILURE_ACTIONS_FLAG: u32 = 4;
const SC_ACTION_RESTART: u32 = 1;
const SERVICE_CONTROL_STOP: u32 = 1;
const SERVICE_CONTROL_INTERROGATE: u32 = 4;
const SERVICE_CONTROL_SHUTDOWN: u32 = 5;
const SERVICE_STOPPED: u32 = 1;
const SERVICE_START_PENDING: u32 = 2;
const SERVICE_STOP_PENDING: u32 = 3;
const SERVICE_RUNNING: u32 = 4;
const SERVICE_ACCEPT_STOP: u32 = 1;
const SERVICE_ACCEPT_SHUTDOWN: u32 = 4;
const NO_ERROR: u32 = 0;
const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_SERVICE_DOES_NOT_EXIST: u32 = 1060;
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: u32 = 1063;
const ERROR_SERVICE_EXISTS: u32 = 1073;
const ERROR_SERVICE_SPECIFIC_ERROR: u32 = 1066;

const DISPLAY_NAME: &str = "Network Scope Monitor";
const DESCRIPTION: &str = "Repeats network scans, compares them with the inventory and raises alerts for changes (Network Scope).";

/// A null-terminated UTF-16 string.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn last_error() -> u32 {
    unsafe { GetLastError() }
}
fn describe(action: &str, code: u32) -> String {
    let hint = match code {
        ERROR_ACCESS_DENIED => ": run this from an elevated (administrator) prompt",
        ERROR_SERVICE_EXISTS => {
            ": a service with this name exists; use --service-name or `service uninstall`"
        }
        ERROR_SERVICE_DOES_NOT_EXIST => ": no service with this name is installed",
        _ => "",
    };
    format!("{action} failed (Windows error {code}){hint}")
}

/// Closes a service handle when it goes out of scope.
struct Handle(isize);
impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe { CloseServiceHandle(self.0) };
        }
    }
}

pub(super) fn install(name: &str, command_line: &str) -> Result<(), String> {
    let manager = Handle(unsafe {
        OpenSCManagerW(
            std::ptr::null(),
            std::ptr::null(),
            SC_MANAGER_CREATE_SERVICE,
        )
    });
    if manager.0 == 0 {
        return Err(describe("Opening the service manager", last_error()));
    }
    let (name_w, display_w, path_w) = (wide(name), wide(DISPLAY_NAME), wide(command_line));
    // Default account (LocalSystem): the inventory under %ProgramData% and capture drivers work
    // without further access rights. `sc config NAME obj= "NT AUTHORITY\LocalService"` narrows it.
    let service = Handle(unsafe {
        CreateServiceW(
            manager.0,
            name_w.as_ptr(),
            display_w.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            path_w.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        )
    });
    if service.0 == 0 {
        return Err(describe("Creating the service", last_error()));
    }
    // Nice to have; a failure here leaves a working service.
    let mut description = wide(DESCRIPTION);
    let mut info = ServiceDescription {
        description: description.as_mut_ptr(),
    };
    let mut delayed = DelayedAutoStart { delayed: 1 };
    let mut actions = [
        ScAction {
            kind: SC_ACTION_RESTART,
            delay_ms: 60_000,
        },
        ScAction {
            kind: SC_ACTION_RESTART,
            delay_ms: 60_000,
        },
        ScAction {
            kind: SC_ACTION_RESTART,
            delay_ms: 60_000,
        },
    ];
    // SERVICE_FAILURE_ACTIONS_FLAG: one BOOL, fFailureActionsOnNonCrashFailures.
    let mut on_error_exit: i32 = 1;
    let mut failure = FailureActions {
        reset_period_s: 86_400,
        reboot_msg: std::ptr::null_mut(),
        command: std::ptr::null_mut(),
        actions: actions.len() as u32,
        action_list: actions.as_mut_ptr(),
    };
    unsafe {
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_DESCRIPTION,
            (&raw mut info).cast(),
        );
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
            (&raw mut delayed).cast(),
        );
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            (&raw mut failure).cast(),
        );
        // Without this flag the actions above only follow a crash. The monitor that gives up
        // (several cycles in a row failed) stops with an error code, and must be restarted too.
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
            (&raw mut on_error_exit).cast(),
        );
    }
    Ok(())
}

pub(super) fn uninstall(name: &str) -> Result<(), String> {
    let manager =
        Handle(unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) });
    if manager.0 == 0 {
        return Err(describe("Opening the service manager", last_error()));
    }
    let name_w = wide(name);
    let service = Handle(unsafe {
        OpenServiceW(
            manager.0,
            name_w.as_ptr(),
            DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG,
        )
    });
    if service.0 == 0 {
        return Err(describe("Opening the service", last_error()));
    }
    // Ask a running service to stop (it ends its loop cleanly) and give it a few seconds.
    let mut status = ServiceStatus {
        service_type: 0,
        current_state: 0,
        controls_accepted: 0,
        win32_exit_code: 0,
        service_specific_exit_code: 0,
        check_point: 0,
        wait_hint: 0,
    };
    unsafe {
        if ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) != 0 {
            for _ in 0..40 {
                if QueryServiceStatus(service.0, &mut status) == 0
                    || status.current_state == SERVICE_STOPPED
                {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        }
    }
    if unsafe { DeleteService(service.0) } == 0 {
        return Err(describe("Removing the service", last_error()));
    }
    Ok(())
}

// ---- Running as a service ---------------------------------------------------------------

struct Job {
    name: String,
    log: PathBuf,
    body: Body,
}
static JOB: Mutex<Option<Job>> = Mutex::new(None);
static STOP: OnceLock<Arc<AtomicBool>> = OnceLock::new();
static STATUS_HANDLE: AtomicIsize = AtomicIsize::new(0);
static STATE: AtomicU32 = AtomicU32::new(SERVICE_START_PENDING);

/// Hands the process to the Service Control Manager. Returns when the service has stopped.
/// Started from a shell (not by the manager) it fails at once with an explanation.
pub(super) fn run(name: &str, log: PathBuf, body: Body) -> Result<(), String> {
    *JOB.lock().unwrap_or_else(|e| e.into_inner()) = Some(Job {
        name: name.to_string(),
        log,
        body,
    });
    let name_w = wide(name);
    let table = [
        ServiceTableEntry {
            name: name_w.as_ptr(),
            proc: Some(service_main),
        },
        ServiceTableEntry {
            name: std::ptr::null(),
            proc: None,
        },
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        let code = last_error();
        return Err(if code == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT {
            "`service run` is started by the Windows service manager (see `service install`); to run the monitor in a terminal use `monitor`".into()
        } else {
            describe("Connecting to the service manager", code)
        });
    }
    Ok(())
}

fn report(state: u32, accepted: u32, exit_code: u32, specific: u32, checkpoint: u32, hint_ms: u32) {
    STATE.store(state, Ordering::SeqCst);
    let status = ServiceStatus {
        service_type: SERVICE_WIN32_OWN_PROCESS,
        current_state: state,
        controls_accepted: accepted,
        win32_exit_code: exit_code,
        service_specific_exit_code: specific,
        check_point: checkpoint,
        wait_hint: hint_ms,
    };
    let handle = STATUS_HANDLE.load(Ordering::SeqCst);
    if handle != 0 {
        unsafe { SetServiceStatus(handle, &status) };
    }
}

fn log_line(path: &std::path::Path, text: &str) {
    use std::io::Write;
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "{seconds} {text}");
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let Some(job) = JOB.lock().unwrap_or_else(|e| e.into_inner()).take() else {
        return;
    };
    let name_w = wide(&job.name);
    let handle = unsafe {
        RegisterServiceCtrlHandlerExW(name_w.as_ptr(), control_handler, std::ptr::null_mut())
    };
    if handle == 0 {
        log_line(
            &job.log,
            &describe("Registering the control handler", last_error()),
        );
        return;
    }
    STATUS_HANDLE.store(handle, Ordering::SeqCst);
    let stop = Arc::new(AtomicBool::new(false));
    let _ = STOP.set(stop.clone());
    report(SERVICE_START_PENDING, 0, NO_ERROR, 0, 1, 10_000);
    log_line(&job.log, "service started");
    report(
        SERVICE_RUNNING,
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
        NO_ERROR,
        0,
        0,
        0,
    );
    // A panic in the monitor must not leave the service claiming to run.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (job.body)(stop)))
        .unwrap_or_else(|_| Err("the monitor stopped unexpectedly".into()));
    match result {
        Ok(()) => {
            log_line(&job.log, "service stopped");
            report(SERVICE_STOPPED, 0, NO_ERROR, 0, 0, 0);
        }
        Err(e) => {
            log_line(&job.log, &format!("service failed: {e}"));
            report(SERVICE_STOPPED, 0, ERROR_SERVICE_SPECIFIC_ERROR, 1, 0, 0);
        }
    }
}

unsafe extern "system" fn control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            if let Some(stop) = STOP.get() {
                stop.store(true, Ordering::SeqCst);
            }
            report(SERVICE_STOP_PENDING, 0, NO_ERROR, 0, 1, 30_000);
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => {
            let state = STATE.load(Ordering::SeqCst);
            let accepted = if state == SERVICE_RUNNING {
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
            } else {
                0
            };
            report(state, accepted, NO_ERROR, 0, 0, 0);
            NO_ERROR
        }
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_structures_have_the_documented_sizes() {
        assert_eq!(std::mem::size_of::<ServiceStatus>(), 28, "SERVICE_STATUS");
        assert_eq!(std::mem::size_of::<ScAction>(), 8, "SC_ACTION");
        assert_eq!(
            std::mem::size_of::<FailureActions>(),
            if cfg!(target_pointer_width = "64") {
                40
            } else {
                20
            },
            "SERVICE_FAILURE_ACTIONSW"
        );
        assert_eq!(
            std::mem::size_of::<ServiceTableEntry>(),
            2 * std::mem::size_of::<usize>()
        );
    }

    #[test]
    fn strings_are_null_terminated_utf16() {
        assert_eq!(wide("ab"), [97, 98, 0]);
        assert_eq!(wide(""), [0]);
        assert_eq!(wide("ä"), [0xE4, 0]);
    }

    #[test]
    fn errors_name_what_to_do() {
        assert!(describe("Creating the service", ERROR_ACCESS_DENIED).contains("elevated"));
        assert!(describe("Creating the service", ERROR_SERVICE_EXISTS).contains("--service-name"));
        assert!(describe("x", 9999).ends_with("(Windows error 9999)"));
    }

    /// Started from a shell, `service run` is refused by the Service Control Manager at once
    /// instead of hanging, and the monitor body never runs.
    #[test]
    fn running_outside_the_service_manager_fails_with_an_explanation() {
        let ran = Arc::new(AtomicBool::new(false));
        let flag = ran.clone();
        let log = std::env::temp_dir().join(format!("ns-svc-{}.log", std::process::id()));
        let err = run(
            "NetworkScopeTest",
            log,
            Box::new(move |_| {
                flag.store(true, Ordering::SeqCst);
                Ok(())
            }),
        )
        .unwrap_err();
        assert!(
            err.contains("service manager") && err.contains("monitor"),
            "{err}"
        );
        assert!(!ran.load(Ordering::SeqCst));
    }

    #[test]
    fn the_log_gets_one_timestamped_line_per_event() {
        let path = std::env::temp_dir()
            .join(format!("ns-svc-log-{}", std::process::id()))
            .join("service.log");
        log_line(&path, "service started");
        log_line(&path, "service stopped");
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "{text}");
        assert!(lines[0].ends_with(" service started") && lines[1].ends_with(" service stopped"));
        assert!(lines[0].split(' ').next().unwrap().parse::<u64>().is_ok());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
