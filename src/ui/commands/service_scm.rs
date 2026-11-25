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
//!
//! The service runs as LocalSystem, so `service install` first makes sure that other users cannot
//! steer what it writes: see `prepare_data_dir`.
use std::{
    ffi::c_void,
    os::windows::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
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
#[link(name = "advapi32")]
unsafe extern "system" {
    fn GetNamedSecurityInfoW(
        name: *const u16,
        object_type: u32,
        info: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        descriptor: *mut *mut c_void,
    ) -> u32;
    fn SetNamedSecurityInfoW(
        name: *const u16,
        object_type: u32,
        info: u32,
        owner: *mut c_void,
        group: *mut c_void,
        dacl: *mut c_void,
        sacl: *mut c_void,
    ) -> u32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl: *const u16,
        revision: u32,
        descriptor: *mut *mut c_void,
        size: *mut u32,
    ) -> i32;
    fn GetSecurityDescriptorDacl(
        descriptor: *mut c_void,
        present: *mut i32,
        dacl: *mut *mut c_void,
        defaulted: *mut i32,
    ) -> i32;
    fn GetAce(acl: *mut c_void, index: u32, ace: *mut *mut c_void) -> i32;
    fn ConvertSidToStringSidW(sid: *mut c_void, text: *mut *mut u16) -> i32;
}
unsafe extern "system" {
    fn GetLastError() -> u32;
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
    fn CreateDirectoryW(path: *const u16, attributes: *const SecurityAttributes) -> i32;
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

// ---- Who may change what the service uses ----------------------------------------------

#[repr(C)]
struct SecurityAttributes {
    length: u32,
    descriptor: *mut c_void,
    inherit: i32,
}
/// The fixed head of an ACL (`ACL`) and of an access-allowed entry (`ACCESS_ALLOWED_ACE`, whose
/// SID follows at offset 8).
#[repr(C)]
struct AclHeader {
    revision: u8,
    sbz1: u8,
    size: u16,
    count: u16,
    sbz2: u16,
}
#[repr(C)]
struct AceHeader {
    kind: u8,
    flags: u8,
    size: u16,
    mask: u32,
}

const SE_FILE_OBJECT: u32 = 1;
const OWNER_SECURITY_INFORMATION: u32 = 0x1;
const DACL_SECURITY_INFORMATION: u32 = 0x4;
const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;
const SDDL_REVISION_1: u32 = 1;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const INHERIT_ONLY_ACE: u8 = 0x8;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// The access of the service's data folder: full control for SYSTEM and Administrators, nothing
/// inherited from `%ProgramData%` (where every user may create files and folders), inherited by
/// everything below it. Other users get no access, not even to read the inventory.
const DATA_DIR_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
/// Owners trusted in the data folder: SYSTEM, LocalService, NetworkService and Administrators.
const TRUSTED_OWNERS: [&str; 4] = ["S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-32-544"];
/// Everyone, INTERACTIVE, Authenticated Users and Users: groups every local account is in.
const BROAD_GROUPS: [&str; 4] = ["S-1-1-0", "S-1-5-4", "S-1-5-11", "S-1-5-32-545"];
/// Rights that let the holder change a file or put files into a folder: write data or add a
/// file, append or add a folder, delete a child, delete, change the permissions or the owner,
/// generic all and generic write.
const WRITE_RIGHTS: u32 =
    0x2 | 0x4 | 0x40 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x1000_0000 | 0x4000_0000;

/// A null-terminated UTF-16 path.
fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain([0]).collect()
}

/// Memory a security function allocated, freed when it goes out of scope.
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

/// The owner and the access-allowed entries (SID, rights, entry flags) of a file or folder.
/// `allowed` is `None` when there is no DACL at all, which gives everyone every right.
struct Security {
    owner: String,
    allowed: Option<Vec<(String, u32, u8)>>,
}

fn sid_text(sid: *mut c_void) -> Result<String, String> {
    let mut text: *mut u16 = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(describe("Reading a security identifier", last_error()));
    }
    let _free = Local(text.cast());
    let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
    Ok(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(text, len)
    }))
}

fn security(path: &Path) -> Result<Security, String> {
    let name = wide_path(path);
    let (mut owner, mut dacl, mut descriptor) = (
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    );
    let code = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if code != 0 {
        return Err(format!(
            "{}: {}",
            path.display(),
            describe("Reading the access rights", code)
        ));
    }
    let _free = Local(descriptor);
    let allowed = if dacl.is_null() {
        None
    } else {
        let count = unsafe { (*dacl.cast::<AclHeader>()).count };
        let mut entries = vec![];
        for i in 0..u32::from(count) {
            let mut ace = std::ptr::null_mut();
            if unsafe { GetAce(dacl, i, &mut ace) } == 0 {
                return Err(describe("Reading an access entry", last_error()));
            }
            let head = unsafe { &*ace.cast::<AceHeader>() };
            if head.kind == ACCESS_ALLOWED_ACE_TYPE {
                let sid = unsafe { ace.cast::<u8>().add(8) }.cast();
                entries.push((sid_text(sid)?, head.mask, head.flags));
            }
        }
        Some(entries)
    };
    Ok(Security {
        owner: sid_text(owner)?,
        allowed,
    })
}

/// Whether every local user may change it: an entry that applies to the object itself (not
/// only to what is created below it) gives one of [`BROAD_GROUPS`] a right in [`WRITE_RIGHTS`].
fn open_to_users(s: &Security) -> bool {
    s.allowed.as_ref().is_none_or(|entries| {
        entries.iter().any(|(sid, mask, flags)| {
            flags & INHERIT_ONLY_ACE == 0
                && mask & WRITE_RIGHTS != 0
                && BROAD_GROUPS.contains(&sid.as_str())
        })
    })
}

/// A security descriptor from its SDDL text.
fn descriptor(sddl: &str) -> Result<Local, String> {
    let text = wide(sddl);
    let mut sd = std::ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(describe("Building the access rights", last_error()));
    }
    Ok(Local(sd))
}

/// Replaces the DACL of `path` with the one in `sddl`, protected from inheritance; files and
/// folders below get its inheritable entries.
fn set_dacl(path: &Path, sddl: &str) -> Result<(), String> {
    let sd = descriptor(sddl)?;
    let (mut present, mut defaulted, mut dacl) = (0, 0, std::ptr::null_mut());
    if unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted) } == 0 {
        return Err(describe("Building the access rights", last_error()));
    }
    let name = wide_path(path);
    let code = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null_mut(),
        )
    };
    if code != 0 {
        return Err(format!(
            "{}: {}",
            path.display(),
            describe("Setting the access rights", code)
        ));
    }
    Ok(())
}

/// Refuses a link (reparse point) anywhere in the tree, and an entry whose owner is not in
/// `owners`: a link sends the service's writes elsewhere, and an owner can always change the
/// permissions of what it owns.
fn check_tree(path: &Path, owners: &[&str]) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(format!(
            "{} is a link (reparse point), through which the service would write elsewhere; remove it and install again",
            path.display()
        ));
    }
    let owner = security(path)?.owner;
    if !owners.contains(&owner.as_str()) {
        return Err(format!(
            "{} is owned by {owner}, not by SYSTEM or Administrators, so that account could change what the service (running as SYSTEM) reads and writes; remove it or make Administrators the owner (takeown /a /r /d y /f \"{}\") and install again",
            path.display(),
            path.display()
        ));
    }
    if meta.is_dir() {
        for entry in std::fs::read_dir(path).map_err(|e| format!("{}: {e}", path.display()))? {
            let entry = entry.map_err(|e| format!("{}: {e}", path.display()))?;
            check_tree(&entry.path(), owners)?;
        }
    }
    Ok(())
}

/// Prepares the folder of the service's inventory, where `service.log` and the default
/// `alert-scripts` folder are too. A missing folder is created with [`DATA_DIR_SDDL`]. An
/// existing one must hold no links and nothing owned by other accounts; the default folder
/// (`protect`: `%ProgramData%\NetworkScope`, made by earlier versions with the inherited access)
/// then gets [`DATA_DIR_SDDL`], while a folder named with `--db` keeps its access (it may be any
/// folder) but must not be writable by every user.
pub(super) fn prepare_data_dir(dir: &Path, protect: bool) -> Result<(), String> {
    prepare_dir(dir, protect, &TRUSTED_OWNERS)
}

fn prepare_dir(dir: &Path, protect: bool, owners: &[&str]) -> Result<(), String> {
    if std::fs::symlink_metadata(dir).is_err() {
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        let sd = descriptor(DATA_DIR_SDDL)?;
        let attributes = SecurityAttributes {
            length: std::mem::size_of::<SecurityAttributes>() as u32,
            descriptor: sd.0,
            inherit: 0,
        };
        let name = wide_path(dir);
        // Created with its access in one step: a user who makes the folder first makes this fail
        // instead of owning the service's folder.
        if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0 {
            return Err(format!(
                "{}: {}",
                dir.display(),
                describe("Creating the folder", last_error())
            ));
        }
        return Ok(());
    }
    check_tree(dir, owners)?;
    if protect {
        return set_dacl(dir, DATA_DIR_SDDL);
    }
    if open_to_users(&security(dir)?) {
        return Err(format!(
            "{}: every local user may write to this folder, and the service runs as SYSTEM; use a folder only administrators can write to, or leave out --db (the default is %ProgramData%\\NetworkScope)",
            dir.display()
        ));
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

    fn temp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ns-svc-acl-{tag}-{}", std::process::id()));
        if d.exists() {
            let _ = set_dacl(&d, "D:(A;OICI;FA;;;WD)");
            let _ = std::fs::remove_dir_all(&d);
        }
        std::fs::create_dir_all(&d).unwrap();
        d
    }
    /// Gives the temp folder back to everyone (its owner may always change its access), so the
    /// test can delete it after locking it down.
    fn remove(d: &Path) {
        set_dacl(d, "D:(A;OICI;FA;;;WD)").unwrap();
        let _ = std::fs::remove_dir_all(d);
    }

    /// The data folder is created for SYSTEM and Administrators only; the checks refuse links and
    /// foreign owners. Runs without administrator rights on a temp folder: the test accepts the
    /// test user as an owner, since it owns what it creates.
    #[test]
    fn the_data_folder_is_created_for_system_and_administrators_only() {
        let base = temp("data");
        let me = security(&base).unwrap().owner;
        let owners = [me.as_str(), "S-1-5-18", "S-1-5-32-544"];
        let dir = base.join("NetworkScope");
        prepare_dir(&dir, true, &owners).unwrap();
        let s = security(&dir).unwrap();
        let entries = s.allowed.as_ref().unwrap();
        let mut sids: Vec<&str> = entries.iter().map(|(sid, _, _)| sid.as_str()).collect();
        sids.sort();
        assert_eq!(sids, ["S-1-5-18", "S-1-5-32-544"], "{entries:?}");
        // Not inherited (INHERITED_ACE 0x10), passed on to files and folders (OI|CI 0x3).
        assert!(
            entries
                .iter()
                .all(|(_, _, f)| f & 0x10 == 0 && f & 0x3 == 0x3)
        );
        assert!(!open_to_users(&s));
        // An existing folder with wider access (as made by an older version) is checked and
        // locked down again. The test user needs access to list it; an elevated install has it
        // through Administrators.
        set_dacl(
            &dir,
            &format!("D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{me})(A;CI;0x116;;;BU)"),
        )
        .unwrap();
        assert!(open_to_users(&security(&dir).unwrap()));
        prepare_dir(&dir, true, &owners).unwrap();
        assert!(!open_to_users(&security(&dir).unwrap()));
        // Another owner is refused (here: the test user, when not trusted).
        let err = prepare_dir(&dir, true, &["S-1-5-18"]).unwrap_err();
        assert!(err.contains("owned by") && err.contains("takeown"), "{err}");
        remove(&dir);
        remove(&base);
    }

    #[test]
    fn links_in_the_data_folder_are_refused() {
        let base = temp("link");
        let me = security(&base).unwrap().owner;
        let owners = [me.as_str()];
        let (dir, elsewhere) = (base.join("data"), base.join("elsewhere"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&elsewhere).unwrap();
        let junction = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(dir.join("alert-scripts"))
            .arg(&elsewhere)
            .output()
            .is_ok_and(|o| o.status.success());
        if junction {
            let err = prepare_dir(&dir, false, &owners).unwrap_err();
            assert!(err.contains("reparse point"), "{err}");
            // The data folder itself as a link.
            let err = prepare_dir(&dir.join("alert-scripts"), false, &owners).unwrap_err();
            assert!(err.contains("reparse point"), "{err}");
        } else {
            eprintln!("skipped the junction part: mklink /J failed");
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The write-rights check that guards an existing `--db` folder: a right for one of the
    /// groups every user is in counts, read rights and entries for what is created below do not.
    #[test]
    fn folders_writable_by_every_user_are_recognised() {
        let base = temp("open");
        let me = security(&base).unwrap().owner;
        for (sddl, open) in [
            ("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", false),
            ("D:P(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)", false),
            ("D:P(A;OICI;FA;;;SY)(A;OICIIO;FA;;;AU)", false),
            // %ProgramData%: Users may create files and folders.
            ("D:P(A;OICI;FA;;;SY)(A;CI;0x116;;;BU)", true),
            ("D:P(A;OICI;0x1301bf;;;AU)", true),
            ("D:P(A;;FA;;;WD)", true),
            ("D:P(A;;0x10000;;;IU)", true),
        ] {
            // The test user keeps access to list the folder.
            let sddl = format!("{sddl}(A;OICI;FA;;;{me})");
            set_dacl(&base, &sddl).unwrap();
            assert_eq!(open_to_users(&security(&base).unwrap()), open, "{sddl}");
            let result = prepare_dir(&base, false, &[me.as_str()]);
            assert_eq!(result.is_err(), open, "{sddl}: {result:?}");
        }
        remove(&base);
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
