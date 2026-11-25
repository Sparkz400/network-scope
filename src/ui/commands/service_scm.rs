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
//! steer what it runs or writes: see `check_not_writable` and `prepare_data_dir`.
use std::{
    ffi::c_void,
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
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
    fn SetSecurityInfo(
        handle: *mut c_void,
        object_type: u32,
        info: u32,
        owner: *mut c_void,
        group: *mut c_void,
        dacl: *mut c_void,
        sacl: *mut c_void,
    ) -> u32;
    fn GetAce(acl: *mut c_void, index: u32, ace: *mut *mut c_void) -> i32;
    fn ConvertSidToStringSidW(sid: *mut c_void, text: *mut *mut u16) -> i32;
}
unsafe extern "system" {
    fn GetLastError() -> u32;
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
    fn CreateDirectoryW(path: *const u16, attributes: *const SecurityAttributes) -> i32;
    fn GetDriveTypeW(root: *const u16) -> u32;
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
/// Access-denied entries (plain, object, callback, callback object): the only kinds that may be
/// left out, since they can only take rights away.
const DENY_ACE_TYPES: [u8; 4] = [1, 6, 10, 12];
/// Stands in for the SID of an allow entry of a kind that is not parsed.
const UNKNOWN_ACE: &str = "an access entry of type ";
const DRIVE_FIXED: u32 = 3;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const READ_CONTROL: u32 = 0x2_0000;
const WRITE_DAC: u32 = 0x4_0000;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
const FILE_SHARE_READ: u32 = 0x1;
const FILE_SHARE_WRITE: u32 = 0x2;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x20_0000;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x200_0000;

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
/// The rights on a folder further up that let the holder rename or replace what is in it:
/// delete a child, delete, change the permissions or the owner, generic all. Adding files or
/// folders is not among them (every user may create a folder in the root of a drive).
const REPLACE_RIGHTS: u32 = 0x40 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x1000_0000;
/// SYSTEM, Administrators and TrustedInstaller: the accounts that may own or change what a
/// service runs.
const ADMIN_SIDS: [&str; 3] = [
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];

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
    // A null DACL (no list at all) gives everyone every right.
    let allowed = match unsafe { dacl.cast::<AclHeader>().as_ref() } {
        None => None,
        Some(acl) => {
            let count = acl.count;
            let mut entries = vec![];
            for i in 0..u32::from(count) {
                let mut ace = std::ptr::null_mut();
                if unsafe { GetAce(dacl, i, &mut ace) } == 0 {
                    return Err(describe("Reading an access entry", last_error()));
                }
                let Some(head) = (unsafe { ace.cast::<AceHeader>().as_ref() }) else {
                    return Err(describe("Reading an access entry", last_error()));
                };
                if head.kind == ACCESS_ALLOWED_ACE_TYPE {
                    let sid = unsafe { ace.cast::<u8>().add(8) }.cast();
                    entries.push((sid_text(sid)?, head.mask, head.flags));
                } else if !DENY_ACE_TYPES.contains(&head.kind) {
                    // Not parsed (callback, object, ...): counted as every right for anyone.
                    entries.push((format!("{UNKNOWN_ACE}{}", head.kind), u32::MAX, head.flags));
                }
            }
            Some(entries)
        }
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
                && (BROAD_GROUPS.contains(&sid.as_str()) || sid.starts_with(UNKNOWN_ACE))
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

/// The DACL inside a descriptor from [`descriptor`] (valid as long as the descriptor is).
fn dacl_of(sd: &Local) -> Result<*mut c_void, String> {
    let (mut present, mut defaulted, mut dacl) = (0, 0, std::ptr::null_mut());
    if unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted) } == 0 {
        return Err(describe("Building the access rights", last_error()));
    }
    Ok(dacl)
}

/// Replaces the DACL of `path` with the one in `sddl`, protected from inheritance; files and
/// folders below get its inheritable entries.
fn set_dacl(path: &Path, sddl: &str) -> Result<(), String> {
    let sd = descriptor(sddl)?;
    let name = wide_path(path);
    let code = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl_of(&sd)?,
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
/// `alert-scripts` folder are too. A missing folder is created with [`DATA_DIR_SDDL`]. The
/// default folder (`protect`: `%ProgramData%\NetworkScope`, made by earlier versions with the
/// inherited access) gets [`DATA_DIR_SDDL`] first, a folder named with `--db` keeps its access (it
/// may be any folder) but must not be writable by every user; then neither may hold links or
/// anything owned by other accounts.
pub(super) fn prepare_data_dir(dir: &Path, protect: bool) -> Result<(), String> {
    prepare_dir(dir, protect.then_some(DATA_DIR_SDDL), &TRUSTED_OWNERS)
}

/// The account other than `admins` that owns `s` or holds one of `rights` on it (entries only
/// for what is created below do not count).
fn other_writer(s: &Security, rights: u32, admins: &[&str]) -> Option<String> {
    if !admins.contains(&s.owner.as_str()) {
        return Some(format!("its owner {}", s.owner));
    }
    let Some(entries) = &s.allowed else {
        return Some("everyone (it has no access list)".into());
    };
    entries
        .iter()
        .find(|(sid, mask, flags)| {
            flags & INHERIT_ONLY_ACE == 0 && mask & rights != 0 && !admins.contains(&sid.as_str())
        })
        .map(|(sid, _, _)| sid.clone())
}

/// Refuses files the service runs or obeys (the program, scripts, probes, the scope file) unless
/// only SYSTEM, Administrators and TrustedInstaller own or may change them and the folder they
/// are in (another account could replace them, or put a DLL next to the program), no link sits
/// anywhere on the path, and no other account may rename or replace a folder further up: the
/// service would run as SYSTEM what is there.
pub(super) fn check_not_writable(paths: &[PathBuf]) -> Result<(), String> {
    check_paths(paths, &ADMIN_SIDS)
}

fn check_paths(paths: &[PathBuf], admins: &[&str]) -> Result<(), String> {
    let refuse = |p: &Path, why: String| {
        format!(
            "{}: {why}, and the service would run as SYSTEM what is there. Copy the program (and the files the service reads) to a folder only administrators can change, such as C:\\Program Files\\Network Scope, and install the service from there",
            p.display()
        )
    };
    // Trailing separators and case do not make another path.
    let norm = |s: &str| s.trim_end_matches('\\').to_lowercase();
    for path in paths {
        let absolute = std::path::absolute(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let canonical =
            std::fs::canonicalize(&absolute).map_err(|e| format!("{}: {e}", path.display()))?;
        let canonical = canonical.to_str().unwrap_or_default();
        // On a local fixed disk, not a network share or removable media other machines or
        // users could change behind the access lists.
        let local = canonical.strip_prefix(r"\\?\").unwrap_or(canonical);
        let root = local.get(..3).filter(|r| &r.as_bytes()[1..] == b":\\");
        let fixed = !canonical.starts_with(r"\\?\UNC\")
            && root.is_some_and(|r| unsafe { GetDriveTypeW(wide(r).as_ptr()) } == DRIVE_FIXED);
        if !fixed {
            return Err(refuse(
                &absolute,
                "this is not on a local fixed disk".into(),
            ));
        }
        // What is checked below is what the service will open: the path as given must be the
        // path the system resolves it to (no link, no short 8.3 name on the way).
        if norm(local) != norm(&absolute.to_string_lossy()) {
            return Err(refuse(
                &absolute,
                format!("this goes through a link or a short name to {local}; give that path"),
            ));
        }
        for (i, p) in absolute.ancestors().enumerate() {
            let meta = std::fs::symlink_metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
            if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(refuse(p, "this is a link (reparse point)".into()));
            }
            // The file and its folder: no other account may change either; further up: none
            // may rename or replace a folder.
            let rights = if i < 2 { WRITE_RIGHTS } else { REPLACE_RIGHTS };
            if let Some(who) = other_writer(&security(p)?, rights, admins) {
                return Err(refuse(p, format!("{who} may change this")));
            }
        }
    }
    Ok(())
}

/// `protect`: the access to give an existing folder (`None`: keep its access). A missing folder
/// is created with that access, or [`DATA_DIR_SDDL`].
fn prepare_dir(dir: &Path, protect: Option<&str>, owners: &[&str]) -> Result<(), String> {
    if std::fs::symlink_metadata(dir).is_err() {
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        let sd = descriptor(protect.unwrap_or(DATA_DIR_SDDL))?;
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
    // The folder itself, opened without following a link and without letting it be renamed or
    // deleted while it is open: what is locked and checked below is this folder.
    let mut access = READ_CONTROL | FILE_READ_ATTRIBUTES;
    if protect.is_some() {
        access |= WRITE_DAC;
    }
    let folder = std::fs::OpenOptions::new()
        .access_mode(access)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    let meta = folder
        .metadata()
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !meta.is_dir() {
        return Err(format!(
            "{} is not a plain folder (a link or a file); remove it and install again",
            dir.display()
        ));
    }
    match protect {
        // Locked first, through the handle, so that no other user can add an entry (or a
        // junction) after the check below has looked; then again by path, which passes the
        // access on to what is already inside.
        Some(sddl) => {
            let sd = descriptor(sddl)?;
            let code = unsafe {
                SetSecurityInfo(
                    folder.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    dacl_of(&sd)?,
                    std::ptr::null_mut(),
                )
            };
            if code != 0 {
                return Err(format!(
                    "{}: {}",
                    dir.display(),
                    describe("Setting the access rights", code)
                ));
            }
            set_dacl(dir, sddl)?;
        }
        // Not ours to change; the check below holds only because other users cannot write here.
        None if open_to_users(&security(dir)?) => {
            return Err(format!(
                "{}: every local user may write to this folder, and the service runs as SYSTEM; use a folder only administrators can write to, or leave out --db (the default is %ProgramData%\\NetworkScope)",
                dir.display()
            ));
        }
        None => {}
    }
    check_tree(dir, owners)
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
        // The long name: CI runners give %TEMP% as an 8.3 short name (RUNNER~1), which the
        // program-file check rightly refuses.
        let tmp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let tmp = PathBuf::from(tmp.to_str().unwrap().trim_start_matches(r"\\?\"));
        let d = tmp.join(format!("ns-svc-acl-{tag}-{}", std::process::id()));
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
        prepare_dir(&dir, Some(DATA_DIR_SDDL), &owners).unwrap();
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
        // An existing folder with wider access (as made by an older version) is locked down
        // again and checked. The test user keeps access to list it (an elevated install has it
        // through Administrators); what is inside gets the new access too.
        let locked = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{me})");
        set_dacl(&dir, &format!("D:(A;OICI;FA;;;{me})(A;OICI;0x116;;;BU)")).unwrap();
        std::fs::create_dir(dir.join("alert-scripts")).unwrap();
        assert!(open_to_users(
            &security(&dir.join("alert-scripts")).unwrap()
        ));
        prepare_dir(&dir, Some(&locked), &owners).unwrap();
        assert!(!open_to_users(&security(&dir).unwrap()));
        assert!(!open_to_users(
            &security(&dir.join("alert-scripts")).unwrap()
        ));
        // Another owner is refused (here: the test user, when not trusted).
        let err = prepare_dir(&dir, Some(&locked), &["S-1-5-18"]).unwrap_err();
        assert!(err.contains("owned by") && err.contains("takeown"), "{err}");
        remove(&dir.join("alert-scripts"));
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
        let before = security(&elsewhere).unwrap().allowed;
        if junction {
            let err = prepare_dir(&dir, None, &owners).unwrap_err();
            assert!(err.contains("reparse point"), "{err}");
            // The data folder itself as a link: refused before anything is changed.
            let err = prepare_dir(&dir.join("alert-scripts"), None, &owners).unwrap_err();
            assert!(err.contains("not a plain folder"), "{err}");
            // The default folder is locked before it is checked, so no user can add an entry
            // after the check: the refused folder already has the new access.
            set_dacl(&dir, &format!("D:(A;OICI;FA;;;{me})(A;OICI;0x116;;;BU)")).unwrap();
            let locked = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{me})");
            let err = prepare_dir(&dir, Some(&locked), &owners).unwrap_err();
            assert!(err.contains("reparse point"), "{err}");
            assert!(!open_to_users(&security(&dir).unwrap()));
            let err = prepare_dir(&dir.join("alert-scripts"), Some(&locked), &owners).unwrap_err();
            assert!(err.contains("not a plain folder"), "{err}");
            // The new access did not travel through the junction.
            assert_eq!(security(&elsewhere).unwrap().allowed, before);
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
            let result = prepare_dir(&base, None, &[me.as_str()]);
            assert_eq!(result.is_err(), open, "{sddl}: {result:?}");
        }
        remove(&base);
    }

    /// The program and the files a service obeys. The test user stands in for Administrators (it
    /// owns the temp folder and its profile), so the rules can be tried without elevation; so do
    /// the accounts that may change the folders above `%TEMP%` on this machine.
    #[test]
    fn program_files_other_accounts_may_change_are_refused() {
        let base = temp("files");
        let me = security(&base).unwrap().owner;
        let mut admins = vec![me.clone(), "S-1-5-18".into(), "S-1-5-32-544".into()];
        admins.push(ADMIN_SIDS[2].into());
        for p in std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .ancestors()
        {
            let s = security(p).unwrap();
            admins.push(s.owner);
            for (sid, mask, flags) in s.allowed.unwrap_or_default() {
                if flags & INHERIT_ONLY_ACE == 0 && mask & REPLACE_RIGHTS != 0 {
                    admins.push(sid);
                }
            }
        }
        if ["S-1-5-32-545", "S-1-5-11", "S-1-5-32-546"]
            .iter()
            .any(|sid| admins.iter().any(|a| a == sid))
        {
            eprintln!("skipped: the folders above %TEMP% are open to Users or Guests here");
            return remove(&base);
        }
        let admins: Vec<&str> = admins.iter().map(String::as_str).collect();
        let check = |p: &Path| check_paths(&[p.to_path_buf()], &admins);
        let dir = base.join("app");
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("policy.rhai");
        std::fs::write(&file, "fn on_host(h) { }").unwrap();
        let mine = format!("D:P(A;OICI;FA;;;{me})");
        set_dacl(&base, &mine).unwrap();
        set_dacl(&dir, &mine).unwrap();
        check(&file).unwrap();
        // The file's folder: another account may add files (a DLL next to the program).
        set_dacl(&dir, &format!("{mine}(A;CI;0x116;;;BU)")).unwrap();
        let err = check(&file).unwrap_err();
        assert!(
            err.contains("Program Files") && err.contains("S-1-5-32-545"),
            "{err}"
        );
        set_dacl(&dir, &mine).unwrap();
        // The file: any account other than the administrators counts, not only Users.
        set_dacl(&file, &format!("D:P(A;;FA;;;{me})(A;;0x4;;;BG)")).unwrap();
        let err = check(&file).unwrap_err();
        assert!(
            err.contains("policy.rhai") && err.contains("S-1-5-32-546"),
            "{err}"
        );
        // An allow entry of a kind that is not parsed (here a conditional one) counts as a writer;
        // a deny entry does not.
        set_dacl(
            &file,
            &format!("D:P(A;;FA;;;{me})(XA;;FA;;;WD;(Member_of {{SID(BA)}}))"),
        )
        .unwrap();
        let err = check(&file).unwrap_err();
        assert!(err.contains("an access entry of type 9"), "{err}");
        set_dacl(
            &file,
            &format!("D:P(D;;FA;;;BG)(A;;FA;;;{me})(A;;0x1200a9;;;BU)"),
        )
        .unwrap();
        check(&file).unwrap();
        // The same path in another case or with a trailing separator is the same object.
        let upper = PathBuf::from(dir.to_string_lossy().to_uppercase());
        check(&upper).unwrap();
        check(&PathBuf::from(format!("{}\\", dir.display()))).unwrap();
        // A short (8.3) name on the way is another spelling the service would open: refused,
        // where the volume makes short names.
        use std::os::windows::process::CommandExt;
        let short = std::process::Command::new("cmd")
            .raw_arg(format!(
                "/C for %I in (\"{}\") do @echo %~sI",
                file.display()
            ))
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        if !short.is_empty() && !short.eq_ignore_ascii_case(&file.to_string_lossy()) {
            let err = check(Path::new(&short)).unwrap_err();
            assert!(err.contains("short name"), "{short}: {err}");
        } else {
            eprintln!("skipped the short-name part: no 8.3 name here");
        }
        // A folder further up: creating folders in it is fine (as in C:\), renaming or
        // replacing what is in it is not; entries only for what is created below do not count.
        set_dacl(&base, &format!("{mine}(A;;0x4;;;AU)(A;OICIIO;FA;;;AU)")).unwrap();
        check(&file).unwrap();
        set_dacl(&base, &format!("{mine}(A;;0x40;;;AU)")).unwrap();
        let err = check(&file).unwrap_err();
        assert!(err.contains("S-1-5-11"), "{err}");
        set_dacl(&base, &mine).unwrap();
        // A junction anywhere on the path.
        let link = base.join("link");
        let junction = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&dir)
            .output()
            .is_ok_and(|o| o.status.success());
        if junction {
            let err = check(&link.join("policy.rhai")).unwrap_err();
            assert!(err.contains("through a link"), "{err}");
        }
        // A missing file fails the check instead of passing it.
        assert!(check(&dir.join("missing.rhai")).is_err());
        // With the real list, a file in the test user's profile is refused (which account
        // trips it first depends on the machine: the user as owner here, the profile's own
        // administrator account on a CI runner), one in Program Files passes.
        assert!(check_not_writable(std::slice::from_ref(&file)).is_err());
        let common = Path::new(r"C:\Program Files\Common Files");
        if common.is_dir() {
            check_not_writable(&[common.to_path_buf()]).unwrap();
        }
        let _ = std::fs::remove_dir(&link);
        remove(&dir);
        remove(&base);
    }

    #[test]
    fn owners_and_entries_of_other_accounts_count_as_writers() {
        let entry = |sid: &str, mask: u32, flags: u8| (sid.to_string(), mask, flags);
        let s = |owner: &str, allowed| Security {
            owner: owner.into(),
            allowed,
        };
        let admins = &ADMIN_SIDS;
        let user = "S-1-5-21-1-2-3-1001";
        assert!(other_writer(&s(user, Some(vec![])), WRITE_RIGHTS, admins).is_some());
        assert!(other_writer(&s("S-1-5-18", None), WRITE_RIGHTS, admins).is_some());
        let creator_below = vec![entry("S-1-3-0", 0x1f01ff, INHERIT_ONLY_ACE | 0x3)];
        assert!(
            other_writer(&s(ADMIN_SIDS[2], Some(creator_below)), WRITE_RIGHTS, admins).is_none()
        );
        let owner_rights = vec![entry(user, 0x8_0000, 0)];
        assert!(
            other_writer(
                &s("S-1-5-32-544", Some(owner_rights)),
                REPLACE_RIGHTS,
                admins
            )
            .is_some()
        );
        let add_folder = vec![entry("S-1-5-11", 0x4, 0)];
        assert!(
            other_writer(
                &s("S-1-5-32-544", Some(add_folder.clone())),
                REPLACE_RIGHTS,
                admins
            )
            .is_none()
        );
        assert!(other_writer(&s("S-1-5-32-544", Some(add_folder)), WRITE_RIGHTS, admins).is_some());
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
