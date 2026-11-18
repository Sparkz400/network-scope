#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
// Modules are `pub(crate)`: src/bin/network-scope-cli.rs compiles this file as a
// module and reaches them as `crate::<module>` through a glob import.
pub(crate) mod arp;
pub(crate) mod capture;
pub(crate) mod core;
pub(crate) mod devices;
pub(crate) mod gui;
pub(crate) mod monitor;
pub(crate) mod nmap;
pub(crate) mod osfp;
pub(crate) mod ot;
pub(crate) mod otpassive;
pub(crate) mod oui;
pub(crate) mod passive;
pub(crate) mod pcapfile;
pub(crate) mod platform;
pub(crate) mod probes;
pub(crate) mod report;
pub(crate) mod risk;
pub(crate) mod scan;
pub(crate) mod script;
pub(crate) mod service;
pub(crate) mod store;
pub(crate) mod syn;
pub(crate) mod tls;
pub(crate) mod topology;
pub(crate) mod trace;
pub(crate) mod udp;
pub(crate) mod ui;
use std::path::PathBuf;

/// A standard handle the process cannot use: never set (a GUI-subsystem process
/// started from a console gets NULL handles) or invalid. Redirected handles (files,
/// pipes) are usable and must be kept.
#[cfg_attr(not(windows), allow(dead_code))]
fn handle_unusable(handle: isize, file_type: u32) -> bool {
    const FILE_TYPE_UNKNOWN: u32 = 0;
    handle == 0 || handle == -1 || file_type == FILE_TYPE_UNKNOWN
}

/// Release builds use the Windows GUI subsystem so a double-click opens no console.
/// For CLI use, attach to the parent's console whenever this process has none,
/// whether or not stdout is redirected, and point only the unusable standard
/// handles at it. Redirected stdout/stderr stay redirected; progress on stderr is no
/// longer lost when only stdout goes to a file. (The shell still does not wait for a
/// GUI-subsystem process; see NOTES-engine.md.)
#[cfg(windows)]
fn attach_parent_console() {
    use std::ffi::c_void;
    extern "system" {
        fn AttachConsole(id: u32) -> i32;
        fn GetConsoleWindow() -> isize;
        fn GetStdHandle(kind: u32) -> isize;
        fn SetStdHandle(kind: u32, handle: isize) -> i32;
        fn GetFileType(handle: isize) -> u32;
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            security: *const c_void,
            disposition: u32,
            flags: u32,
            template: isize,
        ) -> isize;
    }
    const ATTACH_PARENT_PROCESS: u32 = u32::MAX;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const FILE_SHARE_READ_WRITE: u32 = 3;
    const OPEN_EXISTING: u32 = 3;
    let kinds: [(u32, &str); 3] = [
        (-10i32 as u32, "CONIN$"),
        (-11i32 as u32, "CONOUT$"),
        (-12i32 as u32, "CONOUT$"),
    ];
    unsafe {
        if GetConsoleWindow() != 0 {
            return; // Console-subsystem build, or already attached.
        }
        let missing: Vec<(u32, &str)> = kinds
            .into_iter()
            .filter(|(kind, _)| {
                let h = GetStdHandle(*kind);
                handle_unusable(h, if h == 0 || h == -1 { 0 } else { GetFileType(h) })
            })
            .collect();
        if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
            return; // Started from Explorer or a service: nothing to attach to.
        }
        for (kind, device) in missing {
            let name: Vec<u16> = device.encode_utf16().chain([0]).collect();
            let h = CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                0,
            );
            if h != -1 && h != 0 {
                SetStdHandle(kind, h);
            }
        }
    }
}

pub(crate) fn main() -> eframe::Result<()> {
    let cli_args: Vec<String> = std::env::args().skip(1).collect();
    if cli_args
        .first()
        .is_some_and(|a| !a.starts_with("--screenshot"))
    {
        #[cfg(windows)]
        attach_parent_console();
        if let Err(e) = ui::run(&cli_args) {
            eprintln!("{e}");
            std::process::exit(1);
        }
        return Ok(());
    }
    let mut screenshot = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--screenshot" || arg == "--screenshot-path" {
            screenshot = args.next().map(PathBuf::from);
        }
        if let Some(path) = arg.strip_prefix("--screenshot=") {
            screenshot = Some(PathBuf::from(path));
        }
    }
    gui::run(screenshot)
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_missing_or_invalid_std_handles_are_rebound() {
        use super::handle_unusable;
        assert!(handle_unusable(0, 0), "never set (GUI subsystem)");
        assert!(handle_unusable(-1, 0), "INVALID_HANDLE_VALUE");
        assert!(handle_unusable(0x44, 0), "stale handle, unknown type");
        assert!(!handle_unusable(0x44, 1), "redirected to a file: keep");
        assert!(!handle_unusable(0x48, 3), "redirected to a pipe: keep");
        assert!(!handle_unusable(0x4c, 2), "console: keep");
    }

    #[test]
    fn modules_are_visible_to_the_console_binary() {
        // The console binary includes this file as a module; a private `mod x;` here
        // would be unreachable as `crate::x` there.
        let source = include_str!("main.rs");
        for line in source.lines().map(str::trim) {
            if line.starts_with("mod ") || line.starts_with("pub mod ") {
                assert!(
                    line.starts_with("mod tests"),
                    "declare as pub(crate): {line}"
                );
            }
        }
        assert!(include_str!("bin/network-scope-cli.rs").contains("#[path = \"../main.rs\"]"));
    }
}
