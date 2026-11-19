//! Network Scope as a library: the desktop GUI (`gui`), the CLI and TUI (`ui`) on top of the engine
//! crate `network-scope-core` (`core/`). The two binaries (`src/main.rs` and
//! `src/bin/network-scope-cli.rs`) call [`run`]; the fuzz targets in `fuzz/` call the entry points
//! in [`fuzz`] (re-exported from the core crate). Everything else stays crate-private.
#[cfg(feature = "gui")]
pub(crate) mod gui;
pub(crate) mod ui;

// The engine lives in `network-scope-core`; its modules are used here under the same paths
// (`crate::scan::Host`, `crate::risk::analyze_host`, ...).
#[cfg(feature = "gui")]
pub(crate) use network_scope_core::pcapfile;
pub(crate) use network_scope_core::{
    baseline, capture, changes, core, devices, feeds, monitor, nmap, notify, observations,
    otpassive, passive, report, risk, scan, script, service, store, syn, topology, trace,
};

/// The fuzz entry points (`network_scope::fuzz::*`, called by the targets in `fuzz/`).
#[doc(hidden)]
pub use network_scope_core::fuzz;

/// The read-only OT request types (see `network_scope_core::ot::readonly`); kept at this path for
/// existing users of the library.
#[doc(hidden)]
pub use network_scope_core::ot_readonly;

#[cfg(feature = "gui")]
use std::path::PathBuf;

/// Why [`run`] failed. Only the desktop GUI can fail this way; a CLI or TUI command reports its
/// problem on stderr and ends the process with its exit status instead.
pub enum Error {
    /// The desktop window could not be opened.
    #[cfg(feature = "gui")]
    Gui(eframe::Error),
}
// What `fn main() -> Result<..>` prints on failure: exactly the underlying error.
impl std::fmt::Debug for Error {
    #[cfg_attr(not(feature = "gui"), allow(unused_variables))]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            #[cfg(feature = "gui")]
            Self::Gui(ref e) => std::fmt::Debug::fmt(e, f),
        }
    }
}
impl std::fmt::Display for Error {
    #[cfg_attr(not(feature = "gui"), allow(unused_variables))]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            #[cfg(feature = "gui")]
            Self::Gui(ref e) => std::fmt::Display::fmt(e, f),
        }
    }
}
impl std::error::Error for Error {}

/// Result of [`run`] (and of the `main` of both binaries).
pub type RunResult = Result<(), Error>;

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
/// GUI-subsystem process; use network-scope-cli for scripts.)
#[cfg(windows)]
fn attach_parent_console() {
    use std::ffi::c_void;
    unsafe extern "system" {
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

/// The whole program: CLI or TUI when arguments are given, otherwise the desktop GUI.
/// Both binaries (`network-scope` with the Windows GUI subsystem in release builds and the
/// console twin `network-scope-cli`) are thin wrappers around this function.
///
/// Without the `gui` feature (the CLI-only build) there is no window: started without a command
/// it prints a message and ends the process with status 2.
pub fn run() -> RunResult {
    let cli_args: Vec<String> = std::env::args().skip(1).collect();
    if cli_args
        .first()
        .is_some_and(|a| !a.starts_with("--screenshot"))
    {
        #[cfg(windows)]
        attach_parent_console();
        // `--cves FILE` replaces the default user rules (loaded by `ui::run`); otherwise a
        // broken user file is reported here instead of being silently ignored.
        if !cli_args.iter().any(|a| a == "--cves")
            && let Some(warning) = risk::init_cves()
        {
            eprintln!("{warning}");
        }
        let status = match ui::run(&cli_args) {
            Ok(status) => status,
            Err(e) => {
                eprintln!("{e}");
                ui::ExitCode::Error
            }
        };
        // The only process exit of the CLI path (both binaries run through here).
        if status != ui::ExitCode::Success {
            std::process::exit(status.code());
        }
        return Ok(());
    }
    #[cfg(not(feature = "gui"))]
    {
        eprintln!("network-scope-cli: built without the GUI; see --help");
        std::process::exit(2);
    }
    #[cfg(feature = "gui")]
    run_gui()
}

/// The desktop window, with the optional `--screenshot FILE` (a self-test that saves the first
/// frame and exits).
#[cfg(feature = "gui")]
fn run_gui() -> RunResult {
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
    gui::run(screenshot).map_err(Error::Gui)
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
    fn binaries_are_thin_wrappers_around_the_library() {
        // All code lives in the library so the fuzz targets and both binaries share it;
        // only the GUI binary carries the Windows GUI-subsystem attribute.
        let gui = include_str!("main.rs");
        let cli = include_str!("bin/network-scope-cli.rs");
        for source in [gui, cli] {
            assert!(source.contains("network_scope::run()"));
            assert!(!source.contains("mod "), "no modules in a binary");
        }
        assert!(gui.contains("windows_subsystem = \"windows\""));
        assert!(!cli.contains("windows_subsystem"));
    }

    #[test]
    fn the_core_crate_has_the_version_of_this_package() {
        let core = include_str!("../core/Cargo.toml");
        let line = format!("version = \"{}\"", env!("CARGO_PKG_VERSION"));
        assert!(
            core.lines().any(|l| l == line),
            "core/Cargo.toml must say {line}"
        );
    }
}
