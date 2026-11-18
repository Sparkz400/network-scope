//! Console-subsystem build of Network Scope for scripting.
//!
//! The default `network-scope` binary is a Windows GUI-subsystem program in release
//! builds, so `cmd.exe` and PowerShell neither wait for it nor see its exit code. This
//! binary is the same program (it compiles `src/main.rs` as a module and calls its
//! `main`) linked for the console subsystem: shells wait, `%ERRORLEVEL%` and
//! `$LASTEXITCODE` reflect the run, and output never interleaves with the prompt.
//! Modules declared in `src/main.rs` must be `pub(crate)` so they are reachable as
//! `crate::<module>` here through the glob import below.

// `src/main.rs` carries the crate-level `windows_subsystem` attribute; inside a module
// it has no effect, which is exactly what this binary wants.
#[allow(unused_attributes)]
#[path = "../main.rs"]
mod app;
#[allow(unused_imports)]
use app::*;

fn main() -> eframe::Result<()> {
    app::main()
}
