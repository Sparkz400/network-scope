//! Console-subsystem build of Network Scope for scripting.
//!
//! The default `network-scope` binary is a Windows GUI-subsystem program in release
//! builds, so `cmd.exe` and PowerShell neither wait for it nor see its exit code. This
//! binary is the same program (both call `network_scope::run` from the library) linked
//! for the console subsystem: shells wait, `%ERRORLEVEL%` and `$LASTEXITCODE` reflect
//! the run, and output never interleaves with the prompt.

fn main() -> network_scope::RunResult {
    network_scope::run()
}
