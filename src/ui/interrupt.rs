// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Ctrl+C for the commands that can stop and keep what they have (`scan`, `listen`, `dcp`,
//! `monitor`): the first one sets a flag the command polls, so it cancels its run and saves the
//! result as partial; a second one ends the process the usual way. A command that never asks
//! for the flag keeps the default behaviour (Ctrl+C ends it at once).
use std::sync::{
    Arc, Once, OnceLock,
    atomic::{AtomicBool, Ordering},
};

static STOP: OnceLock<Arc<AtomicBool>> = OnceLock::new();
static INSTALL: Once = Once::new();

/// The flag Ctrl+C (and Ctrl+Break) sets. The handler is installed on the first call.
pub fn flag() -> Arc<AtomicBool> {
    let flag = STOP.get_or_init(Default::default).clone();
    INSTALL.call_once(install);
    flag
}

/// What the handler does. True: handled, the process goes on. False (the flag was already set):
/// the default action follows and ends the process.
fn interrupted() -> bool {
    take(STOP.get().map(|flag| &**flag))
}
fn take(flag: Option<&AtomicBool>) -> bool {
    flag.is_some_and(|flag| !flag.swap(true, Ordering::SeqCst))
}

#[cfg(windows)]
fn install() {
    type Handler = unsafe extern "system" fn(u32) -> i32;
    unsafe extern "system" {
        fn SetConsoleCtrlHandler(handler: Option<Handler>, add: i32) -> i32;
    }
    // Runs on a thread of its own that the console starts. CTRL_C_EVENT is 0 and
    // CTRL_BREAK_EVENT 1; close, logoff and shutdown stay with the default handler.
    unsafe extern "system" fn on_event(event: u32) -> i32 {
        i32::from(event <= 1 && interrupted())
    }
    // SAFETY: the handler is a plain function that lives as long as the process and only
    // touches atomics.
    unsafe { SetConsoleCtrlHandler(Some(on_event), 1) };
}

#[cfg(unix)]
fn install() {
    const SIGINT: i32 = 2;
    const SIG_DFL: usize = 0;
    unsafe extern "C" {
        fn signal(signum: i32, handler: usize) -> usize;
    }
    // Only atomics and `signal` itself, which are safe to use in a signal handler.
    extern "C" fn on_signal(_: i32) {
        interrupted();
        // SAFETY: restores the default action, so a second Ctrl+C ends the process.
        unsafe { signal(SIGINT, SIG_DFL) };
    }
    // SAFETY: `on_signal` has the signature of a signal handler and lives as long as the
    // process.
    unsafe { signal(SIGINT, on_signal as extern "C" fn(i32) as usize) };
}

#[cfg(not(any(windows, unix)))]
fn install() {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The handler's decision, on a flag of its own (the real one belongs to the scans other
    /// tests run): the first interrupt is taken, so the command stops and saves; the next one
    /// is left to the default action. Before a command asked for the flag nothing is taken.
    #[test]
    fn the_first_interrupt_sets_the_flag_and_the_second_is_not_handled() {
        assert!(!take(None), "no command asked for the flag");
        let flag = AtomicBool::new(false);
        assert!(take(Some(&flag)));
        assert!(flag.load(Ordering::SeqCst));
        assert!(!take(Some(&flag)));
    }
}
