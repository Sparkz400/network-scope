//! The scope guard for CLI commands (ROADMAP H54): reads `--scope`, `--scope-file`, the default
//! scope file and the consent flags (`--yes-public`, `--allow-out-of-scope`) and calls the one
//! check in the engine, [`scope::enforce`]. A terminal user is asked; everything else
//! (scripts, pipes, monitor under a service manager) is refused unless the flags are given.
use crate::{
    scope::{self, Addresses, Assessment, Consent, Refusal, Scope},
    ui::{Ctx, ExitCode},
};
use std::{
    collections::BTreeMap,
    io::{BufRead, IsTerminal, Write},
    path::PathBuf,
};

/// The consent the command line gives.
pub(super) fn consent(opts: &BTreeMap<String, String>) -> Consent {
    Consent {
        public: opts.contains_key("yes-public"),
        out_of_scope: opts.contains_key("allow-out-of-scope"),
    }
}

/// The declared scope: `--scope TEXT`, else `--scope-file FILE` (which must exist), else the
/// default scope file when there is one.
pub(super) fn declared(opts: &BTreeMap<String, String>) -> Result<Option<Scope>, String> {
    if let Some(path) = opts.get("scope-file")
        && !opts.contains_key("scope")
    {
        let path = PathBuf::from(path);
        return Scope::load(&path)?
            .map(Some)
            .ok_or_else(|| format!("{}: scope file not found", path.display()));
    }
    scope::declared(
        opts.get("scope").map(String::as_str),
        scope::default_path().as_deref(),
    )
}

/// Asks on the terminal. `None` when this is not an interactive session (stdin or stderr is not a
/// terminal), so unattended runs refuse instead of waiting for an answer nobody gives.
fn tty_prompt() -> Option<impl FnMut(&str) -> bool> {
    (std::io::stdin().is_terminal() && std::io::stderr().is_terminal()).then_some(|what: &str| {
        eprint!("{what}\nScan anyway? Type yes to continue: ");
        let _ = std::io::stderr().flush();
        let mut answer = String::new();
        std::io::stdin().lock().read_line(&mut answer).is_ok()
            && matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    })
}

/// The check with an injectable prompt, for tests.
pub(super) fn check<'a>(
    opts: &BTreeMap<String, String>,
    addresses: impl Into<Addresses<'a>>,
    confirm: Option<&mut dyn FnMut(&str) -> bool>,
) -> Result<Result<Assessment, Refusal>, String> {
    let scope = declared(opts)?;
    Ok(scope::enforce(
        addresses,
        scope.as_ref(),
        consent(opts),
        confirm,
    ))
}

/// Runs the scope check for a command about to send traffic. `Ok(true)`: go ahead. `Ok(false)`:
/// refused (the reason is on stderr and the exit status is [`ExitCode::Refused`]); the caller
/// returns without sending anything. `Err`: the scope itself is invalid.
pub(super) fn enforce<'a>(
    ctx: &mut Ctx,
    addresses: impl Into<Addresses<'a>>,
) -> Result<bool, String> {
    let mut prompt = tty_prompt();
    let confirm = prompt.as_mut().map(|p| p as &mut dyn FnMut(&str) -> bool);
    match check(&ctx.opts, addresses, confirm)? {
        Ok(_) => Ok(true),
        Err(refusal) => {
            eprintln!("{refusal}");
            ctx.status = ExitCode::Refused;
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::{args::options, testutil::args};

    fn opts(list: &[&str]) -> BTreeMap<String, String> {
        options(&args(list)).unwrap().1
    }
    fn targets(text: &str) -> crate::scan::Targets {
        crate::scan::parse_targets(text, true, crate::scan::MAX_STREAM).unwrap()
    }

    #[test]
    fn flags_and_options_are_parsed() {
        let o = opts(&[
            "--yes-public",
            "--scope",
            "10.0.0.0/8",
            "--allow-out-of-scope",
        ]);
        assert_eq!(
            consent(&o),
            Consent {
                public: true,
                out_of_scope: true
            }
        );
        assert_eq!(consent(&BTreeMap::new()), Consent::default());
        assert!(declared(&o).unwrap().is_some());
        assert!(declared(&opts(&["--scope", "banana"])).is_err());
    }

    /// [`check`] with no declared scope (the real one would read the default scope file).
    fn check_undeclared<'a>(
        opts: &BTreeMap<String, String>,
        addresses: impl Into<Addresses<'a>>,
        confirm: Option<&mut dyn FnMut(&str) -> bool>,
    ) -> Result<Result<Assessment, Refusal>, String> {
        Ok(scope::enforce(addresses, None, consent(opts), confirm))
    }

    #[test]
    fn public_targets_are_refused_without_a_flag_or_an_answer() {
        // No declared scope, whatever the developer's own scope file says.
        let public = targets("8.8.8.8");
        let o = BTreeMap::new();
        let refusal = check_undeclared(&o, &public, None).unwrap().unwrap_err();
        assert!(refusal.0.contains("--yes-public"), "{refusal}");
        // An interactive "no" refuses, "yes" goes ahead.
        let mut no = |_: &str| false;
        assert!(
            check_undeclared(&o, &public, Some(&mut no))
                .unwrap()
                .is_err()
        );
        let mut yes = |_: &str| true;
        assert!(
            check_undeclared(&o, &public, Some(&mut yes))
                .unwrap()
                .is_ok()
        );
        // The flag goes ahead without asking.
        let flagged = opts(&["--yes-public"]);
        let mut never = |_: &str| panic!("flags make a prompt unnecessary");
        assert!(
            check_undeclared(&flagged, &public, Some(&mut never))
                .unwrap()
                .is_ok()
        );
        // Private targets never ask.
        assert!(
            check_undeclared(&o, &targets("192.168.0.0/24"), Some(&mut never))
                .unwrap()
                .is_ok()
        );
    }

    #[test]
    fn out_of_scope_needs_its_own_flag() {
        let o = opts(&["--scope", "192.168.1.0/24"]);
        let outside = targets("192.168.2.1");
        assert!(check(&o, &targets("192.168.1.9"), None).unwrap().is_ok());
        let refusal = check(&o, &outside, None).unwrap().unwrap_err();
        assert!(refusal.0.contains("--allow-out-of-scope"), "{refusal}");
        let allowed = opts(&["--scope", "192.168.1.0/24", "--allow-out-of-scope"]);
        assert!(check(&allowed, &outside, None).unwrap().is_ok());
        // --yes-public does not cover an out-of-scope address.
        let public_only = opts(&["--scope", "192.168.1.0/24", "--yes-public"]);
        assert!(check(&public_only, &outside, None).unwrap().is_err());
    }

    #[test]
    fn a_scope_file_is_read_and_a_missing_explicit_one_is_an_error() {
        let dir = std::env::temp_dir().join(format!("ns-guard-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("scope.txt");
        std::fs::write(&file, "10.9.0.0/16\n").unwrap();
        let o = opts(&["--scope-file", file.to_str().unwrap()]);
        assert!(check(&o, &targets("10.9.1.1"), None).unwrap().is_ok());
        assert!(check(&o, &targets("10.8.1.1"), None).unwrap().is_err());
        let missing = dir.join("nope.txt");
        let o = opts(&["--scope-file", missing.to_str().unwrap()]);
        assert!(declared(&o).unwrap_err().contains("not found"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every entry point that starts active traffic calls the one check before it does.
    #[test]
    fn every_sending_entry_point_calls_the_scope_check() {
        for (name, source, call) in [
            ("scan", include_str!("commands/scan.rs"), "guard::enforce("),
            (
                "monitor",
                include_str!("commands/monitor.rs"),
                "guard::enforce(",
            ),
            (
                "trace",
                include_str!("commands/trace.rs"),
                "guard::enforce(",
            ),
        ] {
            let code = source.split("#[cfg(test)]").next().unwrap();
            assert!(code.contains(call), "{name} must call the scope guard");
        }
        // `service install` checks the targets (no prompt: nobody can answer in a service), and
        // `service run` is the monitor loop, which calls the guard itself (checked above).
        let service = include_str!("commands/service.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(service.contains("guard::check("), "service install");
        assert!(
            service.contains("run_monitor("),
            "service run goes through monitor"
        );
        assert!(
            service.contains("ExitCode::Refused"),
            "service run reports a refusal"
        );
        // The MCP `scan` tool: the engine's guard without consent flags and without a prompt.
        let mcp = include_str!("../../core/src/mcp.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(mcp.contains("scope::enforce("), "the MCP scan tool");
        assert!(
            mcp.contains("scope_check(&addresses"),
            "the MCP scan tool calls it"
        );
        assert!(
            mcp.contains("Consent::default()") && !mcp.contains("Consent {"),
            "the MCP server never carries consent flags"
        );
        assert!(!mcp.contains("TODO(H54)"));
        // Nothing that is not a scan target goes through the guard: `sync push` sends the
        // inventory to a URL the user gave and opens no scan.
        let sync = include_str!("../../core/src/sync.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(!sync.contains("scan::start") && !sync.contains("Gate"));
        #[cfg(feature = "gui")]
        {
            let gui = include_str!("../gui/mod.rs");
            assert!(
                gui.contains("scope::enforce("),
                "the desktop Start must call the scope guard"
            );
            // The scheduler starts its scans through the same check, unattended: it neither
            // opens the dialog nor uses a stored consent.
            let scheduler = include_str!("../gui/scheduler.rs");
            assert!(scheduler.contains("start_unattended("));
            assert!(!scheduler.contains("scope_consent") && !scheduler.contains("scan::start"));
            assert!(
                gui.contains("fn start_unattended(") && gui.contains("self.scope_check(&hosts"),
                "unattended starts must go through scope_check"
            );
        }
        // The CLI helper itself goes through the engine's single function.
        let code = include_str!("guard.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert!(code.contains("scope::enforce("));
    }

    #[test]
    fn handlers_stop_with_status_2_before_sending() {
        // Unattended (tests have no terminal), a public target is refused: status 2, nothing
        // scanned, nothing saved.
        let dir = std::env::temp_dir().join(format!("ns-guard-run-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("x.sqlite");
        let none = dir.join("no-scope.txt");
        std::fs::write(&none, "127.0.0.0/8\n").unwrap();
        for command in [
            vec!["scan", "8.8.8.8", "--tcp-only", "--ports", "80"],
            vec!["monitor", "8.8.8.8", "--cycles", "1"],
            vec!["trace", "8.8.8.8"],
        ] {
            let mut a = command.clone();
            a.extend([
                "--db",
                db.to_str().unwrap(),
                "--scope-file",
                none.to_str().unwrap(),
            ]);
            let status = crate::ui::run(&args(&a)).unwrap();
            assert_eq!(status, ExitCode::Refused, "{command:?}");
            assert_eq!(status.code(), 2);
        }
        assert!(!db.exists(), "a refused run saves nothing");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
