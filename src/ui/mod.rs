//! Scriptable CLI and live terminal view use exactly the desktop scan engine.
//!
//! # Layout
//!
//! - `args.rs`: the option tables ([`FLAGS`](args::FLAGS), [`VALUES`](args::VALUES)), the
//!   `--key value` parser and the conversion of options into engine settings.
//! - `help.rs`: the `--help` text.
//! - `commands/`: one file per command (or small family of commands), plus the table
//!   [`commands::COMMANDS`] that maps the command word to its handler.
//! - `tui.rs`: the live terminal view of `scan --tui`.
//! - this file: [`run`] (parse, dispatch), [`Ctx`], [`ExitCode`] and the output helpers.
//!
//! # Adding a subcommand
//!
//! 1. Create `commands/<name>.rs` with `pub(super) fn run(ctx: &mut Ctx) -> Result<(), String>`.
//!    Read positional arguments from `ctx.pos`, options from `ctx.opts`, the scan database from
//!    `ctx.db` and the scan ID arguments with `ctx.id(n)`. Print the result with [`output`] (it
//!    honours `--output FILE`) and report progress with [`progress`] (it honours `--quiet`).
//!    Set `ctx.status` only for a non-success exit status (see [`ExitCode`]); return `Err(message)`
//!    for a failure (message on stderr, exit status 1).
//! 2. Register it in `commands/mod.rs`: a `mod <name>;` line and a row in `COMMANDS`.
//! 3. Declare new options in `args.rs` (`FLAGS` for switches, `VALUES` for options with a value) and
//!    describe the command in `help.rs`. The completion scripts are generated from these tables.
//!
//! Tests next to the code check that every option a command reads is declared, that the help text
//! and the table list the same commands, and that the completion scripts cover both.
use crate::{risk, store};
use std::{collections::BTreeMap, path::PathBuf};

mod args;
mod commands;
mod dryrun;
mod guard;
mod help;
mod tui;

#[cfg(test)]
mod testutil;

/// The parsed command line a command handler works on.
pub struct Ctx {
    /// The command word as typed. `listen` and `dcp` share a handler and tell themselves apart by it.
    pub command: String,
    /// Positional arguments after the command word.
    pub pos: Vec<String>,
    /// Options, `--flag` as `"true"` and `--key value` as the value (declared in `args.rs`).
    pub opts: BTreeMap<String, String>,
    /// The scan database (`--db FILE`, or the default location).
    pub db: PathBuf,
    /// The exit status the command ends with; handlers set it only when it is not `Success`.
    pub status: ExitCode,
}
impl Ctx {
    /// The scan ID given as positional argument `i`.
    pub fn id(&self, i: usize) -> Result<i64, String> {
        self.pos
            .get(i)
            .ok_or("Missing scan ID")?
            .parse()
            .map_err(|_| "Invalid scan ID".into())
    }
    /// `--fail-on-findings` was given (only valid for `findings` and `diff`).
    pub fn fail_on_findings(&self) -> bool {
        self.opts.contains_key("fail-on-findings")
    }
}

/// Progress and status messages; `--quiet` suppresses them (errors are returned, not printed here).
fn progress(opts: &BTreeMap<String, String>, message: impl std::fmt::Display) {
    if !opts.contains_key("quiet") {
        eprintln!("{message}");
    }
}
fn output(data: &str, opts: &BTreeMap<String, String>) -> Result<(), String> {
    if let Some(path) = opts.get("output") {
        std::fs::write(path, data).map_err(|e| e.to_string())
    } else {
        use std::io::Write;
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{data}").map_err(|e| e.to_string())
    }
}
/// Process exit status of a CLI run. This is the single definition of the numbers documented in
/// docs/src/cli-reference.md; `lib.rs` turns it into the process exit (the only `exit` call).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitCode {
    /// Everything done.
    Success,
    /// Bad arguments, I/O or database error; nothing (or no result) was saved.
    Error,
    /// A scan or capture stopped early and its partial results were saved.
    Partial,
    /// `findings` / `diff` found something at or above `--min-severity`, only with
    /// `--fail-on-findings`.
    Findings,
    /// The scope guard refused to start: public or out-of-scope targets without confirmation.
    /// Nothing was sent. It shares the number 2 with [`ExitCode::Partial`] (both mean "the run
    /// did not do everything it was asked to"); the message on stderr tells them apart.
    Refused,
}
impl ExitCode {
    pub fn code(self) -> i32 {
        match self {
            Self::Success => 0,
            Self::Error => 1,
            Self::Partial | Self::Refused => 2,
            Self::Findings => 3,
        }
    }
}
/// Status of a scan or capture whose snapshot was saved: partial when it did not run to the end.
fn saved_exit(complete: bool) -> ExitCode {
    if complete {
        ExitCode::Success
    } else {
        ExitCode::Partial
    }
}
/// Status of `findings`/`diff`: 3 only when the gate is on and `matching` findings were found.
fn findings_exit(fail_on_findings: bool, matching: usize) -> ExitCode {
    if fail_on_findings && matching > 0 {
        ExitCode::Findings
    } else {
        ExitCode::Success
    }
}
/// Runs one CLI command and returns its exit status. `Err` is an error message for stderr
/// (status 1); every other status is a result of a command that ran.
pub fn run(args: &[String]) -> Result<ExitCode, String> {
    // Global options may also come before the command (`network-scope --quiet scan ...`).
    let split = args
        .iter()
        .position(|a| a != "--quiet")
        .unwrap_or(args.len());
    let (global, args) = args.split_at(split);
    if ["--version", "-V"].contains(&args.first().map_or("", String::as_str)) {
        println!("network-scope {}", env!("CARGO_PKG_VERSION"));
        return Ok(ExitCode::Success);
    }
    if args.is_empty() || ["help", "--help", "-h"].contains(&args[0].as_str()) {
        println!("{}", help::HELP);
        return Ok(ExitCode::Success);
    }
    let command = &args[0];
    let (pos, mut opts) = args::options(&args[1..])?;
    if opts.contains_key("fail-on-findings")
        && !matches!(command.as_str(), "findings" | "diff" | "ot-listen")
    {
        return Err(
            "--fail-on-findings applies to the findings and diff commands (and ot-listen --model) only"
                .into(),
        );
    }
    if let Some(version) = opts.get("json-schema") {
        crate::schema::check_version(version)?;
    }
    // `service install --dry-run` prints the service command line (it sends nothing either).
    if opts.contains_key("dry-run")
        && command != "service"
        && !dryrun::COMMANDS.contains(&command.as_str())
    {
        return Err(format!(
            "--dry-run applies to {} and service install only",
            dryrun::COMMANDS.join(", ")
        ));
    }
    if opts.contains_key("sent-log") && !matches!(command.as_str(), "scan" | "trace" | "dcp") {
        return Err(
            "--sent-log applies to scan, trace and dcp (monitor stores the log with each scan: see export --format json)".into(),
        );
    }
    if !global.is_empty() {
        opts.insert("quiet".into(), "true".into());
    }
    let db = opts
        .get("db")
        .map(PathBuf::from)
        .unwrap_or_else(store::default_path);
    if let Some(file) = opts.get("cves") {
        risk::load_cves(Some(std::path::Path::new(file)))?;
    }
    // `feeds` itself writes the cache, which may not exist yet.
    if command != "feeds"
        && let Some(file) = opts.get("feeds")
    {
        crate::feeds::load_active(std::path::Path::new(file))?;
    }
    // The NVD cache (`feeds import nvd`) is read by every command that analyses findings.
    if command != "feeds"
        && let Some(file) = opts.get("nvd")
    {
        crate::nvd::load_active(std::path::Path::new(file))?;
    }
    // CISA ICS advisories (`feeds import csaf`) raise CVE findings for industrial devices.
    if command != "feeds"
        && let Some(file) = opts.get("csaf")
    {
        crate::csaf::load_active(std::path::Path::new(file))?;
    }
    let handler =
        commands::find(command).ok_or_else(|| format!("Unknown command {command}. Use --help."))?;
    let mut ctx = Ctx {
        command: command.clone(),
        pos,
        opts,
        db,
        status: ExitCode::Success,
    };
    handler(&mut ctx)?;
    Ok(ctx.status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::{
        args::{min_severity, options},
        testutil::args,
    };

    #[test]
    fn quiet_is_accepted_before_and_after_the_command() {
        let (_, opts) = options(&args(&["history", "--quiet"])).unwrap();
        assert!(opts.contains_key("quiet"));
        // Before the command it is a global option, not an unknown command.
        let dir = std::env::temp_dir().join(format!("ns-quiet-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("c.txt");
        run(&args(&[
            "--quiet",
            "completions",
            "bash",
            "--output",
            out.to_str().unwrap(),
        ]))
        .unwrap();
        assert!(
            std::fs::read_to_string(&out)
                .unwrap()
                .contains("_network_scope")
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            run(&args(&["completions"]))
                .unwrap_err()
                .contains("powershell")
        );
    }

    #[test]
    fn exit_codes_are_the_documented_numbers() {
        assert_eq!(
            [
                ExitCode::Success,
                ExitCode::Error,
                ExitCode::Partial,
                ExitCode::Findings
            ]
            .map(ExitCode::code),
            [0, 1, 2, 3]
        );
        // A scope-guard refusal is documented as 2, like a partial result.
        assert_eq!(ExitCode::Refused.code(), 2);
    }

    #[test]
    fn saved_scans_and_captures_map_to_success_or_partial() {
        assert_eq!(saved_exit(true), ExitCode::Success);
        assert_eq!(saved_exit(false), ExitCode::Partial);
    }

    #[test]
    fn findings_exit_is_3_only_with_the_flag_and_a_match() {
        assert_eq!(findings_exit(false, 0), ExitCode::Success);
        // Default behaviour: findings never change the status without the flag.
        assert_eq!(findings_exit(false, 5), ExitCode::Success);
        assert_eq!(findings_exit(true, 0), ExitCode::Success);
        assert_eq!(findings_exit(true, 1), ExitCode::Findings);
    }

    #[test]
    fn fail_on_findings_is_a_flag_and_only_for_findings_and_diff() {
        let (pos, opts) = options(&args(&[
            "3",
            "--fail-on-findings",
            "--min-severity",
            "high",
        ]))
        .unwrap();
        assert_eq!(pos, ["3"], "the flag takes no value");
        assert!(opts.contains_key("fail-on-findings"));
        assert_eq!(min_severity(&opts).unwrap(), risk::Severity::High);
        // Last: the flag does not swallow the next argument either.
        let (pos, opts) = options(&args(&["--fail-on-findings", "1", "2"])).unwrap();
        assert_eq!((pos.len(), opts.len()), (2, 1));
        assert!(
            !options(&args(&["1"]))
                .unwrap()
                .1
                .contains_key("fail-on-findings")
        );
        for command in ["scan", "history", "export", "monitor", "devices"] {
            let err = run(&args(&[command, "1", "--fail-on-findings"])).unwrap_err();
            assert!(err.contains("--fail-on-findings"), "{command}: {err}");
        }
    }

    #[test]
    fn plain_commands_still_succeed_with_status_0() {
        assert_eq!(run(&args(&["--help"])).unwrap(), ExitCode::Success);
        assert!(run(&args(&["no-such-command"])).is_err());
    }

    #[test]
    fn help_text_and_command_table_list_the_same_commands() {
        let mut documented = std::collections::BTreeSet::new();
        for line in help::HELP.lines() {
            // `network-scope COMMAND ...`; the bare `network-scope` line is the GUI.
            if let Some(rest) = line.strip_prefix("network-scope ")
                && !rest.starts_with([' ', '-'])
            {
                documented.insert(rest.split_whitespace().next().unwrap());
            }
        }
        let registered: std::collections::BTreeSet<&str> =
            commands::COMMANDS.iter().map(|(name, _)| *name).collect();
        assert_eq!(documented, registered);
        assert_eq!(
            registered.len(),
            commands::COMMANDS.len(),
            "duplicate command"
        );
        assert!(commands::find("scan").is_some() && commands::find("help").is_none());
        assert_eq!(commands::names().last(), Some(&"help"));
    }
}
