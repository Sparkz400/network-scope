// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! `service install|uninstall|run`: `monitor` as a Windows service.
//!
//! `service install TARGETS [monitor options]` registers the service with the Service Control
//! Manager: the command line the service starts with is `service run` plus the same arguments, so
//! what runs is exactly what `monitor` would run. `service run` is the entry point the Service
//! Control Manager starts (run by hand it explains that and exits); `service uninstall` stops and
//! removes the service. The building of the command line is plain code tested on every OS; the
//! calls into the Service Control Manager are in `service_scm.rs` (Windows only). On Linux use
//! the systemd units in `packaging/systemd`.
use super::monitor;
use crate::ui::{Ctx, ExitCode, guard, output};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

/// The service name when `--service-name` is not given.
pub(super) const DEFAULT_NAME: &str = "NetworkScopeMonitor";

const USAGE: &str = "Use: service install TARGETS [monitor options] [--service-name NAME] [--db FILE] [--dry-run] | service uninstall [--service-name NAME] | service run";

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    match ctx.pos.first().map(String::as_str) {
        Some("install") => install(ctx),
        Some("uninstall") => uninstall(ctx),
        Some("run") => run_service(ctx),
        _ => Err(USAGE.into()),
    }
}

/// The monitor command the service will run, as the context `monitor` itself would get.
fn monitor_ctx(ctx: &Ctx) -> Ctx {
    Ctx {
        command: "monitor".into(),
        pos: ctx.pos.iter().skip(1).cloned().collect(),
        opts: ctx.opts.clone(),
        db: ctx.db.clone(),
        status: crate::ui::ExitCode::Success,
    }
}

fn install(ctx: &mut Ctx) -> Result<(), String> {
    let name = service_name(&ctx.opts)?;
    if ctx.opts.contains_key("cycles") {
        return Err("A service runs until it is stopped; --cycles does not apply".into());
    }
    // The service's command line is stored in the service configuration, readable by every
    // local user (`sc qc`, the registry): a secret typed here would be saved in clear text.
    if ctx.opts.contains_key("snmp-community") {
        return Err("--snmp-community would store the community string in the service's command line; use --snmp-community-env NAME (the variable must be set for the service) or --snmp-v3".into());
    }
    // Chat webhooks (Slack, Teams, Discord) carry their secret in the path or the query.
    let webhooks = ctx.opts.get("webhook").map_or("", String::as_str);
    for url in webhooks.split(',').map(str::trim).filter(|u| !u.is_empty()) {
        if crate::notify::Sink::webhook(url)?.has_secret_path() {
            return Err("--webhook with a path or query would store the URL (for chat webhooks, their secret) in the service's command line; use --webhook-env NAME (the variable must be set for the service)".into());
        }
    }
    let targets: Vec<String> = ctx.pos.iter().skip(1).cloned().collect();
    // The same checks `monitor` makes at start-up, so a bad option fails here and not in a
    // service that then silently stops.
    let db = service_db(&ctx.opts)?;
    let mut check = monitor_ctx(ctx);
    check.db = db.clone();
    monitor::check(&check)?;
    let exe = std::env::current_exe().map_err(|e| format!("Cannot find this program: {e}"))?;
    let exe = exe
        .to_str()
        .ok_or("The program path is not valid Unicode")?;
    // The scope guard (ROADMAP H54) runs here too, without a prompt: a service started by the
    // Service Control Manager has nobody to ask, so what would need a yes must be given as
    // --yes-public / --allow-out-of-scope now (they are passed on to the service). The declared
    // scope is fixed at install time: a scope file found in the default place is passed on by
    // absolute path, because the service account has a different config folder.
    let mut service_opts = ctx.opts.clone();
    if !service_opts.contains_key("scope")
        && !service_opts.contains_key("scope-file")
        && let Some(file) = crate::scope::default_path().filter(|p| p.is_file())
    {
        service_opts.insert("scope-file".into(), file.display().to_string());
    }
    let args = service_args(&name, &db, &targets, &service_opts);
    let command_line = command_line(exe, &args);
    if ctx.opts.contains_key("dry-run") {
        return output(&command_line, &ctx.opts);
    }
    let hosts = crate::scan::parse_targets(
        &targets.join(" "),
        crate::ui::args::scan_settings(&ctx.opts)?.skip_edges,
        crate::scan::MAX_STREAM,
    )?;
    if let Err(refusal) = guard::check(&service_opts, &hosts, None)? {
        return Err(refusal.to_string());
    }
    // What the service runs or obeys as SYSTEM: no other user may be able to replace it.
    let mut files = vec![PathBuf::from(exe)];
    files.extend(
        ["script", "on-alert", "probes", "scope-file"]
            .iter()
            .filter_map(|key| service_opts.get(*key))
            .filter(|v| *v != "library" && !v.starts_with("library:"))
            .map(|v| PathBuf::from(absolute_value(v))),
    );
    scm_install(
        &name,
        &db,
        !ctx.opts.contains_key("db"),
        &command_line,
        &files,
    )?;
    crate::ui::progress(
        &ctx.opts,
        format_args!(
            "Service {name} installed (starts automatically, delayed). Start it with: sc start {name}\nInventory: {}",
            db.display()
        ),
    );
    Ok(())
}

fn uninstall(ctx: &mut Ctx) -> Result<(), String> {
    let name = service_name(&ctx.opts)?;
    scm_uninstall(&name)?;
    crate::ui::progress(&ctx.opts, format_args!("Service {name} removed"));
    Ok(())
}

fn run_service(ctx: &mut Ctx) -> Result<(), String> {
    let name = service_name(&ctx.opts)?;
    let mut ctx = monitor_ctx(ctx);
    let log = ctx.db.parent().unwrap_or(Path::new("")).join("service.log");
    scm_run(
        &name,
        log,
        Box::new(move |stop| {
            monitor::check(&ctx)?;
            monitor::run_monitor(&mut ctx, Some(stop), false)?;
            // The scope guard refused the targets (nobody to ask in a service): the monitor never
            // started, and the service log must say so.
            if ctx.status == ExitCode::Refused {
                return Err("The scope guard refused the monitor targets (public or outside the declared scope); reinstall the service with --yes-public or --allow-out-of-scope, or fix --scope-file".into());
            }
            Ok(())
        }),
    )
}

#[cfg(windows)]
use super::service_scm::Body;
/// The monitor loop a service runs; the argument is the flag the stop request sets.
#[cfg(not(windows))]
type Body =
    Box<dyn FnOnce(std::sync::Arc<std::sync::atomic::AtomicBool>) -> Result<(), String> + Send>;

/// `default_db`: the inventory is the default one under `%ProgramData%`, whose folder this
/// program owns and may lock down (see `service_scm::prepare_data_dir`). `files`: what the
/// service runs or obeys (see `service_scm::check_not_writable`).
#[cfg(windows)]
fn scm_install(
    name: &str,
    db: &Path,
    default_db: bool,
    command_line: &str,
    files: &[PathBuf],
) -> Result<(), String> {
    super::service_scm::check_not_writable(files)?;
    if let Some(dir) = db.parent() {
        super::service_scm::prepare_data_dir(dir, default_db)?;
    }
    super::service_scm::install(name, command_line)
}
#[cfg(windows)]
fn scm_uninstall(name: &str) -> Result<(), String> {
    super::service_scm::uninstall(name)
}
#[cfg(windows)]
fn scm_run(name: &str, log: PathBuf, body: Body) -> Result<(), String> {
    super::service_scm::run(name, log, body)
}
#[cfg(not(windows))]
fn scm_install(_: &str, _: &Path, _: bool, _: &str, _: &[PathBuf]) -> Result<(), String> {
    Err(NOT_WINDOWS.into())
}
#[cfg(not(windows))]
fn scm_uninstall(_: &str) -> Result<(), String> {
    Err(NOT_WINDOWS.into())
}
#[cfg(not(windows))]
fn scm_run(_: &str, _: PathBuf, _: Body) -> Result<(), String> {
    Err(NOT_WINDOWS.into())
}
#[cfg(not(windows))]
const NOT_WINDOWS: &str = "Windows services are only available on Windows. On Linux use the systemd units in packaging/systemd (see docs: Service and scheduling); `service install --dry-run` prints the command line.";

/// A service name the Service Control Manager accepts and that is safe on a command line.
fn service_name(opts: &BTreeMap<String, String>) -> Result<String, String> {
    let name = opts
        .get("service-name")
        .map_or(DEFAULT_NAME, String::as_str);
    let ok = (1..=80).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'));
    if ok {
        Ok(name.to_string())
    } else {
        Err("The service name must be 1-80 letters, digits, '.', '_' or '-'".into())
    }
}

/// The inventory the service writes: an absolute path, because a service does not run as the
/// installing user and `LOCALAPPDATA` (the default location) is not theirs. Without `--db`:
/// `NetworkScope\inventory.sqlite` under `%ProgramData%`.
fn service_db(opts: &BTreeMap<String, String>) -> Result<PathBuf, String> {
    let db = match opts.get("db") {
        Some(p) => PathBuf::from(p),
        None => program_data().join("NetworkScope").join("inventory.sqlite"),
    };
    std::path::absolute(&db).map_err(|e| format!("{}: {e}", db.display()))
}
fn program_data() -> PathBuf {
    if cfg!(windows) {
        std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
    } else {
        // Only reached by `service install --dry-run`, which prints the Windows command line.
        PathBuf::from("/var/lib")
    }
}

/// The arguments the service is started with (after the program path): `service run`, the
/// service name, the absolute database, the targets and every other option as typed.
fn service_args(
    name: &str,
    db: &Path,
    targets: &[String],
    opts: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut args: Vec<String> = ["service", "run", "--service-name", name, "--db"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    args.push(db.display().to_string());
    args.extend(targets.iter().cloned());
    for (key, value) in opts {
        // Options of the install command itself, not of the monitor.
        if matches!(
            key.as_str(),
            "db" | "service-name" | "dry-run" | "output" | "format"
        ) {
            continue;
        }
        args.push(format!("--{key}"));
        if value != "true" || crate::ui::args::VALUES.contains(&key.as_str()) {
            args.push(if PATH_OPTIONS.contains(&key.as_str()) {
                absolute_value(value)
            } else {
                value.clone()
            });
        }
    }
    args
}

/// Options whose value is a file or folder: a service starts in the system folder, so relative
/// paths from the installing shell are made absolute.
const PATH_OPTIONS: [&str; 8] = [
    "alerts",
    "on-alert",
    "on-alert-dir",
    "probes",
    "cves",
    "feeds",
    "script",
    "scope-file",
];
fn absolute_value(value: &str) -> String {
    // `library` and `library:NAME` name scripts built into the program, not files.
    if value == "library" || value.starts_with("library:") {
        return value.to_string();
    }
    std::path::absolute(value).map_or_else(|_| value.to_string(), |p| p.display().to_string())
}

/// One argument quoted the way `CommandLineToArgvW` (and the C runtime) reads it back: quotes
/// only when needed, backslashes doubled before a quote and at the end of a quoted argument.
pub(super) fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '\n', '\u{b}', '"']) {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            c => {
                out.push_str(&"\\".repeat(backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(backslashes * 2));
    out.push('"');
    out
}

/// The full command line of the service: the program path, always quoted (an unquoted path with
/// spaces lets Windows run a different program), then the arguments.
fn command_line(exe: &str, args: &[String]) -> String {
    let mut line = format!("\"{exe}\"");
    for arg in args {
        line.push(' ');
        line.push_str(&quote_arg(arg));
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::{args::options, run, testutil::args};

    fn opts(list: &[&str]) -> (Vec<String>, BTreeMap<String, String>) {
        options(&args(list)).unwrap()
    }

    /// Reads a command line back with the rules of `CommandLineToArgvW` for the arguments the
    /// builder produces (no `\\\"` ambiguity beyond what `quote_arg` emits).
    fn split(line: &str) -> Vec<String> {
        let (mut out, mut cur, mut quoted, mut any) = (vec![], String::new(), false, false);
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    let mut n = 1;
                    while chars.peek() == Some(&'\\') {
                        chars.next();
                        n += 1;
                    }
                    if chars.peek() == Some(&'"') {
                        cur.push_str(&"\\".repeat(n / 2));
                        if n % 2 == 1 {
                            chars.next();
                            cur.push('"');
                        }
                    } else {
                        cur.push_str(&"\\".repeat(n));
                    }
                    any = true;
                }
                '"' => {
                    quoted = !quoted;
                    any = true;
                }
                ' ' if !quoted => {
                    if any {
                        out.push(std::mem::take(&mut cur));
                        any = false;
                    }
                }
                c => {
                    cur.push(c);
                    any = true;
                }
            }
        }
        if any {
            out.push(cur);
        }
        out
    }

    #[test]
    fn arguments_are_quoted_so_that_they_read_back_unchanged() {
        for arg in [
            "plain",
            "",
            "with space",
            r"C:\Program Files\Network Scope\x.exe",
            r"C:\dir with space\",
            r#"say "hi""#,
            r#"a\"b"#,
            r"back\\slash",
            "tab\there",
        ] {
            let quoted = quote_arg(arg);
            assert_eq!(split(&quoted), [arg.to_string()], "{arg:?} -> {quoted}");
        }
        assert_eq!(
            quote_arg("10.0.0.0/24"),
            "10.0.0.0/24",
            "no needless quotes"
        );
        assert_eq!(quote_arg(""), "\"\"");
    }

    #[test]
    fn the_program_path_is_always_quoted_and_the_arguments_follow() {
        let line = command_line(
            r"C:\Program Files\Network Scope\network-scope-cli.exe",
            &args(&[
                "service",
                "run",
                "--db",
                r"C:\ProgramData\Network Scope\i.sqlite",
            ]),
        );
        assert!(line.starts_with(
            "\"C:\\Program Files\\Network Scope\\network-scope-cli.exe\" service run"
        ));
        assert_eq!(
            split(&line),
            [
                r"C:\Program Files\Network Scope\network-scope-cli.exe",
                "service",
                "run",
                "--db",
                r"C:\ProgramData\Network Scope\i.sqlite"
            ]
        );
        // Even a path without spaces is quoted.
        assert!(command_line(r"C:\x\a.exe", &[]).starts_with("\"C:"));
    }

    #[test]
    fn the_service_arguments_reproduce_the_monitor_options_and_pin_the_database() {
        // An absolute path on every platform (a relative one would be made absolute).
        let alerts = std::env::temp_dir().join("a b.jsonl").display().to_string();
        let (pos, opts) = opts(&[
            "install",
            "10.0.0.0/24",
            "192.168.1.1-50",
            "--interval",
            "600",
            "--learn",
            "--report-missing",
            "--ports",
            "22,80,443",
            "--service-name",
            "MyScope",
            "--db",
            "relative.sqlite",
            "--alerts",
            &alerts,
        ]);
        let name = service_name(&opts).unwrap();
        assert_eq!(name, "MyScope");
        let db = service_db(&opts).unwrap();
        assert!(db.is_absolute(), "{db:?}");
        let service = service_args(&name, &db, &pos[1..], &opts);
        assert_eq!(
            &service[..4],
            ["service", "run", "--service-name", "MyScope"]
        );
        assert_eq!(service[4], "--db");
        assert_eq!(service[5], db.display().to_string());
        assert_eq!(&service[6..8], ["10.0.0.0/24", "192.168.1.1-50"]);
        // What the service runs parses back into the same monitor configuration.
        let (spos, sopts) = options(&service[1..]).unwrap();
        assert_eq!(spos[0], "run");
        assert_eq!(&spos[1..], &pos[1..]);
        for key in ["interval", "ports", "alerts", "service-name"] {
            assert_eq!(sopts[key], opts[key], "{key}");
        }
        assert!(sopts.contains_key("learn") && sopts.contains_key("report-missing"));
        assert_eq!(sopts["db"], db.display().to_string());
        let line = command_line("C:\\x\\network-scope-cli.exe", &service);
        let round = split(&line);
        assert_eq!(&round[1..], &service[..], "{line}");
        assert!(!sopts.contains_key("dry-run"));
    }

    #[test]
    fn file_options_become_absolute_but_built_in_scripts_stay_names() {
        let (pos, opts) = opts(&[
            "install",
            "10.0.0.0/24",
            "--script",
            "policies.rhai",
            "--on-alert",
            "library:log-alerts",
            "--alerts",
            "out/alerts.jsonl",
            "--on-alert-dir",
            "alert-out",
            "--output",
            "ignored.txt",
            "--format",
            "json",
        ]);
        let db = service_db(&opts).unwrap();
        let service = service_args("S", &db, &pos[1..], &opts);
        let (_, sopts) = options(&service[1..]).unwrap();
        for key in ["script", "alerts", "on-alert-dir"] {
            assert!(
                Path::new(&sopts[key]).is_absolute(),
                "{key}: {}",
                sopts[key]
            );
        }
        assert_eq!(sopts["on-alert"], "library:log-alerts");
        assert_eq!(absolute_value("library"), "library");
        assert!(!sopts.contains_key("output") && !sopts.contains_key("format"));
    }

    /// A service has nobody to ask: install refuses what the scope guard would ask about, before
    /// it touches the Service Control Manager (a refusal is the only outcome this test can reach
    /// without installing anything).
    #[test]
    fn install_refuses_public_targets_without_the_consent_flags() {
        let db =
            std::env::temp_dir().join(format!("ns-service-scope-{}.sqlite", std::process::id()));
        // Always with an explicit scope: the default scope file of the developer must not matter.
        for scope in [
            vec!["--scope", "192.168.0.0/16"],
            vec!["--scope", "10.0.0.0/8"],
        ] {
            let mut a = vec![
                "service",
                "install",
                "8.8.8.8",
                "--db",
                db.to_str().unwrap(),
            ];
            a.extend(scope);
            let err = run(&args(&a)).unwrap_err();
            assert!(
                err.contains("Scope guard") && err.contains("--yes-public"),
                "{err}"
            );
        }
        assert!(!db.exists());
    }

    #[test]
    fn names_and_the_default_database_are_validated() {
        assert_eq!(service_name(&BTreeMap::new()).unwrap(), DEFAULT_NAME);
        for bad in ["", "a b", "a/b", "a\\b", "x\"y", &"n".repeat(81), "ü"] {
            let o = BTreeMap::from([("service-name".to_string(), bad.to_string())]);
            assert!(service_name(&o).is_err(), "{bad:?}");
        }
        let db = service_db(&BTreeMap::new()).unwrap();
        assert!(
            db.is_absolute() && db.ends_with("NetworkScope/inventory.sqlite"),
            "{db:?}"
        );
    }

    #[test]
    fn install_checks_the_monitor_options_and_dry_run_prints_the_command_line() {
        let dir = std::env::temp_dir().join(format!("ns-service-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("line.txt");
        let out_arg = out.to_str().unwrap();
        let ok = args(&[
            "service",
            "install",
            "10.0.0.0/24",
            "--interval",
            "900",
            "--dry-run",
            "--output",
            out_arg,
        ]);
        run(&ok).unwrap();
        let printed = std::fs::read_to_string(&out).unwrap();
        let parts = split(printed.trim());
        assert!(Path::new(&parts[0]).is_absolute(), "{printed}");
        assert_eq!(&parts[1..3], ["service", "run"]);
        assert!(parts.contains(&"10.0.0.0/24".to_string()) && parts.contains(&"900".to_string()));
        for own in ["--dry-run", "--output"] {
            assert!(
                !parts.contains(&own.to_string()),
                "{own} is not a monitor option: {printed}"
            );
        }
        // A webhook without a path (a receiver on the LAN) may stay on the command line.
        run(&args(&[
            "service",
            "install",
            "10.0.0.0/24",
            "--webhook",
            "http://10.0.0.9:9000/",
            "--dry-run",
            "--output",
            out_arg,
        ]))
        .unwrap();
        assert!(
            std::fs::read_to_string(&out)
                .unwrap()
                .contains("http://10.0.0.9:9000/")
        );
        for (bad, message) in [
            (
                vec![
                    "service",
                    "install",
                    "10.0.0.0/24",
                    "--snmp-community",
                    "s3cret",
                    "--dry-run",
                ],
                "--snmp-community-env",
            ),
            (
                vec![
                    "service",
                    "install",
                    "10.0.0.0/24",
                    "--webhook",
                    "http://10.0.0.9:9000/,https://hooks.example.com/services/T0/B0/s3cret",
                    "--dry-run",
                ],
                "--webhook-env",
            ),
            (
                vec![
                    "service",
                    "install",
                    "10.0.0.0/24",
                    "--webhook",
                    "https://hooks.example.com/?token=s3cret",
                    "--dry-run",
                ],
                "--webhook-env",
            ),
            (
                vec![
                    "service",
                    "install",
                    "10.0.0.0/24",
                    "--cycles",
                    "2",
                    "--dry-run",
                ],
                "--cycles",
            ),
            (vec!["service", "install", "--dry-run"], ""),
            (
                vec![
                    "service",
                    "install",
                    "10.0.0.0/24",
                    "--min-severity",
                    "bogus",
                    "--dry-run",
                ],
                "Severity",
            ),
            (
                vec![
                    "service",
                    "install",
                    "10.0.0.0/24",
                    "--service-name",
                    "a b",
                    "--dry-run",
                ],
                "service name",
            ),
            (vec!["service", "install", "not a target", "--dry-run"], ""),
            (vec!["service", "frobnicate"], "Use: service"),
            (vec!["service"], "Use: service"),
        ] {
            let err = run(&args(&bad)).unwrap_err();
            assert!(err.contains(message), "{bad:?}: {err}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The shipped systemd units: hardened, Safe Mode, and an `ExecStart` that the real monitor
    /// option parser and start-up checks accept.
    #[test]
    fn the_systemd_units_are_hardened_and_their_command_lines_are_valid() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("packaging/systemd");
        let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap();
        let services = [
            "network-scope-monitor.service",
            "network-scope-monitor-once.service",
        ];
        for name in services {
            let text = read(name);
            let setting = |key: &str| -> Vec<&str> {
                text.lines()
                    .filter_map(|l| l.strip_prefix(&format!("{key}=")))
                    .collect()
            };
            for (key, value) in [
                ("ProtectSystem", "strict"),
                ("NoNewPrivileges", "yes"),
                ("ProtectHome", "yes"),
                ("PrivateTmp", "yes"),
                ("DynamicUser", "yes"),
                ("RestrictAddressFamilies", "AF_INET AF_INET6"),
                ("MemoryDenyWriteExecute", "yes"),
            ] {
                assert_eq!(setting(key), [value], "{name}: {key}");
            }
            // No capabilities unless the comment's opt-in is applied.
            assert_eq!(setting("CapabilityBoundingSet"), [""], "{name}");
            assert_eq!(setting("AmbientCapabilities"), [""], "{name}");
            assert!(text.contains("StateDirectory=network-scope"), "{name}");
            // The one command: monitor, Safe Mode (no --fast), parsed by the real option parser.
            let exec = setting("ExecStart");
            assert_eq!(exec.len(), 1, "{name}");
            let words: Vec<String> = exec[0].split_whitespace().map(str::to_string).collect();
            assert!(words[0].ends_with("/network-scope-cli"), "{name}");
            assert_eq!(words[1], "monitor", "{name}");
            assert!(
                !words.contains(&"--fast".to_string()),
                "{name}: unattended scans stay in Safe Mode"
            );
            let (pos, opts) = options(&words[2..]).unwrap();
            let ctx = Ctx {
                command: "monitor".into(),
                pos,
                opts,
                db: PathBuf::from("/var/lib/network-scope/inventory.sqlite"),
                status: crate::ui::ExitCode::Success,
            };
            monitor::check(&ctx).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(
                ctx.opts["db"], "/var/lib/network-scope/inventory.sqlite",
                "{name}"
            );
            let one_cycle = ctx.opts.get("cycles").is_some_and(|c| c == "1");
            assert_eq!(one_cycle, name.contains("once"), "{name}: --cycles");
            assert_eq!(text.contains("Type=oneshot"), one_cycle, "{name}");
            assert_eq!(text.contains("Restart=on-failure"), !one_cycle, "{name}");
        }
        let timer = read("network-scope-monitor-once.timer");
        assert!(timer.contains("Unit=network-scope-monitor-once.service"));
        assert!(timer.contains("Persistent=true") && timer.contains("OnCalendar="));
        assert!(timer.contains("WantedBy=timers.target"));
    }

    #[cfg(not(windows))]
    #[test]
    fn outside_windows_the_service_commands_explain_where_to_look() {
        for sub in ["uninstall", "run"] {
            let err = run(&args(&["service", sub])).unwrap_err();
            assert!(err.contains("systemd"), "{err}");
        }
        let err = run(&args(&["service", "install", "10.0.0.0/24"])).unwrap_err();
        assert!(err.contains("only available on Windows"), "{err}");
    }
}
