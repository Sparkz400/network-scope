// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Scripts that run when a monitor alert fires (`monitor --on-alert SCRIPT.rhai`).
//!
//! The script defines `on_alert(a)`. It receives the alert (`a.kind`, `a.severity`, `a.host`,
//! `a.details`, `a.timestamp`) and has a deliberately small API:
//!
//! - `log(text)` returns a line to the caller (the CLI prints it on stderr),
//! - `append_file(name, text)` and `write_file(name, text)` write a file in one configured
//!   directory. `name` is a plain file name: no path separators, no `..`, no drive or stream
//!   syntax (`:`), no Windows device names, at most 64 characters. A call writes at most 64 KB,
//!   a file grows to at most 1 MB, a run makes at most 16 writes. Neither the file nor the
//!   directory itself may be a link.
//!
//! There is no network, process, module or other file access, and `eval` is disabled. A run is
//! limited by an operation budget and a wall-clock limit; a script that fails or runs away
//! produces an error for that alert and never stops monitoring.
use crate::monitor::Alert;
use rhai::{AST, Dynamic, Engine, Scope};
use std::{
    cell::Cell,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// Wall-clock limit of one `on_alert` run.
const WALL_LIMIT: Duration = Duration::from_millis(500);
const MAX_OPERATIONS: u64 = 200_000;
/// At most this many bytes in one `append_file` / `write_file` call.
pub const MAX_WRITE_BYTES: usize = 64 * 1024;
/// A file written by scripts never grows beyond this.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_WRITES_PER_RUN: usize = 16;
const MAX_LOG_LINES: usize = 32;

thread_local! {
    static DEADLINE: Cell<Option<Instant>> = const { Cell::new(None) };
}

/// The alert as the script sees it.
#[derive(Clone)]
struct AlertView {
    kind: String,
    severity: String,
    host: String,
    details: String,
    timestamp: i64,
}

#[derive(Default)]
struct RunState {
    log: Vec<String>,
    writes: usize,
}

/// A loaded `on_alert` script and the directory it may write to.
pub struct AlertScript {
    engine: Engine,
    ast: AST,
    name: String,
    state: Arc<Mutex<RunState>>,
}

impl std::fmt::Debug for AlertScript {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AlertScript({})", self.name)
    }
}

/// Checks a file name a script passed to `append_file` / `write_file`.
pub fn safe_file_name(name: &str) -> Result<&str, String> {
    let ok_chars = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if name.is_empty() || name.len() > 64 || !ok_chars {
        return Err("file name must be 1-64 characters of letters, digits, . _ -".into());
    }
    if name.starts_with('.') || name.ends_with('.') || name.contains("..") {
        return Err("file name must not start or end with a dot or contain '..'".into());
    }
    // Windows device names are reserved with or without an extension (CON, CON.txt, ...).
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN" | "CONOUT"
    ) || ["COM", "LPT"].iter().any(|p| {
        stem.strip_prefix(p)
            .is_some_and(|n| n.len() == 1 && n.as_bytes()[0].is_ascii_digit())
    });
    if reserved {
        return Err("file name is a reserved device name".into());
    }
    Ok(name)
}

fn write_file(dir: &Path, name: &str, text: &str, append: bool) -> Result<(), String> {
    let name = safe_file_name(name)?;
    if text.len() > MAX_WRITE_BYTES {
        return Err(format!("a write is limited to {MAX_WRITE_BYTES} bytes"));
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let dir = std::path::absolute(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let real = std::fs::canonicalize(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    // The folder itself must not be a link (a junction another user put in its place would let
    // the script write wherever the monitor may): resolved, it is still its own name in its
    // resolved parent. Links above it (macOS /var, a mapped folder) are fine. The name compares
    // without case, as Windows and macOS file names do.
    if let (Some(parent), Some(own)) = (dir.parent(), dir.file_name()) {
        let parent =
            std::fs::canonicalize(parent).map_err(|e| format!("{}: {e}", dir.display()))?;
        let same_name = real.file_name().is_some_and(|n| {
            n.to_string_lossy()
                .eq_ignore_ascii_case(&own.to_string_lossy())
        });
        if !same_name || real.parent() != Some(parent.as_path()) {
            return Err("refusing to write: the script folder is a link".into());
        }
    }
    let path = real.join(name);
    let existing = match std::fs::symlink_metadata(&path) {
        Ok(m) if m.file_type().is_symlink() => {
            return Err("refusing to write through a link".into());
        }
        Ok(m) => m.len(),
        Err(_) => 0,
    };
    let after = if append { existing } else { 0 } + text.len() as u64;
    if after > MAX_FILE_BYTES {
        return Err(format!("{name} would exceed {MAX_FILE_BYTES} bytes"));
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true);
    if append {
        options.append(true);
    } else {
        options.write(true).truncate(true);
    }
    use std::io::Write;
    options
        .open(&path)
        .and_then(|mut f| f.write_all(text.as_bytes()))
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn clip(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(500).collect()
}

impl AlertScript {
    /// Loads `path` (a `.rhai` file); the script may write files below `dir`.
    pub fn load(path: &str, dir: &Path) -> Result<Self, String> {
        if let Some(name) = path.strip_prefix("library:") {
            let text = crate::script::ALERT_LIBRARY
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, t)| *t)
                .ok_or_else(|| {
                    format!("{path}: no such library alert script; see `scripts list`")
                })?;
            return Self::from_source(name, text, dir);
        }
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        let name = Path::new(path)
            .file_name()
            .map_or(path.to_string(), |n| n.to_string_lossy().into_owned());
        Self::from_source(&name, &text, dir)
    }

    pub fn from_source(name: &str, text: &str, dir: &Path) -> Result<Self, String> {
        if text.len() > 256 * 1024 {
            return Err(format!("{name}: script is larger than 256 KB"));
        }
        let state = Arc::new(Mutex::new(RunState::default()));
        let engine = Self::engine(dir.to_path_buf(), state.clone());
        let ast = engine.compile(text).map_err(|e| format!("{name}: {e}"))?;
        if !ast.iter_functions().any(|f| f.name == "on_alert") {
            return Err(format!("{name}: defines no on_alert(a) function"));
        }
        Ok(Self {
            engine,
            ast,
            name: name.to_string(),
            state,
        })
    }

    fn engine(dir: PathBuf, state: Arc<Mutex<RunState>>) -> Engine {
        let mut e = Engine::new();
        e.disable_symbol("eval");
        e.set_max_operations(MAX_OPERATIONS);
        e.set_max_call_levels(32);
        e.set_max_expr_depths(64, 32);
        e.set_max_string_size(MAX_WRITE_BYTES + 1024);
        e.set_max_array_size(2048);
        e.set_max_map_size(512);
        e.register_fn("sleep", |_: i64| -> Result<(), Box<rhai::EvalAltResult>> {
            Err("sleep is disabled in scripts".into())
        });
        e.register_fn("sleep", |_: f64| -> Result<(), Box<rhai::EvalAltResult>> {
            Err("sleep is disabled in scripts".into())
        });
        e.on_print(|_| {});
        e.on_debug(|_, _, _| {});
        e.on_progress(|_| match DEADLINE.get() {
            Some(d) if Instant::now() > d => Some(Dynamic::UNIT),
            _ => None,
        });
        e.register_type_with_name::<AlertView>("Alert");
        e.register_get("kind", |a: &mut AlertView| a.kind.clone());
        e.register_get("severity", |a: &mut AlertView| a.severity.clone());
        e.register_get("host", |a: &mut AlertView| a.host.clone());
        e.register_get("details", |a: &mut AlertView| a.details.clone());
        e.register_get("timestamp", |a: &mut AlertView| a.timestamp);
        let log_state = state.clone();
        e.register_fn("log", move |text: &str| {
            let mut s = log_state.lock().unwrap_or_else(|e| e.into_inner());
            if s.log.len() < MAX_LOG_LINES {
                s.log.push(clip(text));
            }
        });
        for (fn_name, append) in [("append_file", true), ("write_file", false)] {
            let (dir, state) = (dir.clone(), state.clone());
            e.register_fn(
                fn_name,
                move |name: &str, text: &str| -> Result<(), Box<rhai::EvalAltResult>> {
                    {
                        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                        if s.writes >= MAX_WRITES_PER_RUN {
                            return Err("too many file writes in one run".into());
                        }
                        s.writes += 1;
                    }
                    write_file(&dir, name, text, append).map_err(Into::into)
                },
            );
        }
        e
    }

    /// Runs `on_alert` for one alert. `Ok` carries the lines the script logged; `Err` says why
    /// the run failed (script error, limit hit). Either way the caller carries on.
    pub fn run(&self, alert: &Alert) -> Result<Vec<String>, String> {
        *self.state.lock().unwrap_or_else(|e| e.into_inner()) = RunState::default();
        let view = AlertView {
            kind: clip(&alert.kind),
            severity: alert.severity.name().to_string(),
            host: clip(&alert.subject),
            details: clip(&alert.message),
            timestamp: alert.timestamp,
        };
        DEADLINE.set(Some(Instant::now() + WALL_LIMIT));
        let result =
            self.engine
                .call_fn::<Dynamic>(&mut Scope::new(), &self.ast, "on_alert", (view,));
        DEADLINE.set(None);
        let log = std::mem::take(&mut self.state.lock().unwrap_or_else(|e| e.into_inner()).log);
        match result {
            Ok(_) => Ok(log),
            Err(e) => Err(format!("{}: {e}", self.name)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::Severity;

    fn alert(kind: &str) -> Alert {
        Alert {
            timestamp: 1_700_000_000,
            severity: Severity::High,
            kind: kind.into(),
            subject: "10.0.0.5".into(),
            message: "10.0.0.5: TCP port 23 opened".into(),
        }
    }
    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ns-onalert-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }
    fn script(src: &str, dir: &Path) -> AlertScript {
        AlertScript::from_source("t.rhai", src, dir).unwrap()
    }

    #[test]
    fn the_script_sees_the_alert_and_can_log_and_write_below_the_directory() {
        let d = dir("ok");
        let s = script(
            r#"fn on_alert(a) {
                log(`${a.severity} ${a.kind} ${a.host}`);
                append_file("alerts.log", a.details + "\n");
                append_file("alerts.log", a.timestamp.to_string() + "\n");
                write_file("last.txt", a.kind);
            }"#,
            &d,
        );
        let log = s.run(&alert("port-opened")).unwrap();
        assert_eq!(log, ["high port-opened 10.0.0.5"]);
        assert_eq!(
            std::fs::read_to_string(d.join("alerts.log")).unwrap(),
            "10.0.0.5: TCP port 23 opened\n1700000000\n"
        );
        s.run(&alert("new-device")).unwrap();
        assert_eq!(
            std::fs::read_to_string(d.join("last.txt")).unwrap(),
            "new-device"
        );
        assert_eq!(
            std::fs::read_to_string(d.join("alerts.log"))
                .unwrap()
                .lines()
                .count(),
            4,
            "append keeps earlier runs"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn file_names_cannot_leave_the_directory_or_name_devices() {
        for good in ["a.log", "alerts-2026_01.txt", "x"] {
            assert_eq!(safe_file_name(good), Ok(good));
        }
        for bad in [
            "",
            "../x",
            "..",
            "a/b",
            "a\\b",
            "/etc/passwd",
            "C:\\x",
            "C:x",
            "x:stream",
            ".hidden",
            "x.",
            "a..b",
            "CON",
            "con.txt",
            "NUL",
            "aux.log",
            "COM1",
            "lpt9.txt",
            "name with space",
            "ü.txt",
            &"a".repeat(65),
        ] {
            assert!(safe_file_name(bad).is_err(), "{bad:?} must be refused");
        }
        let d = dir("names");
        let s = script(
            r#"fn on_alert(a) { write_file("../escape.txt", "x"); }"#,
            &d,
        );
        let err = s.run(&alert("x")).unwrap_err();
        assert!(err.contains("file name"), "{err}");
        assert!(!d.parent().unwrap().join("escape.txt").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn write_limits_apply() {
        let d = dir("limits");
        let big = script(
            r#"fn on_alert(a) { let s = "x"; for i in 0..16 { s += s; } s += "y"; append_file("big.txt", s); }"#,
            &d,
        );
        // 2^16 + 1 bytes is one over the 64 KB limit of a call.
        let err = big.run(&alert("x")).unwrap_err();
        assert!(err.contains("limited to"), "{err}");
        assert!(!d.join("big.txt").exists());
        let many = script(
            r#"fn on_alert(a) { for i in 0..20 { append_file("m.txt", "x"); } }"#,
            &d,
        );
        let err = many.run(&alert("x")).unwrap_err();
        assert!(err.contains("too many"), "{err}");
        assert_eq!(std::fs::read_to_string(d.join("m.txt")).unwrap().len(), 16);
        // The counter is per run.
        assert!(many.run(&alert("x")).is_err());
        // A file stops growing at the cap.
        let fill = script(
            r#"fn on_alert(a) { let s = "x"; for i in 0..16 { s += s; } for i in 0..16 { append_file("f.txt", s); } }"#,
            &d,
        );
        assert!(fill.run(&alert("x")).is_ok(), "16 x 64 KB = 1 MB fits");
        let err = fill.run(&alert("x")).unwrap_err();
        assert!(err.contains("exceed"), "{err}");
        assert!(std::fs::metadata(d.join("f.txt")).unwrap().len() <= MAX_FILE_BYTES);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn runaway_and_hostile_scripts_are_contained() {
        let d = dir("hostile");
        let started = Instant::now();
        let err = script("fn on_alert(a) { loop { } }", &d)
            .run(&alert("x"))
            .unwrap_err();
        assert!(err.contains("t.rhai"), "{err}");
        assert!(
            script("fn on_alert(a) { let x = 0; while true { x += 1; } }", &d)
                .run(&alert("x"))
                .is_err()
        );
        assert!(
            script("fn on_alert(a) { sleep(3); }", &d)
                .run(&alert("x"))
                .is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(
            AlertScript::from_source("e.rhai", "fn on_alert(a) { eval(\"1\"); }", &d)
                .unwrap_err()
                .contains("eval")
        );
        // No network, process or other file access exists in the sandbox.
        for call in [
            "open(\"x\")",
            "connect(\"1.1.1.1:80\")",
            "run(\"cmd\")",
            "read_file(\"x\")",
            "http_get(\"http://x\")",
        ] {
            let err = script(&format!("fn on_alert(a) {{ {call}; }}"), &d)
                .run(&alert("x"))
                .unwrap_err();
            assert!(
                err.contains("Function not found") || err.contains("not found"),
                "{call}: {err}"
            );
        }
        // Logging is bounded.
        let log = script(r#"fn on_alert(a) { for i in 0..100 { log("line"); } }"#, &d)
            .run(&alert("x"))
            .unwrap();
        assert_eq!(log.len(), MAX_LOG_LINES);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_library_alert_scripts_run_against_fixture_alerts() {
        let d = dir("library");
        let source = |name: &str| {
            crate::script::ALERT_LIBRARY
                .iter()
                .find(|(n, _)| *n == name)
                .unwrap()
                .1
        };
        let fixture = [
            alert("new-device"),
            alert("port-opened"),
            alert("rogue-dhcp"),
        ];
        let all = AlertScript::from_source("log-alerts", source("log-alerts"), &d).unwrap();
        let services =
            AlertScript::from_source("new-service-log", source("new-service-log"), &d).unwrap();
        for a in &fixture {
            let logged = all.run(a).unwrap();
            assert_eq!(logged.len(), 1);
            assert!(
                logged[0].contains(&a.kind) && logged[0].contains("high"),
                "{logged:?}"
            );
            services.run(a).unwrap();
        }
        let log = std::fs::read_to_string(d.join("alerts.log")).unwrap();
        assert_eq!(log.lines().count(), 3, "{log}");
        assert!(
            log.lines()
                .next()
                .unwrap()
                .starts_with("1700000000 high new-device 10.0.0.5")
        );
        let new = std::fs::read_to_string(d.join("new-services.log")).unwrap();
        assert_eq!(
            new.lines().count(),
            1,
            "only port-opened is recorded: {new}"
        );
        assert!(new.contains("TCP port 23 opened"));
        // Every library alert script is covered here.
        assert_eq!(crate::script::ALERT_LIBRARY.len(), 2);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn scripts_without_on_alert_or_with_syntax_errors_are_rejected_at_load() {
        let d = dir("load");
        let err = AlertScript::from_source("a.rhai", "fn on_host(h) { }", &d).unwrap_err();
        assert!(err.contains("on_alert"), "{err}");
        assert!(
            AlertScript::from_source("b.rhai", "fn on_alert(a) {", &d)
                .unwrap_err()
                .contains("b.rhai")
        );
        assert!(AlertScript::load("no-such-file.rhai", &d).is_err());
    }

    /// A directory link: a junction on Windows (needs no privilege), a symlink elsewhere.
    #[cfg(windows)]
    fn dir_link(target: &Path, link: &Path) -> bool {
        std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .is_ok_and(|o| o.status.success())
    }
    #[cfg(unix)]
    fn dir_link(target: &Path, link: &Path) -> bool {
        std::os::unix::fs::symlink(target, link).is_ok()
    }

    /// A link put in place of the script folder (`alert-scripts` next to a service's inventory)
    /// must not send the writes elsewhere.
    #[test]
    fn a_script_folder_that_is_a_link_is_refused() {
        let d = dir("dirlink");
        let elsewhere = d.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let link = d.join("alert-scripts");
        if !dir_link(&elsewhere, &link) {
            eprintln!("skipped: no directory link could be created here");
            return;
        }
        let s = script(r#"fn on_alert(a) { write_file("x.txt", "x"); }"#, &link);
        let err = s.run(&alert("x")).unwrap_err();
        assert!(err.contains("link"), "{err}");
        assert!(!elsewhere.join("x.txt").exists());
        // A real folder, named in another case than on disk, still works.
        let real = d.join("Real");
        std::fs::create_dir_all(&real).unwrap();
        let other_case = if cfg!(any(windows, target_os = "macos")) {
            d.join("REAL")
        } else {
            real.clone()
        };
        script(
            r#"fn on_alert(a) { write_file("x.txt", "x"); }"#,
            &other_case,
        )
        .run(&alert("x"))
        .unwrap();
        assert!(real.join("x.txt").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[cfg(unix)]
    #[test]
    fn a_link_in_the_directory_is_not_followed() {
        let d = dir("link");
        std::fs::create_dir_all(&d).unwrap();
        let target = d.join("target.txt");
        std::fs::write(&target, "keep").unwrap();
        std::os::unix::fs::symlink(&target, d.join("l.txt")).unwrap();
        let s = script(r#"fn on_alert(a) { write_file("l.txt", "x"); }"#, &d);
        assert!(s.run(&alert("x")).unwrap_err().contains("link"));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        let _ = std::fs::remove_dir_all(&d);
    }
}
