//! User scripts (Rhai) that post-process every scanned host: add custom fields and findings or
//! policy checks. Scripts run in a
//! sandbox: no file, network, process or module access, an operation budget and a wall-clock limit.
//!
//! ```rhai
//! fn on_host(h) {
//!     if h.has_port(23) { h.finding("high", "lab-telnet", "Telnet in the lab", "port 23 open"); }
//!     h.set("owner", if h.vendor.contains("Siemens") { "automation" } else { "it" });
//! }
//! ```
use crate::{risk::Severity, scan::Host};
use rhai::{AST, Array, Dynamic, Engine, Scope};
use std::{
    cell::Cell,
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const WALL_LIMIT: Duration = Duration::from_millis(250);

macro_rules! library {
    ($dir:literal: $($file:literal),* $(,)?) => {
        &[$(($file, include_str!(concat!("../../scripts/library/", $dir, $file, ".rhai")))),*]
    };
}
/// The shared script library (`scripts/library/*.rhai`, embedded so an installed binary has it):
/// scripts with `on_host`, for `scan --script library:NAME` (or `library` for all of them).
pub const LIBRARY: &[(&str, &str)] = library!(
    "":
    "cert-expiry-report",
    "default-credentials-hint",
    "device-class-tags",
    "ot-asset-summary",
    "service-baseline",
    "smbv1-hosts",
    "unexpected-admin-ports",
    "weak-tls-summary",
);
/// The library's `on_alert` examples (`scripts/library/on-alert/*.rhai`) for `monitor --on-alert`.
pub const ALERT_LIBRARY: &[(&str, &str)] = library!("on-alert/": "log-alerts", "new-service-log");

/// What `scripts list` shows about one library script (from its header comment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibraryEntry {
    pub name: String,
    /// `host` (`on_host`, for `scan --script`) or `alert` (`on_alert`, for `monitor --on-alert`).
    pub kind: String,
    pub description: String,
    pub safety: String,
    /// File below `scripts/library/`.
    pub file: String,
}

/// The value of `// key: value` in the leading comment block of a script.
fn header(source: &str, key: &str) -> String {
    source
        .lines()
        .take_while(|l| l.trim_start().starts_with("//"))
        .filter_map(|l| {
            l.trim_start()
                .strip_prefix("//")?
                .trim()
                .strip_prefix(key)?
                .strip_prefix(':')
        })
        .map(|v| v.trim().to_string())
        .next()
        .unwrap_or_default()
}

/// Every library script, host scripts first, each group by name.
pub fn library() -> Vec<LibraryEntry> {
    let entry = |dir: &str, (name, source): &(&str, &str)| LibraryEntry {
        name: header(source, "name"),
        kind: header(source, "kind"),
        description: header(source, "description"),
        safety: header(source, "safety"),
        file: format!("{dir}{name}.rhai"),
    };
    LIBRARY
        .iter()
        .map(|e| entry("", e))
        .chain(ALERT_LIBRARY.iter().map(|e| entry("on-alert/", e)))
        .collect()
}

/// The source of a library script by its name (`smbv1-hosts`).
pub fn library_source(name: &str) -> Option<&'static str> {
    LIBRARY
        .iter()
        .chain(ALERT_LIBRARY)
        .find(|(file, _)| *file == name)
        .map(|(_, source)| *source)
}

thread_local! {
    static DEADLINE: Cell<Option<Instant>> = const { Cell::new(None) };
}

struct Data {
    ip: String,
    hostname: String,
    mac: String,
    ttl: i64,
    ping: i64,
    open: Vec<i64>,
    udp: Vec<i64>,
    identity: BTreeMap<String, String>,
    sets: Vec<(String, String)>,
    findings: Vec<(String, String, String, String)>,
    notes: Vec<String>,
}
#[derive(Clone)]
struct H(Arc<Mutex<Data>>);
impl H {
    fn lock(&self) -> std::sync::MutexGuard<'_, Data> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn clean_key(s: &str) -> String {
    s.chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}
fn clip(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(500).collect()
}

#[derive(Debug)]
pub struct Scripts {
    engine: Engine,
    asts: Vec<(String, AST)>,
}

impl Scripts {
    fn engine() -> Engine {
        let mut e = Engine::new();
        e.disable_symbol("eval");
        e.set_max_operations(500_000);
        e.set_max_call_levels(32);
        e.set_max_expr_depths(64, 32);
        e.set_max_string_size(16 * 1024);
        e.set_max_array_size(2048);
        e.set_max_map_size(512);
        // The built-in sleep blocks without reaching on_progress and would bypass the wall limit.
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
        e.register_type_with_name::<H>("Host");
        e.register_get("ip", |h: &mut H| h.lock().ip.clone());
        e.register_get("hostname", |h: &mut H| h.lock().hostname.clone());
        e.register_get("mac", |h: &mut H| h.lock().mac.clone());
        e.register_get("ttl", |h: &mut H| h.lock().ttl);
        e.register_get("ping", |h: &mut H| h.lock().ping);
        e.register_get("open", |h: &mut H| -> Array {
            h.lock().open.iter().map(|p| Dynamic::from(*p)).collect()
        });
        e.register_get("udp", |h: &mut H| -> Array {
            h.lock().udp.iter().map(|p| Dynamic::from(*p)).collect()
        });
        e.register_get("os", |h: &mut H| {
            h.lock()
                .identity
                .get("os.guess")
                .cloned()
                .unwrap_or_default()
        });
        e.register_get("vendor", |h: &mut H| {
            h.lock()
                .identity
                .get("mac.vendor")
                .cloned()
                .unwrap_or_default()
        });
        e.register_get("device", |h: &mut H| {
            h.lock()
                .identity
                .get("device.type")
                .cloned()
                .unwrap_or_default()
        });
        e.register_fn("has_port", |h: &mut H, p: i64| h.lock().open.contains(&p));
        e.register_fn("identity", |h: &mut H, key: &str| {
            h.lock().identity.get(key).cloned().unwrap_or_default()
        });
        e.register_fn("service", |h: &mut H, port: i64| {
            h.lock()
                .identity
                .get(&format!("svc.{port}"))
                .cloned()
                .unwrap_or_default()
        });
        e.register_fn("has_service", |h: &mut H, name: &str| {
            let name = name.to_ascii_lowercase();
            h.lock().identity.iter().any(|(k, v)| {
                k.starts_with("svc.")
                    && !k.ends_with(".product")
                    && !k.ends_with(".version")
                    && v.to_ascii_lowercase().contains(&name)
            })
        });
        e.register_fn("set", |h: &mut H, key: &str, value: &str| {
            let mut d = h.lock();
            if d.sets.len() < 64 {
                let (k, v) = (clean_key(key), clip(value));
                d.identity.insert(format!("script.{k}"), v.clone());
                d.sets.push((k, v));
            }
        });
        e.register_fn(
            "finding",
            |h: &mut H, severity: &str, id: &str, title: &str, evidence: &str| {
                let mut d = h.lock();
                if d.findings.len() < 32 {
                    let sev = Severity::parse(severity)
                        .unwrap_or(Severity::Info)
                        .name()
                        .to_string();
                    d.findings
                        .push((clean_key(id), sev, clip(title), clip(evidence)));
                }
            },
        );
        e.register_fn("note", |h: &mut H, msg: &str| {
            let mut d = h.lock();
            if d.notes.len() < 8 {
                d.notes.push(clip(msg));
            }
        });
        e
    }

    pub fn from_sources(sources: &[(String, String)]) -> Result<Self, String> {
        let engine = Self::engine();
        let mut asts = vec![];
        for (name, text) in sources {
            let ast = engine.compile(text).map_err(|e| format!("{name}: {e}"))?;
            asts.push((name.clone(), ast));
        }
        Ok(Self { engine, asts })
    }

    /// A `.rhai` file, a directory of them (sorted by name), `library` (every `on_host` script
    /// of the shared library) or `library:NAME` (one of them).
    pub fn load(path: &str) -> Result<Self, String> {
        if path == "library" {
            let sources: Vec<(String, String)> = LIBRARY
                .iter()
                .map(|(name, text)| (format!("{name}.rhai"), (*text).to_string()))
                .collect();
            return Self::from_sources(&sources);
        }
        if let Some(name) = path.strip_prefix("library:") {
            let text = LIBRARY
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, t)| *t)
                .ok_or_else(|| format!("{path}: no such library script; see `scripts list`"))?;
            return Self::from_sources(&[(format!("{name}.rhai"), text.to_string())]);
        }
        let p = Path::new(path);
        let mut files = vec![];
        if p.is_dir() {
            for entry in std::fs::read_dir(p).map_err(|e| format!("{path}: {e}"))? {
                let f = entry.map_err(|e| e.to_string())?.path();
                if f.extension().is_some_and(|x| x == "rhai") {
                    files.push(f);
                }
            }
            files.sort();
        } else {
            files.push(p.to_path_buf());
        }
        if files.is_empty() {
            return Err(format!("{path}: no .rhai scripts found"));
        }
        let mut sources = vec![];
        for f in files {
            let text = std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
            if text.len() > 256 * 1024 {
                return Err(format!("{}: script is larger than 256 KB", f.display()));
            }
            sources.push((
                f.file_name()
                    .map_or(String::new(), |n| n.to_string_lossy().into_owned()),
                text,
            ));
        }
        Self::from_sources(&sources)
    }

    pub fn describe(&self) -> Vec<String> {
        self.asts
            .iter()
            .map(|(name, ast)| {
                let hooks: Vec<&str> = ast.iter_functions().map(|f| f.name).collect();
                format!(
                    "{name}: {}",
                    if hooks.contains(&"on_host") {
                        "defines on_host"
                    } else {
                        "no on_host function (ignored)"
                    }
                )
            })
            .collect()
    }

    /// Runs every script's `on_host`. The wall-clock limit is shared by all scripts of one host:
    /// once it is spent, the remaining scripts are skipped with a note.
    pub fn run_host(&self, host: &mut Host) {
        self.run_host_within(host, WALL_LIMIT);
    }

    /// Runs the scripts against a copy of `host` and reports what they produced. `host` itself is
    /// not changed; [`Outcome::apply`] adds the result to a host later.
    pub fn dry_run(&self, host: &Host) -> Outcome {
        let mut copy = host.clone();
        self.run_host_within(&mut copy, WALL_LIMIT)
    }

    fn run_host_within(&self, host: &mut Host, budget: Duration) -> Outcome {
        let data = H(Arc::new(Mutex::new(Data {
            ip: host.ip.to_string(),
            hostname: host.hostname.clone(),
            mac: host.mac.clone(),
            ttl: host.ttl.map_or(-1, i64::from),
            ping: host.ping.map_or(-1, i64::from),
            open: host.open.iter().map(|p| i64::from(*p)).collect(),
            udp: host.udp_open.iter().map(|p| i64::from(*p)).collect(),
            identity: host.identity.clone(),
            sets: vec![],
            findings: vec![],
            notes: vec![],
        })));
        let deadline = Instant::now() + budget;
        for (name, ast) in &self.asts {
            if !ast.iter_functions().any(|f| f.name == "on_host") {
                continue;
            }
            if Instant::now() >= deadline {
                let mut d = data.lock();
                if d.notes.len() < 8 {
                    d.notes.push(clip(&format!(
                        "script {name}: skipped, time limit for this host used up"
                    )));
                }
                continue;
            }
            DEADLINE.set(Some(deadline));
            let result =
                self.engine
                    .call_fn::<Dynamic>(&mut Scope::new(), ast, "on_host", (data.clone(),));
            DEADLINE.set(None);
            if let Err(e) = result {
                let mut d = data.lock();
                if d.notes.len() < 8 {
                    d.notes.push(clip(&format!("script {name}: {e}")));
                }
            }
        }
        let d = data.lock();
        let outcome = Outcome {
            sets: d.sets.clone(),
            findings: d
                .findings
                .iter()
                .map(|(id, severity, title, evidence)| ScriptFinding {
                    id: id.clone(),
                    severity: severity.clone(),
                    title: title.clone(),
                    evidence: evidence.clone(),
                })
                .collect(),
            notes: d.notes.clone(),
        };
        outcome.apply(host);
        outcome
    }
}

/// A finding added by a script (`h.finding(...)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptFinding {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub evidence: String,
}

/// What the scripts produced for one host: fields set, findings and notes (errors included).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    pub sets: Vec<(String, String)>,
    pub findings: Vec<ScriptFinding>,
    pub notes: Vec<String>,
}
impl Outcome {
    /// Stores the result on a host exactly as a scan does.
    pub fn apply(&self, host: &mut Host) {
        for (k, v) in &self.sets {
            host.identity.insert(format!("script.{k}"), v.clone());
        }
        for f in &self.findings {
            host.identity.insert(
                format!("finding.script.{}", f.id),
                format!(
                    "{}|{}|{}",
                    f.severity,
                    f.title.replace('|', "/"),
                    f.evidence
                ),
            );
        }
        for n in &self.notes {
            if host.errors.len() < 8 {
                host.errors.push(format!("Script: {n}"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> Host {
        Host {
            ip: "10.0.0.5".parse().unwrap(),
            responding: true,
            ping: Some(3),
            ttl: Some(64),
            hostname: "lab-1".into(),
            mac: "AA:BB:CC:00:00:01".into(),
            open: vec![22, 23, 80],
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity: [
                ("svc.80", "http nginx 1.18.0"),
                ("svc.80.product", "nginx"),
                ("os.guess", "Linux"),
                ("mac.vendor", "Siemens AG"),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            udp_open: vec![161],
            trace: vec![],
        }
    }
    fn scripts(src: &str) -> Scripts {
        Scripts::from_sources(&[("t.rhai".into(), src.into())]).unwrap()
    }

    #[test]
    fn scripts_read_hosts_and_add_fields_and_findings() {
        let s = scripts(
            r#"
            fn on_host(h) {
                if h.has_port(23) { h.finding("HIGH", "lab telnet!", "Telnet | in the lab", "port 23 open on " + h.ip); }
                let ports = 0;
                for p in h.open { ports += 1; }
                h.set("port count", `${ports}`);
                h.set("owner", if h.vendor.contains("Siemens") { "automation" } else { "it" });
                if h.has_service("nginx") && h.os == "Linux" { h.set("stack", h.service(80)); }
                if h.udp.contains(161) { h.note("snmp answered"); }
                h.finding("bogus-level", "odd", "Unknown severity falls back", "");
            }
            "#,
        );
        let mut h = host();
        s.run_host(&mut h);
        assert_eq!(h.identity["script.port_count"], "3");
        assert_eq!(h.identity["script.owner"], "automation");
        assert_eq!(h.identity["script.stack"], "http nginx 1.18.0");
        assert_eq!(
            h.identity["finding.script.lab_telnet_"],
            "high|Telnet / in the lab|port 23 open on 10.0.0.5"
        );
        assert_eq!(
            h.identity["finding.script.odd"],
            "info|Unknown severity falls back|"
        );
        assert_eq!(h.errors, ["Script: snmp answered"]);
        let findings = crate::risk::analyze_host(&h);
        assert!(
            findings
                .iter()
                .any(|f| f.id == "script-lab_telnet_" && f.severity == Severity::High)
        );
    }

    #[test]
    fn runaway_and_hostile_scripts_are_contained() {
        let mut h = host();
        scripts("fn on_host(h) { loop { } }").run_host(&mut h);
        assert!(h.errors[0].contains("script t.rhai"), "{:?}", h.errors);
        let mut h = host();
        let started = Instant::now();
        scripts("fn on_host(h) { let x = 0; while true { x += 1; } }").run_host(&mut h);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(
            Scripts::from_sources(&[("e.rhai".into(), "fn on_host(h) { eval(\"1\"); }".into())])
                .unwrap_err()
                .contains("eval"),
            "eval is disabled"
        );
        let mut h = host();
        scripts("fn f(n) { f(n + 1) } fn on_host(h) { f(0); }").run_host(&mut h);
        assert!(!h.errors.is_empty(), "unbounded recursion is stopped");
        let mut h = host();
        scripts("fn on_host(h) { let s = \"x\"; for i in 0..40 { s += s; } }").run_host(&mut h);
        assert!(!h.errors.is_empty(), "string growth is capped");
        let mut h = host();
        scripts("fn on_host(h) { for i in 0..500 { h.set(`k${i}`, \"v\"); h.note(\"n\"); } }")
            .run_host(&mut h);
        assert_eq!(
            h.identity
                .keys()
                .filter(|k| k.starts_with("script."))
                .count(),
            64
        );
        assert_eq!(h.errors.len(), 8);
        // Nothing in the sandbox can reach the file system or the process.
        let mut h = host();
        scripts("fn on_host(h) { let f = open(\"x\"); }").run_host(&mut h);
        assert!(!h.errors.is_empty());
    }

    #[test]
    fn wall_limit_is_shared_by_all_scripts_of_a_host() {
        let s = Scripts::from_sources(&[
            (
                "a.rhai".into(),
                "fn on_host(h) { h.set(\"a\", \"1\"); let t = timestamp(); while t.elapsed < 0.02 { } }".into(),
            ),
            (
                "b.rhai".into(),
                "fn on_host(h) { h.set(\"b\", \"2\"); }".into(),
            ),
        ])
        .unwrap();
        // Script a uses the whole (tiny) budget by the clock; b must not get a fresh one.
        let mut h = host();
        s.run_host_within(&mut h, Duration::from_millis(5));
        assert_eq!(h.identity.get("script.a").map(String::as_str), Some("1"));
        assert!(!h.identity.contains_key("script.b"), "{:?}", h.errors);
        assert!(
            h.errors
                .iter()
                .any(|e| e.contains("b.rhai") && e.contains("skipped")),
            "{:?}",
            h.errors
        );
        let mut h = host();
        s.run_host_within(&mut h, Duration::from_secs(5));
        assert_eq!(h.identity["script.b"], "2");
        assert!(h.errors.is_empty(), "{:?}", h.errors);
    }

    #[test]
    fn sleeping_cannot_outlast_the_wall_limit() {
        let started = Instant::now();
        let mut h = host();
        scripts("fn on_host(h) { sleep(3); h.set(\"late\", \"1\"); }").run_host(&mut h);
        assert!(started.elapsed() < Duration::from_secs(1), "{:?}", h.errors);
        assert!(!h.identity.contains_key("script.late"));
        assert!(h.errors[0].contains("sleep"), "{:?}", h.errors);
        let started = Instant::now();
        let mut h = host();
        scripts("fn on_host(h) { sleep(2.5); }").run_host(&mut h);
        assert!(started.elapsed() < Duration::from_secs(1), "{:?}", h.errors);
    }

    #[test]
    fn dry_run_reports_without_changing_the_host_and_applies_like_a_scan() {
        let s = scripts(
            r#"
            fn on_host(h) {
                h.set("owner", "ot");
                h.finding("high", "telnet", "Telnet open", "port 23");
                h.note("checked");
                h.nosuch();
            }
            "#,
        );
        let original = host();
        let outcome = s.dry_run(&original);
        assert_eq!(outcome.sets, [("owner".to_string(), "ot".to_string())]);
        assert_eq!(outcome.findings.len(), 1);
        assert_eq!(outcome.findings[0].severity, "high");
        assert_eq!(outcome.notes[0], "checked");
        assert!(outcome.notes[1].contains("t.rhai"), "{:?}", outcome.notes);
        assert!(!original.identity.contains_key("script.owner"));
        let mut applied = host();
        outcome.apply(&mut applied);
        let mut scanned = host();
        s.run_host(&mut scanned);
        assert_eq!(applied.identity, scanned.identity);
        assert_eq!(applied.errors, scanned.errors);
    }

    fn lib_host(open: &[u16], udp: &[u16], identity: &[(&str, &str)]) -> Host {
        let mut h = host();
        h.open = open.to_vec();
        h.udp_open = udp.to_vec();
        h.identity = identity
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        h
    }
    /// Runs one library script on a copy of `h`; returns the finding ids (`finding.script.<id>`
    /// keys), the `script.*` fields and the script errors.
    fn run_library(name: &str, h: &Host) -> (Vec<String>, BTreeMap<String, String>, Vec<String>) {
        let s = Scripts::load(&format!("library:{name}")).unwrap();
        let mut h = h.clone();
        s.run_host(&mut h);
        let findings = h
            .identity
            .keys()
            .filter_map(|k| k.strip_prefix("finding.script."))
            .map(str::to_string)
            .collect();
        let fields = h
            .identity
            .iter()
            .filter_map(|(k, v)| Some((k.strip_prefix("script.")?.to_string(), v.clone())))
            .collect();
        (findings, fields, h.errors)
    }

    #[test]
    fn every_library_script_has_a_header_and_a_test_case() {
        let entries = library();
        assert!(entries.len() >= 6 + 2, "{entries:?}");
        for e in &entries {
            assert!(!e.name.is_empty() && !e.description.is_empty(), "{e:?}");
            assert!(
                e.safety.to_lowercase().contains("no ") || e.safety.contains("only"),
                "{e:?}"
            );
            assert!(e.kind == "host" || e.kind == "alert", "{e:?}");
            assert!(
                e.file.starts_with(&e.name) || e.file.ends_with(&format!("{}.rhai", e.name)),
                "{e:?}"
            );
        }
        // The embedded table is the folder: no script on disk is missing from it, none is stale.
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/library");
        for (sub, table) in [("", LIBRARY), ("on-alert", ALERT_LIBRARY)] {
            let mut on_disk: Vec<String> = std::fs::read_dir(root.join(sub))
                .unwrap()
                .filter_map(|e| {
                    let name = e.unwrap().file_name().to_string_lossy().into_owned();
                    name.strip_suffix(".rhai").map(str::to_string)
                })
                .collect();
            on_disk.sort();
            let listed: Vec<String> = table.iter().map(|(n, _)| n.to_string()).collect();
            assert_eq!(on_disk, listed, "scripts/library/{sub}");
        }
        // Host scripts define on_host, alert scripts on_alert; the kind header says which.
        for (name, source) in LIBRARY {
            assert_eq!(header(source, "name"), *name);
            assert_eq!(header(source, "kind"), "host");
            assert!(source.contains("fn on_host("));
        }
        for (name, source) in ALERT_LIBRARY {
            assert_eq!(header(source, "name"), *name);
            assert_eq!(header(source, "kind"), "alert");
            assert!(source.contains("fn on_alert("));
        }
        assert!(library_source("smbv1-hosts").is_some() && library_source("nope").is_none());
        // `library` loads all host scripts at once and every one compiles.
        assert_eq!(
            Scripts::load("library").unwrap().describe().len(),
            LIBRARY.len()
        );
        assert!(
            Scripts::load("library:nope")
                .unwrap_err()
                .contains("scripts list")
        );
    }

    #[test]
    fn library_scripts_fire_on_a_positive_host_and_stay_silent_on_a_clean_one() {
        // (script, finding ids on the positive host, the same on the clean host)
        let cases: Vec<(&str, Host, Vec<&str>, Host)> = vec![
            (
                "smbv1-hosts",
                lib_host(&[445], &[], &[("smb.445.smb1", "accepted")]),
                vec!["smbv1-host"],
                lib_host(&[445], &[], &[("smb.445.smb1", "refused")]),
            ),
            (
                "cert-expiry-report",
                lib_host(
                    &[443],
                    &[],
                    &[("tls.443.days_left", "20"), ("tls.443.expired", "false")],
                ),
                vec!["cert-expiry-60d"],
                lib_host(
                    &[443],
                    &[],
                    &[("tls.443.days_left", "300"), ("tls.443.expired", "false")],
                ),
            ),
            (
                "unexpected-admin-ports",
                lib_host(&[22, 23, 3389], &[], &[]),
                vec!["admin-ports-open"],
                lib_host(&[22, 443], &[], &[]),
            ),
            (
                "ot-asset-summary",
                lib_host(
                    &[502],
                    &[],
                    &[("Modbus.vendor", "Schneider"), ("S7.name", "CPU 1214C")],
                ),
                vec!["ot-asset-summary"],
                lib_host(&[80], &[], &[("svc.80", "http nginx")]),
            ),
            (
                "service-baseline",
                lib_host(&[22, 8080], &[], &[]),
                vec!["service-not-in-baseline"],
                lib_host(&[22, 443], &[], &[]),
            ),
            (
                "weak-tls-summary",
                lib_host(&[443], &[], &[("tls.443.weak", "RC4; 3DES (Sweet32)")]),
                vec!["weak-tls-summary"],
                lib_host(&[443], &[], &[("tls.443.versions", "TLS1.2")]),
            ),
            (
                "default-credentials-hint",
                lib_host(&[23], &[], &[]),
                vec!["default-credentials-hint"],
                lib_host(&[22], &[], &[("mac.vendor", "Dell Inc.")]),
            ),
            (
                "device-class-tags",
                lib_host(&[502], &[], &[]),
                vec![],
                lib_host(&[], &[], &[]),
            ),
        ];
        let mut tested: Vec<&str> = cases.iter().map(|c| c.0).collect();
        tested.sort_unstable();
        let listed: Vec<&str> = LIBRARY.iter().map(|(n, _)| *n).collect();
        assert_eq!(tested, listed, "every library script needs a test case");
        for (name, positive, want, clean) in cases {
            let (ids, _, errors) = run_library(name, &positive);
            assert_eq!(ids, want, "{name} on the positive host");
            assert!(errors.is_empty(), "{name}: {errors:?}");
            let (ids, _, errors) = run_library(name, &clean);
            assert!(ids.is_empty(), "{name} on the clean host: {ids:?}");
            assert!(errors.is_empty(), "{name}: {errors:?}");
        }
    }

    #[test]
    fn library_scripts_report_what_they_read() {
        let (_, fields, _) = run_library(
            "cert-expiry-report",
            &lib_host(
                &[443, 8443],
                &[],
                &[("tls.443.days_left", "20"), ("tls.8443.days_left", "7")],
            ),
        );
        assert_eq!(fields["cert_days_left"], "7", "the soonest certificate");
        let (ids, _, _) = run_library(
            "cert-expiry-report",
            &lib_host(
                &[443],
                &[],
                &[
                    ("tls.443.expired", "true"),
                    ("tls.443.days_left", "garbage"),
                ],
            ),
        );
        assert_eq!(
            ids,
            ["cert-expired-report"],
            "an unparsable value is skipped"
        );
        let h = lib_host(&[22, 23, 3389, 80], &[], &[]);
        let s = Scripts::load("library:unexpected-admin-ports").unwrap();
        let outcome = s.dry_run(&h);
        assert_eq!(outcome.findings[0].severity, "medium");
        assert_eq!(outcome.findings[0].evidence, "Telnet (23), RDP (3389)");
        let (ids, _, _) = run_library(
            "weak-tls-summary",
            &lib_host(&[443], &[], &[("tls.443.weak", "RC4")]),
        );
        assert_eq!(ids, ["weak-tls-summary"]);
        let outcome = Scripts::load("library:weak-tls-summary")
            .unwrap()
            .dry_run(&lib_host(
                &[443],
                &[],
                &[("tls.443.weak", "no forward secrecy")],
            ));
        assert_eq!(
            outcome.findings[0].severity, "medium",
            "severe only for broken suites"
        );
        let (_, fields, _) = run_library(
            "ot-asset-summary",
            &lib_host(
                &[502],
                &[],
                &[
                    ("Modbus.vendor", "Schneider"),
                    ("S7.name", "CPU"),
                    ("S7.firmware", "4.2"),
                ],
            ),
        );
        assert_eq!(fields["ot_protocols"], "Modbus, S7");
        assert_eq!(
            fields["ot_summary"],
            "Modbus: vendor Schneider; S7: name CPU, firmware 4.2"
        );
        for (ports, class) in [
            (vec![502], "ot"),
            (vec![9100], "printer"),
            (vec![554], "camera"),
            (vec![22], "server"),
            (vec![3389], "workstation"),
            (vec![], "other"),
        ] {
            let (_, fields, _) = run_library("device-class-tags", &lib_host(&ports, &[], &[]));
            assert_eq!(fields["class"], class, "{ports:?}");
        }
        // The hint never claims a weakness: it is an info finding about a kind of device.
        let outcome = Scripts::load("library:default-credentials-hint")
            .unwrap()
            .dry_run(&lib_host(
                &[80],
                &[161],
                &[("mac.vendor", "Hikvision Digital")],
            ));
        assert_eq!(outcome.findings[0].severity, "info");
        assert!(
            outcome.findings[0].evidence.contains("Hikvision")
                && outcome.findings[0].evidence.contains("SNMP")
        );
    }

    #[test]
    fn compile_errors_and_loading() {
        assert!(
            Scripts::from_sources(&[("bad.rhai".into(), "fn on_host(h) {".into())])
                .unwrap_err()
                .contains("bad.rhai")
        );
        let s = scripts("fn helper() { 1 }");
        assert_eq!(s.describe(), ["t.rhai: no on_host function (ignored)"]);
        let mut h = host();
        s.run_host(&mut h);
        assert!(h.errors.is_empty());
        let dir = std::env::temp_dir().join(format!("ns-scripts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("b.rhai"), "fn on_host(h) { h.set(\"b\", \"2\"); }").unwrap();
        std::fs::write(dir.join("a.rhai"), "fn on_host(h) { h.set(\"a\", \"1\"); }").unwrap();
        std::fs::write(dir.join("notes.txt"), "ignored").unwrap();
        let s = Scripts::load(dir.to_str().unwrap()).unwrap();
        assert_eq!(s.describe().len(), 2);
        assert!(s.describe()[0].starts_with("a.rhai"));
        let mut h = host();
        s.run_host(&mut h);
        assert_eq!(
            (
                h.identity["script.a"].as_str(),
                h.identity["script.b"].as_str()
            ),
            ("1", "2")
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert!(Scripts::load(dir.to_str().unwrap()).is_err());
        let empty = std::env::temp_dir().join(format!("ns-empty-{}", std::process::id()));
        std::fs::create_dir_all(&empty).unwrap();
        assert!(
            Scripts::load(empty.to_str().unwrap())
                .unwrap_err()
                .contains("no .rhai")
        );
        let _ = std::fs::remove_dir_all(&empty);
    }
}
