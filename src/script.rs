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
use rhai::{Array, Dynamic, Engine, Scope, AST};
use std::{
    cell::Cell,
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const WALL_LIMIT: Duration = Duration::from_millis(250);

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

    /// A `.rhai` file, or a directory of them (sorted by name).
    pub fn load(path: &str) -> Result<Self, String> {
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

    fn run_host_within(&self, host: &mut Host, budget: Duration) {
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
        for (k, v) in &d.sets {
            host.identity.insert(format!("script.{k}"), v.clone());
        }
        for (id, sev, title, evidence) in &d.findings {
            host.identity.insert(
                format!("finding.script.{id}"),
                format!("{sev}|{}|{}", title.replace('|', "/"), evidence),
            );
        }
        for n in &d.notes {
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
        assert!(findings
            .iter()
            .any(|f| f.id == "script-lab_telnet_" && f.severity == Severity::High));
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
        let spin = "let t = timestamp(); while t.elapsed < 0.06 { }";
        let s = Scripts::from_sources(&[
            (
                "a.rhai".into(),
                format!("fn on_host(h) {{ {spin} h.set(\"a\", \"1\"); }}"),
            ),
            (
                "b.rhai".into(),
                format!("fn on_host(h) {{ {spin} h.set(\"b\", \"2\"); }}"),
            ),
            (
                "c.rhai".into(),
                "fn on_host(h) { h.set(\"c\", \"3\"); }".into(),
            ),
        ])
        .unwrap();
        // Each script alone fits the budget; together they do not.
        let mut h = host();
        s.run_host_within(&mut h, Duration::from_millis(100));
        assert_eq!(h.identity.get("script.a").map(String::as_str), Some("1"));
        assert!(!h.identity.contains_key("script.b"), "{:?}", h.errors);
        assert!(!h.identity.contains_key("script.c"), "{:?}", h.errors);
        assert!(
            h.errors.iter().any(|e| e.contains("b.rhai")),
            "{:?}",
            h.errors
        );
        assert!(
            h.errors
                .iter()
                .any(|e| e.contains("c.rhai") && e.contains("skipped")),
            "{:?}",
            h.errors
        );
        let mut h = host();
        s.run_host_within(&mut h, Duration::from_secs(5));
        assert_eq!(h.identity["script.c"], "3");
        assert!(h.errors.is_empty(), "{:?}", h.errors);
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
        assert!(Scripts::load(empty.to_str().unwrap())
            .unwrap_err()
            .contains("no .rhai"));
        let _ = std::fs::remove_dir_all(&empty);
    }
}
