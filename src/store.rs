use crate::{
    passive::Observation,
    scan::{Host, Settings},
};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
    path::{Path, PathBuf},
};
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Snapshot {
    pub targets: String,
    pub complete: bool,
    pub settings: Settings,
    pub hosts: Vec<Host>,
    pub observations: Vec<Observation>,
    #[serde(default)]
    pub notes: BTreeMap<std::net::IpAddr, String>,
}
#[derive(Clone, Serialize)]
pub struct Entry {
    pub id: i64,
    pub timestamp: i64,
    pub targets: String,
    pub complete: bool,
    pub hosts: usize,
}
pub fn default_path() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("NetworkScope/inventory.sqlite")
}
/// Schema version stamped into `PRAGMA user_version` once the DDL below has run. Bump it (and add
/// only additive, idempotent statements) when the schema grows, so existing databases upgrade.
const SCHEMA_VERSION: i64 = 1;
const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, timestamp INTEGER NOT NULL, targets TEXT NOT NULL, complete INTEGER NOT NULL, hosts INTEGER NOT NULL, snapshot TEXT NOT NULL); CREATE TABLE IF NOT EXISTS known_devices(key TEXT PRIMARY KEY, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, timestamp INTEGER NOT NULL, scan_id INTEGER NOT NULL, severity TEXT NOT NULL, kind TEXT NOT NULL, subject TEXT NOT NULL, message TEXT NOT NULL);";
fn open(path: &Path) -> Result<Connection, String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let c = Connection::open(path).map_err(|e| e.to_string())?;
    c.busy_timeout(std::time::Duration::from_secs(3))
        .map_err(|e| e.to_string())?;
    // The DDL and the (persistent) WAL switch only need to run once per database file; later
    // opens just read the stamped schema version. Newer versions are left untouched.
    let version: i64 = c
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if version < SCHEMA_VERSION {
        c.execute_batch("PRAGMA journal_mode=WAL;")
            .map_err(|e| e.to_string())?;
        c.execute_batch(&format!(
            "BEGIN IMMEDIATE; {SCHEMA} PRAGMA user_version={SCHEMA_VERSION}; COMMIT;"
        ))
        .map_err(|e| e.to_string())?;
    }
    Ok(c)
}
pub fn save(path: &Path, snapshot: &Snapshot) -> Result<i64, String> {
    let mut c = open(path)?;
    let tx = c.transaction().map_err(|e| e.to_string())?;
    let data = serde_json::to_string(snapshot).map_err(|e| e.to_string())?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    tx.execute(
        "INSERT INTO scans(timestamp,targets,complete,hosts,snapshot) VALUES(?1,?2,?3,?4,?5)",
        params![
            timestamp,
            snapshot.targets,
            snapshot.complete,
            snapshot.hosts.len(),
            data
        ],
    )
    .map_err(|e| e.to_string())?;
    let id = tx.last_insert_rowid();
    tx.commit().map_err(|e| e.to_string())?;
    Ok(id)
}
pub fn list(path: &Path) -> Result<Vec<Entry>, String> {
    let c = open(path)?;
    let mut statement = c
        .prepare("SELECT id,timestamp,targets,complete,hosts FROM scans ORDER BY id DESC LIMIT 500")
        .map_err(|e| e.to_string())?;
    let rows = statement
        .query_map([], |r| {
            Ok(Entry {
                id: r.get(0)?,
                timestamp: r.get(1)?,
                targets: r.get(2)?,
                complete: r.get(3)?,
                hosts: r.get(4)?,
            })
        })
        .map_err(|e| e.to_string())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())
}
pub fn load(path: &Path, id: i64) -> Result<Snapshot, String> {
    let c = open(path)?;
    let data: String = c
        .query_row("SELECT snapshot FROM scans WHERE id=?1", [id], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    serde_json::from_str(&data).map_err(|e| e.to_string())
}
pub fn timestamp(path: &Path, id: i64) -> Result<i64, String> {
    open(path)?
        .query_row("SELECT timestamp FROM scans WHERE id=?1", [id], |r| {
            r.get(0)
        })
        .map_err(|e| e.to_string())
}
/// Newest completed scan of the same scope older than `before` (id, timestamp, snapshot).
pub fn latest_complete(
    path: &Path,
    targets: &str,
    before: i64,
) -> Result<Option<(i64, i64, Snapshot)>, String> {
    let c = open(path)?;
    let row = c
        .query_row(
            "SELECT id,timestamp,snapshot FROM scans WHERE complete=1 AND targets=?1 AND id<?2 ORDER BY id DESC LIMIT 1",
            params![targets, before],
            |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?)),
        )
        .map(Some)
        .or_else(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            e => Err(e),
        })
        .map_err(|e| e.to_string())?;
    row.map(|(id, ts, data)| {
        Ok((
            id,
            ts,
            serde_json::from_str(&data).map_err(|e| e.to_string())?,
        ))
    })
    .transpose()
}
/// device key -> (first seen, last seen)
pub fn known_devices(path: &Path) -> Result<std::collections::HashMap<String, (i64, i64)>, String> {
    let c = open(path)?;
    let mut s = c
        .prepare("SELECT key,first_seen,last_seen FROM known_devices")
        .map_err(|e| e.to_string())?;
    let rows = s
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                (r.get::<_, i64>(1)?, r.get::<_, i64>(2)?),
            ))
        })
        .map_err(|e| e.to_string())?;
    rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
}
pub fn touch_devices(path: &Path, keys: &[String], now: i64) -> Result<(), String> {
    let mut c = open(path)?;
    let tx = c.transaction().map_err(|e| e.to_string())?;
    for k in keys {
        tx.execute(
            "INSERT INTO known_devices(key,first_seen,last_seen) VALUES(?1,?2,?2) ON CONFLICT(key) DO UPDATE SET last_seen=?2",
            params![k, now],
        )
        .map_err(|e| e.to_string())?;
    }
    tx.commit().map_err(|e| e.to_string())
}
pub fn save_alerts(
    path: &Path,
    scan_id: i64,
    alerts: &[crate::monitor::Alert],
) -> Result<(), String> {
    let mut c = open(path)?;
    let tx = c.transaction().map_err(|e| e.to_string())?;
    for a in alerts {
        tx.execute(
            "INSERT INTO alerts(timestamp,scan_id,severity,kind,subject,message) VALUES(?1,?2,?3,?4,?5,?6)",
            params![a.timestamp, scan_id, a.severity.name(), a.kind, a.subject, a.message],
        )
        .map_err(|e| e.to_string())?;
    }
    tx.commit().map_err(|e| e.to_string())
}
pub fn list_alerts(path: &Path, limit: usize) -> Result<Vec<crate::monitor::Alert>, String> {
    let c = open(path)?;
    let mut s = c
        .prepare(
            "SELECT timestamp,severity,kind,subject,message FROM alerts ORDER BY id DESC LIMIT ?1",
        )
        .map_err(|e| e.to_string())?;
    let rows = s
        .query_map([limit as i64], |r| {
            Ok(crate::monitor::Alert {
                timestamp: r.get(0)?,
                severity: crate::risk::Severity::parse(&r.get::<_, String>(1)?)
                    .unwrap_or(crate::risk::Severity::Info),
                kind: r.get(2)?,
                subject: r.get(3)?,
                message: r.get(4)?,
            })
        })
        .map_err(|e| e.to_string())?;
    rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
}
/// Identity keys whose values change on every scan without anything changing on the device
/// (matched by suffix). Certificate expiry is still reported through `tls.<port>.expired`, which
/// only changes when the certificate actually crosses its expiry date.
pub const VOLATILE_IDENTITY_SUFFIXES: &[&str] = &[".days_left"];

/// Identity keys a diff skips: the built-in volatile suffixes plus user patterns.
///
/// A user pattern matches an identity key when it is equal to it, or as a glob where `*` stands
/// for any run of characters (`http.*.title`, `ssh.*`). A pattern that starts with `.` is a suffix
/// (`.days_left` = `*.days_left`), like the built-in list. Empty patterns are ignored.
#[derive(Clone, Debug, Default)]
pub struct IgnoreList {
    patterns: Vec<String>,
}

impl IgnoreList {
    /// Built-in volatile keys plus `extra` user patterns.
    pub fn new(extra: &[String]) -> Self {
        let mut patterns: Vec<String> = VOLATILE_IDENTITY_SUFFIXES
            .iter()
            .map(|s| format!("*{s}"))
            .collect();
        for p in extra.iter().map(|p| p.trim()).filter(|p| !p.is_empty()) {
            let p = if p.starts_with('.') {
                format!("*{p}")
            } else {
                p.to_string()
            };
            if !patterns.contains(&p) {
                patterns.push(p);
            }
        }
        Self { patterns }
    }
    /// Comma-separated user list (the `--ignore` option), on top of the built-in keys.
    #[allow(dead_code)] // Pending CLI wiring of `diff --ignore` (see NOTES-store-features.md).
    pub fn parse(list: &str) -> Self {
        Self::new(&list.split(',').map(str::to_string).collect::<Vec<_>>())
    }
    pub fn matches(&self, key: &str) -> bool {
        self.patterns.iter().any(|p| glob(p, key))
    }
    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }
}

/// `*` matches any run of characters (including none); everything else matches literally.
fn glob(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !text.starts_with(first) || !text.ends_with(last) || text.len() < first.len() + last.len() {
        return false;
    }
    let mut rest = &text[first.len()..text.len() - last.len()];
    for part in &parts[1..parts.len() - 1] {
        match rest.find(part) {
            Some(i) => rest = &rest[i + part.len()..],
            None => return false,
        }
    }
    true
}

/// Port number of a per-port identity key (`svc.22`, `tls.443.subject`, `udp.161`, ...).
fn key_port(key: &str) -> Option<(&str, u16)> {
    let mut parts = key.split('.');
    let family = parts.next()?;
    let port = parts.next()?.parse().ok()?;
    Some((family, port))
}

/// Detection settings that decide which ports and identity keys a scan can report. Scans that
/// differ in any of them cannot be compared without flooding the diff with spurious changes.
fn incompatible_settings(a: &Settings, b: &Settings) -> Vec<&'static str> {
    let ports = |s: &Settings| crate::scan::parse_ports(&s.ports).map_err(|_| s.ports.clone());
    let mut out = vec![];
    if ports(a) != ports(b) {
        out.push("TCP ports");
    }
    for (name, x, y) in [
        ("OT protocols", a.ot, b.ot),
        ("service detection", a.services, b.services),
        ("UDP probes", a.udp, b.udp),
        ("OS detection", a.os_detect, b.os_detect),
    ] {
        if x != y {
            out.push(name);
        }
    }
    out
}

/// UDP ports probed in both scans (empty unless both had UDP probing enabled).
pub(crate) fn udp_probed_in_both(a: &Settings, b: &Settings) -> std::collections::BTreeSet<u16> {
    if !a.udp || !b.udp {
        return Default::default();
    }
    let parse = |s: &Settings| crate::scan::parse_ports(&s.udp_ports).unwrap_or_default();
    let other = parse(b);
    parse(a).into_iter().filter(|p| other.contains(p)).collect()
}

/// One change between two scans, in the order the text diff lists them.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Change {
    /// Responding now, absent or silent before.
    HostAdded { ip: IpAddr },
    /// Listed in the new scan but did not respond (not proof of offline).
    HostSilent { ip: IpAddr },
    /// Responding before, not listed in the new scan at all.
    HostRemoved { ip: IpAddr },
    /// `protocol` is `tcp` or `udp`; UDP means "newly answering".
    PortOpened {
        ip: IpAddr,
        protocol: &'static str,
        port: u16,
    },
    /// TCP: no longer observed open. UDP: no longer answering (not proof of closure).
    PortClosed {
        ip: IpAddr,
        protocol: &'static str,
        port: u16,
    },
    IdentityAdded {
        ip: IpAddr,
        key: String,
        value: String,
    },
    IdentityChanged {
        ip: IpAddr,
        key: String,
        old: String,
        new: String,
    },
    IdentityRemoved {
        ip: IpAddr,
        key: String,
        old: String,
    },
    /// `attribute` is `hostname` or `MAC`.
    AttributeChanged {
        ip: IpAddr,
        attribute: &'static str,
        old: String,
        new: String,
    },
    ObservationNew {
        mac: String,
        ip: Option<IpAddr>,
        protocol: String,
    },
    ObservationChanged {
        mac: String,
        ip: Option<IpAddr>,
        protocol: String,
    },
}

impl Change {
    /// The human-readable line (unchanged from the original text diff).
    pub fn line(&self) -> String {
        let subject = |mac: &str, ip: &Option<IpAddr>| match ip {
            Some(ip) => format!("{mac} ({ip})"),
            None => mac.to_string(),
        };
        match self {
            Self::HostAdded { ip } => format!("{ip}: new device observed"),
            Self::HostSilent { ip } => {
                format!("{ip}: no response in this scan (not proof of offline)")
            }
            Self::HostRemoved { ip } => format!("{ip}: not observed in new scan"),
            Self::PortOpened {
                ip,
                protocol: "udp",
                port,
            } => format!("{ip}: UDP port {port} newly answering"),
            Self::PortOpened { ip, port, .. } => format!("{ip}: port {port} newly open"),
            Self::PortClosed {
                ip,
                protocol: "udp",
                port,
            } => format!("{ip}: UDP port {port} no longer answering (not proof of closure)"),
            Self::PortClosed { ip, port, .. } => {
                format!("{ip}: port {port} no longer observed open")
            }
            Self::IdentityAdded { ip, key, value } => format!("{ip}: {key} identified: {value}"),
            Self::IdentityChanged { ip, key, old, new } => {
                format!("{ip}: {key} changed: {old} → {new}")
            }
            Self::IdentityRemoved { ip, key, old } => {
                format!("{ip}: {key} no longer reported (was: {old})")
            }
            Self::AttributeChanged {
                ip,
                attribute,
                old,
                new,
            } => format!("{ip}: {attribute} changed: {old} → {new}"),
            Self::ObservationNew { mac, ip, protocol } => {
                format!("{}: new {protocol} observation", subject(mac, ip))
            }
            Self::ObservationChanged { mac, ip, protocol } => {
                format!("{} {protocol}: observed identity changed", subject(mac, ip))
            }
        }
    }
}

/// Counts per change category, for CI gates and monitors.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct DiffSummary {
    pub hosts_added: usize,
    pub hosts_removed: usize,
    pub hosts_silent: usize,
    pub tcp_opened: usize,
    pub tcp_closed: usize,
    pub udp_opened: usize,
    pub udp_closed: usize,
    pub identity_added: usize,
    pub identity_changed: usize,
    pub identity_removed: usize,
    pub attributes_changed: usize,
    pub observations_new: usize,
    pub observations_changed: usize,
    pub new_findings: usize,
    pub resolved_findings: usize,
    /// Highest severity among the new findings (absent when there are none).
    pub highest_new_severity: Option<crate::risk::Severity>,
}

/// Structured comparison of two completed scans of the same scope and settings.
#[derive(Clone, Debug, Serialize)]
pub struct DiffReport {
    pub summary: DiffSummary,
    /// Every change, in text-diff order; `kind` names the category.
    pub changes: Vec<Change>,
    /// Findings (matched by `risk::Finding::key`) present only in the new scan.
    pub new_findings: Vec<crate::risk::Finding>,
    /// Findings present only in the old scan whose evidence the new scan checked again.
    pub resolved_findings: Vec<crate::risk::Finding>,
    /// Findings present only in the old scan that the new scan did not re-check (host silent,
    /// port not checked or UDP port not probed): it cannot tell whether they were fixed.
    pub unconfirmed_findings: Vec<crate::risk::Finding>,
    /// Identity key patterns that were skipped (built-in volatile keys plus the user list).
    pub ignored_keys: Vec<String>,
}

impl DiffReport {
    /// The change lines of the original text diff (findings are not part of them).
    pub fn lines(&self) -> Vec<String> {
        self.changes.iter().map(Change::line).collect()
    }
    /// Plain-text rendering: the change lines followed by new, resolved and unconfirmed findings.
    pub fn text(&self) -> String {
        let mut out: Vec<String> = self.lines();
        let finding = |f: &crate::risk::Finding| {
            format!(
                "{} {}{} {} ({})",
                f.severity.name().to_ascii_uppercase(),
                f.ip,
                f.port.map_or(String::new(), |p| format!(":{p}")),
                f.title,
                f.id
            )
        };
        for (label, list) in [
            ("new finding", &self.new_findings),
            ("resolved finding", &self.resolved_findings),
            ("finding not re-checked", &self.unconfirmed_findings),
        ] {
            out.extend(list.iter().map(|f| format!("{label}: {}", finding(f))));
        }
        if out.is_empty() {
            "No changes.".into()
        } else {
            out.join("\n")
        }
    }
}

/// Renders a diff for the CLI: `json` (the `DiffReport`), `text` (lines plus findings) or
/// `lines` (the original JSON array of change lines, the default output of `diff`).
#[allow(dead_code)] // Pending CLI wiring of `diff --format` (see NOTES-store-features.md).
pub fn diff_output(
    a: &Snapshot,
    b: &Snapshot,
    format: &str,
    ignore: &IgnoreList,
) -> Result<String, String> {
    let report = diff_report(a, b, ignore)?;
    match format {
        "json" => serde_json::to_string_pretty(&report).map_err(|e| e.to_string()),
        "text" => Ok(report.text()),
        "lines" => serde_json::to_string_pretty(&report.lines()).map_err(|e| e.to_string()),
        _ => Err("Choose json, text or lines".into()),
    }
}

pub fn diff(a: &Snapshot, b: &Snapshot) -> Result<Vec<String>, String> {
    diff_report(a, b, &IgnoreList::new(&[])).map(|r| r.lines())
}

pub fn diff_report(a: &Snapshot, b: &Snapshot, ignore: &IgnoreList) -> Result<DiffReport, String> {
    if !a.complete || !b.complete {
        return Err("Compare two completed scans; partial scans do not establish changes.".into());
    }
    // Older imports stored the whole nmap command line as targets; compare the target part only.
    let (ta, tb) = (
        crate::nmap::scope_targets(&a.targets),
        crate::nmap::scope_targets(&b.targets),
    );
    let same_hosts =
        crate::scan::parse_targets(&ta, a.settings.skip_edges, crate::scan::MAX_STREAM)
            .ok()
            .zip(
                crate::scan::parse_targets(&tb, b.settings.skip_edges, crate::scan::MAX_STREAM)
                    .ok(),
            )
            .map(|(a, b)| a == b)
            .unwrap_or(ta == tb);
    if !same_hosts {
        return Err("Select scans with the same targets (the address ranges differ).".into());
    }
    let differing = incompatible_settings(&a.settings, &b.settings);
    if !differing.is_empty() {
        return Err(format!(
            "Select scans with the same scan settings (differs: {}).",
            differing.join(", ")
        ));
    }
    let udp_probed = udp_probed_in_both(&a.settings, &b.settings);
    // Identity keys about a UDP port only compare when that port was probed in both scans.
    let comparable = |key: &str| match key_port(key) {
        Some(("udp", p)) => udp_probed.contains(&p),
        _ => true,
    } && !ignore.matches(key);
    let old: BTreeMap<_, _> = a.hosts.iter().map(|h| (h.ip, h)).collect();
    let new: BTreeMap<_, _> = b.hosts.iter().map(|h| (h.ip, h)).collect();
    let mut changes = vec![];
    for h in &b.hosts {
        let ip = h.ip;
        let Some(previous) = old.get(&ip).filter(|p| p.responding) else {
            if h.responding {
                changes.push(Change::HostAdded { ip });
            }
            continue;
        };
        if !h.responding {
            changes.push(Change::HostSilent { ip });
            continue;
        }
        // Ports reported gone below; their per-port identity keys vanish with them and are not
        // listed again one by one.
        let mut gone_tcp = std::collections::BTreeSet::new();
        let mut gone_udp = std::collections::BTreeSet::new();
        if h.ports_checked && previous.ports_checked {
            for &port in &h.open {
                if !previous.open.contains(&port) {
                    changes.push(Change::PortOpened {
                        ip,
                        protocol: "tcp",
                        port,
                    });
                }
            }
            for &port in &previous.open {
                if !h.open.contains(&port) {
                    changes.push(Change::PortClosed {
                        ip,
                        protocol: "tcp",
                        port,
                    });
                    gone_tcp.insert(port);
                }
            }
        }
        // UDP silence means open|filtered, so only ports probed in both scans are compared and a
        // port that stops answering is not called closed.
        for &port in &udp_probed {
            match (
                previous.udp_open.contains(&port),
                h.udp_open.contains(&port),
            ) {
                (false, true) => changes.push(Change::PortOpened {
                    ip,
                    protocol: "udp",
                    port,
                }),
                (true, false) => {
                    changes.push(Change::PortClosed {
                        ip,
                        protocol: "udp",
                        port,
                    });
                    gone_udp.insert(port);
                }
                _ => {}
            }
        }
        for (key, value) in h.identity.iter().filter(|(k, _)| comparable(k)) {
            if let Some(old) = previous.identity.get(key) {
                if old != value {
                    changes.push(Change::IdentityChanged {
                        ip,
                        key: key.clone(),
                        old: old.clone(),
                        new: value.clone(),
                    });
                }
            } else {
                changes.push(Change::IdentityAdded {
                    ip,
                    key: key.clone(),
                    value: value.clone(),
                });
            }
        }
        for (key, old) in previous.identity.iter().filter(|(k, _)| comparable(k)) {
            if h.identity.contains_key(key) {
                continue;
            }
            let covered = match key_port(key) {
                Some(("udp", p)) => gone_udp.contains(&p),
                Some((_, p)) => gone_tcp.contains(&p),
                None => false,
            };
            if !covered {
                changes.push(Change::IdentityRemoved {
                    ip,
                    key: key.clone(),
                    old: old.clone(),
                });
            }
        }
        for (attribute, old, new) in [
            ("hostname", &previous.hostname, &h.hostname),
            ("MAC", &previous.mac, &h.mac),
        ] {
            if !old.is_empty() && !new.is_empty() && old != new {
                changes.push(Change::AttributeChanged {
                    ip,
                    attribute,
                    old: old.clone(),
                    new: new.clone(),
                });
            }
        }
    }
    for h in &a.hosts {
        if h.responding && !new.contains_key(&h.ip) {
            changes.push(Change::HostRemoved { ip: h.ip });
        }
    }
    // Observations are a multiset per (mac, ip, protocol): identical records cancel out, leftover
    // new records pair with leftover old ones as "changed", and the rest are new.
    type ObsKey<'a> = (&'a str, Option<IpAddr>, &'a str);
    let mut previous: HashMap<ObsKey, Vec<&BTreeMap<String, String>>> = HashMap::new();
    for o in &a.observations {
        previous
            .entry((o.mac.as_str(), o.ip, o.protocol.as_str()))
            .or_default()
            .push(&o.fields);
    }
    let mut unmatched = vec![];
    for o in &b.observations {
        let key = (o.mac.as_str(), o.ip, o.protocol.as_str());
        let olds = previous.entry(key).or_default();
        if let Some(i) = olds.iter().position(|f| **f == o.fields) {
            olds.swap_remove(i);
        } else {
            unmatched.push((key, o));
        }
    }
    for (key, o) in unmatched {
        let olds = previous.entry(key).or_default();
        let (mac, ip, protocol) = (o.mac.clone(), o.ip, o.protocol.clone());
        if olds.pop().is_some() {
            changes.push(Change::ObservationChanged { mac, ip, protocol });
        } else {
            changes.push(Change::ObservationNew { mac, ip, protocol });
        }
    }
    let (new_findings, resolved_findings, unconfirmed_findings) = finding_changes(a, b);
    let mut summary = DiffSummary::default();
    for c in &changes {
        let n = match c {
            Change::HostAdded { .. } => &mut summary.hosts_added,
            Change::HostSilent { .. } => &mut summary.hosts_silent,
            Change::HostRemoved { .. } => &mut summary.hosts_removed,
            Change::PortOpened {
                protocol: "udp", ..
            } => &mut summary.udp_opened,
            Change::PortOpened { .. } => &mut summary.tcp_opened,
            Change::PortClosed {
                protocol: "udp", ..
            } => &mut summary.udp_closed,
            Change::PortClosed { .. } => &mut summary.tcp_closed,
            Change::IdentityAdded { .. } => &mut summary.identity_added,
            Change::IdentityChanged { .. } => &mut summary.identity_changed,
            Change::IdentityRemoved { .. } => &mut summary.identity_removed,
            Change::AttributeChanged { .. } => &mut summary.attributes_changed,
            Change::ObservationNew { .. } => &mut summary.observations_new,
            Change::ObservationChanged { .. } => &mut summary.observations_changed,
        };
        *n += 1;
    }
    summary.new_findings = new_findings.len();
    summary.resolved_findings = resolved_findings.len();
    summary.highest_new_severity = new_findings.iter().map(|f| f.severity).max();
    Ok(DiffReport {
        summary,
        changes,
        new_findings,
        resolved_findings,
        unconfirmed_findings,
        ignored_keys: ignore.patterns().to_vec(),
    })
}

type Findings = Vec<crate::risk::Finding>;

/// New, resolved and unconfirmed findings by `Finding::key`. A finding that disappeared counts as
/// resolved only when the new scan looked at its evidence again: the host answered and the port
/// was checked again (TCP ports checked; UDP port probed in both scans), or, for findings from
/// passive traffic of a silent host, traffic was captured at all. Otherwise it is unconfirmed.
fn finding_changes(a: &Snapshot, b: &Snapshot) -> (Findings, Findings, Findings) {
    let (fa, fb) = (
        crate::risk::analyze_snapshot(a),
        crate::risk::analyze_snapshot(b),
    );
    let keys = |list: &[crate::risk::Finding]| {
        list.iter()
            .map(crate::risk::Finding::key)
            .collect::<std::collections::HashSet<_>>()
    };
    let (ka, kb) = (keys(&fa), keys(&fb));
    let old: HashMap<IpAddr, &crate::scan::Host> = a.hosts.iter().map(|h| (h.ip, h)).collect();
    let answered: HashMap<IpAddr, &crate::scan::Host> = b
        .hosts
        .iter()
        .filter(|h| h.responding)
        .map(|h| (h.ip, h))
        .collect();
    let udp_probed = udp_probed_in_both(&a.settings, &b.settings);
    // The new scan looked again at the evidence: the host answered, and a per-port finding's port
    // was checked again (TCP: ports checked; UDP: probed in both scans).
    let rechecked = |f: &crate::risk::Finding| {
        let Some(now) = answered.get(&f.ip) else {
            return f.port.is_none() && !b.observations.is_empty();
        };
        let Some(port) = f.port else { return true };
        let was_udp = old.get(&f.ip).is_some_and(|h| h.udp_open.contains(&port));
        let was_tcp = old.get(&f.ip).is_some_and(|h| h.open.contains(&port));
        (!was_udp || udp_probed.contains(&port)) && (!was_tcp || now.ports_checked)
    };
    let new = fb.into_iter().filter(|f| !ka.contains(&f.key())).collect();
    let (mut resolved, mut unconfirmed) = (vec![], vec![]);
    for f in fa.into_iter().filter(|f| !kb.contains(&f.key())) {
        let checked = rechecked(&f);
        if checked {
            resolved.push(f);
        } else {
            unconfirmed.push(f);
        }
    }
    (new, resolved, unconfirmed)
}

/// Timeline of one device (MAC or IP address) across every saved scan and capture, oldest first:
/// first/last seen, address, MAC and hostname changes, and port changes between comparable
/// completed scans. For the GUI and `devices --history`.
#[allow(dead_code)] // Pending CLI/GUI wiring (see NOTES-store-features.md).
pub fn device_history(path: &Path, query: &str) -> Result<crate::devices::DeviceHistory, String> {
    let key = crate::devices::HistoryKey::parse(query)?;
    let needles = key.needles();
    let c = open(path)?;
    let mut s = c
        .prepare("SELECT id,timestamp,snapshot FROM scans ORDER BY id ASC")
        .map_err(|e| e.to_string())?;
    let mut rows = s.query([]).map_err(|e| e.to_string())?;
    let mut history = crate::devices::HistoryBuilder::new(key, query);
    while let Some(r) = rows.next().map_err(|e| e.to_string())? {
        let (id, ts): (i64, i64) = (
            r.get(0).map_err(|e| e.to_string())?,
            r.get(1).map_err(|e| e.to_string())?,
        );
        let data: String = r.get(2).map_err(|e| e.to_string())?;
        // Cheap pre-filter: a snapshot that never spells the address cannot contain the device.
        let upper = data.to_ascii_uppercase();
        if !needles
            .iter()
            .any(|n| upper.contains(&n.to_ascii_uppercase()))
        {
            history.skip();
            continue;
        }
        match serde_json::from_str::<Snapshot>(&data) {
            Ok(snapshot) => history.add(id, ts, &snapshot),
            Err(_) => history.skip(),
        }
    }
    Ok(history.finish())
}

/// Export with no scan time (the HTML report and nmap XML then say "time not recorded").
/// Prefer [`export_at`] with the inventory timestamp when it is known.
pub fn export(snapshot: &Snapshot, format: &str) -> Result<String, String> {
    export_at(snapshot, format, 0)
}

/// Export in `json`, `csv`, `html`, `nmap`/`xml`, `md`/`markdown` or `jsonl`, stamping the
/// formats that carry a scan time (html, nmap, md, jsonl) with `timestamp` (Unix seconds; 0 =
/// not recorded).
pub fn export_at(snapshot: &Snapshot, format: &str, timestamp: i64) -> Result<String, String> {
    match format {
        "json" => serde_json::to_string_pretty(snapshot).map_err(|e| e.to_string()),
        "csv" => {
            let mut out = String::from(
                "IP,MAC,Responding,Hostname,Open ports,Identity,Observation protocol,Note\r\n",
            );
            let mut row = |fields: Vec<String>| {
                out.push_str(
                    &fields
                        .iter()
                        .map(|s| crate::scan::csv_cell(s))
                        .collect::<Vec<_>>()
                        .join(","),
                );
                out.push_str("\r\n");
            };
            for h in &snapshot.hosts {
                row(vec![
                    h.ip.to_string(),
                    h.mac.clone(),
                    h.responding.to_string(),
                    h.hostname.clone(),
                    h.open
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(" "),
                    serde_json::to_string(&h.identity).unwrap_or_default(),
                    String::new(),
                    snapshot.notes.get(&h.ip).cloned().unwrap_or_default(),
                ]);
            }
            for o in &snapshot.observations {
                row(vec![
                    o.ip.map(|v| v.to_string()).unwrap_or_default(),
                    o.mac.clone(),
                    "observed".into(),
                    String::new(),
                    String::new(),
                    serde_json::to_string(&o.fields).unwrap_or_default(),
                    o.protocol.clone(),
                    String::new(),
                ]);
            }
            Ok(out)
        }
        "html" => Ok(crate::report::html(snapshot, None, timestamp)),
        "nmap" | "xml" => Ok(crate::nmap::export(snapshot, timestamp)),
        "md" | "markdown" => Ok(crate::report::markdown(snapshot, None, timestamp)),
        "jsonl" => crate::report::jsonl(snapshot, timestamp),
        _ => Err("Choose json, csv, html, nmap, md or jsonl".into()),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot() -> Snapshot {
        Snapshot {
            targets: "127.0.0.1".into(),
            complete: true,
            settings: Settings::default(),
            hosts: vec![Host {
                ip: "127.0.0.1".parse().unwrap(),
                responding: true,
                ping: None,
                ttl: None,
                hostname: "<script>".into(),
                mac: String::new(),
                open: vec![502],
                closed: 0,
                unanswered: 0,
                errors: vec![],
                ports_checked: true,
                identity: BTreeMap::from([("Modbus.firmware".into(), "1.0".into())]),
                udp_open: vec![],
                trace: vec![],
            }],
            observations: vec![],
            notes: BTreeMap::new(),
        }
    }
    #[test]
    fn inventory_roundtrip_and_semantic_diff() {
        let path = std::env::temp_dir().join(format!(
            "netscope-test-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let a = snapshot();
        let id = save(&path, &a).unwrap();
        let mut b = load(&path, id).unwrap();
        assert_eq!(list(&path).unwrap()[0].id, id);
        b.hosts[0].open.push(4840);
        b.hosts[0]
            .identity
            .insert("Modbus.firmware".into(), "2.0".into());
        let changes = diff(&a, &b).unwrap();
        assert!(changes.iter().any(|s| s.contains("4840 newly open")));
        assert!(changes.iter().any(|s| s.contains("firmware changed")));
        b.complete = false;
        assert!(diff(&a, &b).is_err());
        std::fs::remove_file(path).unwrap();
    }
    fn temp_db(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "netscope-{tag}-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn remove_db(path: &Path) {
        for suffix in ["", "-wal", "-shm"] {
            let mut p = path.as_os_str().to_owned();
            p.push(suffix);
            let _ = std::fs::remove_file(PathBuf::from(p));
        }
    }

    #[test]
    fn volatile_identity_keys_are_not_reported() {
        let mut a = snapshot();
        a.hosts[0]
            .identity
            .insert("tls.443.days_left".into(), "40".into());
        a.hosts[0]
            .identity
            .insert("tls.443.expired".into(), "false".into());
        let mut b = a.clone();
        b.hosts[0]
            .identity
            .insert("tls.443.days_left".into(), "39".into());
        assert_eq!(diff(&a, &b).unwrap(), Vec::<String>::new());
        // Gaining or losing only the volatile key is not reported either.
        b.hosts[0].identity.remove("tls.443.days_left");
        assert_eq!(diff(&a, &b).unwrap(), Vec::<String>::new());
        // Expiry is reported once, when the expired flag flips.
        b.hosts[0]
            .identity
            .insert("tls.443.expired".into(), "true".into());
        let changes = diff(&a, &b).unwrap();
        assert_eq!(changes.len(), 1, "{changes:?}");
        assert!(changes[0].contains("tls.443.expired changed: false → true"));
    }

    #[test]
    fn removed_identity_keys_are_reported() {
        let mut a = snapshot();
        a.hosts[0].open = vec![22, 502];
        for (k, v) in [
            ("ssh.22.weak", "diffie-hellman-group1-sha1"),
            ("svc.502", "modbus"),
            ("svc.502.product", "PLC"),
        ] {
            a.hosts[0].identity.insert(k.into(), v.into());
        }
        let mut b = a.clone();
        b.hosts[0].identity.remove("ssh.22.weak");
        let changes = diff(&a, &b).unwrap();
        assert_eq!(
            changes,
            ["127.0.0.1: ssh.22.weak no longer reported (was: diffie-hellman-group1-sha1)"]
        );
        // A port that closed is reported once, not once per identity key it carried.
        b.hosts[0].open = vec![22];
        b.hosts[0].identity.retain(|k, _| !k.starts_with("svc.502"));
        b.hosts[0].identity.remove("Modbus.firmware");
        let changes = diff(&a, &b).unwrap();
        assert!(changes
            .iter()
            .any(|c| c.contains("port 502 no longer observed open")));
        assert!(changes
            .iter()
            .any(|c| c.contains("Modbus.firmware no longer reported")));
        assert!(
            !changes.iter().any(|c| c.contains("svc.502")),
            "{changes:?}"
        );
    }

    #[test]
    fn udp_ports_diff_only_when_probed_in_both() {
        let mut a = snapshot();
        a.settings.udp = true;
        a.settings.udp_ports = "161,1900".into();
        let mut b = a.clone();
        b.settings.udp_ports = "53,161".into();
        b.hosts[0].udp_open = vec![53, 161];
        b.hosts[0]
            .identity
            .insert("udp.53".into(), "DNS answer".into());
        b.hosts[0]
            .identity
            .insert("udp.161".into(), "SNMP sysDescr: x".into());
        let changes = diff(&a, &b).unwrap();
        assert_eq!(
            changes,
            [
                "127.0.0.1: UDP port 161 newly answering",
                "127.0.0.1: udp.161 identified: SNMP sysDescr: x"
            ],
            "port 53 was not probed in the old scan"
        );
        let changes = diff(&b, &a).unwrap();
        assert_eq!(
            changes,
            ["127.0.0.1: UDP port 161 no longer answering (not proof of closure)"]
        );
        // Without UDP probing in both scans nothing UDP is compared (and the scans are refused).
        let mut c = b.clone();
        c.settings.udp = false;
        assert!(diff(&a, &c).unwrap_err().contains("UDP probes"));
    }

    #[test]
    fn detection_settings_must_match_and_are_named() {
        let a = snapshot();
        let mut b = a.clone();
        b.settings.services = true;
        b.settings.os_detect = true;
        let e = diff(&a, &b).unwrap_err();
        assert!(
            e.contains("service detection") && e.contains("OS detection"),
            "{e}"
        );
        let mut b = a.clone();
        b.settings.ports = "8080, 443,80".into();
        assert!(diff(&a, &b).is_ok(), "same port set written differently");
        b.settings.ports = "1-1000".into();
        assert!(diff(&a, &b).unwrap_err().contains("TCP ports"));
    }

    #[test]
    fn observation_diff_is_a_multiset_per_mac_ip_protocol() {
        let obs = |ip: &str, name: &str| Observation {
            protocol: "DHCP".into(),
            mac: "AA:BB:CC:00:11:22".into(),
            ip: Some(ip.parse().unwrap()),
            fields: BTreeMap::from([("hostname".into(), name.into())]),
        };
        let mut a = snapshot();
        a.observations = vec![
            obs("10.0.0.1", "x"),
            obs("10.0.0.2", "y"),
            obs("10.0.0.2", "y"),
        ];
        let mut b = a.clone();
        b.observations.reverse();
        assert_eq!(diff(&a, &b).unwrap(), Vec::<String>::new());
        b.observations[0]
            .fields
            .insert("hostname".into(), "z".into());
        assert_eq!(
            diff(&a, &b).unwrap(),
            ["AA:BB:CC:00:11:22 (10.0.0.2) DHCP: observed identity changed"]
        );
        b.observations.push(obs("10.0.0.2", "w"));
        let changes = diff(&a, &b).unwrap();
        assert_eq!(
            changes,
            [
                "AA:BB:CC:00:11:22 (10.0.0.2) DHCP: observed identity changed",
                "AA:BB:CC:00:11:22 (10.0.0.2): new DHCP observation"
            ]
        );
    }

    #[test]
    fn old_imports_with_full_nmap_args_compare_by_target() {
        let mut a = snapshot();
        a.targets = "nmap -sV -oX a.xml 127.0.0.1".into();
        let mut b = a.clone();
        b.targets = "nmap -sV -oX b.xml 127.0.0.1".into();
        assert!(diff(&a, &b).is_ok());
        b.targets = "nmap -sV -oX b.xml 127.0.0.2".into();
        assert!(diff(&a, &b).unwrap_err().contains("targets"));
    }

    #[test]
    fn open_initialises_once_and_upgrades_legacy_databases() {
        let path = temp_db("schema");
        {
            // A database written by an older version: tables exist, user_version is 0.
            let c = Connection::open(&path).unwrap();
            c.execute_batch(SCHEMA).unwrap();
            c.execute(
                "INSERT INTO scans(timestamp,targets,complete,hosts,snapshot) VALUES(1,'x',1,0,?1)",
                [serde_json::to_string(&snapshot()).unwrap()],
            )
            .unwrap();
        }
        let version = |c: &Connection| -> i64 {
            c.query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap()
        };
        let c = open(&path).unwrap();
        assert_eq!(version(&c), SCHEMA_VERSION);
        let mode: String = c
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        drop(c);
        assert_eq!(list(&path).unwrap().len(), 1, "existing rows survive");
        assert_eq!(load(&path, 1).unwrap().targets, "127.0.0.1");
        // Later opens skip the DDL and keep working; a newer schema is never downgraded.
        open(&path)
            .unwrap()
            .execute_batch("PRAGMA user_version=99")
            .unwrap();
        assert_eq!(version(&open(&path).unwrap()), 99);
        save(&path, &snapshot()).unwrap();
        assert_eq!(list(&path).unwrap().len(), 2);
        remove_db(&path);
        // A fresh file gets the schema.
        let fresh = temp_db("fresh");
        assert_eq!(version(&open(&fresh).unwrap()), SCHEMA_VERSION);
        assert!(list(&fresh).unwrap().is_empty());
        remove_db(&fresh);
    }

    #[test]
    fn report_escapes_device_content() {
        let mut s = snapshot();
        s.hosts[0]
            .identity
            .insert("name".into(), "<script>alert(1)</script>".into());
        let html = export(&s, "html").unwrap();
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }

    fn host(ip: &str, open: &[u16], identity: &[(&str, &str)]) -> Host {
        Host {
            ip: ip.parse().unwrap(),
            responding: true,
            ping: None,
            ttl: None,
            hostname: String::new(),
            mac: String::new(),
            open: open.to_vec(),
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity: identity
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            udp_open: vec![],
            trace: vec![],
        }
    }

    #[test]
    fn diff_report_is_structured_and_text_is_derived_from_it() {
        let mut a = snapshot();
        a.targets = "10.0.0.1-3".into();
        a.hosts = vec![
            host("10.0.0.1", &[22], &[("svc.22", "ssh OpenSSH 9.6p1")]),
            host("10.0.0.2", &[80], &[]),
        ];
        let mut b = a.clone();
        b.hosts[0].open.push(443);
        b.hosts[0]
            .identity
            .insert("svc.22".into(), "ssh OpenSSH 9.7p1".into());
        b.hosts[0].hostname = "new".into();
        b.hosts.remove(1);
        b.hosts.push(host("10.0.0.3", &[], &[]));
        let report = diff_report(&a, &b, &IgnoreList::new(&[])).unwrap();
        assert_eq!(report.lines(), diff(&a, &b).unwrap());
        assert_eq!(
            report.changes[0],
            Change::PortOpened {
                ip: "10.0.0.1".parse().unwrap(),
                protocol: "tcp",
                port: 443
            }
        );
        let s = &report.summary;
        assert_eq!(
            (
                s.tcp_opened,
                s.identity_changed,
                s.hosts_added,
                s.hosts_removed
            ),
            (1, 1, 1, 1)
        );
        let json: serde_json::Value =
            serde_json::from_str(&diff_output(&a, &b, "json", &IgnoreList::new(&[])).unwrap())
                .unwrap();
        assert_eq!(json["changes"][0]["kind"], "port_opened");
        assert_eq!(json["changes"][0]["protocol"], "tcp");
        assert_eq!(json["changes"][1]["kind"], "identity_changed");
        assert_eq!(json["changes"][1]["old"], "ssh OpenSSH 9.6p1");
        assert_eq!(json["summary"]["hosts_removed"], 1);
        assert_eq!(json["ignored_keys"][0], "*.days_left");
        let lines: Vec<String> =
            serde_json::from_str(&diff_output(&a, &b, "lines", &IgnoreList::new(&[])).unwrap())
                .unwrap();
        assert_eq!(lines, diff(&a, &b).unwrap());
        assert!(diff_output(&a, &b, "xml", &IgnoreList::new(&[])).is_err());
        // UDP changes are categorised separately.
        a.settings.udp = true;
        a.settings.udp_ports = "161".into();
        let mut c = a.clone();
        c.hosts[0].udp_open = vec![161];
        let r = diff_report(&a, &c, &IgnoreList::new(&[])).unwrap();
        assert_eq!((r.summary.udp_opened, r.summary.tcp_opened), (1, 0));
    }

    #[test]
    fn diff_reports_new_resolved_and_unconfirmed_findings() {
        let mut a = snapshot();
        a.targets = "10.0.0.1-2".into();
        a.hosts = vec![
            host("10.0.0.1", &[23], &[("svc.23", "telnet")]),
            host("10.0.0.2", &[21], &[("svc.21", "ftp")]),
        ];
        let mut b = a.clone();
        // Telnet closed and FTP opened on .1; .2 stopped answering.
        b.hosts[0] = host("10.0.0.1", &[21], &[("svc.21", "ftp")]);
        b.hosts[1].responding = false;
        let r = diff_report(&a, &b, &IgnoreList::new(&[])).unwrap();
        let ids =
            |l: &[crate::risk::Finding]| -> Vec<String> { l.iter().map(|f| f.key()).collect() };
        assert_eq!(ids(&r.new_findings), ["10.0.0.1|21|ftp-cleartext"]);
        assert_eq!(ids(&r.resolved_findings), ["10.0.0.1|23|telnet-open"]);
        assert_eq!(ids(&r.unconfirmed_findings), ["10.0.0.2|21|ftp-cleartext"]);
        assert_eq!(r.summary.new_findings, 1);
        assert_eq!(
            r.summary.highest_new_severity,
            Some(crate::risk::Severity::Medium)
        );
        let text = r.text();
        assert!(text.contains("new finding: MEDIUM 10.0.0.1:21"), "{text}");
        assert!(
            text.contains("resolved finding: HIGH 10.0.0.1:23"),
            "{text}"
        );
        assert!(text.contains("not re-checked"), "{text}");
        // Findings never leak into the legacy change lines.
        assert!(!diff(&a, &b).unwrap().iter().any(|l| l.contains("finding")));
        let same = diff_report(&a, &a, &IgnoreList::new(&[])).unwrap();
        assert_eq!(same.text(), "No changes.");
        // A UDP finding whose port the new scan did not probe is not "resolved".
        let mut a = snapshot();
        a.settings.udp = true;
        a.settings.udp_ports = "161".into();
        a.hosts[0].udp_open = vec![161];
        a.hosts[0]
            .identity
            .insert("udp.161".into(), "SNMP sysDescr: x".into());
        let mut b = a.clone();
        b.settings.udp_ports = "53".into();
        b.hosts[0].udp_open.clear();
        b.hosts[0].identity.remove("udp.161");
        let r = diff_report(&a, &b, &IgnoreList::new(&[])).unwrap();
        assert!(r.resolved_findings.is_empty(), "{r:?}");
        assert_eq!(ids(&r.unconfirmed_findings), ["127.0.0.1|161|snmp-public"]);
        // Probed in both and silent now: resolved.
        b.settings.udp_ports = "161".into();
        let r = diff_report(&a, &b, &IgnoreList::new(&[])).unwrap();
        assert_eq!(ids(&r.resolved_findings), ["127.0.0.1|161|snmp-public"]);
    }

    #[test]
    fn ignore_list_combines_builtin_and_user_patterns() {
        let list = IgnoreList::parse("http.*.title, .server ,snmp.uptime,,");
        assert!(list.matches("tls.443.days_left"), "built-in stays");
        assert!(list.matches("http.80.title"));
        assert!(!list.matches("http.80.titles"));
        assert!(list.matches("http.8080.server"));
        assert!(list.matches("snmp.uptime"));
        assert!(!list.matches("snmp.uptime2"));
        assert!(!list.matches("svc.80"));
        assert!(glob("a*b*c", "aXbYc") && !glob("a*b*c", "aXcYb"));
        assert!(glob("*", "") && !glob("ab*ba", "aba"));
        assert!(!glob("é*é", "é"), "no slicing inside a character");
        let mut a = snapshot();
        a.hosts[0]
            .identity
            .insert("http.80.title".into(), "a".into());
        let mut b = a.clone();
        b.hosts[0]
            .identity
            .insert("http.80.title".into(), "b".into());
        assert_eq!(diff(&a, &b).unwrap().len(), 1);
        let r = diff_report(&a, &b, &list).unwrap();
        assert!(r.changes.is_empty());
        assert!(r.ignored_keys.contains(&"*.server".to_string()));
    }

    #[test]
    fn export_at_stamps_the_scan_time_in_every_timed_format() {
        let s = snapshot();
        let ts = 1_700_000_000;
        assert!(export_at(&s, "html", ts)
            .unwrap()
            .contains("2023-11-14 22:13 UTC"));
        assert!(export_at(&s, "nmap", ts)
            .unwrap()
            .contains("start=\"1700000000\""));
        assert!(export_at(&s, "md", ts)
            .unwrap()
            .contains("2023-11-14 22:13 UTC"));
        let line = export_at(&s, "jsonl", ts).unwrap();
        let v: serde_json::Value = serde_json::from_str(line.lines().next().unwrap()).unwrap();
        assert_eq!(v["timestamp"], ts);
        // Without a known time the exports say so instead of inventing 1970.
        assert!(export(&s, "html").unwrap().contains("time not recorded"));
        assert!(export(&s, "markdown")
            .unwrap()
            .contains("time not recorded"));
        assert!(export(&s, "pdf").unwrap_err().contains("md or jsonl"));
    }

    #[test]
    fn device_history_follows_a_mac_across_scans() {
        let path = temp_db("history");
        let mac = "aa-bb-cc-00-11-22";
        let mut s1 = snapshot();
        s1.targets = "10.0.0.0/24".into();
        s1.hosts = vec![host("10.0.0.5", &[22], &[])];
        s1.hosts[0].mac = mac.into();
        s1.hosts[0].hostname = "plc".into();
        let mut s2 = s1.clone();
        s2.hosts[0].ip = "10.0.0.6".parse().unwrap();
        s2.hosts[0].open = vec![22, 80];
        // A partial scan that lost port 22 says nothing about it.
        let mut partial = s2.clone();
        partial.complete = false;
        partial.hosts[0].open = vec![80];
        let mut other = s1.clone();
        other.hosts[0].mac = "11:22:33:44:55:66".into();
        for s in [&s1, &other, &s2, &partial] {
            save(&path, s).unwrap();
        }
        let h = device_history(&path, "AA:BB:CC:00:11:22").unwrap();
        assert_eq!(h.key, "mac");
        assert_eq!((h.sightings, h.scans), (3, 4));
        assert_eq!((h.first_scan, h.last_scan), (Some(1), Some(4)));
        assert_eq!(h.ips.len(), 2);
        assert_eq!(h.macs, ["AA:BB:CC:00:11:22"]);
        assert_eq!(h.open_tcp, [22, 80]);
        let kinds: Vec<_> = h.events.iter().map(|e| e.kind).collect();
        assert_eq!(kinds, ["first-seen", "ip-changed", "port-opened"], "{h:?}");
        assert!(h.events[1].detail.contains("10.0.0.5 → 10.0.0.6"));
        // Keyed by IP: the device that held 10.0.0.5, including the MAC change.
        let by_ip = device_history(&path, "10.0.0.5").unwrap();
        assert_eq!((by_ip.key, by_ip.sightings), ("ip", 2));
        assert!(by_ip.events.iter().any(|e| e.kind == "mac-changed"));
        let text = crate::devices::history_output(&by_ip, "text").unwrap();
        assert!(text.contains("Seen in 2 of 4 saved scans"), "{text}");
        assert!(device_history(&path, "not-a-device").is_err());
        let none = device_history(&path, "10.9.9.9").unwrap();
        assert_eq!((none.sightings, none.scans), (0, 4));
        remove_db(&path);
    }
}
