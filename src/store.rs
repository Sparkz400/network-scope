use crate::{
    passive::Observation,
    scan::{Host, Settings},
};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
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

fn volatile(key: &str) -> bool {
    VOLATILE_IDENTITY_SUFFIXES.iter().any(|s| key.ends_with(s))
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
fn udp_probed_in_both(a: &Settings, b: &Settings) -> std::collections::BTreeSet<u16> {
    if !a.udp || !b.udp {
        return Default::default();
    }
    let parse = |s: &Settings| crate::scan::parse_ports(&s.udp_ports).unwrap_or_default();
    let other = parse(b);
    parse(a).into_iter().filter(|p| other.contains(p)).collect()
}

pub fn diff(a: &Snapshot, b: &Snapshot) -> Result<Vec<String>, String> {
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
    } && !volatile(key);
    let old: BTreeMap<_, _> = a.hosts.iter().map(|h| (h.ip, h)).collect();
    let new: BTreeMap<_, _> = b.hosts.iter().map(|h| (h.ip, h)).collect();
    let mut changes = vec![];
    for h in &b.hosts {
        let Some(previous) = old.get(&h.ip).filter(|p| p.responding) else {
            if h.responding {
                changes.push(format!("{}: new device observed", h.ip));
            }
            continue;
        };
        if !h.responding {
            changes.push(format!(
                "{}: no response in this scan (not proof of offline)",
                h.ip
            ));
            continue;
        }
        // Ports reported gone below; their per-port identity keys vanish with them and are not
        // listed again one by one.
        let mut gone_tcp = std::collections::BTreeSet::new();
        let mut gone_udp = std::collections::BTreeSet::new();
        if h.ports_checked && previous.ports_checked {
            for p in &h.open {
                if !previous.open.contains(p) {
                    changes.push(format!("{}: port {p} newly open", h.ip));
                }
            }
            for p in &previous.open {
                if !h.open.contains(p) {
                    changes.push(format!("{}: port {p} no longer observed open", h.ip));
                    gone_tcp.insert(*p);
                }
            }
        }
        // UDP silence means open|filtered, so only ports probed in both scans are compared and a
        // port that stops answering is not called closed.
        for p in &udp_probed {
            match (previous.udp_open.contains(p), h.udp_open.contains(p)) {
                (false, true) => changes.push(format!("{}: UDP port {p} newly answering", h.ip)),
                (true, false) => {
                    changes.push(format!(
                        "{}: UDP port {p} no longer answering (not proof of closure)",
                        h.ip
                    ));
                    gone_udp.insert(*p);
                }
                _ => {}
            }
        }
        for (key, value) in h.identity.iter().filter(|(k, _)| comparable(k)) {
            if let Some(old) = previous.identity.get(key) {
                if old != value {
                    changes.push(format!("{}: {key} changed: {old} → {value}", h.ip));
                }
            } else {
                changes.push(format!("{}: {key} identified: {value}", h.ip));
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
                changes.push(format!("{}: {key} no longer reported (was: {old})", h.ip));
            }
        }
        for (key, old, new) in [
            ("hostname", &previous.hostname, &h.hostname),
            ("MAC", &previous.mac, &h.mac),
        ] {
            if !old.is_empty() && !new.is_empty() && old != new {
                changes.push(format!("{}: {key} changed: {old} → {new}", h.ip));
            }
        }
    }
    for h in &a.hosts {
        if h.responding && !new.contains_key(&h.ip) {
            changes.push(format!("{}: not observed in new scan", h.ip));
        }
    }
    // Observations are a multiset per (mac, ip, protocol): identical records cancel out, leftover
    // new records pair with leftover old ones as "changed", and the rest are new.
    type ObsKey<'a> = (&'a str, Option<std::net::IpAddr>, &'a str);
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
    let subject = |o: &Observation| match o.ip {
        Some(ip) => format!("{} ({ip})", o.mac),
        None => o.mac.clone(),
    };
    for (key, o) in unmatched {
        let olds = previous.entry(key).or_default();
        if olds.pop().is_some() {
            changes.push(format!(
                "{} {}: observed identity changed",
                subject(o),
                o.protocol
            ));
        } else {
            changes.push(format!("{}: new {} observation", subject(o), o.protocol));
        }
    }
    Ok(changes)
}
pub fn export(snapshot: &Snapshot, format: &str) -> Result<String, String> {
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
        "html" => Ok(crate::report::html(snapshot, None, 0)),
        "nmap" | "xml" => Ok(crate::nmap::export(snapshot, 0)),
        _ => Err("Choose json, csv, html or nmap".into()),
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
}
