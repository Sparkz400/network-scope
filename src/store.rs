use crate::{
    passive::Observation,
    scan::{Host, Settings},
};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
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
fn open(path: &Path) -> Result<Connection, String> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let c = Connection::open(path).map_err(|e| e.to_string())?;
    c.busy_timeout(std::time::Duration::from_secs(3))
        .map_err(|e| e.to_string())?;
    c.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY, timestamp INTEGER NOT NULL, targets TEXT NOT NULL, complete INTEGER NOT NULL, hosts INTEGER NOT NULL, snapshot TEXT NOT NULL); CREATE TABLE IF NOT EXISTS known_devices(key TEXT PRIMARY KEY, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, timestamp INTEGER NOT NULL, scan_id INTEGER NOT NULL, severity TEXT NOT NULL, kind TEXT NOT NULL, subject TEXT NOT NULL, message TEXT NOT NULL);").map_err(|e|e.to_string())?;
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
pub fn diff(a: &Snapshot, b: &Snapshot) -> Result<Vec<String>, String> {
    if !a.complete || !b.complete {
        return Err("Compare two completed scans; partial scans do not establish changes.".into());
    }
    let same_hosts =
        crate::scan::parse_targets(&a.targets, a.settings.skip_edges, crate::scan::MAX_STREAM)
            .ok()
            .zip(
                crate::scan::parse_targets(
                    &b.targets,
                    b.settings.skip_edges,
                    crate::scan::MAX_STREAM,
                )
                .ok(),
            )
            .map(|(a, b)| a == b)
            .unwrap_or(a.targets == b.targets);
    if !same_hosts || a.settings.ports != b.settings.ports || a.settings.ot != b.settings.ot {
        return Err("Select scans with the same targets and scan settings.".into());
    }
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
        if h.ports_checked && previous.ports_checked {
            for p in &h.open {
                if !previous.open.contains(p) {
                    changes.push(format!("{}: port {p} newly open", h.ip));
                }
            }
            for p in &previous.open {
                if !h.open.contains(p) {
                    changes.push(format!("{}: port {p} no longer observed open", h.ip));
                }
            }
        }
        for (key, value) in &h.identity {
            if let Some(old) = previous.identity.get(key) {
                if old != value {
                    changes.push(format!("{}: {key} changed: {old} → {value}", h.ip));
                }
            } else {
                changes.push(format!("{}: {key} identified: {value}", h.ip));
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
    for o in &b.observations {
        if let Some(old) = a
            .observations
            .iter()
            .find(|p| p.mac == o.mac && p.protocol == o.protocol)
        {
            if old.fields != o.fields || old.ip != o.ip {
                changes.push(format!(
                    "{} {}: observed identity changed",
                    o.mac, o.protocol
                ));
            }
        } else {
            changes.push(format!("{}: new {} observation", o.mac, o.protocol));
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
