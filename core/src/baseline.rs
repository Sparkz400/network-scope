// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! An approved baseline: which devices are expected on the network, who owns them, how critical
//! they are and how they are tagged. Once a baseline exists, the monitor raises an
//! `unknown-device` alert for every device that is not on the expected list.
//!
//! The baseline lives in the inventory database (schema version 4) next to the device identity
//! records of [`crate::identity`]: an entry is keyed by the stable device key, so it keeps
//! applying when the device changes address or randomised MAC address.
//!
//! - [`approve`] adds every device of a completed scan to the expected list (and starts the
//!   baseline: [`Baseline::exists`] is the explicit marker, not "the list is not empty").
//! - [`set`] changes owner, criticality, tags and the expected flag of one device.
//! - [`load`] reads everything in one call ([`Baseline`]); [`Baseline::expects`] says which
//!   devices of a scan are on the list.
//!
//! Nothing here sends traffic.
use crate::{
    devices::Device,
    identity::{self, Identifier, Kind, Registry},
    store,
};
use rusqlite::{Connection, params};
use serde::Serialize;
use std::{
    collections::{BTreeSet, HashSet},
    path::Path,
};

/// Longest owner text and tag, and most tags per device.
const MAX_OWNER: usize = 100;
const MAX_TAG: usize = 40;
const MAX_TAGS: usize = 20;

/// How much the device matters to the operation of the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Criticality {
    Low,
    Medium,
    High,
    Critical,
}

impl Criticality {
    pub fn name(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
    pub fn parse(text: &str) -> Option<Self> {
        [Self::Low, Self::Medium, Self::High, Self::Critical]
            .into_iter()
            .find(|c| c.name().eq_ignore_ascii_case(text.trim()))
    }
}

/// One device of the baseline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Entry {
    /// The stable device key (see [`crate::identity`]).
    pub key: String,
    /// What to call the device: its host name, else its first address, else its MAC.
    pub label: String,
    pub owner: String,
    pub criticality: Option<Criticality>,
    pub tags: Vec<String>,
    /// On the expected-devices list. A device with `false` is described (owner, tags) but still
    /// raises `unknown-device`.
    pub expected: bool,
    /// Where the entry came from: `approve`, `set` or an import (`import:csv`, ...).
    pub source: String,
    pub approved_at: i64,
    pub updated_at: i64,
}

/// The whole baseline, as the monitor and the GUI read it.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Baseline {
    /// When the baseline was last approved; `None` while there is no baseline (alerting is off).
    pub approved_at: Option<i64>,
    pub entries: Vec<Entry>,
    #[serde(skip)]
    expected: HashSet<String>,
    /// The identifiers of the expected devices, to recognise a device by more than its key.
    #[serde(skip)]
    registry: Registry,
}

impl Baseline {
    /// A baseline was approved: devices not on the expected list raise `unknown-device`.
    pub fn exists(&self) -> bool {
        self.approved_at.is_some()
    }
    pub fn expected_count(&self) -> usize {
        self.expected.len()
    }
    pub fn entry(&self, key: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.key == key)
    }
    /// For each device of a scan (with its stable `keys`, in the same order): is it on the
    /// expected list? A device is expected by its key, or because its identifiers match an
    /// expected device by the rules of [`crate::identity`] (so an imported list that names a
    /// device by host name or address applies to the device a scan finds).
    pub fn expects(&self, devices: &[Device], keys: &[String]) -> Vec<bool> {
        let matches = identity::resolve(&self.registry, devices);
        devices
            .iter()
            .enumerate()
            .map(|(i, _)| keys.get(i).is_some_and(|k| self.expected.contains(k)) || !matches[i].new)
            .collect()
    }
}

/// Reads the baseline. A database without one gives an empty [`Baseline`] (`exists()` false).
pub fn load(path: &Path) -> Result<Baseline, String> {
    load_from(&store::open(path)?)
}
/// [`load`] for a caller that must not write: the inventory is neither created nor upgraded.
pub fn load_read(path: &Path) -> Result<Baseline, String> {
    load_from(&store::open_read(path)?)
}

fn load_from(c: &Connection) -> Result<Baseline, String> {
    let approved_at = c
        .query_row(
            "SELECT value FROM baseline_meta WHERE key='approved_at'",
            [],
            |r| r.get::<_, String>(0),
        )
        .ok()
        .and_then(|v| v.parse::<i64>().ok());
    let mut s = c
        .prepare("SELECT device_key,label,owner,criticality,tags,expected,source,approved_at,updated_at FROM baseline_devices ORDER BY label COLLATE NOCASE, device_key")
        .map_err(|e| e.to_string())?;
    let rows = s
        .query_map([], |r| {
            Ok(Entry {
                key: r.get(0)?,
                label: r.get(1)?,
                owner: r.get(2)?,
                criticality: Criticality::parse(&r.get::<_, String>(3)?),
                tags: split_tags(&r.get::<_, String>(4)?),
                expected: r.get::<_, i64>(5)? != 0,
                source: r.get(6)?,
                approved_at: r.get(7)?,
                updated_at: r.get(8)?,
            })
        })
        .map_err(|e| e.to_string())?;
    let entries: Vec<Entry> = rows.collect::<Result<_, _>>().map_err(|e| e.to_string())?;
    let expected: HashSet<String> = entries
        .iter()
        .filter(|e| e.expected)
        .map(|e| e.key.clone())
        .collect();
    let mut registry = Registry::new();
    for record in store::registry_of(c)?.records() {
        if expected.contains(&record.key) {
            registry.add_key(&record.key);
            for (kind, values) in &record.identifiers {
                for value in values {
                    registry.add(
                        &record.key,
                        Identifier {
                            kind: *kind,
                            value: value.clone(),
                        },
                    );
                }
            }
        }
    }
    Ok(Baseline {
        approved_at,
        entries,
        expected,
        registry,
    })
}

fn split_tags(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

/// What [`approve`] did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Approval {
    pub scan_id: i64,
    /// Devices in the scan.
    pub devices: usize,
    /// Of those, devices that were not on the baseline before.
    pub added: usize,
}

/// Approves the devices of a completed scan (`scan`, or the newest completed scan) as the
/// expected devices: records them in the inventory (stable keys) and adds them to the baseline.
/// Entries already on the baseline keep their owner, criticality and tags and become expected;
/// devices that are not in this scan stay as they are, so approving again only adds.
pub fn approve(path: &Path, scan: Option<i64>, now: i64) -> Result<Approval, String> {
    let scan_id = match scan {
        Some(id) => id,
        None => store::latest_complete_id(path)?
            .ok_or("No completed scan in the inventory; run a scan first.")?,
    };
    let snapshot = store::load(path, scan_id)?;
    if !snapshot.complete {
        return Err(format!(
            "Scan #{scan_id} is partial; approve a completed scan."
        ));
    }
    let devices = crate::devices::merge(&snapshot.hosts, &snapshot.observations);
    let mut c = store::open(path)?;
    let tx = c
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;
    let matches = identity::resolve(&store::registry_of(&tx)?, &devices);
    store::record_matches(&tx, &devices, &matches, now)?;
    let mut added = 0;
    for (d, m) in devices.iter().zip(&matches) {
        let existing: Option<i64> = tx
            .query_row(
                "SELECT expected FROM baseline_devices WHERE device_key=?1",
                [&m.key],
                |r| r.get(0),
            )
            .ok();
        if existing.is_none() {
            added += 1;
        }
        tx.execute(
            "INSERT INTO baseline_devices(device_key,label,expected,source,approved_at,updated_at) VALUES(?1,?2,1,'approve',?3,?3) ON CONFLICT(device_key) DO UPDATE SET expected=1, label=CASE WHEN label='' THEN excluded.label ELSE label END, updated_at=?3",
            params![m.key, label_of(d), now],
        )
        .map_err(|e| e.to_string())?;
    }
    tx.execute(
        "INSERT INTO baseline_meta(key,value) VALUES('approved_at',?1) ON CONFLICT(key) DO UPDATE SET value=?1",
        [now.to_string()],
    )
    .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(Approval {
        scan_id,
        devices: devices.len(),
        added,
    })
}

pub(crate) fn label_of(d: &Device) -> String {
    d.hostnames
        .iter()
        .find(|h| !h.is_empty())
        .cloned()
        .or_else(|| d.ips.first().map(ToString::to_string))
        .unwrap_or_else(|| d.id.clone())
        .chars()
        .filter(|c| !c.is_control())
        .take(100)
        .collect()
}

/// Changes to one baseline entry; `None` leaves a field as it is.
#[derive(Clone, Debug, Default)]
pub struct Update {
    /// An empty text clears the owner.
    pub owner: Option<String>,
    /// `Some(None)` clears the criticality.
    pub criticality: Option<Option<Criticality>>,
    pub add_tags: Vec<String>,
    pub remove_tags: Vec<String>,
    pub expected: Option<bool>,
}

impl Update {
    fn is_empty(&self) -> bool {
        self.owner.is_none()
            && self.criticality.is_none()
            && self.add_tags.is_empty()
            && self.remove_tags.is_empty()
            && self.expected.is_none()
    }
}

fn check_text(what: &str, text: &str, max: usize) -> Result<String, String> {
    let text = text.trim();
    if text.chars().count() > max {
        return Err(format!("{what} is longer than {max} characters"));
    }
    if text.chars().any(char::is_control) {
        return Err(format!("{what} contains control characters"));
    }
    Ok(text.to_string())
}

/// A tag: short, no commas (they separate tags in the database and on the command line).
pub fn check_tag(tag: &str) -> Result<String, String> {
    let tag = check_text("A tag", tag, MAX_TAG)?;
    if tag.is_empty() || tag.contains(',') {
        return Err("A tag cannot be empty or contain a comma".into());
    }
    Ok(tag)
}

/// Sets owner, criticality, tags or the expected flag of the device `device` (a stable key, a
/// MAC, an IP address or a host name, see [`find_device`]). A device that is not on the baseline
/// yet is added (as expected unless `update.expected` says otherwise); this does not start the
/// baseline, only [`approve`] does.
pub fn set(path: &Path, device: &str, update: &Update, now: i64) -> Result<Entry, String> {
    if update.is_empty() {
        return Err(
            "Nothing to change: give --owner, --tag, --untag, --criticality or --expected".into(),
        );
    }
    let owner = update
        .owner
        .as_deref()
        .map(|o| check_text("The owner", o, MAX_OWNER))
        .transpose()?;
    let add = update
        .add_tags
        .iter()
        .map(|t| check_tag(t))
        .collect::<Result<Vec<_>, _>>()?;
    let remove = update
        .remove_tags
        .iter()
        .map(|t| check_tag(t))
        .collect::<Result<Vec<_>, _>>()?;
    let key = find_device(path, device)?;
    let mut c = store::open(path)?;
    let tx = c
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;
    let current = load_from(&tx)?;
    let mut entry = current.entry(&key).cloned().unwrap_or_else(|| Entry {
        label: label_for_key(&tx, &key),
        key: key.clone(),
        owner: String::new(),
        criticality: None,
        tags: vec![],
        expected: true,
        source: "set".into(),
        approved_at: now,
        updated_at: now,
    });
    if let Some(o) = owner {
        entry.owner = o;
    }
    if let Some(c) = update.criticality {
        entry.criticality = c;
    }
    let mut tags: BTreeSet<String> = entry.tags.iter().cloned().collect();
    tags.extend(add);
    for t in &remove {
        tags.retain(|x| !x.eq_ignore_ascii_case(t));
    }
    if tags.len() > MAX_TAGS {
        return Err(format!("A device can have at most {MAX_TAGS} tags"));
    }
    entry.tags = tags.into_iter().collect();
    if let Some(e) = update.expected {
        entry.expected = e;
    }
    entry.updated_at = now;
    tx.execute(
        "INSERT INTO baseline_devices(device_key,label,owner,criticality,tags,expected,source,approved_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(device_key) DO UPDATE SET owner=?3, criticality=?4, tags=?5, expected=?6, updated_at=?9",
        params![
            entry.key,
            entry.label,
            entry.owner,
            entry.criticality.map_or("", Criticality::name),
            entry.tags.join(","),
            i64::from(entry.expected),
            entry.source,
            entry.approved_at,
            entry.updated_at
        ],
    )
    .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(entry)
}

/// Adds an imported device to the baseline (see [`crate::import`]): expected unless the import
/// says otherwise. What the import describes (owner, criticality, tags) is added to the entry;
/// nothing the operator set earlier is cleared. Does not start the baseline.
pub(crate) fn upsert_imported(
    c: &Connection,
    key: &str,
    label: &str,
    d: &crate::import::Imported,
    source: &str,
    now: i64,
) -> Result<(), String> {
    let existing: Option<(String, String, String)> = c
        .query_row(
            "SELECT owner,criticality,tags FROM baseline_devices WHERE device_key=?1",
            [key],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .ok();
    let (old_owner, old_criticality, old_tags) = existing.unwrap_or_default();
    let owner = if d.owner.is_empty() {
        old_owner
    } else {
        d.owner.clone()
    };
    let criticality = d
        .criticality
        .map_or(old_criticality, |c| c.name().to_string());
    let mut tags: BTreeSet<String> = split_tags(&old_tags).into_iter().collect();
    for t in &d.tags {
        if tags.len() < MAX_TAGS {
            tags.insert(t.clone());
        }
    }
    c.execute(
        "INSERT INTO baseline_devices(device_key,label,owner,criticality,tags,expected,source,approved_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?8) ON CONFLICT(device_key) DO UPDATE SET owner=?3, criticality=?4, tags=?5, expected=?6, label=CASE WHEN label='' THEN ?2 ELSE label END, updated_at=?8",
        params![
            key,
            label,
            owner,
            criticality,
            tags.into_iter().collect::<Vec<_>>().join(","),
            i64::from(d.expected.unwrap_or(true)),
            source,
            now
        ],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Starts the baseline without a scan (for a list that was imported): from now on the monitor
/// raises `unknown-device` for every device that is not expected. Needs at least one expected
/// device, or every device would be unknown. Returns how many devices are expected.
pub fn enable(path: &Path, now: i64) -> Result<usize, String> {
    let c = store::open(path)?;
    let n: i64 = c
        .query_row(
            "SELECT count(*) FROM baseline_devices WHERE expected=1",
            [],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    if n == 0 {
        return Err(
            "No device is expected yet: import a list or approve a scan first (baseline approve)."
                .into(),
        );
    }
    c.execute(
        "INSERT INTO baseline_meta(key,value) VALUES('approved_at',?1) ON CONFLICT(key) DO UPDATE SET value=?1",
        [now.to_string()],
    )
    .map_err(|e| e.to_string())?;
    Ok(n as usize)
}

/// The name to show for a device that is only known by its key: its newest host name, else its
/// newest address, else the key.
fn label_for_key(c: &Connection, key: &str) -> String {
    for kind in [Kind::Hostname, Kind::Ip] {
        if let Ok(v) = c.query_row(
            "SELECT value FROM device_identifiers WHERE device_key=?1 AND kind=?2 ORDER BY last_seen DESC LIMIT 1",
            params![key, kind.name()],
            |r| r.get::<_, String>(0),
        ) {
            return v;
        }
    }
    key.to_string()
}

/// Removes a device from the baseline (it is then unknown again). Returns whether it was on it.
pub fn remove(path: &Path, device: &str) -> Result<bool, String> {
    let key = find_device(path, device)?;
    let n = store::open(path)?
        .execute("DELETE FROM baseline_devices WHERE device_key=?1", [&key])
        .map_err(|e| e.to_string())?;
    Ok(n > 0)
}

/// Deletes the whole baseline: no entries and no marker, so no `unknown-device` alerts.
pub fn clear(path: &Path) -> Result<usize, String> {
    let mut c = store::open(path)?;
    let tx = c
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;
    let n = tx
        .execute("DELETE FROM baseline_devices", [])
        .map_err(|e| e.to_string())?;
    tx.execute("DELETE FROM baseline_meta WHERE key='approved_at'", [])
        .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(n)
}

/// The stable key of the device a user means: a device key as shown by `devices`, a MAC address
/// (any notation), an IP address (the device that held it most recently) or a host name. More
/// than one device with the same MAC or name is an error that lists them.
pub fn find_device(path: &Path, query: &str) -> Result<String, String> {
    find_in(&store::open(path)?, query)
}

fn find_in(c: &Connection, query: &str) -> Result<String, String> {
    let query = query.trim();
    if query.is_empty() {
        return Err("Name a device: its key, MAC address, IP address or host name".into());
    }
    let exists = |table: &str, column: &str, value: &str| -> Option<String> {
        c.query_row(
            &format!("SELECT {column} FROM {table} WHERE {column}=?1 COLLATE NOCASE"),
            [value],
            |r| r.get(0),
        )
        .ok()
    };
    if let Some(key) = exists("known_devices", "key", query)
        .or_else(|| exists("baseline_devices", "device_key", query))
    {
        return Ok(key);
    }
    let (kinds, value): (Vec<Kind>, String) = if let Ok(ip) = query.parse::<std::net::IpAddr>() {
        (vec![Kind::Ip], ip.to_string())
    } else if let Ok(crate::devices::HistoryKey::Mac(mac)) =
        crate::devices::HistoryKey::parse(query)
    {
        (vec![Kind::Mac, Kind::RandomMac], mac)
    } else {
        (
            vec![Kind::Hostname, Kind::DeclaredName],
            query.trim_end_matches('.').to_ascii_lowercase(),
        )
    };
    let mut keys: Vec<(String, i64)> = vec![];
    for kind in kinds {
        let mut s = c
            .prepare("SELECT device_key,last_seen FROM device_identifiers WHERE kind=?1 AND value=?2 COLLATE NOCASE")
            .map_err(|e| e.to_string())?;
        let rows = s
            .query_map(params![kind.name(), value], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(|e| e.to_string())?;
        for row in rows {
            let (key, seen): (String, i64) = row.map_err(|e| e.to_string())?;
            match keys.iter_mut().find(|(k, _)| *k == key) {
                Some(existing) => existing.1 = existing.1.max(seen),
                None => keys.push((key, seen)),
            }
        }
    }
    keys.sort_by_key(|(k, seen)| (std::cmp::Reverse(*seen), k.clone()));
    match keys.as_slice() {
        [] => Err(format!(
            "{query}: no such device in the inventory (use a device key from `devices ID`, a MAC, an IP address or a host name)"
        )),
        [(key, _)] => Ok(key.clone()),
        // An address moves between devices: the latest holder is the one meant.
        [(key, _), ..] if value.parse::<std::net::IpAddr>().is_ok() => Ok(key.clone()),
        many => Err(format!(
            "{query} matches {} devices ({}); use the device key",
            many.len(),
            many.iter()
                .take(5)
                .map(|(k, _)| k.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// `baseline show` output: `text` (default) or `json`.
pub fn render(b: &Baseline, format: &str) -> Result<String, String> {
    match format {
        "json" => crate::schema::object("baseline", b),
        "text" => Ok(text(b)),
        _ => Err("Choose text or json".into()),
    }
}

fn text(b: &Baseline) -> String {
    use crate::report::fmt_time;
    use std::fmt::Write as _;
    let mut out = match b.approved_at {
        Some(t) => format!(
            "Baseline approved {}: {} expected of {} devices; devices that are not expected raise unknown-device alerts.\n",
            fmt_time(t),
            b.expected_count(),
            b.entries.len()
        ),
        None => format!(
            "No baseline approved: alerting for unknown devices is off ({} devices described).\n",
            b.entries.len()
        ),
    };
    for e in &b.entries {
        let _ = writeln!(
            out,
            "{}  {}  owner: {}  criticality: {}  tags: {}  [{}]  key: {}",
            if e.expected {
                "expected"
            } else {
                "not expected"
            },
            e.label,
            if e.owner.is_empty() { "-" } else { &e.owner },
            e.criticality.map_or("-", Criticality::name),
            if e.tags.is_empty() {
                "-".to_string()
            } else {
                e.tags.join(",")
            },
            e.source,
            e.key
        );
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        scan::{Host, Settings},
        store::{self, Snapshot},
    };
    use std::path::PathBuf;

    fn temp_db(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "netscope-baseline-{tag}-{}-{}.sqlite",
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
    fn host(ip: &str, mac: &str, name: &str, identity: &[(&str, &str)]) -> Host {
        Host {
            ip: ip.parse().unwrap(),
            responding: true,
            ping: None,
            ttl: Some(64),
            hostname: name.into(),
            mac: mac.into(),
            open: vec![22, 443],
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
    fn snapshot(hosts: Vec<Host>, complete: bool) -> Snapshot {
        Snapshot {
            sent: vec![],
            targets: "10.0.0.0/24".into(),
            complete,
            settings: Settings::default(),
            hosts,
            observations: vec![],
            notes: Default::default(),
        }
    }
    const KEYS: &[(&str, &str)] = &[
        ("ssh.22.hostkey_sha256", "aaaa"),
        ("tls.443.spki_sha256", "bbbb"),
    ];

    fn two_devices() -> Snapshot {
        snapshot(
            vec![
                host("10.0.0.5", "00:00:0C:00:00:01", "switch-1", &[]),
                host("10.0.0.6", "02:00:00:00:00:02", "tablet", KEYS),
            ],
            true,
        )
    }

    #[test]
    fn approving_a_scan_starts_the_baseline_and_is_additive() {
        let path = temp_db("approve");
        assert!(!load(&path).unwrap().exists(), "an empty database has none");
        assert!(
            approve(&path, None, 10)
                .unwrap_err()
                .contains("No completed scan")
        );
        let partial = store::save_at(&path, &snapshot(vec![], false), 1).unwrap();
        assert!(
            approve(&path, None, 10).is_err(),
            "a partial scan is no baseline"
        );
        assert!(
            approve(&path, Some(partial), 10)
                .unwrap_err()
                .contains("partial")
        );
        let id = store::save_at(&path, &two_devices(), 100).unwrap();
        let a = approve(&path, None, 200).unwrap();
        assert_eq!((a.scan_id, a.devices, a.added), (id, 2, 2));
        let b = load(&path).unwrap();
        assert!(b.exists());
        assert_eq!((b.approved_at, b.expected_count()), (Some(200), 2));
        let tablet = b.entry("02:00:00:00:00:02").unwrap();
        assert_eq!(tablet.label, "tablet");
        assert!(tablet.expected && tablet.owner.is_empty() && tablet.criticality.is_none());
        assert_eq!(tablet.source, "approve");
        // The devices are also in the inventory (stable keys and identifiers).
        assert!(
            store::known_devices(&path)
                .unwrap()
                .contains_key("02:00:00:00:00:02")
        );
        // Approving again adds a new device and keeps what was described.
        set(
            &path,
            "tablet",
            &Update {
                owner: Some("Ada".into()),
                criticality: Some(Some(Criticality::High)),
                add_tags: vec!["lab".into()],
                ..Default::default()
            },
            250,
        )
        .unwrap();
        let mut more = two_devices();
        more.hosts
            .push(host("10.0.0.7", "00:00:0C:00:00:03", "printer", &[]));
        store::save_at(&path, &more, 300).unwrap();
        let a = approve(&path, None, 400).unwrap();
        assert_eq!((a.devices, a.added), (3, 1));
        let b = load(&path).unwrap();
        assert_eq!(b.entries.len(), 3);
        let tablet = b.entry("02:00:00:00:00:02").unwrap();
        assert_eq!(tablet.owner, "Ada");
        assert_eq!(tablet.criticality, Some(Criticality::High));
        assert_eq!(tablet.tags, ["lab"]);
        assert_eq!(b.approved_at, Some(400));
        remove_db(&path);
    }

    #[test]
    fn set_finds_a_device_by_key_mac_ip_or_name_and_validates_input() {
        let path = temp_db("set");
        store::save_at(&path, &two_devices(), 100).unwrap();
        approve(&path, None, 200).unwrap();
        for (n, query) in [
            "02:00:00:00:00:02",
            "02-00-00-00-00-02",
            "10.0.0.6",
            "TABLET",
            "tablet.",
        ]
        .into_iter()
        .enumerate()
        {
            let e = set(
                &path,
                query,
                &Update {
                    add_tags: vec![format!("seen-{n}")],
                    ..Default::default()
                },
                300,
            )
            .unwrap();
            assert_eq!(e.key, "02:00:00:00:00:02", "{query}");
        }
        let e = set(
            &path,
            "switch-1",
            &Update {
                owner: Some("  NetOps ".into()),
                criticality: Some(Criticality::parse("CRITICAL")),
                add_tags: vec!["core".into(), "core".into(), "rack-2".into()],
                remove_tags: vec!["RACK-2".into()],
                ..Default::default()
            },
            300,
        )
        .unwrap();
        assert_eq!(e.owner, "NetOps");
        assert_eq!(e.criticality, Some(Criticality::Critical));
        assert_eq!(e.tags, ["core"]);
        // Clearing.
        let e = set(
            &path,
            "switch-1",
            &Update {
                owner: Some(String::new()),
                criticality: Some(None),
                expected: Some(false),
                ..Default::default()
            },
            400,
        )
        .unwrap();
        assert!(e.owner.is_empty() && e.criticality.is_none() && !e.expected);
        assert_eq!(load(&path).unwrap().expected_count(), 1);
        // Mistakes are refused and change nothing.
        let bad = |u: Update| set(&path, "switch-1", &u, 500).unwrap_err();
        assert!(bad(Update::default()).contains("Nothing to change"));
        assert!(
            bad(Update {
                add_tags: vec!["a,b".into()],
                ..Default::default()
            })
            .contains("comma")
        );
        assert!(
            bad(Update {
                owner: Some("x".repeat(101)),
                ..Default::default()
            })
            .contains("longer than")
        );
        assert!(
            bad(Update {
                owner: Some("a\nb".into()),
                ..Default::default()
            })
            .contains("control")
        );
        assert!(
            bad(Update {
                add_tags: (0..30).map(|i| format!("t{i}")).collect(),
                ..Default::default()
            })
            .contains("at most")
        );
        let nobody = set(
            &path,
            "no-such-device",
            &Update {
                owner: Some("x".into()),
                ..Default::default()
            },
            500,
        );
        assert!(nobody.unwrap_err().contains("no such device"));
        assert!(Criticality::parse("urgent").is_none());
        assert!(Criticality::Low < Criticality::Critical);
        remove_db(&path);
    }

    #[test]
    fn a_hostname_shared_by_two_devices_must_be_given_by_key() {
        let path = temp_db("ambiguous");
        let snap = snapshot(
            vec![
                host("10.0.0.5", "00:00:0C:00:00:01", "printer", &[]),
                host("10.0.0.6", "00:00:0C:00:00:02", "printer", &[]),
            ],
            true,
        );
        store::save_at(&path, &snap, 100).unwrap();
        approve(&path, None, 200).unwrap();
        let e = find_device(&path, "printer").unwrap_err();
        assert!(e.contains("matches 2 devices"), "{e}");
        assert_eq!(
            find_device(&path, "00:00:0c:00:00:02").unwrap(),
            "00:00:0C:00:00:02"
        );
        // An address belongs to the device that held it last.
        let moved = crate::devices::merge(
            &[host("10.0.0.5", "00:00:0C:00:00:02", "printer", &[])],
            &[],
        );
        store::record_devices(&path, &moved, 300).unwrap();
        assert_eq!(find_device(&path, "10.0.0.5").unwrap(), "00:00:0C:00:00:02");
        remove_db(&path);
    }

    #[test]
    fn setting_a_device_does_not_start_the_baseline_and_remove_and_clear_work() {
        let path = temp_db("marker");
        // The device must be in the inventory: record it without approving.
        let known = crate::devices::merge(&two_devices().hosts, &[]);
        store::record_devices(&path, &known, 100).unwrap();
        set(
            &path,
            "switch-1",
            &Update {
                owner: Some("NetOps".into()),
                ..Default::default()
            },
            150,
        )
        .unwrap();
        let b = load(&path).unwrap();
        assert!(!b.exists(), "only approve starts the baseline");
        assert_eq!(b.entries.len(), 1);
        store::save_at(&path, &two_devices(), 100).unwrap();
        approve(&path, None, 200).unwrap();
        assert!(load(&path).unwrap().exists());
        assert!(remove(&path, "switch-1").unwrap());
        assert!(!remove(&path, "switch-1").unwrap(), "already gone");
        assert_eq!(load(&path).unwrap().entries.len(), 1);
        assert_eq!(clear(&path).unwrap(), 1);
        let b = load(&path).unwrap();
        assert!(!b.exists() && b.entries.is_empty());
        remove_db(&path);
    }

    #[test]
    fn an_expected_device_is_recognised_after_it_changes_address_and_mac() {
        let path = temp_db("expects");
        store::save_at(&path, &two_devices(), 100).unwrap();
        approve(&path, None, 200).unwrap();
        let b = load(&path).unwrap();
        let now = [
            // The tablet: new address, new random MAC, same host keys.
            host("10.0.0.99", "06:11:22:33:44:55", "tablet", KEYS),
            // The switch, unchanged.
            host("10.0.0.5", "00:00:0C:00:00:01", "switch-1", &[]),
            // A stranger.
            host("10.0.0.50", "06:99:99:99:99:99", "stranger", &[]),
        ];
        let devices = crate::devices::merge(&now, &[]);
        let matches = store::resolve_devices(&path, &devices).unwrap();
        let keys: Vec<String> = matches.iter().map(|m| m.key.clone()).collect();
        let by_ip = |ip: &str| {
            devices
                .iter()
                .position(|d| d.ips[0].to_string() == ip)
                .unwrap()
        };
        let expected = b.expects(&devices, &keys);
        assert!(expected[by_ip("10.0.0.99")], "recognised: {matches:?}");
        assert!(expected[by_ip("10.0.0.5")]);
        assert!(!expected[by_ip("10.0.0.50")]);
        // A device that is described but marked not expected is not expected.
        set(
            &path,
            "tablet",
            &Update {
                expected: Some(false),
                ..Default::default()
            },
            300,
        )
        .unwrap();
        let b = load(&path).unwrap();
        let expected = b.expects(&devices, &keys);
        assert!(!expected[by_ip("10.0.0.99")]);
        remove_db(&path);
    }

    #[test]
    fn show_renders_text_and_json() {
        let path = temp_db("show");
        store::save_at(&path, &two_devices(), 100).unwrap();
        let none = render(&load(&path).unwrap(), "text").unwrap();
        assert!(none.contains("alerting for unknown devices is off"));
        approve(&path, None, 200).unwrap();
        set(
            &path,
            "tablet",
            &Update {
                owner: Some("Ada".into()),
                add_tags: vec!["lab".into()],
                criticality: Some(Some(Criticality::Low)),
                ..Default::default()
            },
            250,
        )
        .unwrap();
        let b = load(&path).unwrap();
        let text = render(&b, "text").unwrap();
        assert!(text.contains("2 expected of 2 devices"), "{text}");
        assert!(
            text.contains("owner: Ada  criticality: low  tags: lab"),
            "{text}"
        );
        let json: serde_json::Value = serde_json::from_str(&render(&b, "json").unwrap()).unwrap();
        assert_eq!(json["approved_at"], 200);
        assert_eq!(json["entries"].as_array().unwrap().len(), 2);
        assert!(render(&b, "yaml").is_err());
        remove_db(&path);
    }
}
