//! "What changed": the new, gone and changed devices and the new and resolved risks between the
//! newest completed scan and an earlier one (the scan before it, or the state at a point in
//! time). One call returns everything a home screen or a report needs:
//!
//! ```no_run
//! use network_scope_core::{changes, store};
//!
//! let db = store::default_path();
//! let c = changes::changes(&db, &changes::Since::Last, store::now())?;
//! println!("{} new, {} gone", c.summary.new_devices, c.summary.gone_devices);
//! # Ok::<(), String>(())
//! ```
//!
//! The comparison works on devices (see [`crate::identity`]), not on addresses, so a device that
//! moved to another address or randomised MAC is *changed*, not "gone" plus "new". It is built on
//! [`store::diff_report`]: scans are only compared when they cover the same targets and used the
//! same detection settings, and a risk that disappeared counts as *resolved* only when the newer
//! scan looked at its evidence again (otherwise it is *unconfirmed*). [`changes`] never fails
//! because there is nothing to compare: an empty inventory, a single scan or scans that cannot
//! be compared give an empty [`Changes`] whose `notice` says why. Nothing here sends traffic.
use crate::{
    baseline::Baseline,
    devices::{self, Device},
    identity::{self, Registry},
    risk::Finding,
    store::{self, Change, IgnoreList, Snapshot},
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::IpAddr,
    path::Path,
};

/// How far back to compare.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Since {
    /// The newest completed scan against the one before it (of the same targets and settings).
    Last,
    /// The newest completed scan against the state at this time (Unix seconds): the newest
    /// comparable scan taken at or before it.
    At(i64),
}

impl Since {
    /// `last`, a window such as `12h`, `7d` or `2w`, or a UTC date (`2026-11-01`) or date and
    /// time (`2026-11-01T08:30`, `2026-11-01 08:30`). `now` is Unix seconds.
    pub fn parse(text: &str, now: i64) -> Result<Self, String> {
        let t = text.trim();
        if t.eq_ignore_ascii_case("last") {
            return Ok(Self::Last);
        }
        let bad = || {
            format!(
                "{text}: use last, a window like 12h, 7d or 2w, or a date like 2026-11-01 or 2026-11-01T08:30"
            )
        };
        if let Some(unit) = t.chars().last().filter(char::is_ascii_alphabetic) {
            let n: i64 = t[..t.len() - 1].parse().map_err(|_| bad())?;
            let seconds = match unit.to_ascii_lowercase() {
                'h' => 3600,
                'd' => 86_400,
                'w' => 7 * 86_400,
                _ => return Err(bad()),
            };
            // At least one unit and at most ten years back.
            if !(1..=3650 * 86_400 / seconds).contains(&n) {
                return Err(bad());
            }
            return Ok(Self::At(now.saturating_sub(n * seconds)));
        }
        let (date, time) = match t.split_once(['T', ' ']) {
            Some((d, tm)) => (d, Some(tm)),
            None => (t, None),
        };
        let mut d = date.split('-');
        let (y, m, day): (i64, i64, i64) = (
            d.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?,
            d.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?,
            d.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?,
        );
        if d.next().is_some() || !(1970..=9999).contains(&y) || !(1..=12).contains(&m) {
            return Err(bad());
        }
        if !(1..=days_in_month(y, m)).contains(&day) {
            return Err(bad());
        }
        let secs = match time {
            None => 0,
            Some(tm) => {
                let mut p = tm.split(':');
                let h: i64 = p.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?;
                let min: i64 = p.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?;
                if p.next().is_some() || !(0..24).contains(&h) || !(0..60).contains(&min) {
                    return Err(bad());
                }
                h * 3600 + min * 60
            }
        };
        Ok(Self::At(days_from_civil(y, m, day) * 86_400 + secs))
    }
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// A scan that took part in the comparison.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScanRef {
    pub id: i64,
    pub timestamp: i64,
    pub targets: String,
    pub hosts: usize,
}

/// A device in the answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DeviceRef {
    /// The stable device key ([`crate::identity`]).
    pub key: String,
    /// Host name, else first address, else MAC.
    pub label: String,
    pub ips: Vec<IpAddr>,
    pub mac: String,
    pub vendor: String,
    pub device_type: String,
    pub hostnames: Vec<String>,
    /// Whether the device is on the approved baseline; `None` while there is no baseline.
    pub in_baseline: Option<bool>,
}

/// One thing that changed on a device that is in both scans.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DeviceChange {
    /// `address`, `mac`, `hostname`, `port-opened`, `port-closed`, `udp-answering`,
    /// `udp-silent` or `identity` (a service detail such as a version or certificate).
    pub kind: &'static str,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChangedDevice {
    pub device: DeviceRef,
    pub changes: Vec<DeviceChange>,
    /// More changes than fit in `changes` (the list is capped per device).
    pub more: usize,
}

/// A risk (finding) that appeared or went away.
#[derive(Clone, Debug, Serialize)]
pub struct RiskChange {
    /// The device it belongs to, when the address maps to one.
    pub device_key: Option<String>,
    pub finding: Finding,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub new_devices: usize,
    pub gone_devices: usize,
    pub changed_devices: usize,
    pub new_risks: usize,
    pub resolved_risks: usize,
    pub unconfirmed_risks: usize,
}

/// The answer of [`changes`].
#[derive(Clone, Debug, Serialize)]
pub struct Changes {
    /// What was asked: `last`, a window (`7d`) or a date, as given.
    pub since: String,
    pub now: i64,
    /// The newest completed scan (what "now" is); `None` when there is none.
    pub current: Option<ScanRef>,
    /// The scan it was compared with; `None` when nothing could be compared.
    pub previous: Option<ScanRef>,
    /// Why there is nothing to compare (or a caveat about what was compared); `None` when the
    /// comparison is plain.
    pub notice: Option<String>,
    pub summary: Summary,
    /// Devices in the current scan that were not in the previous one.
    pub new_devices: Vec<DeviceRef>,
    /// Devices in the previous scan that the current one did not observe (not proof that they
    /// are offline).
    pub gone_devices: Vec<DeviceRef>,
    pub changed_devices: Vec<ChangedDevice>,
    pub new_risks: Vec<RiskChange>,
    /// Risks that went away and whose evidence the current scan checked again.
    pub resolved_risks: Vec<RiskChange>,
    /// Risks that went away but were not checked again (host silent, port not probed): the scan
    /// cannot tell whether they were fixed.
    pub unconfirmed_risks: Vec<RiskChange>,
    /// Devices of the current scan that are not on the approved baseline; `None` while there is
    /// no baseline.
    pub unknown_devices: Option<usize>,
}

impl Changes {
    fn empty(since: String, now: i64, notice: impl Into<String>) -> Self {
        Self {
            since,
            now,
            current: None,
            previous: None,
            notice: Some(notice.into()),
            summary: Summary::default(),
            new_devices: vec![],
            gone_devices: vec![],
            changed_devices: vec![],
            new_risks: vec![],
            resolved_risks: vec![],
            unconfirmed_risks: vec![],
            unknown_devices: None,
        }
    }
    /// Nothing new, gone, changed or risky.
    pub fn is_quiet(&self) -> bool {
        self.summary == Summary::default()
    }
}

/// Most changes listed per changed device.
const MAX_CHANGES_PER_DEVICE: usize = 20;
/// Most earlier scans tried as the comparison partner of the newest one.
const MAX_CANDIDATES: usize = 25;

/// What changed in the inventory at `db` since `since`. Errors only for an unreadable database.
pub fn changes(db: &Path, since: &Since, now: i64) -> Result<Changes, String> {
    let label = match since {
        Since::Last => "last".to_string(),
        Since::At(t) => crate::report::fmt_time(*t),
    };
    let scans = store::list(db)?;
    let Some(current) = scans.iter().find(|s| s.complete) else {
        return Ok(Changes::empty(
            label,
            now,
            if scans.is_empty() {
                "The inventory has no scans yet."
            } else {
                "The inventory has no completed scan (partial scans do not establish changes)."
            },
        ));
    };
    let cur_ref = ScanRef {
        id: current.id,
        timestamp: current.timestamp,
        targets: current.targets.clone(),
        hosts: current.hosts,
    };
    let mut out = Changes::empty(label, now, "");
    out.notice = None;
    out.current = Some(cur_ref.clone());
    if let Since::At(cutoff) = since
        && current.timestamp <= *cutoff
    {
        out.notice = Some(format!(
            "The newest completed scan (#{}, {}) is older than the window: nothing has been scanned since.",
            current.id,
            crate::report::fmt_time(current.timestamp)
        ));
        return Ok(out);
    }
    let earlier: Vec<&store::Entry> = scans
        .iter()
        .filter(|s| s.complete && s.id < current.id && s.targets == current.targets)
        .collect();
    // Candidates in the order they are tried.
    let (ordered, later_than_cutoff): (Vec<&store::Entry>, usize) = match since {
        Since::Last => (earlier.clone(), 0),
        Since::At(cutoff) => {
            let mut at_or_before: Vec<&store::Entry> = earlier
                .iter()
                .copied()
                .filter(|s| s.timestamp <= *cutoff)
                .collect();
            let mut after: Vec<&store::Entry> = earlier
                .iter()
                .copied()
                .filter(|s| s.timestamp > *cutoff)
                .collect();
            after.reverse(); // oldest first
            let n = at_or_before.len();
            at_or_before.extend(after);
            (at_or_before, n)
        }
    };
    let cur = store::load(db, current.id)?;
    let mut last_error = None;
    for (i, entry) in ordered.iter().take(MAX_CANDIDATES).enumerate() {
        let prev = store::load(db, entry.id)?;
        match store::diff_report(&prev, &cur, &IgnoreList::new(&[])) {
            Ok(_) => {
                let registry = store::device_registry(db)?;
                let baseline = crate::baseline::load(db)?;
                let parts = between(&prev, &cur, registry, Some(&baseline))?;
                out.previous = Some(ScanRef {
                    id: entry.id,
                    timestamp: entry.timestamp,
                    targets: entry.targets.clone(),
                    hosts: entry.hosts,
                });
                out.summary = parts.summary;
                out.new_devices = parts.new_devices;
                out.gone_devices = parts.gone_devices;
                out.changed_devices = parts.changed_devices;
                out.new_risks = parts.new_risks;
                out.resolved_risks = parts.resolved_risks;
                out.unconfirmed_risks = parts.unconfirmed_risks;
                out.unknown_devices = parts.unknown_devices;
                if i >= later_than_cutoff && matches!(since, Since::At(_)) {
                    out.notice = Some(format!(
                        "No comparable scan from before {}; compared with the oldest later scan (#{}, {}).",
                        out.since,
                        entry.id,
                        crate::report::fmt_time(entry.timestamp)
                    ));
                }
                return Ok(out);
            }
            Err(e) => last_error = Some(e),
        }
    }
    out.notice = Some(match (earlier.is_empty(), last_error) {
        (true, _) => format!(
            "There is no earlier completed scan of {} to compare with.",
            current.targets
        ),
        (false, Some(e)) => format!(
            "No earlier scan of {} can be compared: {e}",
            current.targets
        ),
        (false, None) => "No earlier scan can be compared.".into(),
    });
    // With no partner, the unknown-device count of the current scan is still worth showing.
    let baseline = crate::baseline::load(db)?;
    if baseline.exists() {
        let devices = devices::merge(&cur.hosts, &cur.observations);
        let keys: Vec<String> = identity::resolve(&store::device_registry(db)?, &devices)
            .into_iter()
            .map(|m| m.key)
            .collect();
        out.unknown_devices = Some(
            baseline
                .expects(&devices, &keys)
                .iter()
                .filter(|e| !**e)
                .count(),
        );
    }
    Ok(out)
}

/// The comparison of two scans (see [`between`]).
#[derive(Clone, Debug)]
pub struct Parts {
    pub summary: Summary,
    pub new_devices: Vec<DeviceRef>,
    pub gone_devices: Vec<DeviceRef>,
    pub changed_devices: Vec<ChangedDevice>,
    pub new_risks: Vec<RiskChange>,
    pub resolved_risks: Vec<RiskChange>,
    pub unconfirmed_risks: Vec<RiskChange>,
    pub unknown_devices: Option<usize>,
}

fn device_ref(d: &Device, key: &str, in_baseline: Option<bool>) -> DeviceRef {
    DeviceRef {
        key: key.to_string(),
        label: crate::baseline::label_of(d),
        ips: d.ips.clone(),
        mac: d.mac.clone(),
        vendor: d.vendor.clone(),
        device_type: d.device_type.clone(),
        hostnames: d.hostnames.clone(),
        in_baseline,
    }
}

fn list<T: ToString>(items: impl IntoIterator<Item = T>) -> String {
    items
        .into_iter()
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Compares two completed scans of the same scope (see [`store::diff_report`] for what that
/// means; the error is its refusal). `registry` is what the inventory knows about device
/// identity (an empty one is fine: the devices of `prev` are then taught to it), `baseline`
/// marks new devices that are not expected.
pub fn between(
    prev: &Snapshot,
    cur: &Snapshot,
    mut registry: Registry,
    baseline: Option<&Baseline>,
) -> Result<Parts, String> {
    let diff = store::diff_report(prev, cur, &IgnoreList::new(&[]))?;
    let old_devices = devices::merge(&prev.hosts, &prev.observations);
    let new_devices = devices::merge(&cur.hosts, &cur.observations);
    // Both scans are matched against the same registry; what the older scan showed is taught to
    // it first, so a device that changed address or MAC still gets one key in both.
    let old_matches = identity::resolve(&registry, &old_devices);
    for (d, m) in old_devices.iter().zip(&old_matches) {
        registry.learn(&m.key, d);
    }
    let new_matches = identity::resolve(&registry, &new_devices);
    let old_by_key: BTreeMap<&str, &Device> = old_devices
        .iter()
        .zip(&old_matches)
        .map(|(d, m)| (m.key.as_str(), d))
        .collect();
    let new_by_key: BTreeMap<&str, &Device> = new_devices
        .iter()
        .zip(&new_matches)
        .map(|(d, m)| (m.key.as_str(), d))
        .collect();
    let new_keys: Vec<String> = new_matches.iter().map(|m| m.key.clone()).collect();
    let baseline = baseline.filter(|b| b.exists());
    let expected: Option<Vec<bool>> = baseline.map(|b| b.expects(&new_devices, &new_keys));
    let in_baseline = |key: &str| -> Option<bool> {
        let flags = expected.as_ref()?;
        new_keys.iter().position(|k| k == key).map(|i| flags[i])
    };
    let mut ip_key: HashMap<IpAddr, String> = HashMap::new();
    for (key, d) in old_by_key.iter().chain(new_by_key.iter()) {
        for ip in &d.ips {
            ip_key.insert(*ip, (*key).to_string());
        }
    }

    let mut out = Parts {
        summary: Summary::default(),
        new_devices: vec![],
        gone_devices: vec![],
        changed_devices: vec![],
        new_risks: vec![],
        resolved_risks: vec![],
        unconfirmed_risks: vec![],
        unknown_devices: expected
            .as_ref()
            .map(|flags| flags.iter().filter(|e| !**e).count()),
    };
    for (key, d) in &new_by_key {
        if !old_by_key.contains_key(key) {
            out.new_devices.push(device_ref(d, key, in_baseline(key)));
        }
    }
    // A device that was known only from passive traffic cannot be called gone by a scan that
    // captured nothing.
    let passive_only = |d: &Device| d.sources.iter().all(|s| s.starts_with("passive"));
    for (key, d) in &old_by_key {
        if !new_by_key.contains_key(key) && !(passive_only(d) && cur.observations.is_empty()) {
            out.gone_devices.push(device_ref(d, key, None));
        }
    }
    // Per-device changes: attributes from the merged devices, ports and services from the diff.
    let mut per_device: BTreeMap<String, Vec<DeviceChange>> = BTreeMap::new();
    for (key, new) in &new_by_key {
        let Some(old) = old_by_key.get(key) else {
            continue;
        };
        let changes = per_device.entry((*key).to_string()).or_default();
        let ips = |d: &Device| d.ips.iter().copied().collect::<BTreeSet<_>>();
        if !old.ips.is_empty() && !new.ips.is_empty() && ips(old) != ips(new) {
            changes.push(DeviceChange {
                kind: "address",
                detail: format!("{} → {}", list(&old.ips), list(&new.ips)),
            });
        }
        if !old.mac.is_empty() && !new.mac.is_empty() && old.mac != new.mac {
            changes.push(DeviceChange {
                kind: "mac",
                detail: format!("{} → {}", old.mac, new.mac),
            });
        }
        // Names that only the SMB handshake reported depend on whether services were scanned.
        let names = |d: &Device| {
            d.hostnames
                .iter()
                .filter(|h| !d.smb_names.contains(h))
                .cloned()
                .collect::<BTreeSet<_>>()
        };
        let (old_names, new_names) = (names(old), names(new));
        if !old_names.is_empty() && !new_names.is_empty() && old_names != new_names {
            changes.push(DeviceChange {
                kind: "hostname",
                detail: format!("{} → {}", list(&old_names), list(&new_names)),
            });
        }
    }
    for c in &diff.changes {
        let (ip, kind, detail) = match c {
            Change::PortOpened {
                ip,
                protocol: "udp",
                port,
            } => (ip, "udp-answering", format!("UDP {port}")),
            Change::PortOpened { ip, port, .. } => (ip, "port-opened", format!("TCP {port}")),
            Change::PortClosed {
                ip,
                protocol: "udp",
                port,
            } => (ip, "udp-silent", format!("UDP {port} no longer answering")),
            Change::PortClosed { ip, port, .. } => (
                ip,
                "port-closed",
                format!("TCP {port} no longer observed open"),
            ),
            Change::IdentityAdded { ip, key, value } => {
                (ip, "identity", format!("{key} identified: {value}"))
            }
            Change::IdentityChanged { ip, key, old, new } => {
                (ip, "identity", format!("{key}: {old} → {new}"))
            }
            Change::IdentityRemoved { ip, key, old } => (
                ip,
                "identity",
                format!("{key} no longer reported (was: {old})"),
            ),
            _ => continue,
        };
        if let Some(key) = ip_key
            .get(ip)
            .filter(|k| old_by_key.contains_key(k.as_str()) && new_by_key.contains_key(k.as_str()))
        {
            per_device
                .entry(key.clone())
                .or_default()
                .push(DeviceChange { kind, detail });
        }
    }
    for (key, mut list) in per_device {
        if list.is_empty() {
            continue;
        }
        let more = list.len().saturating_sub(MAX_CHANGES_PER_DEVICE);
        list.truncate(MAX_CHANGES_PER_DEVICE);
        let device = new_by_key[key.as_str()];
        out.changed_devices.push(ChangedDevice {
            device: device_ref(device, &key, in_baseline(&key)),
            changes: list,
            more,
        });
    }
    let risk = |f: &Finding| RiskChange {
        device_key: ip_key.get(&f.ip).cloned(),
        finding: f.clone(),
    };
    out.new_risks = diff.new_findings.iter().map(risk).collect();
    out.resolved_risks = diff.resolved_findings.iter().map(risk).collect();
    out.unconfirmed_risks = diff.unconfirmed_findings.iter().map(risk).collect();
    out.summary = Summary {
        new_devices: out.new_devices.len(),
        gone_devices: out.gone_devices.len(),
        changed_devices: out.changed_devices.len(),
        new_risks: out.new_risks.len(),
        resolved_risks: out.resolved_risks.len(),
        unconfirmed_risks: out.unconfirmed_risks.len(),
    };
    Ok(out)
}

/// `changes` output: `text` (default) or `json` (the [`Changes`] struct).
pub fn render(c: &Changes, format: &str) -> Result<String, String> {
    match format {
        "json" => crate::schema::object("changes", c),
        "text" => Ok(text(c)),
        _ => Err("Choose text or json".into()),
    }
}

fn text(c: &Changes) -> String {
    use crate::report::fmt_time;
    use std::fmt::Write as _;
    let scan = |s: &ScanRef| format!("#{} ({})", s.id, fmt_time(s.timestamp));
    let mut o = match (&c.current, &c.previous) {
        (Some(cur), Some(prev)) => format!(
            "Changes since {}: scan {} against scan {}\n",
            c.since,
            scan(cur),
            scan(prev)
        ),
        (Some(cur), None) => format!("Changes since {}: newest scan {}\n", c.since, scan(cur)),
        _ => format!("Changes since {}\n", c.since),
    };
    if let Some(n) = &c.notice {
        let _ = writeln!(o, "Note: {n}");
    }
    if c.previous.is_none() {
        return o.trim_end().to_string();
    }
    if c.is_quiet() {
        o.push_str("No changes.\n");
    }
    let device = |d: &DeviceRef| {
        let mut s = d.label.clone();
        if d.label != d.ips.first().map(ToString::to_string).unwrap_or_default()
            && !d.ips.is_empty()
        {
            let _ = write!(s, " ({})", list(&d.ips));
        }
        for extra in [&d.mac, &d.vendor, &d.device_type] {
            if !extra.is_empty() {
                let _ = write!(s, ", {extra}");
            }
        }
        if d.in_baseline == Some(false) {
            s.push_str(" [not on the baseline]");
        }
        s
    };
    let section = |o: &mut String, title: &str, items: Vec<String>| {
        if !items.is_empty() {
            let _ = writeln!(o, "{title} ({}):", items.len());
            for i in items {
                let _ = writeln!(o, "  {i}");
            }
        }
    };
    section(
        &mut o,
        "New devices",
        c.new_devices.iter().map(device).collect(),
    );
    section(
        &mut o,
        "Devices not observed (not proof they are offline)",
        c.gone_devices.iter().map(device).collect(),
    );
    section(
        &mut o,
        "Changed devices",
        c.changed_devices
            .iter()
            .map(|d| {
                let mut s = format!(
                    "{}: {}",
                    device(&d.device),
                    d.changes
                        .iter()
                        .map(|c| format!("{} {}", c.kind, c.detail))
                        .collect::<Vec<_>>()
                        .join("; ")
                );
                if d.more > 0 {
                    let _ = write!(s, "; and {} more", d.more);
                }
                s
            })
            .collect(),
    );
    let risk = |r: &RiskChange| {
        let f = &r.finding;
        format!(
            "{} {}{} {} ({})",
            f.severity.name().to_ascii_uppercase(),
            f.ip,
            f.port.map_or(String::new(), |p| format!(":{p}")),
            f.title,
            f.id
        )
    };
    section(&mut o, "New risks", c.new_risks.iter().map(risk).collect());
    section(
        &mut o,
        "Resolved risks",
        c.resolved_risks.iter().map(risk).collect(),
    );
    section(
        &mut o,
        "Risks not checked again (cannot tell whether they were fixed)",
        c.unconfirmed_risks.iter().map(risk).collect(),
    );
    if let Some(n) = c.unknown_devices {
        let _ = writeln!(o, "Devices not on the approved baseline: {n}");
    }
    o.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{Host, Settings};
    use std::path::PathBuf;

    const DAY: i64 = 86_400;
    const NOW: i64 = 1_800_000_000;

    fn temp_db(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "netscope-changes-{tag}-{}-{}.sqlite",
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
    fn host(ip: &str, mac: &str, name: &str, open: &[u16], id: &[(&str, &str)]) -> Host {
        Host {
            ip: ip.parse().unwrap(),
            responding: true,
            ping: None,
            ttl: Some(64),
            hostname: name.into(),
            mac: mac.into(),
            open: open.to_vec(),
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity: id
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            udp_open: vec![],
            trace: vec![],
        }
    }
    fn snap(hosts: Vec<Host>) -> Snapshot {
        Snapshot {
            sent: vec![],
            targets: "10.0.0.0/24".into(),
            complete: true,
            settings: Settings {
                ports: "22,23,80,443,502".into(),
                ..Default::default()
            },
            hosts,
            observations: vec![],
            notes: Default::default(),
        }
    }
    const TELNET: &[(&str, &str)] = &[("svc.23", "telnet")];
    const KEYS: &[(&str, &str)] = &[
        ("ssh.22.hostkey_sha256", "aaaa"),
        ("tls.443.spki_sha256", "bbbb"),
    ];

    #[test]
    fn an_empty_inventory_a_single_scan_and_partial_scans_are_answers_not_errors() {
        let path = temp_db("empty");
        let c = changes(&path, &Since::Last, NOW).unwrap();
        assert!(c.current.is_none() && c.previous.is_none() && c.is_quiet());
        assert!(c.notice.unwrap().contains("no scans yet"));
        let mut partial = snap(vec![]);
        partial.complete = false;
        store::save_at(&path, &partial, NOW - 100).unwrap();
        let c = changes(&path, &Since::Last, NOW).unwrap();
        assert!(c.notice.unwrap().contains("no completed scan"));
        store::save_at(
            &path,
            &snap(vec![host("10.0.0.5", "", "a", &[22], &[])]),
            NOW - 50,
        )
        .unwrap();
        let c = changes(&path, &Since::Last, NOW).unwrap();
        assert_eq!(c.current.as_ref().unwrap().id, 2);
        assert!(c.previous.is_none() && c.is_quiet());
        assert!(
            c.notice
                .as_ref()
                .unwrap()
                .contains("no earlier completed scan")
        );
        // The text and JSON forms exist for every case.
        let text = render(&c, "text").unwrap();
        assert!(text.contains("Note:"), "{text}");
        let json: serde_json::Value = serde_json::from_str(&render(&c, "json").unwrap()).unwrap();
        assert_eq!(json["summary"]["new_devices"], 0);
        assert!(render(&c, "xml").is_err());
        remove_db(&path);
    }

    #[test]
    fn new_gone_and_changed_devices_and_risks_since_the_last_scan() {
        let path = temp_db("last");
        let before = snap(vec![
            host("10.0.0.5", "00:00:0C:00:00:01", "plc-1", &[502], &[]),
            host("10.0.0.6", "00:00:0C:00:00:02", "camera", &[80], &[]),
            host("10.0.0.7", "00:00:0C:00:00:03", "pc", &[23], TELNET),
        ]);
        let after = snap(vec![
            // plc-1: port 80 opened.
            host("10.0.0.5", "00:00:0C:00:00:01", "plc-1", &[80, 502], &[]),
            // camera is gone; pc is quiet again (telnet closed); a new device with telnet.
            host("10.0.0.7", "00:00:0C:00:00:03", "pc", &[], &[]),
            host("10.0.0.9", "00:00:0C:00:00:09", "newbie", &[23], TELNET),
        ]);
        store::save_at(&path, &before, NOW - 2 * DAY).unwrap();
        store::save_at(&path, &after, NOW - DAY).unwrap();
        let c = changes(&path, &Since::Last, NOW).unwrap();
        assert_eq!(c.notice, None);
        assert_eq!(
            (
                c.previous.as_ref().unwrap().id,
                c.current.as_ref().unwrap().id
            ),
            (1, 2)
        );
        let labels = |v: &[DeviceRef]| v.iter().map(|d| d.label.clone()).collect::<Vec<_>>();
        assert_eq!(labels(&c.new_devices), ["newbie"]);
        assert_eq!(labels(&c.gone_devices), ["camera"]);
        // plc-1 (port opened) and pc (telnet closed).
        assert_eq!(c.changed_devices.len(), 2, "{:?}", c.changed_devices);
        let changed = c
            .changed_devices
            .iter()
            .find(|d| d.device.label == "plc-1")
            .unwrap();
        assert!(
            changed
                .changes
                .iter()
                .any(|c| c.kind == "port-opened" && c.detail == "TCP 80"),
            "{changed:?}"
        );
        assert!(
            c.new_risks.iter().any(|r| r.finding.port == Some(23)
                && r.device_key.as_deref() == Some("00:00:0C:00:00:09")),
            "telnet on the new device: {:?}",
            c.new_risks
        );
        assert!(
            c.resolved_risks.iter().any(|r| r.finding.port == Some(23)
                && r.device_key.as_deref() == Some("00:00:0C:00:00:03")),
            "telnet closed on pc: {:?}",
            c.resolved_risks
        );
        assert_eq!(c.summary.new_devices, 1);
        assert_eq!(c.summary.gone_devices, 1);
        assert_eq!(c.summary.changed_devices, 2);
        assert!(!c.is_quiet());
        assert_eq!(c.unknown_devices, None, "no baseline");
        let text = render(&c, "text").unwrap();
        for want in [
            "New devices (1):",
            "newbie",
            "not proof they are offline",
            "Changed devices (2):",
            "port-opened TCP 80",
            "New risks",
            "Resolved risks",
        ] {
            assert!(text.contains(want), "{want}: {text}");
        }
        // Two identical scans: nothing changed.
        store::save_at(&path, &after, NOW - 3600).unwrap();
        let c = changes(&path, &Since::Last, NOW).unwrap();
        assert!(c.is_quiet(), "{c:?}");
        assert!(render(&c, "text").unwrap().contains("No changes."));
        remove_db(&path);
    }

    #[test]
    fn a_device_that_moved_is_changed_not_gone_and_new() {
        let path = temp_db("moved");
        let before = snap(vec![host(
            "10.0.0.5",
            "02:00:00:00:00:01",
            "tablet",
            &[22, 443],
            KEYS,
        )]);
        let after = snap(vec![host(
            "10.0.0.77",
            "06:11:22:33:44:55",
            "tablet",
            &[22, 443],
            KEYS,
        )]);
        store::save_at(&path, &before, NOW - DAY).unwrap();
        store::save_at(&path, &after, NOW - 60).unwrap();
        let c = changes(&path, &Since::Last, NOW).unwrap();
        assert!(
            c.new_devices.is_empty() && c.gone_devices.is_empty(),
            "{c:?}"
        );
        assert_eq!(c.changed_devices.len(), 1);
        let kinds: Vec<&str> = c.changed_devices[0]
            .changes
            .iter()
            .map(|c| c.kind)
            .collect();
        assert!(
            kinds.contains(&"address") && kinds.contains(&"mac"),
            "{kinds:?}"
        );
        assert_eq!(c.changed_devices[0].device.key, "02:00:00:00:00:01");
        // A different device on the old address is new, and the old one is gone.
        let other = snap(vec![host(
            "10.0.0.5",
            "06:aa:aa:aa:aa:aa",
            "other",
            &[22],
            &[],
        )]);
        store::save_at(&path, &other, NOW - 30).unwrap();
        let c = changes(&path, &Since::Last, NOW).unwrap();
        assert_eq!((c.new_devices.len(), c.gone_devices.len()), (1, 1), "{c:?}");
        remove_db(&path);
    }

    #[test]
    fn a_time_window_compares_with_the_state_at_its_start() {
        let path = temp_db("window");
        let a = host("10.0.0.5", "00:00:0C:00:00:01", "a", &[22], &[]);
        let b = host("10.0.0.6", "00:00:0C:00:00:02", "b", &[22], &[]);
        let c3 = host("10.0.0.7", "00:00:0C:00:00:03", "c", &[22], &[]);
        store::save_at(&path, &snap(vec![a.clone()]), NOW - 10 * DAY).unwrap();
        store::save_at(&path, &snap(vec![a.clone(), b.clone()]), NOW - 5 * DAY).unwrap();
        store::save_at(&path, &snap(vec![a, b, c3]), NOW - DAY).unwrap();
        let labels = |c: &Changes| {
            c.new_devices
                .iter()
                .map(|d| d.label.clone())
                .collect::<Vec<_>>()
        };
        // Since 7 days ago: the state then was scan #1 (10 days old is the newest at or before).
        let week = changes(&path, &Since::parse("7d", NOW).unwrap(), NOW).unwrap();
        assert_eq!(week.previous.as_ref().unwrap().id, 1);
        assert_eq!(labels(&week), ["b", "c"]);
        assert_eq!(week.notice, None);
        // Since 2 days ago: the state then was scan #2.
        let two = changes(&path, &Since::parse("2d", NOW).unwrap(), NOW).unwrap();
        assert_eq!(two.previous.as_ref().unwrap().id, 2);
        assert_eq!(labels(&two), ["c"]);
        // Since a date before every scan: compared with the oldest scan, and it says so.
        let all = changes(&path, &Since::parse("2000-01-01", NOW).unwrap(), NOW).unwrap();
        assert_eq!(all.previous.as_ref().unwrap().id, 1);
        assert!(
            all.notice
                .as_ref()
                .unwrap()
                .contains("No comparable scan from before"),
            "{:?}",
            all.notice
        );
        // Nothing has been scanned in the last hour: no comparison, and the answer says so.
        let hour = changes(&path, &Since::parse("1h", NOW).unwrap(), NOW).unwrap();
        assert!(hour.previous.is_none() && hour.is_quiet());
        assert!(hour.notice.unwrap().contains("older than the window"));
        remove_db(&path);
    }

    #[test]
    fn scans_that_cannot_be_compared_are_skipped_or_explained() {
        let path = temp_db("settings");
        let a = host("10.0.0.5", "00:00:0C:00:00:01", "a", &[22], &[]);
        let b = host("10.0.0.6", "00:00:0C:00:00:02", "b", &[22], &[]);
        store::save_at(&path, &snap(vec![a.clone()]), NOW - 3 * DAY).unwrap();
        // A later scan with other ports cannot be compared with the newest one ...
        let mut other_ports = snap(vec![a.clone()]);
        other_ports.settings.ports = "1-1024".into();
        store::save_at(&path, &other_ports, NOW - 2 * DAY).unwrap();
        store::save_at(&path, &snap(vec![a.clone(), b]), NOW - DAY).unwrap();
        // ... so the one before it is used.
        let c = changes(&path, &Since::Last, NOW).unwrap();
        assert_eq!(c.previous.as_ref().unwrap().id, 1, "{c:?}");
        assert_eq!(c.new_devices.len(), 1);
        // Only incomparable scans: an explanation, not an error.
        let only = temp_db("settings-only");
        store::save_at(&only, &other_ports, NOW - 2 * DAY).unwrap();
        store::save_at(&only, &snap(vec![a]), NOW - DAY).unwrap();
        let c = changes(&only, &Since::Last, NOW).unwrap();
        assert!(c.previous.is_none() && c.is_quiet());
        assert!(
            c.notice.unwrap().contains("can be compared"),
            "settings differ"
        );
        remove_db(&path);
        remove_db(&only);
    }

    #[test]
    fn passive_only_devices_are_not_called_gone_by_a_scan_without_a_capture() {
        let path = temp_db("passive");
        let mut before = snap(vec![host("10.0.0.5", "00:00:0C:00:00:01", "a", &[22], &[])]);
        before.observations.push(crate::passive::Observation {
            protocol: "mDNS".into(),
            mac: "00:00:0C:00:00:77".into(),
            ip: Some("10.0.0.77".parse().unwrap()),
            fields: [("hostname".to_string(), "speaker".to_string())].into(),
        });
        let after = snap(vec![host("10.0.0.5", "00:00:0C:00:00:01", "a", &[22], &[])]);
        store::save_at(&path, &before, NOW - DAY).unwrap();
        store::save_at(&path, &after, NOW - 60).unwrap();
        let c = changes(&path, &Since::Last, NOW).unwrap();
        assert!(c.gone_devices.is_empty(), "{c:?}");
        remove_db(&path);
    }

    #[test]
    fn new_devices_are_marked_when_they_are_not_on_the_baseline() {
        let path = temp_db("baseline");
        let a = host("10.0.0.5", "00:00:0C:00:00:01", "a", &[22], &[]);
        let b = host("10.0.0.6", "00:00:0C:00:00:02", "b", &[22], &[]);
        let c = host("10.0.0.7", "00:00:0C:00:00:03", "c", &[22], &[]);
        store::save_at(&path, &snap(vec![a.clone()]), NOW - 3 * DAY).unwrap();
        // b is approved; c is not.
        store::save_at(&path, &snap(vec![a.clone(), b.clone()]), NOW - 2 * DAY).unwrap();
        crate::baseline::approve(&path, None, NOW - 2 * DAY).unwrap();
        store::save_at(&path, &snap(vec![a, b, c]), NOW - DAY).unwrap();
        let r = changes(&path, &Since::Last, NOW).unwrap();
        assert_eq!(r.new_devices.len(), 1);
        assert_eq!(r.new_devices[0].label, "c");
        assert_eq!(r.new_devices[0].in_baseline, Some(false));
        assert_eq!(r.unknown_devices, Some(1));
        assert!(
            render(&r, "text")
                .unwrap()
                .contains("[not on the baseline]")
        );
        // Without a baseline the field is absent.
        let path2 = temp_db("nobaseline");
        store::save_at(
            &path2,
            &snap(vec![host("10.0.0.5", "", "a", &[22], &[])]),
            NOW - 2 * DAY,
        )
        .unwrap();
        store::save_at(
            &path2,
            &snap(vec![
                host("10.0.0.5", "", "a", &[22], &[]),
                host("10.0.0.6", "", "b", &[22], &[]),
            ]),
            NOW - DAY,
        )
        .unwrap();
        let r = changes(&path2, &Since::Last, NOW).unwrap();
        assert_eq!(r.new_devices[0].in_baseline, None);
        assert_eq!(r.unknown_devices, None);
        remove_db(&path);
        remove_db(&path2);
    }

    #[test]
    fn since_values_parse_and_bad_ones_are_refused() {
        assert_eq!(Since::parse("last", NOW).unwrap(), Since::Last);
        assert_eq!(Since::parse(" LAST ", NOW).unwrap(), Since::Last);
        assert_eq!(Since::parse("7d", NOW).unwrap(), Since::At(NOW - 7 * DAY));
        assert_eq!(
            Since::parse("12h", NOW).unwrap(),
            Since::At(NOW - 12 * 3600)
        );
        assert_eq!(Since::parse("2w", NOW).unwrap(), Since::At(NOW - 14 * DAY));
        assert_eq!(Since::parse("1970-01-02", NOW).unwrap(), Since::At(DAY));
        assert_eq!(
            Since::parse("2026-11-01T08:30", NOW).unwrap(),
            Since::At(1_793_521_800)
        );
        assert_eq!(
            Since::parse("2026-11-01 08:30", NOW).unwrap(),
            Since::parse("2026-11-01T08:30", NOW).unwrap()
        );
        assert_eq!(Since::parse("2024-02-29", NOW).map(|_| ()), Ok(()));
        for bad in [
            "",
            "x",
            "0d",
            "-3d",
            "7",
            "7x",
            "d",
            "99999d",
            "2026-13-01",
            "2026-02-30",
            "2025-02-29",
            "2026-11",
            "2026-11-01-02",
            "2026-11-01T25:00",
            "2026-11-01T08",
            "1969-12-31",
            "2026-11-01T08:30:15",
        ] {
            assert!(Since::parse(bad, NOW).is_err(), "{bad:?} must be refused");
        }
    }
}
