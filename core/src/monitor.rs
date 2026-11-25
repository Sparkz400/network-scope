//! Continuous monitoring: repeat a scan, compare it with the previous one and with the set of
//! devices ever seen, and raise alerts for new devices, opened/closed ports, new findings and
//! unexpected DHCP servers. Alerts are stored in the inventory database and emitted as JSON lines.
//! A condition that persists is alerted once (`Dedup`), not every cycle; alerts can also go to
//! configured webhook/syslog destinations (`crate::notify`).
use crate::{
    devices, risk,
    risk::Severity,
    scan::{self, Host},
    store::{self, Snapshot},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    net::IpAddr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, RecvTimeoutError},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Alert {
    pub timestamp: i64,
    pub severity: Severity,
    pub kind: String,
    pub subject: String,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct Policy {
    /// Record devices without alerting (the first run does this automatically).
    pub learn: bool,
    /// DHCP servers that are expected. Empty: only more than one server is reported.
    pub dhcp_allow: BTreeSet<IpAddr>,
    pub min_severity: Severity,
    pub report_missing: bool,
    /// Alert delivery and de-duplication.
    pub notify: Notify,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            learn: false,
            dhcp_allow: BTreeSet::new(),
            min_severity: Severity::Low,
            report_missing: false,
            notify: Notify::default(),
        }
    }
}

/// Where alerts go besides stdout/the database, and how repeats are handled.
#[derive(Clone, Debug)]
pub struct Notify {
    /// Webhook/syslog destinations (opt-in; empty by default).
    pub sinks: Vec<crate::notify::Sink>,
    /// Per-operation network timeout for the sinks.
    pub timeout: Duration,
    /// Raise an alert only when its condition is new, not on every cycle while it persists.
    pub dedup: bool,
    /// With `dedup`: raise a persisting condition again after this long. `None`: only after it
    /// resolved and came back.
    pub renotify: Option<Duration>,
}
impl Default for Notify {
    fn default() -> Self {
        Self {
            sinks: vec![],
            timeout: crate::notify::DEFAULT_TIMEOUT,
            dedup: true,
            renotify: Some(Duration::from_secs(24 * 3600)),
        }
    }
}

/// The identity of an alert's condition, for de-duplication: kind, subject and the stable part
/// of the message (counters, offered addresses and similar details are left out).
pub fn alert_key(a: &Alert) -> String {
    let detail = match a.kind.as_str() {
        // "N DHCP servers answer: ip (how); ip (how)": the set of servers
        "rogue-dhcp" if a.subject == "dhcp" => {
            let mut servers: Vec<&str> = a
                .message
                .split_once(": ")
                .map_or("", |(_, list)| list)
                .split("; ")
                .map(|s| s.split(" (").next().unwrap_or_default())
                .collect();
            servers.sort_unstable();
            servers.join(",")
        }
        "capture-incomplete" | "dhcp-discover-failed" | "rogue-dhcp" => String::new(),
        // The subject is the stable device key; the addresses in the message change.
        "unknown-device" => String::new(),
        // new-device/device-missing (the subject is only the first IP; the message names the
        // device), new-finding (title and evidence, as fine as `risk::Finding::key`),
        // port-opened/closed ("ip: TCP port N ..."), address-changed and anything else
        _ => a.message.clone(),
    };
    format!("{}|{}|{detail}", a.kind, a.subject)
}

/// De-duplication across monitoring cycles. A key raised in a cycle is suppressed in later
/// cycles while it keeps being produced; it is raised again after a complete cycle without it
/// (the condition resolved, then recurred) or after `renotify`.
#[derive(Debug, Default)]
pub struct Dedup {
    /// key -> when it was last raised (emitted)
    active: HashMap<String, i64>,
    renotify: Option<i64>,
}
impl Dedup {
    pub fn new(renotify: Option<Duration>) -> Self {
        Self {
            active: HashMap::new(),
            renotify: renotify.map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX)),
        }
    }
    /// The oldest alert time that can still suppress a repeat at `now`: with `renotify`, an
    /// alert raised that long ago is raised again anyway; without it, any alert can.
    pub fn restore_since(&self, now: i64) -> i64 {
        self.renotify.map_or(0, |r| now.saturating_sub(r))
    }
    /// Seeds the state from stored alerts of this monitor (`store::list_alerts_since` with
    /// `restore_since` and the monitor's targets), so a restarted monitor does not repeat what
    /// it raised before: the latest raise time of each key is restored, which also restarts the
    /// `renotify` timer where it was.
    pub fn restore(&mut self, stored: &[Alert], now: i64) {
        let since = self.restore_since(now);
        for a in stored.iter().filter(|a| a.timestamp >= since) {
            let t = self.active.entry(alert_key(a)).or_insert(a.timestamp);
            *t = (*t).max(a.timestamp);
        }
    }
    /// The alerts to raise this cycle and how many repeats were suppressed. `complete`: the
    /// cycle compared everything, so a key it did not produce has resolved. After an
    /// incomplete cycle (comparisons skipped) nothing counts as resolved.
    pub fn filter(&mut self, alerts: Vec<Alert>, now: i64, complete: bool) -> (Vec<Alert>, usize) {
        let mut seen = HashSet::new();
        let mut out = vec![];
        let mut suppressed = 0;
        for a in alerts {
            let key = alert_key(&a);
            let repeat = self.active.get(&key).is_some_and(|&last| {
                seen.contains(&key) || self.renotify.is_none_or(|r| now - last < r)
            });
            if repeat {
                suppressed += 1;
            } else {
                self.active.insert(key.clone(), now);
                out.push(a);
            }
            seen.insert(key);
        }
        if complete {
            self.active.retain(|k, _| seen.contains(k));
        }
        (out, suppressed)
    }
}

/// Alert kinds `evaluate` filters by `min_severity`, with the highest severity each can have.
/// (`new-finding` can have any severity; notices such as `capture-incomplete` are never
/// filtered.)
const KIND_MAX_SEVERITY: [(&str, Severity); 7] = [
    ("port-closed", Severity::Info),
    ("device-missing", Severity::Low),
    ("address-changed", Severity::Medium),
    ("unknown-device", Severity::Medium),
    ("new-device", Severity::High),
    ("port-opened", Severity::High),
    ("rogue-dhcp", Severity::Critical),
];

/// With `--report-missing`: a one-line hint when `min_severity` hides whole alert kinds.
pub fn severity_hint(policy: &Policy) -> Option<String> {
    if !policy.report_missing {
        return None;
    }
    let hidden: Vec<String> = KIND_MAX_SEVERITY
        .iter()
        .filter(|(_, s)| *s < policy.min_severity)
        .map(|(k, s)| format!("{k} ({})", s.name()))
        .collect();
    if hidden.is_empty() {
        return None;
    }
    Some(format!(
        "Hint: --min-severity {} hides these alert kinds: {}{}",
        policy.min_severity.name(),
        hidden.join(", "),
        if policy.min_severity > Severity::Low {
            "; --report-missing has no visible effect (use --min-severity low)"
        } else {
            ""
        }
    ))
}

const RISKY_PORTS: [u16; 14] = [
    21, 23, 69, 135, 139, 445, 1433, 3306, 3389, 5900, 6379, 27017, 2375, 502,
];

/// Every DHCP server seen: scan answers (DHCPINFORM), passive OFFER/ACK traffic and active discovery.
pub fn dhcp_servers(s: &Snapshot) -> BTreeMap<IpAddr, String> {
    let mut found = BTreeMap::new();
    for h in &s.hosts {
        if let Some(info) = h.identity.get("udp.67") {
            let ip = info
                .split("server ")
                .nth(1)
                .and_then(|r| r.split([',', ')']).next())
                .and_then(|a| a.trim().parse().ok())
                .unwrap_or(h.ip);
            found.insert(ip, format!("answered DHCPINFORM at {}", h.ip));
        }
    }
    for o in &s.observations {
        if o.protocol == "DHCP" {
            // A passive DHCP observation's `ip` is the client. Servers are recorded per server
            // ("dhcp_server.<ip>", from option 54 or else the IP source of an OFFER/ACK/NAK).
            for (key, kind) in &o.fields {
                let Some(server) = key
                    .strip_prefix("dhcp_server.")
                    .and_then(|v| v.parse::<IpAddr>().ok())
                else {
                    continue;
                };
                if matches!(kind.as_str(), "2" | "5") {
                    found
                        .entry(server)
                        .or_insert_with(|| "seen sending DHCP OFFER/ACK".into());
                }
            }
            continue;
        }
        let Some(ip) = o.ip else { continue };
        if o.protocol == "DHCP offer" {
            found.entry(ip).or_insert_with(|| {
                format!(
                    "answered DHCPDISCOVER offering {}",
                    o.fields.get("offered_ip").map_or("?", String::as_str)
                )
            });
        }
    }
    found
}

fn alert(
    now: i64,
    severity: Severity,
    kind: &str,
    subject: impl Into<String>,
    message: impl Into<String>,
) -> Alert {
    Alert {
        timestamp: now,
        severity,
        kind: kind.into(),
        subject: subject.into(),
        message: message.into(),
    }
}

/// What a monitoring cycle knows beyond the two snapshots: the inventory's view of device
/// identity. Empty (the default) means every device is its own key, as before device identity.
#[derive(Clone, Debug, Default)]
pub struct Context {
    /// `Device::id` -> stable device key (see [`crate::identity`]), for the devices of both
    /// snapshots. A device missing here is keyed by its id.
    pub keys: HashMap<String, String>,
    /// The approved baseline ([`crate::baseline`]). With one, a device that is not on its
    /// expected list raises `unknown-device`; without one (`None`, or a baseline that does not
    /// [`exist`](crate::baseline::Baseline::exists)) nothing is checked.
    pub baseline: Option<crate::baseline::Baseline>,
}

pub fn evaluate(
    prev: Option<&Snapshot>,
    cur: &Snapshot,
    known: &HashMap<String, (i64, i64)>,
    policy: &Policy,
    now: i64,
) -> Vec<Alert> {
    evaluate_with(prev, cur, known, policy, &Context::default(), now)
}

/// [`evaluate`] with device identity: `known` is keyed by stable device key, and a device that
/// came back under another address and another (randomised) MAC is neither new nor missing.
pub fn evaluate_with(
    prev: Option<&Snapshot>,
    cur: &Snapshot,
    known: &HashMap<String, (i64, i64)>,
    policy: &Policy,
    ctx: &Context,
    now: i64,
) -> Vec<Alert> {
    // Only the comparison of two complete scans looks at the findings.
    let compared = prev.is_some_and(|p| p.complete) && cur.complete;
    let derive = |s: &Snapshot| {
        let findings = compared.then(|| risk::analyze_snapshot(s));
        (
            devices::merge(&s.hosts, &s.observations),
            findings.unwrap_or_default(),
        )
    };
    let (before, after) = (prev.map(&derive), derive(cur));
    evaluate_derived(
        prev.zip(before.as_ref())
            .map(|(snapshot, (devices, findings))| Derived {
                snapshot,
                devices,
                findings,
            }),
        Derived {
            snapshot: cur,
            devices: &after.0,
            findings: &after.1,
        },
        known,
        policy,
        ctx,
        now,
    )
}

#[cfg(test)]
thread_local! {
    // The heavy steps done on this thread, counted for the test that a cycle does each of them
    // once: `devices::merge`, `risk::analyze_snapshot`, and stored snapshots parsed.
    pub(crate) static MERGES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(crate) static ANALYSES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(crate) static SNAPSHOTS_READ: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// A scan with what a cycle derives from it. The device merge and the risk analysis are the
/// heaviest work between the end of a scan and its alerts, so [`run`] does each once per scan
/// and hands the result to everything that needs it.
#[derive(Clone, Copy)]
struct Derived<'a> {
    snapshot: &'a Snapshot,
    /// `devices::merge` of the snapshot.
    devices: &'a [devices::Device],
    /// `risk::analyze_snapshot` of it; only read when both scans are complete.
    findings: &'a [risk::Finding],
}

fn evaluate_derived(
    previous: Option<Derived>,
    current: Derived,
    known: &HashMap<String, (i64, i64)>,
    policy: &Policy,
    ctx: &Context,
    now: i64,
) -> Vec<Alert> {
    let mut out = vec![];
    let (cur, cur_devices) = (current.snapshot, current.devices);
    let learning = policy.learn || known.is_empty();
    let key_of = |d: &devices::Device| -> String {
        ctx.keys.get(&d.id).cloned().unwrap_or_else(|| d.id.clone())
    };
    let describe = |d: &devices::Device| -> String {
        format!(
            "{} {} {} {}",
            d.ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("/"),
            d.mac,
            d.vendor,
            d.device_type
        )
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
    };

    // Not on the approved baseline. Independent of `learn` and of the first run: a baseline is
    // what the operator declared, not what was seen. The subject is the stable device key, so
    // the alert keeps its identity (and its de-duplication) when the device changes address.
    if let Some(baseline) = ctx.baseline.as_ref().filter(|b| b.exists()) {
        let keys: Vec<String> = cur_devices.iter().map(key_of).collect();
        let expected = baseline.expects(cur_devices, &keys);
        for ((d, key), expected) in cur_devices.iter().zip(&keys).zip(expected) {
            if !expected {
                out.push(alert(
                    now,
                    Severity::Medium,
                    "unknown-device",
                    key.clone(),
                    format!("Device not in the approved baseline: {}", describe(d)),
                ));
            }
        }
    }

    if !learning {
        for d in cur_devices {
            if known.contains_key(&key_of(d)) {
                continue;
            }
            let ot = d.device_type.starts_with("Industrial")
                || d.open_tcp
                    .iter()
                    .any(|p| crate::service::is_ot_port_candidate(*p));
            out.push(alert(
                now,
                if ot { Severity::High } else { Severity::Medium },
                "new-device",
                d.ips.first().map_or(d.id.clone(), ToString::to_string),
                format!("New device {}", describe(d)),
            ));
        }
    }

    if let Some(previous) = previous.filter(|p| p.snapshot.complete && cur.complete) {
        let prev = previous.snapshot;
        let old: HashMap<IpAddr, &Host> = prev
            .hosts
            .iter()
            .filter(|h| h.responding)
            .map(|h| (h.ip, h))
            .collect();
        // A port that only one of the two scans probed says nothing about a change.
        let scanned = |s: &Snapshot| -> BTreeSet<u16> {
            scan::parse_ports(&s.settings.ports)
                .unwrap_or_default()
                .into_iter()
                .collect()
        };
        let comparable: BTreeSet<u16> =
            scanned(prev).intersection(&scanned(cur)).copied().collect();
        // UDP: only when both scans probed UDP, and only ports both of them probed.
        let udp_scanned = |s: &Snapshot| -> BTreeSet<u16> {
            if !s.settings.udp {
                return BTreeSet::new();
            }
            scan::parse_ports(&s.settings.udp_ports)
                .unwrap_or_default()
                .into_iter()
                .collect()
        };
        let udp_comparable: BTreeSet<u16> = udp_scanned(prev)
            .intersection(&udp_scanned(cur))
            .copied()
            .collect();
        for h in cur.hosts.iter().filter(|h| h.responding) {
            let Some(before) = old.get(&h.ip) else {
                continue;
            };
            // A port is compared when both scans looked at it: every port of a fully checked host,
            // the probed ports of one that an incremental scan sampled.
            let tcp_ok = |p: &u16| {
                comparable.contains(p)
                    && crate::incremental::checked(h, *p)
                    && crate::incremental::checked(before, *p)
            };
            let udp_ok = before.ports_checked && h.ports_checked;
            for p in h
                .open
                .iter()
                .filter(|p| tcp_ok(p) && !before.open.contains(p))
            {
                let sev = if RISKY_PORTS.contains(p) {
                    Severity::High
                } else {
                    Severity::Medium
                };
                out.push(alert(
                    now,
                    sev,
                    "port-opened",
                    h.ip.to_string(),
                    format!("{}: TCP port {p} newly open", h.ip),
                ));
            }
            for p in before
                .open
                .iter()
                .filter(|p| tcp_ok(p) && !h.open.contains(p))
            {
                out.push(alert(
                    now,
                    Severity::Info,
                    "port-closed",
                    h.ip.to_string(),
                    format!(
                        "{}: TCP port {p} no longer open (a timeout is not proof it closed)",
                        h.ip
                    ),
                ));
            }
            for p in h
                .udp_open
                .iter()
                .filter(|p| udp_ok && udp_comparable.contains(p) && !before.udp_open.contains(p))
            {
                out.push(alert(
                    now,
                    Severity::Medium,
                    "port-opened",
                    h.ip.to_string(),
                    format!("{}: UDP port {p} newly answering", h.ip),
                ));
            }
        }
        for f in new_findings(previous.findings, current.findings.to_vec()) {
            out.push(alert(
                now,
                f.severity,
                "new-finding",
                format!(
                    "{}{}",
                    f.ip,
                    f.port.map_or(String::new(), |p| format!(":{p}"))
                ),
                format!("{} - {}", f.title, f.evidence),
            ));
        }
        let now_by_id: HashMap<&str, &devices::Device> =
            cur_devices.iter().map(|d| (d.id.as_str(), d)).collect();
        let now_keys: HashSet<String> = cur_devices.iter().map(key_of).collect();
        for d in previous.devices {
            match now_by_id.get(d.id.as_str()) {
                Some(n)
                    if !d.mac.is_empty()
                        && n.ips != d.ips
                        && !d.ips.is_empty()
                        && !n.ips.is_empty() =>
                {
                    // Medium: a known MAC on a new address can be spoofing or a misconfiguration.
                    out.push(alert(
                        now,
                        Severity::Medium,
                        "address-changed",
                        d.mac.clone(),
                        format!("{} moved from {:?} to {:?}", d.mac, d.ips, n.ips),
                    ));
                }
                // Present under another id (a rotated MAC, a new address): not missing.
                None if policy.report_missing && !now_keys.contains(&key_of(d)) => {
                    // Low, so the explicitly requested report passes the default threshold.
                    out.push(alert(
                        now,
                        Severity::Low,
                        "device-missing",
                        d.ips.first().map_or(d.id.clone(), ToString::to_string),
                        format!(
                            "{} {} was not observed in this scan (not proof it is offline)",
                            d.id, d.vendor
                        ),
                    ));
                }
                _ => {}
            }
        }
    }

    let servers = dhcp_servers(cur);
    if policy.dhcp_allow.is_empty() {
        if servers.len() > 1 {
            out.push(alert(
                now,
                Severity::High,
                "rogue-dhcp",
                "dhcp",
                format!(
                    "{} DHCP servers answer: {}",
                    servers.len(),
                    servers
                        .iter()
                        .map(|(ip, how)| format!("{ip} ({how})"))
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            ));
        }
    } else {
        for (ip, how) in servers
            .iter()
            .filter(|(ip, _)| !policy.dhcp_allow.contains(ip))
        {
            out.push(alert(
                now,
                Severity::Critical,
                "rogue-dhcp",
                ip.to_string(),
                format!(
                    "Unexpected DHCP server {ip} ({how}); allowed: {}",
                    policy
                        .dhcp_allow
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
    }
    out.retain(|a| a.severity >= policy.min_severity);
    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.kind.cmp(&b.kind))
            .then(a.subject.cmp(&b.subject))
    });
    out
}

pub struct RunConfig {
    pub interval: Duration,
    /// 0 means run until the process is stopped.
    pub cycles: u32,
    pub policy: Policy,
    pub dhcp_discover: bool,
    pub interface: String,
    pub listen_seconds: u64,
    /// `--quiet`: no hint, per-cycle summary or capture warnings on stderr (the capture
    /// warning is still raised as a `capture-incomplete` alert; delivery failures still print).
    pub quiet: bool,
    /// Repeat scans (`scan --incremental`): after a first full scan, a cycle probes the known open
    /// ports and a sample and carries the rest over from the previous cycle.
    pub incremental: bool,
    /// With `incremental`: every Nth cycle (the first, then the N+1st, ...) is a full scan; 0 never.
    pub full_every: u32,
    /// Keep only the newest this many scans of these targets in the inventory (0: all). A
    /// monitor saves one scan per cycle, 288 a day at the default interval.
    pub keep_scans: usize,
    /// Set from another thread (a service control handler, a signal handler) to end the run
    /// cleanly: the cycle in progress is cancelled (a partial scan is saved as such), the wait
    /// between cycles is cut short and [`run`] returns `Ok`. `None`: runs until the process ends.
    pub stop: Option<Arc<AtomicBool>>,
}
impl RunConfig {
    fn stopped(&self) -> bool {
        self.stop
            .as_ref()
            .is_some_and(|s| s.load(Ordering::Relaxed))
    }
}

/// How often a wait or a blocking receive looks at the stop flag.
const STOP_POLL: Duration = Duration::from_millis(250);

/// Sleeps for `total`, in slices so that a stop request ends it within [`STOP_POLL`]. Returns
/// true when the run was stopped.
fn sleep_or_stop(total: Duration, cfg: &RunConfig) -> bool {
    let end = Instant::now() + total;
    loop {
        if cfg.stopped() {
            return true;
        }
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        std::thread::sleep(left.min(STOP_POLL));
    }
}

/// The items of `receiver` until it closes or a stop is requested (then `cancel` is set, so the
/// producer ends too).
fn until_stopped<'a, T>(
    receiver: &'a Receiver<T>,
    cfg: &'a RunConfig,
    cancel: &'a AtomicBool,
) -> impl Iterator<Item = T> + 'a {
    std::iter::from_fn(move || {
        loop {
            if cfg.stopped() {
                cancel.store(true, Ordering::Relaxed);
                return None;
            }
            match receiver.recv_timeout(STOP_POLL) {
                Ok(item) => return Some(item),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return None,
            }
        }
    })
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Merges captured observations, turning capture errors and the observation cap into warnings
/// (the extra observations are dropped) instead of failing the monitoring cycle.
fn collect_observations(
    observations: &mut Vec<crate::passive::Observation>,
    items: impl IntoIterator<Item = Result<crate::passive::Observation, String>>,
) -> Vec<String> {
    let mut warnings = vec![];
    let mut capped = 0u64;
    for item in items {
        match item {
            Ok(o) => {
                if crate::observations::merge(observations, o).is_err() {
                    capped += 1;
                }
            }
            Err(e) => warnings.push(e),
        }
    }
    if capped > 0 {
        warnings.push(format!(
            "observation limit reached; {capped} further observations were not kept"
        ));
    }
    warnings
}

/// Cycles in a row that may fail before the monitor gives up. One failed cycle (the inventory
/// was locked by another program, an adapter was down after standby) is reported and the next
/// one is tried; a monitor that ended on the first error stayed down until someone noticed.
const MAX_FAILED_CYCLES: u32 = 5;

/// Seeds `dedup` from the alerts this monitor raised before a restart: those of scans of the
/// same targets. Other monitors on the same database (other targets) are not considered, so they
/// neither suppress nor renotify each other.
fn restore_dedup(dedup: &mut Dedup, db: &Path, targets_text: &str, now: i64) -> Result<(), String> {
    let stored = store::list_alerts_since(db, dedup.restore_since(now), Some(targets_text))?;
    dedup.restore(&stored, now);
    Ok(())
}

/// The newest complete scan of the targets with what a cycle derived from it, kept for the
/// next cycle: reading the scan back from the inventory (15 to 20 MB of JSON for a /16),
/// merging its devices and analysing it again was most of the time between the end of a scan
/// and its alerts. The snapshot is the one that was saved, not one read back: they differ only
/// in the settings that are never stored, which no comparison looks at.
struct Last {
    id: i64,
    /// When it was saved (Unix seconds).
    saved: i64,
    snapshot: Snapshot,
    devices: Vec<devices::Device>,
    /// The findings and what they were analysed with; `None` until a comparison needs them.
    findings: Option<(Vec<risk::Finding>, risk::Inputs)>,
}

/// Makes `last` the newest complete scan of the targets in the inventory. What was kept from
/// the last cycle stays while it still is that scan, which the inventory is asked: another
/// program may have saved or deleted one. Otherwise the scan is read.
fn sync_last(db: &Path, targets: &str, last: &mut Option<Last>) -> Result<(), String> {
    if let Some(kept) = last.as_ref() {
        let newest = store::earlier_complete(db, targets, i64::MAX, store::Earlier::Any, 1)?;
        // By id and time: the id of a deleted newest scan is given to the next one saved.
        if newest
            .first()
            .is_some_and(|e| (e.id, e.timestamp) == (kept.id, kept.saved))
        {
            return Ok(());
        }
    }
    *last = store::latest_complete(db, targets, i64::MAX)?.map(|(id, saved, snapshot)| Last {
        id,
        saved,
        devices: devices::merge(&snapshot.hosts, &snapshot.observations),
        snapshot,
        findings: None,
    });
    Ok(())
}

pub fn run(
    targets_text: &str,
    settings: scan::Settings,
    db: &Path,
    cfg: &RunConfig,
    emit: &mut dyn FnMut(&Alert),
) -> Result<(), String> {
    let targets = scan::parse_targets(targets_text, settings.skip_edges, scan::MAX_STREAM)?;
    let ports = scan::parse_ports(&settings.ports)?;
    if let Some(hint) = severity_hint(&cfg.policy).filter(|_| !cfg.quiet) {
        eprintln!("{hint}");
    }
    let notify = &cfg.policy.notify;
    let mut dedup = Dedup::new(notify.renotify);
    if notify.dedup {
        // A lookup failure only costs repeated alerts.
        if let Err(e) = restore_dedup(&mut dedup, db, targets_text, now()) {
            eprintln!("Alert history not read ({e}); persisting alerts may repeat once");
        }
    }
    // What the last run could not deliver goes out with the first cycle.
    let mut outbox = crate::notify::Outbox::restore(db, targets_text, &notify.sinks);
    let mut cycle = 0;
    let (mut failed, mut last_error) = (0, None);
    let mut last: Option<Last> = None;
    loop {
        if cfg.stopped() {
            return Ok(());
        }
        cycle += 1;
        // What was imported (or edited: the user's `cves.json`) since the last cycle is used
        // from this one on. Not part of the cycle's result: a file that cannot be read keeps
        // the loaded data, and the cycle runs.
        risk::refresh_cves();
        crate::feeds::refresh();
        crate::nvd::refresh();
        crate::csaf::refresh();
        crate::vex::refresh();
        crate::sbom::refresh();
        let result = (|| -> Result<(), String> {
            let mut observations = vec![];
            let mut notices = vec![];
            if !cfg.interface.is_empty() {
                let listening =
                    crate::passive::start(cfg.interface.clone(), cfg.listen_seconds, None);
                // A capture problem never ends monitoring: the cycle continues with what was seen.
                let items = until_stopped(&listening.receiver, cfg, &listening.cancel);
                for warning in collect_observations(&mut observations, items) {
                    if !cfg.quiet {
                        eprintln!("Cycle {cycle}: warning: {warning}");
                    }
                    notices.push(alert(
                        now(),
                        Severity::Low,
                        "capture-incomplete",
                        cfg.interface.as_str(),
                        format!("Passive capture incomplete: {warning}"),
                    ));
                }
            }
            let total = targets.count() as usize;
            let full_cycle = cfg.full_every != 0 && (cycle - 1) % cfg.full_every == 0;
            let previous = if cfg.incremental && !full_cycle {
                sync_last(db, targets_text, &mut last)?;
                let newest = last
                    .as_ref()
                    .map(|l| (l.id, &l.snapshot.settings, l.snapshot.hosts.clone()));
                match crate::incremental::base_of(newest, &settings) {
                    Ok(base) => Some(base),
                    Err(why) => {
                        if !cfg.quiet {
                            eprintln!(
                                "Cycle {cycle}: full scan instead of an incremental one: {why}"
                            );
                        }
                        None
                    }
                }
            } else {
                None
            };
            let run = scan::start_incremental(
                Box::new(targets.iter_interleaved()),
                total,
                ports.clone(),
                settings.clone(),
                previous,
            );
            let mut hosts = vec![];
            let sparse = total > scan::MAX_HOSTS;
            let mut complete = true;
            loop {
                let event = match run.receiver.recv_timeout(STOP_POLL) {
                    Ok(event) => event,
                    Err(RecvTimeoutError::Timeout) => {
                        if cfg.stopped() {
                            run.cancel.store(true, Ordering::Relaxed);
                        }
                        continue;
                    }
                    Err(e) => return Err(e.to_string()),
                };
                match event {
                    scan::Event::Host(h) => {
                        if h.responding || !sparse {
                            hosts.push(h)
                        }
                    }
                    scan::Event::Partial(_) => {}
                    scan::Event::Done => break,
                    scan::Event::Error(e) => return Err(e),
                }
            }
            if run.cancel.load(std::sync::atomic::Ordering::Relaxed) {
                complete = false;
            }
            // --ipv6-discover: the local link over IPv6, once per cycle, after the scan (the IPv4
            // hosts and their MACs are known). One echo per interface through the scan's own pacing
            // and sent log. Only a neighbour that answered this cycle's echo becomes a host of its
            // own: one whose cache entry merely flips between reachable and stale would otherwise
            // appear and vanish from cycle to cycle. The rest stays an observation.
            if settings.ipv6_discover && complete && !cfg.stopped() {
                let outcome = crate::ipv6::after_scan(
                    &settings,
                    run.sent.clone(),
                    &mut hosts,
                    crate::ipv6::AddHosts::Answered,
                );
                if !cfg.quiet {
                    for note in &outcome.found.notes {
                        eprintln!("Cycle {cycle}: warning: {note}");
                    }
                }
                observations.extend(outcome.observations);
            }
            let dhcp_log = crate::sendlog::SentLog::new();
            if cfg.dhcp_discover && !cfg.stopped() {
                match crate::udp::dhcp_discover(Duration::from_secs(4), &dhcp_log) {
                    Ok(offers) => {
                        for o in offers {
                            observations.push(crate::passive::Observation {
                                protocol: "DHCP offer".into(),
                                mac: String::new(),
                                ip: Some(IpAddr::V4(o.server)),
                                fields: BTreeMap::from([
                                    ("offered_ip".to_string(), o.offered.to_string()),
                                    (
                                        "router".to_string(),
                                        o.router.map_or(String::new(), |r| r.to_string()),
                                    ),
                                    (
                                        "dns".to_string(),
                                        o.dns
                                            .iter()
                                            .map(ToString::to_string)
                                            .collect::<Vec<_>>()
                                            .join(","),
                                    ),
                                    (
                                        "lease_seconds".to_string(),
                                        o.lease.map_or(String::new(), |l| l.to_string()),
                                    ),
                                ]),
                            });
                        }
                    }
                    Err(e) => notices.push(alert(
                        now(),
                        Severity::Low,
                        "dhcp-discover-failed",
                        "dhcp",
                        format!("DHCP discovery could not run: {e}"),
                    )),
                }
            }
            let snapshot = Snapshot {
                targets: targets_text.to_string(),
                complete,
                settings: crate::provenance::stamped(&settings),
                hosts,
                observations,
                notes: BTreeMap::new(),
                sent: crate::sendlog::merge([run.sent.snapshot(), dhcp_log.snapshot()]),
            };
            // Everything that can fail is read before the scan is saved. A scan that is saved but
            // never compared becomes the "previous" one of the next cycle, and what changed up to
            // it would never be reported.
            sync_last(db, targets_text, &mut last)?;
            let known = store::known_devices(db)?;
            let t = now();
            // Match the devices of both scans against the inventory, so a device that changed its
            // address or randomised MAC keeps its key. The registry is written only after the
            // comparison (and only for complete scans), or every new device would already be known.
            let cur_devices = devices::merge(&snapshot.hosts, &snapshot.observations);
            let registry = store::device_registry(db)?;
            let matches = crate::identity::resolve(&registry, &cur_devices);
            let mut ctx = Context {
                keys: crate::identity::key_map(&cur_devices, &matches),
                // Read every cycle, so an approval made while the monitor runs applies at once.
                baseline: Some(crate::baseline::load(db)?),
            };
            if let Some(p) = &last {
                let prev_matches = crate::identity::resolve(&registry, &p.devices);
                for (id, key) in crate::identity::key_map(&p.devices, &prev_matches) {
                    ctx.keys.entry(id).or_insert(key);
                }
            }
            // Analysed once, for the rows saved with the scan and for the comparison. What it
            // read is noted first: rules replaced while it runs then count as changed.
            let inputs = risk::Inputs::current();
            let findings = risk::analyze_snapshot(&snapshot);
            let saved = store::now();
            let id = store::save_analysed(db, &snapshot, &findings, saved)?;
            // The comparison is between two analyses with the same rules and feeds, on the same
            // day: what an import or the calendar changed in the findings of an unchanged host
            // is not a new finding. So the kept findings of the previous scan are used only
            // while nothing they depend on changed; otherwise (and for a scan that was read
            // from the inventory) the previous scan is analysed now.
            if let Some(p) = last.as_mut().filter(|_| complete)
                && !p.findings.as_ref().is_some_and(|(_, of)| of.same(&inputs))
            {
                p.findings = Some((risk::analyze_snapshot(&p.snapshot), inputs.clone()));
            }
            let previous = last.as_ref().map(|p| Derived {
                snapshot: &p.snapshot,
                devices: &p.devices,
                findings: p.findings.as_ref().map_or(&[], |(f, _)| f),
            });
            let current = Derived {
                snapshot: &snapshot,
                devices: &cur_devices,
                findings: &findings,
            };
            let mut alerts = evaluate_derived(previous, current, &known, &cfg.policy, &ctx, t);
            alerts.extend(notices);
            let mut suppressed = 0;
            if notify.dedup {
                (alerts, suppressed) = dedup.filter(alerts, t, complete);
            }
            if !cfg.quiet {
                eprintln!(
                    "Cycle {cycle}: scan #{id}, {} hosts, {} alerts{}",
                    snapshot.hosts.len(),
                    alerts.len(),
                    if suppressed > 0 {
                        format!(" ({suppressed} still-active alerts not repeated)")
                    } else {
                        String::new()
                    }
                );
            }
            for a in &alerts {
                emit(a);
            }
            // Delivery problems are reported and never end monitoring; what a sink did not take
            // is sent again with the next cycle.
            for warning in outbox.deliver(&notify.sinks, &alerts, notify.timeout) {
                eprintln!("Cycle {cycle}: alert delivery failed: {warning}");
            }
            // The bookkeeping comes after the alerts went out: a failure here costs the stored
            // copy of an alert or raises a new device once more, never the alert itself.
            store::save_alerts(db, id, &alerts)?;
            if complete {
                store::record_devices(db, &cur_devices, t)?;
            }
            if cfg.keep_scans > 0 {
                let rule = store::Prune {
                    scope: Some(targets_text),
                    keep: Some(cfg.keep_scans),
                    ..Default::default()
                };
                // Housekeeping never fails a cycle.
                if let Err(e) = store::prune(db, &rule) {
                    eprintln!("Cycle {cycle}: older scans not deleted: {e}");
                }
            }
            if complete {
                // The scan the next cycle compares with (see `sync_last`).
                last = Some(Last {
                    id,
                    saved,
                    snapshot,
                    devices: cur_devices,
                    findings: Some((findings, inputs)),
                });
            }
            Ok(())
        })();
        if let Err(e) = result {
            failed += 1;
            // Also with --quiet: a cycle that did not run is an error, not progress.
            eprintln!("Cycle {cycle} failed: {e}");
            let notice = alert(
                now(),
                Severity::Medium,
                "monitor-cycle-failed",
                targets_text,
                format!("Monitoring cycle {cycle} failed: {e}"),
            );
            emit(&notice);
            for warning in
                outbox.deliver(&notify.sinks, std::slice::from_ref(&notice), notify.timeout)
            {
                eprintln!("Cycle {cycle}: alert delivery failed: {warning}");
            }
            if failed >= MAX_FAILED_CYCLES {
                return Err(format!("{e} ({failed} cycles in a row failed)"));
            }
            last_error = Some(e);
        } else {
            failed = 0;
        }
        if cfg.cycles != 0 && cycle >= cfg.cycles {
            // A run of a fixed length (a script, a test) reports a cycle that failed.
            return last_error.map_or(Ok(()), Err);
        }
        if sleep_or_stop(cfg.interval, cfg) {
            return Ok(());
        }
    }
}

/// Findings of the new scan that the previous one did not have. A finding an imported vendor
/// statement clears (VEX: not affected, fixed, false positive) is not alerted: it does not count
/// anywhere else either. One that was cleared in the previous scan and is not any more (other
/// firmware, a withdrawn statement) is new: nobody was told about it yet.
fn new_findings(before: &[risk::Finding], now: Vec<risk::Finding>) -> Vec<risk::Finding> {
    let old: HashSet<String> = before
        .iter()
        .filter(|f| !f.cleared_by_vex())
        .map(risk::Finding::key)
        .collect();
    now.into_iter()
        .filter(|f| !old.contains(&f.key()) && !f.cleared_by_vex())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passive::Observation;

    fn host(ip: &str, mac: &str, open: &[u16], id: &[(&str, &str)]) -> Host {
        Host {
            ip: ip.parse().unwrap(),
            responding: true,
            ping: None,
            ttl: None,
            hostname: String::new(),
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
    fn snap(hosts: Vec<Host>, observations: Vec<Observation>) -> Snapshot {
        Snapshot {
            sent: vec![],
            targets: "10.0.0.0/24".into(),
            complete: true,
            settings: crate::scan::Settings {
                ports: "1-1024".into(),
                ..Default::default()
            },
            hosts,
            observations,
            notes: Default::default(),
        }
    }
    fn known(keys: &[&str]) -> HashMap<String, (i64, i64)> {
        keys.iter().map(|k| (k.to_string(), (1, 1))).collect()
    }
    fn kinds(a: &[Alert]) -> Vec<&str> {
        a.iter().map(|a| a.kind.as_str()).collect()
    }

    #[test]
    fn new_devices_alert_but_the_first_run_only_learns() {
        let base = snap(
            vec![host("10.0.0.5", "AA:BB:CC:00:00:01", &[22], &[])],
            vec![],
        );
        let cur = snap(
            vec![
                host("10.0.0.5", "AA:BB:CC:00:00:01", &[22], &[]),
                host("10.0.0.9", "AA:BB:CC:00:00:09", &[502], &[]),
            ],
            vec![],
        );
        let none: HashMap<String, (i64, i64)> = HashMap::new();
        assert!(
            evaluate(None, &cur, &none, &Policy::default(), 1).is_empty(),
            "first run learns silently"
        );
        let known = known(&["AA:BB:CC:00:00:01"]);
        let a = evaluate(Some(&base), &cur, &known, &Policy::default(), 1);
        assert!(kinds(&a).contains(&"new-device"));
        let nd = a.iter().find(|a| a.kind == "new-device").unwrap();
        assert_eq!(
            nd.severity,
            Severity::High,
            "a new OT device is high severity"
        );
        assert!(nd.message.contains("10.0.0.9"));
        let learn = Policy {
            learn: true,
            ..Policy::default()
        };
        assert!(!kinds(&evaluate(Some(&base), &cur, &known, &learn, 1)).contains(&"new-device"));
    }

    #[test]
    fn a_device_that_rotated_its_mac_and_address_is_neither_new_nor_missing() {
        let identity = [
            ("ssh.22.hostkey_sha256", "aaaa"),
            ("tls.443.spki_sha256", "bbbb"),
        ];
        let before = snap(
            vec![host("10.0.0.5", "02:00:00:00:00:01", &[22, 443], &identity)],
            vec![],
        );
        let after = snap(
            vec![host(
                "10.0.0.77",
                "06:11:22:33:44:55",
                &[22, 443],
                &identity,
            )],
            vec![],
        );
        let policy = Policy {
            report_missing: true,
            ..Policy::default()
        };
        let known = known(&["02:00:00:00:00:01"]);
        // Without device identity: one new device and one missing device.
        let plain = evaluate(Some(&before), &after, &known, &policy, 1);
        assert!(kinds(&plain).contains(&"new-device"), "{plain:?}");
        assert!(kinds(&plain).contains(&"device-missing"), "{plain:?}");
        // With the inventory's view of identity: the same device.
        let mut registry = crate::identity::Registry::new();
        let old_devices = devices::merge(&before.hosts, &before.observations);
        registry.learn(&old_devices[0].id, &old_devices[0]);
        let new_devices = devices::merge(&after.hosts, &after.observations);
        let matches = crate::identity::resolve(&registry, &new_devices);
        let ctx = Context {
            keys: crate::identity::key_map(&new_devices, &matches),
            ..Default::default()
        };
        let a = evaluate_with(Some(&before), &after, &known, &policy, &ctx, 1);
        assert!(
            !kinds(&a).contains(&"new-device") && !kinds(&a).contains(&"device-missing"),
            "{a:?}"
        );
        // A different device with a new MAC and nothing in common is still new.
        let stranger = snap(
            vec![host("10.0.0.88", "06:99:99:99:99:99", &[22, 443], &[])],
            vec![],
        );
        let devices = devices::merge(&stranger.hosts, &stranger.observations);
        let matches = crate::identity::resolve(&registry, &devices);
        let ctx = Context {
            keys: crate::identity::key_map(&devices, &matches),
            ..Default::default()
        };
        let a = evaluate_with(Some(&before), &stranger, &known, &policy, &ctx, 1);
        assert!(kinds(&a).contains(&"new-device"), "{a:?}");
    }

    fn approved_baseline(tag: &str, approved: &Snapshot) -> crate::baseline::Baseline {
        let path = std::env::temp_dir().join(format!(
            "netscope-monitor-baseline-{tag}-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        store::save(&path, approved).unwrap();
        crate::baseline::approve(&path, None, 10).unwrap();
        let baseline = crate::baseline::load(&path).unwrap();
        for suffix in ["", "-wal", "-shm"] {
            let mut p = path.as_os_str().to_owned();
            p.push(suffix);
            let _ = std::fs::remove_file(std::path::PathBuf::from(p));
        }
        baseline
    }

    #[test]
    fn unknown_devices_alert_only_once_a_baseline_exists() {
        let approved = snap(
            vec![host("10.0.0.5", "00:00:0C:00:00:01", &[22], &[])],
            vec![],
        );
        let cur = snap(
            vec![
                host("10.0.0.5", "00:00:0C:00:00:01", &[22], &[]),
                host("10.0.0.9", "00:00:0C:00:00:09", &[80], &[]),
            ],
            vec![],
        );
        let devices = devices::merge(&cur.hosts, &cur.observations);
        let known = known(&["00:00:0C:00:00:01", "00:00:0C:00:00:09"]);
        let with = |baseline: Option<crate::baseline::Baseline>, policy: &Policy| {
            let ctx = Context {
                keys: devices
                    .iter()
                    .map(|d| (d.id.clone(), d.id.clone()))
                    .collect(),
                baseline,
            };
            evaluate_with(Some(&approved), &cur, &known, policy, &ctx, 1)
        };
        let baseline = approved_baseline("unknown", &approved);
        let a = with(Some(baseline.clone()), &Policy::default());
        let unknown: Vec<_> = a.iter().filter(|a| a.kind == "unknown-device").collect();
        assert_eq!(unknown.len(), 1, "{a:?}");
        assert_eq!(unknown[0].severity, Severity::Medium);
        assert_eq!(unknown[0].subject, "00:00:0C:00:00:09", "the stable key");
        assert!(unknown[0].message.contains("10.0.0.9"), "{:?}", unknown[0]);
        assert!(
            !kinds(&a).contains(&"new-device"),
            "the device is known, just not approved"
        );
        // Not gated by --learn, and the same condition at another address is the same alert.
        let learn = Policy {
            learn: true,
            ..Policy::default()
        };
        assert_eq!(
            with(Some(baseline.clone()), &learn)
                .iter()
                .filter(|a| a.kind == "unknown-device")
                .count(),
            1
        );
        let mut moved = unknown[0].clone();
        moved.message = "Device not in the approved baseline: 10.0.0.77 vendor".into();
        assert_eq!(alert_key(&moved), alert_key(unknown[0]));
        // No baseline, or an empty "baseline" object, checks nothing.
        for none in [None, Some(crate::baseline::Baseline::default())] {
            let a = with(none, &Policy::default());
            assert!(!kinds(&a).contains(&"unknown-device"), "{a:?}");
        }
        // --min-severity above medium hides it, and the hint says so.
        let high = Policy {
            min_severity: Severity::High,
            report_missing: true,
            ..Policy::default()
        };
        assert!(!kinds(&with(Some(baseline), &high)).contains(&"unknown-device"));
        assert!(severity_hint(&high).unwrap().contains("unknown-device"));
    }

    #[test]
    fn a_new_finding_a_vendor_statement_clears_is_not_alerted() {
        let finding = |id: &str, vex: Option<crate::vex::State>| risk::Finding {
            severity: Severity::High,
            id: id.into(),
            title: id.into(),
            ip: "10.0.0.5".parse().unwrap(),
            port: Some(102),
            evidence: String::new(),
            cve: vec![],
            advice: String::new(),
            exploit: Default::default(),
            reference: None,
            confidence: 40,
            vex: vex.map(|state| crate::vex::Applied {
                state,
                justification: String::new(),
                detail: String::new(),
                source: "VEX-1".into(),
            }),
        };
        let now = vec![
            finding("cve-cve-2099-1", Some(crate::vex::State::NotAffected)),
            finding("cve-cve-2099-2", Some(crate::vex::State::Affected)),
            finding("cve-cve-2099-3", None),
            finding("telnet-open", None),
        ];
        let ids: Vec<String> = new_findings(&[finding("telnet-open", None)], now)
            .into_iter()
            .map(|f| f.id)
            .collect();
        assert_eq!(ids, ["cve-cve-2099-2", "cve-cve-2099-3"]);
        // Cleared before, live now (the firmware left the statement's range): alerted.
        let cleared = finding("cve-cve-2099-1", Some(crate::vex::State::NotAffected));
        let live = finding("cve-cve-2099-1", None);
        let before = std::slice::from_ref(&cleared);
        assert_eq!(new_findings(before, vec![live]).len(), 1);
        assert!(new_findings(before, vec![cleared.clone()]).is_empty());
    }

    #[test]
    fn port_changes_and_new_findings() {
        let before = snap(
            vec![host("10.0.0.5", "AA:BB:CC:00:00:01", &[22, 80], &[])],
            vec![],
        );
        let after = snap(
            vec![host(
                "10.0.0.5",
                "AA:BB:CC:00:00:01",
                &[22, 23],
                &[("svc.23", "telnet")],
            )],
            vec![],
        );
        let a = evaluate(
            Some(&before),
            &after,
            &known(&["AA:BB:CC:00:00:01"]),
            &Policy::default(),
            1,
        );
        assert!(a.iter().any(|a| a.kind == "port-opened"
            && a.severity == Severity::High
            && a.message.contains("23")));
        assert!(
            a.iter()
                .any(|a| a.kind == "new-finding" && a.message.contains("Telnet"))
        );
        assert!(
            !a.iter().any(|a| a.kind == "port-closed"),
            "info is below the default threshold"
        );
        let all = Policy {
            min_severity: Severity::Info,
            ..Policy::default()
        };
        let a = evaluate(
            Some(&before),
            &after,
            &known(&["AA:BB:CC:00:00:01"]),
            &all,
            1,
        );
        assert!(
            a.iter()
                .any(|a| a.kind == "port-closed" && a.message.contains("80"))
        );
        // The same state again produces no change alerts.
        assert!(
            evaluate(
                Some(&after),
                &after,
                &known(&["AA:BB:CC:00:00:01"]),
                &all,
                1
            )
            .is_empty()
        );
        // A partial scan never produces change alerts: absence proves nothing.
        let mut partial = after.clone();
        partial.complete = false;
        assert!(
            evaluate(
                Some(&before),
                &partial,
                &known(&["AA:BB:CC:00:00:01"]),
                &all,
                1
            )
            .is_empty()
        );
    }

    #[test]
    fn ports_only_one_scan_probed_are_not_changes() {
        let mut before = snap(
            vec![host("10.0.0.5", "AA:BB:CC:00:00:01", &[80], &[])],
            vec![],
        );
        let after = snap(
            vec![host("10.0.0.5", "AA:BB:CC:00:00:01", &[22, 80], &[])],
            vec![],
        );
        before.settings.ports = "80".into();
        let policy = Policy {
            min_severity: Severity::Info,
            ..Policy::default()
        };
        let k = known(&["AA:BB:CC:00:00:01"]);
        let a = evaluate(Some(&before), &after, &k, &policy, 1);
        assert!(
            !a.iter().any(|a| a.kind == "port-opened"),
            "port 22 was not probed before: {a:?}"
        );
        let mut dropped = after.clone();
        dropped.settings.ports = "22".into();
        dropped.hosts[0].open = vec![22];
        let a = evaluate(Some(&before), &dropped, &k, &policy, 1);
        assert!(
            !a.iter().any(|a| a.kind == "port-closed"),
            "port 80 was not probed now: {a:?}"
        );
    }

    #[test]
    fn missing_and_moved_devices() {
        let before = snap(
            vec![
                host("10.0.0.5", "AA:BB:CC:00:00:01", &[], &[]),
                host("10.0.0.6", "AA:BB:CC:00:00:02", &[], &[]),
            ],
            vec![],
        );
        let after = snap(
            vec![host("10.0.0.50", "AA:BB:CC:00:00:01", &[], &[])],
            vec![],
        );
        let policy = Policy {
            report_missing: true,
            min_severity: Severity::Info,
            ..Policy::default()
        };
        let a = evaluate(
            Some(&before),
            &after,
            &known(&["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"]),
            &policy,
            1,
        );
        assert!(
            a.iter()
                .any(|a| a.kind == "address-changed" && a.message.contains("10.0.0.50"))
        );
        let missing = a.iter().find(|a| a.kind == "device-missing").unwrap();
        assert!(missing.message.contains("not proof"));
        let quiet = evaluate(
            Some(&before),
            &after,
            &known(&["AA:BB:CC:00:00:01"]),
            &Policy {
                min_severity: Severity::Info,
                ..Policy::default()
            },
            1,
        );
        assert!(!kinds(&quiet).contains(&"device-missing"));
    }

    #[test]
    fn rogue_dhcp_detection() {
        // As passive::decode records it: `ip` is the client, the server has its own key.
        let obs = |server: &str, kind: &str| Observation {
            protocol: "DHCP".into(),
            mac: "AA:BB:CC:00:00:77".into(),
            ip: Some("10.0.0.200".parse().unwrap()),
            fields: [
                ("message_type".to_string(), kind.to_string()),
                (format!("dhcp_server.{server}"), kind.to_string()),
            ]
            .into(),
        };
        let discover = Observation {
            protocol: "DHCP offer".into(),
            mac: String::new(),
            ip: Some("10.0.0.99".parse().unwrap()),
            fields: [("offered_ip".to_string(), "10.0.0.150".to_string())].into(),
        };
        let cur = snap(
            vec![host(
                "10.0.0.1",
                "AA:BB:CC:00:00:01",
                &[],
                &[("udp.67", "DHCP ACK (server 10.0.0.1, mask 255.255.255.0)")],
            )],
            vec![obs("10.0.0.1", "5"), discover, obs("10.0.0.7", "1")],
        );
        let servers = dhcp_servers(&cur);
        assert_eq!(
            servers.keys().map(ToString::to_string).collect::<Vec<_>>(),
            ["10.0.0.1", "10.0.0.99"],
            "a client DISCOVER (type 1) is not a server"
        );
        let k = known(&["AA:BB:CC:00:00:01"]);
        let learn = Policy {
            learn: true,
            ..Policy::default()
        };
        let a = evaluate(None, &cur, &k, &learn, 1);
        assert_eq!(
            kinds(&a),
            ["rogue-dhcp"],
            "two servers without an allow-list"
        );
        assert_eq!(a[0].severity, Severity::High);
        let allow = Policy {
            dhcp_allow: ["10.0.0.1".parse().unwrap()].into(),
            learn: true,
            ..Policy::default()
        };
        let a = evaluate(None, &cur, &k, &allow, 1);
        assert_eq!(a.len(), 1);
        assert_eq!(
            (a[0].severity, a[0].subject.as_str()),
            (Severity::Critical, "10.0.0.99")
        );
        let single = snap(vec![], vec![obs("10.0.0.1", "2")]);
        assert!(evaluate(None, &single, &k, &learn, 1).is_empty());
    }

    /// Real OFFER/ACK frames through passive::decode and observations::merge, as a live capture does.
    #[test]
    fn rogue_dhcp_from_decoded_frames() {
        use crate::passive::tests::dhcp_reply_frame;
        let client = [0xaa, 0xbb, 0xcc, 0, 0, 0x42];
        let other = [0xaa, 0xbb, 0xcc, 0, 0, 0x43];
        let capture = |frames: &[Vec<u8>]| {
            let mut observations = vec![];
            for f in frames {
                crate::observations::merge(&mut observations, crate::passive::decode(f).unwrap())
                    .unwrap();
            }
            observations
        };
        // One legitimate server handing out leases to two clients: no rogue server.
        let legit = capture(&[
            dhcp_reply_frame(
                2,
                [10, 0, 0, 1],
                Some([10, 0, 0, 1]),
                [10, 0, 0, 150],
                client,
            ),
            dhcp_reply_frame(
                5,
                [10, 0, 0, 1],
                Some([10, 0, 0, 1]),
                [10, 0, 0, 150],
                client,
            ),
            dhcp_reply_frame(
                5,
                [10, 0, 0, 1],
                Some([10, 0, 0, 1]),
                [10, 0, 0, 151],
                other,
            ),
        ]);
        let cur = snap(vec![], legit);
        assert_eq!(
            dhcp_servers(&cur)
                .keys()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["10.0.0.1"],
            "clients are not servers"
        );
        let k = known(&["AA:BB:CC:00:00:01"]);
        let learn = Policy {
            learn: true,
            ..Policy::default()
        };
        assert!(evaluate(None, &cur, &k, &learn, 1).is_empty());
        let allow = Policy {
            dhcp_allow: ["10.0.0.1".parse().unwrap()].into(),
            learn: true,
            ..Policy::default()
        };
        assert!(evaluate(None, &cur, &k, &allow, 1).is_empty());
        // A second server answers the same client: both survive the merge and are reported.
        let rogue = capture(&[
            dhcp_reply_frame(
                2,
                [10, 0, 0, 1],
                Some([10, 0, 0, 1]),
                [10, 0, 0, 150],
                client,
            ),
            dhcp_reply_frame(
                2,
                [10, 0, 0, 66],
                Some([10, 0, 0, 66]),
                [10, 0, 0, 150],
                client,
            ),
        ]);
        let cur = snap(vec![], rogue);
        let a = evaluate(None, &cur, &k, &allow, 1);
        assert_eq!(a.len(), 1, "{a:?}");
        assert_eq!(
            (a[0].kind.as_str(), a[0].severity, a[0].subject.as_str()),
            ("rogue-dhcp", Severity::Critical, "10.0.0.66")
        );
        // A relayed ACK is attributed to option 54, not to the relay.
        let relayed = capture(&[dhcp_reply_frame(
            5,
            [10, 0, 0, 254],
            Some([10, 0, 0, 1]),
            [10, 0, 0, 150],
            client,
        )]);
        assert!(evaluate(None, &snap(vec![], relayed), &k, &allow, 1).is_empty());
    }

    #[test]
    fn requested_missing_and_moved_alerts_pass_the_default_threshold() {
        let before = snap(
            vec![
                host("10.0.0.5", "AA:BB:CC:00:00:01", &[], &[]),
                host("10.0.0.6", "AA:BB:CC:00:00:02", &[], &[]),
            ],
            vec![],
        );
        let after = snap(
            vec![host("10.0.0.50", "AA:BB:CC:00:00:01", &[], &[])],
            vec![],
        );
        let policy = Policy {
            report_missing: true,
            ..Policy::default()
        };
        let k = known(&["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"]);
        let a = evaluate(Some(&before), &after, &k, &policy, 1);
        let moved = a.iter().find(|a| a.kind == "address-changed").unwrap();
        assert_eq!(moved.severity, Severity::Medium);
        let missing = a.iter().find(|a| a.kind == "device-missing").unwrap();
        assert_eq!(missing.severity, Severity::Low);
        // Without --report-missing there is still no missing-device alert.
        let a = evaluate(Some(&before), &after, &k, &Policy::default(), 1);
        assert!(!kinds(&a).contains(&"device-missing"));
    }

    #[test]
    fn udp_changes_need_udp_probed_in_both_scans() {
        let mut before = snap(
            vec![host("10.0.0.5", "AA:BB:CC:00:00:01", &[], &[])],
            vec![],
        );
        let mut after = before.clone();
        after.hosts[0].udp_open = vec![161, 5353];
        let k = known(&["AA:BB:CC:00:00:01"]);
        let udp_opened = |a: &[Alert]| {
            a.iter()
                .filter(|a| a.kind == "port-opened" && a.message.contains("UDP"))
                .map(|a| a.message.clone())
                .collect::<Vec<_>>()
        };
        // The previous scan did not probe UDP at all: nothing is "newly" answering.
        after.settings.udp = true;
        after.settings.udp_ports = "161,5353".into();
        let a = evaluate(Some(&before), &after, &k, &Policy::default(), 1);
        assert!(udp_opened(&a).is_empty(), "{a:?}");
        // Both probed UDP, but only 161 was probed before.
        before.settings.udp = true;
        before.settings.udp_ports = "161".into();
        let a = evaluate(Some(&before), &after, &k, &Policy::default(), 1);
        assert_eq!(udp_opened(&a), ["10.0.0.5: UDP port 161 newly answering"]);
    }

    #[test]
    fn capture_errors_and_the_observation_cap_do_not_fail_a_cycle() {
        let o = |i: u32| Observation {
            protocol: "ARP".into(),
            mac: format!("{i:012X}"),
            ip: None,
            fields: Default::default(),
        };
        let mut items: Vec<Result<Observation, String>> = vec![Ok(o(0)), Err("driver".into())];
        items.extend((1..10_005).map(|i| Ok(o(i))));
        let mut observations = vec![];
        let warnings = collect_observations(&mut observations, items);
        assert_eq!(observations.len(), 10_000, "truncated at the cap");
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert_eq!(warnings[0], "driver");
        assert!(warnings[1].contains("5 further"), "{warnings:?}");
    }

    fn a(kind: &str, subject: &str, message: &str) -> Alert {
        alert(0, Severity::High, kind, subject, message)
    }

    #[test]
    fn alert_keys_ignore_volatile_details() {
        let k = |kind, subject, message| alert_key(&a(kind, subject, message));
        assert_eq!(
            k(
                "rogue-dhcp",
                "dhcp",
                "2 DHCP servers answer: 10.0.0.1 (answered DHCPDISCOVER offering 10.0.0.57); 10.0.0.9 (seen sending DHCP OFFER/ACK)"
            ),
            k(
                "rogue-dhcp",
                "dhcp",
                "2 DHCP servers answer: 10.0.0.9 (x); 10.0.0.1 (answered DHCPDISCOVER offering 10.0.0.80)"
            )
        );
        assert_ne!(
            k(
                "rogue-dhcp",
                "dhcp",
                "2 DHCP servers answer: 10.0.0.1 (x); 10.0.0.9 (y)"
            ),
            k(
                "rogue-dhcp",
                "dhcp",
                "2 DHCP servers answer: 10.0.0.1 (x); 10.0.0.7 (y)"
            )
        );
        assert_ne!(
            k("new-finding", "10.0.0.5:502", "Control traffic - Write"),
            k("new-finding", "10.0.0.5:502", "Control traffic - Stop")
        );
        assert_eq!(
            k(
                "capture-incomplete",
                "eth0",
                "Passive capture incomplete: 5 dropped"
            ),
            k(
                "capture-incomplete",
                "eth0",
                "Passive capture incomplete: 9 dropped"
            )
        );
        assert_ne!(
            k(
                "port-opened",
                "10.0.0.5",
                "10.0.0.5: TCP port 22 newly open"
            ),
            k(
                "port-opened",
                "10.0.0.5",
                "10.0.0.5: TCP port 23 newly open"
            )
        );
        assert_ne!(
            k("new-device", "10.0.0.5", ""),
            k("device-missing", "10.0.0.5", "")
        );
        // two devices on one IP in consecutive cycles both alert
        let mut d = Dedup::new(None);
        let first = a(
            "new-device",
            "10.0.0.5",
            "New device 10.0.0.5 AA:BB:CC:00:00:01",
        );
        let second = a(
            "new-device",
            "10.0.0.5",
            "New device 10.0.0.5 AA:BB:CC:00:00:02",
        );
        assert_eq!(d.filter(vec![first], 1, true).0.len(), 1);
        assert_eq!(d.filter(vec![second], 2, true).0.len(), 1);
    }

    #[test]
    fn persisting_alerts_are_raised_once() {
        let rogue = || {
            a(
                "rogue-dhcp",
                "10.0.0.66",
                "Unexpected DHCP server 10.0.0.66",
            )
        };
        let port = || {
            a(
                "port-opened",
                "10.0.0.5",
                "10.0.0.5: TCP port 23 newly open",
            )
        };
        let mut d = Dedup::new(None);
        let (out, n) = d.filter(vec![rogue(), port()], 100, true);
        assert_eq!((out.len(), n), (2, 0));
        // the condition persists: not raised again
        let (out, n) = d.filter(vec![rogue()], 200, true);
        assert_eq!((out.len(), n), (0, 1));
        // an incomplete cycle without it does not count as resolved
        let (out, _) = d.filter(vec![], 300, false);
        assert!(out.is_empty());
        let (out, n) = d.filter(vec![rogue()], 400, true);
        assert_eq!((out.len(), n), (0, 1));
        // resolved in a complete cycle, then recurring: raised again
        d.filter(vec![], 500, true);
        let (out, _) = d.filter(vec![rogue(), port()], 600, true);
        assert_eq!(kinds(&out), ["rogue-dhcp", "port-opened"]);
        // the same key twice in one cycle is raised once
        let mut d = Dedup::new(None);
        let (out, n) = d.filter(vec![rogue(), rogue()], 1, true);
        assert_eq!((out.len(), n), (1, 1));
    }

    #[test]
    fn persisting_alerts_are_repeated_after_the_renotify_interval() {
        let rogue = || a("rogue-dhcp", "10.0.0.66", "x");
        let mut d = Dedup::new(Some(Duration::from_secs(3600)));
        assert_eq!(d.filter(vec![rogue()], 0, true).0.len(), 1);
        assert_eq!(d.filter(vec![rogue()], 3599, true).0.len(), 0);
        assert_eq!(d.filter(vec![rogue()], 3600, true).0.len(), 1);
        assert_eq!(
            d.filter(vec![rogue()], 4000, true).0.len(),
            0,
            "timer restarted"
        );
    }

    #[test]
    fn dedup_state_is_restored_from_stored_alerts() {
        let mut old = a("rogue-dhcp", "10.0.0.66", "x");
        old.timestamp = 1000;
        let mut ancient = a("new-device", "10.0.0.7", "New device 10.0.0.7");
        ancient.timestamp = 10;
        // Without renotify any stored alert still counts, however old.
        let mut d = Dedup::new(None);
        assert_eq!(d.restore_since(1500), 0);
        d.restore(&[old.clone(), ancient.clone()], 1500);
        let (out, n) = d.filter(vec![old.clone(), ancient.clone()], 1600, true);
        assert_eq!((out.len(), n), (0, 2));
        // With renotify, an alert older than the interval would be raised again anyway, and
        // a restored one keeps its original timer.
        let mut d = Dedup::new(Some(Duration::from_secs(900)));
        assert_eq!(d.restore_since(1500), 600);
        d.restore(&[old.clone(), ancient.clone()], 1500);
        let (out, n) = d.filter(vec![old.clone(), ancient], 1600, true);
        assert_eq!(n, 1, "the recent alert is not repeated after a restart");
        assert_eq!(kinds(&out), ["new-device"]);
        let (out, _) = d.filter(vec![old], 1900, true);
        assert_eq!(out.len(), 1, "raised again 900 s after its stored time");
    }

    fn temp_db(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "netscope-monitor-{tag}-{}-{}.sqlite",
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
            let _ = std::fs::remove_file(std::path::PathBuf::from(p));
        }
    }

    /// One monitoring cycle against `db` the way `run` does it: restore, scan row, filter, save.
    fn cycle(
        db: &Path,
        targets: &str,
        renotify: Option<Duration>,
        now: i64,
        produced: Vec<Alert>,
    ) -> Vec<Alert> {
        let mut d = Dedup::new(renotify);
        restore_dedup(&mut d, db, targets, now).unwrap();
        let id = store::save(
            db,
            &Snapshot {
                sent: vec![],
                targets: targets.into(),
                complete: true,
                settings: scan::Settings::default(),
                hosts: vec![],
                observations: vec![],
                notes: BTreeMap::new(),
            },
        )
        .unwrap();
        let (out, _) = d.filter(produced, now, true);
        store::save_alerts(db, id, &out).unwrap();
        out
    }

    fn at(t: i64, kind: &str, subject: &str, message: &str) -> Alert {
        alert(t, Severity::High, kind, subject, message)
    }

    #[test]
    fn a_restarted_monitor_does_not_repeat_what_it_raised() {
        let db = temp_db("restart");
        let rogue = |t| {
            at(
                t,
                "rogue-dhcp",
                "10.0.0.66",
                "Unexpected DHCP server 10.0.0.66",
            )
        };
        let hour = Some(Duration::from_secs(3600));
        // long before the restart, outside any short window, and with other alerts in between
        assert_eq!(
            cycle(&db, "10.0.0.0/24", hour, 1000, vec![rogue(1000)]).len(),
            1
        );
        for t in [1100, 1200] {
            let noise = at(
                t,
                "port-opened",
                "10.0.0.5",
                &format!("10.0.0.5: TCP port {t} newly open"),
            );
            cycle(&db, "10.0.0.0/24", hour, t, vec![rogue(t), noise]);
        }
        // a "restart" is a new Dedup: still suppressed 3000 s later, long after the old
        // two-intervals window, and the renotify timer continues from the first raise
        assert!(cycle(&db, "10.0.0.0/24", hour, 4000, vec![rogue(4000)]).is_empty());
        assert_eq!(
            cycle(&db, "10.0.0.0/24", hour, 4600, vec![rogue(4600)]).len(),
            1,
            "renotify window elapsed (3600 s after the raise at 1000)"
        );
        // after that raise the timer starts over
        assert!(cycle(&db, "10.0.0.0/24", hour, 5000, vec![rogue(5000)]).is_empty());
        // without renotify a persisting alert stays suppressed across restarts
        assert!(cycle(&db, "10.0.0.0/24", None, 900_000, vec![rogue(900_000)]).is_empty());
        remove_db(&db);
    }

    #[test]
    fn many_stored_alerts_do_not_push_older_state_out() {
        let db = temp_db("many");
        let first = cycle(
            &db,
            "10.0.0.0/24",
            None,
            1,
            vec![at(1, "rogue-dhcp", "10.0.0.66", "x")],
        );
        assert_eq!(first.len(), 1);
        // more alerts than any fixed row limit
        let noise: Vec<Alert> = (0..2500)
            .map(|i| {
                at(
                    2,
                    "port-opened",
                    "10.0.0.5",
                    &format!("10.0.0.5: TCP port {i} newly open"),
                )
            })
            .collect();
        cycle(&db, "10.0.0.0/24", None, 2, noise);
        let again = cycle(
            &db,
            "10.0.0.0/24",
            None,
            3,
            vec![at(3, "rogue-dhcp", "10.0.0.66", "x")],
        );
        assert!(again.is_empty());
        remove_db(&db);
    }

    #[test]
    fn monitors_with_other_targets_on_one_database_do_not_suppress_each_other() {
        let db = temp_db("scopes");
        let rogue = |t| {
            at(
                t,
                "rogue-dhcp",
                "dhcp",
                "2 DHCP servers answer: 10.0.0.1 (x); 10.0.0.9 (y)",
            )
        };
        let cap = |t| {
            at(
                t,
                "capture-incomplete",
                "eth0",
                "Passive capture incomplete: 5 dropped",
            )
        };
        let day = Some(Duration::from_secs(86_400));
        assert_eq!(
            cycle(&db, "10.0.0.0/24", day, 100, vec![rogue(100), cap(100)]).len(),
            2
        );
        // monitor B (other targets) raises the identical conditions: not suppressed by A
        assert_eq!(
            cycle(&db, "10.0.1.0/24", day, 200, vec![rogue(200), cap(200)]).len(),
            2
        );
        // each monitor, restarted, still suppresses its own and only its own
        assert!(cycle(&db, "10.0.0.0/24", day, 300, vec![rogue(300), cap(300)]).is_empty());
        assert!(cycle(&db, "10.0.1.0/24", day, 400, vec![rogue(400), cap(400)]).is_empty());
        // a third scope has its own history
        assert_eq!(
            cycle(&db, "192.168.0.0/24", day, 500, vec![rogue(500)]).len(),
            1
        );
        remove_db(&db);
    }

    #[test]
    fn hint_when_min_severity_hides_requested_alerts() {
        let mut p = Policy {
            report_missing: true,
            ..Policy::default()
        };
        // default (low): only port-closed (info) is hidden
        let h = severity_hint(&p).unwrap();
        assert!(
            h.contains("port-closed (info)") && !h.contains("device-missing"),
            "{h}"
        );
        assert!(!h.contains('\n'));
        p.min_severity = Severity::High;
        let h = severity_hint(&p).unwrap();
        assert!(
            h.contains("device-missing (low)") && h.contains("address-changed (medium)"),
            "{h}"
        );
        assert!(h.contains("--report-missing has no visible effect"), "{h}");
        p.min_severity = Severity::Info;
        assert_eq!(severity_hint(&p), None);
        p.min_severity = Severity::Critical;
        p.report_missing = false;
        assert_eq!(severity_hint(&p), None, "only with --report-missing");
    }

    fn stop_config(stop: &Arc<AtomicBool>, interval: Duration) -> RunConfig {
        RunConfig {
            interval,
            cycles: 0,
            policy: Policy::default(),
            dhcp_discover: false,
            interface: String::new(),
            listen_seconds: 1,
            quiet: true,
            incremental: false,
            full_every: 0,
            keep_scans: 0,
            stop: Some(stop.clone()),
        }
    }

    /// A database path that cannot be opened while `blocker` (a file where its directory should
    /// be) exists.
    fn blocked_db(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let blocker = std::env::temp_dir().join(format!(
            "netscope-monitor-{tag}-{}-{}",
            std::process::id(),
            now()
        ));
        let _ = std::fs::remove_dir_all(&blocker);
        std::fs::write(&blocker, b"").unwrap();
        (blocker.join("inventory.sqlite"), blocker)
    }
    fn loopback() -> scan::Settings {
        scan::Settings {
            ports: "1".into(),
            tcp_only: true,
            ..Default::default()
        }
    }

    #[test]
    fn a_failed_cycle_is_reported_and_the_next_one_runs() {
        let (db, blocker) = blocked_db("retry");
        let idle = Arc::new(AtomicBool::new(false));
        let cfg = RunConfig {
            cycles: 2,
            ..stop_config(&idle, Duration::from_millis(1))
        };
        let mut kinds = vec![];
        let result = run("127.0.0.1", loopback(), &db, &cfg, &mut |a| {
            kinds.push(a.kind.clone());
            // The first cycle could not open the inventory: make room for the second.
            if a.kind == "monitor-cycle-failed" {
                std::fs::remove_file(&blocker).unwrap();
            }
        });
        assert!(
            result.is_err(),
            "a fixed-length run reports the failed cycle"
        );
        assert_eq!(
            kinds.first().map(String::as_str),
            Some("monitor-cycle-failed")
        );
        assert_eq!(store::list(&db).unwrap().len(), 1, "the second cycle saved");
        std::fs::remove_dir_all(&blocker).unwrap();
    }

    #[test]
    fn a_monitor_gives_up_after_cycles_that_fail_in_a_row() {
        let (db, blocker) = blocked_db("give-up");
        let idle = Arc::new(AtomicBool::new(false));
        // No cycle limit: without the give-up this would never return.
        let cfg = stop_config(&idle, Duration::from_millis(1));
        let mut failures = 0;
        let error = run("127.0.0.1", loopback(), &db, &cfg, &mut |a| {
            failures += u32::from(a.kind == "monitor-cycle-failed");
        })
        .unwrap_err();
        assert_eq!(failures, MAX_FAILED_CYCLES);
        assert!(error.contains("cycles in a row failed"), "{error}");
        std::fs::remove_file(&blocker).unwrap();
    }

    #[test]
    fn a_monitor_keeps_only_the_newest_scans_it_is_told_to() {
        let db = temp_db("keep-scans");
        let idle = Arc::new(AtomicBool::new(false));
        let cfg = RunConfig {
            cycles: 4,
            keep_scans: 2,
            ..stop_config(&idle, Duration::from_millis(1))
        };
        run("127.0.0.1", loopback(), &db, &cfg, &mut |_| {}).unwrap();
        let ids: Vec<i64> = store::list(&db).unwrap().iter().map(|e| e.id).collect();
        assert_eq!(ids, [4, 3]);
        remove_db(&db);
    }

    /// The device merges, risk analyses and stored snapshots read on this thread so far.
    fn work() -> [usize; 3] {
        [MERGES.get(), ANALYSES.get(), SNAPSHOTS_READ.get()]
    }

    /// A cycle merges the devices of its scan once and analyses it once, and the next cycle
    /// compares with what was kept: per cycle it used to be four merges, three analyses and,
    /// for an incremental scan, the previous scan read from the inventory twice.
    #[test]
    fn a_cycle_derives_everything_from_its_scan_once() {
        let db = temp_db("once");
        let idle = Arc::new(AtomicBool::new(false));
        let cfg = RunConfig {
            cycles: 4,
            incremental: true,
            ..stop_config(&idle, Duration::from_millis(1))
        };
        let before = work();
        run("127.0.0.1", loopback(), &db, &cfg, &mut |_| {}).unwrap();
        let after = work();
        let [merges, analyses, read] = [0, 1, 2].map(|i| after[i] - before[i]);
        assert_eq!((merges, read), (4, 0));
        // One more when the day changes during the run: the kept findings are of yesterday.
        assert!((4..=5).contains(&analyses), "{analyses} analyses");
        assert_eq!(store::list(&db).unwrap().len(), 4);
        remove_db(&db);
    }

    /// What was kept from the last cycle is only used while the inventory would return the same
    /// scan: another program can save a scan of the same targets, or delete one.
    #[test]
    fn the_kept_scan_is_used_while_it_is_the_newest_complete_one_in_the_inventory() {
        let db = temp_db("kept");
        let scan = |targets: &str, complete: bool, open: &[u16]| Snapshot {
            targets: targets.into(),
            complete,
            ..snap(
                vec![host("10.0.0.1", "AA:BB:CC:00:00:01", open, &[])],
                vec![],
            )
        };
        let mut last = None;
        let sync = |last: &mut Option<Last>| {
            let read = SNAPSHOTS_READ.get();
            sync_last(&db, "lab", last).unwrap();
            let kept = last
                .as_ref()
                .map(|l| (l.id, l.snapshot.hosts[0].open.clone()));
            (kept, SNAPSHOTS_READ.get() - read)
        };
        assert_eq!(sync(&mut last), (None, 0));
        let first = store::save(&db, &scan("lab", true, &[22])).unwrap();
        assert_eq!(sync(&mut last), (Some((first, vec![22])), 1));
        assert_eq!(last.as_ref().unwrap().devices.len(), 1);
        // Still the newest: kept, also after scans that are not its successor.
        store::save(&db, &scan("elsewhere", true, &[1])).unwrap();
        store::save(&db, &scan("lab", false, &[2])).unwrap();
        assert_eq!(sync(&mut last), (Some((first, vec![22])), 0));
        // Another program saved a scan of these targets.
        let second = store::save(&db, &scan("lab", true, &[22, 80])).unwrap();
        assert_eq!(sync(&mut last), (Some((second, vec![22, 80])), 1));
        // It deleted it and saved another: that one gets the same id, and is not the same scan.
        store::delete(&db, second).unwrap();
        let later = store::now() + 60;
        let third = store::save_at(&db, &scan("lab", true, &[443]), later).unwrap();
        assert_eq!(third, second);
        assert_eq!(sync(&mut last), (Some((third, vec![443])), 1));
        store::delete(&db, third).unwrap();
        assert_eq!(sync(&mut last), (Some((first, vec![22])), 1));
        store::delete(&db, first).unwrap();
        assert_eq!(sync(&mut last), (None, 0));
        remove_db(&db);
    }

    /// An incremental cycle (ROADMAP B14) compares exactly the ports it looked at: a known port
    /// that closed is reported, a port it did not probe is not, and a host that was not fully
    /// checked and has no record of what it probed alerts about nothing.
    #[test]
    fn an_incremental_cycle_alerts_only_about_the_ports_it_probed() {
        let all = Policy {
            min_severity: Severity::Info,
            ..Policy::default()
        };
        let mac = "AA:BB:CC:00:00:01";
        let before = snap(vec![host("10.0.0.1", mac, &[22, 8081], &[])], vec![]);
        let cycle = |open: &[u16], rechecked: Option<&str>| {
            let mut h = host("10.0.0.1", mac, open, &[]);
            if let Some(list) = rechecked {
                h.ports_checked = false;
                h.identity.insert("incr.rechecked".into(), list.into());
            }
            let after = snap(vec![h], vec![]);
            evaluate(Some(&before), &after, &known(&[mac]), &all, 1)
        };
        // 22 was probed again and is gone; 8081 was not probed, so nothing is said about it.
        let a = cycle(&[], Some("22,80,443"));
        assert!(
            a.iter()
                .any(|a| a.kind == "port-closed" && a.message.contains("22")),
            "{a:?}"
        );
        assert!(!a.iter().any(|a| a.message.contains("8081")), "{a:?}");
        // A sampled port that opened is reported.
        let a = cycle(&[22, 8081, 23], Some("22,23,8081"));
        assert!(
            a.iter()
                .any(|a| a.kind == "port-opened" && a.message.contains("23"))
        );
        // Not fully checked and no record of what was probed: no port alert at all.
        let a = cycle(&[], Some(""));
        assert!(!a.iter().any(|a| a.kind.starts_with("port-")), "{a:?}");
        // Bookkeeping keys are not facts: an unchanged host raises nothing.
        let a = cycle(&[22, 8081], Some("22,8081"));
        assert!(!a.iter().any(|a| a.kind.starts_with("port-")), "{a:?}");
    }

    #[test]
    fn a_stop_request_cuts_the_wait_short_and_a_set_flag_runs_no_cycle() {
        let stop = Arc::new(AtomicBool::new(false));
        let cfg = stop_config(&stop, Duration::from_secs(3600));
        assert!(!cfg.stopped());
        let setter = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(300));
                stop.store(true, Ordering::Relaxed);
            })
        };
        let started = Instant::now();
        assert!(sleep_or_stop(Duration::from_secs(3600), &cfg), "stopped");
        assert!(started.elapsed() < Duration::from_secs(5));
        setter.join().unwrap();
        // Without a flag (or with it unset) the wait runs its full length.
        let idle = Arc::new(AtomicBool::new(false));
        let cfg = stop_config(&idle, Duration::ZERO);
        let started = Instant::now();
        assert!(!sleep_or_stop(Duration::from_millis(300), &cfg));
        assert!(started.elapsed() >= Duration::from_millis(300));
        let none = RunConfig {
            stop: None,
            ..stop_config(&idle, Duration::ZERO)
        };
        assert!(!none.stopped());
        // A flag that is already set: no scan starts and nothing is saved.
        let db = temp_db("preset-stop");
        let preset = Arc::new(AtomicBool::new(true));
        let settings = scan::Settings {
            ports: "1".into(),
            tcp_only: true,
            ..Default::default()
        };
        run(
            "127.0.0.1",
            settings,
            &db,
            &stop_config(&preset, Duration::from_secs(1)),
            &mut |_| {},
        )
        .unwrap();
        assert!(store::list(&db).unwrap().is_empty());
        remove_db(&db);
    }

    #[test]
    fn stopping_between_cycles_ends_the_run_cleanly_after_the_saved_scan() {
        let db = temp_db("stop-between");
        let stop = Arc::new(AtomicBool::new(false));
        // A long interval: without the stop flag this would wait for an hour.
        let cfg = stop_config(&stop, Duration::from_secs(3600));
        let setter = {
            let (stop, db) = (stop.clone(), db.clone());
            std::thread::spawn(move || {
                // Stop once the first cycle has saved its scan (the monitor is then waiting).
                for _ in 0..200 {
                    if store::list(&db).is_ok_and(|l| !l.is_empty()) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                stop.store(true, Ordering::Relaxed);
            })
        };
        let settings = scan::Settings {
            ports: "1".into(),
            tcp_only: true,
            ..Default::default()
        };
        let started = Instant::now();
        run("127.0.0.1", settings, &db, &cfg, &mut |_| {}).unwrap();
        setter.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(60));
        assert_eq!(
            store::list(&db).unwrap().len(),
            1,
            "one cycle ran, then it stopped"
        );
        remove_db(&db);
    }

    #[test]
    fn notification_defaults_are_opt_in() {
        let n = Policy::default().notify;
        assert!(n.sinks.is_empty(), "nothing is sent unless configured");
        assert!(n.dedup);
        assert_eq!(n.renotify, Some(Duration::from_secs(86_400)));
    }
}
