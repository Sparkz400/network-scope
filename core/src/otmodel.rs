// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Learn what normal industrial traffic looks like, then report what is new (ROADMAP L69).
//!
//! `ot-learn` reads a capture (a pcap file or a live, receive-only capture) and records, for every
//! device that answers an industrial protocol, **who talks to it** (peers), **with which
//! functions** (Modbus function codes, S7 job types, CIP services, DNP3 and IEC 104 commands),
//! **how often** (events per minute) and **when** (events per hour of the day, UTC). The result is
//! a [`Model`], a versioned JSON file. `ot-listen --model` then checks new traffic against it and
//! reports [`Alert`]s for anything the model has not seen:
//!
//! | Alert kind | When |
//! |---|---|
//! | `new-asset` | A device that is not in the model receives industrial traffic. |
//! | `new-station` | A client that never talked to this device before (a new engineering station, HMI or scanner). |
//! | `stop-outside-window` | A Stop, restart or PLC-control function outside the declared maintenance window (with no window declared, every Stop). |
//! | `first-write` | A write or control function that this device has never received in the learned traffic. |
//! | `new-function` | A read-type function that this device has never received. |
//! | `unusual-hour` | A write or control function at an hour of the day with no learned control traffic, when at least 24 hours were learned. |
//! | `rate-anomaly` | A minute with far more messages to a device than the busiest learned minute. |
//!
//! One message yields one alert that lists all of its reasons (a write from a new station is one
//! `new-station` alert that also names the first write); repeats of the same message are counted
//! in `occurrences`. Nothing here sends traffic: the events come from the passive tracker in
//! [`crate::otpassive`], which has no transmit path.
//!
//! # Limits
//!
//! - The model is only as good as the capture it was learned from: traffic that is rare (a yearly
//!   maintenance job) is "new" the first time it appears after learning. Learn over a
//!   representative period.
//! - Only protocols the passive decoders understand are learned (Modbus/TCP, S7comm, DNP3,
//!   IEC 104, EtherNet/IP, BACnet/IP, OPC UA); OPC UA and BACnet requests carry no function name
//!   here, so only peers and rates are learned for them.
//! - Peers are IP addresses, so an engineering station that gets a new DHCP lease looks new.
//! - A capture with scrambled time stamps gives scrambled rates and hours.
//! - Times of day are UTC unless the maintenance window gives an offset.
use crate::{otpassive::OtEvent, risk::Severity};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

/// Version of the model file; a newer file is refused.
pub const MODEL_VERSION: u32 = 1;
const MAX_ASSETS: usize = 4096;
const MAX_PEERS: usize = 256;
const MAX_FUNCTIONS: usize = 128;
const MAX_MINUTE_BUCKETS: usize = 2_000_000;
const MAX_ALERTS: usize = 10_000;
const MAX_MODEL_BYTES: u64 = 256 * 1024 * 1024;
/// A minute is a rate anomaly when its count exceeds both `3 x` the busiest learned minute and
/// the busiest learned minute plus this many messages.
const RATE_FACTOR: u32 = 3;
const RATE_MARGIN: u32 = 30;
/// Hours of learned traffic needed before the hour of the day counts for anything.
const MIN_SPAN_FOR_HOURS: i64 = 86_400;

/// How often a function was seen, and whether it is a write or control function.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionStat {
    pub count: u64,
    pub control: bool,
}

/// One client of a device.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub events: u64,
    pub first: i64,
    pub last: i64,
    /// Functions this client used (`Modbus/TCP: Read Holding Registers`).
    pub functions: BTreeSet<String>,
}

/// What was learned about one device (the server side of the industrial protocols).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AssetModel {
    pub protocols: BTreeSet<String>,
    pub first: i64,
    pub last: i64,
    pub events: u64,
    /// Client address to what it did.
    pub peers: BTreeMap<String, Peer>,
    /// `Protocol: function` to how often it was seen.
    pub functions: BTreeMap<String, FunctionStat>,
    /// Messages per hour of the day (UTC), 24 values.
    pub hours: Vec<u64>,
    /// Write and control messages per hour of the day (UTC), 24 values.
    pub control_hours: Vec<u64>,
    /// Minutes that had at least one message.
    pub active_minutes: u64,
    /// The most messages in one minute.
    pub max_per_minute: u32,
}

impl Default for AssetModel {
    fn default() -> Self {
        Self {
            protocols: BTreeSet::new(),
            first: 0,
            last: 0,
            events: 0,
            peers: BTreeMap::new(),
            functions: BTreeMap::new(),
            hours: vec![0; 24],
            control_hours: vec![0; 24],
            active_minutes: 0,
            max_per_minute: 0,
        }
    }
}

impl AssetModel {
    /// Mean messages per active minute.
    pub fn mean_per_minute(&self) -> f64 {
        if self.active_minutes == 0 {
            0.0
        } else {
            self.events as f64 / self.active_minutes as f64
        }
    }
}

/// The learned model of a network.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Model {
    pub version: u32,
    /// Where it was learned from (a file name or an interface).
    pub source: String,
    /// Time of the first and last message learned (Unix seconds).
    pub first: i64,
    pub last: i64,
    pub events: u64,
    /// Device address to what was learned about it.
    pub assets: BTreeMap<String, AssetModel>,
}

impl Model {
    pub fn load(path: &Path) -> Result<Self, String> {
        let size = std::fs::metadata(path)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .len();
        if size > MAX_MODEL_BYTES {
            return Err(format!("{}: file is too large", path.display()));
        }
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&bytes, &path.display().to_string())
    }

    /// Reads a model from its JSON text; `origin` names it in the error messages. Checks the
    /// version and the shape the detector relies on (the 24-hour tables).
    pub fn parse(bytes: &[u8], origin: &str) -> Result<Self, String> {
        let model: Self = serde_json::from_slice(bytes)
            .map_err(|e| format!("{origin}: not an OT traffic model: {e}"))?;
        if model.version != MODEL_VERSION {
            return Err(format!(
                "{origin}: model version {} is not supported (expected {MODEL_VERSION}); learn it again",
                model.version
            ));
        }
        if model.assets.len() > MAX_ASSETS {
            return Err(format!("{origin}: the model has too many devices"));
        }
        for (ip, a) in &model.assets {
            if a.hours.len() != 24 || a.control_hours.len() != 24 {
                return Err(format!(
                    "{origin}: the model of {ip} is damaged (hour tables)"
                ));
            }
        }
        Ok(model)
    }

    /// Writes the model (with its `schema` member) through a temporary file.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        let text = crate::schema::object("ot-model", self)?;
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = std::path::PathBuf::from(tmp);
        std::fs::write(&tmp, text).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("{}: {e}", path.display())
        })
    }

    /// A few lines for the terminal.
    pub fn summary(&self) -> Vec<String> {
        let mut out = vec![format!(
            "Learned {} messages to {} devices from {}",
            self.events,
            self.assets.len(),
            self.source
        )];
        for (ip, a) in &self.assets {
            let control = a.functions.values().filter(|f| f.control).count();
            out.push(format!(
                "  {ip}: {} clients, {} functions ({control} write/control), {} messages, up to {}/min",
                a.peers.len(),
                a.functions.len(),
                a.events,
                a.max_per_minute
            ));
        }
        out
    }
}

fn hour_of(ts: i64) -> usize {
    (ts.div_euclid(3600).rem_euclid(24)) as usize
}

fn function_key(e: &OtEvent) -> Option<String> {
    (!e.function.is_empty()).then(|| format!("{}: {}", e.proto, e.function))
}

/// Builds a [`Model`] from events.
pub struct Learner {
    model: Model,
    /// Messages per minute, per device.
    buckets: BTreeMap<String, BTreeMap<i64, u32>>,
    bucket_count: usize,
}

impl Learner {
    pub fn new(source: &str) -> Self {
        Self {
            model: Model {
                version: MODEL_VERSION,
                source: source.chars().take(200).collect(),
                first: 0,
                last: 0,
                events: 0,
                assets: BTreeMap::new(),
            },
            buckets: BTreeMap::new(),
            bucket_count: 0,
        }
    }

    pub fn observe(&mut self, e: &OtEvent) {
        let server = e.server.to_string();
        if !self.model.assets.contains_key(&server) && self.model.assets.len() >= MAX_ASSETS {
            return;
        }
        let m = &mut self.model;
        if m.events == 0 || e.ts < m.first {
            m.first = e.ts;
        }
        m.last = m.last.max(e.ts);
        m.events += 1;
        let a = m.assets.entry(server.clone()).or_default();
        if a.events == 0 || e.ts < a.first {
            a.first = e.ts;
        }
        a.last = a.last.max(e.ts);
        a.events += 1;
        a.protocols.insert(e.proto.to_string());
        a.hours[hour_of(e.ts)] += 1;
        let client = e.client.to_string();
        if a.peers.contains_key(&client) || a.peers.len() < MAX_PEERS {
            let p = a.peers.entry(client).or_default();
            if p.events == 0 || e.ts < p.first {
                p.first = e.ts;
            }
            p.last = p.last.max(e.ts);
            p.events += 1;
            if let Some(key) = function_key(e)
                && (p.functions.len() < MAX_FUNCTIONS || p.functions.contains(&key))
            {
                p.functions.insert(key);
            }
        }
        if let Some(key) = function_key(e)
            && (a.functions.len() < MAX_FUNCTIONS || a.functions.contains_key(&key))
        {
            let f = a.functions.entry(key).or_default();
            f.count += 1;
            f.control |= e.control;
        }
        if e.control {
            a.control_hours[hour_of(e.ts)] += 1;
        }
        if self.bucket_count < MAX_MINUTE_BUCKETS {
            let b = self.buckets.entry(server).or_default();
            let n = b.entry(e.ts.div_euclid(60)).or_insert(0);
            if *n == 0 {
                self.bucket_count += 1;
            }
            *n = n.saturating_add(1);
        }
    }

    pub fn finish(mut self) -> Model {
        for (server, minutes) in &self.buckets {
            if let Some(a) = self.model.assets.get_mut(server) {
                a.active_minutes = minutes.len() as u64;
                a.max_per_minute = minutes.values().copied().max().unwrap_or(0);
            }
        }
        self.model
    }
}

// ---- Maintenance windows -------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
struct Window {
    /// Sunday = 0.
    days: [bool; 7],
    start: u32,
    end: u32,
    /// Minutes east of UTC.
    offset: i32,
}

/// A declared maintenance window (`--maintenance "Sat 02:00-06:00"`): Stop functions inside it
/// are expected.
///
/// Several windows are separated by `;`. Each is `DAYS HH:MM-HH:MM [UTC+H[:MM]]`, with `DAYS`
/// one day (`Sat`), a range (`Mon-Fri`), a list (`Sat,Sun`) or `daily`. A window whose end is
/// before its start runs over midnight into the next day (`Sat 22:00-02:00` ends Sunday 02:00).
/// Without a zone, times are UTC.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Maintenance {
    windows: Vec<Window>,
}

const DAYS: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

fn day_index(name: &str) -> Option<usize> {
    let name = name.trim().to_ascii_lowercase();
    DAYS.iter()
        .position(|d| name.len() >= 3 && name.starts_with(d))
}

fn clock(text: &str) -> Result<u32, String> {
    let (h, m) = text
        .trim()
        .split_once(':')
        .ok_or_else(|| format!("{text:?} is not HH:MM"))?;
    let (h, m): (u32, u32) = (
        h.parse().map_err(|_| format!("{text:?} is not HH:MM"))?,
        m.parse().map_err(|_| format!("{text:?} is not HH:MM"))?,
    );
    if h > 23 || m > 59 {
        return Err(format!("{text:?} is not a time of day"));
    }
    Ok(h * 60 + m)
}

fn zone(text: &str) -> Result<i32, String> {
    let rest = text
        .trim()
        .strip_prefix("UTC")
        .or_else(|| text.trim().strip_prefix("utc"))
        .ok_or_else(|| format!("{text:?} is not a zone like UTC+1"))?;
    if rest.is_empty() {
        return Ok(0);
    }
    let sign = match rest.as_bytes()[0] {
        b'+' => 1,
        b'-' => -1,
        _ => return Err(format!("{text:?} is not a zone like UTC+1")),
    };
    let (h, m) = rest[1..].split_once(':').unwrap_or((&rest[1..], "0"));
    // Unsigned, so "UTC+-99999999" is refused here instead of overflowing below (found by fuzzing).
    let (h, m): (u32, u32) = (
        h.parse().map_err(|_| format!("{text:?} is not a zone"))?,
        m.parse().map_err(|_| format!("{text:?} is not a zone"))?,
    );
    if h > 14 || m > 59 {
        return Err(format!("{text:?} is not a zone"));
    }
    Ok(sign * (h * 60 + m) as i32)
}

impl Maintenance {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let mut windows = vec![];
        for part in spec.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            let mut words = part.split_whitespace();
            let (days_text, times, tz) = (
                words.next().ok_or("empty maintenance window")?,
                words
                    .next()
                    .ok_or_else(|| format!("{part:?}: missing HH:MM-HH:MM"))?,
                words.next(),
            );
            if words.next().is_some() {
                return Err(format!("{part:?}: too many words"));
            }
            let mut days = [false; 7];
            if ["daily", "*", "every day"].contains(&days_text.to_ascii_lowercase().as_str()) {
                days = [true; 7];
            } else {
                for item in days_text.split(',') {
                    if let Some((from, to)) = item.split_once('-') {
                        let (from, to) = (
                            day_index(from).ok_or_else(|| format!("{from:?} is not a day"))?,
                            day_index(to).ok_or_else(|| format!("{to:?} is not a day"))?,
                        );
                        let mut d = from;
                        loop {
                            days[d] = true;
                            if d == to {
                                break;
                            }
                            d = (d + 1) % 7;
                        }
                    } else {
                        days[day_index(item).ok_or_else(|| format!("{item:?} is not a day"))?] =
                            true;
                    }
                }
            }
            let (start, end) = times
                .split_once('-')
                .ok_or_else(|| format!("{times:?} is not HH:MM-HH:MM"))?;
            let (start, end) = (clock(start)?, clock(end)?);
            if start == end {
                return Err(format!("{times:?}: the window is empty"));
            }
            windows.push(Window {
                days,
                start,
                end,
                offset: tz.map(zone).transpose()?.unwrap_or(0),
            });
        }
        if windows.is_empty() {
            return Err("no maintenance window given".into());
        }
        Ok(Self { windows })
    }

    /// Whether the Unix time `ts` falls inside any window.
    pub fn contains(&self, ts: i64) -> bool {
        self.windows.iter().any(|w| {
            let local = ts.saturating_add(i64::from(w.offset) * 60);
            let minute = local.rem_euclid(86_400) as u32 / 60;
            // 1970-01-01 was a Thursday (4, with Sunday = 0).
            let day = (local.div_euclid(86_400) + 4).rem_euclid(7) as usize;
            if w.start < w.end {
                w.days[day] && minute >= w.start && minute < w.end
            } else {
                (w.days[day] && minute >= w.start) || (w.days[(day + 6) % 7] && minute < w.end)
            }
        })
    }
}

// ---- Detection -----------------------------------------------------------------------------

/// Whether a function stops, restarts or otherwise takes a controller out of operation.
pub fn is_stop(function: &str) -> bool {
    let f = function.to_ascii_lowercase();
    f.contains("stop")
        || f.contains("restart")
        || f.contains("plc control")
        || f.contains("listen only")
        || f == "reset"
        || f.contains("initialize application")
}

/// One finding of the detector.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Alert {
    /// The most telling reason (see the module documentation).
    pub kind: String,
    /// Every reason this message was reported for.
    pub kinds: Vec<String>,
    pub severity: Severity,
    pub first_seen: i64,
    pub last_seen: i64,
    pub occurrences: u64,
    pub protocol: String,
    pub client: String,
    pub server: String,
    pub function: String,
    pub control: bool,
    pub message: String,
}

/// Precedence of the reasons when naming the alert.
const ORDER: [&str; 7] = [
    "new-asset",
    "new-station",
    "stop-outside-window",
    "first-write",
    "new-function",
    "unusual-hour",
    "rate-anomaly",
];

/// Checks events against a [`Model`].
pub struct Detector {
    model: std::sync::Arc<Model>,
    window: Option<Maintenance>,
    alerts: Vec<Alert>,
    index: BTreeMap<(String, String, String, String, Vec<String>), usize>,
    buckets: BTreeMap<String, BTreeMap<i64, u32>>,
    bucket_count: usize,
    /// Messages that were not stored for lack of room.
    pub dropped: u64,
}

impl Detector {
    pub fn new(model: std::sync::Arc<Model>, window: Option<Maintenance>) -> Self {
        Self {
            model,
            window,
            alerts: vec![],
            index: BTreeMap::new(),
            buckets: BTreeMap::new(),
            bucket_count: 0,
            dropped: 0,
        }
    }

    fn push(&mut self, e: &OtEvent, mut reasons: Vec<(&'static str, String)>) {
        if reasons.is_empty() {
            return;
        }
        reasons.sort_by_key(|(k, _)| ORDER.iter().position(|o| o == k).unwrap_or(ORDER.len()));
        let kinds: Vec<String> = reasons.iter().map(|(k, _)| (*k).to_string()).collect();
        let key = (
            e.client.to_string(),
            e.server.to_string(),
            e.proto.to_string(),
            e.function.clone(),
            kinds.clone(),
        );
        if let Some(&i) = self.index.get(&key) {
            let a = &mut self.alerts[i];
            a.occurrences += 1;
            a.first_seen = a.first_seen.min(e.ts);
            a.last_seen = a.last_seen.max(e.ts);
            return;
        }
        if self.alerts.len() >= MAX_ALERTS {
            self.dropped += 1;
            return;
        }
        let severity = if e.control || kinds[0] == "stop-outside-window" {
            Severity::High
        } else if kinds.iter().any(|k| k == "new-station" || k == "new-asset") {
            Severity::Medium
        } else {
            Severity::Low
        };
        let what = if e.function.is_empty() {
            "traffic".to_string()
        } else {
            format!("{} {}", e.proto, e.function)
        };
        let message = format!(
            "{} -> {}: {what}. {}",
            e.client,
            e.server,
            reasons
                .iter()
                .map(|(_, t)| t.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        );
        self.index.insert(key, self.alerts.len());
        self.alerts.push(Alert {
            kind: kinds[0].clone(),
            kinds,
            severity,
            first_seen: e.ts,
            last_seen: e.ts,
            occurrences: 1,
            protocol: e.proto.to_string(),
            client: e.client.to_string(),
            server: e.server.to_string(),
            function: e.function.clone(),
            control: e.control,
            message,
        });
    }

    pub fn observe(&mut self, e: &OtEvent) {
        let (client, server) = (e.client.to_string(), e.server.to_string());
        let mut reasons: Vec<(&'static str, String)> = vec![];
        if self.bucket_count < MAX_MINUTE_BUCKETS {
            let b = self.buckets.entry(server.clone()).or_default();
            let n = b.entry(e.ts.div_euclid(60)).or_insert(0);
            if *n == 0 {
                self.bucket_count += 1;
            }
            *n = n.saturating_add(1);
        }
        let key = function_key(e);
        match self.model.assets.get(&server) {
            None => reasons.push((
                "new-asset",
                format!("{server} is not in the learned model."),
            )),
            Some(asset) => {
                if !asset.peers.contains_key(&client) {
                    reasons.push((
                        "new-station",
                        format!("{client} never talked to {server} in the learned traffic."),
                    ));
                }
                if let Some(key) = &key
                    && !asset.functions.contains_key(key)
                {
                    if e.control {
                        reasons.push((
                            "first-write",
                            format!("{} was never seen on {server} before.", e.function),
                        ));
                    } else {
                        reasons.push((
                            "new-function",
                            format!("{} was never seen on {server} before.", e.function),
                        ));
                    }
                }
                if e.control
                    && asset.last.saturating_sub(asset.first) >= MIN_SPAN_FOR_HOURS
                    && asset.control_hours[hour_of(e.ts)] == 0
                {
                    reasons.push((
                        "unusual-hour",
                        format!(
                            "No write or control message was learned at {:02}:00 UTC.",
                            hour_of(e.ts)
                        ),
                    ));
                }
            }
        }
        if is_stop(&e.function) && !self.window.as_ref().is_some_and(|w| w.contains(e.ts)) {
            reasons.push((
                "stop-outside-window",
                if self.window.is_some() {
                    format!("{} is outside the maintenance window.", e.function)
                } else {
                    format!(
                        "{} with no maintenance window declared (--maintenance).",
                        e.function
                    )
                },
            ));
        }
        // A device that is not in the model at all is reported once as new, not once per client
        // and function: the reasons above are only about known devices.
        self.push(e, reasons);
    }

    /// Ends the run: adds the rate anomalies and returns every alert, oldest first.
    pub fn finish(mut self) -> Vec<Alert> {
        for (server, minutes) in std::mem::take(&mut self.buckets) {
            let Some(asset) = self.model.assets.get(&server) else {
                continue;
            };
            let limit = asset
                .max_per_minute
                .saturating_mul(RATE_FACTOR)
                .max(asset.max_per_minute.saturating_add(RATE_MARGIN));
            let mut loud: Vec<(i64, u32)> =
                minutes.into_iter().filter(|(_, n)| *n > limit).collect();
            loud.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
            for (minute, n) in loud.into_iter().take(3) {
                if self.alerts.len() >= MAX_ALERTS {
                    self.dropped += 1;
                    continue;
                }
                self.alerts.push(Alert {
                    kind: "rate-anomaly".into(),
                    kinds: vec!["rate-anomaly".into()],
                    severity: Severity::Medium,
                    first_seen: minute * 60,
                    last_seen: minute * 60 + 59,
                    occurrences: u64::from(n),
                    protocol: asset
                        .protocols
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", "),
                    client: String::new(),
                    server: server.clone(),
                    function: String::new(),
                    control: false,
                    message: format!(
                        "{server}: {n} messages in one minute, the busiest learned minute had {}.",
                        asset.max_per_minute
                    ),
                });
            }
        }
        self.alerts
            .sort_by(|a, b| a.first_seen.cmp(&b.first_seen).then(a.kind.cmp(&b.kind)));
        self.alerts
    }
}

// ---- Captures ------------------------------------------------------------------------------

/// A tracker whose events go to `sink`.
fn tracker_with(
    sink: impl FnMut(&OtEvent) + Send + 'static,
    reassembly: bool,
) -> crate::otpassive::Tracker {
    let mut tracker = crate::otpassive::Tracker::new();
    tracker.set_reassembly(reassembly);
    tracker.set_event_sink(Box::new(sink));
    tracker
}

/// Learns a model from a pcap or pcapng file.
pub fn learn_pcap(path: &str, reassembly: bool) -> Result<Model, String> {
    let learner = std::sync::Arc::new(std::sync::Mutex::new(Learner::new(path)));
    let sink = learner.clone();
    let mut tracker = tracker_with(
        move |e| {
            if let Ok(mut l) = sink.lock() {
                l.observe(e);
            }
        },
        reassembly,
    );
    crate::otpassive::read_pcap_file(path, &mut tracker)?;
    drop(tracker);
    finish_learner(learner)
}

/// Learns a model from a live, receive-only capture of `seconds`.
pub fn learn_live(interface: &str, seconds: u64) -> Result<Model, String> {
    let learner = std::sync::Arc::new(std::sync::Mutex::new(Learner::new(interface)));
    let sink = learner.clone();
    let mut tracker = tracker_with(
        move |e| {
            if let Ok(mut l) = sink.lock() {
                l.observe(e);
            }
        },
        true,
    );
    let cancel = std::sync::atomic::AtomicBool::new(false);
    crate::otpassive::listen_live(interface, seconds, &cancel, &mut tracker)?;
    drop(tracker);
    finish_learner(learner)
}

fn finish_learner(learner: std::sync::Arc<std::sync::Mutex<Learner>>) -> Result<Model, String> {
    let learner = std::sync::Arc::try_unwrap(learner)
        .map_err(|_| "the learner is still in use".to_string())?
        .into_inner()
        .map_err(|_| "the learner failed".to_string())?;
    Ok(learner.finish())
}

/// What a check against a model found.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Report {
    pub source: String,
    /// Industrial messages checked.
    pub events: u64,
    pub alerts: Vec<Alert>,
    /// Alerts that did not fit the limit.
    pub dropped: u64,
}

/// A [`Detector`] that a tracker feeds through [`Checker::sink`]; [`Checker::finish`] ends the run.
/// The command line uses it to check a capture while it also saves what the capture contained.
pub struct Checker {
    shared: std::sync::Arc<std::sync::Mutex<Option<(Detector, u64)>>>,
    source: String,
}

impl Checker {
    /// `source` names the capture in the report. The detector owns a copy of the model (it is
    /// small: per device, not per message).
    pub fn new(source: &str, model: &Model, window: Option<Maintenance>) -> Self {
        Self {
            shared: std::sync::Arc::new(std::sync::Mutex::new(Some((
                Detector::new(std::sync::Arc::new(model.clone()), window),
                0,
            )))),
            source: source.chars().take(200).collect(),
        }
    }

    /// The sink to give to [`crate::otpassive::Tracker::set_event_sink`].
    pub fn sink(&self) -> crate::otpassive::EventSink {
        let shared = self.shared.clone();
        Box::new(move |e| {
            if let Ok(mut guard) = shared.lock()
                && let Some((d, n)) = guard.as_mut()
            {
                d.observe(e);
                *n += 1;
            }
        })
    }

    pub fn finish(self) -> Result<Report, String> {
        let (detector, events) = self
            .shared
            .lock()
            .map_err(|_| "the detector failed".to_string())?
            .take()
            .ok_or("the run was already finished")?;
        let dropped = detector.dropped;
        Ok(Report {
            source: self.source,
            events,
            alerts: detector.finish(),
            dropped,
        })
    }
}

impl Report {
    /// One line per alert, for the terminal.
    pub fn lines(&self) -> Vec<String> {
        let mut out = vec![format!(
            "{} industrial messages checked, {} alerts",
            self.events,
            self.alerts.len()
        )];
        for a in &self.alerts {
            out.push(format!(
                "[{}] {} {} (x{}, first at {})",
                a.severity.name().to_ascii_uppercase(),
                a.kind,
                a.message,
                a.occurrences,
                crate::research::export::rfc3339(a.first_seen)
            ));
        }
        if self.dropped > 0 {
            out.push(format!("{} further alerts were not listed", self.dropped));
        }
        out
    }
}

fn run_detector(
    source: &str,
    model: &Model,
    window: Option<Maintenance>,
    feed: impl FnOnce(&mut crate::otpassive::Tracker) -> Result<(), String>,
    reassembly: bool,
) -> Result<Report, String> {
    let checker = Checker::new(source, model, window);
    let mut tracker = crate::otpassive::Tracker::new();
    tracker.set_reassembly(reassembly);
    tracker.set_event_sink(checker.sink());
    feed(&mut tracker)?;
    checker.finish()
}

/// Checks a pcap or pcapng file against `model`.
pub fn check_pcap(
    path: &str,
    model: &Model,
    window: Option<Maintenance>,
    reassembly: bool,
) -> Result<Report, String> {
    run_detector(
        path,
        model,
        window,
        |t| crate::otpassive::read_pcap_file(path, t),
        reassembly,
    )
}

/// Checks a live, receive-only capture of `seconds` against `model`.
pub fn check_live(
    interface: &str,
    seconds: u64,
    model: &Model,
    window: Option<Maintenance>,
) -> Result<Report, String> {
    run_detector(
        interface,
        model,
        window,
        |t| {
            let cancel = std::sync::atomic::AtomicBool::new(false);
            crate::otpassive::listen_live(interface, seconds, &cancel, t)
        },
        true,
    )
}

#[cfg(test)]
#[path = "otmodel_tests.rs"]
mod tests;
