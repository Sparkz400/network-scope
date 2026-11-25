// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Automatic back-off for one host during a scan (ROADMAP H52): per-device-type limits and a
//! reaction when the host starts to fail.
//!
//! The controller only ever **slows a host down**; it never raises a limit above what Safe Mode
//! or `--parallel` allow, and `--no-backoff` turns it off completely.
//!
//! # What counts as evidence
//!
//! Closed ports answer with a refusal, and filtered ports with silence, on a perfectly healthy
//! host, so "many refusals" or "many timeouts" alone say nothing about an ordinary computer. The
//! controller therefore separates two kinds of signal:
//!
//! - **Strong signals** raise a *strike* and can lead to a pause: a connection that was reset or
//!   aborted while connecting ([`Outcome::Reset`]), and a port the scan found open that stops
//!   answering when the scan comes back to it ([`Backoff::known_open_failed`]: service
//!   identification and OT identification connect a second time to open ports). Each strike
//!   halves the host's parallel probes and doubles the delay between probes; enough strikes
//!   pause the host for the rest of the scan.
//! - **Weak signals** apply only to device types that are known to be fragile (OT controllers and
//!   printers, recognised from their open ports): a burst of refusals, or a run of timeouts, after
//!   the host had answered. They slow the host down once (one level) and never pause it.
//!
//! # Per-device-type limits
//!
//! The device type is learned from the ports found open during the scan ([`DeviceClass::of`]);
//! each class caps the parallel probes at the start, sets how long a back-off step waits and how
//! many strikes pause the host:
//!
//! | Class | Recognised by | Parallel cap | Step | Pause after |
//! | --- | --- | --- | --- | --- |
//! | Fragile | an OT or printer port is open | 2 | 250 ms | 3 strikes |
//! | Unknown | everything else (and every host at the start) | 32 | 100 ms | 4 strikes |
//! | Normal | at least two typical computer ports are open and no OT or printer port | none | 50 ms | 6 strikes |
//!
//! The caps are `min(the limit already in force, the class cap)`.
//!
//! [`Backoff`] is a pure state machine (no clock, no I/O) so it can be tested exhaustively;
//! [`HostGovernor`] wraps it for the async scan code.
use std::{
    collections::{BTreeSet, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Notify;

/// Longest delay between two probes to one host.
const MAX_DELAY: Duration = Duration::from_secs(2);
/// Strikes beyond this do not slow the host further (they can still pause it).
const MAX_LEVEL: u32 = 4;
/// Recent outcomes kept for the weak signals.
const WINDOW: usize = 12;
/// Consecutive refusals that count as a burst on a fragile host.
const REFUSAL_BURST: usize = 12;
/// Timeouts among the last [`TIMEOUT_SPAN`] outcomes that count as a run on a fragile host.
const TIMEOUT_RUN: usize = 6;
const TIMEOUT_SPAN: usize = 8;
/// Open ports remembered for classification.
const MAX_OPEN: usize = 64;

/// Ports of computers and servers (SSH, RPC, NetBIOS, SMB, RDP, WinRM, databases, VNC, NFS).
const COMPUTER_PORTS: [u16; 13] = [
    22, 111, 135, 139, 445, 1433, 2049, 3306, 3389, 5432, 5900, 5985, 5986,
];
/// Printer ports (LPD and raw print); see also [`crate::service::is_ot_port`].
fn is_printer_port(port: u16) -> bool {
    port == 515 || (9100..=9107).contains(&port)
}

/// What kind of device a host looks like, from its open ports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeviceClass {
    /// OT controller or printer: the lowest limits.
    Fragile,
    /// Nothing known (the state every host starts in): medium limits.
    Unknown,
    /// A computer or server: no extra limit.
    Normal,
}
impl DeviceClass {
    /// The class for a set of open TCP ports.
    pub fn of(open: &BTreeSet<u16>) -> Self {
        if open
            .iter()
            .any(|&p| crate::service::is_ot_port(p) || is_printer_port(p))
        {
            Self::Fragile
        } else if open.iter().filter(|p| COMPUTER_PORTS.contains(p)).count() >= 2 {
            Self::Normal
        } else {
            Self::Unknown
        }
    }
    /// Cap on parallel probes to the host.
    pub const fn parallel_cap(self) -> usize {
        match self {
            Self::Fragile => 2,
            Self::Unknown => 32,
            Self::Normal => usize::MAX,
        }
    }
    /// The delay of the first back-off level (it doubles per level).
    pub const fn step(self) -> Duration {
        match self {
            Self::Fragile => Duration::from_millis(250),
            Self::Unknown => Duration::from_millis(100),
            Self::Normal => Duration::from_millis(50),
        }
    }
    /// Strikes after which the host is paused.
    pub const fn pause_after(self) -> u32 {
        match self {
            Self::Fragile => 3,
            Self::Unknown => 4,
            Self::Normal => 6,
        }
    }
    pub const fn label(self) -> &'static str {
        match self {
            Self::Fragile => "OT/printer",
            Self::Unknown => "unclassified",
            Self::Normal => "computer",
        }
    }
}

/// What one connection attempt to the host came back as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The connection was established; the port is open.
    Open(u16),
    /// The host refused the connection (RST to the SYN): a closed port.
    Refused,
    /// No answer within the timeout.
    Timeout,
    /// The connection was reset or aborted while connecting.
    Reset,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Seen {
    Open,
    Refused,
    Timeout,
}

/// The back-off state of one host.
#[derive(Clone, Debug)]
pub struct Backoff {
    enabled: bool,
    base: usize,
    class: DeviceClass,
    open: BTreeSet<u16>,
    recent: VecDeque<u8>,
    answered: u32,
    strikes: u32,
    weak: bool,
    paused: bool,
}

impl Backoff {
    /// `base` is the number of parallel probes the scan would use (Safe Mode and `--parallel`
    /// already applied). `enabled = false` (`--no-backoff`) makes the controller inert.
    pub fn new(base: usize, enabled: bool) -> Self {
        Self {
            enabled,
            base: base.max(1),
            class: DeviceClass::Unknown,
            open: BTreeSet::new(),
            recent: VecDeque::with_capacity(WINDOW),
            answered: 0,
            strikes: 0,
            weak: false,
            paused: false,
        }
    }
    pub fn class(&self) -> DeviceClass {
        self.class
    }
    pub fn paused(&self) -> bool {
        self.paused
    }
    /// Strikes so far (strong signals).
    pub fn strikes(&self) -> u32 {
        self.strikes
    }
    fn level(&self) -> u32 {
        self.strikes.min(MAX_LEVEL).max(u32::from(self.weak))
    }
    /// Parallel probes allowed now: the class cap, halved per back-off level, at least 1.
    pub fn limit(&self) -> usize {
        if !self.enabled {
            return self.base;
        }
        (self.base.min(self.class.parallel_cap()) >> self.level()).max(1)
    }
    /// Minimum delay between launching two probes to this host.
    pub fn delay(&self) -> Duration {
        match self.level() {
            0 => Duration::ZERO,
            level => (self.class.step() * (1 << (level - 1))).min(MAX_DELAY),
        }
    }

    /// Feeds one outcome. Returns a note ("backed off: ...") when the controller reacted.
    pub fn observe(&mut self, outcome: Outcome) -> Option<String> {
        if !self.enabled {
            return None;
        }
        if self.recent.len() == WINDOW {
            self.recent.pop_front();
        }
        match outcome {
            Outcome::Open(port) => {
                self.recent.push_back(Seen::Open as u8);
                self.answered += 1;
                if self.open.len() < MAX_OPEN {
                    self.open.insert(port);
                }
                self.class = DeviceClass::of(&self.open);
                None
            }
            Outcome::Refused => {
                self.recent.push_back(Seen::Refused as u8);
                self.answered += 1;
                self.refusal_burst()
            }
            Outcome::Timeout => {
                self.recent.push_back(Seen::Timeout as u8);
                self.timeout_run()
            }
            Outcome::Reset => self.strike("a connection was reset while connecting".into()),
        }
    }

    /// A port the scan found open did not answer when the scan connected again.
    pub fn known_open_failed(&mut self, port: u16) -> Option<String> {
        if !self.enabled {
            return None;
        }
        self.strike(format!(
            "port {port} stopped answering after it was found open"
        ))
    }

    fn count(&self, last: usize, what: Seen) -> usize {
        self.recent
            .iter()
            .rev()
            .take(last)
            .filter(|s| **s == what as u8)
            .count()
    }

    /// Weak signal: a burst of refusals from a fragile host that had accepted a connection.
    fn refusal_burst(&mut self) -> Option<String> {
        let burst = self.recent.len() >= REFUSAL_BURST
            && self.count(REFUSAL_BURST, Seen::Refused) == REFUSAL_BURST;
        if self.class == DeviceClass::Fragile && !self.weak && !self.paused && burst {
            return self.slow_down(format!(
                "{REFUSAL_BURST} refused connections in a row from an {} host that had answered",
                self.class.label()
            ));
        }
        None
    }
    /// Weak signal: a run of timeouts from a fragile host that had answered before.
    fn timeout_run(&mut self) -> Option<String> {
        if self.class == DeviceClass::Fragile
            && !self.weak
            && !self.paused
            && self.answered >= 2
            && self.count(TIMEOUT_SPAN, Seen::Timeout) >= TIMEOUT_RUN
        {
            return self.slow_down(format!(
                "{TIMEOUT_RUN} of the last {TIMEOUT_SPAN} connections timed out on an {} host that had answered",
                self.class.label()
            ));
        }
        None
    }
    fn slow_down(&mut self, reason: String) -> Option<String> {
        let before = (self.limit(), self.delay());
        self.weak = true;
        Some(self.describe(&reason, before))
    }
    /// Strong signal.
    fn strike(&mut self, reason: String) -> Option<String> {
        if self.paused {
            return None;
        }
        let before = (self.limit(), self.delay());
        self.strikes += 1;
        if self.strikes >= self.class.pause_after() {
            self.paused = true;
            return Some(format!(
                "backed off: host paused for the rest of this scan after {} errors ({reason})",
                self.strikes
            ));
        }
        let after = (self.limit(), self.delay());
        (after != before).then(|| self.describe(&reason, before))
    }
    fn describe(&self, reason: &str, before: (usize, Duration)) -> String {
        format!(
            "backed off: {reason}; parallel probes {} -> {}, {} ms between probes",
            before.0,
            self.limit(),
            self.delay().as_millis()
        )
    }
}

/// Permission to start one probe. Dropping it frees the slot.
pub struct Permit(Arc<HostGovernor>);
impl Drop for Permit {
    fn drop(&mut self) {
        {
            let mut g = self.0.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.inflight = g.inflight.saturating_sub(1);
        }
        self.0.wake.notify_one();
    }
}

struct Inner {
    backoff: Backoff,
    inflight: usize,
    next_launch: Option<Instant>,
    notes: Vec<String>,
}

/// The per-host gate of a scan: decides when the next probe may start, from the limits and the
/// back-off state of [`Backoff`]. Probe tasks report what they saw with [`HostGovernor::record`].
pub struct HostGovernor {
    inner: Mutex<Inner>,
    wake: Notify,
}

impl HostGovernor {
    pub fn new(base_parallel: usize, enabled: bool) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                backoff: Backoff::new(base_parallel, enabled),
                inflight: 0,
                next_launch: None,
                notes: vec![],
            }),
            wake: Notify::new(),
        })
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
    /// Waits until a probe may start. `None` when the host is paused: the caller stops probing it.
    /// Must be called by one task at a time (the host's own scan task).
    pub async fn admit(self: &Arc<Self>) -> Option<Permit> {
        loop {
            let until = {
                let mut g = self.lock();
                if g.backoff.paused() {
                    return None;
                }
                if g.inflight >= g.backoff.limit() {
                    None
                } else {
                    let now = Instant::now();
                    match g.next_launch {
                        Some(t) if t > now => Some(t - now),
                        _ => {
                            g.inflight += 1;
                            let delay = g.backoff.delay();
                            g.next_launch = (!delay.is_zero()).then(|| now + delay);
                            return Some(Permit(self.clone()));
                        }
                    }
                }
            };
            match until {
                Some(wait) => tokio::time::sleep(wait).await,
                None => self.wake.notified().await,
            }
        }
    }
    /// Reports what a probe saw.
    pub fn record(&self, outcome: Outcome) {
        let mut g = self.lock();
        if let Some(note) = g.backoff.observe(outcome) {
            g.notes.push(note);
            drop(g);
            self.wake.notify_one();
        }
    }
    /// A port found open did not answer the second time.
    pub fn known_open_failed(&self, port: u16) {
        let mut g = self.lock();
        if let Some(note) = g.backoff.known_open_failed(port) {
            g.notes.push(note);
            drop(g);
            self.wake.notify_one();
        }
    }
    /// Records that `count` ports were not probed because the host was paused.
    pub fn note_unprobed(&self, count: usize) {
        self.lock().notes.push(format!(
            "backed off: {count} port(s) were not probed in this scan; their state is unknown, not closed"
        ));
    }
    pub fn paused(&self) -> bool {
        self.lock().backoff.paused()
    }
    pub fn limit(&self) -> usize {
        self.lock().backoff.limit()
    }
    pub fn delay(&self) -> Duration {
        self.lock().backoff.delay()
    }
    pub fn class(&self) -> DeviceClass {
        self.lock().backoff.class()
    }
    /// The "backed off: ..." notes recorded so far (taken, so each is reported once).
    pub fn take_notes(&self) -> Vec<String> {
        std::mem::take(&mut self.lock().notes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Outcome::*;

    fn feed(b: &mut Backoff, outcomes: &[Outcome]) -> Vec<String> {
        outcomes.iter().filter_map(|o| b.observe(*o)).collect()
    }

    #[test]
    fn classes_follow_the_open_ports() {
        let set = |p: &[u16]| p.iter().copied().collect::<BTreeSet<u16>>();
        for (ports, class) in [
            (&[][..], DeviceClass::Unknown),
            (&[80, 443, 8080], DeviceClass::Unknown),
            (&[22], DeviceClass::Unknown),
            (&[22, 80], DeviceClass::Unknown),
            (&[22, 445], DeviceClass::Normal),
            (&[135, 139, 445, 3389], DeviceClass::Normal),
            (&[502], DeviceClass::Fragile),
            (&[102, 445, 3389], DeviceClass::Fragile),
            (&[44818], DeviceClass::Fragile),
            (&[4840], DeviceClass::Fragile),
            (&[9100], DeviceClass::Fragile),
            (&[9107], DeviceClass::Fragile),
            (&[515, 80], DeviceClass::Fragile),
            (&[9108], DeviceClass::Unknown),
        ] {
            assert_eq!(DeviceClass::of(&set(ports)), class, "{ports:?}");
        }
        // Lowest limits for OT and printers, medium for unknown, none for computers.
        assert!(DeviceClass::Fragile.parallel_cap() < DeviceClass::Unknown.parallel_cap());
        assert!(DeviceClass::Unknown.parallel_cap() < DeviceClass::Normal.parallel_cap());
        assert!(DeviceClass::Fragile.step() > DeviceClass::Unknown.step());
        assert!(DeviceClass::Unknown.step() > DeviceClass::Normal.step());
    }

    #[test]
    fn the_class_cap_is_a_cap_never_a_raise() {
        let mut b = Backoff::new(64, true);
        assert_eq!(
            (b.limit(), b.delay()),
            (32, Duration::ZERO),
            "unknown: medium"
        );
        b.observe(Open(502));
        assert_eq!(b.class(), DeviceClass::Fragile);
        assert_eq!(b.limit(), 2);
        // Safe Mode's limit of 4 is below no cap, and below 2 stays as it is.
        assert_eq!(Backoff::new(1, true).limit(), 1);
        let mut small = Backoff::new(4, true);
        assert_eq!(small.limit(), 4, "unknown cap 32 does not raise 4");
        small.observe(Open(445));
        small.observe(Open(135));
        assert_eq!((small.class(), small.limit()), (DeviceClass::Normal, 4));
        let mut big = Backoff::new(1024, true);
        big.observe(Open(445));
        big.observe(Open(22));
        assert_eq!(big.limit(), 1024, "computers are not capped");
    }

    #[test]
    fn a_healthy_host_with_many_closed_ports_is_never_slowed_or_paused() {
        for base in [4, 64] {
            for ports in [&[80u16, 443][..], &[445, 135][..], &[22][..]] {
                let mut b = Backoff::new(base, true);
                let limit = {
                    for p in ports {
                        b.observe(Open(*p));
                    }
                    b.limit()
                };
                // Three open, then 200 refused (a Linux host) ...
                let notes = feed(&mut b, &[Refused; 200]);
                assert!(notes.is_empty(), "{notes:?}");
                assert_eq!(
                    (b.limit(), b.delay(), b.paused()),
                    (limit, Duration::ZERO, false)
                );
                // ... or 200 silent (a firewall that drops, or Windows loopback).
                let notes = feed(&mut b, &[Timeout; 200]);
                assert!(notes.is_empty(), "{notes:?}");
                assert_eq!(
                    (b.limit(), b.delay(), b.paused()),
                    (limit, Duration::ZERO, false)
                );
                assert_eq!(b.strikes(), 0);
            }
        }
        // Silence from the start, with no open port, is just a filtered host.
        let mut b = Backoff::new(64, true);
        assert!(feed(&mut b, &[Timeout; 500]).is_empty());
        assert!(!b.paused());
    }

    #[test]
    fn a_fragile_host_is_slowed_once_by_refusals_or_timeouts_and_never_paused() {
        for noisy in [Refused, Timeout] {
            let mut b = Backoff::new(64, true);
            b.observe(Open(502));
            b.observe(Open(44818));
            let notes = feed(&mut b, &[noisy; 300]);
            assert_eq!(notes.len(), 1, "{noisy:?}: {notes:?}");
            assert!(notes[0].starts_with("backed off:"), "{}", notes[0]);
            assert!(notes[0].contains("OT/printer"), "{}", notes[0]);
            assert_eq!(b.limit(), 1, "2 halved");
            assert_eq!(b.delay(), Duration::from_millis(250));
            assert!(!b.paused() && b.strikes() == 0);
        }
        // Not enough: a short run of refusals, or timeouts before the host ever answered.
        let mut b = Backoff::new(64, true);
        b.observe(Open(502));
        assert!(feed(&mut b, &[Refused; 11]).is_empty());
        let mut never_answered = Backoff::new(64, true);
        assert!(feed(&mut never_answered, &[Timeout; 50]).is_empty());
        // An interleaved open resets the burst.
        let mut mixed = Backoff::new(64, true);
        mixed.observe(Open(502));
        for _ in 0..5 {
            assert!(feed(&mut mixed, &[Refused; 11]).is_empty());
            mixed.observe(Open(502));
        }
    }

    #[test]
    fn resets_halve_the_parallelism_double_the_delay_and_then_pause() {
        let mut b = Backoff::new(64, true);
        assert_eq!(b.limit(), 32);
        let n1 = b.observe(Reset).unwrap();
        assert_eq!((b.limit(), b.delay()), (16, Duration::from_millis(100)));
        assert!(
            n1.starts_with("backed off:") && n1.contains("32 -> 16"),
            "{n1}"
        );
        b.observe(Reset).unwrap();
        assert_eq!((b.limit(), b.delay()), (8, Duration::from_millis(200)));
        b.observe(Reset).unwrap();
        assert_eq!((b.limit(), b.delay()), (4, Duration::from_millis(400)));
        assert!(!b.paused());
        let last = b.observe(Reset).unwrap();
        assert!(b.paused(), "unknown pauses after 4 strikes");
        assert!(last.contains("paused"), "{last}");
        // Paused hosts take no more events.
        assert_eq!(b.observe(Reset), None);
        assert_eq!(b.known_open_failed(80), None);
    }

    #[test]
    fn fragile_hosts_pause_sooner_and_computers_later() {
        let strikes_to_pause = |ports: &[u16]| {
            let mut b = Backoff::new(64, true);
            for p in ports {
                b.observe(Open(*p));
            }
            let mut n = 0;
            while !b.paused() {
                b.observe(Reset);
                n += 1;
            }
            n
        };
        assert_eq!(strikes_to_pause(&[502]), 3);
        assert_eq!(strikes_to_pause(&[80]), 4);
        assert_eq!(strikes_to_pause(&[445, 135]), 6);
    }

    #[test]
    fn a_known_open_port_that_stops_answering_is_a_strike() {
        let mut b = Backoff::new(64, true);
        b.observe(Open(8080));
        let note = b.known_open_failed(8080).unwrap();
        assert!(note.starts_with("backed off:"), "{note}");
        assert!(note.contains("port 8080 stopped answering after it was found open"));
        assert_eq!(b.strikes(), 1);
        assert_eq!(b.limit(), 16);
        let mut ot = Backoff::new(64, true);
        ot.observe(Open(502));
        ot.known_open_failed(502);
        ot.known_open_failed(502);
        assert!(!ot.paused());
        let last = ot.known_open_failed(502).unwrap();
        assert!(ot.paused() && last.contains("paused"), "{last}");
    }

    #[test]
    fn delay_is_capped_and_limits_never_go_below_one() {
        let mut b = Backoff::new(1, true);
        assert_eq!(b.limit(), 1);
        let mut normal = Backoff::new(64, true);
        normal.observe(Open(445));
        normal.observe(Open(135));
        for _ in 0..5 {
            normal.observe(Reset);
        }
        assert!(!normal.paused());
        assert_eq!(normal.limit(), 4, "64 >> 4");
        assert_eq!(normal.delay(), Duration::from_millis(400));
        // A slow class at the top level stays under the 2 s cap.
        let mut f = Backoff::new(8, true);
        f.observe(Open(502));
        f.observe(Reset);
        f.observe(Reset);
        assert_eq!(f.delay(), Duration::from_millis(500));
        assert!(f.delay() <= MAX_DELAY);
        b.observe(Reset);
        assert_eq!(b.limit(), 1);
    }

    #[test]
    fn disabled_means_inert() {
        let mut b = Backoff::new(64, false);
        assert_eq!(b.limit(), 64, "no class cap either");
        b.observe(Open(502));
        assert_eq!(b.limit(), 64);
        for _ in 0..50 {
            assert_eq!(b.observe(Reset), None);
            assert_eq!(b.known_open_failed(502), None);
        }
        assert_eq!(
            (b.limit(), b.delay(), b.paused(), b.strikes()),
            (64, Duration::ZERO, false, 0)
        );
    }

    #[test]
    fn limits_never_rise_and_delays_never_fall() {
        // A deterministic pseudo-random event stream; the controller only ever slows down.
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for round in 0..200 {
            let base = 1 + (next() % 128) as usize;
            let mut b = Backoff::new(base, true);
            let mut before = (b.class(), b.limit(), b.delay(), b.strikes(), b.paused());
            for _ in 0..400 {
                match next() % 12 {
                    0 => {
                        b.observe(Open([80, 445, 502, 135, 9100, 22][(next() % 6) as usize]));
                    }
                    1 => {
                        b.observe(Reset);
                    }
                    2 => {
                        b.known_open_failed(80);
                    }
                    3..=6 => {
                        b.observe(Refused);
                    }
                    _ => {
                        b.observe(Timeout);
                    }
                }
                let now = (b.class(), b.limit(), b.delay(), b.strikes(), b.paused());
                assert!(
                    (1..=base).contains(&now.1),
                    "round {round}: limit {}",
                    now.1
                );
                assert!(now.2 <= MAX_DELAY);
                // Strikes and the pause never go back.
                assert!(now.3 >= before.3 && (now.4 || !before.4), "round {round}");
                // With the class unchanged the limit only falls and the delay only grows.
                if now.0 == before.0 {
                    assert!(now.1 <= before.1 && now.2 >= before.2, "round {round}");
                }
                before = now;
            }
        }
    }

    #[tokio::test]
    async fn the_governor_enforces_the_limit_and_wakes_on_release() {
        let g = HostGovernor::new(2, true);
        let a = g.admit().await.unwrap();
        let _b = g.admit().await.unwrap();
        // A third probe has to wait for a release.
        let waiting = {
            let g = g.clone();
            tokio::spawn(async move { g.admit().await.is_some() })
        };
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(!waiting.is_finished(), "the limit of 2 holds");
        drop(a);
        assert!(
            tokio::time::timeout(Duration::from_secs(2), waiting)
                .await
                .unwrap()
                .unwrap()
        );
    }

    #[tokio::test]
    async fn the_governor_spaces_probes_after_a_back_off_and_stops_when_paused() {
        let g = HostGovernor::new(8, true);
        g.record(Reset); // unknown class: delay 100 ms, limit 32 >> 1 capped by base 8 -> 4
        assert_eq!(g.delay(), Duration::from_millis(100));
        assert_eq!(g.limit(), 4);
        let start = Instant::now();
        let mut permits = vec![];
        for _ in 0..3 {
            permits.push(g.admit().await.unwrap());
        }
        assert!(
            start.elapsed() >= Duration::from_millis(190),
            "{:?}",
            start.elapsed()
        );
        let notes = g.take_notes();
        assert_eq!(notes.len(), 1);
        assert!(g.take_notes().is_empty(), "notes are taken once");
        // Persisting errors pause the host; a waiting admit returns None.
        let waiting = {
            let g = g.clone();
            tokio::spawn(async move { g.admit().await.is_none() })
        };
        for _ in 0..3 {
            g.record(Reset);
        }
        assert!(g.paused());
        assert!(
            tokio::time::timeout(Duration::from_secs(2), waiting)
                .await
                .unwrap()
                .unwrap()
        );
        assert!(g.admit().await.is_none());
        drop(permits);
    }

    #[tokio::test]
    async fn an_unlimited_healthy_governor_adds_no_delay() {
        let g = HostGovernor::new(64, true);
        let start = Instant::now();
        for _ in 0..2000 {
            drop(g.admit().await.unwrap());
            g.record(Refused);
        }
        assert!(start.elapsed() < Duration::from_millis(500));
        assert!(g.take_notes().is_empty());
    }

    #[test]
    fn the_controller_does_no_io() {
        let code = include_str!("backoff.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for forbidden in ["TcpStream", "UdpSocket", "tokio::net", "capture::"] {
            assert!(
                !code.contains(forbidden),
                "backoff.rs must not use {forbidden}"
            );
        }
    }
}
