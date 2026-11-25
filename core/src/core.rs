// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Bounded async scheduling shared by the desktop, CLI and TUI.
use crate::{
    backoff::{HostGovernor, Outcome},
    osfp::TcpFp,
    rtt::HostRtt,
    scan::{Event, Host, PortState, Settings},
    sendlog::{PacketKind, SentLog},
    service::ProbeDb,
    syn::SynEngine,
};
use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::Sender,
    },
    time::{Duration, Instant},
};
use tokio::{sync::Semaphore, task::JoinSet, time::sleep};

struct Bucket {
    tokens: f64,
    last: Instant,
    rate: f64,
    burst: f64,
}
/// Token-bucket rate limiter. `unlimited()` has no state and never waits, so
/// fast scans pay nothing for it.
pub struct Gate {
    bucket: Option<Mutex<Bucket>>,
    /// Safe Mode: optional extra probes (NTLM session setup, TLS 1.3 enumeration) are skipped.
    safe: bool,
    /// Every packet that takes a token (or is noted) is counted here, per scan.
    log: Arc<SentLog>,
}
impl Gate {
    pub fn unlimited() -> Self {
        Self {
            bucket: None,
            safe: false,
            log: Arc::new(SentLog::new()),
        }
    }
    /// Counts the packets of this gate in `log` (the scan's sent log) instead of a private one.
    pub fn with_log(mut self, log: Arc<SentLog>) -> Self {
        self.log = log;
        self
    }
    /// The log of what this gate's senders transmitted.
    pub fn log(&self) -> &Arc<SentLog> {
        &self.log
    }
    /// Waits for a token and records the packet about to be sent (the form senders use).
    pub async fn wait_for(&self, kind: PacketKind, detail: impl Into<String>) {
        self.log.record(kind, detail);
        self.wait().await;
    }
    /// Like [`Gate::try_take`], recording the packet when a token was taken.
    pub fn try_take_for(
        &self,
        kind: PacketKind,
        detail: impl Into<String>,
    ) -> Result<(), Duration> {
        self.try_take()?;
        self.log.record(kind, detail);
        Ok(())
    }
    /// Records a packet that leaves on an already-gated connection (no token taken).
    pub fn note(&self, kind: PacketKind, detail: impl Into<String>) {
        self.log.record(kind, detail);
    }
    /// Marks this gate as the Safe Mode traffic profile.
    pub fn with_safe(mut self, safe: bool) -> Self {
        self.safe = safe;
        self
    }
    pub fn is_safe(&self) -> bool {
        self.safe
    }
    /// Minimum spacing between probes in milliseconds; 0 disables the limiter.
    pub fn new(spacing_ms: u64) -> Self {
        if spacing_ms == 0 {
            Self::unlimited()
        } else {
            Self::per_second(1000.0 / spacing_ms as f64, 1.0)
        }
    }
    pub fn per_second(rate: f64, burst: f64) -> Self {
        Self {
            bucket: Some(Mutex::new(Bucket {
                tokens: burst.max(1.0),
                last: Instant::now(),
                rate: rate.max(0.001),
                burst: burst.max(1.0),
            })),
            safe: false,
            log: Arc::new(SentLog::new()),
        }
    }
    pub async fn wait(&self) {
        let Some(bucket) = &self.bucket else { return };
        let delay = {
            let mut b = bucket.lock().unwrap_or_else(|e| e.into_inner());
            let now = Instant::now();
            let refill = now.duration_since(b.last).as_secs_f64() * b.rate;
            b.tokens = (b.tokens + refill).min(b.burst);
            b.last = now;
            b.tokens -= 1.0;
            if b.tokens >= 0.0 {
                return;
            }
            Duration::from_secs_f64(-b.tokens / b.rate)
        };
        sleep(delay).await;
    }
    /// Non-blocking variant for synchronous senders (the SYN I/O thread): takes one
    /// token if available, otherwise returns how long until one will be. It never
    /// goes into debt, so async waiters that already reserved tokens keep priority.
    pub fn try_take(&self) -> Result<(), Duration> {
        let Some(bucket) = &self.bucket else {
            return Ok(());
        };
        let mut b = bucket.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let refill = now.duration_since(b.last).as_secs_f64() * b.rate;
        b.tokens = (b.tokens + refill).min(b.burst);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64((1.0 - b.tokens) / b.rate))
        }
    }
}

/// Runs a native blocking call on the bounded blocking pool. The permit moves into
/// the blocking closure, so it is released when the thread really finishes, even if
/// the caller stopped waiting (timeout or Stop).
async fn run_blocking<T: Send + 'static>(
    pool: &Arc<Semaphore>,
    f: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let permit = pool.clone().acquire_owned().await.ok()?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        f()
    })
    .await
    .ok()
}

/// Reverse DNS returns the numeric address when there is no PTR record; that is not a name.
fn hostname_from(name: String) -> String {
    if name.trim().parse::<IpAddr>().is_ok() {
        String::new()
    } else {
        name
    }
}

/// Sends every host whose task already finished. Called before Stop aborts the
/// rest, so completed work is not discarded. Returns false when the receiver is gone.
fn drain_finished(jobs: &mut JoinSet<Host>, tx: &Sender<Event>) -> bool {
    while let Some(result) = jobs.try_join_next() {
        match result {
            Ok(host) => {
                if tx.send(Event::Host(host)).is_err() {
                    return false;
                }
            }
            Err(e) if e.is_cancelled() => {}
            Err(e) => {
                let _ = tx.send(Event::Error(format!("Probe task: {e}")));
            }
        }
    }
    true
}

/// TCP connect with retries: every attempt (first and retries) takes a rate-gate
/// token, and each retry doubles the timeout up to `cap`.
async fn connect_with_retries<F, Fut>(
    gate: &Gate,
    first: Duration,
    cap: Duration,
    retries: u32,
    mut connect: F,
) -> PortState
where
    F: FnMut(Duration) -> Fut,
    Fut: std::future::Future<Output = PortState>,
{
    let mut attempt = first;
    gate.wait_for(PacketKind::TcpConnect, "port scan").await;
    let mut state = connect(attempt).await;
    for _ in 0..retries.min(5) {
        if state != PortState::Unanswered {
            break;
        }
        attempt = (attempt * 2).min(cap.max(first));
        gate.wait_for(PacketKind::TcpConnect, "port scan").await;
        state = connect(attempt).await;
    }
    state
}

/// OT identification runs for hosts that answered something (a host with an open or
/// closed TCP port is responding, so ICMP-silent devices with OT TCP ports qualify) and,
/// when non-responders are scanned, for silent hosts too. A silent host has no open TCP
/// port, so the only probe it gets is the single BACnet Who-Is (rate-gated, wait capped at
/// 2 s): that finds devices that answer nothing but BACnet/IP.
fn wants_ot(h: &Host, s: &Settings) -> bool {
    crate::plan::ot_identification(h.responding, s)
}

/// UDP ports the OT identification talks to over UDP. A parsed reply (`<protocol>.*`
/// identity keys) proves the port answered, so the host lists it as open UDP like a
/// port found by the UDP scan. Today that is only BACnet/IP; EtherNet/IP is identified
/// over TCP 44818.
const OT_UDP: [(&str, u16); 3] = [("BACnet", 47808), ("Omron FINS", 9600), ("KNXnet/IP", 3671)];

fn merge_ot_udp(h: &mut Host) {
    for (protocol, port) in OT_UDP {
        let prefix = format!("{protocol}.");
        if h.identity.keys().any(|k| k.starts_with(&prefix)) && !h.udp_open.contains(&port) {
            h.udp_open.push(port);
            h.udp_open.sort_unstable();
        }
    }
}

/// A raw-packet engine with the interface it sends through.
struct Raw<E> {
    engine: Arc<E>,
    spec: crate::interfaces::Spec,
    source: std::net::Ipv4Addr,
}

/// The SYN engine for an IPv6 target: one engine is used as it is (it reports a target it cannot
/// reach, and the probe falls back to TCP connect with a note); of several, the first whose
/// interface has the target on-link, else the first whose route to it leaves through its own
/// interface, else none (TCP connect, as for an IPv4 target that no interface routes).
async fn pick_v6(engines: &[Raw<SynEngine>], ip: IpAddr) -> Option<usize> {
    match engines {
        [] => None,
        [_] => Some(0),
        _ => {
            if let Some(i) = engines.iter().position(|e| e.engine.on_link(ip)) {
                return Some(i);
            }
            for (i, e) in engines.iter().enumerate() {
                if e.engine.has_path(ip).await {
                    return Some(i);
                }
            }
            None
        }
    }
}

/// The engine whose interface the routing table picks for `ip` (see `interfaces::choose`). With
/// one engine nothing is asked: it behaves as before and the engine itself reports a route that
/// leaves elsewhere. IPv6 targets get none here (the ARP sweep and TCP traceroute are IPv4
/// only; the SYN engine is picked by [`pick_v6`]).
async fn pick<E: Send + Sync + 'static>(
    blocking: &Arc<Semaphore>,
    engines: &[Raw<E>],
    ip: IpAddr,
) -> Option<usize> {
    let IpAddr::V4(v4) = ip else { return None };
    match engines {
        [] => None,
        [_] => Some(0),
        _ => {
            let probes: Vec<(std::net::Ipv4Addr, String)> = engines
                .iter()
                .map(|e| (e.source, e.spec.interface.clone()))
                .collect();
            let routes = run_blocking(blocking, move || {
                probes
                    .iter()
                    .map(|(source, interface)| {
                        match crate::platform::next_hop(v4, *source, interface) {
                            Ok(crate::platform::NextHop::OnLink) => Some(true),
                            Ok(crate::platform::NextHop::Gateway(_)) => Some(false),
                            Err(_) => None,
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .await?;
            crate::interfaces::choose(&routes)
        }
    }
}

struct Ctx {
    gate: Arc<Gate>,
    blocking: Arc<Semaphore>,
    /// In-flight port probes (sockets for TCP connect, outstanding SYNs otherwise).
    /// Taken before a probe task is spawned, so idle hosts cannot pile up tasks.
    sockets: Arc<Semaphore>,
    dhcp: Semaphore,
    /// One SYN engine per interface (`--interface a,b`); empty without `--syn`.
    syn: Vec<Raw<SynEngine>>,
    syn_error: Option<String>,
    /// One ARP engine per interface; empty without `--arp-sweep`.
    arp: Vec<Raw<crate::arp::ArpEngine>>,
    arp_error: Option<String>,
    probes: Option<ProbeDb>,
    udp_ports: Vec<u16>,
    scripts: Option<crate::script::Scripts>,
    /// The scan a repeat scan is based on (`--incremental`), if any.
    previous: Option<Arc<crate::incremental::Previous>>,
    /// Device classes for the probe order and the early stop.
    classes: &'static crate::portorder::ClassTable,
    /// Where `Event::Partial` goes (the scan's event channel); `None` in unit tests.
    partial: Option<Sender<Event>>,
}

#[allow(clippy::too_many_arguments)]
pub async fn execute(
    hosts: Box<dyn Iterator<Item = IpAddr> + Send>,
    ports: Vec<u16>,
    s: Settings,
    cancel: Arc<AtomicBool>,
    pause: Arc<AtomicBool>,
    tx: Sender<Event>,
    sent: Arc<SentLog>,
    previous: Option<Arc<crate::incremental::Previous>>,
) {
    let s = Arc::new(s);
    let gate = Arc::new(
        if s.safe {
            Gate::new(s.delay.max(100)).with_safe(true)
        } else if s.max_rate > 0 {
            let rate = f64::from(s.max_rate);
            Gate::per_second(rate, (rate / 10.0).max(1.0))
        } else {
            Gate::unlimited()
        }
        .with_log(sent),
    );
    // UDP payload probes come from the same database (registered process-wide by `load`), so
    // `--probes FILE` also applies to a UDP-only scan; the value itself is only kept for TCP.
    let probes = if s.services || s.udp {
        match ProbeDb::load(&s.probe_file) {
            Ok(db) => s.services.then_some(db),
            Err(e) => {
                let _ = tx.send(Event::Error(format!("Service probes: {e}")));
                return;
            }
        }
    } else {
        None
    };
    let scripts = if s.scripts.is_empty() {
        None
    } else {
        match crate::script::Scripts::load(&s.scripts) {
            Ok(sc) => Some(sc),
            Err(e) => {
                let _ = tx.send(Event::Error(format!("Scripts: {e}")));
                return;
            }
        }
    };
    let udp_ports = if s.udp {
        match crate::scan::parse_ports(&s.udp_ports) {
            Ok(p) => p,
            Err(e) => {
                let _ = tx.send(Event::Error(format!("UDP ports: {e}")));
                return;
            }
        }
    } else {
        vec![]
    };
    let interfaces = match crate::interfaces::specs(&s) {
        Ok(list) => list,
        Err(e) => {
            let _ = tx.send(Event::Error(format!("Interfaces: {e}")));
            return;
        }
    };
    // One engine per interface; the ones that cannot start are reported, the rest still work.
    let start = |spec: &crate::interfaces::Spec| {
        spec.source_ip
            .parse::<std::net::Ipv4Addr>()
            .ok()
            .map(|source| (crate::interfaces::settings_for(&s, spec), source))
    };
    let (mut syn, mut syn_errors) = (vec![], vec![]);
    if crate::plan::syn_engine(&s) {
        for spec in &interfaces {
            let Some((per, source)) = start(spec) else {
                syn_errors.push("Set the interface's source IPv4".to_string());
                continue;
            };
            match SynEngine::start(&per, gate.clone()) {
                Ok(engine) => syn.push(Raw {
                    engine,
                    spec: spec.clone(),
                    source,
                }),
                Err(e) => syn_errors.push(e),
            }
        }
    }
    let syn_error = (!syn_errors.is_empty()).then(|| syn_errors.join("; "));
    // Opt-in, and never in Safe Mode (the per-host OS lookup is used there).
    let (mut arp, mut arp_errors) = (vec![], vec![]);
    if crate::plan::arp_sweep(&s) {
        for spec in &interfaces {
            let Some((per, source)) = start(spec) else {
                arp_errors.push("Set the interface's source IPv4".to_string());
                continue;
            };
            match crate::arp::ArpEngine::start(&per, gate.clone()) {
                Ok(engine) => arp.push(Raw {
                    engine,
                    spec: spec.clone(),
                    source,
                }),
                Err(e) => arp_errors.push(e),
            }
        }
    }
    let arp_error = (!arp_errors.is_empty()).then(|| arp_errors.join("; "));
    let ctx = Arc::new(Ctx {
        gate,
        // As many as the runtime's blocking threads (`max_blocking_threads` in `scan::start`):
        // with 256, a /24 in --fast queued its ping and ARP calls for several rounds (Windows home
        // /24 with 2 ports: 8.0-10.2 s, now 5.8-6.3 s, same results). Safe Mode runs 8 hosts.
        blocking: Arc::new(Semaphore::new(512)),
        sockets: Arc::new(Semaphore::new(4096)),
        dhcp: Semaphore::new(1),
        syn,
        syn_error,
        arp,
        arp_error,
        probes,
        udp_ports,
        scripts,
        previous,
        classes: crate::portorder::ClassTable::builtin(),
        partial: s.partial_events.then(|| tx.clone()),
    });
    let limit = if s.safe {
        s.workers.clamp(1, 8)
    } else {
        s.workers.clamp(1, 4096)
    };
    let ports = Arc::new(ports);
    let mut queue = hosts;
    let mut jobs = JoinSet::new();
    let mut exhausted = false;
    loop {
        if cancel.load(Ordering::Relaxed) {
            // Keep hosts that already finished but were not joined yet.
            drain_finished(&mut jobs, &tx);
            jobs.abort_all();
            break;
        }
        if !pause.load(Ordering::Relaxed) {
            while jobs.len() < limit && !exhausted {
                if let Some(ip) = queue.next() {
                    let (s, ports, ctx) = (s.clone(), ports.clone(), ctx.clone());
                    jobs.spawn(async move { scan_host(ip, ports, s, ctx).await });
                } else {
                    exhausted = true;
                }
            }
        }
        if exhausted && jobs.is_empty() {
            break;
        }
        tokio::select! {
            result = jobs.join_next(), if !jobs.is_empty() => {
                match result {
                    Some(Ok(host)) => { if tx.send(Event::Host(host)).is_err() { break; } }
                    Some(Err(e)) => { let _ = tx.send(Event::Error(format!("Probe task: {e}"))); }
                    None => {}
                }
            }
            _ = sleep(Duration::from_millis(20)) => {}
        }
    }
}

struct PortProbe {
    state: PortState,
    note: Option<String>,
    fp: Option<TcpFp>,
}

/// The OS neighbor lookup of one host: sets its MAC (and `responding` for a fresh answer) and
/// returns true when the address is known to be unused (`platform::neighbor_probe`).
async fn neighbor_lookup(h: &mut Host, ctx: &Ctx) -> bool {
    let ip = h.ip;
    ctx.gate
        .wait_for(PacketKind::NeighborLookup, "OS neighbor lookup")
        .await;
    run_blocking(&ctx.blocking, move || crate::platform::neighbor_probe(ip))
        .await
        .is_some_and(|answer| apply_neighbor(h, answer))
}

/// A task that is aborted when its handle is dropped (a stopped scan, or an answer not needed).
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Records a neighbor lookup's answer on the host; true when the address is known to be unused.
fn apply_neighbor(
    h: &mut Host,
    (found, silent): (Option<crate::platform::Neighbor>, bool),
) -> bool {
    if let Some(n) = found {
        h.mac = n.mac;
        // A cached (possibly stale) neighbor entry is a MAC source, not proof of life.
        h.responding = n.fresh;
    }
    silent
}

/// Counts a closed or unanswered port without a note at once and keeps every other result for
/// the port-ordered pass in `scan_host`: with `--fast` every host of a /24 runs at the same
/// time, and keeping all results held one record per probe (about 120 bytes each).
fn tally(h: &mut Host, kept: &mut Vec<(u16, PortProbe)>, item: (u16, PortProbe)) {
    match (&item.1.state, &item.1.note) {
        (PortState::Closed, None) => {
            h.closed += 1;
            h.responding = true;
        }
        (PortState::Unanswered, None) => h.unanswered += 1,
        _ => kept.push(item),
    }
}

/// Ports probed before the rest of a host's ports when `tcp_adaptive` is on, so the
/// host's connect RTT is known when the remaining probes choose their timeout.
const PILOT_PORTS: usize = 3;
/// Longest wait for that first completed connect. A host that answers nothing costs
/// this once, in addition to the port timeout.
const PILOT_WAIT: Duration = Duration::from_millis(250);

#[allow(clippy::too_many_arguments)]
async fn probe_port(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    s: &Settings,
    ctx: &Ctx,
    rtt: Option<&HostRtt>,
    syn: Option<&Arc<SynEngine>>,
    first_connect: Option<&std::sync::OnceLock<Instant>>,
) -> PortProbe {
    // The caller already holds this probe's in-flight permit (`ctx.sockets`).
    let cap = timeout.max(Duration::from_millis(u64::from(s.port_timeout)));
    let mut note = ctx
        .syn_error
        .as_ref()
        .map(|e| format!("SYN unavailable; TCP connect fallback: {e}"));
    if let Some(engine) = syn {
        // The SYN engine takes one gate token per transmitted SYN (retransmits
        // included), so the rate is not applied a second time here.
        match engine.probe(ip, port, timeout, cap, s.retries).await {
            Ok((state, fp)) => {
                return PortProbe {
                    state,
                    note: None,
                    fp,
                };
            }
            Err(e) => note = Some(format!("SYN unavailable; TCP connect fallback: {e}")),
        }
    }
    // Adaptive: the first attempt waits for the host's measured RTT, never longer than
    // `timeout`; retries still double up to the user's port timeout.
    let first = rtt.map_or(timeout, |r| {
        let floor = Duration::from_millis(u64::from(s.minimum_timeout.max(1)));
        r.timeout(timeout, floor, cap)
    });
    let state = connect_with_retries(&ctx.gate, first, cap, s.retries, |attempt| async move {
        // Past the rate gate: this connect makes the kernel resolve the address now.
        if let Some(f) = first_connect {
            f.get_or_init(Instant::now);
        }
        let started = Instant::now();
        let state = crate::probes::connect(ip, port, attempt).await;
        // An answer, open or refused, is an RTT sample; silence and local errors are not.
        if let Some(r) = rtt
            && matches!(state, PortState::Open | PortState::Closed)
        {
            r.sample(started.elapsed());
        }
        state
    })
    .await;
    PortProbe {
        state,
        note,
        fp: None,
    }
}

/// How long a host's own probes give the kernel's ARP before an entry without a MAC counts as
/// unused (Linux sends 3 requests 1 s apart, then marks the entry FAILED).
const NEIGHBOR_WAIT: Duration = Duration::from_millis(3500);

/// Whether the Linux unused check is due: 3.5 s after the host's first connect got past the rate
/// gate (never before the first one).
fn neighbor_due(first_connect: &std::sync::OnceLock<Instant>) -> bool {
    first_connect
        .get()
        .is_some_and(|t| t.elapsed() >= NEIGHBOR_WAIT)
}
/// How long until [`neighbor_due`]; a short poll while no connect has got past the gate yet.
fn neighbor_wait_left(first_connect: &std::sync::OnceLock<Instant>) -> Duration {
    first_connect.get().map_or(Duration::from_millis(100), |t| {
        NEIGHBOR_WAIT.saturating_sub(t.elapsed())
    })
}
/// The Linux unused verdict: nothing answered and the kernel's neighbor entry has no MAC.
async fn neighbor_verdict(ctx: &Ctx, ip: IpAddr, h: &Host, results: &[(u16, PortProbe)]) -> bool {
    !answered(h, results)
        && run_blocking(&ctx.blocking, move || {
            crate::platform::neighbor_unresolved(ip)
        })
        .await
            == Some(true)
}

/// Whether the host answered any probe so far: open, refused or reset. Silence and local
/// errors ("no route to host") are not answers.
fn answered(h: &Host, results: &[(u16, PortProbe)]) -> bool {
    h.closed > 0
        || results.iter().any(|(_, p)| {
            matches!(
                p.state,
                PortState::Open | PortState::Closed | PortState::Reset
            )
        })
}

/// Longest window of probes in flight per host with `--early-stop`: a smaller window means the
/// first answers arrive while ports are still left to skip.
const EARLY_WINDOW: usize = 16;

/// Why the rest of the host's ports may be skipped (`--early-stop`), or `None`: the class is
/// certain (`HostOrder::identified`) and the device classifier agrees on the ports found so far.
fn early_stop_reason(
    order: &crate::portorder::HostOrder,
    h: &Host,
    vendor: &str,
) -> Option<String> {
    let class = order.identified()?;
    let open = order.open();
    let identity = BTreeMap::new();
    let facts = crate::devices::Facts {
        mac: &h.mac,
        vendor,
        tcp: &open,
        udp: &[],
        identity: &identity,
        hostnames: &[],
        os: "",
        ttl: h.ttl,
        protocols: &[],
    };
    let (kind, evidence) = crate::devices::classify_detailed(&facts)?;
    (evidence.confidence >= 40).then(|| {
        format!(
            "identified as {} ({kind}, {} %) from ports {}",
            class.label,
            evidence.confidence,
            open.iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )
    })
}

/// Sends a provisional host (`Event::Partial`); a closed channel is not an error here.
fn send_partial(ctx: &Ctx, host: Host) {
    if let Some(tx) = &ctx.partial {
        let _ = tx.send(Event::Partial(host));
    }
}

/// Open ports of one host that are announced one by one and get service identification. A host
/// with more (a captive portal, proxy or tarpit that completes every handshake) keeps its full
/// list of open ports. Without the limit, 65,535 open ports are as many provisional hosts,
/// each carrying every port so far (gigabytes), and as many banner waits (days).
const MANY_OPEN_PORTS: usize = 100;

/// A port was found open: tell the consumer now, with every port found open so far. Beyond
/// [`MANY_OPEN_PORTS`] nothing more is announced: the finished host carries the full list.
fn announce_open(ctx: &Ctx, base: &Host, live: &Mutex<Vec<u16>>, port: u16) {
    let open = {
        let mut list = live.lock().unwrap_or_else(|e| e.into_inner());
        if list.len() >= MANY_OPEN_PORTS {
            return;
        }
        list.push(port);
        list.sort_unstable();
        list.clone()
    };
    let mut host = base.clone();
    host.responding = true;
    host.open = open;
    send_partial(ctx, host);
}

/// Cuts the ports that get service identification to the first [`MANY_OPEN_PORTS`]. When that
/// leaves ports out, the note for the host that says so (`open` is how many it has open).
fn cap_service_ports(ports: &mut Vec<u16>, open: usize) -> Option<String> {
    if ports.len() <= MANY_OPEN_PORTS {
        return None;
    }
    ports.truncate(MANY_OPEN_PORTS);
    Some(format!(
        "{open} open ports (a proxy or tarpit that accepts every connection?); services were identified on the first {MANY_OPEN_PORTS} only"
    ))
}

/// Outcome of the ARP sweep for one host.
#[derive(Debug, Default)]
struct Swept {
    mac: Option<String>,
    /// The sweep gave a definite answer (reply or silence); no per-host lookup needed.
    answered: bool,
    note: Option<String>,
}

/// ARP sweep for on-link IPv4 targets (never this machine's own address). Routed or
/// IPv6 targets, and any engine failure, leave the per-host OS lookup to the caller.
async fn sweep_arp(ip: IpAddr, s: &Settings, ctx: &Ctx) -> Swept {
    if let Some(e) = &ctx.arp_error {
        return Swept {
            note: Some(format!("ARP sweep unavailable; per-host lookup: {e}")),
            ..Swept::default()
        };
    }
    let IpAddr::V4(v4) = ip else {
        return Swept::default();
    };
    let Some(index) = pick(&ctx.blocking, &ctx.arp, ip).await else {
        return Swept::default();
    };
    let engine = &ctx.arp[index].engine;
    let source = engine.source();
    if v4 == source {
        return Swept::default();
    }
    let _ = s;
    let interface = ctx.arp[index].spec.interface.clone();
    let route = run_blocking(&ctx.blocking, move || {
        crate::platform::next_hop(v4, source, &interface)
    })
    .await;
    if route != Some(Ok(crate::platform::NextHop::OnLink)) {
        return Swept::default();
    }
    match engine.resolve(v4).await {
        Ok(mac) => Swept {
            mac,
            answered: true,
            note: None,
        },
        Err(e) => Swept {
            note: Some(format!("ARP sweep unavailable; per-host lookup: {e}")),
            ..Swept::default()
        },
    }
}

/// Traceroute with the configured method. TCP and UDP fall back to ICMP (with a note)
/// when they cannot run: Safe Mode, IPv6, no eligible port, or a local failure.
async fn traceroute(
    ip: IpAddr,
    open: &[u16],
    s: &Arc<Settings>,
    ctx: &Ctx,
) -> (Vec<crate::trace::Hop>, Vec<String>) {
    use crate::trace::TraceMethod;
    let timeout = s.ping_timeout.clamp(200, 3000);
    let plan = crate::trace::plan(ip, open, s);
    let mut notes: Vec<String> = plan.note.into_iter().collect();
    let attempt = match (plan.method, ip, plan.port) {
        (TraceMethod::Tcp, IpAddr::V4(v4), Some(port)) => {
            // The interface that routes the target, when several were given.
            let settings = match pick(&ctx.blocking, &ctx.syn, ip).await {
                Some(i) => Arc::new(crate::interfaces::settings_for(s, &ctx.syn[i].spec)),
                None => s.clone(),
            };
            let gate = ctx.gate.clone();
            let done = run_blocking(&ctx.blocking, move || {
                crate::syn::tcp_trace(&settings, v4, port, settings.trace_hops, timeout, &gate)
            })
            .await
            .unwrap_or_else(|| Err("traceroute task ended".into()));
            Some(
                done.map(crate::trace::assemble)
                    .map_err(|e| format!("TCP traceroute: {e}")),
            )
        }
        (TraceMethod::Udp, IpAddr::V4(v4), _) => Some(
            crate::trace::trace_udp(v4, s.trace_hops, timeout, &ctx.blocking, &ctx.gate)
                .await
                .map_err(|e| format!("UDP traceroute: {e}")),
        ),
        _ => None,
    };
    match attempt {
        Some(Ok(hops)) => return (hops, notes),
        Some(Err(e)) => notes.push(format!("{e}; ICMP traceroute used")),
        None => {}
    }
    match crate::trace::trace(ip, s.trace_hops, timeout, &ctx.blocking, &ctx.gate).await {
        Ok(hops) => (hops, notes),
        Err(e) => {
            notes.push(format!("Traceroute: {e}"));
            (vec![], notes)
        }
    }
}

/// Splits the UDP port list into ports the generic UDP scan may probe and industrial/printer
/// ports it never sends to (`service::is_ot_udp_port`). BACnet and the other OT protocols are
/// identified only by the dedicated read-only path (`--ot`).
fn udp_scan_ports(ports: &[u16]) -> (Vec<u16>, Vec<u16>) {
    crate::plan::udp_ports(ports)
}
fn note(h: &mut Host, text: String) {
    if h.errors.len() < 8 && !h.errors.contains(&text) {
        h.errors.push(text);
    }
}
/// Puts a back-off note first, so it is not lost when port errors already filled the list.
fn note_first(h: &mut Host, text: String) {
    if !h.errors.contains(&text) {
        h.errors.insert(0, text);
        h.errors.truncate(8);
    }
}
/// Moves the notes the back-off controller recorded onto the host.
fn flush_backoff_notes(gov: &HostGovernor, h: &mut Host) {
    for text in gov.take_notes().into_iter().rev() {
        note_first(h, text);
    }
}
/// What a port probe tells the back-off controller (local errors are no evidence).
fn outcome_of(port: u16, state: &PortState) -> Option<Outcome> {
    match state {
        PortState::Open => Some(Outcome::Open(port)),
        PortState::Closed => Some(Outcome::Refused),
        PortState::Unanswered => Some(Outcome::Timeout),
        PortState::Reset => Some(Outcome::Reset),
        PortState::Error(_) => None,
    }
}

async fn scan_host(ip: IpAddr, ports: Arc<Vec<u16>>, s: Arc<Settings>, ctx: Arc<Ctx>) -> Host {
    // A repeat scan (`--incremental`) probes the ports that were open plus a sample, and carries
    // over what it does not look at again; the host says so (`incremental::mark`).
    let base = ctx.previous.clone();
    let before: Option<&Host> = base.as_ref().and_then(|p| p.host(ip));
    let (ports, sampled) = match &base {
        Some(p) => {
            let sample = crate::incremental::ports_for(before, &ports, p.id);
            if sample.len() < ports.len() {
                (Arc::new(sample), true)
            } else {
                (ports, false)
            }
        }
        None => (ports, false),
    };
    let mut carried: Vec<String> = vec![];
    let mut h = Host {
        ip,
        responding: false,
        ping: None,
        ttl: None,
        hostname: String::new(),
        mac: String::new(),
        open: vec![],
        closed: 0,
        unanswered: 0,
        errors: vec![],
        ports_checked: false,
        identity: BTreeMap::new(),
        udp_open: vec![],
        trace: vec![],
    };
    let mut fingerprint = None;
    // Known to be unused: on-link, and no ARP answer (the sweep's or the OS's). Nothing can
    // reach such an address, so its ports are not probed one by one.
    let mut unused = false;
    // ARP is independent of ping: an ICMP-silent LAN device can still be found.
    if crate::plan::arp_lookup(&s) {
        let swept = sweep_arp(ip, &s, &ctx).await;
        if let Some(text) = swept.note {
            note(&mut h, text);
        }
        if let Some(mac) = swept.mac {
            h.mac = mac;
            h.responding = true;
        } else if swept.answered {
            unused = true;
        } else {
            unused = neighbor_lookup(&mut h, &ctx).await;
        }
    }
    let mut rtts = vec![];
    // The ARP check runs alongside the ping, not after it: an unused address then holds its
    // slot for the longer of the two (about 4 s), not for both (about 6 s). Its answer is used
    // only when the ping gets none, so hosts that answer ping come out exactly as before; it is
    // aborted when the ping answers or the scan stops, so nothing is sent for nothing.
    let arp_check = (crate::plan::arp_check(&s) && ip.is_ipv4()).then(|| {
        let ctx = ctx.clone();
        AbortOnDrop(tokio::spawn(async move {
            ctx.gate
                .wait_for(PacketKind::NeighborLookup, "OS neighbor lookup")
                .await;
            run_blocking(&ctx.blocking, move || crate::platform::neighbor_probe(ip)).await
        }))
    });
    if crate::plan::icmp_echoes(&s) > 0 {
        let timeout = s.ping_timeout.clamp(1, 10000);
        let mut echoes = JoinSet::new();
        for _ in 0..crate::plan::icmp_echoes(&s) {
            ctx.gate
                .wait_for(PacketKind::IcmpEcho, "echo request")
                .await;
            let ctx = ctx.clone();
            echoes.spawn(async move {
                run_blocking(&ctx.blocking, move || crate::platform::echo(ip, timeout)).await
            });
        }
        while let Some(result) = echoes.join_next().await {
            if let Ok(Some(echo)) = result {
                if let Some(rtt) = echo.rtt {
                    rtts.push(rtt);
                    h.ttl = echo.ttl;
                }
                if let Some(e) = echo.error
                    && !h.errors.contains(&e)
                {
                    h.errors.push(e);
                }
            }
        }
    }
    if !rtts.is_empty() {
        h.ping = Some((rtts.iter().map(|v| *v as u64).sum::<u64>() / rtts.len() as u64) as u32);
        h.responding = true;
    }
    // Only "unused" is taken from the check. An ARP answer may come from the OS's neighbor
    // cache (a device that just went offline), so it is not proof of life and records no MAC:
    // without --arp/--mac the host is reported as it was before the check existed.
    if let Some(mut task) = arp_check
        && !h.responding
        && let Ok(Some((_, silent))) = (&mut task.0).await
    {
        unused = silent;
    }
    // The host answered: show it now, the ports follow as they are found.
    if h.responding {
        send_partial(&ctx, h.clone());
    }
    let live = Arc::new(Mutex::new(Vec::<u16>::new()));
    let announced = Arc::new(h.clone());
    let parallel = if s.safe {
        s.port_parallel.clamp(1, 4)
    } else {
        s.port_parallel.clamp(1, 1024)
    };
    let parallel = if s.early_stop {
        parallel.min(EARLY_WINDOW)
    } else {
        parallel
    };
    // Per-host pacing: the device-type limits and the back-off (see `backoff`). It replaces the
    // plain per-host semaphore; without a back-off it behaves exactly like one.
    let gov = HostGovernor::new(parallel, s.backoff);
    let mut probed_sample: Option<Vec<u16>> = None;
    if unused && !h.responding && !s.tcp_only {
        note(&mut h, crate::scan::UNUSED_ADDRESS_NOTE.into());
    } else if crate::plan::probes_ports(h.responding, &s) {
        h.ports_checked = true;
        let timeout = crate::scan::port_timeout(rtts.iter().copied().max(), &s);
        let mut unprobed = 0;
        let mut early: Option<String> = None;
        let mut probes: JoinSet<(u16, PortProbe)> = JoinSet::new();
        // Per-host RTT of completed connects (connect scan only; the SYN engine has its own).
        let syn_index = match ip {
            IpAddr::V4(_) => pick(&ctx.blocking, &ctx.syn, ip).await,
            IpAddr::V6(_) => pick_v6(&ctx.syn, ip).await,
        };
        let syn_engine: Option<Arc<SynEngine>> = syn_index.map(|i| ctx.syn[i].engine.clone());
        // An IPv6 target the engine cannot reach at all is probed by TCP connect.
        let syn_probes = syn_engine.as_ref().is_some_and(|e| e.reaches(ip));
        // Only where the ping RTT does not already set the timeout: a host that answers ping
        // keeps exactly that timeout and order (the pilot cost a power-saving Wi-Fi device
        // closed ports in 5 of 20 runs, for no gain).
        let host_rtt = (s.tcp_adaptive && !syn_probes && (rtts.is_empty() || !s.adaptive))
            .then(|| Arc::new(HostRtt::default()));
        // The likeliest ports first, and the order follows what the host turns out to be.
        let vendor = if h.mac.is_empty() || crate::oui::locally_administered(&h.mac) {
            ""
        } else {
            crate::oui::vendor(&h.mac).unwrap_or("")
        };
        let mut order = crate::portorder::HostOrder::new(
            ctx.classes,
            &ports,
            crate::portorder::Hints { vendor, ttl: h.ttl },
        );
        let mut results = vec![];
        let mut launched = 0usize;
        // Linux: when this host has answered nothing once the kernel's ARP for these probes has
        // had its time, an entry still without a MAC means the address is unused. Checked once.
        // `--tcp-only` keeps its meaning: no discovery of any kind, every address gets every port.
        let mut watch = crate::platform::NEIGHBOR_WATCH
            && !s.tcp_only
            && !h.responding
            && ip.is_ipv4()
            && syn_engine.is_none();
        // The 3.5 s count from the first connect that got past the rate gate, not from here:
        // in Safe Mode a host's first SYN can wait seconds for its token.
        let first_connect = Arc::new(std::sync::OnceLock::<Instant>::new());
        while let Some(port) = order.next_port() {
            // Probes that finished since the last launch: their open ports steer the order, and
            // with --early-stop they can end the scan of this host.
            while let Some(done) = probes.try_join_next() {
                if let Ok(item) = done {
                    order.observe(item.0, item.1.state == PortState::Open);
                    tally(&mut h, &mut results, item);
                }
            }
            if s.early_stop
                && let Some(why) = early_stop_reason(&order, &h, vendor)
            {
                // `port` was taken from the order but not probed.
                unprobed = order.remaining() + 1;
                early = Some(why);
                break;
            }
            if launched == PILOT_PORTS
                && let Some(r) = &host_rtt
            {
                r.wait_for_sample(timeout.min(PILOT_WAIT)).await;
            }
            // With the check pending, wait for a probe slot only until its time (`admit` holds
            // nothing while it waits, so giving up on it is safe).
            let mut admitted = None;
            while watch {
                if neighbor_due(&first_connect) {
                    watch = false;
                    while let Some(done) = probes.try_join_next() {
                        if let Ok(item) = done {
                            order.observe(item.0, item.1.state == PortState::Open);
                            tally(&mut h, &mut results, item);
                        }
                    }
                    unused = neighbor_verdict(&ctx, ip, &h, &results).await;
                    break;
                }
                if admitted.is_some() {
                    break;
                }
                tokio::select! {
                    p = gov.admit() => admitted = Some(p),
                    () = sleep(neighbor_wait_left(&first_connect)) => {}
                }
            }
            if unused {
                // Their SYNs wait for an ARP answer that is not coming.
                probes.abort_all();
                unprobed = order.remaining() + 1;
                break;
            }
            let admitted = match admitted {
                Some(p) => p,
                None => gov.admit().await,
            };
            let Some(permit) = admitted else {
                // The host is paused: it gets no further probes in this scan.
                unprobed = order.remaining() + 1;
                break;
            };
            // Global in-flight bound taken before spawning: with many workers and a
            // high --parallel, tasks would otherwise pile up waiting for a socket.
            let Ok(socket) = ctx.sockets.clone().acquire_owned().await else {
                break;
            };
            launched += 1;
            let (s, ctx, rtt, gov) = (s.clone(), ctx.clone(), host_rtt.clone(), gov.clone());
            let (live, announced) = (live.clone(), announced.clone());
            let syn_engine = syn_engine.clone();
            let first_connect = first_connect.clone();
            probes.spawn(async move {
                let result = probe_port(
                    ip,
                    port,
                    timeout,
                    &s,
                    &ctx,
                    rtt.as_deref(),
                    syn_engine.as_ref(),
                    Some(&first_connect),
                )
                .await;
                if let Some(outcome) = outcome_of(port, &result.state) {
                    gov.record(outcome);
                }
                if result.state == PortState::Open {
                    announce_open(&ctx, &announced, &live, port);
                }
                drop(socket);
                drop(permit);
                (port, result)
            });
        }
        // The check also runs here: a short port list is launched before its time comes.
        loop {
            if watch && neighbor_due(&first_connect) {
                watch = false;
                if neighbor_verdict(&ctx, ip, &h, &results).await {
                    unused = true;
                    probes.abort_all();
                }
            }
            let pending = watch && first_connect.get().is_some();
            let next = if pending {
                tokio::select! {
                    r = probes.join_next() => r.map(Some),
                    () = sleep(neighbor_wait_left(&first_connect)) => Some(None),
                }
            } else {
                probes.join_next().await.map(Some)
            };
            match next {
                Some(Some(Ok(item))) => tally(&mut h, &mut results, item),
                Some(_) => {}
                // All probes are done; a host still silent waits out the check's time.
                None if pending && !answered(&h, &results) => {
                    sleep(neighbor_wait_left(&first_connect)).await;
                }
                None => break,
            }
        }
        // A probe still in flight at the check answered after all: the host is there.
        let late_answer = unused && answered(&h, &results);
        unused &= !late_answer;
        results.sort_by_key(|(port, _)| *port);
        for (port, probe) in results {
            if let Some(text) = probe.note {
                note(&mut h, text);
            }
            match probe.state {
                PortState::Open => {
                    h.open.push(port);
                    h.responding = true;
                    if fingerprint.is_none() {
                        fingerprint = probe.fp;
                    }
                }
                PortState::Closed => {
                    h.closed += 1;
                    h.responding = true;
                }
                PortState::Unanswered => h.unanswered += 1,
                PortState::Reset => {
                    if h.errors.len() < 8 {
                        h.errors
                            .push(format!("TCP {port}: connection reset by the host"));
                    }
                }
                PortState::Error(e) => {
                    if h.errors.len() < 8 {
                        h.errors.push(format!("TCP {port}: {e}"));
                    }
                }
            }
        }
        if sampled && unprobed == 0 {
            probed_sample = Some(ports.to_vec());
        }
        if unprobed > 0 {
            // The unprobed ports are unknown, not closed: monitor and diff must not report them.
            h.ports_checked = false;
            match early {
                Some(why) => note(
                    &mut h,
                    format!(
                        "early stop: {why}; {unprobed} port(s) were not probed in this scan; their state is unknown, not closed"
                    ),
                ),
                // The unused note below says why.
                None if unused => {}
                None if late_answer => note(
                    &mut h,
                    format!(
                        "{unprobed} port(s) were not probed: ARP looked unanswered, but the host answered later; their state is unknown, not closed"
                    ),
                ),
                None => gov.note_unprobed(unprobed),
            }
        }
        if unused {
            // The per-port "no route to host" errors are this same ARP failure.
            h.errors.retain(|e| !e.starts_with("TCP "));
            note_first(&mut h, crate::scan::UNUSED_AFTER_PROBES_NOTE.into());
        }
    }
    flush_backoff_notes(&gov, &mut h);
    if s.services && !h.open.is_empty() && !gov.paused() {
        before_identification(&h.open);
        let limit = Duration::from_millis(u64::from(s.port_timeout.clamp(500, 5000)));
        let rounds = if s.safe { 6 } else { 12 };
        let slots = Arc::new(Semaphore::new(
            (if s.safe { 1 } else { 8 }).min(gov.limit()),
        ));
        let mut tasks = JoinSet::new();
        let mut ports = crate::plan::service_ports(&h.open, &s);
        let capped = cap_service_ports(&mut ports, h.open.len());
        for port in ports {
            if gov.paused() {
                break;
            }
            let Ok(permit) = slots.clone().acquire_owned().await else {
                break;
            };
            if !gov.delay().is_zero() {
                sleep(gov.delay()).await;
            }
            let ctx = ctx.clone();
            // What the base scan knew about this port: its change detector.
            let known_fp = before
                .filter(|b| b.responding)
                .and_then(|b| b.identity.get(&format!("incr.fp.{port}")))
                .cloned();
            let repeat = base.is_some();
            tasks.spawn(async move {
                // A repeat scan first checks whether the service still says the same thing.
                let fp = if repeat {
                    crate::service::fingerprint(ip, port, limit, &ctx.gate).await
                } else {
                    None
                };
                let same = fp.is_some() && fp == known_fp;
                let found = match &ctx.probes {
                    Some(db) if !same => {
                        crate::service::detect(ip, port, limit, db, &ctx.gate, rounds).await
                    }
                    _ => None,
                };
                drop(permit);
                (port, found, fp, same)
            });
        }
        let mut found = vec![];
        while let Some(done) = tasks.join_next().await {
            if let Ok(item) = done {
                found.push(item);
            }
        }
        found.sort_by_key(|(port, ..)| *port);
        let mut carried_ports: Vec<String> = vec![];
        for (port, outcome, fp, same) in found {
            if let Some(fp) = &fp {
                h.identity.insert(format!("incr.fp.{port}"), fp.clone());
            }
            if same && let Some(b) = before {
                // Unchanged since the base scan: keep its identification, and say it was kept.
                for (k, v) in crate::incremental::port_entries(&b.identity, port) {
                    h.identity.insert(k, v);
                }
                carried_ports.push(port.to_string());
                continue;
            }
            match outcome {
                Some(o) => h
                    .identity
                    .extend(crate::service::identity_entries(port, &o)),
                None => {
                    note(
                        &mut h,
                        format!("Service detection: port {port} stopped answering"),
                    );
                    gov.known_open_failed(port);
                }
            }
        }
        if !carried_ports.is_empty() {
            carried.push(format!("svc:{}", carried_ports.join(",")));
        }
        flush_backoff_notes(&gov, &mut h);
        // First, like a back-off note: failed identifications may have filled the list.
        if let Some(text) = capped {
            note_first(&mut h, text);
        }
    }
    // JARM: ten extra hellos per port that service detection found to speak TLS. Opt-in, never
    // in Safe Mode, one port at a time, every connection through the rate gate, and never on
    // industrial or printer ports.
    if crate::jarm::enabled(&s) && !gov.paused() {
        let limit = Duration::from_millis(u64::from(s.port_timeout.clamp(500, 5000)));
        let tls_ports: Vec<u16> = h
            .open
            .iter()
            .copied()
            .filter(|p| {
                h.identity.contains_key(&format!("tls.{p}.versions"))
                    || h.identity.contains_key(&format!("tls.{p}.subject"))
            })
            .collect();
        for port in tls_ports {
            if let Some(jarm) = crate::jarm::fingerprint(ip, port, limit, &ctx.gate).await {
                h.identity.insert(format!("tls.{port}.jarm"), jarm);
            }
        }
    }
    let udp_before = before.filter(|b| b.responding && s.udp);
    if let Some(b) = udp_before
        && h.responding
        && !gov.paused()
    {
        // Not probed again: the answers of the base scan, marked as carried over.
        h.udp_open = b.udp_open.clone();
        for (k, v) in &b.identity {
            if k.starts_with("udp.") {
                h.identity.insert(k.clone(), v.clone());
            }
        }
        carried.push("udp".into());
    }
    if s.udp
        && udp_before.is_none_or(|_| !h.responding)
        && !ctx.udp_ports.is_empty()
        && (h.responding || (s.scan_nonresponders && !unused))
        && !gov.paused()
    {
        let wait = Duration::from_millis(u64::from(s.port_timeout.clamp(300, 2000)));
        let tries = (s.retries + 1).min(4);
        let slots = Arc::new(Semaphore::new(
            (if s.safe { 2 } else { 16 }).min(gov.limit()),
        ));
        let mut tasks = JoinSet::new();
        let (ports, skipped) = udp_scan_ports(&ctx.udp_ports);
        if !skipped.is_empty() && h.responding {
            note(
                &mut h,
                format!(
                    "UDP {}: industrial/printer port, not probed by the UDP scan (use --ot for BACnet)",
                    skipped
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                ),
            );
        }
        for port in ports {
            if gov.paused() {
                break;
            }
            let Ok(permit) = slots.clone().acquire_owned().await else {
                break;
            };
            if !gov.delay().is_zero() {
                sleep(gov.delay()).await;
            }
            let ctx = ctx.clone();
            tasks.spawn(async move {
                let _dhcp = if port == 67 {
                    ctx.dhcp.acquire().await.ok()
                } else {
                    None
                };
                let _socket = ctx.sockets.acquire().await.ok();
                let result = crate::udp::probe(ip, port, wait, tries, &ctx.gate).await;
                drop(permit);
                (port, result)
            });
        }
        let mut results = vec![];
        while let Some(done) = tasks.join_next().await {
            if let Ok(item) = done {
                results.push(item);
            }
        }
        results.sort_by_key(|(port, _)| *port);
        for (port, r) in results {
            match r.state {
                crate::udp::State::Open => {
                    h.udp_open.push(port);
                    h.responding = true;
                    if !r.info.is_empty() {
                        h.identity.insert(format!("udp.{port}"), r.info);
                    }
                    if h.mac.is_empty()
                        && let Some(mac) = r.mac
                    {
                        h.mac = mac;
                    }
                }
                crate::udp::State::Error(e) => note(&mut h, format!("UDP {port}: {e}")),
                crate::udp::State::Closed | crate::udp::State::NoReply => {}
            }
        }
    }
    if wants_ot(&h, &s) && !(unused && !h.responding) && !gov.paused() {
        for port in crate::ot::identify(&mut h, &s, &ctx.gate).await {
            gov.known_open_failed(port);
        }
        flush_backoff_notes(&gov, &mut h);
        merge_ot_udp(&mut h);
    }
    // SNMP with the user's credentials: system group, interfaces, addresses, LLDP neighbours.
    if let Some(config) = &s.snmp
        && crate::plan::snmp_read(h.responding, &s)
        && !gov.paused()
    {
        match crate::snmp::collect(ip, config, s.safe, s.port_timeout, &ctx.gate).await {
            Ok(found) => {
                h.responding = true;
                for text in &found.notes {
                    note(&mut h, format!("SNMP: {text}"));
                }
                h.identity.extend(found.identity());
                if config.port == crate::snmp::SnmpConfig::DEFAULT_PORT
                    && !h.udp_open.contains(&161)
                {
                    h.udp_open.push(161);
                    h.udp_open.sort_unstable();
                }
            }
            // most hosts run no agent: silence is not an error (as for BACnet)
            Err(e) if e == crate::snmp::NO_ANSWER => {}
            Err(e) => note(&mut h, format!("SNMP: {e}")),
        }
    } else if h.responding
        && s.snmp.is_none()
        && let Some(why) = &s.snmp_unresolved
    {
        // SNMP was configured (saved by name) but could not be set up: say so, never skip quietly
        note(&mut h, format!("SNMP not read: {why}"));
    }
    // Favicon: one GET /favicon.ico per web port that answered as HTTP(S). Opt-in, never in Safe
    // Mode, never on industrial hosts (so after the OT identification), one request at a time
    // through the rate gate.
    if crate::favicon::enabled(&s) && !gov.paused() {
        let limit = Duration::from_millis(u64::from(s.port_timeout.clamp(500, 5000)));
        for (port, secure) in crate::favicon::candidates(&h) {
            if gov.paused() {
                break;
            }
            if !gov.delay().is_zero() {
                sleep(gov.delay()).await;
            }
            match crate::favicon::fetch(ip, port, secure, limit, &ctx.gate).await {
                crate::favicon::Fetched::Hash(hash) => {
                    h.identity
                        .insert(format!("http.{port}.favicon_mmh3"), hash.to_string());
                }
                crate::favicon::Fetched::NoIcon => {}
                crate::favicon::Fetched::Failed => {
                    note(&mut h, format!("Favicon: port {port} stopped answering"));
                    gov.known_open_failed(port);
                }
            }
        }
        flush_backoff_notes(&gov, &mut h);
    }
    if s.trace
        && h.responding
        && let Some(b) = before.filter(|b| b.responding && !b.trace.is_empty())
    {
        h.trace = b.trace.clone();
        carried.push("trace".into());
    } else if s.trace && h.responding && !gov.paused() {
        let (hops, notes) = traceroute(ip, &h.open, &s, &ctx).await;
        for text in notes {
            note(&mut h, text);
        }
        h.trace = hops;
    }
    if h.responding && s.dns {
        ctx.gate.note(
            PacketKind::DnsLookup,
            "reverse lookup via the system resolver",
        );
        let lookup = run_blocking(&ctx.blocking, move || {
            dns_lookup::lookup_addr(&ip).unwrap_or_default()
        });
        // On timeout the lookup thread keeps its blocking-pool permit until it ends.
        if let Ok(Some(name)) = tokio::time::timeout(Duration::from_secs(3), lookup).await {
            h.hostname = hostname_from(name);
        }
    }
    if s.os_detect && h.responding {
        analyze(&mut h, fingerprint.as_ref());
    }
    if let Some(p) = &base {
        crate::incremental::mark(&mut h, p.id, probed_sample.as_deref(), &carried);
    }
    if ctx.scripts.is_some() {
        // Rhai may run up to its wall-time limit per script; keep it off the async workers.
        let fallback = h.clone();
        let script_ctx = ctx.clone();
        let mut host = h;
        h = match run_blocking(&ctx.blocking, move || {
            if let Some(scripts) = &script_ctx.scripts {
                scripts.run_host(&mut host);
            }
            host
        })
        .await
        {
            Some(done) => done,
            None => {
                let mut kept = fallback;
                note(&mut kept, "Scripts did not complete".into());
                kept
            }
        };
    }
    h
}

/// Manufacturer, OS family and device type from everything learned about the host.
fn analyze(h: &mut Host, fp: Option<&TcpFp>) {
    let mut vendor = "";
    if !h.mac.is_empty()
        && !crate::oui::locally_administered(&h.mac)
        && let Some(v) = crate::oui::vendor(&h.mac)
    {
        vendor = v;
        h.identity.insert("mac.vendor".into(), v.to_string());
    }
    let ttl = h.ttl;
    if let Some(g) = crate::osfp::guess(ttl, fp, &h.identity, &h.open, vendor) {
        h.identity.insert("os.guess".into(), g.name.clone());
        g.evidence().store(&mut h.identity, "os");
    }
    if let Some(fp) = fp {
        h.identity
            .insert("os.tcp_fingerprint".into(), fp.describe());
    }
    let os = h.identity.get("os.guess").cloned().unwrap_or_default();
    let hostnames = [h.hostname.clone()];
    let facts = crate::devices::Facts {
        mac: &h.mac,
        vendor,
        tcp: &h.open,
        udp: &h.udp_open,
        identity: &h.identity,
        hostnames: if h.hostname.is_empty() {
            &[]
        } else {
            &hostnames
        },
        os: &os,
        ttl,
        protocols: &[],
    };
    if let Some((kind, why)) = crate::devices::classify_detailed(&facts) {
        h.identity.insert("device.type".into(), kind);
        why.store(&mut h.identity, "device");
    }
}
/// Tests that talk to the fixed BACnet port (47808) on loopback take this lock, so a scan with
/// `--ot` in one test cannot answer another test's simulated device.
#[cfg(test)]
pub(crate) static BACNET_PORT: Mutex<()> = Mutex::new(());

/// Runs between the port probes and service identification. Empty outside tests, where it
/// stops the fake devices that must refuse identification (`tests::flaky_device`). Defined
/// here, not in `scan_host`: the drift guards read the code above the first `cfg(test)`.
fn before_identification(_open: &[u16]) {
    #[cfg(test)]
    tests::stop_flaky_devices(_open);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_scan_never_sends_to_ot_or_printer_ports() {
        let (send, skip) = udp_scan_ports(&[53, 161, 2222, 9100, 20000, 44818, 47808, 47810, 5353]);
        assert_eq!(send, [53, 161, 5353]);
        assert_eq!(skip, [2222, 9100, 20000, 44818, 47808, 47810]);
    }

    #[tokio::test]
    async fn unlimited_gate_never_waits() {
        let gate = Gate::unlimited();
        let start = Instant::now();
        for _ in 0..10_000 {
            gate.wait().await;
        }
        assert!(start.elapsed() < Duration::from_millis(200));
    }

    #[tokio::test]
    async fn token_bucket_enforces_rate() {
        let gate = Gate::per_second(100.0, 1.0);
        let start = Instant::now();
        for _ in 0..11 {
            gate.wait().await;
        }
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_millis(90), "{elapsed:?}");
        assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");
    }

    #[tokio::test]
    async fn concurrent_waiters_share_the_rate() {
        let gate = Arc::new(Gate::per_second(200.0, 1.0));
        let start = Instant::now();
        let mut set = JoinSet::new();
        for _ in 0..21 {
            let gate = gate.clone();
            set.spawn(async move { gate.wait().await });
        }
        while set.join_next().await.is_some() {}
        assert!(start.elapsed() >= Duration::from_millis(90));
    }

    #[test]
    fn try_take_never_goes_into_debt() {
        assert!(Gate::unlimited().try_take().is_ok());
        let gate = Gate::per_second(10.0, 1.0);
        assert!(gate.try_take().is_ok());
        let wait = gate.try_take().unwrap_err();
        assert!(wait > Duration::from_millis(50) && wait <= Duration::from_millis(100));
        assert!(gate.try_take().is_err(), "refusals do not consume tokens");
        std::thread::sleep(Duration::from_millis(110));
        assert!(gate.try_take().is_ok());
    }

    #[tokio::test]
    async fn every_connect_attempt_takes_a_token_and_doubles() {
        // 20 tokens/s with one in the bucket: four attempts need three more tokens.
        let gate = Gate::per_second(20.0, 1.0);
        let attempts = Arc::new(Mutex::new(vec![]));
        let start = Instant::now();
        let seen = attempts.clone();
        let state = connect_with_retries(
            &gate,
            Duration::from_millis(10),
            Duration::from_millis(40),
            3,
            move |t| {
                seen.lock().unwrap().push(t.as_millis());
                async { PortState::Unanswered }
            },
        )
        .await;
        assert_eq!(state, PortState::Unanswered);
        assert_eq!(*attempts.lock().unwrap(), vec![10, 20, 40, 40]);
        assert!(
            start.elapsed() >= Duration::from_millis(140),
            "{:?}",
            start.elapsed()
        );
        // An answer ends the retries.
        let calls = Arc::new(Mutex::new(0));
        let c = calls.clone();
        let state = connect_with_retries(
            &Gate::unlimited(),
            Duration::from_millis(10),
            Duration::from_millis(40),
            3,
            move |_| {
                *c.lock().unwrap() += 1;
                async { PortState::Closed }
            },
        )
        .await;
        assert_eq!((state, *calls.lock().unwrap()), (PortState::Closed, 1));
    }

    fn host(ip: &str) -> Host {
        Host {
            ip: ip.parse().unwrap(),
            responding: false,
            ping: None,
            ttl: None,
            hostname: String::new(),
            mac: String::new(),
            open: vec![],
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: false,
            identity: BTreeMap::new(),
            udp_open: vec![],
            trace: vec![],
        }
    }

    /// A host that accepts every port: the provisional hosts and the service identification
    /// stop at the limit, and the host says so.
    #[test]
    fn a_host_with_very_many_open_ports_is_announced_and_identified_up_to_a_limit() {
        let (tx, rx) = std::sync::mpsc::channel();
        let ctx = Ctx {
            partial: Some(tx),
            ..test_ctx()
        };
        let live = Mutex::new(vec![]);
        for port in (1..=u16::MAX).rev() {
            announce_open(&ctx, &host("10.0.0.1"), &live, port);
        }
        drop(ctx);
        let announced: Vec<Vec<u16>> = rx
            .iter()
            .map(|event| match event {
                Event::Partial(h) => h.open,
                _ => panic!("only provisional hosts are sent"),
            })
            .collect();
        assert_eq!(announced.len(), MANY_OPEN_PORTS);
        assert_eq!(announced[MANY_OPEN_PORTS - 1].len(), MANY_OPEN_PORTS);
        assert!(announced[MANY_OPEN_PORTS - 1].is_sorted());

        let open: Vec<u16> = (1..=u16::MAX).collect();
        let eligible = crate::plan::service_ports(&open, &Settings::default());
        let mut ports = eligible.clone();
        let note = cap_service_ports(&mut ports, open.len()).unwrap();
        assert_eq!(ports, eligible[..MANY_OPEN_PORTS]);
        assert_eq!(
            note,
            "65535 open ports (a proxy or tarpit that accepts every connection?); services were identified on the first 100 only"
        );
        // At the limit nothing is cut and nothing is said.
        assert_eq!(cap_service_ports(&mut ports, MANY_OPEN_PORTS), None);
        assert_eq!(ports.len(), MANY_OPEN_PORTS);
    }

    #[test]
    fn scan_analysis_stores_reasons_and_confidence_for_os_and_device_type() {
        let mut h = host("10.0.0.1");
        h.ttl = Some(128);
        h.open = vec![9100, 80, 515];
        h.identity
            .insert("svc.80".into(), "http HP LaserJet 4250".into());
        // Enough for an OS call (TTL 128 alone is below the threshold).
        h.identity
            .insert("udp.137".into(), "NetBIOS name table".into());
        analyze(&mut h, None);
        assert_eq!(h.identity["device.type"], "Printer / MFP");
        let device = crate::evidence::Evidence::from_identity(&h.identity, "device").unwrap();
        assert!(device.confidence >= 30, "{device:?}");
        assert!(device.reasons.iter().any(|r| r.contains("print port")));
        assert!(h.identity["device.confidence"].ends_with('%'));
        let os = crate::evidence::Evidence::from_identity(&h.identity, "os").unwrap();
        assert_eq!(h.identity["os.guess"], "Windows");
        assert!(
            os.reasons.contains(&"initial TTL 128".to_string()),
            "{os:?}"
        );
        // Nothing known: no conclusion, so no evidence keys.
        let mut bare = host("10.0.0.2");
        analyze(&mut bare, None);
        assert!(
            !bare
                .identity
                .keys()
                .any(|k| k.starts_with("os.") || k.starts_with("device."))
        );
    }

    #[tokio::test]
    async fn stop_keeps_hosts_that_already_finished() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut jobs = JoinSet::new();
        jobs.spawn(async { host("10.0.0.1") });
        jobs.spawn(async { host("10.0.0.2") });
        jobs.spawn(async {
            sleep(Duration::from_secs(30)).await;
            host("10.0.0.3")
        });
        sleep(Duration::from_millis(50)).await;
        assert!(drain_finished(&mut jobs, &tx));
        jobs.abort_all();
        let mut got: Vec<String> = rx
            .try_iter()
            .filter_map(|e| match e {
                Event::Host(h) => Some(h.ip.to_string()),
                _ => None,
            })
            .collect();
        got.sort();
        assert_eq!(got, ["10.0.0.1", "10.0.0.2"]);
    }

    #[test]
    fn numeric_reverse_dns_is_not_a_hostname() {
        assert_eq!(hostname_from("192.168.1.5".into()), "");
        assert_eq!(hostname_from("fe80::1".into()), "");
        assert_eq!(hostname_from("plc-7.example".into()), "plc-7.example");
        assert_eq!(hostname_from(String::new()), "");
    }

    #[tokio::test]
    async fn blocking_permit_is_held_until_the_thread_finishes() {
        let pool = Arc::new(Semaphore::new(1));
        let slow = run_blocking(&pool, || std::thread::sleep(Duration::from_millis(300)));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), slow)
                .await
                .is_err()
        );
        // The caller gave up, but the native call is still running and keeps its slot.
        assert_eq!(pool.available_permits(), 0);
        // It comes back once the thread ends. Loaded CI runners start blocking threads late,
        // so wait for it (bounded) instead of assuming a fixed delay.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while pool.available_permits() == 0 && std::time::Instant::now() < deadline {
            sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(pool.available_permits(), 1);
    }

    /// Every packet the scanner transmits is counted (ROADMAP H53): a sender takes its rate-gate
    /// token with `wait_for`/`try_take_for` (which record the packet) or notes it with
    /// `Gate::note`. A bare `gate.wait()` or `try_take()` in a sender would send unrecorded
    /// packets. The OT senders take plain tokens because their requests record themselves
    /// (`OtStream`/`OtUdp` with a log).
    #[test]
    fn senders_do_not_take_unrecorded_tokens() {
        let sources = [
            ("arp.rs", include_str!("arp.rs")),
            ("favicon.rs", include_str!("favicon.rs")),
            ("jarm.rs", include_str!("jarm.rs")),
            ("syn.rs", include_str!("syn.rs")),
            ("tls.rs", include_str!("tls.rs")),
            ("trace.rs", include_str!("trace.rs")),
            ("udp.rs", include_str!("udp.rs")),
            ("service/mod.rs", include_str!("service/mod.rs")),
            ("service/rdp.rs", include_str!("service/rdp.rs")),
            ("service/smb/mod.rs", include_str!("service/smb/mod.rs")),
        ];
        for (name, source) in sources {
            let code = source
                .split(
                    "#[cfg(test)]
mod tests",
                )
                .next()
                .unwrap();
            for bare in [".wait().await", ".try_take()"] {
                assert!(
                    !code.contains(bare),
                    "{name} takes a gate token without recording the packet ({bare}); use wait_for/try_take_for"
                );
            }
        }
        // The OT code records through its sockets: no raw send exists there (see ot::readonly).
        let ot = include_str!("ot.rs")
            .split(
                "#[cfg(test)]
mod tests",
            )
            .next()
            .unwrap();
        assert!(
            ot.contains("with_log("),
            "ot.rs must attach the sent log to its sockets"
        );
    }

    /// Scans 127.0.0.1 over TCP connect and returns (open ports, closed count, unanswered).
    fn loopback_scan(ports: Vec<u16>, adaptive: bool, safe: bool) -> (Vec<u16>, usize, usize) {
        let s = Settings {
            tcp_only: true,
            safe,
            tcp_adaptive: adaptive,
            // Windows reports a refused loopback connect only after ~2 s (SYN retransmits).
            port_timeout: 5000,
            delay: 0,
            ..Settings::default()
        };
        let run = crate::scan::start(vec!["127.0.0.1".parse().unwrap()], ports, s);
        let event = run.receiver.recv_timeout(Duration::from_secs(30)).unwrap();
        let Event::Host(h) = event else {
            panic!("missing host")
        };
        (h.open, h.closed, h.unanswered)
    }

    #[test]
    fn adaptive_connect_scan_classifies_like_the_default() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open = listener.local_addr().unwrap().port();
        let reserved: Vec<_> = (0..6).map(|_| crate::probes::refused_port()).collect();
        let closed: Vec<u16> = reserved.iter().map(|r| r.0).collect();
        let mut ports = closed.clone();
        ports.push(open);
        // More ports than the pilot batch, so the RTT-derived timeout is used too.
        let plain = loopback_scan(ports.clone(), false, false);
        let adaptive = loopback_scan(ports.clone(), true, false);
        assert_eq!(plain, (vec![open], closed.len(), 0));
        assert_eq!(adaptive.0, plain.0, "open ports never change");
        if cfg!(windows) {
            // Windows reports a refused connect only after ~2 s, so once an accept has
            // shortened the wait, a closed port may be counted as unanswered instead.
            assert_eq!(adaptive.1 + adaptive.2, closed.len());
        } else {
            assert_eq!(adaptive, plain);
        }
        // Safe Mode (rate gate, few parallel probes) behaves the same.
        let safe = loopback_scan(ports[..4].to_vec(), true, true);
        assert_eq!((safe.0.len(), safe.1 + safe.2), (0, 4));
    }

    #[tokio::test]
    async fn connect_probe_records_an_rtt_sample_only_for_answers() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open = listener.local_addr().unwrap().port();
        let (closed, _reserved) = crate::probes::refused_port();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let s = Settings {
            safe: false,
            tcp_adaptive: true,
            ..Settings::default()
        };
        let ctx = test_ctx();
        for (port, want) in [(open, PortState::Open), (closed, PortState::Closed)] {
            let rtt = HostRtt::default();
            let timeout = Duration::from_millis(5000);
            let got = probe_port(ip, port, timeout, &s, &ctx, Some(&rtt), None, None).await;
            assert_eq!(got.state, want);
            assert!(rtt.has_sample(), "{want:?} is an RTT sample");
            let next = rtt.timeout(timeout, Duration::from_millis(100), timeout);
            assert!(next <= timeout);
            if want == PortState::Open {
                // A loopback accept is far below the 100 ms floor: the wait shrinks to it.
                // (A refused connect is not asserted: Windows takes ~2 s to report it.)
                assert_eq!(next, Duration::from_millis(100));
            }
        }
        // Without the estimator nothing changes.
        let plain = probe_port(
            ip,
            closed,
            Duration::from_millis(5000),
            &s,
            &ctx,
            None,
            None,
            None,
        )
        .await;
        assert_eq!(plain.state, PortState::Closed);
    }

    /// The listeners of the [`flaky_device`]s, by port.
    static FLAKY: Mutex<BTreeMap<u16, std::net::TcpListener>> = Mutex::new(BTreeMap::new());

    /// A "device" that answers the port probe and then stops listening: the identification
    /// connect that follows is refused (or silently dropped, depending on the OS).
    fn flaky_device() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        FLAKY.lock().unwrap().insert(port, listener);
        port
    }

    /// Called by the scan after the port probes and before service identification: closes the
    /// listeners of the flaky devices found open. Closing them anywhere else races with the
    /// scan: an identification connect that reaches a listener's backlog first succeeds, which
    /// made these tests flaky on CI.
    pub(super) fn stop_flaky_devices(open: &[u16]) {
        let mut flaky = FLAKY.lock().unwrap_or_else(|e| e.into_inner());
        for port in open {
            flaky.remove(port);
        }
    }

    fn scan_loopback(ports: Vec<u16>, backoff: bool, services: bool) -> Host {
        let s = Settings {
            tcp_only: true,
            safe: false,
            services,
            backoff,
            retries: 0,
            delay: 0,
            port_timeout: 1500,
            ..Settings::default()
        };
        let run = crate::scan::start(vec!["127.0.0.1".parse().unwrap()], ports, s);
        match run.receiver.recv_timeout(Duration::from_secs(60)).unwrap() {
            Event::Host(h) => h,
            _ => panic!("missing host"),
        }
    }

    #[test]
    fn a_device_that_stops_answering_after_it_was_found_open_gets_a_back_off_note() {
        let port = flaky_device();
        let h = scan_loopback(vec![port], true, true);
        assert_eq!(h.open, [port]);
        let note = h
            .errors
            .iter()
            .find(|e| e.starts_with("backed off:"))
            .unwrap_or_else(|| panic!("no back-off note in {:?}", h.errors));
        assert!(
            note.contains(&format!(
                "port {port} stopped answering after it was found open"
            )),
            "{note}"
        );
        assert_eq!(h.errors[0], *note, "the back-off note comes first");
        // --no-backoff: the same device, no note (the service note stays).
        let port = flaky_device();
        let h = scan_loopback(vec![port], false, true);
        assert!(
            h.errors.iter().all(|e| !e.starts_with("backed off:")),
            "{:?}",
            h.errors
        );
    }

    #[test]
    fn persisting_errors_pause_the_host_for_the_rest_of_the_scan() {
        // Four open ports that each refuse the identification that follows: four strikes pause an
        // unclassified host.
        let paused = |h: &Host| {
            h.errors
                .iter()
                .any(|e| e.contains("host paused for the rest of this scan"))
        };
        let ports: Vec<u16> = (0..4).map(|_| flaky_device()).collect();
        let h = scan_loopback(ports.clone(), true, true);
        for p in &ports {
            assert!(h.open.contains(p), "{p} was found open: {:?}", h.open);
        }
        assert!(paused(&h), "{:?}", h.errors);
        // Every port had been probed before the identification started.
        assert!(h.ports_checked);
    }

    #[test]
    fn a_healthy_host_with_closed_and_open_ports_is_not_backed_off() {
        let listeners: Vec<std::net::TcpListener> = (0..5)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let open: Vec<u16> = listeners
            .iter()
            .map(|l| l.local_addr().unwrap().port())
            .collect();
        // Many closed ports (refused on Linux, silent after ~2 s on Windows loopback).
        let reserved: Vec<_> = (0..60).map(|_| crate::probes::refused_port()).collect();
        let closed: Vec<u16> = reserved.iter().map(|r| r.0).collect();
        let mut ports = [open.clone(), closed].concat();
        ports.sort_unstable();
        ports.dedup();
        let h = scan_loopback(ports.clone(), true, false);
        for p in &open {
            assert!(h.open.contains(p), "{p}");
        }
        assert!(
            h.errors.iter().all(|e| !e.starts_with("backed off:")),
            "{:?}",
            h.errors
        );
        assert!(h.ports_checked, "every port was probed");
        assert_eq!(h.open.len() + h.closed + h.unanswered, ports.len());
    }

    #[test]
    fn back_off_notes_survive_a_full_error_list() {
        let mut h = host("10.0.0.1");
        for i in 0..8 {
            note(&mut h, format!("TCP {i}: some error"));
        }
        note_first(&mut h, "backed off: example".into());
        assert_eq!(h.errors.len(), 8);
        assert_eq!(h.errors[0], "backed off: example");
        note_first(&mut h, "backed off: example".into());
        assert_eq!(h.errors.len(), 8, "no duplicate");
    }

    fn test_ctx() -> Ctx {
        Ctx {
            gate: Arc::new(Gate::unlimited()),
            blocking: Arc::new(Semaphore::new(4)),
            sockets: Arc::new(Semaphore::new(4)),
            dhcp: Semaphore::new(1),
            syn: vec![],
            syn_error: None,
            arp: vec![],
            arp_error: None,
            probes: None,
            udp_ports: vec![],
            scripts: None,
            previous: None,
            classes: crate::portorder::ClassTable::builtin(),
            partial: None,
        }
    }

    /// Scans 127.0.0.1 through `scan_host` with the given class table.
    async fn scan_with(
        ports: Vec<u16>,
        table: Option<&str>,
        early_stop: bool,
        parallel: usize,
    ) -> Host {
        let mut ctx = test_ctx();
        ctx.sockets = Arc::new(Semaphore::new(64));
        if let Some(json) = table {
            ctx.classes = Box::leak(Box::new(crate::portorder::ClassTable::parse(json).unwrap()));
        }
        let s = Settings {
            tcp_only: true,
            safe: false,
            retries: 0,
            port_timeout: 1500,
            early_stop,
            port_parallel: parallel,
            ..Settings::default()
        };
        scan_host(
            "127.0.0.1".parse().unwrap(),
            Arc::new(ports),
            Arc::new(s),
            Arc::new(ctx),
        )
        .await
    }

    /// The order in which ports are probed never changes the result (ROADMAP B13): the same
    /// host scanned with the frequency order and with a class that reverses it is identical.
    #[tokio::test]
    async fn the_probe_order_never_changes_the_result() {
        let listeners: Vec<std::net::TcpListener> = (0..3)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let mut open: Vec<u16> = listeners
            .iter()
            .map(|l| l.local_addr().unwrap().port())
            .collect();
        open.sort_unstable();
        let reserved: Vec<_> = (0..6).map(|_| crate::probes::refused_port()).collect();
        let closed: Vec<u16> = reserved.iter().map(|r| r.0).collect();
        let mut ports = [open.clone(), closed.clone()].concat();
        ports.sort_unstable();
        ports.dedup();
        let reversed: Vec<u16> = ports.iter().rev().copied().collect();
        let table = format!(
            r#"{{"classes":[{{"id":"x","label":"X","ports":{reversed:?},"signature":{open:?},"vendors":[],"ttl":[]}}]}}"#
        );
        let default = scan_with(ports.clone(), None, false, 64).await;
        // Sequential probes, so the class order really is the launch order.
        let forced = scan_with(ports.clone(), Some(&table), false, 1).await;
        for h in [&default, &forced] {
            assert_eq!(h.open, open);
            assert!(h.ports_checked, "every port was probed");
            assert_eq!(h.open.len() + h.closed + h.unanswered, ports.len());
        }
        assert_eq!(
            (
                default.open,
                default.closed,
                default.unanswered,
                default.errors
            ),
            (forced.open, forced.closed, forced.unanswered, forced.errors)
        );
    }

    /// `--early-stop`: a host that is certainly a printer (two print ports open, the class's
    /// priority ports probed) is not probed further, and says so; without the flag the same host
    /// is scanned completely. The print ports are fixed numbers, so the test skips when this
    /// machine already uses one of them.
    #[tokio::test]
    async fn early_stop_skips_the_rest_once_the_class_is_certain_and_says_so() {
        let (Ok(_a), Ok(_b)) = (
            std::net::TcpListener::bind("127.0.0.1:9100"),
            std::net::TcpListener::bind("127.0.0.1:515"),
        ) else {
            return;
        };
        let mut ports = vec![9100, 515, 631];
        ports.extend(29500..29540);
        let full = scan_with(ports.clone(), None, false, 1).await;
        assert!(full.ports_checked && full.open == [515, 9100], "{full:?}");
        let stopped = scan_with(ports.clone(), None, true, 1).await;
        assert_eq!(stopped.open, [515, 9100], "what was found is kept");
        assert!(
            !stopped.ports_checked,
            "unprobed ports are unknown, not closed"
        );
        assert!(
            stopped
                .errors
                .iter()
                .any(|e| e.starts_with("early stop: identified as Printer")
                    && e.contains("not probed")),
            "{:?}",
            stopped.errors
        );
        assert!(stopped.closed + stopped.unanswered < full.closed + full.unanswered);
    }

    /// One scan of 127.0.0.1 through `scan_host`, a repeat scan when `previous` is given.
    async fn scan_repeat(
        ports: Vec<u16>,
        previous: Option<Arc<crate::incremental::Previous>>,
    ) -> Host {
        let mut ctx = test_ctx();
        ctx.sockets = Arc::new(Semaphore::new(64));
        ctx.probes = Some(ProbeDb::load("").unwrap());
        ctx.previous = previous;
        let s = Settings {
            tcp_only: true,
            safe: false,
            services: true,
            retries: 0,
            port_timeout: 1500,
            ..Settings::default()
        };
        scan_host(
            "127.0.0.1".parse().unwrap(),
            Arc::new(ports),
            Arc::new(s),
            Arc::new(ctx),
        )
        .await
    }

    fn scan_of(ports: &str, hosts: Vec<Host>) -> crate::store::Snapshot {
        crate::store::Snapshot {
            targets: "127.0.0.1".into(),
            complete: true,
            settings: Settings {
                ports: ports.into(),
                services: true,
                ..Settings::default()
            },
            hosts,
            observations: vec![],
            notes: Default::default(),
            sent: vec![],
        }
    }

    /// A server that greets with an SSH banner until `stop` is set, then closes its port.
    fn greeting_server(stop: Arc<std::sync::atomic::AtomicBool>) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::Write;
            while !stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.write_all(b"SSH-2.0-OpenSSH_8.4\r\n");
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        port
    }

    /// Fast repeat scans (ROADMAP B14), end to end on loopback: the second scan probes a sample and
    /// seeds the change detector, the third keeps the identification of the unchanged service and
    /// says so, nothing it carried over counts as checked, and the diff against the full scan is
    /// empty. When the server goes away, the repeat scan finds out (a known port is always probed)
    /// and the diff reports exactly that.
    #[tokio::test]
    async fn a_repeat_scan_carries_over_what_did_not_change_and_says_so() {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let port = greeting_server(stop.clone());
        // Closed ports below every OS's ephemeral range (Linux starts at 32768): a listener another
        // test binds to port 0 can never land on them.
        let mut ports: Vec<u16> = (29400..29420).collect();
        ports.push(port);
        let text = format!("29400-29419,{port}");
        let full = scan_repeat(ports.clone(), None).await;
        assert!(full.ports_checked && full.open == [port], "{full:?}");
        assert!(full.identity.keys().all(|k| !k.starts_with("incr.")));
        let base = |n, h: &Host| {
            Some(Arc::new(crate::incremental::Previous::new(
                n,
                vec![h.clone()],
            )))
        };
        // Second scan: a sample, identified in full (nothing to compare with), fingerprint stored.
        let second = scan_repeat(ports.clone(), base(1, &full)).await;
        assert_eq!(second.open, [port]);
        assert!(!second.ports_checked, "a sample is not a full check");
        assert!(crate::incremental::checked(&second, port));
        // The sample is small: some requested port was not probed.
        let sample = crate::incremental::ports_for(Some(&full), &ports, 1);
        let unsampled = *ports.iter().find(|p| !sample.contains(p)).unwrap();
        assert!(!crate::incremental::checked(&second, unsampled));
        assert_eq!(second.identity["incr.base"], "scan #1");
        assert!(second.identity.contains_key(&format!("incr.fp.{port}")));
        assert!(!second.identity.contains_key("incr.carried"), "{second:?}");
        assert_eq!(
            second.identity[&format!("svc.{port}")],
            full.identity[&format!("svc.{port}")]
        );
        // Third scan: the banner hashes the same, so the identification is kept and marked.
        let third = scan_repeat(ports.clone(), base(2, &second)).await;
        assert_eq!(third.identity["incr.carried"], format!("svc:{port}"));
        assert_eq!(
            third.identity[&format!("svc.{port}")],
            full.identity[&format!("svc.{port}")]
        );
        assert_eq!(third.open, [port]);
        // Full -> repeat of an unchanged host: nothing changed, nothing is reported.
        let report = crate::store::diff_report(
            &scan_of(&text, vec![full.clone()]),
            &scan_of(&text, vec![third.clone()]),
            &crate::store::IgnoreList::new(&[]),
        )
        .unwrap();
        assert!(report.changes.is_empty(), "{:?}", report.changes);
        // The server goes away: the repeat scan probes the known port and the diff says so.
        stop.store(true, Ordering::Relaxed);
        sleep(Duration::from_millis(100)).await;
        let fourth = scan_repeat(ports, base(3, &third)).await;
        assert!(fourth.open.is_empty(), "{fourth:?}");
        let report = crate::store::diff_report(
            &scan_of(&text, vec![full]),
            &scan_of(&text, vec![fourth]),
            &crate::store::IgnoreList::new(&[]),
        )
        .unwrap();
        assert!(
            report.changes.iter().any(
                |c| matches!(c, crate::store::Change::PortClosed { port: p, .. } if *p == port)
            ),
            "{:?}",
            report.changes
        );
    }

    /// A port that opened since the base scan is found when it is in the sample.
    #[tokio::test]
    async fn a_repeat_scan_finds_a_newly_opened_port_in_its_sample() {
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let mut ports: Vec<u16> = (29400..29420).collect();
        ports.push(port);
        let text = format!("29400-29419,{port}");
        let full = scan_repeat(ports.clone(), None).await;
        assert!(!full.open.contains(&port));
        let Ok(server) = std::net::TcpListener::bind(("127.0.0.1", port)) else {
            return; // the port was taken meanwhile
        };
        // A base scan number whose rotating slice reaches the port (the sample moves every scan).
        let id = (1..40)
            .find(|g| crate::incremental::ports_for(Some(&full), &ports, *g).contains(&port))
            .unwrap();
        let prev = Arc::new(crate::incremental::Previous::new(id, vec![full.clone()]));
        let again = scan_repeat(ports, Some(prev)).await;
        assert!(again.open.contains(&port), "{again:?}");
        let report = crate::store::diff_report(
            &scan_of(&text, vec![full]),
            &scan_of(&text, vec![again]),
            &crate::store::IgnoreList::new(&[]),
        )
        .unwrap();
        assert!(
            report.changes.iter().any(
                |c| matches!(c, crate::store::Change::PortOpened { port: p, .. } if *p == port)
            ),
            "{:?}",
            report.changes
        );
        drop(server);
    }

    #[test]
    fn ot_identification_for_responding_or_explicitly_scanned_silent_hosts() {
        let s = Settings {
            ot: true,
            scan_nonresponders: false,
            ..Settings::default()
        };
        let mut h = host("10.0.0.1");
        assert!(
            !wants_ot(&h, &s),
            "silent host without --scan-nonresponders: no Who-Is"
        );
        // BACnet-only devices answer nothing else, so a silent host gets the Who-Is when
        // non-responders are scanned.
        assert!(wants_ot(
            &h,
            &Settings {
                scan_nonresponders: true,
                ..s.clone()
            }
        ));
        // An open (or closed) TCP port marks an ICMP-silent device as responding.
        h.open.push(502);
        h.responding = true;
        assert!(wants_ot(&h, &s));
        assert!(!wants_ot(
            &h,
            &Settings {
                ot: false,
                ..Settings::default()
            }
        ));
    }

    #[test]
    fn ot_udp_reply_lists_the_port_as_open_udp() {
        let mut h = host("10.0.0.1");
        h.udp_open = vec![161];
        h.identity.insert("BACnet.device_id".into(), "1000".into());
        merge_ot_udp(&mut h);
        assert_eq!(h.udp_open, [161, 47808]);
        merge_ot_udp(&mut h);
        assert_eq!(h.udp_open, [161, 47808], "no duplicate on repeat");
        // No BACnet identity (or only another protocol's): nothing is added.
        let mut other = host("10.0.0.2");
        other.identity.insert("Modbus.vendor".into(), "x".into());
        merge_ot_udp(&mut other);
        assert!(other.udp_open.is_empty());
        // FINS answered over TCP is not a UDP answer
        other
            .identity
            .insert("Omron FINS/TCP.model".into(), "CP1L".into());
        merge_ot_udp(&mut other);
        assert!(other.udp_open.is_empty(), "{:?}", other.udp_open);
        other
            .identity
            .insert("Omron FINS.model".into(), "CP1L".into());
        merge_ot_udp(&mut other);
        assert_eq!(other.udp_open, [9600]);
    }

    #[test]
    fn ot_scan_lists_bacnet_port_in_udp_open() {
        let _port = BACNET_PORT.lock().unwrap_or_else(|e| e.into_inner());
        // The fixed BACnet port may be taken (lab simulator, another test run): skip then.
        let Ok(device) = std::net::UdpSocket::bind("127.0.0.1:47808") else {
            return;
        };
        device
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let server = std::thread::spawn(move || {
            let mut b = [0u8; 64];
            if let Ok((_, from)) = device.recv_from(&mut b) {
                let iam = [
                    0x81, 0x0a, 0, 20, 1, 0, 0x10, 0, 0xc4, 2, 0, 0, 42, 0x22, 5, 0xdc, 0x91, 3,
                    0x21, 15,
                ];
                let _ = device.send_to(&iam, from);
            }
        });
        let s = Settings {
            tcp_only: true,
            safe: false,
            ot: true,
            scan_nonresponders: true,
            port_timeout: 1500,
            ..Settings::default()
        };
        let run = crate::scan::start(vec!["127.0.0.1".parse().unwrap()], vec![1], s);
        let event = run.receiver.recv_timeout(Duration::from_secs(15)).unwrap();
        let Event::Host(h) = event else {
            panic!("missing host")
        };
        let sent = run.sent.snapshot();
        drop(run);
        let _ = server.join();
        assert_eq!(
            h.identity.get("BACnet.device_id").map(String::as_str),
            Some("42")
        );
        assert_eq!(h.udp_open, [47808]);
        // The Who-Is is in the sent log under its service, and the plan lists exactly that.
        let who_is = "BACnet/IP: unicast Who-Is (unconfirmed service 8)";
        assert!(
            sent.iter()
                .any(|e| e.kind == PacketKind::OtRequest && e.detail == who_is && e.count == 1),
            "{sent:?}"
        );
        let settings = Settings {
            tcp_only: true,
            ot: true,
            scan_nonresponders: true,
            ..Settings::default()
        };
        let planned = crate::plan::host("127.0.0.1".parse().unwrap(), &[1], &[], &settings, None);
        assert!(
            planned
                .keys()
                .contains(&(PacketKind::OtRequest, who_is.to_string()))
        );
    }

    #[test]
    fn scripts_run_off_the_async_workers_and_still_apply() {
        let dir = std::env::temp_dir().join(format!("ns-script-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("mark.rhai");
        std::fs::write(&file, "fn on_host(h) { h.set(\"seen\", \"yes\"); }").unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let s = Settings {
            tcp_only: true,
            safe: false,
            scripts: file.to_string_lossy().into_owned(),
            ..Settings::default()
        };
        let run = crate::scan::start(vec![addr.ip()], vec![addr.port()], s);
        let event = run.receiver.recv_timeout(Duration::from_secs(10)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        let Event::Host(h) = event else {
            panic!("missing host")
        };
        assert_eq!(
            h.identity.get("script.seen").map(String::as_str),
            Some("yes")
        );
    }
}
