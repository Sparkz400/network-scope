//! Bounded async scheduling shared by the desktop, CLI and TUI.
use crate::{
    osfp::TcpFp,
    rtt::HostRtt,
    scan::{Event, Host, PortState, Settings},
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
}
impl Gate {
    pub fn unlimited() -> Self {
        Self {
            bucket: None,
            safe: false,
        }
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
    gate.wait().await;
    let mut state = connect(attempt).await;
    for _ in 0..retries.min(5) {
        if state != PortState::Unanswered {
            break;
        }
        attempt = (attempt * 2).min(cap.max(first));
        gate.wait().await;
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
    s.ot && (h.responding || s.scan_nonresponders)
}

/// UDP ports the OT identification talks to over UDP. A parsed reply (`<protocol>.*`
/// identity keys) proves the port answered, so the host lists it as open UDP like a
/// port found by the UDP scan. Today that is only BACnet/IP; EtherNet/IP is identified
/// over TCP 44818.
const OT_UDP: [(&str, u16); 1] = [("BACnet", 47808)];

fn merge_ot_udp(h: &mut Host) {
    for (protocol, port) in OT_UDP {
        let prefix = format!("{protocol}.");
        if h.identity.keys().any(|k| k.starts_with(&prefix)) && !h.udp_open.contains(&port) {
            h.udp_open.push(port);
            h.udp_open.sort_unstable();
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
    syn: Option<Arc<SynEngine>>,
    syn_error: Option<String>,
    arp: Option<Arc<crate::arp::ArpEngine>>,
    arp_error: Option<String>,
    probes: Option<ProbeDb>,
    udp_ports: Vec<u16>,
    scripts: Option<crate::script::Scripts>,
}

pub async fn execute(
    hosts: Box<dyn Iterator<Item = IpAddr> + Send>,
    ports: Vec<u16>,
    s: Settings,
    cancel: Arc<AtomicBool>,
    pause: Arc<AtomicBool>,
    tx: Sender<Event>,
) {
    let s = Arc::new(s);
    let gate = Arc::new(if s.safe {
        Gate::new(s.delay.max(100)).with_safe(true)
    } else if s.max_rate > 0 {
        let rate = f64::from(s.max_rate);
        Gate::per_second(rate, (rate / 10.0).max(1.0))
    } else {
        Gate::unlimited()
    });
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
    let (syn, syn_error) = if s.syn && !s.safe {
        match SynEngine::start(&s, gate.clone()) {
            Ok(engine) => (Some(engine), None),
            Err(e) => (None, Some(e)),
        }
    } else {
        (None, None)
    };
    // Opt-in, and never in Safe Mode (the per-host OS lookup is used there).
    let (arp, arp_error) = if s.arp_sweep && !s.safe {
        match crate::arp::ArpEngine::start(&s, gate.clone()) {
            Ok(engine) => (Some(engine), None),
            Err(e) => (None, Some(e)),
        }
    } else {
        (None, None)
    };
    let ctx = Arc::new(Ctx {
        gate,
        blocking: Arc::new(Semaphore::new(256)),
        sockets: Arc::new(Semaphore::new(4096)),
        dhcp: Semaphore::new(1),
        syn,
        syn_error,
        arp,
        arp_error,
        probes,
        udp_ports,
        scripts,
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

/// Ports probed before the rest of a host's ports when `tcp_adaptive` is on, so the
/// host's connect RTT is known when the remaining probes choose their timeout.
const PILOT_PORTS: usize = 3;
/// Longest wait for that first completed connect. A host that answers nothing costs
/// this once, in addition to the port timeout.
const PILOT_WAIT: Duration = Duration::from_millis(250);

async fn probe_port(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    s: &Settings,
    ctx: &Ctx,
    rtt: Option<&HostRtt>,
) -> PortProbe {
    // The caller already holds this probe's in-flight permit (`ctx.sockets`).
    let cap = timeout.max(Duration::from_millis(u64::from(s.port_timeout)));
    let mut note = ctx
        .syn_error
        .as_ref()
        .map(|e| format!("SYN unavailable; TCP connect fallback: {e}"));
    if let Some(engine) = &ctx.syn {
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
    let (Some(engine), IpAddr::V4(v4)) = (&ctx.arp, ip) else {
        return Swept::default();
    };
    let source = engine.source();
    if v4 == source {
        return Swept::default();
    }
    let interface = s.interface.clone();
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
            let (settings, gate) = (s.clone(), ctx.gate.clone());
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
    ports
        .iter()
        .partition(|p| !crate::service::is_ot_udp_port(**p))
}
fn note(h: &mut Host, text: String) {
    if h.errors.len() < 8 && !h.errors.contains(&text) {
        h.errors.push(text);
    }
}

async fn scan_host(ip: IpAddr, ports: Arc<Vec<u16>>, s: Arc<Settings>, ctx: Arc<Ctx>) -> Host {
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
    // ARP is independent of ping: an ICMP-silent LAN device can still be found.
    if s.arp || s.mac || s.os_detect || s.arp_sweep {
        let swept = sweep_arp(ip, &s, &ctx).await;
        if let Some(text) = swept.note {
            note(&mut h, text);
        }
        if let Some(mac) = swept.mac {
            h.mac = mac;
            h.responding = true;
        } else if !swept.answered {
            ctx.gate.wait().await;
            if let Some(Some(n)) =
                run_blocking(&ctx.blocking, move || crate::platform::neighbor(ip)).await
            {
                h.mac = n.mac;
                // A cached (possibly stale) neighbor entry is a MAC source, not proof of life.
                h.responding = n.fresh;
            }
        }
    }
    let mut rtts = vec![];
    if !s.tcp_only {
        let timeout = s.ping_timeout.clamp(1, 10000);
        let mut echoes = JoinSet::new();
        for _ in 0..s.probes.clamp(1, 10) {
            ctx.gate.wait().await;
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
    if h.responding || s.scan_nonresponders || s.tcp_only {
        h.ports_checked = true;
        let timeout = crate::scan::port_timeout(rtts.iter().copied().max(), &s);
        let parallel = if s.safe {
            s.port_parallel.clamp(1, 4)
        } else {
            s.port_parallel.clamp(1, 1024)
        };
        let slots = Arc::new(Semaphore::new(parallel));
        let mut probes = JoinSet::new();
        // Per-host RTT of completed connects (connect scan only; the SYN engine has its own).
        let host_rtt = (s.tcp_adaptive && ctx.syn.is_none()).then(|| Arc::new(HostRtt::default()));
        for (index, &port) in ports.iter().enumerate() {
            if index == PILOT_PORTS
                && let Some(r) = &host_rtt
            {
                r.wait_for_sample(timeout.min(PILOT_WAIT)).await;
            }
            let Ok(permit) = slots.clone().acquire_owned().await else {
                break;
            };
            // Global in-flight bound taken before spawning: with many workers and a
            // high --parallel, tasks would otherwise pile up waiting for a socket.
            let Ok(socket) = ctx.sockets.clone().acquire_owned().await else {
                break;
            };
            let (s, ctx, rtt) = (s.clone(), ctx.clone(), host_rtt.clone());
            probes.spawn(async move {
                let result = probe_port(ip, port, timeout, &s, &ctx, rtt.as_deref()).await;
                drop(socket);
                drop(permit);
                (port, result)
            });
        }
        let mut results = vec![];
        while let Some(result) = probes.join_next().await {
            if let Ok(item) = result {
                results.push(item);
            }
        }
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
                PortState::Error(e) => {
                    if h.errors.len() < 8 {
                        h.errors.push(format!("TCP {port}: {e}"));
                    }
                }
            }
        }
    }
    if s.services && !h.open.is_empty() {
        let limit = Duration::from_millis(u64::from(s.port_timeout.clamp(500, 5000)));
        let rounds = if s.safe { 6 } else { 12 };
        let slots = Arc::new(Semaphore::new(if s.safe { 1 } else { 8 }));
        let mut tasks = JoinSet::new();
        for &port in h.open.iter().filter(|p| !crate::service::is_ot_port(**p)) {
            let Ok(permit) = slots.clone().acquire_owned().await else {
                break;
            };
            let ctx = ctx.clone();
            tasks.spawn(async move {
                let found = match &ctx.probes {
                    Some(db) => {
                        crate::service::detect(ip, port, limit, db, &ctx.gate, rounds).await
                    }
                    None => None,
                };
                drop(permit);
                (port, found)
            });
        }
        let mut found = vec![];
        while let Some(done) = tasks.join_next().await {
            if let Ok(item) = done {
                found.push(item);
            }
        }
        found.sort_by_key(|(port, _)| *port);
        for (port, outcome) in found {
            match outcome {
                Some(o) => h
                    .identity
                    .extend(crate::service::identity_entries(port, &o)),
                None => note(
                    &mut h,
                    format!("Service detection: port {port} stopped answering"),
                ),
            }
        }
    }
    // JARM: ten extra hellos per port that service detection found to speak TLS. Opt-in, never
    // in Safe Mode, one port at a time, every connection through the rate gate, and never on
    // industrial or printer ports.
    if crate::jarm::enabled(&s) {
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
    if s.udp && !ctx.udp_ports.is_empty() && (h.responding || s.scan_nonresponders) {
        let wait = Duration::from_millis(u64::from(s.port_timeout.clamp(300, 2000)));
        let tries = (s.retries + 1).min(4);
        let slots = Arc::new(Semaphore::new(if s.safe { 2 } else { 16 }));
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
            let Ok(permit) = slots.clone().acquire_owned().await else {
                break;
            };
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
    if wants_ot(&h, &s) {
        crate::ot::identify(&mut h, &s, &ctx.gate).await;
        merge_ot_udp(&mut h);
    }
    if s.trace && h.responding {
        let (hops, notes) = traceroute(ip, &h.open, &s, &ctx).await;
        for text in notes {
            note(&mut h, text);
        }
        h.trace = hops;
    }
    if h.responding && s.dns {
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
        // Closed ports: bind and release, so nothing listens there.
        let closed: Vec<u16> = (0..6)
            .map(|_| {
                let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                l.local_addr().unwrap().port()
            })
            .collect();
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
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
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
            let got = probe_port(ip, port, timeout, &s, &ctx, Some(&rtt)).await;
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
        let plain = probe_port(ip, closed, Duration::from_millis(5000), &s, &ctx, None).await;
        assert_eq!(plain.state, PortState::Closed);
    }

    fn test_ctx() -> Ctx {
        Ctx {
            gate: Arc::new(Gate::unlimited()),
            blocking: Arc::new(Semaphore::new(4)),
            sockets: Arc::new(Semaphore::new(4)),
            dhcp: Semaphore::new(1),
            syn: None,
            syn_error: None,
            arp: None,
            arp_error: None,
            probes: None,
            udp_ports: vec![],
            scripts: None,
        }
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
    }

    #[test]
    fn ot_scan_lists_bacnet_port_in_udp_open() {
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
        drop(run);
        let _ = server.join();
        assert_eq!(
            h.identity.get("BACnet.device_id").map(String::as_str),
            Some("42")
        );
        assert_eq!(h.udp_open, [47808]);
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
