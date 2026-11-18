//! Bounded async scheduling shared by the desktop, CLI and TUI.
use crate::{
    osfp::TcpFp,
    scan::{Event, Host, PortState, Settings},
    service::ProbeDb,
    syn::SynEngine,
};
use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::Sender,
        Arc, Mutex,
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
}
impl Gate {
    pub fn unlimited() -> Self {
        Self { bucket: None }
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
}

struct Ctx {
    gate: Gate,
    blocking: Arc<Semaphore>,
    sockets: Semaphore,
    dhcp: Semaphore,
    syn: Option<Arc<SynEngine>>,
    syn_error: Option<String>,
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
    let gate = if s.safe {
        Gate::new(s.delay.max(100))
    } else if s.max_rate > 0 {
        let rate = f64::from(s.max_rate);
        Gate::per_second(rate, (rate / 10.0).max(1.0))
    } else {
        Gate::unlimited()
    };
    let probes = if s.services {
        match ProbeDb::load(&s.probe_file) {
            Ok(db) => Some(db),
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
        match SynEngine::start(&s, s.max_rate) {
            Ok(engine) => (Some(engine), None),
            Err(e) => (None, Some(e)),
        }
    } else {
        (None, None)
    };
    let ctx = Arc::new(Ctx {
        gate,
        blocking: Arc::new(Semaphore::new(256)),
        sockets: Semaphore::new(4096),
        dhcp: Semaphore::new(1),
        syn,
        syn_error,
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

async fn probe_port(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    s: &Settings,
    ctx: &Ctx,
) -> PortProbe {
    ctx.gate.wait().await;
    let mut note = ctx
        .syn_error
        .as_ref()
        .map(|e| format!("SYN unavailable; TCP connect fallback: {e}"));
    if let Some(engine) = &ctx.syn {
        match engine.probe(ip, port, timeout, s.retries).await {
            Ok((state, fp)) => {
                return PortProbe {
                    state,
                    note: None,
                    fp,
                }
            }
            Err(e) => note = Some(format!("SYN unavailable; TCP connect fallback: {e}")),
        }
    }
    let _socket = ctx.sockets.acquire().await.ok();
    let cap = timeout.max(Duration::from_millis(u64::from(s.port_timeout)));
    let mut attempt = timeout;
    let mut state = crate::probes::connect(ip, port, attempt).await;
    for _ in 0..s.retries.min(5) {
        if state != PortState::Unanswered {
            break;
        }
        attempt = (attempt * 2).min(cap);
        state = crate::probes::connect(ip, port, attempt).await;
    }
    PortProbe {
        state,
        note,
        fp: None,
    }
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
    if s.arp || s.mac || s.os_detect {
        ctx.gate.wait().await;
        if let Ok(permit) = ctx.blocking.acquire().await {
            h.mac =
                tokio::task::spawn_blocking(move || crate::platform::mac(ip).unwrap_or_default())
                    .await
                    .unwrap_or_default();
            drop(permit);
        }
        h.responding = !h.mac.is_empty();
    }
    let mut rtts = vec![];
    if !s.tcp_only {
        let timeout = s.ping_timeout.clamp(1, 10000);
        let mut echoes = JoinSet::new();
        for _ in 0..s.probes.clamp(1, 10) {
            ctx.gate.wait().await;
            let ctx = ctx.clone();
            echoes.spawn(async move {
                let _permit = ctx.blocking.acquire().await.ok();
                tokio::task::spawn_blocking(move || crate::platform::echo(ip, timeout))
                    .await
                    .ok()
            });
        }
        while let Some(result) = echoes.join_next().await {
            if let Ok(Some(echo)) = result {
                if let Some(rtt) = echo.rtt {
                    rtts.push(rtt);
                    h.ttl = echo.ttl;
                }
                if let Some(e) = echo.error {
                    if !h.errors.contains(&e) {
                        h.errors.push(e);
                    }
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
        for &port in ports.iter() {
            let Ok(permit) = slots.clone().acquire_owned().await else {
                break;
            };
            let (s, ctx) = (s.clone(), ctx.clone());
            probes.spawn(async move {
                let result = probe_port(ip, port, timeout, &s, &ctx).await;
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
        let rounds = if s.safe { 4 } else { 10 };
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
    if s.udp && !ctx.udp_ports.is_empty() && (h.responding || s.scan_nonresponders) {
        let wait = Duration::from_millis(u64::from(s.port_timeout.clamp(300, 2000)));
        let tries = (s.retries + 1).min(4);
        let slots = Arc::new(Semaphore::new(if s.safe { 2 } else { 16 }));
        let mut tasks = JoinSet::new();
        for &port in &ctx.udp_ports {
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
                    if h.mac.is_empty() {
                        if let Some(mac) = r.mac {
                            h.mac = mac;
                        }
                    }
                }
                crate::udp::State::Error(e) => note(&mut h, format!("UDP {port}: {e}")),
                crate::udp::State::Closed | crate::udp::State::NoReply => {}
            }
        }
    }
    if s.ot {
        crate::ot::identify(&mut h, &s, &ctx.gate).await;
    }
    if s.trace && h.responding {
        let timeout = s.ping_timeout.clamp(200, 3000);
        match crate::trace::trace(ip, s.trace_hops, timeout, &ctx.blocking, &ctx.gate).await {
            Ok(hops) => h.trace = hops,
            Err(e) => note(&mut h, format!("Traceroute: {e}")),
        }
    }
    if h.responding && s.dns {
        if let Ok(permit) = ctx.blocking.acquire().await {
            let task = tokio::task::spawn_blocking(move || {
                dns_lookup::lookup_addr(&ip).unwrap_or_default()
            });
            if let Ok(Ok(name)) = tokio::time::timeout(Duration::from_secs(3), task).await {
                h.hostname = name;
            }
            drop(permit);
        }
    }
    if s.os_detect && h.responding {
        analyze(&mut h, fingerprint.as_ref());
    }
    if let Some(scripts) = &ctx.scripts {
        scripts.run_host(&mut h);
    }
    h
}

/// Manufacturer, OS family and device type from everything learned about the host.
fn analyze(h: &mut Host, fp: Option<&TcpFp>) {
    let mut vendor = "";
    if !h.mac.is_empty() && !crate::oui::locally_administered(&h.mac) {
        if let Some(v) = crate::oui::vendor(&h.mac) {
            vendor = v;
            h.identity.insert("mac.vendor".into(), v.to_string());
        }
    }
    let ttl = h.ttl;
    if let Some(g) = crate::osfp::guess(ttl, fp, &h.identity, &h.open, vendor) {
        h.identity.insert("os.guess".into(), g.name.clone());
        h.identity
            .insert("os.confidence".into(), format!("{}%", g.confidence));
        h.identity
            .insert("os.evidence".into(), g.evidence.join("; "));
    }
    if let Some(fp) = fp {
        h.identity
            .insert("os.tcp_fingerprint".into(), fp.describe());
    }
    let os = h.identity.get("os.guess").cloned().unwrap_or_default();
    let hostnames = [h.hostname.clone()];
    let evidence = crate::devices::Evidence {
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
    if let Some((kind, why)) = crate::devices::classify(&evidence) {
        h.identity.insert("device.type".into(), kind);
        h.identity.insert("device.evidence".into(), why);
    }
}
#[cfg(test)]
mod tests {
    use super::*;

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
}
