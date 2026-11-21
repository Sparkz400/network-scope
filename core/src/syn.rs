//! SYN scan engine: one capture handle owned by one I/O thread.
//!
//! libpcap handles are not safe for concurrent use, so a single thread both
//! transmits and receives; async callers submit probes and await a reply.
//! Replies are matched on (target, target port, local port) and validated against
//! a sequence cookie, so stray traffic cannot be mistaken for an answer. Each
//! target MAC is resolved once and cached. Unanswered probes are retransmitted
//! with a doubling wait (capped at the port timeout); retransmits go before new
//! probes, and every transmitted SYN takes one token from the scan's shared rate
//! gate. A probe's reply window starts when its SYN actually leaves, so probes
//! waiting for a token are never reported as unanswered.
//!
//! Routed IPv4 targets are sent to the gateway's MAC: the next hop comes from the OS
//! routing table and each next hop's MAC is resolved once. With `syn_adaptive`, reply
//! windows follow a smoothed RTT (RFC 6298) and new probes are limited by an AIMD
//! congestion window; the rate gate still bounds every transmission.
use crate::sendlog::PacketKind;
use crate::{
    capture::Capture,
    core::Gate,
    osfp::TcpFp,
    platform::{HopReply, NextHop},
    rtt::RttEstimator,
    scan::{PortState, Settings},
};
use pnet_packet::{
    MutablePacket, Packet,
    ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::{Ipv4Packet, MutableIpv4Packet},
    tcp::{MutableTcpPacket, TcpFlags, TcpPacket},
};
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, Sender, TryRecvError},
    },
    time::{Duration, Instant},
};
use tokio::sync::{OnceCell, oneshot};

pub type Outcome = (PortState, Option<TcpFp>);
type Reply = oneshot::Sender<Result<Outcome, String>>;
struct Request {
    ip: Ipv4Addr,
    port: u16,
    mac: [u8; 6],
    /// Wait after the first SYN.
    timeout: Duration,
    /// Upper bound for the doubled wait after a retransmit.
    cap: Duration,
    retries: u32,
    reply: Reply,
}
struct Pending {
    cookie: u32,
    mac: [u8; 6],
    /// Transmissions so far; RTT is only sampled from probes sent once (Karn).
    sends: u32,
    first_sent: Option<Instant>,
    /// Wait after the next send; doubles after each send up to `cap`.
    interval: Duration,
    cap: Duration,
    /// End of the reply window of the last send; `None` while waiting in a send queue.
    wait_until: Option<Instant>,
    sends_left: u32,
    queued: bool,
    reply: Reply,
}
type Key = (Ipv4Addr, u16, u16);
type MacResult = Result<[u8; 6], String>;
type HopResult = Result<Ipv4Addr, String>;

/// The link an I/O thread transmits on and reads from (a capture handle in production).
pub(crate) trait Wire {
    fn send(&mut self, frame: &[u8]) -> Result<(), String>;
    fn next(&mut self) -> Result<Option<Vec<u8>>, String>;
}
impl Wire for Capture {
    fn send(&mut self, frame: &[u8]) -> Result<(), String> {
        Capture::send(self, frame)
    }
    fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
        Capture::next(self)
    }
}

type Router = Arc<dyn Fn(Ipv4Addr) -> Result<NextHop, String> + Send + Sync>;
type Neighbors = Arc<dyn Fn(Ipv4Addr) -> Option<String> + Send + Sync>;

pub struct SynEngine {
    tx: Mutex<Sender<Request>>,
    /// Target -> address whose MAC its frames carry (itself, or its gateway).
    hops: Mutex<HashMap<Ipv4Addr, Arc<OnceCell<HopResult>>>>,
    /// Next hop -> MAC, resolved once per next hop (one entry for all routed targets).
    macs: Mutex<HashMap<Ipv4Addr, Arc<OnceCell<MacResult>>>>,
    gate: Arc<Gate>,
    route: Router,
    neighbor: Neighbors,
}

/// Reply-window and congestion settings for the I/O thread.
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    /// Adaptive reply windows and congestion window (`syn_adaptive`).
    pub adaptive: bool,
    /// Lowest reply window an RTT estimate may produce (`minimum_timeout`).
    pub floor: Duration,
}
impl Timing {
    #[cfg(test)]
    pub const FIXED: Timing = Timing {
        adaptive: false,
        floor: Duration::from_millis(1),
    };
    pub fn from_settings(s: &Settings) -> Self {
        Self {
            adaptive: s.syn_adaptive,
            floor: Duration::from_millis(u64::from(s.minimum_timeout.max(1))),
        }
    }
}

/// AIMD congestion window over probes in flight (sent, not yet answered or expired).
///
/// Loss signal: an answer to a probe that had to be retransmitted (the first SYN or
/// its reply was lost). A probe that is never answered is not a loss: that is what a
/// filtered port looks like, and treating it as congestion would stall every scan of
/// a firewalled network. At most one decrease per reply window.
#[derive(Clone, Copy, Debug)]
pub struct Window {
    cwnd: f64,
    ssthresh: f64,
    max: f64,
    last_cut: Option<Instant>,
}
impl Window {
    pub const INITIAL: f64 = 10.0;
    pub const MIN: f64 = 2.0;
    pub fn new(max: usize) -> Self {
        let max = (max as f64).max(Self::MIN);
        Self {
            cwnd: Self::INITIAL.min(max),
            ssthresh: max,
            max,
            last_cut: None,
        }
    }
    pub fn size(&self) -> usize {
        self.cwnd as usize
    }
    pub fn allows(&self, in_flight: usize) -> bool {
        in_flight < self.size()
    }
    /// Additive increase: slow start below the threshold, then about one probe per window.
    pub fn on_answer(&mut self) {
        self.cwnd += if self.cwnd < self.ssthresh {
            1.0
        } else {
            1.0 / self.cwnd
        };
        self.cwnd = self.cwnd.min(self.max);
    }
    /// Multiplicative decrease; returns false when a cut already happened within `hold`.
    pub fn on_loss(&mut self, now: Instant, hold: Duration) -> bool {
        if self.last_cut.is_some_and(|t| now < t + hold) {
            return false;
        }
        self.ssthresh = (self.cwnd / 2.0).max(Self::MIN);
        self.cwnd = self.ssthresh;
        self.last_cut = Some(now);
        true
    }
}

/// Upper bound for the congestion window: the scan's global in-flight bound.
const MAX_WINDOW: usize = 4096;
/// Per-target RTT estimates kept at most; beyond this the map restarts.
const MAX_ESTIMATES: usize = 65_536;

/// Only a target's own estimate replaces the caller's reply window: a fast LAN
/// neighbour must not shorten the window of a slow routed target (its SYN-ACK would
/// arrive after the probe expired). Targets without samples keep the caller's window.
struct Adaptive {
    window: Window,
    per_target: HashMap<Ipv4Addr, RttEstimator>,
}
impl Adaptive {
    fn new() -> Self {
        Self {
            window: Window::new(MAX_WINDOW),
            per_target: HashMap::new(),
        }
    }
    fn rto(&self, ip: Ipv4Addr, floor: Duration, cap: Duration) -> Option<Duration> {
        self.per_target.get(&ip).and_then(|e| e.rto(floor, cap))
    }
    /// `rtt` is a measured sample, or (after a retransmit) the time since the first
    /// send: an upper bound that keeps the backed-off window for a target that slowed
    /// down (Karn's rule forbids treating it as a precise sample, but it may only
    /// lengthen the estimate's reply windows, never shorten them wrongly).
    fn sample(&mut self, ip: Ipv4Addr, rtt: Duration) {
        if self.per_target.len() >= MAX_ESTIMATES && !self.per_target.contains_key(&ip) {
            self.per_target.clear();
        }
        self.per_target.entry(ip).or_default().sample(rtt);
    }
}

fn cookie(secret: u64, ip: Ipv4Addr, port: u16, local: u16) -> u32 {
    let mut x =
        secret ^ (u64::from(u32::from(ip)) << 32) ^ (u64::from(port) << 16) ^ u64::from(local);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    (x ^ (x >> 31)) as u32
}

fn build(
    source: (Ipv4Addr, [u8; 6]),
    dest: (Ipv4Addr, [u8; 6]),
    ports: (u16, u16),
    flags: u8,
    seq: u32,
    ack: u32,
) -> Vec<u8> {
    build_ttl(source, dest, ports, flags, (seq, ack), 64)
}

fn build_ttl(
    source: (Ipv4Addr, [u8; 6]),
    dest: (Ipv4Addr, [u8; 6]),
    ports: (u16, u16),
    flags: u8,
    (seq, ack): (u32, u32),
    ttl: u8,
) -> Vec<u8> {
    // Our SYN advertises the options of a common modern stack so that the target's
    // SYN-ACK reveals its own option set and ordering (used for OS fingerprinting).
    const SYN_OPTIONS: [u8; 20] = [
        2, 4, 5, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7,
    ];
    let tcp_len = if flags & TcpFlags::SYN != 0 { 40 } else { 20 };
    let mut bytes = vec![0u8; 14 + 20 + tcp_len];
    let mut eth = MutableEthernetPacket::new(&mut bytes).unwrap();
    eth.set_destination(dest.1.into());
    eth.set_source(source.1.into());
    eth.set_ethertype(EtherTypes::Ipv4);
    let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
    ip.set_version(4);
    ip.set_header_length(5);
    ip.set_total_length(20 + tcp_len as u16);
    ip.set_flags(pnet_packet::ipv4::Ipv4Flags::DontFragment);
    ip.set_ttl(ttl);
    ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip.set_source(source.0);
    ip.set_destination(dest.0);
    ip.set_checksum(pnet_packet::ipv4::checksum(&ip.to_immutable()));
    let mut tcp = MutableTcpPacket::new(ip.payload_mut()).unwrap();
    tcp.set_source(ports.0);
    tcp.set_destination(ports.1);
    tcp.set_sequence(seq);
    tcp.set_acknowledgement(ack);
    tcp.set_data_offset((tcp_len / 4) as u8);
    tcp.set_flags(flags);
    tcp.set_window(64240);
    if tcp_len > 20 {
        tcp.packet_mut()[20..40].copy_from_slice(&SYN_OPTIONS);
    }
    tcp.set_checksum(pnet_packet::tcp::ipv4_checksum(
        &tcp.to_immutable(),
        &source.0,
        &dest.0,
    ));
    bytes
}

/// Classification of one captured frame against the probe it may answer.
#[derive(Debug, PartialEq)]
pub enum Answer {
    Open { server_seq: u32, fp: TcpFp },
    Closed,
}
pub fn classify(
    frame: &[u8],
    source: Ipv4Addr,
    pending: &HashMap<Key, u32>,
) -> Option<(Key, Answer)> {
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Ipv4 {
        return None;
    }
    let ip = Ipv4Packet::new(eth.payload())?;
    if ip.get_destination() != source || ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp
    {
        return None;
    }
    let tcp = TcpPacket::new(ip.payload())?;
    let key = (ip.get_source(), tcp.get_source(), tcp.get_destination());
    let cookie = *pending.get(&key)?;
    if tcp.get_acknowledgement() != cookie.wrapping_add(1) {
        return None;
    }
    let flags = tcp.get_flags();
    if flags & (TcpFlags::SYN | TcpFlags::ACK) == TcpFlags::SYN | TcpFlags::ACK {
        Some((
            key,
            Answer::Open {
                server_seq: tcp.get_sequence(),
                fp: {
                    let (opts, mss, wscale) = crate::osfp::parse_options(tcp.get_options_raw());
                    TcpFp {
                        window: tcp.get_window(),
                        ttl: ip.get_ttl(),
                        df: ip.get_flags() & pnet_packet::ipv4::Ipv4Flags::DontFragment != 0,
                        mss,
                        wscale,
                        opts,
                    }
                },
            },
        ))
    } else if flags & TcpFlags::RST != 0 {
        Some((key, Answer::Closed))
    } else {
        None
    }
}

impl SynEngine {
    /// Opens the capture on the I/O thread and reports driver errors synchronously.
    /// `gate` is the scan's shared rate limiter: every SYN, including retransmits,
    /// takes one token from it, so the rate is applied exactly once.
    pub fn start(s: &Settings, gate: Arc<Gate>) -> Result<Arc<Self>, String> {
        let source_ip: Ipv4Addr = s
            .source_ip
            .parse()
            .map_err(|_| "Set the interface's source IPv4")?;
        let source_mac = crate::capture::mac(&s.source_mac)?;
        let interface = s.interface.clone();
        let timing = Timing::from_settings(s);
        let (tx, rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel();
        let io_gate = gate.clone();
        let route_interface = interface.clone();
        std::thread::Builder::new()
            .name("syn-engine".into())
            .spawn(move || {
                // Not promiscuous, and the kernel drops everything but TCP to us.
                let filter = crate::capture::syn_filter(source_ip);
                match Capture::open_with(&interface, false, Some(&filter)) {
                    Ok(cap) => {
                        let _ = ready_tx.send(Ok(()));
                        io_loop(cap, rx, (source_ip, source_mac), io_gate, timing);
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        ready_rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| "Capture driver did not start".to_string())??;
        Ok(Self::with_parts(
            tx,
            gate,
            Arc::new(move |ip| crate::platform::next_hop(ip, source_ip, &route_interface)),
            Arc::new(|ip| crate::platform::mac(IpAddr::V4(ip))),
        ))
    }

    fn with_parts(
        tx: Sender<Request>,
        gate: Arc<Gate>,
        route: Router,
        neighbor: Neighbors,
    ) -> Arc<Self> {
        Arc::new(Self {
            tx: Mutex::new(tx),
            hops: Mutex::new(HashMap::new()),
            macs: Mutex::new(HashMap::new()),
            gate,
            route,
            neighbor,
        })
    }

    /// The address whose MAC frames to `ip` carry: `ip` itself when on-link, else
    /// its gateway. Looked up once per target.
    async fn next_hop(&self, ip: Ipv4Addr) -> Result<Ipv4Addr, String> {
        let cell = self
            .hops
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(ip)
            .or_default()
            .clone();
        let route = self.route.clone();
        cell.get_or_init(|| async move {
            tokio::task::spawn_blocking(move || route(ip))
                .await
                .map_err(|e| e.to_string())?
                .map(|hop| hop.l2_address(ip))
        })
        .await
        .clone()
    }

    async fn resolve(&self, ip: Ipv4Addr) -> Result<[u8; 6], String> {
        let l2 = self.next_hop(ip).await?;
        let cell = self
            .macs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(l2)
            .or_default()
            .clone();
        let gate = self.gate.clone();
        let neighbor = self.neighbor.clone();
        cell.get_or_init(|| async move {
            // A neighbor lookup can emit an ARP request, so it takes a token too.
            gate.wait_for(PacketKind::NeighborLookup, "OS neighbor lookup")
                .await;
            let text = tokio::task::spawn_blocking(move || neighbor(l2))
                .await
                .ok()
                .flatten()
                .ok_or_else(|| {
                    if l2 == ip {
                        "No ARP answer from the target".to_string()
                    } else {
                        format!("No ARP answer from gateway {l2}")
                    }
                })?;
            crate::capture::mac(&text)
        })
        .await
        .clone()
    }

    /// Probes one port. The first SYN waits `timeout`; each retransmit doubles the
    /// wait up to `cap`. Rate limiting happens on the I/O thread, not here.
    pub async fn probe(
        &self,
        ip: IpAddr,
        port: u16,
        timeout: Duration,
        cap: Duration,
        retries: u32,
    ) -> Result<Outcome, String> {
        let IpAddr::V4(ip) = ip else {
            return Err("SYN currently requires local IPv4".into());
        };
        let mac = self.resolve(ip).await?;
        let (reply, answer) = oneshot::channel();
        self.tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .send(Request {
                ip,
                port,
                mac,
                timeout,
                cap: cap.max(timeout),
                retries: retries.min(5),
                reply,
            })
            .map_err(|_| "SYN engine stopped")?;
        answer.await.map_err(|_| "SYN engine stopped".to_string())?
    }
}

/// Pops the next key that is still waiting to be sent: retransmits first, then new probes.
/// New probes are skipped when `fresh_allowed` is false (congestion window full).
fn next_queued(
    retransmit: &mut VecDeque<Key>,
    fresh: &mut VecDeque<Key>,
    pending: &HashMap<Key, Pending>,
    fresh_allowed: bool,
) -> Option<Key> {
    let queues = if fresh_allowed {
        vec![retransmit, fresh]
    } else {
        vec![retransmit]
    };
    for queue in queues {
        while let Some(&key) = queue.front() {
            // A closed reply channel means the caller was aborted (Stop): never send.
            if pending
                .get(&key)
                .is_some_and(|p| p.queued && !p.reply.is_closed())
            {
                return Some(key);
            }
            // Answered, failed, abandoned or already sent through the other queue.
            queue.pop_front();
        }
    }
    None
}

fn io_loop<W: Wire>(
    mut wire: W,
    rx: Receiver<Request>,
    source: (Ipv4Addr, [u8; 6]),
    gate: Arc<Gate>,
    timing: Timing,
) {
    let mut adaptive = timing.adaptive.then(Adaptive::new);
    // Probes sent at least once and not yet answered, expired or dropped.
    let mut in_flight = 0usize;
    let secret = new_secret();
    let mut next_local: u32 = 0;
    let mut pending: HashMap<Key, Pending> = HashMap::new();
    let mut cookies: HashMap<Key, u32> = HashMap::new();
    let mut fresh: VecDeque<Key> = VecDeque::new();
    let mut retransmit: VecDeque<Key> = VecDeque::new();
    let mut next_sweep = Instant::now();
    let mut open = true;
    let fail_all = |pending: &mut HashMap<Key, Pending>, e: String| {
        for (_, p) in pending.drain() {
            let _ = p.reply.send(Err(e.clone()));
        }
    };
    while open || !pending.is_empty() {
        let mut busy = false;
        for _ in 0..512 {
            match rx.try_recv() {
                Ok(r) => {
                    busy = true;
                    let local = 49152 + (next_local % 16384) as u16;
                    next_local = next_local.wrapping_add(1);
                    let key = (r.ip, r.port, local);
                    let c = cookie(secret, r.ip, r.port, local);
                    cookies.insert(key, c);
                    pending.insert(
                        key,
                        Pending {
                            cookie: c,
                            mac: r.mac,
                            sends: 0,
                            first_sent: None,
                            interval: r.timeout,
                            cap: r.cap.max(r.timeout),
                            wait_until: None,
                            sends_left: r.retries + 1,
                            queued: true,
                            reply: r.reply,
                        },
                    );
                    fresh.push_back(key);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    open = false;
                    break;
                }
            }
        }
        loop {
            let fresh_allowed = adaptive.as_ref().is_none_or(|a| a.window.allows(in_flight));
            let Some(key) = next_queued(&mut retransmit, &mut fresh, &pending, fresh_allowed)
            else {
                break;
            };
            // One token per transmitted SYN; a refused token leaves the probe queued
            // (its reply window has not started, so it cannot expire meanwhile).
            if gate.try_take_for(PacketKind::TcpSyn, "port scan").is_err() {
                break;
            }
            let Some(p) = pending.get_mut(&key) else {
                continue;
            };
            let frame = build(
                source,
                (key.0, p.mac),
                (key.2, key.1),
                TcpFlags::SYN,
                p.cookie,
                0,
            );
            if let Err(e) = wire.send(&frame) {
                if let Some(p) = pending.remove(&key) {
                    if p.sends > 0 {
                        in_flight -= 1;
                    }
                    let _ = p.reply.send(Err(e));
                }
                cookies.remove(&key);
                continue;
            }
            busy = true;
            let now = Instant::now();
            if p.sends == 0 {
                in_flight += 1;
                p.first_sent = Some(now);
                if let Some(rto) = adaptive
                    .as_ref()
                    .and_then(|a| a.rto(key.0, timing.floor, p.cap))
                {
                    p.interval = rto;
                }
            }
            p.sends += 1;
            p.sends_left -= 1;
            p.queued = false;
            p.wait_until = Some(now + p.interval);
            p.interval = (p.interval * 2).min(p.cap);
        }
        for _ in 0..512 {
            match wire.next() {
                Ok(Some(frame)) => {
                    busy = true;
                    if let Some((key, answer)) = classify(&frame, source.0, &cookies) {
                        let Some(p) = pending.remove(&key) else {
                            continue;
                        };
                        cookies.remove(&key);
                        if p.sends > 0 {
                            in_flight -= 1;
                        }
                        if let Some(a) = adaptive.as_mut() {
                            let now = Instant::now();
                            let since_first = p.first_sent.map(|t| now - t);
                            match (p.sends, since_first) {
                                (1, Some(rtt)) => {
                                    a.sample(key.0, rtt);
                                    a.window.on_answer();
                                }
                                (_, upper_bound) => {
                                    // Answered only after a retransmit: loss, and an
                                    // upper-bound sample that keeps the window long.
                                    if let Some(bound) = upper_bound {
                                        a.sample(key.0, bound);
                                    }
                                    let hold = a.rto(key.0, timing.floor, p.cap).unwrap_or(p.cap);
                                    a.window.on_loss(now, hold);
                                }
                            }
                        }
                        let state = match answer {
                            Answer::Open { server_seq, fp } => {
                                let rst = build(
                                    source,
                                    (key.0, p.mac),
                                    (key.2, key.1),
                                    TcpFlags::RST | TcpFlags::ACK,
                                    p.cookie.wrapping_add(1),
                                    server_seq.wrapping_add(1),
                                );
                                gate.note(PacketKind::TcpSyn, "RST closing a half-open connection");
                                let _ = wire.send(&rst);
                                (PortState::Open, Some(fp))
                            }
                            Answer::Closed => (PortState::Closed, None),
                        };
                        let _ = p.reply.send(Ok(state));
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    fail_all(&mut pending, e);
                    return;
                }
            }
        }
        let now = Instant::now();
        if now >= next_sweep {
            next_sweep = now + Duration::from_millis(5);
            // Probes whose caller is gone (Stop aborts host tasks) are dropped, so no
            // queued SYN or retransmit leaves after the scan was stopped.
            pending.retain(|key, p| {
                let keep = !p.reply.is_closed();
                if !keep {
                    cookies.remove(key);
                    if p.sends > 0 {
                        in_flight -= 1;
                    }
                }
                keep
            });
            let mut expired = vec![];
            for (key, p) in pending.iter_mut() {
                // Queued probes have no running reply window and never expire.
                let Some(until) = p.wait_until else { continue };
                if now < until {
                    continue;
                }
                if p.sends_left > 0 {
                    p.queued = true;
                    p.wait_until = None;
                    retransmit.push_back(*key);
                } else {
                    expired.push(*key);
                }
            }
            for key in expired {
                if let Some(p) = pending.remove(&key) {
                    in_flight -= 1;
                    // No answer is not a loss signal (filtered ports look like this);
                    // the probe has left the network, so the window may grow, and a
                    // silent range is not held at the initial window.
                    if let Some(a) = adaptive.as_mut() {
                        a.window.on_answer();
                    }
                    let _ = p.reply.send(Ok((PortState::Unanswered, None)));
                }
                cookies.remove(&key);
            }
        }
        if !busy {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// Takes one rate-gate token, sleeping until one is available (blocking callers).
fn take_blocking(gate: &Gate, kind: PacketKind, detail: &str) {
    while let Err(wait) = gate.try_take_for(kind, detail) {
        std::thread::sleep(wait.min(Duration::from_millis(20)));
    }
}

fn new_secret() -> u64 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(1);
    t ^ (u64::from(std::process::id()) << 40)
}

/// Kernel filter for TCP traceroute: ICMP errors from routers and the target's TCP answer.
pub fn trace_filter(source: Ipv4Addr) -> String {
    format!("(icmp or tcp) and dst host {source}")
}

/// TTLs probed at once. The next wave only starts when the target did not answer, so
/// at most this many SYNs reach the target port (all TTLs at or beyond the path
/// length land on it).
pub const TRACE_WAVE: u8 = 3;

/// One TCP traceroute probe's answer.
#[derive(Debug, PartialEq)]
struct TraceAnswer {
    ttl: u8,
    from: Ipv4Addr,
    reached: bool,
    /// The target's sequence number when it answered with a SYN-ACK (needs a RST).
    syn_ack: Option<u32>,
}

/// Probe identity of a TCP traceroute: the local port is `base + ttl`, the sequence
/// number a cookie over (target, port, local port).
#[derive(Clone, Copy)]
struct TraceProbe {
    source: Ipv4Addr,
    dest: Ipv4Addr,
    port: u16,
    base: u16,
    hops: u8,
    secret: u64,
}
impl TraceProbe {
    fn seq(&self, ttl: u8) -> u32 {
        cookie(
            self.secret,
            self.dest,
            self.port,
            self.base + u16::from(ttl),
        )
    }
    fn ttl_of(&self, local: u16) -> Option<u8> {
        let ttl = local.checked_sub(self.base)?;
        (1..=u16::from(self.hops))
            .contains(&ttl)
            .then_some(ttl as u8)
    }
    /// Time Exceeded / Unreachable quoting one of our SYNs, or the target's own answer.
    fn classify(&self, frame: &[u8]) -> Option<TraceAnswer> {
        let eth = EthernetPacket::new(frame)?;
        if eth.get_ethertype() != EtherTypes::Ipv4 {
            return None;
        }
        let ip = Ipv4Packet::new(eth.payload())?;
        if ip.get_destination() != self.source {
            return None;
        }
        let from = ip.get_source();
        match ip.get_next_level_protocol() {
            IpNextHeaderProtocols::Icmp => {
                let icmp = ip.payload();
                if icmp.len() < 8 || !matches!(icmp[0], 3 | 11) {
                    return None;
                }
                let inner = Ipv4Packet::new(&icmp[8..])?;
                let header = usize::from(inner.get_header_length()) * 4;
                if header < 20
                    || inner.get_next_level_protocol() != IpNextHeaderProtocols::Tcp
                    || inner.get_source() != self.source
                    || inner.get_destination() != self.dest
                {
                    return None;
                }
                // Routers quote at least the first 8 bytes: ports and sequence number.
                let tcp = icmp.get(8 + header..8 + header + 8)?;
                let ttl = self.ttl_of(u16::from_be_bytes([tcp[0], tcp[1]]))?;
                let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
                if u16::from_be_bytes([tcp[2], tcp[3]]) != self.port || seq != self.seq(ttl) {
                    return None;
                }
                Some(TraceAnswer {
                    ttl,
                    from,
                    reached: icmp[0] == 3 && from == self.dest,
                    syn_ack: None,
                })
            }
            IpNextHeaderProtocols::Tcp if from == self.dest => {
                let tcp = TcpPacket::new(ip.payload())?;
                let ttl = self.ttl_of(tcp.get_destination())?;
                if tcp.get_source() != self.port
                    || tcp.get_acknowledgement() != self.seq(ttl).wrapping_add(1)
                {
                    return None;
                }
                let flags = tcp.get_flags();
                let syn_ack =
                    flags & (TcpFlags::SYN | TcpFlags::ACK) == TcpFlags::SYN | TcpFlags::ACK;
                (syn_ack || flags & TcpFlags::RST != 0).then(|| TraceAnswer {
                    ttl,
                    from,
                    reached: true,
                    syn_ack: syn_ack.then(|| tcp.get_sequence()),
                })
            }
            _ => None,
        }
    }
}

/// Sends TTL-limited SYNs in ascending waves of [`TRACE_WAVE`] and stops after the
/// wave in which the target answered. Every SYN takes a rate-gate token.
fn trace_loop<W: Wire>(
    wire: &mut W,
    probe: TraceProbe,
    macs: ([u8; 6], [u8; 6]),
    timeout: Duration,
    gate: &Gate,
) -> Result<Vec<(u8, HopReply)>, String> {
    let (source, dest) = ((probe.source, macs.0), (probe.dest, macs.1));
    let mut replies = vec![];
    let mut first = 1u8;
    while first <= probe.hops {
        let last = first.saturating_add(TRACE_WAVE - 1).min(probe.hops);
        let mut sent_at = HashMap::new();
        for ttl in first..=last {
            take_blocking(gate, PacketKind::Traceroute, "TCP SYN, TTL sweep");
            let local = probe.base + u16::from(ttl);
            wire.send(&build_ttl(
                source,
                dest,
                (local, probe.port),
                TcpFlags::SYN,
                (probe.seq(ttl), 0),
                ttl,
            ))?;
            sent_at.insert(ttl, Instant::now());
        }
        let deadline = Instant::now() + timeout;
        let mut answered: HashMap<u8, HopReply> = HashMap::new();
        while answered.len() < sent_at.len() && Instant::now() < deadline {
            let Some(frame) = wire.next()? else {
                std::thread::sleep(Duration::from_millis(1));
                continue;
            };
            let Some(a) = probe.classify(&frame) else {
                continue;
            };
            if let Some(server_seq) = a.syn_ack {
                // Close the half-open connection, as the SYN engine does.
                let local = probe.base + u16::from(a.ttl);
                gate.note(PacketKind::TcpSyn, "RST closing a half-open connection");
                wire.send(&build(
                    source,
                    dest,
                    (local, probe.port),
                    TcpFlags::RST | TcpFlags::ACK,
                    probe.seq(a.ttl).wrapping_add(1),
                    server_seq.wrapping_add(1),
                ))?;
            }
            let Some(sent) = sent_at.get(&a.ttl) else {
                continue;
            };
            answered.entry(a.ttl).or_insert(HopReply {
                ip: Some(IpAddr::V4(a.from)),
                rtt: Some(sent.elapsed().as_millis() as u32),
                reached: a.reached,
            });
        }
        let reached = answered.values().any(|r| r.reached);
        for ttl in first..=last {
            replies.push((ttl, answered.remove(&ttl).unwrap_or_default()));
        }
        if reached {
            break;
        }
        first = last + 1;
    }
    Ok(replies)
}

/// TCP SYN traceroute to `ip:port` through the capture interface (needs Npcap or
/// libpcap). Routed targets are sent to the gateway's MAC. The caller picks a port
/// that passed [`crate::trace::trace_port_allowed`]; it is checked again here.
pub fn tcp_trace(
    s: &Settings,
    ip: Ipv4Addr,
    port: u16,
    max_hops: u8,
    timeout_ms: u32,
    gate: &Gate,
) -> Result<Vec<(u8, HopReply)>, String> {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT_BASE: AtomicU16 = AtomicU16::new(0);
    if !crate::trace::trace_port_allowed(port) {
        return Err(format!(
            "TCP traceroute never targets OT or printer port {port}"
        ));
    }
    let source_ip: Ipv4Addr = s
        .source_ip
        .parse()
        .map_err(|_| "Set the interface's source IPv4")?;
    let source_mac = crate::capture::mac(&s.source_mac)?;
    let l2 = crate::platform::next_hop(ip, source_ip, &s.interface)?.l2_address(ip);
    // The neighbor lookup can emit an ARP request.
    take_blocking(gate, PacketKind::NeighborLookup, "OS neighbor lookup");
    let dest_mac = crate::platform::mac(IpAddr::V4(l2))
        .ok_or_else(|| format!("No ARP answer from next hop {l2}"))
        .and_then(|m| crate::capture::mac(&m))?;
    let mut cap = Capture::open_with(&s.interface, false, Some(&trace_filter(source_ip)))?;
    // Local ports 40001-49023, below the SYN engine's 49152-65535.
    let base = 40_000 + (NEXT_BASE.fetch_add(1, Ordering::Relaxed) % 140) * 64;
    let probe = TraceProbe {
        source: source_ip,
        dest: ip,
        port,
        base,
        hops: max_hops.clamp(1, 64),
        secret: new_secret(),
    };
    trace_loop(
        &mut cap,
        probe,
        (source_mac, dest_mac),
        Duration::from_millis(u64::from(timeout_ms.max(1))),
        gate,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
        flags: u8,
        seq: u32,
        ack: u32,
    ) -> Vec<u8> {
        build(
            (src, [2; 6]),
            (dst, [3; 6]),
            (sport, dport),
            flags,
            seq,
            ack,
        )
        .to_vec()
    }

    #[test]
    fn cookie_depends_on_every_field() {
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let base = cookie(7, ip, 80, 50000);
        assert_eq!(base, cookie(7, ip, 80, 50000));
        assert_ne!(base, cookie(8, ip, 80, 50000));
        assert_ne!(base, cookie(7, Ipv4Addr::new(10, 0, 0, 2), 80, 50000));
        assert_ne!(base, cookie(7, ip, 81, 50000));
        assert_ne!(base, cookie(7, ip, 80, 50001));
    }

    #[test]
    fn replies_are_matched_by_key_and_cookie() {
        let me = Ipv4Addr::new(10, 0, 0, 9);
        let target = Ipv4Addr::new(10, 0, 0, 1);
        let mut pending = HashMap::new();
        pending.insert((target, 80, 50000), 1000u32);
        let synack = frame(
            target,
            me,
            80,
            50000,
            TcpFlags::SYN | TcpFlags::ACK,
            5,
            1001,
        );
        let (key, answer) = classify(&synack, me, &pending).unwrap();
        assert_eq!(key, (target, 80, 50000));
        let Answer::Open { server_seq, fp } = answer else {
            panic!("expected open")
        };
        assert_eq!(server_seq, 5);
        assert_eq!(
            fp,
            TcpFp {
                window: 64240,
                ttl: 64,
                df: true,
                mss: Some(1460),
                wscale: Some(7),
                opts: "M,S,T,N,W".into()
            }
        );
        let rst = frame(
            target,
            me,
            80,
            50000,
            TcpFlags::RST | TcpFlags::ACK,
            0,
            1001,
        );
        assert_eq!(classify(&rst, me, &pending).unwrap().1, Answer::Closed);
        let wrong_ack = frame(target, me, 80, 50000, TcpFlags::SYN | TcpFlags::ACK, 5, 999);
        assert_eq!(classify(&wrong_ack, me, &pending), None);
        let wrong_port = frame(
            target,
            me,
            81,
            50000,
            TcpFlags::SYN | TcpFlags::ACK,
            5,
            1001,
        );
        assert_eq!(classify(&wrong_port, me, &pending), None);
        let other_host = frame(
            Ipv4Addr::new(10, 0, 0, 2),
            me,
            80,
            50000,
            TcpFlags::SYN | TcpFlags::ACK,
            5,
            1001,
        );
        assert_eq!(classify(&other_host, me, &pending), None);
        let not_for_me = frame(
            target,
            Ipv4Addr::new(10, 0, 0, 8),
            80,
            50000,
            TcpFlags::SYN | TcpFlags::ACK,
            5,
            1001,
        );
        assert_eq!(classify(&not_for_me, me, &pending), None);
        assert_eq!(classify(&synack[..20], me, &pending), None);
    }

    type Sent = Arc<Mutex<Vec<(Instant, u8, u16)>>>;
    /// Records every transmitted frame (time, TCP flags, target port); optionally
    /// answers SYNs to `open_port` with a SYN-ACK.
    struct FakeWire {
        sent: Sent,
        open_port: Option<u16>,
        inbox: VecDeque<Vec<u8>>,
    }
    impl Wire for FakeWire {
        fn send(&mut self, frame: &[u8]) -> Result<(), String> {
            let eth = EthernetPacket::new(frame).unwrap();
            let ip = Ipv4Packet::new(eth.payload()).unwrap();
            let tcp = TcpPacket::new(ip.payload()).unwrap();
            self.sent.lock().unwrap().push((
                Instant::now(),
                tcp.get_flags(),
                tcp.get_destination(),
            ));
            if tcp.get_flags() == TcpFlags::SYN && Some(tcp.get_destination()) == self.open_port {
                self.inbox.push_back(build(
                    (ip.get_destination(), [3; 6]),
                    (ip.get_source(), [2; 6]),
                    (tcp.get_destination(), tcp.get_source()),
                    TcpFlags::SYN | TcpFlags::ACK,
                    77,
                    tcp.get_sequence().wrapping_add(1),
                ));
            }
            Ok(())
        }
        fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
            Ok(self.inbox.pop_front())
        }
    }

    const ME: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
    const TARGET: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

    fn engine(gate: Gate, open_port: Option<u16>) -> (Sender<Request>, Sent) {
        let sent: Sent = Arc::default();
        let wire = FakeWire {
            sent: sent.clone(),
            open_port,
            inbox: VecDeque::new(),
        };
        let (tx, rx) = mpsc::channel();
        let gate = Arc::new(gate);
        std::thread::spawn(move || io_loop(wire, rx, (ME, [2; 6]), gate, Timing::FIXED));
        (tx, sent)
    }

    fn submit(
        tx: &Sender<Request>,
        port: u16,
        timeout_ms: u64,
        cap_ms: u64,
        retries: u32,
    ) -> oneshot::Receiver<Result<Outcome, String>> {
        let (reply, answer) = oneshot::channel();
        tx.send(Request {
            ip: TARGET,
            port,
            mac: [3; 6],
            timeout: Duration::from_millis(timeout_ms),
            cap: Duration::from_millis(cap_ms),
            retries,
            reply,
        })
        .unwrap();
        answer
    }

    fn syns(sent: &Sent, port: u16) -> Vec<Instant> {
        sent.lock()
            .unwrap()
            .iter()
            .filter(|(_, flags, p)| *flags == TcpFlags::SYN && *p == port)
            .map(|(t, _, _)| *t)
            .collect()
    }

    #[test]
    fn rate_limited_probes_are_sent_before_they_can_expire() {
        // 20 probes at 200 SYN/s take ~100 ms to leave; each waits only 10 ms. The
        // reply window must start at the actual send, not at submission.
        let (tx, sent) = engine(Gate::per_second(200.0, 1.0), None);
        let answers: Vec<_> = (1..=20).map(|p| submit(&tx, p, 10, 10, 0)).collect();
        for a in answers {
            assert_eq!(a.blocking_recv().unwrap().unwrap().0, PortState::Unanswered);
        }
        for port in 1..=20 {
            assert_eq!(syns(&sent, port).len(), 1, "port {port} sent exactly once");
        }
        let times: Vec<Instant> = sent.lock().unwrap().iter().map(|s| s.0).collect();
        let span = *times.last().unwrap() - times[0];
        assert!(
            span >= Duration::from_millis(85),
            "rate respected: {span:?}"
        );
    }

    #[test]
    fn retransmit_waits_double_up_to_the_cap() {
        let (tx, sent) = engine(Gate::unlimited(), None);
        let doubling = submit(&tx, 1, 40, 1000, 2);
        // Capped at 300 ms; doubling would wait 600 ms. The wide margin keeps the check true on a
        // machine whose timers are coarse (a background process on Windows 11 saw 1 ms sleeps
        // stretched by up to 260 ms).
        let capped = submit(&tx, 2, 300, 300, 2);
        assert_eq!(
            doubling.blocking_recv().unwrap().unwrap().0,
            PortState::Unanswered
        );
        capped.blocking_recv().unwrap().unwrap();
        let d = syns(&sent, 1);
        assert_eq!(d.len(), 3);
        let (g1, g2) = (d[1] - d[0], d[2] - d[1]);
        assert!(g1 >= Duration::from_millis(40), "{g1:?}");
        assert!(
            g2 >= Duration::from_millis(80),
            "second wait doubles: {g2:?}"
        );
        let c = syns(&sent, 2);
        assert_eq!(c.len(), 3);
        let g2 = c[2] - c[1];
        assert!(
            g2 >= Duration::from_millis(300) && g2 < Duration::from_millis(570),
            "wait capped at the port timeout: {g2:?}"
        );
    }

    #[test]
    fn retransmits_go_before_new_probes() {
        let (tx, sent) = engine(Gate::per_second(100.0, 1.0), None);
        let first = submit(&tx, 1000, 5, 5, 1);
        std::thread::sleep(Duration::from_millis(3));
        let rest: Vec<_> = (1..=10).map(|p| submit(&tx, p, 20, 20, 0)).collect();
        first.blocking_recv().unwrap().unwrap();
        for r in rest {
            r.blocking_recv().unwrap().unwrap();
        }
        let order: Vec<u16> = sent.lock().unwrap().iter().map(|s| s.2).collect();
        let resend = order.iter().rposition(|p| *p == 1000).unwrap();
        assert!(
            resend <= 3,
            "retransmit queued behind new probes: {order:?}"
        );
        assert_eq!(order.len(), 12);
    }

    #[test]
    fn stopped_probes_are_never_sent() {
        // 20 probes behind a 20/s gate; the caller is aborted after the first sends.
        let (tx, sent) = engine(Gate::per_second(20.0, 1.0), None);
        let start = std::time::Instant::now();
        let answers: Vec<_> = (1..=20).map(|p| submit(&tx, p, 1000, 1000, 2)).collect();
        std::thread::sleep(Duration::from_millis(60));
        drop(answers);
        // Sends before the stop are limited by the 20/s gate (burst 1); slow CI runners
        // oversleep, so the bound follows the time that really passed.
        let allowed = 2 + (start.elapsed().as_secs_f64() * 20.0).ceil() as usize;
        std::thread::sleep(Duration::from_millis(30));
        let after_stop = sent.lock().unwrap().len();
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(sent.lock().unwrap().len(), after_stop, "SYNs kept leaving");
        assert!(
            after_stop <= allowed,
            "{after_stop} sent, at most {allowed} allowed"
        );
    }

    #[test]
    fn syn_ack_reports_open_and_resets() {
        let (tx, sent) = engine(Gate::unlimited(), Some(502));
        let open = submit(&tx, 502, 500, 500, 1);
        let (state, fp) = open.blocking_recv().unwrap().unwrap();
        assert_eq!(state, PortState::Open);
        assert!(fp.is_some());
        let log = sent.lock().unwrap().clone();
        assert_eq!(log.len(), 2, "one SYN and one RST: {log:?}");
        assert_eq!(log[1].1, TcpFlags::RST | TcpFlags::ACK);
    }

    #[test]
    fn congestion_window_is_aimd() {
        let t0 = Instant::now();
        let hold = Duration::from_millis(100);
        let mut w = Window::new(MAX_WINDOW);
        assert_eq!(w.size(), 10);
        assert!(w.allows(9) && !w.allows(10));
        for _ in 0..6 {
            w.on_answer();
        }
        assert_eq!(w.size(), 16, "slow start: +1 per answer");
        assert!(w.on_loss(t0, hold));
        assert_eq!(w.size(), 8, "halved");
        assert!(
            !w.on_loss(t0 + Duration::from_millis(50), hold),
            "one cut per window"
        );
        assert_eq!(w.size(), 8);
        for _ in 0..7 {
            w.on_answer();
        }
        assert_eq!(w.size(), 8, "congestion avoidance: not +1 per answer");
        w.on_answer();
        w.on_answer();
        assert_eq!(w.size(), 9, "congestion avoidance: about +1 per window");
        assert!(w.on_loss(t0 + Duration::from_millis(150), hold));
        for i in 0..10 {
            w.on_loss(t0 + hold * (i + 3), hold);
        }
        assert_eq!(w.size(), 2, "never below the minimum");
        let mut small = Window::new(4);
        for _ in 0..100 {
            small.on_answer();
        }
        assert_eq!(small.size(), 4, "never above the in-flight bound");
    }

    fn adaptive_engine(open_port: Option<u16>, floor_ms: u64) -> (Sender<Request>, Sent) {
        let sent: Sent = Arc::default();
        let wire = FakeWire {
            sent: sent.clone(),
            open_port,
            inbox: VecDeque::new(),
        };
        let (tx, rx) = mpsc::channel();
        let timing = Timing {
            adaptive: true,
            floor: Duration::from_millis(floor_ms),
        };
        let gate = Arc::new(Gate::unlimited());
        std::thread::spawn(move || io_loop(wire, rx, (ME, [2; 6]), gate, timing));
        (tx, sent)
    }

    #[test]
    fn adaptive_reply_window_follows_measured_rtt() {
        let (tx, _sent) = adaptive_engine(Some(502), 40);
        let open = submit(&tx, 502, 2000, 2000, 0);
        assert_eq!(open.blocking_recv().unwrap().unwrap().0, PortState::Open);
        // The target answered within microseconds: a silent port now expires after
        // the minimum timeout, not after the 2 s port timeout.
        let started = Instant::now();
        let silent = submit(&tx, 7, 2000, 2000, 0);
        assert_eq!(
            silent.blocking_recv().unwrap().unwrap().0,
            PortState::Unanswered
        );
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(40) && waited < Duration::from_millis(1000),
            "{waited:?}"
        );
    }

    #[test]
    fn adaptive_window_limits_new_probes_in_flight() {
        let (tx, sent) = adaptive_engine(None, 1);
        // No probe can expire (and free a slot) within its 1 s timeout, so waiting for the
        // initial window to fill is safe even on a loaded machine (a fixed 120 ms sleep under a
        // 300 ms timeout failed there).
        let answers: Vec<_> = (1..=25).map(|p| submit(&tx, p, 1000, 1000, 0)).collect();
        let deadline = Instant::now() + Duration::from_millis(900);
        while sent.lock().unwrap().len() < Window::INITIAL as usize && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            sent.lock().unwrap().len(),
            Window::INITIAL as usize,
            "initial window"
        );
        for a in answers {
            assert_eq!(a.blocking_recv().unwrap().unwrap().0, PortState::Unanswered);
        }
        assert_eq!(sent.lock().unwrap().len(), 25);
    }

    /// Answers every SYN with a SYN-ACK after a per-target delay.
    struct DelayWire {
        delays: Arc<Mutex<HashMap<Ipv4Addr, Duration>>>,
        sent: Arc<Mutex<Vec<(Ipv4Addr, u16)>>>,
        scheduled: Vec<(Instant, Vec<u8>)>,
    }
    impl Wire for DelayWire {
        fn send(&mut self, frame: &[u8]) -> Result<(), String> {
            let eth = EthernetPacket::new(frame).unwrap();
            let ip = Ipv4Packet::new(eth.payload()).unwrap();
            let tcp = TcpPacket::new(ip.payload()).unwrap();
            if tcp.get_flags() != TcpFlags::SYN {
                return Ok(());
            }
            let dest = ip.get_destination();
            self.sent
                .lock()
                .unwrap()
                .push((dest, tcp.get_destination()));
            let delay = self
                .delays
                .lock()
                .unwrap()
                .get(&dest)
                .copied()
                .unwrap_or_default();
            self.scheduled.push((
                Instant::now() + delay,
                build(
                    (dest, [3; 6]),
                    (ip.get_source(), [2; 6]),
                    (tcp.get_destination(), tcp.get_source()),
                    TcpFlags::SYN | TcpFlags::ACK,
                    5,
                    tcp.get_sequence().wrapping_add(1),
                ),
            ));
            Ok(())
        }
        fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
            let now = Instant::now();
            let due = self.scheduled.iter().position(|(t, _)| *t <= now);
            Ok(due.map(|i| self.scheduled.remove(i).1))
        }
    }

    #[test]
    fn adaptive_windows_are_per_target_and_back_off() {
        let fast = TARGET;
        let slow = Ipv4Addr::new(192, 0, 2, 7);
        let delays: Arc<Mutex<HashMap<Ipv4Addr, Duration>>> = Arc::default();
        delays
            .lock()
            .unwrap()
            .insert(slow, Duration::from_millis(150));
        let sent: Arc<Mutex<Vec<(Ipv4Addr, u16)>>> = Arc::default();
        let wire = DelayWire {
            delays: delays.clone(),
            sent: sent.clone(),
            scheduled: vec![],
        };
        let (tx, rx) = mpsc::channel();
        let timing = Timing {
            adaptive: true,
            floor: Duration::from_millis(20),
        };
        std::thread::spawn(move || {
            io_loop(wire, rx, (ME, [2; 6]), Arc::new(Gate::unlimited()), timing)
        });
        let ask = |ip: Ipv4Addr, port: u16, timeout_ms: u64, retries: u32| {
            let (reply, answer) = oneshot::channel();
            tx.send(Request {
                ip,
                port,
                mac: [3; 6],
                timeout: Duration::from_millis(timeout_ms),
                cap: Duration::from_millis(timeout_ms),
                retries,
                reply,
            })
            .unwrap();
            answer.blocking_recv().unwrap().unwrap().0
        };
        let syns_to = |ip: Ipv4Addr, port: u16| {
            sent.lock()
                .unwrap()
                .iter()
                .filter(|s| **s == (ip, port))
                .count()
        };
        // The fast target's estimate (about the 20 ms floor) must not shorten the
        // slow target's window: its SYN-ACK at 150 ms is still accepted.
        assert_eq!(ask(fast, 502, 400, 1), PortState::Open);
        assert_eq!(ask(slow, 80, 400, 1), PortState::Open);
        assert_eq!(syns_to(slow, 80), 1, "no premature retransmit");
        assert_eq!(ask(slow, 81, 400, 1), PortState::Open);
        assert_eq!(syns_to(slow, 81), 1, "own estimate covers its RTT");
        // The fast target slows down: the answer after retransmits still counts.
        delays
            .lock()
            .unwrap()
            .insert(fast, Duration::from_millis(200));
        assert_eq!(ask(fast, 503, 600, 3), PortState::Open);
        assert!(syns_to(fast, 503) > 1);
    }

    #[test]
    fn retransmitted_answers_lengthen_the_estimate() {
        let (floor, cap) = (Duration::from_millis(20), Duration::from_secs(2));
        let ip = Ipv4Addr::new(10, 0, 0, 3);
        let mut a = Adaptive::new();
        assert_eq!(a.rto(ip, floor, cap), None, "no estimate: caller's window");
        a.sample(ip, Duration::from_millis(1));
        assert_eq!(a.rto(ip, floor, cap), Some(floor));
        a.sample(ip, Duration::from_millis(200));
        assert!(a.rto(ip, floor, cap).unwrap() >= Duration::from_millis(200));
        assert_eq!(a.rto(Ipv4Addr::new(10, 0, 0, 4), floor, cap), None);
    }

    #[tokio::test]
    async fn routed_targets_use_one_gateway_mac() {
        let gateway = Ipv4Addr::new(10, 0, 0, 1);
        let lookups: Arc<Mutex<Vec<Ipv4Addr>>> = Arc::default();
        let seen = lookups.clone();
        let (tx, _rx) = mpsc::channel();
        let engine = SynEngine::with_parts(
            tx,
            Arc::new(Gate::unlimited()),
            Arc::new(move |ip: Ipv4Addr| match ip.octets() {
                [10, 0, 0, _] => Ok(NextHop::OnLink),
                [192, 0, 2, _] => Err("No route to 192.0.2.x".into()),
                _ => Ok(NextHop::Gateway(gateway)),
            }),
            Arc::new(move |ip: Ipv4Addr| {
                seen.lock().unwrap().push(ip);
                (ip.octets()[3] != 99).then(|| format!("02:00:00:00:00:{:02x}", ip.octets()[3]))
            }),
        );
        for target in ["8.8.8.8", "1.1.1.1", "172.16.5.5"] {
            assert_eq!(
                engine.resolve(target.parse().unwrap()).await,
                Ok([2, 0, 0, 0, 0, 1]),
                "{target} goes to the gateway"
            );
        }
        assert_eq!(
            engine.resolve(Ipv4Addr::new(10, 0, 0, 7)).await,
            Ok([2, 0, 0, 0, 0, 7])
        );
        assert_eq!(
            *lookups.lock().unwrap(),
            [gateway, Ipv4Addr::new(10, 0, 0, 7)],
            "the gateway MAC is resolved once"
        );
        // Failures are errors, so the caller falls back to TCP connect.
        assert!(engine.resolve(Ipv4Addr::new(192, 0, 2, 1)).await.is_err());
        let silent = engine.resolve(Ipv4Addr::new(10, 0, 0, 99)).await;
        assert!(silent.unwrap_err().contains("target"));
    }

    /// A routed path of `path.len()` hops: SYNs with a smaller TTL are answered with
    /// Time Exceeded by the router at that hop; the rest reach the target (SYN-ACK).
    struct PathWire {
        path: Vec<Ipv4Addr>,
        inbox: VecDeque<Vec<u8>>,
        syns: Vec<u8>,
        rsts: usize,
    }
    fn time_exceeded(router: Ipv4Addr, me: Ipv4Addr, quoted_ip: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[12] = 8;
        let mut icmp = vec![11, 0, 0, 0, 0, 0, 0, 0];
        icmp.extend(&quoted_ip[..28]);
        let total = 20 + icmp.len();
        let mut ip = vec![
            0x45,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            0,
            0,
            0,
            64,
            1,
            0,
            0,
        ];
        ip.extend(router.octets());
        ip.extend(me.octets());
        f.extend(ip);
        f.extend(icmp);
        f
    }
    impl Wire for PathWire {
        fn send(&mut self, frame: &[u8]) -> Result<(), String> {
            let eth = EthernetPacket::new(frame).unwrap();
            let ip = Ipv4Packet::new(eth.payload()).unwrap();
            let tcp = TcpPacket::new(ip.payload()).unwrap();
            if tcp.get_flags() & TcpFlags::RST != 0 {
                self.rsts += 1;
                return Ok(());
            }
            let ttl = ip.get_ttl();
            self.syns.push(ttl);
            let hops = self.path.len();
            if usize::from(ttl) < hops {
                let router = self.path[usize::from(ttl) - 1];
                self.inbox
                    .push_back(time_exceeded(router, ip.get_source(), eth.payload()));
            } else {
                self.inbox.push_back(build(
                    (ip.get_destination(), [3; 6]),
                    (ip.get_source(), [2; 6]),
                    (tcp.get_destination(), tcp.get_source()),
                    TcpFlags::SYN | TcpFlags::ACK,
                    99,
                    tcp.get_sequence().wrapping_add(1),
                ));
            }
            Ok(())
        }
        fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
            Ok(self.inbox.pop_front())
        }
    }

    fn trace_probe(dest: Ipv4Addr, hops: u8) -> TraceProbe {
        TraceProbe {
            source: ME,
            dest,
            port: 443,
            base: 40_000,
            hops,
            secret: 42,
        }
    }

    #[test]
    fn tcp_trace_walks_the_path_in_waves_and_stops_at_the_target() {
        let dest = Ipv4Addr::new(198, 51, 100, 7);
        let routers: Vec<Ipv4Addr> = (1..=4).map(|n| Ipv4Addr::new(10, 0, n, 1)).collect();
        let mut path = routers.clone();
        path.push(dest);
        let mut wire = PathWire {
            path,
            inbox: VecDeque::new(),
            syns: vec![],
            rsts: 0,
        };
        let replies = trace_loop(
            &mut wire,
            trace_probe(dest, 30),
            ([2; 6], [3; 6]),
            Duration::from_millis(200),
            &Gate::unlimited(),
        )
        .unwrap();
        // Waves 1-3 and 4-6: the target answered TTL 5 and 6; nothing beyond is sent.
        assert_eq!(wire.syns, [1, 2, 3, 4, 5, 6]);
        assert_eq!(wire.rsts, 2, "every SYN-ACK is reset");
        let hops = crate::trace::assemble(replies);
        let ips: Vec<_> = hops.iter().map(|h| h.ip).collect();
        let mut expected: Vec<_> = routers.iter().map(|r| Some(IpAddr::V4(*r))).collect();
        expected.push(Some(IpAddr::V4(dest)));
        assert_eq!(ips, expected);
    }

    #[test]
    fn tcp_trace_rate_gate_and_matching() {
        let dest = Ipv4Addr::new(198, 51, 100, 7);
        let mut wire = PathWire {
            path: vec![Ipv4Addr::new(10, 0, 0, 1), dest],
            inbox: VecDeque::new(),
            syns: vec![],
            rsts: 0,
        };
        let started = Instant::now();
        trace_loop(
            &mut wire,
            trace_probe(dest, 8),
            ([2; 6], [3; 6]),
            Duration::from_millis(200),
            &Gate::per_second(20.0, 1.0),
        )
        .unwrap();
        assert_eq!(wire.syns, [1, 2, 3]);
        assert!(started.elapsed() >= Duration::from_millis(90), "rate gate");
        // A Time Exceeded for another trace (other sequence) or target is ignored.
        let probe = trace_probe(dest, 8);
        let syn = build_ttl(
            (ME, [2; 6]),
            (dest, [3; 6]),
            (40_002, 443),
            TcpFlags::SYN,
            (probe.seq(2), 0),
            2,
        );
        let te = time_exceeded(Ipv4Addr::new(10, 0, 0, 1), ME, &syn[14..]);
        assert_eq!(
            probe.classify(&te),
            Some(TraceAnswer {
                ttl: 2,
                from: Ipv4Addr::new(10, 0, 0, 1),
                reached: false,
                syn_ack: None
            })
        );
        let other = TraceProbe {
            secret: 43,
            ..probe
        };
        assert_eq!(other.classify(&te), None, "other trace");
        let elsewhere = trace_probe(Ipv4Addr::new(198, 51, 100, 8), 8);
        assert_eq!(elsewhere.classify(&te), None, "other target");
        let short = TraceProbe { hops: 1, ..probe };
        assert_eq!(short.classify(&te), None, "TTL outside the trace");
        assert_eq!(probe.classify(&te[..40]), None);
        assert_eq!(trace_filter(ME), "(icmp or tcp) and dst host 10.0.0.9");
    }
}
