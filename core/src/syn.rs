// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
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
//!
//! IPv6 targets follow the same design. An on-link target ([`Link::on_link_source`]: link-local,
//! or inside the on-link prefix of one of the capture interface's addresses) is sent to its own
//! MAC; any other target goes through the OS routing table ([`crate::ipv6::route_of`], looked up
//! once per target) and, when the route leaves through the capture interface, to the gateway's
//! MAC from a global or unique-local source ([`Link::routed_source`]). MACs come from the OS
//! neighbour cache of that interface, once per next hop. Everything the engine cannot do (no
//! route, a route through another interface, no suitable source address, our own address, no
//! MAC) is an error before any frame is sent, so the caller falls back to TCP connect.
use crate::sendlog::PacketKind;
use crate::{
    capture::Capture,
    core::Gate,
    ipv6::{Hop6, Link, Route6},
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
    ipv6::{Ipv6Packet, MutableIpv6Packet},
    tcp::{MutableTcpPacket, TcpFlags, TcpPacket},
};
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
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
    ip: IpAddr,
    /// Our address the SYN leaves from: the source IPv4, or the IPv6 address chosen for this
    /// target. Always of the target's family.
    source: IpAddr,
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
    /// [`Request::source`]; the RST of an open port leaves from it too.
    source: IpAddr,
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
/// (target, target port, local port).
type Key = (IpAddr, u16, u16);
/// The sequence cookie of a pending probe and the address it was sent from; a reply must be
/// addressed to exactly that address.
type Cookies = HashMap<Key, (u32, IpAddr)>;
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
/// The OS route to an IPv6 target that is in none of the interface's on-link prefixes.
type Router6 = Arc<dyn Fn(Ipv6Addr) -> Result<Route6, String> + Send + Sync>;
type Route6Result = Result<Route6, String>;
/// The MAC (as text) of an on-link address: a next hop (an on-link target or a gateway).
type Neighbors = Arc<dyn Fn(IpAddr) -> Option<String> + Send + Sync>;

pub struct SynEngine {
    tx: Mutex<Sender<Request>>,
    /// The capture interface's source IPv4 address.
    source: Ipv4Addr,
    /// The capture interface's IPv6 addresses, read when the engine started, or why the engine
    /// sends no IPv6 (the capture driver refused the filter with IPv6 addresses).
    link: Result<Link, String>,
    /// IPv4 target -> address whose MAC its frames carry (itself, or its gateway).
    hops: Mutex<HashMap<Ipv4Addr, Arc<OnceCell<HopResult>>>>,
    /// IPv6 target outside the on-link prefixes -> its OS route.
    routes6: Mutex<HashMap<Ipv6Addr, Arc<OnceCell<Route6Result>>>>,
    /// Next hop -> MAC, resolved once per next hop (one entry for all targets routed through
    /// the same gateway).
    macs: Mutex<HashMap<IpAddr, Arc<OnceCell<MacResult>>>>,
    gate: Arc<Gate>,
    route: Router,
    route6: Router6,
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

/// The per-target cell of a lookup cache. Past [`MAX_ESTIMATES`] targets the cache restarts, so a
/// /8 keeps flat memory; a target looked up again after that is just looked up once more.
fn bounded_cell<K: std::hash::Hash + Eq, V>(
    cache: &Mutex<HashMap<K, Arc<OnceCell<V>>>>,
    key: K,
) -> Arc<OnceCell<V>> {
    let mut map = cache.lock().unwrap_or_else(|e| e.into_inner());
    if map.len() >= MAX_ESTIMATES && !map.contains_key(&key) {
        map.clear();
    }
    map.entry(key).or_default().clone()
}

/// Only a target's own estimate replaces the caller's reply window: a fast LAN
/// neighbour must not shorten the window of a slow routed target (its SYN-ACK would
/// arrive after the probe expired). Targets without samples keep the caller's window.
struct Adaptive {
    window: Window,
    per_target: HashMap<IpAddr, RttEstimator>,
}
impl Adaptive {
    fn new() -> Self {
        Self {
            window: Window::new(MAX_WINDOW),
            per_target: HashMap::new(),
        }
    }
    fn rto(&self, ip: IpAddr, floor: Duration, cap: Duration) -> Option<Duration> {
        self.per_target.get(&ip).and_then(|e| e.rto(floor, cap))
    }
    /// `rtt` is a measured sample, or (after a retransmit) the time since the first
    /// send: an upper bound that keeps the backed-off window for a target that slowed
    /// down (Karn's rule forbids treating it as a precise sample, but it may only
    /// lengthen the estimate's reply windows, never shorten them wrongly).
    fn sample(&mut self, ip: IpAddr, rtt: Duration) {
        if self.per_target.len() >= MAX_ESTIMATES && !self.per_target.contains_key(&ip) {
            self.per_target.clear();
        }
        self.per_target.entry(ip).or_default().sample(rtt);
    }
}

/// The splitmix64 finalizer.
fn mix(mut x: u64) -> u64 {
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

fn cookie(secret: u64, ip: IpAddr, port: u16, local: u16) -> u32 {
    let address = match ip {
        IpAddr::V4(v4) => u64::from(u32::from(v4)) << 32,
        // The upper half is mixed before it is folded in, so that two addresses that differ
        // by the same bits in both halves do not cancel out.
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            mix((bits >> 64) as u64) ^ bits as u64
        }
    };
    mix(secret ^ address ^ (u64::from(port) << 16) ^ u64::from(local)) as u32
}

/// The TCP options of our SYN: those of a common modern stack, so that the target's SYN-ACK
/// reveals its own option set and ordering (used for OS fingerprinting). `mss` is 1460 over
/// IPv4 and 1440 over IPv6 (a 1500-byte MTU less the larger header).
fn syn_options(mss: u16) -> [u8; 20] {
    let [hi, lo] = mss.to_be_bytes();
    [
        2, 4, hi, lo, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7,
    ]
}

/// Fills a TCP header (and the SYN options) into `bytes`; the checksum is left to the caller.
fn fill_tcp(bytes: &mut [u8], ports: (u16, u16), flags: u8, (seq, ack): (u32, u32), mss: u16) {
    let tcp_len = bytes.len();
    let mut tcp = MutableTcpPacket::new(bytes).unwrap();
    tcp.set_source(ports.0);
    tcp.set_destination(ports.1);
    tcp.set_sequence(seq);
    tcp.set_acknowledgement(ack);
    tcp.set_data_offset((tcp_len / 4) as u8);
    tcp.set_flags(flags);
    tcp.set_window(64240);
    if tcp_len > 20 {
        tcp.packet_mut()[20..40].copy_from_slice(&syn_options(mss));
    }
}

fn tcp_len(flags: u8) -> usize {
    if flags & TcpFlags::SYN != 0 { 40 } else { 20 }
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
    let tcp_len = tcp_len(flags);
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
    let segment = ip.payload_mut();
    fill_tcp(segment, ports, flags, (seq, ack), 1460);
    let mut tcp = MutableTcpPacket::new(segment).unwrap();
    tcp.set_checksum(pnet_packet::tcp::ipv4_checksum(
        &tcp.to_immutable(),
        &source.0,
        &dest.0,
    ));
    bytes
}

/// [`build`] over IPv6: Ethernet, an IPv6 header (next header TCP, hop limit 64, no extension
/// headers) and the TCP segment, its checksum over the IPv6 pseudo-header.
fn build6(
    source: (Ipv6Addr, [u8; 6]),
    dest: (Ipv6Addr, [u8; 6]),
    ports: (u16, u16),
    flags: u8,
    seq: u32,
    ack: u32,
) -> Vec<u8> {
    let tcp_len = tcp_len(flags);
    let mut bytes = vec![0u8; 14 + 40 + tcp_len];
    let mut eth = MutableEthernetPacket::new(&mut bytes).unwrap();
    eth.set_destination(dest.1.into());
    eth.set_source(source.1.into());
    eth.set_ethertype(EtherTypes::Ipv6);
    let mut ip = MutableIpv6Packet::new(eth.payload_mut()).unwrap();
    ip.set_version(6);
    // The payload accessor is bounded by this length, so it is set first.
    ip.set_payload_length(tcp_len as u16);
    ip.set_next_header(IpNextHeaderProtocols::Tcp);
    ip.set_hop_limit(64);
    ip.set_source(source.0);
    ip.set_destination(dest.0);
    let segment = ip.payload_mut();
    fill_tcp(segment, ports, flags, (seq, ack), 1440);
    let mut tcp = MutableTcpPacket::new(segment).unwrap();
    tcp.set_checksum(pnet_packet::tcp::ipv6_checksum(
        &tcp.to_immutable(),
        &source.0,
        &dest.0,
    ));
    bytes
}

/// A frame from `source` to `dest` of the same address family ([`build`] or [`build6`]);
/// `None` for mixed families, which the engine never sends.
fn segment(
    source: (IpAddr, [u8; 6]),
    dest: (IpAddr, [u8; 6]),
    ports: (u16, u16),
    flags: u8,
    seq: u32,
    ack: u32,
) -> Option<Vec<u8>> {
    match (source.0, dest.0) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            Some(build((s, source.1), (d, dest.1), ports, flags, seq, ack))
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            Some(build6((s, source.1), (d, dest.1), ports, flags, seq, ack))
        }
        _ => None,
    }
}

/// Classification of one captured frame against the probe it may answer.
#[derive(Debug, PartialEq)]
pub enum Answer {
    Open { server_seq: u32, fp: TcpFp },
    Closed,
}

/// Matches a captured frame (IPv4 or IPv6, untagged Ethernet) to a pending probe: the key
/// (target, ports), the address the probe was sent from and the sequence cookie must all
/// agree. An IPv6 reply with extension headers before TCP is not recognised.
pub fn classify(frame: &[u8], pending: &Cookies) -> Option<(Key, Answer)> {
    let eth = EthernetPacket::new(frame)?;
    match eth.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ip = Ipv4Packet::new(eth.payload())?;
            if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                return None;
            }
            let df = ip.get_flags() & pnet_packet::ipv4::Ipv4Flags::DontFragment != 0;
            let route = (
                IpAddr::V4(ip.get_source()),
                IpAddr::V4(ip.get_destination()),
            );
            answer(
                route,
                ip.get_ttl(),
                df,
                &TcpPacket::new(ip.payload())?,
                pending,
            )
        }
        EtherTypes::Ipv6 => {
            let ip = Ipv6Packet::new(eth.payload())?;
            if ip.get_next_header() != IpNextHeaderProtocols::Tcp {
                return None;
            }
            let route = (
                IpAddr::V6(ip.get_source()),
                IpAddr::V6(ip.get_destination()),
            );
            // IPv6 has no DF bit (routers never fragment); the hop limit stands in for the TTL.
            let tcp = TcpPacket::new(ip.payload())?;
            answer(route, ip.get_hop_limit(), false, &tcp, pending)
        }
        _ => None,
    }
}

/// [`classify`] once the IP header is read: `(from, to)` are its source and destination.
fn answer(
    (from, to): (IpAddr, IpAddr),
    ttl: u8,
    df: bool,
    tcp: &TcpPacket,
    pending: &Cookies,
) -> Option<(Key, Answer)> {
    let key = (from, tcp.get_source(), tcp.get_destination());
    let &(cookie, source) = pending.get(&key)?;
    if to != source || tcp.get_acknowledgement() != cookie.wrapping_add(1) {
        return None;
    }
    let flags = tcp.get_flags();
    if flags & (TcpFlags::SYN | TcpFlags::ACK) == TcpFlags::SYN | TcpFlags::ACK {
        let (opts, mss, wscale) = crate::osfp::parse_options(tcp.get_options_raw());
        Some((
            key,
            Answer::Open {
                server_seq: tcp.get_sequence(),
                fp: TcpFp {
                    window: tcp.get_window(),
                    ttl,
                    df,
                    mss,
                    wscale,
                    opts,
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
        // The interface's IPv6 addresses (none on macOS): read once, nothing is sent.
        let link = crate::ipv6::link_of(&interface, source_ip);
        // Not promiscuous, and the kernel drops everything but TCP to our addresses.
        let filter = crate::capture::syn_filter(source_ip, &link.sources());
        let v4_filter = crate::capture::syn_filter(source_ip, &[]);
        let (tx, rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel();
        let io_gate = gate.clone();
        let route_interface = interface.clone();
        std::thread::Builder::new()
            .name("syn-engine".into())
            .spawn(move || {
                let mut opened =
                    Capture::open_with(&interface, false, Some(&filter)).map(|c| (c, None));
                if filter != v4_filter
                    && let Err(e) = &opened
                {
                    // A driver that refuses the IPv6 terms must not cost the IPv4 SYN scan:
                    // without them, IPv6 targets fall back to TCP connect.
                    let why = format!("the capture filter with IPv6 addresses failed ({e})");
                    opened = Capture::open_with(&interface, false, Some(&v4_filter))
                        .map(|c| (c, Some(why)));
                }
                match opened {
                    Ok((cap, v6_refused)) => {
                        let _ = ready_tx.send(Ok(v6_refused));
                        io_loop(cap, rx, source_mac, io_gate, timing);
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        let v6_refused = ready_rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| "Capture driver did not start".to_string())??;
        let (neighbor_link, route_link) = (link.clone(), link.clone());
        let neighbors = crate::ipv6::NeighborTable::default();
        Ok(Self::with_parts(
            tx,
            gate,
            (source_ip, v6_refused.map_or(Ok(link), Err)),
            (
                Arc::new(move |ip| crate::platform::next_hop(ip, source_ip, &route_interface)),
                Arc::new(move |ip| crate::ipv6::route_of(ip, &route_link)),
            ),
            Arc::new(move |ip| match ip {
                IpAddr::V4(_) => crate::platform::mac(ip),
                IpAddr::V6(v6) => crate::platform::neighbor6(v6, &neighbor_link, &neighbors),
            }),
        ))
    }

    /// `link` is the capture interface's IPv6 side, or why the engine sends no IPv6 at all.
    fn with_parts(
        tx: Sender<Request>,
        gate: Arc<Gate>,
        (source, link): (Ipv4Addr, Result<Link, String>),
        (route, route6): (Router, Router6),
        neighbor: Neighbors,
    ) -> Arc<Self> {
        Arc::new(Self {
            tx: Mutex::new(tx),
            source,
            link,
            hops: Mutex::new(HashMap::new()),
            routes6: Mutex::new(HashMap::new()),
            macs: Mutex::new(HashMap::new()),
            gate,
            route,
            route6,
            neighbor,
        })
    }

    /// Whether this engine may send to `ip` at all, from what is known without a lookup:
    /// always for IPv4 (the route is looked up when the first probe needs it); for IPv6 an
    /// on-link target with its source, or another target when the interface has a global or
    /// unique-local source for it ([`Link::may_reach`]). Nothing is looked up or sent.
    pub fn reaches(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => true,
            IpAddr::V6(v6) => self.link.as_ref().is_ok_and(|l| l.may_reach(v6)),
        }
    }

    /// Whether the IPv6 target `ip` is on-link on this engine's interface (no route needed).
    pub fn on_link(&self, ip: IpAddr) -> bool {
        let IpAddr::V6(v6) = ip else { return false };
        self.link
            .as_ref()
            .is_ok_and(|l| matches!(l.on_link_source(v6), Ok(Some(_))))
    }

    /// Whether the engine has a source address and next hop for `ip` (IPv6: the route lookup
    /// runs, once per target; no MAC lookup and nothing is sent). IPv4: [`SynEngine::reaches`].
    pub async fn has_path(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(_) => true,
            IpAddr::V6(v6) => self.path_v6(v6).await.is_ok(),
        }
    }

    /// The source address of a SYN to the IPv6 target `target` and the next hop whose MAC its
    /// frames carry (the target itself, or its gateway). On-link targets need no route; for
    /// the others a global or unique-local source must exist before the route is looked up,
    /// and the route must leave through the capture interface.
    async fn path_v6(&self, target: Ipv6Addr) -> Result<(Ipv6Addr, Ipv6Addr), String> {
        let link = self.link.as_ref().map_err(Clone::clone)?;
        if let Some(source) = link.on_link_source(target)? {
            return Ok((source, target));
        }
        link.routed_source(target, None)?;
        let route = self.route_v6(target).await?;
        let source = link.routed_source(target, route.source)?;
        let next = match route.hop {
            Hop6::OnLink => target,
            Hop6::Gateway(gateway) => gateway,
        };
        Ok((source, next))
    }

    /// The OS route to `ip`, looked up once per target (a table read: no token).
    async fn route_v6(&self, ip: Ipv6Addr) -> Route6Result {
        let cell = bounded_cell(&self.routes6, ip);
        let route = self.route6.clone();
        cell.get_or_init(|| async move {
            tokio::task::spawn_blocking(move || route(ip))
                .await
                .map_err(|e| e.to_string())?
        })
        .await
        .clone()
    }

    /// The address whose MAC frames to `ip` carry: `ip` itself when on-link, else
    /// its gateway. Looked up once per target.
    async fn next_hop(&self, ip: Ipv4Addr) -> Result<Ipv4Addr, String> {
        let cell = bounded_cell(&self.hops, ip);
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
        let missing = if l2 == ip {
            "No ARP answer from the target".to_string()
        } else {
            format!("No ARP answer from gateway {l2}")
        };
        self.neighbor_mac(IpAddr::V4(l2), missing).await
    }

    /// The MAC of the on-link address `l2`, looked up once; `missing` is the error when the OS
    /// has none.
    async fn neighbor_mac(&self, l2: IpAddr, missing: String) -> MacResult {
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
            // A neighbor lookup can emit an ARP request or Neighbor Solicitation, so it takes
            // a token too.
            gate.wait_for(PacketKind::NeighborLookup, "OS neighbor lookup")
                .await;
            let text = tokio::task::spawn_blocking(move || neighbor(l2))
                .await
                .ok()
                .flatten()
                .ok_or(missing)?;
            crate::capture::mac(&text)
        })
        .await
        .clone()
    }

    /// Probes one port. The first SYN waits `timeout`; each retransmit doubles the
    /// wait up to `cap`. Rate limiting happens on the I/O thread, not here.
    ///
    /// An error means that no SYN was sent (the caller falls back to TCP connect): no route or
    /// MAC for an IPv4 target; for an IPv6 target no source address of its kind on the
    /// interface, our own address, no route or one through another interface, or no MAC for
    /// the target or its gateway.
    pub async fn probe(
        &self,
        ip: IpAddr,
        port: u16,
        timeout: Duration,
        cap: Duration,
        retries: u32,
    ) -> Result<Outcome, String> {
        let (source, mac) = match ip {
            IpAddr::V4(v4) => (IpAddr::V4(self.source), self.resolve(v4).await?),
            IpAddr::V6(v6) => {
                let (source, next) = self.path_v6(v6).await?;
                let missing = if next == v6 {
                    "No NDP answer from the target".to_string()
                } else {
                    format!("No NDP answer from gateway {next}")
                };
                let mac = self.neighbor_mac(IpAddr::V6(next), missing).await?;
                (IpAddr::V6(source), mac)
            }
        };
        let (reply, answer) = oneshot::channel();
        self.tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .send(Request {
                ip,
                source,
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

/// `mac` is the capture interface's MAC; every request names its own source address.
fn io_loop<W: Wire>(
    mut wire: W,
    rx: Receiver<Request>,
    mac: [u8; 6],
    gate: Arc<Gate>,
    timing: Timing,
) {
    let mut adaptive = timing.adaptive.then(Adaptive::new);
    // Probes sent at least once and not yet answered, expired or dropped.
    let mut in_flight = 0usize;
    let secret = new_secret();
    let mut next_local: u32 = 0;
    let mut pending: HashMap<Key, Pending> = HashMap::new();
    let mut cookies: Cookies = HashMap::new();
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
                    if r.ip.is_ipv4() != r.source.is_ipv4() {
                        // Never sent: such a frame cannot be built.
                        let _ = r
                            .reply
                            .send(Err("Source and target address families differ".into()));
                        continue;
                    }
                    let local = 49152 + (next_local % 16384) as u16;
                    next_local = next_local.wrapping_add(1);
                    let key = (r.ip, r.port, local);
                    let c = cookie(secret, r.ip, r.port, local);
                    cookies.insert(key, (c, r.source));
                    pending.insert(
                        key,
                        Pending {
                            cookie: c,
                            source: r.source,
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
            let sent = segment(
                (p.source, mac),
                (key.0, p.mac),
                (key.2, key.1),
                TcpFlags::SYN,
                p.cookie,
                0,
            )
            .ok_or_else(|| "Source and target address families differ".to_string())
            .and_then(|frame| wire.send(&frame));
            if let Err(e) = sent {
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
                    if let Some((key, answer)) = classify(&frame, &cookies) {
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
                                // The SYN of this key was built, so the RST can be too.
                                if let Some(rst) = segment(
                                    (p.source, mac),
                                    (key.0, p.mac),
                                    (key.2, key.1),
                                    TcpFlags::RST | TcpFlags::ACK,
                                    p.cookie.wrapping_add(1),
                                    server_seq.wrapping_add(1),
                                ) {
                                    gate.note(
                                        PacketKind::TcpSyn,
                                        "RST closing a half-open connection",
                                    );
                                    let _ = wire.send(&rst);
                                }
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
            IpAddr::V4(self.dest),
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
    if !crate::trace::trace_port_allowed(port) || port == s.melsec_port {
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

    #[test]
    fn lookup_caches_stay_bounded() {
        let cache: Mutex<HashMap<u32, Arc<OnceCell<()>>>> = Mutex::new(HashMap::new());
        for k in 0..(MAX_ESTIMATES as u32 + 10) {
            bounded_cell(&cache, k);
        }
        assert!(cache.lock().unwrap().len() <= MAX_ESTIMATES);
        // A known key is reused, not a reason to restart.
        let a = bounded_cell(&cache, 5);
        assert!(Arc::ptr_eq(&a, &bounded_cell(&cache, 5)));
    }

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
        for (ip, other) in [
            ("10.0.0.1", "10.0.0.2"),
            ("fe80::1", "fe80::2"),
            ("2001:db8::1", "2001:db8:0:1::1"),
        ] {
            let (ip, other): (IpAddr, IpAddr) = (ip.parse().unwrap(), other.parse().unwrap());
            let base = cookie(7, ip, 80, 50000);
            assert_eq!(base, cookie(7, ip, 80, 50000));
            assert_ne!(base, cookie(8, ip, 80, 50000));
            assert_ne!(base, cookie(7, other, 80, 50000));
            assert_ne!(base, cookie(7, ip, 81, 50000));
            assert_ne!(base, cookie(7, ip, 80, 50001));
        }
        // Equal bits in both halves of an IPv6 address do not cancel out.
        let a: IpAddr = "::1:0:0:0:1".parse().unwrap();
        let b: IpAddr = "::".parse().unwrap();
        assert_ne!(cookie(7, a, 80, 50000), cookie(7, b, 80, 50000));
    }

    #[test]
    fn replies_are_matched_by_key_and_cookie() {
        let me = Ipv4Addr::new(10, 0, 0, 9);
        let target = Ipv4Addr::new(10, 0, 0, 1);
        let mut pending: Cookies = HashMap::new();
        pending.insert((target.into(), 80, 50000), (1000u32, me.into()));
        let synack = frame(
            target,
            me,
            80,
            50000,
            TcpFlags::SYN | TcpFlags::ACK,
            5,
            1001,
        );
        let (key, answer) = classify(&synack, &pending).unwrap();
        assert_eq!(key, (target.into(), 80, 50000));
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
        assert_eq!(classify(&rst, &pending).unwrap().1, Answer::Closed);
        let wrong_ack = frame(target, me, 80, 50000, TcpFlags::SYN | TcpFlags::ACK, 5, 999);
        assert_eq!(classify(&wrong_ack, &pending), None);
        let wrong_port = frame(
            target,
            me,
            81,
            50000,
            TcpFlags::SYN | TcpFlags::ACK,
            5,
            1001,
        );
        assert_eq!(classify(&wrong_port, &pending), None);
        let other_host = frame(
            Ipv4Addr::new(10, 0, 0, 2),
            me,
            80,
            50000,
            TcpFlags::SYN | TcpFlags::ACK,
            5,
            1001,
        );
        assert_eq!(classify(&other_host, &pending), None);
        let not_for_me = frame(
            target,
            Ipv4Addr::new(10, 0, 0, 8),
            80,
            50000,
            TcpFlags::SYN | TcpFlags::ACK,
            5,
            1001,
        );
        assert_eq!(classify(&not_for_me, &pending), None);
        assert_eq!(classify(&synack[..20], &pending), None);
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
        std::thread::spawn(move || io_loop(wire, rx, [2; 6], gate, Timing::FIXED));
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
            ip: TARGET.into(),
            source: ME.into(),
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
        std::thread::spawn(move || io_loop(wire, rx, [2; 6], gate, timing));
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
        std::thread::spawn(move || io_loop(wire, rx, [2; 6], Arc::new(Gate::unlimited()), timing));
        let ask = |ip: Ipv4Addr, port: u16, timeout_ms: u64, retries: u32| {
            let (reply, answer) = oneshot::channel();
            tx.send(Request {
                ip: ip.into(),
                source: ME.into(),
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
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let mut a = Adaptive::new();
        assert_eq!(a.rto(ip, floor, cap), None, "no estimate: caller's window");
        a.sample(ip, Duration::from_millis(1));
        assert_eq!(a.rto(ip, floor, cap), Some(floor));
        a.sample(ip, Duration::from_millis(200));
        assert!(a.rto(ip, floor, cap).unwrap() >= Duration::from_millis(200));
        assert_eq!(a.rto(Ipv4Addr::new(10, 0, 0, 4).into(), floor, cap), None);
    }

    #[tokio::test]
    async fn routed_targets_use_one_gateway_mac() {
        let gateway = Ipv4Addr::new(10, 0, 0, 1);
        let lookups: Arc<Mutex<Vec<IpAddr>>> = Arc::default();
        let seen = lookups.clone();
        let (tx, _rx) = mpsc::channel();
        let engine = SynEngine::with_parts(
            tx,
            Arc::new(Gate::unlimited()),
            (ME, Ok(Link::default())),
            (
                Arc::new(move |ip: Ipv4Addr| match ip.octets() {
                    [10, 0, 0, _] => Ok(NextHop::OnLink),
                    [192, 0, 2, _] => Err("No route to 192.0.2.x".into()),
                    _ => Ok(NextHop::Gateway(gateway)),
                }),
                Arc::new(|_| panic!("no IPv6 target here")),
            ),
            Arc::new(move |ip: IpAddr| {
                seen.lock().unwrap().push(ip);
                let IpAddr::V4(v4) = ip else { return None };
                (v4.octets()[3] != 99).then(|| format!("02:00:00:00:00:{:02x}", v4.octets()[3]))
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
            [IpAddr::V4(gateway), Ipv4Addr::new(10, 0, 0, 7).into()],
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

    // ---- IPv6 ---------------------------------------------------------------------------------

    const ME6: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 5);
    const TARGET6: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

    /// The TCP checksum of an IPv6 frame, computed independently of pnet (RFC 8200 section
    /// 8.1 pseudo-header): the one's-complement sum over it and the segment must be 0xffff.
    fn tcp6_checksum_ok(frame: &[u8]) -> bool {
        let (ip, tcp) = (&frame[14..54], &frame[54..]);
        let mut data = vec![];
        data.extend(&ip[8..40]);
        data.extend((tcp.len() as u32).to_be_bytes());
        data.extend([0, 0, 0, 6]);
        data.extend(tcp);
        if data.len() % 2 == 1 {
            data.push(0);
        }
        let mut sum: u32 = data
            .chunks(2)
            .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
            .sum();
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum == 0xffff
    }

    #[test]
    fn ipv6_frames_are_built_with_a_valid_checksum() {
        let syn = build6(
            (ME6, [2; 6]),
            (TARGET6, [3; 6]),
            (50000, 80),
            TcpFlags::SYN,
            1000,
            0,
        );
        assert_eq!(syn.len(), 14 + 40 + 40);
        let eth = EthernetPacket::new(&syn).unwrap();
        assert_eq!(eth.get_ethertype(), EtherTypes::Ipv6);
        assert_eq!(eth.get_destination().octets(), [3; 6]);
        let ip = Ipv6Packet::new(eth.payload()).unwrap();
        assert_eq!(ip.get_version(), 6);
        assert_eq!(ip.get_payload_length(), 40);
        assert_eq!(ip.get_next_header(), IpNextHeaderProtocols::Tcp);
        assert_eq!(ip.get_hop_limit(), 64);
        assert_eq!((ip.get_source(), ip.get_destination()), (ME6, TARGET6));
        let tcp = TcpPacket::new(ip.payload()).unwrap();
        assert_eq!((tcp.get_source(), tcp.get_destination()), (50000, 80));
        assert_eq!(tcp.get_sequence(), 1000);
        assert_eq!(tcp.get_flags(), TcpFlags::SYN);
        // MSS 1440: a 1500-byte MTU less the IPv6 and TCP headers.
        assert_eq!(&tcp.get_options_raw()[..4], &[2, 4, 0x05, 0xa0]);
        assert!(tcp6_checksum_ok(&syn), "SYN checksum");
        let rst = build6(
            (ME6, [2; 6]),
            (TARGET6, [3; 6]),
            (50000, 80),
            TcpFlags::RST | TcpFlags::ACK,
            1001,
            78,
        );
        assert_eq!(rst.len(), 14 + 40 + 20);
        assert!(tcp6_checksum_ok(&rst), "RST checksum");
        let mut broken = syn.clone();
        broken[54 + 4] ^= 1;
        assert!(!tcp6_checksum_ok(&broken), "the check sees a changed byte");
        // Mixed families are never built.
        assert!(
            segment(
                (IpAddr::V4(ME), [2; 6]),
                (IpAddr::V6(TARGET6), [3; 6]),
                (50000, 80),
                TcpFlags::SYN,
                1,
                0
            )
            .is_none()
        );
    }

    #[test]
    fn ipv6_replies_are_matched_by_key_source_and_cookie() {
        let mut pending: Cookies = HashMap::new();
        pending.insert((TARGET6.into(), 80, 50000), (1000, ME6.into()));
        let reply = |src: Ipv6Addr, dst: Ipv6Addr, sport: u16, flags: u8, ack: u32| {
            build6((src, [3; 6]), (dst, [2; 6]), (sport, 50000), flags, 5, ack)
        };
        let synack = reply(TARGET6, ME6, 80, TcpFlags::SYN | TcpFlags::ACK, 1001);
        let (key, answer) = classify(&synack, &pending).unwrap();
        assert_eq!(key, (IpAddr::V6(TARGET6), 80, 50000));
        // The hop limit stands in for the TTL; IPv6 has no DF bit.
        assert_eq!(
            answer,
            Answer::Open {
                server_seq: 5,
                fp: TcpFp {
                    window: 64240,
                    ttl: 64,
                    df: false,
                    mss: Some(1440),
                    wscale: Some(7),
                    opts: "M,S,T,N,W".into()
                }
            }
        );
        let rst = reply(TARGET6, ME6, 80, TcpFlags::RST | TcpFlags::ACK, 1001);
        assert_eq!(classify(&rst, &pending).unwrap().1, Answer::Closed);
        let other_me: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let other_target: Ipv6Addr = "fe80::2".parse().unwrap();
        let synack_flags = TcpFlags::SYN | TcpFlags::ACK;
        let ignored = [
            ("wrong cookie", reply(TARGET6, ME6, 80, synack_flags, 999)),
            (
                "another address of ours",
                reply(TARGET6, other_me, 80, synack_flags, 1001),
            ),
            (
                "another target",
                reply(other_target, ME6, 80, synack_flags, 1001),
            ),
            ("another port", reply(TARGET6, ME6, 81, synack_flags, 1001)),
            (
                "neither SYN-ACK nor RST",
                reply(TARGET6, ME6, 80, TcpFlags::ACK, 1001),
            ),
        ];
        for (why, frame) in ignored {
            assert_eq!(classify(&frame, &pending), None, "{why}");
        }
        // Not TCP (next header UDP), and an IPv4 frame for an IPv6 probe.
        let mut udp = synack.clone();
        udp[14 + 6] = 17;
        assert_eq!(classify(&udp, &pending), None, "next header UDP");
        let v4 = frame(TARGET, ME, 80, 50000, synack_flags, 5, 1001);
        assert_eq!(classify(&v4, &pending), None, "wrong family");
        // An IPv4 probe is not answered by an IPv6 frame either.
        let mut v4_pending: Cookies = HashMap::new();
        v4_pending.insert((TARGET.into(), 80, 50000), (1000, ME.into()));
        assert_eq!(classify(&synack, &v4_pending), None, "wrong family");
        // Truncated frames and a payload length beyond the frame are ignored, not a panic.
        for cut in [20, 54, 60, 73] {
            assert_eq!(classify(&synack[..cut], &pending), None, "cut at {cut}");
        }
        let mut long = synack.clone();
        long[18..20].copy_from_slice(&1000u16.to_be_bytes());
        let _ = classify(&long, &pending);
    }

    type Sent6 = Arc<Mutex<Vec<(u8, u16, IpAddr)>>>;
    /// An IPv6 link: records (TCP flags, target port, source address) of every frame; SYNs to
    /// `open` get a SYN-ACK, to `closed` a RST, the rest nothing.
    struct Wire6 {
        sent: Sent6,
        open: u16,
        closed: u16,
        inbox: VecDeque<Vec<u8>>,
    }
    impl Wire for Wire6 {
        fn send(&mut self, frame: &[u8]) -> Result<(), String> {
            let eth = EthernetPacket::new(frame).unwrap();
            assert_eq!(eth.get_ethertype(), EtherTypes::Ipv6);
            assert!(tcp6_checksum_ok(frame));
            let ip = Ipv6Packet::new(eth.payload()).unwrap();
            let tcp = TcpPacket::new(ip.payload()).unwrap();
            let port = tcp.get_destination();
            self.sent
                .lock()
                .unwrap()
                .push((tcp.get_flags(), port, IpAddr::V6(ip.get_source())));
            if tcp.get_flags() != TcpFlags::SYN {
                return Ok(());
            }
            let flags = match port {
                p if p == self.open => TcpFlags::SYN | TcpFlags::ACK,
                p if p == self.closed => TcpFlags::RST | TcpFlags::ACK,
                _ => return Ok(()),
            };
            self.inbox.push_back(build6(
                (ip.get_destination(), [3; 6]),
                (ip.get_source(), [2; 6]),
                (port, tcp.get_source()),
                flags,
                77,
                tcp.get_sequence().wrapping_add(1),
            ));
            Ok(())
        }
        fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
            Ok(self.inbox.pop_front())
        }
    }

    #[test]
    fn ipv6_probes_report_open_closed_and_unanswered() {
        let sent: Sent6 = Arc::default();
        let wire = Wire6 {
            sent: sent.clone(),
            open: 22,
            closed: 23,
            inbox: VecDeque::new(),
        };
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            io_loop(wire, rx, [2; 6], Arc::new(Gate::unlimited()), Timing::FIXED)
        });
        let ask = |ip: IpAddr, source: IpAddr, port: u16| {
            let (reply, answer) = oneshot::channel();
            tx.send(Request {
                ip,
                source,
                port,
                mac: [3; 6],
                timeout: Duration::from_millis(100),
                cap: Duration::from_millis(100),
                retries: 0,
                reply,
            })
            .unwrap();
            answer.blocking_recv().unwrap()
        };
        let (target, me) = (IpAddr::V6(TARGET6), IpAddr::V6(ME6));
        let (state, fp) = ask(target, me, 22).unwrap();
        assert_eq!(state, PortState::Open);
        let fp = fp.unwrap();
        assert_eq!((fp.ttl, fp.df), (64, false));
        assert_eq!(ask(target, me, 23).unwrap().0, PortState::Closed);
        assert_eq!(ask(target, me, 24).unwrap().0, PortState::Unanswered);
        let log = sent.lock().unwrap().clone();
        assert_eq!(
            log,
            [
                (TcpFlags::SYN, 22, me),
                (TcpFlags::RST | TcpFlags::ACK, 22, me),
                (TcpFlags::SYN, 23, me),
                (TcpFlags::SYN, 24, me),
            ],
            "the open port is reset from the same source"
        );
        // A request whose source is of the other family is refused and never sent.
        assert!(ask(target, IpAddr::V4(ME), 22).is_err());
        assert_eq!(sent.lock().unwrap().len(), 4);
    }

    fn link(addresses: &[(&str, u8)]) -> Link {
        Link {
            index: 3,
            name: "eth0".into(),
            addresses: addresses
                .iter()
                .map(|(a, prefix)| crate::ipv6::LocalAddress {
                    address: a.parse().unwrap(),
                    prefix: *prefix,
                })
                .collect(),
            own: vec![],
        }
    }

    type Lookups = Arc<Mutex<Vec<IpAddr>>>;
    /// The IPv6 gateway of the simulated routing table, and its MAC.
    const GATEWAY6: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0xa);

    /// An engine without an I/O thread: the receiver shows whether a probe was submitted, the
    /// lists which route and neighbour lookups ran, the log which tokens were taken.
    struct V6Engine {
        engine: Arc<SynEngine>,
        rx: Receiver<Request>,
        routes: Lookups,
        neighbors: Lookups,
        log: Arc<crate::sendlog::SentLog>,
    }

    /// Routing table: `2001:db8:9::/48` through `GATEWAY6` on the capture interface (the OS
    /// suggests `2001:db8:1::5` as the source), `2001:db8:7::/48` through another interface,
    /// `2001:db8:8::/48` through a gateway without a MAC (`fe80::98`), nothing else. MACs:
    /// `TARGET6` and `GATEWAY6` only.
    fn v6_engine(link: Result<Link, String>) -> V6Engine {
        let (routes, neighbors): (Lookups, Lookups) = Default::default();
        let (seen_routes, seen_neighbors) = (routes.clone(), neighbors.clone());
        let log = Arc::new(crate::sendlog::SentLog::new());
        let (tx, rx) = mpsc::channel();
        let engine = SynEngine::with_parts(
            tx,
            Arc::new(Gate::unlimited().with_log(log.clone())),
            (ME, link),
            (
                Arc::new(|_| panic!("no IPv4 target here")),
                Arc::new(move |ip: Ipv6Addr| {
                    seen_routes.lock().unwrap().push(ip.into());
                    let via = |g: &str| Route6 {
                        hop: Hop6::Gateway(g.parse().unwrap()),
                        source: Some("2001:db8:1::5".parse().unwrap()),
                    };
                    match ip.segments()[..3] {
                        [0x2001, 0xdb8, 9] => Ok(via("fe80::a")),
                        [0x2001, 0xdb8, 8] => Ok(via("fe80::98")),
                        [0x2001, 0xdb8, 7] => Err(format!(
                            "The route to {ip} leaves through another interface than the capture interface"
                        )),
                        _ => Err(format!("No route to {ip}")),
                    }
                }),
            ),
            Arc::new(move |ip: IpAddr| {
                seen_neighbors.lock().unwrap().push(ip);
                match ip {
                    IpAddr::V6(TARGET6) => Some("02:00:00:00:00:01".to_string()),
                    IpAddr::V6(GATEWAY6) => Some("02:00:00:00:00:0a".to_string()),
                    _ => None,
                }
            }),
        );
        V6Engine {
            engine,
            rx,
            routes,
            neighbors,
            log,
        }
    }

    async fn probe6(engine: &SynEngine, ip: &str, port: u16) -> Result<Outcome, String> {
        let short = Duration::from_millis(10);
        engine
            .probe(ip.parse().unwrap(), port, short, short, 0)
            .await
    }

    fn addrs(list: &Lookups) -> Vec<String> {
        list.lock()
            .unwrap()
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    #[tokio::test]
    async fn ipv6_targets_the_engine_cannot_reach_fail_before_anything_is_sent() {
        let e6 = v6_engine(Ok(link(&[("fe80::5", 64), ("2001:db8:1::5", 64)])));
        // Refused from the addresses alone: no route lookup either.
        for (target, why) in [
            ("fe80::5", "own address"),
            ("2001:db8:1::5", "own address"),
            ("ff02::1", "unicast"),
        ] {
            assert!(!e6.engine.reaches(target.parse().unwrap()), "{target}");
            let e = probe6(&e6.engine, target, 80).await.unwrap_err();
            assert!(e.contains(why), "{target}: {e}");
        }
        assert!(addrs(&e6.routes).is_empty(), "no route lookup");
        // No route, and a route through another interface: one route lookup each, no neighbour
        // lookup, no token.
        let e = probe6(&e6.engine, "2001:db8:2::1", 80).await.unwrap_err();
        assert!(e.contains("No route"), "{e}");
        let e = probe6(&e6.engine, "2001:db8:7::1", 80).await.unwrap_err();
        assert!(e.contains("another interface"), "{e}");
        assert!(!e6.engine.has_path("2001:db8:7::1".parse().unwrap()).await);
        assert_eq!(
            addrs(&e6.routes),
            ["2001:db8:2::1", "2001:db8:7::1"],
            "once per target"
        );
        assert!(addrs(&e6.neighbors).is_empty(), "no neighbour lookup");
        assert!(e6.log.is_empty(), "no token taken");
        // A gateway without a MAC: one neighbour lookup (one token), nothing submitted.
        let e = probe6(&e6.engine, "2001:db8:8::1", 80).await.unwrap_err();
        assert!(e.contains("gateway fe80::98"), "{e}");
        assert_eq!(addrs(&e6.neighbors), ["fe80::98"]);
        assert_eq!(e6.log.total(), 1);
        // On-link, but no neighbour entry.
        let e = probe6(&e6.engine, "fe80::99", 80).await.unwrap_err();
        assert!(e.contains("No NDP answer from the target"), "{e}");
        assert_eq!(addrs(&e6.neighbors), ["fe80::98", "fe80::99"]);
        assert!(e6.rx.try_recv().is_err(), "no SYN was submitted");
        // No source of the target's kind: refused before the route is looked up.
        let ll_only = v6_engine(Ok(link(&[("fe80::5", 64)])));
        assert!(!ll_only.engine.reaches("2001:db8:9::1".parse().unwrap()));
        let e = probe6(&ll_only.engine, "2001:db8:9::1", 80)
            .await
            .unwrap_err();
        assert!(e.contains("no global"), "{e}");
        let bare = v6_engine(Ok(Link::default()));
        assert!(!bare.engine.reaches(IpAddr::V6(TARGET6)));
        let e = probe6(&bare.engine, "fe80::1", 80).await.unwrap_err();
        assert!(e.contains("link-local"), "{e}");
        let global_only = v6_engine(Ok(link(&[("2001:db8:1::5", 64)])));
        assert!(probe6(&global_only.engine, "fe80::1", 80).await.is_err());
        for e6 in [&ll_only, &bare, &global_only] {
            assert!(addrs(&e6.routes).is_empty() && addrs(&e6.neighbors).is_empty());
            assert!(e6.rx.try_recv().is_err());
        }
        // The capture driver refused the filter with IPv6 addresses: IPv6 is off, with the reason.
        let refused = v6_engine(Err("the capture filter with IPv6 addresses failed".into()));
        assert!(!refused.engine.reaches(IpAddr::V6(TARGET6)));
        assert!(refused.engine.reaches(IpAddr::V4(TARGET)));
        for target in ["fe80::1", "2001:db8:9::1"] {
            let e = probe6(&refused.engine, target, 80).await.unwrap_err();
            assert!(e.contains("capture filter"), "{e}");
        }
        assert!(addrs(&refused.routes).is_empty() && addrs(&refused.neighbors).is_empty());
        assert!(refused.rx.try_recv().is_err());
    }

    /// Submits one probe, answers it "closed" as the I/O thread would, and returns what the
    /// request carried: (target, source, destination MAC).
    async fn submitted(
        e6: V6Engine,
        target: &'static str,
    ) -> (V6Engine, (IpAddr, IpAddr, [u8; 6])) {
        let prober = e6.engine.clone();
        let task = tokio::spawn(async move { probe6(&prober, target, 80).await });
        let V6Engine {
            engine,
            rx,
            routes,
            neighbors,
            log,
        } = e6;
        let (rx, request) = tokio::task::spawn_blocking(move || {
            let request = rx.recv_timeout(Duration::from_secs(5));
            (rx, request)
        })
        .await
        .unwrap();
        let request = request.unwrap();
        let seen = (request.ip, request.source, request.mac);
        let _ = request.reply.send(Ok((PortState::Closed, None)));
        assert_eq!(task.await.unwrap().unwrap().0, PortState::Closed);
        let e6 = V6Engine {
            engine,
            rx,
            routes,
            neighbors,
            log,
        };
        (e6, seen)
    }

    #[tokio::test]
    async fn on_link_ipv6_targets_are_submitted_with_their_source() {
        let e6 = v6_engine(Ok(link(&[("fe80::5", 64), ("2001:db8:1::5", 64)])));
        assert!(e6.engine.reaches(IpAddr::V6(TARGET6)));
        assert!(e6.engine.on_link(IpAddr::V6(TARGET6)));
        let (e6, seen) = submitted(e6, "fe80::1").await;
        assert_eq!(
            seen,
            (IpAddr::V6(TARGET6), IpAddr::V6(ME6), [2, 0, 0, 0, 0, 1])
        );
        assert!(
            addrs(&e6.routes).is_empty(),
            "an on-link target needs no route"
        );
        // The receiver is gone now (the engine stopped): the probe fails, and the MAC was
        // looked up once per target, not again.
        let V6Engine {
            engine,
            rx,
            neighbors,
            ..
        } = e6;
        drop(rx);
        assert!(probe6(&engine, "fe80::1", 81).await.is_err());
        assert_eq!(addrs(&neighbors), ["fe80::1"]);
    }

    #[tokio::test]
    async fn routed_ipv6_targets_go_to_the_gateway_mac_from_a_global_source() {
        let e6 = v6_engine(Ok(link(&[("fe80::5", 64), ("2001:db8:1::5", 64)])));
        let target: IpAddr = "2001:db8:9::1".parse().unwrap();
        assert!(e6.engine.reaches(target) && !e6.engine.on_link(target));
        assert!(e6.engine.has_path(target).await);
        let global: IpAddr = "2001:db8:1::5".parse().unwrap();
        let gateway_mac = [2, 0, 0, 0, 0, 0x0a];
        let (e6, seen) = submitted(e6, "2001:db8:9::1").await;
        assert_eq!(seen, (target, global, gateway_mac));
        let (e6, seen) = submitted(e6, "2001:db8:9::2").await;
        assert_eq!(seen.1, global, "never the link-local address");
        assert_eq!(seen.2, gateway_mac);
        // One route lookup per target (the first one's, made by has_path, was kept), one
        // gateway MAC lookup for both, and one token for it.
        assert_eq!(addrs(&e6.routes), ["2001:db8:9::1", "2001:db8:9::2"]);
        assert_eq!(addrs(&e6.neighbors), ["fe80::a"]);
        assert_eq!(e6.log.total(), 1);
    }

    /// Manual check that Npcap compiles the engine's capture filter with IPv6 addresses: for
    /// every capture device with an IPv4 and an IPv6 address, the filter is built exactly as
    /// [`SynEngine::start`] builds it and a capture is opened with it, then closed. Nothing is
    /// sent (`send` is never called). The IPv4-only filter is opened first as a control.
    /// `cargo test -p network-scope-core --lib npcap_accepts -- --ignored --nocapture`
    #[cfg(windows)]
    #[test]
    #[ignore]
    fn npcap_accepts_the_ipv6_capture_filter() {
        let devices = crate::capture::interfaces().expect("Npcap is installed");
        let (mut accepted, mut refused) = (0, vec![]);
        for (name, description) in devices {
            let label = format!("{description} ({name})");
            let Some(index) = crate::platform::device_index(&name) else {
                println!("{label}: no OS interface");
                continue;
            };
            // What the desktop fills in for this interface (compare with `Get-NetAdapter`).
            println!(
                "{label}: addresses {:?}",
                crate::platform::interface_addresses(&name)
            );
            let Some(v4) = crate::platform::ipv4_of(index) else {
                println!("{label}: no IPv4 address (the engine needs one)");
                continue;
            };
            let link = crate::ipv6::link_of(&name, v4);
            if link.sources().is_empty() {
                println!("{label}: no IPv6 source address");
                continue;
            }
            let control = crate::capture::syn_filter(v4, &[]);
            if let Err(e) = Capture::open_with(&name, false, Some(&control)) {
                println!("{label}: not openable even with `{control}`: {e}");
                continue;
            }
            let filter = crate::capture::syn_filter(v4, &link.sources());
            match Capture::open_with(&name, false, Some(&filter)) {
                Ok(capture) => {
                    drop(capture);
                    accepted += 1;
                    println!("{label}: accepted `{filter}`");
                }
                Err(e) => {
                    println!("{label}: REFUSED `{filter}`: {e}");
                    refused.push(label);
                }
            }
        }
        println!("{accepted} accepted, {} refused", refused.len());
        assert!(refused.is_empty(), "refused on {refused:?}");
    }
}
