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
use crate::{
    capture::Capture,
    core::Gate,
    osfp::TcpFp,
    scan::{PortState, Settings},
};
use pnet_packet::{
    ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::{Ipv4Packet, MutableIpv4Packet},
    tcp::{MutableTcpPacket, TcpFlags, TcpPacket},
    MutablePacket, Packet,
};
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr},
    sync::{
        mpsc::{self, Receiver, Sender, TryRecvError},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::{oneshot, OnceCell};

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

/// The link the I/O thread transmits on and reads from (a capture handle in production).
trait Wire {
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

pub struct SynEngine {
    tx: Mutex<Sender<Request>>,
    macs: Mutex<HashMap<Ipv4Addr, Arc<OnceCell<MacResult>>>>,
    gate: Arc<Gate>,
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
    ip.set_ttl(64);
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
        let (tx, rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel();
        let io_gate = gate.clone();
        std::thread::Builder::new()
            .name("syn-engine".into())
            .spawn(move || {
                // Not promiscuous, and the kernel drops everything but TCP to us.
                let filter = crate::capture::syn_filter(source_ip);
                match Capture::open_with(&interface, false, Some(&filter)) {
                    Ok(cap) => {
                        let _ = ready_tx.send(Ok(()));
                        io_loop(cap, rx, (source_ip, source_mac), io_gate);
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
        Ok(Arc::new(Self {
            tx: Mutex::new(tx),
            macs: Mutex::new(HashMap::new()),
            gate,
        }))
    }

    async fn resolve(&self, ip: Ipv4Addr) -> Result<[u8; 6], String> {
        let cell = self
            .macs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(ip)
            .or_default()
            .clone();
        let gate = self.gate.clone();
        cell.get_or_init(|| async move {
            // A neighbor lookup can emit an ARP request, so it takes a token too.
            gate.wait().await;
            let text = tokio::task::spawn_blocking(move || crate::platform::mac(IpAddr::V4(ip)))
                .await
                .ok()
                .flatten()
                .ok_or("No local ARP neighbor; use TCP connect for routed targets")?;
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
fn next_queued(
    retransmit: &mut VecDeque<Key>,
    fresh: &mut VecDeque<Key>,
    pending: &HashMap<Key, Pending>,
) -> Option<Key> {
    for queue in [retransmit, fresh] {
        while let Some(&key) = queue.front() {
            if pending.get(&key).is_some_and(|p| p.queued) {
                return Some(key);
            }
            // Answered, failed or already sent through the other queue.
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
) {
    let secret = {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);
        t ^ (u64::from(std::process::id()) << 40)
    };
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
        while let Some(key) = next_queued(&mut retransmit, &mut fresh, &pending) {
            // One token per transmitted SYN; a refused token leaves the probe queued
            // (its reply window has not started, so it cannot expire meanwhile).
            if gate.try_take().is_err() {
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
                    let _ = p.reply.send(Err(e));
                }
                cookies.remove(&key);
                continue;
            }
            busy = true;
            let now = Instant::now();
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
        std::thread::spawn(move || io_loop(wire, rx, (ME, [2; 6]), gate));
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
        let capped = submit(&tx, 2, 40, 40, 2);
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
            g2 >= Duration::from_millis(40) && g2 < Duration::from_millis(78),
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
}
