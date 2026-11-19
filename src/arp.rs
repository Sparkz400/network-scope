//! ARP sweep through the capture handle (opt-in `arp_sweep`).
//!
//! One I/O thread owns a capture handle opened with the kernel filter `arp`. Host
//! tasks submit on-link IPv4 targets; the thread broadcasts ARP requests in batches
//! (at most [`WINDOW`] unanswered at a time, every request taking one token from the
//! scan's shared rate gate), matches replies by sender address and retransmits
//! unanswered requests. A reply proves the host is up right now, unlike a cached
//! neighbor entry, and many hosts resolve in parallel instead of one blocking
//! SendARP call each. ARP carries no ports, so OT and printer services are never
//! addressed.
use crate::{capture::Capture, core::Gate, scan::Settings, syn::Wire};
use std::{
    collections::{HashMap, VecDeque},
    net::Ipv4Addr,
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, Sender, TryRecvError},
    },
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

/// Kernel capture filter: only ARP frames reach the I/O thread.
pub const FILTER: &str = "arp";
/// Upper bound on requests sent and not yet answered or expired. Every request is a
/// broadcast that each host on the segment must process, so even an unlimited rate
/// gate never floods the segment with more than this many at once.
pub const WINDOW: usize = 256;
const BROADCAST: [u8; 6] = [0xff; 6];

/// Ethernet frame with an ARP who-has request for `target`, padded to the 60-byte minimum.
pub fn request(source: (Ipv4Addr, [u8; 6]), target: Ipv4Addr) -> Vec<u8> {
    let mut f = Vec::with_capacity(60);
    f.extend(BROADCAST);
    f.extend(source.1);
    f.extend([0x08, 0x06]);
    // Ethernet / IPv4, hardware length 6, protocol length 4, operation 1 (request).
    f.extend([0, 1, 8, 0, 6, 4, 0, 1]);
    f.extend(source.1);
    f.extend(source.0.octets());
    f.extend([0; 6]);
    f.extend(target.octets());
    f.resize(60, 0);
    f
}

/// An ARP reply addressed to `me`: returns the sender's address and MAC.
pub fn parse_reply(frame: &[u8], me: Ipv4Addr) -> Option<(Ipv4Addr, [u8; 6])> {
    if frame.len() < 42 || frame[12..14] != [0x08, 0x06] {
        return None;
    }
    let arp = &frame[14..42];
    if arp[..8] != [0, 1, 8, 0, 6, 4, 0, 2] || arp[24..28] != me.octets() {
        return None;
    }
    let mac: [u8; 6] = arp[8..14].try_into().ok()?;
    let ip = Ipv4Addr::new(arp[14], arp[15], arp[16], arp[17]);
    (mac != [0; 6] && mac != BROADCAST && !ip.is_unspecified()).then_some((ip, mac))
}

pub fn format_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

type Reply = oneshot::Sender<Option<[u8; 6]>>;
struct Request {
    ip: Ipv4Addr,
    reply: Reply,
}
struct Pending {
    waiters: Vec<Reply>,
    sends_left: u32,
    /// End of the current reply window; `None` while queued for (re)transmission.
    wait_until: Option<Instant>,
}
impl Pending {
    fn abandoned(&self) -> bool {
        self.waiters.iter().all(|w| w.is_closed())
    }
    fn finish(self, mac: Option<[u8; 6]>) {
        for w in self.waiters {
            let _ = w.send(mac);
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Timing {
    /// Reply window per request.
    pub wait: Duration,
    /// Requests per target (first plus retransmits).
    pub tries: u32,
}
impl Timing {
    pub fn from_settings(s: &Settings) -> Self {
        Self {
            // LAN neighbours answer ARP within milliseconds; a short window keeps a
            // silent address from holding a host worker for long.
            wait: Duration::from_millis(u64::from(s.ping_timeout.clamp(100, 300))),
            tries: (s.retries + 1).clamp(1, 3),
        }
    }
}

pub struct ArpEngine {
    tx: Mutex<Sender<Request>>,
    source: Ipv4Addr,
}

impl ArpEngine {
    /// Opens the capture on the I/O thread (non-promiscuous, filter `arp`).
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
        std::thread::Builder::new()
            .name("arp-sweep".into())
            .spawn(
                move || match Capture::open_with(&interface, false, Some(FILTER)) {
                    Ok(cap) => {
                        let _ = ready_tx.send(Ok(()));
                        io_loop(cap, rx, (source_ip, source_mac), gate, timing);
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                    }
                },
            )
            .map_err(|e| e.to_string())?;
        ready_rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| "Capture driver did not start".to_string())??;
        Ok(Arc::new(Self {
            tx: Mutex::new(tx),
            source: source_ip,
        }))
    }

    pub fn source(&self) -> Ipv4Addr {
        self.source
    }

    /// The target's MAC if it answered an ARP request now, `Ok(None)` if it stayed
    /// silent, `Err` if the engine stopped (the caller falls back to the OS lookup).
    pub async fn resolve(&self, ip: Ipv4Addr) -> Result<Option<String>, String> {
        let (reply, answer) = oneshot::channel();
        self.tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .send(Request { ip, reply })
            .map_err(|_| "ARP sweep stopped")?;
        answer
            .await
            .map(|mac| mac.map(format_mac))
            .map_err(|_| "ARP sweep stopped".to_string())
    }
}

fn io_loop<W: Wire>(
    mut wire: W,
    rx: Receiver<Request>,
    source: (Ipv4Addr, [u8; 6]),
    gate: Arc<Gate>,
    timing: Timing,
) {
    let mut pending: HashMap<Ipv4Addr, Pending> = HashMap::new();
    let mut queue: VecDeque<Ipv4Addr> = VecDeque::new();
    let mut outstanding = 0usize;
    let mut open = true;
    let mut next_sweep = Instant::now();
    while open || !pending.is_empty() {
        let mut busy = false;
        for _ in 0..512 {
            match rx.try_recv() {
                Ok(r) => {
                    busy = true;
                    if let Some(p) = pending.get_mut(&r.ip) {
                        p.waiters.push(r.reply);
                    } else {
                        pending.insert(
                            r.ip,
                            Pending {
                                waiters: vec![r.reply],
                                sends_left: timing.tries,
                                wait_until: None,
                            },
                        );
                        queue.push_back(r.ip);
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    open = false;
                    break;
                }
            }
        }
        while outstanding < WINDOW {
            let Some(&ip) = queue.front() else { break };
            let Some(p) = pending.get(&ip) else {
                queue.pop_front();
                continue;
            };
            if p.abandoned() || p.wait_until.is_some() {
                queue.pop_front();
                continue;
            }
            if gate.try_take().is_err() {
                break;
            }
            queue.pop_front();
            busy = true;
            if wire.send(&request(source, ip)).is_err() {
                // A send failure ends the sweep: every waiter falls back to the OS lookup.
                return;
            }
            if let Some(p) = pending.get_mut(&ip) {
                p.sends_left -= 1;
                p.wait_until = Some(Instant::now() + timing.wait);
                outstanding += 1;
            }
        }
        for _ in 0..512 {
            match wire.next() {
                Ok(Some(frame)) => {
                    busy = true;
                    if let Some((ip, mac)) = parse_reply(&frame, source.0)
                        && let Some(p) = pending.remove(&ip)
                    {
                        if p.wait_until.is_some() {
                            outstanding -= 1;
                        }
                        p.finish(Some(mac));
                    }
                }
                Ok(None) => break,
                Err(_) => return,
            }
        }
        let now = Instant::now();
        if now >= next_sweep {
            next_sweep = now + Duration::from_millis(5);
            let mut done = vec![];
            for (ip, p) in pending.iter_mut() {
                let expired = p.wait_until.is_some_and(|t| now >= t);
                if expired {
                    outstanding -= 1;
                    p.wait_until = None;
                    if p.sends_left > 0 && !p.abandoned() {
                        queue.push_front(*ip);
                    } else {
                        done.push(*ip);
                    }
                } else if p.wait_until.is_none() && p.abandoned() {
                    // Queued, and every caller is gone (Stop): never sent.
                    done.push(*ip);
                }
            }
            for ip in done {
                if let Some(p) = pending.remove(&ip) {
                    p.finish(None);
                }
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

    const ME: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 9);
    const MY_MAC: [u8; 6] = [2, 0, 0, 0, 0, 9];

    fn reply_frame(from: Ipv4Addr, mac: [u8; 6], to: Ipv4Addr) -> Vec<u8> {
        let mut f = vec![];
        f.extend(MY_MAC);
        f.extend(mac);
        f.extend([0x08, 0x06, 0, 1, 8, 0, 6, 4, 0, 2]);
        f.extend(mac);
        f.extend(from.octets());
        f.extend(MY_MAC);
        f.extend(to.octets());
        f
    }

    #[test]
    fn request_layout() {
        let f = request((ME, MY_MAC), Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(f.len(), 60);
        assert_eq!(&f[..6], &[0xff; 6]);
        assert_eq!(&f[6..12], &MY_MAC);
        assert_eq!(&f[12..14], &[8, 6]);
        assert_eq!(&f[14..22], &[0, 1, 8, 0, 6, 4, 0, 1]);
        assert_eq!(&f[22..28], &MY_MAC);
        assert_eq!(&f[28..32], &[10, 0, 0, 9]);
        assert_eq!(&f[32..38], &[0; 6]);
        assert_eq!(&f[38..42], &[10, 0, 0, 1]);
        assert!(f[42..].iter().all(|b| *b == 0));
    }

    #[test]
    fn replies_are_parsed_and_validated() {
        let target = Ipv4Addr::new(10, 0, 0, 1);
        let mac = [0, 0x1b, 0x1b, 1, 2, 3];
        let r = reply_frame(target, mac, ME);
        assert_eq!(parse_reply(&r, ME), Some((target, mac)));
        assert_eq!(
            parse_reply(&r, Ipv4Addr::new(10, 0, 0, 8)),
            None,
            "not for us"
        );
        let mut req = r.clone();
        req[21] = 1;
        assert_eq!(parse_reply(&req, ME), None, "a request is not an answer");
        let mut ipv4 = r.clone();
        ipv4[13] = 0;
        assert_eq!(parse_reply(&ipv4, ME), None);
        assert_eq!(parse_reply(&r[..41], ME), None);
        assert_eq!(
            parse_reply(&reply_frame(target, [0; 6], ME), ME),
            None,
            "zero MAC"
        );
        assert_eq!(format_mac(mac), "00:1B:1B:01:02:03");
    }

    type Sent = Arc<Mutex<Vec<(Instant, Ipv4Addr)>>>;
    struct FakeWire {
        sent: Sent,
        alive: Vec<Ipv4Addr>,
        inbox: VecDeque<Vec<u8>>,
    }
    impl Wire for FakeWire {
        fn send(&mut self, frame: &[u8]) -> Result<(), String> {
            assert_eq!(&frame[..6], &[0xff; 6], "requests are broadcast");
            let target = Ipv4Addr::new(frame[38], frame[39], frame[40], frame[41]);
            self.sent.lock().unwrap().push((Instant::now(), target));
            if self.alive.contains(&target) {
                let n = target.octets()[3];
                self.inbox
                    .push_back(reply_frame(target, [0, 1, 2, 3, 4, n], ME));
            }
            Ok(())
        }
        fn next(&mut self) -> Result<Option<Vec<u8>>, String> {
            Ok(self.inbox.pop_front())
        }
    }

    fn engine(gate: Gate, alive: Vec<Ipv4Addr>, timing: Timing) -> (Sender<Request>, Sent) {
        let sent: Sent = Arc::default();
        let wire = FakeWire {
            sent: sent.clone(),
            alive,
            inbox: VecDeque::new(),
        };
        let (tx, rx) = mpsc::channel();
        let gate = Arc::new(gate);
        std::thread::spawn(move || io_loop(wire, rx, (ME, MY_MAC), gate, timing));
        (tx, sent)
    }
    fn ask(tx: &Sender<Request>, ip: Ipv4Addr) -> oneshot::Receiver<Option<[u8; 6]>> {
        let (reply, answer) = oneshot::channel();
        tx.send(Request { ip, reply }).unwrap();
        answer
    }
    fn host(n: u8) -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, n)
    }

    #[test]
    fn live_hosts_answer_and_silent_ones_are_retried() {
        let timing = Timing {
            wait: Duration::from_millis(30),
            tries: 2,
        };
        let (tx, sent) = engine(Gate::unlimited(), vec![host(1)], timing);
        let alive = ask(&tx, host(1));
        let alive_again = ask(&tx, host(1));
        let silent = ask(&tx, host(2));
        assert_eq!(alive.blocking_recv().unwrap(), Some([0, 1, 2, 3, 4, 1]));
        assert_eq!(
            alive_again.blocking_recv().unwrap(),
            Some([0, 1, 2, 3, 4, 1])
        );
        assert_eq!(silent.blocking_recv().unwrap(), None);
        let log = sent.lock().unwrap().clone();
        assert_eq!(
            log.iter().filter(|(_, ip)| *ip == host(1)).count(),
            1,
            "duplicate targets share one request"
        );
        let retries: Vec<Instant> = log
            .iter()
            .filter(|(_, ip)| *ip == host(2))
            .map(|(t, _)| *t)
            .collect();
        assert_eq!(retries.len(), 2);
        assert!(retries[1] - retries[0] >= Duration::from_millis(30));
    }

    #[test]
    fn sweep_respects_the_rate_gate() {
        let timing = Timing {
            wait: Duration::from_millis(10),
            tries: 1,
        };
        let (tx, sent) = engine(Gate::per_second(200.0, 1.0), vec![], timing);
        let answers: Vec<_> = (1..=21).map(|n| ask(&tx, host(n))).collect();
        for a in answers {
            assert_eq!(a.blocking_recv().unwrap(), None);
        }
        let log = sent.lock().unwrap().clone();
        assert_eq!(log.len(), 21);
        let span = log.last().unwrap().0 - log[0].0;
        assert!(span >= Duration::from_millis(90), "{span:?}");
    }

    #[test]
    fn outstanding_requests_are_bounded_by_the_window() {
        let timing = Timing {
            wait: Duration::from_millis(300),
            tries: 1,
        };
        let (tx, sent) = engine(Gate::unlimited(), vec![], timing);
        let answers: Vec<_> = (0..400u32)
            .map(|n| ask(&tx, Ipv4Addr::from(0x0a01_0000 + n)))
            .collect();
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(sent.lock().unwrap().len(), WINDOW);
        for a in answers {
            assert_eq!(a.blocking_recv().unwrap(), None);
        }
        assert_eq!(sent.lock().unwrap().len(), 400);
    }

    #[test]
    fn stopped_requests_are_never_sent() {
        let timing = Timing {
            wait: Duration::from_millis(500),
            tries: 3,
        };
        let (tx, sent) = engine(Gate::per_second(20.0, 1.0), vec![], timing);
        let start = std::time::Instant::now();
        let answers: Vec<_> = (1..=20).map(|n| ask(&tx, host(n))).collect();
        std::thread::sleep(Duration::from_millis(60));
        drop(answers);
        // Sends before the stop are limited by the 20/s gate (burst 1); slow CI runners
        // oversleep, so the bound follows the time that really passed.
        let allowed = 2 + (start.elapsed().as_secs_f64() * 20.0).ceil() as usize;
        std::thread::sleep(Duration::from_millis(30));
        let after_stop = sent.lock().unwrap().len();
        std::thread::sleep(Duration::from_millis(700));
        assert_eq!(
            sent.lock().unwrap().len(),
            after_stop,
            "requests kept leaving"
        );
        assert!(
            after_stop <= allowed,
            "{after_stop} sent, at most {allowed} allowed"
        );
    }
}
