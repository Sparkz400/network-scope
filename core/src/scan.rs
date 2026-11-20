use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    },
    thread,
    time::{Duration, Instant},
};

pub const MAX_HOSTS: usize = 65_536;
/// Streaming limit for the CLI (a /8); the desktop table keeps the smaller limit.
pub const MAX_STREAM: u64 = 1 << 24;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub ports: String,
    pub workers: usize,
    pub probes: u32,
    pub ping_timeout: u32,
    pub port_timeout: u32,
    pub minimum_timeout: u32,
    pub delay: u64,
    pub scan_nonresponders: bool,
    pub skip_edges: bool,
    pub adaptive: bool,
    pub dns: bool,
    pub mac: bool,
    pub tcp_only: bool,
    pub arp: bool,
    pub syn: bool,
    pub safe: bool,
    pub ot: bool,
    pub interface: String,
    pub source_ip: String,
    pub source_mac: String,
    pub modbus_unit: u8,
    pub s7_rack: u8,
    pub s7_slot: u8,
    /// Extra attempts for ports that did not answer (timeout doubles each time).
    pub retries: u32,
    /// Packets per second cap outside Safe Mode; 0 means unlimited.
    pub max_rate: u32,
    /// Concurrent port probes per host outside Safe Mode.
    pub port_parallel: usize,
    /// Identify services on open TCP ports (banners, HTTP, TLS, SMB, databases).
    pub services: bool,
    /// Probe UDP services (DNS, DHCP, NTP, NetBIOS, SNMP, SSDP, mDNS).
    pub udp: bool,
    pub udp_ports: String,
    /// Guess the OS, manufacturer and device type.
    pub os_detect: bool,
    /// Record the router path to every responding host.
    pub trace: bool,
    pub trace_hops: u8,
    /// Extra service probe file (see data/probes.json for the format).
    pub probe_file: String,
    /// Rhai script file or directory run against every scanned host.
    pub scripts: String,
    /// Active ARP sweep through the capture interface (needs Npcap/libpcap and the
    /// interface, source IPv4 and source MAC). Off in Safe Mode; falls back to the
    /// per-host OS lookup without a capture driver.
    pub arp_sweep: bool,
    /// SYN engine: reply windows from a smoothed RTT and an AIMD congestion window.
    pub syn_adaptive: bool,
    /// TCP connect scan: per-host connect timeout from a smoothed RTT of the host's
    /// completed connects (SYN-ACK or RST). Only ever shortens a wait; never in the
    /// SYN engine and never raises a rate.
    pub tcp_adaptive: bool,
    /// Traceroute method: icmp (default), tcp (SYN, needs the capture interface) or udp.
    pub trace_method: crate::trace::TraceMethod,
    /// Destination port for TCP traceroute; 0 picks the host's first open port that is
    /// neither an OT nor a printer port.
    pub trace_port: u16,
    /// JARM-style TLS fingerprint (ten extra ClientHellos per TLS port). Opt-in, and ignored in
    /// Safe Mode like the other transmitting extras.
    pub jarm: bool,
    /// Automatic back-off (`backoff` module): per-device-type limits on the parallel probes to
    /// a host, and a slower pace (or a pause for the rest of the scan) when the host starts
    /// resetting connections. It only ever slows a host down; `--no-backoff` turns it off.
    pub backoff: bool,
    /// SNMP credentials (`--snmp-community`, `--snmp-v3`): when set, responding hosts are read
    /// over SNMP (system group, interfaces, LLDP). Never serialised: it holds secrets.
    #[serde(skip)]
    pub snmp: Option<crate::snmp::SnmpConfig>,
    /// IPv6 discovery of the local link (`--ipv6-discover`): one ICMPv6 echo to `ff02::1` per
    /// interface, the OS neighbour cache, joined to hosts by MAC (see `ipv6`).
    pub ipv6_discover: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            ports: "80,443,8080".into(),
            workers: 64,
            probes: 3,
            ping_timeout: 2000,
            port_timeout: 2000,
            minimum_timeout: 100,
            delay: 20,
            scan_nonresponders: false,
            skip_edges: true,
            adaptive: true,
            dns: false,
            mac: false,
            tcp_only: false,
            arp: false,
            syn: false,
            safe: true,
            ot: false,
            interface: String::new(),
            source_ip: String::new(),
            source_mac: String::new(),
            modbus_unit: 1,
            s7_rack: 0,
            s7_slot: 2,
            retries: 1,
            max_rate: 0,
            port_parallel: 64,
            services: false,
            udp: false,
            udp_ports: "53,67,123,137,161,1900,5353".into(),
            os_detect: false,
            trace: false,
            trace_hops: 20,
            probe_file: String::new(),
            scripts: String::new(),
            arp_sweep: false,
            syn_adaptive: false,
            tcp_adaptive: false,
            trace_method: crate::trace::TraceMethod::Icmp,
            trace_port: 0,
            jarm: false,
            backoff: true,
            snmp: None,
            ipv6_discover: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Host {
    pub ip: IpAddr,
    pub responding: bool,
    pub ping: Option<u32>,
    pub ttl: Option<u8>,
    pub hostname: String,
    pub mac: String,
    pub open: Vec<u16>,
    pub closed: usize,
    pub unanswered: usize,
    pub errors: Vec<String>,
    pub ports_checked: bool,
    #[serde(default)]
    pub identity: std::collections::BTreeMap<String, String>,
    #[serde(default)]
    pub udp_open: Vec<u16>,
    #[serde(default)]
    pub trace: Vec<crate::trace::Hop>,
}

/// Approximate frequency order of commonly open TCP ports (most frequent first),
/// recalled from public scanner statistics; not generated from nmap-services.
pub const TOP_PORTS: [u16; 100] = [
    80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993,
    5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000,
    8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631,
    631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156,
    543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986,
    13, 1029, 9, 5051, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
];

/// Accepts `80`, `8000-8100` and `top:N` (the N most common ports), comma separated.
pub fn parse_ports(input: &str) -> Result<Vec<u16>, String> {
    let mut ports = BTreeSet::new();
    for item in input.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let parse = |s: &str| {
            s.trim()
                .parse::<u16>()
                .ok()
                .filter(|&p| p > 0)
                .ok_or_else(|| format!("Invalid port: {s}"))
        };
        if let Some(n) = item.strip_prefix("top:") {
            let n = n
                .trim()
                .parse::<usize>()
                .ok()
                .filter(|n| (1..=TOP_PORTS.len()).contains(n))
                .ok_or_else(|| format!("top:N needs N from 1 to {}", TOP_PORTS.len()))?;
            ports.extend(TOP_PORTS[..n].iter().copied());
        } else if let Some((a, b)) = item.split_once('-') {
            let (a, b) = (parse(a)?, parse(b)?);
            if a > b {
                return Err("Port range must run from low to high.".into());
            }
            ports.extend(a..=b);
        } else {
            ports.insert(parse(item)?);
        }
    }
    if ports.is_empty() {
        return Err("Enter at least one TCP port.".into());
    }
    Ok(ports.into_iter().collect())
}

/// A lazily expanded target list: ranges are never materialised, so very large
/// scans stream through the scheduler instead of being loaded up front.
///
/// Edge skipping: a CIDR block (prefix 30 or shorter) drops exactly its own network
/// and broadcast address, so `10.0.1.0` inside `10.0.0.0/23` is scanned; /31 and /32
/// are never trimmed. Dash ranges (`a-b`) keep the legacy rule of skipping every
/// `x.x.x.0` and `x.x.x.255`. Single addresses are never skipped.
#[derive(Clone, Debug, PartialEq)]
pub struct Targets {
    singles: Vec<IpAddr>,
    /// Merged union of all ranges (CIDR blocks already trimmed).
    ranges: Vec<(u32, u32)>,
    /// Merged union of the CIDR blocks: addresses here are exempt from the .0/.255 rule.
    exact: Vec<(u32, u32)>,
    skip_edges: bool,
}
fn is_edge(v: u32) -> bool {
    matches!(v & 255, 0 | 255)
}
fn count_mod(lo: u32, hi: u32, r: i64) -> u64 {
    let (lo, hi) = (lo as i64, hi as i64);
    ((hi - r).div_euclid(256) - (lo - 1 - r).div_euclid(256)) as u64
}
fn contains(ranges: &[(u32, u32)], v: u32) -> bool {
    let i = ranges.partition_point(|r| r.1 < v);
    ranges.get(i).is_some_and(|r| r.0 <= v)
}
fn merge(mut ranges: Vec<(u32, u32)>) -> Vec<(u32, u32)> {
    ranges.sort_unstable();
    let mut merged: Vec<(u32, u32)> = vec![];
    for (a, b) in ranges {
        match merged.last_mut() {
            Some(last) if u64::from(a) <= u64::from(last.1) + 1 => last.1 = last.1.max(b),
            _ => merged.push((a, b)),
        }
    }
    merged
}
impl Targets {
    fn skipped(&self, v: u32) -> bool {
        self.skip_edges && is_edge(v) && !contains(&self.exact, v)
    }
    fn covered(&self, v: u32) -> bool {
        contains(&self.ranges, v) && !self.skipped(v)
    }
    pub fn count(&self) -> u64 {
        let mut n = self.singles.len() as u64;
        for &(a, b) in &self.ranges {
            n += u64::from(b) - u64::from(a) + 1;
            if self.skip_edges {
                n -= count_mod(a, b, 0) + count_mod(a, b, 255);
            }
        }
        if self.skip_edges {
            // `exact` is a subset of `ranges`; its .0/.255 addresses are scanned after all.
            for &(a, b) in &self.exact {
                n += count_mod(a, b, 0) + count_mod(a, b, 255);
            }
        }
        let overlap = self
            .singles
            .iter()
            .filter(|ip| matches!(ip, IpAddr::V4(v) if self.covered(u32::from(*v))))
            .count() as u64;
        n - overlap
    }
    /// The target list as it is stored: single addresses and merged IPv4 ranges (as numbers).
    /// The scope guard judges these without expanding them.
    pub fn spans(&self) -> (Vec<IpAddr>, Vec<(u32, u32)>) {
        (self.singles.clone(), self.ranges.clone())
    }
    pub fn iter(&self) -> TargetIter {
        TargetIter {
            singles: self.singles.clone().into_iter(),
            single_v4: self
                .singles
                .iter()
                .filter_map(|ip| match ip {
                    IpAddr::V4(v) => Some(u32::from(*v)),
                    _ => None,
                })
                .collect(),
            ranges: self.ranges.clone(),
            index: 0,
            next: self.ranges.first().map(|r| u64::from(r.0)).unwrap_or(0),
            targets: self.clone_without_singles(),
        }
    }
    fn clone_without_singles(&self) -> Targets {
        Targets {
            singles: vec![],
            ranges: vec![],
            exact: self.exact.clone(),
            skip_edges: self.skip_edges,
        }
    }
}
pub struct TargetIter {
    singles: std::vec::IntoIter<IpAddr>,
    single_v4: std::collections::HashSet<u32>,
    ranges: Vec<(u32, u32)>,
    index: usize,
    next: u64,
    /// Edge-skipping rules only (`exact`, `skip_edges`).
    targets: Targets,
}
impl Iterator for TargetIter {
    type Item = IpAddr;
    fn next(&mut self) -> Option<IpAddr> {
        if let Some(ip) = self.singles.next() {
            return Some(ip);
        }
        while let Some(&(_, end)) = self.ranges.get(self.index) {
            if self.next > u64::from(end) {
                self.index += 1;
                if let Some(r) = self.ranges.get(self.index) {
                    self.next = u64::from(r.0);
                }
                continue;
            }
            let v = self.next as u32;
            self.next += 1;
            if self.targets.skipped(v) || self.single_v4.contains(&v) {
                continue;
            }
            return Some(IpAddr::V4(Ipv4Addr::from(v)));
        }
        None
    }
}

pub fn parse_targets(input: &str, skip_edges: bool, limit: u64) -> Result<Targets, String> {
    let too_many = || format!("Limit each scan to {limit} addresses or fewer.");
    let mut singles = BTreeSet::new();
    let mut ranges: Vec<(u32, u32)> = vec![];
    let mut exact: Vec<(u32, u32)> = vec![];
    for token in input
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|s| !s.is_empty())
    {
        if let Ok(ip) = token.parse::<IpAddr>() {
            singles.insert(ip);
            continue;
        }
        let mut cidr = false;
        let (start, end) = if let Some((ip, prefix)) = token.split_once('/') {
            let ip = ip
                .parse::<Ipv4Addr>()
                .map_err(|_| "CIDR input must be IPv4.".to_string())?;
            let prefix = prefix
                .parse::<u32>()
                .ok()
                .filter(|&p| p <= 32)
                .ok_or("Invalid IPv4 prefix.")?;
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let start = u32::from(ip) & mask;
            cidr = true;
            if skip_edges && prefix <= 30 {
                // Only the block's own network and broadcast addresses.
                (start + 1, (start | !mask) - 1)
            } else {
                (start, start | !mask)
            }
        } else if let Some((a, b)) = token.split_once('-') {
            let a = a
                .parse::<Ipv4Addr>()
                .map_err(|_| "Invalid start address.".to_string())?;
            let b = if b.contains('.') {
                b.parse::<Ipv4Addr>()
                    .map_err(|_| "Invalid end address.".to_string())?
            } else {
                let last = b
                    .parse::<u8>()
                    .map_err(|_| "Invalid end address.".to_string())?;
                let mut bytes = a.octets();
                bytes[3] = last;
                Ipv4Addr::from(bytes)
            };
            (u32::from(a), u32::from(b))
        } else {
            return Err(format!(
                "Invalid address: {token}. Use an IP, IPv4 range, or CIDR."
            ));
        };
        if start > end {
            return Err("Address range must run from low to high.".into());
        }
        if u64::from(end) - u64::from(start) + 1 > limit {
            return Err(too_many());
        }
        ranges.push((start, end));
        if cidr {
            exact.push((start, end));
        }
    }
    let targets = Targets {
        singles: singles.into_iter().collect(),
        ranges: merge(ranges),
        exact: merge(exact),
        skip_edges,
    };
    match targets.count() {
        0 => Err("Enter at least one address to scan.".into()),
        n if n > limit => Err(too_many()),
        _ => Ok(targets),
    }
}

pub fn parse_hosts(input: &str, skip_edges: bool) -> Result<Vec<IpAddr>, String> {
    let mut hosts: Vec<IpAddr> = parse_targets(input, skip_edges, MAX_HOSTS as u64)?
        .iter()
        .collect();
    hosts.sort();
    Ok(hosts)
}

pub fn port_timeout(longest: Option<u32>, s: &Settings) -> Duration {
    let ms = if s.adaptive {
        longest
            .map(|p| {
                p.saturating_mul(3)
                    .max(s.minimum_timeout)
                    .min(s.port_timeout)
            })
            .unwrap_or(s.port_timeout)
    } else {
        s.port_timeout
    };
    Duration::from_millis(ms.max(1) as u64)
}

#[derive(Debug, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Unanswered,
    /// The connection was reset or aborted while connecting (not a plain refusal).
    Reset,
    Error(String),
}
#[cfg(test)]
pub fn probe_port(ip: IpAddr, port: u16, timeout: Duration) -> PortState {
    match std::net::TcpStream::connect_timeout(&std::net::SocketAddr::new(ip, port), timeout) {
        Ok(_) => PortState::Open,
        Err(e) => match e.kind() {
            std::io::ErrorKind::ConnectionRefused => PortState::Closed,
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => PortState::Unanswered,
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted => {
                PortState::Reset
            }
            _ => PortState::Error(e.to_string()),
        },
    }
}

pub enum Event {
    Host(Host),
    Done,
    Error(String),
}
pub struct Running {
    pub receiver: Receiver<Event>,
    pub cancel: Arc<AtomicBool>,
    pub pause: Arc<AtomicBool>,
    pub total: usize,
    pub started: Instant,
    /// What this scan has sent so far, by packet kind and detail (final after `Event::Done`).
    /// Save it with the scan as `store::Snapshot::sent`.
    pub sent: Arc<crate::sendlog::SentLog>,
}
impl Drop for Running {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

pub fn start(hosts: Vec<IpAddr>, ports: Vec<u16>, settings: Settings) -> Running {
    let total = hosts.len();
    start_stream(Box::new(hosts.into_iter()), total, ports, settings)
}

pub fn start_stream(
    hosts: Box<dyn Iterator<Item = IpAddr> + Send>,
    total: usize,
    ports: Vec<u16>,
    settings: Settings,
) -> Running {
    let (tx, receiver) = mpsc::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let pause = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(crate::sendlog::SentLog::new());
    let run = Running {
        receiver,
        cancel: cancel.clone(),
        pause: pause.clone(),
        total,
        started: Instant::now(),
        sent: sent.clone(),
    };
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .max_blocking_threads(512)
            .enable_all()
            .build();
        match runtime {
            Ok(rt) => {
                rt.block_on(crate::core::execute(
                    hosts,
                    ports,
                    settings,
                    cancel,
                    pause,
                    tx.clone(),
                    sent,
                ));
                rt.shutdown_timeout(Duration::from_secs(1));
            }
            Err(e) => {
                let _ = tx.send(Event::Error(e.to_string()));
            }
        }
        let _ = tx.send(Event::Done);
    });
    run
}

/// Quotes one CSV cell. Scanned strings (banners, hostnames, SNMP text) are untrusted,
/// so a cell that a spreadsheet would read as a formula (leading `=`, `+`, `-`, `@`,
/// tab or carriage return) gets a leading `'` (OWASP CSV injection guidance). Plain
/// numbers such as `-1` or `+5` are left alone: spreadsheets read them as numbers.
pub fn csv_cell(value: &str) -> String {
    let numeric = value.parse::<f64>().is_ok_and(f64::is_finite)
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'+' | b'e' | b'E'));
    let risky = value.starts_with(['=', '+', '-', '@', '\t', '\r']) && !numeric;
    let prefix = if risky { "'" } else { "" };
    format!("\"{prefix}{}\"", value.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn address_inputs_and_limits() {
        // A /30 has two usable hosts: network (.0) and broadcast (.3) are skipped.
        assert_eq!(parse_hosts("192.168.1.0/30", true).unwrap().len(), 2);
        assert_eq!(
            parse_hosts("192.168.1.1-3,192.168.1.2 ::1", true)
                .unwrap()
                .len(),
            4
        );
        assert_eq!(parse_hosts("127.0.0.1/32", true).unwrap().len(), 1);
        assert!(parse_hosts("10.0.0.0/8", false).is_err());
        assert!(parse_hosts("10.0.0.4-1", false).is_err());
        assert!(parse_hosts("", false).is_err());
    }
    #[test]
    fn port_inputs() {
        assert_eq!(
            parse_ports("80,443,80,8000-8002").unwrap(),
            vec![80, 443, 8000, 8001, 8002]
        );
        for s in ["", "0", "65536", "90-80"] {
            assert!(parse_ports(s).is_err());
        }
    }
    #[test]
    fn adaptive_bounds() {
        let s = Settings::default();
        assert_eq!(port_timeout(Some(0), &s).as_millis(), 100);
        assert_eq!(port_timeout(Some(1000), &s).as_millis(), 2000);
        assert_eq!(port_timeout(Some(50), &s).as_millis(), 150);
        assert_eq!(port_timeout(None, &s).as_millis(), 2000);
    }
    #[test]
    fn top_ports_are_unique_and_selectable() {
        let unique: BTreeSet<_> = TOP_PORTS.iter().collect();
        assert_eq!(unique.len(), TOP_PORTS.len());
        assert_eq!(parse_ports("top:3").unwrap(), vec![23, 80, 443]);
        assert_eq!(parse_ports("top:2,22").unwrap(), vec![22, 23, 80]);
        assert_eq!(parse_ports("top:100").unwrap().len(), 100);
        for s in ["top:0", "top:101", "top:x", "top:"] {
            assert!(parse_ports(s).is_err(), "{s}");
        }
    }
    #[test]
    fn large_ranges_stream_without_expansion() {
        let t = parse_targets("10.0.0.0/8", true, MAX_STREAM).unwrap();
        // Only 10.0.0.0 and 10.255.255.255 are network/broadcast in a /8.
        assert_eq!(t.count(), (1 << 24) - 2);
        let first: Vec<_> = t.iter().take(3).collect();
        assert_eq!(
            first,
            ["10.0.0.1", "10.0.0.2", "10.0.0.3"].map(|s| s.parse::<IpAddr>().unwrap())
        );
        assert_eq!(t.iter().last().unwrap().to_string(), "10.255.255.254");
        assert!(parse_targets("10.0.0.0/7", true, MAX_STREAM).is_err());
    }
    #[test]
    fn target_overlaps_merge_and_count_matches_iteration() {
        for (input, edges) in [
            ("10.0.0.0/24 10.0.0.128/25 10.0.1.0/24", true),
            ("10.0.0.0/30 10.0.0.1 10.0.0.0 ::1 ::1", true),
            ("10.0.0.0/30 10.0.0.1 10.0.0.0 ::1 ::1", false),
            ("192.168.1.250-255 192.168.1.255", true),
            ("10.0.0.0/23 10.0.0.250-10.0.2.5", true),
            ("10.0.0.0/24 10.0.0.0-10.0.1.10 10.0.1.255/31", true),
            ("10.0.0.0/22 10.0.1.0/24 10.0.3.255/32", true),
            ("10.0.0.0/22 10.0.1.0/24 10.0.3.255/32", false),
        ] {
            let t = parse_targets(input, edges, 1 << 20).unwrap();
            let all: Vec<_> = t.iter().collect();
            let unique: BTreeSet<_> = all.iter().collect();
            assert_eq!(all.len(), unique.len(), "{input}");
            assert_eq!(all.len() as u64, t.count(), "{input}");
        }
        assert_eq!(
            parse_targets("10.0.0.0/24 10.0.0.128/25 10.0.1.0/24", false, 1 << 20)
                .unwrap()
                .count(),
            512
        );
    }
    #[test]
    fn default_scan_is_not_throttled_by_launch_spacing() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let s = Settings {
            tcp_only: true,
            safe: false,
            ..Settings::default()
        };
        assert_eq!(s.delay, 20);
        let ports: Vec<u16> = (0..8).map(|i| addr.port().wrapping_add(i)).collect();
        let started = Instant::now();
        let run = start(vec![addr.ip(); 64], ports, s);
        let mut hosts = 0;
        loop {
            match run.receiver.recv_timeout(Duration::from_secs(20)).unwrap() {
                Event::Host(h) => {
                    hosts += 1;
                    assert!(h.open.contains(&addr.port()));
                }
                Event::Done => break,
                Event::Error(e) => panic!("{e}"),
            }
        }
        assert_eq!(hosts, 64);
        // 512 probes at the old 20 ms global gate would need over 10 seconds.
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    }
    #[test]
    fn closed_port_is_reported_closed() {
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let s = Settings {
            tcp_only: true,
            safe: false,
            retries: 0,
            port_timeout: 5000,
            ..Settings::default()
        };
        let run = start(vec![closed.ip()], vec![closed.port()], s);
        let Event::Host(h) = run.receiver.recv_timeout(Duration::from_secs(10)).unwrap() else {
            panic!("missing host")
        };
        assert!(h.open.is_empty());
        assert_eq!((h.closed, h.unanswered, &h.errors), (1, 0, &vec![]));
        assert!(h.responding);
    }
    #[test]
    fn edges_are_the_true_network_and_broadcast_addresses() {
        let hosts = |input: &str| -> Vec<String> {
            parse_hosts(input, true)
                .unwrap()
                .iter()
                .map(ToString::to_string)
                .collect()
        };
        // Inside a /23, .255 and .0 at the /24 boundary are ordinary hosts.
        let h = hosts("10.0.0.0/23");
        assert_eq!(h.len(), 510);
        assert!(h.contains(&"10.0.0.255".to_string()));
        assert!(h.contains(&"10.0.1.0".to_string()));
        assert!(!h.contains(&"10.0.0.0".to_string()));
        assert!(!h.contains(&"10.0.1.255".to_string()));
        // A /25 that starts mid-octet loses its own edges, not .0/.255.
        let h = hosts("10.0.0.128/25");
        assert_eq!(h.first().unwrap(), "10.0.0.129");
        assert_eq!(h.last().unwrap(), "10.0.0.254");
        assert_eq!(hosts("10.0.0.64/26").len(), 62);
        // /31 and /32 are never trimmed, even on .0/.255.
        assert_eq!(hosts("10.0.0.255/32"), ["10.0.0.255"]);
        assert_eq!(hosts("10.0.0.0/32"), ["10.0.0.0"]);
        assert_eq!(hosts("10.0.0.254/31"), ["10.0.0.254", "10.0.0.255"]);
        // Dash ranges keep the documented legacy rule (skip every .0 and .255).
        assert_eq!(
            hosts("10.0.0.250-10.0.1.2"),
            [
                "10.0.0.250",
                "10.0.0.251",
                "10.0.0.252",
                "10.0.0.253",
                "10.0.0.254",
                "10.0.1.1",
                "10.0.1.2"
            ]
        );
        // Without the option nothing is trimmed.
        assert_eq!(parse_hosts("10.0.0.0/30", false).unwrap().len(), 4);
    }
    #[test]
    fn new_engine_options_are_off_in_old_snapshots() {
        let old: Settings = serde_json::from_str(r#"{"ports":"22","safe":false}"#).unwrap();
        assert!(!old.arp_sweep && !old.syn_adaptive && !old.tcp_adaptive && !old.jarm);
        assert!(
            old.backoff,
            "old snapshots and settings files get the back-off"
        );
        assert_eq!(old.trace_method, crate::trace::TraceMethod::Icmp);
        assert_eq!(old.trace_port, 0);
        let tcp: Settings = serde_json::from_str(r#"{"trace_method":"tcp"}"#).unwrap();
        assert_eq!(tcp.trace_method, crate::trace::TraceMethod::Tcp);
        let text = serde_json::to_string(&Settings {
            trace_method: crate::trace::TraceMethod::Udp,
            ..Settings::default()
        })
        .unwrap();
        assert!(text.contains(r#""trace_method":"udp""#), "{text}");
    }
    #[test]
    fn csv_quotes() {
        assert_eq!(csv_cell("a,\"b\""), "\"a,\"\"b\"\"\"");
    }
    #[test]
    fn csv_cells_cannot_start_formulas() {
        for (input, expected) in [
            ("=HYPERLINK(\"x\")", "\"'=HYPERLINK(\"\"x\"\")\""),
            ("+cmd", "\"'+cmd\""),
            ("-2+3+cmd|' /C calc'!A0", "\"'-2+3+cmd|' /C calc'!A0\""),
            ("@SUM(A1)", "\"'@SUM(A1)\""),
            ("\tx", "\"'\tx\""),
            ("\rx", "\"'\rx\""),
            ("-inf", "\"'-inf\""),
            ("nan", "\"nan\""),
            ("plc-1", "\"plc-1\""),
            // Our own numeric cells keep their value.
            ("-1", "\"-1\""),
            ("+5", "\"+5\""),
            ("-12.5e3", "\"-12.5e3\""),
            ("502", "\"502\""),
            ("", "\"\""),
        ] {
            assert_eq!(csv_cell(input), expected, "{input:?}");
        }
    }
    #[test]
    fn real_loopback_tcp_scan() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        assert_eq!(
            probe_port(addr.ip(), addr.port(), Duration::from_millis(500)),
            PortState::Open
        );
        let s = Settings {
            tcp_only: true,
            delay: 0,
            ..Settings::default()
        };
        let run = start(vec![addr.ip()], vec![addr.port()], s);
        let Event::Host(host) = run.receiver.recv_timeout(Duration::from_secs(5)).unwrap() else {
            panic!("Missing host")
        };
        assert!(host.responding);
        assert_eq!(host.open, vec![addr.port()]);
        assert!(matches!(
            run.receiver.recv_timeout(Duration::from_secs(5)).unwrap(),
            Event::Done
        ));
    }
    #[cfg(windows)]
    #[test]
    fn native_loopback_ping() {
        assert!(
            crate::platform::echo("127.0.0.1".parse().unwrap(), 1000)
                .rtt
                .is_some()
        );
    }

    #[cfg(windows)]
    #[test]
    fn native_ipv6_loopback_ping() {
        let echo = crate::platform::echo("::1".parse().unwrap(), 1000);
        assert!(echo.rtt.is_some(), "{echo:?}");
    }

    #[test]
    fn stop_interrupts_queued_hosts() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let settings = Settings {
            tcp_only: true,
            delay: 1000,
            workers: 16,
            ..Settings::default()
        };
        let run = start(vec![addr.ip(); 32], vec![addr.port()], settings);
        assert!(matches!(
            run.receiver.recv_timeout(Duration::from_secs(5)).unwrap(),
            Event::Host(_)
        ));
        run.cancel.store(true, Ordering::Relaxed);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match run
                .receiver
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .unwrap()
            {
                Event::Done => break,
                Event::Host(_) => (),
                Event::Error(e) => panic!("{e}"),
            }
        }
    }
}
