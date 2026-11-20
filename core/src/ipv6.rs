//! IPv6 discovery (ROADMAP C21): what is on the local link, found without a target list.
//!
//! IPv6 has no address range to sweep, so a scan cannot find hosts by trying addresses. Three
//! sources answer "who is here":
//!
//! 1. **Multicast echo**: one ICMPv6 Echo Request to `ff02::1` (all nodes on the link) per
//!    selected interface, hop limit 1, so it never leaves the link. Hosts that answer ICMPv6 echo
//!    reply to it. Opt-in (`--ipv6-discover`); it is the only part of this module that sends, one
//!    datagram per interface through the rate gate (`PacketKind::Ipv6Echo`), also in Safe Mode,
//!    where one echo request per interface is a single request like the ICMP ping.
//! 2. **The OS neighbour cache**: the IPv6 neighbours the operating system has already resolved
//!    (Windows `GetIpNetTable2`, Linux `ip -6 neigh show`, macOS `ndp -an`). Reading it sends
//!    nothing; the echo above fills it with every host that answered, so the two are used
//!    together.
//! 3. **Passive NDP** (`passive::decode`: Neighbor and Router Advertisements and Solicitations)
//!    in the listening commands; that code never transmits.
//!
//! The results are joined to the scanned hosts by **MAC address**: a host that has an IPv4
//! record with the same MAC gets the IPv6 addresses in its identity (`ipv6.addresses`), and a MAC
//! nothing else knows becomes a host of its own. [`devices::merge`](crate::devices::merge) joins
//! them again, by the same MAC, into one device.
use crate::{core::Gate, passive::Observation, scan::Host, scan::Settings, sendlog::PacketKind};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    time::{Duration, Instant},
};

/// All nodes on the link.
pub const ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
/// What the echo is called in the plan and the sent log.
pub const DETAIL: &str = "echo request to ff02::1 (all nodes)";
/// Most interfaces that get an echo in one run.
pub const MAX_INTERFACES: usize = 8;
/// Most neighbours kept from the cache (a router can hold thousands).
pub const MAX_NEIGHBORS: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    pub index: u32,
    pub name: String,
}

/// The state of a neighbour cache entry. Only those that prove the neighbour answered recently
/// make it a host; a stale entry is a MAC and an address, not proof that it is up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Reachable,
    Delay,
    Probe,
    Permanent,
    Stale,
}
impl State {
    pub fn name(self) -> &'static str {
        match self {
            Self::Reachable => "reachable",
            Self::Delay => "delay",
            Self::Probe => "probe",
            Self::Permanent => "permanent",
            Self::Stale => "stale",
        }
    }
    pub fn fresh(self) -> bool {
        matches!(self, Self::Reachable | Self::Delay | Self::Probe)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Neighbor {
    pub ip: Ipv6Addr,
    /// `AA:BB:CC:DD:EE:FF`
    pub mac: String,
    /// The interface, by name or index as the source reports it.
    pub interface: String,
    pub state: State,
}

/// What a run found.
#[derive(Clone, Debug, Default)]
pub struct Found {
    /// Interfaces that got an echo.
    pub interfaces: Vec<Interface>,
    /// Addresses that answered the multicast echo, with the interface.
    pub responders: Vec<(Ipv6Addr, String)>,
    pub neighbors: Vec<Neighbor>,
    /// What could not be done (no raw socket, no permission, no interface).
    pub notes: Vec<String>,
}

/// `--ipv6-discover` was given.
pub fn enabled(s: &Settings) -> bool {
    s.ipv6_discover
}

/// The gate of a discovery run: the same pacing as the scan's (Safe Mode spacing, `--rate`), and
/// the scan's sent log.
pub fn gate(s: &Settings, log: std::sync::Arc<crate::sendlog::SentLog>) -> Gate {
    if s.safe {
        Gate::new(s.delay.max(100)).with_safe(true)
    } else if s.max_rate > 0 {
        let rate = f64::from(s.max_rate);
        Gate::per_second(rate, (rate / 10.0).max(1.0))
    } else {
        Gate::unlimited()
    }
    .with_log(log)
}

// ---- parsing the OS's text --------------------------------------------------------------------

/// `AA:BB:CC:DD:EE:FF` from a MAC as the OS prints it (`aa:bb:cc:dd:ee:ff`, or `0:1b:21:a:b:c` on
/// the BSDs and macOS, which do not pad). Anything but six hex bytes, and all-zero, is `None`.
pub fn normalize_mac(text: &str) -> Option<String> {
    let parts: Vec<u8> = text
        .split([':', '-'])
        .map(|p| {
            (!p.is_empty() && p.len() <= 2)
                .then(|| u8::from_str_radix(p, 16).ok())
                .flatten()
        })
        .collect::<Option<_>>()?;
    if parts.len() != 6 || parts.iter().all(|b| *b == 0) {
        return None;
    }
    Some(
        parts
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Not an address of a host: multicast, unspecified, loopback.
fn is_host_address(ip: &Ipv6Addr) -> bool {
    !(ip.is_multicast() || ip.is_unspecified() || ip.is_loopback())
}

fn parse_addr(token: &str) -> Option<Ipv6Addr> {
    token.split('%').next()?.parse().ok()
}

/// Linux `ip -6 neigh show`: `fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff router REACHABLE`.
/// Entries without a link-layer address (FAILED, INCOMPLETE) are skipped.
pub fn parse_ip_neigh6(text: &str) -> Vec<Neighbor> {
    let mut out = vec![];
    for line in text.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let (Some(ip), Some(state)) = (tokens.first().and_then(|t| parse_addr(t)), tokens.last())
        else {
            continue;
        };
        let after = |key: &str| {
            tokens
                .iter()
                .position(|t| *t == key)
                .and_then(|i| tokens.get(i + 1))
        };
        let (Some(mac), Some(dev)) = (after("lladdr").and_then(|m| normalize_mac(m)), after("dev"))
        else {
            continue;
        };
        let state = match state.to_ascii_uppercase().as_str() {
            "REACHABLE" => State::Reachable,
            "DELAY" => State::Delay,
            "PROBE" => State::Probe,
            "PERMANENT" => State::Permanent,
            "STALE" => State::Stale,
            _ => continue,
        };
        if is_host_address(&ip) && out.len() < MAX_NEIGHBORS {
            out.push(Neighbor {
                ip,
                mac,
                interface: (*dev).to_string(),
                state,
            });
        }
    }
    out
}

/// macOS `ndp -an`: `Neighbor Linklayer Address Netif Expire St Flgs Prbs`, then rows such as
/// `fe80::1%en0 0:1b:21:aa:bb:cc en0 23h59m50s S R`. `(incomplete)` rows are skipped.
pub fn parse_ndp_an(text: &str) -> Vec<Neighbor> {
    let mut out = vec![];
    for line in text.lines().skip(1) {
        let t: Vec<&str> = line.split_whitespace().collect();
        let (Some(ip), Some(mac), Some(interface)) = (
            t.first().and_then(|a| parse_addr(a)),
            t.get(1).and_then(|m| normalize_mac(m)),
            t.get(2),
        ) else {
            continue;
        };
        let state = if t.get(3) == Some(&"permanent") {
            State::Permanent
        } else {
            match t.get(4).copied() {
                Some("R") => State::Reachable,
                Some("S") => State::Stale,
                Some("D") => State::Delay,
                Some("P") => State::Probe,
                _ => continue,
            }
        };
        if is_host_address(&ip) && out.len() < MAX_NEIGHBORS {
            out.push(Neighbor {
                ip,
                mac,
                interface: (*interface).to_string(),
                state,
            });
        }
    }
    out
}

/// Linux `/proc/net/if_inet6`: `fe80...(32 hex) 02 40 20 80 eth0` (index, prefix length, scope
/// 0x20 = link-local, flags, name). Returns the interfaces with a link-local address and every
/// local address.
pub fn parse_if_inet6(text: &str) -> (Vec<Interface>, Vec<Ipv6Addr>) {
    let (mut interfaces, mut local) = (vec![], vec![]);
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        let (Some(hex), Some(index), Some(scope), Some(name)) =
            (f.first(), f.get(1), f.get(3), f.get(5))
        else {
            continue;
        };
        let (Ok(bits), Ok(index), Ok(scope)) = (
            u128::from_str_radix(hex, 16),
            u32::from_str_radix(index, 16),
            u32::from_str_radix(scope, 16),
        ) else {
            continue;
        };
        if hex.len() != 32 {
            continue;
        }
        local.push(Ipv6Addr::from(bits));
        if scope == 0x20 && !interfaces.iter().any(|i: &Interface| i.index == index) {
            interfaces.push(Interface {
                index,
                name: (*name).to_string(),
            });
        }
    }
    (interfaces, local)
}

/// macOS `ifconfig -a`: an interface header (`en0: flags=...`) and lines such as
/// `inet6 fe80::1%en0 prefixlen 64 secured scopeid 0x4`.
pub fn parse_ifconfig_inet6(text: &str) -> (Vec<Interface>, Vec<Ipv6Addr>) {
    let (mut interfaces, mut local) = (vec![], vec![]);
    let mut name = String::new();
    for line in text.lines() {
        if !line.starts_with([' ', '\t']) {
            name = line.split(':').next().unwrap_or_default().to_string();
            continue;
        }
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.first() != Some(&"inet6") {
            continue;
        }
        let Some(ip) = t.get(1).and_then(|a| parse_addr(a)) else {
            continue;
        };
        local.push(ip);
        let scope = t
            .iter()
            .position(|w| *w == "scopeid")
            .and_then(|i| t.get(i + 1))
            .and_then(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok());
        let link_local = ip.segments()[0] & 0xffc0 == 0xfe80;
        if let (true, Some(index)) = (link_local, scope)
            && !name.is_empty()
            && name != "lo0"
            && !interfaces.iter().any(|i: &Interface| i.index == index)
        {
            interfaces.push(Interface {
                index,
                name: name.clone(),
            });
        }
    }
    (interfaces, local)
}

/// The interfaces to send on: all of them (at most [`MAX_INTERFACES`]), or the one named by
/// `wanted` (the interface index or part of its name, case-insensitive).
pub fn select(all: &[Interface], wanted: &str) -> Vec<Interface> {
    let wanted = wanted.trim().to_ascii_lowercase();
    all.iter()
        .filter(|i| {
            wanted.is_empty()
                || wanted == i.index.to_string()
                || i.name.to_ascii_lowercase().contains(&wanted)
        })
        .take(MAX_INTERFACES)
        .cloned()
        .collect()
}

// ---- joining the results to hosts ------------------------------------------------------------

/// The observations of what was found: one per neighbour, and one per responder without a MAC.
/// The MAC and address in them are what [`devices::merge`](crate::devices::merge) joins on.
pub fn observations(found: &Found) -> Vec<Observation> {
    let responded: BTreeSet<Ipv6Addr> = found.responders.iter().map(|(ip, _)| *ip).collect();
    let mut out: Vec<Observation> = found
        .neighbors
        .iter()
        .map(|n| {
            let mut fields = BTreeMap::new();
            fields.insert("state".to_string(), n.state.name().to_string());
            fields.insert("interface".to_string(), n.interface.clone());
            fields.insert(
                "source".to_string(),
                if responded.contains(&n.ip) {
                    "multicast echo and neighbor cache"
                } else {
                    "neighbor cache"
                }
                .into(),
            );
            Observation {
                protocol: "IPv6 neighbor".into(),
                mac: n.mac.clone(),
                ip: Some(IpAddr::V6(n.ip)),
                fields,
            }
        })
        .collect();
    let known: BTreeSet<Ipv6Addr> = found.neighbors.iter().map(|n| n.ip).collect();
    for (ip, interface) in &found.responders {
        if !known.contains(ip) {
            out.push(Observation {
                protocol: "IPv6 neighbor".into(),
                mac: String::new(),
                ip: Some(IpAddr::V6(*ip)),
                fields: BTreeMap::from([
                    ("source".to_string(), "multicast echo".to_string()),
                    ("interface".to_string(), interface.clone()),
                ]),
            });
        }
    }
    out
}

fn rank(ip: &Ipv6Addr) -> u8 {
    // a global address first, then unique local, then link-local
    match ip.segments()[0] {
        s if s & 0xffc0 == 0xfe80 => 2,
        s if s & 0xfe00 == 0xfc00 => 1,
        _ => 0,
    }
}

/// Which neighbours become hosts of their own when they match no scanned host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddHosts {
    /// Those that answered the echo, or whose cache entry is reachable, delay or probe: what
    /// `scan` does.
    Fresh,
    /// Only those that answered **this run's** multicast echo (`monitor`). A cache entry that
    /// flips between reachable and stale from one cycle to the next would otherwise make a host
    /// appear and disappear; such a neighbour stays an observation.
    Answered,
}

/// [`merge_with`] with [`AddHosts::Fresh`].
pub fn merge(hosts: &mut Vec<Host>, found: &Found) -> usize {
    merge_with(hosts, found, AddHosts::Fresh)
}

/// Joins what was found to the scanned hosts **by MAC address**. A host whose MAC a neighbour
/// has gets its addresses in `ipv6.addresses` (and `ipv6.source`); a neighbour whose MAC no host
/// has, and that answered recently (see [`AddHosts`]), is added as a host of its own with its
/// best address. Other entries and responders without a MAC are only observations. Returns how
/// many hosts were added.
pub fn merge_with(hosts: &mut Vec<Host>, found: &Found, add: AddHosts) -> usize {
    let responded: BTreeSet<Ipv6Addr> = found.responders.iter().map(|(ip, _)| *ip).collect();
    // MAC -> (addresses, fresh evidence, interface)
    let mut by_mac: BTreeMap<String, (BTreeSet<Ipv6Addr>, bool, String)> = BTreeMap::new();
    for n in &found.neighbors {
        let e = by_mac.entry(n.mac.clone()).or_default();
        e.0.insert(n.ip);
        e.1 |= match add {
            AddHosts::Fresh => n.state.fresh() || responded.contains(&n.ip),
            AddHosts::Answered => responded.contains(&n.ip),
        };
        e.2 = n.interface.clone();
    }
    let mut added = 0;
    for (mac, (addresses, fresh, interface)) in by_mac {
        let mut list: Vec<Ipv6Addr> = addresses.into_iter().collect();
        list.sort_by_key(|a| (rank(a), *a));
        list.truncate(8);
        let text = list
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let source = if list.iter().any(|a| responded.contains(a)) {
            "multicast echo"
        } else {
            "neighbor cache"
        };
        let existing = hosts
            .iter_mut()
            .find(|h| h.ip.is_ipv4() && normalize_mac(&h.mac).as_deref() == Some(mac.as_str()));
        if let Some(h) = existing {
            h.identity.insert("ipv6.addresses".into(), text);
            h.identity.insert("ipv6.source".into(), source.into());
            continue;
        }
        if !fresh
            || hosts.iter().any(|h| {
                list.contains(match &h.ip {
                    IpAddr::V6(a) => a,
                    IpAddr::V4(_) => &ALL_NODES,
                })
            })
        {
            continue;
        }
        hosts.push(Host {
            ip: IpAddr::V6(list[0]),
            responding: true,
            ping: None,
            ttl: None,
            hostname: String::new(),
            mac,
            open: vec![],
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: false,
            identity: BTreeMap::from([
                ("ipv6.addresses".to_string(), text),
                ("ipv6.source".to_string(), source.to_string()),
                ("ipv6.interface".to_string(), interface),
            ]),
            udp_open: vec![],
            trace: vec![],
        });
        added += 1;
    }
    added
}

/// What the IPv6 step after a scan produced.
#[derive(Debug, Default)]
pub struct Outcome {
    pub found: Found,
    /// Observations to save with the scan.
    pub observations: Vec<Observation>,
    /// Hosts added to the list.
    pub added: usize,
}
impl Outcome {
    /// One line for the status bar and the terminal.
    pub fn summary(&self) -> String {
        format!(
            "IPv6: {} interface(s), {} answered the multicast echo, {} neighbor(s) in the cache, {} host(s) added",
            self.found.interfaces.len(),
            self.found.responders.len(),
            self.found.neighbors.len(),
            self.added
        )
    }
}

/// The IPv6 step after a finished scan, shared by `scan`, `monitor` and the desktop: one
/// multicast echo per selected interface through the scan's own pacing and sent log (`sent`),
/// then the OS neighbour cache, joined to `hosts` by MAC. It blocks for the echo's wait on every
/// interface (up to [`MAX_INTERFACES`] times the port timeout), so a window runs it off its UI
/// thread. Does nothing, and sends nothing, unless `--ipv6-discover` is on.
pub fn after_scan(
    s: &Settings,
    sent: std::sync::Arc<crate::sendlog::SentLog>,
    hosts: &mut Vec<Host>,
    add: AddHosts,
) -> Outcome {
    after_scan_with(
        s,
        sent,
        hosts,
        add,
        &Os {
            interfaces: &os_interfaces,
            echo: &|i, wait| os_echo(i, wait),
            cache: &os_neighbor_cache,
        },
    )
}

/// [`after_scan`] with the operating system replaced (tests).
pub fn after_scan_with(
    s: &Settings,
    sent: std::sync::Arc<crate::sendlog::SentLog>,
    hosts: &mut Vec<Host>,
    add: AddHosts,
    os: &Os<'_>,
) -> Outcome {
    if !enabled(s) {
        return Outcome::default();
    }
    let gate = gate(s, sent);
    let found = discover_with(s, &gate, os);
    let observations = observations(&found);
    let added = merge_with(hosts, &found, add);
    Outcome {
        found,
        observations,
        added,
    }
}

// ---- the run ---------------------------------------------------------------------------------

/// The pieces of a run that touch the operating system, so a test can stand in for them.
#[allow(clippy::type_complexity)]
pub struct Os<'a> {
    pub interfaces: &'a dyn Fn() -> Result<(Vec<Interface>, Vec<Ipv6Addr>), String>,
    /// Sends one echo request to `ff02::1` on the interface and returns the sources of the replies.
    pub echo: &'a dyn Fn(&Interface, Duration) -> Result<Vec<Ipv6Addr>, String>,
    pub cache: &'a dyn Fn() -> Result<Vec<Neighbor>, String>,
}

/// Runs the discovery against the real operating system.
pub fn discover(s: &Settings, gate: &Gate) -> Found {
    discover_with(
        s,
        gate,
        &Os {
            interfaces: &os_interfaces,
            echo: &|i, wait| os_echo(i, wait),
            cache: &os_neighbor_cache,
        },
    )
}

pub fn discover_with(s: &Settings, gate: &Gate, os: &Os<'_>) -> Found {
    let mut found = Found::default();
    let wait = Duration::from_millis(u64::from(s.port_timeout.clamp(500, 3000)));
    let mut local: Vec<Ipv6Addr> = vec![];
    let mut seen = BTreeSet::new();
    // What the cache held before the echo: an entry that appears afterwards is a host that
    // answered, even if the ICMP API handed back fewer replies than there were.
    let mut before: Option<BTreeSet<Ipv6Addr>> = None;
    match (os.interfaces)() {
        Ok((all, addresses)) => {
            local = addresses;
            let chosen = select(&all, &s.interface);
            if chosen.is_empty() {
                found.notes.push(if all.is_empty() {
                    "IPv6 discovery: no interface has a link-local IPv6 address".into()
                } else {
                    format!(
                        "IPv6 discovery: no interface matches '{}' (interfaces: {})",
                        s.interface,
                        all.iter()
                            .map(|i| format!("{} {}", i.index, i.name))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                });
            }
            if !chosen.is_empty() {
                before = Some(
                    (os.cache)()
                        .map(|c| c.into_iter().map(|n| n.ip).collect())
                        .unwrap_or_default(),
                );
            }
            for interface in chosen {
                // one token per datagram, recorded in the sent log
                loop {
                    match gate.try_take_for(PacketKind::Ipv6Echo, DETAIL) {
                        Ok(()) => break,
                        Err(w) => std::thread::sleep(w.min(Duration::from_secs(1))),
                    }
                }
                match (os.echo)(&interface, wait) {
                    Ok(sources) => {
                        for ip in sources {
                            // our own addresses answer the multicast too
                            if is_host_address(&ip) && !local.contains(&ip) && seen.insert(ip) {
                                found.responders.push((ip, interface.name.clone()));
                            }
                        }
                    }
                    Err(e) => found
                        .notes
                        .push(format!("IPv6 echo on {}: {e}", interface.name)),
                }
                found.interfaces.push(interface);
            }
        }
        Err(e) => found.notes.push(format!("IPv6 discovery: {e}")),
    }
    match (os.cache)() {
        Ok(mut neighbors) => {
            neighbors.truncate(MAX_NEIGHBORS);
            if let Some(before) = &before {
                for n in &neighbors {
                    if !before.contains(&n.ip)
                        && is_host_address(&n.ip)
                        && !local.contains(&n.ip)
                        && seen.insert(n.ip)
                    {
                        found.responders.push((n.ip, n.interface.clone()));
                    }
                }
            }
            found.neighbors = neighbors;
        }
        Err(e) => found.notes.push(format!("IPv6 neighbor cache: {e}")),
    }
    found
}

fn run(program: &str, args: &[&str]) -> Result<String, String> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn os_interfaces() -> Result<(Vec<Interface>, Vec<Ipv6Addr>), String> {
    if cfg!(windows) {
        win::interfaces()
    } else if cfg!(target_os = "macos") {
        Ok(parse_ifconfig_inet6(&run("ifconfig", &["-a"])?))
    } else {
        let text = std::fs::read_to_string("/proc/net/if_inet6")
            .map_err(|e| format!("/proc/net/if_inet6: {e}"))?;
        Ok(parse_if_inet6(&text))
    }
}

fn os_neighbor_cache() -> Result<Vec<Neighbor>, String> {
    if cfg!(windows) {
        win::neighbors()
    } else if cfg!(target_os = "macos") {
        Ok(parse_ndp_an(&run("ndp", &["-an"])?))
    } else {
        Ok(parse_ip_neigh6(&run("ip", &["-6", "neigh", "show"])?))
    }
}

fn os_echo(interface: &Interface, wait: Duration) -> Result<Vec<Ipv6Addr>, String> {
    if cfg!(windows) {
        win::multicast_echo(interface.index, wait)
    } else {
        socket_echo(interface.index, wait)
    }
}

/// ICMPv6 echo to `ff02::1` over an unprivileged datagram ICMP socket where the OS allows it
/// (Linux `ping_group_range`, macOS), else a raw socket (root). Every reply source is collected
/// until `wait` has passed. Compiled on every platform (Windows uses its ICMP API instead).
#[cfg_attr(windows, allow(dead_code))]
fn socket_echo(index: u32, wait: Duration) -> Result<Vec<Ipv6Addr>, String> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    let (socket, raw) = match Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6)) {
        Ok(s) => (s, false),
        Err(_) => (
            Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).map_err(|e| {
                format!("needs root or net.ipv4.ping_group_range for an ICMPv6 socket ({e})")
            })?,
            true,
        ),
    };
    socket
        .set_multicast_if_v6(index)
        .map_err(|e| e.to_string())?;
    socket.set_multicast_hops_v6(1).map_err(|e| e.to_string())?;
    let id = (std::process::id() & 0xffff) as u16;
    let seq = 0x4e53;
    let packet = crate::platform::icmp_request(128, id, seq, false);
    let to = SockAddr::from(SocketAddr::V6(SocketAddrV6::new(ALL_NODES, 0, 0, index)));
    socket
        .send_to(&packet, &to)
        .map_err(|e| format!("send failed: {e}"))?;
    let deadline = Instant::now() + wait;
    let mut out = vec![];
    let mut buffer = [std::mem::MaybeUninit::<u8>::uninit(); 1500];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || socket.set_read_timeout(Some(left)).is_err() {
            break;
        }
        let Ok((n, from)) = socket.recv_from(&mut buffer) else {
            break;
        };
        // SAFETY: recv_from initialised the first `n` bytes.
        let data: Vec<u8> = buffer[..n]
            .iter()
            .map(|b| unsafe { b.assume_init() })
            .collect();
        let Some((_, rid, rseq)) = crate::platform::parse_echo_reply(&data, false) else {
            continue;
        };
        let linux_dgram = !raw && cfg!(any(target_os = "linux", target_os = "android"));
        if !crate::platform::echo_matches(linux_dgram, (rid, rseq), (id, seq)) {
            continue;
        }
        if let Some(SocketAddr::V6(a)) = from.as_socket()
            && !out.contains(a.ip())
        {
            out.push(*a.ip());
        }
    }
    Ok(out)
}

// ---- Windows ---------------------------------------------------------------------------------

#[cfg_attr(not(windows), allow(dead_code, unused_imports))]
mod win {
    use super::{ALL_NODES, Interface, Neighbor, State, normalize_mac};
    use std::{net::Ipv6Addr, time::Duration};

    #[cfg(windows)]
    mod ffi {
        use std::ffi::c_void;
        #[link(name = "iphlpapi")]
        unsafe extern "system" {
            pub(super) fn GetIpNetTable2(family: u16, table: *mut *mut c_void) -> u32;
            pub(super) fn GetUnicastIpAddressTable(family: u16, table: *mut *mut c_void) -> u32;
            pub(super) fn FreeMibTable(memory: *mut c_void);
            pub(super) fn ConvertInterfaceIndexToLuid(index: u32, luid: *mut u64) -> u32;
            pub(super) fn ConvertInterfaceLuidToAlias(
                luid: *const u64,
                alias: *mut u16,
                len: usize,
            ) -> u32;
        }
    }

    // Layouts of the rows `GetIpNetTable2` and `GetUnicastIpAddressTable` return (netioapi.h),
    // read at fixed offsets from the table. The table is `ULONG NumEntries` padded to 8 bytes, then
    // the rows. Both layouts were checked against `Get-NetNeighbor` and `Get-NetIPAddress` on a
    // Windows 11 machine (see the tests of this module).
    pub(super) const TABLE_HEADER: usize = 8;
    /// MIB_IPNET_ROW2: Address (SOCKADDR_INET, 28), InterfaceIndex (28), InterfaceLuid (32),
    /// PhysicalAddress[32] (40), PhysicalAddressLength (72), State (76), flags (80), time (84).
    pub(super) const NET_ROW: usize = 88;
    /// MIB_UNICASTIPADDRESS_ROW: Address (28), InterfaceLuid (32), InterfaceIndex (40),
    /// PrefixOrigin (44), SuffixOrigin (48), lifetimes (52, 56), OnLinkPrefixLength (60),
    /// SkipAsSource (61), DadState (64), ScopeId (68), CreationTimeStamp (72).
    pub(super) const UNICAST_ROW: usize = 80;

    fn u32_at(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
    }
    /// The IPv6 address of a SOCKADDR_INET at the start of `row` (family 23).
    fn address_at(row: &[u8]) -> Option<Ipv6Addr> {
        if u16::from_le_bytes([row[0], row[1]]) != 23 {
            return None;
        }
        Some(Ipv6Addr::from(<[u8; 16]>::try_from(&row[8..24]).ok()?))
    }

    /// Neighbours of a raw `GetIpNetTable2` table (rows of [`NET_ROW`] bytes after the header).
    pub(super) fn parse_net_rows(rows: &[u8]) -> Vec<Neighbor> {
        rows.as_chunks::<NET_ROW>()
            .0
            .iter()
            .filter_map(|row| {
                let ip = address_at(row)?;
                let len = u32_at(row, 72) as usize;
                let mac = (len == 6)
                    .then(|| {
                        row[40..46]
                            .iter()
                            .map(|b| format!("{b:02X}"))
                            .collect::<Vec<_>>()
                            .join(":")
                    })
                    .and_then(|m| normalize_mac(&m))?;
                // NL_NEIGHBOR_STATE: 0 unreachable, 1 incomplete, 2 probe, 3 delay, 4 stale,
                // 5 reachable, 6 permanent
                let state = match u32_at(row, 76) {
                    2 => State::Probe,
                    3 => State::Delay,
                    4 => State::Stale,
                    5 => State::Reachable,
                    6 => State::Permanent,
                    _ => return None,
                };
                (!ip.is_multicast() && !ip.is_unspecified()).then_some(Neighbor {
                    ip,
                    mac,
                    interface: u32_at(row, 28).to_string(),
                    state,
                })
            })
            .collect()
    }

    /// (interface index, address, DAD state) of the rows of `GetUnicastIpAddressTable`.
    pub(super) fn parse_unicast_rows(rows: &[u8]) -> Vec<(u32, Ipv6Addr, u32)> {
        rows.as_chunks::<UNICAST_ROW>()
            .0
            .iter()
            .filter_map(|row| Some((u32_at(row, 40), address_at(row)?, u32_at(row, 64))))
            .collect()
    }

    #[cfg(windows)]
    fn table(
        call: unsafe extern "system" fn(u16, *mut *mut std::ffi::c_void) -> u32,
        row: usize,
    ) -> Result<Vec<u8>, String> {
        let mut ptr: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: the call fills `ptr` with a table that `FreeMibTable` releases; the rows are
        // copied out before that, bounded by the entry count the table itself reports.
        unsafe {
            let code = call(23, &mut ptr);
            if code != 0 || ptr.is_null() {
                return Err(std::io::Error::from_raw_os_error(code as i32).to_string());
            }
            let base = ptr.cast::<u8>();
            let count = (*base.cast::<u32>()) as usize;
            let rows = count.min(65_536);
            let bytes = std::slice::from_raw_parts(base.add(TABLE_HEADER), rows * row).to_vec();
            ffi::FreeMibTable(ptr);
            Ok(bytes)
        }
    }

    #[cfg(windows)]
    fn alias(index: u32) -> String {
        let mut luid = 0u64;
        let mut name = [0u16; 257];
        // SAFETY: both buffers are local and sized as declared.
        unsafe {
            if ffi::ConvertInterfaceIndexToLuid(index, &mut luid) == 0
                && ffi::ConvertInterfaceLuidToAlias(&luid, name.as_mut_ptr(), name.len()) == 0
            {
                let end = name.iter().position(|c| *c == 0).unwrap_or(name.len());
                return String::from_utf16_lossy(&name[..end]);
            }
        }
        format!("interface {index}")
    }

    #[cfg(windows)]
    pub(super) fn interfaces() -> Result<(Vec<Interface>, Vec<Ipv6Addr>), String> {
        let rows = parse_unicast_rows(&table(ffi::GetUnicastIpAddressTable, UNICAST_ROW)?);
        let local: Vec<Ipv6Addr> = rows.iter().map(|(_, a, _)| *a).collect();
        let mut interfaces: Vec<Interface> = vec![];
        for (index, address, dad) in rows {
            // a preferred (DAD state 4) link-local address
            if address.segments()[0] & 0xffc0 == 0xfe80
                && dad == 4
                && !interfaces.iter().any(|i| i.index == index)
            {
                interfaces.push(Interface {
                    index,
                    name: alias(index),
                });
            }
        }
        Ok((interfaces, local))
    }
    #[cfg(not(windows))]
    pub(super) fn interfaces() -> Result<(Vec<Interface>, Vec<Ipv6Addr>), String> {
        Err("not Windows".into())
    }

    /// The raw rows of `GetIpNetTable2`, for the manual layout check in the tests.
    #[cfg(all(windows, test))]
    pub(super) fn raw_net_rows() -> Result<Vec<u8>, String> {
        table(ffi::GetIpNetTable2, NET_ROW)
    }
    #[cfg(windows)]
    pub(super) fn neighbors() -> Result<Vec<Neighbor>, String> {
        let mut list = parse_net_rows(&table(ffi::GetIpNetTable2, NET_ROW)?);
        // a name is friendlier than an index
        for n in &mut list {
            if let Ok(index) = n.interface.parse::<u32>() {
                n.interface = alias(index);
            }
        }
        Ok(list)
    }
    #[cfg(not(windows))]
    pub(super) fn neighbors() -> Result<Vec<Neighbor>, String> {
        Err("not Windows".into())
    }

    /// One ICMPv6 echo to `ff02::1` with the interface as the scope.
    #[cfg(windows)]
    pub(super) fn multicast_echo(index: u32, wait: Duration) -> Result<Vec<Ipv6Addr>, String> {
        crate::platform::multicast_echo6(
            ALL_NODES,
            index,
            u32::try_from(wait.as_millis()).unwrap_or(2000),
        )
    }
    #[cfg(not(windows))]
    pub(super) fn multicast_echo(_: u32, _: Duration) -> Result<Vec<Ipv6Addr>, String> {
        Err("not Windows".into())
    }
}

#[cfg(test)]
#[path = "ipv6_tests.rs"]
mod tests;
