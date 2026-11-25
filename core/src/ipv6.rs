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

// ---- the capture interface, for the SYN engine ------------------------------------------------

/// Most IPv6 addresses of the capture interface the SYN engine uses as sources (each one is a
/// term of its capture filter).
pub const MAX_LINK_ADDRESSES: usize = 16;

/// An IPv6 address of the capture interface and the length of its on-link prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalAddress {
    pub address: Ipv6Addr,
    pub prefix: u8,
}

/// The capture interface as the SYN engine needs it for IPv6: the OS interface index (0 when
/// unknown), the capture interface's name, and its addresses that may be used as a source
/// (tentative and duplicate addresses are left out). Read once when the engine starts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Link {
    pub index: u32,
    pub name: String,
    pub addresses: Vec<LocalAddress>,
    /// The IPv6 addresses of this computer that are never a target, because a frame to them
    /// leaves on the wire and is not looped back: every address in any state (deprecated,
    /// tentative, beyond [`MAX_LINK_ADDRESSES`]), on any interface, except the link-local
    /// addresses of other interfaces (they are not on this link, where the same address, such
    /// as `fe80::1`, can be a neighbour).
    pub own: Vec<Ipv6Addr>,
}

fn is_link_local(ip: &Ipv6Addr) -> bool {
    ip.segments()[0] & 0xffc0 == 0xfe80
}

fn in_prefix(ip: Ipv6Addr, net: Ipv6Addr, prefix: u8) -> bool {
    let bits = u32::from(prefix.min(128));
    let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
    u128::from(ip) & mask == u128::from(net) & mask
}

fn is_unique_local(ip: &Ipv6Addr) -> bool {
    ip.segments()[0] & 0xfe00 == 0xfc00
}

impl Link {
    /// Refuses what is never a SYN target: a non-unicast or IPv4-mapped address, and any
    /// address of this computer (a frame to it leaves on the wire and is not looped back).
    pub fn check_target(&self, target: Ipv6Addr) -> Result<(), String> {
        if !is_host_address(&target) || target.to_ipv4_mapped().is_some() {
            return Err(format!("{target} is not a unicast IPv6 address"));
        }
        if self.own.contains(&target) || self.addresses.iter().any(|a| a.address == target) {
            return Err(format!(
                "{target} is this computer's own address; raw frames to it are not looped back"
            ));
        }
        Ok(())
    }

    /// The source address for an on-link target, decided without the routing table: a
    /// link-local target is sent from a link-local address of the interface, a target inside
    /// the on-link prefix of one of its global or unique-local addresses from that address (the
    /// longest such prefix wins). `None`: the target is in no on-link prefix, so it is routed
    /// (see [`Link::routed_source`]). Errors: a refused target ([`Link::check_target`]), and a
    /// link-local target without a link-local source.
    pub fn on_link_source(&self, target: Ipv6Addr) -> Result<Option<Ipv6Addr>, String> {
        self.check_target(target)?;
        if is_link_local(&target) {
            return self
                .addresses
                .iter()
                .find(|a| is_link_local(&a.address))
                .map(|a| Some(a.address))
                .ok_or_else(|| "The capture interface has no link-local IPv6 address".into());
        }
        Ok(self
            .addresses
            .iter()
            .filter(|a| {
                !is_link_local(&a.address)
                    && (1..128).contains(&a.prefix)
                    && in_prefix(target, a.address, a.prefix)
            })
            .max_by_key(|a| a.prefix)
            .map(|a| a.address))
    }

    /// The source address for a target the routing table sends through this interface (via a
    /// gateway, or on-link outside our prefixes): the OS's own choice (`suggested`) when it is
    /// a global or unique-local address of this interface, because the capture filter passes
    /// replies only to those; else one of the target's kind (unique-local for a unique-local
    /// target, global for any other). Never a link-local address.
    pub fn routed_source(
        &self,
        target: Ipv6Addr,
        suggested: Option<Ipv6Addr>,
    ) -> Result<Ipv6Addr, String> {
        let usable = |a: &Ipv6Addr| !is_link_local(a);
        if let Some(s) = suggested
            && usable(&s)
            && self.addresses.iter().any(|a| a.address == s)
        {
            return Ok(s);
        }
        let ula = is_unique_local(&target);
        self.addresses
            .iter()
            .map(|a| a.address)
            .find(|a| usable(a) && is_unique_local(a) == ula)
            .ok_or_else(|| {
                format!(
                    "The capture interface has no {} IPv6 address for {target}",
                    if ula { "unique-local" } else { "global" }
                )
            })
    }

    /// Whether a SYN to `target` may be possible at all, from the addresses alone: an on-link
    /// target with its source, or one that has a source for a route. Whether a route exists
    /// is only known after the lookup.
    pub fn may_reach(&self, target: Ipv6Addr) -> bool {
        match self.on_link_source(target) {
            Ok(Some(_)) => true,
            Ok(None) => self.routed_source(target, None).is_ok(),
            Err(_) => false,
        }
    }

    /// Every address [`Link::on_link_source`] and [`Link::routed_source`] can return (the
    /// capture filter lists them).
    pub fn sources(&self) -> Vec<Ipv6Addr> {
        self.addresses.iter().map(|a| a.address).collect()
    }

    /// Whether a neighbour cache entry's interface (a name on Linux, an index on Windows) is
    /// this one.
    fn is(&self, interface: &str) -> bool {
        interface == self.name || (self.index != 0 && interface == self.index.to_string())
    }
}

/// Linux `/proc/net/if_inet6` (see [`parse_if_inet6`]) for the interface `name`: its index and
/// its addresses with their prefix length (the fields are hex). Tentative (flag 0x40) and
/// duplicate (0x08, duplicate address detection failed) addresses are left out as sources;
/// [`Link::own`] gets the addresses of every interface (see there).
pub fn parse_if_inet6_link(text: &str, name: &str) -> Link {
    let mut link = Link {
        name: name.to_string(),
        ..Link::default()
    };
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 6 || f[0].len() != 32 {
            continue;
        }
        if f[5] != name {
            if let Ok(bits) = u128::from_str_radix(f[0], 16)
                && !is_link_local(&Ipv6Addr::from(bits))
            {
                link.own.push(Ipv6Addr::from(bits));
            }
            continue;
        }
        let hex = |s: &str| u32::from_str_radix(s, 16).ok();
        let (Ok(bits), Some(index), Some(prefix), Some(flags)) = (
            u128::from_str_radix(f[0], 16),
            hex(f[1]),
            hex(f[2]),
            hex(f[4]),
        ) else {
            continue;
        };
        link.index = index;
        let address = Ipv6Addr::from(bits);
        link.own.push(address);
        if flags & (0x40 | 0x08) == 0
            && is_host_address(&address)
            && prefix <= 128
            && link.addresses.len() < MAX_LINK_ADDRESSES
        {
            link.addresses.push(LocalAddress {
                address,
                prefix: prefix as u8,
            });
        }
    }
    link
}

/// The capture interface's IPv6 side, read from the OS (nothing is sent). Windows: the
/// interface that owns the source IPv4 address `source` (the pcap device name is not an OS
/// interface name), its preferred addresses and their on-link prefix length from
/// `GetUnicastIpAddressTable`. Linux: the interface named `interface` in `/proc/net/if_inet6`.
/// macOS/BSD: the interface named `interface` in `ifconfig -a`. A table that cannot be read
/// gives no addresses, so every IPv6 target falls back to TCP connect.
pub fn link_of(interface: &str, source: std::net::Ipv4Addr) -> Link {
    let mut link = if cfg!(windows) {
        match (
            crate::platform::interface_index(source),
            win::unicast_rows(),
        ) {
            (Some(index), Ok(rows)) => Link {
                index,
                name: interface.to_string(),
                addresses: win::link_addresses(&rows, index),
                own: rows
                    .iter()
                    .filter(|r| r.0 == index || !is_link_local(&r.1))
                    .map(|r| r.1)
                    .collect(),
            },
            _ => Link::default(),
        }
    } else if cfg!(target_os = "linux") {
        std::fs::read_to_string("/proc/net/if_inet6")
            .map(|text| parse_if_inet6_link(&text, interface))
            .unwrap_or_default()
    } else {
        run("ifconfig", &["-a"])
            .map(|text| parse_ifconfig_link(&text, interface))
            .unwrap_or_default()
    };
    link.addresses.truncate(MAX_LINK_ADDRESSES);
    link
}

/// The MAC of `ip` in a neighbour list, on the interface `link` only: a link-local address such
/// as `fe80::1` often exists on several links.
pub fn mac_on_link(neighbors: &[Neighbor], ip: Ipv6Addr, link: &Link) -> Option<String> {
    neighbors
        .iter()
        .find(|n| n.ip == ip && link.is(&n.interface))
        .map(|n| n.mac.clone())
}

/// The OS neighbour cache (Windows `GetIpNetTable2`, Linux `ip -6 neigh show`, else `ndp -an`),
/// `None` when it cannot be read. Stale entries count: they are a MAC source, as the IPv4
/// lookup's are. Reading the cache sends nothing.
pub fn read_neighbors() -> Option<Vec<Neighbor>> {
    if cfg!(windows) {
        win::neighbor_rows().ok()
    } else if cfg!(target_os = "linux") {
        Some(parse_ip_neigh6(&run("ip", &["-6", "neigh", "show"]).ok()?))
    } else {
        Some(parse_ndp_an(&run("ndp", &["-an"]).ok()?))
    }
}

/// The MAC of `ip` in the OS neighbour cache on the interface `link`.
pub fn cached_mac(ip: Ipv6Addr, link: &Link) -> Option<String> {
    mac_on_link(&read_neighbors()?, ip, link)
}

/// The neighbour cache as one SYN scan has read it. On Linux and macOS a read starts a process
/// and returns the whole table, so it is shared instead of repeated for every target: the
/// table that was read last answers for every address it has, and for every lookup that began
/// before it was read.
#[derive(Default)]
pub struct NeighborTable(std::sync::Mutex<Option<(Instant, Vec<Neighbor>)>>);

impl NeighborTable {
    /// The MAC of `ip` on `link`, from the table as it was at `since` or later; `read` (see
    /// [`read_neighbors`]) is called when the table at hand is older and does not have the
    /// address. A read that fails counts for those who waited for it, and keeps what was known.
    pub fn mac(
        &self,
        ip: Ipv6Addr,
        link: &Link,
        since: Instant,
        read: impl FnOnce() -> Option<Vec<Neighbor>>,
    ) -> Option<String> {
        // Held while reading: the lookups that wait here are answered by that one read.
        let mut table = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((at, neighbors)) = table.as_ref() {
            let mac = mac_on_link(neighbors, ip, link);
            if mac.is_some() || *at >= since {
                return mac;
            }
        }
        let at = Instant::now();
        let fresh = read();
        let (read_at, neighbors) = table.get_or_insert_with(|| (at, vec![]));
        *read_at = at;
        if let Some(fresh) = fresh {
            *neighbors = fresh;
        }
        mac_on_link(neighbors, ip, link)
    }
}

/// macOS/BSD `ifconfig -a` (see [`parse_ifconfig_inet6`]) for the interface `name`: its index
/// (the `scopeid` of its link-local address) and its addresses with `prefixlen`. Addresses
/// marked `tentative`, `duplicated`, `detached` or `deprecated` are left out as sources;
/// [`Link::own`] gets the `inet6` addresses of every interface (see there).
pub fn parse_ifconfig_link(text: &str, name: &str) -> Link {
    let mut link = Link {
        name: name.to_string(),
        ..Link::default()
    };
    let mut current = "";
    for line in text.lines() {
        if !line.starts_with([' ', '\t']) {
            current = line.split(':').next().unwrap_or_default();
            continue;
        }
        let t: Vec<&str> = line.split_whitespace().collect();
        if t.first() != Some(&"inet6") {
            continue;
        }
        let Some(address) = t.get(1).and_then(|a| parse_addr(a)) else {
            continue;
        };
        if current == name || !is_link_local(&address) {
            link.own.push(address);
        }
        if current != name {
            continue;
        }
        let after = |key: &str| t.iter().position(|w| *w == key).and_then(|i| t.get(i + 1));
        if let Some(index) =
            after("scopeid").and_then(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok())
        {
            link.index = index;
        }
        let unusable = ["tentative", "duplicated", "detached", "deprecated"]
            .iter()
            .any(|flag| t.contains(flag));
        let prefix = after("prefixlen").and_then(|p| p.parse::<u8>().ok());
        if let Some(prefix) = prefix
            && !unusable
            && prefix <= 128
            && is_host_address(&address)
            && link.addresses.len() < MAX_LINK_ADDRESSES
        {
            link.addresses.push(LocalAddress { address, prefix });
        }
    }
    link
}

/// Where the routing table sends an IPv6 target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hop6 {
    /// On the link: the target's own MAC.
    OnLink,
    /// Through this router: its MAC.
    Gateway(Ipv6Addr),
}

/// The OS route to an IPv6 target through the capture interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route6 {
    pub hop: Hop6,
    /// The source address the OS would use, when it says (Windows, Linux).
    pub source: Option<Ipv6Addr>,
}

/// Shared decision for an OS route answer: it must leave through the capture interface
/// (`via_link`), and a gateway that is one of our own addresses is refused.
pub fn route_decision(
    link: &Link,
    dest: Ipv6Addr,
    via_link: bool,
    gateway: Option<Ipv6Addr>,
    source: Option<Ipv6Addr>,
) -> Result<Route6, String> {
    if !via_link {
        return Err(format!(
            "The route to {dest} leaves through another interface than the capture interface"
        ));
    }
    let hop = match gateway {
        Some(g) if !g.is_unspecified() && g != dest => {
            if link.own.contains(&g) || link.addresses.iter().any(|a| a.address == g) {
                return Err(format!(
                    "The route to {dest} has this computer as its gateway"
                ));
            }
            Hop6::Gateway(g)
        }
        _ => Hop6::OnLink,
    };
    Ok(Route6 { hop, source })
}

/// Linux `ip -6 route get DEST`: `2001:db8:2::1 from :: via fe80::1 dev eth0 proto ra src
/// 2001:db8:1::5 metric 100 pref medium`; an on-link route has no `via`. Unreachable,
/// prohibited and blackhole routes, and no output (the error goes to stderr), are no route.
pub fn parse_ip_route_get6(text: &str, link: &Link, dest: Ipv6Addr) -> Result<Route6, String> {
    let t: Vec<&str> = text
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    let Some(first) = t.first() else {
        return Err(format!("No route to {dest}"));
    };
    if ["unreachable", "prohibit", "blackhole", "throw"].contains(first) {
        return Err(format!("No route to {dest} ({first})"));
    }
    let after = |key: &str| t.iter().position(|w| *w == key).and_then(|i| t.get(i + 1));
    let Some(dev) = after("dev") else {
        return Err(format!("No route to {dest}"));
    };
    route_decision(
        link,
        dest,
        *dev == link.name,
        after("via").and_then(|g| parse_addr(g)),
        after("src").and_then(|s| parse_addr(s)),
    )
}

/// macOS/BSD `route -n get -inet6 DEST`: `gateway: fe80::1%en0` and `interface: en0` for a
/// routed target; an on-link one shows `link#N` or a MAC as its gateway, or none.
pub fn parse_route_get6(text: &str, link: &Link, dest: Ipv6Addr) -> Result<Route6, String> {
    let field = |name: &str| {
        text.lines().find_map(|l| {
            let (k, v) = l.trim().split_once(':')?;
            (k.trim() == name).then(|| v.trim().to_string())
        })
    };
    if text.contains("not in table") || text.trim().is_empty() {
        return Err(format!("No route to {dest}"));
    }
    let Some(interface) = field("interface") else {
        return Err(format!("No route to {dest} (no interface)"));
    };
    route_decision(
        link,
        dest,
        interface == link.name,
        field("gateway").and_then(|g| parse_addr(&g)),
        None,
    )
}

/// The route to `dest` from the OS routing table (a table read; nothing is sent): Windows
/// `GetBestRoute2`, Linux `ip -6 route get`, macOS/BSD `route -n get -inet6`.
pub fn route_of(dest: Ipv6Addr, link: &Link) -> Result<Route6, String> {
    if cfg!(windows) {
        let (index, next_hop, source) = crate::platform::best_route6(dest)?;
        route_decision(
            link,
            dest,
            link.index != 0 && index == link.index,
            Some(next_hop),
            Some(source),
        )
    } else if cfg!(target_os = "linux") {
        // shortcut: one command per routed target here and on macOS/BSD (the kernel selects
        // the route, and the command has a time limit); read the routing table once and select
        // in this module if scans of many routed IPv6 targets are slow.
        parse_ip_route_get6(
            &run("ip", &["-6", "route", "get", &dest.to_string()])?,
            link,
            dest,
        )
    } else {
        parse_route_get6(
            &run("route", &["-n", "get", "-inet6", &dest.to_string()])?,
            link,
            dest,
        )
    }
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

/// How long a system command (`ip`, `ndp`, `route`, `ifconfig`) may take. They answer from
/// kernel tables within milliseconds; one that hangs must not hang the scan.
const RUN_TIMEOUT: Duration = Duration::from_secs(5);

fn run(program: &str, args: &[&str]) -> Result<String, String> {
    run_within(program, args, RUN_TIMEOUT)
}

/// The standard output of a command. One that has not finished writing it after `limit` is
/// killed, and that is an error.
fn run_within(program: &str, args: &[&str], limit: Duration) -> Result<String, String> {
    use std::process::Stdio;
    let mut child = std::process::Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("{program}: {e}"))?;
    // Read on a thread: the wait needs a time limit, and a table larger than the pipe buffer
    // has to be taken off the child while it writes.
    let (done, output) = std::sync::mpsc::channel();
    if let Some(mut stdout) = child.stdout.take() {
        std::thread::spawn(move || {
            let mut bytes = vec![];
            let _ = std::io::Read::read_to_end(&mut stdout, &mut bytes);
            let _ = done.send(bytes);
        });
    }
    let bytes = output.recv_timeout(limit);
    // It has written everything or is over time: nothing more is wanted from it either way.
    let _ = child.kill();
    let _ = child.wait();
    bytes
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .map_err(|_| format!("{program}: no answer within {} ms", limit.as_millis()))
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

    /// (interface index, address, DAD state, on-link prefix length) of the rows of
    /// `GetUnicastIpAddressTable`.
    pub(super) fn parse_unicast_rows(rows: &[u8]) -> Vec<(u32, Ipv6Addr, u32, u8)> {
        rows.as_chunks::<UNICAST_ROW>()
            .0
            .iter()
            .filter_map(|row| Some((u32_at(row, 40), address_at(row)?, u32_at(row, 64), row[60])))
            .collect()
    }

    /// The preferred (DAD state 4) addresses of the interface `index` with their on-link prefix
    /// length.
    pub(super) fn link_addresses(
        rows: &[(u32, Ipv6Addr, u32, u8)],
        index: u32,
    ) -> Vec<super::LocalAddress> {
        rows.iter()
            .filter(|(i, address, dad, _)| {
                *i == index && *dad == 4 && super::is_host_address(address)
            })
            .map(|(_, address, _, prefix)| super::LocalAddress {
                address: *address,
                prefix: *prefix,
            })
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
        let local: Vec<Ipv6Addr> = rows.iter().map(|(_, a, _, _)| *a).collect();
        let mut interfaces: Vec<Interface> = vec![];
        for (index, address, dad, _) in rows {
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

    /// Every row of `GetUnicastIpAddressTable` (see [`parse_unicast_rows`]).
    #[cfg(windows)]
    pub(super) fn unicast_rows() -> Result<Vec<(u32, Ipv6Addr, u32, u8)>, String> {
        Ok(parse_unicast_rows(&table(
            ffi::GetUnicastIpAddressTable,
            UNICAST_ROW,
        )?))
    }
    #[cfg(not(windows))]
    pub(super) fn unicast_rows() -> Result<Vec<(u32, Ipv6Addr, u32, u8)>, String> {
        Err("not Windows".into())
    }

    /// The raw rows of `GetIpNetTable2`, for the manual layout check in the tests.
    #[cfg(all(windows, test))]
    pub(super) fn raw_net_rows() -> Result<Vec<u8>, String> {
        table(ffi::GetIpNetTable2, NET_ROW)
    }
    /// The neighbour cache with the interface as its index.
    #[cfg(windows)]
    pub(super) fn neighbor_rows() -> Result<Vec<Neighbor>, String> {
        Ok(parse_net_rows(&table(ffi::GetIpNetTable2, NET_ROW)?))
    }
    #[cfg(not(windows))]
    pub(super) fn neighbor_rows() -> Result<Vec<Neighbor>, String> {
        Err("not Windows".into())
    }
    #[cfg(windows)]
    pub(super) fn neighbors() -> Result<Vec<Neighbor>, String> {
        let mut list = neighbor_rows()?;
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
