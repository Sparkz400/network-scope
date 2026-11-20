use std::net::IpAddr;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct HopReply {
    pub ip: Option<IpAddr>,
    pub rtt: Option<u32>,
    pub reached: bool,
}

/// A neighbor (ARP/NDP) entry for a target.
#[derive(Debug, Clone, PartialEq)]
pub struct Neighbor {
    pub mac: String,
    /// True when the entry proves the host answered recently: resolved during this
    /// lookup, or confirmed REACHABLE by the kernel. A cached STALE entry is a MAC
    /// source only.
    pub fresh: bool,
}

/// Where an IPv4 packet to a target is sent at layer 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NextHop {
    /// The target is on a local subnet: send to its own MAC.
    OnLink,
    /// The target is routed: send to this gateway's MAC.
    Gateway(std::net::Ipv4Addr),
}
impl NextHop {
    /// The address whose MAC frames to `dest` carry.
    pub fn l2_address(self, dest: std::net::Ipv4Addr) -> std::net::Ipv4Addr {
        match self {
            NextHop::OnLink => dest,
            NextHop::Gateway(g) => g,
        }
    }
}
pub type RouteResult = Result<NextHop, String>;

/// Shared decision for an OS best-route answer. `indirect` is the route type (via a
/// gateway). The route must leave through the interface that owns the source address
/// (when both are known): frames are sent on the capture interface, so a gateway
/// behind another adapter would be unreachable from it.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn route_decision(
    dest: std::net::Ipv4Addr,
    indirect: bool,
    gateway: std::net::Ipv4Addr,
    route_if: Option<u32>,
    source_if: Option<u32>,
) -> RouteResult {
    if let (Some(route), Some(source)) = (route_if, source_if)
        && route != source
    {
        return Err(format!(
            "The route to {dest} leaves through another interface than the source address"
        ));
    }
    if indirect && !gateway.is_unspecified() && gateway != dest {
        Ok(NextHop::Gateway(gateway))
    } else {
        Ok(NextHop::OnLink)
    }
}

/// One IPv4 route from Linux `/proc/net/route` (host byte order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub iface: String,
    pub dest: u32,
    pub gateway: u32,
    pub mask: u32,
    pub metric: u32,
    pub via_gateway: bool,
}
#[cfg_attr(windows, allow(dead_code))]
pub fn parse_proc_route_table(text: &str) -> Vec<Route> {
    let word = |s: &str| {
        u32::from_str_radix(s, 16)
            .ok()
            .map(|v| u32::from(std::net::Ipv4Addr::from(v.to_ne_bytes())))
    };
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let flags = u32::from_str_radix(f.get(3)?, 16).ok()?;
            // RTF_UP only; RTF_REJECT (0x200) routes lead nowhere.
            if flags & 1 == 0 || flags & 0x200 != 0 {
                return None;
            }
            let mask = word(f.get(7)?)?;
            Some(Route {
                iface: f.first()?.to_string(),
                dest: word(f.get(1)?)? & mask,
                gateway: word(f.get(2)?)?,
                mask,
                metric: f.get(6)?.parse().ok()?,
                via_gateway: flags & 2 != 0,
            })
        })
        .collect()
}
/// Longest-prefix match, then lowest metric. `interface` (the capture interface name,
/// empty when unknown) must match the chosen route's device.
#[cfg_attr(windows, allow(dead_code))]
pub fn best_route(routes: &[Route], dest: std::net::Ipv4Addr, interface: &str) -> RouteResult {
    let v = u32::from(dest);
    let best = routes
        .iter()
        .filter(|r| v & r.mask == r.dest)
        .max_by(|a, b| {
            a.mask
                .count_ones()
                .cmp(&b.mask.count_ones())
                .then(b.metric.cmp(&a.metric))
        })
        .ok_or_else(|| format!("No route to {dest}"))?;
    if !interface.is_empty() && best.iface != interface {
        return Err(format!(
            "The route to {dest} leaves through {}, not {interface}",
            best.iface
        ));
    }
    Ok(if best.via_gateway && best.gateway != 0 {
        NextHop::Gateway(std::net::Ipv4Addr::from(best.gateway))
    } else {
        NextHop::OnLink
    })
}
/// macOS/BSD `route -n get IP`: `gateway: 192.168.1.1` for routed targets; on-link
/// targets show no gateway line, or a `link#N` / MAC gateway.
#[cfg_attr(windows, allow(dead_code))]
pub fn parse_route_get(text: &str, interface: &str) -> RouteResult {
    let field = |name: &str| {
        text.lines().find_map(|l| {
            let (k, v) = l.trim().split_once(':')?;
            (k.trim() == name).then(|| v.trim().to_string())
        })
    };
    if text.contains("not in table") || text.trim().is_empty() {
        return Err("No route to the target".into());
    }
    if let Some(dev) = field("interface")
        && !interface.is_empty()
        && dev != interface
    {
        return Err(format!("The route leaves through {dev}, not {interface}"));
    }
    Ok(
        match field("gateway").and_then(|g| g.parse::<std::net::Ipv4Addr>().ok()) {
            Some(g) if !g.is_unspecified() => NextHop::Gateway(g),
            _ => NextHop::OnLink,
        },
    )
}

/// Next hop toward `dest` from the OS routing table: GetBestRoute on Windows,
/// `/proc/net/route` on Linux, `route -n get` on macOS/BSD. `source` and `interface`
/// describe the capture interface; a route through another interface is an error.
pub fn next_hop(
    dest: std::net::Ipv4Addr,
    source: std::net::Ipv4Addr,
    interface: &str,
) -> RouteResult {
    #[cfg(windows)]
    {
        let _ = interface;
        win::next_hop(dest, source)
    }
    #[cfg(not(windows))]
    {
        let _ = source;
        if let Ok(text) = std::fs::read_to_string("/proc/net/route") {
            return best_route(&parse_proc_route_table(&text), dest, interface);
        }
        let out = std::process::Command::new("route")
            .args(["-n", "get", &dest.to_string()])
            .output()
            .map_err(|e| format!("route -n get: {e}"))?;
        parse_route_get(&String::from_utf8_lossy(&out.stdout), interface)
    }
}

#[derive(Debug, Default)]
pub struct Echo {
    pub rtt: Option<u32>,
    pub ttl: Option<u8>,
    pub error: Option<String>,
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::{ffi::c_void, ptr};

    type Handle = *mut c_void;
    #[repr(C)]
    struct Options {
        ttl: u8,
        tos: u8,
        flags: u8,
        size: u8,
        data: *mut u8,
    }
    #[repr(C)]
    struct Reply4 {
        address: u32,
        status: u32,
        rtt: u32,
        size: u16,
        reserved: u16,
        data: *mut c_void,
        options: Options,
    }
    #[repr(C)]
    struct Sock6 {
        family: u16,
        port: u16,
        flow: u32,
        address: [u8; 16],
        scope: u32,
    }
    // Windows IPV6_ADDRESS_EX is packed, unlike SOCKADDR_IN6 above.
    // In particular, the address bytes start at offset 6, not offset 8.
    #[repr(C, packed)]
    struct Address6 {
        port: u16,
        flow: u32,
        address: [u8; 16],
        scope: u32,
    }
    #[repr(C)]
    struct Reply6 {
        address: Address6,
        status: u32,
        rtt: u32,
    }

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn IcmpCreateFile() -> Handle;
        fn Icmp6CreateFile() -> Handle;
        fn IcmpCloseHandle(handle: Handle) -> i32;
        fn IcmpSendEcho(
            handle: Handle,
            dest: u32,
            data: *const c_void,
            size: u16,
            options: *const Options,
            reply: *mut c_void,
            reply_size: u32,
            timeout: u32,
        ) -> u32;
        fn Icmp6SendEcho2(
            handle: Handle,
            event: Handle,
            apc: *const c_void,
            context: *const c_void,
            source: *const Sock6,
            dest: *const Sock6,
            data: *const c_void,
            size: u16,
            options: *const Options,
            reply: *mut c_void,
            reply_size: u32,
            timeout: u32,
        ) -> u32;
        fn SendARP(dest: u32, source: u32, mac: *mut c_void, length: *mut u32) -> u32;
        fn GetBestRoute(dest: u32, source: u32, row: *mut ForwardRow) -> u32;
        fn GetIpAddrTable(table: *mut c_void, size: *mut u32, order: i32) -> u32;
    }
    /// MIB_IPFORWARDROW: fourteen DWORDs, addresses in network byte order.
    #[repr(C)]
    #[derive(Default)]
    struct ForwardRow {
        dest: u32,
        mask: u32,
        policy: u32,
        next_hop: u32,
        if_index: u32,
        kind: u32,
        proto: u32,
        age: u32,
        next_hop_as: u32,
        metrics: [u32; 5],
    }
    /// MIB_IPADDRROW (24 bytes).
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct AddrRow {
        addr: u32,
        index: u32,
        mask: u32,
        broadcast: u32,
        reassembly: u32,
        unused: u16,
        kind: u16,
    }

    /// Interface index that owns `ip` (GetIpAddrTable), if any.
    fn interface_of(ip: std::net::Ipv4Addr) -> Option<u32> {
        let wanted = u32::from_ne_bytes(ip.octets());
        unsafe {
            let mut size = 0u32;
            GetIpAddrTable(ptr::null_mut(), &mut size, 0);
            if size == 0 {
                return None;
            }
            // u32 storage keeps the rows aligned.
            let mut buffer = vec![0u32; (size as usize).div_ceil(4) + 1];
            size = (buffer.len() * 4) as u32;
            if GetIpAddrTable(buffer.as_mut_ptr().cast(), &mut size, 0) != 0 {
                return None;
            }
            let count = buffer[0] as usize;
            let rows = buffer.as_ptr().add(1).cast::<AddrRow>();
            let available = (buffer.len() - 1) * 4 / std::mem::size_of::<AddrRow>();
            (0..count.min(available))
                .map(|i| *rows.add(i))
                .find(|r| r.addr == wanted)
                .map(|r| r.index)
        }
    }

    pub fn next_hop(dest: std::net::Ipv4Addr, source: std::net::Ipv4Addr) -> RouteResult {
        let mut row = ForwardRow::default();
        let code = unsafe {
            GetBestRoute(
                u32::from_ne_bytes(dest.octets()),
                u32::from_ne_bytes(source.octets()),
                &mut row,
            )
        };
        if code != 0 {
            return Err(format!(
                "No route to {dest}: {}",
                std::io::Error::from_raw_os_error(code as i32)
            ));
        }
        let source_if = if source.is_unspecified() {
            None
        } else {
            interface_of(source)
        };
        route_decision(
            dest,
            row.kind == 4,
            std::net::Ipv4Addr::from(row.next_hop.to_ne_bytes()),
            Some(row.if_index),
            source_if,
        )
    }

    /// ICMPv6 echo with a hop limit (Icmp6SendEcho2 honours `Options::ttl` as the hop limit).
    pub fn hop6(dest_ip: std::net::Ipv6Addr, ttl: u8, timeout: u32) -> Result<HopReply, String> {
        unsafe {
            let raw = Icmp6CreateFile();
            if raw.is_null() || raw as isize == -1 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            let h = OwnedHandle(raw);
            let payload = [0u8; 32];
            let mut buffer = [0u64; 128];
            let options = Options {
                ttl,
                tos: 0,
                flags: 0,
                size: 0,
                data: ptr::null_mut(),
            };
            let source = Sock6 {
                family: 23,
                port: 0,
                flow: 0,
                address: [0; 16],
                scope: 0,
            };
            let dest = Sock6 {
                address: dest_ip.octets(),
                ..source
            };
            let count = Icmp6SendEcho2(
                h.0,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                &source,
                &dest,
                payload.as_ptr().cast(),
                32,
                &options,
                buffer.as_mut_ptr().cast(),
                std::mem::size_of_val(&buffer) as u32,
                timeout,
            );
            // As for IPv4: no reply structure means no answer (never guess a hop).
            if count == 0 {
                return Ok(HopReply::default());
            }
            let reply = &*(buffer.as_ptr().cast::<Reply6>());
            let from = std::net::Ipv6Addr::from(reply.address.address);
            Ok(HopReply {
                ip: Some(IpAddr::V6(from)),
                rtt: Some(reply.rtt),
                reached: reply.status == 0 && from == dest_ip,
            })
        }
    }
    /// One ICMPv6 echo to `ff02::1` with the interface index as scope. The ICMP API returns every
    /// reply it received before the timeout (`ipv6` joins them to hosts).
    pub fn multicast_echo6(
        group: std::net::Ipv6Addr,
        scope: u32,
        timeout: u32,
    ) -> Result<Vec<std::net::Ipv6Addr>, String> {
        unsafe {
            let raw = Icmp6CreateFile();
            if raw.is_null() || raw as isize == -1 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            let h = OwnedHandle(raw);
            let payload = [0u8; 32];
            let mut buffer = [0u64; 1024];
            let source = Sock6 {
                family: 23,
                port: 0,
                flow: 0,
                address: [0; 16],
                scope: 0,
            };
            let dest = Sock6 {
                address: group.octets(),
                scope,
                ..source
            };
            let count = Icmp6SendEcho2(
                h.0,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                &source,
                &dest,
                payload.as_ptr().cast(),
                32,
                ptr::null(),
                buffer.as_mut_ptr().cast(),
                std::mem::size_of_val(&buffer) as u32,
                timeout,
            );
            // No reply is a timeout (11000..=11050 are IP status codes), not a local failure.
            if count == 0 {
                let error = std::io::Error::last_os_error();
                let code = error.raw_os_error().unwrap_or(0);
                if code != 0 && !(11000..=11050).contains(&code) {
                    return Err(error.to_string());
                }
            }
            let size = std::mem::size_of::<Reply6>();
            let mut out: Vec<std::net::Ipv6Addr> = vec![];
            for i in 0..(count as usize).min(std::mem::size_of_val(&buffer) / size) {
                let reply = ptr::read_unaligned(
                    buffer.as_ptr().cast::<u8>().add(i * size).cast::<Reply6>(),
                );
                let address = std::net::Ipv6Addr::from(reply.address.address);
                if reply.status == 0 && !out.contains(&address) {
                    out.push(address);
                }
            }
            Ok(out)
        }
    }
    struct OwnedHandle(Handle);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                IcmpCloseHandle(self.0);
            }
        }
    }

    pub fn echo(ip: IpAddr, timeout: u32) -> Echo {
        unsafe {
            let raw = if ip.is_ipv4() {
                IcmpCreateFile()
            } else {
                Icmp6CreateFile()
            };
            if raw.is_null() || raw as isize == -1 {
                return Echo {
                    error: Some(std::io::Error::last_os_error().to_string()),
                    ..Default::default()
                };
            }
            let h = OwnedHandle(raw);
            let payload = [0u8; 32];
            // u64 allocation gives the native reply sufficient alignment on x86 and x64.
            let mut buffer = [0u64; 128];
            let bytes = std::mem::size_of_val(&buffer) as u32;
            match ip {
                IpAddr::V4(ip) => {
                    let dest = u32::from_ne_bytes(ip.octets());
                    let count = IcmpSendEcho(
                        h.0,
                        dest,
                        payload.as_ptr().cast(),
                        32,
                        ptr::null(),
                        buffer.as_mut_ptr().cast(),
                        bytes,
                        timeout,
                    );
                    if count > 0 {
                        let reply = &*(buffer.as_ptr().cast::<Reply4>());
                        if reply.status == 0 && reply.address == dest {
                            return Echo {
                                rtt: Some(reply.rtt),
                                ttl: Some(reply.options.ttl),
                                error: None,
                            };
                        }
                    }
                }
                IpAddr::V6(ip) => {
                    let source = Sock6 {
                        family: 23,
                        port: 0,
                        flow: 0,
                        address: [0; 16],
                        scope: 0,
                    };
                    let dest = Sock6 {
                        address: ip.octets(),
                        ..source
                    };
                    let count = Icmp6SendEcho2(
                        h.0,
                        ptr::null_mut(),
                        ptr::null(),
                        ptr::null(),
                        &source,
                        &dest,
                        payload.as_ptr().cast(),
                        32,
                        ptr::null(),
                        buffer.as_mut_ptr().cast(),
                        bytes,
                        timeout,
                    );
                    if count > 0 {
                        let reply = &*(buffer.as_ptr().cast::<Reply6>());
                        if reply.status == 0 && reply.address.address == ip.octets() {
                            return Echo {
                                rtt: Some(reply.rtt),
                                ttl: None,
                                error: None,
                            };
                        }
                    }
                }
            }
            let error = std::io::Error::last_os_error();
            // Timeouts and remote unreachable messages are observations, not local failures.
            let code = error.raw_os_error().unwrap_or(0);
            Echo {
                error: if code != 0 && !(11000..=11050).contains(&code) {
                    Some(error.to_string())
                } else {
                    None
                },
                ..Default::default()
            }
        }
    }
    pub fn hop(dest_ip: std::net::Ipv4Addr, ttl: u8, timeout: u32) -> Result<HopReply, String> {
        unsafe {
            let raw = IcmpCreateFile();
            if raw.is_null() || raw as isize == -1 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            let h = OwnedHandle(raw);
            let payload = [0u8; 32];
            let mut buffer = [0u64; 128];
            let options = Options {
                ttl,
                tos: 0,
                flags: 0,
                size: 0,
                data: ptr::null_mut(),
            };
            let dest = u32::from_ne_bytes(dest_ip.octets());
            let count = IcmpSendEcho(
                h.0,
                dest,
                payload.as_ptr().cast(),
                32,
                &options,
                buffer.as_mut_ptr().cast(),
                std::mem::size_of_val(&buffer) as u32,
                timeout,
            );
            if count == 0 {
                return Ok(HopReply::default());
            }
            let reply = &*(buffer.as_ptr().cast::<Reply4>());
            let from = std::net::Ipv4Addr::from(reply.address.to_ne_bytes());
            Ok(HopReply {
                ip: Some(IpAddr::V4(from)),
                rtt: Some(reply.rtt),
                reached: reply.status == 0 && from == dest_ip,
            })
        }
    }
    pub fn mac(ip: IpAddr) -> Option<String> {
        let IpAddr::V4(ip) = ip else { return None };
        unsafe {
            let mut buffer = [0u8; 8];
            let mut length = buffer.len() as u32;
            if SendARP(
                u32::from_ne_bytes(ip.octets()),
                0,
                buffer.as_mut_ptr().cast(),
                &mut length,
            ) == 0
                && length == 6
            {
                return Some(
                    buffer[..6]
                        .iter()
                        .map(|v| format!("{v:02X}"))
                        .collect::<Vec<_>>()
                        .join(":"),
                );
            }
        }
        None
    }
}
#[cfg(not(windows))]
mod unix {
    use super::*;
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::{
        mem::MaybeUninit,
        net::SocketAddr,
        sync::atomic::{AtomicU16, Ordering},
        time::{Duration, Instant},
    };

    static SEQUENCE: AtomicU16 = AtomicU16::new(1);

    /// ICMP echo over an unprivileged datagram ICMP socket when the OS allows it
    /// (Linux ping_group_range, macOS), otherwise over a raw socket (needs root).
    pub fn echo(ip: IpAddr, timeout: u32) -> Echo {
        let (domain, protocol, request) = match ip {
            IpAddr::V4(_) => (Domain::IPV4, Protocol::ICMPV4, 8u8),
            IpAddr::V6(_) => (Domain::IPV6, Protocol::ICMPV6, 128u8),
        };
        let (socket, raw) = match Socket::new(domain, Type::DGRAM, Some(protocol)) {
            Ok(s) => (s, false),
            Err(_) => match Socket::new(domain, Type::RAW, Some(protocol)) {
                Ok(s) => (s, true),
                Err(e) => {
                    return Echo {
                        error: Some(format!(
                            "ICMP needs root or net.ipv4.ping_group_range ({e}); use TCP probing"
                        )),
                        ..Default::default()
                    };
                }
            },
        };
        let id = (std::process::id() & 0xffff) as u16;
        let seq = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let packet = icmp_request(request, id, seq, ip.is_ipv4());
        let deadline = Instant::now() + Duration::from_millis(u64::from(timeout.max(1)));
        let started = Instant::now();
        if let Err(e) = socket.send_to(&packet, &SockAddr::from(SocketAddr::new(ip, 0))) {
            return Echo {
                error: Some(format!("ICMP send failed: {e}")),
                ..Default::default()
            };
        }
        let mut buffer = [MaybeUninit::<u8>::uninit(); 1500];
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || socket.set_read_timeout(Some(left)).is_err() {
                return Echo::default();
            }
            let Ok((n, from)) = socket.recv_from(&mut buffer) else {
                return Echo::default();
            };
            // SAFETY: recv_from initialised the first `n` bytes.
            let data: Vec<u8> = buffer[..n]
                .iter()
                .map(|b| unsafe { b.assume_init() })
                .collect();
            let from_ok = from.as_socket().map(|a| a.ip() == ip).unwrap_or(true);
            if !from_ok {
                continue;
            }
            if let Some((ttl, rid, rseq)) = parse_echo_reply(&data, ip.is_ipv4()) {
                let linux_dgram = !raw && cfg!(any(target_os = "linux", target_os = "android"));
                if echo_matches(linux_dgram, (rid, rseq), (id, seq)) {
                    return Echo {
                        rtt: Some(started.elapsed().as_millis() as u32),
                        ttl,
                        error: None,
                    };
                }
            }
        }
    }
}

/// 32-byte-payload ICMP/ICMPv6 echo request. ICMPv6 checksums are filled in by the kernel.
#[cfg_attr(windows, allow(dead_code))]
pub fn icmp_request(kind: u8, id: u16, seq: u16, v4: bool) -> Vec<u8> {
    let mut p = vec![kind, 0, 0, 0];
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend((0..32u8).map(|i| b'a' + i % 23));
    if v4 {
        let sum = icmp_checksum(&p);
        p[2..4].copy_from_slice(&sum.to_be_bytes());
    }
    p
}
#[cfg_attr(windows, allow(dead_code))]
pub fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in data.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
/// Whether an echo reply answers our request. The sequence number is unique per
/// request within the process and survives every socket type, so it is always
/// checked. Linux datagram ("ping") sockets rewrite the identifier to the socket's
/// own id (and the kernel already delivers only that socket's replies), so the
/// identifier is checked everywhere else: raw sockets and macOS/BSD datagram
/// sockets, which leave it untouched and see every echo reply on the host.
#[cfg_attr(windows, allow(dead_code))]
pub fn echo_matches(linux_dgram: bool, reply: (u16, u16), request: (u16, u16)) -> bool {
    reply.1 == request.1 && (linux_dgram || reply.0 == request.0)
}

/// Returns (ttl if an IP header was present, identifier, sequence) for an echo reply.
/// Raw and macOS sockets deliver the IPv4 header; Linux datagram ICMP sockets do not.
#[cfg_attr(windows, allow(dead_code))]
pub fn parse_echo_reply(data: &[u8], v4: bool) -> Option<(Option<u8>, u16, u16)> {
    let (icmp, ttl) = if v4 && data.first().is_some_and(|b| b >> 4 == 4) {
        let header = usize::from(data[0] & 15) * 4;
        // IHL below 5 is malformed and would put the protocol byte out of bounds.
        if header < 20 || data.len() < header + 8 || data[9] != 1 {
            return None;
        }
        (&data[header..], Some(data[8]))
    } else {
        (data, None)
    };
    let reply = if v4 { 0 } else { 129 };
    if icmp.len() < 8 || icmp[0] != reply || icmp[1] != 0 {
        return None;
    }
    Some((
        ttl,
        u16::from_be_bytes([icmp[4], icmp[5]]),
        u16::from_be_bytes([icmp[6], icmp[7]]),
    ))
}

fn normalize_mac(text: &str) -> Option<String> {
    let parts: Vec<u8> = text
        .split([':', '-'])
        .map(|p| u8::from_str_radix(p, 16))
        .collect::<Result<_, _>>()
        .ok()?;
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
/// Linux `/proc/net/arp`: only entries with the "complete" flag (0x2) count. The flag
/// stays set for STALE entries, so a hit gives the MAC but does not prove the host is up.
#[cfg_attr(windows, allow(dead_code))]
pub fn parse_proc_arp(text: &str, ip: IpAddr) -> Option<String> {
    let wanted = ip.to_string();
    text.lines().skip(1).find_map(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        let flags = u32::from_str_radix(f.get(2)?.trim_start_matches("0x"), 16).ok()?;
        (f.first() == Some(&wanted.as_str()) && flags & 2 != 0)
            .then(|| normalize_mac(f.get(3)?))
            .flatten()
    })
}
/// `ip neigh show IP` output, e.g. `192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE`.
#[cfg_attr(windows, allow(dead_code))]
pub fn parse_ip_neigh(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        words.find(|w| *w == "lladdr")?;
        normalize_mac(words.next()?)
    })
}
/// True when `ip neigh show IP` reports a resolved entry the kernel confirmed recently.
/// Only REACHABLE counts: STALE is an old cache entry, and DELAY/PROBE only mean that
/// traffic was sent (possibly by this scanner) without a confirmation yet.
#[cfg_attr(windows, allow(dead_code))]
pub fn ip_neigh_reachable(text: &str) -> bool {
    text.lines().any(|line| {
        let words: Vec<&str> = line.split_whitespace().collect();
        words.contains(&"lladdr") && words.last() == Some(&"REACHABLE")
    })
}
/// On-link IPv4 networks (network, mask; host byte order) from Linux `/proc/net/route`:
/// routes that are up and have no gateway. Addresses there are printed as the
/// native-endian value of the network-order word.
#[cfg_attr(windows, allow(dead_code))]
pub fn parse_proc_route(text: &str) -> Vec<(u32, u32)> {
    let word = |s: &str| {
        u32::from_str_radix(s, 16)
            .ok()
            .map(|v| u32::from(std::net::Ipv4Addr::from(v.to_ne_bytes())))
    };
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let (dest, gateway, flags, mask) = (
                word(f.get(1)?)?,
                word(f.get(2)?)?,
                f.get(3)?,
                word(f.get(7)?)?,
            );
            let flags = u32::from_str_radix(flags, 16).ok()?;
            // RTF_UP and not RTF_GATEWAY.
            (flags & 1 != 0 && flags & 2 == 0 && gateway == 0).then_some((dest & mask, mask))
        })
        .collect()
}
#[cfg_attr(windows, allow(dead_code))]
pub fn on_link(routes: &[(u32, u32)], ip: std::net::Ipv4Addr) -> bool {
    let v = u32::from(ip);
    routes.iter().any(|&(net, mask)| v & mask == net)
}
/// BSD/macOS `arp -n IP`, e.g. `? (10.0.0.1) at 0:1a:2b:3c:4d:5e on en0 ifscope [ethernet]`.
#[cfg_attr(windows, allow(dead_code))]
pub fn parse_arp_n(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        words.find(|w| *w == "at")?;
        normalize_mac(words.next()?)
    })
}

/// Combines the lookups before and after the neighbor-table poke. An entry that only
/// appeared after the poke was resolved by this probe, so it proves the host is up.
#[cfg_attr(windows, allow(dead_code))]
pub fn neighbor_outcome(
    before: Option<(String, bool)>,
    after: impl FnOnce() -> Option<String>,
) -> Option<Neighbor> {
    match before {
        Some((mac, reachable)) => Some(Neighbor {
            mac,
            fresh: reachable,
        }),
        None => after().map(|mac| Neighbor { mac, fresh: true }),
    }
}

#[cfg(not(windows))]
fn neighbor_unix(ip: IpAddr) -> Option<Neighbor> {
    use std::process::Command;
    // Only on-link targets have a neighbor entry; never poke routed addresses.
    // Without a readable routing table (macOS) the target is assumed on-link.
    if let IpAddr::V4(v4) = ip
        && let Ok(text) = std::fs::read_to_string("/proc/net/route")
    {
        let routes = parse_proc_route(&text);
        if !routes.is_empty() && !on_link(&routes, v4) {
            return None;
        }
    }
    let run = |program: &str, args: &[&str]| {
        Command::new(program)
            .args(args)
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
    };
    let target = ip.to_string();
    // /proc/net/arp (Linux, IPv4) needs no process spawn; `ip neigh` / `arp -n` are
    // only run when it is unavailable, plus one `ip neigh` on a hit for its state.
    let use_proc = ip.is_ipv4() && std::path::Path::new("/proc/net/arp").exists();
    let read_proc = || {
        std::fs::read_to_string("/proc/net/arp")
            .ok()
            .and_then(|t| parse_proc_arp(&t, ip))
    };
    let command_lookup = || -> Option<(String, bool)> {
        if let Some(text) = run("ip", &["neigh", "show", &target]) {
            if let Some(mac) = parse_ip_neigh(&text) {
                return Some((mac, ip_neigh_reachable(&text)));
            }
            return None;
        }
        // No `ip` (macOS/BSD): `arp -n` shows no state, so a hit is a MAC source only.
        run("arp", &["-n", &target])
            .and_then(|t| parse_arp_n(&t))
            .map(|mac| (mac, false))
    };
    let before = if use_proc {
        read_proc().map(|mac| {
            let reachable =
                run("ip", &["neigh", "show", &target]).is_some_and(|t| ip_neigh_reachable(&t));
            (mac, reachable)
        })
    } else {
        command_lookup()
    };
    neighbor_outcome(before, || {
        // Absent: trigger resolution with one harmless datagram, wait once, look again.
        let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        if let Ok(socket) = std::net::UdpSocket::bind(bind) {
            let _ = socket.send_to(&[0], (ip, 9));
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
        if use_proc {
            read_proc()
        } else {
            command_lookup().map(|(mac, _)| mac)
        }
    })
}

#[cfg(not(windows))]
fn hop_unix(ip: IpAddr, ttl: u8, timeout: u32, id: u16) -> Result<HopReply, String> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::{
        mem::MaybeUninit,
        net::SocketAddr,
        time::{Duration, Instant},
    };
    let IpAddr::V4(dest) = ip else {
        return Err("Traceroute supports IPv4 only".into());
    };
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
        .map_err(|e| format!("Traceroute needs a raw ICMP socket (root): {e}"))?;
    socket
        .set_ttl_v4(u32::from(ttl))
        .map_err(|e| e.to_string())?;
    let seq = u16::from(ttl);
    let started = Instant::now();
    let deadline = started + Duration::from_millis(u64::from(timeout.max(1)));
    socket
        .send_to(
            &icmp_request(8, id, seq, true),
            &SockAddr::from(SocketAddr::new(ip, 0)),
        )
        .map_err(|e| e.to_string())?;
    let mut buffer = [MaybeUninit::<u8>::uninit(); 1500];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || socket.set_read_timeout(Some(left)).is_err() {
            return Ok(HopReply::default());
        }
        let Ok((n, _)) = socket.recv_from(&mut buffer) else {
            return Ok(HopReply::default());
        };
        // SAFETY: recv_from initialised the first `n` bytes.
        let data: Vec<u8> = buffer[..n]
            .iter()
            .map(|b| unsafe { b.assume_init() })
            .collect();
        if let Some(from) = parse_hop_reply(&data, dest, id, seq) {
            return Ok(HopReply {
                ip: Some(IpAddr::V4(from)),
                rtt: Some(started.elapsed().as_millis() as u32),
                reached: from == dest,
            });
        }
    }
}

/// IPv4 header length in bytes, if the header is well formed and carries ICMP.
#[cfg_attr(windows, allow(dead_code))]
fn icmp_payload_offset(ip: &[u8]) -> Option<usize> {
    let first = *ip.first()?;
    let header = usize::from(first & 15) * 4;
    (first >> 4 == 4 && header >= 20 && ip.len() >= header && ip[9] == 1).then_some(header)
}

/// Raw-socket traceroute reply: an echo reply from `dest`, or Time Exceeded /
/// Unreachable quoting our request to `dest`. A raw socket sees every ICMP message
/// on the host, so parallel traces to other targets must not match.
#[cfg_attr(windows, allow(dead_code))]
pub fn parse_hop_reply(
    data: &[u8],
    dest: std::net::Ipv4Addr,
    id: u16,
    seq: u16,
) -> Option<std::net::Ipv4Addr> {
    let outer = icmp_payload_offset(data)?;
    let source = std::net::Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let icmp = data.get(outer..)?;
    let ids_match = |b: &[u8]| {
        u16::from_be_bytes([b[4], b[5]]) == id && u16::from_be_bytes([b[6], b[7]]) == seq
    };
    if icmp.len() < 8 {
        return None;
    }
    match icmp[0] {
        0 => (source == dest && ids_match(icmp)).then_some(source),
        3 | 11 => {
            let inner = icmp.get(8..)?;
            let inner_header = icmp_payload_offset(inner)?;
            if inner.get(16..20)? != dest.octets() {
                return None;
            }
            let quoted = inner.get(inner_header..)?;
            (quoted.len() >= 8 && quoted[0] == 8 && ids_match(quoted)).then_some(source)
        }
        _ => None,
    }
}

/// ICMPv6 traceroute reply as delivered by a raw ICMPv6 socket (no IPv6 header):
/// an echo reply from `dest`, or Time Exceeded (3) / Destination Unreachable (1)
/// quoting our echo request to `dest`. Returns whether the destination was reached.
#[cfg_attr(windows, allow(dead_code))]
pub fn parse_hop6_reply(
    icmp: &[u8],
    from: std::net::Ipv6Addr,
    dest: std::net::Ipv6Addr,
    id: u16,
    seq: u16,
) -> Option<bool> {
    let ids_match = |b: &[u8]| {
        b.len() >= 8
            && u16::from_be_bytes([b[4], b[5]]) == id
            && u16::from_be_bytes([b[6], b[7]]) == seq
    };
    match *icmp.first()? {
        129 => (from == dest && ids_match(icmp)).then_some(true),
        1 | 3 => {
            // 8-byte ICMPv6 header, then the invoking packet: 40-byte IPv6 header
            // (next header at 6, destination at 24..40) and our echo request.
            let inner = icmp.get(8..)?;
            if inner.len() < 48
                || inner[0] >> 4 != 6
                || inner[6] != 58
                || inner[24..40] != dest.octets()
            {
                return None;
            }
            let quoted = &inner[40..];
            (quoted[0] == 128 && ids_match(quoted)).then_some(from == dest)
        }
        _ => None,
    }
}

#[cfg(not(windows))]
fn hop6_unix(dest: std::net::Ipv6Addr, ttl: u8, timeout: u32, id: u16) -> Result<HopReply, String> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::{
        mem::MaybeUninit,
        net::SocketAddr,
        time::{Duration, Instant},
    };
    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
        .map_err(|e| format!("IPv6 traceroute needs a raw ICMPv6 socket (root): {e}"))?;
    socket
        .set_unicast_hops_v6(u32::from(ttl))
        .map_err(|e| e.to_string())?;
    let seq = u16::from(ttl);
    let started = Instant::now();
    let deadline = started + Duration::from_millis(u64::from(timeout.max(1)));
    socket
        .send_to(
            &icmp_request(128, id, seq, false),
            &SockAddr::from(SocketAddr::new(IpAddr::V6(dest), 0)),
        )
        .map_err(|e| e.to_string())?;
    let mut buffer = [MaybeUninit::<u8>::uninit(); 1500];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || socket.set_read_timeout(Some(left)).is_err() {
            return Ok(HopReply::default());
        }
        let Ok((n, from)) = socket.recv_from(&mut buffer) else {
            return Ok(HopReply::default());
        };
        let Some(IpAddr::V6(from)) = from.as_socket().map(|a| a.ip()) else {
            continue;
        };
        // SAFETY: recv_from initialised the first `n` bytes.
        let data: Vec<u8> = buffer[..n]
            .iter()
            .map(|b| unsafe { b.assume_init() })
            .collect();
        if let Some(reached) = parse_hop6_reply(&data, from, dest, id, seq) {
            return Ok(HopReply {
                ip: Some(IpAddr::V6(from)),
                rtt: Some(started.elapsed().as_millis() as u32),
                reached,
            });
        }
    }
}

/// First UDP traceroute destination port; the probe for TTL t goes to `UDP_TRACE_BASE + t`.
/// 33435-33498 is the classic traceroute range: no OT protocol or printer port lies in it.
pub const UDP_TRACE_BASE: u16 = 33434;

/// UDP traceroute reply, as read from a raw IPv4 ICMP socket (IP header included):
/// Time Exceeded or Destination Unreachable quoting our datagram to `dest` with the
/// given ports. Returns (sender, reached): a Port Unreachable from `dest` means the
/// datagram arrived at the target.
pub fn parse_udp_hop_reply(
    data: &[u8],
    dest: std::net::Ipv4Addr,
    sport: u16,
    dport: u16,
) -> Option<(std::net::Ipv4Addr, bool)> {
    let outer = icmp_payload_offset(data)?;
    let source = std::net::Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let icmp = data.get(outer..)?;
    if icmp.len() < 8 || !matches!(icmp[0], 3 | 11) {
        return None;
    }
    let inner = icmp.get(8..)?;
    let first = *inner.first()?;
    let inner_header = usize::from(first & 15) * 4;
    if first >> 4 != 4 || inner_header < 20 || inner.len() < inner_header + 8 || inner[9] != 17 {
        return None;
    }
    if inner[16..20] != dest.octets() {
        return None;
    }
    let udp = &inner[inner_header..];
    if u16::from_be_bytes([udp[0], udp[1]]) != sport
        || u16::from_be_bytes([udp[2], udp[3]]) != dport
    {
        return None;
    }
    Some((source, icmp[0] == 3 && source == dest))
}

/// One UDP traceroute probe: a datagram with the given TTL to `UDP_TRACE_BASE + ttl`,
/// answered by ICMP read from a raw socket (administrator/root on every OS).
pub fn udp_hop(dest: std::net::Ipv4Addr, ttl: u8, timeout: u32) -> Result<HopReply, String> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::{
        mem::MaybeUninit,
        net::{SocketAddr, UdpSocket},
        time::{Duration, Instant},
    };
    let udp = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    let dport = UDP_TRACE_BASE + u16::from(ttl);
    udp.connect((dest, dport)).map_err(|e| e.to_string())?;
    let local = udp.local_addr().map_err(|e| e.to_string())?;
    let raw = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
        .map_err(|e| format!("UDP traceroute needs a raw ICMP socket (administrator/root): {e}"))?;
    // Windows only delivers to raw sockets bound to a concrete local address.
    raw.bind(&SockAddr::from(SocketAddr::new(local.ip(), 0)))
        .map_err(|e| e.to_string())?;
    udp.set_ttl(u32::from(ttl)).map_err(|e| e.to_string())?;
    let started = Instant::now();
    let deadline = started + Duration::from_millis(u64::from(timeout.max(1)));
    udp.send(&[0u8; 12]).map_err(|e| e.to_string())?;
    let mut buffer = [MaybeUninit::<u8>::uninit(); 1500];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || raw.set_read_timeout(Some(left)).is_err() {
            return Ok(HopReply::default());
        }
        let Ok((n, _)) = raw.recv_from(&mut buffer) else {
            return Ok(HopReply::default());
        };
        // SAFETY: recv_from initialised the first `n` bytes.
        let data: Vec<u8> = buffer[..n]
            .iter()
            .map(|b| unsafe { b.assume_init() })
            .collect();
        if let Some((from, reached)) = parse_udp_hop_reply(&data, dest, local.port(), dport) {
            return Ok(HopReply {
                ip: Some(IpAddr::V4(from)),
                rtt: Some(started.elapsed().as_millis() as u32),
                reached,
            });
        }
    }
}

/// One traceroute probe with the given TTL (hop limit for IPv6). `id` identifies the
/// trace (one value per `trace::trace` call), the TTL is used as the sequence number.
pub fn hop(ip: IpAddr, ttl: u8, timeout: u32, id: u16) -> Result<HopReply, String> {
    #[cfg(windows)]
    {
        // IcmpSendEcho matches replies itself; the identifier is unused here.
        let _ = id;
        match ip {
            IpAddr::V4(v4) => win::hop(v4, ttl, timeout),
            IpAddr::V6(v6) => win::hop6(v6, ttl, timeout),
        }
    }
    #[cfg(not(windows))]
    {
        match ip {
            IpAddr::V4(_) => hop_unix(ip, ttl, timeout, id),
            IpAddr::V6(v6) => hop6_unix(v6, ttl, timeout, id),
        }
    }
}

pub fn echo(ip: IpAddr, timeout: u32) -> Echo {
    #[cfg(windows)]
    {
        win::echo(ip, timeout)
    }
    #[cfg(not(windows))]
    {
        unix::echo(ip, timeout)
    }
}
/// One ICMPv6 echo to a multicast group on the interface with this index (Windows ICMP API; the
/// other platforms use a socket, see `ipv6`). Returns the source of every reply.
#[cfg(windows)]
pub fn multicast_echo6(
    group: std::net::Ipv6Addr,
    scope: u32,
    timeout: u32,
) -> Result<Vec<std::net::Ipv6Addr>, String> {
    win::multicast_echo6(group, scope, timeout)
}
/// Neighbor lookup with liveness evidence (see [`Neighbor::fresh`]).
pub fn neighbor(ip: IpAddr) -> Option<Neighbor> {
    #[cfg(windows)]
    {
        // SendARP is treated as a live resolution, as before.
        win::mac(ip).map(|mac| Neighbor { mac, fresh: true })
    }
    #[cfg(not(windows))]
    {
        neighbor_unix(ip)
    }
}
pub fn mac(ip: IpAddr) -> Option<String> {
    neighbor(ip).map(|n| n.mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_known_packet() {
        // Verifying a packet that already contains its checksum yields zero.
        let p = icmp_request(8, 0x1234, 7, true);
        assert_eq!(icmp_checksum(&p), 0);
        assert_eq!(&p[4..8], &[0x12, 0x34, 0, 7]);
        assert_eq!(p.len(), 40);
    }

    #[test]
    fn echo_reply_with_and_without_ip_header() {
        let mut icmp = vec![0, 0, 0, 0, 0x12, 0x34, 0, 9];
        icmp.extend_from_slice(&[0; 32]);
        assert_eq!(parse_echo_reply(&icmp, true), Some((None, 0x1234, 9)));
        let mut packet = vec![
            0x45, 0, 0, 60, 0, 0, 0, 0, 57, 1, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
        ];
        packet.extend_from_slice(&icmp);
        assert_eq!(parse_echo_reply(&packet, true), Some((Some(57), 0x1234, 9)));
        icmp[0] = 3;
        assert_eq!(parse_echo_reply(&icmp, true), None);
        let v6 = [129u8, 0, 0, 0, 0, 1, 0, 2];
        assert_eq!(parse_echo_reply(&v6, false), Some((None, 1, 2)));
    }

    #[test]
    fn proc_arp_requires_complete_entry() {
        let text = "IP address       HW type     Flags       HW address            Mask     Device\n\
                    192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n\
                    192.168.1.7      0x1         0x0         00:00:00:00:00:00     *        eth0\n";
        assert_eq!(
            parse_proc_arp(text, "192.168.1.1".parse().unwrap()).as_deref(),
            Some("AA:BB:CC:DD:EE:FF")
        );
        assert_eq!(parse_proc_arp(text, "192.168.1.7".parse().unwrap()), None);
        assert_eq!(parse_proc_arp(text, "192.168.1.9".parse().unwrap()), None);
    }

    #[test]
    fn neighbor_command_output() {
        assert_eq!(
            parse_ip_neigh("192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:0f REACHABLE").as_deref(),
            Some("AA:BB:CC:DD:EE:0F")
        );
        assert_eq!(parse_ip_neigh("192.168.1.9 dev eth0  FAILED"), None);
        assert_eq!(
            parse_arp_n("? (10.0.0.1) at 0:1a:2b:3c:4d:5e on en0 ifscope [ethernet]").as_deref(),
            Some("00:1A:2B:3C:4D:5E")
        );
        assert_eq!(parse_arp_n("? (10.0.0.9) at (incomplete) on en0"), None);
    }
    fn ip_header(src: [u8; 4], dst: [u8; 4], proto: u8) -> Vec<u8> {
        let mut h = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0];
        h.extend(src);
        h.extend(dst);
        h
    }

    #[test]
    fn traceroute_reply_parsing() {
        let me = [10, 0, 0, 5];
        let target = std::net::Ipv4Addr::new(8, 8, 8, 8);
        let echo_request = icmp_request(8, 0x4321, 7, true);
        // Time Exceeded from a router quoting our original request to the target.
        let mut te = ip_header([192, 168, 1, 1], me, 1);
        te.extend([11, 0, 0, 0, 0, 0, 0, 0]);
        te.extend(ip_header(me, target.octets(), 1));
        te.extend(&echo_request[..8]);
        assert_eq!(
            parse_hop_reply(&te, target, 0x4321, 7),
            Some([192, 168, 1, 1].into())
        );
        assert_eq!(
            parse_hop_reply(&te, target, 0x4321, 8),
            None,
            "different probe"
        );
        assert_eq!(parse_hop_reply(&te, target, 0x1111, 7), None, "other trace");
        // Echo reply from the target.
        let mut reply = ip_header(target.octets(), me, 1);
        reply.extend([0, 0, 0, 0, 0x43, 0x21, 0, 7]);
        assert_eq!(parse_hop_reply(&reply, target, 0x4321, 7), Some(target));
        reply[20 + 5] = 0x99;
        assert_eq!(parse_hop_reply(&reply, target, 0x4321, 7), None);
        assert_eq!(parse_hop_reply(&[0x45], target, 1, 1), None);
        assert_eq!(parse_hop_reply(&[], target, 1, 1), None);
    }

    #[test]
    fn parallel_traces_do_not_steal_replies() {
        // Same identifier and TTL, but the quoted request went to another host.
        let me = [10, 0, 0, 5];
        let a = std::net::Ipv4Addr::new(10, 1, 0, 1);
        let b = std::net::Ipv4Addr::new(10, 2, 0, 1);
        let mut te = ip_header([192, 168, 1, 1], me, 1);
        te.extend([11, 0, 0, 0, 0, 0, 0, 0]);
        te.extend(ip_header(me, b.octets(), 1));
        te.extend(&icmp_request(8, 0x4321, 3, true)[..8]);
        assert_eq!(parse_hop_reply(&te, a, 0x4321, 3), None);
        assert_eq!(
            parse_hop_reply(&te, b, 0x4321, 3),
            Some([192, 168, 1, 1].into())
        );
        // An echo reply must come from the traced destination itself.
        let mut reply = ip_header(b.octets(), me, 1);
        reply.extend([0, 0, 0, 0, 0x43, 0x21, 0, 3]);
        assert_eq!(parse_hop_reply(&reply, a, 0x4321, 3), None);
        assert_eq!(parse_hop_reply(&reply, b, 0x4321, 3), Some(b));
        // Malformed headers (IHL < 5, non-ICMP inner packet) are rejected without panicking.
        let mut short = reply.clone();
        short[0] = 0x41;
        assert_eq!(parse_hop_reply(&short, b, 0x4321, 3), None);
        let mut inner_udp = te.clone();
        inner_udp[28 + 9] = 17;
        assert_eq!(parse_hop_reply(&inner_udp, b, 0x4321, 3), None);
        let mut inner_short = te;
        inner_short[28] = 0x42;
        assert_eq!(parse_hop_reply(&inner_short, b, 0x4321, 3), None);
    }

    #[test]
    fn echo_reply_with_bad_ihl_does_not_panic() {
        for first in [0x40u8, 0x41, 0x44] {
            for len in 1..=24 {
                let mut p = vec![0u8; len];
                p[0] = first;
                assert_eq!(parse_echo_reply(&p, true), None, "{first:#x} len {len}");
            }
        }
    }

    #[test]
    fn echo_matching_per_socket_kind() {
        // Raw and macOS datagram sockets: identifier and sequence must both match.
        assert!(echo_matches(false, (7, 9), (7, 9)));
        assert!(
            !echo_matches(false, (7, 10), (7, 9)),
            "parallel echo, other seq"
        );
        assert!(!echo_matches(false, (8, 9), (7, 9)), "other process");
        // Linux datagram sockets rewrite the identifier; the sequence still decides.
        assert!(echo_matches(true, (4242, 9), (7, 9)));
        assert!(!echo_matches(true, (4242, 10), (7, 9)));
    }

    #[test]
    fn stale_neighbor_is_mac_only() {
        assert!(ip_neigh_reachable(
            "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:0f REACHABLE"
        ));
        for state in ["STALE", "DELAY", "PROBE", "PERMANENT"] {
            assert!(!ip_neigh_reachable(&format!(
                "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:0f {state}"
            )));
        }
        assert!(!ip_neigh_reachable("192.168.1.9 dev eth0  FAILED"));
        let mut poked = false;
        let cached = neighbor_outcome(Some(("AA:BB:CC:DD:EE:FF".into(), false)), || {
            poked = true;
            None
        });
        assert_eq!(
            cached,
            Some(Neighbor {
                mac: "AA:BB:CC:DD:EE:FF".into(),
                fresh: false
            })
        );
        assert!(!poked, "a cached entry sends no extra traffic");
        let resolved = neighbor_outcome(None, || Some("AA:BB:CC:DD:EE:01".into()));
        assert!(resolved.unwrap().fresh, "appeared after the poke");
        assert_eq!(neighbor_outcome(None, || None), None);
        assert!(
            neighbor_outcome(Some(("AA:BB:CC:DD:EE:FF".into(), true)), || None)
                .unwrap()
                .fresh
        );
    }

    #[test]
    fn route_decision_needs_gateway_and_same_interface() {
        let dest = std::net::Ipv4Addr::new(8, 8, 8, 8);
        let gw = std::net::Ipv4Addr::new(192, 168, 1, 1);
        assert_eq!(
            route_decision(dest, true, gw, Some(4), Some(4)),
            Ok(NextHop::Gateway(gw))
        );
        assert_eq!(
            route_decision(dest, false, gw, Some(4), Some(4)),
            Ok(NextHop::OnLink),
            "direct route"
        );
        assert_eq!(
            route_decision(dest, true, std::net::Ipv4Addr::UNSPECIFIED, None, None),
            Ok(NextHop::OnLink)
        );
        assert!(route_decision(dest, true, gw, Some(4), Some(7)).is_err());
        assert_eq!(NextHop::Gateway(gw).l2_address(dest), gw);
        assert_eq!(NextHop::OnLink.l2_address(dest), dest);
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn proc_route_best_match() {
        let text = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
            eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
            eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n\
            eth0\t0000000A\t0201A8C0\t0003\t0\t0\t50\t000000FF\t0\t0\t0\n\
            eth1\t0000000A\t0101000A\t0003\t0\t0\t10\t000000FF\t0\t0\t0\n\
            eth0\t0000A8C0\t00000000\t0201\t0\t0\t0\t0000FFFF\t0\t0\t0\n";
        let routes = parse_proc_route_table(text);
        assert_eq!(routes.len(), 4, "reject route skipped");
        let gw = std::net::Ipv4Addr::new(192, 168, 1, 1);
        assert_eq!(
            best_route(&routes, "8.8.8.8".parse().unwrap(), "eth0"),
            Ok(NextHop::Gateway(gw))
        );
        assert_eq!(
            best_route(&routes, "192.168.1.50".parse().unwrap(), "eth0"),
            Ok(NextHop::OnLink),
            "longest prefix beats the default route"
        );
        // 10/8 exists twice; the lower metric (eth1) wins, which is not the capture interface.
        assert!(best_route(&routes, "10.1.2.3".parse().unwrap(), "eth0").is_err());
        assert_eq!(
            best_route(&routes, "10.1.2.3".parse().unwrap(), ""),
            Ok(NextHop::Gateway("10.0.1.1".parse().unwrap()))
        );
        assert!(best_route(&[], "8.8.8.8".parse().unwrap(), "").is_err());
    }

    #[test]
    fn route_get_output() {
        let routed = "   route to: 8.8.8.8\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>\n";
        assert_eq!(
            parse_route_get(routed, "en0"),
            Ok(NextHop::Gateway("192.168.1.1".parse().unwrap()))
        );
        assert!(parse_route_get(routed, "en1").is_err());
        let local = "   route to: 192.168.1.20\ndestination: 192.168.1.0\n       mask: 255.255.255.0\n  interface: en0\n      flags: <UP,DONE,CLONING>\n";
        assert_eq!(parse_route_get(local, ""), Ok(NextHop::OnLink));
        let link = "   route to: 192.168.1.20\n    gateway: link#4\n  interface: en0\n";
        assert_eq!(parse_route_get(link, "en0"), Ok(NextHop::OnLink));
        assert!(parse_route_get("route: writing to routing socket: not in table", "").is_err());
    }

    #[test]
    fn icmpv6_hop_replies() {
        let me: std::net::Ipv6Addr = "2001:db8::5".parse().unwrap();
        let dest: std::net::Ipv6Addr = "2001:db8:1::1".parse().unwrap();
        let router: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let request = icmp_request(128, 0x4321, 3, false);
        let mut te = vec![3u8, 0, 0, 0, 0, 0, 0, 0];
        let mut ip6 = vec![0x60, 0, 0, 0, 0, 40, 58, 1];
        ip6.extend(me.octets());
        ip6.extend(dest.octets());
        te.extend(&ip6);
        te.extend(&request[..8]);
        assert_eq!(parse_hop6_reply(&te, router, dest, 0x4321, 3), Some(false));
        assert_eq!(parse_hop6_reply(&te, router, dest, 0x4321, 4), None);
        assert_eq!(parse_hop6_reply(&te, router, router, 0x4321, 3), None);
        let mut short = te.clone();
        short.truncate(50);
        assert_eq!(parse_hop6_reply(&short, router, dest, 0x4321, 3), None);
        let reply = [129u8, 0, 0, 0, 0x43, 0x21, 0, 3];
        assert_eq!(parse_hop6_reply(&reply, dest, dest, 0x4321, 3), Some(true));
        assert_eq!(parse_hop6_reply(&reply, router, dest, 0x4321, 3), None);
        assert_eq!(parse_hop6_reply(&[], dest, dest, 1, 1), None);
    }

    #[test]
    fn udp_hop_replies() {
        let me = [10, 0, 0, 5];
        let dest = std::net::Ipv4Addr::new(10, 9, 0, 1);
        let quoted = |dport: u16| {
            let mut q = ip_header(me, dest.octets(), 17);
            q.extend(50000u16.to_be_bytes());
            q.extend(dport.to_be_bytes());
            q.extend([0, 20, 0, 0]);
            q
        };
        let mut te = ip_header([192, 168, 1, 1], me, 1);
        te.extend([11, 0, 0, 0, 0, 0, 0, 0]);
        te.extend(quoted(33437));
        assert_eq!(
            parse_udp_hop_reply(&te, dest, 50000, 33437),
            Some(([192, 168, 1, 1].into(), false))
        );
        assert_eq!(parse_udp_hop_reply(&te, dest, 50000, 33438), None);
        assert_eq!(parse_udp_hop_reply(&te, dest, 50001, 33437), None);
        let mut unreachable = ip_header(dest.octets(), me, 1);
        unreachable.extend([3, 3, 0, 0, 0, 0, 0, 0]);
        unreachable.extend(quoted(33440));
        assert_eq!(
            parse_udp_hop_reply(&unreachable, dest, 50000, 33440),
            Some((dest, true))
        );
        let mut truncated = te.clone();
        truncated.truncate(te.len() - 6);
        assert_eq!(parse_udp_hop_reply(&truncated, dest, 50000, 33437), None);
        assert_eq!(parse_udp_hop_reply(&[0x45], dest, 1, 1), None);
    }

    #[test]
    fn udp_trace_ports_avoid_ot_and_printer_ports() {
        for ttl in 1..=64u16 {
            let port = UDP_TRACE_BASE + ttl;
            assert!(!crate::service::is_ot_port_candidate(port), "{port}");
            assert!(port != 515 && !(9100..=9107).contains(&port), "{port}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn native_route_lookup() {
        // The loopback route is direct; an Internet address goes via a gateway when
        // this machine has a default route (no route at all is an error, not a panic).
        let lo = std::net::Ipv4Addr::LOCALHOST;
        assert_eq!(
            next_hop(lo, std::net::Ipv4Addr::UNSPECIFIED, ""),
            Ok(NextHop::OnLink)
        );
        let internet = next_hop(
            "8.8.8.8".parse().unwrap(),
            std::net::Ipv4Addr::UNSPECIFIED,
            "",
        );
        // With the outgoing source address, the interface check (GetIpAddrTable) must
        // agree with the route (a UDP connect sends nothing).
        let local = std::net::UdpSocket::bind("0.0.0.0:0")
            .and_then(|s| s.connect("8.8.8.8:53").map(|_| s))
            .and_then(|s| s.local_addr());
        if let (Ok(hop), Ok(std::net::SocketAddr::V4(local))) = (&internet, local) {
            assert_eq!(
                next_hop("8.8.8.8".parse().unwrap(), *local.ip(), ""),
                Ok(*hop)
            );
            // A source address on another interface (loopback) is refused.
            assert!(next_hop("8.8.8.8".parse().unwrap(), lo, "").is_err());
        }
        if let Ok(hop) = internet {
            match hop {
                NextHop::Gateway(g) => assert!(!g.is_unspecified() && !g.is_loopback(), "{g}"),
                NextHop::OnLink => panic!("8.8.8.8 is not on-link"),
            }
        }
    }

    #[test]
    fn udp_hop_without_privileges_is_a_clear_error() {
        // Unprivileged: no raw socket, a clear error and nothing sent. Privileged: a
        // loopback answer or a timeout, never a panic.
        match udp_hop(std::net::Ipv4Addr::LOCALHOST, 1, 300) {
            Err(e) => assert!(e.contains("raw ICMP socket"), "{e}"),
            Ok(r) => assert!(r.ip.is_none() || r.reached, "{r:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn native_ipv6_hop_limit_trace() {
        let r = hop("::1".parse().unwrap(), 1, 1000, 1).unwrap();
        assert!(r.reached, "{r:?}");
        assert_eq!(r.ip, Some("::1".parse().unwrap()));
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn proc_route_on_link_networks() {
        let text = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
            eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
            eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n\
            eth1\t000010AC\t00000000\t0001\t0\t0\t100\t0000FFFF\t0\t0\t0\n\
            eth2\t00000A0A\t00000000\t0000\t0\t0\t100\t0000FFFF\t0\t0\t0\n";
        let routes = parse_proc_route(text);
        assert_eq!(
            routes.len(),
            2,
            "default via gateway and down route excluded"
        );
        assert!(on_link(&routes, "192.168.1.77".parse().unwrap()));
        assert!(on_link(&routes, "172.16.200.1".parse().unwrap()));
        assert!(!on_link(&routes, "8.8.8.8".parse().unwrap()));
        assert!(!on_link(&routes, "10.10.0.1".parse().unwrap()));
        assert!(parse_proc_route("Iface\tDestination\n").is_empty());
    }
}
