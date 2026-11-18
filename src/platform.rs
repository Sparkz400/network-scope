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
    extern "system" {
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
                    }
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
    if let IpAddr::V4(v4) = ip {
        if let Ok(text) = std::fs::read_to_string("/proc/net/route") {
            let routes = parse_proc_route(&text);
            if !routes.is_empty() && !on_link(&routes, v4) {
                return None;
            }
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
    socket.set_ttl(u32::from(ttl)).map_err(|e| e.to_string())?;
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

/// One traceroute probe with the given TTL. `id` identifies the trace (one value per
/// `trace::trace` call), the TTL is used as the sequence number.
pub fn hop(ip: IpAddr, ttl: u8, timeout: u32, id: u16) -> Result<HopReply, String> {
    #[cfg(windows)]
    {
        // IcmpSendEcho matches replies itself; the identifier is unused here.
        let _ = id;
        match ip {
            IpAddr::V4(v4) => win::hop(v4, ttl, timeout),
            IpAddr::V6(_) => Err("Traceroute supports IPv4 only".into()),
        }
    }
    #[cfg(not(windows))]
    {
        hop_unix(ip, ttl, timeout, id)
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
        let text =
            "IP address       HW type     Flags       HW address            Mask     Device\n\
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

    #[cfg(target_endian = "little")]
    #[test]
    fn proc_route_on_link_networks() {
        let text =
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
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
