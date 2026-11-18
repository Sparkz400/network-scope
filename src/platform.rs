use std::net::IpAddr;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct HopReply {
    pub ip: Option<IpAddr>,
    pub rtt: Option<u32>,
    pub reached: bool,
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
                if !raw || (rid == id && rseq == seq) {
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
/// Returns (ttl if an IP header was present, identifier, sequence) for an echo reply.
/// Raw and macOS sockets deliver the IPv4 header; Linux datagram ICMP sockets do not.
#[cfg_attr(windows, allow(dead_code))]
pub fn parse_echo_reply(data: &[u8], v4: bool) -> Option<(Option<u8>, u16, u16)> {
    let (icmp, ttl) = if v4 && data.first().is_some_and(|b| b >> 4 == 4) {
        let header = usize::from(data[0] & 15) * 4;
        if data.len() < header + 8 || data[9] != 1 {
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
/// Linux `/proc/net/arp`: only entries with the "complete" flag (0x2) count.
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
/// BSD/macOS `arp -n IP`, e.g. `? (10.0.0.1) at 0:1a:2b:3c:4d:5e on en0 ifscope [ethernet]`.
#[cfg_attr(windows, allow(dead_code))]
pub fn parse_arp_n(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        words.find(|w| *w == "at")?;
        normalize_mac(words.next()?)
    })
}

#[cfg(not(windows))]
fn neighbor_mac(ip: IpAddr) -> Option<String> {
    use std::process::Command;
    let lookup = |ip: IpAddr| -> Option<String> {
        if let Ok(text) = std::fs::read_to_string("/proc/net/arp") {
            if let Some(mac) = parse_proc_arp(&text, ip) {
                return Some(mac);
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
        run("ip", &["neigh", "show", &target])
            .and_then(|t| parse_ip_neigh(&t))
            .or_else(|| run("arp", &["-n", &target]).and_then(|t| parse_arp_n(&t)))
    };
    if let Some(mac) = lookup(ip) {
        return Some(mac);
    }
    // Populate the neighbor table with one harmless datagram, then look again.
    if let Ok(socket) = std::net::UdpSocket::bind(if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
    {
        let _ = socket.send_to(&[0], (ip, 9));
    }
    for wait in [60, 200, 500] {
        std::thread::sleep(std::time::Duration::from_millis(wait));
        if let Some(mac) = lookup(ip) {
            return Some(mac);
        }
    }
    None
}

#[cfg(not(windows))]
fn hop_unix(ip: IpAddr, ttl: u8, timeout: u32) -> Result<HopReply, String> {
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
    let id = (std::process::id() & 0xffff) as u16;
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
        if let Some(from) = parse_hop_reply(&data, id, seq) {
            return Ok(HopReply {
                ip: Some(IpAddr::V4(from)),
                rtt: Some(started.elapsed().as_millis() as u32),
                reached: from == dest,
            });
        }
    }
}

/// Raw-socket traceroute reply: an echo reply, or Time Exceeded / Unreachable quoting our request.
#[cfg_attr(windows, allow(dead_code))]
pub fn parse_hop_reply(data: &[u8], id: u16, seq: u16) -> Option<std::net::Ipv4Addr> {
    let outer = usize::from(*data.first()? & 15) * 4;
    let source = std::net::Ipv4Addr::new(
        *data.get(12)?,
        *data.get(13)?,
        *data.get(14)?,
        *data.get(15)?,
    );
    let icmp = data.get(outer..)?;
    let matches_request = |b: &[u8]| {
        b.len() >= 8
            && b[0] == 8
            && u16::from_be_bytes([b[4], b[5]]) == id
            && u16::from_be_bytes([b[6], b[7]]) == seq
    };
    match *icmp.first()? {
        0 if icmp.len() >= 8
            && u16::from_be_bytes([icmp[4], icmp[5]]) == id
            && u16::from_be_bytes([icmp[6], icmp[7]]) == seq =>
        {
            Some(source)
        }
        3 | 11 => {
            let inner = icmp.get(8..)?;
            let inner_header = usize::from(*inner.first()? & 15) * 4;
            matches_request(inner.get(inner_header..)?).then_some(source)
        }
        _ => None,
    }
}

/// One traceroute probe with the given TTL.
pub fn hop(ip: IpAddr, ttl: u8, timeout: u32) -> Result<HopReply, String> {
    #[cfg(windows)]
    {
        match ip {
            IpAddr::V4(v4) => win::hop(v4, ttl, timeout),
            IpAddr::V6(_) => Err("Traceroute supports IPv4 only".into()),
        }
    }
    #[cfg(not(windows))]
    {
        hop_unix(ip, ttl, timeout)
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
pub fn mac(ip: IpAddr) -> Option<String> {
    #[cfg(windows)]
    {
        win::mac(ip)
    }
    #[cfg(not(windows))]
    {
        neighbor_mac(ip)
    }
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
    #[test]
    fn traceroute_reply_parsing() {
        let echo_request = icmp_request(8, 0x4321, 7, true);
        let ip_header = |src: [u8; 4], proto: u8| {
            let mut h = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, proto, 0, 0];
            h.extend(src);
            h.extend([10, 0, 0, 5]);
            h
        };
        // Time Exceeded from a router quoting our original request.
        let mut te = ip_header([192, 168, 1, 1], 1);
        te.extend([11, 0, 0, 0, 0, 0, 0, 0]);
        te.extend(ip_header([10, 0, 0, 5], 1));
        te.extend(&echo_request[..8]);
        assert_eq!(
            parse_hop_reply(&te, 0x4321, 7),
            Some([192, 168, 1, 1].into())
        );
        assert_eq!(parse_hop_reply(&te, 0x4321, 8), None, "different probe");
        assert_eq!(parse_hop_reply(&te, 0x1111, 7), None, "other process");
        // Echo reply from the target.
        let mut reply = ip_header([8, 8, 8, 8], 1);
        reply.extend([0, 0, 0, 0, 0x43, 0x21, 0, 7]);
        assert_eq!(
            parse_hop_reply(&reply, 0x4321, 7),
            Some([8, 8, 8, 8].into())
        );
        reply[20 + 5] = 0x99;
        assert_eq!(parse_hop_reply(&reply, 0x4321, 7), None);
        assert_eq!(parse_hop_reply(&[0x45], 1, 1), None);
        assert_eq!(parse_hop_reply(&[], 1, 1), None);
    }
}
