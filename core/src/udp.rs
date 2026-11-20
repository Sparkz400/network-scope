//! UDP service probing with protocol-correct, read-only requests: DNS (version.bind), NTP client
//! request, SNMP get of sysDescr with the community "public", SSDP unicast M-SEARCH, mDNS
//! service enumeration, NetBIOS node status and DHCPINFORM. Any reply from the probed address
//! means "open"; an ICMP port-unreachable means "closed"; silence is "open or filtered".
use crate::{core::Gate, sendlog::PacketKind};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::{net::UdpSocket, time::timeout};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Dns,
    Dhcp,
    Ntp,
    NetBios,
    Snmp,
    Ssdp,
    Mdns,
    Generic,
}
impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Dns => "dns",
            Kind::Dhcp => "dhcp",
            Kind::Ntp => "ntp",
            Kind::NetBios => "netbios",
            Kind::Snmp => "snmp",
            Kind::Ssdp => "ssdp",
            Kind::Mdns => "mdns",
            Kind::Generic => "generic",
        }
    }
}
/// What a probe to `port` is, for the plan and the sent log: `dns/53`, `snmp/161`, or for a
/// port without a built-in protocol `probe-name/5000` / `empty datagram/5000`.
fn describe(kind: Kind, port: u16, data_probe: Option<&crate::service::Probe>) -> String {
    match (kind, data_probe) {
        (Kind::Generic, Some(p)) => format!("{}/{port}", p.name),
        (Kind::Generic, None) => format!("empty datagram/{port}"),
        _ => format!("{}/{port}", kind.name()),
    }
}
/// [`describe`] for a port as the UDP scan would probe it.
pub fn describe_port(port: u16) -> String {
    let kind = kind_for_port(port);
    describe(
        kind,
        port,
        payload_probe(port, kind, &crate::service::udp_probes()),
    )
}
pub fn kind_for_port(port: u16) -> Kind {
    match port {
        53 => Kind::Dns,
        67 => Kind::Dhcp,
        123 => Kind::Ntp,
        137 => Kind::NetBios,
        161 => Kind::Snmp,
        1900 => Kind::Ssdp,
        5353 => Kind::Mdns,
        _ => Kind::Generic,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum State {
    Open,
    Closed,
    NoReply,
    Error(String),
}
#[derive(Debug)]
pub struct Probe {
    pub state: State,
    pub info: String,
    pub mac: Option<String>,
}

fn rand32() -> u32 {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0x1234_5678);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(1);
    let v = N.fetch_add(0x9e37_79b9, std::sync::atomic::Ordering::Relaxed) ^ t;
    (v ^ (v >> 15)).wrapping_mul(0x2c1b_3c6d)
}

// ---- DNS helpers -------------------------------------------------------------------------

pub fn dns_query(id: u16, name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
    let mut q = vec![];
    q.extend(id.to_be_bytes());
    q.extend([0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.').filter(|l| !l.is_empty()) {
        q.push(label.len() as u8);
        q.extend(label.as_bytes());
    }
    q.push(0);
    q.extend(qtype.to_be_bytes());
    q.extend(qclass.to_be_bytes());
    q
}
fn skip_name(m: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let len = *m.get(i)?;
        match len {
            0 => return Some(i + 1),
            l if l & 0xC0 == 0xC0 => return (i + 2 <= m.len()).then_some(i + 2),
            l => i += 1 + usize::from(l),
        }
    }
}
fn read_name(m: &[u8], mut i: usize) -> Option<String> {
    let mut out = vec![];
    for _ in 0..32 {
        let len = *m.get(i)?;
        if len == 0 {
            return Some(out.join("."));
        }
        if len & 0xC0 == 0xC0 {
            i = (usize::from(len & 0x3F) << 8) | usize::from(*m.get(i + 1)?);
            continue;
        }
        let label = m.get(i + 1..i + 1 + usize::from(len))?;
        out.push(
            String::from_utf8_lossy(label)
                .chars()
                .filter(|c| !c.is_control())
                .collect::<String>(),
        );
        i += 1 + usize::from(len);
    }
    None
}
/// Walks the answer section: (type, rdata offset, rdata length).
fn answers(m: &[u8]) -> Option<Vec<(u16, usize, usize)>> {
    let (qd, an) = (
        usize::from(u16::from_be_bytes([*m.get(4)?, *m.get(5)?])),
        usize::from(u16::from_be_bytes([*m.get(6)?, *m.get(7)?])),
    );
    let mut i = 12;
    for _ in 0..qd {
        i = skip_name(m, i)? + 4;
    }
    let mut out = vec![];
    for _ in 0..an.min(64) {
        i = skip_name(m, i)?;
        let kind = u16::from_be_bytes([*m.get(i)?, *m.get(i + 1)?]);
        let len = usize::from(u16::from_be_bytes([*m.get(i + 8)?, *m.get(i + 9)?]));
        i += 10;
        m.get(i..i + len)?;
        out.push((kind, i, len));
        i += len;
    }
    Some(out)
}
pub fn parse_dns(m: &[u8]) -> Option<String> {
    if m.len() < 12 || m[2] & 0x80 == 0 {
        return None;
    }
    let rcode = m[3] & 15;
    for (kind, at, len) in answers(m).unwrap_or_default() {
        if kind == 16 && len > 1 {
            let n = usize::from(m[at]).min(len - 1);
            let text: String = String::from_utf8_lossy(&m[at + 1..at + 1 + n])
                .chars()
                .filter(|c| !c.is_control())
                .collect();
            return Some(format!("DNS server, version.bind: {text}"));
        }
    }
    Some(format!("DNS server (version hidden, rcode {rcode})"))
}
pub fn parse_mdns(m: &[u8]) -> Option<String> {
    if m.len() < 12 || m[2] & 0x80 == 0 {
        return None;
    }
    let names: Vec<String> = answers(m)?
        .into_iter()
        .filter(|(k, ..)| *k == 12)
        .filter_map(|(_, at, _)| read_name(m, at))
        .collect();
    Some(if names.is_empty() {
        "mDNS responder".into()
    } else {
        let extra = names.len().saturating_sub(6);
        let shown = names.iter().take(6).cloned().collect::<Vec<_>>().join(", ");
        format!(
            "mDNS services: {shown}{}",
            if extra > 0 {
                format!(" (+{extra})")
            } else {
                String::new()
            }
        )
    })
}

// ---- NTP, SSDP, NetBIOS ------------------------------------------------------------------

pub fn ntp_request() -> Vec<u8> {
    let mut p = vec![0u8; 48];
    p[0] = 0x23;
    p
}
pub fn parse_ntp(m: &[u8]) -> Option<String> {
    if m.len() < 48 {
        return None;
    }
    let (version, mode, stratum) = ((m[0] >> 3) & 7, m[0] & 7, m[1]);
    if !(4..=6).contains(&mode) {
        return None;
    }
    let refid = if stratum <= 1 {
        String::from_utf8_lossy(&m[12..16])
            .trim_matches('\0')
            .to_string()
    } else {
        Ipv4Addr::new(m[12], m[13], m[14], m[15]).to_string()
    };
    Some(format!(
        "NTPv{version} stratum {stratum}, reference {refid}"
    ))
}
pub fn ssdp_request(ip: IpAddr) -> Vec<u8> {
    format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: {ip}:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n"
    )
    .into_bytes()
}
pub fn parse_ssdp(m: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(m);
    if !text.starts_with("HTTP/1.1 200") && !text.to_ascii_uppercase().starts_with("NOTIFY") {
        return None;
    }
    let pick = |name: &str| {
        text.lines().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| {
                v.trim()
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(100)
                    .collect::<String>()
            })
        })
    };
    let mut parts = vec![];
    for (label, key) in [
        ("server", "SERVER"),
        ("type", "ST"),
        ("location", "LOCATION"),
    ] {
        if let Some(v) = pick(key) {
            parts.push(format!("{label}: {v}"));
        }
    }
    Some(format!("SSDP/UPnP {}", parts.join("; ")).trim().to_string())
}
pub fn netbios_request() -> Vec<u8> {
    let mut q = vec![];
    q.extend((rand32() as u16).to_be_bytes());
    q.extend([0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    q.push(0x20);
    q.extend(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    q.push(0);
    q.extend([0, 0x21, 0, 1]);
    q
}
pub fn parse_netbios(m: &[u8]) -> Option<(String, Option<String>)> {
    if m.len() < 12 || m[2] & 0x80 == 0 {
        return None;
    }
    let at = skip_name(m, 12)? + 10;
    let count = usize::from(*m.get(at)?);
    let mut names = vec![];
    for i in 0..count.min(32) {
        let e = m.get(at + 1 + i * 18..at + 1 + (i + 1) * 18)?;
        let name = String::from_utf8_lossy(&e[..15]).trim().to_string();
        let flags = u16::from_be_bytes([e[16], e[17]]);
        names.push(format!(
            "{name}<{:02X}{}>",
            e[15],
            if flags & 0x8000 != 0 { " group" } else { "" }
        ));
    }
    let mac = m
        .get(at + 1 + count * 18..at + 1 + count * 18 + 6)
        .filter(|b| b.iter().any(|v| *v != 0))
        .map(|b| {
            b.iter()
                .map(|v| format!("{v:02X}"))
                .collect::<Vec<_>>()
                .join(":")
        });
    let shown = names.iter().take(8).cloned().collect::<Vec<_>>().join(", ");
    Some((format!("NetBIOS names: {shown}"), mac))
}

// ---- SNMP --------------------------------------------------------------------------------

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    match content.len() {
        n if n < 128 => v.push(n as u8),
        n if n < 256 => v.extend([0x81, n as u8]),
        n => v.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    v.extend(content);
    v
}
/// SNMP GetRequest for sysDescr.0 (1.3.6.1.2.1.1.1.0). `version` is 0 (v1) or 1 (v2c).
pub fn snmp_get(version: u8, community: &str, request_id: u32) -> Vec<u8> {
    let oid = [0x2B, 6, 1, 2, 1, 1, 1, 0];
    let varbind = tlv(0x30, &[tlv(6, &oid), vec![5, 0]].concat());
    let pdu = tlv(
        0xA0,
        &[
            tlv(2, &request_id.to_be_bytes()),
            tlv(2, &[0]),
            tlv(2, &[0]),
            tlv(0x30, &varbind),
        ]
        .concat(),
    );
    tlv(
        0x30,
        &[tlv(2, &[version]), tlv(4, community.as_bytes()), pdu].concat(),
    )
}
fn ber(d: &[u8], i: usize) -> Option<(u8, &[u8], usize)> {
    let tag = *d.get(i)?;
    let first = *d.get(i + 1)?;
    let (len, start) = if first < 128 {
        (usize::from(first), i + 2)
    } else {
        let n = usize::from(first & 0x7F);
        if n == 0 || n > 3 {
            return None;
        }
        let mut len = 0usize;
        for k in 0..n {
            len = (len << 8) | usize::from(*d.get(i + 2 + k)?);
        }
        (len, i + 2 + n)
    };
    Some((tag, d.get(start..start + len)?, start + len))
}
/// (error-status, sysDescr text if the first varbind is an octet string)
pub fn parse_snmp(d: &[u8]) -> Option<(u32, Option<String>)> {
    let (0x30, msg, _) = ber(d, 0)? else {
        return None;
    };
    let (2, _, i) = ber(msg, 0)? else { return None };
    let (4, _, i) = ber(msg, i)? else { return None };
    let (0xA2, pdu, _) = ber(msg, i)? else {
        return None;
    };
    let (2, _, i) = ber(pdu, 0)? else { return None };
    let (2, status, i) = ber(pdu, i)? else {
        return None;
    };
    let (2, _, i) = ber(pdu, i)? else { return None };
    let (0x30, list, _) = ber(pdu, i)? else {
        return None;
    };
    let status = status.iter().fold(0u32, |a, b| (a << 8) | u32::from(*b));
    let text = (|| {
        let (0x30, vb, _) = ber(list, 0)? else {
            return None;
        };
        let (6, _, i) = ber(vb, 0)? else { return None };
        let (4, value, _) = ber(vb, i)? else {
            return None;
        };
        Some(
            String::from_utf8_lossy(value)
                .chars()
                .map(|c| if c.is_control() { ' ' } else { c })
                .collect::<String>()
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .chars()
                .take(160)
                .collect::<String>(),
        )
    })();
    Some((status, text))
}

// ---- DHCP --------------------------------------------------------------------------------

pub fn dhcp_inform(xid: u32, ciaddr: Ipv4Addr, mac: [u8; 6]) -> Vec<u8> {
    let mut p = vec![0u8; 236];
    p[0] = 1;
    p[1] = 1;
    p[2] = 6;
    p[4..8].copy_from_slice(&xid.to_be_bytes());
    p[12..16].copy_from_slice(&ciaddr.octets());
    p[28..34].copy_from_slice(&mac);
    p.extend([0x63, 0x82, 0x53, 0x63]);
    p.extend([53, 1, 8]);
    p.extend([61, 7, 1]);
    p.extend(mac);
    p.extend([55, 6, 1, 3, 6, 15, 28, 51]);
    p.push(255);
    p
}
pub fn parse_dhcp(m: &[u8], xid: u32) -> Option<String> {
    if m.len() < 240
        || m[0] != 2
        || m[4..8] != xid.to_be_bytes()
        || m[236..240] != [0x63, 0x82, 0x53, 0x63]
    {
        return None;
    }
    let (mut kind, mut server, mut mask, mut router, mut dns, mut domain) =
        (0, None, None, None, None, None);
    let ip = |b: &[u8]| (b.len() >= 4).then(|| Ipv4Addr::new(b[0], b[1], b[2], b[3]).to_string());
    let mut i = 240;
    while let Some(&code) = m.get(i) {
        if code == 255 {
            break;
        }
        if code == 0 {
            i += 1;
            continue;
        }
        let len = usize::from(*m.get(i + 1)?);
        let v = m.get(i + 2..i + 2 + len)?;
        match code {
            53 => kind = v.first().copied().unwrap_or(0),
            54 => server = ip(v),
            1 => mask = ip(v),
            3 => router = ip(v),
            6 => {
                dns = Some(
                    v.chunks(4)
                        .filter_map(ip)
                        .take(3)
                        .collect::<Vec<_>>()
                        .join("/"),
                )
            }
            15 => domain = Some(String::from_utf8_lossy(v).trim_matches('\0').to_string()),
            _ => {}
        }
        i += 2 + len;
    }
    let mut parts = vec![];
    for (label, v) in [
        ("server", server),
        ("mask", mask),
        ("router", router),
        ("dns", dns),
        ("domain", domain),
    ] {
        if let Some(v) = v.filter(|v| !v.is_empty()) {
            parts.push(format!("{label} {v}"));
        }
    }
    Some(format!(
        "DHCP {} ({})",
        match kind {
            5 => "ACK",
            6 => "NAK",
            2 => "OFFER",
            _ => "reply",
        },
        parts.join(", ")
    ))
}

// ---- DHCP server discovery (rogue DHCP detection) ----------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    pub server: Ipv4Addr,
    pub offered: Ipv4Addr,
    pub router: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub lease: Option<u32>,
}

pub fn dhcp_discover_packet(xid: u32, mac: [u8; 6]) -> Vec<u8> {
    let mut p = vec![0u8; 236];
    p[0] = 1;
    p[1] = 1;
    p[2] = 6;
    p[4..8].copy_from_slice(&xid.to_be_bytes());
    p[10] = 0x80; // broadcast flag: replies come back to 255.255.255.255:68
    p[28..34].copy_from_slice(&mac);
    p.extend([0x63, 0x82, 0x53, 0x63]);
    p.extend([53, 1, 1]);
    p.extend([61, 7, 1]);
    p.extend(mac);
    p.extend([55, 4, 1, 3, 6, 51]);
    p.push(255);
    p
}

pub fn parse_offer(m: &[u8], xid: u32) -> Option<Offer> {
    if m.len() < 240
        || m[0] != 2
        || m[4..8] != xid.to_be_bytes()
        || m[236..240] != [0x63, 0x82, 0x53, 0x63]
    {
        return None;
    }
    let addr = |b: &[u8]| (b.len() >= 4).then(|| Ipv4Addr::new(b[0], b[1], b[2], b[3]));
    let (mut kind, mut server, mut router, mut dns, mut lease) = (0, None, None, vec![], None);
    let mut i = 240;
    while let Some(&code) = m.get(i) {
        match code {
            255 => break,
            0 => {
                i += 1;
                continue;
            }
            _ => {}
        }
        let len = usize::from(*m.get(i + 1)?);
        let v = m.get(i + 2..i + 2 + len)?;
        match code {
            53 => kind = v.first().copied().unwrap_or(0),
            54 => server = addr(v),
            3 => router = addr(v),
            6 => dns = v.chunks(4).filter_map(addr).take(4).collect(),
            51 if v.len() == 4 => lease = Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]])),
            _ => {}
        }
        i += 2 + len;
    }
    let server = server.or_else(|| addr(&m[20..24]).filter(|a| !a.is_unspecified()))?;
    (kind == 2).then(|| Offer {
        server,
        offered: Ipv4Addr::new(m[16], m[17], m[18], m[19]),
        router,
        dns,
        lease,
    })
}

/// Broadcasts one DHCPDISCOVER and collects every OFFER for `wait`. No REQUEST is ever sent, so
/// no lease is taken, but a server may briefly reserve the address it offered. Needs local UDP port 68.
pub fn dhcp_discover(wait: Duration, log: &crate::sendlog::SentLog) -> Result<Vec<Offer>, String> {
    use std::time::Instant;
    let raw = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)
        .map_err(|e| e.to_string())?;
    raw.set_reuse_address(true).map_err(|e| e.to_string())?;
    raw.set_broadcast(true).map_err(|e| e.to_string())?;
    raw.bind(&SocketAddr::from(([0, 0, 0, 0], 68)).into())
        .map_err(|e| format!("UDP port 68 is busy ({e}); a DHCP client may hold it"))?;
    let sock: std::net::UdpSocket = raw.into();
    let xid = rand32();
    let mac = [0x02, 0x4e, 0x53, 0x00, rand32() as u8, rand32() as u8];
    log.record(PacketKind::DhcpDiscover, "DHCPDISCOVER broadcast");
    sock.send_to(&dhcp_discover_packet(xid, mac), (Ipv4Addr::BROADCAST, 67))
        .map_err(|e| format!("broadcast failed: {e}"))?;
    let end = Instant::now() + wait;
    let mut offers: Vec<Offer> = vec![];
    let mut buf = [0u8; 1500];
    loop {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() || sock.set_read_timeout(Some(left)).is_err() {
            break;
        }
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if let Some(o) = parse_offer(&buf[..n], xid)
                    && !offers.iter().any(|x| x.server == o.server)
                {
                    offers.push(o);
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(offers)
}
// ---- driver ------------------------------------------------------------------------------

fn parse_reply(kind: Kind, reply: &[u8], xid: u32) -> (String, Option<String>) {
    let generic = || format!("responds ({} bytes)", reply.len());
    match kind {
        Kind::Dns => (parse_dns(reply).unwrap_or_else(generic), None),
        Kind::Ntp => (parse_ntp(reply).unwrap_or_else(generic), None),
        Kind::Ssdp => (parse_ssdp(reply).unwrap_or_else(generic), None),
        Kind::Mdns => (parse_mdns(reply).unwrap_or_else(generic), None),
        Kind::Dhcp => (parse_dhcp(reply, xid).unwrap_or_else(generic), None),
        Kind::NetBios => parse_netbios(reply).unwrap_or_else(|| (generic(), None)),
        Kind::Snmp => match parse_snmp(reply) {
            Some((0, Some(text))) => (format!("SNMP sysDescr: {text}"), None),
            Some((status, _)) => (
                format!("SNMP agent (error {status}; community may differ)"),
                None,
            ),
            None => (generic(), None),
        },
        Kind::Generic => (generic(), None),
    }
}

async fn socket(ip: IpAddr, port: u16, kind: Kind) -> Result<UdpSocket, String> {
    let target = SocketAddr::new(ip, port);
    let sock = if kind == Kind::Dhcp {
        let IpAddr::V4(_) = ip else {
            return Err("DHCP needs IPv4".into());
        };
        let raw = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)
            .map_err(|e| e.to_string())?;
        raw.set_reuse_address(true).map_err(|e| e.to_string())?;
        raw.bind(&SocketAddr::from(([0, 0, 0, 0], 68)).into())
            .map_err(|e| format!("UDP port 68 is busy ({e}); a DHCP client may hold it"))?;
        raw.set_nonblocking(true).map_err(|e| e.to_string())?;
        UdpSocket::from_std(raw.into()).map_err(|e| e.to_string())?
    } else {
        UdpSocket::bind(if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })
            .await
            .map_err(|e| e.to_string())?
    };
    sock.connect(target).await.map_err(|e| e.to_string())?;
    Ok(sock)
}

/// Sends the protocol's request up to `tries` times and classifies the answer. Ports without
/// a built-in handler get the payload of a `"proto": "udp"` probe from probes.json when one
/// lists the port (never on OT or printer ports), else an empty datagram.
pub async fn probe_kind(
    ip: IpAddr,
    port: u16,
    kind: Kind,
    wait: Duration,
    tries: u32,
    gate: &Gate,
) -> Probe {
    probe_with(
        ip,
        port,
        kind,
        wait,
        tries,
        gate,
        &crate::service::udp_probes(),
    )
    .await
}

/// The data-driven probe for a generic UDP port, if any may be sent there.
fn payload_probe(
    port: u16,
    kind: Kind,
    probes: &[crate::service::Probe],
) -> Option<&crate::service::Probe> {
    if kind != Kind::Generic || crate::service::is_ot_udp_port(port) {
        return None;
    }
    probes.iter().find(|p| p.ports.contains(&port))
}

async fn probe_with(
    ip: IpAddr,
    port: u16,
    kind: Kind,
    wait: Duration,
    tries: u32,
    gate: &Gate,
    probes: &[crate::service::Probe],
) -> Probe {
    let data_probe = payload_probe(port, kind, probes);
    let sock = match socket(ip, port, kind).await {
        Ok(s) => s,
        Err(e) => {
            return Probe {
                state: State::Error(e),
                info: String::new(),
                mac: None,
            };
        }
    };
    let xid = rand32();
    let local_v4 = match sock.local_addr().map(|a| a.ip()) {
        Ok(IpAddr::V4(v4)) if !v4.is_unspecified() => v4,
        _ => Ipv4Addr::UNSPECIFIED,
    };
    for attempt in 0..tries.max(1) {
        let payload = match kind {
            Kind::Dns => dns_query(rand32() as u16, "version.bind", 16, 3),
            Kind::Ntp => ntp_request(),
            Kind::Snmp => snmp_get(
                if attempt % 2 == 0 { 1 } else { 0 },
                "public",
                rand32() >> 1,
            ),
            Kind::Ssdp => ssdp_request(ip),
            Kind::Mdns => dns_query(0, "_services._dns-sd._udp.local", 12, 0x8001),
            Kind::NetBios => netbios_request(),
            Kind::Dhcp => dhcp_inform(xid, local_v4, [0x02, 0x4e, 0x53, 0x00, 0x00, 0x01]),
            Kind::Generic => data_probe.map_or_else(Vec::new, |p| p.payload.clone()),
        };
        gate.wait_for(PacketKind::UdpProbe, describe(kind, port, data_probe))
            .await;
        if let Err(e) = sock.send(&payload).await {
            return match e.kind() {
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused => {
                    Probe {
                        state: State::Closed,
                        info: String::new(),
                        mac: None,
                    }
                }
                _ => Probe {
                    state: State::Error(e.to_string()),
                    info: String::new(),
                    mac: None,
                },
            };
        }
        let mut buf = vec![0u8; 2048];
        match timeout(wait, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                let identified = data_probe
                    .and_then(|p| crate::service::ProbeDb::identify(p, &buf[..n]))
                    .map(|svc| (svc.summary(), None));
                let (info, mac) = identified.unwrap_or_else(|| parse_reply(kind, &buf[..n], xid));
                return Probe {
                    state: State::Open,
                    info,
                    mac,
                };
            }
            Ok(Err(e))
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                return Probe {
                    state: State::Closed,
                    info: String::new(),
                    mac: None,
                };
            }
            Ok(Err(e)) => {
                return Probe {
                    state: State::Error(e.to_string()),
                    info: String::new(),
                    mac: None,
                };
            }
            Err(_) => {}
        }
    }
    Probe {
        state: State::NoReply,
        info: String::new(),
        mac: None,
    }
}

pub async fn probe(ip: IpAddr, port: u16, wait: Duration, tries: u32, gate: &Gate) -> Probe {
    probe_kind(ip, port, kind_for_port(port), wait, tries, gate).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_version_bind() {
        let q = dns_query(0x1234, "version.bind", 16, 3);
        assert_eq!(q.len(), 12 + 14 + 4);
        assert_eq!(&q[q.len() - 4..], &[0, 16, 0, 3]);
        let mut r = q.clone();
        r[2] = 0x84;
        r[7] = 1;
        r.extend([0xC0, 12, 0, 16, 0, 3, 0, 0, 0, 0, 0, 7, 6]);
        r.extend(b"9.18.1");
        assert_eq!(parse_dns(&r).unwrap(), "DNS server, version.bind: 9.18.1");
        let mut hidden = q;
        hidden[2] = 0x84;
        hidden[3] = 5;
        assert_eq!(
            parse_dns(&hidden).unwrap(),
            "DNS server (version hidden, rcode 5)"
        );
        assert_eq!(parse_dns(&[0; 5]), None);
        // A compression-pointer loop must not hang or panic.
        let mut evil = vec![0u8; 12];
        evil[2] = 0x80;
        evil[5] = 1;
        evil.extend([0xC0, 12, 0, 1, 0, 1]);
        assert!(parse_dns(&evil).is_some());
        assert_eq!(read_name(&[0xC0, 0], 0), None);
    }

    #[test]
    fn mdns_services() {
        let mut r = dns_query(0, "_services._dns-sd._udp.local", 12, 1);
        r[2] = 0x84;
        r[7] = 2;
        for target in ["_http._tcp.local", "_airplay._tcp.local"] {
            r.extend([0xC0, 12, 0, 12, 0, 1, 0, 0, 0, 120]);
            let mut name = vec![];
            for l in target.split('.') {
                name.push(l.len() as u8);
                name.extend(l.as_bytes());
            }
            name.push(0);
            r.extend((name.len() as u16).to_be_bytes());
            r.extend(name);
        }
        assert_eq!(
            parse_mdns(&r).unwrap(),
            "mDNS services: _http._tcp.local, _airplay._tcp.local"
        );
    }

    #[test]
    fn ntp_reply() {
        let mut m = vec![0u8; 48];
        m[0] = 0x24;
        m[1] = 2;
        m[12..16].copy_from_slice(&[10, 0, 0, 1]);
        assert_eq!(
            parse_ntp(&m).unwrap(),
            "NTPv4 stratum 2, reference 10.0.0.1"
        );
        m[1] = 1;
        m[12..16].copy_from_slice(b"GPS\0");
        assert_eq!(parse_ntp(&m).unwrap(), "NTPv4 stratum 1, reference GPS");
        m[0] = 0x23;
        assert_eq!(
            parse_ntp(&m),
            None,
            "a client-mode echo is not a server reply"
        );
        assert_eq!(parse_ntp(&m[..20]), None);
        assert_eq!(ntp_request()[0], 0x23);
    }

    #[test]
    fn ssdp_reply() {
        let r = b"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.168.1.1:5000/desc.xml\r\nSERVER: Linux/4.9 UPnP/1.0 MiniUPnPd/2.1\r\nST: upnp:rootdevice\r\n\r\n";
        assert_eq!(
            parse_ssdp(r).unwrap(),
            "SSDP/UPnP server: Linux/4.9 UPnP/1.0 MiniUPnPd/2.1; type: upnp:rootdevice; location: http://192.168.1.1:5000/desc.xml"
        );
        assert_eq!(parse_ssdp(b"GET / HTTP/1.1\r\n"), None);
        assert!(
            String::from_utf8(ssdp_request("10.0.0.1".parse().unwrap()))
                .unwrap()
                .contains("HOST: 10.0.0.1:1900")
        );
    }

    #[test]
    fn netbios_status() {
        let mut m = vec![0x12, 0x34, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        m.push(0x20);
        m.extend(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        m.push(0);
        m.extend([0, 0x21, 0, 1, 0, 0, 0, 0, 0, 0]);
        m.push(2);
        for (name, suffix, flags) in [("DESKTOP-01", 0u8, 0x0400u16), ("WORKGROUP", 0, 0x8400)] {
            let mut n = format!("{name:<15}").into_bytes();
            n.push(suffix);
            n.extend(flags.to_be_bytes());
            m.extend(n);
        }
        m.extend([0x00, 0x15, 0x5D, 0x01, 0x02, 0x03]);
        let (info, mac) = parse_netbios(&m).unwrap();
        assert_eq!(info, "NetBIOS names: DESKTOP-01<00>, WORKGROUP<00 group>");
        assert_eq!(mac.unwrap(), "00:15:5D:01:02:03");
        assert_eq!(netbios_request().len(), 50);
        assert!(parse_netbios(&m[..30]).is_none());
    }

    #[test]
    fn snmp_round_trip() {
        let req = snmp_get(1, "public", 0x01020304);
        assert_eq!(req.len(), 43);
        assert_eq!(&req[..2], &[0x30, 0x29]);
        assert_eq!(&req[2..5], &[2, 1, 1]);
        assert_eq!(snmp_get(0, "x", 1)[4], 0);
        let descr = b"Linux router 5.15.0 #1 SMP";
        let varbind = tlv(
            0x30,
            &[tlv(6, &[0x2B, 6, 1, 2, 1, 1, 1, 0]), tlv(4, descr)].concat(),
        );
        let pdu = tlv(
            0xA2,
            &[
                tlv(2, &[1]),
                tlv(2, &[0]),
                tlv(2, &[0]),
                tlv(0x30, &varbind),
            ]
            .concat(),
        );
        let resp = tlv(0x30, &[tlv(2, &[1]), tlv(4, b"public"), pdu].concat());
        assert_eq!(
            parse_snmp(&resp).unwrap(),
            (0, Some("Linux router 5.15.0 #1 SMP".into()))
        );
        // Long strings use multi-byte BER lengths.
        let long = vec![b'a'; 300];
        let varbind = tlv(
            0x30,
            &[tlv(6, &[0x2B, 6, 1, 2, 1, 1, 1, 0]), tlv(4, &long)].concat(),
        );
        let pdu = tlv(
            0xA2,
            &[
                tlv(2, &[1]),
                tlv(2, &[0]),
                tlv(2, &[0]),
                tlv(0x30, &varbind),
            ]
            .concat(),
        );
        let resp = tlv(0x30, &[tlv(2, &[1]), tlv(4, b"public"), pdu].concat());
        assert_eq!(parse_snmp(&resp).unwrap().1.unwrap().len(), 160);
        // Error response without a string, and garbage.
        let pdu = tlv(
            0xA2,
            &[tlv(2, &[1]), tlv(2, &[2]), tlv(2, &[1]), tlv(0x30, &[])].concat(),
        );
        let resp = tlv(0x30, &[tlv(2, &[1]), tlv(4, b"x"), pdu].concat());
        assert_eq!(parse_snmp(&resp).unwrap(), (2, None));
        assert_eq!(parse_snmp(&[0x30, 0x84, 0xff, 0xff]), None);
        assert_eq!(parse_snmp(&[]), None);
    }

    #[test]
    fn dhcp_inform_and_ack() {
        let req = dhcp_inform(0xAABBCCDD, "10.0.0.5".parse().unwrap(), [2, 0, 0, 0, 0, 1]);
        assert_eq!(&req[4..8], &0xAABBCCDDu32.to_be_bytes());
        assert_eq!(&req[12..16], &[10, 0, 0, 5]);
        assert_eq!(&req[236..240], &[0x63, 0x82, 0x53, 0x63]);
        assert_eq!(&req[240..243], &[53, 1, 8]);
        let mut ack = vec![0u8; 236];
        ack[0] = 2;
        ack[4..8].copy_from_slice(&0xAABBCCDDu32.to_be_bytes());
        ack.extend([
            0x63, 0x82, 0x53, 0x63, 53, 1, 5, 54, 4, 10, 0, 0, 1, 1, 4, 255, 255, 255, 0, 3, 4, 10,
            0, 0, 1, 6, 8, 1, 1, 1, 1, 8, 8, 8, 8, 15, 5,
        ]);
        ack.extend(b"lan.x");
        ack.push(255);
        assert_eq!(
            parse_dhcp(&ack, 0xAABBCCDD).unwrap(),
            "DHCP ACK (server 10.0.0.1, mask 255.255.255.0, router 10.0.0.1, dns 1.1.1.1/8.8.8.8, domain lan.x)"
        );
        assert_eq!(parse_dhcp(&ack, 1), None, "xid mismatch");
        assert_eq!(parse_dhcp(&ack[..100], 0xAABBCCDD), None);
    }

    async fn responder(reply: Vec<u8>) -> u16 {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = s.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((_, from)) = s.recv_from(&mut buf).await {
                let _ = s.send_to(&reply, from).await;
            }
        });
        port
    }

    #[tokio::test]
    async fn live_loopback_probes() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let gate = Gate::unlimited();
        let wait = Duration::from_millis(500);
        let mut ntp = vec![0u8; 48];
        ntp[0] = 0x24;
        ntp[1] = 3;
        let p = responder(ntp).await;
        let r = probe_kind(ip, p, Kind::Ntp, wait, 2, &gate).await;
        assert_eq!(r.state, State::Open);
        assert!(r.info.starts_with("NTPv4 stratum 3"), "{}", r.info);

        let p = responder(b"HTTP/1.1 200 OK\r\nSERVER: Test/1\r\n\r\n".to_vec()).await;
        let r = probe_kind(ip, p, Kind::Ssdp, wait, 1, &gate).await;
        assert_eq!(r.info, "SSDP/UPnP server: Test/1");

        let p = responder(b"opaque".to_vec()).await;
        let r = probe_kind(ip, p, Kind::Generic, wait, 1, &gate).await;
        assert_eq!(
            (r.state, r.info.as_str()),
            (State::Open, "responds (6 bytes)")
        );

        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let r = probe_kind(
            ip,
            silent.local_addr().unwrap().port(),
            Kind::Ntp,
            Duration::from_millis(150),
            2,
            &gate,
        )
        .await;
        assert_eq!(r.state, State::NoReply);

        let closed = {
            let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            s.local_addr().unwrap().port()
        };
        let mut r = probe_kind(ip, closed, Kind::Generic, wait, 1, &gate).await;
        for _ in 0..4 {
            if r.state == State::Closed {
                break;
            }
            r = probe_kind(ip, closed, Kind::Generic, wait, 1, &gate).await;
        }
        // Windows sometimes drops or rate-limits the loopback ICMP error, so only a wrong
        // "open" is a failure here; the Closed mapping itself is exercised when the OS delivers it.
        assert!(
            matches!(r.state, State::Closed | State::NoReply),
            "a closed UDP port must never read as open: {:?}",
            r.state
        );
    }

    #[test]
    fn dhcp_offer_parsing() {
        let p = dhcp_discover_packet(7, [2, 0, 0, 0, 0, 9]);
        assert_eq!(p[10], 0x80);
        assert_eq!(&p[240..243], &[53, 1, 1]);
        let mut o = vec![0u8; 236];
        o[0] = 2;
        o[4..8].copy_from_slice(&7u32.to_be_bytes());
        o[16..20].copy_from_slice(&[192, 168, 1, 50]);
        o.extend([
            0x63, 0x82, 0x53, 0x63, 53, 1, 2, 54, 4, 192, 168, 1, 1, 3, 4, 192, 168, 1, 1, 6, 8, 1,
            1, 1, 1, 8, 8, 8, 8, 51, 4, 0, 0, 0x0e, 0x10, 255,
        ]);
        let offer = parse_offer(&o, 7).unwrap();
        assert_eq!(offer.server, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(offer.offered, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(
            (offer.router, offer.dns.len(), offer.lease),
            (Some(Ipv4Addr::new(192, 168, 1, 1)), 2, Some(3600))
        );
        assert_eq!(parse_offer(&o, 8), None, "xid mismatch");
        o[240 + 2] = 5; // an ACK is not an OFFER
        assert_eq!(parse_offer(&o, 7), None);
        assert_eq!(parse_offer(&o[..200], 7), None);
    }

    #[test]
    fn port_mapping() {
        assert_eq!(kind_for_port(161), Kind::Snmp);
        assert_eq!(kind_for_port(9999), Kind::Generic);
    }

    /// A UDP server that records each datagram and answers with `reply`.
    async fn recording_responder(reply: Vec<u8>) -> (u16, tokio::sync::mpsc::Receiver<Vec<u8>>) {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = s.local_addr().unwrap().port();
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, from)) = s.recv_from(&mut buf).await {
                let _ = tx.send(buf[..n].to_vec()).await;
                let _ = s.send_to(&reply, from).await;
            }
        });
        (port, rx)
    }

    /// The next non-empty datagram. Other tests send empty probes to ports they believe
    /// closed; the OS can hand such a port to a responder here right after, so a stray empty
    /// datagram may arrive first (seen on Linux CI).
    async fn next_payload(rx: &mut tokio::sync::mpsc::Receiver<Vec<u8>>) -> Vec<u8> {
        loop {
            let d = rx.recv().await.unwrap();
            if !d.is_empty() {
                return d;
            }
        }
    }

    #[tokio::test]
    async fn generic_ports_use_udp_probes_from_the_database() {
        use crate::service::ProbeDb;
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let gate = Gate::unlimited();
        let wait = Duration::from_millis(500);
        let builtin = ProbeDb::builtin();
        let browser = builtin
            .udp
            .iter()
            .find(|p| p.name == "udp-mssql-browser")
            .unwrap();
        let mut reply = vec![5, 0, 0];
        reply.extend(b"ServerName;SQL01;InstanceName;MSSQLSERVER;IsClustered;No;Version;15.0.2000.5;tcp;1433;;");
        let (port, mut rx) = recording_responder(reply).await;
        let mut probe = browser.clone();
        probe.ports = vec![port];
        let r = probe_with(ip, port, Kind::Generic, wait, 1, &gate, &[probe.clone()]).await;
        assert_eq!(r.state, State::Open);
        assert_eq!(
            r.info,
            "ms-sql-m Microsoft SQL Server 15.0.2000.5 (server SQL01, instance MSSQLSERVER)"
        );
        assert_eq!(
            next_payload(&mut rx).await,
            [3],
            "the probe payload was sent"
        );
        // A reply that matches no rule still means open, with the generic description.
        let (port, mut rx) = recording_responder(b"??".to_vec()).await;
        probe.ports = vec![port];
        let r = probe_with(ip, port, Kind::Generic, wait, 1, &gate, &[probe.clone()]).await;
        assert_eq!(r.info, "responds (2 bytes)");
        assert_eq!(next_payload(&mut rx).await, [3]);
        // Ports without a probe keep the empty datagram.
        let (port, mut rx) = recording_responder(b"x".to_vec()).await;
        let _ = probe_with(ip, port, Kind::Generic, wait, 1, &gate, &[probe.clone()]).await;
        assert!(rx.recv().await.unwrap().is_empty());
    }

    #[test]
    fn udp_probes_never_target_ot_ports() {
        use crate::service::{ProbeDb, is_ot_udp_port};
        let builtin = ProbeDb::builtin();
        assert!(builtin.udp.len() >= 4);
        assert!(builtin.udp.iter().all(|p| !p.payload.is_empty()));
        for p in [
            47808, 47810, 2222, 2221, 34964, 20000, 44818, 502, 102, 9100, 515, 17185,
        ] {
            assert!(is_ot_udp_port(p), "{p}");
            let mut probe = builtin.udp[0].clone();
            probe.ports = vec![p];
            assert!(
                payload_probe(p, Kind::Generic, &[probe]).is_none(),
                "payload for OT port {p}"
            );
        }
        for p in [1434, 111, 5060, 11211] {
            assert!(!is_ot_udp_port(p), "{p}");
            assert!(
                payload_probe(p, Kind::Generic, &builtin.udp).is_some(),
                "{p}"
            );
        }
        // Ports with a protocol handler keep it.
        let mut snmp = builtin.udp[0].clone();
        snmp.ports = vec![161];
        assert!(payload_probe(161, Kind::Snmp, &[snmp]).is_none());
    }

    #[test]
    fn udp_probe_rules_identify_replies() {
        use crate::service::ProbeDb;
        let db = ProbeDb::builtin();
        let get = |n: &str| db.udp.iter().find(|p| p.name == n).unwrap();
        let mut rpc = b"NS\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00".to_vec();
        rpc.extend([0u8; 12]);
        assert_eq!(
            ProbeDb::identify(get("udp-rpcbind"), &rpc)
                .unwrap()
                .summary(),
            "rpcbind (ONC RPC portmapper)"
        );
        assert_eq!(get("udp-rpcbind").payload.len(), 40);
        let mem = get("udp-memcached");
        assert!(mem.payload.ends_with(b"version\r\n") && mem.payload.len() == 17);
        let mut reply = vec![0, 1, 0, 0, 0, 1, 0, 0];
        reply.extend(b"VERSION 1.6.21\r\n");
        assert_eq!(
            ProbeDb::identify(mem, &reply).unwrap().summary(),
            "memcached memcached 1.6.21 (UDP enabled)"
        );
        let sip = b"SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP nm\r\nServer: Asterisk PBX 18.0\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(
            ProbeDb::identify(get("udp-sip"), sip).unwrap().summary(),
            "sip Asterisk PBX 18.0"
        );
    }
}
