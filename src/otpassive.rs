//! Strictly passive OT asset discovery. This module only ever reads: frames come from a live
//! capture handle that exposes no transmit call (`PassiveCapture`) or from a capture file. It
//! recognises Modbus/TCP, S7comm, DNP3, IEC 60870-5-104, EtherNet/IP, BACnet/IP and OPC UA, and
//! flags control traffic (writes, program download, stop/restart, commands) without ever
//! generating any. TCP streams are not reassembled; a message split across segments is missed.
use crate::{devices, oui, passive::Observation, risk::Severity};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::{IpAddr, Ipv4Addr},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Proto {
    Modbus,
    S7,
    Dnp3,
    Iec104,
    EtherNetIp,
    Bacnet,
    OpcUa,
}
impl Proto {
    fn name(self) -> &'static str {
        match self {
            Self::Modbus => "Modbus/TCP",
            Self::S7 => "S7comm",
            Self::Dnp3 => "DNP3",
            Self::Iec104 => "IEC 104",
            Self::EtherNetIp => "EtherNet/IP",
            Self::Bacnet => "BACnet/IP",
            Self::OpcUa => "OPC UA",
        }
    }
}

#[derive(Default)]
struct Endpoint {
    first: i64,
    last: i64,
    packets: u64,
    peers: BTreeSet<IpAddr>,
    units: BTreeSet<u8>,
    functions: BTreeMap<String, u64>,
    control: BTreeMap<String, u64>,
    fields: BTreeMap<String, String>,
}
impl Endpoint {
    fn touch(&mut self, ts: i64, peer: Option<IpAddr>) {
        if self.packets == 0 || ts < self.first {
            self.first = ts;
        }
        self.last = self.last.max(ts);
        self.packets += 1;
        if let Some(p) = peer {
            if self.peers.len() < 256 {
                self.peers.insert(p);
            }
        }
    }
    fn function(&mut self, name: &str, control: bool) {
        if self.functions.len() < 64 || self.functions.contains_key(name) {
            *self.functions.entry(name.to_string()).or_insert(0) += 1;
        }
        if control && (self.control.len() < 64 || self.control.contains_key(name)) {
            *self.control.entry(name.to_string()).or_insert(0) += 1;
        }
    }
}

const MAX_ENDPOINTS: usize = 4096;

#[derive(Default)]
pub struct Tracker {
    servers: BTreeMap<(Proto, IpAddr), Endpoint>,
    clients: BTreeMap<(Proto, IpAddr), Endpoint>,
    passive: Vec<Observation>,
    pub frames: u64,
    /// Set per frame: the frame being decoded is addressed to a group (broadcast/multicast).
    dst_group: bool,
}

fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(i..i + 2)?.try_into().ok()?))
}
fn le16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(i..i + 2)?.try_into().ok()?))
}

struct Packet<'a> {
    src: IpAddr,
    dst: IpAddr,
    /// The destination is not one host: limited/subnet broadcast or multicast (by IP or by a
    /// group destination MAC such as ff:ff:ff:ff:ff:ff).
    dst_group: bool,
    sport: u16,
    dport: u16,
    tcp: bool,
    payload: &'a [u8],
}
fn parse_ip(frame: &[u8]) -> Option<Packet<'_>> {
    let mut kind = be16(frame, 12)?;
    let mut offset = 14;
    for _ in 0..2 {
        if kind == 0x8100 || kind == 0x88a8 {
            kind = be16(frame, offset + 2)?;
            offset += 4;
        }
    }
    if kind != 0x0800 {
        return None;
    }
    let ip = frame.get(offset..)?;
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(ip[0] & 15) * 4;
    let total = usize::from(be16(ip, 2)?).min(ip.len());
    if ihl < 20 || total < ihl || be16(ip, 6)? & 0x1fff != 0 {
        return None;
    }
    let (src, dst) = (
        IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15])),
        IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19])),
    );
    let dst_group = frame[0] & 1 != 0
        || match dst {
            IpAddr::V4(v) => v.is_broadcast() || v.is_multicast(),
            IpAddr::V6(v) => v.is_multicast(),
        };
    let l4 = ip.get(ihl..total)?;
    match ip[9] {
        6 => {
            let hl = usize::from(*l4.get(12)? >> 4) * 4;
            if hl < 20 {
                return None;
            }
            Some(Packet {
                src,
                dst,
                dst_group,
                sport: be16(l4, 0)?,
                dport: be16(l4, 2)?,
                tcp: true,
                payload: l4.get(hl..)?,
            })
        }
        17 => Some(Packet {
            src,
            dst,
            dst_group,
            sport: be16(l4, 0)?,
            dport: be16(l4, 2)?,
            tcp: false,
            payload: l4.get(8..)?,
        }),
        _ => None,
    }
}

// ---- protocol decoders: each returns what the request/response says ---------------------

/// `pdu`: function code and data (the bytes after the unit identifier).
fn modbus_function(pdu: &[u8]) -> (String, bool) {
    let fc = pdu.first().copied().unwrap_or(0);
    if fc == 8 {
        // Diagnostics: some sub-functions change the device's communication state.
        return match be16(pdu, 1) {
            Some(1) => ("Diagnostics: Restart Communications".into(), true),
            Some(4) => ("Diagnostics: Force Listen Only Mode".into(), true),
            Some(10) => ("Diagnostics: Clear Counters".into(), false),
            _ => ("Diagnostics".into(), false),
        };
    }
    let (name, control) = match fc & 0x7f {
        1 => ("Read Coils", false),
        2 => ("Read Discrete Inputs", false),
        3 => ("Read Holding Registers", false),
        4 => ("Read Input Registers", false),
        5 => ("Write Single Coil", true),
        6 => ("Write Single Register", true),
        7 => ("Read Exception Status", false),
        8 => ("Diagnostics", false),
        15 => ("Write Multiple Coils", true),
        16 => ("Write Multiple Registers", true),
        17 => ("Report Server ID", false),
        20 => ("Read File Record", false),
        21 => ("Write File Record", true),
        22 => ("Mask Write Register", true),
        23 => ("Read/Write Multiple Registers", true),
        43 => ("Read Device Identification", false),
        other => return (format!("function {other}"), false),
    };
    (name.to_string(), control)
}
fn s7_function(f: u8) -> Option<(&'static str, bool)> {
    Some(match f {
        0x04 => ("Read Var", false),
        0x05 => ("Write Var", true),
        0x1a => ("Request Download", true),
        0x1b => ("Download Block", true),
        0x1c => ("Download Ended", true),
        0x1d => ("Start Upload", false),
        0x1e => ("Upload", false),
        0x1f => ("End Upload", false),
        0x28 => ("PLC Control", true),
        0x29 => ("PLC Stop", true),
        0xf0 => ("Setup Communication", false),
        _ => return None,
    })
}
fn dnp3_function(f: u8) -> (String, bool) {
    let (n, c) = match f {
        0 => ("Confirm", false),
        1 => ("Read", false),
        2 => ("Write", true),
        3 => ("Select", true),
        4 => ("Operate", true),
        5 => ("Direct Operate", true),
        6 => ("Direct Operate (no ack)", true),
        13 => ("Cold Restart", true),
        14 => ("Warm Restart", true),
        15 => ("Initialize Data", true),
        16 => ("Initialize Application", true),
        17 => ("Start Application", true),
        18 => ("Stop Application", true),
        20 => ("Enable Unsolicited", false),
        21 => ("Disable Unsolicited", true),
        27 => ("Delete File", true),
        _ => return (format!("function {f}"), false),
    };
    (n.to_string(), c)
}
fn iec104_type(t: u8) -> (String, bool) {
    match t {
        45 => ("C_SC single command".into(), true),
        46 => ("C_DC double command".into(), true),
        47 => ("C_RC regulating step command".into(), true),
        48..=51 => (format!("C_SE setpoint command (type {t})"), true),
        58..=64 => (format!("time-tagged command (type {t})"), true),
        100 => ("C_IC interrogation".into(), false),
        101 => ("C_CI counter interrogation".into(), false),
        102 => ("C_RD read".into(), false),
        103 => ("C_CS clock synchronisation".into(), true),
        105 => ("C_RP reset process".into(), true),
        other => (format!("ASDU type {other}"), false),
    }
}
/// The target of a CIP request path: the class (8- or 16-bit logical segment) and whether a
/// symbolic (ANSI extended, tag name) segment is present.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct CipPath {
    class: Option<u16>,
    symbolic: bool,
}
fn cip_path(path: &[u8]) -> CipPath {
    let mut p = CipPath::default();
    let mut i = 0;
    while let Some(&seg) = path.get(i) {
        match seg {
            0x20 => {
                p.class = path.get(i + 1).map(|&c| u16::from(c));
                i += 2;
            }
            0x21 => {
                p.class = le16(path, i + 2);
                i += 4;
            }
            0x24 | 0x28 | 0x30 => i += 2,
            0x25 | 0x29 | 0x31 => i += 4,
            0x91 => {
                p.symbolic = true;
                let n = path.get(i + 1).map_or(0, |&n| usize::from(n));
                i += 2 + n + n % 2;
            }
            _ => break,
        }
    }
    p
}
const CONNECTION_MANAGER: u16 = 0x06;
const LOGIX_SYMBOL: u16 = 0x6b;
/// Names a CIP service. Codes 0x4b-0x63 are object specific: on the Connection Manager 0x4e
/// is Forward Close and 0x52 Unconnected Send, on Logix tags (class 0x6b or a symbolic path)
/// 0x4e is Read-Modify-Write Tag (a write) and 0x52 Read Tag Fragmented.
fn enip_service(s: u8, path: CipPath) -> Option<(String, bool)> {
    let cm = path.class == Some(CONNECTION_MANAGER) && !path.symbolic;
    let tag = path.symbolic || path.class == Some(LOGIX_SYMBOL);
    let (name, control) = match s & 0x7f {
        0x01 => ("Get Attributes All", false),
        0x0e => ("Get Attribute Single", false),
        0x10 => ("Set Attribute Single", true),
        0x02 => ("Set Attributes All", true),
        0x05 => ("Reset", true),
        0x0a => ("Multiple Service Packet", false),
        0x4c => ("Read Tag", false),
        0x4d => ("Write Tag", true),
        0x53 => ("Write Tag Fragmented", true),
        0x4e if cm => ("Forward Close", false),
        0x4e if tag => ("Read Modify Write Tag", true),
        0x52 if cm => ("Unconnected Send", false),
        0x52 if tag => ("Read Tag Fragmented", false),
        0x54 if cm => ("Forward Open", false),
        0x5b if cm => ("Large Forward Open", false),
        other @ (0x4e | 0x52) => {
            return Some((
                format!(
                    "service 0x{other:02X} (class {})",
                    path.class.map_or("?".into(), |c| format!("0x{c:02X}"))
                ),
                false,
            ))
        }
        _ => return None,
    };
    Some((name.to_string(), control))
}
const MAX_CIP_DEPTH: usize = 4;
const MAX_CIP_SERVICES: usize = 32;
/// Classifies a CIP Message Router request, descending into Unconnected Send and Multiple
/// Service Packet so an embedded write is still seen. Bounded in depth and count.
fn cip_request(b: &[u8], depth: usize, out: &mut Vec<(String, bool)>) {
    if depth > MAX_CIP_DEPTH || out.len() >= MAX_CIP_SERVICES {
        return;
    }
    let (Some(&service), Some(&words)) = (b.first(), b.get(1)) else {
        return;
    };
    if service & 0x80 != 0 {
        return; // a reply
    }
    let Some(raw_path) = b.get(2..2 + 2 * usize::from(words)) else {
        return;
    };
    let path = cip_path(raw_path);
    let data = &b[2 + raw_path.len()..];
    let Some(named) = enip_service(service, path) else {
        return;
    };
    let wrapper = named.0.clone();
    out.push(named);
    match wrapper.as_str() {
        "Unconnected Send" => {
            // priority/tick, timeout ticks, embedded request size, embedded request
            if let Some(n) = le16(data, 2) {
                if let Some(inner) = data.get(4..4 + usize::from(n)) {
                    cip_request(inner, depth + 1, out);
                }
            }
        }
        "Multiple Service Packet" => {
            // count, then offsets relative to the count field
            let count = usize::from(le16(data, 0).unwrap_or(0)).min(MAX_CIP_SERVICES);
            let offsets: Vec<usize> = (0..count)
                .map_while(|k| le16(data, 2 + 2 * k).map(usize::from))
                .collect();
            for (k, &start) in offsets.iter().enumerate() {
                let end = offsets.get(k + 1).copied().unwrap_or(data.len());
                if let Some(inner) = data.get(start..end.max(start)) {
                    cip_request(inner, depth + 1, out);
                }
                if out.len() >= MAX_CIP_SERVICES {
                    break;
                }
            }
        }
        _ => {}
    }
}
fn bacnet_service(s: u8) -> (String, bool) {
    let (n, c) = match s {
        12 => ("ReadProperty", false),
        14 => ("ReadPropertyMultiple", false),
        15 => ("WriteProperty", true),
        16 => ("WritePropertyMultiple", true),
        17 => ("DeviceCommunicationControl", true),
        20 => ("ReinitializeDevice", true),
        7 => ("AtomicWriteFile", true),
        _ => return (format!("confirmed service {s}"), false),
    };
    (n.to_string(), c)
}

impl Tracker {
    pub fn new() -> Self {
        Self::default()
    }

    fn server(&mut self, p: Proto, ip: IpAddr) -> Option<&mut Endpoint> {
        if !self.servers.contains_key(&(p, ip)) && self.servers.len() >= MAX_ENDPOINTS {
            return None;
        }
        Some(self.servers.entry((p, ip)).or_default())
    }
    fn client(&mut self, p: Proto, ip: IpAddr) -> Option<&mut Endpoint> {
        if !self.clients.contains_key(&(p, ip)) && self.clients.len() >= MAX_ENDPOINTS {
            return None;
        }
        Some(self.clients.entry((p, ip)).or_default())
    }
    /// A request from `client` to `server`: both sides are recorded. A broadcast or multicast
    /// destination is not a device, so then only the client side is.
    fn request(
        &mut self,
        proto: Proto,
        client: IpAddr,
        server: IpAddr,
        ts: i64,
        functions: impl IntoIterator<Item = (String, bool)>,
        unit: Option<u8>,
    ) {
        let functions: Vec<(String, bool)> = functions.into_iter().collect();
        let server = (!self.dst_group).then_some(server);
        if let Some(s) = server.and_then(|server| self.server(proto, server)) {
            s.touch(ts, Some(client));
            if let Some(u) = unit {
                s.units.insert(u);
            }
            for (name, control) in &functions {
                s.function(name, *control);
            }
        }
        if let Some(c) = self.client(proto, client) {
            c.touch(ts, server);
            for (name, control) in &functions {
                c.function(name, *control);
            }
        }
    }
    fn response(&mut self, proto: Proto, server: IpAddr, client: IpAddr, ts: i64) {
        if let Some(s) = self.server(proto, server) {
            s.touch(ts, Some(client));
        }
    }

    pub fn feed(&mut self, frame: &[u8], ts: i64) {
        self.frames += 1;
        if let Some(o) = crate::passive::decode(frame) {
            if self.passive.len() < 10_000 {
                let _ = crate::ui::merge(&mut self.passive, o);
            }
        }
        let Some(p) = parse_ip(frame) else { return };
        let (src, dst, pl) = (p.src, p.dst, p.payload);
        self.dst_group = p.dst_group;
        if pl.is_empty() {
            return;
        }
        if p.tcp {
            match (p.sport, p.dport) {
                (_, 502) => {
                    if pl.len() >= 8 && be16(pl, 2) == Some(0) {
                        self.request(
                            Proto::Modbus,
                            src,
                            dst,
                            ts,
                            Some(modbus_function(&pl[7..])),
                            Some(pl[6]),
                        );
                    }
                }
                (502, _) => {
                    if pl.len() >= 8 && be16(pl, 2) == Some(0) {
                        self.response(Proto::Modbus, src, dst, ts);
                    }
                }
                (_, 102) => {
                    if let Some(f) = s7_request(pl) {
                        self.request(Proto::S7, src, dst, ts, Some((f.0.to_string(), f.1)), None);
                    } else if pl.len() >= 7 && pl[0] == 3 && pl[1] == 0 {
                        self.request(Proto::S7, src, dst, ts, None, None);
                    }
                }
                (102, _) => {
                    if pl.len() >= 7 && pl[0] == 3 && pl[1] == 0 {
                        self.response(Proto::S7, src, dst, ts);
                    }
                }
                (_, 20000) => {
                    if pl.len() >= 13 && pl[0] == 5 && pl[1] == 0x64 {
                        self.request(Proto::Dnp3, src, dst, ts, Some(dnp3_function(pl[12])), None);
                    }
                }
                (20000, _) => {
                    if pl.len() >= 10 && pl[0] == 5 && pl[1] == 0x64 {
                        self.response(Proto::Dnp3, src, dst, ts);
                    }
                }
                (_, 2404) => {
                    if pl.len() >= 12 && pl[0] == 0x68 && pl[2] & 1 == 0 {
                        self.request(Proto::Iec104, src, dst, ts, Some(iec104_type(pl[6])), None);
                    } else if pl.len() >= 6 && pl[0] == 0x68 {
                        self.request(Proto::Iec104, src, dst, ts, None, None);
                    }
                }
                (2404, _) => {
                    if pl.len() >= 6 && pl[0] == 0x68 {
                        self.response(Proto::Iec104, src, dst, ts);
                    }
                }
                (_, 4840) => {
                    if matches!(&pl.get(..3), Some(b"HEL" | b"OPN" | b"MSG" | b"CLO")) {
                        self.request(Proto::OpcUa, src, dst, ts, None, None);
                    }
                }
                (4840, _) => {
                    if matches!(&pl.get(..3), Some(b"ACK" | b"OPN" | b"MSG" | b"ERR")) {
                        self.response(Proto::OpcUa, src, dst, ts);
                    }
                }
                (_, 44818) => self.enip(src, dst, pl, ts, true),
                (44818, _) => self.enip(dst, src, pl, ts, false),
                _ => {}
            }
        } else {
            match (p.sport, p.dport) {
                (_, 44818) => self.enip(src, dst, pl, ts, true),
                (44818, _) => self.enip(dst, src, pl, ts, false),
                (47808, _) | (_, 47808) => self.bacnet(src, dst, pl, ts),
                _ => {}
            }
        }
    }

    /// `to_server`: the packet travels towards the device port; otherwise it is a reply.
    fn enip(&mut self, client: IpAddr, server: IpAddr, pl: &[u8], ts: i64, to_server: bool) {
        let Some(cmd) = le16(pl, 0) else { return };
        if pl.len() < 24 {
            return;
        }
        if to_server {
            let functions = match cmd {
                0x6f | 0x70 => enip_cip_services(pl),
                0x63 => vec![("List Identity".to_string(), false)],
                _ => vec![],
            };
            self.request(Proto::EtherNetIp, client, server, ts, functions, None);
        } else {
            self.response(Proto::EtherNetIp, server, client, ts);
            if cmd == 0x63 {
                if let Ok(mut fields) = crate::ot::parse_list_identity(&pl[24..]) {
                    if let Some(s) = self.server(Proto::EtherNetIp, server) {
                        s.fields.append(&mut fields);
                    }
                }
            }
        }
    }

    fn bacnet(&mut self, src: IpAddr, dst: IpAddr, pl: &[u8], ts: i64) {
        let Some((kind, service, rest)) = bacnet_apdu(pl) else {
            return;
        };
        match kind {
            1 if service == 0 => {
                // I-Am: the sender is a BACnet device.
                if let Some(s) = self.server(Proto::Bacnet, src) {
                    s.touch(ts, None);
                    if let Some((device, vendor)) = bacnet_iam(rest) {
                        s.fields.insert("device_id".into(), device.to_string());
                        s.fields.insert("vendor_id".into(), vendor.to_string());
                    }
                }
            }
            1 => {
                let name = match service {
                    8 => "Who-Is",
                    7 => "Who-Has",
                    other => {
                        return self.bacnet_client(
                            src,
                            ts,
                            format!("unconfirmed service {other}"),
                            false,
                        )
                    }
                };
                self.bacnet_client(src, ts, name.to_string(), false);
            }
            0 => {
                // A broadcast destination only records the client (see `request`).
                self.request(
                    Proto::Bacnet,
                    src,
                    dst,
                    ts,
                    Some(bacnet_service(service)),
                    None,
                );
            }
            _ => {}
        }
    }
    fn bacnet_client(&mut self, ip: IpAddr, ts: i64, name: String, control: bool) {
        if let Some(c) = self.client(Proto::Bacnet, ip) {
            c.touch(ts, None);
            c.function(&name, control);
        }
    }

    /// Everything seen, as observations (servers, clients and ordinary passive protocols).
    pub fn observations(&self) -> Vec<Observation> {
        let arp: HashMap<IpAddr, String> = self
            .passive
            .iter()
            .filter(|o| o.protocol == "ARP")
            .filter_map(|o| Some((o.ip?, o.mac.clone())))
            .collect();
        let mut out = self.passive.clone();
        for (role, map) in [("server", &self.servers), ("client", &self.clients)] {
            for ((proto, ip), e) in map {
                let mut fields = e.fields.clone();
                fields.insert("packets".into(), e.packets.to_string());
                fields.insert("first_seen".into(), e.first.to_string());
                fields.insert("last_seen".into(), e.last.to_string());
                if !e.peers.is_empty() {
                    fields.insert(
                        if role == "server" {
                            "clients"
                        } else {
                            "servers"
                        }
                        .into(),
                        e.peers
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", "),
                    );
                }
                if !e.units.is_empty() {
                    fields.insert(
                        "unit_ids".into(),
                        e.units
                            .iter()
                            .map(u8::to_string)
                            .collect::<Vec<_>>()
                            .join(", "),
                    );
                }
                let summary = |m: &BTreeMap<String, u64>| {
                    m.iter()
                        .map(|(k, n)| format!("{k} x{n}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                if !e.functions.is_empty() {
                    fields.insert("functions".into(), summary(&e.functions));
                }
                if !e.control.is_empty() {
                    fields.insert("control_traffic".into(), summary(&e.control));
                }
                out.push(Observation {
                    protocol: format!("{} {role} (observed)", proto.name()),
                    mac: arp.get(ip).cloned().unwrap_or_default(),
                    ip: Some(*ip),
                    fields,
                });
            }
        }
        out
    }
}

fn s7_request(pl: &[u8]) -> Option<(&'static str, bool)> {
    if pl.len() < 17 || pl[0] != 3 || pl[1] != 0 {
        return None;
    }
    let cotp = 4 + 1 + usize::from(pl[4]);
    let s7 = pl.get(cotp..)?;
    if s7.first() != Some(&0x32) || s7.get(1) != Some(&1) {
        return None;
    }
    s7_function(*s7.get(10)?)
}
/// Every CIP service named in a SendRRData / SendUnitData encapsulation (embedded ones too).
fn enip_cip_services(pl: &[u8]) -> Vec<(String, bool)> {
    let mut out = vec![];
    let Some(items) = pl.get(24 + 6..) else {
        return out;
    };
    let Some(count) = le16(items, 0) else {
        return out;
    };
    let mut i = 2;
    for _ in 0..usize::from(count).min(4) {
        let (Some(kind), Some(len)) = (le16(items, i), le16(items, i + 2)) else {
            break;
        };
        let len = usize::from(len);
        let Some(data) = items.get(i + 4..i + 4 + len) else {
            break;
        };
        match kind {
            0x00b2 => {
                cip_request(data, 0, &mut out);
                break;
            }
            0x00b1 => {
                // connected data: a 2-byte sequence count precedes the request
                cip_request(data.get(2..).unwrap_or_default(), 0, &mut out);
                break;
            }
            _ => {}
        }
        i += 4 + len;
    }
    out
}
/// (APDU type, service choice, bytes after the service choice) of a BACnet/IP datagram.
fn bacnet_apdu(b: &[u8]) -> Option<(u8, u8, &[u8])> {
    if b.first() != Some(&0x81) || !matches!(b.get(1)?, 0x0a | 0x0b | 0x04) {
        return None;
    }
    let mut i = if b[1] == 0x04 { 10 } else { 4 };
    if *b.get(i)? != 1 {
        return None;
    }
    let control = *b.get(i + 1)?;
    i += 2;
    if control & 0x20 != 0 {
        i += 3 + usize::from(*b.get(i + 2)?);
    }
    if control & 0x08 != 0 {
        i += 3 + usize::from(*b.get(i + 2)?);
    }
    if control & 0x20 != 0 {
        i += 1;
    }
    if control & 0x80 != 0 {
        return None;
    }
    let apdu = b.get(i..)?;
    let kind = apdu.first()? >> 4;
    match kind {
        0 => {
            let skip = if apdu[0] & 0x08 != 0 { 5 } else { 3 };
            Some((0, *apdu.get(skip)?, apdu.get(skip + 1..)?))
        }
        1 => Some((1, *apdu.get(1)?, apdu.get(2..)?)),
        _ => None,
    }
}
fn bacnet_iam(b: &[u8]) -> Option<(u32, u32)> {
    let mut i = 0;
    let mut value = |tag: u8| -> Option<u32> {
        let t = *b.get(i)?;
        i += 1;
        let n = usize::from(t & 7);
        if t >> 4 != tag || t & 8 != 0 || !(1..=4).contains(&n) {
            return None;
        }
        let v = b
            .get(i..i + n)?
            .iter()
            .fold(0u32, |a, v| (a << 8) | u32::from(*v));
        i += n;
        Some(v)
    };
    let object = value(12)?;
    if object >> 22 != 8 {
        return None;
    }
    value(2)?;
    value(9)?;
    Some((object & 0x3f_ffff, value(2)?))
}

// ---- asset inventory -------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Default)]
pub struct Asset {
    pub asset_id: String,
    pub ips: Vec<IpAddr>,
    pub mac: String,
    pub vendor: String,
    pub name: String,
    pub product: String,
    pub firmware: String,
    pub serial: String,
    pub protocols: Vec<String>,
    pub roles: Vec<String>,
    pub control_traffic: Vec<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub packets: u64,
}

pub fn assets(observations: &[Observation]) -> Vec<Asset> {
    let mut out = vec![];
    for d in devices::merge(&[], observations) {
        let mut a = Asset {
            asset_id: d.id.clone(),
            ips: d.ips.clone(),
            mac: d.mac.clone(),
            vendor: d.vendor.clone(),
            name: d.hostnames.first().cloned().unwrap_or_default(),
            ..Default::default()
        };
        let mut seen = false;
        let mut control: BTreeSet<String> = BTreeSet::new();
        for (protocol, f) in &d.observations {
            let ot = protocol.ends_with("(observed)") || protocol == "Profinet DCP";
            if !ot {
                continue;
            }
            seen = true;
            let proto = protocol.trim_end_matches(" (observed)");
            let (base, role) = proto
                .rsplit_once(' ')
                .filter(|(_, r)| matches!(*r, "server" | "client"))
                .map_or((proto, ""), |(b, r)| (b, r));
            if !a.protocols.iter().any(|p| p == base) {
                a.protocols.push(base.to_string());
            }
            if !role.is_empty() && !a.roles.iter().any(|r| r == role) {
                a.roles.push(role.to_string());
            }
            for (k, v) in f {
                match k.as_str() {
                    "vendor" if a.vendor.is_empty() => a.vendor = v.clone(),
                    "name" if a.name.is_empty() => a.name = v.clone(),
                    "firmware" => a.firmware = v.clone(),
                    "serial" => a.serial = v.clone(),
                    "vendor_id" if a.vendor.is_empty() => {
                        a.vendor = if base == "EtherNet/IP" {
                            v.parse()
                                .ok()
                                .and_then(oui::cip_vendor)
                                .map_or(format!("CIP vendor ID {v}"), str::to_string)
                        } else {
                            format!("{base} vendor ID {v}")
                        };
                    }
                    "control_traffic" => {
                        for item in v.split(", ") {
                            control.insert(format!("{base}: {item}"));
                        }
                    }
                    "first_seen" => {
                        let t: i64 = v.parse().unwrap_or(0);
                        if a.first_seen == 0 || (t != 0 && t < a.first_seen) {
                            a.first_seen = t;
                        }
                    }
                    "last_seen" => a.last_seen = a.last_seen.max(v.parse().unwrap_or(0)),
                    "packets" => a.packets += v.parse().unwrap_or(0),
                    _ => {}
                }
            }
            if let Some(p) = f.get("name").filter(|_| base == "EtherNet/IP") {
                a.product = p.clone();
            }
        }
        if seen {
            a.control_traffic = control.into_iter().collect();
            out.push(a);
        }
    }
    out
}

pub fn assets_csv(assets: &[Asset]) -> String {
    let mut out = String::from("asset_id,ip,mac,vendor,name,product,firmware,serial,protocols,roles,control_traffic,first_seen,last_seen,packets\r\n");
    for a in assets {
        let cells = [
            a.asset_id.clone(),
            a.ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" "),
            a.mac.clone(),
            a.vendor.clone(),
            a.name.clone(),
            a.product.clone(),
            a.firmware.clone(),
            a.serial.clone(),
            a.protocols.join("; "),
            a.roles.join("; "),
            a.control_traffic.join("; "),
            a.first_seen.to_string(),
            a.last_seen.to_string(),
            a.packets.to_string(),
        ];
        out.push_str(
            &cells
                .iter()
                .map(|c| crate::scan::csv_cell(c))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push_str("\r\n");
    }
    out
}

/// Findings from observed control traffic: who is writing to or stopping a controller.
pub fn control_findings(observations: &[Observation]) -> Vec<(Severity, IpAddr, String)> {
    observations
        .iter()
        .filter(|o| o.protocol.ends_with("server (observed)"))
        .filter_map(|o| {
            let traffic = o.fields.get("control_traffic")?;
            let sev = if traffic.contains("Stop")
                || traffic.contains("Download")
                || traffic.contains("Restart")
                || traffic.contains("PLC Control")
            {
                Severity::High
            } else {
                Severity::Medium
            };
            Some((
                sev,
                o.ip?,
                format!(
                    "{}: control traffic observed ({traffic}) from {}",
                    o.protocol.trim_end_matches(" (observed)"),
                    o.fields.get("clients").map_or("?", String::as_str)
                ),
            ))
        })
        .collect()
}

pub fn read_pcap_file(path: &str, tracker: &mut Tracker) -> Result<(), String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
    let mut reader = crate::pcapfile::Reader::new(std::io::BufReader::new(file))?;
    while let Some((ts, frame)) = reader.next_frame()? {
        tracker.feed(&frame, ts);
    }
    Ok(())
}

/// Live capture for `seconds`. Uses `PassiveCapture`, which has no way to transmit.
pub fn listen_live(
    interface: &str,
    seconds: u64,
    cancel: &std::sync::atomic::AtomicBool,
    tracker: &mut Tracker,
) -> Result<(), String> {
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    let mut cap = crate::capture::PassiveCapture::open(interface)?;
    let end = Instant::now() + Duration::from_secs(seconds.clamp(1, 7 * 86_400));
    while Instant::now() < end && !cancel.load(std::sync::atomic::Ordering::Relaxed) {
        match cap.next()? {
            Some(frame) => {
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                tracker.feed(&frame, ts);
            }
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(
        src: [u8; 4],
        dst: [u8; 4],
        tcp: bool,
        sport: u16,
        dport: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend([8, 0]);
        let l4_len = if tcp { 20 } else { 8 } + payload.len();
        let mut ip = vec![
            0x45,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            64,
            if tcp { 6 } else { 17 },
            0,
            0,
        ];
        ip.extend(src);
        ip.extend(dst);
        let total = (20 + l4_len) as u16;
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        f.extend(ip);
        f.extend(sport.to_be_bytes());
        f.extend(dport.to_be_bytes());
        if tcp {
            f.extend([0; 8]);
            f.extend([0x50, 0x18, 0, 0, 0, 0, 0, 0]);
        } else {
            f.extend((l4_len as u16).to_be_bytes());
            f.extend([0, 0]);
        }
        f.extend(payload);
        f
    }
    const HMI: [u8; 4] = [10, 0, 0, 50];
    const PLC: [u8; 4] = [10, 0, 0, 10];
    fn obs(t: &Tracker, protocol: &str) -> Vec<Observation> {
        t.observations()
            .into_iter()
            .filter(|o| o.protocol == protocol)
            .collect()
    }

    #[test]
    fn modbus_writes_are_control_traffic() {
        let mut t = Tracker::new();
        // transaction 1, protocol 0, length 6, unit 7, function 3 (read), then 6 (write single register)
        t.feed(
            &frame(
                HMI,
                PLC,
                true,
                50000,
                502,
                &[0, 1, 0, 0, 0, 6, 7, 3, 0, 0, 0, 2],
            ),
            100,
        );
        t.feed(
            &frame(
                PLC,
                HMI,
                true,
                502,
                50000,
                &[0, 1, 0, 0, 0, 7, 7, 3, 4, 0, 1, 0, 2],
            ),
            101,
        );
        t.feed(
            &frame(
                HMI,
                PLC,
                true,
                50000,
                502,
                &[0, 2, 0, 0, 0, 6, 7, 6, 0, 5, 0, 9],
            ),
            105,
        );
        t.feed(
            &frame(
                HMI,
                PLC,
                true,
                50000,
                502,
                &[0, 3, 0, 0, 0, 6, 7, 6, 0, 5, 0, 9],
            ),
            106,
        );
        let s = &obs(&t, "Modbus/TCP server (observed)")[0];
        assert_eq!(s.ip.unwrap().to_string(), "10.0.0.10");
        assert_eq!(s.fields["unit_ids"], "7");
        assert_eq!(s.fields["control_traffic"], "Write Single Register x2");
        assert!(s.fields["functions"].contains("Read Holding Registers x1"));
        assert_eq!(
            (
                s.fields["first_seen"].as_str(),
                s.fields["last_seen"].as_str(),
                s.fields["packets"].as_str()
            ),
            ("100", "106", "4")
        );
        assert_eq!(s.fields["clients"], "10.0.0.50");
        let c = &obs(&t, "Modbus/TCP client (observed)")[0];
        assert_eq!(c.ip.unwrap().to_string(), "10.0.0.50");
        assert_eq!(c.fields["servers"], "10.0.0.10");
        // A non-Modbus payload on port 502 is ignored.
        let mut t = Tracker::new();
        t.feed(
            &frame(HMI, PLC, true, 50000, 502, b"GET / HTTP/1.1\r\n\r\n"),
            1,
        );
        assert!(t.observations().is_empty());
    }

    fn s7(function: u8, rosctr: u8) -> Vec<u8> {
        let mut p = vec![3, 0, 0, 0, 2, 0xf0, 0x80];
        p.extend([0x32, rosctr, 0, 0, 0, 1, 0, 2, 0, 0, function, 1]);
        let n = p.len() as u16;
        p[2..4].copy_from_slice(&n.to_be_bytes());
        p
    }
    #[test]
    fn s7_stop_and_download_are_flagged() {
        let mut t = Tracker::new();
        t.feed(&frame(HMI, PLC, true, 40000, 102, &s7(0x04, 1)), 1);
        t.feed(&frame(HMI, PLC, true, 40000, 102, &s7(0x29, 1)), 2);
        t.feed(&frame(HMI, PLC, true, 40000, 102, &s7(0x1a, 1)), 3);
        t.feed(&frame(PLC, HMI, true, 102, 40000, &s7(0x29, 3)), 4);
        let s = &obs(&t, "S7comm server (observed)")[0];
        assert_eq!(
            s.fields["control_traffic"],
            "PLC Stop x1, Request Download x1"
        );
        assert!(!s.fields["control_traffic"].contains("Read"));
        assert_eq!(s.fields["packets"], "4");
        let findings = control_findings(&t.observations());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].0, Severity::High);
    }

    #[test]
    fn dnp3_and_iec104_commands() {
        let mut t = Tracker::new();
        let dnp = |fc: u8| {
            let mut p = vec![0x05, 0x64, 0x0b, 0xc4, 0x0a, 0, 0x01, 0, 0, 0];
            p.extend([0xc0, 0xc1, fc]);
            p
        };
        t.feed(&frame(HMI, PLC, true, 40000, 20000, &dnp(1)), 1);
        t.feed(&frame(HMI, PLC, true, 40000, 20000, &dnp(5)), 2);
        let s = &obs(&t, "DNP3 server (observed)")[0];
        assert_eq!(s.fields["control_traffic"], "Direct Operate x1");
        let i104 = |type_id: u8| {
            vec![
                0x68, 0x0e, 0x00, 0x00, 0x00, 0x00, type_id, 1, 6, 0, 1, 0, 0, 0, 0, 0,
            ]
        };
        t.feed(&frame(HMI, PLC, true, 40001, 2404, &i104(100)), 3);
        t.feed(&frame(HMI, PLC, true, 40001, 2404, &i104(45)), 4);
        t.feed(
            &frame(HMI, PLC, true, 40001, 2404, &[0x68, 4, 0x07, 0, 0, 0]),
            5,
        );
        let s = &obs(&t, "IEC 104 server (observed)")[0];
        assert_eq!(s.fields["control_traffic"], "C_SC single command x1");
        assert!(s.fields["functions"].contains("C_IC interrogation x1"));
        assert_eq!(
            s.fields["packets"], "3",
            "a U-format keep-alive still counts as presence"
        );
    }

    fn cip_identity() -> Vec<u8> {
        let mut v = vec![1, 0];
        v.extend([0u8; 16]);
        v.extend(1u16.to_le_bytes()); // vendor 1: Rockwell
        v.extend(14u16.to_le_bytes());
        v.extend(166u16.to_le_bytes());
        v.extend([20, 11]);
        v.extend([0, 0]);
        v.extend(0xDEADBEEFu32.to_le_bytes());
        v.push(10);
        v.extend(b"1756-L81E ");
        v.push(3);
        let mut data = vec![1, 0, 0x0c, 0];
        data.extend((v.len() as u16).to_le_bytes());
        data.extend(v);
        let mut p = vec![
            0x63, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, b'N', b'E', b'T', b'S', b'C', b'O', b'P', b'E',
            0, 0, 0, 0,
        ];
        p[2..4].copy_from_slice(&(data.len() as u16).to_le_bytes());
        p.extend(data);
        p
    }
    fn cip_send_rr(service: u8) -> Vec<u8> {
        let mut p = vec![
            0x6f, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        p.extend([
            0, 0, 0, 0, 5, 0, 2, 0, 0, 0, 0, 0, 0xb2, 0, 4, 0, service, 1, 0x20, 0x06,
        ]);
        p
    }
    #[test]
    fn ethernet_ip_identity_and_cip_writes() {
        let mut t = Tracker::new();
        t.feed(&frame(PLC, HMI, false, 44818, 2222, &cip_identity()), 10);
        t.feed(&frame(HMI, PLC, true, 50000, 44818, &cip_send_rr(0x4c)), 11);
        t.feed(&frame(HMI, PLC, true, 50000, 44818, &cip_send_rr(0x4d)), 12);
        let s = &obs(&t, "EtherNet/IP server (observed)")[0];
        assert_eq!(s.fields["vendor"], "Rockwell Automation/Allen-Bradley");
        assert_eq!(s.fields["serial"], 0xDEADBEEFu32.to_string());
        assert_eq!(s.fields["firmware"], "20.11");
        assert_eq!(s.fields["control_traffic"], "Write Tag x1");
    }

    fn bvlc(npdu_control: u8, extra: &[u8], apdu: &[u8], function: u8) -> Vec<u8> {
        let mut p = vec![0x81, function, 0, 0, 1, npdu_control];
        p.extend(extra);
        p.extend(apdu);
        let n = p.len() as u16;
        p[2..4].copy_from_slice(&n.to_be_bytes());
        p
    }
    #[test]
    fn bacnet_iam_with_global_broadcast_destination_and_writes() {
        let mut t = Tracker::new();
        // I-Am broadcast: NPDU destination = global broadcast (dnet 0xffff, dlen 0) plus hop count.
        let iam = [
            0x10, 0x00, 0xc4, 0x02, 0x00, 0x03, 0xe8, 0x22, 0x05, 0xc4, 0x91, 0x00, 0x21, 0x0f,
        ];
        t.feed(
            &frame(
                PLC,
                [10, 0, 0, 255],
                false,
                47808,
                47808,
                &bvlc(0x20, &[0xff, 0xff, 0, 255], &iam, 0x0b),
            ),
            20,
        );
        let s = &obs(&t, "BACnet/IP server (observed)")[0];
        assert_eq!(s.fields["device_id"], "1000");
        assert_eq!(s.fields["vendor_id"], "15");
        // WriteProperty (confirmed request, service 15) sent unicast to the device.
        let write = [0x00, 0x05, 0x01, 0x0f, 0x0c, 0x00, 0x00, 0x00, 0x01];
        t.feed(
            &frame(HMI, PLC, false, 47808, 47808, &bvlc(0, &[], &write, 0x0a)),
            21,
        );
        let s = &obs(&t, "BACnet/IP server (observed)")[0];
        assert_eq!(s.fields["control_traffic"], "WriteProperty x1");
        // Who-Is makes the sender a client, not a server.
        t.feed(
            &frame(
                HMI,
                [10, 0, 0, 255],
                false,
                47808,
                47808,
                &bvlc(0x20, &[0xff, 0xff, 0, 255], &[0x10, 0x08], 0x0b),
            ),
            22,
        );
        assert!(obs(&t, "BACnet/IP client (observed)")
            .iter()
            .any(|c| c.fields["functions"].contains("Who-Is")));
        assert_eq!(obs(&t, "BACnet/IP server (observed)").len(), 1);
    }

    #[test]
    fn assets_merge_protocols_vendor_and_mac() {
        let mut t = Tracker::new();
        // ARP gives the PLC's MAC; its traffic then joins that record.
        let mut arp = vec![0u8; 42];
        arp[12..14].copy_from_slice(&[8, 6]);
        arp[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 2]);
        arp[22..28].copy_from_slice(&[0x00, 0x00, 0xbc, 1, 2, 3]);
        arp[28..32].copy_from_slice(&PLC);
        t.feed(&arp, 5);
        t.feed(&frame(PLC, HMI, false, 44818, 2222, &cip_identity()), 10);
        t.feed(
            &frame(
                HMI,
                PLC,
                true,
                50000,
                502,
                &[0, 2, 0, 0, 0, 6, 1, 16, 0, 5, 0, 9],
            ),
            11,
        );
        t.feed(&frame(HMI, PLC, true, 50000, 102, &s7(0x28, 1)), 12);
        let a = assets(&t.observations());
        let plc = a
            .iter()
            .find(|a| a.ips.contains(&"10.0.0.10".parse().unwrap()))
            .unwrap();
        assert_eq!(plc.mac, "00:00:BC:01:02:03");
        assert!(plc.vendor.contains("Rockwell"), "{plc:?}");
        assert_eq!(plc.protocols, ["EtherNet/IP", "Modbus/TCP", "S7comm"]);
        assert_eq!(plc.roles, ["server"]);
        assert_eq!(plc.firmware, "20.11");
        assert_eq!(plc.product, "1756-L81E");
        assert_eq!(
            plc.control_traffic,
            [
                "Modbus/TCP: Write Multiple Registers x1",
                "S7comm: PLC Control x1"
            ]
        );
        assert_eq!((plc.first_seen, plc.last_seen), (10, 12));
        let hmi = a
            .iter()
            .find(|a| a.ips.contains(&"10.0.0.50".parse().unwrap()))
            .unwrap();
        assert_eq!(hmi.roles, ["client"]);
        assert!(hmi.control_traffic.iter().any(|c| c.contains("Write")));
        let csv = assets_csv(&a);
        assert!(csv.starts_with("asset_id,ip,mac,vendor,"));
        assert!(csv.contains("00:00:BC:01:02:03"));
        assert!(assets(&[]).is_empty());
    }

    #[test]
    fn capture_files_feed_the_tracker_and_garbage_is_ignored() {
        let frames = vec![
            (
                100u32,
                frame(
                    HMI,
                    PLC,
                    true,
                    50000,
                    502,
                    &[0, 1, 0, 0, 0, 6, 7, 5, 0, 0, 0xff, 0],
                ),
            ),
            (101, vec![0xff; 5]),
            (102, vec![0; 200]),
        ];
        let dir = std::env::temp_dir().join(format!("ns-pcap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, bytes) in [
            ("a.pcap", crate::pcapfile::write_pcap(&frames)),
            ("b.pcapng", crate::pcapfile::write_pcapng(&frames, false)),
        ] {
            let path = dir.join(name);
            std::fs::write(&path, bytes).unwrap();
            let mut t = Tracker::new();
            read_pcap_file(path.to_str().unwrap(), &mut t).unwrap();
            assert_eq!(t.frames, 3, "{name}");
            assert_eq!(
                obs(&t, "Modbus/TCP server (observed)")[0].fields["control_traffic"],
                "Write Single Coil x1"
            );
        }
        assert!(read_pcap_file(
            dir.join("missing.pcap").to_str().unwrap(),
            &mut Tracker::new()
        )
        .is_err());
        let _ = std::fs::remove_dir_all(&dir);
        let mut t = Tracker::new();
        for n in 0..300 {
            t.feed(&vec![0x45; n], 0);
            let mut f = frame(HMI, PLC, true, 1, 502, &vec![0xff; n % 40]);
            f.truncate(f.len().saturating_sub(n % 7));
            t.feed(&f, 0);
        }
    }

    /// SendRRData carrying one unconnected Message Router request.
    fn cip_rr(request: &[u8]) -> Vec<u8> {
        let mut p = vec![
            0x6f, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        p.extend([0, 0, 0, 0, 5, 0, 2, 0, 0, 0, 0, 0, 0xb2, 0]);
        p.extend((request.len() as u16).to_le_bytes());
        p.extend(request);
        let n = (p.len() - 24) as u16;
        p[2..4].copy_from_slice(&n.to_le_bytes());
        p
    }
    /// A Message Router request with a symbolic (tag name) path.
    fn tag_request(service: u8, tag: &[u8], data: &[u8]) -> Vec<u8> {
        let mut path = vec![0x91, tag.len() as u8];
        path.extend(tag);
        if tag.len() % 2 == 1 {
            path.push(0);
        }
        let mut r = vec![service, (path.len() / 2) as u8];
        r.extend(path);
        r.extend(data);
        r
    }
    fn cip_server_traffic(requests: &[Vec<u8>]) -> (String, String) {
        let mut t = Tracker::new();
        for (n, r) in requests.iter().enumerate() {
            t.feed(&frame(HMI, PLC, true, 50000, 44818, &cip_rr(r)), n as i64);
        }
        let s = &obs(&t, "EtherNet/IP server (observed)")[0];
        (
            s.fields.get("functions").cloned().unwrap_or_default(),
            s.fields.get("control_traffic").cloned().unwrap_or_default(),
        )
    }
    #[test]
    fn cip_0x4e_depends_on_the_target_class() {
        // Forward Close to the Connection Manager (class 0x06, instance 1).
        let (functions, control) = cip_server_traffic(&[vec![0x4e, 2, 0x20, 0x06, 0x24, 0x01]]);
        assert_eq!(functions, "Forward Close x1");
        assert_eq!(control, "");
        // Read-Modify-Write Tag on a symbolic tag path, and on the Logix symbol class 0x6b.
        let (_, control) = cip_server_traffic(&[
            tag_request(0x4e, b"Speed", &[2, 0, 0xff, 0, 0x01, 0]),
            vec![0x4e, 2, 0x20, 0x6b, 0x24, 0x07, 2, 0],
        ]);
        assert_eq!(control, "Read Modify Write Tag x2");
        // 0x52 on a tag is Read Tag Fragmented, not Unconnected Send.
        let (functions, control) =
            cip_server_traffic(&[tag_request(0x52, b"Big", &[1, 0, 0, 0, 0, 0])]);
        assert_eq!(functions, "Read Tag Fragmented x1");
        assert_eq!(control, "");
    }
    #[test]
    fn cip_writes_inside_unconnected_send_and_multiple_service_packets() {
        let write = tag_request(0x4d, b"Valve", &[0xc1, 0, 1, 0, 1]);
        let read = tag_request(0x4c, b"Level", &[1, 0]);
        // Multiple Service Packet to the Message Router: count, offsets, requests.
        let mut msp_data = vec![2, 0];
        let first = 2 + 2 * 2;
        msp_data.extend((first as u16).to_le_bytes());
        msp_data.extend(((first + read.len()) as u16).to_le_bytes());
        msp_data.extend(&read);
        msp_data.extend(&write);
        let mut msp = vec![0x0a, 2, 0x20, 0x02, 0x24, 0x01];
        msp.extend(&msp_data);
        // Unconnected Send to the Connection Manager wrapping the packet, plus a route path.
        let mut ucs = vec![0x52, 2, 0x20, 0x06, 0x24, 0x01, 0x0a, 0xf0];
        ucs.extend((msp.len() as u16).to_le_bytes());
        ucs.extend(&msp);
        if msp.len() % 2 == 1 {
            ucs.push(0);
        }
        ucs.extend([1, 0, 0x01, 0x00]);
        let (functions, control) = cip_server_traffic(&[ucs]);
        assert_eq!(control, "Write Tag x1", "{functions}");
        for f in [
            "Unconnected Send x1",
            "Multiple Service Packet x1",
            "Read Tag x1",
        ] {
            assert!(functions.contains(f), "{functions}");
        }
        // Self-nesting is bounded.
        let mut nested = write.clone();
        for _ in 0..50 {
            let mut outer = vec![0x52, 2, 0x20, 0x06, 0x24, 0x01, 0x0a, 0xf0];
            outer.extend((nested.len() as u16).to_le_bytes());
            outer.extend(&nested);
            nested = outer;
        }
        let mut out = vec![];
        cip_request(&nested, 0, &mut out);
        assert!(out.len() <= MAX_CIP_DEPTH + 1);
        assert!(
            !out.iter().any(|(_, c)| *c),
            "the write is beyond the depth limit"
        );
    }
    #[test]
    fn broadcasts_are_not_servers() {
        let list_identity = [
            0x63, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mut t = Tracker::new();
        // Limited broadcast, by IP.
        t.feed(
            &frame(
                HMI,
                [255, 255, 255, 255],
                false,
                2222,
                44818,
                &list_identity,
            ),
            1,
        );
        // Subnet broadcast: only the destination MAC says so.
        let mut f = frame(HMI, [10, 0, 0, 255], false, 2222, 44818, &list_identity);
        f[..6].copy_from_slice(&[0xff; 6]);
        t.feed(&f, 2);
        // Multicast.
        t.feed(
            &frame(HMI, [239, 192, 1, 1], false, 2222, 44818, &list_identity),
            3,
        );
        // BACnet confirmed request sent to a subnet broadcast MAC.
        let write = [0x00, 0x05, 0x01, 0x0f, 0x0c, 0x00, 0x00, 0x00, 0x01];
        let mut f = frame(
            HMI,
            [10, 0, 0, 255],
            false,
            47808,
            47808,
            &bvlc(0, &[], &write, 0x0b),
        );
        f[..6].copy_from_slice(&[0xff; 6]);
        t.feed(&f, 4);
        let servers: Vec<_> = t
            .observations()
            .into_iter()
            .filter(|o| o.protocol.ends_with("server (observed)"))
            .collect();
        assert!(servers.is_empty(), "{servers:?}");
        let c = &obs(&t, "EtherNet/IP client (observed)")[0];
        assert_eq!(c.ip.unwrap().to_string(), "10.0.0.50");
        assert_eq!(c.fields["functions"], "List Identity x3");
        assert!(!c.fields.contains_key("servers"));
        // The unicast reply still makes the device a server.
        t.feed(&frame(PLC, HMI, false, 44818, 2222, &cip_identity()), 5);
        assert_eq!(obs(&t, "EtherNet/IP server (observed)").len(), 1);
    }
    #[test]
    fn tcp_header_shorter_than_20_bytes_is_rejected() {
        let mut f = frame(
            HMI,
            PLC,
            true,
            50000,
            502,
            &[0, 1, 0, 0, 0, 6, 7, 6, 0, 5, 0, 9],
        );
        let tcp = 14 + 20;
        assert!(parse_ip(&f).is_some());
        for offset in [0u8, 1, 4] {
            f[tcp + 12] = offset << 4;
            assert!(parse_ip(&f).is_none(), "data offset {offset}");
        }
    }
    #[test]
    fn more_dnp3_and_modbus_control_functions() {
        let mut t = Tracker::new();
        let dnp = |fc: u8| {
            let mut p = vec![0x05, 0x64, 0x0b, 0xc4, 0x0a, 0, 0x01, 0, 0, 0];
            p.extend([0xc0, 0xc1, fc]);
            p
        };
        for fc in [16, 17, 27, 1] {
            t.feed(&frame(HMI, PLC, true, 40000, 20000, &dnp(fc)), 1);
        }
        assert_eq!(
            obs(&t, "DNP3 server (observed)")[0].fields["control_traffic"],
            "Delete File x1, Initialize Application x1, Start Application x1"
        );
        let diag = |sub: u16| {
            let mut p = vec![0, 1, 0, 0, 0, 6, 1, 8];
            p.extend(sub.to_be_bytes());
            p.extend([0, 0]);
            p
        };
        for sub in [0, 1, 4] {
            t.feed(&frame(HMI, PLC, true, 50000, 502, &diag(sub)), 2);
        }
        let s = &obs(&t, "Modbus/TCP server (observed)")[0];
        assert_eq!(
            s.fields["control_traffic"],
            "Diagnostics: Force Listen Only Mode x1, Diagnostics: Restart Communications x1"
        );
        assert!(s.fields["functions"].contains("Diagnostics x1"));
        let findings = control_findings(&t.observations());
        assert!(findings
            .iter()
            .any(|(sev, _, e)| *sev == Severity::High && e.contains("Restart Communications")));
    }

    #[test]
    fn this_module_cannot_transmit() {
        // The passive guarantee is structural: no sockets, no capture-send call in the code above.
        let source = include_str!("otpassive.rs");
        let code = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "UdpSocket",
            "TcpStream",
            "TcpListener",
            ".send(",
            "send_to",
            "::Capture::open(",
            " Capture::open(",
            "sendpacket",
            "std::process",
        ] {
            assert!(
                !code.contains(forbidden),
                "otpassive.rs must stay read-only, found {forbidden}"
            );
        }
        let pcap = include_str!("pcapfile.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for forbidden in ["UdpSocket", "TcpStream", ".send(", " Capture::open("] {
            assert!(
                !pcap.contains(forbidden),
                "pcapfile.rs must stay read-only, found {forbidden}"
            );
        }
        let capture = include_str!("capture.rs");
        let wrapper = capture
            .split("pub struct PassiveCapture")
            .nth(1)
            .unwrap()
            .split("pub fn mac")
            .next()
            .unwrap();
        assert!(
            !wrapper.contains("send"),
            "PassiveCapture must not expose a transmit call"
        );
    }
}
