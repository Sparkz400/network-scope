//! Strictly passive OT asset discovery. This module only ever reads: frames come from a live
//! capture handle that exposes no transmit call (`PassiveCapture`) or from a capture file. It
//! recognises Modbus/TCP, S7comm, IEC 61850 MMS (told from S7comm on port 102 by what the connection
//! carries), DNP3, IEC 60870-5-104, EtherNet/IP, BACnet/IP, OPC UA, Omron FINS, Niagara Fox, MQTT,
//! MELSEC, KNXnet/IP and (by port only) CODESYS, and flags control traffic (writes, program download, stop/restart, commands) without ever
//! generating any. TCP messages of Modbus/TCP, S7comm (TPKT), IEC 104, EtherNet/IP and OPC UA
//! that span several segments are reassembled in order with bounded memory ("reassembly-lite",
//! see `Reassembly`); out-of-order or missing segments end the attempt and the buffered prefix
//! is decoded as far as it goes. DNP3 is decoded per segment.
use crate::passive::Observation;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::IpAddr,
};

mod asset;
mod bacnet;
mod codesys;
mod control;
mod dnp3;
mod enip;
mod fins;
mod fox;
mod iec104;
mod ingest;
mod knx;
mod melsec;
mod mms;
mod modbus;
mod mqtt;
mod packet;
mod reassembly;
mod s7;

pub use asset::{Asset, assets, assets_csv};
pub use control::control_findings;
pub use ingest::{listen_live, read_pcap_file, read_pcap_file_with_progress};

use iec104::iec104_type;
use modbus::modbus_function;
use packet::{be16, parse_ip};
use reassembly::{Pdu, Reassembly, framed_port};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Proto {
    Modbus,
    S7,
    Dnp3,
    Iec104,
    EtherNetIp,
    Bacnet,
    OpcUa,
    Mms,
    Fins,
    Fox,
    Mqtt,
    Melsec,
    Knx,
    Codesys,
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
            Self::Mms => "IEC 61850 MMS",
            Self::Fins => "Omron FINS",
            Self::Fox => "Niagara Fox",
            Self::Mqtt => "MQTT",
            Self::Melsec => "MELSEC",
            Self::Knx => "KNXnet/IP",
            Self::Codesys => "CODESYS",
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
        if let Some(p) = peer
            && self.peers.len() < 256
        {
            self.peers.insert(p);
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

/// One request to an industrial device, as the decoders saw it (see `ot-learn`): one event per
/// function in the message, or one with an empty function for traffic that carries none
/// (a connection setup, a keep-alive, a protocol without function names here).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtEvent {
    pub ts: i64,
    pub proto: &'static str,
    pub client: IpAddr,
    pub server: IpAddr,
    pub function: String,
    /// A write, program download, stop, restart or command (the same flag as `control_traffic`).
    pub control: bool,
}

/// Receives the [`OtEvent`]s while a tracker decodes (see [`Tracker::set_event_sink`]).
pub type EventSink = Box<dyn FnMut(&OtEvent) + Send>;

#[derive(Default)]
pub struct Tracker {
    event_sink: Option<EventSink>,
    servers: BTreeMap<(Proto, IpAddr), Endpoint>,
    clients: BTreeMap<(Proto, IpAddr), Endpoint>,
    passive: Vec<Observation>,
    passive_index: crate::observations::ObservationIndex,
    pub frames: u64,
    /// Set per frame: the frame being decoded is addressed to a group (broadcast/multicast).
    dst_group: bool,
    reassembly: Reassembly,
    /// Which connections on port 102 are S7comm and which are MMS.
    iso: mms::IsoFlows,
}

impl Tracker {
    pub fn new() -> Self {
        Self::default()
    }
    /// Sends every request to an industrial device to `sink` as it is decoded (requests to a
    /// broadcast or multicast address are not requests to a device and are left out). Nothing is
    /// stored here, so a long capture does not grow the tracker.
    pub fn set_event_sink(&mut self, sink: EventSink) {
        self.event_sink = Some(sink);
    }
    /// TCP reassembly-lite is on by default; `false` decodes every segment on its own.
    pub fn set_reassembly(&mut self, on: bool) {
        self.reassembly.disabled = !on;
    }
    /// (messages completed from several segments, partial messages given up)
    pub fn reassembly_stats(&self) -> (u64, u64) {
        (self.reassembly.reassembled, self.reassembly.abandoned)
    }
    /// End of the capture: partial messages still buffered are decoded as far as they go.
    pub fn flush(&mut self) {
        for pdu in self.reassembly.flush() {
            self.decode_pdu(pdu);
        }
        self.iso_flush();
    }

    fn decode_pdu(&mut self, pdu: Pdu) {
        let (src, sport, dst, dport) = pdu.key;
        self.dst_group = pdu.dst_group;
        if !pdu.data.is_empty() {
            self.tcp_message(src, dst, sport, dport, &pdu.data, pdu.ts);
        }
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
        if let (Some(sink), Some(server)) = (self.event_sink.as_mut(), server) {
            let event = |function: String, control: bool| OtEvent {
                ts,
                proto: proto.name(),
                client,
                server,
                function,
                control,
            };
            if functions.is_empty() {
                sink(&event(String::new(), false));
            }
            for (name, control) in &functions {
                sink(&event(name.clone(), *control));
            }
        }
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
        // a reply sent to a broadcast address (MELSOFT does that) names no client
        let peer = (!self.dst_group).then_some(client);
        if let Some(s) = self.server(proto, server) {
            s.touch(ts, peer);
        }
    }

    pub fn feed(&mut self, frame: &[u8], ts: i64) {
        self.frames += 1;
        if let Some(o) = crate::passive::decode(frame)
            && self.passive.len() < 10_000
        {
            let _ =
                crate::observations::merge_indexed(&mut self.passive, &mut self.passive_index, o);
        }
        let Some(p) = parse_ip(frame) else { return };
        let (src, dst, pl) = (p.src, p.dst, p.payload);
        self.dst_group = p.dst_group;
        if pl.is_empty() {
            return;
        }
        if p.tcp {
            // Framed protocols go through reassembly (which, when disabled, only splits
            // segments that hold several messages).
            match framed_port(p.sport, p.dport) {
                Some(port) => {
                    let pdus = self.reassembly.segment(
                        (src, p.sport, dst, p.dport),
                        port,
                        p.seq,
                        p.end_of_flow,
                        p.truncated,
                        p.dst_group,
                        pl,
                        ts,
                    );
                    for pdu in pdus {
                        self.decode_pdu(pdu);
                    }
                }
                None => self.tcp_message(src, dst, p.sport, p.dport, pl, ts),
            }
        } else {
            match (p.sport, p.dport) {
                (_, 44818) => self.enip(src, dst, pl, ts, true),
                (44818, _) => self.enip(dst, src, pl, ts, false),
                (47808, _) | (_, 47808) => self.bacnet(src, dst, pl, ts),
                (_, 9600) => self.fins(src, dst, Some(pl), ts, true),
                (9600, _) => self.fins(dst, src, Some(pl), ts, false),
                (_, 3671) => self.knx(src, dst, pl, ts, true),
                (3671, _) => self.knx(dst, src, pl, ts, false),
                (_, 5006 | 5007) => self.melsec_mc(src, dst, pl, ts, true),
                (5006 | 5007, _) => self.melsec_mc(dst, src, pl, ts, false),
                (_, 5560 | 5561) => self.melsoft(src, dst, pl, ts, true),
                (5560 | 5561, _) => self.melsoft(dst, src, pl, ts, false),
                (_, p) if codesys::is_codesys_udp(p) => self.codesys(src, dst, ts, true, p),
                (p, _) if codesys::is_codesys_udp(p) => self.codesys(dst, src, ts, false, p),
                _ => {}
            }
        }
    }

    /// One TCP message (or segment) on an OT port.
    fn tcp_message(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
        sport: u16,
        dport: u16,
        pl: &[u8],
        ts: i64,
    ) {
        match (sport, dport) {
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
            // S7comm and MMS share port 102: the connection's data says which this is
            (_, 102) | (102, _) => self.iso_message(src, dst, sport, dport, pl, ts),
            (_, 20000) => self.dnp3(src, dst, pl, ts, true),
            (20000, _) => self.dnp3(dst, src, pl, ts, false),
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
            (_, 9600) => self.fins_tcp(src, dst, pl, ts, true),
            (9600, _) => self.fins_tcp(dst, src, pl, ts, false),
            (_, 1911) => self.fox(src, dst, pl, ts, true),
            (1911, _) => self.fox(dst, src, pl, ts, false),
            (_, 1883) => self.mqtt(src, dst, pl, ts, true),
            (1883, _) => self.mqtt(dst, src, pl, ts, false),
            (_, 5006 | 5007) => self.melsec_mc(src, dst, pl, ts, true),
            (5006 | 5007, _) => self.melsec_mc(dst, src, pl, ts, false),
            (_, p) if codesys::is_codesys_tcp(p) => self.codesys(src, dst, ts, true, p),
            (p, _) if codesys::is_codesys_tcp(p) => self.codesys(dst, src, ts, false, p),
            _ => {}
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

#[cfg(test)]
mod real_traffic;
#[cfg(test)]
mod testutil;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::Severity;
    use testutil::{HMI, PLC, bvlc, cip_identity, frame, obs};

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

    #[test]
    fn raw_ip_frames_have_no_source_mac() {
        // a synthesised header has an all-zero source: no MAC must be invented for the device
        let mut ssdp = frame(
            PLC,
            [239, 255, 255, 250],
            false,
            1900,
            1900,
            b"NOTIFY * HTTP/1.1\r\nSERVER: x\r\n\r\n",
        );
        ssdp[6..12].fill(0);
        let o = crate::passive::decode(&ssdp).unwrap();
        assert_eq!(o.mac, "");
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
        assert!(
            findings
                .iter()
                .any(|(sev, _, e)| *sev == Severity::High && e.contains("Restart Communications"))
        );
    }

    #[test]
    fn this_module_cannot_transmit() {
        // The passive guarantee is structural: no sockets, no capture-send call in the code of
        // any file of this module (test code follows the first `#[cfg(test)]` of a file).
        let sources = [
            ("mod.rs", include_str!("mod.rs")),
            ("asset.rs", include_str!("asset.rs")),
            ("bacnet.rs", include_str!("bacnet.rs")),
            ("codesys.rs", include_str!("codesys.rs")),
            ("control.rs", include_str!("control.rs")),
            ("dnp3.rs", include_str!("dnp3.rs")),
            ("enip.rs", include_str!("enip.rs")),
            ("fins.rs", include_str!("fins.rs")),
            ("fox.rs", include_str!("fox.rs")),
            ("iec104.rs", include_str!("iec104.rs")),
            ("ingest.rs", include_str!("ingest.rs")),
            ("knx.rs", include_str!("knx.rs")),
            ("melsec.rs", include_str!("melsec.rs")),
            ("mms.rs", include_str!("mms.rs")),
            ("modbus.rs", include_str!("modbus.rs")),
            ("mqtt.rs", include_str!("mqtt.rs")),
            ("packet.rs", include_str!("packet.rs")),
            ("real_traffic.rs", include_str!("real_traffic.rs")),
            ("reassembly.rs", include_str!("reassembly.rs")),
            ("s7.rs", include_str!("s7.rs")),
            ("testutil.rs", include_str!("testutil.rs")),
        ];
        // a new file must be added to the list above
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/otpassive");
        for entry in std::fs::read_dir(dir).unwrap() {
            let name = entry.unwrap().file_name().into_string().unwrap();
            assert!(
                sources.iter().any(|(n, _)| *n == name),
                "{name} is not checked"
            );
        }
        let forbidden_calls = [
            "UdpSocket",
            "TcpStream",
            "TcpListener",
            ".send(",
            "send_to",
            "::Capture::open(",
            " Capture::open(",
            "sendpacket",
            "std::process",
        ];
        for (name, source) in sources {
            let code = source.split("#[cfg(test)]").next().unwrap();
            for forbidden in forbidden_calls {
                assert!(
                    !code.contains(forbidden),
                    "otpassive/{name} must stay read-only, found {forbidden}"
                );
            }
        }
        let pcap = include_str!("../pcapfile.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for forbidden in ["UdpSocket", "TcpStream", ".send(", " Capture::open("] {
            assert!(
                !pcap.contains(forbidden),
                "pcapfile.rs must stay read-only, found {forbidden}"
            );
        }
        let capture = include_str!("../capture.rs");
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
