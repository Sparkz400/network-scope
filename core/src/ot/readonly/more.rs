//! More allow-listed OT requests (ROADMAP C23): Omron FINS, Niagara Fox, MQTT and KNXnet/IP. Same
//! rules as the rest of [`super`]: closed enums, no public fields, sealed [`ReadOnlyRequest`],
//! sent only through [`OtStream`](super::OtStream) and [`OtUdp`](super::OtUdp).
//!
//! | Protocol | Allowed |
//! | --- | --- |
//! | Omron FINS/UDP | main/sub request code 0x05 0x01, Controller Data Read (the 13-byte frame of a real capture); no memory, program or parameter write, no Run/Stop |
//! | Niagara Fox | the `fox a 1 -1 fox hello` message (the handshake `nmap`'s `fox-info` sends); no authentication, no other command |
//! | MQTT | CONNECT (clean session, empty client ID, no credentials, no will) and DISCONNECT; no PUBLISH, SUBSCRIBE or UNSUBSCRIBE |
//! | KNXnet/IP | unicast DESCRIPTION_REQUEST (0x0203); not the multicast SEARCH_REQUEST, no connection, tunnelling or routing frame |
//!
//! None of the write or control services exists as a value:
//!
//! ```compile_fail
//! use network_scope_core::ot_readonly::FinsCommand;
//! // Memory Area Write (0x0102), Run (0x0401) and Stop (0x0402): no such variants.
//! let _ = FinsCommand::MemoryAreaWrite;
//! let _ = FinsCommand::Stop;
//! ```
//!
//! ```
//! use network_scope_core::ot_readonly::{FinsCommand, FinsRequest, ReadOnlyRequest};
//! let request = FinsRequest::new(0x63, FinsCommand::ControllerDataRead);
//! assert_eq!(request.encode()[10..12], [0x05, 0x01]);
//! ```
//!
//! ```compile_fail
//! use network_scope_core::ot_readonly::MqttPacket;
//! let _ = MqttPacket::Publish;
//! let _ = MqttPacket::Subscribe;
//! ```
//!
//! ```
//! use network_scope_core::ot_readonly::{MqttPacket, MqttRequest, ReadOnlyRequest};
//! assert_eq!(MqttRequest::new(MqttPacket::Disconnect).encode(), [0xe0, 0x00]);
//! ```
//!
//! ```compile_fail
//! use network_scope_core::ot_readonly::KnxService;
//! // the multicast search, a connection and a tunnelling request: not allowed
//! let _ = KnxService::SearchRequest;
//! let _ = KnxService::ConnectRequest;
//! let _ = KnxService::TunnellingRequest;
//! ```
//!
//! ```compile_fail
//! use network_scope_core::ot_readonly::FoxMessage;
//! let _ = FoxMessage::Authenticate;
//! ```
use super::{ReadOnlyRequest, RequestInfo, sealed};

// ---------------------------------------------------------------------------------------------
// Omron FINS

/// The FINS commands that may be sent: Controller Data Read (main request code 0x05, sub request
/// code 0x01), which returns the controller model and version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinsCommand {
    ControllerDataRead,
}

impl FinsCommand {
    pub const ALLOWED: [Self; 1] = [Self::ControllerDataRead];
    /// (main request code, sub request code)
    pub const fn codes(self) -> (u8, u8) {
        match self {
            Self::ControllerDataRead => (0x05, 0x01),
        }
    }
    /// The allow-listed command for a request code pair. Everything else (memory, parameter and
    /// program area writes, Run, Stop, clock write, file operations, ...) is `None`.
    pub const fn from_wire(main: u8, sub: u8) -> Option<Self> {
        match (main, sub) {
            (0x05, 0x01) => Some(Self::ControllerDataRead),
            _ => None,
        }
    }
    /// The command of an encoded FINS/UDP request: 13 bytes, local destination, command frame
    /// (ICF 0x80), the node number and service ID are free, everything else must match.
    pub fn of_frame(frame: &[u8]) -> Option<Self> {
        if frame.len() != 13
            || frame[..7] != [0x80, 0, 2, 0, 0, 0, 0]
            || frame[8] != 0
            || frame[12] != 0
        {
            return None;
        }
        Self::from_wire(frame[10], frame[11])
    }
}

/// One FINS/UDP request frame of an allow-listed command. `node` is the sender's FINS node number
/// (source node, SA1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinsRequest {
    node: u8,
    command: FinsCommand,
}

impl FinsRequest {
    /// The service ID of the frame the captured client sent (`omron_test.pcap`).
    pub const SERVICE_ID: u8 = 0xef;
    pub const fn new(node: u8, command: FinsCommand) -> Self {
        Self { node, command }
    }
}

impl sealed::Sealed for FinsRequest {}
impl ReadOnlyRequest for FinsRequest {
    fn info(&self) -> RequestInfo {
        let (main, sub) = self.command.codes();
        RequestInfo {
            protocol: "Omron FINS/UDP",
            service: format!("Controller Data Read (command {main:#04X}{sub:02X})"),
        }
    }
    fn encode(&self) -> Vec<u8> {
        // ICF 0x80 (command, response wanted), RSV 0, GCT 2, destination network/node/unit 0
        // (the PLC that receives it), source network 0, node, unit 0, service ID, MRC, SRC, and the
        // one parameter byte the captured client sent.
        let (main, sub) = self.command.codes();
        vec![
            0x80,
            0,
            2,
            0,
            0,
            0,
            0,
            self.node,
            0,
            Self::SERVICE_ID,
            main,
            sub,
            0,
        ]
    }
}

// ---------------------------------------------------------------------------------------------
// Niagara Fox

/// The Fox messages that may be sent: the hello that opens a session. The `fox a 1 -1 fox hello`
/// line and its body are the layout of the client hello in `fox_info.pcap` (the exchange of
/// nmap's `fox-info`); the station answers with its own hello (host name, application, VM and OS
/// versions). Authentication and every other command are not allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FoxMessage {
    Hello,
}

impl FoxMessage {
    pub const ALLOWED: [Self; 1] = [Self::Hello];
    /// The keys of the hello body, in the order of the captured hello.
    pub const HELLO_KEYS: [&'static str; 15] = [
        "fox.version",
        "id",
        "hostName",
        "hostAddress",
        "app.name",
        "app.version",
        "vm.name",
        "vm.version",
        "os.name",
        "os.version",
        "lang",
        "timeZone",
        "hostId",
        "vmUuid",
        "brandId",
    ];
    /// The message of an encoded Fox frame: the hello line, a body of `key=type:value` lines and
    /// the `};;` terminator, nothing else.
    pub fn of_frame(frame: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(frame).ok()?;
        let body = text
            .strip_prefix("fox a 1 -1 fox hello\n{\n")?
            .strip_suffix("};;\n")?;
        let ok = body.lines().all(|line| {
            line.split_once('=').is_some_and(|(key, value)| {
                !key.is_empty()
                    && !key.contains(' ')
                    && value.get(1..2) == Some(":")
                    && !line.starts_with("fox a ")
            })
        });
        ok.then_some(Self::Hello)
    }
}

/// One Fox request of an allow-listed message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FoxRequest {
    message: FoxMessage,
}

impl FoxRequest {
    pub const fn new(message: FoxMessage) -> Self {
        Self { message }
    }
}

impl sealed::Sealed for FoxRequest {}
impl ReadOnlyRequest for FoxRequest {
    fn info(&self) -> RequestInfo {
        RequestInfo {
            protocol: "Niagara Fox",
            service: "hello (fox a 1 -1 fox hello)".into(),
        }
    }
    fn encode(&self) -> Vec<u8> {
        let FoxMessage::Hello = self.message;
        // Neutral values: this scanner is not a Workbench and says so.
        let values = [
            "s:1.0",
            "i:1",
            "s:network-scope",
            "s:0.0.0.0",
            "s:Network Scope",
            "s:0",
            "s:-",
            "s:-",
            "s:-",
            "s:-",
            "s:en",
            "s:UTC;0;0;null;null",
            "s:network-scope",
            "s:00000000-0000-0000-0000-000000000000",
            "s:none",
        ];
        let mut text = String::from("fox a 1 -1 fox hello\n{\n");
        for (key, value) in FoxMessage::HELLO_KEYS.iter().zip(values) {
            text.push_str(&format!("{key}={value}\n"));
        }
        text.push_str("};;\n");
        text.into_bytes()
    }
}

// ---------------------------------------------------------------------------------------------
// MQTT

/// The MQTT control packets that may be sent: CONNECT and DISCONNECT. Reading the broker's
/// CONNACK is all the scanner wants; it never subscribes and never publishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MqttPacket {
    Connect,
    Disconnect,
}

impl MqttPacket {
    pub const ALLOWED: [Self; 2] = [Self::Connect, Self::Disconnect];
    /// The allow-listed packet for the first byte of a control packet (type and flags): CONNECT
    /// is 0x10 and DISCONNECT 0xE0. PUBLISH (0x3_), SUBSCRIBE (0x82), UNSUBSCRIBE (0xA2) and the
    /// rest are `None`.
    pub const fn from_first_byte(byte: u8) -> Option<Self> {
        match byte {
            0x10 => Some(Self::Connect),
            0xe0 => Some(Self::Disconnect),
            _ => None,
        }
    }
    const fn bytes(self) -> &'static [u8] {
        match self {
            // MQTT 3.1.1: protocol name "MQTT", level 4, clean session only (no will, user name
            // or password), keep alive 60 s, client identifier of length 0. The same 14 bytes
            // as the service probe in data/probes.json.
            Self::Connect => &[
                0x10, 0x0c, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3c, 0x00, 0x00,
            ],
            Self::Disconnect => &[0xe0, 0x00],
        }
    }
    /// The packet of an encoded frame: exactly one of the two byte strings.
    pub fn of_frame(frame: &[u8]) -> Option<Self> {
        Self::ALLOWED.into_iter().find(|p| p.bytes() == frame)
    }
}

/// One MQTT packet of an allow-listed type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MqttRequest {
    packet: MqttPacket,
}

impl MqttRequest {
    pub const fn new(packet: MqttPacket) -> Self {
        Self { packet }
    }
}

impl sealed::Sealed for MqttRequest {}
impl ReadOnlyRequest for MqttRequest {
    fn info(&self) -> RequestInfo {
        RequestInfo {
            protocol: "MQTT",
            service: match self.packet {
                MqttPacket::Connect => "CONNECT (packet type 1, clean session, no credentials)",
                MqttPacket::Disconnect => "DISCONNECT (packet type 14)",
            }
            .into(),
        }
    }
    fn encode(&self) -> Vec<u8> {
        self.packet.bytes().to_vec()
    }
}

// ---------------------------------------------------------------------------------------------
// KNXnet/IP

/// The KNXnet/IP services that may be sent: DESCRIPTION_REQUEST (0x0203) to one address. The
/// multicast SEARCH_REQUEST (0x0201), CONNECT_REQUEST (0x0205), TUNNELLING_REQUEST (0x0420) and
/// ROUTING_INDICATION (0x0530), which can put telegrams on the bus, are not allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KnxService {
    DescriptionRequest,
}

impl KnxService {
    pub const ALLOWED: [Self; 1] = [Self::DescriptionRequest];
    pub const fn service_type(self) -> u16 {
        match self {
            Self::DescriptionRequest => 0x0203,
        }
    }
    pub const fn from_service_type(service_type: u16) -> Option<Self> {
        match service_type {
            0x0203 => Some(Self::DescriptionRequest),
            _ => None,
        }
    }
    /// The service of an encoded frame: header version 0x10, the 14-byte description request with
    /// a UDP control endpoint of 0.0.0.0:0 (reply to the sender).
    pub fn of_frame(frame: &[u8]) -> Option<Self> {
        if frame.len() != 14
            || frame[..2] != [0x06, 0x10]
            || u16::from_be_bytes([frame[4], frame[5]]) != 14
            || frame[6..] != [0x08, 0x01, 0, 0, 0, 0, 0, 0]
        {
            return None;
        }
        Self::from_service_type(u16::from_be_bytes([frame[2], frame[3]]))
    }
}

/// One KNXnet/IP request of an allow-listed service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KnxRequest {
    service: KnxService,
}

impl KnxRequest {
    pub const fn new(service: KnxService) -> Self {
        Self { service }
    }
}

impl sealed::Sealed for KnxRequest {}
impl ReadOnlyRequest for KnxRequest {
    fn info(&self) -> RequestInfo {
        RequestInfo {
            protocol: "KNXnet/IP",
            service: format!(
                "DESCRIPTION_REQUEST (service type {:#06X}, unicast)",
                self.service.service_type()
            ),
        }
    }
    fn encode(&self) -> Vec<u8> {
        // Header: size 6, version 1.0, service type, total length 14; HPAI: size 8, UDP over
        // IPv4, address 0.0.0.0 and port 0 (the device answers to the sender of the datagram).
        let mut frame = vec![0x06, 0x10];
        frame.extend(self.service.service_type().to_be_bytes());
        frame.extend(14u16.to_be_bytes());
        frame.extend([0x08, 0x01, 0, 0, 0, 0, 0, 0]);
        frame
    }
}

/// Adds the requests of this module to the dry-run catalog: `(request info, port, TCP, also sent
/// to hosts that answered nothing)`.
pub(super) fn catalog_entries() -> Vec<(RequestInfo, u16, bool)> {
    let mut out = vec![];
    for c in FinsCommand::ALLOWED {
        out.push((FinsRequest::new(0, c).info(), 9600, false));
    }
    for m in FoxMessage::ALLOWED {
        out.push((FoxRequest::new(m).info(), 1911, true));
    }
    for p in MqttPacket::ALLOWED {
        out.push((MqttRequest::new(p).info(), 1883, true));
    }
    for s in KnxService::ALLOWED {
        out.push((KnxRequest::new(s).info(), 3671, false));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fins_accepts_exactly_controller_data_read() {
        let accepted: Vec<(u8, u8)> = (0..=255u8)
            .flat_map(|m| (0..=255u8).map(move |s| (m, s)))
            .filter(|(m, s)| FinsCommand::from_wire(*m, *s).is_some())
            .collect();
        assert_eq!(accepted, [(0x05, 0x01)]);
        // the write, Run and Stop codes in particular
        for (m, s) in [
            (0x01, 0x02),
            (0x01, 0x03),
            (0x02, 0x02),
            (0x03, 0x07),
            (0x04, 0x01),
            (0x04, 0x02),
            (0x07, 0x02),
        ] {
            assert_eq!(FinsCommand::from_wire(m, s), None, "{m:02x}{s:02x}");
        }
    }

    #[test]
    fn fins_encoded_request_is_the_captured_frame_and_every_byte_matters() {
        // the frame of `omron_test.pcap` (UDP, client 10.1.1.173 to the CP1L-EL at 10.1.1.164)
        let captured = [0x80, 0, 2, 0, 0, 0, 0, 0x63, 0, 0xef, 5, 1, 0];
        let r = FinsRequest::new(0x63, FinsCommand::ControllerDataRead);
        assert_eq!(r.encode(), captured);
        assert_eq!(
            FinsCommand::of_frame(&r.encode()),
            Some(FinsCommand::ControllerDataRead)
        );
        for i in 0..13 {
            for value in 0..=255u8 {
                let mut m = captured;
                m[i] = value;
                let free = i == 7 || i == 9; // node number and service ID
                let expected = free || value == captured[i];
                assert_eq!(
                    FinsCommand::of_frame(&m).is_some(),
                    expected,
                    "byte {i} = {value:#x}"
                );
            }
        }
        assert_eq!(FinsCommand::of_frame(&captured[..12]), None);
        assert_eq!(
            r.info().label(),
            "Omron FINS/UDP: Controller Data Read (command 0x0501)"
        );
    }

    #[test]
    fn mqtt_accepts_exactly_connect_and_disconnect() {
        let accepted: Vec<u8> = (0..=255u8)
            .filter(|b| MqttPacket::from_first_byte(*b).is_some())
            .collect();
        assert_eq!(accepted, [0x10, 0xe0]);
        for p in MqttPacket::ALLOWED {
            let bytes = MqttRequest::new(p).encode();
            assert_eq!(MqttPacket::of_frame(&bytes), Some(p));
            assert_eq!(MqttPacket::from_first_byte(bytes[0]), Some(p));
            // changing any byte to any other value is rejected
            for i in 0..bytes.len() {
                for value in 0..=255u8 {
                    if value != bytes[i] {
                        let mut m = bytes.clone();
                        m[i] = value;
                        assert_eq!(MqttPacket::of_frame(&m), None);
                    }
                }
            }
        }
        // no will, user name, password or client ID: the connect flags are clean session only
        let connect = MqttRequest::new(MqttPacket::Connect).encode();
        assert_eq!((connect[9], connect[12], connect[13]), (0x02, 0, 0));
        assert_eq!(usize::from(connect[1]) + 2, connect.len());
        // the same bytes the service probe sends
        assert_eq!(
            connect,
            [
                0x10, 0x0c, 0, 4, 0x4d, 0x51, 0x54, 0x54, 4, 2, 0, 0x3c, 0, 0
            ]
        );
    }

    #[test]
    fn knx_accepts_exactly_the_unicast_description_request() {
        let accepted: Vec<u16> = (0..=u16::MAX)
            .filter(|t| KnxService::from_service_type(*t).is_some())
            .collect();
        assert_eq!(accepted, [0x0203]);
        let frame = KnxRequest::new(KnxService::DescriptionRequest).encode();
        assert_eq!(frame, [6, 0x10, 2, 3, 0, 14, 8, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            KnxService::of_frame(&frame),
            Some(KnxService::DescriptionRequest)
        );
        for i in 0..frame.len() {
            for value in 0..=255u8 {
                if value != frame[i] {
                    let mut m = frame.clone();
                    m[i] = value;
                    assert_eq!(KnxService::of_frame(&m), None, "byte {i} = {value:#x}");
                }
            }
        }
        // the multicast search request (and the others) are refused
        for t in [0x0201u16, 0x0205, 0x0420, 0x0530] {
            let mut m = frame.clone();
            m[2..4].copy_from_slice(&t.to_be_bytes());
            assert_eq!(KnxService::of_frame(&m), None);
        }
    }

    #[test]
    fn fox_accepts_only_the_hello_and_it_has_the_layout_of_the_captured_one() {
        let hello = FoxRequest::new(FoxMessage::Hello).encode();
        assert_eq!(FoxMessage::of_frame(&hello), Some(FoxMessage::Hello));
        let text = String::from_utf8(hello.clone()).unwrap();
        let keys: Vec<&str> = text
            .lines()
            .filter_map(|l| l.split_once('=').map(|(k, _)| k))
            .collect();
        assert_eq!(keys, FoxMessage::HELLO_KEYS);
        assert!(text.starts_with("fox a 1 -1 fox hello\n{\n") && text.ends_with("};;\n"));
        // no authentication or other command, whatever is appended or changed
        for bad in [
            "fox a 2 -1 fox authenticate\n{\n};;\n",
            "fox a 1 -1 fox hello\n{\n};;\nfox a 2 -1 sys:Station\n{\n};;\n",
            "fox a 1 -1 fox hello\n{\nfox a 2 -1 x\n};;\n",
            "fox a 1 -1 fox hello\n{\nid=i:1\n",
            "",
        ] {
            assert_eq!(FoxMessage::of_frame(bad.as_bytes()), None, "{bad:?}");
        }
        assert!(hello.len() < 600);
        assert!(hello.is_ascii());
    }

    #[test]
    fn the_catalog_entries_list_the_ports() {
        let entries = catalog_entries();
        let labels: Vec<(String, u16, bool)> = entries
            .iter()
            .map(|(i, p, silent)| (i.label(), *p, *silent))
            .collect();
        assert_eq!(labels.len(), 5, "{labels:?}");
        assert!(
            labels
                .iter()
                .any(|(l, p, _)| l.contains("Controller Data Read") && *p == 9600)
        );
        assert!(
            labels
                .iter()
                .any(|(l, p, _)| l.contains("DESCRIPTION_REQUEST") && *p == 3671)
        );
        assert!(labels.iter().any(|(l, _, _)| l.contains("MQTT: CONNECT")));
        assert!(
            labels
                .iter()
                .any(|(l, _, _)| l.contains("MQTT: DISCONNECT"))
        );
        assert!(
            labels
                .iter()
                .any(|(l, p, _)| l.starts_with("Niagara Fox: hello") && *p == 1911)
        );
    }
}
