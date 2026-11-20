//! More allow-listed OT requests, all over TCP (ROADMAP C23): Omron FINS/TCP, Mitsubishi MELSEC
//! MC protocol (3E frame, binary) and DNP3. Same rules as the rest of [`super`]: closed enums, no
//! public fields, sealed [`ReadOnlyRequest`], sent only through [`OtStream`](super::OtStream).
//!
//! | Protocol | Allowed | When it is sent |
//! | --- | --- | --- |
//! | Omron FINS/TCP | the node address exchange (FINS/TCP command 0, which carries no FINS command) and Controller Data Read (0x0501) in a FINS/TCP frame (command 2); the frames of a real capture | `--ot`, tcp/9600 found open |
//! | MELSEC MC 3E | Read CPU Model Name (command 0x0101, subcommand 0x0000), binary 3E frame to the own station | only with `--melsec-port PORT`, only to that port, and only if it was found open |
//! | DNP3 | one unconfirmed-user-data link frame carrying Read (function 1) of class 0 (object group 60, variation 1); never a broadcast, reserved or own address | only with `--dnp3-address N`, tcp/20000 found open |
//!
//! None of the write, control or program services exists as a value:
//!
//! ```compile_fail
//! use network_scope_core::ot_readonly::FinsTcpMessage;
//! // a FINS memory write or Run/Stop wrapped in FINS/TCP: no such variants
//! let _ = FinsTcpMessage::MemoryAreaWrite;
//! let _ = FinsTcpMessage::Stop;
//! ```
//!
//! ```
//! use network_scope_core::ot_readonly::{FinsTcpRequest, ReadOnlyRequest};
//! let handshake = FinsTcpRequest::node_address();
//! assert_eq!(&handshake.encode()[..4], b"FINS");
//! let read = FinsTcpRequest::controller_data_read(200);
//! assert_eq!(read.encode()[26..28], [0x05, 0x01]);
//! ```
//!
//! ```compile_fail
//! use network_scope_core::ot_readonly::McCommand;
//! // Batch Write (0x1401), Remote Run/Stop (0x1001/0x1002), Remote Reset (0x1006): not allowed
//! let _ = McCommand::BatchWrite;
//! let _ = McCommand::RemoteStop;
//! ```
//!
//! ```
//! use network_scope_core::ot_readonly::{McCommand, McRequest, ReadOnlyRequest};
//! assert_eq!(McRequest::new(McCommand::CpuModelRead).encode()[11..13], [0x01, 0x01]);
//! ```
//!
//! ```compile_fail
//! use network_scope_core::ot_readonly::Dnp3Function;
//! // Write, Select, Operate, Direct Operate, restarts: not allowed
//! let _ = Dnp3Function::Write;
//! let _ = Dnp3Function::DirectOperate;
//! let _ = Dnp3Function::ColdRestart;
//! ```
//!
//! A DNP3 request cannot be built for a broadcast, reserved or own address:
//!
//! ```
//! use network_scope_core::ot_readonly::{Dnp3Function, Dnp3Request, ReadOnlyRequest};
//! for broadcast in [0xFFFFu16, 0xFFFE, 0xFFFD, 0xFFFC, 0xFFF0] {
//!     assert!(Dnp3Request::new(broadcast, 1, Dnp3Function::ReadClass0).is_none());
//! }
//! assert!(Dnp3Request::new(1, 1, Dnp3Function::ReadClass0).is_none(), "own address");
//! let request = Dnp3Request::new(10, 1, Dnp3Function::ReadClass0).unwrap();
//! assert_eq!(request.encode()[..2], [0x05, 0x64]);
//! ```
//!
//! ```compile_fail
//! use network_scope_core::ot_readonly::Dnp3Request;
//! let _ = Dnp3Request { destination: 0xFFFF, source: 1 };
//! ```
use super::{Optin, ReadOnlyRequest, RequestInfo, more::FinsCommand, sealed};

// ---------------------------------------------------------------------------------------------
// Omron FINS/TCP

/// The FINS/TCP messages that may be sent. Both frames are those of a real capture
/// (`omron_test.pcap`, FINS/TCP between a client and a CP1L-EL, packets 5 and 7): the node
/// address data command that opens a FINS/TCP session, and one Controller Data Read in a FINS
/// frame send command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinsTcpMessage {
    /// FINS/TCP command 0: "client node 0" asks the server to assign a node address. It carries
    /// no FINS command and changes nothing on the controller.
    NodeAddress,
    /// FINS/TCP command 2 around the FINS frame of Controller Data Read (0x0501).
    ControllerDataRead,
}

impl FinsTcpMessage {
    pub const ALLOWED: [Self; 2] = [Self::NodeAddress, Self::ControllerDataRead];
    /// The message of an encoded FINS/TCP frame: the node address request (20 bytes) or the
    /// Controller Data Read (29 bytes). The server node number is the only free byte, everything
    /// else must match the captured frames.
    pub fn of_frame(frame: &[u8]) -> Option<Self> {
        match frame.len() {
            20 if frame == FinsTcpRequest::node_address().encode() => Some(Self::NodeAddress),
            29 => {
                let template = FinsTcpRequest::controller_data_read(0).encode();
                (frame[..20] == template[..20]
                    && frame[21..] == template[21..]
                    && FinsCommand::from_wire(frame[26], frame[27]).is_some())
                .then_some(Self::ControllerDataRead)
            }
            _ => None,
        }
    }
}

/// One FINS/TCP frame of an allow-listed message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinsTcpRequest {
    message: FinsTcpMessage,
    server_node: u8,
}

impl FinsTcpRequest {
    /// The node address data command: the client asks for an address (client node 0 = assign).
    pub const fn node_address() -> Self {
        Self {
            message: FinsTcpMessage::NodeAddress,
            server_node: 0,
        }
    }
    /// Controller Data Read to `server_node`, the server's own node number from its reply to the
    /// node address command. The source node is 0, the unit 0xEF and the SID 5, as in the capture.
    pub const fn controller_data_read(server_node: u8) -> Self {
        Self {
            message: FinsTcpMessage::ControllerDataRead,
            server_node,
        }
    }
    pub const fn message(&self) -> FinsTcpMessage {
        self.message
    }
}

impl sealed::Sealed for FinsTcpRequest {}
impl ReadOnlyRequest for FinsTcpRequest {
    fn info(&self) -> RequestInfo {
        RequestInfo {
            protocol: "Omron FINS/TCP",
            service: match self.message {
                FinsTcpMessage::NodeAddress => "node address data (FINS/TCP command 0)".into(),
                FinsTcpMessage::ControllerDataRead => {
                    let (main, sub) = FinsCommand::ControllerDataRead.codes();
                    format!("Controller Data Read (command {main:#04X}{sub:02X})")
                }
            },
        }
    }
    fn encode(&self) -> Vec<u8> {
        let mut frame = b"FINS".to_vec();
        match self.message {
            FinsTcpMessage::NodeAddress => {
                // length 12, command 0, error 0, client node 0 (four bytes)
                frame.extend([0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
            }
            FinsTcpMessage::ControllerDataRead => {
                // length 21, command 2 (FINS frame send), error 0, then the FINS frame of the
                // capture: ICF 0x80, RSV 0, GCT 2, destination network 0, node, unit 0, source
                // network 0, node 0, unit 0xEF, SID 5, main/sub request code, one parameter byte
                frame.extend([0, 0, 0, 0x15, 0, 0, 0, 2, 0, 0, 0, 0]);
                let (main, sub) = FinsCommand::ControllerDataRead.codes();
                frame.extend([
                    0x80,
                    0,
                    2,
                    0,
                    self.server_node,
                    0,
                    0,
                    0,
                    0xef,
                    5,
                    main,
                    sub,
                    0,
                ]);
            }
        }
        frame
    }
}

// ---------------------------------------------------------------------------------------------
// MELSEC MC protocol

/// The MC protocol commands that may be sent: Read CPU Model Name (command 0x0101, subcommand
/// 0x0000). Every device read or write (0x04xx, 0x14xx), the remote operations (0x10xx: Run,
/// Stop, Pause, Latch Clear, Reset), password and file commands are not allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McCommand {
    CpuModelRead,
}

impl McCommand {
    pub const ALLOWED: [Self; 1] = [Self::CpuModelRead];
    /// (command, subcommand)
    pub const fn codes(self) -> (u16, u16) {
        match self {
            Self::CpuModelRead => (0x0101, 0x0000),
        }
    }
    pub const fn from_wire(command: u16, subcommand: u16) -> Option<Self> {
        match (command, subcommand) {
            (0x0101, 0x0000) => Some(Self::CpuModelRead),
            _ => None,
        }
    }
    /// The command of an encoded 3E binary request: exactly the 15 bytes this scanner sends
    /// (subheader 0x5000, network 0, PC 0xFF, module I/O 0x03FF, station 0, data length 6, timer
    /// 4 s, command, subcommand). No byte is free.
    pub fn of_frame(frame: &[u8]) -> Option<Self> {
        if frame.len() != 15 || frame[..11] != [0x50, 0, 0, 0xff, 0xff, 3, 0, 6, 0, 0x10, 0] {
            return None;
        }
        Self::from_wire(
            u16::from_le_bytes([frame[11], frame[12]]),
            u16::from_le_bytes([frame[13], frame[14]]),
        )
    }
}

/// One MC protocol 3E request of an allow-listed command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct McRequest {
    command: McCommand,
}

impl McRequest {
    pub const fn new(command: McCommand) -> Self {
        Self { command }
    }
}

impl sealed::Sealed for McRequest {}
impl ReadOnlyRequest for McRequest {
    fn info(&self) -> RequestInfo {
        let (command, sub) = self.command.codes();
        RequestInfo {
            protocol: "MELSEC MC 3E",
            service: format!("Read CPU Model Name (command {command:#06X}, subcommand {sub:#06X})"),
        }
    }
    fn encode(&self) -> Vec<u8> {
        let (command, sub) = self.command.codes();
        let mut frame = vec![0x50, 0x00, 0x00, 0xff, 0xff, 0x03, 0x00];
        // data length: monitoring timer (2) + command (2) + subcommand (2)
        frame.extend(6u16.to_le_bytes());
        frame.extend(0x0010u16.to_le_bytes());
        frame.extend(command.to_le_bytes());
        frame.extend(sub.to_le_bytes());
        frame
    }
}

// ---------------------------------------------------------------------------------------------
// DNP3

/// The DNP3 application functions that may be sent: Read (function code 1) of class 0 (object
/// group 60, variation 1, qualifier 6: all static data), the integrity poll's static part. It
/// asks for current values and does not touch the event buffers (classes 1 to 3 are not read),
/// so nothing is consumed or cleared. Write, Select, Operate, Direct Operate, freezes, restarts,
/// Enable/Disable Unsolicited, Assign Class and file functions are not allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dnp3Function {
    ReadClass0,
}

impl Dnp3Function {
    pub const ALLOWED: [Self; 1] = [Self::ReadClass0];
    /// Link layer: DIR (from the master) and PRM (primary) set, no frame count bit, function 4
    /// (unconfirmed user data): the frame asks for no link layer answer or state.
    const LINK_CONTROL: u8 = 0xc4;
    /// Transport: FIR and FIN, sequence 0. Application control: FIR and FIN, no confirm
    /// requested, sequence 0. Then function 1 (Read) and the object header g60 v1, qualifier 6.
    const USER_DATA: [u8; 6] = [0xc0, 0xc0, 0x01, 0x3c, 0x01, 0x06];

    /// The function of an encoded DNP3 data link frame: a valid 18-byte frame (both CRCs) that
    /// carries exactly Read class 0 to a unicast outstation address. Source and destination
    /// addresses are free, within the rules of [`Dnp3Request::new`].
    pub fn of_frame(frame: &[u8]) -> Option<Self> {
        if frame.len() != 18
            || frame[..4] != [0x05, 0x64, 0x0b, Self::LINK_CONTROL]
            || crc(&frame[..8]).to_le_bytes() != frame[8..10]
            || frame[10..16] != Self::USER_DATA
            || crc(&frame[10..16]).to_le_bytes() != frame[16..18]
        {
            return None;
        }
        let destination = u16::from_le_bytes([frame[4], frame[5]]);
        let source = u16::from_le_bytes([frame[6], frame[7]]);
        Dnp3Request::new(destination, source, Self::ReadClass0).map(|_| Self::ReadClass0)
    }
}

/// The DNP3 CRC (IEEE 1815 clause 8.2.1; CRC-16/DNP: polynomial 0x3D65, reflected, complemented),
/// sent low byte first after the 8 header bytes and after every 16-byte block of user data.
pub fn crc(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &byte in data {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xa6bc
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// The first data link address of the reserved and broadcast range (IEEE 1815: 0xFFF0 to 0xFFFB
/// are reserved, 0xFFFC to 0xFFFF are broadcast addresses).
pub const DNP3_FIRST_RESERVED: u16 = 0xfff0;

/// One DNP3 data link frame of an allow-listed function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dnp3Request {
    destination: u16,
    source: u16,
    function: Dnp3Function,
}

impl Dnp3Request {
    /// A request to the outstation `destination` from the master address `source`. `None` for a
    /// destination or source in the reserved and broadcast range (0xFFF0 and above: a broadcast
    /// would be answered, or acted on, by every outstation in reach) and for a destination equal
    /// to the source.
    pub const fn new(destination: u16, source: u16, function: Dnp3Function) -> Option<Self> {
        if destination >= DNP3_FIRST_RESERVED
            || source >= DNP3_FIRST_RESERVED
            || destination == source
        {
            return None;
        }
        Some(Self {
            destination,
            source,
            function,
        })
    }
    pub const fn destination(&self) -> u16 {
        self.destination
    }
}

impl sealed::Sealed for Dnp3Request {}
impl ReadOnlyRequest for Dnp3Request {
    fn info(&self) -> RequestInfo {
        RequestInfo {
            protocol: "DNP3",
            service: "Read class 0 data (function 0x01, object group 60 variation 1)".into(),
        }
    }
    fn encode(&self) -> Vec<u8> {
        let Dnp3Function::ReadClass0 = self.function;
        let mut frame = vec![0x05, 0x64, 0x0b, Dnp3Function::LINK_CONTROL];
        frame.extend(self.destination.to_le_bytes());
        frame.extend(self.source.to_le_bytes());
        frame.extend(crc(&frame).to_le_bytes());
        frame.extend(Dnp3Function::USER_DATA);
        frame.extend(crc(&Dnp3Function::USER_DATA).to_le_bytes());
        frame
    }
}

/// Adds the requests of this module to the dry-run catalog: `(request info, port, TCP, opt-in)`.
pub(super) fn catalog_entries() -> Vec<(RequestInfo, u16, bool, Optin)> {
    let mut out = vec![];
    for m in FinsTcpMessage::ALLOWED {
        let request = match m {
            FinsTcpMessage::NodeAddress => FinsTcpRequest::node_address(),
            FinsTcpMessage::ControllerDataRead => FinsTcpRequest::controller_data_read(0),
        };
        out.push((request.info(), 9600, true, Optin::No));
    }
    for c in McCommand::ALLOWED {
        // the port is the one the user gives (`--melsec-port`), never a default
        out.push((McRequest::new(c).info(), 0, true, Optin::MelsecPort));
    }
    for f in Dnp3Function::ALLOWED {
        if let Some(r) = Dnp3Request::new(10, 1, f) {
            out.push((r.info(), 20000, true, Optin::Dnp3Address));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The client frames of the FINS/TCP exchange in `omron_test.pcap` (a real capture, see
    /// `tests/fixtures/ics/PROVENANCE.md`), packets 5 and 7, as they are on the wire.
    const CAPTURED_NODE_ADDRESS: &str = "46494e530000000c000000000000000000000000";
    const CAPTURED_READ: &str = "46494e5300000015000000020000000080000200c8000000ef05050100";

    #[test]
    fn fins_tcp_frames_are_the_captured_ones_and_every_byte_matters() {
        let handshake = FinsTcpRequest::node_address().encode();
        assert_eq!(handshake, hex(CAPTURED_NODE_ADDRESS));
        // the server in the capture assigned itself node 0xc8
        let read = FinsTcpRequest::controller_data_read(0xc8).encode();
        assert_eq!(read, hex(CAPTURED_READ));
        assert_eq!(
            FinsTcpMessage::of_frame(&handshake),
            Some(FinsTcpMessage::NodeAddress)
        );
        assert_eq!(
            FinsTcpMessage::of_frame(&read),
            Some(FinsTcpMessage::ControllerDataRead)
        );
        // changing any byte to any other value is rejected, except the server node of the read
        for (frame, free) in [(&handshake, None), (&read, Some(20usize))] {
            for i in 0..frame.len() {
                for value in 0..=255u8 {
                    if value == frame[i] {
                        continue;
                    }
                    let mut m = frame.clone();
                    m[i] = value;
                    assert_eq!(
                        FinsTcpMessage::of_frame(&m).is_some(),
                        free == Some(i),
                        "byte {i} = {value:#x}"
                    );
                }
            }
        }
        // a different length, or other FINS commands (memory write 0102, stop 0402, run 0401)
        assert_eq!(FinsTcpMessage::of_frame(&read[..28]), None);
        for (main, sub) in [(1u8, 2u8), (4, 2), (4, 1), (2, 2)] {
            let mut m = read.clone();
            (m[26], m[27]) = (main, sub);
            assert_eq!(FinsTcpMessage::of_frame(&m), None, "{main:02x}{sub:02x}");
        }
        assert_eq!(
            FinsTcpRequest::node_address().info().label(),
            "Omron FINS/TCP: node address data (FINS/TCP command 0)"
        );
        assert_eq!(
            FinsTcpRequest::controller_data_read(1).info().label(),
            "Omron FINS/TCP: Controller Data Read (command 0x0501)"
        );
    }

    #[test]
    fn mc_accepts_exactly_the_cpu_model_read_and_no_byte_is_free() {
        let accepted: Vec<(u16, u16)> = (0..=u16::MAX)
            .flat_map(|c| [0u16, 1, 0x80, 0xffff].map(move |s| (c, s)))
            .filter(|(c, s)| McCommand::from_wire(*c, *s).is_some())
            .collect();
        assert_eq!(accepted, [(0x0101, 0)]);
        // the write, remote operation and password commands are out
        for command in [
            0x1401u16, 0x1402, 0x1406, 0x1001, 0x1002, 0x1003, 0x1005, 0x1006, 0x1630, 0x1631,
            0x0401, 0x0403,
        ] {
            assert_eq!(McCommand::from_wire(command, 0), None, "{command:04x}");
        }
        let frame = McRequest::new(McCommand::CpuModelRead).encode();
        // the 3E binary frame of the MC protocol reference: subheader 5000, network 00, PC FF,
        // module I/O 03FF, station 00, length 0006, timer 0010, command 0101, subcommand 0000
        assert_eq!(
            frame,
            [0x50, 0, 0, 0xff, 0xff, 3, 0, 6, 0, 0x10, 0, 1, 1, 0, 0]
        );
        assert_eq!(McCommand::of_frame(&frame), Some(McCommand::CpuModelRead));
        for i in 0..frame.len() {
            for value in 0..=255u8 {
                if value != frame[i] {
                    let mut m = frame.clone();
                    m[i] = value;
                    assert_eq!(McCommand::of_frame(&m), None, "byte {i} = {value:#x}");
                }
            }
        }
        assert_eq!(McCommand::of_frame(&frame[..14]), None);
        assert_eq!(
            McRequest::new(McCommand::CpuModelRead).info().label(),
            "MELSEC MC 3E: Read CPU Model Name (command 0x0101, subcommand 0x0000)"
        );
    }

    /// The CRC is checked against the data link frame of the capture `dnp3_read_and_response.pcap`
    /// (packet 3: a master reading classes 1, 2, 3 and 0): header CRC 0xED8F and data block CRC
    /// 0x518A, both sent low byte first.
    #[test]
    fn the_dnp3_crc_matches_the_captured_frame() {
        let header = hex("056414c40a000100");
        let block = hex("c0c0013c02063c03063c04063c0106");
        assert_eq!(crc(&header), 0xed8f);
        assert_eq!(crc(&block), 0x518a);
        // CRC-16/DNP check value of the standard test string
        assert_eq!(crc(b"123456789"), 0xea82);
    }

    #[test]
    fn dnp3_accepts_exactly_read_class_0_to_a_unicast_outstation() {
        let request = Dnp3Request::new(10, 1, Dnp3Function::ReadClass0).unwrap();
        let frame = request.encode();
        assert_eq!(frame.len(), 18);
        // the header is the capture's but for the length (11, one object instead of four) and
        // the CRC that follows from it
        assert_eq!(frame[..8], hex("05640bc40a000100")[..]);
        assert_eq!(frame[10..16], hex("c0c0013c0106")[..]);
        assert_eq!(
            Dnp3Function::of_frame(&frame),
            Some(Dnp3Function::ReadClass0)
        );
        // every changed byte is rejected: with its CRC left alone it no longer verifies, and with
        // the CRCs fixed up again it still is, except the four address bytes
        let fixed = |mut m: Vec<u8>| {
            let h = crc(&m[..8]).to_le_bytes();
            m[8..10].copy_from_slice(&h);
            let d = crc(&m[10..16]).to_le_bytes();
            m[16..18].copy_from_slice(&d);
            m
        };
        for i in 0..frame.len() {
            for value in 0..=255u8 {
                if value == frame[i] {
                    continue;
                }
                let mut m = frame.clone();
                m[i] = value;
                assert_eq!(
                    Dnp3Function::of_frame(&m),
                    None,
                    "byte {i} = {value:#x} without a new CRC"
                );
                if i < 8 || (10..16).contains(&i) {
                    let ok = (4..8).contains(&i)
                        && Dnp3Request::new(
                            u16::from_le_bytes([m[4], m[5]]),
                            u16::from_le_bytes([m[6], m[7]]),
                            Dnp3Function::ReadClass0,
                        )
                        .is_some();
                    assert_eq!(
                        Dnp3Function::of_frame(&fixed(m)).is_some(),
                        ok,
                        "byte {i} = {value:#x}"
                    );
                }
            }
        }
        // no write, operate, restart or other function code in the user data
        for function in 0..=255u8 {
            let mut data = hex("c0c0013c0106");
            data[2] = function;
            let mut m = frame.clone();
            m[10..16].copy_from_slice(&data);
            m[16..18].copy_from_slice(&crc(&data).to_le_bytes());
            assert_eq!(
                Dnp3Function::of_frame(&m).is_some(),
                function == 1,
                "function {function}"
            );
        }
        // other objects: classes 1 to 3 (events), a control relay output block, binary inputs
        for (group, variation) in [(0x3cu8, 2u8), (0x3c, 3), (0x3c, 4), (0x0c, 1), (0x01, 2)] {
            let mut data = hex("c0c0013c0106");
            (data[3], data[4]) = (group, variation);
            let mut m = frame.clone();
            m[10..16].copy_from_slice(&data);
            m[16..18].copy_from_slice(&crc(&data).to_le_bytes());
            assert_eq!(Dnp3Function::of_frame(&m), None, "g{group}v{variation}");
        }
        // broadcast, reserved and own addresses are refused, in the constructor and in a frame
        for destination in 0xfff0..=u16::MAX {
            assert!(Dnp3Request::new(destination, 1, Dnp3Function::ReadClass0).is_none());
        }
        assert!(Dnp3Request::new(10, 0xfffe, Dnp3Function::ReadClass0).is_none());
        assert!(Dnp3Request::new(7, 7, Dnp3Function::ReadClass0).is_none());
        assert!(Dnp3Request::new(0, 1, Dnp3Function::ReadClass0).is_some());
        assert!(Dnp3Request::new(0xffef, 1, Dnp3Function::ReadClass0).is_some());
        let mut broadcast = frame.clone();
        broadcast[4..6].copy_from_slice(&0xffffu16.to_le_bytes());
        assert_eq!(Dnp3Function::of_frame(&fixed(broadcast)), None);
        assert_eq!(
            request.info().label(),
            "DNP3: Read class 0 data (function 0x01, object group 60 variation 1)"
        );
    }

    #[test]
    fn the_catalog_entries_say_which_requests_are_opt_in() {
        let entries = catalog_entries();
        assert_eq!(entries.len(), 4);
        let find = |text: &str| {
            entries
                .iter()
                .find(|(i, _, _, _)| i.label().contains(text))
                .map(|(_, port, tcp, optin)| (*port, *tcp, *optin))
        };
        assert_eq!(find("node address"), Some((9600, true, Optin::No)));
        assert_eq!(find("Controller Data Read"), Some((9600, true, Optin::No)));
        assert_eq!(
            find("Read CPU Model Name"),
            Some((0, true, Optin::MelsecPort)),
            "the MC port is the user's, never a default"
        );
        assert_eq!(
            find("Read class 0"),
            Some((20000, true, Optin::Dnp3Address))
        );
    }
}
