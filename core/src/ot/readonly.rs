//! Type-level read-only guarantee for active OT traffic (ROADMAP H51).
//!
//! Every byte the OT code sends is built here, from a closed allow-list of read-only
//! services, and leaves through the only two sending functions of this crate's OT code,
//! [`OtStream::send`] and [`OtUdp::send`]. Both accept only a [`ReadOnlyRequest`], a sealed
//! trait that only the request types of this module implement; none takes `&[u8]`. The request
//! types have private fields, so the only way to obtain one is a constructor that takes the
//! allow-list enums ([`ModbusFunction`], [`S7Szl`], [`EnipCommand`], [`BacnetService`],
//! [`OpcUaMessage`], [`DcpService`]). A write or control service therefore has no value to pass: sending one
//! needs a new variant in one of those enums, which is a reviewed code change that the tests
//! below (exhaustive over every function code byte) then fail until the allow-list is
//! deliberately updated.
//!
//! The allow-lists contain exactly what the scanner sends today:
//!
//! | Protocol | Allowed |
//! | --- | --- |
//! | Modbus/TCP | function 0x2B with MEI type 0x0E (Read Device Identification) |
//! | S7comm | COTP connection request, Setup communication (job function 0xF0), Userdata CPU functions / Read SZL (0x44, 0x01) for SZL 0x0011 and 0x001C |
//! | EtherNet/IP | encapsulation command 0x0063 (List Identity) |
//! | BACnet/IP | unicast Who-Is (BVLC 0x0A, unconfirmed request, service 8) |
//! | OPC UA | HEL, OpenSecureChannel (446), GetEndpoints (428), FindServers (422), CloseSecureChannel (452), SecurityPolicy None |
//! | Profinet DCP | Identify All (frame ID 0xFEFE, service ID 5, request, option/suboption 0xFF/0xFF), layer 2 multicast, sent only through [`DcpFrameTx`] |
//!
//! A Modbus write cannot be constructed; this does not compile:
//!
//! ```compile_fail
//! use network_scope_core::ot_readonly::{ModbusFunction, ModbusRequest};
//! // Write Single Register (0x06) / Write Multiple Registers (0x10): no such variants.
//! let _ = ModbusRequest::new(1, ModbusFunction::WriteSingleRegister);
//! let _ = ModbusRequest::new(1, ModbusFunction::WriteMultipleRegisters);
//! ```
//!
//! The same code with the allow-listed function compiles, so the failure above is the
//! allow-list and not a missing import:
//!
//! ```
//! use network_scope_core::ot_readonly::{ModbusFunction, ModbusRequest, ReadOnlyRequest};
//! let request = ModbusRequest::new(1, ModbusFunction::ReadDeviceIdentification);
//! assert_eq!(request.encode()[7], 0x2b);
//! ```
//!
//! Request values cannot be built from raw fields either:
//!
//! ```compile_fail
//! use network_scope_core::ot_readonly::ModbusRequest;
//! let _ = ModbusRequest { unit: 1, function: 0x10 };
//! ```
//!
//! S7 has no write, stop, download or block-access variant:
//!
//! ```compile_fail
//! use network_scope_core::ot_readonly::S7Request;
//! let _ = S7Request::write_var(1);
//! let _ = S7Request::plc_stop();
//! ```
//!
//! ```
//! use network_scope_core::ot_readonly::{ReadOnlyRequest, S7Request, S7Szl};
//! let request = S7Request::read_szl(2, S7Szl::ModuleIdentification);
//! assert_eq!(request.encode()[7..9], [0x32, 7]);
//! ```
//!
//! The DCP Identify request is the only layer-2 frame; Set (which changes a device's name or
//! address), Get and Hello have no value:
//!
//! ```compile_fail
//! use network_scope_core::ot_readonly::{DcpRequest, DcpService};
//! let _ = DcpRequest::new([2, 0, 0, 0, 0, 1], DcpService::Set);
//! let _ = DcpRequest::new([2, 0, 0, 0, 0, 1], DcpService::Hello);
//! ```
//!
//! ```
//! use network_scope_core::ot_readonly::{DcpRequest, DcpService, ReadOnlyRequest};
//! let request = DcpRequest::new([2, 0, 0, 0, 0, 1], DcpService::IdentifyAll);
//! assert_eq!(request.encode()[14..17], [0xfe, 0xfe, 5]);
//! ```
//!
//! and the frame sender takes no raw bytes either:
//!
//! ```compile_fail
//! use network_scope_core::{capture::Capture, ot_readonly::DcpFrameTx};
//! fn raw(capture: &mut Capture) {
//!     let _ = DcpFrameTx::new(capture).send(&[0u8; 60]);
//! }
//! ```
//!
//! The socket wrappers accept no raw bytes:
//!
//! ```compile_fail
//! use network_scope_core::ot_readonly::OtStream;
//! async fn raw(stream: &mut OtStream) {
//!     let _ = stream.send(&[0x00u8, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x06]).await;
//! }
//! ```
//!
//! and the sealed trait cannot be implemented elsewhere:
//!
//! ```compile_fail
//! use network_scope_core::ot_readonly::ReadOnlyRequest;
//! struct Write;
//! impl ReadOnlyRequest for Write {
//!     fn encode(&self) -> Vec<u8> {
//!         vec![0x10]
//!     }
//! }
//! ```
use crate::sendlog::{PacketKind, SentLog};
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWriteExt, ReadBuf},
    net::{TcpStream, ToSocketAddrs, UdpSocket},
};

mod sealed {
    pub trait Sealed {}
}

/// What a request is, for the dry run and the sent log: the protocol and the service with its
/// function code. Built from the same allow-list values that build the bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestInfo {
    pub protocol: &'static str,
    pub service: String,
}
impl RequestInfo {
    /// `"Modbus/TCP: function 0x2B, MEI type 0x0E (Read Device Identification)"`: the detail
    /// under which the request is counted in the sent log and listed in the plan.
    pub fn label(&self) -> String {
        format!("{}: {}", self.protocol, self.service)
    }
}

/// A request that is allowed on the wire. Sealed: only the types of this module implement it.
pub trait ReadOnlyRequest: sealed::Sealed {
    /// The exact bytes of this request (one write per request).
    fn encode(&self) -> Vec<u8>;
    /// The protocol and service of this request.
    fn info(&self) -> RequestInfo;
}

/// A TCP connection that can read freely but only send [`ReadOnlyRequest`]s. With a log
/// attached ([`OtStream::with_log`]) every request it sends is counted there.
pub struct OtStream(TcpStream, Option<Arc<SentLog>>);

impl OtStream {
    pub async fn connect(addr: impl ToSocketAddrs) -> io::Result<Self> {
        TcpStream::connect(addr).await.map(|s| Self(s, None))
    }
    /// Counts every request sent through this stream in `log`.
    pub fn with_log(mut self, log: Arc<SentLog>) -> Self {
        self.1 = Some(log);
        self
    }
    /// Sends one request with a single `write_all`.
    pub async fn send<R: ReadOnlyRequest>(&mut self, request: &R) -> io::Result<()> {
        if let Some(log) = &self.1 {
            log.record(PacketKind::OtRequest, request.info().label());
        }
        self.0.write_all(&request.encode()).await
    }
}

impl From<TcpStream> for OtStream {
    fn from(stream: TcpStream) -> Self {
        Self(stream, None)
    }
}

impl AsyncRead for OtStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

/// A connected UDP socket that can receive freely but only send [`ReadOnlyRequest`]s.
pub struct OtUdp(UdpSocket, Option<Arc<SentLog>>);

impl OtUdp {
    /// Binds `local` and connects to `target`; datagrams go only to that one address.
    pub async fn connect(local: &str, target: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(local).await?;
        socket.connect(target).await?;
        Ok(Self(socket, None))
    }
    /// Counts every request sent through this socket in `log`.
    pub fn with_log(mut self, log: Arc<SentLog>) -> Self {
        self.1 = Some(log);
        self
    }
    pub async fn send<R: ReadOnlyRequest>(&self, request: &R) -> io::Result<usize> {
        if let Some(log) = &self.1 {
            log.record(PacketKind::OtRequest, request.info().label());
        }
        self.0.send(&request.encode()).await
    }
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.recv(buf).await
    }
}

// ---------------------------------------------------------------------------------------------
// Modbus/TCP

/// The Modbus function codes the scanner may send. Read Device Identification is function
/// 0x2B with MEI type 0x0E; other MEI types of function 0x2B (for example 0x0D, CANopen
/// transport) are not allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModbusFunction {
    ReadDeviceIdentification,
}

impl ModbusFunction {
    pub const ALLOWED: [Self; 1] = [Self::ReadDeviceIdentification];
    const fn name(self) -> &'static str {
        match self {
            Self::ReadDeviceIdentification => "Read Device Identification",
        }
    }
    const fn function_code(self) -> u8 {
        match self {
            Self::ReadDeviceIdentification => 0x2b,
        }
    }
    const fn mei_type(self) -> u8 {
        match self {
            Self::ReadDeviceIdentification => 0x0e,
        }
    }
    /// The allow-listed function for a function code and MEI type byte, if any. Everything else
    /// (every write, diagnostic and program function) is `None`.
    pub const fn from_wire(function_code: u8, mei_type: u8) -> Option<Self> {
        match (function_code, mei_type) {
            (0x2b, 0x0e) => Some(Self::ReadDeviceIdentification),
            _ => None,
        }
    }
    /// The function of an encoded Modbus/TCP frame (MBAP header and PDU).
    pub fn of_frame(frame: &[u8]) -> Option<Self> {
        let length = u16::from_be_bytes([*frame.get(4)?, *frame.get(5)?]) as usize;
        if frame.len() != 6 + length || frame.get(2..4)? != [0, 0] {
            return None;
        }
        Self::from_wire(*frame.get(7)?, *frame.get(8)?)
    }
}

/// One Modbus/TCP request of an allow-listed function. Transaction ID `NS`, the unit ID is
/// the caller's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModbusRequest {
    unit: u8,
    function: ModbusFunction,
}

impl ModbusRequest {
    pub const fn new(unit: u8, function: ModbusFunction) -> Self {
        Self { unit, function }
    }
}

impl sealed::Sealed for ModbusRequest {}
impl ReadOnlyRequest for ModbusRequest {
    fn info(&self) -> RequestInfo {
        RequestInfo {
            protocol: "Modbus/TCP",
            service: format!(
                "function {:#04X}, MEI type {:#04X} ({})",
                self.function.function_code(),
                self.function.mei_type(),
                self.function.name()
            ),
        }
    }
    fn encode(&self) -> Vec<u8> {
        // MBAP: transaction "NS", protocol 0, length 5, unit; PDU: function, MEI type,
        // read device ID code 1 (basic), object ID 0.
        vec![
            0x4e,
            0x53,
            0,
            0,
            0,
            5,
            self.unit,
            self.function.function_code(),
            self.function.mei_type(),
            1,
            0,
        ]
    }
}

// ---------------------------------------------------------------------------------------------
// S7comm

/// The System State List (SZL) IDs that may be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum S7Szl {
    /// SZL 0x0011: module identification (order code, firmware).
    ModuleIdentification,
    /// SZL 0x001C: component identification (name, serial, CPU type).
    ComponentIdentification,
}

impl S7Szl {
    pub const ALLOWED: [Self; 2] = [Self::ModuleIdentification, Self::ComponentIdentification];
    /// The low byte of the SZL ID (the high byte is always 0).
    pub const fn id(self) -> u8 {
        match self {
            Self::ModuleIdentification => 0x11,
            Self::ComponentIdentification => 0x1c,
        }
    }
    pub const fn from_id(id: u8) -> Option<Self> {
        match id {
            0x11 => Some(Self::ModuleIdentification),
            0x1c => Some(Self::ComponentIdentification),
            _ => None,
        }
    }
}

/// The S7 services the scanner may use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum S7Service {
    /// COTP connection request (PDU type 0xE0); carries no S7 PDU.
    ConnectionRequest,
    /// Job "Setup communication" (function 0xF0).
    SetupCommunication,
    /// Userdata, CPU functions (group 4), subfunction 1: Read SZL.
    ReadSzl,
}

impl S7Service {
    pub const ALLOWED: [Self; 3] = [
        Self::ConnectionRequest,
        Self::SetupCommunication,
        Self::ReadSzl,
    ];
    /// COTP PDU type byte of a connection request.
    pub const fn from_cotp_type(pdu_type: u8) -> Option<Self> {
        match pdu_type {
            0xe0 => Some(Self::ConnectionRequest),
            _ => None,
        }
    }
    /// Job function code (S7 ROSCTR 1). Read/Write Var, PLC control and stop, download and
    /// upload and every other function code are `None`.
    pub const fn from_job_function(function: u8) -> Option<Self> {
        match function {
            0xf0 => Some(Self::SetupCommunication),
            _ => None,
        }
    }
    /// Userdata type/group byte and subfunction (S7 ROSCTR 7). Only request type 4, group 4
    /// (CPU functions), subfunction 1 (Read SZL) is allowed.
    pub const fn from_userdata(type_group: u8, subfunction: u8) -> Option<Self> {
        match (type_group, subfunction) {
            (0x44, 1) => Some(Self::ReadSzl),
            _ => None,
        }
    }
    /// The service of an encoded TPKT frame.
    pub fn of_frame(frame: &[u8]) -> Option<Self> {
        let length = u16::from_be_bytes([*frame.get(2)?, *frame.get(3)?]) as usize;
        if frame.len() != length || frame[0] != 3 || frame[1] != 0 {
            return None;
        }
        match *frame.get(5)? {
            0xf0 => {} // COTP data TPDU carrying S7
            other => return Self::from_cotp_type(other),
        }
        if *frame.get(7)? != 0x32 {
            return None;
        }
        match *frame.get(8)? {
            1 => Self::from_job_function(*frame.get(17)?),
            7 if frame.get(17..20)? == [0, 1, 0x12] => {
                Self::from_userdata(*frame.get(22)?, *frame.get(23)?)
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum S7Kind {
    Connect { tsap_slot: u8 },
    Setup,
    ReadSzl { sequence: u8, szl: S7Szl },
}

/// One S7comm request (TPKT frame) of an allow-listed service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct S7Request(S7Kind);

impl S7Request {
    /// COTP connection request to rack 0-7, slot 0-31; `None` outside that range.
    pub const fn connection_request(rack: u8, slot: u8) -> Option<Self> {
        if rack > 7 || slot > 31 {
            return None;
        }
        Some(Self(S7Kind::Connect {
            tsap_slot: rack * 32 + slot,
        }))
    }
    /// Setup communication (PDU size negotiation).
    pub const fn setup_communication() -> Self {
        Self(S7Kind::Setup)
    }
    /// Read SZL `szl`; `sequence` is the S7 PDU reference.
    pub const fn read_szl(sequence: u8, szl: S7Szl) -> Self {
        Self(S7Kind::ReadSzl { sequence, szl })
    }
}

impl sealed::Sealed for S7Request {}
impl ReadOnlyRequest for S7Request {
    fn info(&self) -> RequestInfo {
        RequestInfo {
            protocol: "S7comm",
            service: match self.0 {
                S7Kind::Connect { .. } => "COTP connection request (PDU type 0xE0)".into(),
                S7Kind::Setup => "Setup communication (job function 0xF0)".into(),
                S7Kind::ReadSzl { szl, .. } => format!(
                    "Read SZL {:#06X} (userdata, group 0x44, subfunction 0x01)",
                    szl.id()
                ),
            },
        }
    }
    fn encode(&self) -> Vec<u8> {
        match self.0 {
            S7Kind::Connect { tsap_slot } => {
                let mut cr = vec![
                    3, 0, 0, 22, 17, 0xe0, 0, 0, 0, 1, 0, 0xc1, 2, 1, 0, 0xc2, 2, 1, 0, 0xc0, 1, 10,
                ];
                cr[18] = tsap_slot;
                cr
            }
            S7Kind::Setup => vec![
                3, 0, 0, 25, 2, 0xf0, 0x80, 0x32, 1, 0, 0, 0, 1, 0, 8, 0, 0, 0xf0, 0, 0, 1, 0, 1,
                1, 0xe0,
            ],
            S7Kind::ReadSzl { sequence, szl } => vec![
                3,
                0,
                0,
                33,
                2,
                0xf0,
                0x80,
                0x32,
                7,
                0,
                0,
                0,
                sequence,
                0,
                8,
                0,
                8,
                0,
                1,
                0x12,
                4,
                0x11,
                0x44,
                1,
                0,
                0xff,
                9,
                0,
                4,
                0,
                szl.id(),
                0,
                0,
            ],
        }
    }
}

// ---------------------------------------------------------------------------------------------
// EtherNet/IP

/// The encapsulation commands that may be sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnipCommand {
    /// 0x0063 List Identity.
    ListIdentity,
}

impl EnipCommand {
    pub const ALLOWED: [Self; 1] = [Self::ListIdentity];
    pub const fn code(self) -> u16 {
        match self {
            Self::ListIdentity => 0x0063,
        }
    }
    /// SendRRData (0x6F), SendUnitData (0x70), RegisterSession and the rest are `None`.
    pub const fn from_code(code: u16) -> Option<Self> {
        match code {
            0x0063 => Some(Self::ListIdentity),
            _ => None,
        }
    }
    /// The command of an encoded encapsulation message (24-byte header).
    pub fn of_frame(frame: &[u8]) -> Option<Self> {
        let length = u16::from_le_bytes([*frame.get(2)?, *frame.get(3)?]) as usize;
        if frame.len() != 24 + length {
            return None;
        }
        Self::from_code(u16::from_le_bytes([frame[0], frame[1]]))
    }
}

/// One EtherNet/IP encapsulation request of an allow-listed command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnipRequest {
    command: EnipCommand,
}

impl EnipRequest {
    /// The sender context the replies must echo (bytes 12 to 20 of the header).
    pub const SENDER_CONTEXT: [u8; 8] = *b"NETSCOPE";
    pub const fn new(command: EnipCommand) -> Self {
        Self { command }
    }
}

impl sealed::Sealed for EnipRequest {}
impl ReadOnlyRequest for EnipRequest {
    fn info(&self) -> RequestInfo {
        RequestInfo {
            protocol: "EtherNet/IP",
            service: match self.command {
                EnipCommand::ListIdentity => {
                    format!("List Identity (command {:#06X})", self.command.code())
                }
            },
        }
    }
    fn encode(&self) -> Vec<u8> {
        let mut request = vec![0u8; 24];
        request[..2].copy_from_slice(&self.command.code().to_le_bytes());
        request[12..20].copy_from_slice(&Self::SENDER_CONTEXT);
        request
    }
}

// ---------------------------------------------------------------------------------------------
// BACnet/IP

/// The BACnet unconfirmed services that may be sent. Confirmed requests (ReadProperty,
/// WriteProperty, ReinitializeDevice, ...) and broadcast BVLC functions are not allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BacnetService {
    /// Unconfirmed service 8.
    WhoIs,
}

impl BacnetService {
    pub const ALLOWED: [Self; 1] = [Self::WhoIs];
    pub const fn unconfirmed_code(self) -> u8 {
        match self {
            Self::WhoIs => 8,
        }
    }
    pub const fn from_unconfirmed_code(code: u8) -> Option<Self> {
        match code {
            8 => Some(Self::WhoIs),
            _ => None,
        }
    }
    /// The service of an encoded BVLC frame: original unicast NPDU (0x0A, not the broadcast
    /// 0x0B), NPDU version 1 without routing, unconfirmed request PDU (type 1).
    pub fn of_frame(frame: &[u8]) -> Option<Self> {
        let length = u16::from_be_bytes([*frame.get(2)?, *frame.get(3)?]) as usize;
        if frame.len() != length || frame[0] != 0x81 || frame[1] != 0x0a {
            return None;
        }
        if *frame.get(4)? != 1 || *frame.get(5)? != 0 || *frame.get(6)? != 0x10 {
            return None;
        }
        Self::from_unconfirmed_code(*frame.get(7)?)
    }
}

/// One unicast BACnet/IP request of an allow-listed unconfirmed service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BacnetRequest {
    service: BacnetService,
}

impl BacnetRequest {
    pub const fn new(service: BacnetService) -> Self {
        Self { service }
    }
}

impl sealed::Sealed for BacnetRequest {}
impl ReadOnlyRequest for BacnetRequest {
    fn info(&self) -> RequestInfo {
        RequestInfo {
            protocol: "BACnet/IP",
            service: match self.service {
                BacnetService::WhoIs => format!(
                    "unicast Who-Is (unconfirmed service {})",
                    self.service.unconfirmed_code()
                ),
            },
        }
    }
    fn encode(&self) -> Vec<u8> {
        // BVLC original-unicast-NPDU, length 8; NPDU version 1, no flags; APDU unconfirmed
        // request (type 1) and the service.
        vec![
            0x81,
            0x0a,
            0,
            8,
            1,
            0,
            0x10,
            self.service.unconfirmed_code(),
        ]
    }
}

// ---------------------------------------------------------------------------------------------
// OPC UA

/// The OPC UA messages that may be sent (UA Binary over TCP, SecurityPolicy None).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpcUaMessage {
    /// Transport HEL message.
    Hello,
    /// OpenSecureChannelRequest (node 446).
    OpenSecureChannel,
    /// GetEndpointsRequest (node 428).
    GetEndpoints,
    /// FindServersRequest (node 422).
    FindServers,
    /// CloseSecureChannelRequest (node 452).
    CloseSecureChannel,
}

impl OpcUaMessage {
    pub const ALLOWED: [Self; 5] = [
        Self::Hello,
        Self::OpenSecureChannel,
        Self::GetEndpoints,
        Self::FindServers,
        Self::CloseSecureChannel,
    ];
    /// Namespace 0 service request node ID. Write (673), Call (712), CreateSession (461),
    /// ActivateSession (467), Browse, Read and every other service are `None`.
    pub const fn from_request_node(id: u16) -> Option<Self> {
        match id {
            446 => Some(Self::OpenSecureChannel),
            428 => Some(Self::GetEndpoints),
            422 => Some(Self::FindServers),
            452 => Some(Self::CloseSecureChannel),
            _ => None,
        }
    }
    const fn request_node(self) -> u16 {
        match self {
            Self::Hello => 0,
            Self::OpenSecureChannel => 446,
            Self::GetEndpoints => 428,
            Self::FindServers => 422,
            Self::CloseSecureChannel => 452,
        }
    }
    /// The sequence number and request handle used for this message.
    pub const fn request_id(self) -> u32 {
        match self {
            Self::Hello => 0,
            Self::OpenSecureChannel => 1,
            Self::GetEndpoints => 2,
            Self::FindServers => 3,
            Self::CloseSecureChannel => 4,
        }
    }
    /// The message of an encoded UA TCP message: the transport tag (final chunk of HEL, OPN,
    /// MSG or CLO) and, for the service messages, the request node ID.
    pub fn of_message(message: &[u8]) -> Option<Self> {
        let length = u32::from_le_bytes(message.get(4..8)?.try_into().ok()?) as usize;
        if message.len() != length {
            return None;
        }
        let word = |at: usize| -> Option<usize> {
            Some(u32::from_le_bytes(message.get(at..at + 4)?.try_into().ok()?) as usize)
        };
        let node_at = |at: usize| -> Option<u16> {
            // four-byte node ID, namespace 0
            if message.get(at..at + 2)? != [1, 0] {
                return None;
            }
            Some(u16::from_le_bytes(
                message.get(at + 2..at + 4)?.try_into().ok()?,
            ))
        };
        match message.get(..4)? {
            b"HELF" => Some(Self::Hello),
            b"OPNF" => {
                // channel ID, policy URI, sender certificate, receiver thumbprint (both
                // null), sequence number, request ID, then the request node ID
                let policy = word(12)?;
                let node = 12usize
                    .checked_add(4)?
                    .checked_add(policy)?
                    .checked_add(16)?;
                Self::from_request_node(node_at(node)?).filter(|m| *m == Self::OpenSecureChannel)
            }
            b"MSGF" => Self::from_request_node(node_at(24)?)
                .filter(|m| matches!(m, Self::GetEndpoints | Self::FindServers)),
            b"CLOF" => {
                Self::from_request_node(node_at(24)?).filter(|m| *m == Self::CloseSecureChannel)
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum UaKind {
    Hello {
        url: String,
    },
    Open,
    Endpoints {
        channel: u32,
        token: u32,
        url: String,
    },
    Servers {
        channel: u32,
        token: u32,
        url: String,
    },
    Close {
        channel: u32,
        token: u32,
    },
}

/// One complete UA TCP message (header and body) of an allow-listed kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpcUaRequest(UaKind);

/// SecurityPolicy None, the only policy the scanner offers.
pub const UA_POLICY_NONE: &str = "http://opcfoundation.org/UA/SecurityPolicy#None";

fn u32le(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn ua_string(b: &mut Vec<u8>, v: &str) {
    u32le(b, v.len() as u32);
    b.extend_from_slice(v.as_bytes());
}

impl OpcUaRequest {
    /// HEL for `url`.
    pub fn hello(url: &str) -> Self {
        Self(UaKind::Hello { url: url.into() })
    }
    /// OpenSecureChannel with SecurityPolicy None, mode None.
    pub fn open_secure_channel() -> Self {
        Self(UaKind::Open)
    }
    pub fn get_endpoints(channel: u32, token: u32, url: &str) -> Self {
        Self(UaKind::Endpoints {
            channel,
            token,
            url: url.into(),
        })
    }
    pub fn find_servers(channel: u32, token: u32, url: &str) -> Self {
        Self(UaKind::Servers {
            channel,
            token,
            url: url.into(),
        })
    }
    pub fn close_secure_channel(channel: u32, token: u32) -> Self {
        Self(UaKind::Close { channel, token })
    }
    pub fn message(&self) -> OpcUaMessage {
        match self.0 {
            UaKind::Hello { .. } => OpcUaMessage::Hello,
            UaKind::Open => OpcUaMessage::OpenSecureChannel,
            UaKind::Endpoints { .. } => OpcUaMessage::GetEndpoints,
            UaKind::Servers { .. } => OpcUaMessage::FindServers,
            UaKind::Close { .. } => OpcUaMessage::CloseSecureChannel,
        }
    }
    /// The request header and node ID shared by all service requests (`id` is the node, the
    /// handle equals the sequence number). `ticks` is the 100 ns time since 1601.
    fn request_header(message: OpcUaMessage, ticks: u64) -> Vec<u8> {
        let mut b = vec![1, 0];
        b.extend_from_slice(&message.request_node().to_le_bytes());
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&ticks.to_le_bytes());
        u32le(&mut b, message.request_id());
        u32le(&mut b, 0);
        u32le(&mut b, u32::MAX);
        u32le(&mut b, 5000);
        b.extend_from_slice(&[0, 0, 0]);
        b
    }
    fn frame(tag: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut b = tag.to_vec();
        u32le(&mut b, (body.len() + 8) as u32);
        b.extend_from_slice(body);
        b
    }
    fn encode_at(&self, ticks: u64) -> Vec<u8> {
        let message = self.message();
        let chunk_head = |channel: u32, token: u32| {
            let mut b = vec![];
            for v in [channel, token, message.request_id(), message.request_id()] {
                u32le(&mut b, v);
            }
            b
        };
        match &self.0 {
            UaKind::Hello { url } => {
                let mut hello = vec![];
                for v in [0, 65536, 65536, 1_048_576, 32] {
                    u32le(&mut hello, v);
                }
                ua_string(&mut hello, url);
                Self::frame(b"HELF", &hello)
            }
            UaKind::Open => {
                let mut open = vec![];
                u32le(&mut open, 0);
                ua_string(&mut open, UA_POLICY_NONE);
                u32le(&mut open, u32::MAX);
                u32le(&mut open, u32::MAX);
                u32le(&mut open, 1);
                u32le(&mut open, 1);
                open.extend_from_slice(&Self::request_header(message, ticks));
                for v in [0, 0, 1, u32::MAX, 60000] {
                    u32le(&mut open, v);
                }
                Self::frame(b"OPNF", &open)
            }
            UaKind::Endpoints {
                channel,
                token,
                url,
            }
            | UaKind::Servers {
                channel,
                token,
                url,
            } => {
                let mut b = chunk_head(*channel, *token);
                b.extend_from_slice(&Self::request_header(message, ticks));
                ua_string(&mut b, url);
                u32le(&mut b, 0);
                u32le(&mut b, 0);
                Self::frame(b"MSGF", &b)
            }
            UaKind::Close { channel, token } => {
                let mut b = chunk_head(*channel, *token);
                b.extend_from_slice(&Self::request_header(message, ticks));
                Self::frame(b"CLOF", &b)
            }
        }
    }
}

impl sealed::Sealed for OpcUaRequest {}
impl ReadOnlyRequest for OpcUaRequest {
    fn info(&self) -> RequestInfo {
        let message = self.message();
        RequestInfo {
            protocol: "OPC UA",
            service: match message {
                OpcUaMessage::Hello => "HEL (transport hello)".into(),
                OpcUaMessage::OpenSecureChannel => format!(
                    "OpenSecureChannel (node {}, SecurityPolicy None)",
                    message.request_node()
                ),
                OpcUaMessage::GetEndpoints => {
                    format!("GetEndpoints (node {})", message.request_node())
                }
                OpcUaMessage::FindServers => {
                    format!("FindServers (node {})", message.request_node())
                }
                OpcUaMessage::CloseSecureChannel => {
                    format!("CloseSecureChannel (node {})", message.request_node())
                }
            },
        }
    }
    fn encode(&self) -> Vec<u8> {
        // FILETIME: 100 ns ticks since 1601-01-01.
        let ticks = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            / 100
            + 116444736000000000) as u64;
        self.encode_at(ticks)
    }
}

// ---------------------------------------------------------------------------------------------
// Catalog

/// One request the scanner may send to a port, for the dry run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogEntry {
    pub info: RequestInfo,
    /// The port the request goes to.
    pub port: u16,
    /// TCP or UDP.
    pub tcp: bool,
}

/// Every request of every allow-list, built from the allow-list values themselves, with the port
/// it is sent to. This is exactly the set `ot::identify` can send; the dry run lists it.
pub fn catalog() -> Vec<CatalogEntry> {
    let mut out = vec![];
    let mut add =
        |info: RequestInfo, port: u16, tcp: bool| out.push(CatalogEntry { info, port, tcp });
    for f in ModbusFunction::ALLOWED {
        add(ModbusRequest::new(1, f).info(), 502, true);
    }
    if let Some(cr) = S7Request::connection_request(0, 2) {
        add(cr.info(), 102, true);
    }
    add(S7Request::setup_communication().info(), 102, true);
    for szl in S7Szl::ALLOWED {
        add(S7Request::read_szl(2, szl).info(), 102, true);
    }
    for m in OpcUaMessage::ALLOWED {
        let request = match m {
            OpcUaMessage::Hello => OpcUaRequest::hello(""),
            OpcUaMessage::OpenSecureChannel => OpcUaRequest::open_secure_channel(),
            OpcUaMessage::GetEndpoints => OpcUaRequest::get_endpoints(0, 0, ""),
            OpcUaMessage::FindServers => OpcUaRequest::find_servers(0, 0, ""),
            OpcUaMessage::CloseSecureChannel => OpcUaRequest::close_secure_channel(0, 0),
        };
        add(request.info(), 4840, true);
    }
    for c in EnipCommand::ALLOWED {
        add(EnipRequest::new(c).info(), 44818, true);
    }
    for s in BacnetService::ALLOWED {
        add(BacnetRequest::new(s).info(), 47808, false);
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Profinet DCP (Ethernet layer 2)

/// The DCP services that may be sent: Identify (service ID 0x05, request) for "all devices"
/// (option 0xFF, suboption 0xFF), the read-only discovery query. Get, Set (which changes a
/// device's name or IP address), Hello and every other service ID, frame ID, option and
/// suboption are not allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcpService {
    /// Identify All (frame ID 0xFEFE, service ID 5, request, option/suboption 0xFF/0xFF).
    IdentifyAll,
}

impl DcpService {
    pub const ALLOWED: [Self; 1] = [Self::IdentifyAll];
    /// The multicast destination of an Identify request (01:0E:CF:00:00:00).
    pub const MULTICAST: [u8; 6] = [1, 14, 207, 0, 0, 0];
    /// Ethertype of Profinet (0x8892).
    pub const ETHERTYPE: u16 = 0x8892;
    const fn frame_id(self) -> u16 {
        match self {
            Self::IdentifyAll => 0xfefe,
        }
    }
    const fn service_id(self) -> u8 {
        match self {
            Self::IdentifyAll => 5,
        }
    }
    /// The allow-listed service for the Ethernet frame ID, DCP service ID, service type
    /// (0 = request) and the option and suboption of the single block it carries. Everything
    /// else (Get 3, Set 4, Hello 6, any response, any other block) is `None`.
    pub const fn from_wire(
        frame_id: u16,
        service_id: u8,
        service_type: u8,
        option: u8,
        suboption: u8,
    ) -> Option<Self> {
        match (frame_id, service_id, service_type, option, suboption) {
            (0xfefe, 5, 0, 0xff, 0xff) => Some(Self::IdentifyAll),
            _ => None,
        }
    }
    /// The service of an encoded DCP frame (the 60-byte Ethernet frame of [`DcpRequest`]); the
    /// source MAC, transaction ID and response delay are free, everything else must match.
    pub fn of_frame(frame: &[u8]) -> Option<Self> {
        if frame.len() != 60
            || frame[..6] != Self::MULTICAST
            || u16::from_be_bytes([frame[12], frame[13]]) != Self::ETHERTYPE
            || frame[24..26] != [0, 4]
            || frame[28..30] != [0, 0]
            || frame[30..].iter().any(|b| *b != 0)
        {
            return None;
        }
        Self::from_wire(
            u16::from_be_bytes([frame[14], frame[15]]),
            frame[16],
            frame[17],
            frame[26],
            frame[27],
        )
    }
}

/// One DCP request frame of an allow-listed service, from `source` (the interface MAC).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcpRequest {
    source: [u8; 6],
    service: DcpService,
}

impl DcpRequest {
    pub const fn new(source: [u8; 6], service: DcpService) -> Self {
        Self { source, service }
    }
    pub const fn service(&self) -> DcpService {
        self.service
    }
}

impl sealed::Sealed for DcpRequest {}
impl ReadOnlyRequest for DcpRequest {
    fn info(&self) -> RequestInfo {
        RequestInfo {
            protocol: "Profinet DCP",
            service: match self.service {
                DcpService::IdentifyAll => format!(
                    "Identify All (frame ID {:#06X}, service ID {})",
                    self.service.frame_id(),
                    self.service.service_id()
                ),
            },
        }
    }
    fn encode(&self) -> Vec<u8> {
        // Ethernet II (multicast destination, source, ethertype 0x8892), padded to 60 bytes;
        // DCP header: frame ID, service ID, service type 0 (request), transaction ID "NS\0\x01",
        // response delay 0x0080, data length 4; one block: option, suboption, length 0.
        let mut frame = vec![0u8; 60];
        frame[..6].copy_from_slice(&DcpService::MULTICAST);
        frame[6..12].copy_from_slice(&self.source);
        frame[12..14].copy_from_slice(&DcpService::ETHERTYPE.to_be_bytes());
        frame[14..16].copy_from_slice(&self.service.frame_id().to_be_bytes());
        frame[16] = self.service.service_id();
        frame[18..24].copy_from_slice(&[0x4e, 0x53, 0, 1, 0, 0x80]);
        frame[24..28].copy_from_slice(&[0, 4, 0xff, 0xff]);
        frame
    }
}

/// A capture handle that can send only [`DcpRequest`] frames. The capture it borrows can
/// still receive through its owner; the only way to put a layer-2 OT frame on the wire is
/// [`DcpFrameTx::send`], which takes nothing but an allow-listed request.
pub struct DcpFrameTx<'a>(&'a mut crate::capture::Capture, Option<Arc<SentLog>>);

impl<'a> DcpFrameTx<'a> {
    pub fn new(capture: &'a mut crate::capture::Capture) -> Self {
        Self(capture, None)
    }
    /// Counts every frame sent through this handle in `log`.
    pub fn with_log(mut self, log: Arc<SentLog>) -> Self {
        self.1 = Some(log);
        self
    }
    /// Sends one request as a single frame.
    pub fn send(&mut self, request: &DcpRequest) -> Result<(), String> {
        if let Some(log) = &self.1 {
            log.record(PacketKind::DcpIdentify, request.info().label());
        }
        self.0.send(&request.encode())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_catalog_lists_every_allow_listed_request_with_its_function_code() {
        let labels: Vec<(String, u16, bool)> = catalog()
            .into_iter()
            .map(|e| (e.info.label(), e.port, e.tcp))
            .collect();
        let has = |text: &str, port: u16| {
            assert!(
                labels
                    .iter()
                    .any(|(l, p, _)| l.contains(text) && *p == port),
                "{text} on {port} missing from {labels:?}"
            );
        };
        has("Modbus/TCP: function 0x2B, MEI type 0x0E", 502);
        has("S7comm: COTP connection request (PDU type 0xE0)", 102);
        has("S7comm: Setup communication (job function 0xF0)", 102);
        has("S7comm: Read SZL 0x0011", 102);
        has("S7comm: Read SZL 0x001C", 102);
        has("OPC UA: HEL", 4840);
        has("OPC UA: OpenSecureChannel (node 446", 4840);
        has("OPC UA: GetEndpoints (node 428)", 4840);
        has("OPC UA: FindServers (node 422)", 4840);
        has("OPC UA: CloseSecureChannel (node 452)", 4840);
        has("EtherNet/IP: List Identity (command 0x0063)", 44818);
        has("BACnet/IP: unicast Who-Is (unconfirmed service 8)", 47808);
        assert_eq!(labels.len(), 12, "{labels:?}");
        // Only BACnet is UDP.
        assert!(labels.iter().all(|(_, p, tcp)| *tcp == (*p != 47808)));
        // Labels are unique, so the sent log keys them apart.
        let unique: std::collections::BTreeSet<_> = labels.iter().map(|l| &l.0).collect();
        assert_eq!(unique.len(), labels.len());
    }

    #[tokio::test]
    async fn logged_streams_count_every_request_they_send() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut c, _) = listener.accept().await.unwrap();
            let mut b = [0u8; 64];
            let _ = tokio::io::AsyncReadExt::read(&mut c, &mut b).await;
        });
        let log = Arc::new(SentLog::new());
        let mut stream = OtStream::connect(addr).await.unwrap().with_log(log.clone());
        stream
            .send(&ModbusRequest::new(
                1,
                ModbusFunction::ReadDeviceIdentification,
            ))
            .await
            .unwrap();
        let entries = log.snapshot();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, PacketKind::OtRequest);
        assert_eq!(
            entries[0].detail,
            "Modbus/TCP: function 0x2B, MEI type 0x0E (Read Device Identification)"
        );
        // Without a log nothing is counted (and nothing breaks).
        let plain = OtStream::connect(addr).await;
        drop(plain);
    }

    #[test]
    fn dcp_constructor_accepts_exactly_the_allow_list() {
        let mut accepted = vec![];
        // Every (service ID, service type) pair with the Identify All frame ID and block.
        for service_id in 0..=255u8 {
            for service_type in 0..=255u8 {
                if let Some(s) = DcpService::from_wire(0xfefe, service_id, service_type, 0xff, 0xff)
                {
                    accepted.push((service_id, service_type, s));
                }
            }
        }
        assert_eq!(accepted, vec![(5, 0, DcpService::IdentifyAll)]);
        // Every frame ID.
        let frames: Vec<u16> = (0..=u16::MAX)
            .filter(|f| DcpService::from_wire(*f, 5, 0, 0xff, 0xff).is_some())
            .collect();
        assert_eq!(
            frames,
            [0xfefe],
            "0xFEFD (Get/Set) and 0xFEFC (Hello) are out"
        );
        // Every option/suboption pair.
        let blocks: Vec<(u8, u8)> = (0..=255u8)
            .flat_map(|o| (0..=255u8).map(move |s| (o, s)))
            .filter(|(o, s)| DcpService::from_wire(0xfefe, 5, 0, *o, *s).is_some())
            .collect();
        assert_eq!(blocks, [(0xff, 0xff)]);
        assert_eq!(accepted.len(), DcpService::ALLOWED.len());
        // Get (3), Set (4) and Hello (6) with their usual frame IDs.
        for (frame, service) in [(0xfefd, 3), (0xfefd, 4), (0xfefc, 6)] {
            assert_eq!(DcpService::from_wire(frame, service, 0, 0xff, 0xff), None);
        }
    }

    #[test]
    fn dcp_encoded_request_equals_the_previous_literal() {
        // The frame the scanner sent before the type existed, byte for byte.
        let source = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut legacy = vec![0u8; 60];
        legacy[..6].copy_from_slice(&[1, 14, 207, 0, 0, 0]);
        legacy[6..12].copy_from_slice(&source);
        legacy[12..30].copy_from_slice(&[
            0x88, 0x92, 0xfe, 0xfe, 5, 0, 0x4e, 0x53, 0, 1, 0, 0x80, 0, 4, 0xff, 0xff, 0, 0,
        ]);
        let request = DcpRequest::new(source, DcpService::IdentifyAll);
        assert_eq!(request.encode(), legacy);
        assert_eq!(request.service(), DcpService::IdentifyAll);
    }

    #[test]
    fn dcp_every_encoded_request_decodes_to_the_allow_list() {
        for byte in 0..=255u8 {
            let source = [byte, 1, 2, 3, 4, byte ^ 0x55];
            for s in DcpService::ALLOWED {
                let bytes = DcpRequest::new(source, s).encode();
                assert_eq!(bytes.len(), 60);
                assert_eq!(bytes[6..12], source);
                assert_eq!(DcpService::of_frame(&bytes), Some(s));
            }
        }
    }

    #[test]
    fn dcp_changing_any_discriminator_byte_is_rejected() {
        let frame = DcpRequest::new([2, 0, 0, 0, 0, 1], DcpService::IdentifyAll).encode();
        // Free bytes: source MAC (6..12), transaction ID (18..22), response delay (22..24).
        let free = |i: usize| (6..12).contains(&i) || (18..24).contains(&i);
        for index in 0..frame.len() {
            for value in 0..=255u8 {
                if value == frame[index] {
                    continue;
                }
                let mut changed = frame.clone();
                changed[index] = value;
                let decoded = DcpService::of_frame(&changed);
                if free(index) {
                    assert_eq!(decoded, Some(DcpService::IdentifyAll), "byte {index}");
                } else {
                    assert_eq!(decoded, None, "byte {index} -> {value:#x}");
                }
            }
        }
        // A truncated or extended frame is not a request either.
        assert_eq!(DcpService::of_frame(&frame[..59]), None);
        let mut longer = frame.clone();
        longer.push(0);
        assert_eq!(DcpService::of_frame(&longer), None);
        assert_eq!(DcpService::of_frame(&[]), None);
    }

    /// The structural half for DCP: the capture send in `passive::start` goes through
    /// [`DcpFrameTx`], not a raw `Capture::send` with hand-built bytes.
    #[test]
    fn dcp_send_in_passive_start_uses_the_typed_sender() {
        let source = include_str!("../passive.rs");
        let code = source.split("#[cfg(test)]").next().unwrap();
        let sender = code.split("pub struct Listening").nth(1).unwrap();
        assert!(
            sender.contains("DcpFrameTx::new"),
            "start must send through DcpFrameTx"
        );
        for forbidden in [
            "cap.send(",
            ".send(&frame",
            "vec![0u8; 60]",
            "pcap_sendpacket",
        ] {
            assert!(
                !sender.contains(forbidden),
                "passive.rs must not build or send raw frames ({forbidden})"
            );
        }
    }

    #[test]
    fn modbus_constructor_accepts_exactly_the_allow_list() {
        let mut accepted = vec![];
        for function in 0..=255u8 {
            for mei in 0..=255u8 {
                if let Some(f) = ModbusFunction::from_wire(function, mei) {
                    accepted.push((function, mei, f));
                }
            }
        }
        // Only function 0x2B with MEI type 0x0E; 0x2B/0x0D (CANopen) and all writes are out.
        assert_eq!(
            accepted,
            vec![(0x2b, 0x0e, ModbusFunction::ReadDeviceIdentification)]
        );
        assert_eq!(accepted.len(), ModbusFunction::ALLOWED.len());
        for f in ModbusFunction::ALLOWED {
            assert_eq!(
                ModbusFunction::from_wire(f.function_code(), f.mei_type()),
                Some(f)
            );
        }
        for write in [0x05, 0x06, 0x0f, 0x10, 0x15, 0x16, 0x17, 0x08, 0x2b] {
            assert_eq!(ModbusFunction::from_wire(write, 0x0d), None);
        }
    }

    #[test]
    fn modbus_every_encoded_request_decodes_to_the_allow_list() {
        for unit in 0..=255u8 {
            for f in ModbusFunction::ALLOWED {
                let bytes = ModbusRequest::new(unit, f).encode();
                assert_eq!(bytes.len(), 11);
                assert_eq!(bytes[6], unit);
                assert_eq!(ModbusFunction::of_frame(&bytes), Some(f));
                // flipping the function code or MEI type to anything else is rejected
                for value in 0..=255u8 {
                    for at in [7, 8] {
                        let mut mutated = bytes.clone();
                        mutated[at] = value;
                        assert_eq!(
                            ModbusFunction::of_frame(&mutated).is_some(),
                            value == bytes[at]
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn s7_constructor_accepts_exactly_the_allow_list() {
        let job: Vec<u8> = (0..=255u8)
            .filter(|c| S7Service::from_job_function(*c).is_some())
            .collect();
        assert_eq!(job, [0xf0]);
        let cotp: Vec<u8> = (0..=255u8)
            .filter(|c| S7Service::from_cotp_type(*c).is_some())
            .collect();
        assert_eq!(cotp, [0xe0]);
        let mut userdata = vec![];
        for group in 0..=255u8 {
            for sub in 0..=255u8 {
                if S7Service::from_userdata(group, sub).is_some() {
                    userdata.push((group, sub));
                }
            }
        }
        assert_eq!(userdata, [(0x44, 1)]);
        let szl: Vec<u8> = (0..=255u8)
            .filter(|c| S7Szl::from_id(*c).is_some())
            .collect();
        assert_eq!(szl, [0x11, 0x1c]);
        assert_eq!(szl.len(), S7Szl::ALLOWED.len());
        // Read Var, Write Var, request/start download, upload, PLC control, PLC stop
        for function in [0x04, 0x05, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x28, 0x29] {
            assert_eq!(S7Service::from_job_function(function), None);
        }
        assert!(S7Request::connection_request(8, 0).is_none());
        assert!(S7Request::connection_request(0, 32).is_none());
    }

    #[test]
    fn s7_every_encoded_request_decodes_to_the_allow_list() {
        for rack in 0..=7 {
            for slot in 0..=31 {
                let b = S7Request::connection_request(rack, slot).unwrap().encode();
                assert_eq!(b[18], rack * 32 + slot);
                assert_eq!(S7Service::of_frame(&b), Some(S7Service::ConnectionRequest));
            }
        }
        // out-of-range rack/slot pairs never construct
        for rack in 0..=255u8 {
            for slot in 0..=255u8 {
                assert_eq!(
                    S7Request::connection_request(rack, slot).is_some(),
                    rack <= 7 && slot <= 31
                );
            }
        }
        let setup = S7Request::setup_communication().encode();
        assert_eq!(
            S7Service::of_frame(&setup),
            Some(S7Service::SetupCommunication)
        );
        for value in 0..=255u8 {
            let mut m = setup.clone();
            m[17] = value;
            assert_eq!(S7Service::of_frame(&m).is_some(), value == 0xf0);
            let mut m = setup.clone();
            m[8] = value; // ROSCTR 7 with job parameters is not a Read SZL either
            assert_eq!(S7Service::of_frame(&m).is_some(), value == 1);
        }
        for szl in S7Szl::ALLOWED {
            for sequence in 0..=255u8 {
                let b = S7Request::read_szl(sequence, szl).encode();
                assert_eq!(b[12], sequence);
                assert_eq!(b[30], szl.id());
                assert_eq!(S7Service::of_frame(&b), Some(S7Service::ReadSzl));
            }
            let b = S7Request::read_szl(2, szl).encode();
            for value in 0..=255u8 {
                // COTP type 0xE0 is the (also allowed) connection request
                for (at, ok) in [(22, &[0x44][..]), (23, &[1]), (8, &[7]), (5, &[0xf0, 0xe0])] {
                    let mut m = b.clone();
                    m[at] = value;
                    assert_eq!(
                        S7Service::of_frame(&m).is_some(),
                        ok.contains(&value),
                        "byte {at} = {value:#x}"
                    );
                }
            }
        }
    }

    #[test]
    fn enip_constructor_accepts_exactly_the_allow_list() {
        let accepted: Vec<u16> = (0..=u16::MAX)
            .filter(|c| EnipCommand::from_code(*c).is_some())
            .collect();
        assert_eq!(accepted, [0x0063]);
        assert_eq!(accepted.len(), EnipCommand::ALLOWED.len());
        let b = EnipRequest::new(EnipCommand::ListIdentity).encode();
        assert_eq!(EnipCommand::of_frame(&b), Some(EnipCommand::ListIdentity));
        for command in 0..=u16::MAX {
            let mut m = b.clone();
            m[..2].copy_from_slice(&command.to_le_bytes());
            assert_eq!(EnipCommand::of_frame(&m).is_some(), command == 0x63);
        }
    }

    #[test]
    fn bacnet_constructor_accepts_exactly_the_allow_list() {
        let accepted: Vec<u8> = (0..=255u8)
            .filter(|c| BacnetService::from_unconfirmed_code(*c).is_some())
            .collect();
        assert_eq!(accepted, [8]);
        assert_eq!(accepted.len(), BacnetService::ALLOWED.len());
        let b = BacnetRequest::new(BacnetService::WhoIs).encode();
        assert_eq!(BacnetService::of_frame(&b), Some(BacnetService::WhoIs));
        // BVLC function (0x0B would be a broadcast), NPDU control, APDU type (0x00 and 0x0x
        // are confirmed requests, e.g. ReadProperty/WriteProperty), service choice
        for value in 0..=255u8 {
            for (at, ok) in [(1, 0x0a), (4, 1), (5, 0), (6, 0x10), (7, 8)] {
                let mut m = b.clone();
                m[at] = value;
                assert_eq!(
                    BacnetService::of_frame(&m).is_some(),
                    value == ok,
                    "byte {at} = {value:#x}"
                );
            }
        }
    }

    #[test]
    fn opcua_constructor_accepts_exactly_the_allow_list() {
        let accepted: Vec<u16> = (0..=u16::MAX)
            .filter(|id| OpcUaMessage::from_request_node(*id).is_some())
            .collect();
        assert_eq!(accepted, [422, 428, 446, 452]);
        // Hello has no request node; with the four service messages the allow-list is five.
        assert_eq!(accepted.len() + 1, OpcUaMessage::ALLOWED.len());
        for m in OpcUaMessage::ALLOWED {
            assert_eq!(
                OpcUaMessage::from_request_node(m.request_node()).is_some(),
                m != OpcUaMessage::Hello
            );
        }
    }

    fn ua_all() -> Vec<(OpcUaRequest, usize)> {
        let url = "opc.tcp://127.0.0.1:4840";
        // (request, offset of the request node ID within the message)
        vec![
            (OpcUaRequest::hello(url), 0),
            (
                OpcUaRequest::open_secure_channel(),
                12 + 4 + UA_POLICY_NONE.len() + 16,
            ),
            (OpcUaRequest::get_endpoints(42, 77, url), 24),
            (OpcUaRequest::find_servers(42, 77, url), 24),
            (OpcUaRequest::close_secure_channel(42, 77), 24),
        ]
    }

    #[test]
    fn opcua_every_encoded_request_decodes_to_the_allow_list() {
        for (request, node_at) in ua_all() {
            let bytes = request.encode_at(0x01d0_0000_0000_0000);
            assert_eq!(OpcUaMessage::of_message(&bytes), Some(request.message()));
            if node_at == 0 {
                continue;
            }
            assert_eq!(&bytes[node_at..node_at + 2], [1, 0]);
            // every possible namespace-0 node ID at the node position
            for id in 0..=u16::MAX {
                let mut m = bytes.clone();
                m[node_at + 2..node_at + 4].copy_from_slice(&id.to_le_bytes());
                // a MSG chunk may carry either discovery request, never anything else
                let expected =
                    OpcUaMessage::from_request_node(id).is_some_and(|found| {
                        match request.message() {
                            OpcUaMessage::GetEndpoints | OpcUaMessage::FindServers => {
                                matches!(
                                    found,
                                    OpcUaMessage::GetEndpoints | OpcUaMessage::FindServers
                                )
                            }
                            own => found == own,
                        }
                    });
                assert_eq!(
                    OpcUaMessage::of_message(&m).is_some(),
                    expected,
                    "node {id} in {:?}",
                    request.message()
                );
            }
            // a nonzero namespace or another NodeId encoding is rejected too
            for encoding in 0..=255u8 {
                let mut m = bytes.clone();
                m[node_at] = encoding;
                assert_eq!(OpcUaMessage::of_message(&m).is_some(), encoding == 1);
            }
        }
        // transport tag bytes: only the four known message tags are accepted
        for (request, _) in ua_all() {
            let bytes = request.encode_at(0);
            for at in 0..4 {
                for value in 0..=255u8 {
                    let mut m = bytes.clone();
                    m[at] = value;
                    assert_eq!(
                        OpcUaMessage::of_message(&m).is_some(),
                        value == bytes[at],
                        "tag byte {at} = {value:#x} in {:?}",
                        request.message()
                    );
                }
            }
        }
    }

    // The reference bytes below are the literals and builders of src/ot.rs and src/ot/opcua.rs
    // before the request types existed.
    #[test]
    fn encoded_bytes_equal_the_previous_literals() {
        for unit in 0..=255u8 {
            assert_eq!(
                ModbusRequest::new(unit, ModbusFunction::ReadDeviceIdentification).encode(),
                [0x4e, 0x53, 0, 0, 0, 5, unit, 0x2b, 0x0e, 1, 0]
            );
        }
        let mut enip = [0u8; 24];
        enip[0] = 0x63;
        enip[12..20].copy_from_slice(b"NETSCOPE");
        assert_eq!(EnipRequest::new(EnipCommand::ListIdentity).encode(), enip);
        assert_eq!(
            BacnetRequest::new(BacnetService::WhoIs).encode(),
            [0x81, 0x0a, 0, 8, 1, 0, 0x10, 8]
        );
        for rack in 0..=7u8 {
            for slot in 0..=31u8 {
                let mut cr = vec![
                    3, 0, 0, 22, 17, 0xe0, 0, 0, 0, 1, 0, 0xc1, 2, 1, 0, 0xc2, 2, 1, 0, 0xc0, 1, 10,
                ];
                cr[18] = rack * 32 + slot;
                assert_eq!(
                    S7Request::connection_request(rack, slot).unwrap().encode(),
                    cr
                );
            }
        }
        assert_eq!(
            S7Request::setup_communication().encode(),
            [
                3, 0, 0, 25, 2, 0xf0, 0x80, 0x32, 1, 0, 0, 0, 1, 0, 8, 0, 0, 0xf0, 0, 0, 1, 0, 1,
                1, 0xe0
            ]
        );
        for (seq, id) in [(2u8, 0x11u8), (3, 0x1c)] {
            let szl = S7Szl::from_id(id).unwrap();
            for seq in [seq, 0, 255] {
                assert_eq!(
                    S7Request::read_szl(seq, szl).encode(),
                    [
                        3, 0, 0, 33, 2, 0xf0, 0x80, 0x32, 7, 0, 0, 0, seq, 0, 8, 0, 8, 0, 1, 0x12,
                        4, 0x11, 0x44, 1, 0, 0xff, 9, 0, 4, 0, id, 0, 0
                    ]
                );
            }
        }
    }

    /// The pre-change OPC UA builders, verbatim apart from the injectable timestamp.
    mod legacy {
        pub fn u32le(b: &mut Vec<u8>, v: u32) {
            b.extend_from_slice(&v.to_le_bytes());
        }
        pub fn string(b: &mut Vec<u8>, v: &str) {
            u32le(b, v.len() as u32);
            b.extend_from_slice(v.as_bytes());
        }
        pub fn node(b: &mut Vec<u8>, id: u16) {
            b.extend_from_slice(&[1, 0]);
            b.extend_from_slice(&id.to_le_bytes());
        }
        pub fn request(id: u16, handle: u32, ticks: u64) -> Vec<u8> {
            let mut b = vec![];
            node(&mut b, id);
            b.extend_from_slice(&[0, 0]);
            b.extend_from_slice(&ticks.to_le_bytes());
            u32le(&mut b, handle);
            u32le(&mut b, 0);
            u32le(&mut b, u32::MAX);
            u32le(&mut b, 5000);
            b.extend_from_slice(&[0, 0, 0]);
            b
        }
        pub fn send(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
            let mut b = kind.to_vec();
            u32le(&mut b, (body.len() + 8) as u32);
            b.extend_from_slice(body);
            b
        }
    }

    #[test]
    fn opcua_bytes_equal_the_previous_builders() {
        use legacy::*;
        const POLICY: &str = "http://opcfoundation.org/UA/SecurityPolicy#None";
        let ticks = 0x01d9_8765_4321_0fedu64;
        for url in ["opc.tcp://127.0.0.1:4840", "opc.tcp://[::1]:4840", ""] {
            let mut hello = vec![];
            for v in [0, 65536, 65536, 1_048_576, 32] {
                u32le(&mut hello, v);
            }
            string(&mut hello, url);
            assert_eq!(
                OpcUaRequest::hello(url).encode_at(ticks),
                send(b"HELF", &hello)
            );
            let mut endpoints = request(428, 2, ticks);
            string(&mut endpoints, url);
            u32le(&mut endpoints, 0);
            u32le(&mut endpoints, 0);
            let mut servers = request(422, 3, ticks);
            string(&mut servers, url);
            u32le(&mut servers, 0);
            u32le(&mut servers, 0);
            for (channel, token) in [(42u32, 77u32), (0, 0), (u32::MAX, 1)] {
                // old `service()`: channel, token, sequence, request ID, then the body
                for (sequence, body, request_new) in [
                    (
                        2,
                        &endpoints,
                        OpcUaRequest::get_endpoints(channel, token, url),
                    ),
                    (3, &servers, OpcUaRequest::find_servers(channel, token, url)),
                ] {
                    let mut b = vec![];
                    for v in [channel, token, sequence, sequence] {
                        u32le(&mut b, v);
                    }
                    b.extend_from_slice(body);
                    assert_eq!(request_new.encode_at(ticks), send(b"MSGF", &b));
                }
                let mut close = vec![];
                for v in [channel, token, 4, 4] {
                    u32le(&mut close, v);
                }
                close.extend_from_slice(&request(452, 4, ticks));
                assert_eq!(
                    OpcUaRequest::close_secure_channel(channel, token).encode_at(ticks),
                    send(b"CLOF", &close)
                );
            }
        }
        let mut open = vec![];
        u32le(&mut open, 0);
        string(&mut open, POLICY);
        u32le(&mut open, u32::MAX);
        u32le(&mut open, u32::MAX);
        u32le(&mut open, 1);
        u32le(&mut open, 1);
        open.extend_from_slice(&request(446, 1, ticks));
        for v in [0, 0, 1, u32::MAX, 60000] {
            u32le(&mut open, v);
        }
        assert_eq!(
            OpcUaRequest::open_secure_channel().encode_at(ticks),
            send(b"OPNF", &open)
        );
    }

    #[test]
    fn opcua_encode_stamps_the_current_time() {
        let a = OpcUaRequest::open_secure_channel().encode();
        let b = OpcUaRequest::open_secure_channel().encode_at(0);
        assert_eq!(a.len(), b.len());
        // only the 8 timestamp bytes may differ
        let differing: Vec<usize> = (0..a.len()).filter(|i| a[*i] != b[*i]).collect();
        let stamp = 12 + 4 + UA_POLICY_NONE.len() + 16 + 6;
        assert!(differing.iter().all(|i| (stamp..stamp + 8).contains(i)));
    }

    /// The structural half of the guarantee: outside this module no OT code can write to a
    /// socket, because the sockets it holds are the wrappers above.
    #[test]
    fn only_this_module_writes_to_sockets() {
        for (name, source) in [
            ("ot.rs", include_str!("../ot.rs")),
            ("ot/opcua.rs", include_str!("opcua.rs")),
        ] {
            let code = source.split("#[cfg(test)]").next().unwrap();
            for forbidden in [
                "write_all",
                "AsyncWriteExt",
                ".write(",
                "send_to",
                "send_vectored",
                "sendpacket",
                "UdpSocket",
                "TcpStream",
                "::from_std",
                "into_split",
                "as_raw",
            ] {
                assert!(
                    !code.contains(forbidden),
                    "{name} must not use {forbidden}; send through ot::readonly"
                );
            }
        }
    }
}
