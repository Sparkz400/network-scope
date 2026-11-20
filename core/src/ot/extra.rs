//! Active identification of Omron FINS (UDP 9600), Niagara Fox (TCP 1911), MQTT (TCP 1883) and
//! KNXnet/IP (UDP 3671), and the parsers of their replies (the passive decoders use them too).
//! Requests are built only from the allow-lists in `readonly::more`; this file holds no raw
//! socket (a test in `readonly` checks that).
use super::{
    Fields, clean, no_listener,
    readonly::{
        Dnp3Function, Dnp3Request, FinsCommand, FinsRequest, FinsTcpRequest, FoxMessage,
        FoxRequest, KnxRequest, KnxService, McCommand, McRequest, MqttPacket, MqttRequest,
        OtStream, OtUdp, dnp3_crc,
    },
};
use crate::sendlog::SentLog;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tokio::io::AsyncReadExt;

/// Replies and hellos are small; anything longer is not read.
const MAX_REPLY: usize = 8192;

/// Printable ASCII only, trimmed, at most 32 characters (model names from untrusted devices).
pub(crate) fn clean_ascii(b: &[u8]) -> String {
    b.iter()
        .take_while(|c| **c != 0)
        .filter(|c| (0x20..0x7f).contains(*c))
        .map(|c| char::from(*c))
        .collect::<String>()
        .trim()
        .chars()
        .take(32)
        .collect()
}

// ---- Omron FINS ----------------------------------------------------------------------------

/// Controller Data Read response: the FINS frame (from ICF) of a reply to command 0x0501. The
/// data is the controller model (20 bytes, space or NUL padded), the controller version (20
/// bytes, here two NUL separated version strings on the captured CP1L-EL), 40 bytes for system
/// use and the area data.
pub(crate) fn parse_fins_controller_data(frame: &[u8]) -> Result<Fields, String> {
    if frame.len() < 14 || frame[0] & 0xc0 != 0xc0 || frame[1] != 0 {
        return Err("Not a FINS response".into());
    }
    if frame[10..12] != [0x05, 0x01] {
        return Err("Not a Controller Data Read response".into());
    }
    let code = u16::from_be_bytes([frame[12], frame[13]]);
    // 0x0000 normal completion; the high bits 0x80 of the first byte flag a relay error and
    // 0x40 a network relay error: neither carries data.
    if code != 0 {
        return Err(format!("FINS end code {code:#06X}"));
    }
    let data = &frame[14..];
    if data.len() < 40 {
        return Err("Truncated Controller Data Read response".into());
    }
    let mut f = Fields::new();
    let model = clean(&data[..20]);
    if model.is_empty() {
        return Err("No controller model".into());
    }
    f.insert("model".into(), model);
    let versions: Vec<String> = data[20..40]
        .split(|b| *b == 0)
        .map(clean)
        .filter(|v| !v.is_empty())
        .collect();
    if let Some(first) = versions.first() {
        f.insert("firmware".into(), first.clone());
    }
    if versions.len() > 1 {
        f.insert("versions".into(), versions.join(", "));
    }
    f.insert("node".into(), frame[7].to_string());
    Ok(f)
}

/// `Ok(None)`: nothing listens on the port.
pub(super) async fn fins(target: SocketAddr, log: &Arc<SentLog>) -> Result<Option<Fields>, String> {
    let ip = target.ip();
    if !ip.is_ipv4() {
        return Ok(None);
    }
    let local = if ip.is_loopback() {
        "127.0.0.1:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = OtUdp::connect(local, target)
        .await
        .map_err(|e| e.to_string())?
        .with_log(log.clone());
    // The sender's FINS node: the last octet of the address the datagram leaves from, the
    // usual automatic address conversion.
    let node = match socket.local_addr().map(|a| a.ip()) {
        Ok(IpAddr::V4(v4)) => v4.octets()[3].max(1),
        _ => 1,
    };
    let request = FinsRequest::new(node, FinsCommand::ControllerDataRead);
    match socket.send(&request).await {
        Ok(_) => {}
        Err(e) if no_listener(&e) => return Ok(None),
        Err(e) => return Err(e.to_string()),
    }
    let mut b = [0u8; 2048];
    match socket.recv(&mut b).await {
        Ok(n) => parse_fins_controller_data(&b[..n]).map(Some),
        Err(e) if no_listener(&e) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

// ---- Niagara Fox ---------------------------------------------------------------------------

/// The station's hello: `fox a 0 -1 fox hello`, then `key=type:value` lines up to `};;`.
pub(crate) fn parse_fox_hello(text: &[u8]) -> Result<Fields, String> {
    let text = std::str::from_utf8(&text[..text.len().min(MAX_REPLY)])
        .map_err(|_| "Fox hello is not text".to_string())?;
    let mut lines = text.lines();
    let first = lines.next().ok_or("Empty Fox message")?;
    if !(first.starts_with("fox a ") && first.ends_with(" fox hello")) {
        return Err("Not a Fox hello".into());
    }
    let mut f = Fields::new();
    for line in lines.take(60) {
        if line.starts_with("};;") {
            break;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let Some(value) = value.get(2..).filter(|_| value.get(1..2) == Some(":")) else {
            continue;
        };
        let name = match key {
            "fox.version" => "fox_version",
            "hostName" => "host_name",
            "hostAddress" => "host_address",
            "app.name" => "app_name",
            "app.version" => "app_version",
            "vm.name" => "vm_name",
            "vm.version" => "vm_version",
            "os.name" => "os_name",
            "os.version" => "os_version",
            "station.name" => "station_name",
            "hostId" => "host_id",
            "brandId" => "brand_id",
            _ => continue,
        };
        let value: String = clean(value.as_bytes()).chars().take(128).collect();
        if !value.is_empty() {
            f.insert(name.into(), value);
        }
    }
    if f.is_empty() {
        return Err("Fox hello without identity fields".into());
    }
    Ok(f)
}

pub(super) async fn fox(ip: IpAddr, log: &Arc<SentLog>) -> Result<Fields, String> {
    let mut socket = OtStream::connect((ip, 1911))
        .await
        .map_err(super::connect_error)?
        .with_log(log.clone());
    socket
        .send(&FoxRequest::new(FoxMessage::Hello))
        .await
        .map_err(|e| e.to_string())?;
    // read until the end of the message (`};;`), the size limit or the identification timeout
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while buf.len() < MAX_REPLY && !buf.windows(3).any(|w| w == b"};;") {
        let n = socket.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    parse_fox_hello(&buf)
}

// ---- MQTT ----------------------------------------------------------------------------------

/// CONNACK (MQTT 3.1.1 section 3.2): `20 02`, the session-present flag and the return code.
pub(crate) fn parse_mqtt_connack(b: &[u8]) -> Result<Fields, String> {
    if b.len() < 4 || b[0] != 0x20 || b[1] != 2 {
        return Err("Not an MQTT CONNACK".into());
    }
    let (reason, info) = match b[3] {
        0 => ("accepted", "anonymous connection accepted"),
        1 => (
            "refused: unacceptable protocol version",
            "protocol version refused",
        ),
        2 => ("refused: identifier rejected", "client id required"),
        3 => ("refused: server unavailable", "server unavailable"),
        4 => (
            "refused: bad user name or password",
            "authentication required",
        ),
        5 => ("refused: not authorized", "authentication required"),
        _ => ("refused: unknown return code", "refused"),
    };
    let mut f = Fields::new();
    f.insert("connack".into(), reason.into());
    f.insert("connack_info".into(), info.into());
    f.insert("return_code".into(), b[3].to_string());
    f.insert("session_present".into(), (b[2] & 1).to_string());
    Ok(f)
}

pub(super) async fn mqtt(ip: IpAddr, log: &Arc<SentLog>) -> Result<Fields, String> {
    let mut socket = OtStream::connect((ip, 1883))
        .await
        .map_err(super::connect_error)?
        .with_log(log.clone());
    socket
        .send(&MqttRequest::new(MqttPacket::Connect))
        .await
        .map_err(|e| e.to_string())?;
    let mut ack = [0u8; 4];
    socket
        .read_exact(&mut ack)
        .await
        .map_err(|e| e.to_string())?;
    let result = parse_mqtt_connack(&ack);
    // leave politely whatever the broker said
    let _ = socket.send(&MqttRequest::new(MqttPacket::Disconnect)).await;
    result
}

// ---- KNXnet/IP -----------------------------------------------------------------------------

/// `1.1.250`: area, line and device of a KNX individual address.
fn knx_address(a: u16) -> String {
    format!("{}.{}.{}", a >> 12, (a >> 8) & 0xf, a & 0xff)
}

/// DESCRIPTION_RESPONSE (service type 0x0204) or SEARCH_RESPONSE (0x0202): the header and the DIBs. The device information
/// DIB (type 1, 54 bytes) holds the medium, individual address, serial number, multicast address,
/// MAC address and the 30-byte friendly name; the supported service families DIB (type 2) lists
/// family and version bytes.
pub(crate) fn parse_knx_description(b: &[u8]) -> Result<Fields, String> {
    if b.len() < 6 || b[..2] != [0x06, 0x10] {
        return Err("Not a KNXnet/IP frame".into());
    }
    let (service, total) = (
        u16::from_be_bytes([b[2], b[3]]),
        usize::from(u16::from_be_bytes([b[4], b[5]])),
    );
    // DESCRIPTION_RESPONSE (0x0204) starts with the DIBs; SEARCH_RESPONSE (0x0202) has the 8-byte
    // control endpoint HPAI in front of them.
    let start = match service {
        0x0204 => 6,
        0x0202 => 14,
        _ => return Err("Not a KNXnet/IP description response".into()),
    };
    if total != b.len() || total > 512 || b.len() < start {
        return Err("Not a KNXnet/IP description response".into());
    }
    let mut f = Fields::new();
    let mut i = start;
    while i + 2 <= b.len() {
        let (len, kind) = (usize::from(b[i]), b[i + 1]);
        let dib = b
            .get(i..i + len)
            .filter(|_| len >= 2)
            .ok_or("Truncated KNX DIB")?;
        i += len;
        match kind {
            1 if len == 54 => {
                f.insert(
                    "medium".into(),
                    match dib[2] {
                        0x01 => "TP0",
                        0x02 => "TP1",
                        0x04 => "PL110",
                        0x08 => "PL132",
                        0x10 => "RF",
                        0x20 => "KNXnet/IP",
                        _ => "other",
                    }
                    .into(),
                );
                f.insert(
                    "individual_address".into(),
                    knx_address(u16::from_be_bytes([dib[4], dib[5]])),
                );
                f.insert(
                    "project_installation_id".into(),
                    format!("{:#06x}", u16::from_be_bytes([dib[6], dib[7]])),
                );
                f.insert(
                    "serial".into(),
                    dib[8..14].iter().map(|v| format!("{v:02x}")).collect(),
                );
                f.insert(
                    "multicast_address".into(),
                    std::net::Ipv4Addr::new(dib[14], dib[15], dib[16], dib[17]).to_string(),
                );
                f.insert(
                    "mac".into(),
                    dib[18..24]
                        .iter()
                        .map(|v| format!("{v:02X}"))
                        .collect::<Vec<_>>()
                        .join(":"),
                );
                let name = clean(&dib[24..54]);
                if !name.is_empty() {
                    f.insert("name".into(), name);
                }
            }
            2 => {
                let families: Vec<String> = dib[2..]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .take(16)
                    .map(|p| {
                        let name = match p[0] {
                            0x02 => "Core",
                            0x03 => "Device Management",
                            0x04 => "Tunnelling",
                            0x05 => "Routing",
                            0x06 => "Remote Logging",
                            0x07 => "Remote Configuration and Diagnosis",
                            0x08 => "Object Server",
                            _ => "family",
                        };
                        format!("{name} {}", p[1])
                    })
                    .collect();
                f.insert("services".into(), families.join(", "));
            }
            _ => {}
        }
    }
    if f.is_empty() {
        return Err("KNX description without device information".into());
    }
    Ok(f)
}

pub(super) async fn knx(target: SocketAddr, log: &Arc<SentLog>) -> Result<Option<Fields>, String> {
    let ip = target.ip();
    if !ip.is_ipv4() {
        return Ok(None);
    }
    let local = if ip.is_loopback() {
        "127.0.0.1:0"
    } else {
        "0.0.0.0:0"
    };
    // Unicast only. The multicast search (224.0.23.12) is not in the allow-list.
    let socket = OtUdp::connect(local, target)
        .await
        .map_err(|e| e.to_string())?
        .with_log(log.clone());
    match socket
        .send(&KnxRequest::new(KnxService::DescriptionRequest))
        .await
    {
        Ok(_) => {}
        Err(e) if no_listener(&e) => return Ok(None),
        Err(e) => return Err(e.to_string()),
    }
    let mut b = [0u8; 1024];
    match socket.recv(&mut b).await {
        Ok(n) => parse_knx_description(&b[..n]).map(Some),
        Err(e) if no_listener(&e) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

// ---- Omron FINS/TCP ------------------------------------------------------------------------

/// Largest FINS/TCP frame read (the Controller Data Read reply of a CP1L-EL is 122 bytes).
const MAX_FINS_TCP: usize = 2048;

/// One FINS/TCP frame: `FINS`, the length of what follows the length field, the FINS/TCP command
/// and error code (four bytes each) and the data. Returns (command, error code, data).
pub(crate) fn parse_fins_tcp_frame(b: &[u8]) -> Result<(u32, u32, &[u8]), String> {
    if b.len() < 16 || b[..4] != *b"FINS" {
        return Err("Not a FINS/TCP frame".into());
    }
    let length = u32::from_be_bytes([b[4], b[5], b[6], b[7]]) as usize;
    if !(8..=MAX_FINS_TCP).contains(&length) || b.len() < 8 + length {
        return Err("Truncated FINS/TCP frame".into());
    }
    let command = u32::from_be_bytes([b[8], b[9], b[10], b[11]]);
    let error = u32::from_be_bytes([b[12], b[13], b[14], b[15]]);
    Ok((command, error, &b[16..8 + length]))
}

/// The reply to the node address data command (FINS/TCP command 1): the node address the server
/// gave the client and the server's own node address, one byte each in four-byte fields.
pub(crate) fn parse_fins_node_address(b: &[u8]) -> Result<(u8, u8), String> {
    let (command, error, data) = parse_fins_tcp_frame(b)?;
    if error != 0 {
        return Err(format!("FINS/TCP error code {error:#010X}"));
    }
    if command != 1 || data.len() != 8 {
        return Err("Not a node address data reply".into());
    }
    let node = |i: usize| {
        (data[i..i + 3] == [0, 0, 0])
            .then_some(data[i + 3])
            .ok_or("FINS node address out of range".to_string())
    };
    Ok((node(0)?, node(4)?))
}

/// The reply to the FINS frame send command (FINS/TCP command 2): a Controller Data Read response.
pub(crate) fn parse_fins_tcp_controller_data(b: &[u8]) -> Result<Fields, String> {
    let (command, error, data) = parse_fins_tcp_frame(b)?;
    if error != 0 {
        return Err(format!("FINS/TCP error code {error:#010X}"));
    }
    if command != 2 {
        return Err("Not a FINS frame send reply".into());
    }
    parse_fins_controller_data(data)
}

/// Reads one FINS/TCP frame: the 8 bytes that give its length, then the rest.
async fn read_fins_tcp_frame(socket: &mut OtStream) -> Result<Vec<u8>, String> {
    let mut frame = vec![0u8; 8];
    socket
        .read_exact(&mut frame)
        .await
        .map_err(|e| e.to_string())?;
    if frame[..4] != *b"FINS" {
        return Err("Not a FINS/TCP frame".into());
    }
    let length = u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]) as usize;
    if !(8..=MAX_FINS_TCP).contains(&length) {
        return Err("Invalid FINS/TCP length".into());
    }
    frame.resize(8 + length, 0);
    socket
        .read_exact(&mut frame[8..])
        .await
        .map_err(|e| e.to_string())?;
    Ok(frame)
}

/// FINS over TCP: the node address exchange, then one Controller Data Read to the node the
/// server named. The connection is closed (dropped) as soon as the reply is read, so the
/// controller's limited FINS/TCP connections are not held.
pub(super) async fn fins_tcp(target: SocketAddr, log: &Arc<SentLog>) -> Result<Fields, String> {
    let mut socket = OtStream::connect(target)
        .await
        .map_err(super::connect_error)?
        .with_log(log.clone());
    socket
        .send(&FinsTcpRequest::node_address())
        .await
        .map_err(|e| e.to_string())?;
    let reply = read_fins_tcp_frame(&mut socket).await?;
    let (_client, server) = parse_fins_node_address(&reply)?;
    socket
        .send(&FinsTcpRequest::controller_data_read(server))
        .await
        .map_err(|e| e.to_string())?;
    let reply = read_fins_tcp_frame(&mut socket).await?;
    parse_fins_tcp_controller_data(&reply)
}

// ---- MELSEC MC protocol --------------------------------------------------------------------

/// The response to Read CPU Model Name in a 3E binary frame: subheader `D0 00`, network, PC,
/// module I/O (2), station, the data length (2, counts the end code and the data), the end code
/// (2) and the data: the model name (16 ASCII bytes, space padded) and the model code (2 bytes).
pub(crate) fn parse_mc_cpu_model(b: &[u8]) -> Result<Fields, String> {
    if b.len() < 11 || b[..2] != [0xd0, 0x00] {
        return Err("Not an MC protocol 3E response".into());
    }
    let length = usize::from(u16::from_le_bytes([b[7], b[8]]));
    if length < 2 || b.len() < 9 + length {
        return Err("Truncated MC protocol response".into());
    }
    let end_code = u16::from_le_bytes([b[9], b[10]]);
    if end_code != 0 {
        return Err(format!("MC protocol end code {end_code:#06X}"));
    }
    let data = &b[11..9 + length];
    if data.len() < 16 {
        return Err("Truncated CPU model name".into());
    }
    let model = clean_ascii(&data[..16]);
    if model.is_empty() {
        return Err("No CPU model name".into());
    }
    let mut f = Fields::new();
    f.insert("model".into(), model);
    if data.len() >= 18 {
        f.insert(
            "model_code".into(),
            format!("{:04X}", u16::from_le_bytes([data[16], data[17]])),
        );
    }
    f.insert("protocol".into(), "MC protocol 3E".into());
    Ok(f)
}

/// Reads the CPU model over the MC protocol, on the port the user named (`--melsec-port`).
pub(super) async fn melsec(target: SocketAddr, log: &Arc<SentLog>) -> Result<Fields, String> {
    let mut socket = OtStream::connect(target)
        .await
        .map_err(super::connect_error)?
        .with_log(log.clone());
    socket
        .send(&McRequest::new(McCommand::CpuModelRead))
        .await
        .map_err(|e| e.to_string())?;
    let mut head = [0u8; 9];
    socket
        .read_exact(&mut head)
        .await
        .map_err(|e| e.to_string())?;
    let length = usize::from(u16::from_le_bytes([head[7], head[8]]));
    if head[..2] != [0xd0, 0x00] || !(2..=512).contains(&length) {
        return Err("Not an MC protocol 3E response".into());
    }
    let mut frame = head.to_vec();
    frame.resize(9 + length, 0);
    socket
        .read_exact(&mut frame[9..])
        .await
        .map_err(|e| e.to_string())?;
    parse_mc_cpu_model(&frame)
}

// ---- DNP3 ----------------------------------------------------------------------------------

/// Largest response read (a few data link frames).
const MAX_DNP3: usize = 4096;

/// The length of the first data link frame in `b` (header, user data, block CRCs), when its header
/// is there and valid.
pub(crate) fn dnp3_frame_len(b: &[u8]) -> Option<usize> {
    if b.len() < 10 || b[..2] != [0x05, 0x64] || dnp3_crc(&b[..8]).to_le_bytes() != b[8..10] {
        return None;
    }
    let length = usize::from(b[2]);
    if length < 5 {
        return None;
    }
    let data = length - 5;
    Some(10 + data + 2 * data.div_ceil(16))
}

/// The first data link frame of an outstation's response: its CRCs are checked (a frame with a
/// wrong CRC is refused), the user data is joined from its blocks. Returns (control, destination,
/// source, user data).
fn dnp3_frame(b: &[u8]) -> Result<(u8, u16, u16, Vec<u8>), String> {
    let total = dnp3_frame_len(b).ok_or("Not a DNP3 data link frame")?;
    if b.len() < total {
        return Err("Truncated DNP3 frame".into());
    }
    let mut data = vec![];
    for block in b[10..total].chunks(18) {
        let (payload, crc) = block.split_at(block.len().saturating_sub(2));
        if block.len() < 3 || dnp3_crc(payload).to_le_bytes() != *crc {
            return Err("DNP3 data block with a wrong CRC".into());
        }
        data.extend_from_slice(payload);
    }
    Ok((
        b[3],
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        data,
    ))
}

/// The outstation's answer to Read class 0: the data link address it answers from, its internal
/// indications and how much data it sent. Only a Response (function 129) or an Unsolicited
/// Response (130) in the first frame counts; the outstation's data objects are not decoded.
pub(crate) fn parse_dnp3_response(b: &[u8]) -> Result<Fields, String> {
    let (control, _destination, source, data) = dnp3_frame(b)?;
    // from an outstation: DIR clear, PRM set
    if control & 0xc0 != 0x40 {
        return Err("Not a frame from an outstation".into());
    }
    // transport header, application control, function, IIN1, IIN2
    if data.len() < 5 || data[0] & 0x40 == 0 {
        return Err("DNP3 response without an application header".into());
    }
    if !matches!(data[2], 0x81 | 0x82) {
        return Err(format!(
            "DNP3 application function {} is not a response",
            data[2]
        ));
    }
    let mut f = Fields::new();
    f.insert("link_address".into(), source.to_string());
    let flags = crate::otpassive::dnp3::iin_flags(data[3], data[4]);
    f.insert("iin".into(), flags.join(", "));
    f.insert("iin_raw".into(), format!("{:02X}{:02X}", data[3], data[4]));
    f.insert(
        "response_bytes".into(),
        data.len().saturating_sub(5).to_string(),
    );
    Ok(f)
}

/// Reads the first response frame from the outstation at `address`: Read class 0 only. Nothing is
/// confirmed and nothing else is sent; the connection is closed after the reply.
pub(super) async fn dnp3(
    target: SocketAddr,
    address: u16,
    master: u16,
    log: &Arc<SentLog>,
) -> Result<Fields, String> {
    let request = Dnp3Request::new(address, master, Dnp3Function::ReadClass0).ok_or(
        "the DNP3 outstation address must be a unicast address different from the master's",
    )?;
    let mut socket = OtStream::connect(target)
        .await
        .map_err(super::connect_error)?
        .with_log(log.clone());
    socket.send(&request).await.map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = socket.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if dnp3_frame_len(&buf).is_some_and(|total| buf.len() >= total) || buf.len() >= MAX_DNP3 {
            break;
        }
    }
    parse_dnp3_response(&buf)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use tokio::{io::AsyncWriteExt, net::UdpSocket};

    /// The Controller Data Read reply of `omron_test.pcap` (UDP frame, 106 bytes).
    pub(crate) const FINS_REPLY: &str = "c0000200630000c800ef050100004350314c2d454c323044522d440000002020202030312e3030000000000030312e3036000000000000000000000000000000000000000000000000010000000000000000000000000000000000010003000a172a1008000000000000";

    pub(crate) fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn fins_controller_data_from_the_captured_reply() {
        let f = parse_fins_controller_data(&hex(FINS_REPLY)).unwrap();
        assert_eq!(f["model"], "CP1L-EL20DR-D");
        assert_eq!(f["firmware"], "01.00");
        assert_eq!(f["versions"], "01.00, 01.06");
        assert_eq!(
            f["node"], "200",
            "the PLC's own FINS node (SA1 of its reply)"
        );
        // every truncation fails cleanly; a request, a write response and an error code are refused
        let reply = hex(FINS_REPLY);
        for cut in 0..54 {
            assert!(parse_fins_controller_data(&reply[..cut]).is_err(), "{cut}");
        }
        let mut request = reply.clone();
        request[0] = 0x80;
        assert!(parse_fins_controller_data(&request).is_err());
        let mut other = reply.clone();
        other[11] = 2;
        assert!(parse_fins_controller_data(&other).is_err());
        let mut error = reply.clone();
        error[12..14].copy_from_slice(&[0x01, 0x01]);
        assert!(
            parse_fins_controller_data(&error)
                .unwrap_err()
                .contains("0x0101")
        );
    }

    #[test]
    fn fox_hello_fields_from_the_captured_station() {
        let hello = "fox a 0 -1 fox hello\n{\nfox.version=s:1.0\nid=i:2\nhostName=s:192.168.2.15\nhostAddress=s:192.168.2.15\napp.name=s:Station\napp.version=s:3.5.41.1\nvm.name=s:J9\nvm.version=s:2.3\nos.name=s:QNX\nos.version=s:6.3.2\nstation.name=s:Legion_HQ_V4\nlang=s:en\nhostId=s:Qnx-NPM6-0000-1490-C30C\nbrandId=s:vykon\nsysInfo=o:bog 61[<bog version=\"1.0\">\n</bog>\n]\n};;\n";
        let f = parse_fox_hello(hello.as_bytes()).unwrap();
        assert_eq!(f["app_name"], "Station");
        assert_eq!(f["os_name"], "QNX");
        assert_eq!(f["station_name"], "Legion_HQ_V4");
        assert_eq!(f["host_id"], "Qnx-NPM6-0000-1490-C30C");
        assert!(!f.contains_key("lang") && !f.contains_key("sysInfo"));
        assert!(parse_fox_hello(b"HTTP/1.1 200 OK\r\n").is_err());
        assert!(parse_fox_hello(b"fox a 0 -1 fox hello\n{\n};;\n").is_err());
        assert!(parse_fox_hello(&[0xff, 0xfe, 0xfd]).is_err());
        assert!(parse_fox_hello(b"").is_err());
        // a huge hello is bounded
        let mut big = hello.as_bytes().to_vec();
        big.extend(std::iter::repeat_n(b'x', 100_000));
        assert!(parse_fox_hello(&big).is_ok());
    }

    #[test]
    fn mqtt_connack_return_codes() {
        let f = parse_mqtt_connack(&[0x20, 2, 0, 0]).unwrap();
        assert_eq!(
            (f["connack"].as_str(), f["connack_info"].as_str()),
            ("accepted", "anonymous connection accepted")
        );
        assert_eq!(
            parse_mqtt_connack(&[0x20, 2, 1, 0]).unwrap()["session_present"],
            "1"
        );
        assert_eq!(
            parse_mqtt_connack(&[0x20, 2, 0, 5]).unwrap()["connack_info"],
            "authentication required"
        );
        assert_eq!(
            parse_mqtt_connack(&[0x20, 2, 0, 4]).unwrap()["connack_info"],
            "authentication required"
        );
        assert_eq!(
            parse_mqtt_connack(&[0x20, 2, 0, 2]).unwrap()["connack_info"],
            "client id required"
        );
        assert_eq!(
            parse_mqtt_connack(&[0x20, 2, 0, 99]).unwrap()["connack"],
            "refused: unknown return code"
        );
        for bad in [
            &[0x20u8, 2, 0][..],
            &[0x30, 2, 0, 0],
            &[0x20, 3, 0, 0, 0],
            &[],
        ] {
            assert!(parse_mqtt_connack(bad).is_err(), "{bad:?}");
        }
    }

    /// A KNXnet/IP DESCRIPTION_RESPONSE as the specification lays it out.
    pub(crate) fn knx_response() -> Vec<u8> {
        let mut dib = vec![
            54, 1, 0x02, 0, 0x11, 0xfa, 0x00, 0x01, 0x00, 0x83, 0x00, 0x11, 0x22, 0x33,
        ];
        dib.extend([224, 0, 23, 12]);
        dib.extend([0x00, 0x1b, 0x21, 0xaa, 0xbb, 0xcc]);
        let mut name = b"KNX IP Interface".to_vec();
        name.resize(30, 0);
        dib.extend(name);
        let services = [10, 2, 2, 1, 3, 1, 4, 1, 5, 1];
        let mut b = vec![6, 0x10, 2, 4, 0, 0];
        b.extend(&dib);
        b.extend(services);
        let n = b.len() as u16;
        b[4..6].copy_from_slice(&n.to_be_bytes());
        b
    }

    #[test]
    fn knx_description_response() {
        let f = parse_knx_description(&knx_response()).unwrap();
        assert_eq!(f["name"], "KNX IP Interface");
        assert_eq!(f["individual_address"], "1.1.250");
        assert_eq!(f["medium"], "TP1");
        assert_eq!(f["serial"], "008300112233");
        assert_eq!(f["mac"], "00:1B:21:AA:BB:CC");
        assert_eq!(f["multicast_address"], "224.0.23.12");
        assert_eq!(
            f["services"],
            "Core 1, Device Management 1, Tunnelling 1, Routing 1"
        );
        let b = knx_response();
        for cut in 0..b.len() {
            assert!(parse_knx_description(&b[..cut]).is_err(), "{cut}");
        }
        let mut wrong_service = b.clone();
        wrong_service[3] = 2;
        assert!(parse_knx_description(&wrong_service).is_err());
        // a DIB claiming to be longer than the frame
        let mut long = b.clone();
        long[6] = 200;
        assert!(parse_knx_description(&long).is_err());
        let mut zero = b.clone();
        zero[6] = 0;
        assert!(parse_knx_description(&zero).is_err());
    }

    #[tokio::test]
    async fn fins_over_udp_against_a_loopback_device() {
        // an ephemeral port: other tests scan 127.0.0.1 and send to the real FINS port
        let device = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = device.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut b = [0u8; 64];
            let (n, from) = device.recv_from(&mut b).await.unwrap();
            assert_eq!(
                FinsCommand::of_frame(&b[..n]),
                Some(FinsCommand::ControllerDataRead)
            );
            device.send_to(&hex(FINS_REPLY), from).await.unwrap();
        });
        let log = Arc::new(SentLog::new());
        let f = fins(address, &log).await.unwrap().unwrap();
        assert_eq!(f["model"], "CP1L-EL20DR-D");
        server.await.unwrap();
        let sent = log.snapshot();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].detail,
            "Omron FINS/UDP: Controller Data Read (command 0x0501)"
        );
    }

    /// The server's two replies of the FINS/TCP exchange in `omron_test.pcap` (packets 6 and 8).
    const FINS_TCP_NODE_REPLY: &str = "46494e53000000100000000100000000000000fb000000c8";
    fn fins_tcp_read_reply() -> Vec<u8> {
        let mut frame = hex("46494e53000000720000000200000000");
        frame.extend(hex(FINS_REPLY_TCP_BODY));
        frame
    }
    /// The FINS frame inside packet 8: the reply to the TCP request (source node 0xc8, SID 5).
    const FINS_REPLY_TCP_BODY: &str = "c0000200fbef00c80005050100004350314c2d454c323044522d440000002020202030312e3030000000000030312e3036000000000000000000000000000000000000000000000000010000000000000000000000000000000000010003000a172a1008000000000000";

    #[test]
    fn fins_tcp_replies_of_the_capture_decode_and_every_truncation_fails_cleanly() {
        let node = hex(FINS_TCP_NODE_REPLY);
        assert_eq!(parse_fins_node_address(&node), Ok((0xfb, 0xc8)));
        let read = fins_tcp_read_reply();
        assert_eq!(read.len(), 122, "packet 8 of the capture");
        let f = parse_fins_tcp_controller_data(&read).unwrap();
        assert_eq!(f["model"], "CP1L-EL20DR-D");
        assert_eq!(f["firmware"], "01.00");
        for cut in 0..node.len() {
            assert!(parse_fins_node_address(&node[..cut]).is_err(), "{cut}");
        }
        for cut in 0..read.len() {
            assert!(
                parse_fins_tcp_controller_data(&read[..cut]).is_err(),
                "{cut}"
            );
        }
        // a reply of the other kind, an error code, another magic, a node above 255, a huge length
        assert!(parse_fins_node_address(&read).is_err());
        assert!(parse_fins_tcp_controller_data(&node).is_err());
        let mut m = node.clone();
        m[15] = 3;
        assert!(
            parse_fins_node_address(&m)
                .unwrap_err()
                .contains("0x00000003")
        );
        let mut m = node.clone();
        m[0] = b'X';
        assert!(parse_fins_node_address(&m).is_err());
        let mut m = node.clone();
        m[17] = 1;
        assert!(parse_fins_node_address(&m).unwrap_err().contains("range"));
        let mut m = node.clone();
        m[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse_fins_node_address(&m).is_err());
    }

    /// FINS over TCP against a loopback device that replays the captured replies: the device sees
    /// the two captured frames and nothing else, the node it named is used, and the client closes
    /// the connection when it has the answer.
    #[tokio::test]
    async fn fins_tcp_sends_the_two_captured_frames_and_closes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut c, _) = listener.accept().await.unwrap();
            let mut first = [0u8; 20];
            c.read_exact(&mut first).await.unwrap();
            assert_eq!(
                crate::ot::readonly::FinsTcpMessage::of_frame(&first),
                Some(crate::ot::readonly::FinsTcpMessage::NodeAddress)
            );
            c.write_all(&hex(FINS_TCP_NODE_REPLY)).await.unwrap();
            let mut second = [0u8; 29];
            c.read_exact(&mut second).await.unwrap();
            assert_eq!(
                crate::ot::readonly::FinsTcpMessage::of_frame(&second),
                Some(crate::ot::readonly::FinsTcpMessage::ControllerDataRead)
            );
            assert_eq!(
                second[20], 0xc8,
                "the server node of the reply is the destination"
            );
            // the reply in two pieces
            let reply = fins_tcp_read_reply();
            c.write_all(&reply[..50]).await.unwrap();
            c.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            c.write_all(&reply[50..]).await.unwrap();
            // nothing more arrives, and the client closes
            let mut rest = [0u8; 8];
            assert_eq!(c.read(&mut rest).await.unwrap(), 0);
        });
        let log = Arc::new(SentLog::new());
        let f = fins_tcp(address, &log).await.unwrap();
        assert_eq!(f["model"], "CP1L-EL20DR-D");
        server.await.unwrap();
        let labels: Vec<String> = log.snapshot().into_iter().map(|e| e.detail).collect();
        assert_eq!(
            labels,
            [
                "Omron FINS/TCP: Controller Data Read (command 0x0501)",
                "Omron FINS/TCP: node address data (FINS/TCP command 0)"
            ]
        );
    }

    /// The first response frame of `dnp3_read_and_response.pcap` (packet 5, 292 bytes: a Response
    /// from outstation 10 to master 1 with the IIN bytes 0000), the frame the decoder was
    /// written against.
    fn dnp3_captured_response() -> Vec<u8> {
        hex(
            "0564ff4401000a005aeb53c081000001020000090202020202022d3a0202020203020000090202020202020270da02020214010000090200000000020000e30b000002000000000200000000020000004dba000200000000020000000002000000007eae02000000000200000000150100000902d3420000000002000000000200000000020069ce00000002000000000200000000020000dd5e000002000000000200000000020000004dba001e0100000902000000000200000000cd6302000000000200000000020000000002f0030000000002000000000200000000020069ce00000002000000000a0200000902020217100202020202020228010000090200000058e4000200000000020000000002000000007eae020000000002000000004e72",
        )
    }

    #[test]
    fn a_dnp3_response_of_the_capture_decodes_with_its_crcs_checked() {
        let frame = dnp3_captured_response();
        assert_eq!(frame.len(), 292, "10 + 250 + 16 block CRCs x 2");
        assert_eq!(dnp3_frame_len(&frame), Some(292));
        let f = parse_dnp3_response(&frame).unwrap();
        assert_eq!(f["link_address"], "10");
        assert_eq!(f["iin"], "", "no internal indication of interest is set");
        assert_eq!(f["iin_raw"], "0000");
        assert_eq!(f["response_bytes"], "245");
        // a flipped byte anywhere in the frame is a CRC error, never a value
        for i in 0..frame.len() {
            let mut m = frame.clone();
            m[i] ^= 0x01;
            assert!(parse_dnp3_response(&m).is_err(), "byte {i}");
        }
        // every truncation
        for cut in 0..frame.len() {
            assert!(parse_dnp3_response(&frame[..cut]).is_err(), "{cut}");
        }
        // IIN bits come out by name (device restart + need time; parameter error)
        let mut m = frame.clone();
        m[13] = 0x90;
        m[14] = 0x04;
        // the first block's CRC covers the user data: recompute it
        let crc = dnp3_crc(&m[10..26]).to_le_bytes();
        m[26..28].copy_from_slice(&crc);
        let f = parse_dnp3_response(&m).unwrap();
        assert_eq!(f["iin"], "device restart, need time, parameter error");
        assert_eq!(f["iin_raw"], "9004");
        // a request from a master is not a response
        let request = crate::ot::readonly::Dnp3Request::new(
            10,
            1,
            crate::ot::readonly::Dnp3Function::ReadClass0,
        )
        .unwrap();
        use crate::ot::readonly::ReadOnlyRequest;
        assert!(parse_dnp3_response(&request.encode()).is_err());
    }

    /// DNP3 against a loopback outstation: the frame it receives is the one allowed request, its
    /// answer is the captured response (in pieces), nothing is confirmed and the client closes.
    #[tokio::test]
    async fn dnp3_sends_read_class_0_only_and_closes_without_confirming() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut c, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 18];
            c.read_exact(&mut request).await.unwrap();
            assert_eq!(
                crate::ot::readonly::Dnp3Function::of_frame(&request),
                Some(crate::ot::readonly::Dnp3Function::ReadClass0)
            );
            assert_eq!(u16::from_le_bytes([request[4], request[5]]), 10);
            assert_eq!(u16::from_le_bytes([request[6], request[7]]), 3);
            let reply = dnp3_captured_response();
            for piece in reply.chunks(100) {
                c.write_all(piece).await.unwrap();
                c.flush().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            // no confirm, no second request: the stream just ends
            let mut rest = [0u8; 32];
            assert_eq!(c.read(&mut rest).await.unwrap(), 0);
        });
        let log = Arc::new(SentLog::new());
        let f = dnp3(address, 10, 3, &log).await.unwrap();
        assert_eq!(f["link_address"], "10");
        server.await.unwrap();
        let sent = log.snapshot();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].detail,
            "DNP3: Read class 0 data (function 0x01, object group 60 variation 1)"
        );
        // a broadcast address never leaves this function, not even a connection is made
        for broadcast in [0xffffu16, 0xfffc, 0xfff0] {
            let e = dnp3(address, broadcast, 3, &log).await.unwrap_err();
            assert!(e.contains("unicast"), "{e}");
        }
        assert!(dnp3(address, 3, 3, &log).await.is_err());
        assert_eq!(log.snapshot().len(), 1);
    }

    /// A response written from the MC protocol reference (no capture of an MC 3E exchange is
    /// among the fixtures): D000, network 0, PC 0xFF, module I/O 0x03FF, station 0, length 20 (end
    /// code 2 + model 16 + model code 2), end code 0, "Q03UDECPU" space padded, model code 0x0268.
    fn mc_response() -> Vec<u8> {
        let mut frame = vec![0xd0, 0, 0, 0xff, 0xff, 3, 0, 20, 0, 0, 0];
        frame.extend(b"Q03UDECPU       ");
        frame.extend([0x68, 0x02]);
        frame
    }

    #[test]
    fn an_mc_cpu_model_response_decodes_and_every_truncation_fails_cleanly() {
        let frame = mc_response();
        assert_eq!(frame.len(), 29);
        let f = parse_mc_cpu_model(&frame).unwrap();
        assert_eq!(f["model"], "Q03UDECPU");
        assert_eq!(f["model_code"], "0268");
        assert_eq!(f["protocol"], "MC protocol 3E");
        for cut in 0..frame.len() {
            assert!(parse_mc_cpu_model(&frame[..cut]).is_err(), "{cut}");
        }
        // an error end code (0xC059: the command is not supported), a request, an empty name
        let mut m = frame.clone();
        m[9..11].copy_from_slice(&0xc059u16.to_le_bytes());
        assert!(parse_mc_cpu_model(&m).unwrap_err().contains("0xC059"));
        let mut m = frame.clone();
        m[0] = 0x50;
        assert!(parse_mc_cpu_model(&m).is_err());
        let mut m = frame.clone();
        m[11..27].fill(b' ');
        assert!(parse_mc_cpu_model(&m).is_err());
        // control characters in a name from the network are not kept
        let mut m = frame.clone();
        m[11] = 0x1b;
        assert!(!parse_mc_cpu_model(&m).unwrap()["model"].contains('\x1b'));
    }

    #[tokio::test]
    async fn mc_sends_the_cpu_model_read_only_on_the_given_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut c, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 15];
            c.read_exact(&mut request).await.unwrap();
            assert_eq!(
                crate::ot::readonly::McCommand::of_frame(&request),
                Some(crate::ot::readonly::McCommand::CpuModelRead)
            );
            c.write_all(&mc_response()).await.unwrap();
            let mut rest = [0u8; 16];
            assert_eq!(
                c.read(&mut rest).await.unwrap(),
                0,
                "one request, then closed"
            );
        });
        let log = Arc::new(SentLog::new());
        let f = melsec(address, &log).await.unwrap();
        assert_eq!(f["model"], "Q03UDECPU");
        server.await.unwrap();
        let sent = log.snapshot();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].detail,
            "MELSEC MC 3E: Read CPU Model Name (command 0x0101, subcommand 0x0000)"
        );
    }

    #[tokio::test]
    async fn mqtt_sends_connect_and_disconnect_only() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut c, _) = listener.accept().await.unwrap();
            let mut seen = vec![];
            let mut b = [0u8; 64];
            let n = c.read(&mut b).await.unwrap();
            seen.extend_from_slice(&b[..n]);
            c.write_all(&[0x20, 2, 0, 5]).await.unwrap();
            // the DISCONNECT, then the end of the stream
            loop {
                let n = c.read(&mut b).await.unwrap();
                if n == 0 {
                    break;
                }
                seen.extend_from_slice(&b[..n]);
            }
            seen
        });
        // the sender talks to the fixed port 1883: reproduce its exchange on a free port
        let log = Arc::new(SentLog::new());
        let mut socket = OtStream::connect(("127.0.0.1", port))
            .await
            .unwrap()
            .with_log(log.clone());
        socket
            .send(&MqttRequest::new(MqttPacket::Connect))
            .await
            .unwrap();
        let mut ack = [0u8; 4];
        socket.read_exact(&mut ack).await.unwrap();
        assert_eq!(
            parse_mqtt_connack(&ack).unwrap()["connack_info"],
            "authentication required"
        );
        socket
            .send(&MqttRequest::new(MqttPacket::Disconnect))
            .await
            .unwrap();
        drop(socket);
        let seen = server.await.unwrap();
        assert_eq!(
            seen[..14],
            [
                0x10, 0x0c, 0, 4, 0x4d, 0x51, 0x54, 0x54, 4, 2, 0, 0x3c, 0, 0
            ]
        );
        assert_eq!(seen[14..], [0xe0, 0]);
        assert_eq!(log.snapshot().len(), 2);
    }
}
