//! Explicit read-only identification requests. No write, control or program services.
mod opcua;
use crate::{
    core::Gate,
    scan::{Host, Settings},
};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};
type Fields = BTreeMap<String, String>;
fn clean(b: &[u8]) -> String {
    String::from_utf8_lossy(b)
        .trim_matches(|c: char| c == '\0' || c.is_whitespace())
        .chars()
        .filter(|c| !c.is_control())
        .take(2048)
        .collect()
}
fn be16(b: &[u8], i: usize) -> Result<u16, String> {
    Ok(u16::from_be_bytes(
        b.get(i..i + 2)
            .ok_or("Truncated response")?
            .try_into()
            .unwrap(),
    ))
}
pub async fn identify(h: &mut Host, s: &Settings, gate: &Gate) {
    for (protocol, port) in [
        ("Modbus", 502),
        ("S7", 102),
        ("OPC UA", 4840),
        ("EtherNet/IP", 44818),
        ("BACnet", 47808),
    ] {
        if port != 47808 && !h.open.contains(&port) {
            continue;
        }
        gate.wait().await;
        let task = async {
            match port {
                502 => modbus(h.ip, s.modbus_unit).await,
                102 => s7(h.ip, s.s7_rack, s.s7_slot, gate).await,
                4840 => opcua::discover(h.ip, gate).await,
                44818 => enip(h.ip).await,
                _ => bacnet(h.ip).await,
            }
        };
        match tokio::time::timeout(
            Duration::from_millis(s.port_timeout.clamp(500, 10000) as u64 * 4),
            task,
        )
        .await
        {
            Ok(Ok(fields)) => {
                h.responding = true;
                for (key, value) in fields {
                    h.identity.insert(format!("{protocol}.{key}"), value);
                }
            }
            Ok(Err(e)) => h.errors.push(format!("{protocol}: {e}")),
            Err(_) => {
                if port != 47808 {
                    h.errors
                        .push(format!("{protocol}: identification timed out"));
                }
            }
        }
    }
}
async fn modbus(ip: IpAddr, unit: u8) -> Result<Fields, String> {
    let socket = TcpStream::connect((ip, 502))
        .await
        .map_err(|e| e.to_string())?;
    modbus_stream(socket, unit).await
}
async fn modbus_stream(mut socket: TcpStream, unit: u8) -> Result<Fields, String> {
    socket
        .write_all(&[0x4e, 0x53, 0, 0, 0, 5, unit, 0x2b, 0x0e, 1, 0])
        .await
        .map_err(|e| e.to_string())?;
    let mut header = [0u8; 7];
    socket
        .read_exact(&mut header)
        .await
        .map_err(|e| e.to_string())?;
    if header[..4] != [0x4e, 0x53, 0, 0] || header[6] != unit {
        return Err("Mismatched transaction or unit".into());
    }
    let length = be16(&header, 4)? as usize;
    if !(2..=254).contains(&length) {
        return Err("Invalid Modbus length".into());
    }
    let mut body = vec![0; length - 1];
    socket
        .read_exact(&mut body)
        .await
        .map_err(|e| e.to_string())?;
    parse_modbus(&body)
}
fn parse_modbus(b: &[u8]) -> Result<Fields, String> {
    if b.len() >= 2 && b[0] == 0xab {
        return Err(format!("Device identification exception {}", b[1]));
    }
    if b.len() < 7 || b[..3] != [0x2b, 0x0e, 1] {
        return Err("Invalid device identification response".into());
    }
    let mut result = Fields::new();
    let mut i = 7;
    for _ in 0..b[6] {
        let id = *b.get(i).ok_or("Missing object ID")?;
        let len = *b.get(i + 1).ok_or("Missing object length")? as usize;
        i += 2;
        let value = b.get(i..i + len).ok_or("Truncated object")?;
        i += len;
        let key = match id {
            0 => "vendor".into(),
            1 => "product".into(),
            2 => "firmware".into(),
            _ => format!("object_{id}"),
        };
        result.insert(key, clean(value));
    }
    if b[4] != 0 {
        result.insert(
            "partial".into(),
            "Additional identification objects available".into(),
        );
    }
    Ok(result)
}
async fn enip(ip: IpAddr) -> Result<Fields, String> {
    let socket = TcpStream::connect((ip, 44818))
        .await
        .map_err(|e| e.to_string())?;
    enip_stream(socket).await
}
async fn enip_stream(mut socket: TcpStream) -> Result<Fields, String> {
    let mut request = [0u8; 24];
    request[0] = 0x63;
    request[12..20].copy_from_slice(b"NETSCOPE");
    socket
        .write_all(&request)
        .await
        .map_err(|e| e.to_string())?;
    let mut header = [0; 24];
    socket
        .read_exact(&mut header)
        .await
        .map_err(|e| e.to_string())?;
    if header[..2] != [0x63, 0] || header[8..12] != [0; 4] || header[12..20] != request[12..20] {
        return Err("Invalid List Identity header".into());
    }
    let len = u16::from_le_bytes([header[2], header[3]]) as usize;
    if !(2..=8192).contains(&len) {
        return Err("Invalid List Identity size".into());
    }
    let mut b = vec![0; len];
    socket.read_exact(&mut b).await.map_err(|e| e.to_string())?;
    parse_list_identity(&b)
}
/// Parses the data of a List Identity reply (item count first, no encapsulation header).
pub(crate) fn parse_list_identity(b: &[u8]) -> Result<Fields, String> {
    if b.len() < 2 {
        return Err("Truncated List Identity".into());
    }
    let count = u16::from_le_bytes([b[0], b[1]]);
    let mut i = 2;
    for _ in 0..count {
        let head = b.get(i..i + 4).ok_or("Truncated identity item")?;
        i += 4;
        let len = u16::from_le_bytes([head[2], head[3]]) as usize;
        let v = b.get(i..i + len).ok_or("Truncated identity")?;
        i += len;
        if head[..2] != [0x0c, 0] || v.len() < 34 {
            continue;
        }
        let word = |n| u16::from_le_bytes([v[n], v[n + 1]]).to_string();
        let mut f = Fields::new();
        f.insert("vendor_id".into(), word(18));
        if let Some(name) = crate::oui::cip_vendor(u16::from_le_bytes([v[18], v[19]])) {
            f.insert("vendor".into(), name.to_string());
        }
        f.insert("device_type".into(), word(20));
        f.insert("product_code".into(), word(22));
        f.insert("firmware".into(), format!("{}.{}", v[24], v[25]));
        f.insert(
            "serial".into(),
            u32::from_le_bytes(v[28..32].try_into().unwrap()).to_string(),
        );
        f.insert(
            "name".into(),
            clean(
                v.get(33..33 + v[32] as usize)
                    .ok_or("Truncated product name")?,
            ),
        );
        return Ok(f);
    }
    Err("No identity item returned".into())
}
async fn bacnet(ip: IpAddr) -> Result<Fields, String> {
    if !ip.is_ipv4() {
        return Err("BACnet/IP requires IPv4".into());
    }
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| e.to_string())?;
    socket
        .connect(SocketAddr::new(ip, 47808))
        .await
        .map_err(|e| e.to_string())?;
    // Unicast Who-Is. Never a subnet-wide broadcast.
    socket
        .send(&[0x81, 0x0a, 0, 8, 1, 0, 0x10, 8])
        .await
        .map_err(|e| e.to_string())?;
    let mut b = [0u8; 2048];
    let n = socket.recv(&mut b).await.map_err(|e| e.to_string())?;
    parse_bacnet(&b[..n])
}
pub(crate) fn parse_bacnet(b: &[u8]) -> Result<Fields, String> {
    if b.len() < 8
        || b[0] != 0x81
        || ![0x0a, 0x0b].contains(&b[1])
        || be16(b, 2)? as usize != b.len()
        || b[4] != 1
        || b[5] & 0xa8 != 0
    {
        return Err("Unsupported BACnet frame".into());
    }
    let mut i = 6;
    if b[5] & 4 != 0 {
        let n = *b.get(i + 2).ok_or("Truncated NPDU")? as usize;
        i += 3 + n;
    }
    if b.get(i..i + 2) != Some(&[0x10, 0][..]) {
        return Err("Not an I-Am response".into());
    }
    i += 2;
    let mut value = |tag: u8| -> Result<u32, String> {
        let t = *b.get(i).ok_or("Missing BACnet tag")?;
        i += 1;
        let n = (t & 7) as usize;
        if t >> 4 != tag || t & 8 != 0 || !(1..=4).contains(&n) {
            return Err("Unexpected BACnet tag".into());
        }
        let bytes = b.get(i..i + n).ok_or("Truncated BACnet value")?;
        i += n;
        Ok(bytes.iter().fold(0, |a, v| (a << 8) | *v as u32))
    };
    let object = value(12)?;
    if object >> 22 != 8 {
        return Err("I-Am object is not a device".into());
    }
    let max = value(2)?;
    let segmentation = value(9)?;
    let vendor = value(2)?;
    Ok(Fields::from([
        ("device_id".into(), (object & 0x3fffff).to_string()),
        ("max_apdu".into(), max.to_string()),
        ("segmentation".into(), segmentation.to_string()),
        ("vendor_id".into(), vendor.to_string()),
    ]))
}
async fn tpkt(socket: &mut TcpStream, request: &[u8]) -> Result<Vec<u8>, String> {
    socket.write_all(request).await.map_err(|e| e.to_string())?;
    let mut head = [0; 4];
    socket
        .read_exact(&mut head)
        .await
        .map_err(|e| e.to_string())?;
    let n = be16(&head, 2)? as usize;
    if head[..2] != [3, 0] || !(7..=8192).contains(&n) {
        return Err("Invalid TPKT".into());
    }
    let mut b = vec![0; n];
    b[..4].copy_from_slice(&head);
    socket
        .read_exact(&mut b[4..])
        .await
        .map_err(|e| e.to_string())?;
    Ok(b)
}
async fn s7(ip: IpAddr, rack: u8, slot: u8, gate: &Gate) -> Result<Fields, String> {
    if rack > 7 || slot > 31 {
        return Err("S7 rack must be 0–7 and slot 0–31".into());
    }
    let mut socket = TcpStream::connect((ip, 102))
        .await
        .map_err(|e| e.to_string())?;
    let mut cr = vec![
        3, 0, 0, 22, 17, 0xe0, 0, 0, 0, 1, 0, 0xc1, 2, 1, 0, 0xc2, 2, 1, 0, 0xc0, 1, 10,
    ];
    cr[18] = rack * 32 + slot;
    let response = tpkt(&mut socket, &cr).await?;
    if response.get(5) != Some(&0xd0) {
        return Err("COTP connection refused".into());
    }
    gate.wait().await;
    let response = tpkt(
        &mut socket,
        &[
            3, 0, 0, 25, 2, 0xf0, 0x80, 0x32, 1, 0, 0, 0, 1, 0, 8, 0, 0, 0xf0, 0, 0, 1, 0, 1, 1,
            0xe0,
        ],
    )
    .await?;
    if response.get(7..9) != Some(&[0x32, 3][..]) || response.get(17..19) != Some(&[0, 0][..]) {
        return Err("S7 setup rejected".into());
    }
    let mut fields = Fields::new();
    for (seq, id) in [(2u8, 0x11u8), (3, 0x1c)] {
        gate.wait().await;
        let request = [
            3, 0, 0, 33, 2, 0xf0, 0x80, 0x32, 7, 0, 0, 0, seq, 0, 8, 0, 8, 0, 1, 0x12, 4, 0x11,
            0x44, 1, 0, 0xff, 9, 0, 4, 0, id, 0, 0,
        ];
        let b = tpkt(&mut socket, &request).await?;
        if b.get(7..9) != Some(&[0x32, 7][..]) || b.get(11..13) != Some(&[0, seq][..]) {
            return Err("Invalid S7 SZL reply".into());
        }
        let plen = be16(&b, 13)? as usize;
        let dlen = be16(&b, 15)? as usize;
        let params = b.get(17..17 + plen).ok_or("Truncated S7 parameters")?;
        if params.len() < 12 || params[10..12] != [0, 0] || params[9] != 0 {
            return Err("S7 SZL denied or segmented reply unsupported".into());
        }
        let data = b
            .get(17 + plen..17 + plen + dlen)
            .ok_or("Truncated S7 data")?;
        if data.len() < 12 || data[0] != 0xff || data[1] != 9 || be16(data, 4)? != id as u16 {
            return Err("S7 SZL unavailable".into());
        }
        let len = be16(data, 8)? as usize;
        let count = be16(data, 10)? as usize;
        if len < 2 || count * len > data.len() - 12 {
            return Err("Invalid SZL record sizes".into());
        }
        for record in data[12..].chunks_exact(len).take(count) {
            let index = be16(record, 0)?;
            if id == 0x11 && len >= 28 {
                if index == 1 {
                    fields.insert("order_code".into(), clean(&record[2..22]));
                }
                if index == 7 {
                    fields.insert(
                        "firmware".into(),
                        format!("{}.{}.{}", record[25], record[26], record[27]),
                    );
                }
            } else if id == 0x1c {
                let key = match index {
                    1 => "name",
                    2 => "module",
                    4 => "copyright",
                    5 => "serial",
                    7 => "cpu_type",
                    _ => continue,
                };
                fields.insert(key.into(), clean(&record[2..]));
            }
        }
    }
    Ok(fields)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn modbus_fragmented_tcp_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 11];
            socket.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [0x4e, 0x53, 0, 0, 0, 5, 7, 0x2b, 0x0e, 1, 0]);
            for part in [
                &[0x4e, 0x53, 0][..],
                &[0, 0, 13, 7][..],
                &[0x2b, 0x0e, 1, 1, 0, 0, 1, 0, 3, b'P', b'L', b'C'][..],
            ] {
                socket.write_all(part).await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let fields = modbus_stream(TcpStream::connect(address).await.unwrap(), 7)
            .await
            .unwrap();
        assert_eq!(fields["vendor"], "PLC");
        server.await.unwrap();
    }
    #[test]
    fn device_id_and_errors() {
        let f = parse_modbus(&[
            0x2b, 0x0e, 1, 1, 0, 0, 2, 0, 3, b'A', b'B', b'C', 2, 3, b'1', b'.', b'2',
        ])
        .unwrap();
        assert_eq!(f["vendor"], "ABC");
        assert_eq!(f["firmware"], "1.2");
        assert!(parse_modbus(&[0xab, 1]).is_err());
        assert!(parse_modbus(&[0x2b, 0x0e, 1, 1, 0, 0, 1, 0, 50]).is_err());
    }
    #[test]
    fn bacnet_identity() {
        let f = parse_bacnet(&[
            0x81, 0x0a, 0, 20, 1, 0, 0x10, 0, 0xc4, 2, 0, 0, 42, 0x22, 5, 0xdc, 0x91, 3, 0x21, 15,
        ])
        .unwrap();
        assert_eq!(f["device_id"], "42");
        assert_eq!(f["vendor_id"], "15");
    }
}
