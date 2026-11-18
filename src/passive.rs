use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Observation {
    pub protocol: String,
    pub mac: String,
    pub ip: Option<IpAddr>,
    pub fields: BTreeMap<String, String>,
}
fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(i..i + 2)?.try_into().ok()?))
}
fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b)
        .trim_matches(char::from(0))
        .chars()
        .filter(|c| !c.is_control())
        .take(1024)
        .collect()
}
fn mac(b: &[u8]) -> String {
    b.iter()
        .map(|v| format!("{v:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}
fn v4(b: &[u8]) -> Option<IpAddr> {
    Some(Ipv4Addr::from(<[u8; 4]>::try_from(b).ok()?).into())
}
pub fn decode(frame: &[u8]) -> Option<Observation> {
    if frame.len() < 14 {
        return None;
    }
    let mut o = Observation {
        protocol: String::new(),
        mac: mac(&frame[6..12]),
        ip: None,
        fields: BTreeMap::new(),
    };
    let mut kind = be16(frame, 12)?;
    let mut offset = 14;
    for _ in 0..2 {
        if kind == 0x8100 || kind == 0x88a8 {
            kind = be16(frame, offset + 2)?;
            offset += 4;
        }
    }
    let b = frame.get(offset..)?;
    match kind {
        0x0806 => {
            if b.len() < 28 || be16(b, 0)? != 1 || be16(b, 2)? != 0x800 || b[4..6] != [6, 4] {
                return None;
            }
            o.protocol = "ARP".into();
            o.mac = mac(&b[8..14]);
            o.ip = v4(&b[14..18]);
            o.fields.insert("operation".into(), be16(b, 6)?.to_string());
        }
        0x88cc => {
            o.protocol = "LLDP".into();
            let mut i = 0;
            while i + 2 <= b.len() {
                let head = be16(b, i)?;
                i += 2;
                let len = (head & 511) as usize;
                let v = b.get(i..i + len)?;
                i += len;
                match head >> 9 {
                    0 => break,
                    1 | 2 if !v.is_empty() => {
                        o.fields.insert(
                            if head >> 9 == 1 { "chassis" } else { "port" }.into(),
                            if v[0] == 4 && v.len() == 7 {
                                mac(&v[1..])
                            } else {
                                text(&v[1..])
                            },
                        );
                    }
                    4 => {
                        o.fields.insert("port_description".into(), text(v));
                    }
                    5 => {
                        o.fields.insert("name".into(), text(v));
                    }
                    6 => {
                        o.fields.insert("description".into(), text(v));
                    }
                    8 if v.len() >= 6 && v[0] == 5 && v[1] == 1 => o.ip = v4(&v[2..6]),
                    _ => {}
                }
            }
        }
        0x8892 => {
            if b.len() < 12 || be16(b, 0)? != 0xfeff || b[2..4] != [5, 1] {
                return None;
            }
            o.protocol = "Profinet DCP".into();
            let end = 12 + be16(b, 10)? as usize;
            if end > b.len() {
                return None;
            }
            let mut i = 12;
            while i + 4 <= end {
                let option = (b[i], b[i + 1]);
                let len = be16(b, i + 2)? as usize;
                i += 4;
                if i + len > end {
                    return None;
                }
                let v = b.get(i..i + len)?;
                i += len + len % 2;
                if v.len() < 2 {
                    continue;
                }
                match option {
                    (1, 2) if v.len() >= 14 => {
                        o.ip = v4(&v[2..6]);
                        o.fields.insert("subnet".into(), v4(&v[6..10])?.to_string());
                        o.fields
                            .insert("gateway".into(), v4(&v[10..14])?.to_string());
                    }
                    (2, 1) => {
                        o.fields.insert("vendor".into(), text(&v[2..]));
                    }
                    (2, 2) => {
                        o.fields.insert("name".into(), text(&v[2..]));
                    }
                    (2, 3) if v.len() >= 6 => {
                        o.fields.insert("vendor_id".into(), be16(v, 2)?.to_string());
                        o.fields.insert("device_id".into(), be16(v, 4)?.to_string());
                    }
                    _ => {}
                }
            }
        }
        0x0800 | 0x86dd => {
            let udp = if kind == 0x0800 {
                if b.len() < 20 || b[0] >> 4 != 4 || b[9] != 17 || be16(b, 6)? & 0x3fff != 0 {
                    return None;
                }
                let header = (b[0] & 15) as usize * 4;
                if header < 20 {
                    return None;
                }
                o.ip = v4(&b[12..16]);
                b.get(header..be16(b, 2)? as usize)?
            } else {
                if b.len() < 40 || b[0] >> 4 != 6 || b[6] != 17 {
                    return None;
                }
                o.ip = Some(Ipv6Addr::from(<[u8; 16]>::try_from(&b[8..24]).ok()?).into());
                b.get(40..40 + be16(b, 4)? as usize)?
            };
            let src = be16(udp, 0)?;
            let dst = be16(udp, 2)?;
            let payload = udp.get(8..be16(udp, 4)? as usize)?;
            if src == 5353 || dst == 5353 || src == 137 || dst == 137 {
                o.protocol = if src == 137 || dst == 137 {
                    "NetBIOS"
                } else {
                    "mDNS"
                }
                .into();
                let records = dns(payload)?;
                if records.is_empty() {
                    return None;
                }
                o.fields.insert("records".into(), records.join("; "));
            } else if src == 1900 || dst == 1900 {
                let message = String::from_utf8_lossy(payload);
                if !(message.starts_with("NOTIFY ") || message.starts_with("HTTP/1.1 200")) {
                    return None;
                }
                o.protocol = "SSDP/UPnP".into();
                for line in message.lines().take(50) {
                    if let Some((key, value)) = line.split_once(':') {
                        let key = key.to_ascii_lowercase();
                        if ["server", "usn", "nt", "st", "location"].contains(&key.as_str()) {
                            o.fields.insert(key, text(value.trim().as_bytes()));
                        }
                    }
                }
            } else if [67, 68].contains(&src) || [67, 68].contains(&dst) {
                if payload.len() < 240
                    || payload[236..240] != [99, 130, 83, 99]
                    || payload[1..3] != [1, 6]
                {
                    return None;
                }
                o.protocol = "DHCP".into();
                o.mac = mac(&payload[28..34]);
                o.ip = v4(&payload[16..20])
                    .filter(|v| !v.is_unspecified())
                    .or_else(|| v4(&payload[12..16]).filter(|v| !v.is_unspecified()));
                let mut i = 240;
                while i < payload.len() {
                    let code = payload[i];
                    i += 1;
                    if code == 255 {
                        break;
                    }
                    if code == 0 {
                        continue;
                    }
                    let len = *payload.get(i)? as usize;
                    i += 1;
                    let v = payload.get(i..i + len)?;
                    i += len;
                    match code {
                        12 => {
                            o.fields.insert("hostname".into(), text(v));
                        }
                        60 => {
                            o.fields.insert("vendor_class".into(), text(v));
                        }
                        53 if !v.is_empty() => {
                            o.fields.insert("message_type".into(), v[0].to_string());
                        }
                        50 if v.len() == 4 => {
                            o.fields.insert("requested_ip".into(), v4(v)?.to_string());
                        }
                        _ => {}
                    }
                }
            } else {
                return None;
            }
        }
        _ => return None,
    }
    o.ip = o.ip.filter(|v| !v.is_unspecified());
    Some(o)
}
fn name(b: &[u8], pos: &mut usize) -> Option<String> {
    let mut i = *pos;
    let mut jumped = false;
    let mut parts = vec![];
    for _ in 0..64 {
        let n = *b.get(i)?;
        i += 1;
        if n == 0 {
            if !jumped {
                *pos = i;
            }
            return Some(parts.join("."));
        }
        if n & 0xc0 == 0xc0 {
            let dest = (((n & 63) as usize) << 8) | *b.get(i)? as usize;
            if !jumped {
                *pos = i + 1;
            }
            jumped = true;
            i = dest;
        } else {
            if n > 63 {
                return None;
            }
            parts.push(text(b.get(i..i + n as usize)?));
            i += n as usize;
        }
    }
    None
}
fn dns(b: &[u8]) -> Option<Vec<String>> {
    if b.len() < 12 || b[2] & 0x80 == 0 {
        return None;
    }
    let mut i = 12;
    for _ in 0..be16(b, 4)?.min(256) {
        name(b, &mut i)?;
        i += 4;
    }
    let count = (be16(b, 6)? as usize + be16(b, 8)? as usize + be16(b, 10)? as usize).min(256);
    let mut records = vec![];
    for _ in 0..count {
        let label = name(b, &mut i)?;
        let kind = be16(b, i)?;
        let len = be16(b, i + 8)? as usize;
        i += 10;
        let data = b.get(i..i + len)?;
        let value = match kind {
            1 if len == 4 => v4(data)?.to_string(),
            28 if len == 16 => Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?).to_string(),
            12 => name(b, &mut i.clone())?,
            33 if len >= 6 => format!("{}:{}", name(b, &mut (i + 6))?, be16(data, 4)?),
            16 => {
                let mut j = 0;
                let mut values = vec![];
                while j < data.len() {
                    let n = data[j] as usize;
                    j += 1;
                    values.push(text(data.get(j..j + n)?));
                    j += n;
                }
                values.join(" ")
            }
            0x20 if len >= 6 => {
                let mut values = vec![];
                for item in data.as_chunks::<6>().0 {
                    values.push(v4(&item[2..6])?.to_string());
                }
                values.join(", ")
            }
            0x21 if len >= 1 => {
                let count = data[0] as usize;
                let entries = data.get(1..1 + count * 18)?;
                entries
                    .as_chunks::<18>()
                    .0
                    .iter()
                    .map(|entry| format!("{} <{:02X}>", text(&entry[..15]).trim(), entry[15]))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
            _ => {
                i += len;
                continue;
            }
        };
        records.push(format!("{label} = {value}"));
        i += len;
    }
    Some(records)
}
pub struct Listening {
    pub receiver: mpsc::Receiver<Result<Observation, String>>,
    pub cancel: Arc<AtomicBool>,
}
impl Drop for Listening {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}
pub fn start(interface: String, seconds: u64, dcp_source: Option<[u8; 6]>) -> Listening {
    let (tx, receiver) = mpsc::sync_channel(4096);
    let cancel = Arc::new(AtomicBool::new(false));
    let stop = cancel.clone();
    std::thread::spawn(move || {
        let work = || -> Result<(), String> {
            let mut cap = crate::capture::Capture::open(&interface)?;
            if let Some(source) = dcp_source {
                // Identify All only. No Set, Reset, Signal or address assignment.
                let mut frame = vec![0u8; 60];
                frame[..6].copy_from_slice(&[1, 14, 207, 0, 0, 0]);
                frame[6..12].copy_from_slice(&source);
                frame[12..30].copy_from_slice(&[
                    0x88, 0x92, 0xfe, 0xfe, 5, 0, 0x4e, 0x53, 0, 1, 0, 0x80, 0, 4, 0xff, 0xff, 0, 0,
                ]);
                cap.send(&frame)?;
            }
            let end = Instant::now() + Duration::from_secs(seconds.clamp(1, 86400));
            while !stop.load(Ordering::Relaxed) && Instant::now() < end {
                if let Some(frame) = cap.next()? {
                    if let Some(o) = decode(&frame) {
                        if dcp_source.is_some() && o.protocol != "Profinet DCP" {
                            continue;
                        }
                        match tx.try_send(Ok(o)) {
                            Ok(()) => {}
                            Err(mpsc::TrySendError::Full(_)) => {
                                return Err(
                                    "Capture queue full; some observations were dropped".into()
                                )
                            }
                            Err(_) => break,
                        }
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            Ok(())
        };
        if let Err(e) = work() {
            let _ = tx.send(Err(e));
        }
    });
    Listening { receiver, cancel }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_packets_do_not_panic() {
        for n in 0..300 {
            let b = vec![255; n];
            assert!(decode(&b).is_none());
        }
        assert!(name(&[0xc0, 0], &mut 0).is_none());
    }
    #[test]
    fn arp_and_lldp_without_ip() {
        let mut b = vec![0u8; 42];
        b[12..14].copy_from_slice(&[8, 6]);
        b[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 2]);
        b[22..28].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        b[28..32].copy_from_slice(&[192, 168, 1, 20]);
        let o = decode(&b).unwrap();
        assert_eq!(o.ip.unwrap().to_string(), "192.168.1.20");
        assert_eq!(o.mac, "01:02:03:04:05:06");
        let mut b = vec![0u8; 14];
        b[12..14].copy_from_slice(&[0x88, 0xcc]);
        b.extend_from_slice(&[10, 3, b'P', b'L', b'C', 0, 0]);
        let o = decode(&b).unwrap();
        assert_eq!(o.fields["name"], "PLC");
        assert!(o.ip.is_none());
    }
}
