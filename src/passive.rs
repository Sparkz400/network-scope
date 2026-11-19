use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
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
    // The source MAC string is only built for frames that produce an observation (see the end);
    // an empty `mac` means "not overridden by the protocol" (ARP and DHCP carry their own).
    let mut o = Observation {
        protocol: String::new(),
        mac: String::new(),
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
                // `ip` and `mac` describe the client (yiaddr/ciaddr, chaddr). The sender of an
                // OFFER/ACK is the server: its identity is kept separately (option 54 and the IP
                // source), never confused with the client address.
                let ip_source = o.ip.filter(|v| !v.is_unspecified());
                if let Some(source) = ip_source {
                    o.fields.insert("ip_source".into(), source.to_string());
                }
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
                        54 if v.len() == 4 => {
                            o.fields.insert("server_id".into(), v4(v)?.to_string());
                        }
                        _ => {}
                    }
                }
                // OFFER (2), ACK (5) and NAK (6) are sent by a server. A per-server key survives
                // merging with other messages for the same client (ui::merge extends fields).
                if payload[0] == 2
                    && matches!(
                        o.fields.get("message_type").map(String::as_str),
                        Some("2" | "5" | "6")
                    )
                {
                    let server = o
                        .fields
                        .get("server_id")
                        .and_then(|s| s.parse::<IpAddr>().ok())
                        .filter(|v| !v.is_unspecified())
                        .or(ip_source);
                    if let Some(server) = server {
                        let kind = o.fields["message_type"].clone();
                        o.fields.insert(format!("dhcp_server.{server}"), kind);
                    }
                }
            } else {
                return None;
            }
        }
        _ => return None,
    }
    o.ip = o.ip.filter(|v| !v.is_unspecified());
    // An all-zero source is a synthesised header (raw IP capture files): no MAC is known.
    if o.mac.is_empty() && frame[6..12] != [0; 6] {
        o.mac = mac(&frame[6..12]);
    }
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
/// Consecutive capture read errors tolerated before the capture is given up.
const MAX_CONSECUTIVE_ERRORS: u32 = 20;
/// Reads frames until `stop`, the deadline, too many consecutive read errors or a closed
/// receiver. A full queue drops the observation and counts it instead of ending the capture.
fn pump(
    next: &mut dyn FnMut() -> Result<Option<Vec<u8>>, String>,
    tx: &mpsc::SyncSender<Result<Observation, String>>,
    stop: &AtomicBool,
    end: Instant,
    dcp_only: bool,
    dropped: &AtomicU64,
    pause: &dyn Fn(Duration),
) -> Result<(), String> {
    let mut errors = 0u32;
    while !stop.load(Ordering::Relaxed) && Instant::now() < end {
        match next() {
            Ok(Some(frame)) => {
                errors = 0;
                if let Some(o) = decode(&frame) {
                    if dcp_only && o.protocol != "Profinet DCP" {
                        continue;
                    }
                    match tx.try_send(Ok(o)) {
                        Ok(()) => {}
                        Err(mpsc::TrySendError::Full(_)) => {
                            dropped.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(mpsc::TrySendError::Disconnected(_)) => break,
                    }
                }
            }
            Ok(None) => {
                errors = 0;
                pause(Duration::from_millis(10));
            }
            Err(e) => {
                errors += 1;
                if errors >= MAX_CONSECUTIVE_ERRORS {
                    return Err(format!(
                        "Capture stopped after {errors} consecutive read errors: {e}"
                    ));
                }
                // Back off 10, 20, 40 ... ms (at most 1 s) and try again.
                pause(Duration::from_millis(10u64 << errors.min(7)).min(Duration::from_secs(1)));
            }
        }
    }
    Ok(())
}
pub fn start(interface: String, seconds: u64, dcp_source: Option<[u8; 6]>) -> Listening {
    let (tx, receiver) = mpsc::sync_channel(4096);
    let cancel = Arc::new(AtomicBool::new(false));
    let stop = cancel.clone();
    // Observations dropped because the consumer did not keep up (results are then partial).
    let lost = AtomicU64::new(0);
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
            pump(
                &mut || cap.next(),
                &tx,
                &stop,
                end,
                dcp_source.is_some(),
                &lost,
                &std::thread::sleep,
            )
        };
        let result = work();
        let n = lost.load(Ordering::Relaxed);
        if n > 0 {
            // Reported as a (non-fatal) error item: consumers mark the capture as partial.
            let _ = tx.send(Err(format!(
                "Capture queue full: {n} observations were dropped; results are partial"
            )));
        }
        if let Err(e) = result {
            let _ = tx.send(Err(e));
        }
    });
    Listening { receiver, cancel }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    /// A real DHCP reply frame: Ethernet + IPv4 + UDP 67->68 + BOOTP with options 53 and 54.
    /// `ip_src` is the IP header source (the server, or a relay agent).
    pub(crate) fn dhcp_reply_frame(
        message_type: u8,
        ip_src: [u8; 4],
        server_id: Option<[u8; 4]>,
        yiaddr: [u8; 4],
        client_mac: [u8; 6],
    ) -> Vec<u8> {
        let mut bootp = vec![0u8; 240];
        bootp[0] = 2; // BOOTREPLY
        bootp[1] = 1; // Ethernet
        bootp[2] = 6;
        bootp[4..8].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        bootp[16..20].copy_from_slice(&yiaddr);
        bootp[28..34].copy_from_slice(&client_mac);
        bootp[236..240].copy_from_slice(&[99, 130, 83, 99]);
        bootp.extend([53, 1, message_type]);
        if let Some(id) = server_id {
            bootp.extend([54, 4]);
            bootp.extend(id);
        }
        bootp.extend([1, 4, 255, 255, 255, 0, 51, 4, 0, 0, 0x0e, 0x10, 255]);
        let udp_len = (8 + bootp.len()) as u16;
        let mut udp = vec![0, 67, 0, 68];
        udp.extend(udp_len.to_be_bytes());
        udp.extend([0, 0]);
        udp.extend(bootp);
        let mut ip = vec![0x45, 0, 0, 0, 0, 1, 0, 0, 64, 17, 0, 0];
        ip[2..4].copy_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
        ip.extend(ip_src);
        ip.extend([255, 255, 255, 255]);
        let mut f = vec![0xff; 6];
        f.extend([0x02, 0, 0, 0, 0, ip_src[3]]);
        f.extend([8, 0]);
        f.extend(ip);
        f.extend(udp);
        f
    }
    #[test]
    fn dhcp_reply_keeps_client_and_server_apart() {
        let client = [0xaa, 0xbb, 0xcc, 0, 0, 0x42];
        let o = decode(&dhcp_reply_frame(
            2,
            [10, 0, 0, 1],
            Some([10, 0, 0, 1]),
            [10, 0, 0, 150],
            client,
        ))
        .unwrap();
        assert_eq!(o.protocol, "DHCP");
        assert_eq!(
            o.ip.unwrap().to_string(),
            "10.0.0.150",
            "the client address"
        );
        assert_eq!(o.mac, "AA:BB:CC:00:00:42", "the client hardware address");
        assert_eq!(o.fields["message_type"], "2");
        assert_eq!(o.fields["server_id"], "10.0.0.1");
        assert_eq!(o.fields["ip_source"], "10.0.0.1");
        assert_eq!(o.fields["dhcp_server.10.0.0.1"], "2");
        // Relayed ACK: the IP source is the relay; option 54 names the server.
        let o = decode(&dhcp_reply_frame(
            5,
            [10, 0, 0, 254],
            Some([10, 9, 9, 9]),
            [10, 0, 0, 150],
            client,
        ))
        .unwrap();
        assert!(o.fields.contains_key("dhcp_server.10.9.9.9"));
        assert!(!o.fields.contains_key("dhcp_server.10.0.0.254"));
        // Without option 54 the IP source is the fallback.
        let o = decode(&dhcp_reply_frame(
            5,
            [10, 0, 0, 7],
            None,
            [10, 0, 0, 150],
            client,
        ))
        .unwrap();
        assert!(o.fields.contains_key("dhcp_server.10.0.0.7"));
    }
    #[test]
    fn source_mac_is_used_only_when_the_protocol_has_none() {
        let mut b = vec![0u8; 14];
        b[6..12].copy_from_slice(&[0x00, 0x1b, 0x1b, 1, 2, 3]);
        b[12..14].copy_from_slice(&[0x88, 0xcc]);
        b.extend_from_slice(&[10, 3, b'P', b'L', b'C', 0, 0]);
        assert_eq!(decode(&b).unwrap().mac, "00:1B:1B:01:02:03");
        // Unknown ethertype: nothing decoded.
        b[12..14].copy_from_slice(&[0x12, 0x34]);
        assert!(decode(&b).is_none());
    }
    #[test]
    fn capture_errors_and_full_queue_do_not_end_the_capture() {
        let mut arp = vec![0u8; 42];
        arp[12..14].copy_from_slice(&[8, 6]);
        arp[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 2]);
        arp[28..32].copy_from_slice(&[192, 168, 1, 20]);
        // Transient errors between frames, then more frames than the queue holds.
        let mut script: Vec<Result<Option<Vec<u8>>, String>> = vec![
            Ok(Some(arp.clone())),
            Err("driver hiccup".into()),
            Err("driver hiccup".into()),
            Ok(None),
            Ok(Some(arp.clone())),
        ];
        for _ in 0..5 {
            script.push(Ok(Some(arp.clone())));
        }
        script.reverse();
        let (tx, rx) = mpsc::sync_channel(4);
        let stop = AtomicBool::new(false);
        let dropped = AtomicU64::new(0);
        let mut next = || match script.pop() {
            Some(item) => item,
            None => {
                stop.store(true, Ordering::Relaxed);
                Ok(None)
            }
        };
        let end = Instant::now() + Duration::from_secs(60);
        pump(&mut next, &tx, &stop, end, false, &dropped, &|_| {}).unwrap();
        assert_eq!(rx.try_iter().count(), 4, "the queue was filled");
        assert_eq!(dropped.load(Ordering::Relaxed), 3, "overflow is counted");
        // A persistent error does end the capture, with an explanation.
        let stop = AtomicBool::new(false);
        let mut failing = || Err::<Option<Vec<u8>>, String>("gone".into());
        let e = pump(&mut failing, &tx, &stop, end, false, &dropped, &|_| {}).unwrap_err();
        assert!(e.contains("consecutive") && e.contains("gone"), "{e}");
    }
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
