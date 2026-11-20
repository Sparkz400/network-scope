//! Passive decoding of frames the capture sees anyway: ARP, IPv6 Neighbor Discovery, LLDP (with
//! LLDP-MED), CDP, Profinet DCP replies, mDNS, NetBIOS name service and browser announcements,
//! SSDP/UPnP, WS-Discovery, DHCP and DHCPv6. [`decode`] never transmits; the only
//! transmitting code in this file is the opt-in DCP Identify request in [`start`], after the
//! decoders (a test keeps everything before [`Listening`] send-free).
//!
//! Besides the raw fields, decoders attach device-type hints (`hint.<category>` and
//! `hint_weak.<category>`, see [`hints`]) that `devices::merge` scores like active evidence.
use serde::{Deserialize, Serialize};
mod browser;
mod cdp;
mod dhcpv6;
pub(crate) mod hints;
mod lldp_med;
mod ndp;
mod wsd;
use hints::Hint;
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
                    // System capabilities: supported (2 bytes) then enabled (2 bytes).
                    7 if v.len() >= 4 => lldp_capabilities(be16(v, 2)?, &mut o.fields),
                    5 => {
                        o.fields.insert("name".into(), text(v));
                    }
                    6 => {
                        o.fields.insert("description".into(), text(v));
                    }
                    8 if v.len() >= 6 && v[0] == 5 && v[1] == 1 => o.ip = v4(&v[2..6]),
                    127 if v.len() >= 4 && v[..3] == lldp_med::OUI => {
                        lldp_med::decode(v[3], &v[4..], &mut o.fields);
                    }
                    _ => {}
                }
            }
            // An LLDP-MED endpoint (a phone with a PC port) also announces the bridge capability.
            if o.fields
                .get("med_device_class")
                .is_some_and(|c| c.starts_with("endpoint"))
            {
                o.fields.remove("hint.network");
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
                    // Device role: a bit set (IO-Device, IO-Controller, IO-Multidevice, IO-Supervisor).
                    (2, 4) if v.len() >= 4 => {
                        let roles: Vec<&str> = [
                            (0x01u8, "IO-Device"),
                            (0x02, "IO-Controller"),
                            (0x04, "IO-Multidevice"),
                            (0x08, "IO-Supervisor"),
                        ]
                        .into_iter()
                        .filter(|(bit, _)| v[2] & bit != 0)
                        .map(|(_, name)| name)
                        .collect();
                        if !roles.is_empty() {
                            o.fields.insert("role".into(), roles.join(", "));
                        }
                    }
                    // Device options: the (option, suboption) pairs the device supports.
                    (2, 5) if v.len() >= 4 => {
                        let pairs: Vec<String> = v[2..]
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .take(32)
                            .map(|p| format!("{}/{}", p[0], p[1]))
                            .collect();
                        o.fields.insert("options".into(), pairs.join(", "));
                    }
                    // Device instance: high and low byte.
                    (2, 7) if v.len() >= 4 => {
                        o.fields
                            .insert("instance".into(), format!("{}.{}", v[2], v[3]));
                    }
                    // OEM device ID: the vendor and device ID of the OEM that built the product.
                    (2, 8) if v.len() >= 6 => {
                        o.fields
                            .insert("oem_vendor_id".into(), be16(v, 2)?.to_string());
                        o.fields
                            .insert("oem_device_id".into(), be16(v, 4)?.to_string());
                    }
                    _ => {}
                }
            }
        }
        // IEEE 802.3 frame (the "type" field is a length): CDP is LLC/SNAP to a fixed multicast
        // address. Other LLC traffic (STP, VTP, UDLD ...) is not decoded.
        length if length <= 1500 && frame[..6] == cdp::DEST => {
            let llc = b.get(..usize::from(length).min(b.len()))?;
            cdp::decode(llc, &mut o)?;
        }
        // ICMPv6 Neighbor Discovery: addresses and MACs of hosts and routers on the link
        0x86dd if b.len() >= 40 && b[6] == 58 => ndp::decode(b, &mut o)?,
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
                if o.protocol == "NetBIOS" && payload.get(2).is_some_and(|f| f & 0x80 == 0) {
                    // Name registration, refresh and release broadcasts: the host announces itself.
                    nbns_announcement(payload, &mut o.fields)?;
                } else {
                    let records = dns(payload)?;
                    if records.is_empty() {
                        return None;
                    }
                    o.fields.insert(
                        "records".into(),
                        records
                            .iter()
                            .map(|r| format!("{} = {}", r.label, r.value))
                            .collect::<Vec<_>>()
                            .join("; "),
                    );
                    if o.protocol == "mDNS" {
                        mdns_details(&records, o.ip, &mut o.fields);
                    }
                }
            } else if src == 138 || dst == 138 {
                browser::decode(payload, &mut o)?;
            } else if dst == 547 {
                dhcpv6::decode(payload, &mut o)?;
            } else if src == 3702 || dst == 3702 {
                wsd::decode(payload, &mut o)?;
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
                let evidence = ["server", "st", "nt", "usn"]
                    .iter()
                    .filter_map(|k| o.fields.get(*k))
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" ");
                hints::attach(
                    &mut o.fields,
                    hints::matching(&evidence, hints::SSDP, "SSDP"),
                );
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
                let mut parameter_list: &[u8] = &[];
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
                        // Client identifier: a hardware type byte and an id, usually derived
                        // from the MAC. Device identity (`identity`) uses it as one identifier.
                        61 if v.len() >= 2 => {
                            o.fields.insert(
                                "client_id".into(),
                                v.iter()
                                    .take(MAX_CLIENT_ID)
                                    .map(|b| format!("{b:02x}"))
                                    .collect::<Vec<_>>()
                                    .join(":"),
                            );
                        }
                        // Parameter request list: the order of the options a client asks for
                        // is characteristic of its DHCP client implementation.
                        55 => {
                            parameter_list = &v[..v.len().min(MAX_PARAMETER_LIST)];
                            o.fields.insert(
                                "param_request_list".into(),
                                parameter_list
                                    .iter()
                                    .map(u8::to_string)
                                    .collect::<Vec<_>>()
                                    .join(","),
                            );
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
                // Fingerprint client messages only (BOOTREQUEST): a server's reply describes the
                // server's configuration, not the client it is addressed to.
                if payload[0] == 1 {
                    let hints = hints::dhcp(
                        parameter_list,
                        o.fields.get("vendor_class").map_or("", String::as_str),
                        o.fields.get("hostname").map_or("", String::as_str),
                    );
                    if let Some(os) = hints::dhcp_os(&hints) {
                        o.fields.insert("os_hint".into(), os.into());
                    }
                    hints::attach(&mut o.fields, hints);
                }
                // OFFER (2), ACK (5) and NAK (6) are sent by a server. A per-server key survives
                // merging with other messages for the same client (observations::merge extends fields).
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
/// A decoded DNS/NetBIOS resource record: owner name, type, a printable value, and the
/// individual strings of a TXT record.
struct Rr {
    label: String,
    kind: u16,
    value: String,
    txt: Vec<String>,
}
fn dns(b: &[u8]) -> Option<Vec<Rr>> {
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
        let mut txt = vec![];
        let value = match kind {
            1 if len == 4 => v4(data)?.to_string(),
            28 if len == 16 => Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?).to_string(),
            12 => name(b, &mut i.clone())?,
            33 if len >= 6 => format!("{}:{}", name(b, &mut (i + 6))?, be16(data, 4)?),
            16 => {
                let mut j = 0;
                while j < data.len() {
                    let n = data[j] as usize;
                    j += 1;
                    txt.push(text(data.get(j..j + n)?));
                    j += n;
                }
                txt.join(" ")
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
        records.push(Rr {
            label,
            kind,
            value,
            txt,
        });
        i += len;
    }
    Some(records)
}
/// Longest DHCP parameter request list kept.
const MAX_PARAMETER_LIST: usize = 64;
/// Longest DHCP client identifier (option 61) kept, in bytes.
const MAX_CLIENT_ID: usize = 32;
/// Host name, services, model and hints of an mDNS response.
///
/// - A `<host>.local` A/AAAA record names the sender only when its address is the packet's
///   source address (a proxy or reflector may answer for other hosts).
/// - `service.<type>` fields come from the closed table in [`hints::MDNS_SERVICES`], so their
///   number is bounded however many distinct names a sender announces, and they accumulate
///   across packets (the `records` field is replaced by each later packet).
fn mdns_details(records: &[Rr], source: Option<IpAddr>, fields: &mut BTreeMap<String, String>) {
    let mut hints: Vec<Hint> = vec![];
    for r in records {
        if matches!(r.kind, 1 | 28)
            && source.is_some_and(|s| r.value.parse::<IpAddr>().is_ok_and(|a| a == s))
            && let Some(host) = r
                .label
                .strip_suffix(".local")
                .or_else(|| r.label.strip_suffix(".LOCAL"))
            && !host.is_empty()
            && !host.starts_with('_')
            && !host.contains('.')
        {
            fields
                .entry("hostname".into())
                .or_insert_with(|| host.to_string());
        }
        let (label, value) = (r.label.to_ascii_lowercase(), r.value.to_ascii_lowercase());
        for (needle, ..) in hints::MDNS_SERVICES {
            // The instance name sits in front of the type (in the PTR target or the SRV/TXT
            // owner); the bare type has nothing in front of it.
            let positions: Vec<(usize, &String)> = [(&label, &r.label), (&value, &r.value)]
                .into_iter()
                .filter_map(|(lower, original)| lower.find(needle).map(|p| (p, original)))
                .collect();
            let found = positions
                .iter()
                .find(|(p, _)| *p > 0)
                .or(positions.first())
                .copied();
            if let Some((position, original)) = found {
                let instance = original[..position].trim_end_matches('.');
                fields.insert(
                    format!("service.{needle}"),
                    if instance.is_empty() {
                        "present"
                    } else {
                        instance
                    }
                    .chars()
                    .take(80)
                    .collect(),
                );
                hints.extend(hints::matching(needle, hints::MDNS_SERVICES, "mDNS"));
            }
        }
        if r.kind == 16 && label.contains("_device-info._tcp") {
            for s in &r.txt {
                if let Some(model) = s.strip_prefix("model=").filter(|m| !m.is_empty()) {
                    fields.insert("model".into(), model.chars().take(64).collect());
                    hints.extend(hints::apple_model(model));
                }
            }
        }
    }
    hints::attach(fields, hints);
}
/// NetBIOS name service registration, refresh and release requests (RFC 1002). A host
/// announcing a unique `<00>` (workstation) or `<20>` (file server) name tells us its name; a
/// group name is its workgroup or domain.
fn nbns_announcement(b: &[u8], fields: &mut BTreeMap<String, String>) -> Option<()> {
    let opcode = (b.get(2)? >> 3) & 15;
    // 5 registration, 8 refresh, 9 multi-homed registration.
    if ![5, 8, 9].contains(&opcode) || be16(b, 4)? != 1 {
        return None;
    }
    // Question: one 32-character first-level encoded name, then type NB (0x20) and class IN.
    if *b.get(12)? != 32 || *b.get(45)? != 0 || be16(b, 46)? != 0x20 {
        return None;
    }
    let (name, suffix) = netbios_name(b.get(13..45)?)?;
    if name.is_empty() || name.starts_with('*') {
        return None;
    }
    // The additional record carries NB_FLAGS; bit 15 is the group flag.
    let group = b.get(62..64).map(|f| f[0] & 0x80 != 0);
    fields.insert(
        "operation".into(),
        match opcode {
            8 => "refresh",
            _ => "registration",
        }
        .into(),
    );
    fields.insert("netbios_suffix".into(), format!("{suffix:02X}"));
    match (group, suffix) {
        (Some(true), _) => {
            fields.insert("workgroup".into(), name);
        }
        (Some(false), 0x00 | 0x20) => {
            fields.insert("name".into(), name);
        }
        _ => {
            fields.insert("netbios_name".into(), name);
        }
    }
    // Samba on Linux and NAS devices registers names too: a weak hint only.
    hints::attach(
        fields,
        [Hint::new("windows", false, "NetBIOS name registration")],
    );
    Some(())
}
/// A first-level encoded NetBIOS name (32 characters `A`-`P`, RFC 1001 14.1): the trimmed name
/// and the suffix byte.
fn netbios_name(encoded: &[u8]) -> Option<(String, u8)> {
    let mut decoded = [0u8; 16];
    if encoded.len() != 32 {
        return None;
    }
    for (out, pair) in decoded.iter_mut().zip(encoded.as_chunks::<2>().0) {
        if !pair.iter().all(|c| (b'A'..=b'P').contains(c)) {
            return None;
        }
        *out = ((pair[0] - b'A') << 4) | (pair[1] - b'A');
    }
    Some((text(&decoded[..15]).trim().to_string(), decoded[15]))
}
/// LLDP system capabilities: the enabled bits as names, and the matching hints.
fn lldp_capabilities(enabled: u16, fields: &mut BTreeMap<String, String>) {
    const NAMES: [(u16, &str); 8] = [
        (0x01, "other"),
        (0x02, "repeater"),
        (0x04, "bridge"),
        (0x08, "wlan_ap"),
        (0x10, "router"),
        (0x20, "telephone"),
        (0x40, "docsis"),
        (0x80, "station"),
    ];
    let names: Vec<&str> = NAMES
        .iter()
        .filter(|(bit, _)| enabled & bit != 0)
        .map(|(_, n)| *n)
        .collect();
    if names.is_empty() {
        return;
    }
    fields.insert("capabilities".into(), names.join(","));
    let mut hints = vec![];
    if enabled & (0x02 | 0x04 | 0x08 | 0x10) != 0 {
        hints.push(Hint::new(
            "network",
            true,
            format!("LLDP capabilities {}", names.join(",")),
        ));
    }
    if enabled & 0x20 != 0 {
        hints.push(Hint::new("voip", true, "LLDP capability telephone"));
    }
    hints::attach(fields, hints);
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
    start_logged(
        interface,
        seconds,
        dcp_source,
        std::sync::Arc::new(crate::sendlog::SentLog::new()),
    )
}
/// [`start`], counting the DCP Identify frame (the only packet this capture can send) in `sent`.
pub fn start_logged(
    interface: String,
    seconds: u64,
    dcp_source: Option<[u8; 6]>,
    sent: std::sync::Arc<crate::sendlog::SentLog>,
) -> Listening {
    let (tx, receiver) = mpsc::sync_channel(4096);
    let cancel = Arc::new(AtomicBool::new(false));
    let stop = cancel.clone();
    // Observations dropped because the consumer did not keep up (results are then partial).
    let lost = AtomicU64::new(0);
    std::thread::spawn(move || {
        let work = || -> Result<(), String> {
            let mut cap = crate::capture::Capture::open(&interface)?;
            if let Some(source) = dcp_source {
                // Identify All only. No Set, Reset, Signal or address assignment: the frame
                // type has no such value (see `ot::readonly`).
                crate::ot::readonly::DcpFrameTx::new(&mut cap)
                    .with_log(sent)
                    .send(&crate::ot::readonly::DcpRequest::new(
                        source,
                        crate::ot::readonly::DcpService::IdentifyAll,
                    ))?;
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
    const MAC: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    /// Ethernet + IPv4 + UDP around `payload`.
    pub(crate) fn udp_frame(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        sport: u16,
        dport: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut udp = [sport.to_be_bytes(), dport.to_be_bytes()].concat();
        udp.extend(((8 + payload.len()) as u16).to_be_bytes());
        udp.extend([0, 0]);
        udp.extend(payload);
        let mut ip = vec![0x45, 0, 0, 0, 0, 1, 0, 0, 64, 17, 0, 0];
        ip[2..4].copy_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
        ip.extend(src_ip);
        ip.extend(dst_ip);
        let mut f = vec![0xff; 6];
        f.extend(MAC);
        f.extend([8, 0]);
        f.extend(ip);
        f.extend(udp);
        f
    }
    /// A DHCP client message (op 1) with the given options.
    pub(crate) fn dhcp_request_frame(options: &[(u8, &[u8])]) -> Vec<u8> {
        let mut bootp = vec![0u8; 240];
        bootp[0] = 1;
        bootp[1] = 1;
        bootp[2] = 6;
        bootp[28..34].copy_from_slice(&MAC);
        bootp[236..240].copy_from_slice(&[99, 130, 83, 99]);
        for (code, value) in options {
            bootp.extend([*code, value.len() as u8]);
            bootp.extend(*value);
        }
        bootp.push(255);
        udp_frame([0; 4], [255; 4], 68, 67, &bootp)
    }
    fn dns_name(name: &str) -> Vec<u8> {
        let mut out = vec![];
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend(label.as_bytes());
        }
        out.push(0);
        out
    }
    fn record(name: &str, kind: u16, rdata: &[u8]) -> Vec<u8> {
        let mut out = dns_name(name);
        out.extend(kind.to_be_bytes());
        out.extend([0x80, 1, 0, 0, 0x78, 0]);
        out.extend((rdata.len() as u16).to_be_bytes());
        out.extend(rdata);
        out
    }
    fn mdns_response(records: &[Vec<u8>]) -> Vec<u8> {
        let mut p = vec![0, 0, 0x84, 0, 0, 0];
        p.extend((records.len() as u16).to_be_bytes());
        p.extend([0; 4]);
        for r in records {
            p.extend(r);
        }
        p
    }
    fn txt(strings: &[&str]) -> Vec<u8> {
        strings
            .iter()
            .flat_map(|s| [vec![s.len() as u8], s.as_bytes().to_vec()].concat())
            .collect()
    }
    fn mdns_frame(src_ip: [u8; 4], records: &[Vec<u8>]) -> Vec<u8> {
        udp_frame(
            src_ip,
            [224, 0, 0, 251],
            5353,
            5353,
            &mdns_response(records),
        )
    }
    /// 802.3 + LLC/SNAP CDP frame with the given TLVs.
    pub(crate) fn cdp_frame(tlvs: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut cdp = vec![2, 180, 0, 0];
        for (kind, value) in tlvs {
            cdp.extend(kind.to_be_bytes());
            cdp.extend(((value.len() + 4) as u16).to_be_bytes());
            cdp.extend(value);
        }
        let mut llc = vec![0xaa, 0xaa, 3, 0, 0, 0x0c, 0x20, 0x00];
        llc.extend(cdp);
        let mut f = vec![1, 0, 0x0c, 0xcc, 0xcc, 0xcc];
        f.extend([0x00, 0x1b, 0x54, 1, 2, 3]);
        f.extend((llc.len() as u16).to_be_bytes());
        f.extend(llc);
        f
    }
    fn cdp_addresses(ips: &[[u8; 4]]) -> Vec<u8> {
        let mut v = (ips.len() as u32).to_be_bytes().to_vec();
        for ip in ips {
            v.extend([1, 1, 0xcc, 0, 4]);
            v.extend(ip);
        }
        v
    }
    fn only_device(o: Observation) -> crate::devices::Device {
        let mut devices = crate::devices::merge(&[], &[o]);
        assert_eq!(devices.len(), 1);
        devices.remove(0)
    }
    /// No prefix of any test frame may panic the decoder.
    fn assert_prefixes_do_not_panic(frame: &[u8]) {
        for n in 0..=frame.len() {
            let _ = decode(&frame[..n]);
        }
    }
    #[test]
    fn cdp_frame_is_decoded_into_identity_fields() {
        let frame = cdp_frame(&[
            (1, b"sw-core-1.example".to_vec()),
            (2, cdp_addresses(&[[10, 0, 0, 2]])),
            (3, b"GigabitEthernet1/0/1".to_vec()),
            (4, 0x0000_0029u32.to_be_bytes().to_vec()),
            (5, b"Cisco IOS Software\nVersion 15.2(7)E".to_vec()),
            (6, b"cisco WS-C2960X-48LPS-L".to_vec()),
            (10, 20u16.to_be_bytes().to_vec()),
            (11, vec![1]),
            (0x16, cdp_addresses(&[[10, 0, 0, 1]])),
            (0x7777, vec![1, 2, 3]),
        ]);
        let o = decode(&frame).unwrap();
        assert_eq!(o.protocol, "CDP");
        assert_eq!(o.mac, "00:1B:54:01:02:03");
        assert_eq!(
            o.ip.unwrap().to_string(),
            "10.0.0.1",
            "management address wins"
        );
        assert_eq!(o.fields["name"], "sw-core-1.example");
        assert_eq!(o.fields["port"], "GigabitEthernet1/0/1");
        assert_eq!(o.fields["platform"], "cisco WS-C2960X-48LPS-L");
        assert_eq!(o.fields["software"], "Cisco IOS Software Version 15.2(7)E");
        assert_eq!(o.fields["capabilities"], "router,switch,igmp");
        assert_eq!(o.fields["native_vlan"], "20");
        assert_eq!(o.fields["duplex"], "full");
        assert_eq!(o.fields["version"], "2");
        assert!(o.fields.contains_key("hint.network"));
        // End to end: the device record names it and calls it a network device.
        let d = only_device(o);
        assert_eq!(d.device_type, "Network device (router/switch/AP)");
        assert!(d.hostnames.contains(&"sw-core-1.example".to_string()));
        assert!(d.sources.contains(&"passive CDP".to_string()));
    }
    #[test]
    fn cdp_phone_and_address_fallback() {
        let frame = cdp_frame(&[
            (1, b"SEP001122334455".to_vec()),
            (2, cdp_addresses(&[[10, 1, 1, 9]])),
            (4, 0x0000_0090u32.to_be_bytes().to_vec()),
            (6, b"Cisco IP Phone 7945".to_vec()),
        ]);
        let o = decode(&frame).unwrap();
        assert_eq!(o.ip.unwrap().to_string(), "10.1.1.9");
        assert_eq!(o.fields["capabilities"], "host,phone");
        assert!(!o.fields.contains_key("hint.network"));
        assert_eq!(only_device(o).device_type, "VoIP phone");
    }
    #[test]
    fn cdp_rejects_other_llc_and_survives_malformed_tlvs() {
        let good = cdp_frame(&[(1, b"x".to_vec())]);
        assert!(decode(&good).is_some());
        // STP (LLC 42 42 03) to a different multicast address.
        let mut stp = vec![
            0x01, 0x80, 0xc2, 0, 0, 0, 2, 2, 2, 2, 2, 2, 0, 7, 0x42, 0x42, 3,
        ];
        stp.extend([0u8; 40]);
        assert!(decode(&stp).is_none());
        // CDP destination but another SNAP protocol id (VTP is 0x2003, DTP 0x2004).
        let mut other = good.clone();
        other[20] = 0x03;
        assert!(decode(&other).is_none());
        // An Ethernet II frame to the CDP address is not CDP.
        let mut eth2 = good.clone();
        eth2[12..14].copy_from_slice(&[0x08, 0x00]);
        assert!(decode(&eth2).is_none());
        // Bad version.
        let mut version = good.clone();
        version[22] = 9;
        assert!(decode(&version).is_none());
        // TLV with length below its header, and a length running past the frame.
        for bad in [[0u8, 1, 0, 2], [0, 1, 0xff, 0xff], [0, 1, 0, 0]] {
            let mut f = cdp_frame(&[]);
            f.extend(bad);
            let n = f.len() as u16 - 14;
            f[12..14].copy_from_slice(&n.to_be_bytes());
            let o = decode(&f).unwrap();
            assert!(!o.fields.contains_key("name"));
        }
        // An address TLV claiming a billion addresses is bounded.
        let huge = (u32::MAX).to_be_bytes().to_vec();
        let o = decode(&cdp_frame(&[(2, huge)])).unwrap();
        assert!(o.ip.is_none());
        assert_prefixes_do_not_panic(&cdp_frame(&[
            (1, b"abc".to_vec()),
            (2, cdp_addresses(&[[1, 2, 3, 4], [5, 6, 7, 8]])),
            (4, vec![0, 0, 0, 8]),
            (0x16, cdp_addresses(&[[9, 9, 9, 9]])),
        ]));
        // With a VLAN tag in front of the LLC header.
        let mut tagged = good[..12].to_vec();
        tagged.extend([0x81, 0x00, 0x00, 0x05]);
        tagged.extend(&good[12..]);
        assert_eq!(decode(&tagged).unwrap().protocol, "CDP");
    }
    #[test]
    fn lldp_capabilities_become_hints() {
        let mut f = vec![0u8; 12];
        f[6..12].copy_from_slice(&[0, 0x1b, 0x1b, 9, 9, 9]);
        f.extend([0x88, 0xcc]);
        // Chassis ID, port ID, system capabilities (supported 0x0024, enabled 0x0020).
        f.extend([2, 7, 4, 0, 0x1b, 0x1b, 9, 9, 9]);
        f.extend([4, 4, 7, b'1', b'/', b'1']);
        f.extend([14, 4, 0x00, 0x24, 0x00, 0x20]);
        f.extend([0, 0]);
        let o = decode(&f).unwrap();
        assert_eq!(o.fields["capabilities"], "telephone");
        assert_eq!(only_device(o).device_type, "VoIP phone");
        // Enabled bridge + router.
        let n = f.len();
        f[n - 4..n - 2].copy_from_slice(&[0x00, 0x14]);
        let o = decode(&f).unwrap();
        assert_eq!(o.fields["capabilities"], "bridge,router");
        assert!(o.fields.contains_key("hint.network"));
        // A host that is only a station gets no network hint.
        f[n - 4..n - 2].copy_from_slice(&[0x00, 0x80]);
        let o = decode(&f).unwrap();
        assert_eq!(o.fields["capabilities"], "station");
        assert!(o.fields.keys().all(|k| !k.starts_with("hint")));
    }
    const WSD_HELLO: &str = r#"<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof" xmlns:wprt="http://schemas.microsoft.com/windows/2006/08/wdp/print"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello</wsa:Action><wsa:MessageID>urn:uuid:0a1b2c3d-0000-0000-0000-000000000001</wsa:MessageID></soap:Header><soap:Body><wsd:Hello><wsa:EndpointReference><wsa:Address>urn:uuid:11111111-2222-3333-4444-555555555555</wsa:Address></wsa:EndpointReference><wsd:Types>wsdp:Device wprt:PrintDeviceType</wsd:Types><wsd:XAddrs>http://192.168.1.50:5357/1111 http://192.168.1.50:5358/2222</wsd:XAddrs><wsd:MetadataVersion>1</wsd:MetadataVersion></wsd:Hello></soap:Body></soap:Envelope>"#;
    fn wsd_frame(xml: &str) -> Vec<u8> {
        udp_frame(
            [192, 168, 1, 50],
            [239, 255, 255, 250],
            3702,
            3702,
            xml.as_bytes(),
        )
    }
    #[test]
    fn ws_discovery_hello_identifies_a_printer() {
        let o = decode(&wsd_frame(WSD_HELLO)).unwrap();
        assert_eq!(o.protocol, "WS-Discovery");
        assert_eq!(o.ip.unwrap().to_string(), "192.168.1.50");
        assert_eq!(o.fields["action"], "Hello");
        assert_eq!(o.fields["types"], "wsdp:Device wprt:PrintDeviceType");
        assert_eq!(
            o.fields["xaddrs"],
            "http://192.168.1.50:5357/1111 http://192.168.1.50:5358/2222"
        );
        assert_eq!(
            o.fields["endpoint"],
            "urn:uuid:11111111-2222-3333-4444-555555555555"
        );
        assert!(o.fields.contains_key("hint.printer"));
        assert_eq!(only_device(o).device_type, "Printer / MFP");
        // The prefix is arbitrary; a Windows computer is only a weak hint.
        let xml = WSD_HELLO.replace("wprt:PrintDeviceType", "pub:Computer");
        let o = decode(&wsd_frame(&xml)).unwrap();
        assert!(o.fields.contains_key("hint_weak.windows"));
        assert_eq!(only_device(o).device_type, "");
        // ProbeMatches and ResolveMatches describe the sender as well.
        for action in ["ProbeMatches", "ResolveMatches"] {
            let xml = WSD_HELLO.replace("/Hello</wsa:Action>", &format!("/{action}</wsa:Action>"));
            assert_eq!(decode(&wsd_frame(&xml)).unwrap().fields["action"], action);
        }
    }
    #[test]
    fn ws_discovery_ignores_requests_bye_dtds_and_junk() {
        // What the sender is looking for says nothing about the sender.
        for action in ["Probe", "Resolve", "Bye"] {
            let xml = WSD_HELLO.replace("/Hello</wsa:Action>", &format!("/{action}</wsa:Action>"));
            assert!(decode(&wsd_frame(&xml)).is_none(), "{action}");
        }
        // A DTD (entity expansion) is rejected outright.
        let bomb = format!(
            "<?xml version=\"1.0\"?><!DOCTYPE s [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;\">]>{}",
            WSD_HELLO.split_once("?>").unwrap().1.replace("1111", "&b;")
        );
        assert!(decode(&wsd_frame(&bomb)).is_none());
        // Not UTF-8, not XML, not a SOAP envelope, oversized.
        assert!(
            decode(&udp_frame(
                [1, 1, 1, 1],
                [2, 2, 2, 2],
                3702,
                3702,
                &[0xff, 0xfe, b'<']
            ))
            .is_none()
        );
        assert!(decode(&wsd_frame("hello")).is_none());
        assert!(decode(&wsd_frame("<a><b/></a>")).is_none());
        let big = format!("<soap:Envelope>{}</soap:Envelope>", "<a/>".repeat(10_000));
        assert!(decode(&wsd_frame(&big)).is_none());
        // Deep nesting and many nodes stay bounded.
        let deep = format!("<Envelope>{}", "<a>".repeat(5000));
        assert!(decode(&wsd_frame(&deep)).is_none());
        let wide = format!(
            "<Envelope><Header><Action>x/Hello</Action></Header>{}</Envelope>",
            "<Types>a b c d e f g h i j k l m n o p q r s t u v w</Types>".repeat(400)
        );
        let o = decode(&wsd_frame(&wide));
        assert!(o.is_none_or(|o| o.fields["types"].split(' ').count() <= 16));
        // Every prefix of a real message decodes or is rejected, never panics.
        assert_prefixes_do_not_panic(&wsd_frame(WSD_HELLO));
    }
    #[test]
    fn dhcp_client_fingerprints() {
        let windows = decode(&dhcp_request_frame(&[
            (53, &[1]),
            (12, b"DESKTOP-AB12CD3"),
            (60, b"MSFT 5.0"),
            (
                55,
                &[1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252],
            ),
        ]))
        .unwrap();
        assert_eq!(
            windows.fields["param_request_list"],
            "1,3,6,15,31,33,43,44,46,47,119,121,249,252"
        );
        assert_eq!(windows.fields["os_hint"], "Windows 10/11");
        assert!(windows.fields.contains_key("hint.windows"));
        assert_eq!(only_device(windows).device_type, "Windows computer");

        let android = decode(&dhcp_request_frame(&[
            (53, &[1]),
            (60, b"android-dhcp-13"),
            (55, &[1, 3, 6, 15, 26, 28, 51, 58, 59, 43]),
        ]))
        .unwrap();
        assert_eq!(android.fields["os_hint"], "Android");
        assert_eq!(only_device(android).device_type, "Smartphone / tablet");

        let apple = decode(&dhcp_request_frame(&[(
            55,
            &[1, 121, 3, 6, 15, 119, 252, 95, 44, 46],
        )]))
        .unwrap();
        assert_eq!(apple.fields["os_hint"], "macOS");
        assert_eq!(only_device(apple).device_type, "Apple device");

        let linux = decode(&dhcp_request_frame(&[(
            55,
            &[1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42],
        )]))
        .unwrap();
        assert_eq!(only_device(linux).device_type, "Linux/Unix host");

        let phone = decode(&dhcp_request_frame(&[(
            60,
            b"Cisco Systems, Inc. IP Phone CP-7945G",
        )]))
        .unwrap();
        assert_eq!(only_device(phone).device_type, "VoIP phone");
        let printer = decode(&dhcp_request_frame(&[
            (12, b"NPI1A2B3C"),
            (60, b"Hewlett-Packard JetDirect"),
        ]))
        .unwrap();
        assert_eq!(only_device(printer).device_type, "Printer / MFP");

        // Unknown clients get the raw list but no hint.
        let other = decode(&dhcp_request_frame(&[(55, &[1, 3, 6]), (60, b"acme")])).unwrap();
        assert_eq!(other.fields["param_request_list"], "1,3,6");
        assert!(
            other
                .fields
                .keys()
                .all(|k| !k.starts_with("hint") && k != "os_hint")
        );
        // The client identifier (option 61) is kept as hex; a one-byte value and an oversized
        // one are handled (the first is ignored, the second cut).
        let o = decode(&dhcp_request_frame(&[(
            61,
            &[1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
        )]))
        .unwrap();
        assert_eq!(o.fields["client_id"], "01:aa:bb:cc:dd:ee:ff");
        let o = decode(&dhcp_request_frame(&[(61, &[1])])).unwrap();
        assert!(!o.fields.contains_key("client_id"));
        let o = decode(&dhcp_request_frame(&[(61, &[7u8; 200])])).unwrap();
        assert_eq!(o.fields["client_id"].split(':').count(), MAX_CLIENT_ID);
        // An oversized list is cut.
        let long = vec![1u8; 250];
        let o = decode(&dhcp_request_frame(&[(55, &long)])).unwrap();
        assert_eq!(
            o.fields["param_request_list"].split(',').count(),
            MAX_PARAMETER_LIST
        );
        // A server reply is never fingerprinted as the client.
        let mut reply = dhcp_reply_frame(2, [10, 0, 0, 1], Some([10, 0, 0, 1]), [10, 0, 0, 9], MAC);
        let n = reply.len();
        reply.splice(n - 1..n - 1, [60, 8].into_iter().chain(*b"MSFT 5.0"));
        // Keep the lengths consistent after the splice.
        let ip_len = (reply.len() - 14) as u16;
        reply[16..18].copy_from_slice(&ip_len.to_be_bytes());
        let udp_len = ip_len - 20;
        reply[38..40].copy_from_slice(&udp_len.to_be_bytes());
        let o = decode(&reply).unwrap();
        assert_eq!(o.fields["vendor_class"], "MSFT 5.0");
        assert!(o.fields.keys().all(|k| !k.starts_with("hint")));
        assert_prefixes_do_not_panic(&dhcp_request_frame(&[(55, &[1, 3, 6]), (60, b"MSFT 5.0")]));
    }
    #[test]
    fn mdns_services_hostname_and_model() {
        let ip = [192, 168, 1, 50];
        let ptr = record(
            "_ipp._tcp.local",
            12,
            &dns_name("Office Laser._ipp._tcp.local"),
        );
        let a = record("xyz1.local", 1, &ip);
        let o = decode(&mdns_frame(ip, &[ptr, a])).unwrap();
        assert_eq!(o.protocol, "mDNS");
        assert_eq!(o.fields["hostname"], "xyz1");
        assert_eq!(o.fields["service._ipp._tcp"], "Office Laser");
        assert!(o.fields["records"].contains("_ipp._tcp.local = Office Laser._ipp._tcp.local"));
        let d = only_device(o);
        assert_eq!(d.device_type, "Printer / MFP");
        assert!(d.hostnames.contains(&"xyz1".to_string()));

        // An A record for another address (proxy, reflector) is not the sender's name.
        let other = record("nas.local", 1, &[192, 168, 1, 99]);
        let o = decode(&mdns_frame(ip, &[other])).unwrap();
        assert!(!o.fields.contains_key("hostname"));

        // Apple model from _device-info; a media service next to it.
        let info = record(
            "mac._device-info._tcp.local",
            16,
            &txt(&["model=MacBookPro18,3", "osxvers=23"]),
        );
        let o = decode(&mdns_frame(ip, &[info])).unwrap();
        assert_eq!(o.fields["model"], "MacBookPro18,3");
        assert_eq!(only_device(o).device_type, "Apple device");
        let cast = record("Living Room._googlecast._tcp.local", 33, &{
            let mut v = vec![0, 0, 0, 0, 0x1f, 0x49];
            v.extend(dns_name("tv.local"));
            v
        });
        let o = decode(&mdns_frame(ip, &[cast])).unwrap();
        assert!(o.fields.contains_key("service._googlecast._tcp"));
        assert_eq!(only_device(o).device_type, "Media / smart TV device");
        let hap = record("_hap._tcp.local", 12, &dns_name("Bulb._hap._tcp.local"));
        assert_eq!(
            only_device(decode(&mdns_frame(ip, &[hap])).unwrap()).device_type,
            "IoT / embedded device"
        );

        // Unknown services add no keys: the field set cannot be grown by a sender.
        let junk: Vec<Vec<u8>> = (0..50)
            .map(|i| {
                record(
                    &format!("_x{i}._tcp.local"),
                    12,
                    &dns_name(&format!("i{i}._x{i}._tcp.local")),
                )
            })
            .collect();
        let o = decode(&mdns_frame(ip, &junk)).unwrap();
        assert!(o.fields.keys().all(|k| !k.starts_with("service.")));
        // Truncations and mDNS queries.
        assert_prefixes_do_not_panic(&mdns_frame(
            ip,
            &[record(
                "_ipp._tcp.local",
                12,
                &dns_name("a._ipp._tcp.local"),
            )],
        ));
        let mut query = mdns_response(&[]);
        query[2] = 0;
        assert!(decode(&udp_frame(ip, [224, 0, 0, 251], 5353, 5353, &query)).is_none());
    }
    #[test]
    fn mdns_services_accumulate_across_packets() {
        let ip = [192, 168, 1, 60];
        let mut observations = vec![];
        for r in [
            record("_ipp._tcp.local", 12, &dns_name("P._ipp._tcp.local")),
            record(
                "_airplay._tcp.local",
                12,
                &dns_name("P._airplay._tcp.local"),
            ),
        ] {
            crate::observations::merge(&mut observations, decode(&mdns_frame(ip, &[r])).unwrap())
                .unwrap();
        }
        assert_eq!(observations.len(), 1);
        let f = &observations[0].fields;
        assert!(f.contains_key("service._ipp._tcp") && f.contains_key("service._airplay._tcp"));
        assert!(f.contains_key("hint.printer") && f.contains_key("hint.media"));
    }
    /// A first-level encoded NetBIOS name with an empty scope.
    fn encoded(name: &str, suffix: u8) -> Vec<u8> {
        let mut raw = format!("{name:<15}").into_bytes();
        raw.push(suffix);
        let mut out = vec![32];
        for b in raw {
            out.extend([b'A' + (b >> 4), b'A' + (b & 15)]);
        }
        out.push(0);
        out
    }
    /// A NetBIOS datagram (RFC 1002 4.4.1) to `destination`, holding an SMB Transaction to
    /// `mailslot` with `data`, laid out as Windows sends browser announcements.
    fn netbios_datagram(destination: &[u8], mailslot: &[u8], data: &[u8]) -> Vec<u8> {
        let mut smb = b"\xffSMB\x25".to_vec();
        smb.resize(32, 0);
        let offset = 32 + 1 + 34 + 2 + mailslot.len();
        smb.push(17);
        for word in [
            0,
            data.len(),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            offset,
            data.len(),
            offset,
        ] {
            smb.extend((word as u16).to_le_bytes());
        }
        smb.extend([3, 0, 1, 0, 1, 0, 2, 0]);
        smb.extend(((mailslot.len() + data.len()) as u16).to_le_bytes());
        smb.extend(mailslot);
        smb.extend(data);
        let mut p = vec![0x11, 0x02, 0x12, 0x34, 192, 168, 1, 80, 0, 138];
        p.extend(((68 + smb.len()) as u16).to_be_bytes());
        p.extend([0, 0]);
        p.extend(encoded("PC-1", 0x00));
        p.extend(destination);
        p.extend(smb);
        p
    }
    /// A browser announcement body (MS-BRWS 2.2.1 layout).
    fn announcement(opcode: u8, name: &str, version: [u8; 2], kind: u32, comment: &str) -> Vec<u8> {
        let mut d = vec![opcode, 1, 0x60, 0xea, 0, 0];
        let mut n = name.as_bytes().to_vec();
        n.resize(16, 0);
        d.extend(n);
        d.extend(version);
        d.extend(kind.to_le_bytes());
        d.extend([15, 1, 0x55, 0xaa]);
        d.extend(comment.as_bytes());
        d.push(0);
        d
    }
    fn browser_frame(destination: &[u8], data: &[u8]) -> Vec<u8> {
        udp_frame(
            [192, 168, 1, 80],
            [192, 168, 1, 255],
            138,
            138,
            &netbios_datagram(destination, b"\\MAILSLOT\\BROWSE\0", data),
        )
    }
    /// Frame 143 of `tests/fixtures/ics/iec104_diverse.pcap` (ITI/ICS-Security-Tools, CC-BY-4.0,
    /// see `PROVENANCE.md` there): a Local Master Announcement from a Windows XP host.
    #[test]
    fn netbios_browser_announcement_from_a_real_capture() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../tests/fixtures/ics/iec104_diverse.pcap"
        );
        let file = std::fs::File::open(path).unwrap();
        let mut reader = crate::pcapfile::Reader::new(std::io::BufReader::new(file)).unwrap();
        let mut found = vec![];
        while let Some((_, frame)) = reader.next_frame().unwrap() {
            found.extend(decode(&frame).filter(|o| o.protocol == "NetBIOS"));
        }
        assert_eq!(found.len(), 1, "{found:?}");
        let o = found.remove(0);
        assert_eq!(o.ip.unwrap().to_string(), "10.0.0.10");
        assert_eq!(o.mac, "02:00:4C:4F:4F:50");
        assert_eq!(o.fields["announcement"], "local_master");
        assert_eq!(o.fields["name"], "EVON", "the garbage after the NUL is cut");
        assert_eq!(o.fields["workgroup"], "ARBETSGRUPP");
        assert_eq!(o.fields["os_version"], "5.1");
        assert_eq!(o.fields["os_hint"], "Windows XP");
        assert_eq!(
            o.fields["server_type"],
            "workstation,server,nt,potential_browser,master_browser"
        );
        assert!(o.fields.contains_key("hint_weak.windows"));
        assert!(!o.fields.contains_key("comment"));
        let d = only_device(o);
        assert_eq!(d.hostnames, ["EVON"]);
        assert!(d.sources.contains(&"passive NetBIOS".to_string()));
    }
    #[test]
    fn netbios_browser_host_domain_and_samba() {
        let windows = announcement(1, "WS-OFFICE", [10, 0], 0x0001_1003, "Front desk");
        let o = decode(&browser_frame(&encoded("CORP", 0x1d), &windows)).unwrap();
        assert_eq!(o.protocol, "NetBIOS");
        assert_eq!(o.fields["announcement"], "host");
        assert_eq!(o.fields["name"], "WS-OFFICE");
        assert_eq!(o.fields["workgroup"], "CORP");
        assert_eq!(o.fields["comment"], "Front desk");
        assert_eq!(o.fields["os_hint"], "Windows 10/11 / Server 2016+");
        // A weak hint alone is not a device type (Samba sets the NT bits too).
        assert_eq!(only_device(o).device_type, "");
        // Samba: the Unix bit, its own announce version, no Windows hint.
        let samba = announcement(1, "NAS", [4, 9], 0x0000_9a03, "Samba 4.19");
        let o = decode(&browser_frame(&encoded("CORP", 0x1d), &samba)).unwrap();
        assert!(o.fields["server_type"].contains("unix"));
        assert!(o.fields.contains_key("hint_weak.linux"));
        assert!(!o.fields.contains_key("hint_weak.windows") && !o.fields.contains_key("os_hint"));
        // Domain announcement: the name is the workgroup, the trailing string the master browser;
        // neither is the sender's host name.
        let mut msbrowse = vec![32];
        for b in *b"\x01\x02__MSBROWSE__\x02\x01" {
            msbrowse.extend([b'A' + (b >> 4), b'A' + (b & 15)]);
        }
        msbrowse.push(0);
        let domain = announcement(0x0c, "CORP", [6, 1], 0x8000_1000, "WS-OFFICE");
        let o = decode(&browser_frame(&msbrowse, &domain)).unwrap();
        assert_eq!(o.fields["announcement"], "domain");
        assert_eq!(o.fields["workgroup"], "CORP");
        assert_eq!(o.fields["master_browser"], "WS-OFFICE");
        assert!(!o.fields.contains_key("name"));
        // Other browser opcodes, other mailslots, fragments and empty names are not decoded.
        let dest = encoded("CORP", 0x1d);
        let election = announcement(8, "WS-OFFICE", [10, 0], 1, "");
        assert!(decode(&browser_frame(&dest, &election)).is_none());
        let lanman = netbios_datagram(&dest, b"\\MAILSLOT\\LANMAN\0", &windows);
        assert!(decode(&udp_frame([1; 4], [2; 4], 138, 138, &lanman)).is_none());
        let mut fragment = netbios_datagram(&dest, b"\\MAILSLOT\\BROWSE\0", &windows);
        fragment[1] = 0x03;
        assert!(decode(&udp_frame([1; 4], [2; 4], 138, 138, &fragment)).is_none());
        let nameless = announcement(1, "", [10, 0], 1, "");
        assert!(decode(&browser_frame(&dest, &nameless)).is_none());
        // A data offset or count past the end is rejected, never read.
        let mut bad = netbios_datagram(&dest, b"\\MAILSLOT\\BROWSE\0", &windows);
        let words = 14 + 2 * 34 + 33;
        bad[words + 22] = 0xff;
        assert!(decode(&udp_frame([1; 4], [2; 4], 138, 138, &bad)).is_none());
        assert_prefixes_do_not_panic(&browser_frame(&dest, &windows));
    }
    /// An LLDP frame: chassis and port ID, then `tlvs` (type, value), then the end TLV.
    fn lldp_frame(tlvs: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut f = vec![
            0x01, 0x80, 0xc2, 0, 0, 0x0e, 0x00, 0x04, 0x13, 1, 2, 3, 0x88, 0xcc,
        ];
        f.extend([2, 7, 4, 0x00, 0x04, 0x13, 1, 2, 3]);
        f.extend([4, 4, 3, 0x00, 0x04, 0x13]);
        for (kind, value) in tlvs {
            f.extend(((u16::from(*kind) << 9) | value.len() as u16).to_be_bytes());
            f.extend(value);
        }
        f.extend([0, 0]);
        f
    }
    fn med(subtype: u8, value: &[u8]) -> (u8, Vec<u8>) {
        (127, [&[0x00, 0x12, 0xbb, subtype][..], value].concat())
    }
    /// Network policy: voice, VLAN 100 tagged, priority 5, DSCP 46.
    fn voice_policy() -> [u8; 4] {
        let p = (0x40_0000u32 | (100 << 9) | (5 << 6) | 46).to_be_bytes();
        [1, p[1], p[2], p[3]]
    }
    /// Hand-built from ANSI/TIA-1057 (no licence-clean public LLDP-MED capture was found).
    #[test]
    fn lldp_med_phone_inventory_and_policy() {
        let phone = lldp_frame(&[
            (5, b"SEP000413010203".to_vec()),
            (7, vec![0x00, 0x24, 0x00, 0x24]),
            med(1, &[0x00, 0x23, 3]),
            med(2, &voice_policy()),
            med(5, b"11"),
            med(6, b"1.2.3"),
            med(7, b"sip88xx.14-1"),
            med(8, b"FCH1234ABCD"),
            med(9, b"Acme Phones"),
            med(10, b"CP-8865"),
            med(11, b""),
            med(3, &[2, 0, 0, 0]),
            (127, vec![0x00, 0x80, 0xc2, 1, 0, 20]),
        ]);
        let o = decode(&phone).unwrap();
        assert_eq!(o.protocol, "LLDP");
        assert_eq!(
            o.fields["med_capabilities"],
            "capabilities,network_policy,inventory"
        );
        assert_eq!(
            o.fields["med_device_class"],
            "endpoint_class_3_communication"
        );
        assert_eq!(
            o.fields["med_policy.voice"],
            "vlan 100 tagged, priority 5, dscp 46"
        );
        assert_eq!(o.fields["med_hardware_revision"], "11");
        assert_eq!(o.fields["med_firmware_revision"], "1.2.3");
        assert_eq!(o.fields["med_software_revision"], "sip88xx.14-1");
        assert_eq!(o.fields["med_serial_number"], "FCH1234ABCD");
        assert_eq!(o.fields["med_manufacturer"], "Acme Phones");
        assert_eq!(o.fields["med_model"], "CP-8865");
        assert!(!o.fields.contains_key("med_asset_id"), "empty");
        assert!(o.fields.contains_key("hint.voip"));
        // The bridge bit is the phone's PC port: no network hint next to the MED endpoint class.
        assert!(!o.fields.contains_key("hint.network"));
        assert_eq!(only_device(o).device_type, "VoIP phone");
        // A switch advertising the voice VLAN: a network device, never a phone.
        let switch = lldp_frame(&[
            (7, vec![0x00, 0x04, 0x00, 0x04]),
            med(1, &[0x00, 0x03, 4]),
            med(2, &voice_policy()),
            med(2, &[2, 0x80, 0, 0]),
            med(2, &[9, 0, 0, 0]),
        ]);
        let o = decode(&switch).unwrap();
        assert_eq!(o.fields["med_device_class"], "network_connectivity");
        assert_eq!(o.fields["med_policy.voice_signaling"], "unknown");
        assert!(
            o.fields
                .keys()
                .filter(|k| k.starts_with("med_policy."))
                .count()
                == 2
        );
        assert!(!o.fields.contains_key("hint.voip"));
        assert_eq!(
            only_device(o).device_type,
            "Network device (router/switch/AP)"
        );
        // Short and unknown MED TLVs add nothing.
        let o = decode(&lldp_frame(&[
            med(1, &[0]),
            med(2, &[1, 0]),
            med(1, &[0, 1, 9]),
            med(99, b"x"),
        ]))
        .unwrap();
        assert!(
            o.fields
                .keys()
                .all(|k| !k.starts_with("med_") || k == "med_capabilities")
        );
        assert_prefixes_do_not_panic(&phone);
    }
    /// Ethernet + IPv6 + UDP 546 -> 547 around `payload`, from a link-local address.
    fn dhcpv6_frame(payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0x33, 0x33, 0, 1, 0, 2];
        f.extend(MAC);
        f.extend([0x86, 0xdd, 0x60, 0, 0, 0]);
        f.extend(((8 + payload.len()) as u16).to_be_bytes());
        f.extend([17, 1]);
        f.extend([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x22, 0xff, 0xfe, 0x33, 0x44, 0x55,
        ]);
        f.extend([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2]);
        f.extend([2, 0x22, 2, 0x23]);
        f.extend(((8 + payload.len()) as u16).to_be_bytes());
        f.extend([0, 0]);
        f.extend(payload);
        f
    }
    fn dhcpv6(kind: u8, options: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut p = vec![kind, 0xab, 0xcd, 0xef];
        for (code, value) in options {
            p.extend(code.to_be_bytes());
            p.extend((value.len() as u16).to_be_bytes());
            p.extend(value);
        }
        p
    }
    /// Hand-built from RFC 8415 and RFC 4704 (no licence-clean public DHCPv6 capture was found).
    #[test]
    fn dhcpv6_client_messages() {
        let duid_llt = [
            &[0, 1, 0, 1, 0x2c, 0x1d, 0x5e, 0x01][..],
            &[0xaa, 0xbb, 0xcc, 1, 2, 3][..],
        ]
        .concat();
        let mut vendor = 311u32.to_be_bytes().to_vec();
        vendor.extend([0, 8]);
        vendor.extend(b"MSFT 5.0");
        let mut fqdn = vec![0];
        fqdn.extend(b"\x0fDESKTOP-AB12CD3\x04corp\x07example\x00");
        let solicit = dhcpv6_frame(&dhcpv6(
            1,
            &[
                (1, duid_llt.clone()),
                (8, vec![0, 0]),
                (39, fqdn),
                (16, vendor),
                (6, vec![0, 17, 0, 23, 0, 24, 0, 39]),
            ],
        ));
        let o = decode(&solicit).unwrap();
        assert_eq!(o.protocol, "DHCPv6");
        assert_eq!(
            o.mac, "02:11:22:33:44:55",
            "the Ethernet source, not the DUID"
        );
        assert_eq!(o.ip.unwrap().to_string(), "fe80::11:22ff:fe33:4455");
        assert_eq!(o.fields["message_type"], "solicit");
        assert_eq!(
            o.fields["client_id"],
            "00:01:00:01:2c:1d:5e:01:aa:bb:cc:01:02:03"
        );
        assert_eq!(o.fields["duid_type"], "LLT");
        assert_eq!(o.fields["duid_mac"], "AA:BB:CC:01:02:03");
        assert_eq!(o.fields["hostname"], "DESKTOP-AB12CD3");
        assert_eq!(o.fields["fqdn"], "DESKTOP-AB12CD3.corp.example");
        assert_eq!(o.fields["vendor_enterprise"], "311");
        assert_eq!(o.fields["vendor_class"], "MSFT 5.0");
        assert_eq!(o.fields["oro"], "17,23,24,39");
        assert_eq!(o.fields["os_hint"], "Windows");
        let d = only_device(o);
        assert_eq!(d.device_type, "Windows computer");
        assert!(d.hostnames.contains(&"DESKTOP-AB12CD3".to_string()));
        // DUID-LL, DUID-EN, a partial FQDN (no final zero) and an Information-request.
        let o = decode(&dhcpv6_frame(&dhcpv6(
            11,
            &[
                (1, vec![0, 3, 0, 1, 1, 2, 3, 4, 5, 6]),
                (39, b"\x01\x05host1".to_vec()),
            ],
        )))
        .unwrap();
        assert_eq!(o.fields["message_type"], "information_request");
        assert_eq!(o.fields["duid_type"], "LL");
        assert_eq!(o.fields["duid_mac"], "01:02:03:04:05:06");
        assert_eq!(o.fields["fqdn"], "host1");
        let o = decode(&dhcpv6_frame(&dhcpv6(
            5,
            &[(1, vec![0, 2, 0, 0, 0, 9, 1, 2])],
        )))
        .unwrap();
        assert_eq!(o.fields["duid_type"], "EN");
        assert_eq!(o.fields["duid_enterprise"], "9");
        assert!(!o.fields.contains_key("duid_mac"));
        // Server and relay messages are not the client's: Advertise, Reply, Relay-forward.
        for kind in [2, 7, 12, 13] {
            assert!(decode(&dhcpv6_frame(&dhcpv6(kind, &[(1, duid_llt.clone())]))).is_none());
        }
        // An option running past the end keeps what came before it.
        let mut cut = dhcpv6(3, &[(1, duid_llt.clone())]);
        cut.extend([0, 39, 0, 50, 0]);
        let o = decode(&dhcpv6_frame(&cut)).unwrap();
        assert_eq!(o.fields["duid_type"], "LLT");
        assert!(!o.fields.contains_key("fqdn"));
        assert_prefixes_do_not_panic(&solicit);
    }
    #[test]
    fn netbios_name_registration() {
        fn registration(name: &str, suffix: u8, flags: u8) -> Vec<u8> {
            let mut p = vec![0x12, 0x34, 0x29, 0x10, 0, 1, 0, 0, 0, 0, 0, 1];
            p.extend(encoded(name, suffix));
            p.extend([0, 0x20, 0, 1]);
            p.extend([
                0xc0, 0x0c, 0, 0x20, 0, 1, 0, 0x04, 0x93, 0xe0, 0, 6, flags, 0,
            ]);
            p.extend([192, 168, 1, 70]);
            p
        }
        let frame = |p: &[u8]| udp_frame([192, 168, 1, 70], [192, 168, 1, 255], 137, 137, p);
        let o = decode(&frame(&registration("WS-OFFICE", 0x00, 0))).unwrap();
        assert_eq!(o.protocol, "NetBIOS");
        assert_eq!(o.fields["name"], "WS-OFFICE");
        assert_eq!(o.fields["netbios_suffix"], "00");
        assert_eq!(o.fields["operation"], "registration");
        assert_eq!(only_device(o).hostnames, ["WS-OFFICE"]);
        let o = decode(&frame(&registration("WORKGROUP", 0x00, 0x80))).unwrap();
        assert_eq!(o.fields["workgroup"], "WORKGROUP");
        assert!(!o.fields.contains_key("name"));
        // A domain controller name <1C> and a messenger name <03> are not host names.
        assert!(
            !decode(&frame(&registration("HOST", 0x03, 0)))
                .unwrap()
                .fields
                .contains_key("name")
        );
        // Wildcard, bad encoding, wrong counts and truncations.
        assert!(decode(&frame(&registration("*", 0, 0))).is_none());
        let mut bad = registration("HOST", 0, 0);
        bad[13] = b'z';
        assert!(decode(&frame(&bad)).is_none());
        let mut queries = registration("HOST", 0, 0);
        queries[2] = 0x01; // opcode 0: a name query, not an announcement
        assert!(decode(&frame(&queries)).is_none());
        assert_prefixes_do_not_panic(&frame(&registration("HOST", 0x20, 0)));
    }
    #[test]
    fn ssdp_hints() {
        let notify = |extra: &str| {
            let m = format!(
                "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNTS: ssdp:alive\r\n{extra}\r\n"
            );
            decode(&udp_frame(
                [192, 168, 1, 1],
                [239, 255, 255, 250],
                1900,
                1900,
                m.as_bytes(),
            ))
            .unwrap()
        };
        let router = notify(
            "NT: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nSERVER: Linux/4.9 UPnP/1.1 MiniUPnPd/2.1\r\nLOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n",
        );
        assert!(router.fields.contains_key("hint.network"));
        assert!(router.fields.contains_key("hint_weak.linux"));
        assert_eq!(
            only_device(router).device_type,
            "Network device (router/switch/AP)"
        );
        let tv = notify(
            "NT: urn:schemas-upnp-org:device:MediaRenderer:1\r\nSERVER: Linux/3.10 UPnP/1.0 Vendor/1.0\r\n",
        );
        assert_eq!(only_device(tv).device_type, "Media / smart TV device");
        let pc = notify(
            "NT: upnp:rootdevice\r\nSERVER: Microsoft-Windows/10.0 UPnP/1.0 UPnP-Device-Host/1.0\r\n",
        );
        assert_eq!(only_device(pc).device_type, "Windows computer");
        let printer = notify("NT: urn:schemas-upnp-org:device:printer:1\r\n");
        assert_eq!(only_device(printer).device_type, "Printer / MFP");
        // A weak hint alone is not a verdict (a generic Linux UPnP stack).
        let generic = notify("NT: upnp:rootdevice\r\nSERVER: Linux/5.4 UPnP/1.0 Foo/1\r\n");
        assert_eq!(only_device(generic).device_type, "");
    }
    /// An Identify response frame (frame ID 0xFEFF) with these blocks (option, suboption, value).
    fn dcp_response(blocks: &[(u8, u8, &[u8])]) -> Vec<u8> {
        let mut data = vec![];
        for (option, suboption, value) in blocks {
            data.extend([*option, *suboption]);
            data.extend((value.len() as u16).to_be_bytes());
            data.extend(*value);
            if value.len() % 2 == 1 {
                data.push(0);
            }
        }
        let mut f = vec![0x01, 0x0e, 0xcf, 0, 0, 0];
        f.extend([0x08, 0, 0x06, 0x93, 0xcf, 0x32]);
        f.extend([0x88, 0x92, 0xfe, 0xff, 5, 1, 0, 0, 0, 1, 0, 0]);
        f.extend((data.len() as u16).to_be_bytes());
        f.extend(data);
        f
    }

    #[test]
    fn profinet_dcp_role_options_instance_and_oem_id() {
        let f = dcp_response(&[
            (2, 2, &[0, 0, b'p', b'l', b'c']),
            (2, 4, &[0, 0, 0x03, 0]),
            (2, 5, &[0, 0, 1, 2, 2, 5]),
            (2, 7, &[0, 0, 0, 1]),
            (2, 8, &[0, 0, 0x01, 0x2a, 0x0a, 0x01]),
        ]);
        let o = decode(&f).unwrap();
        assert_eq!(o.protocol, "Profinet DCP");
        assert_eq!(o.fields["name"], "plc");
        assert_eq!(o.fields["role"], "IO-Device, IO-Controller");
        assert_eq!(o.fields["options"], "1/2, 2/5");
        assert_eq!(o.fields["instance"], "0.1");
        assert_eq!(
            (
                o.fields["oem_vendor_id"].as_str(),
                o.fields["oem_device_id"].as_str()
            ),
            ("298", "2561")
        );
        // a role block without a role bit, and blocks that are too short, add nothing
        let o = decode(&dcp_response(&[
            (2, 4, &[0, 0, 0, 0]),
            (2, 7, &[0, 0]),
            (2, 8, &[0, 0, 1]),
        ]))
        .unwrap();
        for key in ["role", "instance", "oem_vendor_id"] {
            assert!(!o.fields.contains_key(key), "{key}");
        }
        // cut anywhere: no panic
        for cut in 0..f.len() {
            let _ = decode(&f[..cut]);
        }
    }

    #[test]
    fn decoder_code_cannot_transmit() {
        // Everything before `Listening` (the decoders and the hint modules) must stay
        // receive-only. The opt-in DCP Identify request lives in `start`, after it.
        let main = include_str!("passive.rs");
        let decoders = main.split("pub struct Listening").next().unwrap();
        let sources = [
            decoders,
            include_str!("passive/browser.rs"),
            include_str!("passive/cdp.rs"),
            include_str!("passive/dhcpv6.rs"),
            include_str!("passive/lldp_med.rs"),
            include_str!("passive/hints.rs"),
            include_str!("passive/ndp.rs"),
            include_str!("passive/wsd.rs"),
        ];
        for source in sources {
            let code = source.split("#[cfg(test)]").next().unwrap();
            for forbidden in [
                "UdpSocket",
                "TcpStream",
                "TcpListener",
                ".send(",
                "send_to",
                "Capture::open",
                "sendpacket",
                "std::process",
                "std::net::Tcp",
            ] {
                assert!(
                    !code.contains(forbidden),
                    "passive decoders must not use {forbidden}"
                );
            }
        }
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
