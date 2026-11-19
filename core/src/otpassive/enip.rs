//! EtherNet/IP and CIP: encapsulation, services, nested requests, List Identity.
use super::packet::le16;
use super::{Proto, Tracker};
use std::net::IpAddr;

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
        0x06 => ("Start", true),
        0x07 => ("Stop", true),
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
            ));
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
            if let Some(n) = le16(data, 2)
                && let Some(inner) = data.get(4..4 + usize::from(n))
            {
                cip_request(inner, depth + 1, out);
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

impl Tracker {
    /// `to_server`: the packet travels towards the device port; otherwise it is a reply.
    pub(super) fn enip(
        &mut self,
        client: IpAddr,
        server: IpAddr,
        pl: &[u8],
        ts: i64,
        to_server: bool,
    ) {
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
            if cmd == 0x63
                && let Ok(mut fields) = crate::ot::parse_list_identity(&pl[24..])
                && let Some(s) = self.server(Proto::EtherNetIp, server)
            {
                s.fields.append(&mut fields);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otpassive::Tracker;
    use crate::otpassive::testutil::{HMI, PLC, cip_identity, cip_send_rr, frame, obs};

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
    fn cip_start_and_stop_services_are_control_traffic() {
        // Common services 0x06 Start / 0x07 Stop, e.g. a controller stop (class 0x8e).
        let (functions, control) = cip_server_traffic(&[
            vec![0x07, 2, 0x20, 0x8e, 0x24, 0x01],
            vec![0x06, 2, 0x20, 0x8e, 0x24, 0x01],
        ]);
        assert_eq!(functions, "Start x1, Stop x1");
        assert_eq!(control, "Start x1, Stop x1");
        // A reply (bit 7 set) is not a request.
        let (functions, _) = cip_server_traffic(&[
            vec![0x87, 2, 0x20, 0x8e, 0x24, 0x01],
            vec![0x0e, 2, 0x20, 0x01, 0x24, 0x01],
        ]);
        assert_eq!(functions, "Get Attribute Single x1");
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
}
