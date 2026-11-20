//! KNXnet/IP (UDP 3671): the frame header and service type, the device information of search and
//! description responses (name, individual address, serial number, MAC) and the cEMI telegrams
//! inside tunnelling requests and routing indications. A group value write, an individual
//! address write, a memory write or a restart is control traffic.
use super::{Proto, Tracker, packet::be16};
use crate::ot::extra::parse_knx_description;
use std::net::IpAddr;

/// (name, control) of a KNXnet/IP service type.
fn service(t: u16) -> Option<(&'static str, bool)> {
    Some(match t {
        0x0201 => ("Search Request", false),
        0x0202 => ("Search Response", false),
        0x0203 => ("Description Request", false),
        0x0204 => ("Description Response", false),
        0x0205 => ("Connect Request", false),
        0x0206 => ("Connect Response", false),
        0x0207 => ("Connection State Request", false),
        0x0208 => ("Connection State Response", false),
        0x0209 => ("Disconnect Request", false),
        0x020a => ("Disconnect Response", false),
        0x0310 => ("Device Configuration Request", false),
        0x0311 => ("Device Configuration Ack", false),
        0x0420 => ("Tunnelling Request", false),
        0x0421 => ("Tunnelling Ack", false),
        0x0530 => ("Routing Indication", false),
        0x0531 => ("Routing Lost Message", false),
        0x0532 => ("Routing Busy", false),
        _ => return None,
    })
}

/// (name, control) of the application layer service (APCI) of a telegram.
fn apci(code: u8) -> (String, bool) {
    let (name, control) = match code {
        0 => ("Group Value Read", false),
        1 => ("Group Value Response", false),
        2 => ("Group Value Write", true),
        3 => ("Individual Address Write", true),
        4 => ("Individual Address Read", false),
        5 => ("Individual Address Response", false),
        6 => ("ADC Read", false),
        8 => ("Memory Read", false),
        10 => ("Memory Write", true),
        12 => ("Device Descriptor Read", false),
        14 => ("Restart", true),
        _ => return (format!("APCI {code}"), false),
    };
    (name.to_string(), control)
}

/// The telegram service of a cEMI L_Data frame (message code 0x11 request, 0x29 indication):
/// message code, additional info length, two control bytes, source, destination, data length and
/// the TPDU whose first two bytes carry the APCI.
fn emi_service(cemi: &[u8]) -> Option<(String, bool)> {
    if !matches!(cemi.first()?, 0x11 | 0x29) {
        return None;
    }
    let at = 2 + usize::from(*cemi.get(1)?);
    let tpdu = cemi.get(at + 7..at + 9)?;
    Some(apci(((tpdu[0] & 0x03) << 2) | (tpdu[1] >> 6)))
}

impl Tracker {
    pub(super) fn knx(
        &mut self,
        client: IpAddr,
        server: IpAddr,
        pl: &[u8],
        ts: i64,
        to_server: bool,
    ) {
        if pl.len() < 6 || pl[0] != 6 || pl[1] != 0x10 {
            return;
        }
        let kind = be16(pl, 2).unwrap_or(0);
        let Some((name, _)) = service(kind) else {
            return;
        };
        if be16(pl, 4).map(usize::from) != Some(pl.len()) {
            return;
        }
        if to_server {
            let mut functions = vec![(name.to_string(), false)];
            // a telegram inside the frame: tunnelling (after the 4-byte connection header) or
            // routing (right after the header)
            let cemi = match kind {
                0x0420 => pl.get(10..),
                0x0530 => pl.get(6..),
                _ => None,
            };
            if let Some((telegram, control)) = cemi.and_then(emi_service) {
                functions.push((telegram, control));
            }
            self.request(Proto::Knx, client, server, ts, functions, None);
        } else {
            self.response(Proto::Knx, server, client, ts);
            if matches!(kind, 0x0202 | 0x0204)
                && let Ok(mut fields) = parse_knx_description(pl)
                && let Some(s) = self.server(Proto::Knx, server)
            {
                s.fields.append(&mut fields);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::otpassive::Tracker;
    use crate::otpassive::testutil::{HMI, PLC, frame, obs};

    /// A tunnelling request carrying L_Data.req from 1.1.10 to group 1/2/3 with this APCI.
    fn tunnelling(apci: u8) -> Vec<u8> {
        let mut b = vec![6, 0x10, 0x04, 0x20, 0, 0, 4, 1, 0, 0];
        // L_Data.req, no additional info, control fields, source, destination, data length 1,
        // TPCI/APCI high bits, APCI low bits and the 6-bit value
        b.extend([
            0x11,
            0,
            0xbc,
            0xe0,
            0x11,
            0x0a,
            0x0a,
            0x03,
            1,
            (apci >> 2) & 3,
            (apci & 3) << 6 | 1,
        ]);
        let n = b.len() as u16;
        b[4..6].copy_from_slice(&n.to_be_bytes());
        b
    }

    #[test]
    fn telegram_writes_and_restarts_are_control_traffic_reads_are_not() {
        let mut t = Tracker::new();
        for code in [0u8, 2, 3, 10, 14, 7] {
            t.feed(&frame(HMI, PLC, false, 50000, 3671, &tunnelling(code)), 1);
        }
        let s = &obs(&t, "KNXnet/IP server (observed)")[0];
        assert_eq!(
            s.fields["control_traffic"],
            "Group Value Write x1, Individual Address Write x1, Memory Write x1, Restart x1"
        );
        assert!(s.fields["functions"].contains("Group Value Read x1"));
        assert!(s.fields["functions"].contains("Tunnelling Request x6"));
        assert!(s.fields["functions"].contains("APCI 7 x1"));
        let findings = crate::otpassive::control_findings(&t.observations());
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].0,
            crate::risk::Severity::High,
            "a restart is high"
        );
    }

    #[test]
    fn a_description_response_names_the_device() {
        let mut t = Tracker::new();
        let request = [6, 0x10, 2, 3, 0, 14, 8, 1, 0, 0, 0, 0, 0, 0];
        t.feed(&frame(HMI, PLC, false, 50000, 3671, &request), 1);
        t.feed(
            &frame(
                PLC,
                HMI,
                false,
                3671,
                50000,
                &crate::ot::extra::tests::knx_response(),
            ),
            2,
        );
        let s = &obs(&t, "KNXnet/IP server (observed)")[0];
        assert_eq!(s.fields["name"], "KNX IP Interface");
        assert_eq!(s.fields["individual_address"], "1.1.250");
        assert_eq!(s.fields["functions"], "Description Request x1");
        assert!(!s.fields.contains_key("control_traffic"));
    }

    #[test]
    fn broken_frames_are_ignored() {
        let mut t = Tracker::new();
        let good = tunnelling(2);
        for cut in 0..good.len() {
            t.feed(&frame(HMI, PLC, false, 50000, 3671, &good[..cut]), 1);
        }
        let mut wrong_length = good.clone();
        wrong_length[5] = 0xff;
        t.feed(&frame(HMI, PLC, false, 50000, 3671, &wrong_length), 1);
        let mut unknown = good.clone();
        unknown[2..4].copy_from_slice(&[0x7f, 0x7f]);
        t.feed(&frame(HMI, PLC, false, 50000, 3671, &unknown), 1);
        t.feed(
            &frame(HMI, PLC, false, 50000, 3671, b"GET / HTTP/1.1\r\n\r\n"),
            1,
        );
        assert!(t.observations().is_empty(), "{:?}", t.observations());
    }
}
