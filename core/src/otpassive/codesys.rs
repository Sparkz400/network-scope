//! CODESYS runtime and gateway traffic: UDP 1740-1743 (name service of V3) and TCP 1200, 1217,
//! 2455 and 11740-11743 (V2 and V3 gateway and runtime).
//!
//! One exchange is decoded, the one the public descriptions of the V2 runtime all agree on (the
//! identification handshake that Digital Bond's `codesys-v2-discover` script performs; the facts
//! below are taken from that description, no code is used): the client sends 7 bytes, `BB BB 01
//! 00 00 xx 01`, where `xx` is 0 for a little-endian and 1 for a big-endian client, and the
//! runtime answers with a message whose first byte is 0xBB and which holds the operating system
//! name at offset 64, the operating system type at offset 96 and the product name at offset
//! 128, each a NUL-terminated string of at most 32 bytes. The offsets come from that description
//! only: **no capture of CODESYS is among the fixtures** (`tests/fixtures/ics`), so this decoder
//! is tested on frames built from the description, not on real traffic. The observation says so
//! (`evidence`).
//!
//! Everything else is **presence only**: a payload on one of the other ports is reported as
//! CODESYS on the strength of the port (`evidence` says "port N only"), the V3 protocol is not
//! decoded, and nothing is flagged as control traffic. Another service that happens to use one
//! of these ports is reported as CODESYS; treat the observation as a hint to look at the device.
//! TCP 1200 is a port that other programs use, so there only a payload that starts with the
//! 0xBB marker counts.
use super::{Proto, Tracker};
use crate::ot::extra::clean_ascii;
use std::net::IpAddr;

/// The CODESYS ports and whether a payload from the server side is a response.
pub(super) fn is_codesys_udp(port: u16) -> bool {
    (1740..=1743).contains(&port)
}
pub(super) fn is_codesys_tcp(port: u16) -> bool {
    matches!(port, 1200 | 1217 | 2455 | 11740..=11743)
}

/// What the identification handshake of the V2 runtime says, from a reply (`None` when the
/// payload is not one). The three strings are cleaned (printable ASCII, 32 characters at most).
pub(super) fn v2_identification(reply: &[u8]) -> Option<(String, String, String)> {
    if reply.first() != Some(&0xbb) || reply.len() < 129 {
        return None;
    }
    let os_name = clean_ascii(&reply[64..96]);
    let os_type = clean_ascii(&reply[96..128]);
    let product = clean_ascii(&reply[128..reply.len().min(160)]);
    (!(os_name.is_empty() && os_type.is_empty() && product.is_empty()))
        .then_some((os_name, os_type, product))
}

/// The byte order a handshake request announces (0: little endian, 1: big endian), if `request`
/// is one.
pub(super) fn v2_handshake_request(request: &[u8]) -> Option<u8> {
    (request.len() >= 7
        && request[..5] == [0xbb, 0xbb, 0x01, 0x00, 0x00]
        && request[5] <= 1
        && request[6] == 0x01)
        .then(|| request[5])
}

impl Tracker {
    pub(super) fn codesys(
        &mut self,
        client: IpAddr,
        server: IpAddr,
        ts: i64,
        to_server: bool,
        port: u16,
        pl: &[u8],
    ) {
        let handshake = to_server.then(|| v2_handshake_request(pl)).flatten();
        let identification = (!to_server).then(|| v2_identification(pl)).flatten();
        // port 1200 is not CODESYS unless the payload says so
        if port == 1200 && handshake.is_none() && pl.first() != Some(&0xbb) {
            return;
        }
        if to_server {
            let function = handshake.map(|_| ("Identification handshake".to_string(), false));
            self.request(Proto::Codesys, client, server, ts, function, None);
        } else {
            self.response(Proto::Codesys, server, client, ts);
        }
        if let Some(s) = self.server(Proto::Codesys, server) {
            if let Some((os_name, os_type, product)) = identification {
                for (key, value) in [
                    ("os_name", os_name),
                    ("os_type", os_type),
                    ("product", product),
                ] {
                    if !value.is_empty() {
                        s.fields.insert(key.into(), value);
                    }
                }
                s.fields.insert(
                    "evidence".into(),
                    "decoded: CODESYS V2 identification reply (layout from a public description, not checked on a capture)".into(),
                );
            } else if handshake.is_some() {
                s.fields
                    .entry("evidence".into())
                    .or_insert_with(|| "decoded: CODESYS V2 identification request".into());
            } else if !s
                .fields
                .get("evidence")
                .is_some_and(|e| e.starts_with("decoded"))
            {
                s.fields.insert(
                    "evidence".into(),
                    format!("port {port} only, payload not decoded"),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{v2_handshake_request, v2_identification};
    use crate::otpassive::Tracker;
    use crate::otpassive::testutil::{HMI, PLC, frame, obs};

    #[test]
    fn presence_is_reported_with_its_evidence_and_never_as_control() {
        let mut t = Tracker::new();
        t.feed(&frame(HMI, PLC, false, 50000, 1740, &[0xc5, 1, 2, 3]), 1);
        t.feed(&frame(HMI, PLC, true, 50001, 11740, &[0xc5, 9]), 2);
        let servers = obs(&t, "CODESYS server (observed)");
        assert_eq!(servers.len(), 1);
        let s = &servers[0];
        assert_eq!(s.fields["packets"], "2");
        assert!(s.fields["evidence"].contains("port"), "{:?}", s.fields);
        assert!(!s.fields.contains_key("control_traffic"));
        assert!(!s.fields.contains_key("functions"));
        // other ports are not CODESYS
        let mut t = Tracker::new();
        t.feed(&frame(HMI, PLC, false, 50000, 1744, &[1]), 1);
        t.feed(&frame(HMI, PLC, true, 50000, 1218, &[1]), 1);
        assert!(t.observations().is_empty());
    }

    /// A V2 identification reply as the public description lays it out: the 0xBB marker, the
    /// operating system name at 64, its type at 96 and the product at 128, NUL terminated. No
    /// real capture of this exchange exists among the fixtures, so these frames are built, not
    /// recorded.
    fn reply(os: &str, os_type: &str, product: &str) -> Vec<u8> {
        let mut m = vec![0u8; 160];
        m[0] = 0xbb;
        m[64..64 + os.len()].copy_from_slice(os.as_bytes());
        m[96..96 + os_type.len()].copy_from_slice(os_type.as_bytes());
        m[128..128 + product.len()].copy_from_slice(product.as_bytes());
        m
    }

    #[test]
    fn the_v2_identification_handshake_is_decoded_and_says_what_it_rests_on() {
        let request = [0xbb, 0xbb, 0x01, 0x00, 0x00, 0x00, 0x01];
        let mut t = Tracker::new();
        t.feed(&frame(HMI, PLC, true, 50000, 1200, &request), 1);
        t.feed(
            &frame(
                PLC,
                HMI,
                true,
                1200,
                50000,
                &reply("Windows NT", "5.1.2600", "3S - Smart Software Solutions"),
            ),
            2,
        );
        let s = &obs(&t, "CODESYS server (observed)")[0];
        assert_eq!(s.fields["os_name"], "Windows NT");
        assert_eq!(s.fields["os_type"], "5.1.2600");
        assert_eq!(s.fields["product"], "3S - Smart Software Solutions");
        assert!(
            s.fields["evidence"].starts_with("decoded: CODESYS V2 identification reply")
                && s.fields["evidence"].contains("not checked on a capture"),
            "{:?}",
            s.fields
        );
        assert_eq!(s.fields["functions"], "Identification handshake x1");
        assert!(!s.fields.contains_key("control_traffic"));
        // the big-endian variant of the request is the same handshake
        assert_eq!(v2_handshake_request(&[0xbb, 0xbb, 1, 0, 0, 1, 1]), Some(1));
        assert_eq!(v2_handshake_request(&request), Some(0));
        for bad in [
            &request[..6],
            &[0xbb, 0xbb, 1, 0, 0, 2, 1][..],
            &[0xbb, 0xbb, 1, 0, 0, 0, 2][..],
            &[0xba, 0xbb, 1, 0, 0, 0, 1][..],
            &[][..],
        ] {
            assert_eq!(v2_handshake_request(bad), None, "{bad:?}");
        }
        // port 1200 is only CODESYS when the payload says so
        let mut t = Tracker::new();
        t.feed(
            &frame(HMI, PLC, true, 50000, 1200, b"GET / HTTP/1.1\r\n"),
            1,
        );
        t.feed(
            &frame(PLC, HMI, true, 1200, 50000, b"HTTP/1.1 200 OK\r\n"),
            2,
        );
        assert!(t.observations().is_empty());
        // another CODESYS port keeps its presence-only evidence for other payloads
        let mut t = Tracker::new();
        t.feed(&frame(HMI, PLC, true, 50000, 2455, &[1, 2, 3]), 1);
        assert_eq!(
            obs(&t, "CODESYS server (observed)")[0].fields["evidence"],
            "port 2455 only, payload not decoded"
        );
    }

    #[test]
    fn the_reply_decoder_is_bounded_and_refuses_what_is_not_a_reply() {
        let m = reply("Linux", "4.19", "CODESYS Control for Linux");
        let (os, kind, product) = v2_identification(&m).unwrap();
        assert_eq!(
            (os.as_str(), kind.as_str(), product.as_str()),
            ("Linux", "4.19", "CODESYS Control for Linux")
        );
        // every shorter message, another marker, no strings at all
        for cut in 0..129 {
            assert_eq!(v2_identification(&m[..cut]), None, "{cut}");
        }
        let mut other = m.clone();
        other[0] = 0xba;
        assert_eq!(v2_identification(&other), None);
        let mut empty = vec![0u8; 160];
        empty[0] = 0xbb;
        assert_eq!(v2_identification(&empty), None);
        // strings that run on without a NUL are cut at 32 characters, control bytes are dropped
        let mut long = vec![0xbbu8; 400];
        long[64..96].fill(b'A');
        long[96..128].fill(0x1b);
        let (os, kind, product) = v2_identification(&long).unwrap();
        assert_eq!((os.len(), kind.as_str()), (32, ""));
        assert!(product.is_empty() || product.chars().count() <= 32);
    }
}
