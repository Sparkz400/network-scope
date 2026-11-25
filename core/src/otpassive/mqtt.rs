// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! MQTT (TCP 1883): control packets, the CONNECT of a client (protocol level, user name,
//! will) and the broker's CONNACK. MQTT has no write function in the sense of the other
//! protocols here (a PUBLISH is as often telemetry as it is a command), so nothing is flagged as
//! control traffic; the observation lists which packet types were seen and whether clients
//! connected without a user name.
use super::{Proto, Tracker};
use crate::ot::extra::parse_mqtt_connack;
use std::net::IpAddr;

/// Most packets read from one segment.
const MAX_PACKETS: usize = 16;

fn packet_name(t: u8) -> Option<&'static str> {
    Some(match t {
        1 => "CONNECT",
        2 => "CONNACK",
        3 => "PUBLISH",
        4 => "PUBACK",
        5 => "PUBREC",
        6 => "PUBREL",
        7 => "PUBCOMP",
        8 => "SUBSCRIBE",
        9 => "SUBACK",
        10 => "UNSUBSCRIBE",
        11 => "UNSUBACK",
        12 => "PINGREQ",
        13 => "PINGRESP",
        14 => "DISCONNECT",
        15 => "AUTH",
        _ => return None,
    })
}

/// The packets of one segment: (type, first byte, body). Stops at a malformed or incomplete one.
fn packets(mut b: &[u8]) -> Vec<(u8, u8, &[u8])> {
    let mut out = vec![];
    while out.len() < MAX_PACKETS && !b.is_empty() {
        let first = b[0];
        let kind = first >> 4;
        if packet_name(kind).is_none() {
            break;
        }
        // remaining length: up to four bytes, seven bits each
        let (mut len, mut shift, mut used) = (0usize, 0, 0);
        loop {
            let Some(&byte) = b.get(1 + used) else {
                return out;
            };
            len |= usize::from(byte & 0x7f) << shift;
            used += 1;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if used == 4 {
                return out;
            }
        }
        let Some(body) = b.get(1 + used..1 + used + len) else {
            break;
        };
        out.push((kind, first, body));
        b = &b[1 + used + len..];
    }
    out
}

/// (protocol name and level, user name flag, will flag) of a CONNECT body.
fn connect(body: &[u8]) -> Option<(String, bool, bool)> {
    let n = usize::from(u16::from_be_bytes([*body.first()?, *body.get(1)?]));
    let name = body.get(2..2 + n)?;
    let level = *body.get(2 + n)?;
    let flags = *body.get(3 + n)?;
    let name = match (name, level) {
        (b"MQTT", 4) => "MQTT 3.1.1".to_string(),
        (b"MQTT", 5) => "MQTT 5".to_string(),
        (b"MQIsdp", 3) => "MQTT 3.1".to_string(),
        _ => return None,
    };
    Some((name, flags & 0x80 != 0, flags & 0x04 != 0))
}

impl Tracker {
    pub(super) fn mqtt(
        &mut self,
        client: IpAddr,
        server: IpAddr,
        pl: &[u8],
        ts: i64,
        to_server: bool,
    ) {
        let list = packets(pl);
        if list.is_empty() {
            return;
        }
        if to_server {
            let functions: Vec<(String, bool)> = list
                .iter()
                .filter_map(|(k, _, _)| packet_name(*k))
                .map(|n| (n.to_string(), false))
                .collect();
            self.request(Proto::Mqtt, client, server, ts, functions, None);
            if let Some((_, _, body)) = list.iter().find(|(k, _, _)| *k == 1)
                && let Some((version, user, will)) = connect(body)
                && let Some(c) = self.client(Proto::Mqtt, client)
            {
                c.fields.insert("protocol".into(), version);
                c.fields.insert(
                    "user_name".into(),
                    if user { "sent" } else { "none" }.into(),
                );
                if will {
                    c.fields.insert("will".into(), "set".into());
                }
            }
        } else {
            self.response(Proto::Mqtt, server, client, ts);
            if let Some((_, _, body)) = list.iter().find(|(k, _, _)| *k == 2) {
                let mut raw = vec![0x20, 2];
                raw.extend_from_slice(body);
                if let Ok(f) = parse_mqtt_connack(&raw)
                    && let Some(s) = self.server(Proto::Mqtt, server)
                {
                    s.fields.extend(f);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otpassive::testutil::{HMI, PLC, frame, obs};

    const CONNECT: [u8; 14] = [
        0x10, 0x0c, 0, 4, 0x4d, 0x51, 0x54, 0x54, 4, 2, 0, 0x3c, 0, 0,
    ];

    #[test]
    fn connect_connack_and_publish() {
        let mut t = Tracker::new();
        t.feed(&frame(HMI, PLC, true, 40000, 1883, &CONNECT), 1);
        t.feed(&frame(PLC, HMI, true, 1883, 40000, &[0x20, 2, 0, 0]), 2);
        // PUBLISH topic "a/b" payload "1", then a PINGREQ in the same segment
        let mut publish = vec![0x30, 6, 0, 3, b'a', b'/', b'b', b'1'];
        publish.extend([0xc0, 0]);
        t.feed(&frame(HMI, PLC, true, 40000, 1883, &publish), 3);
        let s = &obs(&t, "MQTT server (observed)")[0];
        assert_eq!(s.fields["connack"], "accepted");
        assert_eq!(s.fields["connack_info"], "anonymous connection accepted");
        assert_eq!(s.fields["functions"], "CONNECT x1, PINGREQ x1, PUBLISH x1");
        assert!(
            !s.fields.contains_key("control_traffic"),
            "a PUBLISH is not flagged"
        );
        let c = &obs(&t, "MQTT client (observed)")[0];
        assert_eq!(c.fields["protocol"], "MQTT 3.1.1");
        assert_eq!(c.fields["user_name"], "none");
        // topics and payloads are not kept
        assert!(!format!("{:?}", t.observations()).contains("a/b"));
    }

    #[test]
    fn a_client_with_a_user_name_and_a_will() {
        let mut connect = CONNECT.to_vec();
        connect[9] = 0x80 | 0x04 | 0x02;
        let mut t = Tracker::new();
        t.feed(&frame(HMI, PLC, true, 40000, 1883, &connect), 1);
        let c = &obs(&t, "MQTT client (observed)")[0];
        assert_eq!(
            (c.fields["user_name"].as_str(), c.fields["will"].as_str()),
            ("sent", "set")
        );
    }

    #[test]
    fn malformed_and_foreign_data_is_ignored_and_bounded() {
        let mut t = Tracker::new();
        for pl in [
            &b"GET / HTTP/1.1\r\n\r\n"[..],
            &[0x00, 0x00],
            &[0xf0, 0xff, 0xff, 0xff, 0xff, 0x7f],
            &[0x30, 0x80, 0x80, 0x80, 0x80, 0x01],
            &[0x30, 10, 1],
        ] {
            t.feed(&frame(HMI, PLC, true, 40000, 1883, pl), 1);
        }
        assert!(t.observations().is_empty(), "{:?}", t.observations());
        // sixty-four PINGREQs in one segment: at most MAX_PACKETS are read
        assert_eq!(packets(&[0xc0, 0].repeat(64)).len(), MAX_PACKETS);
        // a CONNECT of another protocol is not an MQTT client
        let mut other = CONNECT.to_vec();
        other[4] = b'X';
        assert!(connect(&other[2..]).is_none());
    }
}
