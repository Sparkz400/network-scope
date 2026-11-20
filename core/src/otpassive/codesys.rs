//! CODESYS runtime and gateway traffic: UDP 1740-1743 (name service of V3) and TCP 1217, 2455
//! and 11740-11743 (V2 and V3 gateway and runtime).
//!
//! This decoder is **presence only**. The protocol is not decoded: there is no capture of it in
//! `tests/fixtures/ics`, and the frame layout is not something this project can cite exactly, so
//! the observation says what it is based on (`evidence`: the port) and nothing is flagged as
//! control traffic. Another service that happens to use one of these ports is reported as
//! CODESYS; treat the observation as a hint to look at the device.
use super::{Proto, Tracker};
use std::net::IpAddr;

/// The CODESYS ports and whether a payload from the server side is a response.
pub(super) fn is_codesys_udp(port: u16) -> bool {
    (1740..=1743).contains(&port)
}
pub(super) fn is_codesys_tcp(port: u16) -> bool {
    matches!(port, 1217 | 2455 | 11740..=11743)
}

impl Tracker {
    pub(super) fn codesys(
        &mut self,
        client: IpAddr,
        server: IpAddr,
        ts: i64,
        to_server: bool,
        port: u16,
    ) {
        if to_server {
            self.request(Proto::Codesys, client, server, ts, None, None);
        } else {
            self.response(Proto::Codesys, server, client, ts);
        }
        if let Some(s) = self.server(Proto::Codesys, server) {
            s.fields.insert(
                "evidence".into(),
                format!("port {port} only, payload not decoded"),
            );
        }
    }
}

#[cfg(test)]
mod tests {
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
}
