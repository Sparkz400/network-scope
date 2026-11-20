//! Mitsubishi MELSEC: the MC protocol (3E and 4E binary frames, TCP/UDP 5006 and 5007) and the
//! MELSOFT direct connection of GX Works (UDP 5560 and 5561). The MC protocol decoder names the
//! command of each request and flags the ones that write device memory or change the CPU state.
//! The MELSOFT decoder is written from one capture (`melsec_melsoft_udp.pcap`, an iQ-F FX5U): it
//! recognises the frames and reads the CPU model from the response that carries it, and nothing
//! about that protocol is flagged.
use super::{Proto, Tracker, packet::le16};
use crate::ot::extra::clean_ascii;
use std::net::IpAddr;

/// (name, control) of an MC protocol command (MELSEC Communication Protocol Reference Manual,
/// binary code). The command is little-endian in the frame.
pub(super) fn mc_command(command: u16) -> (String, bool) {
    let (name, control) = match command {
        0x0401 => ("Batch Read", false),
        0x1401 => ("Batch Write", true),
        0x0403 => ("Random Read", false),
        0x1402 => ("Random Write", true),
        0x0406 => ("Block Read", false),
        0x1406 => ("Block Write", true),
        0x0101 => ("Read CPU Model Name", false),
        0x1001 => ("Remote Run", true),
        0x1002 => ("Remote Stop", true),
        0x1003 => ("Remote Pause", true),
        0x1005 => ("Remote Latch Clear", true),
        0x1006 => ("Remote Reset", true),
        _ => return (format!("MC command {command:04X}"), false),
    };
    (name.to_string(), control)
}

/// What a payload on an MC protocol port is: a request (3E subheader 0x50 0x00, 4E 0x54 0x00) with
/// its command, or a response (0xD0 0x00, 0xD4 0x00).
enum Mc {
    Request(u16),
    Response,
}

fn mc(pl: &[u8]) -> Option<Mc> {
    // 3E: subheader(2) network(1) PC(1) module I/O(2) station(1) length(2) timer(2) command(2)
    // 4E: subheader(2) serial(2) reserved(2) then the same fields from "network" on
    let (head, skip) = match pl.get(..2)? {
        [0x50, 0x00] => ("request", 0),
        [0xd0, 0x00] => ("response", 0),
        [0x54, 0x00] => ("request", 4),
        [0xd4, 0x00] => ("response", 4),
        _ => return None,
    };
    // the data length counts everything after itself
    let length = usize::from(le16(pl, 7 + skip)?);
    if pl.len() < 9 + skip + length.min(1) {
        return None;
    }
    if head == "response" {
        return Some(Mc::Response);
    }
    Some(Mc::Request(le16(pl, 11 + skip)?))
}

/// The MELSOFT direct frames: first byte 0x57 (request) or 0xD7 (response), then a fixed
/// 0x01 0x00 0x00 prefix.
fn melsoft(pl: &[u8]) -> Option<bool> {
    match (pl.first()?, pl.get(1..4)?) {
        (0x57, [1, 0, 0]) => Some(true),
        (0xd7, [1, 0, 0]) => Some(false),
        _ => None,
    }
}

/// The CPU model in a MELSOFT response: ASCII after the marker `01 21 01 00 00 00` that the
/// captured response carries, 16 bytes padded with NUL.
fn melsoft_model(pl: &[u8]) -> Option<String> {
    let marker = [0x01, 0x21, 0x01, 0x00, 0x00, 0x00];
    let at = pl.windows(6).position(|w| w == marker)? + 6;
    let model = clean_ascii(pl.get(at..at + 16)?);
    (model.len() >= 3).then_some(model)
}

impl Tracker {
    /// A payload on port 5006 or 5007 (TCP or UDP).
    pub(super) fn melsec_mc(
        &mut self,
        client: IpAddr,
        server: IpAddr,
        pl: &[u8],
        ts: i64,
        to_server: bool,
    ) {
        match (mc(pl), to_server) {
            (Some(Mc::Request(command)), true) => self.request(
                Proto::Melsec,
                client,
                server,
                ts,
                Some(mc_command(command)),
                None,
            ),
            (Some(Mc::Response), false) => self.response(Proto::Melsec, server, client, ts),
            _ => {}
        }
    }

    /// A payload on UDP 5560 or 5561.
    pub(super) fn melsoft(
        &mut self,
        client: IpAddr,
        server: IpAddr,
        pl: &[u8],
        ts: i64,
        to_server: bool,
    ) {
        let handshake =
            matches!(pl.first(), Some(0x5a | 0xda)) && pl.len() >= 4 && pl[1..3] == [0, 0];
        match (melsoft(pl), to_server) {
            (Some(true), true) => self.request(Proto::Melsec, client, server, ts, None, None),
            (Some(false), false) => {
                self.response(Proto::Melsec, server, client, ts);
                if let Some(model) = melsoft_model(pl)
                    && let Some(s) = self.server(Proto::Melsec, server)
                {
                    s.fields.insert("model".into(), model);
                    s.fields
                        .insert("protocol".into(), "MELSOFT direct connection".into());
                }
            }
            _ if handshake && to_server => {
                self.request(Proto::Melsec, client, server, ts, None, None)
            }
            _ if handshake => self.response(Proto::Melsec, server, client, ts),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::otpassive::Tracker;
    use crate::otpassive::testutil::{HMI, PLC, frame, obs};

    /// A 3E binary request: network 0, PC 0xFF, module I/O 0x03FF, station 0, the command.
    fn mc3e(command: u16, data: &[u8]) -> Vec<u8> {
        let mut b = vec![0x50, 0x00, 0x00, 0xff, 0xff, 0x03, 0x00];
        b.extend(((data.len() + 6) as u16).to_le_bytes());
        b.extend([0x10, 0x00]);
        b.extend(command.to_le_bytes());
        b.extend([0, 0]);
        b.extend(data);
        b
    }

    #[test]
    fn mc_protocol_writes_and_remote_control_are_control_traffic() {
        let mut t = Tracker::new();
        for command in [0x0401u16, 0x1401, 0x1002, 0x1001, 0x0101, 0x7777] {
            t.feed(
                &frame(HMI, PLC, true, 40000, 5007, &mc3e(command, &[0; 4])),
                1,
            );
        }
        // a response from the PLC, and a 4E request over UDP
        t.feed(
            &frame(
                PLC,
                HMI,
                true,
                5007,
                40000,
                &[0xd0, 0, 0, 0xff, 0xff, 3, 0, 2, 0, 0, 0],
            ),
            2,
        );
        let mut e4 = mc3e(0x1006, &[]);
        e4.splice(0..2, [0x54, 0, 1, 0, 0, 0]);
        t.feed(&frame(HMI, PLC, false, 40001, 5006, &e4), 3);
        let s = &obs(&t, "MELSEC server (observed)")[0];
        assert_eq!(
            s.fields["control_traffic"],
            "Batch Write x1, Remote Reset x1, Remote Run x1, Remote Stop x1"
        );
        assert!(s.fields["functions"].contains("Read CPU Model Name x1"));
        assert!(s.fields["functions"].contains("MC command 7777 x1"));
        assert_eq!(s.fields["packets"], "8");
        let findings = crate::otpassive::control_findings(&t.observations());
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn foreign_and_truncated_payloads_are_ignored() {
        let mut t = Tracker::new();
        for pl in [
            &b"GET / HTTP/1.1\r\n\r\n"[..],
            &[0x50, 0x00],
            &[0x50, 0, 0, 0xff, 0xff, 3, 0, 4],
            &[],
        ] {
            t.feed(&frame(HMI, PLC, true, 40000, 5007, pl), 1);
        }
        assert!(t.observations().is_empty(), "{:?}", t.observations());
    }
}
