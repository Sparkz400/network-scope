// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Omron FINS: FINS/TCP (a `FINS` header with a length and a command, port 9600) and FINS/UDP
//! (the bare FINS frame). Names the command of each request, flags the ones that write or change
//! the controller's state, and reads the controller model and version from a Controller Data
//! Read response.
use super::{Proto, Tracker};
use crate::ot::extra::parse_fins_controller_data;
use std::net::IpAddr;

/// (name, control) of a request, by main and sub request code (Omron FINS Commands Reference
/// Manual W227). Codes not named here are listed by number and are not flagged.
pub(super) fn fins_command(main: u8, sub: u8) -> (String, bool) {
    let (name, control) = match (main, sub) {
        (0x01, 0x01) => ("Memory Area Read", false),
        (0x01, 0x02) => ("Memory Area Write", true),
        (0x01, 0x03) => ("Memory Area Fill", true),
        (0x01, 0x04) => ("Multiple Memory Area Read", false),
        (0x01, 0x05) => ("Memory Area Transfer", true),
        (0x02, 0x01) => ("Parameter Area Read", false),
        (0x02, 0x02) => ("Parameter Area Write", true),
        (0x02, 0x03) => ("Parameter Area Clear", true),
        (0x03, 0x06) => ("Program Area Read", false),
        (0x03, 0x07) => ("Program Area Write", true),
        (0x03, 0x08) => ("Program Area Clear", true),
        (0x04, 0x01) => ("Run", true),
        (0x04, 0x02) => ("Stop", true),
        (0x05, 0x01) => ("Controller Data Read", false),
        (0x05, 0x02) => ("Connection Data Read", false),
        (0x06, 0x01) => ("Controller Status Read", false),
        (0x06, 0x20) => ("Cycle Time Read", false),
        (0x07, 0x01) => ("Clock Read", false),
        (0x07, 0x02) => ("Clock Write", true),
        (0x0c, 0x01) => ("Access Right Acquire", true),
        (0x0c, 0x02) => ("Access Right Forced Acquire", true),
        (0x0c, 0x03) => ("Access Right Release", false),
        (0x21, 0x01) => ("Error Clear", true),
        (0x21, 0x02) => ("Error Log Read", false),
        (0x21, 0x03) => ("Error Log Clear", true),
        (0x22, 0x01) => ("File Name Read", false),
        (0x22, 0x02) => ("Single File Read", false),
        (0x22, 0x03) => ("Single File Write", true),
        (0x22, 0x04) => ("File Memory Format", true),
        (0x22, 0x05) => ("File Delete", true),
        (0x23, 0x01) => ("Forced Set/Reset", true),
        (0x23, 0x02) => ("Forced Set/Reset Cancel", true),
        _ => return (format!("FINS command {main:02X}{sub:02X}"), false),
    };
    (name.to_string(), control)
}

/// The FINS frame of a TCP payload: after the 16-byte `FINS` header of a frame-send command
/// (command 2). The node address handshake (commands 0 and 1) carries no frame.
fn tcp_frame(pl: &[u8]) -> Result<Option<&[u8]>, ()> {
    if pl.get(..4) != Some(b"FINS") {
        return Err(());
    }
    let command = pl
        .get(8..12)
        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]));
    Ok(if command == Some(2) {
        pl.get(16..)
    } else {
        None
    })
}

impl Tracker {
    /// One FINS/TCP segment on port 9600; `to_server` is the direction.
    pub(super) fn fins_tcp(
        &mut self,
        client: IpAddr,
        server: IpAddr,
        pl: &[u8],
        ts: i64,
        to_server: bool,
    ) {
        match tcp_frame(pl) {
            Err(()) => {}
            Ok(frame) => self.fins(client, server, frame, ts, to_server),
        }
    }

    /// A FINS frame (`None`: a header without a frame, presence only).
    pub(super) fn fins(
        &mut self,
        client: IpAddr,
        server: IpAddr,
        frame: Option<&[u8]>,
        ts: i64,
        to_server: bool,
    ) {
        let header = frame.filter(|f| f.len() >= 12 && f[0] & 0x80 != 0 && f[1] == 0);
        let response = header.is_some_and(|f| f[0] & 0x40 != 0);
        if to_server {
            let functions = header
                .filter(|_| !response)
                .map(|f| fins_command(f[10], f[11]));
            self.request(Proto::Fins, client, server, ts, functions, None);
        } else {
            self.response(Proto::Fins, server, client, ts);
            if let Some(f) = header.filter(|_| response)
                && let Ok(mut fields) = parse_fins_controller_data(f)
                && let Some(s) = self.server(Proto::Fins, server)
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

    fn fins_tcp(body: &[u8], command: u32) -> Vec<u8> {
        let mut p = b"FINS".to_vec();
        p.extend(((body.len() + 8) as u32).to_be_bytes());
        p.extend(command.to_be_bytes());
        p.extend([0; 4]);
        p.extend(body);
        p
    }

    #[test]
    fn writes_run_and_stop_are_control_and_reads_are_not() {
        let mut t = Tracker::new();
        for (main, sub) in [(1u8, 1u8), (1, 2), (4, 2), (4, 1), (5, 1), (0x99, 0x99)] {
            let body = [0x80, 0, 2, 0, 0xc8, 0, 0, 0xfb, 0, 5, main, sub, 0];
            t.feed(&frame(HMI, PLC, true, 40000, 9600, &fins_tcp(&body, 2)), 1);
        }
        let s = &obs(&t, "Omron FINS server (observed)")[0];
        assert_eq!(
            s.fields["control_traffic"],
            "Memory Area Write x1, Run x1, Stop x1"
        );
        assert!(s.fields["functions"].contains("Controller Data Read x1"));
        assert!(s.fields["functions"].contains("FINS command 9999 x1"));
        // the handshake counts as presence and names no function
        let mut t = Tracker::new();
        t.feed(&frame(HMI, PLC, true, 40000, 9600, &fins_tcp(&[], 0)), 1);
        let s = &obs(&t, "Omron FINS server (observed)")[0];
        assert_eq!(s.fields["packets"], "1");
        assert!(!s.fields.contains_key("functions"));
        // something else on the port is ignored
        let mut t = Tracker::new();
        t.feed(
            &frame(HMI, PLC, true, 40000, 9600, b"GET / HTTP/1.1\r\n\r\n"),
            1,
        );
        assert!(t.observations().is_empty());
    }

    #[test]
    fn a_controller_data_response_names_the_model_over_tcp_and_udp() {
        use crate::ot::extra::tests::{FINS_REPLY, hex};
        let reply = hex(FINS_REPLY);
        let mut t = Tracker::new();
        t.feed(&frame(PLC, HMI, true, 9600, 40000, &fins_tcp(&reply, 2)), 1);
        let s = &obs(&t, "Omron FINS server (observed)")[0];
        assert_eq!(s.fields["model"], "CP1L-EL20DR-D");
        let mut t = Tracker::new();
        t.feed(&frame(PLC, HMI, false, 9600, 40000, &reply), 1);
        assert_eq!(
            obs(&t, "Omron FINS server (observed)")[0].fields["firmware"],
            "01.00"
        );
    }

    /// The command table, checked as a whole: every named command that changes something is
    /// flagged and no read is, and a code that is not in the table is listed by number and is
    /// never flagged (an unknown command must not raise a false control finding).
    #[test]
    fn the_command_table_flags_exactly_the_commands_that_change_state() {
        use super::fins_command;
        let changing = [
            "Write",
            "Fill",
            "Transfer",
            "Clear",
            "Run",
            "Stop",
            "Acquire",
            "Forced",
            "Delete",
            "Format",
            "Set/Reset",
        ];
        let mut named = 0;
        for main in 0..=0xffu8 {
            for sub in 0..=0xffu8 {
                let (name, control) = fins_command(main, sub);
                if let Some(code) = name.strip_prefix("FINS command ") {
                    assert_eq!(code, format!("{main:02X}{sub:02X}"));
                    assert!(!control, "an unnamed command is not flagged: {name}");
                    continue;
                }
                named += 1;
                let changes =
                    changing.iter().any(|w| name.contains(w)) && !name.contains("Release");
                assert_eq!(control, changes, "{main:02X}{sub:02X} {name}");
                assert!(
                    !control || !name.contains("Read"),
                    "{name} reads and is flagged"
                );
            }
        }
        assert_eq!(named, 32, "the table has 32 named commands");
        assert_eq!(fins_command(0x04, 0x02), ("Stop".to_string(), true));
        assert_eq!(
            fins_command(0x0c, 0x03),
            ("Access Right Release".to_string(), false)
        );
        assert_eq!(
            fins_command(0x01, 0x04),
            ("Multiple Memory Area Read".to_string(), false)
        );
    }
}
