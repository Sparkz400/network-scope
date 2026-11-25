// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Modbus/TCP function codes.
use super::packet::be16;

/// `pdu`: function code and data (the bytes after the unit identifier).
pub(super) fn modbus_function(pdu: &[u8]) -> (String, bool) {
    let fc = pdu.first().copied().unwrap_or(0);
    if fc == 8 {
        // Diagnostics: some sub-functions change the device's communication state.
        return match be16(pdu, 1) {
            Some(1) => ("Diagnostics: Restart Communications".into(), true),
            Some(4) => ("Diagnostics: Force Listen Only Mode".into(), true),
            Some(10) => ("Diagnostics: Clear Counters".into(), false),
            _ => ("Diagnostics".into(), false),
        };
    }
    let (name, control) = match fc & 0x7f {
        1 => ("Read Coils", false),
        2 => ("Read Discrete Inputs", false),
        3 => ("Read Holding Registers", false),
        4 => ("Read Input Registers", false),
        5 => ("Write Single Coil", true),
        6 => ("Write Single Register", true),
        7 => ("Read Exception Status", false),
        8 => ("Diagnostics", false),
        15 => ("Write Multiple Coils", true),
        16 => ("Write Multiple Registers", true),
        17 => ("Report Server ID", false),
        20 => ("Read File Record", false),
        21 => ("Write File Record", true),
        22 => ("Mask Write Register", true),
        23 => ("Read/Write Multiple Registers", true),
        43 => ("Read Device Identification", false),
        other => return (format!("function {other}"), false),
    };
    (name.to_string(), control)
}

#[cfg(test)]
mod tests {
    use crate::otpassive::Tracker;
    use crate::otpassive::testutil::{HMI, PLC, frame, obs};

    #[test]
    fn modbus_writes_are_control_traffic() {
        let mut t = Tracker::new();
        // transaction 1, protocol 0, length 6, unit 7, function 3 (read), then 6 (write single register)
        t.feed(
            &frame(
                HMI,
                PLC,
                true,
                50000,
                502,
                &[0, 1, 0, 0, 0, 6, 7, 3, 0, 0, 0, 2],
            ),
            100,
        );
        t.feed(
            &frame(
                PLC,
                HMI,
                true,
                502,
                50000,
                &[0, 1, 0, 0, 0, 7, 7, 3, 4, 0, 1, 0, 2],
            ),
            101,
        );
        t.feed(
            &frame(
                HMI,
                PLC,
                true,
                50000,
                502,
                &[0, 2, 0, 0, 0, 6, 7, 6, 0, 5, 0, 9],
            ),
            105,
        );
        t.feed(
            &frame(
                HMI,
                PLC,
                true,
                50000,
                502,
                &[0, 3, 0, 0, 0, 6, 7, 6, 0, 5, 0, 9],
            ),
            106,
        );
        let s = &obs(&t, "Modbus/TCP server (observed)")[0];
        assert_eq!(s.ip.unwrap().to_string(), "10.0.0.10");
        assert_eq!(s.fields["unit_ids"], "7");
        assert_eq!(s.fields["control_traffic"], "Write Single Register x2");
        assert!(s.fields["functions"].contains("Read Holding Registers x1"));
        assert_eq!(
            (
                s.fields["first_seen"].as_str(),
                s.fields["last_seen"].as_str(),
                s.fields["packets"].as_str()
            ),
            ("100", "106", "4")
        );
        assert_eq!(s.fields["clients"], "10.0.0.50");
        let c = &obs(&t, "Modbus/TCP client (observed)")[0];
        assert_eq!(c.ip.unwrap().to_string(), "10.0.0.50");
        assert_eq!(c.fields["servers"], "10.0.0.10");
        // A non-Modbus payload on port 502 is ignored.
        let mut t = Tracker::new();
        t.feed(
            &frame(HMI, PLC, true, 50000, 502, b"GET / HTTP/1.1\r\n\r\n"),
            1,
        );
        assert!(t.observations().is_empty());
    }
}
