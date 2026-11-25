// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! IEC 60870-5-104 ASDU types.

pub(super) fn iec104_type(t: u8) -> (String, bool) {
    match t {
        45 => ("C_SC single command".into(), true),
        46 => ("C_DC double command".into(), true),
        47 => ("C_RC regulating step command".into(), true),
        48..=51 => (format!("C_SE setpoint command (type {t})"), true),
        58..=64 => (format!("time-tagged command (type {t})"), true),
        100 => ("C_IC interrogation".into(), false),
        101 => ("C_CI counter interrogation".into(), false),
        102 => ("C_RD read".into(), false),
        103 => ("C_CS clock synchronisation".into(), true),
        105 => ("C_RP reset process".into(), true),
        other => (format!("ASDU type {other}"), false),
    }
}

#[cfg(test)]
mod tests {
    use super::iec104_type;

    /// Commands change the process (flagged); interrogation, read and everything the outstation
    /// reports on its own are not; an unknown type is listed by number and never flagged.
    #[test]
    fn command_types_are_flagged_and_monitoring_types_are_not() {
        for t in (45..=51).chain(58..=64).chain([103, 105]) {
            let (name, control) = iec104_type(t);
            assert!(control, "type {t} ({name}) is a command");
        }
        for t in [100, 101, 102] {
            let (name, control) = iec104_type(t);
            assert!(!control, "type {t} ({name}) only asks");
            assert!(name.starts_with("C_"), "{name}");
        }
        // Monitoring direction (M_SP, M_ME, M_IT, M_EI ...), the gaps between the command
        // ranges, and the end of the byte.
        for t in [
            0u8, 1, 3, 9, 13, 15, 30, 36, 44, 52, 57, 65, 99, 104, 106, 255,
        ] {
            let (name, control) = iec104_type(t);
            assert!(!control, "type {t} is not a command");
            assert_eq!(name, format!("ASDU type {t}"));
        }
        assert_eq!(iec104_type(45).0, "C_SC single command");
        assert_eq!(iec104_type(46).0, "C_DC double command");
        assert_eq!(iec104_type(47).0, "C_RC regulating step command");
        assert_eq!(iec104_type(50).0, "C_SE setpoint command (type 50)");
        assert_eq!(iec104_type(60).0, "time-tagged command (type 60)");
        assert_eq!(iec104_type(103).0, "C_CS clock synchronisation");
        assert_eq!(iec104_type(105).0, "C_RP reset process");
    }
}
