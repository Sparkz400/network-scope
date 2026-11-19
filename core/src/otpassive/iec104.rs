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
