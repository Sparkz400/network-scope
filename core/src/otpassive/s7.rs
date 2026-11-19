//! S7comm (TPKT/COTP) request decoding.

fn s7_function(f: u8) -> Option<(&'static str, bool)> {
    Some(match f {
        0x04 => ("Read Var", false),
        0x05 => ("Write Var", true),
        0x1a => ("Request Download", true),
        0x1b => ("Download Block", true),
        0x1c => ("Download Ended", true),
        0x1d => ("Start Upload", false),
        0x1e => ("Upload", false),
        0x1f => ("End Upload", false),
        0x28 => ("PLC Control", true),
        0x29 => ("PLC Stop", true),
        0xf0 => ("Setup Communication", false),
        _ => return None,
    })
}

pub(super) fn s7_request(pl: &[u8]) -> Option<(&'static str, bool)> {
    if pl.len() < 17 || pl[0] != 3 || pl[1] != 0 {
        return None;
    }
    let cotp = 4 + 1 + usize::from(pl[4]);
    let s7 = pl.get(cotp..)?;
    if s7.first() != Some(&0x32) || s7.get(1) != Some(&1) {
        return None;
    }
    s7_function(*s7.get(10)?)
}

#[cfg(test)]
mod tests {
    use crate::otpassive::testutil::{HMI, PLC, frame, obs, s7};
    use crate::otpassive::{Tracker, control_findings};
    use crate::risk::Severity;

    #[test]
    fn s7_stop_and_download_are_flagged() {
        let mut t = Tracker::new();
        t.feed(&frame(HMI, PLC, true, 40000, 102, &s7(0x04, 1)), 1);
        t.feed(&frame(HMI, PLC, true, 40000, 102, &s7(0x29, 1)), 2);
        t.feed(&frame(HMI, PLC, true, 40000, 102, &s7(0x1a, 1)), 3);
        t.feed(&frame(PLC, HMI, true, 102, 40000, &s7(0x29, 3)), 4);
        let s = &obs(&t, "S7comm server (observed)")[0];
        assert_eq!(
            s.fields["control_traffic"],
            "PLC Stop x1, Request Download x1"
        );
        assert!(!s.fields["control_traffic"].contains("Read"));
        assert_eq!(s.fields["packets"], "4");
        let findings = control_findings(&t.observations());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].0, Severity::High);
    }
}
