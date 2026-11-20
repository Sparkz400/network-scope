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

    /// Which S7 functions are named, which change the controller, and that nothing else is.
    #[test]
    fn the_function_table_names_eleven_functions_and_flags_the_changing_ones() {
        use super::s7_function;
        let table = [
            (0x04u8, "Read Var", false),
            (0x05, "Write Var", true),
            (0x1a, "Request Download", true),
            (0x1b, "Download Block", true),
            (0x1c, "Download Ended", true),
            (0x1d, "Start Upload", false),
            (0x1e, "Upload", false),
            (0x1f, "End Upload", false),
            (0x28, "PLC Control", true),
            (0x29, "PLC Stop", true),
            (0xf0, "Setup Communication", false),
        ];
        for (f, name, control) in table {
            assert_eq!(s7_function(f), Some((name, control)), "{f:#04x}");
        }
        let named = (0..=255u8).filter(|f| s7_function(*f).is_some()).count();
        assert_eq!(named, table.len());
    }

    /// Only a well-formed S7 job (TPKT, COTP, protocol id 0x32, ROSCTR 1) is decoded: an
    /// acknowledgement, a truncated frame and anything that is not S7 are not.
    #[test]
    fn only_s7_jobs_are_decoded() {
        use super::s7_request;
        assert_eq!(s7_request(&s7(0x05, 1)), Some(("Write Var", true)));
        assert_eq!(s7_request(&s7(0x04, 1)), Some(("Read Var", false)));
        assert_eq!(
            s7_request(&s7(0x29, 3)),
            None,
            "an ack-data PDU is not a request"
        );
        assert_eq!(s7_request(&s7(0x77, 1)), None, "an unknown function");
        let good = s7(0x29, 1);
        for cut in 0..good.len() - 1 {
            assert_eq!(s7_request(&good[..cut]), None, "cut at {cut}");
        }
        let mut not_tpkt = good.clone();
        not_tpkt[0] = 4;
        assert_eq!(s7_request(&not_tpkt), None);
        let mut not_s7 = good.clone();
        not_s7[7] = 0x72; // the S7 protocol id
        assert_eq!(s7_request(&not_s7), None);
        let mut long_cotp = good.clone();
        long_cotp[4] = 200; // a COTP header that runs past the frame
        assert_eq!(s7_request(&long_cotp), None);
    }
}
