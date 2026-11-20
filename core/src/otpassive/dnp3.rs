//! DNP3 (IEEE 1815, TCP 20000): data link frames, application function codes, the data link
//! addresses of master and outstation and the internal indications (IIN) of responses.
//!
//! A TCP segment may hold several data link frames. Each frame is a 10-byte header (`05 64`,
//! length, control, destination and source address, CRC) followed by user data in blocks of 16
//! bytes that each carry a 2-byte CRC. The CRCs are not checked (a capture may be cut short);
//! lengths are bounded and a frame that does not fit ends the segment.
use super::{Proto, Tracker};
use std::net::IpAddr;

pub(super) fn dnp3_function(f: u8) -> (String, bool) {
    let (n, c) = match f {
        0 => ("Confirm", false),
        1 => ("Read", false),
        2 => ("Write", true),
        3 => ("Select", true),
        4 => ("Operate", true),
        5 => ("Direct Operate", true),
        6 => ("Direct Operate (no ack)", true),
        7 => ("Immediate Freeze", true),
        8 => ("Immediate Freeze (no ack)", true),
        9 => ("Freeze and Clear", true),
        10 => ("Freeze and Clear (no ack)", true),
        11 => ("Freeze at Time", true),
        12 => ("Freeze at Time (no ack)", true),
        13 => ("Cold Restart", true),
        14 => ("Warm Restart", true),
        15 => ("Initialize Data", true),
        16 => ("Initialize Application", true),
        17 => ("Start Application", true),
        18 => ("Stop Application", true),
        19 => ("Save Configuration", true),
        20 => ("Enable Unsolicited", false),
        21 => ("Disable Unsolicited", true),
        22 => ("Assign Class", true),
        23 => ("Delay Measurement", false),
        24 => ("Record Current Time", false),
        25 => ("Open File", false),
        26 => ("Close File", false),
        27 => ("Delete File", true),
        28 => ("Get File Info", false),
        29 => ("Authenticate File", false),
        30 => ("Abort File", false),
        31 => ("Activate Config", true),
        32 => ("Authentication Request", false),
        33 => ("Authentication Error", false),
        129 => ("Response", false),
        130 => ("Unsolicited Response", false),
        131 => ("Authentication Response", false),
        _ => return (format!("function {f}"), false),
    };
    (n.to_string(), c)
}

/// Most data link frames read from one segment.
const MAX_FRAMES: usize = 16;

/// One data link frame: control byte, destination, source and the first bytes of the user data
/// (transport header, application control, function code, IIN).
struct Frame {
    control: u8,
    dest: u16,
    source: u16,
    /// transport header, application control, function, IIN1, IIN2 (as many as there are)
    app: Vec<u8>,
}

fn frames(mut b: &[u8]) -> Vec<Frame> {
    let mut out = vec![];
    while out.len() < MAX_FRAMES && b.len() >= 10 && b[0] == 0x05 && b[1] == 0x64 {
        let length = usize::from(b[2]);
        if length < 5 {
            break;
        }
        let data = length - 5;
        let total = 10 + data + 2 * data.div_ceil(16);
        // the frame may be cut short: take what the first block holds
        let first = &b[10..b.len().min(10 + data.min(16))];
        out.push(Frame {
            control: b[3],
            dest: u16::from_le_bytes([b[4], b[5]]),
            source: u16::from_le_bytes([b[6], b[7]]),
            app: first.iter().copied().take(7).collect(),
        });
        if total > b.len() {
            break;
        }
        b = &b[total..];
    }
    out
}

/// IIN bits (IEEE 1815 table 4-1) that say something about the outstation, by name.
fn iin_flags(iin1: u8, iin2: u8) -> Vec<&'static str> {
    let mut out = vec![];
    for (bit, name) in [
        (0x20u8, "local control"),
        (0x40, "device trouble"),
        (0x80, "device restart"),
        (0x10, "need time"),
    ] {
        if iin1 & bit != 0 {
            out.push(name);
        }
    }
    for (bit, name) in [
        (0x01u8, "function code not supported"),
        (0x02, "object unknown"),
        (0x04, "parameter error"),
        (0x08, "event buffer overflow"),
        (0x20, "configuration corrupt"),
    ] {
        if iin2 & bit != 0 {
            out.push(name);
        }
    }
    out
}

/// Adds `items` to a comma separated field, keeping it bounded.
fn add_to_list(fields: &mut std::collections::BTreeMap<String, String>, key: &str, items: &[&str]) {
    let mut list: Vec<String> = fields
        .get(key)
        .map(|v| v.split(", ").map(str::to_string).collect())
        .unwrap_or_default();
    for item in items {
        if list.len() < 16 && !list.iter().any(|l| l == item) {
            list.push((*item).to_string());
        }
    }
    list.sort();
    if !list.is_empty() {
        fields.insert(key.into(), list.join(", "));
    }
}

impl Tracker {
    /// A TCP segment on port 20000; `to_server` is the direction towards the outstation.
    pub(super) fn dnp3(
        &mut self,
        client: IpAddr,
        server: IpAddr,
        pl: &[u8],
        ts: i64,
        to_server: bool,
    ) {
        let list = frames(pl);
        if list.is_empty() {
            return;
        }
        if to_server {
            // only the first frame of a fragment (FIR) carries the application header
            let functions: Vec<(String, bool)> = list
                .iter()
                .filter(|f| f.app.first().is_some_and(|t| t & 0x40 != 0))
                .filter_map(|f| f.app.get(2).copied())
                .map(dnp3_function)
                .collect();
            // primary frames from the master: the destination is the outstation
            let master = list.iter().find(|f| f.control & 0xc0 == 0xc0);
            self.request(Proto::Dnp3, client, server, ts, functions, None);
            if let Some(m) = master {
                if !(0xfff0..=0xffff).contains(&m.dest)
                    && let Some(s) = self.server(Proto::Dnp3, server)
                {
                    s.fields.insert("link_address".into(), m.dest.to_string());
                }
                if let Some(c) = self.client(Proto::Dnp3, client) {
                    c.fields.insert("link_address".into(), m.source.to_string());
                }
            }
        } else {
            self.response(Proto::Dnp3, server, client, ts);
            // the outstation's own address is the source of its frames; response and
            // unsolicited response carry the IIN after the function code
            let mut flags: Vec<&str> = vec![];
            let mut address = None;
            for f in &list {
                address = Some(f.source);
                if f.app.first().is_some_and(|t| t & 0x40 != 0)
                    && matches!(f.app.get(2), Some(0x81 | 0x82))
                    && let (Some(&a), Some(&b)) = (f.app.get(3), f.app.get(4))
                {
                    flags.extend(iin_flags(a, b));
                }
            }
            if let Some(s) = self.server(Proto::Dnp3, server) {
                if let Some(a) = address {
                    s.fields.insert("link_address".into(), a.to_string());
                }
                add_to_list(&mut s.fields, "iin", &flags);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otpassive::testutil::{HMI, PLC, frame, obs};

    /// One data link frame with a single-block user data: control, destination, source, user
    /// data (CRCs are zero: they are not checked).
    fn link(control: u8, dest: u16, source: u16, user: &[u8]) -> Vec<u8> {
        let mut b = vec![0x05, 0x64, (user.len() + 5) as u8, control];
        b.extend(dest.to_le_bytes());
        b.extend(source.to_le_bytes());
        b.extend([0, 0]);
        for block in user.chunks(16) {
            b.extend(block);
            b.extend([0, 0]);
        }
        b
    }

    #[test]
    fn function_names_cover_the_standard_codes() {
        assert_eq!(dnp3_function(19), ("Save Configuration".into(), true));
        assert_eq!(dnp3_function(27), ("Delete File".into(), true));
        assert_eq!(dnp3_function(129), ("Response".into(), false));
        assert_eq!(dnp3_function(200), ("function 200".into(), false));
        // freezes change counters, restarts and file deletes are flagged; reads are not
        for (code, control) in [
            (1u8, false),
            (7, true),
            (13, true),
            (23, false),
            (25, false),
        ] {
            assert_eq!(dnp3_function(code).1, control, "{code}");
        }
    }

    /// Every function code, once: the ones that change the outstation (writes, selects and
    /// operates, freezes, restarts, application control, file deletes, assigning classes and
    /// disabling unsolicited reports) are flagged, reads, confirms, responses and the
    /// authentication messages are not, and a code outside the standard is listed by number.
    #[test]
    fn every_function_code_is_named_or_listed_by_number_and_flagged_correctly() {
        let changing: Vec<u8> = (2..=19).chain([21, 22, 27, 31]).collect();
        let standard: Vec<u8> = (0..=33).chain(129..=131).collect();
        for code in 0..=255u8 {
            let (name, control) = dnp3_function(code);
            assert_eq!(control, changing.contains(&code), "{code} {name}");
            if standard.contains(&code) {
                assert!(!name.starts_with("function"), "{code} should be named");
            } else {
                assert_eq!(name, format!("function {code}"));
            }
        }
        assert_eq!(dnp3_function(2).0, "Write");
        assert_eq!(dnp3_function(13).0, "Cold Restart");
        assert_eq!(dnp3_function(20), ("Enable Unsolicited".into(), false));
        assert_eq!(dnp3_function(21), ("Disable Unsolicited".into(), true));
        assert_eq!(dnp3_function(130).0, "Unsolicited Response");
    }

    #[test]
    fn addresses_functions_and_iin_of_a_conversation() {
        let mut t = Tracker::new();
        // master 1 reads from outstation 10; the response has "device restart" and "need time"
        t.feed(
            &frame(
                HMI,
                PLC,
                true,
                40000,
                20000,
                &link(0xc4, 10, 1, &[0xc0, 0xc0, 1, 0x3c, 2, 6]),
            ),
            1,
        );
        t.feed(
            &frame(
                PLC,
                HMI,
                true,
                20000,
                40000,
                &link(0x44, 1, 10, &[0xc0, 0xc1, 0x81, 0x90, 0x01]),
            ),
            2,
        );
        let s = &obs(&t, "DNP3 server (observed)")[0];
        assert_eq!(s.fields["link_address"], "10");
        assert_eq!(
            s.fields["iin"],
            "device restart, function code not supported, need time"
        );
        assert_eq!(s.fields["functions"], "Read x1");
        let c = &obs(&t, "DNP3 client (observed)")[0];
        assert_eq!(c.fields["link_address"], "1");
        // a broadcast destination is not the outstation's address
        let mut t = Tracker::new();
        t.feed(
            &frame(
                HMI,
                PLC,
                true,
                40000,
                20000,
                &link(0xc4, 0xffff, 1, &[0xc0, 0xc0, 2]),
            ),
            1,
        );
        let s = &obs(&t, "DNP3 server (observed)")[0];
        assert!(!s.fields.contains_key("link_address"));
        assert_eq!(s.fields["control_traffic"], "Write x1");
    }

    #[test]
    fn several_frames_in_one_segment_and_continuation_frames() {
        let mut segment = link(0xc4, 10, 1, &[0xc0, 0xc0, 3, 1, 2, 3]);
        segment.extend(link(0xc4, 10, 1, &[0xc1, 0xc1, 4, 1, 2, 3]));
        // a continuation frame (no FIR) holds no function
        segment.extend(link(0xc4, 10, 1, &[0x01, 0xff, 0xff]));
        // a link status request has no user data at all
        segment.extend(link(0xc9, 10, 1, &[]));
        let mut t = Tracker::new();
        t.feed(&frame(HMI, PLC, true, 40000, 20000, &segment), 1);
        let s = &obs(&t, "DNP3 server (observed)")[0];
        assert_eq!(s.fields["control_traffic"], "Operate x1, Select x1");
        assert_eq!(s.fields["packets"], "1", "one segment is one packet");
    }

    #[test]
    fn a_long_user_data_block_sequence_is_read_by_its_first_block() {
        let user: Vec<u8> = [0xc0u8, 0xc0, 5].into_iter().chain(0..40).collect();
        let mut t = Tracker::new();
        t.feed(
            &frame(HMI, PLC, true, 40000, 20000, &link(0xc4, 10, 1, &user)),
            1,
        );
        assert_eq!(
            obs(&t, "DNP3 server (observed)")[0].fields["control_traffic"],
            "Direct Operate x1"
        );
    }

    #[test]
    fn garbage_and_cut_frames_are_bounded() {
        let mut t = Tracker::new();
        for pl in [
            &[0x05u8, 0x64][..],
            &[0x05, 0x64, 3, 0xc4, 10, 0, 1, 0, 0, 0],
            &[0x05, 0x64, 0xff, 0xc4, 10, 0, 1, 0, 0, 0, 0xc0],
            &[0x05; 40],
        ] {
            t.feed(&frame(HMI, PLC, true, 40000, 20000, pl), 1);
        }
        // sixty-four frames: only MAX_FRAMES are read
        assert_eq!(
            frames(&link(0xc4, 1, 2, &[0xc0, 0xc0, 1]).repeat(64)).len(),
            MAX_FRAMES
        );
        assert!(frames(&[]).is_empty());
        // the IIN list is bounded and sorted
        let mut f = std::collections::BTreeMap::new();
        add_to_list(&mut f, "iin", &["b", "a", "b"]);
        add_to_list(&mut f, "iin", &["c"]);
        assert_eq!(f["iin"], "a, b, c");
    }
}
