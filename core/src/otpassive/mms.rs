// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! TPKT/COTP on port 102 is shared by S7comm and IEC 61850 MMS. This module tells them apart
//! and decodes MMS (ISO 9506): the confirmed services of requests (named, with the ones that
//! write, start, stop or delete flagged as control traffic) and the vendor, model and revision of
//! an Identify response.
//!
//! The decision is made from what the connection carries, not from the port:
//!
//! - the first byte after the COTP data header is `0x32` (S7comm) or `0x72` (S7CommPlus) for S7;
//! - an MMS PDU tag (`0xA0`..`0xA9`, `0xAA`, `0xAD`, `0x85`, `0x86`, `0xA7`, `0x8B`, `0x8C`, as a
//!   bare PDU) or an ISO 8327 session SPDU (`0x0D` CONNECT, `0x0E` ACCEPT, `01 00` data transfer)
//!   is MMS;
//! - a COTP connection request whose TSAPs look like S7 (calling and called TSAP starting with 1, 2
//!   or 3, the PG, OP and other-device types) is S7; any other connection request waits until data
//!   decides, and is then counted for the protocol that data names.
//!
//! The state per connection is bounded.
use super::{Proto, Tracker, s7::s7_request};
use std::{collections::HashMap, net::IpAddr};

/// Connections remembered at the same time.
const MAX_FLOWS: usize = 4096;
/// Messages held back per connection until its protocol is known.
const MAX_PENDING: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Iso {
    S7,
    Mms,
}

/// One connection: client address, client port, server address.
pub(super) type FlowKey = (IpAddr, u16, IpAddr);

#[derive(Default)]
pub(super) struct Flow {
    kind: Option<Iso>,
    /// The first data TPDU decided: later data cannot change it (a continuation fragment starts
    /// with arbitrary bytes, and `2` and `r` are ordinary characters in MMS strings).
    decided: bool,
    /// (is a request, capture time) of the messages seen before the protocol was known.
    pending: Vec<(bool, i64)>,
}

/// The flow table of the tracker.
#[derive(Default)]
pub(super) struct IsoFlows {
    flows: HashMap<FlowKey, Flow>,
}

enum Cotp<'a> {
    /// Connection request; whether its TSAPs look like S7.
    Request {
        s7_like: bool,
    },
    Data(&'a [u8]),
    Other,
}

/// The COTP TPDU of a TPKT message.
fn cotp(pl: &[u8]) -> Option<Cotp<'_>> {
    if pl.len() < 7 || pl[0] != 3 || pl[1] != 0 {
        return None;
    }
    let li = usize::from(pl[4]);
    let user = pl.get(5 + li..).unwrap_or_default();
    Some(match pl[5] {
        0xf0 => Cotp::Data(user),
        0xe0 => {
            // parameters after the 6 fixed bytes: code, length, value
            let (mut calling, mut called) = (None, None);
            let params = pl.get(11..5 + li).unwrap_or_default();
            let mut i = 0;
            while i + 2 <= params.len() {
                let (code, len) = (params[i], usize::from(params[i + 1]));
                let value = params.get(i + 2..i + 2 + len).unwrap_or_default();
                match (code, value.len()) {
                    (0xc1, 2) => calling = Some(value[0]),
                    (0xc2, 2) => called = Some(value[0]),
                    _ => {}
                }
                i += 2 + len;
            }
            Cotp::Request {
                s7_like: matches!((calling, called), (Some(1..=3), Some(1..=3))),
            }
        }
        _ => Cotp::Other,
    })
}

/// What the first bytes of the user data of a COTP data TPDU say.
fn classify(user: &[u8]) -> Option<Iso> {
    match user.first()? {
        0x32 | 0x72 => Some(Iso::S7),
        0xa0..=0xa9 | 0xaa | 0xad | 0x85 | 0x86 | 0x8b | 0x8c => Some(Iso::Mms),
        0x0d | 0x0e => Some(Iso::Mms),
        0x01 if user.get(1) == Some(&0x00) => Some(Iso::Mms),
        _ => None,
    }
}

/// A BER TLV: (tag, value, rest).
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let (len, start): (usize, usize) = match *b.get(1)? {
        n if n < 0x80 => (usize::from(n), 2),
        0x81 => (usize::from(*b.get(2)?), 3),
        0x82 => (usize::from(u16::from_be_bytes([*b.get(2)?, *b.get(3)?])), 4),
        _ => return None,
    };
    let value = b.get(start..start.checked_add(len)?)?;
    Some((tag, value, &b[start + len..]))
}

/// The MMS PDU in the user data: bare, or inside the ISO session data transfer SPDU
/// (`01 00 01 00`) and presentation user data (`61 { 30 { 02 01 ctx, a0 { MMS } } }`).
fn mms_pdu(user: &[u8]) -> Option<&[u8]> {
    if matches!(
        user.first(),
        Some(0xa0..=0xa9 | 0xaa | 0xad | 0x85 | 0x86 | 0x8b | 0x8c)
    ) {
        return Some(user);
    }
    let after_session = user.strip_prefix(&[0x01, 0x00, 0x01, 0x00])?;
    let (tag, ppdu, _) = tlv(after_session)?;
    if tag != 0x61 {
        return None;
    }
    let (tag, pdv, _) = tlv(ppdu)?;
    if tag != 0x30 {
        return None;
    }
    let (tag, _, rest) = tlv(pdv)?; // presentation context identifier
    if tag != 0x02 {
        return None;
    }
    let (tag, inner, _) = tlv(rest)?;
    (tag == 0xa0).then_some(inner)
}

/// (name, control) of a confirmed service by its number in ConfirmedServiceRequest (ISO 9506-2).
fn service(n: u32) -> (String, bool) {
    let (name, control) = match n {
        0 => ("Status", false),
        1 => ("GetNameList", false),
        2 => ("Identify", false),
        4 => ("Read", false),
        5 => ("Write", true),
        6 => ("GetVariableAccessAttributes", false),
        12 => ("GetNamedVariableListAttributes", false),
        40 => ("Start Program Invocation", true),
        41 => ("Stop Program Invocation", true),
        42 => ("Resume Program Invocation", true),
        43 => ("Reset Program Invocation", true),
        44 => ("Kill Program Invocation", true),
        72 => ("FileOpen", false),
        73 => ("FileRead", false),
        74 => ("FileClose", false),
        75 => ("FileRename", true),
        76 => ("FileDelete", true),
        77 => ("FileDirectory", false),
        _ => return (format!("service {n}"), false),
    };
    (name.to_string(), control)
}

/// The service number of the first element after the invoke ID in a confirmed PDU body, from
/// its context tag (short form, or `1f`/`bf`/`9f` with a base-128 number).
fn service_number(after_invoke: &[u8]) -> Option<u32> {
    let tag = *after_invoke.first()?;
    if tag & 0xc0 != 0x80 {
        return None; // not context specific
    }
    if tag & 0x1f != 0x1f {
        return Some(u32::from(tag & 0x1f));
    }
    let mut n = 0u32;
    for b in after_invoke.get(1..)?.iter().take(3) {
        n = (n << 7) | u32::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Some(n);
        }
    }
    None
}

/// The functions of one MMS PDU: `(name, control)`.
fn pdu_functions(pdu: &[u8]) -> Vec<(String, bool)> {
    let Some((tag, body, _)) = tlv(pdu) else {
        return vec![];
    };
    match tag {
        0xa0 => {
            let Some((0x02, _, rest)) = tlv(body) else {
                return vec![];
            };
            service_number(rest)
                .map(|n| vec![service(n)])
                .unwrap_or_default()
        }
        0xa8 => vec![("Initiate".into(), false)],
        0x8b => vec![("Conclude".into(), false)],
        0xa3 => vec![("UnconfirmedService".into(), false)],
        _ => vec![],
    }
}

/// Vendor, model and revision of an Identify response (`a1 { 02 invokeID, a2 { 80 vendor, 81
/// model, 82 revision } }`).
fn identify_response(pdu: &[u8]) -> Option<[String; 3]> {
    let (0xa1, body, _) = tlv(pdu)? else {
        return None;
    };
    let (0x02, _, rest) = tlv(body)? else {
        return None;
    };
    let (0xa2, fields, _) = tlv(rest)? else {
        return None;
    };
    let (mut vendor, mut model, mut revision) = (String::new(), String::new(), String::new());
    let mut rest = fields;
    for _ in 0..4 {
        let Some((tag, value, next)) = tlv(rest) else {
            break;
        };
        let text = crate::ot::extra::clean_ascii(value);
        match tag {
            0x80 => vendor = text,
            0x81 => model = text,
            0x82 => revision = text,
            _ => {}
        }
        rest = next;
    }
    (!vendor.is_empty() || !model.is_empty()).then_some([vendor, model, revision])
}

impl Tracker {
    /// One TPKT message on port 102.
    pub(super) fn iso_message(
        &mut self,
        src: IpAddr,
        dst: IpAddr,
        sport: u16,
        dport: u16,
        pl: &[u8],
        ts: i64,
    ) {
        let to_server = dport == 102;
        let key: FlowKey = if to_server {
            (src, sport, dst)
        } else {
            (dst, dport, src)
        };
        let (client, server) = (key.0, key.2);
        let Some(unit) = cotp(pl) else { return };
        let data_kind = match &unit {
            Cotp::Data(user) => classify(user),
            _ => None,
        };
        if !self.iso.flows.contains_key(&key) && self.iso.flows.len() >= MAX_FLOWS {
            return;
        }
        let flow = self.iso.flows.entry(key).or_default();
        // data decides; a connection request that looks like S7 is S7 until data says otherwise
        if let Some(kind) = data_kind.filter(|_| !flow.decided) {
            flow.kind = Some(kind);
            flow.decided = true;
        } else if let Cotp::Request { s7_like: true } = unit
            && flow.kind.is_none()
        {
            flow.kind = Some(Iso::S7);
        }
        let Some(kind) = flow.kind else {
            if flow.pending.len() < MAX_PENDING {
                flow.pending.push((to_server, ts));
            }
            return;
        };
        let pending = std::mem::take(&mut flow.pending);
        let proto = if kind == Iso::S7 {
            Proto::S7
        } else {
            Proto::Mms
        };
        for (request, at) in pending {
            if request {
                self.request(proto, client, server, at, None, None);
            } else {
                self.response(proto, server, client, at);
            }
        }
        match (kind, to_server) {
            (Iso::S7, true) => match s7_request(pl) {
                Some(f) => self.request(
                    Proto::S7,
                    client,
                    server,
                    ts,
                    Some((f.0.to_string(), f.1)),
                    None,
                ),
                None => self.request(Proto::S7, client, server, ts, None, None),
            },
            (Iso::S7, false) => self.response(Proto::S7, server, client, ts),
            (Iso::Mms, true) => {
                let functions = match &unit {
                    Cotp::Data(user) => mms_pdu(user).map(pdu_functions).unwrap_or_default(),
                    _ => vec![],
                };
                self.request(Proto::Mms, client, server, ts, functions, None);
            }
            (Iso::Mms, false) => {
                self.response(Proto::Mms, server, client, ts);
                if let Cotp::Data(user) = &unit
                    && let Some([vendor, model, revision]) =
                        mms_pdu(user).and_then(identify_response)
                    && let Some(s) = self.server(Proto::Mms, server)
                {
                    for (key, value) in
                        [("vendor", vendor), ("model", model), ("firmware", revision)]
                    {
                        if !value.is_empty() {
                            s.fields.insert(key.into(), value);
                        }
                    }
                }
            }
        }
    }

    /// Connections whose protocol never became known are dropped at the end of a capture.
    pub(super) fn iso_flush(&mut self) {
        self.iso.flows.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otpassive::testutil::{HMI, PLC, frame, obs, s7};

    /// TPKT + COTP data header + user data.
    fn dt(user: &[u8]) -> Vec<u8> {
        let mut b = vec![3, 0, 0, 0, 2, 0xf0, 0x80];
        b.extend(user);
        let n = b.len() as u16;
        b[2..4].copy_from_slice(&n.to_be_bytes());
        b
    }
    fn confirmed(service_tag: &[u8]) -> Vec<u8> {
        let mut body = vec![0x02, 0x01, 0x01];
        body.extend(service_tag);
        let mut pdu = vec![0xa0, body.len() as u8];
        pdu.extend(body);
        pdu
    }
    const CR_MMS: [u8; 19] = [
        3, 0, 0, 19, 0x0e, 0xe0, 0, 0, 0, 6, 0, 0xc1, 2, 0, 2, 0xc2, 2, 2, 0,
    ];

    #[test]
    fn mms_is_told_from_s7_by_what_the_connection_carries() {
        let mut t = Tracker::new();
        // an MMS client: a connection request that does not look like S7, then Initiate, Read, Stop
        t.feed(&frame(HMI, PLC, true, 40000, 102, &CR_MMS), 1);
        t.feed(
            &frame(PLC, HMI, true, 102, 40000, &[3, 0, 0, 7, 2, 0xd0, 0x80]),
            2,
        );
        assert!(
            t.observations().is_empty(),
            "undecided until data: {:?}",
            t.observations()
        );
        t.feed(&frame(HMI, PLC, true, 40000, 102, &dt(&[0xa8, 0x00])), 3);
        t.feed(
            &frame(HMI, PLC, true, 40000, 102, &dt(&confirmed(&[0xa4, 0x00]))),
            4,
        );
        t.feed(
            &frame(
                HMI,
                PLC,
                true,
                40000,
                102,
                &dt(&confirmed(&[0xbf, 0x29, 0x00])),
            ),
            5,
        );
        t.feed(
            &frame(HMI, PLC, true, 40000, 102, &dt(&confirmed(&[0xa5, 0x00]))),
            6,
        );
        let s = &obs(&t, "IEC 61850 MMS server (observed)")[0];
        assert_eq!(
            s.fields["control_traffic"],
            "Stop Program Invocation x1, Write x1"
        );
        assert!(
            s.fields["functions"].contains("Read x1")
                && s.fields["functions"].contains("Initiate x1")
        );
        assert_eq!(
            s.fields["packets"], "6",
            "the held-back connection request and confirm are counted"
        );
        assert!(obs(&t, "S7comm server (observed)").is_empty());
        // an S7 client: S7-like request and an S7 job
        let cr_s7 = [
            3, 0, 0, 22, 17, 0xe0, 0, 0, 0, 1, 0, 0xc1, 2, 1, 0, 0xc2, 2, 1, 2, 0xc0, 1, 10,
        ];
        let mut t = Tracker::new();
        t.feed(&frame(HMI, PLC, true, 40001, 102, &cr_s7), 1);
        t.feed(&frame(HMI, PLC, true, 40001, 102, &s7(0x04, 1)), 2);
        assert_eq!(obs(&t, "S7comm server (observed)").len(), 1);
        assert!(obs(&t, "IEC 61850 MMS server (observed)").is_empty());
        // S7CommPlus (first byte 0x72) is S7, not MMS
        let mut t = Tracker::new();
        t.feed(&frame(HMI, PLC, true, 40002, 102, &dt(&[0x72, 1, 0, 0])), 1);
        assert_eq!(obs(&t, "S7comm server (observed)").len(), 1);
        assert!(obs(&t, "IEC 61850 MMS server (observed)").is_empty());
        // a flow nobody could decide is dropped at the end, not guessed
        let mut t = Tracker::new();
        t.feed(&frame(HMI, PLC, true, 40003, 102, &CR_MMS), 1);
        t.flush();
        assert!(t.observations().is_empty());
    }

    #[test]
    fn the_first_data_decides_and_a_later_fragment_cannot_flip_it() {
        let mut t = Tracker::new();
        t.feed(&frame(HMI, PLC, true, 40000, 102, &dt(&[0xa8, 0])), 1);
        // a continuation fragment of a long MMS message that happens to start with '2' and 'r'
        t.feed(&frame(PLC, HMI, true, 102, 40000, &dt(&[0x32, 1, 2, 3])), 2);
        t.feed(&frame(PLC, HMI, true, 102, 40000, &dt(&[0x72, 1, 2, 3])), 3);
        assert!(obs(&t, "S7comm server (observed)").is_empty());
        assert_eq!(
            obs(&t, "IEC 61850 MMS server (observed)")[0].fields["packets"],
            "3"
        );
        // and the other way round: S7 stays S7 when a later fragment starts like an MMS PDU
        let mut t = Tracker::new();
        t.feed(&frame(HMI, PLC, true, 40001, 102, &s7(0x04, 1)), 1);
        t.feed(&frame(HMI, PLC, true, 40001, 102, &dt(&[0xa0, 1, 2])), 2);
        assert!(obs(&t, "IEC 61850 MMS server (observed)").is_empty());
        assert_eq!(
            obs(&t, "S7comm server (observed)")[0].fields["packets"],
            "2"
        );
    }

    #[test]
    fn full_stack_mms_is_unwrapped_from_session_and_presentation() {
        // session data transfer, presentation user data (context 3), MMS Write
        let mms = confirmed(&[0xa5, 0x00]);
        let mut a0 = vec![0xa0, mms.len() as u8];
        a0.extend(&mms);
        let mut pdv = vec![0x02, 0x01, 0x03];
        pdv.extend(&a0);
        let mut seq = vec![0x30, pdv.len() as u8];
        seq.extend(&pdv);
        let mut ppdu = vec![0x61, seq.len() as u8];
        ppdu.extend(&seq);
        let mut user = vec![0x01, 0x00, 0x01, 0x00];
        user.extend(&ppdu);
        let mut t = Tracker::new();
        t.feed(&frame(HMI, PLC, true, 40000, 102, &dt(&user)), 1);
        let s = &obs(&t, "IEC 61850 MMS server (observed)")[0];
        assert_eq!(s.fields["control_traffic"], "Write x1");
        // the session CONNECT alone marks the protocol
        let mut t = Tracker::new();
        t.feed(
            &frame(HMI, PLC, true, 40000, 102, &dt(&[0x0d, 0x05, 0x01])),
            1,
        );
        assert_eq!(obs(&t, "IEC 61850 MMS server (observed)").len(), 1);
    }

    #[test]
    fn identify_response_names_vendor_model_and_revision() {
        let mut fields = vec![];
        for (tag, text) in [(0x80u8, &b"ACME"[..]), (0x81, b"IED-1"), (0x82, b"2.3")] {
            fields.extend([tag, text.len() as u8]);
            fields.extend(text);
        }
        let mut service = vec![0xa2, fields.len() as u8];
        service.extend(&fields);
        let mut body = vec![0x02, 0x01, 0x01];
        body.extend(&service);
        let mut pdu = vec![0xa1, body.len() as u8];
        pdu.extend(&body);
        let mut t = Tracker::new();
        t.feed(&frame(HMI, PLC, true, 40000, 102, &dt(&[0xa8, 0])), 1);
        t.feed(&frame(PLC, HMI, true, 102, 40000, &dt(&pdu)), 2);
        let s = &obs(&t, "IEC 61850 MMS server (observed)")[0];
        assert_eq!(
            (
                s.fields["vendor"].as_str(),
                s.fields["model"].as_str(),
                s.fields["firmware"].as_str()
            ),
            ("ACME", "IED-1", "2.3")
        );
    }

    #[test]
    fn malformed_pdus_and_flow_limits_are_bounded() {
        for cut in 0..8 {
            let pdu = confirmed(&[0xbf, 0x29, 0x00]);
            let mut t = Tracker::new();
            t.feed(
                &frame(HMI, PLC, true, 40000, 102, &dt(&pdu[..pdu.len().min(cut)])),
                1,
            );
        }
        assert!(pdu_functions(&[0xa0, 0x84, 0xff, 0xff, 0xff, 0xff]).is_empty());
        assert!(service_number(&[0xbf, 0xff, 0xff, 0xff, 0xff]).is_none());
        assert!(identify_response(&[0xa1, 0x02, 0x02, 0x00]).is_none());
        // a thousand connections that never say what they are: held back, then dropped
        let mut t = Tracker::new();
        for port in 1000..6000u16 {
            t.feed(&frame(HMI, PLC, true, port, 102, &CR_MMS), 1);
        }
        assert!(t.iso.flows.len() <= MAX_FLOWS);
        assert!(t.observations().is_empty());
    }
}
