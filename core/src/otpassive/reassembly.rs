// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! TCP reassembly-lite for the framed OT protocols (bounded memory, in order only).
use super::packet::{be16, le16};
use std::{collections::HashMap, net::IpAddr};

/// Largest message buffered for one flow; a longer message is decoded from its first segment.
const MAX_FLOW_BYTES: usize = 16 * 1024;
/// Flows with a partial message at the same time.
const MAX_FLOWS: usize = 1024;
/// All buffered bytes together.
const MAX_TOTAL_BYTES: usize = 4 * 1024 * 1024;
/// A partial message older than this (capture time) is given up.
const FLOW_IDLE_SECS: i64 = 120;

/// (source, source port, destination, destination port)
pub(super) type FlowKey = (IpAddr, u16, IpAddr, u16);

struct Flow {
    /// Sequence number of the next byte expected.
    next_seq: u32,
    buf: Vec<u8>,
    last: i64,
    dst_group: bool,
}

/// A message (or best-effort fragment) ready for the decoders.
pub(super) struct Pdu {
    pub(super) key: FlowKey,
    pub(super) dst_group: bool,
    pub(super) data: Vec<u8>,
    /// Capture time of the last segment that contributed.
    pub(super) ts: i64,
}

/// Per-flow buffers for OT messages split across TCP segments. In order only: a gap, an
/// out-of-order segment, FIN/RST, idle expiry or the end of the capture gives up the buffered
/// prefix, which is then decoded best-effort (what a decoder without reassembly would see).
#[derive(Default)]
pub(super) struct Reassembly {
    flows: HashMap<FlowKey, Flow>,
    bytes: usize,
    pub(super) disabled: bool,
    last_sweep: i64,
    /// Partial messages given up (gap, out of order, limits, idle, end of capture).
    pub(super) abandoned: u64,
    /// Messages completed from two or more segments.
    pub(super) reassembled: u64,
}

/// Ports whose TCP messages carry a length field `message_len` understands.
pub(super) fn framed_port(sport: u16, dport: u16) -> Option<u16> {
    [502, 102, 2404, 44818, 4840]
        .into_iter()
        .find(|p| *p == dport || *p == sport)
}

enum Framing {
    /// The message at the start is this long (it may be longer than the data at hand).
    Len(usize),
    /// Too short to read the length, but what is there fits the protocol.
    NeedHeader,
    /// Not this protocol's framing: decode as is, never buffer.
    NotFramed,
}

/// Length of the OT message at the start of `b` for server port `port`.
fn message_len(port: u16, b: &[u8]) -> Framing {
    use Framing::*;
    let le16 = |i: usize| le16(b, i).map(usize::from);
    match port {
        502 => {
            // MBAP: transaction(2) protocol 0 (2) length(2) - length counts unit id + PDU
            if b.len() >= 4 && b[2..4] != [0, 0] {
                return NotFramed;
            }
            match be16(b, 4).map(usize::from) {
                None => NeedHeader,
                Some(n) if (2..=254).contains(&n) => Len(6 + n),
                Some(_) => NotFramed,
            }
        }
        102 => {
            // TPKT: version 3, reserved 0, total length(2)
            if b.first().is_some_and(|v| *v != 3) || b.get(1).is_some_and(|v| *v != 0) {
                return NotFramed;
            }
            match be16(b, 2).map(usize::from) {
                None => NeedHeader,
                Some(n) if n >= 7 => Len(n),
                Some(_) => NotFramed,
            }
        }
        2404 => {
            // APCI: start 0x68, length of the rest (>= 4)
            match (b.first(), b.get(1)) {
                (Some(0x68), Some(n)) if *n >= 4 => Len(2 + usize::from(*n)),
                (Some(0x68), None) => NeedHeader,
                _ => NotFramed,
            }
        }
        44818 => {
            // encapsulation header: command(2) length(2) ... 24 bytes, then `length` bytes
            const COMMANDS: [usize; 10] =
                [0x01, 0x04, 0x63, 0x64, 0x65, 0x66, 0x6f, 0x70, 0x72, 0x73];
            match (le16(0), le16(2)) {
                (Some(c), _) if !COMMANDS.contains(&c) => NotFramed,
                (Some(_), Some(n)) => Len(24 + n),
                _ => NeedHeader,
            }
        }
        4840 => {
            // message type(3) chunk type(1) size(4, little-endian, whole message)
            const TYPES: [&[u8]; 6] = [b"HEL", b"ACK", b"OPN", b"MSG", b"CLO", b"ERR"];
            let head = &b[..b.len().min(3)];
            if !TYPES.iter().any(|t| t.starts_with(head))
                || b.get(3).is_some_and(|c| !b"FCA".contains(c))
            {
                return NotFramed;
            }
            match b.get(4..8) {
                None => NeedHeader,
                Some(n) => {
                    let n = u32::from_le_bytes([n[0], n[1], n[2], n[3]]) as usize;
                    if n >= 8 { Len(n) } else { NotFramed }
                }
            }
        }
        _ => NotFramed,
    }
}

/// `a` is at or before `b` in sequence space.
fn seq_le(a: u32, b: u32) -> bool {
    (b.wrapping_sub(a) as i32) >= 0
}

impl Reassembly {
    fn take(&mut self, key: &FlowKey) -> Option<Flow> {
        let flow = self.flows.remove(key)?;
        self.bytes -= flow.buf.len();
        Some(flow)
    }
    fn give_up(&mut self, key: FlowKey, flow: Flow, out: &mut Vec<Pdu>) {
        self.abandoned += 1;
        out.push(Pdu {
            key,
            dst_group: flow.dst_group,
            data: flow.buf,
            ts: flow.last,
        });
    }
    /// Partial messages idle for longer than `FLOW_IDLE_SECS`, checked every 10 s of capture time.
    fn expire(&mut self, ts: i64, out: &mut Vec<Pdu>) {
        // Capture timestamps come from untrusted pcap files: saturate instead of overflowing.
        if ts.saturating_sub(self.last_sweep) < 10 {
            return;
        }
        self.last_sweep = ts;
        let old: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, f)| ts.saturating_sub(f.last) > FLOW_IDLE_SECS)
            .map(|(k, _)| *k)
            .collect();
        for key in old {
            if let Some(flow) = self.take(&key) {
                self.give_up(key, flow, out);
            }
        }
    }
    /// Everything still buffered, given up (end of capture).
    pub(super) fn flush(&mut self) -> Vec<Pdu> {
        let mut out = vec![];
        let keys: Vec<FlowKey> = self.flows.keys().copied().collect();
        for key in keys {
            if let Some(flow) = self.take(&key) {
                self.give_up(key, flow, &mut out);
            }
        }
        out
    }

    /// One TCP segment with payload; returns what to decode now, in order.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn segment(
        &mut self,
        key: FlowKey,
        port: u16,
        seq: u32,
        end_of_flow: bool,
        truncated: bool,
        dst_group: bool,
        payload: &[u8],
        ts: i64,
    ) -> Vec<Pdu> {
        let mut out = vec![];
        self.expire(ts, &mut out);
        let mut joined = false;
        let data = match self.take(&key) {
            Some(mut flow) => {
                let end = seq.wrapping_add(payload.len() as u32);
                if truncated {
                    self.give_up(key, flow, &mut out);
                    payload.to_vec()
                } else if seq_le(end, flow.next_seq) {
                    // a retransmission of bytes already buffered
                    self.bytes += flow.buf.len();
                    flow.last = ts;
                    self.flows.insert(key, flow);
                    return out;
                } else if seq_le(seq, flow.next_seq) {
                    // in order, or overlapping the buffered end: append only the new bytes
                    let new = &payload[flow.next_seq.wrapping_sub(seq) as usize..];
                    let mut buf = flow.buf.clone();
                    buf.extend_from_slice(new);
                    if matches!(message_len(port, &buf), Framing::NotFramed) {
                        // The buffered start was no message (e.g. a 1-byte keep-alive probe):
                        // decode it and the new bytes separately.
                        self.give_up(key, flow, &mut out);
                        new.to_vec()
                    } else {
                        joined = true;
                        buf
                    }
                } else {
                    // gap: the missing bytes will not come back in a capture
                    self.give_up(key, flow, &mut out);
                    payload.to_vec()
                }
            }
            None => payload.to_vec(),
        };
        let next_seq = seq.wrapping_add(payload.len() as u32);
        let pdu = |data: &[u8]| Pdu {
            key,
            dst_group,
            data: data.to_vec(),
            ts,
        };
        let mut rest = &data[..];
        let mut first = true;
        while !rest.is_empty() {
            let framing = if truncated {
                Framing::NotFramed
            } else {
                message_len(port, rest)
            };
            match framing {
                Framing::Len(n) if n <= rest.len() => {
                    if joined && first {
                        self.reassembled += 1;
                    }
                    let after = &rest[n..];
                    if !after.is_empty() && matches!(message_len(port, after), Framing::NotFramed) {
                        // The bytes after it are no message: the length field may be wrong,
                        // so decode everything as one piece (as without reassembly).
                        out.push(pdu(rest));
                        return out;
                    }
                    out.push(pdu(&rest[..n]));
                    rest = after;
                }
                Framing::Len(n)
                    if n <= MAX_FLOW_BYTES
                        && !end_of_flow
                        && !self.disabled
                        && self.flows.len() < MAX_FLOWS
                        && self.bytes + rest.len() <= MAX_TOTAL_BYTES =>
                {
                    self.keep(key, next_seq, rest, ts, dst_group);
                    return out;
                }
                Framing::NeedHeader
                    if !end_of_flow
                        && !self.disabled
                        && self.flows.len() < MAX_FLOWS
                        && self.bytes + rest.len() <= MAX_TOTAL_BYTES =>
                {
                    self.keep(key, next_seq, rest, ts, dst_group);
                    return out;
                }
                _ => {
                    // too long, limits reached, end of flow, or not framed: decode as is
                    if joined {
                        self.abandoned += 1;
                    }
                    out.push(pdu(rest));
                    return out;
                }
            }
            first = false;
        }
        out
    }
    fn keep(&mut self, key: FlowKey, next_seq: u32, data: &[u8], ts: i64, dst_group: bool) {
        self.bytes += data.len();
        self.flows.insert(
            key,
            Flow {
                next_seq,
                buf: data.to_vec(),
                last: ts,
                dst_group,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otpassive::Tracker;
    use crate::otpassive::testutil::{HMI, PLC, cip_send_rr, control, modbus_write, obs, s7, seg};

    #[test]
    fn extreme_capture_timestamps_do_not_overflow() {
        // Found by ClusterFuzzLite: `ts - last` overflowed on crafted pcap timestamps.
        let m = modbus_write();
        for (a, b) in [
            (i64::MIN, i64::MAX),
            (i64::MAX, i64::MIN),
            (0, i64::MIN),
            (i64::MIN, 0),
        ] {
            let mut t = Tracker::new();
            t.feed(&seg(HMI, PLC, 502, 1000, 0x18, &m[..3]), a);
            t.feed(&seg(HMI, PLC, 502, 2000, 0x18, &m[..3]), b);
            t.feed(&seg(PLC, HMI, 502, 3000, 0x18, &m[..3]), a);
        }
    }

    #[test]
    fn reassembly_joins_split_modbus_s7_and_enip_messages() {
        // Modbus split inside the MBAP header (decodable from neither part alone)
        let m = modbus_write();
        let mut t = Tracker::new();
        t.feed(&seg(HMI, PLC, 502, 1000, 0x18, &m[..3]), 1);
        assert!(obs(&t, "Modbus/TCP server (observed)").is_empty(), "waits");
        t.feed(&seg(HMI, PLC, 502, 1003, 0x18, &m[3..9]), 2);
        t.feed(&seg(HMI, PLC, 502, 1009, 0x18, &m[9..]), 3);
        assert_eq!(
            control(&t, "Modbus/TCP server (observed)").as_deref(),
            Some("Write Multiple Registers x1")
        );
        assert_eq!(t.reassembly_stats(), (1, 0));
        let s = &obs(&t, "Modbus/TCP server (observed)")[0];
        assert_eq!(s.fields["packets"], "1", "one message, not three segments");

        // S7 PLC Stop split after the TPKT/COTP headers
        let stop = s7(0x29, 1);
        let mut t = Tracker::new();
        t.feed(&seg(HMI, PLC, 102, 5, 0x18, &stop[..7]), 1);
        t.feed(&seg(HMI, PLC, 102, 12, 0x18, &stop[7..]), 1);
        assert_eq!(
            control(&t, "S7comm server (observed)").as_deref(),
            Some("PLC Stop x1")
        );

        // EtherNet/IP SendRRData with a correct length, split in the middle of the CIP request
        let mut rr = cip_send_rr(0x4d);
        let n = (rr.len() - 24) as u16;
        rr[2..4].copy_from_slice(&n.to_le_bytes());
        let mut t = Tracker::new();
        t.feed(&seg(HMI, PLC, 44818, u32::MAX - 9, 0x18, &rr[..30]), 1); // seq wraps
        t.feed(&seg(HMI, PLC, 44818, 20, 0x18, &rr[30..]), 1);
        assert_eq!(
            control(&t, "EtherNet/IP server (observed)").as_deref(),
            Some("Write Tag x1")
        );
    }

    #[test]
    fn reassembly_handles_several_messages_retransmissions_and_overlap() {
        let m = modbus_write();
        // two complete messages and the start of a third in one segment
        let mut data = m.clone();
        data.extend(&m);
        data.extend(&m[..5]);
        let mut t = Tracker::new();
        t.feed(&seg(HMI, PLC, 502, 0, 0x18, &data), 1);
        let s = &obs(&t, "Modbus/TCP server (observed)")[0];
        assert_eq!(s.fields["control_traffic"], "Write Multiple Registers x2");
        // a retransmission of the buffered bytes is ignored, an overlap adds only new bytes
        let at = (2 * m.len()) as u32;
        t.feed(&seg(HMI, PLC, 502, at, 0x18, &m[..5]), 2);
        t.feed(&seg(HMI, PLC, 502, at + 3, 0x18, &m[3..]), 3);
        let s = &obs(&t, "Modbus/TCP server (observed)")[0];
        assert_eq!(s.fields["control_traffic"], "Write Multiple Registers x3");
        assert_eq!(t.reassembly_stats(), (1, 0));
    }

    #[test]
    fn reassembly_gives_up_on_gaps_fin_and_end_of_capture() {
        let m = modbus_write();
        // A gap: the buffered prefix is decoded as far as it goes (it holds the function code),
        // the segment after the gap is decoded on its own.
        let mut t = Tracker::new();
        t.feed(&seg(HMI, PLC, 502, 100, 0x18, &m[..9]), 1);
        t.feed(&seg(HMI, PLC, 502, 200, 0x18, &m), 2);
        assert_eq!(
            control(&t, "Modbus/TCP server (observed)").as_deref(),
            Some("Write Multiple Registers x2")
        );
        assert_eq!(t.reassembly_stats(), (0, 1));
        // FIN with an incomplete message: nothing stays buffered
        let mut t = Tracker::new();
        t.feed(&seg(HMI, PLC, 502, 1, 0x11, &m[..9]), 1);
        assert!(t.reassembly.flows.is_empty());
        assert!(control(&t, "Modbus/TCP server (observed)").is_some());
        // end of capture: flush decodes what is buffered
        let mut t = Tracker::new();
        t.feed(&seg(HMI, PLC, 502, 1, 0x18, &m[..9]), 1);
        assert!(control(&t, "Modbus/TCP server (observed)").is_none());
        t.flush();
        assert!(control(&t, "Modbus/TCP server (observed)").is_some());
        assert!(t.reassembly.flows.is_empty() && t.reassembly.bytes == 0);
        // idle partial messages are given up once capture time moves on
        let mut t = Tracker::new();
        t.feed(&seg(HMI, PLC, 502, 1, 0x18, &m[..9]), 1000);
        t.feed(
            &seg(PLC, HMI, 502, 1, 0x18, &m[..2]),
            1000 + FLOW_IDLE_SECS + 11,
        );
        assert!(control(&t, "Modbus/TCP server (observed)").is_some());
        assert_eq!(t.reassembly.flows.len(), 1, "only the new partial message");
    }

    #[test]
    fn a_stray_byte_does_not_swallow_the_next_message() {
        // TCP keep-alive probe: one old byte at S-1, then a complete write at S
        let m = modbus_write();
        let mut t = Tracker::new();
        t.feed(&seg(HMI, PLC, 502, 999, 0x18, &[0x42]), 1);
        t.feed(&seg(HMI, PLC, 502, 1000, 0x18, &m), 2);
        assert_eq!(
            control(&t, "Modbus/TCP server (observed)").as_deref(),
            Some("Write Multiple Registers x1")
        );
        assert!(t.reassembly.flows.is_empty());
        // given-up fragments keep the time they were captured, not the time of the flush
        let mut t = Tracker::new();
        t.feed(&seg(HMI, PLC, 502, 1, 0x18, &m[..9]), 50);
        t.feed(&seg(PLC, HMI, 502, 1, 0x18, &[0, 1]), 90);
        t.flush();
        let s = &obs(&t, "Modbus/TCP server (observed)")[0];
        assert_eq!(s.fields["last_seen"], "50");
    }

    #[test]
    fn reassembly_memory_is_bounded() {
        // a message longer than the per-flow limit is decoded from its first segment
        let mut opc = b"MSGF".to_vec();
        opc.extend(((MAX_FLOW_BYTES + 100) as u32).to_le_bytes());
        opc.extend([0; 100]);
        let mut t = Tracker::new();
        t.feed(&seg(HMI, PLC, 4840, 0, 0x18, &opc), 1);
        assert!(t.reassembly.flows.is_empty());
        assert_eq!(obs(&t, "OPC UA server (observed)").len(), 1);
        // at most MAX_FLOWS partial messages
        let mut t = Tracker::new();
        for i in 0..(MAX_FLOWS + 50) {
            let client = [10, 1, (i >> 8) as u8, i as u8];
            t.feed(&seg(client, PLC, 502, 0, 0x18, &modbus_write()[..9]), 1);
        }
        assert_eq!(t.reassembly.flows.len(), MAX_FLOWS);
        assert!(t.reassembly.bytes <= MAX_TOTAL_BYTES);
        let s = &obs(&t, "Modbus/TCP server (observed)")[0];
        assert_eq!(
            s.fields["control_traffic"], "Write Multiple Registers x50",
            "segments beyond the limit are decoded on their own"
        );
        // snap-length truncated segments are never buffered
        let mut f = seg(HMI, PLC, 502, 0, 0x18, &modbus_write());
        f.truncate(f.len() - 4);
        let mut t = Tracker::new();
        t.feed(&f, 1);
        assert!(t.reassembly.flows.is_empty());
        assert!(control(&t, "Modbus/TCP server (observed)").is_some());
        // switched off: no buffering at all
        let mut t = Tracker::new();
        t.set_reassembly(false);
        t.feed(&seg(HMI, PLC, 502, 0, 0x18, &modbus_write()[..3]), 1);
        assert!(t.reassembly.flows.is_empty());
    }
}
