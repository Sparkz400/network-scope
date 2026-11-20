//! A record of what a scan sent and received, as pcapng (ROADMAP L72: `scan --record FILE.pcapng`).
//!
//! **This is an application-level record, not a wire capture.** The scanner opens ordinary
//! sockets, so it never sees the Ethernet, IP or TCP headers it sends. What it does see are the
//! bytes it hands to a socket and the bytes the socket hands back. The [`Recorder`] keeps those,
//! with the time, the peer address and the direction, at the places the scan sends them; the file
//! writer then puts each chunk into a *synthetic* Ethernet/IP/TCP or UDP frame so that Wireshark,
//! `tshark` and this program's own `ot-listen --pcap` can read the payloads. What is made up:
//!
//! - both MAC addresses (`02:00:00:00:00:01` the scanner, `02:00:00:00:00:02` the peer), the
//!   scanner's address (`192.0.2.1`, or `2001:db8::1` for an IPv6 peer: documentation addresses),
//!   the scanner's port (one per flow, from 40000) and every sequence and acknowledgement number;
//! - there are no handshake, acknowledgement, retransmission or closing frames, and a payload of
//!   more than 1,400 bytes is cut into several frames;
//! - time stamps are the moments the scan handed the bytes over or received them, not times on a
//!   wire.
//!
//! Every packet carries a comment saying what it is (`sent: Modbus/TCP: function 0x2B ...`) and the
//! file's header says it is an application-level record. The recorder covers the senders that take
//! part: read-only OT requests and their replies (every OT protocol), and the payloads of service
//! identification (probes, HTTP and the SMB/RDP negotiate requests). **Not recorded** are the TCP
//! connect attempts themselves, ICMP, ARP, UDP probes of the UDP scan, DNS lookups, the TLS and SSH
//! exchanges and traceroute: the sent log (`--sent-log`) still lists them. `scan --record` says how
//! many packets of the sent log the record covers.
//!
//! With the capture driver present, `scan --record-wire` records the real frames instead
//! ([`crate::wirecap`], written by [`write_wire_pcapng`]); this synthetic file is what the scan
//! writes without it.
//!
//! The recorder is bounded: at most [`MAX_RECORDS`] chunks and [`MAX_BYTES`] of payload are kept,
//! each cut at [`MAX_PAYLOAD`] bytes; what does not fit is counted and reported, never silently
//! lost.
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

/// Most chunks kept.
pub const MAX_RECORDS: usize = 500_000;
/// Most payload bytes kept in all.
pub const MAX_BYTES: usize = 128 * 1024 * 1024;
/// Longest payload kept per chunk; the rest is cut (the comment of the frame says so).
pub const MAX_PAYLOAD: usize = 4096;
/// Payload bytes per synthetic frame.
const SEGMENT: usize = 1400;

const SCANNER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
const PEER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];

/// One chunk of application data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// Microseconds since the Unix epoch.
    pub micros: u64,
    pub peer: SocketAddr,
    pub udp: bool,
    /// Sent by the scanner (otherwise received from the peer).
    pub outbound: bool,
    pub data: Vec<u8>,
    /// What it is (`Modbus/TCP: function 0x2B ...`, `HTTP GET /`).
    pub note: String,
    /// The payload was longer and has been cut.
    pub truncated: bool,
}

#[derive(Debug, Default)]
struct Inner {
    records: Vec<Record>,
    bytes: usize,
    dropped: u64,
}

/// Collects the chunks of one scan; shared between the scan's tasks.
#[derive(Debug)]
pub struct Recorder {
    inner: Mutex<Inner>,
    max_records: usize,
    max_bytes: usize,
}

impl Default for Recorder {
    fn default() -> Self {
        Self::with_limits(MAX_RECORDS, MAX_BYTES)
    }
}

/// What [`Recorder::write_pcapng`] wrote.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Written {
    /// Chunks in the file.
    pub records: usize,
    /// Frames (a long chunk is several).
    pub frames: usize,
    /// Chunks that did not fit the bounds and are not in the file.
    pub dropped: u64,
}

fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_micros() as u64)
}

impl Recorder {
    pub fn new() -> Self {
        Self::default()
    }

    /// A recorder with other bounds than [`MAX_RECORDS`] and [`MAX_BYTES`] (for tests).
    pub(crate) fn with_limits(max_records: usize, max_bytes: usize) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            max_records,
            max_bytes,
        }
    }

    /// Records that `data` was sent to (`outbound`) or received from `peer`.
    pub fn add(&self, peer: SocketAddr, udp: bool, outbound: bool, data: &[u8], note: &str) {
        if data.is_empty() {
            return;
        }
        let micros = now_micros();
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let kept = data.len().min(MAX_PAYLOAD);
        if inner.records.len() >= self.max_records || inner.bytes + kept > self.max_bytes {
            inner.dropped += 1;
            return;
        }
        inner.bytes += kept;
        inner.records.push(Record {
            micros,
            peer,
            udp,
            outbound,
            data: data[..kept].to_vec(),
            note: note.chars().take(200).collect(),
            truncated: kept < data.len(),
        });
    }

    /// The chunks recorded so far, oldest first.
    pub fn records(&self) -> Vec<Record> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .records
            .clone()
    }

    /// (chunks kept, chunks that did not fit).
    pub fn counts(&self) -> (usize, u64) {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        (inner.records.len(), inner.dropped)
    }

    /// Writes the record as a pcapng file (see the module documentation for what is synthetic).
    pub fn write_pcapng(&self, path: &Path) -> Result<Written, String> {
        let (records, dropped) = {
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            (inner.records.clone(), inner.dropped)
        };
        let (bytes, frames) = pcapng(&records);
        std::fs::write(path, bytes).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(Written {
            records: records.len(),
            frames,
            dropped,
        })
    }
}

// ---- pcapng --------------------------------------------------------------------------------

fn pad4(v: &mut Vec<u8>) {
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
}

fn option(out: &mut Vec<u8>, code: u16, value: &[u8]) {
    out.extend(code.to_le_bytes());
    out.extend((value.len() as u16).to_le_bytes());
    out.extend(value);
    pad4(out);
}

fn block(kind: u32, body: &[u8]) -> Vec<u8> {
    let total = (body.len() + 12) as u32;
    let mut out = Vec::with_capacity(total as usize);
    out.extend(kind.to_le_bytes());
    out.extend(total.to_le_bytes());
    out.extend(body);
    out.extend(total.to_le_bytes());
    out
}

/// One's complement sum of 16-bit words (the Internet checksum).
fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut odd: Option<u8> = None;
    for part in parts {
        for &b in *part {
            match odd.take() {
                Some(high) => sum += u32::from(u16::from_be_bytes([high, b])),
                None => odd = Some(b),
            }
        }
    }
    if let Some(high) = odd {
        sum += u32::from(u16::from_be_bytes([high, 0]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

struct Flow {
    port: u16,
    out_seq: u32,
    in_seq: u32,
}

/// The frames of one chunk (one per [`SEGMENT`] bytes), advancing the flow's sequence numbers.
fn frames_of(r: &Record, flow: &mut Flow) -> Vec<Vec<u8>> {
    let local_v4 = [192, 0, 2, 1];
    let local_v6: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let (sport, dport) = if r.outbound {
        (flow.port, r.peer.port())
    } else {
        (r.peer.port(), flow.port)
    };
    let mut out = vec![];
    let chunks: Vec<&[u8]> = r.data.chunks(SEGMENT).collect();
    for chunk in chunks {
        let (seq, ack) = if r.outbound {
            (flow.out_seq, flow.in_seq)
        } else {
            (flow.in_seq, flow.out_seq)
        };
        let mut l4 = vec![];
        if r.udp {
            l4.extend(sport.to_be_bytes());
            l4.extend(dport.to_be_bytes());
            l4.extend(((8 + chunk.len()) as u16).to_be_bytes());
            l4.extend([0, 0]);
        } else {
            l4.extend(sport.to_be_bytes());
            l4.extend(dport.to_be_bytes());
            l4.extend(seq.to_be_bytes());
            l4.extend(ack.to_be_bytes());
            l4.extend([5 << 4, 0x18]);
            l4.extend(65535u16.to_be_bytes());
            l4.extend([0, 0, 0, 0]);
        }
        l4.extend(chunk);
        let proto: u8 = if r.udp { 17 } else { 6 };
        let (src_mac, dst_mac) = if r.outbound {
            (SCANNER_MAC, PEER_MAC)
        } else {
            (PEER_MAC, SCANNER_MAC)
        };
        let mut frame = vec![];
        frame.extend(dst_mac);
        frame.extend(src_mac);
        match r.peer.ip() {
            IpAddr::V4(peer) => {
                let (src, dst) = if r.outbound {
                    (local_v4, peer.octets())
                } else {
                    (peer.octets(), local_v4)
                };
                let pseudo: Vec<u8> = [
                    &src[..],
                    &dst[..],
                    &[0, proto],
                    &(l4.len() as u16).to_be_bytes()[..],
                ]
                .concat();
                let at = if r.udp { 6 } else { 16 };
                let sum = checksum(&[&pseudo, &l4]);
                let sum = if r.udp && sum == 0 { 0xffff } else { sum };
                l4[at..at + 2].copy_from_slice(&sum.to_be_bytes());
                let mut ip = vec![0x45, 0];
                ip.extend(((20 + l4.len()) as u16).to_be_bytes());
                ip.extend([0, 0, 0x40, 0, 64, proto, 0, 0]);
                ip.extend(src);
                ip.extend(dst);
                let hsum = checksum(&[&ip]);
                ip[10..12].copy_from_slice(&hsum.to_be_bytes());
                frame.extend([0x08, 0x00]);
                frame.extend(ip);
            }
            IpAddr::V6(peer) => {
                let (src, dst) = if r.outbound {
                    (local_v6, peer.octets())
                } else {
                    (peer.octets(), local_v6)
                };
                let pseudo: Vec<u8> = [
                    &src[..],
                    &dst[..],
                    &(l4.len() as u32).to_be_bytes()[..],
                    &[0, 0, 0, proto],
                ]
                .concat();
                let at = if r.udp { 6 } else { 16 };
                let sum = checksum(&[&pseudo, &l4]);
                let sum = if r.udp && sum == 0 { 0xffff } else { sum };
                l4[at..at + 2].copy_from_slice(&sum.to_be_bytes());
                let mut ip = vec![0x60, 0, 0, 0];
                ip.extend((l4.len() as u16).to_be_bytes());
                ip.extend([proto, 64]);
                ip.extend(src);
                ip.extend(dst);
                frame.extend([0x86, 0xdd]);
                frame.extend(ip);
            }
        }
        frame.extend(l4);
        if !r.udp {
            let n = chunk.len() as u32;
            if r.outbound {
                flow.out_seq = flow.out_seq.wrapping_add(n);
            } else {
                flow.in_seq = flow.in_seq.wrapping_add(n);
            }
        }
        out.push(frame);
    }
    out
}

/// The pcapng bytes of `records` and the number of frames.
fn pcapng(records: &[Record]) -> (Vec<u8>, usize) {
    let mut out = vec![];
    // Section header: byte-order magic, version 1.0, unknown section length, then options.
    let mut shb = vec![];
    shb.extend(0x1a2b_3c4du32.to_le_bytes());
    shb.extend(1u16.to_le_bytes());
    shb.extend(0u16.to_le_bytes());
    shb.extend((-1i64).to_le_bytes());
    option(
        &mut shb,
        1,
        b"APPLICATION-LEVEL RECORD, NOT A WIRE CAPTURE: the payloads a Network Scope scan handed to its sockets and received, in synthetic Ethernet/IP/TCP|UDP frames (made-up MAC addresses, scanner address, ports and sequence numbers; no handshakes or acknowledgements).",
    );
    option(
        &mut shb,
        4,
        format!("network-scope {}", env!("CARGO_PKG_VERSION")).as_bytes(),
    );
    option(&mut shb, 0, b"");
    out.extend(block(0x0a0d_0d0a, &shb));
    // One interface: Ethernet, microsecond time stamps.
    let mut idb = vec![];
    idb.extend(1u16.to_le_bytes());
    idb.extend(0u16.to_le_bytes());
    idb.extend(0u32.to_le_bytes());
    option(&mut idb, 2, b"network-scope application record");
    option(&mut idb, 9, &[6]);
    option(&mut idb, 0, b"");
    out.extend(block(1, &idb));
    let mut flows: HashMap<(SocketAddr, bool), Flow> = HashMap::new();
    let mut frames = 0;
    for r in records {
        let next_port = 40_000 + (flows.len() % 20_000) as u16;
        let flow = flows.entry((r.peer, r.udp)).or_insert(Flow {
            port: next_port,
            out_seq: 1000,
            in_seq: 5000,
        });
        let comment = format!(
            "{}: {}{}",
            if r.outbound { "sent" } else { "received" },
            r.note,
            if r.truncated { " (payload cut)" } else { "" }
        );
        for frame in frames_of(r, flow) {
            let mut epb = vec![];
            epb.extend(0u32.to_le_bytes());
            epb.extend(((r.micros >> 32) as u32).to_le_bytes());
            epb.extend((r.micros as u32).to_le_bytes());
            epb.extend((frame.len() as u32).to_le_bytes());
            epb.extend((frame.len() as u32).to_le_bytes());
            epb.extend(&frame);
            pad4(&mut epb);
            // epb_flags: bit 0-1 direction, 1 inbound and 2 outbound
            option(
                &mut epb,
                2,
                &(if r.outbound { 2u32 } else { 1u32 }).to_le_bytes(),
            );
            option(&mut epb, 1, comment.as_bytes());
            option(&mut epb, 0, b"");
            out.extend(block(6, &epb));
            frames += 1;
        }
    }
    (out, frames)
}

// ---- wire capture --------------------------------------------------------------------------

/// One frame captured from the wire (`scan --record-wire`, see [`crate::wirecap`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireFrame {
    /// Microseconds since the Unix epoch, as the capture driver stamped it.
    pub micros: u64,
    pub data: Vec<u8>,
}

/// The pcapng bytes of real frames captured on `interface` with the kernel filter `filter`.
/// `link_type` is the capture's own (1 Ethernet, 0 loopback). Unlike [`Recorder`]'s file nothing
/// here is made up: the headers, addresses, sequence numbers and times are the ones on the wire,
/// and the file's header says so.
pub fn wire_pcapng(link_type: u16, interface: &str, filter: &str, frames: &[WireFrame]) -> Vec<u8> {
    let mut out = vec![];
    let mut shb = vec![];
    shb.extend(0x1a2b_3c4du32.to_le_bytes());
    shb.extend(1u16.to_le_bytes());
    shb.extend(0u16.to_le_bytes());
    shb.extend((-1i64).to_le_bytes());
    option(
        &mut shb,
        1,
        b"WIRE CAPTURE of a Network Scope scan: the real frames the capture driver saw on the interface named below while the scan ran, filtered to the scan's targets. Headers, addresses, sequence numbers and times are those of the wire. Traffic of other programs to or from the same hosts is included; the payload of TLS and SSH is encrypted as it was on the wire.",
    );
    option(
        &mut shb,
        4,
        format!("network-scope {}", env!("CARGO_PKG_VERSION")).as_bytes(),
    );
    option(&mut shb, 0, b"");
    out.extend(block(0x0a0d_0d0a, &shb));
    let mut idb = vec![];
    idb.extend(link_type.to_le_bytes());
    idb.extend(0u16.to_le_bytes());
    idb.extend(65535u32.to_le_bytes());
    option(&mut idb, 2, interface.as_bytes());
    // if_filter: a byte 0 (a libpcap filter string) and the string
    let mut f = vec![0u8];
    f.extend(filter.as_bytes());
    option(&mut idb, 11, &f);
    option(&mut idb, 9, &[6]);
    option(&mut idb, 0, b"");
    out.extend(block(1, &idb));
    for frame in frames {
        let mut epb = vec![];
        epb.extend(0u32.to_le_bytes());
        epb.extend(((frame.micros >> 32) as u32).to_le_bytes());
        epb.extend((frame.micros as u32).to_le_bytes());
        epb.extend((frame.data.len() as u32).to_le_bytes());
        epb.extend((frame.data.len() as u32).to_le_bytes());
        epb.extend(&frame.data);
        pad4(&mut epb);
        option(&mut epb, 0, b"");
        out.extend(block(6, &epb));
    }
    out
}

/// Writes [`wire_pcapng`] to `path`.
pub fn write_wire_pcapng(
    path: &Path,
    link_type: u16,
    interface: &str,
    filter: &str,
    frames: &[WireFrame],
) -> Result<(), String> {
    std::fs::write(path, wire_pcapng(link_type, interface, filter, frames))
        .map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
#[path = "record_tests.rs"]
mod tests;
