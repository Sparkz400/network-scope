//! Offline capture files: classic pcap (all four magic variants) and pcapng, Ethernet frames only.
//! Pure Rust: no capture driver is needed to analyse a file recorded elsewhere.
use std::io::Read;

pub const MAX_FRAME: usize = 262_144;
/// Largest pcapng block read into memory; bigger blocks are skipped (read and discarded).
const MAX_BLOCK: usize = MAX_FRAME + 4096;
const LINKTYPE_ETHERNET: u32 = 1;

/// A pcapng interface: its link type and timestamp resolution (`if_tsresol`).
#[derive(Debug, Clone, Copy)]
struct Interface {
    link: u16,
    /// Timestamp units: 10^-n seconds, or 2^-n seconds when `binary`.
    resol: u8,
    binary: bool,
}
impl Interface {
    fn seconds(&self, ts: u64) -> i64 {
        let secs = if self.binary {
            ts.checked_shr(u32::from(self.resol)).unwrap_or(0)
        } else {
            10u64
                .checked_pow(u32::from(self.resol))
                .map_or(0, |unit| ts / unit)
        };
        i64::try_from(secs).unwrap_or(i64::MAX)
    }
}

fn link_name(link: u32) -> &'static str {
    match link {
        0 => " (BSD loopback)",
        101 => " (raw IP)",
        105 => " (802.11 Wi-Fi)",
        113 => " (Linux cooked capture SLL)",
        127 => " (802.11 radiotap)",
        228 => " (raw IPv4)",
        276 => " (Linux cooked capture SLL2)",
        _ => "",
    }
}

#[derive(Debug)]
pub struct Reader<R: Read> {
    input: R,
    big_endian: bool,
    ng: bool,
    interfaces: Vec<Interface>,
    /// classic pcap: bytes of frame check sequence at the end of every frame
    fcs: usize,
    /// frames returned so far, and link types of interfaces whose packets were skipped
    returned: u64,
    other_links: std::collections::BTreeSet<u16>,
    pub skipped: u64,
}

fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<bool, String> {
    let mut done = 0;
    while done < buf.len() {
        match r.read(&mut buf[done..]) {
            Ok(0) if done == 0 => return Ok(false),
            Ok(0) => return Err("Truncated capture file".into()),
            Ok(n) => done += n,
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(true)
}

impl<R: Read> Reader<R> {
    pub fn new(mut input: R) -> Result<Self, String> {
        let mut magic = [0u8; 4];
        if !read_exact_or_eof(&mut input, &mut magic)? {
            return Err("Empty capture file".into());
        }
        let mut r = Self {
            input,
            big_endian: false,
            ng: false,
            interfaces: vec![],
            fcs: 0,
            returned: 0,
            other_links: Default::default(),
            skipped: 0,
        };
        match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => {}
            [0xa1, 0xb2, 0xc3, 0xd4] => r.big_endian = true,
            [0x4d, 0x3c, 0xb2, 0xa1] => {}
            [0xa1, 0xb2, 0x3c, 0x4d] => r.big_endian = true,
            [0x0a, 0x0d, 0x0d, 0x0a] => {
                r.ng = true;
                r.section_header()?;
                return Ok(r);
            }
            _ => return Err("Not a pcap or pcapng file".into()),
        }
        let mut header = [0u8; 20];
        if !read_exact_or_eof(&mut r.input, &mut header)? {
            return Err("Truncated pcap header".into());
        }
        // Link-type word: bits 0-27 link type, bit 28 "FCS present", bits 29-31 FCS length
        // in 16-bit words.
        let word = r.u32(&header[16..20]);
        let link = word & 0x0fff_ffff;
        if link != LINKTYPE_ETHERNET {
            return Err(format!(
                "Unsupported link type {link}{}: only Ethernet captures are read",
                link_name(link)
            ));
        }
        if word & 0x1000_0000 != 0 {
            r.fcs = (word >> 29) as usize * 2;
        }
        Ok(r)
    }
    fn u32(&self, b: &[u8]) -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        if self.big_endian {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        }
    }
    fn u16(&self, b: &[u8]) -> u16 {
        let a = [b[0], b[1]];
        if self.big_endian {
            u16::from_be_bytes(a)
        } else {
            u16::from_le_bytes(a)
        }
    }
    /// The block type word was already consumed; reads the rest of a section header block.
    fn section_header(&mut self) -> Result<(), String> {
        let mut head = [0u8; 8];
        if !read_exact_or_eof(&mut self.input, &mut head)? {
            return Err("Truncated pcapng header".into());
        }
        self.big_endian = match head[4..8] {
            [0x4d, 0x3c, 0x2b, 0x1a] => false,
            [0x1a, 0x2b, 0x3c, 0x4d] => true,
            _ => return Err("Bad pcapng byte-order magic".into()),
        };
        let total = self.u32(&head[..4]) as usize;
        if total < 28 || !total.is_multiple_of(4) {
            return Err("Bad pcapng section header".into());
        }
        self.discard(total - 12)?;
        self.interfaces.clear();
        Ok(())
    }
    /// Reads and drops `n` bytes without holding them in memory.
    fn discard(&mut self, n: usize) -> Result<(), String> {
        let copied = std::io::copy(&mut (&mut self.input).take(n as u64), &mut std::io::sink())
            .map_err(|e| e.to_string())?;
        if copied != n as u64 {
            return Err("Truncated capture file".into());
        }
        Ok(())
    }
    /// Interface Description Block body (after the block header).
    fn interface(&self, body: &[u8]) -> Interface {
        let mut iface = Interface {
            link: self.u16(&body[..2]),
            resol: 6,
            binary: false,
        };
        let mut i = 8;
        while let Some(head) = body.get(i..i + 4) {
            let (code, len) = (self.u16(&head[..2]), usize::from(self.u16(&head[2..4])));
            i += 4;
            let Some(value) = body.get(i..i + len) else {
                break;
            };
            match code {
                0 => break,
                9 if len == 1 => {
                    iface.binary = value[0] & 0x80 != 0;
                    iface.resol = value[0] & 0x7f;
                }
                _ => {}
            }
            i += len.div_ceil(4) * 4;
        }
        iface
    }

    /// Next Ethernet frame with its timestamp in seconds; `None` at the end of the file.
    pub fn next_frame(&mut self) -> Result<Option<(i64, Vec<u8>)>, String> {
        if self.ng {
            self.next_ng()
        } else {
            self.next_classic()
        }
    }
    fn next_classic(&mut self) -> Result<Option<(i64, Vec<u8>)>, String> {
        let mut h = [0u8; 16];
        if !read_exact_or_eof(&mut self.input, &mut h)? {
            return Ok(None);
        }
        let (secs, caplen) = (self.u32(&h[0..4]), self.u32(&h[8..12]) as usize);
        if caplen > MAX_FRAME {
            return Err("Oversized frame in capture file".into());
        }
        let mut data = vec![0u8; caplen];
        if !read_exact_or_eof(&mut self.input, &mut data)? && caplen > 0 {
            return Err("Truncated capture file".into());
        }
        let orig = self.u32(&h[12..16]) as usize;
        // Drop a trailing FCS, but only when the frame was captured completely.
        if self.fcs > 0 && caplen >= orig && data.len() >= self.fcs {
            data.truncate(data.len() - self.fcs);
        }
        Ok(Some((i64::from(secs), data)))
    }
    fn next_ng(&mut self) -> Result<Option<(i64, Vec<u8>)>, String> {
        let frame = self.next_ng_frame()?;
        match &frame {
            Some(_) => self.returned += 1,
            None if self.returned == 0 && !self.other_links.is_empty() => {
                return Err(format!(
                    "Unsupported link type {}: only Ethernet captures are read",
                    self.other_links
                        .iter()
                        .map(|&l| format!("{l}{}", link_name(u32::from(l))))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            None => {}
        }
        Ok(frame)
    }
    fn next_ng_frame(&mut self) -> Result<Option<(i64, Vec<u8>)>, String> {
        loop {
            let mut h = [0u8; 8];
            if !read_exact_or_eof(&mut self.input, &mut h)? {
                return Ok(None);
            }
            if h[..4] == [0x0a, 0x0d, 0x0d, 0x0a] {
                // A new section may change the byte order; the order magic follows the length.
                let mut magic = [0u8; 4];
                if !read_exact_or_eof(&mut self.input, &mut magic)? {
                    return Err("Truncated pcapng section".into());
                }
                self.big_endian = match magic {
                    [0x4d, 0x3c, 0x2b, 0x1a] => false,
                    [0x1a, 0x2b, 0x3c, 0x4d] => true,
                    _ => return Err("Bad pcapng byte-order magic".into()),
                };
                let total = self.u32(&h[4..8]) as usize;
                if total < 28 || !total.is_multiple_of(4) {
                    return Err("Bad pcapng section header".into());
                }
                self.discard(total - 12)?;
                self.interfaces.clear();
                continue;
            }
            let (kind, total) = (self.u32(&h[..4]), self.u32(&h[4..8]) as usize);
            if total < 12 || !total.is_multiple_of(4) {
                return Err("Bad pcapng block length".into());
            }
            if total > MAX_BLOCK {
                // Too large to be an Ethernet frame we would read: skip it, keep the file.
                self.discard(total - 8)?;
                if kind == 1 {
                    // keep interface numbering intact; its packets are skipped
                    self.interfaces.push(Interface {
                        link: 0xffff,
                        resol: 6,
                        binary: false,
                    });
                }
                self.skipped += 1;
                continue;
            }
            let mut body = vec![0u8; total - 8];
            if !read_exact_or_eof(&mut self.input, &mut body)? {
                return Err("Truncated pcapng block".into());
            }
            let body = &body[..body.len() - 4];
            match kind {
                1 if body.len() >= 8 => {
                    let iface = self.interface(body);
                    self.interfaces.push(iface);
                }
                6 if body.len() >= 20 => {
                    let iface = self.u32(&body[..4]) as usize;
                    let (hi, lo, cap) = (
                        self.u32(&body[4..8]),
                        self.u32(&body[8..12]),
                        self.u32(&body[12..16]) as usize,
                    );
                    let Some(data) = body.get(20..20 + cap) else {
                        return Err("Truncated pcapng packet".into());
                    };
                    match self.interfaces.get(iface) {
                        Some(i) if u32::from(i.link) == LINKTYPE_ETHERNET => {
                            let ts = (u64::from(hi) << 32) | u64::from(lo);
                            return Ok(Some((i.seconds(ts), data.to_vec())));
                        }
                        Some(i) => {
                            self.other_links.insert(i.link);
                        }
                        None => {}
                    }
                    self.skipped += 1;
                }
                3 if body.len() >= 4 => {
                    let orig = self.u32(&body[..4]) as usize;
                    match self.interfaces.first() {
                        Some(i) if u32::from(i.link) == LINKTYPE_ETHERNET => {
                            let data = &body[4..];
                            return Ok(Some((0, data[..orig.min(data.len())].to_vec())));
                        }
                        Some(i) => {
                            self.other_links.insert(i.link);
                        }
                        None => {}
                    }
                    self.skipped += 1;
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
pub fn write_pcap(frames: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let mut out = vec![
        0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0,
    ];
    for (ts, f) in frames {
        out.extend(ts.to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend((f.len() as u32).to_le_bytes());
        out.extend((f.len() as u32).to_le_bytes());
        out.extend(f);
    }
    out
}

#[cfg(test)]
pub fn write_pcapng(frames: &[(u32, Vec<u8>)], big_endian: bool) -> Vec<u8> {
    let w32 = |v: u32| {
        if big_endian {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    };
    let w16 = |v: u16| {
        if big_endian {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
    };
    let block = |kind: u32, body: Vec<u8>| {
        let mut padded = body;
        while !padded.len().is_multiple_of(4) {
            padded.push(0);
        }
        let total = (padded.len() + 12) as u32;
        let mut b = w32(kind).to_vec();
        b.extend(w32(total));
        b.extend(padded);
        b.extend(w32(total));
        b
    };
    let mut shb = w32(0x1A2B3C4D).to_vec();
    shb.extend(w16(1));
    shb.extend(w16(0));
    shb.extend([0xff; 8]);
    let mut out = block(0x0A0D0D0A, shb);
    let mut idb = w16(1).to_vec();
    idb.extend(w16(0));
    idb.extend(w32(65535));
    out.extend(block(1, idb));
    let mut wifi = w16(105).to_vec();
    wifi.extend(w16(0));
    wifi.extend(w32(65535));
    out.extend(block(1, wifi));
    for (ts, f) in frames {
        let micros = u64::from(*ts) * 1_000_000;
        let mut epb = w32(0).to_vec();
        epb.extend(w32((micros >> 32) as u32));
        epb.extend(w32(micros as u32));
        epb.extend(w32(f.len() as u32));
        epb.extend(w32(f.len() as u32));
        epb.extend(f);
        out.extend(block(6, epb));
    }
    let mut skipped = w32(1).to_vec();
    skipped.extend([0; 8]);
    skipped.extend(w32(4));
    skipped.extend(w32(4));
    skipped.extend([1, 2, 3, 4]);
    out.extend(block(6, skipped));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frames() -> Vec<(u32, Vec<u8>)> {
        vec![
            (100, vec![1, 2, 3, 4, 5]),
            (101, vec![9; 60]),
            (102, vec![]),
        ]
    }
    fn read_all(bytes: &[u8]) -> Result<Vec<(i64, Vec<u8>)>, String> {
        let mut r = Reader::new(bytes)?;
        let mut out = vec![];
        while let Some(f) = r.next_frame()? {
            out.push(f);
        }
        Ok(out)
    }

    #[test]
    fn classic_pcap_round_trip() {
        let got = read_all(&write_pcap(&frames())).unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0], (100, vec![1, 2, 3, 4, 5]));
        assert_eq!(got[2], (102, vec![]));
    }

    #[test]
    fn big_endian_and_nanosecond_variants() {
        let mut be = vec![
            0xa1, 0xb2, 0xc3, 0xd4, 0, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0,
            1,
        ];
        be.extend(7u32.to_be_bytes());
        be.extend(0u32.to_be_bytes());
        be.extend(3u32.to_be_bytes());
        be.extend(3u32.to_be_bytes());
        be.extend([1, 2, 3]);
        assert_eq!(read_all(&be).unwrap(), [(7, vec![1, 2, 3])]);
        let mut nano = write_pcap(&frames());
        nano[..4].copy_from_slice(&[0x4d, 0x3c, 0xb2, 0xa1]);
        assert_eq!(read_all(&nano).unwrap().len(), 3);
    }

    #[test]
    fn pcapng_both_byte_orders_and_non_ethernet_interfaces() {
        for big in [false, true] {
            let got = read_all(&write_pcapng(&frames(), big)).unwrap();
            assert_eq!(
                got.len(),
                3,
                "big_endian={big}: the packet on the 802.11 interface is skipped"
            );
            assert_eq!(got[1], (101, vec![9; 60]));
        }
    }

    #[test]
    fn hostile_files_fail_cleanly() {
        assert!(Reader::new(&b""[..]).is_err());
        assert!(Reader::new(&b"GARBAGE-FILE-NOT-PCAP"[..]).is_err());
        let mut p = write_pcap(&frames());
        p[20] = 105;
        assert!(Reader::new(&p[..]).unwrap_err().contains("link type"));
        let p = write_pcap(&frames());
        assert!(
            read_all(&p[..p.len() - 3]).is_err(),
            "truncated final frame"
        );
        let mut huge = write_pcap(&[(1, vec![0; 4])]);
        huge[32..36].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(read_all(&huge).unwrap_err().contains("Oversized"));
        let mut ng = write_pcapng(&frames(), false);
        ng[32..36].copy_from_slice(&7u32.to_le_bytes());
        assert!(read_all(&ng).is_err());
        assert!(read_all(&write_pcapng(&frames(), false)[..40]).is_err());
    }

    fn ng_block(kind: u32, mut body: Vec<u8>) -> Vec<u8> {
        while !body.len().is_multiple_of(4) {
            body.push(0);
        }
        let total = (body.len() + 12) as u32;
        let mut b = kind.to_le_bytes().to_vec();
        b.extend(total.to_le_bytes());
        b.extend(body);
        b.extend(total.to_le_bytes());
        b
    }
    fn ng_shb() -> Vec<u8> {
        let mut shb = 0x1A2B3C4Du32.to_le_bytes().to_vec();
        shb.extend([1, 0, 0, 0]);
        shb.extend([0xff; 8]);
        ng_block(0x0A0D0D0A, shb)
    }
    fn ng_idb(link: u16, tsresol: Option<u8>) -> Vec<u8> {
        let mut idb = link.to_le_bytes().to_vec();
        idb.extend([0, 0]);
        idb.extend(65535u32.to_le_bytes());
        // an unrelated option first (if_name, 5 bytes, padded), then if_tsresol
        idb.extend([2, 0, 5, 0]);
        idb.extend(b"eth0\0");
        idb.extend([0, 0, 0]);
        if let Some(r) = tsresol {
            idb.extend([9, 0, 1, 0, r, 0, 0, 0]);
        }
        idb.extend([0, 0, 0, 0]);
        ng_block(1, idb)
    }
    fn ng_epb(iface: u32, ts: u64, data: &[u8]) -> Vec<u8> {
        let mut epb = iface.to_le_bytes().to_vec();
        epb.extend(((ts >> 32) as u32).to_le_bytes());
        epb.extend((ts as u32).to_le_bytes());
        epb.extend((data.len() as u32).to_le_bytes());
        epb.extend((data.len() as u32).to_le_bytes());
        epb.extend(data);
        ng_block(6, epb)
    }

    #[test]
    fn pcapng_timestamp_resolution_per_interface() {
        let t = 1_700_000_000u64;
        let mut f = ng_shb();
        f.extend(ng_idb(1, None)); // default: microseconds
        f.extend(ng_idb(1, Some(9))); // nanoseconds
        f.extend(ng_idb(1, Some(0x80 | 20))); // 2^-20 s
        f.extend(ng_idb(1, Some(0))); // seconds
        f.extend(ng_epb(0, t * 1_000_000 + 999_999, &[1]));
        f.extend(ng_epb(1, t * 1_000_000_000 + 5, &[2]));
        f.extend(ng_epb(2, (t << 20) | 0xfffff, &[3]));
        f.extend(ng_epb(3, t, &[4]));
        let got = read_all(&f).unwrap();
        let t = t as i64;
        assert_eq!(
            got,
            [(t, vec![1]), (t, vec![2]), (t, vec![3]), (t, vec![4])]
        );
    }

    #[test]
    fn oversized_pcapng_blocks_are_skipped() {
        let mut f = ng_shb();
        f.extend(ng_idb(1, None));
        f.extend(ng_epb(0, 1_000_000, &[1]));
        // A 400 KB custom block, then a 300 KB packet: both skipped, the file continues.
        f.extend(ng_block(0x0000_0BAD, vec![7; 400_000]));
        f.extend(ng_epb(0, 2_000_000, &vec![8; 300_000]));
        f.extend(ng_epb(0, 3_000_000, &[3]));
        let mut r = Reader::new(&f[..]).unwrap();
        let mut got = vec![];
        while let Some(frame) = r.next_frame().unwrap() {
            got.push(frame);
        }
        assert_eq!(got, [(1, vec![1]), (3, vec![3])]);
        assert_eq!(r.skipped, 2);
        // An oversized block cut short is still a truncated file.
        let mut cut = ng_shb();
        cut.extend(ng_idb(1, None));
        cut.extend(&ng_block(0x0000_0BAD, vec![7; 400_000])[..1000]);
        assert!(read_all(&cut).is_err());
    }

    #[test]
    fn classic_pcap_with_fcs_flag_in_the_link_type() {
        let mut p = write_pcap(&[(5, vec![1, 2, 3, 4, 0xde, 0xad, 0xbe, 0xef])]);
        // Ethernet, FCS present, 2 x 16-bit words = 4 bytes of FCS
        p[20..24].copy_from_slice(&(1u32 | 0x1000_0000 | (2 << 29)).to_le_bytes());
        assert_eq!(read_all(&p).unwrap(), [(5, vec![1, 2, 3, 4])]);
        // Unsupported link types say what they are.
        let mut sll = write_pcap(&frames());
        sll[20..24].copy_from_slice(&113u32.to_le_bytes());
        let e = Reader::new(&sll[..]).unwrap_err();
        assert!(e.contains("113") && e.contains("SLL"), "{e}");
        let mut f = ng_shb();
        f.extend(ng_idb(113, None));
        f.extend(ng_epb(0, 0, &[1]));
        let e = read_all(&f).unwrap_err();
        assert!(e.contains("113") && e.contains("SLL"), "{e}");
    }
}
