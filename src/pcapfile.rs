//! Offline capture files: classic pcap (all four magic variants) and pcapng, Ethernet frames only.
//! Pure Rust: no capture driver is needed to analyse a file recorded elsewhere.
use std::io::Read;

pub const MAX_FRAME: usize = 262_144;

#[derive(Debug)]
pub struct Reader<R: Read> {
    input: R,
    big_endian: bool,
    ng: bool,
    /// pcapng interfaces: true when the link type is Ethernet
    interfaces: Vec<bool>,
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
        let link = r.u32(&header[16..20]);
        if link != 1 {
            return Err(format!(
                "Unsupported link type {link}: only Ethernet captures are read"
            ));
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
        if !(28..=1 << 20).contains(&total) {
            return Err("Bad pcapng section header".into());
        }
        let mut rest = vec![0u8; total - 12];
        if !read_exact_or_eof(&mut self.input, &mut rest)? {
            return Err("Truncated pcapng header".into());
        }
        self.interfaces.clear();
        Ok(())
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
        Ok(Some((i64::from(secs), data)))
    }
    fn next_ng(&mut self) -> Result<Option<(i64, Vec<u8>)>, String> {
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
                if !(28..=1 << 20).contains(&total) {
                    return Err("Bad pcapng section header".into());
                }
                let mut rest = vec![0u8; total - 12];
                if !read_exact_or_eof(&mut self.input, &mut rest)? {
                    return Err("Truncated pcapng section".into());
                }
                self.interfaces.clear();
                continue;
            }
            let (kind, total) = (self.u32(&h[..4]), self.u32(&h[4..8]) as usize);
            if total < 12 || !total.is_multiple_of(4) || total > MAX_FRAME + 4096 {
                return Err("Bad pcapng block length".into());
            }
            let mut body = vec![0u8; total - 8];
            if !read_exact_or_eof(&mut self.input, &mut body)? {
                return Err("Truncated pcapng block".into());
            }
            let body = &body[..body.len() - 4];
            match kind {
                1 if body.len() >= 4 => self.interfaces.push(self.u16(&body[..2]) == 1),
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
                    if self.interfaces.get(iface).copied().unwrap_or(false) {
                        let micros = (u64::from(hi) << 32) | u64::from(lo);
                        return Ok(Some(((micros / 1_000_000) as i64, data.to_vec())));
                    }
                    self.skipped += 1;
                }
                3 if body.len() >= 4 => {
                    let orig = self.u32(&body[..4]) as usize;
                    if self.interfaces.first().copied().unwrap_or(false) {
                        let data = &body[4..];
                        return Ok(Some((0, data[..orig.min(data.len())].to_vec())));
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
}
