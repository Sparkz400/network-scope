//! Test helpers: writers for small pcap and pcapng files. Compiled only into tests: by
//! `pcapfile.rs` for this crate's tests and by the root crate's `src/lib.rs` (`#[path]`) for the
//! GUI tests, so neither crate needs a feature for them.

/// A classic pcap file from `(timestamp, frame)` pairs.
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

/// A pcapng file (one section, one interface); see [`write_pcap`].
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
