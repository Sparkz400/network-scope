// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Cisco Discovery Protocol (CDP) frames: IEEE 802.3 with an LLC/SNAP header (`AA AA 03`, OUI
//! `00 00 0C`, protocol id `0x2000`) to the multicast address `01:00:0C:CC:CC:CC`. Passive
//! decoding only; nothing here transmits.
//!
//! Layout: version (1), TTL (1), checksum (2), then TLVs of type (2), length (2, including these
//! four bytes) and value. The TLV numbers follow the publicly documented CDP format as
//! implemented by Wireshark's CDP dissector; only the identity-bearing TLVs are read. The
//! checksum is not verified.
use super::{
    Observation, be16,
    hints::{self, Hint},
    text, v4,
};
use std::net::IpAddr;

/// Destination address of CDP frames.
pub(super) const DEST: [u8; 6] = [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc];
const LLC_SNAP_CISCO_CDP: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x0c, 0x20, 0x00];
/// Addresses read from one address TLV.
const MAX_ADDRESSES: u32 = 16;

/// Capability bits of TLV 0x0004.
const CAPABILITIES: [(u32, &str); 8] = [
    (0x01, "router"),
    (0x02, "transparent_bridge"),
    (0x04, "source_route_bridge"),
    (0x08, "switch"),
    (0x10, "host"),
    (0x20, "igmp"),
    (0x40, "repeater"),
    (0x80, "phone"),
];

/// Decodes the LLC payload of an 802.3 frame (`llc` starts at the `AA AA 03` header and is
/// already limited to the 802.3 length). `None` for anything that is not a CDP frame.
pub(super) fn decode(llc: &[u8], o: &mut Observation) -> Option<()> {
    if llc.get(..8)? != LLC_SNAP_CISCO_CDP {
        return None;
    }
    let cdp = &llc[8..];
    let version = *cdp.first()?;
    if !(1..=2).contains(&version) || cdp.len() < 4 {
        return None;
    }
    o.protocol = "CDP".into();
    o.fields.insert("version".into(), version.to_string());
    let mut i = 4;
    let mut address = None;
    let mut management = None;
    let mut hints = vec![];
    // A truncated or padded tail ends the loop but keeps what was read so far.
    while i + 4 <= cdp.len() {
        let kind = be16(cdp, i)?;
        let len = be16(cdp, i + 2)? as usize;
        if len < 4 {
            break;
        }
        let Some(v) = cdp.get(i + 4..i + len) else {
            break;
        };
        i += len;
        match kind {
            0x0001 => {
                let id = lines_as_text(v);
                if !id.is_empty() {
                    o.fields.insert("name".into(), id.clone());
                    o.fields.insert("device_id".into(), id);
                }
            }
            0x0002 => address = address.or_else(|| addresses(v).into_iter().next()),
            0x0003 => {
                o.fields.insert("port".into(), lines_as_text(v));
            }
            0x0004 if v.len() >= 4 => {
                let bits = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
                let names: Vec<&str> = CAPABILITIES
                    .iter()
                    .filter(|(bit, _)| bits & bit != 0)
                    .map(|(_, name)| *name)
                    .collect();
                if !names.is_empty() {
                    o.fields.insert("capabilities".into(), names.join(","));
                }
                if bits & (0x01 | 0x02 | 0x04 | 0x08 | 0x40) != 0 {
                    hints.push(Hint::new(
                        "network",
                        true,
                        format!("CDP capabilities {}", names.join(",")),
                    ));
                }
                if bits & 0x80 != 0 {
                    hints.push(Hint::new("voip", true, "CDP capability phone"));
                }
            }
            0x0005 => {
                o.fields.insert("software".into(), lines_as_text(v));
            }
            0x0006 => {
                let platform = lines_as_text(v);
                hints.extend(hints::matching(
                    &platform,
                    hints::CDP_PLATFORM,
                    "CDP platform",
                ));
                o.fields.insert("platform".into(), platform);
            }
            0x000a if v.len() == 2 => {
                o.fields
                    .insert("native_vlan".into(), be16(v, 0)?.to_string());
            }
            0x000b if v.len() == 1 => {
                o.fields.insert(
                    "duplex".into(),
                    if v[0] == 1 { "full" } else { "half" }.into(),
                );
            }
            0x0016 => management = management.or_else(|| addresses(v).into_iter().next()),
            _ => {}
        }
    }
    // The management address identifies the device better than any interface address.
    o.ip = management.or(address);
    hints::attach(&mut o.fields, hints);
    Some(())
}

/// A string TLV; line breaks (software versions are multi-line) become spaces.
fn lines_as_text(v: &[u8]) -> String {
    let flat: Vec<u8> = v
        .iter()
        .map(|&b| if b == b'\n' || b == b'\r' { b' ' } else { b })
        .collect();
    text(&flat).trim().to_string()
}

/// IPv4 addresses of an address TLV (count (4), then per address: protocol type (1), protocol
/// length (1), protocol, address length (2), address). IPv4 is NLPID type 1 with protocol 0xCC.
/// Stops at the first malformed entry and returns what was read.
fn addresses(v: &[u8]) -> Vec<IpAddr> {
    let mut out = vec![];
    let Some(count) = v
        .get(..4)
        .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
    else {
        return out;
    };
    let mut i = 4;
    for _ in 0..count.min(MAX_ADDRESSES) {
        let (Some(&kind), Some(&plen)) = (v.get(i), v.get(i + 1)) else {
            break;
        };
        let plen = plen as usize;
        let Some(proto) = v.get(i + 2..i + 2 + plen) else {
            break;
        };
        let Some(alen) = be16(v, i + 2 + plen).map(usize::from) else {
            break;
        };
        let Some(addr) = v.get(i + 4 + plen..i + 4 + plen + alen) else {
            break;
        };
        i += 4 + plen + alen;
        if kind == 1 && proto == [0xcc] && alen == 4 {
            out.extend(v4(addr));
        }
    }
    out
}
