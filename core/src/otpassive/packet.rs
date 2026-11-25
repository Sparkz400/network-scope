// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Ethernet/IPv4 frame parsing shared by the OT decoders.
use std::net::{IpAddr, Ipv4Addr};

pub(super) fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(i..i + 2)?.try_into().ok()?))
}
pub(super) fn le16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(i..i + 2)?.try_into().ok()?))
}

pub(super) struct Packet<'a> {
    pub(super) src: IpAddr,
    pub(super) dst: IpAddr,
    /// The destination is not one host: limited/subnet broadcast or multicast (by IP or by a
    /// group destination MAC such as ff:ff:ff:ff:ff:ff).
    pub(super) dst_group: bool,
    pub(super) sport: u16,
    pub(super) dport: u16,
    pub(super) tcp: bool,
    /// TCP only: sequence number, FIN or RST set
    pub(super) seq: u32,
    pub(super) end_of_flow: bool,
    /// The capture cut the packet short (snap length): its payload is incomplete.
    pub(super) truncated: bool,
    pub(super) payload: &'a [u8],
}
pub(super) fn parse_ip(frame: &[u8]) -> Option<Packet<'_>> {
    let mut kind = be16(frame, 12)?;
    let mut offset = 14;
    for _ in 0..2 {
        if kind == 0x8100 || kind == 0x88a8 {
            kind = be16(frame, offset + 2)?;
            offset += 4;
        }
    }
    if kind != 0x0800 {
        return None;
    }
    let ip = frame.get(offset..)?;
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(ip[0] & 15) * 4;
    let claimed = usize::from(be16(ip, 2)?);
    let truncated = claimed > ip.len();
    let total = claimed.min(ip.len());
    if ihl < 20 || total < ihl || be16(ip, 6)? & 0x1fff != 0 {
        return None;
    }
    let (src, dst) = (
        IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15])),
        IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19])),
    );
    let dst_group = frame[0] & 1 != 0
        || match dst {
            IpAddr::V4(v) => v.is_broadcast() || v.is_multicast(),
            IpAddr::V6(v) => v.is_multicast(),
        };
    let l4 = ip.get(ihl..total)?;
    match ip[9] {
        6 => {
            let hl = usize::from(*l4.get(12)? >> 4) * 4;
            if hl < 20 {
                return None;
            }
            Some(Packet {
                src,
                dst,
                dst_group,
                sport: be16(l4, 0)?,
                dport: be16(l4, 2)?,
                tcp: true,
                seq: u32::from_be_bytes(l4.get(4..8)?.try_into().ok()?),
                end_of_flow: *l4.get(13)? & 0x05 != 0,
                truncated,
                payload: l4.get(hl..)?,
            })
        }
        17 => Some(Packet {
            src,
            dst,
            dst_group,
            sport: be16(l4, 0)?,
            dport: be16(l4, 2)?,
            tcp: false,
            seq: 0,
            end_of_flow: false,
            truncated,
            payload: l4.get(8..)?,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otpassive::testutil::{HMI, PLC, frame};

    #[test]
    fn tcp_header_shorter_than_20_bytes_is_rejected() {
        let mut f = frame(
            HMI,
            PLC,
            true,
            50000,
            502,
            &[0, 1, 0, 0, 0, 6, 7, 6, 0, 5, 0, 9],
        );
        let tcp = 14 + 20;
        assert!(parse_ip(&f).is_some());
        for offset in [0u8, 1, 4] {
            f[tcp + 12] = offset << 4;
            assert!(parse_ip(&f).is_none(), "data offset {offset}");
        }
    }
}
