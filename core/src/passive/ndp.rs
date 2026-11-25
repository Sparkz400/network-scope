// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! IPv6 Neighbor Discovery (RFC 4861) seen on the wire: Neighbor Solicitation and Advertisement,
//! Router Solicitation and Advertisement. Every address a host announces comes with its link-layer
//! address, so this is how IPv6 neighbours are found without sending anything.
//!
//! Only messages with hop limit 255 are accepted (RFC 4861 section 7.1: a router in between would
//! have decremented it, so such a message did not come from the link). Options are bounded.
use super::{Observation, be16, mac};
use std::net::{IpAddr, Ipv6Addr};

/// Most options read from one message.
const MAX_OPTIONS: usize = 16;

fn addr(b: &[u8]) -> Option<Ipv6Addr> {
    Some(Ipv6Addr::from(<[u8; 16]>::try_from(b.get(..16)?).ok()?))
}

/// `b` is the IPv6 packet (header first). `None` when it is not a valid ND message.
pub(super) fn decode(b: &[u8], o: &mut Observation) -> Option<()> {
    if b.len() < 48 || b[0] >> 4 != 6 || b[6] != 58 || b[7] != 255 {
        return None;
    }
    let src = addr(&b[8..])?;
    let icmp = b.get(40..40 + usize::from(be16(b, 4)?).min(b.len() - 40))?;
    if icmp.get(1) != Some(&0) {
        return None; // code is 0 in every ND message
    }
    let (name, options_at) = match icmp[0] {
        133 => ("router solicitation", 8),
        134 => ("router advertisement", 16),
        135 => ("neighbor solicitation", 24),
        136 => ("neighbor advertisement", 24),
        _ => return None,
    };
    let options = icmp.get(options_at..)?;
    o.protocol = "NDP".into();
    o.fields.insert("message".into(), name.into());
    let mut link_layer: Option<(bool, String)> = None;
    match icmp[0] {
        134 => {
            o.fields.insert("router".into(), "true".into());
            o.fields
                .insert("hop_limit".into(), icmp.get(4).copied()?.to_string());
            let flags = *icmp.get(5)?;
            o.fields
                .insert("managed".into(), (flags & 0x80 != 0).to_string());
            o.fields
                .insert("other_config".into(), (flags & 0x40 != 0).to_string());
            o.fields
                .insert("router_lifetime".into(), be16(icmp, 6)?.to_string());
        }
        135 | 136 => {
            let target = addr(icmp.get(8..)?)?;
            o.fields.insert("target".into(), target.to_string());
            if icmp[0] == 136 {
                let flags = *icmp.get(4)?;
                o.fields
                    .insert("router".into(), (flags & 0x80 != 0).to_string());
                o.fields
                    .insert("solicited".into(), (flags & 0x40 != 0).to_string());
                o.fields
                    .insert("override".into(), (flags & 0x20 != 0).to_string());
                // an advertisement describes the target
                o.ip = Some(IpAddr::V6(target));
            } else if src.is_unspecified() {
                // duplicate address detection: the sender is about to use the target
                o.fields.insert("dad".into(), "true".into());
                o.ip = Some(IpAddr::V6(target));
            }
        }
        _ => {}
    }
    let (mut prefixes, mut dns): (Vec<String>, Vec<String>) = (vec![], vec![]);
    let mut i = 0;
    for _ in 0..MAX_OPTIONS {
        let (Some(&kind), Some(&units)) = (options.get(i), options.get(i + 1)) else {
            break;
        };
        let len = usize::from(units) * 8;
        let Some(data) = options.get(i..i + len).filter(|_| len >= 8) else {
            break; // a zero or truncated option ends the message
        };
        match kind {
            1 | 2 if len == 8 => link_layer = Some((kind == 2, mac(&data[2..8]))),
            3 if len == 32 && prefixes.len() < 4 => {
                prefixes.push(format!("{}/{}", addr(&data[16..])?, data[2]));
            }
            5 if len == 8 => {
                o.fields.insert(
                    "mtu".into(),
                    u32::from_be_bytes(data[4..8].try_into().ok()?).to_string(),
                );
            }
            25 if len >= 24 => {
                for a in data[8..].as_chunks::<16>().0.iter().take(4) {
                    dns.push(addr(a)?.to_string());
                }
            }
            _ => {}
        }
        i += len;
    }
    if !prefixes.is_empty() {
        o.fields.insert("prefixes".into(), prefixes.join(", "));
    }
    if !dns.is_empty() {
        o.fields.insert("dns_servers".into(), dns.join(", "));
    }
    // The link-layer address option names the sender (solicitation, router advertisement) or the
    // target (neighbor advertisement); it is the MAC of the host the address belongs to.
    if let Some((_, address)) = link_layer {
        o.mac = address;
    }
    if o.ip.is_none() && !src.is_unspecified() {
        o.ip = Some(IpAddr::V6(src));
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::super::decode;

    const SRC_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];

    /// Ethernet + IPv6 + ICMPv6 with this hop limit and message.
    pub(crate) fn frame(src: &str, hop: u8, icmp: &[u8]) -> Vec<u8> {
        let mut f = vec![0x33, 0x33, 0, 0, 0, 1];
        f.extend(SRC_MAC);
        f.extend([0x86, 0xdd]);
        let mut ip = vec![0x60, 0, 0, 0];
        ip.extend((icmp.len() as u16).to_be_bytes());
        ip.extend([58, hop]);
        ip.extend(src.parse::<std::net::Ipv6Addr>().unwrap().octets());
        ip.extend("ff02::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
        f.extend(ip);
        f.extend(icmp);
        f
    }
    fn octets(s: &str) -> [u8; 16] {
        s.parse::<std::net::Ipv6Addr>().unwrap().octets()
    }
    fn lla(kind: u8, mac: [u8; 6]) -> Vec<u8> {
        let mut v = vec![kind, 1];
        v.extend(mac);
        v
    }

    #[test]
    fn neighbor_advertisement_names_the_target_and_its_mac() {
        let mut icmp = vec![136, 0, 0, 0, 0xe0, 0, 0, 0];
        icmp.extend(octets("2001:db8::5"));
        icmp.extend(lla(2, [0x00, 0x1b, 0x21, 0xaa, 0xbb, 0xcc]));
        let o = decode(&frame("fe80::5", 255, &icmp)).unwrap();
        assert_eq!(o.protocol, "NDP");
        assert_eq!(o.ip.unwrap().to_string(), "2001:db8::5");
        assert_eq!(o.mac, "00:1B:21:AA:BB:CC");
        assert_eq!(o.fields["message"], "neighbor advertisement");
        assert_eq!(
            (
                o.fields["router"].as_str(),
                o.fields["solicited"].as_str(),
                o.fields["override"].as_str()
            ),
            ("true", "true", "true")
        );
        // without a link-layer option the Ethernet source is the MAC
        let mut bare = vec![136, 0, 0, 0, 0x20, 0, 0, 0];
        bare.extend(octets("fe80::5"));
        let o = decode(&frame("fe80::5", 255, &bare)).unwrap();
        assert_eq!(o.mac, "02:00:00:00:00:01");
        assert_eq!(o.fields["router"], "false");
    }

    #[test]
    fn router_advertisement_carries_prefixes_mtu_and_dns() {
        let mut icmp = vec![134, 0, 0, 0, 64, 0xc0, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0];
        icmp.extend(lla(1, [0x52, 0x54, 0, 0x12, 0x34, 0x56]));
        let mut prefix = vec![
            3, 4, 64, 0xc0, 0, 0, 0x0e, 0x10, 0, 0, 0x03, 0x84, 0, 0, 0, 0,
        ];
        prefix.extend(octets("2001:db8:1::"));
        icmp.extend(prefix);
        icmp.extend([5, 1, 0, 0, 0, 0, 5, 0xdc]);
        let mut rdnss = vec![25, 3, 0, 0, 0, 0, 0x0e, 0x10];
        rdnss.extend(octets("2001:db8::53"));
        icmp.extend(rdnss);
        let o = decode(&frame("fe80::1", 255, &icmp)).unwrap();
        assert_eq!(o.mac, "52:54:00:12:34:56");
        assert_eq!(o.ip.unwrap().to_string(), "fe80::1");
        assert_eq!(o.fields["router"], "true");
        assert_eq!(o.fields["router_lifetime"], "1800");
        assert_eq!(
            (
                o.fields["managed"].as_str(),
                o.fields["other_config"].as_str()
            ),
            ("true", "true")
        );
        assert_eq!(o.fields["prefixes"], "2001:db8:1::/64");
        assert_eq!(o.fields["mtu"], "1500");
        assert_eq!(o.fields["dns_servers"], "2001:db8::53");
        assert_eq!(o.fields["hop_limit"], "64");
    }

    #[test]
    fn solicitations_including_duplicate_address_detection() {
        let mut ns = vec![135, 0, 0, 0, 0, 0, 0, 0];
        ns.extend(octets("fe80::77"));
        let o = decode(&frame("::", 255, &ns)).unwrap();
        assert_eq!(o.fields["dad"], "true");
        assert_eq!(o.ip.unwrap().to_string(), "fe80::77");
        assert_eq!(o.mac, "02:00:00:00:00:01");
        let mut ns = vec![135, 0, 0, 0, 0, 0, 0, 0];
        ns.extend(octets("fe80::1"));
        ns.extend(lla(1, [2, 0, 0, 0, 0, 9]));
        let o = decode(&frame("fe80::9", 255, &ns)).unwrap();
        assert_eq!(
            (o.ip.unwrap().to_string(), o.mac.as_str()),
            ("fe80::9".to_string(), "02:00:00:00:00:09")
        );
        assert!(!o.fields.contains_key("dad"));
        let mut rs = vec![133, 0, 0, 0, 0, 0, 0, 0];
        rs.extend(lla(1, [2, 0, 0, 0, 0, 0xa]));
        let o = decode(&frame("fe80::a", 255, &rs)).unwrap();
        assert_eq!(o.fields["message"], "router solicitation");
    }

    #[test]
    fn a_message_that_crossed_a_router_or_is_malformed_is_ignored() {
        let mut na = vec![136, 0, 0, 0, 0x60, 0, 0, 0];
        na.extend(octets("fe80::5"));
        assert!(decode(&frame("fe80::5", 255, &na)).is_some());
        for hop in [0u8, 1, 64, 254] {
            assert!(
                decode(&frame("fe80::5", hop, &na)).is_none(),
                "hop limit {hop}"
            );
        }
        let mut code = na.clone();
        code[1] = 1;
        assert!(decode(&frame("fe80::5", 255, &code)).is_none());
        // other ICMPv6 types (echo, redirect) are not decoded here
        for kind in [128u8, 129, 137, 1, 143] {
            let mut m = na.clone();
            m[0] = kind;
            assert!(decode(&frame("fe80::5", 255, &m)).is_none(), "type {kind}");
        }
        // every truncation fails cleanly or decodes what is there
        let mut ra = vec![134, 0, 0, 0, 64, 0, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0];
        ra.extend(lla(1, [2, 0, 0, 0, 0, 1]));
        let full = frame("fe80::1", 255, &ra);
        for cut in 0..full.len() {
            let _ = decode(&full[..cut]);
        }
        // options: a zero length ends the list, an oversized one is not read past the packet,
        // and more than MAX_OPTIONS are not followed
        let mut zero = ra[..16].to_vec();
        zero.extend([1, 0, 0, 0, 0, 0, 0, 0]);
        zero.extend(lla(1, [2, 0, 0, 0, 0, 7]));
        assert_eq!(
            decode(&frame("fe80::1", 255, &zero)).unwrap().mac,
            "02:00:00:00:00:01"
        );
        let mut big = ra[..16].to_vec();
        big.extend([1, 200, 0, 0, 0, 0, 0, 0]);
        assert!(decode(&frame("fe80::1", 255, &big)).is_some());
        let mut many = ra[..16].to_vec();
        for _ in 0..40 {
            many.extend([99, 1, 0, 0, 0, 0, 0, 0]);
        }
        many.extend(lla(1, [2, 0, 0, 0, 0, 8]));
        assert_eq!(
            decode(&frame("fe80::1", 255, &many)).unwrap().mac,
            "02:00:00:00:00:01"
        );
    }

    #[test]
    fn the_observation_merges_into_a_device_by_mac() {
        let mut na = vec![136, 0, 0, 0, 0x60, 0, 0, 0];
        na.extend(octets("2001:db8::5"));
        na.extend(lla(2, [0x00, 0x1b, 0x21, 0xaa, 0xbb, 0xcc]));
        let o = decode(&frame("fe80::5", 255, &na)).unwrap();
        let devices = crate::devices::merge(&[], &[o]);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].mac, "00:1B:21:AA:BB:CC");
        assert!(
            devices[0]
                .ips
                .iter()
                .any(|i| i.to_string() == "2001:db8::5")
        );
    }
}
