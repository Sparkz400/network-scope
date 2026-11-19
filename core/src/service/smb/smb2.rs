//! SMB2 NEGOTIATE response parsing (dialect, GUID, capabilities, 3.1.1 contexts) and the
//! `smb.*` identity fields built from it.
use crate::service::Fields;

/// What an SMB2 NEGOTIATE response tells beyond dialect and signing (MS-SMB2 2.2.4).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SmbNegotiate {
    pub dialect: u16,
    pub security_mode: u16,
    pub guid: [u8; 16],
    pub capabilities: u32,
    /// FILETIME (100 ns since 1601) of the server clock.
    pub system_time: u64,
    /// FILETIME of the server start; 0 on modern Windows.
    pub start_time: u64,
    pub preauth: Vec<u16>,
    pub ciphers: Vec<u16>,
    pub compression: Vec<u16>,
    pub compression_chained: bool,
    pub signing: Vec<u16>,
    /// Authentication mechanisms named in the SPNEGO security buffer.
    pub mechs: Vec<&'static str>,
}

pub fn parse_smb2_negotiate(data: &[u8]) -> Option<SmbNegotiate> {
    let smb = data.get(4..)?;
    if smb.get(..4)? != [0xFE, b'S', b'M', b'B'] || smb.get(8..12)? != [0; 4] {
        return None;
    }
    let u16_at = |i: usize| Some(u16::from_le_bytes(smb.get(i..i + 2)?.try_into().ok()?));
    let u32_at = |i: usize| Some(u32::from_le_bytes(smb.get(i..i + 4)?.try_into().ok()?));
    let u64_at = |i: usize| Some(u64::from_le_bytes(smb.get(i..i + 8)?.try_into().ok()?));
    let mut n = SmbNegotiate {
        security_mode: u16_at(66)?,
        dialect: u16_at(68)?,
        ..Default::default()
    };
    // Short (truncated or minimal) replies still give dialect and signing.
    let Some(guid) = smb.get(72..88) else {
        return Some(n);
    };
    n.guid.copy_from_slice(guid);
    n.capabilities = u32_at(88).unwrap_or(0);
    n.system_time = u64_at(104).unwrap_or(0);
    n.start_time = u64_at(112).unwrap_or(0);
    if let (Some(off), Some(len)) = (u16_at(120), u16_at(122))
        && let Some(blob) = smb.get(usize::from(off)..usize::from(off) + usize::from(len))
    {
        let has = |oid: &[u8]| blob.windows(oid.len()).any(|w| w == oid);
        for (oid, name) in [
            (
                &[0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02][..],
                "Kerberos (MS)",
            ),
            (
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02][..],
                "Kerberos",
            ),
            (
                &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x1e][..],
                "NEGOEX",
            ),
            (
                &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a][..],
                "NTLM",
            ),
        ] {
            if has(oid) {
                n.mechs.push(name);
            }
        }
    }
    if n.dialect == 0x0311 {
        let count = u16_at(70).unwrap_or(0);
        let mut at = u32_at(124).unwrap_or(0) as usize;
        for _ in 0..count.min(16) {
            let (Some(kind), Some(len)) = (u16_at(at), u16_at(at + 2)) else {
                break;
            };
            let len = usize::from(len);
            let Some(body) = smb.get(at + 8..at + 8 + len) else {
                break;
            };
            let list = |from: usize, count: usize| -> Vec<u16> {
                (0..count.min(16))
                    .filter_map(|i| {
                        body.get(from + 2 * i..from + 2 * i + 2)
                            .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    })
                    .collect()
            };
            let count_at = |i: usize| {
                body.get(i..i + 2)
                    .map_or(0, |b| usize::from(u16::from_le_bytes([b[0], b[1]])))
            };
            match kind {
                1 => n.preauth = list(4, count_at(0)),
                2 => n.ciphers = list(2, count_at(0)),
                3 => {
                    n.compression = list(8, count_at(0));
                    n.compression_chained = body.get(4).is_some_and(|f| f & 1 != 0);
                }
                8 => n.signing = list(2, count_at(0)),
                _ => {}
            }
            at += 8 + len;
            at = at.div_ceil(8) * 8;
        }
    }
    Some(n)
}

pub(super) fn smb_dialect_name(dialect: u16) -> &'static str {
    match dialect {
        0x0202 => "2.0.2",
        0x0210 => "2.1",
        0x02FF => "2.x",
        0x0300 => "3.0",
        0x0302 => "3.0.2",
        0x0311 => "3.1.1",
        _ => "unknown dialect",
    }
}

/// Server GUID in the usual registry form (first three groups little-endian).
pub fn guid_string(g: &[u8; 16]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8],
        g[9],
        g[10..]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

fn filetime_unix(ft: u64) -> Option<i64> {
    (ft > 0).then(|| (ft / 10_000_000) as i64 - 11_644_473_600)
}

/// Coarse clock offset: stable from scan to scan while the server clock is right.
fn clock_skew(seconds: i64) -> String {
    let a = seconds.unsigned_abs();
    let sign = if seconds < 0 { "-" } else { "+" };
    if a < 120 {
        "in sync (< 2 min)".into()
    } else if a < 7200 {
        format!("{sign}{} min", a / 60)
    } else if a < 172_800 {
        format!("{sign}{} h", a / 3600)
    } else {
        format!("{sign}{} days", a / 86_400)
    }
}

fn names(ids: &[u16], table: &[(u16, &str)]) -> String {
    ids.iter()
        .map(|id| {
            table
                .iter()
                .find(|t| t.0 == *id)
                .map_or_else(|| format!("0x{id:04x}"), |t| t.1.to_string())
        })
        .collect::<Vec<_>>()
        .join(", ")
}

const SMB_CIPHERS: &[(u16, &str)] = &[
    (0, "none"),
    (1, "AES-128-CCM"),
    (2, "AES-128-GCM"),
    (3, "AES-256-CCM"),
    (4, "AES-256-GCM"),
];
const SMB_COMPRESSION: &[(u16, &str)] = &[
    (0, "none"),
    (1, "LZNT1"),
    (2, "LZ77"),
    (3, "LZ77+Huffman"),
    (4, "Pattern_V1"),
    (5, "LZ4"),
];
const SMB_SIGNING: &[(u16, &str)] = &[(0, "HMAC-SHA256"), (1, "AES-CMAC"), (2, "AES-GMAC")];

/// Identity fields (`smb.<field>`) from a NEGOTIATE response. `now` is the local Unix time
/// for the clock offset. Only values that stay the same between scans are stored.
pub fn smb2_fields(n: &SmbNegotiate, now: i64) -> Fields {
    let mut f = Fields::new();
    f.insert("smb.dialect".into(), smb_dialect_name(n.dialect).into());
    if n.guid != [0; 16] {
        f.insert("smb.guid".into(), guid_string(&n.guid));
    }
    let caps: Vec<&str> = [
        (0x01, "DFS"),
        (0x02, "leasing"),
        (0x04, "large MTU"),
        (0x08, "multichannel"),
        (0x10, "persistent handles"),
        (0x20, "directory leasing"),
        (0x40, "encryption"),
        (0x80, "notifications"),
    ]
    .iter()
    .filter(|(bit, _)| n.capabilities & bit != 0)
    .map(|(_, name)| *name)
    .collect();
    if !caps.is_empty() {
        f.insert("smb.capabilities".into(), caps.join(", "));
    }
    if let Some(t) = filetime_unix(n.system_time) {
        f.insert("smb.clock_skew".into(), clock_skew(t - now));
    }
    if let Some(t) = filetime_unix(n.start_time) {
        f.insert("smb.boot_time".into(), crate::tls::date(t));
    }
    // Encryption: 3.1.1 negotiates a cipher context; 3.0/3.0.2 announce a capability.
    let encryption = match n.dialect {
        0x0311 => match n.ciphers.iter().find(|c| **c != 0) {
            Some(c) => names(&[*c], SMB_CIPHERS),
            None => "not supported".into(),
        },
        0x0300 | 0x0302 if n.capabilities & 0x40 != 0 => "supported".into(),
        0x0300 | 0x0302 => "not supported".into(),
        _ => "not supported (SMB 2.x)".into(),
    };
    f.insert("smb.encryption".into(), encryption);
    if n.dialect == 0x0311 {
        if !n.preauth.is_empty() {
            f.insert(
                "smb.preauth_integrity".into(),
                names(&n.preauth, &[(1, "SHA-512")]),
            );
        }
        let compression: Vec<u16> = n.compression.iter().copied().filter(|a| *a != 0).collect();
        f.insert(
            "smb.compression".into(),
            if compression.is_empty() {
                "none".into()
            } else {
                format!(
                    "{}{}",
                    names(&compression, SMB_COMPRESSION),
                    if n.compression_chained {
                        " (chained)"
                    } else {
                        ""
                    }
                )
            },
        );
        if !n.signing.is_empty() {
            f.insert(
                "smb.signing_algorithms".into(),
                names(&n.signing, SMB_SIGNING),
            );
        }
    }
    if !n.mechs.is_empty() {
        f.insert("smb.auth_mechs".into(), n.mechs.join(", "));
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::smb::tests::{smb2_reply, smb311_reply};

    #[test]
    fn smb2_negotiate_details_and_contexts() {
        let reply = smb311_reply(&[1, 2, 3], 2);
        let n = parse_smb2_negotiate(&reply).unwrap();
        assert_eq!(n.dialect, 0x0311);
        assert_eq!(guid_string(&n.guid), "12345678-9abc-def0-0102-030405060708");
        assert_eq!(n.ciphers, [2]);
        assert_eq!(n.compression, [1, 2, 3]);
        assert_eq!(n.signing, [2]);
        assert_eq!(n.preauth, [1]);
        assert_eq!(n.mechs, ["NTLM"]);
        let f = smb2_fields(&n, 1_704_067_200 + 30);
        assert_eq!(f["smb.dialect"], "3.1.1");
        assert_eq!(f["smb.guid"], "12345678-9abc-def0-0102-030405060708");
        assert_eq!(
            f["smb.capabilities"],
            "DFS, leasing, large MTU, multichannel, directory leasing"
        );
        assert_eq!(f["smb.clock_skew"], "in sync (< 2 min)");
        assert_eq!(f["smb.encryption"], "AES-128-GCM");
        assert_eq!(f["smb.compression"], "LZNT1, LZ77, LZ77+Huffman");
        assert_eq!(f["smb.signing_algorithms"], "AES-GMAC");
        assert_eq!(f["smb.preauth_integrity"], "SHA-512");
        assert!(!f.contains_key("smb.boot_time"));
        assert_eq!(
            smb2_fields(&n, 1_704_067_200 - 3 * 3600)["smb.clock_skew"],
            "+3 h"
        );
        // No common cipher and no compression.
        let f = smb2_fields(&parse_smb2_negotiate(&smb311_reply(&[], 0)).unwrap(), 0);
        assert_eq!(f["smb.encryption"], "not supported");
        assert_eq!(f["smb.compression"], "none");
        // SMB 3.0.2 announces encryption as a capability; 2.x has none.
        let mut n30 = n.clone();
        n30.dialect = 0x0302;
        n30.capabilities = 0x40;
        assert_eq!(smb2_fields(&n30, 0)["smb.encryption"], "supported");
        assert!(!smb2_fields(&n30, 0).contains_key("smb.compression"));
        n30.capabilities = 0;
        assert_eq!(smb2_fields(&n30, 0)["smb.encryption"], "not supported");
        n30.dialect = 0x0210;
        assert_eq!(
            smb2_fields(&n30, 0)["smb.encryption"],
            "not supported (SMB 2.x)"
        );
        // The minimal 76-byte reply of older tests still parses.
        let short = parse_smb2_negotiate(&smb2_reply(1)).unwrap();
        assert_eq!((short.dialect, short.guid), (0x0311, [0; 16]));
        assert_eq!(parse_smb2_negotiate(&reply[..40]), None);
        // Hostile context offsets and counts must not panic.
        let mut evil = reply.clone();
        evil[4 + 64 + 60..4 + 64 + 64].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        assert!(parse_smb2_negotiate(&evil).unwrap().ciphers.is_empty());
    }
}
