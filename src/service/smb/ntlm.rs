//! The NTLM CHALLENGE inside an SMB2 SESSION_SETUP response.
use crate::service::Fields;

/// OS version and names from the NTLM CHALLENGE inside a SESSION_SETUP response
/// (MS-NLMP 2.2.1.2, 2.2.2.1, 2.2.2.10).
pub fn parse_ntlm_challenge(data: &[u8]) -> Fields {
    let mut f = Fields::new();
    let Some(at) = data.windows(8).position(|w| w == b"NTLMSSP\0") else {
        return f;
    };
    let m = &data[at..];
    if m.get(8..12) != Some(&[2, 0, 0, 0]) {
        return f;
    }
    let u16_at = |i: usize| m.get(i..i + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let flags = m
        .get(20..24)
        .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    if flags & 0x0200_0000 != 0
        && let Some(v) = m.get(48..56)
    {
        let build = u16::from_le_bytes([v[2], v[3]]);
        if v[0] != 0 {
            f.insert(
                "smb.os_version".into(),
                format!("{}.{}.{build}", v[0], v[1]),
            );
        }
    }
    let (Some(len), Some(off)) = (
        u16_at(40),
        m.get(44..48)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize),
    ) else {
        return f;
    };
    let Some(info) = m.get(off..off + usize::from(len)) else {
        return f;
    };
    let mut i = 0;
    while let Some(head) = info.get(i..i + 4) {
        let id = u16::from_le_bytes([head[0], head[1]]);
        let n = usize::from(u16::from_le_bytes([head[2], head[3]]));
        if id == 0 {
            break;
        }
        let Some(value) = info.get(i + 4..i + 4 + n) else {
            break;
        };
        let key = match id {
            1 => Some("smb.netbios_name"),
            2 => Some("smb.netbios_domain"),
            3 => Some("smb.dns_name"),
            4 => Some("smb.dns_domain"),
            5 => Some("smb.dns_forest"),
            _ => None,
        };
        if let Some(key) = key {
            let units: Vec<u16> = value
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect();
            let text: String = String::from_utf16_lossy(&units)
                .chars()
                .filter(|c| !c.is_control())
                .take(100)
                .collect();
            if !text.is_empty() {
                f.insert(key.into(), text);
            }
        }
        i += 4 + n;
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::smb::{smb2_session_setup_request, tests::ntlm_challenge};

    #[test]
    fn ntlm_challenge_names_os_and_host() {
        let req = smb2_session_setup_request();
        assert_eq!(
            usize::from(req[3]) + (usize::from(req[2]) << 8),
            req.len() - 4
        );
        assert_eq!(u16::from_le_bytes([req[16], req[17]]), 1, "SESSION_SETUP");
        assert!(req.windows(8).any(|w| w == b"NTLMSSP\0"));
        let f = parse_ntlm_challenge(&ntlm_challenge([10, 0, 0x63, 0x47, 0, 0, 0, 15]));
        assert_eq!(f["smb.os_version"], "10.0.18275");
        assert_eq!(f["smb.netbios_name"], "DESKTOP-42");
        assert_eq!(f["smb.netbios_domain"], "LAB");
        assert_eq!(f["smb.dns_name"], "desktop-42.lab.local");
        assert_eq!(f["smb.dns_forest"], "lab.local");
        assert!(!parse_ntlm_challenge(&ntlm_challenge([0; 8])).contains_key("smb.os_version"));
        assert!(parse_ntlm_challenge(b"no ntlm here").is_empty());
        let full = ntlm_challenge([10, 0, 0x63, 0x47, 0, 0, 0, 15]);
        for cut in [90, 120, 150, full.len() - 3] {
            let _ = parse_ntlm_challenge(&full[..cut]);
        }
    }
}
