// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! NetBIOS browser announcements: the Computer Browser service's Host, Local Master and Domain
//! Announcements (MS-BRWS 2.2.1, 2.2.6, 2.2.12), carried in an SMB Transaction to the mailslot
//! `\MAILSLOT\BROWSE` inside a NetBIOS datagram (RFC 1002 4.4.1, UDP 138). Windows hosts and
//! Samba servers broadcast them every few minutes. Passive decoding only; nothing here transmits.
use super::{
    Observation, be16,
    hints::{self, Hint},
    netbios_name, text,
};

/// Server type bits (MS-BRWS 2.2.1, the `SV_TYPE_*` values of MS-RAP) that are shown by name.
const SERVER_TYPES: [(u32, &str); 21] = [
    (0x0000_0001, "workstation"),
    (0x0000_0002, "server"),
    (0x0000_0004, "sql_server"),
    (0x0000_0008, "domain_controller"),
    (0x0000_0010, "backup_domain_controller"),
    (0x0000_0020, "time_source"),
    (0x0000_0040, "apple"),
    (0x0000_0080, "novell"),
    (0x0000_0100, "domain_member"),
    (0x0000_0200, "print_server"),
    (0x0000_0400, "dialin_server"),
    (0x0000_0800, "unix"),
    (0x0000_1000, "nt"),
    (0x0000_2000, "wfw"),
    (0x0000_8000, "server_nt"),
    (0x0001_0000, "potential_browser"),
    (0x0002_0000, "backup_browser"),
    (0x0004_0000, "master_browser"),
    (0x0008_0000, "domain_master"),
    (0x0040_0000, "windows"),
    (0x0080_0000, "dfs"),
];
const UNIX: u32 = 0x800;
const NT: u32 = 0x1000;
const MAILSLOT: &[u8] = b"\\MAILSLOT\\BROWSE\0";

fn le16(b: &[u8], i: usize) -> Option<usize> {
    Some(u16::from_le_bytes(b.get(i..i + 2)?.try_into().ok()?).into())
}

/// Decodes a NetBIOS datagram (the UDP payload). `None` unless it is an unfragmented direct or
/// broadcast datagram holding a browser announcement.
pub(super) fn decode(b: &[u8], o: &mut Observation) -> Option<()> {
    // 0x10 direct unique, 0x11 direct group, 0x12 broadcast; flags: first fragment, no more.
    if !(0x10..=0x12).contains(b.first()?) || b.get(1)? & 3 != 2 || be16(b, 12)? != 0 {
        return None;
    }
    let mut i = 14;
    skip_name(b, &mut i)?;
    let destination = b.get(i + 1..i + 33).and_then(netbios_name);
    skip_name(b, &mut i)?;
    let smb = b.get(i..)?;
    // SMB_COM_TRANSACTION: 32-byte header, word count, words, byte count, mailslot name.
    if smb.get(..5)? != b"\xffSMB\x25" {
        return None;
    }
    let words = usize::from(*smb.get(32)?);
    if words < 14 {
        return None;
    }
    let (count, offset) = (le16(smb, 33 + 22)?, le16(smb, 33 + 24)?);
    let bytes = 33 + 2 * words + 2;
    if !smb
        .get(bytes..bytes + MAILSLOT.len())?
        .eq_ignore_ascii_case(MAILSLOT)
    {
        return None;
    }
    let d = smb.get(offset..offset + count)?;
    let announcement = match d.first()? {
        0x01 => "host",
        0x0f => "local_master",
        0x0c => "domain",
        _ => return None,
    };
    let name = until_nul(d.get(6..22)?);
    let server_type = u32::from_le_bytes(d.get(24..28)?.try_into().ok()?);
    let comment = until_nul(d.get(32..).unwrap_or_default());
    o.protocol = "NetBIOS".into();
    o.fields.insert("announcement".into(), announcement.into());
    if announcement == "domain" {
        // The name field is the workgroup or domain, the trailing string the master browser.
        o.fields.insert("workgroup".into(), name);
        if !comment.is_empty() {
            o.fields.insert("master_browser".into(), comment);
        }
    } else {
        if name.is_empty() {
            return None;
        }
        o.fields.insert("name".into(), name);
        if !comment.is_empty() {
            o.fields.insert("comment".into(), comment);
        }
        // Host announcements go to WORKGROUP<1D>, local master announcements to WORKGROUP<1E>.
        if let Some((group, 0x1d | 0x1e)) = destination
            && !group.is_empty()
        {
            o.fields.insert("workgroup".into(), group);
        }
    }
    let (major, minor) = (d[22], d[23]);
    o.fields
        .insert("os_version".into(), format!("{major}.{minor}"));
    let names: Vec<&str> = SERVER_TYPES
        .iter()
        .filter(|(bit, _)| server_type & bit != 0)
        .map(|(_, n)| *n)
        .collect();
    if !names.is_empty() {
        o.fields.insert("server_type".into(), names.join(","));
    }
    // Samba announces the Unix bit (and an announce version of its own); Windows does not. Both
    // set the NT bits, so the result is a weak hint either way.
    let hint = if server_type & UNIX != 0 {
        Hint::new("linux", false, "NetBIOS browser announcement (Samba)")
    } else if server_type & NT != 0 {
        if let Some(os) = windows_version(major, minor) {
            o.fields.insert("os_hint".into(), os.into());
        }
        Hint::new("windows", false, "NetBIOS browser announcement")
    } else {
        return Some(());
    };
    hints::attach(&mut o.fields, [hint]);
    Some(())
}

/// Moves `i` past an encoded NetBIOS name: length 32, the name, scope labels, a zero byte.
fn skip_name(b: &[u8], i: &mut usize) -> Option<()> {
    if *b.get(*i)? != 32 {
        return None;
    }
    *i += 33;
    for _ in 0..16 {
        let n = usize::from(*b.get(*i)?);
        *i += 1 + n;
        if n == 0 {
            return Some(());
        }
    }
    None
}

/// A fixed-size or trailing string: up to the first zero byte (the rest is often garbage).
fn until_nul(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    text(&b[..end]).trim().chars().take(128).collect()
}

/// The Windows release an NT-family OS version number stands for.
fn windows_version(major: u8, minor: u8) -> Option<&'static str> {
    Some(match (major, minor) {
        (4, 0) => "Windows NT 4.0",
        (5, 0) => "Windows 2000",
        (5, 1) => "Windows XP",
        (5, 2) => "Windows XP x64 / Server 2003",
        (6, 0) => "Windows Vista / Server 2008",
        (6, 1) => "Windows 7 / Server 2008 R2",
        (6, 2) => "Windows 8 / Server 2012",
        (6, 3) => "Windows 8.1 / Server 2012 R2",
        (10, 0) => "Windows 10/11 / Server 2016+",
        _ => return None,
    })
}
