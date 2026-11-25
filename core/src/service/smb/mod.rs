// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! SMB 1 and SMB 2/3: NEGOTIATE requests, the SMB1/SMB2 probing flow and its Outcome. The
//! SMB2 reply details live in `smb2`, the NTLM challenge in `ntlm`.
use super::{Fields, Outcome, Service, connect, negotiate_once};
use crate::{core::Gate, sendlog::PacketKind};
use std::{net::IpAddr, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

mod ntlm;
mod smb2;

pub use ntlm::parse_ntlm_challenge;
pub use smb2::{parse_smb2_negotiate, smb2_fields};

use smb2::smb_dialect_name;

/// Client capabilities offered so the server reports its own (MS-SMB2 3.3.5.4 only echoes
/// leasing, multichannel and, for 3.0/3.0.2, encryption when the client sets them): DFS,
/// leasing, large MTU, multichannel, persistent handles, directory leasing, encryption.
const SMB2_CLIENT_CAPS: u32 = 0x7F;

fn smb2_header(command: u16, message_id: u64) -> Vec<u8> {
    let mut m = vec![0xFE, b'S', b'M', b'B'];
    m.extend(64u16.to_le_bytes()); // structure size
    m.extend([0; 2]); // credit charge
    m.extend([0; 4]); // status
    m.extend(command.to_le_bytes());
    m.extend(1u16.to_le_bytes()); // credits requested
    m.extend([0; 4]); // flags
    m.extend([0; 4]); // next command
    m.extend(message_id.to_le_bytes());
    m.extend([0; 4]); // process id
    m.extend([0; 4]); // tree id
    m.extend([0; 8]); // session id
    m.extend([0; 16]); // signature
    m
}

fn netbios_frame(m: Vec<u8>) -> Vec<u8> {
    let mut packet = vec![0];
    packet.extend(&(m.len() as u32).to_be_bytes()[1..]);
    packet.extend(m);
    packet
}

/// SMB2 NEGOTIATE offering 2.0.2 to 3.1.1 with the 3.1.1 negotiate contexts: preauth
/// integrity (SHA-512), encryption (AES-128/256 CCM/GCM), compression (LZNT1, LZ77,
/// LZ77+Huffman, Pattern_V1, LZ4) and signing (HMAC-SHA256, AES-CMAC, AES-GMAC).
pub fn smb2_negotiate_request() -> Vec<u8> {
    let mut m = smb2_header(0, 0);
    m.extend(36u16.to_le_bytes());
    m.extend(5u16.to_le_bytes()); // dialect count
    m.extend(1u16.to_le_bytes()); // security mode: signing enabled
    m.extend([0; 2]);
    m.extend(SMB2_CLIENT_CAPS.to_le_bytes());
    m.extend([0x4e; 16]); // client GUID
    m.extend(112u32.to_le_bytes()); // negotiate context offset
    m.extend(4u16.to_le_bytes()); // negotiate context count
    m.extend([0; 2]);
    for dialect in [0x0202u16, 0x0210, 0x0300, 0x0302, 0x0311] {
        m.extend(dialect.to_le_bytes());
    }
    m.extend([0; 2]);
    assert_eq!(m.len(), 112);
    let mut preauth = vec![];
    preauth.extend(1u16.to_le_bytes()); // hash algorithm count
    preauth.extend(32u16.to_le_bytes()); // salt length
    preauth.extend(1u16.to_le_bytes()); // SHA-512
    preauth.extend([0x5a; 32]);
    let mut encryption = 4u16.to_le_bytes().to_vec();
    for cipher in [0x0002u16, 0x0001, 0x0004, 0x0003] {
        encryption.extend(cipher.to_le_bytes());
    }
    let mut compression = 5u16.to_le_bytes().to_vec();
    compression.extend([0; 2]); // padding
    compression.extend([0; 4]); // flags: no chaining
    for algorithm in [1u16, 2, 3, 4, 5] {
        compression.extend(algorithm.to_le_bytes());
    }
    let mut signing = 3u16.to_le_bytes().to_vec();
    for algorithm in [2u16, 1, 0] {
        signing.extend(algorithm.to_le_bytes());
    }
    let contexts: [(u16, Vec<u8>); 4] = [
        (1, preauth),
        (2, encryption),
        (3, compression),
        (8, signing),
    ];
    for (i, (kind, data)) in contexts.iter().enumerate() {
        m.extend(kind.to_le_bytes());
        m.extend((data.len() as u16).to_le_bytes());
        m.extend([0; 4]);
        m.extend(data);
        if i + 1 < contexts.len() {
            while !m.len().is_multiple_of(8) {
                m.push(0);
            }
        }
    }
    netbios_frame(m)
}

/// NTLMSSP NEGOTIATE (no credentials) in a SPNEGO NegTokenInit, sent as SMB2 SESSION_SETUP.
/// The server answers with an NTLM CHALLENGE naming its OS version and NetBIOS/DNS names;
/// the exchange stops there, so no logon is attempted or logged as failed.
pub fn smb2_session_setup_request() -> Vec<u8> {
    let mut ntlm = b"NTLMSSP\0".to_vec();
    ntlm.extend(1u32.to_le_bytes());
    // Unicode, request target, NTLM, always sign, extended session security, version,
    // 128-bit, key exchange, 56-bit.
    ntlm.extend(0xE208_8205u32.to_le_bytes());
    ntlm.extend([0; 16]); // empty domain and workstation fields
    ntlm.extend([0; 8]); // version
    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        match content.len() {
            n if n < 128 => v.push(n as u8),
            n => v.extend([0x81, n as u8]),
        }
        v.extend(content);
        v
    }
    let ntlm_oid = [
        0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
    ];
    let mech_types = der(0xa0, &der(0x30, &ntlm_oid));
    let mech_token = der(0xa2, &der(0x04, &ntlm));
    let init = der(0xa0, &der(0x30, &[mech_types, mech_token].concat()));
    let spnego_oid = [0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
    let token = der(0x60, &[spnego_oid.to_vec(), init].concat());
    let mut m = smb2_header(1, 1);
    m.extend(25u16.to_le_bytes());
    m.push(0); // flags
    m.push(1); // security mode: signing enabled
    m.extend(1u32.to_le_bytes()); // capabilities: DFS
    m.extend([0; 4]); // channel
    m.extend(88u16.to_le_bytes()); // security buffer offset
    m.extend((token.len() as u16).to_le_bytes());
    m.extend([0; 8]); // previous session id
    m.extend(token);
    netbios_frame(m)
}
/// SMB1 SMB_COM_NEGOTIATE offering only the "NT LM 0.12" dialect: a server that selects it
/// has SMBv1 enabled. Read-only, like the SMB2 negotiate.
pub fn smb1_negotiate_request() -> Vec<u8> {
    let mut m = vec![0xFF, b'S', b'M', b'B', 0x72];
    m.extend([0; 4]); // status
    m.push(0x18); // flags: canonical paths, case-insensitive
    m.extend(0xC001u16.to_le_bytes()); // flags2: unicode, NT status, long names
    m.extend([0; 12]); // PID high, security features, reserved
    m.extend([0; 2]); // TID
    m.extend(0xFEFFu16.to_le_bytes()); // PID low
    m.extend([0; 2]); // UID
    m.extend([0; 2]); // MID
    assert_eq!(m.len(), 32);
    m.push(0); // word count
    let dialects = b"\x02NT LM 0.12\x00";
    m.extend((dialects.len() as u16).to_le_bytes());
    m.extend(dialects);
    let mut packet = vec![0];
    packet.extend(&(m.len() as u32).to_be_bytes()[1..]);
    packet.extend(m);
    packet
}

/// True when `data` is an SMB1 negotiate response that selected our only dialect (index 0).
/// Servers with SMB1 disabled close the connection or answer with index 0xFFFF.
pub fn smb1_accepted(data: &[u8]) -> bool {
    data.get(4..8) == Some(&[0xFF, b'S', b'M', b'B'])
        && data.get(8) == Some(&0x72)
        && data.get(9..13) == Some(&[0; 4])
        && data.get(36).is_some_and(|wc| *wc >= 1)
        && data.get(37..39) == Some(&[0, 0])
}

pub fn parse_smb(data: &[u8]) -> Option<Service> {
    let magic = data.get(4..8)?;
    if magic == [0xFF, b'S', b'M', b'B'] {
        if !smb1_accepted(data) {
            return None;
        }
        return Some(Service {
            name: "microsoft-ds".into(),
            product: "SMBv1".into(),
            info: "SMBv1 enabled (legacy, insecure)".into(),
            ..Default::default()
        });
    }
    if magic != [0xFE, b'S', b'M', b'B'] || data.get(12..16)? != [0; 4] {
        return None;
    }
    let mode = u16::from_le_bytes(data.get(70..72)?.try_into().ok()?);
    let dialect = u16::from_le_bytes(data.get(72..74)?.try_into().ok()?);
    let version = smb_dialect_name(dialect);
    Some(Service {
        name: "microsoft-ds".into(),
        product: "SMB".into(),
        version: version.into(),
        info: if mode & 2 != 0 {
            "signing required"
        } else if mode & 1 != 0 {
            "signing enabled, not required"
        } else {
            "signing disabled"
        }
        .into(),
    })
}

/// Reads one NetBIOS-framed message (or what arrives within `limit`).
async fn read_frame<S: AsyncRead + Unpin>(s: &mut S, limit: Duration) -> Vec<u8> {
    let mut data = vec![];
    let mut chunk = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + limit;
    while data.len() < 65_536 {
        if data.len() >= 4 {
            let need = 4
                + ((usize::from(data[1]) << 16)
                    | (usize::from(data[2]) << 8)
                    | usize::from(data[3]));
            if data.len() >= need {
                break;
            }
        }
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match timeout(left, s.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => data.extend_from_slice(&chunk[..n]),
            _ => break,
        }
    }
    data
}

/// NEGOTIATE, then (same connection) the credential-less SESSION_SETUP for the NTLM
/// challenge. Returns the negotiate reply and the NTLM fields. Safe Mode sends only the
/// NEGOTIATE, so it gets no Windows build or NetBIOS/DNS names.
async fn smb2_exchange(ip: IpAddr, port: u16, limit: Duration, gate: &Gate) -> (Vec<u8>, Fields) {
    let Some(mut s) = connect(ip, port, limit, gate).await else {
        return (vec![], Fields::new());
    };
    gate.note(PacketKind::SmbNegotiate, "SMB2 negotiate");
    if s.write_all(&smb2_negotiate_request()).await.is_err() {
        return (vec![], Fields::new());
    }
    let reply = read_frame(&mut s, limit).await;
    let mut ntlm = Fields::new();
    if !gate.is_safe() && parse_smb2_negotiate(&reply).is_some() && {
        gate.note(
            PacketKind::SmbNegotiate,
            "NTLM SESSION_SETUP (no AUTHENTICATE)",
        );
        s.write_all(&smb2_session_setup_request()).await.is_ok()
    } {
        ntlm = parse_ntlm_challenge(&read_frame(&mut s, limit).await);
    }
    (reply, ntlm)
}

/// SMB2 negotiate (dialect, signing, GUID, capabilities, 3.1.1 contexts) with the NTLM
/// challenge on the same connection, plus a separate SMB1 negotiate offering only
/// "NT LM 0.12": modern servers answer the SMB2 request with SMB2 even when SMB1 is still
/// enabled, so only the SMB1-only offer reveals it. Two connections, both through the gate.
pub(super) async fn smb_negotiate(
    ip: IpAddr,
    port: u16,
    limit: Duration,
    gate: &Gate,
) -> Option<Outcome> {
    let (reply, ntlm) = smb2_exchange(ip, port, limit, gate).await;
    let smb2 = parse_smb(&reply);
    let smb1 = smb1_accepted(
        &negotiate_once(
            ip,
            port,
            limit,
            gate,
            (PacketKind::SmbNegotiate, "SMB1 negotiate"),
            &smb1_negotiate_request(),
        )
        .await,
    );
    let mut out = Outcome::default();
    match (smb2, smb1) {
        (Some(svc), smb1) => {
            out.fields.insert(
                "smb.smb1".into(),
                if smb1 || svc.product == "SMBv1" {
                    "accepted"
                } else {
                    "refused"
                }
                .into(),
            );
            if let Some(n) = parse_smb2_negotiate(&reply) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs() as i64);
                out.fields.extend(smb2_fields(&n, now));
            }
            out.fields.extend(ntlm);
            out.service = Some(svc);
        }
        (None, true) => {
            out.fields.insert("smb.smb1".into(), "accepted".into());
            out.service = Some(Service {
                name: "microsoft-ds".into(),
                product: "SMBv1".into(),
                info: "SMBv1 enabled (legacy, insecure)".into(),
                ..Default::default()
            });
        }
        (None, false) => return None,
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{identity_entries, tests::serve};
    use std::sync::Arc;

    #[test]
    fn smb_request_and_responses() {
        let req = smb2_negotiate_request();
        assert_eq!(req.len(), 4 + 232);
        assert_eq!(&req[..4], &[0, 0, 0, 232]);
        assert_eq!(&req[4..8], &[0xFE, b'S', b'M', b'B']);
        // Contexts start 8-aligned at 112: preauth, encryption, compression, signing.
        let smb = &req[4..];
        assert_eq!(u16::from_le_bytes([smb[96], smb[97]]), 4, "context count");
        for (at, kind) in [(112, 1u16), (160, 2), (184, 3), (216, 8)] {
            assert_eq!(u16::from_le_bytes([smb[at], smb[at + 1]]), kind, "at {at}");
        }
        assert_eq!(u32::from_le_bytes(smb[72..76].try_into().unwrap()), 0x7F);
        let mut resp = vec![0u8; 4 + 64 + 8];
        resp[4..8].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
        resp[70..72].copy_from_slice(&3u16.to_le_bytes());
        resp[72..74].copy_from_slice(&0x0311u16.to_le_bytes());
        assert_eq!(
            parse_smb(&resp).unwrap().summary(),
            "microsoft-ds SMB 3.1.1 (signing required)"
        );
        resp[70] = 1;
        assert_eq!(
            parse_smb(&resp).unwrap().info,
            "signing enabled, not required"
        );
        let mut v1 = vec![0u8; 40];
        v1[4..9].copy_from_slice(&[0xFF, b'S', b'M', b'B', 0x72]);
        v1[36] = 17;
        assert!(parse_smb(&v1).unwrap().info.contains("SMBv1"));
        // An SMB1 reply that selected no dialect is not SMBv1 support.
        v1[37..39].copy_from_slice(&[0xFF, 0xFF]);
        assert_eq!(parse_smb(&v1), None);
        assert_eq!(parse_smb(&resp[..20]), None);
        assert_eq!(parse_smb(b"HTTP/1.1 200 OK\r\n\r\n"), None);
    }

    #[test]
    fn smb1_negotiate_request_and_replies() {
        let req = smb1_negotiate_request();
        assert_eq!(usize::from(req[3]), req.len() - 4);
        assert_eq!(&req[4..9], &[0xFF, b'S', b'M', b'B', 0x72]);
        assert!(req.ends_with(b"\x02NT LM 0.12\x00"));
        assert_eq!(req[36], 0, "word count");
        assert_eq!(usize::from(u16::from_le_bytes([req[37], req[38]])), 12);
        let reply = |status: u8, word_count: u8, index: u16| {
            let mut r = vec![0u8, 0, 0, 0];
            r.extend([0xFF, b'S', b'M', b'B', 0x72, status, 0, 0, 0]);
            r.extend([0u8; 23]);
            r.push(word_count);
            r.extend(index.to_le_bytes());
            r.extend([0u8; 40]);
            r
        };
        assert!(smb1_accepted(&reply(0, 17, 0)));
        assert!(!smb1_accepted(&reply(0, 1, 0xFFFF)), "no dialect chosen");
        assert!(!smb1_accepted(&reply(0x22, 0, 0)), "error status");
        assert!(!smb1_accepted(&[]));
        assert!(parse_smb(&reply(0, 17, 0)).unwrap().info.contains("SMBv1"));
        assert_eq!(parse_smb(&reply(0, 1, 0xFFFF)), None);
    }

    pub(super) fn smb2_reply(mode: u16) -> Vec<u8> {
        let mut resp = vec![0u8; 4 + 64 + 8];
        resp[4..8].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
        resp[70..72].copy_from_slice(&mode.to_le_bytes());
        resp[72..74].copy_from_slice(&0x0311u16.to_le_bytes());
        resp
    }

    /// A Windows-like server: SMB2 for SMB2 requests and, when `smb1` is set, an SMB1
    /// negotiate response selecting "NT LM 0.12"; otherwise it closes on SMB1.
    async fn smb_server(smb1: bool) -> u16 {
        serve(move |mut s| {
            Box::pin(async move {
                let mut buf = [0u8; 512];
                let n = s.read(&mut buf).await.unwrap_or(0);
                if n > 8 && buf[4] == 0xFE {
                    let _ = s.write_all(&smb2_reply(1)).await;
                } else if n > 8 && buf[4] == 0xFF && smb1 {
                    let mut r = vec![0u8, 0, 0, 80, 0xFF, b'S', b'M', b'B', 0x72];
                    r.extend([0u8; 27]);
                    r.push(17);
                    r.extend([0u8; 60]);
                    let _ = s.write_all(&r).await;
                }
            })
        })
        .await
    }

    #[tokio::test]
    async fn smb1_is_detected_with_a_separate_negotiate() {
        let ip = "127.0.0.1".parse().unwrap();
        let limit = Duration::from_secs(1);
        let gate = Gate::unlimited();
        let both = smb_negotiate(ip, smb_server(true).await, limit, &gate)
            .await
            .unwrap();
        assert_eq!(
            both.service.unwrap().summary(),
            "microsoft-ds SMB 3.1.1 (signing enabled, not required)"
        );
        assert_eq!(both.fields["smb.smb1"], "accepted");
        let modern = smb_negotiate(ip, smb_server(false).await, limit, &gate)
            .await
            .unwrap();
        assert_eq!(modern.fields["smb.smb1"], "refused");
        let ids = identity_entries(445, &modern);
        assert_eq!(ids["smb.445.smb1"], "refused");
    }

    /// A Windows-like SMB 3.1.1 NEGOTIATE response with GUID, capabilities, times, a SPNEGO
    /// hint and the four negotiate contexts.
    pub(super) fn smb311_reply(compression: &[u16], cipher: u16) -> Vec<u8> {
        let mut smb = vec![0u8; 64];
        smb[..4].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
        let mut body = vec![0u8; 64];
        body[0..2].copy_from_slice(&65u16.to_le_bytes());
        body[2..4].copy_from_slice(&1u16.to_le_bytes()); // signing enabled
        body[4..6].copy_from_slice(&0x0311u16.to_le_bytes());
        body[6..8].copy_from_slice(&4u16.to_le_bytes());
        body[8..24].copy_from_slice(&[
            0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 1, 2, 3, 4, 5, 6, 7, 8,
        ]);
        body[24..28].copy_from_slice(&0x2Fu32.to_le_bytes()); // DFS, leasing, MTU, MC, PH
        // 2024-01-01T00:00:00Z as FILETIME.
        let ft = (1_704_067_200u64 + 11_644_473_600) * 10_000_000;
        body[40..48].copy_from_slice(&ft.to_le_bytes());
        let mech = [
            0x06u8, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
        ];
        body[56..58].copy_from_slice(&128u16.to_le_bytes());
        body[58..60].copy_from_slice(&(mech.len() as u16).to_le_bytes());
        smb.extend(body);
        smb.extend(mech);
        while !smb.len().is_multiple_of(8) {
            smb.push(0);
        }
        let ctx_at = smb.len() as u32;
        smb[64 + 60..64 + 64].copy_from_slice(&ctx_at.to_le_bytes());
        let mut comp = (compression.len() as u16).to_le_bytes().to_vec();
        comp.extend([0, 0, 0, 0, 0, 0]);
        for a in compression {
            comp.extend(a.to_le_bytes());
        }
        let contexts: Vec<(u16, Vec<u8>)> = vec![
            (
                1,
                [1u16, 32, 1]
                    .iter()
                    .flat_map(|v| v.to_le_bytes())
                    .chain([9u8; 32])
                    .collect(),
            ),
            (
                2,
                [1u16, cipher]
                    .iter()
                    .flat_map(|v| v.to_le_bytes())
                    .collect(),
            ),
            (3, comp),
            (8, [1u16, 2].iter().flat_map(|v| v.to_le_bytes()).collect()),
        ];
        for (i, (kind, data)) in contexts.iter().enumerate() {
            smb.extend(kind.to_le_bytes());
            smb.extend((data.len() as u16).to_le_bytes());
            smb.extend([0; 4]);
            smb.extend(data);
            if i + 1 < contexts.len() {
                while !smb.len().is_multiple_of(8) {
                    smb.push(0);
                }
            }
        }
        netbios_frame(smb)
    }

    pub(super) fn ntlm_challenge(version: [u8; 8]) -> Vec<u8> {
        let mut info = vec![];
        for (id, text) in [
            (1u16, "DESKTOP-42"),
            (2, "LAB"),
            (3, "desktop-42.lab.local"),
            (4, "lab.local"),
            (5, "lab.local"),
        ] {
            let units: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
            info.extend(id.to_le_bytes());
            info.extend((units.len() as u16).to_le_bytes());
            info.extend(units);
        }
        info.extend([7, 0, 8, 0, 1, 2, 3, 4, 5, 6, 7, 8]); // timestamp: ignored
        info.extend([0, 0, 0, 0]);
        let mut m = b"NTLMSSP\0".to_vec();
        m.extend(2u32.to_le_bytes());
        m.extend([0; 8]); // target name
        m.extend(0xE289_8215u32.to_le_bytes());
        m.extend([0x11; 8]); // challenge
        m.extend([0; 8]);
        m.extend((info.len() as u16).to_le_bytes());
        m.extend((info.len() as u16).to_le_bytes());
        m.extend(56u32.to_le_bytes());
        m.extend(version);
        m.extend(info);
        // Wrapped in some SPNEGO/SMB2 bytes, as it arrives.
        let mut reply = vec![0u8; 4 + 64 + 8 + 9];
        reply.extend(m);
        reply
    }

    #[tokio::test]
    async fn live_smb_negotiate_collects_identity() {
        let port = serve(|mut s| {
            Box::pin(async move {
                let mut buf = [0u8; 1024];
                let n = s.read(&mut buf).await.unwrap_or(0);
                if n > 8 && buf[4] == 0xFE {
                    let _ = s.write_all(&smb311_reply(&[1], 4)).await;
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n > 20 && buf[16] == 1 {
                        let mut frame = ntlm_challenge([10, 0, 0xBB, 0x47, 0, 0, 0, 15]);
                        let len = frame.len() - 4;
                        frame[1..4].copy_from_slice(&(len as u32).to_be_bytes()[1..]);
                        frame[4..8].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
                        let _ = s.write_all(&frame).await;
                    }
                }
            })
        })
        .await;
        let out = smb_negotiate(
            "127.0.0.1".parse().unwrap(),
            port,
            Duration::from_secs(1),
            &Gate::unlimited(),
        )
        .await
        .unwrap();
        assert_eq!(
            out.service.as_ref().unwrap().summary(),
            "microsoft-ds SMB 3.1.1 (signing enabled, not required)"
        );
        let ids = identity_entries(445, &out);
        assert_eq!(ids["smb.445.guid"], "12345678-9abc-def0-0102-030405060708");
        assert_eq!(ids["smb.445.encryption"], "AES-256-GCM");
        assert_eq!(ids["smb.445.compression"], "LZNT1");
        assert_eq!(ids["smb.445.os_version"], "10.0.18363");
        assert_eq!(ids["smb.445.netbios_name"], "DESKTOP-42");
        assert_eq!(ids["smb.445.smb1"], "refused");
    }
    /// Safe Mode sends the SMB2 NEGOTIATE but never the NTLM SESSION_SETUP.
    #[tokio::test]
    async fn safe_mode_skips_the_ntlm_session_setup() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let setup_seen = Arc::new(AtomicBool::new(false));
        let seen = setup_seen.clone();
        let port = serve(move |mut s| {
            let seen = seen.clone();
            Box::pin(async move {
                let mut buf = [0u8; 1024];
                let n = s.read(&mut buf).await.unwrap_or(0);
                if n > 8 && buf[4] == 0xFE {
                    let _ = s.write_all(&smb311_reply(&[1], 4)).await;
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n > 20 && buf[16] == 1 {
                        seen.store(true, Ordering::SeqCst);
                    }
                }
            })
        })
        .await;
        let gate = Gate::unlimited().with_safe(true);
        let out = smb_negotiate(
            "127.0.0.1".parse().unwrap(),
            port,
            Duration::from_millis(300),
            &gate,
        )
        .await
        .unwrap();
        let ids = identity_entries(445, &out);
        assert_eq!(ids["smb.445.guid"], "12345678-9abc-def0-0102-030405060708");
        assert!(!ids.contains_key("smb.445.os_version"));
        assert!(!ids.contains_key("smb.445.netbios_name"));
        assert!(
            !setup_seen.load(Ordering::SeqCst),
            "no SESSION_SETUP in Safe Mode"
        );
    }
}
