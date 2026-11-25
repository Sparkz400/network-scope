// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! SSH key exchange: KEXINIT parsing, algorithm assessment and HASSH fields.
use super::{Fields, read_some};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Default, PartialEq)]
pub struct Kexinit {
    pub kex: Vec<String>,
    pub hostkey: Vec<String>,
    pub ciphers: Vec<String>,
    pub macs: Vec<String>,
    /// All ten name-lists exactly as sent (not split or sanitised), for HASSH.
    pub raw: Vec<String>,
}

/// Parses the server's SSH_MSG_KEXINIT binary packet (RFC 4253 section 7.1).
pub fn parse_kexinit(packet: &[u8]) -> Option<Kexinit> {
    let len = u32::from_be_bytes(packet.get(..4)?.try_into().ok()?) as usize;
    if !(21..=65_536).contains(&len) {
        return None;
    }
    let body = packet.get(4..4 + len.min(packet.len() - 4))?;
    let padding = usize::from(*body.first()?);
    let payload = body.get(1..body.len().checked_sub(padding)?)?;
    if *payload.first()? != 20 {
        return None;
    }
    let mut i = 17;
    let mut lists = vec![];
    let mut raw = vec![];
    for _ in 0..10 {
        let n = u32::from_be_bytes(payload.get(i..i + 4)?.try_into().ok()?) as usize;
        let text = payload.get(i + 4..i + 4 + n)?;
        raw.push(String::from_utf8_lossy(text).into_owned());
        lists.push(
            String::from_utf8_lossy(text)
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| {
                    s.chars()
                        .filter(|c| !c.is_control())
                        .take(80)
                        .collect::<String>()
                })
                .collect::<Vec<_>>(),
        );
        i += 4 + n;
    }
    Some(Kexinit {
        kex: lists[0].clone(),
        hostkey: lists[1].clone(),
        ciphers: lists[2].clone(),
        macs: lists[4].clone(),
        raw,
    })
}

/// (weak, legacy) findings for an SSH server's offered algorithms.
pub fn assess_ssh(k: &Kexinit) -> (Vec<String>, Vec<String>) {
    let (mut weak, mut legacy) = (vec![], vec![]);
    let has = |list: &[String], name: &str| list.iter().any(|a| a == name);
    for a in &k.kex {
        match a.as_str() {
            "diffie-hellman-group1-sha1" => weak.push(format!("kex {a} (1024-bit DH, SHA-1)")),
            "diffie-hellman-group14-sha1" | "diffie-hellman-group-exchange-sha1" => {
                legacy.push(format!("kex {a} (SHA-1)"))
            }
            _ => {}
        }
    }
    for a in &k.hostkey {
        match a.as_str() {
            "ssh-dss" => weak.push(format!("host key {a} (1024-bit DSA)")),
            "ssh-rsa" => legacy.push(format!("host key {a} (SHA-1 signatures)")),
            _ => {}
        }
    }
    for a in &k.ciphers {
        let l = a.as_str();
        if l.contains("arcfour")
            || l.contains("3des")
            || l.contains("des-cbc")
            || l.contains("blowfish")
            || l.contains("cast128")
            || l == "none"
        {
            weak.push(format!("cipher {a}"));
        } else if l.ends_with("-cbc") {
            legacy.push(format!("cipher {a} (CBC)"));
        }
    }
    for a in &k.macs {
        let l = a.as_str();
        if l.contains("md5") || l.contains("-96") || l.starts_with("umac-64") || l == "none" {
            weak.push(format!("mac {a}"));
        }
    }
    let strict = has(&k.kex, "kex-strict-s-v00@openssh.com");
    let chacha = has(&k.ciphers, "chacha20-poly1305@openssh.com");
    let cbc_etm = k.ciphers.iter().any(|c| c.ends_with("-cbc"))
        && k.macs.iter().any(|m| m.ends_with("-etm@openssh.com"));
    if !strict && (chacha || cbc_etm) {
        weak.push("Terrapin (CVE-2023-48795): ChaCha20-Poly1305 or CBC-EtM offered without strict key exchange".into());
    }
    (weak, legacy)
}

/// The `ssh.*` fields of a server's KEXINIT.
pub(crate) fn kexinit_fields(k: &Kexinit) -> Fields {
    let mut f = Fields::new();
    f.insert("ssh.kex".into(), k.kex.join(", "));
    f.insert("ssh.hostkeys".into(), k.hostkey.join(", "));
    f.insert("ssh.ciphers".into(), k.ciphers.join(", "));
    f.insert("ssh.macs".into(), k.macs.join(", "));
    // HASSHServer: kex; encryption, MAC and compression server-to-client (lists 0, 3, 5, 7).
    let (hassh, algorithms) =
        crate::fingerprint::hassh_server(&k.raw[0], &k.raw[3], &k.raw[5], &k.raw[7]);
    f.insert("ssh.hassh".into(), hassh);
    f.insert(
        "ssh.hassh_algorithms".into(),
        algorithms
            .chars()
            .filter(|c| !c.is_control())
            .take(2000)
            .collect(),
    );
    let (weak, legacy) = assess_ssh(k);
    if !weak.is_empty() {
        f.insert("ssh.weak".into(), weak.join("; "));
    }
    if !legacy.is_empty() {
        f.insert("ssh.legacy".into(), legacy.join("; "));
    }
    f
}
pub(super) async fn ssh_fields<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    first: &[u8],
    limit: Duration,
) -> Fields {
    let mut f = Fields::new();
    let mut data = first
        .iter()
        .position(|b| *b == b'\n')
        .map(|n| first[n + 1..].to_vec())
        .unwrap_or_default();
    if s.write_all(b"SSH-2.0-NetworkScope\r\n").await.is_err() {
        return f;
    }
    // One bound for the whole key exchange packet, however slowly it arrives.
    let deadline = tokio::time::Instant::now() + limit + super::READ_CAP;
    if data.len() < 4 {
        data.extend(read_some(s, limit, 8192).await);
    }
    while data.len() >= 4 && tokio::time::Instant::now() < deadline {
        let need = 4 + u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() >= need || need > 70_000 {
            break;
        }
        let more = read_some(s, Duration::from_millis(400), 8192).await;
        if more.is_empty() {
            break;
        }
        data.extend(more);
    }
    if let Some(k) = parse_kexinit(&data) {
        f = kexinit_fields(&k);
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{
        identity_entries,
        tests::{run, serve},
    };
    use tokio::io::AsyncReadExt;

    fn kexinit_packet(lists: [&str; 10]) -> Vec<u8> {
        let mut payload = vec![20u8];
        payload.extend([7u8; 16]);
        for l in lists {
            payload.extend((l.len() as u32).to_be_bytes());
            payload.extend(l.as_bytes());
        }
        payload.extend([0, 0, 0, 0, 0]);
        let padding = 8 - (payload.len() + 5) % 8;
        let mut packet = ((payload.len() + padding + 1) as u32)
            .to_be_bytes()
            .to_vec();
        packet.push(padding as u8);
        packet.extend(payload);
        packet.extend(vec![0u8; padding]);
        packet
    }

    #[test]
    fn ssh_kexinit_parsing_and_assessment() {
        let p = kexinit_packet([
            "curve25519-sha256,diffie-hellman-group1-sha1,kex-strict-s-v00@openssh.com",
            "ssh-ed25519,ssh-rsa,ssh-dss",
            "chacha20-poly1305@openssh.com,aes128-cbc,3des-cbc",
            "aes128-ctr",
            "hmac-sha2-256-etm@openssh.com,hmac-md5",
            "hmac-sha2-256",
            "none",
            "none",
            "",
            "",
        ]);
        let k = parse_kexinit(&p).unwrap();
        assert_eq!(k.kex.len(), 3);
        assert_eq!(k.hostkey, ["ssh-ed25519", "ssh-rsa", "ssh-dss"]);
        assert_eq!(k.macs, ["hmac-sha2-256-etm@openssh.com", "hmac-md5"]);
        let (weak, legacy) = assess_ssh(&k);
        let weak = weak.join(";");
        assert!(
            weak.contains("diffie-hellman-group1-sha1")
                && weak.contains("ssh-dss")
                && weak.contains("3des-cbc")
                && weak.contains("hmac-md5")
        );
        assert!(!weak.contains("Terrapin"), "strict kex is offered");
        assert!(
            legacy.iter().any(|l| l.contains("ssh-rsa"))
                && legacy.iter().any(|l| l.contains("aes128-cbc"))
        );
        let modern = kexinit_packet([
            "curve25519-sha256",
            "ssh-ed25519",
            "aes256-gcm@openssh.com",
            "aes256-gcm@openssh.com",
            "hmac-sha2-512",
            "hmac-sha2-512",
            "none",
            "none",
            "",
            "",
        ]);
        let (weak, legacy) = assess_ssh(&parse_kexinit(&modern).unwrap());
        assert!(weak.is_empty() && legacy.is_empty());
        let terrapin = kexinit_packet([
            "curve25519-sha256",
            "ssh-ed25519",
            "chacha20-poly1305@openssh.com",
            "chacha20-poly1305@openssh.com",
            "hmac-sha2-512",
            "hmac-sha2-512",
            "none",
            "none",
            "",
            "",
        ]);
        assert!(assess_ssh(&parse_kexinit(&terrapin).unwrap()).0[0].contains("Terrapin"));
        assert_eq!(parse_kexinit(&p[..30]), None);
        assert_eq!(parse_kexinit(&[0, 0, 0, 1, 0]), None);
        assert_eq!(parse_kexinit(&[]), None);
        let mut bad = p.clone();
        bad[5] = 21;
        assert_eq!(parse_kexinit(&bad), None);
    }

    #[tokio::test]
    async fn live_ssh_server_algorithms_are_collected() {
        let packet = kexinit_packet([
            "diffie-hellman-group1-sha1",
            "ssh-rsa",
            "aes128-cbc",
            "aes128-cbc",
            "hmac-sha1",
            "hmac-sha1",
            "none",
            "none",
            "",
            "",
        ]);
        let port = serve(move |mut s| {
            let packet = packet.clone();
            Box::pin(async move {
                let mut out = b"SSH-2.0-OpenSSH_7.4\r\n".to_vec();
                out.extend(packet);
                let _ = s.write_all(&out).await;
                let mut buf = [0u8; 64];
                let n = s.read(&mut buf).await.unwrap_or(0);
                assert!(buf[..n].starts_with(b"SSH-2.0-NetworkScope"));
            })
        })
        .await;
        let out = run(port).await;
        let ids = identity_entries(port, &out);
        assert_eq!(ids[&format!("svc.{port}.product")], "OpenSSH");
        assert_eq!(ids[&format!("svc.{port}.version")], "7.4");
        assert!(
            ids[&format!("ssh.{port}.weak")].contains("group1"),
            "{ids:?}"
        );
        assert!(ids[&format!("ssh.{port}.legacy")].contains("aes128-cbc"));
        let text = "diffie-hellman-group1-sha1;aes128-cbc;hmac-sha1;none";
        assert_eq!(ids[&format!("ssh.{port}.hassh_algorithms")], text);
        assert_eq!(
            ids[&format!("ssh.{port}.hassh")],
            crate::fingerprint::hex(&crate::fingerprint::md5(text.as_bytes()))
        );
    }

    #[tokio::test]
    async fn trickled_key_exchange_ends_at_the_deadline() {
        // Announces a 60,000-byte packet, then sends it one byte every 50 ms.
        let port = crate::service::tests::trickle(&[0, 0, 0xEA, 0x60]).await;
        let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let start = std::time::Instant::now();
        let f = ssh_fields(&mut s, b"SSH-2.0-x\r\n", Duration::from_millis(100)).await;
        let took = start.elapsed();
        assert!(took < Duration::from_secs(3), "took {took:?}");
        assert!(f.is_empty());
    }
}
