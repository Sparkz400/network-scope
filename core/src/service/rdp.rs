// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! RDP: the standard-security request that tells whether NLA is required.
use super::{Gate, PacketKind, negotiate_once};
use std::{net::IpAddr, time::Duration};

/// X.224 Connection Request with an RDP Negotiation Request for PROTOCOL_RDP only (0x00).
pub fn rdp_standard_request() -> Vec<u8> {
    vec![
        0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0, 0, 0, 0, 0, 0x01, 0x00, 0x08, 0x00, 0, 0, 0, 0,
    ]
}

/// A server selects HYBRID (NLA) whenever the client offers it, whether or not NLA is
/// required. Offering only standard RDP security tells (MS-RDPBCGR 2.2.1.2.1/2.2.1.2.2):
/// accepted -> NLA not required; SSL_REQUIRED_BY_SERVER -> TLS without NLA is accepted;
/// HYBRID_REQUIRED_BY_SERVER -> NLA is required.
pub fn parse_rdp_standard_reply(data: &[u8]) -> Option<&'static str> {
    if data.get(..2) != Some(&[3, 0]) || data.get(5) != Some(&0xd0) {
        return None;
    }
    let value = u32::from_le_bytes(data.get(15..19)?.try_into().ok()?);
    match (data.get(11)?, value) {
        (2, 0) => Some("standard RDP security also accepted (NLA not required)"),
        (3, 1) => Some("TLS security also accepted (NLA not required)"),
        (3, 5) => Some("NLA required"),
        _ => None,
    }
}

pub(super) async fn rdp_nla_check(
    ip: IpAddr,
    port: u16,
    limit: Duration,
    gate: &Gate,
) -> Option<&'static str> {
    parse_rdp_standard_reply(
        &negotiate_once(
            ip,
            port,
            limit,
            gate,
            (PacketKind::RdpNegotiate, "standard security negotiation"),
            &rdp_standard_request(),
        )
        .await,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::{ProbeDb, detect, tests::serve};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// End to end: HYBRID selected for the normal probe, then the PROTOCOL_RDP-only offer
    /// decides whether NLA is required. Exactly two connections.
    #[tokio::test]
    async fn rdp_nla_follow_up_runs_after_hybrid() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        for (kind, value, want) in [
            (3u8, 5u8, "ms-wbt-server RDP (NLA (CredSSP); NLA required)"),
            (
                2,
                0,
                "ms-wbt-server RDP (NLA (CredSSP); standard RDP security also accepted (NLA not required))",
            ),
        ] {
            let conns = Arc::new(AtomicUsize::new(0));
            let counter = conns.clone();
            let port = serve(move |mut s| {
                counter.fetch_add(1, SeqCst);
                Box::pin(async move {
                    let mut buf = [0u8; 64];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n < 19 {
                        return;
                    }
                    let (k, v) = if buf[15] == 0 { (kind, value) } else { (2, 2) };
                    let reply = [
                        3, 0, 0, 0x13, 0x0e, 0xd0, 0, 0, 0x12, 0x34, 0, k, 0, 8, 0, v, 0, 0, 0,
                    ];
                    let _ = s.write_all(&reply).await;
                })
            })
            .await;
            let mut db = ProbeDb::builtin();
            db.probes
                .iter_mut()
                .find(|p| p.name == "rdp")
                .unwrap()
                .ports = vec![port];
            let out = detect(
                "127.0.0.1".parse().unwrap(),
                port,
                Duration::from_secs(2),
                &db,
                &Gate::unlimited(),
                4,
            )
            .await
            .unwrap();
            assert_eq!(out.service.unwrap().summary(), want);
            assert_eq!(conns.load(SeqCst), 2);
        }
    }

    #[test]
    fn rdp_standard_security_follow_up() {
        let req = rdp_standard_request();
        assert_eq!(usize::from(req[3]), req.len());
        assert_eq!(req[11], 1, "negotiation request");
        assert_eq!(&req[15..], &[0, 0, 0, 0], "PROTOCOL_RDP only");
        let reply = |kind: u8, value: u8| {
            vec![
                3, 0, 0, 0x13, 0x0e, 0xd0, 0, 0, 0x12, 0x34, 0, kind, 0, 8, 0, value, 0, 0, 0,
            ]
        };
        assert!(
            parse_rdp_standard_reply(&reply(2, 0))
                .unwrap()
                .contains("standard RDP security")
        );
        assert!(
            parse_rdp_standard_reply(&reply(3, 1))
                .unwrap()
                .contains("TLS security")
        );
        assert_eq!(parse_rdp_standard_reply(&reply(3, 5)), Some("NLA required"));
        assert_eq!(parse_rdp_standard_reply(&reply(3, 2)), None);
        assert_eq!(parse_rdp_standard_reply(b"HTTP/1.1"), None);
    }
}
