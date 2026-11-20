//! Traceroute: all TTLs are probed in parallel (one blocking ICMP probe each), then assembled.
use crate::sendlog::PacketKind;
use crate::{core::Gate, platform::HopReply};
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
};
use tokio::{sync::Semaphore, task::JoinSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hop {
    pub ttl: u8,
    pub ip: Option<IpAddr>,
    pub rtt: Option<u32>,
}

/// Orders replies by TTL, ends the path at the destination when it answered, and drops
/// trailing hops that never answered (a silent destination looks like that).
pub fn assemble(mut replies: Vec<(u8, HopReply)>) -> Vec<Hop> {
    replies.sort_by_key(|(ttl, _)| *ttl);
    if let Some(end) = replies.iter().position(|(_, r)| r.reached) {
        replies.truncate(end + 1);
    }
    while replies.last().is_some_and(|(_, r)| r.ip.is_none()) {
        replies.pop();
    }
    replies
        .into_iter()
        .map(|(ttl, r)| Hop {
            ttl,
            ip: r.ip,
            rtt: r.rtt,
        })
        .collect()
}

/// ICMP identifier for one trace. Unique per concurrent trace in this process (so
/// raw-socket replies of parallel traces are not confused) and never equal to the
/// process-id identifier that ping echoes use.
pub fn next_trace_id() -> u16 {
    static NEXT: AtomicU16 = AtomicU16::new(0);
    let echo_id = (std::process::id() & 0xffff) as u16;
    loop {
        let id = NEXT.fetch_add(1, Ordering::Relaxed) ^ echo_id ^ 0x8000;
        if id != echo_id {
            return id;
        }
    }
}

/// How the router path is probed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TraceMethod {
    /// ICMP echo with increasing TTL (IPv6: hop limit). Works without a capture driver.
    #[default]
    Icmp,
    /// TTL-limited TCP SYNs to an open port through the capture interface.
    Tcp,
    /// UDP datagrams to high ports (33435-33498); ICMP answers read from a raw socket.
    Udp,
}

/// Ports a TCP traceroute may target: never an industrial protocol port (including the
/// ambiguous 2222) and never a raw printer port (LPD 515, JetDirect 9100-9107).
pub fn trace_port_allowed(port: u16) -> bool {
    port != 0
        && !crate::service::is_ot_port_candidate(port)
        && port != 515
        && !(9100..=9107).contains(&port)
}

/// The traceroute actually run for one host, with the reason when it differs from
/// the configured method.
#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    pub method: TraceMethod,
    pub port: Option<u16>,
    pub note: Option<String>,
}
pub fn plan(ip: IpAddr, open: &[u16], s: &crate::scan::Settings) -> Plan {
    let icmp = |note: &str| Plan {
        method: TraceMethod::Icmp,
        port: None,
        note: Some(note.to_string()),
    };
    match s.trace_method {
        TraceMethod::Icmp => Plan {
            method: TraceMethod::Icmp,
            port: None,
            note: None,
        },
        _ if s.safe => icmp("Safe Mode: ICMP traceroute used"),
        _ if ip.is_ipv6() => icmp("TCP/UDP traceroute is IPv4 only: ICMPv6 traceroute used"),
        TraceMethod::Udp => Plan {
            method: TraceMethod::Udp,
            port: None,
            note: None,
        },
        TraceMethod::Tcp => {
            let port = if s.trace_port != 0 {
                Some(s.trace_port).filter(|p| trace_port_allowed(*p))
            } else {
                open.iter().copied().find(|p| trace_port_allowed(*p))
            };
            match port {
                Some(p) => Plan {
                    method: TraceMethod::Tcp,
                    port: Some(p),
                    note: None,
                },
                None if s.trace_port != 0 => icmp(&format!(
                    "TCP traceroute never targets OT or printer port {}: ICMP traceroute used",
                    s.trace_port
                )),
                None => icmp("TCP traceroute needs an open non-OT port: ICMP traceroute used"),
            }
        }
    }
}

/// TTLs probed at once by the TCP/UDP methods; the next wave starts only when the
/// target has not answered, so few probes reach the target itself.
pub const WAVE: u8 = 3;

/// Runs `probe(ttl)` in ascending waves of `wave` TTLs (one rate-gate token each) and
/// stops after the first wave in which the destination answered.
pub async fn in_waves<F, Fut>(
    max_hops: u8,
    wave: u8,
    gate: &Gate,
    detail: &str,
    mut probe: F,
) -> (Vec<(u8, HopReply)>, Option<String>)
where
    F: FnMut(u8) -> Fut,
    Fut: std::future::Future<Output = Result<HopReply, String>> + Send + 'static,
{
    let hops = max_hops.clamp(1, 64);
    let wave = wave.max(1);
    let (mut replies, mut error) = (vec![], None);
    let mut first = 1u8;
    while first <= hops {
        let last = first.saturating_add(wave - 1).min(hops);
        let mut set = JoinSet::new();
        for ttl in first..=last {
            gate.wait_for(PacketKind::Traceroute, detail).await;
            let fut = probe(ttl);
            set.spawn(async move { (ttl, fut.await) });
        }
        let mut reached = false;
        while let Some(done) = set.join_next().await {
            match done {
                Ok((ttl, Ok(r))) => {
                    reached |= r.reached;
                    replies.push((ttl, r));
                }
                Ok((_, Err(e))) => error = Some(e),
                Err(_) => {}
            }
        }
        if reached || replies.is_empty() {
            // Done, or every probe failed locally (no raw socket): stop sending.
            break;
        }
        first = last + 1;
    }
    (replies, error)
}

/// UDP traceroute (IPv4): one datagram per TTL to `UDP_TRACE_BASE + ttl`, sent in waves.
pub async fn trace_udp(
    ip: std::net::Ipv4Addr,
    max_hops: u8,
    timeout_ms: u32,
    blocking: &Arc<Semaphore>,
    gate: &Gate,
) -> Result<Vec<Hop>, String> {
    let (replies, error) = in_waves(max_hops, WAVE, gate, "UDP datagrams, TTL sweep", |ttl| {
        let blocking = blocking.clone();
        async move {
            let permit = blocking.acquire_owned().await.map_err(|e| e.to_string())?;
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                crate::platform::udp_hop(ip, ttl, timeout_ms)
            })
            .await
            .map_err(|e| e.to_string())?
        }
    })
    .await;
    if replies.is_empty() {
        return Err(error.unwrap_or_else(|| "no traceroute replies".into()));
    }
    Ok(assemble(replies))
}

pub async fn trace(
    ip: IpAddr,
    max_hops: u8,
    timeout_ms: u32,
    blocking: &Arc<Semaphore>,
    gate: &Gate,
) -> Result<Vec<Hop>, String> {
    let mut set = JoinSet::new();
    let hops = max_hops.clamp(1, 64);
    let id = next_trace_id();
    for ttl in 1..=hops {
        gate.wait_for(PacketKind::Traceroute, "ICMP echo, TTL sweep")
            .await;
        let Ok(permit) = blocking.clone().acquire_owned().await else {
            break;
        };
        set.spawn_blocking(move || {
            let _permit = permit;
            (ttl, crate::platform::hop(ip, ttl, timeout_ms, id))
        });
    }
    let (mut replies, mut error) = (vec![], None);
    while let Some(done) = set.join_next().await {
        match done {
            Ok((ttl, Ok(r))) => replies.push((ttl, r)),
            Ok((_, Err(e))) => error = Some(e),
            Err(_) => {}
        }
    }
    if replies.is_empty() {
        return Err(error.unwrap_or_else(|| "no traceroute replies".into()));
    }
    Ok(assemble(replies))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(ip: Option<&str>, reached: bool) -> HopReply {
        HopReply {
            ip: ip.map(|s| s.parse().unwrap()),
            rtt: ip.map(|_| 1),
            reached,
        }
    }

    #[test]
    fn path_ends_at_destination_and_is_ordered() {
        let hops = assemble(vec![
            (3, reply(Some("8.8.8.8"), true)),
            (1, reply(Some("192.168.1.1"), false)),
            (4, reply(Some("8.8.8.8"), true)),
            (2, reply(None, false)),
        ]);
        assert_eq!(hops.iter().map(|h| h.ttl).collect::<Vec<_>>(), [1, 2, 3]);
        assert_eq!(hops[1].ip, None);
        assert_eq!(hops[2].ip, Some("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn silent_destination_trims_trailing_stars() {
        let hops = assemble(vec![
            (1, reply(Some("10.0.0.1"), false)),
            (2, reply(Some("10.0.1.1"), false)),
            (3, reply(None, false)),
            (4, reply(None, false)),
        ]);
        assert_eq!(hops.len(), 2);
        assert!(assemble(vec![(1, reply(None, false))]).is_empty());
        assert!(assemble(vec![]).is_empty());
    }

    #[test]
    fn trace_ids_are_distinct_and_not_the_echo_id() {
        let echo_id = (std::process::id() & 0xffff) as u16;
        let ids: std::collections::HashSet<u16> = (0..1000).map(|_| next_trace_id()).collect();
        assert_eq!(ids.len(), 1000);
        assert!(!ids.contains(&echo_id));
    }

    #[test]
    fn trace_ports_exclude_ot_and_printers() {
        for p in [0, 102, 502, 2222, 4840, 44818, 47808, 515, 9100, 9104, 9107] {
            assert!(!trace_port_allowed(p), "{p}");
        }
        for p in [22, 80, 443, 3389, 9099, 9108] {
            assert!(trace_port_allowed(p), "{p}");
        }
    }

    #[test]
    fn trace_plan_falls_back_to_icmp() {
        use crate::scan::Settings;
        let v4: IpAddr = "10.0.0.1".parse().unwrap();
        let tcp = Settings {
            safe: false,
            trace_method: TraceMethod::Tcp,
            ..Settings::default()
        };
        let p = plan(v4, &[502, 9100, 443, 80], &tcp);
        assert_eq!(
            (p.method, p.port, p.note),
            (TraceMethod::Tcp, Some(443), None)
        );
        let p = plan(v4, &[502, 9100], &tcp);
        assert_eq!(p.method, TraceMethod::Icmp);
        assert!(p.note.unwrap().contains("non-OT"));
        let fixed = Settings {
            trace_port: 102,
            ..tcp.clone()
        };
        let p = plan(v4, &[443], &fixed);
        assert_eq!(
            (p.method, p.port),
            (TraceMethod::Icmp, None),
            "explicit OT port refused"
        );
        let fixed = Settings {
            trace_port: 8443,
            ..tcp.clone()
        };
        assert_eq!(plan(v4, &[], &fixed).port, Some(8443));
        let safe = Settings {
            safe: true,
            ..tcp.clone()
        };
        let p = plan(v4, &[443], &safe);
        assert_eq!(p.method, TraceMethod::Icmp);
        assert!(p.note.unwrap().contains("Safe Mode"));
        let p = plan("2001:db8::1".parse().unwrap(), &[443], &tcp);
        assert_eq!(p.method, TraceMethod::Icmp);
        let udp = Settings {
            trace_method: TraceMethod::Udp,
            ..tcp
        };
        assert_eq!(plan(v4, &[], &udp).method, TraceMethod::Udp);
        assert_eq!(
            plan(v4, &[], &Settings::default()),
            Plan {
                method: TraceMethod::Icmp,
                port: None,
                note: None
            }
        );
    }

    #[tokio::test]
    async fn waves_ascend_and_stop_at_the_destination() {
        let sent = Arc::new(std::sync::Mutex::new(vec![]));
        let log = sent.clone();
        let (replies, error) = in_waves(30, 3, &Gate::unlimited(), "test", move |ttl| {
            log.lock().unwrap().push(ttl);
            async move {
                Ok(if ttl >= 5 {
                    reply(Some("8.8.8.8"), true)
                } else {
                    reply(Some("10.0.0.1"), false)
                })
            }
        })
        .await;
        assert_eq!(error, None);
        let mut ttls = sent.lock().unwrap().clone();
        ttls.sort();
        assert_eq!(ttls, [1, 2, 3, 4, 5, 6], "two waves, nothing beyond");
        assert_eq!(assemble(replies).len(), 5);
        // A local failure (no raw socket) stops after the first wave.
        let count = Arc::new(std::sync::Mutex::new(0));
        let c = count.clone();
        let (replies, error) = in_waves(30, 3, &Gate::unlimited(), "test", move |_| {
            *c.lock().unwrap() += 1;
            async { Err("needs a raw socket".to_string()) }
        })
        .await;
        assert!(replies.is_empty());
        assert_eq!(error.as_deref(), Some("needs a raw socket"));
        assert_eq!(*count.lock().unwrap(), 3);
    }

    #[tokio::test]
    async fn loopback_traces_in_one_hop() {
        let blocking = Arc::new(Semaphore::new(8));
        let hops = trace(
            "127.0.0.1".parse().unwrap(),
            4,
            1000,
            &blocking,
            &Gate::unlimited(),
        )
        .await;
        match hops {
            Ok(h) => {
                assert_eq!(h.len(), 1, "{h:?}");
                assert_eq!(h[0].ip, Some("127.0.0.1".parse().unwrap()));
            }
            Err(e) => assert!(cfg!(not(windows)) && e.contains("root"), "{e}"),
        }
    }
}
