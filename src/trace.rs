//! Traceroute: all TTLs are probed in parallel (one blocking ICMP probe each), then assembled.
use crate::{core::Gate, platform::HopReply};
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
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
        gate.wait().await;
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
