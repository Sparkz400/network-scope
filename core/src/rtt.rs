// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Round-trip-time estimation shared by the adaptive timing of the SYN engine
//! (`--adaptive-syn`) and of the TCP connect scan (`--adaptive-tcp`).
use std::{sync::Mutex, time::Duration};

/// Smoothed RTT and RTT variance (RFC 6298 section 2, alpha 1/8, beta 1/4).
#[derive(Clone, Copy, Debug, Default)]
pub struct RttEstimator {
    srtt: f64,
    rttvar: f64,
    samples: u32,
}
impl RttEstimator {
    /// Clock granularity G of RFC 6298.
    const GRANULARITY: f64 = 0.001;
    pub fn sample(&mut self, rtt: Duration) {
        let r = rtt.as_secs_f64();
        if self.samples == 0 {
            self.srtt = r;
            self.rttvar = r / 2.0;
        } else {
            self.rttvar = 0.75 * self.rttvar + 0.25 * (self.srtt - r).abs();
            self.srtt = 0.875 * self.srtt + 0.125 * r;
        }
        self.samples = self.samples.saturating_add(1);
    }
    /// SRTT + max(G, 4 * RTTVAR), clamped to `[floor, cap]`; `None` before the first sample.
    pub fn rto(&self, floor: Duration, cap: Duration) -> Option<Duration> {
        (self.samples > 0).then(|| {
            Duration::from_secs_f64(self.srtt + (4.0 * self.rttvar).max(Self::GRANULARITY))
                .clamp(floor, cap.max(floor))
        })
    }
}

/// One target's estimator, shared by the probe tasks of that target (TCP connect scan).
#[derive(Debug, Default)]
pub struct HostRtt(Mutex<RttEstimator>);
impl HostRtt {
    fn estimator(&self) -> RttEstimator {
        *self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
    pub fn sample(&self, rtt: Duration) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).sample(rtt);
    }
    pub fn has_sample(&self) -> bool {
        self.estimator()
            .rto(Duration::ZERO, Duration::MAX)
            .is_some()
    }
    /// Wait for a first connect that completed (`SYN-ACK` or `RST`), at most `limit`.
    pub async fn wait_for_sample(&self, limit: Duration) {
        let deadline = tokio::time::Instant::now() + limit;
        while !self.has_sample() && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
    /// Connect timeout for the next attempt: SRTT + 4 * RTTVAR clamped to `[floor, cap]`
    /// (`cap` is the user's port timeout), but never longer than `first`, the wait the
    /// scan would use without adaptive timing. Without a sample it is `first`.
    pub fn timeout(&self, first: Duration, floor: Duration, cap: Duration) -> Duration {
        self.estimator()
            .rto(floor, cap)
            .map_or(first, |rto| rto.min(first))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtt_estimator_follows_rfc_6298() {
        let (floor, cap) = (Duration::from_millis(1), Duration::from_secs(10));
        let mut e = RttEstimator::default();
        assert_eq!(e.rto(floor, cap), None);
        e.sample(Duration::from_millis(100));
        // SRTT = R, RTTVAR = R/2, RTO = SRTT + 4 * RTTVAR.
        let rto = e.rto(floor, cap).unwrap().as_secs_f64();
        assert!((rto - 0.3).abs() < 1e-9, "{rto}");
        e.sample(Duration::from_millis(100));
        let rto = e.rto(floor, cap).unwrap().as_secs_f64();
        assert!((rto - 0.25).abs() < 1e-9, "RTTVAR decays: {rto}");
        e.sample(Duration::from_millis(500));
        assert!(e.rto(floor, cap).unwrap() > Duration::from_millis(500));
        // Clamped to the minimum timeout and the port timeout.
        let mut fast = RttEstimator::default();
        fast.sample(Duration::from_micros(200));
        assert_eq!(
            fast.rto(Duration::from_millis(100), cap),
            Some(Duration::from_millis(100))
        );
        assert_eq!(
            e.rto(floor, Duration::from_millis(200)),
            Some(Duration::from_millis(200))
        );
    }

    #[test]
    fn connect_timeout_is_clamped_and_never_longer_than_the_default() {
        let (floor, cap) = (Duration::from_millis(100), Duration::from_millis(2000));
        let first = Duration::from_millis(2000);
        let h = HostRtt::default();
        assert!(!h.has_sample());
        assert_eq!(h.timeout(first, floor, cap), first, "no sample: unchanged");
        // A loopback-fast host: the floor applies.
        h.sample(Duration::from_micros(300));
        assert!(h.has_sample());
        assert_eq!(h.timeout(first, floor, cap), floor);
        // A slower host: SRTT + 4 * RTTVAR = 3 * 150 ms.
        let slow = HostRtt::default();
        slow.sample(Duration::from_millis(150));
        assert_eq!(slow.timeout(first, floor, cap), Duration::from_millis(450));
        // The user's port timeout caps it, and the non-adaptive wait is an upper bound.
        assert_eq!(
            slow.timeout(first, floor, Duration::from_millis(300)),
            Duration::from_millis(300)
        );
        assert_eq!(
            slow.timeout(Duration::from_millis(200), floor, cap),
            Duration::from_millis(200)
        );
        // A timeout below the floor (user asked for 20 ms) is respected.
        assert_eq!(
            h.timeout(Duration::from_millis(20), floor, Duration::from_millis(20)),
            Duration::from_millis(20)
        );
    }

    #[tokio::test]
    async fn waiting_for_a_sample_is_bounded() {
        let h = std::sync::Arc::new(HostRtt::default());
        let start = std::time::Instant::now();
        h.wait_for_sample(Duration::from_millis(60)).await;
        assert!(start.elapsed() >= Duration::from_millis(55));
        let writer = h.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            writer.sample(Duration::from_millis(1));
        });
        let start = std::time::Instant::now();
        h.wait_for_sample(Duration::from_secs(5)).await;
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
