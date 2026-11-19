//! Recurring scans for the desktop GUI: the settings and the decision of what to do on each tick.
//! A scheduled scan is an ordinary scan with the user's current settings (Safe Mode included),
//! started while the program is open; for monitoring that survives a closed window or a reboot
//! use `monitor` as a service (`service install` on Windows, the systemd units in
//! `packaging/systemd`). The decisions are pure functions so the rules are tested without a window.
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Shortest interval between two scheduled scans. A scan is a load on the network, and in Safe
/// Mode a /24 takes minutes, so a shorter interval would just queue scans up.
pub const MIN_INTERVAL_MINUTES: u32 = 5;
/// Longest interval (one week).
pub const MAX_INTERVAL_MINUTES: u32 = 7 * 24 * 60;

/// The saved scheduler settings. Off by default; nothing runs until the user enables it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Schedule {
    pub enabled: bool,
    pub interval_minutes: u32,
    /// What to scan, in the same syntax as the main window (`192.168.1.1-254`, `10.0.0.0/24`).
    pub targets: String,
}
impl Default for Schedule {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_minutes: 60,
            targets: String::new(),
        }
    }
}

/// What the scheduler should do on this tick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// The scheduler is off.
    Off,
    /// Enabled, but the settings cannot run (the reason is for the user).
    Invalid(String),
    /// Not due yet; time left.
    Wait(Duration),
    /// Due, but a scan, capture or inventory load is in progress: try again on the next tick
    /// without losing the slot.
    Postponed,
    /// Due and free: start a scan now.
    Start,
}

impl Schedule {
    pub fn interval(&self) -> Duration {
        Duration::from_secs(u64::from(self.interval_minutes) * 60)
    }

    /// The cheap checks (no address parsing): usable on every frame.
    pub fn check(&self) -> Result<(), String> {
        if !(MIN_INTERVAL_MINUTES..=MAX_INTERVAL_MINUTES).contains(&self.interval_minutes) {
            return Err(format!(
                "The interval must be {MIN_INTERVAL_MINUTES} to {MAX_INTERVAL_MINUTES} minutes"
            ));
        }
        if self.targets.trim().is_empty() {
            return Err("Enter the targets to scan".into());
        }
        Ok(())
    }

    /// Everything [`check`](Self::check) does, plus the target syntax.
    pub fn validate(&self, skip_edges: bool) -> Result<(), String> {
        self.check()?;
        crate::scan::parse_hosts(&self.targets, skip_edges).map(|_| ())
    }

    /// The decision for one tick: `elapsed` is the time since the schedule was enabled or the
    /// last scheduled scan was started, `busy` that something else uses the scanner.
    pub fn decide(&self, elapsed: Duration, busy: bool) -> Action {
        if !self.enabled {
            return Action::Off;
        }
        if let Err(reason) = self.check() {
            return Action::Invalid(reason);
        }
        let interval = self.interval();
        if elapsed < interval {
            Action::Wait(interval - elapsed)
        } else if busy {
            Action::Postponed
        } else {
            Action::Start
        }
    }
}

/// "in 5 min", "in 1 h 20 min", "in under a minute".
pub fn describe_wait(left: Duration) -> String {
    let minutes = left.as_secs().div_ceil(60);
    match minutes {
        0 | 1 => "in under a minute".into(),
        m if m < 60 => format!("in {m} min"),
        m if m % 60 == 0 => format!("in {} h", m / 60),
        m => format!("in {} h {} min", m / 60, m % 60),
    }
}

/// The command that keeps `monitor` running when the program is closed, for the settings page.
pub fn service_hint(schedule: &Schedule) -> String {
    let targets = if schedule.targets.trim().is_empty() {
        "TARGETS"
    } else {
        schedule.targets.trim()
    };
    let seconds = u64::from(schedule.interval_minutes.max(MIN_INTERVAL_MINUTES)) * 60;
    if cfg!(windows) {
        format!("network-scope-cli service install {targets} --interval {seconds}")
    } else {
        format!(
            "network-scope-cli monitor {targets} --interval {seconds}   (systemd units: packaging/systemd)"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule(minutes: u32, targets: &str) -> Schedule {
        Schedule {
            enabled: true,
            interval_minutes: minutes,
            targets: targets.into(),
        }
    }
    const MIN: Duration = Duration::from_secs(60);

    #[test]
    fn off_by_default_and_nothing_starts_while_off() {
        let s = Schedule::default();
        assert!(!s.enabled && s.targets.is_empty());
        assert_eq!(
            s.decide(Duration::from_secs(10_000_000), false),
            Action::Off
        );
        // A saved preferences file without the section loads as off.
        let loaded: Schedule = serde_json::from_str("{}").unwrap();
        assert_eq!(loaded, s);
    }

    #[test]
    fn a_scan_starts_when_the_interval_has_passed_and_the_scanner_is_free() {
        let s = schedule(15, "192.168.1.1-254");
        assert_eq!(s.decide(Duration::ZERO, false), Action::Wait(15 * MIN));
        assert_eq!(s.decide(14 * MIN, false), Action::Wait(MIN));
        assert_eq!(s.decide(15 * MIN, false), Action::Start);
        assert_eq!(s.decide(400 * MIN, false), Action::Start);
        // Busy: the slot is kept and retried, never run on top of another scan.
        assert_eq!(s.decide(15 * MIN, true), Action::Postponed);
        assert_eq!(s.decide(5 * MIN, true), Action::Wait(10 * MIN));
    }

    #[test]
    fn unusable_settings_are_reported_not_run() {
        for (minutes, targets, text) in [
            (4, "10.0.0.1", "interval"),
            (0, "10.0.0.1", "interval"),
            (MAX_INTERVAL_MINUTES + 1, "10.0.0.1", "interval"),
            (60, "", "targets"),
            (60, "   ", "targets"),
        ] {
            match schedule(minutes, targets).decide(1000 * MIN, false) {
                Action::Invalid(reason) => assert!(reason.contains(text), "{reason}"),
                other => panic!("{minutes} {targets:?}: {other:?}"),
            }
        }
        assert_eq!(
            schedule(5, "10.0.0.1").decide(5 * MIN, false),
            Action::Start
        );
        assert_eq!(
            schedule(MAX_INTERVAL_MINUTES, "10.0.0.1").decide(Duration::ZERO, false),
            Action::Wait(Duration::from_secs(u64::from(MAX_INTERVAL_MINUTES) * 60))
        );
        // The full validation also parses the targets.
        assert!(schedule(60, "10.0.0.1-5").validate(false).is_ok());
        assert!(schedule(60, "not a target").validate(false).is_err());
        assert!(schedule(1, "10.0.0.1").validate(false).is_err());
    }

    #[test]
    fn waiting_times_read_naturally() {
        assert_eq!(describe_wait(Duration::from_secs(5)), "in under a minute");
        assert_eq!(describe_wait(Duration::from_secs(61)), "in 2 min");
        assert_eq!(describe_wait(Duration::from_secs(59 * 60)), "in 59 min");
        assert_eq!(describe_wait(Duration::from_secs(120 * 60)), "in 2 h");
        assert_eq!(describe_wait(Duration::from_secs(80 * 60)), "in 1 h 20 min");
    }

    #[test]
    fn the_service_hint_names_the_targets_and_a_valid_interval() {
        let hint = service_hint(&schedule(15, "10.0.0.0/24"));
        assert!(
            hint.contains("10.0.0.0/24") && hint.contains("--interval 900"),
            "{hint}"
        );
        assert!(service_hint(&Schedule::default()).contains("TARGETS"));
        assert!(service_hint(&schedule(1, "x")).contains("--interval 300"));
    }
}
