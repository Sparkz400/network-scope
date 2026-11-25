// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Scan presets: named bundles of [`Settings`] that the CLI (`--preset quick|office|plant|full`)
//! and the desktop app (the preset picker) share, so both mean exactly the same thing.
//!
//! | Preset | Traffic | What it turns on |
//! |---|---|---|
//! | `quick` | active, Safe Mode | ping + TCP connect to 80, 443, 8080; nothing else |
//! | `office` | active, Safe Mode | the common office and server ports, service identification, OS / vendor / device-type guess, MAC lookup |
//! | `plant` | **passive only** | no active packet at all; listen with `ot-listen` (live) or read a pcap |
//! | `full` | active, Safe Mode **off** | everything the engine can do, still behind the scope guard and the back-off |
//!
//! `quick` and `office` stay in Safe Mode (at most 8 hosts at a time, at least 100 ms between
//! probes, no SYN, no ARP sweep, ICMP traceroute only). `full` is the only preset that leaves
//! Safe Mode, so it must be chosen on purpose; it keeps the automatic back-off
//! (`Settings::backoff`) on, and a scan started with it still passes the scope guard
//! ([`crate::scope::enforce`]) like every other scan. OT and printer ports are never probed by the
//! generic probes whatever the preset. A preset only sets the scan options; machine settings
//! (capture interface, source addresses, script and probe files) are kept from the base settings.
use crate::scan::Settings;

/// A named scan profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preset {
    Quick,
    Office,
    Plant,
    Full,
}

/// Why a preset cannot be turned into settings for an active scan.
pub const PASSIVE_ONLY: &str = "The plant preset is passive: it sends no packets, so there is nothing to scan. Listen with ot-listen --interface NAME (live) or ot-listen --pcap FILE (a capture file)";

impl Preset {
    /// Every preset, in the order the pickers show them.
    pub const ALL: [Self; 4] = [Self::Quick, Self::Office, Self::Plant, Self::Full];

    /// The name used on the command line (`--preset NAME`).
    pub const fn name(self) -> &'static str {
        match self {
            Self::Quick => "quick",
            Self::Office => "office",
            Self::Plant => "plant",
            Self::Full => "full",
        }
    }
    /// The label in the desktop picker.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Quick => "Quick",
            Self::Office => "Office",
            Self::Plant => "Plant (passive)",
            Self::Full => "Full audit",
        }
    }
    /// `quick`, `office`, `plant` or `full` (any case).
    pub fn parse(text: &str) -> Result<Self, String> {
        Self::ALL
            .into_iter()
            .find(|p| p.name().eq_ignore_ascii_case(text.trim()))
            .ok_or_else(|| format!("Unknown preset {text}: choose quick, office, plant or full"))
    }
    /// The preset sends packets (every preset except `plant`).
    pub const fn active(self) -> bool {
        !matches!(self, Self::Plant)
    }
    /// Starts in Safe Mode (every preset except `full`; `plant` sends nothing at all).
    pub const fn safe_mode(self) -> bool {
        !matches!(self, Self::Full)
    }

    /// What the preset turns on, one line per point, for the picker's tooltip and the
    /// documentation. The text is checked against [`Preset::settings`] by a test.
    pub fn describe(self) -> Vec<&'static str> {
        match self {
            Self::Quick => vec![
                "Safe Mode on (at most 8 hosts at a time, 100 ms between probes)",
                "Ping and TCP connect to ports 80, 443 and 8080",
                "No service, UDP, OS or OT probes, no traceroute",
            ],
            Self::Office => vec![
                "Safe Mode on (at most 8 hosts at a time, 100 ms between probes)",
                "Ping and TCP connect to the common office and server ports",
                "Identifies services on open ports (banners, HTTP, TLS, SMB, RDP)",
                "Guesses OS, manufacturer and device type; looks up MAC addresses",
                "No UDP, OT or traceroute probes",
            ],
            Self::Plant => vec![
                "Passive only: no packet is sent",
                "Listens with ot-listen (live capture) or reads a pcap file",
                "Nothing is scanned, so no device is touched",
            ],
            Self::Full => vec![
                "Safe Mode off: up to 256 hosts at a time",
                "Ping, TCP connect (SYN engine with adaptive timing when an interface is set), ARP sweep",
                "Services, UDP services, OS guess, read-only OT identification, JARM, ICMP traceroute, DNS names, MACs",
                "The scope guard still asks before public or out-of-scope targets, and the back-off still slows devices that reset connections",
            ],
        }
    }

    /// The settings of an active preset on top of `base` (which keeps the capture interface,
    /// source addresses, script and probe files). `Err` for `plant`, which sends nothing.
    pub fn settings(self, base: &Settings) -> Result<Settings, String> {
        let keep = Settings {
            interface: base.interface.clone(),
            source_ip: base.source_ip.clone(),
            source_mac: base.source_mac.clone(),
            scripts: base.scripts.clone(),
            probe_file: base.probe_file.clone(),
            ..Settings::default()
        };
        Ok(match self {
            Self::Quick => Settings {
                safe: true,
                ..keep
            },
            Self::Office => Settings {
                safe: true,
                ports: "21,22,23,25,53,80,110,135,139,143,389,443,445,631,993,1433,3306,3389,5900,8080,8443".into(),
                services: true,
                os_detect: true,
                mac: true,
                ..keep
            },
            Self::Plant => return Err(PASSIVE_ONLY.into()),
            Self::Full => Settings {
                safe: false,
                ports: "1-1024,top:100".into(),
                workers: 256,
                probes: 2,
                services: true,
                udp: true,
                os_detect: true,
                ot: true,
                trace: true,
                jarm: true,
                dns: true,
                mac: true,
                arp: true,
                arp_sweep: true,
                syn: true,
                syn_adaptive: true,
                tcp_adaptive: true,
                scan_nonresponders: true,
                backoff: true,
                ..keep
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{plan, scan};

    #[test]
    fn names_parse_in_any_case_and_unknown_names_are_refused() {
        for p in Preset::ALL {
            assert_eq!(Preset::parse(p.name()).unwrap(), p);
            assert_eq!(Preset::parse(&p.name().to_uppercase()).unwrap(), p);
        }
        assert_eq!(Preset::parse(" Full ").unwrap(), Preset::Full);
        let e = Preset::parse("turbo").unwrap_err();
        assert!(e.contains("quick, office, plant or full"), "{e}");
    }

    #[test]
    fn quick_is_the_safe_default_scan() {
        let s = Preset::Quick.settings(&Settings::default()).unwrap();
        assert_eq!(
            serde_json::to_value(&s).unwrap(),
            serde_json::to_value(Settings::default()).unwrap(),
            "quick is what a plain scan does"
        );
        assert!(s.safe && !s.services && !s.udp && !s.ot && !s.trace && !s.syn && !s.arp_sweep);
    }

    #[test]
    fn office_adds_identification_but_stays_in_safe_mode() {
        let s = Preset::Office.settings(&Settings::default()).unwrap();
        assert!(s.safe && s.services && s.os_detect && s.mac);
        assert!(!s.udp && !s.ot && !s.trace && !s.syn && !s.arp_sweep && !s.jarm);
        let ports = scan::parse_ports(&s.ports).unwrap();
        assert!(ports.contains(&443) && ports.contains(&445) && ports.contains(&3389));
        // No printer or OT port is selected by the generic scan (CONTRIBUTING, rule 4).
        for p in [515, 9100, 102, 502, 44818, 47808] {
            assert!(!ports.contains(&p), "{p}");
        }
    }

    #[test]
    fn plant_sends_nothing_and_has_no_scan_settings() {
        let e = Preset::Plant.settings(&Settings::default()).unwrap_err();
        assert!(e.contains("ot-listen"), "{e}");
        assert!(!Preset::Plant.active());
        assert!(Preset::Plant.safe_mode());
        assert!(Preset::Quick.active() && Preset::Office.active() && Preset::Full.active());
    }

    #[test]
    fn full_leaves_safe_mode_and_turns_everything_on_but_keeps_the_back_off() {
        let s = Preset::Full.settings(&Settings::default()).unwrap();
        assert!(!s.safe && s.backoff);
        assert!(s.services && s.udp && s.os_detect && s.ot && s.trace && s.jarm);
        assert!(s.syn && s.syn_adaptive && s.arp_sweep && s.tcp_adaptive);
        assert!(s.workers <= 4096 && s.max_rate == 0);
        assert!(scan::parse_ports(&s.ports).is_ok());
        assert!(!Preset::Full.safe_mode());
        // Everything it enables is something a plan can list (so --dry-run shows it).
        let plan = plan::host(
            "10.0.0.5".parse().unwrap(),
            &[80, 443],
            &[],
            &s,
            crate::service::ProbeDb::load("").ok().as_ref(),
        );
        assert!(plan.packets.len() > 4, "{:?}", plan.lines());
    }

    #[test]
    fn machine_settings_survive_every_active_preset() {
        let base = Settings {
            interface: "eth0".into(),
            source_ip: "10.0.0.9".into(),
            source_mac: "AA:BB:CC:DD:EE:FF".into(),
            scripts: "policy.rhai".into(),
            probe_file: "probes.json".into(),
            workers: 7,
            safe: false,
            ..Settings::default()
        };
        for p in [Preset::Quick, Preset::Office, Preset::Full] {
            let s = p.settings(&base).unwrap();
            assert_eq!(
                (
                    &s.interface,
                    &s.source_ip,
                    &s.source_mac,
                    &s.scripts,
                    &s.probe_file
                ),
                (
                    &base.interface,
                    &base.source_ip,
                    &base.source_mac,
                    &base.scripts,
                    &base.probe_file
                ),
                "{p:?}"
            );
            assert_ne!(s.workers, 7, "{p:?} sets its own concurrency");
            assert_eq!(s.safe, p.safe_mode(), "{p:?}");
        }
    }

    #[test]
    fn the_descriptions_state_the_safe_mode_of_each_preset() {
        for p in Preset::ALL {
            let text = p.describe().join(" ").to_lowercase();
            assert!(!p.describe().is_empty());
            if p == Preset::Full {
                assert!(text.contains("safe mode off"), "{text}");
            } else if p == Preset::Plant {
                assert!(text.contains("no packet is sent"), "{text}");
            } else {
                assert!(text.contains("safe mode on"), "{text}");
            }
        }
    }
}
