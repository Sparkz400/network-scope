//! Several network interfaces in one scan (ROADMAP B16).
//!
//! The raw features (the SYN scan, the ARP sweep, TCP traceroute) send through one capture
//! interface and need its source IPv4 address and MAC. `--interface eth0,eth1` with
//! `--source-ip A,B` and `--source-mac M1,M2` (paired by position) gives a scan one engine per
//! interface; every target then goes out through the interface the operating system's routing
//! table picks for it ([`choose`]): an interface on whose subnet the target lies first, else the
//! first interface that routes to it, else none (the TCP connect scan, which the OS routes itself,
//! takes over). With one interface, or none, nothing changes.
//!
//! The pairing and the choice are pure functions, tested here; opening the capture drivers needs
//! Npcap or libpcap and administrator rights, and that part has not been run against two real
//! interfaces.
use crate::scan::Settings;

/// One interface with its source address, as given on the command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spec {
    pub interface: String,
    pub source_ip: String,
    pub source_mac: String,
}

fn list(text: &str) -> Vec<&str> {
    text.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}

/// The interfaces of a scan: one [`Spec`] per comma-separated `interface`, with `source_ip` and
/// `source_mac` paired by position. A single (or no) interface keeps the three values as they
/// are, so a scan that names one is unchanged. More than one needs a source IPv4 and a MAC for
/// each, because the SYN and ARP engines are opened per interface.
pub fn specs(s: &Settings) -> Result<Vec<Spec>, String> {
    let names = list(&s.interface);
    if names.len() <= 1 {
        return Ok(vec![Spec {
            interface: s.interface.trim().to_string(),
            source_ip: s.source_ip.clone(),
            source_mac: s.source_mac.clone(),
        }]);
    }
    let (ips, macs) = (list(&s.source_ip), list(&s.source_mac));
    if ips.len() != names.len() || macs.len() != names.len() {
        return Err(format!(
            "{} interfaces need {} source IPv4 addresses (--source-ip) and {} source MACs (--source-mac), paired by position",
            names.len(),
            names.len(),
            names.len()
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    if let Some(dup) = names.iter().find(|n| !seen.insert(**n)) {
        return Err(format!("Interface {dup} is listed twice"));
    }
    Ok(names
        .iter()
        .zip(ips.iter().zip(&macs))
        .map(|(n, (ip, mac))| Spec {
            interface: (*n).to_string(),
            source_ip: (*ip).to_string(),
            source_mac: (*mac).to_string(),
        })
        .collect())
}

/// The settings an engine of one interface is opened with.
pub fn settings_for(s: &Settings, spec: &Spec) -> Settings {
    Settings {
        interface: spec.interface.clone(),
        source_ip: spec.source_ip.clone(),
        source_mac: spec.source_mac.clone(),
        ..s.clone()
    }
}

/// Which candidate sends to a target, from what the routing table said about each: `Some(true)`
/// the target is on its subnet, `Some(false)` it is routed through it, `None` it cannot reach the
/// target (the route leaves through another interface, or there is none).
pub fn choose(routes: &[Option<bool>]) -> Option<usize> {
    routes
        .iter()
        .position(|r| *r == Some(true))
        .or_else(|| routes.iter().position(Option::is_some))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(interface: &str, ip: &str, mac: &str) -> Settings {
        Settings {
            interface: interface.into(),
            source_ip: ip.into(),
            source_mac: mac.into(),
            ..Settings::default()
        }
    }

    #[test]
    fn one_or_no_interface_is_left_exactly_as_given() {
        let s = settings("eth0", "10.0.0.5", "02:00:00:00:00:01");
        assert_eq!(
            specs(&s).unwrap(),
            [Spec {
                interface: "eth0".into(),
                source_ip: "10.0.0.5".into(),
                source_mac: "02:00:00:00:00:01".into()
            }]
        );
        let none = specs(&Settings::default()).unwrap();
        assert_eq!(none.len(), 1);
        assert!(none[0].interface.is_empty());
    }

    #[test]
    fn several_interfaces_pair_with_their_source_addresses_by_position() {
        let s = settings(
            "eth0, eth1",
            "10.0.0.5,192.168.1.5",
            "02:00:00:00:00:01,02:00:00:00:00:02",
        );
        let list = specs(&s).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[1].interface, "eth1");
        assert_eq!(list[1].source_ip, "192.168.1.5");
        assert_eq!(list[1].source_mac, "02:00:00:00:00:02");
        let one = settings_for(&s, &list[1]);
        assert_eq!(
            (one.interface.as_str(), one.source_ip.as_str()),
            ("eth1", "192.168.1.5")
        );
        assert_eq!(one.ports, s.ports, "everything else is kept");
    }

    #[test]
    fn a_missing_or_surplus_source_address_or_a_repeated_interface_is_refused() {
        for s in [
            settings(
                "eth0,eth1",
                "10.0.0.5",
                "02:00:00:00:00:01,02:00:00:00:00:02",
            ),
            settings("eth0,eth1", "10.0.0.5,10.0.1.5", ""),
            settings("eth0,eth1", "10.0.0.5,10.0.1.5,10.0.2.5", "a,b"),
            settings("eth0,eth0", "10.0.0.5,10.0.1.5", "a,b"),
        ] {
            assert!(specs(&s).is_err(), "{s:?}");
        }
    }

    #[test]
    fn a_target_goes_out_through_the_interface_that_routes_it() {
        // On-link beats routed, whatever the order.
        assert_eq!(choose(&[Some(false), Some(true)]), Some(1));
        assert_eq!(choose(&[Some(true), Some(true)]), Some(0));
        // Routed through the only interface that can.
        assert_eq!(choose(&[None, Some(false)]), Some(1));
        // Nobody routes it: the connect scan takes over.
        assert_eq!(choose(&[None, None]), None);
        assert_eq!(choose(&[]), None);
    }
}
