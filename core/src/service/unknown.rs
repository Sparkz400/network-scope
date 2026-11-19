//! The banners of services that nothing identified, taken from stored scans, for people who want
//! to contribute a probe rule (roadmap K65, `fingerprints export-unknown`).
//!
//! Nothing is sent anywhere. The result is a plain JSON value the user reads, redacts and attaches
//! to an issue or pull request themselves. It carries no IP address, MAC address, host name or
//! scan time of a host: only the port, the banner text and how many hosts showed the same
//! banner. The host's own address, MAC and name are removed from the banner text as well, but a
//! banner can contain anything the device chose to say (a user name, a serial number, a site
//! name), so the file must still be read before it is shared.
use crate::store::Snapshot;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// Most entries in one export, so a large inventory gives a file a person can read.
pub const MAX_ENTRIES: usize = 500;
/// The `format` field of the export.
pub const FORMAT: &str = "network-scope-unknown-banners";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UnknownBanner {
    pub proto: &'static str,
    pub port: u16,
    /// What the port number alone suggests (`ftp` for 21), when it suggests something.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_hint: Option<String>,
    /// The banner as the store keeps it: control characters removed, at most 120 characters.
    pub banner: String,
    /// On how many different hosts this exact banner was seen on this port.
    pub hosts: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UnknownExport {
    pub format: &'static str,
    pub version: u32,
    pub generated_by: String,
    pub review: &'static str,
    pub entries: Vec<UnknownBanner>,
    /// True when more banners existed than [`MAX_ENTRIES`].
    pub truncated: bool,
}

/// Replaces what identifies the host itself (its address, MAC address and host name) in `text`.
fn redact(text: &str, host: &crate::scan::Host) -> String {
    let mut out = text.replace(&host.ip.to_string(), "<ip>");
    if host.hostname.len() >= 3 {
        out = replace_ignore_case(&out, &host.hostname, "<host>");
    }
    if host.mac.len() >= 12 {
        out = replace_ignore_case(&out, &host.mac, "<mac>");
    }
    out
}
fn replace_ignore_case(text: &str, needle: &str, with: &str) -> String {
    let (lower, needle) = (text.to_ascii_lowercase(), needle.to_ascii_lowercase());
    let mut out = String::new();
    let mut at = 0;
    // ASCII lower-casing keeps byte offsets, so the match positions index the original text.
    while let Some(found) = lower[at..].find(&needle) {
        out.push_str(&text[at..at + found]);
        out.push_str(with);
        at += found + needle.len();
    }
    out.push_str(&text[at..]);
    out
}

/// The unidentified TCP banners of `snapshots`, one entry per distinct (port, banner), most
/// widespread first.
pub fn unknown_banners<'a>(snapshots: impl IntoIterator<Item = &'a Snapshot>) -> UnknownExport {
    let mut seen = BTreeSet::new();
    let mut counts: BTreeMap<(u16, String), usize> = BTreeMap::new();
    for snapshot in snapshots {
        for host in &snapshot.hosts {
            for (key, banner) in &host.identity {
                let Some(port) = key
                    .strip_prefix("banner.")
                    .and_then(|p| p.parse::<u16>().ok())
                else {
                    continue;
                };
                // A banner is stored only when no rule matched, but an identified port (a later
                // scan with more probes) is not unknown any more.
                let identified = host
                    .identity
                    .get(&format!("svc.{port}"))
                    .is_some_and(|s| !s.starts_with("unidentified"));
                let banner = redact(banner.trim(), host);
                if identified || banner.is_empty() {
                    continue;
                }
                // The same host in several scans counts once.
                if seen.insert((host.ip, port, banner.clone())) {
                    *counts.entry((port, banner)).or_default() += 1;
                }
            }
        }
    }
    let mut entries: Vec<UnknownBanner> = counts
        .into_iter()
        .map(|((port, banner), hosts)| UnknownBanner {
            proto: "tcp",
            port,
            port_hint: super::port_hint(port).map(str::to_string),
            banner,
            hosts,
        })
        .collect();
    entries.sort_by(|a, b| b.hosts.cmp(&a.hosts).then(a.port.cmp(&b.port)));
    let truncated = entries.len() > MAX_ENTRIES;
    entries.truncate(MAX_ENTRIES);
    UnknownExport {
        format: FORMAT,
        version: 1,
        generated_by: format!("network-scope {}", env!("CARGO_PKG_VERSION")),
        review: "Read every entry and remove or redact anything that identifies a person, \
                 host or organisation (names, serial numbers, addresses, site names) before \
                 you share this file. Network Scope never uploads it.",
        entries,
        truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::Host;

    fn host(ip: &str, identity: &[(&str, &str)]) -> Host {
        Host {
            ip: ip.parse().unwrap(),
            responding: true,
            ping: None,
            ttl: None,
            hostname: "plant-gw.example.org".into(),
            mac: "00:11:22:33:44:55".into(),
            open: vec![],
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity: identity
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            udp_open: vec![],
            trace: vec![],
        }
    }
    fn snapshot(hosts: Vec<Host>) -> Snapshot {
        Snapshot {
            targets: "10.0.0.0/24".into(),
            complete: true,
            settings: Default::default(),
            hosts,
            observations: vec![],
            notes: Default::default(),
        }
    }

    #[test]
    fn unidentified_banners_are_grouped_and_carry_no_host_data() {
        let a = host(
            "10.0.0.5",
            &[
                ("banner.9999", "ACME-GW 2.1 ready"),
                ("svc.9999", "unidentified"),
                ("banner.21", "FTPX 1.0"),
                ("svc.21", "unidentified (port suggests ftp)"),
                ("svc.80", "http"),
                ("banner.80", "left over"),
                ("tls.443.versions", "TLS1.3"),
            ],
        );
        // Same banner on a second host, the first host again in a second scan, and a banner
        // that names the host.
        let b = host("10.0.0.6", &[("banner.9999", "ACME-GW 2.1 ready")]);
        let c = host(
            "10.0.0.7",
            &[(
                "banner.7000",
                "hello 10.0.0.7 from PLANT-GW.example.org (00:11:22:33:44:55) v3.2.1.0",
            )],
        );
        let export = unknown_banners(&[snapshot(vec![a.clone(), b, c]), snapshot(vec![a])]);
        let got: Vec<(u16, &str, usize)> = export
            .entries
            .iter()
            .map(|e| (e.port, e.banner.as_str(), e.hosts))
            .collect();
        assert_eq!(
            got,
            [
                (9999, "ACME-GW 2.1 ready", 2),
                (21, "FTPX 1.0", 1),
                // The firmware version stays; the host's own address, name and MAC do not.
                (7000, "hello <ip> from <host> (<mac>) v3.2.1.0", 1),
            ]
        );
        assert_eq!(export.entries[1].port_hint.as_deref(), Some("ftp"));
        assert_eq!(export.entries[0].port_hint, None);
        let text = serde_json::to_string(&export).unwrap();
        for private in ["10.0.0.5", "10.0.0.6", "10.0.0.7", "plant-gw", "00:11:22"] {
            assert!(!text.contains(private), "{private} in {text}");
        }
        assert!(text.contains(FORMAT) && !export.truncated);
    }

    #[test]
    fn the_export_is_capped_and_an_empty_store_gives_an_empty_list() {
        assert!(unknown_banners([]).entries.is_empty());
        let hosts: Vec<Host> = (0..MAX_ENTRIES + 5)
            .map(|i| host("10.0.1.1", &[(&format!("banner.{}", 1000 + i), "x")]))
            .collect();
        let export = unknown_banners(&[snapshot(hosts)]);
        assert_eq!(export.entries.len(), MAX_ENTRIES);
        assert!(export.truncated);
    }

    #[test]
    fn case_insensitive_replacement_keeps_the_rest() {
        assert_eq!(replace_ignore_case("Abc ABC abc", "abc", "X"), "X X X");
        assert_eq!(replace_ignore_case("none", "abc", "X"), "none");
        assert_eq!(replace_ignore_case("é abc", "abc", "X"), "é X");
    }
}
