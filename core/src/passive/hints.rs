// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Device-type hints derived from passive observations.
//!
//! Every decoder in `passive` can attach hints to the observation it produces. A hint is stored
//! as an ordinary observation field from a closed set of keys (so merging observations for the
//! same device accumulates them without unbounded growth):
//!
//! - `hint.<category>`: strong evidence (a service type or device type that names the kind of device),
//! - `hint_weak.<category>`: weak evidence (a generic service or an OS-level fingerprint that
//!   many kinds of device share).
//!
//! The value is the human-readable reason. `devices::merge` turns these fields into scored
//! device-type evidence next to the evidence of active scans.
//!
//! All tables below are **heuristics written for this project** from public protocol
//! documentation and common knowledge of how devices announce themselves. They are not copied
//! from a fingerprint database, they have been checked against hand-built frames (and the NetBIOS
//! browser decoder against one real capture), and a match is a hint, not proof. A device can announce services it does not
//! really offer.
use std::collections::BTreeMap;

/// Categories a hint can name. `devices.rs` maps them to its device types.
pub const CATEGORIES: [&str; 11] = [
    "printer", "camera", "network", "windows", "linux", "apple", "media", "iot", "voip", "nas",
    "mobile",
];

pub(super) struct Hint {
    pub category: &'static str,
    pub strong: bool,
    pub why: String,
    /// Operating system name for DHCP fingerprints (shown as `os_hint`).
    pub os: Option<&'static str>,
}

impl Hint {
    pub(super) fn new(category: &'static str, strong: bool, why: impl Into<String>) -> Self {
        debug_assert!(CATEGORIES.contains(&category));
        Hint {
            category,
            strong,
            why: why.into(),
            os: None,
        }
    }
}

/// Stores hints as observation fields. A strong hint replaces a weak one of the same category;
/// the first reason for a category is kept.
pub(super) fn attach(fields: &mut BTreeMap<String, String>, hints: impl IntoIterator<Item = Hint>) {
    for h in hints {
        let strong_key = format!("hint.{}", h.category);
        let weak_key = format!("hint_weak.{}", h.category);
        let why: String = h.why.chars().take(120).collect();
        if h.strong {
            fields.remove(&weak_key);
            fields.entry(strong_key).or_insert(why);
        } else if !fields.contains_key(&strong_key) {
            fields.entry(weak_key).or_insert(why);
        }
    }
}

/// The hints stored in an observation's fields: (category, strong, reason). Unknown categories
/// are ignored, so stored data from other versions cannot inject anything.
pub fn stored(fields: &BTreeMap<String, String>) -> Vec<(&'static str, bool, String)> {
    let mut out = vec![];
    for category in CATEGORIES {
        if let Some(why) = fields.get(&format!("hint.{category}")) {
            out.push((category, true, why.clone()));
        } else if let Some(why) = fields.get(&format!("hint_weak.{category}")) {
            out.push((category, false, why.clone()));
        }
    }
    out
}

/// (needle in lower-case text, category, strong). The first column is the evidence shown.
pub(super) type Table = [(&'static str, &'static str, bool)];

/// Hints for every needle of `table` that occurs in `text` (compared case-insensitively).
pub(super) fn matching(text: &str, table: &Table, source: &str) -> Vec<Hint> {
    let lower = text.to_ascii_lowercase();
    table
        .iter()
        .filter(|(needle, _, _)| lower.contains(needle))
        .map(|(needle, category, strong)| {
            Hint::new(
                category,
                *strong,
                format!("{source} {}", needle.trim_matches('|')),
            )
        })
        .collect()
}

/// mDNS service types (`_type._proto`). `_ipp._tcp` does not match `_ipps._tcp`.
pub(super) const MDNS_SERVICES: &Table = &[
    ("_ipp._tcp", "printer", true),
    ("_ipps._tcp", "printer", true),
    ("_ipp-tls._tcp", "printer", true),
    ("_printer._tcp", "printer", true),
    ("_pdl-datastream._tcp", "printer", true),
    ("_scanner._tcp", "printer", false),
    ("_uscan._tcp", "printer", false),
    ("_uscans._tcp", "printer", false),
    ("_airplay._tcp", "media", true),
    ("_raop._tcp", "media", true),
    ("_googlecast._tcp", "media", true),
    ("_sonos._tcp", "media", true),
    ("_mediaremotetv._tcp", "media", true),
    ("_spotify-connect._tcp", "media", false),
    ("_hap._tcp", "iot", true),
    ("_hap._udp", "iot", true),
    ("_matter._tcp", "iot", true),
    ("_matterc._udp", "iot", true),
    ("_hue._tcp", "iot", true),
    ("_esphomelib._tcp", "iot", true),
    ("_mqtt._tcp", "iot", false),
    ("_companion-link._tcp", "apple", true),
    ("_apple-mobdev2._tcp", "apple", true),
    ("_sleep-proxy._udp", "apple", true),
    ("_airport._tcp", "network", true),
    ("_axis-video._tcp", "camera", true),
    ("_rtsp._tcp", "camera", false),
    ("_workstation._tcp", "linux", false),
    ("_adisk._tcp", "nas", false),
    ("_smb._tcp", "nas", false),
    ("_afpovertcp._tcp", "nas", false),
];

/// Hints for the `model=` value of an mDNS `_device-info._tcp` TXT record (Apple model
/// identifiers such as `MacBookPro18,3`, `Mac14,2`, `AppleTV11,1`).
pub(super) fn apple_model(model: &str) -> Vec<Hint> {
    let m = model.to_ascii_lowercase();
    let why = format!("mDNS model {}", model.chars().take(40).collect::<String>());
    let mac_family = m.starts_with("macbook")
        || m.starts_with("imac")
        || m.starts_with("macmini")
        || m.starts_with("macpro")
        || m.starts_with("xserve")
        || m.strip_prefix("mac")
            .is_some_and(|r| r.starts_with(|c: char| c.is_ascii_digit()));
    let mut hints = vec![];
    if mac_family || m.starts_with("iphone") || m.starts_with("ipad") {
        hints.push(Hint::new("apple", true, why.clone()));
    }
    if m.starts_with("appletv") || m.starts_with("audioaccessory") {
        hints.push(Hint::new("apple", true, why.clone()));
        hints.push(Hint::new("media", true, why));
    }
    hints
}

/// SSDP/UPnP SERVER, ST, NT and USN text. UPnP device types are `urn:...:device:<Type>:<n>`.
pub(super) const SSDP: &Table = &[
    ("internetgatewaydevice", "network", true),
    ("wanconnectiondevice", "network", true),
    ("wandevice", "network", true),
    ("wfadevice", "network", true),
    ("miniupnpd", "network", true),
    ("mediarenderer", "media", true),
    ("dial-multiscreen-org", "media", true),
    ("roku:ecp", "media", true),
    ("zoneplayer", "media", true),
    ("sonos", "media", true),
    ("mediaserver", "media", false),
    ("printbasic", "printer", true),
    ("device:printer", "printer", true),
    ("digitalsecuritycamera", "camera", true),
    ("networkvideotransmitter", "camera", true),
    ("ipbridge", "iot", true),
    ("urn:belkin:device", "iot", true),
    ("microsoft-windows", "windows", true),
    ("windows nt", "windows", false),
    ("synology", "nas", true),
    ("qnap", "nas", true),
    ("readynas", "nas", true),
    ("linux/", "linux", false),
];

/// WS-Discovery `Types`: the local part of each QName in lower case, wrapped in `|` so that a
/// whole name must match.
pub(super) const WSD_TYPES: &Table = &[
    ("|printdevicetype|", "printer", true),
    ("|printbasictype|", "printer", true),
    ("|scandevicetype|", "printer", true),
    ("|networkvideotransmitter|", "camera", true),
    // Published by Windows and also by Samba's wsdd on Linux and NAS devices.
    ("|computer|", "windows", false),
];

/// CDP platform strings.
pub(super) const CDP_PLATFORM: &Table = &[("ip phone", "voip", true)];

/// DHCP vendor class (option 60).
const DHCP_VENDOR_CLASS: &Table = &[
    ("msft 5.0", "windows", true),
    ("android-dhcp", "mobile", true),
    ("dhcpcd", "linux", true),
    ("udhcp", "iot", false),
    ("hewlett-packard jetdirect", "printer", true),
    ("ip phone", "voip", true),
    ("polycom", "voip", true),
    ("yealink", "voip", true),
    ("grandstream", "voip", true),
    ("snom", "voip", true),
    ("avaya", "voip", true),
    ("aastra", "voip", true),
    ("cisco ap", "network", true),
    ("ubnt", "network", true),
];

/// DHCP parameter request lists (option 55), exact match, with the OS they usually mean.
/// Written from commonly published client behaviour; not verified against real captures here.
const DHCP_PARAMETER_LISTS: &[(&[u8], &str, &str)] = &[
    (
        &[1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252],
        "Windows 10/11",
        "windows",
    ),
    (
        &[1, 15, 3, 6, 44, 46, 47, 31, 33, 121, 249, 43],
        "Windows Vista/7",
        "windows",
    ),
    (&[1, 121, 3, 6, 15, 119, 252, 95, 44, 46], "macOS", "apple"),
    (&[1, 121, 3, 6, 15, 119, 252], "iOS/iPadOS", "apple"),
    (&[1, 3, 6, 15, 26, 28, 51, 58, 59, 43], "Android", "mobile"),
    (
        &[1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42],
        "Linux (ISC dhclient)",
        "linux",
    ),
];

/// Default host names set by an OS or a printer vendor: (lower-case prefix, characters that
/// must follow, accepted characters, OS name, category). `0` follows means "any rest".
type NamePattern = (
    &'static str,
    usize,
    fn(char) -> bool,
    Option<&'static str>,
    &'static str,
);
const DHCP_HOSTNAMES: &[NamePattern] = &[
    (
        "desktop-",
        7,
        |c| c.is_ascii_alphanumeric(),
        Some("Windows"),
        "windows",
    ),
    (
        "laptop-",
        7,
        |c| c.is_ascii_alphanumeric(),
        Some("Windows"),
        "windows",
    ),
    (
        "android-",
        0,
        |c| c.is_ascii_hexdigit(),
        Some("Android"),
        "mobile",
    ),
    ("npi", 6, |c| c.is_ascii_hexdigit(), None, "printer"),
    ("brn", 12, |c| c.is_ascii_hexdigit(), None, "printer"),
    ("brw", 12, |c| c.is_ascii_hexdigit(), None, "printer"),
];

/// Hints for a DHCP client message (DISCOVER/REQUEST/INFORM): option 55 parameter request list,
/// option 60 vendor class and option 12 host name. Only call this for client messages.
pub(super) fn dhcp(parameter_list: &[u8], vendor_class: &str, hostname: &str) -> Vec<Hint> {
    let mut hints = vec![];
    for (list, os, category) in DHCP_PARAMETER_LISTS {
        if *list == parameter_list {
            let mut h = Hint::new(category, true, format!("DHCP request list matches {os}"));
            h.os = Some(os);
            hints.push(h);
        }
    }
    for mut h in matching(vendor_class, DHCP_VENDOR_CLASS, "DHCP vendor class") {
        h.os = match h.category {
            "windows" => Some("Windows"),
            "mobile" => Some("Android"),
            "linux" => Some("Linux"),
            _ => None,
        };
        hints.push(h);
    }
    let lower = hostname.to_ascii_lowercase();
    if lower.contains("iphone") || lower.contains("ipad") {
        let mut h = Hint::new("apple", true, "DHCP host name names an iPhone/iPad");
        h.os = Some("iOS/iPadOS");
        hints.push(h);
    }
    for (prefix, count, accepted, os, category) in DHCP_HOSTNAMES {
        if let Some(rest) = lower.strip_prefix(prefix)
            && !rest.is_empty()
            && (*count == 0 || rest.chars().count() == *count)
            && rest.chars().all(accepted)
        {
            let mut h = Hint::new(category, true, format!("DHCP default host name {prefix}…"));
            h.os = *os;
            hints.push(h);
        }
    }
    hints
}

/// The OS name to show for a set of DHCP hints: the first one that names an OS.
pub(super) fn dhcp_os(hints: &[Hint]) -> Option<&'static str> {
    hints.iter().find_map(|h| h.os)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strong_replaces_weak_and_keys_come_from_a_closed_set() {
        let mut f = BTreeMap::new();
        attach(&mut f, [Hint::new("media", false, "a")]);
        assert_eq!(f["hint_weak.media"], "a");
        attach(
            &mut f,
            [
                Hint::new("media", true, "b"),
                Hint::new("media", false, "c"),
            ],
        );
        assert_eq!(f["hint.media"], "b");
        assert!(!f.contains_key("hint_weak.media"));
        assert_eq!(stored(&f), vec![("media", true, "b".to_string())]);
        // Unknown categories in stored data are ignored.
        f.insert("hint.bogus".into(), "x".into());
        assert_eq!(stored(&f).len(), 1);
    }

    #[test]
    fn dhcp_hints_cover_the_table() {
        let h = dhcp(
            &[1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252],
            "MSFT 5.0",
            "",
        );
        assert!(h.iter().all(|h| h.category == "windows" && h.strong));
        assert_eq!(dhcp_os(&h), Some("Windows 10/11"));
        assert_eq!(dhcp_os(&dhcp(&[], "android-dhcp-13", "")), Some("Android"));
        let h = dhcp(&[], "", "NPI1A2B3C");
        assert_eq!(h[0].category, "printer");
        assert!(dhcp(&[], "", "NPI1A2B3").is_empty(), "wrong length");
        assert!(dhcp(&[], "", "npi").is_empty());
        assert_eq!(dhcp(&[], "", "Nicks-iPhone")[0].category, "apple");
        assert_eq!(dhcp(&[], "", "DESKTOP-AB12CD3")[0].category, "windows");
        assert!(dhcp(&[], "", "DESKTOP-AB12").is_empty());
        assert!(dhcp(&[1, 2, 3], "unknown", "host").is_empty());
    }

    #[test]
    fn apple_models() {
        assert_eq!(apple_model("MacBookPro18,3")[0].category, "apple");
        assert_eq!(apple_model("Mac14,2")[0].category, "apple");
        let tv = apple_model("AppleTV11,1");
        assert!(tv.iter().any(|h| h.category == "media"));
        assert!(apple_model("DS918+").is_empty());
        assert!(apple_model("Machine").is_empty());
    }
}
