// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Embedded IEEE OUI registries (MA-L, MA-M, MA-S) and the ODVA/CIP vendor list.
use std::{collections::HashMap, sync::OnceLock};

static OUI: &str = include_str!("../../data/oui.tsv");
static CIP: &str = include_str!("../../data/cip_vendors.tsv");

fn oui_table() -> &'static HashMap<&'static str, &'static str> {
    static TABLE: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    TABLE.get_or_init(|| {
        OUI.lines()
            .filter_map(|l| l.split_once('\t'))
            .collect::<HashMap<_, _>>()
    })
}
fn cip_table() -> &'static HashMap<u16, &'static str> {
    static TABLE: OnceLock<HashMap<u16, &'static str>> = OnceLock::new();
    TABLE.get_or_init(|| {
        CIP.lines()
            .filter_map(|l| {
                let (id, name) = l.split_once('\t')?;
                Some((id.parse().ok()?, name))
            })
            .collect()
    })
}

/// Manufacturer for a MAC in any common notation. Longest registered prefix wins
/// (MA-S 36 bit, then MA-M 28 bit, then MA-L 24 bit).
pub fn vendor(mac: &str) -> Option<&'static str> {
    let hex: String = mac
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if hex.len() < 6 {
        return None;
    }
    let table = oui_table();
    [9, 7, 6]
        .into_iter()
        .filter(|n| hex.len() >= *n)
        .find_map(|n| table.get(&hex[..n]).copied())
}

/// Locally administered addresses (second-least-significant bit of the first octet) are
/// randomised or virtual; they carry no manufacturer information.
pub fn locally_administered(mac: &str) -> bool {
    let first: String = mac
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(2)
        .collect();
    u8::from_str_radix(&first, 16).is_ok_and(|b| first.len() == 2 && b & 2 != 0)
}
pub fn cip_vendor(id: u16) -> Option<&'static str> {
    cip_table().get(&id).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_embedded_and_matches_prefixes() {
        assert!(oui_table().len() > 40_000);
        assert!(vendor("00:00:0C:12:34:56").unwrap().contains("Cisco"));
        assert_eq!(vendor("00-00-0c-12-34-56"), vendor("00000C123456"));
        assert!(vendor("28:6F:B9:00:00:01").unwrap().contains("Nokia"));
        assert_eq!(vendor("zz"), None);
        assert_eq!(vendor("FF:FF:FF:FF:FF:FF"), None);
    }

    #[test]
    fn longer_prefixes_take_precedence() {
        let long = oui_table().keys().find(|k| k.len() == 9).unwrap();
        let name = oui_table()[long];
        let mac = format!("{long}FFF");
        assert_eq!(vendor(&mac), Some(name));
    }

    #[test]
    fn locally_administered_bit() {
        assert!(locally_administered("02:00:00:00:00:01"));
        assert!(locally_administered("DA-A1-19-00-00-00"));
        assert!(!locally_administered("00:00:0C:00:00:01"));
    }

    #[test]
    fn cip_vendors() {
        assert_eq!(cip_vendor(1), Some("Rockwell Automation/Allen-Bradley"));
        assert!(cip_table().len() > 1000);
    }
}
