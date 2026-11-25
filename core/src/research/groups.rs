// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Groups of devices that share a fingerprint (ROADMAP L70): the same certificate key, the same
//! TLS or SSH stack (JARM, JA3S, HASSH), the same web
//! interface (favicon hash) or the same industrial firmware, across scans and sites.
//!
//! The grouping is one SQL query over the `fingerprints` and `services` tables (see
//! [`super::schema_text`]) plus a fold over its members. A device is its MAC address when a scan
//! saw one, else its IP address, so a device that changed address counts once. A *site* is the
//! target list of the scan that saw the device, which is as much as the inventory knows about
//! where a scan was taken.
//!
//! What a group means depends on the fingerprint (`strength`):
//!
//! | Strength | Fingerprints | Reading |
//! |---|---|---|
//! | `key` | `spki_sha256` | The devices use the same private key. Vendor default keys and cloned images do this; anyone with the key can impersonate all of them. |
//! | `firmware` | `ot_firmware` | The same industrial vendor, product and firmware version (a version-level fact). |
//! | `software` | `jarm`, `ja3s`, `hassh`, `favicon_mmh3` | Likely the same software stack, configuration or web interface; evidence, not proof. |
//!
//! Nothing here sends traffic.
use super::open_read_only;
use rusqlite::params;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

/// Most members listed per group (the count is always complete).
const MAX_MEMBERS: usize = 50;
/// Most sites listed per group.
const MAX_SITES: usize = 20;
/// Most groups returned when no limit is given.
pub const DEFAULT_LIMIT: usize = 200;

/// One device in a group.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Member {
    /// MAC address, or the IP address when no scan saw a MAC.
    pub device: String,
    pub ips: Vec<String>,
    pub hostnames: Vec<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    /// Scans that saw the device with this fingerprint.
    pub scans: u64,
}

/// Devices that share one fingerprint value.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Group {
    /// `spki_sha256`, `jarm`, `ja3s`, `hassh`, `favicon_mmh3` or `ot_firmware`.
    pub kind: String,
    pub value: String,
    /// `key`, `firmware` or `software` (see the module documentation).
    pub strength: String,
    pub meaning: String,
    /// How many different devices share it.
    pub devices: usize,
    /// Target lists of the scans that saw it.
    pub sites: Vec<String>,
    pub members: Vec<Member>,
}

fn describe(kind: &str) -> (&'static str, &'static str) {
    match kind {
        "spki_sha256" => (
            "key",
            "the same certificate key: a vendor default key or a cloned image; whoever holds the key can impersonate every device in the group",
        ),
        "ot_firmware" => (
            "firmware",
            "the same industrial vendor, product and firmware version",
        ),
        "jarm" | "ja3s" => ("software", "the same TLS stack and configuration"),
        "hassh" => ("software", "the same SSH stack and configuration"),
        "favicon_mmh3" => ("software", "the same web interface"),
        _ => ("software", "the same fingerprint"),
    }
}

/// Sort position of a strength: keys first, then firmware, then software.
fn rank(strength: &str) -> u8 {
    match strength {
        "key" => 0,
        "firmware" => 1,
        _ => 2,
    }
}

/// Every fingerprint (and derived industrial firmware version) as `(scan_id, scan_time, ip, kind,
/// value)`; the common table expression both queries below start with.
const PIVOTS: &str = "WITH p AS (SELECT scan_id, scan_time, ip, kind, value FROM fingerprints UNION ALL SELECT scan_id, scan_time, ip, 'ot_firmware', name || ' | ' || product || ' | ' || version FROM services WHERE name IN ('S7', 'EtherNet/IP', 'Modbus', 'OPC UA') AND product != '' AND version != '')";

/// The groups of at least two devices, keys first, then by size; at most `limit` fingerprints are
/// examined (the ones shared by the most addresses first).
pub fn groups(db: &Path, limit: usize) -> Result<Vec<Group>, String> {
    let c = open_read_only(db)?;
    let mut candidates = c
        .prepare(&format!(
            "{PIVOTS} SELECT kind, value, count(DISTINCT ip) AS n FROM p GROUP BY kind, value HAVING n >= 2 ORDER BY n DESC, kind, value LIMIT ?1"
        ))
        .map_err(|e| e.to_string())?;
    let found: Vec<(String, String)> = candidates
        .query_map(params![limit as i64], |r| Ok((r.get(0)?, r.get(1)?)))
        .map_err(|e| e.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    let mut members = c
        .prepare(&format!(
            "{PIVOTS} SELECT p.ip, h.mac, h.hostname, h.targets, p.scan_time FROM p JOIN hosts h ON h.scan_id = p.scan_id AND h.ip = p.ip WHERE p.kind = ?1 AND p.value = ?2"
        ))
        .map_err(|e| e.to_string())?;
    let mut out = vec![];
    for (kind, value) in found {
        #[derive(Default)]
        struct Device {
            ips: BTreeSet<String>,
            hostnames: BTreeSet<String>,
            first: i64,
            last: i64,
            scans: u64,
        }
        let mut devices: BTreeMap<String, Device> = BTreeMap::new();
        let mut sites: BTreeSet<String> = BTreeSet::new();
        let rows = members
            .query_map(params![kind, value], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        for row in rows {
            let (ip, mac, hostname, targets, time) = row.map_err(|e| e.to_string())?;
            let key = if mac.is_empty() { ip.clone() } else { mac };
            let d = devices.entry(key).or_insert_with(|| Device {
                first: time,
                last: time,
                ..Default::default()
            });
            d.ips.insert(ip);
            if !hostname.is_empty() {
                d.hostnames.insert(hostname);
            }
            d.first = d.first.min(time);
            d.last = d.last.max(time);
            d.scans += 1;
            if sites.len() < MAX_SITES {
                sites.insert(targets);
            }
        }
        if devices.len() < 2 {
            continue;
        }
        let (strength, meaning) = describe(&kind);
        let count = devices.len();
        let mut list: Vec<Member> = devices
            .into_iter()
            .map(|(device, d)| Member {
                device,
                ips: d.ips.into_iter().take(10).collect(),
                hostnames: d.hostnames.into_iter().take(5).collect(),
                first_seen: d.first,
                last_seen: d.last,
                scans: d.scans,
            })
            .collect();
        list.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then(a.device.cmp(&b.device)));
        list.truncate(MAX_MEMBERS);
        out.push(Group {
            kind,
            value,
            strength: strength.into(),
            meaning: meaning.into(),
            devices: count,
            sites: sites.into_iter().collect(),
            members: list,
        });
    }
    out.sort_by(|a, b| {
        rank(&a.strength)
            .cmp(&rank(&b.strength))
            .then(b.devices.cmp(&a.devices))
            .then(a.kind.cmp(&b.kind))
            .then(a.value.cmp(&b.value))
    });
    Ok(out)
}

/// The groups as text for the terminal.
pub fn text(groups: &[Group]) -> String {
    if groups.is_empty() {
        return "No fingerprint is shared by two or more devices.".into();
    }
    let mut out = vec![];
    for g in groups {
        out.push(format!(
            "[{}] {} {}: {} devices at {} site(s), {}",
            g.strength.to_ascii_uppercase(),
            g.kind,
            g.value,
            g.devices,
            g.sites.len(),
            g.meaning
        ));
        for m in &g.members {
            out.push(format!(
                "    {}  {}{}",
                m.device,
                m.ips.join(", "),
                if m.hostnames.is_empty() {
                    String::new()
                } else {
                    format!("  ({})", m.hostnames.join(", "))
                }
            ));
        }
        if g.devices > g.members.len() {
            out.push(format!("    ... and {} more", g.devices - g.members.len()));
        }
    }
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::super::tests::{host, remove_db, snapshot, temp_db};
    use super::*;
    use crate::store;

    const K1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const K2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn device(ip: &str, mac: &str, key: &str, extra: &[(&str, &str)]) -> crate::scan::Host {
        let mut id = vec![
            ("tls.443.spki_sha256", key),
            (
                "tls.443.jarm",
                "27d27d27d27d27d1dc27d27d27d27d00000000000000000000000000000000",
            ),
        ];
        id.extend_from_slice(extra);
        let mut h = host(ip, &[443], &id);
        h.mac = mac.into();
        h
    }

    #[test]
    fn devices_sharing_a_key_or_firmware_across_sites_form_groups() {
        let path = temp_db("groups");
        let s7 = [
            ("S7.order_code", "6ES7 214-1AG40-0XB0"),
            ("S7.firmware", "4.2.3"),
        ];
        // site A, then site B a day later, then site A again with the first device at a new address
        let mut a = snapshot(vec![device("10.1.0.5", "AA:00:00:00:00:01", K1, &s7)]);
        a.targets = "10.1.0.0/24".into();
        store::save_at(&path, &a, 1_000).unwrap();
        let mut b = snapshot(vec![
            device("10.2.0.9", "AA:00:00:00:00:02", K1, &s7),
            device("10.2.0.10", "AA:00:00:00:00:03", K2, &[]),
        ]);
        b.targets = "10.2.0.0/24".into();
        store::save_at(&path, &b, 2_000).unwrap();
        let mut c = snapshot(vec![device("10.1.0.77", "AA:00:00:00:00:01", K1, &s7)]);
        c.targets = "10.1.0.0/24".into();
        store::save_at(&path, &c, 3_000).unwrap();

        let all = groups(&path, DEFAULT_LIMIT).unwrap();
        let key = all
            .iter()
            .find(|g| g.kind == "spki_sha256" && g.value == K1)
            .unwrap();
        assert_eq!(key.strength, "key");
        assert_eq!(
            key.devices, 2,
            "the device that changed address counts once"
        );
        assert_eq!(key.sites, ["10.1.0.0/24", "10.2.0.0/24"]);
        let moved = key
            .members
            .iter()
            .find(|m| m.device == "AA:00:00:00:00:01")
            .unwrap();
        assert_eq!(moved.ips, ["10.1.0.5", "10.1.0.77"]);
        assert_eq!(
            (moved.first_seen, moved.last_seen, moved.scans),
            (1_000, 3_000, 2)
        );
        assert!(
            all.iter()
                .all(|g| !(g.kind == "spki_sha256" && g.value == K2)),
            "one device alone is not a group"
        );
        let firmware = all.iter().find(|g| g.kind == "ot_firmware").unwrap();
        assert_eq!(firmware.value, "S7 | 6ES7 214-1AG40-0XB0 | 4.2.3");
        assert_eq!(
            (firmware.strength.as_str(), firmware.devices),
            ("firmware", 2)
        );
        // the JARM is shared by all three devices: a software group, listed after the key
        let jarm = all.iter().find(|g| g.kind == "jarm").unwrap();
        assert_eq!((jarm.strength.as_str(), jarm.devices), ("software", 3));
        assert_eq!(all[0].kind, "spki_sha256", "keys first");
        let text = text(&all);
        assert!(text.contains("[KEY] spki_sha256"), "{text}");
        assert!(text.contains("AA:00:00:00:00:01"), "{text}");
        // the limit bounds the groups that are examined
        assert_eq!(groups(&path, 1).unwrap().len(), 1);
        remove_db(&path);
    }

    #[test]
    fn without_shared_fingerprints_there_are_no_groups() {
        let path = temp_db("groups-none");
        assert!(groups(&path, 10).unwrap().is_empty());
        assert!(text(&[]).contains("No fingerprint"));
        store::save_at(
            &path,
            &snapshot(vec![device("10.0.0.5", "AA:00:00:00:00:09", K1, &[])]),
            5,
        )
        .unwrap();
        assert!(groups(&path, 10).unwrap().is_empty());
        remove_db(&path);
    }

    #[test]
    fn a_group_lists_at_most_fifty_members_but_counts_all() {
        let path = temp_db("groups-many");
        let hosts: Vec<_> = (0..60)
            .map(|i| {
                device(
                    &format!("10.3.0.{}", i + 1),
                    &format!("AA:00:00:00:01:{i:02X}"),
                    K1,
                    &[],
                )
            })
            .collect();
        store::save_at(&path, &snapshot(hosts), 10).unwrap();
        let g = groups(&path, 10).unwrap();
        let key = g.iter().find(|g| g.kind == "spki_sha256").unwrap();
        assert_eq!((key.devices, key.members.len()), (60, MAX_MEMBERS));
        assert!(text(&g).contains("... and 10 more"));
        remove_db(&path);
    }
}
