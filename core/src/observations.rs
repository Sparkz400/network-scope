// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Merging of passive observations: one entry per MAC, protocol and IP, fields merged, capped at
//! [`MAX_OBSERVATIONS`]. Used by the passive capture commands, `monitor`, the OT listener and the GUI.
use crate::passive;

/// Adds an observation, or merges its fields into the entry with the same MAC, protocol and IP.
/// Linear lookup; long-running callers should use [`merge_indexed`] with an [`ObservationIndex`].
pub fn merge(
    observations: &mut Vec<passive::Observation>,
    o: passive::Observation,
) -> Result<(), String> {
    if let Some(old) = observations
        .iter_mut()
        .find(|v| v.mac == o.mac && v.protocol == o.protocol && v.ip == o.ip)
    {
        old.fields.extend(o.fields);
    } else if observations.len() < MAX_OBSERVATIONS {
        observations.push(o);
    } else {
        return Err(LIMIT_MESSAGE.into());
    }
    Ok(())
}
pub const MAX_OBSERVATIONS: usize = 10_000;
const LIMIT_MESSAGE: &str = "Observation limit (10,000) reached";
type ObservationKey = (String, String, Option<std::net::IpAddr>);
fn observation_key(o: &passive::Observation) -> ObservationKey {
    (o.mac.clone(), o.protocol.clone(), o.ip)
}
/// Hash index over an observation list for [`merge_indexed`]. It rebuilds itself when the list
/// was replaced or changed behind its back (length mismatch or a stale entry).
#[derive(Default)]
pub struct ObservationIndex {
    map: std::collections::HashMap<ObservationKey, usize>,
    len: usize,
}
impl ObservationIndex {
    pub fn clear(&mut self) {
        self.map.clear();
        self.len = 0;
    }
    fn rebuild(&mut self, observations: &[passive::Observation]) {
        self.map.clear();
        for (i, o) in observations.iter().enumerate() {
            self.map.entry(observation_key(o)).or_insert(i);
        }
        self.len = observations.len();
    }
    fn find(&self, observations: &[passive::Observation], key: &ObservationKey) -> Option<usize> {
        self.map.get(key).copied().filter(|&i| {
            observations
                .get(i)
                .is_some_and(|v| v.mac == key.0 && v.protocol == key.1 && v.ip == key.2)
        })
    }
}
/// Same semantics as [`merge`] in O(1) per call.
pub fn merge_indexed(
    observations: &mut Vec<passive::Observation>,
    index: &mut ObservationIndex,
    o: passive::Observation,
) -> Result<(), String> {
    if index.len != observations.len() {
        index.rebuild(observations);
    }
    let key = observation_key(&o);
    let mut found = index.find(observations, &key);
    if found.is_none() && index.map.contains_key(&key) {
        // Stale entry: the list was edited in place.
        index.rebuild(observations);
        found = index.find(observations, &key);
    }
    if let Some(i) = found {
        observations[i].fields.extend(o.fields);
    } else if observations.len() < MAX_OBSERVATIONS {
        index.map.insert(key, observations.len());
        observations.push(o);
        index.len = observations.len();
    } else {
        return Err(LIMIT_MESSAGE.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(
        mac: &str,
        protocol: &str,
        ip: Option<&str>,
        field: (&str, &str),
    ) -> passive::Observation {
        passive::Observation {
            protocol: protocol.into(),
            mac: mac.into(),
            ip: ip.map(|i| i.parse().unwrap()),
            fields: std::collections::BTreeMap::from([(field.0.to_string(), field.1.to_string())]),
        }
    }

    #[test]
    fn indexed_merge_matches_linear_merge() {
        let input = vec![
            obs("aa", "mDNS", Some("10.0.0.1"), ("name", "a")),
            obs("aa", "mDNS", Some("10.0.0.1"), ("model", "x")),
            obs("aa", "mDNS", None, ("name", "b")),
            obs("aa", "LLDP", Some("10.0.0.1"), ("port", "1")),
            obs("bb", "mDNS", Some("10.0.0.1"), ("name", "c")),
            obs("aa", "mDNS", Some("10.0.0.1"), ("name", "a2")),
        ];
        let mut linear = vec![];
        let mut indexed = vec![];
        let mut index = ObservationIndex::default();
        for o in input {
            merge(&mut linear, o.clone()).unwrap();
            merge_indexed(&mut indexed, &mut index, o).unwrap();
        }
        assert_eq!(linear, indexed);
        assert_eq!(indexed.len(), 4);
        assert_eq!(indexed[0].fields["name"], "a2");
        assert_eq!(indexed[0].fields["model"], "x");
        // The list is replaced behind the index's back: it must notice and rebuild.
        indexed = vec![obs("cc", "ARP", None, ("x", "1"))];
        merge_indexed(&mut indexed, &mut index, obs("cc", "ARP", None, ("y", "2"))).unwrap();
        assert_eq!(indexed.len(), 1);
        assert_eq!(indexed[0].fields.len(), 2);
        // Same length, different content.
        indexed = vec![obs("dd", "ARP", None, ("x", "1"))];
        merge_indexed(&mut indexed, &mut index, obs("cc", "ARP", None, ("z", "3"))).unwrap();
        assert_eq!(indexed.len(), 2);
        index.clear();
        merge_indexed(&mut indexed, &mut index, obs("dd", "ARP", None, ("w", "4"))).unwrap();
        assert_eq!(indexed.len(), 2);
    }

    #[test]
    fn observation_cap_keeps_merging_existing_entries() {
        let mut list = vec![];
        let mut index = ObservationIndex::default();
        for i in 0..MAX_OBSERVATIONS {
            merge_indexed(
                &mut list,
                &mut index,
                obs(&format!("{i}"), "ARP", None, ("n", "1")),
            )
            .unwrap();
        }
        merge_indexed(&mut list, &mut index, obs("5", "ARP", None, ("m", "2"))).unwrap();
        assert_eq!(list[5].fields["m"], "2");
        assert!(merge_indexed(&mut list, &mut index, obs("new", "ARP", None, ("n", "1"))).is_err());
        assert!(merge(&mut list, obs("new", "ARP", None, ("n", "1"))).is_err());
        assert!(merge(&mut list, obs("7", "ARP", None, ("m", "2"))).is_ok());
    }
}
