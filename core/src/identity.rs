//! Stable device identity: a key for a device that survives address changes and randomised MAC
//! addresses.
//!
//! A scan result is keyed by MAC address (or by IP address when no MAC is visible, see
//! [`crate::devices::merge`]). Phones and laptops rotate "private" MAC addresses, and DHCP hands
//! out new IP addresses, so those keys alone make one device look like several. This module
//! scores identifiers a device reports and matches a device against the ones already recorded:
//!
//! | Identifier | Points | Notes |
//! |---|---|---|
//! | globally unique MAC (also the fixed `52:54:00`-style virtual NIC prefixes) | 100 | decides alone |
//! | SNMP engine ID (when an agent reported one) | 100 | decides alone |
//! | SMB server GUID | 70 | cloned VMs share it |
//! | SSH host key fingerprint (when reported) | 70 | golden images share it |
//! | DHCP client identifier (option 61) | 60 | usually derived from the MAC, which rotates |
//! | TLS certificate public key hash | 40 | vendor default certificates are shared |
//! | randomised (locally administered) MAC | 40 | never decides alone |
//! | host name (mDNS, DHCP, NetBIOS, reverse DNS) | 30 | names get reused |
//! | host name declared by an import (AD, NetBox, CSV) | 100 | decides alone; see below |
//! | IP address | 15 | addresses get reassigned |
//! | HASSH + JA4S pair | 10 | identifies the software, not the device |
//!
//! Two records are the same device when the points of their *matching* identifiers reach
//! [`MATCH_THRESHOLD`] (100), so one strong identifier decides, and weak ones only add up: a
//! shared default TLS key, a common host name or an identical SSH stack never merge two devices
//! on their own. Identifiers that cannot belong to two devices veto a match: two different
//! globally unique MACs, two different SMB GUIDs or two different SNMP engine IDs.
//!
//! A host name that an operator *declared* (an Active Directory computer, a NetBox device or a CSV
//! row, see [`crate::baseline`] and the `import` command) is the exception to "names get reused":
//! it is the list's own name for the device, so it decides alone when the name of a scanned device
//! matches it (the first label, e.g. `pc-01` for `PC-01.corp.local`; two full names must be equal).
//! Names are not authenticated: a hostile device can claim a declared name, so for an allow-list
//! on an untrusted network declare MAC addresses too.
//!
//! The key of a device is the id it was first seen with (its MAC, or `ip:ADDRESS`), kept for as
//! long as the device is recognised. Databases written before this module therefore keep their
//! keys, and a device that shows up again under the same id keeps matching it exactly as before.
//! Nothing here sends traffic: identifiers come only from replies a scan already collected.
use crate::devices::Device;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Points a candidate pair needs to count as one device.
pub const MATCH_THRESHOLD: u32 = 100;
/// Most values kept per identifier kind of one device (older ones are dropped first).
pub const MAX_VALUES_PER_KIND: usize = 8;
/// Longest identifier value kept (identifiers come from untrusted devices).
const MAX_VALUE_LEN: usize = 200;

/// What an identifier is derived from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A MAC address that is globally unique, or a virtual NIC prefix that does not rotate.
    Mac,
    /// A locally administered MAC address (bit 0x02 of the first octet): randomised by the
    /// device or assigned by software, so it may change at any time.
    RandomMac,
    SnmpEngineId,
    SmbGuid,
    SshHostKey,
    TlsKey,
    DhcpClientId,
    Hostname,
    /// HASSH and JA4S of the same host: weak evidence that two hosts run the same software.
    ServiceFingerprint,
    Ip,
    /// A host name an operator declared for the device (an import). Never derived from a scan.
    DeclaredName,
}

impl Kind {
    pub const ALL: [Kind; 11] = [
        Kind::Mac,
        Kind::RandomMac,
        Kind::SnmpEngineId,
        Kind::SmbGuid,
        Kind::SshHostKey,
        Kind::TlsKey,
        Kind::DhcpClientId,
        Kind::Hostname,
        Kind::ServiceFingerprint,
        Kind::Ip,
        Kind::DeclaredName,
    ];
    /// The name stored in the database and shown in reports.
    pub fn name(self) -> &'static str {
        match self {
            Kind::Mac => "mac",
            Kind::RandomMac => "random_mac",
            Kind::SnmpEngineId => "snmp_engine_id",
            Kind::SmbGuid => "smb_guid",
            Kind::SshHostKey => "ssh_host_key",
            Kind::TlsKey => "tls_key",
            Kind::DhcpClientId => "dhcp_client_id",
            Kind::Hostname => "hostname",
            Kind::ServiceFingerprint => "service_fingerprint",
            Kind::Ip => "ip",
            Kind::DeclaredName => "declared_name",
        }
    }
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }
    /// Points a matching identifier of this kind adds.
    pub fn weight(self) -> u32 {
        match self {
            Kind::Mac | Kind::SnmpEngineId | Kind::DeclaredName => 100,
            Kind::SmbGuid | Kind::SshHostKey => 70,
            Kind::DhcpClientId => 60,
            Kind::RandomMac | Kind::TlsKey => 40,
            Kind::Hostname => 30,
            Kind::Ip => 15,
            Kind::ServiceFingerprint => 10,
        }
    }
    /// Kinds that are unique to one device: two different values rule a match out.
    fn vetoes(self) -> bool {
        matches!(self, Kind::Mac | Kind::SmbGuid | Kind::SnmpEngineId)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Identifier {
    pub kind: Kind,
    pub value: String,
}

impl Identifier {
    fn new(kind: Kind, value: impl Into<String>) -> Option<Self> {
        let value: String = value
            .into()
            .trim()
            .chars()
            .filter(|c| !c.is_control())
            .take(MAX_VALUE_LEN)
            .collect();
        (!value.is_empty()).then_some(Self { kind, value })
    }
}

/// Whether a (normalised) MAC address identifies the device for good: not locally administered,
/// or a virtual NIC prefix that hypervisors assign once and keep.
pub fn mac_is_stable(mac: &str) -> bool {
    !crate::oui::locally_administered(mac) || crate::devices::is_virtual_mac(mac)
}

fn hostname_identifier(name: &str, ips: &[std::net::IpAddr]) -> Option<Identifier> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty()
        || name == "localhost"
        || name.parse::<std::net::IpAddr>().is_ok()
        // Reverse DNS names built from the address (`host-10-0-0-5.lan`) change with it.
        || ips
            .iter()
            .any(|ip| name.contains(&ip.to_string().replace(['.', ':'], "-")))
    {
        return None;
    }
    Identifier::new(Kind::Hostname, name)
}

/// The identifiers of one merged device, derived from what the scan and the passive capture
/// reported. `identity` is the active identity of the device (`smb.445.guid`, `tls.443.spki_sha256`,
/// `ssh.22.hostkey_sha256`, `snmp.engine_id`, ...), `observations` the passive records by protocol.
pub fn identifiers(
    mac: &str,
    ips: &[std::net::IpAddr],
    hostnames: &[String],
    identity: &BTreeMap<String, String>,
    observations: &BTreeMap<String, BTreeMap<String, String>>,
) -> Vec<Identifier> {
    let mut out: BTreeSet<Identifier> = BTreeSet::new();
    if !mac.is_empty() {
        let kind = if mac_is_stable(mac) {
            Kind::Mac
        } else {
            Kind::RandomMac
        };
        out.extend(Identifier::new(kind, mac));
    }
    out.extend(
        ips.iter()
            .filter_map(|ip| Identifier::new(Kind::Ip, ip.to_string())),
    );
    out.extend(hostnames.iter().filter_map(|h| hostname_identifier(h, ips)));
    let (mut hassh, mut ja4s) = (None, None);
    for (key, value) in identity {
        let parts: Vec<&str> = key.split('.').collect();
        let kind = match parts.as_slice() {
            ["smb", port, "guid"] if port.parse::<u16>().is_ok() => Some(Kind::SmbGuid),
            ["ssh", port, "hostkey_sha256"] if port.parse::<u16>().is_ok() => {
                Some(Kind::SshHostKey)
            }
            ["tls", port, "spki_sha256"] if port.parse::<u16>().is_ok() => Some(Kind::TlsKey),
            ["snmp", "engine_id"] => Some(Kind::SnmpEngineId),
            ["udp", port, "engine_id"] if port.parse::<u16>().is_ok() => Some(Kind::SnmpEngineId),
            ["ssh", port, "hassh"] if port.parse::<u16>().is_ok() => {
                hassh.get_or_insert(value.as_str());
                None
            }
            ["tls", port, "ja4s"] if port.parse::<u16>().is_ok() => {
                ja4s.get_or_insert(value.as_str());
                None
            }
            _ => None,
        };
        if let Some(kind) = kind {
            // Hashes and GUIDs compare case-insensitively.
            out.extend(Identifier::new(kind, value.to_ascii_lowercase()));
        }
    }
    if let (Some(h), Some(j)) = (hassh, ja4s) {
        out.extend(Identifier::new(
            Kind::ServiceFingerprint,
            format!("{}+{}", h.to_ascii_lowercase(), j.to_ascii_lowercase()),
        ));
    }
    for fields in observations.values() {
        if let Some(id) = fields.get("client_id") {
            out.extend(Identifier::new(Kind::DhcpClientId, id.to_ascii_lowercase()));
        }
    }
    out.into_iter().collect()
}

/// One recorded device: its key and everything it was seen with.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Record {
    pub key: String,
    pub identifiers: BTreeMap<Kind, BTreeSet<String>>,
}

impl Record {
    fn has(&self, kind: Kind, value: &str) -> bool {
        self.identifiers
            .get(&kind)
            .is_some_and(|set| set.contains(value))
    }
    fn conflicts(&self, kind: Kind, device: &BTreeMap<Kind, BTreeSet<&str>>) -> bool {
        let (Some(mine), Some(theirs)) = (self.identifiers.get(&kind), device.get(&kind)) else {
            return false;
        };
        !mine.is_empty() && !theirs.is_empty() && !theirs.iter().any(|v| mine.contains(*v))
    }
}

/// The devices recorded so far (loaded from the store, see `store::device_registry`).
#[derive(Clone, Debug, Default)]
pub struct Registry {
    records: Vec<Record>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    pub fn records(&self) -> &[Record] {
        &self.records
    }
    pub fn contains_key(&self, key: &str) -> bool {
        self.records.iter().any(|r| r.key == key)
    }
    /// Makes sure a device with this key exists (no identifiers needed).
    pub fn add_key(&mut self, key: &str) {
        if !self.contains_key(key) {
            self.records.push(Record {
                key: key.to_string(),
                ..Default::default()
            });
        }
    }
    /// Adds an identifier to the record of `key`, creating the record.
    pub fn add(&mut self, key: &str, identifier: Identifier) {
        let record = match self.records.iter().position(|r| r.key == key) {
            Some(i) => &mut self.records[i],
            None => {
                self.records.push(Record {
                    key: key.to_string(),
                    ..Default::default()
                });
                self.records.last_mut().expect("just pushed")
            }
        };
        record
            .identifiers
            .entry(identifier.kind)
            .or_default()
            .insert(identifier.value);
    }
    /// Remembers the identifiers of `device` under `key` (what `store::record_devices` does
    /// persistently), so a later [`resolve`] call recognises it.
    pub fn learn(&mut self, key: &str, device: &Device) {
        for i in &device.identifiers {
            self.add(key, i.clone());
        }
        self.add_key(key);
    }
}

/// A device matched against the registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Match {
    /// The stable key: that of the recognised device, or a new one (the device's id).
    pub key: String,
    /// The device was not recognised: nothing recorded reaches the threshold.
    pub new: bool,
    /// Points of the matching identifiers (an exact repeat of the key counts as 1000).
    pub score: u32,
    /// Kinds of the matching identifiers, or `same-id` for a device seen under the same id.
    pub reasons: Vec<String>,
}

/// The first label of a host name (`pc-01` of `pc-01.corp.local`).
fn first_label(name: &str) -> &str {
    name.split('.').next().unwrap_or(name)
}

/// Two host names are the same name: equal, or one of them is a bare name and the first labels
/// are equal. Two fully qualified names must be equal.
fn names_match(a: &str, b: &str) -> bool {
    if a.contains('.') && b.contains('.') {
        a == b
    } else {
        !first_label(a).is_empty() && first_label(a) == first_label(b)
    }
}

/// Score of `device` against `record`, or `None` when an identifier rules the match out.
fn score(
    device: &Device,
    values: &BTreeMap<Kind, BTreeSet<&str>>,
    record: &Record,
) -> Option<(u32, Vec<&'static str>)> {
    let exact = record.key == device.id;
    let global_mac = values.contains_key(&Kind::Mac);
    // A globally unique MAC is the strongest identifier: it is not vetoed by anything else (a
    // reinstalled system has a new SMB GUID). Any other match can be.
    if !(exact && global_mac)
        && Kind::ALL
            .iter()
            .filter(|k| k.vetoes())
            .any(|k| record.conflicts(*k, values))
    {
        return None;
    }
    let mut points = 0;
    let mut reasons = vec![];
    for kind in Kind::ALL {
        // Declared names are matched against names of either kind below.
        let Some(mine) = values.get(&kind).filter(|_| kind != Kind::DeclaredName) else {
            continue;
        };
        if mine.iter().any(|v| record.has(kind, v)) {
            points += kind.weight();
            reasons.push(kind.name());
        }
    }
    let of_device =
        |k: Kind| -> Vec<&str> { values.get(&k).into_iter().flatten().copied().collect() };
    let of_record = |k: Kind| -> Vec<&str> {
        record
            .identifiers
            .get(&k)
            .into_iter()
            .flatten()
            .map(String::as_str)
            .collect()
    };
    let (dev_declared, dev_scanned) = (of_device(Kind::DeclaredName), of_device(Kind::Hostname));
    let (rec_declared, rec_scanned) = (of_record(Kind::DeclaredName), of_record(Kind::Hostname));
    let declared_hit = dev_declared.iter().any(|a| {
        rec_declared
            .iter()
            .chain(&rec_scanned)
            .any(|b| names_match(a, b))
    }) || dev_scanned
        .iter()
        .any(|a| rec_declared.iter().any(|b| names_match(a, b)));
    if declared_hit {
        points += Kind::DeclaredName.weight();
        reasons.push(Kind::DeclaredName.name());
    }
    if exact {
        // The same id as before (its MAC or `ip:ADDRESS`) is the same device, as it always was.
        return Some((1000, vec!["same-id"]));
    }
    (points > 0).then_some((points, reasons))
}

/// Matches every device against the registry, one record per device at most. A device that
/// reaches [`MATCH_THRESHOLD`] against no record keeps its own id as a new key (with `#2`, `#3`
/// ... appended when that key is taken by another device).
pub fn resolve(registry: &Registry, devices: &[Device]) -> Vec<Match> {
    let by_value: Vec<BTreeMap<Kind, BTreeSet<&str>>> = devices
        .iter()
        .map(|d| {
            let mut m: BTreeMap<Kind, BTreeSet<&str>> = BTreeMap::new();
            for i in &d.identifiers {
                m.entry(i.kind).or_default().insert(i.value.as_str());
            }
            m
        })
        .collect();
    // Which records share an identifier with a device, so only those are scored.
    let mut index: HashMap<(Kind, &str), Vec<usize>> = HashMap::new();
    let mut by_key: HashMap<&str, usize> = HashMap::new();
    for (n, r) in registry.records.iter().enumerate() {
        by_key.insert(r.key.as_str(), n);
        for (kind, set) in &r.identifiers {
            for v in set {
                index.entry((*kind, v.as_str())).or_default().push(n);
            }
        }
    }
    // Records by the first label of their host names (scanned and declared), for declared names.
    let mut by_name: HashMap<&str, Vec<usize>> = HashMap::new();
    for (n, r) in registry.records.iter().enumerate() {
        for kind in [Kind::Hostname, Kind::DeclaredName] {
            for v in r.identifiers.get(&kind).into_iter().flatten() {
                by_name.entry(first_label(v)).or_default().push(n);
            }
        }
    }
    let mut pairs: Vec<(u32, usize, usize, Vec<&'static str>)> = vec![];
    for (d, device) in devices.iter().enumerate() {
        let mut candidates: BTreeSet<usize> = by_key
            .get(device.id.as_str())
            .copied()
            .into_iter()
            .collect();
        for (kind, set) in &by_value[d] {
            for v in set {
                candidates.extend(index.get(&(*kind, *v)).into_iter().flatten().copied());
            }
        }
        for kind in [Kind::Hostname, Kind::DeclaredName] {
            for v in by_value[d].get(&kind).into_iter().flatten() {
                candidates.extend(by_name.get(first_label(v)).into_iter().flatten().copied());
            }
        }
        for r in candidates {
            if let Some((points, reasons)) = score(device, &by_value[d], &registry.records[r])
                && points >= MATCH_THRESHOLD
            {
                pairs.push((points, d, r, reasons));
            }
        }
    }
    // Best pairs first; a record or a device is used once.
    pairs.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| registry.records[a.2].key.cmp(&registry.records[b.2].key))
            .then(a.1.cmp(&b.1))
    });
    let mut out: Vec<Option<Match>> = vec![None; devices.len()];
    let mut used: HashSet<usize> = HashSet::new();
    let mut taken: HashSet<String> = HashSet::new();
    for (points, d, r, reasons) in pairs {
        if out[d].is_some() || used.contains(&r) {
            continue;
        }
        used.insert(r);
        let key = registry.records[r].key.clone();
        taken.insert(key.clone());
        out[d] = Some(Match {
            key,
            new: false,
            score: points,
            reasons: reasons.into_iter().map(str::to_string).collect(),
        });
    }
    let mut result = vec![];
    for (d, device) in devices.iter().enumerate() {
        result.push(out[d].take().unwrap_or_else(|| {
            let mut key = device.id.clone();
            let mut n = 2;
            while registry.contains_key(&key) || taken.contains(&key) {
                key = format!("{}#{n}", device.id);
                n += 1;
            }
            taken.insert(key.clone());
            Match {
                key,
                new: true,
                score: 0,
                reasons: vec![],
            }
        }));
    }
    result
}

/// Device id -> stable key, for code that works with `Device::id`.
pub fn key_map(devices: &[Device], matches: &[Match]) -> HashMap<String, String> {
    devices
        .iter()
        .zip(matches)
        .map(|(d, m)| (d.id.clone(), m.key.clone()))
        .collect()
}

/// Seeds a registry from the keys of a database written before identifiers were recorded
/// (`known_devices`): a MAC-shaped key becomes a MAC identifier, `ip:ADDRESS` an IP identifier.
pub fn identifier_of_legacy_key(key: &str) -> Option<Identifier> {
    if let Some(ip) = key.strip_prefix("ip:") {
        return Identifier::new(Kind::Ip, ip);
    }
    let hex: String = key.chars().filter(char::is_ascii_hexdigit).collect();
    let separators_only = key.chars().all(|c| c.is_ascii_hexdigit() || c == ':');
    if hex.len() == 12 && separators_only {
        let kind = if mac_is_stable(key) {
            Kind::Mac
        } else {
            Kind::RandomMac
        };
        return Identifier::new(kind, key.to_ascii_uppercase());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{devices, passive::Observation, scan::Host};
    use std::collections::BTreeMap;

    fn host(ip: &str, mac: &str, name: &str, identity: &[(&str, &str)]) -> Host {
        Host {
            ip: ip.parse().unwrap(),
            responding: true,
            ping: None,
            ttl: Some(64),
            hostname: name.into(),
            mac: mac.into(),
            open: vec![22, 443],
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
    fn devices_of(hosts: &[Host]) -> Vec<Device> {
        devices::merge(hosts, &[])
    }
    const STRONG: &[(&str, &str)] = &[
        ("ssh.22.hostkey_sha256", "AAAA11"),
        ("tls.443.spki_sha256", "BBBB22"),
    ];

    #[test]
    fn randomised_macs_are_detected_and_are_not_a_stable_identifier() {
        for (mac, stable) in [
            ("00:00:0C:12:34:56", true),
            ("02:00:00:00:00:01", false),
            ("DA-A1-19-00-00-00", false),
            // Hypervisor NICs are locally administered but assigned once.
            ("52:54:00:12:34:56", true),
        ] {
            assert_eq!(mac_is_stable(mac), stable, "{mac}");
        }
        let d = &devices_of(&[host("10.0.0.5", "02:00:00:00:00:01", "", &[])])[0];
        assert!(d.randomized_mac);
        assert!(
            d.identifiers
                .iter()
                .any(|i| i.kind == Kind::RandomMac && i.value == "02:00:00:00:00:01")
        );
        assert!(!d.identifiers.iter().any(|i| i.kind == Kind::Mac));
    }

    #[test]
    fn a_device_with_a_new_ip_and_a_new_random_mac_keeps_its_key() {
        let mut registry = Registry::new();
        let before = devices_of(&[host("10.0.0.5", "02:00:00:00:00:01", "tablet", STRONG)]);
        let m = resolve(&registry, &before);
        assert!(m[0].new);
        assert_eq!(m[0].key, "02:00:00:00:00:01");
        registry.learn(&m[0].key, &before[0]);
        // Same device a week later: another address, another random MAC.
        let after = devices_of(&[host("10.0.0.77", "06:11:22:33:44:55", "tablet", STRONG)]);
        let m = resolve(&registry, &after);
        assert!(!m[0].new, "{m:?}");
        assert_eq!(m[0].key, "02:00:00:00:00:01");
        assert!(m[0].score >= MATCH_THRESHOLD);
        assert!(m[0].reasons.contains(&"ssh_host_key".to_string()));
        assert!(!m[0].reasons.contains(&"random_mac".to_string()));
    }

    #[test]
    fn a_weak_identifier_shared_by_two_devices_does_not_merge_them() {
        let mut registry = Registry::new();
        let a = devices_of(&[host(
            "10.0.0.5",
            "02:00:00:00:00:01",
            "printer",
            &[
                ("ssh.22.hassh", "h1"),
                ("tls.443.ja4s", "j1"),
                ("tls.443.spki_sha256", "DEFAULTCERT"),
            ],
        )]);
        registry.learn(&resolve(&registry, &a)[0].key, &a[0]);
        // Another device: same default certificate, same SSH/TLS software, same common name.
        let b = devices_of(&[host(
            "10.0.0.9",
            "06:aa:bb:cc:dd:ee",
            "printer",
            &[
                ("ssh.22.hassh", "h1"),
                ("tls.443.ja4s", "j1"),
                ("tls.443.spki_sha256", "DEFAULTCERT"),
            ],
        )]);
        let m = resolve(&registry, &b);
        assert!(
            m[0].new,
            "default TLS key + name + software stack are 80 points: {m:?}"
        );
        assert_ne!(m[0].key, "02:00:00:00:00:01");
        // Each weak identifier alone is clearly below the threshold.
        for k in [
            Kind::ServiceFingerprint,
            Kind::Ip,
            Kind::Hostname,
            Kind::RandomMac,
            Kind::TlsKey,
            Kind::SshHostKey,
            Kind::SmbGuid,
        ] {
            assert!(k.weight() < MATCH_THRESHOLD, "{k:?}");
        }
        // Even a shared SSH host key (a cloned image) does not decide alone.
        let mut registry = Registry::new();
        let a = devices_of(&[host("10.0.0.5", "02:00:00:00:00:01", "", STRONG)]);
        registry.learn("02:00:00:00:00:01", &a[0]);
        let b = devices_of(&[host(
            "10.0.0.6",
            "06:00:00:00:00:02",
            "",
            &[("ssh.22.hostkey_sha256", "AAAA11")],
        )]);
        assert!(resolve(&registry, &b)[0].new);
    }

    #[test]
    fn globally_unique_macs_decide_and_two_different_ones_veto() {
        let mut registry = Registry::new();
        let a = devices_of(&[host("10.0.0.5", "00:00:0C:00:00:01", "a", STRONG)]);
        registry.learn("00:00:0C:00:00:01", &a[0]);
        // Same MAC on a new address with nothing else in common: the same device.
        let b = devices_of(&[host("10.0.0.50", "00:00:0C:00:00:01", "", &[])]);
        let m = resolve(&registry, &b);
        assert_eq!((m[0].new, m[0].key.as_str()), (false, "00:00:0C:00:00:01"));
        // A clone with another real MAC and the very same keys, certificate and name is another
        // device.
        let c = devices_of(&[host("10.0.0.51", "00:00:0C:00:00:02", "a", STRONG)]);
        let m = resolve(&registry, &c);
        assert!(m[0].new, "{m:?}");
        assert_eq!(m[0].key, "00:00:0C:00:00:02");
    }

    #[test]
    fn different_smb_guids_veto_and_a_shared_guid_with_a_name_merges() {
        let guid = |g: &'static str| [("smb.445.guid", g), ("smb.445.netbios_name", "FILESRV")];
        let mut registry = Registry::new();
        let a = devices_of(&[host("10.0.0.5", "06:00:00:00:00:01", "", &guid("g-1"))]);
        registry.learn("06:00:00:00:00:01", &a[0]);
        // GUID (70) + NetBIOS name (30) from a new random MAC and address.
        let same = devices_of(&[host("10.0.0.6", "0a:00:00:00:00:02", "", &guid("G-1"))]);
        let m = resolve(&registry, &same);
        assert_eq!(m[0].key, "06:00:00:00:00:01", "{m:?}");
        // Another GUID with every other identifier equal.
        let other = devices_of(&[host(
            "10.0.0.5",
            "0a:00:00:00:00:03",
            "",
            &[
                ("smb.445.guid", "g-2"),
                ("smb.445.netbios_name", "FILESRV"),
                ("ssh.22.hostkey_sha256", "AAAA11"),
                ("tls.443.spki_sha256", "BBBB22"),
            ],
        )]);
        let mut with_keys = Registry::new();
        let mut rec = a[0].clone();
        rec.identifiers.push(Identifier {
            kind: Kind::SshHostKey,
            value: "aaaa11".into(),
        });
        rec.identifiers.push(Identifier {
            kind: Kind::TlsKey,
            value: "bbbb22".into(),
        });
        with_keys.learn("06:00:00:00:00:01", &rec);
        assert!(resolve(&with_keys, &other)[0].new);
    }

    #[test]
    fn one_record_is_claimed_once_per_scan() {
        let mut registry = Registry::new();
        let a = devices_of(&[host("10.0.0.5", "02:00:00:00:00:01", "tablet", STRONG)]);
        registry.learn("02:00:00:00:00:01", &a[0]);
        // Two devices in one scan report the same strong identifiers (cloned image): the better
        // match (same address as before) gets the key, the other one is new.
        let now = devices_of(&[
            host("10.0.0.5", "06:00:00:00:00:0a", "tablet", STRONG),
            host("10.0.0.6", "06:00:00:00:00:0b", "tablet", STRONG),
        ]);
        let m = resolve(&registry, &now);
        let kept: Vec<_> = m.iter().filter(|m| !m.new).collect();
        assert_eq!(kept.len(), 1, "{m:?}");
        assert_eq!(kept[0].key, "02:00:00:00:00:01");
        let new: Vec<_> = m.iter().filter(|m| m.new).collect();
        assert_eq!(new.len(), 1);
        assert_ne!(new[0].key, kept[0].key);
        // Resolution order does not matter.
        let rev: Vec<Device> = now.iter().rev().cloned().collect();
        let m2 = resolve(&registry, &rev);
        assert_eq!(m2.iter().filter(|m| !m.new).count(), 1);
        let winner = |devs: &[Device], m: &[Match]| {
            devs.iter()
                .zip(m)
                .find(|(_, m)| !m.new)
                .map(|(d, _)| d.id.clone())
        };
        assert_eq!(winner(&now, &m), winner(&rev, &m2));
    }

    #[test]
    fn the_same_id_stays_the_same_device_even_without_any_other_evidence() {
        let mut registry = Registry::new();
        for key in ["02:00:00:00:00:01", "ip:10.0.0.9"] {
            registry.add(
                key,
                identifier_of_legacy_key(key).expect("legacy key is understood"),
            );
        }
        let now = devices_of(&[
            host("10.0.0.5", "02:00:00:00:00:01", "", &[]),
            host("10.0.0.9", "", "", &[]),
        ]);
        let m = resolve(&registry, &now);
        assert!(m.iter().all(|m| !m.new), "{m:?}");
        assert_eq!(m[0].reasons, ["same-id"]);
        // A random MAC that now reports another SMB GUID than the record is not the same device.
        let mut registry = Registry::new();
        let old = devices_of(&[host(
            "10.0.0.5",
            "02:00:00:00:00:01",
            "",
            &[("smb.445.guid", "g-1")],
        )]);
        registry.learn("02:00:00:00:00:01", &old[0]);
        let reused = devices_of(&[host(
            "10.0.0.5",
            "02:00:00:00:00:01",
            "",
            &[("smb.445.guid", "g-2")],
        )]);
        let m = resolve(&registry, &reused);
        assert!(m[0].new);
        assert_eq!(m[0].key, "02:00:00:00:00:01#2");
    }

    #[test]
    fn identifiers_come_from_replies_already_collected() {
        let obs = [Observation {
            protocol: "DHCP".into(),
            mac: "06:00:00:00:00:01".into(),
            ip: Some("10.0.0.7".parse().unwrap()),
            fields: BTreeMap::from([
                ("client_id".into(), "01:AA:BB".into()),
                ("hostname".into(), "Pixel-7.".into()),
            ]),
        }];
        let d = &devices::merge(&[], &obs)[0];
        let has = |kind, value: &str| {
            d.identifiers
                .iter()
                .any(|i| i.kind == kind && i.value == value)
        };
        assert!(has(Kind::DhcpClientId, "01:aa:bb"));
        assert!(has(Kind::Hostname, "pixel-7"));
        assert!(has(Kind::RandomMac, "06:00:00:00:00:01"));
        assert!(has(Kind::Ip, "10.0.0.7"));
        // Names built from the address, localhost, empty and control characters are no identity.
        let ips = ["10.0.0.5".parse().unwrap()];
        assert!(hostname_identifier("host-10-0-0-5.lan", &ips).is_none());
        assert!(hostname_identifier("localhost", &ips).is_none());
        assert!(hostname_identifier("  ", &ips).is_none());
        assert!(hostname_identifier("10.1.1.1", &ips).is_none());
        let long = "x".repeat(1000);
        assert_eq!(
            hostname_identifier(&long, &ips).unwrap().value.len(),
            MAX_VALUE_LEN
        );
        // HASSH alone is not an identifier; HASSH with JA4S is a weak one.
        let only_hassh = devices_of(&[host("10.0.0.5", "", "", &[("ssh.22.hassh", "x")])]);
        assert!(
            !only_hassh[0]
                .identifiers
                .iter()
                .any(|i| i.kind == Kind::ServiceFingerprint)
        );
    }

    fn declared(id: &str, names: &[&str]) -> Device {
        Device {
            id: id.into(),
            hostnames: names.iter().map(|n| n.to_string()).collect(),
            identifiers: names
                .iter()
                .map(|n| Identifier {
                    kind: Kind::DeclaredName,
                    value: n.to_string(),
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn a_declared_name_decides_alone_but_only_for_the_same_name() {
        let mut registry = Registry::new();
        let list = declared("name:pc-01", &["pc-01.corp.local", "pc-01"]);
        registry.learn("name:pc-01", &list);
        let scanned = |name: &str| devices_of(&[host("10.0.0.20", "06:11:22:33:44:55", name, &[])]);
        // The first label of a scanned name matches the declared name, in any case or form.
        for name in ["PC-01", "pc-01.corp.local", "pc-01.other.example"] {
            let m = resolve(&registry, &scanned(name));
            assert_eq!(
                (m[0].new, m[0].key.as_str()),
                (false, "name:pc-01"),
                "{name}"
            );
            assert_eq!(m[0].reasons, ["declared_name"]);
        }
        // Another name, a name that only starts the same, or no name: not the device.
        for name in ["pc-02", "pc-011", "xpc-01", ""] {
            assert!(resolve(&registry, &scanned(name))[0].new, "{name}");
        }
        // Two fully qualified names must be equal (the list here has no bare name).
        let mut fqdn_only = Registry::new();
        fqdn_only.learn("name:x", &declared("name:x", &["pc-01.corp.local"]));
        let other = devices_of(&[host(
            "10.0.0.20",
            "06:11:22:33:44:55",
            "pc-01.other.example",
            &[],
        )]);
        assert!(resolve(&fqdn_only, &other)[0].new);
        let same = devices_of(&[host(
            "10.0.0.20",
            "06:11:22:33:44:55",
            "pc-01.corp.local",
            &[],
        )]);
        assert!(!resolve(&fqdn_only, &same)[0].new);
        // A declared name is vetoed like any other match: this host has another SMB GUID than
        // the one the list's device was last seen with.
        let mut seen = devices_of(&[host(
            "10.0.0.20",
            "06:11:22:33:44:55",
            "pc-01",
            &[("smb.445.guid", "g-1")],
        )]);
        let mut registry = Registry::new();
        registry.learn("06:11:22:33:44:55", &seen[0]);
        registry.learn("name:pc-01", &list);
        // The scanned device keeps its own (exact) key, not the list's.
        let m = resolve(&registry, &seen);
        assert_eq!(m[0].key, "06:11:22:33:44:55");
        // A declared device that was matched to a scanned one with another GUID is refused.
        seen[0].identifiers.retain(|i| i.kind != Kind::SmbGuid);
        let imposter = devices_of(&[host(
            "10.0.0.21",
            "06:99:99:99:99:99",
            "pc-01",
            &[("smb.445.guid", "g-2")],
        )]);
        let mut registry = Registry::new();
        let mut rec = declared("name:pc-01", &["pc-01"]);
        rec.identifiers.push(Identifier {
            kind: Kind::SmbGuid,
            value: "g-1".into(),
        });
        registry.learn("name:pc-01", &rec);
        assert!(resolve(&registry, &imposter)[0].new);
    }

    #[test]
    fn legacy_keys_are_understood_and_others_ignored() {
        let id = identifier_of_legacy_key("00:00:0C:00:00:01").unwrap();
        assert_eq!(
            (id.kind, id.value.as_str()),
            (Kind::Mac, "00:00:0C:00:00:01")
        );
        assert_eq!(
            identifier_of_legacy_key("02:00:00:00:00:01").unwrap().kind,
            Kind::RandomMac
        );
        let id = identifier_of_legacy_key("ip:10.0.0.9").unwrap();
        assert_eq!((id.kind, id.value.as_str()), (Kind::Ip, "10.0.0.9"));
        assert!(identifier_of_legacy_key("something else").is_none());
        for k in Kind::ALL {
            assert_eq!(Kind::parse(k.name()), Some(k));
        }
        assert_eq!(Kind::parse("nope"), None);
    }
}
