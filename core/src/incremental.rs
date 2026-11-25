//! Fast repeat scans (ROADMAP B14): `scan --incremental` and `monitor --incremental`.
//!
//! A repeat scan of the same targets does not have to look at everything again. With the previous
//! complete scan as the base ([`Previous`]), a host is checked like this:
//!
//! - **Ports:** the ports that were open last time are probed again, plus a *sample* of the rest:
//!   the likeliest ports first, and a rotating slice of the others, so every port is reached after
//!   a few scans ([`ports_for`]). A host that was silent last time gets the sample only; that is
//!   where most of the time of a sparse network goes.
//! - **Services:** an open port whose greeting banner (or, for web servers, status line, `Server`
//!   header and title) hashes the same as last time keeps its previous identification; only a
//!   changed or new one is identified again. The hash is stored with the host as `incr.fp.PORT`.
//! - **UDP and traceroute:** carried over from the previous scan for a host that answered then.
//! - **Everything else** (ping, ARP, OT identification, DNS, OS and device guess) runs as usual.
//!
//! Nothing carried over is ever presented as checked again. A host that was not probed on every
//! requested port has `ports_checked = false`, with the ports it did probe in `incr.rechecked`;
//! what was copied from the base scan is listed in `incr.carried`, and `incr.base` names the base
//! scan. Diff and monitor use [`checked`] to compare exactly the ports both scans looked at, so a
//! known port that closes, or a sampled port that opens, is still reported, and nothing else is.
//! These keys live in the host's `identity` map (no new field, so nothing that builds a host
//! changes); [`is_marker`] tells the comparisons to leave them out.
//!
//! The trade is stated plainly in the documentation: an incremental scan can miss a new service on
//! a port outside the sample until the rotation reaches it, so a full scan now and then is the
//! rule (`monitor --full-every N`).
use crate::scan::{Host, Settings};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

/// Prefix of the identity keys this module writes.
pub const PREFIX: &str = "incr.";
/// The ports of the sample taken in the order of likelihood.
pub const LIKELY: usize = 8;
/// The ports of the rotating part of the sample.
pub const ROTATE: usize = 8;

/// The scan a repeat scan is based on.
#[derive(Debug)]
pub struct Previous {
    /// Id of the base scan in the inventory.
    pub id: i64,
    hosts: HashMap<IpAddr, Host>,
}

impl Previous {
    pub fn new(id: i64, hosts: Vec<Host>) -> Self {
        Self {
            id,
            hosts: hosts.into_iter().map(|h| (h.ip, h)).collect(),
        }
    }
    pub fn host(&self, ip: IpAddr) -> Option<&Host> {
        self.hosts.get(&ip)
    }
    pub fn len(&self) -> usize {
        self.hosts.len()
    }
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }
}

/// True for the identity keys of this module (`incr.base`, `incr.rechecked`, `incr.carried`,
/// `incr.fp.PORT`): bookkeeping about this scan, not facts about the host.
pub fn is_marker(key: &str) -> bool {
    key.starts_with(PREFIX)
}

/// The newest complete scan of exactly these targets in the inventory as the base of a repeat scan.
/// `Ok(Err(reason))` when there is none or it cannot be the base (other settings): the caller runs
/// a full scan and says why.
pub fn load_base(
    db: &std::path::Path,
    targets: &str,
    settings: &Settings,
) -> Result<Result<std::sync::Arc<Previous>, String>, String> {
    Ok(
        match crate::store::latest_complete(db, targets, i64::MAX)? {
            Some((id, _, snapshot)) => {
                base_of(Some((id, &snapshot.settings, snapshot.hosts)), settings)
            }
            None => base_of(None, settings),
        },
    )
}

/// [`load_base`] for a caller that has the newest complete scan of the targets at hand (a
/// monitor keeps it from cycle to cycle): its id, settings and hosts, `None` when there is none.
pub fn base_of(
    newest: Option<(i64, &Settings, Vec<Host>)>,
    settings: &Settings,
) -> Result<std::sync::Arc<Previous>, String> {
    let Some((id, used, hosts)) = newest else {
        return Err("no earlier complete scan of these targets".into());
    };
    compatible(used, settings)?;
    Ok(std::sync::Arc::new(Previous::new(id, hosts)))
}

/// The ports an incremental scan probed on this host, when it did not probe them all.
pub fn rechecked(h: &Host) -> Option<BTreeSet<u16>> {
    let list = h.identity.get("incr.rechecked")?;
    Some(list.split(',').filter_map(|p| p.parse().ok()).collect())
}

/// Whether this scan looked at `port` of the host: every port when the host was fully checked,
/// else only the ports it recorded as rechecked.
pub fn checked(h: &Host, port: u16) -> bool {
    h.ports_checked || rechecked(h).is_some_and(|r| r.contains(&port))
}

/// Whether the base scan can serve as the base of a scan with these settings: the settings that
/// decide which ports and identity keys a scan can report must match, or the comparison would
/// flood the diff with changes that are only different settings.
pub fn compatible(base: &Settings, now: &Settings) -> Result<(), String> {
    let differing = crate::store::incompatible_settings(base, now);
    if differing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "the previous scan used other settings (differs: {})",
            differing.join(", ")
        ))
    }
}

/// The ports to probe on one host: the ports it had open (that are still requested), the
/// [`LIKELY`] likeliest of the others and a rotating slice of [`ROTATE`] more, taken from the
/// others in port order at an offset that moves by one slice per base scan (`generation`).
/// A scan with so few ports that the sample would be everything probes them all.
pub fn ports_for(previous: Option<&Host>, requested: &[u16], generation: i64) -> Vec<u16> {
    if requested.len() <= LIKELY + ROTATE {
        return requested.to_vec();
    }
    let known: BTreeSet<u16> = previous
        .filter(|h| h.responding)
        .map(|h| {
            h.open
                .iter()
                .copied()
                .filter(|p| requested.contains(p))
                .collect()
        })
        .unwrap_or_default();
    let mut rest: Vec<u16> = requested
        .iter()
        .copied()
        .filter(|p| !known.contains(p))
        .collect();
    rest.sort_unstable();
    rest.dedup();
    let mut by_likelihood = rest.clone();
    by_likelihood.sort_by_key(|&p| (crate::portorder::frequency_rank(p), p));
    let mut chosen: BTreeSet<u16> = known;
    chosen.extend(by_likelihood.iter().take(LIKELY));
    let others: Vec<u16> = rest
        .iter()
        .copied()
        .filter(|p| !chosen.contains(p))
        .collect();
    if !others.is_empty() {
        let start = (generation.unsigned_abs() as usize).wrapping_mul(ROTATE) % others.len();
        chosen.extend(
            others
                .iter()
                .cycle()
                .skip(start)
                .take(ROTATE.min(others.len())),
        );
    }
    chosen.into_iter().collect()
}

/// The identity entries that belong to one TCP port: `svc.80`, `svc.80.product`, `http.80.server`,
/// `tls.443.subject`, ... (the port is the second dot-separated segment).
pub fn port_entries(identity: &BTreeMap<String, String>, port: u16) -> Vec<(String, String)> {
    let wanted = port.to_string();
    identity
        .iter()
        .filter(|(k, _)| !is_marker(k) && k.split('.').nth(1) == Some(wanted.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// The 64-bit FNV-1a hash of some bytes as 16 hex digits: a change detector, not a security
/// property.
pub fn hash(data: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// Writes the bookkeeping keys of an incremental host: the base scan, the probed ports (when not
/// all of them were) and what was carried over.
pub fn mark(h: &mut Host, base: i64, probed: Option<&[u16]>, carried: &[String]) {
    h.identity
        .insert("incr.base".into(), format!("scan #{base}"));
    if let Some(ports) = probed {
        h.ports_checked = false;
        h.identity.insert(
            "incr.rechecked".into(),
            ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    if !carried.is_empty() {
        h.identity.insert("incr.carried".into(), carried.join(";"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(open: &[u16], responding: bool) -> Host {
        Host {
            ip: "10.0.0.1".parse().unwrap(),
            responding,
            ping: None,
            ttl: None,
            hostname: String::new(),
            mac: String::new(),
            open: open.to_vec(),
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity: BTreeMap::new(),
            udp_open: vec![],
            trace: vec![],
        }
    }

    #[test]
    fn known_open_ports_are_always_probed_and_the_sample_is_small() {
        let requested: Vec<u16> = (1..=1000).collect();
        let prev = host(&[22, 443, 888], true);
        let got = ports_for(Some(&prev), &requested, 1);
        for p in [22, 443, 888] {
            assert!(got.contains(&p), "{p}");
        }
        assert_eq!(got.len(), 3 + LIKELY + ROTATE);
        // The likeliest ports of the rest are in it (80, 23, 21, 25, ...).
        for p in [80, 23, 21] {
            assert!(got.contains(&p), "{p}");
        }
        // A host that was silent gets the sample only.
        assert_eq!(
            ports_for(Some(&host(&[], false)), &requested, 1).len(),
            LIKELY + ROTATE
        );
        assert_eq!(ports_for(None, &requested, 1).len(), LIKELY + ROTATE);
        // A port that is no longer requested is not probed.
        assert!(!ports_for(Some(&host(&[5555], true)), &[80, 443], 1).contains(&5555));
    }

    #[test]
    fn the_rotation_reaches_every_port_after_a_few_scans() {
        let requested: Vec<u16> = (1..=200).collect();
        let mut seen = BTreeSet::new();
        for generation in 1..=40 {
            seen.extend(ports_for(None, &requested, generation));
        }
        assert_eq!(seen.len(), requested.len());
        // The same base scan always gives the same sample.
        assert_eq!(
            ports_for(None, &requested, 7),
            ports_for(None, &requested, 7)
        );
        assert_ne!(
            ports_for(None, &requested, 7),
            ports_for(None, &requested, 8)
        );
    }

    #[test]
    fn a_short_port_list_is_probed_completely() {
        let requested = vec![22, 80, 443, 502];
        assert_eq!(ports_for(None, &requested, 3), requested);
    }

    #[test]
    fn marks_say_what_was_probed_and_what_was_carried_and_never_claim_a_full_check() {
        let mut h = host(&[22], true);
        assert!(
            checked(&h, 12345),
            "a fully checked host checked every port"
        );
        mark(&mut h, 4, Some(&[22, 80]), &["svc:22".into(), "udp".into()]);
        assert!(!h.ports_checked);
        assert!(checked(&h, 22) && checked(&h, 80));
        assert!(!checked(&h, 12345));
        assert_eq!(h.identity["incr.base"], "scan #4");
        assert_eq!(h.identity["incr.carried"], "svc:22;udp");
        assert_eq!(rechecked(&h).unwrap().len(), 2);
        assert!(is_marker("incr.fp.22") && !is_marker("svc.22"));
    }

    #[test]
    fn the_entries_of_one_port_are_found_by_their_second_segment() {
        let id: BTreeMap<String, String> = [
            ("svc.22", "ssh"),
            ("svc.22.product", "OpenSSH"),
            ("svc.2222", "x"),
            ("tls.22.subject", "y"),
            ("http.80.server", "z"),
            ("incr.fp.22", "abc"),
            ("mac.vendor", "v"),
        ]
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .into();
        let keys: Vec<String> = port_entries(&id, 22).into_iter().map(|(k, _)| k).collect();
        assert_eq!(keys, ["svc.22", "svc.22.product", "tls.22.subject"]);
    }

    #[test]
    fn the_hash_detects_a_changed_banner() {
        assert_eq!(
            hash(b"SSH-2.0-OpenSSH_8.4\r\n"),
            hash(b"SSH-2.0-OpenSSH_8.4\r\n")
        );
        assert_ne!(
            hash(b"SSH-2.0-OpenSSH_8.4\r\n"),
            hash(b"SSH-2.0-OpenSSH_9.6\r\n")
        );
        assert_eq!(hash(b"").len(), 16);
    }

    #[test]
    fn other_settings_cannot_be_the_base() {
        let a = Settings::default();
        assert!(compatible(&a, &a.clone()).is_ok());
        let b = Settings {
            services: true,
            ..Settings::default()
        };
        assert!(
            compatible(&a, &b)
                .unwrap_err()
                .contains("service detection")
        );
    }
}
