// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Check network segmentation against a declared zone and conduit model (ROADMAP L71).
//!
//! IEC 62443 divides a plant into *zones* (groups of assets with the same security needs) joined
//! by *conduits* (the only paths allowed between zones). This module reads such a model from a
//! small JSON file, takes an existing scan, and lists every path from the scan's vantage zone that
//! the model does not allow: a host in another zone that answers although no conduit leads there,
//! an open port the conduit does not permit, a reachable host that belongs to no zone.
//!
//! It **sends nothing**: it reads a stored scan. Run the scan from a host inside the zone you want
//! to test (scan the other zones' ranges), then check it with `--from` naming that zone. A scan is
//! a single vantage point; it cannot see paths the scanner is not on, and it only knows the ports
//! it probed. A port that did not answer proves nothing about the conduit.
//!
//! # The file
//!
//! ```json
//! {
//!   "zones": {
//!     "enterprise": ["10.0.0.0/24"],
//!     "dmz": ["10.0.1.0/24"],
//!     "control": ["10.0.2.0/24", "fd00:2::/64"]
//!   },
//!   "conduits": [
//!     { "from": "enterprise", "to": "dmz", "ports": ["tcp/443"] },
//!     { "from": "dmz", "to": "control", "ports": ["tcp/44818", "tcp/502"] }
//!   ]
//! }
//! ```
//!
//! A conduit lets the `from` zone start connections to the listed ports of the `to` zone (it is
//! one direction; declare the reverse separately). A port is `tcp/443`, `udp/161`, a range
//! `tcp/8000-8100`, a bare `443` (TCP), `tcp/any`, `udp/any`, `icmp` (the host answers probes) or
//! `any`. Traffic inside one zone is not constrained by this check. A host that matches several
//! zones belongs to the one with the longest matching prefix.
use crate::{risk::Severity, store::Snapshot};
use serde::Serialize;
use serde_json::Value;
use std::{collections::BTreeMap, net::IpAddr};

/// Largest zones file accepted.
pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_ZONES: usize = 1_000;
const MAX_CIDRS: usize = 100_000;
const MAX_CONDUITS: usize = 100_000;
const MAX_PORT_SPECS: usize = 1_000;

/// An address range: an address and a prefix length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// `10.0.0.0/24`, `fd00::/64` or a single address (`10.0.0.5` is a /32).
    pub fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim();
        let (addr, prefix) = match text.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (text, None),
        };
        let addr: IpAddr = addr
            .trim()
            .parse()
            .map_err(|_| format!("{text:?} is not an address range"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p
                .trim()
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= max)
                .ok_or_else(|| format!("{text:?}: the prefix length must be 0-{max}"))?,
            None => max,
        };
        Ok(Self { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let bits = |a: IpAddr| -> Option<(u128, u8)> {
            match a {
                IpAddr::V4(v) => Some((u128::from(u32::from(v)), 32)),
                IpAddr::V6(v) => Some((u128::from(v), 128)),
            }
        };
        let (Some((net, width)), Some((host, host_width))) = (bits(self.addr), bits(ip)) else {
            return false;
        };
        if width != host_width {
            return false;
        }
        if self.prefix == 0 {
            return true;
        }
        let shift = u32::from(width - self.prefix);
        (net >> shift) == (host >> shift)
    }
}

/// A port, protocol or "everything" a conduit allows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortSpec {
    Any,
    Icmp,
    /// `tcp`/`udp`, from, to (inclusive); `0..=65535` for `tcp/any`.
    Ports(&'static str, u16, u16),
}

impl PortSpec {
    pub fn parse(text: &str) -> Result<Self, String> {
        let t = text.trim().to_ascii_lowercase();
        if t == "any" || t == "*" {
            return Ok(Self::Any);
        }
        if t == "icmp" {
            return Ok(Self::Icmp);
        }
        let (proto, ports) = match t.split_once('/') {
            Some((p, rest)) => (p.trim(), rest.trim()),
            None => ("tcp", t.as_str()),
        };
        let proto = match proto {
            "tcp" => "tcp",
            "udp" => "udp",
            _ => return Err(format!("{text:?}: the protocol must be tcp, udp or icmp")),
        };
        if ports == "any" || ports == "*" {
            return Ok(Self::Ports(proto, 0, 65535));
        }
        let port = |s: &str| -> Result<u16, String> {
            s.trim()
                .parse::<u16>()
                .ok()
                .filter(|p| *p > 0)
                .ok_or_else(|| format!("{text:?}: {s:?} is not a port (1-65535)"))
        };
        match ports.split_once('-') {
            Some((a, b)) => {
                let (a, b) = (port(a)?, port(b)?);
                if a > b {
                    return Err(format!("{text:?}: the range is backwards"));
                }
                Ok(Self::Ports(proto, a, b))
            }
            None => {
                let p = port(ports)?;
                Ok(Self::Ports(proto, p, p))
            }
        }
    }

    fn allows(&self, protocol: &str, port: Option<u16>) -> bool {
        match self {
            Self::Any => true,
            Self::Icmp => protocol == "icmp",
            Self::Ports(p, lo, hi) => {
                *p == protocol && port.is_some_and(|port| (*lo..=*hi).contains(&port))
            }
        }
    }
}

/// One direction of allowed traffic between two zones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conduit {
    pub from: String,
    pub to: String,
    pub ports: Vec<PortSpec>,
}

/// The declared model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZoneModel {
    zones: BTreeMap<String, Vec<Cidr>>,
    conduits: Vec<Conduit>,
}

impl ZoneModel {
    /// Reads the JSON text of a zones file (see the module documentation). Unknown top-level
    /// members are ignored; everything that is present must be valid.
    pub fn parse(text: &[u8]) -> Result<Self, String> {
        let doc: Value = serde_json::from_slice(text).map_err(|e| format!("not JSON: {e}"))?;
        let zones_doc = doc
            .get("zones")
            .and_then(Value::as_object)
            .ok_or("the file needs a \"zones\" object (zone name to a list of CIDR ranges)")?;
        if zones_doc.is_empty() || zones_doc.len() > MAX_ZONES {
            return Err(format!("declare between 1 and {MAX_ZONES} zones"));
        }
        let mut zones = BTreeMap::new();
        let mut total = 0;
        for (name, list) in zones_doc {
            let name = name.trim();
            if name.is_empty() || name.len() > 80 || name.chars().any(char::is_control) {
                return Err(format!("{name:?} is not a usable zone name"));
            }
            let cidrs: Vec<Cidr> = list
                .as_array()
                .ok_or_else(|| format!("zone {name:?}: expected a list of CIDR ranges"))?
                .iter()
                .map(|c| {
                    c.as_str()
                        .ok_or_else(|| format!("zone {name:?}: a range is not text"))
                        .and_then(|c| Cidr::parse(c).map_err(|e| format!("zone {name:?}: {e}")))
                })
                .collect::<Result<_, _>>()?;
            if cidrs.is_empty() {
                return Err(format!("zone {name:?} has no ranges"));
            }
            total += cidrs.len();
            if total > MAX_CIDRS {
                return Err(format!("more than {MAX_CIDRS} ranges"));
            }
            zones.insert(name.to_string(), cidrs);
        }
        // Two zones with the very same range cannot be told apart.
        let mut seen: BTreeMap<(String, u8), &str> = BTreeMap::new();
        for (name, cidrs) in &zones {
            for c in cidrs {
                let key = (c.addr.to_string(), c.prefix);
                if let Some(other) = seen.insert(key, name)
                    && other != name
                {
                    return Err(format!(
                        "zones {other:?} and {name:?} both declare {}/{}",
                        c.addr, c.prefix
                    ));
                }
            }
        }
        let mut conduits = vec![];
        for (i, c) in doc
            .get("conduits")
            .map(|c| c.as_array().ok_or("\"conduits\" must be a list"))
            .transpose()?
            .into_iter()
            .flatten()
            .enumerate()
        {
            if conduits.len() >= MAX_CONDUITS {
                return Err(format!("more than {MAX_CONDUITS} conduits"));
            }
            let zone = |key: &str| -> Result<String, String> {
                let n = c
                    .get(key)
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("conduit {}: missing \"{key}\"", i + 1))?
                    .trim()
                    .to_string();
                if zones.contains_key(&n) {
                    Ok(n)
                } else {
                    Err(format!(
                        "conduit {}: \"{key}\" names the undeclared zone {n:?}",
                        i + 1
                    ))
                }
            };
            let ports = c
                .get("ports")
                .and_then(Value::as_array)
                .filter(|p| !p.is_empty() && p.len() <= MAX_PORT_SPECS)
                .ok_or_else(|| format!("conduit {}: \"ports\" must be a non-empty list", i + 1))?
                .iter()
                .map(|p| {
                    p.as_str()
                        .ok_or_else(|| format!("conduit {}: a port is not text", i + 1))
                        .and_then(PortSpec::parse)
                })
                .collect::<Result<Vec<_>, _>>()?;
            conduits.push(Conduit {
                from: zone("from")?,
                to: zone("to")?,
                ports,
            });
        }
        Ok(Self { zones, conduits })
    }

    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let size = std::fs::metadata(path)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .len();
        if size > MAX_FILE_BYTES {
            return Err(format!("{}: file is too large", path.display()));
        }
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&bytes).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Whether `name` is a declared zone.
    pub fn has_zone(&self, name: &str) -> bool {
        self.zones.contains_key(name)
    }

    /// The zone an address belongs to: the one with the longest matching prefix.
    pub fn zone_of(&self, ip: IpAddr) -> Option<&str> {
        self.zones
            .iter()
            .flat_map(|(name, cidrs)| cidrs.iter().map(move |c| (name.as_str(), c)))
            .filter(|(_, c)| c.contains(ip))
            .max_by_key(|(_, c)| c.prefix)
            .map(|(name, _)| name)
    }

    fn conduits(&self, from: &str, to: &str) -> Vec<&Conduit> {
        self.conduits
            .iter()
            .filter(|c| c.from == from && c.to == to)
            .collect()
    }
}

/// One path the model does not allow.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Violation {
    /// `no-conduit` (the host answers but no conduit leads to its zone), `port-not-allowed` (a
    /// conduit exists but not for this port) or `unzoned-host` (the host belongs to no zone).
    pub kind: String,
    pub severity: Severity,
    pub from_zone: String,
    /// The destination zone, absent for an unzoned host.
    pub to_zone: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    /// `tcp`, `udp` or `icmp` (the host answered, no port is open or probed).
    pub protocol: String,
    /// The service the scan identified on the port, when it did.
    pub service: String,
    pub message: String,
}

/// What a check found.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Report {
    pub scan_id: Option<i64>,
    pub vantage_zone: String,
    /// Hosts that answered the scan.
    pub hosts_reachable: usize,
    /// Of those, in another zone than the vantage zone.
    pub hosts_in_other_zones: usize,
    /// Reachable hosts in no declared zone.
    pub unzoned_hosts: usize,
    /// Hosts per zone that answered.
    pub reachable_per_zone: BTreeMap<String, usize>,
    pub violations: Vec<Violation>,
    /// What the check cannot say.
    pub notes: Vec<String>,
}

fn service_of(h: &crate::scan::Host, port: u16, udp: bool) -> String {
    let key = if udp {
        format!("udp.{port}")
    } else {
        format!("svc.{port}")
    };
    h.identity
        .get(&key)
        .map(|s| s.chars().take(80).collect())
        .unwrap_or_default()
}

fn ot_port(port: u16) -> bool {
    crate::service::is_ot_port_candidate(port)
}

/// Compares the reachable hosts of `snapshot` with the model, as seen from `vantage`.
pub fn check(
    model: &ZoneModel,
    vantage: &str,
    snapshot: &Snapshot,
    scan_id: Option<i64>,
) -> Result<Report, String> {
    if !model.has_zone(vantage) {
        return Err(format!(
            "{vantage:?} is not a declared zone (declared: {})",
            model.zones.keys().cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    let mut report = Report {
        scan_id,
        vantage_zone: vantage.into(),
        hosts_reachable: 0,
        hosts_in_other_zones: 0,
        unzoned_hosts: 0,
        reachable_per_zone: BTreeMap::new(),
        violations: vec![],
        notes: vec![
            "A scan is one vantage point: paths from other places are not seen.".into(),
            "Only the ports the scan probed can be reported; a port that did not answer proves nothing about the conduit.".into(),
            "Traffic inside one zone is not checked.".into(),
        ],
    };
    if !snapshot.complete {
        report
            .notes
            .push("The scan is partial: hosts it did not reach are missing.".into());
    }
    for h in snapshot.hosts.iter().filter(|h| h.responding) {
        report.hosts_reachable += 1;
        let host = h.ip.to_string();
        let Some(zone) = model.zone_of(h.ip) else {
            report.unzoned_hosts += 1;
            report.violations.push(Violation {
                kind: "unzoned-host".into(),
                severity: Severity::Medium,
                from_zone: vantage.into(),
                to_zone: None,
                host: host.clone(),
                port: None,
                protocol: "icmp".into(),
                service: String::new(),
                message: format!(
                    "{host} is reachable from {vantage} but belongs to no declared zone: add its range to a zone or find out why it is reachable."
                ),
            });
            continue;
        };
        *report
            .reachable_per_zone
            .entry(zone.to_string())
            .or_default() += 1;
        if zone == vantage {
            continue;
        }
        report.hosts_in_other_zones += 1;
        let conduits = model.conduits(vantage, zone);
        let allowed = |protocol: &str, port: Option<u16>| {
            conduits
                .iter()
                .any(|c| c.ports.iter().any(|p| p.allows(protocol, port)))
        };
        let mut open: Vec<(&str, u16)> = h.open.iter().map(|p| ("tcp", *p)).collect();
        open.extend(h.udp_open.iter().map(|p| ("udp", *p)));
        if conduits.is_empty() {
            let ot = open.iter().any(|(_, p)| ot_port(*p));
            let listing = if open.is_empty() {
                "it answers the scan".to_string()
            } else {
                format!(
                    "open: {}",
                    open.iter()
                        .map(|(p, n)| format!("{p}/{n}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            report.violations.push(Violation {
                kind: "no-conduit".into(),
                severity: if ot { Severity::High } else { Severity::Medium },
                from_zone: vantage.into(),
                to_zone: Some(zone.into()),
                host: host.clone(),
                port: None,
                protocol: "icmp".into(),
                service: String::new(),
                message: format!(
                    "{host} in zone {zone} is reachable from {vantage}, but no conduit {vantage} -> {zone} is declared ({listing})."
                ),
            });
            continue;
        }
        // A conduit exists: the host answering at all is allowed only when the conduit lists
        // icmp or any; ports are judged one by one.
        for (protocol, port) in &open {
            if allowed(protocol, Some(*port)) {
                continue;
            }
            let service = service_of(h, *port, *protocol == "udp");
            report.violations.push(Violation {
                kind: "port-not-allowed".into(),
                severity: if ot_port(*port) { Severity::High } else { Severity::Medium },
                from_zone: vantage.into(),
                to_zone: Some(zone.into()),
                host: host.clone(),
                port: Some(*port),
                protocol: (*protocol).into(),
                service: service.clone(),
                message: format!(
                    "{host}:{port}/{protocol}{} in zone {zone} is reachable from {vantage}, but the conduit {vantage} -> {zone} does not allow it.",
                    if service.is_empty() {
                        String::new()
                    } else {
                        format!(" ({service})")
                    }
                ),
            });
        }
    }
    report.violations.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.to_zone.cmp(&b.to_zone))
            .then(a.host.cmp(&b.host))
            .then(a.port.cmp(&b.port))
            .then(a.protocol.cmp(&b.protocol))
    });
    Ok(report)
}

impl Report {
    /// The report as text for the terminal.
    pub fn text(&self) -> String {
        let mut out = vec![format!(
            "Segmentation seen from zone {}: {} hosts answered, {} in other zones, {} in no zone; {} paths break the model.",
            self.vantage_zone,
            self.hosts_reachable,
            self.hosts_in_other_zones,
            self.unzoned_hosts,
            self.violations.len()
        )];
        for v in &self.violations {
            out.push(format!(
                "[{}] {}: {}",
                v.severity.name().to_ascii_uppercase(),
                v.kind,
                v.message
            ));
        }
        if self.violations.is_empty() {
            out.push("Every reachable path from this zone is allowed by a conduit.".into());
        }
        for n in &self.notes {
            out.push(format!("Note: {n}"));
        }
        out.join("\n")
    }
}

#[cfg(test)]
#[path = "segmentation_tests.rs"]
mod tests;
