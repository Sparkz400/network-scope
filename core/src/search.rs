//! Search across all saved scans: "where did 10.0.5.17 last appear?".
//!
//! [`search`] looks for an IP address, a MAC address (or a vendor prefix of one), a host name
//! fragment, a vendor name, a device type or a finding id / CVE id in the newest saved scans and
//! returns where it was seen, newest scan first. The command `search QUERY` and the command
//! palette of the desktop app answer this question. The MCP tool `search_inventory` is the older,
//! narrower form of it (an exact address or MAC, or a host-name fragment, in hosts and passive
//! observations; its output is the `mcp-where-seen` schema) and keeps its own rules, so a client of
//! that tool sees no change. Nothing here sends traffic; it only reads the inventory.
//!
//! What a query is taken for:
//!
//! - a full IP address: that address, exactly;
//! - digits and dots (`10.0.5`): the start of addresses, as text;
//! - a full MAC address in any notation (`00:0c:29:aa:bb:cc`, `000c.29aa.bbcc`): exactly that MAC;
//! - 6 to 11 hex digits written with `:` or `-` (`00:0c:29`): the start of a MAC (a vendor prefix);
//! - anything else: a case-insensitive fragment of a host name, vendor, device type, finding id
//!   or CVE id.
//!
//! Finding ids are only checked in the newest [`FINDING_SCANS`] scans because they need the
//! risk analysis of every scan; addresses and names look at the newest [`SEARCH_SCANS`].
use crate::{
    risk,
    store::{self, Entry, Snapshot},
};
use serde::Serialize;
use std::{net::IpAddr, path::Path};

/// How many of the newest scans are read.
pub const SEARCH_SCANS: usize = 200;
/// How many of the newest scans are also analysed for finding ids.
pub const FINDING_SCANS: usize = 20;
/// Longest query accepted.
pub const MAX_QUERY: usize = 100;

/// What a query looks for (see the module documentation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Needle {
    Ip(IpAddr),
    /// The start of an address as text (`10.0.5`).
    IpPart(String),
    /// A full MAC: 12 upper-case hex digits.
    Mac(String),
    /// The start of a MAC: upper-case hex digits, 6 to 11.
    MacPart(String),
    /// A lower-case fragment of a name, vendor, type, finding id or CVE id.
    Text(String),
}

impl Needle {
    /// `None` for an empty or overlong query.
    pub fn parse(query: &str) -> Option<Self> {
        let q = query.trim();
        if q.is_empty() || q.len() > MAX_QUERY {
            return None;
        }
        if let Ok(ip) = q.parse::<IpAddr>() {
            return Some(Self::Ip(ip));
        }
        if q.len() >= 3 && q.chars().all(|c| c.is_ascii_digit() || c == '.') && q.contains('.') {
            return Some(Self::IpPart(q.to_string()));
        }
        let hex: String = q.chars().filter(char::is_ascii_hexdigit).collect();
        let notation = q
            .chars()
            .all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '-' | '.'));
        if notation {
            if hex.len() == 12 {
                return Some(Self::Mac(hex.to_ascii_uppercase()));
            }
            if (6..12).contains(&hex.len()) && q.contains([':', '-']) {
                return Some(Self::MacPart(hex.to_ascii_uppercase()));
            }
        }
        Some(Self::Text(q.to_lowercase()))
    }

    fn matches_ip(&self, ip: Option<IpAddr>) -> bool {
        match (self, ip) {
            (Self::Ip(wanted), Some(ip)) => *wanted == ip,
            (Self::IpPart(part), Some(ip)) => ip.to_string().starts_with(part.as_str()),
            _ => false,
        }
    }
    fn matches_mac(&self, mac: &str) -> bool {
        let hex: String = mac
            .chars()
            .filter(char::is_ascii_hexdigit)
            .collect::<String>()
            .to_ascii_uppercase();
        match self {
            Self::Mac(wanted) => hex == *wanted,
            Self::MacPart(prefix) => hex.starts_with(prefix.as_str()),
            _ => false,
        }
    }
    fn matches_text(&self, names: &[&str]) -> bool {
        match self {
            Self::Text(part) => names.iter().any(|n| n.to_lowercase().contains(part)),
            _ => false,
        }
    }
    /// Whether the finding ids of the scans can match at all.
    fn wants_findings(&self) -> bool {
        matches!(self, Self::Text(_))
    }
}

/// One place where the query was seen.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Hit {
    pub scan_id: i64,
    /// Unix seconds.
    pub timestamp: i64,
    pub targets: String,
    /// `host` (an active scan result), `observation` (a passive capture) or `finding`.
    pub source: &'static str,
    pub ip: Option<IpAddr>,
    pub mac: String,
    pub hostname: String,
    pub vendor: String,
    /// For a finding its id and title; for a host the open ports; empty otherwise.
    pub detail: String,
}

/// The answer of [`search`].
#[derive(Clone, Debug, Serialize)]
pub struct Results {
    pub query: String,
    pub scans_checked: usize,
    pub scans_total: usize,
    /// More scans or more hits than were returned.
    pub truncated: bool,
    /// Newest scan first.
    pub hits: Vec<Hit>,
    /// The newest hit that shows a device (not a finding): where it last appeared.
    pub last_seen: Option<Hit>,
}

fn vendor_of(identity_vendor: Option<&String>, mac: &str) -> String {
    identity_vendor
        .cloned()
        .or_else(|| crate::oui::vendor(mac).map(str::to_string))
        .unwrap_or_default()
}

/// The hits of one scan. `with_findings` also looks at the finding ids of the scan.
pub fn search_snapshot(
    entry: &Entry,
    snapshot: &Snapshot,
    needle: &Needle,
    with_findings: bool,
) -> Vec<Hit> {
    let mut hits = vec![];
    let make = |source, ip, mac: &str, hostname: &str, vendor: String, detail: String| Hit {
        scan_id: entry.id,
        timestamp: entry.timestamp,
        targets: entry.targets.clone(),
        source,
        ip,
        mac: mac.to_string(),
        hostname: hostname.to_string(),
        vendor,
        detail,
    };
    for h in &snapshot.hosts {
        let vendor = vendor_of(h.identity.get("mac.vendor"), &h.mac);
        let kind = h.identity.get("device.type").map_or("", String::as_str);
        if needle.matches_ip(Some(h.ip))
            || needle.matches_mac(&h.mac)
            || needle.matches_text(&[&h.hostname, &vendor, kind])
        {
            let detail = if h.open.is_empty() {
                String::new()
            } else {
                format!(
                    "open {}",
                    h.open
                        .iter()
                        .take(12)
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            hits.push(make(
                "host",
                Some(h.ip),
                &h.mac,
                &h.hostname,
                vendor,
                detail,
            ));
        }
    }
    for o in &snapshot.observations {
        let names: Vec<&str> = o
            .fields
            .iter()
            .filter(|(k, _)| k.contains("name"))
            .map(|(_, v)| v.as_str())
            .collect();
        let vendor = vendor_of(None, &o.mac);
        let mut text = names.clone();
        text.push(&vendor);
        if needle.matches_ip(o.ip) || needle.matches_mac(&o.mac) || needle.matches_text(&text) {
            hits.push(make(
                "observation",
                o.ip,
                &o.mac,
                names.first().copied().unwrap_or(""),
                vendor,
                o.protocol.clone(),
            ));
        }
    }
    if with_findings && needle.wants_findings() {
        let Needle::Text(part) = needle else {
            return hits;
        };
        for f in risk::analyze_snapshot(snapshot) {
            let cve = f.cve.join(" ");
            if [f.id.as_str(), cve.as_str()]
                .iter()
                .any(|s| s.to_lowercase().contains(part))
            {
                let mac = snapshot
                    .hosts
                    .iter()
                    .find(|h| h.ip == f.ip)
                    .map(|h| h.mac.as_str())
                    .unwrap_or("");
                hits.push(make(
                    "finding",
                    Some(f.ip),
                    mac,
                    "",
                    String::new(),
                    format!("{}: {}", f.id, f.title),
                ));
            }
        }
    }
    hits
}

/// Searches the inventory at `db`. At most `limit` hits (1 to 500) are returned. An empty query
/// is an error; an empty inventory or no match is an empty answer.
pub fn search(db: &Path, query: &str, limit: usize) -> Result<Results, String> {
    let needle = Needle::parse(query).ok_or_else(|| {
        format!(
            "The query must be 1 to {MAX_QUERY} characters (an address, MAC, name or finding id)"
        )
    })?;
    let limit = limit.clamp(1, 500);
    let entries = store::list(db)?;
    let scans_total = entries.len();
    let mut truncated = scans_total > SEARCH_SCANS;
    let mut hits: Vec<Hit> = vec![];
    let mut checked = 0;
    for (n, entry) in entries.iter().take(SEARCH_SCANS).enumerate() {
        let Ok(snapshot) = store::load(db, entry.id) else {
            continue;
        };
        checked += 1;
        hits.extend(search_snapshot(
            entry,
            &snapshot,
            &needle,
            n < FINDING_SCANS,
        ));
        if hits.len() >= limit {
            hits.truncate(limit);
            truncated = true;
            break;
        }
    }
    let last_seen = hits.iter().find(|h| h.source != "finding").cloned();
    Ok(Results {
        query: query.trim().to_string(),
        scans_checked: checked,
        scans_total,
        truncated,
        hits,
        last_seen,
    })
}

/// A readable text of the answer (what `search` prints without `--format json`).
pub fn render(r: &Results) -> String {
    let mut out = String::new();
    if r.hits.is_empty() {
        out.push_str(&format!(
            "\"{}\" was not found in {} of {} saved scans.\n",
            r.query, r.scans_checked, r.scans_total
        ));
        return out;
    }
    if let Some(h) = &r.last_seen {
        out.push_str(&format!(
            "Last seen in scan #{} on {} ({}).\n",
            h.scan_id,
            crate::report::fmt_time(h.timestamp),
            h.targets
        ));
    }
    for h in &r.hits {
        out.push_str(&format!(
            "#{:<4} {}  {:<11} {:<15} {:<17} {}{}\n",
            h.scan_id,
            crate::report::fmt_time(h.timestamp),
            h.source,
            h.ip.map_or(String::new(), |i| i.to_string()),
            h.mac,
            h.hostname,
            if h.detail.is_empty() {
                String::new()
            } else {
                format!("  [{}]", h.detail)
            }
        ));
    }
    if r.truncated {
        out.push_str(&format!(
            "More exists: {} of {} scans read; narrow the query or raise --top.\n",
            r.scans_checked, r.scans_total
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{Host, Settings};

    fn host(ip: &str, mac: &str, name: &str, vendor: &str, ports: Vec<u16>) -> Host {
        let mut identity = std::collections::BTreeMap::new();
        if !vendor.is_empty() {
            identity.insert("mac.vendor".to_string(), vendor.to_string());
        }
        Host {
            ip: ip.parse().unwrap(),
            responding: true,
            ping: None,
            ttl: None,
            hostname: name.into(),
            mac: mac.into(),
            open: ports,
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity,
            udp_open: vec![],
            trace: vec![],
        }
    }
    fn snapshot(hosts: Vec<Host>) -> Snapshot {
        Snapshot {
            sent: vec![],
            targets: "10.0.0.0/16".into(),
            complete: true,
            settings: Settings::default(),
            hosts,
            observations: vec![],
            notes: Default::default(),
        }
    }
    fn entry(id: i64) -> Entry {
        Entry {
            id,
            timestamp: 1_790_000_000 + id * 86_400,
            targets: "10.0.0.0/16".into(),
            complete: true,
            hosts: 1,
        }
    }

    #[test]
    fn the_query_kind_is_recognised() {
        assert!(matches!(Needle::parse("10.0.5.17"), Some(Needle::Ip(_))));
        assert!(matches!(Needle::parse("fe80::1"), Some(Needle::Ip(_))));
        assert!(matches!(Needle::parse("10.0.5"), Some(Needle::IpPart(_))));
        for mac in ["00:0c:29:aa:bb:cc", "00-0C-29-AA-BB-CC", "000c.29aa.bbcc"] {
            assert!(matches!(Needle::parse(mac), Some(Needle::Mac(_))), "{mac}");
        }
        assert!(matches!(
            Needle::parse("00:0c:29"),
            Some(Needle::MacPart(_))
        ));
        // Short hex words and host names stay text.
        assert!(matches!(Needle::parse("cafe"), Some(Needle::Text(_))));
        assert!(matches!(Needle::parse("PLC-1"), Some(Needle::Text(_))));
        assert!(matches!(
            Needle::parse("telnet-open"),
            Some(Needle::Text(_))
        ));
        assert_eq!(Needle::parse("   "), None);
        assert_eq!(Needle::parse(&"x".repeat(MAX_QUERY + 1)), None);
    }

    #[test]
    fn hosts_match_by_address_mac_name_and_vendor() {
        let snap = snapshot(vec![
            host(
                "10.0.5.17",
                "00:0C:29:AA:BB:CC",
                "plc-1.lab",
                "Siemens AG",
                vec![102],
            ),
            host("10.0.5.18", "", "printer", "", vec![]),
        ]);
        let e = entry(1);
        let count = |q: &str| search_snapshot(&e, &snap, &Needle::parse(q).unwrap(), false).len();
        assert_eq!(count("10.0.5.17"), 1);
        assert_eq!(count("10.0.5"), 2, "start of an address");
        assert_eq!(count("10.0.6"), 0);
        assert_eq!(count("10.0.5.1"), 0, "a full address is exact");
        assert_eq!(count("000c.29aa.bbcc"), 1);
        assert_eq!(count("00:0c:29"), 1, "vendor prefix");
        assert_eq!(count("00:0C:29:AA:BB:CD"), 0, "a near miss is no match");
        assert_eq!(count("PLC"), 1);
        assert_eq!(count("siemens"), 1);
        assert_eq!(count("nothing-like-this"), 0);
        let hit = &search_snapshot(&e, &snap, &Needle::parse("plc").unwrap(), false)[0];
        assert_eq!((hit.scan_id, hit.source), (1, "host"));
        assert_eq!(hit.detail, "open 102");
    }

    #[test]
    fn finding_ids_match_only_in_text_queries_and_only_when_asked() {
        let mut telnet = host("10.0.5.17", "", "", "", vec![23]);
        telnet.identity.insert("svc.23".into(), "telnet".into());
        let snap = snapshot(vec![telnet]);
        let e = entry(2);
        let q = Needle::parse("telnet-open").unwrap();
        let with = search_snapshot(&e, &snap, &q, true);
        assert!(
            with.iter()
                .any(|h| h.source == "finding" && h.detail.starts_with("telnet-open")),
            "{with:?}"
        );
        assert!(search_snapshot(&e, &snap, &q, false).is_empty());
        // An address query never runs the analysis.
        let ip = Needle::parse("10.0.5.17").unwrap();
        assert!(
            search_snapshot(&e, &snap, &ip, true)
                .iter()
                .all(|h| h.source == "host")
        );
    }

    #[test]
    fn the_search_reads_the_inventory_newest_scan_first() {
        let dir = std::env::temp_dir().join(format!("ns-search-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("inventory.sqlite");
        let seen = host("10.0.5.17", "00:0C:29:AA:BB:CC", "plc-1", "", vec![502]);
        for (i, hosts) in [vec![seen.clone()], vec![], vec![seen.clone()]]
            .into_iter()
            .enumerate()
        {
            store::save_at(&db, &snapshot(hosts), 1_790_000_000 + i as i64 * 3600).unwrap();
        }
        let r = search(&db, "10.0.5.17", 100).unwrap();
        assert_eq!((r.scans_checked, r.scans_total, r.truncated), (3, 3, false));
        assert_eq!(r.hits.len(), 2);
        assert!(r.hits[0].scan_id > r.hits[1].scan_id, "newest first");
        assert_eq!(r.last_seen.as_ref().unwrap().scan_id, r.hits[0].scan_id);
        let text = render(&r);
        assert!(text.starts_with("Last seen in scan #3"), "{text}");
        let limited = search(&db, "10.0.5.17", 1).unwrap();
        assert_eq!(limited.hits.len(), 1);
        assert!(limited.truncated);
        let none = search(&db, "10.0.9.9", 100).unwrap();
        assert!(none.hits.is_empty() && none.last_seen.is_none());
        assert!(render(&none).contains("was not found in 3 of 3"));
        assert!(search(&db, "", 10).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
