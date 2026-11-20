//! Where a scan result came from (ROADMAP L72): the version of the tool and a SHA-256 of every
//! rules file and feed that shaped it, stamped into the scan (`settings.provenance`, so also in
//! every export), so a finding can be cited and the scan re-run (`scan --replay-check`).
//!
//! What is hashed is the *effective* rule set, not just a file name:
//!
//! | Entry | Content hashed |
//! |---|---|
//! | `rules["probes.json"]` | the service probes in effect: the built-in `data/probes.json` merged with the user file (`--probes FILE`, else the default user file), as canonical text |
//! | `rules["cves.json"]` | the CVE and CPE rules in effect: built-in merged with the user file (`--cves`, else the default), as canonical text |
//! | `rules["compliance.json"]` | the embedded `data/compliance.json` |
//! | `feeds["kev-epss"]` | the imported CISA KEV and EPSS data in use (a hash of the cache's content) |
//! | `feeds["nvd"]` | the imported NVD cache: its import time, source files and the list of CVEs with their ratings (the CPE ranges themselves are not hashed: the cache can be a gigabyte) |
//! | `feeds["csaf"]` | the imported CISA advisories in use (a hash of the cache's content) |
//!
//! A feed that is not in use is absent. `combined` is one SHA-256 over the tool string and all
//! entries: the value to cite. Two scans with equal `combined` ran with the same rules; when it
//! differs, [`Provenance::differences`] says which part changed.
use crate::scan::Settings;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The version and rule hashes of a scan.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// `network-scope 0.5.1`.
    pub tool: String,
    pub rules: BTreeMap<String, String>,
    pub feeds: BTreeMap<String, String>,
    /// SHA-256 over the tool string and every entry above; the value to cite.
    pub combined: String,
}

/// `sha256:<64 hex digits>` of `text`.
pub fn hash(text: &[u8]) -> String {
    format!(
        "sha256:{}",
        crate::fingerprint::hex(&crate::fingerprint::sha256(text))
    )
}

impl Provenance {
    /// The provenance of a scan that runs now with `settings`: the tool, the rules in effect (the
    /// probe file of the settings included) and the feeds in use.
    pub fn current(settings: &Settings) -> Self {
        let mut rules = BTreeMap::new();
        rules.insert(
            "probes.json".to_string(),
            match crate::service::ProbeDb::effective(&settings.probe_file) {
                Ok(db) => db.fingerprint(),
                // An unreadable probe file makes the scan fail anyway; say so instead of hiding it.
                Err(e) => format!("unreadable: {}", hash(e.as_bytes())),
            },
        );
        rules.insert("cves.json".into(), crate::risk::cve_db().fingerprint());
        rules.insert(
            "compliance.json".into(),
            hash(crate::compliance::data_text().as_bytes()),
        );
        let mut feeds = BTreeMap::new();
        let kev = crate::feeds::active();
        if !kev.is_empty() {
            feeds.insert("kev-epss".to_string(), kev.fingerprint());
        }
        let nvd = crate::nvd::active();
        if !nvd.is_empty() {
            feeds.insert("nvd".to_string(), nvd.fingerprint());
        }
        let csaf = crate::csaf::active();
        if !csaf.is_empty() {
            feeds.insert("csaf".to_string(), csaf.fingerprint());
        }
        Self::with(rules, feeds)
    }

    /// A provenance from its parts; `combined` is derived.
    pub fn with(rules: BTreeMap<String, String>, feeds: BTreeMap<String, String>) -> Self {
        let tool = format!("network-scope {}", env!("CARGO_PKG_VERSION"));
        let mut text = format!("{tool}\n");
        for (k, v) in &rules {
            text.push_str(&format!("rules.{k}={v}\n"));
        }
        for (k, v) in &feeds {
            text.push_str(&format!("feeds.{k}={v}\n"));
        }
        Self {
            tool,
            rules,
            feeds,
            combined: hash(text.as_bytes()),
        }
    }

    /// What differs from `other`, one line each (empty when the two are the same).
    pub fn differences(&self, other: &Self) -> Vec<String> {
        let mut out = vec![];
        if self.tool != other.tool {
            out.push(format!("tool: {} -> {}", self.tool, other.tool));
        }
        for (what, a, b) in [
            ("rules", &self.rules, &other.rules),
            ("feeds", &self.feeds, &other.feeds),
        ] {
            for key in a
                .keys()
                .chain(b.keys())
                .collect::<std::collections::BTreeSet<_>>()
            {
                match (a.get(key), b.get(key)) {
                    (Some(x), Some(y)) if x != y => out.push(format!("{what} {key}: changed")),
                    (Some(_), None) => out.push(format!("{what} {key}: no longer in use")),
                    (None, Some(_)) => out.push(format!("{what} {key}: now in use")),
                    _ => {}
                }
            }
        }
        out
    }
}

/// What `scan --replay-check` found: a scan that was run again with the stored settings, compared
/// with the stored result.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ReplayCheck {
    pub original_scan: i64,
    pub replay_scan: i64,
    /// The result is the same and the rules are the same.
    pub reproducible: bool,
    /// Nothing changed between the two results: no host, port, identity or finding.
    pub same_result: bool,
    /// Both scans carry a provenance stamp and the stamps are equal.
    pub same_rules: bool,
    pub original_provenance: Option<Provenance>,
    pub replay_provenance: Option<Provenance>,
    /// What differs between the two stamps, one line each.
    pub rule_differences: Vec<String>,
    /// Packets (kind and detail) that were sent a different number of times.
    pub sent_differences: Vec<String>,
    /// The changes between the results: the diff lines and the new and resolved findings.
    pub changes: Vec<String>,
    /// What the check cannot say.
    pub notes: Vec<String>,
}

fn sent_map(s: &crate::store::Snapshot) -> std::collections::BTreeMap<String, u64> {
    s.sent
        .iter()
        .map(|e| (format!("{}: {}", e.kind.name(), e.detail), e.count))
        .collect()
}

/// Compares a stored scan with the scan that re-ran it.
pub fn replay_check(
    original: &crate::store::Snapshot,
    original_id: i64,
    replay: &crate::store::Snapshot,
    replay_id: i64,
) -> ReplayCheck {
    let mut notes = vec![];
    let (a, b) = (
        original.settings.provenance.clone(),
        replay.settings.provenance.clone(),
    );
    let (same_rules, rule_differences) = match (&a, &b) {
        (Some(x), Some(y)) => {
            let d = x.differences(y);
            (d.is_empty() && x.combined == y.combined, d)
        }
        (None, _) => {
            notes.push(
                "The original scan has no provenance stamp (it was saved before stamps existed, or it is an import): which rules it ran with is not known."
                    .into(),
            );
            (false, vec![])
        }
        (Some(_), None) => (false, vec![]),
    };
    let (same_result, changes) =
        match crate::store::diff_report(original, replay, &crate::store::IgnoreList::new(&[])) {
            Ok(report) => {
                let same = report.changes.is_empty()
                    && report.new_findings.is_empty()
                    && report.resolved_findings.is_empty();
                (
                    same,
                    if same {
                        vec![]
                    } else {
                        report.text().lines().map(str::to_string).collect()
                    },
                )
            }
            Err(e) => {
                notes.push(format!("The results could not be compared: {e}"));
                (false, vec![])
            }
        };
    let (before, after) = (sent_map(original), sent_map(replay));
    let mut sent_differences = vec![];
    for key in before
        .keys()
        .chain(after.keys())
        .collect::<std::collections::BTreeSet<_>>()
    {
        let (x, y) = (
            before.get(key).copied().unwrap_or(0),
            after.get(key).copied().unwrap_or(0),
        );
        if x != y {
            sent_differences.push(format!("{key}: {x} -> {y}"));
        }
    }
    notes.push(
        "A difference in the result can be a real change in the network since the original scan, a changed rule or feed (see the rule differences), or timing: a host that answers slowly, packet loss, a rate limit."
            .into(),
    );
    ReplayCheck {
        original_scan: original_id,
        replay_scan: replay_id,
        reproducible: same_result && same_rules,
        same_result,
        same_rules,
        original_provenance: a,
        replay_provenance: b,
        rule_differences,
        sent_differences,
        changes,
        notes,
    }
}

impl ReplayCheck {
    /// The result as text for the terminal.
    pub fn text(&self) -> String {
        let mut out = vec![format!(
            "Scan #{} re-run as scan #{}: {}",
            self.original_scan,
            self.replay_scan,
            if self.reproducible {
                "reproduced (same result, same rules)"
            } else {
                "NOT reproduced"
            }
        )];
        out.push(format!(
            "  result: {}",
            if self.same_result {
                "identical"
            } else {
                "different"
            }
        ));
        out.push(format!(
            "  rules:  {}",
            if self.same_rules {
                "identical"
            } else {
                "different or unknown"
            }
        ));
        for l in &self.rule_differences {
            out.push(format!("    {l}"));
        }
        for l in &self.changes {
            out.push(format!("    change: {l}"));
        }
        for l in &self.sent_differences {
            out.push(format!("    sent: {l}"));
        }
        if let Some(p) = &self.original_provenance {
            out.push(format!("  original: {} {}", p.tool, p.combined));
        }
        if let Some(p) = &self.replay_provenance {
            out.push(format!("  replay:   {} {}", p.tool, p.combined));
        }
        for n in &self.notes {
            out.push(format!("Note: {n}"));
        }
        out.join("\n")
    }
}

/// `settings` with the provenance of a scan that runs now.
pub fn stamped(settings: &Settings) -> Settings {
    Settings {
        provenance: Some(Provenance::current(settings)),
        ..settings.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_provenance_names_the_tool_and_the_rules_in_effect() {
        let p = Provenance::current(&Settings::default());
        assert_eq!(
            p.tool,
            format!("network-scope {}", env!("CARGO_PKG_VERSION"))
        );
        for key in ["probes.json", "cves.json", "compliance.json"] {
            let h = &p.rules[key];
            assert!(h.starts_with("sha256:") && h.len() == 7 + 64, "{key}: {h}");
        }
        assert!(p.feeds.is_empty(), "no feeds are imported in tests");
        assert_eq!(p.combined.len(), 7 + 64);
        // deterministic
        assert_eq!(p, Provenance::current(&Settings::default()));
        // the settings only matter through the probe file: same rules, same provenance
        let other = Settings {
            ports: "1-1000".into(),
            ..Settings::default()
        };
        assert_eq!(Provenance::current(&other), p);
    }

    #[test]
    fn a_changed_rule_a_feed_or_the_tool_changes_the_combined_hash() {
        let base = Provenance::current(&Settings::default());
        let mut rules = base.rules.clone();
        rules.insert("probes.json".into(), hash(b"another probe file"));
        let changed = Provenance::with(rules, base.feeds.clone());
        assert_ne!(changed.combined, base.combined);
        assert_eq!(base.differences(&changed), ["rules probes.json: changed"]);
        let mut feeds = BTreeMap::new();
        feeds.insert("nvd".to_string(), hash(b"x"));
        let with_feed = Provenance::with(base.rules.clone(), feeds);
        assert_ne!(with_feed.combined, base.combined);
        assert_eq!(base.differences(&with_feed), ["feeds nvd: now in use"]);
        assert_eq!(
            with_feed.differences(&base),
            ["feeds nvd: no longer in use"]
        );
        let mut older = base.clone();
        older.tool = "network-scope 0.0.1".into();
        let lines = older.differences(&base);
        assert!(
            lines[0].starts_with("tool: network-scope 0.0.1 ->"),
            "{lines:?}"
        );
        assert!(base.differences(&base).is_empty());
    }

    #[test]
    fn a_user_probe_file_changes_the_probes_hash() {
        let dir = std::env::temp_dir().join(format!("ns-prov-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("probes.json");
        std::fs::write(
            &file,
            r#"{"probes":[{"name":"banner","rules":[{"re":"^X","service":"x"}]}]}"#,
        )
        .unwrap();
        let with = |f: &std::path::Path| {
            Provenance::current(&Settings {
                probe_file: f.display().to_string(),
                ..Settings::default()
            })
        };
        let a = with(&file);
        assert_ne!(
            a.rules["probes.json"],
            Provenance::current(&Settings::default()).rules["probes.json"]
        );
        std::fs::write(
            &file,
            r#"{"probes":[{"name":"banner","rules":[{"re":"^Y","service":"x"}]}]}"#,
        )
        .unwrap();
        assert_ne!(a.rules["probes.json"], with(&file).rules["probes.json"]);
        // a missing file is said, not hidden
        let missing = with(&dir.join("none.json"));
        assert!(missing.rules["probes.json"].starts_with("unreadable:"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn scan_with(provenance: Option<Provenance>, ports: &[u16]) -> crate::store::Snapshot {
        let host = crate::scan::Host {
            ip: "10.0.0.5".parse().unwrap(),
            responding: true,
            ping: None,
            ttl: None,
            hostname: String::new(),
            mac: String::new(),
            open: ports.to_vec(),
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity: Default::default(),
            udp_open: vec![],
            trace: vec![],
        };
        crate::store::Snapshot {
            targets: "10.0.0.5".into(),
            complete: true,
            settings: Settings {
                provenance,
                ..Settings::default()
            },
            hosts: vec![host],
            observations: vec![],
            notes: Default::default(),
            sent: vec![crate::sendlog::SentEntry {
                kind: crate::sendlog::PacketKind::TcpConnect,
                detail: "port scan".into(),
                count: 3,
            }],
        }
    }

    #[test]
    fn a_replay_with_the_same_result_and_rules_is_reproduced() {
        let p = Provenance::current(&Settings::default());
        let a = scan_with(Some(p.clone()), &[22]);
        let b = scan_with(Some(p), &[22]);
        let r = replay_check(&a, 1, &b, 2);
        assert!(r.reproducible && r.same_result && r.same_rules, "{r:#?}");
        assert!(
            r.changes.is_empty() && r.rule_differences.is_empty() && r.sent_differences.is_empty()
        );
        assert!(
            r.text().contains("reproduced (same result, same rules)"),
            "{}",
            r.text()
        );
    }

    #[test]
    fn a_different_result_or_different_rules_is_not_reproduced_and_says_why() {
        let p = Provenance::current(&Settings::default());
        let mut other_rules = p.rules.clone();
        other_rules.insert("cves.json".into(), hash(b"newer rules"));
        let q = Provenance::with(other_rules, p.feeds.clone());
        // same result, other rules
        let r = replay_check(
            &scan_with(Some(p.clone()), &[22]),
            1,
            &scan_with(Some(q.clone()), &[22]),
            2,
        );
        assert!(r.same_result && !r.same_rules && !r.reproducible);
        assert_eq!(r.rule_differences, ["rules cves.json: changed"]);
        // other result (telnet opened), same rules, and the sent log differs
        let mut b = scan_with(Some(p.clone()), &[22, 23]);
        b.sent[0].count = 4;
        let r = replay_check(&scan_with(Some(p.clone()), &[22]), 1, &b, 2);
        assert!(!r.same_result && r.same_rules && !r.reproducible);
        assert!(
            r.changes.iter().any(|l| l.contains("23")),
            "{:?}",
            r.changes
        );
        assert_eq!(r.sent_differences, ["tcp-connect: port scan: 3 -> 4"]);
        let text = r.text();
        assert!(
            text.contains("NOT reproduced") && text.contains("sent: tcp-connect"),
            "{text}"
        );
        // an original without a stamp: the rules are not known
        let r = replay_check(&scan_with(None, &[22]), 1, &scan_with(Some(p), &[22]), 2);
        assert!(r.same_result && !r.same_rules && !r.reproducible);
        assert!(r.notes[0].contains("no provenance stamp"), "{:?}", r.notes);
        // two partial scans cannot be compared and the note says so
        let mut partial = scan_with(None, &[22]);
        partial.complete = false;
        let r = replay_check(&partial, 1, &partial, 2);
        assert!(!r.same_result && r.notes.iter().any(|n| n.contains("could not be compared")));
    }

    #[test]
    fn the_replay_check_matches_its_schema_file() {
        let p = Provenance::current(&Settings::default());
        let r = replay_check(
            &scan_with(Some(p.clone()), &[22]),
            1,
            &scan_with(Some(p), &[22, 23]),
            2,
        );
        let text = crate::schema::object("replay-check", &r).unwrap();
        let schema: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../docs/schema/replay-check.v1.schema.json"),
            )
            .unwrap(),
        )
        .unwrap();
        crate::schema::validate(&schema, &serde_json::from_str(&text).unwrap()).unwrap();
    }

    #[test]
    fn stamped_settings_carry_the_provenance_and_survive_a_round_trip() {
        let s = stamped(&Settings::default());
        let p = s.provenance.clone().unwrap();
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"provenance\""), "{json}");
        let back: Settings = serde_json::from_str(&json).unwrap();
        assert_eq!(back.provenance, Some(p));
        // a settings document without the member (an older scan) loads without one
        let old = serde_json::to_string(&Settings::default()).unwrap();
        assert!(!old.contains("provenance"), "{old}");
        assert!(
            serde_json::from_str::<Settings>(&old)
                .unwrap()
                .provenance
                .is_none()
        );
    }
}
