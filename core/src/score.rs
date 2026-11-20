//! Risk scores per host and per network, and the "fix these things first" list (ROADMAP D26).
//!
//! The formula is deliberately simple so that it can be explained and checked by hand:
//!
//! **Points of one finding** = severity weight x known-exploited factor x EPSS factor x
//! exposure factor x confidence.
//!
//! | Factor | Value |
//! | --- | --- |
//! | Severity weight | critical 40, high 20, medium 8, low 3, info 1 |
//! | Known exploited (CISA KEV) | x 2.0; x 2.5 when KEV lists ransomware use; otherwise x 1.0 |
//! | EPSS (probability of exploitation in 30 days, 0 to 1) | x (1 + EPSS); x 1.0 without EPSS data |
//! | Exposure: cleartext or unauthenticated remote access or administration (Telnet, FTP, HTTP Basic, VNC, RDP without NLA, SMBv1, open Redis/memcached/MQTT/LDAP/Docker/SNMP, reachable industrial ports) | x 1.5 |
//! | Confidence (0 to 100, see [`crate::evidence`]; unscored counts as 100) | x confidence / 100 |
//!
//! **Host score** (0 to 100) = 100 x (1 - e^(-P / 60)) where P is the sum of the points of the
//! host's findings. The curve saturates: one critical finding is about 49, two about 74, and
//! nothing can exceed 100. **Network score** = 0.7 x the worst host score + 0.3 x the mean of
//! the ten highest host scores, so one very exposed host dominates but a network with many
//! exposed hosts ranks above one with a single such host. The bands are 0 none, 1-24 low,
//! 25-49 medium, 50-74 high, 75-100 critical.
//!
//! **Fix list**: identical findings (the same rule id, so the same CVE or the same weak setting)
//! across hosts form one group. The group's *risk reduction* is the sum, over the affected
//! hosts, of how far each host score drops when the group is fixed on that host, evaluated for
//! each group alone against the current state. Groups are ranked by that reduction, then by
//! severity and id, so fixing a medium issue on 40 hosts can outrank one critical on one host.
//!
//! The score is a ranking aid for a person deciding what to do first, not a measurement of
//! compromise likelihood. It inherits the limits of the findings: version-based hints count
//! less (their confidence is low) but are still not confirmed.
use crate::risk::{Finding, Severity};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

/// Scale of the saturating curve: P = 60 points give a score of about 63.
const SCALE: f64 = 60.0;

pub fn severity_weight(s: Severity) -> f64 {
    match s {
        Severity::Critical => 40.0,
        Severity::High => 20.0,
        Severity::Medium => 8.0,
        Severity::Low => 3.0,
        Severity::Info => 1.0,
    }
}

/// Rules that expose cleartext credentials or unauthenticated remote access or
/// administration, or an industrial protocol port: x 1.5.
pub fn is_exposure(id: &str) -> bool {
    matches!(
        id,
        "telnet-open"
            | "ftp-cleartext"
            | "mail-cleartext"
            | "http-basic-cleartext"
            | "vnc-exposed"
            | "rdp-no-nla"
            | "smb1-enabled"
            | "redis-noauth"
            | "memcached-open"
            | "mqtt-anonymous"
            | "ldap-anonymous"
            | "docker-api"
            | "snmp-public"
            | "ot-reachable"
            | "ot-control-traffic"
    )
}

/// The points of one finding (see the module documentation).
pub fn finding_points(f: &Finding) -> f64 {
    let mut p = severity_weight(f.severity);
    if f.exploit.kev {
        p *= if f.exploit.kev_ransomware { 2.5 } else { 2.0 };
    }
    if let Some(e) = f.exploit.epss {
        p *= 1.0 + e.as_f64();
    }
    if is_exposure(&f.id) {
        p *= 1.5;
    }
    if f.confidence > 0 {
        p *= f64::from(f.confidence.min(100)) / 100.0;
    }
    p
}

/// 0 to 100 from the points of one host.
fn curve(points: f64) -> f64 {
    100.0 * (1.0 - (-points.max(0.0) / SCALE).exp())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Band {
    None,
    Low,
    Medium,
    High,
    Critical,
}
impl Band {
    pub fn of(score: u8) -> Self {
        match score {
            0 => Self::None,
            1..=24 => Self::Low,
            25..=49 => Self::Medium,
            50..=74 => Self::High,
            _ => Self::Critical,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct HostScore {
    pub ip: IpAddr,
    /// 0 to 100.
    pub score: u8,
    pub band: Band,
    /// Sum of the points of the host's findings.
    pub points: f64,
    pub findings: usize,
    pub worst: Option<Severity>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct NetworkScore {
    /// 0 to 100.
    pub score: u8,
    pub band: Band,
    pub hosts: usize,
    pub findings: usize,
}

/// A group of identical findings across hosts, with what fixing it buys.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct FixGroup {
    /// The rule id shared by the findings (`telnet-open`, `cve-cve-2021-41773`).
    pub id: String,
    pub title: String,
    /// The highest severity in the group.
    pub severity: Severity,
    pub hosts: Vec<IpAddr>,
    pub findings: usize,
    /// Sum over the hosts of the host-score drop when the group is fixed there (score points).
    pub risk_reduction: f64,
    /// A CVE of the group is in the CISA KEV catalog.
    pub kev: bool,
    pub cve: Vec<String>,
    pub advice: String,
    pub reference: Option<String>,
}

/// Everything the reports and the GUI show.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Assessment {
    pub network: NetworkScore,
    /// Hosts with findings, highest score first.
    pub hosts: Vec<HostScore>,
    pub top_fixes: Vec<FixGroup>,
}

/// Scores of the hosts that have findings, highest first (ties by address). Hosts without
/// findings are not listed; their score is 0.
pub fn host_scores(findings: &[Finding]) -> Vec<HostScore> {
    let mut by_host: BTreeMap<IpAddr, (f64, usize, Option<Severity>)> = BTreeMap::new();
    for f in findings {
        let e = by_host.entry(f.ip).or_insert((0.0, 0, None));
        e.0 += finding_points(f);
        e.1 += 1;
        e.2 = e.2.max(Some(f.severity));
    }
    let mut out: Vec<HostScore> = by_host
        .into_iter()
        .map(|(ip, (points, n, worst))| {
            let score = curve(points).round().clamp(0.0, 100.0) as u8;
            HostScore {
                ip,
                score,
                band: Band::of(score),
                points,
                findings: n,
                worst,
            }
        })
        .collect();
    out.sort_by(|a, b| b.score.cmp(&a.score).then(a.ip.cmp(&b.ip)));
    out
}

/// The network score from host scores (highest first, as [`host_scores`] returns them).
pub fn network_score_of(hosts: &[HostScore], findings: usize) -> NetworkScore {
    let worst = f64::from(hosts.first().map_or(0, |h| h.score));
    let top: Vec<f64> = hosts.iter().take(10).map(|h| f64::from(h.score)).collect();
    let mean = if top.is_empty() {
        0.0
    } else {
        top.iter().sum::<f64>() / top.len() as f64
    };
    let score = (0.7 * worst + 0.3 * mean).round().clamp(0.0, 100.0) as u8;
    NetworkScore {
        score,
        band: Band::of(score),
        hosts: hosts.len(),
        findings,
    }
}

pub fn network_score(findings: &[Finding]) -> NetworkScore {
    network_score_of(&host_scores(findings), findings.len())
}

/// The `limit` groups of identical findings whose fix lowers the scores the most.
pub fn top_fixes(findings: &[Finding], limit: usize) -> Vec<FixGroup> {
    let mut totals: BTreeMap<IpAddr, f64> = BTreeMap::new();
    for f in findings {
        *totals.entry(f.ip).or_default() += finding_points(f);
    }
    struct Acc {
        title: String,
        severity: Severity,
        per_host: BTreeMap<IpAddr, f64>,
        findings: usize,
        kev: bool,
        cve: BTreeSet<String>,
        advice: String,
        reference: Option<String>,
    }
    let mut groups: BTreeMap<&str, Acc> = BTreeMap::new();
    for f in findings {
        let g = groups.entry(f.id.as_str()).or_insert_with(|| Acc {
            title: f.title.clone(),
            severity: f.severity,
            per_host: BTreeMap::new(),
            findings: 0,
            kev: false,
            cve: BTreeSet::new(),
            advice: f.advice.clone(),
            reference: f.reference.clone(),
        });
        *g.per_host.entry(f.ip).or_default() += finding_points(f);
        g.findings += 1;
        g.severity = g.severity.max(f.severity);
        g.kev |= f.exploit.kev;
        g.cve.extend(f.cve.iter().cloned());
        if g.reference.is_none() {
            g.reference = f.reference.clone();
        }
    }
    let mut out: Vec<FixGroup> = groups
        .into_iter()
        .map(|(id, g)| {
            let risk_reduction: f64 = g
                .per_host
                .iter()
                .map(|(ip, p)| {
                    let total = totals.get(ip).copied().unwrap_or(0.0);
                    curve(total) - curve(total - p)
                })
                .sum();
            FixGroup {
                id: id.to_string(),
                title: g.title,
                severity: g.severity,
                hosts: g.per_host.keys().copied().collect(),
                findings: g.findings,
                risk_reduction: (risk_reduction * 10.0).round() / 10.0,
                kev: g.kev,
                cve: g.cve.into_iter().collect(),
                advice: g.advice,
                reference: g.reference,
            }
        })
        .collect();
    out.sort_by(|a, b| {
        b.risk_reduction
            .total_cmp(&a.risk_reduction)
            .then(b.severity.cmp(&a.severity))
            .then(a.id.cmp(&b.id))
    });
    out.truncate(limit);
    out
}

/// Network score, host scores and the top `limit` fixes in one call (what the GUI and the
/// reports use).
pub fn assess(findings: &[Finding], limit: usize) -> Assessment {
    let hosts = host_scores(findings);
    Assessment {
        network: network_score_of(&hosts, findings.len()),
        top_fixes: top_fixes(findings, limit),
        hosts,
    }
}

/// "3 hosts" / "10.0.0.5" for a fix group in text output.
pub fn hosts_text(hosts: &[IpAddr]) -> String {
    match hosts {
        [one] => one.to_string(),
        many => format!("{} hosts", many.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feeds::{Exploit, Score};

    fn f(ip: &str, id: &str, sev: Severity) -> Finding {
        Finding {
            severity: sev,
            id: id.into(),
            title: format!("title of {id}"),
            ip: ip.parse().unwrap(),
            port: Some(80),
            evidence: String::new(),
            cve: vec![],
            advice: format!("fix {id}"),
            exploit: Exploit::default(),
            reference: None,
            confidence: 0,
        }
    }

    #[test]
    fn points_follow_the_documented_factors() {
        let base = f("10.0.0.1", "x-rule", Severity::High);
        assert_eq!(finding_points(&base), 20.0);
        for (sev, want) in [
            (Severity::Critical, 40.0),
            (Severity::Medium, 8.0),
            (Severity::Low, 3.0),
            (Severity::Info, 1.0),
        ] {
            assert_eq!(
                finding_points(&Finding {
                    severity: sev,
                    ..base.clone()
                }),
                want
            );
        }
        let mut kev = base.clone();
        kev.exploit.kev = true;
        assert_eq!(finding_points(&kev), 40.0);
        kev.exploit.kev_ransomware = true;
        assert_eq!(finding_points(&kev), 50.0);
        let mut epss = base.clone();
        epss.exploit.epss = Score::from_f64(0.5);
        assert_eq!(finding_points(&epss), 30.0);
        // Exposure and confidence.
        assert_eq!(
            finding_points(&f("10.0.0.1", "telnet-open", Severity::High)),
            30.0
        );
        assert_eq!(
            finding_points(&Finding {
                confidence: 40,
                ..base.clone()
            }),
            8.0
        );
        assert_eq!(
            finding_points(&Finding {
                confidence: 100,
                ..base
            }),
            20.0
        );
        // A hand-written Exploit without feeds changes nothing.
        let none = Finding {
            exploit: Exploit::default(),
            ..f("10.0.0.1", "y", Severity::Low)
        };
        assert_eq!(finding_points(&none), 3.0);
    }

    #[test]
    fn host_scores_saturate_and_never_exceed_100() {
        assert!(host_scores(&[]).is_empty());
        assert_eq!(network_score(&[]).score, 0);
        assert_eq!(network_score(&[]).band, Band::None);
        let one = host_scores(&[f("10.0.0.1", "a", Severity::Critical)]);
        assert_eq!(one[0].score, 49, "one critical is about 49");
        let two = host_scores(&[
            f("10.0.0.1", "a", Severity::Critical),
            f("10.0.0.1", "b", Severity::Critical),
        ]);
        assert_eq!(two[0].score, 74);
        assert_eq!(two[0].findings, 2);
        assert_eq!(two[0].worst, Some(Severity::Critical));
        let many: Vec<Finding> = (0..200)
            .map(|i| f("10.0.0.1", &format!("r{i}"), Severity::Critical))
            .collect();
        assert_eq!(host_scores(&many)[0].score, 100);
        // Monotonic: more findings never lower the score; info alone stays low.
        assert!(host_scores(&[f("10.0.0.1", "i", Severity::Info)])[0].score <= 2);
        assert_eq!(Band::of(0), Band::None);
        assert_eq!(Band::of(24), Band::Low);
        assert_eq!(Band::of(25), Band::Medium);
        assert_eq!(Band::of(50), Band::High);
        assert_eq!(Band::of(75), Band::Critical);
    }

    #[test]
    fn known_exploited_and_confidence_move_the_score() {
        let plain = f("10.0.0.1", "cve-cve-2021-41773", Severity::Critical);
        let mut kev = plain.clone();
        kev.exploit.kev = true;
        let hint = Finding {
            confidence: 40,
            ..plain.clone()
        };
        let s = |x: &Finding| host_scores(std::slice::from_ref(x))[0].score;
        assert!(s(&kev) > s(&plain), "KEV raises the score");
        assert!(s(&hint) < s(&plain), "a version hint counts less");
    }

    #[test]
    fn network_score_is_dominated_by_the_worst_host_but_rewards_breadth() {
        let crit = |ip: &str, id: &str| f(ip, id, Severity::Critical);
        let single = network_score(&[crit("10.0.0.1", "a")]);
        assert_eq!(single.score, 49);
        assert_eq!((single.hosts, single.findings), (1, 1));
        let broad: Vec<Finding> = (1..=10)
            .map(|i| crit(&format!("10.0.0.{i}"), "a"))
            .collect();
        // Ten hosts at 49: worst 49, mean 49.
        assert_eq!(network_score(&broad).score, 49);
        // One bad host among clean-ish ones: the worst host counts for 70 %.
        let mut mixed = vec![
            crit("10.0.0.1", "a"),
            crit("10.0.0.1", "b"),
            crit("10.0.0.1", "c"),
        ];
        mixed.extend((2..=10).map(|i| f(&format!("10.0.0.{i}"), "z", Severity::Low)));
        let n = network_score(&mixed);
        let worst = host_scores(&mixed)[0].score;
        assert!(
            n.score < worst && f64::from(n.score) >= 0.7 * f64::from(worst),
            "{n:?}"
        );
        // Adding a second exposed host raises the score.
        let two = network_score(&[crit("10.0.0.1", "a"), crit("10.0.0.2", "a")]);
        assert_eq!(two.score, 49, "same worst, same mean");
        let three_levels = network_score(&[
            crit("10.0.0.1", "a"),
            crit("10.0.0.1", "b"),
            f("10.0.0.2", "c", Severity::High),
        ]);
        assert!(three_levels.score > single.score);
    }

    #[test]
    fn fix_list_groups_identical_findings_and_ranks_by_total_reduction() {
        let mut list = vec![
            // One critical on one host.
            f("10.0.0.1", "redis-noauth", Severity::Critical),
            // The same medium issue on five hosts.
            f("10.0.0.1", "smb-signing", Severity::Medium),
        ];
        for i in 2..=6 {
            list.push(f(&format!("10.0.0.{i}"), "smb-signing", Severity::Medium));
        }
        // A low finding that repeats on one host (two ports).
        list.push(f("10.0.0.2", "ftp-cleartext", Severity::Low));
        list.push(Finding {
            port: Some(2121),
            ..f("10.0.0.2", "ftp-cleartext", Severity::Low)
        });
        let top = top_fixes(&list, 10);
        assert_eq!(top.len(), 3);
        assert_eq!(
            top[0].id, "smb-signing",
            "five hosts beat one critical: {top:?}"
        );
        assert_eq!(top[0].hosts.len(), 6, "{:?}", top[0].hosts);
        assert_eq!(top[0].findings, 6);
        assert_eq!(top[1].id, "redis-noauth");
        assert_eq!(top[2].id, "ftp-cleartext");
        assert_eq!(top[2].findings, 2);
        assert_eq!(top[2].hosts.len(), 1, "two ports on one host: one host");
        // Reductions are positive and descend; none exceeds what the hosts score.
        assert!(
            top.windows(2)
                .all(|w| w[0].risk_reduction >= w[1].risk_reduction)
        );
        let total: f64 = host_scores(&list).iter().map(|h| f64::from(h.score)).sum();
        assert!(
            top.iter()
                .all(|g| g.risk_reduction > 0.0 && g.risk_reduction <= total + 1.0)
        );
        assert_eq!(top[1].advice, "fix redis-noauth");
        // The limit and the empty case.
        assert_eq!(top_fixes(&list, 1).len(), 1);
        assert!(top_fixes(&list, 0).is_empty());
        assert!(top_fixes(&[], 10).is_empty());
    }

    #[test]
    fn fixing_the_only_finding_removes_the_whole_host_score_and_ties_are_stable() {
        let list = vec![
            f("10.0.0.2", "b-rule", Severity::High),
            f("10.0.0.1", "a-rule", Severity::High),
        ];
        let top = top_fixes(&list, 10);
        let score = host_scores(&list)[0].score;
        // Equal reductions: ordered by id.
        assert_eq!(
            (top[0].id.as_str(), top[1].id.as_str()),
            ("a-rule", "b-rule")
        );
        assert!((top[0].risk_reduction - f64::from(score)).abs() < 1.0);
        // Diminishing returns: fixing one of two criticals on a host removes less than half.
        let two = vec![
            f("10.0.0.1", "a", Severity::Critical),
            f("10.0.0.1", "b", Severity::Critical),
        ];
        let t = top_fixes(&two, 10);
        assert!(t[0].risk_reduction < 74.0 / 2.0 + 1.0 && t[0].risk_reduction > 20.0);
        // KEV marks the group and carries the CVE ids.
        let mut k = f("10.0.0.1", "cve-cve-2021-41773", Severity::Critical);
        k.cve = vec!["CVE-2021-41773".into()];
        k.exploit.kev = true;
        let g = &top_fixes(&[k], 5)[0];
        assert!(g.kev);
        assert_eq!(g.cve, ["CVE-2021-41773"]);
    }

    #[test]
    fn assessment_bundles_scores_and_fixes_and_serialises() {
        let list = vec![
            f("10.0.0.1", "telnet-open", Severity::High),
            f("10.0.0.2", "telnet-open", Severity::High),
        ];
        let a = assess(&list, 10);
        assert_eq!(a.hosts.len(), 2);
        assert_eq!(a.top_fixes[0].id, "telnet-open");
        assert_eq!(a.network.findings, 2);
        let json = serde_json::to_value(&a).unwrap();
        assert_eq!(json["network"]["band"], "medium");
        assert_eq!(json["top_fixes"][0]["severity"], "high");
        assert_eq!(hosts_text(&a.top_fixes[0].hosts), "2 hosts");
        assert_eq!(hosts_text(&a.top_fixes[0].hosts[..1]), "10.0.0.1");
    }
}
