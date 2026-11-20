//! A workbench for unknown devices (ROADMAP L73): group the responses that nothing identified,
//! compare them across firmware versions and turn a group into a draft rule for
//! `data/probes.json` that passes `probes lint`.
//!
//! It works on the banners the store keeps for services no rule recognised (`banner.<port>` with
//! `svc.<port>` unidentified), the same input as `fingerprints export-unknown`, and sends nothing.
//! Unlike that export it also keeps, for the analysis on this machine, how many distinct hosts
//! answered and the MAC vendors they carry; the draft contains none of that, only the banner texts
//! (host address, MAC and name replaced as in the export) and the rule.
//!
//! # Grouping
//!
//! Banners are normalised (lower case, every digit written as `#`, white space collapsed) and cut
//! into overlapping three-character shingles; two banners are *similar* when the Jaccard index of
//! their shingle sets is at least [`THRESHOLD`] (0.6), and groups are the connected components of
//! that relation. A group is named by the first 8 hex digits of the SHA-256 of its template: the
//! commonest banner with every version-like number replaced by `‹v›`.
//!
//! # The draft
//!
//! If all banners of a group have the same template, the rule is that template as a regular
//! expression with a capture group around the first version-like number (`$1` is the version);
//! if they differ, the rule is anchored on the longest common prefix of the templates and says so.
//! It refuses when that prefix is shorter than [`MIN_PREFIX`] characters, because such a rule
//! would claim unrelated services. The product and service names are guesses that a person must
//! check. The rule is added to the `banner` probe, which only listens and sends nothing.
use crate::store::Snapshot;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// Jaccard index of the shingle sets from which two banners count as similar.
pub const THRESHOLD: f64 = 0.6;
/// Shortest literal prefix a draft rule may rest on.
pub const MIN_PREFIX: usize = 5;
/// Most distinct banners looked at (the commonest ones).
const MAX_BANNERS: usize = 1_500;
const MAX_VARIANTS_LISTED: usize = 50;
/// Marks a version-like number in a template.
const PLACEHOLDER: char = '\u{1}';

/// One distinct banner of a group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Variant {
    pub banner: String,
    /// The version-like numbers in the banner, in order.
    pub versions: Vec<String>,
    pub ports: Vec<u16>,
    /// How many different hosts sent exactly this banner.
    pub hosts: usize,
    /// MAC vendors of those hosts, when known (local only).
    pub vendors: Vec<String>,
}

/// Responses that look alike: probably one product in several versions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Group {
    /// First 8 hex digits of the SHA-256 of the template.
    pub id: String,
    /// The commonest banner with version-like numbers shown as `‹v›`.
    pub template: String,
    pub ports: Vec<u16>,
    /// What the port number alone suggests (`ftp` for 21), when the group sits on one port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_hint: Option<String>,
    pub hosts: usize,
    /// Distinct banners in the group.
    pub banners: usize,
    pub vendors: Vec<String>,
    /// The commonest banners, most widespread first.
    pub variants: Vec<Variant>,
    /// Where the banners differ (see [`varying`]).
    pub varying: Vec<String>,
}

/// A draft rule for the `banner` probe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Draft {
    pub group: String,
    pub rule: serde_json::Value,
    /// A complete probe file with only this rule: what `probes validate` and `--probes` take.
    pub probe_file: String,
    pub checklist: Vec<String>,
    /// Said when the rule had to be made more general than the banners are.
    pub notes: Vec<String>,
}

fn normalise(banner: &str) -> String {
    let mut out = String::new();
    for c in banner.to_lowercase().chars() {
        let c = if c.is_ascii_digit() { '#' } else { c };
        if c.is_whitespace() {
            if !out.ends_with(' ') {
                out.push(' ');
            }
        } else {
            out.push(c);
        }
    }
    out.trim().to_string()
}

/// The three-character shingles of a normalised banner as sorted, distinct 32-bit hashes
/// (FNV-1a); a text shorter than three characters is one shingle.
fn shingles(text: &str) -> Vec<u32> {
    let chars: Vec<char> = text.chars().collect();
    let hash = |s: &str| {
        s.bytes().fold(0x811c_9dc5u32, |h, b| {
            (h ^ u32::from(b)).wrapping_mul(0x0100_0193)
        })
    };
    let mut out: Vec<u32> = if chars.len() < 3 {
        vec![hash(text)]
    } else {
        chars
            .windows(3)
            .map(|w| hash(&w.iter().collect::<String>()))
            .collect()
    };
    out.sort_unstable();
    out.dedup();
    out
}

/// Jaccard index of two sorted, distinct hash lists.
fn jaccard(a: &[u32], b: &[u32]) -> f64 {
    let (mut i, mut j, mut both) = (0, 0, 0usize);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                both += 1;
                i += 1;
                j += 1;
            }
        }
    }
    let either = a.len() + b.len() - both;
    if either == 0 {
        1.0
    } else {
        both as f64 / either as f64
    }
}

/// Jaccard index of two banners' shingle sets (1.0 for banners that differ only in digits).
pub fn similarity(a: &str, b: &str) -> f64 {
    jaccard(&shingles(&normalise(a)), &shingles(&normalise(b)))
}

/// Splits a banner at its version-like numbers (`2`, `2.1`, `20.11.3`): the text with
/// [`PLACEHOLDER`] in their place, and the numbers.
fn split_versions(banner: &str) -> (String, Vec<String>) {
    let chars: Vec<char> = banner.chars().collect();
    let (mut template, mut versions) = (String::new(), vec![]);
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            let start = i;
            loop {
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
                if i + 1 < chars.len() && chars[i] == '.' && chars[i + 1].is_ascii_digit() {
                    i += 1;
                } else {
                    break;
                }
            }
            versions.push(chars[start..i].iter().collect());
            template.push(PLACEHOLDER);
        } else {
            template.push(chars[i]);
            i += 1;
        }
    }
    (template, versions)
}

fn display_template(template: &str) -> String {
    template.replace(PLACEHOLDER, "‹v›")
}

#[derive(Default)]
struct Item {
    hosts: BTreeSet<std::net::IpAddr>,
    vendors: BTreeSet<String>,
}

/// The groups of similar unidentified banners of `snapshots`, the most widespread first.
pub fn groups<'a>(snapshots: impl IntoIterator<Item = &'a Snapshot>) -> Vec<Group> {
    let mut items: BTreeMap<(u16, String), Item> = BTreeMap::new();
    for snapshot in snapshots {
        for host in &snapshot.hosts {
            for (key, banner) in &host.identity {
                let Some(port) = key
                    .strip_prefix("banner.")
                    .and_then(|p| p.parse::<u16>().ok())
                else {
                    continue;
                };
                let identified = host
                    .identity
                    .get(&format!("svc.{port}"))
                    .is_some_and(|s| !s.starts_with("unidentified"));
                let banner = super::unknown::redact(banner.trim(), host);
                if identified || banner.is_empty() {
                    continue;
                }
                let item = items.entry((port, banner)).or_default();
                item.hosts.insert(host.ip);
                if let Some(v) = host.identity.get("mac.vendor").filter(|v| !v.is_empty()) {
                    item.vendors.insert(v.clone());
                }
            }
        }
    }
    // The commonest banners first, so the cap drops the rarest and the order is deterministic.
    let mut list: Vec<((u16, String), Item)> = items.into_iter().collect();
    list.sort_by(|a, b| b.1.hosts.len().cmp(&a.1.hosts.len()).then(a.0.cmp(&b.0)));
    list.truncate(MAX_BANNERS);
    let sets: Vec<Vec<u32>> = list
        .iter()
        .map(|((_, b), _)| shingles(&normalise(b)))
        .collect();
    // Connected components of the similarity relation (union-find).
    let mut parent: Vec<usize> = (0..list.len()).collect();
    fn find(parent: &mut [usize], mut x: usize) -> usize {
        while parent[x] != x {
            parent[x] = parent[parent[x]];
            x = parent[x];
        }
        x
    }
    for i in 0..list.len() {
        for j in i + 1..list.len() {
            if jaccard(&sets[i], &sets[j]) >= THRESHOLD {
                let (a, b) = (find(&mut parent, i), find(&mut parent, j));
                if a != b {
                    parent[b.max(a)] = b.min(a);
                }
            }
        }
    }
    let mut members: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in 0..list.len() {
        let root = find(&mut parent, i);
        members.entry(root).or_default().push(i);
    }
    let mut out: Vec<Group> = members
        .into_values()
        .map(|idx| {
            let variants: Vec<Variant> = idx
                .iter()
                .map(|&i| {
                    let ((port, banner), item) = &list[i];
                    Variant {
                        banner: banner.clone(),
                        versions: split_versions(banner).1,
                        ports: vec![*port],
                        hosts: item.hosts.len(),
                        vendors: item.vendors.iter().cloned().collect(),
                    }
                })
                .collect();
            // The same banner on several ports is one variant.
            let mut merged: Vec<Variant> = vec![];
            for v in variants {
                match merged.iter_mut().find(|m| m.banner == v.banner) {
                    Some(m) => {
                        m.ports.extend(&v.ports);
                        m.hosts += v.hosts;
                        m.vendors.extend(v.vendors);
                    }
                    None => merged.push(v),
                }
            }
            for v in &mut merged {
                v.ports.sort_unstable();
                v.ports.dedup();
                v.vendors.sort();
                v.vendors.dedup();
            }
            merged.sort_by(|a, b| b.hosts.cmp(&a.hosts).then(a.banner.cmp(&b.banner)));
            let template = split_versions(&merged[0].banner).0;
            let mut ports: Vec<u16> = merged.iter().flat_map(|v| v.ports.clone()).collect();
            ports.sort_unstable();
            ports.dedup();
            let mut vendors: Vec<String> = merged.iter().flat_map(|v| v.vendors.clone()).collect();
            vendors.sort();
            vendors.dedup();
            let hosts: BTreeSet<_> = idx
                .iter()
                .flat_map(|&i| list[i].1.hosts.iter().copied())
                .collect();
            let id = crate::fingerprint::hex(&crate::fingerprint::sha256(template.as_bytes()))[..8]
                .to_string();
            let varying = varying(&merged);
            Group {
                id,
                template: display_template(&template),
                port_hint: (ports.len() == 1)
                    .then(|| super::port_hint(ports[0]))
                    .flatten()
                    .map(str::to_string),
                ports,
                hosts: hosts.len(),
                banners: merged.len(),
                vendors,
                varying,
                variants: merged.into_iter().take(MAX_VARIANTS_LISTED).collect(),
            }
        })
        .collect();
    out.sort_by(|a, b| {
        b.hosts
            .cmp(&a.hosts)
            .then(b.banners.cmp(&a.banners))
            .then(a.id.cmp(&b.id))
    });
    out
}

/// Where the banners of a group differ: the version-like numbers by position (`#1: 2.1, 3.0`)
/// when the banners share a template, else the number of different templates.
pub fn varying(variants: &[Variant]) -> Vec<String> {
    let templates: BTreeSet<String> = variants
        .iter()
        .map(|v| split_versions(&v.banner).0)
        .collect();
    if templates.len() > 1 {
        return vec![format!(
            "the banners have {} different shapes, not only different version numbers",
            templates.len()
        )];
    }
    let width = variants.iter().map(|v| v.versions.len()).max().unwrap_or(0);
    (0..width)
        .filter_map(|n| {
            let values: BTreeSet<&str> = variants
                .iter()
                .filter_map(|v| v.versions.get(n).map(String::as_str))
                .collect();
            (values.len() > 1).then(|| {
                let mut list: Vec<&str> = values.into_iter().collect();
                list.sort_by(|a, b| crate::nvd::compare_versions(a, b));
                format!("number {} varies: {}", n + 1, list.join(", "))
            })
        })
        .collect()
}

/// The group with this id (or an unambiguous prefix of it).
pub fn find<'g>(groups: &'g [Group], id: &str) -> Result<&'g Group, String> {
    let id = id.trim().to_ascii_lowercase();
    if id.len() < 4 {
        return Err("Give at least 4 characters of the group id".into());
    }
    let mut hits = groups.iter().filter(|g| g.id.starts_with(&id));
    match (hits.next(), hits.next()) {
        (Some(g), None) => Ok(g),
        (None, _) => Err(format!(
            "No group {id}; list them with `fingerprints groups`"
        )),
        (Some(_), Some(_)) => Err(format!("{id} matches several groups; give more characters")),
    }
}

/// The group as text: its template, its variants and what varies.
pub fn compare_text(g: &Group) -> String {
    let mut out = vec![format!(
        "Group {}: {} ({} hosts, {} distinct banners, ports {})",
        g.id,
        g.template,
        g.hosts,
        g.banners,
        g.ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    )];
    if let Some(h) = &g.port_hint {
        out.push(format!("The port number suggests: {h}"));
    }
    if !g.vendors.is_empty() {
        out.push(format!(
            "MAC vendors of the hosts: {}",
            g.vendors.join(", ")
        ));
    }
    for v in &g.varying {
        out.push(format!("Differs: {v}"));
    }
    if g.varying.is_empty() {
        out.push("The banners are identical apart from nothing the workbench can see.".into());
    }
    for v in &g.variants {
        out.push(format!(
            "  {:>4} host(s)  {}  versions: {}",
            v.hosts,
            v.banner,
            if v.versions.is_empty() {
                "-".to_string()
            } else {
                v.versions.join(" / ")
            }
        ));
    }
    if g.banners > g.variants.len() {
        out.push(format!(
            "  ... and {} more banners",
            g.banners - g.variants.len()
        ));
    }
    out.join("\n")
}

/// The groups as text for the terminal.
pub fn groups_text(groups: &[Group]) -> String {
    if groups.is_empty() {
        return "No unidentified banners in the stored scans.".into();
    }
    groups
        .iter()
        .map(|g| {
            format!(
                "{}  {:>3} hosts  {:>2} banners  port {:<12} {}{}",
                g.id,
                g.hosts,
                g.banners,
                g.ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(","),
                g.template,
                g.port_hint
                    .as_ref()
                    .map_or(String::new(), |h| format!("  (port suggests {h})"))
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn slug(s: &str) -> String {
    let slug: String = s
        .chars()
        .take_while(|c| !c.is_whitespace())
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect::<String>()
        .to_lowercase();
    if slug.is_empty() {
        "unknown".into()
    } else {
        slug
    }
}

/// A regular expression over `template` (as [`split_versions`] makes it) with a capture group
/// around the first version-like number.
fn template_regex(template: &str) -> String {
    let mut re = String::from("^");
    let mut first = true;
    let mut literal = String::new();
    for c in template.chars() {
        if c == PLACEHOLDER {
            re.push_str(&regex::escape(&literal));
            literal.clear();
            if first {
                re.push_str(r"([\d.]+)");
                first = false;
            } else {
                re.push_str(r"[\d.]+");
            }
        } else if c.is_whitespace() {
            re.push_str(&regex::escape(&literal));
            literal.clear();
            re.push_str(r"\s+");
        } else {
            literal.push(c);
        }
    }
    re.push_str(&regex::escape(&literal));
    re
}

fn common_prefix(templates: &[String]) -> String {
    let first = &templates[0];
    let mut n = first.chars().count();
    for t in &templates[1..] {
        n = n.min(
            first
                .chars()
                .zip(t.chars())
                .take_while(|(a, b)| a == b)
                .count(),
        );
    }
    first.chars().take(n).collect()
}

/// Turns a group into a draft rule (see the module documentation).
pub fn draft(g: &Group) -> Result<Draft, String> {
    let templates: Vec<String> = g
        .variants
        .iter()
        .map(|v| split_versions(&v.banner).0)
        .collect();
    let distinct: BTreeSet<&String> = templates.iter().collect();
    let mut notes = vec![];
    let (re, has_version) = if distinct.len() == 1 {
        let t = &templates[0];
        (template_regex(t), t.contains(PLACEHOLDER))
    } else {
        let prefix = common_prefix(&templates);
        // Do not end in the middle of a number or word of the shorter banners.
        let prefix = prefix.trim_end().to_string();
        if prefix.chars().filter(|c| *c != PLACEHOLDER).count() < MIN_PREFIX {
            return Err(format!(
                "the banners of group {} differ too early ({} different shapes, common start {:?}); \
                 a rule on so little would claim unrelated services",
                g.id,
                distinct.len(),
                display_template(&prefix)
            ));
        }
        notes.push(format!(
            "The banners have {} different shapes, so the rule only anchors on their common start {:?}; make it more specific if you can.",
            distinct.len(),
            display_template(&prefix)
        ));
        let has = prefix.contains(PLACEHOLDER);
        (template_regex(&prefix), has)
    };
    if g.variants.len() < g.banners {
        notes.push(format!(
            "Only the {} commonest of {} banners were used to build the rule.",
            g.variants.len(),
            g.banners
        ));
    }
    let name_part = g.template.split('‹').next().unwrap_or("").trim();
    let product = if name_part.is_empty() {
        g.template.clone()
    } else {
        name_part.to_string()
    };
    let service = slug(&product);
    let mut rule = serde_json::json!({
        "re": re,
        "service": service,
        "product": product,
    });
    if has_version {
        rule["version"] = serde_json::json!("$1");
    }
    // Every banner of the group must match, and the version must come out as the number.
    let compiled =
        regex::bytes::Regex::new(rule["re"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
    for v in &g.variants {
        if !compiled.is_match(v.banner.as_bytes()) {
            return Err(format!(
                "the draft rule does not match {:?}; this is a bug in the workbench",
                v.banner
            ));
        }
    }
    let probe_file = serde_json::to_string_pretty(&serde_json::json!({
        "probes": [{ "name": "banner", "wait_ms": 2500, "rules": [rule.clone()] }]
    }))
    .map_err(|e| e.to_string())?;
    let issues = super::lint_probes(&probe_file)?;
    if super::lint_error_count(&issues) > 0 {
        return Err(format!(
            "the draft does not pass probes lint: {}",
            issues
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    let checklist = vec![
        "Read the banners above: remove or generalise anything that identifies a person, a site or an organisation (names, serial numbers, addresses).".into(),
        "Check `service`, `product` and what `$1` means against the vendor's documentation: the workbench only guesses them from the banner text.".into(),
        "The banner text is shown with control characters removed and cut at 120 characters: capture a raw reply (for example `nc HOST PORT | xxd`) and make sure the rule matches it.".into(),
        "Put the rule into the `banner` probe of data/probes.json, before more general rules (the first match wins), or send the file as it is.".into(),
        "Run `network-scope-cli probes validate FILE` and `probes lint`; both must pass.".into(),
        "Scan a device that sends this banner (`scan HOST --ports PORT --services --probes FILE`) and check the service, product and version.".into(),
        "Add a test that exercises the rule (CONTRIBUTING.md, Adding data) and open the pull request with `?template=fingerprint.md`.".into(),
        "Do not add a probe that sends anything to an industrial or printer port; this rule only listens.".into(),
    ];
    Ok(Draft {
        group: g.id.clone(),
        rule,
        probe_file,
        checklist,
        notes,
    })
}

/// The checklist and notes of a draft as a Markdown file for the pull request.
pub fn checklist_markdown(d: &Draft, g: &Group) -> String {
    let mut out = format!(
        "# Fingerprint draft for group {}\n\nBanners ({} hosts, ports {}):\n\n",
        d.group,
        g.hosts,
        g.ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );
    for v in &g.variants {
        out.push_str(&format!(
            "- `{}` ({} hosts)\n",
            v.banner.replace('`', "'"),
            v.hosts
        ));
    }
    out.push_str("\nRule:\n\n```json\n");
    out.push_str(&serde_json::to_string_pretty(&d.rule).unwrap_or_default());
    out.push_str("\n```\n");
    for n in &d.notes {
        out.push_str(&format!("\nNote: {n}\n"));
    }
    out.push_str("\n## Checklist\n\n");
    for item in &d.checklist {
        out.push_str(&format!("- [ ] {item}\n"));
    }
    out
}

#[cfg(test)]
#[path = "workbench_tests.rs"]
mod tests;
