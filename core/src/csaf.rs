//! Offline vulnerability intelligence for industrial devices (ROADMAP L68): CISA ICS advisories
//! in CSAF 2.0 format, matched against the vendor, product and firmware an OT identification
//! found (`S7.*`, `EtherNet/IP.*`, `Modbus.*`, `OPC UA.*`, see [`crate::otdevice`]).
//!
//! `feeds import csaf FILE|DIR...` reads advisories the user downloaded (for example from
//! <https://github.com/cisagov/CSAF>) into a small local cache (`csaf.json` next to `feeds.json`).
//! Nothing here touches the network. A scan then raises `cve-*` findings for devices whose
//! firmware lies in an affected version range, and KEV and EPSS data of the imported feeds rank
//! them like every other CVE finding.
//!
//! # Order of sources
//!
//! For one device and port the sources are consulted in this order:
//!
//! 1. imported **CSAF advisories** (this module, vendor data),
//! 2. the imported **NVD feed** (by CPE, see [`crate::nvd`]),
//! 3. the hand-written rules of `data/cves.json` (and the user's `--cves` file), **only for CVEs
//!    the feeds did not already raise on that port**.
//!
//! The curated rules are a fallback for what the feeds do not cover, not the main source: when an
//! advisory or an NVD record names a CVE for the device, the feed's finding is the one reported
//! and a curated rule for the same CVE is skipped.
//!
//! # What is parsed
//!
//! The `product_tree` branches (vendor, product family and name, version or version range) and
//! `full_product_names`, with `product_identification_helper` model numbers and SKUs, and the
//! `vulnerabilities` (CVE, title, CVSS scores per product, `product_status.known_affected`,
//! remediations). Version ranges may be written as `vers:` strings (`vers:intdot/>=2.0|<2.7.1`,
//! `vers:all/*`) or in the plain forms CISA uses (`<V4.5.1`, `>=V2.0|<V2.7.1`, `V4.5.1`,
//! `All versions`). Products without any version information are skipped: matching them would
//! flag every firmware.
//!
//! # Relationships
//!
//! CSAF 2.0 lets an advisory name a product that exists only as a pair: `product_tree.relationships`
//! entries say that `product_reference` is a `default_component_of`, `installed_on`,
//! `installed_with`, `optional_component_of` or `external_component_of` the product
//! `relates_to_product_reference`, and give the pair its own `full_product_name.product_id`, which
//! is what `product_status` then lists (typically "firmware below V4.5.1" `installed_on`
//! "SIMATIC S7-1200 CPU"). Each such pair becomes one product that has the **vendor** of the
//! platform (else of the component), the **names, model numbers and SKUs of both** (so a device
//! is found by its hardware name or by the firmware's), and the **version of the component**
//! (the `product_reference`; when it has none, the one of the platform). A pair may itself be
//! part of another pair (chains are resolved, up to 8 levels); a pair whose parts are not
//! defined in the tree, or that has no version at all, is counted as skipped like any other
//! product. Relationship categories other than the five above are ignored.
//!
//! # Matching, and its limits
//!
//! A device matches an advisory product when the vendors agree (when both are known), one of
//! the normalised product names (letters and digits only, at least 5 characters) contains the
//! other, or a model number or SKU of the advisory is contained in one of the device's names, and
//! the firmware version is in the range. A device without a firmware version matches only ranges
//! that cover all versions. Siemens S7 CPUs are additionally known by their family (`CPU 1214C`
//! is an S7-1200, `CPU 1511-1 PN` an S7-1500) because advisories name families, not CPU models.
//! Matching is by name, so a hardware variant an advisory does not distinguish can be reported
//! although it is not affected; the finding says "version-based hint" like every other one.
use crate::{otdevice::OtDevice, risk::Severity};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
};

/// Largest advisory file accepted (real ones are a few hundred KB).
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CACHE_BYTES: u64 = 512 * 1024 * 1024;
/// At most this many files from a directory.
pub const MAX_FILES: usize = 20_000;
const MAX_DEPTH: usize = 24;
const MAX_NODES: usize = 200_000;
const MAX_VULNERABILITIES: usize = 10_000;
const MAX_ENTRIES_PER_FILE: usize = 100_000;
const MAX_ENTRIES: usize = 1_000_000;
const MAX_TEXT: usize = 300;
const CACHE_VERSION: u32 = 1;
/// At most this many findings per device, so one old product does not drown a report.
pub const MAX_FINDINGS_PER_DEVICE: usize = 50;

/// One affected product of one vulnerability of one advisory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// `document.tracking.id` (`ICSA-23-285-01`).
    pub advisory: String,
    pub cve: String,
    pub title: String,
    pub severity: Severity,
    /// CVSS base score in tenths (98 = 9.8), when the advisory gives one for this product.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvss: Option<u32>,
    pub vendor: String,
    /// Product names, model numbers and SKUs the advisory uses for the product.
    pub products: Vec<String>,
    /// The affected versions in canonical form: `*` for all, else `|`-separated constraints
    /// such as `>=2.0|<2.7.1` or `=4.5`.
    pub range: String,
    /// What the vendor says to do (the first remediation for the product), may be empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fix: String,
    /// The advisory's own web address, may be empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url: String,
}

/// The cache file: every imported advisory entry.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Csaf {
    // `version` and `entries` are what makes a file a CSAF cache (see `Csaf::read`): not
    // optional, or any JSON object would load as an empty cache.
    pub version: u32,
    /// Unix time of the last import.
    #[serde(default)]
    pub imported_at: u64,
    /// Files imported so far (names only), for `feeds status`.
    #[serde(default)]
    pub sources: Vec<String>,
    pub entries: Vec<Entry>,
}

/// One vulnerability that applies to a device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub cve: String,
    pub severity: Severity,
    pub cvss: Option<u32>,
    pub title: String,
    /// The advisories that name this CVE for the device, sorted.
    pub advisories: Vec<String>,
    /// The affected range of the strongest entry, for the evidence.
    pub range: String,
    pub fix: String,
    /// The advisory's own web address (HTTPS only), may be empty.
    pub url: String,
}

/// What one advisory file gave.
#[derive(Debug, Default)]
pub struct Parsed {
    pub advisory: String,
    pub title: String,
    pub entries: Vec<Entry>,
    /// Vulnerability/product pairs that could not be used (no version, unknown range syntax,
    /// no CVE id).
    pub skipped: usize,
}

// ---- version ranges ------------------------------------------------------------------------

/// `V4.5.1` and `4.5.1` are the same version; leading `v` and white space go.
pub(crate) fn norm_version(v: &str) -> &str {
    let v = v.trim();
    v.strip_prefix(['v', 'V']).map_or(v, str::trim_start)
}

fn valid_version(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 40
        && v.bytes().any(|b| b.is_ascii_digit())
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
}

/// The canonical form of a version range text, or `None` when it is not understood (`!=`,
/// free text, unknown syntax). See the module documentation for the accepted forms.
pub fn parse_range(text: &str) -> Option<String> {
    let mut t = text.trim().to_string();
    if t.len() > 200 {
        return None;
    }
    if let Some(rest) = t.strip_prefix("vers:") {
        // vers:<scheme>/<constraints>
        t = rest.split_once('/')?.1.to_string();
    }
    let lower = t.to_ascii_lowercase();
    let lower = lower.trim();
    if lower == "*" || lower == "all" || lower == "all versions" || lower == "all versions." {
        return Some("*".into());
    }
    // "All versions < V4.5.1", "all versions prior to 4.5.1"
    let lower = lower
        .strip_prefix("all versions")
        .map_or(lower, str::trim_start);
    let mut constraints = vec![];
    for part in lower.split('|') {
        let part = part.trim();
        let (op, value) = if let Some(v) = part.strip_prefix("<=") {
            ("<=", v)
        } else if let Some(v) = part.strip_prefix(">=") {
            (">=", v)
        } else if part.starts_with("!=") {
            return None;
        } else if let Some(v) = part.strip_prefix('<') {
            ("<", v)
        } else if let Some(v) = part.strip_prefix('>') {
            (">", v)
        } else if let Some(v) = part.strip_prefix('=') {
            ("=", v)
        } else if let Some(v) = part
            .strip_prefix("prior to")
            .or_else(|| part.strip_prefix("before"))
        {
            ("<", v)
        } else if let Some(v) = part
            .strip_suffix("and earlier")
            .or_else(|| part.strip_suffix("and prior"))
            .or_else(|| part.strip_suffix("or earlier"))
        {
            ("<=", v)
        } else {
            ("=", part)
        };
        let value = norm_version(value);
        if !valid_version(value) {
            return None;
        }
        constraints.push(format!("{op}{value}"));
    }
    (!constraints.is_empty() && constraints.len() <= 4).then(|| constraints.join("|"))
}

/// Whether `version` lies in the canonical `range`. An empty version is in `*` only.
pub fn range_holds(range: &str, version: &str) -> bool {
    use std::cmp::Ordering::*;
    if range == "*" {
        return true;
    }
    let version = norm_version(version);
    if !valid_version(version) {
        return false;
    }
    range.split('|').all(|c| {
        let (op, value) = if let Some(v) = c.strip_prefix("<=") {
            ("<=", v)
        } else if let Some(v) = c.strip_prefix(">=") {
            (">=", v)
        } else if let Some(v) = c.strip_prefix('<') {
            ("<", v)
        } else if let Some(v) = c.strip_prefix('>') {
            (">", v)
        } else {
            ("=", c.strip_prefix('=').unwrap_or(c))
        };
        let o = crate::nvd::compare_versions(version, value);
        match op {
            "<=" => o != Greater,
            ">=" => o != Less,
            "<" => o == Less,
            ">" => o == Greater,
            _ => o == Equal,
        }
    })
}

// ---- parsing -------------------------------------------------------------------------------

fn text(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .map(clean)
        .unwrap_or_default()
}

fn clean(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(MAX_TEXT)
        .collect::<String>()
        .trim()
        .to_string()
}

fn valid_cve(s: &str) -> bool {
    let mut parts = s.split('-');
    parts.next() == Some("CVE")
        && parts
            .next()
            .is_some_and(|y| y.len() == 4 && y.bytes().all(|b| b.is_ascii_digit()))
        && parts
            .next()
            .is_some_and(|n| n.len() >= 4 && n.len() <= 9 && n.bytes().all(|b| b.is_ascii_digit()))
        && parts.next().is_none()
}

/// What the product tree says about one product id.
#[derive(Clone, Debug, Default)]
struct Product {
    vendor: String,
    names: Vec<String>,
    /// The names that narrow the product down, broadest first (see [`StatusEntry::specific`]).
    specific: Vec<String>,
    version: Option<String>,
}

#[derive(Clone, Default)]
struct Trail {
    vendor: String,
    names: Vec<String>,
    specific: Vec<String>,
    /// A `product_name` branch is on the path: the leaf's own name then only repeats the path.
    model: bool,
    version: Option<String>,
}

fn add_unique(list: &mut Vec<String>, value: String) {
    if !value.is_empty() && !list.iter().any(|v| v.eq_ignore_ascii_case(&value)) {
        list.push(value);
    }
}

/// A leaf `product` object: a name such as `Siemens SIMATIC S7-1200 CPU: <V4.5.1` splits at the
/// last `:` into a product name and a version text.
fn leaf(product: &Value, path: &Trail, out: &mut BTreeMap<String, Product>) {
    leaf_with(product, path, out, true);
}

/// [`leaf`]; `add_name` false leaves the product's own name out of the names (a relationship's
/// name is a sentence about two products that already contribute their names).
fn leaf_with(product: &Value, path: &Trail, out: &mut BTreeMap<String, Product>, add_name: bool) {
    let id = text(product, "product_id");
    if id.is_empty() {
        return;
    }
    let mut p = Product {
        vendor: path.vendor.clone(),
        names: path.names.clone(),
        specific: path.specific.clone(),
        version: path.version.clone(),
    };
    let full = text(product, "name");
    let (name_part, version_part) = match full.rsplit_once(':') {
        Some((n, v)) if parse_range(v).is_some() => {
            (n.trim().to_string(), Some(v.trim().to_string()))
        }
        _ => (full.clone(), None),
    };
    if add_name {
        if !path.model {
            // Without a `product_name` branch the leaf's name is what narrows the product down
            // (a flat list, or a model directly under a family); the vendor is not part of it.
            let vendor = if path.vendor.is_empty() {
                full.split_whitespace().next().unwrap_or("")
            } else {
                path.vendor.as_str()
            };
            let own = match name_part.get(..vendor.len()) {
                Some(v) if !v.is_empty() && v.eq_ignore_ascii_case(vendor) => {
                    name_part[v.len()..].trim()
                }
                _ => name_part.as_str(),
            };
            add_unique(&mut p.specific, own.to_string());
        }
        add_unique(&mut p.names, name_part);
    }
    if p.version.is_none() {
        p.version = version_part;
    }
    if let Some(helper) = product.get("product_identification_helper") {
        for key in ["model_numbers", "skus"] {
            for v in helper
                .get(key)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(s) = v.as_str() {
                    add_unique(&mut p.names, clean(s));
                }
            }
        }
        // A CPE names vendor and product too: cpe:2.3:h:siemens:simatic_s7-1200_cpu:...
        if let Some(cpe) = helper.get("cpe").and_then(Value::as_str)
            && let Some(c) = crate::nvd::parse_cpe(cpe)
        {
            if p.vendor.is_empty() {
                p.vendor = c.product_key().split(':').nth(1).unwrap_or("").to_string();
            }
            add_unique(
                &mut p.names,
                c.product_key()
                    .split(':')
                    .nth(2)
                    .unwrap_or("")
                    .replace('_', " "),
            );
            if p.version.is_none() {
                let v = c.full_version();
                if parse_range(&v).is_some() && v != "*" && v != "-" {
                    p.version = Some(v);
                }
            }
        }
    }
    if p.vendor.is_empty()
        && add_name
        && let Some(first) = full.split_whitespace().next()
    {
        p.vendor = first.to_string();
    }
    out.insert(id, p);
}

fn walk(
    branch: &Value,
    mut path: Trail,
    depth: usize,
    nodes: &mut usize,
    out: &mut BTreeMap<String, Product>,
) {
    *nodes += 1;
    if depth > MAX_DEPTH || *nodes > MAX_NODES {
        return;
    }
    let name = text(branch, "name");
    match branch.get("category").and_then(Value::as_str).unwrap_or("") {
        "vendor" => path.vendor = name,
        category @ ("product_family" | "product_name") => {
            path.model |= category == "product_name" && !name.is_empty();
            add_unique(&mut path.specific, name.clone());
            add_unique(&mut path.names, name);
        }
        "product_version_range" | "product_version" => path.version = Some(name),
        _ => {}
    }
    if let Some(product) = branch.get("product") {
        leaf(product, &path, out);
    }
    for child in branch
        .get("branches")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        walk(child, path.clone(), depth + 1, nodes, out);
    }
}

/// The relationship categories whose `full_product_name` is a product made of two others.
const RELATIONSHIPS: [&str; 5] = [
    "default_component_of",
    "installed_on",
    "installed_with",
    "optional_component_of",
    "external_component_of",
];
const MAX_RELATIONSHIPS: usize = 100_000;
/// Passes over the relationships: a pair can be part of another pair, one level per pass.
const MAX_RELATIONSHIP_PASSES: usize = 8;

/// Adds the products that `product_tree.relationships` define (see the module documentation).
fn relationships(tree: &Value, out: &mut BTreeMap<String, Product>) {
    let list: Vec<&Value> = tree
        .get("relationships")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_RELATIONSHIPS)
        .filter(|r| {
            RELATIONSHIPS.contains(&r.get("category").and_then(Value::as_str).unwrap_or(""))
        })
        .collect();
    let mut done = vec![false; list.len()];
    for _ in 0..MAX_RELATIONSHIP_PASSES {
        let mut progress = false;
        for (i, r) in list.iter().enumerate() {
            let Some(fpn) = r.get("full_product_name") else {
                done[i] = true;
                continue;
            };
            if done[i] {
                continue;
            }
            let (component, platform) = (
                out.get(&text(r, "product_reference")),
                out.get(&text(r, "relates_to_product_reference")),
            );
            let (Some(component), Some(platform)) = (component, platform) else {
                continue;
            };
            let mut trail = Trail {
                vendor: if platform.vendor.is_empty() {
                    component.vendor.clone()
                } else {
                    platform.vendor.clone()
                },
                names: platform.names.clone(),
                // The device is the platform: its names decide which model a statement is for.
                specific: if platform.specific.is_empty() {
                    component.specific.clone()
                } else {
                    platform.specific.clone()
                },
                model: true,
                version: component
                    .version
                    .clone()
                    .or_else(|| platform.version.clone()),
            };
            for n in component.names.clone() {
                add_unique(&mut trail.names, n);
            }
            done[i] = true;
            progress = true;
            let add_name = trail.names.is_empty();
            leaf_with(fpn, &trail, out, add_name);
        }
        if !progress {
            break;
        }
    }
}

fn severity_of(score_tenths: u32, label: Option<&str>) -> Severity {
    if let Some(s) = label.and_then(Severity::parse)
        && s != Severity::Info
    {
        return s;
    }
    match score_tenths {
        90.. => Severity::Critical,
        70..=89 => Severity::High,
        40..=69 => Severity::Medium,
        1..=39 => Severity::Low,
        0 => Severity::Info,
    }
}

fn ids(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|s| s.chars().take(100).collect())
        .collect()
}

/// Parses one CSAF 2.0 advisory (see the module documentation for what is used).
/// Every product id the `product_tree` defines (branches, full product names, relationships).
fn product_tree(doc: &Value) -> BTreeMap<String, Product> {
    let mut products: BTreeMap<String, Product> = BTreeMap::new();
    let mut nodes = 0usize;
    if let Some(tree) = doc.get("product_tree") {
        for b in tree
            .get("branches")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            walk(b, Trail::default(), 0, &mut nodes, &mut products);
        }
        for p in tree
            .get("full_product_names")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            leaf(p, &Trail::default(), &mut products);
        }
        relationships(tree, &mut products);
    }
    products
}

/// A product status of a CSAF document (a VEX document or an advisory): what the vendor says
/// about one CVE for one product.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusEntry {
    pub cve: String,
    pub vendor: String,
    pub products: Vec<String>,
    /// The names that narrow the product down, broadest first: the `product_family` and
    /// `product_name` branches above it, and its own name when no `product_name` branch is (a
    /// relationship: those of the platform). A statement for `S7-1200` > `CPU 1217C` is about
    /// the 1217C only, although `products` also holds the family for matching advisories.
    pub specific: Vec<String>,
    /// Versions in canonical form (`*` when the product names no version, see [`parse_range`]).
    pub range: String,
    /// `known_not_affected`, `fixed`, `known_affected` or `under_investigation`.
    pub status: &'static str,
    /// The flag label for the product (`vulnerable_code_not_present`, ...), may be empty.
    pub justification: String,
    /// The vendor's text: an impact statement for not-affected products, else the remediation.
    pub detail: String,
}

/// The product statuses of a CSAF 2.0 document: its tracking id, one entry per CVE, product
/// and status (`first_fixed` counts as `fixed`, `first_affected` and `last_affected` as
/// `known_affected`, `recommended` is not a status), and the number of pairs that could not be
/// used (no CVE id, a product id the tree does not define, a version text that is no range).
pub fn parse_statuses(bytes: &[u8]) -> Result<(String, Vec<StatusEntry>, usize), String> {
    let doc: Value = serde_json::from_slice(bytes).map_err(|e| format!("not JSON: {e}"))?;
    let document = doc
        .get("document")
        .ok_or("not a CSAF document: no `document`")?;
    let category = text(document, "category");
    if !category.starts_with("csaf_") {
        return Err(format!("not a CSAF document: category {category:?}"));
    }
    if !text(document, "csaf_version").starts_with("2.") {
        return Err("unsupported CSAF version (2.0 is read)".into());
    }
    let id = document
        .get("tracking")
        .map(|t| text(t, "id"))
        .filter(|id| !id.is_empty())
        .ok_or("the document has no tracking id")?;
    let products = product_tree(&doc);
    let vulns = doc
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .ok_or("the document has no vulnerabilities")?;
    let mut out = vec![];
    let mut skipped = 0;
    for v in vulns.iter().take(MAX_VULNERABILITIES) {
        let cve = text(v, "cve").to_ascii_uppercase();
        if !valid_cve(&cve) {
            skipped += 1;
            continue;
        }
        // Flags (the VEX justification) and impact statements per product id.
        let mut flag_of: BTreeMap<String, String> = BTreeMap::new();
        for f in v
            .get("flags")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let label = text(f, "label");
            for pid in ids(f.get("product_ids")) {
                flag_of.entry(pid).or_insert_with(|| label.clone());
            }
        }
        let mut impact_of: BTreeMap<String, String> = BTreeMap::new();
        for t in v
            .get("threats")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if text(t, "category") == "impact" {
                let details = text(t, "details");
                for pid in ids(t.get("product_ids")) {
                    impact_of.entry(pid).or_insert_with(|| details.clone());
                }
            }
        }
        let mut fix_of: BTreeMap<String, String> = BTreeMap::new();
        for r in v
            .get("remediations")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let details = text(r, "details");
            for pid in ids(r.get("product_ids")) {
                fix_of.entry(pid).or_insert_with(|| details.clone());
            }
        }
        let status = v.get("product_status");
        for (keys, label) in [
            (&["known_not_affected"][..], "known_not_affected"),
            (&["fixed", "first_fixed"][..], "fixed"),
            (
                &["known_affected", "first_affected", "last_affected"][..],
                "known_affected",
            ),
            (&["under_investigation"][..], "under_investigation"),
        ] {
            let mut pids: Vec<String> = keys
                .iter()
                .flat_map(|k| ids(status.and_then(|s| s.get(*k))))
                .collect();
            pids.sort();
            pids.dedup();
            for pid in pids {
                let Some(p) = products.get(&pid) else {
                    skipped += 1;
                    continue;
                };
                let range = match p.version.as_deref() {
                    None => "*".to_string(),
                    Some(v) => match parse_range(v) {
                        Some(r) => r,
                        None => {
                            skipped += 1;
                            continue;
                        }
                    },
                };
                if out.len() >= MAX_ENTRIES_PER_FILE {
                    break;
                }
                out.push(StatusEntry {
                    cve: cve.clone(),
                    vendor: p.vendor.clone(),
                    products: p.names.clone(),
                    specific: p.specific.clone(),
                    range,
                    status: label,
                    justification: flag_of.get(&pid).cloned().unwrap_or_default(),
                    detail: impact_of
                        .get(&pid)
                        .or_else(|| fix_of.get(&pid))
                        .cloned()
                        .unwrap_or_default(),
                });
            }
        }
    }
    Ok((id, out, skipped))
}

pub fn parse_csaf(bytes: &[u8]) -> Result<Parsed, String> {
    let doc: Value = serde_json::from_slice(bytes).map_err(|e| format!("not JSON: {e}"))?;
    let document = doc
        .get("document")
        .ok_or("not a CSAF document: no `document`")?;
    let category = text(document, "category");
    if !category.starts_with("csaf_") {
        return Err(format!("not a CSAF document: category {category:?}"));
    }
    let version = text(document, "csaf_version");
    if !version.starts_with("2.") {
        return Err(format!(
            "unsupported CSAF version {version:?} (2.0 is read)"
        ));
    }
    let advisory = document
        .get("tracking")
        .map(|t| text(t, "id"))
        .filter(|id| !id.is_empty())
        .ok_or("the advisory has no tracking id")?;
    let title = text(document, "title");
    let url = document
        .get("references")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|r| r.get("category").and_then(Value::as_str).unwrap_or("self") == "self")
        .map(|r| text(r, "url"))
        .find(|u| u.starts_with("https://") || u.starts_with("http://"))
        .unwrap_or_default();

    let products = product_tree(&doc);

    let mut parsed = Parsed {
        advisory: advisory.clone(),
        title,
        ..Default::default()
    };
    let vulns = doc
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .ok_or("the advisory has no vulnerabilities")?;
    for v in vulns.iter().take(MAX_VULNERABILITIES) {
        let cve = text(v, "cve").to_ascii_uppercase();
        if !valid_cve(&cve) {
            parsed.skipped += 1;
            continue;
        }
        let vuln_title = {
            let t = text(v, "title");
            if t.is_empty() { cve.clone() } else { t }
        };
        // CVSS per product id (and the best score overall, for products no score names).
        let mut score_of: BTreeMap<String, (u32, Option<String>)> = BTreeMap::new();
        let mut best: Option<(u32, Option<String>)> = None;
        for s in v
            .get("scores")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let cvss = s
                .get("cvss_v3")
                .or_else(|| s.get("cvss_v4"))
                .or_else(|| s.get("cvss_v2"));
            let Some(base) = cvss
                .and_then(|c| c.get("baseScore"))
                .and_then(Value::as_f64)
            else {
                continue;
            };
            if !(0.0..=10.0).contains(&base) {
                continue;
            }
            let tenths = (base * 10.0).round() as u32;
            let label = cvss
                .and_then(|c| c.get("baseSeverity"))
                .and_then(Value::as_str)
                .map(str::to_string);
            if best.as_ref().is_none_or(|(b, _)| tenths > *b) {
                best = Some((tenths, label.clone()));
            }
            for id in ids(s.get("products")) {
                let slot = score_of.entry(id).or_insert((0, None));
                if tenths >= slot.0 {
                    *slot = (tenths, label.clone());
                }
            }
        }
        // The first remediation of each product (vendor fixes first).
        let mut fix_of: BTreeMap<String, String> = BTreeMap::new();
        let mut remediations: Vec<&Value> = v
            .get("remediations")
            .and_then(Value::as_array)
            .map(|a| a.iter().collect())
            .unwrap_or_default();
        remediations.sort_by_key(|r| text(r, "category") != "vendor_fix");
        for r in remediations {
            let details = text(r, "details");
            for id in ids(r.get("product_ids")) {
                fix_of.entry(id).or_insert_with(|| details.clone());
            }
        }
        let status = v.get("product_status");
        let mut affected: Vec<String> = vec![];
        for key in ["known_affected", "first_affected", "last_affected"] {
            affected.extend(ids(status.and_then(|s| s.get(key))));
        }
        affected.sort();
        affected.dedup();
        for id in affected {
            let Some(p) = products.get(&id) else {
                parsed.skipped += 1;
                continue;
            };
            let Some(range) = p.version.as_deref().and_then(parse_range) else {
                parsed.skipped += 1;
                continue;
            };
            let (tenths, label) = score_of.get(&id).cloned().or_else(|| best.clone()).unzip();
            let entry = Entry {
                advisory: advisory.clone(),
                cve: cve.clone(),
                title: vuln_title.clone(),
                severity: severity_of(tenths.unwrap_or(0), label.flatten().as_deref()),
                cvss: tenths,
                vendor: p.vendor.clone(),
                products: p.names.clone(),
                range,
                fix: fix_of.get(&id).cloned().unwrap_or_default(),
                url: url.clone(),
            };
            if parsed.entries.len() >= MAX_ENTRIES_PER_FILE {
                break;
            }
            if !parsed.entries.iter().any(|e| {
                e.cve == entry.cve
                    && e.vendor == entry.vendor
                    && e.products == entry.products
                    && e.range == entry.range
            }) {
                parsed.entries.push(entry);
            }
        }
    }
    Ok(parsed)
}

// ---- matching ------------------------------------------------------------------------------

/// Letters and digits only, lower case: `6ES7 214-1AG40` and `6es72141ag40` compare equal.
pub(crate) fn norm(s: &str) -> String {
    s.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

pub(crate) fn vendor_matches(a: &str, b: &str) -> bool {
    let (a, b) = (norm(a), norm(b));
    a.len() >= 3 && b.len() >= 3 && (a.contains(&b) || b.contains(&a))
}

/// `S7-1200` for `CPU 1214C`, `S7-1500` for `CPU 1511-1 PN`, `S7-300` for `CPU 315-2 DP`:
/// advisories name the family, the S7 identification gives the CPU. Only Siemens CPU names of
/// the common families are recognised.
pub(crate) fn siemens_family(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    let at = lower.find("cpu")?;
    let digits: String = lower[at + 3..]
        .trim_start()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    match (digits.len(), digits.get(..2)) {
        (4, Some("12")) => Some("S7-1200"),
        (4, Some("15")) => Some("S7-1500"),
        (4, Some("18")) => Some("S7-1500"),
        (3, Some("31")) | (3, Some("32")) => Some("S7-300"),
        (3, Some("41")) | (3, Some("42")) => Some("S7-400"),
        _ => None,
    }
}

/// Whether a device's names match a product's names: the matching rule of the advisories
/// (normalised names of at least 5 characters, one containing the other; Siemens S7 CPUs also by
/// their family), for callers with plain names (VEX statements, SBOMs).
pub(crate) fn names_match(device: &[String], wanted: &[String]) -> bool {
    let mut names: Vec<String> = device.iter().map(|n| norm(n)).collect();
    for n in device {
        if let Some(f) = siemens_family(n) {
            names.push(norm(f));
        }
    }
    let wanted: Vec<String> = wanted.iter().map(|w| norm(w)).collect();
    names.iter().filter(|n| n.len() >= 5).any(|n| {
        wanted
            .iter()
            .filter(|w| w.len() >= 5)
            .any(|w| n.contains(w.as_str()) || w.contains(n.as_str()))
    })
}

fn product_matches(device: &OtDevice, entry: &Entry) -> bool {
    let mut names: Vec<String> = device.products.iter().map(|p| norm(p)).collect();
    if device.protocol == "S7" {
        for p in &device.products {
            if let Some(f) = siemens_family(p) {
                names.push(norm(f));
            }
        }
    }
    let wanted: Vec<String> = entry.products.iter().map(|p| norm(p)).collect();
    names.iter().filter(|n| n.len() >= 5).any(|n| {
        wanted
            .iter()
            .filter(|w| w.len() >= 5)
            .any(|w| n.contains(w.as_str()) || w.contains(n.as_str()))
    })
}

impl Csaf {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Adds the entries of an advisory, replacing the ones the same advisory gave before.
    pub fn merge(&mut self, parsed: Parsed, source: &str) -> Result<(), String> {
        self.entries.retain(|e| e.advisory != parsed.advisory);
        if self.entries.len() + parsed.entries.len() > MAX_ENTRIES {
            return Err(format!("the cache would exceed {MAX_ENTRIES} entries"));
        }
        self.entries.extend(parsed.entries);
        if !self.sources.iter().any(|s| s == source) && self.sources.len() < 100_000 {
            self.sources.push(source.chars().take(120).collect());
        }
        Ok(())
    }

    /// A SHA-256 of the imported advisories (the content of the cache), for the provenance stamp.
    pub fn fingerprint(&self) -> String {
        crate::provenance::hash(&serde_json::to_vec(self).unwrap_or_default())
    }

    /// The advisories' CVEs that apply to `device`, strongest first, one per CVE.
    pub fn lookup(&self, device: &OtDevice) -> Vec<Hit> {
        let mut hits: BTreeMap<String, Hit> = BTreeMap::new();
        for e in &self.entries {
            if !e.vendor.is_empty()
                && !device.vendor.is_empty()
                && !vendor_matches(&e.vendor, &device.vendor)
            {
                continue;
            }
            // Without a vendor on the device (OPC UA) the product name has to carry the match.
            if !product_matches(device, e) || !range_holds(&e.range, &device.version) {
                continue;
            }
            let hit = hits.entry(e.cve.clone()).or_insert_with(|| Hit {
                cve: e.cve.clone(),
                severity: e.severity,
                cvss: e.cvss,
                title: e.title.clone(),
                advisories: vec![],
                range: e.range.clone(),
                fix: e.fix.clone(),
                url: if e.url.starts_with("https://") {
                    e.url.clone()
                } else {
                    String::new()
                },
            });
            if !hit.advisories.contains(&e.advisory) {
                hit.advisories.push(e.advisory.clone());
            }
            if (e.severity, e.cvss) > (hit.severity, hit.cvss) {
                hit.severity = e.severity;
                hit.cvss = e.cvss;
                hit.range = e.range.clone();
            }
            if hit.fix.is_empty() {
                hit.fix = e.fix.clone();
            }
        }
        let mut out: Vec<Hit> = hits.into_values().collect();
        for h in &mut out {
            h.advisories.sort();
        }
        out.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.cve.cmp(&b.cve)));
        out
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        Self::read(path)?.map_err(|version| {
            format!(
                "{}: cache version {version} is not supported (expected {CACHE_VERSION}); import the advisories again",
                path.display()
            )
        })
    }

    /// [`Self::load`], with a cache that an older version of the program wrote told apart as
    /// `Ok(Err(its version))`: that one is expected after an upgrade, and an import starts
    /// over. Every other file that does not load is an error, and is never written over.
    fn read(path: &Path) -> Result<Result<Self, u32>, String> {
        /// What a cache of any version has. The version alone does not make a file a cache: a
        /// CycloneDX document and the caches next to this one have a top-level `version` too.
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct Header {
            version: u32,
            entries: Vec<serde::de::IgnoredAny>,
        }
        let size = std::fs::metadata(path)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .len();
        if size > MAX_CACHE_BYTES {
            return Err(format!("{}: file is too large", path.display()));
        }
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        match serde_json::from_slice::<Self>(&bytes) {
            Ok(cache) if cache.version == CACHE_VERSION => Ok(Ok(cache)),
            Ok(cache) if cache.version < CACHE_VERSION => Ok(Err(cache.version)),
            Ok(cache) => Err(format!(
                "{}: cache version {} is not supported (expected {CACHE_VERSION}); a newer version of the program wrote it",
                path.display(),
                cache.version
            )),
            // An older version may have stored its entries in another shape.
            Err(e) => match serde_json::from_slice::<Header>(&bytes) {
                Ok(header) if header.version < CACHE_VERSION => Ok(Err(header.version)),
                _ => Err(format!("{}: not a CSAF cache: {e}", path.display())),
            },
        }
    }

    /// Writes the cache through a temporary file, so an interrupted import keeps the old one.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        crate::feeds::check_size(bytes.len(), MAX_CACHE_BYTES, path)?;
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        std::fs::write(&tmp, bytes).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!("{}: {e}", path.display())
        })
    }
}

/// `csaf.json` next to `feeds.json`.
pub fn default_path() -> Option<PathBuf> {
    crate::feeds::default_path().map(|p| p.with_file_name("csaf.json"))
}

/// The files an import argument names: the file itself, or the `.json` files of a directory
/// (one level down as well, sorted, at most [`MAX_FILES`]).
fn expand(path: &Path) -> Result<Vec<PathBuf>, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !meta.is_dir() {
        return Ok(vec![path.to_path_buf()]);
    }
    let mut files = vec![];
    let mut stack = vec![(path.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        for entry in std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))? {
            let p = entry.map_err(|e| e.to_string())?.path();
            if p.is_dir() && depth < 1 {
                stack.push((p, depth + 1));
            } else if p
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("json"))
            {
                files.push(p);
                if files.len() > MAX_FILES {
                    return Err(format!("more than {MAX_FILES} files in {}", path.display()));
                }
            }
        }
    }
    files.sort();
    Ok(files)
}

/// What an import did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub cache: PathBuf,
    pub advisories: usize,
    pub entries: usize,
    pub skipped_products: usize,
    /// Files that were not CSAF advisories (name and reason).
    pub rejected: Vec<String>,
    pub total_entries: usize,
}
impl ImportReport {
    pub fn lines(&self) -> Vec<String> {
        let mut out = vec![format!(
            "CSAF: {} advisories, {} affected-product entries ({} product/vulnerability pairs skipped: no usable version range)",
            self.advisories, self.entries, self.skipped_products
        )];
        for r in self.rejected.iter().take(20) {
            out.push(format!("Skipped {r}"));
        }
        if self.rejected.len() > 20 {
            out.push(format!(
                "... and {} more skipped files",
                self.rejected.len() - 20
            ));
        }
        out.push(format!(
            "{} entries in the cache {}",
            self.total_entries,
            self.cache.display()
        ));
        out
    }
}

/// Imports advisory files or directories into the cache at `cache`. A file that is not a CSAF
/// advisory is reported and skipped; nothing is written when no file could be used.
pub fn import(paths: &[PathBuf], cache: &Path, now: u64) -> Result<ImportReport, String> {
    if paths.is_empty() {
        return Err("Provide one or more CSAF files or folders".into());
    }
    let mut files = vec![];
    for p in paths {
        files.extend(expand(p)?);
    }
    let mut csaf = if cache.exists() {
        // A cache of an older version starts over (its files are imported again). A file that
        // does not load for any other reason stays as it is: it may be no cache at all (the
        // cache option naming an advisory), and saving would write over it.
        Csaf::read(cache)
            .map_err(|e| format!("{e}; nothing was imported and the file is unchanged"))?
            .unwrap_or_default()
    } else {
        Csaf::default()
    };
    let mut report = ImportReport {
        cache: cache.to_path_buf(),
        ..Default::default()
    };
    let mut seen = BTreeSet::new();
    for file in files {
        let name = file.file_name().map_or_else(
            || file.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        let size = std::fs::metadata(&file)
            .map_err(|e| format!("{}: {e}", file.display()))?
            .len();
        if size > MAX_FILE_BYTES {
            report.rejected.push(format!("{name}: file is too large"));
            continue;
        }
        let bytes = std::fs::read(&file).map_err(|e| format!("{}: {e}", file.display()))?;
        if bytes.starts_with(&[0x1f, 0x8b]) {
            report
                .rejected
                .push(format!("{name}: gzip-compressed, unpack it first"));
            continue;
        }
        match parse_csaf(&bytes) {
            Ok(parsed) => {
                report.skipped_products += parsed.skipped;
                report.entries += parsed.entries.len();
                if seen.insert(parsed.advisory.clone()) {
                    report.advisories += 1;
                }
                csaf.merge(parsed, &name)?;
            }
            Err(e) => report.rejected.push(format!("{name}: {e}")),
        }
    }
    if report.advisories == 0 {
        return Err(format!(
            "No CSAF advisory could be read ({})",
            report.rejected.first().map_or("no files", String::as_str)
        ));
    }
    csaf.version = CACHE_VERSION;
    csaf.imported_at = now;
    csaf.save(cache)?;
    report.total_entries = csaf.entries.len();
    Ok(report)
}

/// `feeds status`: what the cache holds.
pub fn status(csaf: &Csaf, path: &Path) -> Value {
    let advisories: BTreeSet<&str> = csaf.entries.iter().map(|e| e.advisory.as_str()).collect();
    let cves: BTreeSet<&str> = csaf.entries.iter().map(|e| e.cve.as_str()).collect();
    serde_json::json!({
        "cache": path.display().to_string(),
        "imported_at": csaf.imported_at,
        "advisories": advisories.len(),
        "cves": cves.len(),
        "entries": csaf.entries.len(),
        "sources": csaf.sources.iter().take(50).collect::<Vec<_>>(),
    })
}

// ---- Active advisories ---------------------------------------------------------------------

static ACTIVE: crate::feeds::ActiveCache<Csaf> =
    crate::feeds::ActiveCache::new("CSAF", "advisories are not used", default_path, Csaf::load);

/// Makes the cache at `explicit` (`--csaf FILE`) the active advisories; an error when it is
/// missing or unreadable.
pub fn load_active(explicit: &Path) -> Result<(), String> {
    ACTIVE.set(explicit)
}

/// The active advisories: the explicit cache, else the default cache when it exists, else
/// nothing. Tests never read the developer's own cache.
pub fn active() -> Arc<Csaf> {
    ACTIVE.get()
}

/// Reads the cache again when its file changed since it was loaded (see `feeds::refresh`).
pub fn refresh() {
    ACTIVE.refresh()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIEMENS: &str = include_str!("../../tests/fixtures/csaf/icsa-test-0001-siemens-s7.json");
    const ROCKWELL: &str =
        include_str!("../../tests/fixtures/csaf/icsa-test-0002-rockwell-cip.json");
    const OPCUA: &str = include_str!("../../tests/fixtures/csaf/icsa-test-0003-opcua-gateway.json");

    pub(crate) fn fixture_cache() -> Csaf {
        let mut c = Csaf::default();
        for (name, text) in [
            ("siemens", SIEMENS),
            ("rockwell", ROCKWELL),
            ("opcua", OPCUA),
        ] {
            c.merge(parse_csaf(text.as_bytes()).unwrap(), name).unwrap();
        }
        c
    }

    fn device(protocol: &'static str, vendor: &str, products: &[&str], version: &str) -> OtDevice {
        OtDevice {
            protocol,
            port: 102,
            vendor: vendor.into(),
            products: products.iter().map(|p| p.to_string()).collect(),
            version: version.into(),
        }
    }

    #[test]
    fn range_texts_are_understood_and_normalised() {
        for (text, want) in [
            ("vers:all/*", Some("*")),
            ("All versions", Some("*")),
            ("*", Some("*")),
            ("<V4.5.1", Some("<4.5.1")),
            ("< V4.5.1", Some("<4.5.1")),
            ("<=4.5", Some("<=4.5")),
            ("V4.5.1", Some("=4.5.1")),
            ("vers:intdot/>=2.0|<2.7.1", Some(">=2.0|<2.7.1")),
            (">=V2.0|<V2.7.1", Some(">=2.0|<2.7.1")),
            ("vers:semver/<4.5.1", Some("<4.5.1")),
            ("all versions < V4.5.1", Some("<4.5.1")),
            ("V4.5 and earlier", Some("<=4.5")),
            ("prior to V3.1", Some("<3.1")),
            ("vers:intdot/!=2.0", None),
            ("", None),
            ("see advisory", None),
            ("<", None),
            ("vers:all", None),
        ] {
            assert_eq!(parse_range(text).as_deref(), want, "{text:?}");
        }
        assert_eq!(parse_range(&"1".repeat(300)), None, "bounded");
    }

    #[test]
    fn ranges_hold_at_their_boundaries() {
        let r = ">=2.0|<2.7.1";
        assert!(range_holds(r, "2.0") && range_holds(r, "V2.5") && range_holds(r, "2.7"));
        assert!(!range_holds(r, "2.7.1") && !range_holds(r, "1.9") && !range_holds(r, "2.7.2"));
        assert!(range_holds("<=4.5", "4.5") && !range_holds("<=4.5", "4.5.1"));
        assert!(range_holds("=4.5.1", "V4.5.1") && range_holds("=4.5", "4.5.0"));
        assert!(
            range_holds("*", "") && !range_holds("<4.5", ""),
            "no version, only `*`"
        );
        assert!(!range_holds("<4.5", "not a version"));
    }

    #[test]
    fn the_fixtures_parse_into_entries() {
        let s = parse_csaf(SIEMENS.as_bytes()).unwrap();
        assert_eq!(s.advisory, "ICSA-TEST-0001");
        let cves: Vec<&str> = s.entries.iter().map(|e| e.cve.as_str()).collect();
        assert!(
            cves.contains(&"CVE-2099-1001") && cves.contains(&"CVE-2099-1002"),
            "{cves:?}"
        );
        let e = s.entries.iter().find(|e| e.cve == "CVE-2099-1001").unwrap();
        assert_eq!(e.vendor, "Siemens");
        assert_eq!(e.range, "<4.5.1");
        assert_eq!(e.severity, Severity::Critical);
        assert_eq!(e.cvss, Some(98));
        assert!(e.fix.contains("V4.5.1"), "{}", e.fix);
        assert!(
            e.products.iter().any(|p| p.contains("S7-1200")),
            "{:?}",
            e.products
        );
        assert!(e.url.starts_with("https://"));
        // a product that is only known_not_affected or fixed yields nothing, and a vulnerability
        // without a CVE id is skipped and counted
        assert!(!cves.contains(&"CVE-2099-1003"), "known_not_affected only");
        assert!(s.skipped >= 1);
        let r = parse_csaf(ROCKWELL.as_bytes()).unwrap();
        assert_eq!(r.entries[0].range, ">=20.0|<20.14");
        assert_eq!(r.entries[0].vendor, "Rockwell Automation");
        let o = parse_csaf(OPCUA.as_bytes()).unwrap();
        assert_eq!(o.entries[0].range, "*");
    }

    #[test]
    fn a_siemens_cpu_matches_by_family_and_firmware() {
        let c = fixture_cache();
        let s7 = |version: &str| {
            c.lookup(&device(
                "S7",
                "Siemens",
                &["6ES7 214-1AG40-0XB0", "CPU 1214C DC/DC/DC"],
                version,
            ))
        };
        let hits = s7("V4.2.3");
        let cves: Vec<&str> = hits.iter().map(|h| h.cve.as_str()).collect();
        assert!(cves.contains(&"CVE-2099-1001"), "{cves:?}");
        assert_eq!(hits[0].severity, Severity::Critical, "strongest first");
        assert_eq!(hits[0].advisories, ["ICSA-TEST-0001"]);
        // the fixed version, and a version the range excludes, do not match
        assert!(s7("4.5.1").iter().all(|h| h.cve != "CVE-2099-1001"));
        assert!(s7("V4.6").is_empty());
        // an unknown firmware matches nothing that has a bounded range
        assert!(s7("").is_empty());
        // a different family or vendor does not match
        assert!(
            c.lookup(&device("S7", "Siemens", &["CPU 1511-1 PN"], "V1.0"))
                .iter()
                .all(|h| h.cve != "CVE-2099-1001"),
            "S7-1500 is not in the S7-1200 advisory"
        );
        assert!(
            c.lookup(&device(
                "Modbus",
                "Schneider Electric",
                &["CPU 1214C"],
                "V4.2.3"
            ))
            .is_empty(),
            "vendor mismatch"
        );
    }

    #[test]
    fn a_cip_device_matches_inside_its_range_only() {
        let c = fixture_cache();
        let cip = |v: &str| {
            c.lookup(&device(
                "EtherNet/IP",
                "Rockwell Automation/Allen-Bradley",
                &["1756-L81E"],
                v,
            ))
        };
        assert_eq!(cip("20.11").len(), 1);
        assert_eq!(cip("20.11")[0].cve, "CVE-2099-2001");
        assert!(cip("20.14").is_empty() && cip("19.9").is_empty());
        assert!(cip("20.11")[0].fix.contains("20.14"));
    }

    #[test]
    fn all_versions_matches_by_product_without_a_firmware() {
        let c = fixture_cache();
        let hits = c.lookup(&device("OPC UA", "", &["Example OPC UA Gateway"], ""));
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].range, "*");
        assert!(
            c.lookup(&device("OPC UA", "", &["Other Server"], ""))
                .is_empty(),
            "another product"
        );
    }

    const RELATIONSHIPS_FIXTURE: &str =
        include_str!("../../tests/fixtures/csaf/icsa-test-0004-relationships.json");

    fn relationship_cache() -> Csaf {
        let mut c = Csaf::default();
        c.merge(
            parse_csaf(RELATIONSHIPS_FIXTURE.as_bytes()).unwrap(),
            "relationships",
        )
        .unwrap();
        c
    }

    #[test]
    fn a_product_defined_by_a_relationship_becomes_an_entry() {
        let p = parse_csaf(RELATIONSHIPS_FIXTURE.as_bytes()).unwrap();
        assert_eq!(p.advisory, "ICSA-TEST-0004");
        let find =
            |cve: &str| -> Vec<&Entry> { p.entries.iter().filter(|e| e.cve == cve).collect() };
        // firmware (the component) "installed on" nothing but its hardware: vendor and hardware
        // name come from the platform, the range from the component
        let reboot = find("CVE-2099-4001");
        assert_eq!(reboot.len(), 1, "{reboot:?}");
        assert_eq!(reboot[0].range, "<2.8.0");
        assert_eq!(reboot[0].vendor, "Examplon Controls");
        assert!(
            reboot[0]
                .products
                .iter()
                .any(|n| n == "Examplon EX-500 PLC")
        );
        assert!(
            reboot[0]
                .products
                .iter()
                .any(|n| n == "Examplon EX-500 firmware")
        );
        assert_eq!(reboot[0].cvss, Some(75));
        assert!(reboot[0].fix.contains("2.8.0"));
        // model numbers of the platform carry over, and a chain (agent installed on a pair that
        // is itself runtime installed on hardware) inherits the range of the pair
        let disclosure = find("CVE-2099-4002");
        assert_eq!(disclosure.len(), 2, "{disclosure:?}");
        assert!(disclosure.iter().all(|e| e.range == ">=1.0|<1.4"));
        assert!(
            disclosure
                .iter()
                .all(|e| e.products.iter().any(|n| n == "EX-700-A"))
        );
        assert!(
            disclosure
                .iter()
                .any(|e| e.products.iter().any(|n| n == "Examplon Cloud Agent"))
        );
        // an all-versions component
        assert_eq!(find("CVE-2099-4003")[0].range, "*");
        // known_not_affected is not an entry; the product ids no tree part defines, the pair with
        // undefined parts and the pair without any version are skipped and counted
        assert_eq!(p.entries.len(), 4, "{:#?}", p.entries);
        assert_eq!(p.skipped, 3, "4031, 4099 and 4032");
    }

    #[test]
    fn a_device_matches_a_relationship_product_by_hardware_name_and_firmware() {
        let c = relationship_cache();
        let ex500 = |version: &str| {
            c.lookup(&device(
                "Modbus",
                "Examplon Controls",
                &["Examplon EX-500 PLC"],
                version,
            ))
        };
        let hits = ex500("2.7.1");
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].cve, "CVE-2099-4001");
        assert_eq!(hits[0].advisories, ["ICSA-TEST-0004"]);
        assert_eq!(hits[0].severity, Severity::High);
        assert!(ex500("2.8.0").is_empty(), "the fixed version");
        assert!(ex500("3.0").is_empty());
        assert!(
            ex500("").is_empty(),
            "no firmware: only all-versions ranges"
        );
        // the vendor must agree
        assert!(
            c.lookup(&device(
                "Modbus",
                "Other Vendor",
                &["Examplon EX-500 PLC"],
                "2.7.1"
            ))
            .is_empty()
        );
        // found by the model number of the platform; the runtime range decides
        let ex700 = |version: &str| {
            c.lookup(&device(
                "Modbus",
                "Examplon Controls",
                &["EX-700-A"],
                version,
            ))
        };
        assert_eq!(ex700("1.2").len(), 1);
        assert!(ex700("1.4").is_empty() && ex700("0.9").is_empty());
    }

    #[test]
    fn a_device_without_firmware_matches_only_all_versions_relationship_products() {
        let c = relationship_cache();
        let hits = c.lookup(&device(
            "Modbus",
            "Examplon Controls",
            &["Examplon EX-900 PLC"],
            "",
        ));
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].cve, "CVE-2099-4003");
        assert_eq!(hits[0].range, "*");
        // the same device with a firmware matches too: every version is affected
        assert_eq!(
            c.lookup(&device(
                "Modbus",
                "Examplon Controls",
                &["Examplon EX-900 PLC"],
                "9.9"
            ))
            .len(),
            1
        );
        // the EX-500 has a bounded range, so without firmware nothing is reported
        assert!(
            c.lookup(&device(
                "Modbus",
                "Examplon Controls",
                &["Examplon EX-500 PLC"],
                ""
            ))
            .is_empty()
        );
    }

    #[test]
    fn relationship_chains_and_cycles_are_bounded() {
        // A is installed on B and B on A: neither is defined first, so neither resolves, and
        // nothing loops
        let cyclic = r#"{"document":{"category":"csaf_security_advisory","csaf_version":"2.0","tracking":{"id":"C-1"}},
          "product_tree":{"branches":[{"category":"vendor","name":"Examplon Controls","branches":[
            {"category":"product_name","name":"Alpha Controller","product":{"product_id":"A","name":"Alpha Controller"}},
            {"category":"product_version","name":"<1.0","product":{"product_id":"B","name":"Beta firmware <1.0"}}]}],
           "relationships":[
            {"category":"installed_on","product_reference":"P2","relates_to_product_reference":"P1","full_product_name":{"product_id":"P1","name":"p1"}},
            {"category":"installed_on","product_reference":"P1","relates_to_product_reference":"P2","full_product_name":{"product_id":"P2","name":"p2"}},
            {"category":"installed_on","product_reference":"B","relates_to_product_reference":"A","full_product_name":{"product_id":"AB","name":"Beta on Alpha"}},
            {"category":"not_a_relationship","product_reference":"B","relates_to_product_reference":"A","full_product_name":{"product_id":"XX","name":"ignored"}}]},
          "vulnerabilities":[{"cve":"CVE-2099-0010","product_status":{"known_affected":["P1","P2","AB","XX"]}}]}"#;
        let p = parse_csaf(cyclic.as_bytes()).unwrap();
        assert_eq!(p.entries.len(), 1, "{:?}", p.entries);
        assert_eq!(p.entries[0].range, "<1.0");
        assert_eq!(p.skipped, 3, "P1, P2 and XX are not products");
        // a long chain resolves a bounded number of levels
        let mut chain = String::from(
            r#"{"document":{"category":"csaf_security_advisory","csaf_version":"2.0","tracking":{"id":"L-1"}},"product_tree":{"branches":[{"category":"vendor","name":"Examplon Controls","branches":[{"category":"product_version","name":"<1.0","product":{"product_id":"N0","name":"Gamma firmware"}}]}],"relationships":["#,
        );
        for i in (1..=20).rev() {
            chain.push_str(&format!(
                r#"{{"category":"installed_on","product_reference":"N0","relates_to_product_reference":"N{}","full_product_name":{{"product_id":"N{i}","name":"n{i}"}}}},"#,
                i - 1
            ));
        }
        chain.pop();
        chain.push_str(r#"]},"vulnerabilities":[{"cve":"CVE-2099-0011","product_status":{"known_affected":["N1","N8","N9","N20"]}}]}"#);
        let p = parse_csaf(chain.as_bytes()).unwrap();
        // listed in reverse order, so each pass resolves one level: N1..N8 resolve (N1 and N8
        // are the same product to the matcher, one entry), N9 and above do not
        assert_eq!(p.entries.len(), 1, "{:?}", p.entries);
        assert_eq!(p.skipped, 2, "N9 and N20");
    }

    #[test]
    fn a_cve_in_two_advisories_is_one_hit_naming_both() {
        let mut c = fixture_cache();
        let mut second = parse_csaf(SIEMENS.as_bytes()).unwrap();
        second.advisory = "ICSA-TEST-0009".into();
        for e in &mut second.entries {
            e.advisory = "ICSA-TEST-0009".into();
        }
        c.merge(second, "second").unwrap();
        let hits = c.lookup(&device("S7", "Siemens", &["CPU 1214C"], "4.2"));
        let one = hits.iter().filter(|h| h.cve == "CVE-2099-1001").count();
        assert_eq!(one, 1);
        assert_eq!(
            hits.iter()
                .find(|h| h.cve == "CVE-2099-1001")
                .unwrap()
                .advisories,
            ["ICSA-TEST-0001", "ICSA-TEST-0009"]
        );
    }

    #[test]
    fn re_importing_an_advisory_replaces_its_entries() {
        let mut c = fixture_cache();
        let before = c.entries.len();
        c.merge(parse_csaf(SIEMENS.as_bytes()).unwrap(), "again")
            .unwrap();
        assert_eq!(c.entries.len(), before);
    }

    #[test]
    fn family_names_come_from_the_cpu_designation() {
        for (name, family) in [
            ("CPU 1214C DC/DC/DC", Some("S7-1200")),
            ("CPU 1511-1 PN", Some("S7-1500")),
            ("CPU1518-4 PN/DP", Some("S7-1500")),
            ("CPU 315-2 DP", Some("S7-300")),
            ("CPU 414-3 PN/DP", Some("S7-400")),
            ("CPU 12", None),
            ("Plant controller", None),
            ("6ES7 214-1AG40-0XB0", None),
        ] {
            assert_eq!(siemens_family(name), family, "{name}");
        }
    }

    #[test]
    fn documents_that_are_not_csaf_are_rejected_without_a_panic() {
        for bad in [
            "",
            "null",
            "[]",
            "{}",
            r#"{"document":{"category":"other","csaf_version":"2.0"}}"#,
            r#"{"document":{"category":"csaf_security_advisory","csaf_version":"1.0"}}"#,
            r#"{"document":{"category":"csaf_security_advisory","csaf_version":"2.0","tracking":{"id":"X"}}}"#,
            r#"{"document":{"category":"csaf_security_advisory","csaf_version":"2.0"},"vulnerabilities":[]}"#,
        ] {
            assert!(parse_csaf(bad.as_bytes()).is_err(), "{bad:?}");
        }
        // a valid shell with nothing usable inside is fine and empty
        let p = parse_csaf(
            br#"{"document":{"category":"csaf_security_advisory","csaf_version":"2.0","tracking":{"id":"X-1"}},"vulnerabilities":[{"cve":"nope"},{"cve":"CVE-2099-0001","product_status":{"known_affected":["missing"]}}]}"#,
        )
        .unwrap();
        assert!(p.entries.is_empty());
        assert_eq!(p.skipped, 2);
    }

    #[test]
    fn deeply_nested_and_huge_trees_are_bounded() {
        let mut deep = String::new();
        for _ in 0..200 {
            deep.push_str(r#"{"category":"product_family","name":"x","branches":["#);
        }
        deep.push_str(r#"{"category":"product_version","name":"1.0","product":{"product_id":"P","name":"deep"}}"#);
        for _ in 0..200 {
            deep.push_str("]}");
        }
        let doc = format!(
            r#"{{"document":{{"category":"csaf_security_advisory","csaf_version":"2.0","tracking":{{"id":"D-1"}}}},"product_tree":{{"branches":[{deep}]}},"vulnerabilities":[{{"cve":"CVE-2099-0002","product_status":{{"known_affected":["P"]}}}}]}}"#
        );
        // serde_json refuses nesting beyond its recursion limit; either way no panic
        let _ = parse_csaf(doc.as_bytes());
        let mut wide = String::from(
            r#"{"document":{"category":"csaf_security_advisory","csaf_version":"2.0","tracking":{"id":"W-1"}},"product_tree":{"branches":["#,
        );
        for i in 0..2000 {
            if i > 0 {
                wide.push(',');
            }
            wide.push_str(&format!(
                r#"{{"category":"product_version","name":"<1.{i}","product":{{"product_id":"P{i}","name":"Example Product {i}"}}}}"#
            ));
        }
        wide.push_str(r#"]},"vulnerabilities":[{"cve":"CVE-2099-0003","product_status":{"known_affected":["P1","P1999"]}}]}"#);
        let p = parse_csaf(wide.as_bytes()).unwrap();
        assert_eq!(p.entries.len(), 2);
    }

    #[test]
    fn import_reads_files_and_folders_and_keeps_a_cache() {
        let dir = std::env::temp_dir().join(format!("ns-csaf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let advisories = dir.join("advisories");
        std::fs::create_dir_all(&advisories).unwrap();
        std::fs::write(advisories.join("a.json"), SIEMENS).unwrap();
        std::fs::write(advisories.join("b.json"), ROCKWELL).unwrap();
        std::fs::write(advisories.join("junk.json"), "{}").unwrap();
        std::fs::write(advisories.join("notes.txt"), "ignored").unwrap();
        let cache = dir.join("csaf.json");
        let report = import(std::slice::from_ref(&advisories), &cache, 7).unwrap();
        assert_eq!(report.advisories, 2);
        assert_eq!(report.rejected.len(), 1, "{:?}", report.rejected);
        assert!(report.rejected[0].starts_with("junk.json"));
        let loaded = Csaf::load(&cache).unwrap();
        assert_eq!(loaded.imported_at, 7);
        assert_eq!(loaded.entries.len(), report.total_entries);
        // a second import of one file adds to the cache
        let one = dir.join("opcua.json");
        std::fs::write(&one, OPCUA).unwrap();
        let more = import(&[one], &cache, 8).unwrap();
        assert_eq!(more.total_entries, report.total_entries + 1);
        assert_eq!(
            status(&Csaf::load(&cache).unwrap(), &cache)["advisories"],
            3
        );
        // nothing usable, a missing file and gzip are errors that name the problem
        assert!(import(&[dir.join("none.json")], &cache, 9).is_err());
        let gz = dir.join("a.json.gz");
        std::fs::write(&gz, [0x1f, 0x8b, 8]).unwrap();
        let e = import(&[gz], &cache, 9).unwrap_err();
        assert!(e.contains("unpack it first"), "{e}");
        assert!(import(&[], &cache, 9).is_err());
        // a cache of another version is refused, not misread
        std::fs::write(&cache, r#"{"version":99,"entries":[]}"#).unwrap();
        assert!(Csaf::load(&cache).unwrap_err().contains("version 99"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What stands at the cache path decides what an import may do with it: only a cache of
    /// this version is added to, one of an older version starts over, and anything else is
    /// left alone.
    #[test]
    fn an_import_never_writes_over_a_file_it_could_not_load() {
        let dir = std::env::temp_dir().join(format!("ns-csaf-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (advisory, cache) = (dir.join("a.json"), dir.join("csaf.json"));
        std::fs::write(&advisory, SIEMENS).unwrap();
        let import = || import(std::slice::from_ref(&advisory), &cache, 7);
        let newer = format!(r#"{{"version":{},"entries":[]}}"#, CACHE_VERSION + 1);
        // An advisory where the cache should be (`--csaf advisory.json`), a document that has a
        // `version` of its own, a damaged file and a cache from a newer version of the program.
        for (case, content) in [
            ("an advisory", SIEMENS),
            ("CycloneDX", r#"{"bomFormat":"CycloneDX","version":1}"#),
            ("any JSON object", "{}"),
            ("damaged", r#"{"version":1,"imported_at":1,"entr"#),
            ("empty", ""),
            ("newer", newer.as_str()),
        ] {
            std::fs::write(&cache, content).unwrap();
            let e = import().unwrap_err();
            assert!(e.contains("the file is unchanged"), "{case}: {e}");
            assert_eq!(std::fs::read_to_string(&cache).unwrap(), content, "{case}");
        }
        // A cache an older version wrote, also one with entries this version cannot read: the
        // import starts over.
        for old in [
            r#"{"version":0,"entries":[]}"#,
            r#"{"version":0,"entries":[{"shape":"of version 0"}]}"#,
        ] {
            std::fs::write(&cache, old).unwrap();
            assert!(
                Csaf::load(&cache)
                    .unwrap_err()
                    .contains("import the advisories again")
            );
            let report = import().unwrap();
            let loaded = Csaf::load(&cache).unwrap();
            assert_eq!(
                (loaded.version, loaded.entries.len()),
                (CACHE_VERSION, report.entries),
                "{old}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
