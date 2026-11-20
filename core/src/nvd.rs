//! Offline NVD CVE feed: imports the NVD "CVE JSON 2.0" files (`nvdcve-2.0-<year>.json`, or an
//! API 2.0 response saved to a file), keeps for every CVE the CPE ranges that name a vulnerable
//! application or operating system, and matches the CPE names the scanner derives
//! (`svc.<port>.cpe`) against them to produce `cve` findings.
//!
//! Nothing here touches the network; the user downloads the files. The index lives in its own
//! cache file (`nvd.json` next to `feeds.json`) because a full NVD import is large, and it is
//! loaded only when a scan has a CPE to look up. The built-in `data/cves.json` stays the
//! fallback: without an imported cache nothing changes.
//!
//! Matching is deliberately conservative, because a wrong CVE finding costs trust:
//! - only `vulnerable: true` matches count; a match with no version bound (`*`) or the "not
//!   applicable" version (`-`) is ignored (it would flag every version);
//! - a configuration that also requires a platform (an AND of an application and an operating
//!   system or hardware, which the scanner cannot confirm remotely) is not matched;
//! - versions compare with their letter suffixes (`1.0.1e` is older than `1.0.1f`), and a
//!   version that has no digits matches nothing;
//! - rejected CVEs are dropped.
//!
//! Like every version-based hint, a match does not prove the host is vulnerable: distributions
//! backport fixes without changing the version string.
use crate::risk::Severity;
use serde::{Deserialize, Serialize, de::IgnoredAny};
use std::{
    collections::{BTreeMap, HashMap},
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock, RwLock},
};

/// Largest feed file accepted (a year file is at most a few hundred MB uncompressed).
pub const MAX_NVD_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_CACHE_BYTES: u64 = 1024 * 1024 * 1024;
/// Entry limits: NVD has about 280,000 CVEs in total.
const MAX_CVES_PER_FILE: usize = 1_000_000;
const MAX_CVES: usize = 2_000_000;
const MAX_MATCHES_PER_CVE: usize = 2_000;
const MAX_TITLE: usize = 140;
const CACHE_VERSION: u32 = 1;
/// At most this many NVD findings per port, so one old product does not drown a report.
pub const MAX_FINDINGS_PER_PORT: usize = 50;

/// One vulnerable CPE range of a CVE.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Match {
    /// `part:vendor:product`, lower case (`a:openbsd:openssh`).
    pub product: String,
    /// An exact version the CPE names (no range bounds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub from_excl: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub to_incl: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvdCve {
    pub severity: Severity,
    pub title: String,
    pub matches: Vec<Match>,
}

/// The cache file: every imported CVE that has at least one usable match.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Nvd {
    #[serde(default)]
    pub version: u32,
    /// Unix time of the last import.
    #[serde(default)]
    pub imported_at: u64,
    /// Files imported so far (names only), for `feeds status`.
    #[serde(default)]
    pub sources: Vec<String>,
    #[serde(default)]
    pub cves: BTreeMap<String, NvdCve>,
    /// (product -> (cve id, match index)); built on load, not stored.
    #[serde(skip)]
    index: HashMap<String, Vec<(String, usize)>>,
}

/// One CVE that applies to a CPE.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub cve: String,
    pub severity: Severity,
    pub title: String,
    /// The matching range, for the evidence ("8.5 <= v < 9.8").
    pub range: String,
}

// ---- version comparison --------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
enum Token {
    Num(u64),
    Alpha(String),
}
fn tokens(v: &str) -> Vec<Token> {
    let mut out = vec![];
    let b = v.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let s = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            // Longer than 18 digits: saturate, comparison then falls back to the text order.
            out.push(Token::Num(v[s..i].parse().unwrap_or(u64::MAX)));
        } else if b[i].is_ascii_alphabetic() {
            let s = i;
            while i < b.len() && b[i].is_ascii_alphabetic() {
                i += 1;
            }
            out.push(Token::Alpha(v[s..i].to_ascii_lowercase()));
        } else {
            i += 1; // separators: . - _ : +
        }
    }
    out
}
fn pre_release(a: &str) -> bool {
    matches!(
        a,
        "alpha" | "a" | "beta" | "b" | "rc" | "pre" | "dev" | "snapshot" | "preview" | "milestone"
    )
}
/// Version order that knows letter suffixes: `1.0.1e < 1.0.1f`, `9.6 < 9.6p1`, `1.0 > 1.0rc1`.
pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering::*;
    let (ta, tb) = (tokens(a), tokens(b));
    for i in 0..ta.len().max(tb.len()) {
        let o = match (ta.get(i), tb.get(i)) {
            (Some(Token::Num(x)), Some(Token::Num(y))) => x.cmp(y),
            (Some(Token::Alpha(x)), Some(Token::Alpha(y))) => x.cmp(y),
            (Some(Token::Num(_)), Some(Token::Alpha(_))) => Greater,
            (Some(Token::Alpha(_)), Some(Token::Num(_))) => Less,
            // The longer version is newer, unless what it adds is a pre-release marker.
            (Some(Token::Alpha(x)), None) => {
                if pre_release(x) {
                    Less
                } else {
                    Greater
                }
            }
            (None, Some(Token::Alpha(y))) => {
                if pre_release(y) {
                    Greater
                } else {
                    Less
                }
            }
            (Some(Token::Num(x)), None) => {
                // "1.0" vs "1.0.0": trailing zeros do not make a version newer.
                if *x == 0 { Equal } else { Greater }
            }
            (None, Some(Token::Num(y))) => {
                if *y == 0 {
                    Equal
                } else {
                    Less
                }
            }
            (None, None) => Equal,
        };
        if o != Equal {
            return o;
        }
    }
    Equal
}

fn has_digit(v: &str) -> bool {
    v.bytes().any(|b| b.is_ascii_digit())
}

// ---- CPE names -----------------------------------------------------------------------------

/// The parts of a CPE name that matching needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cpe {
    /// `a`, `o` or `h`.
    pub part: char,
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub update: String,
}
impl Cpe {
    /// `a:vendor:product`.
    pub fn product_key(&self) -> String {
        format!("{}:{}:{}", self.part, self.vendor, self.product)
    }
    /// Version with the update appended when it is a patch level (`9.6` + `p1` = `9.6p1`).
    pub fn full_version(&self) -> String {
        match self.update.as_str() {
            "" | "*" | "-" => self.version.clone(),
            u => format!("{}{u}", self.version),
        }
    }
}
fn split_cpe(s: &str, sep: char) -> Vec<String> {
    // Components may escape the separator with a backslash (`cpe:2.3:a:a\:b:...`).
    let mut out = vec![String::new()];
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                out.last_mut().unwrap().push(n);
            }
        } else if c == sep {
            out.push(String::new());
        } else {
            out.last_mut().unwrap().push(c);
        }
    }
    out
}
/// Parses a CPE 2.3 formatted string (`cpe:2.3:a:openbsd:openssh:9.6:p1:*:...`) or a 2.2 URI
/// (`cpe:/a:openbsd:openssh:9.6:p1`). Lower-cases everything; `None` when it is neither.
pub fn parse_cpe(s: &str) -> Option<Cpe> {
    let s = s.trim();
    if s.len() > 512 {
        return None;
    }
    let parts = split_cpe(s, ':');
    let (part, rest) = if parts.get(1).map(String::as_str) == Some("2.3") {
        (parts.get(2)?, parts.get(3..)?)
    } else if parts.get(1).is_some_and(|p| p.starts_with('/')) {
        // URI form: the part letter follows "cpe:/".
        (parts.get(1)?, parts.get(2..)?)
    } else {
        return None;
    };
    let part = part.trim_start_matches('/');
    let mut c = part.chars();
    let part = c.next()?.to_ascii_lowercase();
    if c.next().is_some() || !matches!(part, 'a' | 'o' | 'h') {
        return None;
    }
    let get = |i: usize| {
        rest.get(i)
            .map(|v| v.to_ascii_lowercase())
            .unwrap_or_default()
    };
    let (vendor, product) = (get(0), get(1));
    if vendor.is_empty() || product.is_empty() || vendor == "*" || product == "*" {
        return None;
    }
    Some(Cpe {
        part,
        vendor,
        product,
        version: get(2),
        update: get(3),
    })
}

impl Match {
    /// Does the version fall in the range? Unbounded and "not applicable" matches never do.
    fn applies(&self, cpe: &Cpe) -> bool {
        let version = cpe.full_version();
        if !has_digit(&version) || version == "*" || version == "-" {
            return false;
        }
        use std::cmp::Ordering::*;
        if let Some(e) = &self.exact {
            return compare_versions(&version, e) == Equal;
        }
        if self.from.is_none() && self.to.is_none() {
            return false;
        }
        if let Some(f) = &self.from {
            match compare_versions(&version, f) {
                Less => return false,
                Equal if self.from_excl => return false,
                _ => {}
            }
        }
        if let Some(t) = &self.to {
            match compare_versions(&version, t) {
                Greater => return false,
                Equal if !self.to_incl => return false,
                _ => {}
            }
        }
        true
    }
    fn describe(&self) -> String {
        if let Some(e) = &self.exact {
            return format!("version {e}");
        }
        let lo = self
            .from
            .as_ref()
            .map(|f| format!("{f} {}", if self.from_excl { "<" } else { "<=" }));
        let hi = self
            .to
            .as_ref()
            .map(|t| format!("{} {t}", if self.to_incl { "<=" } else { "<" }));
        format!(
            "{}v{}",
            lo.map(|l| format!("{l} ")).unwrap_or_default(),
            hi.map(|h| format!(" {h}")).unwrap_or_default()
        )
    }
}

// ---- parsing the feed ----------------------------------------------------------------------

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawVuln {
    cve: RawCve,
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct RawCve {
    id: String,
    #[serde(rename = "vulnStatus")]
    status: Option<String>,
    descriptions: Vec<RawDesc>,
    metrics: RawMetrics,
    configurations: Vec<RawConfig>,
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct RawDesc {
    lang: String,
    value: String,
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct RawMetrics {
    #[serde(rename = "cvssMetricV40")]
    v40: Vec<RawMetric>,
    #[serde(rename = "cvssMetricV31")]
    v31: Vec<RawMetric>,
    #[serde(rename = "cvssMetricV30")]
    v30: Vec<RawMetric>,
    #[serde(rename = "cvssMetricV2")]
    v2: Vec<RawMetric>,
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct RawMetric {
    #[serde(rename = "cvssData")]
    data: RawCvss,
    /// CVSS 2 keeps the rating here instead of in `cvssData`.
    #[serde(rename = "baseSeverity")]
    base_severity: Option<String>,
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct RawCvss {
    #[serde(rename = "baseSeverity")]
    base_severity: Option<String>,
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct RawConfig {
    operator: Option<String>,
    nodes: Vec<RawNode>,
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct RawNode {
    operator: Option<String>,
    negate: bool,
    #[serde(rename = "cpeMatch")]
    matches: Vec<RawMatch>,
}
#[derive(Deserialize, Default)]
#[serde(default)]
struct RawMatch {
    vulnerable: bool,
    criteria: String,
    #[serde(rename = "versionStartIncluding")]
    start_incl: Option<String>,
    #[serde(rename = "versionStartExcluding")]
    start_excl: Option<String>,
    #[serde(rename = "versionEndIncluding")]
    end_incl: Option<String>,
    #[serde(rename = "versionEndExcluding")]
    end_excl: Option<String>,
}

fn severity_of(text: &str) -> Option<Severity> {
    match text.trim().to_ascii_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        _ => None,
    }
}
/// The rating of the newest CVSS version present (4.0, 3.1, 3.0, then 2); `Info` when NVD has
/// not rated the CVE yet.
fn severity_from(m: &RawMetrics) -> Severity {
    for list in [&m.v40, &m.v31, &m.v30, &m.v2] {
        if let Some(s) = list.iter().find_map(|x| {
            x.data
                .base_severity
                .as_deref()
                .or(x.base_severity.as_deref())
                .and_then(severity_of)
        }) {
            return s;
        }
    }
    Severity::Info
}
fn normalize_cve(s: &str) -> Option<String> {
    let s = s.trim().to_ascii_uppercase();
    let rest = s.strip_prefix("CVE-")?;
    let (year, n) = rest.split_once('-')?;
    (year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && (4..=10).contains(&n.len())
        && n.bytes().all(|b| b.is_ascii_digit()))
    .then_some(s)
}
fn bounded_title(descriptions: &[RawDesc]) -> String {
    let text = descriptions
        .iter()
        .find(|d| d.lang.eq_ignore_ascii_case("en"))
        .or(descriptions.first())
        .map(|d| d.value.as_str())
        .unwrap_or("");
    let first = text.split(". ").next().unwrap_or(text);
    first
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_TITLE)
        .collect::<String>()
        .trim()
        .to_string()
}
fn clean_version(v: &Option<String>) -> Option<String> {
    v.as_deref()
        .map(|s| {
            s.trim()
                .chars()
                .filter(|c| !c.is_control())
                .take(64)
                .collect::<String>()
        })
        .filter(|s| has_digit(s))
}

/// The usable matches of one CVE: `vulnerable` matches of an OR configuration that names an
/// application, operating system or hardware product with a version or range.
fn matches_of(configs: &[RawConfig]) -> Vec<Match> {
    let mut out = vec![];
    for config in configs {
        let and =
            |op: &Option<String>| op.as_deref().is_some_and(|o| o.eq_ignore_ascii_case("and"));
        // An AND of conditions includes a platform the scanner cannot confirm.
        if and(&config.operator) || config.nodes.iter().any(|n| and(&n.operator)) {
            continue;
        }
        // Several nodes in one configuration are alternatives (OR) in NVD 2.0 unless the
        // configuration operator says AND, handled above.
        for node in config.nodes.iter().filter(|n| !n.negate) {
            for m in node.matches.iter().filter(|m| m.vulnerable) {
                let Some(cpe) = parse_cpe(&m.criteria) else {
                    continue;
                };
                let (from, from_excl) = match (&m.start_incl, &m.start_excl) {
                    (Some(_), _) => (clean_version(&m.start_incl), false),
                    (None, Some(_)) => (clean_version(&m.start_excl), true),
                    _ => (None, false),
                };
                let (to, to_incl) = match (&m.end_incl, &m.end_excl) {
                    (Some(_), _) => (clean_version(&m.end_incl), true),
                    (None, Some(_)) => (clean_version(&m.end_excl), false),
                    _ => (None, false),
                };
                let bounded = from.is_some() || to.is_some();
                let exact = (!bounded && has_digit(&cpe.version)).then(|| cpe.full_version());
                if !bounded && exact.is_none() {
                    continue; // `*` or `-` without bounds
                }
                if out.len() >= MAX_MATCHES_PER_CVE {
                    return out;
                }
                out.push(Match {
                    product: cpe.product_key(),
                    exact,
                    from,
                    from_excl,
                    to,
                    to_incl,
                });
            }
        }
    }
    out.dedup();
    out
}

/// A parsed feed: the CVEs with at least one usable match.
#[derive(Debug, Default)]
pub struct Parsed {
    pub cves: BTreeMap<String, NvdCve>,
    /// Records in the file.
    pub records: usize,
    /// Records without a valid CVE id, rejected CVEs and records that name no usable product.
    pub skipped: usize,
}

struct FileVisitor<'a>(&'a mut Parsed, &'a mut Result<(), String>);
struct SeqVisitor<'a>(&'a mut Parsed, &'a mut Result<(), String>);
struct SeqSeed<'a>(&'a mut Parsed, &'a mut Result<(), String>);

impl<'de> serde::de::Visitor<'de> for FileVisitor<'_> {
    type Value = bool;
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("an NVD CVE JSON 2.0 object")
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<bool, A::Error> {
        let mut found = false;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "vulnerabilities" => {
                    map.next_value_seed(SeqSeed(self.0, self.1))?;
                    found = true;
                }
                "format" => {
                    let f: String = map.next_value()?;
                    if f != "NVD_CVE" {
                        return Err(serde::de::Error::custom(format!(
                            "format {f:?}, expected the NVD CVE JSON 2.0 feed"
                        )));
                    }
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(found)
    }
}
impl<'de> serde::de::DeserializeSeed<'de> for SeqSeed<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_seq(SeqVisitor(self.0, self.1))
    }
}
impl<'de> serde::de::Visitor<'de> for SeqVisitor<'_> {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a list of vulnerabilities")
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while let Some(v) = seq.next_element::<RawVuln>()? {
            self.0.records += 1;
            if self.0.records > MAX_CVES_PER_FILE {
                *self.1 = Err(format!("more than {MAX_CVES_PER_FILE} records"));
                // Stop consuming; the caller reports the error.
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                return Ok(());
            }
            let cve = v.cve;
            let rejected = cve
                .status
                .as_deref()
                .is_some_and(|s| s.eq_ignore_ascii_case("rejected"));
            let (Some(id), false) = (normalize_cve(&cve.id), rejected) else {
                self.0.skipped += 1;
                continue;
            };
            let matches = matches_of(&cve.configurations);
            if matches.is_empty() {
                self.0.skipped += 1;
                continue;
            }
            self.0.cves.insert(
                id,
                NvdCve {
                    severity: severity_from(&cve.metrics),
                    title: bounded_title(&cve.descriptions),
                    matches,
                },
            );
        }
        Ok(())
    }
}

/// Parses an NVD 2.0 feed from a reader, streaming: only the compact records are kept. A gzip
/// file is refused with a message to unpack it first.
pub fn parse_reader<R: Read>(mut reader: R) -> Result<Parsed, String> {
    let mut head = [0u8; 2];
    let n = reader.read(&mut head).map_err(|e| e.to_string())?;
    if n == 2 && head == [0x1f, 0x8b] {
        return Err(
            "NVD file is gzip-compressed; unpack it first (gunzip nvdcve-2.0-2024.json.gz)".into(),
        );
    }
    let reader = std::io::Cursor::new(head[..n].to_vec()).chain(reader);
    let mut parsed = Parsed::default();
    let mut limit = Ok(());
    let mut de = serde_json::Deserializer::from_reader(std::io::BufReader::new(reader));
    let found = serde::Deserializer::deserialize_map(&mut de, FileVisitor(&mut parsed, &mut limit))
        .map_err(|e| format!("NVD file is not valid CVE JSON 2.0: {e}"))?;
    limit?;
    if !found {
        return Err(
            "NVD file has no \"vulnerabilities\" list (expected nvdcve-2.0-<year>.json)".into(),
        );
    }
    Ok(parsed)
}

/// [`parse_reader`] over bytes (used by the fuzz target and the tests).
pub fn parse_nvd(bytes: &[u8]) -> Result<Parsed, String> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    parse_reader(bytes)
}

// ---- the cache -----------------------------------------------------------------------------

impl Nvd {
    pub fn is_empty(&self) -> bool {
        self.cves.is_empty()
    }

    fn rebuild_index(&mut self) {
        self.index.clear();
        for (id, cve) in &self.cves {
            for (i, m) in cve.matches.iter().enumerate() {
                self.index
                    .entry(m.product.clone())
                    .or_default()
                    .push((id.clone(), i));
            }
        }
    }

    /// Adds (or replaces, by CVE id) the parsed CVEs; the caller saves.
    pub fn merge(&mut self, parsed: Parsed, source: &str) -> Result<(), String> {
        for (id, cve) in parsed.cves {
            self.cves.insert(id, cve);
        }
        if self.cves.len() > MAX_CVES {
            return Err(format!("more than {MAX_CVES} CVEs in the NVD cache"));
        }
        if !self.sources.iter().any(|s| s == source) {
            self.sources.push(source.chars().take(120).collect());
        }
        self.rebuild_index();
        Ok(())
    }

    /// CVEs whose vulnerable ranges contain the CPE's version, highest severity first.
    /// Empty for a CPE without a usable version.
    /// A SHA-256 over the import time, the source files and every CVE with its rating and number
    /// of vulnerable ranges, for the provenance stamp. The ranges themselves are not hashed: the
    /// cache can be a gigabyte.
    pub fn fingerprint(&self) -> String {
        let mut text = format!("{}|{}\n", self.imported_at, self.sources.join(","));
        for (id, cve) in &self.cves {
            text.push_str(&format!(
                "{id}|{}|{}\n",
                cve.severity.name(),
                cve.matches.len()
            ));
        }
        crate::provenance::hash(text.as_bytes())
    }

    pub fn lookup(&self, cpe: &str) -> Vec<Hit> {
        let Some(c) = parse_cpe(cpe) else {
            return vec![];
        };
        let Some(entries) = self.index.get(&c.product_key()) else {
            return vec![];
        };
        let mut hits: Vec<Hit> = vec![];
        for (id, i) in entries {
            let Some(cve) = self.cves.get(id) else {
                continue;
            };
            let m = &cve.matches[*i];
            if m.applies(&c) && !hits.iter().any(|h| &h.cve == id) {
                hits.push(Hit {
                    cve: id.clone(),
                    severity: cve.severity,
                    title: cve.title.clone(),
                    range: m.describe(),
                });
            }
        }
        hits.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.cve.cmp(&b.cve)));
        hits
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let size = std::fs::metadata(path)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .len();
        if size > MAX_CACHE_BYTES {
            return Err(format!("{}: file is too large", path.display()));
        }
        let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut nvd: Self = serde_json::from_reader(std::io::BufReader::new(file))
            .map_err(|e| format!("{}: not an NVD cache: {e}", path.display()))?;
        if nvd.version != CACHE_VERSION {
            return Err(format!(
                "{}: cache version {} is not supported (expected {CACHE_VERSION}); import the NVD files again",
                path.display(),
                nvd.version
            ));
        }
        nvd.rebuild_index();
        Ok(nvd)
    }

    /// Writes through a temporary file, so an interrupted import keeps the old cache.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
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

/// `%LOCALAPPDATA%/NetworkScope/nvd.json` (or under `XDG_CONFIG_HOME`), next to `feeds.json`.
pub fn default_path() -> Option<PathBuf> {
    crate::feeds::default_path().map(|p| p.with_file_name("nvd.json"))
}

/// Result of an import, for the command's output.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub path: PathBuf,
    pub files: usize,
    pub records: usize,
    pub skipped: usize,
    /// CVEs in the cache after the import.
    pub cves: usize,
    pub replaced_unreadable: Option<String>,
}
impl ImportReport {
    pub fn lines(&self) -> Vec<String> {
        let mut out = vec![];
        if let Some(e) = &self.replaced_unreadable {
            out.push(format!("Replaced an unreadable NVD cache ({e})"));
        }
        out.push(format!(
            "NVD: {} file(s), {} records read, {} skipped (rejected, without a CPE range or id); {} CVEs in the cache",
            self.files, self.records, self.skipped, self.cves
        ));
        out.push(format!("Cache written to {}", self.path.display()));
        out
    }
}

/// Imports NVD feed files into the cache at `cache`, merging with what it holds (a CVE that is
/// imported again is replaced). Nothing is written when a file is rejected.
pub fn import(files: &[PathBuf], cache: &Path, now: u64) -> Result<ImportReport, String> {
    if files.is_empty() {
        return Err("Provide the NVD feed files: feeds import nvd FILE...".into());
    }
    let mut report = ImportReport {
        path: cache.to_path_buf(),
        files: files.len(),
        ..Default::default()
    };
    let mut nvd = if cache.exists() {
        Nvd::load(cache).unwrap_or_else(|e| {
            report.replaced_unreadable = Some(e);
            Nvd::default()
        })
    } else {
        Nvd::default()
    };
    for path in files {
        let size = std::fs::metadata(path)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .len();
        if size > MAX_NVD_BYTES {
            return Err(format!(
                "{}: NVD file is too large (limit {} MB)",
                path.display(),
                MAX_NVD_BYTES / (1024 * 1024)
            ));
        }
        let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let parsed = parse_reader(file).map_err(|e| format!("{}: {e}", path.display()))?;
        report.records += parsed.records;
        report.skipped += parsed.skipped;
        let name = path
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        nvd.merge(parsed, &name)?;
    }
    nvd.version = CACHE_VERSION;
    nvd.imported_at = now;
    report.cves = nvd.cves.len();
    nvd.save(cache)?;
    Ok(report)
}

/// `feeds status`: what the NVD cache holds.
pub fn status(nvd: &Nvd, path: &Path) -> serde_json::Value {
    serde_json::json!({
        "cache": path.display().to_string(),
        "imported_at": nvd.imported_at,
        "cves": nvd.cves.len(),
        "products": nvd.index.len(),
        "sources": nvd.sources,
    })
}

// ---- the active cache ----------------------------------------------------------------------

fn slot() -> &'static RwLock<Option<Arc<Nvd>>> {
    static SLOT: OnceLock<RwLock<Option<Arc<Nvd>>>> = OnceLock::new();
    SLOT.get_or_init(|| RwLock::new(None))
}

/// Makes the cache at `explicit` (`--nvd FILE`) the active one; an error when it is missing or
/// unreadable. The previous cache stays in place on error.
pub fn load_active(explicit: &Path) -> Result<(), String> {
    let nvd = Nvd::load(explicit)?;
    if let Ok(mut s) = slot().write() {
        *s = Some(Arc::new(nvd));
    }
    Ok(())
}

/// The active NVD data: the explicit cache, else the default cache when it exists, else
/// nothing. Loaded once; an unreadable default cache is reported once on stderr. Tests never
/// read the developer's own cache.
pub fn active() -> Arc<Nvd> {
    if let Some(n) = slot().read().ok().and_then(|s| s.clone()) {
        return n;
    }
    #[cfg(test)]
    let nvd = Arc::new(Nvd::default());
    #[cfg(not(test))]
    let nvd = Arc::new(match default_path().filter(|p| p.exists()) {
        Some(p) => Nvd::load(&p).unwrap_or_else(|e| {
            eprintln!("NVD: {e}; only the built-in CVE rules are used");
            Nvd::default()
        }),
        None => Nvd::default(),
    });
    if let Ok(mut s) = slot().write() {
        if let Some(existing) = s.as_ref() {
            return existing.clone();
        }
        *s = Some(nvd.clone());
    }
    nvd
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../../tests/fixtures/nvd-sample.json");

    fn nvd() -> Nvd {
        let mut n = Nvd::default();
        n.merge(parse_nvd(FIXTURE.as_bytes()).unwrap(), "nvd-sample.json")
            .unwrap();
        n
    }
    fn ids(n: &Nvd, cpe: &str) -> Vec<String> {
        n.lookup(cpe).into_iter().map(|h| h.cve).collect()
    }

    #[test]
    fn version_order_knows_letters_patch_levels_and_prereleases() {
        use std::cmp::Ordering::*;
        for (a, b, want) in [
            ("1.0.1e", "1.0.1f", Less),
            ("1.0.1f", "1.0.1", Greater),
            ("9.6", "9.6p1", Less),
            ("9.6p1", "9.6p2", Less),
            ("9.10", "9.9", Greater),
            ("1.0", "1.0.0", Equal),
            ("1.0", "1.0.1", Less),
            ("1.0rc1", "1.0", Less),
            ("2.4.49", "2.4.49", Equal),
            ("10.0", "9.9.9", Greater),
            ("1.0", "1.0-beta", Greater),
        ] {
            assert_eq!(compare_versions(a, b), want, "{a} vs {b}");
            assert_eq!(compare_versions(b, a), want.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn cpe_names_parse_in_both_forms() {
        let c = parse_cpe("cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*").unwrap();
        assert_eq!(
            (c.part, c.vendor.as_str(), c.product.as_str()),
            ('a', "openbsd", "openssh")
        );
        assert_eq!(c.full_version(), "9.6p1");
        assert_eq!(c.product_key(), "a:openbsd:openssh");
        let c = parse_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*").unwrap();
        assert_eq!(c.full_version(), "2.4.49");
        let c = parse_cpe("cpe:/a:igor_sysoev:nginx:1.18.0").unwrap();
        assert_eq!(
            (c.vendor.as_str(), c.version.as_str()),
            ("igor_sysoev", "1.18.0")
        );
        let c = parse_cpe(r"cpe:2.3:a:vendor\:x:prod\_y:1.0:*:*:*:*:*:*:*").unwrap();
        assert_eq!(c.vendor, "vendor:x");
        for bad in [
            "",
            "cpe:",
            "cpe:2.3:z:a:b:1",
            "cpe:2.3:a:*:*:1",
            "openssh 9.6",
            "cpe:2.3:a::b:1",
        ] {
            assert_eq!(parse_cpe(bad), None, "{bad:?}");
        }
        assert_eq!(
            parse_cpe(&format!("cpe:2.3:a:{}:b:1", "x".repeat(600))),
            None
        );
    }

    #[test]
    fn fixture_imports_with_conservative_selection() {
        let parsed = parse_nvd(FIXTURE.as_bytes()).unwrap();
        assert_eq!(parsed.records, 9);
        let kept: Vec<&str> = parsed.cves.keys().map(String::as_str).collect();
        assert_eq!(
            kept,
            [
                "CVE-2014-0160",
                "CVE-2021-41773",
                "CVE-2024-6387",
                "CVE-2099-0001",
                "CVE-2099-0005"
            ],
            "AND configurations, rejected records, unbounded matches and records without \
             configurations are dropped"
        );
        assert_eq!(parsed.skipped, 4);
        assert_eq!(parsed.cves["CVE-2024-6387"].severity, Severity::High);
        // CVSS 2 only: the rating comes from the metric itself.
        assert_eq!(parsed.cves["CVE-2099-0001"].severity, Severity::Medium);
        assert!(
            parsed.cves["CVE-2024-6387"]
                .title
                .starts_with("A security regression")
        );
    }

    #[test]
    fn lookup_follows_version_ranges_in_both_directions() {
        let n = nvd();
        let ssh = |v: &str| ids(&n, &format!("cpe:2.3:a:openbsd:openssh:{v}:*:*:*:*:*:*:*"));
        // versionStartIncluding 8.5 (+ patch level), versionEndExcluding 9.8.
        assert_eq!(ssh("9.6"), ["CVE-2024-6387"]);
        assert_eq!(ssh("8.5"), ["CVE-2024-6387"], "start is inclusive");
        assert!(ssh("8.4").is_empty(), "below the start");
        assert!(ssh("9.8").is_empty(), "end is exclusive");
        assert!(ssh("9.8p1").is_empty());
        assert_eq!(
            ids(&n, "cpe:2.3:a:openbsd:openssh:9.7:p1:*:*:*:*:*:*"),
            ["CVE-2024-6387"],
            "the update field is part of the version"
        );
        // start excluded, end included (CVE-2099-0001: 1.0 < v <= 2.0).
        let ex = |v: &str| {
            ids(
                &n,
                &format!("cpe:2.3:a:example:examplehttpd:{v}:*:*:*:*:*:*:*"),
            )
        };
        assert!(ex("1.0").is_empty(), "start is exclusive");
        assert_eq!(ex("1.0.1"), ["CVE-2099-0001"]);
        assert_eq!(ex("2.0"), ["CVE-2099-0001"], "end is inclusive");
        assert!(ex("2.0.1").is_empty());
        // Letters: openssl 1.0.1 through 1.0.1f is affected, 1.0.1g is not.
        let ssl = |v: &str| ids(&n, &format!("cpe:2.3:a:openssl:openssl:{v}:*:*:*:*:*:*:*"));
        assert_eq!(ssl("1.0.1e"), ["CVE-2014-0160"]);
        assert_eq!(ssl("1.0.1f"), ["CVE-2014-0160"]);
        assert!(ssl("1.0.1g").is_empty(), "1.0.1g is newer than 1.0.1f");
        assert!(ssl("1.0.2").is_empty());
        // An exact version list entry.
        let ap = |v: &str| {
            ids(
                &n,
                &format!("cpe:2.3:a:apache:http_server:{v}:*:*:*:*:*:*:*"),
            )
        };
        assert_eq!(ap("2.4.49"), ["CVE-2021-41773"]);
        assert!(ap("2.4.51").is_empty());
        // No version, "any", "not applicable" or no digits at all: no match.
        for v in ["*", "-", "", "x"] {
            assert!(ap(v).is_empty() && ssh(v).is_empty(), "{v:?}");
        }
        // Another vendor with the same product name, another part, and non-CPE text.
        assert!(ids(&n, "cpe:2.3:a:other:openssh:9.6:*:*:*:*:*:*:*").is_empty());
        assert!(ids(&n, "cpe:2.3:o:openbsd:openssh:9.6:*:*:*:*:*:*:*").is_empty());
        assert!(ids(&n, "openssh 9.6").is_empty());
        // 2.2 URIs from imported Nmap data work as well.
        assert_eq!(ids(&n, "cpe:/a:openbsd:openssh:9.6"), ["CVE-2024-6387"]);
    }

    #[test]
    fn hits_carry_severity_title_and_range_sorted_by_severity() {
        let n = nvd();
        let hits = n.lookup("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].severity, Severity::Critical);
        assert_eq!(hits[0].range, "version 2.4.49");
        let ssh = n.lookup("cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*");
        assert_eq!(ssh[0].range, "8.5 <= v < 9.8");
        assert!(ssh[0].title.len() <= MAX_TITLE);
    }

    #[test]
    fn malformed_feeds_are_rejected_without_panicking() {
        assert!(parse_nvd(b"").is_err());
        assert!(parse_nvd(b"[]").is_err());
        assert!(parse_nvd(b"{\"vulnerabilities\": 5}").is_err());
        assert!(
            parse_nvd(br#"{"format":"NVD_CVE"}"#)
                .unwrap_err()
                .contains("no \"vulnerabilities\"")
        );
        assert!(
            parse_nvd(br#"{"format":"other","vulnerabilities":[]}"#)
                .unwrap_err()
                .contains("format")
        );
        assert!(
            parse_nvd(&FIXTURE.as_bytes()[..FIXTURE.len() / 2]).is_err(),
            "truncated"
        );
        // Every prefix and a byte-flipped copy of the fixture: an error or a parse, no panic.
        for n in (0..FIXTURE.len()).step_by(37) {
            let _ = parse_nvd(&FIXTURE.as_bytes()[..n]);
        }
        for i in (0..FIXTURE.len()).step_by(53) {
            let mut b = FIXTURE.as_bytes().to_vec();
            b[i] ^= 0x55;
            let _ = parse_nvd(&b);
        }
        // Gzip: the message says what to do.
        assert!(
            parse_nvd(&[0x1f, 0x8b, 8, 0])
                .unwrap_err()
                .contains("gunzip")
        );
        // A BOM, an empty list, records without an id and with odd types of optional fields.
        let p = parse_nvd(b"\xEF\xBB\xBF{\"vulnerabilities\":[]}").unwrap();
        assert_eq!((p.records, p.cves.len()), (0, 0));
        let p = parse_nvd(br#"{"vulnerabilities":[{}, {"cve":{"id":"nope"}}, {"cve":{"id":"CVE-2099-1000","configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*"}]}]}]}}]}"#).unwrap();
        assert_eq!((p.records, p.skipped, p.cves.len()), (3, 2, 1));
        // Huge numbers and long strings stay bounded.
        let long = "9".repeat(5000);
        let json = format!(
            r#"{{"vulnerabilities":[{{"cve":{{"id":"CVE-2099-1001","descriptions":[{{"lang":"en","value":"{}"}}],"configurations":[{{"nodes":[{{"cpeMatch":[{{"vulnerable":true,"criteria":"cpe:2.3:a:v:p:*:*:*:*:*:*:*:*","versionEndExcluding":"{long}"}}]}}]}}]}}}}]}}"#,
            "x".repeat(10_000)
        );
        let p = parse_nvd(json.as_bytes()).unwrap();
        let c = &p.cves["CVE-2099-1001"];
        assert!(c.title.chars().count() <= MAX_TITLE);
        assert!(c.matches[0].to.as_ref().unwrap().len() <= 64);
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ns-nvd-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn import_merges_files_and_round_trips_the_cache() {
        let dir = temp("import");
        let (a, b, cache) = (dir.join("a.json"), dir.join("b.json"), dir.join("nvd.json"));
        std::fs::write(&a, FIXTURE).unwrap();
        // A second file with one new CVE and a replacement of CVE-2021-41773.
        std::fs::write(
            &b,
            r#"{"format":"NVD_CVE","vulnerabilities":[
              {"cve":{"id":"CVE-2099-2000","metrics":{"cvssMetricV31":[{"cvssData":{"baseSeverity":"LOW"}}]},
                "configurations":[{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*","versionEndExcluding":"2.4.10"}]}]}]}},
              {"cve":{"id":"CVE-2021-41773","metrics":{"cvssMetricV31":[{"cvssData":{"baseSeverity":"MEDIUM"}}]},
                "configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}]}]}]}}]}"#,
        )
        .unwrap();
        let r = import(&[a.clone(), b], &cache, 1234).unwrap();
        assert_eq!((r.files, r.records, r.cves), (2, 11, 6), "{r:?}");
        assert!(r.lines().join("\n").contains("6 CVEs in the cache"));
        let loaded = Nvd::load(&cache).unwrap();
        assert_eq!(loaded.imported_at, 1234);
        assert_eq!(loaded.sources, ["a.json", "b.json"]);
        let apache = loaded.lookup("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*");
        assert_eq!(apache.len(), 1, "the replaced CVE appears once");
        assert_eq!(apache[0].severity, Severity::Medium, "the later file wins");
        assert_eq!(
            ids(&loaded, "cpe:2.3:a:apache:http_server:2.4.9:*:*:*:*:*:*:*"),
            ["CVE-2099-2000"]
        );
        let s = status(&loaded, &cache);
        assert_eq!(s["cves"], 6);
        // Importing again keeps the cache and does not duplicate anything.
        let again = import(&[a], &cache, 5).unwrap();
        assert_eq!(again.cves, 6);
        // A rejected file writes nothing and keeps the old cache.
        let bad = dir.join("bad.json");
        std::fs::write(&bad, b"not json").unwrap();
        let before = std::fs::read(&cache).unwrap();
        assert!(import(std::slice::from_ref(&bad), &cache, 6).is_err());
        assert_eq!(std::fs::read(&cache).unwrap(), before);
        std::fs::write(&bad, [0x1f, 0x8b, 8, 0, 0]).unwrap();
        assert!(import(&[bad], &cache, 6).unwrap_err().contains("gunzip"));
        assert!(import(&[], &cache, 6).is_err());
        assert!(import(&[dir.join("missing.json")], &cache, 6).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_version_and_damage_are_checked() {
        let dir = temp("cache");
        let cache = dir.join("nvd.json");
        std::fs::write(&cache, r#"{"version":99,"cves":{}}"#).unwrap();
        assert!(Nvd::load(&cache).unwrap_err().contains("not supported"));
        std::fs::write(&cache, b"{").unwrap();
        assert!(Nvd::load(&cache).unwrap_err().contains("not an NVD cache"));
        // An unreadable cache is replaced by an import and says so.
        let f = dir.join("f.json");
        std::fs::write(&f, FIXTURE).unwrap();
        let r = import(&[f], &cache, 1).unwrap();
        assert!(r.replaced_unreadable.is_some());
        assert!(Nvd::load(&cache).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
