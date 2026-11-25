//! VEX: what a vendor says about a CVE for its product (`feeds import vex`).
//!
//! Version-based findings are hints: a CVE is reported because a product version lies in an
//! affected range, although the vendor may have backported the fix or the vulnerable code may not
//! be in that product at all. Vendors publish that as **VEX** (Vulnerability Exploitability
//! eXchange): a CSAF 2.0 document (`product_status`: `known_not_affected`, `fixed`,
//! `known_affected`, `under_investigation`, with the justification flag and impact statement), or a
//! CycloneDX document whose `vulnerabilities` carry an `analysis` (`not_affected`, `resolved`,
//! `false_positive`, `exploitable`, `in_triage`) for the components they `affect`.
//!
//! `feeds import vex FILE|DIR...` reads such files into a local cache (`vex.json` next to
//! `feeds.json`). A finding whose CVE a statement covers for the product and version the scan saw
//! then carries the statement (`vex`): it stays in the list, marked, and a finding the vendor says
//! does not affect the product (not affected, fixed, false positive) no longer counts in the risk
//! score. The CycloneDX export writes the statement as the vulnerability's `analysis`.
//!
//! **Matching** is the rule of the CISA advisories ([`crate::csaf`]): the CVE, the vendor when
//! both name one, the product names (normalised, at least 5 characters, one containing the other;
//! Siemens CPUs also by family) and the version in the statement's range. A statement without a
//! version covers every version of the product. When statements disagree for one version, the one
//! with a version range wins over one for all versions. Nothing here touches the network.
use crate::{
    csaf::{
        names_match, norm, norm_version, parse_range, range_holds, siemens_family, vendor_matches,
    },
    risk::Finding,
    scan::Host,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CACHE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FILES: usize = 20_000;
const MAX_STATEMENTS: usize = 1_000_000;
const MAX_PER_FILE: usize = 100_000;
const MAX_COMPONENTS: usize = 100_000;
const MAX_DEPTH: usize = 16;
const MAX_TEXT: usize = 300;
const CACHE_VERSION: u32 = 2;

/// What a statement says.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    NotAffected,
    Fixed,
    FalsePositive,
    Affected,
    UnderInvestigation,
}

impl State {
    /// The vendor says the finding does not apply: it no longer counts in the risk score.
    pub fn resolves(self) -> bool {
        matches!(self, Self::NotAffected | Self::Fixed | Self::FalsePositive)
    }
    /// The CycloneDX `analysis.state`.
    pub fn cyclonedx(self) -> &'static str {
        match self {
            Self::NotAffected => "not_affected",
            Self::Fixed => "resolved",
            Self::FalsePositive => "false_positive",
            Self::Affected => "exploitable",
            Self::UnderInvestigation => "in_triage",
        }
    }
    /// For people: `not affected`, `fixed`, ...
    pub fn label(self) -> &'static str {
        match self {
            Self::NotAffected => "not affected",
            Self::Fixed => "fixed",
            Self::FalsePositive => "false positive",
            Self::Affected => "affected",
            Self::UnderInvestigation => "under investigation",
        }
    }
}

/// One statement: a CVE, a product and its versions, and what the vendor says.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    pub cve: String,
    pub vendor: String,
    pub products: Vec<String>,
    /// CSAF: the names that narrow the product down, broadest first (see
    /// [`crate::csaf::StatusEntry::specific`]). A statement that clears a finding must cover the
    /// device with every one of them; empty for statements that name one product (CycloneDX).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub specific: Vec<String>,
    /// Versions in canonical form (see [`crate::csaf::parse_range`]); `*` for all.
    pub range: String,
    pub state: State,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub justification: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    /// The document (CSAF tracking id or CycloneDX serial number, else the file name).
    pub source: String,
    /// The package URL without version, qualifiers and subpath (`pkg:deb/debian/openssl`), when
    /// the statement names one: it then matches SBOM components by package URL.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub purl: String,
}

/// A package URL (`pkg:type/namespace/name@version?qualifiers#subpath`) split into its identity
/// (type, namespace and name, lowercase and percent-decoded, without version, qualifiers and
/// subpath) and its version. `None` for text that is no package URL.
pub fn purl_parts(text: &str) -> Option<(String, String)> {
    let rest = text.trim().strip_prefix("pkg:")?;
    let rest = rest.trim_start_matches('/');
    let rest = rest.split_once('#').map_or(rest, |(a, _)| a);
    let rest = rest.split_once('?').map_or(rest, |(a, _)| a);
    let (path, version) = match rest.rsplit_once('@') {
        // An `@` in the last segment separates the version (an npm scope is `%40`-encoded).
        Some((p, v)) if !v.contains('/') => (p, v),
        _ => (rest, ""),
    };
    let segments: Vec<String> = path
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| percent_decode(s).to_lowercase())
        .collect();
    if segments.len() < 2 || segments.iter().any(|s| s.len() > 200) {
        return None;
    }
    Some((
        clean(&format!("pkg:{}", segments.join("/"))),
        clean(&percent_decode(version)),
    ))
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(v) =
                u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("x"), 16)
        {
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// What a finding carries when a statement covers it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Applied {
    pub state: State,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub justification: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    pub source: String,
}

impl From<&Statement> for Applied {
    fn from(s: &Statement) -> Self {
        Self {
            state: s.state,
            justification: s.justification.clone(),
            detail: s.detail.clone(),
            source: s.source.clone(),
        }
    }
}

/// The imported statements.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Library {
    pub version: u32,
    pub imported_at: u64,
    #[serde(default)]
    pub sources: Vec<String>,
    pub statements: Vec<Statement>,
}

fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_TEXT)
        .collect::<String>()
        .trim()
        .to_string()
}

fn text(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .map(clean)
        .unwrap_or_default()
}

fn valid_cve(s: &str) -> bool {
    let mut parts = s.split('-');
    parts.next() == Some("CVE")
        && parts
            .next()
            .is_some_and(|y| y.len() == 4 && y.bytes().all(|b| b.is_ascii_digit()))
        && parts
            .next()
            .is_some_and(|n| (4..=9).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_digit()))
        && parts.next().is_none()
}

/// The versions of a CycloneDX `version` or `range` text in canonical form; `None` when the text
/// is no version.
fn range_of(text: &str) -> Option<String> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    parse_range(t).or_else(|| parse_range(&format!("={}", norm_version(t))))
}

fn parse_csaf_vex(bytes: &[u8]) -> Result<Vec<Statement>, String> {
    let (id, entries, _) = crate::csaf::parse_statuses(bytes)?;
    Ok(entries
        .into_iter()
        .map(|e| Statement {
            cve: e.cve,
            vendor: clean(&e.vendor),
            products: e.products.iter().map(|p| clean(p)).collect(),
            specific: e.specific.iter().map(|p| clean(p)).collect(),
            range: e.range,
            state: match e.status {
                "known_not_affected" => State::NotAffected,
                "fixed" => State::Fixed,
                "known_affected" => State::Affected,
                _ => State::UnderInvestigation,
            },
            justification: clean(&e.justification),
            detail: clean(&e.detail),
            source: clean(&id),
            purl: String::new(),
        })
        .collect())
}

/// A CycloneDX component the statements may refer to.
struct Target {
    vendor: String,
    name: String,
    version: String,
    /// The component's package URL identity (see [`purl_parts`]).
    purl: String,
}

fn organisation(v: Option<&Value>) -> String {
    v.and_then(|o| o.get("name"))
        .and_then(Value::as_str)
        .map(clean)
        .unwrap_or_default()
}

fn parse_cyclonedx_vex(doc: &Value, file: &str) -> Result<Vec<Statement>, String> {
    let source = {
        let serial = text(doc, "serialNumber");
        if serial.is_empty() {
            clean(file)
        } else {
            serial
        }
    };
    // Components by bom-ref (the metadata component too), followed into nested components.
    let mut targets: HashMap<String, Target> = HashMap::new();
    let mut stack: Vec<(&Value, usize)> = vec![];
    if let Some(c) = doc.get("metadata").and_then(|m| m.get("component")) {
        stack.push((c, 0));
    }
    stack.extend(
        doc.get("components")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|c| (c, 0)),
    );
    let mut seen = 0usize;
    while let Some((c, depth)) = stack.pop() {
        seen += 1;
        if seen > MAX_COMPONENTS {
            break;
        }
        let r = text(c, "bom-ref");
        if !r.is_empty() {
            let vendor = [
                organisation(c.get("manufacturer")),
                organisation(c.get("supplier")),
            ]
            .into_iter()
            .find(|s| !s.is_empty())
            .unwrap_or_default();
            targets.insert(
                r,
                Target {
                    vendor,
                    name: text(c, "name"),
                    version: text(c, "version"),
                    purl: purl_parts(&text(c, "purl"))
                        .map(|(p, _)| p)
                        .unwrap_or_default(),
                },
            );
        }
        if depth < MAX_DEPTH
            && let Some(children) = c.get("components").and_then(Value::as_array)
        {
            stack.extend(children.iter().map(|x| (x, depth + 1)));
        }
    }
    let vulns = doc
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .ok_or("a CycloneDX document without vulnerabilities is no VEX")?;
    let mut out = vec![];
    for v in vulns.iter().take(MAX_PER_FILE) {
        let cve = text(v, "id").to_ascii_uppercase();
        if !valid_cve(&cve) {
            continue;
        }
        let analysis = v.get("analysis").unwrap_or(&Value::Null);
        let state = match text(analysis, "state").as_str() {
            "not_affected" => Some(State::NotAffected),
            "resolved" | "resolved_with_pedigree" => Some(State::Fixed),
            "false_positive" => Some(State::FalsePositive),
            "exploitable" => Some(State::Affected),
            "in_triage" => Some(State::UnderInvestigation),
            _ => None,
        };
        let (justification, detail) = (text(analysis, "justification"), text(analysis, "detail"));
        for a in v
            .get("affects")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            // A ref, or a BOM-Link (`urn:cdx:serial/version#bom-ref`) into this document.
            let r = text(a, "ref");
            let frag = r.rsplit_once('#').map_or(r.as_str(), |(_, frag)| frag);
            // A ref into another BOM often names the package by its package URL
            // (`urn:cdx:...#pkg:maven/org/name@1.0`): that is enough to match SBOM components.
            let from_purl;
            let t = match targets.get(frag) {
                Some(t) => t,
                None => {
                    let decoded = percent_decode(frag);
                    let Some((purl, version)) = purl_parts(&decoded) else {
                        continue;
                    };
                    from_purl = Target {
                        vendor: String::new(),
                        name: purl.rsplit('/').next().unwrap_or_default().to_string(),
                        version,
                        purl,
                    };
                    &from_purl
                }
            };
            if t.name.is_empty() {
                continue;
            }
            let versions: Vec<&Value> = a
                .get("versions")
                .and_then(Value::as_array)
                .map(|vs| vs.iter().collect())
                .unwrap_or_default();
            let mut push = |range: String, state: State| {
                if out.len() < MAX_PER_FILE {
                    out.push(Statement {
                        cve: cve.clone(),
                        vendor: t.vendor.clone(),
                        products: vec![t.name.clone()],
                        specific: vec![],
                        range,
                        state,
                        justification: justification.clone(),
                        detail: detail.clone(),
                        source: source.clone(),
                        purl: t.purl.clone(),
                    });
                }
            };
            if versions.is_empty() {
                let Some(state) = state else { continue };
                let range = if t.version.is_empty() {
                    Some("*".to_string())
                } else {
                    range_of(&t.version)
                };
                if let Some(range) = range {
                    push(range, state);
                }
            } else {
                for ver in versions {
                    // `unaffected` takes the analysis' reason when it gives one that resolves.
                    let s = match text(ver, "status").as_str() {
                        "unaffected" => {
                            state.filter(|s| s.resolves()).unwrap_or(State::NotAffected)
                        }
                        "affected" => State::Affected,
                        _ => continue,
                    };
                    let spec = [text(ver, "version"), text(ver, "range")]
                        .into_iter()
                        .find(|x| !x.is_empty())
                        .unwrap_or_default();
                    if let Some(range) = range_of(&spec) {
                        push(range, s);
                    }
                }
            }
        }
    }
    Ok(out)
}

/// The statements of one file: CSAF 2.0 (a VEX document or an advisory) or CycloneDX VEX.
pub fn parse(bytes: &[u8], file: &str) -> Result<Vec<Statement>, String> {
    let doc: Value = serde_json::from_slice(bytes).map_err(|e| format!("not JSON: {e}"))?;
    let statements = if doc.get("document").is_some() {
        parse_csaf_vex(bytes)?
    } else if text(&doc, "bomFormat").eq_ignore_ascii_case("CycloneDX") {
        parse_cyclonedx_vex(&doc, file)?
    } else {
        return Err("neither CSAF 2.0 (document) nor CycloneDX (bomFormat)".into());
    };
    if statements.is_empty() {
        return Err("no statement about a CVE for a product with a usable version".into());
    }
    Ok(statements)
}

impl Library {
    pub fn is_empty(&self) -> bool {
        self.statements.is_empty()
    }

    /// The statement that covers `cve` for a product with these names and this version.
    ///
    /// A statement that would **clear** a finding (not affected, fixed, false positive) must be
    /// exact: the vendor known on both sides and the same, a version range (not "all versions"),
    /// and a product name equal to one the device reports or more general than it (a statement
    /// for the `S7-1200` family covers a `CPU 1214C`; one for the `CPU 1217C` does not). Other
    /// statements (affected, under investigation) only add information and match like the
    /// advisories. When both kinds match, affected wins; within a kind, a version range wins over
    /// all versions.
    pub fn lookup(
        &self,
        cve: &str,
        vendor: &str,
        names: &[String],
        version: &str,
    ) -> Option<&Statement> {
        let version = norm_version(version);
        let mut open: Option<&Statement> = None;
        let mut clearing: Option<&Statement> = None;
        for s in &self.statements {
            if !s.cve.eq_ignore_ascii_case(cve) {
                continue;
            }
            if !s.vendor.is_empty() && !vendor.is_empty() && !vendor_matches(&s.vendor, vendor) {
                continue;
            }
            let all = s.range == "*";
            if !all && (version.is_empty() || !range_holds(&s.range, version)) {
                continue;
            }
            if s.state.resolves() {
                let exact = !all
                    && !s.vendor.is_empty()
                    && !vendor.is_empty()
                    && if s.specific.is_empty() {
                        names_cover(names, &s.products)
                    } else {
                        covers_all(names, &s.specific)
                    };
                if exact && clearing.is_none() {
                    clearing = Some(s);
                }
            } else if names_match(names, &s.products) && open.is_none_or(|b| b.range == "*" && !all)
            {
                open = Some(s);
            }
        }
        open.or(clearing)
    }

    /// The statement that covers `cve` for the package with this package URL (an SBOM
    /// component's): same type, namespace and name, the version (from the package URL, else
    /// `version`) in the statement's range. A statement that would clear a finding needs a
    /// version range here too; affected wins, as in [`Library::lookup`].
    pub fn lookup_purl(&self, cve: &str, purl: &str, version: &str) -> Option<&Statement> {
        let (id, from_purl) = purl_parts(purl)?;
        let version = if from_purl.is_empty() {
            norm_version(version).to_string()
        } else {
            norm_version(&from_purl).to_string()
        };
        let mut open: Option<&Statement> = None;
        let mut clearing: Option<&Statement> = None;
        for s in &self.statements {
            if s.purl != id || !s.cve.eq_ignore_ascii_case(cve) {
                continue;
            }
            let all = s.range == "*";
            if !all && (version.is_empty() || !range_holds(&s.range, &version)) {
                continue;
            }
            if s.state.resolves() {
                if !all && clearing.is_none() {
                    clearing = Some(s);
                }
            } else if open.is_none_or(|b| b.range == "*" && !all) {
                open = Some(s);
            }
        }
        open.or(clearing)
    }

    /// Adds a file's statements, replacing those an earlier import of the same source gave.
    fn merge(&mut self, statements: Vec<Statement>, file: &str) -> Result<(), String> {
        let sources: Vec<String> = {
            let mut s: Vec<String> = statements.iter().map(|x| x.source.clone()).collect();
            s.sort();
            s.dedup();
            s
        };
        self.statements.retain(|x| !sources.contains(&x.source));
        if self.statements.len() + statements.len() > MAX_STATEMENTS {
            return Err(format!(
                "the cache would exceed {MAX_STATEMENTS} statements"
            ));
        }
        self.statements.extend(statements);
        if !self.sources.iter().any(|s| s == file) && self.sources.len() < 100_000 {
            self.sources.push(clean(file));
        }
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        Self::read(path)?.map_err(|version| {
            format!(
                "{}: cache version {version} is not supported (expected {CACHE_VERSION}); import the VEX files again",
                path.display()
            )
        })
    }

    /// [`Self::load`], with a cache that an older version of the program wrote told apart as
    /// `Ok(Err(its version))`: that one is expected after an upgrade, and an import starts
    /// over. Every other file that does not load is an error, and is never written over.
    fn read(path: &Path) -> Result<Result<Self, u32>, String> {
        /// What a cache of any version has. The version alone does not make a file a cache: a
        /// vendor's CycloneDX document has a top-level `version` too.
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct Header {
            version: u32,
            imported_at: u64,
            statements: Vec<serde::de::IgnoredAny>,
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
                _ => Err(format!("{}: not a VEX cache: {e}", path.display())),
            },
        }
    }

    /// Writes the cache through a temporary file, so an interrupted import keeps the old one.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        check_size(bytes.len(), path)?;
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

/// Whether a statement's product name is one the device reports, or a more general one it
/// contains (normalised as for the advisories, at least 5 characters; Siemens S7 CPUs also by
/// family). Unlike [`names_match`], a statement name that only contains the device's name (a more
/// specific model) does not count.
fn names_cover(device: &[String], products: &[String]) -> bool {
    let names = device_names(device);
    products
        .iter()
        .map(|p| core_name(p))
        .filter(|w| w.len() >= 5)
        .any(|w| {
            names
                .iter()
                .any(|n| *n == w || (n.len() > w.len() && n.contains(w.as_str())))
        })
}

/// The device's names as [`names_cover`] compares them. A Siemens S7 CPU is also known by its
/// family, and by family and CPU together (`S7-1200 CPU 1217C`, as product lists write it).
fn device_names(device: &[String]) -> Vec<String> {
    let mut names: Vec<String> = device.iter().map(|n| core_name(n)).collect();
    for n in device {
        if let Some(f) = siemens_family(n) {
            names.push(core_name(f));
            names.push(core_name(&format!("{f} {n}")));
        }
    }
    names
}

/// [`names_cover`] for the names of a CSAF product path, broadest first (family, then model):
/// every one of them must cover the device, or a statement for one model would clear its
/// siblings through the family name they share. A name too short to compare (under 5
/// characters) only counts when it is equal, and may be skipped unless it is the last, most
/// specific one.
fn covers_all(device: &[String], specific: &[String]) -> bool {
    let names = device_names(device);
    specific.iter().enumerate().all(|(i, p)| {
        let w = core_name(p);
        (w.len() < 5 && i + 1 < specific.len())
            || names
                .iter()
                .any(|n| *n == w || (w.len() >= 5 && n.len() > w.len() && n.contains(w.as_str())))
    })
}

/// A product name without the words that do not tell products apart (`SIMATIC`, `CPU`,
/// `family`, `firmware`, version numbers), normalised like [`norm`]: `SIMATIC S7-1200 CPU V4`
/// and `S7-1200` are both `s71200`.
fn core_name(name: &str) -> String {
    const GENERIC: [&str; 10] = [
        "simatic", "cpu", "cpus", "family", "firmware", "fw", "series", "all", "versions",
        "version",
    ];
    let words: Vec<String> = name
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '.')
        .map(str::to_ascii_lowercase)
        .filter(|w| !w.is_empty() && !GENERIC.contains(&w.as_str()))
        // A version (`v4`, `4.2.1`, `v4.2`) is not part of the product name.
        .filter(|w| {
            let v = w.strip_prefix('v').unwrap_or(w);
            !(v.contains('.') || (w.starts_with('v') && v.chars().all(|c| c.is_ascii_digit())))
        })
        .collect();
    norm(&words.join(" "))
}

/// What the scan saw on a port (or on the whole host): vendor, product names and version.
type Context = (String, Vec<String>, String);

/// The products a finding is about: the industrial identification on its port, else the
/// service's product and version; without a port, every identification of the host.
fn contexts(host: &Host, port: Option<u16>) -> Vec<Context> {
    let mut out: Vec<Context> = crate::otdevice::from_identity(&host.identity)
        .into_iter()
        .filter(|d| port.is_none_or(|p| d.port == p))
        .map(|d| (d.vendor, d.products, d.version))
        .collect();
    if let Some(p) = port {
        let get = |k: String| host.identity.get(&k).cloned().unwrap_or_default();
        let product = get(format!("svc.{p}.product"));
        if !product.is_empty() {
            out.push((
                String::new(),
                vec![product],
                get(format!("svc.{p}.version")),
            ));
        }
    }
    out
}

/// Marks the findings a statement covers (the first CVE of a finding that one covers).
pub fn apply(findings: &mut [Finding], hosts: &[Host]) {
    apply_with(&active(), findings, hosts);
}

pub fn apply_with(library: &Library, findings: &mut [Finding], hosts: &[Host]) {
    if library.is_empty() {
        return;
    }
    let by_ip: BTreeMap<IpAddr, &Host> = hosts.iter().map(|h| (h.ip, h)).collect();
    for f in findings.iter_mut().filter(|f| !f.cve.is_empty()) {
        let Some(host) = by_ip.get(&f.ip) else {
            continue;
        };
        let ctx = contexts(host, f.port);
        f.vex = f.cve.iter().find_map(|cve| {
            ctx.iter()
                .find_map(|(vendor, names, version)| library.lookup(cve, vendor, names, version))
                .map(Applied::from)
        });
    }
}

/// A cache that [`Library::load`] would refuse for its size is not written: the next import
/// could not read it back.
fn check_size(bytes: usize, path: &Path) -> Result<(), String> {
    if bytes as u64 > MAX_CACHE_BYTES {
        return Err(format!(
            "{}: the cache would be larger than {} MB and could not be read again; nothing was written",
            path.display(),
            MAX_CACHE_BYTES / (1024 * 1024)
        ));
    }
    Ok(())
}

/// `vex.json` next to `feeds.json`.
pub fn default_path() -> Option<PathBuf> {
    crate::feeds::default_path().map(|p| p.with_file_name("vex.json"))
}

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
#[derive(Debug, Default)]
pub struct ImportReport {
    pub cache: PathBuf,
    pub files: usize,
    pub statements: usize,
    pub rejected: Vec<String>,
    pub total: usize,
}
impl ImportReport {
    pub fn lines(&self) -> Vec<String> {
        let mut out = vec![format!(
            "VEX: {} files, {} statements",
            self.files, self.statements
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
            "{} statements in the cache {}",
            self.total,
            self.cache.display()
        ));
        out
    }
}

/// Imports VEX files or directories into the cache at `cache`; files that are not VEX are
/// reported and skipped, nothing is written when no file could be used.
pub fn import(paths: &[PathBuf], cache: &Path, now: u64) -> Result<ImportReport, String> {
    if paths.is_empty() {
        return Err("Provide one or more VEX files (CSAF 2.0 or CycloneDX JSON) or folders".into());
    }
    let mut files = vec![];
    for p in paths {
        files.extend(expand(p)?);
    }
    let mut library = if cache.exists() {
        // A cache of an older version starts over (its files are imported again). A file that
        // does not load for any other reason stays as it is: it may be no cache at all (the
        // cache option naming a vendor's document), and saving would write over it.
        Library::read(cache)
            .map_err(|e| format!("{e}; nothing was imported and the file is unchanged"))?
            .unwrap_or_default()
    } else {
        Library::default()
    };
    let mut report = ImportReport {
        cache: cache.to_path_buf(),
        ..Default::default()
    };
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
        match parse(&bytes, &name) {
            Ok(statements) => {
                report.files += 1;
                report.statements += statements.len();
                library.merge(statements, &name)?;
            }
            Err(e) => report.rejected.push(format!("{name}: {e}")),
        }
    }
    if report.files == 0 {
        return Err(format!(
            "No VEX file could be read ({})",
            report.rejected.first().map_or("no files", String::as_str)
        ));
    }
    library.version = CACHE_VERSION;
    library.imported_at = now;
    library.save(cache)?;
    report.total = library.statements.len();
    Ok(report)
}

/// `feeds status`: what the cache holds.
pub fn status(library: &Library, path: &Path) -> Value {
    let mut by_state: BTreeMap<&str, usize> = BTreeMap::new();
    for s in &library.statements {
        *by_state.entry(s.state.label()).or_default() += 1;
    }
    serde_json::json!({
        "cache": path.display().to_string(),
        "imported_at": library.imported_at,
        "statements": library.statements.len(),
        "by_state": by_state,
        "sources": library.sources.iter().take(50).collect::<Vec<_>>(),
    })
}

static ACTIVE: crate::feeds::ActiveCache<Library> = crate::feeds::ActiveCache::new(
    "VEX",
    "no statements are used",
    default_path,
    Library::load,
);

/// Makes the cache at `explicit` (`--vex FILE`) the active statements.
pub fn load_active(explicit: &Path) -> Result<(), String> {
    ACTIVE.set(explicit)
}

/// Forgets the loaded statements, so the next [`active`] reads the cache again (the desktop after
/// an import).
pub fn reload() {
    ACTIVE.clear()
}

/// The active statements: the explicit cache, else the default cache when it exists, else none.
/// Tests never read the developer's own cache.
pub fn active() -> Arc<Library> {
    ACTIVE.get()
}

/// Reads the cache again when its file changed since it was loaded (see `feeds::refresh`).
pub fn refresh() {
    ACTIVE.refresh()
}

#[cfg(test)]
#[path = "vex_tests.rs"]
mod tests;
