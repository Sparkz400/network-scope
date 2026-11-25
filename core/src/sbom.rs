// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Software bills of materials of device firmware, imported from files (`feeds import sbom`).
//!
//! A network scan sees what a device announces (vendor, product, firmware version), never the
//! libraries inside its firmware. Those come from a **vendor's SBOM** or from analysing a
//! firmware image with a tool such as Syft, Trivy or EMBA. This module reads such files
//! (CycloneDX JSON 1.2 to 1.7, SPDX JSON 2.2 and 2.3) into a small local cache (`sboms.json` next
//! to `feeds.json`) and finds the SBOM of a device's firmware, so the CycloneDX export
//! ([`crate::cyclonedx`]) can nest the firmware's components under the device.
//!
//! Each SBOM describes one product version: its **subject** (vendor, product, version, from the
//! CycloneDX `metadata.component` or the package an SPDX document `DESCRIBES`), and its
//! **components**. A tool run on a firmware image usually names the image file as the subject,
//! so the import takes `--sbom-vendor`, `--sbom-product` and `--sbom-version` to say what the
//! SBOM is about. An SBOM without a product name or version is rejected: it could not be matched
//! to a device.
//!
//! **Matching** is by name, like the CISA advisories ([`crate::csaf`]): the vendors agree when
//! both are known, one of the normalised names (letters and digits only, at least 5 characters)
//! contains the other (Siemens CPUs also by their family), and the versions are equal after
//! normalisation (`V4.2.1` is `4.2.1`). A version range never matches: an SBOM lists the contents
//! of exactly one version. Nothing here touches the network; files are untrusted input and every
//! size is bounded.
use crate::csaf::{norm, norm_version, siemens_family, vendor_matches};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Arc,
};

/// Largest SBOM file read.
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CACHE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_FILES: usize = 20_000;
/// Components kept per SBOM; the rest is counted (`truncated`).
pub const MAX_COMPONENTS: usize = 20_000;
const MAX_SBOMS: usize = 10_000;
/// Nesting of CycloneDX `components` followed.
const MAX_DEPTH: usize = 16;
const MAX_TEXT: usize = 300;
const CACHE_VERSION: u32 = 1;

/// One component of an SBOM.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Component {
    /// A CycloneDX component type (`library`, `application`, `operating-system`, ...).
    pub kind: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub supplier: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub purl: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cpe: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub licenses: Vec<String>,
}

/// One imported SBOM: what it describes and what it lists.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sbom {
    /// File name it was imported from.
    pub source: String,
    /// `sha256:...` of the file.
    pub sha256: String,
    /// `CycloneDX 1.6`, `SPDX-2.3`.
    pub format: String,
    pub vendor: String,
    pub product: String,
    /// More names of the product, compared like the product name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    pub version: String,
    pub components: Vec<Component>,
    /// Components beyond [`MAX_COMPONENTS`] that were not kept.
    #[serde(default)]
    pub truncated: usize,
}

/// The imported SBOMs.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Library {
    pub version: u32,
    pub imported_at: u64,
    pub sboms: Vec<Sbom>,
}

/// What the import says about the SBOM, when the file's own subject is not the product (a tool
/// run on a firmware image names the image file).
#[derive(Clone, Debug, Default)]
pub struct Subject {
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
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

/// An organisation name in CycloneDX (`{"name": ...}`) or SPDX (`Organization: X (email)`).
fn organisation(v: Option<&Value>) -> String {
    match v {
        Some(Value::Object(o)) => o
            .get("name")
            .and_then(Value::as_str)
            .map(clean)
            .unwrap_or_default(),
        Some(Value::String(s)) => {
            let s = s
                .strip_prefix("Organization:")
                .or_else(|| s.strip_prefix("Person:"))
                .unwrap_or(s);
            let s = s.split('(').next().unwrap_or("");
            let s = clean(s);
            if s.eq_ignore_ascii_case("NOASSERTION") {
                String::new()
            } else {
                s
            }
        }
        _ => String::new(),
    }
}

const CYCLONEDX_TYPES: [&str; 13] = [
    "application",
    "framework",
    "library",
    "container",
    "platform",
    "operating-system",
    "device",
    "device-driver",
    "firmware",
    "file",
    "machine-learning-model",
    "data",
    "cryptographic-asset",
];

fn cyclonedx_type(t: &str) -> String {
    let t = t.trim().to_ascii_lowercase();
    if CYCLONEDX_TYPES.contains(&t.as_str()) {
        t
    } else {
        "library".into()
    }
}

/// SPDX `primaryPackagePurpose` as a CycloneDX component type.
fn spdx_type(purpose: &str) -> String {
    match purpose.trim().to_ascii_uppercase().as_str() {
        "FIRMWARE" => "firmware",
        "OPERATING-SYSTEM" => "operating-system",
        "APPLICATION" => "application",
        "FRAMEWORK" => "framework",
        "CONTAINER" => "container",
        "DEVICE" => "device",
        "FILE" => "file",
        _ => "library",
    }
    .into()
}

/// CycloneDX licenses: `[{"license": {"id"|"name": ...}}, {"expression": ...}]`.
fn cyclonedx_licenses(v: Option<&Value>) -> Vec<String> {
    let mut out = vec![];
    for l in v.and_then(Value::as_array).into_iter().flatten().take(16) {
        let name = l
            .get("license")
            .map(|x| {
                let id = text(x, "id");
                if id.is_empty() { text(x, "name") } else { id }
            })
            .unwrap_or_else(|| text(l, "expression"));
        if !name.is_empty() && !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

fn cyclonedx_component(c: &Value) -> Component {
    Component {
        kind: cyclonedx_type(&text(c, "type")),
        name: text(c, "name"),
        version: text(c, "version"),
        supplier: [
            organisation(c.get("supplier")),
            organisation(c.get("manufacturer")),
            text(c, "publisher"),
        ]
        .into_iter()
        .find(|s| !s.is_empty())
        .unwrap_or_default(),
        purl: text(c, "purl"),
        cpe: text(c, "cpe"),
        licenses: cyclonedx_licenses(c.get("licenses")),
    }
}

/// The parsed file before the import's own subject is applied.
#[derive(Debug, Default)]
pub struct Parsed {
    pub sbom: Sbom,
}

fn parse_cyclonedx(doc: &Value) -> Sbom {
    let meta = doc.get("metadata").unwrap_or(&Value::Null);
    let subject = meta.get("component").unwrap_or(&Value::Null);
    let mut sbom = Sbom {
        format: format!("CycloneDX {}", text(doc, "specVersion"))
            .trim()
            .to_string(),
        vendor: [
            organisation(subject.get("manufacturer")),
            organisation(subject.get("supplier")),
            organisation(meta.get("manufacture")),
            organisation(meta.get("supplier")),
            text(subject, "publisher"),
        ]
        .into_iter()
        .find(|s| !s.is_empty())
        .unwrap_or_default(),
        product: text(subject, "name"),
        version: text(subject, "version"),
        ..Default::default()
    };
    let mut stack: Vec<(&Value, usize)> = doc
        .get("components")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|c| (c, 0))
        .collect();
    stack.reverse();
    while let Some((c, depth)) = stack.pop() {
        if sbom.components.len() >= MAX_COMPONENTS {
            sbom.truncated += 1;
        } else {
            let component = cyclonedx_component(c);
            if !component.name.is_empty() {
                sbom.components.push(component);
            }
        }
        if depth < MAX_DEPTH
            && let Some(children) = c.get("components").and_then(Value::as_array)
        {
            stack.extend(children.iter().rev().map(|x| (x, depth + 1)));
        }
    }
    sbom
}

fn parse_spdx(doc: &Value) -> Sbom {
    let packages: Vec<&Value> = doc
        .get("packages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .collect();
    // The described package: `documentDescribes`, else a DESCRIBES relationship of the document.
    let mut described: Vec<String> = doc
        .get("documentDescribes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    for r in doc
        .get("relationships")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(1_000_000)
    {
        if text(r, "relationshipType") == "DESCRIBES"
            && text(r, "spdxElementId") == "SPDXRef-DOCUMENT"
        {
            described.push(text(r, "relatedSpdxElement"));
        }
    }
    // By id, the first package of each: neither list is bounded, and a search of the packages
    // per described id took hours on a crafted file.
    let mut by_id: std::collections::HashMap<String, &Value> = Default::default();
    for p in &packages {
        by_id.entry(text(p, "SPDXID")).or_insert(*p);
    }
    let subject = described.iter().find_map(|id| by_id.get(id)).copied();
    let external = |p: &Value, kinds: &[&str]| -> String {
        p.get("externalRefs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|r| kinds.contains(&text(r, "referenceType").as_str()))
            .map(|r| text(r, "referenceLocator"))
            .unwrap_or_default()
    };
    let license = |p: &Value| -> Vec<String> {
        ["licenseConcluded", "licenseDeclared"]
            .iter()
            .map(|k| text(p, k))
            .find(|l| !l.is_empty() && l != "NOASSERTION" && l != "NONE")
            .into_iter()
            .collect()
    };
    let mut sbom = Sbom {
        format: text(doc, "spdxVersion"),
        ..Default::default()
    };
    if let Some(s) = subject {
        sbom.product = text(s, "name");
        sbom.version = text(s, "versionInfo");
        if sbom.version == "NOASSERTION" {
            sbom.version.clear();
        }
        sbom.vendor = organisation(s.get("supplier"));
        if sbom.vendor.is_empty() {
            sbom.vendor = organisation(s.get("originator"));
        }
    }
    let subject_id = subject.map(|s| text(s, "SPDXID")).unwrap_or_default();
    for p in packages {
        if !subject_id.is_empty() && text(p, "SPDXID") == subject_id {
            continue;
        }
        if sbom.components.len() >= MAX_COMPONENTS {
            sbom.truncated += 1;
            continue;
        }
        let name = text(p, "name");
        if name.is_empty() {
            continue;
        }
        let version = text(p, "versionInfo");
        sbom.components.push(Component {
            kind: spdx_type(&text(p, "primaryPackagePurpose")),
            name,
            version: if version == "NOASSERTION" {
                String::new()
            } else {
                version
            },
            supplier: organisation(p.get("supplier")),
            purl: external(p, &["purl"]),
            cpe: external(p, &["cpe23Type", "cpe22Type"]),
            licenses: license(p),
        });
    }
    sbom
}

/// Reads one SBOM file's bytes. `subject` overrides what the file says it describes.
pub fn parse(bytes: &[u8], subject: &Subject) -> Result<Parsed, String> {
    let doc: Value = serde_json::from_slice(bytes).map_err(|e| format!("not JSON: {e}"))?;
    let mut sbom = if text(&doc, "bomFormat").eq_ignore_ascii_case("CycloneDX") {
        parse_cyclonedx(&doc)
    } else if text(&doc, "spdxVersion").starts_with("SPDX-") {
        parse_spdx(&doc)
    } else {
        return Err("neither CycloneDX JSON (bomFormat) nor SPDX JSON (spdxVersion)".into());
    };
    if let Some(v) = subject
        .vendor
        .as_deref()
        .map(clean)
        .filter(|v| !v.is_empty())
    {
        sbom.vendor = v;
    }
    if let Some(p) = subject
        .product
        .as_deref()
        .map(clean)
        .filter(|p| !p.is_empty())
    {
        // The file's own subject name is dropped: a tool run on an image names the image file
        // or `rootfs`, not a model.
        sbom.product = p;
    }
    if let Some(v) = subject
        .version
        .as_deref()
        .map(clean)
        .filter(|v| !v.is_empty())
    {
        sbom.version = v;
    }
    if sbom.product.is_empty() {
        return Err("no product name: the file names no subject; pass --sbom-product".into());
    }
    if sbom.version.is_empty() {
        return Err("no firmware version: the file names none; pass --sbom-version".into());
    }
    Ok(Parsed { sbom })
}

fn names_match(device: &[String], sbom: &Sbom) -> bool {
    let wanted: Vec<String> = std::iter::once(&sbom.product)
        .chain(&sbom.aliases)
        .map(|n| norm(n))
        .filter(|n| n.len() >= 5)
        .collect();
    let mut names: Vec<String> = device.iter().map(|n| norm(n)).collect();
    for n in device {
        if let Some(f) = siemens_family(n) {
            names.push(norm(f));
        }
    }
    names.iter().filter(|n| n.len() >= 5).any(|n| {
        wanted
            .iter()
            .any(|w| n.contains(w.as_str()) || w.contains(n.as_str()))
    })
}

impl Library {
    pub fn is_empty(&self) -> bool {
        self.sboms.is_empty()
    }

    /// The SBOM of a device's firmware: same version, a matching name, and the same vendor when
    /// both name one. An exact name wins over a contained one.
    pub fn find(&self, vendor: &str, names: &[String], version: &str) -> Option<&Sbom> {
        let version = norm_version(version);
        if version.is_empty() {
            return None;
        }
        let candidates = self.sboms.iter().filter(|s| {
            norm_version(&s.version).eq_ignore_ascii_case(version)
                && (s.vendor.is_empty() || vendor.is_empty() || vendor_matches(&s.vendor, vendor))
                && names_match(names, s)
        });
        let exact = |s: &&Sbom| names.iter().any(|n| norm(n) == norm(&s.product));
        let all: Vec<&Sbom> = candidates.collect();
        all.iter()
            .find(|s| exact(s))
            .or_else(|| all.first())
            .copied()
    }

    /// Adds an SBOM, replacing one for the same vendor, product and version.
    fn merge(&mut self, sbom: Sbom) -> Result<(), String> {
        let key = |s: &Sbom| {
            (
                norm(&s.vendor),
                norm(&s.product),
                norm_version(&s.version).to_ascii_lowercase(),
            )
        };
        let k = key(&sbom);
        self.sboms.retain(|s| key(s) != k);
        if self.sboms.len() >= MAX_SBOMS {
            return Err(format!("the cache would exceed {MAX_SBOMS} SBOMs"));
        }
        self.sboms.push(sbom);
        Ok(())
    }

    /// A SHA-256 of the cache's content, for the provenance stamp.
    pub fn fingerprint(&self) -> String {
        crate::provenance::hash(&serde_json::to_vec(self).unwrap_or_default())
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        Self::read(path)?.map_err(|version| {
            format!(
                "{}: cache version {version} is not supported (expected {CACHE_VERSION}); import the SBOMs again",
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
            sboms: Vec<serde::de::IgnoredAny>,
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
                _ => Err(format!("{}: not an SBOM cache: {e}", path.display())),
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

/// `sboms.json` next to `feeds.json`.
pub fn default_path() -> Option<PathBuf> {
    crate::feeds::default_path().map(|p| p.with_file_name("sboms.json"))
}

/// The `.json` files an argument names (a file, or a directory and its subdirectories one level
/// down), sorted.
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
    /// `vendor product version (N components)` per imported SBOM.
    pub imported: Vec<String>,
    pub rejected: Vec<String>,
    pub total: usize,
}
impl ImportReport {
    pub fn lines(&self) -> Vec<String> {
        let mut out = vec![format!("SBOM: {} imported", self.imported.len())];
        out.extend(self.imported.iter().take(50).map(|i| format!("  {i}")));
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
            "{} SBOMs in the cache {}",
            self.total,
            self.cache.display()
        ));
        out
    }
}

/// Imports SBOM files or directories into the cache at `cache`. A file that is not an SBOM, or
/// names no product or version, is reported and skipped; nothing is written when no file could
/// be used.
pub fn import(
    paths: &[PathBuf],
    subject: &Subject,
    cache: &Path,
    now: u64,
) -> Result<ImportReport, String> {
    if paths.is_empty() {
        return Err("Provide one or more SBOM files (CycloneDX or SPDX JSON) or folders".into());
    }
    let mut files = vec![];
    for p in paths {
        files.extend(expand(p)?);
    }
    let overridden =
        subject.vendor.is_some() || subject.product.is_some() || subject.version.is_some();
    if overridden && files.len() > 1 {
        return Err(format!(
            "--sbom-vendor, --sbom-product and --sbom-version describe one SBOM, but {} files were given; import them one by one",
            files.len()
        ));
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
        match parse(&bytes, subject) {
            Ok(Parsed { mut sbom }) => {
                sbom.source = clean(&name);
                sbom.sha256 = crate::provenance::hash(&bytes);
                report.imported.push(format!(
                    "{} {} {} ({} components{}) from {name}",
                    if sbom.vendor.is_empty() {
                        "-"
                    } else {
                        &sbom.vendor
                    },
                    sbom.product,
                    sbom.version,
                    sbom.components.len(),
                    if sbom.truncated > 0 {
                        format!(", {} more not kept", sbom.truncated)
                    } else {
                        String::new()
                    }
                ));
                library.merge(sbom)?;
            }
            Err(e) => report.rejected.push(format!("{name}: {e}")),
        }
    }
    if report.imported.is_empty() {
        return Err(format!(
            "No SBOM could be read ({})",
            report.rejected.first().map_or("no files", String::as_str)
        ));
    }
    library.version = CACHE_VERSION;
    library.imported_at = now;
    library.save(cache)?;
    report.total = library.sboms.len();
    Ok(report)
}

/// `feeds status`: what the cache holds.
pub fn status(library: &Library, path: &Path) -> Value {
    let products: BTreeSet<String> = library
        .sboms
        .iter()
        .take(200)
        .map(|s| {
            format!("{} {} {}", s.vendor, s.product, s.version)
                .trim()
                .to_string()
        })
        .collect();
    serde_json::json!({
        "cache": path.display().to_string(),
        "imported_at": library.imported_at,
        "sboms": library.sboms.len(),
        "components": library.sboms.iter().map(|s| s.components.len()).sum::<usize>(),
        "products": products,
    })
}

// ---- Active SBOMs --------------------------------------------------------------------------

static ACTIVE: crate::feeds::ActiveCache<Library> =
    crate::feeds::ActiveCache::new("SBOM", "no SBOMs are used", default_path, Library::load);

/// Makes the cache at `explicit` (`--sboms FILE`) the active SBOMs; an error when it is missing
/// or unreadable.
pub fn load_active(explicit: &Path) -> Result<(), String> {
    ACTIVE.set(explicit)
}

/// Forgets the loaded SBOMs, so the next [`active`] reads the cache again (the desktop after an
/// import).
pub fn reload() {
    ACTIVE.clear()
}

/// The active SBOMs: the explicit cache, else the default cache when it exists, else none.
/// Tests never read the developer's own cache.
pub fn active() -> Arc<Library> {
    ACTIVE.get()
}

/// Reads the cache again when its file changed since it was loaded (see `feeds::refresh`).
pub fn refresh() {
    ACTIVE.refresh()
}

/// A firmware a host reported, with the imported SBOM that describes it (the desktop's host
/// details).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirmwareSbom {
    /// Where the firmware was reported: `S7 identification`, `LLDP-MED`, `passive industrial
    /// traffic`.
    pub source: String,
    /// The firmware's name and version as the device reported them.
    pub name: String,
    pub version: String,
    /// The SBOM's position in [`Library::sboms`].
    pub sbom: usize,
}

/// The SBOMs of the firmware each host reported, found as the CycloneDX export finds them: the
/// industrial identification of an active scan (S7, Modbus, EtherNet/IP, OPC UA), the industrial
/// traffic and the LLDP-MED inventory observed for its MAC or address. Hosts without one are left
/// out.
pub fn for_hosts(
    library: &Library,
    hosts: &[crate::scan::Host],
    observations: &[crate::passive::Observation],
) -> std::collections::BTreeMap<std::net::IpAddr, Vec<FirmwareSbom>> {
    use std::collections::BTreeMap;
    let mut out: BTreeMap<std::net::IpAddr, Vec<FirmwareSbom>> = BTreeMap::new();
    if library.sboms.is_empty() {
        return out;
    }
    let index = |s: &Sbom| library.sboms.iter().position(|x| std::ptr::eq(x, s));
    // LLDP-MED inventory by MAC (lowercase).
    let mut lldp: BTreeMap<String, &std::collections::BTreeMap<String, String>> = BTreeMap::new();
    for o in observations.iter().filter(|o| o.protocol == "LLDP") {
        if !o.mac.is_empty() && o.fields.contains_key("med_model") {
            lldp.insert(o.mac.to_ascii_lowercase(), &o.fields);
        }
    }
    let assets = if observations.is_empty() {
        vec![]
    } else {
        crate::otpassive::assets(observations)
    };
    for h in hosts {
        let mut found: Vec<FirmwareSbom> = vec![];
        let mut add = |source: String, vendor: &str, names: Vec<String>, version: &str| {
            let name = names.first().cloned().unwrap_or_default();
            if let Some(i) = library.find(vendor, &names, version).and_then(index)
                && !found.iter().any(|f| f.sbom == i)
            {
                found.push(FirmwareSbom {
                    source,
                    name,
                    version: version.to_string(),
                    sbom: i,
                });
            }
        };
        for ot in crate::otdevice::from_identity(&h.identity) {
            add(
                format!("{} identification", ot.protocol),
                &ot.vendor,
                ot.products.clone(),
                &ot.version,
            );
        }
        let mac = h.mac.to_ascii_lowercase();
        for a in assets.iter().filter(|a| {
            (!mac.is_empty() && a.mac.eq_ignore_ascii_case(&mac)) || a.ips.contains(&h.ip)
        }) {
            add(
                "passive industrial traffic".into(),
                &a.vendor,
                vec![a.product.clone()],
                &a.firmware,
            );
        }
        if let Some(f) = lldp.get(&mac) {
            let get = |k: &str| f.get(k).cloned().unwrap_or_default();
            for field in ["med_firmware_revision", "med_software_revision"] {
                add(
                    "LLDP-MED".into(),
                    &get("med_manufacturer"),
                    vec![get("med_model")],
                    &get(field),
                );
            }
        }
        if !found.is_empty() {
            out.insert(h.ip, found);
        }
    }
    out
}

#[cfg(test)]
#[path = "sbom_tests.rs"]
mod tests;
