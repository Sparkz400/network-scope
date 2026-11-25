//! Offline exploitation intelligence: the CISA Known Exploited Vulnerabilities (KEV) catalog and
//! the FIRST EPSS scores, imported from files the user downloaded, kept in a small local cache
//! and used to enrich and rank findings that carry CVE ids.
//!
//! Nothing here touches the network. `feeds import` reads the two files, `analyze` and
//! `analyze_snapshot` call [`apply`], which does nothing (and leaves the order alone) while no
//! cache exists. KEV says a CVE is exploited in the wild; EPSS is a probability estimate. Neither
//! says that a version-based hint is correct for the host in question.
use crate::risk::Finding;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

/// Size limits checked before a file is read (the catalog is about 1.5 MB, the plain EPSS CSV
/// about 10 MB at the time of writing).
pub const MAX_KEV_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_EPSS_BYTES: u64 = 128 * 1024 * 1024;
const MAX_CACHE_BYTES: u64 = 256 * 1024 * 1024;
/// Entry limits (the catalog has about 1,500 entries, EPSS about 300,000 rows).
const MAX_KEV_ENTRIES: usize = 100_000;
const MAX_EPSS_ROWS: usize = 2_000_000;
/// Longer lines are malformed.
const MAX_LINE: usize = 1024;
const CACHE_VERSION: u32 = 1;
/// EPSS values are kept with five decimals, which is what the published files carry.
const SCALE: f64 = 100_000.0;

/// A probability or percentile in 0..=1 with five decimals, stored as an integer so `Finding`
/// keeps its `Eq`. In JSON it is a plain number such as `0.97542`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Score(u32);
impl Score {
    /// `None` for anything that is not a finite number in 0..=1 (`NaN`, `inf`, `-0.1`, `1.5`).
    pub fn from_f64(v: f64) -> Option<Self> {
        (v.is_finite() && (0.0..=1.0).contains(&v)).then(|| Self((v * SCALE).round() as u32))
    }
    pub fn parse(s: &str) -> Option<Self> {
        Self::from_f64(s.trim().parse().ok()?)
    }
    pub fn as_f64(self) -> f64 {
        f64::from(self.0) / SCALE
    }
    /// "97.54 %" for 0.97542.
    pub fn percent_text(self) -> String {
        format!("{:.2} %", self.as_f64() * 100.0)
    }
}
impl Serialize for Score {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_f64(self.as_f64())
    }
}
impl<'de> Deserialize<'de> for Score {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = f64::deserialize(d)?;
        Self::from_f64(v).ok_or_else(|| serde::de::Error::custom("score must be 0 to 1"))
    }
}

/// What the feeds say about one finding, flattened into the finding's JSON. Every field is
/// omitted while empty, so exports are unchanged without imported feeds, and exports written
/// before these fields existed still load.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Exploit {
    /// One of the finding's CVEs is in the CISA KEV catalog.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub kev: bool,
    /// Earliest `dateAdded` (YYYY-MM-DD) among the finding's KEV CVEs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kev_added: Option<String>,
    /// KEV lists a known ransomware campaign use for one of the CVEs.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub kev_ransomware: bool,
    /// Highest EPSS probability (exploitation in the next 30 days) among the CVEs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epss: Option<Score>,
    /// Highest EPSS percentile among the CVEs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epss_percentile: Option<Score>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct KevEntry {
    /// `dateAdded`, YYYY-MM-DD.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub added: Option<String>,
    /// `knownRansomwareCampaignUse` is "Known".
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ransomware: bool,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Kev {
    #[serde(default)]
    pub catalog_version: String,
    #[serde(default)]
    pub date_released: String,
    pub entries: BTreeMap<String, KevEntry>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Epss {
    #[serde(default)]
    pub model_version: String,
    #[serde(default)]
    pub score_date: String,
    /// CVE id to [epss, percentile], both in units of 1e-5.
    pub scores: BTreeMap<String, [u32; 2]>,
}

/// The local cache (`feeds.json`): either part may be missing.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Feeds {
    #[serde(default)]
    pub version: u32,
    /// Unix time of the last import.
    #[serde(default)]
    pub imported_at: u64,
    #[serde(default)]
    pub kev: Option<Kev>,
    #[serde(default)]
    pub epss: Option<Epss>,
}

/// A parsed feed and the number of entries that were skipped as malformed.
#[derive(Debug)]
pub struct Parsed<T> {
    pub data: T,
    pub skipped: usize,
}

fn check_plain(bytes: &[u8], what: &str) -> Result<(), String> {
    if bytes.starts_with(&[0x1f, 0x8b]) {
        return Err(format!(
            "{what} is gzip-compressed; unpack it first (gunzip epss_scores-current.csv.gz)"
        ));
    }
    Ok(())
}

/// `CVE-YYYY-NNNN...` in upper case, or `None`.
fn normalize_cve(s: &str) -> Option<String> {
    let s = s.trim().to_ascii_uppercase();
    let rest = s.strip_prefix("CVE-")?;
    let (year, number) = rest.split_once('-')?;
    let ok = year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && (4..=10).contains(&number.len())
        && number.bytes().all(|b| b.is_ascii_digit());
    ok.then_some(s)
}

/// `YYYY-MM-DD` (shape only).
fn valid_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
        && (1..=12).contains(&s[5..7].parse::<u8>().unwrap_or(0))
        && (1..=31).contains(&s[8..10].parse::<u8>().unwrap_or(0))
}

fn bounded(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect::<String>()
}

/// The CISA catalog (`known_exploited_vulnerabilities.json`). Unknown fields are ignored; an
/// entry without a valid `cveID` is skipped.
pub fn parse_kev(bytes: &[u8]) -> Result<Parsed<Kev>, String> {
    check_plain(bytes, "KEV file")?;
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let root: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("KEV file is not valid JSON: {e}"))?;
    let list = root
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .ok_or("KEV file has no \"vulnerabilities\" list (expected known_exploited_vulnerabilities.json)")?;
    if list.len() > MAX_KEV_ENTRIES {
        return Err(format!("KEV file has more than {MAX_KEV_ENTRIES} entries"));
    }
    let text = |v: &serde_json::Value, key: &str| {
        v.get(key)
            .and_then(|s| s.as_str())
            .map(bounded)
            .unwrap_or_default()
    };
    let mut kev = Kev {
        catalog_version: text(&root, "catalogVersion"),
        date_released: text(&root, "dateReleased"),
        entries: BTreeMap::new(),
    };
    let mut skipped = 0;
    for item in list {
        let Some(id) = item
            .get("cveID")
            .and_then(|s| s.as_str())
            .and_then(normalize_cve)
        else {
            skipped += 1;
            continue;
        };
        let added = item
            .get("dateAdded")
            .and_then(|s| s.as_str())
            .map(str::trim)
            .filter(|d| valid_date(d))
            .map(str::to_string);
        let ransomware = item
            .get("knownRansomwareCampaignUse")
            .and_then(|s| s.as_str())
            .is_some_and(|s| s.trim().eq_ignore_ascii_case("known"));
        kev.entries
            .entry(id)
            .or_insert(KevEntry { added, ransomware });
    }
    if kev.entries.is_empty() {
        return Err("KEV file has no usable entries".into());
    }
    Ok(Parsed { data: kev, skipped })
}

/// The FIRST EPSS CSV: an optional `#model_version:...,score_date:...` comment line, the header
/// `cve,epss,percentile` (columns are found by name) and one row per CVE. Plain text only.
pub fn parse_epss(bytes: &[u8]) -> Result<Parsed<Epss>, String> {
    check_plain(bytes, "EPSS file")?;
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let text = std::str::from_utf8(bytes).map_err(|_| "EPSS file is not UTF-8 text")?;
    let mut epss = Epss::default();
    let mut columns: Option<(usize, usize, usize)> = None;
    let (mut skipped, mut rows) = (0, 0usize);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.len() > MAX_LINE {
            skipped += 1;
            continue;
        }
        if let Some(comment) = line.strip_prefix('#') {
            for part in comment.split(',') {
                if let Some((k, v)) = part.split_once([':', '=']) {
                    match k.trim() {
                        "model_version" => epss.model_version = bounded(v.trim()),
                        "score_date" => epss.score_date = bounded(v.trim()),
                        _ => {}
                    }
                }
            }
            continue;
        }
        let fields: Vec<&str> = line
            .split(',')
            .map(|f| f.trim().trim_matches('"'))
            .collect();
        let Some((ci, ei, pi)) = columns else {
            let find = |name: &str| fields.iter().position(|f| f.eq_ignore_ascii_case(name));
            let (Some(c), Some(e), Some(p)) = (find("cve"), find("epss"), find("percentile"))
            else {
                return Err("EPSS file has no header line \"cve,epss,percentile\"".into());
            };
            columns = Some((c, e, p));
            continue;
        };
        rows += 1;
        if rows > MAX_EPSS_ROWS {
            return Err(format!("EPSS file has more than {MAX_EPSS_ROWS} rows"));
        }
        let row = (|| {
            let id = normalize_cve(fields.get(ci)?)?;
            let score = Score::parse(fields.get(ei)?)?;
            let pct = Score::parse(fields.get(pi)?)?;
            Some((id, [score.0, pct.0]))
        })();
        match row {
            Some((id, v)) => {
                epss.scores.insert(id, v);
            }
            None => skipped += 1,
        }
    }
    if epss.scores.is_empty() {
        return Err("EPSS file has no usable rows".into());
    }
    Ok(Parsed {
        data: epss,
        skipped,
    })
}

impl Feeds {
    pub fn is_empty(&self) -> bool {
        self.kev.is_none() && self.epss.is_none()
    }

    /// Exploitation data for a finding with these CVE ids.
    pub fn exploit_for(&self, cves: &[String]) -> Exploit {
        let mut out = Exploit::default();
        for cve in cves {
            let Some(id) = normalize_cve(cve) else {
                continue;
            };
            if let Some(e) = self.kev.as_ref().and_then(|k| k.entries.get(&id)) {
                out.kev = true;
                out.kev_ransomware |= e.ransomware;
                if let Some(added) = &e.added {
                    // ISO dates compare as text.
                    if out.kev_added.as_ref().is_none_or(|old| added < old) {
                        out.kev_added = Some(added.clone());
                    }
                }
            }
            if let Some([s, p]) = self.epss.as_ref().and_then(|e| e.scores.get(&id)) {
                out.epss = out.epss.max(Some(Score(*s)));
                out.epss_percentile = out.epss_percentile.max(Some(Score(*p)));
            }
        }
        out
    }

    /// A SHA-256 of the KEV and EPSS data (the content of the cache), for the provenance stamp.
    pub fn fingerprint(&self) -> String {
        crate::provenance::hash(&serde_json::to_vec(self).unwrap_or_default())
    }

    /// Fills `Finding::exploit` for every finding that has CVE ids.
    pub fn enrich(&self, findings: &mut [Finding]) {
        for f in findings.iter_mut().filter(|f| !f.cve.is_empty()) {
            f.exploit = self.exploit_for(&f.cve);
        }
    }

    /// Reads a cache file, bounded and version-checked.
    pub fn load(path: &Path) -> Result<Self, String> {
        Self::read(path)?.map_err(|version| {
            format!(
                "{}: cache version {version} is not supported (expected {CACHE_VERSION}); import the feeds again",
                path.display()
            )
        })
    }

    /// [`Self::load`], with a cache that an older version of the program wrote told apart as
    /// `Ok(Err(its version))`: that one is expected after an upgrade, and an import starts
    /// over. Every other file that does not load is an error, and is never written over.
    fn read(path: &Path) -> Result<Result<Self, u32>, String> {
        /// What a feeds cache of any version has. The version alone does not make a file one:
        /// the caches next to it (`nvd.json`, `csaf.json`) and a CycloneDX document have one
        /// too, and every other field of [`Feeds`] may be missing.
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct Header {
            version: u32,
            kev: serde::de::IgnoredAny,
            epss: serde::de::IgnoredAny,
        }
        let size = std::fs::metadata(path)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .len();
        if size > MAX_CACHE_BYTES {
            return Err(format!("{}: file is too large", path.display()));
        }
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let not_a_cache =
            |e: serde_json::Error| format!("{}: not a feeds cache: {e}", path.display());
        let header: Header = serde_json::from_slice(&bytes).map_err(not_a_cache)?;
        match header.version.cmp(&CACHE_VERSION) {
            std::cmp::Ordering::Less => Ok(Err(header.version)),
            std::cmp::Ordering::Equal => {
                serde_json::from_slice(&bytes).map(Ok).map_err(not_a_cache)
            }
            std::cmp::Ordering::Greater => Err(format!(
                "{}: cache version {} is not supported (expected {CACHE_VERSION}); a newer version of the program wrote it",
                path.display(),
                header.version
            )),
        }
    }

    /// Writes the cache through a temporary file, so an interrupted import keeps the old one.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        check_size(bytes.len(), MAX_CACHE_BYTES, path)?;
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

/// A cache that `load` would refuse for its size (`limit`) is not written: the next import
/// could not read it back.
pub(crate) fn check_size(bytes: usize, limit: u64, path: &Path) -> Result<(), String> {
    if bytes as u64 > limit {
        return Err(format!(
            "{}: the cache would be larger than {} MB and could not be read again; nothing was written",
            path.display(),
            limit / (1024 * 1024)
        ));
    }
    Ok(())
}

/// `feeds.json` in the per-user configuration folder (see `appdir`), next to the user
/// `cves.json`.
pub fn default_path() -> Option<PathBuf> {
    crate::appdir::file("feeds.json")
}

/// Result of an import, for the command's output.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub path: PathBuf,
    pub kev_entries: Option<usize>,
    pub kev_skipped: usize,
    pub epss_rows: Option<usize>,
    pub epss_skipped: usize,
}
impl ImportReport {
    pub fn lines(&self) -> Vec<String> {
        let mut out = vec![];
        if let Some(n) = self.kev_entries {
            out.push(format!(
                "KEV: {n} known exploited CVEs ({} entries skipped)",
                self.kev_skipped
            ));
        }
        if let Some(n) = self.epss_rows {
            out.push(format!(
                "EPSS: {n} scores ({} rows skipped)",
                self.epss_skipped
            ));
        }
        out.push(format!("Cache written to {}", self.path.display()));
        out
    }
}

fn read_limited(path: &Path, limit: u64, what: &str) -> Result<Vec<u8>, String> {
    let size = std::fs::metadata(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .len();
    if size > limit {
        return Err(format!(
            "{what} file is too large (limit {} MB)",
            limit / (1024 * 1024)
        ));
    }
    std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Imports a KEV file and/or an EPSS file into the cache at `cache`. A part that is not given
/// keeps its previous content. Nothing is written when a file is rejected, or when what stands
/// at `cache` cannot be loaded (a cache of an older version starts over).
pub fn import(
    kev: Option<&Path>,
    epss: Option<&Path>,
    cache: &Path,
    now: u64,
) -> Result<ImportReport, String> {
    if kev.is_none() && epss.is_none() {
        return Err("Provide --kev FILE and/or --epss FILE".into());
    }
    let mut report = ImportReport {
        path: cache.to_path_buf(),
        ..Default::default()
    };
    // Before the feed files are read: the part that is not given comes from this cache, so a
    // file that does not load (damaged, a newer version, the cache option naming another
    // file) stays as it is.
    let mut feeds = if cache.exists() {
        Feeds::read(cache)
            .map_err(|e| format!("{e}; nothing was imported and the file is unchanged"))?
            .unwrap_or_default()
    } else {
        Feeds::default()
    };
    let kev = kev
        .map(|p| parse_kev(&read_limited(p, MAX_KEV_BYTES, "KEV")?))
        .transpose()?;
    let epss = epss
        .map(|p| parse_epss(&read_limited(p, MAX_EPSS_BYTES, "EPSS")?))
        .transpose()?;
    if let Some(p) = kev {
        report.kev_entries = Some(p.data.entries.len());
        report.kev_skipped = p.skipped;
        feeds.kev = Some(p.data);
    }
    if let Some(p) = epss {
        report.epss_rows = Some(p.data.scores.len());
        report.epss_skipped = p.skipped;
        feeds.epss = Some(p.data);
    }
    feeds.version = CACHE_VERSION;
    feeds.imported_at = now;
    feeds.save(cache)?;
    Ok(report)
}

/// `feeds status`: what the cache holds.
pub fn status(feeds: &Feeds, path: &Path) -> serde_json::Value {
    serde_json::json!({
        "schema": crate::schema::id("feeds-status"),
        "cache": path.display().to_string(),
        "imported_at": feeds.imported_at,
        "kev": feeds.kev.as_ref().map(|k| serde_json::json!({
            "entries": k.entries.len(),
            "catalog_version": k.catalog_version,
            "date_released": k.date_released,
        })),
        "epss": feeds.epss.as_ref().map(|e| serde_json::json!({
            "scores": e.scores.len(),
            "model_version": e.model_version,
            "score_date": e.score_date,
        })),
    })
}

// ---- Active feeds -------------------------------------------------------------------------

/// The process-wide copy of one cache file (`feeds.json`, `nvd.json`, `csaf.json`, `vex.json`,
/// `sboms.json`): loaded on first use, and again by [`ActiveCache::refresh`] when the file has
/// changed, so a monitor that runs for weeks uses what was imported in the meantime.
pub(crate) struct ActiveCache<T> {
    /// The name in messages ("Feeds", "NVD").
    label: &'static str,
    /// What it means that the default cache could not be loaded ("findings are not enriched").
    without: &'static str,
    default_path: fn() -> Option<PathBuf>,
    load: fn(&Path) -> Result<T, String>,
    slot: RwLock<Option<Loaded<T>>>,
}
struct Loaded<T> {
    data: Arc<T>,
    /// The file `data` is from; `None` when there is none to look at again (tests, no
    /// configuration folder).
    path: Option<PathBuf>,
    stamp: Stamp,
}
/// Modification time and length of a file, `None` while it does not exist: tells a rewritten
/// cache from the loaded one without reading it.
pub(crate) type Stamp = Option<(std::time::SystemTime, u64)>;
pub(crate) fn stamp(path: &Path) -> Stamp {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.modified().ok()?, meta.len()))
}
impl<T: Default> ActiveCache<T> {
    pub(crate) const fn new(
        label: &'static str,
        without: &'static str,
        default_path: fn() -> Option<PathBuf>,
        load: fn(&Path) -> Result<T, String>,
    ) -> Self {
        Self {
            label,
            without,
            default_path,
            load,
            slot: RwLock::new(None),
        }
    }
    fn write(&self) -> std::sync::RwLockWriteGuard<'_, Option<Loaded<T>>> {
        self.slot.write().unwrap_or_else(|e| e.into_inner())
    }
    /// Makes the cache at `path` the active one; an error when it is missing or unreadable, and
    /// the previous one then stays.
    pub(crate) fn set(&self, path: &Path) -> Result<(), String> {
        // Taken before the read: a file replaced in between counts as changed afterwards.
        let stamp = stamp(path);
        let data = Arc::new((self.load)(path)?);
        *self.write() = Some(Loaded {
            data,
            path: Some(path.to_path_buf()),
            stamp,
        });
        Ok(())
    }
    /// Forgets the loaded data: the next [`Self::get`] reads the default cache again.
    pub(crate) fn clear(&self) {
        *self.write() = None;
    }
    /// The active data: what [`Self::set`] loaded, else the default cache when it exists, else
    /// nothing. An unreadable default cache is reported on stderr.
    pub(crate) fn get(&self) -> Arc<T> {
        if let Some(loaded) = &*self.slot.read().unwrap_or_else(|e| e.into_inner()) {
            return loaded.data.clone();
        }
        // Tests never read the developer's own cache.
        let path = (self.default_path)().filter(|_| !cfg!(test));
        let stamp = path.as_deref().and_then(stamp);
        let data = match &path {
            Some(p) if stamp.is_some() => (self.load)(p).unwrap_or_else(|e| {
                eprintln!("{}: {e}; {}", self.label, self.without);
                T::default()
            }),
            _ => T::default(),
        };
        let loaded = Loaded {
            data: Arc::new(data),
            path,
            stamp,
        };
        self.write().get_or_insert(loaded).data.clone()
    }
    /// Loads the file again when it changed (or appeared) since it was loaded. A file that is
    /// gone or cannot be loaded now (half written, damaged, another version) keeps the loaded
    /// data in use; that is said once, and the file is read again only after its next change.
    pub(crate) fn refresh(&self) {
        let (path, loaded) = match self.write().as_ref() {
            Some(Loaded {
                path: Some(path),
                stamp,
                ..
            }) => (path.clone(), *stamp),
            _ => return,
        };
        let now = stamp(&path);
        if now.is_none() || now == loaded {
            return;
        }
        let result = (self.load)(&path);
        let mut slot = self.write();
        let Some(active) = slot.as_mut().filter(|a| a.path.as_ref() == Some(&path)) else {
            return;
        };
        active.stamp = now;
        match result {
            Ok(data) => active.data = Arc::new(data),
            Err(e) => eprintln!("{}: {e}; the data loaded before stays in use", self.label),
        }
    }
}

static ACTIVE: ActiveCache<Feeds> = ActiveCache::new(
    "Feeds",
    "findings are not enriched",
    default_path,
    Feeds::load,
);

/// Makes the cache at `explicit` (`--feeds FILE`) the active feeds; an error when it is missing
/// or unreadable. The previous feeds stay in place on error.
pub fn load_active(explicit: &Path) -> Result<(), String> {
    ACTIVE.set(explicit)
}

/// The active feeds: the explicit cache, else the default cache when it exists, else nothing.
/// An unreadable default cache is reported once on stderr. Tests never read the developer's
/// own cache.
pub fn active() -> Arc<Feeds> {
    ACTIVE.get()
}

/// Reads the cache again when its file changed since it was loaded (an import while a monitor
/// runs). Never an error: a file that cannot be read keeps the loaded feeds in use.
pub fn refresh() {
    ACTIVE.refresh()
}

/// Enriches the findings from the active feeds and ranks them. A no-op without feeds: the
/// caller's order stays.
pub fn apply(findings: &mut [Finding]) {
    let feeds = active();
    if feeds.is_empty() {
        return;
    }
    feeds.enrich(findings);
    rank(findings);
}

/// Known exploited first, then severity, then EPSS; ties by host, port and id (the order the
/// plain severity sort uses).
pub fn rank(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.exploit
            .kev
            .cmp(&a.exploit.kev)
            .then(b.severity.cmp(&a.severity))
            .then(b.exploit.epss.cmp(&a.exploit.epss))
            .then(a.ip.cmp(&b.ip))
            .then(a.port.cmp(&b.port))
            .then(a.id.cmp(&b.id))
    });
}

/// The order without feeds: severity, then host, port and id.
pub fn sort_by_severity(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.ip.cmp(&b.ip))
            .then(a.port.cmp(&b.port))
            .then(a.id.cmp(&b.id))
    });
}

/// "Known exploited" and EPSS badges for the HTML report (empty without feed data). Dates come
/// from validated cache fields but are escaped by construction: digits and dashes only.
pub fn badges_html(f: &Finding) -> String {
    let e = &f.exploit;
    let mut o = String::new();
    if e.kev {
        let since = e
            .kev_added
            .as_deref()
            .filter(|d| valid_date(d))
            .map(|d| format!(" (since {d})"))
            .unwrap_or_default();
        o.push_str(&format!(
            " <span class=\"badge\" style=\"background:#b71c1c\">Known exploited{since}</span>"
        ));
        if e.kev_ransomware {
            o.push_str(" <span class=\"badge\" style=\"background:#6a1b9a\">Ransomware use</span>");
        }
    }
    if let Some(s) = e.epss {
        o.push_str(&format!(
            " <span class=\"badge\" style=\"background:#546e7a\">EPSS {}</span>",
            s.percent_text()
        ));
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::risk::Severity;

    const KEV: &str = include_str!("../../tests/fixtures/kev.json");
    const EPSS: &str = include_str!("../../tests/fixtures/epss.csv");

    fn finding(sev: Severity, ip: &str, id: &str, cve: &[&str]) -> Finding {
        Finding {
            severity: sev,
            id: id.into(),
            title: id.into(),
            ip: ip.parse().unwrap(),
            port: Some(80),
            evidence: String::new(),
            cve: cve.iter().map(|c| c.to_string()).collect(),
            advice: String::new(),
            exploit: Exploit::default(),
            reference: None,
            confidence: 0,
            vex: None,
        }
    }
    fn feeds() -> Feeds {
        Feeds {
            version: CACHE_VERSION,
            imported_at: 1,
            kev: Some(parse_kev(KEV.as_bytes()).unwrap().data),
            epss: Some(parse_epss(EPSS.as_bytes()).unwrap().data),
        }
    }
    fn ids(list: &[Finding]) -> Vec<&str> {
        list.iter().map(|f| f.id.as_str()).collect()
    }

    /// What a monitor relies on between two cycles: a cache that was imported again is read
    /// again, and one that cannot be read right now changes nothing.
    #[test]
    fn an_active_cache_follows_its_file_and_keeps_its_data_when_the_file_is_broken() {
        let dir = std::env::temp_dir().join(format!("ns-active-cache-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("cache.txt");
        let cache = ActiveCache::<String>::new(
            "Test",
            "nothing is used",
            || None,
            |path| match std::fs::read_to_string(path) {
                Ok(text) if text.starts_with("cache") => Ok(text),
                Ok(_) => Err("not a cache".into()),
                Err(e) => Err(e.to_string()),
            },
        );
        // Nothing is loaded yet, and a file that is not there is not made active.
        cache.refresh();
        assert!(cache.set(&file).is_err());
        std::fs::write(&file, "cache 1").unwrap();
        cache.set(&file).unwrap();
        let first = cache.get();
        assert_eq!(*first, "cache 1");
        // Unchanged: not read again.
        cache.refresh();
        assert!(Arc::ptr_eq(&first, &cache.get()));
        // Imported again (the length differs, so the test does not depend on the clock).
        std::fs::write(&file, "cache of the second import").unwrap();
        cache.refresh();
        assert_eq!(*cache.get(), "cache of the second import");
        // Half written, then gone: the loaded data stays in use.
        std::fs::write(&file, "{").unwrap();
        cache.refresh();
        assert_eq!(*cache.get(), "cache of the second import");
        std::fs::remove_file(&file).unwrap();
        cache.refresh();
        assert_eq!(*cache.get(), "cache of the second import");
        // Complete again.
        std::fs::write(&file, "cache, third").unwrap();
        cache.refresh();
        assert_eq!(*cache.get(), "cache, third");
        // Forgotten: tests have no default cache, so nothing is active.
        cache.clear();
        assert_eq!(*cache.get(), "");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kev_fixture_parses_and_ignores_unknown_fields() {
        let p = parse_kev(KEV.as_bytes()).unwrap();
        assert_eq!(p.data.catalog_version, "2026.11.12");
        assert_eq!(p.data.date_released, "2026-11-12T15:04:05.000Z");
        // Four valid entries; one without a usable cveID and one with a number are skipped.
        assert_eq!(p.data.entries.len(), 4);
        assert_eq!(p.skipped, 2);
        let e = &p.data.entries["CVE-2021-44228"];
        assert_eq!(e.added.as_deref(), Some("2021-12-10"));
        assert!(e.ransomware);
        let e = &p.data.entries["CVE-2023-48795"];
        assert!(!e.ransomware);
        // A bad date is dropped, the entry stays; lower-case ids are normalized.
        assert_eq!(p.data.entries["CVE-2020-0001"].added, None);
    }

    #[test]
    fn epss_fixture_parses_header_comment_and_skips_bad_rows() {
        let p = parse_epss(EPSS.as_bytes()).unwrap();
        assert_eq!(p.data.model_version, "v2025.03.14");
        assert_eq!(p.data.score_date, "2026-11-18T12:55:00Z");
        assert_eq!(p.data.scores.len(), 4);
        // NaN, a score above 1, a short row and a bad id.
        assert_eq!(p.skipped, 4);
        assert_eq!(p.data.scores["CVE-2021-44228"], [97_544, 99_998]);
        assert_eq!(p.data.scores["CVE-2023-48795"], [431, 52_200]);
    }

    #[test]
    fn epss_tolerates_bom_crlf_column_order_and_no_comment() {
        let text = "\u{feff}percentile,extra,epss,cve\r\n0.5,x,0.25,cve-2024-0001\r\n";
        let p = parse_epss(text.as_bytes()).unwrap();
        assert_eq!(p.data.scores["CVE-2024-0001"], [25_000, 50_000]);
        assert_eq!(p.data.model_version, "");
    }

    #[test]
    fn malformed_input_is_rejected_without_panicking() {
        assert!(parse_kev(b"").is_err());
        assert!(parse_kev(b"not json").is_err());
        assert!(parse_kev(b"[]").is_err());
        assert!(parse_kev(br#"{"vulnerabilities": 3}"#).is_err());
        assert!(parse_kev(br#"{"vulnerabilities": []}"#).is_err());
        assert!(parse_kev(br#"{"vulnerabilities": [{"cveID": "nope"}]}"#).is_err());
        assert!(parse_kev(&[0xff, 0xfe, 0x00]).is_err());
        assert!(parse_epss(b"").is_err());
        assert!(parse_epss(b"#model_version:v1\n").is_err());
        assert!(parse_epss(b"cve,epss\nCVE-2024-0001,0.1\n").is_err());
        assert!(parse_epss(b"cve,epss,percentile\n").is_err());
        assert!(parse_epss(b"cve,epss,percentile\nCVE-2024-0001,abc,0.1\n").is_err());
        assert!(parse_epss(&[0xff, 0xfe, 0x00]).is_err());
        // Oversized line and deep nesting.
        let long = format!(
            "cve,epss,percentile\nCVE-2024-0001,0.1,{}\n",
            "9".repeat(5000)
        );
        assert!(parse_epss(long.as_bytes()).is_err());
        let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
        assert!(parse_kev(deep.as_bytes()).is_err());
        // Truncated input.
        for cut in 0..KEV.len().min(300) {
            let _ = parse_kev(&KEV.as_bytes()[..cut]);
        }
        for cut in 0..EPSS.len().min(300) {
            let _ = parse_epss(&EPSS.as_bytes()[..cut]);
        }
    }

    #[test]
    fn gzip_input_gets_a_clear_message() {
        let gz = [0x1f, 0x8b, 8, 0, 0, 0];
        let e = parse_epss(&gz).unwrap_err();
        assert!(e.contains("gunzip"), "{e}");
        assert!(parse_kev(&gz).unwrap_err().contains("gzip"));
    }

    #[test]
    fn score_rejects_non_finite_and_out_of_range() {
        for bad in ["NaN", "inf", "-inf", "-0.1", "1.01", "", "x", "1e400"] {
            assert_eq!(Score::parse(bad), None, "{bad}");
        }
        assert_eq!(Score::parse("0"), Some(Score(0)));
        assert_eq!(Score::parse("1"), Some(Score(100_000)));
        assert_eq!(Score::parse(" 0.00043 "), Some(Score(43)));
        assert_eq!(Score(97_544).percent_text(), "97.54 %");
    }

    #[test]
    fn enrichment_takes_the_strongest_value_over_all_cves() {
        let f = feeds();
        let e = f.exploit_for(&["CVE-2023-48795".into(), "CVE-2021-44228".into()]);
        assert!(e.kev && e.kev_ransomware);
        assert_eq!(e.kev_added.as_deref(), Some("2021-12-10"));
        assert_eq!(e.epss, Some(Score(97_544)));
        assert_eq!(e.epss_percentile, Some(Score(99_998)));
        // EPSS only: not in KEV.
        let e = f.exploit_for(&["CVE-2024-6387".into()]);
        assert!(!e.kev && e.kev_added.is_none() && !e.kev_ransomware);
        assert_eq!(e.epss, Some(Score(1_234)));
        // Unknown and empty.
        assert_eq!(f.exploit_for(&["CVE-1999-0001".into()]), Exploit::default());
        assert_eq!(f.exploit_for(&[]), Exploit::default());
        // Only findings with CVEs are touched.
        let mut list = vec![
            finding(Severity::High, "10.0.0.1", "a", &[]),
            finding(Severity::High, "10.0.0.1", "b", &["CVE-2021-44228"]),
        ];
        f.enrich(&mut list);
        assert_eq!(list[0].exploit, Exploit::default());
        assert!(list[1].exploit.kev);
    }

    #[test]
    fn ranking_is_kev_then_severity_then_epss() {
        let f = feeds();
        let mut list = vec![
            finding(Severity::Critical, "10.0.0.1", "crit-no-feed", &[]),
            finding(Severity::Medium, "10.0.0.2", "med-kev", &["CVE-2021-44228"]),
            finding(
                Severity::High,
                "10.0.0.3",
                "high-low-epss",
                &["CVE-2024-6387"],
            ),
            finding(
                Severity::High,
                "10.0.0.4",
                "high-high-epss",
                &["CVE-2025-1111"],
            ),
            finding(
                Severity::High,
                "10.0.0.5",
                "high-kev",
                &["CVE-2023-48795", "CVE-2020-0001"],
            ),
        ];
        sort_by_severity(&mut list);
        assert_eq!(
            ids(&list),
            [
                "crit-no-feed",
                "high-low-epss",
                "high-high-epss",
                "high-kev",
                "med-kev"
            ]
        );
        f.enrich(&mut list);
        rank(&mut list);
        // KEV: high-kev (high) before med-kev (medium); then severity; EPSS breaks the tie
        // between the two high findings without KEV.
        assert_eq!(
            ids(&list),
            [
                "high-kev",
                "med-kev",
                "crit-no-feed",
                "high-high-epss",
                "high-low-epss"
            ]
        );
        // Restoring the plain order is possible.
        sort_by_severity(&mut list);
        assert_eq!(list[0].id, "crit-no-feed");
    }

    #[test]
    fn without_feeds_apply_keeps_the_order() {
        // Tests never load the developer's cache, so the active feeds are empty.
        let mut list = vec![
            finding(Severity::Low, "10.0.0.2", "b", &["CVE-2021-44228"]),
            finding(Severity::High, "10.0.0.1", "a", &["CVE-2021-44228"]),
        ];
        let before = list.clone();
        apply(&mut list);
        assert_eq!(list, before);
    }

    #[test]
    fn json_is_unchanged_without_feeds_and_old_exports_still_load() {
        let plain = finding(Severity::High, "10.0.0.1", "x", &["CVE-2021-44228"]);
        let json = serde_json::to_value(&plain).unwrap();
        let keys: Vec<_> = json.as_object().unwrap().keys().cloned().collect();
        assert!(
            !keys
                .iter()
                .any(|k| k.starts_with("kev") || k.starts_with("epss") || k == "exploit"),
            "{keys:?}"
        );
        // An export from before the feeds existed.
        let old = r#"{"severity":"high","id":"cve-x","title":"t","ip":"10.0.0.1","port":22,
            "evidence":"e","cve":["CVE-2021-44228"],"advice":"a"}"#;
        let loaded: Finding = serde_json::from_str(old).unwrap();
        assert_eq!(loaded.exploit, Exploit::default());
        assert_eq!(loaded.cve, ["CVE-2021-44228"]);
        // Enriched findings round-trip, flattened.
        let mut e = plain;
        feeds().enrich(std::slice::from_mut(&mut e));
        let json = serde_json::to_value(&e).unwrap();
        assert_eq!(json["kev"], true);
        assert_eq!(json["kev_added"], "2021-12-10");
        assert_eq!(json["kev_ransomware"], true);
        assert_eq!(json["epss"], 0.97544);
        assert_eq!(json["epss_percentile"], 0.99998);
        let back: Finding = serde_json::from_value(json).unwrap();
        assert_eq!(back, e);
        // Hostile values in an imported export are rejected.
        let bad = old.replace("\"advice\"", "\"epss\":7,\"advice\"");
        assert!(serde_json::from_str::<Finding>(&bad).is_err());
    }

    #[test]
    fn html_badges() {
        let mut f = finding(Severity::High, "10.0.0.1", "x", &["CVE-2021-44228"]);
        assert_eq!(badges_html(&f), "");
        feeds().enrich(std::slice::from_mut(&mut f));
        let html = badges_html(&f);
        assert!(
            html.contains("Known exploited (since 2021-12-10)"),
            "{html}"
        );
        assert!(html.contains("Ransomware use"));
        assert!(html.contains("EPSS 97.54 %"));
        // EPSS without KEV shows only the score.
        let mut g = finding(Severity::High, "10.0.0.1", "x", &["CVE-2024-6387"]);
        feeds().enrich(std::slice::from_mut(&mut g));
        let html = badges_html(&g);
        assert!(!html.contains("Known exploited") && html.contains("EPSS 1.23 %"));
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ns-feeds-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn import_writes_a_cache_and_keeps_the_part_not_imported() {
        let dir = temp("import");
        let kev = dir.join("kev.json");
        let epss = dir.join("epss.csv");
        std::fs::write(&kev, KEV).unwrap();
        std::fs::write(&epss, EPSS).unwrap();
        let cache = dir.join("sub").join("feeds.json");
        assert!(import(None, None, &cache, 5).is_err());
        let r = import(Some(&kev), None, &cache, 10).unwrap();
        assert_eq!(
            (r.kev_entries, r.epss_rows, r.kev_skipped),
            (Some(4), None, 2)
        );
        let loaded = Feeds::load(&cache).unwrap();
        assert!(loaded.kev.is_some() && loaded.epss.is_none());
        assert_eq!(loaded.imported_at, 10);
        // Importing EPSS afterwards keeps the KEV part.
        let r = import(None, Some(&epss), &cache, 20).unwrap();
        assert_eq!(r.epss_rows, Some(4));
        let loaded = Feeds::load(&cache).unwrap();
        assert!(loaded.kev.is_some() && loaded.epss.is_some());
        assert_eq!(loaded.imported_at, 20);
        assert_eq!(loaded, feeds_with(20));
        // A rejected file leaves the cache alone.
        let bad = dir.join("bad.json");
        std::fs::write(&bad, "{}").unwrap();
        assert!(import(Some(&bad), None, &cache, 30).is_err());
        assert_eq!(Feeds::load(&cache).unwrap().imported_at, 20);
        assert!(!cache.with_extension("json.tmp").exists());
        // A missing file.
        assert!(import(Some(&dir.join("none")), None, &cache, 1).is_err());
        let r = import(Some(&kev), None, &cache, 40).unwrap();
        assert!(r.lines().iter().any(|l| l.starts_with("KEV: 4")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What stands at the cache path decides what an import may do with it: only a cache of
    /// this version is added to (an import of one feed keeps the other from it), one of an
    /// older version starts over, and anything else is left alone.
    #[test]
    fn an_import_never_writes_over_a_file_it_could_not_load() {
        let dir = temp("guard");
        let (kev, cache) = (dir.join("kev.json"), dir.join("feeds.json"));
        std::fs::write(&kev, KEV).unwrap();
        let newer = format!(
            r#"{{"version":{},"imported_at":1,"kev":null,"epss":null}}"#,
            CACHE_VERSION + 1
        );
        // Another cache where this one should be (`--feeds csaf.json`), the feed itself, a
        // damaged file and a cache from a newer version of the program.
        for (case, content) in [
            (
                "another cache",
                r#"{"version":1,"imported_at":1,"sources":[],"entries":[]}"#,
            ),
            ("the KEV file", KEV),
            ("any JSON object", "{}"),
            ("damaged", r#"{"version":1,"imported_at":1,"kev":{"entr"#),
            ("empty", ""),
            ("newer", newer.as_str()),
        ] {
            std::fs::write(&cache, content).unwrap();
            let e = import(Some(&kev), None, &cache, 5).unwrap_err();
            assert!(e.contains("the file is unchanged"), "{case}: {e}");
            assert_eq!(std::fs::read_to_string(&cache).unwrap(), content, "{case}");
        }
        // A cache an older version wrote, with a part this version cannot read: the import
        // starts over.
        let old = r#"{"version":0,"imported_at":1,"kev":{"shape":"of version 0"},"epss":null}"#;
        std::fs::write(&cache, old).unwrap();
        assert!(
            Feeds::load(&cache)
                .unwrap_err()
                .contains("import the feeds again")
        );
        import(Some(&kev), None, &cache, 5).unwrap();
        let feeds = Feeds::load(&cache).unwrap();
        assert!(feeds.version == CACHE_VERSION && feeds.kev.is_some() && feeds.epss.is_none());
        // A cache this version could not load again is not written.
        assert!(check_size(MAX_CACHE_BYTES as usize, MAX_CACHE_BYTES, &cache).is_ok());
        let e = check_size(MAX_CACHE_BYTES as usize + 1, MAX_CACHE_BYTES, &cache).unwrap_err();
        assert!(e.contains("nothing was written"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }
    fn feeds_with(at: u64) -> Feeds {
        Feeds {
            imported_at: at,
            ..feeds()
        }
    }

    #[test]
    fn cache_version_and_size_are_checked() {
        let dir = temp("cache");
        let path = dir.join("feeds.json");
        std::fs::write(&path, r#"{"version": 99, "kev": null, "epss": null}"#).unwrap();
        assert!(Feeds::load(&path).unwrap_err().contains("version"));
        std::fs::write(&path, "\"text\"").unwrap();
        assert!(Feeds::load(&path).is_err());
        assert!(Feeds::load(&dir.join("missing.json")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_input_is_refused_before_reading() {
        let dir = temp("size");
        let path = dir.join("kev.json");
        std::fs::write(&path, "x").unwrap();
        assert!(
            read_limited(&path, 0, "KEV")
                .unwrap_err()
                .contains("too large")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cve_ids_and_dates() {
        assert_eq!(
            normalize_cve(" cve-2021-44228 ").as_deref(),
            Some("CVE-2021-44228")
        );
        for bad in [
            "",
            "CVE-21-1",
            "CVE-2021-12",
            "CVE-2021-",
            "CVE-2021-12a4",
            "XCVE-2021-1234",
        ] {
            assert_eq!(normalize_cve(bad), None, "{bad}");
        }
        assert!(valid_date("2021-12-10"));
        for bad in [
            "2021-13-10",
            "2021-12-00",
            "20211210",
            "2021-1-1x",
            "2021-12-1é",
        ] {
            assert!(!valid_date(bad), "{bad}");
        }
    }
}
