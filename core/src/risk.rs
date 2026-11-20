//! Findings derived from what a scan observed: weak TLS/SSH configuration, risky exposed
//! services, and version-based CVE hints. Version hints are NOT confirmed vulnerabilities:
//! distributions backport fixes without changing the version string.
use crate::scan::Host;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::IpAddr,
    path::Path,
    sync::{Arc, OnceLock, RwLock},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}
impl Severity {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "info" => Self::Info,
            "low" => Self::Low,
            "medium" | "med" => Self::Medium,
            "high" => Self::High,
            "critical" | "crit" => Self::Critical,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub id: String,
    pub title: String,
    pub ip: IpAddr,
    pub port: Option<u16>,
    pub evidence: String,
    pub cve: Vec<String>,
    pub advice: String,
    /// KEV and EPSS data from the imported feeds (`feeds import`); empty, and left out of the
    /// JSON, without them. Missing in exports written before the feeds existed.
    #[serde(default, flatten)]
    pub exploit: crate::feeds::Exploit,
    /// Official documentation for the finding (HTTPS URL), when the rule has one. Missing in
    /// exports written before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// How sure the rule is that the condition is real (0-100; see [`rule_confidence`]). 0 in
    /// exports written before the score existed, and then left out of the JSON.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub confidence: u8,
}
fn is_zero(v: &u8) -> bool {
    *v == 0
}

/// Confidence (0-100) that a finding of this rule is real. Direct observations (the server
/// said so) score 95, rules that read a service name or banner 90, an open port number alone 50
/// and version-based hints 40 (distributions backport fixes). `None` for an id without an
/// entry; a test requires one for every rule. The run-time families are looked up by their
/// prefix (`cve-`, `script-`).
pub fn rule_confidence(id: &str) -> Option<u8> {
    Some(match id {
        "tls-cert-expired"
        | "tls-cert-expiring"
        | "tls-cert-not-yet-valid"
        | "tls-self-signed"
        | "tls-self-signed-bad-signature"
        | "tls-weak-signature"
        | "tls-weak-key"
        | "tls-sslv3"
        | "tls-deprecated-protocol"
        | "tls-broken-cipher"
        | "tls-3des"
        | "tls-no-pfs"
        | "ssh-weak-algorithms"
        | "ssh-legacy-algorithms"
        | "redis-noauth"
        | "memcached-open"
        | "mqtt-anonymous"
        | "ldap-anonymous"
        | "postgres-no-tls"
        | "rdp-no-nla"
        | "smb1-enabled"
        | "smb-signing"
        | "smb-no-encryption"
        | "docker-api"
        | "snmp-public" => 95,
        "ssh-protocol-1"
        | "telnet-open"
        | "ftp-cleartext"
        | "vnc-exposed"
        | "mail-cleartext"
        | "http-basic-cleartext"
        | "netbios-ns"
        | "upnp-exposed" => 90,
        "ot-control-traffic" => 85,
        "php-eol" => 70,
        "ot-reachable" => 50,
        "heartbleed" | "cve-cve-2020-0796" => 40,
        _ if id.starts_with("cve-") => 40,
        _ if id.starts_with("script-") => 60,
        _ => return None,
    })
}

const MS_SMB: &str = "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3";
const MS_SMB_SIGNING: &str =
    "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview";
const MS_RDP_NLA: &str = "https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/remote-desktop-allow-access";
const CISA_TELNET: &str = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-245a";
const MOZILLA_TLS: &str = "https://wiki.mozilla.org/Security/Server_Side_TLS";

/// Documentation link for a rule id, if one is curated. Only official vendor or standards pages.
fn reference_for(id: &str) -> Option<&'static str> {
    Some(match id {
        "smb1-enabled" => MS_SMB,
        "smb-signing" => MS_SMB_SIGNING,
        "rdp-no-nla" => MS_RDP_NLA,
        "telnet-open" => CISA_TELNET,
        "tls-sslv3"
        | "tls-deprecated-protocol"
        | "tls-broken-cipher"
        | "tls-3des"
        | "tls-no-pfs"
        | "tls-weak-signature"
        | "tls-weak-key" => MOZILLA_TLS,
        _ => return None,
    })
}

impl Finding {
    /// The reasons for the finding and its confidence: what was observed, and how the rule
    /// works (see the finding's documentation page for the false positives).
    pub fn explain(&self) -> crate::evidence::Evidence {
        let basis = match self.confidence {
            90.. => "observed directly",
            60..=89 => "inferred from what the service reported",
            50..=59 => "inferred from the port number only",
            1..=49 => "version-based hint, fixes may be backported",
            0 => "",
        };
        crate::evidence::Evidence::new([self.evidence.as_str(), basis], self.confidence)
    }

    /// Identity used to decide whether a finding is new compared with a previous scan.
    pub fn key(&self) -> String {
        format!(
            "{}|{}|{}",
            self.ip,
            self.port.map_or(String::new(), |p| p.to_string()),
            self.id
        )
    }
}

/// Dotted version with an optional `pN` patch level: "8.9p1" -> [8, 9, 1].
pub fn parse_version(s: &str) -> Vec<u32> {
    let mut parts = vec![];
    let mut number = String::new();
    let mut chars = s.chars().peekable();
    let mut seen_p = false;
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() {
            number.push(c);
        } else {
            if !number.is_empty() {
                parts.push(number.parse().unwrap_or(0));
                number.clear();
            }
            let patch = c == 'p' && !seen_p && chars.peek().is_some_and(char::is_ascii_digit);
            if patch {
                seen_p = true;
            } else if c != '.' {
                break;
            }
        }
    }
    if !number.is_empty() {
        parts.push(number.parse().unwrap_or(0));
    }
    parts
}
fn compare(a: &[u32], b: &[u32]) -> std::cmp::Ordering {
    for i in 0..a.len().max(b.len()) {
        let (x, y) = (
            a.get(i).copied().unwrap_or(0),
            b.get(i).copied().unwrap_or(0),
        );
        if x != y {
            return x.cmp(&y);
        }
    }
    std::cmp::Ordering::Equal
}
/// `min <= version < max`; either bound may be absent.
pub fn in_range(version: &str, min: Option<&str>, max_exclusive: Option<&str>) -> bool {
    let v = parse_version(version);
    if v.is_empty() {
        return false;
    }
    min.is_none_or(|m| compare(&v, &parse_version(m)).is_ge())
        && max_exclusive.is_none_or(|m| compare(&v, &parse_version(m)).is_lt())
}

// ---- CVE / CPE database (data/cves.json plus an optional user file) ----------------------

static BUILTIN_CVES: &str = include_str!("../../data/cves.json");

#[derive(Deserialize)]
struct RawCveRule {
    id: String,
    product: String,
    #[serde(default)]
    exclude: Vec<String>,
    #[serde(default)]
    min: Option<String>,
    #[serde(default)]
    max: Option<String>,
    severity: String,
    cve: Vec<String>,
    title: String,
}
#[derive(Deserialize)]
struct RawCpe {
    id: String,
    products: Vec<String>,
    template: String,
}
#[derive(Deserialize)]
struct RawCveDb {
    #[serde(default)]
    rules: Vec<RawCveRule>,
    #[serde(default)]
    cpe: Vec<RawCpe>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CveRule {
    pub id: String,
    /// Lower-case substring of the detected product name.
    pub product: String,
    /// Lower-case product substrings the rule does not apply to.
    pub exclude: Vec<String>,
    pub min: Option<String>,
    pub max: Option<String>,
    pub severity: Severity,
    pub cve: Vec<String>,
    pub title: String,
}
#[derive(Clone, Debug, PartialEq)]
pub struct CpeRule {
    pub id: String,
    /// Exact lower-case product names.
    pub products: Vec<String>,
    pub template: String,
}
#[derive(Clone, Debug, PartialEq)]
pub struct CveDb {
    pub rules: Vec<CveRule>,
    pub cpe: Vec<CpeRule>,
}

/// A rule bound: digits separated by dots with an optional `pN` patch level (`8.5p1`).
fn valid_version(s: &str) -> bool {
    let (base, patch) = match s.split_once('p') {
        Some((b, p)) => (b, Some(p)),
        None => (s, None),
    };
    let numeric = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
    base.split('.').all(numeric) && patch.is_none_or(numeric)
}
fn valid_cve(s: &str) -> bool {
    let mut parts = s.split('-');
    parts.next() == Some("CVE")
        && parts
            .next()
            .is_some_and(|y| y.len() == 4 && y.bytes().all(|b| b.is_ascii_digit()))
        && parts
            .next()
            .is_some_and(|n| n.len() >= 4 && n.bytes().all(|b| b.is_ascii_digit()))
        && parts.next().is_none()
}

impl CveDb {
    fn parse(json: &str, origin: &str) -> Result<Self, String> {
        let raw: RawCveDb = serde_json::from_str(json).map_err(|e| format!("{origin}: {e}"))?;
        let mut rules = vec![];
        for r in raw.rules {
            let err = |what: String| format!("{origin}: rule {:?}: {what}", r.id);
            if r.id.trim().is_empty() {
                return Err(format!("{origin}: a rule has an empty id"));
            }
            if r.product.trim().is_empty() {
                return Err(err("empty product".into()));
            }
            for bound in [&r.min, &r.max].into_iter().flatten() {
                if !valid_version(bound) {
                    return Err(err(format!(
                        "bad version {bound:?} (expected e.g. 2.4.49 or 8.5p1)"
                    )));
                }
            }
            if let (Some(lo), Some(hi)) = (&r.min, &r.max)
                && compare(&parse_version(lo), &parse_version(hi)).is_ge()
            {
                return Err(err(format!("min {lo} is not below max {hi}")));
            }
            let severity = Severity::parse(&r.severity)
                .ok_or_else(|| err(format!("unknown severity {:?}", r.severity)))?;
            if r.cve.is_empty() {
                return Err(err("cve list is empty".into()));
            }
            if let Some(bad) = r.cve.iter().find(|c| !valid_cve(c)) {
                return Err(err(format!("bad CVE id {bad:?}")));
            }
            rules.push(CveRule {
                product: r.product.trim().to_ascii_lowercase(),
                exclude: r.exclude.iter().map(|e| e.to_ascii_lowercase()).collect(),
                min: r.min,
                max: r.max,
                severity,
                cve: r.cve,
                title: r.title,
                id: r.id,
            });
        }
        let mut cpe = vec![];
        for c in raw.cpe {
            if c.id.trim().is_empty() || c.products.is_empty() {
                return Err(format!(
                    "{origin}: cpe {:?}: needs an id and products",
                    c.id
                ));
            }
            if !c.template.starts_with("cpe:2.3:")
                || c.template.split(':').count() != 13
                || !(c.template.contains("{version}") || c.template.contains("{base}"))
            {
                return Err(format!(
                    "{origin}: cpe {:?}: template must be a 13-part cpe:2.3 name with {{version}} or {{base}}",
                    c.id
                ));
            }
            cpe.push(CpeRule {
                products: c.products.iter().map(|p| p.to_ascii_lowercase()).collect(),
                template: c.template,
                id: c.id,
            });
        }
        Ok(Self { rules, cpe })
    }
    pub fn builtin() -> Self {
        Self::parse(BUILTIN_CVES, "built-in CVE rules").expect("built-in CVE rules are valid")
    }
    /// Built-in rules plus a user file: same id replaces, new ids are added.
    pub fn with_user_file(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::with_user_text(&text, &path.display().to_string())
    }
    /// Built-in rules plus the contents of a user file named `origin`.
    pub(crate) fn with_user_text(text: &str, origin: &str) -> Result<Self, String> {
        let user = Self::parse(text, origin)?;
        let mut db = Self::builtin();
        for rule in user.rules {
            match db.rules.iter_mut().find(|r| r.id == rule.id) {
                Some(slot) => *slot = rule,
                None => db.rules.push(rule),
            }
        }
        for c in user.cpe {
            match db.cpe.iter_mut().find(|x| x.id == c.id) {
                Some(slot) => *slot = c,
                None => db.cpe.push(c),
            }
        }
        Ok(db)
    }
    /// The explicit file (`--cves FILE`), else `%LOCALAPPDATA%/NetworkScope/cves.json` when it
    /// exists, else the built-in rules.
    pub fn load(explicit: Option<&Path>) -> Result<Self, String> {
        if let Some(p) = explicit {
            return Self::with_user_file(p);
        }
        let default = std::env::var_os("LOCALAPPDATA")
            .or_else(|| std::env::var_os("XDG_CONFIG_HOME"))
            .map(|p| Path::new(&p).join("NetworkScope").join("cves.json"));
        match default {
            Some(p) if p.exists() => Self::with_user_file(&p),
            _ => Ok(Self::builtin()),
        }
    }
    /// CPE 2.3 name for a detected product and version, when the table knows the product and
    /// the version is a plain version string (banners are untrusted input).
    pub fn cpe(&self, product: &str, version: &str) -> Option<String> {
        let product = product.trim().to_ascii_lowercase();
        // Distribution suffixes ("8.0.33-0ubuntu0.22.04.2") are not part of the CPE version.
        let version: String = version
            .trim()
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '_')
            .collect::<String>()
            .to_ascii_lowercase();
        if version.is_empty()
            || version.len() > 40
            || !version.starts_with(|c: char| c.is_ascii_digit())
        {
            return None;
        }
        let rule = self.cpe.iter().find(|c| c.products.contains(&product))?;
        let (base, update) = match version.find('p') {
            Some(at)
                if version[at + 1..].chars().all(|c| c.is_ascii_digit())
                    && at + 1 < version.len() =>
            {
                (&version[..at], &version[at..])
            }
            _ => (version.as_str(), "*"),
        };
        Some(
            rule.template
                .replace("{version}", &version)
                .replace("{base}", base)
                .replace("{update}", update),
        )
    }
}

fn cve_slot() -> &'static RwLock<Option<Arc<CveDb>>> {
    static SLOT: OnceLock<RwLock<Option<Arc<CveDb>>>> = OnceLock::new();
    SLOT.get_or_init(|| RwLock::new(None))
}

/// Loads the CVE/CPE rules (explicit file, else the default user file, else built-in) and makes
/// them the rules every later analysis uses. Called for `--cves FILE`; on error the previously
/// active rules stay in place.
pub fn load_cves(explicit: Option<&Path>) -> Result<(), String> {
    set_cves(CveDb::load(explicit)?);
    Ok(())
}

/// Makes `db` the rules every later analysis uses.
pub fn set_cves(db: CveDb) {
    if let Ok(mut slot) = cve_slot().write() {
        *slot = Some(Arc::new(db));
    }
}

/// Start-up load of the default rules (user file `NetworkScope/cves.json` under LOCALAPPDATA or
/// XDG_CONFIG_HOME, else built-in). A broken user file is returned as an error message for the
/// caller to show, and the built-in rules are used.
pub fn init_cves() -> Option<String> {
    let error = load_cves(None).err()?;
    if let Ok(mut slot) = cve_slot().write() {
        *slot = Some(Arc::new(CveDb::builtin()));
    }
    Some(format!("CVE rules: {error}; using the built-in rules"))
}

/// The active rules. Until `load_cves` ran: the default user file when it is valid, else the
/// built-in rules (an invalid user file is reported once on stderr).
pub fn cve_db() -> Arc<CveDb> {
    if let Some(db) = cve_slot().read().ok().and_then(|s| s.clone()) {
        return db;
    }
    // Tests never read the developer's own override file.
    #[cfg(test)]
    let db = Arc::new(CveDb::builtin());
    #[cfg(not(test))]
    let db = Arc::new(CveDb::load(None).unwrap_or_else(|e| {
        eprintln!("CVE rules: {e}; using the built-in rules");
        CveDb::builtin()
    }));
    if let Ok(mut slot) = cve_slot().write() {
        if let Some(existing) = slot.as_ref() {
            return existing.clone();
        }
        *slot = Some(db.clone());
    }
    db
}
/// PHP branch end-of-life dates (end of security support, php.net/supported-versions).
/// Branches not listed here (8.2 and newer once added) are not flagged; extend the table
/// when php.net publishes new dates. Last reviewed 2026-11.
const PHP_EOL: &[(&str, &str)] = &[
    ("8.1", "2025-12-31"),
    ("8.2", "2026-12-31"),
    ("8.3", "2027-12-31"),
    ("8.4", "2028-12-31"),
];

/// End-of-life date when `version` (a `PHP/x.y.z` value) is unsupported on `today` (ISO date).
/// Everything older than the first listed branch is long out of support.
pub fn php_eol(version: &str, today: &str) -> Option<String> {
    let v = parse_version(version);
    if v.is_empty() {
        return None;
    }
    let (oldest, oldest_eol) = PHP_EOL[0];
    if compare(&v, &parse_version(oldest)).is_lt() {
        return Some(format!("before {oldest_eol}"));
    }
    let branch = [v[0], v.get(1).copied().unwrap_or(0)];
    PHP_EOL
        .iter()
        .find(|(b, _)| parse_version(b) == branch)
        .filter(|(_, eol)| *eol < today)
        .map(|(_, eol)| (*eol).to_string())
}

fn today() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    crate::tls::date(now)
}

const BACKPORT_NOTE: &str = "Version-based hint only: distributions backport fixes without changing the version. Confirm with the vendor advisory or an authenticated check.";

fn heartbleed(server: &str) -> Option<String> {
    let at = server.find("OpenSSL/1.0.1")?;
    let rest = &server[at + "OpenSSL/1.0.1".len()..];
    let letter = rest.chars().next().filter(char::is_ascii_lowercase);
    match letter {
        None => Some("1.0.1".into()),
        Some(c) if c <= 'f' => Some(format!("1.0.1{c}")),
        _ => None,
    }
}

/// SMBGhost (CVE-2020-0796) is limited to Windows 10 / Server version 1903 (build 18362) and
/// 1909 (build 18363) with SMB 3.1.1 compression. The NTLM challenge names the build but not
/// the update revision, so a patched host looks the same: a version-based hint only, never
/// raised on compression alone.
pub fn smbghost_hint(dialect: &str, compression: &str, os_version: &str) -> Option<String> {
    let v = parse_version(os_version);
    let affected = v.len() == 3 && v[0] == 10 && v[1] == 0 && matches!(v[2], 18362 | 18363);
    let compressing = !compression.is_empty() && compression != "none";
    (dialect == "3.1.1" && compressing && affected).then(|| {
        format!(
            "SMB 3.1.1, compression {compression}, Windows build {os_version}. Version-based hint: the patch level (KB4551762) is not visible remotely."
        )
    })
}

struct Out<'a> {
    host: &'a Host,
    list: Vec<Finding>,
}
impl Out<'_> {
    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        severity: Severity,
        id: &str,
        title: &str,
        port: Option<u16>,
        evidence: impl Into<String>,
        cve: &[&str],
        advice: &str,
    ) {
        self.list.push(Finding {
            severity,
            id: id.into(),
            title: title.into(),
            ip: self.host.ip,
            port,
            evidence: evidence.into(),
            cve: cve.iter().map(|c| (*c).to_string()).collect(),
            advice: advice.into(),
            exploit: Default::default(),
            reference: reference_for(id).map(str::to_string),
            confidence: rule_confidence(id).unwrap_or(0),
        });
    }
}

pub fn analyze_host(h: &Host) -> Vec<Finding> {
    analyze_host_nvd(h, &cve_db(), &crate::nvd::active())
}

/// The built-in/user CVE rules only (no imported NVD data); used by the tests.
#[cfg_attr(not(test), allow(dead_code))]
fn analyze_host_with(h: &Host, cves: &CveDb) -> Vec<Finding> {
    analyze_host_nvd(h, cves, &crate::nvd::Nvd::default())
}

/// Every rule, with the CVE rules from `cves` and the imported NVD feed `nvd` (see
/// [`crate::nvd`]): NVD hits for a port's `svc.<port>.cpe` come after the built-in rules and
/// never repeat a CVE they already raised.
fn analyze_host_nvd(h: &Host, cves: &CveDb, nvd: &crate::nvd::Nvd) -> Vec<Finding> {
    let mut o = Out {
        host: h,
        list: vec![],
    };
    let id = &h.identity;
    let get = |k: String| id.get(&k).map(String::as_str).unwrap_or("");
    let mut ports: Vec<u16> = h.open.clone();
    ports.extend(h.udp_open.iter().copied());
    ports.sort_unstable();
    ports.dedup();

    for &p in &h.open {
        let svc = get(format!("svc.{p}"));
        let name = svc.split_whitespace().next().unwrap_or("");
        let product = get(format!("svc.{p}.product"));
        let version = get(format!("svc.{p}.version"));
        let port = Some(p);

        // TLS
        if id.contains_key(&format!("tls.{p}.subject"))
            || id.contains_key(&format!("tls.{p}.versions"))
        {
            if get(format!("tls.{p}.expired")) == "true" {
                o.add(
                    Severity::High,
                    "tls-cert-expired",
                    "TLS certificate has expired",
                    port,
                    format!("not after {}", get(format!("tls.{p}.not_after"))),
                    &[],
                    "Renew the certificate.",
                );
            } else if let Ok(days) = get(format!("tls.{p}.days_left")).parse::<i64>()
                && days <= 30
            {
                o.add(
                    Severity::Medium,
                    "tls-cert-expiring",
                    "TLS certificate expires within 30 days",
                    port,
                    format!(
                        "{days} days left (not after {})",
                        get(format!("tls.{p}.not_after"))
                    ),
                    &[],
                    "Renew the certificate before it expires.",
                );
            }
            // The validity period has two ends: a certificate dated in the future (device
            // clock reset, wrong issuance date) fails verification just like an expired one.
            if get(format!("tls.{p}.not_yet_valid")) == "true" {
                o.add(
                    Severity::Medium,
                    "tls-cert-not-yet-valid",
                    "TLS certificate is not yet valid",
                    port,
                    format!("not before {}", get(format!("tls.{p}.not_before"))),
                    &[],
                    "Check the device clock and reissue the certificate with a correct validity period.",
                );
            }
            if get(format!("tls.{p}.self_signed")) == "true"
                && get(format!("tls.{p}.self_signature")) == "invalid"
            {
                // Issuer equals subject, but the signature does not verify with the
                // certificate's own key. Reported instead of the plain self-signed finding;
                // "unchecked" (an algorithm the verifier lacks) never lands here.
                o.add(
                    Severity::Medium,
                    "tls-self-signed-bad-signature",
                    "Certificate claims to be self-signed but its signature does not verify",
                    port,
                    format!(
                        "{}: signature does not verify with the certificate's own key",
                        get(format!("tls.{p}.subject"))
                    ),
                    &[],
                    "Replace the certificate. Either it was issued by another key under its own name, or it is corrupt or has been tampered with.",
                );
            } else if get(format!("tls.{p}.self_signed")) == "true" {
                o.add(
                    Severity::Low,
                    "tls-self-signed",
                    "Self-signed TLS certificate",
                    port,
                    get(format!("tls.{p}.subject")),
                    &[],
                    "Use a certificate from a trusted CA where clients need to verify the server.",
                );
            }
            let sig = get(format!("tls.{p}.signature"));
            if sig.contains("(weak)") {
                o.add(
                    Severity::Medium,
                    "tls-weak-signature",
                    "Certificate signed with a weak hash",
                    port,
                    sig,
                    &[],
                    "Reissue the certificate with SHA-256 or better.",
                );
            }
            if let Some(bits) = get(format!("tls.{p}.key"))
                .strip_prefix("RSA ")
                .and_then(|b| b.parse::<u32>().ok())
                && bits < 2048
            {
                o.add(
                    Severity::High,
                    "tls-weak-key",
                    "Certificate uses a short RSA key",
                    port,
                    format!("RSA {bits}"),
                    &[],
                    "Use RSA 2048 or larger, or an EC key.",
                );
            }
            let weak = get(format!("tls.{p}.weak"));
            if !weak.is_empty() {
                let any = |needles: &[&str]| needles.iter().any(|n| weak.contains(n));
                if weak.contains("SSLv3 enabled") {
                    o.add(
                        Severity::High,
                        "tls-sslv3",
                        "SSLv3 is enabled",
                        port,
                        weak,
                        &["CVE-2014-3566"],
                        "Disable SSLv3 (POODLE).",
                    );
                }
                if weak.contains("TLS1.0 enabled") || weak.contains("TLS1.1 enabled") {
                    o.add(
                        Severity::Medium,
                        "tls-deprecated-protocol",
                        "Deprecated TLS 1.0/1.1 is enabled",
                        port,
                        get(format!("tls.{p}.versions")),
                        &[],
                        "Disable TLS 1.0 and 1.1 (RFC 8996).",
                    );
                }
                if any(&[
                    "RC4",
                    "export-grade",
                    "no encryption",
                    "anonymous",
                    "single DES",
                ]) {
                    o.add(
                        Severity::High,
                        "tls-broken-cipher",
                        "Broken TLS cipher suites are accepted",
                        port,
                        weak,
                        &[],
                        "Remove RC4, DES, export, NULL and anonymous suites.",
                    );
                } else if weak.contains("3DES") {
                    o.add(
                        Severity::Medium,
                        "tls-3des",
                        "3DES cipher suites are accepted",
                        port,
                        weak,
                        &["CVE-2016-2183"],
                        "Remove 3DES suites (Sweet32).",
                    );
                }
                if weak.contains("no forward secrecy") {
                    o.add(
                        Severity::Low,
                        "tls-no-pfs",
                        "Cipher suites without forward secrecy are accepted",
                        port,
                        "static RSA key exchange offered",
                        &[],
                        "Prefer ECDHE suites.",
                    );
                }
            }
        }
        // SSH
        let ssh_weak = get(format!("ssh.{p}.weak"));
        if !ssh_weak.is_empty() {
            let terrapin = ssh_weak.contains("Terrapin");
            o.add(Severity::Medium, "ssh-weak-algorithms", "SSH server offers weak algorithms", port, ssh_weak, if terrapin { &["CVE-2023-48795"] } else { &[] }, "Remove weak key exchange, cipher and MAC algorithms; update to a release with strict key exchange.");
        }
        let ssh_legacy = get(format!("ssh.{p}.legacy"));
        if !ssh_legacy.is_empty() {
            o.add(
                Severity::Low,
                "ssh-legacy-algorithms",
                "SSH server offers legacy algorithms",
                port,
                ssh_legacy.to_string(),
                &[],
                "Prefer modern algorithms; drop SHA-1 and CBC modes.",
            );
        }
        // Only an SSH service: other protocols print "protocol 1.x" for their own version.
        if name == "ssh" && svc.contains("protocol 1.") && !svc.contains("protocol 1.99") {
            o.add(
                Severity::High,
                "ssh-protocol-1",
                "SSH protocol 1 in use",
                port,
                svc,
                &[],
                "Use SSH protocol 2 only.",
            );
        }
        // Services and exposure
        match name {
            "telnet" => o.add(Severity::High, "telnet-open", "Telnet exposes credentials in clear text", port, svc, &[], "Disable Telnet; use SSH."),
            "ftp" => o.add(Severity::Medium, "ftp-cleartext", "FTP sends credentials in clear text", port, svc, &[], "Use SFTP or FTPS."),
            "vnc" => o.add(Severity::Medium, "vnc-exposed", "VNC is reachable", port, svc, &[], "Restrict VNC to a management network or tunnel it; it often has weak authentication."),
            "pop3" | "imap" => o.add(Severity::Low, "mail-cleartext", "Mail retrieval without TLS", port, svc, &[], "Use the TLS variants or STARTTLS."),
            "redis" if !version.is_empty() => o.add(Severity::Critical, "redis-noauth", "Redis answers without authentication", port, svc, &[], "Require authentication and bind Redis to localhost or a private interface."),
            "memcached" if !version.is_empty() => o.add(Severity::High, "memcached-open", "memcached answers without authentication", port, svc, &[], "Bind to localhost or firewall it; exposed memcached is abused for amplification and data theft."),
            "mqtt" if svc.contains("anonymous connection accepted") => o.add(Severity::High, "mqtt-anonymous", "MQTT broker accepts anonymous clients", port, svc, &[], "Require authentication and per-topic ACLs."),
            "ldap" if svc.contains("anonymous bind accepted") => o.add(Severity::Low, "ldap-anonymous", "LDAP answers an anonymous bind", port, svc, &[], "Disable anonymous binds unless needed; prefer LDAPS."),
            "postgresql" if svc.contains("TLS not supported") => o.add(Severity::Low, "postgres-no-tls", "PostgreSQL does not offer TLS", port, svc, &[], "Enable ssl in postgresql.conf."),
            "ms-wbt-server" => {
                if svc.contains("standard RDP security") {
                    o.add(Severity::High, "rdp-no-nla", "RDP uses legacy security without TLS or NLA", port, svc, &["CVE-2019-0708"], "Require NLA and patch Windows (BlueKeep applies to unpatched Windows 7/2008 with this setting).");
                } else if svc.contains("TLS security") {
                    o.add(Severity::Medium, "rdp-no-nla", "RDP does not require Network Level Authentication", port, svc, &[], "Require NLA.");
                }
            }
            "microsoft-ds" => {
                // Independent checks: a server can speak SMB2/3 without signing and still accept
                // an SMB1 negotiate (reported in `smb.<port>.smb1`).
                if svc.contains("SMBv1") || get(format!("smb.{p}.smb1")) == "accepted" {
                    let evidence = if svc.contains("SMBv1") {
                        svc.to_string()
                    } else {
                        format!("{svc}; SMB1 negotiate (NT LM 0.12) accepted")
                    };
                    o.add(Severity::High, "smb1-enabled", "SMBv1 is enabled", port, evidence, &["CVE-2017-0144"], "Disable SMBv1; confirm MS17-010 is installed (EternalBlue exposure depends on patch level).");
                }
                if svc.contains("signing disabled") || svc.contains("not required") {
                    o.add(Severity::Medium, "smb-signing", "SMB signing is not required", port, svc, &[], "Require SMB signing to prevent relay attacks.");
                }
                let encryption = get(format!("smb.{p}.encryption"));
                if encryption.starts_with("not supported") {
                    o.add(Severity::Info, "smb-no-encryption", "SMB server does not offer encryption", port, format!("dialect {}; encryption {encryption}", get(format!("smb.{p}.dialect"))), &[], "Enable SMB 3.x encryption for shares that carry sensitive data.");
                }
                if let Some(evidence) = smbghost_hint(
                    get(format!("smb.{p}.dialect")),
                    get(format!("smb.{p}.compression")),
                    get(format!("smb.{p}.os_version")),
                ) {
                    o.add(Severity::High, "cve-cve-2020-0796", "SMBv3 compression on a Windows build affected by SMBGhost", port, evidence, &["CVE-2020-0796"], "Install KB4551762 (March 2020) or later, or disable SMBv3 compression; Windows 10 1903/1909 is out of support, upgrade it.");
                }
            }
            _ => {}
        }
        if name == "http"
            && !svc.starts_with("https")
            && get(format!("http.{p}.auth"))
                .to_ascii_lowercase()
                .starts_with("basic")
        {
            o.add(
                Severity::Medium,
                "http-basic-cleartext",
                "HTTP Basic authentication over an unencrypted connection",
                port,
                get(format!("http.{p}.auth")),
                &[],
                "Serve the interface over HTTPS.",
            );
        }
        let server = get(format!("http.{p}.server"));
        if server.starts_with("Docker/") {
            o.add(
                Severity::Critical,
                "docker-api",
                "Docker Engine API is exposed",
                port,
                server,
                &[],
                "Never expose the Docker socket without TLS client authentication.",
            );
        }
        if let Some(v) = heartbleed(server) {
            o.add(
                Severity::Critical,
                "heartbleed",
                "Server header names a Heartbleed-vulnerable OpenSSL",
                port,
                format!("OpenSSL {v}"),
                &["CVE-2014-0160"],
                "Upgrade OpenSSL to 1.0.1g or later (header may be stale or backported).",
            );
        }
        // Version hints
        let mut candidates: Vec<(String, String)> = vec![];
        if !product.is_empty() && !version.is_empty() {
            candidates.push((product.to_string(), version.to_string()));
        }
        if let Some((n, v)) = server.split_once('/') {
            candidates.push((
                n.trim().to_string(),
                v.split_whitespace().next().unwrap_or("").to_string(),
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        // CVE ids the built-in rules raised on this port; the NVD lookup below skips them.
        let mut raised = std::collections::BTreeSet::<String>::new();
        for (prod, ver) in candidates {
            let prod = prod.to_ascii_lowercase();
            for rule in cves.rules.iter().filter(|r| {
                // e.g. the portable-OpenSSH issues do not concern OpenSSH for Windows.
                let excluded = r.exclude.iter().any(|x| prod.contains(x.as_str()));
                prod.contains(r.product.as_str())
                    && !excluded
                    && in_range(&ver, r.min.as_deref(), r.max.as_deref())
            }) {
                if seen.insert(rule.cve[0].clone()) {
                    raised.extend(rule.cve.iter().map(|c| c.to_ascii_uppercase()));
                    let cve: Vec<&str> = rule.cve.iter().map(String::as_str).collect();
                    o.add(
                        rule.severity,
                        &format!("cve-{}", rule.cve[0].to_ascii_lowercase()),
                        &rule.title,
                        port,
                        format!("{prod} {ver}. {BACKPORT_NOTE}"),
                        &cve,
                        "Update to a fixed release or confirm the vendor backported the fix.",
                    );
                }
            }
        }
        // Imported NVD feed (`feeds import nvd`): CVEs whose vulnerable range holds the version
        // of the CPE the scanner derived for this port.
        let cpe = get(format!("svc.{p}.cpe"));
        if !cpe.is_empty() {
            for hit in nvd
                .lookup(cpe)
                .into_iter()
                .filter(|hit| !raised.contains(&hit.cve))
                .take(crate::nvd::MAX_FINDINGS_PER_PORT)
            {
                o.add(
                    hit.severity,
                    &format!("cve-{}", hit.cve.to_ascii_lowercase()),
                    if hit.title.is_empty() {
                        &hit.cve
                    } else {
                        &hit.title
                    },
                    port,
                    format!("{cpe} in the NVD range {}. {BACKPORT_NOTE}", hit.range),
                    &[&hit.cve],
                    "Update to a fixed release or confirm the vendor backported the fix.",
                );
            }
        }
        if let Some(v) = get(format!("http.{p}.powered_by")).strip_prefix("PHP/")
            && let Some(eol) = php_eol(v, &today())
        {
            o.add(
                Severity::Low,
                "php-eol",
                "PHP release is no longer supported",
                port,
                format!("PHP {v} (end of life {eol})"),
                &[],
                "Upgrade to a supported PHP release.",
            );
        }
        // 2222/tcp is EtherNet/IP I/O (and legacy Allen-Bradley CSP) but also a very common
        // alternative SSH port; service detection only listens there, so an SSH greeting
        // means it is not an industrial service. The same holds on every other industrial
        // port number: nothing there speaks SSH (a service imported from Nmap XML, or a
        // server moved onto the port).
        let ssh_on_ot_port = name == "ssh";
        if crate::service::is_ot_port_candidate(p) && !ssh_on_ot_port {
            o.add(Severity::Medium, "ot-reachable", "Industrial protocol port is reachable from the scanner", port, format!("TCP {p} open"), &[], "OT services should only be reachable from the control network; check segmentation.");
        }
    }
    for &p in &h.udp_open {
        let info = get(format!("udp.{p}"));
        match p {
            161 if info.starts_with("SNMP sysDescr") => o.add(
                Severity::High,
                "snmp-public",
                "SNMP answers the community string 'public'",
                Some(p),
                info,
                &[],
                "Change the community string or move to SNMPv3; restrict by source address.",
            ),
            137 => o.add(
                Severity::Low,
                "netbios-ns",
                "NetBIOS name service is exposed",
                Some(p),
                info,
                &[],
                "Disable NetBIOS over TCP/IP where it is not needed.",
            ),
            1900 => o.add(
                Severity::Low,
                "upnp-exposed",
                "UPnP/SSDP is answering",
                Some(p),
                info,
                &[],
                "Disable UPnP on devices that do not need it.",
            ),
            _ => {}
        }
    }
    // Findings added by user scripts: finding.script.<id> = "severity|title|evidence".
    for (k, v) in id {
        if let Some(fid) = k.strip_prefix("finding.script.") {
            let mut parts = v.splitn(3, '|');
            let sev = parts
                .next()
                .and_then(Severity::parse)
                .unwrap_or(Severity::Info);
            let title = parts.next().unwrap_or(fid);
            o.add(
                sev,
                &format!("script-{fid}"),
                title,
                None,
                parts.next().unwrap_or(""),
                &[],
                "Raised by a user script.",
            );
        }
    }
    o.list
}

pub fn analyze(hosts: &[Host]) -> Vec<Finding> {
    let mut all: Vec<Finding> = hosts
        .iter()
        .filter(|h| h.responding)
        .flat_map(analyze_host)
        .collect();
    all.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.ip.cmp(&b.ip))
            .then(a.port.cmp(&b.port))
            .then(a.id.cmp(&b.id))
    });
    crate::feeds::apply(&mut all);
    all
}

/// Host findings plus findings from passively observed control traffic.
pub fn analyze_snapshot(s: &crate::store::Snapshot) -> Vec<Finding> {
    let mut all = analyze(&s.hosts);
    for (severity, ip, evidence) in crate::otpassive::control_findings(&s.observations) {
        all.push(Finding {
            severity,
            id: "ot-control-traffic".into(),
            title: "Control traffic observed on an industrial protocol".into(),
            ip,
            port: None,
            evidence,
            cve: vec![],
            advice: "Verify that writes, program downloads and stop/restart commands come from authorised engineering stations.".into(),
            exploit: Default::default(),
            reference: None,
            confidence: rule_confidence("ot-control-traffic").unwrap_or(0),
        });
    }
    all.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.ip.cmp(&b.ip))
            .then(a.port.cmp(&b.port))
            .then(a.id.cmp(&b.id))
    });
    crate::feeds::apply(&mut all);
    all
}

pub fn counts(findings: &[Finding]) -> BTreeMap<Severity, usize> {
    let mut m = BTreeMap::new();
    for f in findings {
        *m.entry(f.severity).or_insert(0) += 1;
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(open: &[u16], id: &[(&str, &str)]) -> Host {
        Host {
            ip: "10.0.0.5".parse().unwrap(),
            responding: true,
            ping: None,
            ttl: None,
            hostname: String::new(),
            mac: String::new(),
            open: open.to_vec(),
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity: id
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            udp_open: vec![],
            trace: vec![],
        }
    }
    fn ids(h: &Host) -> Vec<String> {
        analyze_host(h).into_iter().map(|f| f.id).collect()
    }

    #[test]
    fn version_parsing_and_ranges() {
        assert_eq!(parse_version("8.9p1"), [8, 9, 1]);
        assert_eq!(parse_version("2.4.49"), [2, 4, 49]);
        assert_eq!(parse_version("9.6"), [9, 6]);
        assert_eq!(parse_version("1.0.1e"), [1, 0, 1]);
        assert_eq!(parse_version("x"), Vec::<u32>::new());
        assert!(in_range("9.7p1", Some("8.5p1"), Some("9.8p1")));
        assert!(!in_range("9.8p1", Some("8.5p1"), Some("9.8p1")));
        assert!(!in_range("8.4p1", Some("8.5p1"), Some("9.8p1")));
        assert!(
            !in_range("8.5", Some("8.5p1"), None),
            "8.5 is older than 8.5p1"
        );
        assert!(in_range("2.4.49", Some("2.4.49"), Some("2.4.51")));
        assert!(!in_range("2.4.51", Some("2.4.49"), Some("2.4.51")));
        assert!(in_range("7.4", None, Some("7.7")));
        assert!(!in_range("", None, Some("7.7")));
        assert!(!in_range("junk", None, Some("7.7")));
    }

    #[test]
    fn cve_hints_follow_version_ranges() {
        let h = host(
            &[22],
            &[
                ("svc.22.product", "OpenSSH"),
                ("svc.22.version", "9.6p1"),
                ("svc.22", "ssh OpenSSH 9.6p1"),
            ],
        );
        let f = analyze_host(&h);
        let regresshion = f
            .iter()
            .find(|f| f.cve.contains(&"CVE-2024-6387".to_string()))
            .unwrap();
        assert_eq!(regresshion.severity, Severity::High);
        assert!(regresshion.evidence.contains("Version-based hint"));
        assert!(
            f.iter()
                .all(|f| !f.cve.contains(&"CVE-2023-38408".to_string())),
            "9.6p1 is past 9.3p2"
        );
        let windows = host(
            &[22],
            &[
                ("svc.22.product", "OpenSSH for Windows"),
                ("svc.22.version", "9.5"),
            ],
        );
        assert!(
            analyze_host(&windows).is_empty(),
            "portable-OpenSSH CVEs do not apply to OpenSSH for Windows"
        );
        let fixed = host(
            &[22],
            &[("svc.22.product", "OpenSSH"), ("svc.22.version", "9.9p1")],
        );
        assert!(analyze_host(&fixed).is_empty());
        let apache = host(&[80], &[("http.80.server", "Apache/2.4.49 (Unix)")]);
        assert!(
            analyze_host(&apache)
                .iter()
                .any(|f| f.severity == Severity::Critical
                    && f.cve.contains(&"CVE-2021-41773".to_string()))
        );
        let vsftpd = host(
            &[21],
            &[
                ("svc.21", "ftp vsFTPd 2.3.4"),
                ("svc.21.product", "vsFTPd"),
                ("svc.21.version", "2.3.4"),
            ],
        );
        assert!(ids(&vsftpd).contains(&"cve-cve-2011-2523".to_string()));
        let hb = host(
            &[443],
            &[(
                "http.443.server",
                "Apache/2.2.22 (Ubuntu) mod_ssl/2.2.22 OpenSSL/1.0.1e",
            )],
        );
        assert!(ids(&hb).contains(&"heartbleed".to_string()));
        let patched = host(
            &[443],
            &[("http.443.server", "Apache/2.2.22 OpenSSL/1.0.1g")],
        );
        assert!(!ids(&patched).contains(&"heartbleed".to_string()));
    }

    #[test]
    fn tls_findings() {
        let h = host(
            &[443],
            &[
                ("tls.443.subject", "CN=x"),
                ("tls.443.expired", "true"),
                ("tls.443.not_after", "2020-01-01"),
                ("tls.443.self_signed", "true"),
                ("tls.443.signature", "sha1WithRSA (weak)"),
                ("tls.443.key", "RSA 1024"),
                ("tls.443.versions", "TLS1.2, TLS1.0 (deprecated)"),
                (
                    "tls.443.weak",
                    "TLS1.0 enabled (deprecated); TLS1.0: RSA_RC4_128_SHA - RC4; TLS1.2: RSA_AES_128_CBC_SHA - no forward secrecy",
                ),
            ],
        );
        let got = ids(&h);
        for want in [
            "tls-cert-expired",
            "tls-self-signed",
            "tls-weak-signature",
            "tls-weak-key",
            "tls-deprecated-protocol",
            "tls-broken-cipher",
            "tls-no-pfs",
        ] {
            assert!(got.contains(&want.to_string()), "{want} missing in {got:?}");
        }
        let soon = host(
            &[443],
            &[
                ("tls.443.subject", "CN=x"),
                ("tls.443.days_left", "12"),
                ("tls.443.not_after", "2026-12-01"),
            ],
        );
        assert_eq!(ids(&soon), ["tls-cert-expiring"]);
        let good = host(
            &[443],
            &[
                ("tls.443.subject", "CN=x"),
                ("tls.443.days_left", "200"),
                ("tls.443.versions", "TLS1.3, TLS1.2"),
                ("tls.443.key", "RSA 2048"),
            ],
        );
        assert!(ids(&good).is_empty());
    }

    #[test]
    fn exposure_findings() {
        let h = host(
            &[23, 445, 3389, 6379, 502],
            &[
                ("svc.23", "telnet"),
                (
                    "svc.445",
                    "microsoft-ds SMB 3.1.1 (signing enabled, not required)",
                ),
                (
                    "svc.3389",
                    "ms-wbt-server RDP (standard RDP security (no TLS/NLA))",
                ),
                ("svc.6379", "redis Redis 7.0.11"),
                ("svc.6379.version", "7.0.11"),
            ],
        );
        let got = ids(&h);
        for want in [
            "telnet-open",
            "smb-signing",
            "rdp-no-nla",
            "redis-noauth",
            "ot-reachable",
        ] {
            assert!(got.contains(&want.to_string()), "{want} missing in {got:?}");
        }
        let locked = host(
            &[6379],
            &[("svc.6379", "redis Redis (authentication required)")],
        );
        assert!(ids(&locked).is_empty());
        let mut s = host(&[], &[("udp.161", "SNMP sysDescr: Linux")]);
        s.udp_open = vec![161];
        assert_eq!(ids(&s), ["snmp-public"]);
    }

    #[test]
    fn telnet_rule_needs_an_identified_telnet_service() {
        let hit = host(&[23], &[("svc.23", "telnet")]);
        assert_eq!(ids(&hit), ["telnet-open"]);
        // Port 23 open, but the banner identified another service.
        let ssh = host(&[23], &[("svc.23", "ssh OpenSSH 9.9 (protocol 2.0)")]);
        assert!(!ids(&ssh).contains(&"telnet-open".to_string()));
        // Port 23 open, nothing identified: only a port-number guess.
        let guess = host(&[23], &[("svc.23", "unidentified (port suggests telnet)")]);
        assert!(!ids(&guess).contains(&"telnet-open".to_string()));
        // No identity at all.
        assert!(!ids(&host(&[23], &[])).contains(&"telnet-open".to_string()));
    }

    #[test]
    fn ftp_cleartext_rule_ignores_ftps_only_servers() {
        let hit = host(&[21], &[("svc.21", "ftp vsFTPd 3.0.3")]);
        assert_eq!(ids(&hit), ["ftp-cleartext"]);
        // Implicit FTPS on 990 speaks TLS from the first byte, so it is not identified as
        // plain "ftp".
        let ftps = host(
            &[990],
            &[
                ("svc.990", "ftps"),
                ("tls.990.subject", "CN=ftp.example"),
                ("tls.990.days_left", "200"),
                ("tls.990.versions", "TLS1.3, TLS1.2"),
                ("tls.990.key", "RSA 2048"),
            ],
        );
        assert!(ids(&ftps).is_empty(), "{:?}", ids(&ftps));
        let guess = host(&[21], &[("svc.21", "unidentified (port suggests ftp)")]);
        assert!(!ids(&guess).contains(&"ftp-cleartext".to_string()));
    }

    #[test]
    fn redis_rule_needs_a_version_read_without_authentication() {
        let hit = host(
            &[6379],
            &[
                ("svc.6379", "redis Redis 7.0.11"),
                ("svc.6379.version", "7.0.11"),
            ],
        );
        let f = analyze_host(&hit);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "redis-noauth");
        assert_eq!(f[0].severity, Severity::Critical);
        // Redis identified but no version read (the server answered NOAUTH).
        let no_version = host(&[6379], &[("svc.6379", "redis Redis")]);
        assert!(!ids(&no_version).contains(&"redis-noauth".to_string()));
        // A version field on a port that is not identified as Redis.
        let other = host(
            &[6379],
            &[
                ("svc.6379", "memcached 1.6.9"),
                ("svc.6379.version", "1.6.9"),
            ],
        );
        assert!(!ids(&other).contains(&"redis-noauth".to_string()));
    }

    #[test]
    fn http_basic_rule_only_fires_on_plain_http() {
        let basic = "Basic realm=\"router\"";
        let hit = host(&[80], &[("svc.80", "http"), ("http.80.auth", basic)]);
        assert_eq!(ids(&hit), ["http-basic-cleartext"]);
        // The same header over TLS is fine.
        let tls = host(&[443], &[("svc.443", "https"), ("http.443.auth", basic)]);
        assert!(!ids(&tls).contains(&"http-basic-cleartext".to_string()));
        // Plain HTTP with another scheme, or no challenge at all.
        let bearer = host(
            &[80],
            &[("svc.80", "http"), ("http.80.auth", "Bearer realm=\"api\"")],
        );
        assert!(!ids(&bearer).contains(&"http-basic-cleartext".to_string()));
        let none = host(&[80], &[("svc.80", "http")]);
        assert!(!ids(&none).contains(&"http-basic-cleartext".to_string()));
    }

    #[test]
    fn snmp_rule_needs_an_answer_on_udp_161() {
        let mut hit = host(&[], &[("udp.161", "SNMP sysDescr: Linux")]);
        hit.udp_open = vec![161];
        assert_eq!(ids(&hit), ["snmp-public"]);
        // Port reported open but no SNMP answer was recorded.
        let mut silent = host(&[], &[]);
        silent.udp_open = vec![161];
        assert!(ids(&silent).is_empty());
        // A sysDescr answer recorded, but 161 is not among the open UDP ports.
        let closed = host(&[], &[("udp.161", "SNMP sysDescr: Linux")]);
        assert!(ids(&closed).is_empty());
        // Some other reply recorded on 161.
        let mut other = host(&[], &[("udp.161", "unknown reply")]);
        other.udp_open = vec![161];
        assert!(ids(&other).is_empty());
    }

    #[test]
    fn curated_rules_carry_an_https_reference() {
        let h = host(
            &[23, 445, 3389, 443],
            &[
                ("svc.23", "telnet"),
                ("svc.445", "microsoft-ds SMBv1 (signing disabled)"),
                ("svc.3389", "ms-wbt-server RDP (TLS security)"),
                ("tls.443.versions", "TLS1.2, TLS1.0 (deprecated)"),
                ("tls.443.weak", "TLS1.0 enabled (deprecated)"),
            ],
        );
        let f = analyze_host(&h);
        for (id, host) in [
            ("telnet-open", "www.cisa.gov"),
            ("smb1-enabled", "learn.microsoft.com"),
            ("smb-signing", "learn.microsoft.com"),
            ("rdp-no-nla", "learn.microsoft.com"),
            ("tls-deprecated-protocol", "wiki.mozilla.org"),
        ] {
            let found = f
                .iter()
                .find(|f| f.id == id)
                .unwrap_or_else(|| panic!("{id}"));
            let url = found.reference.as_deref().unwrap_or_else(|| panic!("{id}"));
            assert!(url.starts_with(&format!("https://{host}/")), "{id}: {url}");
        }
        // Rules without a curated link stay without one.
        let ftp = host(&[21], &[("svc.21", "ftp vsFTPd 3.0.3")]);
        assert_eq!(analyze_host(&ftp)[0].reference, None);
    }

    #[test]
    fn finding_json_without_reference_still_loads() {
        let old = r#"{"severity":"high","id":"telnet-open","title":"Telnet","ip":"10.0.0.5","port":23,"evidence":"telnet","cve":[],"advice":"Disable Telnet."}"#;
        let f: Finding = serde_json::from_str(old).unwrap();
        assert_eq!(f.reference, None);
        // A missing reference is not written back out; a present one round-trips.
        assert!(!serde_json::to_string(&f).unwrap().contains("reference"));
        let linked = Finding {
            reference: Some("https://example.org/doc".into()),
            ..f
        };
        let back: Finding = serde_json::from_str(&serde_json::to_string(&linked).unwrap()).unwrap();
        assert_eq!(back, linked);
    }

    #[test]
    fn not_yet_valid_certificate_is_reported() {
        let h = host(
            &[443],
            &[
                ("tls.443.subject", "CN=x"),
                ("tls.443.not_yet_valid", "true"),
                ("tls.443.not_before", "2999-01-01"),
                ("tls.443.days_left", "400000"),
            ],
        );
        let f = analyze_host(&h);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].id, "tls-cert-not-yet-valid");
        assert!(f[0].evidence.contains("2999-01-01"));
    }

    #[test]
    fn openssh_username_enumeration_includes_7_7() {
        let cve = |v: &str| {
            let h = host(
                &[22],
                &[("svc.22.product", "OpenSSH"), ("svc.22.version", v)],
            );
            ids(&h).contains(&"cve-cve-2018-15473".to_string())
        };
        assert!(cve("7.4"));
        assert!(cve("7.7"));
        assert!(cve("7.7p1"));
        assert!(!cve("7.8"));
        assert!(!cve("7.8p1"));
    }

    #[test]
    fn php_end_of_life_is_date_aware() {
        let today = "2026-11-18";
        assert_eq!(php_eol("7.4.33", today).unwrap(), "before 2025-12-31");
        assert_eq!(php_eol("8.0.30", today).unwrap(), "before 2025-12-31");
        assert_eq!(php_eol("8.1.2", today).unwrap(), "2025-12-31");
        assert_eq!(
            php_eol("8.2.10", today),
            None,
            "8.2 is supported until 2026-12-31"
        );
        assert_eq!(php_eol("8.2.10", "2027-01-01").unwrap(), "2026-12-31");
        assert_eq!(php_eol("8.3.1", today), None);
        assert_eq!(
            php_eol("9.0.0", today),
            None,
            "unknown newer branches are not flagged"
        );
        assert_eq!(php_eol("junk", today), None);
        let h = host(&[80], &[("http.80.powered_by", "PHP/8.1.2")]);
        assert!(ids(&h).contains(&"php-eol".to_string()));
    }

    #[test]
    fn ldap_smb_and_port_2222_findings() {
        let refused = host(&[389], &[("svc.389", "ldap (anonymous bind refused)")]);
        assert!(ids(&refused).is_empty());
        let plain = host(&[389], &[("svc.389", "ldap")]);
        assert!(ids(&plain).is_empty());
        let open = host(&[389], &[("svc.389", "ldap (anonymous bind accepted)")]);
        assert_eq!(ids(&open), ["ldap-anonymous"]);

        // SMB1 accepted besides an SMB2 dialect without required signing: both findings.
        let smb = host(
            &[445],
            &[
                (
                    "svc.445",
                    "microsoft-ds SMB 3.1.1 (signing enabled, not required)",
                ),
                ("smb.445.smb1", "accepted"),
            ],
        );
        let got = ids(&smb);
        assert!(
            got.contains(&"smb1-enabled".to_string()) && got.contains(&"smb-signing".to_string())
        );
        let smb2_only = host(
            &[445],
            &[
                ("svc.445", "microsoft-ds SMB 3.1.1 (signing required)"),
                ("smb.445.smb1", "refused"),
            ],
        );
        assert!(ids(&smb2_only).is_empty());

        let ssh = host(&[2222], &[("svc.2222", "ssh OpenSSH 9.6 (protocol 2.0)")]);
        assert!(!ids(&ssh).contains(&"ot-reachable".to_string()));
        let silent = host(&[2222], &[("svc.2222", "unidentified")]);
        assert_eq!(ids(&silent), ["ot-reachable"]);
    }

    #[test]
    fn rdp_follow_up_results_raise_nla_findings() {
        let sev = |svc: &str| {
            let h = host(&[3389], &[("svc.3389", svc)]);
            analyze_host(&h)
                .into_iter()
                .find(|f| f.id == "rdp-no-nla")
                .map(|f| f.severity)
        };
        assert_eq!(sev("ms-wbt-server RDP (NLA (CredSSP); NLA required)"), None);
        assert_eq!(
            sev("ms-wbt-server RDP (NLA (CredSSP); TLS security also accepted (NLA not required))"),
            Some(Severity::Medium)
        );
        assert_eq!(
            sev(
                "ms-wbt-server RDP (NLA (CredSSP); standard RDP security also accepted (NLA not required))"
            ),
            Some(Severity::High)
        );
    }

    #[test]
    fn script_findings_and_sorting() {
        let h = host(
            &[],
            &[("finding.script.lab-1", "high|Lab device exposed|port 9999")],
        );
        let f = analyze_host(&h);
        assert_eq!(
            (f[0].severity, f[0].id.as_str(), f[0].evidence.as_str()),
            (Severity::High, "script-lab-1", "port 9999")
        );
        let mut a = host(&[23], &[("svc.23", "telnet")]);
        a.ip = "10.0.0.9".parse().unwrap();
        let b = host(&[21], &[("svc.21", "ftp")]);
        let all = analyze(&[b, a]);
        assert_eq!(all[0].severity, Severity::High);
        assert!(all.windows(2).all(|w| w[0].severity >= w[1].severity));
        assert_eq!(counts(&all)[&Severity::High], 1);
        assert_eq!(Severity::parse("CRIT"), Some(Severity::Critical));
        assert_eq!(Severity::parse("x"), None);
        let mut silent = host(&[23], &[("svc.23", "telnet")]);
        silent.responding = false;
        assert!(analyze(&[silent]).is_empty());
    }

    #[test]
    fn builtin_cve_rules_match_the_former_table() {
        let db = CveDb::builtin();
        assert_eq!(db.rules.len(), 8);
        let first: Vec<&str> = db.rules.iter().map(|r| r.cve[0].as_str()).collect();
        assert_eq!(
            first,
            [
                "CVE-2024-6387",
                "CVE-2023-38408",
                "CVE-2018-15473",
                "CVE-2021-41773",
                "CVE-2021-23017",
                "CVE-2011-2523",
                "CVE-2019-10149",
                "CVE-2017-7269"
            ]
        );
        let regre = &db.rules[0];
        assert_eq!(
            (regre.min.as_deref(), regre.max.as_deref(), regre.severity),
            (Some("8.5p1"), Some("9.8p1"), Severity::High)
        );
        assert_eq!(regre.exclude, ["for windows"]);
        assert_eq!(db.rules[3].cve.len(), 2);
    }

    #[test]
    fn cve_file_validation_and_merge() {
        let parse = |json: &str| CveDb::parse(json, "test");
        let rule = |extra: &str| {
            format!(
                r#"{{"rules":[{{"id":"x","product":"foo","severity":"high","cve":["CVE-2020-1234"],"title":"t"{extra}}}]}}"#
            )
        };
        assert!(parse(&rule(r#","min":"1.2","max":"1.3p1""#)).is_ok());
        assert!(
            parse(&rule(r#","max":"1.x""#))
                .unwrap_err()
                .contains("bad version")
        );
        assert!(
            parse(&rule(r#","min":"""#))
                .unwrap_err()
                .contains("bad version")
        );
        assert!(
            parse(&rule(r#","min":"2.0","max":"1.0""#))
                .unwrap_err()
                .contains("not below")
        );
        assert!(parse(&rule(r#","min":"1.0","max":"1.0""#)).is_err());
        assert!(parse(
            r#"{"rules":[{"id":"x","product":"foo","severity":"severe","cve":["CVE-2020-1234"],"title":"t"}]}"#
        )
        .unwrap_err()
        .contains("severity"));
        assert!(
            parse(
                r#"{"rules":[{"id":"x","product":"foo","severity":"low","cve":[],"title":"t"}]}"#
            )
            .unwrap_err()
            .contains("empty")
        );
        assert!(parse(
            r#"{"rules":[{"id":"x","product":"foo","severity":"low","cve":["CVE-20-1"],"title":"t"}]}"#
        )
        .unwrap_err()
        .contains("bad CVE"));
        assert!(
            parse(r#"{"cpe":[{"id":"c","products":["foo"],"template":"cpe:2.3:a:foo"}]}"#)
                .unwrap_err()
                .contains("template")
        );
        assert!(parse("not json").is_err());

        let path = std::env::temp_dir().join(format!("ns-cves-{}.json", std::process::id()));
        std::fs::write(
            &path,
            r#"{"rules":[
              {"id":"openssh-user-enum","product":"openssh","max":"7.5","severity":"medium","cve":["CVE-2018-15473"],"title":"replaced"},
              {"id":"lab-1","product":"labd","min":"1.0","max":"2.0","severity":"critical","cve":["CVE-2099-0001"],"title":"Lab daemon"}],
             "cpe":[{"id":"labd","products":["labd"],"template":"cpe:2.3:a:lab:labd:{version}:*:*:*:*:*:*:*"}]}"#,
        )
        .unwrap();
        let db = CveDb::load(Some(&path)).unwrap();
        assert_eq!(db.rules.len(), 9, "one replaced, one added");
        let replaced = db
            .rules
            .iter()
            .find(|r| r.id == "openssh-user-enum")
            .unwrap();
        assert_eq!(
            (replaced.title.as_str(), replaced.max.as_deref()),
            ("replaced", Some("7.5"))
        );
        let h = host(
            &[7000],
            &[("svc.7000.product", "labd"), ("svc.7000.version", "1.4")],
        );
        let f = analyze_host_with(&h, &db);
        assert_eq!(f.len(), 1);
        assert_eq!(
            (f[0].id.as_str(), f[0].severity),
            ("cve-cve-2099-0001", Severity::Critical)
        );
        assert!(analyze_host_with(&h, &CveDb::builtin()).is_empty());
        // 7.6 is no longer in the replaced range.
        let ssh = host(
            &[22],
            &[("svc.22.product", "OpenSSH"), ("svc.22.version", "7.6")],
        );
        assert!(
            !analyze_host_with(&ssh, &db)
                .iter()
                .any(|f| f.id == "cve-cve-2018-15473")
        );
        assert_eq!(
            db.cpe("labd", "1.4").unwrap(),
            "cpe:2.3:a:lab:labd:1.4:*:*:*:*:*:*:*"
        );
        std::fs::write(&path, r#"{"rules":[{"id":"y","product":"p","max":"abc","severity":"low","cve":["CVE-2020-0001"],"title":"t"}]}"#).unwrap();
        assert!(
            CveDb::load(Some(&path))
                .unwrap_err()
                .contains("bad version")
        );
        let _ = std::fs::remove_file(&path);
        assert!(CveDb::load(Some(&path)).is_err());
    }

    #[test]
    fn cpe_names_from_product_and_version() {
        let db = CveDb::builtin();
        assert_eq!(
            db.cpe("OpenSSH", "7.4p1").unwrap(),
            "cpe:2.3:a:openbsd:openssh:7.4:p1:*:*:*:*:*:*"
        );
        assert_eq!(
            db.cpe("OpenSSH", "9.6").unwrap(),
            "cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*"
        );
        assert_eq!(
            db.cpe("Apache", "2.4.49").unwrap(),
            "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
        );
        assert_eq!(
            db.cpe("MySQL", "8.0.33-0ubuntu0.22.04.2").unwrap(),
            "cpe:2.3:a:oracle:mysql:8.0.33:*:*:*:*:*:*:*"
        );
        assert_eq!(
            db.cpe("OpenSSH for Windows", "9.5"),
            None,
            "exact names only"
        );
        assert_eq!(db.cpe("Apache-Coyote", "1.1"), None);
        assert_eq!(db.cpe("OpenSSH", ""), None);
        assert_eq!(db.cpe("OpenSSH", "x:y*"), None, "untrusted banner text");
        assert_eq!(db.cpe("unknown", "1.0"), None);
    }

    // The vendor:product pairs of the table are compared with the NVD CPE dictionary by
    // `lab/check_cpe.py` (CI, job real-servers); this is its format check, and it pins the
    // vendor that the dictionary check found wrong (`beasts` is not a vendor of vsftpd there).
    #[test]
    fn builtin_cpe_templates_are_well_formed_names() {
        let db = CveDb::builtin();
        let mut pairs = std::collections::BTreeSet::new();
        for rule in &db.cpe {
            let fields: Vec<&str> = rule.template.split(':').collect();
            assert_eq!(fields.len(), 13, "{}", rule.id);
            assert_eq!(&fields[..3], ["cpe", "2.3", "a"], "{}", rule.id);
            for name in &fields[3..5] {
                assert!(
                    name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
                        && name.bytes().all(|b| matches!(b,
                            b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-' | b'~')),
                    "{}: {name:?}",
                    rule.id
                );
            }
            assert!(
                pairs.insert((fields[3], fields[4])),
                "{} repeats a pair",
                rule.id
            );
        }
        assert!(pairs.contains(&("vsftpd_project", "vsftpd")));
        assert!(!pairs.contains(&("beasts", "vsftpd")));
        assert_eq!(
            db.cpe("vsftpd", "3.0.5").unwrap(),
            "cpe:2.3:a:vsftpd_project:vsftpd:3.0.5:*:*:*:*:*:*:*"
        );
    }
    #[test]
    fn smb_encryption_and_smbghost_hints() {
        let smb = |extra: &[(&str, &str)]| {
            let mut kv = vec![("svc.445", "microsoft-ds SMB 3.1.1 (signing required)")];
            kv.extend_from_slice(extra);
            ids(&host(&[445], &kv))
        };
        assert_eq!(
            smb(&[
                ("smb.445.dialect", "3.0"),
                ("smb.445.encryption", "not supported")
            ]),
            ["smb-no-encryption"]
        );
        assert!(
            smb(&[
                ("smb.445.dialect", "3.1.1"),
                ("smb.445.encryption", "AES-128-GCM")
            ])
            .is_empty()
        );
        let ghost = [
            ("smb.445.dialect", "3.1.1"),
            ("smb.445.encryption", "AES-128-GCM"),
            ("smb.445.compression", "LZNT1"),
            ("smb.445.os_version", "10.0.18363"),
        ];
        let h = host(
            &[445],
            &[
                &[("svc.445", "microsoft-ds SMB 3.1.1 (signing required)")][..],
                &ghost[..],
            ]
            .concat(),
        );
        let f = analyze_host(&h);
        let g = f.iter().find(|f| f.id == "cve-cve-2020-0796").unwrap();
        assert_eq!(g.cve, ["CVE-2020-0796"]);
        assert!(g.evidence.contains("Version-based hint"));
        // Never on compression alone, nor on other builds, nor without compression.
        assert!(smbghost_hint("3.1.1", "LZNT1", "").is_none());
        assert!(smbghost_hint("3.1.1", "LZNT1", "10.0.19045").is_none());
        assert!(smbghost_hint("3.1.1", "none", "10.0.18362").is_none());
        assert!(smbghost_hint("3.0.2", "LZNT1", "10.0.18362").is_none());
        assert!(smbghost_hint("3.1.1", "LZ77", "10.0.18362").is_some());
    }
}

// False-alarm budget: a case table with one must-trigger and one must-not-trigger host per rule.
#[cfg(test)]
#[path = "risk_budget.rs"]
pub(crate) mod budget;
