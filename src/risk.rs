//! Findings derived from what a scan observed: weak TLS/SSH configuration, risky exposed
//! services, and version-based CVE hints. Version hints are NOT confirmed vulnerabilities:
//! distributions backport fixes without changing the version string.
use crate::scan::Host;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::IpAddr};

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

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub id: String,
    pub title: String,
    pub ip: IpAddr,
    pub port: Option<u16>,
    pub evidence: String,
    pub cve: Vec<String>,
    pub advice: String,
}
impl Finding {
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

struct CveRule {
    product: &'static str,
    min: Option<&'static str>,
    max: Option<&'static str>,
    severity: Severity,
    cve: &'static [&'static str],
    title: &'static str,
}
const CVE_RULES: &[CveRule] = &[
    CveRule {
        product: "openssh",
        min: Some("8.5p1"),
        max: Some("9.8p1"),
        severity: Severity::High,
        cve: &["CVE-2024-6387"],
        title: "OpenSSH regreSSHion (unauthenticated signal-handler race, glibc Linux)",
    },
    CveRule {
        product: "openssh",
        min: None,
        max: Some("9.3p2"),
        severity: Severity::Medium,
        cve: &["CVE-2023-38408"],
        title: "OpenSSH ssh-agent PKCS#11 code execution (needs a forwarded agent)",
    },
    CveRule {
        product: "openssh",
        min: None,
        // Affected through 7.7 (fixed in 7.8). "7.7p1" parses as [7, 7, 1], above "7.7", so the
        // exclusive bound must be 7.8 to include 7.7 and 7.7p1.
        max: Some("7.8"),
        severity: Severity::Low,
        cve: &["CVE-2018-15473"],
        title: "OpenSSH username enumeration",
    },
    CveRule {
        product: "apache",
        min: Some("2.4.49"),
        max: Some("2.4.51"),
        severity: Severity::Critical,
        cve: &["CVE-2021-41773", "CVE-2021-42013"],
        title: "Apache httpd 2.4.49/2.4.50 path traversal and remote code execution",
    },
    CveRule {
        product: "nginx",
        min: Some("0.6.18"),
        max: Some("1.20.1"),
        severity: Severity::Medium,
        cve: &["CVE-2021-23017"],
        title: "nginx resolver off-by-one (only when a resolver is configured)",
    },
    CveRule {
        product: "vsftpd",
        min: Some("2.3.4"),
        max: Some("2.3.5"),
        severity: Severity::Critical,
        cve: &["CVE-2011-2523"],
        title: "vsFTPd 2.3.4 backdoor",
    },
    CveRule {
        product: "exim",
        min: Some("4.87"),
        max: Some("4.92"),
        severity: Severity::Critical,
        cve: &["CVE-2019-10149"],
        title: "Exim 4.87-4.91 remote command execution",
    },
    CveRule {
        product: "microsoft-iis",
        min: Some("6.0"),
        max: Some("6.1"),
        severity: Severity::High,
        cve: &["CVE-2017-7269"],
        title: "IIS 6.0 WebDAV buffer overflow",
    },
];
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

const BACKPORT_NOTE: &str =
    "Version-based hint only: distributions backport fixes without changing the version. Confirm with the vendor advisory or an authenticated check.";

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
        });
    }
}

pub fn analyze_host(h: &Host) -> Vec<Finding> {
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
            } else if let Ok(days) = get(format!("tls.{p}.days_left")).parse::<i64>() {
                if days <= 30 {
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
            if get(format!("tls.{p}.self_signed")) == "true" {
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
            {
                if bits < 2048 {
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
        if svc.contains("protocol 1.") && !svc.contains("protocol 1.99") {
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
        for (prod, ver) in candidates {
            let prod = prod.to_ascii_lowercase();
            for rule in CVE_RULES.iter().filter(|r| {
                // These OpenSSH issues concern the portable (Unix) release, not OpenSSH for Windows.
                let windows_port = r.product == "openssh" && prod.contains("for windows");
                prod.contains(r.product) && !windows_port && in_range(&ver, r.min, r.max)
            }) {
                if seen.insert(rule.cve[0]) {
                    o.add(
                        rule.severity,
                        &format!("cve-{}", rule.cve[0].to_ascii_lowercase()),
                        rule.title,
                        port,
                        format!("{prod} {ver}. {BACKPORT_NOTE}"),
                        rule.cve,
                        "Update to a fixed release or confirm the vendor backported the fix.",
                    );
                }
            }
        }
        if let Some(v) = get(format!("http.{p}.powered_by")).strip_prefix("PHP/") {
            if let Some(eol) = php_eol(v, &today()) {
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
        }
        // 2222/tcp is EtherNet/IP I/O (and legacy Allen-Bradley CSP) but also a very common
        // alternative SSH port; service detection only listens there, so an SSH greeting
        // means it is not an industrial service.
        let ssh_on_2222 = p == 2222 && name == "ssh";
        if crate::service::is_ot_port_candidate(p) && !ssh_on_2222 {
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
        });
    }
    all.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.ip.cmp(&b.ip))
            .then(a.port.cmp(&b.port))
            .then(a.id.cmp(&b.id))
    });
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
        assert!(analyze_host(&apache)
            .iter()
            .any(|f| f.severity == Severity::Critical
                && f.cve.contains(&"CVE-2021-41773".to_string())));
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
                ("tls.443.weak", "TLS1.0 enabled (deprecated); TLS1.0: RSA_RC4_128_SHA - RC4; TLS1.2: RSA_AES_128_CBC_SHA - no forward secrecy"),
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
            sev("ms-wbt-server RDP (NLA (CredSSP); standard RDP security also accepted (NLA not required))"),
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
}
