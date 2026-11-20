//! False-alarm budget for the risk rules (ROADMAP A8): every rule id in `risk.rs` has a table
//! entry with a host that must trigger it and a near-miss host that must not. The inventory
//! test reads the rule ids out of the `risk.rs` source, so a new rule without both cases fails
//! the build. The near misses are chosen to look like the rule's evidence (same port, same
//! keys, a different value), because those are the cases that produce false alarms.
use super::*;

/// One scan result: open TCP ports, open UDP ports and the identity keys.
struct Spec {
    tcp: &'static [u16],
    udp: &'static [u16],
    id: &'static [(&'static str, &'static str)],
}
const fn spec(
    tcp: &'static [u16],
    udp: &'static [u16],
    id: &'static [(&'static str, &'static str)],
) -> Spec {
    Spec { tcp, udp, id }
}

struct Case {
    id: &'static str,
    /// Must raise the finding.
    hit: Spec,
    /// Evidence that is close to the rule's but means the condition is absent.
    miss: Spec,
}

fn host_of(s: &Spec) -> Host {
    Host {
        ip: "10.0.0.5".parse().unwrap(),
        responding: true,
        ping: None,
        ttl: None,
        hostname: String::new(),
        mac: String::new(),
        open: s.tcp.to_vec(),
        closed: 0,
        unanswered: 0,
        errors: vec![],
        ports_checked: true,
        identity: s
            .id
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        udp_open: s.udp.to_vec(),
        trace: vec![],
    }
}
fn ids_of(s: &Spec) -> Vec<String> {
    analyze_host_with(&host_of(s), &CveDb::builtin())
        .into_iter()
        .map(|f| f.id)
        .collect()
}

/// Every rule id that `analyze_host` and `analyze_snapshot` can raise by a literal id. The
/// data-driven families (`cve-*` from data/cves.json, `script-*` from user scripts) have their
/// own tests below.
fn cases() -> Vec<Case> {
    vec![
        Case {
            id: "tls-cert-expired",
            hit: spec(
                &[443],
                &[],
                &[
                    ("tls.443.subject", "CN=x"),
                    ("tls.443.expired", "true"),
                    ("tls.443.not_after", "2020-01-01"),
                ],
            ),
            miss: spec(
                &[443],
                &[],
                &[
                    ("tls.443.subject", "CN=x"),
                    ("tls.443.expired", "false"),
                    ("tls.443.days_left", "200"),
                ],
            ),
        },
        Case {
            id: "tls-cert-expiring",
            hit: spec(
                &[443],
                &[],
                &[("tls.443.subject", "CN=x"), ("tls.443.days_left", "30")],
            ),
            // One day outside the window.
            miss: spec(
                &[443],
                &[],
                &[("tls.443.subject", "CN=x"), ("tls.443.days_left", "31")],
            ),
        },
        Case {
            id: "tls-cert-not-yet-valid",
            hit: spec(
                &[443],
                &[],
                &[
                    ("tls.443.subject", "CN=x"),
                    ("tls.443.not_yet_valid", "true"),
                    ("tls.443.not_before", "2999-01-01"),
                ],
            ),
            miss: spec(
                &[443],
                &[],
                &[
                    ("tls.443.subject", "CN=x"),
                    ("tls.443.not_yet_valid", "false"),
                    ("tls.443.not_before", "2020-01-01"),
                    ("tls.443.days_left", "200"),
                ],
            ),
        },
        Case {
            id: "tls-self-signed",
            hit: spec(
                &[443],
                &[],
                &[("tls.443.subject", "CN=x"), ("tls.443.self_signed", "true")],
            ),
            miss: spec(
                &[443],
                &[],
                &[
                    ("tls.443.subject", "CN=x"),
                    ("tls.443.self_signed", "false"),
                    ("tls.443.days_left", "200"),
                ],
            ),
        },
        Case {
            id: "tls-self-signed-bad-signature",
            hit: spec(
                &[443],
                &[],
                &[
                    ("tls.443.subject", "CN=x"),
                    ("tls.443.self_signed", "true"),
                    ("tls.443.self_signature", "invalid"),
                ],
            ),
            // A verifier limit is not a forged certificate; neither is a valid signature.
            miss: spec(
                &[443],
                &[],
                &[
                    ("tls.443.subject", "CN=x"),
                    ("tls.443.self_signed", "true"),
                    (
                        "tls.443.self_signature",
                        "unchecked (signature algorithm not supported by the verifier)",
                    ),
                ],
            ),
        },
        Case {
            id: "tls-weak-signature",
            hit: spec(
                &[443],
                &[],
                &[
                    ("tls.443.subject", "CN=x"),
                    ("tls.443.signature", "sha1WithRSA (weak)"),
                ],
            ),
            miss: spec(
                &[443],
                &[],
                &[
                    ("tls.443.subject", "CN=x"),
                    ("tls.443.signature", "sha256WithRSAEncryption"),
                    ("tls.443.days_left", "200"),
                ],
            ),
        },
        Case {
            id: "tls-weak-key",
            hit: spec(
                &[443],
                &[],
                &[("tls.443.subject", "CN=x"), ("tls.443.key", "RSA 1024")],
            ),
            // RSA 2048 is the floor; an EC key has no RSA bit count at all.
            miss: spec(
                &[443],
                &[],
                &[
                    ("tls.443.subject", "CN=x"),
                    ("tls.443.key", "EC P-256"),
                    ("tls.443.days_left", "200"),
                ],
            ),
        },
        Case {
            id: "tls-sslv3",
            hit: spec(
                &[443],
                &[],
                &[
                    ("tls.443.subject", "CN=x"),
                    ("tls.443.weak", "SSLv3 enabled (POODLE)"),
                ],
            ),
            miss: spec(
                &[443],
                &[],
                &[
                    ("tls.443.subject", "CN=x"),
                    ("tls.443.weak", "TLS1.0 enabled (deprecated)"),
                    ("tls.443.versions", "TLS1.2, TLS1.0 (deprecated)"),
                ],
            ),
        },
        Case {
            id: "tls-deprecated-protocol",
            hit: spec(
                &[443],
                &[],
                &[
                    ("tls.443.subject", "CN=x"),
                    ("tls.443.weak", "TLS1.1 enabled (deprecated)"),
                    ("tls.443.versions", "TLS1.2, TLS1.1 (deprecated)"),
                ],
            ),
            miss: spec(
                &[443],
                &[],
                &[
                    ("tls.443.subject", "CN=x"),
                    ("tls.443.weak", "SSLv3 enabled (POODLE)"),
                ],
            ),
        },
        Case {
            id: "tls-broken-cipher",
            hit: spec(
                &[443],
                &[],
                &[
                    ("tls.443.subject", "CN=x"),
                    ("tls.443.weak", "TLS1.0: RSA_RC4_128_SHA - RC4"),
                ],
            ),
            miss: spec(
                &[443],
                &[],
                &[
                    ("tls.443.subject", "CN=x"),
                    ("tls.443.weak", "TLS1.2: RSA_3DES_EDE_CBC_SHA - 3DES"),
                ],
            ),
        },
        Case {
            id: "tls-3des",
            hit: spec(
                &[443],
                &[],
                &[
                    ("tls.443.subject", "CN=x"),
                    ("tls.443.weak", "TLS1.2: RSA_3DES_EDE_CBC_SHA - 3DES"),
                ],
            ),
            miss: spec(
                &[443],
                &[],
                &[
                    ("tls.443.subject", "CN=x"),
                    (
                        "tls.443.weak",
                        "TLS1.2: RSA_AES_128_CBC_SHA - no forward secrecy",
                    ),
                ],
            ),
        },
        Case {
            id: "tls-no-pfs",
            hit: spec(
                &[443],
                &[],
                &[
                    ("tls.443.subject", "CN=x"),
                    (
                        "tls.443.weak",
                        "TLS1.2: RSA_AES_128_CBC_SHA - no forward secrecy",
                    ),
                ],
            ),
            miss: spec(
                &[443],
                &[],
                &[
                    ("tls.443.subject", "CN=x"),
                    ("tls.443.weak", "TLS1.2: RSA_3DES_EDE_CBC_SHA - 3DES"),
                ],
            ),
        },
        Case {
            id: "ssh-weak-algorithms",
            hit: spec(
                &[22],
                &[],
                &[("ssh.22.weak", "kex diffie-hellman-group1-sha1")],
            ),
            miss: spec(&[22], &[], &[("ssh.22.legacy", "hmac-sha1")]),
        },
        Case {
            id: "ssh-legacy-algorithms",
            hit: spec(&[22], &[], &[("ssh.22.legacy", "hmac-sha1")]),
            miss: spec(
                &[22],
                &[],
                &[("ssh.22.weak", "kex diffie-hellman-group1-sha1")],
            ),
        },
        Case {
            id: "ssh-protocol-1",
            hit: spec(&[22], &[], &[("svc.22", "ssh OpenSSH_3.9 (protocol 1.5)")]),
            // Protocol 1.99 is "2.0 compatible"; and a service that is not SSH may print
            // "protocol 1.x" for its own protocol.
            miss: spec(
                &[22, 1883],
                &[],
                &[
                    ("svc.22", "ssh OpenSSH 7.4 (protocol 1.99)"),
                    ("svc.1883", "mqtt (protocol 1.0 gateway)"),
                ],
            ),
        },
        Case {
            id: "telnet-open",
            hit: spec(&[23], &[], &[("svc.23", "telnet")]),
            miss: spec(
                &[23],
                &[],
                &[("svc.23", "unidentified (port suggests telnet)")],
            ),
        },
        Case {
            id: "ftp-cleartext",
            hit: spec(&[21], &[], &[("svc.21", "ftp vsFTPd 3.0.3")]),
            miss: spec(&[990], &[], &[("svc.990", "ftps")]),
        },
        Case {
            id: "vnc-exposed",
            hit: spec(&[5900], &[], &[("svc.5900", "vnc RFB 003.008")]),
            miss: spec(
                &[5900],
                &[],
                &[("svc.5900", "unidentified (port suggests vnc)")],
            ),
        },
        Case {
            id: "mail-cleartext",
            hit: spec(&[110], &[], &[("svc.110", "pop3 Dovecot")]),
            // The TLS variants are identified as pop3s/imaps.
            miss: spec(
                &[995, 993],
                &[],
                &[("svc.995", "pop3s"), ("svc.993", "imaps")],
            ),
        },
        Case {
            id: "redis-noauth",
            hit: spec(
                &[6379],
                &[],
                &[
                    ("svc.6379", "redis Redis 7.0.11"),
                    ("svc.6379.version", "7.0.11"),
                ],
            ),
            miss: spec(
                &[6379],
                &[],
                &[("svc.6379", "redis Redis (authentication required)")],
            ),
        },
        Case {
            id: "memcached-open",
            hit: spec(
                &[11211],
                &[],
                &[
                    ("svc.11211", "memcached memcached 1.6.9"),
                    ("svc.11211.version", "1.6.9"),
                ],
            ),
            // Identified, but no version was read: the server did not answer a command.
            miss: spec(&[11211], &[], &[("svc.11211", "memcached")]),
        },
        Case {
            id: "mqtt-anonymous",
            hit: spec(
                &[1883],
                &[],
                &[("svc.1883", "mqtt (anonymous connection accepted)")],
            ),
            miss: spec(&[1883], &[], &[("svc.1883", "mqtt")]),
        },
        Case {
            id: "ldap-anonymous",
            hit: spec(
                &[389],
                &[],
                &[("svc.389", "ldap (anonymous bind accepted)")],
            ),
            miss: spec(&[389], &[], &[("svc.389", "ldap (anonymous bind refused)")]),
        },
        Case {
            id: "postgres-no-tls",
            hit: spec(
                &[5432],
                &[],
                &[("svc.5432", "postgresql (TLS not supported)")],
            ),
            miss: spec(&[5432], &[], &[("svc.5432", "postgresql (TLS supported)")]),
        },
        Case {
            id: "rdp-no-nla",
            hit: spec(
                &[3389],
                &[],
                &[(
                    "svc.3389",
                    "ms-wbt-server RDP (standard RDP security (no TLS/NLA))",
                )],
            ),
            miss: spec(
                &[3389],
                &[],
                &[(
                    "svc.3389",
                    "ms-wbt-server RDP (NLA (CredSSP); NLA required)",
                )],
            ),
        },
        Case {
            id: "smb1-enabled",
            hit: spec(
                &[445],
                &[],
                &[("svc.445", "microsoft-ds SMBv1 (signing disabled)")],
            ),
            miss: spec(
                &[445],
                &[],
                &[
                    ("svc.445", "microsoft-ds SMB 3.1.1 (signing required)"),
                    ("smb.445.smb1", "refused"),
                ],
            ),
        },
        Case {
            id: "smb-signing",
            hit: spec(
                &[445],
                &[],
                &[(
                    "svc.445",
                    "microsoft-ds SMB 3.1.1 (signing enabled, not required)",
                )],
            ),
            miss: spec(
                &[445],
                &[],
                &[("svc.445", "microsoft-ds SMB 3.1.1 (signing required)")],
            ),
        },
        Case {
            id: "smb-no-encryption",
            hit: spec(
                &[445],
                &[],
                &[
                    ("svc.445", "microsoft-ds SMB 2.1 (signing required)"),
                    ("smb.445.dialect", "2.1"),
                    ("smb.445.encryption", "not supported (dialect below 3.0)"),
                ],
            ),
            miss: spec(
                &[445],
                &[],
                &[
                    ("svc.445", "microsoft-ds SMB 3.1.1 (signing required)"),
                    ("smb.445.encryption", "AES-128-GCM"),
                ],
            ),
        },
        Case {
            id: "cve-cve-2020-0796",
            hit: spec(
                &[445],
                &[],
                &[
                    ("svc.445", "microsoft-ds SMB 3.1.1 (signing required)"),
                    ("smb.445.dialect", "3.1.1"),
                    ("smb.445.compression", "LZNT1"),
                    ("smb.445.os_version", "10.0.18362"),
                ],
            ),
            // The same dialect and compression on a build that is not affected.
            miss: spec(
                &[445],
                &[],
                &[
                    ("svc.445", "microsoft-ds SMB 3.1.1 (signing required)"),
                    ("smb.445.dialect", "3.1.1"),
                    ("smb.445.compression", "LZNT1"),
                    ("smb.445.os_version", "10.0.19045"),
                ],
            ),
        },
        Case {
            id: "http-basic-cleartext",
            hit: spec(
                &[80],
                &[],
                &[("svc.80", "http"), ("http.80.auth", "Basic realm=\"r\"")],
            ),
            miss: spec(
                &[443],
                &[],
                &[("svc.443", "https"), ("http.443.auth", "Basic realm=\"r\"")],
            ),
        },
        Case {
            id: "docker-api",
            hit: spec(
                &[2375],
                &[],
                &[("http.2375.server", "Docker/24.0.7 (linux)")],
            ),
            miss: spec(
                &[2375],
                &[],
                &[("http.2375.server", "Apache/2.4.58 (Unix)")],
            ),
        },
        Case {
            id: "heartbleed",
            hit: spec(
                &[443],
                &[],
                &[("http.443.server", "Apache/2.2.22 OpenSSL/1.0.1e")],
            ),
            miss: spec(
                &[443],
                &[],
                &[("http.443.server", "Apache/2.2.22 OpenSSL/1.0.1g")],
            ),
        },
        Case {
            id: "php-eol",
            hit: spec(&[80], &[], &[("http.80.powered_by", "PHP/7.4.33")]),
            miss: spec(&[80], &[], &[("http.80.powered_by", "PHP/8.4.1")]),
        },
        Case {
            id: "ot-reachable",
            hit: spec(&[502], &[], &[]),
            // SSH answered on an industrial port number (2222 is the usual case).
            miss: spec(
                &[2222, 20000],
                &[],
                &[
                    ("svc.2222", "ssh OpenSSH 9.6 (protocol 2.0)"),
                    ("svc.20000", "ssh OpenSSH 8.4 (protocol 2.0)"),
                ],
            ),
        },
        Case {
            id: "snmp-public",
            hit: spec(&[], &[161], &[("udp.161", "SNMP sysDescr: Linux")]),
            miss: spec(&[], &[161], &[("udp.161", "unknown reply")]),
        },
        Case {
            id: "netbios-ns",
            hit: spec(&[], &[137], &[("udp.137", "NetBIOS name table")]),
            // A recorded answer, but the port is not among the open UDP ports.
            miss: spec(&[], &[], &[("udp.137", "NetBIOS name table")]),
        },
        Case {
            id: "upnp-exposed",
            hit: spec(&[], &[1900], &[("udp.1900", "SSDP")]),
            miss: spec(&[], &[], &[("udp.1900", "SSDP")]),
        },
        Case {
            id: "ot-control-traffic",
            // Raised from passive observations; see `control_traffic_needs_a_write_or_stop`.
            hit: spec(&[], &[], &[]),
            miss: spec(&[], &[], &[]),
        },
    ]
}

/// Rule ids that are raised in `analyze_snapshot` from passive observations, not from a host.
const SNAPSHOT_ONLY: &[&str] = &["ot-control-traffic"];

#[test]
fn every_rule_triggers_on_its_evidence_and_stays_quiet_on_the_near_miss() {
    for case in cases() {
        if SNAPSHOT_ONLY.contains(&case.id) {
            continue;
        }
        let hit = ids_of(&case.hit);
        assert!(
            hit.iter().any(|i| i == case.id),
            "{} did not fire on its positive case; got {hit:?}",
            case.id
        );
        let miss = ids_of(&case.miss);
        assert!(
            miss.iter().all(|i| i != case.id),
            "{} fired on its negative case (a false alarm); got {miss:?}",
            case.id
        );
    }
}

/// The ids come from the source text of `risk.rs`, the same extraction the documentation
/// checker (`docs/check_finding_pages.py`) uses, so a new rule cannot be added unnoticed.
pub(crate) fn source_rule_ids() -> (std::collections::BTreeSet<String>, Vec<String>) {
    let source = include_str!("risk.rs");
    let code = source.split("\n#[cfg(test)]").next().unwrap();
    let add = regex::Regex::new(
        r#"\bo\.add\(\s*[A-Za-z_:.]+\s*,\s*("([a-z0-9][a-z0-9-]*)"|&format!\(\s*"([a-z]+-))"#,
    )
    .unwrap();
    let literal = regex::Regex::new(r#"\bid:\s*"([a-z0-9][a-z0-9-]*)"\s*\.into\(\)"#).unwrap();
    let mut ids = std::collections::BTreeSet::new();
    let mut families = vec![];
    for c in add.captures_iter(code) {
        match (c.get(2), c.get(3)) {
            (Some(id), _) => {
                ids.insert(id.as_str().to_string());
            }
            (_, Some(f)) => families.push(f.as_str().to_string()),
            _ => {}
        }
    }
    for c in literal.captures_iter(code) {
        ids.insert(c[1].to_string());
    }
    families.sort();
    families.dedup();
    (ids, families)
}

#[test]
fn the_rule_inventory_matches_the_case_table() {
    let (ids, families) = source_rule_ids();
    assert!(ids.len() >= 30, "the id extraction found only {ids:?}");
    let table: std::collections::BTreeSet<String> =
        cases().into_iter().map(|c| c.id.to_string()).collect();
    for id in &ids {
        assert!(
            table.contains(id),
            "rule {id:?} in risk.rs has no entry in risk_budget.rs: add a case that must trigger \
             it and a near miss that must not (A8)"
        );
    }
    for id in &table {
        assert!(
            ids.contains(id),
            "risk_budget.rs has a case for {id:?}, which risk.rs no longer raises"
        );
    }
    // Rule families whose ids are built at run time have dedicated tests below.
    assert_eq!(
        families,
        ["cve-", "script-"],
        "a new run-time id family needs its own budget test"
    );
}

#[test]
fn every_builtin_cve_rule_triggers_inside_and_not_outside_its_range() {
    let db = CveDb::builtin();
    assert!(!db.rules.is_empty());
    for rule in &db.rules {
        let at = |version: &str, product: &str| -> Vec<String> {
            let h = host_of(&spec(&[8080], &[], &[]));
            let mut h = h;
            h.identity
                .insert("svc.8080.product".into(), product.to_string());
            h.identity
                .insert("svc.8080.version".into(), version.to_string());
            analyze_host_with(&h, &db)
                .into_iter()
                .map(|f| f.id)
                .collect()
        };
        let want = format!("cve-{}", rule.cve[0].to_ascii_lowercase());
        let inside = rule.min.clone().unwrap_or_else(|| "0.1".to_string());
        assert!(
            at(&inside, &rule.product).contains(&want),
            "{} must fire at its lower bound {inside}",
            rule.id
        );
        if let Some(max) = &rule.max {
            assert!(
                !at(max, &rule.product).contains(&want),
                "{} must not fire at its (exclusive) upper bound {max}",
                rule.id
            );
        }
        if let Some(min) = &rule.min {
            // One patch level below the lower bound: the version before it.
            let below = parse_version(min);
            let mut v = below.clone();
            if let Some(last) = v.last_mut().filter(|l| **l > 0) {
                *last -= 1;
                let text = v.iter().map(u32::to_string).collect::<Vec<_>>().join(".");
                assert!(
                    !at(&text, &rule.product).contains(&want),
                    "{} must not fire below its lower bound ({text})",
                    rule.id
                );
            }
        }
        for excluded in &rule.exclude {
            assert!(
                !at(&inside, &format!("{} {excluded}", rule.product)).contains(&want),
                "{} must not apply to {excluded}",
                rule.id
            );
        }
        // A different product with the same version number never matches.
        assert!(
            !at(&inside, "unrelated-daemon").contains(&want),
            "{} fired for an unrelated product",
            rule.id
        );
    }
}

fn nvd_sample() -> crate::nvd::Nvd {
    let mut nvd = crate::nvd::Nvd::default();
    let parsed =
        crate::nvd::parse_nvd(include_bytes!("../../tests/fixtures/nvd-sample.json")).unwrap();
    nvd.merge(parsed, "nvd-sample.json").unwrap();
    nvd
}

#[test]
fn nvd_hits_raise_cve_findings_inside_their_range_only() {
    let nvd = nvd_sample();
    let run = |id: &[(&str, &str)]| {
        let mut h = host_of(&spec(&[8080], &[], &[]));
        for (k, v) in id {
            h.identity.insert(k.to_string(), v.to_string());
        }
        analyze_host_nvd(&h, &CveDb::builtin(), &nvd)
    };
    let cpe = |v: &str| -> Vec<Finding> {
        let c = format!("cpe:2.3:a:example:examplehttpd:{v}:*:*:*:*:*:*:*");
        run(&[("svc.8080.cpe", c.as_str())])
    };
    let hit = cpe("1.5");
    assert_eq!(hit.len(), 1, "{hit:?}");
    let f = &hit[0];
    assert_eq!(f.id, "cve-cve-2099-0001");
    assert_eq!(f.cve, ["CVE-2099-0001"]);
    assert_eq!(f.severity, Severity::Medium);
    assert_eq!(f.confidence, 40);
    assert!(f.evidence.contains("1.0 < v <= 2.0"), "{}", f.evidence);
    assert!(f.evidence.contains("Version-based hint"), "{}", f.evidence);
    // Boundaries and unrelated input: nothing.
    for v in ["1.0", "2.0.1", "0.9", "*", "-"] {
        assert!(cpe(v).is_empty(), "{v}");
    }
    assert!(run(&[]).is_empty(), "no CPE, no NVD lookup");
    assert!(run(&[("svc.8080.cpe", "not a cpe")]).is_empty());
    // AND configurations, rejected and unbounded records never match, whatever the version.
    for v in ["1.0.1", "3.0", "5.0", "9.0"] {
        assert!(
            cpe(v).iter().all(|f| f.id != "cve-cve-2099-0002"
                && f.id != "cve-cve-2099-0003"
                && f.id != "cve-cve-2099-0004"),
            "{v}"
        );
    }
    // Without imported data nothing changes.
    let none = analyze_host_nvd(
        &host_of(&spec(
            &[8080],
            &[],
            &[(
                "svc.8080.cpe",
                "cpe:2.3:a:example:examplehttpd:1.5:*:*:*:*:*:*:*",
            )],
        )),
        &CveDb::builtin(),
        &crate::nvd::Nvd::default(),
    );
    assert!(none.is_empty());
}

#[test]
fn nvd_never_repeats_a_cve_the_builtin_rules_raised() {
    let nvd = nvd_sample();
    let host = host_of(&spec(
        &[22, 8080],
        &[],
        &[
            ("svc.22.product", "OpenSSH"),
            ("svc.22.version", "9.6p1"),
            ("svc.22.cpe", "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*"),
            ("svc.8080.product", "Apache"),
            ("svc.8080.version", "2.4.49"),
            (
                "svc.8080.cpe",
                "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            ),
        ],
    ));
    let with = analyze_host_nvd(&host, &CveDb::builtin(), &nvd);
    let without = analyze_host_with(&host, &CveDb::builtin());
    assert_eq!(
        with.iter().map(|f| &f.id).collect::<Vec<_>>(),
        without.iter().map(|f| &f.id).collect::<Vec<_>>(),
        "NVD has the same two CVEs: the built-in findings are kept, none are added"
    );
    for id in ["cve-cve-2024-6387", "cve-cve-2021-41773"] {
        assert_eq!(with.iter().filter(|f| f.id == id).count(), 1, "{id}");
    }
}

#[test]
fn script_findings_need_the_script_key() {
    let hit = host_of(&spec(&[], &[], &[("finding.script.lab", "high|Lab|x")]));
    assert!(
        analyze_host_with(&hit, &CveDb::builtin())
            .iter()
            .any(|f| f.id == "script-lab")
    );
    let miss = host_of(&spec(
        &[],
        &[],
        &[("script.lab", "high|Lab|x"), ("finding.lab", "high|Lab|x")],
    ));
    assert!(analyze_host_with(&miss, &CveDb::builtin()).is_empty());
}

#[test]
fn control_traffic_needs_a_write_or_stop() {
    use crate::passive::Observation;
    let obs = |protocol: &str, traffic: Option<&str>| Observation {
        protocol: protocol.into(),
        mac: String::new(),
        ip: Some("10.0.0.9".parse().unwrap()),
        fields: traffic
            .map(|t| [("control_traffic".to_string(), t.to_string())].into())
            .unwrap_or_default(),
    };
    let found = |o: Observation| crate::otpassive::control_findings(&[o]);
    let hit = found(obs(
        "Modbus server (observed)",
        Some("Write Single Register"),
    ));
    assert_eq!(hit.len(), 1);
    assert_eq!(hit[0].0, Severity::Medium);
    let stop = found(obs("S7 server (observed)", Some("CPU Stop")));
    assert_eq!(stop[0].0, Severity::High);
    // No control traffic recorded, or an observation of something other than a server.
    assert!(found(obs("Modbus server (observed)", None)).is_empty());
    assert!(
        found(obs(
            "Modbus client (observed)",
            Some("Write Single Register")
        ))
        .is_empty()
    );
}

/// The false-alarm budget: over every near-miss host, no rule may raise its own finding.
/// Printed with `cargo test false_alarm -- --nocapture`.
#[test]
fn false_alarm_budget_is_zero_for_every_rule() {
    let mut report = vec![];
    for case in cases().iter().filter(|c| !SNAPSHOT_ONLY.contains(&c.id)) {
        let n = ids_of(&case.miss).iter().filter(|i| *i == case.id).count();
        report.push(format!("{:<28} near-miss false alarms: {n}", case.id));
        assert_eq!(n, 0, "{}", case.id);
    }
    println!("{}", report.join("\n"));
}

#[test]
fn every_rule_has_a_confidence_and_findings_explain_themselves() {
    let (ids, _) = source_rule_ids();
    for id in &ids {
        let c =
            rule_confidence(id).unwrap_or_else(|| panic!("{id} has no entry in rule_confidence"));
        assert!((1..=100).contains(&c), "{id}: {c}");
    }
    assert_eq!(rule_confidence("cve-cve-2024-6387"), Some(40));
    assert_eq!(rule_confidence("script-lab"), Some(60));
    assert_eq!(rule_confidence("no-such-rule"), None);
    // Direct observations outrank port-number guesses, and version hints rank lowest.
    assert!(rule_confidence("tls-weak-key") > rule_confidence("ot-reachable"));
    assert!(rule_confidence("ot-reachable") > rule_confidence("cve-cve-2011-2523"));

    let case = cases().into_iter().find(|c| c.id == "telnet-open").unwrap();
    let found = analyze_host_with(&host_of(&case.hit), &CveDb::builtin());
    let f = found.iter().find(|f| f.id == "telnet-open").unwrap();
    assert_eq!(f.confidence, 90);
    let why = f.explain();
    assert_eq!(why.confidence, 90);
    assert_eq!(why.reasons, ["telnet", "observed directly"]);
    // The score is in the JSON; an export from before the score existed loads with 0 and
    // writes no key.
    let json = serde_json::to_value(f).unwrap();
    assert_eq!(json["confidence"], 90);
    let old = r#"{"severity":"high","id":"telnet-open","title":"t","ip":"10.0.0.5","port":23,"evidence":"telnet","cve":[],"advice":"a"}"#;
    let loaded: Finding = serde_json::from_str(old).unwrap();
    assert_eq!(loaded.confidence, 0);
    assert!(
        serde_json::to_value(&loaded)
            .unwrap()
            .get("confidence")
            .is_none()
    );
    assert_eq!(loaded.explain().reasons, ["telnet"]);
}
