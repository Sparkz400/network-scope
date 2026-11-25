// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
use super::*;
use crate::scan::Host;

fn host(ip: &str, vendor: &str, banners: &[(u16, &str)]) -> Host {
    let mut identity: std::collections::BTreeMap<String, String> = banners
        .iter()
        .flat_map(|(port, b)| {
            [
                (format!("banner.{port}"), (*b).to_string()),
                (format!("svc.{port}"), "unidentified".to_string()),
            ]
        })
        .collect();
    if !vendor.is_empty() {
        identity.insert("mac.vendor".into(), vendor.into());
    }
    Host {
        ip: ip.parse().unwrap(),
        responding: true,
        ping: None,
        ttl: None,
        hostname: "plant-gw.example.org".into(),
        mac: "00:11:22:33:44:55".into(),
        open: banners.iter().map(|(p, _)| *p).collect(),
        closed: 0,
        unanswered: 0,
        errors: vec![],
        ports_checked: true,
        identity,
        udp_open: vec![],
        trace: vec![],
    }
}

fn snapshot(hosts: Vec<Host>) -> Snapshot {
    Snapshot {
        targets: "10.0.0.0/24".into(),
        complete: true,
        settings: Default::default(),
        hosts,
        observations: vec![],
        notes: Default::default(),
        sent: vec![],
    }
}

/// The same product in three firmware versions on two ports, an unrelated device, a banner that
/// was identified later and a banner that names its host.
fn scans() -> Vec<Snapshot> {
    let first = snapshot(vec![
        host("10.0.0.1", "Acme Ltd", &[(9999, "ACME-GW 2.1 ready")]),
        host("10.0.0.2", "Acme Ltd", &[(9999, "ACME-GW 2.1 ready")]),
        host("10.0.0.3", "Acme Ltd", &[(9999, "ACME-GW 3.0.4 ready")]),
        host("10.0.0.4", "", &[(7000, "ACME-GW 3.0.4 ready")]),
        host("10.0.0.5", "", &[(9999, "ACME-GW 2.0 ready")]),
        host(
            "10.0.0.6",
            "Other",
            &[(2000, "PrintBox queue empty, 12 pages")],
        ),
    ]);
    // the first host again in a later scan (counts once), plus a banner that has an identified
    // service and one that carries the host's own address
    let mut identified = host("10.0.0.7", "", &[(9999, "ACME-GW 9.9 ready")]);
    identified
        .identity
        .insert("svc.9999".into(), "acme-gw".into());
    let second = snapshot(vec![
        host("10.0.0.1", "Acme Ltd", &[(9999, "ACME-GW 2.1 ready")]),
        identified,
        host(
            "10.0.0.8",
            "",
            &[(8888, "Hello 10.0.0.8 from PLANT-GW.example.org")],
        ),
    ]);
    vec![first, second]
}

#[test]
fn similar_banners_form_one_group_and_the_rest_stay_apart() {
    let g = groups(&scans());
    let acme = g
        .iter()
        .find(|g| g.template.starts_with("ACME-GW"))
        .unwrap();
    assert_eq!(acme.template, "ACME-GW ‹v› ready");
    assert_eq!((acme.hosts, acme.banners), (5, 3), "{acme:#?}");
    assert_eq!(acme.ports, [7000, 9999]);
    assert_eq!(acme.vendors, ["Acme Ltd"]);
    assert_eq!(acme.id.len(), 8);
    // most widespread variant first; the same banner on two ports is one variant
    assert_eq!(acme.variants[0].banner, "ACME-GW 2.1 ready");
    assert_eq!(
        acme.variants[0].hosts, 2,
        "the host seen in two scans counts once"
    );
    let v304 = acme
        .variants
        .iter()
        .find(|v| v.banner.contains("3.0.4"))
        .unwrap();
    assert_eq!((v304.ports.clone(), v304.hosts), (vec![7000, 9999], 2));
    assert_eq!(v304.versions, ["3.0.4"]);
    assert!(
        acme.variants.iter().all(|v| !v.banner.contains("9.9")),
        "an identified service is not unknown"
    );
    // the other device is a group of its own, and the host's own data is redacted
    assert!(
        g.iter()
            .any(|g| g.template.starts_with("PrintBox queue empty, ‹v› pages")),
        "{g:#?}"
    );
    assert!(
        g.iter().any(|g| g.template == "Hello <ip> from <host>"),
        "{g:#?}"
    );
    // deterministic, widest group first
    assert_eq!(g, groups(&scans()));
    assert_eq!(g[0].id, acme.id);
}

#[test]
fn what_varies_is_named_in_version_order() {
    let g = groups(&scans());
    let acme = g
        .iter()
        .find(|g| g.template.starts_with("ACME-GW"))
        .unwrap();
    assert_eq!(acme.varying, ["number 1 varies: 2.0, 2.1, 3.0.4"]);
    let text = compare_text(acme);
    assert!(text.contains("Differs: number 1 varies"), "{text}");
    assert!(
        text.contains("2 host(s)  ACME-GW 2.1 ready  versions: 2.1"),
        "{text}"
    );
    assert!(
        text.contains("MAC vendors of the hosts: Acme Ltd"),
        "{text}"
    );
    assert!(groups_text(&g).contains(&acme.id));
    assert!(groups_text(&[]).contains("No unidentified"));
}

#[test]
fn similarity_ignores_digits_and_rejects_unrelated_text() {
    assert_eq!(similarity("ACME-GW 2.1 ready", "acme-gw 7.9 READY"), 1.0);
    assert!(similarity("ACME-GW 2.1 ready", "ACME-GW 3.0.4 ready") >= THRESHOLD);
    assert!(similarity("ACME-GW 2.1 ready", "220 ProFTPD Server") < THRESHOLD);
    assert_eq!(similarity("", ""), 1.0);
    assert!(similarity("ab", "ab") == 1.0 && similarity("ab", "cd") == 0.0);
}

#[test]
fn groups_are_found_by_a_prefix_of_their_id() {
    let g = groups(&scans());
    let id = g[0].id.clone();
    assert_eq!(find(&g, &id).unwrap().id, id);
    assert_eq!(find(&g, &id[..6].to_uppercase()).unwrap().id, id);
    assert!(find(&g, "ab").unwrap_err().contains("at least 4"));
    assert!(find(&g, "zzzz").unwrap_err().contains("No group"));
    let twin = Group {
        id: format!("{}ffff", &id[..4]),
        ..g[0].clone()
    };
    let both = [g[0].clone(), twin];
    assert!(find(&both, &id[..4]).unwrap_err().contains("several"));
}

/// The rule drafted for a group matches every banner of the group, reads the version out of it
/// and passes the probe linter.
#[test]
fn the_draft_rule_matches_the_group_and_passes_the_linter() {
    let g = groups(&scans());
    let acme = g
        .iter()
        .find(|g| g.template.starts_with("ACME-GW"))
        .unwrap();
    let d = draft(acme).unwrap();
    assert_eq!(d.rule["re"], r"^ACME\-GW\s+([\d.]+)\s+ready");
    assert_eq!(d.rule["service"], "acme-gw");
    assert_eq!(d.rule["product"], "ACME-GW");
    assert_eq!(d.rule["version"], "$1");
    let re = regex::bytes::Regex::new(d.rule["re"].as_str().unwrap()).unwrap();
    for v in &acme.variants {
        // the raw reply has a line break the store dropped
        let raw = format!("{}\r\n", v.banner);
        let caps = re
            .captures(raw.as_bytes())
            .unwrap_or_else(|| panic!("{} did not match", v.banner));
        assert_eq!(
            std::str::from_utf8(&caps[1]).unwrap(),
            v.versions[0],
            "{}",
            v.banner
        );
    }
    assert!(!re.is_match(b"220 ProFTPD Server ready"));
    // the linter has no error, and the file loads as a user probe file
    let issues = crate::service::lint_probes(&d.probe_file).unwrap();
    assert_eq!(crate::service::lint_error_count(&issues), 0, "{issues:?}");
    let db = crate::service::ProbeDb::builtin()
        .merge_user(&d.probe_file, "draft")
        .unwrap();
    drop(db);
    assert!(d.probe_file.contains("\"name\": \"banner\""));
    assert!(d.notes.is_empty(), "{:?}", d.notes);
    assert!(d.checklist.iter().any(|c| c.contains("probes validate")));
    assert!(
        d.checklist
            .iter()
            .any(|c| c.contains("identifies a person"))
    );
    let md = checklist_markdown(&d, acme);
    assert!(
        md.contains("- [ ] Read the banners") && md.contains("ACME-GW 2.1 ready"),
        "{md}"
    );
}

#[test]
fn banners_of_different_shapes_get_a_rule_on_their_common_start() {
    let hosts = vec![
        host("10.0.1.1", "", &[(5555, "WidgetOS 1.2 login:")]),
        host("10.0.1.2", "", &[(5555, "WidgetOS 2.0 build 77 login:")]),
    ];
    let g = groups(&[snapshot(hosts)]);
    assert_eq!(g.len(), 1, "{g:#?}");
    assert!(
        g[0].varying[0].contains("different shapes"),
        "{:?}",
        g[0].varying
    );
    let d = draft(&g[0]).unwrap();
    assert_eq!(d.rule["re"], r"^WidgetOS\s+([\d.]+)");
    assert!(d.notes[0].contains("common start"), "{:?}", d.notes);
    let re = regex::bytes::Regex::new(d.rule["re"].as_str().unwrap()).unwrap();
    assert!(re.is_match(b"WidgetOS 1.2 login:") && re.is_match(b"WidgetOS 2.0 build 77 login:"));
    assert_eq!(
        crate::service::lint_error_count(&crate::service::lint_probes(&d.probe_file).unwrap()),
        0
    );
    // banners that already differ at the start give no rule: it would claim unrelated services
    let hosts = vec![
        host("10.0.2.1", "", &[(5555, "AB hello wide world")]),
        host("10.0.2.2", "", &[(5555, "AC hello wide world")]),
    ];
    let g = groups(&[snapshot(hosts)]);
    assert_eq!(g.len(), 1, "{g:#?}");
    let e = draft(&g[0]).unwrap_err();
    assert!(e.contains("differ too early"), "{e}");
}

#[test]
fn a_banner_without_a_number_gets_a_rule_without_a_version() {
    let g = groups(&[snapshot(vec![host(
        "10.0.3.1",
        "",
        &[(4000, "Welcome to the Frobnicator console")],
    )])]);
    let d = draft(&g[0]).unwrap();
    assert!(d.rule.get("version").is_none());
    assert_eq!(d.rule["re"], r"^Welcome\s+to\s+the\s+Frobnicator\s+console");
    assert_eq!(
        crate::service::lint_error_count(&crate::service::lint_probes(&d.probe_file).unwrap()),
        0
    );
}

#[test]
fn many_distinct_banners_are_bounded() {
    let hosts: Vec<Host> = (0..1700)
        .map(|i| {
            host(
                &format!("10.{}.{}.1", i / 250, i % 250),
                "",
                &[(6000, &format!("device-{i:04}-{}", "x".repeat(i % 40)))],
            )
        })
        .collect();
    let g = groups(&[snapshot(hosts)]);
    let banners: usize = g.iter().map(|g| g.banners).sum();
    assert!(banners <= MAX_BANNERS, "{banners}");
    assert!(g.iter().all(|g| g.variants.len() <= MAX_VARIANTS_LISTED));
}

#[test]
fn the_outputs_match_their_schema_files() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/schema");
    let check = |kind: &str, text: String| {
        let schema: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(dir.join(format!("{kind}.v1.schema.json"))).unwrap(),
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        crate::schema::validate(&schema, &value).unwrap_or_else(|e| {
            panic!(
                "{kind}: {e}
{text}"
            )
        });
    };
    let g = groups(&scans());
    check(
        "banner-groups",
        crate::schema::list("banner-groups", "groups", &g).unwrap(),
    );
    let acme = g
        .iter()
        .find(|g| g.template.starts_with("ACME-GW"))
        .unwrap();
    check(
        "fingerprint-draft",
        crate::schema::object("fingerprint-draft", &draft(acme).unwrap()).unwrap(),
    );
}
