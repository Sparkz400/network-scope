// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
use super::*;
use crate::risk::Severity;

/// A CSAF VEX document: one CVE, the vulnerable code is not in the S7-1200 firmware V4.x, and
/// the S7-1500 below V3.1 is affected (V3.1 fixes it).
const CSAF_VEX: &str = r#"{
  "document": { "category": "csaf_vex", "csaf_version": "2.0", "title": "VEX",
    "tracking": { "id": "VEX-TEST-0001" } },
  "product_tree": { "branches": [ { "category": "vendor", "name": "Siemens", "branches": [
    { "category": "product_name", "name": "SIMATIC S7-1200 CPU", "branches": [
      { "category": "product_version_range", "name": ">=V4.0|<V5.0",
        "product": { "product_id": "S12", "name": "SIMATIC S7-1200 CPU V4" } } ] },
    { "category": "product_name", "name": "SIMATIC S7-1500 CPU", "branches": [
      { "category": "product_version_range", "name": "<V3.1",
        "product": { "product_id": "S15old", "name": "SIMATIC S7-1500 CPU < V3.1" } },
      { "category": "product_version", "name": "V3.1",
        "product": { "product_id": "S15new", "name": "SIMATIC S7-1500 CPU V3.1" } } ] } ] } ] },
  "vulnerabilities": [ {
    "cve": "CVE-2099-1000",
    "product_status": {
      "known_not_affected": ["S12"], "known_affected": ["S15old"], "fixed": ["S15new"] },
    "flags": [ { "label": "vulnerable_code_not_present", "product_ids": ["S12"] } ],
    "threats": [ { "category": "impact", "details": "The OpenSSL in this firmware is built without SM2.",
      "product_ids": ["S12"] } ],
    "remediations": [ { "category": "vendor_fix", "details": "Update to V3.1",
      "product_ids": ["S15old"] } ]
  } ]
}"#;

/// A CycloneDX VEX: the LabSwitch 2.4.1 is not affected by a CVE (code not reachable); per
/// version, 2.3.0 is affected.
const CYCLONEDX_VEX: &str = r#"{
  "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
  "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000001",
  "components": [ { "bom-ref": "sw", "type": "firmware", "name": "LabSwitch 24",
    "version": "2.4.1", "manufacturer": { "name": "Lab Networks" } } ],
  "vulnerabilities": [
    { "id": "CVE-2099-2000",
      "analysis": { "state": "not_affected", "justification": "code_not_reachable",
        "detail": "The web server is not compiled in." },
      "affects": [ { "ref": "sw" } ] },
    { "id": "CVE-2099-2001",
      "analysis": { "state": "not_affected" },
      "affects": [ { "ref": "urn:cdx:00000000-0000-4000-8000-000000000001/1#sw",
        "versions": [ { "version": "2.4.1", "status": "unaffected" },
                      { "version": "2.3.0", "status": "affected" } ] } ] },
    { "id": "not-a-cve", "analysis": { "state": "not_affected" }, "affects": [ { "ref": "sw" } ] }
  ]
}"#;

fn library(files: &[(&str, &str)]) -> Library {
    let mut l = Library::default();
    for (name, text) in files {
        l.merge(parse(text.as_bytes(), name).unwrap(), name)
            .unwrap();
    }
    l
}

fn names(n: &[&str]) -> Vec<String> {
    n.iter().map(|s| s.to_string()).collect()
}

#[test]
fn csaf_vex_statuses_become_statements_with_their_reason() {
    let l = library(&[("vex.json", CSAF_VEX)]);
    let cpu = names(&["6ES7 214-1AG40-0XB0", "CPU 1214C DC/DC/DC"]);
    let s = l
        .lookup("CVE-2099-1000", "Siemens", &cpu, "V4.2.1")
        .unwrap();
    assert_eq!(s.state, State::NotAffected);
    assert_eq!(s.justification, "vulnerable_code_not_present");
    assert!(s.detail.contains("without SM2"));
    assert_eq!(s.source, "VEX-TEST-0001");
    // Outside the range: no statement.
    assert!(l.lookup("CVE-2099-1000", "Siemens", &cpu, "5.1").is_none());
    // The S7-1500: affected below V3.1, fixed at V3.1.
    let s1500 = names(&["CPU 1511-1 PN"]);
    assert_eq!(
        l.lookup("CVE-2099-1000", "Siemens", &s1500, "3.0.2")
            .unwrap()
            .state,
        State::Affected
    );
    assert_eq!(
        l.lookup("CVE-2099-1000", "Siemens", &s1500, "V3.1")
            .unwrap()
            .state,
        State::Fixed
    );
    // Another vendor or another CVE: nothing.
    assert!(
        l.lookup("CVE-2099-1000", "Rockwell", &cpu, "4.2.1")
            .is_none()
    );
    assert!(
        l.lookup("CVE-2099-9999", "Siemens", &cpu, "4.2.1")
            .is_none()
    );
}

#[test]
fn cyclonedx_vex_analysis_and_per_version_status_are_read() {
    let l = library(&[("switch.vex.json", CYCLONEDX_VEX)]);
    let sw = names(&["LabSwitch 24"]);
    let s = l
        .lookup("CVE-2099-2000", "Lab Networks", &sw, "2.4.1")
        .unwrap();
    assert_eq!(
        (s.state, s.justification.as_str()),
        (State::NotAffected, "code_not_reachable")
    );
    assert!(
        l.lookup("CVE-2099-2000", "", &sw, "2.4.2").is_none(),
        "only the stated version"
    );
    // A BOM-Link reference into the same document, with a status per version.
    assert_eq!(
        l.lookup("CVE-2099-2001", "Lab Networks", &sw, "2.4.1")
            .unwrap()
            .state,
        State::NotAffected
    );
    assert_eq!(
        l.lookup("CVE-2099-2001", "Lab Networks", &sw, "2.3.0")
            .unwrap()
            .state,
        State::Affected
    );
    // An id that is no CVE is not a statement.
    assert_eq!(l.statements.len(), 3);
}

#[test]
fn a_statement_with_a_version_range_wins_over_one_for_all_versions() {
    // Two statements that add information (neither clears the finding): the one with a range wins.
    let mut l = library(&[("vex.json", CSAF_VEX)]);
    let mut all = l.statements[0].clone();
    all.range = "*".into();
    all.state = State::UnderInvestigation;
    all.source = "OTHER".into();
    let mut ranged = l.statements[0].clone();
    ranged.state = State::Affected;
    l.statements = vec![all, ranged];
    let cpu = names(&["CPU 1214C"]);
    assert_eq!(
        l.lookup("CVE-2099-1000", "Siemens", &cpu, "4.2.1")
            .unwrap()
            .state,
        State::Affected
    );
}

fn host() -> Host {
    Host {
        ip: "10.0.0.5".parse().unwrap(),
        responding: true,
        ping: None,
        ttl: None,
        hostname: String::new(),
        mac: String::new(),
        open: vec![102],
        closed: 0,
        unanswered: 0,
        errors: vec![],
        ports_checked: true,
        identity: [
            ("S7.order_code", "6ES7 214-1AG40-0XB0"),
            ("S7.cpu_type", "CPU 1214C DC/DC/DC"),
            ("S7.firmware", "V4.2.1"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect(),
        udp_open: vec![],
        trace: vec![],
    }
}

fn finding(cve: &str) -> Finding {
    Finding {
        severity: Severity::Critical,
        id: format!("cve-{}", cve.to_ascii_lowercase()),
        title: "t".into(),
        ip: "10.0.0.5".parse().unwrap(),
        port: Some(102),
        evidence: "e".into(),
        cve: vec![cve.into()],
        advice: "a".into(),
        exploit: Default::default(),
        reference: None,
        confidence: 40,
        vex: None,
    }
}

#[test]
fn a_covered_finding_is_marked_and_no_longer_counts_in_the_score() {
    let l = library(&[("vex.json", CSAF_VEX)]);
    let mut findings = vec![finding("CVE-2099-1000"), finding("CVE-2099-3000")];
    let before = crate::score::finding_points(&findings[0]);
    assert!(before > 0.0);
    apply_with(&l, &mut findings, &[host()]);
    let v = findings[0].vex.as_ref().expect("statement applied");
    assert_eq!(v.state, State::NotAffected);
    assert_eq!(crate::score::finding_points(&findings[0]), 0.0);
    assert!(findings[1].vex.is_none(), "a CVE without a statement");
    // In the JSON only when there is a statement.
    let json = serde_json::to_value(&findings).unwrap();
    assert_eq!(json[0]["vex"]["state"], "not_affected");
    assert!(json[1].get("vex").is_none());
    // An affected statement keeps the score.
    let mut affected = finding("CVE-2099-1000");
    let s1500 = Host {
        identity: [("S7.cpu_type", "CPU 1511-1 PN"), ("S7.firmware", "V3.0.2")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        ..host()
    };
    apply_with(&l, std::slice::from_mut(&mut affected), &[s1500]);
    assert_eq!(affected.vex.as_ref().unwrap().state, State::Affected);
    assert!(crate::score::finding_points(&affected) > 0.0);
}

#[test]
fn broken_input_is_rejected() {
    assert!(parse(b"\xff\xfe", "x").is_err());
    assert!(parse(&CSAF_VEX.as_bytes()[..300], "x").is_err());
    assert!(parse(br#"{"a":1}"#, "x").unwrap_err().contains("neither"));
    // A CycloneDX document without vulnerabilities, and one whose refs resolve to nothing.
    assert!(parse(br#"{"bomFormat":"CycloneDX","components":[]}"#, "x").is_err());
    let dangling = r#"{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-2099-0001",
        "analysis":{"state":"not_affected"},"affects":[{"ref":"nowhere"}]}]}"#;
    assert!(
        parse(dangling.as_bytes(), "x")
            .unwrap_err()
            .contains("no statement")
    );
}

#[test]
fn import_writes_the_cache_and_a_second_import_replaces_the_same_document() {
    let dir = std::env::temp_dir().join(format!("ns-vex-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a.json"), CSAF_VEX).unwrap();
    std::fs::write(dir.join("b.json"), CYCLONEDX_VEX).unwrap();
    std::fs::write(dir.join("c.json"), "{}").unwrap();
    let cache = dir.join("vex.json");
    let r = import(std::slice::from_ref(&dir), &cache, 5).unwrap();
    assert_eq!((r.files, r.rejected.len()), (2, 1));
    let first = Library::load(&cache).unwrap().statements.len();
    import(&[dir.join("a.json")], &cache, 6).unwrap();
    assert_eq!(
        Library::load(&cache).unwrap().statements.len(),
        first,
        "replaced, not doubled"
    );
    assert_eq!(
        status(&Library::load(&cache).unwrap(), &cache)["by_state"]["not affected"],
        3
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// What stands at the cache path decides what an import may do with it: only a cache of this
/// version is added to, one of an older version starts over, and anything else is left alone.
#[test]
fn an_import_never_writes_over_a_file_it_could_not_load() {
    let dir = std::env::temp_dir().join(format!("ns-vex-guard-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (input, cache) = (dir.join("in").join("a.json"), dir.join("vex.json"));
    std::fs::create_dir_all(input.parent().unwrap()).unwrap();
    std::fs::write(&input, CSAF_VEX).unwrap();
    let newer = format!(
        r#"{{"version":{},"imported_at":1,"statements":[]}}"#,
        CACHE_VERSION + 1
    );
    // A vendor's document where the cache should be (`--vex vendor.json`), a damaged file and
    // a cache from a newer version of the program.
    for (case, content) in [
        ("CycloneDX", CYCLONEDX_VEX),
        ("CSAF", CSAF_VEX),
        ("damaged", r#"{"version":2,"imported_at":1,"statem"#),
        ("empty", ""),
        ("newer", newer.as_str()),
    ] {
        std::fs::write(&cache, content).unwrap();
        let e = import(std::slice::from_ref(&input), &cache, 5).unwrap_err();
        assert!(e.contains("the file is unchanged"), "{case}: {e}");
        assert_eq!(std::fs::read_to_string(&cache).unwrap(), content, "{case}");
    }
    // A cache an older version wrote, also one with entries this version cannot read: the
    // import starts over.
    for old in [
        r#"{"version":1,"imported_at":1,"statements":[]}"#,
        r#"{"version":1,"imported_at":1,"statements":[{"shape":"of version 1"}]}"#,
    ] {
        std::fs::write(&cache, old).unwrap();
        assert!(
            Library::load(&cache)
                .unwrap_err()
                .contains("import the VEX files again")
        );
        let report = import(std::slice::from_ref(&input), &cache, 5).unwrap();
        let library = Library::load(&cache).unwrap();
        assert_eq!(library.version, CACHE_VERSION);
        assert_eq!(library.statements.len(), report.statements, "{old}");
    }
    // A cache this version could not load again is not written.
    assert!(check_size(MAX_CACHE_BYTES as usize, &cache).is_ok());
    let e = check_size(MAX_CACHE_BYTES as usize + 1, &cache).unwrap_err();
    assert!(e.contains("nothing was written"), "{e}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_clearing_statement_must_be_exact_and_affected_wins() {
    let statement = |vendor: &str, product: &str, range: &str, state: State| Statement {
        cve: "CVE-2099-4000".into(),
        vendor: vendor.into(),
        products: vec![product.into()],
        specific: vec![],
        range: range.into(),
        state,
        justification: String::new(),
        detail: String::new(),
        source: "T".into(),
        purl: String::new(),
    };
    let lib = |list: Vec<Statement>| Library {
        version: 1,
        imported_at: 0,
        sources: vec![],
        statements: list,
    };
    // A distribution's "openssh not affected" for all versions, without a vendor: it must not
    // clear the OpenSSH finding of every host (services have no vendor).
    let distro = lib(vec![statement("", "OpenSSH", "*", State::NotAffected)]);
    assert!(
        distro
            .lookup("CVE-2099-4000", "", &names(&["OpenSSH"]), "7.4")
            .is_none()
    );
    // A statement for a more specific model does not clear a sibling model of the family.
    let model = lib(vec![statement(
        "Siemens",
        "S7-1200 CPU 1217C",
        ">=4.0|<5.0",
        State::NotAffected,
    )]);
    let cpu = names(&["CPU 1214C DC/DC/DC"]);
    assert!(
        model
            .lookup("CVE-2099-4000", "Siemens", &cpu, "4.2.1")
            .is_none()
    );
    // The family name, or the device's own name, does.
    let family = lib(vec![statement(
        "Siemens",
        "S7-1200",
        ">=4.0|<5.0",
        State::NotAffected,
    )]);
    assert!(
        family
            .lookup("CVE-2099-4000", "Siemens", &cpu, "4.2.1")
            .is_some()
    );
    // An affected statement still attaches with the loose rule, and wins over a clearing one.
    let both = lib(vec![
        statement("Siemens", "S7-1200", ">=4.0|<5.0", State::NotAffected),
        statement("Siemens", "S7-1200 CPU 1214C", "*", State::Affected),
    ]);
    assert_eq!(
        both.lookup("CVE-2099-4000", "Siemens", &cpu, "4.2.1")
            .unwrap()
            .state,
        State::Affected
    );
}

#[test]
fn package_urls_are_read_and_match_sbom_components() {
    assert_eq!(
        purl_parts("pkg:npm/%40angular/core@16.2.0?arch=x#src"),
        Some(("pkg:npm/@angular/core".into(), "16.2.0".into()))
    );
    assert_eq!(
        purl_parts("pkg:Maven/Org.Example/Lib"),
        Some(("pkg:maven/org.example/lib".into(), String::new()))
    );
    assert_eq!(purl_parts("cpe:2.3:a:x:y"), None);
    assert_eq!(purl_parts("pkg:nameonly"), None);
    // A VEX whose refs point into another BOM by package URL; one component of this document
    // carries its own package URL.
    let doc = r#"{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:1",
      "components":[{"bom-ref":"c1","name":"zlib","version":"1.2.11","purl":"pkg:generic/zlib@1.2.11"}],
      "vulnerabilities":[
        {"id":"CVE-2099-5000","analysis":{"state":"not_affected","justification":"code_not_reachable"},
         "affects":[{"ref":"urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.10.0?type=jar"}]},
        {"id":"CVE-2099-5001","analysis":{"state":"not_affected"},
         "affects":[{"ref":"c1"}]},
        {"id":"CVE-2099-5002","analysis":{"state":"exploitable"},
         "affects":[{"ref":"other#pkg:deb/debian/openssl","versions":[{"range":"vers:deb/>=3.0.0|<3.0.11","status":"affected"}]}]}]}"#;
    let list = parse(doc.as_bytes(), "x.json").unwrap();
    assert_eq!(list.len(), 3, "{list:?}");
    assert_eq!(
        list[0].purl,
        "pkg:maven/com.fasterxml.jackson.core/jackson-databind"
    );
    assert_eq!(list[0].products, vec!["jackson-databind".to_string()]);
    assert_eq!(list[0].range, "=2.10.0");
    assert_eq!(list[1].purl, "pkg:generic/zlib");
    let lib = Library {
        version: 1,
        imported_at: 0,
        sources: vec![],
        statements: list,
    };
    let jackson = "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.10.0";
    assert_eq!(
        lib.lookup_purl("CVE-2099-5000", jackson, "").unwrap().state,
        State::NotAffected
    );
    // Another version, another package, another CVE: nothing.
    assert!(
        lib.lookup_purl(
            "CVE-2099-5000",
            "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.11.0",
            ""
        )
        .is_none()
    );
    assert!(
        lib.lookup_purl(
            "CVE-2099-5000",
            "pkg:maven/other/jackson-databind@2.10.0",
            ""
        )
        .is_none()
    );
    assert!(lib.lookup_purl("CVE-2099-5001", jackson, "").is_none());
    // Without a version in the package URL, the component's version counts.
    assert!(
        lib.lookup_purl("CVE-2099-5001", "pkg:generic/zlib", "1.2.11")
            .is_some()
    );
    // A vers range.
    let ssl = lib
        .lookup_purl("CVE-2099-5002", "pkg:deb/debian/openssl@3.0.2", "")
        .unwrap();
    assert_eq!(ssl.state, State::Affected);
    assert!(
        lib.lookup_purl("CVE-2099-5002", "pkg:deb/debian/openssl@3.0.11", "")
            .is_none()
    );
}

/// A CSAF VEX document that says product `P` of `tree` is not affected by CVE-2099-4100.
fn not_affected(tree: &str) -> Library {
    let text = format!(
        r#"{{"document":{{"category":"csaf_vex","csaf_version":"2.0","title":"T",
            "tracking":{{"id":"VEX-TREE"}}}},"product_tree":{{{tree}}},
            "vulnerabilities":[{{"cve":"CVE-2099-4100",
            "product_status":{{"known_not_affected":["P"]}}}}]}}"#
    );
    library(&[("tree.json", &text)])
}

/// A statement for one model must not clear its siblings through the family name above it in
/// the product tree, however the tree spells the model: as a `product_name` branch, in the
/// product's own name, in a flat list, or as the platform of a relationship.
#[test]
fn a_statement_for_one_model_does_not_clear_the_rest_of_its_family() {
    let cleared = |lib: &Library, vendor: &str, device: &str, version: &str| {
        lib.lookup("CVE-2099-4100", vendor, &names(&[device]), version)
            .is_some_and(|s| s.state.resolves())
    };
    let (other, same) = ("CPU 1214C DC/DC/DC", "CPU 1217C DC/DC/DC");
    let range = r#"{"category":"product_version_range","name":">=V4.0|<V5.0","product":"#;
    let siemens = |inner: &str| {
        not_affected(&format!(
            r#""branches":[{{"category":"vendor","name":"Siemens","branches":[{inner}]}}]"#
        ))
    };
    // Family, then model, then versions.
    let branch = siemens(&format!(
        r#"{{"category":"product_family","name":"SIMATIC S7-1200","branches":[
            {{"category":"product_name","name":"CPU 1217C DC/DC/DC","branches":[
            {range}{{"product_id":"P","name":"SIMATIC S7-1200 CPU 1217C DC/DC/DC V4"}}}}]}}]}}"#
    ));
    assert!(!cleared(&branch, "Siemens", other, "4.2.1"));
    assert!(cleared(&branch, "Siemens", same, "4.2.1"));
    assert!(
        !cleared(&branch, "Siemens", same, "5.0"),
        "outside the range"
    );
    // The model only in the product's own name, directly under the family.
    let leaf = siemens(&format!(
        r#"{{"category":"product_family","name":"SIMATIC S7-1200","branches":[
            {range}{{"product_id":"P","name":"Siemens SIMATIC S7-1200 CPU 1217C DC/DC/DC"}}}}]}}"#
    ));
    assert!(!cleared(&leaf, "Siemens", other, "4.2.1"));
    assert!(cleared(&leaf, "Siemens", same, "4.2.1"));
    // A statement for the family itself still covers every CPU of it.
    let family = siemens(&format!(
        r#"{{"category":"product_family","name":"SIMATIC S7-1200","branches":[
            {range}{{"product_id":"P","name":"SIMATIC S7-1200 CPU family V4"}}}}]}}"#
    ));
    assert!(cleared(&family, "Siemens", other, "4.2.1"));
    assert!(cleared(&family, "Siemens", same, "4.2.1"));
    // A flat product list: vendor, model and versions in one name.
    let flat = not_affected(
        r#""full_product_names":[{"product_id":"P",
            "name":"Siemens SIMATIC S7-1200 CPU 1217C DC/DC/DC: >=V4.0|<V5.0"}]"#,
    );
    assert!(!cleared(&flat, "Siemens", other, "4.2.1"));
    assert!(cleared(&flat, "Siemens", same, "4.2.1"));
    // A relationship: the firmware (named after the family) installed on one controller. The
    // platform's names decide, not the family name the component carries.
    let relationship = not_affected(
        r#""branches":[{"category":"vendor","name":"Rockwell Automation","branches":[
            {"category":"product_family","name":"ControlLogix","branches":[
              {"category":"product_name","name":"1756-L81E",
               "product":{"product_id":"HW","name":"ControlLogix 1756-L81E"}}]},
            {"category":"product_name","name":"ControlLogix firmware","branches":[
              {"category":"product_version_range","name":">=V33.0|<V34.0",
               "product":{"product_id":"FW","name":"ControlLogix firmware V33"}}]}]}],
          "relationships":[{"category":"installed_on","product_reference":"FW",
            "relates_to_product_reference":"HW",
            "full_product_name":{"product_id":"P","name":"ControlLogix firmware V33 on 1756-L81E"}}]"#,
    );
    let rockwell = "Rockwell Automation";
    assert!(!cleared(
        &relationship,
        rockwell,
        "1756-L83E/B ControlLogix",
        "33.11"
    ));
    assert!(cleared(
        &relationship,
        rockwell,
        "1756-L81E/B ControlLogix",
        "33.11"
    ));
}

/// Many statements and many findings: a finding is matched against the statements about its
/// CVEs, not against all of them (a cache may hold a million).
#[test]
fn a_lookup_reads_only_the_statements_about_its_cve() {
    let mut l = library(&[("vex.json", CSAF_VEX)]);
    let first = l.statements[0].clone();
    l.statements.extend((0..100_000).map(|i| Statement {
        cve: format!("CVE-2098-{i}"),
        ..first.clone()
    }));
    // Ids compare without case, and the statements of the file itself are still found.
    let mut findings: Vec<Finding> = (0..2_000)
        .map(|i| finding(&format!("cve-2098-{i}")))
        .chain([finding("CVE-2099-1000"), finding("CVE-2099-3000")])
        .collect();
    // 0.2 s here; walking every statement for every finding took 3 s.
    apply_with(&l, &mut findings, &[host()]);
    assert!(findings[..2_001].iter().all(|f| f.vex.is_some()));
    assert!(findings[2_001].vex.is_none(), "a CVE without a statement");
    // Not a matter of timing: only the positions the index names are looked at.
    let mut index = by_cve(&l);
    index.remove("CVE-2098-7");
    apply_indexed(&l, &index, &mut findings[..10], &[host()]);
    let marked: Vec<bool> = findings[5..10].iter().map(|f| f.vex.is_some()).collect();
    assert_eq!(marked, [true, true, false, true, true]);
    // The active cache gets its index when it is loaded.
    let cache = std::env::temp_dir().join(format!("ns-vex-index-{}.json", std::process::id()));
    let mut small = library(&[("vex.json", CSAF_VEX), ("b.json", CYCLONEDX_VEX)]);
    small.version = CACHE_VERSION;
    small.save(&cache).unwrap();
    let loaded = load_indexed(&cache).unwrap();
    std::fs::remove_file(&cache).unwrap();
    assert_eq!(loaded.by_cve["CVE-2099-1000"], [0, 1, 2]);
    assert_eq!(loaded.by_cve.len(), 3);
    let mut one = [finding("cve-2099-1000")];
    apply_indexed(&loaded.library, &loaded.by_cve, &mut one, &[host()]);
    assert_eq!(one[0].vex.as_ref().unwrap().state, State::NotAffected);
}

#[test]
fn every_state_has_a_cyclonedx_value_a_label_and_a_verdict() {
    let all = [
        (State::NotAffected, "not_affected", "not affected", true),
        (State::Fixed, "resolved", "fixed", true),
        (
            State::FalsePositive,
            "false_positive",
            "false positive",
            true,
        ),
        (State::Affected, "exploitable", "affected", false),
        (
            State::UnderInvestigation,
            "in_triage",
            "under investigation",
            false,
        ),
    ];
    for (state, cyclonedx, label, resolves) in all {
        assert_eq!(
            (state.cyclonedx(), state.label(), state.resolves()),
            (cyclonedx, label, resolves)
        );
    }
}

#[test]
fn an_import_skips_compressed_files_and_summarises_long_lists_of_skipped_ones() {
    let dir = std::env::temp_dir().join(format!("ns-vex-skipped-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let files = dir.join("in");
    std::fs::create_dir_all(&files).unwrap();
    let cache = dir.join("vex.json");
    assert!(
        import(&[], &cache, 1)
            .unwrap_err()
            .contains("Provide one or more")
    );
    // Nothing usable: nothing is written.
    std::fs::write(files.join("a.json"), [0x1f, 0x8b, 8, 0]).unwrap();
    let e = import(std::slice::from_ref(&files), &cache, 1).unwrap_err();
    assert!(
        e.contains("a.json: gzip-compressed, unpack it first"),
        "{e}"
    );
    assert!(!cache.exists());
    for i in 0..22 {
        std::fs::write(files.join(format!("n{i:02}.json")), "{}").unwrap();
    }
    std::fs::write(files.join("vex.json"), CSAF_VEX).unwrap();
    let r = import(std::slice::from_ref(&files), &cache, 2).unwrap();
    assert_eq!((r.files, r.rejected.len()), (1, 23));
    let lines = r.lines();
    assert_eq!(
        lines[0],
        format!("VEX: 1 files, {} statements", r.statements)
    );
    assert_eq!(
        lines.iter().filter(|l| l.starts_with("Skipped ")).count(),
        20
    );
    assert!(
        lines.contains(&"... and 3 more skipped files".to_string()),
        "{lines:?}"
    );
    assert!(
        lines
            .last()
            .unwrap()
            .starts_with(&format!("{} statements in the cache", r.total))
    );
    let _ = std::fs::remove_dir_all(&dir);
}
