use super::*;

/// A vendor SBOM of a PLC firmware, CycloneDX 1.5, with a nested component.
const CYCLONEDX: &str = r#"{
  "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
  "metadata": { "component": {
      "type": "firmware", "name": "S7-1200 CPU firmware", "version": "V4.2.1",
      "manufacturer": { "name": "Siemens AG" } } },
  "components": [
    { "type": "library", "name": "openssl", "version": "1.1.1k",
      "purl": "pkg:generic/openssl@1.1.1k",
      "cpe": "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*",
      "licenses": [ { "license": { "id": "OpenSSL" } } ],
      "components": [ { "type": "library", "name": "zlib", "version": "1.2.11" } ] },
    { "type": "operating-system", "name": "Linux kernel", "version": "4.19.0" },
    { "type": "unknown-kind", "name": "busybox", "version": "1.31.1",
      "supplier": { "name": "BusyBox project" } }
  ]
}"#;

/// What Syft writes for a firmware image: SPDX 2.3, the subject is the image file.
const SPDX: &str = r#"{
  "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "fw.bin",
  "documentDescribes": [ "SPDXRef-image" ],
  "packages": [
    { "SPDXID": "SPDXRef-image", "name": "fw.bin", "versionInfo": "NOASSERTION" },
    { "SPDXID": "SPDXRef-p1", "name": "dropbear", "versionInfo": "2019.78",
      "supplier": "Organization: Dropbear (dropbear@example.org)",
      "licenseConcluded": "MIT", "primaryPackagePurpose": "APPLICATION",
      "externalRefs": [
        { "referenceCategory": "SECURITY", "referenceType": "cpe23Type",
          "referenceLocator": "cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:2019.78:*:*:*:*:*:*:*" },
        { "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
          "referenceLocator": "pkg:generic/dropbear@2019.78" } ] },
    { "SPDXID": "SPDXRef-p2", "name": "uclibc", "versionInfo": "NOASSERTION",
      "licenseConcluded": "NOASSERTION" }
  ]
}"#;

fn subject(vendor: &str, product: &str, version: &str) -> Subject {
    let some = |s: &str| (!s.is_empty()).then(|| s.to_string());
    Subject {
        vendor: some(vendor),
        product: some(product),
        version: some(version),
    }
}

#[test]
fn cyclonedx_subject_and_components_are_read_including_nested_ones() {
    let s = parse(CYCLONEDX.as_bytes(), &Subject::default())
        .unwrap()
        .sbom;
    assert_eq!(s.format, "CycloneDX 1.5");
    assert_eq!(
        (s.vendor.as_str(), s.product.as_str(), s.version.as_str()),
        ("Siemens AG", "S7-1200 CPU firmware", "V4.2.1")
    );
    let names: Vec<&str> = s.components.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["openssl", "zlib", "Linux kernel", "busybox"]);
    let openssl = &s.components[0];
    assert_eq!(
        openssl.cpe,
        "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"
    );
    assert_eq!(openssl.licenses, ["OpenSSL"]);
    assert_eq!(s.components[2].kind, "operating-system");
    // An unknown type becomes a library; the supplier is kept.
    assert_eq!(s.components[3].kind, "library");
    assert_eq!(s.components[3].supplier, "BusyBox project");
}

#[test]
fn an_spdx_sbom_of_a_firmware_image_needs_the_product_and_version_from_the_import() {
    // The image file is the subject and has no version: rejected without the import's subject.
    let e = parse(SPDX.as_bytes(), &Subject::default()).unwrap_err();
    assert!(e.contains("--sbom-version"), "{e}");
    let s = parse(
        SPDX.as_bytes(),
        &subject("Lab Networks", "LabSwitch 24", "2.4.1"),
    )
    .unwrap()
    .sbom;
    assert_eq!(s.format, "SPDX-2.3");
    assert_eq!(s.product, "LabSwitch 24");
    assert!(
        s.aliases.is_empty(),
        "the image file name is no product name"
    );
    assert_eq!(
        s.components.len(),
        2,
        "the described image is not its own component"
    );
    let dropbear = &s.components[0];
    assert_eq!(dropbear.kind, "application");
    assert_eq!(dropbear.supplier, "Dropbear");
    assert_eq!(dropbear.purl, "pkg:generic/dropbear@2019.78");
    assert!(dropbear.cpe.starts_with("cpe:2.3:a:dropbear_ssh_project"));
    assert_eq!(dropbear.licenses, ["MIT"]);
    // NOASSERTION is no version and no license.
    assert_eq!(s.components[1].version, "");
    assert!(s.components[1].licenses.is_empty());
}

#[test]
fn matching_needs_the_same_version_a_matching_name_and_vendor() {
    let mut library = Library::default();
    library
        .merge(
            parse(CYCLONEDX.as_bytes(), &Subject::default())
                .unwrap()
                .sbom,
        )
        .unwrap();
    let names = |n: &[&str]| n.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    // The S7 identification names the CPU; its family is S7-1200.
    let cpu = names(&["6ES7 214-1AG40-0XB0", "CPU 1214C DC/DC/DC"]);
    assert!(
        library.find("Siemens", &cpu, "4.2.1").is_some(),
        "V4.2.1 is 4.2.1"
    );
    assert!(
        library.find("Siemens", &cpu, "4.2.2").is_none(),
        "another version"
    );
    assert!(
        library.find("Rockwell", &cpu, "4.2.1").is_none(),
        "another vendor"
    );
    assert!(library.find("", &cpu, "4.2.1").is_some(), "unknown vendor");
    assert!(
        library
            .find("Siemens", &names(&["CPU 1511-1 PN"]), "4.2.1")
            .is_none(),
        "S7-1500"
    );
    assert!(
        library.find("Siemens", &cpu, "").is_none(),
        "no version, no match"
    );
}

#[test]
fn a_second_import_of_the_same_product_version_replaces_the_first() {
    let mut library = Library::default();
    let s = parse(CYCLONEDX.as_bytes(), &Subject::default())
        .unwrap()
        .sbom;
    library.merge(s.clone()).unwrap();
    let mut newer = s;
    newer.components.truncate(1);
    library.merge(newer).unwrap();
    assert_eq!(library.sboms.len(), 1);
    assert_eq!(library.sboms[0].components.len(), 1);
}

#[test]
fn hostile_and_broken_input_is_rejected_or_bounded() {
    // Not JSON, truncated JSON, JSON that is no SBOM.
    assert!(parse(b"\x00\x01binary", &Subject::default()).is_err());
    assert!(parse(&CYCLONEDX.as_bytes()[..200], &Subject::default()).is_err());
    assert!(
        parse(br#"{"hello": "world"}"#, &Subject::default())
            .unwrap_err()
            .contains("neither")
    );
    // Nesting deeper than the JSON parser allows is an error, not a crash.
    let mut deep = String::from(r#"{"type":"library","name":"leaf"}"#);
    for i in 0..200 {
        deep = format!(r#"{{"type":"library","name":"n{i}","components":[{deep}]}}"#);
    }
    let doc = format!(r#"{{"bomFormat":"CycloneDX","components":[{deep}]}}"#);
    assert!(
        parse(doc.as_bytes(), &Subject::default())
            .unwrap_err()
            .contains("not JSON")
    );
    // Nesting the parser accepts stops at MAX_DEPTH.
    let mut deep = String::from(r#"{"type":"library","name":"leaf"}"#);
    for i in 0..40 {
        deep = format!(r#"{{"type":"library","name":"n{i}","components":[{deep}]}}"#);
    }
    let doc = format!(
        r#"{{"bomFormat":"CycloneDX","metadata":{{"component":{{"name":"Deep Device","version":"1.0"}}}},"components":[{deep}]}}"#
    );
    let s = parse(doc.as_bytes(), &Subject::default()).unwrap().sbom;
    assert_eq!(s.components.len(), MAX_DEPTH + 1);
    // More components than kept are counted, not stored.
    let many: Vec<String> = (0..MAX_COMPONENTS + 5)
        .map(|i| format!(r#"{{"type":"library","name":"c{i}"}}"#))
        .collect();
    let doc = format!(
        r#"{{"bomFormat":"CycloneDX","metadata":{{"component":{{"name":"Big Device","version":"1.0"}}}},"components":[{}]}}"#,
        many.join(",")
    );
    let s = parse(doc.as_bytes(), &Subject::default()).unwrap().sbom;
    assert_eq!(s.components.len(), MAX_COMPONENTS);
    assert_eq!(s.truncated, 5);
    // Device text is one line and bounded.
    let long = "x".repeat(10_000);
    let doc = format!(
        r#"{{"bomFormat":"CycloneDX","metadata":{{"component":{{"name":"A\nB {long}","version":"1.0"}}}}}}"#
    );
    let s = parse(doc.as_bytes(), &Subject::default()).unwrap().sbom;
    assert!(!s.product.contains('\n') && s.product.chars().count() <= MAX_TEXT);
}

#[test]
fn import_writes_the_cache_and_skips_files_that_are_not_sboms() {
    let dir = std::env::temp_dir().join(format!("ns-sbom-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("plc.cdx.json"), CYCLONEDX).unwrap();
    std::fs::write(dir.join("notes.json"), r#"{"a":1}"#).unwrap();
    let cache = dir.join("cache").join("sboms.json");
    let report = import(std::slice::from_ref(&dir), &Subject::default(), &cache, 7).unwrap();
    assert_eq!(report.imported.len(), 1);
    assert_eq!(report.rejected.len(), 1, "{:?}", report.rejected);
    let library = Library::load(&cache).unwrap();
    assert_eq!(library.sboms[0].source, "plc.cdx.json");
    assert!(library.sboms[0].sha256.starts_with("sha256:"));
    assert_eq!(library.imported_at, 7);
    assert_eq!(status(&library, &cache)["components"], 4);
    // The import's own product and version describe one file, not a folder of them.
    std::fs::write(dir.join("second.cdx.json"), CYCLONEDX).unwrap();
    let e = import(
        std::slice::from_ref(&dir),
        &subject("Siemens", "CPU 1214C", "4.2.1"),
        &cache,
        8,
    )
    .unwrap_err();
    assert!(e.contains("one by one"), "{e}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn the_sboms_of_the_firmware_a_host_reported_are_found() {
    let file = r#"{"bomFormat":"CycloneDX","specVersion":"1.6",
      "metadata":{"component":{"type":"firmware","name":"OpenWrt","version":"25.12.6",
        "manufacturer":{"name":"OpenWrt"}}},
      "components":[{"type":"library","name":"busybox","version":"1.37.0"}]}"#;
    let sbom = parse(file.as_bytes(), &Subject::default()).unwrap().sbom;
    let library = Library {
        version: 1,
        imported_at: 0,
        sboms: vec![sbom],
    };
    let host = |ip: &str, mac: &str| crate::scan::Host {
        ip: ip.parse().unwrap(),
        responding: true,
        ping: None,
        ttl: None,
        hostname: String::new(),
        mac: mac.into(),
        open: vec![],
        closed: 0,
        unanswered: 0,
        errors: vec![],
        ports_checked: true,
        identity: Default::default(),
        udp_open: vec![],
        trace: vec![],
    };
    let lldp = |version: &str| crate::passive::Observation {
        protocol: "LLDP".into(),
        mac: "AA:BB:CC:00:00:01".into(),
        ip: None,
        fields: [
            ("med_model", "OpenWrt"),
            ("med_manufacturer", "OpenWrt"),
            ("med_software_revision", version),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect(),
    };
    let hosts = [host("10.0.0.1", "aa:bb:cc:00:00:01"), host("10.0.0.2", "")];
    let found = for_hosts(&library, &hosts, &[lldp("25.12.6")]);
    assert_eq!(found.len(), 1);
    let f = &found[&"10.0.0.1".parse::<std::net::IpAddr>().unwrap()];
    assert_eq!(
        f,
        &[FirmwareSbom {
            source: "LLDP-MED".into(),
            name: "OpenWrt".into(),
            version: "25.12.6".into(),
            sbom: 0,
        }]
    );
    // Another version: none.
    assert!(for_hosts(&library, &hosts, &[lldp("24.10.0")]).is_empty());
}
