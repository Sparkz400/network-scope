// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
use super::*;
use crate::{
    passive::Observation,
    scan::{Host, Settings},
};

fn host(ip: &str, mac: &str, open: &[u16], id: &[(&str, &str)]) -> Host {
    Host {
        ip: ip.parse().unwrap(),
        responding: true,
        ping: None,
        ttl: None,
        hostname: String::new(),
        mac: mac.into(),
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

/// A PLC that reported its firmware over S7, a switch with an SSH banner and LLDP-MED, and a
/// host that reported nothing but an open port.
fn snapshot() -> Snapshot {
    let mut lldp = BTreeMap::new();
    for (k, v) in [
        ("med_model", "LabSwitch 24"),
        ("med_manufacturer", "Lab Networks"),
        ("med_firmware_revision", "2.4.1"),
        ("med_serial_number", "LS24-0001"),
    ] {
        lldp.insert(k.to_string(), v.to_string());
    }
    Snapshot {
        sent: vec![],
        targets: "10.0.0.0/24".into(),
        complete: true,
        settings: Settings::default(),
        hosts: vec![
            host(
                "10.0.0.5",
                "00:1B:1B:7C:22:05",
                &[102],
                &[
                    ("S7.order_code", "6ES7 214-1AG40-0XB0"),
                    ("S7.cpu_type", "CPU 1214C DC/DC/DC"),
                    ("S7.firmware", "V4.2.1"),
                    ("svc.102", "iso-tsap"),
                ],
            ),
            host(
                "10.0.0.1",
                "00:11:22:33:44:55",
                &[22, 23],
                &[
                    ("svc.22", "ssh"),
                    ("svc.22.product", "OpenSSH"),
                    ("svc.22.version", "7.4"),
                    ("svc.23", "telnet"),
                    ("snmp.sysdescr", "LabSwitch 24\u{0}\nfirmware 2.4.1"),
                ],
            ),
            host("10.0.0.9", "", &[80], &[("svc.80", "http")]),
        ],
        observations: vec![Observation {
            protocol: "LLDP".into(),
            mac: "00:11:22:33:44:55".into(),
            ip: None,
            fields: lldp,
        }],
        notes: Default::default(),
    }
}

fn finding(ip: &str, port: Option<u16>, id: &str, cve: &[&str], severity: Severity) -> Finding {
    Finding {
        severity,
        id: id.into(),
        title: format!("title of {id}"),
        ip: ip.parse().unwrap(),
        port,
        evidence: "evidence".into(),
        cve: cve.iter().map(|c| c.to_string()).collect(),
        advice: "advice".into(),
        exploit: Default::default(),
        reference: None,
        confidence: 40,
        vex: None,
    }
}

fn bom(s: &Snapshot, findings: &[Finding]) -> Value {
    bom_with(s, findings, &crate::sbom::Library::default())
}

/// The NVD feed of the tests: one CVE for the OpenSSL of the PLC's firmware SBOM.
fn nvd(cpe: &str) -> Vec<crate::nvd::Hit> {
    if cpe.contains(":openssl:openssl:1.1.1k:") {
        vec![crate::nvd::Hit {
            cve: "CVE-2021-3711".into(),
            severity: Severity::Critical,
            title: "SM2 decryption buffer overflow".into(),
            range: "1.1.1 <= v < 1.1.1l".into(),
        }]
    } else {
        vec![]
    }
}

fn bom_with(s: &Snapshot, findings: &[Finding], sboms: &crate::sbom::Library) -> Value {
    let devices = devices::merge(&s.hosts, &s.observations);
    let assets = otpassive::assets(&s.observations);
    build(&Input {
        snapshot: s,
        devices: &devices,
        assets: &assets,
        findings,
        cpe: &|p, v| {
            (p == "OpenSSH").then(|| format!("cpe:2.3:a:openbsd:openssh:{v}:*:*:*:*:*:*:*"))
        },
        sboms,
        vex: &crate::vex::Library::default(),
        enrich: &|_| {},
        nvd: &nvd,
        timestamp: 1_795_000_000,
    })
}

/// The vendor's SBOM of the PLC firmware the S7 identification reports (6ES7 214-1AG40, V4.2.1).
fn plc_sbom() -> crate::sbom::Library {
    let file = r#"{
      "bomFormat": "CycloneDX", "specVersion": "1.5",
      "metadata": { "component": { "type": "firmware", "name": "S7-1200 CPU firmware",
        "version": "V4.2.1", "manufacturer": { "name": "Siemens AG" } } },
      "components": [
        { "type": "library", "name": "openssl", "version": "1.1.1k",
          "purl": "pkg:generic/openssl@1.1.1k",
          "cpe": "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*",
          "licenses": [ { "license": { "id": "OpenSSL" } } ],
          "supplier": { "name": "OpenSSL Project" } },
        { "type": "operating-system", "name": "Linux kernel", "version": "4.19.0" }
      ]
    }"#;
    let mut sbom = crate::sbom::parse(file.as_bytes(), &Default::default())
        .unwrap()
        .sbom;
    sbom.source = "s7-1200-v4.2.1.cdx.json".into();
    sbom.sha256 = "sha256:00".into();
    crate::sbom::Library {
        version: 1,
        imported_at: 0,
        sboms: vec![sbom],
    }
}

/// Every component, nested ones included.
fn all_components(v: &Value) -> Vec<&Value> {
    let mut out = vec![];
    let mut stack: Vec<&Value> = v["components"].as_array().unwrap().iter().collect();
    while let Some(c) = stack.pop() {
        out.push(c);
        if let Some(children) = c["components"].as_array() {
            stack.extend(children);
        }
    }
    out
}

fn prop<'a>(c: &'a Value, name: &str) -> Vec<&'a str> {
    c["properties"]
        .as_array()
        .map(|ps| {
            ps.iter()
                .filter(|p| p["name"] == format!("network-scope:{name}"))
                .filter_map(|p| p["value"].as_str())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn the_header_is_cyclonedx_1_6_and_the_serial_number_is_stable() {
    let s = snapshot();
    let a = bom(&s, &[]);
    assert_eq!(a["bomFormat"], "CycloneDX");
    assert_eq!(a["specVersion"], "1.6");
    assert_eq!(a["version"], 1);
    let serial = a["serialNumber"].as_str().unwrap();
    // urn:uuid:xxxxxxxx-xxxx-5xxx-[89ab]xxx-xxxxxxxxxxxx, lowercase (the schema's pattern).
    let uuid = serial.strip_prefix("urn:uuid:").unwrap();
    let groups: Vec<&str> = uuid.split('-').collect();
    assert_eq!(
        groups.iter().map(|g| g.len()).collect::<Vec<_>>(),
        [8, 4, 4, 4, 12]
    );
    assert!(
        uuid.chars()
            .all(|c| c == '-' || c.is_ascii_digit() || ('a'..='f').contains(&c))
    );
    assert!(groups[2].starts_with('5'), "{serial}");
    assert!(matches!(&groups[3][..1], "8" | "9" | "a" | "b"), "{serial}");
    // The same scan gives the same document; another scan another serial number.
    assert_eq!(a, bom(&s, &[]));
    let mut other = s.clone();
    other.hosts.pop();
    assert_ne!(bom(&other, &[])["serialNumber"], a["serialNumber"]);
    assert_eq!(a["metadata"]["timestamp"], "2026-11-18T11:06:40Z");
    assert_eq!(
        a["metadata"]["tools"]["components"][0]["name"],
        "Network Scope"
    );
    assert_eq!(a["metadata"]["lifecycles"][0]["phase"], "operations");
}

#[test]
fn reported_firmware_and_service_versions_become_components_with_their_source() {
    let v = bom(&snapshot(), &[]);
    let all = all_components(&v);
    let devices: Vec<_> = all.iter().filter(|c| c["type"] == "device").collect();
    assert_eq!(devices.len(), 3, "one per device");

    let plc = all
        .iter()
        .find(|c| c["type"] == "firmware" && c["name"] == "6ES7 214-1AG40-0XB0")
        .expect("S7 firmware");
    assert_eq!(plc["version"], "V4.2.1");
    assert_eq!(plc["manufacturer"]["name"], "Siemens");
    assert_eq!(prop(plc, "source"), ["S7 identification"]);

    let lldp = all
        .iter()
        .find(|c| c["type"] == "firmware" && c["name"] == "LabSwitch 24")
        .expect("LLDP-MED firmware");
    assert_eq!(lldp["version"], "2.4.1");
    assert_eq!(lldp["manufacturer"]["name"], "Lab Networks");
    assert_eq!(prop(lldp, "source"), ["LLDP-MED firmware revision"]);

    let ssh = all
        .iter()
        .find(|c| c["type"] == "application")
        .expect("OpenSSH service");
    assert_eq!(ssh["name"], "OpenSSH");
    assert_eq!(ssh["version"], "7.4");
    assert_eq!(ssh["cpe"], "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:*");
    assert_eq!(prop(ssh, "port"), ["22"]);
    assert_eq!(prop(ssh, "source"), ["service banner"]);
    // Telnet and HTTP named no product: they stay open ports, not components.
    assert_eq!(all.iter().filter(|c| c["type"] == "application").count(), 1);

    let switch = devices
        .iter()
        .find(|c| prop(c, "address") == ["10.0.0.1"])
        .unwrap();
    assert_eq!(prop(switch, "serial-number"), ["LS24-0001"]);
    assert_eq!(prop(switch, "open-tcp-ports"), ["22,23"]);
    // Device text is flattened to one line.
    assert_eq!(
        prop(switch, "snmp-sysdescr"),
        ["LabSwitch 24  firmware 2.4.1"]
    );
    assert_eq!(switch["manufacturer"]["name"], "Lab Networks");
    assert_eq!(prop(switch, "manufacturer-source"), ["LLDP-MED"]);

    // A host that reported nothing is a device with its address and port, nothing more.
    let quiet = devices
        .iter()
        .find(|c| prop(c, "address") == ["10.0.0.9"])
        .unwrap();
    assert!(quiet.get("components").is_none());
    assert_eq!(quiet["name"], "10.0.0.9");
}

/// Findings shaped like the real rules: `cve-*` findings name the product they matched in their
/// evidence (the CVE table: "openssh 7.4. ..."; the NVD feed: the CPE; CISA advisories: the OT
/// identification), other rules carry a CVE for a probe or a setting (Heartbleed, SMBv1).
fn findings() -> Vec<Finding> {
    let mut v = vec![
        finding(
            "10.0.0.1",
            Some(22),
            "cve-cve-2023-38408",
            &["CVE-2023-38408"],
            Severity::High,
        ),
        // The same CVE from the NVD feed: one vulnerability, the higher severity.
        finding(
            "10.0.0.1",
            Some(22),
            "cve-cve-2023-38408",
            &["CVE-2023-38408"],
            Severity::Critical,
        ),
        // A CISA advisory for the PLC's firmware, found by its S7 identification.
        finding(
            "10.0.0.5",
            Some(102),
            "cve-cve-2022-38465",
            &["CVE-2022-38465"],
            Severity::Critical,
        ),
        // A CVE from a probe on the OpenSSH port that is not about OpenSSH's version.
        finding(
            "10.0.0.1",
            Some(22),
            "heartbleed",
            &["CVE-2014-0160"],
            Severity::High,
        ),
        // No port: the device itself.
        finding("10.0.0.9", None, "x", &["CVE-2021-0001"], Severity::Low),
        // Findings without a CVE are not vulnerabilities in the BOM.
        finding("10.0.0.1", Some(23), "telnet-open", &[], Severity::High),
    ];
    v[0].evidence = "openssh 7.4. Version-based hint".into();
    v[1].evidence = "cpe:2.3:a:openbsd:openssh:7.4:*:*:*:*:*:*:* in the NVD range < 9.3p2".into();
    v[2].evidence = "S7 on port 102, vendor Siemens, firmware V4.2.1".into();
    v[3].evidence = "the server answered a malformed heartbeat".into();
    v
}

#[test]
fn bom_refs_are_unique_and_every_vulnerability_points_at_one() {
    let v = bom(&snapshot(), &findings());
    let refs: Vec<&str> = all_components(&v)
        .iter()
        .filter_map(|c| c["bom-ref"].as_str())
        .collect();
    let unique: BTreeSet<&str> = refs.iter().copied().collect();
    assert_eq!(unique.len(), refs.len(), "duplicate bom-ref in {refs:?}");

    let vulns = v["vulnerabilities"].as_array().unwrap();
    assert_eq!(vulns.len(), 4);
    for vuln in vulns {
        for a in vuln["affects"].as_array().unwrap() {
            assert!(unique.contains(a["ref"].as_str().unwrap()), "{a}");
        }
        assert_eq!(vuln["ratings"][0]["method"], "other");
    }
    let by_id = |id: &str| vulns.iter().find(|v| v["id"] == id).unwrap();

    // Matched OpenSSH's version: the OpenSSH component.
    let ssh = by_id("CVE-2023-38408");
    assert_eq!(ssh["ratings"][0]["severity"], "critical");
    assert_eq!(
        ssh["affects"],
        json!([{ "ref": "service:10.0.0.1:22/tcp" }])
    );
    assert_eq!(prop(ssh, "found-on"), ["10.0.0.1:22"]);
    assert_eq!(
        ssh["source"]["url"],
        "https://nvd.nist.gov/vuln/detail/CVE-2023-38408"
    );
    // The advisory: the firmware the S7 identification reported.
    let plc = by_id("CVE-2022-38465");
    assert!(
        plc["affects"][0]["ref"]
            .as_str()
            .unwrap()
            .ends_with(":firmware:S7:102"),
        "{plc}"
    );
    // A probe on port 22 that is not about OpenSSH's version: the device, with the port.
    let heartbleed = by_id("CVE-2014-0160");
    let target = heartbleed["affects"][0]["ref"].as_str().unwrap();
    assert!(
        target.starts_with("device:") && !target.contains("service"),
        "{target}"
    );
    assert_eq!(prop(heartbleed, "found-on"), ["10.0.0.1:22"]);
    // No port: the device.
    let quiet = by_id("CVE-2021-0001");
    assert!(
        quiet["affects"][0]["ref"]
            .as_str()
            .unwrap()
            .starts_with("device:")
    );
}

#[test]
fn the_order_of_the_hosts_does_not_change_the_serial_number() {
    let s = snapshot();
    let mut reversed = s.clone();
    reversed.hosts.reverse();
    assert_eq!(
        bom(&s, &[])["serialNumber"],
        bom(&reversed, &[])["serialNumber"]
    );
}

#[test]
fn an_empty_scan_is_still_a_valid_document() {
    let mut s = snapshot();
    s.hosts.clear();
    s.observations.clear();
    let v = bom(&s, &[]);
    assert_eq!(v["components"], json!([]));
    assert!(v.get("vulnerabilities").is_none());
}

/// Writes the sample document (firmware from S7 and LLDP-MED, a service with a CPE, CVEs on a
/// service, a firmware and a device) to the file named by `CYCLONEDX_SAMPLE`, for the schema
/// check in CI (`cyclonedx validate`); does nothing without the variable.
#[test]
fn write_the_sample_for_the_schema_check() {
    let Some(path) = std::env::var_os("CYCLONEDX_SAMPLE") else {
        return;
    };
    // With a VEX statement on one finding, so the schema check sees an `analysis` too.
    let mut list = findings();
    list[3].vex = Some(not_affected());
    // And an LLDP link, so it sees `dependencies`.
    let mut s = snapshot();
    with_lldp_neighbours(&mut s);
    let text = serde_json::to_string_pretty(&bom_with(&s, &list, &plc_sbom())).unwrap();
    std::fs::write(path, text).unwrap();
}

#[test]
fn the_vendor_sbom_of_a_reported_firmware_is_nested_with_its_cves() {
    let v = bom_with(&snapshot(), &[], &plc_sbom());
    let all = all_components(&v);
    let firmware = all
        .iter()
        .find(|c| c["type"] == "firmware" && c["name"] == "6ES7 214-1AG40-0XB0")
        .unwrap();
    assert_eq!(prop(firmware, "sbom"), ["s7-1200-v4.2.1.cdx.json"]);
    assert_eq!(prop(firmware, "sbom-format"), ["CycloneDX 1.5"]);
    let inside = firmware["components"].as_array().unwrap();
    let names: Vec<&str> = inside.iter().filter_map(|c| c["name"].as_str()).collect();
    assert_eq!(names, ["openssl", "Linux kernel"]);
    let openssl = &inside[0];
    assert_eq!(openssl["version"], "1.1.1k");
    assert_eq!(openssl["purl"], "pkg:generic/openssl@1.1.1k");
    assert_eq!(openssl["supplier"]["name"], "OpenSSL Project");
    assert_eq!(openssl["licenses"][0]["license"]["name"], "OpenSSL");
    assert_eq!(prop(openssl, "source"), ["SBOM s7-1200-v4.2.1.cdx.json"]);
    assert_eq!(inside[1]["type"], "operating-system");

    // The NVD feed's CVE for the OpenSSL inside the firmware points at that library.
    let vulns = v["vulnerabilities"].as_array().unwrap();
    let cve = vulns.iter().find(|x| x["id"] == "CVE-2021-3711").unwrap();
    assert_eq!(cve["affects"][0]["ref"], openssl["bom-ref"]);
    assert_eq!(prop(cve, "rule"), ["sbom-cve-cve-2021-3711"]);
    assert_eq!(prop(cve, "found-on"), ["10.0.0.5"]);

    // Another firmware version: no SBOM, nothing nested.
    let mut other = snapshot();
    other.hosts[0]
        .identity
        .insert("S7.firmware".into(), "V4.3.0".into());
    let v = bom_with(&other, &[], &plc_sbom());
    let firmware = all_components(&v)
        .into_iter()
        .find(|c| c["type"] == "firmware" && c["name"] == "6ES7 214-1AG40-0XB0")
        .unwrap()
        .clone();
    assert!(firmware.get("components").is_none());
    assert!(prop(&firmware, "sbom").is_empty());
}

#[test]
fn two_devices_on_the_same_firmware_share_one_lookup_and_one_vulnerability() {
    let mut s = snapshot();
    let mut twin = s.hosts[0].clone();
    twin.ip = "10.0.0.6".parse().unwrap();
    twin.mac = "00:1B:1B:7C:22:06".into();
    s.hosts.push(twin);
    let lookups = std::cell::Cell::new(0);
    let counting = |cpe: &str| {
        lookups.set(lookups.get() + 1);
        nvd(cpe)
    };
    let devices = devices::merge(&s.hosts, &s.observations);
    let library = plc_sbom();
    let v = build(&Input {
        snapshot: &s,
        devices: &devices,
        assets: &[],
        findings: &[],
        cpe: &|_, _| None,
        sboms: &library,
        vex: &crate::vex::Library::default(),
        enrich: &|_| {},
        nvd: &counting,
        timestamp: 1_795_000_000,
    });
    assert_eq!(lookups.get(), 1, "one NVD lookup for the shared CPE");
    let cve = v["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == "CVE-2021-3711")
        .unwrap();
    assert_eq!(cve["affects"].as_array().unwrap().len(), 2, "{cve}");
    assert_eq!(prop(cve, "found-on"), ["10.0.0.5", "10.0.0.6"]);
    let scope = prop(&v["metadata"], "scope");
    assert!(
        scope[0].contains("1 imported SBOM(s) for 2 firmware component(s)"),
        "{scope:?}"
    );
    // Without a matching SBOM the document says so.
    let plain = bom(&snapshot(), &[]);
    assert!(prop(&plain["metadata"], "scope")[0].contains("none matched"));
}

fn not_affected() -> crate::vex::Applied {
    crate::vex::Applied {
        state: crate::vex::State::NotAffected,
        justification: "vulnerable_code_not_present".into(),
        detail: "Not compiled in.".into(),
        source: "VEX-TEST-0001".into(),
    }
}

#[test]
fn vex_statements_become_the_analysis_and_split_affected_from_not_affected_devices() {
    let mut s = snapshot();
    let mut twin = s.hosts[1].clone();
    twin.ip = "10.0.0.2".parse().unwrap();
    twin.mac = "00:11:22:33:44:56".into();
    s.hosts.push(twin);
    let mut on_one = finding(
        "10.0.0.1",
        Some(22),
        "heartbleed",
        &["CVE-2014-0160"],
        Severity::High,
    );
    on_one.vex = Some(not_affected());
    let on_other = finding(
        "10.0.0.2",
        Some(22),
        "heartbleed",
        &["CVE-2014-0160"],
        Severity::High,
    );
    let v = bom(&s, &[on_one, on_other]);
    let entries: Vec<&Value> = v["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|x| x["id"] == "CVE-2014-0160")
        .collect();
    assert_eq!(entries.len(), 2, "affected and not affected apart");
    let stated = entries
        .iter()
        .find(|e| e.get("analysis").is_some())
        .unwrap();
    assert_eq!(stated["analysis"]["state"], "not_affected");
    assert_eq!(stated["analysis"]["justification"], "code_not_present");
    assert!(
        stated["analysis"]["detail"]
            .as_str()
            .unwrap()
            .contains("VEX-TEST-0001")
    );
    assert_eq!(
        stated["bom-ref"],
        "vulnerability:CVE-2014-0160:not_affected"
    );
    let open = entries
        .iter()
        .find(|e| e.get("analysis").is_none())
        .unwrap();
    assert_eq!(open["bom-ref"], "vulnerability:CVE-2014-0160");
}

#[test]
fn a_vex_statement_for_the_firmware_covers_the_cve_of_a_library_inside_it() {
    let s = snapshot();
    let devices = devices::merge(&s.hosts, &s.observations);
    let library = plc_sbom();
    let vex_file = r#"{
      "document": { "category": "csaf_vex", "csaf_version": "2.0", "tracking": { "id": "VEX-PLC" } },
      "product_tree": { "branches": [ { "category": "vendor", "name": "Siemens", "branches": [
        { "category": "product_name", "name": "S7-1200 CPU firmware", "branches": [
          { "category": "product_version", "name": "V4.2.1",
            "product": { "product_id": "F", "name": "S7-1200 CPU firmware V4.2.1" } } ] } ] } ] },
      "vulnerabilities": [ { "cve": "CVE-2021-3711",
        "product_status": { "known_not_affected": ["F"] },
        "flags": [ { "label": "vulnerable_code_not_in_execute_path", "product_ids": ["F"] } ] } ]
    }"#;
    let mut vex = crate::vex::Library::default();
    vex.statements = crate::vex::parse(vex_file.as_bytes(), "plc.vex.json").unwrap();
    let v = build(&Input {
        snapshot: &s,
        devices: &devices,
        assets: &[],
        findings: &[],
        cpe: &|_, _| None,
        sboms: &library,
        vex: &vex,
        enrich: &|_| {},
        nvd: &nvd,
        timestamp: 1_795_000_000,
    });
    let cve = v["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == "CVE-2021-3711")
        .unwrap();
    assert_eq!(cve["analysis"]["state"], "not_affected");
    assert_eq!(cve["analysis"]["justification"], "code_not_reachable");
}

/// A one-request HTTP server: the raw request it received; answers 200 with a token like
/// Dependency-Track.
fn mock_server() -> (u16, std::thread::JoinHandle<String>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = s.read(&mut buf).unwrap_or(0);
            raw.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&raw).into_owned();
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let len = head
                    .lines()
                    .find_map(|l| l.strip_prefix("Content-Length: "))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if body.len() >= len {
                    break;
                }
            }
            if n == 0 {
                break;
            }
        }
        let reply = r#"{"token":"00000000-0000-0000-0000-000000000000"}"#;
        let _ = write!(
            s,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
            reply.len()
        );
        String::from_utf8_lossy(&raw).into_owned()
    });
    (port, handle)
}

#[test]
fn the_dependency_track_upload_is_a_multipart_post_with_the_key_in_a_header() {
    let bom = serde_json::to_string(&bom(&snapshot(), &[])).unwrap();
    let key = "odt_s3cr3tKey";
    let (port, server) = mock_server();
    push_dependency_track(
        &format!("http://127.0.0.1:{port}"),
        key,
        "Plant A",
        "10.0.0.0/24",
        &bom,
        std::time::Duration::from_secs(5),
    )
    .unwrap();
    let req = server.join().unwrap();
    let (head, body) = req.split_once("\r\n\r\n").unwrap();
    assert!(head.starts_with("POST /api/v1/bom HTTP/1.1\r\n"), "{head}");
    assert!(head.contains(&format!("X-Api-Key: {key}\r\n")), "{head}");
    assert!(
        !head.lines().next().unwrap().contains(key),
        "never in the request line"
    );
    let ctype = head
        .lines()
        .find_map(|l| l.strip_prefix("Content-Type: "))
        .unwrap();
    let boundary = ctype
        .strip_prefix("multipart/form-data; boundary=")
        .unwrap();
    for (name, value) in [
        ("autoCreate", "true"),
        ("projectName", "Plant A"),
        ("projectVersion", "10.0.0.0/24"),
        ("bom", bom.as_str()),
    ] {
        let part = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        );
        assert!(body.contains(&part), "field {name}");
    }
    assert!(body.ends_with(&format!("--{boundary}--\r\n")));
    // A token goes only over https://, except to localhost; no query string; a project name.
    let e = push_dependency_track(
        "http://dtrack.example",
        key,
        "p",
        "v",
        "{}",
        std::time::Duration::from_secs(1),
    )
    .unwrap_err();
    assert!(e.contains("https://"), "{e}");
    assert!(
        push_dependency_track(
            "https://dtrack.example/api/v1/bom?x=1",
            key,
            "p",
            "v",
            "{}",
            std::time::Duration::from_secs(1)
        )
        .is_err()
    );
    assert!(
        push_dependency_track(
            "https://dtrack.example",
            key,
            " ",
            "v",
            "{}",
            std::time::Duration::from_secs(1)
        )
        .is_err()
    );
}

#[test]
fn the_multipart_boundary_never_occurs_in_a_value() {
    let (_, body) = multipart(&[("bom", "x --network-scope-00000000 y")]);
    assert!(body.starts_with("--network-scope-00000001\r\n"), "{body}");
}

#[test]
fn software_a_device_listed_over_snmp_becomes_application_components() {
    let mut s = snapshot();
    let switch = &mut s.hosts[1].identity;
    switch.insert(
        "snmp.software".into(),
        "net-snmp-5.9.4; openssh-server-9.6p1".into(),
    );
    let v = bom(&s, &[]);
    let apps: Vec<&Value> = all_components(&v)
        .into_iter()
        .filter(|c| prop(c, "source") == ["SNMP hrSWInstalledName"])
        .collect();
    let mut names: Vec<&str> = apps.iter().filter_map(|c| c["name"].as_str()).collect();
    names.sort();
    assert_eq!(names, ["net-snmp-5.9.4", "openssh-server-9.6p1"]);
    assert!(apps.iter().all(|c| c["type"] == "application"));
    // A long list (far beyond the length limit of one value) is exported whole.
    let many: Vec<String> = (0..150)
        .map(|i| format!("package-number-{i:03}-1.0"))
        .collect();
    s.hosts[1]
        .identity
        .insert("snmp.software".into(), many.join("; "));
    let v = bom(&s, &[]);
    let mut exported: Vec<String> = all_components(&v)
        .into_iter()
        .filter(|c| prop(c, "source") == ["SNMP hrSWInstalledName"])
        .filter_map(|c| c["name"].as_str().map(str::to_string))
        .collect();
    exported.sort();
    assert_eq!(exported, many);
}

/// Writes a scan of 65,536 hosts to the database named by `NS_LARGE_SCAN_DB`, for measuring
/// `export --format cyclonedx` on a large network (docs/src/lab-and-testing.md); does nothing
/// without the variable. Every host has an SSH and an HTTP banner with a version (both raise CVE
/// hints), every hundredth is a PLC that reported its firmware.
#[test]
#[ignore = "writes a large database; run by hand for the export measurement"]
fn write_a_large_scan_for_the_export_measurement() {
    let Some(path) = std::env::var_os("NS_LARGE_SCAN_DB") else {
        return;
    };
    let hosts: Vec<Host> = (0..65_536u32)
        .map(|i| {
            let ip = std::net::Ipv4Addr::from(0x0a00_0000 + i).to_string();
            let mac = format!(
                "02:00:{:02X}:{:02X}:{:02X}:{:02X}",
                i >> 24,
                (i >> 16) & 0xff,
                (i >> 8) & 0xff,
                i & 0xff
            );
            let mut id = vec![
                ("svc.22", "ssh"),
                ("svc.22.product", "OpenSSH"),
                ("svc.22.version", "7.4"),
                ("svc.80", "http"),
                ("svc.80.product", "nginx"),
                ("svc.80.version", "1.14.0"),
            ];
            let mut open = vec![22, 80];
            if i % 100 == 0 {
                id.extend([
                    ("S7.order_code", "6ES7 214-1AG40-0XB0"),
                    ("S7.cpu_type", "CPU 1214C DC/DC/DC"),
                    ("S7.firmware", "V4.2.1"),
                ]);
                open.push(102);
            }
            let mut h = host(&ip, &mac, &open, &id);
            h.hostname = format!("host-{i}");
            h
        })
        .collect();
    let snapshot = Snapshot {
        sent: vec![],
        targets: "10.0.0.0/16".into(),
        complete: true,
        settings: Settings::default(),
        hosts,
        observations: vec![],
        notes: Default::default(),
    };
    crate::store::save(std::path::Path::new(&path), &snapshot).unwrap();
}

/// A real firmware SBOM (from a vendor or from Syft on an unpacked image) nested into the export:
/// `NS_REAL_SBOM=file NS_REAL_SBOM_VENDOR=.. NS_REAL_SBOM_PRODUCT=.. NS_REAL_SBOM_VERSION=..
/// NS_REAL_SBOM_OUT=out.cdx.json cargo test -p network-scope-core --lib real_firmware_sbom --
/// --ignored`. The device announces that product and version over LLDP-MED; the first component
/// with a CPE gets a made-up CVE and a VEX statement by its package URL.
#[test]
#[ignore = "needs a real SBOM file (NS_REAL_SBOM)"]
fn a_real_firmware_sbom_is_nested_into_the_export() {
    let Some(file) = std::env::var_os("NS_REAL_SBOM") else {
        return;
    };
    let var = |k: &str| std::env::var(k).unwrap_or_default();
    let bytes = std::fs::read(file).unwrap();
    let subject = crate::sbom::Subject {
        vendor: Some(var("NS_REAL_SBOM_VENDOR")),
        product: Some(var("NS_REAL_SBOM_PRODUCT")),
        version: Some(var("NS_REAL_SBOM_VERSION")),
    };
    let mut sbom = crate::sbom::parse(&bytes, &subject).unwrap().sbom;
    sbom.source = "real.sbom.json".into();
    let first = sbom
        .components
        .iter()
        .find(|c| !c.cpe.is_empty() && !c.purl.is_empty())
        .expect("a component with a CPE and a package URL")
        .clone();
    let library = crate::sbom::Library {
        version: 1,
        imported_at: 0,
        sboms: vec![sbom],
    };
    let mut s = snapshot();
    let lldp = &mut s.observations[0].fields;
    lldp.insert("med_model".into(), var("NS_REAL_SBOM_PRODUCT"));
    lldp.insert("med_manufacturer".into(), var("NS_REAL_SBOM_VENDOR"));
    lldp.insert("med_firmware_revision".into(), var("NS_REAL_SBOM_VERSION"));
    let statement = format!(
        r#"{{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[{{"id":"CVE-2099-7777",
          "analysis":{{"state":"not_affected","justification":"code_not_reachable"}},
          "affects":[{{"ref":"urn:cdx:x/1#{}"}}]}}]}}"#,
        first.purl
    );
    let vex = crate::vex::Library {
        version: 1,
        imported_at: 0,
        sources: vec![],
        statements: crate::vex::parse(statement.as_bytes(), "vex.json").unwrap(),
    };
    let cpe = first.cpe.clone();
    let nvd = move |c: &str| {
        if c == cpe {
            vec![crate::nvd::Hit {
                cve: "CVE-2099-7777".into(),
                severity: Severity::High,
                title: "test".into(),
                range: "*".into(),
            }]
        } else {
            vec![]
        }
    };
    let devices = devices::merge(&s.hosts, &s.observations);
    let assets = otpassive::assets(&s.observations);
    let started = std::time::Instant::now();
    let v = build(&Input {
        snapshot: &s,
        devices: &devices,
        assets: &assets,
        findings: &[],
        cpe: &|_, _| None,
        sboms: &library,
        vex: &vex,
        enrich: &|_| {},
        nvd: &nvd,
        timestamp: 1_795_000_000,
    });
    let firmware = all_components(&v)
        .into_iter()
        .find(|c| c["type"] == "firmware" && prop(c, "sbom") == ["real.sbom.json"])
        .expect("the SBOM is nested into the LLDP-MED firmware");
    let inside = firmware["components"].as_array().unwrap();
    let cve = v["vulnerabilities"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == "CVE-2099-7777")
        .expect("the CVE of the component");
    assert_eq!(
        cve["analysis"]["state"], "not_affected",
        "VEX by package URL"
    );
    assert!(inside.iter().all(|c| c["type"] != "file"));
    eprintln!(
        "{} components nested ({:?} file entries left out), built in {:?}; {} -> {}",
        inside.len(),
        prop(firmware, "sbom-files-left-out"),
        started.elapsed(),
        first.purl,
        cve["analysis"]
    );
    if let Ok(out) = std::env::var("NS_REAL_SBOM_OUT") {
        std::fs::write(out, serde_json::to_string_pretty(&v).unwrap()).unwrap();
    }
}

/// The switch (10.0.0.1) reports two neighbours over SNMP: the PLC by its MAC, and a device
/// that is not in the scan.
fn with_lldp_neighbours(s: &mut Snapshot) {
    let switch = s
        .hosts
        .iter_mut()
        .find(|h| h.ip.to_string() == "10.0.0.1")
        .unwrap();
    for (k, v) in [
        ("device.type", "Switch"),
        ("snmp.lldp.0.local_port", "5"),
        ("snmp.lldp.0.local_port_desc", "Gi1/0/5"),
        ("snmp.lldp.0.chassis_id", "00:1B:1B:7C:22:05"),
        ("snmp.lldp.0.port_id", "X1 P1"),
        ("snmp.lldp.1.local_port", "7"),
        ("snmp.lldp.1.chassis_id", "02:00:00:00:00:99"),
        ("snmp.lldp.1.sys_name", "unknown-ap"),
    ] {
        switch.identity.insert(k.into(), v.into());
    }
}

#[test]
fn a_device_depends_on_the_switch_its_lldp_link_goes_to() {
    let mut s = snapshot();
    with_lldp_neighbours(&mut s);
    let v = bom(&s, &[]);
    let deps = v["dependencies"].as_array().expect("dependencies");
    assert_eq!(deps.len(), 1, "{deps:?}");
    let plc = all_components(&v)
        .into_iter()
        .find(|c| c["type"] == "device" && prop(c, "address") == ["10.0.0.5"])
        .unwrap();
    let sw = all_components(&v)
        .into_iter()
        .find(|c| c["type"] == "device" && prop(c, "address") == ["10.0.0.1"])
        .unwrap();
    assert_eq!(deps[0]["ref"], plc["bom-ref"]);
    assert_eq!(deps[0]["dependsOn"], json!([sw["bom-ref"]]));
    assert_eq!(prop(plc, "connected-to"), ["10.0.0.1 Gi1/0/5"]);
    // Without LLDP tables: no dependencies.
    assert!(bom(&snapshot(), &[]).get("dependencies").is_none());
}

/// Firmware seen in passive industrial traffic: one component per product and version (case
/// does not matter), named by the product, else the station name, else just "firmware".
#[test]
fn firmware_from_passive_traffic_becomes_one_component_per_product_and_version() {
    let s = snapshot();
    let devices = devices::merge(&s.hosts, &s.observations);
    let asset = |ip: &str, mac: &str, name: &str, product: &str, firmware: &str| Asset {
        ips: if ip.is_empty() {
            vec![]
        } else {
            vec![ip.parse().unwrap()]
        },
        mac: mac.into(),
        vendor: "Acme".into(),
        name: name.into(),
        product: product.into(),
        firmware: firmware.into(),
        protocols: vec!["EtherNet/IP".into(), "CIP".into()],
        ..Default::default()
    };
    let mut serial = asset("10.0.0.9", "", "station-9", "Ctrl 9", "3.1");
    serial.serial = "SN-9".into();
    let assets = vec![
        serial,
        // The same firmware again, spelled differently: no second component.
        asset("10.0.0.9", "", "", "CTRL 9", "3.1"),
        // Nothing to name the firmware by: no component.
        asset("10.0.0.9", "", "", "", ""),
        asset("10.0.0.9", "", "station-9", "", "4.0"),
        asset("10.0.0.9", "", "", "", "5.0"),
        // Matched by MAC on the switch; an asset of no device is left out.
        asset("", "00:11:22:33:44:55", "", "Switch OS", "9.9"),
        asset("10.9.9.9", "", "", "Elsewhere", "1.0"),
    ];
    let v = build(&Input {
        snapshot: &s,
        devices: &devices,
        assets: &assets,
        findings: &[],
        cpe: &|_, _| None,
        sboms: &crate::sbom::Library::default(),
        vex: &crate::vex::Library::default(),
        enrich: &|_| {},
        nvd: &|_| vec![],
        timestamp: 1_795_000_000,
    });
    let all = all_components(&v);
    let quiet = all
        .iter()
        .find(|c| c["type"] == "device" && prop(c, "address") == ["10.0.0.9"])
        .unwrap();
    assert_eq!(quiet["manufacturer"]["name"], "Acme");
    assert_eq!(
        prop(quiet, "manufacturer-source"),
        ["passive industrial traffic"]
    );
    assert_eq!(prop(quiet, "serial-number"), ["SN-9"]);
    let firmware: Vec<(&str, &str)> = quiet["components"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["name"].as_str().unwrap(), c["version"].as_str().unwrap()))
        .collect();
    assert_eq!(
        firmware,
        [("Ctrl 9", "3.1"), ("station-9", "4.0"), ("firmware", "5.0")]
    );
    let ctrl = &quiet["components"][0];
    assert_eq!(ctrl["type"], "firmware");
    assert_eq!(ctrl["manufacturer"]["name"], "Acme");
    assert_eq!(prop(ctrl, "source"), ["passive EtherNet/IP, CIP"]);
    let switch = all
        .iter()
        .find(|c| c["type"] == "device" && prop(c, "address") == ["10.0.0.1"])
        .unwrap();
    assert!(
        switch["components"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "Switch OS" && c["version"] == "9.9")
    );
    assert!(!v.to_string().contains("Elsewhere"));
}

#[test]
fn vex_justifications_map_to_the_closest_cyclonedx_value() {
    for (from, to) in [
        ("code_not_present", Some("code_not_present")),
        ("component_not_present", Some("code_not_present")),
        (" vulnerable_code_not_present ", Some("code_not_present")),
        (
            "vulnerable_code_not_in_execute_path",
            Some("code_not_reachable"),
        ),
        ("requires_configuration", Some("requires_configuration")),
        ("requires_dependency", Some("requires_dependency")),
        ("requires_environment", Some("requires_environment")),
        ("protected_by_compiler", Some("protected_by_compiler")),
        ("protected_at_runtime", Some("protected_at_runtime")),
        ("protected_at_perimeter", Some("protected_at_perimeter")),
        (
            "inline_mitigations_already_exist",
            Some("protected_by_mitigating_control"),
        ),
        (
            "vulnerable_code_cannot_be_controlled_by_adversary",
            Some("protected_by_mitigating_control"),
        ),
        ("because", None),
        ("", None),
    ] {
        assert_eq!(justification(from), to, "{from}");
    }
}
