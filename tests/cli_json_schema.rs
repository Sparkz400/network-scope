//! The JSON the built CLI prints, validated against the schema files in `docs/schema`
//! (see `network_scope_core::schema` for the compatibility promise). The database is built with
//! `import` from two small nmap XML files, so no network traffic happens.
use network_scope_core::schema;
use serde_json::Value;
use std::{path::PathBuf, process::Command};

const BIN: &str = env!("CARGO_BIN_EXE_network-scope-cli");

fn xml(extra: &str, start: u32) -> String {
    format!(
        r#"<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -p 22,23 10.0.0.1" start="{start}">
<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>
<address addr="00:0C:29:AA:BB:CC" addrtype="mac"/>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>{extra}</ports>
</host></nmaprun>"#
    )
}

struct Fixture {
    dir: PathBuf,
    db: String,
}
impl Fixture {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ns-schema-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("inventory.sqlite").to_str().unwrap().to_string();
        let fixture = Self { dir, db };
        let telnet = r#"<port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>"#;
        for (file, text) in [
            ("old.xml", xml("", 1_700_000_000)),
            ("new.xml", xml(telnet, 1_700_000_100)),
        ] {
            let path = fixture.dir.join(file);
            std::fs::write(&path, text).unwrap();
            let (code, _, err) = fixture.run(&["import", path.to_str().unwrap(), "--quiet"]);
            assert_eq!(code, 0, "import {file}: {err}");
        }
        fixture
    }
    fn run(&self, args: &[&str]) -> (i32, String, String) {
        let out = Command::new(BIN)
            .args(args)
            .args(["--db", &self.db])
            .output()
            .unwrap();
        (
            out.status.code().expect("exited by signal"),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }
    /// Runs the command, checks that every output line or document matches the schema `kind`.
    fn check(&self, kind: &str, args: &[&str], jsonl: bool) -> Vec<Value> {
        let (code, out, err) = self.run(args);
        assert_eq!(code, 0, "{args:?}: {err}");
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("docs/schema")
            .join(format!("{kind}.{}.schema.json", schema::CURRENT));
        let schema_doc: Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let docs: Vec<Value> = if jsonl {
            out.lines()
                .filter(|l| !l.is_empty())
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        } else {
            vec![serde_json::from_str(&out).unwrap_or_else(|e| panic!("{args:?}: {e}\n{out}"))]
        };
        assert!(!docs.is_empty(), "{args:?} printed nothing");
        for doc in &docs {
            schema::validate(&schema_doc, doc).unwrap_or_else(|e| panic!("{args:?}: {e}\n{out}"));
            assert_eq!(doc["schema"], schema::id(kind));
        }
        docs
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn every_json_output_of_the_cli_carries_its_schema_and_matches_it() {
    let f = Fixture::new("outputs");
    let scan = f.check("scan", &["export", "2", "--format", "json"], false);
    assert_eq!(
        scan[0]["hosts"][0]["ip"], "10.0.0.1",
        "existing members are unchanged"
    );
    f.check("host", &["export", "2", "--format", "jsonl"], true);
    f.check("diff-lines", &["diff", "1", "2"], false);
    let diff = f.check("diff", &["diff", "1", "2", "--format", "json"], false);
    assert!(diff[0]["summary"]["new_findings"].as_u64().unwrap() >= 1);
    f.check("devices", &["devices", "2"], false);
    f.check(
        "device-history",
        &["devices", "--history", "10.0.0.1", "--format", "json"],
        false,
    );
    let findings = f.check("findings", &["findings", "2"], false);
    assert!(
        findings[0]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["id"] == "telnet-open")
    );
    let scans = f.check("scans", &["history"], false);
    assert_eq!(scans[0]["scans"].as_array().unwrap().len(), 2);
    f.check("alerts", &["alerts"], false);
    f.check("ot-assets", &["ot-assets", "2"], false);
}

/// The outputs added with changes, baseline, risk scores, import and the dry run (G44).
#[test]
fn the_newer_json_outputs_carry_their_schema_and_match_it() {
    let f = Fixture::new("newer");
    let changes = f.check("changes", &["changes", "--format", "json"], false);
    assert_eq!(changes[0]["summary"]["new_risks"], 1);
    assert_eq!(changes[0]["new_risks"][0]["finding"]["id"], "telnet-open");
    // No baseline yet: an empty entry list and no approval time.
    let none = f.check("baseline", &["baseline", "show", "--format", "json"], false);
    assert!(none[0]["approved_at"].is_null());
    let (code, _, err) = f.run(&["baseline", "approve", "--quiet"]);
    assert_eq!(code, 0, "{err}");
    let approved = f.check("baseline", &["baseline", "show", "--format", "json"], false);
    assert_eq!(approved[0]["entries"].as_array().unwrap().len(), 1);
    let score = f.check(
        "risk-score",
        &["findings", "2", "--top", "3", "--format", "json"],
        false,
    );
    assert_eq!(score[0]["top_fixes"][0]["id"], "telnet-open");
    let csv = f.dir.join("inventory.csv");
    std::fs::write(
        &csv,
        "ip,mac,hostname
10.0.0.9,00:11:22:33:44:55,printer
",
    )
    .unwrap();
    let summary = f.check(
        "import-summary",
        &[
            "import",
            "csv",
            csv.to_str().unwrap(),
            "--format",
            "json",
            "--quiet",
        ],
        false,
    );
    assert_eq!(summary[0]["merged"]["new"], 1);
}

#[test]
fn the_unknown_banner_export_carries_its_schema_and_keeps_its_own_format() {
    let f = Fixture::new("unknown");
    let doc = f.check(
        "unknown-banners",
        &["fingerprints", "export-unknown", "--quiet"],
        false,
    );
    assert_eq!(doc[0]["format"], "network-scope-unknown-banners");
    assert!(doc[0]["entries"].is_array());
}

#[test]
fn every_dry_run_prints_the_dry_run_schema() {
    let f = Fixture::new("dryrun");
    // A declared scope keeps the result independent of the developer's own scope file.
    let scope = ["--scope", "10.0.0.0/8", "--format", "json", "--dry-run"];
    for (command, args) in [
        (
            "scan",
            vec![
                "scan",
                "10.0.0.1-3",
                "--fast",
                "--ot",
                "--jarm",
                "--services",
            ],
        ),
        ("monitor", vec!["monitor", "10.0.0.1", "--dhcp-discover"]),
        ("trace", vec!["trace", "10.0.0.1"]),
        ("dcp", vec!["dcp"]),
    ] {
        let mut a = args;
        a.extend(scope);
        let doc = f.check("dry-run", &a, false);
        assert_eq!(doc[0]["command"], command);
        assert_eq!(doc[0]["packets_sent"], 0);
    }
    let scan = f.check(
        "dry-run",
        &[
            "scan",
            "10.0.0.1",
            "--scope",
            "10.0.0.0/8",
            "--dry-run",
            "--format",
            "json",
        ],
        false,
    );
    assert_eq!(scan[0]["scope"]["would_need_confirmation"], false);
}

#[test]
fn json_schema_option_accepts_v1_and_rejects_other_versions() {
    let f = Fixture::new("option");
    f.check("findings", &["findings", "2", "--json-schema", "v1"], false);
    for bad in ["v2", "v0", "1", ""] {
        let (code, out, err) = f.run(&["findings", "2", "--json-schema", bad]);
        assert_eq!(code, 1, "{bad:?}: {out}");
        assert!(err.contains("Unsupported --json-schema"), "{err}");
        assert!(out.is_empty(), "nothing is printed on a bad version: {out}");
    }
    let (code, _, err) = f.run(&["findings", "2", "--json-schema"]);
    assert_eq!(code, 1);
    assert!(err.contains("Missing --json-schema"), "{err}");
}
