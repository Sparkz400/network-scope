//! Exit status of the built CLI binaries against a fixture database. The database is built with
//! `import` from two small nmap XML files (no network traffic): scan 1 has only SSH on
//! 10.0.0.1, scan 2 adds Telnet (a high-severity finding), scan 3 is scan 1 again.
use std::{path::PathBuf, process::Command};

const SCAN_OLD: &str = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -p 22,23 10.0.0.1" start="1700000000">
<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports>
</host></nmaprun>"#;

const SCAN_NEW: &str = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -p 22,23 10.0.0.1" start="1700000100">
<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port></ports>
</host></nmaprun>"#;

struct Fixture {
    dir: PathBuf,
    db: String,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ns-exit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("inventory.sqlite").to_str().unwrap().to_string();
        let fixture = Self { dir, db };
        for (file, xml) in [
            ("old.xml", SCAN_OLD),
            ("new.xml", SCAN_NEW),
            ("old2.xml", SCAN_OLD),
        ] {
            let path = fixture.dir.join(file);
            std::fs::write(&path, xml).unwrap();
            let (code, _, err) = fixture.run(&["import", path.to_str().unwrap(), "--quiet"]);
            assert_eq!(code, 0, "import {file}: {err}");
        }
        fixture
    }

    /// Runs the CLI with `--db` appended; returns exit code, stdout, stderr.
    fn run(&self, args: &[&str]) -> (i32, String, String) {
        run_bin(
            env!("CARGO_BIN_EXE_network-scope-cli"),
            args,
            Some(&self.db),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn run_bin(bin: &str, args: &[&str], db: Option<&str>) -> (i32, String, String) {
    let mut cmd = Command::new(bin);
    cmd.args(args);
    if let Some(db) = db {
        cmd.args(["--db", db]);
    }
    let out = cmd.output().unwrap();
    (
        out.status.code().expect("exited by signal"),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn version_prints_the_package_version() {
    let (code, out, _) = run_bin(
        env!("CARGO_BIN_EXE_network-scope-cli"),
        &["--version"],
        None,
    );
    assert_eq!(code, 0);
    assert_eq!(
        out.trim(),
        concat!("network-scope ", env!("CARGO_PKG_VERSION"))
    );
}

// Only in the CLI-only build (`--no-default-features`): without a command there is no window to
// open, so the binary says so and exits 2.
#[cfg(not(feature = "gui"))]
#[test]
fn cli_only_build_without_arguments_exits_2() {
    let (code, out, err) = run_bin(env!("CARGO_BIN_EXE_network-scope-cli"), &[], None);
    assert_eq!(code, 2);
    assert!(out.is_empty(), "{out}");
    assert!(err.contains("built without the GUI; see --help"), "{err}");
}

#[test]
fn help_and_plain_success_exit_0() {
    let (code, out, _) = run_bin(env!("CARGO_BIN_EXE_network-scope-cli"), &["--help"], None);
    assert_eq!(code, 0);
    assert!(out.contains("--fail-on-findings"), "{out}");
    assert!(out.contains("Exit status"), "{out}");
    // The help of one command, in its three forms: on stdout, status 0, nothing on stderr, and
    // nothing is scanned (`-h` is not a target).
    for args in [&["scan", "--help"][..], &["scan", "-h"], &["help", "scan"]] {
        let (code, one, err) = run_bin(env!("CARGO_BIN_EXE_network-scope-cli"), args, None);
        assert_eq!((code, err.as_str()), (0, ""), "{args:?}");
        assert!(one.starts_with("network-scope scan TARGETS"), "{one}");
        assert!(one.contains("Examples:") && one.len() < out.len(), "{one}");
        assert!(!one.contains("network-scope findings"), "{one}");
    }
    let (code, _, err) = run_bin(
        env!("CARGO_BIN_EXE_network-scope-cli"),
        &["frobnicate", "--help"],
        None,
    );
    assert_eq!(code, 1);
    assert!(err.contains("Unknown command frobnicate"), "{err}");
}

#[test]
fn errors_exit_1() {
    let bin = env!("CARGO_BIN_EXE_network-scope-cli");
    let (code, _, err) = run_bin(bin, &["--no-such-option"], None);
    assert_eq!(code, 1, "{err}");
    let (code, _, err) = run_bin(bin, &["frobnicate"], None);
    assert_eq!(code, 1);
    assert!(err.contains("Unknown command"), "{err}");
    let fixture = Fixture::new("errors");
    // Unknown scan ID, bad severity, flag on a command it does not apply to.
    assert_eq!(fixture.run(&["findings", "99"]).0, 1);
    assert_eq!(
        fixture.run(&["findings", "1", "--min-severity", "bogus"]).0,
        1
    );
    let (code, _, err) = fixture.run(&["history", "--fail-on-findings"]);
    assert_eq!(code, 1);
    assert!(err.contains("--fail-on-findings"), "{err}");
}

#[test]
fn history_prune_deletes_old_scans_and_refuses_what_it_cannot_do() {
    let fixture = Fixture::new("prune");
    let scans = |f: &Fixture| -> usize {
        let (code, out, err) = f.run(&["history"]);
        assert_eq!(code, 0, "{err}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        v["scans"].as_array().unwrap().len()
    };
    assert_eq!(scans(&fixture), 3);
    // Without a rule, with a rule that deletes everything, and --dry-run on the listing.
    let (code, _, err) = fixture.run(&["history", "prune"]);
    assert_eq!(code, 1);
    assert!(err.contains("history prune --keep"), "{err}");
    assert_eq!(fixture.run(&["history", "prune", "--keep", "0"]).0, 1);
    assert_eq!(
        fixture.run(&["history", "prune", "--older-than", "last"]).0,
        1
    );
    assert_eq!(fixture.run(&["history", "--dry-run"]).0, 1);
    // A dry run counts and deletes nothing.
    let (code, out, err) = fixture.run(&["history", "prune", "--keep", "1", "--dry-run"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Would delete 2 scans; 1 stay."), "{out}");
    assert_eq!(scans(&fixture), 3);
    let (code, out, err) = fixture.run(&["history", "prune", "--keep", "1"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Deleted 2 scans; 1 stay."), "{out}");
    assert_eq!(scans(&fixture), 1);
    // The fixture's scans are years old, but the newest completed one always stays.
    let (code, out, _) = fixture.run(&["history", "prune", "--older-than", "30d"]);
    assert_eq!(code, 0);
    assert!(out.contains("Deleted 0 scans; 1 stay."), "{out}");
    // A mistyped --db is an error and creates no inventory.
    let missing = fixture.dir.join("typo.sqlite");
    let (code, _, err) = run_bin(
        env!("CARGO_BIN_EXE_network-scope-cli"),
        &["history", "prune", "--keep", "1"],
        missing.to_str(),
    );
    assert_eq!(code, 1);
    assert!(err.contains("no such inventory"), "{err}");
    assert!(!missing.exists());
}

#[test]
fn findings_default_is_unchanged_and_the_gate_exits_3() {
    let fixture = Fixture::new("findings");
    // Scan 2 has Telnet: a finding, but without the flag the status stays 0.
    let (code, out, err) = fixture.run(&["findings", "2"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("telnet-open"), "{out}");
    let (code, out, _) = fixture.run(&["findings", "2", "--fail-on-findings"]);
    assert_eq!(code, 3);
    assert!(
        out.contains("telnet-open"),
        "output is still printed: {out}"
    );
    // The threshold applies: telnet is high, so "critical" finds nothing.
    assert_eq!(
        fixture
            .run(&[
                "findings",
                "2",
                "--min-severity",
                "critical",
                "--fail-on-findings"
            ])
            .0,
        0
    );
    assert_eq!(
        fixture
            .run(&[
                "findings",
                "2",
                "--min-severity",
                "high",
                "--fail-on-findings"
            ])
            .0,
        3
    );
    // Scan 1 has no high finding at all.
    assert_eq!(
        fixture
            .run(&[
                "findings",
                "1",
                "--min-severity",
                "high",
                "--fail-on-findings",
                "--quiet"
            ])
            .0,
        0
    );
}

#[test]
fn diff_gate_counts_new_findings_only() {
    let fixture = Fixture::new("diff");
    // Telnet appeared between scan 1 and 2: new high finding.
    let (code, out, err) = fixture.run(&["diff", "1", "2"]);
    assert_eq!(code, 0, "default is unchanged: {err}");
    assert!(out.contains("23"), "{out}");
    assert_eq!(fixture.run(&["diff", "1", "2", "--fail-on-findings"]).0, 3);
    assert_eq!(
        fixture
            .run(&[
                "diff",
                "1",
                "2",
                "--fail-on-findings",
                "--min-severity",
                "critical"
            ])
            .0,
        0
    );
    // --min-severity alone neither filters nor changes the status.
    let plain = fixture.run(&["diff", "1", "2", "--format", "json"]);
    let with_min = fixture.run(&[
        "diff",
        "1",
        "2",
        "--format",
        "json",
        "--min-severity",
        "critical",
    ]);
    assert_eq!((plain.0, with_min.0), (0, 0));
    assert_eq!(plain.1, with_min.1);
    // The finding is resolved going back (no new finding): status 0 even with the gate.
    assert_eq!(fixture.run(&["diff", "2", "3", "--fail-on-findings"]).0, 0);
    // Identical scans: nothing new.
    assert_eq!(fixture.run(&["diff", "1", "3", "--fail-on-findings"]).0, 0);
}

// The GUI binary exists only with the `gui` feature (the default).
#[cfg(feature = "gui")]
#[test]
fn gui_binary_uses_the_same_exit_codes() {
    // The GUI binary runs the same code when it gets arguments. (With a GUI-subsystem release
    // build the status is still the process status; only shells do not wait for it.)
    let bin = env!("CARGO_BIN_EXE_network-scope");
    let (code, _, _) = run_bin(bin, &["--no-such-option"], None);
    assert_eq!(code, 1);
    let fixture = Fixture::new("gui");
    let (code, _, _) = run_bin(
        bin,
        &["findings", "2", "--fail-on-findings", "--quiet"],
        Some(&fixture.db),
    );
    assert_eq!(code, 3);
}
