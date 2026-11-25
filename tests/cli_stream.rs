// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! `scan --stream`: live events on stdout, validated against `docs/schema/scan-event.v1.schema.json`.
use network_scope_core::schema;
use serde_json::Value;
use std::{
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const BIN: &str = env!("CARGO_BIN_EXE_network-scope-cli");

fn schema_doc() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("docs/schema")
        .join(format!("scan-event.{}.schema.json", schema::CURRENT));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn the_scan_prints_each_event_as_json_lines_and_the_report_only_goes_to_output() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let dir = std::env::temp_dir().join(format!("ns-stream-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("x.sqlite");
    let mut child = Command::new(BIN)
        .args([
            "scan",
            "127.0.0.1",
            "--scope",
            "127.0.0.0/8",
            "--tcp-only",
            "--fast",
            "--stream",
            "--quiet",
            "--ports",
            &port.to_string(),
            "--db",
            db.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    let reader = BufReader::new(child.stdout.take().unwrap());
    let mut events: Vec<Value> = vec![];
    let mut first_after = None;
    for line in reader.lines() {
        first_after.get_or_insert(started.elapsed());
        events.push(serde_json::from_str(&line.unwrap()).unwrap());
    }
    assert!(child.wait().unwrap().success());
    let schema = schema_doc();
    for e in &events {
        schema::validate(&schema, e).unwrap_or_else(|m| panic!("{m}: {e}"));
        assert_eq!(e["schema"], schema::id("scan-event"));
    }
    let kinds: Vec<&str> = events
        .iter()
        .map(|e| e["event"].as_str().unwrap())
        .collect();
    // The port is announced before the host is done, and nothing else is on stdout (no report).
    assert_eq!(kinds, ["host-up", "port-open", "host-done"], "{events:?}");
    assert_eq!(events[1]["port"], port);
    assert_eq!(events[2]["open"], serde_json::json!([port]));
    assert!(first_after.unwrap() < Duration::from_secs(5));
    let _ = std::fs::remove_dir_all(&dir);
}
