// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! `network-scope-cli mcp` as a process: JSON-RPC lines in on stdin, only JSON-RPC lines out on
//! stdout. The inventory is built with `import` from an nmap XML file (no network traffic), and
//! the scan tool is switched off with `--no-scan`.
use serde_json::{Value, json};
use std::{
    io::Write,
    process::{Command, Stdio},
};

const BIN: &str = env!("CARGO_BIN_EXE_network-scope-cli");

const XML: &str = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -p 22,23 10.0.0.1" start="1700000000">
<host><status state="up"/><address addr="10.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port></ports>
</host></nmaprun>"#;

#[test]
fn the_mcp_command_speaks_only_json_rpc_on_stdout() {
    let dir = std::env::temp_dir().join(format!("ns-mcp-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("inventory.sqlite").to_str().unwrap().to_string();
    let xml = dir.join("scan.xml");
    std::fs::write(&xml, XML).unwrap();
    let import = Command::new(BIN)
        .args(["import", xml.to_str().unwrap(), "--quiet", "--db", &db])
        .output()
        .unwrap();
    assert!(import.status.success());

    let mut child = Command::new(BIN)
        .args(["mcp", "--db", &db, "--no-scan"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let lines = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list_findings", "arguments": {"finding_id": "telnet-open"}}}),
    ];
    {
        let stdin = child.stdin.as_mut().unwrap();
        for line in &lines {
            writeln!(stdin, "{line}").unwrap();
        }
        writeln!(stdin, "this is not json").unwrap();
    }
    drop(child.stdin.take()); // end of input: the server ends
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let replies: Vec<Value> = String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSON: {l}: {e}")))
        .collect();
    assert_eq!(replies.len(), 4, "{replies:?}");
    assert_eq!(replies[0]["result"]["protocolVersion"], "2025-06-18");
    let names: Vec<&str> = replies[1]["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"list_findings") && !names.contains(&"scan"),
        "{names:?}"
    );
    assert_eq!(replies[2]["result"]["isError"], false);
    assert_eq!(
        replies[2]["result"]["structuredContent"]["findings"][0]["id"],
        "telnet-open"
    );
    assert_eq!(replies[3]["error"]["code"], -32700);
    let _ = std::fs::remove_dir_all(&dir);

    // Positional arguments are an error (exit status 1), with nothing on stdout.
    let bad = Command::new(BIN)
        .args(["mcp", "10.0.0.0/24"])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(1));
    assert!(bad.stdout.is_empty());
}
