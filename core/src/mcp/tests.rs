//! The MCP server driven with scripted JSON-RPC lines, in process: no process, no sockets (the
//! `scan` tool is only ever pointed at the loopback address).
use super::*;
use crate::nmap;
use std::{io::Cursor, path::Path};

// ---- Fixtures and helpers --------------------------------------------------------------------

fn temp_db(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "netscope-mcp-{tag}-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
fn remove_db(path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}
fn nmap_scan(targets: &str, extra_ports: &str) -> store::Snapshot {
    nmap::import(&format!(
        r#"<nmaprun args="nmap {targets}" start="1700000000"><host><status state="up"/>
        <address addr="10.0.0.1" addrtype="ipv4"/><address addr="00:0C:29:AA:BB:CC" addrtype="mac"/>
        <hostnames><hostname name="plc-1.lab"/></hostnames>
        <ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
        {extra_ports}</ports></host></nmaprun>"#
    ))
    .unwrap()
}
const TELNET: &str =
    r#"<port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>"#;
const SMB1: &str = r#"<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>"#;

fn set_timestamp(db: &Path, id: i64, timestamp: i64) {
    let c = rusqlite::Connection::open(db).unwrap();
    c.execute("UPDATE scans SET timestamp=?1 WHERE id=?2", [timestamp, id])
        .unwrap();
}

/// Three scans of 10.0.0.1: #1 (2023-11-14) SSH only, #2 (2023-11-16) adds Telnet, #3
/// (2023-11-20) the same as #2; plus an incomplete scan of another scope.
fn fixture(tag: &str) -> PathBuf {
    let db = temp_db(tag);
    let scans = [
        (nmap_scan("10.0.0.1", ""), 1_699_920_000),
        (nmap_scan("10.0.0.1", TELNET), 1_700_100_000),
        (nmap_scan("10.0.0.1", TELNET), 1_700_450_000),
    ];
    for (i, (snapshot, ts)) in scans.iter().enumerate() {
        let id = store::save(&db, snapshot).unwrap();
        assert_eq!(id, i as i64 + 1);
        set_timestamp(&db, id, *ts);
    }
    db
}

fn config(db: &Path, allow_scan: bool) -> Config {
    Config {
        db: db.to_path_buf(),
        allow_scan,
        scope: None,
    }
}
fn session(db: &Path) -> Server {
    let mut server = Server::new(config(db, true));
    let reply = send(
        &mut server,
        "initialize",
        json!({"protocolVersion": LATEST_PROTOCOL}),
    );
    assert_eq!(reply["result"]["protocolVersion"], LATEST_PROTOCOL);
    server
}
fn line(id: i64, method: &str, params: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string()
}
fn send(server: &mut Server, method: &str, params: Value) -> Value {
    let reply = server
        .handle_line(line(7, method, params).as_bytes())
        .unwrap();
    let value: Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(value["jsonrpc"], "2.0");
    assert_eq!(value["id"], 7, "the reply carries the request id");
    value
}
/// A `tools/call` result (not the JSON-RPC envelope).
fn call(server: &mut Server, name: &str, arguments: Value) -> Value {
    let reply = send(
        server,
        "tools/call",
        json!({"name": name, "arguments": arguments}),
    );
    assert!(reply.get("error").is_none(), "{name}: {reply}");
    reply["result"].clone()
}
/// A successful tool result: the structured content, checked against the schema file and
/// against the text content.
fn ok(server: &mut Server, name: &str, arguments: Value, kind: &str) -> Value {
    let result = call(server, name, arguments);
    assert_eq!(result["isError"], false, "{name}: {result}");
    let structured = result["structuredContent"].clone();
    let text: Value = serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text, structured, "the text content is the same JSON");
    assert_eq!(structured["schema"], schema::id(kind), "{name}");
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../docs/schema")
        .join(format!("{kind}.{}.schema.json", schema::CURRENT));
    let schema_doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    schema::validate(&schema_doc, &structured).unwrap_or_else(|e| panic!("{name}: {e}"));
    structured
}
fn failed(server: &mut Server, name: &str, arguments: Value) -> String {
    let result = call(server, name, arguments);
    assert_eq!(result["isError"], true, "{name}: {result}");
    result["content"][0]["text"].as_str().unwrap().to_string()
}

// ---- Protocol ---------------------------------------------------------------------------------

#[test]
fn the_handshake_negotiates_the_protocol_version() {
    let db = temp_db("handshake");
    for (requested, answered) in [
        ("2025-06-18", "2025-06-18"),
        ("2025-03-26", "2025-03-26"),
        ("2024-11-05", "2024-11-05"),
        ("2099-01-01", LATEST_PROTOCOL),
        ("garbage", LATEST_PROTOCOL),
    ] {
        let mut server = Server::new(config(&db, true));
        let reply = send(
            &mut server,
            "initialize",
            json!({"protocolVersion": requested, "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}),
        );
        let result = &reply["result"];
        assert_eq!(result["protocolVersion"], answered, "requested {requested}");
        assert_eq!(result["serverInfo"]["name"], "network-scope");
        assert!(result["capabilities"]["tools"].is_object());
        assert!(result["capabilities"].get("resources").is_none());
        assert!(
            result["instructions"]
                .as_str()
                .unwrap()
                .contains("Safe Mode")
        );
    }
    // The version is required.
    let mut server = Server::new(config(&db, true));
    let reply = send(&mut server, "initialize", json!({}));
    assert_eq!(reply["error"]["code"], -32602);
    let reply = server
        .handle_line(br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#)
        .unwrap();
    assert!(reply.contains("-32602"));
    assert_eq!(SUPPORTED_PROTOCOLS[0], LATEST_PROTOCOL);
}

#[test]
fn requests_before_initialize_are_refused_but_ping_works() {
    let db = temp_db("preinit");
    let mut server = Server::new(config(&db, true));
    assert_eq!(send(&mut server, "ping", json!({}))["result"], json!({}));
    for method in ["tools/list", "tools/call"] {
        let reply = send(&mut server, method, json!({"name": "list_scans"}));
        assert_eq!(reply["error"]["code"], -32002, "{method}");
    }
    // The initialized notification alone also opens the session (no reply to a notification).
    assert!(
        server
            .handle_line(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
            .is_none()
    );
    assert!(send(&mut server, "tools/list", json!({}))["result"]["tools"].is_array());
}

#[test]
fn notifications_and_stray_responses_get_no_reply() {
    let db = temp_db("notify");
    let mut server = session(&db);
    for text in [
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3}}"#,
        r#"{"jsonrpc":"2.0","method":"something/unknown"}"#,
        r#"{"jsonrpc":"2.0","id":99,"result":{}}"#,
        r#"{"jsonrpc":"2.0","id":99,"error":{"code":-1,"message":"x"}}"#,
        "",
        "   ",
    ] {
        assert!(server.handle_line(text.as_bytes()).is_none(), "{text:?}");
    }
    // A notification never produces an error, even one with bad parameters.
    assert!(
        server
            .handle_line(br#"{"jsonrpc":"2.0","method":"tools/call","params":5}"#)
            .is_none()
    );
}

#[test]
fn malformed_input_gets_json_rpc_errors_and_never_panics() {
    let db = temp_db("malformed");
    let mut server = session(&db);
    let deep = format!("{}{}", "[".repeat(5000), "]".repeat(5000));
    for (text, code, null_id) in [
        ("{", -32700, true),
        ("not json", -32700, true),
        ("[1,2", -32700, true),
        (deep.as_str(), -32700, true),
        ("null", -32600, true),
        ("42", -32600, true),
        ("\"x\"", -32600, true),
        ("[]", -32600, true),
        (r#"{"jsonrpc":"2.0"}"#, -32600, true),
        (r#"{"jsonrpc":"2.0","id":1}"#, -32600, false),
        (
            r#"{"jsonrpc":"2.0","id":{"a":1},"method":"ping"}"#,
            -32600,
            true,
        ),
        (
            r#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#,
            -32600,
            true,
        ),
        (r#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#, -32600, false),
        (r#"{"id":1,"method":"ping"}"#, -32600, false),
        (r#"{"jsonrpc":"2.0","id":1,"method":5}"#, -32600, false),
        (
            r#"{"jsonrpc":"2.0","id":1,"method":"no/such"}"#,
            -32601,
            false,
        ),
        (
            r#"{"jsonrpc":"2.0","id":"abc","method":"resources/list"}"#,
            -32601,
            false,
        ),
    ] {
        let reply = server
            .handle_line(text.as_bytes())
            .unwrap_or_else(|| panic!("{text}"));
        let value: Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(value["error"]["code"], code, "{text:.60}: {reply}");
        assert_eq!(value["id"].is_null(), null_id, "{text:.60}: {reply}");
        assert!(!reply.contains('\n'), "one reply is one line");
    }
    // String ids are echoed unchanged.
    let reply = server
        .handle_line(br#"{"jsonrpc":"2.0","id":"abc","method":"ping"}"#)
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&reply).unwrap()["id"], "abc");
    // Invalid UTF-8 is a parse error, not a crash.
    let reply = server.handle_line(&[b'{', 0xff, 0xfe, b'}']).unwrap();
    assert!(reply.contains("-32700"));
}

/// A cheap stand-in for the fuzzer on every `cargo test`: mutated and spliced messages never
/// panic and always get a well-formed reply or none.
#[test]
fn mutated_messages_never_panic() {
    let db = temp_db("mutate");
    let mut server = session(&db);
    server.cfg.allow_scan = false;
    let seeds: Vec<String> = vec![
        line(1, "tools/call", json!({"name": "list_findings", "arguments": {"limit": 3, "ip": "10.0.0.1"}})),
        line(2, "tools/call", json!({"name": "findings_gained", "arguments": {"finding_id": "x", "since": "2024-02-29"}})),
        line(3, "tools/call", json!({"name": "scan", "arguments": {"targets": "10.0.0.0/24"}})),
        line(4, "initialize", json!({"protocolVersion": "2025-06-18"})),
        r#"[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"tools/list"}]"#.into(),
    ];
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for round in 0..3000 {
        let mut bytes = seeds[round % seeds.len()].clone().into_bytes();
        for _ in 0..(next() % 6) {
            let at = (next() as usize) % bytes.len().max(1);
            let last = bytes.len() - 1;
            match next() % 4 {
                0 => bytes[at.min(last)] = next() as u8,
                1 => {
                    bytes.remove(at.min(last));
                }
                2 => bytes.insert(at, b"{}[]\":,\\0123-"[(next() % 13) as usize]),
                _ => bytes.truncate(at.max(1)),
            }
            if bytes.is_empty() {
                bytes.push(b'{');
            }
        }
        if let Some(reply) = server.handle_line(&bytes) {
            let value: Value = serde_json::from_str(&reply).unwrap();
            let items = value.as_array().cloned().unwrap_or_else(|| vec![value]);
            for item in items {
                assert_eq!(item["jsonrpc"], "2.0", "{reply}");
                assert!(
                    item.get("result").is_some() ^ item.get("error").is_some(),
                    "{reply}"
                );
            }
        }
    }
}

#[test]
fn batches_are_answered_as_batches() {
    let db = temp_db("batch");
    let mut server = session(&db);
    let batch = r#"[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","id":2,"method":"no/such"}]"#;
    let reply: Value =
        serde_json::from_str(&server.handle_line(batch.as_bytes()).unwrap()).unwrap();
    let items = reply.as_array().unwrap();
    assert_eq!(items.len(), 2, "the notification has no entry");
    assert_eq!(items[0]["id"], 1);
    assert_eq!(items[1]["error"]["code"], -32601);
    // Only notifications: no reply at all.
    assert!(
        server
            .handle_line(br#"[{"jsonrpc":"2.0","method":"notifications/initialized"}]"#)
            .is_none()
    );
    // An oversized batch is refused.
    let many = format!(
        "[{}]",
        vec![r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#; MAX_BATCH + 1].join(",")
    );
    assert!(
        server
            .handle_line(many.as_bytes())
            .unwrap()
            .contains("-32600")
    );
}

#[test]
fn long_lines_are_refused_and_the_session_continues() {
    let db = temp_db("long");
    let huge = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"ping","params":{{"x":"{}"}}}}"#,
        "a".repeat(MAX_LINE_BYTES)
    );
    let input = format!(
        "{}\n{huge}\n{}\n",
        line(1, "initialize", json!({"protocolVersion": LATEST_PROTOCOL})),
        line(2, "ping", json!({})),
    );
    let mut out = Vec::new();
    serve(config(&db, true), Cursor::new(input.into_bytes()), &mut out).unwrap();
    let replies: Vec<Value> = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(replies.len(), 3, "{replies:?}");
    assert_eq!(replies[0]["id"], 1);
    assert_eq!(replies[1]["error"]["code"], -32600);
    assert!(replies[1]["id"].is_null());
    assert_eq!(
        replies[2]["id"], 2,
        "the line after the oversized one is handled"
    );
    // A last line without a newline is handled too; an empty input ends cleanly.
    let mut out = Vec::new();
    serve(
        config(&db, true),
        Cursor::new(line(5, "ping", json!({})).into_bytes()),
        &mut out,
    )
    .unwrap();
    assert!(String::from_utf8(out).unwrap().contains("\"id\":5"));
    serve(config(&db, true), Cursor::new(Vec::new()), &mut Vec::new()).unwrap();
}

#[test]
fn the_output_stream_holds_only_json_rpc_lines() {
    let db = fixture("stream");
    let mut script = [
        line(1, "initialize", json!({"protocolVersion": "2025-03-26"})),
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_string(),
        line(2, "tools/list", json!({})),
        line(
            3,
            "tools/call",
            json!({"name": "list_scans", "arguments": {}}),
        ),
        line(
            4,
            "tools/call",
            json!({"name": "list_devices", "arguments": {"scan_id": 2}}),
        ),
        line(5, "tools/call", json!({"name": "nope"})),
        "garbage".to_string(),
        line(6, "ping", json!({})),
    ];
    // Windows line endings are accepted.
    script[3].push('\r');
    let input = script.join("\n") + "\n";
    let mut out = Vec::new();
    serve(
        config(&db, false),
        Cursor::new(input.into_bytes()),
        &mut out,
    )
    .unwrap();
    let text = String::from_utf8(out).unwrap();
    let mut ids = vec![];
    for l in text.lines() {
        let v: Value = serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSON: {l}: {e}"));
        assert_eq!(v["jsonrpc"], "2.0", "{l}");
        assert!(v.get("result").is_some() ^ v.get("error").is_some(), "{l}");
        ids.push(v["id"].clone());
    }
    assert_eq!(
        ids,
        [
            json!(1),
            json!(2),
            json!(3),
            json!(4),
            json!(5),
            Value::Null,
            json!(6)
        ]
    );
    remove_db(&db);
}

// ---- Tools ------------------------------------------------------------------------------------

#[test]
fn tools_list_declares_proper_input_schemas() {
    let db = temp_db("tools");
    let mut server = session(&db);
    let tools = send(&mut server, "tools/list", json!({}))["result"]["tools"].clone();
    let tools = tools.as_array().unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        [
            "list_scans",
            "list_devices",
            "device_history",
            "list_findings",
            "diff_scans",
            "search_inventory",
            "findings_gained",
            "scan"
        ]
    );
    for tool in tools {
        let name = tool["name"].as_str().unwrap();
        assert!(!tool["description"].as_str().unwrap().is_empty(), "{name}");
        let schema = &tool["inputSchema"];
        assert_eq!(schema["type"], "object", "{name}");
        assert_eq!(schema["additionalProperties"], false, "{name}");
        let properties = schema["properties"].as_object().unwrap();
        let required = schema["required"].as_array().unwrap();
        for r in required {
            assert!(properties.contains_key(r.as_str().unwrap()), "{name}: {r}");
        }
        // The schema only uses keywords the checker implements: it validates something.
        let verdict = schema::validate(schema, &json!({}));
        assert_eq!(verdict.is_ok(), required.is_empty(), "{name}: {verdict:?}");
        let message = verdict.err().unwrap_or_default();
        assert!(!message.contains("unsupported"), "{name}: {message}");
        let read_only = tool["annotations"]["readOnlyHint"].as_bool().unwrap();
        assert_eq!(read_only, name != "scan", "{name}");
        assert_eq!(tool["annotations"]["destructiveHint"], false);
        assert_eq!(tool["annotations"]["openWorldHint"], !read_only, "{name}");
    }
    // Without the scan tool nothing in the list can send traffic.
    let mut server = Server::new(config(&db, false));
    send(
        &mut server,
        "initialize",
        json!({"protocolVersion": LATEST_PROTOCOL}),
    );
    let tools = send(&mut server, "tools/list", json!({}))["result"]["tools"].clone();
    assert!(
        tools
            .as_array()
            .unwrap()
            .iter()
            .all(|t| t["name"] != "scan")
    );
    assert!(
        tools
            .as_array()
            .unwrap()
            .iter()
            .all(|t| t["annotations"]["readOnlyHint"] == true)
    );
    let text = failed(&mut server, "scan", json!({"targets": "127.0.0.1"}));
    assert!(text.contains("--no-scan"), "{text}");
}

#[test]
fn unknown_tools_and_bad_arguments_are_distinguished() {
    let db = fixture("badargs");
    let mut server = session(&db);
    for (params, code) in [
        (json!({"name": "no_such_tool"}), -32602),
        (json!({}), -32602),
        (json!({"name": 5}), -32602),
        (json!({"name": "list_scans", "arguments": [1]}), -32602),
        (json!(5), -32602),
    ] {
        let reply = send(&mut server, "tools/call", params.clone());
        assert_eq!(reply["error"]["code"], code, "{params}");
    }
    assert!(
        send(&mut server, "tools/call", json!({"name": "no_such_tool"}))["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Unknown tool")
    );
    // Arguments that do not fit the schema are a tool error the assistant can read.
    for (tool, args, message) in [
        ("list_scans", json!({"limit": 0}), "below the minimum"),
        ("list_scans", json!({"limit": 100_000}), "above the maximum"),
        ("list_scans", json!({"limit": "ten"}), "expected integer"),
        (
            "list_scans",
            json!({"surprise": true}),
            "unexpected member surprise",
        ),
        ("list_findings", json!({"min_severity": "loud"}), "allowed"),
        ("device_history", json!({}), "missing required member query"),
        (
            "device_history",
            json!({"query": "x".repeat(65)}),
            "longer than",
        ),
        ("diff_scans", json!({"old_id": 1}), "new_id"),
        ("search_inventory", json!({"query": ""}), "shorter than"),
        (
            "findings_gained",
            json!({"finding_id": "a", "since": []}),
            "string or integer",
        ),
    ] {
        let text = failed(&mut server, tool, args.clone());
        assert!(
            text.starts_with("Invalid arguments"),
            "{tool} {args}: {text}"
        );
        assert!(text.contains(message), "{tool} {args}: {text}");
    }
    remove_db(&db);
}

#[test]
fn the_read_tools_answer_from_the_inventory() {
    let db = fixture("read");
    let mut server = session(&db);

    let scans = ok(&mut server, "list_scans", json!({}), "scans");
    let ids: Vec<i64> = scans["scans"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["id"].as_i64().unwrap())
        .collect();
    assert_eq!(ids, [3, 2, 1], "newest first");
    let one = ok(&mut server, "list_scans", json!({"limit": 1}), "scans");
    assert_eq!(one["scans"].as_array().unwrap().len(), 1);

    let devices = ok(&mut server, "list_devices", json!({}), "devices");
    assert_eq!(devices["total"], 1);
    assert_eq!(devices["truncated"], false);
    assert_eq!(devices["devices"][0]["mac"], "00:0C:29:AA:BB:CC");
    let old = ok(
        &mut server,
        "list_devices",
        json!({"scan_id": 1}),
        "devices",
    );
    assert!(
        !old["devices"][0]["open_tcp"]
            .as_array()
            .unwrap()
            .contains(&json!(23))
    );
    let newest = ok(
        &mut server,
        "list_devices",
        json!({"scan_id": 3}),
        "devices",
    );
    assert!(
        newest["devices"][0]["open_tcp"]
            .as_array()
            .unwrap()
            .contains(&json!(23))
    );
    assert!(
        failed(&mut server, "list_devices", json!({"scan_id": 99})).contains("No scan with ID 99")
    );

    let findings = ok(
        &mut server,
        "list_findings",
        json!({"scan_id": 2}),
        "findings",
    );
    assert!(
        findings["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == "telnet-open")
    );
    let by_id = ok(
        &mut server,
        "list_findings",
        json!({"scan_id": 2, "finding_id": "TELNET-OPEN"}),
        "findings",
    );
    assert!(
        by_id["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["id"] == "telnet-open")
    );
    assert_eq!(by_id["total"], by_id["findings"].as_array().unwrap().len());
    let none = ok(
        &mut server,
        "list_findings",
        json!({"scan_id": 2, "min_severity": "critical"}),
        "findings",
    );
    assert!(none["findings"].as_array().unwrap().is_empty());
    let other_ip = ok(
        &mut server,
        "list_findings",
        json!({"scan_id": 2, "ip": "10.9.9.9"}),
        "findings",
    );
    assert!(other_ip["findings"].as_array().unwrap().is_empty());
    let capped = ok(
        &mut server,
        "list_findings",
        json!({"scan_id": 2, "limit": 1}),
        "findings",
    );
    assert_eq!(capped["findings"].as_array().unwrap().len(), 1);
    assert_eq!(capped["truncated"], capped["total"].as_u64().unwrap() > 1);
    assert!(
        failed(&mut server, "list_findings", json!({"ip": "not an ip"})).contains("Invalid IP")
    );

    let diff = ok(
        &mut server,
        "diff_scans",
        json!({"old_id": 1, "new_id": 2}),
        "diff",
    );
    assert!(diff["summary"]["new_findings"].as_u64().unwrap() >= 1);
    assert!(
        diff["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["kind"] == "port_opened" && c["port"] == 23)
    );
    assert_eq!(diff["truncated"], false);
    let same = ok(
        &mut server,
        "diff_scans",
        json!({"old_id": 2, "new_id": 3}),
        "diff",
    );
    assert_eq!(same["summary"]["new_findings"], 0);
    assert!(
        failed(
            &mut server,
            "diff_scans",
            json!({"old_id": 1, "new_id": 42})
        )
        .contains("No scan with ID 42")
    );

    let history = ok(
        &mut server,
        "device_history",
        json!({"query": "00:0C:29:AA:BB:CC"}),
        "device-history",
    );
    assert_eq!(history["sightings"], 3);
    assert!(
        history["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "port-opened")
    );
    let by_ip = ok(
        &mut server,
        "device_history",
        json!({"query": "10.0.0.1"}),
        "device-history",
    );
    assert_eq!(by_ip["key"], "ip");
    remove_db(&db);
}

#[test]
fn search_finds_where_an_address_name_or_mac_appeared() {
    let db = fixture("search");
    let mut server = session(&db);
    for (query, hostname) in [
        ("10.0.0.1", "plc-1.lab"),
        ("PLC-1", "plc-1.lab"),
        ("00-0c-29-aa-bb-cc", "plc-1.lab"),
        ("000c.29aa.bbcc", "plc-1.lab"),
    ] {
        let found = ok(
            &mut server,
            "search_inventory",
            json!({"query": query}),
            "mcp-where-seen",
        );
        let matches = found["matches"].as_array().unwrap();
        assert_eq!(matches.len(), 3, "{query}: one match per scan");
        assert_eq!(matches[0]["scan_id"], 3, "newest first");
        assert_eq!(matches[0]["hostname"], hostname);
        assert_eq!(matches[0]["source"], "host");
        assert_eq!(
            (
                found["scans_checked"].as_u64(),
                found["scans_total"].as_u64()
            ),
            (Some(3), Some(3))
        );
        assert_eq!(found["truncated"], false);
    }
    // Negatives: another address, a name that is not there, a near-miss MAC.
    for query in ["10.0.0.2", "printer", "00:0C:29:AA:BB:CD", "10.0.0"] {
        let found = ok(
            &mut server,
            "search_inventory",
            json!({"query": query}),
            "mcp-where-seen",
        );
        assert!(found["matches"].as_array().unwrap().is_empty(), "{query}");
    }
    let limited = ok(
        &mut server,
        "search_inventory",
        json!({"query": "10.0.0.1", "limit": 2}),
        "mcp-where-seen",
    );
    assert_eq!(limited["matches"].as_array().unwrap().len(), 2);
    assert_eq!(limited["truncated"], true);
    remove_db(&db);
}

#[test]
fn findings_gained_compares_with_the_last_complete_scan_before_the_date() {
    let db = fixture("gained");
    let mut server = session(&db);
    let gained = |server: &mut Server, id: &str, since: Value| {
        ok(
            server,
            "findings_gained",
            json!({"finding_id": id, "since": since}),
            "mcp-findings-gained",
        )
    };
    // Telnet appeared in scan 2 (2023-11-16); the baseline for 2023-11-15 is scan 1.
    let r = gained(&mut server, "telnet-open", json!("2023-11-15"));
    let hosts = r["hosts"].as_array().unwrap();
    assert_eq!(hosts.len(), 1, "{r}");
    assert_eq!(hosts[0]["ip"], "10.0.0.1");
    assert_eq!(hosts[0]["port"], 23);
    assert_eq!(
        (
            hosts[0]["scan_id"].clone(),
            hosts[0]["baseline_scan_id"].clone()
        ),
        (json!(3), json!(1))
    );
    assert_eq!(r["since_date"], "2023-11-15");
    assert!(r["notes"].as_array().unwrap().is_empty());
    // The same question with the date as Unix seconds, and a case-insensitive id.
    let r2 = gained(&mut server, "TELNET-OPEN", json!(1_700_006_400));
    assert_eq!(r2["hosts"], r["hosts"]);
    // Since a date after the change, the baseline already has the finding: not gained.
    let r = gained(&mut server, "telnet-open", json!("2023-11-18"));
    assert!(r["hosts"].as_array().unwrap().is_empty(), "{r}");
    assert_eq!(r["scopes"][0]["baseline_scan_id"], 2);
    // Another finding the hosts never had.
    let r = gained(&mut server, "smb1-enabled", json!("2023-11-15"));
    assert!(r["hosts"].as_array().unwrap().is_empty());
    // No scan before the date: listed, with the honest note.
    let r = gained(&mut server, "telnet-open", json!("2023-11-01"));
    assert_eq!(r["hosts"].as_array().unwrap().len(), 1);
    assert_eq!(r["hosts"][0]["baseline_scan_id"], Value::Null);
    assert!(r["notes"][0].as_str().unwrap().contains("unknown"), "{r}");
    // No scan after the date: nothing, and the note says why.
    let r = gained(&mut server, "telnet-open", json!("2030-01-01"));
    assert!(
        r["hosts"].as_array().unwrap().is_empty() && r["scopes"].as_array().unwrap().is_empty()
    );
    assert!(
        r["notes"][0].as_str().unwrap().contains("No complete scan"),
        "{r}"
    );
    // Bad dates are refused.
    for bad in [
        "2023-02-30",
        "yesterday",
        "2023-13-01",
        "23-1-1",
        "1960-01-01",
    ] {
        let text = failed(
            &mut server,
            "findings_gained",
            json!({"finding_id": "telnet-open", "since": bad}),
        );
        assert!(
            text.contains("since") || text.contains("calendar date"),
            "{bad}: {text}"
        );
    }
    // A scan that did not complete is never the latest or the baseline.
    let mut partial = nmap_scan("10.0.0.1", SMB1);
    partial.complete = false;
    let id = store::save(&db, &partial).unwrap();
    set_timestamp(&db, id, 1_700_500_000);
    let r = gained(&mut server, "smb1-enabled", json!("2023-11-15"));
    assert!(r["hosts"].as_array().unwrap().is_empty(), "{r}");
    remove_db(&db);
}

#[test]
fn a_missing_database_is_an_empty_inventory_and_is_not_created() {
    let db = temp_db("missing");
    let mut server = session(&db);
    let scans = ok(&mut server, "list_scans", json!({}), "scans");
    assert!(scans["scans"].as_array().unwrap().is_empty());
    let found = ok(
        &mut server,
        "search_inventory",
        json!({"query": "10.0.0.1"}),
        "mcp-where-seen",
    );
    assert!(found["matches"].as_array().unwrap().is_empty());
    let gained = ok(
        &mut server,
        "findings_gained",
        json!({"finding_id": "x", "since": "2023-01-01"}),
        "mcp-findings-gained",
    );
    assert!(gained["hosts"].as_array().unwrap().is_empty());
    for (tool, args) in [
        ("list_devices", json!({})),
        ("list_findings", json!({})),
        ("device_history", json!({"query": "10.0.0.1"})),
        ("diff_scans", json!({"old_id": 1, "new_id": 2})),
    ] {
        assert!(
            failed(&mut server, tool, args).contains("no scans yet"),
            "{tool}"
        );
    }
    assert!(!db.exists(), "reading must not create the database");
}

#[test]
fn the_read_tools_never_change_the_inventory() {
    let db = fixture("readonly");
    let mut server = session(&db);
    for (tool, args) in [
        ("list_scans", json!({})),
        ("list_devices", json!({})),
        ("list_findings", json!({})),
        ("diff_scans", json!({"old_id": 1, "new_id": 2})),
        ("search_inventory", json!({"query": "10.0.0.1"})),
        (
            "findings_gained",
            json!({"finding_id": "telnet-open", "since": "2023-11-15"}),
        ),
    ] {
        assert_eq!(call(&mut server, tool, args)["isError"], false, "{tool}");
    }
    let c = rusqlite::Connection::open(&db).unwrap();
    let n: i64 = c
        .query_row("SELECT COUNT(*) FROM scans", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 3);
    drop(c);
    remove_db(&db);
}

// ---- The scan tool ----------------------------------------------------------------------------

#[test]
fn the_scope_check_works_on_parsed_addresses() {
    let ok = |s: &str| scope_check(&[s.parse().unwrap()], None);
    for private in [
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.1",
        "127.0.0.1",
        "::1",
        "fd12:3456::1",
        "fc00::1",
        "::ffff:10.0.0.1",
        "::ffff:192.168.0.9",
    ] {
        assert!(ok(private).is_ok(), "{private}");
    }
    for public in [
        "8.8.8.8",
        "1.1.1.1",
        "172.32.0.1",
        "172.15.255.255",
        "192.169.0.1",
        "100.64.0.1",
        "169.254.1.1",
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "2001:4860:4860::8888",
        "fe80::1",
        "::ffff:8.8.8.8",
        "::10.0.0.1",
        "::",
    ] {
        let err = ok(public).unwrap_err();
        assert!(err.contains("not a private address"), "{public}: {err}");
    }
    // One public address among private ones refuses the whole list.
    let mixed: Vec<IpAddr> = ["10.0.0.1", "10.0.0.2", "8.8.8.8"]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
    assert!(scope_check(&mixed, None).is_err());
    assert!(scope_check(&[], None).is_ok());
}

#[test]
fn the_scan_tool_refuses_public_oversized_and_unusual_requests() {
    let db = temp_db("refuse");
    let mut server = session(&db);
    for (arguments, message) in [
        (json!({"targets": "8.8.8.8"}), "not a private address"),
        (
            json!({"targets": "10.0.0.1 8.8.8.8"}),
            "not a private address",
        ),
        (
            json!({"targets": "10.0.0.250-10.0.1.5, 1.1.1.1"}),
            "not a private address",
        ),
        (
            json!({"targets": "::ffff:8.8.8.8"}),
            "not a private address",
        ),
        (json!({"targets": "fe80::1"}), "not a private address"),
        (json!({"targets": "172.32.0.0/30"}), "not a private address"),
        (json!({"targets": "example.com"}), "Invalid address"),
        (json!({"targets": "localhost"}), "Invalid address"),
        (json!({"targets": "10.0.0.0/23"}), "256 addresses"),
        (json!({"targets": "10.0.0.0/8"}), "256 addresses"),
        (json!({"targets": "192.168.0.0/16"}), "256 addresses"),
        (
            json!({"targets": "10.0.0.1", "ports": "1-2000"}),
            "limit is 1024",
        ),
        (
            json!({"targets": "10.0.0.1", "ports": "top:100,1000-1999"}),
            "limit is 1024",
        ),
        (
            json!({"targets": "10.0.0.0/24", "ports": "1-100"}),
            "limit is 4000",
        ),
        (
            json!({"targets": "10.0.0.1-50", "ports": "1-1024"}),
            "limit is 4000",
        ),
        (json!({"targets": "10.0.0.1", "ports": "0"}), "Invalid port"),
        (
            json!({"targets": "10.0.0.1", "ports": "abc"}),
            "Invalid port",
        ),
        // Options that would weaken Safe Mode or add traffic do not exist.
        (
            json!({"targets": "10.0.0.1", "fast": true}),
            "unexpected member fast",
        ),
        (
            json!({"targets": "10.0.0.1", "safe": false}),
            "unexpected member safe",
        ),
        (
            json!({"targets": "10.0.0.1", "syn": true}),
            "unexpected member syn",
        ),
        (
            json!({"targets": "10.0.0.1", "ot": true}),
            "unexpected member ot",
        ),
        (
            json!({"targets": "10.0.0.1", "udp": true}),
            "unexpected member udp",
        ),
        (json!({}), "missing required member targets"),
        (json!({"targets": ""}), "shorter than"),
        (
            json!({"targets": "10.0.0.1", "timeout_seconds": 1}),
            "below the minimum",
        ),
        (
            json!({"targets": "10.0.0.1", "timeout_seconds": 100_000}),
            "above the maximum",
        ),
    ] {
        let text = failed(&mut server, "scan", arguments.clone());
        assert!(text.contains(message), "{arguments}: {text}");
    }
    assert!(!db.exists(), "a refused scan saves nothing");
}

/// A session whose server declares `scope`.
fn scoped_session(db: &Path, scope: &str) -> Server {
    let mut server = Server::new(Config {
        scope: Some(crate::scope::Scope::parse(scope).unwrap()),
        ..config(db, true)
    });
    send(
        &mut server,
        "initialize",
        json!({"protocolVersion": LATEST_PROTOCOL}),
    );
    server
}

#[test]
fn the_scan_tool_runs_the_scope_guard_without_consent() {
    let db = temp_db("scope-guard");
    let mut server = scoped_session(&db, "10.5.0.0/16");
    // Private but outside the declared scope: refused, and nothing can override it.
    let text = failed(&mut server, "scan", json!({"targets": "10.9.0.1"}));
    assert!(
        text.contains("Scope guard") && text.contains("cannot override"),
        "{text}"
    );
    assert!(!text.contains("--yes-public"), "{text}");
    // Consent-like arguments are not part of the tool.
    for arguments in [
        json!({"targets": "10.9.0.1", "yes_public": true}),
        json!({"targets": "8.8.8.8", "allow_out_of_scope": true}),
    ] {
        let text = failed(&mut server, "scan", arguments);
        assert!(
            text.contains("unexpected member") || text.contains("not a private address"),
            "{text}"
        );
    }
    // The dry run is refused the same way.
    let text = failed(
        &mut server,
        "scan",
        json!({"targets": "10.9.0.1", "dry_run": true}),
    );
    assert!(text.contains("Scope guard"), "{text}");
    assert!(!db.exists());
    remove_db(&db);
}

#[test]
fn the_scan_tool_can_return_its_plan_and_sends_and_saves_nothing() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let db = temp_db("dry-run");
    let mut server = session(&db);
    let plan = ok(
        &mut server,
        "scan",
        json!({"targets": "127.0.0.1", "ports": port.to_string(), "services": true, "dry_run": true}),
        "dry-run",
    );
    assert_eq!(plan["dry_run"], true);
    assert_eq!(plan["packets_sent"], 0);
    assert_eq!(plan["command"], "scan");
    let kinds: Vec<&str> = plan["groups"][0]["packets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["kind"].as_str().unwrap())
        .collect();
    assert!(
        kinds.contains(&"tcp-connect") && kinds.contains(&"icmp-echo"),
        "{kinds:?}"
    );
    assert!(listener.accept().is_err(), "the dry run connected");
    assert!(!db.exists(), "a dry run saves nothing");
    remove_db(&db);
}

#[test]
fn the_scan_tool_always_runs_in_safe_mode_and_saves_a_summary() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let db = temp_db("scan");
    let mut server = session(&db);
    let summary = ok(
        &mut server,
        "scan",
        json!({"targets": "127.0.0.1", "ports": port.to_string(), "timeout_seconds": 60}),
        "mcp-scan",
    );
    assert_eq!(summary["safe_mode"], true);
    assert_eq!(summary["complete"], true, "{summary}");
    assert_eq!(
        (summary["addresses"].as_u64(), summary["ports"].as_u64()),
        (Some(1), Some(1))
    );
    assert_eq!(summary["responding"], 1);
    assert_eq!(
        summary["open_ports"], 1,
        "the listener's port is open: {summary}"
    );
    assert_eq!(summary["targets"], "127.0.0.1");
    assert!(summary["findings"]["by_severity"].is_object());
    // The result is in the inventory, with settings built from scratch: Safe Mode, none of the
    // opt-in features, the 100 ms probe spacing.
    let id = summary["scan_id"].as_i64().unwrap();
    let saved = store::load(&db, id).unwrap();
    let s = &saved.settings;
    assert!(s.safe && s.delay >= 100, "{s:?}");
    assert!(!s.syn && !s.arp_sweep && !s.arp && !s.ot && !s.udp && !s.trace && !s.os_detect);
    assert!(!s.syn_adaptive && !s.tcp_adaptive && s.scripts.is_empty() && s.probe_file.is_empty());
    assert!(s.interface.is_empty() && s.source_ip.is_empty() && s.max_rate == 0);
    assert!(
        !saved.sent.is_empty(),
        "the sent log is saved with the scan"
    );
    assert_eq!(saved.hosts.len(), 1);
    assert_eq!(saved.hosts[0].open, [port]);
    // The new scan is queryable like any other.
    let scans = ok(&mut server, "list_scans", json!({}), "scans");
    assert_eq!(scans["scans"][0]["id"], id);
    let devices = ok(
        &mut server,
        "list_devices",
        json!({"scan_id": id}),
        "devices",
    );
    assert_eq!(devices["total"], 1);
    drop(listener);
    remove_db(&db);
}

#[test]
fn a_scan_that_runs_out_of_time_is_cancelled_and_saved_as_partial() {
    // 1,000 closed loopback ports at the 100 ms Safe Mode spacing would take minutes; the
    // shortest time limit cuts it, and the saved scan says so.
    let db = temp_db("timeout");
    let mut server = session(&db);
    let started = Instant::now();
    let summary = ok(
        &mut server,
        "scan",
        json!({"targets": "127.0.0.1", "ports": "20000-20999", "timeout_seconds": 10}),
        "mcp-scan",
    );
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(summary["complete"], false, "{summary}");
    assert!(
        summary["notes"][0].as_str().unwrap().contains("time limit"),
        "{summary}"
    );
    assert!(
        !store::load(&db, summary["scan_id"].as_i64().unwrap())
            .unwrap()
            .complete
    );
    remove_db(&db);
}

// ---- Helpers ----------------------------------------------------------------------------------

#[test]
fn dates_parse_strictly() {
    assert_eq!(
        parse_since(&json!("1970-01-01")).unwrap(),
        (0, "1970-01-01".into())
    );
    assert_eq!(
        parse_since(&json!("2023-11-15")).unwrap(),
        (1_700_006_400, "2023-11-15".into())
    );
    assert_eq!(parse_since(&json!("2024-02-29")).unwrap().1, "2024-02-29");
    assert_eq!(parse_since(&json!(1_700_006_400)).unwrap().0, 1_700_006_400);
    assert_eq!(parse_since(&json!("1700006400")).unwrap().0, 1_700_006_400);
    for bad in [
        json!("2023-02-29"),
        json!("2023-04-31"),
        json!("2023-00-10"),
        json!(""),
        json!(null),
        json!(-5),
        json!(1.5),
        json!(true),
        json!("2023/11/15"),
        json!("99999999999999"),
    ] {
        assert!(parse_since(&bad).is_err(), "{bad}");
    }
    assert_eq!(days_from_civil(2000, 3, 1), 11_017);
    assert_eq!(days_from_civil(1970, 1, 1), 0);
}

#[test]
fn the_needle_recognises_addresses_macs_and_names() {
    assert!(matches!(Needle::parse("10.0.0.1"), Needle::Ip(_)));
    assert!(matches!(Needle::parse("fe80::1"), Needle::Ip(_)));
    for mac in [
        "00:0c:29:aa:bb:cc",
        "00-0C-29-AA-BB-CC",
        "000c.29aa.bbcc",
        "000c29aabbcc",
    ] {
        assert!(matches!(Needle::parse(mac), Needle::Mac(_)), "{mac}");
    }
    // Twelve hex digits inside a name are a name; a short hex string is a name too.
    assert!(matches!(Needle::parse("deadbeef-host-0"), Needle::Name(_)));
    assert!(matches!(Needle::parse("cafe"), Needle::Name(_)));
    assert!(Needle::Name("plc".into()).matches(None, "", &["PLC-1.lab"]));
    assert!(!Needle::Name("".into()).matches(None, "", &["x"]));
    assert!(!Needle::Ip("10.0.0.1".parse().unwrap()).matches(None, "", &["10.0.0.1"]));
}
