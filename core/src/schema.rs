//! Versioned JSON output: every JSON document the program prints carries
//! `"schema": "network-scope/<kind>/<version>"` (every JSON Lines record too), and the shape of
//! each kind is described by a hand-written JSON Schema (draft 2020-12) in `docs/schema/`.
//!
//! # Compatibility promise
//!
//! - Adding a field, or a new value of an open-ended field, keeps the version (`v1`). Consumers
//!   must ignore fields they do not know.
//! - Removing or renaming a field, changing a type or the meaning of a field, or changing the
//!   envelope bumps the version (`v2`). For at least one release both are available:
//!   `--json-schema v1` prints the old shape, the default prints the new one.
//! - [`SUPPORTED`] lists the versions this build can print; [`check_version`] rejects others.
//!
//! Lists are wrapped in an object (`{"schema": ..., "findings": [...]}`), because a bare array
//! has no room for the identifier.
//!
//! The module also holds [`validate`], a checker for the small subset of JSON Schema the schema
//! files and the MCP tool input schemas use. It is what the tests validate real output with, so
//! the schemas cannot promise more than the checker verifies: a keyword outside the subset is an
//! error, not silently ignored.
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

/// The version the program prints by default.
pub const CURRENT: &str = "v1";
/// Every version `--json-schema` accepts. The newest one comes last.
pub const SUPPORTED: &[&str] = &["v1"];

/// Every output kind. `docs/schema/<kind>.v1.schema.json` exists for each (a test checks it in
/// both directions).
pub const KINDS: &[&str] = &[
    "scan",
    "host",
    "diff",
    "diff-lines",
    "devices",
    "device-history",
    "findings",
    "scans",
    "alerts",
    "alert",
    "ot-assets",
    "feeds-status",
    "interfaces",
    "mcp-where-seen",
    "mcp-devices",
    "mcp-findings-gained",
    "mcp-scan",
    "mcp-scan-status",
    "changes",
    "baseline",
    "risk-score",
    "import-summary",
    "dry-run",
    "unknown-banners",
    "search",
    "research-query",
    "research-export",
    "research-rebuild",
    "ot-model",
    "ot-alerts",
    "research-groups",
    "segmentation-report",
    "banner-groups",
    "fingerprint-draft",
    "replay-check",
    "scan-event",
];

/// The `schema` value of a kind at the current version.
pub fn id(kind: &str) -> String {
    format!("network-scope/{kind}/{CURRENT}")
}

/// Accepts `v1` (and every other version in [`SUPPORTED`]); the error names the valid ones.
pub fn check_version(requested: &str) -> Result<(), String> {
    if SUPPORTED.contains(&requested) {
        Ok(())
    } else {
        Err(format!(
            "Unsupported --json-schema {requested}; this version prints {}",
            SUPPORTED.join(", ")
        ))
    }
}

#[derive(Serialize)]
struct Envelope<'a, T: Serialize> {
    schema: String,
    #[serde(flatten)]
    body: &'a T,
}

/// A JSON object (a struct or map) with `schema` as its first member.
pub fn object<T: Serialize>(kind: &str, value: &T) -> Result<String, String> {
    serde_json::to_string_pretty(&Envelope {
        schema: id(kind),
        body: value,
    })
    .map_err(|e| e.to_string())
}

/// A list as the member `key` of an object with `schema` as its first member.
pub fn list<T: Serialize>(kind: &str, key: &str, items: &T) -> Result<String, String> {
    object(kind, &BTreeMap::from([(key, items)]))
}

/// One compact line (JSON Lines) with `schema` first, for a stream of records.
pub fn line<T: Serialize>(kind: &str, value: &T) -> Result<String, String> {
    serde_json::to_string(&Envelope {
        schema: id(kind),
        body: value,
    })
    .map_err(|e| e.to_string())
}

// ---- The schema subset checker ------------------------------------------------------------

/// Keywords the checker implements. `$schema`, `$id`, `title`, `description`, `default` and
/// `examples` are annotations. Anything else in a schema is an error.
const KEYWORDS: &[&str] = &[
    "$schema",
    "$id",
    "$defs",
    "$ref",
    "title",
    "description",
    "default",
    "examples",
    "type",
    "properties",
    "required",
    "items",
    "enum",
    "const",
    "minimum",
    "maximum",
    "minItems",
    "maxItems",
    "maxLength",
    "minLength",
    "additionalProperties",
];

/// Checks `value` against `schema`: `type` (one name or a list), `properties`, `required`,
/// `items`, `enum`, `const`, `minimum`, `maximum`, `minItems`, `maxItems`, `maxLength` and
/// `$ref` to `#/$defs/<name>`. Properties that are not listed are allowed (additive changes keep
/// the version). `Err` names the path of the first violation, or the unsupported keyword.
pub fn validate(schema: &Value, value: &Value) -> Result<(), String> {
    check(schema, schema, value, "$", 0)
}

fn check(
    root: &Value,
    schema: &Value,
    value: &Value,
    path: &str,
    depth: usize,
) -> Result<(), String> {
    if depth > 32 {
        return Err(format!("{path}: schema nesting too deep"));
    }
    let Value::Object(map) = schema else {
        return Err(format!("{path}: a schema must be an object"));
    };
    if let Some(unknown) = map.keys().find(|k| !KEYWORDS.contains(&k.as_str())) {
        return Err(format!("{path}: unsupported schema keyword {unknown}"));
    }
    if let Some(target) = map.get("$ref") {
        let name = target
            .as_str()
            .and_then(|r| r.strip_prefix("#/$defs/"))
            .ok_or_else(|| format!("{path}: only #/$defs/<name> references are supported"))?;
        let def = root
            .get("$defs")
            .and_then(|d| d.get(name))
            .ok_or_else(|| format!("{path}: unknown definition {name}"))?;
        return check(root, def, value, path, depth + 1);
    }
    if let Some(t) = map.get("type") {
        let names: Vec<&str> = match t {
            Value::String(s) => vec![s.as_str()],
            Value::Array(a) => a.iter().filter_map(Value::as_str).collect(),
            _ => return Err(format!("{path}: bad type keyword")),
        };
        if !names.iter().any(|n| type_matches(n, value)) {
            return Err(format!(
                "{path}: expected {}, found {}",
                names.join(" or "),
                type_name(value)
            ));
        }
    }
    if let Some(Value::Array(allowed)) = map.get("enum")
        && !allowed.contains(value)
    {
        return Err(format!("{path}: {value} is not one of the allowed values"));
    }
    if let Some(expected) = map.get("const")
        && expected != value
    {
        return Err(format!("{path}: expected {expected}, found {value}"));
    }
    if let (Some(min), Some(n)) = (map.get("minimum").and_then(Value::as_f64), value.as_f64())
        && n < min
    {
        return Err(format!("{path}: {n} is below the minimum {min}"));
    }
    if let (Some(max), Some(n)) = (map.get("maximum").and_then(Value::as_f64), value.as_f64())
        && n > max
    {
        return Err(format!("{path}: {n} is above the maximum {max}"));
    }
    if let (Some(max), Value::String(s)) = (map.get("maxLength").and_then(Value::as_u64), value)
        && s.chars().count() as u64 > max
    {
        return Err(format!("{path}: longer than {max} characters"));
    }
    if let (Some(min), Value::String(s)) = (map.get("minLength").and_then(Value::as_u64), value)
        && (s.chars().count() as u64) < min
    {
        return Err(format!("{path}: shorter than {min} characters"));
    }
    if let Value::Array(items) = value {
        if let Some(min) = map.get("minItems").and_then(Value::as_u64)
            && (items.len() as u64) < min
        {
            return Err(format!("{path}: fewer than {min} items"));
        }
        if let Some(max) = map.get("maxItems").and_then(Value::as_u64)
            && items.len() as u64 > max
        {
            return Err(format!("{path}: more than {max} items"));
        }
        if let Some(item_schema) = map.get("items") {
            for (i, item) in items.iter().enumerate() {
                check(root, item_schema, item, &format!("{path}[{i}]"), depth + 1)?;
            }
        }
    }
    if let Value::Object(members) = value {
        if let Some(Value::Array(required)) = map.get("required") {
            for name in required.iter().filter_map(Value::as_str) {
                if !members.contains_key(name) {
                    return Err(format!("{path}: missing required member {name}"));
                }
            }
        }
        if let Some(Value::Object(properties)) = map.get("properties") {
            for (name, sub) in properties {
                if let Some(member) = members.get(name) {
                    check(root, sub, member, &format!("{path}.{name}"), depth + 1)?;
                }
            }
            match map.get("additionalProperties") {
                None | Some(Value::Bool(true)) => {}
                Some(Value::Bool(false)) => {
                    if let Some(extra) = members.keys().find(|k| !properties.contains_key(*k)) {
                        return Err(format!("{path}: unexpected member {extra}"));
                    }
                }
                Some(_) => {
                    return Err(format!(
                        "{path}: additionalProperties must be true or false"
                    ));
                }
            }
        }
    }
    Ok(())
}

fn type_matches(name: &str, value: &Value) -> bool {
    match name {
        "null" => value.is_null(),
        "boolean" => value.is_boolean(),
        "string" => value.is_string(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        "number" => value.is_number(),
        "integer" => {
            value.is_i64() || value.is_u64() || value.as_f64().is_some_and(|f| f.fract() == 0.0)
        }
        _ => false,
    }
}

fn type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn envelopes_put_the_identifier_first() {
        let text = object("scan", &json!({"hosts": []})).unwrap();
        assert!(
            text.starts_with("{\n  \"schema\": \"network-scope/scan/v1\""),
            "{text}"
        );
        let text = list("findings", "findings", &vec![1, 2]).unwrap();
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["schema"], "network-scope/findings/v1");
        assert_eq!(v["findings"], json!([1, 2]));
        let l = line("alert", &json!({"kind": "x"})).unwrap();
        assert!(
            l.starts_with("{\"schema\":\"network-scope/alert/v1\""),
            "{l}"
        );
        assert!(!l.contains('\n'));
    }

    #[test]
    fn only_listed_versions_are_accepted() {
        assert!(check_version("v1").is_ok());
        let err = check_version("v2").unwrap_err();
        assert!(err.contains("v2") && err.contains("v1"), "{err}");
        assert!(check_version("").is_err());
        assert_eq!(SUPPORTED.last(), Some(&CURRENT));
    }

    use crate::{devices, monitor, nmap, passive::Observation, risk, store};
    use std::path::{Path, PathBuf};

    fn schema_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/schema")
    }
    fn load_schema(kind: &str) -> Value {
        let path = schema_dir().join(format!("{kind}.{CURRENT}.schema.json"));
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{path:?}: {e}"))
    }
    /// Parses `text` (one document, or the first line of JSON Lines) and validates it.
    fn assert_valid(kind: &str, text: &str) -> Value {
        let value: Value = serde_json::from_str(text)
            .or_else(|_| serde_json::from_str(text.lines().next().unwrap_or("")))
            .unwrap();
        validate(&load_schema(kind), &value).unwrap_or_else(|e| panic!("{kind}: {e}\n{text}"));
        assert_eq!(value["schema"], id(kind), "{kind}");
        value
    }
    fn nmap_scan(extra_port: &str) -> store::Snapshot {
        nmap::import(&format!(
            r#"<nmaprun args="nmap -p 22,23 10.0.0.1" start="1700000000"><host><status state="up"/>
            <address addr="10.0.0.1" addrtype="ipv4"/><address addr="00:0C:29:AA:BB:CC" addrtype="mac"/>
            <hostnames><hostname name="plc-1"/></hostnames>
            <ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>{extra_port}</ports>
            </host></nmaprun>"#
        ))
        .unwrap()
    }
    fn ot_assets() -> Vec<crate::otpassive::Asset> {
        let obs = Observation {
            protocol: "S7comm server (observed)".into(),
            mac: "00:00:BC:01:02:03".into(),
            ip: Some("10.0.0.10".parse().unwrap()),
            fields: [
                ("name", "plc-1"),
                ("firmware", "V4.2"),
                ("first_seen", "10"),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        };
        crate::otpassive::assets(&[obs])
    }

    #[test]
    fn schema_files_and_kinds_match_in_both_directions() {
        let mut files: Vec<String> = std::fs::read_dir(schema_dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        files.sort();
        let mut expected: Vec<String> = KINDS
            .iter()
            .map(|k| format!("{k}.{CURRENT}.schema.json"))
            .collect();
        expected.sort();
        assert_eq!(files, expected);
        for kind in KINDS {
            let schema = load_schema(kind);
            assert_eq!(
                schema["$schema"],
                "https://json-schema.org/draft/2020-12/schema"
            );
            assert_eq!(schema["properties"]["schema"]["const"], id(kind), "{kind}");
            assert!(
                schema["required"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("schema")),
                "{kind}: schema must be required"
            );
            // Every schema (and sub-schema) uses only keywords the checker implements.
            let mut stack = vec![(&schema, true)];
            while let Some((v, is_schema)) = stack.pop() {
                match v {
                    Value::Object(m) if is_schema => {
                        for (key, sub) in m {
                            assert!(
                                KEYWORDS.contains(&key.as_str()),
                                "{kind}: unsupported keyword {key}"
                            );
                            match key.as_str() {
                                "properties" | "$defs" => stack
                                    .extend(sub.as_object().unwrap().values().map(|s| (s, true))),
                                "items" => stack.push((sub, true)),
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    #[test]
    fn real_output_validates_against_the_schema_files() {
        let old = nmap_scan("");
        let new = nmap_scan(
            r#"<port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>"#,
        );
        let scan = assert_valid(
            "scan",
            &store::export_at(&new, "json", 1_700_000_000).unwrap(),
        );
        assert_eq!(scan["hosts"][0]["ip"], "10.0.0.1");
        let host = assert_valid(
            "host",
            &store::export_at(&new, "jsonl", 1_700_000_000).unwrap(),
        );
        assert!(
            !host["findings"].as_array().unwrap().is_empty(),
            "telnet is a finding"
        );

        let report = store::diff_report(&old, &new, &store::IgnoreList::new(&[])).unwrap();
        let diff = assert_valid("diff", &store::render_diff(&report, "json").unwrap());
        assert!(diff["summary"]["new_findings"].as_u64().unwrap() >= 1);
        assert_valid("diff-lines", &store::render_diff(&report, "lines").unwrap());

        let found = risk::analyze_snapshot(&new);
        let findings = assert_valid("findings", &list("findings", "findings", &found).unwrap());
        assert!(!findings["findings"].as_array().unwrap().is_empty());
        let devs = devices::merge(&new.hosts, &new.observations);
        let devices = assert_valid("devices", &list("devices", "devices", &devs).unwrap());
        assert_eq!(devices["devices"][0]["mac"], "00:0C:29:AA:BB:CC");

        let ot = ot_assets();
        assert!(!ot.is_empty(), "the fixture must produce an asset");
        assert_valid("ot-assets", &list("ot-assets", "assets", &ot).unwrap());

        let alert = monitor::Alert {
            timestamp: 1_700_000_000,
            severity: risk::Severity::High,
            kind: "new-device".into(),
            subject: "10.0.0.1".into(),
            message: "New device".into(),
        };
        assert_valid("alert", &line("alert", &alert).unwrap());

        let db = std::env::temp_dir().join(format!("ns-schema-{}.sqlite", std::process::id()));
        let _ = std::fs::remove_file(&db);
        let id1 = store::save(&db, &old).unwrap();
        store::save(&db, &new).unwrap();
        store::save_alerts(&db, id1, &[alert]).unwrap();
        let scans = list("scans", "scans", &store::list(&db).unwrap()).unwrap();
        assert_eq!(
            assert_valid("scans", &scans)["scans"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        let alerts = list("alerts", "alerts", &store::list_alerts(&db, 10).unwrap()).unwrap();
        assert_eq!(
            assert_valid("alerts", &alerts)["alerts"][0]["kind"],
            "new-device"
        );
        let history = store::device_history(&db, "00:0C:29:AA:BB:CC").unwrap();
        let text = devices::history_output(&history, "json").unwrap();
        assert_eq!(assert_valid("device-history", &text)["sightings"], 2);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", db.display()));
        }

        let interfaces = list("interfaces", "interfaces", &vec![("eth0", "Ethernet")]).unwrap();
        assert_valid("interfaces", &interfaces);
        let feeds = crate::feeds::status(&crate::feeds::Feeds::default(), Path::new("feeds.json"));
        assert_valid("feeds-status", &serde_json::to_string(&feeds).unwrap());
    }

    #[test]
    fn output_that_breaks_the_schema_is_rejected() {
        let new = nmap_scan("");
        let text = list("findings", "findings", &risk::analyze_snapshot(&new)).unwrap();
        let schema = load_schema("findings");
        let mut v: Value = serde_json::from_str(&text).unwrap();
        assert!(validate(&schema, &v).is_ok());
        v["schema"] = json!("network-scope/findings/v2");
        assert!(validate(&schema, &v).unwrap_err().contains("$.schema"));
        assert!(
            validate(&schema, &json!([])).is_err(),
            "a bare array is not v1"
        );
        let mut v: Value = serde_json::from_str(&text).unwrap();
        v["findings"] = json!([{"severity": "loud"}]);
        assert!(validate(&schema, &v).is_err());
    }

    #[test]
    fn the_checker_implements_the_subset_and_rejects_the_rest() {
        let schema = json!({
            "$defs": {"port": {"type": "integer", "minimum": 1, "maximum": 65535}},
            "type": "object",
            "required": ["schema", "ports"],
            "properties": {
                "schema": {"const": "x/v1"},
                "ports": {"type": "array", "items": {"$ref": "#/$defs/port"}, "maxItems": 2},
                "name": {"type": ["string", "null"], "maxLength": 3},
                "level": {"enum": ["low", "high"]}
            }
        });
        let ok = json!({"schema": "x/v1", "ports": [80, 443], "name": null, "extra": 1});
        assert!(
            validate(&schema, &ok).is_ok(),
            "unknown members are allowed"
        );
        for (bad, why) in [
            (json!([]), "expected object"),
            (json!({"ports": []}), "missing required member schema"),
            (json!({"schema": "x/v2", "ports": []}), "expected"),
            (json!({"schema": "x/v1", "ports": [0]}), "$.ports[0]"),
            (
                json!({"schema": "x/v1", "ports": [1.5]}),
                "expected integer",
            ),
            (json!({"schema": "x/v1", "ports": [1, 2, 3]}), "more than 2"),
            (
                json!({"schema": "x/v1", "ports": [], "name": 5}),
                "string or null",
            ),
            (
                json!({"schema": "x/v1", "ports": [], "name": "long"}),
                "longer",
            ),
            (
                json!({"schema": "x/v1", "ports": [], "level": "mid"}),
                "allowed",
            ),
        ] {
            let err = validate(&schema, &bad).unwrap_err();
            assert!(err.contains(why), "{bad}: {err}");
        }
        // Keywords outside the subset are errors, so a schema cannot promise more than is checked.
        for keyword in ["pattern", "oneOf", "anyOf", "patternProperties", "format"] {
            let schema = json!({ keyword: true });
            let err = validate(&schema, &json!(1)).unwrap_err();
            assert!(err.contains(keyword), "{err}");
        }
        // additionalProperties: false rejects unlisted members (used by the MCP tool inputs).
        let strict = json!({"type": "object", "properties": {"a": {"type": "integer"}}, "additionalProperties": false});
        assert!(validate(&strict, &json!({"a": 1})).is_ok());
        let err = validate(&strict, &json!({"a": 1, "fast": true})).unwrap_err();
        assert!(err.contains("unexpected member fast"), "{err}");
        assert!(
            validate(
                &json!({"properties": {}, "additionalProperties": {}}),
                &json!({})
            )
            .is_err()
        );
        assert!(validate(&json!({"$ref": "http://x"}), &json!(1)).is_err());
        assert!(validate(&json!({"$ref": "#/$defs/nope"}), &json!(1)).is_err());
    }
}
