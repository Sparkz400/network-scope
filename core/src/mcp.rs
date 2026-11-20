//! A Model Context Protocol (MCP) server over stdio: `network-scope mcp` lets an AI assistant
//! query the local inventory and, optionally, run a small Safe Mode scan. JSON-RPC 2.0 messages
//! arrive one per line on the input and replies leave one per line on the output. There is no
//! network listener, and nothing but protocol messages is ever written to the output.
//!
//! # Protocol
//!
//! `initialize` negotiates the protocol revision: the client's requested version is echoed when it
//! is one of [`SUPPORTED_PROTOCOLS`], otherwise the server answers with [`LATEST_PROTOCOL`] and
//! the client decides whether it can continue. The only capability is `tools`
//! (`tools/list`, `tools/call`); `ping` always works. Notifications get no reply. A line that is
//! not JSON gets a `-32700` error with a null id, a malformed message `-32600`, an unknown method
//! `-32601`, bad parameters `-32602`. A failing tool is a *result* with `isError: true` (the
//! assistant can read and react to it), not a protocol error. Batches (allowed by the older
//! revisions) are answered as a batch. Lines are limited to [`MAX_LINE_BYTES`].
//!
//! # Tools
//!
//! Read-only queries over the inventory: `list_scans`, `list_devices`, `device_history`,
//! `list_findings`, `diff_scans`, `search_inventory`, `findings_gained`. They never write and
//! never touch the network. The `scan` tool is the only one that sends traffic. It **always**
//! runs in Safe Mode (the settings are built from scratch; no argument can change that), refuses
//! anything but private addresses ([`scope_check`]), names no hostnames, and is limited in
//! addresses, ports, total probes and time. It is absent with `--no-scan`. Every tool result
//! carries a `schema` identifier (see [`crate::schema`]) in its `structuredContent`.
use crate::{devices, risk, scan, schema, store};
use serde_json::{Map, Value, json};
use std::{
    io::{BufRead, Write},
    net::IpAddr,
    path::PathBuf,
    time::{Duration, Instant},
};

/// The newest protocol revision this server implements.
pub const LATEST_PROTOCOL: &str = "2025-06-18";
/// Every revision the server answers to; the first is the newest.
pub const SUPPORTED_PROTOCOLS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];
/// The longest message line accepted; a longer one is refused and skipped.
pub const MAX_LINE_BYTES: usize = 1 << 20;
/// Messages in one batch.
const MAX_BATCH: usize = 32;
/// A tool result larger than this is replaced by an error asking for narrower filters.
const MAX_RESULT_BYTES: usize = 1 << 20;

/// Most addresses one `scan` call may cover (a /24).
pub const MAX_SCAN_ADDRESSES: u64 = 256;
/// Most ports one `scan` call may probe.
pub const MAX_SCAN_PORTS: usize = 1024;
/// Most probes (addresses x (ports + one ping)). At Safe Mode spacing (100 ms between probes)
/// this is about seven minutes, so it also bounds the run time.
pub const MAX_SCAN_PROBES: u64 = 4000;
/// Default and largest wall-clock limit of a `scan` call, in seconds; a scan that is still
/// running then is cancelled and saved as partial.
const DEFAULT_SCAN_SECONDS: u64 = 240;
const MAX_SCAN_SECONDS: u64 = 600;
const DEFAULT_SCAN_PORTS: &str = "22,80,443,445,3389";

const SERVER_INSTRUCTIONS: &str = "Read-only queries over a local Network Scope inventory (scans, devices, findings, history), plus a `scan` tool that always runs in Safe Mode, only on private addresses and within small limits. Findings are hints from read-only probes; verify before acting.";

/// What the server may do.
#[derive(Clone, Debug)]
pub struct Config {
    /// The inventory database (read by the query tools, written by `scan`).
    pub db: PathBuf,
    /// Offer the `scan` tool. Off for a strictly read-only server.
    pub allow_scan: bool,
}

/// One MCP session.
pub struct Server {
    cfg: Config,
    initialized: bool,
}

// ---- JSON-RPC plumbing ----------------------------------------------------------------------

fn reply(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}
fn failure(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// One line of input.
enum Line {
    Message(Vec<u8>),
    TooLong,
    Eof,
}

/// Reads up to the next newline without ever holding more than [`MAX_LINE_BYTES`]: an oversized
/// line is skipped to its end and reported as [`Line::TooLong`].
fn read_line<R: BufRead>(input: &mut R) -> std::io::Result<Line> {
    let mut line = Vec::new();
    let mut too_long = false;
    loop {
        let chunk = input.fill_buf()?;
        if chunk.is_empty() {
            return Ok(if too_long {
                Line::TooLong
            } else if line.is_empty() {
                Line::Eof
            } else {
                Line::Message(line)
            });
        }
        let end = chunk.iter().position(|&b| b == b'\n');
        let take = end.unwrap_or(chunk.len());
        if !too_long {
            if line.len() + take > MAX_LINE_BYTES {
                too_long = true;
                line = Vec::new();
            } else {
                line.extend_from_slice(&chunk[..take]);
            }
        }
        let used = end.map_or(take, |i| i + 1);
        input.consume(used);
        if end.is_some() {
            return Ok(if too_long {
                Line::TooLong
            } else {
                Line::Message(line)
            });
        }
    }
}

/// Runs a session: reads messages from `input` until it ends and writes the replies to `output`.
pub fn serve<R: BufRead, W: Write>(
    cfg: Config,
    mut input: R,
    output: &mut W,
) -> std::io::Result<()> {
    let mut server = Server::new(cfg);
    loop {
        let reply = match read_line(&mut input)? {
            Line::Eof => return Ok(()),
            Line::TooLong => Some(failure(&Value::Null, -32600, "Request too large").to_string()),
            Line::Message(bytes) => server.handle_line(&bytes),
        };
        if let Some(text) = reply {
            writeln!(output, "{text}")?;
            output.flush()?;
        }
    }
}

impl Server {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            initialized: false,
        }
    }

    /// Handles one line (one message or one batch); `None` when no reply is due.
    pub fn handle_line(&mut self, line: &[u8]) -> Option<String> {
        let text = String::from_utf8_lossy(line);
        let text = text.trim();
        if text.is_empty() {
            return None;
        }
        let reply = match serde_json::from_str::<Value>(text) {
            Err(_) => Some(failure(&Value::Null, -32700, "Parse error")),
            Ok(Value::Array(items)) => {
                if items.is_empty() || items.len() > MAX_BATCH {
                    Some(failure(&Value::Null, -32600, "Invalid batch"))
                } else {
                    let replies: Vec<Value> = items
                        .iter()
                        .filter_map(|m| self.handle_message(m))
                        .collect();
                    (!replies.is_empty()).then_some(Value::Array(replies))
                }
            }
            Ok(message) => self.handle_message(&message),
        };
        reply.map(|r| r.to_string())
    }

    fn handle_message(&mut self, message: &Value) -> Option<Value> {
        let Some(object) = message.as_object() else {
            return Some(failure(&Value::Null, -32600, "Invalid Request"));
        };
        let id = object.get("id");
        // Ids are strings or numbers (null is not allowed in MCP).
        if id.is_some_and(|i| !(i.is_string() || i.is_number())) {
            return Some(failure(&Value::Null, -32600, "Invalid Request: bad id"));
        }
        let Some(method) = object.get("method").and_then(Value::as_str) else {
            // A response to a request we never made, or garbage: only garbage gets an answer.
            let is_response = object.contains_key("result") || object.contains_key("error");
            return (!is_response).then(|| {
                failure(
                    id.unwrap_or(&Value::Null),
                    -32600,
                    "Invalid Request: no method",
                )
            });
        };
        if object.get("jsonrpc") != Some(&json!("2.0")) {
            return id.map(|i| failure(i, -32600, "Invalid Request: jsonrpc must be \"2.0\""));
        }
        let params = object.get("params");
        let Some(id) = id else {
            // A notification: acted on if known, never answered.
            if method == "notifications/initialized" {
                self.initialized = true;
            }
            return None;
        };
        Some(match self.dispatch(method, params) {
            Ok(result) => reply(id, result),
            Err((code, message)) => failure(id, code, &message),
        })
    }

    fn dispatch(&mut self, method: &str, params: Option<&Value>) -> Result<Value, (i64, String)> {
        match method {
            "ping" => Ok(json!({})),
            "initialize" => self.initialize(params),
            "tools/list" | "tools/call" if !self.initialized => Err((
                -32002,
                "Server not initialized: send initialize first".into(),
            )),
            "tools/list" => Ok(json!({"tools": self.tool_list()})),
            "tools/call" => self.call_tool(params),
            other => Err((-32601, format!("Method not found: {other}"))),
        }
    }

    fn initialize(&mut self, params: Option<&Value>) -> Result<Value, (i64, String)> {
        let requested = params
            .and_then(|p| p.get("protocolVersion"))
            .and_then(Value::as_str)
            .ok_or((
                -32602,
                "initialize needs params.protocolVersion".to_string(),
            ))?;
        let version = SUPPORTED_PROTOCOLS
            .iter()
            .find(|v| **v == requested)
            .copied()
            .unwrap_or(LATEST_PROTOCOL);
        // Usable from now on: clients that skip the `initialized` notification still work.
        self.initialized = true;
        Ok(json!({
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": {
                "name": "network-scope",
                "title": "Network Scope",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "instructions": SERVER_INSTRUCTIONS,
        }))
    }

    fn call_tool(&mut self, params: Option<&Value>) -> Result<Value, (i64, String)> {
        let params = params
            .and_then(Value::as_object)
            .ok_or((-32602, "tools/call needs params".to_string()))?;
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or((-32602, "tools/call needs params.name".to_string()))?;
        let empty = Value::Object(Map::new());
        let arguments = params.get("arguments").unwrap_or(&empty);
        if !arguments.is_object() {
            return Err((-32602, "arguments must be an object".into()));
        }
        let tools = self.tools();
        let Some(tool) = tools.iter().find(|t| t.name == name) else {
            if name == "scan" && !self.cfg.allow_scan {
                return Ok(tool_error(
                    "The scan tool is disabled (the server was started with --no-scan).",
                ));
            }
            return Err((-32602, format!("Unknown tool: {name}")));
        };
        if let Err(e) = schema::validate(&tool.input_schema, arguments) {
            return Ok(tool_error(&format!("Invalid arguments: {e}")));
        }
        Ok(match self.run_tool(name, arguments) {
            Ok(value) => tool_result(&value),
            Err(message) => tool_error(&message),
        })
    }

    fn run_tool(&self, name: &str, args: &Value) -> Result<Value, String> {
        match name {
            "list_scans" => self.list_scans(args),
            "list_devices" => self.list_devices(args),
            "device_history" => self.device_history(args),
            "list_findings" => self.list_findings(args),
            "diff_scans" => self.diff_scans(args),
            "search_inventory" => self.search_inventory(args),
            "findings_gained" => self.findings_gained(args),
            "scan" => self.scan(args),
            _ => Err(format!("Unknown tool: {name}")),
        }
    }
}

fn tool_result(value: &Value) -> Value {
    let text = serde_json::to_string(value).unwrap_or_default();
    if text.len() > MAX_RESULT_BYTES {
        return tool_error("The result is too large; narrow it with filters or a lower limit.");
    }
    json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": value,
        "isError": false,
    })
}
fn tool_error(message: &str) -> Value {
    json!({"content": [{"type": "text", "text": message}], "isError": true})
}

// ---- Tool definitions -------------------------------------------------------------------------

struct Tool {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    input_schema: Value,
    read_only: bool,
}

fn limit_property(default: u64, max: u64) -> Value {
    json!({"type": "integer", "minimum": 1, "maximum": max, "default": default,
           "description": format!("Most results to return (default {default}, at most {max})")})
}
fn scan_id_property() -> Value {
    json!({"type": "integer", "minimum": 1,
           "description": "Scan ID from list_scans (default: the newest scan)"})
}
fn object_schema(properties: Value, required: &[&str]) -> Value {
    json!({"type": "object", "properties": properties, "required": required, "additionalProperties": false})
}

impl Server {
    fn tools(&self) -> Vec<Tool> {
        let mut tools = vec![
            Tool {
                name: "list_scans",
                title: "List saved scans",
                description: "The saved scans of the inventory, newest first: ID, time, targets, whether the scan completed and how many hosts it saw.",
                input_schema: object_schema(json!({"limit": limit_property(50, 500)}), &[]),
                read_only: true,
            },
            Tool {
                name: "list_devices",
                title: "List devices of a scan",
                description: "One record per device in a scan (active and passive results merged): addresses, vendor, type, OS, open ports and services.",
                input_schema: object_schema(
                    json!({"scan_id": scan_id_property(), "limit": limit_property(100, 500)}),
                    &[],
                ),
                read_only: true,
            },
            Tool {
                name: "device_history",
                title: "History of one device",
                description: "The timeline of one device across all saved scans: first and last seen, addresses, names, open ports and events such as port-opened or ip-changed.",
                input_schema: object_schema(
                    json!({"query": {"type": "string", "maxLength": 64,
                            "description": "A MAC address or an IP address"}}),
                    &["query"],
                ),
                read_only: true,
            },
            Tool {
                name: "list_findings",
                title: "List findings of a scan",
                description: "Findings (weak TLS or SSH, risky services, CVE hints) of a scan, optionally filtered by minimum severity, finding ID or address.",
                input_schema: object_schema(
                    json!({
                        "scan_id": scan_id_property(),
                        "min_severity": {"enum": ["info", "low", "medium", "high", "critical"], "default": "info"},
                        "finding_id": {"type": "string", "maxLength": 64,
                            "description": "Only this finding rule, for example smb1-enabled or telnet-open"},
                        "ip": {"type": "string", "maxLength": 45, "description": "Only findings of this address"},
                        "limit": limit_property(200, 1000),
                    }),
                    &[],
                ),
                read_only: true,
            },
            Tool {
                name: "diff_scans",
                title: "Compare two scans",
                description: "What changed between two completed scans of the same targets: hosts and ports that appeared or disappeared, changed identity, new, resolved and unconfirmed findings.",
                input_schema: object_schema(
                    json!({
                        "old_id": {"type": "integer", "minimum": 1},
                        "new_id": {"type": "integer", "minimum": 1},
                        "ignore": {"type": "string", "maxLength": 500,
                            "description": "Comma-separated identity keys to ignore (globs such as http.*.title)"},
                    }),
                    &["old_id", "new_id"],
                ),
                read_only: true,
            },
            Tool {
                name: "search_inventory",
                title: "Where did an address or name appear",
                description: "Every saved scan in which an IP address, MAC address or hostname (substring) was seen, with the scan time. Looks at the newest 200 scans.",
                input_schema: object_schema(
                    json!({
                        "query": {"type": "string", "minLength": 1, "maxLength": 100,
                            "description": "An IP address, a MAC address or part of a hostname"},
                        "limit": limit_property(100, 500),
                    }),
                    &["query"],
                ),
                read_only: true,
            },
            Tool {
                name: "findings_gained",
                title: "Hosts that gained a finding since a date",
                description: "Hosts that have the finding in the newest complete scan of their targets but did not have it in the last complete scan before the date. Use it for questions like \"which hosts gained SMBv1 since the first of the month\".",
                input_schema: object_schema(
                    json!({
                        "finding_id": {"type": "string", "minLength": 1, "maxLength": 64,
                            "description": "The finding rule, for example smb1-enabled, telnet-open or tls-cert-expired"},
                        "since": {"type": ["string", "integer"],
                            "description": "A date YYYY-MM-DD (UTC) or Unix seconds"},
                    }),
                    &["finding_id", "since"],
                ),
                read_only: true,
            },
        ];
        if self.cfg.allow_scan {
            tools.push(Tool {
                name: "scan",
                title: "Scan a private network (Safe Mode)",
                description: "Scans private IP addresses (RFC 1918, loopback, IPv6 unique-local) with TCP connect probes and saves the result to the inventory. ALWAYS Safe Mode: at most 8 hosts at a time, at least 100 ms between probes, no SYN or ARP tricks, no OT queries. Limits: 256 addresses, 1024 ports, 4000 probes in total, a time limit. Refuses public addresses and hostnames. This sends network traffic.",
                input_schema: object_schema(
                    json!({
                        "targets": {"type": "string", "minLength": 1, "maxLength": 200,
                            "description": "IPv4 addresses, ranges or CIDR, for example 192.168.1.0/24 or 10.0.0.5-20"},
                        "ports": {"type": "string", "maxLength": 200, "default": DEFAULT_SCAN_PORTS,
                            "description": "TCP ports, for example 22,80,443 or 1-1024 (default 22,80,443,445,3389)"},
                        "services": {"type": "boolean", "default": false,
                            "description": "Also identify services on open ports (banners, TLS, SMB); more requests per open port"},
                        "timeout_seconds": {"type": "integer", "minimum": 10, "maximum": MAX_SCAN_SECONDS,
                            "default": DEFAULT_SCAN_SECONDS,
                            "description": "Cancel the scan (saved as partial) after this long"},
                    }),
                    &["targets"],
                ),
                read_only: false,
            });
        }
        tools
    }

    fn tool_list(&self) -> Vec<Value> {
        self.tools()
            .into_iter()
            .map(|t| {
                json!({
                    "name": t.name,
                    "title": t.title,
                    "description": t.description,
                    "inputSchema": t.input_schema,
                    "annotations": {
                        "title": t.title,
                        "readOnlyHint": t.read_only,
                        "destructiveHint": false,
                        "idempotentHint": t.read_only,
                        "openWorldHint": !t.read_only,
                    },
                })
            })
            .collect()
    }
}

// ---- Argument helpers ---------------------------------------------------------------------------

fn text_arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str)
}
fn int_arg(args: &Value, key: &str) -> Option<i64> {
    args.get(key).and_then(Value::as_i64)
}
fn limit_arg(args: &Value, default: usize, max: usize) -> usize {
    int_arg(args, "limit")
        .and_then(|n| usize::try_from(n).ok())
        .map_or(default, |n| n.clamp(1, max))
}
/// A typed result as a JSON value with its `schema` identifier first.
fn enveloped<T: serde::Serialize>(kind: &str, value: &T) -> Result<Value, String> {
    serde_json::from_str(&schema::object(kind, value)?).map_err(|e| e.to_string())
}

// ---- Read-only tools ----------------------------------------------------------------------------

impl Server {
    /// The saved scans, newest first. A missing database is an empty inventory (and is not
    /// created by asking).
    fn scans(&self) -> Result<Vec<store::Entry>, String> {
        if !self.cfg.db.exists() {
            return Ok(vec![]);
        }
        store::list(&self.cfg.db)
    }

    /// The snapshot of `scan_id`, or of the newest scan.
    fn snapshot(&self, args: &Value) -> Result<(i64, store::Snapshot), String> {
        let id = match int_arg(args, "scan_id") {
            Some(id) => id,
            None => self
                .scans()?
                .first()
                .map(|e| e.id)
                .ok_or("The inventory has no scans yet")?,
        };
        if !self.cfg.db.exists() {
            return Err("The inventory has no scans yet".into());
        }
        let snapshot =
            store::load(&self.cfg.db, id).map_err(|_| format!("No scan with ID {id}"))?;
        Ok((id, snapshot))
    }

    fn list_scans(&self, args: &Value) -> Result<Value, String> {
        let mut scans = self.scans()?;
        scans.truncate(limit_arg(args, 50, 500));
        enveloped("scans", &json!({"scans": scans}))
    }

    fn list_devices(&self, args: &Value) -> Result<Value, String> {
        let (_, snapshot) = self.snapshot(args)?;
        let all = devices::merge(&snapshot.hosts, &snapshot.observations);
        let limit = limit_arg(args, 100, 500);
        let total = all.len();
        let shown: Vec<_> = all.into_iter().take(limit).collect();
        enveloped(
            "devices",
            &json!({"devices": shown, "total": total, "truncated": total > limit}),
        )
    }

    fn device_history(&self, args: &Value) -> Result<Value, String> {
        let query = text_arg(args, "query").unwrap_or_default();
        if !self.cfg.db.exists() {
            return Err("The inventory has no scans yet".into());
        }
        let history = store::device_history(&self.cfg.db, query)?;
        enveloped("device-history", &history)
    }

    fn list_findings(&self, args: &Value) -> Result<Value, String> {
        let (_, snapshot) = self.snapshot(args)?;
        let min = risk::Severity::parse(text_arg(args, "min_severity").unwrap_or("info"))
            .unwrap_or(risk::Severity::Info);
        let id = text_arg(args, "finding_id").map(str::to_ascii_lowercase);
        let ip = match text_arg(args, "ip") {
            Some(text) => Some(
                text.trim()
                    .parse::<IpAddr>()
                    .map_err(|_| format!("Invalid IP address: {text}"))?,
            ),
            None => None,
        };
        let matching: Vec<risk::Finding> = risk::analyze_snapshot(&snapshot)
            .into_iter()
            .filter(|f| f.severity >= min)
            .filter(|f| id.as_ref().is_none_or(|id| f.id.eq_ignore_ascii_case(id)))
            .filter(|f| ip.is_none_or(|ip| f.ip == ip))
            .collect();
        let limit = limit_arg(args, 200, 1000);
        let total = matching.len();
        let shown: Vec<_> = matching.into_iter().take(limit).collect();
        enveloped(
            "findings",
            &json!({"findings": shown, "total": total, "truncated": total > limit}),
        )
    }

    fn diff_scans(&self, args: &Value) -> Result<Value, String> {
        let (old_id, new_id) = (
            int_arg(args, "old_id").unwrap_or(0),
            int_arg(args, "new_id").unwrap_or(0),
        );
        if !self.cfg.db.exists() {
            return Err("The inventory has no scans yet".into());
        }
        let load =
            |id: i64| store::load(&self.cfg.db, id).map_err(|_| format!("No scan with ID {id}"));
        let ignore = store::IgnoreList::parse(text_arg(args, "ignore").unwrap_or(""));
        let report = store::diff_report(&load(old_id)?, &load(new_id)?, &ignore)?;
        let mut value = enveloped("diff", &report)?;
        // Long lists are cut so the answer stays readable; the summary has the full counts.
        let mut truncated = false;
        for key in [
            "changes",
            "new_findings",
            "resolved_findings",
            "unconfirmed_findings",
        ] {
            if let Some(Value::Array(items)) = value.get_mut(key)
                && items.len() > 200
            {
                items.truncate(200);
                truncated = true;
            }
        }
        value["truncated"] = json!(truncated);
        Ok(value)
    }

    fn search_inventory(&self, args: &Value) -> Result<Value, String> {
        let query = text_arg(args, "query")
            .unwrap_or_default()
            .trim()
            .to_string();
        let limit = limit_arg(args, 100, 500);
        let needle = Needle::parse(&query);
        let entries = self.scans()?;
        let scans_total = entries.len();
        let mut matches = vec![];
        let mut checked = 0;
        let mut truncated = scans_total > SEARCH_SCANS;
        'scans: for entry in entries.iter().take(SEARCH_SCANS) {
            let Ok(snapshot) = store::load(&self.cfg.db, entry.id) else {
                continue;
            };
            checked += 1;
            let found = |ip: Option<IpAddr>, mac: &str, hostname: &str, source: &str| {
                json!({
                    "scan_id": entry.id, "timestamp": entry.timestamp, "targets": entry.targets,
                    "ip": ip, "mac": mac, "hostname": hostname, "source": source,
                })
            };
            for h in &snapshot.hosts {
                if needle.matches(Some(h.ip), &h.mac, &[h.hostname.as_str()]) {
                    matches.push(found(Some(h.ip), &h.mac, &h.hostname, "host"));
                }
            }
            for o in &snapshot.observations {
                let names: Vec<&str> = o
                    .fields
                    .iter()
                    .filter(|(k, _)| k.contains("name"))
                    .map(|(_, v)| v.as_str())
                    .collect();
                if needle.matches(o.ip, &o.mac, &names) {
                    matches.push(found(
                        o.ip,
                        &o.mac,
                        names.first().copied().unwrap_or(""),
                        "observation",
                    ));
                }
            }
            if matches.len() >= limit {
                matches.truncate(limit);
                truncated = true;
                break 'scans;
            }
        }
        enveloped(
            "mcp-where-seen",
            &json!({
                "query": query, "scans_checked": checked, "scans_total": scans_total,
                "truncated": truncated, "matches": matches,
            }),
        )
    }

    fn findings_gained(&self, args: &Value) -> Result<Value, String> {
        let finding_id = text_arg(args, "finding_id")
            .unwrap_or_default()
            .trim()
            .to_string();
        let (since, since_date) = parse_since(args.get("since").unwrap_or(&Value::Null))?;
        let entries = self.scans()?;
        let mut scopes: Vec<String> = vec![];
        for e in entries.iter().filter(|e| e.complete) {
            if !scopes.contains(&e.targets) {
                scopes.push(e.targets.clone());
            }
        }
        let matching = |snapshot: &store::Snapshot| -> Vec<risk::Finding> {
            risk::analyze_snapshot(snapshot)
                .into_iter()
                .filter(|f| f.id.eq_ignore_ascii_case(&finding_id))
                .collect()
        };
        let (mut hosts, mut scope_rows, mut notes) = (vec![], vec![], vec![]);
        for scope in scopes {
            // Entries are newest first: the first complete scan of the scope is the latest one;
            // the baseline is the first one that is older than the date.
            let complete = entries.iter().filter(|e| e.complete && e.targets == scope);
            let Some(latest) = complete.clone().next().filter(|e| e.timestamp >= since) else {
                continue;
            };
            let baseline = complete.clone().find(|e| e.timestamp < since);
            let load = |id: i64| store::load(&self.cfg.db, id);
            let before: Vec<(IpAddr, Option<u16>)> = match baseline {
                Some(b) => matching(&load(b.id)?)
                    .iter()
                    .map(|f| (f.ip, f.port))
                    .collect(),
                None => vec![],
            };
            if baseline.is_none() {
                notes.push(format!(
                    "No complete scan of {scope} before {since_date}: every host with the finding is listed, but when it appeared is unknown."
                ));
            }
            for f in matching(&load(latest.id)?) {
                if before.contains(&(f.ip, f.port)) {
                    continue;
                }
                hosts.push(json!({
                    "ip": f.ip, "port": f.port, "severity": f.severity, "title": f.title,
                    "evidence": f.evidence, "scan_id": latest.id,
                    "baseline_scan_id": baseline.map(|b| b.id),
                }));
            }
            scope_rows.push(json!({
                "targets": scope, "latest_scan_id": latest.id,
                "baseline_scan_id": baseline.map(|b| b.id),
            }));
        }
        if scope_rows.is_empty() {
            notes.push(format!(
                "No complete scan was made on or after {since_date}."
            ));
        }
        enveloped(
            "mcp-findings-gained",
            &json!({
                "finding_id": finding_id, "since": since, "since_date": since_date,
                "hosts": hosts, "scopes": scope_rows, "notes": notes,
            }),
        )
    }
}

/// How many of the newest scans `search_inventory` reads.
const SEARCH_SCANS: usize = 200;

/// What `search_inventory` looks for: an address, a MAC (12 hex digits in any notation) or a
/// hostname fragment.
enum Needle {
    Ip(IpAddr),
    Mac(String),
    Name(String),
}
impl Needle {
    fn parse(query: &str) -> Self {
        if let Ok(ip) = query.parse::<IpAddr>() {
            return Self::Ip(ip);
        }
        let hex: String = query.chars().filter(char::is_ascii_hexdigit).collect();
        let separators_only = query
            .chars()
            .all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '-' | '.'));
        if hex.len() == 12 && separators_only {
            return Self::Mac(hex.to_ascii_uppercase());
        }
        Self::Name(query.to_lowercase())
    }
    fn matches(&self, ip: Option<IpAddr>, mac: &str, names: &[&str]) -> bool {
        match self {
            Self::Ip(wanted) => ip == Some(*wanted),
            Self::Mac(wanted) => {
                let hex: String = mac.chars().filter(char::is_ascii_hexdigit).collect();
                hex.eq_ignore_ascii_case(wanted)
            }
            Self::Name(part) => {
                !part.is_empty() && names.iter().any(|n| n.to_lowercase().contains(part))
            }
        }
    }
}

/// `since`: `YYYY-MM-DD` (midnight UTC), a string of digits or an integer (Unix seconds).
fn parse_since(value: &Value) -> Result<(i64, String), String> {
    let bad = || "since must be a date YYYY-MM-DD or Unix seconds".to_string();
    let ts = match value {
        Value::Number(n) => n.as_i64().ok_or_else(bad)?,
        Value::String(s) if !s.is_empty() && s.chars().all(|c| c.is_ascii_digit()) => {
            s.parse().map_err(|_| bad())?
        }
        Value::String(s) => {
            let mut parts = s.trim().splitn(3, '-');
            let mut next = || parts.next().and_then(|p| p.parse::<i64>().ok());
            let (y, m, d) = (
                next().ok_or_else(bad)?,
                next().ok_or_else(bad)?,
                next().ok_or_else(bad)?,
            );
            if !(1970..=2200).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
                return Err(bad());
            }
            let ts = days_from_civil(y, m, d) * 86_400;
            // February 30th and the like roll over into the next month: refuse them.
            if crate::tls::date(ts) != format!("{y:04}-{m:02}-{d:02}") {
                return Err(format!("{s} is not a calendar date"));
            }
            ts
        }
        _ => return Err(bad()),
    };
    if !(0..=7_258_118_400).contains(&ts) {
        return Err(bad());
    }
    Ok((ts, crate::tls::date(ts)))
}

/// Days since 1970-01-01 of a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

// ---- The scan tool ------------------------------------------------------------------------------

/// Whether an unattended assistant may scan these addresses: private ranges only (RFC 1918,
/// loopback, IPv6 unique-local; an IPv4-mapped IPv6 address counts as its IPv4 address). Takes
/// the parsed addresses, never the user's text, so spellings and tricks cannot get past it.
// TODO(H54): call core scope guard
pub fn scope_check(addresses: &[IpAddr]) -> Result<(), String> {
    for address in addresses {
        let address = match address {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(*address, IpAddr::V4),
            v4 => *v4,
        };
        let private = match address {
            IpAddr::V4(v4) => v4.is_private() || v4.is_loopback(),
            IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
        };
        if !private {
            return Err(format!(
                "{address} is not a private address. This tool scans only private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, loopback, IPv6 unique-local)."
            ));
        }
    }
    Ok(())
}

impl Server {
    fn scan(&self, args: &Value) -> Result<Value, String> {
        if !self.cfg.allow_scan {
            return Err(
                "The scan tool is disabled (the server was started with --no-scan).".into(),
            );
        }
        let targets_text = text_arg(args, "targets")
            .unwrap_or_default()
            .trim()
            .to_string();
        let ports_text = text_arg(args, "ports")
            .unwrap_or(DEFAULT_SCAN_PORTS)
            .trim()
            .to_string();
        let services = args
            .get("services")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let seconds = int_arg(args, "timeout_seconds")
            .and_then(|s| u64::try_from(s).ok())
            .unwrap_or(DEFAULT_SCAN_SECONDS)
            .clamp(10, MAX_SCAN_SECONDS);

        // The limits are applied to what the text parses to, not to the text: `top:N`, ranges
        // and CIDR all count. Hostnames do not parse as targets at all.
        let targets = scan::parse_targets(&targets_text, true, MAX_SCAN_ADDRESSES)?;
        let addresses: Vec<IpAddr> = targets.iter().collect();
        let ports = scan::parse_ports(&ports_text)?;
        if ports.len() > MAX_SCAN_PORTS {
            return Err(format!(
                "{} ports requested; the limit is {MAX_SCAN_PORTS}.",
                ports.len()
            ));
        }
        let probes = addresses.len() as u64 * (ports.len() as u64 + 1);
        if probes > MAX_SCAN_PROBES {
            return Err(format!(
                "{} addresses x {} ports would send {probes} probes; the limit is {MAX_SCAN_PROBES} (Safe Mode spaces probes by 100 ms, so a scan this large takes too long).",
                addresses.len(),
                ports.len()
            ));
        }
        scope_check(&addresses)?;

        // Built from scratch: nothing the caller sends can switch Safe Mode off or enable SYN,
        // ARP, UDP, OT queries, traceroute or scripts.
        let settings = scan::Settings {
            ports: ports_text.clone(),
            safe: true,
            delay: 100,
            probes: 1,
            scan_nonresponders: true,
            services,
            skip_edges: true,
            ..scan::Settings::default()
        };
        debug_assert!(settings.safe && !settings.syn && !settings.ot && !settings.udp);
        let started = Instant::now();
        let total = addresses.len();
        let run = scan::start_stream(
            Box::new(addresses.into_iter()),
            total,
            ports.clone(),
            settings.clone(),
        );
        let deadline = started + Duration::from_secs(seconds);
        let (mut hosts, mut notes, mut complete) = (vec![], vec![], true);
        loop {
            match run.receiver.recv_timeout(Duration::from_millis(250)) {
                Ok(scan::Event::Host(h)) => hosts.push(h),
                Ok(scan::Event::Done) => break,
                Ok(scan::Event::Error(e)) => {
                    notes.push(e);
                    complete = false;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if Instant::now() >= deadline
                        && !run.cancel.load(std::sync::atomic::Ordering::Relaxed)
                    {
                        run.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                        notes.push(format!(
                            "Stopped after the {seconds} s time limit; the result is partial."
                        ));
                        complete = false;
                        // Drain until the scan reports Done (it ends quickly once cancelled).
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    notes.push("The scan ended unexpectedly.".into());
                    complete = false;
                    break;
                }
            }
        }
        if run.cancel.load(std::sync::atomic::Ordering::Relaxed) {
            complete = false;
        }
        let snapshot = store::Snapshot {
            sent: vec![],
            targets: targets_text.clone(),
            complete,
            settings,
            hosts,
            observations: vec![],
            notes: Default::default(),
        };
        let scan_id = store::save(&self.cfg.db, &snapshot)?;
        let findings = risk::analyze_snapshot(&snapshot);
        let mut by_severity = Map::new();
        for severity in ["critical", "high", "medium", "low", "info"] {
            let n = findings
                .iter()
                .filter(|f| f.severity.name() == severity)
                .count();
            by_severity.insert(severity.to_string(), json!(n));
        }
        let mut top: Vec<&risk::Finding> = findings.iter().collect();
        top.sort_by_key(|f| std::cmp::Reverse(f.severity));
        let top_findings: Vec<Value> = top
            .iter()
            .take(10)
            .map(|f| json!({"ip": f.ip, "port": f.port, "severity": f.severity, "id": f.id, "title": f.title}))
            .collect();
        enveloped(
            "mcp-scan",
            &json!({
                "scan_id": scan_id,
                "targets": targets_text,
                "complete": complete,
                "safe_mode": true,
                "addresses": total,
                "ports": ports.len(),
                "responding": snapshot.hosts.iter().filter(|h| h.responding).count(),
                "open_ports": snapshot.hosts.iter().map(|h| h.open.len()).sum::<usize>(),
                "duration_seconds": (started.elapsed().as_secs_f64() * 10.0).round() / 10.0,
                "findings": {"total": findings.len(), "by_severity": by_severity},
                "top_findings": top_findings,
                "notes": notes,
            }),
        )
    }
}

#[cfg(test)]
mod tests;
