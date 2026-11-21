//! A Model Context Protocol (MCP) server over stdio: `network-scope mcp` lets an AI assistant
//! query the local inventory and, optionally, run a small Safe Mode scan. JSON-RPC 2.0 messages
//! arrive one per line on the input and replies leave one per line on the output. There is no
//! network listener, and nothing but protocol messages is ever written to the output.
//!
//! # Protocol
//!
//! The server is "dual-era" (MCP 2026-07-28, *Versioning*). Legacy clients start with
//! `initialize`, which negotiates a handshake revision: the client's requested version is echoed
//! when it is one of [`LEGACY_PROTOCOLS`], otherwise the server answers with
//! [`LATEST_LEGACY_PROTOCOL`] and the client decides whether it can continue. Modern clients send
//! no handshake: a request whose `params._meta` names `io.modelcontextprotocol/protocolVersion`
//! is served statelessly (one of [`MODERN_PROTOCOLS`], or error `-32022` listing the supported
//! versions), its result carries `resultType` and the server info in `_meta`, and
//! `server/discover` answers the versions and capabilities. The era is decided per request, so
//! the handshake state never leaks into a modern request. The only capability is `tools`
//! (`tools/list`, `tools/call`); `ping` works in the legacy era. Notifications get no reply. A line that is
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
//! addresses, ports, total probes and time; with `dry_run: true` it returns the plan and sends
//! nothing, with `background: true` it runs on its own thread and `scan_status` reports it. The server has no consent flags: the engine's scope guard ([`crate::scope::enforce`])
//! runs without a prompt, so a declared scope is binding too. It is absent with `--no-scan`. Every tool result
//! carries a `schema` identifier (see [`crate::schema`]) in its `structuredContent`.
use crate::{devices, risk, scan, schema, store};
use serde_json::{Map, Value, json};
use std::{
    io::{BufRead, Write},
    net::IpAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

/// The newest revision with the `initialize` handshake (the "legacy" era).
pub const LATEST_LEGACY_PROTOCOL: &str = "2025-11-25";
/// Every handshake revision `initialize` accepts; the first is the newest.
pub const LEGACY_PROTOCOLS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
/// Stateless revisions (the "modern" era): no handshake, every request names its version in
/// `params._meta`.
pub const MODERN_PROTOCOLS: &[&str] = &["2026-07-28"];
const VERSION_KEY: &str = "io.modelcontextprotocol/protocolVersion";
const CAPABILITIES_KEY: &str = "io.modelcontextprotocol/clientCapabilities";
/// How long a modern client may cache `server/discover` and `tools/list`: the tool set never
/// changes while the process runs.
const CACHE_TTL_MS: u64 = 3_600_000;
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
/// Most probes in the worst case (`worst_case_probes`): every address silent, so each gets its
/// ping and every port is tried twice. At [`SAFE_PROBE_MS`] this is the [`MAX_SCAN_SECONDS`].
pub const MAX_SCAN_PROBES: u64 = 5000;
/// Measured time per probe in Safe Mode (the 100 ms spacing plus overhead): a home /24 with the
/// default 5 ports sent 2,755 probes in 331 s.
const SAFE_PROBE_MS: u64 = 120;
/// Default and largest wall-clock limit of a `scan` call, in seconds; a scan that is still
/// running then is cancelled and saved as partial. The default stays under the 60 s request
/// timeout many MCP clients use, so the summary arrives instead of being dropped; the session
/// answers nothing else while a scan runs.
const DEFAULT_SCAN_SECONDS: u64 = 50;
const MAX_SCAN_SECONDS: u64 = 600;
/// How long a cancelled scan may take to wind down before the tool stops waiting for it.
const CANCEL_GRACE: Duration = Duration::from_secs(15);
const DEFAULT_SCAN_PORTS: &str = "22,80,443,445,3389";

/// Probes a scan sends when nothing answers: one ping per address (plus the ARP check of a
/// silent one where there is one, `plan::arp_check`), and each port tried `1 + retries` times.
/// An answered port is tried once and an unused on-link address gets no port probes, so real
/// scans send fewer.
fn worst_case_probes(addresses: u64, ports: u64, retries: u32) -> u64 {
    let discovery = 1 + u64::from(crate::platform::NEIGHBOR_SILENCE);
    addresses * (discovery + ports * (1 + u64::from(retries)))
}
/// Measured time of a Windows ARP lookup that gets no answer (`SendARP`, 4.17 s on a home LAN).
const SILENT_ARP_MS: u64 = 4200;

/// The worst-case run time of a Safe Mode scan, in whole seconds: the larger of two bounds.
/// Tokens: every probe at [`SAFE_PROBE_MS`]. Host slots: Safe Mode works on 8 addresses at a
/// time, and a silent address holds its slot for the ping timeout or the ARP check that runs
/// alongside it (Windows), whichever is longer, and then its port waves (4 in parallel, every
/// try waiting the port timeout). With few ports the slots
/// bound it: a /24 with one port sends about 1,000 probes but takes about three minutes.
fn estimated_seconds(addresses: u64, ports: u64, s: &scan::Settings) -> u64 {
    let tokens = worst_case_probes(addresses, ports, s.retries) * SAFE_PROBE_MS;
    let waves = ports.div_ceil(s.port_parallel.clamp(1, 4) as u64);
    let arp = if crate::platform::NEIGHBOR_SILENCE {
        SILENT_ARP_MS
    } else {
        0
    };
    let per_address = u64::from(s.ping_timeout).max(arp)
        + waves * (1 + u64::from(s.retries)) * u64::from(s.port_timeout);
    let slots = addresses.div_ceil(s.workers.clamp(1, 8) as u64) * per_address;
    tokens.max(slots).div_ceil(1000)
}

const SERVER_INSTRUCTIONS: &str = "Read-only queries over a local Network Scope inventory (scans, devices, findings, history), plus a `scan` tool that always runs in Safe Mode, only on private addresses and within small limits. Findings are hints from read-only probes; verify before acting.";

/// What the server may do.
#[derive(Clone, Debug)]
pub struct Config {
    /// The inventory database (read by the query tools, written by `scan`).
    pub db: PathBuf,
    /// Offer the `scan` tool. Off for a strictly read-only server.
    pub allow_scan: bool,
    /// The declared scope (`--scope`, `--scope-file` or the default scope file). When there is
    /// one, the `scan` tool refuses every address outside it. There is no way to override it
    /// from a tool call: the server has no consent flags.
    pub scope: Option<crate::scope::Scope>,
}

/// One MCP session.
pub struct Server {
    cfg: Config,
    initialized: bool,
    /// The scan started with `background: true`, kept until the next one starts.
    job: Option<Job>,
}

/// A background scan: its thread until it ends, then its outcome.
struct Job {
    targets: String,
    started: Instant,
    estimate: u64,
    timeout: u64,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<Result<Value, String>>>,
    outcome: Option<Result<Value, String>>,
}

impl Job {
    /// True while the scan runs; collects its outcome once the thread has ended.
    fn running(&mut self) -> bool {
        if self.thread.as_ref().is_some_and(|t| t.is_finished())
            && let Some(thread) = self.thread.take()
        {
            self.outcome = Some(
                thread
                    .join()
                    .unwrap_or_else(|_| Err("The scan stopped unexpectedly.".into())),
            );
        }
        self.thread.is_some()
    }
}

/// The session ends (input closed): a background scan is cancelled and saved as partial before
/// the process exits, so nothing that was sent goes unrecorded.
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(job) = &mut self.job {
            job.stop.store(true, Ordering::Relaxed);
            if let Some(thread) = job.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

/// A checked scan request, ready to run (in the call or on a background thread).
struct Planned {
    db: PathBuf,
    targets_text: String,
    addresses: Vec<IpAddr>,
    ports: Vec<u16>,
    settings: scan::Settings,
    seconds: u64,
    estimate: u64,
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
            job: None,
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
        // The era is chosen per request (2026-07-28 "dual-era" rules): a request that names its
        // version in `_meta` is served statelessly; anything else, `initialize` above all, follows
        // the handshake. Legacy clients send `_meta` too (progressToken), so only the version key
        // counts.
        let modern_version = params
            .and_then(|p| p.get("_meta"))
            .and_then(|m| m.get(VERSION_KEY))
            .filter(|_| method != "initialize");
        if let Some(version) = modern_version {
            return Some(match self.dispatch_modern(method, params, version) {
                Ok(result) => reply(id, result),
                Err(error) => json!({"jsonrpc": "2.0", "id": id, "error": error}),
            });
        }
        Some(match self.dispatch(method, params) {
            Ok(result) => reply(id, result),
            Err((code, message)) => failure(id, code, &message),
        })
    }

    /// A modern (stateless) request: never reads or changes the handshake state.
    fn dispatch_modern(
        &mut self,
        method: &str,
        params: Option<&Value>,
        version: &Value,
    ) -> Result<Value, Value> {
        let error = |code: i64, message: &str| json!({"code": code, "message": message});
        let version = version
            .as_str()
            .ok_or_else(|| error(-32602, "_meta protocolVersion must be a string"))?;
        if !MODERN_PROTOCOLS.contains(&version) {
            // Also for the handshake revisions: they need `initialize`.
            return Err(json!({
                "code": -32022,
                "message": "Unsupported protocol version",
                "data": {"supported": all_protocols(), "requested": version},
            }));
        }
        let declares_capabilities = params
            .and_then(|p| p.get("_meta"))
            .and_then(|m| m.get(CAPABILITIES_KEY))
            .is_some_and(Value::is_object);
        if !declares_capabilities {
            return Err(error(
                -32602,
                "_meta needs io.modelcontextprotocol/clientCapabilities",
            ));
        }
        let mut result = match method {
            "server/discover" => json!({
                "supportedVersions": all_protocols(),
                "capabilities": {"tools": {}},
                "instructions": SERVER_INSTRUCTIONS,
                "ttlMs": CACHE_TTL_MS,
                "cacheScope": "public",
            }),
            "tools/list" => json!({
                "tools": self.tool_list(),
                "ttlMs": CACHE_TTL_MS,
                "cacheScope": "public",
            }),
            "tools/call" => self
                .call_tool(params)
                .map_err(|(code, message)| error(code, &message))?,
            other => return Err(error(-32601, &format!("Method not found: {other}"))),
        };
        result["resultType"] = json!("complete");
        result["_meta"] = json!({"io.modelcontextprotocol/serverInfo": server_info()});
        Ok(result)
    }

    fn dispatch(&mut self, method: &str, params: Option<&Value>) -> Result<Value, (i64, String)> {
        match method {
            "ping" => Ok(json!({})),
            "initialize" => self.initialize(params),
            "server/discover" => Err((
                -32602,
                format!(
                    "server/discover needs params._meta[\"{VERSION_KEY}\"] (one of {MODERN_PROTOCOLS:?}); legacy clients send initialize"
                ),
            )),
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
        // A stateless revision is never the answer to a handshake.
        let version = LEGACY_PROTOCOLS
            .iter()
            .find(|v| **v == requested)
            .copied()
            .unwrap_or(LATEST_LEGACY_PROTOCOL);
        // Usable from now on: clients that skip the `initialized` notification still work.
        self.initialized = true;
        Ok(json!({
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": server_info(),
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

    fn run_tool(&mut self, name: &str, args: &Value) -> Result<Value, String> {
        match name {
            "list_scans" => self.list_scans(args),
            "list_devices" => self.list_devices(args),
            "device_history" => self.device_history(args),
            "list_findings" => self.list_findings(args),
            "diff_scans" => self.diff_scans(args),
            "search_inventory" => self.search_inventory(args),
            "findings_gained" => self.findings_gained(args),
            "scan" => self.scan(args),
            "scan_status" => self.scan_status(),
            _ => Err(format!("Unknown tool: {name}")),
        }
    }
}

/// Every revision, newest first (the `supported` list of a version error and of
/// `server/discover`).
fn all_protocols() -> Vec<&'static str> {
    MODERN_PROTOCOLS
        .iter()
        .chain(LEGACY_PROTOCOLS)
        .copied()
        .collect()
}
fn server_info() -> Value {
    json!({
        "name": "network-scope",
        "title": "Network Scope",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Network inventory queries and Safe Mode scans of private networks",
    })
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
                input_schema: object_schema(json!({"limit": limit_property(20, 500)}), &[]),
                read_only: true,
            },
            Tool {
                name: "list_devices",
                title: "List devices of a scan",
                description: "One short record per device in a scan (active and passive results merged): addresses, vendor, type, OS, open ports and services. detail: true returns the full records (evidence, identifiers, passive observations), which are much larger: combine it with ip or a small limit.",
                input_schema: object_schema(
                    json!({
                        "scan_id": scan_id_property(),
                        "ip": {"type": "string", "maxLength": 45, "description": "Only the device with this address"},
                        "detail": {"type": "boolean", "default": false,
                            "description": "Full device records instead of the short summary"},
                        "limit": limit_property(50, 500),
                    }),
                    &[],
                ),
                read_only: true,
            },
            Tool {
                name: "device_history",
                title: "History of one device",
                description: "The timeline of one device across all saved scans: first and last seen, addresses, names, open ports and events such as port-opened or ip-changed.",
                input_schema: object_schema(
                    json!({"query": {"type": "string", "minLength": 1, "maxLength": 64,
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
                        "limit": limit_property(50, 1000),
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
                        "limit": limit_property(50, 500),
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
                description: "Scans private IP addresses (RFC 1918, loopback, IPv6 unique-local) with TCP connect probes and saves the result to the inventory. ALWAYS Safe Mode: at most 8 hosts at a time, at least 100 ms between probes, no SYN or ARP tricks, no OT queries. Limits: 256 addresses, 1024 ports, 5000 probes counted for the worst case (one ping per address, every port tried twice), a time limit. Refuses public addresses and hostnames. This sends network traffic.",
                input_schema: object_schema(
                    json!({
                        "targets": {"type": "string", "minLength": 1, "maxLength": 200,
                            "description": "IPv4 addresses, ranges or CIDR, for example 192.168.1.0/24 or 10.0.0.5-20"},
                        "ports": {"type": "string", "maxLength": 200, "default": DEFAULT_SCAN_PORTS,
                            "description": "TCP ports, for example 22,80,443 or 1-1024 (default 22,80,443,445,3389)"},
                        "services": {"type": "boolean", "default": false,
                            "description": "Also identify services on open ports (banners, TLS, SMB); more requests per open port"},
                        "dry_run": {"type": "boolean", "default": false,
                            "description": "Return the plan (which packet kinds would go to which ports) and send and save nothing. The scope and size limits still apply"},
                        "background": {"type": "boolean", "default": false,
                            "description": "Start the scan and answer at once (schema mcp-scan-status); call scan_status for the summary. One scan at a time. Use it when the scan takes longer than the client waits (see estimated_seconds); its time limit then defaults to the estimate plus 10 %"},
                        "timeout_seconds": {"type": "integer", "minimum": 10, "maximum": MAX_SCAN_SECONDS,
                            "default": DEFAULT_SCAN_SECONDS,
                            "description": "Cancel the scan (saved as partial) after this long. A dry run returns estimated_seconds, a worst case (a /24 with the default 5 ports: about 320 to 460 s; real LANs are usually faster). Above about 55 s many clients stop waiting for the answer (the scan is still saved)"},
                    }),
                    &["targets"],
                ),
                read_only: false,
            });
            tools.push(Tool {
                name: "scan_status",
                title: "State of the background scan",
                description: "Whether the scan started with background: true is still running (elapsed and estimated seconds), and its summary (the same as a scan's) once it has ended. Sends nothing.",
                input_schema: object_schema(json!({}), &[]),
                read_only: true,
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
/// The optional `ip` filter.
fn ip_arg(args: &Value) -> Result<Option<IpAddr>, String> {
    text_arg(args, "ip")
        .map(|text| {
            text.trim()
                .parse::<IpAddr>()
                .map_err(|_| format!("Invalid IP address: {text}"))
        })
        .transpose()
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
        Ok((id, self.load(id)?))
    }

    /// A saved scan. Only a missing one is "No scan with ID": a locked or damaged inventory
    /// says what is wrong.
    fn load(&self, id: i64) -> Result<store::Snapshot, String> {
        store::load(&self.cfg.db, id).map_err(|e| {
            if e == rusqlite::Error::QueryReturnedNoRows.to_string() {
                format!("No scan with ID {id}")
            } else {
                format!("Could not read scan {id}: {e}")
            }
        })
    }

    fn list_scans(&self, args: &Value) -> Result<Value, String> {
        let mut scans = self.scans()?;
        scans.truncate(limit_arg(args, 20, 500));
        enveloped("scans", &json!({"scans": scans}))
    }

    fn list_devices(&self, args: &Value) -> Result<Value, String> {
        let ip = ip_arg(args)?;
        let (_, snapshot) = self.snapshot(args)?;
        let all: Vec<devices::Device> = devices::merge(&snapshot.hosts, &snapshot.observations)
            .into_iter()
            .filter(|d| ip.is_none_or(|ip| d.ips.contains(&ip)))
            .collect();
        let limit = limit_arg(args, 50, 500);
        let total = all.len();
        let shown: Vec<_> = all.into_iter().take(limit).collect();
        let truncated = total > limit;
        if args.get("detail").and_then(Value::as_bool) == Some(true) {
            return enveloped(
                "devices",
                &json!({"devices": shown, "total": total, "truncated": truncated}),
            );
        }
        // The full record (evidence, identifiers, passive observations) is about ten times
        // larger; the summary keeps what an assistant needs to pick a device.
        let summaries: Vec<Value> = shown
            .iter()
            .map(|d| {
                json!({
                    "id": d.id, "mac": d.mac, "vendor": d.vendor, "ips": d.ips,
                    "hostnames": d.hostnames, "device_type": d.device_type, "os": d.os,
                    "open_tcp": d.open_tcp, "open_udp": d.open_udp, "services": d.services,
                })
            })
            .collect();
        enveloped(
            "mcp-devices",
            &json!({"devices": summaries, "total": total, "truncated": truncated}),
        )
    }

    fn device_history(&self, args: &Value) -> Result<Value, String> {
        let query = text_arg(args, "query").unwrap_or_default().trim();
        if query.is_empty() {
            return Err(
                "query is empty: give a MAC address (AA:BB:CC:DD:EE:FF) or an IP address".into(),
            );
        }
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
        let ip = ip_arg(args)?;
        let matching: Vec<risk::Finding> = risk::analyze_snapshot(&snapshot)
            .into_iter()
            .filter(|f| f.severity >= min)
            .filter(|f| id.as_ref().is_none_or(|id| f.id.eq_ignore_ascii_case(id)))
            .filter(|f| ip.is_none_or(|ip| f.ip == ip))
            .collect();
        let limit = limit_arg(args, 50, 1000);
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
        let ignore = store::IgnoreList::parse(text_arg(args, "ignore").unwrap_or(""));
        let report = store::diff_report(&self.load(old_id)?, &self.load(new_id)?, &ignore)?;
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
        if query.is_empty() {
            return Err(
                "query is empty: give an IP address, a MAC address or part of a hostname".into(),
            );
        }
        let limit = limit_arg(args, 50, 500);
        let needle = Needle::parse(&query);
        let entries = self.scans()?;
        let scans_total = entries.len();
        let mut matches = vec![];
        let (mut checked, mut skipped) = (0, 0);
        let mut first_error = None;
        let mut truncated = scans_total > SEARCH_SCANS;
        // One connection for every scan read, opened only when there is one (asking never
        // creates the inventory).
        let conn = (!entries.is_empty())
            .then(|| store::open_read(&self.cfg.db))
            .transpose()?;
        'scans: for entry in entries.iter().take(SEARCH_SCANS) {
            let snapshot = match conn.as_ref().map(|c| store::load_on(c, entry.id)) {
                Some(Ok(snapshot)) => snapshot,
                // A locked or damaged scan must not look like "not found": count and report it.
                Some(Err(e)) => {
                    skipped += 1;
                    first_error.get_or_insert(format!("scan {}: {e}", entry.id));
                    continue;
                }
                None => continue,
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
        let mut notes = vec![];
        if let Some(error) = first_error {
            truncated = true;
            notes.push(format!(
                "{skipped} scan(s) could not be read and were not searched, so the result may be incomplete (first error: {error})."
            ));
        }
        enveloped(
            "mcp-where-seen",
            &json!({
                "query": query, "scans_checked": checked, "scans_skipped": skipped,
                "scans_total": scans_total, "truncated": truncated, "matches": matches,
                "notes": notes,
            }),
        )
    }

    fn findings_gained(&self, args: &Value) -> Result<Value, String> {
        let finding_id = text_arg(args, "finding_id")
            .unwrap_or_default()
            .trim()
            .to_string();
        let (since, since_date) = parse_since(args.get("since").unwrap_or(&Value::Null))?;
        // Asked of the database, not of `list_scans` (the newest 500 only): a monitor makes 500
        // scans in under two days and the baseline would seem not to exist.
        let scopes = if self.cfg.db.exists() {
            store::latest_complete_per_scope(&self.cfg.db)?
        } else {
            vec![]
        };
        let matching = |snapshot: &store::Snapshot| -> Vec<risk::Finding> {
            risk::analyze_snapshot(snapshot)
                .into_iter()
                .filter(|f| f.id.eq_ignore_ascii_case(&finding_id))
                .collect()
        };
        let (mut hosts, mut scope_rows, mut notes) = (vec![], vec![], vec![]);
        for (scope, latest_id, latest_timestamp) in scopes {
            // The latest complete scan of the scope must be on or after the date; the baseline
            // is the newest complete one before it.
            if latest_timestamp < since {
                continue;
            }
            let baseline = store::latest_complete_before_time(&self.cfg.db, &scope, since)?;
            let before: Vec<(IpAddr, Option<u16>)> = match baseline {
                Some(b) => matching(&self.load(b)?)
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
            for f in matching(&self.load(latest_id)?) {
                if before.contains(&(f.ip, f.port)) {
                    continue;
                }
                hosts.push(json!({
                    "ip": f.ip, "port": f.port, "severity": f.severity, "title": f.title,
                    "evidence": f.evidence, "scan_id": latest_id,
                    "baseline_scan_id": baseline,
                }));
            }
            scope_rows.push(json!({
                "targets": scope, "latest_scan_id": latest_id,
                "baseline_scan_id": baseline,
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
/// loopback, IPv6 unique-local; an IPv4-mapped IPv6 address counts as its IPv4 address) and, when
/// a scope is declared, inside it. The second part is the engine's scope guard
/// ([`crate::scope::enforce`]) in its non-interactive form, with no consent flags and no prompt:
/// an assistant can never confirm anything, so every address the guard would ask about is
/// refused. Takes the parsed addresses, never the user's text, so spellings and tricks cannot get
/// past it.
pub fn scope_check(
    addresses: &[IpAddr],
    scope: Option<&crate::scope::Scope>,
) -> Result<(), String> {
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
    crate::scope::enforce(addresses, scope, crate::scope::Consent::default(), None)
        .map(|_| ())
        .map_err(|_| {
            format!(
                "Scope guard: {} The scan tool cannot override this: it scans only addresses inside the declared scope (--scope or the scope file of the server).",
                crate::scope::assess(addresses, scope).describe()
            )
        })
}

impl Server {
    fn scan(&mut self, args: &Value) -> Result<Value, String> {
        if !self.cfg.allow_scan {
            return Err(
                "The scan tool is disabled (the server was started with --no-scan).".into(),
            );
        }
        if let Some(job) = &mut self.job
            && job.running()
        {
            return Err(format!(
                "A scan of {} is already running ({} s so far, up to about {} s); call scan_status for its result. One scan runs at a time.",
                job.targets,
                job.started.elapsed().as_secs(),
                job.estimate.min(job.timeout)
            ));
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
        let dry_run = args
            .get("dry_run")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let background = args
            .get("background")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let requested_seconds =
            int_arg(args, "timeout_seconds").and_then(|s| u64::try_from(s).ok());

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
        let retries = scan::Settings::default().retries;
        let probes = worst_case_probes(addresses.len() as u64, ports.len() as u64, retries);
        if probes > MAX_SCAN_PROBES {
            return Err(format!(
                "{} addresses x {} ports can send {probes} probes (a silent port is tried {} times, plus one ping per address); the limit is {MAX_SCAN_PROBES} (Safe Mode spaces probes by 100 ms, so a scan this large takes too long).",
                addresses.len(),
                ports.len(),
                1 + retries
            ));
        }
        let estimate = estimated_seconds(
            addresses.len() as u64,
            ports.len() as u64,
            &scan::Settings::default(),
        );
        // A background scan has no client waiting on it: by default it may run to its estimate.
        let seconds = requested_seconds
            .unwrap_or(if background {
                with_margin(estimate)
            } else {
                DEFAULT_SCAN_SECONDS
            })
            .clamp(10, MAX_SCAN_SECONDS);
        scope_check(&addresses, self.cfg.scope.as_ref())?;

        // Built from scratch: nothing the caller sends can switch Safe Mode off or enable SYN,
        // ARP, UDP, OT queries, traceroute or scripts.
        let settings = scan::Settings {
            ports: ports_text.clone(),
            safe: true,
            delay: 100,
            probes: 1,
            retries,
            scan_nonresponders: true,
            services,
            skip_edges: true,
            ..scan::Settings::default()
        };
        // IPv6 discovery (a multicast echo to the whole link) and SNMP (credentials) are not part
        // of this tool: it reaches only the private addresses the caller names.
        debug_assert!(settings.safe && !settings.syn && !settings.ot && !settings.udp);
        debug_assert!(
            !settings.ipv6_discover && settings.snmp.is_none() && settings.snmp_ref.is_none()
        );
        if dry_run {
            // The same plan the CLI's `scan --dry-run` prints; nothing is sent or saved.
            let probe_db = if services {
                Some(crate::service::ProbeDb::load("")?)
            } else {
                None
            };
            let groups = crate::plan::scan(
                addresses.iter().copied(),
                &ports,
                &settings,
                probe_db.as_ref(),
            );
            return enveloped(
                "dry-run",
                &json!({
                    "dry_run": true,
                    "command": "scan",
                    "packets_sent": 0,
                    "safe_mode": true,
                    "hosts": addresses.len(),
                    "estimated_seconds": estimate,
                    "scope": {"checked": true, "would_need_confirmation": false},
                    "groups": groups,
                }),
            );
        }
        let planned = Planned {
            db: self.cfg.db.clone(),
            targets_text,
            addresses,
            ports,
            settings,
            seconds,
            estimate,
        };
        if !background {
            return execute(planned, &AtomicBool::new(false));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let targets = planned.targets_text.clone();
        let thread = std::thread::Builder::new()
            .name("mcp-scan".into())
            .spawn(move || execute(planned, &flag))
            .map_err(|e| format!("Could not start the scan: {e}"))?;
        self.job = Some(Job {
            targets,
            started: Instant::now(),
            estimate,
            timeout: seconds,
            stop,
            thread: Some(thread),
            outcome: None,
        });
        self.scan_status()
    }

    /// The background scan: running, ended (with the scan's summary) or none.
    fn scan_status(&mut self) -> Result<Value, String> {
        let Some(job) = &mut self.job else {
            return enveloped("mcp-scan-status", &json!({"state": "idle"}));
        };
        let running = job.running();
        let mut status = json!({
            "targets": job.targets,
            "elapsed_seconds": job.started.elapsed().as_secs_f64().round(),
            "estimated_seconds": job.estimate,
            "timeout_seconds": job.timeout,
        });
        match (running, &job.outcome) {
            (true, _) => status["state"] = json!("running"),
            (false, Some(Ok(summary))) => {
                status["state"] = json!("done");
                status["elapsed_seconds"] = summary["duration_seconds"].clone();
                status["summary"] = summary.clone();
            }
            (false, Some(Err(e))) => {
                status["state"] = json!("failed");
                status["error"] = json!(e);
            }
            (false, None) => status["state"] = json!("failed"),
        }
        enveloped("mcp-scan-status", &status)
    }
}

/// A scan time with 10 % margin (the estimate and a real /24 differed by 1.5 %).
fn with_margin(seconds: u64) -> u64 {
    seconds + seconds.div_ceil(10)
}

/// Runs a checked scan until it ends, its time limit passes or `stop` is set, saves it (partial
/// when it did not finish) and returns the summary.
fn execute(p: Planned, stop: &AtomicBool) -> Result<Value, String> {
    let Planned {
        db,
        targets_text,
        addresses,
        ports,
        settings,
        seconds,
        estimate,
    } = p;
    {
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
        let mut cancelled_at: Option<Instant> = None;
        loop {
            // Checked on every turn, not only when the channel is idle: a busy scan still stops.
            let now = Instant::now();
            if stop.load(Ordering::Relaxed) && cancelled_at.is_none() {
                run.cancel.store(true, Ordering::Relaxed);
                cancelled_at = Some(now);
                notes.push("Stopped because the MCP session ended; the result is partial.".into());
                complete = false;
            }
            if now >= deadline && cancelled_at.is_none() {
                run.cancel.store(true, Ordering::Relaxed);
                cancelled_at = Some(now);
                notes.push(format!(
                    "Stopped after the {seconds} s time limit; the result is partial. This scan can take up to {estimate} s; call scan again with timeout_seconds of about {} to let it finish.",
                    with_margin(estimate).clamp(10, MAX_SCAN_SECONDS)
                ));
                complete = false;
                // Drain until the scan reports Done (it ends quickly once cancelled).
            }
            if cancelled_at.is_some_and(|at| now >= at + CANCEL_GRACE) {
                notes.push(format!(
                    "The scan did not stop within {} s of being cancelled; saved what had arrived.",
                    CANCEL_GRACE.as_secs()
                ));
                break;
            }
            match run.receiver.recv_timeout(Duration::from_millis(250)) {
                Ok(scan::Event::Host(h)) => hosts.push(h),
                Ok(scan::Event::Partial(_)) => {}
                Ok(scan::Event::Done) => break,
                Ok(scan::Event::Error(e)) => {
                    notes.push(e);
                    complete = false;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
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
            sent: run.sent.snapshot(),
            targets: targets_text.clone(),
            complete,
            settings: crate::provenance::stamped(&settings),
            hosts,
            observations: vec![],
            notes: Default::default(),
        };
        let scan_id = store::save(&db, &snapshot)?;
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
                "estimated_seconds": estimate,
                "findings": {"total": findings.len(), "by_severity": by_severity},
                "top_findings": top_findings,
                "notes": notes,
            }),
        )
    }
}

#[cfg(test)]
mod tests;
