# MCP server for AI assistants

`network-scope-cli mcp` starts a [Model Context Protocol](https://modelcontextprotocol.io) server on **stdin and stdout**, so an AI assistant (Claude Desktop, Claude Code and other MCP clients) can query your inventory: "which hosts gained SMBv1 since the first of the month?", "when did 192.168.1.20 first appear?", "what changed between scan 12 and 14?". There is no network listener: the client starts the program and talks to it through the pipes.

```sh
network-scope-cli mcp [--db FILE] [--no-scan] [--scope CIDR[,CIDR] | --scope-file FILE]
```

`--db` selects the inventory (default as for every command). `--no-scan` removes the `scan` tool, which leaves a server that only reads. `--scope` / `--scope-file` (or the default `scope.txt` in the config folder) declare the scope the `scan` tool may touch; `--yes-public` and `--allow-out-of-scope` are refused, because an assistant can never confirm anything.

## Setting it up

**Claude Code:**

```sh
claude mcp add network-scope -- network-scope-cli mcp
# a read-only server, with a specific inventory
claude mcp add network-scope -- network-scope-cli mcp --no-scan --db /var/lib/network-scope/inventory.sqlite
```

**Claude Desktop** (`claude_desktop_config.json`, restart the app afterwards; use the full path to `network-scope-cli`):

```json
{
  "mcpServers": {
    "network-scope": {
      "command": "C:\\Program Files\\Network Scope\\network-scope-cli.exe",
      "args": ["mcp", "--db", "C:\\Users\\me\\AppData\\Local\\NetworkScope\\inventory.sqlite"]
    }
  }
}
```

On Linux or macOS the `command` is the path of the binary, for example `/usr/local/bin/network-scope-cli`. The server writes nothing to stdout except protocol messages; problems go to stderr, where the client shows them in its logs.

## Tools

All results are JSON with a `schema` identifier (see [JSON output and schemas](json-output.md)) in `structuredContent`; the same JSON is in the text content for clients that only show text (the specification recommends this for every revision, including 2026-07-28). Lists are capped (`limit`, with small defaults so an answer stays readable for an assistant) and say when they were cut.

| Tool | Arguments | Answers |
| --- | --- | --- |
| `list_scans` | `limit` (default 20) | The saved scans, newest first |
| `list_devices` | `scan_id`, `ip`, `detail`, `limit` (default 50) | One short record per device of a scan (default: the newest; schema `mcp-devices`): addresses, vendor, type, OS, open ports, services. `detail: true` returns the full records (schema `devices`, with evidence, identifiers and passive observations, about ten times larger); combine it with `ip` |
| `device_history` | `query` (MAC or IP) | One device across all saved scans: first/last seen, addresses, events |
| `list_findings` | `scan_id`, `min_severity`, `finding_id`, `ip`, `limit` (default 50) | Findings of a scan, filtered |
| `diff_scans` | `old_id`, `new_id`, `ignore` | What changed between two completed scans of the same targets |
| `search_inventory` | `query` (IP, MAC or hostname part), `limit` (default 50) | Every saved scan in which it appeared (newest 200 scans). A scan that cannot be read (locked or damaged inventory) is counted in `scans_skipped`, sets `truncated` and is explained in `notes`, so it never looks like "not seen there" |
| `findings_gained` | `finding_id`, `since` (`YYYY-MM-DD` or Unix seconds) | Hosts that have the finding in the newest complete scan of their targets but did not in the last complete scan before the date |
| `scan` | `targets`, `ports`, `services`, `dry_run`, `background`, `timeout_seconds` | A Safe Mode scan of a private range, saved to the inventory (omitted with `--no-scan`) |
| `scan_status` | none | The state of the scan started with `background: true` (running, done with its summary, failed, or idle when none was started); sends nothing (omitted with `--no-scan`) |

`findings_gained` is a comparison of two saved scans, so it can only answer for scopes that were scanned before and after the date. When no complete scan of a scope exists before the date, the hosts that have the finding are listed anyway, with `baseline_scan_id: null` and a note that when it appeared is unknown. Scans that did not complete are never used. A host the baseline scan did not cover counts as "gained".

The query tools only read. They never send traffic and never write to the inventory; asking against a database that does not exist reports an empty inventory and does not create the file. They open the inventory read-only, so a write-protected file works too. An inventory saved by an older version is read as it is and is not upgraded (the app upgrades it the next time it saves a scan). `device_history` counts saved scans it could not read in `unreadable`, so a damaged inventory is not mistaken for "not seen".

## The scan tool

`scan` is the only tool that sends network traffic, and it is deliberately narrow:

- **Always Safe Mode.** The scan settings are built inside the server; no argument can switch Safe Mode off, and `fast`, `safe`, `syn`, `udp`, `ot` or any other unknown argument is refused. At most 8 hosts at a time, at least 100 ms between probes, TCP connect only (no SYN, no ARP sweep, no UDP, no OT queries, no traceroute, no scripts). On Windows an address that does not answer ping gets one OS ARP lookup first, and an unused on-link address is not port-probed ([details](scanning-engine.md#unused-addresses-on-the-local-network-windows)). `services` is optional and adds the read-only service identification Safe Mode allows. OT and printer ports are protected by the engine's deny lists as everywhere else.
- **Private addresses only.** RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback and IPv6 unique-local addresses. The check runs on the parsed addresses, not on the text, so every spelling (ranges, CIDR, IPv4-mapped IPv6) is checked; one public address refuses the whole request. Hostnames are not accepted at all. On top of that the engine's [scope guard](safe-mode-and-ot-safety.md) runs in its non-interactive form: with a declared scope, a private address outside it is refused too, and there is no consent flag or prompt that could lift either refusal.
- **`dry_run: true` returns the plan.** The result (schema `dry-run`) lists the packet kinds the scan would send, per group of hosts, and nothing is sent or saved. The scope and size limits apply to a dry run too.
- **Small.** At most 256 addresses (a /24), 1,024 ports (`top:N` and ranges count after expansion), 5,000 probes counted for the worst case (one ping per address and every port tried twice, as a silent port is; Safe Mode spacing makes more than that take longer than a tool call should), and a time limit (`timeout_seconds`, default 50, at most 600; many MCP clients stop waiting for an answer after 60 s, and the session answers nothing else while a scan runs in the call): a scan still running then is cancelled and saved as partial, and the summary says so and names the `timeout_seconds` that would let it finish.
- **`background: true` for longer scans.** The scan starts on its own thread and the call answers at once with the state (schema `mcp-scan-status`); `scan_status` reports it while it runs (elapsed and estimated seconds) and returns the same summary as a scan in the call once it has ended. The session keeps answering queries meanwhile. Without `timeout_seconds` a background scan may run to its estimate plus 10 % (at most 600 s). One scan runs at a time: another `scan` call is refused until it has ended. When the session ends (the client closes the server's input), a running background scan is cancelled and saved as partial before the process exits. The result stays in the process, so a client that restarts the server finds it in `list_scans` instead.
- **`estimated_seconds`.** The dry run and the summary carry a worst-case run time, as if every address were present but silent. It is the larger of two bounds. One is the probes: the count above at 0.12 s each (the 100 ms spacing plus the overhead measured on a real /24). The other is the host slots: Safe Mode works on 8 addresses at a time, and a silent address holds its slot for the ping timeout (2 s), the ARP check on Windows (4.2 s measured) and its port waves (4 ports at a time, 2 tries of 2 s each). With few ports the slots bound it. A /24 with the default 5 ports (254 addresses) is estimated at 336 s on Linux and macOS and 455 s on Windows; one port, 192 s and 327 s. Measured on a real home /24 (Windows): 331 s for 5 ports when every silent address was probed; with unused on-link addresses skipped, 182 s for 5 ports and 173 s for one port (the probe bound alone would have said 122 s). Ask for a dry run first and pass `timeout_seconds` from it when the client waits that long, or use `background`. The model is checked on Windows only; off Windows it assumes the documented timeouts.
- **A summary, not the data.** The result has the new scan ID, whether it completed, counts, the finding counts by severity and the ten most severe findings. Everything else is available through the query tools by scan ID.

A client should ask you before it calls `scan`; most MCP clients prompt before a tool that is not marked read-only (this one is marked as touching the network). Read [Responsible use](responsible-use.md) before scanning networks that are not yours.

## Protocol details

JSON-RPC 2.0, one message per line. The server is *dual-era* in the sense of the 2026-07-28 specification: it serves clients with and without the `initialize` handshake on the same process, and decides per request.

- **Legacy clients (handshake).** `initialize` accepts the revisions 2025-11-25, 2025-06-18, 2025-03-26 and 2024-11-05: the client's version is echoed when supported, otherwise the server answers with 2025-11-25 and the client decides. Implemented: `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`. `tools/list` and `tools/call` before `initialize` get -32002.
- **Modern clients (2026-07-28, stateless).** A request whose `params._meta` carries `io.modelcontextprotocol/protocolVersion` needs no handshake. The version must be 2026-07-28; any other (a handshake revision included) gets error -32022 with `data.supported` (every revision, newest first) and `data.requested`. `io.modelcontextprotocol/clientCapabilities` is required (-32602 without it). Implemented: `server/discover` (supported versions, the `tools` capability, instructions), `tools/list` (with `ttlMs` and `cacheScope`) and `tools/call`; every result carries `resultType: "complete"` and the server info in `_meta`. `ping` is not part of this revision. A modern request never depends on, or opens, a legacy session. Only the version key selects the modern era: legacy clients also send `_meta` (a progress token), and `initialize` is always the handshake.

Not implemented (not advertised): resources, prompts, logging, completion, sampling, subscriptions, progress and cancellation notifications. Tool failures, including arguments that do not fit the input schema, are results with `isError: true` (the assistant can read and correct them); protocol errors use the JSON-RPC codes (-32700 parse error with a null id, -32600 invalid request, -32601 unknown method, -32602 unknown tool or malformed parameters, -32002 legacy request before `initialize`, -32022 unsupported modern version). Lines longer than 1 MiB are refused and skipped; batches (older revisions) are answered as batches, up to 32 messages. A `scan` in the call blocks the process until it ends (requests are handled one at a time); a `background` scan does not.

The tool input schemas are JSON Schema in the default dialect (2020-12, no `$schema`), and tool names use only letters, digits and `_`, as 2025-11-25 recommends; the server validates arguments against the schemas before it runs a tool. The message reader is a parser of untrusted input and has a fuzz target (`mcp_message`).

**What is tested and what is not.** The protocol and every tool are tested in process with scripted JSON-RPC lines (handshake and version negotiation, the modern era without a handshake: `server/discover`, `tools/list`, `tools/call`, unsupported versions and malformed metadata, both eras on one process, errors, batches, oversized and mutated input, every tool against a fixture inventory with the output checked against the schemas, the default `list_devices` size for a full /24) and once as a real process over pipes. On a real home /24 (2026-11-20, Windows) a process over pipes ran `scan` with the default 5 ports: Safe Mode, 336 s, complete, 12 responding hosts; then `list_devices`, `list_findings` and `device_history` for the gateway answered from that scan. That /24 needs `timeout_seconds` of about 400; with the default 50 the same call stopped at 50 s and returned a partial result (`complete: false`, a note saying so, not an error), so expect a partial /24 from clients that stop waiting after 60 s. On 2026-11-21 the same call with the ARP check for unused addresses: 179 s, complete, 13 responding hosts (4 of them drop ping but answer ARP), the same 9 open ports; it sent 254 echoes, 245 neighbor lookups and 91 TCP connects instead of 2,501.

It was also tried with a real client: **Claude Code 2.1.302** (`claude -p` with a temporary `--mcp-config` and `--strict-mcp-config`, a temporary inventory filled by scans of 127.0.0.1, the server started with `--scope 127.0.0.1/32`, every message logged by a pass-through shim). Verified there:

- **Modern era.** Claude Code probes with `server/discover` (version 2026-07-28), then sends `tools/list` and `tools/call` with the version in `_meta` and never sends `initialize`. All eight tools were called this way and answered: `list_scans`, `list_devices`, `device_history`, `list_findings`, `diff_scans`, `search_inventory` (including the whitespace-only query, which came back as the readable tool error), `findings_gained` and `scan`.
- **Legacy fallback.** With `server/discover` refused by the shim, Claude Code falls back to `initialize` with 2025-11-25, the server echoes it, and the tool calls work over the handshake.
- **What the model sees.** The model receives the text content (the JSON as text). `structuredContent` is not passed to the model, so the JSON stays in the text block.
- **Asking before `scan`.** In `claude -p` with only the read-only tools allowed, the `scan` call was denied by Claude Code's permission check and never reached the server. With `scan` allowed, it scanned 127.0.0.1 in Safe Mode and saved the result.

Not tried: Claude Desktop and other MCP clients, Claude Code's interactive permission prompt (only the non-interactive denial was observed), and a long scan against a client's request timeout.
