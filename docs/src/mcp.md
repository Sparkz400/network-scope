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

All results are JSON with a `schema` identifier (see [JSON output and schemas](json-output.md)) in `structuredContent`; the same JSON is in the text content for clients that only show text. Lists are capped (`limit`) and say when they were cut.

| Tool | Arguments | Answers |
| --- | --- | --- |
| `list_scans` | `limit` | The saved scans, newest first |
| `list_devices` | `scan_id`, `limit` | One record per device of a scan (default: the newest) |
| `device_history` | `query` (MAC or IP) | One device across all saved scans: first/last seen, addresses, events |
| `list_findings` | `scan_id`, `min_severity`, `finding_id`, `ip`, `limit` | Findings of a scan, filtered |
| `diff_scans` | `old_id`, `new_id`, `ignore` | What changed between two completed scans of the same targets |
| `search_inventory` | `query` (IP, MAC or hostname part), `limit` | Every saved scan in which it appeared (newest 200 scans) |
| `findings_gained` | `finding_id`, `since` (`YYYY-MM-DD` or Unix seconds) | Hosts that have the finding in the newest complete scan of their targets but did not in the last complete scan before the date |
| `scan` | `targets`, `ports`, `services`, `timeout_seconds` | A Safe Mode scan of a private range, saved to the inventory (omitted with `--no-scan`) |

`findings_gained` is a comparison of two saved scans, so it can only answer for scopes that were scanned before and after the date. When no complete scan of a scope exists before the date, the hosts that have the finding are listed anyway, with `baseline_scan_id: null` and a note that when it appeared is unknown. Scans that did not complete are never used. A host the baseline scan did not cover counts as "gained".

The query tools only read. They never send traffic and never write to the inventory; asking against a database that does not exist reports an empty inventory and does not create the file.

## The scan tool

`scan` is the only tool that sends network traffic, and it is deliberately narrow:

- **Always Safe Mode.** The scan settings are built inside the server; no argument can switch Safe Mode off, and `fast`, `safe`, `syn`, `udp`, `ot` or any other unknown argument is refused. At most 8 hosts at a time, at least 100 ms between probes, TCP connect only (no SYN, no ARP sweep, no UDP, no OT queries, no traceroute, no scripts). `services` is optional and adds the read-only service identification Safe Mode allows. OT and printer ports are protected by the engine's deny lists as everywhere else.
- **Private addresses only.** RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback and IPv6 unique-local addresses. The check runs on the parsed addresses, not on the text, so every spelling (ranges, CIDR, IPv4-mapped IPv6) is checked; one public address refuses the whole request. Hostnames are not accepted at all. On top of that the engine's [scope guard](safe-mode-and-ot-safety.md) runs in its non-interactive form: with a declared scope, a private address outside it is refused too, and there is no consent flag or prompt that could lift either refusal.
- **`dry_run: true` returns the plan.** The result (schema `dry-run`) lists the packet kinds the scan would send, per group of hosts, and nothing is sent or saved. The scope and size limits apply to a dry run too.
- **Small.** At most 256 addresses (a /24), 1,024 ports (`top:N` and ranges count after expansion), 4,000 probes in total (addresses times ports plus one ping each; Safe Mode spacing makes more than that take longer than a tool call should), and a time limit (`timeout_seconds`, default 50, at most 600; many MCP clients stop waiting for an answer after 60 s, and the session answers nothing else while a scan runs): a scan still running then is cancelled and saved as partial, and the summary says so.
- **A summary, not the data.** The result has the new scan ID, whether it completed, counts, the finding counts by severity and the ten most severe findings. Everything else is available through the query tools by scan ID.

A client should ask you before it calls `scan`; most MCP clients prompt before a tool that is not marked read-only (this one is marked as touching the network). Read [Responsible use](responsible-use.md) before scanning networks that are not yours.

## Protocol details

JSON-RPC 2.0, one message per line. `initialize` accepts the protocol revisions 2025-06-18, 2025-03-26 and 2024-11-05: the client's version is echoed when supported, otherwise the server answers with 2025-06-18 and the client decides. Implemented: `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`. Not implemented (not advertised): resources, prompts, logging, completion, sampling, progress and cancellation notifications. Tool failures are results with `isError: true`; protocol errors use the JSON-RPC codes (-32700 parse error with a null id, -32600 invalid request, -32601 unknown method, -32602 unknown tool or bad parameters, -32002 used before `initialize`). Lines longer than 1 MiB are refused and skipped; batches (older revisions) are answered as batches, up to 32 messages. A `scan` blocks the session until it ends (requests are handled one at a time).

The tool input schemas are JSON Schema; the server validates arguments against them before it runs a tool. The message reader is a parser of untrusted input and has a fuzz target (`mcp_message`).

**What is tested and what is not.** The protocol and every tool are tested in process with scripted JSON-RPC lines (handshake and version negotiation, errors, batches, oversized and mutated input, every tool against a fixture inventory with the output checked against the schemas) and once as a real process over pipes. The server has **not** been tried with Claude Desktop, Claude Code or any other real MCP client yet; client-specific behaviour (how a client displays `structuredContent`, whether it asks before `scan`) is unverified.
