# CLI reference

On Windows use `network-scope-cli` (console subsystem: shells wait and see the exit code). `network-scope` behaves the same on Linux and macOS. `network-scope-cli --help` prints the built-in summary.

General rules:

- Exit status: see [Exit codes](#exit-codes). `scan`, `listen` and `dcp` save what was collected when an error occurs or the run is stopped early (marked partial) and exit with status 2; errors with nothing collected fail with status 1 without saving. A forced process kill cannot save in-memory work.
- `--quiet` (before or after the command, any command) suppresses progress lines on stderr, including monitor's per-cycle lines; errors still print and the exit status is unchanged.
- `--db FILE` selects the inventory database (default `%LOCALAPPDATA%\NetworkScope\inventory.sqlite` on Windows).
- `--cves FILE` merges extra CVE/CPE rules for any command; see [Findings and CVE hints](findings-and-cves.md).
- `--csaf FILE` selects the CSAF advisory cache (default `csaf.json` next to `feeds.json`); see [CISA ICS advisories](findings-and-cves.md#cisa-ics-advisories-for-ot-devices-csaf-offline).
- `--nvd FILE` selects the NVD cache (default `nvd.json` next to `feeds.json`); see [NVD import](findings-and-cves.md#nvd-import-offline).
- `--feeds FILE` selects the KEV/EPSS cache (default `feeds.json` next to the user `cves.json`); without a cache findings are not enriched. See [Known exploited and EPSS](findings-and-cves.md#known-exploited-and-epss-offline-feeds).
- `--json-schema v1` selects the version of the JSON output format (any command). Every JSON document carries a `schema` member; see [JSON output and schemas](json-output.md).
- `--format` and `--output FILE` select an export where a command produces one. Without `--output` the result is printed to stdout.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Error: bad arguments, I/O, database (also: nothing was saved because the scan or capture failed before collecting anything) |
| 2 | Partial result: a scan or capture stopped early and its results were saved (marked partial in the inventory). Also: the [scope guard](#scope-guard) refused to start because the targets are public or outside the declared scope and nothing confirmed them (nothing was sent or saved; the message on stderr says which) |
| 3 | `findings` / `diff` found something at or above `--min-severity`, **only** when `--fail-on-findings` is given |

Without `--fail-on-findings`, `findings` and `diff` exit 0 however much they report. The flag is an error on any other command (status 1).

What counts as partial (2): `scan` stopped with Q/Esc in the `--tui` view, or ended after errors (for example a terminal failure or a worker that disconnected) with at least some results; `listen` and `dcp` that hit a capture error after observing something. In each case the snapshot is saved with `complete = false` (shown as `partial`), the result is still written to stdout or `--output`, and an error line is printed on stderr. `listen --seconds N` running to the end is a normal, complete run (0). `ot-listen` and `monitor` are not covered by the partial-result code 2 (a scope-guard refusal does apply to `monitor`): `monitor` reports incomplete passive captures as `capture-incomplete` alerts and keeps running, and Ctrl+C or a process kill ends the process without saving (the shell's own status for the signal).

`findings ID --fail-on-findings` exits 3 when at least one finding at or above `--min-severity` (default `info`) is listed. `diff OLD NEW --fail-on-findings` exits 3 when the comparison contains at least one **new** finding at or above `--min-severity` (default `info`). Other changes (hosts or ports appearing, changed identity), resolved findings and findings the new scan did not re-check do not count; use `--format json` and its `summary` for other gates. On `diff`, `--min-severity` only sets this threshold and never filters the output. The output is written in full before the process exits with 3, so stdout still carries the structured result.

```powershell
network-scope-cli findings 3 --min-severity high --fail-on-findings --quiet > findings.json
if ($LASTEXITCODE -eq 3) { "High findings present" }
network-scope-cli diff 2 3 --format json --fail-on-findings --min-severity medium
```

`network-scope` with arguments (the GUI binary) returns the same codes; on Windows its shell does not wait for it, so use `network-scope-cli` in scripts.

## Commands

| Command | Purpose |
| --- | --- |
| *(no arguments)* | Open the desktop GUI |
| `scan TARGETS [options]` | Active scan, saved to SQLite |
| `listen --interface ID [--seconds 60]` | Passive capture only (sends nothing) |
| `dcp --interface ID --source-mac MAC [--seconds 60]` | Read-only Profinet DCP Identify |
| `interfaces` | List capture interfaces |
| `history [--db FILE]` | List saved scans as JSON |
| `diff OLD_ID NEW_ID [--format lines\|json\|text] [--ignore KEY,KEY] [--fail-on-findings [--min-severity SEV]]` | Compare two snapshots |
| `changes [--since last\|7d\|DATE] [--format text\|json]` | New, gone and changed devices and new and resolved risks, see [Inventory](inventory-diff-reports.md#what-changed) |
| `baseline approve [SCAN_ID]` / `enable` / `set DEVICE [...]` / `show` / `remove DEVICE` / `clear` | Approved baseline of expected devices, see [Inventory](inventory-diff-reports.md#approved-baseline) |
| `export ID --format json\|csv\|html\|nmap\|md\|jsonl [--baseline ID] [--output FILE]` | Export a snapshot |
| `export ID --format compliance-iec62443\|compliance-nis2\|compliance-cis [-csv] [--output FILE]` | Asset inventory with findings mapped to IEC 62443, NIS2 Art. 21 or CIS Controls v8 (Markdown, or CSV with the `-csv` suffix); see [Compliance exports](inventory-diff-reports.md#compliance-exports) |
| `export ID --format netbox\|netbox-devices\|snipeit\|splunk\|elastic\|servicenow [--push URL --token-env VAR]` | Export to other systems, optional opt-in push, see [Export](import-export.md#export-to-other-systems) |
| `report ID [--baseline ID] [--output FILE]` | HTML report with charts and map |
| `import FILE.xml` | Import an nmap XML scan into the inventory |
| `import csv\|isc-dhcp\|dnsmasq\|windows-dhcp\|ad-csv\|ad-ldif\|netbox FILE...` | Known devices from a list (offline file, never a scan), see [Import](import-export.md) |
| `findings ID [--min-severity low] [--sort exploited\|severity] [--fail-on-findings]` | Weak TLS/SSH, risky services, CVE hints |
| `feeds import [--kev FILE] [--epss FILE] [--feeds FILE]` | Import CISA KEV (JSON) and FIRST EPSS (plain CSV) files you downloaded; no network access |
| `feeds import nvd FILE... [--nvd FILE]` | Import NVD CVE JSON 2.0 feed files (unpack `.gz` first) into the NVD cache; CPE matches become `cve` findings. No network access |
| `feeds import csaf FILE\|DIR... [--csaf FILE]` | Import CISA ICS advisories (CSAF 2.0 JSON) into the CSAF cache; S7, CIP, Modbus and OPC UA firmware is matched against them. No network access |
| `feeds status [--feeds FILE] [--nvd FILE]` | Show what the feeds cache and the NVD cache hold (JSON) |
| `monitor TARGETS [scan options] --interval 300 [...]` | Repeat scans and alert on changes |
| `service install\|uninstall\|run` | `monitor` as a Windows service, see [Service and scheduling](service-and-scheduling.md) |
| `mcp [--db FILE] [--no-scan]` | MCP server on stdin/stdout for AI assistants, see [MCP server](mcp.md) |
| `alerts [--db FILE]` | Alerts raised by monitor runs |
| `scripts PATH` | Check Rhai scripts (use `--script PATH` with `scan`) |
| `ot-listen --interface ID --seconds N` or `ot-listen --pcap FILE [--progress] [--no-reassembly]` | Passive OT asset discovery |
| `ot-learn --pcap FILE` or `ot-learn --interface ID --seconds N` `[--model FILE] [--no-reassembly]` | Learn normal industrial traffic (peers, functions, rates, hours) from a capture and save the model; receive-only. See [Learning normal traffic](ot-industrial.md#learning-normal-traffic-ot-learn-ot-listen---model) |
| `ot-listen ... --model FILE [--maintenance SPEC] [--format json\|text] [--fail-on-findings]` | Check the traffic against a learned model and print alerts (new station, first write, Stop outside the window, ...) instead of the asset list |
| `ot-assets ID [--format json\|csv]` | OT asset inventory from a passive capture |
| `devices ID [--format json\|csv]` | One record per device (active and passive merged), with its stable device key |
| `devices --history MAC\|IP [--format text\|json]` | Timeline of one device across saved scans |
| `topology ID [--format ascii\|dot]` | Network path map from traceroute data |
| `trace TARGET [--max-hops 20] [--timeout 1000] [--fast --trace-method udp\|tcp --trace-port N]` | Traceroute to one IP |
| `probes [--probes FILE]` | List the TCP and UDP probe database |
| `probes validate FILE` | Load a probe file like a scan with `--probes` would, then lint it; exit 1 on an error |
| `probes lint [FILE]` | Safety lint: OT and printer ports, write-like payloads, payload and regex size, nested quantifiers (default: the built-in probes) |
| `research query "SQL" [--top N] [--format json\|csv\|tsv]` | One read-only SQL statement on the [research tables](research.md); sends nothing |
| `research schema`, `research rebuild` | Document the tables; derive the rows of scans saved before the tables existed |
| `research groups [--top N] [--format text\|json]` | Devices that share a key, certificate template, TLS/SSH stack, web interface or OT firmware across scans and sites; see [Fingerprints you can pivot on](research.md#fingerprints-you-can-pivot-on) |
| `fingerprints favicon FILE` | Shodan-compatible favicon hash (`http.favicon.hash:N`) of a local file; nothing is fetched |
| `research export csv\|ndjson --output DIR` | One file per table (DuckDB layout) and a manifest |
| `research export stix\|ocsf [SCAN_ID] [--output FILE]` | STIX 2.1 bundle or OCSF events of one scan |
| `fingerprints export-unknown [SCAN_ID] [--output FILE]` | Banners of unidentified services from the local store as JSON, without host addresses, to review and redact before sharing; sends nothing. See [Contributing fingerprints](contributing-fingerprints.md) |
| `update check` | Ask GitHub whether a newer release exists; prints the release page and the verification commands. Notify only: it never downloads or installs anything. See [Checking for updates](installation.md#checking-for-updates) |
| `completions powershell\|bash` | Print a shell completion script |
| `help`, `--help`, `-h` | Print the help text |
| `--version`, `-V` | Print the program version |

## Targets

`TARGETS` is an IP address, an IPv4 dash range, a CIDR block, or several of them separated by commas or spaces. Ranges are expanded lazily. The CLI accepts up to 16,777,216 addresses (a /8); above 65,536 only responding hosts are kept in memory and saved. See [Scanning engine](scanning-engine.md#targets) for how network and broadcast addresses are skipped.

Every CLI scan and monitor run also checks the ports of addresses that did not answer ping.

## Scan options

These apply to `scan` and `monitor`.

| Option | Default | Meaning |
| --- | --- | --- |
| `--ports LIST` | `80,443,8080`; with `--ot` and no `--ports`: `80,443,102,502,4840,44818` | TCP ports; `top:N` adds the N most common ports |
| `--top-ports N` | | Add the N most common TCP ports (1-100) |
| `--workers N` | 1024 | Hosts scanned concurrently (1-4096; Safe Mode caps at 8) |
| `--timeout MS` | 2000 | Port and ping timeout (1-10000 ms) |
| `--retries N` | 1 | Extra attempts for unanswered ports (0-5); the timeout doubles each time |
| `--rate PPS` | 0 | Probe rate cap outside Safe Mode (0 = unlimited) |
| `--parallel N` | 64 | Concurrent port probes per host outside Safe Mode (1-1024; Safe Mode: 4) |
| `--tcp-only` | off | Skip ICMP ping |
| `--arp` | off | ARP discovery on the local IPv4 network |
| `--dns` | off | Resolve host names (system DNS) |
| `--ot` | off | Read-only industrial identification (Modbus, S7, EtherNet/IP, BACnet, OPC UA) |
| `--unit N` | 1 | Modbus unit ID |
| `--rack N` / `--slot N` | 0 / 2 | S7 rack and slot |
| `--services` | off | Identify services: banners, HTTP, TLS, SMB, RDP, databases… |
| `--udp` | off | Probe UDP: DNS, DHCP, NTP, NetBIOS, SNMP (community `public`), SSDP, mDNS |
| `--udp-ports LIST` | `53,67,123,137,161,1900,5353` | Replace the UDP port list (implies `--udp`; OT and printer ports are skipped) |
| `--os` | off | OS family, manufacturer (IEEE OUI) and device type guess |
| `--deep` | off | Same as `--services --udp --os` |
| `--trace` | off | Record the router path to each responding host |
| `--max-hops N` | 20 | Traceroute hop limit (1-64) |
| `--trace-method icmp\|tcp\|udp` | icmp | Traceroute method (implies `--trace`; tcp/udp only with `--fast`) |
| `--trace-port N` | first open port | TCP traceroute port (never OT or printer ports) |
| `--probes FILE` | | Extra service probes (TCP and UDP), merged over `data/probes.json` by name |
| `--script PATH` | | Rhai script, or folder of `.rhai` files, run against every host |
| `--fast` | off | Leave Safe Mode (read-only OT still applies) |
| `--syn` | off | IPv4 SYN scan via Npcap/libpcap (routed targets via the gateway MAC); else TCP connect |
| `--adaptive-syn` | off | RTT-based SYN reply windows and congestion window (with `--syn --fast`) |
| `--adaptive-tcp` | off | Per-host TCP connect timeout from the host's measured connect RTT; only shortens waits (also in Safe Mode) |
| `--jarm` | off | JARM-style TLS fingerprint: ten extra ClientHellos per TLS port (needs `--services` and `--fast`; ignored in Safe Mode; not verified against the reference JARM, see [Detection](detection.md)) |
| `--no-backoff` | off | Turn off the [automatic back-off](scanning-engine.md#automatic-back-off) (on by default; it only ever slows a host down) |
| `--arp-sweep` | off | Fast ARP sweep through the capture interface (with `--fast`; needs Npcap/libpcap) |
| `--interface ID` | | Capture interface (see `interfaces`); required for SYN, ARP sweep, TCP trace, capture |
| `--source-ip IPV4` / `--source-mac MAC` | | Source addresses of that interface |
| `--tui` | off | Live terminal view |
| `--format FMT` / `--output FILE` | json | Also write an export of the finished scan |
| `--db FILE` | | Inventory database |
| `--dry-run` | off | Print, per host, exactly which packet types the command would send, and send nothing (see [Dry run and sent log](#dry-run-and-sent-log)); `scan`, `monitor`, `trace`, `dcp` |
| `--sent-log` | off | Print the packets the run actually sent, by kind and detail, on stderr; `scan`, `trace`, `dcp` |
| `--scope CIDR[,CIDR...]` | | Declared scope: CIDR blocks, addresses or ranges that may be scanned (see [Scope guard](#scope-guard)) |
| `--scope-file FILE` | `scope.txt` in the config folder | Read the declared scope from a file instead |
| `--yes-public` | off | Confirm that public addresses may be scanned |
| `--allow-out-of-scope` | off | Confirm that addresses outside the declared scope may be scanned (also covers public ones) |

TUI keys: Space pauses/resumes; Q, q or Escape stops and saves a partial result; Up/Down/PgUp/PgDn/Home/End select a row; Enter shows the host's ports, services, findings and identity fields (Enter or Backspace returns); S cycles the sort order (newest, address, open ports).

## Scope guard

Before `scan`, `monitor`, `trace` or the desktop Start button send anything, the targets are checked (nothing is expanded, a /8 is judged as a range):

- **Public addresses** are everything except RFC 1918 (`10/8`, `172.16/12`, `192.168/16`), carrier-grade NAT (`100.64/10`), loopback, link-local (`169.254/16`, `fe80::/10`), unique local (`fc00::/7`) and "this host" (`0/8`, `::`). An IPv4-mapped IPv6 address counts as its IPv4 address.
- A **declared scope** is a list of CIDR blocks, addresses and ranges, from `--scope 10.0.0.0/8,192.168.1.0/24`, `--scope-file FILE` or the default file `scope.txt` in the config folder (`%LOCALAPPDATA%/NetworkScope/` on Windows, one entry per line or comma separated, `#` starts a comment). Without a scope only the public-address rule applies. With a scope, every address outside it needs confirmation, and a public address inside it does not.

On a terminal the CLI describes what it found and asks `Scan anyway? Type yes to continue`. Anything else (a script, a pipe, `monitor` under a service manager) refuses with exit status 2 unless the flags are given: `--yes-public` for public addresses, `--allow-out-of-scope` for addresses outside the declared scope (it covers public addresses too). The desktop shows a confirmation dialog before the scan starts; it reads the same scope file. A refusal sends nothing and saves nothing.

## Dry run and sent log

`--dry-run` (on `scan`, `monitor`, `trace` and `dcp`) lists what the command would send and stops: no socket is opened, no capture driver is loaded, nothing is saved, and the exit status is 0. Hosts with the same plan are grouped (IPv4 and IPv6 hosts differ), so a /8 is described in a few lines. Each line is `kind  detail -> where [when]`:

```text
$ network-scope-cli scan 192.168.1.0/30 --ports 22,445,502 --deep --ot --fast --dry-run
DRY RUN: nothing was sent.
Mode: --fast

ipv4 2 host(s), 192.168.1.1 ... 192.168.1.2
  icmp-echo        echo request -> the host [1 per host]
  tcp-connect      port scan -> tcp/22,445,502 [always; up to 2 attempt(s) per unanswered port]
  smb-negotiate    NTLM SESSION_SETUP (no AUTHENTICATE) -> tcp/445 [not in Safe Mode]
  ot-request       Modbus/TCP: function 0x2B, MEI type 0x0E (Read Device Identification) -> tcp/502 [only if tcp/502 was found open]
  ...
```

The packet kinds are `icmp-echo`, `arp-request`, `neighbor-lookup`, `tcp-connect`, `tcp-syn`, `udp-probe`, `service-probe`, `http-request`, `tls-client-hello`, `smb-negotiate`, `rdp-negotiate`, `ssh-banner`, `ot-request` (with the protocol, service and function code), `dcp-identify`, `traceroute`, `dhcp-discover` and `dns-ptr` (the reverse lookup goes to your resolver, not to the host). `--format json` prints the same plan as JSON (`dry_run`, `packets_sent: 0`, `groups`, and the scope verdict). The plan is built from the same conditions and allow-lists the scanner uses (a test runs a real scan and checks that everything it sent was in the plan), and a dry run does not need scope confirmation: it prints what a real run would ask instead.

Every scan also keeps a **sent log**: a counter per `(kind, detail)` of the packets it really sent (a port scan counts under `tcp-connect` / `port scan`, a UDP probe under `udp-probe` / `dns/53`, an OT request under its protocol and function code). It is stored with the scan (the `sent` array of the JSON export, `export ID --format json`), shown in the desktop by hovering the status line after a scan, and printed by `--sent-log`:

```text
Packets sent: 24
          2  icmp-echo        echo request
         14  tcp-connect      port scan
          8  udp-probe        dns/53
```

## Export formats

`--format json|csv|html|nmap|md|jsonl` for `scan` and `export` (`export` also takes `compliance-iec62443|compliance-nis2|compliance-cis`, with `-csv` for CSV):

| Format | Content |
| --- | --- |
| `json` | Full snapshot |
| `csv` | One row per host; cells starting with `=`, `+`, `-`, `@`, TAB or CR get a leading `'` (purely numeric cells such as `-1` are unchanged) |
| `html` | Same as `report`: self-contained HTML report |
| `md` | Markdown summary (scope, totals, findings, findings by host, devices, changes since `--baseline`) |
| `jsonl` | One JSON object per responding host |
| `nmap` | nmap-compatible XML |

Exports from `scan`, `listen`, `dcp` and `export` carry the stored scan time. Details in [Inventory, diffs and reports](inventory-diff-reports.md).

## diff options

| Option | Meaning |
| --- | --- |
| `--format lines` (default) | JSON object with the change lines (`lines`) |
| `--format json` | Structured report for CI and monitors |
| `--format text` | Plain lines |
| `--ignore K,K` | Extra ignored keys: exact keys, globs (`http.*.title`) or suffixes (`.server`) |
| `--fail-on-findings` | Exit 3 when a new finding at or above `--min-severity` appeared; see [Exit codes](#exit-codes) |
| `--min-severity SEV` | Threshold for `--fail-on-findings` (default `info`); does not filter the output |

## findings options

`--top N` (1 to 1000) prints the network risk score, the riskiest hosts and the N things to fix first instead of the list (`--format text|json`, default text; see [Risk score and fix list](findings-and-cves.md#risk-score-and-fix-list)), `--min-severity info|low|medium|high|critical` (default `info`), `--cves FILE`, `--feeds FILE`, `--fail-on-findings` (exit 3 when anything at or above the threshold is listed; see [Exit codes](#exit-codes)), `--sort exploited|severity` (default `exploited`: known exploited first, then severity, then EPSS, when feeds are imported; the same as `severity` without feeds).

## feeds options

`feeds import` needs `--kev FILE` (`known_exploited_vulnerabilities.json`) and/or `--epss FILE` (plain CSV; run `gunzip` on the `.csv.gz` first). The part not given keeps its previous content. `--feeds FILE` writes to another cache file.

## monitor options

All scan options, plus:

| Option | Default | Meaning |
| --- | --- | --- |
| `--interval S` | 300 | Seconds between cycles (1-86400) |
| `--cycles N` | 0 (endless) | Number of cycles |
| `--learn` | off | Record devices without alerting |
| `--min-severity SEV` | | Minimum alert severity |
| `--report-missing` | off | Alert when a known device is not seen |
| `--alerts FILE` | | Append alerts as JSON lines |
| `--dhcp-allow IP,IP` | | Legitimate DHCP servers |
| `--dhcp-discover` | off | Broadcast one DHCPDISCOVER per cycle and collect offers |
| `--interface ID` / `--listen-seconds N` | 30 | Passive DHCP listening per cycle |
| `--webhook http(s)://URL,...` | | POST alerts as JSON; HTTPS is verified against the OS certificate store |
| `--syslog [udp://\|tcp://]HOST[:PORT],...` | | RFC 5424 syslog |
| `--alert-timeout S` | 5 | Per-operation alert delivery timeout (1-60) |
| `--no-dedup` | off | Alert every cycle |
| `--renotify-hours H` | 24 | Re-alert a persisting condition after H hours (0 = only after it resolved) |
| `--on-alert SCRIPT` | | Run a Rhai script for every alert that fires (a `.rhai` file or `library:NAME`); see [Scripts that run on an alert](scripting.md#scripts-that-run-on-an-alert) |
| `--on-alert-dir DIR` | `alert-scripts` next to the database | The only directory the on-alert script can write to |

See [Monitoring and alerts](monitoring-alerts.md).

## Passive and OT options

| Option | Default | Meaning |
| --- | --- | --- |
| `--seconds N` | `listen`/`dcp`: 60 (max 86400); `ot-listen`: 300 (max 604800) | Capture duration |
| `--pcap FILE` | | Read a pcap/pcapng file instead of an interface (`ot-listen`) |
| `--progress` | off | Print percent, frames and frames/s on stderr while reading a file |
| `--no-reassembly` | off | Disable OT TCP reassembly |
| `--model FILE` | `ot-model.json` next to the database (`ot-learn`) | The learned traffic model: written by `ot-learn`, read by `ot-listen` |
| `--maintenance SPEC` | none | `ot-listen --model`: when Stops are expected, `"Sat 02:00-06:00"` (UTC unless `UTC+H`), several windows separated by `;` |

## trace options

`trace TARGET` takes `--max-hops` (default 20), `--timeout` (default 1000 ms), `--trace-method icmp|tcp|udp` (tcp/udp need `--fast`), `--trace-port N`, `--rate PPS`, and for TCP the SYN interface options `--interface`, `--source-ip`, `--source-mac`.

## devices options

`devices ID [--format json|csv]`, or `devices --history MAC|IP [--format text|json]`. The MAC can be written `AA:BB:..`, `aa-bb-..`, `aabb.cc..` or `aabbcc…`.

## Examples

```powershell
network-scope-cli scan 192.168.1.0/24 --tcp-only --fast --workers 1024 --ports 80,443
network-scope-cli scan 192.168.1.10 --arp --ot --tui --output inventory.json
network-scope-cli scan 192.168.1.0/24 --deep --trace --script scripts\example.rhai --format md --output scan.md
network-scope-cli scan 10.0.0.0/22 --fast --syn --adaptive-syn --arp-sweep --interface "INTERFACE_ID" --source-ip 10.0.0.9 --source-mac "AA:BB:CC:DD:EE:FF"
network-scope-cli history
network-scope-cli diff 1 2 --format json --ignore http.*.title,.server
network-scope-cli export 2 --format html --output report.html
network-scope-cli export 3 --format jsonl --output hosts.jsonl
network-scope-cli findings 3 --min-severity medium --cves my-cves.json
network-scope-cli feeds import --kev known_exploited_vulnerabilities.json --epss epss_scores-current.csv
network-scope-cli findings 3 --sort exploited
network-scope-cli report 3 --baseline 2 --output report.html
network-scope-cli export 3 --format nmap --output scan.xml
network-scope-cli import nmap-result.xml
network-scope-cli devices --history AA:BB:CC:DD:EE:FF
network-scope-cli monitor 192.168.1.0/24 --deep --interval 300 --dhcp-allow 192.168.1.1 --alerts alerts.jsonl --syslog udp://10.0.0.5
network-scope-cli ot-listen --pcap plant.pcapng --progress
network-scope-cli ot-assets 4 --format csv --output assets.csv
network-scope-cli trace 10.20.0.1 --fast --trace-method udp
network-scope-cli interfaces
network-scope-cli listen --interface "INTERFACE_ID" --seconds 60
network-scope-cli dcp --interface "INTERFACE_ID" --source-mac "AA:BB:CC:DD:EE:FF"
network-scope-cli completions powershell | Out-String | Invoke-Expression
```
