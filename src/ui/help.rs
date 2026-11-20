//! The `--help` text. A new command gets a line here (the test in `ui/mod.rs` checks that every
//! registered command is mentioned).
pub(super) const HELP: &str = r#"Network Scope — portable Rust network inventory

network-scope                         Desktop GUI
network-scope --version               Print the version
network-scope scan TARGETS [options]  Active scan, saved to SQLite
network-scope listen --interface ID [--seconds 60]  Passive capture only
network-scope dcp --interface ID --source-mac MAC  Read-only DCP Identify
network-scope interfaces              List capture interfaces
network-scope history [--db FILE]      List saved scans as JSON
network-scope diff OLD_ID NEW_ID [--format lines|json|text] [--ignore KEY,KEY] [--db FILE]
        [--fail-on-findings [--min-severity low]]
network-scope changes [--since last|7d|2026-11-01] [--format text|json]   New, gone and changed devices, new and resolved risks
network-scope baseline approve [SCAN_ID]       Approve the devices of a completed scan as the expected devices
network-scope baseline set DEVICE [--owner TEXT] [--tag a,b] [--untag a,b]
        [--criticality low|medium|high|critical|none] [--expected yes|no]   Describe one device
network-scope baseline show [--format text|json]   Expected devices, owners, tags, criticality
network-scope baseline enable                  Start alerting on unknown devices (baseline from an import)
network-scope baseline remove DEVICE | clear   Drop one device, or the whole baseline (alerting off)
network-scope export ID --format json|csv|html|nmap|md|jsonl|compliance-iec62443|compliance-nis2|compliance-cis[-csv] [--baseline ID] [--output FILE]
network-scope export ID --format netbox|netbox-devices|snipeit|splunk|elastic|servicenow [--output FILE]
        [--push URL --token-env VAR] [--netbox-site S --netbox-role R --netbox-device-type T] [--index NAME]
network-scope report ID [--baseline ID] [--output FILE]   HTML report with charts and map
network-scope import FILE.xml                  Import an nmap XML scan into the inventory
network-scope import csv|isc-dhcp|dnsmasq|windows-dhcp|ad-csv|ad-ldif|netbox FILE...  [--format json]
                                               Known devices from a list (offline file); never a scan
network-scope findings ID [--min-severity low] [--sort exploited|severity] [--fail-on-findings]
                                               Weak TLS/SSH, risky services, CVE hints
network-scope findings ID --top N [--format text|json]   Risk scores and the "fix these first" list
network-scope feeds import [--kev FILE] [--epss FILE]   Offline CISA KEV and EPSS data for findings
network-scope feeds import nvd FILE...   Offline NVD CVE JSON 2.0 feed files (unzip .gz first) for CVE findings
network-scope feeds status                     What the feeds cache holds
network-scope monitor TARGETS [scan options] --interval 300 [--cycles N] [--learn]
        [--dhcp-allow IP,IP] [--dhcp-discover] [--report-missing] [--min-severity low]
        [--interface ID --listen-seconds 30] [--alerts FILE]   Repeat scans and alert on changes
        [--webhook http(s)://URL,...] [--syslog [udp://|tcp://]HOST[:PORT],...]
        [--alert-timeout 5] [--no-dedup] [--renotify-hours 24]
        [--on-alert SCRIPT.rhai|library:NAME [--on-alert-dir DIR]]   Run a script for every alert
network-scope alerts [--db FILE]               Alerts raised by monitor runs
network-scope scripts PATH                     Check Rhai scripts (use --script PATH with scan)
network-scope service install TARGETS [monitor options] [--service-name NAME] [--db FILE] [--dry-run]
network-scope service uninstall [--service-name NAME]   Windows service for monitor (run as administrator)
network-scope mcp [--db FILE] [--no-scan]       MCP server on stdin/stdout for AI assistants (read-only queries, Safe Mode scan)
network-scope scripts list|show NAME           The built-in script library (--script library:NAME)
network-scope ot-listen --interface ID --seconds N | --pcap FILE [--progress] [--no-reassembly]
                                               Passive OT asset discovery
network-scope ot-assets ID [--format json|csv]  OT asset inventory from a passive capture
network-scope devices ID [--format json|csv]   One record per device (active + passive merged)
network-scope devices --history MAC|IP [--format text|json]   Timeline of one device across saved scans
network-scope topology ID [--format ascii|dot] Network path map from traceroute data
network-scope trace TARGET [--max-hops 20] [--timeout 1000] [--fast --trace-method udp|tcp --trace-port N]
network-scope probes [--probes FILE]           List the TCP and UDP probe database
network-scope probes validate FILE             Load a probe file like a scan would, then lint it
network-scope probes lint [FILE]               Safety lint (OT/printer ports, write-like payloads, size,
                                               regex shape); default: the built-in data/probes.json
network-scope fingerprints export-unknown [SCAN_ID] [--output FILE]
                                               Banners nothing identified, from the local store, as JSON
                                               to review and redact (never uploaded)
network-scope update check                     Ask GitHub for the latest release (one HTTPS request); prints
                                               the release page and how to verify a download; never downloads
network-scope completions powershell|bash      Print a shell completion script

Scan options:
  --ports 80,443,502,102,4840,44818 --workers 1024 --timeout 2000
  --top-ports N   Add the N most common TCP ports (1-100); also usable as top:N in --ports
  --retries 1     Extra attempts for unanswered ports (timeout doubles each time)
  --rate PPS      Cap probe rate outside Safe Mode (0 = unlimited)
  --parallel 64   Concurrent port probes per host outside Safe Mode
  --tcp-only --arp --ot --dns --tui --format json|csv|html|nmap|md|jsonl --output FILE
  --services      Identify services: banners, HTTP, TLS (certificate, versions, ciphers), SMB, RDP, databases...
  --udp           Probe UDP: DNS, DHCP, NTP, NetBIOS, SNMP (community "public"), SSDP, mDNS
  --udp-ports 53,123,161   Replace the default UDP port list (OT and printer ports are skipped)
  --os            OS family, manufacturer (IEEE OUI) and device type guess
  --deep          Same as --services --udp --os
  --trace         Record the router path to each responding host (--max-hops 20)
  --trace-method icmp|tcp|udp  Traceroute method (implies --trace; tcp/udp only with --fast)
  --trace-port N  TCP traceroute port (default: first open port; never OT or printer ports)
  --probes FILE   Extra service probes (TCP and UDP), merged over data/probes.json by name
  --cves FILE     Extra CVE/CPE rules, merged over data/cves.json by id; any command
  --feeds FILE    KEV/EPSS cache (default: feeds.json next to the user cves.json); any command
  --nvd FILE      NVD cache (default: nvd.json next to feeds.json); any command
  --script PATH   Rhai script (or folder of .rhai files) run against every host
  --db FILE       Defaults to LOCALAPPDATA/NetworkScope/inventory.sqlite
  --fast          Disable conservative rate limits (read-only OT still applies)
  --syn           IPv4 SYN via Npcap (routed targets via the gateway MAC); else TCP connect
  --adaptive-syn  RTT-based SYN reply windows and congestion window (with --syn --fast)
  --adaptive-tcp  Per-host TCP connect timeout from the measured connect RTT (shortens waits only)
  --jarm          JARM-style TLS fingerprint (10 hellos per TLS port; with --services --fast)
  --dry-run       scan, monitor, trace, dcp: print per host which packet types would be sent
                  (ports, UDP probe names, TLS/SMB, OT requests with function codes, ...) and send nothing
  --early-stop    Stop probing a host's remaining ports once its device class is certain (e.g. two print
                  ports open); such a host is marked as not fully checked. Off by default
  --stream        scan: print each result as a JSON line the moment it is found (host-up, port-open,
                  host-done); the report then goes to --output only, not stdout
  --sent-log      scan, trace, dcp: print the packets actually sent, by kind and detail (stderr)
  --no-backoff    Turn off the automatic back-off (per-device-type parallel limits and slowing or
                  pausing a host that resets connections; on by default, it only ever slows down)
  --arp-sweep     Fast ARP sweep through the capture interface (with --fast; needs Npcap)
  --interface ID --source-ip IPV4 --source-mac MAC  Required for SYN, ARP sweep, TCP trace
  --unit 1 --rack 0 --slot 2   Modbus unit and S7 addressing
  --json-schema v1  JSON output version (default and only version for now); any command
  --scope CIDR[,CIDR]  Declared scope (also --scope-file FILE; default scope.txt in the config folder)
  --yes-public    Allow public (non-private) addresses; without it scan/monitor/trace ask on a
                  terminal and otherwise refuse with exit status 2
  --allow-out-of-scope  Allow addresses outside the declared scope (covers public ones too)
  --quiet         No progress messages on stderr (errors still print); any command
  --fail-on-findings  findings/diff only: exit 3 when a finding (diff: a new one) is at or
                  above --min-severity (default info); otherwise the exit status is unchanged

Exit status: 0 success, 1 error (arguments, I/O, database), 2 partial result (scan or
capture stopped early, results saved; or the scope guard refused to start, nothing sent),
3 findings found (only with --fail-on-findings).

Safe Mode is on by default: 8 hosts max, >=100 ms between probes, no SYN, no ARP
sweep, ICMP traceroute only. --fast lifts it.
Targets are streamed: ranges up to 16,777,216 addresses (/8) are accepted; above
65,536 only responding hosts are kept in memory and saved.
Read-only traffic can still affect fragile equipment; passive listen sends none.
OT queries run only on their standard open ports; BACnet uses unicast UDP Who-Is.
Npcap is optional for TCP connect; capture/DCP/SYN require its driver and access.
TUI: Space pause/resume, Q/Esc stop and save a partial scan, Up/Down select,
Enter host details (Enter/Backspace back), S change sort. No scan starts by itself.
"#;
