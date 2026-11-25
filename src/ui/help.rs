//! The `--help` text. A new command gets a line here (the test in `ui/mod.rs` checks that every
//! registered command is mentioned). The help of one command ([`command`]: `CMD --help`,
//! `help CMD`) is cut out of the same text, so only the [`EXAMPLES`] are written separately.
pub(super) const HELP: &str = r#"Network Scope — portable Rust network inventory

network-scope                         Desktop GUI
network-scope --version               Print the version
network-scope scan TARGETS [options]  Active scan, saved to SQLite
network-scope listen --interface ID [--seconds 60]  Passive capture only
network-scope dcp --interface ID --source-mac MAC  Read-only DCP Identify
network-scope interfaces              List capture interfaces
network-scope history [--db FILE]      List saved scans as JSON
network-scope history prune [--keep N] [--older-than 30d|DATE] [--dry-run]   Delete old saved scans (keep the newest N per
                                      target set and/or drop older ones; the newest completed scan always stays)
network-scope search QUERY [--top N] [--format text|json]   Where an address, MAC, name, vendor or finding id appeared in the saved scans
network-scope wol MAC [--broadcast IPV4] [--dry-run]   Wake-on-LAN: one magic packet to the broadcast address (only on request)
network-scope diff OLD_ID NEW_ID [--format lines|json|text] [--ignore KEY,KEY] [--db FILE]
        [--fail-on-findings [--min-severity low]]
network-scope changes [--since last|7d|2026-11-01] [--format text|json]   New, gone and changed devices, new and resolved risks
network-scope baseline approve [SCAN_ID]       Approve the devices of a completed scan as the expected devices
network-scope baseline set DEVICE [--owner TEXT] [--tag a,b] [--untag a,b]
        [--criticality low|medium|high|critical|none] [--expected yes|no]   Describe one device
network-scope baseline show [--format text|json]   Expected devices, owners, tags, criticality
network-scope baseline enable                  Start alerting on unknown devices (baseline from an import)
network-scope baseline remove DEVICE | clear   Drop one device, or the whole baseline (alerting off)
network-scope export ID --format json|csv|html|nmap|md|jsonl|cyclonedx|compliance-iec62443|compliance-nis2|compliance-cis[-csv] [--baseline ID] [--output FILE]
network-scope export ID --format cyclonedx --push URL --token-env VAR [--dt-project NAME] [--dt-version V]   Upload to Dependency-Track
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
network-scope feeds import csaf FILE|DIR...   Offline CISA ICS advisories (CSAF 2.0) matched against OT firmware
network-scope feeds import sbom FILE|DIR... [--sbom-vendor V] [--sbom-product P] [--sbom-version X]
                                               Firmware SBOMs (CycloneDX or SPDX JSON) for the CycloneDX export
network-scope feeds import vex FILE|DIR...       Vendor VEX statements (CSAF 2.0 or CycloneDX) that mark findings as not affected, fixed, ...
network-scope feeds status                     What the feeds cache holds
network-scope monitor TARGETS [scan options] --interval 300 [--cycles N] [--learn] [--keep N]
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
network-scope ot-learn --pcap FILE | --interface ID --seconds N [--model FILE] [--no-reassembly]
                                               Learn normal industrial traffic: who talks to each device, with
                                               which functions, how often and when (saved as a model file)
network-scope ot-listen --pcap FILE | --interface ID --model FILE [--maintenance "Sat 02:00-06:00"]
        [--format json|text] [--fail-on-findings]   Report what the model has not seen: a new station, a first
                                               write, a Stop outside the window (receive-only)
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
network-scope research query "SELECT ..." [--top N] [--format json|csv|tsv]   Read-only SQL on the research tables
network-scope research schema | rebuild        Document the tables; fill them for scans saved before they existed
network-scope research export csv|ndjson|parquet --output DIR   One file per table (DuckDB/pandas layout)
network-scope research export stix|ocsf [SCAN_ID] [--output FILE]   STIX 2.1 bundle or OCSF events of one scan
network-scope research groups [--top N] [--format text|json]   Devices that share a key, a TLS/SSH stack,
                                               web interface or OT firmware, across scans and sites
network-scope fingerprints groups [SCAN_ID]    The unidentified banners, grouped by similarity (the workbench queue)
network-scope fingerprints compare GROUP [SCAN_ID]   One group side by side: what differs between firmware versions
network-scope fingerprints draft GROUP [SCAN_ID] [--output FILE]   A draft probes.json rule (passes probes lint)
                                               and the pull request checklist
network-scope fingerprints favicon FILE        Shodan-compatible favicon hash of a local file (nothing is fetched)
network-scope segmentation check --zones FILE --from ZONE [SCAN_ID] [--format text|json] [--fail-on-findings]
                                               Paths from the scan's zone that the declared IEC 62443 zones and
                                               conduits do not allow (reads a stored scan, sends nothing)
network-scope update check                     Ask GitHub for the latest release (one HTTPS request); prints
                                               the release page and how to verify a download; never downloads
network-scope completions powershell|bash|zsh|fish   Print a shell completion script

One command: network-scope COMMAND --help (or: network-scope help COMMAND)

Scan options:
  --preset quick|office|plant|full  Named settings bundle (explicit options still win): quick = the
                  Safe Mode default, office = + service/OS/MAC identification, full = Safe Mode off with
                  everything on (scope guard and back-off still apply); plant is passive: use ot-listen
  --targets-file FILE  scan: targets from a list file (one per line, # comments); adds to TARGETS
  --randomize     scan: probe the addresses in random order (up to 1,048,576 addresses)
  --ports 80,443,502,102,4840,44818 --workers 1024 --timeout 2000
  --top-ports N   Add the N most common TCP ports (1-100); also usable as top:N in --ports
  --retries 1     Extra attempts for unanswered ports (timeout doubles each time)
  --rate PPS      Cap probe rate outside Safe Mode (0 = unlimited)
  --parallel 64   Concurrent port probes per host outside Safe Mode
  --tcp-only --arp --ot --dns --tui --format json|csv|html|nmap|md|jsonl|cyclonedx --output FILE
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
  --csaf FILE     CSAF advisory cache (default: csaf.json next to feeds.json); any command
  --script PATH   Rhai script (or folder of .rhai files) run against every host
  --db FILE       Defaults to LOCALAPPDATA/NetworkScope/inventory.sqlite
  --fast          Disable conservative rate limits (read-only OT still applies)
  --syn           SYN via Npcap, IPv4 and IPv6 (routed targets via the gateway MAC); else TCP connect
  --adaptive-syn  RTT-based SYN reply windows and congestion window (with --syn --fast)
  --no-adaptive-tcp  By default a host without a ping RTT (drops ping, or --tcp-only) gets a connect
                  timeout from its measured connect RTT (shortens waits only); this turns it off
  --jarm          JARM-style TLS fingerprint (10 hellos per TLS port; with --services --fast)
  --snmp-community STRING  Read responding hosts over SNMP v2c (sysDescr, interfaces, LLDP neighbours) with
                  this community; read-only (Get/GetNext/GetBulk), never guessed; allowed in Safe Mode
  --snmp-community-env NAME  Like --snmp-community, but the community is read from the environment
                  variable NAME; only the name is saved with the scan (scheduled scans, services, replay)
  --snmp-version 2c|1  Version for --snmp-community and --snmp-community-env (default 2c)
  --snmp-v3 USER[:AUTH:AUTH_ENV[:PRIV:PRIV_ENV]]  SNMPv3: AUTH is sha, sha256 or md5 (weak), PRIV is aes
                  or des (weak); the *_ENV parts are names of environment variables that hold the
                  passphrases (min. 8 characters); only the names are saved with the scan
  --ipv6-discover Find hosts on the local link over IPv6 (scan, monitor): one ICMPv6 echo to ff02::1 per
                  interface (--interface picks one by index or name), then the OS neighbour cache;
                  joined to scanned hosts by MAC. One datagram per interface, also in Safe Mode
  --favicon       one GET /favicon.ico per web port, hashed (Shodan-compatible) into http.PORT.favicon_mmh3
                  (with --services --fast; not on hosts the scan found industrial)
  --dry-run       scan, monitor, trace, dcp, wol: print per host which packet types would be sent
                  (ports, UDP probe names, TLS/SMB, OT requests with function codes, ...) and send nothing;
                  history prune: say how many scans would be deleted and delete nothing;
                  service install: print the service command line and install nothing
  --record FILE.pcapng  scan: keep the payloads the scan sent and received (OT requests and replies, service
                  probes, HTTP) as pcapng. An application-level record, not a wire capture
  --record-wire   with --record: capture the real frames of the scan instead (Npcap/libpcap; --interface, or the
                  loopback interface for loopback targets); falls back to the application-level record
  --replay-check ID  scan: run stored scan ID again with its own targets and settings and compare the result
                  and the version/rules stamp (--fail-on-findings: exit 3 when it is not reproduced)
  --incremental   scan, monitor: a repeat scan of the same targets: known open ports plus a sample are probed again,
                  unchanged services keep their identification (marked as carried over); needs an earlier scan
  --full-every N  monitor with --incremental: every Nth cycle is a full scan (default 10, 0 never)
  --keep N        monitor: keep only the newest N scans of these targets in the inventory (default: all; a monitor
                  saves one scan per cycle); history prune: the newest N scans of every target set
  --older-than T  history prune: delete scans older than a window (30d, 12w) or from before a UTC date
  --early-stop    Stop probing a host's remaining ports once its device class is certain (e.g. two print
                  ports open); such a host is marked as not fully checked. Off by default
  --no-report     scan: save the scan and print no report (for very large scans; read it with export ID)
  --stream        scan: print each result as a JSON line the moment it is found (host-up, port-open,
                  host-done); the report then goes to --output only, not stdout
  --sent-log      scan, trace, dcp: print the packets actually sent, by kind and detail (stderr)
  --no-backoff    Turn off the automatic back-off (per-device-type parallel limits and slowing or
                  pausing a host that resets connections; on by default, it only ever slows down)
  --arp-sweep     Fast ARP sweep through the capture interface (with --fast; needs Npcap)
  --interface ID --source-ip IPV4 --source-mac MAC  Required for SYN, ARP sweep, TCP trace
                  scan: --interface A,B --source-ip X,Y --source-mac M1,M2 uses several interfaces (paired by position)
  --unit 1 --rack 0 --slot 2   Modbus unit and S7 addressing
  --melsec-port PORT  With --ot: MELSEC MC protocol CPU model read on this TCP port (in --ports; never a default)
  --dnp3-address N [--dnp3-master M]  With --ot: DNP3 read of class 0 from outstation N on tcp/20000 (in --ports);
                  never a broadcast or reserved address
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

/// Two or three examples for the common commands, shown by [`command`]. A test checks that
/// every option in them is a declared one.
const EXAMPLES: &[(&str, &[&str])] = &[
    (
        "scan",
        &[
            "network-scope scan 192.168.1.0/24",
            "network-scope scan 192.168.1.0/24 --preset office --format html --output scan.html",
            "network-scope scan 192.168.1.10 --ports 22,80,443 --services --dry-run",
        ],
    ),
    (
        "monitor",
        &[
            "network-scope monitor 192.168.1.0/24 --interval 300",
            "network-scope monitor 192.168.1.0/24 --interval 900 --keep 100 --alerts alerts.jsonl",
        ],
    ),
    (
        "findings",
        &[
            "network-scope findings 12 --min-severity medium",
            "network-scope findings 12 --top 5",
            "network-scope findings 12 --fail-on-findings --min-severity high",
        ],
    ),
    (
        "diff",
        &[
            "network-scope diff 11 12",
            "network-scope diff 11 12 --format text",
            "network-scope diff 11 12 --fail-on-findings --min-severity high",
        ],
    ),
    (
        "export",
        &[
            "network-scope export 12 --format csv --output scan.csv",
            "network-scope export 12 --format html --baseline 11 --output report.html",
            "network-scope export 12 --format cyclonedx --output bom.json",
        ],
    ),
    (
        "history",
        &[
            "network-scope history",
            "network-scope history prune --keep 20 --dry-run",
            "network-scope history prune --older-than 90d",
        ],
    ),
    (
        "changes",
        &[
            "network-scope changes",
            "network-scope changes --since 7d",
            "network-scope changes --since 2026-11-01 --format json",
        ],
    ),
    (
        "listen",
        &[
            "network-scope listen --interface ID",
            "network-scope listen --interface ID --seconds 300",
        ],
    ),
    (
        "feeds",
        &[
            "network-scope feeds import --kev kev.json --epss epss.csv",
            "network-scope feeds import nvd nvdcve-2.0-2026.json",
            "network-scope feeds status",
        ],
    ),
    (
        "devices",
        &[
            "network-scope devices 12",
            "network-scope devices 12 --format csv --output devices.csv",
            "network-scope devices --history 192.168.1.20",
        ],
    ),
    (
        "search",
        &[
            "network-scope search 192.168.1.20",
            "network-scope search printer --top 10",
            "network-scope search telnet-open --format json",
        ],
    ),
    (
        "trace",
        &[
            "network-scope trace 192.168.1.1",
            "network-scope trace 10.20.0.1 --max-hops 10 --dry-run",
        ],
    ),
];

/// The option names (`--name` without the dashes) in a piece of help text.
fn option_names(text: &str) -> Vec<&str> {
    text.split("--")
        .skip(1)
        .map(|rest| {
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                .unwrap_or(rest.len());
            &rest[..end]
        })
        .filter(|name| !name.is_empty())
        .collect()
}

/// Whether a line of an option description says the option is for `command`: the command word
/// in the list in front of a colon (`scan, monitor: ...`, `history prune: ...`).
fn names_command(line: &str, command: &str) -> bool {
    let boundary = |c: Option<char>| c.is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '-'));
    line.match_indices(command).any(|(at, _)| {
        let after = &line[at + command.len()..];
        boundary(line[..at].chars().next_back())
            && boundary(after.chars().next())
            && after.split_once(':').is_some_and(|(list, _)| {
                list.chars()
                    .all(|c| c.is_ascii_lowercase() || " ,/-".contains(c))
            })
    })
}

/// The help of one command, cut out of [`HELP`]: its usage lines, the descriptions of the
/// options that apply to it and, for the common commands, examples. `None` when the text has
/// no usage line for `name`, which is the case exactly for an unknown command.
///
/// An option description applies when the command takes the scan options (its usage says
/// `options]`), when the usage names every option the description is about, when the
/// description names the command in front of a colon, or when it says "any command".
pub(super) fn command(name: &str) -> Option<String> {
    let (commands, rest) = HELP.split_once("\nScan options:\n")?;
    let (options, notes) = rest.split_once("\n\n")?;
    // Usage: the `network-scope NAME ...` lines, each with its indented continuation lines.
    let mut usage = vec![];
    let mut mine = false;
    for line in commands.lines() {
        if !line.starts_with(' ') {
            mine = line
                .strip_prefix("network-scope ")
                .is_some_and(|rest| rest.split_whitespace().next() == Some(name));
        }
        if mine {
            usage.push(line);
        }
    }
    if usage.is_empty() {
        return None;
    }
    let usage = usage.join("\n");
    let scans = usage.contains("options]");
    let named = option_names(&usage);
    // Option descriptions: a line indented by two spaces starts one, deeper lines continue it.
    let mut blocks: Vec<Vec<&str>> = vec![];
    for line in options.lines() {
        match blocks.last_mut() {
            Some(block) if line.starts_with("   ") => block.push(line),
            _ => blocks.push(vec![line]),
        }
    }
    let applies = |block: &Vec<&str>| {
        // What the description is about: the options before the gap that starts the text.
        let about = block[0].trim_start();
        let about = option_names(about.split_once("  ").map_or(about, |(spec, _)| spec));
        scans
            || about.iter().all(|o| named.contains(o))
            || block
                .iter()
                .any(|l| l.contains("any command") || names_command(l, name))
    };
    let mut out = format!("{usage}\n\nOptions:\n");
    for block in blocks.iter().filter(|b| applies(b)) {
        out.push_str(&block.join("\n"));
        out.push('\n');
    }
    if scans {
        // The two lines about Safe Mode: what a scan does unless `--fast` is given.
        let safe: Vec<&str> = notes
            .lines()
            .skip_while(|l| !l.starts_with("Safe Mode"))
            .take(2)
            .collect();
        out.push_str(&format!("\n{}\n", safe.join("\n")));
    }
    if let Some((_, examples)) = EXAMPLES.iter().find(|(command, _)| *command == name) {
        out.push_str("\nExamples:\n");
        for example in *examples {
            out.push_str(&format!("  {example}\n"));
        }
    }
    out.push_str("\nEvery command and option: network-scope --help");
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::{args::options, commands};

    #[test]
    fn every_command_has_its_own_help() {
        for (name, _) in commands::COMMANDS {
            let text = command(name).unwrap_or_else(|| panic!("{name}"));
            assert!(
                text.starts_with(&format!("network-scope {name}")),
                "{name}: {text}"
            );
            assert!(text.len() < HELP.len(), "{name} is not the whole help");
            // The options of every command are in each one.
            assert!(text.contains("\n  --quiet "), "{name}");
            // Only this command's usage lines.
            for line in text.lines() {
                if let Some(rest) = line.strip_prefix("network-scope ") {
                    assert_eq!(rest.split_whitespace().next(), Some(*name), "{line}");
                }
            }
        }
        assert!(command("help").is_none() && command("no-such-command").is_none());
        // A prefix of a command word is not that command.
        assert!(command("ot").is_none() && command("scans").is_none());
    }

    #[test]
    fn a_command_lists_the_options_that_apply_to_it() {
        let has = |name: &str, option: &str| {
            command(name)
                .unwrap()
                .lines()
                .any(|l| l.starts_with(&format!("  --{option} ")))
        };
        // The scanning commands take every scan option, and say what Safe Mode is.
        for name in ["scan", "monitor", "service"] {
            for option in ["ports", "targets-file", "fast", "older-than", "quiet"] {
                assert!(has(name, option), "{name} --{option}");
            }
            assert!(
                command(name)
                    .unwrap()
                    .contains("\nSafe Mode is on by default")
            );
        }
        assert!(!command("scan").unwrap().contains("history prune ["));
        // Named in the usage line, or named by the description.
        for (name, option) in [
            ("history", "keep"),
            ("history", "older-than"),
            ("history", "db"),
            ("findings", "fail-on-findings"),
            ("diff", "fail-on-findings"),
            ("trace", "trace-method"),
            ("trace", "dry-run"),
            ("trace", "sent-log"),
            ("dcp", "sent-log"),
            ("wol", "dry-run"),
            ("export", "json-schema"),
        ] {
            assert!(has(name, option), "{name} --{option}");
        }
        // And not the rest.
        for (name, option) in [
            ("history", "ports"),
            ("findings", "keep"),
            ("export", "no-report"),
            ("report", "no-report"),
            ("interfaces", "interface"),
            ("trace", "trace"),
            ("alerts", "fast"),
        ] {
            assert!(!has(name, option), "{name} --{option}");
        }
        assert!(!command("history").unwrap().contains("Safe Mode"));
        // --dry-run does something else for these two, and their help says what.
        for (name, does) in [
            (
                "history",
                "history prune: say how many scans would be deleted",
            ),
            ("service", "service install: print the service command line"),
        ] {
            assert!(command(name).unwrap().contains(does), "{name}");
        }
    }

    #[test]
    fn examples_are_for_known_commands_and_use_declared_options() {
        for (name, examples) in EXAMPLES {
            assert!(commands::find(name).is_some(), "{name}");
            assert!((2..=3).contains(&examples.len()), "{name}");
            for example in *examples {
                let words: Vec<String> = example.split_whitespace().map(str::to_string).collect();
                assert_eq!(words[..2], ["network-scope", *name], "{example}");
                options(&words[2..]).unwrap_or_else(|e| panic!("{example}: {e}"));
                assert!(command(name).unwrap().contains(example), "{example}");
            }
        }
    }
}
