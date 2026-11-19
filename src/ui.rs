//! Scriptable CLI and live terminal view use exactly the desktop scan engine.
use crate::{devices, monitor, nmap, passive, risk, scan, store, topology};
use std::{collections::BTreeMap, path::PathBuf, sync::atomic::Ordering, time::Duration};
const HELP: &str = r#"Network Scope — portable Rust network inventory

network-scope                         Desktop GUI
network-scope scan TARGETS [options]  Active scan, saved to SQLite
network-scope listen --interface ID [--seconds 60]  Passive capture only
network-scope dcp --interface ID --source-mac MAC  Read-only DCP Identify
network-scope interfaces              List capture interfaces
network-scope history [--db FILE]      List saved scans as JSON
network-scope diff OLD_ID NEW_ID [--format lines|json|text] [--ignore KEY,KEY] [--db FILE]
        [--fail-on-findings [--min-severity low]]
network-scope export ID --format json|csv|html|nmap|md|jsonl [--baseline ID] [--output FILE]
network-scope report ID [--baseline ID] [--output FILE]   HTML report with charts and map
network-scope import FILE.xml                  Import an nmap XML scan into the inventory
network-scope findings ID [--min-severity low] [--sort exploited|severity] [--fail-on-findings]
                                               Weak TLS/SSH, risky services, CVE hints
network-scope feeds import [--kev FILE] [--epss FILE]   Offline CISA KEV and EPSS data for findings
network-scope feeds status                     What the feeds cache holds
network-scope monitor TARGETS [scan options] --interval 300 [--cycles N] [--learn]
        [--dhcp-allow IP,IP] [--dhcp-discover] [--report-missing] [--min-severity low]
        [--interface ID --listen-seconds 30] [--alerts FILE]   Repeat scans and alert on changes
        [--webhook http(s)://URL,...] [--syslog [udp://|tcp://]HOST[:PORT],...]
        [--alert-timeout 5] [--no-dedup] [--renotify-hours 24]
network-scope alerts [--db FILE]               Alerts raised by monitor runs
network-scope scripts PATH                     Check Rhai scripts (use --script PATH with scan)
network-scope ot-listen --interface ID --seconds N | --pcap FILE [--progress] [--no-reassembly]
                                               Passive OT asset discovery
network-scope ot-assets ID [--format json|csv]  OT asset inventory from a passive capture
network-scope devices ID [--format json|csv]   One record per device (active + passive merged)
network-scope devices --history MAC|IP [--format text|json]   Timeline of one device across saved scans
network-scope topology ID [--format ascii|dot] Network path map from traceroute data
network-scope trace TARGET [--max-hops 20] [--timeout 1000] [--fast --trace-method udp|tcp --trace-port N]
network-scope probes [--probes FILE]           List/validate the TCP and UDP probe database
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
  --script PATH   Rhai script (or folder of .rhai files) run against every host
  --db FILE       Defaults to LOCALAPPDATA/NetworkScope/inventory.sqlite
  --fast          Disable conservative rate limits (read-only OT still applies)
  --syn           IPv4 SYN via Npcap (routed targets via the gateway MAC); else TCP connect
  --adaptive-syn  RTT-based SYN reply windows and congestion window (with --syn --fast)
  --arp-sweep     Fast ARP sweep through the capture interface (with --fast; needs Npcap)
  --interface ID --source-ip IPV4 --source-mac MAC  Required for SYN, ARP sweep, TCP trace
  --unit 1 --rack 0 --slot 2   Modbus unit and S7 addressing
  --quiet         No progress messages on stderr (errors still print); any command
  --fail-on-findings  findings/diff only: exit 3 when a finding (diff: a new one) is at or
                  above --min-severity (default info); otherwise the exit status is unchanged

Exit status: 0 success, 1 error (arguments, I/O, database), 2 partial result (scan or
capture stopped early, results saved), 3 findings found (only with --fail-on-findings).

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
const FLAGS: [&str; 22] = [
    "quiet",
    "fail-on-findings",
    "arp-sweep",
    "adaptive-syn",
    "no-dedup",
    "progress",
    "no-reassembly",
    "tcp-only",
    "arp",
    "ot",
    "dns",
    "tui",
    "fast",
    "syn",
    "services",
    "udp",
    "os",
    "trace",
    "deep",
    "learn",
    "dhcp-discover",
    "report-missing",
];
const VALUES: [&str; 42] = [
    "feeds",
    "kev",
    "epss",
    "sort",
    "ports",
    "ignore",
    "history",
    "cves",
    "webhook",
    "syslog",
    "alert-timeout",
    "renotify-hours",
    "trace-method",
    "trace-port",
    "top-ports",
    "udp-ports",
    "max-hops",
    "probes",
    "script",
    "interval",
    "cycles",
    "dhcp-allow",
    "min-severity",
    "baseline",
    "listen-seconds",
    "alerts",
    "pcap",
    "retries",
    "rate",
    "parallel",
    "workers",
    "timeout",
    "format",
    "output",
    "db",
    "interface",
    "source-ip",
    "source-mac",
    "seconds",
    "unit",
    "rack",
    "slot",
];
/// Every command `run` accepts (the completion scripts offer these).
const COMMANDS: [&str; 22] = [
    "feeds",
    "scan",
    "listen",
    "dcp",
    "interfaces",
    "history",
    "diff",
    "export",
    "report",
    "import",
    "findings",
    "monitor",
    "alerts",
    "scripts",
    "ot-listen",
    "ot-assets",
    "devices",
    "topology",
    "trace",
    "probes",
    "completions",
    "help",
];
/// Options that take a file name (completed with file names).
const FILE_VALUES: [&str; 10] = [
    "output", "db", "pcap", "script", "probes", "alerts", "cves", "feeds", "kev", "epss",
];
const FORMATS: &str = "json csv html nmap md jsonl lines text ascii dot";
fn completions(shell: &str) -> Result<String, String> {
    let commands = COMMANDS.join(" ");
    let options = FLAGS
        .iter()
        .chain(VALUES.iter())
        .map(|o| format!("--{o}"))
        .collect::<Vec<_>>();
    let values = VALUES.iter().map(|o| format!("--{o}")).collect::<Vec<_>>();
    let files = FILE_VALUES
        .iter()
        .map(|o| format!("--{o}"))
        .collect::<Vec<_>>();
    let quoted = |list: &[String]| {
        list.iter()
            .map(|o| format!("'{o}'"))
            .collect::<Vec<_>>()
            .join(",")
    };
    match shell {
        "bash" => Ok(format!(
            r#"# network-scope completion for bash. Load with: source <(network-scope completions bash)
_network_scope() {{
    local cur="${{COMP_WORDS[COMP_CWORD]}}"
    local prev="${{COMP_WORDS[COMP_CWORD-1]}}"
    local values=" {values} "
    if [[ $COMP_CWORD -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "{commands} --quiet" -- "$cur") )
        return
    fi
    case "$prev" in
        --format) COMPREPLY=( $(compgen -W "{FORMATS}" -- "$cur") ); return ;;
        {file_case}) COMPREPLY=( $(compgen -f -- "$cur") ); return ;;
    esac
    if [[ "$values" == *" $prev "* ]]; then
        return
    fi
    if [[ "${{COMP_WORDS[1]}}" == completions ]]; then
        COMPREPLY=( $(compgen -W "bash powershell" -- "$cur") )
        return
    fi
    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "{options}" -- "$cur") )
    fi
}}
complete -o default -F _network_scope network-scope network-scope.exe network-scope-cli network-scope-cli.exe
"#,
            values = values.join(" "),
            options = options.join(" "),
            file_case = files.join("|"),
        )),
        "powershell" => Ok(format!(
            r#"# network-scope completion for PowerShell. Load with:
#   network-scope completions powershell | Out-String | Invoke-Expression
Register-ArgumentCompleter -Native -CommandName 'network-scope','network-scope.exe','network-scope-cli','network-scope-cli.exe' -ScriptBlock {{
    param($wordToComplete, $commandAst, $cursorPosition)
    $commands = @({commands_q},'--quiet')
    $options = @({options_q})
    $values = @({values_q})
    $formats = @('{formats_q}')
    $words = @($commandAst.CommandElements | ForEach-Object {{ $_.ToString() }})
    $before = $words.Count
    if ($wordToComplete -ne '') {{ $before-- }}
    $prev = if ($before -ge 1) {{ $words[$before - 1] }} else {{ '' }}
    if ($before -le 1) {{ $candidates = $commands }}
    elseif ($prev -eq '--format') {{ $candidates = $formats }}
    elseif ($values -contains $prev) {{ return }}
    elseif ($words[1] -eq 'completions') {{ $candidates = @('bash','powershell') }}
    elseif ($wordToComplete -eq '' -or $wordToComplete.StartsWith('-')) {{ $candidates = $options }}
    else {{ return }}
    $candidates | Where-Object {{ $_ -like "$wordToComplete*" }} | ForEach-Object {{
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }}
}}
"#,
            commands_q = quoted(&COMMANDS.iter().map(|c| c.to_string()).collect::<Vec<_>>()),
            options_q = quoted(&options),
            values_q = quoted(&values),
            formats_q = FORMATS.replace(' ', "','"),
        )),
        _ => Err("Choose powershell or bash".into()),
    }
}
/// Progress and status messages; `--quiet` suppresses them (errors are returned, not printed here).
fn progress(opts: &BTreeMap<String, String>, message: impl std::fmt::Display) {
    if !opts.contains_key("quiet") {
        eprintln!("{message}");
    }
}
fn options(args: &[String]) -> Result<(Vec<String>, BTreeMap<String, String>), String> {
    let (flags, values) = (FLAGS, VALUES);
    let mut positional = vec![];
    let mut opts = BTreeMap::new();
    let mut i = 0;
    while i < args.len() {
        if let Some(key) = args[i].strip_prefix("--") {
            if flags.contains(&key) {
                opts.insert(key.into(), "true".into());
            } else if values.contains(&key) {
                i += 1;
                opts.insert(
                    key.into(),
                    args.get(i)
                        .filter(|v| !v.starts_with("--"))
                        .ok_or_else(|| format!("Missing --{key} value"))?
                        .clone(),
                );
            } else {
                return Err(format!("Unknown option --{key}"));
            }
        } else {
            positional.push(args[i].clone());
        }
        i += 1;
    }
    Ok((positional, opts))
}
fn number<T: std::str::FromStr>(
    opts: &BTreeMap<String, String>,
    key: &str,
    default: T,
) -> Result<T, String> {
    match opts.get(key) {
        Some(s) => s.parse().map_err(|_| format!("Invalid --{key}")),
        None => Ok(default),
    }
}
fn scan_settings(opts: &BTreeMap<String, String>) -> Result<scan::Settings, String> {
    let mut s = scan::Settings {
        scan_nonresponders: true,
        probes: 1,
        ..Default::default()
    };
    if let Some(p) = opts.get("ports") {
        s.ports = p.clone();
    } else if opts.contains_key("ot") {
        s.ports = "80,443,102,502,4840,44818".into();
    }
    s.workers = number(opts, "workers", 1024)?;
    if !(1..=4096).contains(&s.workers) {
        return Err("Workers must be 1–4096".into());
    }
    s.port_timeout = number(opts, "timeout", 2000)?;
    if !(1..=10000).contains(&s.port_timeout) {
        return Err("Timeout must be 1–10000 ms".into());
    }
    s.ping_timeout = s.port_timeout;
    s.tcp_only = opts.contains_key("tcp-only");
    s.arp = opts.contains_key("arp");
    s.ot = opts.contains_key("ot");
    s.dns = opts.contains_key("dns");
    s.safe = !opts.contains_key("fast");
    s.syn = opts.contains_key("syn");
    let deep = opts.contains_key("deep");
    s.services = deep || opts.contains_key("services");
    s.udp = deep || opts.contains_key("udp");
    s.os_detect = deep || opts.contains_key("os");
    s.trace = opts.contains_key("trace");
    // Opt-in transmitting features; the engine ignores them in Safe Mode (without --fast).
    s.arp_sweep = opts.contains_key("arp-sweep");
    s.syn_adaptive = opts.contains_key("adaptive-syn");
    if let Some(m) = opts.get("trace-method") {
        s.trace_method = trace_method(m)?;
        s.trace = true;
    }
    if let Some(p) = opts.get("trace-port") {
        s.trace_port = trace_port(p)?;
    }
    s.trace_hops = number(opts, "max-hops", 20)?;
    if !(1..=64).contains(&s.trace_hops) {
        return Err("Max hops must be 1-64".into());
    }
    if let Some(p) = opts.get("udp-ports") {
        s.udp_ports = p.clone();
        s.udp = true;
    }
    s.probe_file = opts.get("probes").cloned().unwrap_or_default();
    s.delay = 0;
    s.retries = number(opts, "retries", 1)?;
    if s.retries > 5 {
        return Err("Retries must be 0-5".into());
    }
    s.max_rate = number(opts, "rate", 0)?;
    s.port_parallel = number(opts, "parallel", 64)?;
    if !(1..=1024).contains(&s.port_parallel) {
        return Err("Parallel must be 1-1024".into());
    }
    if let Some(n) = opts.get("top-ports") {
        s.ports = format!("{},top:{n}", s.ports);
    }
    s.interface = opts.get("interface").cloned().unwrap_or_default();
    s.source_ip = opts.get("source-ip").cloned().unwrap_or_default();
    s.source_mac = opts.get("source-mac").cloned().unwrap_or_default();
    s.modbus_unit = number(opts, "unit", 1)?;
    s.s7_rack = number(opts, "rack", 0)?;
    s.s7_slot = number(opts, "slot", 2)?;
    s.scripts = opts.get("script").cloned().unwrap_or_default();
    Ok(s)
}
fn trace_method(text: &str) -> Result<crate::trace::TraceMethod, String> {
    serde_json::from_value(serde_json::Value::String(text.to_lowercase()))
        .map_err(|_| "Trace method must be icmp, tcp or udp".to_string())
}
fn trace_port(text: &str) -> Result<u16, String> {
    let port: u16 = text
        .parse()
        .ok()
        .filter(|p| *p != 0)
        .ok_or("Trace port must be 1-65535")?;
    if !crate::trace::trace_port_allowed(port) {
        return Err(format!(
            "Trace port {port} is an OT or printer port; TCP traceroute never uses those"
        ));
    }
    Ok(port)
}
/// The `--baseline ID` snapshot and its time, for reports with a "changes since" section.
fn baseline(
    db: &std::path::Path,
    opts: &BTreeMap<String, String>,
) -> Result<Option<(store::Snapshot, i64)>, String> {
    match opts.get("baseline") {
        Some(b) => {
            let b: i64 = b.parse().map_err(|_| "Invalid --baseline".to_string())?;
            Ok(Some((store::load(db, b)?, store::timestamp(db, b)?)))
        }
        None => Ok(None),
    }
}
fn report_html(
    db: &std::path::Path,
    snapshot: &store::Snapshot,
    stamp: i64,
    opts: &BTreeMap<String, String>,
) -> Result<String, String> {
    let baseline = baseline(db, opts)?;
    Ok(crate::report::html(
        snapshot,
        baseline.as_ref().map(|(s, t)| (s, *t)),
        stamp,
    ))
}
/// Monitor alert policy from the command line, including the opt-in webhook/syslog sinks.
fn monitor_policy(opts: &BTreeMap<String, String>) -> Result<monitor::Policy, String> {
    let mut policy = monitor::Policy {
        learn: opts.contains_key("learn"),
        report_missing: opts.contains_key("report-missing"),
        ..Default::default()
    };
    if let Some(list) = opts.get("dhcp-allow") {
        for item in list.split(',').filter(|i| !i.trim().is_empty()) {
            policy.dhcp_allow.insert(
                item.trim()
                    .parse()
                    .map_err(|_| format!("Invalid DHCP server address: {item}"))?,
            );
        }
    }
    if let Some(m) = opts.get("min-severity") {
        policy.min_severity = risk::Severity::parse(m)
            .ok_or("Severity must be info, low, medium, high or critical")?;
    }
    let list = |key: &str| {
        opts.get(key)
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    };
    for url in list("webhook") {
        policy
            .notify
            .sinks
            .push(crate::notify::Sink::webhook(&url)?);
    }
    for dest in list("syslog") {
        policy
            .notify
            .sinks
            .push(crate::notify::Sink::syslog(&dest)?);
    }
    let timeout: u64 = number(opts, "alert-timeout", 5)?;
    if !(1..=60).contains(&timeout) {
        return Err("Alert timeout must be 1-60 seconds".into());
    }
    policy.notify.timeout = Duration::from_secs(timeout);
    policy.notify.dedup = !opts.contains_key("no-dedup");
    let hours: u64 = number(opts, "renotify-hours", 24)?;
    if hours > 24 * 365 {
        return Err("Renotify hours must be 0-8760".into());
    }
    policy.notify.renotify = (hours > 0).then(|| Duration::from_secs(hours * 3600));
    Ok(policy)
}
fn ot_assets_output(
    snapshot: &store::Snapshot,
    opts: &BTreeMap<String, String>,
) -> Result<(), String> {
    let assets = crate::otpassive::assets(&snapshot.observations);
    match opts.get("format").map(String::as_str).unwrap_or("json") {
        "json" => output(
            &serde_json::to_string_pretty(&assets).map_err(|e| e.to_string())?,
            opts,
        ),
        "csv" => output(&crate::otpassive::assets_csv(&assets), opts),
        _ => Err("Choose json or csv".into()),
    }
}
/// `feeds import [--kev FILE] [--epss FILE]` and `feeds status`; `--feeds FILE` picks the cache.
fn feeds_command(pos: &[String], opts: &BTreeMap<String, String>) -> Result<(), String> {
    let cache = opts
        .get("feeds")
        .map(PathBuf::from)
        .or_else(crate::feeds::default_path)
        .ok_or("No default location for the feeds cache; use --feeds FILE")?;
    match pos.first().map(String::as_str) {
        Some("import") => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let report = crate::feeds::import(
                opts.get("kev").map(std::path::Path::new),
                opts.get("epss").map(std::path::Path::new),
                &cache,
                now,
            )?;
            output(&report.lines().join("\n"), opts)
        }
        Some("status") => {
            let feeds = if cache.exists() {
                crate::feeds::Feeds::load(&cache)?
            } else {
                crate::feeds::Feeds::default()
            };
            output(
                &serde_json::to_string_pretty(&crate::feeds::status(&feeds, &cache))
                    .map_err(|e| e.to_string())?,
                opts,
            )
        }
        _ => Err("Use: feeds import [--kev FILE] [--epss FILE] | feeds status".into()),
    }
}
fn output(data: &str, opts: &BTreeMap<String, String>) -> Result<(), String> {
    if let Some(path) = opts.get("output") {
        std::fs::write(path, data).map_err(|e| e.to_string())
    } else {
        use std::io::Write;
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{data}").map_err(|e| e.to_string())
    }
}
/// Process exit status of a CLI run. This is the single definition of the numbers documented in
/// docs/src/cli-reference.md; `lib.rs` turns it into the process exit (the only `exit` call).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitCode {
    /// Everything done.
    Success = 0,
    /// Bad arguments, I/O or database error; nothing (or no result) was saved.
    Error = 1,
    /// A scan or capture stopped early and its partial results were saved.
    Partial = 2,
    /// `findings` / `diff` found something at or above `--min-severity`, only with
    /// `--fail-on-findings`.
    Findings = 3,
}
impl ExitCode {
    pub fn code(self) -> i32 {
        self as i32
    }
}
/// Status of a scan or capture whose snapshot was saved: partial when it did not run to the end.
fn saved_exit(complete: bool) -> ExitCode {
    if complete {
        ExitCode::Success
    } else {
        ExitCode::Partial
    }
}
/// Status of `findings`/`diff`: 3 only when the gate is on and `matching` findings were found.
fn findings_exit(fail_on_findings: bool, matching: usize) -> ExitCode {
    if fail_on_findings && matching > 0 {
        ExitCode::Findings
    } else {
        ExitCode::Success
    }
}
/// `--min-severity` for `findings` and for the `diff` gate (default `info`).
fn min_severity(opts: &BTreeMap<String, String>) -> Result<risk::Severity, String> {
    risk::Severity::parse(
        opts.get("min-severity")
            .map(String::as_str)
            .unwrap_or("info"),
    )
    .ok_or_else(|| "Severity must be info, low, medium, high or critical".into())
}
/// New findings of a diff at or above `min`: what `diff --fail-on-findings` gates on. Changed
/// hosts or ports, resolved findings and findings the new scan did not re-check do not count.
fn new_findings_at_or_above(report: &store::DiffReport, min: risk::Severity) -> usize {
    report
        .new_findings
        .iter()
        .filter(|f| f.severity >= min)
        .count()
}
/// Runs one CLI command and returns its exit status. `Err` is an error message for stderr
/// (status 1); every other status is a result of a command that ran.
pub fn run(args: &[String]) -> Result<ExitCode, String> {
    let mut status = ExitCode::Success;
    execute(args, &mut status)?;
    Ok(status)
}
fn execute(args: &[String], status: &mut ExitCode) -> Result<(), String> {
    // Global options may also come before the command (`network-scope --quiet scan ...`).
    let split = args
        .iter()
        .position(|a| a != "--quiet")
        .unwrap_or(args.len());
    let (global, args) = args.split_at(split);
    if args.is_empty() || ["help", "--help", "-h"].contains(&args[0].as_str()) {
        println!("{HELP}");
        return Ok(());
    }
    let command = &args[0];
    let (pos, mut opts) = options(&args[1..])?;
    let fail_on_findings = opts.contains_key("fail-on-findings");
    if fail_on_findings && !matches!(command.as_str(), "findings" | "diff") {
        return Err("--fail-on-findings applies to the findings and diff commands only".into());
    }
    if !global.is_empty() {
        opts.insert("quiet".into(), "true".into());
    }
    let db = opts
        .get("db")
        .map(PathBuf::from)
        .unwrap_or_else(store::default_path);
    let id = |i: usize| -> Result<i64, String> {
        pos.get(i)
            .ok_or("Missing scan ID")?
            .parse()
            .map_err(|_| "Invalid scan ID".into())
    };
    if let Some(file) = opts.get("cves") {
        risk::load_cves(Some(std::path::Path::new(file)))?;
    }
    // `feeds` itself writes the cache, which may not exist yet.
    if command != "feeds"
        && let Some(file) = opts.get("feeds")
    {
        crate::feeds::load_active(std::path::Path::new(file))?;
    }
    match command.as_str() {
        "feeds" => feeds_command(&pos, &opts),
        "completions" => output(
            completions(pos.first().ok_or("Provide the shell: powershell or bash")?)?.trim_end(),
            &opts,
        ),
        "interfaces" => output(
            &serde_json::to_string_pretty(&crate::capture::interfaces()?)
                .map_err(|e| e.to_string())?,
            &opts,
        ),
        "history" => output(
            &serde_json::to_string_pretty(&store::list(&db)?).map_err(|e| e.to_string())?,
            &opts,
        ),
        "diff" => {
            let ignore =
                store::IgnoreList::parse(opts.get("ignore").map(String::as_str).unwrap_or(""));
            let format = opts.get("format").map(String::as_str).unwrap_or("lines");
            // --min-severity only sets the threshold of --fail-on-findings; it does not filter
            // the output, and without the flag it is not read (existing calls are unchanged).
            let gate = if fail_on_findings {
                Some(min_severity(&opts)?)
            } else {
                None
            };
            let report = store::diff_report(
                &store::load(&db, id(0)?)?,
                &store::load(&db, id(1)?)?,
                &ignore,
            )?;
            output(&store::render_diff(&report, format)?, &opts)?;
            if let Some(min) = gate {
                *status = findings_exit(true, new_findings_at_or_above(&report, min));
            }
            Ok(())
        }
        "export" => {
            let snapshot = store::load(&db, id(0)?)?;
            let format = opts.get("format").map(String::as_str).unwrap_or("json");
            let stamp = store::timestamp(&db, id(0)?)?;
            let text = match format {
                "html" => report_html(&db, &snapshot, stamp, &opts)?,
                "nmap" | "xml" => nmap::export(&snapshot, stamp),
                "md" | "markdown" => {
                    let baseline = baseline(&db, &opts)?;
                    crate::report::markdown(
                        &snapshot,
                        baseline.as_ref().map(|(s, t)| (s, *t)),
                        stamp,
                    )
                }
                other => store::export_at(&snapshot, other, stamp)?,
            };
            output(&text, &opts)
        }
        "report" => {
            let snapshot = store::load(&db, id(0)?)?;
            let stamp = store::timestamp(&db, id(0)?)?;
            output(&report_html(&db, &snapshot, stamp, &opts)?, &opts)
        }
        "import" => {
            let path = pos.first().ok_or("Provide the nmap XML file")?;
            let size = std::fs::metadata(path)
                .map_err(|e| format!("{path}: {e}"))?
                .len();
            if size > nmap::MAX_IMPORT_BYTES as u64 {
                return Err("XML file is too large (limit 256 MB)".into());
            }
            let xml = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
            let snapshot = nmap::import(&xml)?;
            let scan_id = store::save(&db, &snapshot)?;
            progress(
                &opts,
                format_args!("Imported {} hosts as scan #{scan_id}", snapshot.hosts.len()),
            );
            Ok(())
        }
        "findings" => {
            let snapshot = store::load(&db, id(0)?)?;
            let min = min_severity(&opts)?;
            let mut list: Vec<_> = risk::analyze_snapshot(&snapshot)
                .into_iter()
                .filter(|f| f.severity >= min)
                .collect();
            // Imported feeds rank known exploited findings first; without them both orders match.
            match opts.get("sort").map(String::as_str).unwrap_or("exploited") {
                "exploited" => {}
                "severity" => crate::feeds::sort_by_severity(&mut list),
                _ => return Err("Sort must be exploited or severity".into()),
            }
            output(
                &serde_json::to_string_pretty(&list).map_err(|e| e.to_string())?,
                &opts,
            )?;
            *status = findings_exit(fail_on_findings, list.len());
            Ok(())
        }
        "alerts" => output(
            &serde_json::to_string_pretty(&store::list_alerts(&db, 500)?)
                .map_err(|e| e.to_string())?,
            &opts,
        ),
        "scripts" => {
            let scripts = crate::script::Scripts::load(
                pos.first().ok_or("Provide a script file or folder")?,
            )?;
            output(&scripts.describe().join("\n"), &opts)
        }
        "monitor" => {
            let targets = pos.join(" ");
            let mut s = scan_settings(&opts)?;
            s.scan_nonresponders = true;
            let policy = monitor_policy(&opts)?;
            let cfg = monitor::RunConfig {
                interval: Duration::from_secs(number(&opts, "interval", 300u64)?.clamp(1, 86_400)),
                cycles: number(&opts, "cycles", 0)?,
                policy,
                dhcp_discover: opts.contains_key("dhcp-discover"),
                interface: opts.get("interface").cloned().unwrap_or_default(),
                listen_seconds: number(&opts, "listen-seconds", 30)?,
                quiet: opts.contains_key("quiet"),
            };
            let mut file = match opts.get("alerts") {
                Some(p) => Some(
                    std::fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(p)
                        .map_err(|e| format!("{p}: {e}"))?,
                ),
                None => None,
            };
            monitor::run(&targets, s, &db, &cfg, &mut |a| {
                let line = serde_json::to_string(a).unwrap_or_default();
                println!("{line}");
                if let Some(f) = file.as_mut() {
                    use std::io::Write;
                    let _ = writeln!(f, "{line}");
                }
            })
        }
        "ot-listen" => {
            let mut tracker = crate::otpassive::Tracker::new();
            tracker.set_reassembly(!opts.contains_key("no-reassembly"));
            let label = if let Some(path) = opts.get("pcap") {
                if opts.contains_key("progress") && !opts.contains_key("quiet") {
                    crate::otpassive::read_pcap_file_with_progress(
                        path,
                        &mut tracker,
                        None,
                        &mut |p| {
                            eprint!("\r{}{}", p.line(), if p.done { "\n" } else { "   " });
                        },
                    )?;
                } else {
                    crate::otpassive::read_pcap_file(path, &mut tracker)?;
                }
                format!("ot-passive:{path}")
            } else {
                let interface = opts
                    .get("interface")
                    .ok_or("Provide --interface (see the interfaces command) or --pcap FILE")?;
                let seconds: u64 = number(&opts, "seconds", 300)?;
                if !(1..=604_800).contains(&seconds) {
                    return Err("Seconds must be 1-604800".into());
                }
                progress(
                    &opts,
                    format_args!(
                        "Listening passively on {interface} for {seconds} s. Nothing is transmitted."
                    ),
                );
                let cancel = std::sync::atomic::AtomicBool::new(false);
                crate::otpassive::listen_live(interface, seconds, &cancel, &mut tracker)?;
                format!("ot-passive:{interface}")
            };
            let snapshot = store::Snapshot {
                targets: label,
                complete: true,
                settings: scan::Settings::default(),
                hosts: vec![],
                observations: tracker.observations(),
                notes: BTreeMap::new(),
            };
            let scan_id = store::save(&db, &snapshot)?;
            let (reassembled, abandoned) = tracker.reassembly_stats();
            progress(
                &opts,
                format_args!(
                    "Saved passive OT capture #{scan_id}: {} frames, {} observations{}",
                    tracker.frames,
                    snapshot.observations.len(),
                    if reassembled + abandoned > 0 {
                        format!(
                            ", {reassembled} messages reassembled, {abandoned} partial messages"
                        )
                    } else {
                        String::new()
                    }
                ),
            );
            ot_assets_output(&snapshot, &opts)
        }
        "ot-assets" => ot_assets_output(&store::load(&db, id(0)?)?, &opts),
        "devices" => {
            if let Some(q) = opts.get("history") {
                let h = store::device_history(&db, q)?;
                return output(
                    &devices::history_output(
                        &h,
                        opts.get("format").map(String::as_str).unwrap_or("text"),
                    )?,
                    &opts,
                );
            }
            let snapshot = store::load(&db, id(0)?)?;
            let devices = devices::merge(&snapshot.hosts, &snapshot.observations);
            match opts.get("format").map(String::as_str).unwrap_or("json") {
                "json" => output(
                    &serde_json::to_string_pretty(&devices).map_err(|e| e.to_string())?,
                    &opts,
                ),
                "csv" => output(&devices::csv(&devices), &opts),
                _ => Err("Choose json or csv".into()),
            }
        }
        "topology" => {
            let snapshot = store::load(&db, id(0)?)?;
            let graph = topology::build(&snapshot.hosts);
            match opts.get("format").map(String::as_str).unwrap_or("ascii") {
                "ascii" => output(topology::ascii(&graph).trim_end(), &opts),
                "dot" => output(topology::dot(&graph).trim_end(), &opts),
                _ => Err("Choose ascii or dot".into()),
            }
        }
        "trace" => {
            let target: std::net::IpAddr = pos
                .first()
                .ok_or("Provide a target IP address")?
                .parse()
                .map_err(|_| "Target must be an IP address".to_string())?;
            let hops: u8 = number(&opts, "max-hops", 20)?;
            let timeout: u32 = number(&opts, "timeout", 1000)?;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .max_blocking_threads(128)
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            let blocking = std::sync::Arc::new(tokio::sync::Semaphore::new(64));
            let method = match opts.get("trace-method") {
                Some(m) => trace_method(m)?,
                None => crate::trace::TraceMethod::Icmp,
            };
            // TCP/UDP traceroute transmits beyond ICMP echo: like in scans, only with --fast.
            if method != crate::trace::TraceMethod::Icmp && !opts.contains_key("fast") {
                return Err("TCP/UDP traceroute needs --fast (Safe Mode allows ICMP only)".into());
            }
            let rate: u32 = number(&opts, "rate", 0)?;
            let gate = if rate > 0 {
                crate::core::Gate::per_second(f64::from(rate), (f64::from(rate) / 10.0).max(1.0))
            } else {
                crate::core::Gate::unlimited()
            };
            let v4 = || match target {
                std::net::IpAddr::V4(v4) => Ok(v4),
                _ => Err("TCP/UDP traceroute is IPv4 only".to_string()),
            };
            let path = match method {
                crate::trace::TraceMethod::Icmp => runtime
                    .block_on(crate::trace::trace(target, hops, timeout, &blocking, &gate))?,
                crate::trace::TraceMethod::Udp => runtime.block_on(crate::trace::trace_udp(
                    v4()?,
                    hops,
                    timeout,
                    &blocking,
                    &gate,
                ))?,
                crate::trace::TraceMethod::Tcp => {
                    let port = trace_port(
                        opts.get("trace-port")
                            .ok_or("TCP traceroute needs --trace-port N (an open port)")?,
                    )?;
                    let settings = scan_settings(&opts)?;
                    crate::trace::assemble(crate::syn::tcp_trace(
                        &settings,
                        v4()?,
                        port,
                        hops,
                        timeout,
                        &gate,
                    )?)
                }
            };
            let mut text = format!("Path to {target}\n");
            for h in &path {
                text.push_str(&format!(
                    "{:>3}  {:<40} {}\n",
                    h.ttl,
                    h.ip.map_or("*".to_string(), |ip| ip.to_string()),
                    h.rtt.map_or(String::new(), |r| format!("{r} ms"))
                ));
            }
            output(text.trim_end(), &opts)
        }
        "probes" => {
            let db = crate::service::ProbeDb::load(
                opts.get("probes").map(String::as_str).unwrap_or(""),
            )?;
            let mut text = format!(
                "{} TCP probes, {} UDP probes\n",
                db.probes.len(),
                db.udp.len()
            );
            let tagged = db
                .probes
                .iter()
                .map(|p| ("tcp", p))
                .chain(db.udp.iter().map(|p| ("udp", p)));
            for (proto, p) in tagged {
                text.push_str(&format!(
                    "{proto} {:<12} ports {:<16} {} bytes sent, {} rules\n",
                    p.name,
                    if p.ports.is_empty() {
                        "any (listen)".to_string()
                    } else {
                        p.ports
                            .iter()
                            .map(u16::to_string)
                            .collect::<Vec<_>>()
                            .join(",")
                    },
                    p.payload.len(),
                    p.rules.len()
                ));
            }
            output(text.trim_end(), &opts)
        }
        "scan" => {
            let targets = pos.join(" ");
            let s = scan_settings(&opts)?;
            let format = opts.get("format").map(String::as_str).unwrap_or("json");
            if !["json", "csv", "html", "nmap", "md", "jsonl"].contains(&format) {
                return Err("Choose json, csv, html, nmap, md or jsonl".into());
            }
            let hosts = scan::parse_targets(&targets, s.skip_edges, scan::MAX_STREAM)?;
            let ports = scan::parse_ports(&s.ports)?;
            let total = hosts.count() as usize;
            let run = scan::start_stream(Box::new(hosts.iter()), total, ports, s.clone());
            let (results, complete, errors) = if opts.contains_key("tui") {
                tui(&run)
            } else {
                collect(&run)
            };
            if results.is_empty() && !errors.is_empty() {
                return Err(errors.join("; "));
            }
            let snapshot = store::Snapshot {
                targets,
                complete,
                settings: s,
                hosts: results,
                observations: vec![],
                notes: BTreeMap::new(),
            };
            let id = store::save(&db, &snapshot)?;
            progress(
                &opts,
                format_args!(
                    "Saved scan #{id} ({})",
                    if complete { "complete" } else { "partial" }
                ),
            );
            output(
                &store::export_at(&snapshot, format, store::timestamp(&db, id)?)?,
                &opts,
            )?;
            // Saved but stopped early (TUI stop, or errors): partial result, status 2.
            if !errors.is_empty() {
                eprintln!(
                    "Scan #{id} saved as partial after errors: {}",
                    errors.join("; ")
                );
            }
            *status = saved_exit(complete);
            Ok(())
        }
        "listen" | "dcp" => {
            let interface = opts
                .get("interface")
                .ok_or("Provide --interface from the interfaces command")?;
            let seconds: u64 = number(&opts, "seconds", 60)?;
            if !(1..=86400).contains(&seconds) {
                return Err("Seconds must be 1–86400".into());
            }
            let source = if command == "dcp" {
                Some(crate::capture::mac(
                    opts.get("source-mac")
                        .ok_or("Provide --source-mac of the interface")?,
                )?)
            } else {
                None
            };
            let run = passive::start(interface.clone(), seconds, source);
            let (observations, error) = drain_observations(&run.receiver);
            if error.is_some() {
                run.cancel.store(true, Ordering::Relaxed);
            }
            drop(run);
            if let (Some(e), true) = (&error, observations.is_empty()) {
                return Err(e.clone());
            }
            let snapshot = store::Snapshot {
                targets: format!("{command}:{interface}"),
                complete: error.is_none(),
                settings: scan::Settings::default(),
                hosts: vec![],
                observations,
                notes: BTreeMap::new(),
            };
            let id = store::save(&db, &snapshot)?;
            progress(
                &opts,
                format_args!(
                    "Saved capture #{id} ({})",
                    if error.is_none() {
                        "complete"
                    } else {
                        "partial"
                    }
                ),
            );
            output(
                &store::export_at(
                    &snapshot,
                    opts.get("format").map(String::as_str).unwrap_or("json"),
                    store::timestamp(&db, id)?,
                )?,
                &opts,
            )?;
            if let Some(e) = &error {
                eprintln!("Capture #{id} saved as partial: {e}");
            }
            *status = saved_exit(error.is_none());
            Ok(())
        }
        _ => Err(format!("Unknown command {command}. Use --help.")),
    }
}
/// Adds an observation, or merges its fields into the entry with the same MAC, protocol and IP.
/// Linear lookup; long-running callers should use [`merge_indexed`] with an [`ObservationIndex`].
pub fn merge(
    observations: &mut Vec<passive::Observation>,
    o: passive::Observation,
) -> Result<(), String> {
    if let Some(old) = observations
        .iter_mut()
        .find(|v| v.mac == o.mac && v.protocol == o.protocol && v.ip == o.ip)
    {
        old.fields.extend(o.fields);
    } else if observations.len() < MAX_OBSERVATIONS {
        observations.push(o);
    } else {
        return Err(LIMIT_MESSAGE.into());
    }
    Ok(())
}
const MAX_OBSERVATIONS: usize = 10_000;
const LIMIT_MESSAGE: &str = "Observation limit (10,000) reached";
type ObservationKey = (String, String, Option<std::net::IpAddr>);
fn observation_key(o: &passive::Observation) -> ObservationKey {
    (o.mac.clone(), o.protocol.clone(), o.ip)
}
/// Hash index over an observation list for [`merge_indexed`]. It rebuilds itself when the list
/// was replaced or changed behind its back (length mismatch or a stale entry).
#[derive(Default)]
pub struct ObservationIndex {
    map: std::collections::HashMap<ObservationKey, usize>,
    len: usize,
}
impl ObservationIndex {
    pub fn clear(&mut self) {
        self.map.clear();
        self.len = 0;
    }
    fn rebuild(&mut self, observations: &[passive::Observation]) {
        self.map.clear();
        for (i, o) in observations.iter().enumerate() {
            self.map.entry(observation_key(o)).or_insert(i);
        }
        self.len = observations.len();
    }
    fn find(&self, observations: &[passive::Observation], key: &ObservationKey) -> Option<usize> {
        self.map.get(key).copied().filter(|&i| {
            observations
                .get(i)
                .is_some_and(|v| v.mac == key.0 && v.protocol == key.1 && v.ip == key.2)
        })
    }
}
/// Same semantics as [`merge`] in O(1) per call.
pub fn merge_indexed(
    observations: &mut Vec<passive::Observation>,
    index: &mut ObservationIndex,
    o: passive::Observation,
) -> Result<(), String> {
    if index.len != observations.len() {
        index.rebuild(observations);
    }
    let key = observation_key(&o);
    let mut found = index.find(observations, &key);
    if found.is_none() && index.map.contains_key(&key) {
        // Stale entry: the list was edited in place.
        index.rebuild(observations);
        found = index.find(observations, &key);
    }
    if let Some(i) = found {
        observations[i].fields.extend(o.fields);
    } else if observations.len() < MAX_OBSERVATIONS {
        index.map.insert(key, observations.len());
        observations.push(o);
        index.len = observations.len();
    } else {
        return Err(LIMIT_MESSAGE.into());
    }
    Ok(())
}
/// Collects a passive capture; on an error (capture failure or the observation cap) it stops and
/// returns everything gathered so far together with the error.
/// Collects a capture. Error items (a full capture queue, a read error, the observation cap)
/// are warnings: they are printed once each, mark the capture partial and collection goes on
/// with what still arrives, as in the GUI and `monitor`.
fn drain_observations(
    items: impl IntoIterator<Item = Result<passive::Observation, String>>,
) -> (Vec<passive::Observation>, Option<String>) {
    let mut observations = vec![];
    let mut index = ObservationIndex::default();
    let mut errors: Vec<String> = vec![];
    for item in items {
        if let Err(e) = item.and_then(|o| merge_indexed(&mut observations, &mut index, o))
            && !errors.contains(&e)
        {
            eprintln!("Warning: {e}");
            errors.push(e);
        }
    }
    (
        observations,
        (!errors.is_empty()).then(|| errors.join("; ")),
    )
}
/// Applies one scan event and returns true on `Done`. Errors never discard results: they are
/// recorded and mark the scan partial (the engine always follows with `Done`).
fn accept(
    event: scan::Event,
    hosts: &mut Vec<scan::Host>,
    sparse: bool,
    errors: &mut Vec<String>,
) -> bool {
    match event {
        scan::Event::Host(h) => {
            if h.responding || !sparse {
                hosts.push(h)
            }
            false
        }
        scan::Event::Done => true,
        scan::Event::Error(e) => {
            errors.push(e);
            false
        }
    }
}
/// Hosts, complete flag, errors.
type Collected = (Vec<scan::Host>, bool, Vec<String>);
fn collect(run: &scan::Running) -> Collected {
    let mut hosts = vec![];
    let mut errors = vec![];
    let sparse = run.total > scan::MAX_HOSTS;
    loop {
        match run.receiver.recv() {
            Ok(event) => {
                if accept(event, &mut hosts, sparse, &mut errors) {
                    break;
                }
            }
            Err(_) => {
                errors.push("Scan worker disconnected".into());
                break;
            }
        }
    }
    let complete = errors.is_empty() && !run.cancel.load(Ordering::Relaxed);
    (hosts, complete, errors)
}
fn stop_key(code: crossterm::event::KeyCode) -> bool {
    use crossterm::event::KeyCode;
    matches!(code, KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc)
}
static TUI_THREAD: std::sync::Mutex<Option<std::thread::ThreadId>> = std::sync::Mutex::new(None);
fn restore_terminal() {
    let _ = crossterm::terminal::disable_raw_mode();
    let _ = crossterm::execute!(
        std::io::stdout(),
        crossterm::terminal::LeaveAlternateScreen,
        crossterm::cursor::Show
    );
}
/// Panic messages from other threads while the live view is on; printed once it is closed.
static TUI_PANICS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
/// A panic printed inside the alternate screen would be lost. On the TUI thread the terminal is
/// restored first; panics of worker threads (the TUI keeps running) are also kept and printed
/// after the terminal is restored. Then the previous (default) hook runs. Installed once; inert
/// outside the TUI.
fn install_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let tui = TUI_THREAD.lock().map(|t| *t).unwrap_or(None);
            if let Some(id) = tui {
                if id == std::thread::current().id() {
                    restore_terminal();
                } else {
                    if let Ok(mut panics) = TUI_PANICS.lock()
                        && panics.len() < 16
                    {
                        let thread = std::thread::current();
                        panics.push(format!(
                            "thread '{}' {info}",
                            thread.name().unwrap_or("<unnamed>")
                        ));
                    }
                }
            }
            previous(info);
        }));
    });
}
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
enum TuiSort {
    #[default]
    Newest,
    Address,
    OpenPorts,
}
impl TuiSort {
    fn next(self) -> Self {
        match self {
            Self::Newest => Self::Address,
            Self::Address => Self::OpenPorts,
            Self::OpenPorts => Self::Newest,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Newest => "newest",
            Self::Address => "address",
            Self::OpenPorts => "open ports",
        }
    }
}
#[derive(PartialEq, Eq, Debug)]
enum TuiAction {
    None,
    Stop,
    Pause,
}
/// Live view state: sort order, selection (kept by address across re-sorts) and detail view.
#[derive(Default)]
struct TuiView {
    sort: TuiSort,
    selected: Option<std::net::IpAddr>,
    detail: bool,
    /// First line shown in the detail view.
    scroll: u16,
    /// Indexes into the host list in display order.
    order: Vec<usize>,
    key: Option<(usize, TuiSort)>,
}
impl TuiView {
    /// Re-sorts only when hosts arrived or the sort mode changed.
    fn refresh(&mut self, hosts: &[scan::Host]) {
        let key = (hosts.len(), self.sort);
        if self.key == Some(key) {
            return;
        }
        self.key = Some(key);
        let mut order: Vec<usize> = (0..hosts.len()).collect();
        match self.sort {
            TuiSort::Newest => order.reverse(),
            TuiSort::Address => order.sort_by_key(|&i| hosts[i].ip),
            TuiSort::OpenPorts => order.sort_by(|&a, &b| {
                let n = |h: &scan::Host| h.open.len() + h.udp_open.len();
                n(&hosts[b])
                    .cmp(&n(&hosts[a]))
                    .then(hosts[a].ip.cmp(&hosts[b].ip))
            }),
        }
        self.order = order;
    }
    fn position(&self, hosts: &[scan::Host]) -> Option<usize> {
        let ip = self.selected?;
        self.order.iter().position(|&i| hosts[i].ip == ip)
    }
    /// Visible slice of `order` for a list of `height` rows, keeping the selection in view.
    fn window(&self, hosts: &[scan::Host], height: usize) -> (usize, usize) {
        let start = match self.position(hosts) {
            Some(p) if height > 0 && p >= height => p + 1 - height,
            _ => 0,
        };
        (start, (start + height).min(self.order.len()))
    }
    fn detail_host<'a>(&self, hosts: &'a [scan::Host]) -> Option<&'a scan::Host> {
        if !self.detail {
            return None;
        }
        let ip = self.selected?;
        hosts.iter().find(|h| h.ip == ip)
    }
    fn key(&mut self, code: crossterm::event::KeyCode, hosts: &[scan::Host]) -> TuiAction {
        use crossterm::event::KeyCode;
        if stop_key(code) {
            return TuiAction::Stop;
        }
        self.refresh(hosts);
        let len = self.order.len();
        let current = self.position(hosts);
        let target = match code {
            KeyCode::Char(' ') => return TuiAction::Pause,
            KeyCode::Char('s') | KeyCode::Char('S') => {
                self.sort = self.sort.next();
                self.refresh(hosts);
                return TuiAction::None;
            }
            KeyCode::Enter => {
                self.scroll = 0;
                if self.detail {
                    self.detail = false;
                } else if current.is_some() {
                    self.detail = true;
                } else if let Some(&first) = self.order.first() {
                    self.selected = Some(hosts[first].ip);
                    self.detail = true;
                }
                return TuiAction::None;
            }
            KeyCode::Backspace | KeyCode::Left => {
                self.detail = false;
                return TuiAction::None;
            }
            KeyCode::Down | KeyCode::PageDown if self.detail => {
                let step = if code == KeyCode::Down { 1 } else { 10 };
                self.scroll = self.scroll.saturating_add(step).min(500);
                return TuiAction::None;
            }
            KeyCode::Up | KeyCode::PageUp if self.detail => {
                let step = if code == KeyCode::Up { 1 } else { 10 };
                self.scroll = self.scroll.saturating_sub(step);
                return TuiAction::None;
            }
            _ if self.detail || len == 0 => return TuiAction::None,
            KeyCode::Down => current.map_or(0, |p| (p + 1).min(len - 1)),
            KeyCode::Up => current.map_or(0, |p| p.saturating_sub(1)),
            KeyCode::PageDown => current.map_or(0, |p| (p + 10).min(len - 1)),
            KeyCode::PageUp => current.map_or(0, |p| p.saturating_sub(10)),
            KeyCode::Home => 0,
            KeyCode::End => len - 1,
            _ => return TuiAction::None,
        };
        self.selected = Some(hosts[self.order[target]].ip);
        TuiAction::None
    }
}
/// Detail view text: ports with their identified services, identity and findings.
fn detail_lines(h: &scan::Host) -> Vec<String> {
    let mut lines = vec![
        format!(
            "Status: {}{}",
            if h.responding {
                "responding"
            } else {
                "no reply"
            },
            h.ping.map_or(String::new(), |p| format!(" · ping {p} ms"))
        ),
        format!(
            "Hostname: {}",
            if h.hostname.is_empty() {
                "-"
            } else {
                &h.hostname
            }
        ),
        format!("MAC: {}", if h.mac.is_empty() { "-" } else { &h.mac }),
        String::new(),
        format!("Open TCP ports ({})", h.open.len()),
    ];
    for p in &h.open {
        let service = h.identity.get(&format!("svc.{p}"));
        lines.push(format!(
            "  {p:>5}/tcp  {}",
            service.map_or("", String::as_str)
        ));
    }
    if !h.udp_open.is_empty() {
        lines.push(format!("Open UDP ports ({})", h.udp_open.len()));
        for p in &h.udp_open {
            let service = h.identity.get(&format!("udp.{p}"));
            lines.push(format!(
                "  {p:>5}/udp  {}",
                service.map_or("", String::as_str)
            ));
        }
    }
    let findings = risk::analyze_host(h);
    lines.push(String::new());
    lines.push(format!("Findings ({})", findings.len()));
    for f in &findings {
        lines.push(format!(
            "  [{}] {}{}: {}",
            f.severity.name(),
            f.title,
            f.port.map_or(String::new(), |p| format!(" (port {p})")),
            f.evidence
        ));
    }
    let identity: Vec<String> = h
        .identity
        .iter()
        .filter(|(k, _)| {
            !k.starts_with("svc.") && !k.starts_with("udp.") && !k.starts_with("finding.")
        })
        .map(|(k, v)| format!("  {k}: {v}"))
        .collect();
    if !identity.is_empty() {
        lines.push(String::new());
        lines.push("Identity".into());
        lines.extend(identity);
    }
    for e in &h.errors {
        lines.push(format!("Error: {e}"));
    }
    lines
}
/// One frame of the live view: the host list, or the detail view of the selected host.
fn draw_tui(f: &mut ratatui::Frame, view: &TuiView, hosts: &[scan::Host], progress: &str) {
    use ratatui::{
        layout::Constraint,
        style::{Modifier, Style},
        text::Line,
        widgets::{Block, Borders, Paragraph, Row, Table, Wrap},
    };
    let area = f.area();
    if let Some(host) = view.detail_host(hosts) {
        let lines: Vec<Line> = detail_lines(host).into_iter().map(Line::from).collect();
        f.render_widget(
            Paragraph::new(lines)
                .wrap(Wrap { trim: false })
                .scroll((view.scroll, 0))
                .block(Block::default().borders(Borders::ALL).title(format!(
                    " {} · {progress} · ↑↓ scroll · Enter/Backspace back · Space pause / Q stop ",
                    host.ip
                ))),
            area,
        );
        return;
    }
    let height = area.height.saturating_sub(3) as usize;
    let (start, end) = view.window(hosts, height);
    let rows = view.order[start..end].iter().map(|&i| {
        let h: &scan::Host = &hosts[i];
        let row = Row::new(vec![
            h.ip.to_string(),
            if h.responding {
                "Responding"
            } else {
                "No reply"
            }
            .into(),
            h.open
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(","),
            h.identity
                .keys()
                .filter(|k| k.ends_with("name") || k.ends_with("firmware"))
                .map(|k| format!("{k}: {}", h.identity[k]))
                .collect::<Vec<_>>()
                .join("; "),
        ]);
        if view.selected == Some(h.ip) {
            row.style(Style::default().add_modifier(Modifier::REVERSED))
        } else {
            row
        }
    });
    f.render_widget(
        Table::new(
            rows,
            [
                Constraint::Length(18),
                Constraint::Length(13),
                Constraint::Length(22),
                Constraint::Min(10),
            ],
        )
        .header(Row::new(["IP", "Status", "Ports", "Identity"]))
        .block(Block::default().borders(Borders::ALL).title(format!(
            " Network Scope · {progress} · sort: {} (S) · ↑↓ Enter details · Space pause / Q stop ",
            view.sort.name()
        ))),
        area,
    );
}
fn tui(run: &scan::Running) -> Collected {
    use crossterm::{
        event::{self, Event, KeyEventKind},
        execute,
        terminal::{EnterAlternateScreen, enable_raw_mode},
    };
    use ratatui::{Terminal, backend::CrosstermBackend};
    /// Undoes only what was set up, then prints panics of other threads seen meanwhile.
    struct Restore {
        raw: bool,
        screen: bool,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            if let Ok(mut t) = TUI_THREAD.lock() {
                *t = None;
            }
            if self.raw {
                let _ = crossterm::terminal::disable_raw_mode();
            }
            if self.screen {
                let _ = crossterm::execute!(
                    std::io::stdout(),
                    crossterm::terminal::LeaveAlternateScreen,
                    crossterm::cursor::Show
                );
            }
            if let Ok(mut panics) = TUI_PANICS.lock() {
                for p in panics.drain(..) {
                    eprintln!("{p}");
                }
            }
        }
    }
    install_panic_hook();
    if let Ok(mut t) = TUI_THREAD.lock() {
        *t = Some(std::thread::current().id());
    }
    let mut restore = Restore {
        raw: false,
        screen: false,
    };
    let setup = enable_raw_mode()
        .and_then(|()| {
            restore.raw = true;
            execute!(std::io::stdout(), EnterAlternateScreen)
        })
        .and_then(|()| {
            restore.screen = true;
            Terminal::new(CrosstermBackend::new(std::io::stdout()))
        });
    let mut terminal = match setup {
        Ok(t) => t,
        Err(e) => {
            // No usable terminal: keep the scan and collect it without the live view.
            drop(restore);
            eprintln!("Live view unavailable ({e}); collecting without it.");
            return collect(run);
        }
    };
    let mut hosts = vec![];
    let mut errors = vec![];
    let mut seen = 0usize;
    let mut view = TuiView::default();
    let sparse = run.total > scan::MAX_HOSTS;
    let mut done = false;
    while !done {
        loop {
            match run.receiver.try_recv() {
                Ok(event) => {
                    if matches!(event, scan::Event::Host(_)) {
                        seen += 1;
                    }
                    if accept(event, &mut hosts, sparse, &mut errors) {
                        done = true;
                        break;
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(_) => {
                    errors.push("Scan worker disconnected".into());
                    done = true;
                    break;
                }
            }
        }
        if done {
            break;
        }
        view.refresh(&hosts);
        let paused = run.pause.load(Ordering::Relaxed);
        let progress = format!(
            "{seen}/{} · {}",
            run.total,
            if paused { "paused" } else { "scanning" }
        );
        let drawn = terminal.draw(|f| draw_tui(f, &view, &hosts, &progress));
        let input = drawn.and_then(|_| {
            if event::poll(Duration::from_millis(60))?
                && let Event::Key(k) = event::read()?
                && k.kind == KeyEventKind::Press
            {
                match view.key(k.code, &hosts) {
                    TuiAction::Stop => run.cancel.store(true, Ordering::Relaxed),
                    TuiAction::Pause => {
                        run.pause.fetch_xor(true, Ordering::Relaxed);
                    }
                    TuiAction::None => {}
                }
            }
            Ok(())
        });
        if let Err(e) = input {
            // Terminal failure: stop the scan but keep what was found.
            errors.push(format!("Terminal: {e}"));
            run.cancel.store(true, Ordering::Relaxed);
            break;
        }
    }
    drop(restore);
    let complete = done && errors.is_empty() && !run.cancel.load(Ordering::Relaxed);
    (hosts, complete, errors)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }
    fn obs(
        mac: &str,
        protocol: &str,
        ip: Option<&str>,
        field: (&str, &str),
    ) -> passive::Observation {
        passive::Observation {
            protocol: protocol.into(),
            mac: mac.into(),
            ip: ip.map(|i| i.parse().unwrap()),
            fields: BTreeMap::from([(field.0.to_string(), field.1.to_string())]),
        }
    }

    #[test]
    fn monitor_alerts_option_is_accepted() {
        let (pos, opts) = options(&args(&[
            "10.0.0.0/24",
            "--alerts",
            "alerts.jsonl",
            "--learn",
        ]))
        .unwrap();
        assert_eq!(pos, ["10.0.0.0/24"]);
        assert_eq!(opts["alerts"], "alerts.jsonl");
        assert_eq!(opts["learn"], "true");
        assert!(
            options(&args(&["--alerts"]))
                .unwrap_err()
                .contains("Missing --alerts")
        );
        assert!(
            options(&args(&["--bogus"]))
                .unwrap_err()
                .contains("Unknown")
        );
    }

    #[test]
    fn every_option_read_by_a_command_is_declared() {
        let src = include_str!("ui.rs");
        let mut keys = std::collections::BTreeSet::new();
        for pattern in [
            "opts.get(\"",
            "opts.contains_key(\"",
            "number(opts, \"",
            "number(&opts, \"",
        ] {
            for part in src.split(pattern).skip(1) {
                keys.insert(part.split('"').next().unwrap().to_string());
            }
        }
        assert!(keys.len() > 30, "{keys:?}");
        for k in &keys {
            assert!(
                FLAGS.contains(&k.as_str()) || VALUES.contains(&k.as_str()),
                "--{k} is read but not declared"
            );
        }
        for k in FLAGS {
            assert!(!VALUES.contains(&k), "--{k} is both flag and value");
        }
    }

    #[test]
    fn new_scan_and_monitor_options_parse() {
        let (_, opts) = options(&args(&[
            "--arp-sweep",
            "--adaptive-syn",
            "--trace-method",
            "TCP",
            "--trace-port",
            "8443",
        ]))
        .unwrap();
        let s = scan_settings(&opts).unwrap();
        assert!(s.arp_sweep && s.syn_adaptive && s.trace && s.safe);
        assert_eq!(s.trace_method, crate::trace::TraceMethod::Tcp);
        assert_eq!(s.trace_port, 8443);
        assert!(trace_method("ping").is_err());
        assert!(trace_port("502").unwrap_err().contains("OT or printer"));
        assert!(trace_port("9100").is_err());
        assert!(trace_port("0").is_err());
        let (_, opts) = options(&args(&[
            "--webhook",
            "http://127.0.0.1:9000/hook",
            "--syslog",
            "udp://127.0.0.1,tcp://127.0.0.1:6514",
            "--alert-timeout",
            "10",
            "--no-dedup",
            "--renotify-hours",
            "0",
        ]))
        .unwrap();
        let p = monitor_policy(&opts).unwrap();
        assert_eq!(p.notify.sinks.len(), 3);
        assert_eq!(p.notify.timeout, Duration::from_secs(10));
        assert!(!p.notify.dedup);
        assert_eq!(p.notify.renotify, None);
        assert!(
            run(&args(&["trace", "127.0.0.1", "--trace-method", "udp"]))
                .unwrap_err()
                .contains("--fast")
        );
        let defaults = monitor_policy(&BTreeMap::new()).unwrap();
        assert!(defaults.notify.sinks.is_empty() && defaults.notify.dedup);
        let https = BTreeMap::from([("webhook".to_string(), "https://hooks.local/a".to_string())]);
        assert_eq!(monitor_policy(&https).unwrap().notify.sinks.len(), 1);
        let ftp = BTreeMap::from([("webhook".to_string(), "ftp://x".to_string())]);
        assert!(monitor_policy(&ftp).unwrap_err().contains("https://"));
        let slow = BTreeMap::from([("alert-timeout".to_string(), "600".to_string())]);
        assert!(monitor_policy(&slow).is_err());
    }

    #[test]
    fn indexed_merge_matches_linear_merge() {
        let input = vec![
            obs("aa", "mDNS", Some("10.0.0.1"), ("name", "a")),
            obs("aa", "mDNS", Some("10.0.0.1"), ("model", "x")),
            obs("aa", "mDNS", None, ("name", "b")),
            obs("aa", "LLDP", Some("10.0.0.1"), ("port", "1")),
            obs("bb", "mDNS", Some("10.0.0.1"), ("name", "c")),
            obs("aa", "mDNS", Some("10.0.0.1"), ("name", "a2")),
        ];
        let mut linear = vec![];
        let mut indexed = vec![];
        let mut index = ObservationIndex::default();
        for o in input {
            merge(&mut linear, o.clone()).unwrap();
            merge_indexed(&mut indexed, &mut index, o).unwrap();
        }
        assert_eq!(linear, indexed);
        assert_eq!(indexed.len(), 4);
        assert_eq!(indexed[0].fields["name"], "a2");
        assert_eq!(indexed[0].fields["model"], "x");
        // The list is replaced behind the index's back: it must notice and rebuild.
        indexed = vec![obs("cc", "ARP", None, ("x", "1"))];
        merge_indexed(&mut indexed, &mut index, obs("cc", "ARP", None, ("y", "2"))).unwrap();
        assert_eq!(indexed.len(), 1);
        assert_eq!(indexed[0].fields.len(), 2);
        // Same length, different content.
        indexed = vec![obs("dd", "ARP", None, ("x", "1"))];
        merge_indexed(&mut indexed, &mut index, obs("cc", "ARP", None, ("z", "3"))).unwrap();
        assert_eq!(indexed.len(), 2);
        index.clear();
        merge_indexed(&mut indexed, &mut index, obs("dd", "ARP", None, ("w", "4"))).unwrap();
        assert_eq!(indexed.len(), 2);
    }

    #[test]
    fn observation_cap_keeps_merging_existing_entries() {
        let mut list = vec![];
        let mut index = ObservationIndex::default();
        for i in 0..MAX_OBSERVATIONS {
            merge_indexed(
                &mut list,
                &mut index,
                obs(&format!("{i}"), "ARP", None, ("n", "1")),
            )
            .unwrap();
        }
        merge_indexed(&mut list, &mut index, obs("5", "ARP", None, ("m", "2"))).unwrap();
        assert_eq!(list[5].fields["m"], "2");
        assert!(merge_indexed(&mut list, &mut index, obs("new", "ARP", None, ("n", "1"))).is_err());
        assert!(merge(&mut list, obs("new", "ARP", None, ("n", "1"))).is_err());
        assert!(merge(&mut list, obs("7", "ARP", None, ("m", "2"))).is_ok());
    }

    #[test]
    fn capture_errors_keep_collected_observations() {
        let items = vec![
            Ok(obs("aa", "ARP", None, ("a", "1"))),
            Ok(obs("bb", "ARP", None, ("a", "1"))),
            Err("Capture queue full".to_string()),
            Ok(obs("cc", "ARP", None, ("a", "1"))),
        ];
        let (list, error) = drain_observations(items);
        assert_eq!(list.len(), 3, "observations after a warning are kept");
        assert_eq!(error.as_deref(), Some("Capture queue full"));
        let many =
            (0..MAX_OBSERVATIONS + 5).map(|i| Ok(obs(&format!("{i}"), "ARP", None, ("a", "1"))));
        let (list, error) = drain_observations(many);
        assert_eq!(list.len(), MAX_OBSERVATIONS);
        assert!(error.unwrap().contains("limit"));
        let (list, error) = drain_observations(vec![Ok(obs("aa", "ARP", None, ("a", "1")))]);
        assert_eq!((list.len(), error), (1, None));
    }

    #[test]
    fn scan_errors_do_not_discard_hosts() {
        let host = |ip: &str, responding: bool| scan::Host {
            ip: ip.parse().unwrap(),
            responding,
            ping: None,
            ttl: None,
            hostname: String::new(),
            mac: String::new(),
            open: vec![],
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: false,
            identity: BTreeMap::new(),
            udp_open: vec![],
            trace: vec![],
        };
        let mut hosts = vec![];
        let mut errors = vec![];
        assert!(!accept(
            scan::Event::Host(host("10.0.0.1", true)),
            &mut hosts,
            false,
            &mut errors
        ));
        assert!(!accept(
            scan::Event::Error("Probe task: boom".into()),
            &mut hosts,
            false,
            &mut errors
        ));
        assert!(!accept(
            scan::Event::Host(host("10.0.0.2", false)),
            &mut hosts,
            true,
            &mut errors
        ));
        assert!(!accept(
            scan::Event::Host(host("10.0.0.3", false)),
            &mut hosts,
            false,
            &mut errors
        ));
        assert!(accept(scan::Event::Done, &mut hosts, false, &mut errors));
        assert_eq!(hosts.len(), 2);
        assert_eq!(errors, ["Probe task: boom"]);
    }

    #[test]
    fn upper_and_lower_case_q_stop_the_tui() {
        use crossterm::event::KeyCode;
        assert!(stop_key(KeyCode::Char('q')));
        assert!(stop_key(KeyCode::Char('Q')));
        assert!(stop_key(KeyCode::Esc));
        assert!(!stop_key(KeyCode::Char(' ')));
    }

    fn tui_host(ip: &str, open: Vec<u16>) -> scan::Host {
        scan::Host {
            ip: ip.parse().unwrap(),
            responding: true,
            ping: Some(1),
            ttl: None,
            hostname: String::new(),
            mac: String::new(),
            open,
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity: BTreeMap::from([("svc.23".to_string(), "telnet".to_string())]),
            udp_open: vec![],
            trace: vec![],
        }
    }

    #[test]
    fn tui_selection_detail_and_sort_keys() {
        use crossterm::event::KeyCode;
        let hosts = vec![
            tui_host("10.0.0.3", vec![80]),
            tui_host("10.0.0.1", vec![]),
            tui_host("10.0.0.2", vec![22, 23, 80]),
        ];
        let mut v = TuiView::default();
        v.refresh(&hosts);
        assert_eq!(v.order, [2, 1, 0], "newest first");
        // Enter without a selection opens the first row.
        assert_eq!(v.key(KeyCode::Enter, &hosts), TuiAction::None);
        assert!(v.detail);
        assert_eq!(v.detail_host(&hosts).unwrap().ip, hosts[2].ip);
        // Arrows do nothing in the detail view; Esc and Q still stop, Space still pauses.
        v.key(KeyCode::Down, &hosts);
        assert_eq!(v.selected, Some(hosts[2].ip));
        assert_eq!(v.key(KeyCode::Esc, &hosts), TuiAction::Stop);
        assert_eq!(v.key(KeyCode::Char('Q'), &hosts), TuiAction::Stop);
        assert_eq!(v.key(KeyCode::Char(' '), &hosts), TuiAction::Pause);
        v.key(KeyCode::Backspace, &hosts);
        assert!(!v.detail && v.detail_host(&hosts).is_none());
        v.key(KeyCode::Down, &hosts);
        assert_eq!(v.selected, Some(hosts[1].ip));
        // Sorting keeps the selected host.
        v.key(KeyCode::Char('s'), &hosts);
        assert_eq!(v.sort, TuiSort::Address);
        assert_eq!(v.order, [1, 2, 0]);
        assert_eq!(v.position(&hosts), Some(0));
        v.key(KeyCode::Char('S'), &hosts);
        assert_eq!(v.order, [2, 0, 1], "most open ports first");
        v.key(KeyCode::End, &hosts);
        assert_eq!(v.selected, Some(hosts[1].ip));
        v.key(KeyCode::Up, &hosts);
        assert_eq!(v.selected, Some(hosts[0].ip));
        v.key(KeyCode::Char('s'), &hosts);
        assert_eq!(v.sort, TuiSort::Newest);
        // The window follows the selection.
        let many: Vec<scan::Host> = (1..=50)
            .map(|i| tui_host(&format!("10.0.1.{i}"), vec![]))
            .collect();
        let mut v = TuiView::default();
        v.key(KeyCode::End, &many);
        assert_eq!(v.window(&many, 10), (40, 50));
        v.key(KeyCode::Home, &many);
        assert_eq!(v.window(&many, 10), (0, 10));
        assert_eq!(TuiView::default().window(&[], 10), (0, 0));
    }

    #[test]
    fn tui_renders_list_and_detail_views_at_any_size() {
        use crossterm::event::KeyCode;
        use ratatui::{Terminal, backend::TestBackend};
        let hosts: Vec<scan::Host> = (1..=30)
            .map(|i| tui_host(&format!("10.0.0.{i}"), vec![23]))
            .collect();
        let text = |t: &Terminal<TestBackend>| {
            let b = t.backend().buffer();
            b.content().iter().map(|c| c.symbol()).collect::<String>()
        };
        for (w, h) in [(100, 24), (12, 3), (1, 1)] {
            let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
            let mut v = TuiView::default();
            v.refresh(&hosts);
            v.key(KeyCode::End, &hosts);
            t.draw(|f| draw_tui(f, &v, &hosts, "30/30 · scanning"))
                .unwrap();
            if w == 100 {
                let screen = text(&t);
                assert!(screen.contains("10.0.0.1 "), "{screen}");
                assert!(screen.contains("sort: newest"), "{screen}");
            }
            v.key(KeyCode::Enter, &hosts);
            v.key(KeyCode::PageDown, &hosts);
            t.draw(|f| draw_tui(f, &v, &hosts, "30/30 · scanning"))
                .unwrap();
            if w == 100 {
                assert_eq!(v.scroll, 10);
                v.key(KeyCode::Up, &hosts);
                v.key(KeyCode::PageUp, &hosts);
                assert_eq!(v.scroll, 0);
                t.draw(|f| draw_tui(f, &v, &hosts, "30/30 · scanning"))
                    .unwrap();
                let screen = text(&t);
                assert!(screen.contains("23/tcp  telnet"), "{screen}");
                assert!(screen.contains("Findings ("), "{screen}");
            }
        }
    }

    #[test]
    fn tui_details_show_ports_services_and_findings() {
        let h = tui_host("10.0.0.2", vec![23]);
        let text = detail_lines(&h).join("\n");
        assert!(text.contains("23/tcp  telnet"), "{text}");
        assert!(text.contains("Findings ("), "{text}");
        let findings = risk::analyze_host(&h);
        for f in &findings {
            assert!(text.contains(&f.title), "{text}");
        }
    }

    #[test]
    fn completions_cover_every_command_and_option() {
        for shell in ["bash", "powershell"] {
            let script = completions(shell).unwrap();
            for c in COMMANDS {
                assert!(script.contains(c), "{shell}: {c}");
            }
            for o in FLAGS.iter().chain(VALUES.iter()) {
                assert!(script.contains(&format!("--{o}")), "{shell}: --{o}");
            }
        }
        assert!(
            completions("bash")
                .unwrap()
                .contains("complete -o default -F _network_scope")
        );
        assert!(
            completions("powershell")
                .unwrap()
                .contains("Register-ArgumentCompleter -Native")
        );
        assert!(completions("fish").is_err());
        for f in FILE_VALUES {
            assert!(VALUES.contains(&f), "--{f}");
        }
    }

    #[test]
    fn commands_table_matches_the_dispatcher() {
        let src = include_str!("ui.rs");
        let body = src
            .split("match command.as_str() {")
            .nth(1)
            .unwrap()
            .split("_ => Err(format!(\"Unknown command")
            .next()
            .unwrap();
        let mut arms = std::collections::BTreeSet::new();
        for line in body.lines() {
            // Arms of this match are indented by exactly eight spaces.
            if let Some(rest) = line.strip_prefix("        \"") {
                if !line.contains("=>") {
                    continue;
                }
                for name in format!("\"{rest}").split("=>").next().unwrap().split('|') {
                    arms.insert(name.trim().trim_matches('"').to_string());
                }
            }
        }
        assert!(arms.len() >= 19, "{arms:?}");
        for a in &arms {
            assert!(COMMANDS.contains(&a.as_str()), "{a} missing from COMMANDS");
        }
        for c in COMMANDS {
            assert!(c == "help" || arms.contains(c), "{c} is not dispatched");
        }
    }

    #[test]
    fn feeds_import_and_status_commands() {
        let dir = std::env::temp_dir().join(format!("ns-feeds-cli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cache = dir.join("feeds.json");
        let out = dir.join("out.txt");
        let (kev, epss) = (dir.join("kev.json"), dir.join("epss.csv"));
        std::fs::write(&kev, include_str!("../tests/fixtures/kev.json")).unwrap();
        std::fs::write(&epss, include_str!("../tests/fixtures/epss.csv")).unwrap();
        let path = |p: &std::path::Path| p.to_str().unwrap().to_string();
        let mut import = args(&["feeds", "import", "--kev", &path(&kev)]);
        import.extend(args(&["--epss", &path(&epss), "--feeds", &path(&cache)]));
        import.extend(args(&["--output", &path(&out)]));
        run(&import).unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(text.contains("KEV: 4"), "{text}");
        assert!(text.contains("EPSS: 4"), "{text}");
        run(&args(&[
            "feeds",
            "status",
            "--feeds",
            &path(&cache),
            "--output",
            &path(&out),
        ]))
        .unwrap();
        let status: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(status["kev"]["entries"], 4);
        assert_eq!(status["epss"]["model_version"], "v2025.03.14");
        // Errors: no files, unknown subcommand, a gzip file, an unknown --sort value.
        assert!(
            run(&args(&["feeds", "import", "--feeds", &path(&cache)]))
                .unwrap_err()
                .contains("--kev")
        );
        assert!(run(&args(&["feeds", "--feeds", &path(&cache)])).is_err());
        std::fs::write(&epss, [0x1f, 0x8b, 8, 0]).unwrap();
        let e = run(&args(&[
            "feeds",
            "import",
            "--epss",
            &path(&epss),
            "--feeds",
            &path(&cache),
        ]))
        .unwrap_err();
        assert!(e.contains("gunzip"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn quiet_is_accepted_before_and_after_the_command() {
        let (_, opts) = options(&args(&["history", "--quiet"])).unwrap();
        assert!(opts.contains_key("quiet"));
        // Before the command it is a global option, not an unknown command.
        let dir = std::env::temp_dir().join(format!("ns-quiet-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("c.txt");
        run(&args(&[
            "--quiet",
            "completions",
            "bash",
            "--output",
            out.to_str().unwrap(),
        ]))
        .unwrap();
        assert!(
            std::fs::read_to_string(&out)
                .unwrap()
                .contains("_network_scope")
        );
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            run(&args(&["completions"]))
                .unwrap_err()
                .contains("powershell")
        );
    }

    #[test]
    fn exit_codes_are_the_documented_numbers() {
        assert_eq!(
            [
                ExitCode::Success,
                ExitCode::Error,
                ExitCode::Partial,
                ExitCode::Findings
            ]
            .map(ExitCode::code),
            [0, 1, 2, 3]
        );
    }

    #[test]
    fn saved_scans_and_captures_map_to_success_or_partial() {
        assert_eq!(saved_exit(true), ExitCode::Success);
        assert_eq!(saved_exit(false), ExitCode::Partial);
    }

    #[test]
    fn findings_exit_is_3_only_with_the_flag_and_a_match() {
        assert_eq!(findings_exit(false, 0), ExitCode::Success);
        // Default behaviour: findings never change the status without the flag.
        assert_eq!(findings_exit(false, 5), ExitCode::Success);
        assert_eq!(findings_exit(true, 0), ExitCode::Success);
        assert_eq!(findings_exit(true, 1), ExitCode::Findings);
    }

    #[test]
    fn fail_on_findings_is_a_flag_and_only_for_findings_and_diff() {
        let (pos, opts) = options(&args(&[
            "3",
            "--fail-on-findings",
            "--min-severity",
            "high",
        ]))
        .unwrap();
        assert_eq!(pos, ["3"], "the flag takes no value");
        assert!(opts.contains_key("fail-on-findings"));
        assert_eq!(min_severity(&opts).unwrap(), risk::Severity::High);
        // Last: the flag does not swallow the next argument either.
        let (pos, opts) = options(&args(&["--fail-on-findings", "1", "2"])).unwrap();
        assert_eq!((pos.len(), opts.len()), (2, 1));
        assert!(
            !options(&args(&["1"]))
                .unwrap()
                .1
                .contains_key("fail-on-findings")
        );
        for command in ["scan", "history", "export", "monitor", "devices"] {
            let err = run(&args(&[command, "1", "--fail-on-findings"])).unwrap_err();
            assert!(err.contains("--fail-on-findings"), "{command}: {err}");
        }
    }

    #[test]
    fn min_severity_defaults_to_info_and_rejects_unknown_names() {
        assert_eq!(
            min_severity(&BTreeMap::new()).unwrap(),
            risk::Severity::Info
        );
        let opts = BTreeMap::from([("min-severity".to_string(), "bogus".to_string())]);
        assert!(
            min_severity(&opts)
                .unwrap_err()
                .contains("Severity must be")
        );
    }

    #[test]
    fn diff_gate_counts_new_findings_at_or_above_the_threshold() {
        let snapshot = |hosts: Vec<scan::Host>| store::Snapshot {
            targets: "10.0.0.2".into(),
            complete: true,
            settings: scan::Settings::default(),
            hosts,
            observations: vec![],
            notes: BTreeMap::new(),
        };
        let quiet = snapshot(vec![tui_host("10.0.0.2", vec![])]);
        let telnet = snapshot(vec![tui_host("10.0.0.2", vec![23])]);
        let ignore = store::IgnoreList::new(&[]);
        let appeared = store::diff_report(&quiet, &telnet, &ignore).unwrap();
        let high = risk::Severity::High;
        assert!(new_findings_at_or_above(&appeared, risk::Severity::Info) >= 1);
        assert!(
            new_findings_at_or_above(&appeared, high) >= 1,
            "telnet is high"
        );
        assert_eq!(
            new_findings_at_or_above(&appeared, risk::Severity::Critical),
            0
        );
        // A finding that went away is not "found": only new findings count.
        let resolved = store::diff_report(&telnet, &quiet, &ignore).unwrap();
        assert_eq!(new_findings_at_or_above(&resolved, risk::Severity::Info), 0);
        // Unchanged scans report nothing new.
        let same = store::diff_report(&telnet, &telnet, &ignore).unwrap();
        assert_eq!(new_findings_at_or_above(&same, risk::Severity::Info), 0);
    }

    #[test]
    fn plain_commands_still_succeed_with_status_0() {
        assert_eq!(run(&args(&["--help"])).unwrap(), ExitCode::Success);
        assert!(run(&args(&["no-such-command"])).is_err());
    }
}
