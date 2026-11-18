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
network-scope diff OLD_ID NEW_ID [--db FILE]
network-scope export ID --format json|csv|html|nmap [--output FILE] [--db FILE]
network-scope report ID [--baseline ID] [--output FILE]   HTML report with charts and map
network-scope import FILE.xml                  Import an nmap XML scan into the inventory
network-scope findings ID [--min-severity low] Weak TLS/SSH, risky services, CVE hints
network-scope monitor TARGETS [scan options] --interval 300 [--cycles N] [--learn]
        [--dhcp-allow IP,IP] [--dhcp-discover] [--report-missing] [--min-severity low]
        [--interface ID --listen-seconds 30] [--alerts FILE]   Repeat scans and alert on changes
network-scope alerts [--db FILE]               Alerts raised by monitor runs
network-scope scripts PATH                     Check Rhai scripts (use --script PATH with scan)
network-scope ot-listen --interface ID --seconds N | --pcap FILE   Passive OT asset discovery
network-scope ot-assets ID [--format json|csv]  OT asset inventory from a passive capture
network-scope devices ID [--format json|csv]   One record per device (active + passive merged)
network-scope topology ID [--format ascii|dot] Network path map from traceroute data
network-scope trace TARGET [--max-hops 20] [--timeout 1000]
network-scope probes [--probes FILE]           List/validate the service probe database

Scan options:
  --ports 80,443,502,102,4840,44818 --workers 1024 --timeout 2000
  --top-ports N   Add the N most common TCP ports (1-100); also usable as top:N in --ports
  --retries 1     Extra attempts for unanswered ports (timeout doubles each time)
  --rate PPS      Cap probe rate outside Safe Mode (0 = unlimited)
  --parallel 64   Concurrent port probes per host outside Safe Mode
  --tcp-only --arp --ot --dns --tui --format json|csv|html --output FILE
  --services      Identify services: banners, HTTP, TLS (certificate, versions, ciphers), SMB, RDP, databases...
  --udp           Probe UDP: DNS, DHCP, NTP, NetBIOS, SNMP (community "public"), SSDP, mDNS
  --udp-ports 53,123,161   Replace the default UDP port list
  --os            OS family, manufacturer (IEEE OUI) and device type guess
  --deep          Same as --services --udp --os
  --trace         Record the router path to each responding host (--max-hops 20)
  --probes FILE   Extra service probes, merged over data/probes.json by probe name
  --script PATH   Rhai script (or folder of .rhai files) run against every host
  --db FILE       Defaults to LOCALAPPDATA/NetworkScope/inventory.sqlite
  --fast          Disable conservative rate limits (read-only OT still applies)
  --syn           IPv4 LAN SYN via Npcap; unavailable -> TCP connect fallback
  --interface ID --source-ip IPV4 --source-mac MAC  Required for SYN
  --unit 1 --rack 0 --slot 2   Modbus unit and S7 addressing

Safe Mode is on by default: 8 hosts max, >=100 ms between probes, no SYN.
Targets are streamed: ranges up to 16,777,216 addresses (/8) are accepted; above
65,536 only responding hosts are kept in memory and saved.
Read-only traffic can still affect fragile equipment; passive listen sends none.
OT queries run only on their standard open ports; BACnet uses unicast UDP Who-Is.
Npcap is optional for TCP connect; capture/DCP/SYN require its driver and access.
TUI: Space pause/resume, Q stop and save a partial scan. No scan starts by itself.
"#;
const FLAGS: [&str; 15] = [
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
const VALUES: [&str; 29] = [
    "ports",
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
fn report_html(
    db: &std::path::Path,
    snapshot: &store::Snapshot,
    stamp: i64,
    opts: &BTreeMap<String, String>,
) -> Result<String, String> {
    let baseline = match opts.get("baseline") {
        Some(b) => {
            let b: i64 = b.parse().map_err(|_| "Invalid --baseline".to_string())?;
            Some((store::load(db, b)?, store::timestamp(db, b)?))
        }
        None => None,
    };
    Ok(crate::report::html(
        snapshot,
        baseline.as_ref().map(|(s, t)| (s, *t)),
        stamp,
    ))
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
fn output(data: &str, opts: &BTreeMap<String, String>) -> Result<(), String> {
    if let Some(path) = opts.get("output") {
        std::fs::write(path, data).map_err(|e| e.to_string())
    } else {
        use std::io::Write;
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{data}").map_err(|e| e.to_string())
    }
}
pub fn run(args: &[String]) -> Result<(), String> {
    if args.is_empty() || ["help", "--help", "-h"].contains(&args[0].as_str()) {
        println!("{HELP}");
        return Ok(());
    }
    let command = &args[0];
    let (pos, opts) = options(&args[1..])?;
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
    match command.as_str() {
        "interfaces" => output(
            &serde_json::to_string_pretty(&crate::capture::interfaces()?)
                .map_err(|e| e.to_string())?,
            &opts,
        ),
        "history" => output(
            &serde_json::to_string_pretty(&store::list(&db)?).map_err(|e| e.to_string())?,
            &opts,
        ),
        "diff" => output(
            &serde_json::to_string_pretty(&store::diff(
                &store::load(&db, id(0)?)?,
                &store::load(&db, id(1)?)?,
            )?)
            .map_err(|e| e.to_string())?,
            &opts,
        ),
        "export" => {
            let snapshot = store::load(&db, id(0)?)?;
            let format = opts.get("format").map(String::as_str).unwrap_or("json");
            let stamp = store::timestamp(&db, id(0)?)?;
            let text = match format {
                "html" => report_html(&db, &snapshot, stamp, &opts)?,
                "nmap" | "xml" => nmap::export(&snapshot, stamp),
                other => store::export(&snapshot, other)?,
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
            eprintln!("Imported {} hosts as scan #{scan_id}", snapshot.hosts.len());
            Ok(())
        }
        "findings" => {
            let snapshot = store::load(&db, id(0)?)?;
            let min = risk::Severity::parse(
                opts.get("min-severity")
                    .map(String::as_str)
                    .unwrap_or("info"),
            )
            .ok_or("Severity must be info, low, medium, high or critical")?;
            let list: Vec<_> = risk::analyze_snapshot(&snapshot)
                .into_iter()
                .filter(|f| f.severity >= min)
                .collect();
            output(
                &serde_json::to_string_pretty(&list).map_err(|e| e.to_string())?,
                &opts,
            )
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
            let cfg = monitor::RunConfig {
                interval: Duration::from_secs(number(&opts, "interval", 300u64)?.clamp(1, 86_400)),
                cycles: number(&opts, "cycles", 0)?,
                policy,
                dhcp_discover: opts.contains_key("dhcp-discover"),
                interface: opts.get("interface").cloned().unwrap_or_default(),
                listen_seconds: number(&opts, "listen-seconds", 30)?,
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
            let label = if let Some(path) = opts.get("pcap") {
                crate::otpassive::read_pcap_file(path, &mut tracker)?;
                format!("ot-passive:{path}")
            } else {
                let interface = opts
                    .get("interface")
                    .ok_or("Provide --interface (see the interfaces command) or --pcap FILE")?;
                let seconds: u64 = number(&opts, "seconds", 300)?;
                if !(1..=604_800).contains(&seconds) {
                    return Err("Seconds must be 1-604800".into());
                }
                eprintln!(
                    "Listening passively on {interface} for {seconds} s. Nothing is transmitted."
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
            eprintln!(
                "Saved passive OT capture #{scan_id}: {} frames, {} observations",
                tracker.frames,
                snapshot.observations.len()
            );
            ot_assets_output(&snapshot, &opts)
        }
        "ot-assets" => ot_assets_output(&store::load(&db, id(0)?)?, &opts),
        "devices" => {
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
            let path = runtime.block_on(crate::trace::trace(
                target,
                hops,
                timeout,
                &blocking,
                &crate::core::Gate::unlimited(),
            ))?;
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
            let mut text = format!("{} probes\n", db.probes.len());
            for p in &db.probes {
                text.push_str(&format!(
                    "{:<12} ports {:<16} {} bytes sent, {} rules\n",
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
            if !["json", "csv", "html", "nmap"].contains(&format) {
                return Err("Choose json, csv, html or nmap".into());
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
            eprintln!(
                "Saved scan #{id} ({})",
                if complete { "complete" } else { "partial" }
            );
            output(&store::export(&snapshot, format)?, &opts)?;
            if errors.is_empty() {
                Ok(())
            } else {
                Err(format!(
                    "Scan #{id} saved as partial after errors: {}",
                    errors.join("; ")
                ))
            }
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
            eprintln!(
                "Saved capture #{id} ({})",
                if error.is_none() {
                    "complete"
                } else {
                    "partial"
                }
            );
            output(
                &store::export(
                    &snapshot,
                    opts.get("format").map(String::as_str).unwrap_or("json"),
                )?,
                &opts,
            )?;
            match error {
                None => Ok(()),
                Some(e) => Err(format!("Capture #{id} saved as partial: {e}")),
            }
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
fn drain_observations(
    items: impl IntoIterator<Item = Result<passive::Observation, String>>,
) -> (Vec<passive::Observation>, Option<String>) {
    let mut observations = vec![];
    let mut index = ObservationIndex::default();
    for item in items {
        if let Err(e) = item.and_then(|o| merge_indexed(&mut observations, &mut index, o)) {
            return (observations, Some(e));
        }
    }
    (observations, None)
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
/// A panic on the TUI thread would print inside the alternate screen and be lost: restore the
/// terminal first, then run the previous (default) hook. Installed once; inert outside the TUI.
fn install_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let on_tui = TUI_THREAD
                .lock()
                .map(|t| *t == Some(std::thread::current().id()))
                .unwrap_or(false);
            if on_tui {
                restore_terminal();
            }
            previous(info);
        }));
    });
}
fn tui(run: &scan::Running) -> Collected {
    use crossterm::{
        event::{self, Event, KeyCode, KeyEventKind},
        execute,
        terminal::{enable_raw_mode, EnterAlternateScreen},
    };
    use ratatui::{
        backend::CrosstermBackend,
        layout::Constraint,
        widgets::{Block, Borders, Row, Table},
        Terminal,
    };
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            if let Ok(mut t) = TUI_THREAD.lock() {
                *t = None;
            }
            restore_terminal();
        }
    }
    install_panic_hook();
    if let Ok(mut t) = TUI_THREAD.lock() {
        *t = Some(std::thread::current().id());
    }
    let restore = Restore;
    let mut terminal = match enable_raw_mode()
        .and_then(|()| execute!(std::io::stdout(), EnterAlternateScreen))
        .and_then(|()| Terminal::new(CrosstermBackend::new(std::io::stdout())))
    {
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
        let drawn = terminal.draw(|f| {
            let rows = hosts
                .iter()
                .rev()
                .take(f.area().height.saturating_sub(4) as usize)
                .map(|h: &scan::Host| {
                    Row::new(vec![
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
                    ])
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
                    " Network Scope · {}/{} · {} · Space pause / Q stop ",
                    seen,
                    run.total,
                    if run.pause.load(Ordering::Relaxed) {
                        "paused"
                    } else {
                        "scanning"
                    }
                ))),
                f.area(),
            );
        });
        let input = drawn.and_then(|_| {
            if event::poll(Duration::from_millis(60))? {
                if let Event::Key(k) = event::read()? {
                    if k.kind == KeyEventKind::Press {
                        if stop_key(k.code) {
                            run.cancel.store(true, Ordering::Relaxed);
                        } else if k.code == KeyCode::Char(' ') {
                            run.pause.fetch_xor(true, Ordering::Relaxed);
                        }
                    }
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
        assert!(options(&args(&["--alerts"]))
            .unwrap_err()
            .contains("Missing --alerts"));
        assert!(options(&args(&["--bogus"]))
            .unwrap_err()
            .contains("Unknown"));
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
        assert_eq!(list.len(), 2);
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
}
