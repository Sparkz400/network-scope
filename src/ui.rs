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
fn options(args: &[String]) -> Result<(Vec<String>, BTreeMap<String, String>), String> {
    let flags = [
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
    let values = [
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
            let (results, complete) = if opts.contains_key("tui") {
                tui(&run)?
            } else {
                collect(&run)?
            };
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
            output(&store::export(&snapshot, format)?, &opts)
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
            let mut observations = vec![];
            for item in &run.receiver {
                let o = item?;
                merge(&mut observations, o)?;
            }
            let snapshot = store::Snapshot {
                targets: format!("{command}:{interface}"),
                complete: true,
                settings: scan::Settings::default(),
                hosts: vec![],
                observations,
                notes: BTreeMap::new(),
            };
            let id = store::save(&db, &snapshot)?;
            eprintln!("Saved capture #{id}");
            output(
                &store::export(
                    &snapshot,
                    opts.get("format").map(String::as_str).unwrap_or("json"),
                )?,
                &opts,
            )
        }
        _ => Err(format!("Unknown command {command}. Use --help.")),
    }
}
pub fn merge(
    observations: &mut Vec<passive::Observation>,
    o: passive::Observation,
) -> Result<(), String> {
    if let Some(old) = observations
        .iter_mut()
        .find(|v| v.mac == o.mac && v.protocol == o.protocol && v.ip == o.ip)
    {
        old.fields.extend(o.fields);
    } else if observations.len() < 10000 {
        observations.push(o);
    } else {
        return Err("Observation limit (10,000) reached".into());
    }
    Ok(())
}
fn collect(run: &scan::Running) -> Result<(Vec<scan::Host>, bool), String> {
    let mut hosts = vec![];
    let sparse = run.total > scan::MAX_HOSTS;
    loop {
        match run.receiver.recv().map_err(|e| e.to_string())? {
            scan::Event::Host(h) => {
                if h.responding || !sparse {
                    hosts.push(h)
                }
            }
            scan::Event::Done => return Ok((hosts, !run.cancel.load(Ordering::Relaxed))),
            scan::Event::Error(e) => return Err(e),
        }
    }
}
fn tui(run: &scan::Running) -> Result<(Vec<scan::Host>, bool), String> {
    use crossterm::{
        event::{self, Event, KeyCode, KeyEventKind},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
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
            let _ = disable_raw_mode();
            let _ = execute!(
                std::io::stdout(),
                LeaveAlternateScreen,
                crossterm::cursor::Show
            );
        }
    }
    enable_raw_mode().map_err(|e| e.to_string())?;
    let _restore = Restore;
    execute!(std::io::stdout(), EnterAlternateScreen).map_err(|e| e.to_string())?;
    let mut terminal =
        Terminal::new(CrosstermBackend::new(std::io::stdout())).map_err(|e| e.to_string())?;
    let mut hosts = vec![];
    let mut seen = 0usize;
    let sparse = run.total > scan::MAX_HOSTS;
    let mut done = false;
    while !done {
        loop {
            match run.receiver.try_recv() {
                Ok(scan::Event::Host(h)) => {
                    seen += 1;
                    if h.responding || !sparse {
                        hosts.push(h)
                    }
                }
                Ok(scan::Event::Done) => {
                    done = true;
                    break;
                }
                Ok(scan::Event::Error(e)) => return Err(e),
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(_) => return Err("Scan worker disconnected".into()),
            }
        }
        terminal
            .draw(|f| {
                let rows = hosts
                    .iter()
                    .rev()
                    .take(f.area().height.saturating_sub(4) as usize)
                    .map(|h| {
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
            })
            .map_err(|e| e.to_string())?;
        if event::poll(Duration::from_millis(60)).map_err(|e| e.to_string())? {
            if let Event::Key(k) = event::read().map_err(|e| e.to_string())? {
                if k.kind == KeyEventKind::Press {
                    match k.code {
                        KeyCode::Char('q') | KeyCode::Esc => {
                            run.cancel.store(true, Ordering::Relaxed)
                        }
                        KeyCode::Char(' ') => {
                            run.pause.fetch_xor(true, Ordering::Relaxed);
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    Ok((hosts, !run.cancel.load(Ordering::Relaxed)))
}
