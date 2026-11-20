//! Command-line parsing shared by all commands: the table of known options, the `--key value`
//! parser and the helpers that turn options into engine settings.
//!
//! A new option is declared in [`FLAGS`] (no value) or [`VALUES`] (takes a value); a test checks
//! that every option a command reads is declared here. Add it to `help.rs` as well.
use crate::{risk, scan};
use std::collections::BTreeMap;

pub(super) const FLAGS: [&str; 32] = [
    "quiet",
    "fail-on-findings",
    "arp-sweep",
    "adaptive-syn",
    "adaptive-tcp",
    "jarm",
    "favicon",
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
    "dry-run",
    "no-scan",
    "yes-public",
    "allow-out-of-scope",
    "no-backoff",
    "sent-log",
    "randomize",
];
pub(super) const VALUES: [&str; 72] = [
    "feeds",
    "top",
    "nvd",
    "csaf",
    "model",
    "maintenance",
    "zones",
    "from",
    "record",
    "replay-check",
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
    "json-schema",
    "on-alert",
    "on-alert-dir",
    "service-name",
    "owner",
    "tag",
    "untag",
    "criticality",
    "expected",
    "since",
    "push",
    "token-env",
    "netbox-site",
    "netbox-role",
    "netbox-device-type",
    "index",
    "scope",
    "scope-file",
    "preset",
    "broadcast",
    "targets-file",
];
pub(super) fn options(args: &[String]) -> Result<(Vec<String>, BTreeMap<String, String>), String> {
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
pub(super) fn number<T: std::str::FromStr>(
    opts: &BTreeMap<String, String>,
    key: &str,
    default: T,
) -> Result<T, String> {
    match opts.get(key) {
        Some(s) => s.parse().map_err(|_| format!("Invalid --{key}")),
        None => Ok(default),
    }
}
/// The scan settings of the command line: the options on top of the defaults, or, with
/// `--preset NAME`, on top of that preset (see [`crate::presets`]; an option given explicitly
/// wins over what the preset sets). `plant` is passive and refused here.
pub(super) fn scan_settings(opts: &BTreeMap<String, String>) -> Result<scan::Settings, String> {
    let cli = settings_from_options(opts)?;
    let Some(name) = opts.get("preset") else {
        return Ok(cli);
    };
    let mut s = crate::presets::Preset::parse(name)?.settings(&cli)?;
    // What the user typed beats the preset.
    let has = |k: &str| opts.contains_key(k);
    for (key, field) in [
        ("tcp-only", &mut s.tcp_only),
        ("arp", &mut s.arp),
        ("ot", &mut s.ot),
        ("dns", &mut s.dns),
        ("syn", &mut s.syn),
        ("arp-sweep", &mut s.arp_sweep),
        ("adaptive-syn", &mut s.syn_adaptive),
        ("adaptive-tcp", &mut s.tcp_adaptive),
        ("jarm", &mut s.jarm),
        ("favicon", &mut s.favicon),
        ("trace", &mut s.trace),
        ("services", &mut s.services),
        ("udp", &mut s.udp),
        ("os", &mut s.os_detect),
    ] {
        if has(key) {
            *field = true;
        }
    }
    if has("deep") {
        (s.services, s.udp, s.os_detect) = (true, true, true);
    }
    if has("fast") {
        s.safe = false;
    }
    if has("no-backoff") {
        s.backoff = false;
    }
    if has("ports") || has("ot") || has("top-ports") {
        s.ports = cli.ports.clone();
    }
    if has("workers") {
        s.workers = cli.workers;
    }
    if has("timeout") {
        (s.port_timeout, s.ping_timeout) = (cli.port_timeout, cli.ping_timeout);
    }
    if has("udp-ports") {
        (s.udp_ports, s.udp) = (cli.udp_ports.clone(), true);
    }
    if has("trace-method") {
        (s.trace_method, s.trace) = (cli.trace_method, true);
    }
    if has("trace-port") {
        s.trace_port = cli.trace_port;
    }
    if has("max-hops") {
        s.trace_hops = cli.trace_hops;
    }
    if has("retries") {
        s.retries = cli.retries;
    }
    if has("rate") {
        s.max_rate = cli.max_rate;
    }
    if has("parallel") {
        s.port_parallel = cli.port_parallel;
    }
    for (key, f) in [
        ("unit", cli.modbus_unit),
        ("rack", cli.s7_rack),
        ("slot", cli.s7_slot),
    ] {
        if has(key) {
            match key {
                "unit" => s.modbus_unit = f,
                "rack" => s.s7_rack = f,
                _ => s.s7_slot = f,
            }
        }
    }
    Ok(s)
}
fn settings_from_options(opts: &BTreeMap<String, String>) -> Result<scan::Settings, String> {
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
    s.tcp_adaptive = opts.contains_key("adaptive-tcp");
    s.jarm = opts.contains_key("jarm");
    s.favicon = opts.contains_key("favicon");
    // On by default; it only ever slows a host down (see `backoff`).
    s.backoff = !opts.contains_key("no-backoff");
    s.record = opts.contains_key("record");
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
pub(super) fn trace_method(text: &str) -> Result<crate::trace::TraceMethod, String> {
    serde_json::from_value(serde_json::Value::String(text.to_lowercase()))
        .map_err(|_| "Trace method must be icmp, tcp or udp".to_string())
}
pub(super) fn trace_port(text: &str) -> Result<u16, String> {
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
/// `--min-severity` for `findings` and for the `diff` gate (default `info`).
pub(super) fn min_severity(opts: &BTreeMap<String, String>) -> Result<risk::Severity, String> {
    risk::Severity::parse(
        opts.get("min-severity")
            .map(String::as_str)
            .unwrap_or("info"),
    )
    .ok_or_else(|| "Severity must be info, low, medium, high or critical".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::testutil::args;

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
        // Every source file of the `ui` module tree, so a command in a new file is covered too.
        fn sources(dir: &std::path::Path, out: &mut String) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    sources(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push_str(&std::fs::read_to_string(path).unwrap());
                }
            }
        }
        let mut src = String::new();
        sources(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ui"),
            &mut src,
        );
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
    fn new_scan_options_parse() {
        let (_, opts) = options(&args(&[
            "--arp-sweep",
            "--adaptive-syn",
            "--adaptive-tcp",
            "--jarm",
            "--favicon",
            "--trace-method",
            "TCP",
            "--trace-port",
            "8443",
        ]))
        .unwrap();
        let s = scan_settings(&opts).unwrap();
        assert!(
            s.arp_sweep
                && s.syn_adaptive
                && s.tcp_adaptive
                && s.jarm
                && s.favicon
                && s.trace
                && s.safe
        );
        assert!(s.backoff, "the back-off is on unless --no-backoff is given");
        let (_, opts) = options(&args(&["--no-backoff"])).unwrap();
        assert!(!scan_settings(&opts).unwrap().backoff);
        assert_eq!(s.trace_method, crate::trace::TraceMethod::Tcp);
        assert_eq!(s.trace_port, 8443);
        assert!(trace_method("ping").is_err());
        assert!(trace_port("502").unwrap_err().contains("OT or printer"));
        assert!(trace_port("9100").is_err());
        assert!(trace_port("0").is_err());
    }

    #[test]
    fn presets_set_the_base_and_explicit_options_win() {
        let o = |list: &[&str]| options(&args(list)).unwrap().1;
        // quick: the safe default scan.
        let s = scan_settings(&o(&["--preset", "quick"])).unwrap();
        assert!(s.safe && !s.services && s.workers == scan::Settings::default().workers);
        // office adds identification and stays in Safe Mode; --ports still wins.
        let s = scan_settings(&o(&["--preset", "office", "--ports", "22"])).unwrap();
        assert!(s.safe && s.services && s.os_detect && s.mac);
        assert_eq!(s.ports, "22");
        // full leaves Safe Mode, and --no-backoff or --workers still apply on top of it.
        let s =
            scan_settings(&o(&["--preset", "FULL", "--no-backoff", "--workers", "32"])).unwrap();
        assert!(!s.safe && s.jarm && s.syn && !s.backoff && s.workers == 32);
        // --fast on a safe preset leaves Safe Mode; machine settings come from the options.
        let s = scan_settings(&o(&["--preset", "quick", "--fast", "--interface", "eth0"])).unwrap();
        assert!(!s.safe && s.interface == "eth0");
        // plant is passive: the scan options refuse it and point to ot-listen.
        let e = scan_settings(&o(&["--preset", "plant"])).unwrap_err();
        assert!(e.contains("ot-listen"), "{e}");
        assert!(
            scan_settings(&o(&["--preset", "turbo"]))
                .unwrap_err()
                .contains("Unknown preset")
        );
        // No preset: the old defaults (all ports probed, one probe).
        let s = scan_settings(&o(&[])).unwrap();
        assert!(s.scan_nonresponders && s.probes == 1);
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
}
