//! Command-line parsing shared by all commands: the table of known options, the `--key value`
//! parser and the helpers that turn options into engine settings.
//!
//! A new option is declared in [`FLAGS`] (no value) or [`VALUES`] (takes a value); a test checks
//! that every option a command reads is declared here. Add it to `help.rs` as well.
use crate::{risk, scan};
use std::collections::BTreeMap;

pub(super) const FLAGS: [&str; 39] = [
    "quiet",
    "fail-on-findings",
    "arp-sweep",
    "adaptive-syn",
    "adaptive-tcp",
    "no-adaptive-tcp",
    "jarm",
    "favicon",
    "record-wire",
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
    "stream",
    "early-stop",
    "no-report",
    "incremental",
    "ipv6-discover",
];
pub(super) const VALUES: [&str; 80] = [
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
    "full-every",
    "melsec-port",
    "dnp3-address",
    "dnp3-master",
    "snmp-community",
    "snmp-community-env",
    "snmp-version",
    "snmp-v3",
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
    if has("no-adaptive-tcp") {
        s.tcp_adaptive = false;
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
        s.ports = "80,443,102,502,1883,1911,4840,9600,44818".into();
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
    // On by default since it only shortens waits; `--adaptive-tcp` is still accepted.
    s.tcp_adaptive = !opts.contains_key("no-adaptive-tcp");
    s.jarm = opts.contains_key("jarm");
    s.favicon = opts.contains_key("favicon");
    // On by default; it only ever slows a host down (see `backoff`).
    s.backoff = !opts.contains_key("no-backoff");
    s.record = opts.contains_key("record");
    (s.snmp, s.snmp_ref) = snmp_config(opts)?;
    s.ipv6_discover = opts.contains_key("ipv6-discover");
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
    s.early_stop = opts.contains_key("early-stop");
    ot_opt_ins(opts, &mut s)?;
    s.partial_events = opts.contains_key("stream");
    Ok(s)
}
/// `--melsec-port`, `--dnp3-address` and `--dnp3-master`: the two OT requests that have no safe
/// default and so need an address the user gives. They are read-only identification like the rest
/// of `--ot` and need it. A port or address that could do harm is refused here, not clamped.
fn ot_opt_ins(opts: &BTreeMap<String, String>, s: &mut scan::Settings) -> Result<(), String> {
    let wants = |key: &str| opts.contains_key(key);
    if (wants("melsec-port") || wants("dnp3-address") || wants("dnp3-master")) && !s.ot {
        return Err("--melsec-port, --dnp3-address and --dnp3-master need --ot".into());
    }
    if wants("melsec-port") {
        let port: u16 = number(opts, "melsec-port", 0)?;
        if port < 1024 || crate::service::is_ot_port_candidate(port) {
            return Err(format!(
                "--melsec-port {port}: the MC protocol is read only on a port above 1023 that has no protocol of its own here (the usual ones are 5006, 5007 or the one set in the PLC's Ethernet parameters)"
            ));
        }
        s.melsec_port = port;
    }
    // The request goes only to a port that was found open, so the port must be among those scanned
    // (a scan never adds a port by itself).
    let scanned = scan::parse_ports(&s.ports).unwrap_or_default();
    if s.melsec_port != 0 && !scanned.contains(&s.melsec_port) {
        return Err(format!(
            "--melsec-port {0} must also be in --ports (the MC request goes only to a port found open); add --ports ...,{0}",
            s.melsec_port
        ));
    }
    if wants("dnp3-master") && !wants("dnp3-address") {
        return Err("--dnp3-master needs --dnp3-address".into());
    }
    if wants("dnp3-address") {
        let address: u32 = number(opts, "dnp3-address", 0)?;
        let master: u32 = number(opts, "dnp3-master", 1)?;
        let (address, master) = (
            u16::try_from(address).map_err(|_| "--dnp3-address is 0 to 65519")?,
            u16::try_from(master).map_err(|_| "--dnp3-master is 0 to 65519")?,
        );
        if crate::ot_readonly::Dnp3Request::new(
            address,
            master,
            crate::ot_readonly::Dnp3Function::ReadClass0,
        )
        .is_none()
        {
            return Err(format!(
                "--dnp3-address {address} (master {master}): the address must be a unicast address (0 to 65519, broadcast and reserved addresses are never used) and differ from the master's"
            ));
        }
        if !scanned.contains(&20000) {
            return Err(
                "--dnp3-address needs tcp/20000 among the scanned ports (--ports ...,20000): the request goes only to a port found open"
                    .into(),
            );
        }
        s.dnp3_address = Some(address);
        s.dnp3_master = master;
    }
    Ok(())
}
/// `--snmp-community` / `--snmp-community-env` / `--snmp-version` or `--snmp-v3`: the credentials
/// of the SNMP read, and the form that may be saved with the scan (names of environment
/// variables only). The v3 secrets come from the environment variables named in the option,
/// never from the command line; a community string given with `--snmp-community` is used for
/// this run only and has no saved form.
pub(super) fn snmp_config(
    opts: &BTreeMap<String, String>,
) -> Result<
    (
        Option<crate::snmp::SnmpConfig>,
        Option<crate::snmp::SnmpRef>,
    ),
    String,
> {
    use crate::snmp::{SnmpConfig, SnmpRef};
    let (community, community_env, v3) = (
        opts.get("snmp-community"),
        opts.get("snmp-community-env"),
        opts.get("snmp-v3"),
    );
    if [community.is_some(), community_env.is_some(), v3.is_some()]
        .iter()
        .filter(|set| **set)
        .count()
        > 1
    {
        return Err(
            "Use one of --snmp-community, --snmp-community-env and --snmp-v3, not several".into(),
        );
    }
    if opts.contains_key("snmp-version") && community.is_none() && community_env.is_none() {
        return Err(
            "--snmp-version needs --snmp-community or --snmp-community-env (SNMPv3 has --snmp-v3)"
                .into(),
        );
    }
    let version = opts.get("snmp-version").map_or("2c", String::as_str);
    if let Some(c) = community {
        return Ok((Some(SnmpConfig::community(version, c)?), None));
    }
    if let Some(name) = community_env {
        let saved = SnmpRef::community(version, name)?;
        let config = saved.resolve(|n| std::env::var(n).ok())?;
        return Ok((Some(config), Some(saved)));
    }
    match v3 {
        Some(spec) => {
            let saved = SnmpRef::v3(spec)?;
            let config = saved.resolve(|n| std::env::var(n).ok())?;
            Ok((Some(config), Some(saved)))
        }
        None => Ok((None, None)),
    }
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
    fn snmp_options_build_the_credentials_and_never_take_a_passphrase() {
        let parse = |list: &[&str]| scan_settings(&options(&args(list)).unwrap().1);
        // no option, no SNMP (and it is not "public" by default)
        assert!(parse(&[]).unwrap().snmp.is_none());
        let c = parse(&["--snmp-community", "s3cret"])
            .unwrap()
            .snmp
            .unwrap();
        assert_eq!(c.version(), crate::snmp::Version::V2c);
        assert!(!format!("{c:?}").contains("s3cret"));
        let c = parse(&["--snmp-community", "x", "--snmp-version", "1"])
            .unwrap()
            .snmp
            .unwrap();
        assert_eq!(c.version(), crate::snmp::Version::V1);
        assert!(parse(&["--snmp-community", "x", "--snmp-version", "3"]).is_err());
        assert!(parse(&["--snmp-version", "2c"]).is_err());
        assert!(parse(&["--snmp-community", "x", "--snmp-v3", "u"]).is_err());
        // v3 names an environment variable (PATH exists everywhere and is long enough)
        let c = parse(&["--snmp-v3", "monitor:sha256:PATH:aes:PATH"])
            .unwrap()
            .snmp
            .unwrap();
        assert_eq!(c.version(), crate::snmp::Version::V3);
        assert!(!format!("{c:?}").contains("PATH") || format!("{c:?}").contains("hidden"));
        let e = parse(&["--snmp-v3", "monitor:sha:NS_TEST_NO_SUCH_VARIABLE"]).unwrap_err();
        assert!(e.contains("not set"), "{e}");
        let e = parse(&["--snmp-v3", "monitor:sha:my passphrase here"]).unwrap_err();
        assert!(e.contains("environment variable"), "{e}");
        assert!(
            !e.contains("passphrase here"),
            "a mistyped passphrase is never echoed: {e}"
        );
        // a community string given on the command line has no saved form; names have
        let s = parse(&["--snmp-community", "s3cret"]).unwrap();
        assert!(s.snmp.is_some() && s.snmp_ref.is_none());
        let s = parse(&["--snmp-v3", "monitor:sha256:PATH:aes:PATH"]).unwrap();
        let saved = serde_json::to_string(&s.snmp_ref).unwrap();
        assert_eq!(saved, r#"{"v3":{"spec":"monitor:sha256:PATH:aes:PATH"}}"#);
        // the weak algorithms are accepted when named
        let s = parse(&["--snmp-v3", "monitor:md5:PATH:des:PATH"]).unwrap();
        assert_eq!(s.snmp.unwrap().weak_crypto().len(), 2);
        // --snmp-community-env: a variable name, never the community; one SNMP option at a time
        let e = parse(&["--snmp-community-env", "NS_TEST_NO_SUCH_VARIABLE"]).unwrap_err();
        assert!(e.contains("not set"), "{e}");
        let e = parse(&["--snmp-community-env", "my community"]).unwrap_err();
        assert!(
            e.contains("environment variable") && !e.contains("my community"),
            "{e}"
        );
        assert!(parse(&["--snmp-community-env", "PATH", "--snmp-community", "x"]).is_err());
        assert!(parse(&["--snmp-community-env", "PATH", "--snmp-v3", "u"]).is_err());
        assert!(
            parse(&[
                "--snmp-version",
                "1",
                "--snmp-community-env",
                "NS_TEST_NO_SUCH_VARIABLE"
            ])
            .unwrap_err()
            .contains("not set")
        );
    }

    #[test]
    fn the_mc_port_and_the_dnp3_address_are_opt_in_and_checked() {
        let parse = |list: &[&str]| scan_settings(&options(&args(list)).unwrap().1);
        // off by default
        let s = parse(&["--ot"]).unwrap();
        assert_eq!((s.melsec_port, s.dnp3_address, s.dnp3_master), (0, None, 1));
        // given
        let s = parse(&["--ot", "--ports", "80,15007", "--melsec-port", "15007"]).unwrap();
        assert_eq!(s.melsec_port, 15007);
        let s = parse(&[
            "--ot",
            "--ports",
            "80,20000",
            "--dnp3-address",
            "10",
            "--dnp3-master",
            "3",
        ])
        .unwrap();
        assert_eq!((s.dnp3_address, s.dnp3_master), (Some(10), 3));
        // they need --ot and the port among the scanned ones
        for (list, text) in [
            (
                vec!["--ports", "15007", "--melsec-port", "15007"],
                "need --ot",
            ),
            (
                vec!["--ot", "--ports", "80", "--melsec-port", "15007"],
                "must also be in --ports",
            ),
            (
                vec!["--ot", "--ports", "80", "--dnp3-address", "10"],
                "tcp/20000",
            ),
            (vec!["--ot", "--dnp3-master", "3"], "needs --dnp3-address"),
            // an industrial port with a protocol of its own, a well-known low port, port 0
            (
                vec!["--ot", "--ports", "502", "--melsec-port", "502"],
                "above 1023",
            ),
            (
                vec!["--ot", "--ports", "80", "--melsec-port", "80"],
                "above 1023",
            ),
            (
                vec!["--ot", "--ports", "44818", "--melsec-port", "44818"],
                "above 1023",
            ),
            (
                vec!["--ot", "--ports", "20000", "--melsec-port", "20000"],
                "above 1023",
            ),
            (
                vec!["--ot", "--ports", "80", "--melsec-port", "0"],
                "above 1023",
            ),
            // DNP3 broadcast and reserved addresses, the master's own address, out of range
            (
                vec!["--ot", "--ports", "20000", "--dnp3-address", "65535"],
                "unicast",
            ),
            (
                vec!["--ot", "--ports", "20000", "--dnp3-address", "65532"],
                "unicast",
            ),
            (
                vec!["--ot", "--ports", "20000", "--dnp3-address", "65520"],
                "unicast",
            ),
            (
                vec!["--ot", "--ports", "20000", "--dnp3-address", "1"],
                "differ",
            ),
            (
                vec![
                    "--ot",
                    "--ports",
                    "20000",
                    "--dnp3-address",
                    "10",
                    "--dnp3-master",
                    "65535",
                ],
                "unicast",
            ),
            (
                vec!["--ot", "--ports", "20000", "--dnp3-address", "70000"],
                "0 to 65519",
            ),
        ] {
            let e = parse(&list).unwrap_err();
            assert!(e.contains(text), "{list:?}: {e}");
        }
        assert!(parse(&["--ot", "--ports", "20000", "--dnp3-address", "65519"]).is_ok());
        assert!(parse(&["--ot", "--ports", "20000", "--dnp3-address", "0"]).is_ok());
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
        let (_, opts) = options(&args(&["--no-backoff", "--no-adaptive-tcp"])).unwrap();
        let off = scan_settings(&opts).unwrap();
        assert!(!off.backoff && !off.tcp_adaptive);
        let (_, opts) = options(&args(&[])).unwrap();
        assert!(scan_settings(&opts).unwrap().tcp_adaptive, "on by default");
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
