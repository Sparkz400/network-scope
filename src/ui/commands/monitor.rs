//! `monitor TARGETS --interval N ...`: repeated scans that alert on changes (JSON lines on stdout,
//! optionally appended to `--alerts FILE`, and to the opt-in webhook and syslog sinks).
use crate::{
    monitor, risk,
    ui::{
        Ctx,
        args::{number, scan_settings},
        dryrun, guard,
    },
};
use std::{collections::BTreeMap, time::Duration};

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    let opts = ctx.opts.clone();
    let opts = &opts;
    let targets = ctx.pos.join(" ");
    let mut s = scan_settings(opts)?;
    s.scan_nonresponders = true;
    // The same scope rule as `scan`; monitor runs unattended, so without a terminal it refuses
    // unless --yes-public / --allow-out-of-scope is given.
    let hosts = crate::scan::parse_targets(&targets, s.skip_edges, crate::scan::MAX_STREAM)?;
    if dryrun::requested(opts) {
        let ports = crate::scan::parse_ports(&s.ports)?;
        return dryrun::scan_plan(opts, "monitor", &hosts, &ports, &s);
    }
    if !guard::enforce(ctx, &hosts)? {
        return Ok(());
    }
    let policy = monitor_policy(opts)?;
    let cfg = monitor::RunConfig {
        interval: Duration::from_secs(number(opts, "interval", 300u64)?.clamp(1, 86_400)),
        cycles: number(opts, "cycles", 0)?,
        policy,
        dhcp_discover: opts.contains_key("dhcp-discover"),
        interface: opts.get("interface").cloned().unwrap_or_default(),
        listen_seconds: number(opts, "listen-seconds", 30)?,
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
    monitor::run(&targets, s, &ctx.db, &cfg, &mut |a| {
        let line = serde_json::to_string(a).unwrap_or_default();
        println!("{line}");
        if let Some(f) = file.as_mut() {
            use std::io::Write;
            let _ = writeln!(f, "{line}");
        }
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::{args::options, testutil::args};

    #[test]
    fn monitor_sink_options_parse() {
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
        let defaults = monitor_policy(&BTreeMap::new()).unwrap();
        assert!(defaults.notify.sinks.is_empty() && defaults.notify.dedup);
        let https = BTreeMap::from([("webhook".to_string(), "https://hooks.local/a".to_string())]);
        assert_eq!(monitor_policy(&https).unwrap().notify.sinks.len(), 1);
        let ftp = BTreeMap::from([("webhook".to_string(), "ftp://x".to_string())]);
        assert!(monitor_policy(&ftp).unwrap_err().contains("https://"));
        let slow = BTreeMap::from([("alert-timeout".to_string(), "600".to_string())]);
        assert!(monitor_policy(&slow).is_err());
    }
}
