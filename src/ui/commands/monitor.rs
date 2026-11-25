// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! `monitor TARGETS --interval N ...`: repeated scans that alert on changes (JSON lines on stdout,
//! optionally appended to `--alerts FILE`, and to the opt-in webhook and syslog sinks).
use crate::{
    alertscript::AlertScript,
    monitor, risk,
    ui::{
        Ctx,
        args::{number, scan_settings},
        dryrun, guard,
    },
};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    run_monitor(ctx, None, true)
}

/// The monitor loop behind `monitor` and `service run`. `stop` ends it cleanly when set from
/// another thread (the service control handler); without it, in a console, Ctrl+C does. `echo`
/// prints each alert on stdout, which a service has no use for.
pub(in crate::ui) fn run_monitor(
    ctx: &mut Ctx,
    stop: Option<Arc<AtomicBool>>,
    echo: bool,
) -> Result<(), String> {
    let opts = ctx.opts.clone();
    let opts = &opts;
    let targets = ctx.pos.join(" ");
    let mut s = scan_settings(opts)?;
    s.scan_nonresponders = true;
    super::scan::snmp_warnings(opts, &s);
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
    // Ctrl+C ends the monitor like a service stop: the cycle in progress is saved as partial.
    // Taken only here, after the scope question, where Ctrl+C still ends the process at once.
    let stop = stop.or_else(|| echo.then(crate::ui::interrupt::flag));
    let policy = monitor_policy(opts)?;
    let cfg = monitor::RunConfig {
        interval: Duration::from_secs(number(opts, "interval", 300u64)?.clamp(1, 86_400)),
        cycles: number(opts, "cycles", 0)?,
        policy,
        dhcp_discover: opts.contains_key("dhcp-discover"),
        interface: opts.get("interface").cloned().unwrap_or_default(),
        listen_seconds: number(opts, "listen-seconds", 30)?,
        quiet: opts.contains_key("quiet"),
        incremental: opts.contains_key("incremental"),
        full_every: number(opts, "full-every", 10u32)?,
        keep_scans: number(opts, "keep", 0usize)?,
        stop,
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
    let on_alert = on_alert_script(opts, &ctx.db)?;
    monitor::run(&targets, s, &ctx.db, &cfg, &mut |a| {
        let line = crate::schema::line("alert", a).unwrap_or_default();
        if echo {
            println!("{line}");
        }
        if let Some(f) = file.as_mut() {
            use std::io::Write;
            let _ = writeln!(f, "{line}");
        }
        if let Some(script) = &on_alert {
            run_on_alert(script, a, cfg.quiet);
        }
    })
}
/// The checks `monitor` makes before it starts looping, without starting anything: options,
/// targets, ports and the on-alert script. `service install` runs them, so a bad option fails
/// there and not in a service that then stops.
pub(in crate::ui) fn check(ctx: &Ctx) -> Result<(), String> {
    let opts = &ctx.opts;
    let s = scan_settings(opts)?;
    monitor_policy(opts)?;
    number(opts, "interval", 300u64)?;
    number(opts, "cycles", 0u32)?;
    number(opts, "listen-seconds", 30u64)?;
    number(opts, "keep", 0usize)?;
    on_alert_script(opts, &ctx.db)?;
    crate::scan::parse_targets(&ctx.pos.join(" "), s.skip_edges, crate::scan::MAX_STREAM)?;
    crate::scan::parse_ports(&s.ports)?;
    Ok(())
}
/// `--on-alert SCRIPT [--on-alert-dir DIR]`: the script and the directory it may write to
/// (default: `alert-scripts` next to the database).
fn on_alert_script(
    opts: &BTreeMap<String, String>,
    db: &std::path::Path,
) -> Result<Option<AlertScript>, String> {
    let Some(path) = opts.get("on-alert") else {
        if opts.contains_key("on-alert-dir") {
            return Err("--on-alert-dir needs --on-alert SCRIPT".into());
        }
        return Ok(None);
    };
    let dir = match opts.get("on-alert-dir") {
        Some(d) => PathBuf::from(d),
        None => db
            .parent()
            .unwrap_or(std::path::Path::new(""))
            .join("alert-scripts"),
    };
    AlertScript::load(path, &dir).map(Some)
}
/// Runs the script for one alert. A failing script is reported and never stops monitoring.
fn run_on_alert(script: &AlertScript, alert: &monitor::Alert, quiet: bool) {
    match script.run(alert) {
        Ok(lines) => {
            if !quiet {
                for line in lines {
                    eprintln!("on-alert: {line}");
                }
            }
        }
        Err(e) => eprintln!("on-alert script failed: {e}"),
    }
}
/// `--webhook-env NAME`: the webhook URL from that environment variable, so that it is neither on
/// the command line nor in a service's configuration (chat webhooks carry their secret in the
/// path). Errors name the variable, never its value.
fn webhook_env(
    name: &str,
    env: impl Fn(&str) -> Option<String>,
) -> Result<crate::notify::Sink, String> {
    let valid = !name.is_empty()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !name.starts_with(|c: char| c.is_ascii_digit());
    if !valid {
        return Err("--webhook-env takes the name of an environment variable (the URL itself must not be given here)".into());
    }
    let url = env(name)
        .filter(|u| !u.trim().is_empty())
        .ok_or_else(|| {
            format!("The environment variable {name} is not set or empty; --webhook-env reads the webhook URL from it")
        })?;
    crate::notify::Sink::webhook(&url).map_err(|_| {
        format!(
            "The environment variable {name} does not hold a valid http:// or https:// webhook URL"
        )
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
    if let Some(name) = opts.get("webhook-env") {
        policy
            .notify
            .sinks
            .push(webhook_env(name, |n| std::env::var(n).ok())?);
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

    #[test]
    fn webhook_env_reads_the_url_from_the_named_variable() {
        let secret = "https://hooks.example.com/services/T0/B0/s3cret";
        let env = |n: &str| match n {
            "NS_HOOK" => Some(secret.to_string()),
            "NS_EMPTY" => Some(" ".to_string()),
            "NS_BAD" => Some("ftp://s3cret".to_string()),
            _ => None,
        };
        assert_eq!(
            webhook_env("NS_HOOK", env).unwrap(),
            crate::notify::Sink::webhook(secret).unwrap()
        );
        for (name, message) in [
            ("NS_UNSET", "NS_UNSET is not set"),
            ("NS_EMPTY", "NS_EMPTY is not set or empty"),
            ("NS_BAD", "NS_BAD does not hold a valid"),
            (secret, "name of an environment variable"),
            ("1X", "name of an environment variable"),
            ("", "name of an environment variable"),
        ] {
            let err = webhook_env(name, env).unwrap_err();
            assert!(err.contains(message), "{name}: {err}");
            assert!(!err.contains("s3cret"), "the value is never shown: {err}");
        }
        // Through the option: an unset variable is a start-up error.
        let err = monitor_policy(&opts(&[(
            "webhook-env",
            "NS_TEST_NO_SUCH_WEBHOOK_VARIABLE",
        )]))
        .unwrap_err();
        assert!(err.contains("NS_TEST_NO_SUCH_WEBHOOK_VARIABLE"), "{err}");
    }

    fn opts(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn on_alert_option_loads_the_script_and_defaults_the_directory_next_to_the_db() {
        let dir = std::env::temp_dir().join(format!("ns-on-alert-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("inventory.sqlite");
        assert!(on_alert_script(&opts(&[]), &db).unwrap().is_none());
        let err = on_alert_script(&opts(&[("on-alert-dir", "x")]), &db).unwrap_err();
        assert!(err.contains("--on-alert"), "{err}");
        let script = dir.join("a.rhai");
        std::fs::write(
            &script,
            r#"fn on_alert(a) { write_file("seen.txt", a.kind); log("hi"); }"#,
        )
        .unwrap();
        let path = script.to_str().unwrap();
        let loaded = on_alert_script(&opts(&[("on-alert", path)]), &db)
            .unwrap()
            .unwrap();
        let alert = monitor::Alert {
            timestamp: 1,
            severity: risk::Severity::High,
            kind: "new-device".into(),
            subject: "10.0.0.5".into(),
            message: "New device".into(),
        };
        run_on_alert(&loaded, &alert, true);
        assert_eq!(
            std::fs::read_to_string(dir.join("alert-scripts/seen.txt")).unwrap(),
            "new-device"
        );
        // An explicit directory wins; a broken script is a start-up error, a failing one is not fatal.
        let other = dir.join("elsewhere");
        let loaded = on_alert_script(
            &opts(&[
                ("on-alert", path),
                ("on-alert-dir", other.to_str().unwrap()),
            ]),
            &db,
        )
        .unwrap()
        .unwrap();
        run_on_alert(&loaded, &alert, true);
        assert!(other.join("seen.txt").exists());
        std::fs::write(&script, "fn on_alert(a) { nosuch(); }").unwrap();
        let failing = on_alert_script(&opts(&[("on-alert", path)]), &db)
            .unwrap()
            .unwrap();
        run_on_alert(&failing, &alert, true);
        std::fs::write(&script, "fn on_host(h) { }").unwrap();
        assert!(on_alert_script(&opts(&[("on-alert", path)]), &db).is_err());
        assert!(on_alert_script(&opts(&[("on-alert", "missing.rhai")]), &db).is_err());
        assert!(
            on_alert_script(&opts(&[("on-alert", "library:log-alerts")]), &db)
                .unwrap()
                .is_some()
        );
        assert!(on_alert_script(&opts(&[("on-alert", "library:nope")]), &db).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
