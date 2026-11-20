//! `scan TARGETS [options]`: an active scan, saved to the inventory and printed in the chosen
//! format; with `--tui` the live terminal view (`ui::tui`) runs while it works.
use crate::{
    scan, store,
    ui::{Ctx, args::scan_settings, dryrun, guard, output, progress, saved_exit, tui},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::IpAddr,
    sync::atomic::Ordering,
};

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    let (opts, pos, db) = (ctx.opts.clone(), ctx.pos.clone(), ctx.db.clone());
    let (opts, db) = (&opts, &db);
    let targets = pos.join(" ");
    let s = scan_settings(opts)?;
    let format = opts.get("format").map(String::as_str).unwrap_or("json");
    if !["json", "csv", "html", "nmap", "md", "jsonl"].contains(&format) {
        return Err("Choose json, csv, html, nmap, md or jsonl".into());
    }
    let hosts = scan::parse_targets(&targets, s.skip_edges, scan::MAX_STREAM)?;
    let ports = scan::parse_ports(&s.ports)?;
    // --dry-run: print what would be sent and stop before anything is started or saved.
    if dryrun::requested(opts) {
        return dryrun::scan_plan(opts, "scan", &hosts, &ports, &s);
    }
    // Public or out-of-scope targets need confirmation before anything is sent (ROADMAP H54).
    if !guard::enforce(ctx, &hosts)? {
        return Ok(());
    }
    let total = hosts.count() as usize;
    let run = scan::start_stream(Box::new(hosts.iter()), total, ports, s.clone());
    let stream = opts.contains_key("stream");
    if stream && opts.contains_key("tui") {
        return Err("--stream and --tui both take the terminal; choose one".into());
    }
    let (results, complete, errors) = if opts.contains_key("tui") {
        tui::tui(&run)
    } else if stream {
        collect_streaming(&run)
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
        sent: run.sent.snapshot(),
    };
    let id = store::save(db, &snapshot)?;
    progress(
        opts,
        format_args!(
            "Saved scan #{id} ({})",
            if complete { "complete" } else { "partial" }
        ),
    );
    if opts.contains_key("sent-log") {
        eprintln!("{}", crate::sendlog::format_table(&snapshot.sent));
    }
    // With --stream stdout carries the live events; the report is written only to --output.
    if !stream || opts.contains_key("output") {
        output(
            &store::export_at(&snapshot, format, store::timestamp(db, id)?)?,
            opts,
        )?;
    }
    // Saved but stopped early (TUI stop, or errors): partial result, status 2.
    if !errors.is_empty() {
        eprintln!(
            "Scan #{id} saved as partial after errors: {}",
            errors.join("; ")
        );
    }
    ctx.status = saved_exit(complete);
    Ok(())
}
/// Hosts, complete flag, errors.
pub(in crate::ui) type Collected = (Vec<scan::Host>, bool, Vec<String>);
pub(in crate::ui) fn collect(run: &scan::Running) -> Collected {
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
/// Like [`collect`], and prints a `scan-event` line to stdout for every host that answers, every
/// port found open and every responding host that finishes, at the moment the engine reports it.
pub(in crate::ui) fn collect_streaming(run: &scan::Running) -> Collected {
    use std::io::Write;
    let mut hosts = vec![];
    let mut errors = vec![];
    let sparse = run.total > scan::MAX_HOSTS;
    // Ports already announced per host still being scanned (dropped when the host finishes).
    let mut announced: HashMap<IpAddr, BTreeSet<u16>> = HashMap::new();
    let mut stdout = std::io::stdout().lock();
    let mut line = |value: serde_json::Value| {
        if let Ok(text) = crate::schema::line("scan-event", &value) {
            // A closed pipe only ends the live output; the scan still completes and is saved.
            let _ = writeln!(stdout, "{text}").and_then(|()| stdout.flush());
        }
    };
    let elapsed = || run.started.elapsed().as_millis() as u64;
    loop {
        let event = match run.receiver.recv() {
            Ok(event) => event,
            Err(_) => {
                errors.push("Scan worker disconnected".into());
                break;
            }
        };
        match &event {
            scan::Event::Partial(h) => {
                let seen = announced.entry(h.ip).or_insert_with(|| {
                    line(serde_json::json!({"event": "host-up", "ip": h.ip.to_string(), "elapsed_ms": elapsed()}));
                    BTreeSet::new()
                });
                for &port in &h.open {
                    if seen.insert(port) {
                        line(
                            serde_json::json!({"event": "port-open", "ip": h.ip.to_string(), "port": port, "elapsed_ms": elapsed()}),
                        );
                    }
                }
            }
            scan::Event::Host(h) => {
                let before = announced.remove(&h.ip).unwrap_or_default();
                if h.responding {
                    if before.is_empty() && h.open.is_empty() {
                        line(
                            serde_json::json!({"event": "host-up", "ip": h.ip.to_string(), "elapsed_ms": elapsed()}),
                        );
                    }
                    for &port in h.open.iter().filter(|p| !before.contains(p)) {
                        line(
                            serde_json::json!({"event": "port-open", "ip": h.ip.to_string(), "port": port, "elapsed_ms": elapsed()}),
                        );
                    }
                    line(
                        serde_json::json!({"event": "host-done", "ip": h.ip.to_string(), "open": h.open, "ports_checked": h.ports_checked, "elapsed_ms": elapsed()}),
                    );
                }
            }
            _ => {}
        }
        if accept(event, &mut hosts, sparse, &mut errors) {
            break;
        }
    }
    let complete = errors.is_empty() && !run.cancel.load(Ordering::Relaxed);
    (hosts, complete, errors)
}
/// Applies one scan event and returns true on `Done`. Errors never discard results: they are
/// recorded and mark the scan partial (the engine always follows with `Done`).
pub(in crate::ui) fn accept(
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
        // Provisional hosts are for live views; the final `Host` event carries the result.
        scan::Event::Partial(_) => false,
        scan::Event::Done => true,
        scan::Event::Error(e) => {
            errors.push(e);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::{run, testutil::args};

    /// The sent log is saved with the scan, appears in the JSON output and in `--sent-log`.
    #[test]
    fn a_real_scan_records_what_it_sent() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port().to_string();
        let dir = std::env::temp_dir().join(format!("ns-sentlog-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (db, out) = (dir.join("x.sqlite"), dir.join("out.json"));
        let status = run(&args(&[
            "scan",
            "127.0.0.1",
            "--scope",
            "127.0.0.0/8",
            "--tcp-only",
            "--fast",
            "--sent-log",
            "--ports",
            &port,
            "--db",
            db.to_str().unwrap(),
            "--output",
            out.to_str().unwrap(),
            "--quiet",
        ]))
        .unwrap();
        assert_eq!(status, crate::ui::ExitCode::Success);
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        let sent = json["sent"].as_array().unwrap();
        assert!(
            sent.iter().any(|e| e["kind"] == "tcp-connect"
                && e["detail"] == "port scan"
                && e["count"].as_u64().unwrap() >= 1),
            "{sent:?}"
        );
        // --tcp-only: no ping was sent, so none is logged.
        assert!(sent.iter().all(|e| e["kind"] != "icmp-echo"), "{sent:?}");
        let stored = store::load(&db, 1).unwrap();
        assert_eq!(stored.sent.len(), sent.len());
        assert!(crate::sendlog::total(&stored.sent) >= 1);
        let _ = std::fs::remove_dir_all(&dir);
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
}
