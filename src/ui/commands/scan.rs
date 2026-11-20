//! `scan TARGETS [options]`: an active scan, saved to the inventory and printed in the chosen
//! format; with `--tui` the live terminal view (`ui::tui`) runs while it works.
use crate::{
    scan, store, store_stream,
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
    // `--replay-check ID` runs the stored scan again with its own targets and settings.
    let replay_of = opts
        .get("replay-check")
        .map(|v| {
            v.parse::<i64>()
                .map_err(|_| "--replay-check needs a scan ID".to_string())
        })
        .transpose()?;
    if replay_of.is_none() && opts.contains_key("fail-on-findings") {
        return Err("--fail-on-findings applies to scan only together with --replay-check".into());
    }
    let original = replay_of.map(|id| store::load(db, id)).transpose()?;
    let (targets, s) = match &original {
        Some(o) => {
            if !pos.is_empty() || opts.contains_key("targets-file") {
                return Err(
                    "--replay-check takes the targets from the stored scan; give none".into(),
                );
            }
            const OWN: [&str; 10] = [
                "ports",
                "fast",
                "deep",
                "services",
                "udp",
                "os",
                "ot",
                "timeout",
                "probes",
                "top-ports",
            ];
            if let Some(k) = OWN.iter().find(|k| opts.contains_key(**k)) {
                return Err(format!(
                    "--{k} cannot be combined with --replay-check: the settings of the stored scan are used"
                ));
            }
            let mut s = o.settings.clone();
            s.provenance = None;
            s.record = opts.contains_key("record");
            (o.targets.clone(), s)
        }
        None => {
            let mut targets = pos.join(" ");
            // --targets-file FILE: more targets from a list file (one entry per line, # comments).
            if let Some(file) = opts.get("targets-file") {
                let listed = crate::targets::read_file(std::path::Path::new(file))?;
                targets = if targets.is_empty() {
                    listed
                } else {
                    format!("{targets} {listed}")
                };
            }
            (targets, scan_settings(opts)?)
        }
    };
    let format = opts
        .get("format")
        .map(String::as_str)
        .unwrap_or(if original.is_some() { "text" } else { "json" });
    if original.is_some() {
        if !["text", "json"].contains(&format) {
            return Err("With --replay-check choose --format text or json".into());
        }
    } else if !["json", "csv", "html", "nmap", "md", "jsonl"].contains(&format) {
        return Err("Choose json, csv, html, nmap, md or jsonl".into());
    }
    // Several interfaces (--interface a,b) need a source address and MAC each.
    crate::interfaces::specs(&s)?;
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
    let stream = opts.contains_key("stream");
    let tui_view = opts.contains_key("tui");
    if stream && tui_view {
        return Err("--stream and --tui both take the terminal; choose one".into());
    }
    // A scan of more than MAX_HOSTS addresses never collects its hosts in memory: they go to the
    // inventory in batches while the scan runs (ROADMAP B15). The terminal view needs them in
    // memory to draw, so it keeps the old path.
    let batched = total > scan::MAX_HOSTS && !tui_view;
    let mut writer = if batched {
        Some(store_stream::ScanWriter::begin(
            db,
            &targets,
            &crate::provenance::stamped(&s),
        )?)
    } else {
        None
    };
    // A repeat scan: the newest complete scan of the same targets is the base.
    let previous = if opts.contains_key("incremental") {
        match crate::incremental::load_base(db, &targets, &s)? {
            Ok(base) => {
                progress(
                    opts,
                    format_args!(
                        "Incremental scan based on scan #{} ({} hosts): known open ports and a sample are probed again, the rest is carried over",
                        base.id,
                        base.len()
                    ),
                );
                Some(base)
            }
            Err(why) => {
                progress(
                    opts,
                    format_args!("Full scan instead of an incremental one: {why}"),
                );
                None
            }
        }
    } else {
        None
    };
    let run = scan::start_incremental(
        // --randomize: the same addresses in random order (the order of probing only).
        if opts.contains_key("randomize") {
            Box::new(crate::targets::randomized(&hosts, crate::targets::fresh_seed())?.into_iter())
        } else {
            Box::new(hosts.iter_interleaved())
        },
        total,
        ports,
        s.clone(),
        previous,
    );
    let (mut results, complete, errors) = if tui_view {
        tui::tui(&run)
    } else if let Some(w) = writer.as_mut() {
        let (complete, errors) = drive(&run, stream, &mut |h| w.push(&h));
        (vec![], complete, errors)
    } else if stream {
        collect_streaming(&run)
    } else {
        collect(&run)
    };
    // --ipv6-discover: the local link over IPv6, joined to the scanned hosts by MAC. Runs after the
    // scan (the IPv4 hosts and their MACs are known), one echo per interface through the scan's
    // own pacing and sent log. A stopped scan does not start it.
    let mut observations = vec![];
    // A batch-written scan (above 65,536 addresses) has no hosts in memory to join to.
    if s.ipv6_discover && complete && writer.is_some() {
        progress(
            opts,
            "IPv6 discovery skipped: the scan was written in batches (more than 65,536 addresses)",
        );
    } else if s.ipv6_discover && complete {
        let gate = crate::ipv6::gate(&s, run.sent.clone());
        let found = crate::ipv6::discover(&s, &gate);
        for note in &found.notes {
            progress(opts, note);
        }
        observations = crate::ipv6::observations(&found);
        let added = crate::ipv6::merge(&mut results, &found);
        progress(
            opts,
            format_args!(
                "IPv6: {} interface(s), {} answered the multicast echo, {} neighbor(s) in the cache, {added} host(s) added",
                found.interfaces.len(),
                found.responders.len(),
                found.neighbors.len()
            ),
        );
    }
    let found = writer
        .as_ref()
        .map_or(results.len(), store_stream::ScanWriter::hosts);
    if found == 0 && !errors.is_empty() {
        return Err(errors.join("; "));
    }
    let sent = run.sent.snapshot();
    let (id, snapshot) = match writer {
        Some(w) => (w.finish(complete, sent.clone())?, None),
        None => {
            let snapshot = store::Snapshot {
                targets,
                complete,
                settings: crate::provenance::stamped(&s),
                hosts: results,
                observations,
                notes: BTreeMap::new(),
                sent: sent.clone(),
            };
            (store::save(db, &snapshot)?, Some(snapshot))
        }
    };
    progress(
        opts,
        format_args!(
            "Saved scan #{id} ({})",
            if complete { "complete" } else { "partial" }
        ),
    );
    if opts.contains_key("sent-log") {
        eprintln!("{}", crate::sendlog::format_table(&sent));
    }
    if let Some(file) = opts.get("record") {
        write_record(&run, file, &sent, opts)?;
    }
    if let (Some(original), Some(original_id)) = (&original, replay_of) {
        let snapshot = match snapshot {
            Some(snapshot) => snapshot,
            None => store::load(db, id)?,
        };
        let check = crate::provenance::replay_check(original, original_id, &snapshot, id);
        match format {
            "json" => output(&crate::schema::object("replay-check", &check)?, opts)?,
            _ => output(&check.text(), opts)?,
        }
        if !errors.is_empty() {
            eprintln!(
                "Scan #{id} saved as partial after errors: {}",
                errors.join("; ")
            );
        }
        ctx.status = if !complete {
            saved_exit(false)
        } else {
            crate::ui::findings_exit(ctx.fail_on_findings(), usize::from(!check.reproducible))
        };
        return Ok(());
    }
    // With --stream stdout carries the live events; the report is written only to --output.
    let report = !opts.contains_key("no-report") && (!stream || opts.contains_key("output"));
    if report {
        // A batch-written scan is read back for the report: the scan itself ran in flat memory,
        // the report needs the responding hosts (and only those) in memory.
        let snapshot = match snapshot {
            Some(snapshot) => snapshot,
            None => store::load(db, id)?,
        };
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
/// Writes the payload record of the scan (`--record FILE`) and says what it is and what it covers.
fn write_record(
    run: &scan::Running,
    file: &str,
    sent: &[crate::sendlog::SentEntry],
    opts: &BTreeMap<String, String>,
) -> Result<(), String> {
    let recorder = run
        .sent
        .recorder()
        .ok_or("Recording was not started for this scan")?;
    let written = recorder.write_pcapng(std::path::Path::new(file))?;
    progress(
        opts,
        format_args!(
            "Recorded {} payloads ({} frames) to {file}. This is an application-level record, not a wire capture: the MAC addresses, the scanner's address and port and the sequence numbers are synthetic, and there are no handshake or acknowledgement frames.",
            written.records, written.frames
        ),
    );
    progress(
        opts,
        format_args!(
            "The sent log lists {} packets; the record covers the OT requests and replies and the service identification payloads (probes, HTTP, SMB and RDP negotiate), not the connects, ICMP, ARP, UDP probes, TLS, SSH, DNS or traceroute.",
            crate::sendlog::total(sent)
        ),
    );
    if written.dropped > 0 {
        progress(
            opts,
            format_args!(
                "{} payloads did not fit the bounds of the record and are not in it.",
                written.dropped
            ),
        );
    }
    Ok(())
}

/// Hosts, complete flag, errors.
pub(in crate::ui) type Collected = (Vec<scan::Host>, bool, Vec<String>);
pub(in crate::ui) fn collect(run: &scan::Running) -> Collected {
    collect_with(run, false)
}
/// Like [`collect`], and prints a `scan-event` line to stdout for every host that answers, every
/// port found open and every responding host that finishes, at the moment the engine reports it.
pub(in crate::ui) fn collect_streaming(run: &scan::Running) -> Collected {
    collect_with(run, true)
}
fn collect_with(run: &scan::Running, stream: bool) -> Collected {
    let mut hosts = vec![];
    let (complete, errors) = drive(run, stream, &mut |h| {
        hosts.push(h);
        Ok(())
    });
    (hosts, complete, errors)
}
/// Runs the scan's events to the end: every host worth keeping (responding ones, or all when the
/// scan is small) goes to `sink`, with `stream` the live events go to stdout. A failing sink
/// stops the scan and is reported as an error. Returns (complete, errors); errors never discard
/// results, they only mark the scan partial.
fn drive(
    run: &scan::Running,
    stream: bool,
    sink: &mut dyn FnMut(scan::Host) -> Result<(), String>,
) -> (bool, Vec<String>) {
    use std::io::Write;
    let mut errors = vec![];
    let sparse = run.total > scan::MAX_HOSTS;
    // Ports already announced per host still being scanned (dropped when the host finishes).
    let mut announced: HashMap<IpAddr, BTreeSet<u16>> = HashMap::new();
    let mut stdout = std::io::stdout().lock();
    let mut line = |value: serde_json::Value| {
        if stream && let Ok(text) = crate::schema::line("scan-event", &value) {
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
        match event {
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
                if (h.responding || !sparse)
                    && let Err(e) = sink(h)
                    && !errors.contains(&e)
                {
                    // The results cannot be kept: stop, the engine ends with `Done`.
                    run.cancel.store(true, Ordering::Relaxed);
                    errors.push(e);
                }
            }
            scan::Event::Done => break,
            scan::Event::Error(e) => errors.push(e),
        }
    }
    let complete = errors.is_empty() && !run.cancel.load(Ordering::Relaxed);
    (complete, errors)
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

    /// A listener that answers an HTTP request, and its port.
    fn http_listener() -> (std::net::TcpListener, String) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port().to_string();
        let l = listener.try_clone().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            for stream in l.incoming() {
                let Ok(mut s) = stream else { break };
                std::thread::spawn(move || {
                    let mut buf = [0u8; 2048];
                    let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                    if s.read(&mut buf).unwrap_or(0) > 0 {
                        let _ = s.write_all(
                            b"HTTP/1.1 200 OK\r\nServer: lab/1.0\r\nContent-Length: 0\r\n\r\n",
                        );
                    }
                });
            }
        });
        (listener, port)
    }

    /// `--record` writes the payloads of the scan as pcapng, honestly labelled, and the file
    /// reads back as frames that hold the HTTP request and its reply.
    #[test]
    fn record_writes_the_payloads_of_the_scan_as_pcapng() {
        let (_listener, port) = http_listener();
        let dir = std::env::temp_dir().join(format!("ns-record-cli-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (db, rec) = (dir.join("r.sqlite"), dir.join("scan.pcapng"));
        let status = run(&args(&[
            "scan",
            "127.0.0.1",
            "--scope",
            "127.0.0.0/8",
            "--tcp-only",
            "--fast",
            "--services",
            "--ports",
            &port,
            "--db",
            db.to_str().unwrap(),
            "--output",
            dir.join("o.json").to_str().unwrap(),
            "--record",
            rec.to_str().unwrap(),
            "--quiet",
        ]))
        .unwrap();
        assert_eq!(status, crate::ui::ExitCode::Success);
        let bytes = std::fs::read(&rec).unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.contains("NOT A WIRE CAPTURE"),
            "header says what it is"
        );
        assert!(text.contains("sent: HTTP GET /"), "the request is labelled");
        let mut reader = network_scope_core::pcapfile::Reader::new(&bytes[..]).unwrap();
        let mut payloads = vec![];
        while let Some((_, frame)) = reader.next_frame().unwrap() {
            payloads.push(String::from_utf8_lossy(&frame[54..]).into_owned());
        }
        assert!(
            payloads.iter().any(|p| p.starts_with("GET / HTTP/1.1")),
            "{payloads:?}"
        );
        assert!(
            payloads.iter().any(|p| p.starts_with("HTTP/1.1 200 OK")),
            "{payloads:?}"
        );
        // without --record nothing is written and --record is refused on other commands
        assert!(
            run(&args(&[
                "history",
                "--record",
                "x.pcapng",
                "--db",
                db.to_str().unwrap()
            ]))
            .is_err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `--replay-check` runs the stored scan again and compares the results and the stamps.
    #[test]
    fn replay_check_reproduces_a_scan_and_reports_changed_rules() {
        let (listener, port) = http_listener();
        let dir = std::env::temp_dir().join(format!("ns-replay-cli-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = |n: &str| dir.join(n).to_str().unwrap().to_string();
        let (db, out) = (p("r.sqlite"), p("out.txt"));
        run(&args(&[
            "scan",
            "127.0.0.1",
            "--scope",
            "127.0.0.0/8",
            "--tcp-only",
            "--fast",
            "--ports",
            &port,
            "--db",
            &db,
            "--output",
            &p("o.json"),
            "--quiet",
        ]))
        .unwrap();
        let stored = store::load(std::path::Path::new(&db), 1).unwrap();
        assert!(
            stored.settings.provenance.is_some(),
            "a scan carries its stamp"
        );
        let exported: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(p("o.json")).unwrap()).unwrap();
        assert!(
            exported["settings"]["provenance"]["combined"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        // the same scan again: reproduced
        let status = run(&args(&[
            "scan",
            "--replay-check",
            "1",
            "--scope",
            "127.0.0.0/8",
            "--db",
            &db,
            "--output",
            &out,
            "--quiet",
            "--fail-on-findings",
        ]))
        .unwrap();
        // The result is the same. The rules are too unless another test of this process loaded
        // a feed or a rule file (they are process-wide) between the two scans.
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(text.contains("result: identical"), "{text}");
        if text.contains("rules:  identical") {
            assert_eq!(status, crate::ui::ExitCode::Success);
            assert!(
                text.contains("reproduced (same result, same rules)"),
                "{text}"
            );
        }
        // a copy of the scan with a stamp of other rules: not reproduced, and the gate says 3
        let mut changed = stored.clone();
        let prov = changed.settings.provenance.as_mut().unwrap();
        prov.rules
            .insert("cves.json".into(), crate::provenance::hash(b"older rules"));
        let id = store::save(std::path::Path::new(&db), &changed).unwrap();
        let status = run(&args(&[
            "scan",
            "--replay-check",
            &id.to_string(),
            "--scope",
            "127.0.0.0/8",
            "--db",
            &db,
            "--format",
            "json",
            "--output",
            &out,
            "--quiet",
            "--fail-on-findings",
        ]))
        .unwrap();
        assert_eq!(
            status,
            crate::ui::ExitCode::Findings,
            "{}",
            std::fs::read_to_string(&out).unwrap()
        );
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(json["schema"], "network-scope/replay-check/v1");
        assert_eq!(json["same_result"], true);
        assert_eq!(json["same_rules"], false);
        assert_eq!(json["rule_differences"][0], "rules cves.json: changed");
        // the listener going away changes the result
        drop(listener);
        // (the listener thread keeps the socket open; closing is not guaranteed, so only check errors)
        for bad in [
            vec!["scan", "--replay-check", "abc"],
            vec!["scan", "--replay-check", "99"],
            vec!["scan", "10.0.0.1", "--replay-check", "1"],
            vec!["scan", "--replay-check", "1", "--ports", "80"],
            vec!["scan", "--replay-check", "1", "--format", "csv"],
            vec!["scan", "127.0.0.1", "--fail-on-findings"],
        ] {
            let mut a = bad.clone();
            a.extend(["--db", &db, "--scope", "127.0.0.0/8"]);
            assert!(run(&args(&a)).is_err(), "{bad:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The sent log is saved with the scan, appears in the JSON output and in `--sent-log`.
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

    /// Events of a big scan (above MAX_HOSTS addresses): only responding hosts reach the sink, a
    /// failing sink stops the scan, and nothing but the sink keeps a host.
    #[test]
    fn a_big_scan_keeps_responding_hosts_in_the_sink_only() {
        let host = |n: u8, responding: bool| scan::Host {
            ip: format!("10.0.0.{n}").parse().unwrap(),
            responding,
            ping: None,
            ttl: None,
            hostname: String::new(),
            mac: String::new(),
            open: vec![],
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity: BTreeMap::new(),
            udp_open: vec![],
            trace: vec![],
        };
        let running = |total: usize| {
            let (tx, receiver) = std::sync::mpsc::channel();
            for (n, up) in [(1, true), (2, false), (3, true)] {
                tx.send(scan::Event::Host(host(n, up))).unwrap();
            }
            tx.send(scan::Event::Done).unwrap();
            scan::Running {
                receiver,
                cancel: Default::default(),
                pause: Default::default(),
                total,
                started: std::time::Instant::now(),
                sent: Default::default(),
            }
        };
        let mut kept = vec![];
        let (complete, errors) = drive(&running(scan::MAX_HOSTS + 1), false, &mut |h| {
            kept.push(h.ip.to_string());
            Ok(())
        });
        assert!(complete && errors.is_empty());
        assert_eq!(
            kept,
            ["10.0.0.1", "10.0.0.3"],
            "the silent host is not kept"
        );
        // A small scan keeps every host.
        let mut all = 0;
        drive(&running(3), false, &mut |_| {
            all += 1;
            Ok(())
        });
        assert_eq!(all, 3);
        // A sink that fails (disk full) cancels the scan and marks it partial.
        let run = running(scan::MAX_HOSTS + 1);
        let (complete, errors) = drive(&run, false, &mut |_| Err("disk full".into()));
        assert!(!complete && errors == ["disk full"], "{errors:?}");
        assert!(run.cancel.load(Ordering::Relaxed));
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
