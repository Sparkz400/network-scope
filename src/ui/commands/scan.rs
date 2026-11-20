//! `scan TARGETS [options]`: an active scan, saved to the inventory and printed in the chosen
//! format; with `--tui` the live terminal view (`ui::tui`) runs while it works.
use crate::{
    scan, store,
    ui::{Ctx, args::scan_settings, dryrun, guard, output, progress, saved_exit, tui},
};
use std::{collections::BTreeMap, sync::atomic::Ordering};

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
    if opts.contains_key("record-wire") && !opts.contains_key("record") {
        return Err(
            "--record-wire needs --record FILE.pcapng (the file the capture is written to)".into(),
        );
    }
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
    // --record-wire: capture the real frames of the scan while it runs, when the driver allows it.
    let wire = start_wire(opts, &s.interface, &hosts, total);
    // --randomize: the same addresses in random order (the order of probing only).
    let order: Box<dyn Iterator<Item = std::net::IpAddr> + Send> = if opts.contains_key("randomize")
    {
        Box::new(crate::targets::randomized(&hosts, crate::targets::fresh_seed())?.into_iter())
    } else {
        Box::new(hosts.iter())
    };
    let run = scan::start_stream(order, total, ports, s.clone());
    let (results, complete, errors) = if opts.contains_key("tui") {
        tui::tui(&run)
    } else {
        collect(&run)
    };
    if results.is_empty() && !errors.is_empty() {
        return Err(errors.join("; "));
    }
    let snapshot = store::Snapshot {
        targets,
        complete,
        settings: crate::provenance::stamped(&s),
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
    if let Some(file) = opts.get("record") {
        let wire_written = match wire {
            Some(capture) => write_wire(capture, file, opts),
            None => false,
        };
        if !wire_written {
            write_record(&run, file, &snapshot, opts)?;
        }
    }
    if let (Some(original), Some(original_id)) = (&original, replay_of) {
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
    output(
        &store::export_at(&snapshot, format, store::timestamp(db, id)?)?,
        opts,
    )?;
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
/// `--record-wire`: starts the capture of the scan's real frames. `None` when it was not asked
/// for, and, with the reason on stderr, when it cannot be done (no driver, no permission, no
/// interface for these targets, too many targets): the application-level record follows then.
fn start_wire(
    opts: &BTreeMap<String, String>,
    interface: &str,
    hosts: &scan::Targets,
    total: usize,
) -> Option<network_scope_core::wirecap::WireCapture> {
    use network_scope_core::wirecap;
    if !opts.contains_key("record-wire") {
        return None;
    }
    let started = (|| {
        if total > wirecap::MAX_FILTER_HOSTS {
            return Err(format!(
                "{total} targets are too many for a capture filter (at most {})",
                wirecap::MAX_FILTER_HOSTS
            ));
        }
        let targets: Vec<std::net::IpAddr> = hosts.iter().collect();
        wirecap::WireCapture::start(wirecap::plan(interface, &targets)?)
    })();
    match started {
        Ok(capture) => {
            progress(
                opts,
                format_args!(
                    "Capturing the wire traffic of the targets on {} (filter: {})",
                    capture.plan().interface,
                    capture.plan().filter
                ),
            );
            Some(capture)
        }
        Err(e) => {
            progress(
                opts,
                format_args!(
                    "Wire capture not possible: {e}. Writing the application-level record instead."
                ),
            );
            None
        }
    }
}

/// Ends the capture and writes it to `file` as pcapng. `false` (with the reason) when nothing was
/// captured or the file could not be written, so that the caller writes the application-level
/// record instead.
fn write_wire(
    capture: network_scope_core::wirecap::WireCapture,
    file: &str,
    opts: &BTreeMap<String, String>,
) -> bool {
    let plan = capture.plan().clone();
    let captured = capture.finish();
    if captured.frames.is_empty() {
        let why = captured.error.as_deref().unwrap_or(
            "no frame matched the filter; the targets may be reached through another interface, or are this computer's own addresses",
        );
        progress(
            opts,
            format_args!(
                "Wire capture on {} saw no frames ({why}). Writing the application-level record instead.",
                plan.interface
            ),
        );
        return false;
    }
    if let Err(e) = network_scope_core::record::write_wire_pcapng(
        std::path::Path::new(file),
        captured.link_type,
        &plan.interface,
        &plan.filter,
        &captured.frames,
    ) {
        progress(
            opts,
            format_args!("{e}. Writing the application-level record instead."),
        );
        return false;
    }
    progress(
        opts,
        format_args!(
            "Recorded {} frames from the wire ({}, filter: {}) to {file}. This is a wire capture: the frames are the real ones, with their own headers, addresses, sequence numbers and times. TLS and SSH payloads are encrypted as they were on the wire, and other traffic of the same hosts during the scan is included.",
            captured.frames.len(),
            plan.interface,
            plan.filter
        ),
    );
    if captured.dropped > 0 {
        progress(
            opts,
            format_args!(
                "{} frames did not fit the bounds of the capture and are not in it.",
                captured.dropped
            ),
        );
    }
    if let Some(e) = captured.error {
        progress(
            opts,
            format_args!(
                "The capture ended early ({e}); the file holds what was captured until then."
            ),
        );
    }
    true
}

/// Writes the payload record of the scan (`--record FILE`) and says what it is and what it covers.
fn write_record(
    run: &scan::Running,
    file: &str,
    snapshot: &store::Snapshot,
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
            crate::sendlog::total(&snapshot.sent)
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

    /// `--record-wire` needs `--record`, and without a usable capture (here an interface that does
    /// not exist, so also without a driver) the scan falls back to the application-level record,
    /// labelled as such.
    #[test]
    fn record_wire_falls_back_to_the_application_level_record() {
        let (_listener, port) = http_listener();
        let dir = std::env::temp_dir().join(format!("ns-record-wire-cli-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (db, rec) = (dir.join("w.sqlite"), dir.join("scan.pcapng"));
        let out = dir.join("o.json");
        let scan = |extra: &[&str]| {
            let mut a = vec![
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
                out.to_str().unwrap(),
                "--quiet",
            ];
            a.extend(extra);
            run(&args(&a))
        };
        // --record-wire alone has nothing to write to
        let e = scan(&["--record-wire"]).unwrap_err();
        assert!(e.contains("--record-wire needs --record"), "{e}");
        assert!(!rec.exists());
        // a capture that cannot be opened: the application-level record is written
        scan(&[
            "--record",
            rec.to_str().unwrap(),
            "--record-wire",
            "--interface",
            "no-such-interface-0",
        ])
        .unwrap();
        let text = String::from_utf8_lossy(&std::fs::read(&rec).unwrap()).into_owned();
        assert!(text.contains("APPLICATION-LEVEL RECORD, NOT A WIRE CAPTURE"));
        assert!(!text.contains("WIRE CAPTURE of a Network Scope scan"));
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
        // an old scan without a stamp can never be reproduced, and the output says why
        let mut old = stored.clone();
        old.settings.provenance = None;
        let id = store::save(std::path::Path::new(&db), &old).unwrap();
        run(&args(&[
            "scan",
            "--replay-check",
            &id.to_string(),
            "--scope",
            "127.0.0.0/8",
            "--db",
            &db,
            "--output",
            &out,
            "--quiet",
        ]))
        .unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(
            text.contains("cannot be called reproduced") && !text.contains("NOT reproduced"),
            "{text}"
        );
        assert!(
            text.contains(&format!("Scan #{id} has no provenance stamp"))
                && text.contains("re-run (and so stamp) the scans you want to cite"),
            "{text}"
        );
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
