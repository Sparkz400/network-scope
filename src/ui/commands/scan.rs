// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! `scan TARGETS [options]`: an active scan, saved to the inventory and printed in the chosen
//! format; with `--tui` the live terminal view (`ui::tui`) runs while it works.
use crate::{
    scan, store, store_stream,
    ui::{Ctx, args::scan_settings, dryrun, guard, output, progress, saved_exit, tui},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    io::IsTerminal,
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::RecvTimeoutError,
    },
    time::{Duration, Instant},
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
    let original = replay_of
        .map(|id| crate::ui::load_scan(db, id))
        .transpose()?;
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
    } else if !["json", "csv", "html", "nmap", "md", "jsonl", "cyclonedx"].contains(&format) {
        return Err("Choose json, csv, html, nmap, md, jsonl or cyclonedx".into());
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
    // --record-wire: capture the real frames of the scan while it runs, when the driver allows it.
    let wire = start_wire(opts, &s.interface, &hosts, total);
    let stream = opts.contains_key("stream");
    let tui_view = opts.contains_key("tui");
    if stream && tui_view {
        return Err("--stream and --tui both take the terminal; choose one".into());
    }
    snmp_warnings(opts, &s);
    // The terminal view shows a host as soon as it answers (provisional rows, like the desktop).
    let mut s = s;
    s.partial_events |= tui_view;
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
    // On a terminal a plain scan says what it is doing (a Safe Mode /24 takes minutes). A
    // stderr that is a pipe or a file gets nothing new: scripts read it.
    let live =
        !opts.contains_key("quiet") && !stream && !tui_view && std::io::stderr().is_terminal();
    if live {
        eprintln!("{}", start_text(total, ports.len(), s.safe));
    }
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
        let stop = crate::ui::interrupt::flag();
        let (complete, errors) = drive(&run, stream, live, &stop, &mut |h| w.push(&h));
        (vec![], complete, errors)
    } else if stream {
        collect_streaming(&run)
    } else {
        collect(&run, live)
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
        let outcome = crate::ipv6::after_scan(
            &s,
            run.sent.clone(),
            &mut results,
            crate::ipv6::AddHosts::Fresh,
        );
        for note in &outcome.found.notes {
            progress(opts, note);
        }
        progress(opts, outcome.summary());
        observations = outcome.observations;
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
    // A batched (streamed) scan writes no research rows: run `research rebuild` to index it.
    if snapshot.is_none() {
        progress(
            opts,
            format_args!(
                "Large scan #{id}: run `research rebuild` to index it for research queries and exports"
            ),
        );
    }
    if opts.contains_key("sent-log") {
        eprintln!("{}", crate::sendlog::format_table(&sent));
    }
    if let Some(file) = opts.get("record") {
        let wire_written = match wire {
            Some(capture) => write_wire(capture, file, opts),
            None => false,
        };
        if !wire_written {
            write_record(&run, file, &sent, opts)?;
        }
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
/// `live`: print the progress line of a plain scan on stderr (see [`drive`]).
pub(in crate::ui) fn collect(run: &scan::Running, live: bool) -> Collected {
    collect_with(run, false, live)
}
/// Like [`collect`], and prints a `scan-event` line to stdout for every host that answers, every
/// port found open and every responding host that finishes, at the moment the engine reports it.
pub(in crate::ui) fn collect_streaming(run: &scan::Running) -> Collected {
    collect_with(run, true, false)
}
fn collect_with(run: &scan::Running, stream: bool, live: bool) -> Collected {
    let mut hosts = vec![];
    let stop = crate::ui::interrupt::flag();
    let (complete, errors) = drive(run, stream, live, &stop, &mut |h| {
        hosts.push(h);
        Ok(())
    });
    (hosts, complete, errors)
}
/// A warning before the scan when the SNMP setting uses a weak algorithm (MD5 authentication,
/// DES privacy): they exist for old devices and must not look like a default.
pub(in crate::ui) fn snmp_warnings(opts: &BTreeMap<String, String>, s: &scan::Settings) {
    if let Some(config) = &s.snmp {
        for weak in config.weak_crypto() {
            progress(opts, format_args!("SNMP warning: {weak}"));
        }
    }
}
/// Runs the scan's events to the end: every host worth keeping (responding ones, or all when the
/// scan is small) goes to `sink`, with `stream` the live events go to stdout. A failing sink
/// stops the scan and is reported as an error. `stop` (Ctrl+C, see `ui::interrupt`) cancels the
/// scan: the engine finishes the hosts it is working on and what was found is kept. With `live`
/// a progress line ([`progress_text`]) is rewritten on stderr every [`PROGRESS_EVERY`] and ended
/// with a newline. Returns (complete, errors); errors never discard results, they only mark the
/// scan partial.
fn drive(
    run: &scan::Running,
    stream: bool,
    live: bool,
    stop: &AtomicBool,
    sink: &mut dyn FnMut(scan::Host) -> Result<(), String>,
) -> (bool, Vec<String>) {
    use std::io::Write;
    let mut errors = vec![];
    // Hosts finished and hosts that responded, for the progress line; when it was last printed.
    let (mut done, mut responded) = (0usize, 0usize);
    let mut printed: Option<Instant> = None;
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
        // Checked after every event and every timeout: a busy scan never times out.
        if live && printed.unwrap_or(run.started).elapsed() >= PROGRESS_EVERY {
            // No padding: every number in the line only grows, so it never gets shorter.
            eprint!(
                "\r{}",
                progress_text(done, run.total, responded, run.started.elapsed())
            );
            printed = Some(Instant::now());
        }
        let event = match run.receiver.recv_timeout(Duration::from_millis(200)) {
            Ok(event) => event,
            Err(RecvTimeoutError::Timeout) => {
                if stop.load(Ordering::Relaxed) && !run.cancel.swap(true, Ordering::Relaxed) {
                    if printed.is_some() {
                        // End the progress line; the next one starts on a line of its own.
                        eprintln!();
                    }
                    eprintln!(
                        "Stopping: what was found so far is saved (Ctrl+C again ends at once)"
                    );
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => {
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
                done += 1;
                responded += usize::from(h.responding);
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
    if live {
        // The final count, and the newline that ends the progress line before the report.
        eprintln!(
            "\r{}",
            progress_text(done, run.total, responded, run.started.elapsed())
        );
    }
    let complete = errors.is_empty() && !run.cancel.load(Ordering::Relaxed);
    (complete, errors)
}
/// How often the progress line of a plain scan is rewritten.
const PROGRESS_EVERY: Duration = Duration::from_secs(2);
/// The line a plain scan on a terminal starts with.
fn start_text(addresses: usize, ports: usize, safe: bool) -> String {
    let plural = |n: usize, ending: &'static str| if n == 1 { "" } else { ending };
    format!(
        "Scanning {addresses} address{}, {ports} TCP port{}, Safe Mode {}",
        plural(addresses, "es"),
        plural(ports, "s"),
        if safe { "on" } else { "off" }
    )
}
/// The progress line of a plain scan: hosts finished of all, how many responded, time so far.
fn progress_text(done: usize, total: usize, responded: usize, elapsed: Duration) -> String {
    let seconds = elapsed.as_secs();
    format!(
        "{done}/{total} hosts done, {responded} responded, {}:{:02} elapsed",
        seconds / 60,
        seconds % 60
    )
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
        let idle = AtomicBool::new(false);
        let big = running(scan::MAX_HOSTS + 1);
        let (complete, errors) = drive(&big, false, false, &idle, &mut |h| {
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
        // The progress line (stderr) changes nothing about what is kept.
        drive(&running(3), false, true, &idle, &mut |_| {
            all += 1;
            Ok(())
        });
        assert_eq!(all, 3);
        // A sink that fails (disk full) cancels the scan and marks it partial.
        let run = running(scan::MAX_HOSTS + 1);
        let (complete, errors) = drive(&run, false, false, &idle, &mut |_| Err("disk full".into()));
        assert!(!complete && errors == ["disk full"], "{errors:?}");
        assert!(run.cancel.load(Ordering::Relaxed));
    }

    #[test]
    fn the_progress_of_a_plain_scan_reads_as_counts_and_time() {
        let at = Duration::from_secs;
        assert_eq!(
            progress_text(0, 254, 0, at(0)),
            "0/254 hosts done, 0 responded, 0:00 elapsed"
        );
        assert_eq!(
            progress_text(12, 254, 3, at(42)),
            "12/254 hosts done, 3 responded, 0:42 elapsed"
        );
        assert_eq!(
            progress_text(254, 254, 12, at(331)),
            "254/254 hosts done, 12 responded, 5:31 elapsed"
        );
        // Nothing to divide by: an empty scan is a line too.
        assert_eq!(
            progress_text(0, 0, 0, at(3600)),
            "0/0 hosts done, 0 responded, 60:00 elapsed"
        );
        // The line is rewritten in place without padding, so it must never get shorter.
        let mut width = 0;
        for (done, seconds) in [(0, 0), (9, 59), (10, 60), (100, 599), (254, 600)] {
            let line = progress_text(done, 254, done / 10, at(seconds));
            assert!(line.len() >= width, "{line}");
            width = line.len();
        }
        assert_eq!(
            start_text(254, 6, true),
            "Scanning 254 addresses, 6 TCP ports, Safe Mode on"
        );
        assert_eq!(
            start_text(1, 1, false),
            "Scanning 1 address, 1 TCP port, Safe Mode off"
        );
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

    /// Targets from a list file (alone or after the command line's), a repeat scan based on the
    /// last one, and the options that are refused before anything is sent.
    #[test]
    fn targets_files_incremental_repeats_and_refused_options() {
        let (_listener, port) = http_listener();
        let dir = std::env::temp_dir().join(format!("ns-scan-incr-cli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("i.sqlite");
        let (list, out) = (dir.join("targets.txt"), dir.join("o.csv"));
        std::fs::write(&list, "# lab\n127.0.0.1\n").unwrap();
        let scan = |extra: &[&str]| {
            let mut a = vec![
                "scan",
                "--scope",
                "127.0.0.0/8",
                "--tcp-only",
                "--fast",
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
        let l = list.to_str().unwrap();
        let e = scan(&["127.0.0.1", "--format", "pdf"]).unwrap_err();
        assert_eq!(e, "Choose json, csv, html, nmap, md, jsonl or cyclonedx");
        let e = scan(&["127.0.0.1", "--stream", "--tui"]).unwrap_err();
        assert!(e.contains("choose one"), "{e}");
        assert!(store::list(&db).unwrap().is_empty(), "nothing was saved");

        // The first incremental scan has no base and runs in full.
        for _ in 0..2 {
            let status = scan(&["--targets-file", l, "--incremental", "--format", "csv"]).unwrap();
            assert_eq!(status, crate::ui::ExitCode::Success);
            let csv = std::fs::read_to_string(&out).unwrap();
            assert!(
                csv.lines()
                    .any(|r| r.starts_with("\"127.0.0.1\"") && r.contains(&format!("\"{port}\""))),
                "{csv}"
            );
        }
        let saved = store::list(&db).unwrap();
        assert_eq!(saved.len(), 2);
        assert!(saved.iter().all(|e| e.targets == "127.0.0.1" && e.complete));
        // The second scan was based on the first, and only that one.
        let based = |id: i64| {
            let s = store::load(&db, id).unwrap();
            s.hosts[0].identity.get("incr.base").cloned()
        };
        assert_eq!(based(saved[1].id), None);
        assert_eq!(based(saved[0].id), Some(format!("scan #{}", saved[1].id)));

        // Command-line targets come first, then the file's.
        std::fs::write(&list, "127.0.0.2\n").unwrap();
        scan(&["127.0.0.1", "--targets-file", l]).unwrap();
        assert_eq!(store::list(&db).unwrap()[0].targets, "127.0.0.1 127.0.0.2");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
