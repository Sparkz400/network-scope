//! `scan TARGETS [options]`: an active scan, saved to the inventory and printed in the chosen
//! format; with `--tui` the live terminal view (`ui::tui`) runs while it works.
use crate::{
    scan, store,
    ui::{Ctx, args::scan_settings, output, progress, saved_exit, tui},
};
use std::{collections::BTreeMap, sync::atomic::Ordering};

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    let (opts, pos, db) = (&ctx.opts, &ctx.pos, &ctx.db);
    let targets = pos.join(" ");
    let s = scan_settings(opts)?;
    let format = opts.get("format").map(String::as_str).unwrap_or("json");
    if !["json", "csv", "html", "nmap", "md", "jsonl"].contains(&format) {
        return Err("Choose json, csv, html, nmap, md or jsonl".into());
    }
    let hosts = scan::parse_targets(&targets, s.skip_edges, scan::MAX_STREAM)?;
    let ports = scan::parse_ports(&s.ports)?;
    let total = hosts.count() as usize;
    let run = scan::start_stream(Box::new(hosts.iter()), total, ports, s.clone());
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
        settings: s,
        hosts: results,
        observations: vec![],
        notes: BTreeMap::new(),
    };
    let id = store::save(db, &snapshot)?;
    progress(
        opts,
        format_args!(
            "Saved scan #{id} ({})",
            if complete { "complete" } else { "partial" }
        ),
    );
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
