//! `listen` and `dcp` (passive capture of an interface, saved as a scan; `dcp` also sends one
//! read-only DCP Identify request) and `interfaces` (the capture interfaces).
use crate::{
    observations::{ObservationIndex, merge_indexed},
    passive, scan, schema, store,
    ui::{Ctx, args::number, dryrun, output, progress, saved_exit},
};
use std::{collections::BTreeMap, sync::atomic::Ordering};

pub(super) fn interfaces(ctx: &mut Ctx) -> Result<(), String> {
    output(
        &schema::list("interfaces", "interfaces", &crate::capture::interfaces()?)?,
        &ctx.opts,
    )
}

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    let (opts, command, db) = (&ctx.opts, &ctx.command, &ctx.db);
    if command == "dcp" && dryrun::requested(opts) {
        return dryrun::dcp_plan(opts);
    }
    let interface = opts
        .get("interface")
        .ok_or("Provide --interface from the interfaces command")?;
    let seconds: u64 = number(opts, "seconds", 60)?;
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
    let sent = std::sync::Arc::new(crate::sendlog::SentLog::new());
    let run = passive::start_logged(interface.clone(), seconds, source, sent.clone());
    let (observations, error) = drain_observations(&run.receiver);
    if error.is_some() {
        run.cancel.store(true, Ordering::Relaxed);
    }
    drop(run);
    if let (Some(e), true) = (&error, observations.is_empty()) {
        return Err(e.clone());
    }
    let snapshot = store::Snapshot {
        targets: format!("{command}:{interface}"),
        complete: error.is_none(),
        settings: scan::Settings::default(),
        hosts: vec![],
        observations,
        notes: BTreeMap::new(),
        sent: sent.snapshot(),
    };
    let id = store::save(db, &snapshot)?;
    progress(
        opts,
        format_args!(
            "Saved capture #{id} ({})",
            if error.is_none() {
                "complete"
            } else {
                "partial"
            }
        ),
    );
    output(
        &store::export_at(
            &snapshot,
            opts.get("format").map(String::as_str).unwrap_or("json"),
            store::timestamp(db, id)?,
        )?,
        opts,
    )?;
    if let Some(e) = &error {
        eprintln!("Capture #{id} saved as partial: {e}");
    }
    ctx.status = saved_exit(error.is_none());
    Ok(())
}
/// Collects a passive capture; on an error (capture failure or the observation cap) it stops and
/// returns everything gathered so far together with the error.
/// Collects a capture. Error items (a full capture queue, a read error, the observation cap)
/// are warnings: they are printed once each, mark the capture partial and collection goes on
/// with what still arrives, as in the GUI and `monitor`.
fn drain_observations(
    items: impl IntoIterator<Item = Result<passive::Observation, String>>,
) -> (Vec<passive::Observation>, Option<String>) {
    let mut observations = vec![];
    let mut index = ObservationIndex::default();
    let mut errors: Vec<String> = vec![];
    for item in items {
        if let Err(e) = item.and_then(|o| merge_indexed(&mut observations, &mut index, o))
            && !errors.contains(&e)
        {
            eprintln!("Warning: {e}");
            errors.push(e);
        }
    }
    (
        observations,
        (!errors.is_empty()).then(|| errors.join("; ")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{observations::MAX_OBSERVATIONS, ui::testutil::obs};

    #[test]
    fn capture_errors_keep_collected_observations() {
        let items = vec![
            Ok(obs("aa", "ARP", None, ("a", "1"))),
            Ok(obs("bb", "ARP", None, ("a", "1"))),
            Err("Capture queue full".to_string()),
            Ok(obs("cc", "ARP", None, ("a", "1"))),
        ];
        let (list, error) = drain_observations(items);
        assert_eq!(list.len(), 3, "observations after a warning are kept");
        assert_eq!(error.as_deref(), Some("Capture queue full"));
        let many =
            (0..MAX_OBSERVATIONS + 5).map(|i| Ok(obs(&format!("{i}"), "ARP", None, ("a", "1"))));
        let (list, error) = drain_observations(many);
        assert_eq!(list.len(), MAX_OBSERVATIONS);
        assert!(error.unwrap().contains("limit"));
        let (list, error) = drain_observations(vec![Ok(obs("aa", "ARP", None, ("a", "1")))]);
        assert_eq!((list.len(), error), (1, None));
    }
}
