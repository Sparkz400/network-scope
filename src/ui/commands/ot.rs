//! `ot-listen` (passive OT capture from an interface or a pcap file, saved as a scan) and
//! `ot-assets ID` (the OT asset inventory of a saved capture).
use crate::{
    scan, store,
    ui::{Ctx, args::number, output, progress},
};
use std::collections::BTreeMap;

pub(super) fn assets(ctx: &mut Ctx) -> Result<(), String> {
    ot_assets_output(&store::load(&ctx.db, ctx.id(0)?)?, &ctx.opts)
}

/// The model file `--model FILE` names, or `ot-model.json` next to the inventory database.
fn model_path(ctx: &Ctx) -> std::path::PathBuf {
    ctx.opts
        .get("model")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            ctx.db
                .parent()
                .map_or_else(std::path::PathBuf::new, std::path::Path::to_path_buf)
                .join("ot-model.json")
        })
}

/// `ot-learn`: learns the normal industrial traffic of a capture file or a live capture and
/// saves the model.
pub(super) fn learn(ctx: &mut Ctx) -> Result<(), String> {
    let opts = &ctx.opts;
    let reassembly = !opts.contains_key("no-reassembly");
    let model = if let Some(path) = opts.get("pcap") {
        crate::otmodel::learn_pcap(path, reassembly)?
    } else {
        let interface = opts.get("interface").ok_or(
            "Provide --pcap FILE or --interface (see the interfaces command) with --seconds",
        )?;
        let seconds: u64 = number(opts, "seconds", 3600)?;
        if !(1..=604_800).contains(&seconds) {
            return Err("Seconds must be 1-604800".into());
        }
        progress(
            opts,
            format_args!(
                "Learning passively on {interface} for {seconds} s. Nothing is transmitted."
            ),
        );
        crate::otmodel::learn_live(interface, seconds)?
    };
    if model.events == 0 {
        return Err("No industrial traffic in the capture; no model was written".into());
    }
    let path = model_path(ctx);
    model.save(&path)?;
    progress(
        &ctx.opts,
        format_args!("Model written to {}", path.display()),
    );
    output(&model.summary().join("\n"), &ctx.opts)
}

pub(super) fn listen(ctx: &mut Ctx) -> Result<(), String> {
    let opts = &ctx.opts.clone();
    let mut tracker = crate::otpassive::Tracker::new();
    tracker.set_reassembly(!opts.contains_key("no-reassembly"));
    // With --model the same pass also checks the traffic against what was learned.
    let checker = match opts.get("model") {
        Some(file) => {
            let model = crate::otmodel::Model::load(std::path::Path::new(file))?;
            let window = opts
                .get("maintenance")
                .map(|w| crate::otmodel::Maintenance::parse(w))
                .transpose()?;
            let source = opts
                .get("pcap")
                .or_else(|| opts.get("interface"))
                .map_or("", String::as_str);
            let checker = crate::otmodel::Checker::new(source, &model, window);
            tracker.set_event_sink(checker.sink());
            Some(checker)
        }
        None if opts.contains_key("maintenance") => {
            return Err("--maintenance needs --model FILE (from ot-learn)".into());
        }
        None => None,
    };
    let label = if let Some(path) = opts.get("pcap") {
        if opts.contains_key("progress") && !opts.contains_key("quiet") {
            crate::otpassive::read_pcap_file_with_progress(path, &mut tracker, None, &mut |p| {
                eprint!("\r{}{}", p.line(), if p.done { "\n" } else { "   " });
            })?;
        } else {
            crate::otpassive::read_pcap_file(path, &mut tracker)?;
        }
        format!("ot-passive:{path}")
    } else {
        let interface = opts
            .get("interface")
            .ok_or("Provide --interface (see the interfaces command) or --pcap FILE")?;
        let seconds: u64 = number(opts, "seconds", 300)?;
        if !(1..=604_800).contains(&seconds) {
            return Err("Seconds must be 1-604800".into());
        }
        progress(
            opts,
            format_args!(
                "Listening passively on {interface} for {seconds} s. Nothing is transmitted."
            ),
        );
        let cancel = std::sync::atomic::AtomicBool::new(false);
        crate::otpassive::listen_live(interface, seconds, &cancel, &mut tracker)?;
        format!("ot-passive:{interface}")
    };
    let snapshot = store::Snapshot {
        sent: vec![],
        targets: label,
        complete: true,
        settings: scan::Settings::default(),
        hosts: vec![],
        observations: tracker.observations(),
        notes: BTreeMap::new(),
    };
    let scan_id = store::save(&ctx.db, &snapshot)?;
    let (reassembled, abandoned) = tracker.reassembly_stats();
    progress(
        opts,
        format_args!(
            "Saved passive OT capture #{scan_id}: {} frames, {} observations{}",
            tracker.frames,
            snapshot.observations.len(),
            if reassembled + abandoned > 0 {
                format!(", {reassembled} messages reassembled, {abandoned} partial messages")
            } else {
                String::new()
            }
        ),
    );
    if let Some(checker) = checker {
        let report = checker.finish()?;
        let alerts = report.alerts.len();
        match opts.get("format").map(String::as_str).unwrap_or("json") {
            "json" => output(&crate::schema::object("ot-alerts", &report)?, opts)?,
            "text" => output(&report.lines().join("\n"), opts)?,
            _ => return Err("Choose json or text".into()),
        }
        ctx.status = crate::ui::findings_exit(ctx.fail_on_findings(), alerts);
        return Ok(());
    }
    ot_assets_output(&snapshot, opts)
}
fn ot_assets_output(
    snapshot: &store::Snapshot,
    opts: &BTreeMap<String, String>,
) -> Result<(), String> {
    let assets = crate::otpassive::assets(&snapshot.observations);
    match opts.get("format").map(String::as_str).unwrap_or("json") {
        "json" => output(&crate::schema::list("ot-assets", "assets", &assets)?, opts),
        "csv" => output(&crate::otpassive::assets_csv(&assets), opts),
        _ => Err("Choose json or csv".into()),
    }
}
