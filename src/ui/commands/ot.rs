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

pub(super) fn listen(ctx: &mut Ctx) -> Result<(), String> {
    let opts = &ctx.opts;
    let mut tracker = crate::otpassive::Tracker::new();
    tracker.set_reassembly(!opts.contains_key("no-reassembly"));
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
    ot_assets_output(&snapshot, opts)
}
fn ot_assets_output(
    snapshot: &store::Snapshot,
    opts: &BTreeMap<String, String>,
) -> Result<(), String> {
    let assets = crate::otpassive::assets(&snapshot.observations);
    match opts.get("format").map(String::as_str).unwrap_or("json") {
        "json" => output(
            &serde_json::to_string_pretty(&assets).map_err(|e| e.to_string())?,
            opts,
        ),
        "csv" => output(&crate::otpassive::assets_csv(&assets), opts),
        _ => Err("Choose json or csv".into()),
    }
}
