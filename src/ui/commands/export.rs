//! `export ID --format ...` and `report ID`: a saved scan as JSON, CSV, HTML, nmap XML,
//! Markdown or JSON lines, optionally with a "changes since" section (`--baseline ID`).
use crate::{
    nmap, store,
    ui::{Ctx, output},
};
use std::collections::BTreeMap;

pub(super) fn export(ctx: &mut Ctx) -> Result<(), String> {
    let (opts, db) = (&ctx.opts, &ctx.db);
    let snapshot = store::load(db, ctx.id(0)?)?;
    let format = opts.get("format").map(String::as_str).unwrap_or("json");
    let stamp = store::timestamp(db, ctx.id(0)?)?;
    let text = match format {
        "html" => report_html(db, &snapshot, stamp, opts)?,
        "nmap" | "xml" => nmap::export(&snapshot, stamp),
        "md" | "markdown" => {
            let baseline = baseline(db, opts)?;
            crate::report::markdown(&snapshot, baseline.as_ref().map(|(s, t)| (s, *t)), stamp)
        }
        other => store::export_at(&snapshot, other, stamp)?,
    };
    output(&text, opts)
}

pub(super) fn report(ctx: &mut Ctx) -> Result<(), String> {
    let (opts, db) = (&ctx.opts, &ctx.db);
    let snapshot = store::load(db, ctx.id(0)?)?;
    let stamp = store::timestamp(db, ctx.id(0)?)?;
    output(&report_html(db, &snapshot, stamp, opts)?, opts)
}

/// The `--baseline ID` snapshot and its time, for reports with a "changes since" section.
fn baseline(
    db: &std::path::Path,
    opts: &BTreeMap<String, String>,
) -> Result<Option<(store::Snapshot, i64)>, String> {
    match opts.get("baseline") {
        Some(b) => {
            let b: i64 = b.parse().map_err(|_| "Invalid --baseline".to_string())?;
            Ok(Some((store::load(db, b)?, store::timestamp(db, b)?)))
        }
        None => Ok(None),
    }
}
fn report_html(
    db: &std::path::Path,
    snapshot: &store::Snapshot,
    stamp: i64,
    opts: &BTreeMap<String, String>,
) -> Result<String, String> {
    let baseline = baseline(db, opts)?;
    Ok(crate::report::html(
        snapshot,
        baseline.as_ref().map(|(s, t)| (s, *t)),
        stamp,
    ))
}
