//! `findings ID [--min-severity low] [--sort exploited|severity] [--fail-on-findings]`.
use crate::{
    risk, schema, store,
    ui::{Ctx, args::min_severity, findings_exit, output},
};

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    let opts = &ctx.opts;
    let snapshot = store::load(&ctx.db, ctx.id(0)?)?;
    let min = min_severity(opts)?;
    let mut list: Vec<_> = risk::analyze_snapshot(&snapshot)
        .into_iter()
        .filter(|f| f.severity >= min)
        .collect();
    // Imported feeds rank known exploited findings first; without them both orders match.
    match opts.get("sort").map(String::as_str).unwrap_or("exploited") {
        "exploited" => {}
        "severity" => crate::feeds::sort_by_severity(&mut list),
        _ => return Err("Sort must be exploited or severity".into()),
    }
    output(&schema::list("findings", "findings", &list)?, opts)?;
    ctx.status = findings_exit(ctx.fail_on_findings(), list.len());
    Ok(())
}
