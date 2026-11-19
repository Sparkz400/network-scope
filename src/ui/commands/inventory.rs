//! Commands on the saved inventory: `history`, `alerts` and `import` (an nmap XML scan).
use crate::{
    nmap, schema, store,
    ui::{Ctx, output, progress},
};

pub(super) fn history(ctx: &mut Ctx) -> Result<(), String> {
    output(
        &schema::list("scans", "scans", &store::list(&ctx.db)?)?,
        &ctx.opts,
    )
}

pub(super) fn alerts(ctx: &mut Ctx) -> Result<(), String> {
    output(
        &schema::list("alerts", "alerts", &store::list_alerts(&ctx.db, 500)?)?,
        &ctx.opts,
    )
}

pub(super) fn import(ctx: &mut Ctx) -> Result<(), String> {
    let path = ctx.pos.first().ok_or("Provide the nmap XML file")?;
    let size = std::fs::metadata(path)
        .map_err(|e| format!("{path}: {e}"))?
        .len();
    if size > nmap::MAX_IMPORT_BYTES as u64 {
        return Err("XML file is too large (limit 256 MB)".into());
    }
    let xml = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let snapshot = nmap::import(&xml)?;
    let scan_id = store::save(&ctx.db, &snapshot)?;
    progress(
        &ctx.opts,
        format_args!("Imported {} hosts as scan #{scan_id}", snapshot.hosts.len()),
    );
    Ok(())
}
