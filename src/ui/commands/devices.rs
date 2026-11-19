//! `devices ID` (active and passive results merged, one record per device, with its stable key), `devices --history`
//! and `topology ID` (network path map from traceroute data).
use crate::{
    devices, store, topology,
    ui::{Ctx, output},
};

pub(super) fn devices(ctx: &mut Ctx) -> Result<(), String> {
    let (opts, db) = (&ctx.opts, &ctx.db);
    if let Some(q) = opts.get("history") {
        let h = store::device_history(db, q)?;
        return output(
            &devices::history_output(&h, opts.get("format").map(String::as_str).unwrap_or("text"))?,
            opts,
        );
    }
    let snapshot = store::load(db, ctx.id(0)?)?;
    let mut devices = devices::merge(&snapshot.hosts, &snapshot.observations);
    // The stable device key: what the inventory recognises the device as across scans.
    let matches = store::resolve_devices(db, &devices)?;
    for (d, m) in devices.iter_mut().zip(matches) {
        d.key = m.key;
    }
    match opts.get("format").map(String::as_str).unwrap_or("json") {
        "json" => output(
            &serde_json::to_string_pretty(&devices).map_err(|e| e.to_string())?,
            opts,
        ),
        "csv" => output(&devices::csv(&devices), opts),
        _ => Err("Choose json or csv".into()),
    }
}

pub(super) fn topology(ctx: &mut Ctx) -> Result<(), String> {
    let opts = &ctx.opts;
    let snapshot = store::load(&ctx.db, ctx.id(0)?)?;
    let graph = topology::build(&snapshot.hosts);
    match opts.get("format").map(String::as_str).unwrap_or("ascii") {
        "ascii" => output(topology::ascii(&graph).trim_end(), opts),
        "dot" => output(topology::dot(&graph).trim_end(), opts),
        _ => Err("Choose ascii or dot".into()),
    }
}
