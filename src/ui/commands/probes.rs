//! `probes [--probes FILE]`: lists and validates the TCP and UDP service probe database.
use crate::ui::{Ctx, output};

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    let opts = &ctx.opts;
    let db = crate::service::ProbeDb::load(opts.get("probes").map(String::as_str).unwrap_or(""))?;
    let mut text = format!(
        "{} TCP probes, {} UDP probes\n",
        db.probes.len(),
        db.udp.len()
    );
    let tagged = db
        .probes
        .iter()
        .map(|p| ("tcp", p))
        .chain(db.udp.iter().map(|p| ("udp", p)));
    for (proto, p) in tagged {
        text.push_str(&format!(
            "{proto} {:<12} ports {:<16} {} bytes sent, {} rules\n",
            p.name,
            if p.ports.is_empty() {
                "any (listen)".to_string()
            } else {
                p.ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            },
            p.payload.len(),
            p.rules.len()
        ));
    }
    output(text.trim_end(), opts)
}
