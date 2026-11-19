//! `scripts PATH`: checks Rhai scripts (they run with `scan --script PATH`).
use crate::ui::{Ctx, output};

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    let scripts =
        crate::script::Scripts::load(ctx.pos.first().ok_or("Provide a script file or folder")?)?;
    output(&scripts.describe().join("\n"), &ctx.opts)
}
