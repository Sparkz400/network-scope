//! `mcp [--db FILE] [--no-scan]`: the Model Context Protocol server (`core::mcp`) on stdin and
//! stdout. Only protocol messages are written to stdout; everything else goes to stderr.
use crate::{mcp, ui::Ctx};

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    if !ctx.pos.is_empty() {
        return Err("mcp takes no arguments (options: --db FILE, --no-scan)".into());
    }
    let cfg = mcp::Config {
        db: ctx.db.clone(),
        allow_scan: !ctx.opts.contains_key("no-scan"),
    };
    let stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    mcp::serve(cfg, stdin, &mut stdout).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use crate::ui::{run, testutil::args};

    #[test]
    fn the_command_takes_no_positional_arguments() {
        let err = run(&args(&["mcp", "10.0.0.0/24"])).unwrap_err();
        assert!(err.contains("no arguments"), "{err}");
    }
}
