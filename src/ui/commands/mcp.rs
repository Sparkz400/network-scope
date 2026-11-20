//! `mcp [--db FILE] [--no-scan]`: the Model Context Protocol server (`core::mcp`) on stdin and
//! stdout. Only protocol messages are written to stdout; everything else goes to stderr.
//!
//! The `scan` tool runs the engine's scope guard without a prompt and without consent flags, so
//! it never scans public or out-of-scope addresses; `--scope`, `--scope-file` and the default
//! scope file declare the scope. `--yes-public` and `--allow-out-of-scope` are refused here.
use crate::{
    mcp,
    ui::{Ctx, guard},
};

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    if !ctx.pos.is_empty() {
        return Err("mcp takes no arguments (options: --db FILE, --no-scan, --scope CIDR, --scope-file FILE)".into());
    }
    if ctx.opts.contains_key("yes-public") || ctx.opts.contains_key("allow-out-of-scope") {
        return Err("mcp has no consent flags: its scan tool never scans public or out-of-scope addresses (declare the scope with --scope or --scope-file)".into());
    }
    let cfg = mcp::Config {
        db: ctx.db.clone(),
        allow_scan: !ctx.opts.contains_key("no-scan"),
        scope: guard::declared(&ctx.opts)?,
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
