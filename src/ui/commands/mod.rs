//! The commands, one file per command or small family of related commands. `ui::run` looks the
//! command word up in [`COMMANDS`] and calls its handler; see the module docs of `ui` for how to
//! add one.
mod baseline;
mod changes;
mod completions;
mod devices;
mod diff;
mod export;
mod feeds;
mod findings;
mod fingerprints;
mod inventory;
mod listen;
mod mcp;
mod monitor;
mod ot;
mod probes;
mod research;
pub(in crate::ui) mod scan;
mod scripts;
mod service;
#[cfg(windows)]
mod service_scm;
mod trace;
mod update;

use super::Ctx;

/// A command: reads what it needs from [`Ctx`] (positional arguments, options, database path),
/// writes its result with `ui::output` and may set `ctx.status`.
pub(super) type Handler = fn(&mut Ctx) -> Result<(), String>;

/// Every command word and its handler. The order is the order of the completion scripts. `help`
/// is not listed: `ui::run` answers it before any option is parsed (see [`names`]).
pub(super) const COMMANDS: &[(&str, Handler)] = &[
    ("feeds", feeds::run),
    ("scan", scan::run),
    ("listen", listen::run),
    ("dcp", listen::run),
    ("interfaces", listen::interfaces),
    ("history", inventory::history),
    ("diff", diff::run),
    ("baseline", baseline::run),
    ("changes", changes::run),
    ("export", export::export),
    ("report", export::report),
    ("import", inventory::import),
    ("findings", findings::run),
    ("monitor", monitor::run),
    ("alerts", inventory::alerts),
    ("scripts", scripts::run),
    ("service", service::run),
    ("mcp", mcp::run),
    ("ot-listen", ot::listen),
    ("ot-learn", ot::learn),
    ("ot-assets", ot::assets),
    ("devices", devices::devices),
    ("topology", devices::topology),
    ("trace", trace::run),
    ("probes", probes::run),
    ("fingerprints", fingerprints::run),
    ("research", research::run),
    ("update", update::run),
    ("completions", completions::run),
];

/// The handler of a command word.
pub(super) fn find(command: &str) -> Option<Handler> {
    COMMANDS
        .iter()
        .find(|(name, _)| *name == command)
        .map(|(_, handler)| *handler)
}

/// Every command word the program accepts, including `help`: what the completion scripts offer.
pub(super) fn names() -> Vec<&'static str> {
    COMMANDS
        .iter()
        .map(|(name, _)| *name)
        .chain(["help"])
        .collect()
}
