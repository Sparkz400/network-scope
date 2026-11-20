//! `scripts PATH` checks Rhai scripts (they run with `scan --script PATH`); `scripts list` shows
//! the shared library that is built into the program and `scripts show NAME` prints one.
use crate::{
    script,
    ui::{Ctx, output},
};

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    let first = ctx
        .pos
        .first()
        .ok_or("Provide a script file or folder, or `list`")?;
    match first.as_str() {
        "list" => output(&list(), &ctx.opts),
        "show" => {
            let name = ctx.pos.get(1).ok_or("Usage: scripts show NAME")?;
            let name = name.strip_prefix("library:").unwrap_or(name);
            let source = script::library_source(name)
                .ok_or_else(|| format!("No library script {name}; see `scripts list`"))?;
            output(source.trim_end(), &ctx.opts)
        }
        path => {
            let scripts = script::Scripts::load(path)?;
            output(&scripts.describe().join("\n"), &ctx.opts)
        }
    }
}

/// The library as text: name, what it does, what it is safe against, and how to use it.
fn list() -> String {
    let entries = script::library();
    let mut out = String::from(
        "Shared script library (built in). All scripts are read-only: they see scan results or an\nalert, make no network connections and no login attempts.\n",
    );
    for (kind, title) in [
        (
            "host",
            "Host scripts: scan TARGETS --script library:NAME (or --script library for all)",
        ),
        (
            "alert",
            "Alert scripts: monitor TARGETS --on-alert library:NAME",
        ),
    ] {
        out.push_str(&format!("\n{title}\n"));
        for e in entries.iter().filter(|e| e.kind == kind) {
            out.push_str(&format!(
                "  {:<26} {}\n  {:<26} safety: {}\n",
                e.name, e.description, "", e.safety
            ));
        }
    }
    out.push_str(
        "\n`scripts show NAME` prints a script to copy and edit; `scripts PATH` checks your own.",
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::{run, testutil::args};

    #[test]
    fn list_names_every_library_script_with_its_safety_note() {
        let text = list();
        for e in script::library() {
            assert!(
                text.contains(&e.name) && text.contains(&e.safety),
                "{}",
                e.name
            );
        }
        assert!(text.contains("library:NAME") && text.contains("--on-alert"));
    }

    #[test]
    fn show_and_check_work_for_library_scripts_and_reject_unknown_names() {
        let dir = std::env::temp_dir().join(format!("ns-scripts-cmd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("out.txt");
        let out_arg = out.to_str().unwrap();
        run(&args(&["scripts", "list", "--output", out_arg])).unwrap();
        assert!(
            std::fs::read_to_string(&out)
                .unwrap()
                .contains("smbv1-hosts")
        );
        run(&args(&[
            "scripts",
            "show",
            "smbv1-hosts",
            "--output",
            out_arg,
        ]))
        .unwrap();
        assert!(
            std::fs::read_to_string(&out)
                .unwrap()
                .contains("fn on_host")
        );
        run(&args(&[
            "scripts",
            "library:smbv1-hosts",
            "--output",
            out_arg,
        ]))
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(&out).unwrap().trim(),
            "smbv1-hosts.rhai: defines on_host"
        );
        run(&args(&["scripts", "library", "--output", out_arg])).unwrap();
        assert!(std::fs::read_to_string(&out).unwrap().lines().count() >= 8);
        assert!(run(&args(&["scripts", "show", "nope"])).is_err());
        assert!(run(&args(&["scripts", "library:nope"])).is_err());
        assert!(run(&args(&["scripts", "show"])).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
