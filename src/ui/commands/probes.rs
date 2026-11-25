// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! `probes [--probes FILE]` lists the TCP and UDP service probe database; `probes validate FILE`
//! loads a probe file the way a scan would and lints it; `probes lint [FILE]` runs only the safety
//! linter (on `data/probes.json` when no file is given). Nothing is sent to the network.
use crate::ui::{Ctx, output};

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    match ctx.pos.first().map(String::as_str) {
        None => list(ctx),
        Some("validate") => validate(ctx),
        Some("lint") => lint(ctx),
        Some(other) => Err(format!(
            "Unknown probes subcommand {other}. Use: probes [--probes FILE] | probes validate FILE | probes lint [FILE]"
        )),
    }
}

fn list(ctx: &mut Ctx) -> Result<(), String> {
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

/// The lint report as text; `Err` carries the same text when there is an error-level issue, so
/// the exit status is 1 and the issues are still printed.
fn lint_report(json: &str, origin: &str, summary: &str) -> Result<String, String> {
    let issues = crate::service::lint_probes(json).map_err(|e| format!("{origin}: {e}"))?;
    let errors = crate::service::lint_error_count(&issues);
    let mut text = String::new();
    for issue in &issues {
        text.push_str(&format!("{issue}\n"));
    }
    let sep = if summary.is_empty() { "" } else { "; " };
    text.push_str(&format!(
        "{origin}: {summary}{sep}{errors} error(s), {} warning(s)",
        issues.len() - errors
    ));
    if errors > 0 { Err(text) } else { Ok(text) }
}

fn validate(ctx: &mut Ctx) -> Result<(), String> {
    let file = ctx.pos.get(1).ok_or("Use: probes validate FILE")?;
    // The scanner's own loader: a file that fails here would fail a scan with --probes.
    let db = crate::service::ProbeDb::with_user_file(std::path::Path::new(file))?;
    let json = std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
    let summary = format!(
        "loads; with the built-in probes {} TCP and {} UDP probes",
        db.probes.len(),
        db.udp.len()
    );
    output(&lint_report(&json, file, &summary)?, &ctx.opts)
}

fn lint(ctx: &mut Ctx) -> Result<(), String> {
    let (json, origin) = match ctx.pos.get(1) {
        Some(file) => (
            std::fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?,
            file.as_str(),
        ),
        None => (
            crate::service::ProbeDb::builtin_json().to_string(),
            "built-in probes",
        ),
    };
    output(&lint_report(&json, origin, "")?, &ctx.opts)
}

#[cfg(test)]
mod tests {
    use crate::ui::{run, testutil::args};

    fn dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("ns-probes-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn lint_passes_the_builtin_probes_and_validate_checks_a_user_file() {
        let dir = dir("ok");
        let out = dir.join("out.txt");
        let path = |p: &std::path::Path| p.to_str().unwrap().to_string();
        run(&args(&["probes", "lint", "--output", &path(&out)])).unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(text.contains("0 error(s), 0 warning(s)"), "{text}");
        let good = dir.join("good.json");
        std::fs::write(
            &good,
            r#"{"probes":[{"name":"lab","ports":[7777],"send":"PING\n","rules":[{"re":"^PONG ([\\d.]+)","service":"labd","version":"$1"}]}]}"#,
        )
        .unwrap();
        run(&args(&[
            "probes",
            "validate",
            &path(&good),
            "--output",
            &path(&out),
        ]))
        .unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(text.contains("loads; with the built-in probes"), "{text}");
        assert!(text.contains("0 error(s)"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unsafe_and_broken_probe_files_fail_with_the_reasons() {
        let dir = dir("bad");
        let path = |p: &std::path::Path| p.to_str().unwrap().to_string();
        let unsafe_file = dir.join("unsafe.json");
        std::fs::write(
            &unsafe_file,
            r#"{"probes":[
              {"name":"plc","ports":[502],"send":"hello","rules":[]},
              {"name":"w","ports":[7777],"send":"FLUSHALL\r\n","rules":[{"re":"(a+)+","service":"x"}]}]}"#,
        )
        .unwrap();
        for command in ["lint", "validate"] {
            let e = run(&args(&["probes", command, &path(&unsafe_file)])).unwrap_err();
            for want in [
                "[ot-port]",
                "[write-payload]",
                "[regex-nested-quantifier]",
                "3 error(s)",
            ] {
                assert!(e.contains(want), "{command}: {e}");
            }
        }
        // A file the scanner cannot load at all: validate says so, lint reports the JSON error.
        let broken = dir.join("broken.json");
        std::fs::write(
            &broken,
            r#"{"probes":[{"name":"x","rules":[{"re":"(","service":"y"}]}]}"#,
        )
        .unwrap();
        assert!(
            run(&args(&["probes", "validate", &path(&broken)]))
                .unwrap_err()
                .contains("bad regex")
        );
        assert!(
            run(&args(&["probes", "lint", &path(&broken)]))
                .unwrap_err()
                .contains("[bad-regex]")
        );
        std::fs::write(&broken, "not json").unwrap();
        assert!(run(&args(&["probes", "lint", &path(&broken)])).is_err());
        assert!(
            run(&args(&["probes", "validate"]))
                .unwrap_err()
                .contains("FILE")
        );
        assert!(
            run(&args(&["probes", "check"]))
                .unwrap_err()
                .contains("Unknown probes subcommand")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
