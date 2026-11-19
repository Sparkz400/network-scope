//! `feeds import [--kev FILE] [--epss FILE]` and `feeds status`; `--feeds FILE` picks the cache.
use crate::ui::{Ctx, output};
use std::path::PathBuf;

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    let (pos, opts) = (&ctx.pos, &ctx.opts);
    let cache = opts
        .get("feeds")
        .map(PathBuf::from)
        .or_else(crate::feeds::default_path)
        .ok_or("No default location for the feeds cache; use --feeds FILE")?;
    match pos.first().map(String::as_str) {
        Some("import") => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let report = crate::feeds::import(
                opts.get("kev").map(std::path::Path::new),
                opts.get("epss").map(std::path::Path::new),
                &cache,
                now,
            )?;
            output(&report.lines().join("\n"), opts)
        }
        Some("status") => {
            let feeds = if cache.exists() {
                crate::feeds::Feeds::load(&cache)?
            } else {
                crate::feeds::Feeds::default()
            };
            output(
                &serde_json::to_string_pretty(&crate::feeds::status(&feeds, &cache))
                    .map_err(|e| e.to_string())?,
                opts,
            )
        }
        _ => Err("Use: feeds import [--kev FILE] [--epss FILE] | feeds status".into()),
    }
}

#[cfg(test)]
mod tests {
    use crate::ui::{run, testutil::args};

    #[test]
    fn feeds_import_and_status_commands() {
        let dir = std::env::temp_dir().join(format!("ns-feeds-cli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cache = dir.join("feeds.json");
        let out = dir.join("out.txt");
        let (kev, epss) = (dir.join("kev.json"), dir.join("epss.csv"));
        std::fs::write(&kev, include_str!("../../../tests/fixtures/kev.json")).unwrap();
        std::fs::write(&epss, include_str!("../../../tests/fixtures/epss.csv")).unwrap();
        let path = |p: &std::path::Path| p.to_str().unwrap().to_string();
        let mut import = args(&["feeds", "import", "--kev", &path(&kev)]);
        import.extend(args(&["--epss", &path(&epss), "--feeds", &path(&cache)]));
        import.extend(args(&["--output", &path(&out)]));
        run(&import).unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(text.contains("KEV: 4"), "{text}");
        assert!(text.contains("EPSS: 4"), "{text}");
        run(&args(&[
            "feeds",
            "status",
            "--feeds",
            &path(&cache),
            "--output",
            &path(&out),
        ]))
        .unwrap();
        let status: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(status["kev"]["entries"], 4);
        assert_eq!(status["epss"]["model_version"], "v2025.03.14");
        // Errors: no files, unknown subcommand, a gzip file, an unknown --sort value.
        assert!(
            run(&args(&["feeds", "import", "--feeds", &path(&cache)]))
                .unwrap_err()
                .contains("--kev")
        );
        assert!(run(&args(&["feeds", "--feeds", &path(&cache)])).is_err());
        std::fs::write(&epss, [0x1f, 0x8b, 8, 0]).unwrap();
        let e = run(&args(&[
            "feeds",
            "import",
            "--epss",
            &path(&epss),
            "--feeds",
            &path(&cache),
        ]))
        .unwrap_err();
        assert!(e.contains("gunzip"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
