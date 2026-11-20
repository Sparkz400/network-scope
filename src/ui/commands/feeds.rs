//! `feeds import [--kev FILE] [--epss FILE]`, `feeds import nvd FILE...` and `feeds status`;
//! `--feeds FILE` picks the KEV/EPSS cache and `--nvd FILE` the NVD cache.
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
        Some("import") if pos.get(1).map(String::as_str) == Some("nvd") => {
            let nvd_cache = opts
                .get("nvd")
                .map(PathBuf::from)
                .or_else(crate::nvd::default_path)
                .ok_or("No default location for the NVD cache; use --nvd FILE")?;
            let files: Vec<PathBuf> = pos[2..].iter().map(PathBuf::from).collect();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let report = crate::nvd::import(&files, &nvd_cache, now)?;
            output(&report.lines().join("\n"), opts)
        }
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
            let mut status = crate::feeds::status(&feeds, &cache);
            if let Some(path) = opts
                .get("nvd")
                .map(PathBuf::from)
                .or_else(crate::nvd::default_path)
                .filter(|p| p.exists())
            {
                status["nvd"] = crate::nvd::status(&crate::nvd::Nvd::load(&path)?, &path);
            }
            output(
                &serde_json::to_string_pretty(&status).map_err(|e| e.to_string())?,
                opts,
            )
        }
        _ => Err("Use: feeds import [--kev FILE] [--epss FILE] | feeds import nvd FILE... | feeds status".into()),
    }
}

#[cfg(test)]
mod tests {
    use crate::ui::{run, testutil::args};

    #[test]
    fn feeds_import_nvd_command_imports_files_and_reports_status() {
        let dir = std::env::temp_dir().join(format!("ns-nvd-cli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (nvd, feeds, out) = (
            dir.join("nvd.json"),
            dir.join("feeds.json"),
            dir.join("out.txt"),
        );
        let file = dir.join("nvdcve-2.0-sample.json");
        std::fs::write(
            &file,
            include_str!("../../../tests/fixtures/nvd-sample.json"),
        )
        .unwrap();
        let path = |p: &std::path::Path| p.to_str().unwrap().to_string();
        run(&args(&[
            "feeds",
            "import",
            "nvd",
            &path(&file),
            "--nvd",
            &path(&nvd),
            "--output",
            &path(&out),
        ]))
        .unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(text.contains("5 CVEs in the cache"), "{text}");
        run(&args(&[
            "feeds",
            "status",
            "--feeds",
            &path(&feeds),
            "--nvd",
            &path(&nvd),
            "--output",
            &path(&out),
        ]))
        .unwrap();
        let status: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(status["nvd"]["cves"], 5);
        assert_eq!(status["nvd"]["sources"][0], "nvdcve-2.0-sample.json");
        // No file, a gzip file and a missing file are errors that say what to do.
        assert!(run(&args(&["feeds", "import", "nvd", "--nvd", &path(&nvd)])).is_err());
        let gz = dir.join("feed.json.gz");
        std::fs::write(&gz, [0x1f, 0x8b, 8, 0]).unwrap();
        let e = run(&args(&[
            "feeds",
            "import",
            "nvd",
            &path(&gz),
            "--nvd",
            &path(&nvd),
        ]))
        .unwrap_err();
        assert!(e.contains("unpack it first"), "{e}");
        assert!(
            run(&args(&[
                "feeds",
                "import",
                "nvd",
                &path(&dir.join("none.json")),
                "--nvd",
                &path(&nvd)
            ]))
            .is_err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

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
