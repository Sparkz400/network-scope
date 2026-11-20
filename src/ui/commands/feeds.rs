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
        Some("import") if pos.get(1).map(String::as_str) == Some("csaf") => {
            let csaf_cache = opts
                .get("csaf")
                .map(PathBuf::from)
                .or_else(crate::csaf::default_path)
                .ok_or("No default location for the CSAF cache; use --csaf FILE")?;
            let paths: Vec<PathBuf> = pos[2..].iter().map(PathBuf::from).collect();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let report = crate::csaf::import(&paths, &csaf_cache, now)?;
            output(&report.lines().join("\n"), opts)
        }
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
            if let Some(path) = opts
                .get("csaf")
                .map(PathBuf::from)
                .or_else(crate::csaf::default_path)
                .filter(|p| p.exists())
            {
                status["csaf"] = crate::csaf::status(&crate::csaf::Csaf::load(&path)?, &path);
            }
            output(
                &serde_json::to_string_pretty(&status).map_err(|e| e.to_string())?,
                opts,
            )
        }
        _ => Err("Use: feeds import [--kev FILE] [--epss FILE] | feeds import nvd FILE... | feeds import csaf FILE|DIR... | feeds status".into()),
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

    /// L68 end to end: advisories imported with `feeds import csaf`, then `findings` on a scan
    /// that identified an S7 CPU raises the advisory's CVE and says which advisory it is from.
    #[test]
    fn csaf_import_feeds_the_findings_of_an_s7_cpu() {
        let dir = std::env::temp_dir().join(format!("ns-csaf-cli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let advisories = dir.join("advisories");
        std::fs::create_dir_all(&advisories).unwrap();
        std::fs::write(
            advisories.join("icsa-test-0001.json"),
            include_str!("../../../tests/fixtures/csaf/icsa-test-0001-siemens-s7.json"),
        )
        .unwrap();
        let (cache, out, db) = (
            dir.join("csaf.json"),
            dir.join("out.txt"),
            dir.join("inventory.sqlite"),
        );
        let path = |p: &std::path::Path| p.to_str().unwrap().to_string();
        run(&args(&[
            "feeds",
            "import",
            "csaf",
            &path(&advisories),
            "--csaf",
            &path(&cache),
            "--output",
            &path(&out),
        ]))
        .unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(text.contains("1 advisories"), "{text}");
        let host = crate::scan::Host {
            ip: "10.0.0.10".parse().unwrap(),
            responding: true,
            ping: None,
            ttl: None,
            hostname: String::new(),
            mac: String::new(),
            open: vec![102],
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity: [
                ("S7.order_code", "6ES7 214-1AG40-0XB0"),
                ("S7.module", "CPU 1214C DC/DC/DC"),
                ("S7.firmware", "4.2.3"),
            ]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            udp_open: vec![],
            trace: vec![],
        };
        let snapshot = crate::store::Snapshot {
            targets: "10.0.0.10".into(),
            complete: true,
            settings: crate::scan::Settings::default(),
            hosts: vec![host],
            observations: vec![],
            notes: Default::default(),
            sent: vec![],
        };
        crate::store::save(&db, &snapshot).unwrap();
        let findings = |extra: &[&str]| -> String {
            let (db_path, out_path) = (path(&db), path(&out));
            let mut a = vec!["findings", "1", "--db", &db_path, "--output", &out_path];
            a.extend(extra);
            run(&args(&a)).unwrap();
            std::fs::read_to_string(&out).unwrap()
        };
        let with = findings(&["--csaf", &path(&cache)]);
        assert!(with.contains("cve-cve-2099-1001"), "{with}");
        assert!(with.contains("ICSA-TEST-0001"), "{with}");
        // a cache that does not exist is an error, not silence
        assert!(
            run(&args(&[
                "findings",
                "1",
                "--db",
                &path(&db),
                "--csaf",
                &path(&dir.join("missing.json")),
            ]))
            .is_err()
        );
        // a non-advisory file imports nothing and says so
        let junk = dir.join("junk.json");
        std::fs::write(&junk, "{}").unwrap();
        let e = run(&args(&[
            "feeds",
            "import",
            "csaf",
            &path(&junk),
            "--csaf",
            &path(&cache),
        ]))
        .unwrap_err();
        assert!(e.contains("No CSAF advisory"), "{e}");
        assert!(run(&args(&["feeds", "import", "csaf", "--csaf", &path(&cache)])).is_err());
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
