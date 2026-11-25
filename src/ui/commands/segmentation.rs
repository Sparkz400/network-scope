//! `segmentation check --zones FILE --from ZONE [SCAN_ID]` (ROADMAP L71): compares what a stored
//! scan could reach with the declared IEC 62443 zones and conduits and lists every path the model
//! does not allow. It reads the database and the zones file only and sends nothing.
use crate::{
    schema, segmentation, store,
    ui::{Ctx, findings_exit, output, progress},
};

const USAGE: &str = "Use: segmentation check --zones FILE [--from ZONE] [SCAN_ID] [--format text|json] [--fail-on-findings]";

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    match ctx.pos.first().map(String::as_str) {
        Some("check") => check(ctx),
        _ => Err(USAGE.into()),
    }
}

fn check(ctx: &mut Ctx) -> Result<(), String> {
    let (opts, db) = (&ctx.opts, &ctx.db);
    let file = opts
        .get("zones")
        .ok_or("Provide --zones FILE (zones with CIDR ranges and the allowed conduits)")?;
    let model = segmentation::ZoneModel::load(std::path::Path::new(file))?;
    let id = match ctx.pos.get(1) {
        Some(_) => ctx.id(1)?,
        None => store::latest_complete_id(db)?
            .ok_or("No completed scan in the database; run a scan from the zone to test first")?,
    };
    let snapshot = crate::ui::load_scan(db, id)?;
    // The scan does not record where it ran, except for the source address of a SYN or ARP scan.
    let vantage = match opts.get("from") {
        Some(zone) => zone.clone(),
        None => snapshot
            .settings
            .source_ip
            .parse()
            .ok()
            .and_then(|ip| model.zone_of(ip))
            .map(str::to_string)
            .ok_or(
                "Provide --from ZONE: the zone the scan was run from (the scan does not record it)",
            )?,
    };
    progress(
        opts,
        format_args!("Checking scan #{id} as seen from zone {vantage}. Nothing is sent."),
    );
    let report = segmentation::check(&model, &vantage, &snapshot, Some(id))?;
    match opts.get("format").map(String::as_str).unwrap_or("text") {
        "json" => output(&schema::object("segmentation-report", &report)?, opts)?,
        "text" => output(&report.text(), opts)?,
        _ => return Err("Choose text or json".into()),
    }
    ctx.status = findings_exit(ctx.fail_on_findings(), report.violations.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::ui::{ExitCode, run, testutil::args};

    const ZONES: &str =
        r#"{"zones":{"office":["10.0.0.0/24"],"plant":["10.0.2.0/24"]},"conduits":[]}"#;

    fn host(ip: &str, ports: &[u16]) -> crate::scan::Host {
        crate::scan::Host {
            ip: ip.parse().unwrap(),
            responding: true,
            ping: None,
            ttl: None,
            hostname: String::new(),
            mac: String::new(),
            open: ports.to_vec(),
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity: Default::default(),
            udp_open: vec![],
            trace: vec![],
        }
    }

    #[test]
    fn check_reports_paths_and_gates_with_fail_on_findings() {
        let dir = std::env::temp_dir().join(format!("ns-seg-cli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = |name: &str| dir.join(name).to_str().unwrap().to_string();
        let (db, zones, out) = (path("i.sqlite"), path("zones.json"), path("out.txt"));
        std::fs::write(&zones, ZONES).unwrap();
        let snapshot = crate::store::Snapshot {
            targets: "10.0.0.0/16".into(),
            complete: true,
            settings: crate::scan::Settings::default(),
            hosts: vec![host("10.0.2.10", &[502]), host("10.0.0.5", &[22])],
            observations: vec![],
            notes: Default::default(),
            sent: vec![],
        };
        crate::store::save(std::path::Path::new(&db), &snapshot).unwrap();
        let read = || std::fs::read_to_string(&out).unwrap();
        run(&args(&[
            "segmentation",
            "check",
            "--zones",
            &zones,
            "--from",
            "office",
            "--db",
            &db,
            "--output",
            &out,
            "--quiet",
        ]))
        .unwrap();
        assert!(read().contains("[HIGH] no-conduit"), "{}", read());
        assert!(read().contains("10.0.2.10"), "{}", read());
        let status = run(&args(&[
            "segmentation",
            "check",
            "1",
            "--zones",
            &zones,
            "--from",
            "office",
            "--format",
            "json",
            "--db",
            &db,
            "--output",
            &out,
            "--quiet",
            "--fail-on-findings",
        ]))
        .unwrap();
        assert_eq!(status, ExitCode::Findings);
        let json: serde_json::Value = serde_json::from_str(&read()).unwrap();
        assert_eq!(json["schema"], "network-scope/segmentation-report/v1");
        assert_eq!(json["violations"][0]["kind"], "no-conduit");
        // seen from the plant, the office host breaks the model instead
        run(&args(&[
            "segmentation",
            "check",
            "--zones",
            &zones,
            "--from",
            "plant",
            "--db",
            &db,
            "--output",
            &out,
            "--quiet",
        ]))
        .unwrap();
        assert!(
            read().contains("10.0.0.5") && !read().contains("[HIGH]"),
            "{}",
            read()
        );
        // errors say what is missing
        for bad in [
            vec!["segmentation", "check", "--from", "office", "--db", &db],
            vec!["segmentation", "check", "--zones", &zones, "--db", &db],
            vec![
                "segmentation",
                "check",
                "--zones",
                &zones,
                "--from",
                "moon",
                "--db",
                &db,
            ],
            vec![
                "segmentation",
                "check",
                "9",
                "--zones",
                &zones,
                "--from",
                "office",
                "--db",
                &db,
            ],
            vec![
                "segmentation",
                "check",
                "--zones",
                "missing.json",
                "--from",
                "office",
                "--db",
                &db,
            ],
            vec!["segmentation", "bogus"],
        ] {
            assert!(run(&args(&bad)).is_err(), "{bad:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
