// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! `ot-listen` (passive OT capture from an interface or a pcap file, saved as a scan) and
//! `ot-assets ID` (the OT asset inventory of a saved capture).
use crate::{
    scan, store,
    ui::{Ctx, args::number, output, progress},
};
use std::collections::BTreeMap;

pub(super) fn assets(ctx: &mut Ctx) -> Result<(), String> {
    ot_assets_output(&ctx.scan(0)?, &ctx.opts)
}

/// The model file `--model FILE` names, or `ot-model.json` next to the inventory database.
fn model_path(ctx: &Ctx) -> std::path::PathBuf {
    ctx.opts
        .get("model")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            ctx.db
                .parent()
                .map_or_else(std::path::PathBuf::new, std::path::Path::to_path_buf)
                .join("ot-model.json")
        })
}

/// `ot-learn`: learns the normal industrial traffic of a capture file or a live capture and
/// saves the model.
pub(super) fn learn(ctx: &mut Ctx) -> Result<(), String> {
    let opts = &ctx.opts;
    let reassembly = !opts.contains_key("no-reassembly");
    let model = if let Some(path) = opts.get("pcap") {
        crate::otmodel::learn_pcap(path, reassembly)?
    } else {
        let interface = opts.get("interface").ok_or(
            "Provide --pcap FILE or --interface (see the interfaces command) with --seconds",
        )?;
        let seconds: u64 = number(opts, "seconds", 3600)?;
        if !(1..=604_800).contains(&seconds) {
            return Err("Seconds must be 1-604800".into());
        }
        progress(
            opts,
            format_args!(
                "Learning passively on {interface} for {seconds} s. Nothing is transmitted."
            ),
        );
        crate::otmodel::learn_live(interface, seconds)?
    };
    if model.events == 0 {
        return Err("No industrial traffic in the capture; no model was written".into());
    }
    let path = model_path(ctx);
    model.save(&path)?;
    progress(
        &ctx.opts,
        format_args!("Model written to {}", path.display()),
    );
    output(&model.summary().join("\n"), &ctx.opts)
}

pub(super) fn listen(ctx: &mut Ctx) -> Result<(), String> {
    let opts = &ctx.opts.clone();
    // `--preset plant` is what this command is; the active presets belong to `scan`.
    if let Some(name) = opts.get("preset")
        && crate::presets::Preset::parse(name)? != crate::presets::Preset::Plant
    {
        return Err(format!(
            "ot-listen is passive: use --preset plant (or none); {name} is a scan preset"
        ));
    }
    let mut tracker = crate::otpassive::Tracker::new();
    tracker.set_reassembly(!opts.contains_key("no-reassembly"));
    // With --model the same pass also checks the traffic against what was learned.
    let checker = match opts.get("model") {
        Some(file) => {
            let model = crate::otmodel::Model::load(std::path::Path::new(file))?;
            let window = opts
                .get("maintenance")
                .map(|w| crate::otmodel::Maintenance::parse(w))
                .transpose()?;
            let source = opts
                .get("pcap")
                .or_else(|| opts.get("interface"))
                .map_or("", String::as_str);
            let checker = crate::otmodel::Checker::new(source, &model, window);
            tracker.set_event_sink(checker.sink());
            Some(checker)
        }
        None if opts.contains_key("maintenance") => {
            return Err("--maintenance needs --model FILE (from ot-learn)".into());
        }
        None => None,
    };
    let label = if let Some(path) = opts.get("pcap") {
        if opts.contains_key("progress") && !opts.contains_key("quiet") {
            crate::otpassive::read_pcap_file_with_progress(path, &mut tracker, None, &mut |p| {
                eprint!("\r{}{}", p.line(), if p.done { "\n" } else { "   " });
            })?;
        } else {
            crate::otpassive::read_pcap_file(path, &mut tracker)?;
        }
        format!("ot-passive:{path}")
    } else {
        let interface = opts
            .get("interface")
            .ok_or("Provide --interface (see the interfaces command) or --pcap FILE")?;
        let seconds: u64 = number(opts, "seconds", 300)?;
        if !(1..=604_800).contains(&seconds) {
            return Err("Seconds must be 1-604800".into());
        }
        progress(
            opts,
            format_args!(
                "Listening passively on {interface} for {seconds} s. Nothing is transmitted."
            ),
        );
        let cancel = std::sync::atomic::AtomicBool::new(false);
        crate::otpassive::listen_live(interface, seconds, &cancel, &mut tracker)?;
        format!("ot-passive:{interface}")
    };
    let snapshot = store::Snapshot {
        sent: vec![],
        targets: label,
        complete: true,
        settings: scan::Settings::default(),
        hosts: vec![],
        observations: tracker.observations(),
        notes: BTreeMap::new(),
    };
    let scan_id = store::save(&ctx.db, &snapshot)?;
    let (reassembled, abandoned) = tracker.reassembly_stats();
    progress(
        opts,
        format_args!(
            "Saved passive OT capture #{scan_id}: {} frames, {} observations{}",
            tracker.frames,
            snapshot.observations.len(),
            if reassembled + abandoned > 0 {
                format!(", {reassembled} messages reassembled, {abandoned} partial messages")
            } else {
                String::new()
            }
        ),
    );
    if let Some(checker) = checker {
        let report = checker.finish()?;
        let alerts = report.alerts.len();
        match opts.get("format").map(String::as_str).unwrap_or("json") {
            "json" => output(&crate::schema::object("ot-alerts", &report)?, opts)?,
            "text" => output(&report.lines().join("\n"), opts)?,
            _ => return Err("Choose json or text".into()),
        }
        ctx.status = crate::ui::findings_exit(ctx.fail_on_findings(), alerts);
        return Ok(());
    }
    ot_assets_output(&snapshot, opts)
}
fn ot_assets_output(
    snapshot: &store::Snapshot,
    opts: &BTreeMap<String, String>,
) -> Result<(), String> {
    let assets = crate::otpassive::assets(&snapshot.observations);
    match opts.get("format").map(String::as_str).unwrap_or("json") {
        "json" => output(&crate::schema::list("ot-assets", "assets", &assets)?, opts),
        "csv" => output(&crate::otpassive::assets_csv(&assets), opts),
        _ => Err("Choose json or csv".into()),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        store,
        ui::{ExitCode, run, testutil::args},
    };

    const CAPTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/ics/modbus_test_data_part1.pcap"
    );

    #[test]
    fn learn_listen_and_assets_from_a_capture_file() {
        let dir = std::env::temp_dir().join(format!("ns-ot-cli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("inventory.sqlite");
        let d = db.to_str().unwrap();
        let out = dir.join("out.txt");
        let o = out.to_str().unwrap();
        let ok = |v: &[&str]| {
            let mut v = v.to_vec();
            v.extend(["--db", d, "--quiet", "--output", o]);
            let status = run(&args(&v)).unwrap();
            (status, std::fs::read_to_string(&out).unwrap())
        };
        let err = |v: &[&str]| {
            let mut v = v.to_vec();
            v.extend(["--db", d, "--quiet"]);
            run(&args(&v)).unwrap_err()
        };

        // The model goes next to the inventory unless --model names a file.
        let (status, summary) = ok(&["ot-learn", "--pcap", CAPTURE]);
        assert_eq!(status, ExitCode::Success);
        assert!(
            summary.starts_with("Learned 20 messages to 2 devices"),
            "{summary}"
        );
        assert!(summary.contains("10.0.0.3: 2 clients"), "{summary}");
        let model = dir.join("ot-model.json");
        assert!(model.exists());
        let custom = dir.join("custom.json");
        let c = custom.to_str().unwrap();
        ok(&[
            "ot-learn",
            "--pcap",
            CAPTURE,
            "--model",
            c,
            "--no-reassembly",
        ]);
        assert!(custom.exists());
        // A capture without industrial traffic writes no model.
        let empty = dir.join("empty.pcap");
        let mut header = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
        header.extend([0; 8]);
        header.extend([0xff, 0xff, 0, 0, 1, 0, 0, 0]);
        std::fs::write(&empty, header).unwrap();
        let none = dir.join("none.json");
        let (e, n) = (empty.to_str().unwrap(), none.to_str().unwrap());
        let e = err(&["ot-learn", "--pcap", e, "--model", n]);
        assert!(e.contains("No industrial traffic"), "{e}");
        assert!(!none.exists());
        assert!(err(&["ot-learn"]).contains("Provide --pcap FILE or --interface"));
        for seconds in ["0", "604801"] {
            let e = err(&["ot-learn", "--interface", "x", "--seconds", seconds]);
            assert_eq!(e, "Seconds must be 1-604800");
            let e = err(&["ot-listen", "--interface", "x", "--seconds", seconds]);
            assert_eq!(e, "Seconds must be 1-604800");
        }

        // Checked against the model: the Stop-class functions of the capture are alerts unless
        // they fall in the maintenance window (the capture ran on a Thursday, 12:01-12:22 UTC).
        let m = model.to_str().unwrap();
        let (status, json) = ok(&["ot-listen", "--pcap", CAPTURE, "--model", m]);
        assert_eq!(
            status,
            ExitCode::Success,
            "findings change the status on request only"
        );
        let report: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(report["events"], 20);
        let alerts = report["alerts"].as_array().unwrap().len();
        assert!(alerts > 0, "{json}");
        let text = ["--format", "text", "--fail-on-findings"];
        let (status, out) =
            ok(&[&["ot-listen", "--pcap", CAPTURE, "--model", m], &text[..]].concat());
        assert_eq!(status, ExitCode::Findings);
        let first = format!("20 industrial messages checked, {alerts} alerts");
        assert!(out.starts_with(&first), "{out}");
        let window = ["--maintenance", "Thu 11:00-13:00"];
        let v = [
            &["ot-listen", "--pcap", CAPTURE, "--model", m],
            &text[..],
            &window[..],
        ]
        .concat();
        let (status, out) = ok(&v);
        assert_eq!(status, ExitCode::Success);
        assert_eq!(out.trim(), "20 industrial messages checked, 0 alerts");
        let e = err(&[
            "ot-listen",
            "--pcap",
            CAPTURE,
            "--model",
            m,
            "--format",
            "csv",
        ]);
        assert_eq!(e, "Choose json or text");
        let e = err(&[&["ot-listen", "--pcap", CAPTURE], &window[..]].concat());
        assert!(e.contains("--maintenance needs --model"), "{e}");
        let missing = dir.join("missing.json");
        let e = err(&[
            "ot-listen",
            "--pcap",
            CAPTURE,
            "--model",
            missing.to_str().unwrap(),
        ]);
        assert!(!e.is_empty());

        // Without a model: the capture is saved and its asset inventory printed.
        let e = err(&["ot-listen", "--pcap", CAPTURE, "--preset", "quick"]);
        assert!(e.contains("quick is a scan preset"), "{e}");
        assert!(err(&["ot-listen"]).contains("Provide --interface"));
        let (status, json) = ok(&["ot-listen", "--pcap", CAPTURE, "--preset", "plant"]);
        assert_eq!(status, ExitCode::Success);
        let assets: serde_json::Value = serde_json::from_str(&json).unwrap();
        let listed = assets["assets"].as_array().unwrap();
        assert!(
            listed.iter().any(|a| a.to_string().contains("10.0.0.3")),
            "{json}"
        );
        let id = store::list(&db).unwrap()[0].id.to_string();
        let (_, again) = ok(&["ot-assets", &id]);
        assert_eq!(again, json, "the saved capture gives the same inventory");
        let (_, csv) = ok(&["ot-assets", &id, "--format", "csv"]);
        assert!(
            csv.lines().count() > listed.len(),
            "a header and a row per asset: {csv}"
        );
        assert!(csv.contains("10.0.0.3"));
        assert_eq!(
            err(&["ot-assets", &id, "--format", "xml"]),
            "Choose json or csv"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
