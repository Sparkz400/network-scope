// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! `fingerprints export-unknown [SCAN_ID] [--output FILE]`: writes the banners of services that
//! nothing identified, taken from the local store, as JSON for a contribution (see
//! docs/src/contributing-fingerprints.md). Without a scan ID every stored scan is used. It reads
//! the local database only and never uploads anything; the file carries no addresses of hosts,
//! and the user reads and redacts it before sharing it.
use crate::{
    service::{unknown_banners, workbench},
    store,
    ui::{Ctx, output, progress},
};

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    match ctx.pos.first().map(String::as_str) {
        Some("export-unknown") => export_unknown(ctx),
        Some("favicon") => favicon(ctx),
        Some("groups") => groups(ctx),
        Some("compare") => compare(ctx),
        Some("draft") => draft(ctx),
        _ => Err("Use: fingerprints export-unknown [SCAN_ID] [--output FILE] | fingerprints groups [SCAN_ID] | fingerprints compare GROUP [SCAN_ID] | fingerprints draft GROUP [SCAN_ID] [--output FILE] | fingerprints favicon FILE".into()),
    }
}

/// The stored scans a workbench command looks at: the one named at `pos[index]`, else all.
fn workbench_snapshots(ctx: &Ctx, index: usize) -> Result<Vec<store::Snapshot>, String> {
    let ids: Vec<i64> = if ctx.pos.len() > index {
        vec![ctx.id(index)?]
    } else {
        store::list(&ctx.db)?.into_iter().map(|e| e.id).collect()
    };
    ids.iter()
        .map(|id| crate::ui::load_scan(&ctx.db, *id))
        .collect()
}

/// `fingerprints groups [SCAN_ID]`: the unidentified banners, grouped by similarity (the
/// workbench queue).
fn groups(ctx: &mut Ctx) -> Result<(), String> {
    let snapshots = workbench_snapshots(ctx, 1)?;
    let groups = workbench::groups(&snapshots);
    match ctx.opts.get("format").map(String::as_str).unwrap_or("text") {
        "json" => output(
            &crate::schema::list("banner-groups", "groups", &groups)?,
            &ctx.opts,
        ),
        "text" => output(&workbench::groups_text(&groups), &ctx.opts),
        _ => Err("Choose text or json".into()),
    }
}

/// `fingerprints compare GROUP [SCAN_ID]`: the variants of one group side by side, with what
/// differs between firmware versions.
fn compare(ctx: &mut Ctx) -> Result<(), String> {
    let id = ctx
        .pos
        .get(1)
        .ok_or("Use: fingerprints compare GROUP [SCAN_ID]")?;
    let snapshots = workbench_snapshots(ctx, 2)?;
    let groups = workbench::groups(&snapshots);
    let group = workbench::find(&groups, id)?;
    match ctx.opts.get("format").map(String::as_str).unwrap_or("text") {
        "json" => output(
            &crate::schema::list("banner-groups", "groups", &[group])?,
            &ctx.opts,
        ),
        "text" => output(&workbench::compare_text(group), &ctx.opts),
        _ => Err("Choose text or json".into()),
    }
}

/// `fingerprints draft GROUP [SCAN_ID] [--output FILE]`: a draft rule for `data/probes.json` as a
/// probe file that `probes validate` accepts, and the pull request checklist. With `--output FILE`
/// the probe file goes to FILE and the checklist to FILE.checklist.md. The banners were read from
/// the local store; the draft holds only their text (host data replaced), nothing is uploaded.
fn draft(ctx: &mut Ctx) -> Result<(), String> {
    let id = ctx
        .pos
        .get(1)
        .ok_or("Use: fingerprints draft GROUP [SCAN_ID] [--output FILE]")?;
    let snapshots = workbench_snapshots(ctx, 2)?;
    let groups = workbench::groups(&snapshots);
    let group = workbench::find(&groups, id)?;
    let draft = workbench::draft(group)?;
    if let Some(file) = ctx.opts.get("output") {
        let checklist = format!("{file}.checklist.md");
        std::fs::write(file, format!("{}\n", draft.probe_file))
            .map_err(|e| format!("{file}: {e}"))?;
        std::fs::write(&checklist, workbench::checklist_markdown(&draft, group))
            .map_err(|e| format!("{checklist}: {e}"))?;
        progress(
            &ctx.opts,
            format_args!(
                "Wrote {file} (check it with `probes validate {file}`) and {checklist}. Read both and remove anything that identifies a person, host or site; nothing was sent."
            ),
        );
        return Ok(());
    }
    match ctx.opts.get("format").map(String::as_str).unwrap_or("text") {
        "json" => output(
            &crate::schema::object("fingerprint-draft", &draft)?,
            &ctx.opts,
        ),
        "text" => {
            let mut out = vec![draft.probe_file.clone(), String::new()];
            out.extend(draft.notes.iter().map(|n| format!("Note: {n}")));
            out.push("Pull request checklist:".into());
            out.extend(draft.checklist.iter().map(|c| format!("  [ ] {c}")));
            output(&out.join("\n"), &ctx.opts)
        }
        _ => Err("Choose text or json".into()),
    }
}

/// `fingerprints favicon FILE`: the Shodan-compatible favicon hash of a local file. Reads the
/// file only; nothing is fetched or sent.
fn favicon(ctx: &mut Ctx) -> Result<(), String> {
    const MAX_FAVICON: u64 = 4 * 1024 * 1024;
    let file = ctx.pos.get(1).ok_or("Use: fingerprints favicon FILE")?;
    let size = std::fs::metadata(file)
        .map_err(|e| format!("{file}: {e}"))?
        .len();
    if size > MAX_FAVICON {
        return Err(format!("{file}: not a favicon (larger than 4 MB)"));
    }
    let data = std::fs::read(file).map_err(|e| format!("{file}: {e}"))?;
    let hash = crate::pivot::favicon_hash(&data);
    output(&format!("http.favicon.hash:{hash}"), &ctx.opts)
}

fn export_unknown(ctx: &mut Ctx) -> Result<(), String> {
    let ids: Vec<i64> = if ctx.pos.len() > 1 {
        vec![ctx.id(1)?]
    } else {
        store::list(&ctx.db)?.into_iter().map(|e| e.id).collect()
    };
    let snapshots = ids
        .iter()
        .map(|id| crate::ui::load_scan(&ctx.db, *id))
        .collect::<Result<Vec<_>, _>>()?;
    let export = unknown_banners(&snapshots);
    progress(
        &ctx.opts,
        format!(
            "{} unidentified banner(s) from {} scan(s). Read the file and remove anything that \
             identifies a person, host or organisation before you share it; nothing was sent.",
            export.entries.len(),
            snapshots.len()
        ),
    );
    output(
        &crate::schema::object("unknown-banners", &export)?,
        &ctx.opts,
    )
}

#[cfg(test)]
mod tests {
    use crate::{
        scan::Host,
        store,
        ui::{run, testutil::args},
    };

    #[test]
    fn export_unknown_writes_banners_from_the_store_without_host_data() {
        let dir = std::env::temp_dir().join(format!("ns-fp-cli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (db, out) = (dir.join("s.sqlite"), dir.join("unknown.json"));
        let path = |p: &std::path::Path| p.to_str().unwrap().to_string();
        let host = Host {
            ip: "10.9.8.7".parse().unwrap(),
            responding: true,
            ping: None,
            ttl: None,
            hostname: String::new(),
            mac: String::new(),
            open: vec![9999],
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity: [
                ("banner.9999".to_string(), "ACME-GW 2.1 ready".to_string()),
                ("svc.9999".to_string(), "unidentified".to_string()),
            ]
            .into(),
            udp_open: vec![],
            trace: vec![],
        };
        let snapshot = store::Snapshot {
            sent: vec![],
            targets: "10.9.8.0/24".into(),
            complete: true,
            settings: Default::default(),
            hosts: vec![host],
            observations: vec![],
            notes: Default::default(),
        };
        let id = store::save(&db, &snapshot).unwrap();
        for ids in [vec![], vec![id.to_string()]] {
            let mut a = vec!["fingerprints".to_string(), "export-unknown".to_string()];
            a.extend(ids);
            a.extend(args(&[
                "--db",
                &path(&db),
                "--output",
                &path(&out),
                "--quiet",
            ]));
            run(&a).unwrap();
            let text = std::fs::read_to_string(&out).unwrap();
            let json: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(json["format"], "network-scope-unknown-banners");
            assert_eq!(json["entries"][0]["port"], 9999);
            assert_eq!(json["entries"][0]["banner"], "ACME-GW 2.1 ready");
            assert!(!text.contains("10.9.8"), "{text}");
        }
        assert!(
            run(&args(&["fingerprints"]))
                .unwrap_err()
                .contains("export-unknown")
        );
        assert!(
            run(&args(&[
                "fingerprints",
                "export-unknown",
                "abc",
                "--db",
                &path(&db)
            ]))
            .is_err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn favicon_prints_the_shodan_hash_of_a_local_file() {
        let dir = std::env::temp_dir().join(format!("ns-favicon-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (icon, out) = (dir.join("favicon.ico"), dir.join("out.txt"));
        let path = |p: &std::path::Path| p.to_str().unwrap().to_string();
        std::fs::write(&icon, (0..=255u8).collect::<Vec<u8>>()).unwrap();
        run(&args(&[
            "fingerprints",
            "favicon",
            &path(&icon),
            "--output",
            &path(&out),
        ]))
        .unwrap();
        // the value of an independent Python implementation of mmh3.hash(base64 with newlines)
        assert_eq!(
            std::fs::read_to_string(&out).unwrap().trim(),
            "http.favicon.hash:-757223386"
        );
        assert!(run(&args(&["fingerprints", "favicon"])).is_err());
        assert!(
            run(&args(&[
                "fingerprints",
                "favicon",
                &path(&dir.join("none.ico"))
            ]))
            .is_err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// L73 end to end: group, compare, draft; the drafted file passes `probes validate` and
    /// `probes lint`, and the rule finds the service in a scan with it.
    #[test]
    fn the_workbench_turns_unknown_banners_into_a_valid_draft() {
        let dir = std::env::temp_dir().join(format!("ns-workbench-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = |name: &str| dir.join(name).to_str().unwrap().to_string();
        let (db, out, draft) = (path("s.sqlite"), path("out.txt"), path("draft.json"));
        let host = |ip: &str, banner: &str| {
            let mut h = crate::scan::Host {
                ip: ip.parse().unwrap(),
                responding: true,
                ping: None,
                ttl: None,
                hostname: String::new(),
                mac: String::new(),
                open: vec![9999],
                closed: 0,
                unanswered: 0,
                errors: vec![],
                ports_checked: true,
                identity: Default::default(),
                udp_open: vec![],
                trace: vec![],
            };
            h.identity.insert("banner.9999".into(), banner.into());
            h.identity.insert("svc.9999".into(), "unidentified".into());
            h
        };
        let snapshot = store::Snapshot {
            targets: "10.0.0.0/24".into(),
            complete: true,
            settings: crate::scan::Settings::default(),
            hosts: vec![
                host("10.0.0.1", "ACME-GW 2.1 ready"),
                host("10.0.0.2", "ACME-GW 2.1 ready"),
                host("10.0.0.3", "ACME-GW 3.0.4 ready"),
            ],
            observations: vec![],
            notes: Default::default(),
            sent: vec![],
        };
        store::save(std::path::Path::new(&db), &snapshot).unwrap();
        let read = || std::fs::read_to_string(&out).unwrap();
        run(&args(&[
            "fingerprints",
            "groups",
            "--db",
            &db,
            "--output",
            &out,
        ]))
        .unwrap();
        let line = read();
        assert!(
            line.contains("ACME-GW ‹v› ready") && line.contains("3 hosts"),
            "{line}"
        );
        let id = line.split_whitespace().next().unwrap().to_string();
        run(&args(&[
            "fingerprints",
            "groups",
            "--format",
            "json",
            "--db",
            &db,
            "--output",
            &out,
        ]))
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&read()).unwrap();
        assert_eq!(json["schema"], "network-scope/banner-groups/v1");
        assert_eq!(json["groups"][0]["id"], id.as_str());
        run(&args(&[
            "fingerprints",
            "compare",
            &id[..5],
            "--db",
            &db,
            "--output",
            &out,
        ]))
        .unwrap();
        assert!(read().contains("number 1 varies: 2.1, 3.0.4"), "{}", read());
        run(&args(&[
            "fingerprints",
            "draft",
            &id,
            "--format",
            "json",
            "--db",
            &db,
            "--output",
            &out,
        ]))
        .unwrap();
        // with --output the probe file is written (and the checklist next to it), whatever
        // --format says
        let text = read();
        assert!(text.contains("\"re\""), "{text}");
        run(&args(&[
            "fingerprints",
            "draft",
            &id,
            "--db",
            &db,
            "--output",
            &draft,
            "--quiet",
        ]))
        .unwrap();
        assert!(
            std::fs::read_to_string(format!("{draft}.checklist.md"))
                .unwrap()
                .contains("- [ ] ")
        );
        // the draft is a valid probe file
        run(&args(&["probes", "validate", &draft, "--output", &out])).unwrap();
        run(&args(&["probes", "lint", &draft, "--output", &out])).unwrap();
        // and bad arguments are errors that say what to do
        assert!(run(&args(&["fingerprints", "compare", "--db", &db])).is_err());
        assert!(run(&args(&["fingerprints", "compare", "zzzzzz", "--db", &db])).is_err());
        assert!(run(&args(&["fingerprints", "draft", "ab", "--db", &db])).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
