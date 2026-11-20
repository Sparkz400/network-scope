//! `fingerprints export-unknown [SCAN_ID] [--output FILE]`: writes the banners of services that
//! nothing identified, taken from the local store, as JSON for a contribution (see
//! docs/src/contributing-fingerprints.md). Without a scan ID every stored scan is used. It reads
//! the local database only and never uploads anything; the file carries no addresses of hosts,
//! and the user reads and redacts it before sharing it.
use crate::{
    service::unknown_banners,
    store,
    ui::{Ctx, output, progress},
};

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    match ctx.pos.first().map(String::as_str) {
        Some("export-unknown") => export_unknown(ctx),
        Some("favicon") => favicon(ctx),
        _ => Err("Use: fingerprints export-unknown [SCAN_ID] [--output FILE] | fingerprints favicon FILE".into()),
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
        .map(|id| store::load(&ctx.db, *id))
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
}
