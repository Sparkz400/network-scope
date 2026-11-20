//! Commands on the saved inventory: `history`, `alerts` and `import` (an nmap XML scan, or
//! `import KIND FILE...` for lists of known devices).
use crate::{
    baseline, import, nmap, schema, store,
    ui::{Ctx, output, progress},
};

pub(super) fn history(ctx: &mut Ctx) -> Result<(), String> {
    output(
        &schema::list("scans", "scans", &store::list(&ctx.db)?)?,
        &ctx.opts,
    )
}

pub(super) fn alerts(ctx: &mut Ctx) -> Result<(), String> {
    output(
        &schema::list("alerts", "alerts", &store::list_alerts(&ctx.db, 500)?)?,
        &ctx.opts,
    )
}

/// `import KIND FILE...`: known devices from a CSV, DHCP leases, Active Directory or NetBox,
/// merged into the inventory and the baseline (never saved as a scan).
fn import_known(ctx: &mut Ctx, kind: import::Kind) -> Result<(), String> {
    let paths = &ctx.pos[1..];
    if paths.is_empty() {
        return Err(format!("Provide the {} file", kind.name()));
    }
    let mut files = vec![];
    for path in paths {
        let size = std::fs::metadata(path)
            .map_err(|e| format!("{path}: {e}"))?
            .len();
        if size > import::MAX_FILE_BYTES as u64 {
            return Err(format!(
                "{path}: the file is too large (limit {} MB)",
                import::MAX_FILE_BYTES / 1024 / 1024
            ));
        }
        files.push(std::fs::read(path).map_err(|e| format!("{path}: {e}"))?);
    }
    let parsed = import::parse_files(kind, &files)?;
    let merged = import::merge(&ctx.db, &parsed, store::now())?;
    progress(
        &ctx.opts,
        format_args!(
            "Imported {} devices from {} ({} new, {} already known); {} entries skipped. No scan was saved.",
            merged.devices,
            kind.name(),
            merged.new,
            merged.known,
            parsed.skipped + merged.skipped
        ),
    );
    for note in &parsed.notes {
        progress(&ctx.opts, format_args!("  {note}"));
    }
    if !baseline::load(&ctx.db)?.exists() {
        progress(
            &ctx.opts,
            "The baseline is not active: run `baseline enable` (or `baseline approve` after a scan) to alert on unknown devices.",
        );
    }
    if ctx.opts.get("format").is_some_and(|f| f == "json") {
        let summary = serde_json::json!({
            "kind": kind.name(),
            "merged": merged,
            "skipped": parsed.skipped,
            "notes": parsed.notes,
        });
        return output(
            &crate::schema::object("import-summary", &summary)?,
            &ctx.opts,
        );
    }
    Ok(())
}

pub(super) fn import(ctx: &mut Ctx) -> Result<(), String> {
    if let Some(kind) = ctx.pos.first().and_then(|k| import::Kind::parse(k)) {
        return import_known(ctx, kind);
    }
    let path = ctx
        .pos
        .first()
        .ok_or("Provide the nmap XML file, or a kind (csv, isc-dhcp, dnsmasq, windows-dhcp, ad-csv, ad-ldif, netbox) and its file")?;
    let size = std::fs::metadata(path)
        .map_err(|e| format!("{path}: {e}"))?
        .len();
    if size > nmap::MAX_IMPORT_BYTES as u64 {
        return Err("XML file is too large (limit 256 MB)".into());
    }
    let xml = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let snapshot = nmap::import(&xml)?;
    let scan_id = store::save(&ctx.db, &snapshot)?;
    progress(
        &ctx.opts,
        format_args!("Imported {} hosts as scan #{scan_id}", snapshot.hosts.len()),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        baseline, store,
        ui::{ExitCode, run, testutil::args},
    };

    fn dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ns-import-cli-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn import_kind_file_merges_known_devices_and_never_saves_a_scan() {
        let d = dir("kinds");
        let db = d.join("inventory.sqlite");
        let db_arg = db.to_str().unwrap();
        let write = |name: &str, text: &str| {
            let p = d.join(name);
            std::fs::write(&p, text).unwrap();
            p.to_str().unwrap().to_string()
        };
        let csv = write(
            "list.csv",
            "mac,hostname,owner\naa:bb:cc:00:00:01,plc-1,Plant\n",
        );
        let leases = write("dnsmasq.leases", "0 aa:bb:cc:00:00:02 10.0.0.7 cam-1 *\n");
        let nb_devices = write(
            "devices.json",
            r#"{"results":[{"name":"sw-1","device_type":{},"status":{"value":"active"},"primary_ip4":{"address":"10.0.0.1/24"}}]}"#,
        );
        let nb_ips = write(
            "ips.json",
            r#"{"results":[{"address":"10.0.0.2/24","status":{"value":"active"},"assigned_object":{"device":{"name":"sw-1"}}}]}"#,
        );
        let ok = |a: &[&str]| {
            let mut v: Vec<&str> = a.to_vec();
            v.extend(["--db", db_arg, "--quiet"]);
            assert_eq!(run(&args(&v)).unwrap(), ExitCode::Success, "{a:?}");
        };
        let err = |a: &[&str]| {
            let mut v: Vec<&str> = a.to_vec();
            v.extend(["--db", db_arg, "--quiet"]);
            run(&args(&v)).unwrap_err()
        };
        ok(&["import", "csv", &csv]);
        ok(&["import", "dnsmasq", &leases]);
        ok(&["import", "netbox", &nb_devices, &nb_ips]);
        assert!(store::list(&db).unwrap().is_empty(), "never a scan result");
        let b = baseline::load(&db).unwrap();
        assert_eq!(b.entries.len(), 3, "{:?}", b.entries);
        assert!(!b.exists());
        let plc = b.entry("AA:BB:CC:00:00:01").unwrap();
        assert_eq!((plc.owner.as_str(), plc.expected), ("Plant", true));
        let sw = b.entries.iter().find(|e| e.label == "sw-1").unwrap();
        assert_eq!(sw.source, "import:netbox");
        // The imported list can start the baseline.
        ok(&["baseline", "enable"]);
        assert!(baseline::load(&db).unwrap().exists());
        // JSON summary.
        let out = d.join("summary.json");
        ok(&[
            "import",
            "csv",
            &csv,
            "--format",
            "json",
            "--output",
            out.to_str().unwrap(),
        ]);
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(json["merged"]["known"], 1);
        // Mistakes.
        assert!(err(&["import", "csv"]).contains("Provide the csv file"));
        assert!(err(&["import", "csv", d.join("nope.csv").to_str().unwrap()]).contains("nope.csv"));
        let bad = write("bad.csv", "foo,bar\n1,2\n");
        assert!(err(&["import", "csv", &bad]).contains("at least one of"));
        assert!(err(&["import", "isc-dhcp", &csv]).contains("Not a dhcpd.leases"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn import_of_an_nmap_file_still_saves_a_scan() {
        let d = dir("nmap");
        let db = d.join("inventory.sqlite");
        let xml = d.join("scan.xml");
        std::fs::write(
            &xml,
            r#"<nmaprun args="nmap 10.0.0.5"><host><status state="up"/><address addr="10.0.0.5" addrtype="ipv4"/><ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host></nmaprun>"#,
        )
        .unwrap();
        let v = [
            "import",
            xml.to_str().unwrap(),
            "--db",
            db.to_str().unwrap(),
            "--quiet",
        ];
        assert_eq!(run(&args(&v)).unwrap(), ExitCode::Success);
        assert_eq!(store::list(&db).unwrap().len(), 1);
        let none = run(&args(&["import", "--db", db.to_str().unwrap()])).unwrap_err();
        assert!(none.contains("nmap XML file"));
        let _ = std::fs::remove_dir_all(&d);
    }
}
