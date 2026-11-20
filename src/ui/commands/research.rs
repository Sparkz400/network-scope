//! `research query SQL`, `research schema`, `research rebuild` and `research export ...`
//! (ROADMAP L67): the research tables of the inventory database. None of
//! them sends a packet.
use crate::{
    research, schema, store,
    ui::{Ctx, args::number, output, progress},
};

const USAGE: &str = "Use: research query SQL [--top N] [--format json|csv|tsv] | research schema | research rebuild | research export csv|ndjson --output DIR | research export stix|ocsf [SCAN_ID] [--output FILE]";

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    let (pos, opts, db) = (&ctx.pos, &ctx.opts, &ctx.db);
    match pos.first().map(String::as_str) {
        Some("schema") => output(research::schema_text().trim_end(), opts),
        Some("rebuild") => {
            let report = research::rebuild(db)?;
            progress(
                opts,
                format_args!(
                    "Indexed {} scans ({} unreadable snapshots skipped)",
                    report.scans, report.skipped
                ),
            );
            output(&schema::object("research-rebuild", &report)?, opts)
        }
        Some("query") => {
            if pos.len() != 2 {
                return Err("Use: research query \"SELECT ...\" (one quoted statement)".into());
            }
            let limit: usize = number(opts, "top", 10_000)?;
            let result = research::query(db, &pos[1], limit)?;
            if result.truncated {
                progress(
                    opts,
                    format_args!("Output limited to {limit} rows (--top N)"),
                );
            }
            match opts.get("format").map(String::as_str).unwrap_or("json") {
                "json" => output(&schema::object("research-query", &result)?, opts),
                "csv" => output(&delimited(&result, ',', true), opts),
                "tsv" => output(&delimited(&result, '\t', false), opts),
                _ => Err("Choose json, csv or tsv".into()),
            }
        }
        Some("export") => export(ctx),
        _ => Err(USAGE.into()),
    }
}

/// CSV (quoted, formula-safe) or tab-separated text of a query result.
fn delimited(result: &research::QueryResult, separator: char, quote: bool) -> String {
    let cell = |s: String| {
        if quote {
            crate::scan::csv_cell(&s)
        } else {
            s.replace(['\t', '\n', '\r'], " ")
        }
    };
    let sep = separator.to_string();
    let mut lines = vec![
        result
            .columns
            .iter()
            .map(|c| cell(c.clone()))
            .collect::<Vec<_>>()
            .join(&sep),
    ];
    for row in &result.rows {
        lines.push(
            row.iter()
                .map(|v| cell(research::cell_text(v)))
                .collect::<Vec<_>>()
                .join(&sep),
        );
    }
    lines.join(if quote { "\r\n" } else { "\n" })
}

fn export(ctx: &mut Ctx) -> Result<(), String> {
    let (pos, opts, db) = (&ctx.pos, &ctx.opts, &ctx.db);
    let format = pos.get(1).map(String::as_str).unwrap_or("");
    match format {
        "csv" | "ndjson" => {
            let dir = opts
                .get("output")
                .ok_or("Provide --output DIR for the table files")?;
            let report = research::export::export_tables(db, std::path::Path::new(dir), format)?;
            progress(
                opts,
                format_args!("Wrote {} files to {dir}", report.tables.len() + 1),
            );
            // The directory is the output; the manifest goes to stdout.
            println!("{}", schema::object("research-export", &report)?);
            Ok(())
        }
        "stix" | "ocsf" => {
            let id = match pos.get(2) {
                Some(_) => ctx.id(2)?,
                None => {
                    store::latest_complete_id(db)?.ok_or("No completed scan in the database")?
                }
            };
            let snapshot = store::load(db, id)?;
            let time = store::timestamp(db, id)?;
            let findings = crate::risk::analyze_snapshot(&snapshot);
            let text = if format == "stix" {
                serde_json::to_string_pretty(&research::export::stix_bundle(
                    &snapshot, &findings, time,
                ))
                .map_err(|e| e.to_string())?
            } else {
                research::export::ocsf_ndjson(&research::export::ocsf_events(
                    &snapshot, &findings, time,
                ))
            };
            output(&text, opts)
        }
        _ => Err(USAGE.into()),
    }
}

#[cfg(test)]
mod tests {
    use crate::ui::{run, testutil::args};

    fn xml(ip: &str) -> String {
        format!(
            r#"<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap -p 23 {ip}" start="1700000000">
<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port></ports>
</host></nmaprun>"#
        )
    }

    #[test]
    fn query_schema_rebuild_and_export_work_end_to_end() {
        let dir = std::env::temp_dir().join(format!("ns-research-cli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = |name: &str| dir.join(name).to_str().unwrap().to_string();
        let (db, out) = (path("inventory.sqlite"), path("out.txt"));
        let file = path("scan.xml");
        std::fs::write(&file, xml("10.0.0.7")).unwrap();
        run(&args(&["import", &file, "--db", &db, "--quiet"])).unwrap();
        let read = || std::fs::read_to_string(&out).unwrap();

        run(&args(&[
            "research",
            "query",
            "SELECT ip, port, name FROM services",
            "--db",
            &db,
            "--output",
            &out,
            "--quiet",
        ]))
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&read()).unwrap();
        assert_eq!(json["schema"], "network-scope/research-query/v1");
        assert_eq!(json["rows"][0][0], "10.0.0.7");
        assert_eq!(json["truncated"], false);

        run(&args(&[
            "research",
            "query",
            "SELECT ip FROM hosts",
            "--format",
            "csv",
            "--db",
            &db,
            "--output",
            &out,
        ]))
        .unwrap();
        assert!(read().starts_with("\"ip\"\r\n\"10.0.0.7\""), "{}", read());

        // a write is refused with an error, and nothing changes
        let e = run(&args(&[
            "research",
            "query",
            "DELETE FROM hosts",
            "--db",
            &db,
        ]))
        .unwrap_err();
        assert!(e.contains("read-only"), "{e}");
        assert!(run(&args(&["research", "query", "--db", &db])).is_err());

        run(&args(&[
            "research", "schema", "--db", &db, "--output", &out,
        ]))
        .unwrap();
        assert!(read().contains("## certificates"));
        run(&args(&[
            "research", "rebuild", "--db", &db, "--output", &out, "--quiet",
        ]))
        .unwrap();
        let rebuilt: serde_json::Value = serde_json::from_str(&read()).unwrap();
        assert_eq!(rebuilt["schema"], "network-scope/research-rebuild/v1");
        assert_eq!(rebuilt["rows"]["hosts"], 1);

        run(&args(&[
            "research", "export", "stix", "--db", &db, "--output", &out,
        ]))
        .unwrap();
        let stix: serde_json::Value = serde_json::from_str(&read()).unwrap();
        assert_eq!(stix["type"], "bundle");
        run(&args(&[
            "research", "export", "ocsf", "1", "--db", &db, "--output", &out,
        ]))
        .unwrap();
        assert!(read().contains("\"class_uid\":5001"), "{}", read());
        let tables = path("tables");
        run(&args(&[
            "research", "export", "ndjson", "--db", &db, "--output", &tables, "--quiet",
        ]))
        .unwrap();
        assert!(std::path::Path::new(&tables).join("hosts.ndjson").exists());
        assert!(run(&args(&["research", "export", "ndjson", "--db", &db])).is_err());
        assert!(run(&args(&["research", "bogus", "--db", &db])).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
