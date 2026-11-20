//! `search QUERY [--top N] [--format text|json]`: where an IP address, MAC address (or vendor
//! prefix), host name, vendor, device type or finding id appeared in the saved scans, newest
//! scan first. Read-only; it only reads the inventory (`core::search`).
use crate::{
    schema, search,
    ui::{Ctx, args::number, output},
};

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    let opts = &ctx.opts;
    let format = opts.get("format").map(String::as_str).unwrap_or("text");
    if !["text", "json"].contains(&format) {
        return Err("Choose text or json".into());
    }
    let [query] = ctx.pos.as_slice() else {
        return Err("Usage: search QUERY (an address, MAC, name, vendor or finding id)".into());
    };
    let limit: usize = number(opts, "top", 100)?;
    let results = search::search(&ctx.db, query, limit)?;
    let text = if format == "json" {
        schema::object("search", &results)?
    } else {
        search::render(&results).trim_end().to_string()
    };
    output(&text, opts)
}

#[cfg(test)]
mod tests {
    use crate::{
        scan::{Host, Settings},
        store,
        ui::{run, testutil::args},
    };

    fn fixture(name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("ns-search-cli-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("inventory.sqlite");
        let host = Host {
            ip: "10.0.5.17".parse().unwrap(),
            responding: true,
            ping: None,
            ttl: None,
            hostname: "plc-1".into(),
            mac: "00:0C:29:AA:BB:CC".into(),
            open: vec![502],
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity: Default::default(),
            udp_open: vec![],
            trace: vec![],
        };
        store::save_at(
            &db,
            &store::Snapshot {
                sent: vec![],
                targets: "10.0.5.0/24".into(),
                complete: true,
                settings: Settings::default(),
                hosts: vec![host],
                observations: vec![],
                notes: Default::default(),
            },
            1_790_000_000,
        )
        .unwrap();
        (dir, db)
    }

    #[test]
    fn search_prints_text_and_json_and_refuses_bad_input() {
        let (dir, db) = fixture("run");
        let out = dir.join("out.txt");
        let go = |list: &[&str]| {
            let mut a: Vec<&str> = list.to_vec();
            a.extend([
                "--db",
                db.to_str().unwrap(),
                "--output",
                out.to_str().unwrap(),
            ]);
            run(&args(&a)).map(|_| std::fs::read_to_string(&out).unwrap_or_default())
        };
        let text = go(&["search", "10.0.5.17"]).unwrap();
        assert!(text.contains("Last seen in scan #1"), "{text}");
        let json: serde_json::Value =
            serde_json::from_str(&go(&["search", "plc-1", "--format", "json"]).unwrap()).unwrap();
        assert_eq!(json["schema"], "network-scope/search/v1");
        assert_eq!(json["hits"][0]["scan_id"], 1);
        assert_eq!(json["hits"][0]["source"], "host");
        assert!(
            go(&["search", "10.0.9.9"])
                .unwrap()
                .contains("was not found")
        );
        assert!(go(&["search"]).unwrap_err().contains("Usage"));
        assert!(go(&["search", "a", "b"]).unwrap_err().contains("Usage"));
        assert!(go(&["search", "x", "--format", "xml"]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
