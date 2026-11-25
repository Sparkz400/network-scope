// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! `changes [--since last|7d|DATE] [--format text|json]`: the new, gone and changed devices and
//! the new and resolved risks between the newest completed scan and the previous one (`last`), or
//! the state at the start of a window (`12h`, `7d`, `2w`) or at a UTC date (`2026-11-01`).
use crate::{
    changes::{self, Since},
    store,
    ui::{Ctx, output},
};

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    let opts = &ctx.opts;
    let now = store::now();
    let since = Since::parse(opts.get("since").map(String::as_str).unwrap_or("last"), now)?;
    let format = opts.get("format").map(String::as_str).unwrap_or("text");
    // A wrong format is refused before the database is opened.
    if !["text", "json"].contains(&format) {
        return Err("Choose text or json".into());
    }
    let result = changes::changes(&ctx.db, &since, now)?;
    output(&changes::render(&result, format)?, opts)
}

#[cfg(test)]
mod tests {
    use crate::{
        scan::{Host, Settings},
        store,
        ui::{ExitCode, run, testutil::args},
    };

    fn host(ip: &str, mac: &str) -> Host {
        Host {
            ip: ip.parse().unwrap(),
            responding: true,
            ping: None,
            ttl: None,
            hostname: String::new(),
            mac: mac.into(),
            open: vec![22],
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
    fn changes_prints_text_and_json_and_refuses_bad_options() {
        let dir = std::env::temp_dir().join(format!("ns-changes-cli-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("inventory.sqlite");
        let (d, out) = (db.to_str().unwrap(), dir.join("out.txt"));
        let o = out.to_str().unwrap();
        let snapshot = |hosts: Vec<Host>| store::Snapshot {
            sent: vec![],
            targets: "10.0.0.0/24".into(),
            complete: true,
            settings: Settings::default(),
            hosts,
            observations: vec![],
            notes: Default::default(),
        };
        let now = store::now();
        store::save_at(
            &db,
            &snapshot(vec![host("10.0.0.5", "00:00:0C:00:00:01")]),
            now - 7200,
        )
        .unwrap();
        store::save_at(
            &db,
            &snapshot(vec![
                host("10.0.0.5", "00:00:0C:00:00:01"),
                host("10.0.0.6", "00:00:0C:00:00:02"),
            ]),
            now - 60,
        )
        .unwrap();
        let read = |extra: &[&str]| {
            let mut v = vec!["changes", "--db", d, "--quiet", "--output", o];
            v.extend_from_slice(extra);
            assert_eq!(run(&args(&v)).unwrap(), ExitCode::Success, "{extra:?}");
            std::fs::read_to_string(&out).unwrap()
        };
        let text = read(&[]);
        assert!(
            text.contains("New devices (1):") && text.contains("10.0.0.6"),
            "{text}"
        );
        let json: serde_json::Value =
            serde_json::from_str(&read(&["--since", "1d", "--format", "json"])).unwrap();
        assert_eq!(json["summary"]["new_devices"], 1);
        assert_eq!(json["previous"]["id"], 1);
        // A window that starts after the newest scan is an answer, not an error.
        let quiet = read(&["--since", "9999-12-31"]);
        assert!(quiet.contains("older than the window"), "{quiet}");
        assert!(!quiet.contains("New devices"));
        let err = |extra: &[&str]| {
            let mut v = vec!["changes", "--db", d, "--quiet"];
            v.extend_from_slice(extra);
            run(&args(&v)).unwrap_err()
        };
        assert!(err(&["--since", "yesterday"]).contains("use last"));
        assert!(err(&["--format", "xml"]).contains("text or json"));
        assert!(err(&["--since"]).contains("Missing --since"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
