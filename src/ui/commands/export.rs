//! `export ID --format ...` and `report ID`: a saved scan as JSON, CSV, HTML, nmap XML,
//! Markdown, JSON lines or a compliance inventory (`compliance-iec62443|nis2|cis[-csv]`), optionally
//! with a "changes since" section (`--baseline ID`); and for other systems as `netbox`,
//! `netbox-devices`, `snipeit`, `splunk`, `elastic` or `servicenow`, with an opt-in
//! `--push URL --token-env VAR` for NetBox, Splunk and Elastic.
use crate::{
    nmap, store,
    sync::{self, Target},
    ui::{Ctx, output, progress},
};
use std::{collections::BTreeMap, time::Duration};

pub(super) fn export(ctx: &mut Ctx) -> Result<(), String> {
    let (opts, db) = (&ctx.opts, &ctx.db);
    let snapshot = store::load(db, ctx.id(0)?)?;
    let format = opts.get("format").map(String::as_str).unwrap_or("json");
    let stamp = store::timestamp(db, ctx.id(0)?)?;
    if let Some(target) = Target::parse(format) {
        return sync_export(ctx, target, &snapshot, stamp);
    }
    if opts.contains_key("push") || opts.contains_key("token-env") {
        return Err(
            "--push and --token-env apply to --format netbox, netbox-devices, splunk or elastic"
                .into(),
        );
    }
    let text = match format {
        "html" => report_html(db, &snapshot, stamp, opts)?,
        "nmap" | "xml" => nmap::export(&snapshot, stamp),
        "md" | "markdown" => {
            let baseline = baseline(db, opts)?;
            crate::report::markdown(&snapshot, baseline.as_ref().map(|(s, t)| (s, *t)), stamp)
        }
        other => store::export_at(&snapshot, other, stamp)?,
    };
    output(&text, opts)
}

/// An export for another system, and with `--push` its delivery. The token comes from the
/// environment variable named by `--token-env` and is read before anything is sent; it is
/// never part of the URL.
fn sync_export(
    ctx: &Ctx,
    target: Target,
    snapshot: &store::Snapshot,
    stamp: i64,
) -> Result<(), String> {
    let opts = &ctx.opts;
    let get = |k: &str| opts.get(k).cloned().unwrap_or_default();
    let settings = sync::Options {
        site: get("netbox-site"),
        role: get("netbox-role"),
        device_type: get("netbox-device-type"),
        index: get("index"),
    };
    let push = opts.get("push");
    let token = match (push, opts.get("token-env")) {
        (Some(_), None) => return Err("--push needs --token-env VAR (the name of an environment variable that holds the token)".into()),
        (None, Some(_)) => return Err("--token-env is only used with --push".into()),
        (Some(_), Some(var)) => {
            if !target.can_push() {
                return Err(format!("{} is a file for the target's own importer; it cannot be pushed", target.name()));
            }
            Some(sync::token_from_env(var)?)
        }
        (None, None) => None,
    };
    let text = sync::render(target, snapshot, stamp, &settings)?;
    if let (Some(url), Some(token)) = (push, token) {
        sync::push(target, url, &token, &text, Duration::from_secs(30))?;
        progress(
            opts,
            format_args!("Pushed the {} export to {url}", target.name()),
        );
        // The body is printed only when a file was asked for.
        if opts.contains_key("output") {
            output(&text, opts)?;
        }
        return Ok(());
    }
    output(&text, opts)
}

pub(super) fn report(ctx: &mut Ctx) -> Result<(), String> {
    let (opts, db) = (&ctx.opts, &ctx.db);
    let snapshot = store::load(db, ctx.id(0)?)?;
    let stamp = store::timestamp(db, ctx.id(0)?)?;
    output(&report_html(db, &snapshot, stamp, opts)?, opts)
}

/// The `--baseline ID` snapshot and its time, for reports with a "changes since" section.
fn baseline(
    db: &std::path::Path,
    opts: &BTreeMap<String, String>,
) -> Result<Option<(store::Snapshot, i64)>, String> {
    match opts.get("baseline") {
        Some(b) => {
            let b: i64 = b.parse().map_err(|_| "Invalid --baseline".to_string())?;
            Ok(Some((store::load(db, b)?, store::timestamp(db, b)?)))
        }
        None => Ok(None),
    }
}
fn report_html(
    db: &std::path::Path,
    snapshot: &store::Snapshot,
    stamp: i64,
    opts: &BTreeMap<String, String>,
) -> Result<String, String> {
    let baseline = baseline(db, opts)?;
    Ok(crate::report::html(
        snapshot,
        baseline.as_ref().map(|(s, t)| (s, *t)),
        stamp,
    ))
}

#[cfg(test)]
mod tests {
    use crate::{
        scan::{Host, Settings},
        store,
        ui::{ExitCode, run, testutil::args},
    };
    use std::{
        io::{Read, Write},
        net::TcpListener,
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
    fn export_formats_for_other_systems_and_an_opt_in_push() {
        let dir = std::env::temp_dir().join(format!("ns-export-cli-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("inventory.sqlite");
        let d = db.to_str().unwrap();
        store::save(
            &db,
            &store::Snapshot {
                sent: vec![],
                targets: "10.0.0.0/24".into(),
                complete: true,
                settings: Settings::default(),
                hosts: vec![host("10.0.0.5", "00:00:0C:00:00:01")],
                observations: vec![],
                notes: Default::default(),
            },
        )
        .unwrap();
        let out = dir.join("out.txt");
        let read = |extra: &[&str]| {
            let mut v = vec![
                "export",
                "1",
                "--db",
                d,
                "--quiet",
                "--output",
                out.to_str().unwrap(),
            ];
            v.extend_from_slice(extra);
            assert_eq!(run(&args(&v)).unwrap(), ExitCode::Success, "{extra:?}");
            std::fs::read_to_string(&out).unwrap()
        };
        let err = |extra: &[&str]| {
            let mut v = vec!["export", "1", "--db", d, "--quiet"];
            v.extend_from_slice(extra);
            run(&args(&v)).unwrap_err()
        };
        assert!(read(&["--format", "netbox"]).contains("10.0.0.5/32"));
        assert!(read(&["--format", "snipeit"]).contains("NS-00000C000001"));
        assert!(read(&["--format", "servicenow"]).contains("cmdb_ci"));
        assert!(read(&["--format", "elastic", "--index", "ot"]).contains("\"_index\":\"ot\""));
        assert!(read(&["--format", "splunk"]).contains("network-scope:device"));
        assert!(
            read(&[
                "--format",
                "netbox-devices",
                "--netbox-site",
                "HQ",
                "--netbox-role",
                "R",
                "--netbox-device-type",
                "T"
            ])
            .contains("\"site\"")
        );
        // Mistakes.
        assert!(err(&["--format", "netbox-devices"]).contains("--netbox-site"));
        assert!(
            err(&["--format", "splunk", "--push", "http://127.0.0.1:9/"]).contains("--token-env")
        );
        assert!(err(&["--format", "splunk", "--token-env", "X"]).contains("only used with --push"));
        assert!(err(&["--format", "json", "--push", "http://127.0.0.1:9/"]).contains("--push"));
        assert!(
            err(&[
                "--format",
                "snipeit",
                "--push",
                "http://127.0.0.1:9/",
                "--token-env",
                "X"
            ])
            .contains("cannot be pushed")
        );

        // A missing variable fails before anything is sent.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let var = format!("NS_TEST_PUSH_TOKEN_{}", std::process::id());
        let e = err(&["--format", "splunk", "--push", &url, "--token-env", &var]);
        assert!(e.contains(&var), "{e}");
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "no connection was made"
        );

        // With the variable set the export is pushed, the token in the header only.
        listener.set_nonblocking(false).unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut raw = vec![];
            let mut buf = [0u8; 4096];
            while !String::from_utf8_lossy(&raw).contains("\r\n\r\n{\"") {
                let n = s.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buf[..n]);
            }
            let _ = write!(
                s,
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            String::from_utf8_lossy(&raw).into_owned()
        });
        // SAFETY: the variable has a name no other test or thread uses.
        unsafe { std::env::set_var(&var, "hec-token-123") };
        let mut v = vec![
            "export", "1", "--db", d, "--quiet", "--format", "splunk", "--push", &url,
        ];
        v.extend(["--token-env", &var]);
        assert_eq!(run(&args(&v)).unwrap(), ExitCode::Success);
        unsafe { std::env::remove_var(&var) };
        let req = server.join().unwrap();
        let head = req.split("\r\n\r\n").next().unwrap();
        assert!(
            head.starts_with("POST /services/collector/event HTTP/1.1"),
            "{head}"
        );
        assert!(
            head.contains("Authorization: Splunk hec-token-123"),
            "{head}"
        );
        assert!(!head.lines().next().unwrap().contains("hec-token-123"));
        assert!(
            req.contains("\"sourcetype\":\"network-scope:device\""),
            "{req}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
