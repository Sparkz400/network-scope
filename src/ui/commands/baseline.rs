//! `baseline approve [SCAN_ID]`, `baseline set DEVICE [--owner ..] [--tag ..] [--untag ..]
//! [--criticality ..] [--expected yes|no]`, `baseline show [--format text|json]`,
//! `baseline remove DEVICE` and `baseline clear`: the approved baseline of expected devices. Once
//! one is approved, `monitor` raises `unknown-device` for every device that is not on it.
use crate::{
    baseline::{self, Criticality, Update},
    store,
    ui::{Ctx, output, progress},
};

const USAGE: &str = "Use baseline approve [SCAN_ID], set DEVICE ..., show, remove DEVICE or clear";

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    let sub = ctx.pos.first().map(String::as_str).ok_or(USAGE)?;
    match sub {
        "approve" => approve(ctx),
        "set" => set(ctx),
        "show" => show(ctx),
        "remove" => {
            let device = ctx.pos.get(1).ok_or("Name the device to remove")?;
            let removed = baseline::remove(&ctx.db, device)?;
            progress(
                &ctx.opts,
                if removed {
                    format!("Removed {device} from the baseline")
                } else {
                    format!("{device} was not on the baseline")
                },
            );
            Ok(())
        }
        "clear" => {
            let n = baseline::clear(&ctx.db)?;
            progress(
                &ctx.opts,
                format_args!("Baseline cleared ({n} devices); unknown-device alerts are off"),
            );
            Ok(())
        }
        _ => Err(USAGE.into()),
    }
}

fn approve(ctx: &mut Ctx) -> Result<(), String> {
    let scan = ctx
        .pos
        .get(1)
        .map(|id| id.parse::<i64>().map_err(|_| "Invalid scan ID".to_string()))
        .transpose()?;
    let a = baseline::approve(&ctx.db, scan, store::now())?;
    progress(
        &ctx.opts,
        format_args!(
            "Approved {} devices from scan #{} ({} new on the baseline); `monitor` now alerts on unknown devices",
            a.devices, a.scan_id, a.added
        ),
    );
    Ok(())
}

fn set(ctx: &mut Ctx) -> Result<(), String> {
    let device = ctx
        .pos
        .get(1)
        .ok_or("Name the device: baseline set DEVICE ...")?;
    let opts = &ctx.opts;
    let list = |key: &str| -> Vec<String> {
        opts.get(key)
            .map(|v| v.split(',').map(str::to_string).collect())
            .unwrap_or_default()
    };
    let criticality = opts
        .get("criticality")
        .map(|c| {
            if c.eq_ignore_ascii_case("none") {
                Ok(None)
            } else {
                Criticality::parse(c)
                    .map(Some)
                    .ok_or("Criticality must be low, medium, high, critical or none")
            }
        })
        .transpose()?;
    let expected = opts
        .get("expected")
        .map(|e| match e.to_ascii_lowercase().as_str() {
            "yes" | "true" => Ok(true),
            "no" | "false" => Ok(false),
            _ => Err("--expected must be yes or no"),
        })
        .transpose()?;
    let update = Update {
        owner: opts.get("owner").cloned(),
        criticality,
        add_tags: list("tag"),
        remove_tags: list("untag"),
        expected,
    };
    let entry = baseline::set(&ctx.db, device, &update, store::now())?;
    progress(
        opts,
        format_args!(
            "{}: owner {}, criticality {}, tags {}, {}",
            entry.label,
            if entry.owner.is_empty() {
                "-"
            } else {
                &entry.owner
            },
            entry.criticality.map_or("-", Criticality::name),
            if entry.tags.is_empty() {
                "-".to_string()
            } else {
                entry.tags.join(",")
            },
            if entry.expected {
                "expected"
            } else {
                "not expected"
            }
        ),
    );
    Ok(())
}

fn show(ctx: &mut Ctx) -> Result<(), String> {
    let format = ctx.opts.get("format").map(String::as_str).unwrap_or("text");
    output(
        &baseline::render(&baseline::load(&ctx.db)?, format)?,
        &ctx.opts,
    )
}

#[cfg(test)]
mod tests {
    use crate::{
        scan::{Host, Settings},
        store,
        ui::{ExitCode, run, testutil::args},
    };

    fn temp_db() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ns-baseline-cli-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn host(ip: &str, mac: &str, name: &str) -> Host {
        Host {
            ip: ip.parse().unwrap(),
            responding: true,
            ping: None,
            ttl: None,
            hostname: name.into(),
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
    fn approve_set_show_remove_and_clear_from_the_command_line() {
        let db = temp_db();
        let d = db.to_str().unwrap();
        let snapshot = store::Snapshot {
            targets: "10.0.0.0/24".into(),
            complete: true,
            settings: Settings::default(),
            hosts: vec![
                host("10.0.0.5", "00:00:0C:00:00:01", "switch-1"),
                host("10.0.0.6", "00:00:0C:00:00:02", "plc-1"),
            ],
            observations: vec![],
            notes: Default::default(),
        };
        store::save(&db, &snapshot).unwrap();
        let ok = |a: &[&str]| {
            let mut v = vec![a[0], a[1]];
            v.extend_from_slice(&a[2..]);
            v.extend(["--db", d, "--quiet"]);
            assert_eq!(run(&args(&v)).unwrap(), ExitCode::Success, "{a:?}");
        };
        let err = |a: &[&str]| {
            let mut v = a.to_vec();
            v.extend(["--db", d, "--quiet"]);
            run(&args(&v)).unwrap_err()
        };
        ok(&["baseline", "approve"]);
        ok(&[
            "baseline",
            "set",
            "plc-1",
            "--owner",
            "Plant",
            "--tag",
            "ot,line-1",
            "--criticality",
            "critical",
        ]);
        let out =
            std::env::temp_dir().join(format!("ns-baseline-show-{}.json", std::process::id()));
        ok(&[
            "baseline",
            "show",
            "--format",
            "json",
            "--output",
            out.to_str().unwrap(),
        ]);
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        let _ = std::fs::remove_file(&out);
        assert_eq!(json["entries"].as_array().unwrap().len(), 2);
        let plc = json["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["label"] == "plc-1")
            .unwrap();
        assert_eq!(plc["owner"], "Plant");
        assert_eq!(plc["criticality"], "critical");
        assert_eq!(plc["tags"], serde_json::json!(["line-1", "ot"]));
        ok(&[
            "baseline",
            "set",
            "plc-1",
            "--untag",
            "ot",
            "--criticality",
            "none",
            "--expected",
            "no",
        ]);
        ok(&["baseline", "show"]);
        ok(&["baseline", "remove", "plc-1"]);
        // Mistakes.
        assert!(err(&["baseline"]).contains("baseline approve"));
        assert!(err(&["baseline", "bogus"]).contains("baseline approve"));
        assert!(err(&["baseline", "approve", "x"]).contains("Invalid scan ID"));
        assert!(
            err(&["baseline", "approve", "99"]).len() > 3,
            "no such scan"
        );
        assert!(err(&["baseline", "set"]).contains("Name the device"));
        assert!(err(&["baseline", "set", "switch-1"]).contains("Nothing to change"));
        assert!(
            err(&["baseline", "set", "switch-1", "--criticality", "urgent"])
                .contains("Criticality must be")
        );
        assert!(err(&["baseline", "set", "switch-1", "--expected", "maybe"]).contains("yes or no"));
        assert!(err(&["baseline", "remove"]).contains("Name the device"));
        assert!(err(&["baseline", "show", "--format", "xml"]).contains("text or json"));
        ok(&["baseline", "clear"]);
        for suffix in ["", "-wal", "-shm"] {
            let mut p = db.as_os_str().to_owned();
            p.push(suffix);
            let _ = std::fs::remove_file(std::path::PathBuf::from(p));
        }
    }
}
