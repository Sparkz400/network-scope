//! `findings ID [--min-severity low] [--sort exploited|severity] [--fail-on-findings]` and
//! `findings ID --top N [--format text|json]` (risk scores and the "fix these first" list).
use crate::{
    risk, schema, score,
    ui::{Ctx, args::min_severity, findings_exit, output},
};

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    let opts = &ctx.opts;
    let snapshot = ctx.scan(0)?;
    let min = min_severity(opts)?;
    let mut list: Vec<_> = risk::analyze_snapshot(&snapshot)
        .into_iter()
        .filter(|f| f.severity >= min)
        .collect();
    // Imported feeds rank known exploited findings first; without them both orders match.
    match opts.get("sort").map(String::as_str).unwrap_or("exploited") {
        "exploited" => {}
        "severity" => crate::feeds::sort_by_severity(&mut list),
        _ => return Err("Sort must be exploited or severity".into()),
    }
    // A finding the vendor says does not apply (VEX) does not fail a gate.
    let open = list.iter().filter(|f| !f.cleared_by_vex()).count();
    if let Some(n) = opts.get("top") {
        let n: usize = n
            .parse()
            .ok()
            .filter(|n| (1..=1000).contains(n))
            .ok_or("--top needs a number from 1 to 1000")?;
        let assessment = score::assess(&list, n);
        let text = match opts.get("format").map(String::as_str).unwrap_or("text") {
            "text" => top_text(&assessment),
            "json" => schema::object("risk-score", &assessment)?,
            _ => return Err("Choose text or json".into()),
        };
        output(&text, opts)?;
        ctx.status = findings_exit(ctx.fail_on_findings(), open);
        return Ok(());
    }
    output(&schema::list("findings", "findings", &list)?, opts)?;
    ctx.status = findings_exit(ctx.fail_on_findings(), open);
    Ok(())
}

/// The network score, the riskiest hosts and the fix list as plain text.
fn top_text(a: &score::Assessment) -> String {
    let mut o = format!(
        "Network risk score: {} / 100 ({}); {} finding(s) on {} host(s)\n",
        a.network.score,
        a.network.band.name(),
        a.network.findings,
        a.network.hosts
    );
    for h in a.hosts.iter().take(5) {
        o.push_str(&format!(
            "  {:<16} {:>3} ({}), {} finding(s)\n",
            h.ip.to_string(),
            h.score,
            h.band.name(),
            h.findings
        ));
    }
    if a.top_fixes.is_empty() {
        o.push_str("\nNothing to fix.");
        return o;
    }
    o.push_str(&format!("\nFix these first (top {}):\n", a.top_fixes.len()));
    for (i, g) in a.top_fixes.iter().enumerate() {
        o.push_str(&format!(
            "{:>2}. [{}] {} - {}{}, lowers risk by {:.1}\n      {}\n",
            i + 1,
            g.severity.name(),
            g.title,
            score::hosts_text(&g.hosts),
            if g.kev { ", known exploited" } else { "" },
            g.risk_reduction,
            g.advice
        ));
    }
    o.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use crate::{
        scan::Settings,
        store,
        ui::{
            run,
            testutil::{args, tui_host},
        },
    };

    #[test]
    fn findings_top_prints_scores_and_the_fix_list() {
        let dir = std::env::temp_dir().join(format!("ns-findings-top-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (db, out) = (dir.join("inv.sqlite"), dir.join("out.txt"));
        let snapshot = store::Snapshot {
            sent: vec![],
            targets: "10.0.0.0/24".into(),
            complete: true,
            settings: Settings::default(),
            hosts: vec![
                tui_host("10.0.0.2", vec![23]),
                tui_host("10.0.0.3", vec![23]),
                tui_host("10.0.0.4", vec![80]),
            ],
            observations: vec![],
            notes: Default::default(),
        };
        store::save(&db, &snapshot).unwrap();
        let p = |p: &std::path::Path| p.to_str().unwrap().to_string();
        let top = |extra: &[&str]| {
            let mut a = vec!["findings", "1", "--db"];
            let (d, o) = (p(&db), p(&out));
            a.push(&d);
            a.extend(["--output", &o]);
            a.extend(extra);
            run(&args(&a))
        };
        top(&["--top", "5"]).unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        assert!(text.contains("Network risk score:"), "{text}");
        assert!(text.contains("Fix these first (top 1):"), "{text}");
        assert!(
            text.contains("Telnet exposes credentials in clear text - 2 hosts"),
            "{text}"
        );
        assert!(text.contains("10.0.0.2"), "{text}");
        top(&["--top", "5", "--format", "json"]).unwrap();
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(json["top_fixes"][0]["id"], "telnet-open");
        assert_eq!(json["top_fixes"][0]["hosts"].as_array().unwrap().len(), 2);
        assert_eq!(json["network"]["hosts"], 2);
        // Without --top the plain list is unchanged.
        top(&[]).unwrap();
        let list: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(list["schema"], "network-scope/findings/v1");
        assert_eq!(list["findings"].as_array().unwrap().len(), 2);
        // Errors: a bad count and a bad format.
        for bad in ["0", "x", "5000"] {
            assert!(top(&["--top", bad]).is_err(), "{bad}");
        }
        assert!(top(&["--top", "3", "--format", "xml"]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
