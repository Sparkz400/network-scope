//! `diff OLD_ID NEW_ID [--format lines|json|text] [--ignore KEY,KEY] [--fail-on-findings]`.
use crate::{
    risk, store,
    ui::{Ctx, args::min_severity, findings_exit, output},
};

pub(super) fn run(ctx: &mut Ctx) -> Result<(), String> {
    let opts = &ctx.opts;
    let ignore = store::IgnoreList::parse(opts.get("ignore").map(String::as_str).unwrap_or(""));
    let format = opts.get("format").map(String::as_str).unwrap_or("lines");
    // --min-severity only sets the threshold of --fail-on-findings; it does not filter
    // the output, and without the flag it is not read (existing calls are unchanged).
    let gate = if ctx.fail_on_findings() {
        Some(min_severity(opts)?)
    } else {
        None
    };
    let report = store::diff_report(
        &store::load(&ctx.db, ctx.id(0)?)?,
        &store::load(&ctx.db, ctx.id(1)?)?,
        &ignore,
    )?;
    output(&store::render_diff(&report, format)?, opts)?;
    if let Some(min) = gate {
        ctx.status = findings_exit(true, new_findings_at_or_above(&report, min));
    }
    Ok(())
}
/// New findings of a diff at or above `min`: what `diff --fail-on-findings` gates on. Changed
/// hosts or ports, resolved findings, findings the new scan did not re-check and findings a
/// vendor statement clears (VEX) do not count.
fn new_findings_at_or_above(report: &store::DiffReport, min: risk::Severity) -> usize {
    report
        .new_findings
        .iter()
        .filter(|f| f.severity >= min && !f.cleared_by_vex())
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{scan, ui::testutil::tui_host};
    use std::collections::BTreeMap;

    #[test]
    fn diff_gate_counts_new_findings_at_or_above_the_threshold() {
        let snapshot = |hosts: Vec<scan::Host>| store::Snapshot {
            sent: vec![],
            targets: "10.0.0.2".into(),
            complete: true,
            settings: scan::Settings::default(),
            hosts,
            observations: vec![],
            notes: BTreeMap::new(),
        };
        let quiet = snapshot(vec![tui_host("10.0.0.2", vec![])]);
        let telnet = snapshot(vec![tui_host("10.0.0.2", vec![23])]);
        let ignore = store::IgnoreList::new(&[]);
        let appeared = store::diff_report(&quiet, &telnet, &ignore).unwrap();
        let high = risk::Severity::High;
        assert!(new_findings_at_or_above(&appeared, risk::Severity::Info) >= 1);
        assert!(
            new_findings_at_or_above(&appeared, high) >= 1,
            "telnet is high"
        );
        assert_eq!(
            new_findings_at_or_above(&appeared, risk::Severity::Critical),
            0
        );
        // A finding that went away is not "found": only new findings count.
        let resolved = store::diff_report(&telnet, &quiet, &ignore).unwrap();
        assert_eq!(new_findings_at_or_above(&resolved, risk::Severity::Info), 0);
        // Unchanged scans report nothing new.
        let same = store::diff_report(&telnet, &telnet, &ignore).unwrap();
        assert_eq!(new_findings_at_or_above(&same, risk::Severity::Info), 0);
    }
}
