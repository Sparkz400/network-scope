// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Compliance exports (ROADMAP D30): the asset inventory of a scan with its findings mapped to
//! the controls of IEC 62443 (foundational requirements, with a zone and a criticality per
//! asset), the NIS2 Directive (Article 21(2) measures) and the CIS Controls v8 (safeguards), as
//! Markdown or CSV.
//!
//! The mapping table is `data/compliance.json` (identifiers and short titles only, with its
//! provenance in the file). It is this project's judgment of what a finding is evidence about,
//! not an official crosswalk; the export says so, and a scan sees only what is reachable from
//! the network. Zones and criticalities are defaults derived from the asset's role (documented
//! in [`zone_of`] and [`criticality_of`]) that a person is expected to review.
use crate::{
    devices::{self, Device},
    report, risk,
    risk::{Finding, Severity},
    score,
    store::Snapshot,
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    sync::OnceLock,
};

static DATA: &str = include_str!("../../data/compliance.json");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standard {
    Iec62443,
    Nis2,
    Cis,
}
impl Standard {
    /// The `export --format` names: `compliance-iec62443`, `compliance-nis2`, `compliance-cis`,
    /// each with an optional `-csv` suffix (Markdown without). Returns the standard and whether
    /// CSV was asked for.
    pub fn from_format(format: &str) -> Option<(Self, bool)> {
        let rest = format.strip_prefix("compliance-")?;
        let (name, csv) = match rest.strip_suffix("-csv") {
            Some(n) => (n, true),
            None => (rest, false),
        };
        let s = match name {
            "iec62443" => Self::Iec62443,
            "nis2" => Self::Nis2,
            "cis" => Self::Cis,
            _ => return None,
        };
        Some((s, csv))
    }
    fn key(self) -> &'static str {
        match self {
            Self::Iec62443 => "iec62443",
            Self::Nis2 => "nis2",
            Self::Cis => "cis",
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Control {
    pub id: String,
    pub name: String,
}
#[derive(Debug, Deserialize)]
struct Evidence {
    control: String,
    note: String,
}
#[derive(Debug, Deserialize)]
struct StandardDef {
    name: String,
    short: String,
    controls: Vec<Control>,
    #[serde(default)]
    evidence: Vec<Evidence>,
}
#[derive(Debug, Deserialize)]
struct Group {
    ids: Vec<String>,
    #[serde(default)]
    iec62443: Vec<String>,
    #[serde(default)]
    nis2: Vec<String>,
    #[serde(default)]
    cis: Vec<String>,
}
#[derive(Debug, Deserialize)]
struct Table {
    standards: BTreeMap<String, StandardDef>,
    groups: Vec<Group>,
}

/// The embedded `data/compliance.json` (what the provenance stamp of a scan hashes).
pub fn data_text() -> &'static str {
    DATA
}

fn table() -> &'static Table {
    static T: OnceLock<Table> = OnceLock::new();
    T.get_or_init(|| serde_json::from_str(DATA).expect("data/compliance.json is valid"))
}

/// Checks the mapping table: every referenced control exists in its standard, there are no
/// duplicate ids. Used by the test and by anyone who edits the table.
pub fn validate() -> Result<(), String> {
    let t = table();
    let mut seen = BTreeSet::new();
    for g in &t.groups {
        for id in &g.ids {
            if !seen.insert(id.as_str()) {
                return Err(format!("{id} is mapped twice"));
            }
        }
        for s in [Standard::Iec62443, Standard::Nis2, Standard::Cis] {
            let def = t
                .standards
                .get(s.key())
                .ok_or(format!("{} missing", s.key()))?;
            for c in g.controls(s) {
                if !def.controls.iter().any(|d| &d.id == c) {
                    return Err(format!("{}: unknown control {c:?}", s.key()));
                }
            }
        }
    }
    Ok(())
}

impl Group {
    fn controls(&self, s: Standard) -> &[String] {
        match s {
            Standard::Iec62443 => &self.iec62443,
            Standard::Nis2 => &self.nis2,
            Standard::Cis => &self.cis,
        }
    }
}

/// The group a finding id belongs to: an exact id, else a prefix entry (`cve-*`).
fn group_of(id: &str) -> Option<&'static Group> {
    let t = table();
    t.groups
        .iter()
        .find(|g| g.ids.iter().any(|i| i == id))
        .or_else(|| {
            t.groups.iter().find(|g| {
                g.ids
                    .iter()
                    .any(|i| i.strip_suffix('*').is_some_and(|p| id.starts_with(p)))
            })
        })
}

/// The control ids a finding maps to in a standard (empty when it has no mapping).
pub fn controls_for(s: Standard, finding_id: &str) -> Vec<&'static str> {
    group_of(finding_id)
        .map(|g| g.controls(s).iter().map(String::as_str).collect())
        .unwrap_or_default()
}

/// Is there a mapping entry (possibly an empty one) for this finding id?
pub fn is_mapped(finding_id: &str) -> bool {
    group_of(finding_id).is_some()
}

fn is_printer_port(p: u16) -> bool {
    p == 515 || (9100..=9107).contains(&p)
}

/// IEC 62443 zone of an asset, by role: `OT / control` for industrial controllers and any asset
/// with an industrial protocol port open or observed, `Network infrastructure`, `Peripherals
/// and IoT` (printers, cameras, media, phones, embedded) and `IT systems` for the rest.
pub fn zone_of(d: &Device) -> &'static str {
    let ot_ports = d
        .open_tcp
        .iter()
        .any(|p| crate::service::is_ot_port_candidate(*p))
        || d.open_udp
            .iter()
            .any(|p| crate::service::is_ot_udp_port(*p) && !is_printer_port(*p));
    let ot_seen = d.observations.keys().any(|k| k.ends_with("(observed)"));
    if d.device_type.starts_with("Industrial") || ot_ports || ot_seen {
        "OT / control"
    } else if d.device_type.starts_with("Network device") {
        "Network infrastructure"
    } else if [
        "Printer",
        "IP camera",
        "Media",
        "IoT",
        "VoIP",
        "Smartphone",
        "Single-board",
    ]
    .iter()
    .any(|p| d.device_type.starts_with(p))
    {
        "Peripherals and IoT"
    } else {
        "IT systems"
    }
}

/// Default asset criticality by role: High for OT controllers and network infrastructure,
/// Medium for database and storage servers and assets with open industrial ports that are not
/// controllers, Low for peripherals and workstations, and `Unclassified` when the device type
/// is unknown. A person should replace these with the organisation's own classification.
pub fn criticality_of(d: &Device) -> &'static str {
    match zone_of(d) {
        "OT / control" if d.device_type.starts_with("Industrial") => "High",
        "OT / control" => "Medium",
        "Network infrastructure" => "High",
        "Peripherals and IoT" => "Low",
        _ if d.device_type.starts_with("Database") || d.device_type.starts_with("NAS") => "Medium",
        _ if d.device_type.is_empty() => "Unclassified",
        _ => "Low",
    }
}

struct Row<'a> {
    device: &'a Device,
    findings: Vec<&'a Finding>,
    score: u8,
}

fn rows<'a>(devs: &'a [Device], findings: &'a [Finding]) -> Vec<Row<'a>> {
    let scores = score::host_scores(findings);
    devs.iter()
        .map(|d| {
            let mut mine: Vec<&Finding> =
                findings.iter().filter(|f| d.ips.contains(&f.ip)).collect();
            mine.sort_by(|a, b| {
                b.severity
                    .cmp(&a.severity)
                    .then(a.port.cmp(&b.port))
                    .then(a.id.cmp(&b.id))
            });
            let score = d
                .ips
                .iter()
                .filter_map(|ip| scores.iter().find(|s| s.ip == *ip))
                .map(|s| s.score)
                .max()
                .unwrap_or(0);
            Row {
                device: d,
                findings: mine,
                score,
            }
        })
        .collect()
}

fn ips_text(ips: &[IpAddr]) -> String {
    ips.iter()
        .map(IpAddr::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}
fn ports_text(d: &Device) -> String {
    d.open_tcp
        .iter()
        .map(u16::to_string)
        .chain(d.open_udp.iter().map(|p| format!("{p}/udp")))
        .collect::<Vec<_>>()
        .join(" ")
}
fn asset_name(d: &Device) -> String {
    d.hostnames
        .first()
        .cloned()
        .unwrap_or_else(|| ips_text(&d.ips))
}

/// The export for a snapshot: Markdown, or CSV (one row per asset and finding, assets without
/// findings once with empty finding columns).
pub fn export(snapshot: &Snapshot, standard: Standard, csv: bool, timestamp: i64) -> String {
    let findings = risk::analyze_snapshot(snapshot);
    let devs = devices::merge(&snapshot.hosts, &snapshot.observations);
    let rows = rows(&devs, &findings);
    if csv {
        csv_export(&rows, standard)
    } else {
        markdown_export(snapshot, &rows, &findings, standard, timestamp)
    }
}

fn csv_export(rows: &[Row], s: Standard) -> String {
    let iec = s == Standard::Iec62443;
    let mut header = vec![
        "asset",
        "addresses",
        "mac",
        "vendor",
        "device_type",
        "os",
        "open_ports",
    ];
    if iec {
        header.extend(["zone", "criticality"]);
    }
    header.extend([
        "risk_score",
        "finding_id",
        "severity",
        "port",
        "title",
        "confidence",
        "controls",
        "evidence",
    ]);
    let mut out = header.join(",");
    out.push_str("\r\n");
    for r in rows {
        let d = r.device;
        let mut base = vec![
            asset_name(d),
            ips_text(&d.ips),
            d.mac.clone(),
            d.vendor.clone(),
            d.device_type.clone(),
            d.os.clone(),
            ports_text(d),
        ];
        if iec {
            base.push(zone_of(d).into());
            base.push(criticality_of(d).into());
        }
        base.push(r.score.to_string());
        let mut lines: Vec<Vec<String>> = vec![];
        if r.findings.is_empty() {
            lines.push(vec![String::new(); 7]);
        }
        for f in &r.findings {
            let controls = controls_for(s, &f.id);
            lines.push(vec![
                f.id.clone(),
                f.severity.name().into(),
                f.port.map(|p| p.to_string()).unwrap_or_default(),
                f.title.clone(),
                if f.confidence > 0 {
                    f.confidence.to_string()
                } else {
                    String::new()
                },
                if controls.is_empty() {
                    "not mapped".into()
                } else {
                    controls.join("; ")
                },
                f.evidence.clone(),
            ]);
        }
        for line in lines {
            let cells: Vec<String> = base.iter().cloned().chain(line).collect();
            out.push_str(
                &cells
                    .iter()
                    .map(|c| crate::scan::csv_cell(c))
                    .collect::<Vec<_>>()
                    .join(","),
            );
            out.push_str("\r\n");
        }
    }
    out
}

fn markdown_export(
    snapshot: &Snapshot,
    rows: &[Row],
    findings: &[Finding],
    s: Standard,
    timestamp: i64,
) -> String {
    use std::fmt::Write as _;
    let def = &table().standards[s.key()];
    let md = report::md;
    let mut o = format!("# {} asset inventory and findings\n\n", md(&def.short));
    let _ = writeln!(
        o,
        "Scope: {}  \nStatus: {}  \nTime: {}  \nFramework: {}\n",
        md(&snapshot.targets),
        if snapshot.complete {
            "completed scan"
        } else {
            "PARTIAL scan (interrupted); absence of an asset proves nothing"
        },
        report::fmt_time(timestamp),
        md(&def.name)
    );
    o.push_str("> This document is an aid for preparing an assessment. It is **not** a compliance assessment or a certification. The mapping of findings to controls is this project's own judgment (see `data/compliance.json` for its provenance), a network scan sees only what is reachable from the scanner, and CVE findings are version-based hints.\n\n");

    let _ = writeln!(o, "## Asset inventory ({})\n", rows.len());
    let iec = s == Standard::Iec62443;
    o.push_str("| Asset | Addresses | MAC | Vendor | Type | OS (guess) |");
    if iec {
        o.push_str(" Zone | Criticality |");
    }
    o.push_str(" Open ports | Risk score | Findings |\n|---|---|---|---|---|---|");
    if iec {
        o.push_str("---|---|");
    }
    o.push_str("---|---|---|\n");
    for r in rows {
        let d = r.device;
        let _ = write!(
            o,
            "| {} | {} | {} | {} | {} | {} |",
            md(&asset_name(d)),
            md(&ips_text(&d.ips)),
            md(&d.mac),
            md(&d.vendor),
            md(&d.device_type),
            md(&d.os)
        );
        if iec {
            let _ = write!(o, " {} | {} |", zone_of(d), criticality_of(d));
        }
        let _ = writeln!(
            o,
            " {} | {} | {} |",
            md(&ports_text(d)),
            r.score,
            r.findings.len()
        );
    }
    if iec {
        o.push_str("\nZones and criticalities are defaults derived from the asset's role (industrial controllers and assets with industrial protocol ports: `OT / control`; routers, switches and access points: `Network infrastructure`; printers, cameras, phones and embedded devices: `Peripherals and IoT`; everything else: `IT systems`; criticality High for controllers and network infrastructure, Medium for database/storage servers, Low otherwise). Replace them with your own zone model and criticality classification.\n");
    }

    // Coverage: findings and assets per control.
    let mut per_control: BTreeMap<&str, (usize, BTreeSet<usize>)> = BTreeMap::new();
    let mut unmapped: Vec<(usize, &Finding)> = vec![];
    for (i, r) in rows.iter().enumerate() {
        for f in &r.findings {
            let c = controls_for(s, &f.id);
            if c.is_empty() {
                unmapped.push((i, f));
            }
            for id in c {
                let e = per_control.entry(id).or_default();
                e.0 += 1;
                e.1.insert(i);
            }
        }
    }
    let _ = writeln!(
        o,
        "\n## Control coverage\n\n| Control | Title | Findings | Assets affected |\n|---|---|---|---|"
    );
    for c in &def.controls {
        let (n, assets) = per_control
            .get(c.id.as_str())
            .map_or((0, 0), |(n, a)| (*n, a.len()));
        let _ = writeln!(
            o,
            "| {} | {} | {} | {} |",
            md(&c.id),
            md(&c.name),
            if n == 0 { "-".into() } else { n.to_string() },
            if n == 0 {
                "-".into()
            } else {
                assets.to_string()
            }
        );
    }
    o.push_str("\nA control with no findings is not proof of compliance: it means this scan found nothing that maps to it.\n");

    if !def.evidence.is_empty() {
        o.push_str("\n## What this scan evidences\n\n");
        for e in &def.evidence {
            let title = def
                .controls
                .iter()
                .find(|c| c.id == e.control)
                .map_or("", |c| c.name.as_str());
            let _ = writeln!(
                o,
                "- **{}** ({}): {}",
                md(&e.control),
                md(title),
                md(&e.note)
            );
        }
    }
    let passive = snapshot.observations.len();
    let _ = writeln!(
        o,
        "- Passive observations in this scan: {passive}; assets seen only passively are in the inventory with their source."
    );

    let _ = writeln!(o, "\n## Findings by control\n");
    let mut any = false;
    for c in &def.controls {
        let mut list: Vec<(usize, &Finding)> = vec![];
        for (i, r) in rows.iter().enumerate() {
            for f in &r.findings {
                if controls_for(s, &f.id).contains(&c.id.as_str()) {
                    list.push((i, f));
                }
            }
        }
        if list.is_empty() {
            continue;
        }
        any = true;
        list.sort_by(|a, b| b.1.severity.cmp(&a.1.severity).then(a.1.id.cmp(&b.1.id)));
        let _ = writeln!(
            o,
            "### {} {}\n\n| Severity | Finding | Asset | Port | Confidence |\n|---|---|---|---|---|",
            md(&c.id),
            md(&c.name)
        );
        for (i, f) in list {
            let _ = writeln!(
                o,
                "| {} | {} | {} | {} | {} |",
                f.severity.name(),
                md(&f.title),
                md(&asset_name(rows[i].device)),
                f.port.map_or(String::new(), |p| p.to_string()),
                if f.confidence > 0 {
                    format!("{} %", f.confidence)
                } else {
                    String::new()
                }
            );
        }
        o.push('\n');
    }
    if !any {
        o.push_str("No findings map to this framework.\n");
    }
    if !unmapped.is_empty() {
        let _ = writeln!(
            o,
            "\n## Findings without a mapping ({})\n\n| Severity | Finding | Asset |\n|---|---|---|",
            unmapped.len()
        );
        for (i, f) in unmapped {
            let _ = writeln!(
                o,
                "| {} | {} | {} |",
                f.severity.name(),
                md(&f.title),
                md(&asset_name(rows[i].device))
            );
        }
    }
    let worst = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Info);
    let _ = writeln!(
        o,
        "\nFindings in total: {}; highest severity: {}. Generated by Network Scope.",
        findings.len(),
        if findings.is_empty() {
            "none"
        } else {
            worst.name()
        }
    );
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        passive::Observation,
        scan::{Host, Settings},
    };

    fn host(ip: &str, mac: &str, open: &[u16], id: &[(&str, &str)]) -> Host {
        Host {
            ip: ip.parse().unwrap(),
            responding: true,
            ping: None,
            ttl: None,
            hostname: String::new(),
            mac: mac.into(),
            open: open.to_vec(),
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity: id
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            udp_open: vec![],
            trace: vec![],
        }
    }
    fn snapshot() -> Snapshot {
        Snapshot {
            sent: vec![],
            targets: "10.0.0.0/24 <x>".into(),
            complete: true,
            settings: Settings::default(),
            hosts: vec![
                host(
                    "10.0.0.5",
                    "00:11:22:33:44:55",
                    &[23, 443],
                    &[
                        ("svc.23", "telnet"),
                        ("tls.443.subject", "CN=x"),
                        ("tls.443.self_signed", "true"),
                    ],
                ),
                host(
                    "10.0.0.6",
                    "",
                    &[502],
                    &[("device.type", "Industrial controller / OT device")],
                ),
                host("10.0.0.7", "", &[80], &[("svc.80", "http")]),
            ],
            observations: vec![],
            notes: Default::default(),
        }
    }

    #[test]
    fn the_mapping_table_is_valid_and_covers_every_rule_id() {
        validate().unwrap();
        let (ids, _) = crate::risk::budget::source_rule_ids();
        assert!(ids.len() > 30);
        for id in &ids {
            assert!(
                is_mapped(id),
                "rule {id} has no entry in data/compliance.json"
            );
        }
        // The run-time families have an entry too.
        assert!(is_mapped("cve-cve-2024-6387") && is_mapped("script-lab"));
        // Every mapped rule names at least one control in each framework, except scripts.
        for id in &ids {
            for s in [Standard::Iec62443, Standard::Nis2, Standard::Cis] {
                assert!(!controls_for(s, id).is_empty(), "{id} {s:?}");
            }
        }
        assert!(controls_for(Standard::Cis, "script-lab").is_empty());
        // Unknown ids are not mapped (negative case).
        assert!(
            !is_mapped("no-such-rule") && controls_for(Standard::Nis2, "no-such-rule").is_empty()
        );
        assert_eq!(
            controls_for(Standard::Iec62443, "telnet-open"),
            ["FR 1", "FR 4"]
        );
        assert_eq!(
            controls_for(Standard::Cis, "cve-cve-2021-41773"),
            ["7.1", "7.2", "7.5", "7.7"]
        );
    }

    #[test]
    fn format_names_select_standard_and_layout() {
        assert_eq!(
            Standard::from_format("compliance-nis2"),
            Some((Standard::Nis2, false))
        );
        assert_eq!(
            Standard::from_format("compliance-cis-csv"),
            Some((Standard::Cis, true))
        );
        assert_eq!(
            Standard::from_format("compliance-iec62443-csv"),
            Some((Standard::Iec62443, true))
        );
        for bad in [
            "compliance-",
            "compliance-iso27001",
            "nis2",
            "csv",
            "compliance-nis2-md",
        ] {
            assert_eq!(Standard::from_format(bad), None, "{bad}");
        }
        // Through the shared export entry point (`export --format ...`).
        let s = snapshot();
        let md = crate::store::export_at(&s, "compliance-nis2", 0).unwrap();
        assert!(md.starts_with("# NIS2 asset inventory"));
        let csv = crate::store::export_at(&s, "compliance-cis-csv", 0).unwrap();
        assert!(csv.starts_with("asset,addresses"));
        let e = crate::store::export_at(&s, "compliance-iso27001", 0).unwrap_err();
        assert!(e.contains("compliance-nis2"), "{e}");
    }

    #[test]
    fn zones_and_criticality_follow_the_role() {
        let devs = devices::merge(&snapshot().hosts, &[]);
        let by = |ip: &str| devs.iter().find(|d| d.ips[0].to_string() == ip).unwrap();
        assert_eq!(zone_of(by("10.0.0.6")), "OT / control");
        assert_eq!(criticality_of(by("10.0.0.6")), "High");
        assert_eq!(zone_of(by("10.0.0.5")), "IT systems");
        assert_eq!(criticality_of(by("10.0.0.7")), "Unclassified");
        // A network device, a printer, a database server.
        let mk = |t: &str, ports: &[u16]| Device {
            device_type: t.into(),
            open_tcp: ports.to_vec(),
            ..Default::default()
        };
        assert_eq!(
            zone_of(&mk("Network device (router/switch/AP)", &[])),
            "Network infrastructure"
        );
        assert_eq!(
            criticality_of(&mk("Network device (router/switch/AP)", &[])),
            "High"
        );
        assert_eq!(
            zone_of(&mk("Printer / MFP", &[9100])),
            "Peripherals and IoT",
            "9100 is a printer port, not OT"
        );
        assert_eq!(criticality_of(&mk("Database server", &[5432])), "Medium");
        assert_eq!(zone_of(&mk("Linux/Unix host", &[44818])), "OT / control");
        assert_eq!(criticality_of(&mk("Linux/Unix host", &[44818])), "Medium");
        assert_eq!(criticality_of(&mk("Windows computer", &[445])), "Low");
    }

    #[test]
    fn markdown_export_has_inventory_coverage_and_findings_per_control() {
        let md = export(&snapshot(), Standard::Iec62443, false, 1_700_000_000);
        for want in [
            "# IEC 62443 asset inventory and findings",
            "2023-11-14 22:13 UTC",
            "## Asset inventory (3)",
            "| Zone | Criticality |",
            "OT / control",
            "## Control coverage",
            "| FR 1 | Identification and authentication control | 2 | 1 |",
            "### FR 4 Data confidentiality",
            "Telnet exposes credentials in clear text",
            "not** a compliance assessment",
            "10.0.0.0/24 &lt;x&gt;",
        ] {
            assert!(md.contains(want), "missing {want:?} in\n{md}");
        }
        // Controls without findings show a dash; the other frameworks have no zone column.
        assert!(
            md.contains("| FR 7 | Resource availability | - | - |"),
            "{md}"
        );
        let nis2 = export(&snapshot(), Standard::Nis2, false, 0);
        assert!(nis2.contains("# NIS2 asset inventory and findings"));
        assert!(nis2.contains("Art. 21(2)(h)") && !nis2.contains("| Zone |"));
        let cis = export(&snapshot(), Standard::Cis, false, 0);
        assert!(
            cis.contains("| 1.1 | Establish and Maintain Detailed Enterprise Asset Inventory"),
            "{cis}"
        );
        assert!(
            cis.contains("### 12.6 Use of Secure Network Management"),
            "{cis}"
        );
        assert!(cis.contains("**1.1** (Establish and Maintain Detailed"));
    }

    #[test]
    fn csv_export_has_one_row_per_asset_and_finding() {
        let csv = export(&snapshot(), Standard::Iec62443, true, 0);
        let lines: Vec<&str> = csv.split("\r\n").filter(|l| !l.is_empty()).collect();
        assert!(lines[0].starts_with("asset,addresses,mac,vendor,device_type,os,open_ports,zone,criticality,risk_score,finding_id"));
        // 10.0.0.5: telnet + self-signed; 10.0.0.6: ot-reachable; 10.0.0.7: no findings.
        assert_eq!(lines.len(), 1 + 2 + 1 + 1, "{csv}");
        assert!(csv.contains("telnet-open"));
        assert!(csv.contains("\"FR 1; FR 4\""), "{csv}");
        assert!(csv.contains("\"OT / control\",\"High\""), "{csv}");
        let quiet = lines.iter().find(|l| l.contains("10.0.0.7")).unwrap();
        assert!(
            quiet.ends_with(",\"\",\"\",\"\",\"\",\"\",\"\",\"\""),
            "{quiet}"
        );
        // Other frameworks: no zone columns, a user-script finding is "not mapped".
        let mut s = snapshot();
        s.hosts[2]
            .identity
            .insert("finding.script.lab".into(), "high|Lab|x".into());
        let cis = export(&s, Standard::Cis, true, 0);
        assert!(!cis.lines().next().unwrap().contains("zone"));
        assert!(cis.contains("not mapped"), "{cis}");
        // Formula-looking cells are neutralised by the shared CSV writer.
        let mut evil = snapshot();
        evil.hosts[2].hostname = "=cmd|' /C calc'!A0".into();
        let out = export(&evil, Standard::Nis2, true, 0);
        assert!(!out.contains(",\"=cmd") && !out.contains(",=cmd"), "{out}");
    }

    #[test]
    fn empty_and_passive_only_inventories_export_cleanly() {
        let empty = Snapshot {
            hosts: vec![],
            ..snapshot()
        };
        let md = export(&empty, Standard::Cis, false, 0);
        assert!(
            md.contains("## Asset inventory (0)")
                && md.contains("No findings map to this framework.")
        );
        assert_eq!(
            export(&empty, Standard::Nis2, true, 0)
                .split("\r\n")
                .count(),
            2
        );
        let passive = Snapshot {
            hosts: vec![],
            observations: vec![Observation {
                protocol: "LLDP".into(),
                mac: "AA:BB:CC:00:00:01".into(),
                ip: None,
                fields: [("name".to_string(), "sw".to_string())].into(),
            }],
            ..snapshot()
        };
        let md = export(&passive, Standard::Cis, false, 0);
        assert!(
            md.contains("## Asset inventory (1)")
                && md.contains("Passive observations in this scan: 1")
        );
        // A partial scan says so.
        let partial = Snapshot {
            complete: false,
            ..snapshot()
        };
        assert!(export(&partial, Standard::Nis2, false, 0).contains("PARTIAL scan"));
    }
}
