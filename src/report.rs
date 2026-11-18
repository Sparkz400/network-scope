//! Self-contained HTML report: summary, charts (inline SVG, no scripts), findings, changes since a
//! baseline, topology map, devices and per-host details. All scanned content is escaped.
use crate::{
    devices, risk,
    risk::Severity,
    scan::Host,
    store::{self, Snapshot},
    topology,
};
use std::{collections::BTreeMap, fmt::Write as _};

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() && c != '\n' => {}
            c => out.push(c),
        }
    }
    out
}

pub fn fmt_time(ts: i64) -> String {
    if ts <= 0 {
        return "time not recorded".into();
    }
    let secs = ts.rem_euclid(86_400);
    format!(
        "{} {:02}:{:02} UTC",
        crate::tls::date(ts),
        secs / 3600,
        secs % 3600 / 60
    )
}

fn sev_color(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "#9b1c1c",
        Severity::High => "#d9480f",
        Severity::Medium => "#e8a317",
        Severity::Low => "#2b6cb0",
        Severity::Info => "#718096",
    }
}
const PALETTE: [&str; 8] = [
    "#2b6cb0", "#2f855a", "#d9480f", "#805ad5", "#e8a317", "#319795", "#b83280", "#718096",
];

fn bars(items: &[(String, usize)], colors: &dyn Fn(usize, &str) -> String) -> String {
    if items.is_empty() {
        return "<p class=\"muted\">No data.</p>".into();
    }
    let max = items.iter().map(|i| i.1).max().unwrap_or(1).max(1);
    let height = items.len() * 24 + 8;
    let mut s = format!(
        "<svg role=\"img\" viewBox=\"0 0 440 {height}\" width=\"440\" height=\"{height}\">"
    );
    for (i, (label, n)) in items.iter().enumerate() {
        let y = 4 + i * 24;
        let w = (*n as f64 / max as f64 * 230.0).max(2.0);
        let label: String = label.chars().take(22).collect();
        let _ = write!(
            s,
            "<text x=\"126\" y=\"{}\" text-anchor=\"end\" font-size=\"12\" fill=\"#173041\">{}</text><rect x=\"134\" y=\"{y}\" width=\"{w:.1}\" height=\"16\" rx=\"2\" fill=\"{}\"/><text x=\"{:.1}\" y=\"{}\" font-size=\"12\" fill=\"#173041\">{n}</text>",
            y + 12,
            esc(&label),
            colors(i, &label),
            134.0 + w + 6.0,
            y + 12
        );
    }
    s.push_str("</svg>");
    s
}

fn donut(items: &[(String, usize)]) -> String {
    let total: usize = items.iter().map(|i| i.1).sum();
    if total == 0 {
        return "<p class=\"muted\">No data.</p>".into();
    }
    let (cx, cy, r, ri) = (90.0_f64, 90.0_f64, 80.0_f64, 46.0_f64);
    let mut s = String::from("<div class=\"donut\"><svg role=\"img\" viewBox=\"0 0 180 180\" width=\"180\" height=\"180\">");
    let mut angle = -std::f64::consts::FRAC_PI_2;
    for (i, (_, n)) in items.iter().enumerate() {
        let color = PALETTE[i % PALETTE.len()];
        let sweep = *n as f64 / total as f64 * std::f64::consts::TAU;
        if items.len() == 1 {
            let _ = write!(s, "<circle cx=\"{cx}\" cy=\"{cy}\" r=\"{}\" fill=\"none\" stroke=\"{color}\" stroke-width=\"{}\"/>", (r + ri) / 2.0, r - ri);
            break;
        }
        let (a1, a2) = (angle, angle + sweep);
        let p = |rad: f64, a: f64| (cx + rad * a.cos(), cy + rad * a.sin());
        let ((x1, y1), (x2, y2), (x3, y3), (x4, y4)) = (p(r, a1), p(r, a2), p(ri, a2), p(ri, a1));
        let large = u8::from(sweep > std::f64::consts::PI);
        let _ = write!(
            s,
            "<path d=\"M{x1:.2} {y1:.2} A{r} {r} 0 {large} 1 {x2:.2} {y2:.2} L{x3:.2} {y3:.2} A{ri} {ri} 0 {large} 0 {x4:.2} {y4:.2}Z\" fill=\"{color}\"/>"
        );
        angle = a2;
    }
    s.push_str("</svg><ul>");
    for (i, (label, n)) in items.iter().enumerate() {
        let _ = write!(
            s,
            "<li><span class=\"dot\" style=\"background:{}\"></span>{} <b>{n}</b></li>",
            PALETTE[i % PALETTE.len()],
            esc(label)
        );
    }
    s.push_str("</ul></div>");
    s
}

fn topology_svg(hosts: &[Host]) -> String {
    let g = topology::build(hosts);
    if g.nodes.len() <= 1 {
        return "<p class=\"muted\">No path data. Scan with traceroute enabled (--trace) to see the network map.</p>".into();
    }
    if g.nodes.len() > 400 {
        return format!("<p class=\"muted\">{} nodes: too many to draw. Use <code>topology --format dot</code> and Graphviz.</p>", g.nodes.len());
    }
    let layers = topology::layers(&g);
    let (col, row) = (190.0, 26.0);
    let rows = layers.iter().map(Vec::len).max().unwrap_or(1).max(1);
    let (w, h) = (layers.len() as f64 * col + 40.0, rows as f64 * row + 30.0);
    let mut at = vec![(0.0, 0.0); g.nodes.len()];
    for (x, layer) in layers.iter().enumerate() {
        for (y, &n) in layer.iter().enumerate() {
            at[n] = (20.0 + x as f64 * col, 18.0 + y as f64 * row);
        }
    }
    let mut s = format!("<div class=\"scroll\"><svg role=\"img\" viewBox=\"0 0 {w} {h}\" width=\"{w}\" height=\"{h}\">");
    for &(a, b) in &g.edges {
        let _ = write!(
            s,
            "<line x1=\"{:.1}\" y1=\"{:.1}\" x2=\"{:.1}\" y2=\"{:.1}\" stroke=\"#a0aec0\"/>",
            at[a].0, at[a].1, at[b].0, at[b].1
        );
    }
    for (i, n) in g.nodes.iter().enumerate() {
        let color = match n.kind {
            topology::Kind::Source => "#2b6cb0",
            topology::Kind::Router => "#718096",
            topology::Kind::Host => "#2f855a",
            topology::Kind::Unknown => "#cbd5e0",
        };
        let label: String = n.label.chars().take(28).collect();
        let _ = write!(
            s,
            "<circle cx=\"{:.1}\" cy=\"{:.1}\" r=\"6\" fill=\"{color}\"/><text x=\"{:.1}\" y=\"{:.1}\" font-size=\"12\" fill=\"#173041\">{}<title>{}</title></text>",
            at[i].0,
            at[i].1,
            at[i].0 + 10.0,
            at[i].1 + 4.0,
            esc(&label),
            esc(&format!("{} {}", n.label, n.detail))
        );
    }
    s.push_str("</svg></div>");
    s
}

fn cve_links(ids: &[String]) -> String {
    ids.iter()
        .map(|id| {
            let ok = id.len() < 24
                && id.starts_with("CVE-")
                && id[4..].chars().all(|c| c.is_ascii_digit() || c == '-');
            if ok {
                format!(
                    "<a href=\"https://nvd.nist.gov/vuln/detail/{id}\" rel=\"noreferrer\">{id}</a>"
                )
            } else {
                esc(id)
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn top_counts(map: BTreeMap<String, usize>, limit: usize) -> Vec<(String, usize)> {
    let mut v: Vec<_> = map.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    v.truncate(limit);
    v
}

pub fn html(snapshot: &Snapshot, baseline: Option<(&Snapshot, i64)>, timestamp: i64) -> String {
    let findings = risk::analyze_snapshot(snapshot);
    let counts = risk::counts(&findings);
    let devs = devices::merge(&snapshot.hosts, &snapshot.observations);
    let up = snapshot.hosts.iter().filter(|h| h.responding).count();
    let mut o = String::with_capacity(64 * 1024);
    let _ = write!(
        o,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\"><title>Network Scope report</title><style>{CSS}</style></head><body>"
    );
    let _ = write!(
        o,
        "<h1>Network Scope report</h1><p class=\"muted\">Scope <b>{}</b> &middot; {} &middot; {}</p>",
        esc(&snapshot.targets),
        if snapshot.complete { "completed scan" } else { "PARTIAL scan (interrupted); absence of a host proves nothing" },
        fmt_time(timestamp)
    );
    let open_ports: usize = snapshot
        .hosts
        .iter()
        .map(|h| h.open.len() + h.udp_open.len())
        .sum();
    o.push_str("<div class=\"cards\">");
    for (label, value, color) in [
        (
            "Hosts responding",
            format!("{up} / {}", snapshot.hosts.len()),
            "#2f855a",
        ),
        ("Devices", devs.len().to_string(), "#2b6cb0"),
        ("Open ports", open_ports.to_string(), "#805ad5"),
        (
            "Findings",
            findings.len().to_string(),
            if findings.iter().any(|f| f.severity >= Severity::High) {
                "#d9480f"
            } else {
                "#718096"
            },
        ),
    ] {
        let _ = write!(o, "<div class=\"card\" style=\"border-top:4px solid {color}\"><div class=\"big\">{}</div>{label}</div>", esc(&value));
    }
    o.push_str("</div><h2>Charts</h2><div class=\"charts\">");
    let sev: Vec<(String, usize)> = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ]
    .into_iter()
    .map(|s| (s.name().to_string(), counts.get(&s).copied().unwrap_or(0)))
    .collect();
    o.push_str("<div><h3>Findings by severity</h3>");
    o.push_str(&bars(&sev, &|_, label| {
        sev_color(Severity::parse(label).unwrap_or(Severity::Info)).to_string()
    }));
    let mut port_counts = BTreeMap::new();
    for h in snapshot.hosts.iter().filter(|h| h.responding) {
        for p in &h.open {
            let name = h
                .identity
                .get(&format!("svc.{p}"))
                .and_then(|s| s.split_whitespace().next())
                .filter(|n| *n != "unidentified")
                .map(|n| format!("{p} {n}"))
                .unwrap_or_else(|| p.to_string());
            *port_counts.entry(name).or_insert(0) += 1;
        }
        for p in &h.udp_open {
            *port_counts.entry(format!("{p}/udp")).or_insert(0) += 1;
        }
    }
    o.push_str("</div><div><h3>Most common open ports</h3>");
    o.push_str(&bars(&top_counts(port_counts, 10), &|i, _| {
        PALETTE[i % PALETTE.len()].to_string()
    }));
    let mut types = BTreeMap::new();
    for d in &devs {
        *types
            .entry(if d.device_type.is_empty() {
                "Unclassified".to_string()
            } else {
                d.device_type.clone()
            })
            .or_insert(0) += 1;
    }
    o.push_str("</div><div><h3>Device types</h3>");
    o.push_str(&donut(&top_counts(types, 8)));
    let mut oses = BTreeMap::new();
    for h in snapshot.hosts.iter().filter(|h| h.responding) {
        if let Some(os) = h.identity.get("os.guess") {
            *oses.entry(os.clone()).or_insert(0) += 1;
        }
    }
    o.push_str("</div><div><h3>OS families (guess)</h3>");
    o.push_str(&bars(&top_counts(oses, 8), &|i, _| {
        PALETTE[i % PALETTE.len()].to_string()
    }));
    o.push_str("</div></div>");

    let _ = write!(o, "<h2>Findings ({})</h2>", findings.len());
    if findings.is_empty() {
        o.push_str("<p class=\"muted\">Nothing found. Enable --services to collect the evidence these checks need.</p>");
    } else {
        o.push_str("<p class=\"muted\">CVE entries are version-based hints, not confirmed vulnerabilities; vendors often backport fixes.</p><table><tr><th>Severity</th><th>Finding</th><th>Host</th><th>Evidence</th><th>CVE</th><th>Advice</th></tr>");
        for f in &findings {
            let _ = write!(
                o,
                "<tr><td><span class=\"badge\" style=\"background:{}\">{}</span></td><td>{}</td><td>{}{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                sev_color(f.severity),
                f.severity.name(),
                esc(&f.title),
                f.ip,
                f.port.map_or(String::new(), |p| format!(":{p}")),
                esc(&f.evidence),
                cve_links(&f.cve),
                esc(&f.advice)
            );
        }
        o.push_str("</table>");
    }

    if let Some((base, base_ts)) = baseline {
        let _ = write!(o, "<h2>Changes since {}</h2>", fmt_time(base_ts));
        match store::diff(base, snapshot) {
            Ok(changes) if changes.is_empty() => o.push_str("<p class=\"muted\">No changes.</p>"),
            Ok(changes) => {
                o.push_str("<ul>");
                for c in changes {
                    let _ = write!(o, "<li>{}</li>", esc(&c));
                }
                o.push_str("</ul>");
            }
            Err(e) => {
                let _ = write!(o, "<p class=\"muted\">{}</p>", esc(&e));
            }
        }
    }

    o.push_str("<h2>Network map</h2>");
    o.push_str(&topology_svg(&snapshot.hosts));

    let _ = write!(o, "<h2>Devices ({})</h2><div class=\"scroll\"><table><tr><th>Address</th><th>MAC / manufacturer</th><th>Type</th><th>OS (guess)</th><th>Open ports</th><th>Seen by</th></tr>", devs.len());
    for d in &devs {
        let ports: Vec<String> = d
            .open_tcp
            .iter()
            .map(u16::to_string)
            .chain(d.open_udp.iter().map(|p| format!("{p}/udp")))
            .collect();
        let _ = write!(
            o,
            "<tr><td>{}<br><span class=\"muted\">{}</span></td><td>{}<br><span class=\"muted\">{}</span></td><td title=\"{}\">{}</td><td>{} {}</td><td>{}</td><td>{}</td></tr>",
            esc(&d.ips.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")),
            esc(&d.hostnames.join(", ")),
            esc(&d.mac),
            esc(&if d.randomized_mac { "randomized/locally administered".to_string() } else { d.vendor.clone() }),
            esc(&d.type_evidence),
            esc(&d.device_type),
            esc(&d.os),
            esc(&d.os_confidence),
            esc(&ports.join(", ")),
            esc(&d.sources.join("; "))
        );
    }
    o.push_str("</table></div><h2>Host details</h2>");
    for h in snapshot.hosts.iter().filter(|h| h.responding) {
        let _ = write!(
            o,
            "<details><summary>{} {}</summary><table>",
            h.ip,
            esc(&h.hostname)
        );
        for (k, v) in &h.identity {
            let _ = write!(o, "<tr><td>{}</td><td>{}</td></tr>", esc(k), esc(v));
        }
        if !h.errors.is_empty() {
            let _ = write!(
                o,
                "<tr><td>probe notes</td><td>{}</td></tr>",
                esc(&h.errors.join("; "))
            );
        }
        if let Some(note) = snapshot.notes.get(&h.ip) {
            let _ = write!(o, "<tr><td>note</td><td>{}</td></tr>", esc(note));
        }
        o.push_str("</table></details>");
    }
    if !snapshot.observations.is_empty() {
        let _ = write!(o, "<h2>Passive observations ({})</h2><div class=\"scroll\"><table><tr><th>Protocol</th><th>MAC</th><th>IP</th><th>Fields</th></tr>", snapshot.observations.len());
        for ob in &snapshot.observations {
            let _ = write!(
                o,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td><pre>{}</pre></td></tr>",
                esc(&ob.protocol),
                esc(&ob.mac),
                ob.ip.map_or(String::new(), |i| i.to_string()),
                esc(&ob
                    .fields
                    .iter()
                    .map(|(k, v)| format!("{k}: {v}"))
                    .collect::<Vec<_>>()
                    .join("\n"))
            );
        }
        o.push_str("</table></div>");
    }
    o.push_str("<p class=\"muted\">Generated by Network Scope. Device types, OS families and CVE entries are heuristics.</p></body></html>");
    o
}

const CSS: &str = "body{font:14px/1.45 system-ui,Segoe UI,sans-serif;margin:32px;color:#173041;max-width:1280px}h1{margin:0 0 4px}h2{margin-top:36px;border-bottom:2px solid #eaf1f5;padding-bottom:6px}h3{margin:0 0 6px;font-size:14px}.muted{color:#6b7c8a}.cards{display:flex;gap:16px;flex-wrap:wrap;margin:18px 0}.card{background:#f6f9fb;padding:14px 20px;min-width:150px;border-radius:4px}.big{font-size:28px;font-weight:600}.charts{display:flex;gap:36px;flex-wrap:wrap}.donut{display:flex;gap:16px;align-items:center}.donut ul{list-style:none;padding:0;margin:0}.dot{display:inline-block;width:10px;height:10px;border-radius:5px;margin-right:6px}table{border-collapse:collapse;width:100%;margin:8px 0}td,th{padding:8px 10px;border-bottom:1px solid #e1e8ed;text-align:left;vertical-align:top}th{background:#eaf1f5}pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:0}.badge{color:#fff;padding:2px 8px;border-radius:10px;font-size:12px;text-transform:uppercase}details{margin:4px 0}summary{cursor:pointer;padding:4px 0}.scroll{overflow:auto}@media print{details{display:block}body{margin:12px}}";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{passive::Observation, scan::Settings, trace::Hop};

    fn host(ip: &str, open: &[u16], id: &[(&str, &str)], trace: &[(u8, Option<&str>)]) -> Host {
        Host {
            ip: ip.parse().unwrap(),
            responding: true,
            ping: None,
            ttl: None,
            hostname: "<img src=x onerror=alert(1)>".into(),
            mac: "00:0C:29:00:00:01".into(),
            open: open.to_vec(),
            closed: 0,
            unanswered: 0,
            errors: vec!["<b>note</b>".into()],
            ports_checked: true,
            identity: id
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            udp_open: vec![],
            trace: trace
                .iter()
                .map(|(t, i)| Hop {
                    ttl: *t,
                    ip: i.map(|s| s.parse().unwrap()),
                    rtt: Some(1),
                })
                .collect(),
        }
    }
    fn snapshot() -> Snapshot {
        Snapshot {
            targets: "10.0.0.0/24 <script>".into(),
            complete: true,
            settings: Settings::default(),
            hosts: vec![
                host(
                    "10.0.0.5",
                    &[23, 80],
                    &[
                        ("svc.23", "telnet"),
                        ("svc.80", "http nginx 1.18.0 (200 OK)"),
                        ("svc.80.product", "nginx"),
                        ("svc.80.version", "1.18.0"),
                        ("os.guess", "Linux"),
                        ("http.80.title", "</title><script>alert(1)</script>"),
                    ],
                    &[(1, Some("10.0.0.1")), (2, Some("10.0.0.5"))],
                ),
                host(
                    "10.0.0.6",
                    &[445],
                    &[("svc.445", "microsoft-ds SMB 3.1.1 (signing required)")],
                    &[],
                ),
            ],
            observations: vec![Observation {
                protocol: "LLDP".into(),
                mac: "AA:BB:CC:00:00:01".into(),
                ip: None,
                fields: [("name".to_string(), "<sw>".to_string())].into(),
            }],
            notes: [("10.0.0.5".parse().unwrap(), "note \" & <x>".to_string())].into(),
        }
    }

    #[test]
    fn report_has_all_sections_and_escapes_everything() {
        let html = html(&snapshot(), None, 1_700_000_000);
        for section in [
            "Network Scope report",
            "Findings by severity",
            "Most common open ports",
            "Device types",
            "Findings (",
            "Network map",
            "Devices (",
            "Host details",
            "Passive observations",
        ] {
            assert!(html.contains(section), "missing {section}");
        }
        assert!(html.contains("2023-11-14 22:13 UTC"));
        assert!(html.contains("Telnet exposes credentials"));
        assert!(html.contains("<svg"));
        for raw in ["<script", "<img src=x", "<b>note</b>", "<sw>", "<x>"] {
            assert!(!html.contains(raw), "unescaped content: {raw}");
        }
        assert!(html.contains("&lt;script&gt;") && html.contains("&lt;img src=x"));
        assert!(html.contains("Content-Security-Policy"));
        assert!(
            !html.contains("<script"),
            "the report itself must not contain scripts"
        );
    }

    #[test]
    fn partial_scans_are_labelled_and_baseline_changes_listed() {
        let mut base = snapshot();
        let mut now = snapshot();
        base.hosts[0].open = vec![23];
        now.hosts[0].open = vec![23, 80, 8080];
        let html = html(&now, Some((&base, 1_600_000_000)), 1_700_000_000);
        assert!(html.contains("Changes since 2020-09-13"));
        assert!(html.contains("port 80 newly open") || html.contains("port 8080 newly open"));
        now.complete = false;
        assert!(super::html(&now, Some((&base, 1)), 0).contains("PARTIAL scan"));
        assert!(super::html(&now, None, 0).contains("time not recorded"));
    }

    #[test]
    fn charts_handle_edge_cases() {
        assert!(donut(&[]).contains("No data"));
        assert!(donut(&[("only".into(), 3)]).contains("<circle"));
        let two = donut(&[("a".into(), 1), ("b".into(), 1)]);
        assert_eq!(two.matches("<path").count(), 2);
        assert!(bars(&[], &|_, _| "#000".into()).contains("No data"));
        let b = bars(&[("<x>".into(), 0), ("y".into(), 5)], &|_, _| "#000".into());
        assert!(b.contains("&lt;x&gt;") && !b.contains("<x>"));
        assert!(cve_links(&["CVE-2024-6387".into()]).contains("nvd.nist.gov"));
        assert!(!cve_links(&["javascript:alert(1)\"".into()]).contains("<a "));
        let empty = Snapshot {
            targets: String::new(),
            complete: true,
            settings: Settings::default(),
            hosts: vec![],
            observations: vec![],
            notes: Default::default(),
        };
        let h = html(&empty, None, 0);
        assert!(h.contains("Nothing found") && h.contains("No path data"));
    }
}
