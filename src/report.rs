//! Self-contained HTML report: summary, charts (inline SVG, no scripts), findings, changes since a
//! baseline, topology map, devices and per-host details. All scanned content is escaped.
use crate::{
    devices, risk,
    risk::Severity,
    scan::Host,
    store::{self, Snapshot},
    topology,
};
use std::{collections::BTreeMap, fmt::Write as _, net::IpAddr};

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
    let cpes = Cpes::new(snapshot);
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
        o.push_str("<p class=\"muted\">CVE entries are version-based hints, not confirmed vulnerabilities; vendors often backport fixes.</p>");
        o.push_str(&findings_table(&findings, &cpes));
        let by_host = findings_by_host(snapshot, &findings);
        let _ = write!(
            o,
            "<h3>Findings by host ({})</h3><p class=\"muted\">Sorted by the most severe finding, then by count.</p><div class=\"scroll\"><table><tr><th>Host</th><th>Highest</th>",
            by_host.len()
        );
        for sev in SEVERITIES {
            let _ = write!(o, "<th>{}</th>", sev.name());
        }
        o.push_str("<th>Total</th></tr>");
        for h in &by_host {
            let _ = write!(
                o,
                "<tr><td>{}<br><span class=\"muted\">{}</span></td><td><span class=\"badge\" style=\"background:{}\">{}</span></td>",
                h.ip,
                esc(&h.hostname),
                sev_color(h.worst),
                h.worst.name()
            );
            for n in h.counts {
                let _ = write!(o, "<td>{n}</td>");
            }
            let _ = write!(o, "<td><b>{}</b></td></tr>", h.total());
        }
        o.push_str("</table></div>");
    }

    if let Some((base, base_ts)) = baseline {
        let _ = write!(o, "<h2>Changes since {}</h2>", fmt_time(base_ts));
        match store::diff_report(base, snapshot, &store::IgnoreList::new(&[])) {
            Ok(report) => {
                if report.changes.is_empty() {
                    o.push_str("<p class=\"muted\">No changes.</p>");
                } else {
                    o.push_str("<ul>");
                    for c in report.lines() {
                        let _ = write!(o, "<li>{}</li>", esc(&c));
                    }
                    o.push_str("</ul>");
                }
                for (title, list) in [
                    ("New findings", &report.new_findings),
                    ("Resolved findings", &report.resolved_findings),
                    (
                        "Findings not re-checked (host did not respond)",
                        &report.unconfirmed_findings,
                    ),
                ] {
                    if list.is_empty() && title.starts_with("Findings not") {
                        continue;
                    }
                    let _ = write!(o, "<h3>{title} ({})</h3>", list.len());
                    if list.is_empty() {
                        o.push_str("<p class=\"muted\">None.</p>");
                    } else {
                        o.push_str(&findings_table(list, &cpes));
                    }
                }
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

const SEVERITIES: [Severity; 5] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::Info,
];

/// `svc.<port>.cpe` values per host; `any` is false when no host recorded a CPE.
struct Cpes<'a> {
    hosts: BTreeMap<IpAddr, &'a Host>,
    any: bool,
}

impl<'a> Cpes<'a> {
    fn new(snapshot: &'a Snapshot) -> Self {
        let any = snapshot
            .hosts
            .iter()
            .any(|h| h.identity.keys().any(|k| is_cpe_key(k)));
        Self {
            hosts: snapshot.hosts.iter().map(|h| (h.ip, h)).collect(),
            any,
        }
    }
    fn get(&self, ip: IpAddr, port: Option<u16>) -> Option<&'a str> {
        let port = port?;
        self.hosts
            .get(&ip)?
            .identity
            .get(&format!("svc.{port}.cpe"))
            .map(String::as_str)
    }
}

fn is_cpe_key(k: &str) -> bool {
    k.strip_prefix("svc.")
        .and_then(|r| r.strip_suffix(".cpe"))
        .is_some_and(|p| p.parse::<u16>().is_ok())
}

/// Findings table; the CPE column appears only when some host carries `svc.<port>.cpe`.
fn findings_table(findings: &[risk::Finding], cpes: &Cpes) -> String {
    let mut o = String::from(
        "<div class=\"scroll\"><table><tr><th>Severity</th><th>Finding</th><th>Host</th>",
    );
    if cpes.any {
        o.push_str("<th>CPE</th>");
    }
    o.push_str("<th>Evidence</th><th>CVE</th><th>Advice</th></tr>");
    for f in findings {
        let _ = write!(
            o,
            "<tr><td><span class=\"badge\" style=\"background:{}\">{}</span></td><td>{}</td><td>{}{}</td>",
            sev_color(f.severity),
            f.severity.name(),
            esc(&f.title),
            f.ip,
            f.port.map_or(String::new(), |p| format!(":{p}")),
        );
        if cpes.any {
            let _ = write!(
                o,
                "<td><code>{}</code></td>",
                esc(cpes.get(f.ip, f.port).unwrap_or(""))
            );
        }
        let _ = write!(
            o,
            "<td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&f.evidence),
            cve_links(&f.cve),
            esc(&f.advice)
        );
    }
    o.push_str("</table></div>");
    o
}

/// Finding counts of one host, most severe first (critical, high, medium, low, info).
#[derive(Clone, Debug, PartialEq)]
pub struct HostFindings {
    pub ip: IpAddr,
    pub hostname: String,
    pub counts: [usize; 5],
    pub worst: Severity,
}

impl HostFindings {
    pub fn total(&self) -> usize {
        self.counts.iter().sum()
    }
}

/// One row per host with findings, sorted by its most severe finding, then by the counts from
/// critical down, then by address (the report has no scripts, so the order is fixed here).
pub fn findings_by_host(snapshot: &Snapshot, findings: &[risk::Finding]) -> Vec<HostFindings> {
    let names: BTreeMap<IpAddr, &str> = snapshot
        .hosts
        .iter()
        .map(|h| (h.ip, h.hostname.as_str()))
        .collect();
    let mut rows: BTreeMap<IpAddr, HostFindings> = BTreeMap::new();
    for f in findings {
        let row = rows.entry(f.ip).or_insert_with(|| HostFindings {
            ip: f.ip,
            hostname: names.get(&f.ip).copied().unwrap_or("").to_string(),
            counts: [0; 5],
            worst: f.severity,
        });
        let i = SEVERITIES
            .iter()
            .position(|s| *s == f.severity)
            .unwrap_or(4);
        row.counts[i] += 1;
        row.worst = row.worst.max(f.severity);
    }
    let mut rows: Vec<_> = rows.into_values().collect();
    rows.sort_by(|a, b| {
        b.worst
            .cmp(&a.worst)
            .then(b.counts.cmp(&a.counts))
            .then(a.ip.cmp(&b.ip))
    });
    rows
}

/// Markdown table cell / inline text: no table breaks, no raw HTML, no Markdown markup.
fn md(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '|' | '\\' | '`' | '*' | '_' | '[' | ']' | '#' | '!' => {
                out.push('\\');
                out.push(c);
            }
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '\n' | '\r' | '\t' => out.push(' '),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// Markdown summary: scope, totals, findings by severity and by host, the findings, changes
/// since a baseline (with new and resolved findings) and the device list.
pub fn markdown(snapshot: &Snapshot, baseline: Option<(&Snapshot, i64)>, timestamp: i64) -> String {
    let findings = risk::analyze_snapshot(snapshot);
    let counts = risk::counts(&findings);
    let devs = devices::merge(&snapshot.hosts, &snapshot.observations);
    let cpes = Cpes::new(snapshot);
    let up = snapshot.hosts.iter().filter(|h| h.responding).count();
    let open_ports: usize = snapshot
        .hosts
        .iter()
        .map(|h| h.open.len() + h.udp_open.len())
        .sum();
    let mut o = String::from("# Network Scope summary\n\n");
    let _ = writeln!(
        o,
        "Scope: {}  \nStatus: {}  \nTime: {}\n",
        md(&snapshot.targets),
        if snapshot.complete {
            "completed scan"
        } else {
            "PARTIAL scan (interrupted); absence of a host proves nothing"
        },
        fmt_time(timestamp)
    );
    let _ = writeln!(
        o,
        "| Hosts responding | Devices | Open ports | Findings |\n|---|---|---|---|\n| {up} / {} | {} | {open_ports} | {} |\n",
        snapshot.hosts.len(),
        devs.len(),
        findings.len()
    );
    o.push_str("## Findings by severity\n\n| Severity | Count |\n|---|---|\n");
    for sev in SEVERITIES {
        let _ = writeln!(
            o,
            "| {} | {} |",
            sev.name(),
            counts.get(&sev).copied().unwrap_or(0)
        );
    }
    let md_findings = |o: &mut String, list: &[risk::Finding]| {
        o.push_str("| Severity | Finding | Host |");
        if cpes.any {
            o.push_str(" CPE |");
        }
        o.push_str(" Evidence | CVE |\n|---|---|---|");
        if cpes.any {
            o.push_str("---|");
        }
        o.push_str("---|---|\n");
        for f in list {
            let _ = write!(
                o,
                "| {} | {} | {}{} |",
                f.severity.name(),
                md(&f.title),
                f.ip,
                f.port.map_or(String::new(), |p| format!(":{p}"))
            );
            if cpes.any {
                let _ = write!(o, " {} |", md(cpes.get(f.ip, f.port).unwrap_or("")));
            }
            let _ = writeln!(o, " {} | {} |", md(&f.evidence), md(&f.cve.join(", ")));
        }
    };
    let _ = writeln!(o, "\n## Findings ({})\n", findings.len());
    if findings.is_empty() {
        o.push_str("Nothing found. Enable --services to collect the evidence these checks need.\n");
    } else {
        o.push_str("CVE entries are version-based hints, not confirmed vulnerabilities.\n\n");
        md_findings(&mut o, &findings);
        o.push_str("\n### Findings by host\n\n| Host | Highest | critical | high | medium | low | info | Total |\n|---|---|---|---|---|---|---|---|\n");
        for h in findings_by_host(snapshot, &findings) {
            let host = if h.hostname.is_empty() {
                h.ip.to_string()
            } else {
                format!("{} ({})", h.ip, md(&h.hostname))
            };
            let _ = write!(o, "| {host} | {} |", h.worst.name());
            for n in h.counts {
                let _ = write!(o, " {n} |");
            }
            let _ = writeln!(o, " {} |", h.total());
        }
    }
    if let Some((base, base_ts)) = baseline {
        let _ = writeln!(o, "\n## Changes since {}\n", fmt_time(base_ts));
        match store::diff_report(base, snapshot, &store::IgnoreList::new(&[])) {
            Ok(report) => {
                if report.changes.is_empty() {
                    o.push_str("No changes.\n");
                }
                for line in report.lines() {
                    let _ = writeln!(o, "- {}", md(&line));
                }
                for (title, list) in [
                    ("New findings", &report.new_findings),
                    ("Resolved findings", &report.resolved_findings),
                    (
                        "Findings not re-checked (host did not respond)",
                        &report.unconfirmed_findings,
                    ),
                ] {
                    if !list.is_empty() {
                        let _ = writeln!(o, "\n### {title} ({})\n", list.len());
                        md_findings(&mut o, list);
                    }
                }
            }
            Err(e) => {
                let _ = writeln!(o, "{}", md(&e));
            }
        }
    }
    let _ = writeln!(
        o,
        "\n## Devices ({})\n\n| Address | MAC | Vendor | Type | OS (guess) | Open ports |\n|---|---|---|---|---|---|",
        devs.len()
    );
    for d in &devs {
        let ports: Vec<String> = d
            .open_tcp
            .iter()
            .map(u16::to_string)
            .chain(d.open_udp.iter().map(|p| format!("{p}/udp")))
            .collect();
        let ips = d
            .ips
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(
            o,
            "| {} | {} | {} | {} | {} | {} |",
            md(&ips),
            md(&d.mac),
            md(&d.vendor),
            md(&d.device_type),
            md(&d.os),
            md(&ports.join(", "))
        );
    }
    o.push_str(
        "\nGenerated by Network Scope. Device types, OS families and CVE entries are heuristics.\n",
    );
    o
}

/// One compact JSON object per responding host (JSON Lines), for log pipelines and SIEMs.
pub fn jsonl(snapshot: &Snapshot, timestamp: i64) -> Result<String, String> {
    let findings = risk::analyze_snapshot(snapshot);
    let devs = devices::merge(&snapshot.hosts, &snapshot.observations);
    let mut out = String::new();
    for h in snapshot.hosts.iter().filter(|h| h.responding) {
        let dev = devs.iter().find(|d| d.ips.contains(&h.ip));
        let id = |k: String| h.identity.get(&k).cloned();
        let tcp = h.open.iter().map(|&port| {
            serde_json::json!({
                "port": port,
                "protocol": "tcp",
                "summary": id(format!("svc.{port}")),
                "product": id(format!("svc.{port}.product")),
                "version": id(format!("svc.{port}.version")),
                "cpe": id(format!("svc.{port}.cpe")),
            })
        });
        let udp = h.udp_open.iter().map(|&port| {
            serde_json::json!({
                "port": port,
                "protocol": "udp",
                "summary": id(format!("udp.{port}")),
            })
        });
        let services: Vec<serde_json::Value> = tcp.chain(udp).collect();
        let host_findings: Vec<serde_json::Value> = findings
            .iter()
            .filter(|f| f.ip == h.ip)
            .map(|f| {
                serde_json::json!({
                    "key": f.key(),
                    "severity": f.severity,
                    "id": f.id,
                    "title": f.title,
                    "port": f.port,
                    "evidence": f.evidence,
                    "cve": f.cve,
                })
            })
            .collect();
        let record = serde_json::json!({
            "timestamp": timestamp,
            "scope": snapshot.targets,
            "complete": snapshot.complete,
            "ip": h.ip,
            "mac": h.mac,
            "vendor": dev.map(|d| d.vendor.as_str()).unwrap_or(""),
            "hostname": h.hostname,
            "device_type": dev.map(|d| d.device_type.as_str()).unwrap_or(""),
            "os": h.identity.get("os.guess"),
            "open_tcp": h.open,
            "open_udp": h.udp_open,
            "services": services,
            "findings": host_findings,
            "identity": h.identity,
            "note": snapshot.notes.get(&h.ip),
        });
        out.push_str(&serde_json::to_string(&record).map_err(|e| e.to_string())?);
        out.push('\n');
    }
    Ok(out)
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

    #[test]
    fn findings_by_host_is_sorted_by_severity_then_count() {
        let mut s = snapshot();
        // .6 gets a critical finding (Redis without auth), .5 has High (telnet) + more findings.
        s.hosts[1].open = vec![6379];
        s.hosts[1].identity = [
            ("svc.6379".to_string(), "redis Redis 7.0".to_string()),
            ("svc.6379.version".to_string(), "7.0".to_string()),
        ]
        .into();
        s.hosts
            .push(host("10.0.0.4", &[21], &[("svc.21", "ftp")], &[]));
        let findings = risk::analyze_snapshot(&s);
        let rows = findings_by_host(&s, &findings);
        let order: Vec<String> = rows.iter().map(|r| r.ip.to_string()).collect();
        assert_eq!(order, ["10.0.0.6", "10.0.0.5", "10.0.0.4"]);
        assert_eq!(rows[0].worst, Severity::Critical);
        assert_eq!(rows[0].counts[0], 1);
        assert_eq!(
            rows.iter().map(HostFindings::total).sum::<usize>(),
            findings.len()
        );
        let html = html(&s, None, 0);
        let table = &html[html.find("Findings by host").unwrap()..];
        assert!(table.find("10.0.0.6").unwrap() < table.find("10.0.0.4").unwrap());
        assert!(!table.contains("<img"), "hostnames are escaped");
    }

    #[test]
    fn cpe_column_only_when_cpe_keys_exist() {
        let s = snapshot();
        assert!(!html(&s, None, 0).contains("<th>CPE</th>"));
        assert!(!markdown(&s, None, 0).contains("| CPE |"));
        let mut s = snapshot();
        s.hosts[0]
            .identity
            .insert("svc.23.cpe".into(), "cpe:/a:busybox:telnetd<x>".into());
        let h = html(&s, None, 0);
        assert!(h.contains("<th>CPE</th>"));
        assert!(h.contains("cpe:/a:busybox:telnetd&lt;x&gt;"));
        assert!(markdown(&s, None, 0).contains("cpe:/a:busybox:telnetd&lt;x&gt;"));
        assert!(!is_cpe_key("svc.cpe") && is_cpe_key("svc.443.cpe") && !is_cpe_key("tls.443.cpe"));
    }

    #[test]
    fn baseline_section_lists_new_and_resolved_findings() {
        let mut base = snapshot();
        let mut now = snapshot();
        base.hosts[0].open = vec![23, 80];
        now.hosts[0].open = vec![21, 80];
        now.hosts[0].identity.remove("svc.23");
        now.hosts[0].identity.insert("svc.21".into(), "ftp".into());
        let h = html(&now, Some((&base, 1_600_000_000)), 1_700_000_000);
        assert!(h.contains("port 21 newly open"));
        assert!(h.contains("New findings (1)") && h.contains("FTP sends credentials"));
        assert!(h.contains("Resolved findings (1)"));
        let resolved = &h[h.find("Resolved findings").unwrap()..];
        assert!(resolved.contains("Telnet exposes credentials"));
        let md = markdown(&now, Some((&base, 1_600_000_000)), 1_700_000_000);
        assert!(md.contains("## Changes since 2020-09-13"));
        assert!(md.contains("### New findings (1)") && md.contains("### Resolved findings (1)"));
    }

    #[test]
    fn markdown_summary_escapes_cells() {
        let mut s = snapshot();
        s.hosts[0].hostname = "a|b\n<script>*x*".into();
        let md = markdown(&s, None, 1_700_000_000);
        for section in [
            "# Network Scope summary",
            "## Findings by severity",
            "### Findings by host",
            "## Devices (",
            "2023-11-14 22:13 UTC",
        ] {
            assert!(md.contains(section), "missing {section}");
        }
        assert!(!md.contains("<script") && !md.contains("<img") && !md.contains("<sw>"));
        assert!(md.contains("a\\|b &lt;script&gt;\\*x\\*"), "{md}");
        // Every table row has the same number of cells as its header.
        for table in md.split("\n\n").filter(|t| t.starts_with('|')) {
            let cells: Vec<usize> = table
                .lines()
                .map(|l| l.replace("\\|", "").matches('|').count())
                .collect();
            assert!(cells.iter().all(|c| *c == cells[0]), "{table}");
        }
        assert!(md.contains("PARTIAL") == !s.complete);
    }

    #[test]
    fn jsonl_has_one_object_per_responding_host() {
        let mut s = snapshot();
        s.hosts[1].responding = false;
        s.hosts[0].identity.insert(
            "svc.80.cpe".into(),
            "cpe:/a:igor_sysoev:nginx:1.18.0".into(),
        );
        let out = jsonl(&s, 42).unwrap();
        let lines: Vec<serde_json::Value> = out
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 1);
        let h = &lines[0];
        assert_eq!(h["ip"], "10.0.0.5");
        assert_eq!(h["timestamp"], 42);
        assert_eq!(h["open_tcp"], serde_json::json!([23, 80]));
        assert_eq!(h["services"][1]["product"], "nginx");
        assert_eq!(h["services"][1]["cpe"], "cpe:/a:igor_sysoev:nginx:1.18.0");
        assert_eq!(h["note"], "note \" & <x>");
        assert!(h["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == "telnet-open" && f["severity"] == "high"));
        assert!(!out.trim_end().contains('\n'), "one line per host");
    }
}
