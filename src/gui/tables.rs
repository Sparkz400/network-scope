//! Sorting and filtering for the Findings and Devices windows. Row lists are recomputed only
//! when the data or the view settings change.
use super::i18n::tr;
use crate::{devices::Device, risk};
use eframe::egui;
use std::{cmp::Ordering, collections::HashMap, net::IpAddr};

/// Data generation, sort column, direction, minimum severity, lowercase query, "known exploited
/// only", the minimum EPSS in percent and the one finding rule shown.
type ViewKey = (
    Option<u64>,
    usize,
    bool,
    Option<risk::Severity>,
    String,
    bool,
    u8,
    Option<String>,
);
/// Sort column, direction, minimum severity and text filter of one table.
#[derive(Default)]
pub(super) struct View {
    pub sort: usize,
    pub reverse: bool,
    /// `None` shows everything (devices without findings included).
    pub min: Option<risk::Severity>,
    pub query: String,
    /// Findings only: show only findings with a CVE in the CISA KEV catalog.
    pub kev_only: bool,
    /// Findings only: show only findings whose EPSS is at least this many percent (0: no limit).
    pub epss_min: u8,
    /// Findings only: show only the findings of this rule (a row of the grouped view was
    /// clicked). An exact id, unlike the text filter.
    pub rule: Option<String>,
    /// Give the filter box the keyboard focus on the next frame (Ctrl+F).
    pub focus_query: bool,
    pub rows: Vec<usize>,
    key: Option<ViewKey>,
}
/// The EPSS limits the filter offers, in percent.
pub(super) const EPSS_STEPS: [u8; 4] = [0, 1, 10, 50];
impl View {
    /// True when `rows` must be recomputed for data of this generation.
    pub fn stale(&mut self, generation: Option<u64>) -> bool {
        let key = (
            generation,
            self.sort,
            self.reverse,
            self.min,
            self.query.to_lowercase(),
            self.kev_only,
            self.epss_min,
            self.rule.clone(),
        );
        if self.key.as_ref() == Some(&key) {
            return false;
        }
        self.key = Some(key);
        true
    }
    /// A header was clicked: same column flips the direction.
    pub fn click(&mut self, column: usize) {
        if self.sort == column {
            self.reverse = !self.reverse;
        } else {
            self.sort = column;
            self.reverse = false;
        }
    }
    /// Severity selector and text box above a table.
    pub fn controls(&mut self, ui: &mut egui::Ui, id: &str, any: &str) {
        self.controls_with(ui, id, any, false);
    }
    /// The same, plus (for findings) the filters on the feed data: known exploited (KEV) only
    /// and a minimum EPSS.
    pub fn controls_with(&mut self, ui: &mut egui::Ui, id: &str, any: &str, exploit: bool) {
        ui.horizontal_wrapped(|ui| {
            let severity = egui::ComboBox::from_id_salt(id)
                .selected_text(
                    self.min
                        .map_or(any.to_string(), |s| tr!("{} and above", super::home::severity_name(s))),
                )
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.min, None, any);
                    for s in [
                        risk::Severity::Info,
                        risk::Severity::Low,
                        risk::Severity::Medium,
                        risk::Severity::High,
                        risk::Severity::Critical,
                    ] {
                        ui.selectable_value(
                            &mut self.min,
                            Some(s),
                            tr!("{} and above", super::home::severity_name(s)),
                        );
                    }
                });
            super::a11y::named(severity.response, tr!("Minimum severity"));
            let filter = super::a11y::named(
                ui.add(
                    egui::TextEdit::singleline(&mut self.query)
                        .hint_text(tr!("Filter…"))
                        .desired_width(220.0),
                ),
                tr!("Filter…"),
            );
            if std::mem::take(&mut self.focus_query) {
                filter.request_focus();
            }
            if !self.query.is_empty() && ui.small_button(tr!("Clear")).clicked() {
                self.query.clear();
            }
            if exploit {
                ui.checkbox(&mut self.kev_only, tr!("Known exploited (KEV) only"))
                    .on_hover_text(tr!(
                        "Findings with a CVE in the CISA catalog of vulnerabilities exploited in the wild. Needs imported feeds (feeds import)."
                    ));
                let epss = egui::ComboBox::from_id_salt(format!("{id}_epss"))
                    .selected_text(if self.epss_min == 0 {
                        tr!("Any EPSS").to_string()
                    } else {
                        tr!("EPSS {} % or more", self.epss_min)
                    })
                    .show_ui(ui, |ui| {
                        for step in EPSS_STEPS {
                            let text = if step == 0 {
                                tr!("Any EPSS").to_string()
                            } else {
                                tr!("EPSS {} % or more", step)
                            };
                            ui.selectable_value(&mut self.epss_min, step, text);
                        }
                    })
                    .response;
                super::a11y::named(epss, tr!("Minimum EPSS")).on_hover_text(tr!(
                        "EPSS: the estimated probability that the vulnerability is exploited in the next 30 days."
                    ));
            }
        });
    }
}

/// Labels that do not take clicks, so a click on cell text reaches the clickable table row.
pub(super) fn plain_labels(ui: &mut egui::Ui) {
    ui.style_mut().interaction.selectable_labels = false;
}

/// Header cell: a clickable label with the sort direction; returns true when clicked.
pub(super) fn header(ui: &mut egui::Ui, view: &View, column: usize, name: &str) -> bool {
    let text = if view.sort == column {
        format!("{name} {}", if view.reverse { "⬇" } else { "⬆" })
    } else {
        name.to_string()
    };
    ui.selectable_label(view.sort == column, egui::RichText::new(text).strong())
        .clicked()
}

fn ordered<T>(
    items: &[T],
    keep: impl Fn(&T) -> bool,
    cmp: impl Fn(&T, &T) -> Ordering,
    reverse: bool,
) -> Vec<usize> {
    let mut rows: Vec<usize> = (0..items.len()).filter(|&i| keep(&items[i])).collect();
    // Stable: equal keys keep their natural order in both directions.
    rows.sort_by(|&a, &b| {
        let o = cmp(&items[a], &items[b]);
        if reverse { o.reverse() } else { o }
    });
    rows
}

/// The sortable column names of the findings table (translated).
pub(super) fn finding_columns() -> [&'static str; 7] {
    [
        tr!("Severity"),
        tr!("Host"),
        tr!("Finding"),
        tr!("Evidence"),
        tr!("CVE"),
        tr!("KEV"),
        tr!("EPSS"),
    ]
}
/// The EPSS of a finding in percent, if the feeds gave one.
pub(super) fn epss_percent(f: &risk::Finding) -> Option<f64> {
    f.exploit.epss.map(|s| s.as_f64() * 100.0)
}

/// Findings columns: severity (highest first), host, title, evidence, CVE, known exploited
/// (KEV first, then ransomware use) and EPSS (highest first).
pub(super) fn finding_rows(findings: &[risk::Finding], view: &View) -> Vec<usize> {
    let query = view.query.to_lowercase();
    ordered(
        findings,
        |f| {
            view.min.is_none_or(|m| f.severity >= m)
                && view.rule.as_ref().is_none_or(|r| *r == f.id)
                && (!view.kev_only || f.exploit.kev)
                && (view.epss_min == 0
                    || epss_percent(f).is_some_and(|p| p >= f64::from(view.epss_min)))
                && (query.is_empty()
                    || [
                        f.ip.to_string(),
                        f.port.map_or(String::new(), |p| p.to_string()),
                        f.title.clone(),
                        f.evidence.clone(),
                        f.cve.join(" "),
                        f.id.clone(),
                        f.severity.name().to_string(),
                        if f.exploit.kev {
                            "kev".into()
                        } else {
                            String::new()
                        },
                        if f.exploit.kev_ransomware {
                            "ransomware".into()
                        } else {
                            String::new()
                        },
                    ]
                    .iter()
                    .any(|s| s.to_lowercase().contains(&query)))
        },
        |a, b| {
            match view.sort {
                1 => (a.ip, a.port).cmp(&(b.ip, b.port)),
                2 => a.title.cmp(&b.title),
                3 => a.evidence.cmp(&b.evidence),
                4 => b
                    .cve
                    .len()
                    .cmp(&a.cve.len())
                    .then_with(|| a.cve.cmp(&b.cve)),
                5 => (b.exploit.kev, b.exploit.kev_ransomware)
                    .cmp(&(a.exploit.kev, a.exploit.kev_ransomware))
                    .then_with(|| b.severity.cmp(&a.severity)),
                6 => b
                    .exploit
                    .epss
                    .cmp(&a.exploit.epss)
                    .then_with(|| b.severity.cmp(&a.severity)),
                _ => b.severity.cmp(&a.severity),
            }
            .then_with(|| a.ip.cmp(&b.ip))
        },
        view.reverse,
    )
}

/// The column names of the devices table (translated).
pub(super) fn device_columns() -> [&'static str; 7] {
    [
        tr!("Address"),
        tr!("MAC"),
        tr!("Manufacturer"),
        tr!("Type"),
        tr!("OS guess"),
        tr!("Open ports"),
        tr!("Risk"),
    ]
}

/// Highest finding severity per IP address.
pub(super) fn risk_by_ip(findings: &[risk::Finding]) -> HashMap<IpAddr, risk::Severity> {
    let mut map = HashMap::new();
    for f in findings {
        let e = map.entry(f.ip).or_insert(f.severity);
        *e = (*e).max(f.severity);
    }
    map
}
pub(super) fn device_risk(
    d: &Device,
    risk: &HashMap<IpAddr, risk::Severity>,
) -> Option<risk::Severity> {
    d.ips.iter().filter_map(|ip| risk.get(ip).copied()).max()
}

pub(super) fn device_rows(
    devices: &[Device],
    risk: &HashMap<IpAddr, risk::Severity>,
    view: &View,
) -> Vec<usize> {
    let query = view.query.to_lowercase();
    ordered(
        devices,
        |d| {
            view.min
                .is_none_or(|m| device_risk(d, risk).is_some_and(|r| r >= m))
                && (query.is_empty()
                    || d.ips.iter().any(|ip| ip.to_string().contains(&query))
                    || [
                        &d.mac,
                        &d.vendor,
                        &d.device_type,
                        &d.os,
                        &d.hostnames.join(" "),
                        &d.sources.join(" "),
                    ]
                    .iter()
                    .any(|s| s.to_lowercase().contains(&query))
                    || d.open_tcp.iter().any(|p| p.to_string() == query))
        },
        |a, b| {
            match view.sort {
                1 => a.mac.cmp(&b.mac),
                2 => a.vendor.to_lowercase().cmp(&b.vendor.to_lowercase()),
                3 => a.device_type.cmp(&b.device_type),
                4 => a.os.cmp(&b.os),
                5 => (b.open_tcp.len() + b.open_udp.len())
                    .cmp(&(a.open_tcp.len() + a.open_udp.len())),
                6 => device_risk(b, risk).cmp(&device_risk(a, risk)),
                _ => Ordering::Equal,
            }
            .then_with(|| a.ips.first().cmp(&b.ips.first()))
            .then_with(|| a.mac.cmp(&b.mac))
        },
        view.reverse,
    )
}

/// The findings on view grouped by rule: one entry per finding id, in the order the flat view
/// shows them first, with the indexes of every finding of that rule.
pub(super) fn finding_groups(findings: &[risk::Finding], rows: &[usize]) -> Vec<Vec<usize>> {
    let mut groups: Vec<Vec<usize>> = vec![];
    let mut at: HashMap<&str, usize> = HashMap::new();
    for &i in rows {
        let id = findings[i].id.as_str();
        match at.get(id) {
            Some(&g) => groups[g].push(i),
            None => {
                at.insert(id, groups.len());
                groups.push(vec![i]);
            }
        }
    }
    groups
}

/// The hosts of a group in a few words: the first `shown` addresses (with the port), then
/// "and N more".
pub(super) fn group_hosts(findings: &[risk::Finding], members: &[usize], shown: usize) -> String {
    let mut text = members
        .iter()
        .take(shown)
        .map(|&i| host_port(&findings[i]))
        .collect::<Vec<_>>()
        .join(", ");
    if members.len() > shown {
        text.push(' ');
        text.push_str(&tr!("and {} more", members.len() - shown));
    }
    text
}

/// `10.0.0.5:23`, or the address alone when the finding has no port.
pub(super) fn host_port(f: &risk::Finding) -> String {
    match f.port {
        Some(p) => format!("{}:{p}", f.ip),
        None => f.ip.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use risk::Severity;

    fn finding(sev: Severity, ip: &str, title: &str) -> risk::Finding {
        risk::Finding {
            severity: sev,
            id: title.to_lowercase(),
            title: title.into(),
            ip: ip.parse().unwrap(),
            port: Some(23),
            evidence: format!("{title} evidence"),
            cve: vec![],
            advice: String::new(),
            exploit: Default::default(),
            reference: None,
            confidence: 0,
        }
    }

    #[test]
    fn findings_group_by_rule_in_the_order_of_the_flat_view() {
        let findings = vec![
            finding(Severity::Medium, "10.0.0.2", "Modbus"),
            finding(Severity::High, "10.0.0.1", "Telnet"),
            finding(Severity::Medium, "10.0.0.3", "Modbus"),
            finding(Severity::High, "10.0.0.4", "Telnet"),
            finding(Severity::Medium, "10.0.0.5", "Modbus"),
        ];
        // The flat view sorted by severity: Telnet first.
        let groups = finding_groups(&findings, &[1, 3, 0, 2, 4]);
        assert_eq!(groups, vec![vec![1, 3], vec![0, 2, 4]]);
        // Filtered rows give only their groups.
        assert_eq!(finding_groups(&findings, &[2]), vec![vec![2]]);
        assert_eq!(
            group_hosts(&findings, &groups[1], 2),
            "10.0.0.2:23, 10.0.0.3:23 and 1 more"
        );
        assert_eq!(
            group_hosts(&findings, &groups[0], 5),
            "10.0.0.1:23, 10.0.0.4:23"
        );
        let mut no_port = findings[0].clone();
        no_port.port = None;
        assert_eq!(host_port(&no_port), "10.0.0.2");
    }

    #[test]
    fn findings_sort_filter_and_search() {
        let list = vec![
            finding(Severity::Low, "10.0.0.2", "Weak cipher"),
            finding(Severity::Critical, "10.0.0.9", "Telnet"),
            finding(Severity::Medium, "10.0.0.1", "SMBv1"),
        ];
        let mut v = View::default();
        assert_eq!(finding_rows(&list, &v), [1, 2, 0], "highest severity first");
        v.click(0);
        assert!(v.reverse);
        assert_eq!(finding_rows(&list, &v), [0, 2, 1]);
        v.click(1);
        assert_eq!((v.sort, v.reverse), (1, false));
        assert_eq!(finding_rows(&list, &v), [2, 0, 1]);
        v.min = Some(Severity::Medium);
        assert_eq!(finding_rows(&list, &v), [2, 1]);
        v.query = "TELNET".into();
        assert_eq!(finding_rows(&list, &v), [1]);
        v.query = "10.0.0.2".into();
        assert!(finding_rows(&list, &v).is_empty(), "filtered by severity");
        v.min = None;
        assert_eq!(finding_rows(&list, &v), [0]);
    }

    /// Lays out a clickable three-row table; returns the clicked row and row 1's label rect.
    fn table_frame(
        ctx: &egui::Context,
        events: Vec<egui::Event>,
        plain: bool,
    ) -> (Option<usize>, egui::Rect) {
        use egui_extras::{Column, TableBuilder};
        let (mut clicked, mut rect) = (None, egui::Rect::NOTHING);
        let input = egui::RawInput {
            events,
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(800.0, 600.0),
            )),
            ..Default::default()
        };
        ctx.run_ui(input, |ui| {
            egui::CentralPanel::default().show(ui, |ui| {
                if plain {
                    plain_labels(ui);
                }
                TableBuilder::new(ui)
                    .sense(egui::Sense::click())
                    .column(Column::initial(300.0))
                    .body(|body| {
                        body.rows(22.0, 3, |mut row| {
                            let i = row.index();
                            row.col(|ui| {
                                let r = ui.label(format!("row {i} text"));
                                if i == 1 {
                                    rect = r.rect;
                                }
                            });
                            if row.response().clicked() {
                                clicked = Some(i);
                            }
                        });
                    });
            });
        })
        // The test never paints, so the font atlas upload is dropped on purpose.
        .drop_without_applying_deltas();
        (clicked, rect)
    }
    fn click_label(plain: bool) -> Option<usize> {
        let ctx = egui::Context::default();
        let (_, rect) = table_frame(&ctx, vec![], plain);
        let pos = rect.center();
        let button = |pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: Default::default(),
        };
        let mut clicked = table_frame(&ctx, vec![egui::Event::PointerMoved(pos)], plain).0;
        clicked = clicked.or(table_frame(&ctx, vec![button(true)], plain).0);
        clicked.or(table_frame(&ctx, vec![button(false)], plain).0)
    }

    #[test]
    fn a_click_on_cell_text_selects_the_row() {
        assert_eq!(click_label(true), Some(1));
    }

    fn with_feed(
        mut f: risk::Finding,
        kev: bool,
        ransomware: bool,
        epss: Option<f64>,
    ) -> risk::Finding {
        f.exploit.kev = kev;
        f.exploit.kev_ransomware = ransomware;
        f.exploit.epss = epss.and_then(crate::feeds::Score::from_f64);
        f
    }

    #[test]
    fn findings_sort_and_filter_by_kev_and_epss() {
        let list = vec![
            with_feed(
                finding(Severity::Medium, "10.0.0.1", "a"),
                false,
                false,
                Some(0.02),
            ),
            with_feed(
                finding(Severity::High, "10.0.0.2", "b"),
                true,
                false,
                Some(0.40),
            ),
            with_feed(
                finding(Severity::Low, "10.0.0.3", "c"),
                true,
                true,
                Some(0.95),
            ),
            with_feed(
                finding(Severity::Critical, "10.0.0.4", "d"),
                false,
                false,
                None,
            ),
        ];
        let mut v = View::default();
        // KEV column: ransomware use first, then known exploited, then the rest by severity.
        v.click(5);
        assert_eq!(finding_rows(&list, &v), [2, 1, 3, 0]);
        // EPSS column: highest first, findings without a score last.
        v.click(6);
        assert_eq!(finding_rows(&list, &v), [2, 1, 0, 3]);
        v.click(6);
        assert_eq!(
            finding_rows(&list, &v),
            [3, 0, 1, 2],
            "the same column again reverses it"
        );
        // Filters.
        v.kev_only = true;
        assert_eq!(finding_rows(&list, &v), [1, 2]);
        v.kev_only = false;
        v.epss_min = 10;
        assert_eq!(
            finding_rows(&list, &v),
            [1, 2],
            "EPSS 40 % and 95 %, not 2 % or none"
        );
        v.epss_min = 50;
        assert_eq!(finding_rows(&list, &v), [2]);
        v.epss_min = 0;
        v.query = "ransomware".into();
        assert_eq!(finding_rows(&list, &v), [2]);
        v.query = "kev".into();
        assert_eq!(finding_rows(&list, &v).len(), 2);
        // The view recomputes when a feed filter changes.
        let mut v = View::default();
        assert!(v.stale(Some(1)));
        assert!(!v.stale(Some(1)));
        v.kev_only = true;
        assert!(v.stale(Some(1)));
        v.epss_min = 1;
        assert!(v.stale(Some(1)));
        assert!(!v.stale(Some(1)));
    }

    #[test]
    fn epss_is_shown_in_percent() {
        let f = with_feed(
            finding(Severity::Low, "10.0.0.1", "a"),
            false,
            false,
            Some(0.5),
        );
        assert_eq!(epss_percent(&f), Some(50.0));
        assert_eq!(epss_percent(&finding(Severity::Low, "10.0.0.1", "a")), None);
        assert_eq!(EPSS_STEPS[0], 0, "the first step is no limit");
    }

    #[test]
    fn view_recomputes_only_on_change() {
        let mut v = View::default();
        assert!(v.stale(Some(1)));
        assert!(!v.stale(Some(1)));
        v.query = "x".into();
        assert!(v.stale(Some(1)));
        assert!(!v.stale(Some(1)));
        assert!(v.stale(Some(2)));
        v.click(3);
        assert!(v.stale(Some(2)));
    }

    #[test]
    fn devices_sort_by_risk_and_filter_by_severity() {
        let dev = |ip: &str, vendor: &str, ports: Vec<u16>| Device {
            id: ip.into(),
            ips: vec![ip.parse().unwrap()],
            vendor: vendor.into(),
            open_tcp: ports,
            ..Default::default()
        };
        let devices = vec![
            dev("10.0.0.3", "Siemens", vec![102]),
            dev("10.0.0.1", "HP", vec![80, 443, 9100]),
            dev("10.0.0.2", "Cisco", vec![]),
        ];
        let risk = risk_by_ip(&[
            finding(Severity::Low, "10.0.0.1", "a"),
            finding(Severity::High, "10.0.0.3", "b"),
            finding(Severity::Info, "10.0.0.3", "c"),
        ]);
        assert_eq!(device_risk(&devices[0], &risk), Some(Severity::High));
        let mut v = View::default();
        assert_eq!(device_rows(&devices, &risk, &v), [1, 2, 0], "by address");
        v.click(6);
        assert_eq!(device_rows(&devices, &risk, &v), [0, 1, 2]);
        v.click(5);
        assert_eq!(device_rows(&devices, &risk, &v), [1, 0, 2]);
        v.min = Some(Severity::Low);
        assert_eq!(device_rows(&devices, &risk, &v), [1, 0]);
        v.min = None;
        v.query = "siem".into();
        assert_eq!(device_rows(&devices, &risk, &v), [0]);
        v.query = "9100".into();
        assert_eq!(device_rows(&devices, &risk, &v), [1]);
    }
}
