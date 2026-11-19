//! Sorting and filtering for the Findings and Devices windows. Row lists are recomputed only
//! when the data or the view settings change.
use crate::{devices::Device, risk};
use eframe::egui;
use std::{cmp::Ordering, collections::HashMap, net::IpAddr};

/// Data generation, sort column, direction, minimum severity and lowercase query.
type ViewKey = (Option<u64>, usize, bool, Option<risk::Severity>, String);
/// Sort column, direction, minimum severity and text filter of one table.
#[derive(Default)]
pub(super) struct View {
    pub sort: usize,
    pub reverse: bool,
    /// `None` shows everything (devices without findings included).
    pub min: Option<risk::Severity>,
    pub query: String,
    pub rows: Vec<usize>,
    key: Option<ViewKey>,
}
impl View {
    /// True when `rows` must be recomputed for data of this generation.
    pub fn stale(&mut self, generation: Option<u64>) -> bool {
        let key = (
            generation,
            self.sort,
            self.reverse,
            self.min,
            self.query.to_lowercase(),
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
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt(id)
                .selected_text(
                    self.min
                        .map_or(any.to_string(), |s| format!("{} and above", s.name())),
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
                            format!("{} and above", s.name()),
                        );
                    }
                });
            ui.add(
                egui::TextEdit::singleline(&mut self.query)
                    .hint_text("Filter…")
                    .desired_width(220.0),
            );
            if !self.query.is_empty() && ui.small_button("Clear").clicked() {
                self.query.clear();
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

pub(super) const FINDING_COLUMNS: [&str; 5] = ["Severity", "Host", "Finding", "Evidence", "CVE"];

/// Findings columns: severity (highest first), host, title, evidence, CVE.
pub(super) fn finding_rows(findings: &[risk::Finding], view: &View) -> Vec<usize> {
    let query = view.query.to_lowercase();
    ordered(
        findings,
        |f| {
            view.min.is_none_or(|m| f.severity >= m)
                && (query.is_empty()
                    || [
                        f.ip.to_string(),
                        f.port.map_or(String::new(), |p| p.to_string()),
                        f.title.clone(),
                        f.evidence.clone(),
                        f.cve.join(" "),
                        f.id.clone(),
                        f.severity.name().to_string(),
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
                _ => b.severity.cmp(&a.severity),
            }
            .then_with(|| a.ip.cmp(&b.ip))
        },
        view.reverse,
    )
}

pub(super) const DEVICE_COLUMNS: [&str; 7] = [
    "Address",
    "MAC",
    "Manufacturer",
    "Type",
    "OS guess",
    "Open ports",
    "Risk",
];

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
        }
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
