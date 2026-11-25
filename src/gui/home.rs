// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! The "what changed" overview (ROADMAP E31): the first view when the app opens. It shows the
//! new, gone and changed devices and the new and resolved risks since the last scan, the last 24
//! hours or the last 7 days, the network risk score with the five things to fix first, and the
//! devices that are not on the approved baseline. Every entry opens that host's details. With no
//! scan yet it shows an empty state that leads to "Scan my network".
//!
//! The data comes from the engine's `changes::changes` and `score::assess`, computed on the
//! background worker ([`compute`]); the drawing only reads the result.
use super::{i18n::tr, *};
use crate::{changes, score};
use std::path::Path;

/// How far back "what changed" looks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Window {
    /// The newest completed scan against the one before it.
    #[default]
    Last,
    Day,
    Week,
}
impl Window {
    pub const ALL: [Self; 3] = [Self::Last, Self::Day, Self::Week];
    pub fn label(self) -> &'static str {
        match self {
            Self::Last => tr!("Since the last scan"),
            Self::Day => tr!("Last 24 hours"),
            Self::Week => tr!("Last 7 days"),
        }
    }
    /// The engine's `Since` for this window at time `now` (Unix seconds).
    pub fn since(self, now: i64) -> changes::Since {
        match self {
            Self::Last => changes::Since::Last,
            Self::Day => changes::Since::At(now - 86_400),
            Self::Week => changes::Since::At(now - 7 * 86_400),
        }
    }
}

/// What the overview shows.
pub(super) struct HomeData {
    pub changes: changes::Changes,
    pub assessment: score::Assessment,
    /// Scans in the inventory (0: nothing was ever scanned).
    pub scans: usize,
}

/// Reads the overview from the inventory (runs on the worker). The fix-first list and the score
/// come from the newest completed scan.
pub(super) fn compute(db: &Path, window: Window, now: i64) -> Result<HomeData, String> {
    let scans = store::list(db)?;
    let changes = changes::changes(db, &window.since(now), now)?;
    let findings = match scans.iter().find(|s| s.complete) {
        Some(entry) => risk::analyze_snapshot(&store::load(db, entry.id)?),
        None => vec![],
    };
    Ok(HomeData {
        changes,
        assessment: score::assess(&findings, 5),
        scans: scans.len(),
    })
}

#[derive(Default)]
pub(super) struct HomeState {
    pub window: Window,
    pub data: Option<Result<Box<HomeData>, String>>,
    /// The token of the newest request; older answers are dropped.
    pub token: u64,
}

/// What a click on the overview asks for.
enum Action {
    Window(Window),
    Refresh,
    /// Show a host: the scan to open when it is not on screen, and its addresses.
    Open(Option<i64>, Vec<IpAddr>),
    ScanMyNetwork,
    ShowHosts,
}

/// Entries listed per section before "and N more".
const SHOWN: usize = 8;

pub(super) fn severity_color(s: risk::Severity, dark: bool) -> Color32 {
    use risk::Severity::*;
    match (s, dark) {
        (Critical, false) => Color32::from_rgb(155, 28, 28),
        (Critical, true) => Color32::from_rgb(255, 130, 130),
        (High, false) => Color32::from_rgb(190, 60, 10),
        (High, true) => Color32::from_rgb(255, 150, 90),
        (Medium, false) => Color32::from_rgb(150, 100, 0),
        (Medium, true) => Color32::from_rgb(240, 190, 70),
        (Low, false) => Color32::from_rgb(33, 98, 166),
        (Low, true) => Color32::from_rgb(130, 180, 240),
        (Info, false) => Color32::from_gray(90),
        (Info, true) => Color32::from_gray(170),
    }
}
/// The severity word in the current language.
pub(super) fn severity_name(s: risk::Severity) -> &'static str {
    use risk::Severity::*;
    match s {
        Critical => tr!("critical"),
        High => tr!("high"),
        Medium => tr!("medium"),
        Low => tr!("low"),
        Info => tr!("info"),
    }
}
/// The score band in the current language.
fn band_name(b: score::Band) -> &'static str {
    use score::Band::*;
    match b {
        None => tr!("none"),
        Low => tr!("low"),
        Medium => tr!("medium"),
        High => tr!("high"),
        Critical => tr!("critical"),
    }
}
fn band_color(band: score::Band, dark: bool) -> Color32 {
    use score::Band::*;
    severity_color(
        match band {
            None => risk::Severity::Info,
            Low => risk::Severity::Low,
            Medium => risk::Severity::Medium,
            High => risk::Severity::High,
            Critical => risk::Severity::Critical,
        },
        dark,
    )
}
fn good_color(dark: bool) -> Color32 {
    if dark {
        Color32::from_rgb(110, 210, 140)
    } else {
        Color32::from_rgb(20, 110, 60)
    }
}

/// A number with its label, in a frame.
fn card(ui: &mut egui::Ui, count: usize, label: &str, color: Color32) {
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.set_min_width(96.0);
        ui.vertical(|ui| {
            ui.label(
                RichText::new(count.to_string())
                    .size(26.0)
                    .strong()
                    .color(color),
            );
            ui.label(label);
        });
    });
}

/// "and N more" under a capped list.
fn more(ui: &mut egui::Ui, total: usize) {
    if total > SHOWN {
        ui.weak(tr!(
            "and {} more (see Inventory and the changes command)",
            total - SHOWN
        ));
    }
}

fn device_line(
    ui: &mut egui::Ui,
    d: &changes::DeviceRef,
    scan: Option<i64>,
    act: &mut Option<Action>,
) {
    ui.horizontal_wrapped(|ui| {
        if ui
            .link(&d.label)
            .on_hover_text(tr!("Show the details of this host"))
            .clicked()
        {
            *act = Some(Action::Open(scan, d.ips.clone()));
        }
        let mut info: Vec<String> = d.ips.iter().take(2).map(ToString::to_string).collect();
        for part in [&d.vendor, &d.device_type] {
            if !part.is_empty() {
                info.push(part.clone());
            }
        }
        ui.weak(info.join(" · "));
        if d.in_baseline == Some(false) {
            ui.weak(tr!("not on the baseline"));
        }
    });
}

fn risk_line(
    ui: &mut egui::Ui,
    r: &changes::RiskChange,
    scan: Option<i64>,
    dark: bool,
    act: &mut Option<Action>,
) {
    let f = &r.finding;
    ui.horizontal_wrapped(|ui| {
        ui.label(
            RichText::new(severity_name(f.severity).to_uppercase())
                .small()
                .strong()
                .color(severity_color(f.severity, dark)),
        );
        let place = format!(
            "{}{}",
            f.ip,
            f.port.map_or(String::new(), |p| format!(":{p}"))
        );
        if ui
            .link(format!("{} · {place}", f.title))
            .on_hover_text(tr!("Show the details of this host"))
            .clicked()
        {
            *act = Some(Action::Open(scan, vec![f.ip]));
        }
        super::explain_button(ui, &f.id);
        if f.exploit.kev {
            ui.label(
                RichText::new("KEV")
                    .small()
                    .strong()
                    .color(severity_color(risk::Severity::Critical, dark)),
            )
            .on_hover_text(tr!("Known exploited vulnerability (CISA KEV)"));
        }
    });
}

impl Scanner {
    /// Asks the worker for the overview of the chosen window.
    pub(super) fn refresh_home(&mut self) {
        if self.screenshot.is_some() {
            return;
        }
        self.home.token += 1;
        self.submit(Job::Home(self.home.token, self.home.window));
    }

    /// An overview answer from the worker; an answer for an older request is dropped.
    pub(super) fn home_loaded(&mut self, token: u64, result: Result<Box<HomeData>, String>) {
        self.busy.home = false;
        if token == self.home.token {
            self.home.data = Some(result);
        }
    }

    /// Shows a host from the overview: straight away when its scan is on screen, else after
    /// opening that scan.
    fn open_home_host(&mut self, scan: Option<i64>, ips: Vec<IpAddr>) {
        let on_screen = scan.is_none() || self.loaded_scan == scan;
        if on_screen
            && ips
                .iter()
                .any(|ip| self.results.iter().any(|h| h.ip == *ip))
        {
            self.view = MainView::Hosts;
            self.focus_host(&ips);
            return;
        }
        let Some(id) = scan else {
            self.status = tr!("This device is not in the results on screen").into();
            return;
        };
        if self.live() || self.busy.loading {
            self.error =
                tr!("The scan cannot be opened while a scan or capture is running.").into();
            return;
        }
        self.pending_focus = Some(ips);
        self.view = MainView::Hosts;
        self.submit(Job::Load(id));
    }

    pub(super) fn home_view(&mut self, ui: &mut egui::Ui) {
        let dark = ui.visuals().dark_mode;
        let mut act: Option<Action> = None;
        let busy = self.busy.home;
        let scanning = self.run.is_some();
        let window = self.home.window;
        // A short window keeps the logo out, so "Scan my network" stays on screen.
        let room = ui.available_height() > 420.0;
        egui::ScrollArea::vertical()
            .id_salt("home_scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.heading(tr!("What changed"));
                    ui.add_space(8.0);
                    for w in Window::ALL {
                        if ui.selectable_label(window == w, w.label()).clicked() {
                            act = Some(Action::Window(w));
                        }
                    }
                    if ui.button(tr!("Refresh")).clicked() {
                        act = Some(Action::Refresh);
                    }
                    if ui
                        .add_enabled(!scanning, egui::Button::new(tr!("Scan my network")))
                        .on_hover_text(tr!(
                            "Finds your local networks and scans them in Safe Mode."
                        ))
                        .clicked()
                    {
                        act = Some(Action::ScanMyNetwork);
                    }
                    if busy {
                        ui.spinner();
                    }
                });
                ui.add_space(6.0);
                match &self.home.data {
                    None if busy => {
                        ui.label(tr!("Reading the inventory…"));
                    }
                    Some(Err(e)) => {
                        ui.colored_label(severity_color(risk::Severity::Critical, dark), e);
                    }
                    Some(Ok(d)) if d.scans > 0 => home_body(ui, d, dark, &mut act),
                    _ => empty_state(ui, scanning, room, &mut act),
                }
            });
        match act {
            Some(Action::Window(w)) => {
                self.home.window = w;
                self.refresh_home();
            }
            Some(Action::Refresh) => self.refresh_home(),
            Some(Action::Open(scan, ips)) => self.open_home_host(scan, ips),
            Some(Action::ScanMyNetwork) => self.scan_my_network(),
            Some(Action::ShowHosts) => self.view = MainView::Hosts,
            None => {}
        }
    }
}

/// No scan yet: one clear next step.
fn empty_state(ui: &mut egui::Ui, scanning: bool, logo: bool, act: &mut Option<Action>) {
    ui.add_space(40.0);
    ui.vertical_centered(|ui| {
        if logo {
            let logo = super::icons::logo(ui.ctx());
            ui.add(egui::Image::new((logo.id(), egui::vec2(48.0, 48.0))));
            ui.add_space(8.0);
        }
        ui.heading(tr!("No scan yet"));
        ui.add_space(6.0);
        ui.label(tr!("Network Scope has not scanned anything on this computer yet."));
        ui.label(tr!(
            "One click finds your local network and scans it in Safe Mode: a few gentle probes per device, nothing that changes a device."
        ));
        ui.add_space(14.0);
        if ui
            .add_enabled(
                !scanning,
                egui::Button::new(RichText::new(tr!("Scan my network")).size(18.0).color(Color32::WHITE))
                    .fill(Color32::from_rgb(33, 105, 180))
                    .min_size(egui::vec2(220.0, 44.0)),
            )
            .clicked()
        {
            *act = Some(Action::ScanMyNetwork);
        }
        ui.add_space(14.0);
        ui.weak(tr!("Or enter addresses at the top and choose Start."));
        if ui.link(tr!("Show the hosts table")).clicked() {
            *act = Some(Action::ShowHosts);
        }
    });
}

fn home_body(ui: &mut egui::Ui, d: &HomeData, dark: bool, act: &mut Option<Action>) {
    let c = &d.changes;
    // What is being compared.
    match (&c.current, &c.previous) {
        (Some(now), Some(before)) => {
            ui.label(tr!(
                "Scan #{} ({}, {} hosts) compared with scan #{} ({}).",
                now.id,
                crate::report::fmt_time(now.timestamp),
                now.hosts,
                before.id,
                crate::report::fmt_time(before.timestamp)
            ));
        }
        (Some(now), None) => {
            ui.label(tr!(
                "Latest scan: #{} ({}, {} hosts).",
                now.id,
                crate::report::fmt_time(now.timestamp),
                now.hosts
            ));
        }
        _ => {}
    }
    if let Some(notice) = &c.notice {
        ui.colored_label(severity_color(risk::Severity::Medium, dark), notice);
    }
    ui.add_space(6.0);
    let s = &c.summary;
    ui.horizontal_wrapped(|ui| {
        card(
            ui,
            s.new_devices,
            tr!("New devices"),
            if s.new_devices > 0 {
                severity_color(risk::Severity::Medium, dark)
            } else {
                ui.visuals().text_color()
            },
        );
        card(
            ui,
            s.gone_devices,
            tr!("Gone devices"),
            ui.visuals().text_color(),
        );
        card(
            ui,
            s.changed_devices,
            tr!("Changed devices"),
            ui.visuals().text_color(),
        );
        card(
            ui,
            s.new_risks,
            tr!("New risks"),
            if s.new_risks > 0 {
                severity_color(risk::Severity::High, dark)
            } else {
                ui.visuals().text_color()
            },
        );
        card(
            ui,
            s.resolved_risks,
            tr!("Resolved risks"),
            good_color(dark),
        );
        if let Some(n) = c.unknown_devices {
            card(
                ui,
                n,
                tr!("Not on the baseline"),
                if n > 0 {
                    severity_color(risk::Severity::High, dark)
                } else {
                    good_color(dark)
                },
            );
        }
        // The network score.
        let n = &d.assessment.network;
        egui::Frame::group(ui.style())
            .show(ui, |ui| {
                ui.set_min_width(150.0);
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(format!("{} / 100", n.score))
                            .size(26.0)
                            .strong()
                            .color(band_color(n.band, dark)),
                    );
                    ui.label(tr!("Network risk score ({})", band_name(n.band)));
                });
            })
            .response
            .on_hover_text(tr!(
                "{} hosts, {} findings in the newest completed scan",
                n.hosts,
                n.findings
            ));
    });
    ui.add_space(8.0);
    let (current, previous) = (
        c.current.as_ref().map(|s| s.id),
        c.previous.as_ref().map(|s| s.id),
    );
    ui.columns(2, |cols| {
        let ui = &mut cols[0];
        ui.strong(tr!("Devices"));
        section(ui, tr!("New devices"), c.new_devices.len(), |ui| {
            for d in c.new_devices.iter().take(SHOWN) {
                device_line(ui, d, current, act);
            }
        });
        section(ui, tr!("Gone devices (not seen; not proof that they are off)"), c.gone_devices.len(), |ui| {
            for d in c.gone_devices.iter().take(SHOWN) {
                device_line(ui, d, previous, act);
            }
        });
        section(ui, tr!("Changed devices"), c.changed_devices.len(), |ui| {
            for ch in c.changed_devices.iter().take(SHOWN) {
                device_line(ui, &ch.device, current, act);
                let what: Vec<&str> = ch.changes.iter().take(3).map(|x| x.detail.as_str()).collect();
                ui.indent("changes", |ui| ui.weak(what.join("; ")));
            }
        });
        if let Some(n) = c.unknown_devices {
            ui.add_space(4.0);
            ui.label(if n == 0 {
                tr!("Every device is on the approved baseline.").to_string()
            } else {
                tr!("{} devices are not on the approved baseline.", n)
            });
        }

        let ui = &mut cols[1];
        ui.strong(tr!("Fix these first"));
        if d.assessment.top_fixes.is_empty() {
            ui.label(tr!("Nothing to fix in the newest completed scan."));
        }
        for (i, fix) in d.assessment.top_fixes.iter().enumerate() {
            ui.add_space(2.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(format!("{}.", i + 1));
                ui.label(
                    RichText::new(severity_name(fix.severity).to_uppercase())
                        .small()
                        .strong()
                        .color(severity_color(fix.severity, dark)),
                );
                ui.strong(&fix.title);
                super::explain_button(ui, &fix.id);
                if fix.kev {
                    ui.label(RichText::new("KEV").small().strong().color(severity_color(risk::Severity::Critical, dark)))
                        .on_hover_text(tr!("Known exploited vulnerability (CISA KEV)"));
                }
            });
            ui.indent(("fix", i), |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(tr!("Affects"));
                    for ip in fix.hosts.iter().take(4) {
                        if ui.link(ip.to_string()).on_hover_text(tr!("Show the details of this host")).clicked() {
                            *act = Some(Action::Open(current, vec![*ip]));
                        }
                    }
                    if fix.hosts.len() > 4 {
                        ui.weak(tr!("and {} more", fix.hosts.len() - 4));
                    }
                });
                if !fix.advice.is_empty() {
                    let advice: String = fix.advice.chars().take(160).collect();
                    ui.weak(advice);
                }
                ui.horizontal(|ui| {
                    if let Some(url) = &fix.reference {
                        super::convenience::link_to(ui, tr!("Reference"), url);
                    }
                    super::convenience::link_to(ui, tr!("Learn more"), &super::docs_url(&fix.id));
                });
            });
        }
        ui.add_space(10.0);
        ui.strong(tr!("Risks"));
        section(ui, tr!("New risks"), c.new_risks.len(), |ui| {
            for r in c.new_risks.iter().take(SHOWN) {
                risk_line(ui, r, current, dark, act);
            }
        });
        section(ui, tr!("Resolved risks"), c.resolved_risks.len(), |ui| {
            for r in c.resolved_risks.iter().take(SHOWN) {
                risk_line(ui, r, previous, dark, act);
            }
        });
        if !c.unconfirmed_risks.is_empty() {
            ui.weak(tr!(
                "Not seen again, but not checked by the scan either (host silent or port not probed): {}",
                c.unconfirmed_risks.len()
            ));
        }
    });
}

/// A titled list that is skipped when empty.
fn section(ui: &mut egui::Ui, title: &str, total: usize, body: impl FnOnce(&mut egui::Ui)) {
    ui.add_space(4.0);
    if total == 0 {
        ui.weak(format!("{title}: 0"));
        return;
    }
    ui.label(RichText::new(format!("{title} ({total})")).strong());
    body(ui);
    more(ui, total);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_windows_map_to_the_engines_since() {
        let now = 1_800_000_000;
        assert_eq!(Window::Last.since(now), changes::Since::Last);
        assert_eq!(Window::Day.since(now), changes::Since::At(now - 86_400));
        assert_eq!(
            Window::Week.since(now),
            changes::Since::At(now - 7 * 86_400)
        );
        assert_eq!(Window::default(), Window::Last);
        // Every window has a distinct label.
        let labels: std::collections::BTreeSet<_> = Window::ALL.iter().map(|w| w.label()).collect();
        assert_eq!(labels.len(), 3);
    }

    #[test]
    fn the_overview_of_an_empty_inventory_says_so_and_a_scan_gives_numbers() {
        let dir = std::env::temp_dir().join(format!("ns-home-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("inventory.sqlite");
        let now = store::now();
        // No database yet: nothing scanned, nothing to compare.
        let empty = compute(&db, Window::Last, now).unwrap();
        assert_eq!(empty.scans, 0);
        assert!(empty.changes.is_quiet() && empty.changes.notice.is_some());
        assert!(empty.assessment.top_fixes.is_empty());
        // Two scans: a telnet host appears.
        let host = |ip: &str, open: Vec<u16>| {
            let mut h = demo::demo_host(ip, &open, &[("svc.23", "telnet")]);
            h.mac = format!("00:0C:29:00:00:{:02X}", ip.len());
            h
        };
        let snapshot = |hosts| store::Snapshot {
            sent: vec![],
            targets: "10.0.0.0/24".into(),
            complete: true,
            settings: Default::default(),
            hosts,
            observations: vec![],
            notes: Default::default(),
        };
        store::save_at(&db, &snapshot(vec![host("10.0.0.5", vec![22])]), now - 7200).unwrap();
        store::save_at(
            &db,
            &snapshot(vec![
                host("10.0.0.5", vec![22]),
                host("10.0.0.66", vec![23]),
            ]),
            now - 60,
        )
        .unwrap();
        let d = compute(&db, Window::Last, now).unwrap();
        assert_eq!(d.scans, 2);
        assert_eq!(d.changes.summary.new_devices, 1);
        assert!(d.changes.summary.new_risks >= 1);
        assert_eq!(d.assessment.top_fixes[0].id, "telnet-open");
        assert!(d.assessment.network.score > 0);
        // The 24 hour window compares with the state a day ago: nothing existed, so it says so
        // or lists the devices as new; either way it does not fail.
        assert!(compute(&db, Window::Day, now).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn severity_colours_differ_per_theme_and_level() {
        use risk::Severity::*;
        for s in [Critical, High, Medium, Low, Info] {
            assert_ne!(severity_color(s, false), severity_color(s, true), "{s:?}");
        }
        assert_ne!(severity_color(Critical, false), severity_color(Low, false));
    }
}
