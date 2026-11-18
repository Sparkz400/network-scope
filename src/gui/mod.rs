mod controls;
mod details;
mod settings;
mod windows;

use crate::{passive, scan, store};
use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap, net::IpAddr, path::PathBuf, sync::atomic::Ordering, time::Duration,
};

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct Saved {
    settings: scan::Settings,
    favorites: Vec<String>,
    notes: BTreeMap<IpAddr, String>,
}
fn saved_path() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("NetworkScope")
        .join("preferences.json")
}

#[derive(PartialEq, Clone, Copy)]
enum Filter {
    Responding,
    All,
    Open,
}
struct Scanner {
    saved: Saved,
    targets: String,
    results: Vec<scan::Host>,
    previous: BTreeMap<IpAddr, scan::Host>,
    run: Option<scan::Running>,
    filter: Filter,
    search: String,
    status: String,
    error: String,
    settings_open: bool,
    about_open: bool,
    selected: Option<IpAddr>,
    screenshot: Option<PathBuf>,
    frames: usize,
    screenshot_requested: bool,
    sort_column: usize,
    sort_reverse: bool,
    history_open: bool,
    topology_open: bool,
    devices_open: bool,
    findings_open: bool,
    capture_open: bool,
    history: Vec<store::Entry>,
    compare_a: Option<i64>,
    compare_b: Option<i64>,
    changes: Vec<String>,
    observations: Vec<passive::Observation>,
    listening: Option<passive::Listening>,
    interfaces: Vec<(String, String)>,
    capture_seconds: u64,
    capture_scope: String,
    capture_complete: bool,
    scan_complete: bool,
    scan_scope: String,
    scan_settings: scan::Settings,
}
impl Scanner {
    fn new(cc: &eframe::CreationContext<'_>, screenshot: Option<PathBuf>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::light());
        let mut style = (*cc.egui_ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(10.0, 6.0);
        cc.egui_ctx.set_style(style);
        let saved = if screenshot.is_none() {
            std::fs::read(saved_path())
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or_default()
        } else {
            Saved::default()
        };
        Self {
            saved,
            targets: "192.168.1.1-254".into(),
            results: vec![],
            previous: BTreeMap::new(),
            run: None,
            filter: Filter::Responding,
            search: String::new(),
            status: "Ready to scan".into(),
            error: String::new(),
            settings_open: false,
            about_open: false,
            selected: None,
            screenshot,
            frames: 0,
            screenshot_requested: false,
            sort_column: 0,
            sort_reverse: false,
            history_open: false,
            topology_open: false,
            devices_open: false,
            findings_open: false,
            capture_open: false,
            history: vec![],
            compare_a: None,
            compare_b: None,
            changes: vec![],
            observations: vec![],
            listening: None,
            interfaces: vec![],
            capture_seconds: 60,
            capture_scope: String::new(),
            capture_complete: true,
            scan_complete: true,
            scan_scope: String::new(),
            scan_settings: scan::Settings::default(),
        }
    }
    fn start(&mut self) {
        if self.listening.is_some() {
            self.error = "Stop passive capture before starting an active scan.".into();
            return;
        }
        let parsed =
            scan::parse_hosts(&self.targets, self.saved.settings.skip_edges).and_then(|hosts| {
                scan::parse_ports(&self.saved.settings.ports).map(|ports| (hosts, ports))
            });
        match parsed {
            Ok((hosts, ports)) => {
                self.previous = self.results.drain(..).map(|h| (h.ip, h)).collect();
                self.selected = None;
                self.observations.clear();
                self.scan_complete = true;
                self.scan_scope = self.targets.clone();
                self.scan_settings = self.saved.settings.clone();
                self.error.clear();
                self.status = format!("Scanning {} addresses", hosts.len());
                self.run = Some(scan::start(hosts, ports, self.saved.settings.clone()));
            }
            Err(e) => self.error = e,
        }
    }
    fn poll(&mut self) {
        let mut done = false;
        let mut changed = false;
        if let Some(run) = &self.run {
            for _ in 0..2048 {
                match run.receiver.try_recv() {
                    Ok(scan::Event::Host(host)) => {
                        self.results.push(host);
                        changed = true;
                    }
                    Ok(scan::Event::Error(e)) => {
                        self.error = e;
                        self.scan_complete = false;
                    }
                    Ok(scan::Event::Done) => {
                        done = true;
                        break;
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        self.scan_complete = false;
                        done = true;
                        break;
                    }
                    Err(_) => break,
                }
            }
            if done {
                self.status = format!(
                    "{} · {} of {} addresses · {:.1}s",
                    if run.cancel.load(Ordering::Relaxed) {
                        "Stopped"
                    } else {
                        "Complete"
                    },
                    self.results.len(),
                    run.total,
                    run.started.elapsed().as_secs_f32()
                );
            }
        }
        if done {
            self.scan_complete &= self
                .run
                .as_ref()
                .map(|r| !r.cancel.load(Ordering::Relaxed))
                .unwrap_or(false);
            self.run = None;
            let snapshot = self.snapshot();
            match store::save(&store::default_path(), &snapshot) {
                Ok(id) => self.status.push_str(&format!(" · saved #{id}")),
                Err(e) => self.error = format!("Inventory could not be saved: {e}"),
            }
        }
        if changed {
            self.sort();
        }
    }
    fn sort(&mut self) {
        self.results.sort_by(|a, b| {
            let order = match self.sort_column {
                1 => b.responding.cmp(&a.responding),
                2 => a.ping.unwrap_or(u32::MAX).cmp(&b.ping.unwrap_or(u32::MAX)),
                3 => a.hostname.cmp(&b.hostname),
                4 => a.open.cmp(&b.open),
                _ => a.ip.cmp(&b.ip),
            }
            .then_with(|| a.ip.cmp(&b.ip));
            if self.sort_reverse {
                order.reverse()
            } else {
                order
            }
        });
    }
    fn visible(&self) -> Vec<usize> {
        let query = self.search.to_lowercase();
        self.results
            .iter()
            .enumerate()
            .filter(|(_, h)| {
                (match self.filter {
                    Filter::All => true,
                    Filter::Responding => h.responding,
                    Filter::Open => !h.open.is_empty(),
                }) && (query.is_empty()
                    || format!(
                        "{} {} {} {} {}",
                        h.ip,
                        h.hostname,
                        serde_json::to_string(&h.identity).unwrap_or_default(),
                        ports_text(&h.open),
                        self.saved
                            .notes
                            .get(&h.ip)
                            .map(String::as_str)
                            .unwrap_or("")
                    )
                    .to_lowercase()
                    .contains(&query))
            })
            .map(|(i, _)| i)
            .collect()
    }
    fn export(&mut self, extension: &str) {
        let Some(path) = rfd::FileDialog::new()
            .set_file_name(format!("network-scan.{extension}"))
            .add_filter("Scan results", &[extension])
            .save_file()
        else {
            return;
        };
        let mut snapshot = self.snapshot();
        snapshot.hosts = self
            .visible()
            .into_iter()
            .map(|i| self.results[i].clone())
            .collect();
        let data = store::export(&snapshot, extension);
        match data.and_then(|data| std::fs::write(&path, data).map_err(|e| e.to_string())) {
            Ok(()) => self.status = format!("Saved {}", path.display()),
            Err(e) => self.error = e,
        }
    }
}

impl eframe::App for Scanner {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        self.poll_capture();
        self.controls(ctx);
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            if let Some(run) = &self.run {
                let label = if run.cancel.load(Ordering::Relaxed) {
                    "Stopping…"
                } else if run.pause.load(Ordering::Relaxed) {
                    "Paused"
                } else {
                    "Scanning"
                };
                ui.add(
                    egui::ProgressBar::new(self.results.len() as f32 / run.total.max(1) as f32)
                        .text(format!(
                            "{label} · {} / {} · {:.1}s",
                            self.results.len(),
                            run.total,
                            run.started.elapsed().as_secs_f32()
                        )),
                );
            }
            ui.horizontal(|ui| {
                ui.label(&self.status);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(format!(
                        "{} responding · {} with open ports",
                        self.results.iter().filter(|h| h.responding).count(),
                        self.results.iter().filter(|h| !h.open.is_empty()).count()
                    ));
                });
            });
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            let visible = self.visible();
            let mut sort = None;
            TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::initial(135.0).at_least(80.0))
                .column(Column::initial(110.0))
                .column(Column::initial(65.0))
                .column(Column::remainder().at_least(80.0))
                .column(Column::initial(140.0))
                .header(26.0, |mut row| {
                    for (i, name) in ["IP address", "Status", "Ping", "Hostname", "Open TCP ports"]
                        .iter()
                        .enumerate()
                    {
                        row.col(|ui| {
                            if ui.selectable_label(self.sort_column == i, *name).clicked() {
                                sort = Some(i);
                            }
                        });
                    }
                })
                .body(|body| {
                    body.rows(26.0, visible.len(), |mut row| {
                        let host = &self.results[visible[row.index()]];
                        row.col(|ui| {
                            if ui
                                .selectable_label(
                                    self.selected == Some(host.ip),
                                    host.ip.to_string(),
                                )
                                .clicked()
                            {
                                self.selected = Some(host.ip);
                            }
                        });
                        row.col(|ui| {
                            ui.colored_label(
                                if host.responding {
                                    Color32::from_rgb(26, 128, 82)
                                } else {
                                    Color32::from_gray(115)
                                },
                                host_status(host),
                            );
                        });
                        row.col(|ui| {
                            ui.label(ping_text(host.ping));
                        });
                        row.col(|ui| {
                            ui.label(if host.hostname.is_empty() {
                                "—"
                            } else {
                                &host.hostname
                            });
                        });
                        row.col(|ui| {
                            ui.label(if host.ports_checked {
                                ports_text(&host.open)
                            } else {
                                "Not checked".into()
                            });
                        });
                    });
                });
            if let Some(column) = sort {
                if self.sort_column == column {
                    self.sort_reverse = !self.sort_reverse;
                } else {
                    self.sort_column = column;
                    self.sort_reverse = false;
                }
                self.sort();
            }
            if visible.is_empty() {
                // Overlay the empty state without inserting fake scan results.
                let center = ui.max_rect().center();
                ui.painter().text(
                    center - egui::vec2(0.0, 8.0),
                    egui::Align2::CENTER_CENTER,
                    if self.results.is_empty() && self.run.is_none() {
                        "Discover devices on your network"
                    } else {
                        "No hosts match this view"
                    },
                    egui::FontId::proportional(18.0),
                    Color32::from_gray(85),
                );
                ui.painter().text(
                    center + egui::vec2(0.0, 20.0),
                    egui::Align2::CENTER_CENTER,
                    if self.run.is_some() {
                        "Results appear as each host finishes."
                    } else if self.results.is_empty() {
                        "Enter addresses and choose Start to begin."
                    } else {
                        "Try All hosts or clear the search."
                    },
                    egui::FontId::proportional(13.0),
                    Color32::from_gray(125),
                );
            }
        });
        self.settings(ctx);
        self.details(ctx);
        self.inventory_window(ctx);
        self.topology_window(ctx);
        self.devices_window(ctx);
        self.findings_window(ctx);
        self.capture_window(ctx);
        if self.run.is_some() || self.listening.is_some() || self.screenshot.is_some() {
            ctx.request_repaint_after(Duration::from_millis(16));
        }
        self.frames += 1;
        if self.screenshot.is_some() && self.frames >= 120 && !self.screenshot_requested {
            self.screenshot_requested = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
        }
        if let Some(path) = &self.screenshot {
            for event in ctx.input(|i| i.events.clone()) {
                if let egui::Event::Screenshot { image, .. } = event {
                    let pixels: Vec<u8> = image.pixels.iter().flat_map(|p| p.to_array()).collect();
                    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    match image::save_buffer(
                        path,
                        &pixels,
                        image.size[0] as u32,
                        image.size[1] as u32,
                        image::ColorType::Rgba8,
                    ) {
                        Ok(()) => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
                        Err(e) => {
                            self.error = format!("Screenshot failed: {e}");
                            eprintln!("{}", self.error);
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    }
                }
            }
        }
    }
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if self.screenshot.is_none() && (self.run.is_some() || self.listening.is_some()) {
            let mut snapshot = self.snapshot();
            snapshot.complete = false;
            if self.listening.is_some() {
                snapshot.targets = self.capture_scope.clone();
            }
            if let Err(e) = store::save(&store::default_path(), &snapshot) {
                eprintln!("Could not save interrupted scan: {e}");
            }
        }
        if let Some(run) = &self.run {
            run.cancel.store(true, Ordering::Relaxed);
        }
        if self.screenshot.is_none() {
            let path = saved_path();
            if let Some(parent) = path.parent() {
                if std::fs::create_dir_all(parent).is_ok() {
                    if let Ok(bytes) = serde_json::to_vec_pretty(&self.saved) {
                        let _ = std::fs::write(path, bytes);
                    }
                }
            }
        }
    }
}
fn ports_text(ports: &[u16]) -> String {
    if ports.is_empty() {
        "—".into()
    } else {
        ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}
fn ping_text(ping: Option<u32>) -> String {
    ping.map(|p| {
        if p == 0 {
            "<1 ms".into()
        } else {
            format!("{p} ms")
        }
    })
    .unwrap_or_else(|| "—".into())
}
fn host_status(host: &scan::Host) -> &'static str {
    if host.responding {
        "Responding"
    } else if !host.errors.is_empty() {
        "Probe error"
    } else {
        "No reply"
    }
}
pub fn run(screenshot: Option<PathBuf>) -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 450.0])
            .with_min_inner_size([700.0, 400.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Network Scope",
        options,
        Box::new(move |cc| Ok(Box::new(Scanner::new(cc, screenshot)))),
    )
}
