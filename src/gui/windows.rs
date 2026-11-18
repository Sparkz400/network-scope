use super::Scanner;
use crate::{capture, devices, passive, risk, store, topology};
use eframe::egui;
use std::sync::{atomic::Ordering, mpsc::TryRecvError};
impl Scanner {
    pub(super) fn snapshot(&self) -> store::Snapshot {
        store::Snapshot {
            targets: self.scan_scope.clone(),
            complete: self.scan_complete && self.run.is_none() && self.listening.is_none(),
            settings: self.scan_settings.clone(),
            hosts: self.results.clone(),
            observations: self.observations.clone(),
            notes: self.saved.notes.clone(),
        }
    }
    pub(super) fn topology_window(&mut self, ctx: &egui::Context) {
        if !self.topology_open {
            return;
        }
        let mut open = self.topology_open;
        egui::Window::new("Network topology")
            .open(&mut open)
            .default_size([780.0, 460.0])
            .show(ctx, |ui| {
                let graph = topology::build(&self.results);
                if graph.nodes.len() <= 1 {
                    ui.label("No path data yet. Enable \"Record router path\" in Settings and scan again.");
                    return;
                }
                ui.label(format!(
                    "{} nodes, {} links. Columns are router hops from this scanner; unanswered hops are shown as *.",
                    graph.nodes.len(),
                    graph.edges.len()
                ));
                egui::ScrollArea::both().show(ui, |ui| {
                    let layers = topology::layers(&graph);
                    let (col_w, row_h) = (190.0, 30.0);
                    let rows = layers.iter().map(Vec::len).max().unwrap_or(1).max(1);
                    let size = egui::vec2(col_w * layers.len() as f32 + 20.0, row_h * rows as f32 + 20.0);
                    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
                    let painter = ui.painter_at(rect);
                    let mut at = vec![egui::Pos2::ZERO; graph.nodes.len()];
                    for (x, layer) in layers.iter().enumerate() {
                        for (y, &node) in layer.iter().enumerate() {
                            at[node] = rect.min + egui::vec2(16.0 + x as f32 * col_w, 16.0 + y as f32 * row_h);
                        }
                    }
                    for &(a, b) in &graph.edges {
                        painter.line_segment([at[a], at[b]], egui::Stroke::new(1.0_f32, egui::Color32::from_gray(170)));
                    }
                    for (i, node) in graph.nodes.iter().enumerate() {
                        let color = match node.kind {
                            topology::Kind::Source => egui::Color32::from_rgb(43, 108, 176),
                            topology::Kind::Router => egui::Color32::from_rgb(113, 128, 150),
                            topology::Kind::Host => egui::Color32::from_rgb(47, 133, 90),
                            topology::Kind::Unknown => egui::Color32::from_gray(190),
                        };
                        painter.circle_filled(at[i], 6.0, color);
                        let label: String = node.label.chars().take(26).collect();
                        painter.text(
                            at[i] + egui::vec2(10.0, 0.0),
                            egui::Align2::LEFT_CENTER,
                            label,
                            egui::FontId::proportional(12.0),
                            egui::Color32::from_gray(30),
                        );
                    }
                });
            });
        self.topology_open = open;
    }

    pub(super) fn findings_window(&mut self, ctx: &egui::Context) {
        if !self.findings_open {
            return;
        }
        let mut open = self.findings_open;
        egui::Window::new("Findings (weak configuration, risky services, CVE hints)")
            .open(&mut open)
            .default_size([900.0, 420.0])
            .show(ctx, |ui| {
                let findings = risk::analyze_snapshot(&self.snapshot());
                ui.label(format!("{} findings. CVE entries are version-based hints; vendors often backport fixes.", findings.len()));
                if findings.is_empty() {
                    ui.label("Nothing found. Enable service detection in Settings to collect the evidence these checks use.");
                }
                egui::ScrollArea::both().show(ui, |ui| {
                    egui::Grid::new("findings_grid").striped(true).num_columns(5).spacing([16.0, 6.0]).show(ui, |ui| {
                        for h in ["Severity", "Host", "Finding", "Evidence", "CVE"] {
                            ui.strong(h);
                        }
                        ui.end_row();
                        for f in &findings {
                            let color = match f.severity {
                                risk::Severity::Critical => egui::Color32::from_rgb(155, 28, 28),
                                risk::Severity::High => egui::Color32::from_rgb(217, 72, 15),
                                risk::Severity::Medium => egui::Color32::from_rgb(180, 120, 0),
                                risk::Severity::Low => egui::Color32::from_rgb(43, 108, 176),
                                risk::Severity::Info => egui::Color32::GRAY,
                            };
                            ui.colored_label(color, f.severity.name());
                            ui.label(format!("{}{}", f.ip, f.port.map_or(String::new(), |p| format!(":{p}"))));
                            ui.label(&f.title).on_hover_text(&f.advice);
                            ui.label(f.evidence.chars().take(90).collect::<String>()).on_hover_text(&f.evidence);
                            ui.label(f.cve.join(", "));
                            ui.end_row();
                        }
                    });
                });
            });
        self.findings_open = open;
    }
    pub(super) fn devices_window(&mut self, ctx: &egui::Context) {
        if !self.devices_open {
            return;
        }
        let mut open = self.devices_open;
        egui::Window::new("Devices (active + passive merged)")
            .open(&mut open)
            .default_size([900.0, 420.0])
            .show(ctx, |ui| {
                let devices = devices::merge(&self.results, &self.observations);
                ui.label(format!(
                    "{} devices. Records are keyed by MAC address, or by IP when no MAC is known.",
                    devices.len()
                ));
                egui::ScrollArea::both().show(ui, |ui| {
                    egui::Grid::new("devices_grid")
                        .striped(true)
                        .num_columns(6)
                        .spacing([18.0, 6.0])
                        .show(ui, |ui| {
                            for h in [
                                "Address",
                                "MAC",
                                "Manufacturer",
                                "Type",
                                "OS guess",
                                "Open ports",
                            ] {
                                ui.strong(h);
                            }
                            ui.end_row();
                            for d in &devices {
                                ui.label(
                                    d.ips
                                        .iter()
                                        .map(ToString::to_string)
                                        .collect::<Vec<_>>()
                                        .join(", "),
                                );
                                ui.label(if d.randomized_mac {
                                    format!("{} (randomized)", d.mac)
                                } else {
                                    d.mac.clone()
                                });
                                ui.label(&d.vendor);
                                ui.label(&d.device_type).on_hover_text(&d.type_evidence);
                                ui.label(if d.os.is_empty() {
                                    String::new()
                                } else {
                                    format!("{} {}", d.os, d.os_confidence)
                                });
                                let ports: Vec<String> = d
                                    .open_tcp
                                    .iter()
                                    .map(|p| p.to_string())
                                    .chain(d.open_udp.iter().map(|p| format!("{p}/udp")))
                                    .collect();
                                ui.label(ports.join(", "));
                                ui.end_row();
                            }
                        });
                });
            });
        self.devices_open = open;
    }
    pub(super) fn refresh_history(&mut self) {
        match store::list(&store::default_path()) {
            Ok(h) => self.history = h,
            Err(e) => self.error = e,
        }
    }
    pub(super) fn inventory_window(&mut self, ctx: &egui::Context) {
        let mut open = self.history_open;
        egui::Window::new("Saved inventory & scan differences")
            .open(&mut open)
            .default_width(650.0)
            .show(ctx, |ui| {
                ui.label(
                    "Scans are saved automatically, including interrupted scans marked as partial.",
                );
                ui.horizontal(|ui| {
                    if ui.button("Refresh").clicked() {
                        self.refresh_history();
                    }
                    if ui.button("Compare A → B").clicked() {
                        let compare = || -> Result<Vec<String>, String> {
                            let path = store::default_path();
                            let a = store::load(&path, self.compare_a.ok_or("Select baseline A")?)?;
                            let b = store::load(&path, self.compare_b.ok_or("Select scan B")?)?;
                            store::diff(&a, &b)
                        };
                        match compare() {
                            Ok(changes) => {
                                self.changes = if changes.is_empty() {
                                    vec!["No observed changes.".into()]
                                } else {
                                    changes
                                }
                            }
                            Err(e) => self.error = e,
                        }
                    }
                });
                let mut load = None;
                egui::ScrollArea::vertical()
                    .id_salt("history")
                    .max_height(220.0)
                    .show(ui, |ui| {
                        for h in &self.history {
                            ui.horizontal(|ui| {
                                ui.radio_value(&mut self.compare_a, Some(h.id), "A");
                                ui.radio_value(&mut self.compare_b, Some(h.id), "B");
                                ui.label(format!(
                                    "#{} · {} hosts · {} · {}",
                                    h.id,
                                    h.hosts,
                                    if h.complete { "complete" } else { "partial" },
                                    h.targets
                                ));
                                if ui
                                    .add_enabled(
                                        self.run.is_none() && self.listening.is_none(),
                                        egui::Button::new("Open"),
                                    )
                                    .clicked()
                                {
                                    load = Some(h.id);
                                }
                            });
                        }
                        if self.history.is_empty() {
                            ui.label("No saved scans yet. Run a scan to start an inventory.");
                        }
                    });
                if let Some(id) = load {
                    match store::load(&store::default_path(), id) {
                        Ok(snapshot) => {
                            self.results = snapshot.hosts;
                            self.observations = snapshot.observations;
                            self.scan_scope = snapshot.targets;
                            self.scan_settings = snapshot.settings;
                            self.scan_complete = snapshot.complete;
                            self.selected = None;
                            self.previous.clear();
                            self.status = format!("Loaded inventory #{id}");
                            self.sort();
                        }
                        Err(e) => self.error = e,
                    }
                }
                ui.separator();
                egui::ScrollArea::vertical()
                    .id_salt("differences")
                    .max_height(200.0)
                    .show(ui, |ui| {
                        for change in &self.changes {
                            ui.label(change);
                        }
                    });
                ui.horizontal(|ui| {
                    for format in ["json", "csv", "html"] {
                        if ui.button(format!("Export {format}")).clicked() {
                            self.export(format);
                        }
                    }
                });
            });
        self.history_open = open;
    }
    pub(super) fn poll_capture(&mut self) {
        let mut done = false;
        if let Some(run) = &self.listening {
            for _ in 0..1024 {
                match run.receiver.try_recv() {
                    Ok(Ok(o)) => {
                        if let Err(e) = crate::ui::merge(&mut self.observations, o) {
                            self.error = e;
                            self.capture_complete = false;
                            run.cancel.store(true, Ordering::Relaxed);
                        }
                    }
                    Ok(Err(e)) => {
                        self.error = e;
                        self.capture_complete = false;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        done = true;
                        break;
                    }
                }
            }
        }
        if done {
            if let Some(run) = &self.listening {
                self.capture_complete &= !run.cancel.load(Ordering::Relaxed);
            }
            self.listening = None;
            self.scan_scope = self.capture_scope.clone();
            self.scan_complete = self.capture_complete;
            self.scan_settings = self.saved.settings.clone();
            match store::save(&store::default_path(), &self.snapshot()) {
                Ok(id) => {
                    self.status = format!(
                        "{} observations · saved capture #{id}",
                        self.observations.len()
                    )
                }
                Err(e) => self.error = e,
            }
        }
    }
    fn begin_capture(&mut self, dcp: bool) {
        let source = if dcp {
            match capture::mac(&self.saved.settings.source_mac) {
                Ok(mac) => Some(mac),
                Err(e) => {
                    self.error = e;
                    return;
                }
            }
        } else {
            None
        };
        self.results.clear();
        self.observations.clear();
        self.selected = None;
        self.error.clear();
        self.capture_complete = true;
        self.capture_scope = format!(
            "{}:{}",
            if dcp { "dcp" } else { "listen" },
            self.saved.settings.interface
        );
        self.listening = Some(passive::start(
            self.saved.settings.interface.clone(),
            self.capture_seconds,
            source,
        ));
        self.status = if dcp {
            "DCP Identify running"
        } else {
            "Listening — no packets sent"
        }
        .into();
    }
    pub(super) fn capture_window(&mut self, ctx: &egui::Context) {
        let mut open = self.capture_open;
        egui::Window::new("Passive discovery / Profinet DCP")
            .vscroll(true)
            .open(&mut open)
            .default_width(660.0)
            .show(ctx, |ui| {
                ui.label("Passive: mDNS · SSDP · LLDP · NetBIOS · DHCP · ARP");
                ui.label(
                    "Requires Npcap and permission to capture on the selected Ethernet interface.",
                );
                ui.add_enabled_ui(self.listening.is_none() && self.run.is_none(), |ui| {
                    if ui.button("Refresh interfaces").clicked() {
                        match capture::interfaces() {
                            Ok(v) => self.interfaces = v,
                            Err(e) => self.error = e,
                        }
                    }
                    egui::ComboBox::from_label("Interface")
                        .selected_text(if self.saved.settings.interface.is_empty() {
                            "Choose interface"
                        } else {
                            &self.saved.settings.interface
                        })
                        .width(440.0)
                        .show_ui(ui, |ui| {
                            for (id, name) in &self.interfaces {
                                ui.selectable_value(
                                    &mut self.saved.settings.interface,
                                    id.clone(),
                                    format!("{name} · {id}"),
                                );
                            }
                        });
                    ui.horizontal(|ui| {
                        ui.label("Duration");
                        ui.add(
                            egui::DragValue::new(&mut self.capture_seconds)
                                .range(1..=86400)
                                .suffix(" seconds"),
                        );
                    });
                    ui.horizontal(|ui| {
                        ui.label("Interface MAC (DCP / SYN)");
                        ui.text_edit_singleline(&mut self.saved.settings.source_mac);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Interface IPv4 (SYN)");
                        ui.text_edit_singleline(&mut self.saved.settings.source_ip);
                    });
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(
                                !self.saved.settings.interface.is_empty(),
                                egui::Button::new("Start passive listening"),
                            )
                            .clicked()
                        {
                            self.begin_capture(false);
                        }
                        if ui
                            .add_enabled(
                                !self.saved.settings.interface.is_empty(),
                                egui::Button::new("DCP Identify (read only)"),
                            )
                            .clicked()
                        {
                            self.begin_capture(true);
                        }
                    });
                });
                if let Some(run) = &self.listening {
                    if ui.button("Stop capture").clicked() {
                        run.cancel.store(true, Ordering::Relaxed);
                    }
                }
                ui.separator();
                ui.label(format!(
                    "{} observed device/protocol combinations",
                    self.observations.len()
                ));
                egui::ScrollArea::vertical()
                    .max_height(300.0)
                    .show(ui, |ui| {
                        for o in &self.observations {
                            ui.collapsing(
                                format!(
                                    "{} · {} · {}",
                                    o.protocol,
                                    o.mac,
                                    o.ip.map(|v| v.to_string())
                                        .unwrap_or_else(|| "No IP advertised".into())
                                ),
                                |ui| {
                                    for (k, v) in &o.fields {
                                        ui.label(format!("{k}: {v}"));
                                    }
                                },
                            );
                        }
                    });
                if !self.error.is_empty() {
                    ui.colored_label(egui::Color32::DARK_RED, &self.error);
                }
            });
        self.capture_open = open;
    }
}
