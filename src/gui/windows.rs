use super::{Job, Scanner, home, i18n::tr, tables, win_size};
use crate::{capture, devices, passive, risk, store};
use eframe::egui;
use egui_extras::{Column, TableBuilder};
use std::sync::{atomic::Ordering, mpsc::TryRecvError};
/// Combines non-empty, distinct scopes ("10.0.0.0/24 + listen:eth0").
fn combined_scope(scan: &str, capture: &str) -> String {
    match (scan.is_empty(), capture.is_empty()) {
        (_, true) => scan.to_string(),
        (true, false) => capture.to_string(),
        (false, false) if scan == capture => scan.to_string(),
        (false, false) => format!("{scan} + {capture}"),
    }
}
impl Scanner {
    /// Everything on screen: active results plus passive observations (exports, reports).
    pub(super) fn snapshot(&self) -> store::Snapshot {
        let mut notes = self.saved.notes.clone();
        super::prune_notes(&mut notes);
        store::Snapshot {
            sent: self.scan_sent.clone(),
            targets: combined_scope(&self.scan_scope, &self.capture_scope),
            complete: self.scan_complete && self.capture_complete && !self.live(),
            settings: self.scan_settings.clone(),
            hosts: self.results.clone(),
            observations: self.observations.clone(),
            notes,
        }
    }
    /// The active scan alone, as the inventory stores it.
    pub(super) fn scan_snapshot(&self) -> store::Snapshot {
        let mut notes = self.saved.notes.clone();
        super::prune_notes(&mut notes);
        store::Snapshot {
            sent: self.scan_sent.clone(),
            targets: self.scan_scope.clone(),
            complete: self.scan_complete && self.run.is_none(),
            settings: self.scan_settings.clone(),
            hosts: self.results.clone(),
            observations: vec![],
            notes,
        }
    }
    /// The passive capture alone, as the inventory stores it.
    pub(super) fn capture_snapshot(&self) -> store::Snapshot {
        let mut notes = self.saved.notes.clone();
        super::prune_notes(&mut notes);
        store::Snapshot {
            sent: vec![],
            targets: self.capture_scope.clone(),
            complete: self.capture_complete && self.listening.is_none(),
            settings: self.saved.settings.clone(),
            hosts: vec![],
            observations: self.observations.clone(),
            notes,
        }
    }
    /// Confirmation before a scan of public or out-of-scope addresses (ROADMAP H54). "Scan
    /// anyway" starts the scan with consent for this one start; "Cancel" sends nothing.
    pub(super) fn scope_dialog(&mut self, ctx: &egui::Context) {
        let Some((shown_for, text)) = self.scope_confirm.clone() else {
            return;
        };
        let mut choice = None;
        egui::Window::new(tr!("Confirm scan targets"))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(text);
                ui.label(tr!(
                    "Only scan networks you are authorized to test. Nothing has been sent yet."
                ));
                ui.horizontal(|ui| {
                    if ui.button(tr!("Scan anyway")).clicked() {
                        choice = Some(true);
                    }
                    if ui.button(tr!("Cancel")).clicked() {
                        choice = Some(false);
                    }
                });
            });
        match choice {
            Some(true) if shown_for != self.targets => {
                // The targets were edited after the dialog was shown: the answer does not apply.
                self.scope_confirm = None;
                self.status = tr!("Targets changed; press Start again").into();
            }
            Some(true) => {
                self.scope_confirm = None;
                self.scope_consent = crate::scope::Consent {
                    public: true,
                    out_of_scope: true,
                };
                self.start();
            }
            Some(false) => self.scope_confirm = None,
            None => {}
        }
    }
    /// Findings of everything on screen, recomputed when results or observations change.
    pub(super) fn ensure_findings(&mut self) {
        if self.findings.stale(self.generation, self.live()) {
            // Borrow the data into a snapshot instead of deep-cloning it.
            let snapshot = store::Snapshot {
                sent: vec![],
                targets: String::new(),
                complete: false,
                settings: Default::default(),
                hosts: std::mem::take(&mut self.results),
                observations: std::mem::take(&mut self.observations),
                notes: Default::default(),
            };
            #[allow(unused_mut)]
            let mut findings = risk::analyze_snapshot(&snapshot);
            if self.screenshot.is_some() {
                super::demo::decorate_findings(&mut findings);
            }
            self.results = snapshot.hosts;
            self.observations = snapshot.observations;
            self.findings.set(self.generation, findings);
        }
    }

    pub(super) fn findings_window(&mut self, ctx: &egui::Context) {
        if !self.findings_open {
            return;
        }
        self.ensure_findings();
        if self.findings_view.stale(self.findings.generation) {
            self.findings_view.rows =
                tables::finding_rows(&self.findings.value, &self.findings_view);
        }
        let mut open = self.findings_open;
        let mut focus = None;
        let mut sort = None;
        let findings = &self.findings.value;
        let view = &mut self.findings_view;
        egui::Window::new(tr!("Findings (weak configuration, risky services, CVE hints)"))
            .open(&mut open)
            .default_size(win_size([900.0, 420.0]))
            .default_pos(self.window_origin)
            // Wide tables must not push the window past the screen edge.
            .max_width((ctx.content_rect().width() - 24.0).max(320.0))
            .show(ctx, |ui| {
                ui.label(tr!(
                    "{} of {} findings shown. CVE entries are version-based hints; vendors often backport fixes. Click a row to show the host.",
                    view.rows.len(),
                    findings.len()
                ));
                if findings.is_empty() {
                    ui.label(tr!("Nothing found. Enable service detection in Settings to collect the evidence these checks use."));
                    return;
                }
                view.controls_with(ui, "findings_severity", tr!("All severities"), true);
                tables::plain_labels(ui);
                TableBuilder::new(ui)
                    .id_salt("findings_table")
                    .striped(true)
                    .resizable(true)
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(Column::initial(80.0))
                    .column(Column::initial(140.0))
                    .column(Column::initial(240.0).clip(true))
                    .column(Column::initial(220.0).clip(true))
                    .column(Column::initial(130.0).clip(true))
                    .column(Column::initial(80.0))
                    .column(Column::initial(70.0))
                    .column(Column::remainder())
                    .header(22.0, |mut row| {
                        for (i, h) in tables::finding_columns().iter().enumerate() {
                            row.col(|ui| {
                                if tables::header(ui, view, i, h) {
                                    sort = Some(i);
                                }
                            });
                        }
                        row.col(|ui| {
                            ui.strong(tr!("Learn more"));
                        });
                    })
                    .body(|body| {
                        body.rows(22.0, view.rows.len(), |mut row| {
                            let f = &findings[view.rows[row.index()]];
                            row.col(|ui| {
                                ui.colored_label(severity_color(f.severity), home::severity_name(f.severity));
                            });
                            row.col(|ui| {
                                ui.label(format!("{}{}", f.ip, f.port.map_or(String::new(), |p| format!(":{p}"))));
                            });
                            row.col(|ui| {
                                ui.label(&f.title).on_hover_text(&f.advice);
                            });
                            row.col(|ui| {
                                ui.label(f.evidence.chars().take(90).collect::<String>()).on_hover_text(&f.evidence);
                            });
                            row.col(|ui| {
                                ui.label(f.cve.join(", "));
                            });
                            row.col(|ui| {
                                if f.exploit.kev {
                                    let text = if f.exploit.kev_ransomware { "KEV · ransomware" } else { "KEV" };
                                    ui.colored_label(
                                        home::severity_color(risk::Severity::Critical, ui.visuals().dark_mode),
                                        text,
                                    )
                                    .on_hover_text(match (&f.exploit.kev_added, f.exploit.kev_ransomware) {
                                        (Some(date), true) => tr!("Known exploited (CISA KEV, added {}); used in ransomware campaigns", date),
                                        (Some(date), false) => tr!("Known exploited (CISA KEV, added {})", date),
                                        (None, true) => tr!("Known exploited (CISA KEV); used in ransomware campaigns").to_string(),
                                        (None, false) => tr!("Known exploited (CISA KEV)").to_string(),
                                    });
                                }
                            });
                            row.col(|ui| {
                                if let Some(p) = tables::epss_percent(f) {
                                    ui.label(format!("{p:.1} %")).on_hover_text(tr!(
                                        "Estimated probability of exploitation within 30 days (EPSS)"
                                    ));
                                }
                            });
                            row.col(|ui| {
                                // The last column is not clipped, so the links are always visible;
                                // a click opens the default browser.
                                super::convenience::link_to(ui, tr!("Learn more"), &super::docs_url(&f.id));
                                if let Some(url) = f.reference.as_deref().filter(|u| u.starts_with("https://")) {
                                    super::convenience::link_to(ui, tr!("Reference"), url);
                                }
                            });
                            if row.response().clicked() {
                                focus = Some(vec![f.ip]);
                            }
                        });
                    });
            });
        if let Some(column) = sort {
            self.findings_view.click(column);
        }
        if let Some(ips) = focus {
            self.focus_host(&ips);
        }
        self.findings_open = open;
    }
    pub(super) fn devices_window(&mut self, ctx: &egui::Context) {
        if !self.devices_open {
            return;
        }
        if self.devices.stale(self.generation, self.live()) {
            let merged = devices::merge(&self.results, &self.observations);
            self.devices.set(self.generation, merged);
        }
        self.ensure_findings();
        let risk = tables::risk_by_ip(&self.findings.value);
        // Both caches follow the same data generation; recompute when either moved.
        let generation = self
            .devices
            .generation
            .zip(self.findings.generation)
            .map(|(d, f)| d.wrapping_mul(1_000_003) ^ f);
        if self.devices_view.stale(generation) {
            self.devices_view.rows =
                tables::device_rows(&self.devices.value, &risk, &self.devices_view);
        }
        let mut open = self.devices_open;
        let mut focus = None;
        let mut sort = None;
        let devices = &self.devices.value;
        let view = &mut self.devices_view;
        egui::Window::new(tr!("Devices (active + passive merged)"))
            .open(&mut open)
            .default_size(win_size([980.0, 420.0]))
            .default_pos(self.window_origin)
            // Wide tables must not push the window past the screen edge.
            .max_width((ctx.content_rect().width() - 24.0).max(320.0))
            .show(ctx, |ui| {
                ui.label(tr!(
                    "{} of {} devices shown. Records are keyed by MAC address, or by IP when no MAC is known. Click a row to show the host.",
                    view.rows.len(),
                    devices.len()
                ));
                view.controls(ui, "devices_severity", tr!("Any risk"));
                tables::plain_labels(ui);
                TableBuilder::new(ui)
                    .id_salt("devices_table")
                    .striped(true)
                    .resizable(true)
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(Column::initial(150.0).clip(true))
                    .column(Column::initial(150.0).clip(true))
                    .column(Column::initial(150.0).clip(true))
                    .column(Column::initial(110.0).clip(true))
                    .column(Column::initial(120.0).clip(true))
                    .column(Column::initial(150.0).clip(true))
                    .column(Column::remainder())
                    .header(22.0, |mut row| {
                        for (i, h) in tables::device_columns().iter().enumerate() {
                            row.col(|ui| {
                                if tables::header(ui, view, i, h) {
                                    sort = Some(i);
                                }
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(22.0, view.rows.len(), |mut row| {
                            let d = &devices[view.rows[row.index()]];
                            row.col(|ui| {
                                ui.label(
                                    d.ips
                                        .iter()
                                        .map(ToString::to_string)
                                        .collect::<Vec<_>>()
                                        .join(", "),
                                );
                            });
                            row.col(|ui| {
                                ui.label(if d.randomized_mac {
                                    tr!("{} (randomized)", d.mac)
                                } else {
                                    d.mac.clone()
                                });
                            });
                            row.col(|ui| {
                                ui.label(&d.vendor);
                            });
                            row.col(|ui| {
                                ui.label(&d.device_type).on_hover_text(&d.type_evidence);
                            });
                            row.col(|ui| {
                                ui.label(if d.os.is_empty() {
                                    String::new()
                                } else {
                                    format!("{} {}", d.os, d.os_confidence)
                                });
                            });
                            row.col(|ui| {
                                let ports: Vec<String> = d
                                    .open_tcp
                                    .iter()
                                    .map(|p| p.to_string())
                                    .chain(d.open_udp.iter().map(|p| format!("{p}/udp")))
                                    .collect();
                                ui.label(ports.join(", "));
                            });
                            row.col(|ui| {
                                if let Some(s) = tables::device_risk(d, &risk) {
                                    ui.colored_label(severity_color(s), home::severity_name(s));
                                }
                            });
                            if row.response().clicked() {
                                focus = Some(d.ips.clone());
                            }
                        });
                    });
            });
        if let Some(column) = sort {
            self.devices_view.click(column);
        }
        if let Some(ips) = focus {
            self.focus_host(&ips);
        }
        self.devices_open = open;
    }
    pub(super) fn refresh_history(&mut self) {
        if !self.busy.listing {
            self.submit(Job::List);
        }
    }
    pub(super) fn inventory_window(&mut self, ctx: &egui::Context) {
        let mut open = self.history_open;
        egui::Window::new(tr!("Saved inventory & scan differences"))
            .open(&mut open)
            .default_size(win_size([650.0, 420.0]))
            .default_pos(self.window_origin)
            .show(ctx, |ui| {
                ui.label(tr!(
                    "Scans are saved automatically, including interrupted scans marked as partial."
                ));
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(!self.busy.listing, egui::Button::new(tr!("Refresh")))
                        .clicked()
                    {
                        self.refresh_history();
                    }
                    if ui
                        .add_enabled(
                            !self.busy.comparing,
                            egui::Button::new(tr!("Compare A → B")),
                        )
                        .clicked()
                    {
                        match (self.compare_a, self.compare_b) {
                            (Some(a), Some(b)) => self.submit(Job::Diff(a, b)),
                            (None, _) => self.error = tr!("Select baseline A").into(),
                            (_, None) => self.error = tr!("Select scan B").into(),
                        }
                    }
                    if self.busy.listing || self.busy.comparing || self.busy.loading {
                        ui.spinner();
                    }
                });
                let mut load = None;
                let can_open = !self.live() && !self.busy.loading;
                egui::ScrollArea::vertical()
                    .id_salt("history")
                    .max_height(220.0)
                    .show(ui, |ui| {
                        for h in &self.history {
                            ui.horizontal(|ui| {
                                ui.radio_value(&mut self.compare_a, Some(h.id), "A");
                                ui.radio_value(&mut self.compare_b, Some(h.id), "B");
                                ui.label(tr!(
                                    "#{} · {} hosts · {} · {}",
                                    h.id,
                                    h.hosts,
                                    if h.complete {
                                        tr!("complete")
                                    } else {
                                        tr!("partial")
                                    },
                                    h.targets
                                ));
                                if ui
                                    .add_enabled(can_open, egui::Button::new(tr!("Open")))
                                    .clicked()
                                {
                                    load = Some(h.id);
                                }
                            });
                        }
                        if self.history.is_empty() && !self.busy.listing {
                            ui.label(tr!("No saved scans yet. Run a scan to start an inventory."));
                        }
                    });
                if let Some(id) = load {
                    self.submit(Job::Load(id));
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
                        if ui.button(tr!("Export {}", format)).clicked() {
                            self.export(format);
                        }
                    }
                });
            });
        self.history_open = open;
    }
    pub(super) fn poll_capture(&mut self) {
        let mut done = false;
        let mut changed = false;
        if let Some(run) = &self.listening {
            for _ in 0..1024 {
                match run.receiver.try_recv() {
                    Ok(Ok(o)) => {
                        changed = true;
                        if let Err(e) = crate::observations::merge_indexed(
                            &mut self.observations,
                            &mut self.observation_index,
                            o,
                        ) {
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
        if changed {
            self.data_changed();
        }
        if done {
            if let Some(run) = &self.listening {
                self.capture_complete &= !run.cancel.load(Ordering::Relaxed);
            }
            self.listening = None;
            self.data_changed();
            self.status = format!("{} observations · saving capture", self.observations.len());
            let snapshot = self.capture_snapshot();
            self.submit(Job::Save(Box::new(snapshot), "capture"));
        }
    }
    fn begin_capture(&mut self, dcp: bool) {
        if self.busy.loading {
            self.error = tr!("Wait until the inventory scan has been opened.").into();
            return;
        }
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
        // A new capture replaces the previous capture only; active scan results stay so the
        // Devices window can merge both.
        self.reset_observations();
        self.data_changed();
        self.error.clear();
        self.capture_complete = true;
        self.opened_stamp = None;
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
            tr!("DCP Identify running")
        } else {
            tr!("Listening — no packets sent")
        }
        .into();
    }
    pub(super) fn capture_window(&mut self, ctx: &egui::Context) {
        let mut open = self.capture_open;
        egui::Window::new(tr!("Passive discovery / Profinet DCP / OT"))
            .vscroll(true)
            .open(&mut open)
            .default_size(win_size([760.0, 620.0]))
            .default_pos([24.0, 40.0])
            .show(ctx, |ui| {
                ui.label(tr!("Passive: mDNS · SSDP · LLDP · NetBIOS · DHCP · ARP"));
                ui.label(tr!(
                    "Requires Npcap and permission to capture on the selected Ethernet interface."
                ));
                ui.add_enabled_ui(
                    self.listening.is_none() && self.run.is_none() && !self.ot.capturing(),
                    |ui| {
                        if ui.button(tr!("Refresh interfaces")).clicked() {
                            match capture::interfaces() {
                                Ok(v) => self.interfaces = v,
                                Err(e) => self.error = e,
                            }
                        }
                        egui::ComboBox::from_label(tr!("Interface"))
                            .selected_text(if self.saved.settings.interface.is_empty() {
                                tr!("Choose interface")
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
                            ui.label(tr!("Duration"));
                            ui.add(
                                egui::DragValue::new(&mut self.capture_seconds)
                                    .range(1..=86400)
                                    .suffix(format!(" {}", tr!("seconds"))),
                            );
                        });
                        ui.horizontal(|ui| {
                            ui.label(tr!("Interface MAC (DCP / SYN)"));
                            ui.text_edit_singleline(&mut self.saved.settings.source_mac);
                        });
                        ui.horizontal(|ui| {
                            ui.label(tr!("Interface IPv4 (SYN)"));
                            ui.text_edit_singleline(&mut self.saved.settings.source_ip);
                        });
                        ui.horizontal(|ui| {
                            if ui
                                .add_enabled(
                                    !self.saved.settings.interface.is_empty(),
                                    egui::Button::new(tr!("Start passive listening")),
                                )
                                .clicked()
                            {
                                self.begin_capture(false);
                            }
                            if ui
                                .add_enabled(
                                    !self.saved.settings.interface.is_empty(),
                                    egui::Button::new(tr!("DCP Identify (read only)")),
                                )
                                .clicked()
                            {
                                self.begin_capture(true);
                            }
                        });
                    },
                );
                if let Some(run) = &self.listening
                    && ui.button(tr!("Stop capture")).clicked()
                {
                    run.cancel.store(true, Ordering::Relaxed);
                }
                ui.separator();
                ui.label(tr!(
                    "{} observed device/protocol combinations",
                    self.observations.len()
                ));
                // Virtualized: only the rows in view are laid out, even with 10,000 entries.
                let text_height = ui.text_style_height(&egui::TextStyle::Body);
                let row_height = text_height + 2.0 * ui.spacing().button_padding.y;
                let observations = &self.observations;
                let selected = &mut self.capture_selected;
                egui::ScrollArea::vertical()
                    .id_salt("observations")
                    .max_height(260.0)
                    .auto_shrink([false, true])
                    .show_rows(ui, row_height, observations.len(), |ui, range| {
                        for i in range {
                            let o = &observations[i];
                            if ui
                                .selectable_label(
                                    *selected == Some(i),
                                    format!(
                                        "{} · {} · {}",
                                        o.protocol,
                                        o.mac,
                                        o.ip.map(|v| v.to_string())
                                            .unwrap_or_else(|| tr!("No IP advertised").into())
                                    ),
                                )
                                .clicked()
                            {
                                *selected = if *selected == Some(i) { None } else { Some(i) };
                            }
                        }
                    });
                if let Some(o) = self.capture_selected.and_then(|i| self.observations.get(i)) {
                    ui.separator();
                    ui.strong(format!("{} · {}", o.protocol, o.mac));
                    egui::ScrollArea::vertical()
                        .id_salt("observation_fields")
                        .max_height(160.0)
                        .show(ui, |ui| {
                            for (k, v) in &o.fields {
                                ui.label(format!("{k}: {v}"));
                            }
                        });
                }
                if !self.error.is_empty() {
                    ui.colored_label(egui::Color32::from_rgb(205, 70, 70), &self.error);
                }
                self.ot_section(ui);
            });
        self.capture_open = open;
    }
}

fn severity_color(s: risk::Severity) -> egui::Color32 {
    // Same colours as the overview, for the theme that is active.
    home::severity_color(s, dark_mode())
}
thread_local! {
    static DARK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
/// Set once per frame by the window code: whether the dark theme is on.
pub(super) fn set_dark_mode(dark: bool) {
    DARK.with(|d| d.set(dark));
}
fn dark_mode() -> bool {
    DARK.with(std::cell::Cell::get)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn export_scope_names_both_sources() {
        assert_eq!(combined_scope("10.0.0.0/24", ""), "10.0.0.0/24");
        assert_eq!(combined_scope("", "listen:eth0"), "listen:eth0");
        assert_eq!(combined_scope("a", "a"), "a");
        assert_eq!(
            combined_scope("10.0.0.0/24", "listen:eth0"),
            "10.0.0.0/24 + listen:eth0"
        );
        assert_eq!(combined_scope("", ""), "");
    }
}
