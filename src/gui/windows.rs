use super::{Job, Scanner, a11y, home, i18n::tr, tables};
use crate::{capture, devices, passive, risk, scan, store};
use eframe::egui::{self, RichText};
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
/// The settings a scan that starts now runs with: the ones in the window, stamped with the
/// provenance (tool version and hashes of the rules and feeds in effect, ROADMAP L72) like a
/// scan from the CLI, the monitor or MCP. The preferences keep the unstamped settings.
pub(super) fn settings_for_scan(current: &scan::Settings) -> scan::Settings {
    crate::provenance::stamped(current)
}

/// A hash cut to `sha256:` and its first 16 digits.
fn short_hash(hash: &str) -> String {
    let (algorithm, digits) = hash.split_once(':').unwrap_or(("", hash));
    let cut: String = digits.chars().take(16).collect();
    let more = if digits.chars().count() > 16 {
        "…"
    } else {
        ""
    };
    if algorithm.is_empty() {
        format!("{cut}{more}")
    } else {
        format!("{algorithm}:{cut}{more}")
    }
}

/// What the "Scan details" section says about the provenance of the scan on screen.
pub(super) fn provenance_lines(provenance: Option<&crate::provenance::Provenance>) -> Vec<String> {
    let Some(p) = provenance else {
        return vec![
            tr!(
                "No provenance stamp: the scan was saved before stamps existed or it is an import, so the rules it ran with are not known."
            )
            .to_string(),
        ];
    };
    let mut lines = vec![tr!("Tool: {}", p.tool)];
    for (name, hash) in &p.rules {
        lines.push(tr!("Rules {}: {}", name, short_hash(hash)));
    }
    if p.feeds.is_empty() {
        lines.push(tr!("Data feeds: none in use").to_string());
    }
    for (name, hash) in &p.feeds {
        lines.push(tr!("Feed {}: {}", name, short_hash(hash)));
    }
    lines
}

/// The line to cite a scan by (tool and combined hash), also what the Copy button puts on the
/// clipboard.
pub(super) fn provenance_cite(p: &crate::provenance::Provenance) -> String {
    format!("{} {}", p.tool, p.combined)
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

    /// The Findings page.
    pub(super) fn findings_view(&mut self, ui: &mut egui::Ui) {
        self.ensure_findings();
        self.ensure_hostnames();
        // The rule a grouped row opened has no findings any more (a new scan, an opened scan, a
        // vendor statement): back to the full list. Nothing would be listed, and "Show all
        // findings" is only offered next to a rule that exists.
        let findings = &self.findings.value;
        if (self.findings_view.rule.as_ref()).is_some_and(|r| !findings.iter().any(|f| &f.id == r))
        {
            self.findings_view.rule = None;
        }
        if self.findings_view.stale(self.findings.generation) {
            self.findings_view.rows =
                tables::finding_rows(&self.findings.value, &self.findings_view);
            self.finding_groups =
                tables::finding_groups(&self.findings.value, &self.findings_view.rows);
        }
        let mut focus = None;
        let mut sort = None;
        let mut open_group: Option<String> = None;
        let mut show_all = false;
        let findings = &self.findings.value;
        let view = &mut self.findings_view;
        let group = &mut self.saved.group_findings;
        let groups = &self.finding_groups;
        let names = &self.hostnames.value;
        page(
            ui,
            tr!("Findings (weak configuration, risky services, CVE hints)"),
            |ui| {
                // One line, cut short in a narrow window (hovering shows all of it): two wrapped
                // lines cost the table two rows.
                ui.add(
                    egui::Label::new(tr!(
                        "{} of {} findings shown. CVE entries are version-based hints; vendors often backport fixes. Click a row to show the host.",
                        view.rows.len(),
                        findings.len()
                    ))
                    .truncate(),
                );
                if findings.is_empty() {
                    ui.label(tr!("Nothing found. Enable service detection in Settings to collect the evidence these checks use."));
                    return;
                }
                view.controls_with(ui, "findings_severity", tr!("All severities"), true);
                // The hosts of one rule (a grouped row was clicked), or the choice to group.
                let shown_rule = view
                    .rule
                    .as_ref()
                    .and_then(|r| findings.iter().find(|f| &f.id == r))
                    .map(|f| f.title.clone());
                if let Some(title) = shown_rule {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(tr!("The hosts of: {}", title));
                        if ui.button(tr!("Show all findings")).clicked() {
                            show_all = true;
                        }
                    });
                } else {
                    ui.checkbox(group, tr!("Group by finding"))
                        .on_hover_text(tr!("One row per finding with the hosts it affects. Click a row to list its hosts."));
                }
                let grouped = *group && view.rule.is_none();
                tables::plain_labels(ui);
                // Wide tables scroll sideways instead of running past the edge.
                // The bar stays visible, so it is clear that more columns are to the right.
                egui::ScrollArea::horizontal()
                    .id_salt("findings_scroll")
                    .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
                    .show(ui, |ui| {
                        if grouped {
                            TableBuilder::new(ui)
                                .id_salt("finding_groups_table")
                                .striped(true)
                                .resizable(true)
                                .sense(egui::Sense::click())
                                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                                // The finding takes the room that is left: its title is what
                                // the row is about.
                                .column(Column::initial(65.0))
                                .column(Column::remainder().at_least(215.0).clip(true))
                                .column(Column::initial(180.0).clip(true))
                                .column(Column::initial(110.0).clip(true))
                                .column(Column::initial(65.0).clip(true))
                                .column(Column::initial(55.0))
                                .column(Column::initial(150.0))
                                .header(22.0, |mut row| {
                                    for h in [
                                        tr!("Severity"),
                                        tr!("Finding"),
                                        tr!("Hosts"),
                                        tr!("CVE"),
                                        tr!("KEV"),
                                        tr!("EPSS"),
                                        tr!("Learn more"),
                                    ] {
                                        row.col(|ui| {
                                            ui.strong(h);
                                        });
                                    }
                                })
                                .body(|body| {
                                    body.rows(22.0, groups.len(), |mut row| {
                                        let members = &groups[row.index()];
                                        let f = &findings[members[0]];
                                        row.col(|ui| {
                                            ui.colored_label(
                                                severity_color(f.severity),
                                                home::severity_name(f.severity),
                                            );
                                        });
                                        let mut chosen = false;
                                        row.col(|ui| {
                                            super::explain_button(ui, &f.id);
                                            chosen = tables::row_link(ui, &f.title)
                                                .on_hover_text(&f.advice)
                                                .clicked();
                                        });
                                        row.col(|ui| {
                                            ui.strong(members.len().to_string());
                                            ui.label(tables::group_hosts(findings, members, 3))
                                                .on_hover_text(tables::group_hosts(
                                                    findings, members, 40,
                                                ));
                                        });
                                        row.col(|ui| {
                                            ui.label(f.cve.join(", "));
                                        });
                                        row.col(|ui| {
                                            kev_label(ui, f);
                                        });
                                        row.col(|ui| {
                                            epss_label(ui, f);
                                        });
                                        row.col(|ui| {
                                            links(ui, f);
                                        });
                                        if row.response().clicked() || chosen {
                                            open_group = Some(f.id.clone());
                                        }
                                    });
                                });
                            return;
                        }
                        TableBuilder::new(ui)
                            .id_salt("findings_table")
                            .striped(true)
                            .resizable(true)
                            .sense(egui::Sense::click())
                            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                            // The finding takes the room that is left (a wide window shows
                            // the whole title). The fixed columns fit a 1100 px window with
                            // both links in view; below that the table scrolls sideways.
                            .column(Column::initial(65.0))
                            .column(Column::initial(140.0).clip(true))
                            .column(Column::remainder().at_least(150.0).clip(true))
                            .column(Column::initial(95.0).clip(true))
                            .column(Column::initial(105.0).clip(true))
                            .column(Column::initial(50.0).clip(true))
                            .column(Column::initial(55.0))
                            .column(Column::initial(160.0))
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
                                        match &f.vex {
                                            // The vendor says it does not apply: greyed, with why.
                                            Some(v) if v.state.resolves() => {
                                                ui.weak(format!(
                                                    "{} · {}",
                                                    home::severity_name(f.severity),
                                                    tr!("VEX: {}", v.state.label())
                                                ))
                                                .on_hover_text(vex_hover(v));
                                            }
                                            Some(v) => {
                                                ui.colored_label(
                                                    severity_color(f.severity),
                                                    home::severity_name(f.severity),
                                                )
                                                .on_hover_text(vex_hover(v));
                                            }
                                            None => {
                                                ui.colored_label(
                                                    severity_color(f.severity),
                                                    home::severity_name(f.severity),
                                                );
                                            }
                                        }
                                    });
                                    let mut chosen = false;
                                    row.col(|ui| {
                                        // The address with the port, then the host name when
                                        // known. The address is the keyboard way to the row.
                                        let address = tables::host_port(f);
                                        let name = names.get(&f.ip);
                                        let cell = tables::row_link(ui, &address);
                                        chosen = cell.clicked();
                                        tables::copy_menu(&cell, || {
                                            tables::finding_copies(f, name)
                                        });
                                        if let Some(name) = name {
                                            cell.on_hover_text(format!("{address} · {name}"));
                                            ui.weak(name);
                                        }
                                    });
                                    row.col(|ui| {
                                        // The "?" first: the column clips long titles.
                                        super::explain_button(ui, &f.id);
                                        ui.label(f.title_with_vex()).on_hover_text(&f.advice);
                                    });
                                    row.col(|ui| {
                                        ui.label(f.evidence.chars().take(90).collect::<String>())
                                            .on_hover_text(&f.evidence);
                                    });
                                    row.col(|ui| {
                                        ui.label(f.cve.join(", "));
                                    });
                                    row.col(|ui| {
                                        kev_label(ui, f);
                                    });
                                    row.col(|ui| {
                                        epss_label(ui, f);
                                    });
                                    row.col(|ui| {
                                        links(ui, f);
                                    });
                                    let whole = row.response();
                                    tables::copy_menu(&whole, || {
                                        tables::finding_copies(f, names.get(&f.ip))
                                    });
                                    if whole.clicked() || chosen {
                                        focus = Some(vec![f.ip]);
                                    }
                                });
                            });
                    });
            },
        );
        if let Some(column) = sort {
            self.findings_view.click(column);
        }
        if let Some(ips) = focus {
            self.focus_host(&ips);
        }
        // A rule was clicked in the grouped view: list its hosts (the grouping and the text
        // filter stay as they are, for "Show all findings").
        if let Some(id) = open_group {
            self.findings_view.rule = Some(id);
        }
        if show_all {
            self.findings_view.rule = None;
        }
    }
    /// The merged devices, recomputed when results or observations change.
    pub(super) fn ensure_devices(&mut self) {
        if self.devices.stale(self.generation, self.live()) {
            let merged = devices::merge(&self.results, &self.observations);
            self.devices.set(self.generation, merged);
        }
    }
    /// The Devices page.
    pub(super) fn devices_view(&mut self, ui: &mut egui::Ui) {
        self.ensure_devices();
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
        let mut focus = None;
        let mut sort = None;
        let mut workbench = false;
        let devices = &self.devices.value;
        let view = &mut self.devices_view;
        let mode = &mut self.view;
        // No heading: this is the Hosts page in its device mode, with the same switch first.
        ui.scope(|ui| {
            ui.horizontal_wrapped(|ui| {
                super::controls::mode_switch(ui, mode);
                view.controls(ui, "devices_severity", tr!("Any risk"));
                if ui
                    .button(tr!("Unknown devices…"))
                    .on_hover_text(tr!(
                        "Group the banners that no rule identified, compare firmware versions and draft a probe rule."
                    ))
                    .clicked()
                {
                    workbench = true;
                }
            });
            ui.weak(tr!(
                "{} of {} devices shown. Records are keyed by MAC address, or by IP when no MAC is known. Click a row to show the host.",
                view.rows.len(),
                devices.len()
            ));
            tables::plain_labels(ui);
            egui::ScrollArea::horizontal()
                .id_salt("devices_scroll")
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
                .show(ui, |ui| {
                    TableBuilder::new(ui)
                        .id_salt("devices_table")
                        .striped(true)
                        .resizable(true)
                        .sense(egui::Sense::click())
                        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                        // Fits a 1100 px window next to the sidebar; Manufacturer takes the rest.
                        .column(Column::initial(130.0).clip(true))
                        .column(Column::initial(150.0).clip(true))
                        .column(Column::remainder().at_least(110.0).clip(true))
                        .column(Column::initial(120.0).clip(true))
                        .column(Column::initial(100.0).clip(true))
                        .column(Column::initial(140.0).clip(true))
                        .column(Column::initial(70.0))
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
                                let mut chosen = false;
                                row.col(|ui| {
                                    // The keyboard way to the row, as in the hosts table.
                                    let cell = tables::row_link(
                                        ui,
                                        &d.ips
                                            .iter()
                                            .map(ToString::to_string)
                                            .collect::<Vec<_>>()
                                            .join(", "),
                                    );
                                    chosen = cell.clicked();
                                    tables::copy_menu(&cell, || tables::device_copies(d));
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
                                let whole = row.response();
                                tables::copy_menu(&whole, || tables::device_copies(d));
                                if whole.clicked() || chosen {
                                    focus = Some((d.ips.clone(), d.id.clone()));
                                }
                            });
                        });
                });
        });
        if let Some(column) = sort {
            self.devices_view.click(column);
        }
        if let Some((ips, id)) = focus {
            // A device the scan did not reach has no host to show: its own details open.
            if !self.try_focus_host(&ips) {
                self.selected = None;
                self.selected_device = Some(id);
            }
        }
        if workbench {
            self.open_workbench();
        }
    }
    pub(super) fn refresh_history(&mut self) {
        // Screenshot runs show sample data and never read the inventory.
        if !self.busy.listing && self.screenshot.is_none() {
            self.submit(Job::List);
        }
    }
    /// The Saved inventory page.
    pub(super) fn inventory_view(&mut self, ui: &mut egui::Ui) {
        page(ui, tr!("Saved inventory & scan differences"), |ui| {
            egui::ScrollArea::vertical()
                .id_salt("inventory_page")
                .show(ui, |ui| {
                    ui.label(tr!(
                    "Scans are saved automatically, including interrupted scans marked as partial."
                ));
                    // What a scan is called in the list and in the two pickers.
                    let when = |h: &store::Entry| crate::report::fmt_time(h.timestamp);
                    let pick = |id: Option<i64>, history: &[store::Entry]| {
                        (history.iter().find(|h| Some(h.id) == id))
                            .map_or(tr!("choose a scan").to_string(), |h| {
                                format!("#{} · {}", h.id, when(h))
                            })
                    };
                    ui.horizontal_wrapped(|ui| {
                        if ui
                            .add_enabled(!self.busy.listing, egui::Button::new(tr!("Refresh")))
                            .clicked()
                        {
                            self.refresh_history();
                        }
                        ui.separator();
                        // Two pickers instead of an "A" and a "B" button on every row.
                        ui.label(tr!("Compare"));
                        for (salt, name, slot) in [
                            ("compare_a", tr!("Older scan (A)"), &mut self.compare_a),
                            ("compare_b", tr!("Newer scan (B)"), &mut self.compare_b),
                        ] {
                            let combo = egui::ComboBox::from_id_salt(salt)
                                .selected_text(pick(*slot, &self.history))
                                .width(210.0)
                                .show_ui(ui, |ui| {
                                    for h in &self.history {
                                        ui.selectable_value(
                                            slot,
                                            Some(h.id),
                                            format!("#{} · {} · {}", h.id, when(h), h.targets),
                                        );
                                    }
                                });
                            a11y::named(combo.response, name).on_hover_text(name);
                            if salt == "compare_a" {
                                ui.label(tr!("with"));
                            }
                        }
                        if ui
                            .add_enabled(
                                !self.busy.comparing,
                                egui::Button::new(tr!("Compare A to B")),
                            )
                            .clicked()
                        {
                            match (self.compare_a, self.compare_b) {
                                (Some(a), Some(b)) => self.submit(Job::Diff(a, b)),
                                (None, _) => self.error = tr!("Select baseline A").into(),
                                (_, None) => self.error = tr!("Select scan B").into(),
                            }
                        }
                    });
                    let mut load = None;
                    let can_open = !self.live() && !self.busy.loading;
                    let row_height = ui.spacing().interact_size.y;
                    if self.history.is_empty() && !self.busy.listing {
                        ui.label(tr!("No saved scans yet. Run a scan to start an inventory."));
                    }
                    // Only the rows in view are laid out: a monitor fills this list.
                    egui::ScrollArea::vertical()
                        .id_salt("history")
                        .max_height(220.0)
                        .show_rows(ui, row_height, self.history.len(), |ui, range| {
                            for h in &self.history[range] {
                                ui.horizontal(|ui| {
                                    let open =
                                        ui.add_enabled(can_open, egui::Button::new(tr!("Open")));
                                    if a11y::named(open, &tr!("Open scan #{}", h.id)).clicked() {
                                        load = Some(h.id);
                                    }
                                    let delete = ui.add_enabled(
                                        !self.busy.listing,
                                        egui::Button::new(tr!("Delete")),
                                    );
                                    if a11y::named(delete, &tr!("Delete scan #{}", h.id)).clicked()
                                    {
                                        self.delete_ask = Some(h.id);
                                    }
                                    ui.label(tr!(
                                        "#{} · {} · {} hosts · {} · {}",
                                        h.id,
                                        when(h),
                                        h.hosts,
                                        if h.complete {
                                            tr!("complete")
                                        } else {
                                            tr!("partial")
                                        },
                                        h.targets
                                    ));
                                });
                            }
                        });
                    if let Some(id) = load {
                        // The opened scan is shown on the Hosts page.
                        self.view = super::MainView::Hosts;
                        if self.screenshot.is_none() {
                            self.submit(Job::Load(id));
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
                    self.scan_details(ui);
                    ui.horizontal(|ui| {
                        for format in ["json", "csv", "html"] {
                            if ui.button(tr!("Export {}", format)).clicked() {
                                self.export(format);
                            }
                        }
                    });
                });
        });
    }
    /// Asked before a saved scan is deleted (the Inventory page): it cannot be undone.
    pub(super) fn delete_dialog(&mut self, ctx: &egui::Context) {
        let Some(id) = self.delete_ask else {
            return;
        };
        let Some(scan) = self.history.iter().find(|h| h.id == id) else {
            self.delete_ask = None;
            return;
        };
        let mut choice = None;
        egui::Window::new(tr!("Delete scan #{}?", id))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_max_width(420.0);
                ui.label(tr!(
                    "The scan of {} from {} ({} hosts) is deleted from the inventory with the alerts raised for it. This cannot be undone.",
                    scan.targets,
                    crate::report::fmt_time(scan.timestamp),
                    scan.hosts
                ));
                ui.horizontal(|ui| {
                    if ui.button(tr!("Delete")).clicked() {
                        choice = Some(true);
                    }
                    if ui.button(tr!("Keep")).clicked() {
                        choice = Some(false);
                    }
                });
            });
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape)) {
            choice = Some(false);
        }
        if let Some(delete) = choice {
            self.delete_ask = None;
            if delete && self.screenshot.is_none() {
                self.submit(Job::Delete(id));
            }
        }
    }
    /// Where the scan on screen came from: its source, whether it finished and the provenance
    /// stamp (tool version and rule hashes) with a button that copies the line to cite it by.
    fn scan_details(&self, ui: &mut egui::Ui) {
        egui::CollapsingHeader::new(tr!("Scan details"))
            .id_salt("scan_details")
            .default_open(self.screenshot.is_some())
            .show(ui, |ui| {
                if self.results.is_empty() && self.scan_scope.is_empty() {
                    ui.label(tr!("No scan on screen."));
                    return;
                }
                let state = if self.run.is_some() {
                    tr!("running")
                } else if self.scan_complete {
                    tr!("complete")
                } else {
                    tr!("partial")
                };
                ui.label(match self.loaded_scan {
                    Some(id) => tr!("Saved scan #{} · {} · {}", id, self.scan_scope, state),
                    None => tr!("Scan not saved yet · {} · {}", self.scan_scope, state),
                });
                let provenance = self.scan_settings.provenance.as_ref();
                for line in provenance_lines(provenance) {
                    ui.label(line);
                }
                if let Some(p) = provenance {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(tr!("Combined hash (cite this):"));
                        ui.label(RichText::new(&p.combined).monospace().small());
                        if ui.button(tr!("Copy")).clicked() {
                            ui.ctx().copy_text(provenance_cite(p));
                        }
                    });
                }
            });
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
            self.status = tr!("{} observations · saving capture", self.observations.len());
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
    /// The Passive discovery / OT page.
    pub(super) fn capture_view(&mut self, ui: &mut egui::Ui) {
        page(ui, tr!("Passive discovery / Profinet DCP / OT"), |ui| {
            egui::ScrollArea::both().id_salt("capture_page").show(ui, |ui| {
                ui.label(tr!("Passive: mDNS · SSDP · LLDP · CDP · NetBIOS · WS-Discovery · DHCP · DHCPv6 · ARP"));
                ui.label(tr!(
                    "Requires Npcap and permission to capture on the selected Ethernet interface."
                ));
                ui.add_enabled_ui(
                    self.listening.is_none() && self.run.is_none() && !self.ot.capturing(),
                    |ui| {
                        // The list is read once when the page is first shown (quietly: without
                        // a capture driver the page still explains what it needs).
                        if !std::mem::replace(&mut self.interfaces_tried, true)
                            && self.interfaces.is_empty()
                            && self.screenshot.is_none()
                        {
                            self.interfaces = capture::interfaces().unwrap_or_default();
                        }
                        if ui.button(tr!("Refresh interfaces")).clicked() {
                            match capture::interfaces() {
                                Ok(v) => self.interfaces = v,
                                Err(e) => self.error = e,
                            }
                        }
                        let chosen_before = self.saved.settings.interface.clone();
                        let chosen = &self.saved.settings.interface;
                        egui::ComboBox::from_label(tr!("Interface"))
                            .selected_text(if chosen.is_empty() {
                                tr!("Choose interface").to_string()
                            } else {
                                // By its name when the list has it; the device id says little.
                                (self.interfaces.iter().find(|(id, _)| id == chosen))
                                    .map_or(chosen.clone(), |(id, name)| format!("{name} · {id}"))
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
                            let label = ui.label(tr!("Duration"));
                            ui.add(
                                egui::DragValue::new(&mut self.capture_seconds)
                                    .range(1..=86400)
                                    .suffix(format!(" {}", tr!("seconds"))),
                            )
                            .labelled_by(label.id);
                        });
                        // The interface's own addresses, where the system tells them: filled
                        // in when the interface is chosen and the fields are empty (a typed
                        // value, or a list for several interfaces, is never replaced unasked).
                        let own = (self.saved.settings.interface != chosen_before)
                            .then(|| {
                                capture::interface_addresses(&self.saved.settings.interface)
                            })
                            .flatten();
                        if let Some((mac, ip)) = own {
                            let s = &mut self.saved.settings;
                            if s.source_mac.trim().is_empty() {
                                s.source_mac = mac;
                            }
                            if s.source_ip.trim().is_empty() {
                                s.source_ip = ip;
                            }
                        }
                        ui.horizontal(|ui| {
                            let label = ui.label(tr!("Interface MAC (DCP / SYN)"));
                            ui.text_edit_singleline(&mut self.saved.settings.source_mac)
                                .labelled_by(label.id);
                        });
                        ui.horizontal(|ui| {
                            let label = ui.label(tr!("Interface IPv4 (SYN)"));
                            ui.text_edit_singleline(&mut self.saved.settings.source_ip)
                                .labelled_by(label.id);
                            if ui
                                .add_enabled(
                                    !self.saved.settings.interface.is_empty(),
                                    egui::Button::new(tr!("Use the interface's addresses")),
                                )
                                .on_hover_text(tr!(
                                    "Fills in the MAC and IPv4 address of the chosen interface, replacing what is there."
                                ))
                                .clicked()
                            {
                                match capture::interface_addresses(
                                    &self.saved.settings.interface,
                                ) {
                                    Some((mac, ip)) if !mac.is_empty() || !ip.is_empty() => {
                                        self.saved.settings.source_mac = mac;
                                        self.saved.settings.source_ip = ip;
                                    }
                                    _ => {
                                        self.error = tr!(
                                            "The addresses of this interface could not be read; enter them by hand."
                                        )
                                        .into()
                                    }
                                }
                            }
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
                // Errors show under the scan controls, above every page.
                self.ot_section(ui);
            });
        });
    }
}

/// "KEV" (with "ransomware" when it was used in such campaigns) for a known exploited finding.
fn kev_label(ui: &mut egui::Ui, f: &risk::Finding) {
    if !f.exploit.kev {
        return;
    }
    let text = if f.exploit.kev_ransomware {
        "KEV · ransomware"
    } else {
        "KEV"
    };
    ui.colored_label(
        home::severity_color(risk::Severity::Critical, ui.visuals().dark_mode),
        text,
    )
    .on_hover_text(match (&f.exploit.kev_added, f.exploit.kev_ransomware) {
        (Some(date), true) => tr!(
            "Known exploited (CISA KEV, added {}); used in ransomware campaigns",
            date
        ),
        (Some(date), false) => tr!("Known exploited (CISA KEV, added {})", date),
        (None, true) => tr!("Known exploited (CISA KEV); used in ransomware campaigns").to_string(),
        (None, false) => tr!("Known exploited (CISA KEV)").to_string(),
    });
}

/// The EPSS of a finding in percent, when the feeds gave one.
fn epss_label(ui: &mut egui::Ui, f: &risk::Finding) {
    if let Some(p) = tables::epss_percent(f) {
        ui.label(format!("{p:.1} %")).on_hover_text(tr!(
            "Estimated probability of exploitation within 30 days (EPSS)"
        ));
    }
}

/// The documentation page of a finding and its reference; a click opens the default browser.
pub(super) fn links(ui: &mut egui::Ui, f: &risk::Finding) {
    super::convenience::link_to(ui, tr!("Learn more"), &super::docs_url(&f.id));
    if let Some(url) = f.reference.as_deref().filter(|u| u.starts_with("https://")) {
        super::convenience::link_to(ui, tr!("Reference"), url);
    }
}

/// A full-size page of the main window: its title, then the content.
pub(super) fn page(ui: &mut egui::Ui, title: &str, add: impl FnOnce(&mut egui::Ui)) {
    ui.heading(title);
    ui.add_space(2.0);
    add(ui);
}

/// What a VEX statement says, for the hover text of a finding.
fn vex_hover(v: &crate::vex::Applied) -> String {
    let mut text = tr!("Vendor statement (VEX {}): {}", v.source, v.state.label());
    if !v.justification.is_empty() {
        text.push_str(&format!(" ({})", v.justification));
    }
    if !v.detail.is_empty() {
        text.push_str(&format!("\n{}", v.detail));
    }
    text
}

pub(super) fn severity_color(s: risk::Severity) -> egui::Color32 {
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

    #[test]
    fn a_gui_scan_carries_the_provenance_stamp_like_a_cli_scan() {
        let window = scan::Settings {
            ports: "22,80".into(),
            ..Default::default()
        };
        assert!(window.provenance.is_none());
        let used = settings_for_scan(&window);
        let p = used.provenance.clone().expect("a stamp");
        assert_eq!(p, crate::provenance::Provenance::current(&window));
        assert!(p.tool.starts_with("network-scope "), "{}", p.tool);
        assert!(p.combined.starts_with("sha256:"), "{}", p.combined);
        for rules in ["probes.json", "cves.json", "compliance.json"] {
            assert!(p.rules.contains_key(rules), "{rules}");
        }
        // Everything else is what the window had, and the same call as the CLI makes.
        assert_eq!(used.ports, "22,80");
        assert_eq!(
            serde_json::to_string(&used).unwrap(),
            serde_json::to_string(&crate::provenance::stamped(&window)).unwrap()
        );
        // The settings in the window (and so the preferences file) never get the stamp.
        assert!(window.provenance.is_none());
        let saved = super::super::Saved {
            settings: window,
            ..Default::default()
        };
        let prefs = String::from_utf8(saved.to_disk()).unwrap();
        assert!(!prefs.contains("provenance"), "{prefs}");
    }

    #[test]
    fn every_gui_scan_start_goes_through_the_stamping_helper() {
        let code = include_str!("mod.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap()
            .to_string();
        assert!(
            code.contains("self.scan_settings = windows::settings_for_scan(&self.saved.settings);")
        );
        assert!(
            !code.contains("self.scan_settings = self.saved.settings.clone()"),
            "a scan would be saved without its provenance"
        );
    }

    #[test]
    fn the_details_show_the_stamp_or_say_there_is_none() {
        let none = provenance_lines(None);
        assert_eq!(none.len(), 1);
        assert!(none[0].starts_with("No provenance stamp"), "{none:?}");
        let mut rules = std::collections::BTreeMap::new();
        rules.insert("cves.json".to_string(), crate::provenance::hash(b"rules"));
        let p = crate::provenance::Provenance::with(rules, Default::default());
        let lines = provenance_lines(Some(&p));
        assert!(lines[0].starts_with("Tool: network-scope "), "{lines:?}");
        assert!(
            lines[1].starts_with("Rules cves.json: sha256:"),
            "{lines:?}"
        );
        assert!(lines[1].ends_with('…'), "a long hash is cut: {lines:?}");
        assert_eq!(lines[2], "Data feeds: none in use");
        assert_eq!(lines.len(), 3);
        let mut feeds = std::collections::BTreeMap::new();
        feeds.insert("nvd".to_string(), crate::provenance::hash(b"feed"));
        let with_feed = crate::provenance::Provenance::with(Default::default(), feeds);
        let lines = provenance_lines(Some(&with_feed));
        assert!(
            lines.iter().any(|l| l.starts_with("Feed nvd: sha256:")),
            "{lines:?}"
        );
        assert!(!lines.iter().any(|l| l.contains("none in use")));
        // What the Copy button gives: the tool and the full combined hash.
        let cite = provenance_cite(&p);
        assert_eq!(cite, format!("{} {}", p.tool, p.combined));
        assert_eq!(cite.len(), p.tool.len() + 1 + 71);
        assert_eq!(
            short_hash("sha256:0123456789abcdef0123"),
            "sha256:0123456789abcdef…"
        );
        assert_eq!(short_hash("sha256:0123"), "sha256:0123");
    }

    #[test]
    fn the_stamp_survives_the_inventory_and_shows_when_the_scan_is_opened_again() {
        let path = std::env::temp_dir().join(format!(
            "ns-gui-provenance-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let snapshot = |settings: scan::Settings| store::Snapshot {
            sent: vec![],
            targets: "10.0.0.0/24".into(),
            complete: true,
            settings,
            hosts: vec![],
            observations: vec![],
            notes: Default::default(),
        };
        let stamped = settings_for_scan(&scan::Settings::default());
        let with = store::save(&path, &snapshot(stamped.clone())).unwrap();
        let without = store::save(&path, &snapshot(scan::Settings::default())).unwrap();
        let opened = store::load(&path, with).unwrap();
        assert_eq!(opened.settings.provenance, stamped.provenance);
        assert_eq!(
            provenance_lines(opened.settings.provenance.as_ref()),
            provenance_lines(stamped.provenance.as_ref())
        );
        // A scan stored without a stamp is not given one when it is opened.
        let old = store::load(&path, without).unwrap();
        assert!(old.settings.provenance.is_none());
        assert!(provenance_lines(old.settings.provenance.as_ref())[0].starts_with("No provenance"));
        for suffix in ["", "-wal", "-shm"] {
            let mut p = path.as_os_str().to_owned();
            p.push(suffix);
            let _ = std::fs::remove_file(std::path::PathBuf::from(p));
        }
    }

    #[test]
    fn stamping_is_cheap_enough_for_the_ui_thread() {
        let started = std::time::Instant::now();
        for _ in 0..5 {
            let _ = settings_for_scan(&scan::Settings::default());
        }
        let each = started.elapsed() / 5;
        eprintln!("provenance stamp: {each:?} each (debug build)");
        assert!(each < std::time::Duration::from_millis(500), "{each:?}");
    }
}
