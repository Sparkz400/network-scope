use super::*;
impl Scanner {
    pub(super) fn controls(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("controls").show(ui, |ui| {
            self.menu_bar(ui);
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                let label = ui.label(tr!("Addresses"));
                ui.add_enabled(
                    self.run.is_none(),
                    egui::TextEdit::singleline(&mut self.targets)
                        .desired_width((ui.available_width() - 200.0).max(180.0))
                        .hint_text("192.168.1.1-254 or 10.0.0.0/24"),
                )
                .labelled_by(label.id);
                // The menu bar's behaviour: removing a favorite keeps the menu open.
                let (favorites, _) = egui::containers::menu::MenuButton::new("★")
                    .config(menu_config())
                    .ui(ui, |ui| self.favorites_menu(ui));
                a11y::named(favorites, tr!("Favorite addresses"))
                    .on_hover_text(tr!("Favorite addresses"));
                if let Some(run) = &self.run {
                    let stopping = run.cancel.load(Ordering::Relaxed);
                    let paused = run.pause.load(Ordering::Relaxed);
                    if ui
                        .add_enabled(
                            !stopping,
                            egui::Button::new(if paused { tr!("Resume") } else { tr!("Pause") }),
                        )
                        .clicked()
                    {
                        run.pause.store(!paused, Ordering::Relaxed);
                    }
                    if ui
                        .add_enabled(!stopping, egui::Button::new(tr!("Stop")))
                        .clicked()
                    {
                        run.cancel.store(true, Ordering::Relaxed);
                    }
                } else if ui
                    .add(
                        egui::Button::new(RichText::new(tr!("▶ Start")).color(Color32::WHITE))
                            .fill(Color32::from_rgb(33, 105, 180)),
                    )
                    .on_hover_text("F5")
                    .clicked()
                {
                    // The same command as F5 and Scan → Start scan (it shows the Hosts page).
                    let ctx = ui.ctx().clone();
                    self.run_command(&ctx, palette::Cmd::StartScan);
                }
            });
            ui.horizontal(|ui| {
                let label = ui.label(tr!("TCP ports"));
                ui.add_enabled(
                    self.run.is_none(),
                    egui::TextEdit::singleline(&mut self.saved.settings.ports).desired_width(175.0),
                )
                .labelled_by(label.id);
                ui.add_enabled_ui(self.run.is_none(), |ui| {
                    ui.label(tr!("Preset"));
                    self.preset_picker(ui);
                });
            });
            if !self.error.is_empty() {
                ui.colored_label(
                    home::severity_color(risk::Severity::Critical, ui.visuals().dark_mode),
                    &self.error,
                );
            }
            ui.add_space(3.0);
        });
    }
    /// The filters and the search box of the hosts table, above the table.
    pub(super) fn hosts_filters(&mut self, ui: &mut egui::Ui) {
        // Next to the docked details in a small window the row would not fit: then it wraps,
        // with the search box at its end instead of on the right.
        let narrow = ui.available_width() < 640.0;
        let mut row = |ui: &mut egui::Ui| {
            ui.selectable_value(&mut self.filter, Filter::Responding, tr!("Responding"));
            ui.selectable_value(&mut self.filter, Filter::All, tr!("All hosts"));
            ui.selectable_value(&mut self.filter, Filter::Open, tr!("Open ports"));
            ui.selectable_value(&mut self.filter, Filter::Starred, tr!("Starred ★"));
            ui.separator();
            // Ticking a column keeps the menu open, like the menu bar.
            egui::containers::menu::MenuButton::new(tr!("Columns"))
                .config(menu_config())
                .ui(ui, |ui| {
                    let c = &mut self.saved.host_columns;
                    ui.checkbox(&mut c.vendor, tr!("Manufacturer"));
                    ui.checkbox(&mut c.kind, tr!("Type"));
                    ui.checkbox(&mut c.os, tr!("OS guess"));
                    ui.checkbox(&mut c.risk, tr!("Risk"))
                        .on_hover_text(tr!("The worst finding of the host. Large scans: open the Findings page once to fill it."));
                });
            let mut search = |ui: &mut egui::Ui| {
                // The hint text is only the "placeholder" for a screen reader: name the box.
                let response = a11y::named(
                    ui.add(
                        egui::TextEdit::singleline(&mut self.search)
                            .hint_text(tr!("Search results…"))
                            .desired_width(190.0),
                    ),
                    tr!("Search results…"),
                );
                if std::mem::take(&mut self.focus_search) {
                    response.request_focus();
                }
            };
            if narrow {
                search(ui);
            } else {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), search);
            }
        };
        if narrow {
            ui.horizontal_wrapped(|ui| row(ui));
        } else {
            ui.horizontal(|ui| row(ui));
        }
        ui.add_space(2.0);
    }
}
/// Menu behaviour shared by the menu bar and the favorite-addresses menu.
pub(super) fn menu_config() -> egui::containers::menu::MenuConfig {
    egui::containers::menu::MenuConfig::new()
        .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
}
