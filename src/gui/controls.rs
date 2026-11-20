use super::*;
impl Scanner {
    pub(super) fn controls(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("controls").show(ui, |ui| {
            // Menus close through `ui.close()` or an outside click (as before 0.32), so e.g.
            // removing a favorite keeps the menu open.
            egui::MenuBar::new()
                .config(menu_config())
                .ui(ui, |ui| {
                ui.menu_button(tr!("Scan"), |ui| {
                    if ui
                        .add_enabled(self.run.is_none(), egui::Button::new(tr!("Scan my network")))
                        .on_hover_text(tr!("Finds your local networks and scans them in Safe Mode."))
                        .clicked()
                    {
                        self.scan_my_network();
                        ui.close();
                    }
                    if ui
                        .add_enabled(self.run.is_none(), egui::Button::new(tr!("Start scan")))
                        .clicked()
                    {
                        self.start();
                        ui.close();
                    }
                    if ui
                        .add_enabled(
                            self.run.is_none() && !self.busy.importing,
                            egui::Button::new(tr!("Import address list…")),
                        )
                        .clicked()
                    {
                        ui.close();
                        self.import_address_list();
                    }
                    ui.separator();
                    if ui
                        .add_enabled(
                            !self.results.is_empty(),
                            egui::Button::new(tr!("Export visible rows as CSV…")),
                        )
                        .clicked()
                    {
                        self.export("csv");
                        ui.close();
                    }
                    if ui
                        .add_enabled(
                            !self.results.is_empty(),
                            egui::Button::new(tr!("Export visible rows as JSON…")),
                        )
                        .clicked()
                    {
                        self.export("json");
                        ui.close();
                    }
                    if ui
                        .add_enabled(
                            !self.results.is_empty() || !self.observations.is_empty(),
                            egui::Button::new(tr!("Export HTML report…")),
                        )
                        .clicked()
                    {
                        self.export("html");
                        ui.close();
                    }
                    if ui
                        .add_enabled(
                            !self.results.is_empty() || !self.observations.is_empty(),
                            egui::Button::new(tr!("Export Markdown summary…")),
                        )
                        .clicked()
                    {
                        self.export("md");
                        ui.close();
                    }
                    if ui
                        .add_enabled(
                            !self.live() && !self.busy.loading,
                            egui::Button::new(tr!("Clear results and captures")),
                        )
                        .on_hover_text(
                            tr!("Removes active scan results and passive observations from the window. Saved inventory is kept."),
                        )
                        .clicked()
                    {
                        self.clear();
                        ui.close();
                    }
                });
                ui.menu_button(tr!("Favorites"), |ui| {
                    if ui.button(tr!("Save current addresses")).clicked() {
                        if !self.saved.favorites.contains(&self.targets) {
                            self.saved.favorites.push(self.targets.clone());
                        }
                        ui.close();
                    }
                    ui.separator();
                    let mut remove = None;
                    for (i, target) in self.saved.favorites.iter().enumerate() {
                        ui.horizontal(|ui| {
                            if ui
                                .add_enabled(self.run.is_none(), egui::Button::new(target))
                                .clicked()
                            {
                                self.targets = target.clone();
                                ui.close();
                            }
                            if ui.small_button(tr!("Remove")).clicked() {
                                remove = Some(i);
                            }
                        });
                    }
                    if let Some(i) = remove {
                        self.saved.favorites.remove(i);
                    }
                    ui.separator();
                    if ui
                        .button(tr!("Show starred devices"))
                        .on_hover_text(tr!("Right click a host and choose Add to favorites to star it."))
                        .clicked()
                    {
                        self.view = MainView::Hosts;
                        self.filter = Filter::Starred;
                        ui.close();
                    }
                });
                if ui.button(tr!("Settings")).clicked() {
                    self.settings_open = true;
                }
                if ui.button(tr!("Inventory")).clicked() {
                    self.history_open = true;
                    self.refresh_history();
                }
                if ui.button(tr!("Network map")).clicked() {
                    self.topology_open = true;
                }
                if ui.button(tr!("Findings")).clicked() {
                    self.findings_open = true;
                }
                if ui.button(tr!("Devices")).clicked() {
                    self.devices_open = true;
                }
                if ui.button(tr!("Passive / DCP")).clicked() {
                    self.capture_open = true;
                }
                if ui
                    .button(tr!("Commands (Ctrl+K)"))
                    .on_hover_text(tr!("Search actions and all saved scans: an address, MAC, name, vendor or finding id."))
                    .clicked()
                {
                    self.open_palette();
                }
                if ui.button(tr!("About")).clicked() {
                    self.about_open = true;
                }
            });
            ui.separator();
            ui.horizontal(|ui| {
                ui.heading("Network Scope");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new(tr!("IP & PORT SCANNER"))
                            .small()
                            .color(ui.visuals().weak_text_color()),
                    );
                });
            });
            ui.horizontal(|ui| {
                let label = ui.label(tr!("Addresses"));
                ui.add_enabled(
                    self.run.is_none(),
                    egui::TextEdit::singleline(&mut self.targets)
                        .desired_width((ui.available_width() - 165.0).max(180.0))
                        .hint_text("192.168.1.1-254 or 10.0.0.0/24"),
                )
                .labelled_by(label.id);
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
                    .clicked()
                {
                    self.start();
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
                    if ui
                        .button(tr!("Standard"))
                        .on_hover_text(
                            tr!("Original scan defaults (keeps interface, source addresses and script)"),
                        )
                        .clicked()
                    {
                        self.saved.settings = standard_settings(&self.saved.settings);
                        self.saved.preset.clear();
                    }
                    if ui
                        .button(tr!("Fast"))
                        .on_hover_text(
                            tr!("TCP discovery, up to 1024 concurrent hosts, 800 ms timeouts"),
                        )
                        .clicked()
                    {
                        self.saved.settings.safe = false;
                        self.saved.settings.workers = 1024;
                        self.saved.settings.tcp_only = true;
                        self.saved.settings.probes = 1;
                        self.saved.settings.ping_timeout = 800;
                        self.saved.settings.port_timeout = 800;
                        self.saved.settings.delay = 0;
                        self.saved.preset.clear();
                    }
                    if ui
                        .button(tr!("Thorough"))
                        .on_hover_text(tr!("Three probes and port checks even when ping gets no reply"))
                        .clicked()
                    {
                        self.saved.settings.probes = 3;
                        self.saved.settings.ping_timeout = 2000;
                        self.saved.settings.port_timeout = 2000;
                        self.saved.settings.scan_nonresponders = true;
                        self.saved.preset.clear();
                    }
                });
            });
            ui.add_space(3.0);
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.view, MainView::Home, tr!("Overview"))
                    .on_hover_text(tr!("What changed since the last scan, the risk score and what to fix first"));
                ui.selectable_value(&mut self.view, MainView::Hosts, tr!("Hosts"));
                ui.separator();
                ui.add_enabled_ui(self.view == MainView::Hosts, |ui| {
                    ui.selectable_value(&mut self.filter, Filter::Responding, tr!("Responding"));
                    ui.selectable_value(&mut self.filter, Filter::All, tr!("All hosts"));
                    ui.selectable_value(&mut self.filter, Filter::Open, tr!("Open ports"));
                    ui.selectable_value(&mut self.filter, Filter::Starred, tr!("Starred ★"));
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // The hint text is only the "placeholder" for a screen reader: name the box.
                    a11y::named(
                        ui.add(
                            egui::TextEdit::singleline(&mut self.search)
                                .hint_text(tr!("Search results…"))
                                .desired_width(190.0),
                        ),
                        tr!("Search results…"),
                    );
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
}
/// Menu behaviour shared by the menu bar and the details window.
pub(super) fn menu_config() -> egui::containers::menu::MenuConfig {
    egui::containers::menu::MenuConfig::new()
        .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
}
