use super::*;
impl Scanner {
    pub(super) fn controls(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("controls").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("Scan", |ui| {
                    if ui
                        .add_enabled(self.run.is_none(), egui::Button::new("Start scan"))
                        .clicked()
                    {
                        self.start();
                        ui.close_menu();
                    }
                    if ui
                        .add_enabled(
                            self.run.is_none() && !self.busy.importing,
                            egui::Button::new("Import address list…"),
                        )
                        .clicked()
                    {
                        ui.close_menu();
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("Address list", &["txt"])
                            .pick_file()
                        {
                            // Read in the background; large lists must not freeze the window.
                            self.submit(Job::ReadFile(path));
                        }
                    }
                    ui.separator();
                    if ui
                        .add_enabled(
                            !self.results.is_empty(),
                            egui::Button::new("Export visible rows as CSV…"),
                        )
                        .clicked()
                    {
                        self.export("csv");
                        ui.close_menu();
                    }
                    if ui
                        .add_enabled(
                            !self.results.is_empty(),
                            egui::Button::new("Export visible rows as JSON…"),
                        )
                        .clicked()
                    {
                        self.export("json");
                        ui.close_menu();
                    }
                    if ui
                        .add_enabled(
                            !self.results.is_empty() || !self.observations.is_empty(),
                            egui::Button::new("Export HTML report…"),
                        )
                        .clicked()
                    {
                        self.export("html");
                        ui.close_menu();
                    }
                    if ui
                        .add_enabled(
                            !self.live() && !self.busy.loading,
                            egui::Button::new("Clear results and captures"),
                        )
                        .on_hover_text(
                            "Removes active scan results and passive observations from the window. Saved inventory is kept.",
                        )
                        .clicked()
                    {
                        self.clear();
                        ui.close_menu();
                    }
                });
                ui.menu_button("Favorites", |ui| {
                    if ui.button("Save current addresses").clicked() {
                        if !self.saved.favorites.contains(&self.targets) {
                            self.saved.favorites.push(self.targets.clone());
                        }
                        ui.close_menu();
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
                                ui.close_menu();
                            }
                            if ui.small_button("Remove").clicked() {
                                remove = Some(i);
                            }
                        });
                    }
                    if let Some(i) = remove {
                        self.saved.favorites.remove(i);
                    }
                });
                if ui.button("Settings").clicked() {
                    self.settings_open = true;
                }
                if ui.button("Inventory").clicked() {
                    self.history_open = true;
                    self.refresh_history();
                }
                if ui.button("Topology").clicked() {
                    self.topology_open = true;
                }
                if ui.button("Findings").clicked() {
                    self.findings_open = true;
                }
                if ui.button("Devices").clicked() {
                    self.devices_open = true;
                }
                if ui.button("Passive / DCP").clicked() {
                    self.capture_open = true;
                }
                if ui.button("About").clicked() {
                    self.about_open = true;
                }
            });
            ui.separator();
            ui.horizontal(|ui| {
                ui.heading("Network Scope");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new("IP & PORT SCANNER")
                            .small()
                            .color(Color32::from_gray(105)),
                    );
                });
            });
            ui.horizontal(|ui| {
                ui.label("Addresses");
                ui.add_enabled(
                    self.run.is_none(),
                    egui::TextEdit::singleline(&mut self.targets)
                        .desired_width((ui.available_width() - 165.0).max(180.0))
                        .hint_text("192.168.1.1-254 or 10.0.0.0/24"),
                );
                if let Some(run) = &self.run {
                    let stopping = run.cancel.load(Ordering::Relaxed);
                    let paused = run.pause.load(Ordering::Relaxed);
                    if ui
                        .add_enabled(
                            !stopping,
                            egui::Button::new(if paused { "Resume" } else { "Pause" }),
                        )
                        .clicked()
                    {
                        run.pause.store(!paused, Ordering::Relaxed);
                    }
                    if ui
                        .add_enabled(!stopping, egui::Button::new("Stop"))
                        .clicked()
                    {
                        run.cancel.store(true, Ordering::Relaxed);
                    }
                } else if ui
                    .add(
                        egui::Button::new(RichText::new("▶ Start").color(Color32::WHITE))
                            .fill(Color32::from_rgb(33, 105, 180)),
                    )
                    .clicked()
                {
                    self.start();
                }
            });
            ui.horizontal(|ui| {
                ui.label("TCP ports");
                ui.add_enabled(
                    self.run.is_none(),
                    egui::TextEdit::singleline(&mut self.saved.settings.ports).desired_width(175.0),
                );
                ui.add_enabled_ui(self.run.is_none(), |ui| {
                    if ui
                        .button("Standard")
                        .on_hover_text(
                            "Original scan defaults (keeps interface, source addresses and script)",
                        )
                        .clicked()
                    {
                        self.saved.settings = standard_settings(&self.saved.settings);
                    }
                    if ui
                        .button("Fast")
                        .on_hover_text(
                            "TCP discovery, up to 1024 concurrent hosts, 800 ms timeouts",
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
                    }
                    if ui
                        .button("Thorough")
                        .on_hover_text("Three probes and port checks even when ping gets no reply")
                        .clicked()
                    {
                        self.saved.settings.probes = 3;
                        self.saved.settings.ping_timeout = 2000;
                        self.saved.settings.port_timeout = 2000;
                        self.saved.settings.scan_nonresponders = true;
                    }
                });
            });
            ui.add_space(3.0);
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.filter, Filter::Responding, "Responding");
                ui.selectable_value(&mut self.filter, Filter::All, "All hosts");
                ui.selectable_value(&mut self.filter, Filter::Open, "Open ports");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.search)
                            .hint_text("Search results…")
                            .desired_width(190.0),
                    );
                });
            });
            if !self.error.is_empty() {
                ui.colored_label(Color32::from_rgb(180, 40, 40), &self.error);
            }
            ui.add_space(3.0);
        });
    }
}
