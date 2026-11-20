use super::*;
/// The CVE rules for a rules file path from the settings, loaded like `--cves FILE` (built-in
/// rules plus the file). An empty path means the default rules. A file that cannot be read or
/// parsed is an error carrying the path and the reason; nothing is installed here.
pub(super) fn load_cve_rules(path: &str) -> Result<risk::CveDb, String> {
    let path = path.trim();
    risk::CveDb::load((!path.is_empty()).then(|| std::path::Path::new(path)))
}
impl Scanner {
    /// Loads the CVE rules file named in the settings and makes it the active rules for later
    /// scans and findings. On an error the previous rules stay active and the error is kept
    /// for the settings window.
    pub(super) fn apply_cves_file(&mut self) {
        match load_cve_rules(&self.saved.cves_file) {
            Ok(db) => {
                risk::set_cves(db);
                self.cves_error.clear();
                // Findings on screen are recomputed with the new rules.
                self.data_changed();
            }
            Err(e) => self.cves_error = e,
        }
    }
    pub(super) fn settings(&mut self, ctx: &egui::Context) {
        let mut apply_cves = false;
        let mut language = None;
        let mut dark = None;
        egui::Window::new(tr!("Scan settings")).vscroll(true)
            .open(&mut self.settings_open)
            .default_size(default_win_size())
            .default_pos(self.window_origin)
            .resizable(false)
            .show(ctx, |ui| {
                ui.add_enabled_ui(self.run.is_none(), |ui| {
                    let s = &mut self.saved.settings;
                    egui::Grid::new("settings_grid")
                        .num_columns(2)
                        .spacing([24.0, 10.0])
                        .show(ui, |ui| {
                            // The label is the accessible name of the field next to it.
                            labelled_row(ui, tr!("Concurrent hosts"), egui::DragValue::new(&mut s.workers).range(1..=4096));
                            labelled_row(ui, tr!("Ping probes"), egui::DragValue::new(&mut s.probes).range(1..=10));
                            labelled_row(
                                ui,
                                tr!("Ping timeout"),
                                egui::DragValue::new(&mut s.ping_timeout).range(100..=10000).suffix(" ms"),
                            );
                            labelled_row(
                                ui,
                                tr!("Port timeout"),
                                egui::DragValue::new(&mut s.port_timeout).range(100..=10000).suffix(" ms"),
                            );
                            labelled_row(
                                ui,
                                tr!("Minimum port timeout"),
                                egui::DragValue::new(&mut s.minimum_timeout).range(1..=s.port_timeout).suffix(" ms"),
                            );
                            labelled_row(
                                ui,
                                tr!("Probe spacing (Safe Mode)"),
                                egui::DragValue::new(&mut s.delay).range(0..=1000).suffix(" ms"),
                            );
                            labelled_row(ui, tr!("Port probes per host"), egui::DragValue::new(&mut s.port_parallel).range(1..=1024));
                            labelled_row(ui, tr!("Retries for silent ports"), egui::DragValue::new(&mut s.retries).range(0..=5));
                            labelled_row(
                                ui,
                                tr!("Rate cap (0 = none)"),
                                egui::DragValue::new(&mut s.max_rate).range(0..=1_000_000).suffix(" pps"),
                            );
                        });
                    ui.separator();
                    ui.checkbox(
                        &mut s.safe,
                        tr!("Safe Mode: max. 8 hosts, 100 ms probe spacing, no SYN, no ARP sweep, ICMP traceroute"),
                    );
                    ui.checkbox(
                        &mut s.arp,
                        tr!("ARP discovery even without a ping response (Windows LAN)"),
                    );
                    ui.add_enabled(
                        !s.safe,
                        egui::Checkbox::new(
                            &mut s.arp_sweep,
                            tr!("Fast ARP sweep through the capture interface (needs Npcap)"),
                        ),
                    )
                    .on_disabled_hover_text(tr!("Not in Safe Mode"));
                    ui.checkbox(
                        &mut s.ot,
                        tr!("Read industrial device identities (standard ports + BACnet UDP)"),
                    );
                    if s.ot {
                        if ui.button(tr!("Use industrial ports")).clicked() {
                            s.ports = "80,443,102,502,1883,1911,4840,9600,44818".into();
                            s.scan_nonresponders = true;
                        }
                        ui.horizontal(|ui| {
                            let unit = ui.label(tr!("Modbus unit"));
                            ui.add(egui::DragValue::new(&mut s.modbus_unit)).labelled_by(unit.id);
                            let rack = ui.label(tr!("S7 rack / slot"));
                            ui.add(egui::DragValue::new(&mut s.s7_rack).range(0..=7)).labelled_by(rack.id);
                            a11y::named(
                                ui.add(egui::DragValue::new(&mut s.s7_slot).range(0..=31)),
                                tr!("S7 slot"),
                            );
                        });
                    }
                    ui.add_enabled(
                        !s.safe,
                        egui::Checkbox::new(&mut s.syn, tr!("SYN via Npcap; fallback to TCP connect")),
                    );
                    ui.add_enabled(
                        !s.safe && s.syn,
                        egui::Checkbox::new(
                            &mut s.syn_adaptive,
                            tr!("Adaptive SYN timing (RTT-based timeouts, slows down on packet loss)"),
                        ),
                    );
                    ui.add_enabled(
                        !s.safe && s.services,
                        egui::Checkbox::new(
                            &mut s.jarm,
                            tr!("JARM TLS fingerprint (10 extra connections per TLS port; needs service detection)"),
                        ),
                    )
                    .on_disabled_hover_text(tr!("Needs service detection, and not in Safe Mode"));
                    ui.add_enabled(
                        !s.safe && s.services,
                        egui::Checkbox::new(
                            &mut s.favicon,
                            tr!("Favicon hash (one GET /favicon.ico per web port; not on industrial hosts)"),
                        ),
                    )
                    .on_disabled_hover_text(tr!("Needs service detection, and not in Safe Mode"));
                    if s.syn || s.arp_sweep {
                        ui.label(tr!("Configure interface, source IPv4 and MAC in Passive / DCP."));
                    }
                    ui.separator();
                    ui.checkbox(
                        &mut s.services,
                        tr!("Identify services on open TCP ports (banners, HTTP, TLS certificate/ciphers, SMB, RDP, databases)"),
                    );
                    ui.checkbox(&mut s.udp, tr!("Probe UDP services (DNS, DHCP, NTP, NetBIOS, SNMP public, SSDP, mDNS)"));
                    if s.udp {
                        ui.horizontal(|ui| {
                            let name = ui.label(tr!("UDP ports"));
                            ui.add(egui::TextEdit::singleline(&mut s.udp_ports).desired_width(190.0))
                                .labelled_by(name.id);
                        });
                    }
                    ui.horizontal(|ui| {
                        let label = ui.label(tr!("Script (.rhai file or folder)"));
                        ui.add(egui::TextEdit::singleline(&mut s.scripts).desired_width(220.0))
                            .labelled_by(label.id);
                    });
                    let cves_label = ui.label(tr!("CVE rules file (added to the built-in rules)"));
                    ui.horizontal(|ui| {
                        let edit = ui
                            .add(
                                egui::TextEdit::singleline(&mut self.saved.cves_file)
                                    .hint_text("cves.json")
                                    .desired_width(190.0),
                            )
                            .labelled_by(cves_label.id);
                        // Enter or leaving the field loads the file, so a path is not
                        // parsed on every keystroke.
                        if edit.lost_focus() {
                            apply_cves = true;
                        }
                        if ui.button(tr!("Browse…")).clicked()
                            && let Some(path) = rfd::FileDialog::new()
                                .add_filter("CVE rules", &["json"])
                                .pick_file()
                        {
                            self.saved.cves_file = path.display().to_string();
                            apply_cves = true;
                        }
                        if !self.saved.cves_file.is_empty() && ui.button(tr!("Clear")).clicked() {
                            self.saved.cves_file.clear();
                            apply_cves = true;
                        }
                    });
                    if !self.cves_error.is_empty() {
                        ui.scope(|ui| {
                            ui.set_max_width(360.0);
                            ui.colored_label(
                                egui::Color32::from_rgb(205, 70, 70),
                                tr!("{} (previous rules stay active)", self.cves_error),
                            );
                        });
                    }
                    ui.checkbox(&mut s.os_detect, tr!("Guess OS, manufacturer and device type"));
                    ui.checkbox(&mut s.trace, tr!("Record router path to each responding host (traceroute)"));
                    if s.trace {
                        ui.horizontal(|ui| {
                            let hops = ui.label(tr!("Max hops"));
                            ui.add(egui::DragValue::new(&mut s.trace_hops).range(1..=64))
                                .labelled_by(hops.id);
                            ui.label(tr!("Method"));
                            trace_method_combo(ui, s.safe, &mut s.trace_method);
                        });
                        if s.trace_method == TraceMethod::Tcp {
                            ui.horizontal(|ui| {
                                let port = ui.label(tr!("TCP port"));
                                ui.add_enabled(
                                    !s.safe,
                                    egui::DragValue::new(&mut s.trace_port).range(0..=65535),
                                )
                                .labelled_by(port.id);
                                ui.label(tr!("0 = first open port; OT and printer ports are never used"));
                            });
                            if s.trace_port != 0
                                && !crate::trace::trace_port_allowed(s.trace_port)
                            {
                                ui.colored_label(
                                    egui::Color32::from_rgb(205, 70, 70),
                                    tr!("OT/printer port: ICMP will be used instead"),
                                );
                            }
                        }
                    }
                    ui.separator();
                    ui.checkbox(&mut s.tcp_only, tr!("TCP only (skip ICMP ping)"));
                    ui.checkbox(
                        &mut s.scan_nonresponders,
                        tr!("Check ports even when ping gets no reply"),
                    );
                    ui.checkbox(&mut s.adaptive, tr!("Adapt port timeout to measured ping"));
                    ui.checkbox(
                        &mut s.backoff,
                        tr!("Back off when a device resets connections (lower limits for OT/printers)"),
                    );
                    ui.checkbox(
                        &mut s.skip_edges,
                        tr!("Skip network/broadcast addresses (CIDR: true edges; ranges: .0 and .255)"),
                    );
                    ui.checkbox(&mut s.dns, tr!("Resolve hostnames (system DNS)"));
                    ui.checkbox(&mut s.mac, tr!("Look up MAC addresses (local IPv4 network)"));
                    ui.checkbox(
                        &mut self.saved.randomize,
                        tr!("Probe the addresses in random order"),
                    )
                    .on_hover_text(tr!(
                        "Only the order changes, not which addresses or probes. Spreads the load over the network instead of walking it address by address."
                    ));
                    ui.separator();
                    ui.checkbox(
                        &mut self.saved.check_updates,
                        tr!("Check for updates on start (one request to GitHub; only tells you, never downloads)"),
                    )
                    .on_hover_text(
                        tr!("Sends one HTTPS request to api.github.com with the user agent network-scope/<version> and no other data. Off by default."),
                    );
                    ui.separator();
                    ui.label(tr!("A ping timeout does not prove a device is offline."));
                    ui.label(tr!("Read-only queries can still affect fragile devices. Passive listening sends none."));
                    ui.label(tr!("Pause lets active hosts finish. Stop cancels async work."));
                    if ui
                        .button(tr!("Restore defaults"))
                        .on_hover_text(tr!("Keeps interface, source addresses, script and probe file"))
                        .clicked()
                    {
                        *s = standard_settings(s);
                        self.saved.preset.clear();
                    }
                });
                if self.run.is_some() {
                    ui.label(tr!("Settings can be changed after this scan finishes."));
                }
                // Appearance and language apply at once, also while a scan runs.
                ui.separator();
                let heading = ui.heading(tr!("Appearance and language"));
                if std::mem::take(&mut self.scroll_to_appearance) {
                    heading.scroll_to_me(Some(egui::Align::TOP));
                }
                egui::Grid::new("appearance_grid")
                    .num_columns(2)
                    .spacing([24.0, 10.0])
                    .show(ui, |ui| {
                        let language_label = ui.label(tr!("Language"));
                        let shown = match self.saved.language.as_str() {
                            "" | "auto" => tr!("Automatic (system language)").to_string(),
                            code => i18n::Lang::from_locale(code).map_or(code.to_string(), |l| l.name().to_string()),
                        };
                        let language_box = egui::ComboBox::from_id_salt("language")
                            .selected_text(shown)
                            .show_ui(ui, |ui| {
                                if ui
                                    .selectable_label(
                                        matches!(self.saved.language.as_str(), "" | "auto"),
                                        tr!("Automatic (system language)"),
                                    )
                                    .clicked()
                                {
                                    language = Some("auto");
                                }
                                for l in i18n::LANGUAGES {
                                    if ui
                                        .selectable_label(self.saved.language == l.code(), l.name())
                                        .clicked()
                                    {
                                        language = Some(l.code());
                                    }
                                }
                            });
                        language_box.response.labelled_by(language_label.id);
                        ui.end_row();
                        ui.label(tr!("Theme"));
                        ui.horizontal(|ui| {
                            if ui.selectable_label(!self.saved.dark, tr!("Light")).clicked() {
                                dark = Some(false);
                            }
                            if ui.selectable_label(self.saved.dark, tr!("Dark")).clicked() {
                                dark = Some(true);
                            }
                        });
                        ui.end_row();
                        let scale_label = ui.label(tr!("Interface scale"));
                        let mut zoom = if self.saved.zoom > 0.0 { self.saved.zoom } else { 1.0 };
                        if ui
                            .add(egui::Slider::new(&mut zoom, ZOOM_RANGE).fixed_decimals(2).step_by(0.05))
                            .labelled_by(scale_label.id)
                            .on_hover_text(tr!("On top of the system's display scaling (also Ctrl and + or -)."))
                            .changed()
                        {
                            self.saved.zoom = zoom;
                        }
                        ui.end_row();
                    });
                super::scheduler::schedule_section(
                    ui,
                    &mut self.saved,
                    &self.targets,
                    &self.schedule_note,
                    &mut self.schedule_error,
                );
            });
        if let Some(code) = language {
            self.set_language(code);
        }
        if let Some(dark) = dark {
            self.set_dark(ctx, dark);
        }
        if apply_cves {
            self.apply_cves_file();
        }
        egui::Window::new(tr!("About Network Scope"))
            .open(&mut self.about_open)
            .default_size(default_win_size())
            .default_pos(self.window_origin)
            .resizable(false)
            .show(ctx, |ui| {
                ui.heading("Network Scope");
                ui.label(tr!(
                    "A native Rust network scanner · {}",
                    env!("CARGO_PKG_VERSION")
                ));
                ui.label(tr!(
                    "Built with egui/eframe, egui_extras, image, serde, rfd and dns-lookup."
                ));
                ui.label(tr!(
                    "Address inputs: IPv4, IPv6, IPv4 ranges, CIDR, or an imported list."
                ));
                ui.label(tr!(
                    "Use the Scan menu to export the currently visible results."
                ));
                ui.label(tr!("Press Ctrl+K for the command palette."));
                ui.horizontal_wrapped(|ui| {
                    convenience::link_to(
                        ui,
                        tr!("Project page"),
                        "https://github.com/Sparkz400/network-scope",
                    );
                    convenience::link_to(
                        ui,
                        tr!("Documentation"),
                        "https://sparkz400.github.io/network-scope/",
                    );
                    convenience::link_to(
                        ui,
                        tr!("Releases"),
                        "https://github.com/Sparkz400/network-scope/releases",
                    );
                });
            });
    }
}
use crate::trace::TraceMethod;
/// A settings grid row: the label and the field, the label naming the field for screen readers.
fn labelled_row(ui: &mut egui::Ui, label: &str, field: impl egui::Widget) {
    let name = ui.label(label);
    ui.add(field).labelled_by(name.id);
    ui.end_row();
}
/// Traceroute method; TCP and UDP transmit beyond ICMP and are not offered in Safe Mode.
fn trace_method_combo(ui: &mut egui::Ui, safe: bool, method: &mut TraceMethod) {
    let name = |m: TraceMethod| match m {
        TraceMethod::Icmp => "ICMP",
        TraceMethod::Tcp => tr!("TCP SYN (needs Npcap)"),
        TraceMethod::Udp => tr!("UDP (needs administrator)"),
    };
    let shown = if safe && *method != TraceMethod::Icmp {
        tr!("ICMP in Safe Mode").to_string()
    } else {
        name(*method).to_string()
    };
    egui::ComboBox::from_id_salt("trace_method")
        .selected_text(shown)
        .show_ui(ui, |ui| {
            for m in [TraceMethod::Icmp, TraceMethod::Tcp, TraceMethod::Udp] {
                ui.add_enabled_ui(!safe || m == TraceMethod::Icmp, |ui| {
                    ui.selectable_value(method, m, name(m));
                });
            }
        });
}
