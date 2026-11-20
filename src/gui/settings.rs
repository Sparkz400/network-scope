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
        egui::Window::new("Scan settings").vscroll(true)
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
                            ui.label("Concurrent hosts");
                            ui.add(egui::DragValue::new(&mut s.workers).range(1..=4096));
                            ui.end_row();
                            ui.label("Ping probes");
                            ui.add(egui::DragValue::new(&mut s.probes).range(1..=10));
                            ui.end_row();
                            ui.label("Ping timeout");
                            ui.add(
                                egui::DragValue::new(&mut s.ping_timeout)
                                    .range(100..=10000)
                                    .suffix(" ms"),
                            );
                            ui.end_row();
                            ui.label("Port timeout");
                            ui.add(
                                egui::DragValue::new(&mut s.port_timeout)
                                    .range(100..=10000)
                                    .suffix(" ms"),
                            );
                            ui.end_row();
                            ui.label("Minimum port timeout");
                            ui.add(
                                egui::DragValue::new(&mut s.minimum_timeout)
                                    .range(1..=s.port_timeout)
                                    .suffix(" ms"),
                            );
                            ui.end_row();
                            ui.label("Probe spacing (Safe Mode)");
                            ui.add(
                                egui::DragValue::new(&mut s.delay)
                                    .range(0..=1000)
                                    .suffix(" ms"),
                            );
                            ui.end_row();
                            ui.label("Port probes per host");
                            ui.add(egui::DragValue::new(&mut s.port_parallel).range(1..=1024));
                            ui.end_row();
                            ui.label("Retries for silent ports");
                            ui.add(egui::DragValue::new(&mut s.retries).range(0..=5));
                            ui.end_row();
                            ui.label("Rate cap (0 = none)");
                            ui.add(
                                egui::DragValue::new(&mut s.max_rate)
                                    .range(0..=1_000_000)
                                    .suffix(" pps"),
                            );
                            ui.end_row();
                        });
                    ui.separator();
                    ui.checkbox(
                        &mut s.safe,
                        "Safe Mode: max. 8 hosts, 100 ms probe spacing, no SYN, no ARP sweep, ICMP traceroute",
                    );
                    ui.checkbox(
                        &mut s.arp,
                        "ARP discovery even without a ping response (Windows LAN)",
                    );
                    ui.add_enabled(
                        !s.safe,
                        egui::Checkbox::new(
                            &mut s.arp_sweep,
                            "Fast ARP sweep through the capture interface (needs Npcap)",
                        ),
                    )
                    .on_disabled_hover_text("Not in Safe Mode");
                    ui.checkbox(
                        &mut s.ot,
                        "Read industrial device identities (standard ports + BACnet UDP)",
                    );
                    if s.ot {
                        if ui.button("Use industrial ports").clicked() {
                            s.ports = "80,443,102,502,4840,44818".into();
                            s.scan_nonresponders = true;
                        }
                        ui.horizontal(|ui| {
                            ui.label("Modbus unit");
                            ui.add(egui::DragValue::new(&mut s.modbus_unit));
                            ui.label("S7 rack / slot");
                            ui.add(egui::DragValue::new(&mut s.s7_rack).range(0..=7));
                            ui.add(egui::DragValue::new(&mut s.s7_slot).range(0..=31));
                        });
                    }
                    ui.add_enabled(
                        !s.safe,
                        egui::Checkbox::new(&mut s.syn, "SYN via Npcap; fallback to TCP connect"),
                    );
                    ui.add_enabled(
                        !s.safe && s.syn,
                        egui::Checkbox::new(
                            &mut s.syn_adaptive,
                            "Adaptive SYN timing (RTT-based timeouts, slows down on packet loss)",
                        ),
                    );
                    ui.add_enabled(
                        !s.safe && s.services,
                        egui::Checkbox::new(
                            &mut s.jarm,
                            "JARM TLS fingerprint (10 extra connections per TLS port; needs service detection)",
                        ),
                    )
                    .on_disabled_hover_text("Needs service detection, and not in Safe Mode");
                    if s.syn || s.arp_sweep {
                        ui.label("Configure interface, source IPv4 and MAC in Passive / DCP.");
                    }
                    ui.separator();
                    ui.checkbox(
                        &mut s.services,
                        "Identify services on open TCP ports (banners, HTTP, TLS certificate/ciphers, SMB, RDP, databases)",
                    );
                    ui.checkbox(&mut s.udp, "Probe UDP services (DNS, DHCP, NTP, NetBIOS, SNMP public, SSDP, mDNS)");
                    if s.udp {
                        ui.horizontal(|ui| {
                            ui.label("UDP ports");
                            ui.add(egui::TextEdit::singleline(&mut s.udp_ports).desired_width(190.0));
                        });
                    }
                    ui.horizontal(|ui| {
                        ui.label("Script (.rhai file or folder)");
                        ui.add(egui::TextEdit::singleline(&mut s.scripts).desired_width(220.0));
                    });
                    ui.label("CVE rules file (added to the built-in rules)");
                    ui.horizontal(|ui| {
                        let edit = ui.add(
                            egui::TextEdit::singleline(&mut self.saved.cves_file)
                                .hint_text("cves.json")
                                .desired_width(190.0),
                        );
                        // Enter or leaving the field loads the file, so a path is not
                        // parsed on every keystroke.
                        if edit.lost_focus() {
                            apply_cves = true;
                        }
                        if ui.button("Browse…").clicked()
                            && let Some(path) = rfd::FileDialog::new()
                                .add_filter("CVE rules", &["json"])
                                .pick_file()
                        {
                            self.saved.cves_file = path.display().to_string();
                            apply_cves = true;
                        }
                        if !self.saved.cves_file.is_empty() && ui.button("Clear").clicked() {
                            self.saved.cves_file.clear();
                            apply_cves = true;
                        }
                    });
                    if !self.cves_error.is_empty() {
                        ui.scope(|ui| {
                            ui.set_max_width(360.0);
                            ui.colored_label(
                                egui::Color32::DARK_RED,
                                format!("{} (previous rules stay active)", self.cves_error),
                            );
                        });
                    }
                    ui.checkbox(&mut s.os_detect, "Guess OS, manufacturer and device type");
                    ui.checkbox(&mut s.trace, "Record router path to each responding host (traceroute)");
                    if s.trace {
                        ui.horizontal(|ui| {
                            ui.label("Max hops");
                            ui.add(egui::DragValue::new(&mut s.trace_hops).range(1..=64));
                            ui.label("Method");
                            trace_method_combo(ui, s.safe, &mut s.trace_method);
                        });
                        if s.trace_method == TraceMethod::Tcp {
                            ui.horizontal(|ui| {
                                ui.label("TCP port");
                                ui.add_enabled(
                                    !s.safe,
                                    egui::DragValue::new(&mut s.trace_port).range(0..=65535),
                                );
                                ui.label("0 = first open port; OT and printer ports are never used");
                            });
                            if s.trace_port != 0
                                && !crate::trace::trace_port_allowed(s.trace_port)
                            {
                                ui.colored_label(
                                    egui::Color32::DARK_RED,
                                    "OT/printer port: ICMP will be used instead",
                                );
                            }
                        }
                    }
                    ui.separator();
                    ui.checkbox(&mut s.tcp_only, "TCP only (skip ICMP ping)");
                    ui.checkbox(
                        &mut s.scan_nonresponders,
                        "Check ports even when ping gets no reply",
                    );
                    ui.checkbox(&mut s.adaptive, "Adapt port timeout to measured ping");
                    ui.checkbox(
                        &mut s.skip_edges,
                        "Skip network/broadcast addresses (CIDR: true edges; ranges: .0 and .255)",
                    );
                    ui.checkbox(&mut s.dns, "Resolve hostnames (system DNS)");
                    ui.checkbox(&mut s.mac, "Look up MAC addresses (local IPv4 network)");
                    ui.separator();
                    ui.label("A ping timeout does not prove a device is offline.");
                    ui.label("Read-only queries can still affect fragile devices. Passive listening sends none.");
                    ui.label("Pause lets active hosts finish. Stop cancels async work.");
                    if ui
                        .button("Restore defaults")
                        .on_hover_text("Keeps interface, source addresses, script and probe file")
                        .clicked()
                    {
                        *s = standard_settings(s);
                    }
                });
                if self.run.is_some() {
                    ui.label("Settings can be changed after this scan finishes.");
                }
                super::scheduler::schedule_section(
                    ui,
                    &mut self.saved,
                    &self.targets,
                    &self.schedule_note,
                    &mut self.schedule_error,
                );
            });
        if apply_cves {
            self.apply_cves_file();
        }
        egui::Window::new("About Network Scope")
            .open(&mut self.about_open)
            .default_size(default_win_size())
            .default_pos(self.window_origin)
            .resizable(false)
            .show(ctx, |ui| {
                ui.heading("Network Scope");
                ui.label(format!(
                    "A native Rust network scanner · {}",
                    env!("CARGO_PKG_VERSION")
                ));
                ui.label("Built with egui/eframe, egui_extras, image, serde, rfd and dns-lookup.");
                ui.label("Address inputs: IPv4, IPv6, IPv4 ranges, CIDR, or an imported list.");
                ui.label("Use the Scan menu to export the currently visible results.");
            });
    }
}
use crate::trace::TraceMethod;
/// Traceroute method; TCP and UDP transmit beyond ICMP and are not offered in Safe Mode.
fn trace_method_combo(ui: &mut egui::Ui, safe: bool, method: &mut TraceMethod) {
    let name = |m: TraceMethod| match m {
        TraceMethod::Icmp => "ICMP",
        TraceMethod::Tcp => "TCP SYN (needs Npcap)",
        TraceMethod::Udp => "UDP (needs administrator)",
    };
    let shown = if safe && *method != TraceMethod::Icmp {
        "ICMP in Safe Mode".to_string()
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
