use super::*;
impl Scanner {
    pub(super) fn settings(&mut self, ctx: &egui::Context) {
        egui::Window::new("Scan settings").vscroll(true)
            .open(&mut self.settings_open)
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
                        "Safe Mode: max. 8 hosts, 100 ms probe spacing, no SYN",
                    );
                    ui.checkbox(
                        &mut s.arp,
                        "ARP discovery even without a ping response (Windows LAN)",
                    );
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
                    if s.syn {
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
                    ui.checkbox(&mut s.os_detect, "Guess OS, manufacturer and device type");
                    ui.checkbox(&mut s.trace, "Record router path to each responding host (traceroute)");
                    if s.trace {
                        ui.horizontal(|ui| {
                            ui.label("Max hops");
                            ui.add(egui::DragValue::new(&mut s.trace_hops).range(1..=64));
                        });
                    }
                    ui.separator();
                    ui.checkbox(&mut s.tcp_only, "TCP only (skip ICMP ping)");
                    ui.checkbox(
                        &mut s.scan_nonresponders,
                        "Check ports even when ping gets no reply",
                    );
                    ui.checkbox(&mut s.adaptive, "Adapt port timeout to measured ping");
                    ui.checkbox(&mut s.skip_edges, "Skip .0 and .255 in ranges and subnets");
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
            });
        egui::Window::new("About Network Scope")
            .open(&mut self.about_open)
            .resizable(false)
            .show(ctx, |ui| {
                ui.heading("Network Scope");
                ui.label("A native Rust network scanner · 0.1.0");
                ui.label("Built with egui/eframe, egui_extras, image, serde, rfd and dns-lookup.");
                ui.label("Address inputs: IPv4, IPv6, IPv4 ranges, CIDR, or an imported list.");
                ui.label("Use the Scan menu to export the currently visible results.");
            });
    }
}
