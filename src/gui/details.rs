use super::*;
impl Scanner {
    pub(super) fn details(&mut self, ctx: &egui::Context) {
        let Some(ip) = self.selected else {
            return;
        };
        let Some(host) = self.results.iter().find(|h| h.ip == ip) else {
            return;
        };
        let mut open = true;
        egui::Window::new(format!("Host details · {ip}"))
            .open(&mut open)
            .default_width(400.0)
            .vscroll(true)
            .show(ctx, |ui| {
                ui.label(format!("Status: {}", host_status(host)));
                ui.label(format!("Ping: {}", ping_text(host.ping)));
                if let Some(ttl) = host.ttl {
                    ui.label(format!("TTL: {ttl}"));
                }
                ui.label(format!(
                    "Hostname: {}",
                    if host.hostname.is_empty() {
                        "—"
                    } else {
                        &host.hostname
                    }
                ));
                ui.label(format!(
                    "MAC: {}",
                    if host.mac.is_empty() {
                        "—"
                    } else {
                        &host.mac
                    }
                ));
                ui.label(format!("Open ports: {}", ports_text(&host.open)));
                if !host.udp_open.is_empty() {
                    ui.label(format!(
                        "Open UDP ports: {}",
                        host.udp_open
                            .iter()
                            .map(u16::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                if !host.trace.is_empty() {
                    ui.label(format!(
                        "Path: {}",
                        host.trace
                            .iter()
                            .map(|h| h.ip.map_or("*".to_string(), |ip| ip.to_string()))
                            .collect::<Vec<_>>()
                            .join(" > ")
                    ));
                }
                if !host.identity.is_empty() {
                    egui::ScrollArea::vertical()
                        .max_height(180.0)
                        .show(ui, |ui| {
                            for (key, value) in &host.identity {
                                ui.label(format!("{key}: {value}"));
                            }
                        });
                }
                if host.ports_checked {
                    ui.label(format!(
                        "Closed: {}   No reply: {}",
                        host.closed, host.unanswered
                    ));
                } else {
                    ui.label("Ports not checked: no ping reply.");
                }
                if let Some(old) = self.previous.get(&ip) {
                    if old.responding != host.responding || old.open != host.open {
                        ui.colored_label(
                            Color32::from_rgb(170, 100, 15),
                            format!(
                                "Changed since previous scan · previously {} · ports {}",
                                host_status(old),
                                ports_text(&old.open)
                            ),
                        );
                    } else {
                        ui.label("Unchanged since previous scan.");
                    }
                }
                for error in &host.errors {
                    ui.colored_label(Color32::from_rgb(180, 40, 40), error);
                }
                ui.separator();
                ui.label("Your note");
                // Edit a copy: viewing a host must not create an empty note.
                let mut note = self.saved.notes.get(&ip).cloned().unwrap_or_default();
                if ui
                    .add(
                        egui::TextEdit::multiline(&mut note)
                            .desired_rows(3)
                            .desired_width(f32::INFINITY),
                    )
                    .changed()
                {
                    set_note(&mut self.saved.notes, ip, note);
                    self.notes_generation += 1;
                }
                if ui.button("Copy IP address").clicked() {
                    ctx.copy_text(ip.to_string());
                }
            });
        if !open {
            self.selected = None;
        }
    }
}
