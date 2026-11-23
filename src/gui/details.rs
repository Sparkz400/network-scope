use super::*;
impl Scanner {
    /// The host details, docked on the right of the main window while a host is selected.
    pub(super) fn details(&mut self, root: &mut egui::Ui) {
        let ctx = &root.ctx().clone();
        let Some(ip) = self.selected else {
            return;
        };
        let Some(host) = self.results.iter().find(|h| h.ip == ip) else {
            return;
        };
        let (mut test, mut apply, mut discard, mut timeline) = (None, false, false, false);
        let mut open = true;
        let mut menu_action = None;
        // At most 45 % of the room next to the sidebar, so the page stays usable in a small
        // window (800 px wide: about 280 px for the details, 340 px for the page).
        let max = ((ctx.content_rect().width() - 172.0) * 0.45).max(220.0);
        egui::Panel::right("host_details")
            .resizable(true)
            .default_size(330.0_f32.min(max))
            .size_range(220.0..=max)
            .show(root, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.strong(tr!("Host details · {}", ip));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .small_button(tr!("Close"))
                            .on_hover_text(tr!("Close the host details (Esc)"))
                            .clicked()
                        {
                            open = false;
                        }
                    });
                });
                ui.separator();
                egui::ScrollArea::vertical().id_salt("host_details").show(ui, |ui| {
                ui.label(tr!("Status: {}", host_status(host)));
                ui.label(tr!("Ping: {}", ping_text(host.ping)));
                if let Some(ttl) = host.ttl {
                    ui.label(format!("TTL: {ttl}"));
                }
                ui.label(tr!(
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
                // The conclusions with their confidence; hover for the reasons.
                for (label, key, prefix) in [
                    (tr!("OS"), "os.guess", "os"),
                    (tr!("Type"), "device.type", "device"),
                ] {
                    if let Some(value) = host.identity.get(key) {
                        let why = crate::evidence::Evidence::from_identity(&host.identity, prefix);
                        let shown = why
                            .as_ref()
                            .filter(|e| e.confidence > 0)
                            .map_or(value.clone(), |e| format!("{value} ({} %)", e.confidence));
                        let response = ui.label(format!("{label}: {shown}"));
                        if let Some(e) = why.filter(|e| !e.reasons.is_empty()) {
                            response.on_hover_text(tr!("because {}", e.because()));
                        }
                    }
                }
                ui.label(tr!("Open ports: {}", ports_text(&host.open)));
                if !host.udp_open.is_empty() {
                    ui.label(tr!(
                        "Open UDP ports: {}",
                        host.udp_open
                            .iter()
                            .map(u16::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                if !host.trace.is_empty() {
                    ui.label(tr!(
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
                    ui.label(tr!(
                        "Closed: {}   No reply: {}",
                        host.closed,
                        host.unanswered
                    ));
                } else {
                    ui.label(tr!("Ports not checked: no ping reply."));
                }
                if let Some(old) = self.previous.get(&ip) {
                    if old.responding != host.responding || old.open != host.open {
                        ui.colored_label(
                            Color32::from_rgb(170, 100, 15),
                            tr!(
                                "Changed since previous scan · previously {} · ports {}",
                                host_status(old),
                                ports_text(&old.open)
                            ),
                        );
                    } else {
                        ui.label(tr!("Unchanged since previous scan."));
                    }
                }
                for error in &host.errors {
                    ui.colored_label(Color32::from_rgb(205, 70, 70), error);
                }
                ui.separator();
                ui.label(tr!("Your note"));
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
                // Two rows of two, so the panel stays narrow and no button text wraps.
                ui.horizontal(|ui| {
                    if ui.button(tr!("Copy IP address")).clicked() {
                        ctx.copy_text(ip.to_string());
                    }
                    // The same actions as the right-click menu of the table row.
                    let starred = self.saved.starred.contains(&convenience::favorite_key(host));
                    ui.menu_button(tr!("Actions"), |ui| {
                        menu_action = Some(convenience::host_menu(ui, host, starred));
                    });
                });
                ui.horizontal(|ui| {
                    if ui
                        .button(tr!("Timeline…"))
                        .on_hover_text(
                            tr!("When this device was first seen and what changed: address, MAC, name, ports and findings, from the saved scans."),
                        )
                        .clicked()
                    {
                        timeline = true;
                    }
                    ui.add_enabled_ui(!self.busy.testing, |ui| {
                        let menu = egui::containers::menu::MenuButton::new(tr!("Test script…"))
                            .config(super::controls::menu_config());
                        menu.ui(ui, |ui| {
                            let configured = self.saved.settings.scripts.trim();
                            if ui
                                .add_enabled(
                                    !configured.is_empty(),
                                    egui::Button::new(if configured.is_empty() {
                                        tr!("Configured script (none set in Settings)").to_string()
                                    } else {
                                        tr!("Configured script ({})", configured)
                                    }),
                                )
                                .clicked()
                            {
                                test = Some(configured.to_string());
                                ui.close();
                            }
                            if ui.button(tr!("Choose .rhai file…")).clicked() {
                                ui.close();
                                if let Some(path) = rfd::FileDialog::new()
                                    .add_filter("Rhai script", &["rhai"])
                                    .pick_file()
                                {
                                    test = Some(path.display().to_string());
                                }
                            }
                        })
                        .0
                        .on_hover_text(
                            tr!("Runs the script on a copy of this host. Nothing is rescanned or changed until you choose Apply."),
                        );
                    });
                });
                if let Some(t) = self.script_test.as_ref().filter(|t| t.ip == ip) {
                    ui.separator();
                    ui.strong(tr!("Script test · {}", t.path));
                    match &t.result {
                        None => {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label(tr!("Running…"));
                            });
                        }
                        Some(Err(e)) => {
                            ui.colored_label(Color32::from_rgb(205, 70, 70), e);
                        }
                        Some(Ok(outcome)) => {
                            for line in script_lines(outcome) {
                                ui.label(line);
                            }
                            ui.horizontal(|ui| {
                                if ui
                                    .add_enabled(
                                        self.run.is_none() && !outcome_is_empty(outcome),
                                        egui::Button::new(tr!("Apply")),
                                    )
                                    .on_hover_text(
                                        tr!("Adds these fields, findings and notes to the host in this window."),
                                    )
                                    .on_disabled_hover_text(
                                        tr!("Nothing to apply, or a scan is running."),
                                    )
                                    .clicked()
                                {
                                    apply = true;
                                }
                                if ui.button(tr!("Discard")).clicked() {
                                    discard = true;
                                }
                            });
                        }
                    }
                }
                });
            });
        if let Some(act) = menu_action
            && let Some(host) = self.results.iter().find(|h| h.ip == ip).cloned()
        {
            self.do_menu_action(ctx, &host, act);
        }
        let tested = test.and_then(|path| {
            let host = self.results.iter().find(|h| h.ip == ip)?.clone();
            Some((path, host))
        });
        if let Some((path, host_copy)) = tested {
            self.script_tokens += 1;
            self.script_test = Some(ScriptTest {
                token: self.script_tokens,
                ip,
                path: path.clone(),
                result: None,
            });
            self.submit(Job::TestScript(
                self.script_tokens,
                path,
                Box::new(host_copy),
            ));
        }
        if timeline && let Some(host) = self.results.iter().find(|h| h.ip == ip).cloned() {
            self.open_timeline(&host);
        }
        if apply {
            self.apply_script_test();
        }
        if discard || !open {
            self.script_test = None;
        }
        if !open {
            self.selected = None;
        }
    }
    /// Adds the result of the finished dry-run to the host it ran on, if it is still there.
    fn apply_script_test(&mut self) {
        let Some(ScriptTest {
            ip,
            path,
            result: Some(Ok(outcome)),
            ..
        }) = self.script_test.take()
        else {
            return;
        };
        if self.run.is_some() {
            self.error = tr!("Script result not applied: a scan is running.").into();
            return;
        }
        match self.results.iter_mut().find(|h| h.ip == ip) {
            Some(host) => {
                outcome.apply(host);
                self.haystacks.remove(&ip);
                self.data_changed();
                self.status = tr!(
                    "Applied {} to {} (in this window; export or rescan to keep it)",
                    path,
                    ip
                );
            }
            None => self.error = tr!("{} is no longer in the results.", ip),
        }
    }
}
fn outcome_is_empty(o: &crate::script::Outcome) -> bool {
    o.sets.is_empty() && o.findings.is_empty() && o.notes.is_empty()
}
/// Readable lines for a dry-run result.
fn script_lines(o: &crate::script::Outcome) -> Vec<String> {
    if outcome_is_empty(o) {
        return vec!["The script set nothing for this host.".into()];
    }
    let mut lines = vec![];
    for (k, v) in &o.sets {
        lines.push(format!("Set script.{k} = {v}"));
    }
    for f in &o.findings {
        lines.push(format!(
            "Finding [{}] {}: {}{}",
            f.severity,
            f.id,
            f.title,
            if f.evidence.is_empty() {
                String::new()
            } else {
                format!(" ({})", f.evidence)
            }
        ));
    }
    for n in &o.notes {
        lines.push(format!("Note / error: {n}"));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dry_run_lines_list_fields_findings_and_notes() {
        let o = crate::script::Outcome {
            sets: vec![("owner".into(), "ot".into())],
            findings: vec![crate::script::ScriptFinding {
                id: "telnet".into(),
                severity: "high".into(),
                title: "Telnet open".into(),
                evidence: "port 23".into(),
            }],
            notes: vec!["script t.rhai: boom".into()],
        };
        assert_eq!(
            script_lines(&o),
            [
                "Set script.owner = ot",
                "Finding [high] telnet: Telnet open (port 23)",
                "Note / error: script t.rhai: boom"
            ]
        );
        assert!(outcome_is_empty(&Default::default()));
        assert_eq!(script_lines(&Default::default()).len(), 1);
    }
}
