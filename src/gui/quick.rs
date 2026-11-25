// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! "Scan my network" in one click (ROADMAP F36): finds the networks this computer is connected
//! to, picks the private on-link ones (`core::localnets` explains the rules: no loopback,
//! link-local, VPN-looking /32, public or virtual networks; anything larger than a /22 only after
//! a confirmation) and starts a Safe Mode scan of them through the normal start path, so the scope
//! guard applies like for any other scan.
use super::{i18n::tr, *};
use crate::localnets::{self, Candidate, Decision, LocalNet};

#[derive(Default)]
pub(super) struct QuickState {
    /// A detection started by the button is running; its answer starts the scan.
    pub pending: bool,
    /// The networks of the last detection with the decision about each.
    pub candidates: Vec<Candidate>,
    /// The confirmation dialog is open (large networks, or nothing could be chosen).
    pub dialog: bool,
    /// The user ticked the large networks in the dialog.
    pub include_large: bool,
}

/// Text for the skipped networks, for the status line and the dialog.
pub(super) fn skipped_text(candidates: &[Candidate]) -> String {
    candidates
        .iter()
        .filter_map(|c| match &c.decision {
            Decision::Skip(why) => Some(format!("{} ({why})", c.net.cidr())),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("; ")
}

impl Scanner {
    /// The button: detects the local networks (in the background) and then scans them.
    pub(super) fn scan_my_network(&mut self) {
        if self.run.is_some() || self.listening.is_some() || self.ot.capturing() {
            self.error = tr!("Stop the running scan or capture first.").into();
            return;
        }
        if self.busy.detecting {
            return;
        }
        self.quick.pending = true;
        self.quick.include_large = false;
        self.status = tr!("Looking for your networks…").into();
        self.submit(Job::Networks);
    }

    /// The answer of the detection.
    pub(super) fn networks_found(&mut self, result: Result<Vec<LocalNet>, String>) {
        self.busy.detecting = false;
        let nets = match result {
            Ok(nets) => nets,
            Err(e) => {
                self.quick.pending = false;
                self.error = e;
                return;
            }
        };
        self.local_nets = nets.clone();
        self.quick.candidates = localnets::classify(&nets);
        if !self.quick.pending {
            return;
        }
        self.quick.pending = false;
        let sure = localnets::selected(&self.quick.candidates, false);
        let large = localnets::selected(&self.quick.candidates, true).len() - sure.len();
        if sure.is_empty() || large > 0 {
            // Nothing to scan without asking, or something big: the user decides.
            self.quick.dialog = true;
            if sure.is_empty() && large == 0 {
                self.error = tr!("No private network was found on this computer.").into();
            }
        } else {
            self.start_quick(sure);
        }
    }

    /// Starts the Safe Mode scan of `networks` (CIDR texts).
    fn start_quick(&mut self, networks: Vec<String>) {
        self.targets = networks.join(", ");
        // Always the gentle profile; the other settings stay as the user has them.
        self.saved.settings.safe = true;
        self.saved.preset.clear();
        self.view = MainView::Hosts;
        self.start();
        if self.run.is_some() {
            let skipped = skipped_text(&self.quick.candidates);
            self.status = if skipped.is_empty() {
                tr!("Scanning {} in Safe Mode", self.targets)
            } else {
                tr!(
                    "Scanning {} in Safe Mode (skipped: {})",
                    self.targets,
                    skipped
                )
            };
        }
    }

    pub(super) fn quick_dialog(&mut self, ctx: &egui::Context) {
        if !self.quick.dialog {
            return;
        }
        let mut choice = None;
        egui::Window::new(tr!("Scan my network"))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_max_width(520.0);
                let c = &self.quick.candidates;
                if localnets::selected(c, false).is_empty()
                    && localnets::selected(c, true).is_empty()
                {
                    ui.label(tr!("No private network was found on this computer."));
                }
                for cand in c {
                    match &cand.decision {
                        Decision::Scan => {
                            ui.label(format!("✔ {} · {}", cand.net.cidr(), cand.net.interface));
                        }
                        Decision::Confirm(why) => {
                            ui.label(
                                RichText::new(tr!(
                                    "{} on {} is large ({}).",
                                    cand.net.cidr(),
                                    cand.net.interface,
                                    why
                                ))
                                .strong(),
                            );
                        }
                        Decision::Skip(_) => {}
                    }
                }
                if c.iter().any(|x| matches!(x.decision, Decision::Confirm(_))) {
                    ui.checkbox(
                        &mut self.quick.include_large,
                        tr!("Scan the large networks too (this takes a long time)"),
                    );
                }
                let skipped = skipped_text(c);
                if !skipped.is_empty() {
                    ui.add_space(4.0);
                    ui.collapsing(tr!("Left out"), |ui| {
                        ui.weak(skipped);
                    });
                }
                ui.label(tr!(
                    "Safe Mode: at most 8 hosts at a time and 100 ms between probes."
                ));
                let chosen = localnets::selected(c, self.quick.include_large);
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(!chosen.is_empty(), egui::Button::new(tr!("Scan")))
                        .clicked()
                    {
                        choice = Some(true);
                    }
                    if ui.button(tr!("Cancel")).clicked() {
                        choice = Some(false);
                    }
                });
            });
        match choice {
            Some(true) => {
                self.quick.dialog = false;
                let chosen = localnets::selected(&self.quick.candidates, self.quick.include_large);
                self.start_quick(chosen);
            }
            Some(false) => self.quick.dialog = false,
            None => {}
        }
    }
}
