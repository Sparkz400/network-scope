//! The opt-in update check of the desktop app (setting "Check for updates on start", off by
//! default). Notify only: one request to GitHub on a background thread when the program starts,
//! then a line in the status bar and a window with the release page and the verification
//! commands. Nothing is downloaded or installed; see `network_scope_core::update`.
use super::*;
use crate::update;

/// The pending answer of the background check.
pub(super) type Check = mpsc::Receiver<Result<update::Outcome, String>>;

/// What an answer changes on screen.
#[derive(Debug, PartialEq)]
pub(super) enum Effect {
    /// A newer release exists: show the notice.
    Notice(update::Release),
    /// A failed check: one line in the status bar.
    Failed(String),
    /// Up to date, ahead of the release, or only a pre-release: nothing to show.
    Nothing,
}

pub(super) fn effect(result: Result<update::Outcome, String>) -> Effect {
    match result {
        Ok(update::Outcome::Available(release)) => Effect::Notice(release),
        Ok(_) => Effect::Nothing,
        Err(e) => Effect::Failed(format!("Update check failed: {e}")),
    }
}

impl Scanner {
    /// Starts the check on a background thread; `poll_update` picks up the answer.
    pub(super) fn start_update_check(&mut self, ctx: &egui::Context) {
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let outcome = update::check(env!("CARGO_PKG_VERSION"), update::DEFAULT_TIMEOUT);
            let _ = tx.send(outcome);
            ctx.request_repaint();
        });
        self.update_check = Some(rx);
    }

    /// Takes the answer of the background check, when it has arrived.
    pub(super) fn poll_update(&mut self) {
        let Some(rx) = &self.update_check else {
            return;
        };
        match rx.try_recv() {
            Ok(result) => {
                self.update_check = None;
                match effect(result) {
                    Effect::Notice(release) => self.update_notice = Some(release),
                    Effect::Failed(message) => self.status = message,
                    Effect::Nothing => {}
                }
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => self.update_check = None,
        }
    }

    /// The notice in the status bar: a link to the release page, the verification window and a
    /// way to dismiss it.
    pub(super) fn update_notice_ui(&mut self, ui: &mut egui::Ui) {
        let Some(release) = self.update_notice.clone() else {
            return;
        };
        ui.separator();
        convenience::link_to(
            ui,
            tr!("Version {} is available", release.version_text()),
            &release.url(),
        );
        if ui.small_button(tr!("How to verify…")).clicked() {
            self.update_open = true;
        }
        if ui.small_button(tr!("Dismiss")).clicked() {
            self.update_notice = None;
            self.update_open = false;
        }
    }

    pub(super) fn update_window(&mut self, ctx: &egui::Context) {
        let Some(release) = self.update_notice.clone() else {
            return;
        };
        egui::Window::new(tr!("Update available"))
            .open(&mut self.update_open)
            .default_pos(self.window_origin)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(tr!(
                    "Version {} is available (this is {}).",
                    release.version_text(),
                    env!("CARGO_PKG_VERSION")
                ));
                convenience::link_to(ui, release.url(), &release.url());
                ui.label(
                    tr!("Network Scope never downloads or installs updates. Download the file for your platform from the release page and verify it first:"),
                );
                let text = update::verification_text(&release);
                ui.add(
                    egui::TextEdit::multiline(&mut text.as_str())
                        .font(egui::TextStyle::Monospace)
                        .desired_width(560.0),
                );
                if ui.button(tr!("Copy text")).clicked() {
                    ui.ctx().copy_text(text);
                }
            });
    }
}
