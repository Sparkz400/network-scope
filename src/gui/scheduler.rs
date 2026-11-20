//! Scheduled scans: the tick that starts them and the "Scheduled scans" section of the settings.
//! The rules (interval limits, due time, postponing while busy) are in `core::schedule`.
use super::*;
use crate::schedule::{Action, MAX_INTERVAL_MINUTES, MIN_INTERVAL_MINUTES, describe_wait};

impl Scanner {
    /// Runs on every `logic` tick, also while the window is hidden. Starts a scan when one is
    /// due and nothing else uses the scanner; otherwise it only updates the note for the settings.
    pub(super) fn poll_schedule(&mut self, ctx: &egui::Context) {
        if self.screenshot.is_some() {
            return;
        }
        if !self.saved.schedule.enabled {
            self.schedule_anchor = None;
            self.schedule_note.clear();
            return;
        }
        let anchor = *self.schedule_anchor.get_or_insert_with(Instant::now);
        let busy = self.live() || self.ot.capturing() || self.busy.loading;
        let action = self.saved.schedule.decide(anchor.elapsed(), busy);
        self.schedule_note = match &action {
            Action::Off => String::new(),
            Action::Invalid(reason) => reason.clone(),
            Action::Wait(left) => tr!("Next scan {}", describe_wait(*left)),
            Action::Postponed => tr!("Next scan waits for the running scan or capture").into(),
            Action::Start => tr!("Starting").into(),
        };
        if action == Action::Start {
            self.schedule_anchor = Some(Instant::now());
            self.start_scheduled();
        }
        // The countdown and the due time are checked a few times a minute, not every frame.
        ctx.request_repaint_after(Duration::from_secs(5));
    }

    /// One scheduled scan: the scheduled targets, the user's settings, but always Safe Mode (an
    /// unattended scan never lifts the safety limits). It is saved to the inventory like any scan.
    fn start_scheduled(&mut self) {
        let targets = std::mem::replace(&mut self.targets, self.saved.schedule.targets.clone());
        let was_safe = crate::schedule::force_safe_mode(&mut self.saved.settings);
        // Through the scope guard like every scan, but without anyone to confirm: public and
        // out-of-scope targets are refused, never asked about.
        self.start_unattended();
        self.saved.settings.safe = was_safe;
        self.targets = targets;
        if self.run.is_some() {
            self.status = tr!("Scheduled scan · {}", self.status);
        }
    }
}

/// The "Scheduled scans" section of the settings (editing stays possible while a scan runs).
/// `main_targets` is the main window's target field, `note` what the scheduler is waiting for and
/// `error` why the scheduled targets do not parse.
pub(super) fn schedule_section(
    ui: &mut egui::Ui,
    saved: &mut Saved,
    main_targets: &str,
    note: &str,
    error: &mut String,
) {
    ui.separator();
    ui.heading(tr!("Scheduled scans"));
    ui.checkbox(
        &mut saved.schedule.enabled,
        tr!("Scan on a schedule while Network Scope is open"),
    );
    ui.horizontal(|ui| {
        ui.label(tr!("Targets"));
        let edit = ui.add(
            egui::TextEdit::singleline(&mut saved.schedule.targets)
                .hint_text("192.168.1.1-254")
                .desired_width(180.0),
        );
        if edit.changed() {
            *error = saved
                .schedule
                .validate(saved.settings.skip_edges)
                .err()
                .filter(|_| !saved.schedule.targets.trim().is_empty())
                .unwrap_or_default();
        }
        if ui
            .button(tr!("Use main window"))
            .on_hover_text(tr!("Copy the targets from the main window"))
            .clicked()
        {
            saved.schedule.targets = main_targets.to_string();
            error.clear();
        }
    });
    ui.horizontal(|ui| {
        ui.label(tr!("Every"));
        ui.add(
            egui::DragValue::new(&mut saved.schedule.interval_minutes)
                .range(MIN_INTERVAL_MINUTES..=MAX_INTERVAL_MINUTES)
                .suffix(" min"),
        );
    });
    if !error.is_empty() {
        ui.colored_label(egui::Color32::from_rgb(205, 70, 70), error.as_str());
    }
    if saved.schedule.enabled && !note.is_empty() {
        ui.label(note);
    }
    ui.label(
        tr!("Scheduled scans always run in Safe Mode with your other settings and are saved to the inventory. They run only while this window is open."),
    );
    ui.label(tr!(
        "For monitoring that keeps running with the window closed, run `monitor` as a service:"
    ));
    let hint = crate::schedule::service_hint(&saved.schedule);
    ui.monospace(&hint);
    if ui.button(tr!("Copy command")).clicked() {
        ui.ctx().copy_text(hint);
    }
}
