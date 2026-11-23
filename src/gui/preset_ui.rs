//! The preset picker (ROADMAP F40): Quick, Office, Plant (passive) and Full audit. The bundles
//! themselves are `core::presets`, shared with the CLI's `--preset`. Choosing an active preset
//! replaces the scan options (and keeps the machine settings: interface, source addresses,
//! script and probe files); Plant is passive, so it sets no scan options: it opens the passive
//! capture window, and Start explains why nothing is scanned until another preset is chosen.
use super::{i18n::tr, *};
use crate::presets::Preset;

/// The value of `Saved::preset` while the passive Plant preset is chosen.
pub(super) const PLANT: &str = "plant";

/// Whether the settings are exactly what an active preset produces from them.
pub(super) fn matches(p: Preset, s: &scan::Settings) -> bool {
    p.settings(s)
        .is_ok_and(|expected| serde_json::to_value(&expected).ok() == serde_json::to_value(s).ok())
}

/// The preset the picker shows: Plant when it was chosen, else the active preset the settings
/// equal, else `None` (custom settings).
pub(super) fn current(saved_preset: &str, s: &scan::Settings) -> Option<Preset> {
    if saved_preset == PLANT {
        return Some(Preset::Plant);
    }
    [Preset::Quick, Preset::Office, Preset::Full]
        .into_iter()
        .find(|p| matches(*p, s))
}

/// What the picker's button says.
pub(super) fn label(saved_preset: &str, s: &scan::Settings) -> &'static str {
    match current(saved_preset, s) {
        Some(Preset::Quick) => tr!("Quick"),
        Some(Preset::Office) => tr!("Office"),
        Some(Preset::Plant) => tr!("Plant (passive)"),
        Some(Preset::Full) => tr!("Full audit"),
        None => tr!("Custom"),
    }
}

pub(super) fn name(p: Preset) -> &'static str {
    match p {
        Preset::Quick => tr!("Quick"),
        Preset::Office => tr!("Office"),
        Preset::Plant => tr!("Plant (passive)"),
        Preset::Full => tr!("Full audit"),
    }
}

/// The tooltip of a preset: what it turns on, one line per point (translated when the German
/// catalog has the line).
pub(super) fn tooltip(p: Preset) -> String {
    p.describe()
        .into_iter()
        .map(i18n::text)
        .collect::<Vec<_>>()
        .join("\n")
}

impl Scanner {
    /// Applies a preset to the settings of the next scan (without asking; see `choose_preset`).
    pub(super) fn apply_preset(&mut self, p: Preset) {
        if self.run.is_some() {
            self.error = tr!("Settings can be changed after this scan finishes.").into();
            return;
        }
        match p.settings(&self.saved.settings) {
            Ok(settings) => {
                self.saved.settings = settings;
                self.saved.preset.clear();
                self.error.clear();
                self.status = tr!("Preset {} applied", name(p));
            }
            Err(_) => {
                // Plant: nothing to scan with.
                self.saved.preset = PLANT.into();
                self.saved.settings.safe = true;
                self.view = MainView::Passive;
                self.status =
                    tr!("Plant preset: passive only. Listen with Listen (OT); no scan is started.")
                        .into();
            }
        }
    }

    /// The preset picker of the scan controls: the presets, and the Faster and More thorough
    /// adjustments (the same entries as Scan → Preset). A choice that turns Safe Mode off asks
    /// first.
    pub(super) fn preset_picker(&mut self, ui: &mut egui::Ui) {
        let shown = label(&self.saved.preset, &self.saved.settings);
        let response = egui::ComboBox::from_id_salt("preset_picker")
            .selected_text(shown)
            .show_ui(ui, |ui| self.profile_entries(ui));
        super::a11y::named(response.response, tr!("Preset")).on_hover_text(tr!(
            "A bundle of scan settings. Hover a preset to see what it turns on."
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_picker_names_the_preset_the_settings_equal() {
        let base = scan::Settings::default();
        assert_eq!(
            current("", &base),
            Some(Preset::Quick),
            "the defaults are Quick"
        );
        for p in [Preset::Quick, Preset::Office, Preset::Full] {
            let s = p.settings(&base).unwrap();
            assert_eq!(current("", &s), Some(p), "{p:?}");
            assert!(matches(p, &s));
        }
        // A change on top of a preset is custom.
        let mut custom = Preset::Office.settings(&base).unwrap();
        custom.workers = 3;
        assert_eq!(current("", &custom), None);
        assert_eq!(label("", &custom), "Custom");
        // Machine settings do not make a preset "custom".
        let mut with_interface = Preset::Full.settings(&base).unwrap();
        with_interface.interface = "eth0".into();
        assert_eq!(current("", &with_interface), Some(Preset::Full));
        // Plant is a mode of its own, kept in the preferences.
        assert_eq!(current(PLANT, &base), Some(Preset::Plant));
        assert!(!matches(Preset::Plant, &base));
        assert_eq!(label(PLANT, &base), "Plant (passive)");
    }

    #[test]
    fn every_preset_line_has_a_german_translation() {
        let catalog = i18n::catalog(i18n::Lang::German).unwrap();
        for p in Preset::ALL {
            for line in p.describe() {
                assert!(catalog.contains_key(line), "no German entry for: {line}");
            }
        }
        i18n::set(i18n::Lang::German);
        let text = tooltip(Preset::Plant);
        i18n::set(i18n::Lang::English);
        assert!(text.contains("Es wird kein Paket gesendet"), "{text}");
    }

    #[test]
    fn every_preset_has_a_name_and_a_tooltip_that_states_the_traffic() {
        for p in Preset::ALL {
            assert!(!name(p).is_empty());
            assert!(
                tooltip(p).to_lowercase().contains("safe mode") || tooltip(p).contains("no packet")
            );
        }
    }
}
