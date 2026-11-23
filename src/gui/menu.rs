//! The menu bar and the keyboard shortcuts. Every action is a [`Cmd`], the list the command
//! palette runs: the menus, the shortcuts and the palette are built from it, so a menu entry, its
//! shortcut and its palette entry run the same code and are enabled under the same conditions.
//!
//! The menus: File (import, export, clear, quit), Scan (start, pause, stop, preset, favorite
//! addresses, settings), View (the views and windows, search, theme), Tools (workbench, schedule,
//! command palette) and Help (shortcuts, documentation, about).
use super::{i18n::tr, palette::Cmd, *};
use crate::presets::Preset;
use egui::{Key, KeyboardShortcut, Modifiers};

pub(super) const DOCS_URL: &str = "https://sparkz400.github.io/network-scope/";

/// Every command that has a shortcut, the most specific first: egui ignores an extra Shift when it
/// matches a shortcut, so Shift+F5 must be checked before F5.
pub(super) const SHORTCUTS: [Cmd; 16] = [
    Cmd::StopScan,
    Cmd::StartScan,
    Cmd::ImportList,
    Cmd::ExportHtml,
    Cmd::Settings,
    Cmd::Overview,
    Cmd::Hosts,
    Cmd::Devices,
    Cmd::Findings,
    Cmd::Map,
    Cmd::Passive,
    Cmd::Inventory,
    Cmd::Search,
    Cmd::Palette,
    Cmd::Shortcuts,
    Cmd::Quit,
];

/// A change that turns Safe Mode off, waiting for the user's confirmation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Unsafe {
    Preset(Preset),
    Faster,
}

impl Cmd {
    /// The short name in the menus (the palette has longer names with keywords).
    pub(super) fn menu_label(self) -> &'static str {
        match self {
            Cmd::ScanMyNetwork => tr!("Scan my network"),
            Cmd::StartScan => tr!("Start scan"),
            Cmd::StopScan => tr!("Stop scan"),
            Cmd::PauseScan => tr!("Pause / resume"),
            Cmd::ImportList => tr!("Import address list…"),
            Cmd::Overview => tr!("Overview"),
            Cmd::Hosts => tr!("Hosts"),
            Cmd::Settings => tr!("Settings…"),
            Cmd::Inventory => tr!("Saved inventory"),
            Cmd::Map => tr!("Network map"),
            Cmd::Findings => tr!("Findings"),
            Cmd::Devices => tr!("Devices"),
            Cmd::Workbench => tr!("Unknown-device workbench"),
            Cmd::Passive => tr!("Passive discovery / OT"),
            Cmd::About => tr!("About Network Scope"),
            Cmd::ExportCsv => tr!("Visible rows as CSV…"),
            Cmd::ExportJson => tr!("Visible rows as JSON…"),
            Cmd::ExportHtml => tr!("HTML report…"),
            Cmd::ExportMarkdown => tr!("Markdown summary…"),
            Cmd::ClearResults => tr!("Clear results and captures"),
            Cmd::Preset(p) => preset_ui::name(p),
            Cmd::Faster => tr!("Faster (turns Safe Mode off)"),
            Cmd::Thorough => tr!("More thorough"),
            Cmd::Language(l) => l.name(),
            Cmd::DarkTheme => tr!("Dark"),
            Cmd::LightTheme => tr!("Light"),
            Cmd::Search => tr!("Search hosts"),
            Cmd::Schedule => tr!("Scheduled scans…"),
            Cmd::Palette => tr!("Command palette"),
            Cmd::Shortcuts => tr!("Keyboard shortcuts"),
            Cmd::Documentation => tr!("Documentation"),
            Cmd::Quit => tr!("Quit"),
        }
    }

    /// The keyboard shortcut (`Ctrl` is `Cmd` on macOS).
    pub(super) fn shortcut(self) -> Option<KeyboardShortcut> {
        let ctrl = |key| Some(KeyboardShortcut::new(Modifiers::COMMAND, key));
        match self {
            Cmd::StartScan => Some(KeyboardShortcut::new(Modifiers::NONE, Key::F5)),
            Cmd::StopScan => Some(KeyboardShortcut::new(Modifiers::SHIFT, Key::F5)),
            Cmd::ImportList => ctrl(Key::O),
            Cmd::ExportHtml => ctrl(Key::E),
            Cmd::Settings => ctrl(Key::Comma),
            Cmd::Overview => ctrl(Key::Num1),
            Cmd::Hosts => ctrl(Key::Num2),
            Cmd::Devices => ctrl(Key::Num3),
            Cmd::Findings => ctrl(Key::Num4),
            Cmd::Map => ctrl(Key::Num5),
            Cmd::Passive => ctrl(Key::Num6),
            Cmd::Inventory => ctrl(Key::Num7),
            Cmd::Search => ctrl(Key::F),
            Cmd::Palette => ctrl(Key::K),
            Cmd::Shortcuts => Some(KeyboardShortcut::new(Modifiers::NONE, Key::F1)),
            Cmd::Quit => ctrl(Key::Q),
            _ => None,
        }
    }
}

impl Scanner {
    /// Whether a command can run now; its menu entry is greyed out otherwise.
    pub(super) fn cmd_enabled(&self, cmd: Cmd) -> bool {
        let stoppable = self
            .run
            .as_ref()
            .is_some_and(|r| !r.cancel.load(Ordering::Relaxed));
        let has_rows = !self.results.is_empty();
        let has_data = has_rows || !self.observations.is_empty();
        match cmd {
            Cmd::ScanMyNetwork | Cmd::StartScan => self.run.is_none(),
            Cmd::StopScan | Cmd::PauseScan => stoppable,
            Cmd::ImportList => self.run.is_none() && !self.busy.importing,
            Cmd::ExportCsv | Cmd::ExportJson => has_rows,
            Cmd::ExportHtml | Cmd::ExportMarkdown => has_data,
            Cmd::ClearResults => !self.live() && !self.busy.loading,
            Cmd::Preset(_) | Cmd::Faster | Cmd::Thorough => self.run.is_none(),
            _ => true,
        }
    }

    /// Whether a command's menu entry is shown as chosen: the current view, an open window,
    /// the current profile or theme.
    fn cmd_checked(&self, cmd: Cmd) -> bool {
        match cmd {
            Cmd::Overview => self.view == MainView::Home,
            Cmd::Hosts => self.view == MainView::Hosts,
            Cmd::Inventory => self.view == MainView::Inventory,
            Cmd::Map => self.view == MainView::Map,
            Cmd::Findings => self.view == MainView::Findings,
            Cmd::Devices => self.view == MainView::Devices,
            Cmd::Passive => self.view == MainView::Passive,
            Cmd::Workbench => self.workbench.open,
            Cmd::Preset(p) => {
                preset_ui::current(&self.saved.preset, &self.saved.settings) == Some(p)
            }
            Cmd::DarkTheme => self.saved.dark,
            Cmd::LightTheme => !self.saved.dark,
            _ => false,
        }
    }

    /// Runs the commands whose shortcut was pressed this frame.
    pub(super) fn shortcuts(&mut self, ctx: &egui::Context) {
        for cmd in SHORTCUTS {
            let Some(shortcut) = cmd.shortcut() else {
                continue;
            };
            if ctx.input_mut(|i| i.consume_shortcut(&shortcut)) && self.cmd_enabled(cmd) {
                self.run_command(ctx, cmd);
            }
        }
    }

    /// One menu entry: the command's name, its shortcut, greyed out when it cannot run.
    fn item(&mut self, ui: &mut egui::Ui, cmd: Cmd) -> egui::Response {
        let mut button = egui::Button::new(cmd.menu_label()).selected(self.cmd_checked(cmd));
        if let Some(shortcut) = cmd.shortcut() {
            button = button.shortcut_text(ui.ctx().format_shortcut(&shortcut));
        }
        let response = ui.add_enabled(self.cmd_enabled(cmd), button);
        if response.clicked() {
            ui.close();
            let ctx = ui.ctx().clone();
            self.run_command(&ctx, cmd);
        }
        response
    }

    /// The menu bar.
    pub(super) fn menu_bar(&mut self, ui: &mut egui::Ui) {
        // Menus close through `ui.close()` or an outside click (as before 0.32), so e.g.
        // removing a favorite keeps the menu open.
        egui::MenuBar::new()
            .config(controls::menu_config())
            .ui(ui, |ui| {
                ui.menu_button(tr!("File"), |ui| {
                    self.item(ui, Cmd::ImportList);
                    ui.menu_button(tr!("Export"), |ui| {
                        self.item(ui, Cmd::ExportHtml);
                        self.item(ui, Cmd::ExportMarkdown);
                        ui.separator();
                        self.item(ui, Cmd::ExportCsv);
                        self.item(ui, Cmd::ExportJson);
                    });
                    ui.separator();
                    self.item(ui, Cmd::ClearResults).on_hover_text(tr!(
                        "Removes active scan results and passive observations from the window. Saved inventory is kept."
                    ));
                    ui.separator();
                    self.item(ui, Cmd::Quit);
                });
                ui.menu_button(tr!("Scan"), |ui| {
                    self.item(ui, Cmd::ScanMyNetwork).on_hover_text(tr!(
                        "Finds your local networks and scans them in Safe Mode."
                    ));
                    self.item(ui, Cmd::StartScan);
                    self.item(ui, Cmd::PauseScan);
                    self.item(ui, Cmd::StopScan);
                    ui.separator();
                    ui.menu_button(tr!("Preset"), |ui| self.profile_entries(ui));
                    ui.menu_button(tr!("Favorite addresses"), |ui| self.favorites_menu(ui));
                    ui.separator();
                    self.item(ui, Cmd::Settings);
                });
                ui.menu_button(tr!("View"), |ui| {
                    for cmd in [Cmd::Overview, Cmd::Hosts] {
                        self.item(ui, cmd);
                    }
                    ui.separator();
                    for cmd in [
                        Cmd::Devices,
                        Cmd::Findings,
                        Cmd::Map,
                        Cmd::Passive,
                        Cmd::Inventory,
                    ] {
                        self.item(ui, cmd);
                    }
                    ui.separator();
                    self.item(ui, Cmd::Search);
                    ui.menu_button(tr!("Theme"), |ui| {
                        self.item(ui, Cmd::LightTheme);
                        self.item(ui, Cmd::DarkTheme);
                    });
                });
                ui.menu_button(tr!("Tools"), |ui| {
                    self.item(ui, Cmd::Workbench).on_hover_text(tr!(
                        "Group the banners that no rule identified, compare firmware versions and draft a probe rule."
                    ));
                    self.item(ui, Cmd::Schedule);
                    ui.separator();
                    self.item(ui, Cmd::Palette).on_hover_text(tr!(
                        "Search actions and all saved scans: an address, MAC, name, vendor or finding id."
                    ));
                });
                ui.menu_button(tr!("Help"), |ui| {
                    self.item(ui, Cmd::Shortcuts);
                    self.item(ui, Cmd::Documentation);
                    ui.separator();
                    self.item(ui, Cmd::About);
                });
            });
    }

    /// The profiles (presets) and the two adjustments, for the Scan menu and the header picker.
    pub(super) fn profile_entries(&mut self, ui: &mut egui::Ui) {
        for p in Preset::ALL {
            self.item(ui, Cmd::Preset(p))
                .on_hover_text(preset_ui::tooltip(p));
        }
        ui.separator();
        ui.weak(tr!("Adjust the current settings"));
        self.item(ui, Cmd::Faster).on_hover_text(tr!(
            "TCP discovery, up to 1024 concurrent hosts, 800 ms timeouts"
        ));
        self.item(ui, Cmd::Thorough).on_hover_text(tr!(
            "Three probes and port checks even when ping gets no reply"
        ));
    }

    /// The saved address lists and the starred devices.
    pub(super) fn favorites_menu(&mut self, ui: &mut egui::Ui) {
        if ui.button(tr!("Save current addresses")).clicked() {
            if !self.targets.trim().is_empty() && !self.saved.favorites.contains(&self.targets) {
                self.saved.favorites.push(self.targets.clone());
            }
            ui.close();
        }
        if !self.saved.favorites.is_empty() {
            ui.separator();
        }
        let mut remove = None;
        for (i, target) in self.saved.favorites.iter().enumerate() {
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(self.run.is_none(), egui::Button::new(target))
                    .clicked()
                {
                    self.targets = target.clone();
                    ui.close();
                }
                if ui.small_button(tr!("Remove")).clicked() {
                    remove = Some(i);
                }
            });
        }
        if let Some(i) = remove {
            self.saved.favorites.remove(i);
        }
        ui.separator();
        if ui
            .button(tr!("Show starred devices"))
            .on_hover_text(tr!(
                "Right click a host and choose Add to favorites to star it."
            ))
            .clicked()
        {
            self.view = MainView::Hosts;
            self.filter = Filter::Starred;
            ui.close();
        }
    }

    /// Chooses a preset; one that turns Safe Mode off asks first.
    pub(super) fn choose_preset(&mut self, p: Preset) {
        if p.active() && !p.safe_mode() && self.saved.settings.safe {
            self.unsafe_confirm = Some(Unsafe::Preset(p));
        } else {
            self.apply_preset(p);
        }
    }

    /// The Faster adjustment; asks first while Safe Mode is on.
    pub(super) fn choose_faster(&mut self) {
        if self.saved.settings.safe {
            self.unsafe_confirm = Some(Unsafe::Faster);
        } else {
            self.apply_faster();
        }
    }

    fn apply_faster(&mut self) {
        if self.run.is_some() {
            self.error = tr!("Settings can be changed after this scan finishes.").into();
            return;
        }
        let s = &mut self.saved.settings;
        s.safe = false;
        s.workers = 1024;
        s.tcp_only = true;
        s.probes = 1;
        s.ping_timeout = 800;
        s.port_timeout = 800;
        s.delay = 0;
        self.saved.preset.clear();
        self.status = tr!("Faster settings applied; Safe Mode is off").into();
    }

    pub(super) fn apply_thorough(&mut self) {
        if self.run.is_some() {
            self.error = tr!("Settings can be changed after this scan finishes.").into();
            return;
        }
        let s = &mut self.saved.settings;
        s.probes = 3;
        s.ping_timeout = 2000;
        s.port_timeout = 2000;
        s.scan_nonresponders = true;
        self.saved.preset.clear();
        self.status = tr!("More thorough settings applied").into();
    }

    /// Asks before a one-click change turns Safe Mode off. Nothing changes until the user agrees.
    pub(super) fn unsafe_dialog(&mut self, ctx: &egui::Context) {
        let Some(change) = self.unsafe_confirm else {
            return;
        };
        let what = match change {
            Unsafe::Preset(p) => preset_ui::name(p),
            Unsafe::Faster => tr!("Faster"),
        };
        let mut choice = None;
        egui::Window::new(tr!("Turn Safe Mode off?"))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.set_max_width(420.0);
                ui.label(tr!("{} turns Safe Mode off.", what));
                ui.label(tr!(
                    "Without Safe Mode the scan contacts many more hosts at once and sends probes without spacing; SYN scans and the ARP sweep are allowed. Fragile devices such as PLCs and printers can react badly."
                ));
                ui.horizontal(|ui| {
                    if ui.button(tr!("Turn Safe Mode off")).clicked() {
                        choice = Some(true);
                    }
                    if ui.button(tr!("Keep Safe Mode on")).clicked() {
                        choice = Some(false);
                    }
                });
            });
        if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Escape)) {
            choice = Some(false);
        }
        match choice {
            Some(true) => {
                self.unsafe_confirm = None;
                match change {
                    Unsafe::Preset(p) => self.apply_preset(p),
                    Unsafe::Faster => self.apply_faster(),
                }
            }
            Some(false) => self.unsafe_confirm = None,
            None => {}
        }
    }

    /// The list of keyboard shortcuts (F1), built from the same commands as the menus.
    pub(super) fn shortcuts_window(&mut self, ctx: &egui::Context) {
        if !self.shortcuts_open {
            return;
        }
        let mut open = true;
        egui::Window::new(tr!("Keyboard shortcuts"))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_pos(self.window_origin)
            .show(ctx, |ui| {
                egui::Grid::new("shortcuts_grid")
                    .num_columns(2)
                    .spacing([24.0, 6.0])
                    .striped(true)
                    .show(ui, |ui| {
                        for cmd in shortcut_order() {
                            if let Some(shortcut) = cmd.shortcut() {
                                ui.label(RichText::new(ctx.format_shortcut(&shortcut)).strong());
                                ui.label(cmd.menu_label());
                                ui.end_row();
                            }
                        }
                        ui.label(RichText::new(tr!("Up / Down")).strong());
                        ui.label(tr!("Choose a host in the table"));
                        ui.end_row();
                        ui.label(RichText::new("Esc").strong());
                        ui.label(tr!("Close the host details"));
                        ui.end_row();
                        ui.label(RichText::new(tr!("Ctrl and + or -")).strong());
                        ui.label(tr!("Interface scale"));
                        ui.end_row();
                    });
                ui.add_space(4.0);
                convenience::link_to(ui, tr!("Documentation"), DOCS_URL);
            });
        if !open {
            self.shortcuts_open = false;
        }
    }

    /// Moves the selection in the hosts table with the arrow keys, and closes the host details
    /// with Escape, while no text field has the keyboard focus and no menu, drop-down or dialog
    /// is open (they use those keys).
    pub(super) fn table_keys(&mut self, ctx: &egui::Context) {
        let dialog = self.palette.open
            || self.unsafe_confirm.is_some()
            || self.scope_confirm.is_some()
            || self.quick.dialog
            || self.wake.is_some();
        if dialog || ctx.text_edit_focused() || egui::Popup::is_any_open(ctx) {
            return;
        }
        if self.selected.is_some() && ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Escape))
        {
            self.selected = None;
            self.script_test = None;
            return;
        }
        if self.view != MainView::Hosts || self.rows.is_empty() {
            return;
        }
        let down = ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::ArrowDown));
        let up = ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::ArrowUp));
        if !down && !up {
            return;
        }
        let position = self.selected.and_then(|ip| {
            self.rows
                .iter()
                .position(|&i| self.results.get(i).is_some_and(|h| h.ip == ip))
        });
        let next = match (position, down) {
            (None, _) => 0,
            (Some(p), true) => (p + 1).min(self.rows.len() - 1),
            (Some(p), false) => p.saturating_sub(1),
        };
        if let Some(host) = self.results.get(self.rows[next]) {
            if self.selected != Some(host.ip) {
                self.script_test = None;
            }
            self.selected = Some(host.ip);
            self.scroll_to = Some(host.ip);
        }
    }
}

/// The shortcut list in reading order (the run order puts Shift+F5 first).
fn shortcut_order() -> [Cmd; 16] {
    let mut order = SHORTCUTS;
    order.swap(0, 1);
    order
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_listed_command_has_a_distinct_shortcut() {
        let shortcuts: Vec<KeyboardShortcut> =
            SHORTCUTS.iter().filter_map(|c| c.shortcut()).collect();
        assert_eq!(shortcuts.len(), SHORTCUTS.len());
        for (i, s) in shortcuts.iter().enumerate() {
            assert!(!shortcuts[..i].contains(s), "{s:?} twice");
        }
    }

    #[test]
    fn a_more_specific_shortcut_is_checked_before_the_one_it_contains() {
        // egui ignores an extra Shift or Alt, so F5 would also fire for Shift+F5.
        for (i, a) in SHORTCUTS.iter().enumerate() {
            for b in &SHORTCUTS[..i] {
                let (a, b) = (a.shortcut().unwrap(), b.shortcut().unwrap());
                // Pressing `a` would also match the earlier `b`.
                let contains = a.logical_key == b.logical_key
                    && a.modifiers.matches_logically(b.modifiers)
                    && a.modifiers != b.modifiers;
                assert!(!contains, "{a:?} is checked after the more general {b:?}");
            }
        }
    }

    #[test]
    fn the_shortcut_list_shows_start_before_stop() {
        let order = shortcut_order();
        assert_eq!(order[0], Cmd::StartScan);
        assert_eq!(order[1], Cmd::StopScan);
    }

    #[test]
    fn every_command_with_a_shortcut_is_in_the_list() {
        for entry in palette::entries() {
            if entry.cmd.shortcut().is_some() {
                assert!(SHORTCUTS.contains(&entry.cmd), "{:?}", entry.cmd);
            }
        }
    }

    /// The app as it starts in screenshot mode: no preferences read or written, no inventory.
    fn app(ctx: &egui::Context) -> Scanner {
        let cc = eframe::CreationContext::_new_kittest(ctx.clone());
        Scanner::new(&cc, Some(PathBuf::from("unused.png")), Saved::default())
    }

    /// One frame in which `key` is pressed with `modifiers`; runs the shortcut handling and the
    /// arrow keys of the table, as the real frame does.
    fn press(ctx: &egui::Context, app: &mut Scanner, key: Key, modifiers: Modifiers) {
        let input = egui::RawInput {
            events: vec![egui::Event::Key {
                key,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers,
            }],
            ..Default::default()
        };
        ctx.run_ui(input, |ui| {
            app.shortcuts(ui.ctx());
            app.table_keys(ui.ctx());
            app.unsafe_dialog(ui.ctx());
        })
        // The test never paints, so the font atlas upload is dropped on purpose.
        .drop_without_applying_deltas();
    }

    #[test]
    fn a_one_click_change_that_turns_safe_mode_off_asks_first() {
        let ctx = egui::Context::default();
        let mut app = app(&ctx);
        assert!(app.saved.settings.safe);
        let before = app.saved.settings.clone();
        app.run_command(&ctx, Cmd::Preset(Preset::Full));
        assert_eq!(app.unsafe_confirm, Some(Unsafe::Preset(Preset::Full)));
        assert_eq!(
            serde_json::to_value(&app.saved.settings).unwrap(),
            serde_json::to_value(&before).unwrap(),
            "nothing changes before the answer"
        );
        // Escape is "Keep Safe Mode on".
        press(&ctx, &mut app, Key::Escape, Modifiers::NONE);
        assert_eq!(app.unsafe_confirm, None);
        assert!(app.saved.settings.safe);

        app.run_command(&ctx, Cmd::Faster);
        assert_eq!(app.unsafe_confirm, Some(Unsafe::Faster));
        assert!(app.saved.settings.safe);
        app.unsafe_confirm = None;

        // Presets that keep Safe Mode on, and More thorough, apply at once.
        app.run_command(&ctx, Cmd::Preset(Preset::Office));
        assert_eq!(app.unsafe_confirm, None);
        assert!(preset_ui::matches(Preset::Office, &app.saved.settings));
        app.run_command(&ctx, Cmd::Thorough);
        assert_eq!(app.unsafe_confirm, None);
        assert_eq!(app.saved.settings.probes, 3);
        assert!(app.saved.settings.safe);

        // With Safe Mode already off there is nothing to confirm.
        app.saved.settings.safe = false;
        app.run_command(&ctx, Cmd::Faster);
        assert_eq!(app.unsafe_confirm, None);
        assert_eq!(app.saved.settings.workers, 1024);
        app.run_command(&ctx, Cmd::Preset(Preset::Full));
        assert_eq!(app.unsafe_confirm, None);
        assert!(preset_ui::matches(Preset::Full, &app.saved.settings));
    }

    #[test]
    fn shortcuts_open_the_views_and_a_disabled_command_does_nothing() {
        let ctx = egui::Context::default();
        let mut app = app(&ctx);
        press(&ctx, &mut app, Key::Num4, Modifiers::COMMAND);
        assert!(app.view == MainView::Findings);
        press(&ctx, &mut app, Key::Num2, Modifiers::COMMAND);
        assert!(app.view == MainView::Hosts);
        press(&ctx, &mut app, Key::Num1, Modifiers::COMMAND);
        assert!(app.view == MainView::Home);
        press(&ctx, &mut app, Key::F, Modifiers::COMMAND);
        assert!(app.view == MainView::Hosts && app.focus_search);
        press(&ctx, &mut app, Key::K, Modifiers::COMMAND);
        assert!(app.palette.open);
        press(&ctx, &mut app, Key::K, Modifiers::COMMAND);
        assert!(!app.palette.open, "Ctrl+K also closes the palette");
        press(&ctx, &mut app, Key::F1, Modifiers::NONE);
        assert!(app.shortcuts_open);
        // Nothing to stop, and Shift+F5 is not taken for F5 (Start).
        press(&ctx, &mut app, Key::F5, Modifiers::SHIFT);
        assert!(app.run.is_none());
        // Exports need results.
        assert!(!app.cmd_enabled(Cmd::ExportCsv));
        assert!(app.cmd_enabled(Cmd::StartScan));
        assert!(!app.cmd_enabled(Cmd::StopScan));
    }

    #[test]
    fn the_arrow_keys_move_the_selection_in_the_hosts_table() {
        let ctx = egui::Context::default();
        let mut app = app(&ctx);
        app.results = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
            .iter()
            .map(|ip| demo::demo_host(ip, &[80], &[]))
            .collect();
        app.rows = vec![0, 1, 2];
        app.view = MainView::Hosts;
        let ip = |s: &str| Some(s.parse::<IpAddr>().unwrap());
        press(&ctx, &mut app, Key::ArrowDown, Modifiers::NONE);
        assert_eq!(app.selected, ip("10.0.0.1"));
        press(&ctx, &mut app, Key::ArrowDown, Modifiers::NONE);
        press(&ctx, &mut app, Key::ArrowDown, Modifiers::NONE);
        press(&ctx, &mut app, Key::ArrowDown, Modifiers::NONE);
        assert_eq!(app.selected, ip("10.0.0.3"), "stops at the last row");
        assert_eq!(app.scroll_to, ip("10.0.0.3"));
        press(&ctx, &mut app, Key::ArrowUp, Modifiers::NONE);
        assert_eq!(app.selected, ip("10.0.0.2"));
        // Escape closes the host details (with the dialog gate below, too).
        app.unsafe_confirm = Some(Unsafe::Faster);
        press(&ctx, &mut app, Key::Escape, Modifiers::NONE);
        assert_eq!(app.unsafe_confirm, None, "the dialog took the Escape");
        assert_eq!(app.selected, ip("10.0.0.2"), "and the details stay open");
        app.selected = ip("10.0.0.2");
        press(&ctx, &mut app, Key::Escape, Modifiers::NONE);
        assert_eq!(app.selected, None);
        app.selected = ip("10.0.0.2");
        // Not while a dialog is open, nor on the Overview.
        app.unsafe_confirm = Some(Unsafe::Faster);
        press(&ctx, &mut app, Key::ArrowUp, Modifiers::NONE);
        assert_eq!(app.selected, ip("10.0.0.2"));
        app.unsafe_confirm = None;
        app.view = MainView::Home;
        press(&ctx, &mut app, Key::ArrowUp, Modifiers::NONE);
        assert_eq!(app.selected, ip("10.0.0.2"));
    }
}
