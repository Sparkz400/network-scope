// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Tests that use the whole window the way a person does: they render real frames of the app
//! with the screenshot sample data, find a widget by its accessible name (what a screen reader
//! reads) and click it with pointer events. Nothing is scanned, saved or read from disk.
use super::*;
use crate::presets::Preset;
use eframe::App as _;

/// The window size of the tests (the screenshot size).
const SIZE: egui::Vec2 = egui::vec2(1100.0, 720.0);

/// A widget of the last frame: its accessible name, role and place.
#[derive(Debug, Clone)]
struct Widget {
    id: egui::accesskit::NodeId,
    name: String,
    role: String,
    rect: egui::Rect,
}

struct Harness {
    ctx: egui::Context,
    app: Scanner,
    frame: eframe::Frame,
    events: Vec<egui::Event>,
    widgets: Vec<Widget>,
    size: egui::Vec2,
    /// The modifier keys that are held down (see `hold`).
    held: egui::Modifiers,
}

impl Harness {
    /// The app with the sample data of a screenshot state ("main", "findings", ...).
    fn new(state: &str) -> Self {
        Self::sized(state, SIZE)
    }

    /// The same in a window of another size.
    fn sized(state: &str, size: egui::Vec2) -> Self {
        Self::start(state, size, Saved::default())
    }

    /// The same with the preferences of an earlier start.
    fn start(state: &str, size: egui::Vec2, saved: Saved) -> Self {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let cc = eframe::CreationContext::_new_kittest(ctx.clone());
        let mut app = Scanner::new(&cc, Some(PathBuf::from("unused.png")), saved);
        app.seed_demo(state);
        i18n::set(i18n::Lang::English);
        let mut h = Self {
            ctx,
            app,
            frame: eframe::Frame::_new_kittest(),
            events: vec![],
            widgets: vec![],
            size,
            held: Default::default(),
        };
        // Layout settles over a couple of frames (sizes of panels and tables).
        for _ in 0..3 {
            h.step();
        }
        h
    }

    /// One frame with the queued events.
    fn step(&mut self) {
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, self.size)),
            events: std::mem::take(&mut self.events),
            ..Default::default()
        };
        let ctx = self.ctx.clone();
        let (app, frame) = (&mut self.app, &mut self.frame);
        let mut output = ctx.run_ui(input, |ui| {
            app.logic(ui.ctx(), frame);
            app.ui(ui, frame);
        });
        // Nothing renders these textures.
        output.textures_delta.clear();
        let update = output
            .platform_output
            .accesskit_update
            .expect("accessibility is on");
        self.widgets = update
            .nodes
            .iter()
            .filter_map(|(id, node)| {
                let b = node.bounds()?;
                let name = node
                    .label()
                    .or_else(|| node.value())
                    .unwrap_or_default()
                    .to_string();
                Some(Widget {
                    id: *id,
                    name,
                    role: format!("{:?}", node.role()),
                    rect: egui::Rect::from_min_max(
                        egui::pos2(b.x0 as f32, b.y0 as f32),
                        egui::pos2(b.x1 as f32, b.y1 as f32),
                    ),
                })
            })
            .collect();
    }

    /// The widgets with this name (or whose name starts with it and a space, as a sidebar entry
    /// with its count).
    /// Text runs repeat the text of their label, and a label next to a control names it: when
    /// both are found, the control is the one meant.
    fn find(&self, name: &str) -> Vec<&Widget> {
        let mut found: Vec<&Widget> = self
            .widgets
            .iter()
            .filter(|w| w.role != "TextRun" && w.name == name)
            .collect();
        if found.is_empty() {
            found = self
                .widgets
                .iter()
                .filter(|w| w.role != "TextRun" && w.name.starts_with(&format!("{name} ")))
                .collect();
        }
        if found.len() > 1 && found.iter().any(|w| w.role != "Label") {
            found.retain(|w| w.role != "Label");
        }
        found
    }

    /// Holds these modifier keys down from the next frame on (none: lets them go).
    fn hold(&mut self, keys: egui::Modifiers) {
        self.held = keys;
        self.events.push(egui::Event::ModifiersChanged(keys));
    }

    fn has(&self, name: &str) -> bool {
        !self.find(name).is_empty()
    }

    /// The one widget with this name; fails with the names on screen when there is none or
    /// more than one.
    fn one(&self, name: &str) -> egui::Rect {
        let found = self.find(name);
        assert!(
            found.len() == 1,
            "{} widgets named {name:?}: {found:?}\non screen: {:?}",
            found.len(),
            self.widgets
                .iter()
                .filter(|w| !w.name.is_empty())
                .map(|w| (&w.name, &w.role))
                .collect::<Vec<_>>()
        );
        found[0].rect
    }

    fn press(&mut self, pos: egui::Pos2, button: egui::PointerButton) {
        self.events.push(egui::Event::PointerMoved(pos));
        self.step();
        for pressed in [true, false] {
            self.events.push(egui::Event::PointerButton {
                pos,
                button,
                pressed,
                modifiers: self.held,
            });
            self.step();
        }
        self.step();
    }

    /// Clicks the one widget with this name.
    fn click(&mut self, name: &str) {
        let pos = self.one(name).center();
        self.press(pos, egui::PointerButton::Primary);
    }

    fn right_click(&mut self, name: &str) {
        let pos = self.one(name).center();
        self.press(pos, egui::PointerButton::Secondary);
    }

    /// Gives the one widget with this name the keyboard focus, as a screen reader does, then
    /// presses a key.
    fn focus_and_press(&mut self, name: &str, key: egui::Key) {
        let found = self.find(name);
        assert_eq!(found.len(), 1, "one widget named {name:?}");
        let target_node = found[0].id;
        self.events.push(egui::Event::AccessKitActionRequest(
            egui::accesskit::ActionRequest {
                action: egui::accesskit::Action::Focus,
                target_tree: egui::accesskit::TreeId::ROOT,
                target_node,
                data: None,
            },
        ));
        self.step();
        for pressed in [true, false] {
            self.events.push(egui::Event::Key {
                key,
                physical_key: None,
                pressed,
                repeat: false,
                modifiers: Default::default(),
            });
            self.step();
        }
        self.step();
    }

    /// Moves the pointer onto the widget (a submenu opens on hover).
    fn hover(&mut self, name: &str) {
        let pos = self.one(name).center();
        self.events.push(egui::Event::PointerMoved(pos));
        self.step();
        self.step();
    }
}

fn ip(s: &str) -> Option<IpAddr> {
    Some(s.parse().unwrap())
}

#[test]
fn the_menus_open_their_entries_and_run_them() {
    let mut h = Harness::new("main");
    assert!(!h.has("Quit"), "menus start closed");
    h.click("File");
    assert!(h.has("Quit") && h.has("Import address list…"));
    h.hover("Export");
    assert!(h.has("HTML report…"), "the Export submenu opens on hover");
    assert!(h.has("CycloneDX inventory (all devices)…"));
    // Escape closes the menus; then another menu of the bar.
    h.events.push(egui::Event::Key {
        key: egui::Key::Escape,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers: Default::default(),
    });
    h.step();
    h.step();
    assert!(!h.has("Quit"), "Escape closed the menu");
    h.click("Help");
    h.click("Keyboard shortcuts");
    assert!(h.app.shortcuts_open);
    assert!(
        !h.has("Documentation") || !h.has("About Network Scope"),
        "the menu closed"
    );
}

#[test]
fn removing_a_favorite_keeps_the_star_menu_open() {
    let mut h = Harness::new("main");
    h.click("Favorite addresses");
    h.click("Save current addresses");
    assert_eq!(h.app.saved.favorites, vec![h.app.targets.clone()]);
    assert!(
        !h.has("Save current addresses"),
        "choosing an entry closes the menu"
    );
    h.click("Favorite addresses");
    h.click("Remove");
    assert!(h.app.saved.favorites.is_empty());
    assert!(
        h.has("Save current addresses"),
        "the menu stays open after Remove"
    );
}

#[test]
fn full_audit_from_the_picker_asks_before_safe_mode_goes_off() {
    let mut h = Harness::new("main");
    h.click("Preset");
    h.click("Full audit");
    assert!(
        h.app.saved.settings.safe,
        "nothing changes before the answer"
    );
    assert!(h.has("Turn Safe Mode off?") || h.has("Turn Safe Mode off"));
    h.click("Turn Safe Mode off");
    assert!(!h.app.saved.settings.safe);
    assert!(preset_ui::matches(Preset::Full, &h.app.saved.settings));
}

#[test]
fn a_click_anywhere_in_a_row_shows_the_host_and_close_hides_it() {
    let mut h = Harness::new("main");
    // The host name cell, not the address.
    h.click("plc-line-1");
    assert_eq!(h.app.selected, ip("10.20.0.5"));
    assert!(h.has("Close"), "the details are docked on the right");
    assert!(h.has("Findings (3)"), "with the host's findings");
    h.click("Close");
    assert_eq!(h.app.selected, None);
    // A right click in the middle of a row opens the host menu.
    h.right_click("historian");
    assert!(egui::Popup::is_any_open(&h.ctx));
    assert!(h.has("Ping in a terminal"));
}

#[test]
fn the_sidebar_opens_pages_and_a_finding_shows_its_host_beside_the_page() {
    let mut h = Harness::new("main");
    // The sidebar entry carries its count ("Findings 10").
    h.click("Findings");
    assert_eq!(h.app.view, MainView::Findings);
    h.click("Telnet exposes credentials in clear text");
    assert_eq!(h.app.selected, ip("10.20.0.5"));
    assert_eq!(h.app.view, MainView::Findings, "the page stays");
    assert!(h.has("Close"));
    h.click("Inventory");
    assert_eq!(h.app.view, MainView::Inventory);
    // The keyboard way: focus an entry and press Enter.
    h.focus_and_press("Network map", egui::Key::Enter);
    assert_eq!(h.app.view, MainView::Map);
}

#[test]
fn devices_are_the_hosts_page_by_device() {
    let mut h = Harness::new("main");
    assert!(!h.has("Devices"), "no sidebar entry of their own");
    // The Start button is read as "Start", not with the triangle of its label.
    assert!(h.find("Start").iter().any(|w| w.role == "Button"));
    h.click("By device");
    assert_eq!(h.app.view, MainView::Devices);
    assert!(h.has("Unknown devices…"));
    // Ctrl+F filters the devices instead of going back to the addresses.
    h.app.run_command(&h.ctx.clone(), palette::Cmd::Search);
    assert_eq!(h.app.view, MainView::Devices);
    assert!(h.app.devices_view.focus_query);
    h.step();
    assert!(
        !h.app.devices_view.focus_query,
        "the filter box took the focus"
    );
    h.click("By address");
    assert_eq!(h.app.view, MainView::Hosts);
}

#[test]
fn a_rule_in_the_grouped_findings_lists_its_hosts() {
    let mut h = Harness::new("findings-grouped");
    assert_eq!(h.app.view, MainView::Findings);
    h.click("Industrial protocol port is reachable from the scanner");
    assert!(h.app.saved.group_findings, "the saved choice stays");
    assert!(
        h.app.findings_view.query.is_empty(),
        "the text filter stays"
    );
    let id = h.app.findings_view.rule.clone().expect("one rule shown");
    h.step();
    assert!(
        h.app.findings_view.rows.len() >= 5
            && h.app
                .findings_view
                .rows
                .iter()
                .all(|&i| h.app.findings.value[i].id == id),
        "only the hosts of that rule"
    );
    h.click("Show all findings");
    assert_eq!(h.app.findings_view.rule, None);
    assert!(h.has("Group by finding"), "back to the grouped view");
    // A rule that is shown and then has no findings any more (a new scan) does not leave an
    // empty list without a way back.
    h.click("Industrial protocol port is reachable from the scanner");
    assert!(h.app.findings_view.rule.is_some());
    h.app.findings_view.rule = Some("a-rule-of-an-earlier-scan".into());
    h.step();
    assert_eq!(h.app.findings_view.rule, None);
    assert!(!h.app.findings_view.rows.is_empty());
    assert!(h.has("Group by finding"));
}

#[test]
fn a_message_can_be_dismissed_and_ctrl_f_filters_the_findings() {
    let mut h = Harness::new("findings");
    h.app.error = "Export failed: disk full".into();
    h.step();
    h.click("Dismiss the message");
    assert!(h.app.error.is_empty());
    // Ctrl+F stays on the page and takes its filter box.
    h.app.run_command(&h.ctx.clone(), palette::Cmd::Search);
    assert_eq!(h.app.view, MainView::Findings);
    assert!(h.app.findings_view.focus_query);
    // A dropped file the app cannot read is named, and nothing else happens.
    h.app.open_dropped("notes.docx".into(), &h.ctx.clone());
    assert!(h.app.error.contains("notes.docx"), "{}", h.app.error);
    assert_eq!(h.app.view, MainView::Findings);
}

#[test]
fn the_addresses_and_the_sort_are_remembered_but_not_a_huge_list() {
    let mut h = Harness::new("main");
    h.app.targets = "10.9.0.0/24".into();
    (h.app.sort_column, h.app.sort_reverse) = (4, true);
    h.app.remember_view();
    assert_eq!(h.app.saved.targets, "10.9.0.0/24");
    assert_eq!(h.app.saved.host_sort, (4, true));
    // An imported list of thousands of addresses is not written into the preferences.
    h.app.targets = "10.0.0.1 ".repeat(MAX_SAVED_TARGETS);
    h.app.remember_view();
    assert_eq!(h.app.saved.targets, "10.9.0.0/24");
}

#[test]
fn a_finding_and_a_device_are_reached_with_the_keyboard() {
    let mut h = Harness::new("findings");
    // The address of a finding's row is a control: Tab reaches it, Enter opens the host.
    h.focus_and_press("10.20.0.5:23", egui::Key::Enter);
    assert_eq!(h.app.selected, "10.20.0.5".parse().ok());
    let mut h = Harness::new("devices");
    h.focus_and_press("10.20.0.60", egui::Key::Enter);
    assert_eq!(h.app.selected, "10.20.0.60".parse().ok());
}

#[test]
fn a_device_seen_only_in_passive_traffic_has_details() {
    let mut h = Harness::new("devices");
    h.app.observations.push(passive::Observation {
        protocol: "mDNS".into(),
        mac: "02:AA:BB:00:00:99".into(),
        ip: "10.20.0.200".parse().ok(),
        fields: [("name".to_string(), "tablet-lobby".to_string())].into(),
    });
    h.app.data_changed();
    h.step();
    h.click("10.20.0.200");
    assert_eq!(h.app.selected, None, "no scanned host to show");
    assert!(h.app.selected_device.is_some());
    assert!(h.has("Device details ·"), "the panel is open");
    assert!(h.has("MAC: 02:AA:BB:00:00:99"));
    // A scanned host chosen afterwards takes the panel.
    h.click("10.20.0.60");
    assert_eq!(h.app.selected, "10.20.0.60".parse().ok());
    h.step();
    assert_eq!(h.app.selected_device, None);
}

#[test]
fn shift_marks_hosts_and_the_menu_of_one_copies_them_all() {
    let mut h = Harness::new("main");
    let ip = |h: &Harness, row: usize| h.app.results[h.app.rows[row]].ip;
    // A starred host shows a star before its address.
    let name = |h: &Harness, row: usize| {
        let ip = ip(h, row).to_string();
        if h.has(&ip) { ip } else { format!("★ {ip}") }
    };
    let (first, third) = (name(&h, 0), name(&h, 2));
    h.click(&first);
    assert_eq!(h.app.selected, Some(ip(&h, 0)));
    h.hold(egui::Modifiers::SHIFT);
    h.click(&third);
    h.hold(Default::default());
    assert_eq!(
        h.app.selected,
        Some(ip(&h, 0)),
        "the details stay where they were"
    );
    for row in 0..3 {
        assert!(h.app.marked.has(&ip(&h, row)), "row {row}");
    }
    assert!(!h.app.marked.has(&ip(&h, 3)));
    // A click that lets go of Shift in the frame of the release (a remote-control tool, a
    // very quick hand) still counts as a Shift+click.
    let fourth = h.one(&name(&h, 3)).center();
    h.events.push(egui::Event::PointerMoved(fourth));
    h.step();
    let button = |pressed| egui::Event::PointerButton {
        pos: fourth,
        button: egui::PointerButton::Primary,
        pressed,
        modifiers: egui::Modifiers::SHIFT,
    };
    let quick = [
        egui::Event::ModifiersChanged(egui::Modifiers::SHIFT),
        button(true),
        button(false),
        egui::Event::ModifiersChanged(Default::default()),
    ];
    h.events.extend(quick);
    h.step();
    h.step();
    assert!(
        h.app.marked.has(&ip(&h, 3)),
        "the fourth row joined the range"
    );
    h.right_click(&third);
    assert!(h.has("Copy 4 addresses") && h.has("Copy 4 rows"));
    // The keyboard: Shift with an arrow key marks the rows it passes.
    let mut h = Harness::new("main");
    h.click(&name(&h, 1));
    let down = |modifiers| egui::Event::Key {
        key: egui::Key::ArrowDown,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers,
    };
    h.hold(egui::Modifiers::SHIFT);
    for _ in 0..2 {
        h.events.push(down(egui::Modifiers::SHIFT));
        h.step();
    }
    h.hold(Default::default());
    assert_eq!(
        h.app.selected,
        Some(ip(&h, 3)),
        "the details follow the arrows"
    );
    assert!((1..=3).all(|row| h.app.marked.has(&ip(&h, row))) && !h.app.marked.has(&ip(&h, 0)));
    h.events.push(down(Default::default()));
    h.step();
    assert!(
        !h.app.marked.has(&ip(&h, 3)),
        "an arrow without Shift starts over"
    );
    assert!(h.has("Copy IP address"), "the host's own menu follows");
    // The findings and the devices mark the same way.
    let mut h = Harness::new("findings");
    h.click("10.20.0.5:23");
    h.hold(egui::Modifiers::COMMAND);
    let address = "10.20.0.55:502";
    let other = (h.app.findings.value.iter())
        .position(|f| tables::host_port(f) == address)
        .unwrap();
    h.click(address);
    h.hold(Default::default());
    assert!(h.app.findings_view.marks.has(&other));
    h.right_click(address);
    assert!(h.has("Copy 2 rows") && h.has("Copy finding"));
}

#[test]
fn a_dragged_column_width_is_used_again_and_the_default_ones_are_not_kept() {
    for state in ["main", "findings", "devices", "ot"] {
        let h = Harness::new(state);
        // Only a column that grows to fit its text is wider than its default by itself.
        let kept = &h.app.saved.column_widths;
        assert!(
            kept.keys().all(|k| k == "findings.severity"),
            "{state}: {kept:?}"
        );
    }
    let mut saved = Saved::default();
    saved.column_widths.insert("findings.host".into(), 222.0);
    saved.column_widths.insert("hosts.ping".into(), 91.0);
    // The table reports the width it has: a width that was not applied would be gone here.
    let h = Harness::start("findings", SIZE, saved.clone());
    assert_eq!(h.app.saved.column_widths.get("findings.host"), Some(&222.0));
    let h = Harness::start("main", SIZE, saved);
    assert_eq!(h.app.saved.column_widths.get("hosts.ping"), Some(&91.0));
}

#[test]
fn a_saved_scan_is_deleted_only_after_the_question() {
    let mut h = Harness::new("scan-details");
    assert_eq!(h.app.view, MainView::Inventory);
    // Two pickers for the comparison, and every row names its scan.
    assert!(h.has("Older scan (A)") && h.has("Newer scan (B)"));
    assert!(h.has("Open scan #9"));
    h.click("Delete scan #8");
    assert_eq!(h.app.delete_ask, Some(8));
    h.click("Keep");
    assert_eq!(h.app.delete_ask, None);
    h.click("Delete scan #8");
    h.click("Delete");
    assert_eq!(h.app.delete_ask, None, "answered");
}

#[test]
fn ticking_a_column_adds_it_and_keeps_the_menu_open() {
    let mut h = Harness::new("main");
    h.click("Hosts");
    h.click("Columns");
    h.click("Manufacturer");
    assert!(h.app.saved.host_columns.vendor);
    assert!(h.has("OS guess"), "the menu stays open");
    // Close the menu with a click elsewhere, then the new column header is in the table.
    h.press(egui::pos2(600.0, 650.0), egui::PointerButton::Primary);
    assert!(h.has("Manufacturer"), "the table has the column");
    assert!(h.has("Siemens AG"));
}

#[test]
fn the_timeline_is_a_panel_under_the_page_with_its_own_close() {
    let mut h = Harness::new("timeline");
    assert!(h.app.timeline.is_some());
    assert!(h.has("Copy as text"));
    // Two Close buttons: the host details (top right) and the timeline (lower down).
    let closes = h.find("Close");
    assert_eq!(closes.len(), 2, "details and timeline");
    let lower = closes
        .iter()
        .max_by(|a, b| a.rect.min.y.total_cmp(&b.rect.min.y))
        .unwrap()
        .rect
        .center();
    h.press(lower, egui::PointerButton::Primary);
    assert!(h.app.timeline.is_none(), "the timeline closed");
    assert!(h.app.selected.is_some(), "the host details stay");
}

#[test]
fn the_risk_column_sorts_the_worst_host_first() {
    let mut h = Harness::new("columns");
    let generation = h.app.findings.generation;
    assert!(generation.is_some(), "the sample findings are worked out");
    h.click("Risk");
    assert_eq!(h.app.sort_column, RISK_COLUMN);
    // 10.20.0.5 has the only high finding; hosts without findings come last.
    let first = h.app.rows[0];
    assert_eq!(
        h.app.results[first].ip,
        "10.20.0.5".parse::<IpAddr>().unwrap()
    );
    let last = *h.app.rows.last().unwrap();
    assert_eq!(h.app.results[last].hostname, "laptop-qa");
    // Sorting changed no data, so the findings were not worked out again.
    assert_eq!(h.app.findings.generation, Some(h.app.generation));
    // New data sorted in (a scan batch, a loaded scan) makes them out of date again: the
    // sample is small, so they are worked out anew for the order and then still hold.
    let worked_out = h.app.findings.generation;
    h.app.results[0].open.push(23);
    h.app.sort();
    assert_ne!(h.app.findings.generation, worked_out, "worked out again");
    assert_eq!(h.app.findings.generation, Some(h.app.generation));
}

#[test]
fn dragging_the_edge_of_the_details_makes_them_wider() {
    let mut h = Harness::new("main");
    h.click("plc-line-1");
    let title = "Host details · 10.20.0.5";
    let before = h.one(title).min.x;
    // The panel's edge is just left of its content.
    let edge = egui::pos2(before - 9.0, 400.0);
    h.events.push(egui::Event::PointerMoved(edge));
    h.step();
    h.events.push(egui::Event::PointerButton {
        pos: edge,
        button: egui::PointerButton::Primary,
        pressed: true,
        modifiers: Default::default(),
    });
    h.step();
    for dx in [20.0, 40.0, 60.0, 80.0] {
        h.events
            .push(egui::Event::PointerMoved(edge - egui::vec2(dx, 0.0)));
        h.step();
    }
    h.events.push(egui::Event::PointerButton {
        pos: edge - egui::vec2(80.0, 0.0),
        button: egui::PointerButton::Primary,
        pressed: false,
        modifiers: Default::default(),
    });
    h.step();
    h.step();
    let after = h.one(title).min.x;
    assert!(after < before - 40.0, "{before} -> {after}");
}

#[test]
fn the_findings_table_scrolls_sideways() {
    // A window too narrow for all columns.
    let mut h = Harness::sized("findings", egui::vec2(900.0, 720.0));
    let before = h
        .find("Learn more")
        .iter()
        .map(|w| w.rect.min.x)
        .fold(f32::MAX, f32::min);
    let over = h.one("Telnet exposes credentials in clear text").center();
    h.events.push(egui::Event::PointerMoved(over));
    h.step();
    for _ in 0..5 {
        h.events.push(egui::Event::MouseWheel {
            unit: egui::MouseWheelUnit::Point,
            delta: egui::vec2(-60.0, 0.0),
            modifiers: Default::default(),
            phase: egui::TouchPhase::Move,
            source: egui::MouseWheelSource::Wheel,
        });
        h.step();
    }
    h.step();
    let after = h
        .find("Learn more")
        .iter()
        .map(|w| w.rect.min.x)
        .fold(f32::MAX, f32::min);
    assert!(after < before - 10.0, "{before} -> {after}");
}

#[test]
fn the_action_buttons_stay_after_one_is_used() {
    let mut h = Harness::new("main");
    h.click("plc-line-1");
    assert!(h.has("Actions") && h.has("Wake-on-LAN…"));
    let panel = h.one("Host details · 10.20.0.5").min.x;
    // Copy is the one action that starts no program and sends nothing.
    h.click("Copy IP address");
    assert!(
        h.has("Copy IP address") && h.has("Wake-on-LAN…"),
        "the buttons are still there"
    );
    assert_eq!(
        h.one("Host details · 10.20.0.5").min.x,
        panel,
        "the panel kept its width"
    );
    assert_eq!(h.app.selected, ip("10.20.0.5"));
}

#[test]
fn opening_a_saved_scan_shows_the_hosts_page() {
    let mut h = Harness::new("scan-details");
    assert_eq!(h.app.view, MainView::Inventory);
    // The first "Open" of the list (screenshot runs never read the inventory).
    let first = h
        .find("Open")
        .into_iter()
        .map(|w| w.rect)
        .min_by(|a, b| a.min.y.total_cmp(&b.min.y))
        .expect("an Open button");
    h.press(first.center(), egui::PointerButton::Primary);
    assert_eq!(h.app.view, MainView::Hosts);
}

#[test]
fn the_host_details_list_the_packages_of_a_matching_firmware_sbom() {
    let mut h = Harness::new("main");
    let plc = ip("10.20.0.5").unwrap();
    let host = h.app.results.iter_mut().find(|x| x.ip == plc).unwrap();
    for (k, v) in [
        ("S7.order_code", "6ES7 515-2AM02-0AB0"),
        ("S7.firmware", "V2.9.4"),
    ] {
        host.identity.insert(k.into(), v.into());
    }
    let file = r#"{"bomFormat":"CycloneDX","specVersion":"1.6",
      "metadata":{"component":{"type":"firmware","name":"6ES7 515-2AM02-0AB0","version":"V2.9.4",
        "manufacturer":{"name":"Siemens"}}},
      "components":[
        {"type":"library","name":"openssl","version":"3.0.13","purl":"pkg:generic/openssl@3.0.13"},
        {"type":"file","name":"/etc/passwd"}]}"#;
    let mut sbom = crate::sbom::parse(file.as_bytes(), &Default::default())
        .unwrap()
        .sbom;
    sbom.source = "plc.cdx.json".into();
    let library = std::sync::Arc::new(crate::sbom::Library {
        version: 1,
        imported_at: 0,
        sboms: vec![sbom],
    });
    let found = crate::sbom::for_hosts(&library, &h.app.results, &h.app.observations);
    let generation = h.app.generation;
    h.app.firmware_sboms.set(generation, (library, found));
    h.click("plc-line-1");
    assert!(h.has("Firmware (SBOM) (1)"), "the section is there, closed");
    assert!(!h.has("openssl 3.0.13"));
    h.click("Firmware (SBOM) (1)");
    assert!(h.has("6ES7 515-2AM02-0AB0 V2.9.4"));
    assert!(h.has("openssl 3.0.13"));
    assert!(h.has("1 single files not listed"));
}
