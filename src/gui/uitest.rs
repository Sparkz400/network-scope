// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Tests that use the whole window the way a person does: they render real frames of the app
//! with the screenshot sample data, find a widget by its accessible name (what a screen reader
//! reads) and click it with pointer events. Nothing is scanned, saved or read from disk.
use super::*;
use crate::presets::Preset;
use crate::snmp::SnmpRef;
use crate::trace::TraceMethod;
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
    /// What the app gave its background worker: nothing runs, nothing reads the inventory.
    jobs: mpsc::Receiver<Job>,
    /// Answers in the worker's place (see `answer`).
    done: mpsc::Sender<Done>,
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
        // The test holds both ends of the worker's channels.
        let (job_tx, jobs) = mpsc::channel();
        let (done, done_rx) = mpsc::channel();
        app.worker = Worker {
            jobs: Some(job_tx),
            done: done_rx,
            thread: None,
        };
        let mut h = Self {
            ctx,
            app,
            frame: eframe::Frame::_new_kittest(),
            events: vec![],
            widgets: vec![],
            size,
            held: Default::default(),
            jobs,
            done,
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

    /// Whether any text on screen contains this (a status line, a progress bar).
    fn shows(&self, part: &str) -> bool {
        self.widgets.iter().any(|w| w.name.contains(part))
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

    /// Frames until a section has opened or closed and a scroll has ended (their animations).
    fn settle(&mut self) {
        for _ in 0..10 {
            self.step();
        }
    }

    /// Presses and releases a key (to whatever has the focus).
    fn key(&mut self, key: egui::Key) {
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
    }

    /// The text field on the right of this label (the label names it for a screen reader,
    /// but the field's own node carries its text).
    fn field(&self, label: &str) -> egui::Pos2 {
        let label = self.one(label);
        let row = label.y_range().expand(4.0);
        (self.widgets.iter())
            .filter(|w| w.role == "TextInput" && w.rect.min.x >= label.max.x)
            .filter(|w| row.contains(w.rect.center().y))
            .min_by(|a, b| a.rect.min.x.total_cmp(&b.rect.min.x))
            .unwrap_or_else(|| panic!("no field next to {label:?}"))
            .rect
            .center()
    }

    /// Opens the drop-down that shows this choice now.
    fn open_combo(&mut self, shown: &str) {
        let combo = (self.widgets.iter())
            .find(|w| w.role == "ComboBox" && w.name == shown)
            .unwrap_or_else(|| panic!("no drop-down showing {shown:?}"))
            .rect
            .center();
        self.press(combo, egui::PointerButton::Primary);
    }

    /// Clicks into the text field next to this label and types the text at its end.
    fn type_into(&mut self, label: &str, text: &str) {
        let pos = self.field(label);
        self.press(pos, egui::PointerButton::Primary);
        self.key(egui::Key::End);
        self.events.push(egui::Event::Text(text.into()));
        self.step();
        self.step();
    }

    /// The next job the app gave its worker.
    fn job(&mut self) -> Option<Job> {
        self.jobs.try_recv().ok()
    }

    /// The worker's answer, as it arrives in the next frame.
    fn answer(&mut self, done: Done) {
        self.done.send(done).unwrap();
        self.step();
        self.step();
    }
}

/// A complete scan of 10.20.0.0/24 as the inventory hands it back.
fn saved_scan(hosts: Vec<scan::Host>) -> store::Snapshot {
    store::Snapshot {
        sent: vec![],
        targets: "10.20.0.0/24".into(),
        complete: true,
        settings: Default::default(),
        hosts,
        observations: vec![],
        notes: Default::default(),
    }
}

/// A scan the test runs by hand: it sends nothing, the test sends its events.
fn fake_scan(total: usize) -> (scan::Running, mpsc::Sender<scan::Event>) {
    let (tx, receiver) = mpsc::channel();
    let run = scan::Running {
        receiver,
        cancel: Default::default(),
        pause: Default::default(),
        total,
        started: Instant::now(),
        sent: Default::default(),
    };
    (run, tx)
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

#[test]
fn a_running_scan_lists_hosts_as_they_answer_and_is_saved_when_done() {
    let mut h = Harness::new("hosts-empty");
    assert!(h.app.results.is_empty());
    h.app.scan_settings.ipv6_discover = false;
    let (run, events) = fake_scan(3);
    h.app.run = Some(run);
    h.step();
    assert!(h.shows("Scanning · 0 / 3"), "the progress bar");
    assert!(!h.app.cmd_enabled(palette::Cmd::StartScan));
    // A host that answered shows at once, and its final result takes its row.
    let early = demo::demo_host("10.20.0.5", &[], &[]);
    events.send(scan::Event::Partial(early)).unwrap();
    h.step();
    assert_eq!(h.app.results.len(), 1);
    assert!(h.has("10.20.0.5"));
    let mut done = demo::demo_host("10.20.0.5", &[502], &[]);
    done.hostname = "plc-line-1".into();
    events.send(scan::Event::Host(done)).unwrap();
    events
        .send(scan::Event::Host(demo::demo_host("10.20.0.6", &[], &[])))
        .unwrap();
    events
        .send(scan::Event::Error("10.20.0.7: no route".into()))
        .unwrap();
    h.step();
    assert_eq!(h.app.results.len(), 2, "replaced, not added");
    assert!(h.has("plc-line-1"));
    assert_eq!((h.app.responding, h.app.with_open), (2, 1));
    assert!(h.shows("2 responding · 1 with open ports"));
    assert_eq!(h.app.error, "10.20.0.7: no route");
    // Pause and Stop work on the running scan.
    h.app.run_command(&h.ctx.clone(), palette::Cmd::PauseScan);
    h.step();
    assert!(h.shows("Paused · 2 / 3"));
    h.app.run_command(&h.ctx.clone(), palette::Cmd::StopScan);
    h.step();
    assert!(h.shows("Stopping…"));
    assert!(!h.app.cmd_enabled(palette::Cmd::StopScan), "stopped once");
    events.send(scan::Event::Done).unwrap();
    h.step();
    assert!(h.app.run.is_none());
    assert!(
        h.app.status.starts_with("Stopped · 2 of 3 addresses"),
        "{}",
        h.app.status
    );
    assert!(!h.app.scan_complete, "a stopped scan is partial");
    // The result goes to the inventory, and the saved number is shown.
    match h.job() {
        Some(Job::Save(snapshot, "scan")) => {
            assert_eq!(snapshot.hosts.len(), 2);
            assert!(!snapshot.complete);
        }
        _ => panic!("the scan is saved"),
    }
    assert!(h.shows("Saving to inventory…"));
    h.answer(Done::Saved("scan", 0, Ok(12)));
    assert_eq!(h.app.loaded_scan, Some(12));
    assert!(h.app.status.ends_with("saved #12"), "{}", h.app.status);
    assert!(!h.shows("Saving to inventory…"));
}

#[test]
fn a_scan_that_ends_by_itself_is_complete_and_a_lost_scan_is_not() {
    let mut h = Harness::new("hosts-empty");
    h.app.scan_settings.ipv6_discover = false;
    let (run, events) = fake_scan(1);
    h.app.run = Some(run);
    events
        .send(scan::Event::Host(demo::demo_host("10.0.0.1", &[22], &[])))
        .unwrap();
    events.send(scan::Event::Done).unwrap();
    h.step();
    assert!(
        h.app.status.starts_with("Complete · 1 of 1"),
        "{}",
        h.app.status
    );
    assert!(h.app.scan_complete);
    assert!(matches!(h.job(), Some(Job::Save(s, _)) if s.complete));
    // The scan thread went away without a word: what came is kept, but it is not complete.
    let (run, events) = fake_scan(5);
    h.app.run = Some(run);
    drop(events);
    h.step();
    assert!(h.app.run.is_none());
    assert!(!h.app.scan_complete);
    assert!(matches!(h.job(), Some(Job::Save(s, _)) if !s.complete));
}

#[test]
fn closing_the_window_during_a_scan_asks_first() {
    let mut h = Harness::new("main");
    let (run, _events) = fake_scan(4);
    h.app.run = Some(run);
    h.app.quit_ask = true;
    h.step();
    h.step();
    assert!(h.has("Quit while a scan is running?"));
    h.click("Keep running");
    assert!(!h.app.quit_ask && !h.app.quit_ok);
    assert!(h.app.run.is_some(), "the scan goes on");
    h.app.quit_ask = true;
    h.step();
    h.step();
    h.key(egui::Key::Escape);
    h.step();
    assert!(!h.app.quit_ask, "Escape is Keep running");
    h.app.quit_ask = true;
    h.step();
    h.step();
    h.click("Stop and quit");
    assert!(h.app.quit_ok);
    // Settings wait for the scan to end.
    h.app.run_command(&h.ctx.clone(), palette::Cmd::Settings);
    h.step();
    h.step();
    assert!(h.has("Settings can be changed after this scan finishes."));
    // A question left open when the scan ended goes away by itself.
    h.app.run = None;
    h.app.quit_ask = true;
    h.step();
    assert!(!h.app.quit_ask);
}

#[test]
fn the_answers_of_the_background_worker_reach_the_window() {
    let mut h = Harness::new("main");
    h.answer(Done::Saved("capture", 5, Ok(3)));
    assert_eq!(h.app.status, "5 observations · saved capture #3");
    h.answer(Done::Saved("ot", 2, Ok(4)));
    assert_eq!(
        h.app.status,
        "OT passive: 2 observations · saved capture #4"
    );
    h.answer(Done::Saved("scan", 0, Err("disk full".into())));
    assert_eq!(h.app.error, "Inventory could not be saved: disk full");
    let entry = |id| store::Entry {
        id,
        timestamp: 1_790_000_000,
        targets: "10.20.0.0/24".into(),
        complete: true,
        hosts: 12,
    };
    h.answer(Done::Listed(Ok(vec![entry(8), entry(9)])));
    assert_eq!(h.app.history.len(), 2);
    h.answer(Done::Listed(Err("locked".into())));
    assert_eq!(h.app.error, "locked");
    // A deleted scan is picked nowhere any more.
    (h.app.compare_a, h.app.compare_b, h.app.loaded_scan) = (Some(8), Some(9), Some(8));
    h.answer(Done::Deleted(8, Ok(vec![entry(9)])));
    assert_eq!(h.app.status, "Deleted scan #8");
    assert_eq!(
        (h.app.compare_a, h.app.compare_b, h.app.loaded_scan),
        (None, Some(9), None)
    );
    h.answer(Done::Deleted(9, Err("busy".into())));
    assert_eq!(h.app.error, "Scan #9 was not deleted: busy");
    assert_eq!(h.app.history.len(), 1);
    h.answer(Done::Diffed(Ok(vec![])));
    assert_eq!(h.app.changes, ["No observed changes."]);
    h.answer(Done::Diffed(Ok(vec!["10.20.0.9 is new".into()])));
    assert_eq!(h.app.changes, ["10.20.0.9 is new"]);
    h.answer(Done::Diffed(Err("scan #3 is gone".into())));
    assert_eq!(h.app.error, "scan #3 is gone");
    h.answer(Done::Loaded(3, Err("scan #3 is gone".into())));
    assert!(!h.app.busy.loading);
    // An address list fills the Addresses field; an empty one says so.
    h.answer(Done::Read(Ok("# plant\n10.9.0.1\n10.9.0.2\n".into())));
    assert_eq!(h.app.targets, "10.9.0.1 10.9.0.2");
    h.answer(Done::Read(Ok("# nothing here\n".into())));
    assert_eq!(h.app.error, "The list has no addresses.");
    assert_eq!(h.app.targets, "10.9.0.1 10.9.0.2");
    h.answer(Done::Read(Err("list.txt: not found".into())));
    assert_eq!(h.app.error, "list.txt: not found");
    h.answer(Done::PrefsWritten(Err("read-only".into())));
    assert_eq!(h.app.error, "Preferences could not be saved: read-only");
    h.answer(Done::Exported("report.html".into(), Ok(())));
    assert_eq!(h.app.status, "Saved report.html");
    h.answer(Done::Exported("report.html".into(), Err("denied".into())));
    assert_eq!(h.app.error, "Export failed: denied");
    h.answer(Done::FeedImported(FeedKind::Vex, Err("not CSAF".into())));
    assert_eq!(h.app.error, "not CSAF");
    h.answer(Done::DraftWritten(Ok((
        "probes.json".into(),
        "list".into(),
    ))));
    assert_eq!(h.app.status, "Saved probes.json");
    assert!(h.app.workbench.written.is_some());
    // The error line on screen is the last one.
    assert!(h.shows("Export failed: denied") || h.shows("not CSAF"));
}

#[test]
fn an_address_list_is_ignored_while_a_scan_runs() {
    let mut h = Harness::new("main");
    let (run, _events) = fake_scan(4);
    h.app.run = Some(run);
    let before = h.app.targets.clone();
    h.answer(Done::Read(Ok("10.9.0.1".into())));
    assert_eq!(h.app.targets, before);
    assert_eq!(h.app.error, "Address list ignored: a scan is running.");
    // A saved scan is not opened over the running one either.
    h.answer(Done::Loaded(7, Ok(Box::new(saved_scan(vec![])))));
    assert!(
        h.app.error.contains("Inventory #7 was not opened"),
        "{}",
        h.app.error
    );
}

#[test]
fn a_search_hit_shows_the_host_and_one_from_another_scan_opens_that_scan() {
    let mut h = Harness::new("palette");
    h.app.loaded_scan = Some(9);
    let hits = match &h.app.palette.results {
        Some(Ok(r)) => r.hits.clone(),
        _ => panic!("sample hits"),
    };
    assert!(h.has("Seen in the saved scans (newest first)"));
    // The scan on screen: the host is shown straight away.
    h.click(&palette::hit_text(&hits[0]));
    assert!(!h.app.palette.open);
    assert_eq!(h.app.view, MainView::Hosts);
    assert_eq!(h.app.selected, ip("10.20.0.5"));
    assert!(h.job().is_none(), "nothing to load");
    // Another scan is opened first, then the host is shown.
    h.app.palette.open = true;
    h.step();
    h.step();
    h.click(&palette::hit_text(&hits[1]));
    assert!(matches!(h.job(), Some(Job::Load(7))));
    assert!(h.shows("Opening inventory…"));
    let snapshot = saved_scan(vec![
        demo::demo_host("10.20.0.5", &[23], &[]),
        demo::demo_host("10.20.0.6", &[], &[]),
    ]);
    h.app.selected = None;
    h.answer(Done::Loaded(7, Ok(Box::new(snapshot))));
    assert_eq!(h.app.status, "Loaded inventory #7");
    assert_eq!(h.app.loaded_scan, Some(7));
    assert_eq!(h.app.results.len(), 2);
    assert_eq!(h.app.selected, ip("10.20.0.5"), "the host of the hit");
    // While a scan runs, a hit of another scan is not opened.
    let (run, _events) = fake_scan(1);
    h.app.run = Some(run);
    h.app.palette.open = true;
    h.step();
    h.step();
    h.click(&palette::hit_text(&hits[2]));
    assert!(h.job().is_none());
    assert_eq!(
        h.app.error,
        "The scan cannot be opened while a scan or capture is running."
    );
}

#[test]
fn the_palette_is_used_with_the_keyboard() {
    let mut h = Harness::new("main");
    h.app.run_command(&h.ctx.clone(), palette::Cmd::Palette);
    h.step();
    h.step();
    assert!(h.app.palette.open);
    assert!(h.has("Up/Down choose · Enter runs · Esc closes"));
    // The box has the focus: typing filters the actions.
    h.events.push(egui::Event::Text("network map".into()));
    h.step();
    h.step();
    assert_eq!(h.app.palette.query, "network map");
    assert!(h.has("Open the network map"));
    h.key(egui::Key::ArrowDown);
    h.key(egui::Key::ArrowUp);
    assert_eq!(h.app.palette.selected, 0);
    h.key(egui::Key::Enter);
    h.step();
    assert!(!h.app.palette.open);
    assert_eq!(h.app.view, MainView::Map);
    // Nothing matches: it says so. Escape closes; the shortcut toggles.
    h.app.open_palette();
    h.app.palette.query = "qqqqqq".into();
    h.step();
    assert!(h.has("Nothing matches."));
    h.key(egui::Key::Escape);
    assert!(!h.app.palette.open);
    h.app.run_command(&h.ctx.clone(), palette::Cmd::Palette);
    h.app.run_command(&h.ctx.clone(), palette::Cmd::Palette);
    assert!(!h.app.palette.open, "the second press closes it");
}

#[test]
fn palette_commands_open_pages_windows_and_change_the_settings() {
    let mut h = Harness::new("main");
    let ctx = h.ctx.clone();
    for (cmd, view) in [
        (palette::Cmd::Overview, MainView::Home),
        (palette::Cmd::Findings, MainView::Findings),
        (palette::Cmd::Devices, MainView::Devices),
        (palette::Cmd::Passive, MainView::Passive),
        (palette::Cmd::Map, MainView::Map),
        (palette::Cmd::Inventory, MainView::Inventory),
        (palette::Cmd::Hosts, MainView::Hosts),
    ] {
        h.app.run_command(&ctx, cmd);
        h.step();
        assert_eq!(h.app.view, view, "{cmd:?}");
    }
    assert!(h.job().is_none(), "screenshot runs read no inventory");
    // Ctrl+F on the hosts page: its search box.
    h.app.run_command(&ctx, palette::Cmd::Search);
    assert!(h.app.focus_search);
    for (cmd, open) in [
        (palette::Cmd::About, "About Network Scope"),
        (palette::Cmd::Shortcuts, "Keyboard shortcuts"),
        (palette::Cmd::Schedule, "Settings"),
    ] {
        h.app.run_command(&ctx, cmd);
        h.step();
        h.step();
        assert!(h.has(open), "{cmd:?}");
    }
    assert!(h.has("Network Scope") && h.shows(env!("CARGO_PKG_VERSION")));
    assert!(h.has("Scheduled scans"), "the schedule section is shown");
    h.app.run_command(&ctx, palette::Cmd::DarkTheme);
    assert!(h.app.saved.dark && ctx.global_style().visuals.dark_mode);
    h.app.run_command(&ctx, palette::Cmd::LightTheme);
    assert!(!h.app.saved.dark && !ctx.global_style().visuals.dark_mode);
    h.app
        .run_command(&ctx, palette::Cmd::Language(i18n::Lang::German));
    assert_eq!(h.app.saved.language, "de");
    assert_eq!(tr!("Settings"), "Einstellungen");
    h.app
        .run_command(&ctx, palette::Cmd::Language(i18n::Lang::English));
    assert_eq!(tr!("Settings"), "Settings");
    // More thorough keeps Safe Mode; Faster asks first.
    h.app.run_command(&ctx, palette::Cmd::Thorough);
    let s = &h.app.saved.settings;
    assert!(s.safe && s.scan_nonresponders && s.probes == 3);
    assert_eq!(h.app.status, "More thorough settings applied");
    h.app.run_command(&ctx, palette::Cmd::Faster);
    h.step();
    h.step();
    assert!(h.has("Faster turns Safe Mode off."));
    h.key(egui::Key::Escape);
    assert!(h.app.unsafe_confirm.is_none());
    assert!(h.app.saved.settings.safe, "Escape keeps Safe Mode on");
    h.app.run_command(&ctx, palette::Cmd::Faster);
    h.step();
    h.step();
    h.click("Turn Safe Mode off");
    let s = &h.app.saved.settings;
    assert!(!s.safe && s.workers == 1024 && s.tcp_only);
    // Without Safe Mode, Faster needs no question.
    h.app.saved.settings.workers = 8;
    h.app.run_command(&ctx, palette::Cmd::Faster);
    assert!(h.app.unsafe_confirm.is_none());
    assert_eq!(h.app.saved.settings.workers, 1024);
    // Clear empties the window, not the inventory.
    h.app.run_command(&ctx, palette::Cmd::ClearResults);
    h.step();
    assert!(h.app.results.is_empty());
    assert_eq!(h.app.status, "Ready to scan");
    assert!(h.app.rows.is_empty());
    assert!(h.job().is_none());
}

#[test]
fn settings_cannot_change_while_a_scan_runs() {
    let mut h = Harness::new("main");
    let (run, _events) = fake_scan(4);
    h.app.run = Some(run);
    let ctx = h.ctx.clone();
    let before = h.app.saved.settings.clone();
    // The commands are greyed out; called anyway they refuse.
    assert!(!h.app.cmd_enabled(palette::Cmd::Thorough));
    h.app.apply_thorough();
    assert_eq!(
        h.app.error,
        "Settings can be changed after this scan finishes."
    );
    h.app.saved.settings.safe = false;
    h.app.run_command(&ctx, palette::Cmd::Faster);
    h.app.choose_faster();
    assert_eq!(h.app.saved.settings.workers, before.workers);
}

#[test]
fn a_start_that_cannot_scan_says_why_and_sends_nothing() {
    let mut h = Harness::new("main");
    // The passive preset points to the listener.
    h.app.saved.preset = preset_ui::PLANT.into();
    h.app.start();
    assert!(h.app.run.is_none());
    assert!(
        h.app.error.contains("Plant preset is passive"),
        "{}",
        h.app.error
    );
    assert_eq!(h.app.view, MainView::Passive);
    h.app.saved.preset.clear();
    // Addresses that are not addresses.
    h.app.targets = "the plant".into();
    h.app.start();
    assert!(h.app.run.is_none());
    assert!(!h.app.error.is_empty());
    // A scan being opened from the inventory.
    h.app.targets = "10.20.0.0/24".into();
    h.app.busy.loading = true;
    h.app.start();
    assert_eq!(
        h.app.error,
        "Wait until the inventory scan has been opened."
    );
    assert!(h.app.run.is_none());
}

#[test]
fn the_scope_question_does_not_apply_to_edited_targets_and_cancel_sends_nothing() {
    let mut h = Harness::new("main");
    h.app.scope_confirm = Some(("8.8.8.0/24".into(), "8.8.8.0/24 is public.".into()));
    h.step();
    h.step();
    assert!(h.has("Confirm scan targets") && h.has("8.8.8.0/24 is public."));
    h.click("Cancel");
    assert!(h.app.scope_confirm.is_none());
    assert!(h.app.run.is_none());
    // The Addresses field shows other targets now than the question was about.
    h.app.scope_confirm = Some(("8.8.8.0/24".into(), "8.8.8.0/24 is public.".into()));
    h.step();
    h.step();
    h.click("Scan anyway");
    assert!(h.app.scope_confirm.is_none());
    assert!(h.app.run.is_none());
    assert_eq!(h.app.status, "Targets changed; press Start again");
}

#[test]
fn an_available_update_is_shown_until_dismissed() {
    let release = update::parse_latest(br#"{"tag_name":"v99.0.0"}"#).unwrap();
    let outcome = update::compare(env!("CARGO_PKG_VERSION"), release).unwrap();
    let mut h = Harness::new("main");
    let (tx, rx) = mpsc::channel();
    h.app.update_check = Some(rx);
    h.step();
    assert!(h.app.update_check.is_some(), "no answer yet");
    tx.send(Ok(outcome)).unwrap();
    h.step();
    h.step();
    assert!(h.app.update_check.is_none());
    assert!(h.has("Version 99.0.0 is available"));
    h.click("How to verify…");
    assert!(h.has("Update available"));
    assert!(h.shows("Network Scope never downloads or installs updates."));
    h.click("Copy text");
    assert!(h.has("Update available"), "copying keeps the window");
    // The tall window can cover the status bar; the keyboard reaches the button anyway.
    h.focus_and_press("Dismiss", egui::Key::Enter);
    assert!(h.app.update_notice.is_none() && !h.app.update_open);
    assert!(!h.has("Update available") && !h.has("Version 99.0.0 is available"));
    // A failed check is one line in the status bar; a lost check is forgotten.
    let (tx, rx) = mpsc::channel();
    h.app.update_check = Some(rx);
    tx.send(Err("offline".into())).unwrap();
    h.step();
    assert_eq!(h.app.status, "Update check failed: offline");
    let (tx, rx) = mpsc::channel::<Result<update::Outcome, String>>();
    h.app.update_check = Some(rx);
    drop(tx);
    h.step();
    assert!(h.app.update_check.is_none());
}

#[test]
fn scan_my_network_asks_before_large_networks_and_cancel_scans_nothing() {
    let mut h = Harness::new("quick");
    assert!(h.has("Scan my network"));
    assert!(
        h.shows("192.168.178.0/24 · Ethernet"),
        "a network it would scan"
    );
    assert!(h.shows("is large"), "the /16 needs a yes");
    h.click("Scan the large networks too (this takes a long time)");
    assert!(h.app.quick.include_large);
    h.click("Left out");
    assert!(h.shows("loopback"), "with the reason");
    h.click("Cancel");
    assert!(!h.app.quick.dialog);
    assert!(h.app.run.is_none() && h.job().is_none(), "nothing scanned");
}

#[test]
fn scan_my_network_looks_for_the_networks_first() {
    let mut h = Harness::new("main");
    let net = |ip: &str, prefix| crate::localnets::LocalNet {
        interface: "Ethernet".into(),
        ip: ip.parse().unwrap(),
        prefix,
    };
    h.app
        .run_command(&h.ctx.clone(), palette::Cmd::ScanMyNetwork);
    assert!(matches!(h.job(), Some(Job::Networks)));
    assert!(h.app.quick.pending);
    assert_eq!(h.app.status, "Looking for your networks…");
    h.step();
    assert!(h.shows("Looking for your networks…"));
    // A second press while it looks does nothing more.
    h.app.scan_my_network();
    assert!(h.job().is_none());
    // Only a large network: the user decides.
    h.answer(Done::Networks(Ok(vec![net("10.20.0.31", 16)])));
    assert!(h.app.quick.dialog && !h.app.quick.pending);
    assert!(h.app.run.is_none());
    assert!(h.shows("10.20.0.0/16 on Ethernet is large"));
    h.click("Cancel");
    // No private network at all.
    h.app.scan_my_network();
    assert!(matches!(h.job(), Some(Job::Networks)));
    h.answer(Done::Networks(Ok(vec![net("8.8.4.4", 24)])));
    assert_eq!(
        h.app.error,
        "No private network was found on this computer."
    );
    assert!(h.has("No private network was found on this computer."));
    h.click("Cancel");
    // The detection failed.
    h.app.scan_my_network();
    assert!(matches!(h.job(), Some(Job::Networks)));
    h.answer(Done::Networks(Err("no adapters".into())));
    assert_eq!(h.app.error, "no adapters");
    assert!(!h.app.quick.pending);
    // An answer nobody waits for only updates the list.
    h.answer(Done::Networks(Ok(vec![net("192.168.1.5", 24)])));
    assert!(!h.app.quick.dialog && h.app.run.is_none());
    assert_eq!(h.app.local_nets.len(), 1);
    // Not while a scan runs.
    let (run, _events) = fake_scan(1);
    h.app.run = Some(run);
    h.app.scan_my_network();
    assert_eq!(h.app.error, "Stop the running scan or capture first.");
    assert!(h.job().is_none());
}

/// Settings with only the named sections open (the window scrolls; the folded ones fit).
fn settings_with(sections: &[&str]) -> Harness {
    let mut h = Harness::new("settings");
    for s in ["Safe Mode and discovery", "Scripts, rules and recording"]
        .iter()
        .chain(sections)
    {
        h.click(s);
        h.settle();
    }
    h
}

#[test]
fn the_service_options_show_their_fields_and_safe_mode_holds_back_the_noisy_ones() {
    let mut h = settings_with(&["Services and identification"]);
    assert!(!h.has("TCP only (skip ICMP ping)"), "the folded section");
    let udp = h.app.saved.settings.udp;
    assert_eq!(h.has("UDP ports"), udp);
    h.click("Probe UDP services (DNS, DHCP, NTP, NetBIOS, SNMP public, SSDP, mDNS)");
    assert_eq!(h.app.saved.settings.udp, !udp);
    assert_eq!(h.has("UDP ports"), !udp, "the port list follows the box");
    let jarm = "JARM TLS fingerprint (10 extra connections per TLS port; needs service detection)";
    h.app.saved.settings.services = true;
    h.step();
    h.click(jarm);
    assert!(!h.app.saved.settings.jarm, "not in Safe Mode");
    h.app.saved.settings.safe = false;
    h.step();
    h.click(jarm);
    assert!(h.app.saved.settings.jarm);
}

#[test]
fn the_industrial_options_set_the_ot_ports() {
    let mut h = settings_with(&["Industrial (OT)"]);
    h.app.saved.settings.ot = false;
    h.step();
    assert!(!h.has("Use industrial ports"));
    h.click("Read industrial device identities (standard ports + BACnet UDP)");
    assert!(h.app.saved.settings.ot);
    assert!(h.has("Modbus unit") && h.has("S7 slot"));
    h.app.saved.settings.scan_nonresponders = false;
    h.click("Use industrial ports");
    let s = &h.app.saved.settings;
    assert_eq!(s.ports, "80,443,102,502,1883,1911,4840,9600,44818");
    assert!(s.scan_nonresponders, "PLCs often ignore ping");
}

#[test]
fn the_traceroute_method_needs_safe_mode_off_and_warns_about_ot_ports() {
    let mut h = settings_with(&["Traceroute"]);
    h.app.saved.settings.trace = false;
    h.step();
    h.click("Record router path to each responding host (traceroute)");
    assert!(h.app.saved.settings.trace);
    assert!(h.has("Max hops"));
    // In Safe Mode only ICMP can be chosen.
    h.open_combo("ICMP");
    h.click("TCP SYN (needs Npcap)");
    assert_eq!(h.app.saved.settings.trace_method, TraceMethod::Icmp);
    h.key(egui::Key::Escape);
    h.app.saved.settings.safe = false;
    h.step();
    h.open_combo("ICMP");
    h.click("TCP SYN (needs Npcap)");
    assert_eq!(h.app.saved.settings.trace_method, TraceMethod::Tcp);
    assert!(h.has("TCP port"));
    assert!(!h.has("OT/printer port: ICMP will be used instead"));
    h.app.saved.settings.trace_port = 502;
    h.step();
    assert!(h.has("OT/printer port: ICMP will be used instead"));
    // Turned back on, Safe Mode shows the method it will use.
    h.app.saved.settings.safe = true;
    h.step();
    assert!(h.has("ICMP in Safe Mode"));
}

#[test]
fn the_timing_options_and_restore_defaults() {
    let mut h = settings_with(&["Timing and performance"]);
    assert!(h.has("Concurrent hosts") && h.has("Rate cap (0 = none)"));
    let backoff = h.app.saved.settings.backoff;
    // Below the fold of the scrolling window: the keyboard reaches it.
    h.focus_and_press(
        "Back off when a device resets connections (lower limits for OT/printers)",
        egui::Key::Space,
    );
    assert_eq!(h.app.saved.settings.backoff, !backoff);
    // Restore defaults keeps what belongs to this computer.
    h.app.saved.settings.workers = 999;
    h.app.saved.settings.interface = "Ethernet 2".into();
    h.app.saved.preset = "full".into();
    h.click("Timing and performance");
    h.settle();
    h.click("Restore defaults");
    let s = &h.app.saved.settings;
    assert_eq!(s.workers, scan::Settings::default().workers);
    assert_eq!(s.backoff, scan::Settings::default().backoff);
    assert_eq!(s.interface, "Ethernet 2");
    assert!(h.app.saved.preset.is_empty());
}

#[test]
fn the_snmp_form_keeps_the_names_of_the_variables_and_never_a_secret() {
    let mut h = settings_with(&["SNMP (read-only)"]);
    assert_eq!(h.app.saved.settings.snmp_ref, None);
    let mode = |h: &mut Harness, from: &str, to: &str| {
        h.open_combo(from);
        h.click(to);
    };
    mode(&mut h, "Off", "Community (SNMP v1/v2c)");
    // Nothing is saved before the form is complete; it says what is missing.
    assert_eq!(h.app.saved.settings.snmp_ref, None);
    assert!(h.shows("environment variable"));
    h.type_into("Environment variable with the community", "NS_COMMUNITY");
    let community = |version: &str| SnmpRef::Community {
        version: version.into(),
        env: "NS_COMMUNITY".into(),
    };
    assert_eq!(h.app.saved.settings.snmp_ref, Some(community("2c")));
    assert!(h.shows("Only the names of the variables are saved"));
    h.click("v1");
    assert_eq!(h.app.saved.settings.snmp_ref, Some(community("1")));
    // SNMPv3: the user, then each passphrase by the name of its variable.
    mode(&mut h, "Community (SNMP v1/v2c)", "SNMPv3 user");
    h.type_into("User name", "monitor");
    let v3 = |spec: &str| Some(SnmpRef::V3 { spec: spec.into() });
    assert_eq!(h.app.saved.settings.snmp_ref, v3("monitor"));
    h.click("SHA-256");
    assert_eq!(h.app.saved.settings.snmp_ref, v3("monitor"), "incomplete");
    h.type_into(
        "Environment variable with the authentication passphrase",
        "SNMP_AUTH",
    );
    assert_eq!(
        h.app.saved.settings.snmp_ref,
        v3("monitor:sha256:SNMP_AUTH")
    );
    h.click("AES-128");
    h.type_into(
        "Environment variable with the privacy passphrase",
        "SNMP_PRIV",
    );
    assert_eq!(
        h.app.saved.settings.snmp_ref,
        v3("monitor:sha256:SNMP_AUTH:aes:SNMP_PRIV")
    );
    // Without authentication (the upper "none") there is no privacy either.
    let no_auth = (h.find("none").into_iter())
        .map(|w| w.rect.center())
        .min_by(|a, b| a.y.total_cmp(&b.y))
        .unwrap();
    h.press(no_auth, egui::PointerButton::Primary);
    assert!(!h.has("Privacy"));
    assert_eq!(h.app.saved.settings.snmp_ref, v3("monitor"));
    mode(&mut h, "SNMPv3 user", "Off");
    assert_eq!(h.app.saved.settings.snmp_ref, None);
}

#[test]
fn appearance_language_and_the_update_check_apply_at_once() {
    let mut h = Harness::new("appearance");
    h.settle();
    assert!(h.has("Appearance and language"));
    h.click("Dark");
    assert!(h.app.saved.dark && h.ctx.global_style().visuals.dark_mode);
    h.click("Light");
    assert!(!h.app.saved.dark && !h.ctx.global_style().visuals.dark_mode);
    h.open_combo("English");
    h.click("Deutsch");
    assert_eq!(h.app.saved.language, "de");
    // The window is named by its title: it is laid out anew in German.
    h.settle();
    assert!(h.has("Einstellungen"), "the window speaks German at once");
    assert!(
        h.has("Sicherer Modus und Erkennung"),
        "and so do its sections"
    );
    i18n::set(i18n::Lang::English);
    h.step();
    // The last section, below the fold: the keyboard opens it and ticks its box.
    let mut h = Harness::new("settings");
    h.focus_and_press("Updates", egui::Key::Enter);
    h.settle();
    assert!(!h.app.saved.check_updates, "off by default");
    h.focus_and_press(
        "Check for updates on start (one request to GitHub; only tells you, never downloads)",
        egui::Key::Space,
    );
    assert!(h.app.saved.check_updates);
    assert!(
        h.app.update_check.is_none(),
        "it checks on the next start, not now"
    );
}

#[test]
fn the_about_window_names_the_version() {
    let mut h = Harness::new("main");
    h.click("Help");
    h.click("About Network Scope");
    h.step();
    assert!(h.app.about_open);
    assert!(h.shows(env!("CARGO_PKG_VERSION")));
    assert!(h.has("Project page") && h.has("Releases"));
}

#[test]
fn the_menus_switch_pages_and_the_theme_and_open_the_tools() {
    let mut h = Harness::new("main");
    for (menu, entry, view) in [
        ("View", "Passive discovery / OT", MainView::Passive),
        ("View", "Devices", MainView::Devices),
        ("View", "Saved inventory", MainView::Inventory),
    ] {
        h.click(menu);
        h.click(entry);
        assert_eq!(h.app.view, view, "{entry}");
    }
    h.click("View");
    h.hover("Theme");
    h.click("Dark");
    assert!(h.app.saved.dark);
    h.click("Tools");
    h.click("Scheduled scans…");
    assert!(h.app.settings_open);
    h.step();
    assert!(h.has("Scheduled scans"));
    h.click("Scan");
    h.click("Scan my network");
    assert!(
        matches!(h.job(), Some(Job::Networks)),
        "it looks for the networks"
    );
    // A saved address list is chosen from the star menu; starred devices filter the hosts.
    h.app.saved.favorites = vec!["10.30.0.0/24".into()];
    h.click("Favorite addresses");
    h.click("10.30.0.0/24");
    assert_eq!(h.app.targets, "10.30.0.0/24");
    h.app.view = MainView::Map;
    h.click("Favorite addresses");
    h.click("Show starred devices");
    assert_eq!(h.app.view, MainView::Hosts);
    assert_eq!(h.app.filter, Filter::Starred);
}

#[test]
fn a_script_test_result_is_applied_to_the_host_or_discarded() {
    let tall = egui::vec2(1100.0, 1400.0);
    let mut h = Harness::sized("script", tall);
    let plc = ip("10.20.0.5").unwrap();
    assert!(h.has("Script test · policy.rhai"));
    assert!(h.has("Set script.owner = automation"));
    h.click("Apply");
    let host = h.app.results.iter().find(|x| x.ip == plc).unwrap();
    assert_eq!(
        host.identity.get("script.owner").map(String::as_str),
        Some("automation")
    );
    assert!(h.app.status.starts_with("Applied policy.rhai to 10.20.0.5"));
    assert!(h.app.script_test.is_none());
    let mut h = Harness::sized("script", tall);
    h.click("Discard");
    assert!(h.app.script_test.is_none());
    assert!(!h.has("Script test · policy.rhai"));
    let host = h.app.results.iter().find(|x| x.ip == plc).unwrap();
    assert!(
        !host.identity.contains_key("script.owner"),
        "nothing applied"
    );
    // A result that arrives while a scan runs is not applied.
    let mut h = Harness::sized("script", tall);
    let (run, _events) = fake_scan(1);
    h.app.run = Some(run);
    h.step();
    h.click("Apply");
    assert!(h.app.script_test.is_some(), "greyed out while scanning");
}

#[test]
fn the_configured_script_is_tested_on_the_worker() {
    // Tall enough for the whole details panel.
    let mut h = Harness::sized("main", egui::vec2(1100.0, 1400.0));
    h.click("plc-line-1");
    h.click("Test script…");
    assert!(h.has("Configured script (none set in Settings)"));
    h.key(egui::Key::Escape);
    h.app.saved.settings.scripts = "policy.rhai".into();
    h.step();
    h.click("Test script…");
    h.click("Configured script (policy.rhai)");
    let token = match h.job() {
        Some(Job::TestScript(token, path, host)) => {
            assert_eq!(path, "policy.rhai");
            assert_eq!(
                host.ip,
                ip("10.20.0.5").unwrap(),
                "a copy of the selected host"
            );
            token
        }
        _ => panic!("the test runs on the worker"),
    };
    assert!(h.has("Running…") && h.shows("Running script…"));
    // An answer for an older test is dropped; the current one is shown.
    h.answer(Done::ScriptTested(token + 1, Err("old".into())));
    assert!(h.has("Running…"));
    h.answer(Done::ScriptTested(
        token,
        Err("policy.rhai: syntax error".into()),
    ));
    assert!(h.has("policy.rhai: syntax error"));
    assert!(!h.has("Apply"), "nothing to apply");
    // Choosing another host drops the test.
    h.click("historian");
    assert!(h.app.script_test.is_none());
}

#[test]
fn the_host_details_show_what_changed_and_keep_a_note() {
    let mut h = Harness::sized("main", egui::vec2(1100.0, 1400.0));
    let plc = ip("10.20.0.5").unwrap();
    let mut old = h.app.results.iter().find(|x| x.ip == plc).unwrap().clone();
    old.open = vec![21, 102];
    h.app.previous.insert(plc, old.clone());
    h.click("plc-line-1");
    assert!(h.shows("Changed since previous scan · previously"));
    assert!(h.shows("ports 21, 102"));
    old.open = h
        .app
        .results
        .iter()
        .find(|x| x.ip == plc)
        .unwrap()
        .open
        .clone();
    h.app.previous.insert(plc, old);
    h.step();
    assert!(h.has("Unchanged since previous scan."));
    // A host that did not answer ping, with UDP, a path and an error.
    let host = h.app.results.iter_mut().find(|x| x.ip == plc).unwrap();
    host.ports_checked = false;
    host.udp_open = vec![161];
    host.errors = vec!["port 102: connection reset".into()];
    host.trace = vec![
        crate::trace::Hop {
            ttl: 1,
            ip: ip("10.20.0.1"),
            rtt: Some(1),
        },
        crate::trace::Hop {
            ttl: 2,
            ip: None,
            rtt: None,
        },
    ];
    h.step();
    assert!(h.has("Ports not checked: no ping reply."));
    assert!(h.has("Open UDP ports: 161"));
    assert!(h.has("Path: 10.20.0.1 > *"));
    assert!(h.has("port 102: connection reset"));
    // Every identity field, folded until asked for.
    let fields = h
        .app
        .results
        .iter()
        .find(|x| x.ip == plc)
        .unwrap()
        .identity
        .len();
    let title = format!("All identity fields ({fields})");
    assert!(!h.has("device.type: PLC"));
    h.click(&title);
    h.settle();
    assert!(h.has("device.type: PLC"));
    h.click(&title);
    h.settle();
    // The note is kept per address; viewing a host makes none.
    assert!(h.app.saved.notes.is_empty());
    let note = (h.widgets.iter())
        .find(|w| w.role == "MultilineTextInput")
        .expect("the note field")
        .rect
        .center();
    h.press(note, egui::PointerButton::Primary);
    h.events.push(egui::Event::Text("spare in store".into()));
    h.step();
    assert_eq!(
        h.app.saved.notes.get(&plc).map(String::as_str),
        Some("spare in store")
    );
    // The timeline of the device opens beside the details.
    h.click("Timeline");
    assert!(h.app.timeline.is_some());
}

#[test]
fn a_passive_device_copies_its_address_and_mac_and_closes() {
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
    assert!(h.has("Device details · tablet-lobby") || h.has("Device details · 10.20.0.200"));
    assert!(h.shows("Seen by: "), "the protocols that saw it");
    h.click("Copy address");
    h.click("Copy MAC address");
    assert!(h.app.selected_device.is_some(), "copying keeps the panel");
    h.click("Close");
    assert!(h.app.selected_device.is_none());
    // A device that is gone from the data closes its panel.
    h.click("10.20.0.200");
    h.app.observations.clear();
    h.app.data_changed();
    h.step();
    h.step();
    assert!(h.app.selected_device.is_none());
}
/// Every screenshot state of the documentation renders in each variant (small window, Safe Mode
/// off, dark theme, German) without a panic, and shows the page it is about.
#[test]
fn every_screenshot_state_renders_in_every_variant() {
    const STATES: [&str; 27] = [
        "main",
        "findings",
        "devices",
        "ot",
        "script",
        "timeline",
        "scan-details",
        "workbench",
        "workbench-compare",
        "workbench-draft",
        "settings",
        "schedule",
        "shortcuts",
        "safe-off",
        "findings-grouped",
        "columns",
        "home",
        "home-empty",
        "hosts-empty",
        "map",
        "map-large",
        "quick",
        "palette",
        "palette-actions",
        "appearance",
        "wake",
        "main-small-fast-dark-de",
    ];
    for state in STATES {
        for variant in ["", "-small", "-fast", "-dark", "-de"] {
            let name = format!("{state}{variant}");
            let mut h = Harness::new(&name);
            h.step();
            assert!(!h.widgets.is_empty(), "{name}: nothing rendered");
        }
    }
    i18n::set(i18n::Lang::English);
}
