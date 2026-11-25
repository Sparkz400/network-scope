//! The sidebar: the pages of the main window, each with a small count (hosts that answered,
//! findings in the colour of the worst one, passive observations, saved scans). The pages are
//! the same as in the View menu and on `Ctrl+1` to `Ctrl+7` (`Ctrl+3` is the device mode of the
//! Hosts page); a click runs the same command.
use super::{palette::Cmd, *};

/// The pages in sidebar order, with the command that opens each. `None` draws a separator.
/// Devices is not a page of its own: it is the "by device" mode of the Hosts page (still
/// `Ctrl+3`, the View menu and the palette).
const PAGES: [Option<(MainView, Cmd)>; 8] = [
    Some((MainView::Home, Cmd::Overview)),
    Some((MainView::Hosts, Cmd::Hosts)),
    None,
    Some((MainView::Findings, Cmd::Findings)),
    Some((MainView::Map, Cmd::Map)),
    Some((MainView::Passive, Cmd::Passive)),
    None,
    Some((MainView::Inventory, Cmd::Inventory)),
];

/// The width of the sidebar.
const WIDTH: f32 = 196.0;
/// Up to this many hosts and observations the sidebar works out the finding count on the UI
/// thread (about 25 ms once per data change in release). Above it the findings are worked out on
/// a thread of their own once no scan or capture runs ([`Scanner::background_findings`]; 65,536
/// hosts take about 0.4 s), so a large scan never stalls the window.
const EAGER_LIMIT: usize = 4096;

/// Findings being worked out on another thread for one data generation.
pub(super) struct BackgroundFindings {
    generation: u64,
    rx: mpsc::Receiver<Vec<risk::Finding>>,
}

impl BackgroundFindings {
    /// The hosts were only sorted (`before` -> `now`): the answer still holds for them.
    pub(super) fn restamp(&mut self, before: u64, now: u64) {
        if self.generation == before {
            self.generation = now;
        }
    }
}

/// The name of a page in the sidebar: the menu's name, shortened where the sidebar has no room
/// for it next to a count (the menus, the palette and the hover text keep the full name).
fn sidebar_label(cmd: Cmd) -> &'static str {
    match cmd {
        Cmd::Passive => tr!("Passive / OT"),
        Cmd::Inventory => tr!("Inventory"),
        other => other.menu_label(),
    }
}

impl Scanner {
    /// Whether findings and devices may be worked out without the user asking for them: no
    /// scan or capture runs and the data is small ([`EAGER_LIMIT`]).
    pub(super) fn eager(&self) -> bool {
        !self.live()
            && !self.ot.running()
            && self.results.len() + self.observations.len() <= EAGER_LIMIT
    }

    /// More hosts and observations than are analysed on the UI thread ([`EAGER_LIMIT`]).
    pub(super) fn large(&self) -> bool {
        self.results.len() + self.observations.len() > EAGER_LIMIT
    }

    /// Starts working out the findings of a large scan on another thread when they are out of
    /// date, and takes the answer when it is there (once per frame). When nothing runs it
    /// starts by itself (the sidebar counts them) and the answer is used only if the data did
    /// not change meanwhile. While a scan or capture runs it starts only for a page that shows
    /// findings ([`Scanner::ensure_findings`]), one answer at a time and no more often than
    /// such a page refreshes; that answer is shown although the data has moved on. The hosts
    /// are copied for the thread, so the window keeps showing and sorting them.
    // shortcut: that copy is made on the UI thread (some tens of milliseconds for 65,536
    // hosts) for every answer; share the hosts with the thread if it shows while a scan runs.
    pub(super) fn background_findings(&mut self, ctx: &egui::Context) {
        let running = self.live() || self.ot.running();
        if let Some(job) = &self.background_findings {
            match job.rx.try_recv() {
                Ok(findings) => {
                    let current = job.generation == self.generation;
                    if current || running {
                        self.findings.set(job.generation, findings);
                    }
                    self.background_findings = None;
                    // The hosts are in the order of their risk: that order is known now.
                    if current && self.sort_column == super::RISK_COLUMN {
                        self.resort();
                    }
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => self.background_findings = None,
            }
        }
        let asked = std::mem::take(&mut self.findings_wanted);
        let wanted = self.large()
            && self.screenshot.is_none()
            && if running {
                asked
                    && self.background_findings.is_none()
                    && self.findings.stale(self.generation, true)
            } else {
                self.findings.generation != Some(self.generation)
                    && self
                        .background_findings
                        .as_ref()
                        .is_none_or(|job| job.generation != self.generation)
            };
        // The page that asked keeps its note until the answer is there.
        self.findings_wanted = asked && self.findings.generation != Some(self.generation);
        if !wanted {
            return;
        }
        let snapshot = store::Snapshot {
            sent: vec![],
            targets: String::new(),
            complete: false,
            settings: Default::default(),
            hosts: self.results.clone(),
            observations: self.observations.clone(),
            notes: Default::default(),
        };
        let (tx, rx) = mpsc::channel();
        let ctx = ctx.clone();
        let started = std::thread::Builder::new()
            .name("findings".into())
            .spawn(move || {
                // A dropped receiver (newer data) is not an error.
                let _ = tx.send(risk::analyze_snapshot(&snapshot));
                ctx.request_repaint();
            });
        if started.is_ok() {
            self.background_findings = Some(BackgroundFindings {
                generation: self.generation,
                rx,
            });
        }
    }

    /// The findings of the data on screen, worked out now when that is cheap. False when they
    /// are not up to date (a large scan whose Findings page was not opened, or a running scan).
    pub(super) fn fresh_findings(&mut self) -> bool {
        if self.eager() {
            self.ensure_findings();
        }
        self.findings.generation == Some(self.generation)
    }

    /// The worst finding per address, when the findings are up to date (see [`Self::fresh_findings`]).
    pub(super) fn ensure_risk_map(&mut self) {
        if self.fresh_findings() && self.risk_map.generation != Some(self.generation) {
            let map = tables::risk_by_ip(&self.findings.value);
            self.risk_map.set(self.generation, map);
        }
    }

    /// The imported SBOMs of the firmware each host reported (see [`crate::sbom::for_hosts`]).
    pub(super) fn ensure_firmware_sboms(&mut self) {
        if self.firmware_sboms.stale(self.generation, self.live()) {
            let library = crate::sbom::active();
            let found = crate::sbom::for_hosts(&library, &self.results, &self.observations);
            self.firmware_sboms.set(self.generation, (library, found));
        }
    }

    /// The host name of every address that has one, for the Findings page.
    pub(super) fn ensure_hostnames(&mut self) {
        if self.hostnames.stale(self.generation, self.live()) {
            let names = self
                .results
                .iter()
                .filter(|h| !h.hostname.is_empty())
                .map(|h| (h.ip, h.hostname.clone()))
                .collect();
            self.hostnames.set(self.generation, names);
        }
    }

    /// The count shown next to a page name, and its colour. Devices and findings are worked
    /// out here only when [`Self::eager`] allows it; a count that does not match the data on
    /// screen is not shown.
    fn badge(&mut self, view: MainView) -> Option<(String, Option<Color32>)> {
        let dark = self.saved.dark;
        let eager = self.eager();
        match view {
            MainView::Hosts => {
                (!self.results.is_empty()).then(|| (self.responding.to_string(), None))
            }
            MainView::Findings => {
                if eager {
                    self.ensure_findings();
                }
                if self.findings.generation != Some(self.generation) {
                    return None;
                }
                let findings = &self.findings.value;
                let worst = findings.iter().map(|f| f.severity).max()?;
                Some((
                    findings.len().to_string(),
                    Some(home::severity_color(worst, dark)),
                ))
            }
            MainView::Passive => {
                let n = self.observations.len();
                (n > 0).then(|| (n.to_string(), None))
            }
            MainView::Inventory => {
                // The list of the page, or the number the overview read at start.
                let n = match &self.home.data {
                    _ if !self.history.is_empty() => self.history.len(),
                    Some(Ok(data)) => data.scans,
                    _ => 0,
                };
                (n > 0).then(|| (n.to_string(), None))
            }
            // Devices has no entry of its own (see `PAGES`).
            MainView::Home | MainView::Map | MainView::Devices => None,
        }
    }

    /// The sidebar with the pages.
    pub(super) fn sidebar(&mut self, root: &mut egui::Ui) {
        egui::Panel::left("pages")
            .resizable(false)
            .exact_size(WIDTH)
            .show(root, |ui| {
                // Scrolls only when the window is shorter than the list.
                egui::ScrollArea::vertical()
                    .id_salt("pages_scroll")
                    .show(ui, |ui| self.sidebar_pages(ui));
            });
    }

    /// The logo and the page buttons.
    fn sidebar_pages(&mut self, ui: &mut egui::Ui) {
        ui.spacing_mut().item_spacing.y = 2.0;
        // The app's mark and name, like the title of a document window.
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.add_space(6.0);
            let logo = icons::logo(ui.ctx());
            ui.add(egui::Image::new((logo.id(), egui::vec2(22.0, 22.0))));
            ui.label(RichText::new("Network Scope").strong().size(15.0));
        });
        ui.add_space(4.0);
        ui.separator();
        for page in PAGES {
            let Some((view, cmd)) = page else {
                ui.separator();
                continue;
            };
            let badge = self.badge(view);
            // The Hosts entry stays highlighted in its device mode.
            let selected =
                self.view == view || (view == MainView::Hosts && self.view == MainView::Devices);
            let label = sidebar_label(cmd);
            let mut response = icons::page_button(ui, view, selected, label, badge.as_ref());
            // The full name (when the sidebar shortens it) and the shortcut.
            let mut hover = String::new();
            if label != cmd.menu_label() {
                hover.push_str(cmd.menu_label());
            }
            if let Some(shortcut) = cmd.shortcut() {
                if !hover.is_empty() {
                    hover.push_str(" · ");
                }
                hover.push_str(&ui.ctx().format_shortcut(&shortcut));
            }
            if !hover.is_empty() {
                response = response.on_hover_text(hover);
            }
            if response.clicked() {
                let ctx = ui.ctx().clone();
                self.run_command(&ctx, cmd);
            }
        }
    }

    /// The page of the main window that is chosen in the sidebar.
    pub(super) fn page_ui(&mut self, ui: &mut egui::Ui) -> bool {
        match self.view {
            MainView::Home => self.home_view(ui),
            MainView::Devices => self.devices_view(ui),
            MainView::Findings => self.findings_view(ui),
            MainView::Map => self.map_view(ui),
            MainView::Passive => self.capture_view(ui),
            MainView::Inventory => self.inventory_view(ui),
            MainView::Hosts => return false,
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The app in screenshot mode with `hosts` hosts that each offer Telnet.
    fn app_with(hosts: u32) -> Scanner {
        let cc = eframe::CreationContext::_new_kittest(egui::Context::default());
        let mut app = Scanner::new(&cc, Some(PathBuf::from("unused.png")), Saved::default());
        app.results = (0..hosts)
            .map(|i| {
                let ip = std::net::Ipv4Addr::from(0x0a00_0000 + i).to_string();
                demo::demo_host(&ip, &[23], &[("svc.23", "telnet")])
            })
            .collect();
        app.data_changed();
        app
    }

    #[test]
    fn small_data_is_counted_at_once_and_large_data_once_its_page_was_opened() {
        let mut small = app_with(20);
        assert_eq!(
            small.badge(MainView::Findings).map(|b| b.0),
            Some("20".into()),
            "one telnet finding per host"
        );
        assert_eq!(small.findings.generation, Some(small.generation));
        // New data: counted again, never the old number for the new data.
        small.results.truncate(5);
        small.data_changed();
        assert_eq!(
            small.badge(MainView::Findings).map(|b| b.0),
            Some("5".into())
        );

        let mut large = app_with(EAGER_LIMIT as u32 + 1);
        assert_eq!(large.badge(MainView::Findings), None);
        assert_eq!(large.findings.generation, None, "nothing was analysed");
        // What the Findings page does when it is opened.
        large.ensure_findings();
        assert_eq!(
            large.badge(MainView::Findings).map(|b| b.0),
            Some((EAGER_LIMIT + 1).to_string())
        );
        assert_eq!(large.findings.generation, Some(large.generation));
    }

    #[test]
    fn a_large_scan_gets_its_findings_from_another_thread() {
        let mut large = app_with(EAGER_LIMIT as u32 + 101);
        // `app_with` is a screenshot run, which never starts threads.
        large.screenshot = None;
        let ctx = egui::Context::default();
        let wait = |app: &mut Scanner| {
            let deadline = Instant::now() + Duration::from_secs(60);
            while app.background_findings.is_some() {
                assert!(Instant::now() < deadline, "the thread answered");
                std::thread::sleep(Duration::from_millis(5));
                app.background_findings(&ctx);
            }
        };
        large.background_findings(&ctx);
        let first = large.generation;
        assert_eq!(
            large.background_findings.as_ref().map(|j| j.generation),
            Some(first)
        );
        // New data while the thread works: its answer is dropped and a new one is asked for.
        large.results.truncate(EAGER_LIMIT + 1);
        large.data_changed();
        large.background_findings(&ctx);
        assert_eq!(
            large.background_findings.as_ref().map(|j| j.generation),
            Some(large.generation)
        );
        wait(&mut large);
        assert_eq!(large.findings.generation, Some(large.generation));
        assert_eq!(
            large.badge(MainView::Findings).map(|b| b.0),
            Some((EAGER_LIMIT + 1).to_string())
        );
        // Up to date: nothing more is started.
        large.background_findings(&ctx);
        assert!(large.background_findings.is_none());
    }

    #[test]
    fn the_pages_of_a_large_scan_leave_the_findings_to_the_other_thread() {
        let mut large = app_with(EAGER_LIMIT as u32 + 101);
        large.screenshot = None;
        (large.sort_column, large.sort_reverse) = (super::super::RISK_COLUMN, false);
        let ctx = egui::Context::default();
        // What the Findings page, Hosts by device and the map do in every frame.
        large.ensure_findings();
        assert_eq!(large.findings.generation, None, "nothing on the UI thread");
        assert!(large.findings_wanted);
        large.background_findings(&ctx);
        assert!(large.findings_wanted, "the page keeps its note");
        let deadline = Instant::now() + Duration::from_secs(60);
        while large.background_findings.is_some() {
            assert!(Instant::now() < deadline, "the thread answered");
            std::thread::sleep(Duration::from_millis(5));
            large.background_findings(&ctx);
        }
        // The answer is used, and the hosts were put in the order of their risk with it (the
        // sort stamps the data anew and the answer with it).
        assert_eq!(large.findings.generation, Some(large.generation));
        assert_eq!(large.findings.value.len(), EAGER_LIMIT + 101);
        large.ensure_findings();
        assert!(!large.findings_wanted, "up to date: nothing is asked for");
    }

    #[test]
    fn every_page_is_in_the_sidebar_once_with_its_view_command() {
        let pages: Vec<(MainView, Cmd)> = PAGES.into_iter().flatten().collect();
        assert_eq!(pages.len(), 6, "Devices is a mode of the Hosts page");
        for (i, (view, cmd)) in pages.iter().enumerate() {
            assert!(!pages[..i].iter().any(|(v, _)| v == view), "{view:?} twice");
            assert!(cmd.shortcut().is_some(), "{cmd:?} has no shortcut");
        }
    }
}
