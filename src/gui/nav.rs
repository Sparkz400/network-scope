//! The sidebar: the pages of the main window, each with a small count (hosts that answered,
//! devices, findings in the colour of the worst one, passive observations, saved scans). The
//! pages are the same as in the View menu and on `Ctrl+1` to `Ctrl+7`; a click runs the same
//! command.
use super::{palette::Cmd, *};

/// The pages in sidebar order, with the command that opens each. `None` draws a separator.
const PAGES: [Option<(MainView, Cmd)>; 9] = [
    Some((MainView::Home, Cmd::Overview)),
    Some((MainView::Hosts, Cmd::Hosts)),
    None,
    Some((MainView::Devices, Cmd::Devices)),
    Some((MainView::Findings, Cmd::Findings)),
    Some((MainView::Map, Cmd::Map)),
    Some((MainView::Passive, Cmd::Passive)),
    None,
    Some((MainView::Inventory, Cmd::Inventory)),
];

/// The width of the sidebar.
const WIDTH: f32 = 172.0;
/// Up to this many hosts and observations the sidebar works out the device and finding counts
/// itself (about 25 ms once per data change in release); above it, a count appears once its page
/// has been opened, so a large scan never stalls the window for pages nobody looks at (65,536
/// hosts take about 0.4 s).
const EAGER_LIMIT: usize = 4096;

impl Scanner {
    /// Whether findings and devices may be worked out without the user asking for them: no
    /// scan or capture runs and the data is small ([`EAGER_LIMIT`]).
    pub(super) fn eager(&self) -> bool {
        !self.live()
            && !self.ot.running()
            && self.results.len() + self.observations.len() <= EAGER_LIMIT
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
            MainView::Devices => {
                if eager {
                    self.ensure_devices();
                }
                let n = self.devices.value.len();
                (self.devices.generation == Some(self.generation) && n > 0)
                    .then(|| (n.to_string(), None))
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
            MainView::Home | MainView::Map => None,
        }
    }

    /// The sidebar with the pages.
    pub(super) fn sidebar(&mut self, root: &mut egui::Ui) {
        egui::Panel::left("pages")
            .resizable(false)
            .exact_size(WIDTH)
            .show(root, |ui| {
                ui.add_space(6.0);
                for page in PAGES {
                    let Some((view, cmd)) = page else {
                        ui.separator();
                        continue;
                    };
                    let mut button = egui::Button::selectable(self.view == view, cmd.menu_label())
                        .min_size(egui::vec2(ui.available_width(), 28.0));
                    if let Some((count, color)) = self.badge(view) {
                        let mut text = RichText::new(count).small();
                        text = match color {
                            Some(c) => text.color(c).strong(),
                            None => text.color(ui.visuals().weak_text_color()),
                        };
                        button = button.right_text(text);
                    }
                    let mut response = ui.add(button);
                    if let Some(shortcut) = cmd.shortcut() {
                        response = response.on_hover_text(ui.ctx().format_shortcut(&shortcut));
                    }
                    if response.clicked() {
                        let ctx = ui.ctx().clone();
                        self.run_command(&ctx, cmd);
                    }
                }
            });
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
            small.badge(MainView::Devices).map(|b| b.0),
            Some("20".into())
        );
        let _ = small.badge(MainView::Findings);
        assert_eq!(small.findings.generation, Some(small.generation));
        // New data: counted again, never the old number for the new data.
        small.results.truncate(5);
        small.data_changed();
        assert_eq!(
            small.badge(MainView::Devices).map(|b| b.0),
            Some("5".into())
        );

        let mut large = app_with(EAGER_LIMIT as u32 + 1);
        assert_eq!(large.badge(MainView::Devices), None);
        assert_eq!(large.badge(MainView::Findings), None);
        assert_eq!(large.findings.generation, None, "nothing was analysed");
        // What the Devices and Findings pages do when they are opened.
        large.ensure_devices();
        large.ensure_findings();
        assert_eq!(
            large.badge(MainView::Devices).map(|b| b.0),
            Some((EAGER_LIMIT + 1).to_string())
        );
        assert_eq!(large.findings.generation, Some(large.generation));
    }

    #[test]
    fn every_page_is_in_the_sidebar_once_with_its_view_command() {
        let pages: Vec<(MainView, Cmd)> = PAGES.into_iter().flatten().collect();
        assert_eq!(pages.len(), 7);
        for (i, (view, cmd)) in pages.iter().enumerate() {
            assert!(!pages[..i].iter().any(|(v, _)| v == view), "{view:?} twice");
            assert!(cmd.shortcut().is_some(), "{cmd:?} has no shortcut");
        }
    }
}
