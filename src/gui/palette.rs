//! The command palette (ROADMAP F39): `Ctrl+K` (`Cmd+K` on macOS) opens a box where you type a
//! few letters of an action ("new scan", "settings", "export", "map") or an address, MAC, host
//! name, vendor or finding id. Actions are matched fuzzily; the text is also searched in all saved
//! scans (`core::search`, on the background worker), so "where did 10.0.5.17 last appear?" is
//! answered without leaving the keyboard. Up and Down choose, Enter runs, Escape closes.
use super::{i18n::tr, *};
use crate::{presets::Preset, search};

/// Most actions listed.
const MAX_ACTIONS: usize = 9;
/// Most saved-scan hits listed.
const MAX_HITS: usize = 12;
/// A search starts this long after the last keystroke.
const SEARCH_DELAY: Duration = Duration::from_millis(250);
/// The shortest text that is searched in the saved scans.
const MIN_QUERY: usize = 2;

/// What the user can run from the palette.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cmd {
    ScanMyNetwork,
    StartScan,
    StopScan,
    ImportList,
    Overview,
    Hosts,
    Settings,
    Inventory,
    Map,
    Findings,
    Devices,
    Workbench,
    Passive,
    About,
    ExportCsv,
    ExportJson,
    ExportHtml,
    ExportMarkdown,
    ClearResults,
    Preset(Preset),
    Language(i18n::Lang),
    DarkTheme,
    LightTheme,
}

/// An action with its (translated) name and extra words it is found by.
pub(super) struct Entry {
    pub cmd: Cmd,
    pub label: String,
    pub keywords: &'static str,
}

/// Every action, with names in the current language.
pub(super) fn entries() -> Vec<Entry> {
    let mut v = vec![
        (
            Cmd::ScanMyNetwork,
            tr!("New scan: scan my network"),
            "new scan network automatic one click",
        ),
        (
            Cmd::StartScan,
            tr!("Start the scan of the addresses"),
            "run begin",
        ),
        (Cmd::StopScan, tr!("Stop the running scan"), "cancel abort"),
        (
            Cmd::ImportList,
            tr!("Import an address list…"),
            "targets file ip list open",
        ),
        (
            Cmd::Overview,
            tr!("Open the overview (what changed)"),
            "home changes new gone risk score",
        ),
        (Cmd::Hosts, tr!("Open the hosts table"), "results list"),
        (
            Cmd::Settings,
            tr!("Open the scan settings"),
            "preferences options safe mode",
        ),
        (
            Cmd::Inventory,
            tr!("Open the saved inventory"),
            "history scans compare diff",
        ),
        (Cmd::Map, tr!("Open the network map"), "topology graph path"),
        (
            Cmd::Findings,
            tr!("Open the findings"),
            "risks vulnerabilities cve kev",
        ),
        (Cmd::Devices, tr!("Open the devices"), "assets mac vendor"),
        (
            Cmd::Workbench,
            tr!("Open the unknown-device workbench"),
            "unidentified banners fingerprint probe rule draft group compare",
        ),
        (
            Cmd::Passive,
            tr!("Open passive discovery / OT"),
            "capture listen dcp pcap",
        ),
        (Cmd::About, tr!("About Network Scope"), "version info"),
        (
            Cmd::ExportCsv,
            tr!("Export the visible rows as CSV…"),
            "save file",
        ),
        (
            Cmd::ExportJson,
            tr!("Export the visible rows as JSON…"),
            "save file",
        ),
        (
            Cmd::ExportHtml,
            tr!("Export the HTML report…"),
            "save file report",
        ),
        (
            Cmd::ExportMarkdown,
            tr!("Export the Markdown summary…"),
            "save file report",
        ),
        (
            Cmd::ClearResults,
            tr!("Clear the results and captures"),
            "reset empty",
        ),
        (
            Cmd::DarkTheme,
            tr!("Use the dark theme"),
            "appearance colors night",
        ),
        (
            Cmd::LightTheme,
            tr!("Use the light theme"),
            "appearance colors day",
        ),
    ]
    .into_iter()
    .map(|(cmd, label, keywords)| Entry {
        cmd,
        label: label.to_string(),
        keywords,
    })
    .collect::<Vec<_>>();
    for p in Preset::ALL {
        v.push(Entry {
            cmd: Cmd::Preset(p),
            label: tr!("Preset: {}", p.label()),
            keywords: "profile settings bundle",
        });
    }
    for l in i18n::LANGUAGES {
        v.push(Entry {
            cmd: Cmd::Language(l),
            label: tr!("Language: {}", l.name()),
            keywords: "sprache translation locale",
        });
    }
    v
}

/// How well `token` matches `text` (both are compared in lower case): a substring scores high,
/// more at the start of the text or of a word; letters in order with gaps score lower; `None`
/// when the letters are not all there in order.
pub(super) fn token_score(token: &str, text: &str) -> Option<i32> {
    let (token, text) = (token.to_lowercase(), text.to_lowercase());
    if token.is_empty() {
        return Some(0);
    }
    let word_start = |chars: &[char], i: usize| i == 0 || !chars[i - 1].is_alphanumeric();
    let chars: Vec<char> = text.chars().collect();
    if let Some(byte) = text.find(&token) {
        let pos = text[..byte].chars().count();
        return Some(200 - pos.min(60) as i32 + if word_start(&chars, pos) { 60 } else { 0 });
    }
    let (mut score, mut at, mut previous) = (0i32, 0usize, None::<usize>);
    for t in token.chars() {
        let found = (at..chars.len()).find(|&i| chars[i] == t)?;
        score += 6;
        if previous == Some(found.wrapping_sub(1)) {
            score += 8;
        }
        if word_start(&chars, found) {
            score += 10;
        }
        score -= (found - at).min(10) as i32;
        previous = Some(found);
        at = found + 1;
    }
    Some(score)
}

/// The score of a whole query (words separated by spaces; every word must match) against an
/// action's name and keywords. The name counts more than the keywords.
pub(super) fn score(query: &str, label: &str, keywords: &str) -> Option<i32> {
    let mut total = 0;
    for word in query.split_whitespace() {
        let in_label = token_score(word, label).map(|s| s * 2);
        let in_keywords = token_score(word, keywords);
        total += in_label.into_iter().chain(in_keywords).max()?;
    }
    Some(total)
}

/// Indexes into `entries`, best match first. An empty query lists the first actions in order.
pub(super) fn rank(entries: &[Entry], query: &str) -> Vec<usize> {
    if query.trim().is_empty() {
        return (0..entries.len().min(MAX_ACTIONS)).collect();
    }
    let mut scored: Vec<(i32, usize)> = entries
        .iter()
        .enumerate()
        .filter_map(|(i, e)| score(query, &e.label, e.keywords).map(|s| (s, i)))
        .collect();
    // Higher score first; equal scores keep the list's order.
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    scored
        .into_iter()
        .map(|(_, i)| i)
        .take(MAX_ACTIONS)
        .collect()
}

/// One line of a search hit: what was seen, where and when.
pub(super) fn hit_text(h: &search::Hit) -> String {
    let who = [
        h.ip.map(|i| i.to_string()).unwrap_or_default(),
        h.hostname.clone(),
        h.mac.clone(),
        h.vendor.clone(),
    ]
    .into_iter()
    .filter(|s| !s.is_empty())
    .collect::<Vec<_>>()
    .join(" · ");
    let what = if h.detail.is_empty() || h.source == "host" {
        String::new()
    } else {
        format!(" [{}]", h.detail)
    };
    tr!(
        "{}{} — scan #{}, {}",
        who,
        what,
        h.scan_id,
        crate::report::fmt_time(h.timestamp)
    )
}

#[derive(Default)]
pub(super) struct Palette {
    pub open: bool,
    pub query: String,
    pub selected: usize,
    /// The text the newest search request was made for.
    pub asked: String,
    pub token: u64,
    pub results: Option<Result<Box<search::Results>, String>>,
    pub edited: Option<Instant>,
    /// Focus the text box on the next frame.
    pub focus: bool,
}

/// A row of the list.
enum Row {
    Action(usize),
    Hit(usize),
}

impl Scanner {
    pub(super) fn open_palette(&mut self) {
        self.palette.open = true;
        self.palette.focus = true;
        self.palette.selected = 0;
    }

    /// An answer of the saved-scan search; older answers are dropped.
    pub(super) fn search_loaded(
        &mut self,
        token: u64,
        result: Result<Box<search::Results>, String>,
    ) {
        self.busy.searching = false;
        if token == self.palette.token {
            self.palette.results = Some(result);
        }
    }

    fn ask_search(&mut self) {
        let query = self.palette.query.trim().to_string();
        if self.screenshot.is_some() || query == self.palette.asked {
            return;
        }
        self.palette.asked = query.clone();
        self.palette.token += 1;
        if query.chars().count() < MIN_QUERY {
            self.palette.results = None;
            return;
        }
        self.submit(Job::Search(self.palette.token, query));
    }

    pub(super) fn palette_window(&mut self, ctx: &egui::Context) {
        // The shortcut works everywhere, also while the box is open (it closes it).
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::K)) {
            if self.palette.open {
                self.palette.open = false;
            } else {
                self.open_palette();
            }
        }
        if !self.palette.open {
            return;
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::Escape)) {
            self.palette.open = false;
            return;
        }
        // Up and Down belong to the list, not to the text cursor.
        let down = ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::ArrowDown));
        let up = ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, egui::Key::ArrowUp));
        let entries = entries();
        let order = rank(&entries, &self.palette.query);
        let hits: Vec<search::Hit> = match &self.palette.results {
            Some(Ok(r)) if !self.palette.query.trim().is_empty() => {
                r.hits.iter().take(MAX_HITS).cloned().collect()
            }
            _ => vec![],
        };
        let rows: Vec<Row> = order
            .iter()
            .map(|&i| Row::Action(i))
            .chain((0..hits.len()).map(Row::Hit))
            .collect();
        if rows.is_empty() {
            self.palette.selected = 0;
        } else {
            if down {
                self.palette.selected = (self.palette.selected + 1).min(rows.len() - 1);
            }
            if up {
                self.palette.selected = self.palette.selected.saturating_sub(1);
            }
            self.palette.selected = self.palette.selected.min(rows.len() - 1);
        }
        let mut chosen: Option<usize> = None;
        let mut edited = false;
        egui::Window::new(tr!("Command palette"))
            .title_bar(false)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_TOP, [0.0, 70.0])
            .fixed_size([620.0, 0.0])
            .show(ctx, |ui| {
                let edit = ui.add(
                    egui::TextEdit::singleline(&mut self.palette.query)
                        .hint_text(tr!(
                            "Type an action, or an address, MAC, name, vendor or finding id…"
                        ))
                        .desired_width(f32::INFINITY),
                );
                a11y::named(
                    edit.clone(),
                    tr!("Type an action, or an address, MAC, name, vendor or finding id…"),
                );
                if self.palette.focus {
                    edit.request_focus();
                    self.palette.focus = false;
                }
                if edit.changed() {
                    edited = true;
                    self.palette.selected = 0;
                }
                if edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    chosen = Some(self.palette.selected);
                }
                ui.add_space(4.0);
                if rows.is_empty() {
                    ui.weak(if self.busy.searching {
                        tr!("Searching the saved scans…")
                    } else {
                        tr!("Nothing matches.")
                    });
                }
                let mut shown_hits = false;
                for (k, row) in rows.iter().enumerate() {
                    let text = match row {
                        Row::Action(i) => entries[*i].label.clone(),
                        Row::Hit(i) => {
                            if !shown_hits {
                                shown_hits = true;
                                ui.separator();
                                ui.weak(tr!("Seen in the saved scans (newest first)"));
                            }
                            hit_text(&hits[*i])
                        }
                    };
                    if ui
                        .selectable_label(self.palette.selected == k, text)
                        .clicked()
                    {
                        chosen = Some(k);
                    }
                }
                if self.busy.searching && !rows.is_empty() {
                    ui.weak(tr!("Searching the saved scans…"));
                }
                ui.add_space(2.0);
                ui.weak(tr!("Up/Down choose · Enter runs · Esc closes"));
            });
        if edited {
            self.palette.edited = Some(Instant::now());
        }
        if let Some(at) = self.palette.edited {
            if at.elapsed() >= SEARCH_DELAY {
                self.palette.edited = None;
                self.ask_search();
            } else {
                ctx.request_repaint_after(SEARCH_DELAY);
            }
        }
        if let Some(k) = chosen.filter(|&k| k < rows.len()) {
            self.palette.open = false;
            match rows[k] {
                Row::Action(i) => self.run_command(ctx, entries[i].cmd),
                Row::Hit(i) => self.open_hit(&hits[i]),
            }
        }
    }

    /// Opens the scan a search hit is from and shows the host.
    fn open_hit(&mut self, hit: &search::Hit) {
        let ips: Vec<IpAddr> = hit.ip.into_iter().collect();
        if self.loaded_scan == Some(hit.scan_id)
            && ips
                .iter()
                .any(|ip| self.results.iter().any(|h| h.ip == *ip))
        {
            self.view = MainView::Hosts;
            self.focus_host(&ips);
            return;
        }
        if self.live() || self.busy.loading {
            self.error =
                tr!("The scan cannot be opened while a scan or capture is running.").into();
            return;
        }
        self.pending_focus = (!ips.is_empty()).then_some(ips);
        self.view = MainView::Hosts;
        self.submit(Job::Load(hit.scan_id));
    }

    pub(super) fn run_command(&mut self, ctx: &egui::Context, cmd: Cmd) {
        match cmd {
            Cmd::ScanMyNetwork => self.scan_my_network(),
            Cmd::StartScan => {
                if self.run.is_none() {
                    self.view = MainView::Hosts;
                    self.start();
                }
            }
            Cmd::StopScan => {
                if let Some(run) = &self.run {
                    run.cancel.store(true, Ordering::Relaxed);
                }
            }
            Cmd::ImportList => self.import_address_list(),
            Cmd::Overview => self.view = MainView::Home,
            Cmd::Hosts => self.view = MainView::Hosts,
            Cmd::Settings => self.settings_open = true,
            Cmd::Inventory => {
                self.history_open = true;
                self.refresh_history();
            }
            Cmd::Map => self.topology_open = true,
            Cmd::Findings => self.findings_open = true,
            Cmd::Devices => self.devices_open = true,
            Cmd::Workbench => self.open_workbench(),
            Cmd::Passive => self.capture_open = true,
            Cmd::About => self.about_open = true,
            Cmd::ExportCsv => self.export("csv"),
            Cmd::ExportJson => self.export("json"),
            Cmd::ExportHtml => self.export("html"),
            Cmd::ExportMarkdown => self.export("md"),
            Cmd::ClearResults => {
                if !self.live() && !self.busy.loading {
                    self.clear();
                }
            }
            Cmd::Preset(p) => self.apply_preset(p),
            Cmd::Language(l) => self.set_language(l.code()),
            Cmd::DarkTheme => self.set_dark(ctx, true),
            Cmd::LightTheme => self.set_dark(ctx, false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(query: &str) -> Vec<String> {
        let all = entries();
        rank(&all, query)
            .into_iter()
            .map(|i| all[i].label.clone())
            .collect()
    }

    #[test]
    fn a_substring_beats_scattered_letters_and_word_starts_beat_the_middle() {
        let sub = token_score("scan", "Start the scan").unwrap();
        let scattered = token_score("scan", "Show the clean archive now").unwrap();
        assert!(sub > scattered, "{sub} vs {scattered}");
        let start = token_score("set", "Settings window").unwrap();
        let middle = token_score("set", "Reset everything").unwrap();
        assert!(start > middle, "{start} vs {middle}");
        assert_eq!(token_score("zzz", "Settings"), None);
        assert_eq!(token_score("", "anything"), Some(0));
        // Case does not matter.
        assert_eq!(
            token_score("SET", "settings"),
            token_score("set", "SETTINGS")
        );
        // Letters must come in order.
        assert_eq!(token_score("gnits", "Settings"), None);
        assert!(
            token_score("stg", "Settings").is_some(),
            "fuzzy: letters in order"
        );
    }

    #[test]
    fn all_words_of_the_query_must_match() {
        assert!(score("export csv", "Export the visible rows as CSV…", "save file").is_some());
        assert!(
            score(
                "export banana",
                "Export the visible rows as CSV…",
                "save file"
            )
            .is_none()
        );
        // A word may match the keywords instead of the name.
        assert!(
            score(
                "compare",
                "Open the saved inventory",
                "history scans compare diff"
            )
            .is_some()
        );
        // The name counts more than the keywords.
        let by_name = score("map", "Open the network map", "topology graph").unwrap();
        let by_keyword = score("map", "Open the findings", "map").unwrap();
        assert!(by_name > by_keyword);
        assert_eq!(score("   ", "x", "y"), Some(0));
    }

    #[test]
    fn typing_a_few_letters_finds_the_action() {
        assert_eq!(
            labels("settings").first().map(String::as_str),
            Some("Open the scan settings")
        );
        assert!(
            labels("new scan")[0].contains("scan my network"),
            "{:?}",
            labels("new scan")
        );
        assert!(
            labels("export")
                .iter()
                .filter(|l| l.starts_with("Export"))
                .count()
                >= 4
        );
        assert!(labels("map")[0].contains("network map"));
        assert!(labels("dark")[0].contains("dark theme"));
        assert!(
            labels("full")[0].contains("Full audit"),
            "{:?}",
            labels("full")
        );
        assert!(labels("plant").iter().any(|l| l.contains("Plant")));
        assert!(labels("deutsch").iter().any(|l| l.contains("Deutsch")));
        assert!(labels("qqqqqq").is_empty());
    }

    #[test]
    fn the_list_is_capped_and_an_empty_query_lists_the_first_actions() {
        let all = entries();
        assert_eq!(rank(&all, "").len(), MAX_ACTIONS);
        assert_eq!(rank(&all, "")[0], 0);
        assert!(rank(&all, "o").len() <= MAX_ACTIONS);
        // Every action has a name and a distinct command.
        assert!(all.iter().all(|e| !e.label.is_empty()));
        let cmds: Vec<Cmd> = all.iter().map(|e| e.cmd).collect();
        for (i, c) in cmds.iter().enumerate() {
            assert!(!cmds[..i].contains(c), "{c:?} twice");
        }
    }

    #[test]
    fn german_names_are_found_in_german() {
        i18n::set(i18n::Lang::German);
        let found = labels("einstellungen");
        i18n::set(i18n::Lang::English);
        assert!(
            found.first().is_some_and(|l| l.contains("Einstellungen")),
            "{found:?}"
        );
    }

    #[test]
    fn a_search_hit_reads_as_who_where_and_when() {
        let hit = search::Hit {
            scan_id: 12,
            timestamp: 1_790_000_000,
            targets: "10.0.5.0/24".into(),
            source: "host",
            ip: Some("10.0.5.17".parse().unwrap()),
            mac: "00:0C:29:AA:BB:CC".into(),
            hostname: "plc-1".into(),
            vendor: "Siemens AG".into(),
            detail: "open 102".into(),
        };
        let text = hit_text(&hit);
        assert!(
            text.starts_with("10.0.5.17 · plc-1 · 00:0C:29:AA:BB:CC · Siemens AG"),
            "{text}"
        );
        assert!(text.contains("scan #12"), "{text}");
        let finding = search::Hit {
            source: "finding",
            detail: "telnet-open: Telnet".into(),
            ..hit
        };
        assert!(hit_text(&finding).contains("[telnet-open: Telnet]"));
    }
}
