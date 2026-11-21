mod a11y;
mod controls;
mod convenience;
mod demo;
mod details;
mod home;
mod i18n;
mod map;
mod ot;
mod palette;
mod preset_ui;
mod quick;
mod recording;
mod scheduler;
mod settings;
mod tables;
mod timeline;
mod updates;
mod windows;
mod workbench;

use crate::{devices, localnets, passive, risk, scan, store, topology, update};
use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};
use i18n::tr;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::IpAddr,
    path::PathBuf,
    sync::{atomic::Ordering, mpsc},
    time::{Duration, Instant},
};

#[derive(Default, Clone, Serialize, Deserialize)]
#[serde(default)]
struct Saved {
    settings: scan::Settings,
    favorites: Vec<String>,
    notes: BTreeMap<IpAddr, String>,
    /// CVE rules file merged over the built-in rules (like `--cves`); empty: the default rules.
    cves_file: String,
    /// Recurring scans while the window is open (off by default).
    schedule: crate::schedule::Schedule,
    /// Ask GitHub for the latest release once when the program starts (notify only, never
    /// downloads). Off unless the user turns it on.
    check_updates: bool,
    /// Starred devices (favorites), by MAC address or, without one, IP address. Kept here and
    /// not in the inventory: it is a setting of this computer (see `convenience`).
    starred: BTreeSet<String>,
    /// The chosen scan preset when it is the passive `plant` one (else empty: the picker shows
    /// the preset the settings equal).
    preset: String,
    /// Probe the addresses in random order.
    randomize: bool,
    /// Record each scan's traffic to `NetworkScope/recordings` (wire capture when possible).
    record_traffic: bool,
    /// `auto` (or empty: follow the system), `en` or `de`.
    language: String,
    /// Dark theme (light is the default).
    dark: bool,
    /// Interface scale on top of the system's scale factor; 0 means 1.0.
    zoom: f32,
    /// Adaptive TCP connect timing became the default after these preferences could already
    /// hold its old value; set once the saved settings were switched over (see [`Saved::migrate`]).
    adaptive_tcp_migrated: bool,
}
impl Saved {
    /// One-time changes to preferences saved by an older version. The saved `false` for
    /// adaptive TCP timing was never a choice (there was no checkbox), so it is switched on
    /// once; turning it off afterwards is remembered.
    fn migrate(&mut self) {
        if !self.adaptive_tcp_migrated {
            self.settings.tcp_adaptive = true;
            self.adaptive_tcp_migrated = true;
        }
    }
    /// What goes to disk: empty notes are dropped.
    fn to_disk(&self) -> Vec<u8> {
        let mut copy = self.clone();
        prune_notes(&mut copy.notes);
        serde_json::to_vec_pretty(&copy).unwrap_or_default()
    }
}
fn prune_notes(notes: &mut BTreeMap<IpAddr, String>) {
    notes.retain(|_, n| !n.trim().is_empty());
}
/// Stores an edited note; an empty note removes the entry instead of keeping a blank one.
fn set_note(notes: &mut BTreeMap<IpAddr, String>, ip: IpAddr, text: String) {
    if text.trim().is_empty() {
        notes.remove(&ip);
    } else {
        notes.insert(ip, text);
    }
}
fn saved_path() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("NetworkScope")
        .join("preferences.json")
}
fn write_prefs(bytes: &[u8]) -> Result<(), String> {
    let path = saved_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(path, bytes).map_err(|e| e.to_string())
}
/// The "Standard" preset and "Restore defaults": scan defaults, but the fields that describe
/// this machine (capture interface, source addresses, script and probe files) are kept.
fn standard_settings(current: &scan::Settings) -> scan::Settings {
    scan::Settings {
        interface: current.interface.clone(),
        source_ip: current.source_ip.clone(),
        source_mac: current.source_mac.clone(),
        scripts: current.scripts.clone(),
        probe_file: current.probe_file.clone(),
        ..scan::Settings::default()
    }
}

/// While a scan or capture is running, derived views refresh at most this often.
const LIVE_REFRESH: Duration = Duration::from_millis(500);
/// A value derived from results/observations, recomputed only when the data generation changed.
struct Cached<T> {
    generation: Option<u64>,
    at: Instant,
    value: T,
}
impl<T: Default> Default for Cached<T> {
    fn default() -> Self {
        Self {
            generation: None,
            at: Instant::now(),
            value: T::default(),
        }
    }
}
impl<T> Cached<T> {
    fn stale(&self, generation: u64, live: bool) -> bool {
        self.generation != Some(generation)
            && (!live || self.generation.is_none() || self.at.elapsed() >= LIVE_REFRESH)
    }
    fn set(&mut self, generation: u64, value: T) {
        self.generation = Some(generation);
        self.at = Instant::now();
        self.value = value;
    }
}

/// Lowercase text a host is searched by (notes are matched separately: they change on their own).
fn haystack(h: &scan::Host) -> String {
    format!(
        "{} {} {} {}",
        h.ip,
        h.hostname,
        serde_json::to_string(&h.identity).unwrap_or_default(),
        ports_text(&h.open)
    )
    .to_lowercase()
}
fn filter_rows(
    results: &[scan::Host],
    filter: Filter,
    query: &str,
    haystacks: &mut HashMap<IpAddr, String>,
    notes: &BTreeMap<IpAddr, String>,
    starred: &BTreeSet<String>,
) -> Vec<usize> {
    results
        .iter()
        .enumerate()
        .filter(|(_, h)| {
            (match filter {
                Filter::All => true,
                Filter::Responding => h.responding,
                Filter::Open => !h.open.is_empty(),
                Filter::Starred => starred.contains(&convenience::favorite_key(h)),
            }) && (query.is_empty()
                || haystacks
                    .entry(h.ip)
                    .or_insert_with(|| haystack(h))
                    .contains(query)
                || notes
                    .get(&h.ip)
                    .is_some_and(|n| n.to_lowercase().contains(query)))
        })
        .map(|(i, _)| i)
        .collect()
}

/// Inventory work that must not block the UI thread. One worker runs jobs in order, which also
/// serializes access to the SQLite file.
enum Job {
    Save(Box<store::Snapshot>, &'static str),
    List,
    Diff(i64, i64),
    Load(i64),
    ReadFile(PathBuf),
    WritePrefs(Vec<u8>),
    /// Formats a snapshot (json/csv/html/md) stamped with the given Unix time and writes it.
    Export(Box<store::Snapshot>, String, i64, PathBuf),
    /// Writes the OT asset table as CSV (true) or JSON (false).
    ExportAssets(Vec<crate::otpassive::Asset>, bool, PathBuf),
    /// Loads a script file/folder and runs it on a copy of the host (token, path, host).
    TestScript(u64, String, Box<scan::Host>),
    /// The timeline of one device (token, MAC or IP address): `store::device_history`.
    History(u64, String),
    /// The "what changed" overview (token, window).
    Home(u64, home::Window),
    /// The local IPv4 networks of this computer (`localnets::detect`).
    Networks,
    /// A search across the saved scans (token, query).
    Search(u64, String),
    /// The unknown-device workbench: group the unidentified banners of every saved scan.
    Groups(u64),
    /// A draft probe rule for one group (token, group).
    Draft(u64, Box<crate::service::workbench::Group>),
    /// Writes a draft probe file and its checklist (`FILE`, `FILE.checklist.md`).
    WriteDraft(Box<workbench::DraftView>, PathBuf),
}
enum Done {
    Saved(&'static str, usize, Result<i64, String>),
    Listed(Result<Vec<store::Entry>, String>),
    Diffed(Result<Vec<String>, String>),
    Loaded(i64, Result<Box<store::Snapshot>, String>),
    Read(Result<String, String>),
    PrefsWritten(Result<(), String>),
    Exported(PathBuf, Result<(), String>),
    ScriptTested(u64, Result<crate::script::Outcome, String>),
    History(u64, Result<Box<crate::devices::DeviceHistory>, String>),
    Home(u64, Result<Box<home::HomeData>, String>),
    Networks(Result<Vec<localnets::LocalNet>, String>),
    Searched(u64, Result<Box<crate::search::Results>, String>),
    Groups(u64, Result<Box<workbench::GroupsData>, String>),
    /// A draft (token, group id, result).
    Drafted(u64, String, Result<Box<workbench::DraftView>, String>),
    DraftWritten(Result<(String, String), String>),
}
fn write_file(path: &std::path::Path, data: Result<String, String>) -> Result<(), String> {
    data.and_then(|d| std::fs::write(path, d).map_err(|e| format!("{}: {e}", path.display())))
}
fn run_job(job: Job) -> Done {
    let path = store::default_path();
    match job {
        Job::Save(snapshot, kind) => Done::Saved(
            kind,
            snapshot.observations.len(),
            store::save(&path, &snapshot),
        ),
        Job::List => Done::Listed(store::list(&path)),
        Job::Diff(a, b) => Done::Diffed(
            store::load(&path, a)
                .and_then(|a| store::load(&path, b).and_then(|b| store::diff(&a, &b))),
        ),
        Job::Load(id) => Done::Loaded(id, store::load(&path, id).map(Box::new)),
        Job::ReadFile(file) => Done::Read(
            std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display())),
        ),
        Job::WritePrefs(bytes) => Done::PrefsWritten(write_prefs(&bytes)),
        Job::Export(snapshot, format, stamp, file) => {
            let result = write_file(&file, store::export_at(&snapshot, &format, stamp));
            Done::Exported(file, result)
        }
        Job::ExportAssets(assets, csv, file) => {
            let data = if csv {
                Ok(crate::otpassive::assets_csv(&assets))
            } else {
                crate::schema::list("ot-assets", "assets", &assets)
            };
            let result = write_file(&file, data);
            Done::Exported(file, result)
        }
        Job::TestScript(token, path, host) => Done::ScriptTested(
            token,
            crate::script::Scripts::load(&path).map(|s| s.dry_run(&host)),
        ),
        Job::History(token, query) => {
            Done::History(token, store::device_history(&path, &query).map(Box::new))
        }
        Job::Home(token, window) => Done::Home(
            token,
            home::compute(&path, window, unix_now()).map(Box::new),
        ),
        Job::Networks => Done::Networks(localnets::detect()),
        Job::Search(token, query) => Done::Searched(
            token,
            crate::search::search(&path, &query, 60).map(Box::new),
        ),
        Job::Groups(token) => Done::Groups(token, workbench::load_groups(&path)),
        Job::Draft(token, group) => {
            let id = group.id.clone();
            Done::Drafted(token, id, workbench::make_draft(&group))
        }
        Job::WriteDraft(view, file) => Done::DraftWritten(workbench::write_draft(&file, &view)),
    }
}
struct Worker {
    jobs: Option<mpsc::Sender<Job>>,
    done: mpsc::Receiver<Done>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Worker {
    fn start(ctx: egui::Context) -> Self {
        let (jobs, inbox) = mpsc::channel::<Job>();
        let (outbox, done) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            for job in inbox {
                if outbox.send(run_job(job)).is_err() {
                    break;
                }
                ctx.request_repaint();
            }
        });
        Self {
            jobs: Some(jobs),
            done,
            thread: Some(thread),
        }
    }
    /// Lets queued jobs (an in-flight inventory save in particular) finish.
    fn finish(&mut self) {
        self.jobs = None;
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
#[derive(Default)]
struct Busy {
    saving: usize,
    listing: bool,
    comparing: bool,
    loading: bool,
    importing: bool,
    prefs: bool,
    exporting: usize,
    testing: bool,
    history: bool,
    home: bool,
    detecting: bool,
    searching: bool,
    workbench: bool,
    drafting: bool,
    writing_draft: bool,
}
impl Busy {
    fn label(&self) -> Option<&'static str> {
        if self.saving > 0 {
            Some(tr!("Saving to inventory…"))
        } else if self.exporting > 0 {
            Some(tr!("Writing export…"))
        } else if self.testing {
            Some(tr!("Running script…"))
        } else if self.history {
            Some(tr!("Reading device history…"))
        } else if self.loading {
            Some(tr!("Opening inventory…"))
        } else if self.comparing {
            Some(tr!("Comparing scans…"))
        } else if self.detecting {
            Some(tr!("Looking for your networks…"))
        } else if self.listing {
            Some(tr!("Reading inventory…"))
        } else if self.workbench {
            Some(tr!("Grouping unidentified banners…"))
        } else if self.drafting || self.writing_draft {
            Some(tr!("Drafting a probe rule…"))
        } else if self.importing {
            Some(tr!("Reading address list…"))
        } else {
            None
        }
    }
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum Filter {
    Responding,
    All,
    Open,
    Starred,
}
/// The two main views: the "what changed" overview and the table of hosts.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Default)]
enum MainView {
    #[default]
    Home,
    Hosts,
}
/// The documentation page name of a finding rule id (`telnet-open`). The run-time id families
/// have one shared page each (`cve-...`, `script-...`); `cve-cve-2020-0796` has its own.
fn docs_page(id: &str) -> String {
    let lower = id.to_ascii_lowercase();
    if lower != "cve-cve-2020-0796" && lower.starts_with("cve-") {
        "cve-hints".into()
    } else if lower.starts_with("script-") {
        "script-findings".into()
    } else {
        lower
    }
}
fn docs_url(id: &str) -> String {
    format!(
        "https://sparkz400.github.io/network-scope/findings/{}.html",
        docs_page(id)
    )
}

const EXPLAIN: &str = include_str!("lang/explain.txt");

/// `page -> (English, German)` from `lang/explain.txt` (ROADMAP F41).
fn explanations() -> &'static BTreeMap<&'static str, (&'static str, &'static str)> {
    static TEXTS: std::sync::OnceLock<BTreeMap<&str, (&str, &str)>> = std::sync::OnceLock::new();
    TEXTS.get_or_init(|| {
        EXPLAIN
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .filter_map(|l| {
                let mut parts = l.split(" || ").map(str::trim);
                Some((parts.next()?, (parts.next()?, parts.next()?)))
            })
            .collect()
    })
}

/// The plain-language explanation of a finding rule id in the current language.
fn explanation(id: &str) -> Option<&'static str> {
    let (en, de) = explanations().get(docs_page(id).as_str())?;
    Some(match i18n::current() {
        i18n::Lang::English => en,
        i18n::Lang::German => de,
    })
}

/// A small "?" button that explains a finding in plain language: on hover, while it has keyboard
/// focus, and as its screen-reader name. Nothing when the rule has no explanation.
fn explain_button(ui: &mut egui::Ui, id: &str) {
    let Some(text) = explanation(id) else {
        return;
    };
    let response = ui.add(egui::Button::new(RichText::new("?").strong()).small());
    let response = a11y::named(response, &format!("{} {text}", tr!("Explain this:")));
    if response.has_focus() {
        response.show_tooltip_text(text);
    } else {
        response.on_hover_text(text);
    }
}
struct Scanner {
    saved: Saved,
    targets: String,
    results: Vec<scan::Host>,
    previous: BTreeMap<IpAddr, scan::Host>,
    run: Option<scan::Running>,
    filter: Filter,
    search: String,
    status: String,
    error: String,
    /// Why the CVE rules file in the settings could not be loaded; empty when it loaded.
    cves_error: String,
    /// The answer of the update check that runs at start (when enabled) while it is pending.
    update_check: Option<updates::Check>,
    /// A newer release that the check found; shown in the status bar until dismissed.
    update_notice: Option<update::Release>,
    update_open: bool,
    settings_open: bool,
    about_open: bool,
    selected: Option<IpAddr>,
    screenshot: Option<PathBuf>,
    frames: usize,
    screenshot_requested: bool,
    /// Top-left of the area below the menu and status panels, where windows without a fixed
    /// position open (egui 0.31 auto-placed them there; newer egui uses the whole screen).
    window_origin: egui::Pos2,
    /// Filled by the screenshot callback once the integration has read the frame back.
    screenshot_image: std::sync::Arc<std::sync::Mutex<Option<std::sync::Arc<egui::ColorImage>>>>,
    sort_column: usize,
    sort_reverse: bool,
    history_open: bool,
    topology_open: bool,
    devices_open: bool,
    findings_open: bool,
    capture_open: bool,
    history: Vec<store::Entry>,
    compare_a: Option<i64>,
    compare_b: Option<i64>,
    changes: Vec<String>,
    observations: Vec<passive::Observation>,
    observation_index: crate::observations::ObservationIndex,
    capture_selected: Option<usize>,
    listening: Option<passive::Listening>,
    interfaces: Vec<(String, String)>,
    capture_seconds: u64,
    capture_scope: String,
    capture_complete: bool,
    scan_complete: bool,
    scan_scope: String,
    scan_settings: scan::Settings,
    /// The IPv6 step after a finished scan (`--ipv6-discover`), running off the UI thread: it
    /// blocks for the echo's wait on every interface. Its answer is the host list with the IPv6
    /// results joined by MAC.
    ipv6_job: Option<mpsc::Receiver<(Vec<scan::Host>, crate::ipv6::Outcome)>>,
    /// Bumped whenever results (including their order) or observations change.
    generation: u64,
    /// Bumped whenever a note changes.
    notes_generation: u64,
    haystacks: HashMap<IpAddr, String>,
    /// Rows of hosts still being scanned (`scan::Event::Partial`), by address: the row index.
    live: HashMap<IpAddr, usize>,
    /// The traffic recording of the running scan (Settings: "Record the scan's traffic").
    recording: Option<recording::Recording>,
    rows: Vec<usize>,
    rows_key: Option<(u64, u64, Filter, String)>,
    responding: usize,
    with_open: usize,
    findings: Cached<Vec<risk::Finding>>,
    devices: Cached<Vec<devices::Device>>,
    topology: Cached<(topology::Graph, Vec<Vec<usize>>)>,
    worker: Worker,
    busy: Busy,
    prefs_written: Vec<u8>,
    prefs_dirty: Option<Instant>,
    /// Row of the main table to scroll to on the next frame (set from Findings/Devices).
    scroll_to: Option<IpAddr>,
    findings_view: tables::View,
    devices_view: tables::View,
    script_test: Option<ScriptTest>,
    script_tokens: u64,
    /// The device timeline window (opened from the host details).
    timeline: Option<timeline::Timeline>,
    timeline_tokens: u64,
    ot: ot::OtState,
    /// The unknown-device workbench window.
    workbench: workbench::WorkbenchState,
    /// Stored time of the inventory snapshot on screen; `None` for live results (exports are
    /// then stamped with the current time).
    opened_stamp: Option<i64>,
    /// When the schedule was enabled or its last scan started; the interval counts from here.
    schedule_anchor: Option<Instant>,
    /// What the scheduler is waiting for, shown in the settings.
    schedule_note: String,
    /// Why the scheduled targets cannot be scanned; empty when they parse.
    schedule_error: String,
    /// The scope guard wants a yes before this scan starts: what it found (public or
    /// out-of-scope addresses). Shown as a dialog; `None` when nothing is pending.
    scope_confirm: Option<(String, String)>,
    /// What the last scan sent, by packet kind and detail (saved with the scan).
    scan_sent: Vec<crate::sendlog::SentEntry>,
    /// Set for one call of `start` after the user confirmed the dialog.
    scope_consent: crate::scope::Consent,
    /// What the main area shows.
    view: MainView,
    home: home::HomeState,
    quick: quick::QuickState,
    /// The local networks of the last detection (for broadcast addresses).
    local_nets: Vec<localnets::LocalNet>,
    wake: Option<convenience::WakeRequest>,
    palette: palette::Palette,
    map: map::MapState,
    /// The id of the saved scan whose results are on screen (None: a live or unsaved scan).
    loaded_scan: Option<i64>,
    /// Show these hosts as soon as the scan being opened has loaded.
    pending_focus: Option<Vec<IpAddr>>,
    /// The zoom factor last applied to the context.
    zoom_applied: f32,
    /// Screenshot mode: scroll the settings to the appearance section.
    scroll_to_appearance: bool,
}
/// A script dry-run for the host in the details window.
struct ScriptTest {
    token: u64,
    ip: IpAddr,
    path: String,
    result: Option<Result<crate::script::Outcome, String>>,
}
impl Scanner {
    fn new(cc: &eframe::CreationContext<'_>, screenshot: Option<PathBuf>) -> Self {
        let mut style = (*cc.egui_ctx.global_style()).clone();
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(10.0, 6.0);
        cc.egui_ctx.set_global_style(style);
        let mut saved: Saved = if screenshot.is_none() {
            std::fs::read(saved_path())
                .ok()
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or_default()
        } else {
            Saved::default()
        };
        prune_notes(&mut saved.notes);
        // Taken before the migration, so a migrated file differs and is written right away.
        let prefs_written = saved.to_disk();
        saved.migrate();
        i18n::set(i18n::detect(&saved.language));
        let mut app = Self {
            saved,
            targets: "192.168.1.1-254".into(),
            results: vec![],
            previous: BTreeMap::new(),
            run: None,
            filter: Filter::Responding,
            search: String::new(),
            status: tr!("Ready to scan").into(),
            error: String::new(),
            cves_error: String::new(),
            update_check: None,
            update_notice: None,
            update_open: false,
            settings_open: false,
            about_open: false,
            selected: None,
            screenshot,
            frames: 0,
            screenshot_requested: false,
            screenshot_image: Default::default(),
            window_origin: egui::pos2(16.0, 16.0),
            sort_column: 0,
            sort_reverse: false,
            history_open: false,
            topology_open: false,
            devices_open: false,
            findings_open: false,
            capture_open: false,
            history: vec![],
            compare_a: None,
            compare_b: None,
            changes: vec![],
            observations: vec![],
            observation_index: Default::default(),
            capture_selected: None,
            listening: None,
            interfaces: vec![],
            capture_seconds: 60,
            capture_scope: String::new(),
            capture_complete: true,
            scan_complete: true,
            scan_scope: String::new(),
            scan_settings: scan::Settings::default(),
            ipv6_job: None,
            generation: 0,
            notes_generation: 0,
            haystacks: HashMap::new(),
            live: HashMap::new(),
            recording: None,
            rows: vec![],
            rows_key: None,
            responding: 0,
            with_open: 0,
            findings: Cached::default(),
            devices: Cached::default(),
            topology: Cached::default(),
            worker: Worker::start(cc.egui_ctx.clone()),
            busy: Busy::default(),
            prefs_written,
            prefs_dirty: None,
            scroll_to: None,
            findings_view: tables::View::default(),
            devices_view: tables::View::default(),
            script_test: None,
            script_tokens: 0,
            timeline: None,
            timeline_tokens: 0,
            ot: ot::OtState::default(),
            workbench: Default::default(),
            opened_stamp: None,
            schedule_anchor: None,
            schedule_note: String::new(),
            schedule_error: String::new(),
            scope_confirm: None,
            scan_sent: vec![],
            scope_consent: Default::default(),
            view: MainView::Home,
            home: Default::default(),
            quick: Default::default(),
            local_nets: vec![],
            wake: None,
            palette: Default::default(),
            map: Default::default(),
            loaded_scan: None,
            pending_focus: None,
            zoom_applied: 1.0,
            scroll_to_appearance: false,
        };
        i18n::set(i18n::detect(&app.saved.language));
        apply_theme(&cc.egui_ctx, app.saved.dark);
        if app.saved.zoom > 0.0 {
            cc.egui_ctx.set_zoom_factor(app.saved.zoom);
            app.zoom_applied = app.saved.zoom;
        }
        // A broken user CVE file is reported, not silently replaced by the built-in rules.
        if app.screenshot.is_none() {
            if app.saved.cves_file.trim().is_empty() {
                if let Some(warning) = risk::init_cves() {
                    app.error = warning;
                }
            } else {
                app.apply_cves_file();
                if !app.cves_error.is_empty() {
                    // Keep the default rules active and tell the user why the file is unused.
                    let _ = risk::init_cves();
                    app.error = format!(
                        "CVE rules file: {}; using the default rules instead",
                        app.cves_error
                    );
                }
            }
        }
        // Opt-in, never in screenshot mode: one request, in the background.
        if app.saved.check_updates && app.screenshot.is_none() {
            app.start_update_check(&cc.egui_ctx);
        }
        // The first view: what changed, read from the inventory in the background.
        app.refresh_home();
        if app.screenshot.is_some()
            && let Ok(state) = std::env::var("NETWORK_SCOPE_SCREENSHOT_STATE")
        {
            app.seed_demo(&state);
            // The theme and language the state asked for ("-dark", "-de").
            i18n::set(i18n::detect(&app.saved.language));
            apply_theme(&cc.egui_ctx, app.saved.dark);
            app.status = tr!("Ready to scan").into();
        }
        app
    }
    fn live(&self) -> bool {
        self.run.is_some() || self.listening.is_some()
    }
    fn submit(&mut self, job: Job) {
        match &job {
            Job::Save(..) => self.busy.saving += 1,
            Job::List => self.busy.listing = true,
            Job::Diff(..) => self.busy.comparing = true,
            Job::Load(_) => self.busy.loading = true,
            Job::ReadFile(_) => self.busy.importing = true,
            Job::WritePrefs(_) => self.busy.prefs = true,
            Job::Export(..) | Job::ExportAssets(..) => self.busy.exporting += 1,
            Job::TestScript(..) => self.busy.testing = true,
            Job::History(..) => self.busy.history = true,
            Job::Home(..) => self.busy.home = true,
            Job::Networks => self.busy.detecting = true,
            Job::Search(..) => self.busy.searching = true,
            Job::Groups(..) => self.busy.workbench = true,
            Job::Draft(..) => self.busy.drafting = true,
            Job::WriteDraft(..) => self.busy.writing_draft = true,
        }
        let sent = self
            .worker
            .jobs
            .as_ref()
            .is_some_and(|tx| tx.send(job).is_ok());
        if !sent {
            self.busy = Busy::default();
            self.error = "Background worker stopped; restart the program.".into();
        }
    }
    fn poll_jobs(&mut self) {
        while let Ok(done) = self.worker.done.try_recv() {
            match done {
                Done::Saved(kind, observations, result) => {
                    self.busy.saving = self.busy.saving.saturating_sub(1);
                    match result {
                        Ok(id) if kind == "capture" => {
                            self.status =
                                format!("{observations} observations · saved capture #{id}")
                        }
                        Ok(id) if kind == "ot" => {
                            self.status = tr!(
                                "OT passive: {} observations · saved capture #{}",
                                observations,
                                id
                            )
                        }
                        Ok(id) => {
                            self.status
                                .push_str(&format!(" · {}", tr!("saved #{}", id)));
                            if kind == "scan" {
                                if self.run.is_none() {
                                    self.loaded_scan = Some(id);
                                }
                                self.refresh_home();
                            }
                        }
                        Err(e) => self.error = tr!("Inventory could not be saved: {}", e),
                    }
                }
                Done::Listed(result) => {
                    self.busy.listing = false;
                    match result {
                        Ok(h) => self.history = h,
                        Err(e) => self.error = e,
                    }
                }
                Done::Diffed(result) => {
                    self.busy.comparing = false;
                    match result {
                        Ok(changes) if changes.is_empty() => {
                            self.changes = vec!["No observed changes.".into()]
                        }
                        Ok(changes) => self.changes = changes,
                        Err(e) => self.error = e,
                    }
                }
                Done::Loaded(id, result) => {
                    self.busy.loading = false;
                    match result {
                        Ok(_) if self.live() => {
                            self.error = format!(
                                "Inventory #{id} was not opened: a scan or capture is running."
                            )
                        }
                        Ok(snapshot) => self.open_snapshot(id, *snapshot),
                        Err(e) => self.error = e,
                    }
                }
                Done::Read(result) => {
                    self.busy.importing = false;
                    match result {
                        Ok(text) if self.run.is_none() => {
                            let list = crate::targets::from_list(&text);
                            if list.is_empty() {
                                self.error = tr!("The list has no addresses.").into();
                            } else {
                                self.targets = list;
                            }
                        }
                        Ok(_) => {
                            self.error = tr!("Address list ignored: a scan is running.").into()
                        }
                        Err(e) => self.error = e,
                    }
                }
                Done::PrefsWritten(result) => {
                    self.busy.prefs = false;
                    if let Err(e) = result {
                        self.error = format!("Preferences could not be saved: {e}");
                    }
                }
                Done::Exported(path, result) => {
                    self.busy.exporting = self.busy.exporting.saturating_sub(1);
                    match result {
                        Ok(()) => self.status = format!("Saved {}", path.display()),
                        Err(e) => self.error = format!("Export failed: {e}"),
                    }
                }
                Done::History(token, result) => {
                    self.busy.history = false;
                    // An answer for a window that was closed or asked again since is dropped.
                    if let Some(t) = self.timeline.as_mut().filter(|t| t.token == token) {
                        t.result = Some(result);
                    }
                }
                Done::Home(token, result) => self.home_loaded(token, result),
                Done::Networks(result) => self.networks_found(result),
                Done::Searched(token, result) => self.search_loaded(token, result),
                Done::Groups(token, result) => self.groups_loaded(token, result),
                Done::Drafted(token, group, result) => self.draft_made(token, group, result),
                Done::DraftWritten(result) => self.draft_written(result),
                Done::ScriptTested(token, result) => {
                    self.busy.testing = false;
                    // A test for another host (or one replaced since) is dropped.
                    if let Some(test) = self.script_test.as_mut().filter(|t| t.token == token) {
                        test.result = Some(result);
                    }
                }
            }
        }
    }
    /// Results and/or observations were replaced or reordered.
    fn data_changed(&mut self) {
        self.generation += 1;
    }
    fn recount(&mut self) {
        self.responding = self.results.iter().filter(|h| h.responding).count();
        self.with_open = self.results.iter().filter(|h| !h.open.is_empty()).count();
    }
    fn reset_observations(&mut self) {
        self.observations.clear();
        self.observation_index.clear();
        self.capture_selected = None;
    }
    fn open_snapshot(&mut self, id: i64, snapshot: store::Snapshot) {
        self.results = snapshot.hosts;
        self.observations = snapshot.observations;
        self.observation_index.clear();
        self.capture_selected = None;
        self.capture_scope = if self.observations.is_empty() {
            String::new()
        } else {
            snapshot.targets.clone()
        };
        self.capture_complete = snapshot.complete;
        self.scan_scope = if self.results.is_empty() && !self.observations.is_empty() {
            String::new()
        } else {
            snapshot.targets
        };
        self.scan_settings = snapshot.settings;
        self.scan_complete = snapshot.complete;
        self.scan_sent = snapshot.sent;
        self.selected = None;
        self.script_test = None;
        self.previous.clear();
        self.haystacks.clear();
        self.status = format!("Loaded inventory #{id}");
        self.opened_stamp = self
            .history
            .iter()
            .find(|e| e.id == id)
            .map(|e| e.timestamp);
        // A saved OT capture refills the OT asset table, as after `ot-listen`.
        if self.capture_scope.starts_with("ot-passive:") {
            self.ot.show_saved(
                &self.capture_scope,
                &self.observations,
                self.capture_complete,
            );
        }
        self.recount();
        self.sort();
        self.loaded_scan = Some(id);
        if let Some(ips) = self.pending_focus.take() {
            self.view = MainView::Hosts;
            self.focus_host(&ips);
        }
    }
    fn clear(&mut self) {
        self.results.clear();
        self.previous.clear();
        self.reset_observations();
        self.haystacks.clear();
        self.selected = None;
        self.script_test = None;
        self.scan_scope.clear();
        self.scan_sent.clear();
        self.capture_scope.clear();
        self.scan_complete = true;
        self.capture_complete = true;
        self.changes.clear();
        self.opened_stamp = None;
        self.loaded_scan = None;
        self.status = tr!("Ready to scan").into();
        self.recount();
        self.data_changed();
    }
    fn start(&mut self) {
        self.start_checked(false);
    }
    /// A scan nobody is watching (the scheduler): the same scope guard, but nobody can confirm,
    /// so what needs a yes is refused (no dialog, no stored consent is used) and the reason goes
    /// to the status line.
    fn start_unattended(&mut self) {
        self.start_checked(true);
    }
    fn start_checked(&mut self, unattended: bool) {
        if self.listening.is_some() || self.ot.capturing() {
            self.error = "Stop passive capture before starting an active scan.".into();
            return;
        }
        if self.busy.loading {
            self.error = tr!("Wait until the inventory scan has been opened.").into();
            return;
        }
        if self.saved.preset == preset_ui::PLANT {
            // The passive preset sends nothing: point to the listener instead of scanning.
            self.error = tr!(
                "The Plant preset is passive and sends no packets. Use Listen (OT) in Passive / DCP, or choose another preset to scan."
            )
            .into();
            if !unattended {
                self.capture_open = true;
            }
            return;
        }
        // Consent counts for this call only, whichever way it ends.
        let consent = if unattended {
            crate::scope::Consent::default()
        } else {
            std::mem::take(&mut self.scope_consent)
        };
        let parsed =
            scan::parse_hosts(&self.targets, self.saved.settings.skip_edges).and_then(|hosts| {
                scan::parse_ports(&self.saved.settings.ports).map(|ports| (hosts, ports))
            });
        match parsed {
            Ok((mut hosts, ports)) => {
                // The same scope check as the CLI (ROADMAP H54): public or out-of-scope
                // addresses need a yes in the confirmation dialog first.
                if let Some(text) = self.scope_check(&hosts, consent) {
                    if unattended {
                        self.error = format!("Scheduled scan not started. {text}");
                        return;
                    }
                    // The dialog remembers the targets it was shown for.
                    self.scope_confirm = Some((self.targets.clone(), text));
                    return;
                }
                // The same addresses, probed in random order (the order only).
                if self.saved.randomize {
                    crate::targets::shuffle(&mut hosts, crate::targets::fresh_seed());
                }
                if !unattended {
                    self.view = MainView::Hosts;
                }
                self.loaded_scan = None;
                // Passive observations stay: the Devices window merges them with this scan.
                self.previous = self.results.drain(..).map(|h| (h.ip, h)).collect();
                self.haystacks.clear();
                self.live.clear();
                self.selected = None;
                self.script_test = None;
                self.scan_complete = true;
                self.scan_scope = self.targets.clone();
                self.scan_settings = windows::settings_for_scan(&self.saved.settings);
                self.opened_stamp = None;
                self.scan_sent.clear();
                self.error.clear();
                self.status = tr!("Scanning {} addresses", hosts.len());
                self.recount();
                self.data_changed();
                let live_settings = scan::Settings {
                    partial_events: true,
                    record: self.saved.record_traffic,
                    ..self.saved.settings.clone()
                };
                // The wire capture starts before the scan sends its first packet.
                self.recording = self.saved.record_traffic.then(|| {
                    let dir = saved_path().with_file_name("recordings");
                    let _ = std::fs::create_dir_all(&dir);
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs());
                    recording::start(
                        recording::file_in(&dir, now),
                        &self.saved.settings.interface,
                        &hosts,
                    )
                });
                self.run = Some(scan::start(hosts, ports, live_settings));
            }
            Err(e) => self.error = e,
        }
    }
    /// `Some(description)` when the scope guard needs the user's confirmation for `hosts`.
    fn scope_check(&mut self, hosts: &[IpAddr], consent: crate::scope::Consent) -> Option<String> {
        let declared = match crate::scope::declared(None, crate::scope::default_path().as_deref()) {
            Ok(declared) => declared,
            // An unreadable scope file blocks the scan until the user confirms once.
            Err(_) if consent.out_of_scope => None,
            Err(e) => {
                return Some(format!(
                    "The scope file is invalid ({e}), so nothing is known to be in scope."
                ));
            }
        };
        match crate::scope::enforce(hosts, declared.as_ref(), consent, None) {
            Ok(_) => None,
            Err(_) => Some(crate::scope::assess(hosts, declared.as_ref()).describe()),
        }
    }
    /// The end of a scan: the results are final (the IPv6 step, if any, has run), they are saved
    /// to the inventory and the scan is over for the rest of the window.
    fn finish_scan(&mut self) {
        self.live.clear();
        self.run = None;
        self.data_changed();
        let snapshot = self.scan_snapshot();
        self.submit(Job::Save(Box::new(snapshot), "scan"));
    }
    /// Waits for the IPv6 step; true while it runs.
    fn poll_ipv6(&mut self) -> bool {
        let Some(job) = &self.ipv6_job else {
            return false;
        };
        match job.try_recv() {
            Ok((hosts, outcome)) => {
                self.ipv6_job = None;
                self.results = hosts;
                self.haystacks.clear();
                if let Some(run) = &self.run {
                    // the echoes are in the sent log now
                    self.scan_sent = run.sent.snapshot();
                }
                self.status = format!("{} · {}", self.status, outcome.summary());
                if !outcome.found.notes.is_empty() {
                    self.status = format!("{} ({})", self.status, outcome.found.notes.join("; "));
                }
                self.recount();
                self.sort();
                self.finish_scan();
                false
            }
            Err(mpsc::TryRecvError::Empty) => true,
            Err(mpsc::TryRecvError::Disconnected) => {
                self.ipv6_job = None;
                self.status = format!("{} · IPv6 discovery failed", self.status);
                self.finish_scan();
                false
            }
        }
    }
    fn poll(&mut self) {
        if self.poll_ipv6() {
            return;
        }
        let mut done = false;
        let mut changed = false;
        let mut recount = false;
        if let Some(run) = &self.run {
            for _ in 0..2048 {
                match run.receiver.try_recv() {
                    Ok(scan::Event::Partial(host)) => {
                        // A host that answered, or a port found open, before the host is done.
                        self.haystacks.remove(&host.ip);
                        match self.live.get(&host.ip).copied() {
                            Some(i) if self.results.get(i).is_some_and(|r| r.ip == host.ip) => {
                                self.results[i] = host;
                            }
                            _ => {
                                self.live.insert(host.ip, self.results.len());
                                self.results.push(host);
                            }
                        }
                        recount = true;
                        changed = true;
                    }
                    Ok(scan::Event::Host(host)) => {
                        self.haystacks.remove(&host.ip);
                        match self.live.remove(&host.ip) {
                            Some(i) if self.results.get(i).is_some_and(|r| r.ip == host.ip) => {
                                // Replaces the provisional row; the counters are redone below.
                                self.results[i] = host;
                                recount = true;
                            }
                            _ => {
                                self.responding += usize::from(host.responding);
                                self.with_open += usize::from(!host.open.is_empty());
                                self.results.push(host);
                            }
                        }
                        changed = true;
                    }
                    Ok(scan::Event::Error(e)) => {
                        self.error = e;
                        self.scan_complete = false;
                    }
                    Ok(scan::Event::Done) => {
                        done = true;
                        break;
                    }
                    Err(mpsc::TryRecvError::Disconnected) => {
                        self.scan_complete = false;
                        done = true;
                        break;
                    }
                    Err(_) => break,
                }
            }
            if done {
                self.scan_sent = run.sent.snapshot();
                self.status = format!(
                    "{} · {} of {} addresses · {:.1}s · {} packets sent",
                    if run.cancel.load(Ordering::Relaxed) {
                        "Stopped"
                    } else {
                        "Complete"
                    },
                    self.results.len(),
                    run.total,
                    run.started.elapsed().as_secs_f32(),
                    crate::sendlog::total(&self.scan_sent)
                );
                // The recording ends with the scan; its result follows the scan summary.
                if let Some(rec) = self.recording.take() {
                    let recorded = rec.finish(run.sent.recorder());
                    self.status = format!("{} · {recorded}", self.status);
                }
            }
        }
        if recount {
            self.recount();
        }
        if changed {
            // Sorted once per batch of new hosts, never on idle frames.
            self.sort();
        }
        if done {
            self.scan_complete &= self
                .run
                .as_ref()
                .map(|r| !r.cancel.load(Ordering::Relaxed))
                .unwrap_or(false);
            // IPv6 discovery of the local link (opt-in; also in Safe Mode, one echo per interface):
            // after a complete scan, on a worker thread, joined to the hosts by MAC. A stopped
            // scan does not start it. The scan stays "running" until it has answered.
            if self.scan_complete
                && self.scan_settings.ipv6_discover
                && let Some(run) = &self.run
            {
                let (tx, rx) = mpsc::channel();
                let (settings, sent) = (self.scan_settings.clone(), run.sent.clone());
                let mut hosts = self.results.clone();
                std::thread::spawn(move || {
                    let outcome = crate::ipv6::after_scan(
                        &settings,
                        sent,
                        &mut hosts,
                        crate::ipv6::AddHosts::Fresh,
                    );
                    let _ = tx.send((hosts, outcome));
                });
                self.ipv6_job = Some(rx);
                self.status = format!("{} · IPv6 discovery…", self.status);
            } else {
                self.finish_scan();
            }
        }
    }
    fn sort(&mut self) {
        self.results.sort_by(|a, b| {
            let order = match self.sort_column {
                1 => b.responding.cmp(&a.responding),
                2 => a.ping.unwrap_or(u32::MAX).cmp(&b.ping.unwrap_or(u32::MAX)),
                3 => a.hostname.cmp(&b.hostname),
                4 => a.open.cmp(&b.open),
                _ => a.ip.cmp(&b.ip),
            }
            .then_with(|| a.ip.cmp(&b.ip));
            if self.sort_reverse {
                order.reverse()
            } else {
                order
            }
        });
        // Rows moved: the provisional ones are found again by address.
        if !self.live.is_empty() {
            let live: HashMap<IpAddr, usize> = self
                .results
                .iter()
                .enumerate()
                .filter(|(_, h)| self.live.contains_key(&h.ip))
                .map(|(i, h)| (h.ip, i))
                .collect();
            self.live = live;
        }
        self.data_changed();
    }
    /// Recomputes the visible row list only when data, notes, filter or query changed.
    fn refresh_rows(&mut self) {
        let query = self.search.to_lowercase();
        let key = (self.generation, self.notes_generation, self.filter, query);
        if self.rows_key.as_ref() == Some(&key) {
            return;
        }
        self.rows = filter_rows(
            &self.results,
            self.filter,
            &key.3,
            &mut self.haystacks,
            &self.saved.notes,
            &self.saved.starred,
        );
        self.rows_key = Some(key);
    }
    fn export(&mut self, extension: &str) {
        let Some(path) = rfd::FileDialog::new()
            .set_file_name(format!("network-scan.{extension}"))
            .add_filter("Scan results", &[extension])
            .save_file()
        else {
            return;
        };
        self.refresh_rows();
        let mut snapshot = self.snapshot();
        snapshot.hosts = self.rows.iter().map(|&i| self.results[i].clone()).collect();
        let stamp = self.opened_stamp.unwrap_or_else(unix_now);
        // Formatting and writing happen on the worker; the dialog stays on this thread.
        self.status = format!("Writing {}…", path.display());
        self.submit(Job::Export(
            Box::new(snapshot),
            extension.to_string(),
            stamp,
            path,
        ));
    }
    /// Selects a host of the active results (first of `ips` that is one), makes its row visible
    /// in the main table and opens its details.
    fn focus_host(&mut self, ips: &[IpAddr]) {
        let Some(ip) = ips
            .iter()
            .copied()
            .find(|ip| self.results.iter().any(|h| h.ip == *ip))
        else {
            self.status = format!(
                "{} is not in the active scan results (seen passively only)",
                ips.first()
                    .map_or("This device".to_string(), |ip| ip.to_string())
            );
            return;
        };
        if self.selected != Some(ip) {
            self.script_test = None;
        }
        self.selected = Some(ip);
        self.refresh_rows();
        if !self.rows.iter().any(|&i| self.results[i].ip == ip) {
            // Hidden by the filter or the search: show everything so the row can be reached.
            self.filter = Filter::All;
            self.search.clear();
        }
        self.scroll_to = Some(ip);
    }
    /// Saves preferences in the background shortly after the user stops interacting.
    fn save_prefs_debounced(&mut self, ctx: &egui::Context) {
        if self.screenshot.is_some() {
            return;
        }
        if ctx.input(|i| !i.events.is_empty()) {
            self.prefs_dirty = Some(Instant::now());
        }
        let Some(since) = self.prefs_dirty else {
            return;
        };
        let wait = Duration::from_secs(1);
        if since.elapsed() < wait || self.busy.prefs {
            ctx.request_repaint_after(wait);
            return;
        }
        self.prefs_dirty = None;
        let bytes = self.saved.to_disk();
        if bytes != self.prefs_written {
            self.prefs_written = bytes.clone();
            self.submit(Job::WritePrefs(bytes));
        }
    }
}

/// Initial window size from the size of its content area. Since egui 0.32 `default_size` and
/// friends include the title bar and frame, which 0.31 added on top; this keeps windows as large
/// as before.
fn win_size(content: [f32; 2]) -> egui::Vec2 {
    egui::vec2(content[0] + 12.0, content[1] + 45.0)
}
/// egui's own default content size of a window, as an outer size (see [`win_size`]).
fn default_win_size() -> egui::Vec2 {
    win_size([340.0, 420.0])
}

/// Light or dark colours, with a thicker outline on the widget that has keyboard focus (egui
/// draws a focused widget with its "active" look, so the outline is what makes Tab visible).
fn apply_theme(ctx: &egui::Context, dark: bool) {
    let mut visuals = if dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    visuals.widgets.active.bg_stroke.width = 2.0;
    visuals.selection.stroke.width = 2.0;
    ctx.set_visuals(visuals);
}
/// The scale factors the interface scale setting accepts (on top of the system's factor).
const ZOOM_RANGE: std::ops::RangeInclusive<f32> = 0.75..=2.0;

impl Scanner {
    /// Applies the interface scale setting when it changed.
    fn apply_zoom(&mut self, ctx: &egui::Context) {
        let wanted = if self.saved.zoom > 0.0 {
            self.saved
                .zoom
                .clamp(*ZOOM_RANGE.start(), *ZOOM_RANGE.end())
        } else {
            1.0
        };
        if (wanted - self.zoom_applied).abs() > f32::EPSILON {
            ctx.set_zoom_factor(wanted);
            self.zoom_applied = wanted;
        }
    }
    /// Changes the theme and remembers it.
    fn set_dark(&mut self, ctx: &egui::Context, dark: bool) {
        self.saved.dark = dark;
        apply_theme(ctx, dark);
    }
    /// Changes the language (`auto`, `en` or `de`) and remembers it.
    fn set_language(&mut self, code: &str) {
        self.saved.language = code.to_string();
        i18n::set(i18n::detect(code));
    }
    /// The file picker for an address list (read in the background; `#` comments allowed).
    fn import_address_list(&mut self) {
        if self.run.is_some() || self.busy.importing {
            return;
        }
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("Address list", &["txt", "csv", "lst"])
            .pick_file()
        {
            // Read in the background; large lists must not freeze the window.
            self.submit(Job::ReadFile(path));
        }
    }
}

impl eframe::App for Scanner {
    /// Runs before every `ui` call and also while the window is hidden, so background jobs,
    /// scans and captures keep draining their channels.
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_jobs();
        self.poll();
        self.poll_capture();
        self.poll_ot();
        self.poll_schedule(ctx);
        if self.live() || self.ot.running() {
            ctx.request_repaint_after(Duration::from_millis(16));
        }
    }
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = &ui.ctx().clone();
        windows::set_dark_mode(ui.visuals().dark_mode);
        // A link from the last frame that could not be opened.
        if let Some(e) = convenience::take_link_error() {
            self.error = e;
        }
        self.poll_update();
        self.apply_zoom(ctx);
        self.controls(ui);
        egui::Panel::bottom("status").show(ui, |ui| {
            if let Some(run) = &self.run {
                let label = if run.cancel.load(Ordering::Relaxed) {
                    tr!("Stopping…")
                } else if run.pause.load(Ordering::Relaxed) {
                    tr!("Paused")
                } else {
                    tr!("Scanning")
                };
                ui.add(
                    egui::ProgressBar::new(self.results.len() as f32 / run.total.max(1) as f32)
                        .text(format!(
                            "{label} · {} / {} · {:.1}s",
                            self.results.len(),
                            run.total,
                            run.started.elapsed().as_secs_f32()
                        )),
                );
            }
            // Read from the live settings every frame, so changing Settings, the preset or the
            // targets changes the indicator at once; a running scan keeps its own snapshot.
            let badge = cached_badge(
                &self.saved.settings,
                &self.targets,
                self.saved.preset == preset_ui::PLANT,
            );
            if safe_mode_indicator(ui, &badge) {
                self.settings_open = true;
            }
            ui.horizontal(|ui| {
                if let Some(busy) = self.busy.label() {
                    ui.spinner();
                    ui.label(busy);
                }
                // Hovering the status line also lists what the Safe Mode badge limits.
                let status = ui.label(&self.status);
                if !self.scan_sent.is_empty() {
                    // The scan summary: every kind of packet the scan sent, with counts.
                    status.on_hover_text(crate::sendlog::format_table(&self.scan_sent));
                }
                self.update_notice_ui(ui);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(tr!(
                        "{} responding · {} with open ports",
                        self.responding,
                        self.with_open
                    ));
                });
            });
        });
        self.refresh_rows();
        self.window_origin = ui.available_rect_before_wrap().min + egui::vec2(16.0, 16.0);
        let mut menu: Option<(usize, convenience::MenuAction)> = None;
        egui::CentralPanel::default().show(ui, |ui| {
            if self.view == MainView::Home {
                self.home_view(ui);
                return;
            }
            let visible = std::mem::take(&mut self.rows);
            let mut sort = None;
            let scroll_row = self.scroll_to.take().and_then(|ip| {
                visible
                    .iter()
                    .position(|&i| self.results.get(i).is_some_and(|h| h.ip == ip))
            });
            let mut table = TableBuilder::new(ui);
            if let Some(row) = scroll_row {
                table = table.scroll_to_row(row, Some(egui::Align::Center));
            }
            table
                .striped(true)
                .resizable(true)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::initial(135.0).at_least(80.0))
                .column(Column::initial(110.0))
                .column(Column::initial(65.0))
                .column(Column::remainder().at_least(80.0))
                .column(Column::initial(140.0))
                .header(26.0, |mut row| {
                    for (i, name) in [
                        tr!("IP address"),
                        tr!("Status"),
                        tr!("Ping"),
                        tr!("Hostname"),
                        tr!("Open TCP ports"),
                    ]
                    .iter()
                    .enumerate()
                    {
                        row.col(|ui| {
                            if ui.selectable_label(self.sort_column == i, *name).clicked() {
                                sort = Some(i);
                            }
                        });
                    }
                })
                .body(|body| {
                    body.rows(26.0, visible.len(), |mut row| {
                        let index = visible[row.index()];
                        let host = &self.results[index];
                        row.col(|ui| {
                            let starred = self
                                .saved
                                .starred
                                .contains(&convenience::favorite_key(host));
                            let shown = if starred {
                                format!("★ {}", host.ip)
                            } else {
                                host.ip.to_string()
                            };
                            let response =
                                ui.selectable_label(self.selected == Some(host.ip), shown);
                            if response.clicked() {
                                if self.selected != Some(host.ip) {
                                    self.script_test = None;
                                }
                                self.selected = Some(host.ip);
                            }
                            // Right click (or the menu key): open, ping, favorite, Wake-on-LAN.
                            response.context_menu(|ui| {
                                menu = Some((index, convenience::host_menu(ui, host, starred)));
                            });
                        });
                        row.col(|ui| {
                            ui.colored_label(
                                if host.responding {
                                    Color32::from_rgb(40, 150, 95)
                                } else {
                                    Color32::from_gray(115)
                                },
                                host_status(host),
                            );
                        });
                        row.col(|ui| {
                            ui.label(ping_text(host.ping));
                        });
                        row.col(|ui| {
                            ui.label(if host.hostname.is_empty() {
                                "—"
                            } else {
                                &host.hostname
                            });
                        });
                        row.col(|ui| {
                            ui.label(if host.ports_checked {
                                ports_text(&host.open)
                            } else {
                                tr!("Not checked").into()
                            });
                        });
                    });
                });
            let empty = visible.is_empty();
            self.rows = visible;
            if let Some(column) = sort {
                if self.sort_column == column {
                    self.sort_reverse = !self.sort_reverse;
                } else {
                    self.sort_column = column;
                    self.sort_reverse = false;
                }
                self.sort();
            }
            if empty {
                // Overlay the empty state without inserting fake scan results.
                let center = ui.max_rect().center();
                ui.painter().text(
                    center - egui::vec2(0.0, 8.0),
                    egui::Align2::CENTER_CENTER,
                    if self.results.is_empty() && self.run.is_none() {
                        tr!("Discover devices on your network")
                    } else {
                        tr!("No hosts match this view")
                    },
                    egui::FontId::proportional(18.0),
                    ui.visuals().text_color(),
                );
                ui.painter().text(
                    center + egui::vec2(0.0, 20.0),
                    egui::Align2::CENTER_CENTER,
                    if self.run.is_some() {
                        tr!("Results appear as each host finishes.")
                    } else if self.results.is_empty() {
                        tr!("Enter addresses and choose Start to begin.")
                    } else {
                        tr!("Try All hosts or clear the search.")
                    },
                    egui::FontId::proportional(13.0),
                    ui.visuals().weak_text_color(),
                );
            }
        });
        if let Some((index, act)) = menu {
            let host = self.results[index].clone();
            self.do_menu_action(ctx, &host, act);
        }
        self.settings(ctx);
        self.update_window(ctx);
        self.details(ctx);
        self.timeline_window(ctx);
        self.workbench_window(ctx);
        self.inventory_window(ctx);
        self.map_window(ctx);
        self.devices_window(ctx);
        self.findings_window(ctx);
        self.capture_window(ctx);
        self.scope_dialog(ctx);
        self.quick_dialog(ctx);
        self.wake_dialog(ctx);
        self.palette_window(ctx);
        self.save_prefs_debounced(ctx);
        if self.live() || self.ot.running() || self.screenshot.is_some() {
            ctx.request_repaint_after(Duration::from_millis(16));
        }
        self.frames += 1;
        // egui_glow panics when it reads back a zero-sized framebuffer, which happens if the
        // window is still being sized or was minimized; wait until it has a real size.
        let drawable = ctx.input(|i| {
            let r = i.viewport_rect();
            r.width() >= 1.0 && r.height() >= 1.0 && i.viewport().minimized != Some(true)
        });
        if self.screenshot.is_some() && self.frames >= 120 && drawable && !self.screenshot_requested
        {
            self.screenshot_requested = true;
            // The image arrives through a callback; keep it for the next frame and wake it up.
            let slot = std::sync::Arc::clone(&self.screenshot_image);
            let repaint = ctx.clone();
            ctx.request_screenshot(move |image| {
                if let Ok(mut slot) = slot.lock() {
                    *slot = Some(image);
                }
                repaint.request_repaint();
            });
        }
        if let Some(path) = &self.screenshot {
            let taken = self.screenshot_image.lock().ok().and_then(|mut s| s.take());
            if let Some(image) = taken {
                let pixels: Vec<u8> = image.pixels.iter().flat_map(|p| p.to_array()).collect();
                if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                    let _ = std::fs::create_dir_all(parent);
                }
                match image::save_buffer(
                    path,
                    &pixels,
                    image.size[0] as u32,
                    image.size[1] as u32,
                    image::ColorType::Rgba8,
                ) {
                    Ok(()) => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
                    Err(e) => {
                        self.error = format!("Screenshot failed: {e}");
                        eprintln!("{}", self.error);
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                }
            }
        }
    }
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if let Some(run) = &self.run {
            run.cancel.store(true, Ordering::Relaxed);
        }
        // A running OT capture stops and hands over what it has (bounded wait).
        let ot_partial = self.ot.stop_for_exit(Duration::from_secs(3));
        // Queued saves finish first; the worker owns the database until then.
        self.worker.finish();
        if self.screenshot.is_some() {
            return;
        }
        let path = store::default_path();
        if self.run.is_some() {
            let mut snapshot = self.scan_snapshot();
            snapshot.complete = false;
            if let Err(e) = store::save(&path, &snapshot) {
                eprintln!("Could not save interrupted scan: {e}");
            }
        }
        if self.listening.is_some() {
            let mut snapshot = self.capture_snapshot();
            snapshot.complete = false;
            if let Err(e) = store::save(&path, &snapshot) {
                eprintln!("Could not save interrupted capture: {e}");
            }
        }
        if let Some((label, observations)) = ot_partial.filter(|(_, o)| !o.is_empty()) {
            let snapshot = store::Snapshot {
                sent: vec![],
                targets: label,
                complete: false,
                settings: Default::default(),
                hosts: vec![],
                observations,
                notes: Default::default(),
            };
            if let Err(e) = store::save(&path, &snapshot) {
                eprintln!("Could not save interrupted OT capture: {e}");
            }
        }
        if let Err(e) = write_prefs(&self.saved.to_disk()) {
            eprintln!("Could not save preferences: {e}");
        }
    }
}
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}
fn ports_text(ports: &[u16]) -> String {
    if ports.is_empty() {
        "—".into()
    } else {
        ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}
fn ping_text(ping: Option<u32>) -> String {
    ping.map(|p| {
        if p == 0 {
            "<1 ms".into()
        } else {
            format!("{p} ms")
        }
    })
    .unwrap_or_else(|| "—".into())
}
/// The Safe Mode indicator (ROADMAP F43): the traffic profile and what the next scan is about to
/// send, taken from the dry-run plan (`plan::scan`, as `scan --dry-run` prints it), so it lists
/// exactly the packet kinds the scan engine would send with these settings.
#[derive(Clone)]
struct SafeBadge {
    safe: bool,
    label: &'static str,
    /// What is sent, as short translated names (`ICMP echo, TCP connect`).
    sends: String,
    tooltip: String,
}
/// The badge for the current settings. `targets` only decides whether IPv6 hosts are planned
/// too; `plant` is the passive Plant preset, which sends nothing.
fn safe_badge(s: &scan::Settings, targets: &str, plant: bool) -> SafeBadge {
    let (label, protections) = if s.safe {
        (
            tr!("Safe Mode"),
            tr!(
                "At most 8 hosts at a time, at least 100 ms between probes; SYN, ARP sweep and TCP/UDP traceroute are off."
            )
            .to_string(),
        )
    } else {
        let workers = s.workers.clamp(1, 4096);
        (
            tr!("Safe Mode off"),
            if s.max_rate > 0 {
                tr!(
                    "Up to {} hosts at a time, at most {} packets per second.",
                    workers,
                    s.max_rate
                )
            } else {
                tr!("Up to {} hosts at a time, no rate cap.", workers)
            },
        )
    };
    let mut tip = vec![protections];
    let mut kinds: Vec<crate::sendlog::PacketKind> = vec![];
    if plant {
        tip.push(tr!("The Plant preset is passive: Start sends nothing.").into());
    } else {
        let ports = scan::parse_ports(&s.ports).unwrap_or_else(|e| {
            tip.push(tr!("The port list is invalid: {}", e));
            vec![]
        });
        // One documentation address per family stands for every host: the plan of a host depends
        // on the settings and the address family only.
        let mut hosts = vec![IpAddr::from([192, 0, 2, 1])];
        if targets.contains(':') {
            hosts.push("2001:db8::1".parse().unwrap_or(hosts[0]));
        }
        let mut plans: Vec<crate::plan::HostPlan> =
            crate::plan::scan(hosts.into_iter(), &ports, s, None)
                .into_iter()
                .map(|g| g.plan)
                .collect();
        plans.extend(crate::plan::ipv6_discovery(s));
        tip.push(tr!("Per host, as the dry run lists it:").into());
        for p in &plans {
            for packet in &p.packets {
                if !kinds.contains(&packet.kind) {
                    kinds.push(packet.kind);
                }
            }
            tip.extend(p.lines().into_iter().map(|l| format!("  {l}")));
        }
    }
    tip.push(tr!("Click to open Settings.").into());
    let sends = if kinds.is_empty() {
        tr!("nothing").to_string()
    } else {
        kinds
            .into_iter()
            .map(packet_name)
            .collect::<Vec<_>>()
            .join(", ")
    };
    SafeBadge {
        safe: s.safe && !plant,
        label,
        sends,
        tooltip: tip.join(
            "
",
        ),
    }
}
/// A short name for a kind of packet, for people who are not network specialists.
fn packet_name(kind: crate::sendlog::PacketKind) -> &'static str {
    use crate::sendlog::PacketKind as K;
    match kind {
        K::IcmpEcho => tr!("ICMP echo (ping)"),
        K::ArpRequest => tr!("ARP requests"),
        K::NeighborLookup => tr!("neighbour lookup"),
        K::TcpConnect => tr!("TCP connect"),
        K::TcpSyn => tr!("TCP SYN"),
        K::UdpProbe => tr!("UDP probes"),
        K::ServiceProbe => tr!("service probes"),
        K::HttpRequest => tr!("HTTP requests"),
        K::TlsClientHello => tr!("TLS handshakes"),
        K::SmbNegotiate => tr!("SMB negotiation"),
        K::RdpNegotiate => tr!("RDP negotiation"),
        K::SshBanner => tr!("SSH handshakes"),
        K::OtRequest => tr!("read-only OT queries"),
        K::DcpIdentify => tr!("PROFINET DCP"),
        K::Traceroute => tr!("traceroute"),
        K::DhcpDiscover => tr!("DHCP discover"),
        K::Ipv6Echo => tr!("IPv6 echo"),
        K::SnmpRequest => tr!("SNMP reads"),
        K::DnsLookup => tr!("DNS lookups"),
        K::WakeOnLan => tr!("Wake-on-LAN"),
    }
}
/// `safe_badge`, recomputed only when the settings, the target families, the preset or the
/// language changed (the status bar is drawn every frame while a scan runs).
fn cached_badge(s: &scan::Settings, targets: &str, plant: bool) -> SafeBadge {
    thread_local! {
        static CACHE: std::cell::RefCell<Option<(String, SafeBadge)>> = const { std::cell::RefCell::new(None) };
    }
    let key = format!(
        "{}|{}|{plant}|{}",
        serde_json::to_string(s).unwrap_or_default(),
        targets.contains(':'),
        i18n::current().code()
    );
    CACHE.with(|c| {
        let mut c = c.borrow_mut();
        match &*c {
            Some((k, badge)) if *k == key => badge.clone(),
            _ => {
                let badge = safe_badge(s, targets, plant);
                *c = Some((key, badge.clone()));
                badge
            }
        }
    })
}
/// The always visible Safe Mode indicator: a button with the profile (opens Settings) and, next to
/// it, what the scan is about to send. Wraps on narrow windows; the tooltip has the whole plan.
/// Returns whether the button was clicked.
fn safe_mode_indicator(ui: &mut egui::Ui, badge: &SafeBadge) -> bool {
    let color = badge_color(badge.safe, ui.visuals().dark_mode);
    let sends = tr!("Sends: {}", badge.sends);
    ui.horizontal_wrapped(|ui| {
        let button = ui.add(egui::Button::new(
            RichText::new(badge.label).strong().color(color),
        ));
        let button = a11y::named(button, &format!("{}. {sends}", badge.label));
        let clicked = button.clicked();
        // Keyboard users get the plan while the button has focus, mouse users on hover.
        if button.has_focus() {
            button.show_tooltip_text(&badge.tooltip);
        } else {
            button.on_hover_text(&badge.tooltip);
        }
        ui.label(sends).on_hover_text(&badge.tooltip);
        clicked
    })
    .inner
}
/// Green for Safe Mode, amber when it is off; darker shades on the light theme, lighter on the dark one.
fn badge_color(safe: bool, dark: bool) -> Color32 {
    match (safe, dark) {
        (true, false) => Color32::from_rgb(20, 110, 60),
        (true, true) => Color32::from_rgb(110, 210, 140),
        (false, false) => Color32::from_rgb(165, 95, 0),
        (false, true) => Color32::from_rgb(255, 190, 70),
    }
}
fn host_status(host: &scan::Host) -> &'static str {
    if host.responding {
        tr!("Responding")
    } else if host.errors.iter().any(|e| scan::is_unused_note(e)) {
        // It wins over other notes: on Linux an unprivileged scan also notes that ICMP is not
        // permitted, and that is not what went wrong with this address.
        tr!("Unused (no ARP answer)")
    } else if !host.errors.is_empty() {
        tr!("Probe error")
    } else {
        tr!("No reply")
    }
}
pub fn run(screenshot: Option<PathBuf>) -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            // Screenshot states show the larger windows; the plain screenshot keeps the default.
            .with_inner_size(
                if screenshot.is_some()
                    && std::env::var("NETWORK_SCOPE_SCREENSHOT_STATE")
                        .is_ok_and(|s| !s.contains("-small"))
                {
                    [1100.0, 720.0]
                } else {
                    [800.0, 450.0]
                },
            )
            .with_min_inner_size([700.0, 400.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Network Scope",
        options,
        Box::new(move |cc| Ok(Box::new(Scanner::new(cc, screenshot)))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn host(ip: &str, responding: bool, open: Vec<u16>, hostname: &str) -> scan::Host {
        scan::Host {
            ip: ip.parse().unwrap(),
            responding,
            ping: None,
            ttl: None,
            hostname: hostname.into(),
            mac: String::new(),
            open,
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity: BTreeMap::from([("Modbus.Vendor".into(), "ACME PLC".into())]),
            udp_open: vec![],
            trace: vec![],
        }
    }

    #[test]
    fn an_unused_address_is_not_shown_as_a_probe_error() {
        let mut h = host("10.0.0.9", false, vec![], "");
        assert_eq!(host_status(&h), "No reply");
        h.errors = vec![scan::UNUSED_ADDRESS_NOTE.into()];
        assert_eq!(host_status(&h), "Unused (no ARP answer)");
        h.errors = vec![
            "ICMP needs root or net.ipv4.ping_group_range".into(),
            scan::UNUSED_AFTER_PROBES_NOTE.into(),
        ];
        assert_eq!(
            host_status(&h),
            "Unused (no ARP answer)",
            "Linux, unprivileged"
        );
        h.errors = vec!["TCP 80: refused by policy".into()];
        assert_eq!(host_status(&h), "Probe error");
    }

    #[test]
    fn safe_badge_describes_the_active_profile() {
        let safe = safe_badge(
            &scan::Settings {
                safe: true,
                syn: true,
                max_rate: 500,
                ..Default::default()
            },
            "10.0.0.0/24",
            false,
        );
        assert!(safe.safe);
        assert_eq!(safe.label, "Safe Mode");
        assert!(
            safe.tooltip
                .starts_with("At most 8 hosts at a time, at least 100 ms between probes;")
        );
        assert!(
            !safe.tooltip.contains("500"),
            "Safe Mode ignores the rate cap"
        );
        // Safe Mode never uses the SYN engine, whatever the setting says.
        assert!(safe.sends.contains("TCP connect") && !safe.sends.contains("SYN"));

        let plain = safe_badge(
            &scan::Settings {
                safe: false,
                workers: 1024,
                ..Default::default()
            },
            "10.0.0.1",
            false,
        );
        assert!(!plain.safe);
        assert_eq!(plain.label, "Safe Mode off");
        assert!(plain.tooltip.contains("Up to 1024 hosts"));
        assert!(plain.tooltip.contains("no rate cap"));

        let fast = scan::Settings {
            safe: false,
            syn: true,
            max_rate: 500,
            ..Default::default()
        };
        let full = safe_badge(&fast, "10.0.0.1", false);
        assert!(full.tooltip.contains("at most 500 packets per second"));
        assert!(full.sends.contains("TCP SYN"), "{}", full.sends);

        let plant = safe_badge(&scan::Settings::default(), "10.0.0.1", true);
        assert_eq!(plant.sends, "nothing");
        assert!(!plant.safe);
        assert_ne!(badge_color(true, false), badge_color(false, false));
    }

    #[test]
    fn the_indicator_lists_exactly_what_the_dry_run_plans() {
        let ot = scan::Settings {
            ot: true,
            ports: "80,502".into(),
            ..Default::default()
        };
        let udp = scan::Settings {
            udp: true,
            services: true,
            ..Default::default()
        };
        let syn = scan::Settings {
            safe: false,
            syn: true,
            arp_sweep: true,
            ..Default::default()
        };
        for s in [scan::Settings::default(), ot, udp, syn] {
            let ports = scan::parse_ports(&s.ports).unwrap();
            let want: BTreeSet<&str> = crate::plan::scan(
                [IpAddr::from([192, 0, 2, 1]), "2001:db8::1".parse().unwrap()].into_iter(),
                &ports,
                &s,
                None,
            )
            .into_iter()
            .flat_map(|g| g.plan.packets)
            .chain(
                crate::plan::ipv6_discovery(&s)
                    .into_iter()
                    .flat_map(|p| p.packets),
            )
            .map(|p| packet_name(p.kind))
            .collect();
            let badge = safe_badge(&s, "10.0.0.1, fd00::1", false);
            let got: BTreeSet<&str> = badge.sends.split(", ").collect();
            assert_eq!(got, want, "{}", badge.tooltip);
        }
    }

    #[test]
    fn the_safe_mode_indicator_is_a_named_button() {
        let badge = safe_badge(&scan::Settings::default(), "10.0.0.1", false);
        let nodes = a11y::tests::tree(|ui| {
            safe_mode_indicator(ui, &badge);
        });
        let buttons = a11y::tests::names(&nodes, &["Button"]);
        assert_eq!(buttons.len(), 1, "{nodes:?}");
        assert!(
            buttons[0].starts_with("Safe Mode. Sends: ") && buttons[0].contains("TCP connect"),
            "{buttons:?}"
        );
    }

    #[test]
    fn the_explain_button_is_named_with_its_text() {
        let nodes = a11y::tests::tree(|ui| {
            explain_button(ui, "telnet-open");
            explain_button(ui, "no-such-rule");
        });
        let buttons = a11y::tests::names(&nodes, &["Button"]);
        assert_eq!(buttons.len(), 1, "{nodes:?}");
        assert!(
            buttons[0].starts_with("Explain this: The device offers Telnet"),
            "{buttons:?}"
        );
    }

    #[test]
    fn standard_preset_keeps_machine_specific_fields() {
        let current = scan::Settings {
            interface: "\\Device\\NPF_{X}".into(),
            source_ip: "10.0.0.9".into(),
            source_mac: "AA:BB:CC:DD:EE:FF".into(),
            scripts: "C:\\scripts".into(),
            probe_file: "probes.json".into(),
            workers: 999,
            safe: false,
            ports: "1-1000".into(),
            ..Default::default()
        };
        let s = standard_settings(&current);
        assert_eq!(s.interface, current.interface);
        assert_eq!(s.source_ip, current.source_ip);
        assert_eq!(s.source_mac, current.source_mac);
        assert_eq!(s.scripts, current.scripts);
        assert_eq!(s.probe_file, current.probe_file);
        let d = scan::Settings::default();
        assert_eq!((s.workers, s.safe, s.ports), (d.workers, d.safe, d.ports));
    }

    #[test]
    fn cve_rules_file_is_loaded_validated_and_persisted() {
        let dir = std::env::temp_dir().join(format!("ns-gui-cves-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("good.json");
        std::fs::write(
            &good,
            r#"{"rules":[{"id":"lab-1","product":"labd","min":"1.0","max":"2.0","severity":"critical","cve":["CVE-2099-0001"],"title":"Lab daemon"}]}"#,
        )
        .unwrap();
        let builtin = risk::CveDb::builtin();
        let db = settings::load_cve_rules(&format!("  {}  ", good.display())).unwrap();
        assert_eq!(
            db.rules.len(),
            builtin.rules.len() + 1,
            "added to the built-in rules"
        );
        assert!(db.rules.iter().any(|r| r.id == "lab-1"));
        // A file that does not parse is an error naming the file; so is a missing one.
        let bad = dir.join("bad.json");
        std::fs::write(&bad, "not json").unwrap();
        let e = settings::load_cve_rules(&bad.display().to_string()).unwrap_err();
        assert!(e.contains("bad.json"), "{e}");
        let e =
            settings::load_cve_rules(&dir.join("missing.json").display().to_string()).unwrap_err();
        assert!(e.contains("missing.json"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
        // The path is part of the preferences; preferences from before it existed still load.
        let saved = Saved {
            cves_file: "C:\\rules\\cves.json".into(),
            ..Default::default()
        };
        let disk: Saved = serde_json::from_slice(&saved.to_disk()).unwrap();
        assert_eq!(disk.cves_file, "C:\\rules\\cves.json");
        let old: Saved = serde_json::from_str(r#"{"favorites":["10.0.0.1"]}"#).unwrap();
        assert!(old.cves_file.is_empty());
    }

    #[test]
    fn old_preferences_get_adaptive_tcp_once_and_a_later_choice_sticks() {
        // Saved before the setting had a checkbox: an explicit false that nobody chose.
        let mut old: Saved =
            serde_json::from_str(r#"{"settings":{"ports":"22","tcp_adaptive":false}}"#).unwrap();
        assert!(!old.settings.tcp_adaptive);
        old.migrate();
        assert!(old.settings.tcp_adaptive && old.adaptive_tcp_migrated);
        // The user turns it off; saved and loaded again, it stays off.
        old.settings.tcp_adaptive = false;
        let mut again: Saved = serde_json::from_slice(&old.to_disk()).unwrap();
        again.migrate();
        assert!(!again.settings.tcp_adaptive);
        // A new install starts with it on.
        let mut fresh = Saved::default();
        fresh.migrate();
        assert!(fresh.settings.tcp_adaptive);
    }

    #[test]
    fn the_schedule_is_saved_with_the_preferences_and_off_when_absent() {
        let mut saved = Saved::default();
        assert!(!saved.schedule.enabled, "off by default");
        saved.schedule = crate::schedule::Schedule {
            enabled: true,
            interval_minutes: 30,
            targets: "10.0.0.0/24".into(),
        };
        let disk: Saved = serde_json::from_slice(&saved.to_disk()).unwrap();
        assert_eq!(disk.schedule, saved.schedule);
        let old: Saved = serde_json::from_str(r#"{"favorites":["10.0.0.1"]}"#).unwrap();
        assert!(!old.schedule.enabled && old.schedule.targets.is_empty());
    }

    #[test]
    fn update_check_is_off_by_default_and_remembered_when_turned_on() {
        // Off for a new user and for preferences from before the setting existed.
        assert!(!Saved::default().check_updates);
        let old: Saved = serde_json::from_str(r#"{"favorites":["10.0.0.1"]}"#).unwrap();
        assert!(!old.check_updates);
        let on = Saved {
            check_updates: true,
            ..Default::default()
        };
        let disk: Saved = serde_json::from_slice(&on.to_disk()).unwrap();
        assert!(disk.check_updates);
    }

    #[test]
    fn update_answers_become_a_notice_a_status_line_or_nothing() {
        use updates::{Effect, effect};
        let release = |tag: &str| {
            update::parse_latest(format!(r#"{{"tag_name":"{tag}"}}"#).as_bytes()).unwrap()
        };
        let current = env!("CARGO_PKG_VERSION");
        let outcome = |tag: &str| update::compare(current, release(tag)).unwrap();
        assert_eq!(
            effect(Ok(outcome("v99.0.0"))),
            Effect::Notice(release("v99.0.0"))
        );
        assert_eq!(effect(Ok(outcome(&format!("v{current}")))), Effect::Nothing);
        assert_eq!(effect(Ok(outcome("v0.0.1"))), Effect::Nothing);
        assert_eq!(effect(Ok(outcome("v100.0.0-rc.1"))), Effect::Nothing);
        assert_eq!(
            effect(Err("no release has been published yet (HTTP 404)".into())),
            Effect::Failed(
                "Update check failed: no release has been published yet (HTTP 404)".into()
            )
        );
    }

    #[test]
    fn notes_are_stored_only_when_not_empty() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let mut notes = BTreeMap::new();
        set_note(&mut notes, ip, String::new());
        assert!(notes.is_empty(), "viewing a host must not add a note");
        set_note(&mut notes, ip, "rack 3".into());
        assert_eq!(notes[&ip], "rack 3");
        set_note(&mut notes, ip, "  ".into());
        assert!(notes.is_empty());
        let mut saved = Saved::default();
        saved.notes.insert(ip, " ".into());
        saved
            .notes
            .insert("10.0.0.2".parse().unwrap(), "keep".into());
        let disk: Saved = serde_json::from_slice(&saved.to_disk()).unwrap();
        assert_eq!(disk.notes.len(), 1);
    }

    #[test]
    fn every_finding_page_has_a_plain_explanation_in_both_languages() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/src/findings");
        let pages: BTreeSet<String> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| {
                let name = e.unwrap().file_name().to_string_lossy().into_owned();
                name.strip_suffix(".md")
                    .filter(|s| *s != "index")
                    .map(str::to_string)
            })
            .collect();
        let texts = explanations();
        let entries: BTreeSet<String> = texts.keys().map(|k| k.to_string()).collect();
        assert_eq!(
            pages, entries,
            "lang/explain.txt and docs/src/findings differ"
        );
        let lines = EXPLAIN
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'));
        assert_eq!(
            lines.count(),
            texts.len(),
            "an entry is duplicated or malformed"
        );
        for (id, (en, de)) in texts {
            for text in [en, de] {
                let sentences = text.matches(". ").count() + 1;
                assert!(
                    text.ends_with('.') && (1..=3).contains(&sentences),
                    "{id}: {text}"
                );
            }
            assert_ne!(en, de, "{id}");
        }
        // Run-time ids reach their family's text, in the current language.
        i18n::set(i18n::Lang::German);
        assert!(
            explanation("cve-CVE-2021-41773")
                .unwrap()
                .starts_with("Die Softwareversion")
        );
        i18n::set(i18n::Lang::English);
        assert!(explanation("Telnet-Open").unwrap().contains("Telnet"));
        assert!(
            explanation("script-owner-check")
                .unwrap()
                .contains("script")
        );
        assert_eq!(explanation("no-such-rule"), None);
    }

    #[test]
    fn every_finding_page_is_reached_through_the_docs_url() {
        // The pages in docs/src/findings (without the index) are what `docs_url` can point to.
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/src/findings");
        let mut pages = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            let Some(stem) = name.strip_suffix(".md").filter(|s| *s != "index") else {
                continue;
            };
            pages += 1;
            let url = docs_url(stem);
            if stem == "cve-hints" || stem == "script-findings" {
                // The shared pages are reached through the ids of their family.
                continue;
            }
            assert_eq!(
                url,
                format!("https://sparkz400.github.io/network-scope/findings/{stem}.html"),
                "{stem}"
            );
        }
        assert!(pages > 30, "{pages}");
        // The families built at run time share one page each; other CVE ids too.
        assert!(docs_url("cve-CVE-2021-41773").ends_with("/findings/cve-hints.html"));
        assert!(docs_url("script-owner-check").ends_with("/findings/script-findings.html"));
        assert!(docs_url("cve-CVE-2020-0796").ends_with("/findings/cve-cve-2020-0796.html"));
        assert!(docs_url("Telnet-Open").ends_with("/findings/telnet-open.html"));
        // And every URL it builds is one the opener accepts.
        assert!(convenience::valid_url(&docs_url("telnet-open")));
    }

    #[test]
    fn caches_refresh_on_new_data_and_throttle_while_live() {
        let mut c: Cached<u32> = Cached::default();
        assert!(c.stale(0, true), "first computation is never delayed");
        c.set(0, 1);
        assert!(!c.stale(0, false));
        assert!(!c.stale(0, true));
        assert!(c.stale(1, false), "idle: new data refreshes at once");
        assert!(!c.stale(1, true), "live: throttled");
        c.at = Instant::now() - LIVE_REFRESH;
        assert!(c.stale(1, true));
    }

    #[test]
    fn search_uses_cached_haystacks_and_notes() {
        let results = vec![
            host("10.0.0.1", true, vec![502], "plc-1"),
            host("10.0.0.2", false, vec![], "printer"),
            host("10.0.0.3", true, vec![], "PC-7"),
        ];
        let mut hay = HashMap::new();
        let mut notes = BTreeMap::new();
        let stars = BTreeSet::new();
        assert_eq!(
            filter_rows(&results, Filter::All, "", &mut hay, &notes, &stars),
            [0, 1, 2]
        );
        assert!(hay.is_empty(), "no haystacks without a query");
        assert_eq!(
            filter_rows(&results, Filter::Responding, "", &mut hay, &notes, &stars),
            [0, 2]
        );
        assert_eq!(
            filter_rows(&results, Filter::Open, "", &mut hay, &notes, &stars),
            [0]
        );
        assert_eq!(
            filter_rows(&results, Filter::All, "pc-7", &mut hay, &notes, &stars),
            [2]
        );
        assert_eq!(
            filter_rows(&results, Filter::All, "acme plc", &mut hay, &notes, &stars),
            [0, 1, 2]
        );
        assert_eq!(hay.len(), 3);
        notes.insert(results[1].ip, "Basement Rack".to_string());
        assert_eq!(
            filter_rows(&results, Filter::All, "basement", &mut hay, &notes, &stars),
            [1]
        );
    }

    /// GUI budget (ROADMAP B17): a table of 65,536 hosts stays within one 60 fps frame (16.6 ms).
    /// The window itself needs a display, so this drives the same `TableBuilder` columns and cells
    /// as the results table through a headless egui context, and times the two things that happen
    /// to 65k rows while a scan runs: a frame that only draws (the rows are virtual, only the
    /// visible ones are laid out), and a frame that also gets a new batch of hosts (sort by open
    /// ports, then the filtered row list with a text query, which builds the search text of every
    /// row once). A timing test, so it is ignored by default and runs in release mode:
    /// `cargo test --release --lib frame_budget -- --ignored --nocapture`
    /// (`scripts/resource_budget.py --gui`). It prints one `GUI_FRAME_MS` line.
    #[test]
    #[ignore = "timing test, run in release mode by scripts/resource_budget.py --gui"]
    fn frame_budget_with_65k_rows() {
        let mut results: Vec<scan::Host> = (0..65_536u32)
            .map(|i| {
                let ip = std::net::Ipv4Addr::from(0x0a00_0000 + i).to_string();
                let open = if i % 5 == 0 { vec![80, 443] } else { vec![] };
                host(&ip, i % 3 != 0, open, &format!("pc-{i}.example.net"))
            })
            .collect();
        let ctx = egui::Context::default();
        let input = || egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1280.0, 800.0),
            )),
            ..Default::default()
        };
        let rows: Vec<usize> = (0..results.len()).collect();
        let draw = |results: &[scan::Host], rows: &[usize]| {
            ctx.run_ui(input(), |ui| {
                egui::CentralPanel::default().show(ui, |ui| {
                    TableBuilder::new(ui)
                        .striped(true)
                        .resizable(true)
                        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                        .column(Column::initial(135.0).at_least(80.0))
                        .column(Column::initial(110.0))
                        .column(Column::initial(65.0))
                        .column(Column::remainder().at_least(80.0))
                        .column(Column::initial(140.0))
                        .header(26.0, |mut row| {
                            for name in
                                ["IP address", "Status", "Ping", "Hostname", "Open TCP ports"]
                            {
                                row.col(|ui| {
                                    let _ = ui.selectable_label(false, name);
                                });
                            }
                        })
                        .body(|body| {
                            body.rows(26.0, rows.len(), |mut row| {
                                let host = &results[rows[row.index()]];
                                row.col(|ui| {
                                    let _ = ui.selectable_label(false, host.ip.to_string());
                                });
                                row.col(|ui| {
                                    ui.label(host_status(host));
                                });
                                row.col(|ui| {
                                    ui.label(ping_text(host.ping));
                                });
                                row.col(|ui| {
                                    ui.label(&host.hostname);
                                });
                                row.col(|ui| {
                                    ui.label(ports_text(&host.open));
                                });
                            });
                        });
                });
            })
            // Nothing is painted, so the font atlas upload is dropped on purpose.
            .drop_without_applying_deltas();
        };
        let time = |mut f: Box<dyn FnMut() + '_>| {
            f(); // warm-up: fonts, layout caches
            let mut samples: Vec<f64> = (0..30)
                .map(|_| {
                    let t = Instant::now();
                    f();
                    t.elapsed().as_secs_f64() * 1000.0
                })
                .collect();
            samples.sort_by(f64::total_cmp);
            (samples[samples.len() / 2], samples[samples.len() - 1])
        };
        let (idle_median, idle_max) = time(Box::new(|| draw(&results, &rows)));
        let mut haystacks = HashMap::new();
        let notes = BTreeMap::new();
        let (live_median, live_max) = time(Box::new(|| {
            // The work of a frame that received hosts: the sort of `Scanner::sort` (column 4)...
            results.sort_by(|a, b| a.open.cmp(&b.open).then_with(|| a.ip.cmp(&b.ip)));
            // ...the visible row list for a search text (the cache of search texts is kept)...
            let visible = filter_rows(
                &results,
                Filter::All,
                "pc-1",
                &mut haystacks,
                &notes,
                &BTreeSet::new(),
            );
            // ...and the draw.
            draw(&results, &visible);
        }));
        println!(
            "GUI_FRAME_MS idle_median={idle_median:.3} idle_max={idle_max:.3} live_median={live_median:.3} live_max={live_max:.3} rows=65536"
        );
        if !cfg!(debug_assertions) {
            assert!(
                idle_median < 1000.0 / 60.0,
                "idle frame {idle_median:.2} ms"
            );
            assert!(
                live_median < 1000.0 / 60.0,
                "live frame {live_median:.2} ms"
            );
        }
    }
}
