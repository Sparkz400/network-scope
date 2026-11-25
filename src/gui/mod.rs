// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
mod a11y;
mod controls;
mod convenience;
mod demo;
mod desktop;
mod details;
mod home;
mod i18n;
mod icons;
mod map;
mod menu;
mod nav;
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
    /// Size, position and maximized state of the window when it was last open.
    window: desktop::WindowState,
    /// The optional columns of the hosts table.
    host_columns: HostColumns,
    /// The Findings page shows one row per rule instead of one per host.
    group_findings: bool,
    /// The Addresses field when the window was last open (empty: the example range). An
    /// imported list longer than [`MAX_SAVED_TARGETS`] is not kept.
    targets: String,
    /// Sort column and direction (reversed) of the hosts table.
    host_sort: (usize, bool),
    /// The widths of table columns that were dragged to another width.
    column_widths: tables::Widths,
}
/// The longest Addresses text that is remembered across starts.
const MAX_SAVED_TARGETS: usize = 2000;

/// The optional columns of the hosts table (all off by default). They show what the Devices
/// page shows, for the scanned hosts.
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(default)]
struct HostColumns {
    vendor: bool,
    kind: bool,
    os: bool,
    risk: bool,
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
/// The file a preferences file that could not be read is kept as, next to it.
const BAD_PREFS: &str = "preferences.bad.json";
/// The saved preferences at `path`, and why the file could not be used. No file: the defaults,
/// silently (a first start). A file that cannot be read or does not parse: the defaults and the
/// reason, and the file is kept as [`BAD_PREFS`], because the next save writes the defaults over
/// it and the notes, stars and favorites exist nowhere else.
fn load_saved(path: &std::path::Path) -> (Saved, Option<String>) {
    let why = match std::fs::read(path) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(saved) => return (saved, None),
            Err(e) => e.to_string(),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (Saved::default(), None),
        Err(e) => e.to_string(),
    };
    let _ = std::fs::copy(path, path.with_file_name(BAD_PREFS));
    (Saved::default(), Some(why))
}
fn write_prefs(bytes: &[u8]) -> Result<(), String> {
    write_prefs_to(&saved_path(), bytes)
}
/// Writes the preferences through a temporary file and a rename, so a crash or a power loss in
/// the middle leaves the old file and not half of the new one.
fn write_prefs_to(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        e.to_string()
    })
}
/// The sort index of the Risk column of the hosts table (after the identity columns, 5 to 7).
const RISK_COLUMN: usize = 8;

/// An identity field of a host, or "" when it has none.
fn identity_field<'a>(host: &'a scan::Host, key: &str) -> &'a str {
    host.identity.get(key).map_or("", String::as_str)
}

/// The identity keys of the optional hosts-table columns Manufacturer, Type and OS guess (sort
/// columns 5, 6 and 7).
const HOST_COLUMN_KEYS: [&str; 3] = ["mac.vendor", "device.type", "os.guess"];

/// "Restore defaults": scan defaults, but the fields that describe
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
/// The SBOM library and, per address, the firmware SBOMs found in it (see `ensure_firmware_sboms`).
type FirmwareSboms = (
    std::sync::Arc<crate::sbom::Library>,
    BTreeMap<IpAddr, Vec<crate::sbom::FirmwareSbom>>,
);

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
    /// Deletes a saved scan and lists what is left.
    Delete(i64),
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
    /// Imports firmware SBOMs or VEX statements into their cache (`feeds import sbom|vex`).
    ImportFeed(FeedKind, Vec<PathBuf>),
}

/// Which cache a desktop import fills.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FeedKind {
    Sbom,
    Vex,
}
enum Done {
    Saved(&'static str, usize, Result<i64, String>),
    Listed(Result<Vec<store::Entry>, String>),
    Deleted(i64, Result<Vec<store::Entry>, String>),
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
    /// What an SBOM or VEX import did (its report lines), or why it failed.
    FeedImported(FeedKind, Result<Vec<String>, String>),
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
        Job::Delete(id) => Done::Deleted(
            id,
            store::delete(&path, id).and_then(|()| store::list(&path)),
        ),
        Job::Diff(a, b) => Done::Diffed(
            store::load(&path, a)
                .and_then(|a| store::load(&path, b).and_then(|b| store::diff(&a, &b))),
        ),
        Job::Load(id) => Done::Loaded(id, store::load(&path, id).map(Box::new)),
        Job::ReadFile(file) => Done::Read(
            std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display())),
        ),
        Job::ImportFeed(kind, files) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let result = match kind {
                FeedKind::Sbom => crate::sbom::default_path()
                    .ok_or_else(|| tr!("No location for the SBOM cache").to_string())
                    .and_then(|cache| crate::sbom::import(&files, &Default::default(), &cache, now))
                    .map(|r| r.lines()),
                FeedKind::Vex => crate::vex::default_path()
                    .ok_or_else(|| tr!("No location for the VEX cache").to_string())
                    .and_then(|cache| crate::vex::import(&files, &cache, now))
                    .map(|r| r.lines()),
            };
            Done::FeedImported(kind, result)
        }
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
/// The pages of the main window, chosen in the sidebar: the "what changed" overview, the hosts
/// table and the pages that were separate windows before.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Default)]
enum MainView {
    #[default]
    Home,
    Hosts,
    Devices,
    Findings,
    Map,
    Passive,
    Inventory,
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
    /// The hosts marked with Ctrl or Shift, to copy several rows.
    marked: tables::Marks<IpAddr>,
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
    /// The scan on screen was started by the user, not by the schedule: its end is announced.
    attended: bool,
    /// A scan the user started has ended: the taskbar button flashes if the window is not in
    /// front (set by `finish_scan`, sent with the next frame).
    attention: bool,
    /// The window was asked to close while a scan or capture runs: the question is open.
    quit_ask: bool,
    /// The answer was to quit anyway.
    quit_ok: bool,
    history: Vec<store::Entry>,
    compare_a: Option<i64>,
    compare_b: Option<i64>,
    /// The saved scan the Delete question is open for.
    delete_ask: Option<i64>,
    /// The capture interfaces were listed once for the Passive / OT page.
    interfaces_tried: bool,
    /// A device of the Hosts page (by device) that is not among the scanned hosts, by its id:
    /// its details are shown in place of a host's (see `details::device_details`).
    selected_device: Option<String>,
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
    /// Open and scroll the settings to the scheduled scans (Tools → Scheduled scans).
    scroll_to_schedule: bool,
    /// Give the hosts search box the keyboard focus on the next frame (Ctrl+F).
    focus_search: bool,
    shortcuts_open: bool,
    /// A one-click change that would turn Safe Mode off, waiting for confirmation.
    unsafe_confirm: Option<menu::Unsafe>,
    /// The findings on view grouped by rule (indexes into the findings), with the rows.
    finding_groups: Vec<Vec<usize>>,
    /// Host name per address, for the Findings page.
    hostnames: Cached<HashMap<IpAddr, String>>,
    /// The worst finding per address, for the Risk column and the host details.
    risk_map: Cached<HashMap<IpAddr, risk::Severity>>,
    /// The imported SBOMs of the firmware each host reported, for the host details, with the
    /// SBOM library they were found in.
    firmware_sboms: Cached<FirmwareSboms>,
    /// Findings of a large scan being worked out on a thread of their own (see `nav.rs`).
    background_findings: Option<nav::BackgroundFindings>,
    /// A page that shows findings was drawn with findings that are out of date for a large
    /// scan: the other thread works them out, also while a scan runs.
    findings_wanted: bool,
}
/// A script dry-run for the host in the details window.
struct ScriptTest {
    token: u64,
    ip: IpAddr,
    path: String,
    result: Option<Result<crate::script::Outcome, String>>,
}
impl Scanner {
    /// `saved`: the preferences from [`load_saved`] (the defaults for a screenshot).
    fn new(
        cc: &eframe::CreationContext<'_>,
        screenshot: Option<PathBuf>,
        mut saved: Saved,
    ) -> Self {
        let mut style = (*cc.egui_ctx.global_style()).clone();
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(10.0, 6.0);
        cc.egui_ctx.set_global_style(style);
        prune_notes(&mut saved.notes);
        // Taken before the migration, so a migrated file differs and is written right away.
        let prefs_written = saved.to_disk();
        saved.migrate();
        i18n::set(i18n::detect(&saved.language));
        let targets = match saved.targets.trim() {
            "" => "192.168.1.1-254".to_string(),
            remembered => remembered.to_string(),
        };
        let (sort_column, sort_reverse) = (saved.host_sort.0.min(RISK_COLUMN), saved.host_sort.1);
        let mut app = Self {
            saved,
            targets,
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
            marked: Default::default(),
            screenshot,
            frames: 0,
            screenshot_requested: false,
            screenshot_image: Default::default(),
            window_origin: egui::pos2(16.0, 16.0),
            sort_column,
            sort_reverse,
            attended: false,
            attention: false,
            quit_ask: false,
            quit_ok: false,
            history: vec![],
            compare_a: None,
            compare_b: None,
            delete_ask: None,
            interfaces_tried: false,
            selected_device: None,
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
            scroll_to_schedule: false,
            focus_search: false,
            shortcuts_open: false,
            unsafe_confirm: None,
            finding_groups: vec![],
            hostnames: Default::default(),
            risk_map: Default::default(),
            firmware_sboms: Default::default(),
            background_findings: None,
            findings_wanted: false,
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
                    app.error = tr!(
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
            Job::List | Job::Delete(_) => self.busy.listing = true,
            Job::Diff(..) => self.busy.comparing = true,
            Job::Load(_) => self.busy.loading = true,
            Job::ReadFile(_) | Job::ImportFeed(..) => self.busy.importing = true,
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
            self.error = tr!("Background worker stopped; restart the program.").into();
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
                                tr!("{} observations · saved capture #{}", observations, id)
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
                            // The list on screen shows the new scan at once.
                            if self.view == MainView::Inventory {
                                self.refresh_history();
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
                Done::Deleted(id, result) => {
                    self.busy.listing = false;
                    match result {
                        Ok(h) => {
                            self.history = h;
                            self.status = tr!("Deleted scan #{}", id);
                            // Nothing may point at the scan any more.
                            for pick in [&mut self.compare_a, &mut self.compare_b] {
                                pick.take_if(|p| *p == id);
                            }
                            self.loaded_scan.take_if(|l| *l == id);
                            self.refresh_home();
                        }
                        Err(e) => self.error = tr!("Scan #{} was not deleted: {}", id, e),
                    }
                }
                Done::Diffed(result) => {
                    self.busy.comparing = false;
                    match result {
                        Ok(changes) if changes.is_empty() => {
                            self.changes = vec![tr!("No observed changes.").into()]
                        }
                        Ok(changes) => self.changes = changes,
                        Err(e) => self.error = e,
                    }
                }
                Done::Loaded(id, result) => {
                    self.busy.loading = false;
                    match result {
                        Ok(_) if self.live() => {
                            self.error = tr!(
                                "Inventory #{} was not opened: a scan or capture is running.",
                                id
                            )
                        }
                        Ok(snapshot) => self.open_snapshot(id, *snapshot),
                        Err(e) => self.error = e,
                    }
                }
                Done::FeedImported(kind, result) => {
                    self.busy.importing = false;
                    match result {
                        Ok(lines) => {
                            // The next export and analysis read the new cache.
                            match kind {
                                FeedKind::Sbom => crate::sbom::reload(),
                                FeedKind::Vex => crate::vex::reload(),
                            }
                            // VEX changes what the findings say: work them out again.
                            self.data_changed();
                            self.status = lines.join(" · ");
                        }
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
                        self.error = tr!("Preferences could not be saved: {}", e);
                    }
                }
                Done::Exported(path, result) => {
                    self.busy.exporting = self.busy.exporting.saturating_sub(1);
                    match result {
                        Ok(()) => self.status = tr!("Saved {}", path.display()),
                        Err(e) => self.error = tr!("Export failed: {}", e),
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
        self.marked.clear();
        self.script_test = None;
        self.previous.clear();
        self.haystacks.clear();
        self.status = tr!("Loaded inventory #{}", id);
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
        self.marked.clear();
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
            self.error = tr!("Stop passive capture before starting an active scan.").into();
            return;
        }
        if self.busy.loading {
            self.error = tr!("Wait until the inventory scan has been opened.").into();
            return;
        }
        if self.saved.preset == preset_ui::PLANT {
            // The passive preset sends nothing: point to the listener instead of scanning.
            self.error = tr!(
                "The Plant preset is passive and sends no packets. Use Listen (OT) in Passive discovery / OT, or choose another preset to scan."
            )
            .into();
            if !unattended {
                self.view = MainView::Passive;
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
                        self.error = tr!("Scheduled scan not started. {}", text);
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
                self.attended = !unattended;
                self.loaded_scan = None;
                // Passive observations stay: the Devices window merges them with this scan.
                self.previous = self.results.drain(..).map(|h| (h.ip, h)).collect();
                self.haystacks.clear();
                self.live.clear();
                self.selected = None;
                self.marked.clear();
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
                return Some(tr!(
                    "The scope file is invalid ({}), so nothing is known to be in scope.",
                    e
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
        self.attention = self.attended;
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
                self.status = tr!("{} · IPv6 discovery failed", self.status);
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
                self.status = tr!(
                    "{} · {} of {} addresses · {} s · {} packets sent",
                    if run.cancel.load(Ordering::Relaxed) {
                        tr!("Stopped")
                    } else {
                        tr!("Complete")
                    },
                    self.results.len(),
                    run.total,
                    format!("{:.1}", run.started.elapsed().as_secs_f32()),
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
                self.status = tr!("{} · IPv6 discovery…", self.status);
            } else {
                self.finish_scan();
            }
        }
    }
    /// Sorts the hosts after their data changed (new hosts, a loaded scan).
    fn sort(&mut self) {
        self.sort_hosts(false);
    }

    /// Sorts the hosts in a new order (a column header was clicked); the data is the same.
    fn resort(&mut self) {
        self.sort_hosts(true);
    }

    fn sort_hosts(&mut self, order_only: bool) {
        if !order_only {
            // New data: whatever was worked out from the old data is out of date from here on.
            self.data_changed();
        }
        // The Risk column sorts by the worst finding of each host. A header click works the
        // findings out even for a large scan (the user asked for this order); after new data
        // only when that is cheap ([`Self::eager`]), else the last known findings order it.
        let risk = if self.sort_column == RISK_COLUMN {
            if (order_only && !self.live()) || self.eager() {
                self.ensure_findings();
            }
            tables::risk_by_ip(&self.findings.value)
        } else {
            HashMap::new()
        };
        self.results.sort_by(|a, b| {
            let order = match self.sort_column {
                1 => b.responding.cmp(&a.responding),
                2 => a.ping.unwrap_or(u32::MAX).cmp(&b.ping.unwrap_or(u32::MAX)),
                3 => a.hostname.cmp(&b.hostname),
                4 => a.open.cmp(&b.open),
                5..=7 => {
                    let key = HOST_COLUMN_KEYS[self.sort_column - 5];
                    let (x, y) = (identity_field(a, key), identity_field(b, key));
                    // Hosts without the value go last.
                    (x.is_empty(), x).cmp(&(y.is_empty(), y))
                }
                // The worst finding first; hosts without findings last.
                RISK_COLUMN => risk.get(&b.ip).cmp(&risk.get(&a.ip)),
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
        let before = self.generation;
        self.data_changed();
        // Sorting moves rows but changes no data: what was worked out from the hosts as they are
        // now (findings, worst finding and host name per address) still holds, so it is not
        // worked out again. Values of older data keep their older generation.
        for generation in [
            &mut self.findings.generation,
            &mut self.risk_map.generation,
            &mut self.hostnames.generation,
            &mut self.firmware_sboms.generation,
        ] {
            if *generation == Some(before) {
                *generation = Some(self.generation);
            }
        }
        // Findings being worked out for the hosts as they are now still hold after the sort.
        if let Some(job) = self.background_findings.as_mut() {
            job.restamp(before, self.generation);
        }
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
            .add_filter(tr!("Scan results"), &[extension])
            .save_file()
        else {
            return;
        };
        self.refresh_rows();
        let mut snapshot = self.snapshot();
        snapshot.hosts = self.rows.iter().map(|&i| self.results[i].clone()).collect();
        let stamp = self.opened_stamp.unwrap_or_else(unix_now);
        // Formatting and writing happen on the worker; the dialog stays on this thread.
        self.status = tr!("Writing {}…", path.display());
        self.submit(Job::Export(
            Box::new(snapshot),
            extension.to_string(),
            stamp,
            path,
        ));
    }
    /// Exports every result and observation (not only the visible rows) in `format`, to a file
    /// ending in `.{extension}`: the CycloneDX inventory should list the whole network.
    fn export_all(&mut self, format: &str, extension: &str) {
        let Some(path) = rfd::FileDialog::new()
            .set_file_name(format!("network-scan.{extension}"))
            .add_filter(tr!("CycloneDX JSON"), &["json"])
            .save_file()
        else {
            return;
        };
        let snapshot = self.snapshot();
        let stamp = self.opened_stamp.unwrap_or_else(unix_now);
        self.status = tr!("Writing {}…", path.display());
        self.submit(Job::Export(
            Box::new(snapshot),
            format.to_string(),
            stamp,
            path,
        ));
    }
    /// Selects a host of the active results (first of `ips` that is one), makes its row visible
    /// in the main table and opens its details.
    fn focus_host(&mut self, ips: &[IpAddr]) {
        if !self.try_focus_host(ips) {
            self.status = tr!(
                "{} is not in the active scan results (seen passively only)",
                ips.first()
                    .map_or(tr!("This device").to_string(), |ip| ip.to_string())
            );
        }
    }
    /// [`Scanner::focus_host`]; false when none of `ips` is a scanned host.
    fn try_focus_host(&mut self, ips: &[IpAddr]) -> bool {
        let Some(ip) = ips
            .iter()
            .copied()
            .find(|ip| self.results.iter().any(|h| h.ip == *ip))
        else {
            return false;
        };
        self.selected_device = None;
        if self.selected != Some(ip) {
            self.script_test = None;
        }
        self.selected = Some(ip);
        self.refresh_rows();
        // On another page the details dock beside it and the hosts table is not in view, so
        // its filter and search stay as they are.
        if self.view == MainView::Hosts && !self.rows.iter().any(|&i| self.results[i].ip == ip) {
            // Hidden by the filter or the search: show everything so the row can be reached.
            self.filter = Filter::All;
            self.search.clear();
        }
        self.scroll_to = Some(ip);
        true
    }
    /// Saves preferences in the background shortly after the user stops interacting.
    /// Copies what the window shows and the preferences remember (the Addresses field, the
    /// sort of the hosts table) into `saved`, before it is written.
    fn remember_view(&mut self) {
        if self.targets.len() <= MAX_SAVED_TARGETS {
            self.saved.targets.clone_from(&self.targets);
        }
        self.saved.host_sort = (self.sort_column, self.sort_reverse);
    }
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
        self.remember_view();
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
    /// The file picker for firmware SBOMs or VEX statements, imported on the worker.
    pub(super) fn import_feed(&mut self, kind: FeedKind) {
        if self.busy.importing {
            return;
        }
        let title = match kind {
            FeedKind::Sbom => tr!("SBOM (CycloneDX or SPDX JSON)"),
            FeedKind::Vex => tr!("VEX (CSAF or CycloneDX JSON)"),
        };
        if let Some(files) = rfd::FileDialog::new()
            .add_filter(title, &["json"])
            .pick_files()
        {
            self.status = tr!("Importing {} files…", files.len());
            self.submit(Job::ImportFeed(kind, files));
        }
    }
    /// The file picker for an address list (read in the background; `#` comments allowed).
    /// A file dropped on the window: an address list fills the Addresses field (a scan is
    /// never started by it), a capture is read for OT assets. Anything else is named.
    fn open_dropped(&mut self, path: PathBuf, ctx: &egui::Context) {
        let extension = (path.extension().and_then(|e| e.to_str()))
            .unwrap_or_default()
            .to_ascii_lowercase();
        match extension.as_str() {
            "txt" | "csv" | "lst" => {
                if self.run.is_some() || self.busy.importing {
                    self.error = tr!("Address list ignored: a scan is running.").into();
                } else {
                    self.submit(Job::ReadFile(path));
                }
            }
            "pcap" | "pcapng" | "cap" => {
                if self.ot.running() {
                    self.error = tr!("A capture is already being read.").into();
                } else {
                    self.view = MainView::Passive;
                    self.open_capture_file(path, ctx);
                }
            }
            _ => {
                self.error = tr!(
                    "{} was not opened: drop an address list (.txt, .csv, .lst) or a capture (.pcap, .pcapng) here.",
                    path.file_name().unwrap_or_default().to_string_lossy()
                );
            }
        }
    }
    fn import_address_list(&mut self) {
        if self.run.is_some() || self.busy.importing {
            return;
        }
        if let Some(path) = rfd::FileDialog::new()
            .add_filter(tr!("Address list"), &["txt", "csv", "lst"])
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
        self.background_findings(ctx);
        // A scan the user started has ended while the window was not in front: flash its
        // taskbar button (a long Safe Mode scan otherwise ends unnoticed).
        if std::mem::take(&mut self.attention)
            && self.screenshot.is_none()
            && !ctx.input(|i| i.viewport().focused.unwrap_or(true))
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
                egui::UserAttentionType::Informational,
            ));
        }
        if self.live() || self.ot.running() {
            ctx.request_repaint_after(Duration::from_millis(16));
        }
    }
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = &ui.ctx().clone();
        windows::set_dark_mode(ui.visuals().dark_mode);
        if self.screenshot.is_none() {
            let zoom = ctx.zoom_factor();
            let window = &mut self.saved.window;
            ctx.input(|i| window.observe(i.viewport(), i.content_rect().size(), zoom));
        }
        if self.screenshot.is_none() {
            // Closing the window while a scan or capture runs asks first (the partial result
            // is saved either way, but a scan that ran for minutes is not ended by a slip).
            if ctx.input(|i| i.viewport().close_requested())
                && !self.quit_ok
                && (self.live() || self.ot.running())
            {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.quit_ask = true;
            }
            let dropped: Vec<PathBuf> = ctx.input(|i| {
                (i.raw.dropped_files.iter())
                    .map(|f| f.path().to_path_buf())
                    .filter(|p| !p.as_os_str().is_empty())
                    .collect()
            });
            for path in dropped {
                self.open_dropped(path, ctx);
            }
        }
        // A link from the last frame that could not be opened.
        if let Some(e) = convenience::take_link_error() {
            self.error = e;
        }
        self.poll_update();
        self.apply_zoom(ctx);
        self.shortcuts(ctx);
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
            // One line: the Safe Mode badge, the status, what the scan sends (cut short on narrow
            // windows; the tooltip has it all) and the counts on the right.
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(tr!(
                        "{} responding · {} with open ports",
                        self.responding,
                        self.with_open
                    ));
                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                        if safe_mode_indicator(ui, &badge) {
                            self.settings_open = true;
                        }
                        if let Some(busy) = self.busy.label() {
                            ui.spinner();
                            ui.label(busy);
                        }
                        // Hovering the status line also lists what the Safe Mode badge limits.
                        let status = ui.add(egui::Label::new(&self.status).truncate());
                        if !self.scan_sent.is_empty() {
                            // The scan summary: every kind of packet the scan sent, with counts.
                            status.on_hover_text(crate::sendlog::format_table(&self.scan_sent));
                        } else if !self.status.is_empty() {
                            status.on_hover_text(&self.status);
                        }
                        self.update_notice_ui(ui);
                        ui.separator();
                        ui.add(
                            egui::Label::new(
                                RichText::new(tr!("Sends: {}", badge.sends))
                                    .color(ui.visuals().weak_text_color()),
                            )
                            .truncate(),
                        )
                        .on_hover_text(&badge.tooltip);
                    });
                });
            });
        });
        self.refresh_rows();
        self.table_keys(ctx);
        let mut menu: Option<(usize, convenience::MenuAction)> = None;
        self.sidebar(ui);
        // Floating windows (Settings, the workbench, ...) open next to the sidebar.
        self.window_origin = ui.available_rect_before_wrap().min + egui::vec2(16.0, 16.0);
        self.details(ui);
        self.device_details(ui);
        self.timeline_panel(ui);
        egui::CentralPanel::default().show(ui, |ui| {
            if self.page_ui(ui) {
                return;
            }
            self.hosts_filters(ui);
            let columns = self.saved.host_columns;
            if columns.risk {
                self.ensure_risk_map();
            }
            let risk_fresh = self.risk_map.generation == Some(self.generation);
            // The optional columns in display order: sort index (None: not sortable), title.
            // Then the name and the default width its width is remembered under.
            type HostColumn = (Option<usize>, &'static str, (&'static str, f32));
            let extra: Vec<HostColumn> = [
                (columns.vendor, Some(5), tr!("Manufacturer"), "hosts.vendor"),
                (columns.kind, Some(6), tr!("Type"), "hosts.kind"),
                (columns.os, Some(7), tr!("OS guess"), "hosts.os"),
                (columns.risk, Some(RISK_COLUMN), tr!("Risk"), "hosts.risk"),
            ]
            .into_iter()
            .filter(|(on, ..)| *on)
            .map(|(_, sort, name, key)| (sort, name, (key, 120.0)))
            .collect();
            // Whichever of the host name and the ports takes the rest of the width has no
            // width of its own (see `hostname_column`).
            let (name_width, ports_width) = if extra.is_empty() {
                (("hosts.hostname", 140.0), ("", 0.0))
            } else {
                (("", 0.0), ("hosts.ports", 140.0))
            };
            let base: [HostColumn; 4] = [
                (Some(0), tr!("IP address"), ("hosts.ip", 120.0)),
                (Some(1), tr!("Status"), ("hosts.status", 110.0)),
                (Some(2), tr!("Ping"), ("hosts.ping", 65.0)),
                (Some(3), tr!("Hostname"), name_width),
            ];
            let last: [HostColumn; 1] = [(Some(4), tr!("Open TCP ports"), ports_width)];
            let mut widths = std::mem::take(&mut self.saved.column_widths);
            let visible = std::mem::take(&mut self.rows);
            let mut sort = None;
            let scroll_row = self.scroll_to.take().and_then(|ip| {
                visible
                    .iter()
                    .position(|&i| self.results.get(i).is_some_and(|h| h.ip == ip))
            });
            tables::plain_labels(ui);
            // Where the header row starts, so the empty state can stay clear of it.
            let table_top = ui.cursor().top();
            // Optional columns can make the table wider than the page: it scrolls sideways.
            egui::ScrollArea::horizontal()
                .id_salt("hosts_scroll")
                .show(ui, |ui| {
                    let mut table = TableBuilder::new(ui);
                    if let Some(row) = scroll_row {
                        table = table.scroll_to_row(row, Some(egui::Align::Center));
                    }
                    table = table
                        .striped(true)
                        .resizable(true)
                        // The whole row is the click target: select (opens the details), right click
                        // for the host menu.
                        .sense(egui::Sense::click())
                        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                        .column(tables::sized(&widths, base[0].2).at_least(80.0))
                        .column(tables::sized(&widths, base[1].2))
                        .column(tables::sized(&widths, base[2].2))
                        .column(hostname_column(!extra.is_empty(), &widths));
                    for (.., width) in &extra {
                        table =
                            table.column(tables::sized(&widths, *width).at_least(50.0).clip(true));
                    }
                    table
                        .column(ports_column(!extra.is_empty(), &widths))
                        .header(26.0, |mut row| {
                            for (i, name, width) in base.iter().chain(&extra).chain(&last) {
                                row.col(|ui| {
                                    tables::keep(&mut widths, *width, ui);
                                    match i {
                                        Some(i) => {
                                            if ui
                                                .selectable_label(self.sort_column == *i, *name)
                                                .clicked()
                                            {
                                                sort = Some(*i);
                                            }
                                        }
                                        None => {
                                            ui.strong(*name);
                                        }
                                    }
                                });
                            }
                        })
                        .body(|body| {
                            body.rows(26.0, visible.len(), |mut row| {
                                let at = row.index();
                                let index = visible[at];
                                let host = &self.results[index];
                                let starred = self
                                    .saved
                                    .starred
                                    .contains(&convenience::favorite_key(host));
                                row.set_selected(
                                    self.selected == Some(host.ip) || self.marked.has(&host.ip),
                                );
                                // With several hosts marked, their menu copies all of them.
                                let many = |ui: &mut egui::Ui| {
                                    let items = self.marked.copies(
                                        at,
                                        visible.len(),
                                        |i| self.results[visible[i]].ip,
                                        |i| host_copy(&self.results[visible[i]]),
                                    );
                                    if !items.is_empty() {
                                        tables::copy_buttons(ui, items);
                                        ui.separator();
                                    }
                                };
                                let mut chosen = false;
                                row.col(|ui| {
                                    // A named, focusable control: the keyboard and screen-reader way to
                                    // the row (Tab, then Enter or the menu key).
                                    let shown = if starred {
                                        format!("★ {}", host.ip)
                                    } else {
                                        host.ip.to_string()
                                    };
                                    let response =
                                        ui.selectable_label(self.selected == Some(host.ip), shown);
                                    chosen = response.clicked();
                                    response.context_menu(|ui| {
                                        many(ui);
                                        menu = Some((
                                            index,
                                            convenience::host_menu(ui, host, starred),
                                        ));
                                    });
                                });
                                row.col(|ui| status_cell(ui, host));
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
                                for (sort, ..) in &extra {
                                    row.col(|ui| match sort {
                                        Some(i) if *i != RISK_COLUMN => {
                                            let key = HOST_COLUMN_KEYS[i - 5];
                                            ui.label(
                                                host.identity.get(key).map_or("", String::as_str),
                                            );
                                        }
                                        _ => {
                                            let worst = risk_fresh
                                                .then(|| self.risk_map.value.get(&host.ip).copied())
                                                .flatten();
                                            if let Some(s) = worst {
                                                ui.colored_label(
                                                    home::severity_color(s, ui.visuals().dark_mode),
                                                    home::severity_name(s),
                                                );
                                            }
                                        }
                                    });
                                }
                                row.col(|ui| {
                                    ui.label(if host.ports_checked {
                                        ports_text(&host.open)
                                    } else {
                                        tr!("Not checked").into()
                                    });
                                });
                                let response = row.response();
                                // Right click (or the menu key): open, ping, favorite, Wake-on-LAN.
                                response.context_menu(|ui| {
                                    many(ui);
                                    menu = Some((index, convenience::host_menu(ui, host, starred)));
                                });
                                // Ctrl or Shift marks rows; a plain click selects (the details).
                                if (chosen || response.clicked())
                                    && !self.marked.click(
                                        tables::click_keys(&response.ctx),
                                        at,
                                        visible.len(),
                                        |i| self.results[visible[i]].ip,
                                    )
                                {
                                    if self.selected != Some(host.ip) {
                                        self.script_test = None;
                                    }
                                    self.selected = Some(host.ip);
                                }
                            });
                        });
                });
            self.saved.column_widths = widths;
            let empty = visible.is_empty();
            self.rows = visible;
            if let Some(column) = sort {
                if self.sort_column == column {
                    self.sort_reverse = !self.sort_reverse;
                } else {
                    self.sort_column = column;
                    self.sort_reverse = false;
                }
                self.resort();
            }
            if empty {
                // Overlay the empty state without inserting fake scan results.
                let center = ui.max_rect().center();
                if self.results.is_empty() && self.run.is_none() {
                    let logo = icons::logo(ui.ctx());
                    let rect = egui::Rect::from_center_size(
                        center - egui::vec2(0.0, 60.0),
                        egui::vec2(48.0, 48.0),
                    );
                    // Only below the header row (a short window has no room for it).
                    if rect.top() > table_top + 34.0 {
                        let uv =
                            egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0));
                        ui.painter().image(logo.id(), rect, uv, Color32::WHITE);
                    }
                }
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
        self.workbench_window(ctx);
        self.scope_dialog(ctx);
        self.unsafe_dialog(ctx);
        self.quit_dialog(ctx);
        self.delete_dialog(ctx);
        self.shortcuts_window(ctx);
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
        self.remember_view();
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
/// The always visible Safe Mode indicator: a button with the profile that opens Settings. Its
/// accessible name and tooltip also say what the scan is about to send (the status bar shows that
/// next to it). Returns whether the button was clicked.
fn safe_mode_indicator(ui: &mut egui::Ui, badge: &SafeBadge) -> bool {
    let color = badge_color(badge.safe, ui.visuals().dark_mode);
    let sends = tr!("Sends: {}", badge.sends);
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
    clicked
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
/// The hosts table's host name column. Without optional columns it is wide enough for most
/// names and the ports take the rest of the width (no gap opens between them); with optional
/// columns the host name gives way instead, so the ports stay on screen.
fn hostname_column(extra: bool, widths: &tables::Widths) -> Column {
    if extra {
        Column::remainder().at_least(80.0).clip(true)
    } else {
        tables::sized(widths, ("hosts.hostname", 140.0))
            .at_least(80.0)
            .clip(true)
    }
}
/// The hosts table's last column (open ports); see [`hostname_column`].
fn ports_column(extra: bool, widths: &tables::Widths) -> Column {
    if extra {
        tables::sized(widths, ("hosts.ports", 140.0))
    } else {
        Column::remainder().at_least(110.0)
    }
}
/// What copying a host copies: its address, and its row (tab-separated).
fn host_copy(host: &scan::Host) -> (String, String) {
    let ip = host.ip.to_string();
    let row = [
        ip.as_str(),
        &host.hostname,
        &host.mac,
        &ports_text(&host.open),
    ]
    .join("\t");
    (ip, row)
}

/// The status of a host in the table: a coloured dot and the status in words (the words carry
/// the meaning; the dot makes the column scannable).
fn status_cell(ui: &mut egui::Ui, host: &scan::Host) {
    let dark = ui.visuals().dark_mode;
    let color = if host.responding {
        badge_color(true, dark)
    } else if !host.errors.is_empty() && !host.errors.iter().any(|e| scan::is_unused_note(e)) {
        badge_color(false, dark)
    } else {
        ui.visuals().weak_text_color()
    };
    let (rect, _) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 4.0, color);
    if host.responding {
        ui.label(host_status(host));
    } else {
        ui.weak(host_status(host));
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
/// The application icon (assets/icon/, also embedded in the .exe by build.rs) as window icon.
/// Windows scales this one image down to the 16 px title bar and 24 px taskbar button, so it gets
/// the 48 px render of the simplified small-size design; the macOS dock and Linux want 256 px.
#[cfg(windows)]
const WINDOW_ICON_PNG: &[u8] = icons::LOGO_PNG;
#[cfg(not(windows))]
const WINDOW_ICON_PNG: &[u8] = include_bytes!("../../assets/icon/icon-256.png");

fn window_icon() -> egui::IconData {
    let image = image::load_from_memory_with_format(WINDOW_ICON_PNG, image::ImageFormat::Png)
        .expect("the bundled icon is a valid PNG")
        .into_rgba8();
    let (width, height) = image.dimensions();
    egui::IconData {
        rgba: image.into_raw(),
        width,
        height,
    }
}

pub fn run(screenshot: Option<PathBuf>) -> eframe::Result<()> {
    // Before any window exists: the taskbar groups the window under this ID.
    #[cfg(windows)]
    desktop::set_app_user_model_id();
    // One window per user session; a screenshot run is a self-test and always starts.
    #[cfg(windows)]
    let _instance = match screenshot {
        Some(_) => None,
        None => match desktop::claim_single_instance() {
            desktop::Instance::Another => return Ok(()),
            desktop::Instance::First(guard) => Some(guard),
        },
    };
    let (saved, unreadable) = if screenshot.is_none() {
        load_saved(&saved_path())
    } else {
        (Saved::default(), None)
    };
    // Screenshot states show the larger windows; the plain screenshot keeps the default.
    let size = if screenshot.is_some()
        && std::env::var("NETWORK_SCOPE_SCREENSHOT_STATE").is_ok_and(|s| !s.contains("-small"))
    {
        [1100.0, 720.0]
    } else {
        desktop::DEFAULT_SIZE
    };
    let viewport = egui::ViewportBuilder::default()
        .with_inner_size(size)
        .with_min_inner_size(desktop::MIN_SIZE)
        // Shown in the title bar and taskbar; without it eframe uses the egui logo.
        .with_icon(window_icon())
        // The desktop file name and Wayland/X11 application ID on Linux.
        .with_app_id("network-scope");
    let options = eframe::NativeOptions {
        // The last size and place of the window (nothing saved yet: the defaults above).
        viewport: saved.window.apply(viewport),
        ..Default::default()
    };
    eframe::run_native(
        "Network Scope",
        options,
        Box::new(move |cc| {
            let mut app = Scanner::new(cc, screenshot, saved);
            if let Some(why) = unreadable {
                app.error = tr!(
                    "The preferences could not be read ({}); the defaults are in use. The old file was kept as {}.",
                    why,
                    BAD_PREFS
                );
            }
            Ok(Box::new(app))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn window_icon_decodes_to_a_square_rgba_image() {
        let icon = window_icon();
        let size = if cfg!(windows) { 48 } else { 256 };
        assert_eq!((icon.width, icon.height), (size, size));
        assert_eq!(icon.rgba.len(), (size * size * 4) as usize);
        // Transparent corner: the round mark, not a square tile.
        assert_eq!(icon.rgba[3], 0);
    }
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

    #[test]
    fn preferences_survive_a_broken_file_and_are_written_whole() {
        let dir = std::env::temp_dir().join(format!("ns-gui-prefs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("preferences.json");
        // No file (a first start): the defaults, and nothing to report.
        let (first, why) = load_saved(&path);
        assert!(why.is_none() && first.notes.is_empty());
        let mut saved = Saved::default();
        saved
            .notes
            .insert("10.0.0.5".parse().unwrap(), "the PLC".into());
        write_prefs_to(&path, &saved.to_disk()).unwrap();
        assert!(!path.with_extension("json.tmp").exists());
        let (back, why) = load_saved(&path);
        assert!(why.is_none());
        assert_eq!(back.notes, saved.notes);
        // A file cut short: reported, and kept next to the preferences.
        let bytes = std::fs::read(&path).unwrap();
        let half = &bytes[..bytes.len() / 2];
        std::fs::write(&path, half).unwrap();
        let (fresh, why) = load_saved(&path);
        assert!(why.is_some() && fresh.notes.is_empty());
        assert_eq!(std::fs::read(dir.join(BAD_PREFS)).unwrap(), half);
        std::fs::remove_dir_all(&dir).unwrap();
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
                    tables::plain_labels(ui);
                    TableBuilder::new(ui)
                        .striped(true)
                        .resizable(true)
                        .sense(egui::Sense::click())
                        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                        .column(Column::initial(120.0).at_least(80.0))
                        .column(Column::initial(110.0))
                        .column(Column::initial(65.0))
                        .column(hostname_column(false, &Default::default()))
                        .column(ports_column(false, &Default::default()))
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
                                row.set_selected(false);
                                row.col(|ui| {
                                    let _ = ui.selectable_label(false, host.ip.to_string());
                                });
                                row.col(|ui| status_cell(ui, host));
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

// Declared last: a test reads the code of this file up to the first test attribute.
#[cfg(test)]
mod uitest;
