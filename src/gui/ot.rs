//! Passive OT asset discovery in the GUI. A pcap file, or a live capture through
//! `capture::PassiveCapture` (which has no transmit call), is fed to `otpassive::Tracker` on a
//! thread of its own: a long capture must not hold up the inventory worker or the window.
use super::{Job, Scanner};
use crate::{capture, otpassive, passive, store};
use eframe::egui;
use egui_extras::{Column, TableBuilder};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc,
    },
    time::{Duration, Instant},
};

/// How often a live capture publishes the asset table while it runs.
const PROGRESS_EVERY: Duration = Duration::from_secs(2);

enum Source {
    Pcap(PathBuf),
    Live { interface: String, seconds: u64 },
}
impl Source {
    fn label(&self) -> String {
        match self {
            Source::Pcap(p) => format!("ot-passive:{}", p.display()),
            Source::Live { interface, .. } => format!("ot-passive:{interface}"),
        }
    }
}

/// One step of an ingest loop.
enum Step {
    Frame(i64, Vec<u8>),
    /// Nothing captured right now (live only).
    Idle,
    End,
}

enum Msg {
    /// Assets seen so far (live capture).
    Progress(Vec<otpassive::Asset>),
    Done {
        observations: Vec<passive::Observation>,
        assets: Vec<otpassive::Asset>,
        error: Option<String>,
    },
}

struct Run {
    cancel: Arc<AtomicBool>,
    frames: Arc<AtomicU64>,
    rx: mpsc::Receiver<Msg>,
    started: Instant,
    label: String,
    live: bool,
}

pub(super) struct OtState {
    run: Option<Run>,
    pub(super) assets: Vec<otpassive::Asset>,
    observations: usize,
    frames: u64,
    label: String,
    error: String,
    complete: bool,
    seconds: u64,
}
impl Default for OtState {
    fn default() -> Self {
        Self {
            run: None,
            assets: vec![],
            observations: 0,
            frames: 0,
            label: String::new(),
            error: String::new(),
            complete: true,
            seconds: 300,
        }
    }
}
impl OtState {
    pub(super) fn running(&self) -> bool {
        self.run.is_some()
    }
    /// A live OT capture holds the interface.
    pub(super) fn capturing(&self) -> bool {
        self.run.as_ref().is_some_and(|r| r.live)
    }
    pub(super) fn cancel(&self) {
        if let Some(run) = &self.run {
            run.cancel.store(true, Ordering::Relaxed);
        }
    }
    /// Sample table for screenshot runs.
    pub(super) fn demo(&mut self) {
        self.label = "ot-passive:plant.pcap".into();
        self.frames = 18_204;
        self.observations = 9;
        self.assets = vec![
            otpassive::Asset {
                ips: vec!["10.0.0.5".parse().unwrap_or(std::net::IpAddr::from([0; 4]))],
                vendor: "Siemens".into(),
                product: "S7-1500".into(),
                firmware: "V2.9.4".into(),
                serial: "S C-X4U12345".into(),
                protocols: vec!["S7comm".into()],
                roles: vec!["server".into()],
                control_traffic: vec!["S7comm: PLC Stop".into()],
                first_seen: 1_763_450_000,
                last_seen: 1_763_453_600,
                ..Default::default()
            },
            otpassive::Asset {
                ips: vec!["10.0.0.20"
                    .parse()
                    .unwrap_or(std::net::IpAddr::from([0; 4]))],
                vendor: "Rockwell Automation".into(),
                product: "1756-EN2T".into(),
                firmware: "11.2".into(),
                protocols: vec!["EtherNet/IP".into()],
                roles: vec!["server".into()],
                first_seen: 1_763_450_100,
                last_seen: 1_763_453_500,
                ..Default::default()
            },
        ];
    }
    #[cfg(test)]
    fn wait(&mut self) {
        while self.run.is_some() {
            self.poll();
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    /// Takes new messages; returns the finished capture (label, observations, complete).
    fn poll(&mut self) -> Option<(String, Vec<passive::Observation>, bool)> {
        let run = self.run.as_ref()?;
        self.frames = run.frames.load(Ordering::Relaxed);
        let mut finished = None;
        loop {
            match run.rx.try_recv() {
                Ok(Msg::Progress(assets)) => self.assets = assets,
                Ok(Msg::Done {
                    observations,
                    assets,
                    error,
                }) => {
                    finished = Some((observations, assets, error));
                    break;
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    finished = Some((vec![], vec![], Some("OT capture thread stopped".into())));
                    break;
                }
            }
        }
        let (observations, assets, error) = finished?;
        let cancelled = run.cancel.load(Ordering::Relaxed);
        let label = run.label.clone();
        self.run = None;
        self.complete = error.is_none() && !cancelled;
        self.error = error.unwrap_or_default();
        self.observations = observations.len();
        self.assets = assets;
        Some((label, observations, self.complete))
    }
    fn begin(&mut self, source: Source, ctx: egui::Context) {
        let cancel = Arc::new(AtomicBool::new(false));
        let frames = Arc::new(AtomicU64::new(0));
        let (tx, rx) = mpsc::channel();
        self.label = source.label();
        let live = matches!(source, Source::Live { .. });
        self.assets.clear();
        self.observations = 0;
        self.frames = 0;
        self.error.clear();
        self.complete = true;
        self.run = Some(Run {
            cancel: cancel.clone(),
            frames: frames.clone(),
            rx,
            started: Instant::now(),
            label: self.label.clone(),
            live,
        });
        std::thread::spawn(move || ingest(source, &cancel, &frames, &tx, &ctx));
    }
}

/// Feeds frames to the tracker until the source ends, an error occurs or `cancel` is set.
/// `tick` runs every [`PROGRESS_EVERY`]. What was fed stays in the tracker on an error.
fn pump(
    tracker: &mut otpassive::Tracker,
    mut next: impl FnMut() -> Result<Step, String>,
    cancel: &AtomicBool,
    frames: &AtomicU64,
    mut tick: impl FnMut(&otpassive::Tracker),
) -> Result<(), String> {
    let mut last = Instant::now();
    let result = loop {
        if cancel.load(Ordering::Relaxed) {
            break Ok(());
        }
        match next() {
            Ok(Step::Frame(ts, frame)) => {
                tracker.feed(&frame, ts);
                frames.store(tracker.frames, Ordering::Relaxed);
            }
            Ok(Step::Idle) => std::thread::sleep(Duration::from_millis(5)),
            Ok(Step::End) => break Ok(()),
            Err(e) => break Err(e),
        }
        if last.elapsed() >= PROGRESS_EVERY {
            last = Instant::now();
            tick(tracker);
        }
    };
    frames.store(tracker.frames, Ordering::Relaxed);
    result
}

fn ingest_pcap(
    path: &std::path::Path,
    tracker: &mut otpassive::Tracker,
    cancel: &AtomicBool,
    frames: &AtomicU64,
) -> Result<(), String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut reader = crate::pcapfile::Reader::new(std::io::BufReader::new(file))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    pump(
        tracker,
        || {
            Ok(match reader.next_frame()? {
                Some((ts, frame)) => Step::Frame(ts, frame),
                None => Step::End,
            })
        },
        cancel,
        frames,
        |_| {},
    )
}

fn ingest_live(
    interface: &str,
    seconds: u64,
    tracker: &mut otpassive::Tracker,
    cancel: &AtomicBool,
    frames: &AtomicU64,
    progress: impl FnMut(&otpassive::Tracker),
) -> Result<(), String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    // Receive-only: PassiveCapture exposes no way to transmit.
    let mut cap = capture::PassiveCapture::open(interface)?;
    let end = Instant::now() + Duration::from_secs(seconds.clamp(1, 7 * 86_400));
    pump(
        tracker,
        || {
            if Instant::now() >= end {
                return Ok(Step::End);
            }
            Ok(match cap.next()? {
                Some(frame) => Step::Frame(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs() as i64),
                    frame,
                ),
                None => Step::Idle,
            })
        },
        cancel,
        frames,
        progress,
    )
}

fn ingest(
    source: Source,
    cancel: &AtomicBool,
    frames: &AtomicU64,
    tx: &mpsc::Sender<Msg>,
    ctx: &egui::Context,
) {
    let mut tracker = otpassive::Tracker::new();
    let result = match &source {
        Source::Pcap(path) => ingest_pcap(path, &mut tracker, cancel, frames),
        Source::Live { interface, seconds } => {
            ingest_live(interface, *seconds, &mut tracker, cancel, frames, |t| {
                let _ = tx.send(Msg::Progress(otpassive::assets(&t.observations())));
                ctx.request_repaint();
            })
        }
    };
    let observations = tracker.observations();
    let assets = otpassive::assets(&observations);
    let _ = tx.send(Msg::Done {
        observations,
        assets,
        error: result.err(),
    });
    ctx.request_repaint();
}

fn list(items: &[String]) -> String {
    items.join(", ")
}

impl Scanner {
    pub(super) fn poll_ot(&mut self) {
        let Some((label, observations, complete)) = self.ot.poll() else {
            return;
        };
        if observations.is_empty() {
            self.status = format!("OT passive: no observations in {label}");
            return;
        }
        if self.screenshot.is_some() {
            return;
        }
        // Saved like `ot-listen` does, so `ot-assets ID` works on it later.
        let snapshot = store::Snapshot {
            targets: label,
            complete,
            settings: Default::default(),
            hosts: vec![],
            observations,
            notes: Default::default(),
        };
        self.submit(Job::Save(Box::new(snapshot), "ot"));
    }

    fn export_assets(&mut self, csv: bool) {
        let extension = if csv { "csv" } else { "json" };
        let Some(path) = rfd::FileDialog::new()
            .set_file_name(format!("ot-assets.{extension}"))
            .add_filter("OT assets", &[extension])
            .save_file()
        else {
            return;
        };
        self.status = format!("Writing {}…", path.display());
        self.submit(Job::ExportAssets(self.ot.assets.clone(), csv, path));
    }

    /// The OT part of the Passive window.
    pub(super) fn ot_section(&mut self, ui: &mut egui::Ui) {
        ui.separator();
        ui.strong("OT passive asset discovery");
        ui.label(
            "Reads a capture file or listens on the interface above. Nothing is transmitted. \
             Industrial protocol traffic (Modbus, S7, EtherNet/IP, OPC UA, Profinet...) builds the asset table.",
        );
        let running = self.ot.running();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!running, egui::Button::new("Open pcap…"))
                .clicked()
            {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("Packet capture", &["pcap", "pcapng", "cap"])
                    .add_filter("All files", &["*"])
                    .pick_file()
                {
                    self.ot.begin(Source::Pcap(path), ui.ctx().clone());
                }
            }
            let can_listen = !running
                && self.listening.is_none()
                && self.run.is_none()
                && !self.saved.settings.interface.is_empty();
            ui.add_enabled(
                !running,
                egui::DragValue::new(&mut self.ot.seconds)
                    .range(1..=604_800)
                    .suffix(" s"),
            );
            if ui
                .add_enabled(can_listen, egui::Button::new("Listen (OT)"))
                .on_disabled_hover_text("Choose an interface; stop other captures and scans first.")
                .clicked()
            {
                let source = Source::Live {
                    interface: self.saved.settings.interface.clone(),
                    seconds: self.ot.seconds,
                };
                self.ot.begin(source, ui.ctx().clone());
            }
            if running && ui.button("Stop").clicked() {
                self.ot.cancel();
            }
        });
        if let Some(run) = &self.ot.run {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(format!(
                    "{} · {} frames processed · {:.0}s",
                    run.label,
                    self.ot.frames,
                    run.started.elapsed().as_secs_f32()
                ));
            });
        } else if !self.ot.label.is_empty() {
            ui.label(format!(
                "{} · {} frames · {} observations · {} OT assets{}",
                self.ot.label,
                self.ot.frames,
                self.ot.observations,
                self.ot.assets.len(),
                if self.ot.complete { "" } else { " (partial)" }
            ));
        }
        if !self.ot.error.is_empty() {
            ui.colored_label(egui::Color32::DARK_RED, &self.ot.error);
        }
        if self.ot.assets.is_empty() {
            return;
        }
        ui.horizontal(|ui| {
            if ui.button("Export assets CSV…").clicked() {
                self.export_assets(true);
            }
            if ui.button("Export assets JSON…").clicked() {
                self.export_assets(false);
            }
            ui.colored_label(CONTROL, "■");
            ui.label("control traffic seen (writes, program changes, stop/start)");
        });
        asset_table(ui, &self.ot.assets);
    }
}

const CONTROL: egui::Color32 = egui::Color32::from_rgb(190, 60, 20);

fn asset_table(ui: &mut egui::Ui, assets: &[otpassive::Asset]) {
    TableBuilder::new(ui)
        .id_salt("ot_assets")
        .striped(true)
        .resizable(true)
        .max_scroll_height(240.0)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::initial(110.0).clip(true))
        .column(Column::initial(120.0).clip(true))
        .column(Column::initial(120.0).clip(true))
        .column(Column::initial(80.0).clip(true))
        .column(Column::initial(80.0).clip(true))
        .column(Column::initial(120.0).clip(true))
        .column(Column::initial(80.0).clip(true))
        .column(Column::initial(130.0).clip(true))
        .column(Column::initial(130.0).clip(true))
        .column(Column::remainder().clip(true))
        .header(22.0, |mut row| {
            for h in [
                "Address",
                "Vendor",
                "Product",
                "Firmware",
                "Serial",
                "Protocols",
                "Roles",
                "First seen",
                "Last seen",
                "Control traffic",
            ] {
                row.col(|ui| {
                    ui.strong(h);
                });
            }
        })
        .body(|body| {
            body.rows(22.0, assets.len(), |mut row| {
                let a = &assets[row.index()];
                let control = !a.control_traffic.is_empty();
                let text = |s: String| {
                    let t = egui::RichText::new(s);
                    if control {
                        t.color(CONTROL).strong()
                    } else {
                        t
                    }
                };
                let address = if a.ips.is_empty() {
                    a.mac.clone()
                } else {
                    a.ips
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                let product = if a.product.is_empty() {
                    a.name.clone()
                } else {
                    a.product.clone()
                };
                let cells = [
                    address,
                    a.vendor.clone(),
                    product,
                    a.firmware.clone(),
                    a.serial.clone(),
                    list(&a.protocols),
                    list(&a.roles),
                    seen(a.first_seen),
                    seen(a.last_seen),
                ];
                for cell in cells {
                    row.col(|ui| {
                        ui.label(text(cell));
                    });
                }
                row.col(|ui| {
                    let all = a.control_traffic.join("\n");
                    ui.label(text(list(&a.control_traffic)))
                        .on_hover_text(if control { all.as_str() } else { "None seen" });
                });
            });
        });
}

fn seen(ts: i64) -> String {
    if ts <= 0 {
        "—".into()
    } else {
        crate::report::fmt_time(ts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pump_counts_frames_stops_on_cancel_and_keeps_data_on_errors() {
        let frames = AtomicU64::new(0);
        let cancel = AtomicBool::new(false);
        let mut tracker = otpassive::Tracker::new();
        let mut n = 0;
        let result = pump(
            &mut tracker,
            || {
                n += 1;
                Ok(if n <= 5 {
                    Step::Frame(1, vec![0u8; 60])
                } else {
                    Step::End
                })
            },
            &cancel,
            &frames,
            |_| {},
        );
        assert!(result.is_ok());
        assert_eq!(frames.load(Ordering::Relaxed), 5);
        // An error mid-stream: frames fed before it stay in the tracker.
        let mut n = 0;
        let result = pump(
            &mut tracker,
            || {
                n += 1;
                if n == 3 {
                    Err("truncated record".to_string())
                } else {
                    Ok(Step::Frame(2, vec![0u8; 60]))
                }
            },
            &cancel,
            &frames,
            |_| {},
        );
        assert_eq!(result.unwrap_err(), "truncated record");
        assert_eq!(tracker.frames, 7);
        cancel.store(true, Ordering::Relaxed);
        let result = pump(
            &mut tracker,
            || Ok(Step::Frame(3, vec![])),
            &cancel,
            &frames,
            |_| {},
        );
        assert!(result.is_ok());
        assert_eq!(tracker.frames, 7, "cancelled before reading");
    }

    #[test]
    fn missing_pcap_finishes_with_an_error_off_the_ui_thread() {
        let mut state = OtState::default();
        let missing = std::env::temp_dir().join("network-scope-no-such-file.pcap");
        state.begin(Source::Pcap(missing), egui::Context::default());
        assert!(state.running());
        state.wait();
        assert!(!state.complete);
        assert!(state.error.contains("no-such-file"), "{}", state.error);
        assert_eq!(state.observations, 0);
        assert!(state.label.starts_with("ot-passive:"));
    }
}
