// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! The device timeline, a panel under the page opened from the host details: when a device was first seen, when
//! its address, MAC or name changed, which ports opened or closed and which findings appeared or
//! were resolved, newest first. The data is `store::device_history`, the same function behind
//! `devices --history`; it runs on the inventory worker, never on the UI thread.
use super::*;
use crate::devices::{DeviceHistory, history_text};

/// The window's state: what is shown for which device.
pub(super) struct Timeline {
    /// Matches the answer of the worker to the latest request.
    pub token: u64,
    /// What the history is looked up by: the MAC address, else the IP address.
    pub query: String,
    pub label: String,
    /// `None` while the worker reads the inventory.
    pub result: Option<Result<Box<DeviceHistory>, String>>,
}

/// How an event is coloured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Tone {
    Info,
    /// Something got better (a finding was resolved).
    Good,
    /// Something changed that deserves a look.
    Warn,
    /// A new risk.
    Bad,
}

/// One line of the timeline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Row {
    pub when: String,
    pub scan_id: i64,
    pub label: &'static str,
    pub detail: String,
    pub tone: Tone,
}

/// The heading and tone of a history event kind (see `devices::HistoryEvent::kind`).
pub(super) fn event_label(kind: &str) -> (&'static str, Tone) {
    match kind {
        "first-seen" => (tr!("First seen"), Tone::Info),
        "ip-changed" => (tr!("Address changed"), Tone::Warn),
        "mac-changed" => (tr!("MAC changed"), Tone::Warn),
        "hostname-changed" => (tr!("Name changed"), Tone::Info),
        "port-opened" => (tr!("Port opened"), Tone::Warn),
        "port-closed" => (tr!("Port closed"), Tone::Info),
        "udp-answering" => (tr!("UDP answering"), Tone::Warn),
        "udp-silent" => (tr!("UDP silent"), Tone::Info),
        "finding-appeared" => (tr!("Finding appeared"), Tone::Bad),
        "finding-resolved" => (tr!("Finding resolved"), Tone::Good),
        _ => (tr!("Event"), Tone::Info),
    }
}

/// The events newest first (events of one scan keep their order).
pub(super) fn rows(h: &DeviceHistory) -> Vec<Row> {
    h.events
        .iter()
        .rev()
        .map(|e| {
            let (label, tone) = event_label(e.kind);
            Row {
                when: crate::report::fmt_time(e.timestamp),
                scan_id: e.scan_id,
                label,
                // The window font has no arrow.
                detail: e.detail.replace('→', "->"),
                tone,
            }
        })
        .collect()
}

/// The header lines: first and last sighting, addresses, MACs, names and open ports.
pub(super) fn summary(h: &DeviceHistory) -> Vec<String> {
    let unreadable = (h.unreadable > 0).then(|| {
        tr!(
            "{} of the saved scans could not be read; the history may be incomplete.",
            h.unreadable
        )
    });
    let (Some(first), Some(last)) = (h.first_seen, h.last_seen) else {
        let mut lines = vec![tr!(
            "Not seen in any of {} saved scans (a scan that never reached it, or none saved yet).",
            h.scans
        )];
        lines.extend(unreadable);
        return lines;
    };
    let join = |v: Vec<String>| {
        if v.is_empty() {
            "—".to_string()
        } else {
            v.join(", ")
        }
    };
    vec![
        tr!(
            "First seen {} · last seen {} · in {} of {} saved scans",
            crate::report::fmt_time(first),
            crate::report::fmt_time(last),
            h.sightings,
            h.scans
        ),
        tr!(
            "Addresses: {}",
            join(h.ips.iter().map(ToString::to_string).collect())
        ),
        tr!("MAC addresses: {}", join(h.macs.clone())),
        tr!("Names: {}", join(h.hostnames.clone())),
        tr!(
            "Open TCP ports (latest completed scan): {}",
            join(h.open_tcp.iter().map(u16::to_string).collect())
        ),
    ]
    .into_iter()
    .chain(unreadable)
    .collect()
}

/// What a host's history is looked up by: its MAC address when it has one (it survives an
/// address change), else its IP address.
pub(super) fn query_for(host: &scan::Host) -> String {
    if host.mac.trim().is_empty() {
        host.ip.to_string()
    } else {
        host.mac.trim().to_string()
    }
}

fn tone_color(tone: Tone) -> Option<Color32> {
    match tone {
        Tone::Info => None,
        Tone::Good => Some(Color32::from_rgb(30, 130, 70)),
        Tone::Warn => Some(Color32::from_rgb(170, 100, 15)),
        Tone::Bad => Some(Color32::from_rgb(205, 70, 70)),
    }
}

impl Scanner {
    /// Opens (or refreshes) the timeline of a host and asks the worker for its history.
    pub(super) fn open_timeline(&mut self, host: &scan::Host) {
        self.timeline_tokens += 1;
        let query = query_for(host);
        let label = if host.hostname.is_empty() {
            host.ip.to_string()
        } else {
            format!("{} ({})", host.hostname, host.ip)
        };
        self.timeline = Some(Timeline {
            token: self.timeline_tokens,
            query: query.clone(),
            label,
            result: None,
        });
        if self.screenshot.is_none() {
            self.submit(Job::History(self.timeline_tokens, query));
        }
    }

    /// The timeline panel under the page, while a device's timeline is open. It spans the page
    /// (not the sidebar or the host details) and can be made taller by dragging its edge.
    pub(super) fn timeline_panel(&mut self, root: &mut egui::Ui) {
        let Some(t) = self.timeline.as_ref() else {
            return;
        };
        let (title, query) = (tr!("Device timeline · {}", t.label), t.query.clone());
        let mut open = true;
        let mut refresh = false;
        let mut copy = None;
        let busy = t.result.is_none();
        let result = &t.result;
        let max = (root.available_height() * 0.5).max(140.0);
        egui::Panel::bottom("device_timeline")
            .resizable(true)
            .default_size(240.0_f32.min(max))
            .size_range(120.0..=max)
            .show(root, |ui| {
                ui.add_space(4.0);
                // A narrow panel puts the title above the buttons, so it stays readable.
                let narrow = ui.available_width() < 460.0;
                if narrow {
                    ui.add(egui::Label::new(RichText::new(&title).strong()).truncate());
                }
                ui.horizontal(|ui| {
                    if !narrow {
                        ui.add(egui::Label::new(RichText::new(&title).strong()).truncate());
                    }
                    if busy {
                        ui.spinner();
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button(tr!("Close")).clicked() {
                            open = false;
                        }
                        if let Some(Ok(h)) = result
                            && ui.button(tr!("Copy as text")).clicked()
                        {
                            copy = Some(history_text(h));
                        }
                        if ui
                            .add_enabled(!busy, egui::Button::new(tr!("Refresh")))
                            .clicked()
                        {
                            refresh = true;
                        }
                    });
                });
                ui.separator();
                // Everything under the header scrolls together.
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.weak(tr!("Looked up by {}", query));
                        match result {
                            None => {
                                ui.label(tr!("Reading the saved inventory…"));
                            }
                            Some(Err(e)) => {
                                ui.colored_label(Color32::from_rgb(205, 70, 70), e);
                            }
                            Some(Ok(h)) => {
                                for line in summary(h) {
                                    ui.label(line);
                                }
                                ui.separator();
                                let rows = rows(h);
                                if rows.is_empty() {
                                    ui.label(tr!(
                                        "No events yet: the device was not seen in a saved scan."
                                    ));
                                }
                                egui::Grid::new("timeline_rows")
                                    .num_columns(4)
                                    .striped(true)
                                    .show(ui, |ui| {
                                        for r in &rows {
                                            ui.label(&r.when);
                                            ui.label(format!("#{}", r.scan_id));
                                            let text = RichText::new(r.label).strong();
                                            match tone_color(r.tone) {
                                                Some(c) => ui.label(text.color(c)),
                                                None => ui.label(text),
                                            };
                                            ui.label(&r.detail);
                                            ui.end_row();
                                        }
                                    });
                            }
                        }
                    });
            });
        if let Some(text) = copy {
            root.ctx().copy_text(text);
        }
        if refresh {
            let host = self.results.iter().find(|h| query_for(h) == query).cloned();
            if let Some(host) = host {
                self.open_timeline(&host);
            } else if let Some(t) = self.timeline.as_mut() {
                self.timeline_tokens += 1;
                t.token = self.timeline_tokens;
                t.result = None;
                let (token, q) = (t.token, t.query.clone());
                self.submit(Job::History(token, q));
            }
        }
        if !open {
            self.timeline = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::HistoryEvent;

    fn event(scan_id: i64, timestamp: i64, kind: &'static str, detail: &str) -> HistoryEvent {
        HistoryEvent {
            scan_id,
            timestamp,
            kind,
            detail: detail.into(),
        }
    }

    #[test]
    fn rows_are_newest_first_with_a_heading_and_a_tone_per_kind() {
        let h = DeviceHistory {
            events: vec![
                event(1, 1_000, "first-seen", "10.0.0.5 (AA:BB:CC:00:11:22)"),
                event(2, 2_000, "ip-changed", "10.0.0.5 → 10.0.0.6"),
                event(2, 2_000, "port-opened", "TCP 23 open (not in scan #1)"),
                event(
                    2,
                    2_000,
                    "finding-appeared",
                    "HIGH Telnet (telnet-open) on 10.0.0.6:23",
                ),
                event(
                    3,
                    3_000,
                    "finding-resolved",
                    "HIGH Telnet (telnet-open) on 10.0.0.6:23",
                ),
                event(3, 3_000, "something-new", "x"),
            ],
            ..Default::default()
        };
        let r = rows(&h);
        assert_eq!(r.len(), 6);
        assert_eq!(r[0].label, "Event", "an unknown kind still shows");
        assert_eq!((r[1].label, r[1].tone), ("Finding resolved", Tone::Good));
        assert_eq!((r[2].label, r[2].tone), ("Finding appeared", Tone::Bad));
        assert_eq!((r[3].label, r[3].tone), ("Port opened", Tone::Warn));
        assert_eq!((r[4].label, r[4].tone), ("Address changed", Tone::Warn));
        assert_eq!((r[5].label, r[5].tone), ("First seen", Tone::Info));
        assert_eq!(r[5].scan_id, 1);
        assert!(r[5].when.contains("1970"), "{}", r[5].when);
        assert!(r[2].detail.contains("telnet-open"));
        assert_eq!(
            r[4].detail, "10.0.0.5 -> 10.0.0.6",
            "no arrow glyph in the GUI font"
        );
        // Every kind the history can produce has its own heading.
        for kind in [
            "first-seen",
            "ip-changed",
            "mac-changed",
            "hostname-changed",
            "port-opened",
            "port-closed",
            "udp-answering",
            "udp-silent",
            "finding-appeared",
            "finding-resolved",
        ] {
            assert_ne!(event_label(kind).0, "Event", "{kind}");
        }
        assert!(rows(&DeviceHistory::default()).is_empty());
    }

    #[test]
    fn the_summary_says_when_a_device_was_never_seen() {
        let never = DeviceHistory {
            scans: 4,
            ..Default::default()
        };
        let lines = summary(&never);
        assert_eq!(lines.len(), 1);
        assert!(
            lines[0].contains("Not seen in any of 4 saved scans"),
            "{lines:?}"
        );
        let seen = DeviceHistory {
            first_seen: Some(1_000),
            last_seen: Some(2_000),
            sightings: 2,
            scans: 3,
            ips: vec!["10.0.0.5".parse().unwrap(), "10.0.0.6".parse().unwrap()],
            macs: vec!["AA:BB:CC:00:11:22".into()],
            open_tcp: vec![22, 80],
            ..Default::default()
        };
        let lines = summary(&seen);
        assert!(lines[0].contains("in 2 of 3 saved scans"), "{lines:?}");
        assert_eq!(lines[1], "Addresses: 10.0.0.5, 10.0.0.6");
        assert_eq!(lines[2], "MAC addresses: AA:BB:CC:00:11:22");
        assert_eq!(lines[3], "Names: —");
        assert_eq!(lines[4], "Open TCP ports (latest completed scan): 22, 80");
        assert_eq!(lines.len(), 5);
        let partial = DeviceHistory {
            unreadable: 1,
            ..seen
        };
        assert_eq!(
            summary(&partial)[5],
            "1 of the saved scans could not be read; the history may be incomplete."
        );
        let never_partial = DeviceHistory {
            unreadable: 2,
            ..never
        };
        assert!(summary(&never_partial)[1].starts_with("2 of the saved scans"));
    }

    #[test]
    fn the_headings_and_the_summary_follow_the_language() {
        super::i18n::set(super::i18n::Lang::German);
        assert_eq!(event_label("first-seen").0, "Erstmals gesehen");
        assert_eq!(event_label("finding-resolved").0, "Befund behoben");
        assert_eq!(event_label("no-such-kind").0, "Ereignis");
        let never = DeviceHistory {
            scans: 4,
            ..Default::default()
        };
        assert!(summary(&never)[0].starts_with("In keinem von 4 gespeicherten Scans"));
        let seen = DeviceHistory {
            first_seen: Some(1_000),
            last_seen: Some(2_000),
            sightings: 2,
            scans: 3,
            ..Default::default()
        };
        let lines = summary(&seen);
        assert!(
            lines[0].contains("in 2 von 3 gespeicherten Scans"),
            "{lines:?}"
        );
        assert_eq!(lines[1], "Adressen: —");
        super::i18n::set(super::i18n::Lang::English);
        assert_eq!(event_label("first-seen").0, "First seen");
        assert_eq!(summary(&seen)[1], "Addresses: —");
    }

    #[test]
    fn a_host_is_looked_up_by_mac_when_it_has_one() {
        let host = |mac: &str| scan::Host {
            ip: "10.0.0.5".parse().unwrap(),
            responding: true,
            ping: None,
            ttl: None,
            hostname: String::new(),
            mac: mac.into(),
            open: vec![],
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity: Default::default(),
            udp_open: vec![],
            trace: vec![],
        };
        assert_eq!(query_for(&host(" AA:BB:CC:00:11:22 ")), "AA:BB:CC:00:11:22");
        assert_eq!(query_for(&host("")), "10.0.0.5");
        // Both are accepted by the history lookup the worker runs.
        assert!(crate::devices::HistoryKey::parse(&query_for(&host("AA:BB:CC:00:11:22"))).is_ok());
        assert!(crate::devices::HistoryKey::parse(&query_for(&host(""))).is_ok());
    }

    #[test]
    fn the_rows_come_from_the_same_function_as_the_cli_history() {
        let path = std::env::temp_dir().join(format!(
            "ns-gui-timeline-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let scan = |ip: &str, open: Vec<u16>, telnet: bool| {
            let mut h = scan::Host {
                ip: ip.parse().unwrap(),
                responding: true,
                ping: None,
                ttl: None,
                hostname: "plc-1".into(),
                mac: "AA:BB:CC:00:11:22".into(),
                open,
                closed: 0,
                unanswered: 0,
                errors: vec![],
                ports_checked: true,
                identity: Default::default(),
                udp_open: vec![],
                trace: vec![],
            };
            if telnet {
                h.identity.insert("svc.23".into(), "telnet".into());
            }
            store::Snapshot {
                sent: vec![],
                targets: "10.0.0.0/24".into(),
                complete: true,
                settings: scan::Settings {
                    ports: "22,23".into(),
                    ..Default::default()
                },
                hosts: vec![h],
                observations: vec![],
                notes: Default::default(),
            }
        };
        store::save(&path, &scan("10.0.0.5", vec![22], false)).unwrap();
        store::save(&path, &scan("10.0.0.6", vec![22, 23], true)).unwrap();
        let history = store::device_history(&path, "aa-bb-cc-00-11-22").unwrap();
        let r = rows(&history);
        let labels: Vec<&str> = r.iter().map(|r| r.label).collect();
        assert_eq!(
            labels,
            [
                "Finding appeared",
                "Port opened",
                "Address changed",
                "First seen"
            ],
            "{r:?}"
        );
        assert!(summary(&history)[0].contains("in 2 of 2 saved scans"));
        for suffix in ["", "-wal", "-shm"] {
            let mut p = path.as_os_str().to_owned();
            p.push(suffix);
            let _ = std::fs::remove_file(PathBuf::from(p));
        }
    }
}
