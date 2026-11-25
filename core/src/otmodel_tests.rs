// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
use super::*;
use std::{net::IpAddr, sync::Arc};

fn fixture(name: &str) -> String {
    format!(
        "{}/../tests/fixtures/ics/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn event(ts: i64, client: &str, server: &str, function: &str, control: bool) -> OtEvent {
    OtEvent {
        ts,
        proto: "Modbus/TCP",
        client: ip(client),
        server: ip(server),
        function: function.into(),
        control,
    }
}

/// The events of one frame (on its own tracker).
#[allow(clippy::let_and_return)] // the guard must be dropped before `out`
fn events_of(frame: &[u8], ts: i64) -> Vec<OtEvent> {
    let out = Arc::new(std::sync::Mutex::new(vec![]));
    let sink = out.clone();
    let mut t = crate::otpassive::Tracker::new();
    t.set_event_sink(Box::new(move |e| sink.lock().unwrap().push(e.clone())));
    t.feed(frame, ts);
    t.flush();
    let events = out.lock().unwrap().clone();
    events
}

/// Every frame of a fixture capture: (Unix seconds, bytes).
fn frames(name: &str) -> Vec<(i64, Vec<u8>)> {
    let file = std::fs::File::open(fixture(name)).unwrap();
    let mut reader = crate::pcapfile::Reader::new(std::io::BufReader::new(file)).unwrap();
    let mut out = vec![];
    while let Some(frame) = reader.next_frame().unwrap() {
        out.push(frame);
    }
    out
}

fn write_capture(tag: &str, frames: &[(i64, Vec<u8>)]) -> String {
    let path = std::env::temp_dir().join(format!("ns-otmodel-{tag}-{}.pcap", std::process::id()));
    let list: Vec<(u32, Vec<u8>)> = frames.iter().map(|(t, f)| (*t as u32, f.clone())).collect();
    std::fs::write(&path, crate::pcapfile::write_pcap(&list)).unwrap();
    path.to_str().unwrap().to_string()
}

/// A copy of a real Modbus read request with a write function code and a new source address:
/// the "one injected write from a new station" of ROADMAP L69, crafted from a captured frame
/// (same length: Read Holding Registers and Write Single Register both carry address and a
/// 16-bit value).
fn injected_write(frames: &[(i64, Vec<u8>)], from: [u8; 4]) -> (i64, Vec<u8>) {
    let (ts, template) = frames
        .iter()
        .find(|(ts, f)| {
            events_of(f, *ts)
                .iter()
                .any(|e| e.function == "Read Holding Registers" && e.client == ip("10.0.0.9"))
        })
        .expect("a read request in the fixture")
        .clone();
    let mut f = template;
    let ip_start = 14;
    let ihl = usize::from(f[ip_start] & 15) * 4;
    let tcp = ip_start + ihl;
    let payload = tcp + usize::from(f[tcp + 12] >> 4) * 4;
    assert_eq!(f[payload + 7], 3, "Read Holding Registers");
    f[payload + 7] = 6; // Write Single Register
    f[ip_start + 12..ip_start + 16].copy_from_slice(&from);
    (ts + 1, f)
}

/// Reads and the like only: the frames that carry no write or control function.
fn without_control(frames: &[(i64, Vec<u8>)]) -> Vec<(i64, Vec<u8>)> {
    frames
        .iter()
        .filter(|(ts, f)| !events_of(f, *ts).iter().any(|e| e.control))
        .cloned()
        .collect()
}

fn alerts_for(model: &Model, window: Option<&str>, capture: &str) -> Report {
    let window = window.map(|w| Maintenance::parse(w).unwrap());
    check_pcap(capture, model, window, true).unwrap()
}

/// The done-when of ROADMAP L69: a capture is learned, then replayed with one write injected from
/// a new station, and exactly that is reported.
#[test]
fn a_replay_with_one_injected_write_from_a_new_station_reports_exactly_that() {
    let original = frames("modbus_test_data_part1.pcap");
    let learned_from = write_capture("learn", &original);
    let model = learn_pcap(&learned_from, true).unwrap();
    assert_eq!(
        model.assets.keys().map(String::as_str).collect::<Vec<_>>(),
        ["10.0.0.3", "10.0.0.8"]
    );
    let plc = &model.assets["10.0.0.3"];
    assert_eq!(
        plc.peers.keys().map(String::as_str).collect::<Vec<_>>(),
        ["10.0.0.57", "10.0.0.9"]
    );
    assert!(plc.functions["Modbus/TCP: Write Single Register"].control);
    assert_eq!(plc.events, 16);

    // The capture contains Restart Communications and Force Listen Only Mode, which are Stop
    // class: declared as maintenance (the capture ran on Thursday 2004-08-26, 12:01-12:22 UTC).
    let window = Some("Thu 11:00-13:00");
    let clean = alerts_for(&model, window, &learned_from);
    assert!(
        clean.alerts.is_empty(),
        "the learned traffic itself: {clean:?}"
    );
    assert_eq!(clean.events, 20);

    let mut replay = original.clone();
    let injected = injected_write(&original, [10, 0, 0, 99]);
    replay.insert(replay.len() / 2, injected);
    let path = write_capture("replay", &replay);
    let report = alerts_for(&model, window, &path);
    assert_eq!(report.events, 21);
    assert_eq!(report.alerts.len(), 1, "exactly one alert: {report:#?}");
    let a = &report.alerts[0];
    assert_eq!(a.kind, "new-station");
    assert_eq!(a.client, "10.0.0.99");
    assert_eq!(a.server, "10.0.0.3");
    assert_eq!(a.function, "Write Single Register");
    assert!(a.control);
    assert_eq!(a.severity, Severity::High);
    assert_eq!(a.occurrences, 1);
    assert!(a.message.contains("never talked"), "{}", a.message);
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(learned_from);
}

/// Without a declared window every Stop is outside it.
#[test]
fn a_stop_is_reported_unless_it_is_inside_the_maintenance_window() {
    let original = frames("modbus_test_data_part1.pcap");
    let path = write_capture("stops", &original);
    let model = learn_pcap(&path, true).unwrap();
    let none = alerts_for(&model, None, &path);
    let kinds: Vec<(&str, &str)> = none
        .alerts
        .iter()
        .map(|a| (a.kind.as_str(), a.function.as_str()))
        .collect();
    assert_eq!(
        kinds,
        [
            ("stop-outside-window", "Diagnostics: Force Listen Only Mode"),
            ("stop-outside-window", "Diagnostics: Restart Communications"),
        ]
        .map(|(k, f)| (k, f)),
        "{none:#?}"
    );
    assert!(
        none.alerts
            .iter()
            .all(|a| a.occurrences == 3 && a.severity == Severity::High)
    );
    assert!(none.alerts[0].message.contains("no maintenance window"));
    // A window on another day, or other hours, does not cover it.
    for w in ["Fri 11:00-13:00", "Thu 12:30-13:30", "Thu 11:00-11:30"] {
        assert_eq!(alerts_for(&model, Some(w), &path).alerts.len(), 2, "{w}");
    }
    assert!(
        alerts_for(&model, Some("Thu 11:00-13:00"), &path)
            .alerts
            .is_empty()
    );
    assert!(
        alerts_for(&model, Some("daily 11:00-13:00"), &path)
            .alerts
            .is_empty()
    );
    // The real S7 Stop capture: a new device, and a Stop.
    let stop = fixture("snap7_s300_stop.pcapng");
    let report = check_pcap(&stop, &model, None, true).unwrap();
    assert_eq!(report.alerts.len(), 1, "{report:#?}");
    assert_eq!(report.alerts[0].kinds, ["new-asset", "stop-outside-window"]);
    assert_eq!(report.alerts[0].function, "PLC Stop");
    let _ = std::fs::remove_file(path);
}

/// A write from a station the model knows, a function the device never received: `first-write`,
/// and not `new-station`.
#[test]
fn a_known_station_that_writes_for_the_first_time_is_a_first_write() {
    let original = frames("modbus_test_data_part1.pcap");
    let reads = without_control(&original);
    assert!(reads.len() < original.len());
    let learn = write_capture("reads", &reads);
    let model = learn_pcap(&learn, true).unwrap();
    assert!(
        model.assets["10.0.0.3"]
            .functions
            .values()
            .all(|f| !f.control),
        "only reads were learned"
    );
    // the same reads again: nothing new
    assert!(alerts_for(&model, None, &learn).alerts.is_empty());
    // plus one write from the station that only read before
    let mut replay = reads.clone();
    replay.push(injected_write(&original, [10, 0, 0, 9]));
    let path = write_capture("first-write", &replay);
    let report = alerts_for(&model, None, &path);
    assert_eq!(report.alerts.len(), 1, "{report:#?}");
    let a = &report.alerts[0];
    assert_eq!(
        (a.kind.as_str(), a.client.as_str()),
        ("first-write", "10.0.0.9")
    );
    assert_eq!(a.kinds, ["first-write"]);
    assert_eq!(a.severity, Severity::High);
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(learn);
}

#[test]
fn the_tracker_sends_no_event_for_broadcasts_and_garbage() {
    // EtherNet/IP List Identity to the limited broadcast address: a client, but no device.
    let mut f = vec![0u8; 12];
    f.extend([8, 0]);
    let payload = [
        0x63u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let mut ipv4 = vec![
        0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 50, 255, 255, 255, 255,
    ];
    let total = (20 + 8 + payload.len()) as u16;
    ipv4[2..4].copy_from_slice(&total.to_be_bytes());
    f.extend(ipv4);
    f.extend(2222u16.to_be_bytes());
    f.extend(44818u16.to_be_bytes());
    f.extend(((8 + payload.len()) as u16).to_be_bytes());
    f.extend([0, 0]);
    f.extend(payload);
    assert!(events_of(&f, 1).is_empty());
    for n in 0..64 {
        assert!(events_of(&vec![0xAB; n], 1).is_empty());
    }
}

#[test]
fn the_learner_records_peers_functions_rates_and_hours() {
    let mut l = Learner::new("test");
    // 10:00 UTC on day 0 and 03:00 on day 1; three messages in one minute
    let t0 = 10 * 3600;
    for (i, f) in ["Read Coils", "Read Coils", "Write Single Coil"]
        .iter()
        .enumerate()
    {
        l.observe(&event(
            t0 + i as i64,
            "10.0.0.50",
            "10.0.0.10",
            f,
            f.starts_with("Write"),
        ));
    }
    l.observe(&event(
        86_400 + 3 * 3600,
        "10.0.0.51",
        "10.0.0.10",
        "Read Coils",
        false,
    ));
    l.observe(&event(t0 + 5, "10.0.0.50", "10.0.0.10", "", false));
    let m = l.finish();
    assert_eq!((m.events, m.assets.len()), (5, 1));
    let a = &m.assets["10.0.0.10"];
    assert_eq!(a.peers.len(), 2);
    assert_eq!(a.peers["10.0.0.50"].events, 4);
    assert_eq!(a.functions["Modbus/TCP: Read Coils"].count, 3);
    assert!(!a.functions["Modbus/TCP: Read Coils"].control);
    assert!(a.functions["Modbus/TCP: Write Single Coil"].control);
    assert!(
        !a.functions.contains_key("Modbus/TCP: "),
        "no function, no entry"
    );
    assert_eq!((a.hours[10], a.hours[3]), (4, 1));
    assert_eq!(
        (a.control_hours[10], a.control_hours.iter().sum::<u64>()),
        (1, 1)
    );
    assert_eq!((a.active_minutes, a.max_per_minute), (2, 4));
    assert!((a.mean_per_minute() - 2.5).abs() < 1e-9);
    assert_eq!((a.first, a.last), (t0, 86_400 + 3 * 3600));
    assert!(m.summary()[1].contains("2 clients"));
}

fn learned() -> Model {
    let mut l = Learner::new("test");
    let day = 86_400;
    for d in 0..2 {
        let base = d * day + 10 * 3600;
        for i in 0..20 {
            l.observe(&event(
                base + i * 30,
                "10.0.0.50",
                "10.0.0.10",
                "Read Holding Registers",
                false,
            ));
        }
        l.observe(&event(
            base + 100,
            "10.0.0.50",
            "10.0.0.10",
            "Write Single Register",
            true,
        ));
    }
    l.finish()
}

#[test]
fn the_detector_names_each_kind_of_novelty() {
    let model = learned();
    let run = |events: &[OtEvent]| {
        let mut d = Detector::new(Arc::new(model.clone()), None);
        for e in events {
            d.observe(e);
        }
        d.finish()
    };
    let t = 2 * 86_400 + 10 * 3600;
    // normal traffic: nothing
    assert!(
        run(&[
            event(t, "10.0.0.50", "10.0.0.10", "Read Holding Registers", false),
            event(
                t + 1,
                "10.0.0.50",
                "10.0.0.10",
                "Write Single Register",
                true
            ),
        ])
        .is_empty()
    );
    // a new device
    let a = run(&[event(t, "10.0.0.50", "10.0.0.77", "Read Coils", false)]);
    assert_eq!(
        (a[0].kind.as_str(), a[0].severity),
        ("new-asset", Severity::Medium)
    );
    // a new read function from a known station: low
    let a = run(&[event(t, "10.0.0.50", "10.0.0.10", "Read Coils", false)]);
    assert_eq!(
        (a[0].kind.as_str(), a[0].severity),
        ("new-function", Severity::Low)
    );
    // a new write function from a known station
    let a = run(&[event(
        t,
        "10.0.0.50",
        "10.0.0.10",
        "Write Multiple Registers",
        true,
    )]);
    assert_eq!(
        (a[0].kind.as_str(), a[0].severity),
        ("first-write", Severity::High)
    );
    // a new station reading: medium
    let a = run(&[event(
        t,
        "10.0.0.60",
        "10.0.0.10",
        "Read Holding Registers",
        false,
    )]);
    assert_eq!(
        (a[0].kind.as_str(), a[0].severity),
        ("new-station", Severity::Medium)
    );
    // a write at 03:00, when none was learned over 48 hours
    let a = run(&[event(
        2 * 86_400 + 3 * 3600,
        "10.0.0.50",
        "10.0.0.10",
        "Write Single Register",
        true,
    )]);
    assert_eq!(a[0].kinds, ["unusual-hour"]);
    // one message, several reasons, one alert; repeats are counted
    let many: Vec<OtEvent> = (0..4)
        .map(|i| event(t + i, "10.0.0.60", "10.0.0.10", "PLC Stop", true))
        .collect();
    let a = run(&many);
    assert_eq!(a.len(), 1);
    assert_eq!(
        a[0].kinds,
        ["new-station", "stop-outside-window", "first-write"]
    );
    assert_eq!(
        (a[0].occurrences, a[0].first_seen, a[0].last_seen),
        (4, t, t + 3)
    );
    // a flood: 200 messages in one minute against a learned maximum of 2
    let flood: Vec<OtEvent> = (0..200)
        .map(|_| {
            event(
                t + 5,
                "10.0.0.50",
                "10.0.0.10",
                "Read Holding Registers",
                false,
            )
        })
        .collect();
    let a = run(&flood);
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].kind, "rate-anomaly");
    assert!(a[0].message.contains("200 messages"), "{}", a[0].message);
}

#[test]
fn short_models_do_not_judge_the_hour_and_small_rate_changes_pass() {
    // learned over one hour only: the hour of the day says nothing
    let mut l = Learner::new("short");
    l.observe(&event(
        10 * 3600,
        "10.0.0.50",
        "10.0.0.10",
        "Write Single Register",
        true,
    ));
    l.observe(&event(
        10 * 3600 + 60,
        "10.0.0.50",
        "10.0.0.10",
        "Read Coils",
        false,
    ));
    let model = l.finish();
    let mut d = Detector::new(Arc::new(model), None);
    d.observe(&event(
        3 * 3600,
        "10.0.0.50",
        "10.0.0.10",
        "Write Single Register",
        true,
    ));
    assert!(d.finish().is_empty());
    // twice the busiest minute is not an anomaly (three times and 30 more is)
    let model = learned();
    let max = model.assets["10.0.0.10"].max_per_minute;
    let mut d = Detector::new(Arc::new(model), None);
    for _ in 0..(max * 2) {
        d.observe(&event(
            5 * 86_400 + 10 * 3600,
            "10.0.0.50",
            "10.0.0.10",
            "Read Holding Registers",
            false,
        ));
    }
    assert!(d.finish().is_empty());
}

#[test]
fn stop_functions_are_recognised_by_name() {
    for stop in [
        "PLC Stop",
        "Stop",
        "Stop Application",
        "Cold Restart",
        "Warm Restart",
        "Diagnostics: Restart Communications",
        "Diagnostics: Force Listen Only Mode",
        "PLC Control",
        "Initialize Application",
        "Reset",
    ] {
        assert!(is_stop(stop), "{stop}");
    }
    for other in [
        "Write Single Register",
        "Read Coils",
        "Request Download",
        "Start",
        "Direct Operate",
        "Diagnostics: Clear Counters",
        "",
    ] {
        assert!(!is_stop(other), "{other}");
    }
}

#[test]
fn maintenance_windows_parse_and_contain_times() {
    // 2026-11-21 is a Saturday: 1_795_219_200 = 2026-11-21T00:00:00Z
    let sat = 1_795_219_200;
    let w = Maintenance::parse("Sat 02:00-06:00").unwrap();
    assert!(w.contains(sat + 2 * 3600) && w.contains(sat + 6 * 3600 - 1));
    assert!(!w.contains(sat + 6 * 3600) && !w.contains(sat + 3600));
    assert!(!w.contains(sat + 86_400 + 3 * 3600), "Sunday 03:00");
    assert!(!w.contains(sat - 86_400 + 3 * 3600), "Friday 03:00");
    // over midnight: Saturday 22:00 to Sunday 02:00
    let w = Maintenance::parse("Sat 22:00-02:00").unwrap();
    assert!(w.contains(sat + 23 * 3600) && w.contains(sat + 86_400 + 3600));
    assert!(
        !w.contains(sat + 3600),
        "Saturday 01:00 is before the window"
    );
    assert!(
        !w.contains(sat + 86_400 + 2 * 3600),
        "Sunday 02:00 is after it"
    );
    // ranges, lists, daily, several windows
    let w = Maintenance::parse("Mon-Fri 08:00-17:00; Sun 00:00-01:00").unwrap();
    assert!(w.contains(sat - 86_400 + 9 * 3600), "Friday 09:00");
    assert!(!w.contains(sat + 9 * 3600), "Saturday");
    assert!(w.contains(sat + 86_400 + 1800), "Sunday 00:30");
    assert!(
        Maintenance::parse("Sat,Sun 00:00-23:59")
            .unwrap()
            .contains(sat + 5 * 3600)
    );
    assert!(
        Maintenance::parse("daily 04:00-05:00")
            .unwrap()
            .contains(sat + 4 * 3600)
    );
    assert!(
        Maintenance::parse("Fri-Mon 00:00-12:00")
            .unwrap()
            .contains(sat + 3600),
        "a range over the week end"
    );
    // zones
    let w = Maintenance::parse("Sat 02:00-06:00 UTC+2").unwrap();
    assert!(
        w.contains(sat + 3600) && !w.contains(sat + 5 * 3600),
        "02:00 local is 00:00 UTC"
    );
    let w = Maintenance::parse("Sat 02:00-06:00 UTC-5:30").unwrap();
    assert!(w.contains(sat + 7 * 3600 + 30 * 60) && !w.contains(sat + 3 * 3600));
    // errors say what is wrong
    for bad in [
        "",
        "Sat",
        "Sat 02:00",
        "Sat 2-6",
        "Someday 02:00-06:00",
        "Sat 25:00-06:00",
        "Sat 02:00-02:00",
        "Sat 02:00-06:00 CET",
        "Sat 02:00-06:00 UTC+20",
        "Sat 02:00-06:00 UTC+-99999999",
        "Sat 02:00-06:00 UTC+1:-99999999",
        "Sat 02:00-06:00 UTC+1 extra",
        "Sat 02:61-06:00",
    ] {
        assert!(Maintenance::parse(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn a_model_round_trips_and_a_damaged_one_is_refused() {
    let dir = std::env::temp_dir().join(format!("ns-otmodel-file-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("model.json");
    let model = learned();
    model.save(&path).unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(
        text.contains("\"schema\": \"network-scope/ot-model/v1\""),
        "{text}"
    );
    assert_eq!(Model::load(&path).unwrap(), model);
    std::fs::write(&path, text.replace("\"version\": 1", "\"version\": 7")).unwrap();
    assert!(Model::load(&path).unwrap_err().contains("version 7"));
    std::fs::write(&path, "not json").unwrap();
    assert!(
        Model::load(&path)
            .unwrap_err()
            .contains("not an OT traffic model")
    );
    let mut broken = model.clone();
    broken.assets.get_mut("10.0.0.10").unwrap().hours = vec![1, 2];
    std::fs::write(&path, serde_json::to_string(&broken).unwrap()).unwrap();
    assert!(Model::load(&path).unwrap_err().contains("damaged"));
    assert!(Model::load(&dir.join("missing.json")).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_model_is_bounded() {
    let mut l = Learner::new("bounds");
    for i in 0..(MAX_PEERS + 50) {
        let client = format!("10.1.{}.{}", i / 250, i % 250 + 1);
        l.observe(&event(
            i as i64,
            &client,
            "10.0.0.10",
            &format!("function {i}"),
            false,
        ));
    }
    let m = l.finish();
    let a = &m.assets["10.0.0.10"];
    assert_eq!(a.peers.len(), MAX_PEERS);
    assert_eq!(a.functions.len(), MAX_FUNCTIONS);
    assert_eq!(
        a.events,
        (MAX_PEERS + 50) as u64,
        "every message is still counted"
    );
}
