// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Feeding the tracker: capture files (pcap/pcapng) and the live, receive-only capture.
use super::Tracker;

pub fn read_pcap_file(path: &str, tracker: &mut Tracker) -> Result<(), String> {
    read_pcap_file_with_progress(path, tracker, None, &mut |_| {})
}

/// How often `read_pcap_file_with_progress` reports (plus one final report).
pub const PROGRESS_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

/// Reads a capture file into `tracker`, calling `on_progress` about every `PROGRESS_INTERVAL`
/// and once more at the end (`done: true`). `cancel` stops reading early (what was read so far
/// stays in the tracker; the result is then an error saying so).
pub fn read_pcap_file_with_progress(
    path: &str,
    tracker: &mut Tracker,
    cancel: Option<&std::sync::atomic::AtomicBool>,
    on_progress: &mut dyn FnMut(&crate::pcapfile::Progress),
) -> Result<(), String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
    let total_bytes = file.metadata().map(|m| m.len()).unwrap_or(0);
    let reader = crate::pcapfile::Reader::new(std::io::BufReader::new(file))?;
    feed_reader(reader, total_bytes, tracker, cancel, on_progress)
}

fn feed_reader<R: std::io::Read>(
    mut reader: crate::pcapfile::Reader<R>,
    total_bytes: u64,
    tracker: &mut Tracker,
    cancel: Option<&std::sync::atomic::AtomicBool>,
    on_progress: &mut dyn FnMut(&crate::pcapfile::Progress),
) -> Result<(), String> {
    let start = std::time::Instant::now();
    let mut next_report = start + PROGRESS_INTERVAL;
    let progress = |reader: &crate::pcapfile::Reader<R>, done: bool| crate::pcapfile::Progress {
        frames: reader.frames(),
        bytes: reader.bytes_read(),
        total_bytes,
        elapsed: start.elapsed().as_secs_f64(),
        done,
    };
    let result = loop {
        let frame = match reader.next_frame() {
            Ok(Some(f)) => f,
            Ok(None) => break Ok(()),
            Err(e) => break Err(e),
        };
        tracker.feed(&frame.1, frame.0);
        // the clock is read every 256 frames only
        if reader.frames().is_multiple_of(256) {
            if cancel.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed)) {
                break Err("Reading the capture file was cancelled; results are partial".into());
            }
            let now = std::time::Instant::now();
            if now >= next_report {
                next_report = now + PROGRESS_INTERVAL;
                on_progress(&progress(&reader, false));
            }
        }
    };
    tracker.flush();
    on_progress(&progress(&reader, true));
    result
}

/// Live capture for `seconds`. Uses `PassiveCapture`, which has no way to transmit.
pub fn listen_live(
    interface: &str,
    seconds: u64,
    cancel: &std::sync::atomic::AtomicBool,
    tracker: &mut Tracker,
) -> Result<(), String> {
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
    let mut cap = crate::capture::PassiveCapture::open(interface)?;
    let end = Instant::now() + Duration::from_secs(seconds.clamp(1, 7 * 86_400));
    while Instant::now() < end && !cancel.load(std::sync::atomic::Ordering::Relaxed) {
        match cap.next()? {
            Some(frame) => {
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                tracker.feed(&frame, ts);
            }
            None => std::thread::sleep(Duration::from_millis(5)),
        }
    }
    tracker.flush();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otpassive::testutil::{HMI, PLC, control, frame, modbus_write, obs, seg};

    #[test]
    fn capture_files_feed_the_tracker_and_garbage_is_ignored() {
        let frames = vec![
            (
                100u32,
                frame(
                    HMI,
                    PLC,
                    true,
                    50000,
                    502,
                    &[0, 1, 0, 0, 0, 6, 7, 5, 0, 0, 0xff, 0],
                ),
            ),
            (101, vec![0xff; 5]),
            (102, vec![0; 200]),
        ];
        let dir = std::env::temp_dir().join(format!("ns-pcap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for (name, bytes) in [
            ("a.pcap", crate::pcapfile::write_pcap(&frames)),
            ("b.pcapng", crate::pcapfile::write_pcapng(&frames, false)),
        ] {
            let path = dir.join(name);
            std::fs::write(&path, bytes).unwrap();
            let mut t = Tracker::new();
            read_pcap_file(path.to_str().unwrap(), &mut t).unwrap();
            assert_eq!(t.frames, 3, "{name}");
            assert_eq!(
                obs(&t, "Modbus/TCP server (observed)")[0].fields["control_traffic"],
                "Write Single Coil x1"
            );
        }
        assert!(
            read_pcap_file(
                dir.join("missing.pcap").to_str().unwrap(),
                &mut Tracker::new()
            )
            .is_err()
        );
        let _ = std::fs::remove_dir_all(&dir);
        let mut t = Tracker::new();
        for n in 0..300 {
            t.feed(&vec![0x45; n], 0);
            let mut f = frame(HMI, PLC, true, 1, 502, &vec![0xff; n % 40]);
            f.truncate(f.len().saturating_sub(n % 7));
            t.feed(&f, 0);
        }
    }

    #[test]
    fn cooked_capture_files_reach_the_ot_decoders() {
        // Linux SLL record of a Modbus write: the Ethernet header is replaced by a cooked one
        let eth = seg(HMI, PLC, 502, 0, 0x18, &modbus_write());
        let mut cooked = vec![
            0, 0, 0, 1, 0, 6, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0, 0, 8, 0,
        ];
        cooked.extend(&eth[14..]);
        let mut file = crate::pcapfile::write_pcap(&[(42, cooked)]);
        file[20..24].copy_from_slice(&113u32.to_le_bytes());
        let dir = std::env::temp_dir().join(format!("ns-sll-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sll.pcap");
        std::fs::write(&path, &file).unwrap();
        let mut t = Tracker::new();
        let mut reports = vec![];
        read_pcap_file_with_progress(path.to_str().unwrap(), &mut t, None, &mut |p| {
            reports.push(*p)
        })
        .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            control(&t, "Modbus/TCP server (observed)").as_deref(),
            Some("Write Multiple Registers x1")
        );
        let last = reports.last().unwrap();
        assert!(last.done);
        assert_eq!((last.frames, last.bytes), (1, file.len() as u64));
        assert_eq!(last.total_bytes, file.len() as u64);
        assert_eq!(last.percent(), Some(100.0));
    }

    #[test]
    fn progress_reports_are_throttled_and_cancel_stops_reading() {
        let frames: Vec<(u32, Vec<u8>)> = (0..2000)
            .map(|i| (i, seg(HMI, PLC, 502, i * 17, 0x18, &modbus_write())))
            .collect();
        let file = crate::pcapfile::write_pcap(&frames);
        let mut reports = 0;
        let reader = crate::pcapfile::Reader::new(&file[..]).unwrap();
        let mut t = Tracker::new();
        feed_reader(reader, file.len() as u64, &mut t, None, &mut |_| {
            reports += 1
        })
        .unwrap();
        assert_eq!(t.frames, 2000);
        assert!(reports <= 3, "{reports} reports for a fast read");
        let cancel = std::sync::atomic::AtomicBool::new(true);
        let reader = crate::pcapfile::Reader::new(&file[..]).unwrap();
        let mut t = Tracker::new();
        let mut done = false;
        let e = feed_reader(reader, 0, &mut t, Some(&cancel), &mut |p| done = p.done).unwrap_err();
        assert!(e.contains("cancelled"), "{e}");
        assert!(done, "a final report is sent after cancel too");
        assert_eq!(t.frames, 256);
    }
}
