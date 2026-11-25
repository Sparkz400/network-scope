//! "Record the scan's traffic" in the desktop app: the same recording as `scan --record FILE
//! --record-wire` on the command line. A wire capture of the targets runs while the scan runs when
//! the capture driver allows it (Npcap/libpcap, at most `wirecap::MAX_FILTER_HOSTS` targets);
//! otherwise, or when the capture saw nothing, the application-level record of the scan (the
//! payloads the scan sent and received, labelled as such) is written instead. The file goes to
//! `NetworkScope/recordings/scan-<unix time>.pcapng` next to the preferences.
use super::i18n::tr;
use network_scope_core::{record::Recorder, wirecap};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

/// A recording that runs with the current scan.
pub(super) struct Recording {
    pub(super) path: PathBuf,
    wire: Option<wirecap::WireCapture>,
    /// Why there is no wire capture (shown with the result).
    why_not_wire: Option<String>,
}

/// The file of a recording started at `unix_secs`, in `dir`.
pub(super) fn file_in(dir: &Path, unix_secs: u64) -> PathBuf {
    dir.join(format!("scan-{unix_secs}.pcapng"))
}

/// Starts the wire capture for `hosts` (when possible) before the scan sends anything.
pub(super) fn start(path: PathBuf, interface: &str, hosts: &[IpAddr]) -> Recording {
    let started = if hosts.len() > wirecap::MAX_FILTER_HOSTS {
        Err(tr!(
            "{} targets are too many for a capture filter (at most {})",
            hosts.len(),
            wirecap::MAX_FILTER_HOSTS
        ))
    } else {
        wirecap::plan(interface, hosts).and_then(wirecap::WireCapture::start)
    };
    match started {
        Ok(wire) => Recording {
            path,
            wire: Some(wire),
            why_not_wire: None,
        },
        Err(e) => Recording {
            path,
            wire: None,
            why_not_wire: Some(e),
        },
    }
}

impl Recording {
    /// Ends the capture and writes the file: the wire frames, else the application-level record.
    /// Returns the sentence for the status line.
    pub(super) fn finish(self, recorder: Option<&Arc<Recorder>>) -> String {
        let mut why = self.why_not_wire;
        if let Some(wire) = self.wire {
            let plan = wire.plan().clone();
            let captured = wire.finish();
            if captured.frames.is_empty() {
                why = Some(captured.error.unwrap_or_else(|| {
                    tr!("no frame matched the filter (the targets may be reached through another interface, or are this computer's own addresses)").into()
                }));
            } else {
                match network_scope_core::record::write_wire_pcapng(
                    &self.path,
                    captured.link_type,
                    &plan.interface,
                    &plan.filter,
                    &captured.frames,
                ) {
                    Ok(()) => {
                        return tr!(
                            "Wire capture: {} frames recorded to {}",
                            captured.frames.len(),
                            self.path.display()
                        );
                    }
                    Err(e) => why = Some(e),
                }
            }
        }
        let why = why.unwrap_or_default();
        match recorder.map(|r| r.write_pcapng(&self.path)) {
            Some(Ok(written)) => tr!(
                "No wire capture ({}); application-level record of {} payloads written to {} (not a wire capture)",
                why,
                written.records,
                self.path.display()
            ),
            Some(Err(e)) => tr!("Recording failed: {}", e),
            None => tr!("No wire capture ({}) and no application-level record", why),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_file_is_named_after_the_start_time() {
        let p = file_in(Path::new("rec"), 1_763_640_000);
        assert_eq!(p, Path::new("rec").join("scan-1763640000.pcapng"));
    }

    #[test]
    fn too_many_targets_fall_back_to_the_application_level_record() {
        let hosts: Vec<IpAddr> = (0..=wirecap::MAX_FILTER_HOSTS as u32)
            .map(|i| IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + i)))
            .collect();
        let dir = std::env::temp_dir().join(format!("ns-gui-rec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let rec = start(file_in(&dir, 1), "", &hosts);
        assert!(rec.wire.is_none());
        assert!(rec.why_not_wire.as_deref().unwrap().contains("too many"));
        let recorder = Arc::new(Recorder::new());
        let text = rec.finish(Some(&recorder));
        assert!(text.contains("application-level record"), "{text}");
        assert!(text.contains("too many"), "{text}");
        assert!(file_in(&dir, 1).exists());
        // Without a recorder nothing is written and the status says so.
        let rec = start(file_in(&dir, 2), "", &hosts);
        let text = rec.finish(None);
        assert!(text.contains("no application-level record"), "{text}");
        assert!(!file_in(&dir, 2).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
