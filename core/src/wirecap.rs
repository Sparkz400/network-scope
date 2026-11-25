// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Recording the real wire traffic of a scan (ROADMAP L72: `scan --record FILE --record-wire`).
//!
//! The scanner's sockets never see the Ethernet, IP and TCP headers they send, so
//! [`crate::record`]'s default file is an application-level record with synthetic headers. When
//! the capture driver is there (Npcap on Windows, libpcap elsewhere, loaded at run time, see
//! [`crate::capture`]) a scan can instead keep what really crossed the interface: [`WireCapture`]
//! opens a read-only capture before the scan starts, with a kernel filter that lets through only
//! the traffic to and from the scan's targets, and collects the frames until the scan is done.
//! [`crate::record::write_wire_pcapng`] writes them with their own headers, addresses, sequence
//! numbers and time stamps.
//!
//! Nothing here sends a packet: the capture handle ([`PassiveCapture`]) has no way to transmit,
//! so there is no packet kind to record and nothing for the dry run to list. What it needs:
//!
//! * the capture driver, and permission to use it (Npcap may be restricted to administrators,
//!   libpcap normally needs root or a capability);
//! * an interface: `--interface`, or, when every target is a loopback address, the loopback
//!   interface (`\Device\NPF_Loopback` with Npcap, `lo`, `lo0`). Link types other than Ethernet
//!   and loopback are refused;
//! * at most [`MAX_FILTER_HOSTS`] targets (the filter lists every address).
//!
//! When any of this is missing, [`plan`] says why and the caller falls back to the
//! application-level record. Limits: a computer cannot see traffic to itself on a physical
//! interface (use the loopback interface for the loopback addresses; a scan of this computer's own
//! LAN address is delivered internally and appears on no network interface), traffic that
//! bypasses the chosen interface (another route) is missing, and the capture is bounded at
//! [`MAX_FRAMES`] frames and [`MAX_BYTES`] bytes, counted when exceeded.
use crate::{capture, record::WireFrame};
use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

/// Most targets a capture filter is built from.
pub const MAX_FILTER_HOSTS: usize = 256;
/// Most frames kept.
pub const MAX_FRAMES: usize = 2_000_000;
/// Most frame bytes kept.
pub const MAX_BYTES: usize = 256 * 1024 * 1024;
/// How long the capture goes on after the scan has finished, so that the last replies arrive.
const GRACE: Duration = Duration::from_millis(400);

/// The kernel filter for the targets: `host A or host B ...`.
pub fn filter_for(targets: &[IpAddr]) -> Result<String, String> {
    if targets.is_empty() {
        return Err("no targets to filter for".into());
    }
    if targets.len() > MAX_FILTER_HOSTS {
        return Err(format!(
            "{} targets are too many for a capture filter (at most {MAX_FILTER_HOSTS})",
            targets.len()
        ));
    }
    Ok(targets
        .iter()
        .map(|ip| format!("host {ip}"))
        .collect::<Vec<_>>()
        .join(" or "))
}

/// The interface to capture on: `requested` (`--interface`) when given, else the loopback
/// interface when every target is a loopback address (`interfaces` is the driver's list of
/// `(name, description)`), else an error that says what to do.
pub fn pick_interface(
    requested: &str,
    targets: &[IpAddr],
    interfaces: &[(String, String)],
) -> Result<String, String> {
    if !requested.is_empty() {
        return Ok(requested.to_string());
    }
    if targets.is_empty() || !targets.iter().all(IpAddr::is_loopback) {
        return Err("name the interface the targets are reached through with --interface".into());
    }
    interfaces
        .iter()
        .map(|(name, _)| name)
        .find(|n| n.ends_with("NPF_Loopback") || *n == "lo" || *n == "lo0")
        .cloned()
        .ok_or_else(|| {
            "no loopback capture interface found (Npcap needs its loopback adapter)".into()
        })
}

/// What a recording will capture on, or why it cannot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub interface: String,
    pub filter: String,
}

/// Decides interface and filter for a scan of `targets` (see the module documentation). `Err`
/// is the reason, in a sentence, that the caller shows before it falls back.
pub fn plan(requested_interface: &str, targets: &[IpAddr]) -> Result<Plan, String> {
    let filter = filter_for(targets)?;
    let interfaces = if requested_interface.is_empty() {
        capture::interfaces()?
    } else {
        vec![]
    };
    Ok(Plan {
        interface: pick_interface(requested_interface, targets, &interfaces)?,
        filter,
    })
}

/// A running capture.
pub struct WireCapture {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Captured>>,
    plan: Plan,
}

/// What a capture collected.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Captured {
    /// 1 Ethernet, 0 loopback.
    pub link_type: u16,
    pub frames: Vec<WireFrame>,
    /// Frames that did not fit the bounds.
    pub dropped: u64,
    /// The capture ended early with this error (frames up to then are kept).
    pub error: Option<String>,
}

impl WireCapture {
    /// Opens the capture and starts collecting. `Err` when the driver, the interface or the
    /// filter is not usable (nothing was started then).
    pub fn start(plan: Plan) -> Result<Self, String> {
        let stop = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = mpsc::channel();
        let (flag, p) = (stop.clone(), plan.clone());
        // The capture handle is not `Send`: it is opened inside the thread, which reports back.
        let thread = std::thread::spawn(move || {
            let mut cap = match capture::PassiveCapture::open_wire(&p.interface, &p.filter) {
                Ok(cap) => {
                    let _ = ready_tx.send(Ok(()));
                    cap
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    return Captured::default();
                }
            };
            let mut out = Captured {
                link_type: cap.link_type(),
                ..Default::default()
            };
            let mut bytes = 0usize;
            let mut stopped_at: Option<Instant> = None;
            loop {
                match cap.next_timed() {
                    Ok(Some((micros, data))) => {
                        if out.frames.len() >= MAX_FRAMES || bytes + data.len() > MAX_BYTES {
                            out.dropped += 1;
                        } else {
                            bytes += data.len();
                            out.frames.push(WireFrame { micros, data });
                        }
                    }
                    Ok(None) => {
                        if flag.load(Ordering::SeqCst) {
                            let since = *stopped_at.get_or_insert_with(Instant::now);
                            if since.elapsed() >= GRACE {
                                break;
                            }
                        }
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(e) => {
                        out.error = Some(e);
                        break;
                    }
                }
            }
            out
        });
        match ready_rx.recv_timeout(Duration::from_secs(10)) {
            Ok(Ok(())) => Ok(Self {
                stop,
                thread: Some(thread),
                plan,
            }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                stop.store(true, Ordering::SeqCst);
                Err("the capture driver did not answer".into())
            }
        }
    }

    /// What the capture runs on.
    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    /// Ends the capture (after a short grace period for the last replies) and returns what it
    /// collected.
    pub fn finish(mut self) -> Captured {
        self.stop.store(true, Ordering::SeqCst);
        self.thread
            .take()
            .and_then(|t| t.join().ok())
            .unwrap_or_else(|| Captured {
                error: Some("the capture thread failed".into()),
                ..Default::default()
            })
    }
}

impl Drop for WireCapture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn the_filter_lists_every_target_and_is_bounded() {
        assert_eq!(
            filter_for(&[ip("10.0.0.1"), ip("2001:db8::5")]).unwrap(),
            "host 10.0.0.1 or host 2001:db8::5"
        );
        assert!(filter_for(&[]).is_err());
        let many: Vec<IpAddr> = (0..=MAX_FILTER_HOSTS as u32)
            .map(|i| IpAddr::from(std::net::Ipv4Addr::from(0x0a00_0000 + i)))
            .collect();
        assert!(filter_for(&many).unwrap_err().contains("too many"));
        assert!(filter_for(&many[..MAX_FILTER_HOSTS]).is_ok());
    }

    #[test]
    fn the_interface_is_the_requested_one_or_the_loopback_for_loopback_targets() {
        let list = vec![
            ("\\Device\\NPF_{ABC}".to_string(), "Ethernet".to_string()),
            ("\\Device\\NPF_Loopback".to_string(), "Loopback".to_string()),
        ];
        let loopback = [ip("127.0.0.1"), ip("::1")];
        assert_eq!(
            pick_interface("eth9", &[ip("10.0.0.1")], &list).unwrap(),
            "eth9"
        );
        assert_eq!(
            pick_interface("", &loopback, &list).unwrap(),
            "\\Device\\NPF_Loopback"
        );
        // lo and lo0 on Linux and macOS
        let unix = vec![
            ("eth0".to_string(), String::new()),
            ("lo".to_string(), String::new()),
        ];
        assert_eq!(pick_interface("", &loopback, &unix).unwrap(), "lo");
        // a network target needs --interface; a mixed list does too
        assert!(
            pick_interface("", &[ip("10.0.0.1")], &list)
                .unwrap_err()
                .contains("--interface")
        );
        assert!(pick_interface("", &[ip("127.0.0.1"), ip("10.0.0.1")], &list).is_err());
        // no loopback interface in the list
        assert!(pick_interface("", &loopback, &list[..1]).is_err());
        assert!(pick_interface("", &[], &list).is_err());
    }

    #[test]
    fn a_missing_interface_or_filter_error_is_reported_not_panicked() {
        // an interface that does not exist (or no driver at all): an error, nothing started
        let result = WireCapture::start(Plan {
            interface: "no-such-interface-0".into(),
            filter: "host 127.0.0.1".into(),
        });
        assert!(result.is_err());
        assert!(plan("", &[]).is_err());
        assert!(plan("eth0", &[ip("10.0.0.1")]).is_ok());
    }

    /// Needs the capture driver and permission to use it (Npcap with its loopback adapter, or
    /// libpcap and root): `cargo test -p network-scope-core wire_capture -- --ignored`.
    #[test]
    #[ignore = "needs a capture driver and permission to capture on the loopback interface"]
    fn wire_capture_sees_the_frames_of_a_loopback_connection() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut stream = stream;
                let mut buf = [0u8; 64];
                let n = stream.read(&mut buf).unwrap_or(0);
                let _ = stream.write_all(&buf[..n]);
            }
        });
        let targets = [ip("127.0.0.1")];
        let plan = plan("", &targets).expect("a loopback interface");
        let wire = WireCapture::start(plan).expect("capture permission");
        std::thread::sleep(Duration::from_millis(300));
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(b"wire-capture-needle").unwrap();
        let mut echo = [0u8; 32];
        let _ = s.read(&mut echo).unwrap();
        drop(s);
        let captured = wire.finish();
        assert_eq!(captured.error, None);
        assert!(
            matches!(captured.link_type, 0 | 1),
            "{}",
            captured.link_type
        );
        assert!(!captured.frames.is_empty());
        let needles = captured
            .frames
            .iter()
            .filter(|f| f.data.windows(19).any(|w| w == b"wire-capture-needle"))
            .count();
        assert!(needles >= 2, "request and echo: {needles}");
        assert!(
            captured
                .frames
                .windows(2)
                .all(|w| w[0].micros <= w[1].micros),
            "time stamps do not go backwards"
        );
    }
}
