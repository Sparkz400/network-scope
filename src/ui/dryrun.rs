//! `--dry-run` (ROADMAP H53): print what a command would send, per host, and send nothing.
//!
//! The plan comes from the engine (`plan::scan`, `plan::trace`, `plan::dcp`), which is built from
//! the same conditions and allow-lists the senders use. A dry run never reaches the scheduler: no
//! socket is opened, no capture driver is loaded, nothing is saved, and the scope guard only
//! reports what it would have asked.
use crate::{
    plan, scan,
    scope::{self, Addresses},
    ui::{guard, output},
};
use serde_json::json;
use std::collections::BTreeMap;

/// Commands that accept `--dry-run`: the ones that can send something.
pub(super) const COMMANDS: [&str; 4] = ["scan", "monitor", "trace", "dcp"];

pub(super) fn requested(opts: &BTreeMap<String, String>) -> bool {
    opts.contains_key("dry-run")
}

/// What the scope guard would do with these addresses, as text and as JSON.
fn scope_verdict<'a>(
    opts: &BTreeMap<String, String>,
    addresses: impl Into<Addresses<'a>>,
) -> Result<(String, serde_json::Value), String> {
    let declared = guard::declared(opts)?;
    let a = scope::assess(addresses, declared.as_ref());
    let needs = a.needs_confirmation(guard::consent(opts));
    let text = if needs {
        format!(
            "Scope guard: a real run would ask for confirmation (or refuse without --yes-public / --allow-out-of-scope). {}",
            a.describe()
        )
    } else {
        "Scope guard: the targets are private or in scope; a real run would not ask.".to_string()
    };
    let json = json!({
        "would_need_confirmation": needs,
        "public": a.public,
        "out_of_scope": a.out_of_scope,
        "scope_declared": a.scope_declared,
        "description": a.describe(),
    });
    Ok((text, json))
}

fn wants_json(opts: &BTreeMap<String, String>) -> bool {
    opts.get("format").is_some_and(|f| f == "json")
}

/// The plan of `scan` / `monitor` for these targets.
pub(super) fn scan_plan(
    opts: &BTreeMap<String, String>,
    command: &str,
    targets: &scan::Targets,
    ports: &[u16],
    s: &scan::Settings,
) -> Result<(), String> {
    let db = if s.services || s.udp {
        Some(crate::service::ProbeDb::load(&s.probe_file)?)
    } else {
        None
    };
    let groups = plan::scan(targets.iter(), ports, s, db.as_ref());
    let (verdict, verdict_json) = scope_verdict(opts, targets)?;
    let extras = (command == "monitor").then(|| {
        plan::monitor_extras(
            opts.contains_key("dhcp-discover"),
            opts.contains_key("interface"),
        )
    });
    if wants_json(opts) {
        let doc = json!({
            "dry_run": true,
            "command": command,
            "packets_sent": 0,
            "safe_mode": s.safe,
            "hosts": targets.count(),
            "scope": verdict_json,
            "groups": groups,
            "per_cycle": extras,
        });
        return output(
            &serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?,
            opts,
        );
    }
    let mut text = plan::format_scan(&groups, s);
    if let Some(extra) = extras {
        for line in extra.lines() {
            text.push_str(&format!("\nper monitor cycle: {line}"));
        }
        text.push_str("\neach monitor cycle repeats the scan above");
    }
    text.push_str(&format!("\n\n{verdict}"));
    output(&text, opts)
}

/// The plan of `trace TARGET`.
pub(super) fn trace_plan(
    opts: &BTreeMap<String, String>,
    target: std::net::IpAddr,
    method: crate::trace::TraceMethod,
    port: Option<u16>,
    hops: u8,
) -> Result<(), String> {
    let p = plan::trace(target, method, port, hops);
    let (verdict, verdict_json) = scope_verdict(opts, &[target][..])?;
    if wants_json(opts) {
        let doc = json!({
            "dry_run": true,
            "command": "trace",
            "packets_sent": 0,
            "target": target.to_string(),
            "scope": verdict_json,
            "packets": p.packets,
            "notes": p.notes,
        });
        return output(
            &serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?,
            opts,
        );
    }
    let mut text = format!("DRY RUN: nothing was sent.\n\n{target}\n");
    for line in p.lines() {
        text.push_str(&format!("  {line}\n"));
    }
    text.push_str(&format!("\n{verdict}"));
    output(&text, opts)
}

/// The plan of `dcp`: one layer-2 frame, no IP addresses involved.
pub(super) fn dcp_plan(opts: &BTreeMap<String, String>) -> Result<(), String> {
    let p = plan::dcp();
    if wants_json(opts) {
        let doc = json!({
            "dry_run": true,
            "command": "dcp",
            "packets_sent": 0,
            "packets": p.packets,
            "notes": p.notes,
        });
        return output(
            &serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?,
            opts,
        );
    }
    let mut text = String::from("DRY RUN: nothing was sent.\n\n");
    for line in p.lines() {
        text.push_str(&format!("  {line}\n"));
    }
    text.push_str("\nThe capture itself only listens.");
    output(&text, opts)
}

#[cfg(test)]
mod tests {
    use crate::ui::{run, testutil::args};

    /// Runs a command whose output goes to a file and returns what it wrote.
    fn run_to_file(list: &[&str]) -> (String, crate::ui::ExitCode) {
        let dir = std::env::temp_dir().join(format!(
            "ns-dry-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("out.txt");
        let none = dir.join("scope.txt");
        std::fs::write(&none, "127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16\n").unwrap();
        let db = dir.join("x.sqlite");
        let mut a: Vec<&str> = list.to_vec();
        a.extend([
            "--output",
            out.to_str().unwrap(),
            "--db",
            db.to_str().unwrap(),
            "--scope-file",
            none.to_str().unwrap(),
        ]);
        let status = run(&args(&a)).unwrap();
        let text = std::fs::read_to_string(&out).unwrap_or_default();
        assert!(
            !dir.join("x.sqlite").exists(),
            "a dry run saves nothing: {list:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
        (text, status)
    }

    #[test]
    fn scan_dry_run_lists_the_packets_per_host_and_exits_0() {
        let (text, status) = run_to_file(&[
            "scan",
            "192.168.77.0/30",
            "--dry-run",
            "--ports",
            "22,80,443,445,502",
            "--deep",
            "--ot",
            "--fast",
            "--udp-ports",
            "53,161,9100",
        ]);
        assert_eq!(status, crate::ui::ExitCode::Success);
        assert!(text.starts_with("DRY RUN: nothing was sent."), "{text}");
        assert!(
            text.contains("ipv4 2 host(s), 192.168.77.1 ... 192.168.77.2"),
            "{text}"
        );
        for want in [
            "icmp-echo",
            "tcp-connect",
            "tcp/22,80,443,445,502",
            "udp-probe",
            "dns/53",
            "snmp/161",
            "tls-client-hello",
            "http-request",
            "smb-negotiate",
            "ot-request",
            "Modbus/TCP: function 0x2B, MEI type 0x0E",
            "TLS 1.3 suite enumeration",
        ] {
            assert!(text.contains(want), "missing {want} in:\n{text}");
        }
        assert!(text.contains("private or in scope"), "{text}");
    }

    #[test]
    fn dry_run_json_and_the_scope_verdict_for_a_public_target() {
        // A public target would be refused by a real run; the dry run reports it and exits 0.
        let (text, status) = run_to_file(&[
            "scan",
            "8.8.8.8",
            "--dry-run",
            "--format",
            "json",
            "--ports",
            "53",
        ]);
        assert_eq!(status, crate::ui::ExitCode::Success);
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["dry_run"], true);
        assert_eq!(v["packets_sent"], 0);
        assert_eq!(v["hosts"], 1);
        assert_eq!(v["scope"]["would_need_confirmation"], true);
        assert_eq!(v["groups"][0]["family"], "ipv4");
        assert!(v["groups"][0]["packets"].as_array().unwrap().len() >= 2);
    }

    #[test]
    fn trace_monitor_and_dcp_dry_runs() {
        let (text, status) =
            run_to_file(&["trace", "192.168.77.1", "--dry-run", "--max-hops", "8"]);
        assert_eq!(status, crate::ui::ExitCode::Success);
        assert!(
            text.contains("traceroute") && text.contains("TTL 1 to 8"),
            "{text}"
        );
        let (text, _) = run_to_file(&[
            "monitor",
            "192.168.77.5",
            "--dry-run",
            "--dhcp-discover",
            "--interval",
            "60",
        ]);
        assert!(
            text.contains("dhcp-discover") && text.contains("each monitor cycle repeats"),
            "{text}"
        );
        let (text, _) = run_to_file(&["dcp", "--dry-run"]);
        assert!(
            text.contains("dcp-identify") && text.contains("Identify All"),
            "{text}"
        );
        assert!(text.contains("01:0E:CF:00:00:00"));
    }

    #[test]
    fn tcp_traceroute_in_safe_mode_is_not_planned_as_tcp() {
        // The real command refuses TCP/UDP traceroute without --fast; the dry run does too.
        let dir = std::env::temp_dir().join(format!("ns-dry-trace-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let err = run(&args(&[
            "trace",
            "192.168.77.1",
            "--dry-run",
            "--trace-method",
            "tcp",
            "--trace-port",
            "443",
        ]))
        .unwrap_err();
        assert!(err.contains("--fast"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dry_run_is_rejected_by_commands_that_cannot_send() {
        for command in ["history", "export", "findings", "listen", "feeds"] {
            let err = run(&args(&[command, "1", "--dry-run"])).unwrap_err();
            assert!(err.contains("--dry-run"), "{command}: {err}");
        }
    }

    /// The proof that a dry run sends nothing: a real listener on loopback is named as the
    /// target of an everything-on scan, trace and DCP dry run, and never sees a connection or a
    /// datagram.
    #[test]
    fn a_dry_run_sends_nothing() {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        tcp.set_nonblocking(true).unwrap();
        let tcp_port = tcp.local_addr().unwrap().port();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.set_nonblocking(true).unwrap();
        let udp_port = udp.local_addr().unwrap().port();
        let ports = tcp_port.to_string();
        let udp_ports = udp_port.to_string();
        for list in [
            vec![
                "scan",
                "127.0.0.1",
                "--dry-run",
                "--fast",
                "--deep",
                "--ot",
                "--trace",
                "--dns",
                "--syn",
                "--arp-sweep",
                "--ports",
                &ports,
                "--udp-ports",
                &udp_ports,
            ],
            vec!["trace", "127.0.0.1", "--dry-run", "--fast"],
            vec![
                "monitor",
                "127.0.0.1",
                "--dry-run",
                "--fast",
                "--dhcp-discover",
                "--ports",
                &ports,
            ],
            vec!["dcp", "--dry-run"],
        ] {
            let (text, status) = run_to_file(&list);
            assert_eq!(status, crate::ui::ExitCode::Success, "{list:?}");
            assert!(text.contains("nothing was sent") || text.contains("\"packets_sent\": 0"));
        }
        // Give a stray connection time to arrive, then look.
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(
            matches!(tcp.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "the dry run connected to the target"
        );
        let mut buf = [0u8; 64];
        assert!(
            matches!(udp.recv_from(&mut buf), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "the dry run sent a datagram to the target"
        );
    }

    /// Structural half: the dry-run code reaches no sender.
    #[test]
    fn the_dry_run_module_has_no_way_to_send() {
        let code = include_str!("dryrun.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for forbidden in [
            "start_stream",
            "scan::start(",
            "execute(",
            "TcpStream",
            "UdpSocket",
            "tokio::net",
            "Gate",
            "capture::",
            "store::save",
            "passive::start",
        ] {
            assert!(
                !code.contains(forbidden),
                "dryrun.rs must not use {forbidden}"
            );
        }
    }
}
