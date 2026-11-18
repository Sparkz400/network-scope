//! Continuous monitoring: repeat a scan, compare it with the previous one and with the set of
//! devices ever seen, and raise alerts for new devices, opened/closed ports, new findings and
//! unexpected DHCP servers. Alerts are stored in the inventory database and emitted as JSON lines.
use crate::{
    devices, risk,
    risk::Severity,
    scan::{self, Host},
    store::{self, Snapshot},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    net::IpAddr,
    path::Path,
    time::Duration,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Alert {
    pub timestamp: i64,
    pub severity: Severity,
    pub kind: String,
    pub subject: String,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct Policy {
    /// Record devices without alerting (the first run does this automatically).
    pub learn: bool,
    /// DHCP servers that are expected. Empty: only more than one server is reported.
    pub dhcp_allow: BTreeSet<IpAddr>,
    pub min_severity: Severity,
    pub report_missing: bool,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            learn: false,
            dhcp_allow: BTreeSet::new(),
            min_severity: Severity::Low,
            report_missing: false,
        }
    }
}

const RISKY_PORTS: [u16; 14] = [
    21, 23, 69, 135, 139, 445, 1433, 3306, 3389, 5900, 6379, 27017, 2375, 502,
];

/// Every DHCP server seen: scan answers (DHCPINFORM), passive OFFER/ACK traffic and active discovery.
pub fn dhcp_servers(s: &Snapshot) -> BTreeMap<IpAddr, String> {
    let mut found = BTreeMap::new();
    for h in &s.hosts {
        if let Some(info) = h.identity.get("udp.67") {
            let ip = info
                .split("server ")
                .nth(1)
                .and_then(|r| r.split([',', ')']).next())
                .and_then(|a| a.trim().parse().ok())
                .unwrap_or(h.ip);
            found.insert(ip, format!("answered DHCPINFORM at {}", h.ip));
        }
    }
    for o in &s.observations {
        if o.protocol == "DHCP" {
            // A passive DHCP observation's `ip` is the client. Servers are recorded per server
            // ("dhcp_server.<ip>", from option 54 or else the IP source of an OFFER/ACK/NAK).
            for (key, kind) in &o.fields {
                let Some(server) = key
                    .strip_prefix("dhcp_server.")
                    .and_then(|v| v.parse::<IpAddr>().ok())
                else {
                    continue;
                };
                if matches!(kind.as_str(), "2" | "5") {
                    found
                        .entry(server)
                        .or_insert_with(|| "seen sending DHCP OFFER/ACK".into());
                }
            }
            continue;
        }
        let Some(ip) = o.ip else { continue };
        if o.protocol == "DHCP offer" {
            found.entry(ip).or_insert_with(|| {
                format!(
                    "answered DHCPDISCOVER offering {}",
                    o.fields.get("offered_ip").map_or("?", String::as_str)
                )
            });
        }
    }
    found
}

fn alert(
    now: i64,
    severity: Severity,
    kind: &str,
    subject: impl Into<String>,
    message: impl Into<String>,
) -> Alert {
    Alert {
        timestamp: now,
        severity,
        kind: kind.into(),
        subject: subject.into(),
        message: message.into(),
    }
}

pub fn evaluate(
    prev: Option<&Snapshot>,
    cur: &Snapshot,
    known: &HashMap<String, (i64, i64)>,
    policy: &Policy,
    now: i64,
) -> Vec<Alert> {
    let mut out = vec![];
    let cur_devices = devices::merge(&cur.hosts, &cur.observations);
    let learning = policy.learn || known.is_empty();

    if !learning {
        for d in &cur_devices {
            if known.contains_key(&d.id) {
                continue;
            }
            let ot = d.device_type.starts_with("Industrial")
                || d.open_tcp
                    .iter()
                    .any(|p| crate::service::is_ot_port_candidate(*p));
            out.push(alert(
                now,
                if ot { Severity::High } else { Severity::Medium },
                "new-device",
                d.ips.first().map_or(d.id.clone(), ToString::to_string),
                format!(
                    "New device {} {} {} {}",
                    d.ips
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join("/"),
                    d.mac,
                    d.vendor,
                    d.device_type
                )
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" "),
            ));
        }
    }

    if let Some(prev) = prev.filter(|p| p.complete && cur.complete) {
        let old: HashMap<IpAddr, &Host> = prev
            .hosts
            .iter()
            .filter(|h| h.responding)
            .map(|h| (h.ip, h))
            .collect();
        // A port that only one of the two scans probed says nothing about a change.
        let scanned = |s: &Snapshot| -> BTreeSet<u16> {
            scan::parse_ports(&s.settings.ports)
                .unwrap_or_default()
                .into_iter()
                .collect()
        };
        let comparable: BTreeSet<u16> =
            scanned(prev).intersection(&scanned(cur)).copied().collect();
        // UDP: only when both scans probed UDP, and only ports both of them probed.
        let udp_scanned = |s: &Snapshot| -> BTreeSet<u16> {
            if !s.settings.udp {
                return BTreeSet::new();
            }
            scan::parse_ports(&s.settings.udp_ports)
                .unwrap_or_default()
                .into_iter()
                .collect()
        };
        let udp_comparable: BTreeSet<u16> = udp_scanned(prev)
            .intersection(&udp_scanned(cur))
            .copied()
            .collect();
        for h in cur.hosts.iter().filter(|h| h.responding) {
            let Some(before) = old
                .get(&h.ip)
                .filter(|b| b.ports_checked && h.ports_checked)
            else {
                continue;
            };
            for p in h
                .open
                .iter()
                .filter(|p| comparable.contains(p) && !before.open.contains(p))
            {
                let sev = if RISKY_PORTS.contains(p) {
                    Severity::High
                } else {
                    Severity::Medium
                };
                out.push(alert(
                    now,
                    sev,
                    "port-opened",
                    h.ip.to_string(),
                    format!("{}: TCP port {p} newly open", h.ip),
                ));
            }
            for p in before
                .open
                .iter()
                .filter(|p| comparable.contains(p) && !h.open.contains(p))
            {
                out.push(alert(
                    now,
                    Severity::Info,
                    "port-closed",
                    h.ip.to_string(),
                    format!(
                        "{}: TCP port {p} no longer open (a timeout is not proof it closed)",
                        h.ip
                    ),
                ));
            }
            for p in h
                .udp_open
                .iter()
                .filter(|p| udp_comparable.contains(p) && !before.udp_open.contains(p))
            {
                out.push(alert(
                    now,
                    Severity::Medium,
                    "port-opened",
                    h.ip.to_string(),
                    format!("{}: UDP port {p} newly answering", h.ip),
                ));
            }
        }
        let old_findings: HashSet<String> = risk::analyze_snapshot(prev)
            .iter()
            .map(risk::Finding::key)
            .collect();
        for f in risk::analyze_snapshot(cur)
            .into_iter()
            .filter(|f| !old_findings.contains(&f.key()))
        {
            out.push(alert(
                now,
                f.severity,
                "new-finding",
                format!(
                    "{}{}",
                    f.ip,
                    f.port.map_or(String::new(), |p| format!(":{p}"))
                ),
                format!("{} - {}", f.title, f.evidence),
            ));
        }
        let prev_devices = devices::merge(&prev.hosts, &prev.observations);
        let now_by_id: HashMap<&str, &devices::Device> =
            cur_devices.iter().map(|d| (d.id.as_str(), d)).collect();
        for d in &prev_devices {
            match now_by_id.get(d.id.as_str()) {
                Some(n)
                    if !d.mac.is_empty()
                        && n.ips != d.ips
                        && !d.ips.is_empty()
                        && !n.ips.is_empty() =>
                {
                    // Medium: a known MAC on a new address can be spoofing or a misconfiguration.
                    out.push(alert(
                        now,
                        Severity::Medium,
                        "address-changed",
                        d.mac.clone(),
                        format!("{} moved from {:?} to {:?}", d.mac, d.ips, n.ips),
                    ));
                }
                None if policy.report_missing => {
                    // Low, so the explicitly requested report passes the default threshold.
                    out.push(alert(
                        now,
                        Severity::Low,
                        "device-missing",
                        d.ips.first().map_or(d.id.clone(), ToString::to_string),
                        format!(
                            "{} {} was not observed in this scan (not proof it is offline)",
                            d.id, d.vendor
                        ),
                    ));
                }
                _ => {}
            }
        }
    }

    let servers = dhcp_servers(cur);
    if policy.dhcp_allow.is_empty() {
        if servers.len() > 1 {
            out.push(alert(
                now,
                Severity::High,
                "rogue-dhcp",
                "dhcp",
                format!(
                    "{} DHCP servers answer: {}",
                    servers.len(),
                    servers
                        .iter()
                        .map(|(ip, how)| format!("{ip} ({how})"))
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            ));
        }
    } else {
        for (ip, how) in servers
            .iter()
            .filter(|(ip, _)| !policy.dhcp_allow.contains(ip))
        {
            out.push(alert(
                now,
                Severity::Critical,
                "rogue-dhcp",
                ip.to_string(),
                format!(
                    "Unexpected DHCP server {ip} ({how}); allowed: {}",
                    policy
                        .dhcp_allow
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
    }
    out.retain(|a| a.severity >= policy.min_severity);
    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.kind.cmp(&b.kind))
            .then(a.subject.cmp(&b.subject))
    });
    out
}

pub struct RunConfig {
    pub interval: Duration,
    /// 0 means run until the process is stopped.
    pub cycles: u32,
    pub policy: Policy,
    pub dhcp_discover: bool,
    pub interface: String,
    pub listen_seconds: u64,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Merges captured observations, turning capture errors and the observation cap into warnings
/// (the extra observations are dropped) instead of failing the monitoring cycle.
fn collect_observations(
    observations: &mut Vec<crate::passive::Observation>,
    items: impl IntoIterator<Item = Result<crate::passive::Observation, String>>,
) -> Vec<String> {
    let mut warnings = vec![];
    let mut capped = 0u64;
    for item in items {
        match item {
            Ok(o) => {
                if crate::ui::merge(observations, o).is_err() {
                    capped += 1;
                }
            }
            Err(e) => warnings.push(e),
        }
    }
    if capped > 0 {
        warnings.push(format!(
            "observation limit reached; {capped} further observations were not kept"
        ));
    }
    warnings
}

pub fn run(
    targets_text: &str,
    settings: scan::Settings,
    db: &Path,
    cfg: &RunConfig,
    emit: &mut dyn FnMut(&Alert),
) -> Result<(), String> {
    let targets = scan::parse_targets(targets_text, settings.skip_edges, scan::MAX_STREAM)?;
    let ports = scan::parse_ports(&settings.ports)?;
    let mut cycle = 0;
    loop {
        cycle += 1;
        let mut observations = vec![];
        let mut notices = vec![];
        if !cfg.interface.is_empty() {
            let listening = crate::passive::start(cfg.interface.clone(), cfg.listen_seconds, None);
            // A capture problem never ends monitoring: the cycle continues with what was seen.
            for warning in collect_observations(&mut observations, &listening.receiver) {
                eprintln!("Cycle {cycle}: warning: {warning}");
                notices.push(alert(
                    now(),
                    Severity::Low,
                    "capture-incomplete",
                    cfg.interface.as_str(),
                    format!("Passive capture incomplete: {warning}"),
                ));
            }
        }
        let total = targets.count() as usize;
        let run = scan::start_stream(
            Box::new(targets.iter()),
            total,
            ports.clone(),
            settings.clone(),
        );
        let mut hosts = vec![];
        let sparse = total > scan::MAX_HOSTS;
        let mut complete = true;
        loop {
            match run.receiver.recv().map_err(|e| e.to_string())? {
                scan::Event::Host(h) => {
                    if h.responding || !sparse {
                        hosts.push(h)
                    }
                }
                scan::Event::Done => break,
                scan::Event::Error(e) => return Err(e),
            }
        }
        if run.cancel.load(std::sync::atomic::Ordering::Relaxed) {
            complete = false;
        }
        if cfg.dhcp_discover {
            match crate::udp::dhcp_discover(Duration::from_secs(4)) {
                Ok(offers) => {
                    for o in offers {
                        observations.push(crate::passive::Observation {
                            protocol: "DHCP offer".into(),
                            mac: String::new(),
                            ip: Some(IpAddr::V4(o.server)),
                            fields: BTreeMap::from([
                                ("offered_ip".to_string(), o.offered.to_string()),
                                (
                                    "router".to_string(),
                                    o.router.map_or(String::new(), |r| r.to_string()),
                                ),
                                (
                                    "dns".to_string(),
                                    o.dns
                                        .iter()
                                        .map(ToString::to_string)
                                        .collect::<Vec<_>>()
                                        .join(","),
                                ),
                                (
                                    "lease_seconds".to_string(),
                                    o.lease.map_or(String::new(), |l| l.to_string()),
                                ),
                            ]),
                        });
                    }
                }
                Err(e) => notices.push(alert(
                    now(),
                    Severity::Low,
                    "dhcp-discover-failed",
                    "dhcp",
                    format!("DHCP discovery could not run: {e}"),
                )),
            }
        }
        let snapshot = Snapshot {
            targets: targets_text.to_string(),
            complete,
            settings: settings.clone(),
            hosts,
            observations,
            notes: BTreeMap::new(),
        };
        let id = store::save(db, &snapshot)?;
        let prev = store::latest_complete(db, targets_text, id)?.map(|(_, _, s)| s);
        let known = store::known_devices(db)?;
        let t = now();
        let mut alerts = evaluate(prev.as_ref(), &snapshot, &known, &cfg.policy, t);
        alerts.extend(notices);
        let keys: Vec<String> = devices::merge(&snapshot.hosts, &snapshot.observations)
            .into_iter()
            .map(|d| d.id)
            .collect();
        if complete {
            store::touch_devices(db, &keys, t)?;
        }
        store::save_alerts(db, id, &alerts)?;
        eprintln!(
            "Cycle {cycle}: scan #{id}, {} hosts, {} alerts",
            snapshot.hosts.len(),
            alerts.len()
        );
        for a in &alerts {
            emit(a);
        }
        if cfg.cycles != 0 && cycle >= cfg.cycles {
            return Ok(());
        }
        std::thread::sleep(cfg.interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passive::Observation;

    fn host(ip: &str, mac: &str, open: &[u16], id: &[(&str, &str)]) -> Host {
        Host {
            ip: ip.parse().unwrap(),
            responding: true,
            ping: None,
            ttl: None,
            hostname: String::new(),
            mac: mac.into(),
            open: open.to_vec(),
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity: id
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            udp_open: vec![],
            trace: vec![],
        }
    }
    fn snap(hosts: Vec<Host>, observations: Vec<Observation>) -> Snapshot {
        Snapshot {
            targets: "10.0.0.0/24".into(),
            complete: true,
            settings: crate::scan::Settings {
                ports: "1-1024".into(),
                ..Default::default()
            },
            hosts,
            observations,
            notes: Default::default(),
        }
    }
    fn known(keys: &[&str]) -> HashMap<String, (i64, i64)> {
        keys.iter().map(|k| (k.to_string(), (1, 1))).collect()
    }
    fn kinds(a: &[Alert]) -> Vec<&str> {
        a.iter().map(|a| a.kind.as_str()).collect()
    }

    #[test]
    fn new_devices_alert_but_the_first_run_only_learns() {
        let base = snap(
            vec![host("10.0.0.5", "AA:BB:CC:00:00:01", &[22], &[])],
            vec![],
        );
        let cur = snap(
            vec![
                host("10.0.0.5", "AA:BB:CC:00:00:01", &[22], &[]),
                host("10.0.0.9", "AA:BB:CC:00:00:09", &[502], &[]),
            ],
            vec![],
        );
        let none: HashMap<String, (i64, i64)> = HashMap::new();
        assert!(
            evaluate(None, &cur, &none, &Policy::default(), 1).is_empty(),
            "first run learns silently"
        );
        let known = known(&["AA:BB:CC:00:00:01"]);
        let a = evaluate(Some(&base), &cur, &known, &Policy::default(), 1);
        assert!(kinds(&a).contains(&"new-device"));
        let nd = a.iter().find(|a| a.kind == "new-device").unwrap();
        assert_eq!(
            nd.severity,
            Severity::High,
            "a new OT device is high severity"
        );
        assert!(nd.message.contains("10.0.0.9"));
        let learn = Policy {
            learn: true,
            ..Policy::default()
        };
        assert!(!kinds(&evaluate(Some(&base), &cur, &known, &learn, 1)).contains(&"new-device"));
    }

    #[test]
    fn port_changes_and_new_findings() {
        let before = snap(
            vec![host("10.0.0.5", "AA:BB:CC:00:00:01", &[22, 80], &[])],
            vec![],
        );
        let after = snap(
            vec![host(
                "10.0.0.5",
                "AA:BB:CC:00:00:01",
                &[22, 23],
                &[("svc.23", "telnet")],
            )],
            vec![],
        );
        let a = evaluate(
            Some(&before),
            &after,
            &known(&["AA:BB:CC:00:00:01"]),
            &Policy::default(),
            1,
        );
        assert!(a.iter().any(|a| a.kind == "port-opened"
            && a.severity == Severity::High
            && a.message.contains("23")));
        assert!(a
            .iter()
            .any(|a| a.kind == "new-finding" && a.message.contains("Telnet")));
        assert!(
            !a.iter().any(|a| a.kind == "port-closed"),
            "info is below the default threshold"
        );
        let all = Policy {
            min_severity: Severity::Info,
            ..Policy::default()
        };
        let a = evaluate(
            Some(&before),
            &after,
            &known(&["AA:BB:CC:00:00:01"]),
            &all,
            1,
        );
        assert!(a
            .iter()
            .any(|a| a.kind == "port-closed" && a.message.contains("80")));
        // The same state again produces no change alerts.
        assert!(evaluate(
            Some(&after),
            &after,
            &known(&["AA:BB:CC:00:00:01"]),
            &all,
            1
        )
        .is_empty());
        // A partial scan never produces change alerts: absence proves nothing.
        let mut partial = after.clone();
        partial.complete = false;
        assert!(evaluate(
            Some(&before),
            &partial,
            &known(&["AA:BB:CC:00:00:01"]),
            &all,
            1
        )
        .is_empty());
    }

    #[test]
    fn ports_only_one_scan_probed_are_not_changes() {
        let mut before = snap(
            vec![host("10.0.0.5", "AA:BB:CC:00:00:01", &[80], &[])],
            vec![],
        );
        let after = snap(
            vec![host("10.0.0.5", "AA:BB:CC:00:00:01", &[22, 80], &[])],
            vec![],
        );
        before.settings.ports = "80".into();
        let policy = Policy {
            min_severity: Severity::Info,
            ..Policy::default()
        };
        let k = known(&["AA:BB:CC:00:00:01"]);
        let a = evaluate(Some(&before), &after, &k, &policy, 1);
        assert!(
            !a.iter().any(|a| a.kind == "port-opened"),
            "port 22 was not probed before: {a:?}"
        );
        let mut dropped = after.clone();
        dropped.settings.ports = "22".into();
        dropped.hosts[0].open = vec![22];
        let a = evaluate(Some(&before), &dropped, &k, &policy, 1);
        assert!(
            !a.iter().any(|a| a.kind == "port-closed"),
            "port 80 was not probed now: {a:?}"
        );
    }

    #[test]
    fn missing_and_moved_devices() {
        let before = snap(
            vec![
                host("10.0.0.5", "AA:BB:CC:00:00:01", &[], &[]),
                host("10.0.0.6", "AA:BB:CC:00:00:02", &[], &[]),
            ],
            vec![],
        );
        let after = snap(
            vec![host("10.0.0.50", "AA:BB:CC:00:00:01", &[], &[])],
            vec![],
        );
        let policy = Policy {
            report_missing: true,
            min_severity: Severity::Info,
            ..Policy::default()
        };
        let a = evaluate(
            Some(&before),
            &after,
            &known(&["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"]),
            &policy,
            1,
        );
        assert!(a
            .iter()
            .any(|a| a.kind == "address-changed" && a.message.contains("10.0.0.50")));
        let missing = a.iter().find(|a| a.kind == "device-missing").unwrap();
        assert!(missing.message.contains("not proof"));
        let quiet = evaluate(
            Some(&before),
            &after,
            &known(&["AA:BB:CC:00:00:01"]),
            &Policy {
                min_severity: Severity::Info,
                ..Policy::default()
            },
            1,
        );
        assert!(!kinds(&quiet).contains(&"device-missing"));
    }

    #[test]
    fn rogue_dhcp_detection() {
        // As passive::decode records it: `ip` is the client, the server has its own key.
        let obs = |server: &str, kind: &str| Observation {
            protocol: "DHCP".into(),
            mac: "AA:BB:CC:00:00:77".into(),
            ip: Some("10.0.0.200".parse().unwrap()),
            fields: [
                ("message_type".to_string(), kind.to_string()),
                (format!("dhcp_server.{server}"), kind.to_string()),
            ]
            .into(),
        };
        let discover = Observation {
            protocol: "DHCP offer".into(),
            mac: String::new(),
            ip: Some("10.0.0.99".parse().unwrap()),
            fields: [("offered_ip".to_string(), "10.0.0.150".to_string())].into(),
        };
        let cur = snap(
            vec![host(
                "10.0.0.1",
                "AA:BB:CC:00:00:01",
                &[],
                &[("udp.67", "DHCP ACK (server 10.0.0.1, mask 255.255.255.0)")],
            )],
            vec![obs("10.0.0.1", "5"), discover, obs("10.0.0.7", "1")],
        );
        let servers = dhcp_servers(&cur);
        assert_eq!(
            servers.keys().map(ToString::to_string).collect::<Vec<_>>(),
            ["10.0.0.1", "10.0.0.99"],
            "a client DISCOVER (type 1) is not a server"
        );
        let k = known(&["AA:BB:CC:00:00:01"]);
        let learn = Policy {
            learn: true,
            ..Policy::default()
        };
        let a = evaluate(None, &cur, &k, &learn, 1);
        assert_eq!(
            kinds(&a),
            ["rogue-dhcp"],
            "two servers without an allow-list"
        );
        assert_eq!(a[0].severity, Severity::High);
        let allow = Policy {
            dhcp_allow: ["10.0.0.1".parse().unwrap()].into(),
            learn: true,
            ..Policy::default()
        };
        let a = evaluate(None, &cur, &k, &allow, 1);
        assert_eq!(a.len(), 1);
        assert_eq!(
            (a[0].severity, a[0].subject.as_str()),
            (Severity::Critical, "10.0.0.99")
        );
        let single = snap(vec![], vec![obs("10.0.0.1", "2")]);
        assert!(evaluate(None, &single, &k, &learn, 1).is_empty());
    }

    /// Real OFFER/ACK frames through passive::decode and ui::merge, as a live capture does.
    #[test]
    fn rogue_dhcp_from_decoded_frames() {
        use crate::passive::tests::dhcp_reply_frame;
        let client = [0xaa, 0xbb, 0xcc, 0, 0, 0x42];
        let other = [0xaa, 0xbb, 0xcc, 0, 0, 0x43];
        let capture = |frames: &[Vec<u8>]| {
            let mut observations = vec![];
            for f in frames {
                crate::ui::merge(&mut observations, crate::passive::decode(f).unwrap()).unwrap();
            }
            observations
        };
        // One legitimate server handing out leases to two clients: no rogue server.
        let legit = capture(&[
            dhcp_reply_frame(
                2,
                [10, 0, 0, 1],
                Some([10, 0, 0, 1]),
                [10, 0, 0, 150],
                client,
            ),
            dhcp_reply_frame(
                5,
                [10, 0, 0, 1],
                Some([10, 0, 0, 1]),
                [10, 0, 0, 150],
                client,
            ),
            dhcp_reply_frame(
                5,
                [10, 0, 0, 1],
                Some([10, 0, 0, 1]),
                [10, 0, 0, 151],
                other,
            ),
        ]);
        let cur = snap(vec![], legit);
        assert_eq!(
            dhcp_servers(&cur)
                .keys()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["10.0.0.1"],
            "clients are not servers"
        );
        let k = known(&["AA:BB:CC:00:00:01"]);
        let learn = Policy {
            learn: true,
            ..Policy::default()
        };
        assert!(evaluate(None, &cur, &k, &learn, 1).is_empty());
        let allow = Policy {
            dhcp_allow: ["10.0.0.1".parse().unwrap()].into(),
            learn: true,
            ..Policy::default()
        };
        assert!(evaluate(None, &cur, &k, &allow, 1).is_empty());
        // A second server answers the same client: both survive the merge and are reported.
        let rogue = capture(&[
            dhcp_reply_frame(
                2,
                [10, 0, 0, 1],
                Some([10, 0, 0, 1]),
                [10, 0, 0, 150],
                client,
            ),
            dhcp_reply_frame(
                2,
                [10, 0, 0, 66],
                Some([10, 0, 0, 66]),
                [10, 0, 0, 150],
                client,
            ),
        ]);
        let cur = snap(vec![], rogue);
        let a = evaluate(None, &cur, &k, &allow, 1);
        assert_eq!(a.len(), 1, "{a:?}");
        assert_eq!(
            (a[0].kind.as_str(), a[0].severity, a[0].subject.as_str()),
            ("rogue-dhcp", Severity::Critical, "10.0.0.66")
        );
        // A relayed ACK is attributed to option 54, not to the relay.
        let relayed = capture(&[dhcp_reply_frame(
            5,
            [10, 0, 0, 254],
            Some([10, 0, 0, 1]),
            [10, 0, 0, 150],
            client,
        )]);
        assert!(evaluate(None, &snap(vec![], relayed), &k, &allow, 1).is_empty());
    }

    #[test]
    fn requested_missing_and_moved_alerts_pass_the_default_threshold() {
        let before = snap(
            vec![
                host("10.0.0.5", "AA:BB:CC:00:00:01", &[], &[]),
                host("10.0.0.6", "AA:BB:CC:00:00:02", &[], &[]),
            ],
            vec![],
        );
        let after = snap(
            vec![host("10.0.0.50", "AA:BB:CC:00:00:01", &[], &[])],
            vec![],
        );
        let policy = Policy {
            report_missing: true,
            ..Policy::default()
        };
        let k = known(&["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"]);
        let a = evaluate(Some(&before), &after, &k, &policy, 1);
        let moved = a.iter().find(|a| a.kind == "address-changed").unwrap();
        assert_eq!(moved.severity, Severity::Medium);
        let missing = a.iter().find(|a| a.kind == "device-missing").unwrap();
        assert_eq!(missing.severity, Severity::Low);
        // Without --report-missing there is still no missing-device alert.
        let a = evaluate(Some(&before), &after, &k, &Policy::default(), 1);
        assert!(!kinds(&a).contains(&"device-missing"));
    }

    #[test]
    fn udp_changes_need_udp_probed_in_both_scans() {
        let mut before = snap(
            vec![host("10.0.0.5", "AA:BB:CC:00:00:01", &[], &[])],
            vec![],
        );
        let mut after = before.clone();
        after.hosts[0].udp_open = vec![161, 5353];
        let k = known(&["AA:BB:CC:00:00:01"]);
        let udp_opened = |a: &[Alert]| {
            a.iter()
                .filter(|a| a.kind == "port-opened" && a.message.contains("UDP"))
                .map(|a| a.message.clone())
                .collect::<Vec<_>>()
        };
        // The previous scan did not probe UDP at all: nothing is "newly" answering.
        after.settings.udp = true;
        after.settings.udp_ports = "161,5353".into();
        let a = evaluate(Some(&before), &after, &k, &Policy::default(), 1);
        assert!(udp_opened(&a).is_empty(), "{a:?}");
        // Both probed UDP, but only 161 was probed before.
        before.settings.udp = true;
        before.settings.udp_ports = "161".into();
        let a = evaluate(Some(&before), &after, &k, &Policy::default(), 1);
        assert_eq!(udp_opened(&a), ["10.0.0.5: UDP port 161 newly answering"]);
    }

    #[test]
    fn capture_errors_and_the_observation_cap_do_not_fail_a_cycle() {
        let o = |i: u32| Observation {
            protocol: "ARP".into(),
            mac: format!("{i:012X}"),
            ip: None,
            fields: Default::default(),
        };
        let mut items: Vec<Result<Observation, String>> = vec![Ok(o(0)), Err("driver".into())];
        items.extend((1..10_005).map(|i| Ok(o(i))));
        let mut observations = vec![];
        let warnings = collect_observations(&mut observations, items);
        assert_eq!(observations.len(), 10_000, "truncated at the cap");
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert_eq!(warnings[0], "driver");
        assert!(warnings[1].contains("5 further"), "{warnings:?}");
    }
}
