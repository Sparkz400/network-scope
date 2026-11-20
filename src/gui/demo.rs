//! Sample data for `--screenshot` runs, chosen with NETWORK_SCOPE_SCREENSHOT_STATE
//! (main, findings, devices, settings, ot, script, timeline, scan-details, workbench, home, home-empty, map, map-large,
//! quick, palette, palette-actions, appearance, wake; append "-small" for the default 800x450 window, "-fast" for Safe Mode off,
//! "-dark" for the dark theme and "-de" for German, e.g. "home-dark" or "main-de"). Screenshot
//! runs never save to the inventory or preferences.
use super::*;

pub(super) fn demo_host(ip: &str, open: &[u16], identity: &[(&str, &str)]) -> scan::Host {
    scan::Host {
        ip: ip.parse().unwrap_or(IpAddr::from([10, 0, 0, 1])),
        responding: true,
        ping: Some(2),
        ttl: Some(64),
        hostname: String::new(),
        mac: String::new(),
        open: open.to_vec(),
        closed: 0,
        unanswered: 0,
        errors: vec![],
        ports_checked: true,
        identity: identity
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        udp_open: vec![],
        trace: vec![],
    }
}

/// ip, hostname, MAC, ping ms, TTL, open ports, identity.
type DemoHost = (
    &'static str,
    &'static str,
    &'static str,
    u32,
    u8,
    &'static [u16],
    &'static [(&'static str, &'static str)],
);

/// Marks some findings as known exploited with EPSS data, so the screenshots show those
/// columns. Used in screenshot mode only (the real feeds come from `feeds import`).
pub(super) fn decorate_findings(findings: &mut [risk::Finding]) {
    let mut n = 0;
    for f in findings
        .iter_mut()
        .filter(|f| !f.cve.is_empty() || f.id == "telnet-open")
    {
        n += 1;
        f.exploit.kev = n % 2 == 1;
        f.exploit.kev_ransomware = n == 1;
        f.exploit.kev_added = Some("2023-06-14".into());
        f.exploit.epss = crate::feeds::Score::from_f64([0.9754, 0.12, 0.034, 0.5][n % 4]);
    }
}

/// The path of a demo host: the core switch, then one of two distribution routers.
fn demo_trace(ip: IpAddr, via: &str) -> Vec<crate::trace::Hop> {
    let hop = |ttl, ip: Option<IpAddr>| crate::trace::Hop {
        ttl,
        ip,
        rtt: Some(1),
    };
    vec![
        hop(1, Some(IpAddr::from([10, 20, 0, 1]))),
        hop(2, via.parse().ok()),
        hop(3, Some(ip)),
    ]
}

impl Scanner {
    pub(super) fn seed_demo(&mut self, state: &str) {
        // Suffixes in any order: "-fast" renders the window with Safe Mode off, "-dark" the
        // dark theme, "-de" German ("main-small-fast").
        let mut state = state;
        // Screenshots are English unless the state says "-de", whatever the system language is.
        self.saved.language = "en".into();
        loop {
            let before = state;
            for suffix in ["-fast", "-dark", "-de", "-small"] {
                if let Some(rest) = state.strip_suffix(suffix) {
                    state = rest;
                    match suffix {
                        "-fast" => self.saved.settings.safe = false,
                        "-dark" => self.saved.dark = true,
                        "-de" => self.saved.language = "de".into(),
                        _ => {}
                    }
                }
            }
            if state == before {
                break;
            }
        }
        self.filter = Filter::All;
        self.view = MainView::Hosts;
        self.targets = "10.20.0.0/24".into();
        // A small plant network: controllers, HMI, infrastructure and office hosts.
        let plant: [DemoHost; 12] = [
            (
                "10.20.0.1",
                "core-sw-01",
                "00:1B:1B:4A:10:01",
                1,
                64,
                &[22, 80, 443],
                &[
                    ("svc.22", "ssh OpenSSH 7.4"),
                    ("svc.22.product", "OpenSSH"),
                    ("svc.22.version", "7.4"),
                    ("mac.vendor", "Siemens AG"),
                    ("device.type", "Switch"),
                ],
            ),
            (
                "10.20.0.5",
                "plc-line-1",
                "00:1B:1B:7C:22:05",
                2,
                30,
                &[21, 23, 102, 502],
                &[
                    ("svc.23", "telnet"),
                    ("mac.vendor", "Siemens AG"),
                    ("device.type", "PLC"),
                    ("ot.s7.order_code", "6ES7 515-2AM02-0AB0"),
                ],
            ),
            (
                "10.20.0.6",
                "plc-line-2",
                "00:1D:9C:31:08:06",
                2,
                64,
                &[44818],
                &[
                    ("mac.vendor", "Rockwell Automation"),
                    ("device.type", "PLC"),
                    ("ot.enip.product", "1756-L83E/B"),
                ],
            ),
            (
                "10.20.0.12",
                "hmi-packaging",
                "00:0E:8C:5A:91:0C",
                3,
                128,
                &[80, 3389, 4840],
                &[
                    ("svc.3389", "ms-wbt-server RDP"),
                    ("device.type", "HMI"),
                    ("os", "Windows"),
                ],
            ),
            (
                "10.20.0.20",
                "historian",
                "00:50:56:A1:3C:14",
                1,
                128,
                &[135, 445, 1433, 3389],
                &[
                    ("svc.445", "microsoft-ds SMB 3.1.1"),
                    ("os", "Windows Server"),
                ],
            ),
            (
                "10.20.0.31",
                "eng-ws-03",
                "3C:52:82:11:7E:1F",
                4,
                128,
                &[135, 445],
                &[("os", "Windows"), ("device.type", "Workstation")],
            ),
            (
                "10.20.0.40",
                "nas-backup",
                "00:11:32:9B:44:28",
                1,
                64,
                &[22, 80, 443, 445],
                &[
                    ("svc.80", "http nginx 1.14.0"),
                    ("svc.80.product", "nginx"),
                    ("svc.80.version", "1.14.0"),
                    ("mac.vendor", "Synology"),
                ],
            ),
            (
                "10.20.0.55",
                "",
                "00:80:F4:12:6A:37",
                5,
                64,
                &[502],
                &[
                    ("mac.vendor", "Schneider Electric"),
                    ("device.type", "Remote I/O"),
                ],
            ),
            (
                "10.20.0.60",
                "bacnet-ahu-2",
                "00:A0:3D:04:91:3C",
                6,
                64,
                &[47808],
                &[
                    ("ot.bacnet.vendor", "Johnson Controls"),
                    ("device.type", "Building controller"),
                ],
            ),
            (
                "10.20.0.77",
                "printer-hall",
                "00:1B:A9:E5:02:4D",
                3,
                64,
                &[80, 515, 631, 9100],
                &[("mac.vendor", "Brother"), ("device.type", "Printer")],
            ),
            (
                "10.20.0.88",
                "cam-gate",
                "BC:AD:28:6F:11:58",
                2,
                64,
                &[80, 554],
                &[("svc.554", "rtsp"), ("device.type", "IP camera")],
            ),
            (
                "10.20.0.101",
                "laptop-qa",
                "F0:9E:4A:3B:77:65",
                7,
                128,
                &[],
                &[("os", "Windows")],
            ),
        ];
        self.results = plant
            .iter()
            .map(|(ip, name, mac, ping, ttl, open, id)| {
                let mut h = demo_host(ip, open, id);
                h.hostname = name.to_string();
                h.mac = mac.to_string();
                h.ping = Some(*ping);
                h.ttl = Some(*ttl);
                h
            })
            .collect();
        self.recount();
        self.data_changed();
        match state {
            "home" => {
                self.view = MainView::Home;
                self.home.data = Some(Ok(Box::new(self.demo_home())));
            }
            "home-empty" => {
                self.view = MainView::Home;
                let mut changes = self.demo_home().changes;
                self.results.clear();
                self.recount();
                changes.current = None;
                changes.previous = None;
                changes.summary = Default::default();
                changes.new_devices.clear();
                changes.gone_devices.clear();
                changes.changed_devices.clear();
                changes.new_risks.clear();
                changes.resolved_risks.clear();
                changes.unconfirmed_risks.clear();
                changes.unknown_devices = None;
                changes.notice = Some("The inventory has no scans yet.".into());
                self.home.data = Some(Ok(Box::new(home::HomeData {
                    changes,
                    assessment: crate::score::assess(&[], 5),
                    scans: 0,
                })));
            }
            "map" | "map-large" => {
                // Paths: the core switch, then two distribution routers.
                for h in self
                    .results
                    .iter_mut()
                    .filter(|h| h.ip != IpAddr::from([10, 20, 0, 1]))
                {
                    let via = if h
                        .open
                        .iter()
                        .any(|p| [102, 502, 44818, 47808, 4840].contains(p))
                    {
                        "10.20.0.3"
                    } else {
                        "10.20.0.2"
                    };
                    h.trace = demo_trace(h.ip, via);
                }
                if state == "map-large" {
                    for i in 0..300u32 {
                        let ip = IpAddr::from([10, 30, (i / 250) as u8, (i % 250) as u8 + 1]);
                        let open: &[u16] = match i % 7 {
                            0 => &[502],
                            1 => &[80, 443],
                            2 => &[9100],
                            3 => &[3389, 445],
                            _ => &[22],
                        };
                        let mut h = demo_host(&ip.to_string(), open, &[]);
                        let via = format!("10.31.{}.1", i % 5);
                        h.trace = demo_trace(ip, &via);
                        self.results.push(h);
                    }
                    self.recount();
                }
                self.data_changed();
                self.topology_open = true;
            }
            "quick" => {
                let net = |name: &str, ip: &str, prefix| crate::localnets::LocalNet {
                    interface: name.into(),
                    ip: ip.parse().unwrap(),
                    prefix,
                };
                self.quick.candidates = crate::localnets::classify(&[
                    net("Ethernet", "192.168.178.20", 24),
                    net("Ethernet 2", "10.20.0.31", 16),
                    net("vEthernet (WSL)", "172.28.16.1", 20),
                    net("OpenVPN Wintun", "10.8.0.6", 32),
                    net("Loopback Pseudo-Interface 1", "127.0.0.1", 8),
                    net("Ethernet", "169.254.9.9", 16),
                ]);
                self.quick.dialog = true;
                self.view = MainView::Home;
                self.home.data = Some(Ok(Box::new(self.demo_home())));
            }
            "palette" => {
                self.palette.open = true;
                self.palette.query = "10.20.0.5".into();
                self.palette.asked = "10.20.0.5".into();
                let hit = |scan_id, days: i64, source, detail: &str| crate::search::Hit {
                    scan_id,
                    timestamp: 1_790_000_000 + days * 86_400,
                    targets: "10.20.0.0/24".into(),
                    source,
                    ip: Some("10.20.0.5".parse().unwrap()),
                    mac: "00:1B:1B:7C:22:05".into(),
                    hostname: "plc-line-1".into(),
                    vendor: "Siemens AG".into(),
                    detail: detail.into(),
                };
                let hits = vec![
                    hit(9, 21, "host", "open 21, 102, 502"),
                    hit(7, 14, "host", "open 21, 23, 102, 502"),
                    hit(3, 0, "host", "open 23, 102"),
                ];
                self.palette.results = Some(Ok(Box::new(crate::search::Results {
                    query: "10.20.0.5".into(),
                    scans_checked: 9,
                    scans_total: 9,
                    truncated: false,
                    last_seen: hits.first().cloned(),
                    hits,
                })));
            }
            "appearance" => {
                self.settings_open = true;
                self.scroll_to_appearance = true;
            }
            "palette-actions" => {
                self.palette.open = true;
                self.palette.query = "sc".into();
            }
            "wake" => {
                let host = self.results[1].clone();
                self.wake = Some(convenience::WakeRequest {
                    label: format!("{} ({})", host.hostname, host.ip),
                    mac: host.mac.clone(),
                    destination: "10.20.0.255".into(),
                });
                self.saved.starred.insert(convenience::favorite_key(&host));
            }
            "workbench" | "workbench-compare" | "workbench-draft" => {
                // Two unknown products from invented banners, grouped and drafted by the core
                // functions (never the user's inventory).
                let host = |ip: &str, mac: &str, port: u16, banner: &str| {
                    let mut h = demo_host(ip, &[port], &[("mac.vendor", mac)]);
                    h.identity
                        .insert(format!("banner.{port}"), banner.to_string());
                    h.identity
                        .insert(format!("svc.{port}"), "unidentified".to_string());
                    h
                };
                let hosts = vec![
                    host(
                        "10.20.0.7",
                        "Kronos Automation",
                        9999,
                        "KRONOS-GW 2.1 ready",
                    ),
                    host(
                        "10.20.0.8",
                        "Kronos Automation",
                        9999,
                        "KRONOS-GW 2.1 ready",
                    ),
                    host(
                        "10.20.0.9",
                        "Kronos Automation",
                        9999,
                        "KRONOS-GW 3.0.4 ready",
                    ),
                    host(
                        "10.20.0.10",
                        "Kronos Automation",
                        9999,
                        "KRONOS-GW 2.0 ready",
                    ),
                    host("10.20.0.11", "", 7000, "KRONOS-GW 3.0.4 ready"),
                    host(
                        "10.20.0.76",
                        "Hallprint",
                        2000,
                        "HALLPRINT queue empty, 12 pages",
                    ),
                    host(
                        "10.20.0.78",
                        "Hallprint",
                        2000,
                        "HALLPRINT queue empty, 40 pages",
                    ),
                ];
                let snapshot = store::Snapshot {
                    sent: vec![],
                    targets: self.targets.clone(),
                    complete: true,
                    settings: Default::default(),
                    hosts,
                    observations: vec![],
                    notes: Default::default(),
                };
                let groups = crate::service::workbench::groups(&[snapshot]);
                let first = groups.first().map(|g| g.id.clone());
                let second = groups.get(1).map(|g| g.id.clone());
                self.workbench.open = true;
                let token = self.workbench.request();
                self.workbench.loaded(
                    token,
                    Ok(Box::new(workbench::GroupsData { groups, scans: 4 })),
                );
                if let Some(id) = first {
                    self.workbench.select(&id);
                    if state == "workbench-compare" {
                        self.workbench.compare_with(second.as_deref());
                    } else if let Some((token, group)) = self.workbench.ask_draft() {
                        self.workbench.show_end = state == "workbench-draft";
                        let id = group.id.clone();
                        self.workbench
                            .drafted(token, id, workbench::make_draft(&group));
                    }
                }
            }
            "scan-details" => {
                // The inventory window with the scan on screen and its provenance stamp (the
                // hashes are those of the rules this build carries, not of the user's files).
                self.history_open = true;
                self.loaded_scan = Some(9);
                self.scan_scope = self.targets.clone();
                self.scan_settings = windows::settings_for_scan(&self.saved.settings);
                self.history = [(9, 12), (8, 12), (7, 11)]
                    .iter()
                    .map(|&(id, hosts)| store::Entry {
                        id,
                        timestamp: 1_790_000_000 - (9 - id) * 86_400,
                        targets: self.targets.clone(),
                        complete: true,
                        hosts,
                    })
                    .collect();
            }
            "findings" => self.findings_open = true,
            "devices" => self.devices_open = true,
            "settings" => {
                // The CVE rules field with a load error, as after a bad path.
                self.settings_open = true;
                self.saved.cves_file = r"C:\rules\plant-cves.json".into();
                self.cves_error =
                    r#"C:\rules\plant-cves.json: bad version "abc" in rule lab-1"#.into();
            }
            "ot" => {
                self.capture_open = true;
                self.ot.demo();
            }
            "timeline" => {
                // The details of a PLC and its timeline, from invented history (never the
                // user's inventory).
                let host = self.results[1].clone();
                self.selected = Some(host.ip);
                self.open_timeline(&host);
                let event = |scan_id, days: i64, kind, detail: &str| crate::devices::HistoryEvent {
                    scan_id,
                    timestamp: 1_790_000_000 + days * 86_400,
                    kind,
                    detail: detail.into(),
                };
                if let Some(t) = self.timeline.as_mut() {
                    t.result = Some(Ok(Box::new(crate::devices::DeviceHistory {
                        query: t.query.clone(),
                        key: "mac",
                        first_seen: Some(1_790_000_000),
                        first_scan: Some(3),
                        last_seen: Some(1_790_000_000 + 21 * 86_400),
                        last_scan: Some(9),
                        sightings: 6,
                        scans: 7,
                        ips: vec![host.ip],
                        macs: vec![host.mac.clone()],
                        hostnames: vec![host.hostname.clone()],
                        open_tcp: vec![21, 102, 502],
                        events: vec![
                            event(3, 0, "first-seen", &format!("{} ({})", host.ip, host.mac)),
                            event(5, 7, "port-opened", "TCP 21 open (not in scan #3)"),
                            event(
                                5,
                                7,
                                "finding-appeared",
                                "HIGH FTP sends credentials in clear text (ftp-cleartext) on port 21",
                            ),
                            event(7, 14, "hostname-changed", "plc-line-1 → plc-line-1a"),
                            event(
                                9,
                                21,
                                "port-closed",
                                "TCP 23 no longer observed open (open in scan #7)",
                            ),
                            event(
                                9,
                                21,
                                "finding-resolved",
                                "HIGH Telnet exposes credentials in clear text (telnet-open) on port 23",
                            ),
                        ],
                    })));
                }
            }
            "script" => {
                self.selected = Some(self.results[1].ip);
                let source = r#"fn on_host(h) {
                    h.set("owner", "automation");
                    if h.has_port(23) { h.finding("high", "telnet", "Telnet on a PLC", "port 23"); }
                    h.note("checked by demo");
                }"#;
                let outcome =
                    crate::script::Scripts::from_sources(&[("policy.rhai".into(), source.into())])
                        .map(|s| s.dry_run(&self.results[1]));
                self.script_test = Some(ScriptTest {
                    token: 0,
                    ip: self.results[1].ip,
                    path: "policy.rhai".into(),
                    result: Some(outcome),
                });
            }
            _ => {}
        }
    }

    /// "What changed" for the demo network: invented, never read from the inventory.
    fn demo_home(&self) -> home::HomeData {
        use crate::changes::{
            ChangedDevice, Changes, DeviceChange, DeviceRef, RiskChange, ScanRef, Summary,
        };
        let device = |h: &scan::Host, baseline: Option<bool>| DeviceRef {
            key: h.mac.clone(),
            label: if h.hostname.is_empty() {
                h.ip.to_string()
            } else {
                h.hostname.clone()
            },
            ips: vec![h.ip],
            mac: h.mac.clone(),
            vendor: h.identity.get("mac.vendor").cloned().unwrap_or_default(),
            device_type: h.identity.get("device.type").cloned().unwrap_or_default(),
            hostnames: vec![h.hostname.clone()],
            in_baseline: baseline,
        };
        let r = &self.results;
        let snapshot = store::Snapshot {
            sent: vec![],
            targets: String::new(),
            complete: true,
            settings: Default::default(),
            hosts: r.clone(),
            observations: vec![],
            notes: Default::default(),
        };
        let mut findings = risk::analyze_snapshot(&snapshot);
        decorate_findings(&mut findings);
        let risk_of = |f: &risk::Finding| RiskChange {
            device_key: None,
            finding: f.clone(),
        };
        let new_risks: Vec<RiskChange> = findings
            .iter()
            .filter(|f| f.severity >= risk::Severity::Medium)
            .take(4)
            .map(risk_of)
            .collect();
        let resolved: Vec<RiskChange> = findings
            .iter()
            .filter(|f| f.severity <= risk::Severity::Low)
            .take(2)
            .map(risk_of)
            .collect();
        let day = 86_400;
        let changes = Changes {
            since: "last".into(),
            now: 1_790_000_000 + 30 * day,
            current: Some(ScanRef {
                id: 9,
                timestamp: 1_790_000_000 + 29 * day,
                targets: "10.20.0.0/24".into(),
                hosts: r.len(),
            }),
            previous: Some(ScanRef {
                id: 8,
                timestamp: 1_790_000_000 + 22 * day,
                targets: "10.20.0.0/24".into(),
                hosts: r.len() - 2,
            }),
            notice: None,
            summary: Summary {
                new_devices: 2,
                gone_devices: 1,
                changed_devices: 2,
                new_risks: new_risks.len(),
                resolved_risks: resolved.len(),
                unconfirmed_risks: 1,
            },
            new_devices: vec![device(&r[11], Some(false)), device(&r[10], Some(false))],
            gone_devices: vec![DeviceRef {
                key: "00:11:22:33:44:55".into(),
                label: "old-plotter".into(),
                ips: vec!["10.20.0.93".parse().unwrap()],
                mac: "00:11:22:33:44:55".into(),
                vendor: "HP".into(),
                device_type: "Printer".into(),
                hostnames: vec![],
                in_baseline: Some(true),
            }],
            changed_devices: vec![
                ChangedDevice {
                    device: device(&r[1], Some(true)),
                    changes: vec![
                        DeviceChange {
                            kind: "port-opened",
                            detail: "TCP 21 open (not in the previous scan)".into(),
                        },
                        DeviceChange {
                            kind: "hostname",
                            detail: "hostname plc-line-1 changed to plc-line-1a".into(),
                        },
                    ],
                    more: 0,
                },
                ChangedDevice {
                    device: device(&r[6], Some(true)),
                    changes: vec![DeviceChange {
                        kind: "identity",
                        detail: "nginx 1.14.0 changed to 1.18.0".into(),
                    }],
                    more: 0,
                },
            ],
            new_risks,
            resolved_risks: resolved,
            unconfirmed_risks: vec![risk_of(&findings[findings.len() - 1])],
            unknown_devices: Some(2),
        };
        home::HomeData {
            changes,
            assessment: crate::score::assess(&findings, 5),
            scans: 9,
        }
    }
}
