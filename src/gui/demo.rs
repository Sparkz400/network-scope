//! Sample data for `--screenshot` runs, chosen with NETWORK_SCOPE_SCREENSHOT_STATE
//! (main, findings, devices, settings, ot, script, timeline; append "-small" for the default 800x450 window). Screenshot runs never save to the inventory or preferences.
use super::*;

fn demo_host(ip: &str, open: &[u16], identity: &[(&str, &str)]) -> scan::Host {
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

impl Scanner {
    pub(super) fn seed_demo(&mut self, state: &str) {
        // "-fast" renders the window with Safe Mode off (e.g. "main-small-fast").
        let state = match state.strip_suffix("-fast") {
            Some(rest) => {
                self.saved.settings.safe = false;
                rest
            }
            None => state,
        };
        self.filter = Filter::All;
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
        // "-small" keeps the default window size.
        match state.trim_end_matches("-small") {
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
}
