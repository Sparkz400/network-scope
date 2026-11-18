//! Sample data for `--screenshot` runs, chosen with NETWORK_SCOPE_SCREENSHOT_STATE
//! (findings, devices, ot, script). Screenshot runs never save to the inventory or preferences.
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

impl Scanner {
    pub(super) fn seed_demo(&mut self, state: &str) {
        self.filter = Filter::All;
        self.results = vec![
            demo_host(
                "10.0.0.5",
                &[21, 23, 502],
                &[("svc.23", "telnet"), ("mac.vendor", "Siemens AG")],
            ),
            demo_host("10.0.0.7", &[80, 445], &[("svc.80", "http nginx 1.14.0")]),
            demo_host("10.0.0.9", &[3389], &[("device.type", "Workstation")]),
        ];
        self.results[0].hostname = "plc-line-1".into();
        self.recount();
        self.data_changed();
        match state {
            "findings" => self.findings_open = true,
            "devices" => self.devices_open = true,
            "ot" => {
                self.capture_open = true;
                self.ot.demo();
            }
            "script" => {
                self.selected = Some(self.results[0].ip);
                let source = r#"fn on_host(h) {
                    h.set("owner", "automation");
                    if h.has_port(23) { h.finding("high", "telnet", "Telnet on a PLC", "port 23"); }
                    h.note("checked by demo");
                }"#;
                let outcome =
                    crate::script::Scripts::from_sources(&[("policy.rhai".into(), source.into())])
                        .map(|s| s.dry_run(&self.results[0]));
                self.script_test = Some(ScriptTest {
                    token: 0,
                    ip: self.results[0].ip,
                    path: "policy.rhai".into(),
                    result: Some(outcome),
                });
            }
            _ => {}
        }
    }
}
