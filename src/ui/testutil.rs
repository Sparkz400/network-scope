//! Helpers shared by the tests of the `ui` modules.
use crate::{passive, scan};
use std::collections::BTreeMap;

pub fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

pub fn obs(
    mac: &str,
    protocol: &str,
    ip: Option<&str>,
    field: (&str, &str),
) -> passive::Observation {
    passive::Observation {
        protocol: protocol.into(),
        mac: mac.into(),
        ip: ip.map(|i| i.parse().unwrap()),
        fields: BTreeMap::from([(field.0.to_string(), field.1.to_string())]),
    }
}

/// A responding host with a telnet banner on port 23 in its identity, with the given open ports.
pub fn tui_host(ip: &str, open: Vec<u16>) -> scan::Host {
    scan::Host {
        ip: ip.parse().unwrap(),
        responding: true,
        ping: Some(1),
        ttl: None,
        hostname: String::new(),
        mac: String::new(),
        open,
        closed: 0,
        unanswered: 0,
        errors: vec![],
        ports_checked: true,
        identity: BTreeMap::from([("svc.23".to_string(), "telnet".to_string())]),
        udp_open: vec![],
        trace: vec![],
    }
}
