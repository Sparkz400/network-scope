use super::*;
use crate::scan::{Host, Settings};

const MODEL: &str = r#"{
  "zones": {
    "enterprise": ["10.0.0.0/24"],
    "dmz": ["10.0.1.0/24"],
    "control": ["10.0.2.0/24", "fd00:2::/64"],
    "safety": ["10.0.9.0/28"],
    "plc-island": ["10.0.2.128/25"]
  },
  "conduits": [
    { "from": "enterprise", "to": "dmz", "ports": ["tcp/443", "tcp/8000-8100", "icmp"] },
    { "from": "dmz", "to": "control", "ports": ["tcp/44818", "502"] }
  ]
}"#;

fn model() -> ZoneModel {
    ZoneModel::parse(MODEL.as_bytes()).unwrap()
}

fn host(ip: &str, open: &[u16], udp: &[u16], identity: &[(&str, &str)]) -> Host {
    Host {
        ip: ip.parse().unwrap(),
        responding: true,
        ping: Some(1),
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
        udp_open: udp.to_vec(),
        trace: vec![],
    }
}

fn snapshot(hosts: Vec<Host>) -> Snapshot {
    Snapshot {
        targets: "10.0.0.0/16".into(),
        complete: true,
        settings: Settings::default(),
        hosts,
        observations: vec![],
        notes: Default::default(),
        sent: vec![],
    }
}

/// The done-when of ROADMAP L71: the report lists each path that breaks the zone model.
#[test]
fn a_report_lists_each_path_that_breaks_the_zone_model() {
    let mut silent = host("10.0.2.99", &[502], &[], &[]);
    silent.responding = false;
    let s = snapshot(vec![
        // the same zone: not checked
        host("10.0.0.7", &[22, 3389], &[], &[]),
        // dmz: 443 and 8080 are allowed, 22 is not, and 161/udp is not
        host(
            "10.0.1.5",
            &[443, 22, 8080],
            &[161],
            &[("svc.22", "ssh OpenSSH 9.6")],
        ),
        // control: no conduit from the enterprise zone at all
        host("10.0.2.10", &[502, 44818], &[], &[]),
        // safety: answers, no open ports, no conduit
        host("10.0.9.3", &[], &[], &[]),
        // in no zone
        host("192.168.5.5", &[80], &[], &[]),
        // a host that did not answer is no path
        silent,
    ]);
    let r = check(&model(), "enterprise", &s, Some(4)).unwrap();
    type Row<'a> = (
        &'a str,
        &'a str,
        Option<&'a str>,
        Option<u16>,
        &'a str,
        Severity,
    );
    let list: Vec<Row> = r
        .violations
        .iter()
        .map(|v| {
            (
                v.kind.as_str(),
                v.host.as_str(),
                v.to_zone.as_deref(),
                v.port,
                v.protocol.as_str(),
                v.severity,
            )
        })
        .collect();
    assert_eq!(
        list,
        [
            // OT ports reachable without a conduit: high
            (
                "no-conduit",
                "10.0.2.10",
                Some("control"),
                None,
                "icmp",
                Severity::High
            ),
            // then by severity, with the host that is in no zone before the zoned ones
            (
                "unzoned-host",
                "192.168.5.5",
                None,
                None,
                "icmp",
                Severity::Medium
            ),
            (
                "port-not-allowed",
                "10.0.1.5",
                Some("dmz"),
                Some(22),
                "tcp",
                Severity::Medium
            ),
            (
                "port-not-allowed",
                "10.0.1.5",
                Some("dmz"),
                Some(161),
                "udp",
                Severity::Medium
            ),
            (
                "no-conduit",
                "10.0.9.3",
                Some("safety"),
                None,
                "icmp",
                Severity::Medium
            ),
        ],
        "{r:#?}"
    );
    assert_eq!(
        (r.hosts_reachable, r.hosts_in_other_zones, r.unzoned_hosts),
        (5, 3, 1)
    );
    assert_eq!(r.reachable_per_zone["enterprise"], 1);
    assert_eq!(r.scan_id, Some(4));
    let ssh = r.violations.iter().find(|v| v.port == Some(22)).unwrap();
    assert_eq!(ssh.service, "ssh OpenSSH 9.6");
    assert!(
        ssh.message.contains("enterprise -> dmz") && ssh.message.contains("does not allow"),
        "{}",
        ssh.message
    );
    let control = r.violations.iter().find(|v| v.host == "10.0.2.10").unwrap();
    assert!(
        control.message.contains("open: tcp/502, tcp/44818"),
        "{}",
        control.message
    );
    let text = r.text();
    assert!(text.contains("5 paths break the model"), "{text}");
    assert!(text.contains("[HIGH] no-conduit"), "{text}");
    assert!(text.contains("Note: A scan is one vantage point"), "{text}");
}

#[test]
fn the_same_scan_from_another_zone_gives_another_answer() {
    let s = snapshot(vec![
        host("10.0.2.10", &[502, 44818, 22], &[], &[]),
        host("10.0.0.7", &[22], &[], &[]),
    ]);
    // from the dmz the conduit allows the two industrial ports, not ssh; the enterprise host
    // has no conduit from the dmz
    let r = check(&model(), "dmz", &s, None).unwrap();
    let kinds: Vec<(&str, &str, Option<u16>)> = r
        .violations
        .iter()
        .map(|v| (v.kind.as_str(), v.host.as_str(), v.port))
        .collect();
    assert_eq!(
        kinds,
        [
            ("port-not-allowed", "10.0.2.10", Some(22)),
            ("no-conduit", "10.0.0.7", None),
        ]
        .map(|(k, h, p)| (k, h, p)),
        "{r:#?}"
    );
    // a conduit that allows everything leaves nothing to report
    let open = ZoneModel::parse(
        br#"{"zones":{"a":["10.0.0.0/24"],"b":["10.0.2.0/24"]},"conduits":[{"from":"a","to":"b","ports":["any"]}]}"#,
    )
    .unwrap();
    let r = check(
        &open,
        "a",
        &snapshot(vec![host("10.0.2.10", &[1, 65535], &[9], &[])]),
        None,
    )
    .unwrap();
    assert!(r.violations.is_empty());
    assert!(r.text().contains("Every reachable path"));
}

#[test]
fn the_longest_prefix_decides_the_zone() {
    let m = model();
    assert_eq!(m.zone_of("10.0.2.10".parse().unwrap()), Some("control"));
    assert_eq!(
        m.zone_of("10.0.2.200".parse().unwrap()),
        Some("plc-island"),
        "/25 inside the /24"
    );
    assert_eq!(m.zone_of("fd00:2::9".parse().unwrap()), Some("control"));
    assert_eq!(m.zone_of("fd00:3::9".parse().unwrap()), None);
    assert_eq!(m.zone_of("10.1.0.1".parse().unwrap()), None);
    // an IPv6 address never matches an IPv4 range and the other way round
    assert!(
        !Cidr::parse("0.0.0.0/0")
            .unwrap()
            .contains("::1".parse().unwrap())
    );
    assert!(
        Cidr::parse("0.0.0.0/0")
            .unwrap()
            .contains("8.8.8.8".parse().unwrap())
    );
    assert!(
        Cidr::parse("::/0")
            .unwrap()
            .contains("fe80::1".parse().unwrap())
    );
    assert!(
        Cidr::parse("10.0.0.5")
            .unwrap()
            .contains("10.0.0.5".parse().unwrap())
    );
    assert!(
        !Cidr::parse("10.0.0.5")
            .unwrap()
            .contains("10.0.0.6".parse().unwrap())
    );
    assert!(
        Cidr::parse("10.0.0.255/24")
            .unwrap()
            .contains("10.0.0.1".parse().unwrap()),
        "host bits are ignored"
    );
}

#[test]
fn port_specs_parse_and_match() {
    use PortSpec::*;
    assert_eq!(PortSpec::parse("443").unwrap(), Ports("tcp", 443, 443));
    assert_eq!(PortSpec::parse("UDP/161").unwrap(), Ports("udp", 161, 161));
    assert_eq!(
        PortSpec::parse("tcp/8000-8100").unwrap(),
        Ports("tcp", 8000, 8100)
    );
    assert_eq!(PortSpec::parse("udp/any").unwrap(), Ports("udp", 0, 65535));
    assert_eq!(PortSpec::parse(" icmp ").unwrap(), Icmp);
    assert_eq!(PortSpec::parse("*").unwrap(), Any);
    for bad in [
        "",
        "tcp/0",
        "tcp/70000",
        "tcp/9-1",
        "sctp/1",
        "tcp/",
        "tcp/a",
        "icmp/1",
    ] {
        assert!(PortSpec::parse(bad).is_err(), "{bad:?}");
    }
    let range = PortSpec::parse("tcp/8000-8100").unwrap();
    assert!(range.allows("tcp", Some(8000)) && range.allows("tcp", Some(8100)));
    assert!(!range.allows("tcp", Some(8101)) && !range.allows("udp", Some(8050)));
    assert!(!range.allows("icmp", None));
    assert!(Icmp.allows("icmp", None) && !Icmp.allows("tcp", Some(80)));
    assert!(Any.allows("udp", Some(1)));
}

#[test]
fn a_bad_model_is_refused_with_the_reason() {
    for (bad, why) in [
        ("", "not JSON"),
        ("[]", "\"zones\""),
        (r#"{"zones":{}}"#, "between 1 and"),
        (r#"{"zones":{"a":"10.0.0.0/24"}}"#, "list of CIDR"),
        (r#"{"zones":{"a":[]}}"#, "no ranges"),
        (r#"{"zones":{"a":["10.0.0.0/33"]}}"#, "0-32"),
        (r#"{"zones":{"a":["nope"]}}"#, "not an address range"),
        (r#"{"zones":{"":["10.0.0.0/24"]}}"#, "usable zone name"),
        (
            r#"{"zones":{"a":["10.0.0.0/24"],"b":["10.0.0.0/24"]}}"#,
            "both declare",
        ),
        (
            r#"{"zones":{"a":["10.0.0.0/24"]},"conduits":{}}"#,
            "must be a list",
        ),
        (
            r#"{"zones":{"a":["10.0.0.0/24"]},"conduits":[{"from":"a","to":"b","ports":["80"]}]}"#,
            "undeclared zone",
        ),
        (
            r#"{"zones":{"a":["10.0.0.0/24"]},"conduits":[{"from":"a","to":"a"}]}"#,
            "non-empty list",
        ),
        (
            r#"{"zones":{"a":["10.0.0.0/24"]},"conduits":[{"from":"a","to":"a","ports":["x"]}]}"#,
            "is not a port",
        ),
        (
            r#"{"zones":{"a":["10.0.0.0/24"]},"conduits":[{"to":"a","ports":["80"]}]}"#,
            "missing \"from\"",
        ),
    ] {
        let e = ZoneModel::parse(bad.as_bytes()).unwrap_err();
        assert!(e.contains(why), "{bad:?}: {e}");
    }
    // a zone that overlaps another with a different prefix is fine (the longest prefix wins)
    assert!(ZoneModel::parse(br#"{"zones":{"a":["10.0.0.0/24"],"b":["10.0.0.0/25"]}}"#).is_ok());
    // the vantage zone must exist
    let e = check(&model(), "nowhere", &snapshot(vec![]), None).unwrap_err();
    assert!(
        e.contains("not a declared zone") && e.contains("enterprise"),
        "{e}"
    );
}

#[test]
fn partial_scans_say_so_and_the_file_loads() {
    let mut s = snapshot(vec![]);
    s.complete = false;
    let r = check(&model(), "enterprise", &s, None).unwrap();
    assert!(r.notes.iter().any(|n| n.contains("partial")));
    let path = std::env::temp_dir().join(format!("ns-zones-{}.json", std::process::id()));
    std::fs::write(&path, MODEL).unwrap();
    assert_eq!(ZoneModel::load(&path).unwrap(), model());
    std::fs::write(&path, "{").unwrap();
    assert!(ZoneModel::load(&path).unwrap_err().contains("not JSON"));
    let _ = std::fs::remove_file(&path);
    assert!(ZoneModel::load(&path).is_err());
}
