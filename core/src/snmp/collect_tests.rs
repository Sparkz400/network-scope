use super::*;
use crate::{
    sendlog::PacketKind,
    snmp::{
        AuthProto, Credentials, PrivProto, UsmUser,
        testagent::{Agent, V3Agent, lab_mib, oid},
    },
};
use std::sync::atomic::Ordering;

fn config(credentials: Credentials, agent: std::net::SocketAddr) -> SnmpConfig {
    SnmpConfig {
        credentials,
        port: agent.port(),
    }
}
fn community(version: Version, text: &str, agent: std::net::SocketAddr) -> SnmpConfig {
    config(
        Credentials::Community {
            version,
            community: text.into(),
        },
        agent,
    )
}
fn ip() -> IpAddr {
    "127.0.0.1".parse().unwrap()
}
fn only_reads(agent: &Agent) {
    let seen = agent.received.lock().unwrap();
    assert!(!seen.is_empty());
    assert!(
        seen.iter().all(|t| [0xA0, 0xA1, 0xA5].contains(t)),
        "{seen:02x?}"
    );
}

fn check_lab_result(c: &Collected) {
    assert_eq!(
        c.system.descr, "Lab Switch 24G, firmware 3.1.4 (c) Lab",
        "control characters are removed"
    );
    assert_eq!(c.system.object_id, "1.3.6.1.4.1.9.1.1208");
    assert_eq!(c.system.name, "core-sw1");
    assert_eq!(c.system.location, "Rack 4");
    assert_eq!(c.system.uptime_ticks, Some(13_163_000));
    assert_eq!(c.interfaces.len(), 3);
    assert_eq!(
        c.interfaces[0],
        Interface {
            index: 1,
            descr: "GigabitEthernet1/0/1".into(),
            mac: "00:1B:21:0A:0B:01".into(),
            status: "up".into()
        }
    );
    assert_eq!(c.interfaces[1].status, "down");
    assert_eq!(c.addresses.len(), 2);
    assert_eq!(c.addresses[0].ip.to_string(), "10.0.0.2");
    assert_eq!(
        (c.addresses[0].if_index, c.addresses[0].mask.as_str()),
        (3, "255.255.255.0")
    );
    assert_eq!(c.addresses[1].mask, "255.255.255.128");
    assert_eq!(c.lldp.len(), 2);
    assert_eq!(
        c.lldp[0],
        LldpNeighbor {
            local_port: 1,
            sys_name: "dist-sw2".into(),
            port_id: "Gi0/24".into(),
            chassis_id: "00:1B:21:77:00:01".into(),
            port_desc: "Gi0/24 uplink".into(),
            local_port_desc: "GigabitEthernet1/0/1".into(),
        }
    );
    assert_eq!(
        (
            c.lldp[1].local_port,
            c.lldp[1].sys_name.as_str(),
            c.lldp[1].chassis_id.as_str()
        ),
        (2, "lab-ap", "52:54:00:12:34:56")
    );
}

#[tokio::test]
async fn v2c_collects_system_interfaces_addresses_and_lldp() {
    let (addr, agent) = Agent::community("lab-community").spawn().await;
    let gate = Gate::unlimited();
    let c = collect(
        ip(),
        &community(Version::V2c, "lab-community", addr),
        false,
        1000,
        &gate,
    )
    .await
    .unwrap();
    check_lab_result(&c);
    assert!(c.notes.is_empty(), "{:?}", c.notes);
    assert_eq!(c.version, "v2c");
    assert!(c.engine_id.is_none());
    only_reads(&agent);
    // bounded and gated: every datagram is in the sent log under its label
    assert!(
        c.requests > 5 && c.requests <= MAX_REQUESTS,
        "{}",
        c.requests
    );
    let sent = gate.log().snapshot();
    assert_eq!(sent.iter().map(|e| e.count).sum::<u64>(), c.requests as u64);
    assert!(sent.iter().all(|e| e.kind == PacketKind::SnmpRequest));
    let allowed = crate::snmp::catalog(Version::V2c);
    assert!(sent.iter().all(|e| allowed.contains(&e.detail)), "{sent:?}");
    assert!(
        sent.iter()
            .any(|e| e.detail == "SNMPv2c: GetBulkRequest (PDU 0xA5)")
    );
}

#[tokio::test]
async fn v1_uses_getnext_only_and_falls_back_when_an_object_is_missing() {
    let mut agent = Agent::community("old");
    // sysLocation missing: v1 answers noSuchName for the whole Get
    agent.mib.remove(&oid("1.3.6.1.2.1.1.6.0"));
    let (addr, agent) = agent.spawn().await;
    let gate = Gate::unlimited();
    let c = collect(
        ip(),
        &community(Version::V1, "old", addr),
        false,
        1000,
        &gate,
    )
    .await
    .unwrap();
    assert_eq!(c.system.name, "core-sw1");
    assert_eq!(c.system.location, "");
    assert_eq!(c.interfaces.len(), 3);
    assert_eq!(c.lldp.len(), 2);
    let seen = agent.received.lock().unwrap().clone();
    assert!(
        seen.iter().all(|t| [0xA0, 0xA1].contains(t)),
        "SNMPv1 has no GetBulk: {seen:02x?}"
    );
    assert!(seen.contains(&0xA1));
    let allowed = crate::snmp::catalog(Version::V1);
    assert!(
        gate.log()
            .snapshot()
            .iter()
            .all(|e| allowed.contains(&e.detail))
    );
}

#[tokio::test]
async fn a_wrong_community_or_a_silent_host_is_an_error_not_a_guess() {
    let (addr, agent) = Agent::community("right").spawn().await;
    let gate = Gate::unlimited();
    let e = collect(
        ip(),
        &community(Version::V2c, "wrong", addr),
        false,
        300,
        &gate,
    )
    .await
    .unwrap_err();
    assert!(e.contains("no SNMP reply"), "{e}");
    // exactly one request with two attempts: no other community is tried
    assert_eq!(agent.count.load(Ordering::SeqCst), 2);
    let sent = gate.log().snapshot();
    assert_eq!(sent.iter().map(|e| e.count).sum::<u64>(), 2);
    // no agent at all
    let free = std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    assert!(
        collect(
            ip(),
            &community(Version::V2c, "x", free),
            false,
            300,
            &Gate::unlimited()
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn tables_are_bounded() {
    let mut agent = Agent::community("big");
    for n in 4..=400 {
        agent.mib.insert(
            oid(&format!("1.3.6.1.2.1.2.2.1.2.{n}")),
            Value::Octets(format!("port{n}").into_bytes()),
        );
    }
    let (addr, _) = agent.spawn().await;
    let gate = Gate::unlimited();
    let c = collect(
        ip(),
        &community(Version::V2c, "big", addr),
        false,
        1000,
        &gate,
    )
    .await
    .unwrap();
    assert_eq!(c.interfaces.len(), MAX_INTERFACES);
    assert!(
        c.notes.iter().any(|n| n.contains("stopped after 128 rows")),
        "{:?}",
        c.notes
    );
    assert!(c.requests <= MAX_REQUESTS);
    // Safe Mode: smaller pages, so more requests for the same rows, within its own limit
    let safe = collect(
        ip(),
        &community(Version::V2c, "big", addr),
        true,
        1000,
        &Gate::unlimited(),
    )
    .await
    .unwrap();
    assert_eq!(safe.interfaces.len(), MAX_INTERFACES);
    assert!(
        safe.requests > c.requests && safe.requests <= SAFE_MAX_REQUESTS,
        "{} vs {}",
        safe.requests,
        c.requests
    );
}

#[tokio::test]
async fn the_request_budget_ends_a_walk_with_a_note() {
    let mut agent = Agent::community("big");
    for n in 4..=1000 {
        agent.mib.insert(
            oid(&format!("1.3.6.1.2.1.2.2.1.2.{n}")),
            Value::Octets(vec![b'x'; 40]),
        );
        agent.mib.insert(
            oid(&format!("1.3.6.1.2.1.2.2.1.6.{n}")),
            Value::Octets(vec![1; 6]),
        );
    }
    let (addr, _) = agent.spawn().await;
    let c = collect(
        ip(),
        &community(Version::V2c, "big", addr),
        true,
        1000,
        &Gate::unlimited(),
    )
    .await
    .unwrap();
    assert!(c.requests <= SAFE_MAX_REQUESTS, "{}", c.requests);
    assert!(!c.interfaces.is_empty());
}

#[tokio::test]
async fn v3_levels_collect_the_same_data_and_report_the_engine_id() {
    type Level = (Option<(AuthProto, &'static str)>, Option<&'static str>);
    let cases: Vec<Level> = vec![
        (None, None),
        (Some((AuthProto::Sha1, "authpass-1234")), None),
        (Some((AuthProto::Sha256, "authpass-1234")), None),
        (
            Some((AuthProto::Sha1, "authpass-1234")),
            Some("privpass-5678"),
        ),
        (
            Some((AuthProto::Sha256, "authpass-1234")),
            Some("privpass-5678"),
        ),
    ];
    for (auth, privacy) in cases {
        let (addr, agent) = Agent::v3(V3Agent::new("monitor", auth, privacy))
            .spawn()
            .await;
        let user = UsmUser {
            name: "monitor".into(),
            auth: auth.map(|(p, s)| (p, s.into())),
            privacy: privacy.map(|s| (PrivProto::Aes128, s.into())),
        };
        let level = user.level();
        let c = collect(
            ip(),
            &config(Credentials::V3(user), addr),
            false,
            1000,
            &Gate::unlimited(),
        )
        .await
        .unwrap_or_else(|e| panic!("{level} {auth:?}: {e}"));
        check_lab_result(&c);
        assert_eq!(
            c.engine_id.as_deref(),
            Some(
                &[
                    0x80, 0, 0x1f, 0x88, 0x80, 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 1
                ][..]
            )
        );
        assert!(
            c.version.starts_with(&format!("v3 {level}")),
            "{}",
            c.version
        );
        let id = c.identity();
        assert_eq!(id["snmp.engine_id"], "80001f8880deadbeef00000001");
        only_reads(&agent);
    }
}

#[tokio::test]
async fn v3_wrong_passwords_users_and_levels_fail_with_a_reason() {
    let (addr, _) = Agent::v3(V3Agent::new(
        "monitor",
        Some((AuthProto::Sha1, "authpass-1234")),
        Some("privpass-5678"),
    ))
    .spawn()
    .await;
    let run = |user: &str, auth: &str, privacy: &str| {
        let user = UsmUser {
            name: user.into(),
            auth: Some((AuthProto::Sha1, auth.into())),
            privacy: Some((PrivProto::Aes128, privacy.into())),
        };
        let config = config(Credentials::V3(user), addr);
        async move { collect(ip(), &config, false, 500, &Gate::unlimited()).await }
    };
    let e = run("monitor", "wrong-auth-pass", "privpass-5678")
        .await
        .unwrap_err();
    assert!(e.contains("authentication"), "{e}");
    let e = run("nobody", "authpass-1234", "privpass-5678")
        .await
        .unwrap_err();
    assert!(e.contains("unknown SNMPv3 user"), "{e}");
    let e = run("monitor", "authpass-1234", "wrong-priv-pass")
        .await
        .unwrap_err();
    assert!(e.contains("privacy") || e.contains("decryption"), "{e}");
    // the agent wants auth, the client offers none
    let user = UsmUser {
        name: "monitor".into(),
        auth: None,
        privacy: None,
    };
    let e = collect(
        ip(),
        &config(Credentials::V3(user), addr),
        false,
        500,
        &Gate::unlimited(),
    )
    .await
    .unwrap_err();
    assert!(e.contains("security level"), "{e}");
}

#[tokio::test]
async fn v3_adopts_the_agents_clock_once_when_the_request_was_late() {
    let v3 = V3Agent::new("monitor", Some((AuthProto::Sha256, "authpass-1234")), None);
    v3.reject_first_as_late.store(true, Ordering::SeqCst);
    let (addr, _) = Agent::v3(v3).spawn().await;
    let user = UsmUser {
        name: "monitor".into(),
        auth: Some((AuthProto::Sha256, "authpass-1234".into())),
        privacy: None,
    };
    let c = collect(
        ip(),
        &config(Credentials::V3(user), addr),
        false,
        1000,
        &Gate::unlimited(),
    )
    .await
    .unwrap();
    check_lab_result(&c);
}

#[test]
fn identity_keys_for_the_inventory() {
    let c = Collected {
        version: "v3 authPriv SHA-256 AES-128".into(),
        engine_id: Some(vec![0x80, 0, 0x1f, 0x88, 0x80, 1]),
        system: System {
            descr: "Lab Switch".into(),
            object_id: "1.3.6.1.4.1.9.1.1".into(),
            name: "sw".into(),
            location: String::new(),
            uptime_ticks: Some(8_640_000 + 360_000 + 100),
        },
        interfaces: vec![Interface {
            index: 2,
            descr: "Gi1/0/2".into(),
            mac: "00:11:22:33:44:55".into(),
            status: "up".into(),
        }],
        addresses: vec![Address {
            ip: "10.0.0.2".parse().unwrap(),
            if_index: 2,
            mask: "255.255.255.0".into(),
        }],
        lldp: vec![LldpNeighbor {
            local_port: 2,
            sys_name: "peer".into(),
            port_id: "Gi0/1".into(),
            chassis_id: "00:AA:BB:CC:DD:EE".into(),
            port_desc: String::new(),
            local_port_desc: "Gi1/0/2".into(),
        }],
        ..Default::default()
    };
    let id = c.identity();
    assert_eq!(id["snmp.sysdescr"], "Lab Switch");
    assert_eq!(id["snmp.engine_id"], "80001f888001");
    assert!(
        !id.contains_key("snmp.uptime"),
        "a value that changes in every scan is not identity"
    );
    assert_eq!(id["snmp.lldp.0.local_port_desc"], "Gi1/0/2");
    assert_eq!(id["snmp.if.2"], "Gi1/0/2; 00:11:22:33:44:55; up");
    assert_eq!(id["snmp.ip.10.0.0.2"], "ifIndex 2, mask 255.255.255.0");
    assert_eq!(id["snmp.lldp.0.sys_name"], "peer");
    assert!(!id.contains_key("snmp.location") && !id.contains_key("snmp.lldp.0.port_desc"));
    // identity.rs reads the engine ID as a strong identifier
    let ids = crate::identity::identifiers("", &[], &[], &id, &Default::default());
    assert!(
        ids.iter()
            .any(|i| i.kind == crate::identity::Kind::SnmpEngineId && i.value == "80001f888001"),
        "{ids:?}"
    );
}

#[test]
fn device_text_is_sanitised() {
    assert_eq!(clean(b"a\x00b\x1b[31m\r\nc   d"), "a b [31m c d");
    assert_eq!(clean(&vec![b'x'; 1000]).len(), MAX_TEXT);
    assert_eq!(
        lldp_id(Some(4), 4, &[0, 0x1b, 0x21, 1, 2, 3]),
        "00:1B:21:01:02:03"
    );
    assert_eq!(lldp_id(Some(5), 4, b"ge-0/0/1"), "ge-0/0/1");
    assert_eq!(lldp_id(Some(7), 4, &[0xff, 0xfe, 0x01]), "fffe01");
    assert_eq!(lldp_id(None, 4, &[1, 2, 3, 4, 5, 6]), "01:02:03:04:05:06");
    assert_eq!(mac_text(&[]), "");
    assert_eq!(oper_status(99), "?");
    assert!(!lab_mib().is_empty());
}
