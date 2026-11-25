// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
use super::*;
use crate::{
    sendlog::PacketKind,
    snmp::{
        AuthProto, Credentials, PrivProto, SnmpRef, UsmUser,
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
            name: "Gi1/0/1".into(),
            mac: "00:1B:21:0A:0B:01".into(),
            status: "up".into()
        }
    );
    assert_eq!(c.interfaces[1].status, "down");
    assert_eq!(c.interfaces[2].name, "Vl1");
    // two IPv4 addresses (the legacy table; ipAddressTable repeats 10.0.0.2, which is not listed
    // twice and keeps the mask) and two IPv6 ones from ipAddressTable
    assert_eq!(c.addresses.len(), 4);
    assert_eq!(
        c.addresses[2],
        Address {
            ip: "2001:db8::2".parse().unwrap(),
            if_index: 3,
            mask: String::new()
        }
    );
    assert_eq!(
        c.addresses[3].ip.to_string(),
        "fe80::1",
        "the zone is dropped"
    );
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
            name: "Gi1/0/2 short".into(),
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
    assert_eq!(id["snmp.ifname.2"], "Gi1/0/2 short");
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

/// The weak pair (HMAC-MD5-96, DES-CBC) works end to end against the test agent, in every
/// combination with the other protocols; wrong passwords are refused as before.
#[tokio::test]
async fn weak_v3_levels_md5_and_des_collect_the_same_data() {
    let cases = [
        (AuthProto::Md5, None),
        (AuthProto::Md5, Some(PrivProto::Aes128)),
        (AuthProto::Md5, Some(PrivProto::Des)),
        (AuthProto::Sha1, Some(PrivProto::Des)),
        (AuthProto::Sha256, Some(PrivProto::Des)),
    ];
    for (auth, privacy) in cases {
        let v3 = V3Agent::with_privacy(
            "monitor",
            Some((auth, "authpass-1234")),
            privacy.map(|p| (p, "privpass-5678")),
        );
        let (addr, agent) = Agent::v3(v3).spawn().await;
        let user = UsmUser {
            name: "monitor".into(),
            auth: Some((auth, "authpass-1234".into())),
            privacy: privacy.map(|p| (p, "privpass-5678".into())),
        };
        let c = collect(
            ip(),
            &config(Credentials::V3(user.clone()), addr),
            false,
            1000,
            &Gate::unlimited(),
        )
        .await
        .unwrap_or_else(|e| panic!("{auth:?} {privacy:?}: {e}"));
        check_lab_result(&c);
        assert!(c.version.contains(auth.name()), "{}", c.version);
        if let Some(p) = privacy {
            assert!(c.version.contains(p.name()), "{}", c.version);
        }
        only_reads(&agent);
        // a wrong passphrase is a clear failure, not data
        let mut wrong = user;
        wrong.auth = Some((auth, "not-the-password".into()));
        let e = collect(
            ip(),
            &config(Credentials::V3(wrong), addr),
            false,
            500,
            &Gate::unlimited(),
        )
        .await
        .unwrap_err();
        assert!(e.contains("authentication"), "{e}");
        if let Some(p) = privacy {
            let wrong = UsmUser {
                name: "monitor".into(),
                auth: Some((auth, "authpass-1234".into())),
                privacy: Some((p, "not-the-priv-pass".into())),
            };
            let e = collect(
                ip(),
                &config(Credentials::V3(wrong.clone()), addr),
                false,
                500,
                &Gate::unlimited(),
            )
            .await
            .unwrap_err();
            assert!(e.contains("privacy") || e.contains("decryption"), "{e}");
        }
    }
}

#[test]
fn inet_addresses_in_the_ip_address_table_index() {
    // type 1: IPv4
    assert_eq!(
        inet_address(&[1, 4, 10, 0, 0, 2]),
        Some("10.0.0.2".parse().unwrap())
    );
    // type 2: IPv6
    let mut v6 = vec![2, 16, 0x20, 0x01, 0x0d, 0xb8];
    v6.extend([0; 11]);
    v6.push(1);
    assert_eq!(inet_address(&v6), Some("2001:db8::1".parse().unwrap()));
    // zoned: the zone is dropped
    assert_eq!(
        inet_address(&[3, 8, 192, 168, 1, 1, 0, 0, 0, 7]),
        Some("192.168.1.1".parse().unwrap())
    );
    let mut z = vec![4, 20, 0xfe, 0x80];
    z.extend([0; 13]);
    z.extend([1, 0, 0, 0, 3]);
    assert_eq!(inet_address(&z[..22]), Some("fe80::1".parse().unwrap()));
    // wrong lengths, unknown types, octets above 255, DNS names (type 16), empty
    for bad in [
        &[1u32, 4, 10, 0, 0][..],
        &[1, 4, 10, 0, 0, 2, 9],
        &[1, 5, 10, 0, 0, 2, 3],
        &[2, 16, 1, 2, 3],
        &[1, 4, 10, 0, 0, 256],
        &[16, 4, 10, 0, 0, 2],
        &[0, 4, 1, 2, 3, 4],
        &[1],
        &[],
    ] {
        assert_eq!(inet_address(bad), None, "{bad:?}");
    }
}

/// The new tables come last: with a budget too small for them the older tables are complete.
#[tokio::test]
async fn the_newer_tables_do_not_take_the_budget_of_the_older_ones() {
    let (addr, _) = Agent::community("lab-community").spawn().await;
    let gate = Gate::unlimited();
    let c = collect(
        ip(),
        &community(Version::V2c, "lab-community", addr),
        true,
        1000,
        &gate,
    )
    .await
    .unwrap();
    // Safe Mode: all of it still fits in the small budget and the pages are smaller
    assert!(c.requests <= SAFE_MAX_REQUESTS, "{}", c.requests);
    assert_eq!(c.interfaces.len(), 3);
    assert_eq!(c.addresses.len(), 4);
}

#[test]
fn weaknesses_name_the_md5_des_and_clear_text_cases() {
    let env = |name: &str| (name != "NOPE").then(|| "passphrase-1234".to_string());
    let weak = |spec: &str| SnmpConfig::v3(spec, env).unwrap().weaknesses();
    assert!(weak("u:sha256:A:aes:B").is_empty());
    assert_eq!(
        weak("u:md5:A:aes:B"),
        ["HMAC-MD5-96 authentication is weak (MD5)"]
    );
    assert_eq!(weak("u:sha:A:des:B"), ["DES privacy is weak (56-bit key)"]);
    assert_eq!(weak("u:md5:A:des:B").len(), 2);
    assert!(weak("u:sha:A")[0].contains("does not encrypt"));
    assert!(weak("u")[0].contains("noAuthNoPriv"));
    let c = SnmpConfig::community("2c", "x").unwrap();
    assert!(c.weaknesses()[0].contains("clear text"));
}

/// Runs a loopback scan with these settings (an open port makes 127.0.0.1 respond) and returns
/// the hosts and what was sent.
fn loopback_scan(
    settings: crate::scan::Settings,
) -> (Vec<crate::scan::Host>, Vec<crate::sendlog::SentEntry>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || for _ in listener.incoming() {});
    let run = crate::scan::start(
        vec![ip()],
        vec![port],
        crate::scan::Settings {
            scan_nonresponders: true,
            ping_timeout: 1000,
            port_timeout: 1000,
            retries: 0,
            probes: 1,
            delay: 0,
            ..settings
        },
    );
    let mut hosts = vec![];
    loop {
        match run
            .receiver
            .recv_timeout(std::time::Duration::from_secs(60))
            .unwrap()
        {
            crate::scan::Event::Host(h) => hosts.push(h),
            crate::scan::Event::Done => break,
            crate::scan::Event::Error(e) => panic!("{e}"),
            crate::scan::Event::Partial(_) => {}
        }
    }
    (hosts, run.sent.snapshot())
}

/// The saved form of the SNMP setting holds variable names; a secret that is in memory for the
/// run reaches neither the database file, nor its write-ahead log, nor any export.
#[test]
fn no_snmp_secret_reaches_the_database_or_any_export() {
    const AUTH: &str = "SENTINEL-auth-s3cr3t-4711";
    const PRIV: &str = "SENTINEL-priv-s3cr3t-4711";
    const COMMUNITY: &str = "SENTINEL-community-4711";
    let rt = tokio::runtime::Runtime::new().unwrap();
    for (name, agent, credentials, saved) in [
        (
            "v3",
            Agent::v3(V3Agent::new(
                "monitor",
                Some((AuthProto::Sha256, AUTH)),
                Some(PRIV),
            )),
            Credentials::V3(UsmUser {
                name: "monitor".into(),
                auth: Some((AuthProto::Sha256, AUTH.into())),
                privacy: Some((PrivProto::Aes128, PRIV.into())),
            }),
            SnmpRef::v3("monitor:sha256:NS_SNMP_AUTH:aes:NS_SNMP_PRIV").unwrap(),
        ),
        (
            "community",
            Agent::community(COMMUNITY),
            Credentials::Community {
                version: Version::V2c,
                community: COMMUNITY.into(),
            },
            SnmpRef::community("2c", "NS_SNMP_COMMUNITY").unwrap(),
        ),
    ] {
        let (addr, _) = rt.block_on(agent.spawn());
        let cfg = config(credentials, addr);
        let (hosts, sent) = loopback_scan(crate::scan::Settings {
            snmp: Some(cfg.clone()),
            snmp_ref: Some(saved.clone()),
            ..Default::default()
        });
        assert!(
            hosts[0]
                .identity
                .get("snmp.sysname")
                .is_some_and(|n| n == "core-sw1"),
            "{name}: the agent was read: {:?}",
            hosts[0].identity
        );
        assert!(sent.iter().any(|e| e.kind == PacketKind::SnmpRequest));
        let snapshot = crate::store::Snapshot {
            targets: "127.0.0.1".into(),
            complete: true,
            settings: crate::scan::Settings {
                snmp: Some(cfg),
                snmp_ref: Some(saved.clone()),
                ..Default::default()
            },
            hosts,
            observations: vec![],
            notes: Default::default(),
            sent,
        };
        let dir =
            std::env::temp_dir().join(format!("ns-snmp-secret-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("inventory.sqlite");
        let id = crate::store::save(&db, &snapshot).unwrap();
        let mut texts = vec![
            serde_json::to_string(&snapshot).unwrap(),
            crate::report::jsonl(&snapshot, 0).unwrap(),
            crate::report::markdown(&snapshot, None, 0),
            crate::report::html(&snapshot, None, 0),
            format!("{:?}", snapshot.settings),
        ];
        // every file the database writes: the main file and the write-ahead log
        let mut raw = vec![];
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            raw.push(std::fs::read(entry.path()).unwrap());
        }
        for secret in [AUTH, PRIV, COMMUNITY] {
            for t in &texts {
                assert!(!t.contains(secret), "{name}: {secret} in an export");
            }
            for bytes in &raw {
                assert!(
                    !bytes.windows(secret.len()).any(|w| w == secret.as_bytes()),
                    "{name}: {secret} in a database file"
                );
            }
        }
        // the names are saved, and come back as names
        let back = crate::store::load(&db, id).unwrap();
        assert!(back.settings.snmp.is_none());
        assert_eq!(back.settings.snmp_ref, Some(saved));
        texts.clear();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// A saved setting that cannot be resolved (the variable is not set where the scan runs) is not
/// skipped quietly: nothing is sent, and the hosts that answered say why.
#[test]
fn a_saved_setting_with_missing_variables_is_noted_and_sends_nothing() {
    let (hosts, sent) = loopback_scan(crate::scan::Settings {
        snmp_ref: Some(SnmpRef::v3("u:sha:NS_TEST_UNSET_VARIABLE_A").unwrap()),
        ..Default::default()
    });
    assert!(
        hosts[0]
            .errors
            .iter()
            .any(|e| e.contains("SNMP not read") && e.contains("NS_TEST_UNSET_VARIABLE_A")),
        "{:?}",
        hosts[0].errors
    );
    assert!(
        !sent.iter().any(|e| e.kind == PacketKind::SnmpRequest),
        "{sent:?}"
    );
}

/// The saved form resolves from the environment each time; old stored settings still load.
#[test]
fn the_saved_form_resolves_from_the_environment_and_old_settings_still_load() {
    let env = |name: &str| match name {
        "NS_COMM" => Some("lab-community".to_string()),
        "NS_AUTH" => Some("authpass-1234".to_string()),
        "NS_PRIV" => Some("privpass-5678".to_string()),
        _ => None,
    };
    let mut s = crate::scan::Settings {
        snmp_ref: Some(SnmpRef::community("2c", "NS_COMM").unwrap()),
        ..Default::default()
    };
    s.resolve_snmp(env);
    assert_eq!(s.snmp.as_ref().unwrap().version(), Version::V2c);
    assert!(s.snmp_unresolved.is_none());
    // a configuration given for this run wins and is not replaced
    let mut s2 = crate::scan::Settings {
        snmp: Some(SnmpConfig::community("1", "other").unwrap()),
        snmp_ref: Some(SnmpRef::community("2c", "NS_COMM").unwrap()),
        ..Default::default()
    };
    s2.resolve_snmp(env);
    assert_eq!(s2.snmp.unwrap().version(), Version::V1);
    // v3 from names
    let mut s3 = crate::scan::Settings {
        snmp_ref: Some(SnmpRef::v3("monitor:md5:NS_AUTH:des:NS_PRIV").unwrap()),
        ..Default::default()
    };
    s3.resolve_snmp(env);
    let Credentials::V3(u) = &s3.snmp.unwrap().credentials else {
        panic!()
    };
    assert_eq!(u.auth, Some((AuthProto::Md5, "authpass-1234".into())));
    assert_eq!(u.privacy, Some((PrivProto::Des, "privpass-5678".into())));
    // a missing variable: no SNMP, and the reason
    let mut s4 = crate::scan::Settings {
        snmp_ref: Some(SnmpRef::community("2c", "NS_MISSING").unwrap()),
        ..Default::default()
    };
    s4.resolve_snmp(env);
    assert!(s4.snmp.is_none());
    assert!(
        s4.snmp_unresolved
            .as_deref()
            .unwrap()
            .contains("NS_MISSING")
    );
    // the form is checked when it is made, a passphrase typed as a name is refused
    assert!(SnmpRef::community("2c", "my secret").is_err());
    assert!(SnmpRef::community("3", "NS_COMM").is_err());
    assert!(SnmpRef::v3("u:sha:my secret pass").is_err());
    assert!(SnmpRef::v3("u:sha").is_err());
    // what is stored: names, in a tagged form
    let json = serde_json::to_string(&s3_ref()).unwrap();
    assert_eq!(json, r#"{"v3":{"spec":"monitor:md5:NS_AUTH:des:NS_PRIV"}}"#);
    // settings saved before this field existed load with none
    let old = serde_json::to_string(&crate::scan::Settings::default()).unwrap();
    let old: serde_json::Value = serde_json::from_str(&old).unwrap();
    let mut old = old.as_object().unwrap().clone();
    old.remove("snmp_ref");
    let back: crate::scan::Settings = serde_json::from_value(old.into()).unwrap();
    assert!(back.snmp_ref.is_none() && back.snmp.is_none());
    // the summary names the variables, not their content
    assert!(s3_ref().summary().contains("authPriv"));
    assert!(
        SnmpRef::community("1", "NS_COMM")
            .unwrap()
            .summary()
            .contains("$NS_COMM")
    );
}
fn s3_ref() -> SnmpRef {
    SnmpRef::v3("monitor:md5:NS_AUTH:des:NS_PRIV").unwrap()
}

/// Interoperability with pysnmp, an independent SNMP implementation (`lab/interop`): every
/// SNMPv3 level this scanner can send, with MD5, SHA-1 and SHA-256 authentication and DES and
/// AES privacy, read from a pysnmp agent. Not run by default; `lab/interop/run_pysnmp_check.py`
/// starts the agent and this test:
///
/// `NS_PYSNMP_PORT=16161 cargo test -p network-scope-core --lib pysnmp -- --ignored --nocapture`
#[tokio::test]
#[ignore = "needs the pysnmp agent of lab/interop (NS_PYSNMP_PORT)"]
async fn pysnmp_agent_accepts_every_v3_level_and_its_replies_decode() {
    let port: u16 = std::env::var("NS_PYSNMP_PORT")
        .expect("NS_PYSNMP_PORT: the port of lab/interop/pysnmp_agent.py")
        .parse()
        .unwrap();
    let agent = std::net::SocketAddr::new(ip(), port);
    let mut failures = vec![];
    // (user, auth, privacy)
    let mut cases: Vec<(String, Option<AuthProto>, Option<PrivProto>)> =
        vec![("u-none".into(), None, None)];
    for (name, auth) in [
        ("md5", AuthProto::Md5),
        ("sha", AuthProto::Sha1),
        ("sha256", AuthProto::Sha256),
    ] {
        cases.push((format!("u-{name}"), Some(auth), None));
        for (pname, privacy) in [("aes", PrivProto::Aes128), ("des", PrivProto::Des)] {
            cases.push((format!("u-{name}-{pname}"), Some(auth), Some(privacy)));
        }
    }
    for (user, auth, privacy) in cases {
        let usm = UsmUser {
            name: user.clone(),
            auth: auth.map(|a| (a, "authpass-1234".into())),
            privacy: privacy.map(|p| (p, "privpass-5678".into())),
        };
        let level = usm.level();
        match collect(
            ip(),
            &config(Credentials::V3(usm), agent),
            false,
            2000,
            &Gate::unlimited(),
        )
        .await
        {
            Ok(c) if c.system.descr.contains("PySNMP") => {
                println!(
                    "ok   {user:<14} {level:<12} {:<28} engine {} requests {}",
                    c.version,
                    c.engine_id.as_deref().map_or(String::new(), |e| e
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect()),
                    c.requests
                );
            }
            Ok(c) => failures.push(format!("{user}: unexpected sysDescr {:?}", c.system.descr)),
            Err(e) => failures.push(format!("{user} {level}: {e}")),
        }
        // the same user with a wrong passphrase must be refused by the agent
        if let Some(a) = auth {
            let wrong = UsmUser {
                name: user.clone(),
                auth: Some((a, "not-the-password".into())),
                privacy: privacy.map(|p| (p, "privpass-5678".into())),
            };
            let r = collect(
                ip(),
                &config(Credentials::V3(wrong), agent),
                false,
                1000,
                &Gate::unlimited(),
            )
            .await;
            match r {
                Err(e) if e.contains("authentication") || e.contains("no SNMP reply") => {
                    println!("ok   {user:<14} wrong password refused: {e}");
                }
                other => failures.push(format!("{user}: wrong password gave {other:?}")),
            }
        }
    }
    for version in [Version::V2c, Version::V1] {
        let r = collect(
            ip(),
            &community(version, "lab-community", agent),
            false,
            2000,
            &Gate::unlimited(),
        )
        .await;
        match r {
            Ok(c) if c.system.descr.contains("PySNMP") => {
                println!("ok   {:<14} requests {}", version.name(), c.requests)
            }
            other => failures.push(format!("{}: {other:?}", version.name())),
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
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

/// `hrSWInstalledName` is read last, bounded, and becomes `snmp.sw.<n>` identity keys.
#[tokio::test]
async fn installed_software_is_read_last_and_bounded() {
    let mut agent = Agent::community("sw");
    for n in 1..=250 {
        agent.mib.insert(
            oid(&format!("1.3.6.1.2.1.25.6.3.1.2.{n}")),
            Value::Octets(format!("package-{n}").into_bytes()),
        );
    }
    // A duplicate name and control characters from the device.
    agent.mib.insert(
        oid("1.3.6.1.2.1.25.6.3.1.2.251"),
        Value::Octets(b"package-1".to_vec()),
    );
    let (addr, _) = agent.spawn().await;
    let gate = Gate::unlimited();
    let c = collect(
        ip(),
        &community(Version::V2c, "sw", addr),
        false,
        1000,
        &gate,
    )
    .await
    .unwrap();
    assert_eq!(c.software.len(), MAX_SOFTWARE);
    assert_eq!(c.software[0], "package-1");
    assert!(
        c.notes.iter().any(|n| n.contains("stopped after 200 rows")),
        "{:?}",
        c.notes
    );
    let id = c.identity();
    let listed: Vec<&str> = id["snmp.software"].split("; ").collect();
    assert_eq!(listed.len(), MAX_SOFTWARE);
    assert!(listed.windows(2).all(|w| w[0] <= w[1]), "sorted");
    assert!(!id.keys().any(|k| k.starts_with("snmp.sw.")));
    // The tables read before it are complete.
    assert_eq!(c.interfaces.len(), 3);
}
