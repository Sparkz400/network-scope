// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
use super::*;
use std::sync::{Arc, Mutex};

fn v6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

#[test]
fn macs_are_normalised_and_junk_is_refused() {
    assert_eq!(
        normalize_mac("aa:bb:cc:dd:ee:0f").as_deref(),
        Some("AA:BB:CC:DD:EE:0F")
    );
    // BSD and macOS do not pad the bytes
    assert_eq!(
        normalize_mac("0:1b:21:a:b:c").as_deref(),
        Some("00:1B:21:0A:0B:0C")
    );
    assert_eq!(
        normalize_mac("AA-BB-CC-DD-EE-FF").as_deref(),
        Some("AA:BB:CC:DD:EE:FF")
    );
    for bad in [
        "",
        "00:00:00:00:00:00",
        "aa:bb:cc:dd:ee",
        "aa:bb:cc:dd:ee:ff:00",
        "zz:bb:cc:dd:ee:ff",
        "(incomplete)",
        "aabb:cc:dd:ee:ff:00",
    ] {
        assert_eq!(normalize_mac(bad), None, "{bad}");
    }
}

#[test]
fn linux_ip_neigh_output() {
    let text = "\
fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff router REACHABLE
2001:db8::5 dev eth0 lladdr 00:11:22:33:44:55 STALE
fe80::9 dev eth0  FAILED
fe80::a dev eth0 INCOMPLETE
ff02::1 dev eth0 lladdr 33:33:00:00:00:01 PERMANENT
fe80::b dev wlan0 lladdr 02:00:00:00:00:0b DELAY
garbage line
fe80::c dev eth0 lladdr 02:00:00:00:00:0c NOARP
";
    let n = parse_ip_neigh6(text);
    assert_eq!(
        n,
        vec![
            Neighbor {
                ip: v6("fe80::1"),
                mac: "AA:BB:CC:DD:EE:FF".into(),
                interface: "eth0".into(),
                state: State::Reachable
            },
            Neighbor {
                ip: v6("2001:db8::5"),
                mac: "00:11:22:33:44:55".into(),
                interface: "eth0".into(),
                state: State::Stale
            },
            Neighbor {
                ip: v6("fe80::b"),
                mac: "02:00:00:00:00:0B".into(),
                interface: "wlan0".into(),
                state: State::Delay
            },
        ]
    );
    assert!(
        State::Reachable.fresh()
            && State::Delay.fresh()
            && !State::Stale.fresh()
            && !State::Permanent.fresh()
    );
    assert!(parse_ip_neigh6("").is_empty());
}

#[test]
fn macos_ndp_an_output() {
    let text = "\
Neighbor                             Linklayer Address  Netif Expire    St Flgs Prbs
fe80::1%en0                          0:1b:21:aa:bb:cc   en0   23h59m50s S  R
fe80::2%en0                          (incomplete)       en0   expired   N
2001:db8::7                          a4:83:e7:1:2:3     en0   9s        R
fe80::3%en0                          a4:83:e7:1:2:4     en0   permanent R
fe80::4%lo0                          (incomplete)       lo0   expired   N
ff02::1%en0                          33:33:0:0:0:1      en0   permanent R
";
    let n = parse_ndp_an(text);
    let summary: Vec<(String, String, &str)> = n
        .iter()
        .map(|n| (n.ip.to_string(), n.mac.clone(), n.state.name()))
        .collect();
    assert_eq!(
        summary,
        [
            (
                "fe80::1".to_string(),
                "00:1B:21:AA:BB:CC".to_string(),
                "stale"
            ),
            (
                "2001:db8::7".to_string(),
                "A4:83:E7:01:02:03".to_string(),
                "reachable"
            ),
            (
                "fe80::3".to_string(),
                "A4:83:E7:01:02:04".to_string(),
                "permanent"
            ),
        ]
    );
    assert_eq!(n[0].interface, "en0");
}

#[test]
fn linux_if_inet6_and_macos_ifconfig_list_the_link_local_interfaces() {
    let text = "\
fe80000000000000021122fffe334455 02 40 20 80     eth0
20010db800000000021122fffe334455 02 40 00 80     eth0
00000000000000000000000000000001 01 80 10 80       lo
fe80000000000000aaaaaaaaaaaaaaaa 05 40 20 80  wlan0
";
    let (interfaces, local) = parse_if_inet6(text);
    assert_eq!(
        interfaces,
        [
            Interface {
                index: 2,
                name: "eth0".into()
            },
            Interface {
                index: 5,
                name: "wlan0".into()
            }
        ]
    );
    assert!(local.contains(&v6("fe80::211:22ff:fe33:4455")) && local.contains(&v6("::1")));
    let ifconfig = "\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet6 ::1 prefixlen 128
\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.5 netmask 0xffffff00
\tinet6 fe80::1c2b:3d4e:5f60:7182%en0 prefixlen 64 secured scopeid 0x4
\tinet6 2001:db8::5 prefixlen 64 autoconf secured
";
    let (interfaces, local) = parse_ifconfig_inet6(ifconfig);
    assert_eq!(
        interfaces,
        [Interface {
            index: 4,
            name: "en0".into()
        }]
    );
    assert_eq!(local.len(), 4);
}

#[test]
fn interfaces_are_selected_by_index_or_name() {
    let all: Vec<Interface> = (1..=12)
        .map(|i| Interface {
            index: i,
            name: format!("Ethernet {i}"),
        })
        .collect();
    assert_eq!(select(&all, "").len(), MAX_INTERFACES, "capped");
    assert_eq!(select(&all, "3")[0].index, 3);
    assert_eq!(select(&all, "ethernet 11")[0].index, 11);
    assert_eq!(select(&all, "wifi").len(), 0);
    assert_eq!(select(&all, "  ETHERNET 7 ").len(), 1);
}

fn host(ip: &str, mac: &str) -> Host {
    Host {
        ip: ip.parse().unwrap(),
        responding: true,
        ping: None,
        ttl: None,
        hostname: String::new(),
        mac: mac.into(),
        open: vec![],
        closed: 0,
        unanswered: 0,
        errors: vec![],
        ports_checked: true,
        identity: BTreeMap::new(),
        udp_open: vec![],
        trace: vec![],
    }
}

fn neighbor(ip: &str, mac: &str, state: State) -> Neighbor {
    Neighbor {
        ip: v6(ip),
        mac: mac.into(),
        interface: "eth0".into(),
        state,
    }
}

#[test]
fn merge_joins_by_mac_and_adds_only_what_is_fresh_and_unknown() {
    let mut hosts = vec![
        host("192.168.1.10", "00:1b:21:aa:bb:cc"),
        host("192.168.1.11", "AA:AA:AA:AA:AA:01"),
    ];
    let found = Found {
        responders: vec![
            (v6("fe80::1"), "eth0".into()),
            (v6("fe80::77"), "eth0".into()),
        ],
        neighbors: vec![
            // the first host again, by MAC (case differs), with two addresses
            neighbor(
                "fe80::211:21ff:feaa:bbcc",
                "00:1B:21:AA:BB:CC",
                State::Reachable,
            ),
            neighbor("2001:db8::10", "00:1B:21:AA:BB:CC", State::Stale),
            // a host nothing else knows, which answered the multicast: becomes a host
            neighbor("fe80::1", "02:00:00:00:00:01", State::Stale),
            neighbor("2001:db8::1", "02:00:00:00:00:01", State::Stale),
            // a stale entry nobody answered for: not a host
            neighbor("fe80::5", "02:00:00:00:00:05", State::Stale),
            // reachable per the cache, unknown: a host
            neighbor("fe80::6", "02:00:00:00:00:06", State::Reachable),
        ],
        ..Default::default()
    };
    let added = merge(&mut hosts, &found);
    assert_eq!(added, 2);
    // the IPv4 host got the addresses, global first
    assert_eq!(
        hosts[0].identity["ipv6.addresses"],
        "2001:db8::10, fe80::211:21ff:feaa:bbcc"
    );
    assert_eq!(hosts[0].identity["ipv6.source"], "neighbor cache");
    assert!(!hosts[1].identity.contains_key("ipv6.addresses"));
    // the new hosts: the best address, MAC, the evidence, no ports checked
    let new: Vec<&Host> = hosts.iter().filter(|h| h.ip.is_ipv6()).collect();
    assert_eq!(new.len(), 2);
    assert_eq!(new[0].ip.to_string(), "2001:db8::1");
    assert_eq!(new[0].mac, "02:00:00:00:00:01");
    assert_eq!(new[0].identity["ipv6.source"], "multicast echo");
    assert_eq!(new[0].identity["ipv6.addresses"], "2001:db8::1, fe80::1");
    assert!(new[0].responding && !new[0].ports_checked);
    assert_eq!(new[1].ip.to_string(), "fe80::6");
    assert!(hosts.iter().all(|h| h.mac != "02:00:00:00:00:05"));
    // running it again adds nothing (the address is already a host)
    assert_eq!(merge(&mut hosts, &found), 0);
    // and the devices view joins the IPv4 and IPv6 records of the first host by MAC
    let devices = crate::devices::merge(&hosts, &[]);
    let d = devices
        .iter()
        .find(|d| d.mac == "00:1B:21:AA:BB:CC")
        .unwrap();
    assert!(d.ips.iter().any(|i| i.is_ipv4()));
}

#[test]
fn observations_carry_mac_and_address_for_the_devices_view() {
    let found = Found {
        responders: vec![
            (v6("fe80::1"), "eth0".into()),
            (v6("fe80::99"), "eth0".into()),
        ],
        neighbors: vec![
            neighbor("fe80::1", "02:00:00:00:00:01", State::Reachable),
            neighbor("fe80::2", "02:00:00:00:00:02", State::Stale),
        ],
        ..Default::default()
    };
    let o = observations(&found);
    assert_eq!(o.len(), 3);
    assert_eq!(o[0].protocol, "IPv6 neighbor");
    assert_eq!(o[0].mac, "02:00:00:00:00:01");
    assert_eq!(o[0].fields["source"], "multicast echo and neighbor cache");
    assert_eq!(o[1].fields["source"], "neighbor cache");
    assert_eq!(o[1].fields["state"], "stale");
    // a responder without a MAC is still an observation, without one
    assert_eq!(
        (o[2].mac.as_str(), o[2].ip),
        ("", Some(IpAddr::V6(v6("fe80::99"))))
    );
    // joined to an IPv4 record by MAC
    let hosts = vec![host("192.168.1.10", "02:00:00:00:00:01")];
    let devices = crate::devices::merge(&hosts, &o);
    let d = devices
        .iter()
        .find(|d| d.mac == "02:00:00:00:00:01")
        .unwrap();
    assert!(d.ips.contains(&IpAddr::V6(v6("fe80::1"))) && d.ips.iter().any(|i| i.is_ipv4()));
}

#[test]
fn the_run_takes_one_token_per_interface_and_skips_our_own_addresses() {
    let log = Arc::new(crate::sendlog::SentLog::new());
    let s = Settings {
        ipv6_discover: true,
        safe: false,
        ..Settings::default()
    };
    let gate = gate(&s, log.clone());
    let calls = Mutex::new(vec![]);
    let os = Os {
        interfaces: &|| {
            Ok((
                vec![
                    Interface {
                        index: 3,
                        name: "Ethernet".into(),
                    },
                    Interface {
                        index: 7,
                        name: "Wi-Fi".into(),
                    },
                ],
                vec![v6("fe80::aa")],
            ))
        },
        echo: &|i, _| {
            calls.lock().unwrap().push(i.index);
            Ok(vec![
                v6("fe80::aa"),
                v6("fe80::10"),
                v6("fe80::10"),
                v6("ff02::1"),
                v6("::"),
            ])
        },
        cache: &|| {
            Ok(vec![neighbor(
                "fe80::10",
                "02:00:00:00:00:10",
                State::Stale,
            )])
        },
    };
    let found = discover_with(&s, &gate, &os);
    assert_eq!(*calls.lock().unwrap(), [3, 7]);
    assert_eq!(
        found.responders,
        [(v6("fe80::10"), "Ethernet".to_string())],
        "deduplicated, ours and multicast removed"
    );
    assert_eq!(found.interfaces.len(), 2);
    assert_eq!(found.neighbors.len(), 1);
    // the sent log has exactly the datagrams, under the plan's detail
    let sent = log.snapshot();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        (sent[0].kind, sent[0].detail.as_str(), sent[0].count),
        (PacketKind::Ipv6Echo, DETAIL, 2)
    );
    let planned = crate::plan::ipv6_discovery(&s).unwrap();
    assert!(
        planned
            .keys()
            .contains(&(PacketKind::Ipv6Echo, DETAIL.to_string()))
    );
    assert!(
        crate::plan::ipv6_discovery(&Settings::default()).is_none(),
        "off unless asked for"
    );
}

/// The step shared by `scan`, `monitor` and the desktop, with the OS replaced: one echo per
/// interface and cycle, through the gate and into the plan's detail; nothing at all when off;
/// `monitor`'s rule keeps a flapping cache entry from becoming a host.
#[test]
fn the_shared_step_sends_one_echo_per_interface_and_monitor_adds_only_answerers() {
    let make = |cache_state: State, answers: bool| {
        let echo_calls = Mutex::new(0usize);
        let s = Settings {
            ipv6_discover: true,
            ..Settings::default()
        };
        let log = Arc::new(crate::sendlog::SentLog::new());
        let hosts = vec![host("192.168.1.10", "02:00:00:00:00:01")];
        let (answered, silent) = (v6("fe80::10"), v6("fe80::20"));
        let os = Os {
            interfaces: &|| {
                Ok((
                    vec![Interface {
                        index: 3,
                        name: "Ethernet".into(),
                    }],
                    vec![],
                ))
            },
            echo: &|_, _| {
                *echo_calls.lock().unwrap() += 1;
                Ok(if answers { vec![answered] } else { vec![] })
            },
            cache: &|| {
                Ok(vec![
                    neighbor("fe80::1", "02:00:00:00:00:01", State::Reachable),
                    neighbor("fe80::10", "02:00:00:00:00:10", cache_state),
                    neighbor("fe80::20", "02:00:00:00:00:20", cache_state),
                ])
            },
        };
        let add = |mode| {
            let mut h = hosts.clone();
            let out = after_scan_with(&s, log.clone(), &mut h, mode, &os);
            (h, out)
        };
        let fresh = add(AddHosts::Fresh);
        let answered_only = add(AddHosts::Answered);
        let sent = log.snapshot();
        (
            fresh,
            answered_only,
            sent,
            *echo_calls.lock().unwrap(),
            silent,
        )
    };
    // The cache says reachable for both, and one of them answered this run's echo.
    let (fresh, answered, sent, calls, silent) = make(State::Reachable, true);
    assert_eq!(calls, 2, "one echo per interface and run (two runs here)");
    assert_eq!(sent.len(), 1);
    assert_eq!(
        (sent[0].kind, sent[0].detail.as_str(), sent[0].count),
        (PacketKind::Ipv6Echo, DETAIL, 2)
    );
    let ips = |h: &Vec<Host>| h.iter().map(|h| h.ip).collect::<Vec<_>>();
    assert_eq!(fresh.1.added, 2, "scan: both fresh neighbours become hosts");
    assert_eq!(answered.1.added, 1, "monitor: only the one that answered");
    assert!(
        ips(&answered.0).contains(&IpAddr::V6(v6("fe80::10")))
            && !ips(&answered.0).contains(&IpAddr::V6(silent)),
        "{:?}",
        ips(&answered.0)
    );
    // The silent neighbour is still in the observations, so nothing is lost.
    assert!(
        answered
            .1
            .observations
            .iter()
            .any(|o| o.ip == Some(IpAddr::V6(silent)))
    );
    // Flapping: the same cache entry stale in the next cycle adds no host in either mode, and
    // monitor's host list for the neighbour that does not answer is the same in both cycles.
    let (fresh2, answered2, _, _, _) = make(State::Stale, false);
    assert_eq!((fresh2.1.added, answered2.1.added), (0, 0));
    assert_eq!(
        ips(&answered2.0),
        ["192.168.1.10".parse::<IpAddr>().unwrap()]
    );
    // the IPv4 host got its IPv6 address either way (joined by MAC)
    assert_eq!(
        answered2.0[0].identity["ipv6.addresses"], "fe80::1",
        "{:?}",
        answered2.0[0].identity
    );
    // off: nothing is sent, nothing changes
    let log = Arc::new(crate::sendlog::SentLog::new());
    let mut hosts = vec![host("192.168.1.10", "02:00:00:00:00:01")];
    let os = Os {
        interfaces: &|| panic!("the OS must not be asked when the step is off"),
        echo: &|_, _| panic!("no echo when off"),
        cache: &|| panic!("no cache read when off"),
    };
    let out = after_scan_with(
        &Settings::default(),
        log.clone(),
        &mut hosts,
        AddHosts::Fresh,
        &os,
    );
    assert_eq!((out.added, hosts.len(), log.snapshot().len()), (0, 1, 0));
}

#[test]
fn failures_and_selection_become_notes_not_panics() {
    let gate = Gate::unlimited();
    let s = Settings {
        interface: "nonesuch".into(),
        ..Settings::default()
    };
    let sent = Mutex::new(0);
    let os = Os {
        interfaces: &|| {
            Ok((
                vec![Interface {
                    index: 2,
                    name: "eth0".into(),
                }],
                vec![],
            ))
        },
        echo: &|_, _| {
            *sent.lock().unwrap() += 1;
            Err("no".into())
        },
        cache: &|| Err("ip: not found".into()),
    };
    let found = discover_with(&s, &gate, &os);
    assert_eq!(
        *sent.lock().unwrap(),
        0,
        "no interface matched: nothing is sent"
    );
    assert!(
        found
            .notes
            .iter()
            .any(|n| n.contains("no interface matches 'nonesuch'") && n.contains("2 eth0")),
        "{:?}",
        found.notes
    );
    assert!(
        found
            .notes
            .iter()
            .any(|n| n.contains("neighbor cache: ip: not found"))
    );
    // an echo error is a note and the run goes on to the cache
    let os2 = Os {
        interfaces: &|| {
            Ok((
                vec![Interface {
                    index: 2,
                    name: "eth0".into(),
                }],
                vec![],
            ))
        },
        echo: &|_, _| Err("needs root".into()),
        cache: &|| Ok(vec![]),
    };
    let found = discover_with(&Settings::default(), &gate, &os2);
    assert!(
        found
            .notes
            .iter()
            .any(|n| n.contains("IPv6 echo on eth0: needs root"))
    );
    // no interface at all
    let os3 = Os {
        interfaces: &|| Ok((vec![], vec![])),
        echo: &|_, _| Ok(vec![]),
        cache: &|| Ok(vec![]),
    };
    assert!(
        discover_with(&Settings::default(), &gate, &os3).notes[0]
            .contains("no interface has a link-local")
    );
}

/// The Windows table layouts, on rows built to the documented offsets.
#[test]
fn windows_table_rows_decode() {
    let mut net = vec![0u8; win::NET_ROW * 3];
    let put = |rows: &mut Vec<u8>,
               n: usize,
               ip: Ipv6Addr,
               mac: [u8; 6],
               len: u32,
               state: u32,
               index: u32| {
        let r = &mut rows[n * win::NET_ROW..(n + 1) * win::NET_ROW];
        r[..2].copy_from_slice(&23u16.to_le_bytes());
        r[8..24].copy_from_slice(&ip.octets());
        r[28..32].copy_from_slice(&index.to_le_bytes());
        r[40..46].copy_from_slice(&mac);
        r[72..76].copy_from_slice(&len.to_le_bytes());
        r[76..80].copy_from_slice(&state.to_le_bytes());
    };
    put(
        &mut net,
        0,
        v6("fe80::1"),
        [0, 0x1b, 0x21, 1, 2, 3],
        6,
        5,
        12,
    );
    put(&mut net, 1, v6("fe80::2"), [0; 6], 0, 1, 12); // incomplete, no address
    put(
        &mut net,
        2,
        v6("ff02::1"),
        [0x33, 0x33, 0, 0, 0, 1],
        6,
        6,
        12,
    ); // multicast
    let n = win::parse_net_rows(&net);
    assert_eq!(
        n,
        [Neighbor {
            ip: v6("fe80::1"),
            mac: "00:1B:21:01:02:03".into(),
            interface: "12".into(),
            state: State::Reachable
        }]
    );
    // a partial trailing row is ignored
    assert_eq!(win::parse_net_rows(&net[..win::NET_ROW * 3 - 5]).len(), 1);
    let rows = [
        (v6("fe80::5"), 9u32, 4u32, 64u8),
        (v6("2001:db8::5"), 9, 4, 64),
        (v6("2001:db8::6"), 9, 1, 64), // tentative
        (v6("fd00::5"), 7, 4, 48),     // another interface
    ];
    let mut uni = vec![0u8; win::UNICAST_ROW * rows.len()];
    for (n, (ip, index, dad, prefix)) in rows.into_iter().enumerate() {
        let r = &mut uni[n * win::UNICAST_ROW..(n + 1) * win::UNICAST_ROW];
        r[..2].copy_from_slice(&23u16.to_le_bytes());
        r[8..24].copy_from_slice(&ip.octets());
        r[40..44].copy_from_slice(&index.to_le_bytes());
        r[60] = prefix;
        r[64..68].copy_from_slice(&dad.to_le_bytes());
    }
    let parsed = win::parse_unicast_rows(&uni);
    assert_eq!(
        parsed[..2],
        [(9, v6("fe80::5"), 4, 64), (9, v6("2001:db8::5"), 4, 64)]
    );
    assert_eq!(
        win::link_addresses(&parsed, 9),
        [
            LocalAddress {
                address: v6("fe80::5"),
                prefix: 64
            },
            LocalAddress {
                address: v6("2001:db8::5"),
                prefix: 64
            }
        ]
    );
}

fn link(addresses: &[(&str, u8)]) -> Link {
    Link {
        index: 3,
        name: "eth0".into(),
        addresses: addresses
            .iter()
            .map(|(a, prefix)| LocalAddress {
                address: v6(a),
                prefix: *prefix,
            })
            .collect(),
        own: vec![],
    }
}

/// The SYN engine's on-link rule: link-local targets from a link-local source, others inside an
/// on-link prefix of the interface from that address; anything else needs a route.
#[test]
fn syn_source_for_on_link_targets() {
    let l = link(&[
        ("fe80::5", 64),
        ("2001:db8:1::5", 64),
        ("2001:db8:1:0:8000::5", 65),
        ("fd00:1::5", 48),
    ]);
    let on_link = |l: &Link, t: &str| l.on_link_source(v6(t));
    assert_eq!(on_link(&l, "fe80::1"), Ok(Some(v6("fe80::5"))));
    assert_eq!(on_link(&l, "2001:db8:1::99"), Ok(Some(v6("2001:db8:1::5"))));
    // the longest matching prefix wins
    assert_eq!(
        on_link(&l, "2001:db8:1:0:8000::99"),
        Ok(Some(v6("2001:db8:1:0:8000::5")))
    );
    assert_eq!(on_link(&l, "fd00:1:0:ffff::1"), Ok(Some(v6("fd00:1::5"))));
    // outside every prefix: routed (decided by the routing table)
    assert_eq!(on_link(&l, "fd00:1:ffff::1"), Ok(None), "outside the /48");
    assert_eq!(on_link(&l, "2001:db8:2::1"), Ok(None));
    for refused in [
        "fe80::5",
        "2001:db8:1::5",
        "ff02::1",
        "::",
        "::1",
        "::ffff:10.0.0.1",
    ] {
        assert!(on_link(&l, refused).is_err(), "{refused}");
        assert!(!l.may_reach(v6(refused)), "{refused}");
    }
    // no link-local source for a link-local target
    let only_global = link(&[("2001:db8:1::5", 64)]);
    let e = on_link(&only_global, "fe80::1").unwrap_err();
    assert!(e.contains("link-local"), "{e}");
    assert!(!only_global.may_reach(v6("fe80::1")));
    assert!(on_link(&Link::default(), "fe80::1").is_err());
    // a /128 or /0 prefix makes nothing on-link
    let odd = link(&[("2001:db8:1::5", 128), ("2001:db8:2::5", 0)]);
    assert_eq!(on_link(&odd, "2001:db8:1::6"), Ok(None));
    assert_eq!(on_link(&odd, "2001:db8:3::6"), Ok(None));
    assert_eq!(l.sources().len(), 4);
    // An address of this computer that is no source (a deprecated temporary address inside the
    // on-link prefix, or one on another interface) is refused as a target too.
    let with_own = Link {
        own: vec![v6("2001:db8:1::77"), v6("fe80::77")],
        ..l.clone()
    };
    for own in ["2001:db8:1::77", "fe80::77"] {
        let e = on_link(&with_own, own).unwrap_err();
        assert!(e.contains("own address"), "{own}: {e}");
        assert!(matches!(on_link(&l, own), Ok(Some(_))), "{own}");
    }
}

/// The source of a routed target: the OS's choice when the capture filter passes it, else one
/// of the target's kind; never link-local.
#[test]
fn syn_source_for_routed_targets() {
    let l = link(&[("fe80::5", 64), ("2001:db8:1::5", 64), ("fd00:1::5", 64)]);
    let target = v6("2001:db8:9::1");
    assert_eq!(l.routed_source(target, None), Ok(v6("2001:db8:1::5")));
    assert_eq!(
        l.routed_source(v6("fd00:9::1"), None),
        Ok(v6("fd00:1::5")),
        "unique-local target, unique-local source"
    );
    // the OS's choice, when it is ours and global
    let both = link(&[("2001:db8:1::5", 64), ("2001:db8:1::6", 64)]);
    assert_eq!(
        both.routed_source(target, Some(v6("2001:db8:1::6"))),
        Ok(v6("2001:db8:1::6"))
    );
    // not ours (the filter would drop the reply), or link-local: our own choice
    for suggested in ["2001:db8:7::7", "fe80::5"] {
        assert_eq!(
            l.routed_source(target, Some(v6(suggested))),
            Ok(v6("2001:db8:1::5")),
            "{suggested}"
        );
    }
    let only_link_local = link(&[("fe80::5", 64)]);
    let e = only_link_local.routed_source(target, None).unwrap_err();
    assert!(e.contains("no global"), "{e}");
    assert!(!only_link_local.may_reach(target));
    assert!(l.may_reach(target));
    let only_ula = link(&[("fd00:1::5", 64)]);
    assert!(
        only_ula.routed_source(target, None).is_err(),
        "a unique-local source does not reach a global target"
    );
}

#[test]
fn route_answers_decide_the_next_hop() {
    let l = Link {
        own: vec![v6("2001:db8:1::77")],
        ..link(&[("fe80::5", 64), ("2001:db8:1::5", 64)])
    };
    let dest = v6("2001:db8:9::1");
    // Linux `ip -6 route get`
    let via = "2001:db8:9::1 from :: via fe80::1 dev eth0 proto ra src 2001:db8:1::5 metric 100 pref medium\n";
    assert_eq!(
        parse_ip_route_get6(via, &l, dest),
        Ok(Route6 {
            hop: Hop6::Gateway(v6("fe80::1")),
            source: Some(v6("2001:db8:1::5"))
        })
    );
    let direct =
        "2001:db8:9::1 from :: dev eth0 proto kernel src 2001:db8:1::5 metric 256 pref medium\n";
    assert_eq!(
        parse_ip_route_get6(direct, &l, dest).unwrap().hop,
        Hop6::OnLink
    );
    let other =
        "2001:db8:9::1 from :: via fe80::1 dev wlan0 proto ra src 2001:db8:5::5 metric 600\n";
    let e = parse_ip_route_get6(other, &l, dest).unwrap_err();
    assert!(e.contains("another interface"), "{e}");
    for none in [
        "",
        "unreachable 2001:db8:9::1 from :: dev lo proto kernel metric 4294967295 error -101 pref medium\n",
        "prohibit 2001:db8:9::1 from :: dev lo metric 1024\n",
        "2001:db8:9::1 from :: via fe80::1 proto ra\n",
    ] {
        assert!(parse_ip_route_get6(none, &l, dest).is_err(), "{none}");
    }
    // our own address as the gateway
    let own_gateway = "2001:db8:9::1 from :: via 2001:db8:1::77 dev eth0 metric 1\n";
    assert!(parse_ip_route_get6(own_gateway, &l, dest).is_err());
    // macOS/BSD `route -n get -inet6`
    let mac = Link {
        name: "en0".into(),
        ..l.clone()
    };
    let routed = "   route to: 2001:db8:9::1
destination: default
       mask: default
    gateway: fe80::1%en0
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>
 recvpipe  sendpipe  ssthresh  rtt,msec    mtu        weight    expire
       0         0         0         0      1500         1         0
";
    assert_eq!(
        parse_route_get6(routed, &mac, dest),
        Ok(Route6 {
            hop: Hop6::Gateway(v6("fe80::1")),
            source: None
        })
    );
    let on_link = "   route to: 2001:db8:9::1
destination: 2001:db8:9::
       mask: ffff:ffff:ffff:ffff::
    gateway: link#4
  interface: en0
      flags: <UP,DONE,CLONING>
";
    assert_eq!(
        parse_route_get6(on_link, &mac, dest).unwrap().hop,
        Hop6::OnLink
    );
    let elsewhere = routed.replace("interface: en0", "interface: utun3");
    assert!(parse_route_get6(&elsewhere, &mac, dest).is_err());
    for none in ["", "route: writing to routing socket: not in table\n"] {
        assert!(parse_route_get6(none, &mac, dest).is_err(), "{none}");
    }
    // Windows `GetBestRoute2`: the interface index decides
    assert!(route_decision(&l, dest, true, Some(Ipv6Addr::UNSPECIFIED), None).is_ok());
    assert!(route_decision(&l, dest, false, Some(v6("fe80::1")), None).is_err());
}

#[test]
fn macos_ifconfig_gives_the_capture_interface_with_prefixes() {
    let text = "\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128
\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 3c:22:fb:01:02:03
\tinet6 fe80::1c2b:3d4e:5f60:7182%en0 prefixlen 64 secured scopeid 0x4
\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255
\tinet6 2001:db8:1::5 prefixlen 64 autoconf secured
\tinet6 2001:db8:1::6 prefixlen 64 deprecated autoconf temporary
\tinet6 2001:db8:1::7 prefixlen 64 tentative
\tinet6 fd00:1::5 prefixlen 48 autoconf secured
\tnd6 options=201<PERFORMNUD,DAD>
\tstatus: active
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet6 fe80::a1b2:c3d4:e5f6:1%utun0 prefixlen 64 scopeid 0xb
";
    let l = parse_ifconfig_link(text, "en0");
    assert_eq!(l.index, 4);
    assert_eq!(
        l.addresses,
        [
            LocalAddress {
                address: v6("fe80::1c2b:3d4e:5f60:7182"),
                prefix: 64
            },
            LocalAddress {
                address: v6("2001:db8:1::5"),
                prefix: 64
            },
            LocalAddress {
                address: v6("fd00:1::5"),
                prefix: 48
            }
        ],
        "deprecated and tentative addresses are no sources"
    );
    // Every inet6 address is ours, except link-local ones of other interfaces: lo0's fe80::1 is
    // not on en0's link, where fe80::1 is often the router.
    assert_eq!(l.own.len(), 6);
    assert!(l.own.contains(&v6("2001:db8:1::6")) && l.own.contains(&v6("::1")));
    assert!(!l.own.contains(&v6("fe80::1")) && !l.own.contains(&v6("fe80::a1b2:c3d4:e5f6:1")));
    assert!(matches!(l.on_link_source(v6("fe80::1")), Ok(Some(_))));
    let utun = parse_ifconfig_link(text, "utun0");
    assert_eq!((utun.index, utun.addresses.len()), (0xb, 1));
    assert!(parse_ifconfig_link(text, "en1").addresses.is_empty());
}

/// macOS `ndp -an` as the SYN engine reads it: scoped link-local addresses, the capture
/// interface only, incomplete entries skipped.
#[test]
fn macos_ndp_gives_the_mac_on_the_capture_interface() {
    let text = "\
Neighbor                             Linklayer Address  Netif Expire    St Flgs Prbs
fe80::1%en0                          0:1b:21:a:b:c         en0 23h59m50s S  R
fe80::1%en1                          2:0:0:0:0:9           en1 10s       R  R
fe80::99%en0                         (incomplete)          en0 expired   N     1
2001:db8:1::20                       a4:83:e7:1:2:3        en0 permanent R
";
    let mac = Link {
        index: 4,
        name: "en0".into(),
        ..Link::default()
    };
    let list = parse_ndp_an(text);
    assert_eq!(
        mac_on_link(&list, v6("fe80::1"), &mac).as_deref(),
        Some("00:1B:21:0A:0B:0C")
    );
    assert_eq!(mac_on_link(&list, v6("fe80::99"), &mac), None, "incomplete");
    assert_eq!(
        mac_on_link(&list, v6("2001:db8:1::20"), &mac).as_deref(),
        Some("A4:83:E7:01:02:03")
    );
}

#[test]
fn linux_if_inet6_gives_the_capture_interface_with_prefixes() {
    let text = "\
fe800000000000000211223344556677 02 40 20 80     eth0
20010db8000100000000000000000005 02 40 00 00     eth0
20010db8000100000000000000000006 02 40 00 40     eth0
20010db8000100000000000000000007 02 40 00 08     eth0
fd000000000000000000000000000005 03 30 00 00     eth1
00000000000000000000000000000001 01 80 10 80       lo
";
    let l = parse_if_inet6_link(text, "eth0");
    assert_eq!(l.index, 2);
    assert_eq!(
        l.addresses,
        [
            LocalAddress {
                address: v6("fe80::211:2233:4455:6677"),
                prefix: 64
            },
            LocalAddress {
                address: v6("2001:db8:1::5"),
                prefix: 64
            }
        ],
        "tentative and duplicate addresses are left out"
    );
    // Every address of every interface is ours, whatever its state.
    assert_eq!(l.own.len(), 6);
    assert!(l.own.contains(&v6("2001:db8:1::6")) && l.own.contains(&v6("fd00::5")));
    let other = parse_if_inet6_link(text, "eth1");
    assert_eq!((other.index, other.addresses.len()), (3, 1));
    assert_eq!(other.addresses[0].prefix, 48);
    assert!(parse_if_inet6_link(text, "wlan0").addresses.is_empty());
    assert!(
        parse_if_inet6_link("garbage\n", "eth0")
            .addresses
            .is_empty()
    );
}

#[test]
fn neighbor_mac_is_taken_only_from_the_capture_interface() {
    let l = link(&[("fe80::5", 64)]);
    let list = [
        Neighbor {
            interface: "eth1".into(),
            ..neighbor("fe80::1", "02:00:00:00:00:01", State::Reachable)
        },
        Neighbor {
            interface: "eth0".into(),
            ..neighbor("fe80::1", "02:00:00:00:00:02", State::Stale)
        },
        Neighbor {
            interface: "3".into(),
            ..neighbor("fe80::3", "02:00:00:00:00:03", State::Reachable)
        },
    ];
    assert_eq!(
        mac_on_link(&list, v6("fe80::1"), &l).as_deref(),
        Some("02:00:00:00:00:02")
    );
    // Windows reports the interface by index
    assert_eq!(
        mac_on_link(&list, v6("fe80::3"), &l).as_deref(),
        Some("02:00:00:00:00:03")
    );
    assert_eq!(mac_on_link(&list, v6("fe80::9"), &l), None);
    let elsewhere = Link {
        index: 0,
        name: "eth2".into(),
        ..Link::default()
    };
    assert_eq!(mac_on_link(&list, v6("fe80::1"), &elsewhere), None);
}

/// What the SYN engine does on Linux and macOS, where reading the neighbour cache starts a
/// process: one read answers for every address it has and for every lookup that began before
/// it; a lookup that began later (after the kernel was asked to resolve the address) reads again.
#[test]
fn a_neighbour_table_read_is_shared_by_the_lookups_it_can_answer() {
    let l = link(&[("fe80::5", 64)]);
    let (table, reads) = (NeighborTable::default(), std::cell::Cell::new(0));
    let known = std::cell::RefCell::new(vec![
        neighbor("fe80::1", "02:00:00:00:00:01", State::Reachable),
        neighbor("fe80::2", "02:00:00:00:00:02", State::Stale),
    ]);
    let read = || {
        reads.set(reads.get() + 1);
        Some(known.borrow().clone())
    };
    let began = Instant::now();
    let later = || Instant::now() + Duration::from_secs(1);
    let mac = |ip: &str, since| table.mac(v6(ip), &l, since, read);
    assert_eq!(mac("fe80::1", began).as_deref(), Some("02:00:00:00:00:01"));
    // In the table: no further read, whenever the lookup began.
    assert_eq!(
        mac("fe80::2", later()).as_deref(),
        Some("02:00:00:00:00:02")
    );
    assert_eq!(
        mac("fe80::1", later()).as_deref(),
        Some("02:00:00:00:00:01")
    );
    // Not in it, and the lookup began before it was read: that read is the answer.
    assert_eq!(mac("fe80::9", began), None);
    assert_eq!(reads.get(), 1);
    // Began after it (the second look, after the datagram that makes the kernel ask): read again.
    assert_eq!(mac("fe80::9", later()), None);
    assert_eq!(reads.get(), 2);
    known
        .borrow_mut()
        .push(neighbor("fe80::9", "02:00:00:00:00:09", State::Reachable));
    assert_eq!(
        mac("fe80::9", later()).as_deref(),
        Some("02:00:00:00:00:09")
    );
    assert_eq!(reads.get(), 3);
    // A read that fails (the command timed out) keeps what is known, and is not repeated for
    // a lookup that waited for it.
    let failed = std::cell::Cell::new(0);
    let fail = || {
        failed.set(failed.get() + 1);
        None
    };
    assert_eq!(table.mac(v6("fe80::7"), &l, later(), fail), None);
    assert_eq!(table.mac(v6("fe80::8"), &l, began, fail), None);
    assert_eq!(failed.get(), 1);
    assert_eq!(
        mac("fe80::9", later()).as_deref(),
        Some("02:00:00:00:00:09")
    );
    assert_eq!(reads.get(), 3);
    // A table that could never be read has nothing, and is tried again by a later lookup.
    let empty = NeighborTable::default();
    assert_eq!(empty.mac(v6("fe80::1"), &l, began, fail), None);
    assert_eq!(
        empty.mac(v6("fe80::1"), &l, later(), read).as_deref(),
        Some("02:00:00:00:00:01")
    );
}

/// A system command that hangs is killed when its time is over, instead of hanging the scan.
#[test]
fn a_command_that_does_not_finish_is_killed_after_its_time_limit() {
    // Something that runs for a long time without input.
    let (slow, args): (&str, &[&str]) = if cfg!(windows) {
        ("ping", &["-n", "60", "127.0.0.1"])
    } else {
        ("sleep", &["60"])
    };
    let started = Instant::now();
    let e = run_within(slow, args, Duration::from_millis(300)).unwrap_err();
    assert!(e.contains("no answer within 300 ms"), "{e}");
    assert!(started.elapsed() < Duration::from_secs(30), "not killed");
    // One that finishes gives its output; a program that is not there is an error.
    let (shell, flag) = if cfg!(windows) {
        ("cmd", "/c")
    } else {
        ("sh", "-c")
    };
    let out = run_within(shell, &[flag, "echo ready"], Duration::from_secs(60)).unwrap();
    assert_eq!(out.trim(), "ready");
    assert!(run_within("network-scope-no-such-command", &[], RUN_TIMEOUT).is_err());
}

/// The real tables of this machine: reading them sends nothing. On Windows this checks the row
/// offsets against the OS (the addresses and MACs must look like addresses and MACs).
#[test]
fn the_real_tables_of_this_machine_decode_sensibly() {
    if let Ok((interfaces, local)) = os_interfaces() {
        for i in &interfaces {
            assert!(i.index > 0 && !i.name.is_empty(), "{i:?}");
        }
        for a in &local {
            assert!(!a.is_multicast(), "{a}");
        }
    }
    if let Ok(neighbors) = os_neighbor_cache() {
        for n in &neighbors {
            assert!(
                normalize_mac(&n.mac).is_some() && !n.ip.is_multicast(),
                "{n:?}"
            );
        }
    }
}

/// Manual check of the on-link prefix length at offset 60 of the real address table (reading
/// it sends nothing): Windows gives every link-local address a /64. It depends on the adapters
/// of the machine, so it is not run by default.
/// `cargo test -p network-scope-core --lib the_real_address_table -- --ignored`
#[cfg(windows)]
#[test]
#[ignore]
fn the_real_address_table_has_on_link_prefixes() {
    let Ok((interfaces, _)) = os_interfaces() else {
        return;
    };
    let rows = win::unicast_rows().unwrap();
    for i in interfaces {
        let addresses = win::link_addresses(&rows, i.index);
        let link_local: Vec<_> = addresses
            .iter()
            .filter(|a| is_link_local(&a.address))
            .collect();
        assert!(!link_local.is_empty(), "{i:?}: {addresses:?}");
        for a in link_local {
            assert_eq!(a.prefix, 64, "{i:?}: {a:?}");
        }
    }
}

/// Manual check of the GetBestRoute2 row offsets with this machine's own on-link prefixes
/// (table reads only, nothing is sent): a neighbour address inside the on-link prefix of one
/// of its global or unique-local addresses must route through that address's interface,
/// on-link (next hop `::`), from an address of that interface.
/// `cargo test -p network-scope-core --lib the_real_on_link_routes -- --ignored --nocapture`
#[cfg(windows)]
#[test]
#[ignore]
fn the_real_on_link_routes_decode() {
    let rows = win::unicast_rows().unwrap();
    let mut checked = 0;
    for &(index, address, dad, prefix) in &rows {
        if dad != 4 || is_link_local(&address) || !(1..128).contains(&prefix) {
            continue;
        }
        // the neighbouring address in the same prefix
        let dest = Ipv6Addr::from(u128::from(address) ^ 1);
        let (route_index, next_hop, source) = crate::platform::best_route6(dest).unwrap();
        println!(
            "prefix /{prefix} on interface {index}: route via {route_index}, next hop {next_hop}"
        );
        assert_eq!(route_index, index, "{dest}");
        assert!(next_hop.is_unspecified(), "on-link: {next_hop}");
        assert!(
            rows.iter().any(|r| r.0 == index && r.1 == source),
            "the source is an address of that interface"
        );
        checked += 1;
    }
    println!("{checked} on-link prefixes checked");
}

/// Manual check against the OS: prints what the real tables hold, to compare with
/// `Get-NetNeighbor -AddressFamily IPv6` and `ip -6 neigh`.
/// `cargo test -p network-scope-core --lib print_the_real_tables -- --ignored --nocapture`
#[test]
#[ignore]
fn print_the_real_tables() {
    println!("{:?}", os_interfaces());
    for n in os_neighbor_cache().unwrap_or_default() {
        println!("{} {} {} {}", n.ip, n.mac, n.interface, n.state.name());
    }
}

/// Manual check of the neighbour row layout including the rows `parse_net_rows` drops (the
/// permanent multicast entries have a MAC too): compare with `Get-NetNeighbor`.
#[cfg(windows)]
#[test]
#[ignore]
fn print_the_raw_neighbor_rows() {
    let rows = win::raw_net_rows().unwrap();
    for row in rows.as_chunks::<{ win::NET_ROW }>().0.iter().take(12) {
        let mac: Vec<String> = row[40..46].iter().map(|b| format!("{b:02x}")).collect();
        println!(
            "{} if={} maclen={} mac={} state={}",
            Ipv6Addr::from(<[u8; 16]>::try_from(&row[8..24]).unwrap()),
            u32::from_le_bytes(row[28..32].try_into().unwrap()),
            u32::from_le_bytes(row[72..76].try_into().unwrap()),
            mac.join("-"),
            u32::from_le_bytes(row[76..80].try_into().unwrap()),
        );
    }
}

/// Manual check of the multicast echo on every interface of this machine (sends one datagram per
/// interface to ff02::1, hop limit 1).
#[test]
#[ignore]
fn send_the_real_multicast_echo() {
    let log = Arc::new(crate::sendlog::SentLog::new());
    let s = Settings {
        ipv6_discover: true,
        port_timeout: 2000,
        ..Settings::default()
    };
    let g = gate(&s, log);
    let started = Instant::now();
    let found = discover(&s, &g);
    println!("took {:?}", started.elapsed());
    println!("interfaces {:?}", found.interfaces);
    println!("responders {:?}", found.responders);
    println!("neighbors {}", found.neighbors.len());
    println!("notes {:?}", found.notes);
}

#[test]
fn a_cache_entry_that_appears_after_the_echo_is_an_answer() {
    let s = Settings {
        ipv6_discover: true,
        ..Settings::default()
    };
    let calls = Mutex::new(0);
    let os = Os {
        interfaces: &|| {
            Ok((
                vec![Interface {
                    index: 3,
                    name: "eth0".into(),
                }],
                vec![v6("fe80::aa")],
            ))
        },
        // the ICMP API returned nothing
        echo: &|_, _| Ok(vec![]),
        cache: &|| {
            let mut n = calls.lock().unwrap();
            *n += 1;
            let mut list = vec![neighbor("fe80::1", "02:00:00:00:00:01", State::Stale)];
            if *n > 1 {
                list.push(neighbor("fe80::20", "02:00:00:00:00:20", State::Stale));
                list.push(neighbor("fe80::aa", "02:00:00:00:00:aa", State::Stale));
            }
            Ok(list)
        },
    };
    let found = discover_with(&s, &Gate::unlimited(), &os);
    // fe80::1 was there before, fe80::aa is ours: only fe80::20 is new
    assert_eq!(found.responders, [(v6("fe80::20"), "eth0".to_string())]);
    let mut hosts = vec![];
    assert_eq!(merge(&mut hosts, &found), 1);
    assert_eq!(hosts[0].ip.to_string(), "fe80::20");
    // nothing was sent without an interface: the cache is not read as answers
    let none = Os {
        interfaces: &|| Ok((vec![], vec![])),
        echo: &|_, _| Ok(vec![]),
        cache: &|| Ok(vec![neighbor("fe80::1", "02:00:00:00:00:01", State::Stale)]),
    };
    assert!(
        discover_with(&s, &Gate::unlimited(), &none)
            .responders
            .is_empty()
    );
}

#[test]
fn only_one_function_transmits() {
    let code = include_str!("ipv6.rs")
        .split("#[cfg(test)]")
        .next()
        .unwrap();
    // the socket code is the echo and nothing else: one send_to
    assert_eq!(code.matches("send_to(").count(), 1);
    assert!(!code.contains("TcpStream") && !code.contains("UdpSocket"));
}

/// The echo is paced like the scan: Safe Mode spacing, `--rate`, or nothing.
#[test]
fn the_gate_follows_safe_mode_and_the_rate() {
    let take = |g: &Gate| g.try_take_for(PacketKind::Ipv6Echo, DETAIL).is_ok();
    let log = Arc::new(crate::sendlog::SentLog::new());
    // Windows of a minute and a second: a stalled test thread does not refill them.
    let slow = Settings {
        delay: 60_000,
        ..Settings::default()
    };
    let safe = gate(&slow, log.clone());
    assert!(safe.is_safe());
    assert!(take(&safe) && !take(&safe), "one echo, then a wait");
    let rated = Settings {
        safe: false,
        max_rate: 1,
        ..Settings::default()
    };
    let g = gate(&rated, log.clone());
    assert!(!g.is_safe());
    assert!(take(&g) && !take(&g), "a burst of one at 1 per second");
    let free = Settings {
        safe: false,
        max_rate: 0,
        ..Settings::default()
    };
    let g = gate(&free, log.clone());
    assert!((0..100).all(|_| take(&g)));
    // Every echo that took a token is in the scan's sent log.
    assert_eq!(log.snapshot()[0].count, 102);
}

/// The step after a scan does nothing unless asked for, and a failed interface list is a note.
#[test]
fn after_scan_is_off_by_default_and_reports_what_it_found() {
    let log = Arc::new(crate::sendlog::SentLog::new());
    let mut hosts = vec![host("192.168.1.10", "02:00:00:00:00:01")];
    let out = after_scan(
        &Settings::default(),
        log.clone(),
        &mut hosts,
        AddHosts::Fresh,
    );
    assert_eq!((out.added, out.observations.len()), (0, 0));
    assert!(log.snapshot().is_empty() && hosts.len() == 1);
    assert_eq!(
        out.summary(),
        "IPv6: 0 interface(s), 0 answered the multicast echo, 0 neighbor(s) in the cache, 0 host(s) added"
    );
    let os = Os {
        interfaces: &|| Err("access denied".into()),
        echo: &|_, _| panic!("no interface, no echo"),
        cache: &|| Ok(vec![neighbor("fe80::7", "02:00:00:00:00:07", State::Delay)]),
    };
    let s = Settings {
        ipv6_discover: true,
        ..Settings::default()
    };
    let out = after_scan_with(&s, log, &mut hosts, AddHosts::Fresh, &os);
    assert_eq!(out.found.notes, ["IPv6 discovery: access denied"]);
    // Without an echo there is no "before" to compare with: the cache entry is no answer.
    assert!(out.found.responders.is_empty());
    assert_eq!(out.found.neighbors.len(), 1);
    assert!(
        out.summary().contains("1 neighbor(s) in the cache"),
        "{}",
        out.summary()
    );
}

#[test]
fn every_neighbour_state_is_read_and_unknown_ones_are_skipped() {
    let linux = "\
fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:01 DELAY
fe80::2 dev eth0 lladdr aa:bb:cc:dd:ee:02 PROBE
fe80::3 dev eth0 lladdr aa:bb:cc:dd:ee:03 NOARP
";
    let states: Vec<&str> = parse_ip_neigh6(linux)
        .iter()
        .map(|n| n.state.name())
        .collect();
    assert_eq!(states, ["delay", "probe"]);
    let macos = "\
Neighbor Linklayer Address Netif Expire St Flgs Prbs
fe80::1%en0 0:1b:21:aa:bb:1 en0 9s D
fe80::2%en0 0:1b:21:aa:bb:2 en0 9s P
fe80::3%en0 0:1b:21:aa:bb:3 en0 9s I
fe80::4%en0 0:1b:21:aa:bb:4 en0 9s
";
    let n = parse_ndp_an(macos);
    let states: Vec<(&str, bool)> = n
        .iter()
        .map(|n| (n.state.name(), n.state.fresh()))
        .collect();
    assert_eq!(states, [("delay", true), ("probe", true)]);
    // Lines that are not addresses are skipped, also in the interface lists.
    let (interfaces, local) = parse_if_inet6(
        "fe80000000000000000000000000001 02 40 20 80 eth0\n00000000000000000000000000000001 01 80 10 80 lo\n",
    );
    assert!(interfaces.is_empty());
    assert_eq!(local, [v6("::1")]);
    let (interfaces, local) = parse_ifconfig_inet6(
        "en0: flags=8863\n\tinet6 not-an-address prefixlen 64\n\tinet6 fe80::1%en0 prefixlen 64 scopeid 0x4\n",
    );
    assert_eq!(local, [v6("fe80::1")]);
    assert_eq!(interfaces[0].name, "en0");
}
