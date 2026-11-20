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
    let planned = plan(&s).unwrap();
    assert!(
        planned
            .keys()
            .contains(&(PacketKind::Ipv6Echo, DETAIL.to_string()))
    );
    assert!(plan(&Settings::default()).is_none(), "off unless asked for");
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
    let mut uni = vec![0u8; win::UNICAST_ROW * 2];
    for (n, (ip, index, dad)) in [(v6("fe80::5"), 9u32, 4u32), (v6("2001:db8::5"), 9, 4)]
        .into_iter()
        .enumerate()
    {
        let r = &mut uni[n * win::UNICAST_ROW..(n + 1) * win::UNICAST_ROW];
        r[..2].copy_from_slice(&23u16.to_le_bytes());
        r[8..24].copy_from_slice(&ip.octets());
        r[40..44].copy_from_slice(&index.to_le_bytes());
        r[64..68].copy_from_slice(&dad.to_le_bytes());
    }
    assert_eq!(
        win::parse_unicast_rows(&uni),
        [(9, v6("fe80::5"), 4), (9, v6("2001:db8::5"), 4)]
    );
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
fn only_one_function_transmits() {
    let code = include_str!("ipv6.rs")
        .split("#[cfg(test)]")
        .next()
        .unwrap();
    // the socket code is the echo and nothing else: one send_to
    assert_eq!(code.matches("send_to(").count(), 1);
    assert!(!code.contains("TcpStream") && !code.contains("UdpSocket"));
}
