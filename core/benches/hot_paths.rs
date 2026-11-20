//! Criterion benchmarks of the hot paths (ROADMAP B18): pcap parsing, passive frame decode, risk
//! analysis over a 1,000-host snapshot, the diff of two such snapshots, target expansion and probe
//! matching. Nothing here touches a network. CI compares them with the base branch
//! (`scripts/bench_compare.py`, `.github/workflows/bench.yml`).
//!
//! `cargo bench -p network-scope-core` runs them; `-- --save-baseline NAME` and
//! `-- --baseline NAME` are criterion's own baseline switches.
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use network_scope_core::{
    passive, pcapfile,
    scan::{self, Host, Settings},
    service::ProbeDb,
    store::{self, IgnoreList, Snapshot},
};
use std::{collections::BTreeMap, hint::black_box};

/// An ARP request frame, one of the frames the passive decoder turns into an observation.
fn arp_frame(n: u32) -> Vec<u8> {
    let mut f = vec![0xff; 6];
    f.extend([0x02, 0, 0, 0, (n >> 8) as u8, n as u8]);
    f.extend([0x08, 0x06, 0, 1, 8, 0, 6, 4, 0, 1]);
    f.extend([0x02, 0, 0, 0, (n >> 8) as u8, n as u8]);
    f.extend([10, 0, (n >> 8) as u8, n as u8]);
    f.extend([0; 6]);
    f.extend([10, 0, 0, 1]);
    f
}

/// A classic pcap file of `count` frames.
fn pcap(count: u32) -> Vec<u8> {
    let mut out = vec![
        0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0,
    ];
    for n in 0..count {
        let frame = arp_frame(n);
        out.extend(n.to_le_bytes());
        out.extend(0u32.to_le_bytes());
        out.extend((frame.len() as u32).to_le_bytes());
        out.extend((frame.len() as u32).to_le_bytes());
        out.extend(frame);
    }
    out
}

fn host(n: u32, shift: u32) -> Host {
    let ip = std::net::Ipv4Addr::from(0x0a00_0000 + n);
    let open: Vec<u16> = match n % 4 {
        0 => vec![22, 80, 443],
        1 => vec![23, 80],
        2 => vec![445, 3389],
        _ => vec![21, 8080],
    };
    let mut identity = BTreeMap::new();
    for &p in &open {
        identity.insert(format!("svc.{p}"), format!("service on {p}"));
    }
    if n.is_multiple_of(4) {
        identity.insert("svc.22".into(), "ssh OpenSSH 7.4 (protocol 2.0)".into());
        identity.insert("svc.22.product".into(), "OpenSSH".into());
        identity.insert("svc.22.version".into(), "7.4".into());
    }
    // A few hosts differ between the two snapshots of the diff benchmark.
    let mut open = open;
    if shift > 0 && n.is_multiple_of(50) {
        open.push(8443);
        identity.insert("svc.8443".into(), "http".into());
    }
    Host {
        ip: ip.into(),
        responding: true,
        ping: Some(1),
        ttl: Some(64),
        hostname: format!("host-{n}"),
        mac: format!("02:00:00:00:{:02X}:{:02X}", (n >> 8) as u8, n as u8),
        open,
        closed: 10,
        unanswered: 0,
        errors: vec![],
        ports_checked: true,
        identity,
        udp_open: vec![],
        trace: vec![],
    }
}

fn snapshot(shift: u32) -> Snapshot {
    Snapshot {
        targets: "10.0.0.0/22".into(),
        complete: true,
        settings: Settings {
            ports: "21-23,80,443,445,3389,8080,8443".into(),
            ..Settings::default()
        },
        hosts: (0..1000).map(|n| host(n, shift)).collect(),
        observations: vec![],
        notes: BTreeMap::new(),
        sent: vec![],
    }
}

fn benches(c: &mut Criterion) {
    let file = pcap(2000);
    let mut g = c.benchmark_group("pcap");
    g.throughput(Throughput::Bytes(file.len() as u64));
    g.bench_function("parse 2000 frames", |b| {
        b.iter(|| {
            let mut reader = pcapfile::Reader::new(black_box(&file[..])).unwrap();
            let mut frames = 0u32;
            while let Some(frame) = reader.next_frame().unwrap() {
                black_box(&frame);
                frames += 1;
            }
            assert_eq!(frames, 2000);
        })
    });
    g.finish();

    let frames: Vec<Vec<u8>> = (0..2000).map(arp_frame).collect();
    assert!(passive::decode(&frames[0]).is_some(), "the frame decodes");
    let mut g = c.benchmark_group("passive");
    g.throughput(Throughput::Elements(frames.len() as u64));
    g.bench_function("decode 2000 ARP frames", |b| {
        b.iter(|| {
            for f in &frames {
                black_box(passive::decode(black_box(f)));
            }
        })
    });
    g.finish();

    let (old, new) = (snapshot(0), snapshot(1));
    c.bench_function("risk analysis, 1000 hosts", |b| {
        b.iter(|| black_box(network_scope_core::risk::analyze_snapshot(black_box(&new))))
    });
    let ignore = IgnoreList::new(&[]);
    c.bench_function("diff of two 1000-host snapshots", |b| {
        b.iter(|| black_box(store::diff_report(black_box(&old), black_box(&new), &ignore).unwrap()))
    });

    let targets = scan::parse_targets("10.0.0.0/16", true, scan::MAX_STREAM).unwrap();
    c.bench_function("target expansion, /16", |b| {
        b.iter(|| {
            let mut n = 0u32;
            for ip in targets.iter() {
                black_box(ip);
                n += 1;
            }
            assert_eq!(n, 65_534);
        })
    });
    c.bench_function("target parsing, mixed ranges", |b| {
        b.iter(|| {
            black_box(
                scan::parse_targets(
                    black_box("10.0.0.0/16 192.168.1.0/24 172.16.0.1-172.16.3.254 ::1"),
                    true,
                    scan::MAX_STREAM,
                )
                .unwrap(),
            )
        })
    });

    let db = ProbeDb::load("").unwrap();
    let banners: [&[u8]; 4] = [
        b"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n",
        b"220 mail.example.com ESMTP Postfix\r\n",
        b"220 ProFTPD 1.3.5 Server (Debian) [10.0.0.5]\r\n",
        b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\nContent-Length: 0\r\n\r\n",
    ];
    c.bench_function("probe matching, 4 banners against every probe", |b| {
        b.iter(|| {
            for banner in banners {
                for probe in &db.probes {
                    black_box(ProbeDb::identify(probe, black_box(banner)));
                }
            }
        })
    });
}

criterion_group!(hot_paths, benches);
criterion_main!(hot_paths);
