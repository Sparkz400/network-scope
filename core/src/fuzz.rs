//! Entry points for the cargo-fuzz targets in `fuzz/` (one per parser of untrusted bytes).
//!
//! Each function feeds arbitrary bytes to the real parser, the same way the scanner or the
//! capture reader does, and follows the result through the code that consumes it. Nothing
//! here sends traffic or touches the file system. The targets in `fuzz/fuzz_targets` are
//! one-liners calling these, so the logic is built, linted and tested with the crate, and the
//! seed corpus in `fuzz/corpus/<target>` runs as a unit test (`seed_corpus_runs_cleanly`).
use crate::{
    arp, fingerprint, jarm, nmap, nvd, osfp, ot, otpassive, passive, pcapfile, platform, risk,
    service, syn, tls, udp,
};
use std::{
    collections::{BTreeMap, HashMap},
    net::Ipv4Addr,
};

/// A fuzz target: its name (the file `fuzz/fuzz_targets/<name>.rs`) and entry point.
pub type Target = (&'static str, fn(&[u8]));

/// All fuzz targets.
pub const TARGETS: &[Target] = &[
    ("pcapfile", pcapfile),
    ("passive_decode", passive_decode),
    ("otpassive_feed", otpassive_feed),
    ("tls_flight", tls_flight),
    ("tls13_server_hello", tls13_server_hello),
    ("jarm_response", jarm_response),
    ("tls_certificate", tls_certificate),
    ("fingerprint_server_hello", fingerprint_server_hello),
    ("smb_negotiate", smb_negotiate),
    ("ntlm_challenge", ntlm_challenge),
    ("ssh_kexinit", ssh_kexinit),
    ("http_response", http_response),
    ("rdp_reply", rdp_reply),
    ("service_banner", service_banner),
    ("modbus_device_id", modbus_device_id),
    ("enip_list_identity", enip_list_identity),
    ("bacnet_iam", bacnet_iam),
    ("s7_szl", s7_szl),
    ("opcua_reply", opcua_reply),
    ("udp_dns", udp_dns),
    ("udp_ntp", udp_ntp),
    ("udp_ssdp", udp_ssdp),
    ("udp_snmp", udp_snmp),
    ("udp_netbios", udp_netbios),
    ("udp_dhcp", udp_dhcp),
    ("nmap_import", nmap_import),
    ("probes_json", probes_json),
    ("cves_json", cves_json),
    ("feeds_import", feeds_import),
    ("nvd_import", nvd_import),
    ("arp_reply", arp_reply),
    ("syn_reply", syn_reply),
    ("tcp_options", tcp_options),
    ("icmp_reply", icmp_reply),
];

/// A pcap or pcapng file, read to the end as the capture-file import does.
pub fn pcapfile(data: &[u8]) {
    let Ok(mut reader) = pcapfile::Reader::new(std::io::Cursor::new(data)) else {
        return;
    };
    while let Ok(Some((_ts, frame))) = reader.next_frame() {
        std::hint::black_box(frame);
    }
    std::hint::black_box((reader.frames(), reader.bytes_read()));
}

/// One Ethernet frame for the passive listener (ARP, LLDP, CDP, DHCP, mDNS, ...).
pub fn passive_decode(data: &[u8]) {
    std::hint::black_box(passive::decode(data));
}

/// A sequence of frames for the passive OT tracker, including TCP reassembly.
///
/// Layout: one flag byte (bit 0 turns reassembly off), an 8-byte little-endian start
/// timestamp, then records of `[length: u16 le][timestamp step: i8][frame]`. Capture-file
/// timestamps are attacker-controlled, so they are fuzzed too.
pub fn otpassive_feed(data: &[u8]) {
    let Some((head, mut rest)) = data.split_first_chunk::<9>() else {
        return;
    };
    let mut tracker = otpassive::Tracker::new();
    tracker.set_reassembly(head[0] & 1 == 0);
    let mut ts = i64::from_le_bytes(head[1..].try_into().unwrap_or_default());
    while let Some((record, tail)) = rest.split_first_chunk::<3>() {
        let len = usize::from(u16::from_le_bytes([record[0], record[1]])).min(tail.len());
        ts = ts.wrapping_add(i64::from(record[2] as i8));
        let (frame, next) = tail.split_at(len);
        tracker.feed(frame, ts);
        rest = next;
    }
    tracker.flush();
    let observations = tracker.observations();
    let assets = otpassive::assets(&observations);
    std::hint::black_box(otpassive::assets_csv(&assets));
    std::hint::black_box(otpassive::control_findings(&observations));
    std::hint::black_box(tracker.reassembly_stats());
}

/// The server's first TLS flight during cipher enumeration, then its certificate.
pub fn tls_flight(data: &[u8]) {
    std::hint::black_box(tls::has_done(data));
    if let tls::Reply::Accepted {
        cert: Some(cert), ..
    } = tls::parse_flight(data)
    {
        std::hint::black_box(tls::describe_cert(&cert).ok());
    }
}

/// An NVD CVE JSON 2.0 feed file (streamed, so only the compact records are kept), the CPE
/// lookup over what it produced, and the CPE and version parsers on the raw text.
pub fn nvd_import(data: &[u8]) {
    if let Ok(parsed) = nvd::parse_nvd(data) {
        let mut cache = nvd::Nvd::default();
        if cache.merge(parsed, "fuzz.json").is_ok() {
            std::hint::black_box(cache.lookup("cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*"));
            std::hint::black_box(cache.lookup("cpe:/a:apache:http_server:2.4.49"));
        }
    }
    if let Ok(text) = std::str::from_utf8(data) {
        std::hint::black_box(nvd::parse_cpe(text));
        std::hint::black_box(nvd::compare_versions(text, "1.0.1e"));
    }
}

/// A server's reply to a JARM probe: the ServerHello parser, the per-probe line and the hash
/// built from ten copies of it.
pub fn jarm_response(data: &[u8]) {
    let parsed = jarm::parse_response(data);
    let line = jarm::response_line(parsed.as_ref());
    let lines = vec![line; 10];
    assert!(jarm::is_jarm(&jarm::hash(&lines)));
}

/// The first handshake message of a TLS 1.3 server, and its JA4S.
pub fn tls13_server_hello(data: &[u8]) {
    if let tls::First::Hello(hello) = tls::first_server_hello(data) {
        std::hint::black_box(fingerprint::ja4s(&hello));
    }
}

/// A DER certificate as sent by a server.
pub fn tls_certificate(data: &[u8]) {
    std::hint::black_box(tls::describe_cert(data).ok());
}

/// A ServerHello body and its JA4S fingerprint.
pub fn fingerprint_server_hello(data: &[u8]) {
    if let Some(hello) = fingerprint::parse_server_hello(data) {
        std::hint::black_box(fingerprint::ja4s(&hello));
    }
}

/// An SMB negotiate reply (SMB1 or SMB2/3, NetBIOS-framed) and the fields derived from it.
pub fn smb_negotiate(data: &[u8]) {
    std::hint::black_box(service::parse_smb(data));
    std::hint::black_box(service::smb1_accepted(data));
    if let Some(n) = service::parse_smb2_negotiate(data) {
        // The clock-skew field depends on "now": derive it from the input.
        let now = i64::from_le_bytes(data.first_chunk::<8>().copied().unwrap_or_default());
        std::hint::black_box(service::smb2_fields(&n, now));
    }
}

/// An SMB2 SESSION_SETUP reply carrying an NTLM CHALLENGE message.
pub fn ntlm_challenge(data: &[u8]) {
    std::hint::black_box(service::parse_ntlm_challenge(data));
}

/// An SSH KEXINIT packet, its fields, HASSHServer and assessment.
pub fn ssh_kexinit(data: &[u8]) {
    if let Some(k) = service::parse_kexinit(data) {
        std::hint::black_box(service::kexinit_fields(&k));
    }
}

/// An HTTP response head, as plain HTTP and as HTTPS.
pub fn http_response(data: &[u8]) {
    for secure in [false, true] {
        if let Some(h) = service::parse_http(data) {
            let mut out = service::Outcome::default();
            service::http_outcome(h, secure, &mut out);
            std::hint::black_box(out);
        }
    }
}

/// An RDP X.224 Connection Confirm.
pub fn rdp_reply(data: &[u8]) {
    std::hint::black_box(service::parse_rdp_standard_reply(data));
}

/// A banner or probe reply matched against every built-in TCP and UDP probe rule.
pub fn service_banner(data: &[u8]) {
    let db = builtin_probes();
    for probe in db.probes.iter().chain(&db.udp) {
        std::hint::black_box(service::ProbeDb::identify(probe, data));
    }
}

fn builtin_probes() -> &'static service::ProbeDb {
    static DB: std::sync::OnceLock<service::ProbeDb> = std::sync::OnceLock::new();
    DB.get_or_init(service::ProbeDb::builtin)
}

/// A Modbus Read Device Identification reply (PDU after the MBAP header).
pub fn modbus_device_id(data: &[u8]) {
    std::hint::black_box(ot::parse_modbus(data).ok());
}

/// An EtherNet/IP List Identity reply.
pub fn enip_list_identity(data: &[u8]) {
    std::hint::black_box(ot::parse_list_identity(data).ok());
}

/// A BACnet/IP I-Am reply.
pub fn bacnet_iam(data: &[u8]) {
    std::hint::black_box(ot::parse_bacnet(data).ok());
}

/// An S7 SZL read reply (TPKT frame), for both SZL ids the scanner reads.
pub fn s7_szl(data: &[u8]) {
    let mut fields = BTreeMap::new();
    for (seq, id) in [(2, 0x11), (3, 0x1c)] {
        std::hint::black_box(ot::parse_szl(data, seq, id, &mut fields).ok());
    }
    std::hint::black_box(fields);
}

/// An OPC UA message body: transport error, OpenSecureChannel, GetEndpoints and
/// FindServers responses.
pub fn opcua_reply(data: &[u8]) {
    std::hint::black_box(ot::opcua::transport_error(data).ok());
    std::hint::black_box(ot::opcua::parse_open(data).ok());
    std::hint::black_box(ot::opcua::parse_endpoints(data).ok());
    std::hint::black_box(ot::opcua::parse_servers(data).ok());
}

/// A DNS reply (version.bind) and an mDNS service-discovery reply.
pub fn udp_dns(data: &[u8]) {
    std::hint::black_box(udp::parse_dns(data));
    std::hint::black_box(udp::parse_mdns(data));
}

/// An NTP reply.
pub fn udp_ntp(data: &[u8]) {
    std::hint::black_box(udp::parse_ntp(data));
}

/// An SSDP reply.
pub fn udp_ssdp(data: &[u8]) {
    std::hint::black_box(udp::parse_ssdp(data));
}

/// An SNMP GetResponse (BER).
pub fn udp_snmp(data: &[u8]) {
    std::hint::black_box(udp::parse_snmp(data));
}

/// A NetBIOS node status reply.
pub fn udp_netbios(data: &[u8]) {
    std::hint::black_box(udp::parse_netbios(data));
}

/// A DHCP ACK or OFFER; the transaction id is taken from the reply so it matches.
pub fn udp_dhcp(data: &[u8]) {
    let xid = data
        .get(4..8)
        .map_or(0, |b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
    std::hint::black_box(udp::parse_dhcp(data, xid));
    std::hint::black_box(udp::parse_offer(data, xid));
}

/// An nmap XML file: import (size cap included), then findings and re-export.
pub fn nmap_import(data: &[u8]) {
    let Ok(xml) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(snapshot) = nmap::import(xml) {
        std::hint::black_box(risk::analyze_snapshot(&snapshot));
        std::hint::black_box(nmap::export(&snapshot, 0));
    }
}

/// A user `probes.json`, merged with the built-in probes; the rules then run on the file.
pub fn probes_json(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    // The same merge as `ProbeDb::with_user_file`, on a cached copy of the built-in probes
    // (compiling their regexes for every input would make fuzzing far too slow).
    if let Ok(db) = builtin_probes().clone().merge_user(text, "probes.json") {
        for probe in db.probes.iter().chain(&db.udp) {
            std::hint::black_box(service::ProbeDb::identify(probe, data));
        }
    }
}

/// A CISA KEV catalog or an EPSS CSV (both parsers get the same bytes), followed through the
/// enrichment of a finding.
pub fn feeds_import(data: &[u8]) {
    let mut feeds = crate::feeds::Feeds::default();
    if let Ok(p) = crate::feeds::parse_kev(data) {
        feeds.kev = Some(p.data);
    }
    if let Ok(p) = crate::feeds::parse_epss(data) {
        feeds.epss = Some(p.data);
    }
    let cves = ["CVE-2021-44228".to_string(), "CVE-2023-48795".to_string()];
    std::hint::black_box(feeds.exploit_for(&cves));
}

/// A user `cves.json`, merged with the built-in rules; every rule is then evaluated.
pub fn cves_json(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(db) = risk::CveDb::with_user_text(text, "cves.json") {
        for rule in db.rules.iter().take(256) {
            for version in [rule.min.as_deref(), rule.max.as_deref()]
                .into_iter()
                .flatten()
            {
                std::hint::black_box(risk::in_range(
                    version,
                    rule.min.as_deref(),
                    rule.max.as_deref(),
                ));
                std::hint::black_box(db.cpe(&rule.product, version));
            }
        }
    }
}

/// An ARP reply; the frame's target address is taken as our own so it can match.
pub fn arp_reply(data: &[u8]) {
    let me = data.get(38..42).map_or(Ipv4Addr::UNSPECIFIED, |b| {
        Ipv4Addr::new(b[0], b[1], b[2], b[3])
    });
    std::hint::black_box(arp::parse_reply(data, me));
}

/// A captured frame answering a SYN probe (SYN-ACK with TCP options, or RST). The pending
/// probe is derived from the frame so the cookie check can pass.
pub fn syn_reply(data: &[u8]) {
    let field = |at: usize, n: usize| data.get(at..at + n);
    let ihl = data.get(14).map_or(20, |b| usize::from(b & 15) * 4);
    let (Some(src), Some(dst), Some(ports), Some(ack)) = (
        field(26, 4),
        field(30, 4),
        field(14 + ihl, 4),
        field(14 + ihl + 8, 4),
    ) else {
        std::hint::black_box(syn::classify(data, Ipv4Addr::UNSPECIFIED, &HashMap::new()));
        return;
    };
    let ip = |b: &[u8]| Ipv4Addr::new(b[0], b[1], b[2], b[3]);
    let key = (
        ip(src),
        u16::from_be_bytes([ports[0], ports[1]]),
        u16::from_be_bytes([ports[2], ports[3]]),
    );
    let cookie = u32::from_be_bytes([ack[0], ack[1], ack[2], ack[3]]).wrapping_sub(1);
    let pending = HashMap::from([(key, cookie)]);
    std::hint::black_box(syn::classify(data, ip(dst), &pending));
}

/// The TCP options of a SYN-ACK (OS fingerprint).
pub fn tcp_options(data: &[u8]) {
    std::hint::black_box(osfp::parse_options(data));
}

/// ICMP/ICMPv6 replies for ping and traceroute. Layout: the traced IPv4 destination
/// (4 bytes), identifier or source port (2), sequence or destination port (2), then the
/// packet as read from the socket.
pub fn icmp_reply(data: &[u8]) {
    let Some((head, packet)) = data.split_first_chunk::<8>() else {
        return;
    };
    let dest = Ipv4Addr::new(head[0], head[1], head[2], head[3]);
    let id = u16::from_be_bytes([head[4], head[5]]);
    let seq = u16::from_be_bytes([head[6], head[7]]);
    for v4 in [true, false] {
        std::hint::black_box(platform::parse_echo_reply(packet, v4));
    }
    std::hint::black_box(platform::parse_hop_reply(packet, dest, id, seq));
    std::hint::black_box(platform::parse_udp_hop_reply(packet, dest, id, seq));
    let dest6 = dest.to_ipv6_mapped();
    for from in [dest6, std::net::Ipv6Addr::LOCALHOST] {
        std::hint::black_box(platform::parse_hop6_reply(packet, from, dest6, id, seq));
    }
}

#[cfg(test)]
mod tests {
    use super::TARGETS;
    use std::path::Path;

    fn fuzz_dir() -> &'static Path {
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../fuzz"))
    }

    #[test]
    fn every_target_has_a_fuzz_binary_and_seeds() {
        let mut names: Vec<&str> = TARGETS.iter().map(|t| t.0).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), TARGETS.len(), "duplicate target names");
        let manifest = std::fs::read_to_string(fuzz_dir().join("Cargo.toml")).unwrap();
        let mut binaries = 0;
        for entry in std::fs::read_dir(fuzz_dir().join("fuzz_targets")).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_stem().unwrap().to_str().unwrap().to_string();
            assert!(names.contains(&name.as_str()), "{name} is not in TARGETS");
            let source = std::fs::read_to_string(&path).unwrap();
            assert!(
                source.contains(&format!("network_scope::fuzz::{name}(")),
                "{name}.rs must call its own entry point"
            );
            assert!(manifest.contains(&format!("name = \"{name}\"")), "{name}");
            binaries += 1;
        }
        assert_eq!(binaries, TARGETS.len(), "a target has no fuzz binary");
        for name in names {
            let seeds = fuzz_dir().join("corpus").join(name);
            assert!(
                std::fs::read_dir(&seeds).is_ok_and(|mut d| d.next().is_some()),
                "{name} has no seeds"
            );
        }
    }

    /// Seeds and regression inputs (crashes found by fuzzing are added to the corpus).
    #[test]
    fn seed_corpus_runs_cleanly() {
        for (name, run) in TARGETS {
            let Ok(dir) = std::fs::read_dir(fuzz_dir().join("corpus").join(name)) else {
                continue;
            };
            for entry in dir {
                let path = entry.unwrap().path();
                run(&std::fs::read(&path).unwrap());
            }
        }
    }
}
