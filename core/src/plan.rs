//! What a scan sends, as a plan (ROADMAP H53): the dry run lists it and sends nothing.
//!
//! The plan is not a second list kept next to the scanner. The conditions that decide *whether*
//! something is sent ([`arp_lookup`], [`icmp_echoes`], [`syn_engine`], [`udp_ports`],
//! [`ot_identification`], ...) are the functions the scan itself calls, the OT requests come from
//! the allow-lists of `ot::readonly` (`readonly::catalog`), UDP probe names from `udp::describe`,
//! and the traceroute method from `trace::plan`. Every `(kind, detail)` pair the sender records in
//! the [`SentLog`](crate::sendlog::SentLog) must appear in [`host`]'s result; a test runs a
//! loopback scan with every feature on and checks that, so a sender added without a plan entry
//! fails the build.
//!
//! This module only computes values. It opens no socket, loads no driver and sends nothing (a test
//! checks the source for that).
use crate::{
    ot::readonly,
    scan::Settings,
    sendlog::PacketKind,
    service::{self, ProbeDb},
    trace::TraceMethod,
};
use serde::Serialize;
use std::{collections::BTreeSet, net::IpAddr};

// ---- the conditions the scan itself uses ---------------------------------------------------

/// A MAC lookup (the ARP sweep or the OS neighbour table) runs for the host.
pub fn arp_lookup(s: &Settings) -> bool {
    s.arp || s.mac || s.os_detect || s.arp_sweep
}
/// The active ARP sweep engine is used (never in Safe Mode).
pub fn arp_sweep(s: &Settings) -> bool {
    s.arp_sweep && !s.safe
}
/// ICMP echo requests per host: none with `--tcp-only`, else `probes` (1 to 10).
pub fn icmp_echoes(s: &Settings) -> u32 {
    if s.tcp_only { 0 } else { s.probes.clamp(1, 10) }
}
/// The SYN engine is used for port probes (never in Safe Mode; connect scan otherwise).
pub fn syn_engine(s: &Settings) -> bool {
    s.syn && !s.safe
}
/// Ports are probed for a host: it answered something, or the user asked for silent hosts too.
pub fn probes_ports(responding: bool, s: &Settings) -> bool {
    responding || s.scan_nonresponders || s.tcp_only
}
/// Open TCP ports that get service identification: everything except industrial ports, which
/// only the dedicated read-only OT identification touches.
pub fn service_ports(ports: &[u16]) -> Vec<u16> {
    ports
        .iter()
        .copied()
        .filter(|p| !service::is_ot_port(*p))
        .collect()
}
/// Splits the UDP port list into ports the generic UDP scan may probe and industrial/printer
/// ports it never sends to (`service::is_ot_udp_port`). BACnet and the other OT protocols are
/// identified only by the dedicated read-only path (`--ot`).
pub fn udp_ports(ports: &[u16]) -> (Vec<u16>, Vec<u16>) {
    ports.iter().partition(|p| !service::is_ot_udp_port(**p))
}
/// What the IPv6 discovery (`--ipv6-discover`, `scan` and `monitor`) sends once per scan (once
/// per cycle in `monitor`): one echo per interface. `None` when it is off.
pub fn ipv6_discovery(s: &Settings) -> Option<HostPlan> {
    if !crate::ipv6::enabled(s) {
        return None;
    }
    let mut plan = HostPlan {
        packets: vec![],
        notes: vec![],
    };
    plan.push(
        PacketKind::Ipv6Echo,
        crate::ipv6::DETAIL,
        format!(
            "ff02::1 on each selected interface (at most {})",
            crate::ipv6::MAX_INTERFACES
        ),
        if s.safe {
            "once per interface, one datagram, hop limit 1; also in Safe Mode (a single echo request per interface)"
        } else {
            "once per interface, one datagram, hop limit 1"
        },
    );
    plan.notes
        .push("reading the OS neighbour cache and decoding NDP in a capture send nothing".into());
    Some(plan)
}

/// The SNMP read (`--snmp-community`, `--snmp-v3`) runs for hosts that answered something when
/// credentials were given. Safe Mode allows it (every request is a read through the rate gate)
/// with tighter limits.
pub fn snmp_read(responding: bool, s: &Settings) -> bool {
    crate::snmp::enabled(s) && responding
}
/// OT identification runs for hosts that answered something (a host with an open or closed TCP
/// port is responding, so ICMP-silent devices with OT TCP ports qualify) and, when
/// non-responders are scanned, for silent hosts too. A silent host has no open TCP port, so the
/// only probe it gets is the single BACnet Who-Is.
pub fn ot_identification(responding: bool, s: &Settings) -> bool {
    s.ot && (responding || s.scan_nonresponders)
}

// ---- the plan ------------------------------------------------------------------------------

/// One kind of packet a scan would send to a host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlannedPacket {
    pub kind: PacketKind,
    /// The detail the sent log counts it under.
    pub detail: String,
    /// Where it goes (ports, not addresses, so hosts with the same plan share it).
    pub to: String,
    /// The condition under which it is sent.
    pub when: String,
}

/// What a scan would send to one host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HostPlan {
    pub packets: Vec<PlannedPacket>,
    /// Things that are deliberately not sent (and why).
    pub notes: Vec<String>,
}

impl HostPlan {
    /// The `(kind, detail)` pairs the sent log may count for this host.
    pub fn keys(&self) -> BTreeSet<(PacketKind, String)> {
        self.packets
            .iter()
            .map(|p| (p.kind, p.detail.clone()))
            .collect()
    }
    /// Text lines for the dry run output.
    pub fn lines(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .packets
            .iter()
            .map(|p| {
                format!(
                    "{:<16} {} -> {} [{}]",
                    p.kind.name(),
                    p.detail,
                    p.to,
                    p.when
                )
            })
            .collect();
        out.extend(self.notes.iter().map(|n| format!("not sent: {n}")));
        out
    }
    fn push(&mut self, kind: PacketKind, detail: &str, to: impl Into<String>, when: &str) {
        let packet = PlannedPacket {
            kind,
            detail: detail.into(),
            to: to.into(),
            when: when.into(),
        };
        if !self.packets.contains(&packet) {
            self.packets.push(packet);
        }
    }
}

/// `22,80,443` or `1-1024,8080`: a compact port list.
pub fn ports_text(ports: &[u16]) -> String {
    let mut sorted = ports.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut out: Vec<String> = vec![];
    let mut i = 0;
    while i < sorted.len() {
        let mut j = i;
        while j + 1 < sorted.len() && sorted[j + 1] == sorted[j] + 1 {
            j += 1;
        }
        out.push(if j > i + 1 {
            format!("{}-{}", sorted[i], sorted[j])
        } else if j == i + 1 {
            format!("{},{}", sorted[i], sorted[j])
        } else {
            sorted[i].to_string()
        });
        i = j + 1;
    }
    out.join(",")
}

/// The plan for one host. `ports` are the TCP ports of the scan, `udp` the UDP port list (only
/// used with `s.udp`), `db` the service probe database (needed to name the probes of
/// `--services`; without one the probes are listed generically).
pub fn host(
    ip: IpAddr,
    ports: &[u16],
    udp: &[u16],
    s: &Settings,
    db: Option<&ProbeDb>,
) -> HostPlan {
    let mut plan = HostPlan {
        packets: vec![],
        notes: vec![],
    };
    let tcp = format!("tcp/{}", ports_text(ports));
    if s.early_stop && probes_ports(true, s) {
        plan.notes.push(
            "--early-stop: the ports listed may be probed only in part (a host whose device class becomes certain is not probed further); the ports are probed likeliest first".into(),
        );
    }
    let ports_when = if s.scan_nonresponders || s.tcp_only {
        "always"
    } else {
        "only if the host answered ping or ARP"
    };

    if arp_lookup(s) {
        if arp_sweep(s) && ip.is_ipv4() {
            plan.push(
                PacketKind::ArpRequest,
                "ARP sweep request",
                "the host's IPv4 address",
                "on-link IPv4 target; needs the capture interface",
            );
        }
        plan.push(
            PacketKind::NeighborLookup,
            "OS neighbor lookup",
            "the host",
            "unless the sweep answered; the OS may emit an ARP/NDP request, and on Linux/macOS an absent entry triggers one 1-byte UDP datagram to port 9",
        );
    }
    let echoes = icmp_echoes(s);
    if echoes > 0 {
        plan.push(
            PacketKind::IcmpEcho,
            "echo request",
            "the host",
            &format!("{echoes} per host"),
        );
    }
    // Port probes.
    let attempts = format!(
        "up to {} attempt(s) per unanswered port",
        s.retries.min(5) + 1
    );
    if syn_engine(s) {
        plan.push(
            PacketKind::TcpSyn,
            "port scan",
            &tcp,
            &format!("{ports_when}; raw SYN through the capture interface, {attempts}"),
        );
        plan.push(
            PacketKind::TcpSyn,
            "RST closing a half-open connection",
            &tcp,
            "for each open port answered with SYN-ACK",
        );
        plan.push(
            PacketKind::NeighborLookup,
            "OS neighbor lookup",
            "the next hop",
            "next-hop MAC resolution for the SYN engine",
        );
        plan.push(
            PacketKind::TcpConnect,
            "port scan",
            &tcp,
            "fallback when the SYN engine cannot start",
        );
    } else {
        plan.push(
            PacketKind::TcpConnect,
            "port scan",
            &tcp,
            &format!("{ports_when}; {attempts}"),
        );
    }

    // Service identification, per open non-OT port.
    if s.services {
        let eligible = service_ports(ports);
        let to = format!("each open port among tcp/{}", ports_text(&eligible));
        let open = "per open port";
        plan.push(
            PacketKind::TcpConnect,
            "service identification",
            &to,
            "one connection per step below (banner wait first)",
        );
        if let Some(db) = db {
            for p in &db.probes {
                let covered: Vec<u16> = p
                    .ports
                    .iter()
                    .copied()
                    .filter(|port| eligible.contains(port) && service::sends_payload(*port))
                    .collect();
                if !covered.is_empty() {
                    plan.push(
                        PacketKind::ServiceProbe,
                        &p.name,
                        format!("tcp/{}", ports_text(&covered)),
                        "until one probe identifies the service",
                    );
                }
            }
        } else {
            plan.push(
                PacketKind::ServiceProbe,
                "probes.json payloads",
                &to,
                "probes listing the port, until one identifies the service",
            );
        }
        plan.push(
            PacketKind::HttpRequest,
            "GET /",
            &to,
            "HTTP ports and as a fallback",
        );
        plan.push(
            PacketKind::TlsClientHello,
            "TLS handshake",
            &to,
            "TLS ports and as a fallback",
        );
        plan.push(
            PacketKind::TlsClientHello,
            "TLS version and cipher enumeration",
            &to,
            "ports that completed a TLS handshake",
        );
        plan.push(
            PacketKind::SshBanner,
            "SSH identification and KEXINIT",
            &to,
            "ports whose banner is SSH",
        );
        if !s.safe {
            plan.push(
                PacketKind::TlsClientHello,
                "TLS 1.3 suite enumeration",
                &to,
                "ports that completed a TLS handshake; not in Safe Mode",
            );
        }
        if crate::jarm::enabled(s) {
            plan.push(
                PacketKind::TlsClientHello,
                crate::jarm::DETAIL,
                &to,
                "ten ClientHellos per port that spoke TLS, one connection each; --jarm only, never in Safe Mode, never on industrial or printer ports",
            );
        } else if s.jarm {
            plan.notes.push(
                "JARM fingerprinting (--jarm) needs --services and leaving Safe Mode, so no JARM hellos are sent"
                    .into(),
            );
        }
        if eligible.contains(&445) {
            plan.push(PacketKind::SmbNegotiate, "SMB2 negotiate", "tcp/445", open);
            plan.push(PacketKind::SmbNegotiate, "SMB1 negotiate", "tcp/445", open);
            if !s.safe {
                plan.push(
                    PacketKind::SmbNegotiate,
                    "NTLM SESSION_SETUP (no AUTHENTICATE)",
                    "tcp/445",
                    "not in Safe Mode",
                );
            }
        }
        if eligible.contains(&3389) {
            plan.push(
                PacketKind::RdpNegotiate,
                "standard security negotiation",
                "tcp/3389",
                "when the server answers NLA",
            );
        }
        plan.notes.push(
            "printer ports (515, 9100-9107) and 2222 only get a banner wait (a connection, nothing sent); industrial ports get no generic probe"
                .into(),
        );
    }

    // UDP.
    if s.udp {
        let (scan, skipped) = udp_ports(udp);
        for port in scan {
            plan.push(
                PacketKind::UdpProbe,
                &crate::udp::describe_port(port),
                format!("udp/{port}"),
                &format!(
                    "{}; up to {} attempt(s)",
                    if s.scan_nonresponders {
                        "always"
                    } else {
                        "if the host answered"
                    },
                    (s.retries + 1).min(4)
                ),
            );
        }
        if !skipped.is_empty() {
            plan.notes.push(format!(
                "udp/{}: industrial or printer ports are never probed by the UDP scan",
                ports_text(&skipped)
            ));
        }
    }

    // SNMP with user-supplied credentials (or the saved names of the variables that hold them).
    let saved_snmp = s
        .snmp
        .clone()
        .or_else(|| s.snmp_ref.as_ref()?.resolve(|n| std::env::var(n).ok()).ok());
    if saved_snmp.is_none()
        && let Some(r) = &s.snmp_ref
    {
        plan.notes.push(format!(
            "SNMP is configured ({}) but its environment variables are not set here: no SNMP request would be sent",
            r.summary()
        ));
    }
    if let Some(config) = &saved_snmp {
        let (requests, seconds) = if s.safe {
            (
                crate::snmp::SAFE_MAX_REQUESTS,
                crate::snmp::SAFE_MAX_SECONDS,
            )
        } else {
            (crate::snmp::MAX_REQUESTS, crate::snmp::MAX_SECONDS)
        };
        for label in config.catalog() {
            plan.push(
                PacketKind::SnmpRequest,
                &label,
                format!("udp/{}", config.port),
                &format!(
                    "only if the host answered; credentials were given ({}); at most {requests} requests and {seconds} s per host, read-only: sysDescr/sysName/sysObjectID/sysUpTime, ifTable and ifName, ipAddrTable and ipAddressTable, LLDP remote table",
                    config.credentials_summary()
                ),
            );
        }
        plan.notes.push(
            "SNMP never sends a SetRequest, never tries other communities and never guesses credentials"
                .into(),
        );
    }

    // Read-only OT identification.
    if s.ot {
        let when_silent = if s.scan_nonresponders {
            "also for silent hosts"
        } else {
            "only if the host answered"
        };
        let catalog = readonly::catalog();
        for (_, port) in crate::ot::TARGETS {
            let tcp_port = catalog.iter().any(|e| e.port == port && e.tcp);
            if tcp_port {
                plan.push(
                    PacketKind::TcpConnect,
                    "OT identification",
                    format!("tcp/{port}"),
                    &if port == 1883 {
                        format!("only if tcp/{port} was found open and --services is off (with --services the MQTT service probe sends the same CONNECT)")
                    } else {
                        format!("only if tcp/{port} was found open")
                    },
                );
            }
            for e in catalog.iter().filter(|e| e.port == port) {
                let when = if e.tcp {
                    format!("only if tcp/{port} was found open")
                } else if port == 47808 {
                    when_silent.to_string()
                } else {
                    // FINS and KNX: never to a host that answered nothing
                    "only if the host answered".to_string()
                };
                plan.push(
                    PacketKind::OtRequest,
                    &e.info.label(),
                    format!("{}/{port}", if e.tcp { "tcp" } else { "udp" }),
                    &when,
                );
            }
        }
        plan.notes.push(
            "OT identification is read-only: no write, control, program or authentication request exists in the code"
                .into(),
        );
    }

    // Traceroute.
    if s.trace {
        // Any scanned port might turn out open, so those are the TCP candidates.
        let t = crate::trace::plan(ip, ports, s);
        let (detail, to, when) = match t.method {
            TraceMethod::Icmp => (
                "ICMP echo, TTL sweep",
                "the host".to_string(),
                "hosts that answered".to_string(),
            ),
            TraceMethod::Udp => (
                "UDP datagrams, TTL sweep",
                "the host (high UDP ports)".to_string(),
                "hosts that answered".to_string(),
            ),
            TraceMethod::Tcp => (
                "TCP SYN, TTL sweep",
                match t.port {
                    Some(p) => format!("tcp/{p}"),
                    None => "the first open non-OT port".to_string(),
                },
                "hosts that answered and have an open non-OT port; else ICMP".to_string(),
            ),
        };
        plan.push(PacketKind::Traceroute, detail, to, &when);
        if t.method == TraceMethod::Tcp {
            plan.push(
                PacketKind::NeighborLookup,
                "OS neighbor lookup",
                "the next hop",
                "next-hop MAC resolution for the TCP traceroute",
            );
            plan.push(
                PacketKind::TcpSyn,
                "RST closing a half-open connection",
                "the traceroute port",
                "if the target answers SYN-ACK",
            );
        }
        if t.method != TraceMethod::Icmp {
            plan.push(
                PacketKind::Traceroute,
                "ICMP echo, TTL sweep",
                "the host",
                "fallback when the TCP/UDP method cannot run",
            );
        }
        if let Some(note) = t.note {
            plan.notes.push(note);
        }
    }

    if s.dns {
        plan.push(
            PacketKind::DnsLookup,
            "reverse lookup via the system resolver",
            "the system resolver, not the host",
            "hosts that answered",
        );
    }
    plan
}

/// The dry-run plan of a whole scan: hosts with the same plan are grouped (IPv4 and IPv6 hosts
/// differ in what they get), so a /8 is described in a few lines.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Group {
    pub family: &'static str,
    pub hosts: u64,
    pub first: IpAddr,
    pub last: IpAddr,
    #[serde(flatten)]
    pub plan: HostPlan,
}

/// Plans every host of `hosts` without sending anything.
pub fn scan(
    hosts: impl Iterator<Item = IpAddr>,
    ports: &[u16],
    s: &Settings,
    db: Option<&ProbeDb>,
) -> Vec<Group> {
    let udp = crate::scan::parse_ports(&s.udp_ports).unwrap_or_default();
    let mut groups: Vec<Group> = vec![];
    for ip in hosts {
        let family = if ip.is_ipv4() { "ipv4" } else { "ipv6" };
        match groups.iter_mut().find(|g| g.family == family) {
            Some(g) => {
                g.hosts += 1;
                g.last = ip;
            }
            None => groups.push(Group {
                family,
                hosts: 1,
                first: ip,
                last: ip,
                plan: host(ip, ports, &udp, s, db),
            }),
        }
    }
    groups
}

/// Text of the dry run for the CLI.
pub fn format_scan(groups: &[Group], s: &Settings) -> String {
    let mut out = String::from("DRY RUN: nothing was sent.\n");
    out.push_str(&format!(
        "Mode: {}\n",
        if s.safe {
            "Safe Mode (8 hosts at a time, at least 100 ms between probes)"
        } else {
            "--fast"
        }
    ));
    for g in groups {
        out.push_str(&format!(
            "\n{} {} host(s), {}{}\n",
            g.family,
            g.hosts,
            g.first,
            if g.first == g.last {
                String::new()
            } else {
                format!(" ... {}", g.last)
            }
        ));
        for line in g.plan.lines() {
            out.push_str(&format!("  {line}\n"));
        }
    }
    out.trim_end().into()
}

/// The plan of `trace TARGET` (nothing is sent by planning it).
pub fn trace(ip: IpAddr, method: TraceMethod, port: Option<u16>, hops: u8) -> HostPlan {
    let mut plan = HostPlan {
        packets: vec![],
        notes: vec![],
    };
    let (detail, to) = match method {
        TraceMethod::Icmp => ("ICMP echo, TTL sweep", "the target".to_string()),
        TraceMethod::Udp => (
            "UDP datagrams, TTL sweep",
            "the target (high UDP ports)".to_string(),
        ),
        TraceMethod::Tcp => (
            "TCP SYN, TTL sweep",
            port.map_or("the target".to_string(), |p| format!("tcp/{p}")),
        ),
    };
    let when = format!(
        "TTL 1 to {}, in waves; stops once the target answers",
        hops.clamp(1, 64)
    );
    plan.push(PacketKind::Traceroute, detail, to, &when);
    if method == TraceMethod::Tcp {
        plan.push(
            PacketKind::NeighborLookup,
            "OS neighbor lookup",
            "the next hop",
            "next-hop MAC resolution",
        );
        plan.push(
            PacketKind::TcpSyn,
            "RST closing a half-open connection",
            port.map_or("the target".to_string(), |p| format!("tcp/{p}")),
            "if the target answers SYN-ACK",
        );
    }
    if ip.is_ipv6() && method != TraceMethod::Icmp {
        plan.notes.push("TCP/UDP traceroute is IPv4 only".into());
    }
    plan
}

/// The plan of `dcp` (nothing is sent by planning it).
pub fn dcp() -> HostPlan {
    let request = readonly::DcpRequest::new([0; 6], readonly::DcpService::IdentifyAll);
    let mut plan = HostPlan {
        packets: vec![],
        notes: vec!["no Set, Get, Hello, Signal or Reset: those frames cannot be built".into()],
    };
    plan.push(
        PacketKind::DcpIdentify,
        &readonly::ReadOnlyRequest::info(&request).label(),
        "the Profinet DCP multicast address 01:0E:CF:00:00:00 (layer 2)",
        "once, at the start of the capture",
    );
    plan
}

/// The plan of `wol MAC` (nothing is sent by planning it): one UDP broadcast datagram, and only
/// because the user asked for it.
pub fn wol(destination: std::net::Ipv4Addr) -> HostPlan {
    let mut plan = HostPlan {
        packets: vec![],
        notes: vec!["sent only on request; a scan never sends it".into()],
    };
    plan.push(
        PacketKind::WakeOnLan,
        crate::wol::DETAIL,
        format!("{destination}:{} (UDP broadcast)", crate::wol::PORT),
        "once",
    );
    plan
}

/// What `monitor` adds to each cycle's scan plan.
pub fn monitor_extras(dhcp_discover: bool, interface_listening: bool) -> HostPlan {
    let mut plan = HostPlan {
        packets: vec![],
        notes: vec![],
    };
    if dhcp_discover {
        plan.push(
            PacketKind::DhcpDiscover,
            "DHCPDISCOVER broadcast",
            "255.255.255.255:67",
            "once per cycle; no DHCPREQUEST is ever sent",
        );
    }
    if interface_listening {
        plan.notes
            .push("passive listening on the interface sends nothing".into());
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::Settings;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }
    fn everything(safe: bool) -> Settings {
        Settings {
            safe,
            services: true,
            udp: true,
            os_detect: true,
            ot: true,
            trace: true,
            dns: true,
            syn: true,
            arp_sweep: true,
            jarm: true,
            scan_nonresponders: true,
            ..Settings::default()
        }
    }
    fn kinds(plan: &HostPlan) -> BTreeSet<PacketKind> {
        plan.packets.iter().map(|p| p.kind).collect()
    }
    fn has(plan: &HostPlan, kind: PacketKind, detail: &str) -> bool {
        plan.packets
            .iter()
            .any(|p| p.kind == kind && p.detail.contains(detail))
    }

    #[test]
    fn a_default_scan_plans_ping_and_connects_only() {
        let s = Settings::default();
        let p = host(ip("10.0.0.5"), &[80, 443, 8080], &[], &s, None);
        assert_eq!(
            kinds(&p),
            BTreeSet::from([PacketKind::IcmpEcho, PacketKind::TcpConnect])
        );
        let line = p.lines().join("\n");
        assert!(line.contains("tcp/80,443,8080"), "{line}");
        assert!(line.contains("echo request"));
        // --tcp-only drops the ping.
        let s = Settings {
            tcp_only: true,
            ..Settings::default()
        };
        assert_eq!(
            kinds(&host(ip("10.0.0.5"), &[80], &[], &s, None)),
            BTreeSet::from([PacketKind::TcpConnect])
        );
    }

    #[test]
    fn safe_mode_leaves_out_what_the_documentation_says() {
        let db = ProbeDb::load("").unwrap();
        let ports = [22, 80, 443, 445, 502, 3389, 9100];
        let safe = host(ip("10.0.0.5"), &ports, &[53], &everything(true), Some(&db));
        let fast = host(ip("10.0.0.5"), &ports, &[53], &everything(false), Some(&db));
        // No SYN engine, no ARP sweep, no TLS 1.3 enumeration, no NTLM session setup in Safe Mode.
        assert!(!kinds(&safe).contains(&PacketKind::TcpSyn));
        assert!(!kinds(&safe).contains(&PacketKind::ArpRequest));
        assert!(!has(&safe, PacketKind::TlsClientHello, "TLS 1.3"));
        assert!(!has(&safe, PacketKind::SmbNegotiate, "NTLM"));
        assert!(kinds(&fast).contains(&PacketKind::TcpSyn));
        assert!(kinds(&fast).contains(&PacketKind::ArpRequest));
        assert!(has(&fast, PacketKind::TlsClientHello, "TLS 1.3"));
        assert!(has(&fast, PacketKind::SmbNegotiate, "NTLM SESSION_SETUP"));
        assert!(has(&fast, PacketKind::SmbNegotiate, "SMB2 negotiate"));
        assert!(has(&fast, PacketKind::RdpNegotiate, "standard security"));
        // Traceroute: ICMP only in Safe Mode, even when TCP was asked for.
        let tcp_trace = Settings {
            trace_method: TraceMethod::Tcp,
            ..everything(true)
        };
        let p = host(ip("10.0.0.5"), &ports, &[53], &tcp_trace, Some(&db));
        assert!(has(&p, PacketKind::Traceroute, "ICMP echo"));
        assert!(!has(&p, PacketKind::Traceroute, "TCP SYN"));
        assert!(p.notes.iter().any(|n| n.contains("Safe Mode")));
    }

    #[test]
    fn ot_requests_come_from_the_allow_lists_with_their_function_codes() {
        let s = Settings {
            ot: true,
            ..Settings::default()
        };
        let p = host(ip("10.0.0.5"), &[102, 502], &[], &s, None);
        let labels: BTreeSet<String> = p
            .packets
            .iter()
            .filter(|p| p.kind == PacketKind::OtRequest)
            .map(|p| p.detail.clone())
            .collect();
        let catalog: BTreeSet<String> = readonly::catalog()
            .into_iter()
            .map(|e| e.info.label())
            .collect();
        assert_eq!(
            labels, catalog,
            "the plan lists exactly the allow-listed requests"
        );
        assert!(
            labels
                .contains("Modbus/TCP: function 0x2B, MEI type 0x0E (Read Device Identification)")
        );
        // Nothing is planned without --ot.
        let none = host(ip("10.0.0.5"), &[102, 502], &[], &Settings::default(), None);
        assert!(!kinds(&none).contains(&PacketKind::OtRequest));
        // The OT port table of the sender and the catalog agree.
        let ports: BTreeSet<u16> = crate::ot::TARGETS.iter().map(|t| t.1).collect();
        let catalog_ports: BTreeSet<u16> = readonly::catalog().iter().map(|e| e.port).collect();
        assert_eq!(ports, catalog_ports);
    }

    #[test]
    fn industrial_and_printer_ports_are_never_planned_for_generic_probes() {
        let db = ProbeDb::load("").unwrap();
        let s = Settings {
            services: true,
            udp: true,
            udp_ports: "53,161,2222,9100,20000,44818,47808".into(),
            ..Settings::default()
        };
        let udp = crate::scan::parse_ports(&s.udp_ports).unwrap();
        let p = host(
            ip("10.0.0.5"),
            &[22, 102, 502, 9100, 44818, 80],
            &udp,
            &s,
            Some(&db),
        );
        let text = p.lines().join("\n");
        for port in ["tcp/102", "tcp/502", "tcp/44818"] {
            for packet in p
                .packets
                .iter()
                .filter(|x| x.kind == PacketKind::ServiceProbe)
            {
                assert!(!packet.to.contains(port), "{packet:?}");
            }
        }
        let udp_to: Vec<&str> = p
            .packets
            .iter()
            .filter(|x| x.kind == PacketKind::UdpProbe)
            .map(|x| x.to.as_str())
            .collect();
        assert_eq!(udp_to, ["udp/53", "udp/161"], "{text}");
        assert!(
            p.notes
                .iter()
                .any(|n| n.contains("never probed by the UDP scan"))
        );
        assert!(
            text.contains("dns/53") && text.contains("snmp/161"),
            "{text}"
        );
    }

    #[test]
    fn ipv6_hosts_get_no_arp_and_groups_split_by_family() {
        let s = Settings {
            arp_sweep: true,
            safe: false,
            ..Settings::default()
        };
        assert!(has(
            &host(ip("10.0.0.5"), &[80], &[], &s, None),
            PacketKind::ArpRequest,
            "sweep"
        ));
        assert!(!has(
            &host(ip("fd00::5"), &[80], &[], &s, None),
            PacketKind::ArpRequest,
            "sweep"
        ));
        let hosts = ["10.0.0.1", "10.0.0.2", "fd00::1", "10.0.0.3"].map(ip);
        let groups = scan(hosts.into_iter(), &[80], &s, None);
        assert_eq!(groups.len(), 2);
        assert_eq!(
            (groups[0].family, groups[0].hosts, groups[0].last),
            ("ipv4", 3, ip("10.0.0.3"))
        );
        assert_eq!((groups[1].family, groups[1].hosts), ("ipv6", 1));
        let text = format_scan(&groups, &s);
        assert!(text.starts_with("DRY RUN: nothing was sent."), "{text}");
        assert!(text.contains("ipv4 3 host(s), 10.0.0.1 ... 10.0.0.3"));
        let json = serde_json::to_value(&groups).unwrap();
        let kinds: Vec<&str> = json[0]["packets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["kind"].as_str().unwrap())
            .collect();
        assert!(
            kinds.contains(&"icmp-echo") && kinds.contains(&"arp-request"),
            "{kinds:?}"
        );
    }

    #[test]
    fn a_big_range_is_planned_without_expanding_the_output() {
        let t = crate::scan::parse_targets("10.0.0.0/16", true, crate::scan::MAX_STREAM).unwrap();
        let groups = scan(t.iter(), &[80], &Settings::default(), None);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].hosts, 65534);
    }

    #[test]
    fn port_lists_are_compact() {
        assert_eq!(ports_text(&[80, 443, 8080]), "80,443,8080");
        assert_eq!(ports_text(&[1, 2, 3, 4, 10]), "1-4,10");
        assert_eq!(ports_text(&[5, 6]), "5,6");
        assert_eq!(ports_text(&[]), "");
        assert_eq!(ports_text(&[9, 9, 8]), "8,9");
    }

    #[test]
    fn trace_and_dcp_plans() {
        let p = trace(ip("10.0.0.1"), TraceMethod::Tcp, Some(443), 20);
        assert!(has(&p, PacketKind::Traceroute, "TCP SYN"));
        assert!(has(&p, PacketKind::TcpSyn, "RST"));
        let p = trace(ip("10.0.0.1"), TraceMethod::Icmp, None, 99);
        assert!(p.packets[0].when.contains("TTL 1 to 64"), "{:?}", p.packets);
        let d = dcp();
        assert_eq!(d.packets.len(), 1);
        assert_eq!(d.packets[0].kind, PacketKind::DcpIdentify);
        assert!(
            d.packets[0].detail.contains("Identify All"),
            "{:?}",
            d.packets
        );
        assert!(d.packets[0].detail.contains("0xFEFE"));
        let m = monitor_extras(true, true);
        assert!(has(&m, PacketKind::DhcpDiscover, "DHCPDISCOVER"));
        assert!(monitor_extras(false, false).packets.is_empty());
    }

    #[test]
    fn the_conditions_are_the_ones_the_scan_uses() {
        // The scan calls these functions; the plan is built from them (see the module docs).
        let s = Settings {
            tcp_only: true,
            ..Settings::default()
        };
        assert_eq!(icmp_echoes(&s), 0);
        assert_eq!(
            icmp_echoes(&Settings {
                probes: 99,
                ..Settings::default()
            }),
            10
        );
        assert!(!arp_lookup(&Settings::default()));
        assert!(arp_lookup(&Settings {
            mac: true,
            ..Settings::default()
        }));
        assert!(
            !syn_engine(&Settings {
                syn: true,
                ..Settings::default()
            }),
            "Safe Mode"
        );
        assert!(ot_identification(
            false,
            &Settings {
                ot: true,
                scan_nonresponders: true,
                ..Settings::default()
            }
        ));
        assert!(!ot_identification(
            false,
            &Settings {
                ot: true,
                scan_nonresponders: false,
                ..Settings::default()
            }
        ));
        let source = include_str!("core.rs");
        let code = source.split("#[cfg(test)]").next().unwrap();
        for call in [
            "plan::arp_lookup(",
            "plan::arp_sweep(",
            "plan::icmp_echoes(",
            "plan::syn_engine(",
            "plan::udp_ports(",
            "plan::ot_identification(",
            "plan::snmp_read(",
            "plan::probes_ports(",
        ] {
            assert!(code.contains(call), "the scheduler must use {call}");
        }
    }

    /// Drift guard that needs no driver: every literal detail a sender passes with a packet kind
    /// (`PacketKind::X, "detail"`) must appear in this file, so the plan can list it.
    #[test]
    fn every_literal_detail_a_sender_records_is_in_the_plan() {
        let plan_source = include_str!("plan.rs");
        let plan_code = plan_source.split("#[cfg(test)]").next().unwrap();
        let senders = [
            ("arp.rs", include_str!("arp.rs")),
            ("core.rs", include_str!("core.rs")),
            ("jarm.rs", include_str!("jarm.rs")),
            ("ot.rs", include_str!("ot.rs")),
            ("snmp/client.rs", include_str!("snmp/client.rs")),
            ("syn.rs", include_str!("syn.rs")),
            ("tls.rs", include_str!("tls.rs")),
            ("trace.rs", include_str!("trace.rs")),
            ("udp.rs", include_str!("udp.rs")),
            ("service/mod.rs", include_str!("service/mod.rs")),
            ("service/rdp.rs", include_str!("service/rdp.rs")),
            ("service/smb/mod.rs", include_str!("service/smb/mod.rs")),
        ];
        let mut checked = 0;
        for (name, source) in senders {
            let code = source
                .split(
                    "#[cfg(test)]
mod tests",
                )
                .next()
                .unwrap();
            for part in code.split("PacketKind::").skip(1) {
                let rest = part.trim_start_matches(|c: char| c.is_alphanumeric());
                let Some(after) = rest.strip_prefix(',') else {
                    continue;
                };
                let Some(literal) = after.trim_start().strip_prefix('"') else {
                    continue;
                };
                let detail = literal.split('"').next().unwrap();
                checked += 1;
                assert!(
                    plan_code.contains(&format!("\"{detail}\"")),
                    "{name} records {detail:?}, but plan.rs never lists it"
                );
            }
        }
        assert!(checked > 20, "the scan found only {checked} literals");
    }

    #[test]
    fn planning_opens_no_socket_and_loads_no_driver() {
        let code = include_str!("plan.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for forbidden in [
            "TcpStream",
            "UdpSocket",
            "tokio::net",
            "std::net::Tcp",
            "capture::",
            "Capture",
            "send_to",
            ".send(",
            "write_all",
            "socket2",
        ] {
            assert!(
                !code.contains(forbidden),
                "plan.rs must not use {forbidden}"
            );
        }
    }

    /// The drift guard: a loopback scan with every feature on (a listener, a fake service, closed
    /// ports) records what it sent, and every `(kind, detail)` must be in the plan for that host.
    #[test]
    fn everything_the_scan_sends_is_in_the_plan() {
        let _port = crate::core::BACNET_PORT
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let open = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                use std::io::Write;
                let mut stream = stream;
                let _ = stream.write_all(b"SSH-2.0-test\r\n");
            }
        });
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        // an SNMP agent that is not there: the request goes out, nothing answers
        let snmp = {
            let free = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let mut c = crate::snmp::SnmpConfig::community("2c", "lab-community").unwrap();
            c.port = free.local_addr().unwrap().port();
            c
        };
        for safe in [true, false] {
            let s = Settings {
                safe,
                services: true,
                udp: true,
                os_detect: true,
                ot: true,
                jarm: true,
                snmp: Some(snmp.clone()),
                trace: false,
                dns: false,
                tcp_only: false,
                scan_nonresponders: true,
                ping_timeout: 1500,
                port_timeout: 1500,
                retries: 0,
                probes: 2,
                delay: 0,
                udp_ports: "53,123".into(),
                ..Settings::default()
            };
            let mut ports = vec![open, closed, 502, 102];
            ports.sort_unstable();
            ports.dedup();
            let run = crate::scan::start(vec![ip("127.0.0.1")], ports.clone(), s.clone());
            let sent = run.sent.clone();
            loop {
                match run
                    .receiver
                    .recv_timeout(std::time::Duration::from_secs(120))
                    .unwrap()
                {
                    crate::scan::Event::Done => break,
                    crate::scan::Event::Error(e) => panic!("{e}"),
                    crate::scan::Event::Host(_) | crate::scan::Event::Partial(_) => {}
                }
            }
            let db = ProbeDb::load("").unwrap();
            let udp = crate::scan::parse_ports(&s.udp_ports).unwrap();
            let planned = host(ip("127.0.0.1"), &ports, &udp, &s, Some(&db)).keys();
            let log = sent.snapshot();
            assert!(!log.is_empty(), "safe={safe}: the scan sent nothing?");
            for e in &log {
                assert!(
                    planned.contains(&(e.kind, e.detail.clone())),
                    "safe={safe}: sent {} / {:?} x{} but the plan does not list it; plan: {planned:?}",
                    e.kind.name(),
                    e.detail,
                    e.count
                );
            }
            // And the basics really were sent.
            let sent_kinds: BTreeSet<PacketKind> = log.iter().map(|e| e.kind).collect();
            for k in [
                PacketKind::IcmpEcho,
                PacketKind::TcpConnect,
                PacketKind::UdpProbe,
                PacketKind::SnmpRequest,
            ] {
                assert!(
                    sent_kinds.contains(&k),
                    "safe={safe}: {k:?} missing from {log:?}"
                );
            }
        }
    }
}
