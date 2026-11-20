//! The list of packet kinds the scanner can transmit, and the per-scan log of what it did send
//! (ROADMAP H53).
//!
//! [`PacketKind`] is the one closed list used by both sides of the dry run: the plan
//! ([`crate::plan`]) says which `(kind, detail)` pairs a scan would send, and the [`SentLog`]
//! counts the pairs it really sent. A test runs a loopback scan with every feature on and checks
//! that everything in the log was in the plan.
//!
//! # Adding a sender
//!
//! 1. Add a [`PacketKind`] variant (or reuse one) with a stable name in [`PacketKind::name`].
//! 2. Where the packet leaves, take the rate-gate token with `Gate::wait_for(kind, detail)` or
//!    `Gate::try_take_for(kind, detail)` (these record the packet), or call `Gate::note` for a
//!    packet that goes out on an already-gated connection. OT requests record themselves: build
//!    them from `ot::readonly` and send them through `OtStream`/`OtUdp` with a log attached.
//! 3. Make `plan::host` list the same `(kind, detail)`; the drift test fails until you do.
//!
//! The detail is a short, address-free description (`"port scan"`, `"dns/53"`, `"Modbus: function
//! 0x2B ..."`), so a scan of a /16 has as many keys as it has kinds of packet, not hosts.
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Mutex};

/// A kind of packet the scanner can transmit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PacketKind {
    /// ICMP echo request (ping).
    IcmpEcho,
    /// ARP request from the ARP sweep engine.
    ArpRequest,
    /// The operating system's neighbour lookup (it may emit an ARP/NDP request itself).
    NeighborLookup,
    /// A TCP connection attempt (SYN through the OS): port scan and service identification.
    TcpConnect,
    /// A raw SYN (or the RST that closes a half-open connection) from the SYN engine.
    TcpSyn,
    /// A UDP probe datagram.
    UdpProbe,
    /// A payload from `probes.json` sent to an open TCP port.
    ServiceProbe,
    /// An HTTP request (`GET /`).
    HttpRequest,
    /// A TLS ClientHello (handshake, version and cipher enumeration).
    TlsClientHello,
    /// An SMB negotiate request (and, outside Safe Mode, NTLM SESSION_SETUP without AUTHENTICATE).
    SmbNegotiate,
    /// An RDP negotiation request.
    RdpNegotiate,
    /// The SSH identification string and key exchange init.
    SshBanner,
    /// A read-only industrial protocol request (see `ot::readonly`).
    OtRequest,
    /// The Profinet DCP Identify frame.
    DcpIdentify,
    /// A traceroute probe (ICMP, TCP SYN or UDP with increasing TTL).
    Traceroute,
    /// A DHCPDISCOVER broadcast (`monitor --dhcp-discover`).
    DhcpDiscover,
    /// A reverse DNS lookup; it goes to the system resolver, not to the scanned host.
    #[serde(rename = "dns-ptr")]
    DnsLookup,
}

impl PacketKind {
    /// The stable name used in output (`--sent-log`, JSON, the dry run).
    pub const fn name(self) -> &'static str {
        match self {
            Self::IcmpEcho => "icmp-echo",
            Self::ArpRequest => "arp-request",
            Self::NeighborLookup => "neighbor-lookup",
            Self::TcpConnect => "tcp-connect",
            Self::TcpSyn => "tcp-syn",
            Self::UdpProbe => "udp-probe",
            Self::ServiceProbe => "service-probe",
            Self::HttpRequest => "http-request",
            Self::TlsClientHello => "tls-client-hello",
            Self::SmbNegotiate => "smb-negotiate",
            Self::RdpNegotiate => "rdp-negotiate",
            Self::SshBanner => "ssh-banner",
            Self::OtRequest => "ot-request",
            Self::DcpIdentify => "dcp-identify",
            Self::Traceroute => "traceroute",
            Self::DhcpDiscover => "dhcp-discover",
            Self::DnsLookup => "dns-ptr",
        }
    }
    /// Every kind, in the order of the enum (used by tests and documentation).
    pub const ALL: [Self; 17] = [
        Self::IcmpEcho,
        Self::ArpRequest,
        Self::NeighborLookup,
        Self::TcpConnect,
        Self::TcpSyn,
        Self::UdpProbe,
        Self::ServiceProbe,
        Self::HttpRequest,
        Self::TlsClientHello,
        Self::SmbNegotiate,
        Self::RdpNegotiate,
        Self::SshBanner,
        Self::OtRequest,
        Self::DcpIdentify,
        Self::Traceroute,
        Self::DhcpDiscover,
        Self::DnsLookup,
    ];
}

/// One line of a sent log: how many packets of a kind and detail were sent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentEntry {
    pub kind: PacketKind,
    pub detail: String,
    pub count: u64,
}

/// Most distinct `(kind, detail)` keys a log keeps; further details are counted under `other`,
/// so even an odd scan cannot grow the log without bound.
const MAX_KEYS: usize = 512;
/// Longest detail kept.
const MAX_DETAIL: usize = 160;

/// Counter of the packets a scan sent, keyed by `(kind, detail)`.
#[derive(Debug, Default)]
pub struct SentLog {
    counts: Mutex<BTreeMap<(PacketKind, String), u64>>,
}

impl SentLog {
    pub fn new() -> Self {
        Self::default()
    }
    /// Counts one packet.
    pub fn record(&self, kind: PacketKind, detail: impl Into<String>) {
        let mut detail: String = detail.into();
        if detail.len() > MAX_DETAIL {
            let mut end = MAX_DETAIL;
            while !detail.is_char_boundary(end) {
                end -= 1;
            }
            detail.truncate(end);
        }
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        let key = (kind, detail);
        if !counts.contains_key(&key) && counts.len() >= MAX_KEYS {
            *counts.entry((kind, "other".into())).or_insert(0) += 1;
        } else {
            *counts.entry(key).or_insert(0) += 1;
        }
    }
    /// The counts so far, sorted by kind and detail.
    pub fn snapshot(&self) -> Vec<SentEntry> {
        self.counts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|((kind, detail), count)| SentEntry {
                kind: *kind,
                detail: detail.clone(),
                count: *count,
            })
            .collect()
    }
    /// All packets counted.
    pub fn total(&self) -> u64 {
        self.counts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .sum()
    }
    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }
}

/// The total of a stored log.
pub fn total(entries: &[SentEntry]) -> u64 {
    entries.iter().map(|e| e.count).sum()
}

/// A plain-text table of a log (`--sent-log`, the desktop scan summary).
pub fn format_table(entries: &[SentEntry]) -> String {
    if entries.is_empty() {
        return "Packets sent: none".into();
    }
    let mut out = format!("Packets sent: {}\n", total(entries));
    for e in entries {
        out.push_str(&format!(
            "  {:>9}  {:<16} {}\n",
            e.count,
            e.kind.name(),
            e.detail
        ));
    }
    out.trim_end().into()
}

/// Folds the entries of several logs (for example one per monitor cycle) into one.
pub fn merge(logs: impl IntoIterator<Item = Vec<SentEntry>>) -> Vec<SentEntry> {
    let mut sum: BTreeMap<(PacketKind, String), u64> = BTreeMap::new();
    for entry in logs.into_iter().flatten() {
        *sum.entry((entry.kind, entry.detail)).or_insert(0) += entry.count;
    }
    sum.into_iter()
        .map(|((kind, detail), count)| SentEntry {
            kind,
            detail,
            count,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_unique_and_stable() {
        let names: std::collections::BTreeSet<_> =
            PacketKind::ALL.iter().map(|k| k.name()).collect();
        assert_eq!(names.len(), PacketKind::ALL.len());
        for k in PacketKind::ALL {
            let json = serde_json::to_string(&k).unwrap();
            assert_eq!(
                json,
                format!("\"{}\"", k.name()),
                "serde name = display name"
            );
            assert_eq!(serde_json::from_str::<PacketKind>(&json).unwrap(), k);
        }
    }

    #[test]
    fn counts_are_keyed_by_kind_and_detail() {
        let log = SentLog::new();
        assert!(log.is_empty());
        for _ in 0..3 {
            log.record(PacketKind::TcpConnect, "port scan");
        }
        log.record(PacketKind::UdpProbe, "dns/53");
        log.record(PacketKind::UdpProbe, "dns/53");
        log.record(PacketKind::UdpProbe, "snmp/161");
        let entries = log.snapshot();
        assert_eq!(log.total(), 6);
        assert_eq!(total(&entries), 6);
        assert_eq!(
            entries
                .iter()
                .map(|e| (e.kind.name(), e.detail.as_str(), e.count))
                .collect::<Vec<_>>(),
            [
                ("tcp-connect", "port scan", 3),
                ("udp-probe", "dns/53", 2),
                ("udp-probe", "snmp/161", 1)
            ]
        );
        let table = format_table(&entries);
        assert!(table.starts_with("Packets sent: 6"), "{table}");
        assert!(table.contains("udp-probe") && table.contains("snmp/161"));
        assert_eq!(format_table(&[]), "Packets sent: none");
    }

    #[test]
    fn the_key_count_and_detail_length_are_bounded() {
        let log = SentLog::new();
        for i in 0..(MAX_KEYS + 100) {
            log.record(PacketKind::TcpConnect, format!("port {i}"));
        }
        let entries = log.snapshot();
        assert_eq!(
            entries.len(),
            MAX_KEYS + 1,
            "the keys plus one `other` bucket"
        );
        assert_eq!(log.total(), (MAX_KEYS + 100) as u64);
        assert!(
            entries
                .iter()
                .any(|e| e.detail == "other" && e.count == 100)
        );
        // A key that exists keeps counting even when the log is full.
        log.record(PacketKind::TcpConnect, "port 0");
        assert_eq!(
            log.snapshot()
                .iter()
                .find(|e| e.detail == "port 0")
                .unwrap()
                .count,
            2
        );
        let long = SentLog::new();
        long.record(PacketKind::UdpProbe, "é".repeat(500));
        assert!(long.snapshot()[0].detail.len() <= MAX_DETAIL);
        assert!(long.snapshot()[0].detail.chars().all(|c| c == 'é'));
    }

    #[test]
    fn logs_merge() {
        let a = SentLog::new();
        a.record(PacketKind::IcmpEcho, "echo request");
        let b = SentLog::new();
        b.record(PacketKind::IcmpEcho, "echo request");
        b.record(PacketKind::DnsLookup, "reverse lookup");
        let merged = merge([a.snapshot(), b.snapshot()]);
        assert_eq!(total(&merged), 3);
        assert_eq!(merged.len(), 2);
    }
}
