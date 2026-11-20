//! Heuristic OS guess from IP TTL, the target's SYN-ACK TCP parameters and service evidence.
//! This is a scored rule set, not a signature database: expect "family" level answers.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What a target's SYN-ACK reveals. `opts` lists option kinds in wire order
/// (M=MSS, N=NOP, W=window scale, S=SACK permitted, T=timestamps, E=end of list).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpFp {
    pub window: u16,
    pub ttl: u8,
    pub df: bool,
    pub mss: Option<u16>,
    pub wscale: Option<u8>,
    pub opts: String,
}
impl TcpFp {
    pub fn describe(&self) -> String {
        format!(
            "win={} ttl={} df={} mss={} ws={} opts={}",
            self.window,
            self.ttl,
            u8::from(self.df),
            self.mss.map_or("-".into(), |v| v.to_string()),
            self.wscale.map_or("-".into(), |v| v.to_string()),
            self.opts
        )
    }
}

pub fn parse_options(raw: &[u8]) -> (String, Option<u16>, Option<u8>) {
    let (mut kinds, mut mss, mut ws) = (vec![], None, None);
    let mut i = 0;
    while i < raw.len() {
        let kind = raw[i];
        match kind {
            0 => {
                kinds.push("E".to_string());
                break;
            }
            1 => {
                kinds.push("N".into());
                i += 1;
                continue;
            }
            _ => {}
        }
        let Some(&len) = raw.get(i + 1) else { break };
        let len = usize::from(len);
        if len < 2 || i + len > raw.len() {
            break;
        }
        match kind {
            2 if len == 4 => {
                mss = Some(u16::from_be_bytes([raw[i + 2], raw[i + 3]]));
                kinds.push("M".into());
            }
            3 if len == 3 => {
                ws = Some(raw[i + 2]);
                kinds.push("W".into());
            }
            4 => kinds.push("S".into()),
            8 => kinds.push("T".into()),
            other => kinds.push(format!("O{other}")),
        }
        i += len;
    }
    (kinds.join(","), mss, ws)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Guess {
    pub name: String,
    pub confidence: u8,
    pub evidence: Vec<String>,
}
impl Guess {
    /// The reasons and the score as the shared [`crate::evidence::Evidence`].
    pub fn evidence(&self) -> crate::evidence::Evidence {
        crate::evidence::Evidence::new(self.evidence.iter().cloned(), self.confidence)
    }
}

pub fn initial_ttl(observed: u8) -> u8 {
    [32u8, 64, 128, 255]
        .into_iter()
        .find(|t| observed <= *t)
        .unwrap_or(255)
}

#[derive(Default)]
struct Scores(BTreeMap<&'static str, (i32, Vec<String>)>);
impl Scores {
    fn add(&mut self, os: &'static str, points: i32, why: impl Into<String>) {
        let entry = self.0.entry(os).or_default();
        entry.0 += points;
        entry.1.push(why.into());
    }
}

const WINDOWS: &str = "Windows";
const LINUX: &str = "Linux";
const APPLE: &str = "macOS/iOS";
const BSD: &str = "BSD";
const NETDEV: &str = "Network device (Cisco/embedded RTOS)";
const EMBEDDED: &str = "Embedded Linux/RTOS";

fn contains_any(text: &str, needles: &[&str]) -> bool {
    let lower = text.to_ascii_lowercase();
    needles
        .iter()
        .any(|n| lower.contains(&n.to_ascii_lowercase()))
}

/// Derived keys that name vendors without being evidence about the OS: a CPE for OpenSSH
/// says "openbsd" on every Linux host, and fingerprint hashes are opaque.
fn derived(key: &str) -> bool {
    key.ends_with(".cpe")
        || key.ends_with(".hassh")
        || key.ends_with(".ja4s")
        || key.ends_with(".jarm")
}

/// Windows release for an NTLM version `major.minor.build` (builds shared by client and
/// server releases name both).
fn windows_release(major: u32, minor: u32, build: u32) -> Option<&'static str> {
    Some(match (major, minor, build) {
        (5, 1, _) => "XP",
        (5, 2, _) => "XP x64 / Server 2003",
        (6, 0, _) => "Vista / Server 2008",
        (6, 1, _) => "7 / Server 2008 R2",
        (6, 2, _) => "8 / Server 2012",
        (6, 3, _) => "8.1 / Server 2012 R2",
        (10, 0, 14393) => "10 1607 / Server 2016",
        (10, 0, 17763) => "10 1809 / Server 2019",
        (10, 0, 20348) => "Server 2022",
        (10, 0, 26100) => "11 24H2 / Server 2025",
        (10, 0, b) if b >= 22000 => "11",
        (10, 0, _) => "10",
        _ => return None,
    })
}

/// `key` is `base` itself or a sub-key of it (`svc.22`, `svc.22.product`), never `svc.220`.
fn key_under(key: &str, base: &str) -> bool {
    key.strip_prefix(base)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
}

/// `identity` is the host's service evidence (keys such as `svc.22`, `http.80.server`).
pub fn guess(
    ttl: Option<u8>,
    fp: Option<&TcpFp>,
    identity: &BTreeMap<String, String>,
    open: &[u16],
    vendor: &str,
) -> Option<Guess> {
    let mut s = Scores::default();
    let observed = fp.map(|f| f.ttl).filter(|t| *t > 0).or(ttl);
    if let Some(t) = observed {
        match initial_ttl(t) {
            64 => {
                s.add(LINUX, 12, "initial TTL 64");
                s.add(APPLE, 12, "initial TTL 64");
                s.add(BSD, 12, "initial TTL 64");
                s.add(EMBEDDED, 8, "initial TTL 64");
            }
            128 => s.add(WINDOWS, 25, "initial TTL 128"),
            255 => s.add(NETDEV, 25, "initial TTL 255"),
            _ => {}
        }
    }
    if let Some(f) = fp {
        let o = f.opts.as_str();
        match o {
            "M,N,W,N,N,S" | "M,N,W,S" | "M,N,N,S" => {
                s.add(WINDOWS, 40, format!("TCP options {o}"));
            }
            "M,S,T,N,W" | "M,S,T,N,W,O34" => s.add(LINUX, 40, format!("TCP options {o}")),
            "M,N,W,N,N,T,S,E" | "M,N,W,N,N,T,S" => s.add(APPLE, 40, format!("TCP options {o}")),
            "M,N,W,S,T" => {
                s.add(BSD, 30, format!("TCP options {o}"));
                s.add(APPLE, 10, format!("TCP options {o}"));
            }
            "M" | "" => {
                s.add(NETDEV, 20, "minimal TCP options");
                s.add(EMBEDDED, 25, "minimal TCP options");
            }
            _ => {}
        }
        match f.window {
            8192 | 64240 | 65535 if o.starts_with("M,N,W,N,N") && f.ttl > 64 => {
                s.add(WINDOWS, 10, format!("window {}", f.window))
            }
            29200 | 14600 | 5792 | 65160 | 64240 if o.contains('T') && f.ttl <= 64 => {
                s.add(LINUX, 15, format!("window {}", f.window))
            }
            4128 => s.add(NETDEV, 30, "window 4128 (Cisco IOS)"),
            65535 if o.contains('T') && f.ttl <= 64 => {
                s.add(APPLE, 15, "window 65535 with timestamps");
                s.add(BSD, 10, "window 65535 with timestamps");
            }
            w if w <= 5840 && o == "M" => s.add(EMBEDDED, 15, format!("small window {w}")),
            _ => {}
        }
    }
    // Service evidence by detected service name, not by port: SSH on 2222 counts, and the
    // value of `svc.220` (FTP) never counts as SSH evidence.
    let by_service = |names: &[&str]| -> String {
        identity
            .iter()
            .filter_map(|(k, v)| {
                let port = k.strip_prefix("svc.")?;
                let name = v.split_whitespace().next().unwrap_or("");
                let name = name.strip_prefix("ssl/").unwrap_or(name);
                (!port.contains('.') && names.contains(&name)).then_some(port)
            })
            .flat_map(|port| {
                let base = format!("svc.{port}");
                identity
                    .iter()
                    .filter(move |(k, _)| key_under(k, &base) && !derived(k))
                    .map(|(_, v)| v.as_str())
            })
            .collect::<Vec<_>>()
            .join(" | ")
    };
    let suffixed = |suffixes: &[&str]| -> String {
        identity
            .iter()
            .filter(|(k, _)| suffixes.iter().any(|s| k.ends_with(s)))
            .map(|(_, v)| v.as_str())
            .collect::<Vec<_>>()
            .join(" | ")
    };
    let ssh = by_service(&["ssh"]);
    let http = suffixed(&[".server", ".powered_by"]);
    let snmp = identity
        .iter()
        .filter(|(k, _)| key_under(k, "udp.161") || k.as_str() == "snmp.sysdescr")
        .map(|(_, v)| v.as_str())
        .collect::<Vec<_>>()
        .join(" | ");
    let smb = identity
        .iter()
        .filter(|(k, _)| key_under(k, "svc.445") || key_under(k, "svc.139"))
        .map(|(_, v)| v.as_str())
        .collect::<Vec<_>>()
        .join(" | ");
    let all = identity
        .iter()
        .filter(|(k, v)| !v.starts_with("unidentified") && !derived(k))
        .map(|(_, v)| v.clone())
        .collect::<Vec<_>>()
        .join(" | ");
    if contains_any(
        &ssh,
        &[
            "ubuntu", "debian", "raspbian", "centos", "fedora", "red hat", "el7", "el8", "el9",
        ],
    ) {
        s.add(LINUX, 45, "SSH banner names a Linux distribution");
    }
    if contains_any(&ssh, &["for_windows", "for windows", "microsoft"]) {
        s.add(WINDOWS, 45, "SSH banner names Windows");
    }
    if contains_any(&ssh, &["freebsd", "openbsd", "netbsd"]) {
        s.add(BSD, 45, "SSH banner names a BSD");
    }
    if contains_any(&ssh, &["dropbear"]) {
        s.add(EMBEDDED, 30, "Dropbear SSH (embedded Linux)");
    }
    if contains_any(&ssh, &["ssh cisco-", "rosssh"]) {
        s.add(
            NETDEV,
            40,
            "SSH banner names network equipment (Cisco/MikroTik)",
        );
    }
    // The NTLM challenge of the SMB session setup names the Windows version and build.
    // Samba answers with a fixed 6.1 and build 0, so build 0 is Samba, not Windows 7.
    for (k, v) in identity
        .iter()
        .filter(|(k, _)| k.starts_with("smb.") && k.ends_with(".os_version"))
    {
        let parts: Vec<u32> = v.split('.').filter_map(|p| p.parse().ok()).collect();
        let [major, minor, build] = parts[..] else {
            continue;
        };
        if build == 0 {
            s.add(
                LINUX,
                25,
                format!("Samba-style SMB server ({k} {v}, build 0)"),
            );
        } else if let Some(release) = windows_release(major, minor, build) {
            s.add(
                WINDOWS,
                70,
                format!("SMB NTLM challenge: Windows {release} (build {build})"),
            );
        }
        break;
    }
    if contains_any(&http, &["microsoft-iis", "microsoft-httpapi"]) {
        s.add(WINDOWS, 45, "HTTP server header names Microsoft");
    }
    if contains_any(
        &http,
        &["(ubuntu)", "(debian)", "(centos)", "(red hat)", "(fedora)"],
    ) {
        s.add(LINUX, 40, "HTTP server header names a Linux distribution");
    }
    if contains_any(
        &http,
        &[
            "lighttpd",
            "uhttpd",
            "goahead",
            "boa/",
            "mini_httpd",
            "thttpd",
            "micro_httpd",
        ],
    ) {
        s.add(EMBEDDED, 30, "embedded-class HTTP server");
    }
    if contains_any(&snmp, &["windows"]) {
        s.add(WINDOWS, 60, "SNMP sysDescr names Windows");
    }
    if contains_any(&snmp, &["linux"]) {
        s.add(LINUX, 60, "SNMP sysDescr names Linux");
    }
    if contains_any(
        &snmp,
        &["cisco ios", "junos", "routeros", "procurve", "comware"],
    ) {
        s.add(NETDEV, 60, "SNMP sysDescr names a network OS");
    }
    if contains_any(&snmp, &["darwin", "mac os"]) {
        s.add(APPLE, 60, "SNMP sysDescr names Apple");
    }
    if open.contains(&3389) || open.contains(&135) || open.contains(&5985) {
        s.add(WINDOWS, 20, "Windows service ports (RDP/RPC/WinRM)");
    }
    if !smb.is_empty() && (open.contains(&3389) || open.contains(&135)) {
        s.add(WINDOWS, 15, "SMB together with RDP/RPC");
    }
    if identity.keys().any(|k| key_under(k, "udp.137")) {
        s.add(WINDOWS, 15, "NetBIOS name service answered");
    }
    if open.contains(&62078)
        || contains_any(&all, &["airplay", "apple"])
        || contains_any(vendor, &["apple"])
    {
        s.add(APPLE, 30, "Apple vendor or service");
    }
    if contains_any(vendor, &["raspberry", "espressif"]) {
        s.add(EMBEDDED, 25, "single-board/IoT vendor OUI");
        s.add(LINUX, 10, "single-board/IoT vendor OUI");
    }
    if contains_any(
        vendor,
        &[
            "cisco", "juniper", "mikrotik", "ubiquiti", "aruba", "fortinet", "netgear", "tp-link",
            "zyxel",
        ],
    ) {
        s.add(NETDEV, 15, "network equipment vendor OUI");
    }
    let mut ranked: Vec<_> = s.0.into_iter().collect();
    ranked.sort_by_key(|(_, (score, _))| -*score);
    let (name, (score, evidence)) = ranked.first()?.clone();
    if score < 30 {
        return None;
    }
    let runner_up = ranked.get(1).map_or(0, |(_, (v, _))| *v);
    let confidence = crate::evidence::confidence_from_scores(score, runner_up);
    Some(Guess {
        name: name.to_string(),
        confidence,
        evidence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn option_parsing_keeps_wire_order() {
        // MSS 1460, NOP, WS 8, NOP, NOP, SACK permitted (a typical Windows SYN-ACK).
        let raw = [2, 4, 5, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2];
        assert_eq!(
            parse_options(&raw),
            ("M,N,W,N,N,S".into(), Some(1460), Some(8))
        );
        // Linux order: MSS, SACK, TS, NOP, WS.
        let raw = [
            2, 4, 5, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 1, 3, 3, 7,
        ];
        assert_eq!(parse_options(&raw).0, "M,S,T,N,W");
        // Truncated and hostile input must not panic or loop.
        assert_eq!(parse_options(&[2, 4, 5]).0, "");
        assert_eq!(parse_options(&[8, 0, 8, 1]).0, "");
        assert_eq!(parse_options(&[0xfe]).0, "");
    }

    #[test]
    fn ttl_buckets() {
        assert_eq!(initial_ttl(57), 64);
        assert_eq!(initial_ttl(64), 64);
        assert_eq!(initial_ttl(117), 128);
        assert_eq!(initial_ttl(250), 255);
    }

    #[test]
    fn windows_is_recognised_from_tcp_and_services() {
        let fp = TcpFp {
            window: 64240,
            ttl: 128,
            df: true,
            mss: Some(1460),
            wscale: Some(8),
            opts: "M,N,W,N,N,S".into(),
        };
        let g = guess(
            None,
            Some(&fp),
            &id(&[("http.80.server", "Microsoft-IIS/10.0")]),
            &[80, 3389],
            "",
        )
        .unwrap();
        assert_eq!(g.name, WINDOWS);
        assert!(g.confidence >= 80, "{g:?}");
        assert!(g.evidence.len() >= 3);
    }

    #[test]
    fn linux_from_ssh_banner_and_ttl_only() {
        let g = guess(
            Some(61),
            None,
            &id(&[("svc.22", "ssh OpenSSH 8.9p1 Ubuntu-3ubuntu0.1")]),
            &[22],
            "",
        )
        .unwrap();
        assert_eq!(g.name, LINUX);
    }

    #[test]
    fn ssh_evidence_is_matched_by_service_not_port_prefix() {
        // SSH on 2222 counts.
        let g = guess(
            Some(61),
            None,
            &id(&[(
                "svc.2222",
                "ssh OpenSSH 8.9p1 (protocol 2.0 Ubuntu-3ubuntu0.1)",
            )]),
            &[2222],
            "",
        )
        .unwrap();
        assert_eq!(g.name, LINUX);
        // A non-SSH service on 220/2222 whose text names a distribution is not SSH evidence.
        assert_eq!(
            guess(
                Some(61),
                None,
                &id(&[("svc.220", "imap Debian"), ("svc.2222", "unidentified")]),
                &[220, 2222],
                "",
            ),
            None
        );
        // OpenSSH for Windows as the banner rule reports it (with spaces).
        let g = guess(
            None,
            None,
            &id(&[
                ("svc.22", "ssh OpenSSH for Windows 9.5 (protocol 2.0)"),
                ("svc.22.product", "OpenSSH for Windows"),
            ]),
            &[22],
            "",
        )
        .unwrap();
        assert_eq!(g.name, WINDOWS);
        assert!(key_under("udp.137", "udp.137") && key_under("udp.137.name", "udp.137"));
        assert!(!key_under("udp.1370", "udp.137"));
    }

    #[test]
    fn weak_evidence_gives_no_guess() {
        // A TTL of 128 alone is only a hint, not an answer.
        assert_eq!(guess(Some(120), None, &BTreeMap::new(), &[], ""), None);
        assert_eq!(guess(None, None, &BTreeMap::new(), &[], ""), None);
        assert_eq!(guess(Some(64), None, &BTreeMap::new(), &[], ""), None);
    }

    #[test]
    fn network_gear() {
        let fp = TcpFp {
            window: 4128,
            ttl: 255,
            df: false,
            mss: Some(536),
            wscale: None,
            opts: "M".into(),
        };
        assert_eq!(
            guess(
                None,
                Some(&fp),
                &BTreeMap::new(),
                &[23],
                "Cisco Systems, Inc"
            )
            .unwrap()
            .name,
            NETDEV
        );
    }

    #[test]
    fn cpe_and_fingerprint_keys_are_not_os_evidence() {
        // The OpenSSH CPE vendor is "openbsd" on every platform.
        let ids = id(&[
            ("svc.22", "ssh OpenSSH 9.6 (protocol 2.0)"),
            ("svc.22.product", "OpenSSH"),
            ("svc.22.cpe", "cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*"),
            ("svc.8080.cpe", "cpe:2.3:a:apple:x:1:*:*:*:*:*:*:*"),
        ]);
        let g = guess(Some(61), None, &ids, &[22], "");
        assert!(
            g.as_ref().is_none_or(|g| g.name != BSD && g.name != APPLE),
            "{g:?}"
        );
    }

    #[test]
    fn smb_ntlm_version_names_windows_or_samba() {
        let g = guess(
            Some(120),
            None,
            &id(&[
                ("svc.445", "microsoft-ds SMB 3.1.1 (signing required)"),
                ("smb.445.os_version", "10.0.20348"),
            ]),
            &[445],
            "",
        )
        .unwrap();
        assert_eq!(g.name, WINDOWS);
        assert!(
            g.evidence.iter().any(|e| e.contains("Server 2022")),
            "{g:?}"
        );
        let samba = guess(
            Some(63),
            None,
            &id(&[
                (
                    "svc.445",
                    "microsoft-ds SMB 3.1.1 (signing enabled, not required)",
                ),
                ("smb.445.os_version", "6.1.0"),
            ]),
            &[445],
            "",
        )
        .unwrap();
        assert_eq!(samba.name, LINUX, "{samba:?}");
        assert_eq!(windows_release(10, 0, 22631), Some("11"));
        assert_eq!(windows_release(10, 0, 19045), Some("10"));
        assert_eq!(windows_release(4, 0, 1381), None);
    }

    #[test]
    fn embedded_and_network_ssh_servers() {
        let g = guess(
            Some(64),
            None,
            &id(&[("svc.22", "ssh dropbear_2022.83 (protocol 2.0)")]),
            &[22],
            "",
        )
        .unwrap();
        assert_eq!(g.name, EMBEDDED);
        let g = guess(
            Some(255),
            None,
            &id(&[("svc.22", "ssh Cisco-1.25 (protocol 2.0)")]),
            &[22],
            "",
        )
        .unwrap();
        assert_eq!(g.name, NETDEV);
    }
}
