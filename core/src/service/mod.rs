//! Service detection: banner grabbing, data-driven probes (data/probes.json plus an optional
//! user file), HTTP and TLS inspection and an SMB negotiate. Everything here only reads.
//!
//! This file holds the detection flow (`detect`, the send policy, the shared socket helpers);
//! the protocols live in the submodules: `probes` (probes.json matching), `http`, `ssh`,
//! `smb` (with `smb2` and `ntlm`), `rdp`, `lint` (the safety linter for probe files) and `unknown` (unidentified banners for
//! contributions).
use crate::{core::Gate, sendlog::PacketKind, tls};
use std::{collections::BTreeMap, net::IpAddr, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

mod http;
mod lint;
mod probes;
mod rdp;
mod smb;
mod ssh;
mod unknown;
pub mod workbench;

pub use http::parse_http;
pub use lint::{
    Issue as LintIssue, Level as LintLevel, error_count as lint_error_count, lint as lint_probes,
};
pub use probes::{Probe, ProbeDb, udp_probes};
pub use rdp::parse_rdp_standard_reply;
pub use smb::{parse_ntlm_challenge, parse_smb, parse_smb2_negotiate, smb1_accepted, smb2_fields};
pub use ssh::parse_kexinit;
pub use unknown::{UnknownExport, unknown_banners};

pub(crate) use http::http_outcome;
pub(crate) use ssh::kexinit_fields;

use http::http_get;
use probes::sanitize;
use rdp::rdp_nla_check;
use smb::smb_negotiate;
use ssh::ssh_fields;

pub type Fields = BTreeMap<String, String>;

const TLS_PORTS: [u16; 17] = [
    443, 465, 636, 853, 989, 990, 992, 993, 995, 2376, 3269, 5061, 5671, 6443, 8443, 8883, 9443,
];
/// Industrial and safety-relevant ports are left to the dedicated read-only identification:
/// generic probing (a banner wait, an HTTP request) could disturb fragile controllers.
/// 2222/tcp (EtherNet/IP I/O, Allen-Bradley CSP) is not listed: it is also a very common SSH
/// port, so service detection runs there in listen-only mode (`SendPolicy::SshOrSilent`) and
/// the findings treat it as industrial unless SSH answered. See `is_ot_port_candidate`.
const OT_PORTS: [u16; 16] = [
    102, 502, 789, 1911, 1962, 2404, 4840, 9600, 18245, 20000, 34962, 34963, 34964, 44818, 47808,
    48898,
];

/// Ports excluded from generic service detection.
pub fn is_ot_port(port: u16) -> bool {
    OT_PORTS.contains(&port)
}

/// Industrial ports including the ambiguous 2222/tcp; use this where "might be OT" matters
/// more than "must not be probed" (device classification, alerts).
pub fn is_ot_port_candidate(port: u16) -> bool {
    is_ot_port(port) || port == 2222
}

/// UDP ports that never receive a probe payload from `probes.json`: the industrial TCP list
/// plus UDP-only OT services (EtherNet/IP 2221-2223, BACnet/IP alternates 47808-47823,
/// Foundation Fieldbus HSE 1089-1091, KNXnet/IP 3671, MELSEC 5006/5007, CODESYS 1740-1743,
/// EtherCAT 34980, VxWorks WDB 17185) and the printer ports that are listen-only on TCP.
pub fn is_ot_udp_port(port: u16) -> bool {
    is_ot_port_candidate(port)
        || matches!(
            port,
            1089..=1091
                | 1740..=1743
                | 2221..=2223
                | 3671
                | 5006
                | 5007
                | 17185
                | 34980
                | 47808..=47823
                | 515
                | 9100..=9107
        )
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Service {
    pub name: String,
    pub product: String,
    pub version: String,
    pub info: String,
}
impl Service {
    pub fn summary(&self) -> String {
        let mut s = self.name.clone();
        for part in [&self.product, &self.version] {
            if !part.is_empty() {
                s.push(' ');
                s.push_str(part);
            }
        }
        if !self.info.is_empty() {
            s.push_str(&format!(" ({})", self.info));
        }
        s
    }
}

// ---- I/O helpers -------------------------------------------------------------------------

async fn connect(ip: IpAddr, port: u16, limit: Duration, gate: &Gate) -> Option<TcpStream> {
    gate.wait_for(PacketKind::TcpConnect, "service identification")
        .await;
    timeout(limit, TcpStream::connect((ip, port)))
        .await
        .ok()?
        .ok()
}

async fn read_some<S: AsyncRead + Unpin>(s: &mut S, first: Duration, max: usize) -> Vec<u8> {
    let mut data = vec![];
    let mut chunk = [0u8; 4096];
    let mut wait = first;
    while data.len() < max {
        match timeout(wait, s.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => data.extend_from_slice(&chunk[..n]),
            _ => break,
        }
        wait = Duration::from_millis(120);
    }
    data.truncate(max);
    data
}

async fn negotiate_once(
    ip: IpAddr,
    port: u16,
    limit: Duration,
    gate: &Gate,
    sent: (PacketKind, &str),
    request: &[u8],
) -> Vec<u8> {
    let Some(mut s) = connect(ip, port, limit, gate).await else {
        return vec![];
    };
    gate.note(sent.0, sent.1);
    let peer = std::net::SocketAddr::new(ip, port);
    gate.log().capture(peer, false, true, request, sent.1);
    if s.write_all(request).await.is_err() {
        return vec![];
    }
    let reply = read_some(&mut s, limit, 4096).await;
    gate.log().capture(peer, false, false, &reply, sent.1);
    reply
}

// ---- detection ---------------------------------------------------------------------------

/// What may be sent to a port before the device has identified itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SendPolicy {
    /// Banner wait, probes, HTTP and TLS fallbacks.
    Normal,
    /// Raw printer ports (JetDirect 9100-9107, LPD 515): whatever arrives is printed, so
    /// only wait for a banner and never send.
    ListenOnly,
    /// 2222/tcp: EtherNet/IP I/O (and legacy Allen-Bradley CSP) but also a common SSH port.
    /// Only wait for a banner; continue (SSH algorithm exchange) only after an SSH greeting.
    SshOrSilent,
}

fn send_policy(port: u16) -> SendPolicy {
    match port {
        515 | 9100..=9107 => SendPolicy::ListenOnly,
        2222 => SendPolicy::SshOrSilent,
        _ => SendPolicy::Normal,
    }
}

/// Service identification may send a payload (probe, HTTP request, TLS hello) to this port:
/// not the listen-only printer ports and not 2222.
pub(crate) fn sends_payload(port: u16) -> bool {
    send_policy(port) == SendPolicy::Normal
}

/// Banner wait without sending anything (except the SSH identification once the server has
/// greeted as SSH under `SshOrSilent`).
async fn detect_passive(
    ip: IpAddr,
    port: u16,
    limit: Duration,
    db: &ProbeDb,
    gate: &Gate,
    policy: SendPolicy,
) -> Option<Outcome> {
    let mut s = connect(ip, port, limit, gate).await?;
    let null = db.null_probe();
    let wait = null.map_or(Duration::from_millis(2500), |p| p.wait);
    let banner = read_some(&mut s, wait, 4096).await;
    let mut out = Outcome::default();
    if banner.is_empty() {
        return Some(out);
    }
    match null.and_then(|p| ProbeDb::identify(p, &banner)) {
        Some(svc) => {
            if svc.name == "ssh" && policy == SendPolicy::SshOrSilent {
                gate.note(PacketKind::SshBanner, "SSH identification and KEXINIT");
                out.fields.extend(ssh_fields(&mut s, &banner, limit).await);
            }
            out.service = Some(svc);
        }
        None => out.banner = Some(sanitize(&banner)),
    }
    Some(out)
}

#[derive(Debug, Default)]
pub struct Outcome {
    pub service: Option<Service>,
    pub banner: Option<String>,
    /// Keys are `section.field` (for example `http.server`, `tls.subject`).
    pub fields: Fields,
}

pub fn port_hint(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "domain",
        80 | 8080 | 8000 | 8008 | 8888 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        443 | 8443 => "https",
        445 => "microsoft-ds",
        993 => "imaps",
        995 => "pop3s",
        1433 => "ms-sql-s",
        1723 => "pptp",
        3306 => "mysql",
        3389 => "ms-wbt-server",
        5060 => "sip",
        5432 => "postgresql",
        5900 => "vnc",
        5985 | 5986 => "wsman",
        6379 => "redis",
        9100 => "jetdirect",
        _ => return None,
    })
}

async fn tls_service(
    ip: IpAddr,
    port: u16,
    limit: Duration,
    db: &ProbeDb,
    gate: &Gate,
    rounds: usize,
) -> Option<Outcome> {
    let tcp = connect(ip, port, limit, gate).await?;
    gate.note(PacketKind::TlsClientHello, "TLS handshake");
    let (mut stream, handshake) = match tls::wrap(tcp, ip, limit).await {
        Ok(ok) => ok,
        // rustls speaks only TLS 1.2/1.3. On a well-known TLS port a legacy-only server
        // (SSLv3 to TLS 1.1) is still TLS: let the raw enumeration decide.
        Err(e) if TLS_PORTS.contains(&port) => {
            let fields = tls::inspect_after(ip, port, limit, rounds, gate, Err(e))
                .await
                .ok()?;
            let mut out = Outcome {
                service: Some(Service {
                    name: "ssl/unknown".into(),
                    ..Default::default()
                }),
                ..Default::default()
            };
            for (k, v) in fields {
                out.fields.insert(format!("tls.{k}"), v);
            }
            return Some(out);
        }
        Err(_) => return None,
    };
    let mut out = Outcome::default();
    let banner = read_some(&mut stream, Duration::from_millis(350), 4096).await;
    let null = db.null_probe();
    if let Some(svc) = null
        .and_then(|p| ProbeDb::identify(p, &banner))
        .filter(|s| s.name != "http")
    {
        out.service = Some(Service {
            name: format!("ssl/{}", svc.name),
            ..svc
        });
    } else if let Some(h) = parse_http(&banner) {
        http_outcome(h, true, &mut out);
    } else if let Some(h) = {
        gate.note(PacketKind::HttpRequest, "GET /");
        http_get(
            &mut stream,
            ip,
            port,
            limit,
            gate.log(),
            "HTTP GET / (inside TLS, decrypted)",
        )
        .await
    } {
        http_outcome(h, true, &mut out);
    } else {
        out.service = Some(Service {
            name: "ssl/unknown".into(),
            ..Default::default()
        });
        if !banner.is_empty() {
            out.banner = Some(sanitize(&banner));
        }
    }
    // Close the session first, then reuse its handshake facts instead of handshaking again.
    drop(stream);
    if let Ok(fields) = tls::inspect_after(ip, port, limit, rounds, gate, Ok(handshake)).await {
        for (k, v) in fields {
            out.fields.insert(format!("tls.{k}"), v);
        }
    }
    Some(out)
}

/// Identifies the service on an open TCP port. Returns `None` when the port could not even be
/// connected to a second time (it closed, or the host rate-limited us).
pub async fn detect(
    ip: IpAddr,
    port: u16,
    limit: Duration,
    db: &ProbeDb,
    gate: &Gate,
    rounds: usize,
) -> Option<Outcome> {
    detect_with(ip, port, limit, db, gate, rounds, send_policy(port)).await
}

async fn detect_with(
    ip: IpAddr,
    port: u16,
    limit: Duration,
    db: &ProbeDb,
    gate: &Gate,
    rounds: usize,
    policy: SendPolicy,
) -> Option<Outcome> {
    if policy != SendPolicy::Normal {
        return detect_passive(ip, port, limit, db, gate, policy).await;
    }
    if TLS_PORTS.contains(&port)
        && let Some(out) = tls_service(ip, port, limit, db, gate, rounds).await
    {
        return Some(out);
    }
    let candidates: Vec<&Probe> = db
        .probes
        .iter()
        .filter(|p| p.ports.contains(&port))
        .collect();
    let null = db.null_probe();
    let hint = port_hint(port);
    let mut out = Outcome::default();
    // Servers that wait for the client (HTTP, the Windows RPC family) never greet first, so do
    // not spend the full banner wait on them. SSH on Windows can take 1.5 s to greet.
    let client_first = matches!(
        hint,
        Some("http" | "msrpc" | "netbios-ssn" | "wsman" | "microsoft-ds")
    );
    if client_first
        && candidates.is_empty()
        && port != 445
        && let Some(mut s) = connect(ip, port, limit, gate).await
        && let Some(h) = {
            gate.note(PacketKind::HttpRequest, "GET /");
            http_get(&mut s, ip, port, limit, gate.log(), "HTTP GET /").await
        }
    {
        http_outcome(h, false, &mut out);
        return Some(out);
    }
    let mut first = connect(ip, port, limit, gate).await?;
    let wait = if candidates.is_empty() && !client_first {
        null.map_or(Duration::from_millis(2500), |p| p.wait)
    } else {
        Duration::from_millis(300)
    };
    let banner = read_some(&mut first, wait, 4096).await;
    if !banner.is_empty() {
        if let Some(svc) = null.and_then(|p| ProbeDb::identify(p, &banner)) {
            if svc.name == "http"
                && let Some(h) = parse_http(&banner)
            {
                http_outcome(h, false, &mut out);
                return Some(out);
            }
            if svc.name == "ssh" {
                gate.note(PacketKind::SshBanner, "SSH identification and KEXINIT");
                out.fields
                    .extend(ssh_fields(&mut first, &banner, limit).await);
            }
            out.service = Some(svc);
            return Some(out);
        }
        out.banner = Some(sanitize(&banner));
    }
    let mut reusable = banner.is_empty().then_some(first);
    for probe in candidates {
        let mut stream = match reusable.take() {
            Some(s) => s,
            None => connect(ip, port, limit, gate).await?,
        };
        gate.note(PacketKind::ServiceProbe, probe.name.clone());
        let peer = std::net::SocketAddr::new(ip, port);
        gate.log()
            .capture(peer, false, true, &probe.payload, &probe.name);
        if stream.write_all(&probe.payload).await.is_err() {
            continue;
        }
        let reply = read_some(&mut stream, probe.wait, 4096).await;
        gate.log().capture(peer, false, false, &reply, &probe.name);
        if let Some(mut svc) = ProbeDb::identify(probe, &reply) {
            drop(stream);
            if probe.name == "rdp"
                && svc.info.starts_with("NLA")
                && let Some(extra) = rdp_nla_check(ip, port, limit, gate).await
            {
                svc.info = format!("{}; {extra}", svc.info);
            }
            out.service = Some(svc);
            return Some(out);
        }
    }
    if port == 445
        && let Some(smb) = smb_negotiate(ip, port, limit, gate).await
    {
        out.service = smb.service;
        out.fields.extend(smb.fields);
        return Some(out);
    }
    if let Some(mut s) = connect(ip, port, limit, gate).await
        && let Some(h) = {
            gate.note(PacketKind::HttpRequest, "GET /");
            http_get(&mut s, ip, port, limit, gate.log(), "HTTP GET /").await
        }
    {
        http_outcome(h, false, &mut out);
        return Some(out);
    }
    if !TLS_PORTS.contains(&port)
        && let Some(tls_out) = tls_service(ip, port, limit, db, gate, rounds).await
    {
        return Some(tls_out);
    }
    Some(out)
}

/// A cheap change detector for an open TCP port, for `--incremental`: one connection, and a hash
/// of what the service says first (its greeting banner) or, for a web server that waits for the
/// client, of its status line, `Server` header and title. `None` when there is nothing to hash (a
/// TLS port, or a silent one): such a port is identified in full every time. Sends nothing beyond
/// what service identification sends to the same port (the connection and, for web servers,
/// `GET /`), and nothing at all to printer ports.
pub async fn fingerprint(ip: IpAddr, port: u16, limit: Duration, gate: &Gate) -> Option<String> {
    let mut s = connect(ip, port, limit, gate).await?;
    let banner = read_some(&mut s, Duration::from_millis(300), 4096).await;
    if !banner.is_empty() {
        return Some(format!("banner:{}", crate::incremental::hash(&banner)));
    }
    if send_policy(port) == SendPolicy::Normal && !TLS_PORTS.contains(&port) {
        gate.note(PacketKind::HttpRequest, "GET /");
        let h = http_get(&mut s, ip, port, limit, gate.log(), "HTTP GET /").await?;
        let text = format!("{}|{}|{}|{}", h.status, h.server, h.powered_by, h.title);
        return Some(format!(
            "http:{}",
            crate::incremental::hash(text.as_bytes())
        ));
    }
    None
}

/// Identity entries for one port: `svc.<port>`, `http.<port>.server`, `tls.<port>.subject`, ...
pub fn identity_entries(port: u16, out: &Outcome) -> Fields {
    let mut f = Fields::new();
    match &out.service {
        Some(s) => {
            f.insert(format!("svc.{port}"), s.summary());
            if !s.product.is_empty() {
                f.insert(format!("svc.{port}.product"), s.product.clone());
            }
            if !s.version.is_empty() {
                f.insert(format!("svc.{port}.version"), s.version.clone());
            }
            if let Some(cpe) = crate::risk::cve_db().cpe(&s.product, &s.version) {
                f.insert(format!("svc.{port}.cpe"), cpe);
            }
        }
        None => {
            let hint = port_hint(port).map(|h| format!("unidentified (port suggests {h})"));
            f.insert(
                format!("svc.{port}"),
                hint.unwrap_or_else(|| "unidentified".into()),
            );
        }
    }
    if let Some(b) = &out.banner {
        f.insert(format!("banner.{port}"), b.clone());
    }
    for (key, value) in &out.fields {
        if let Some((section, rest)) = key.split_once('.') {
            f.insert(format!("{section}.{port}.{rest}"), value.clone());
        }
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    pub(super) async fn serve<F>(handler: F) -> u16
    where
        F: Fn(TcpStream) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
            + Send
            + Sync
            + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((s, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(handler(s));
            }
        });
        port
    }

    pub(super) async fn run(port: u16) -> Outcome {
        detect(
            "127.0.0.1".parse().unwrap(),
            port,
            Duration::from_secs(3),
            &ProbeDb::builtin(),
            &Gate::unlimited(),
            4,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn live_banner_http_and_unknown_services() {
        let ssh = serve(|mut s| {
            Box::pin(async move {
                let _ = s.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await;
            })
        })
        .await;
        let out = run(ssh).await;
        assert_eq!(
            out.service.unwrap().summary(),
            "ssh OpenSSH 9.6 (protocol 2.0)"
        );

        let http = serve(|mut s| Box::pin(async move {
            let mut buf = [0u8; 1024];
            let n = s.read(&mut buf).await.unwrap_or(0);
            assert!(String::from_utf8_lossy(&buf[..n]).starts_with("GET / HTTP/1.1"));
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.59\r\nConnection: close\r\n\r\n<title>Camera</title>").await;
        }))
        .await;
        let out = run(http).await;
        assert_eq!(
            out.service.as_ref().unwrap().summary(),
            "http lighttpd 1.4.59 (200 OK)"
        );
        let ids = identity_entries(http, &out);
        assert_eq!(ids[&format!("http.{http}.title")], "Camera");
        assert_eq!(ids[&format!("svc.{http}")], "http lighttpd 1.4.59 (200 OK)");

        let mute = serve(|s| {
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                drop(s);
            })
        })
        .await;
        let out = run(mute).await;
        assert!(out.service.is_none());
        assert!(identity_entries(mute, &out)[&format!("svc.{mute}")].starts_with("unidentified"));

        let odd = serve(|mut s| {
            Box::pin(async move {
                let _ = s.write_all(b"\x01\x02weird proprietary hello\r\n").await;
                tokio::time::sleep(Duration::from_millis(300)).await;
            })
        })
        .await;
        let out = run(odd).await;
        assert!(out.service.is_none());
        assert!(out.banner.unwrap().contains("weird proprietary hello"));
    }

    #[tokio::test]
    async fn closed_port_yields_no_outcome() {
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let out = detect(
            "127.0.0.1".parse().unwrap(),
            port,
            Duration::from_millis(300),
            &ProbeDb::builtin(),
            &Gate::unlimited(),
            2,
        )
        .await;
        assert!(out.is_none());
    }

    #[test]
    fn ot_ports_are_never_probed_generically() {
        for p in [102, 502, 44818, 4840, 47808] {
            assert!(is_ot_port(p));
            assert!(is_ot_port_candidate(p));
        }
        assert!(!is_ot_port(80));
        // 2222 is detected listen-only (SSH or nothing), but still counts as possibly OT.
        assert!(!is_ot_port(2222) && is_ot_port_candidate(2222));
    }

    #[test]
    fn printer_and_ambiguous_ports_get_a_restricted_send_policy() {
        for p in [515, 9100, 9101, 9107] {
            assert_eq!(send_policy(p), SendPolicy::ListenOnly, "{p}");
        }
        assert_eq!(send_policy(2222), SendPolicy::SshOrSilent);
        for p in [22, 80, 631, 9108, 9099] {
            assert_eq!(send_policy(p), SendPolicy::Normal, "{p}");
        }
    }

    /// A server that optionally greets, then records every byte the client sends until EOF.
    async fn recording_server(
        greeting: &'static [u8],
    ) -> (u16, tokio::sync::mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let port = serve(move |mut s| {
            let tx = tx.clone();
            Box::pin(async move {
                let _ = s.write_all(greeting).await;
                let mut got = vec![];
                let _ = timeout(Duration::from_secs(8), s.read_to_end(&mut got)).await;
                let _ = tx.send(got).await;
            })
        })
        .await;
        (port, rx)
    }

    async fn run_with(port: u16, policy: SendPolicy) -> Outcome {
        detect_with(
            "127.0.0.1".parse().unwrap(),
            port,
            Duration::from_secs(1),
            &ProbeDb::builtin(),
            &Gate::unlimited(),
            4,
            policy,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn listen_only_ports_receive_nothing() {
        // A silent printer port: no HTTP request, no TLS hello, no probe payload.
        let (port, mut rx) = recording_server(b"").await;
        let out = run_with(port, SendPolicy::ListenOnly).await;
        assert!(out.service.is_none());
        assert_eq!(
            rx.recv().await.unwrap(),
            b"",
            "a printer port was sent data"
        );
        assert!(rx.try_recv().is_err(), "only one connection is made");
        // Even an SSH greeting on a printer port is not answered.
        let (port, mut rx) = recording_server(b"SSH-2.0-OpenSSH_9.6\r\n").await;
        let out = run_with(port, SendPolicy::ListenOnly).await;
        assert_eq!(out.service.unwrap().name, "ssh");
        assert_eq!(rx.recv().await.unwrap(), b"");
        // 2222 without an SSH greeting: silent as well.
        let (port, mut rx) = recording_server(b"").await;
        assert!(
            run_with(port, SendPolicy::SshOrSilent)
                .await
                .service
                .is_none()
        );
        assert_eq!(rx.recv().await.unwrap(), b"");
    }

    #[tokio::test]
    async fn ssh_on_2222_is_fingerprinted() {
        let (port, mut rx) = recording_server(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n").await;
        let out = run_with(port, SendPolicy::SshOrSilent).await;
        assert_eq!(out.service.as_ref().unwrap().product, "OpenSSH");
        assert!(
            rx.recv()
                .await
                .unwrap()
                .starts_with(b"SSH-2.0-NetworkScope")
        );
    }

    /// tls_service must handshake once and never hold two connections open at a time
    /// (embedded TLS stacks often allow a single session).
    #[tokio::test]
    async fn tls_service_handshakes_once_and_serially() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["dev.local".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert.der().to_vec())],
            PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (full, open, peak) = (
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
            Arc::new(AtomicUsize::new(0)),
        );
        let counters = (full.clone(), open.clone(), peak.clone());
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (acceptor, (full, open, peak)) = (acceptor.clone(), counters.clone());
                tokio::spawn(async move {
                    // Give the server side time to notice a previous client close, so only
                    // connections the client really keeps open overlap.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    let now = open.fetch_add(1, SeqCst) + 1;
                    peak.fetch_max(now, SeqCst);
                    if let Ok(mut s) = acceptor.accept(tcp).await {
                        full.fetch_add(1, SeqCst);
                        // Stay open until the client closes the session.
                        let mut buf = [0u8; 256];
                        while let Ok(Ok(n)) =
                            timeout(Duration::from_secs(5), s.read(&mut buf)).await
                        {
                            if n == 0 {
                                break;
                            }
                        }
                    }
                    open.fetch_sub(1, SeqCst);
                });
            }
        });
        let out = tls_service(
            "127.0.0.1".parse().unwrap(),
            port,
            Duration::from_secs(2),
            &ProbeDb::builtin(),
            &Gate::unlimited(),
            4,
        )
        .await
        .unwrap();
        assert_eq!(out.fields["tls.san"], "dev.local", "{:?}", out.fields);
        assert!(out.fields.contains_key("tls.versions"));
        assert_eq!(full.load(SeqCst), 1, "exactly one full TLS handshake");
        assert_eq!(peak.load(SeqCst), 1, "connections overlapped");
    }
}
