//! Opt-in delivery of monitor alerts to destinations the user configured: an HTTP webhook (one
//! JSON POST per alert) and syslog (RFC 5424, over UDP or over TCP with RFC 6587 octet-counting
//! framing). Nothing is sent unless a destination is configured. Every network operation has a
//! bounded timeout; failures come back as warnings and never stop monitoring.
//!
//! HTTPS webhooks verify the server certificate against the operating system's certificate store
//! (`rustls-platform-verifier`), so the system's trusted CAs (and any corporate CA an
//! administrator installed) apply. There is no way to switch verification off: an untrusted or
//! mismatching certificate fails the delivery with a warning. Plain http:// stays available for
//! localhost and trusted LAN receivers.
//!
//! The connection code (`open_stream`, the OS-verified TLS configuration) is shared with the
//! opt-in update check in `update`.
use crate::{monitor::Alert, risk::Severity};
use rustls::{ClientConfig, ClientConnection, StreamOwned, pki_types::ServerName};
use rustls_platform_verifier::Verifier;
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

/// Default per-operation timeout (connect, write, read).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest time one destination may take per monitoring cycle; the rest of its alerts are
/// then skipped (and reported as not delivered).
const MAX_SINK_TIME: Duration = Duration::from_secs(30);
/// Longest syslog message (header and text); longer alert texts are cut.
const MAX_SYSLOG: usize = 2048;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Webhook {
    /// `https://` (TLS verified against the OS certificate store) instead of `http://`.
    pub(crate) tls: bool,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) path: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Syslog {
    host: String,
    port: u16,
    pub transport: Transport,
    /// Syslog facility (0-23); default 16 (local0).
    pub facility: u8,
}

/// One alert destination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Sink {
    Webhook(Webhook),
    Syslog(Syslog),
}

/// `host`, `host:port`, `[v6]` or `[v6]:port`.
fn host_port(text: &str, default_port: u16) -> Result<(String, u16), String> {
    let bad = || format!("Invalid host or port: {text}");
    if let Some(rest) = text.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or_else(bad)?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| bad())?,
            None if after.is_empty() => default_port,
            None => return Err(bad()),
        };
        return Ok((host.to_string(), port));
    }
    let (host, port) = match text.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h, p.parse().map_err(|_| bad())?),
        _ => (text, default_port),
    };
    if host.is_empty()
        || port == 0
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_:".contains(c))
    {
        return Err(bad());
    }
    Ok((host.to_string(), port))
}

impl Webhook {
    /// Parses `http://host[:port][/path]` or `https://host[:port][/path]`; `what` names the kind
    /// of URL in error messages ("Webhook", "Update").
    pub(crate) fn parse(url: &str, what: &str) -> Result<Self, String> {
        let url = url.trim();
        let (tls, rest) = match url.split_once("://") {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("http") => (false, rest),
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("https") => (true, rest),
            _ => {
                return Err(format!(
                    "{what} URL must start with http:// or https://: {url}"
                ));
            }
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if authority.contains('@') {
            return Err(format!("{what} URLs with user:password@ are not supported"));
        }
        if path.chars().any(|c| c.is_control() || c == ' ') {
            return Err(format!(
                "Invalid {} path: {path}",
                what.to_ascii_lowercase()
            ));
        }
        let (host, port) = host_port(authority, if tls { 443 } else { 80 })?;
        if tls && ServerName::try_from(host.clone()).is_err() {
            return Err(format!("Not a valid host name for HTTPS: {host}"));
        }
        Ok(Self {
            tls,
            host,
            port,
            path: path.to_string(),
        })
    }
}

impl Sink {
    /// `http://host[:port][/path]` (default port 80) or `https://host[:port][/path]` (default
    /// port 443, certificate verified against the OS certificate store).
    pub fn webhook(url: &str) -> Result<Self, String> {
        Webhook::parse(url, "Webhook").map(Self::Webhook)
    }
    /// `udp://host[:port]` (default port 514), `tcp://host[:port]` (default 601) or
    /// `host[:port]` (UDP).
    pub fn syslog(spec: &str) -> Result<Self, String> {
        let spec = spec.trim();
        let (transport, rest) = if let Some(r) = spec.strip_prefix("tcp://") {
            (Transport::Tcp, r)
        } else if let Some(r) = spec.strip_prefix("udp://") {
            (Transport::Udp, r)
        } else if spec.contains("://") {
            return Err(format!(
                "Syslog destination must be udp:// or tcp://: {spec}"
            ));
        } else {
            (Transport::Udp, spec)
        };
        let default_port = if transport == Transport::Tcp {
            601
        } else {
            514
        };
        let (host, port) = host_port(rest.trim_end_matches('/'), default_port)?;
        Ok(Self::Syslog(Syslog {
            host,
            port,
            transport,
            facility: 16,
        }))
    }
    /// What a stored queue knows the sink by ([`Outbox::restore`]): a hash of its label, since
    /// a webhook URL can carry a token.
    fn key(&self) -> String {
        crate::provenance::hash(self.label().as_bytes())
    }
    fn label(&self) -> String {
        match self {
            Self::Webhook(w) => format!(
                "webhook {}://{}:{}{}",
                if w.tls { "https" } else { "http" },
                w.host,
                w.port,
                w.path
            ),
            Self::Syslog(s) => format!(
                "syslog {}://{}:{}",
                if s.transport == Transport::Tcp {
                    "tcp"
                } else {
                    "udp"
                },
                s.host,
                s.port
            ),
        }
    }
}

fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("{host}: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("{host}: no address"));
    }
    Ok(addrs)
}

fn connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, String> {
    let mut last = String::new();
    for addr in resolve(host, port)? {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => {
                s.set_read_timeout(Some(timeout))
                    .map_err(|e| e.to_string())?;
                s.set_write_timeout(Some(timeout))
                    .map_err(|e| e.to_string())?;
                return Ok(s);
            }
            Err(e) => last = format!("{addr}: {e}"),
        }
    }
    Err(last)
}

/// The TLS client configuration for HTTPS webhooks: the same rustls version and ring crypto
/// provider as the TLS scanner, with the server certificate verified by the operating system
/// (Windows CryptoAPI, macOS Security.framework, the system CA bundle on Linux).
pub(crate) fn platform_tls_config() -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Verifier::new(provider.clone()).map_err(|e| e.to_string())?;
    tls_config(verifier, provider)
}

pub(crate) fn tls_config(
    verifier: Verifier,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<ClientConfig>, String> {
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// A readable message for a failed TLS handshake; certificate problems say what to fix.
pub(crate) fn tls_error(e: &io::Error, host: &str) -> String {
    if matches!(
        e.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        return "TLS handshake timed out".into();
    }
    let Some(err) = e
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    else {
        return format!("TLS handshake failed: {e}");
    };
    match err {
        rustls::Error::InvalidCertificate(_) => {
            let hint = if host.parse::<std::net::IpAddr>().is_ok() {
                "the certificate must be issued by a CA the system trusts and list this IP \
                 address as a subject alternative name"
            } else {
                "the certificate must be issued by a CA the system trusts and be valid for this \
                 host name"
            };
            format!("TLS certificate of {host} rejected ({err}); {hint}")
        }
        other => format!("TLS handshake failed: {other}"),
    }
}

/// Sends `request` over `stream`; Ok when the server answered 2xx.
fn round_trip(stream: &mut (impl Read + Write), request: &str) -> Result<(), String> {
    stream
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;
    // Only the status line is needed.
    let mut head = Vec::with_capacity(256);
    let mut buf = [0u8; 256];
    while !head.windows(2).any(|w| w == b"\r\n") && head.len() < 4096 {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => head.extend_from_slice(&buf[..n]),
            Err(e) => return Err(format!("no answer: {e}")),
        }
    }
    let line = String::from_utf8_lossy(&head);
    let line = line.lines().next().unwrap_or_default();
    let status: u16 = line
        .strip_prefix("HTTP/1.")
        .and_then(|r| r.get(2..5))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| {
            format!(
                "not an HTTP answer: {:?}",
                line.chars().take(60).collect::<String>()
            )
        })?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(format!("HTTP {status}"))
    }
}

/// A connected stream, plain or TLS, for the small HTTP clients of this crate (the webhook POST
/// and the update check).
pub(crate) trait Duplex: Read + Write {
    /// Tells the peer we are done (TLS close_notify); best effort.
    fn finish(&mut self) {}
}
impl Duplex for TcpStream {}
impl Duplex for StreamOwned<ClientConnection, TcpStream> {
    fn finish(&mut self) {
        self.conn.send_close_notify();
        let _ = self.flush();
    }
}

/// Connects to `host:port` and, for `tls`, completes the handshake with `config` (see
/// `platform_tls_config`; the certificate is verified by the operating system). Every socket
/// operation is bounded by `timeout`, and the handshake as a whole by one more.
pub(crate) fn open_stream(
    tls: bool,
    host: &str,
    port: u16,
    timeout: Duration,
    config: Option<&Arc<ClientConfig>>,
) -> Result<Box<dyn Duplex>, String> {
    let mut tcp = connect(host, port, timeout)?;
    if !tls {
        return Ok(Box::new(tcp));
    }
    let config = config.ok_or("TLS is not available")?;
    // An IP literal is sent without SNI and matched against the certificate's IP addresses.
    let name = ServerName::try_from(host.to_string())
        .map_err(|_| format!("{host}: not a valid host name for TLS"))?;
    let mut conn = ClientConnection::new(config.clone(), name).map_err(|e| e.to_string())?;
    // Handshake first, so a certificate error is reported as such.
    let deadline = Instant::now() + timeout;
    while conn.is_handshaking() {
        if Instant::now() > deadline {
            return Err("TLS handshake timed out".into());
        }
        conn.complete_io(&mut tcp)
            .map_err(|e| tls_error(&e, host))?;
    }
    Ok(Box::new(StreamOwned::new(conn, tcp)))
}

/// One POST of a JSON alert; Ok when the server answered 2xx. HTTPS needs `tls` (see
/// `platform_tls_config`).
fn post(
    w: &Webhook,
    body: &str,
    timeout: Duration,
    tls: Option<&Arc<ClientConfig>>,
) -> Result<(), String> {
    post_with(w, body, "application/json", &[], timeout, tls)
}

/// One POST with a content type and extra request headers; Ok when the server answered 2xx.
fn post_with(
    w: &Webhook,
    body: &str,
    content_type: &str,
    headers: &[(String, String)],
    timeout: Duration,
    tls: Option<&Arc<ClientConfig>>,
) -> Result<(), String> {
    let extra: String = headers
        .iter()
        .map(|(k, v)| format!("{k}: {v}\r\n"))
        .collect();
    let mut stream = open_stream(w.tls, &w.host, w.port, timeout, tls)?;
    let host = if w.host.contains(':') {
        format!("[{}]", w.host)
    } else {
        w.host.clone()
    };
    let host = if w.port == if w.tls { 443 } else { 80 } {
        host
    } else {
        format!("{host}:{}", w.port)
    };
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: network-scope\r\n\
         {extra}Content-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        w.path,
        body.len()
    );
    let result = round_trip(&mut stream, &request);
    stream.finish();
    result
}

/// A request header value from the user must not be able to end the header or start another.
fn header_value(name: &str, value: &str) -> Result<String, String> {
    if value.is_empty() || value.chars().any(|c| c.is_control() || c == ' ') {
        return Err(format!(
            "{name}: empty, or contains spaces or control characters"
        ));
    }
    Ok(value.to_string())
}

/// Whether `host` is this machine (plain HTTP is only allowed there when a token is sent).
pub(crate) fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// An opt-in push of an export to a server the user named (NetBox, Splunk HEC, Elastic): one
/// POST of `body` with `Authorization: <scheme> <token>`. The credential travels only in that
/// header, never in the URL: a URL with `user:password@`, a query string or a fragment is
/// refused. `https://` is verified against the operating system's certificate store like
/// webhooks; plain `http://` is accepted only for this machine (`localhost`, `127.0.0.0/8`,
/// `::1`), because a token must not cross a network in clear text. Bounded by `timeout`.
pub fn push(
    url: &str,
    auth: (&str, &str),
    content_type: &str,
    body: &str,
    timeout: Duration,
) -> Result<(), String> {
    let scheme = header_value("Authorization scheme", auth.0)?;
    let token = header_value("Token", auth.1)?;
    push_with_header(
        url,
        ("Authorization", &format!("{scheme} {token}")),
        content_type,
        body,
        timeout,
    )
}

/// [`push`] with the credential in a header of the caller's choice (`X-Api-Key: ...` for
/// Dependency-Track). The same rules: no query string or fragment, a token only over https://
/// (plain http:// to localhost only).
pub fn push_with_header(
    url: &str,
    header: (&str, &str),
    content_type: &str,
    body: &str,
    timeout: Duration,
) -> Result<(), String> {
    if url.contains(['?', '#']) {
        return Err(
            "The push URL must not contain a query string or fragment: credentials never go in a URL"
                .into(),
        );
    }
    let Sink::Webhook(w) = Sink::webhook(url)? else {
        return Err("Not an HTTP URL".into());
    };
    if !w.tls && !is_loopback_host(&w.host) {
        return Err(format!(
            "{}: a token is only sent over https:// (plain http:// is accepted for localhost only)",
            w.host
        ));
    }
    let name = header_value("Header name", header.0)?;
    // The value may hold a scheme and a token ("Bearer x"): one space is allowed between them.
    if header.1.is_empty() || header.1.chars().any(char::is_control) || header.1.contains("  ") {
        return Err(format!("{name}: empty, or contains control characters"));
    }
    let headers = [(name, header.1.to_string())];
    let config = if w.tls {
        Some(platform_tls_config().map_err(|e| format!("TLS setup failed: {e}"))?)
    } else {
        None
    };
    post_with(&w, body, content_type, &headers, timeout, config.as_ref())
}

/// syslog severity: critical 2, error 3, warning 4, notice 5, informational 6.
fn syslog_severity(s: Severity) -> u8 {
    match s {
        Severity::Critical => 2,
        Severity::High => 3,
        Severity::Medium => 4,
        Severity::Low => 5,
        Severity::Info => 6,
    }
}

/// UTC "YYYY-MM-DDTHH:MM:SSZ" (RFC 3339) of a Unix timestamp.
pub(crate) fn rfc3339(ts: i64) -> String {
    let (days, secs) = (ts.div_euclid(86_400), ts.rem_euclid(86_400));
    // civil-from-days (H. Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// Printable ASCII without spaces, at most `max` characters, "-" when empty (RFC 5424 header
/// fields).
fn header_field(text: &str, max: usize) -> String {
    let v: String = text
        .chars()
        .filter(|c| c.is_ascii_graphic())
        .take(max)
        .collect();
    if v.is_empty() { "-".into() } else { v }
}

fn local_hostname() -> String {
    let name = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_default();
    header_field(&name, 255)
}

/// An RFC 5424 message for one alert. Device-supplied text is flattened to one line (control
/// characters become spaces) and the message is cut to `MAX_SYSLOG` bytes.
fn syslog_line(s: &Syslog, a: &Alert, hostname: &str, pid: u32) -> String {
    let pri = u16::from(s.facility.min(23)) * 8 + u16::from(syslog_severity(a.severity));
    let mut line = format!(
        "<{pri}>1 {} {} network-scope {pid} {} - {} {}: {}",
        rfc3339(a.timestamp),
        header_field(hostname, 255),
        header_field(&a.kind, 32),
        a.severity.name(),
        a.subject,
        a.message
    );
    line = line
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if line.len() > MAX_SYSLOG {
        let mut end = MAX_SYSLOG;
        while !line.is_char_boundary(end) {
            end -= 1;
        }
        line.truncate(end);
    }
    line
}

fn send_syslog(s: &Syslog, alerts: &[Alert], timeout: Duration) -> Result<usize, String> {
    let (hostname, pid) = (local_hostname(), std::process::id());
    let lines = alerts.iter().map(|a| syslog_line(s, a, &hostname, pid));
    match s.transport {
        Transport::Udp => {
            let target = resolve(&s.host, s.port)?[0];
            let local: SocketAddr = if target.is_ipv4() {
                ([0, 0, 0, 0], 0).into()
            } else {
                ([0u16; 8], 0).into()
            };
            let socket = UdpSocket::bind(local).map_err(|e| e.to_string())?;
            socket
                .set_write_timeout(Some(timeout))
                .map_err(|e| e.to_string())?;
            let mut sent = 0;
            for line in lines {
                socket
                    .send_to(line.as_bytes(), target)
                    .map_err(|e| e.to_string())?;
                sent += 1;
            }
            Ok(sent)
        }
        Transport::Tcp => {
            let mut stream = connect(&s.host, s.port, timeout)?;
            let mut sent = 0;
            for line in lines {
                // RFC 6587 octet counting: "LEN SP MSG"
                stream
                    .write_all(format!("{} {line}", line.len()).as_bytes())
                    .map_err(|e| e.to_string())?;
                sent += 1;
            }
            stream.flush().map_err(|e| e.to_string())?;
            Ok(sent)
        }
    }
}

/// Sends `alerts` to every sink. Returns one warning per sink that failed; after the first
/// failure (or `MAX_SINK_TIME`) a sink's remaining alerts of this call are skipped.
pub fn deliver(sinks: &[Sink], alerts: &[Alert], timeout: Duration) -> Vec<String> {
    deliver_with(sinks, alerts, timeout, &platform_tls_config)
}

/// `deliver` with the TLS configuration for HTTPS webhooks supplied by `tls` (built once per
/// HTTPS sink and call). Tests inject a verifier that trusts an extra root; production always
/// passes `platform_tls_config`.
fn deliver_with(
    sinks: &[Sink],
    alerts: &[Alert],
    timeout: Duration,
    tls: &dyn Fn() -> Result<Arc<ClientConfig>, String>,
) -> Vec<String> {
    let mut warnings = vec![];
    if alerts.is_empty() {
        return warnings;
    }
    for sink in sinks {
        if let Err((sent, e)) = send(sink, alerts, timeout, tls) {
            warnings.push(format!(
                "{}: {e}; {} of {} alerts not delivered",
                sink.label(),
                alerts.len() - sent,
                alerts.len()
            ));
        }
    }
    warnings
}

/// Sends `alerts` to one sink, in order. On a failure: how many the sink took before it, and
/// why (after the first failure or `MAX_SINK_TIME` the rest is not tried).
fn send(
    sink: &Sink,
    alerts: &[Alert],
    timeout: Duration,
    tls: &dyn Fn() -> Result<Arc<ClientConfig>, String>,
) -> Result<(), (usize, String)> {
    match sink {
        Sink::Webhook(w) => {
            let start = Instant::now();
            let mut sent = 0;
            let mut error = None;
            let mut config = None;
            if w.tls {
                match tls() {
                    Ok(c) => config = Some(c),
                    Err(e) => error = Some(format!("TLS setup failed: {e}")),
                }
            }
            for a in alerts {
                if error.is_some() {
                    break;
                }
                if start.elapsed() > MAX_SINK_TIME {
                    error = Some("time limit for this cycle reached".to_string());
                    break;
                }
                let body = crate::schema::line("alert", a).unwrap_or_default();
                match post(w, &body, timeout, config.as_ref()) {
                    Ok(()) => sent += 1,
                    Err(e) => {
                        error = Some(e);
                        break;
                    }
                }
            }
            match error {
                None => Ok(()),
                Some(e) => Err((sent, e)),
            }
        }
        Sink::Syslog(s) => send_syslog(s, alerts, timeout)
            .map(|_| ())
            .map_err(|e| (0, e)),
    }
}

/// Most alerts kept per sink for a later try; the oldest are dropped beyond it.
pub const MAX_PENDING: usize = 1000;

/// [`deliver`] for a monitor that runs on: what a sink did not take (it was down, or the time
/// limit of the cycle was reached) is kept and sent first on the next call, in order. A sink
/// that fails gets every alert at least once when it is back; a syslog sink that failed in the
/// middle of a batch gets the batch again.
///
/// A monitor's queue ([`Outbox::restore`]) is also kept in its inventory, so a restart does not
/// lose it. The queue in memory is the one that counts: a write that fails (the inventory is
/// locked or gone, which is when alerts matter most) is reported and tried again with the next
/// call, and nothing is dropped for it. The stored copy is written after the sending, so a
/// monitor that is killed in between sends those alerts once more when it is back.
#[derive(Default)]
pub struct Outbox {
    /// Per sink, by position in the `sinks` of every call.
    pending: Vec<Vec<Alert>>,
    /// The inventory and the monitor's targets text the queue is stored under; `None`: memory
    /// only.
    stored: Option<(PathBuf, String)>,
    /// The stored copy is not what `pending` holds: its last write failed, or it has entries
    /// that were dropped when it was read.
    stale: bool,
    /// The stored copy could not be read yet (the inventory was locked when the monitor
    /// started): it is read before the first write, which would replace it otherwise.
    unread: bool,
}
impl Outbox {
    /// The queue that the monitor of `scope` (its targets text) left in the inventory `db`, for
    /// the sinks it has now. A sink is recognised by [`Sink::key`], not by its position: the
    /// list may have changed. What was kept for a sink that is no longer configured is dropped.
    /// An inventory that cannot be read now (it is locked) is read again before the queue is
    /// first written, so what it holds is sent later and not written over.
    pub fn restore(db: &Path, scope: &str, sinks: &[Sink]) -> Self {
        let mut outbox = Self {
            pending: vec![vec![]; sinks.len()],
            stored: Some((db.to_path_buf(), scope.to_string())),
            stale: false,
            unread: false,
        };
        outbox.unread = !outbox.read(sinks);
        outbox.stale |= outbox.unread;
        outbox
    }
    /// Puts the stored queue in front of what is pending (it is older). False when the
    /// inventory could not be read.
    fn read(&mut self, sinks: &[Sink]) -> bool {
        let Some((db, scope)) = self.stored.clone() else {
            return true;
        };
        // No inventory yet (a first run): nothing was kept.
        if !db.exists() {
            return true;
        }
        let entries = match crate::store::load_outbox(&db, &scope) {
            Ok(entries) => entries,
            Err(e) => {
                eprintln!("Undelivered alerts not read ({e}); tried again with the next cycle");
                return false;
            }
        };
        let keys: Vec<String> = sinks.iter().map(Sink::key).collect();
        let mut older = vec![vec![]; sinks.len()];
        for (key, alert) in entries {
            match keys.iter().position(|k| *k == key) {
                Some(sink) => older[sink].push(alert),
                // Its sink is gone: the next write leaves the entry out.
                None => self.stale = true,
            }
        }
        self.pending.resize_with(sinks.len(), Vec::new);
        for (pending, mut older) in self.pending.iter_mut().zip(older) {
            older.append(pending);
            *pending = older;
        }
        true
    }
    /// Writes the queue to the inventory it was restored from (see the type: best effort).
    fn store(&mut self, sinks: &[Sink]) {
        if self.unread {
            self.unread = !self.read(sinks);
            if self.unread {
                self.stale = true;
                return;
            }
        }
        let Some((db, scope)) = &self.stored else {
            return;
        };
        let queues: Vec<(String, &[Alert])> = sinks
            .iter()
            .zip(&self.pending)
            .filter(|(_, pending)| !pending.is_empty())
            .map(|(sink, pending)| (sink.key(), pending.as_slice()))
            .collect();
        self.stale = match crate::store::save_outbox(db, scope, &queues) {
            Ok(()) => false,
            Err(e) => {
                eprintln!(
                    "Undelivered alerts not saved ({e}); they stay in memory and are saved with the next cycle"
                );
                true
            }
        };
    }
    /// One warning per sink that failed, with what is kept for the next call.
    pub fn deliver(&mut self, sinks: &[Sink], alerts: &[Alert], timeout: Duration) -> Vec<String> {
        self.deliver_with(sinks, alerts, timeout, &platform_tls_config)
    }
    fn deliver_with(
        &mut self,
        sinks: &[Sink],
        alerts: &[Alert],
        timeout: Duration,
        tls: &dyn Fn() -> Result<Arc<ClientConfig>, String>,
    ) -> Vec<String> {
        self.pending.resize_with(sinks.len(), Vec::new);
        let mut warnings = vec![];
        // Whether a queue differs from what it held before this call (the stored copy).
        let mut changed = false;
        for (sink, pending) in sinks.iter().zip(&mut self.pending) {
            let kept = pending.len();
            pending.extend_from_slice(alerts);
            if pending.is_empty() {
                continue;
            }
            let Err((sent, e)) = send(sink, pending, timeout, tls) else {
                pending.clear();
                changed |= kept > 0;
                continue;
            };
            changed |= sent > 0 || !alerts.is_empty();
            pending.drain(..sent);
            let dropped = pending.len().saturating_sub(MAX_PENDING);
            pending.drain(..dropped);
            warnings.push(format!(
                "{}: {e}; {} alerts not delivered, kept for the next cycle{}",
                sink.label(),
                pending.len(),
                if dropped > 0 {
                    format!(" ({dropped} older ones dropped)")
                } else {
                    String::new()
                }
            ));
        }
        if changed || self.stale {
            self.store(sinks);
        }
        warnings
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::net::TcpListener;

    fn alert(kind: &str, message: &str) -> Alert {
        Alert {
            timestamp: 1_700_000_000,
            severity: Severity::High,
            kind: kind.into(),
            subject: "10.0.0.5".into(),
            message: message.into(),
        }
    }

    #[test]
    fn destinations_parse() {
        assert_eq!(
            Sink::webhook("http://hooks.local:8080/a/b?x=1").unwrap(),
            Sink::Webhook(Webhook {
                tls: false,
                host: "hooks.local".into(),
                port: 8080,
                path: "/a/b?x=1".into()
            })
        );
        assert_eq!(
            Sink::webhook("http://[::1]").unwrap(),
            Sink::Webhook(Webhook {
                tls: false,
                host: "::1".into(),
                port: 80,
                path: "/".into()
            })
        );
        // https: default port 443, scheme case-insensitive, IPv6 brackets, explicit port
        assert_eq!(
            Sink::webhook("https://hooks.example.com/a/b?x=1").unwrap(),
            Sink::Webhook(Webhook {
                tls: true,
                host: "hooks.example.com".into(),
                port: 443,
                path: "/a/b?x=1".into()
            })
        );
        assert_eq!(
            Sink::webhook(" HTTPS://[2001:db8::1]:8443 ").unwrap(),
            Sink::Webhook(Webhook {
                tls: true,
                host: "2001:db8::1".into(),
                port: 8443,
                path: "/".into()
            })
        );
        assert_eq!(
            Sink::webhook("https://[::1]").unwrap(),
            Sink::Webhook(Webhook {
                tls: true,
                host: "::1".into(),
                port: 443,
                path: "/".into()
            })
        );
        let Sink::Webhook(w) = Sink::webhook("http://Hooks.local:80/").unwrap() else {
            panic!()
        };
        assert!(!w.tls && w.port == 80);
        for bad in [
            "ftp://x/",
            "ws://x/",
            "hooks.local/x",
            "//hooks.local/x",
            "https://",
            "https://u:p@x/",
            "https://x:0/",
            "https://x y/",
            "https:/x/",
            "https://-bad-.example/",
            "http://",
            "http://a b/",
            "http://u:p@x/",
            "http://x:99999/",
        ] {
            assert!(Sink::webhook(bad).is_err(), "{bad}");
        }
        assert_eq!(
            Sink::syslog("tcp://log.local").unwrap(),
            Sink::Syslog(Syslog {
                host: "log.local".into(),
                port: 601,
                transport: Transport::Tcp,
                facility: 16
            })
        );
        let Sink::Syslog(s) = Sink::syslog("10.0.0.1:1514").unwrap() else {
            panic!()
        };
        assert_eq!((s.port, s.transport), (1514, Transport::Udp));
        let Sink::Syslog(s) = Sink::syslog("udp://[fe80::1]").unwrap() else {
            panic!()
        };
        assert_eq!((s.host.as_str(), s.port), ("fe80::1", 514));
        assert!(Sink::syslog("http://x").is_err());
    }

    #[test]
    fn syslog_messages_follow_rfc_5424() {
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        let Sink::Syslog(s) = Sink::syslog("udp://127.0.0.1").unwrap() else {
            panic!()
        };
        let a = alert("rogue-dhcp", "Unexpected DHCP server\r\n<13>1 forged line");
        assert_eq!(
            syslog_line(&s, &a, "scan box", 42),
            // local0 (16) * 8 + err (3) = 131
            "<131>1 2023-11-14T22:13:20Z scanbox network-scope 42 rogue-dhcp - high 10.0.0.5: \
             Unexpected DHCP server  <13>1 forged line"
        );
        let long = alert("new-finding", &"é".repeat(5000));
        let line = syslog_line(&s, &long, "h", 1);
        assert!(line.len() <= MAX_SYSLOG && line.ends_with('é'));
    }

    #[test]
    fn syslog_over_udp_and_tcp() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let port = receiver.local_addr().unwrap().port();
        let sink = Sink::syslog(&format!("udp://127.0.0.1:{port}")).unwrap();
        let alerts = [alert("port-opened", "one"), alert("port-opened", "two")];
        assert!(deliver(&[sink], &alerts, Duration::from_secs(2)).is_empty());
        let mut buf = [0u8; 4096];
        let n = receiver.recv(&mut buf).unwrap();
        let first = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(first.starts_with("<131>1 2023-11-14T22:13:20Z "), "{first}");
        assert!(first.ends_with("10.0.0.5: one"), "{first}");

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            let mut all = String::new();
            c.read_to_string(&mut all).unwrap();
            all
        });
        let sink = Sink::syslog(&format!("tcp://127.0.0.1:{port}")).unwrap();
        assert!(deliver(&[sink], &alerts, Duration::from_secs(2)).is_empty());
        let got = server.join().unwrap();
        let (len, rest) = got.split_once(' ').unwrap();
        let len: usize = len.parse().unwrap();
        assert!(rest[..len].ends_with("10.0.0.5: one"), "{got}");
        assert!(
            rest[len..].contains(" <131>1 ") && got.ends_with("two"),
            "{got}"
        );
    }

    /// Reads one HTTP request from `c` (empty if the connection fails) and answers `status`.
    fn serve_http(c: &mut (impl Read + Write), status: &str) -> String {
        let mut req = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = c.read(&mut buf).unwrap_or(0);
            req.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&req).to_string();
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let len: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("Content-Length: "))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                if body.len() >= len {
                    break;
                }
            }
            if n == 0 {
                break;
            }
        }
        let _ = c.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n").as_bytes());
        let _ = c.flush();
        String::from_utf8_lossy(&req).to_string()
    }

    /// A one-shot HTTP server: returns the request it read; answers with `status`.
    fn http_server(status: &'static str) -> (u16, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            serve_http(&mut c, status)
        });
        (port, handle)
    }

    /// A CA and a server certificate it issued for `ip` (DER), plus the server's key.
    pub(crate) fn test_pki(
        ip: &str,
    ) -> (
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
    ) {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Network Scope test CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let mut leaf_params = rcgen::CertificateParams::new(vec![ip.to_string()]).unwrap();
        leaf_params.is_ca = rcgen::IsCa::ExplicitNoCa;
        leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
        (ca.der().clone(), leaf.der().clone(), key.into())
    }

    /// A one-shot HTTPS server on 127.0.0.1 presenting `cert`. Returns the request it read
    /// (empty when the handshake failed).
    fn https_server(
        cert: rustls::pki_types::CertificateDer<'static>,
        key: rustls::pki_types::PrivateKeyDer<'static>,
        status: &'static str,
    ) -> (u16, std::thread::JoinHandle<String>) {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let conn = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            let mut tls = StreamOwned::new(conn, tcp);
            serve_http(&mut tls, status)
        });
        (port, handle)
    }

    /// The production TLS setup, except that `root` is trusted in addition to the system's CAs.
    pub(crate) fn trusting(
        root: &rustls::pki_types::CertificateDer<'static>,
    ) -> impl Fn() -> Result<Arc<ClientConfig>, String> {
        let root = root.clone();
        move || {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let verifier =
                Verifier::new_with_extra_roots([root.clone()], provider.clone()).unwrap();
            tls_config(verifier, provider)
        }
    }

    #[test]
    fn webhook_posts_json_and_reports_failures() {
        let (port, server) = http_server("204 No Content");
        let sink = Sink::webhook(&format!("http://127.0.0.1:{port}/hook")).unwrap();
        let a = alert("new-device", "New device 10.0.0.5");
        assert!(deliver(&[sink], std::slice::from_ref(&a), Duration::from_secs(2)).is_empty());
        let req = server.join().unwrap();
        assert!(req.starts_with("POST /hook HTTP/1.1\r\n"), "{req}");
        assert!(req.contains(&format!("Host: 127.0.0.1:{port}\r\n")));
        assert!(req.contains("Content-Type: application/json\r\n"));
        let body = req.split("\r\n\r\n").nth(1).unwrap();
        let back: Alert = serde_json::from_str(body).unwrap();
        assert_eq!(back, a);

        // an error status is a failure; the remaining alerts of the cycle are skipped
        let (port, server) = http_server("500 Internal Server Error");
        let sink = Sink::webhook(&format!("http://127.0.0.1:{port}/")).unwrap();
        let w = deliver(
            &[sink],
            &[a.clone(), a.clone(), a.clone()],
            Duration::from_secs(2),
        );
        server.join().unwrap();
        assert_eq!(w.len(), 1);
        assert!(
            w[0].contains("HTTP 500") && w[0].contains("3 of 3"),
            "{w:?}"
        );
    }

    #[test]
    fn an_outbox_sends_what_a_sink_did_not_take_with_the_next_call() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // The receiver fails the first request and is back for the next two.
        let server = std::thread::spawn(move || {
            [
                "500 Internal Server Error",
                "204 No Content",
                "204 No Content",
            ]
            .map(|status| {
                let (mut c, _) = listener.accept().unwrap();
                c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                serve_http(&mut c, status)
            })
        });
        let sinks = [Sink::webhook(&format!("http://127.0.0.1:{port}/")).unwrap()];
        let (first, second) = (alert("new-device", "one"), alert("port-opened", "two"));
        let mut outbox = Outbox::default();
        let t = Duration::from_secs(2);
        let w = outbox.deliver(&sinks, std::slice::from_ref(&first), t);
        assert!(
            w.len() == 1 && w[0].contains("1 alerts not delivered, kept"),
            "{w:?}"
        );
        assert!(
            outbox
                .deliver(&sinks, std::slice::from_ref(&second), t)
                .is_empty()
        );
        // Nothing is left: a third call has nothing to send (and no server to send it to).
        assert!(outbox.deliver(&sinks, &[], t).is_empty());
        let messages = server.join().unwrap().map(|request| {
            let body = request.split("\r\n\r\n").nth(1).unwrap();
            serde_json::from_str::<Alert>(body).unwrap().message
        });
        assert_eq!(messages, ["one", "one", "two"]);
    }

    /// A webhook receiver on a loopback port that answers one request per status, in order.
    fn receiver(
        statuses: &'static [&'static str],
    ) -> (Vec<Sink>, std::thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            statuses
                .iter()
                .map(|status| {
                    let (mut c, _) = listener.accept().unwrap();
                    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                    let request = serve_http(&mut c, status);
                    let body = request.split("\r\n\r\n").nth(1).unwrap();
                    serde_json::from_str::<Alert>(body).unwrap().message
                })
                .collect()
        });
        let sink = Sink::webhook(&format!("http://127.0.0.1:{port}/hook?token=secret")).unwrap();
        (vec![sink], server)
    }

    #[test]
    fn a_restarted_monitor_sends_what_the_last_run_could_not_deliver() {
        let dir = std::env::temp_dir().join(format!("ns-outbox-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("inventory.sqlite");
        let stored = |scope: &str| crate::store::load_outbox(&db, scope).unwrap();
        let (scope, t) = ("10.0.0.0/24", Duration::from_secs(2));
        // The receiver is down for the first run and back for the second.
        let (sinks, server) = receiver(&["500 Internal Server Error", "204 No Content"]);
        let mut outbox = Outbox::restore(&db, scope, &sinks);
        assert!(!db.exists(), "nothing to keep: nothing is written");
        let w = outbox.deliver(&sinks, &[alert("new-device", "one")], t);
        assert!(
            w.len() == 1 && w[0].contains("kept for the next cycle"),
            "{w:?}"
        );
        let kept = stored(scope);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].1.message, "one");
        // The sink is stored as a hash: neither the address nor the token is in the file.
        assert_eq!(kept[0].0, sinks[0].key());
        assert!(kept[0].0.starts_with("sha256:") && !kept[0].0.contains("secret"));
        let file = String::from_utf8_lossy(&std::fs::read(&db).unwrap()).into_owned();
        assert!(!file.contains("token=secret") && !file.contains("127.0.0.1"));
        // A monitor of other targets on the same inventory has a queue of its own.
        let mut other = Outbox::restore(&db, "192.168.1.0/24", &sinks);
        assert!(other.deliver(&sinks, &[], t).is_empty());
        assert_eq!(stored(scope).len(), 1);
        // The monitor is restarted: the queue comes from the inventory and goes out.
        drop(outbox);
        let mut outbox = Outbox::restore(&db, scope, &sinks);
        assert!(outbox.deliver(&sinks, &[], t).is_empty());
        assert!(stored(scope).is_empty());
        assert_eq!(server.join().unwrap(), ["one", "one"]);
        // What was kept for a sink that is no longer configured is dropped, not sent elsewhere.
        let gone = [alert("port-opened", "for the old receiver")];
        crate::store::save_outbox(&db, scope, &[("sha256:gone".into(), &gone[..])]).unwrap();
        let mut outbox = Outbox::restore(&db, scope, &sinks);
        assert!(outbox.deliver(&sinks, &[], t).is_empty());
        assert!(stored(scope).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_queue_that_could_not_be_read_at_the_start_is_read_before_it_is_written() {
        let dir = std::env::temp_dir().join(format!("ns-outbox-unread-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("inventory.sqlite");
        let (scope, t) = ("10.0.0.0/24", Duration::from_secs(2));
        let (sinks, server) = receiver(&[
            "500 Internal Server Error",
            "204 No Content",
            "204 No Content",
        ]);
        // The last run left one alert, and the inventory was locked when this run started.
        let left = [alert("new-device", "stored")];
        crate::store::save_outbox(&db, scope, &[(sinks[0].key(), &left[..])]).unwrap();
        let mut outbox = Outbox {
            pending: vec![vec![]],
            stored: Some((db.clone(), scope.to_string())),
            stale: true,
            unread: true,
        };
        // The receiver is down: the new alert is kept, behind the one that was stored.
        outbox.deliver(&sinks, &[alert("new-device", "new")], t);
        let kept: Vec<String> = (crate::store::load_outbox(&db, scope).unwrap().into_iter())
            .map(|(_, a)| a.message)
            .collect();
        assert_eq!(kept, ["stored", "new"]);
        assert!(outbox.deliver(&sinks, &[], t).is_empty());
        assert_eq!(server.join().unwrap(), ["new", "stored", "new"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_outbox_that_cannot_be_saved_keeps_its_alerts_in_memory() {
        // A file where the inventory's folder should be: every write of the queue fails.
        let blocker =
            std::env::temp_dir().join(format!("ns-outbox-blocked-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&blocker);
        let _ = std::fs::remove_file(&blocker);
        std::fs::write(&blocker, b"").unwrap();
        let db = blocker.join("inventory.sqlite");
        let (sinks, server) = receiver(&["500 Internal Server Error", "204 No Content"]);
        let mut outbox = Outbox::restore(&db, "10.0.0.0/24", &sinks);
        let t = Duration::from_secs(2);
        let w = outbox.deliver(&sinks, &[alert("new-device", "one")], t);
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(outbox.stale && outbox.pending[0].len() == 1);
        assert!(outbox.deliver(&sinks, &[], t).is_empty());
        assert!(outbox.pending[0].is_empty());
        assert_eq!(server.join().unwrap(), ["one", "one"]);
        std::fs::remove_file(&blocker).unwrap();
    }

    // The macOS verifier (Security.framework) has strict rules for test certificates (validity
    // period, trust settings) that have not been checked here; the rejection tests below still
    // run everywhere.
    #[cfg(not(target_vendor = "apple"))]
    #[test]
    fn https_webhook_with_a_trusted_certificate_is_delivered() {
        let (ca, cert, key) = test_pki("127.0.0.1");
        let (port, server) = https_server(cert, key, "204 No Content");
        let sink = Sink::webhook(&format!("https://127.0.0.1:{port}/hook")).unwrap();
        let a = alert("new-device", "New device 10.0.0.5");
        let w = deliver_with(
            &[sink],
            std::slice::from_ref(&a),
            Duration::from_secs(5),
            &trusting(&ca),
        );
        assert!(w.is_empty(), "{w:?}");
        let req = server.join().unwrap();
        assert!(req.starts_with("POST /hook HTTP/1.1\r\n"), "{req}");
        assert!(req.contains(&format!("Host: 127.0.0.1:{port}\r\n")));
        let back: Alert = serde_json::from_str(req.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn https_webhook_with_an_untrusted_certificate_is_rejected() {
        // Valid for 127.0.0.1, but issued by a CA that is not in the system's certificate
        // store: the production verifier must refuse it and nothing may be sent.
        let (_, cert, key) = test_pki("127.0.0.1");
        let (port, server) = https_server(cert, key, "204 No Content");
        let sink = Sink::webhook(&format!("https://127.0.0.1:{port}/hook")).unwrap();
        let w = deliver(
            &[sink],
            &[alert("new-device", "x"), alert("new-device", "y")],
            Duration::from_secs(5),
        );
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(
            w[0].contains("certificate") && w[0].contains("rejected") && w[0].contains("2 of 2"),
            "{w:?}"
        );
        assert!(w[0].contains("subject alternative name"), "{w:?}");
        assert_eq!(
            server.join().unwrap(),
            "",
            "no request may reach the server"
        );

        // A self-signed leaf certificate (no CA) is refused as well.
        let key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let der = rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der());
        let (port, server) = https_server(leaf.der().clone(), der.into(), "204 No Content");
        let sink = Sink::webhook(&format!("https://127.0.0.1:{port}/")).unwrap();
        let w = deliver(&[sink], &[alert("new-device", "x")], Duration::from_secs(5));
        assert!(w.len() == 1 && w[0].contains("rejected"), "{w:?}");
        assert_eq!(server.join().unwrap(), "");
    }

    #[test]
    fn https_webhook_rejects_a_certificate_for_another_address() {
        // Trusted issuer, but the certificate only covers 10.0.0.1, not the IP we connect to.
        let (ca, cert, key) = test_pki("10.0.0.1");
        let (port, server) = https_server(cert, key, "204 No Content");
        let sink = Sink::webhook(&format!("https://127.0.0.1:{port}/")).unwrap();
        let w = deliver_with(
            &[sink],
            &[alert("new-device", "x")],
            Duration::from_secs(5),
            &trusting(&ca),
        );
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(
            w[0].contains("rejected") && w[0].contains("IP address"),
            "{w:?}"
        );
        assert_eq!(server.join().unwrap(), "");
    }

    #[test]
    fn https_webhook_to_a_plain_http_server_fails_cleanly() {
        let (port, server) = http_server("204 No Content");
        let sink = Sink::webhook(&format!("https://127.0.0.1:{port}/")).unwrap();
        let w = deliver(&[sink], &[alert("new-device", "x")], Duration::from_secs(2));
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("TLS"), "{w:?}");
        let _ = server.join();
    }

    #[test]
    fn unreachable_and_silent_webhooks_fail_within_the_timeout() {
        // refused: a port that was just free
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let sink = Sink::webhook(&format!("http://127.0.0.1:{port}/")).unwrap();
        let alerts = vec![alert("new-device", "x"); 4];
        let w = deliver(&[sink], &alerts, Duration::from_millis(500));
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(w[0].contains("4 of 4"), "{w:?}");
        // accepts but never answers: bounded by the read timeout, and only tried once
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let sink = Sink::webhook(&format!("http://127.0.0.1:{port}/")).unwrap();
        let start = Instant::now();
        let w = deliver(&[sink], &alerts, Duration::from_millis(300));
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "{:?}",
            start.elapsed()
        );
        assert!(
            w[0].contains("no answer") && w[0].contains("4 of 4"),
            "{w:?}"
        );
        drop(listener);
        // nothing to send: nothing is attempted
        assert!(
            deliver(
                &[Sink::webhook("http://192.0.2.1/").unwrap()],
                &[],
                DEFAULT_TIMEOUT
            )
            .is_empty()
        );
    }
}
