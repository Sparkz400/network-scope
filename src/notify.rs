//! Opt-in delivery of monitor alerts to destinations the user configured: an HTTP webhook (one
//! JSON POST per alert) and syslog (RFC 5424, over UDP or over TCP with RFC 6587 octet-counting
//! framing). Nothing is sent unless a destination is configured. Every network operation has a
//! bounded timeout; failures come back as warnings and never stop monitoring.
//!
//! HTTPS webhooks are not supported: no trusted certificate store is bundled, and posting alerts
//! over TLS without verifying the server would only look secure. Use an http:// relay on a
//! trusted host (or localhost) instead.
use crate::{monitor::Alert, risk::Severity};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket},
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
    host: String,
    port: u16,
    path: String,
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

impl Sink {
    /// `http://host[:port][/path]`.
    pub fn webhook(url: &str) -> Result<Self, String> {
        let url = url.trim();
        if url.to_ascii_lowercase().starts_with("https://") {
            return Err(
                "HTTPS webhooks are not supported (no trusted certificate store is bundled); \
                 use an http:// URL, e.g. a relay on localhost"
                    .into(),
            );
        }
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| format!("Webhook URL must start with http://: {url}"))?;
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if authority.contains('@') {
            return Err("Webhook URLs with user:password@ are not supported".into());
        }
        if path.chars().any(|c| c.is_control() || c == ' ') {
            return Err(format!("Invalid webhook path: {path}"));
        }
        let (host, port) = host_port(authority, 80)?;
        Ok(Self::Webhook(Webhook {
            host,
            port,
            path: path.to_string(),
        }))
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
    fn label(&self) -> String {
        match self {
            Self::Webhook(w) => format!("webhook http://{}:{}{}", w.host, w.port, w.path),
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

/// One POST; Ok when the server answered 2xx.
fn post(w: &Webhook, body: &str, timeout: Duration) -> Result<(), String> {
    let mut stream = connect(&w.host, w.port, timeout)?;
    let host = if w.host.contains(':') {
        format!("[{}]", w.host)
    } else {
        w.host.clone()
    };
    let host = if w.port == 80 {
        host
    } else {
        format!("{host}:{}", w.port)
    };
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: network-scope\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        w.path,
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| e.to_string())?;
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
fn rfc3339(ts: i64) -> String {
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
    let mut warnings = vec![];
    if alerts.is_empty() {
        return warnings;
    }
    for sink in sinks {
        let result = match sink {
            Sink::Webhook(w) => {
                let start = Instant::now();
                let mut sent = 0;
                let mut error = None;
                for a in alerts {
                    if start.elapsed() > MAX_SINK_TIME {
                        error = Some("time limit for this cycle reached".to_string());
                        break;
                    }
                    let body = serde_json::to_string(a).unwrap_or_default();
                    match post(w, &body, timeout) {
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
        };
        if let Err((sent, e)) = result {
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

#[cfg(test)]
mod tests {
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
                host: "hooks.local".into(),
                port: 8080,
                path: "/a/b?x=1".into()
            })
        );
        assert_eq!(
            Sink::webhook("http://[::1]").unwrap(),
            Sink::Webhook(Webhook {
                host: "::1".into(),
                port: 80,
                path: "/".into()
            })
        );
        assert!(
            Sink::webhook("https://x/")
                .unwrap_err()
                .contains("not supported")
        );
        for bad in [
            "ftp://x/",
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

    /// A one-shot HTTP server: returns the request it read; answers with `status`.
    fn http_server(status: &'static str) -> (u16, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
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
            let _ =
                c.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\n\r\n").as_bytes());
            String::from_utf8_lossy(&req).to_string()
        });
        (port, handle)
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
