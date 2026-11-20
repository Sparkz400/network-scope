//! Favicon fetch (opt-in `--favicon`, ROADMAP L70): one `GET /favicon.ico` per web port, hashed
//! with the Shodan-compatible MurmurHash3 ([`crate::pivot::favicon_hash`]) into
//! `http.<port>.favicon_mmh3`.
//!
//! This is a packet sender, so it follows the rules of the other ones:
//!
//! * **Opt-in and not in Safe Mode**, like JARM: it runs only with `--favicon --services` and
//!   `--fast` ([`enabled`]). The scan's ordinary `GET /` is not affected.
//! * **Only web ports that already answered as web servers**: ports whose identification found
//!   `http` or `https`, never industrial or printer ports, and not on a host that this scan found
//!   to be industrial (an OT port is open, an OT protocol answered): [`candidates`]. That only
//!   knows what the scan saw: a PLC's web port scanned without `--ot` and without its industrial
//!   ports is an ordinary web server to it, as it is to the scan's `GET /`.
//! * **One request per port**, one port after the other, through the rate gate
//!   (`Gate::wait_for(PacketKind::HttpRequest, DETAIL)`), listed in the dry run
//!   ([`crate::plan`]) and recorded by `--sent-log` and `scan --record`. The scheduler stops when
//!   the back-off governor pauses the host and reports a port that stopped answering to it.
//! * **Bounded**: the response is read up to [`MAX_RESPONSE`] bytes within the scan's port
//!   timeout per read; redirects are not followed; a body above [`MAX_BODY`] gives no hash.
//!
//! A hash is stored only when the server answered `200` with something that is an image (an
//! `image/*` content type, or an icon, PNG, GIF, JPEG, BMP, WebP or SVG signature); many servers
//! answer every path with their HTML page, which must not become a favicon hash. The address
//! comes only from the target list, so the scope guard of the scan covers it.
use crate::{core::Gate, pivot, scan::Host, sendlog::PacketKind};
use std::{net::IpAddr, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

/// The detail the request is recorded under in the sent log, and listed under in the dry run.
pub const DETAIL: &str = "GET /favicon.ico";
/// Largest favicon accepted (256 KiB); a larger body gives no hash.
pub const MAX_BODY: usize = 256 * 1024;
/// Most bytes read from one response (the body limit plus room for the headers).
pub const MAX_RESPONSE: usize = MAX_BODY + 16 * 1024;

/// Whether a scan with these settings fetches favicons: opt-in, needs service identification and
/// never in Safe Mode.
pub fn enabled(s: &crate::scan::Settings) -> bool {
    s.favicon && s.services && !s.safe
}

/// Whether the host looks industrial: an OT port is open, or an OT protocol identified it.
fn industrial(h: &Host) -> bool {
    h.open
        .iter()
        .any(|p| crate::service::is_ot_port_candidate(*p))
        || h.udp_open
            .iter()
            .any(|p| crate::service::is_ot_udp_port(*p))
        || !crate::otdevice::from_identity(&h.identity).is_empty()
        || h.identity
            .keys()
            .any(|k| k.starts_with("BACnet.") || k.starts_with("EtherNet/IP."))
}

/// The open ports of `h` that may be asked for a favicon, and whether they use TLS:
/// ports service identification found to be `http` or `https`, on a host that is not industrial.
pub fn candidates(h: &Host) -> Vec<(u16, bool)> {
    if industrial(h) {
        return vec![];
    }
    h.open
        .iter()
        .filter(|p| {
            crate::service::sends_payload(**p) && !crate::service::is_ot_port_candidate(**p)
        })
        .filter_map(|&p| {
            let service = h.identity.get(&format!("svc.{p}"))?;
            match service.split_whitespace().next()? {
                "http" => Some((p, false)),
                "https" => Some((p, true)),
                _ => None,
            }
        })
        .collect()
}

/// What a fetch found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fetched {
    /// The Shodan-compatible hash of the icon.
    Hash(i32),
    /// The server answered, but not with an icon (404, HTML, too large, redirect, ...).
    NoIcon,
    /// The port did not accept a connection (a failed TLS handshake is `NoIcon`).
    Failed,
}

/// Asks one web port for `/favicon.ico` (one request through the rate gate).
pub async fn fetch(ip: IpAddr, port: u16, secure: bool, limit: Duration, gate: &Gate) -> Fetched {
    gate.wait_for(PacketKind::HttpRequest, DETAIL).await;
    let Ok(Ok(tcp)) = timeout(limit, TcpStream::connect((ip, port))).await else {
        return Fetched::Failed;
    };
    let request = crate::service::http_request_for("/favicon.ico", ip, port);
    let peer = std::net::SocketAddr::new(ip, port);
    let data = if secure {
        gate.note(PacketKind::TlsClientHello, "TLS handshake");
        let Ok((mut stream, _)) = crate::tls::wrap(tcp, ip, limit).await else {
            return Fetched::NoIcon;
        };
        let note = "HTTP GET /favicon.ico (inside TLS, decrypted)";
        exchange(&mut stream, request.as_bytes(), limit, gate, (peer, note)).await
    } else {
        let mut stream = tcp;
        exchange(
            &mut stream,
            request.as_bytes(),
            limit,
            gate,
            (peer, "HTTP GET /favicon.ico"),
        )
        .await
    };
    match data.and_then(|d| icon(&d)) {
        Some(body) => Fetched::Hash(pivot::favicon_hash(&body)),
        None => Fetched::NoIcon,
    }
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    request: &[u8],
    limit: Duration,
    gate: &Gate,
    (peer, note): (std::net::SocketAddr, &str),
) -> Option<Vec<u8>> {
    gate.log().capture(peer, false, true, request, note);
    s.write_all(request).await.ok()?;
    let mut data = vec![];
    let mut chunk = [0u8; 8192];
    while data.len() < MAX_RESPONSE {
        match timeout(limit, s.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => data.extend_from_slice(&chunk[..n]),
            _ => break,
        }
        // A server that ignores `Connection: close` would otherwise cost a full timeout.
        if parse(&data).is_some_and(|r| r.complete) {
            break;
        }
    }
    data.truncate(MAX_RESPONSE);
    gate.log().capture(peer, false, false, &data, note);
    (!data.is_empty()).then_some(data)
}

/// A parsed HTTP/1.x response.
struct Response {
    status: u16,
    content_type: String,
    body: Vec<u8>,
    /// The body is known to be complete (Content-Length reached, last chunk seen).
    complete: bool,
    /// The response says how long its body is (Content-Length or chunked); without it the body
    /// is whatever arrived until the server closed the connection.
    framed: bool,
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Decodes a chunked body; `None` when it is malformed, `Some((body, complete))` otherwise.
fn dechunk(mut data: &[u8]) -> Option<(Vec<u8>, bool)> {
    let mut body = vec![];
    loop {
        let Some(line_end) = find(data, b"\r\n") else {
            return Some((body, false));
        };
        let size = std::str::from_utf8(&data[..line_end]).ok()?;
        let size = size.split(';').next()?.trim();
        let size = usize::from_str_radix(size, 16).ok()?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Some((body, true));
        }
        if data.len() < size {
            body.extend_from_slice(data);
            return Some((body, false));
        }
        body.extend_from_slice(&data[..size]);
        data = &data[size..];
        data = data.strip_prefix(b"\r\n").unwrap_or(data);
        if body.len() > MAX_RESPONSE {
            return Some((body, false));
        }
    }
}

fn parse(data: &[u8]) -> Option<Response> {
    let end = find(data, b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&data[..end]);
    let rest = &data[end + 4..];
    let mut lines = head.lines();
    let mut first = lines.next()?.split_whitespace();
    if !first.next()?.starts_with("HTTP/1.") {
        return None;
    }
    let status: u16 = first.next()?.parse().ok()?;
    let (mut content_type, mut length, mut chunked) = (String::new(), None, false);
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-type" => content_type = value.to_ascii_lowercase(),
            "content-length" => length = value.parse::<usize>().ok(),
            "transfer-encoding" => chunked = value.to_ascii_lowercase().contains("chunked"),
            _ => {}
        }
    }
    let (body, complete) = if chunked {
        dechunk(rest)?
    } else if let Some(n) = length {
        (rest[..rest.len().min(n)].to_vec(), rest.len() >= n)
    } else {
        (rest.to_vec(), false)
    };
    Some(Response {
        status,
        content_type,
        body,
        complete,
        framed: chunked || length.is_some(),
    })
}

/// Whether the bytes start like an image format a favicon is served in.
fn looks_like_an_image(body: &[u8]) -> bool {
    const SIGNATURES: [&[u8]; 6] = [
        &[0, 0, 1, 0],
        &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a],
        b"GIF8",
        &[0xff, 0xd8, 0xff],
        b"BM",
        b"<svg",
    ];
    SIGNATURES.iter().any(|s| body.starts_with(s))
        || (body.len() > 12 && &body[..4] == b"RIFF" && &body[8..12] == b"WEBP")
        || (body.starts_with(b"<?xml") && find(&body[..body.len().min(512)], b"<svg").is_some())
}

/// The body of a response that is a complete icon: status 200, an image, within [`MAX_BODY`].
/// `data` is everything read. A body that says how long it is must have arrived in full; one
/// that does not is what the connection delivered until the server closed it (or until the
/// read limit, which [`MAX_BODY`] then rejects).
pub fn icon(data: &[u8]) -> Option<Vec<u8>> {
    let r = parse(data)?;
    if r.status != 200 || r.body.is_empty() || r.body.len() > MAX_BODY || (r.framed && !r.complete)
    {
        return None;
    }
    let image = r.content_type.starts_with("image/") || looks_like_an_image(&r.body);
    let start: Vec<u8> = r.body.iter().take(256).copied().collect();
    let start = String::from_utf8_lossy(&start).to_ascii_lowercase();
    let html = start.trim_start().starts_with("<!doctype html") || start.contains("<html");
    (image && !html).then_some(r.body)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ICO: &[u8] = &[
        0, 0, 1, 0, 1, 0, 16, 16, 0, 0, 1, 0, 32, 0, 40, 0, 0, 0, 22, 0, 0, 0,
    ];

    fn response(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
        let mut r = format!("HTTP/1.1 {status}\r\n{headers}\r\n").into_bytes();
        r.extend_from_slice(body);
        r
    }

    #[test]
    fn a_complete_icon_is_returned() {
        let r = response(
            "200 OK",
            &format!(
                "Content-Type: image/x-icon\r\nContent-Length: {}\r\n",
                ICO.len()
            ),
            ICO,
        );
        assert_eq!(icon(&r).as_deref(), Some(ICO));
        // chunked, in two chunks
        let mut chunked = b"HTTP/1.1 200 OK\r\nContent-Type: image/vnd.microsoft.icon\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for part in ICO.chunks(10) {
            chunked.extend(format!("{:x}\r\n", part.len()).bytes());
            chunked.extend(part);
            chunked.extend(b"\r\n");
        }
        chunked.extend(b"0\r\n\r\n");
        assert_eq!(icon(&chunked).as_deref(), Some(ICO));
        // no content type, but an icon signature; no length, the connection closed
        let bare = response("200 OK", "Connection: close\r\n", ICO);
        assert_eq!(icon(&bare).as_deref(), Some(ICO));
    }

    #[test]
    fn answers_that_are_not_an_icon_give_nothing() {
        let html = b"<!DOCTYPE html><html><head><title>x</title></head></html>";
        for (name, r) in [
            (
                "404",
                response(
                    "404 Not Found",
                    "Content-Type: text/html\r\nContent-Length: 3\r\n",
                    b"no!",
                ),
            ),
            (
                "html for every path",
                response(
                    "200 OK",
                    &format!(
                        "Content-Type: text/html\r\nContent-Length: {}\r\n",
                        html.len()
                    ),
                    html,
                ),
            ),
            (
                "html wrongly typed as an image",
                response(
                    "200 OK",
                    &format!(
                        "Content-Type: image/x-icon\r\nContent-Length: {}\r\n",
                        html.len()
                    ),
                    html,
                ),
            ),
            (
                "redirect",
                response(
                    "301 Moved",
                    "Location: /x.ico\r\nContent-Length: 0\r\n",
                    b"",
                ),
            ),
            (
                "empty",
                response(
                    "200 OK",
                    "Content-Type: image/png\r\nContent-Length: 0\r\n",
                    b"",
                ),
            ),
            (
                "cut short",
                response(
                    "200 OK",
                    "Content-Type: image/png\r\nContent-Length: 500\r\n",
                    ICO,
                ),
            ),
            (
                "plain text",
                response(
                    "200 OK",
                    "Content-Type: text/plain\r\nContent-Length: 5\r\n",
                    b"hello",
                ),
            ),
            ("not http", b"SSH-2.0-OpenSSH_9.6\r\n".to_vec()),
            ("garbage", vec![0xff; 40]),
        ] {
            assert_eq!(icon(&r), None, "{name}");
        }
    }

    #[test]
    fn a_body_above_the_cap_gives_no_hash() {
        let big = vec![0u8; MAX_BODY + 1];
        let mut body = ICO.to_vec();
        body.extend(&big);
        let r = response(
            "200 OK",
            &format!(
                "Content-Type: image/x-icon\r\nContent-Length: {}\r\n",
                body.len()
            ),
            &body,
        );
        assert_eq!(icon(&r), None);
        let mut exact = ICO.to_vec();
        exact.resize(MAX_BODY, 0);
        let r = response(
            "200 OK",
            &format!(
                "Content-Type: image/x-icon\r\nContent-Length: {}\r\n",
                exact.len()
            ),
            &exact,
        );
        assert_eq!(icon(&r).map(|b| b.len()), Some(MAX_BODY));
    }

    #[test]
    fn chunk_decoding_is_bounded_and_strict() {
        assert_eq!(
            dechunk(b"3\r\nabc\r\n0\r\n\r\n"),
            Some((b"abc".to_vec(), true))
        );
        assert_eq!(dechunk(b"3\r\nab"), Some((b"ab".to_vec(), false)));
        assert_eq!(dechunk(b"zz\r\nabc"), None);
        assert_eq!(
            dechunk(b"3;ext=1\r\nabc\r\n0\r\n\r\n"),
            Some((b"abc".to_vec(), true))
        );
        assert_eq!(dechunk(b""), Some((vec![], false)));
    }

    #[test]
    fn only_web_ports_of_ordinary_hosts_are_candidates() {
        let host = |open: &[u16], identity: &[(&str, &str)]| Host {
            ip: "10.0.0.1".parse().unwrap(),
            responding: true,
            ping: None,
            ttl: None,
            hostname: String::new(),
            mac: String::new(),
            open: open.to_vec(),
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity: identity
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            udp_open: vec![],
            trace: vec![],
        };
        let web = [
            ("svc.80", "http nginx 1.2 (200 OK)"),
            ("svc.443", "https"),
            ("svc.22", "ssh OpenSSH 9.6"),
            ("svc.8443", "ssl/unknown"),
        ];
        assert_eq!(
            candidates(&host(&[22, 80, 443, 8443], &web)),
            [(80, false), (443, true)],
            "only ports that answered as http or https"
        );
        assert!(
            candidates(&host(&[80], &[])).is_empty(),
            "no identification, no request"
        );
        // a host with an industrial port, or an industrial identification, gets nothing
        assert!(candidates(&host(&[80, 502], &web)).is_empty());
        assert!(candidates(&host(&[80, 2222], &web)).is_empty());
        let mut with_modbus = web.to_vec();
        with_modbus.push(("Modbus.vendor", "Example"));
        assert!(candidates(&host(&[80], &with_modbus)).is_empty());
        let mut with_bacnet = web.to_vec();
        with_bacnet.push(("BACnet.device_id", "1"));
        assert!(candidates(&host(&[80], &with_bacnet)).is_empty());
        // a printer port is never asked, even when it claimed to be http
        assert!(candidates(&host(&[9100], &[("svc.9100", "http")])).is_empty());
        let mut udp = host(&[80], &web);
        udp.udp_open = vec![47808];
        assert!(candidates(&udp).is_empty());
    }

    #[test]
    fn it_runs_only_when_asked_for_and_never_in_safe_mode() {
        let on = crate::scan::Settings {
            favicon: true,
            services: true,
            safe: false,
            ..Default::default()
        };
        assert!(enabled(&on));
        for off in [
            crate::scan::Settings {
                favicon: false,
                ..on.clone()
            },
            crate::scan::Settings {
                services: false,
                ..on.clone()
            },
            crate::scan::Settings {
                safe: true,
                ..on.clone()
            },
        ] {
            assert!(!enabled(&off));
        }
    }

    // ---- against a local server -----------------------------------------------------------

    /// Answers one request: `/` is a small page, `/favicon.ico` is `icon` (a raw response, so a
    /// test can answer anything); icon requests are counted.
    fn respond<S: std::io::Read + std::io::Write>(
        stream: &mut S,
        icon: &[u8],
        counter: &std::sync::atomic::AtomicUsize,
    ) {
        let mut request = vec![];
        let mut buf = [0u8; 1024];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut buf) {
                Ok(n) if n > 0 => request.extend_from_slice(&buf[..n]),
                _ => return,
            }
        }
        let text = String::from_utf8_lossy(&request).to_string();
        if text.starts_with("GET /favicon.ico ") {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _ = stream.write_all(icon);
        } else {
            let page = "<html><head><title>Lab</title></head></html>";
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nServer: labweb/1.0\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{page}",
                page.len()
            );
        }
        let _ = stream.flush();
    }

    type Asked = std::sync::Arc<std::sync::atomic::AtomicUsize>;

    /// A web server on loopback, plain HTTP; the number of icon requests is counted.
    fn serve(icon: Vec<u8>) -> (u16, Asked) {
        serve_with(icon, None)
    }

    /// The same over TLS with a self-signed certificate (the scanner does not verify it).
    fn serve_tls(icon: Vec<u8>) -> (u16, Asked) {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .unwrap();
        serve_with(icon, Some(std::sync::Arc::new(config)))
    }

    fn serve_with(
        icon: Vec<u8>,
        tls: Option<std::sync::Arc<rustls::ServerConfig>>,
    ) -> (u16, Asked) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let asked = Asked::default();
        let counter = asked.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (icon, counter, tls) = (icon.clone(), counter.clone(), tls.clone());
                std::thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                    match tls {
                        None => respond(&mut { stream }, &icon, &counter),
                        Some(config) => {
                            let conn = rustls::ServerConnection::new(config).unwrap();
                            respond(&mut rustls::StreamOwned::new(conn, stream), &icon, &counter);
                        }
                    }
                });
            }
        });
        (port, asked)
    }

    fn icon_response() -> Vec<u8> {
        response(
            "200 OK",
            &format!(
                "Content-Type: image/x-icon\r\nContent-Length: {}\r\n",
                ICO.len()
            ),
            ICO,
        )
    }

    const LOCAL: &str = "127.0.0.1";

    #[tokio::test]
    async fn fetch_hashes_the_icon_and_records_one_request() {
        let (port, asked) = serve(icon_response());
        let gate = Gate::unlimited();
        let found = fetch(
            LOCAL.parse().unwrap(),
            port,
            false,
            Duration::from_secs(3),
            &gate,
        )
        .await;
        assert_eq!(found, Fetched::Hash(pivot::favicon_hash(ICO)));
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 1);
        let sent = gate.log().snapshot();
        assert_eq!(sent.len(), 1, "{sent:?}");
        assert_eq!(
            (sent[0].kind, sent[0].detail.as_str(), sent[0].count),
            (PacketKind::HttpRequest, DETAIL, 1)
        );
    }

    #[tokio::test]
    async fn fetch_reports_what_is_not_an_icon_and_what_is_not_there() {
        let gate = Gate::unlimited();
        let ip: IpAddr = LOCAL.parse().unwrap();
        let limit = Duration::from_secs(3);
        let (port, _) = serve(response("404 Not Found", "Content-Length: 0\r\n", b""));
        assert_eq!(fetch(ip, port, false, limit, &gate).await, Fetched::NoIcon);
        let html = b"<html>home</html>";
        let (port, _) = serve(response(
            "200 OK",
            &format!(
                "Content-Type: text/html\r\nContent-Length: {}\r\n",
                html.len()
            ),
            html,
        ));
        assert_eq!(fetch(ip, port, false, limit, &gate).await, Fetched::NoIcon);
        // too large: the cap, not the whole file, is read
        let mut huge = ICO.to_vec();
        huge.resize(MAX_BODY * 3, 0);
        let (port, _) = serve(response(
            "200 OK",
            &format!(
                "Content-Type: image/x-icon\r\nContent-Length: {}\r\n",
                huge.len()
            ),
            &huge,
        ));
        assert_eq!(fetch(ip, port, false, limit, &gate).await, Fetched::NoIcon);
        // a closed port
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        assert_eq!(
            fetch(ip, closed, false, limit, &gate).await,
            Fetched::Failed
        );
        // a plain-text server asked over TLS is not an icon and not a failure of the port
        let (port, _) = serve(icon_response());
        assert_eq!(fetch(ip, port, true, limit, &gate).await, Fetched::NoIcon);
    }

    #[tokio::test]
    async fn fetch_over_tls_hashes_the_icon_and_records_the_handshake() {
        let (port, asked) = serve_tls(icon_response());
        let gate = Gate::unlimited();
        let ip: IpAddr = LOCAL.parse().unwrap();
        let found = fetch(ip, port, true, Duration::from_secs(5), &gate).await;
        assert_eq!(found, Fetched::Hash(pivot::favicon_hash(ICO)));
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 1);
        let sent: Vec<(PacketKind, String)> = gate
            .log()
            .snapshot()
            .into_iter()
            .map(|e| (e.kind, e.detail))
            .collect();
        assert!(
            sent.contains(&(PacketKind::HttpRequest, DETAIL.to_string()))
                && sent.contains(&(PacketKind::TlsClientHello, "TLS handshake".to_string())),
            "{sent:?}"
        );
        // asked in the clear, a TLS server gives no icon and the port is not reported as down
        assert_eq!(
            fetch(ip, port, false, Duration::from_secs(2), &gate).await,
            Fetched::NoIcon
        );
    }

    fn scan_host(
        settings: crate::scan::Settings,
        ports: Vec<u16>,
    ) -> (Host, Vec<crate::sendlog::SentEntry>) {
        let run = crate::scan::start(vec![LOCAL.parse().unwrap()], ports, settings);
        let sent = run.sent.clone();
        let mut host = None;
        loop {
            match run.receiver.recv_timeout(Duration::from_secs(120)).unwrap() {
                crate::scan::Event::Done => break,
                crate::scan::Event::Error(e) => panic!("{e}"),
                crate::scan::Event::Host(h) => host = Some(h),
            }
        }
        (host.expect("a host result"), sent.snapshot())
    }

    fn web_settings(favicon: bool, safe: bool) -> crate::scan::Settings {
        crate::scan::Settings {
            safe,
            services: true,
            favicon,
            tcp_only: true,
            scan_nonresponders: true,
            port_timeout: 1500,
            retries: 0,
            probes: 1,
            delay: 0,
            ..Default::default()
        }
    }

    #[test]
    fn a_scan_stores_the_hash_of_the_lab_web_server_and_the_plan_lists_the_request() {
        let (port, asked) = serve(icon_response());
        let (host, sent) = scan_host(web_settings(true, false), vec![port]);
        let key = format!("http.{port}.favicon_mmh3");
        assert_eq!(
            host.identity.get(&key).map(String::as_str),
            Some(pivot::favicon_hash(ICO).to_string().as_str()),
            "{:?}",
            host.identity
        );
        assert_eq!(
            asked.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "one request per port"
        );
        // the sent log has the request and the dry run lists it (it is in the plan)
        let settings = web_settings(true, false);
        let db = crate::service::ProbeDb::load("").unwrap();
        let ip: IpAddr = LOCAL.parse().unwrap();
        let planned = crate::plan::host(ip, &[port], &[], &settings, Some(&db)).keys();
        assert!(planned.contains(&(PacketKind::HttpRequest, DETAIL.to_string())));
        for e in &sent {
            assert!(
                planned.contains(&(e.kind, e.detail.clone())),
                "{e:?} is not in the plan"
            );
        }
        assert!(
            sent.iter()
                .any(|e| e.kind == PacketKind::HttpRequest && e.detail == DETAIL && e.count == 1)
        );
        // without --favicon, in Safe Mode, and without services nothing is requested or stored
        for settings in [
            web_settings(false, false),
            web_settings(true, true),
            crate::scan::Settings {
                services: false,
                ..web_settings(true, false)
            },
        ] {
            let planned = crate::plan::host(ip, &[port], &[], &settings, Some(&db)).keys();
            assert!(!planned.contains(&(PacketKind::HttpRequest, DETAIL.to_string())));
            let (host, sent) = scan_host(settings, vec![port]);
            assert!(!host.identity.contains_key(&key), "{:?}", host.identity);
            assert!(!sent.iter().any(|e| e.detail == DETAIL));
        }
        assert_eq!(
            asked.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "none of those asked again"
        );
    }

    #[test]
    fn a_scan_asks_an_https_port_inside_the_tls_session() {
        let (port, asked) = serve_tls(icon_response());
        let (host, sent) = scan_host(web_settings(true, false), vec![port]);
        assert!(
            host.identity
                .get(&format!("svc.{port}"))
                .is_some_and(|s| s.starts_with("https")),
            "{:?}",
            host.identity
        );
        assert_eq!(
            host.identity
                .get(&format!("http.{port}.favicon_mmh3"))
                .map(String::as_str),
            Some(pivot::favicon_hash(ICO).to_string().as_str()),
            "{:?}",
            host.identity
        );
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 1);
        let db = crate::service::ProbeDb::load("").unwrap();
        let ip: IpAddr = LOCAL.parse().unwrap();
        let planned =
            crate::plan::host(ip, &[port], &[], &web_settings(true, false), Some(&db)).keys();
        for e in &sent {
            assert!(
                planned.contains(&(e.kind, e.detail.clone())),
                "{e:?} is not in the plan"
            );
        }
        assert!(
            sent.iter()
                .any(|e| e.kind == PacketKind::HttpRequest && e.detail == DETAIL)
        );
    }

    #[test]
    fn a_host_with_an_industrial_port_open_is_never_asked() {
        let (web, asked) = serve(icon_response());
        // 1962 (PCWorx) is an industrial port: this host looks like a controller
        let ot = std::net::TcpListener::bind("127.0.0.1:1962").expect("port 1962 is free");
        std::thread::spawn(move || for _ in ot.incoming() {});
        let (host, sent) = scan_host(web_settings(true, false), vec![web, 1962]);
        assert!(
            host.open.contains(&web) && host.open.contains(&1962),
            "{:?}",
            host.open
        );
        assert!(
            !host
                .identity
                .contains_key(&format!("http.{web}.favicon_mmh3"))
        );
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert!(!sent.iter().any(|e| e.detail == DETAIL));
    }
}
