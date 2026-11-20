//! HTTP request, response parsing and the `http.*` fields.
use super::{Outcome, Service, read_some};
use std::{net::IpAddr, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Default, PartialEq)]
pub struct Http {
    pub status: u16,
    pub reason: String,
    pub server: String,
    pub powered_by: String,
    pub title: String,
    pub location: String,
    pub auth: String,
}

pub fn parse_http(data: &[u8]) -> Option<Http> {
    let text = String::from_utf8_lossy(data);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.lines();
    let first = lines.next()?;
    let mut parts = first.splitn(3, ' ');
    if !parts.next()?.starts_with("HTTP/1.") {
        return None;
    }
    let status = parts.next()?.parse().ok()?;
    let mut h = Http {
        status,
        reason: parts.next().unwrap_or("").trim().chars().take(60).collect(),
        ..Default::default()
    };
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value: String = value
            .trim()
            .chars()
            .filter(|c| !c.is_control())
            .take(160)
            .collect();
        match name.trim().to_ascii_lowercase().as_str() {
            "server" => h.server = value,
            "x-powered-by" => h.powered_by = value,
            "location" => h.location = value,
            "www-authenticate" => h.auth = value,
            _ => {}
        }
    }
    let lower = body.to_ascii_lowercase();
    if let Some(start) = lower.find("<title")
        && let Some(open) = lower[start..].find('>')
    {
        let from = start + open + 1;
        if let Some(len) = lower[from..].find("</title") {
            h.title = body[from..from + len]
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .chars()
                .filter(|c| !c.is_control())
                .take(120)
                .collect();
        }
    }
    Some(h)
}

fn http_request(ip: IpAddr, port: u16) -> String {
    http_request_for("/", ip, port)
}

/// RFC 7230 section 5.4: the Host header carries the port unless it is the scheme default
/// (80/443), and an IPv6 literal is bracketed (`[fe80::1]:8080`).
pub(crate) fn http_request_for(path: &str, ip: IpAddr, port: u16) -> String {
    let addr = match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    };
    let host = if matches!(port, 80 | 443) {
        addr
    } else {
        format!("{addr}:{port}")
    };
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NetworkScope\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    )
}

pub(super) async fn http_get<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    ip: IpAddr,
    port: u16,
    limit: Duration,
    log: &crate::sendlog::SentLog,
    note: &str,
) -> Option<Http> {
    let request = http_request(ip, port);
    let peer = std::net::SocketAddr::new(ip, port);
    log.capture(peer, false, true, request.as_bytes(), note);
    s.write_all(request.as_bytes()).await.ok()?;
    let data = read_some(s, limit, 32 * 1024).await;
    log.capture(peer, false, false, &data, note);
    parse_http(&data)
}

pub(crate) fn http_outcome(h: Http, secure: bool, out: &mut Outcome) {
    let mut name = String::new();
    let mut version = String::new();
    if let Some((n, v)) = h.server.split_once('/') {
        name = n.trim().to_string();
        version = v.split_whitespace().next().unwrap_or("").to_string();
    } else if !h.server.is_empty() {
        name = h.server.split_whitespace().next().unwrap_or("").to_string();
    }
    out.service = Some(Service {
        name: if secure { "https" } else { "http" }.into(),
        product: name,
        version,
        info: format!("{} {}", h.status, h.reason).trim().to_string(),
    });
    for (key, value) in [
        ("http.server", h.server),
        ("http.title", h.title),
        ("http.powered_by", h.powered_by),
        ("http.redirect", h.location),
        ("http.auth", h.auth),
    ] {
        if !value.is_empty() {
            out.fields.insert(key.into(), value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_parsing() {
        let data = b"HTTP/1.1 401 Unauthorized\r\nServer: nginx/1.18.0 (Ubuntu)\r\nX-Powered-By: PHP/8.1\r\nWWW-Authenticate: Basic realm=\"router\"\r\nLocation: /login\r\n\r\n<html><HEAD><Title>\n  My  Router \n</TITLE></head>";
        let h = parse_http(data).unwrap();
        assert_eq!((h.status, h.reason.as_str()), (401, "Unauthorized"));
        assert_eq!(h.server, "nginx/1.18.0 (Ubuntu)");
        assert_eq!(h.title, "My Router");
        assert_eq!(h.auth, "Basic realm=\"router\"");
        assert_eq!(h.location, "/login");
        assert_eq!(parse_http(b"SSH-2.0-x\r\n"), None);
        assert_eq!(parse_http(b"HTTP/1.1 abc\r\n\r\n"), None);
        assert_eq!(parse_http(b""), None);
        let mut out = Outcome::default();
        http_outcome(h, false, &mut out);
        assert_eq!(
            out.service.unwrap().summary(),
            "http nginx 1.18.0 (401 Unauthorized)"
        );
    }

    #[test]
    fn http_host_header_brackets_ipv6() {
        let host = |ip: &str, port| {
            let req = http_request(ip.parse().unwrap(), port);
            req.lines()
                .find(|l| l.starts_with("Host: "))
                .unwrap()
                .to_string()
        };
        assert_eq!(host("10.1.2.3", 80), "Host: 10.1.2.3");
        assert_eq!(host("10.1.2.3", 8080), "Host: 10.1.2.3:8080");
        assert_eq!(host("fe80::1", 443), "Host: [fe80::1]");
        assert_eq!(host("::1", 8443), "Host: [::1]:8443");
    }
}
