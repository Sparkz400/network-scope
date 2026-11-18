//! Service detection: banner grabbing, data-driven probes (data/probes.json plus an optional
//! user file), HTTP and TLS inspection and an SMB negotiate. Everything here only reads.
use crate::{core::Gate, tls};
use regex::bytes::{Regex, RegexBuilder};
use serde::Deserialize;
use std::{collections::BTreeMap, net::IpAddr, path::Path, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

pub type Fields = BTreeMap<String, String>;

static BUILTIN: &str = include_str!("../data/probes.json");
const TLS_PORTS: [u16; 17] = [
    443, 465, 636, 853, 989, 990, 992, 993, 995, 2376, 3269, 5061, 5671, 6443, 8443, 8883, 9443,
];
/// Industrial and safety-relevant ports are left to the dedicated read-only identification:
/// generic probing (a banner wait, an HTTP request) could disturb fragile controllers.
const OT_PORTS: [u16; 17] = [
    102, 502, 789, 1911, 1962, 2222, 2404, 4840, 9600, 18245, 20000, 34962, 34963, 34964, 44818,
    47808, 48898,
];

pub fn is_ot_port(port: u16) -> bool {
    OT_PORTS.contains(&port)
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

#[derive(Deserialize)]
struct RawRule {
    re: String,
    service: String,
    #[serde(default)]
    product: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    info: String,
}
#[derive(Deserialize)]
struct RawProbe {
    name: String,
    #[serde(default)]
    ports: Vec<u16>,
    #[serde(default)]
    send: String,
    #[serde(default)]
    send_hex: String,
    #[serde(default)]
    wait_ms: u64,
    #[serde(default)]
    rules: Vec<RawRule>,
}
#[derive(Deserialize)]
struct RawDb {
    probes: Vec<RawProbe>,
}

#[derive(Debug)]
pub struct Rule {
    re: Regex,
    service: String,
    product: String,
    version: String,
    info: String,
}
#[derive(Debug)]
pub struct Probe {
    pub name: String,
    pub ports: Vec<u16>,
    pub payload: Vec<u8>,
    pub wait: Duration,
    pub rules: Vec<Rule>,
}
#[derive(Debug)]
pub struct ProbeDb {
    pub probes: Vec<Probe>,
}

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    let clean: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if !clean.len().is_multiple_of(2) {
        return Err("send_hex has an odd number of digits".into());
    }
    (0..clean.len() / 2)
        .map(|i| u8::from_str_radix(&clean[2 * i..2 * i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
fn sanitize(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .filter(|c| !c.is_control())
        .take(120)
        .collect::<String>()
        .trim()
        .to_string()
}
fn expand(template: &str, caps: &regex::bytes::Captures) -> String {
    let mut out = String::new();
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' {
            if let Some(d) = chars.peek().and_then(|d| d.to_digit(10)) {
                chars.next();
                if let Some(m) = caps.get(d as usize) {
                    out.push_str(&sanitize(m.as_bytes()));
                }
                continue;
            }
        }
        out.push(c);
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

impl ProbeDb {
    fn parse(json: &str, origin: &str) -> Result<Vec<Probe>, String> {
        let raw: RawDb = serde_json::from_str(json).map_err(|e| format!("{origin}: {e}"))?;
        raw.probes
            .into_iter()
            .map(|p| {
                let mut payload = p.send.into_bytes();
                payload
                    .extend(unhex(&p.send_hex).map_err(|e| format!("{origin}: {}: {e}", p.name))?);
                let rules = p
                    .rules
                    .into_iter()
                    .map(|r| {
                        Ok(Rule {
                            re: RegexBuilder::new(&r.re)
                                .unicode(false)
                                .dot_matches_new_line(true)
                                .build()
                                .map_err(|e| {
                                    format!("{origin}: {}: bad regex {:?}: {e}", p.name, r.re)
                                })?,
                            service: r.service,
                            product: r.product,
                            version: r.version,
                            info: r.info,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                Ok(Probe {
                    wait: Duration::from_millis(if p.wait_ms == 0 { 1200 } else { p.wait_ms }),
                    name: p.name,
                    ports: p.ports,
                    payload,
                    rules,
                })
            })
            .collect()
    }
    pub fn builtin() -> Self {
        Self {
            probes: Self::parse(BUILTIN, "built-in probes")
                .expect("built-in probe database is valid"),
        }
    }
    /// Built-in probes plus the user file (same probe name replaces, new names are added).
    pub fn with_user_file(path: &Path) -> Result<Self, String> {
        let mut db = Self::builtin();
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        for probe in Self::parse(&text, &path.display().to_string())? {
            match db.probes.iter_mut().find(|p| p.name == probe.name) {
                Some(slot) => *slot = probe,
                None => db.probes.push(probe),
            }
        }
        Ok(db)
    }
    /// Loads the explicit path, else `%LOCALAPPDATA%/NetworkScope/probes.json` when it exists.
    pub fn load(explicit: &str) -> Result<Self, String> {
        if !explicit.is_empty() {
            return Self::with_user_file(Path::new(explicit));
        }
        let default = std::env::var_os("LOCALAPPDATA")
            .or_else(|| std::env::var_os("XDG_CONFIG_HOME"))
            .map(|p| Path::new(&p).join("NetworkScope").join("probes.json"));
        match default {
            Some(p) if p.exists() => Self::with_user_file(&p),
            _ => Ok(Self::builtin()),
        }
    }
    fn null_probe(&self) -> Option<&Probe> {
        self.probes
            .iter()
            .find(|p| p.ports.is_empty() && p.payload.is_empty())
    }
    pub fn identify(probe: &Probe, data: &[u8]) -> Option<Service> {
        probe.rules.iter().find_map(|r| {
            let caps = r.re.captures(data)?;
            Some(Service {
                name: expand(&r.service, &caps),
                product: expand(&r.product, &caps),
                version: expand(&r.version, &caps),
                info: expand(&r.info, &caps),
            })
        })
    }
}

// ---- I/O helpers -------------------------------------------------------------------------

async fn connect(ip: IpAddr, port: u16, limit: Duration, gate: &Gate) -> Option<TcpStream> {
    gate.wait().await;
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

// ---- HTTP --------------------------------------------------------------------------------

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
    if let Some(start) = lower.find("<title") {
        if let Some(open) = lower[start..].find('>') {
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
    }
    Some(h)
}

async fn http_get<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    ip: IpAddr,
    limit: Duration,
) -> Option<Http> {
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: NetworkScope\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    s.write_all(request.as_bytes()).await.ok()?;
    let data = read_some(s, limit, 32 * 1024).await;
    parse_http(&data)
}

fn http_outcome(h: Http, secure: bool, out: &mut Outcome) {
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

// ---- SSH algorithms ----------------------------------------------------------------------

#[derive(Debug, Default, PartialEq)]
pub struct Kexinit {
    pub kex: Vec<String>,
    pub hostkey: Vec<String>,
    pub ciphers: Vec<String>,
    pub macs: Vec<String>,
}

/// Parses the server's SSH_MSG_KEXINIT binary packet (RFC 4253 section 7.1).
pub fn parse_kexinit(packet: &[u8]) -> Option<Kexinit> {
    let len = u32::from_be_bytes(packet.get(..4)?.try_into().ok()?) as usize;
    if !(21..=65_536).contains(&len) {
        return None;
    }
    let body = packet.get(4..4 + len.min(packet.len() - 4))?;
    let padding = usize::from(*body.first()?);
    let payload = body.get(1..body.len().checked_sub(padding)?)?;
    if *payload.first()? != 20 {
        return None;
    }
    let mut i = 17;
    let mut lists = vec![];
    for _ in 0..10 {
        let n = u32::from_be_bytes(payload.get(i..i + 4)?.try_into().ok()?) as usize;
        let text = payload.get(i + 4..i + 4 + n)?;
        lists.push(
            String::from_utf8_lossy(text)
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| {
                    s.chars()
                        .filter(|c| !c.is_control())
                        .take(80)
                        .collect::<String>()
                })
                .collect::<Vec<_>>(),
        );
        i += 4 + n;
    }
    Some(Kexinit {
        kex: lists[0].clone(),
        hostkey: lists[1].clone(),
        ciphers: lists[2].clone(),
        macs: lists[4].clone(),
    })
}

/// (weak, legacy) findings for an SSH server's offered algorithms.
pub fn assess_ssh(k: &Kexinit) -> (Vec<String>, Vec<String>) {
    let (mut weak, mut legacy) = (vec![], vec![]);
    let has = |list: &[String], name: &str| list.iter().any(|a| a == name);
    for a in &k.kex {
        match a.as_str() {
            "diffie-hellman-group1-sha1" => weak.push(format!("kex {a} (1024-bit DH, SHA-1)")),
            "diffie-hellman-group14-sha1" | "diffie-hellman-group-exchange-sha1" => {
                legacy.push(format!("kex {a} (SHA-1)"))
            }
            _ => {}
        }
    }
    for a in &k.hostkey {
        match a.as_str() {
            "ssh-dss" => weak.push(format!("host key {a} (1024-bit DSA)")),
            "ssh-rsa" => legacy.push(format!("host key {a} (SHA-1 signatures)")),
            _ => {}
        }
    }
    for a in &k.ciphers {
        let l = a.as_str();
        if l.contains("arcfour")
            || l.contains("3des")
            || l.contains("des-cbc")
            || l.contains("blowfish")
            || l.contains("cast128")
            || l == "none"
        {
            weak.push(format!("cipher {a}"));
        } else if l.ends_with("-cbc") {
            legacy.push(format!("cipher {a} (CBC)"));
        }
    }
    for a in &k.macs {
        let l = a.as_str();
        if l.contains("md5") || l.contains("-96") || l.starts_with("umac-64") || l == "none" {
            weak.push(format!("mac {a}"));
        }
    }
    let strict = has(&k.kex, "kex-strict-s-v00@openssh.com");
    let chacha = has(&k.ciphers, "chacha20-poly1305@openssh.com");
    let cbc_etm = k.ciphers.iter().any(|c| c.ends_with("-cbc"))
        && k.macs.iter().any(|m| m.ends_with("-etm@openssh.com"));
    if !strict && (chacha || cbc_etm) {
        weak.push("Terrapin (CVE-2023-48795): ChaCha20-Poly1305 or CBC-EtM offered without strict key exchange".into());
    }
    (weak, legacy)
}

async fn ssh_fields<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    first: &[u8],
    limit: Duration,
) -> Fields {
    let mut f = Fields::new();
    let mut data = first
        .iter()
        .position(|b| *b == b'\n')
        .map(|n| first[n + 1..].to_vec())
        .unwrap_or_default();
    if s.write_all(b"SSH-2.0-NetworkScope\r\n").await.is_err() {
        return f;
    }
    if data.len() < 4 {
        data.extend(read_some(s, limit, 8192).await);
    }
    while data.len() >= 4 {
        let need = 4 + u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() >= need || need > 70_000 {
            break;
        }
        let more = read_some(s, Duration::from_millis(400), 8192).await;
        if more.is_empty() {
            break;
        }
        data.extend(more);
    }
    let Some(k) = parse_kexinit(&data) else {
        return f;
    };
    f.insert("ssh.kex".into(), k.kex.join(", "));
    f.insert("ssh.hostkeys".into(), k.hostkey.join(", "));
    f.insert("ssh.ciphers".into(), k.ciphers.join(", "));
    f.insert("ssh.macs".into(), k.macs.join(", "));
    let (weak, legacy) = assess_ssh(&k);
    if !weak.is_empty() {
        f.insert("ssh.weak".into(), weak.join("; "));
    }
    if !legacy.is_empty() {
        f.insert("ssh.legacy".into(), legacy.join("; "));
    }
    f
}
// ---- SMB ---------------------------------------------------------------------------------

pub fn smb2_negotiate_request() -> Vec<u8> {
    let mut m = vec![0xFE, b'S', b'M', b'B'];
    m.extend(64u16.to_le_bytes());
    m.extend([0; 2]);
    m.extend([0; 4]);
    m.extend([0; 2]);
    m.extend(1u16.to_le_bytes());
    m.extend([0; 4]);
    m.extend([0; 4]);
    m.extend([0; 8]);
    m.extend([0; 4]);
    m.extend([0; 4]);
    m.extend([0; 8]);
    m.extend([0; 16]);
    assert_eq!(m.len(), 64);
    m.extend(36u16.to_le_bytes());
    m.extend(5u16.to_le_bytes());
    m.extend(1u16.to_le_bytes());
    m.extend([0; 2]);
    m.extend([0; 4]);
    m.extend([0x4e; 16]);
    m.extend(112u32.to_le_bytes());
    m.extend(1u16.to_le_bytes());
    m.extend([0; 2]);
    for dialect in [0x0202u16, 0x0210, 0x0300, 0x0302, 0x0311] {
        m.extend(dialect.to_le_bytes());
    }
    m.extend([0; 2]);
    assert_eq!(m.len(), 112);
    m.extend(1u16.to_le_bytes());
    m.extend(38u16.to_le_bytes());
    m.extend([0; 4]);
    m.extend(1u16.to_le_bytes());
    m.extend(32u16.to_le_bytes());
    m.extend(1u16.to_le_bytes());
    m.extend([0x5a; 32]);
    let mut packet = vec![0];
    packet.extend(&(m.len() as u32).to_be_bytes()[1..]);
    packet.extend(m);
    packet
}

pub fn parse_smb(data: &[u8]) -> Option<Service> {
    let magic = data.get(4..8)?;
    if magic == [0xFF, b'S', b'M', b'B'] {
        return Some(Service {
            name: "microsoft-ds".into(),
            product: "SMBv1".into(),
            info: "SMBv1 enabled (legacy, insecure)".into(),
            ..Default::default()
        });
    }
    if magic != [0xFE, b'S', b'M', b'B'] || data.get(12..16)? != [0; 4] {
        return None;
    }
    let mode = u16::from_le_bytes(data.get(70..72)?.try_into().ok()?);
    let dialect = u16::from_le_bytes(data.get(72..74)?.try_into().ok()?);
    let version = match dialect {
        0x0202 => "2.0.2",
        0x0210 => "2.1",
        0x02FF => "2.x",
        0x0300 => "3.0",
        0x0302 => "3.0.2",
        0x0311 => "3.1.1",
        _ => "unknown dialect",
    };
    Some(Service {
        name: "microsoft-ds".into(),
        product: "SMB".into(),
        version: version.into(),
        info: if mode & 2 != 0 {
            "signing required"
        } else if mode & 1 != 0 {
            "signing enabled, not required"
        } else {
            "signing disabled"
        }
        .into(),
    })
}

// ---- detection ---------------------------------------------------------------------------

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
    let (mut stream, _) = tls::wrap(tcp, ip, limit).await.ok()?;
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
    } else if let Some(h) = http_get(&mut stream, ip, limit).await {
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
    drop(stream);
    if let Ok(fields) = tls::inspect(ip, port, limit, rounds, gate).await {
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
    if TLS_PORTS.contains(&port) {
        if let Some(out) = tls_service(ip, port, limit, db, gate, rounds).await {
            return Some(out);
        }
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
    if client_first && candidates.is_empty() && port != 445 {
        if let Some(mut s) = connect(ip, port, limit, gate).await {
            if let Some(h) = http_get(&mut s, ip, limit).await {
                http_outcome(h, false, &mut out);
                return Some(out);
            }
        }
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
            if svc.name == "http" {
                if let Some(h) = parse_http(&banner) {
                    http_outcome(h, false, &mut out);
                    return Some(out);
                }
            }
            if svc.name == "ssh" {
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
        if stream.write_all(&probe.payload).await.is_err() {
            continue;
        }
        let reply = read_some(&mut stream, probe.wait, 4096).await;
        if let Some(svc) = ProbeDb::identify(probe, &reply) {
            out.service = Some(svc);
            return Some(out);
        }
    }
    if port == 445 {
        if let Some(mut s) = connect(ip, port, limit, gate).await {
            if s.write_all(&smb2_negotiate_request()).await.is_ok() {
                let reply = read_some(&mut s, limit, 4096).await;
                if let Some(svc) = parse_smb(&reply) {
                    out.service = Some(svc);
                    return Some(out);
                }
            }
        }
    }
    if let Some(mut s) = connect(ip, port, limit, gate).await {
        if let Some(h) = http_get(&mut s, ip, limit).await {
            http_outcome(h, false, &mut out);
            return Some(out);
        }
    }
    if !TLS_PORTS.contains(&port) {
        if let Some(tls_out) = tls_service(ip, port, limit, db, gate, rounds).await {
            return Some(tls_out);
        }
    }
    Some(out)
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

    fn rule_match(db: &ProbeDb, probe: &str, data: &[u8]) -> Option<String> {
        let p = db.probes.iter().find(|p| p.name == probe).unwrap();
        ProbeDb::identify(p, data).map(|s| s.summary())
    }

    #[test]
    fn builtin_database_loads_and_payloads_are_consistent() {
        let db = ProbeDb::builtin();
        assert!(db.probes.len() >= 10);
        assert!(db.null_probe().is_some());
        let get = |n: &str| &db.probes.iter().find(|p| p.name == n).unwrap().payload;
        assert_eq!(get("mssql").len(), 26);
        assert_eq!(
            usize::from(u16::from_be_bytes([get("mssql")[2], get("mssql")[3]])),
            26
        );
        assert_eq!(get("mongodb").len(), 52);
        assert_eq!(
            u32::from_le_bytes(get("mongodb")[..4].try_into().unwrap()),
            52
        );
        assert_eq!(get("rdp").len(), 19);
        assert_eq!(usize::from(get("rdp")[3]), 19);
        assert_eq!(get("mqtt").len(), 14);
        assert_eq!(usize::from(get("mqtt")[1]), get("mqtt").len() - 2);
        assert_eq!(get("dns-tcp").len(), 32);
        assert_eq!(
            usize::from(u16::from_be_bytes([get("dns-tcp")[0], get("dns-tcp")[1]])),
            30
        );
        assert_eq!(get("ldap").len(), 14);
    }

    #[test]
    fn banner_rules() {
        let db = ProbeDb::builtin();
        let m = |d: &[u8]| rule_match(&db, "banner", d);
        assert_eq!(
            m(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n").unwrap(),
            "ssh OpenSSH 8.9p1 (protocol 2.0 Ubuntu-3ubuntu0.1)"
        );
        assert_eq!(
            m(b"SSH-2.0-dropbear_2022.83\r\n").unwrap(),
            "ssh dropbear_2022.83 (protocol 2.0)"
        );
        assert_eq!(m(b"220 (vsFTPd 3.0.3)\r\n").unwrap(), "ftp vsFTPd 3.0.3");
        assert_eq!(
            m(b"220 mail.example.com ESMTP Postfix (Debian)\r\n").unwrap(),
            "smtp Postfix"
        );
        assert_eq!(
            m(b"220 Microsoft FTP Service\r\n").unwrap(),
            "ftp Microsoft FTP Service"
        );
        assert_eq!(m(b"+OK Dovecot ready.\r\n").unwrap(), "pop3 Dovecot");
        assert_eq!(m(b"* OK IMAP4rev1 ready\r\n").unwrap(), "imap");
        assert_eq!(m(b"RFB 003.008\n").unwrap(), "vnc (protocol 003.008)");
        assert_eq!(m(b"\xff\xfd\x18\xff\xfd\x20").unwrap(), "telnet");
        let mut mysql = vec![0x4a, 0, 0, 0, 0x0a];
        mysql.extend(b"8.0.33-0ubuntu0.22.04.2\0rest");
        assert_eq!(m(&mysql).unwrap(), "mysql MySQL 8.0.33-0ubuntu0.22.04.2");
        let mut maria = vec![0x4a, 0, 0, 0, 0x0a];
        maria.extend(b"10.6.12-MariaDB-0ubuntu0.22.04.1\0");
        assert_eq!(m(&maria).unwrap(), "mysql MariaDB 10.6.12");
        assert_eq!(m(b"garbage that matches nothing"), None);
        assert_eq!(m(b""), None);
    }

    #[test]
    fn binary_protocol_rules() {
        let db = ProbeDb::builtin();
        assert_eq!(
            rule_match(&db, "mqtt", &[0x20, 2, 0, 0]).unwrap(),
            "mqtt (anonymous connection accepted)"
        );
        assert_eq!(
            rule_match(&db, "mqtt", &[0x20, 2, 0, 5]).unwrap(),
            "mqtt (authentication required)"
        );
        let rdp = |proto: u8| {
            let mut r = vec![
                3, 0, 0, 0x13, 0x0e, 0xd0, 0, 0, 0x12, 0x34, 0, 2, 0, 8, 0, proto, 0, 0, 0,
            ];
            r.truncate(19);
            rule_match(&db, "rdp", &r).unwrap()
        };
        assert_eq!(
            rdp(0),
            "ms-wbt-server RDP (standard RDP security (no TLS/NLA))"
        );
        assert_eq!(rdp(1), "ms-wbt-server RDP (TLS security)");
        assert_eq!(rdp(2), "ms-wbt-server RDP (NLA (CredSSP))");
        assert_eq!(
            rdp(8),
            "ms-wbt-server RDP (NLA with early user authentication)"
        );
        assert_eq!(
            rule_match(&db, "postgresql", b"S").unwrap(),
            "postgresql (TLS supported)"
        );
        assert_eq!(
            rule_match(
                &db,
                "redis",
                b"$100\r\n# Server\r\nredis_version:7.0.11\r\n"
            )
            .unwrap(),
            "redis Redis 7.0.11"
        );
        assert_eq!(
            rule_match(&db, "redis", b"-NOAUTH Authentication required.\r\n").unwrap(),
            "redis Redis (authentication required)"
        );
        assert_eq!(
            rule_match(&db, "mssql", &[4, 1, 0, 0x20, 0, 0, 1, 0]).unwrap(),
            "ms-sql-s Microsoft SQL Server"
        );
        assert_eq!(
            rule_match(
                &db,
                "ldap",
                &[0x30, 0x0c, 2, 1, 1, 0x61, 7, 0x0a, 1, 0, 4, 0, 4, 0]
            )
            .unwrap(),
            "ldap (anonymous bind answered)"
        );
        let mut dns = vec![0x00, 0x2e, 0x05, 0x39, 0x84, 0x00, 0, 1, 0, 1, 0, 0, 0, 0];
        dns.extend(b"\x07version\x04bind\x00\x00\x10\x00\x03\xc0\x0c\x00\x10\x00\x03\x00\x00\x00\x00\x00\x0a\x099.16.1-Ubuntu");
        assert_eq!(
            rule_match(&db, "dns-tcp", &dns).unwrap(),
            "domain 9.16.1-Ubuntu (version.bind)"
        );
    }

    #[test]
    fn user_file_replaces_and_adds_probes() {
        let path = std::env::temp_dir().join(format!("ns-probes-{}.json", std::process::id()));
        std::fs::write(
            &path,
            r#"{"probes":[
              {"name":"banner","rules":[{"re":"^HELLO (\\w+)","service":"custom","product":"$1"}]},
              {"name":"lab","ports":[7777],"send":"PING\n","rules":[{"re":"PONG","service":"labd"}]}]}"#,
        )
        .unwrap();
        let db = ProbeDb::with_user_file(&path).unwrap();
        assert_eq!(
            rule_match(&db, "banner", b"HELLO world").unwrap(),
            "custom world"
        );
        assert_eq!(
            rule_match(&db, "banner", b"SSH-2.0-x"),
            None,
            "same name replaces the built-in"
        );
        assert_eq!(rule_match(&db, "lab", b"PONG").unwrap(), "labd");
        assert!(db.probes.iter().any(|p| p.name == "redis"));
        std::fs::write(
            &path,
            r#"{"probes":[{"name":"x","rules":[{"re":"(","service":"y"}]}]}"#,
        )
        .unwrap();
        assert!(ProbeDb::with_user_file(&path)
            .unwrap_err()
            .contains("bad regex"));
        std::fs::write(
            &path,
            r#"{"probes":[{"name":"x","send_hex":"abc","rules":[]}]}"#,
        )
        .unwrap();
        assert!(ProbeDb::with_user_file(&path).unwrap_err().contains("odd"));
        std::fs::write(&path, "not json").unwrap();
        assert!(ProbeDb::with_user_file(&path).is_err());
        let _ = std::fs::remove_file(&path);
        assert!(ProbeDb::with_user_file(&path).is_err());
    }

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

    fn kexinit_packet(lists: [&str; 10]) -> Vec<u8> {
        let mut payload = vec![20u8];
        payload.extend([7u8; 16]);
        for l in lists {
            payload.extend((l.len() as u32).to_be_bytes());
            payload.extend(l.as_bytes());
        }
        payload.extend([0, 0, 0, 0, 0]);
        let padding = 8 - (payload.len() + 5) % 8;
        let mut packet = ((payload.len() + padding + 1) as u32)
            .to_be_bytes()
            .to_vec();
        packet.push(padding as u8);
        packet.extend(payload);
        packet.extend(vec![0u8; padding]);
        packet
    }

    #[test]
    fn ssh_kexinit_parsing_and_assessment() {
        let p = kexinit_packet([
            "curve25519-sha256,diffie-hellman-group1-sha1,kex-strict-s-v00@openssh.com",
            "ssh-ed25519,ssh-rsa,ssh-dss",
            "chacha20-poly1305@openssh.com,aes128-cbc,3des-cbc",
            "aes128-ctr",
            "hmac-sha2-256-etm@openssh.com,hmac-md5",
            "hmac-sha2-256",
            "none",
            "none",
            "",
            "",
        ]);
        let k = parse_kexinit(&p).unwrap();
        assert_eq!(k.kex.len(), 3);
        assert_eq!(k.hostkey, ["ssh-ed25519", "ssh-rsa", "ssh-dss"]);
        assert_eq!(k.macs, ["hmac-sha2-256-etm@openssh.com", "hmac-md5"]);
        let (weak, legacy) = assess_ssh(&k);
        let weak = weak.join(";");
        assert!(
            weak.contains("diffie-hellman-group1-sha1")
                && weak.contains("ssh-dss")
                && weak.contains("3des-cbc")
                && weak.contains("hmac-md5")
        );
        assert!(!weak.contains("Terrapin"), "strict kex is offered");
        assert!(
            legacy.iter().any(|l| l.contains("ssh-rsa"))
                && legacy.iter().any(|l| l.contains("aes128-cbc"))
        );
        let modern = kexinit_packet([
            "curve25519-sha256",
            "ssh-ed25519",
            "aes256-gcm@openssh.com",
            "aes256-gcm@openssh.com",
            "hmac-sha2-512",
            "hmac-sha2-512",
            "none",
            "none",
            "",
            "",
        ]);
        let (weak, legacy) = assess_ssh(&parse_kexinit(&modern).unwrap());
        assert!(weak.is_empty() && legacy.is_empty());
        let terrapin = kexinit_packet([
            "curve25519-sha256",
            "ssh-ed25519",
            "chacha20-poly1305@openssh.com",
            "chacha20-poly1305@openssh.com",
            "hmac-sha2-512",
            "hmac-sha2-512",
            "none",
            "none",
            "",
            "",
        ]);
        assert!(assess_ssh(&parse_kexinit(&terrapin).unwrap()).0[0].contains("Terrapin"));
        assert_eq!(parse_kexinit(&p[..30]), None);
        assert_eq!(parse_kexinit(&[0, 0, 0, 1, 0]), None);
        assert_eq!(parse_kexinit(&[]), None);
        let mut bad = p.clone();
        bad[5] = 21;
        assert_eq!(parse_kexinit(&bad), None);
    }

    #[tokio::test]
    async fn live_ssh_server_algorithms_are_collected() {
        let packet = kexinit_packet([
            "diffie-hellman-group1-sha1",
            "ssh-rsa",
            "aes128-cbc",
            "aes128-cbc",
            "hmac-sha1",
            "hmac-sha1",
            "none",
            "none",
            "",
            "",
        ]);
        let port = serve(move |mut s| {
            let packet = packet.clone();
            Box::pin(async move {
                let mut out = b"SSH-2.0-OpenSSH_7.4\r\n".to_vec();
                out.extend(packet);
                let _ = s.write_all(&out).await;
                let mut buf = [0u8; 64];
                let n = s.read(&mut buf).await.unwrap_or(0);
                assert!(buf[..n].starts_with(b"SSH-2.0-NetworkScope"));
            })
        })
        .await;
        let out = run(port).await;
        let ids = identity_entries(port, &out);
        assert_eq!(ids[&format!("svc.{port}.product")], "OpenSSH");
        assert_eq!(ids[&format!("svc.{port}.version")], "7.4");
        assert!(
            ids[&format!("ssh.{port}.weak")].contains("group1"),
            "{ids:?}"
        );
        assert!(ids[&format!("ssh.{port}.legacy")].contains("aes128-cbc"));
    }

    #[test]
    fn smb_request_and_responses() {
        let req = smb2_negotiate_request();
        assert_eq!(req.len(), 4 + 158);
        assert_eq!(&req[..4], &[0, 0, 0, 158]);
        assert_eq!(&req[4..8], &[0xFE, b'S', b'M', b'B']);
        let mut resp = vec![0u8; 4 + 64 + 8];
        resp[4..8].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
        resp[70..72].copy_from_slice(&3u16.to_le_bytes());
        resp[72..74].copy_from_slice(&0x0311u16.to_le_bytes());
        assert_eq!(
            parse_smb(&resp).unwrap().summary(),
            "microsoft-ds SMB 3.1.1 (signing required)"
        );
        resp[70] = 1;
        assert_eq!(
            parse_smb(&resp).unwrap().info,
            "signing enabled, not required"
        );
        let mut v1 = vec![0u8; 40];
        v1[4..8].copy_from_slice(&[0xFF, b'S', b'M', b'B']);
        assert!(parse_smb(&v1).unwrap().info.contains("SMBv1"));
        assert_eq!(parse_smb(&resp[..20]), None);
        assert_eq!(parse_smb(b"HTTP/1.1 200 OK\r\n\r\n"), None);
    }

    async fn serve<F>(handler: F) -> u16
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

    async fn run(port: u16) -> Outcome {
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
        }
        assert!(!is_ot_port(80));
    }
}
