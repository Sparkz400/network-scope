//! JARM-style active TLS server fingerprint (opt-in, never in Safe Mode).
//!
//! JARM (Salesforce, BSD-3-Clause, <https://github.com/salesforce/jarm>) sends ten differently
//! shaped TLS ClientHellos to one port and condenses the ServerHellos into a 62 character hash:
//! per probe the selected cipher (2 hex characters, its position in the cipher list) and the
//! selected version (1 letter), 30 characters in all, then the first 32 hex characters of the
//! SHA-256 over the ALPN and extension lists of all ten replies. All replies missing gives 62
//! zeros. Servers with the same TLS library, version and configuration answer the same way.
//!
//! Provenance and honesty: the probe parameters (version, cipher order, GREASE, ALPN list,
//! supported-versions, extension order) follow the public specification, but the cipher table,
//! the ALPN lists and the extension bodies here were written without the reference source at
//! hand and have NOT been compared with `jarm.py`. The hash has the JARM format and is stable
//! for a given server, so it is useful to spot identical servers inside one scan, but it must not
//! be compared with hashes from public JARM databases until the tables are diffed against the
//! reference implementation. The ClientHello builder uses the raw TLS code of `tls.rs`
//! (not rustls) so that it can offer SSL/TLS versions and suites that rustls refuses.
//!
//! Sending: ten short connections per port, each through the scan's rate gate, only to ports
//! that already identified as TLS and are neither industrial nor printer ports. The scanner
//! only enables it outside Safe Mode and with `--jarm`.
use crate::{core::Gate, fingerprint, tls};
use std::{net::IpAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

/// Cipher suites offered by the "ALL" probes; a reply's cipher is reported as its 1-based
/// position here.
const ALL: [u16; 69] = [
    0x0016, 0x0033, 0x0067, 0xc09e, 0xc0a2, 0x009e, 0x0039, 0x006b, 0xc09f, 0xc0a3, 0x009f, 0x0045,
    0x00be, 0x0088, 0x00c4, 0x009a, 0xc008, 0xc009, 0xc023, 0xc0ac, 0xc0ae, 0xc02b, 0xc00a, 0xc024,
    0xc0ad, 0xc0af, 0xc02c, 0xc072, 0xc073, 0xcca9, 0x1302, 0x1301, 0xcc14, 0xc007, 0xc012, 0xc013,
    0xc027, 0xc02f, 0xc014, 0xc028, 0xc030, 0xc060, 0xc061, 0xc076, 0xc077, 0xcca8, 0x1305, 0x1304,
    0x1303, 0xcc13, 0xc011, 0x000a, 0x002f, 0x003c, 0xc09c, 0xc0a0, 0x009c, 0x0035, 0x003d, 0xc09d,
    0xc0a1, 0x009d, 0x0041, 0x00ba, 0x0084, 0x00c0, 0x0007, 0x0004, 0x0005,
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Order {
    Forward,
    Reverse,
    TopHalf,
    BottomHalf,
    MiddleOut,
}
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Versions {
    None,
    Tls12,
    Tls13,
}

/// One of the ten probes.
#[derive(Clone, Copy, Debug)]
pub struct Probe {
    pub name: &'static str,
    version: u16,
    /// Offer the TLS 1.3 suites too ("ALL") or only the older ones.
    all_ciphers: bool,
    order: Order,
    grease: bool,
    rare_alpn: bool,
    supported_versions: Versions,
    reverse_extensions: bool,
}

#[allow(clippy::too_many_arguments)]
const fn probe(
    name: &'static str,
    version: u16,
    all_ciphers: bool,
    order: Order,
    grease: bool,
    rare_alpn: bool,
    supported_versions: Versions,
    reverse_extensions: bool,
) -> Probe {
    Probe {
        name,
        version,
        all_ciphers,
        order,
        grease,
        rare_alpn,
        supported_versions,
        reverse_extensions,
    }
}

/// The ten probes in the order they are sent and hashed.
pub const PROBES: [Probe; 10] = [
    probe(
        "tls1_2_forward",
        0x0303,
        true,
        Order::Forward,
        false,
        false,
        Versions::Tls12,
        true,
    ),
    probe(
        "tls1_2_reverse",
        0x0303,
        true,
        Order::Reverse,
        false,
        false,
        Versions::Tls12,
        false,
    ),
    probe(
        "tls1_2_top_half",
        0x0303,
        true,
        Order::TopHalf,
        false,
        false,
        Versions::None,
        false,
    ),
    probe(
        "tls1_2_bottom_half",
        0x0303,
        true,
        Order::BottomHalf,
        false,
        true,
        Versions::None,
        false,
    ),
    probe(
        "tls1_2_middle_out",
        0x0303,
        true,
        Order::MiddleOut,
        true,
        true,
        Versions::None,
        true,
    ),
    probe(
        "tls1_1_middle_out",
        0x0302,
        true,
        Order::Forward,
        false,
        false,
        Versions::None,
        false,
    ),
    probe(
        "tls1_3_forward",
        0x0303,
        true,
        Order::Forward,
        false,
        false,
        Versions::Tls13,
        true,
    ),
    probe(
        "tls1_3_reverse",
        0x0303,
        true,
        Order::Reverse,
        false,
        false,
        Versions::Tls13,
        false,
    ),
    probe(
        "tls1_3_invalid",
        0x0303,
        false,
        Order::Forward,
        false,
        false,
        Versions::Tls13,
        false,
    ),
    probe(
        "tls1_3_middle_out",
        0x0303,
        true,
        Order::MiddleOut,
        true,
        false,
        Versions::Tls13,
        true,
    ),
];

const GREASE: u16 = 0x0a0a;

const ALPN_COMMON: [&str; 10] = [
    "http/0.9", "http/1.0", "spdy/1", "spdy/2", "spdy/3", "h2c", "h2", "http/1.1", "webrtc", "ftp",
];

fn ciphers(p: &Probe) -> Vec<u16> {
    let base: Vec<u16> = ALL
        .iter()
        .copied()
        .filter(|c| p.all_ciphers || c >> 8 != 0x13)
        .collect();
    let n = base.len();
    let mut out: Vec<u16> = match p.order {
        Order::Forward => base,
        Order::Reverse => base.into_iter().rev().collect(),
        Order::BottomHalf => base[n / 2 + n % 2..].to_vec(),
        Order::TopHalf => {
            // The reversed top half, then the bottom half (the spec's "top half" order).
            let mut v: Vec<u16> = base[..n / 2 + n % 2].iter().rev().copied().collect();
            v.extend(&base[n / 2 + n % 2..]);
            v
        }
        Order::MiddleOut => {
            let mid = n / 2;
            let mut v = vec![base[mid]];
            for i in 1..=mid {
                if mid + i < n {
                    v.push(base[mid + i]);
                }
                v.push(base[mid - i]);
            }
            v
        }
    };
    if p.grease {
        out.insert(0, GREASE);
    }
    out
}

fn ext(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    out.extend(kind.to_be_bytes());
    out.extend((data.len() as u16).to_be_bytes());
    out.extend(data);
}

/// The ClientHello record of a probe. `host` goes into the server name extension; `random` and
/// `session` are the 32-byte client random and legacy session id (fixed in tests).
pub fn client_hello(p: &Probe, host: &str, random: [u8; 32], session: [u8; 32]) -> Vec<u8> {
    let suites = ciphers(p);
    let mut body = vec![];
    body.extend(p.version.to_be_bytes());
    body.extend(random);
    body.push(32);
    body.extend(session);
    body.extend(((suites.len() * 2) as u16).to_be_bytes());
    for s in &suites {
        body.extend(s.to_be_bytes());
    }
    body.extend([1, 0]);

    let mut exts: Vec<Vec<u8>> = vec![];
    let mut add = |kind: u16, data: &[u8]| {
        let mut e = vec![];
        ext(&mut e, kind, data);
        exts.push(e);
    };
    if p.grease {
        add(GREASE, &[]);
    }
    let name = host.as_bytes();
    let mut sni = vec![];
    sni.extend(((name.len() + 3) as u16).to_be_bytes());
    sni.push(0);
    sni.extend((name.len() as u16).to_be_bytes());
    sni.extend(name);
    add(0x0000, &sni);
    add(0x0017, &[]); // extended master secret
    add(0x0001, &[1]); // max fragment length
    add(0xff01, &[0]); // renegotiation info
    let mut groups = vec![];
    if p.grease {
        groups.extend(GREASE.to_be_bytes());
    }
    groups.extend([
        0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01,
    ]);
    let mut list = ((groups.len()) as u16).to_be_bytes().to_vec();
    list.extend(groups);
    add(0x000a, &list);
    add(0x000b, &[1, 0]); // EC point formats: uncompressed
    add(0x0023, &[]); // session ticket
    let alpn: Vec<&str> = ALPN_COMMON
        .iter()
        .copied()
        .filter(|a| !p.rare_alpn || !matches!(*a, "h2" | "http/1.1"))
        .collect();
    let mut protos = vec![];
    for a in alpn {
        protos.push(a.len() as u8);
        protos.extend(a.as_bytes());
    }
    let mut alpn_ext = (protos.len() as u16).to_be_bytes().to_vec();
    alpn_ext.extend(protos);
    add(0x0010, &alpn_ext);
    add(
        0x000d,
        &[
            0x00, 0x16, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09,
            0x08, 0x0a, 0x08, 0x0b, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01,
        ],
    );
    if p.supported_versions == Versions::Tls13 {
        // x25519 share with a fixed pattern; no key exchange is completed.
        let mut share = vec![0x00, 0x1d, 0x00, 0x20];
        share.extend(random.iter().rev());
        let mut ks = (share.len() as u16).to_be_bytes().to_vec();
        ks.extend(share);
        add(0x0033, &ks);
        add(0x002d, &[1, 1]); // PSK key exchange modes: psk_dhe_ke
    }
    match p.supported_versions {
        Versions::None => {}
        Versions::Tls12 => add(0x002b, &[2, 0x03, 0x03]),
        Versions::Tls13 => {
            let mut v = vec![8];
            v.extend([0x03, 0x04, 0x03, 0x03, 0x03, 0x02, 0x03, 0x01]);
            add(0x002b, &v);
        }
    }
    if p.reverse_extensions {
        exts.reverse();
    }
    let exts: Vec<u8> = exts.concat();
    body.extend((exts.len() as u16).to_be_bytes());
    body.extend(exts);

    let mut handshake = vec![1];
    handshake.extend(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend(body);
    let mut record = vec![22, 3, 1];
    record.extend((handshake.len() as u16).to_be_bytes());
    record.extend(handshake);
    record
}

/// What a ServerHello tells JARM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub cipher: u16,
    pub version: u16,
    /// Selected ALPN protocol, empty when none.
    pub alpn: String,
    /// Extension types in the order the server sent them.
    pub extensions: Vec<u16>,
}

fn be16(d: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*d.get(i)?, *d.get(i + 1)?]))
}

/// Reads a ServerHello from the first bytes a server answered with. `None` for an alert, for
/// anything that is not a ServerHello and for truncated data; never panics (fuzzed).
pub fn parse_response(data: &[u8]) -> Option<Response> {
    if *data.first()? != 22 || *data.get(5)? != 2 {
        return None;
    }
    let version = be16(data, 9)?;
    let sid = usize::from(*data.get(43)?);
    let at = 44 + sid;
    let cipher = be16(data, at)?;
    // compression method at at+2, extensions length at at+3
    let ext_len = usize::from(be16(data, at + 3).unwrap_or(0));
    let mut extensions = vec![];
    let mut alpn = String::new();
    let mut i = at + 5;
    let end = (i + ext_len).min(data.len());
    while i + 4 <= end && extensions.len() < 64 {
        let kind = be16(data, i)?;
        let len = usize::from(be16(data, i + 2)?);
        let body = data.get(i + 4..(i + 4 + len).min(end)).unwrap_or(&[]);
        extensions.push(kind);
        if kind == 0x0010 && body.len() >= 3 {
            let n = usize::from(body[2]).min(body.len() - 3);
            alpn = body[3..3 + n]
                .iter()
                .filter(|b| b.is_ascii_graphic())
                .map(|b| char::from(*b))
                .collect();
        }
        i += 4 + len;
    }
    Some(Response {
        cipher,
        version,
        alpn,
        extensions,
    })
}

/// The per-probe line the hash is built from: `cipher|version|alpn|ext-ext` (`|||` for no
/// ServerHello), as in the reference tool's raw output.
pub fn response_line(r: Option<&Response>) -> String {
    match r {
        None => "|||".into(),
        Some(r) => format!(
            "{:04x}|{:04x}|{}|{}",
            r.cipher,
            r.version,
            r.alpn,
            r.extensions
                .iter()
                .map(|e| format!("{e:04x}"))
                .collect::<Vec<_>>()
                .join("-")
        ),
    }
}

fn cipher_byte(line: &str) -> String {
    let hex = line.split('|').next().unwrap_or("");
    match u16::from_str_radix(hex, 16)
        .ok()
        .and_then(|c| ALL.iter().position(|a| *a == c))
    {
        Some(i) => format!("{:02x}", i + 1),
        None => "00".into(),
    }
}
fn version_byte(line: &str) -> char {
    let hex = line.split('|').nth(1).unwrap_or("");
    match u16::from_str_radix(hex, 16) {
        Ok(v) => ['a', 'b', 'c', 'd', 'e', 'f'][usize::from(v & 0xf).min(5)],
        Err(_) => '0',
    }
}

/// The 62 character fingerprint from the ten per-probe lines.
pub fn hash(lines: &[String]) -> String {
    if lines.iter().all(|l| l == "|||") {
        return "0".repeat(62);
    }
    let mut fuzzy = String::new();
    let mut tail = String::new();
    for l in lines {
        fuzzy.push_str(&cipher_byte(l));
        fuzzy.push(version_byte(l));
        let mut parts = l.split('|').skip(2);
        tail.push_str(parts.next().unwrap_or(""));
        tail.push_str(parts.next().unwrap_or(""));
    }
    let digest = fingerprint::hex(&fingerprint::sha256(tail.as_bytes()));
    format!("{fuzzy}{}", &digest[..32])
}

/// Same-shaped check for tests and the identity value: 62 lower-case hex characters.
pub fn is_jarm(s: &str) -> bool {
    s.len() == 62
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// JARM runs only when asked for (`--jarm`), after service detection found the TLS ports, and
/// never in Safe Mode.
pub fn enabled(s: &crate::scan::Settings) -> bool {
    s.jarm && s.services && !s.safe
}

/// Ports JARM never touches: industrial and printer ports (the generic probes' deny list).
pub fn allowed_port(port: u16) -> bool {
    !crate::service::is_ot_udp_port(port)
}

/// Fingerprints one TLS port with ten connections, each through the rate gate. `None` when the
/// port is on the deny list.
pub async fn fingerprint(ip: IpAddr, port: u16, limit: Duration, gate: &Gate) -> Option<String> {
    if !allowed_port(port) {
        return None;
    }
    let host = ip.to_string();
    let mut lines = vec![];
    for p in &PROBES {
        gate.wait().await;
        let reply = send(ip, port, &client_hello(p, &host, random(), random()), limit).await;
        lines.push(response_line(
            reply.as_deref().and_then(parse_response).as_ref(),
        ));
    }
    Some(hash(&lines))
}

fn random() -> [u8; 32] {
    tls::random32()
}

async fn send(ip: IpAddr, port: u16, hello: &[u8], limit: Duration) -> Option<Vec<u8>> {
    let mut stream = timeout(limit, TcpStream::connect((ip, port)))
        .await
        .ok()?
        .ok()?;
    stream.write_all(hello).await.ok()?;
    let mut buf = vec![0u8; 1484];
    let n = timeout(limit, stream.read(&mut buf)).await.ok()?.ok()?;
    buf.truncate(n);
    (n > 0).then_some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic ServerHello: TLS 1.2, cipher `c`, ALPN `h2`, extensions 0xff01 and 0x0010.
    fn server_hello(cipher: u16, alpn: Option<&str>, version: u16) -> Vec<u8> {
        let mut exts = vec![];
        ext(&mut exts, 0xff01, &[0]);
        if let Some(a) = alpn {
            let mut body = ((a.len() + 1) as u16).to_be_bytes().to_vec();
            body.push(a.len() as u8);
            body.extend(a.as_bytes());
            ext(&mut exts, 0x0010, &body);
        }
        let mut body = version.to_be_bytes().to_vec();
        body.extend([7u8; 32]);
        body.push(0);
        body.extend(cipher.to_be_bytes());
        body.push(0);
        body.extend((exts.len() as u16).to_be_bytes());
        body.extend(exts);
        let mut hs = vec![2];
        hs.extend(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend(body);
        let mut rec = vec![22, 3, 3];
        rec.extend((hs.len() as u16).to_be_bytes());
        rec.extend(hs);
        rec
    }

    #[test]
    fn there_are_ten_probes_with_distinct_shapes() {
        assert_eq!(PROBES.len(), 10);
        let hellos: Vec<Vec<u8>> = PROBES
            .iter()
            .map(|p| client_hello(p, "10.0.0.1", [1; 32], [2; 32]))
            .collect();
        for (i, a) in hellos.iter().enumerate() {
            assert_eq!(a[0], 22, "handshake record");
            assert_eq!(a[5], 1, "ClientHello");
            assert_eq!(usize::from(be16(a, 3).unwrap()) + 5, a.len());
            for b in &hellos[i + 1..] {
                assert_ne!(a, b, "two probes are identical");
            }
        }
        // The TLS 1.1 probe says so; the "invalid" probe offers no TLS 1.3 suite.
        assert_eq!(be16(&hellos[5], 9), Some(0x0302));
        assert!(!ciphers(&PROBES[8]).iter().any(|c| c >> 8 == 0x13));
        assert!(ciphers(&PROBES[0]).iter().any(|c| c >> 8 == 0x13));
        // GREASE probes start with the GREASE value in suites and extensions.
        assert_eq!(ciphers(&PROBES[4])[0], GREASE);
        // Every ordering is a permutation (middle out, top half) or subset (bottom half).
        let all = ciphers(&PROBES[0]);
        for p in [&PROBES[1], &PROBES[2], &PROBES[7]] {
            let mut a = ciphers(p);
            let mut b = all.clone();
            a.sort_unstable();
            b.sort_unstable();
            assert_eq!(a, b);
        }
        assert_eq!(ciphers(&PROBES[1])[0], *all.last().unwrap());
        assert!(ciphers(&PROBES[3]).len() < all.len());
        let mut mid = ciphers(&PROBES[9]);
        mid.remove(0);
        mid.sort_unstable();
        assert_eq!(mid.len(), all.iter().filter(|c| **c != GREASE).count());
    }

    #[test]
    fn hello_builder_is_deterministic_and_carries_the_name() {
        let a = client_hello(&PROBES[0], "192.0.2.7", [1; 32], [2; 32]);
        assert_eq!(a, client_hello(&PROBES[0], "192.0.2.7", [1; 32], [2; 32]));
        assert!(a.windows(9).any(|w| w == b"192.0.2.7"));
        assert_ne!(a, client_hello(&PROBES[0], "192.0.2.8", [1; 32], [2; 32]));
    }

    #[test]
    fn server_hello_parsing_and_the_hash_format() {
        let h = server_hello(0xc02f, Some("h2"), 0x0303);
        let r = parse_response(&h).unwrap();
        assert_eq!(
            (r.cipher, r.version, r.alpn.as_str()),
            (0xc02f, 0x0303, "h2")
        );
        assert_eq!(r.extensions, [0xff01, 0x0010]);
        assert_eq!(response_line(Some(&r)), "c02f|0303|h2|ff01-0010");
        // Ten identical replies: 10 x (cipher index + version letter) + 32 hex of SHA-256.
        let line = response_line(Some(&r));
        let lines = vec![line; 10];
        let jarm = hash(&lines);
        assert!(is_jarm(&jarm), "{jarm}");
        let index = ALL.iter().position(|c| *c == 0xc02f).unwrap() + 1;
        assert_eq!(&jarm[..3], format!("{index:02x}d"));
        assert_eq!(&jarm[..30], format!("{index:02x}d").repeat(10));
        let expected = fingerprint::hex(&fingerprint::sha256(b"h2ff01-0010".repeat(10).as_slice()));
        assert_eq!(&jarm[30..], &expected[..32]);
        // Deterministic, and different replies give different hashes.
        assert_eq!(jarm, hash(&vec![response_line(Some(&r)); 10]));
        let other = parse_response(&server_hello(0x1301, None, 0x0303)).unwrap();
        let mixed: Vec<String> = (0..10)
            .map(|i| response_line(Some(if i < 5 { &r } else { &other })))
            .collect();
        let mixed = hash(&mixed);
        assert!(is_jarm(&mixed));
        assert_ne!(mixed, jarm);
        // TLS 1.0 and 1.1 replies are letters b and c.
        assert_eq!(version_byte("c02f|0301||"), 'b');
        assert_eq!(version_byte("c02f|0302||"), 'c');
        assert_eq!(version_byte("||"), '0');
        // No replies at all: 62 zeros. A cipher outside the list: "00".
        assert_eq!(hash(&vec!["|||".to_string(); 10]), "0".repeat(62));
        assert!(is_jarm(&"0".repeat(62)));
        assert_eq!(cipher_byte("ffff|0303||"), "00");
        // Not a JARM: wrong length, upper case, other characters.
        assert!(!is_jarm("abc") && !is_jarm(&"A".repeat(62)) && !is_jarm(&"g".repeat(62)));
    }

    #[test]
    fn non_server_hello_input_is_rejected_without_panicking() {
        assert_eq!(parse_response(&[]), None);
        assert_eq!(parse_response(&[21, 3, 3, 0, 2, 2, 40]), None, "an alert");
        assert_eq!(parse_response(b"HTTP/1.1 400 Bad Request\r\n\r\n"), None);
        let good = server_hello(0xc02f, Some("h2"), 0x0303);
        // Every truncation is handled: either a parse of what is there or None.
        for n in 0..good.len() {
            let _ = parse_response(&good[..n]);
        }
        // Hostile lengths: an extension longer than the data, a huge session id length.
        let mut bad = good.clone();
        let len = bad.len();
        bad[len - 7] = 0xff;
        let _ = parse_response(&bad);
        let mut sid = good.clone();
        sid[43] = 255;
        let _ = parse_response(&sid);
        // Many extensions are bounded.
        let mut exts = vec![];
        for _ in 0..500 {
            ext(&mut exts, 0x0017, &[]);
        }
        let mut many = server_hello(0xc02f, None, 0x0303);
        many.truncate(5 + 4 + 2 + 32 + 1 + 2 + 1);
        many.extend((exts.len() as u16).to_be_bytes());
        many.extend(exts);
        assert!(parse_response(&many).unwrap().extensions.len() <= 64);
    }

    #[test]
    fn jarm_is_off_by_default_and_off_in_safe_mode() {
        use crate::scan::Settings;
        let base = Settings::default();
        assert!(!base.jarm && !enabled(&base), "off by default");
        let on = Settings {
            jarm: true,
            services: true,
            safe: false,
            ..base.clone()
        };
        assert!(enabled(&on));
        assert!(
            !enabled(&Settings {
                safe: true,
                ..on.clone()
            }),
            "Safe Mode"
        );
        assert!(
            !enabled(&Settings {
                services: false,
                ..on.clone()
            }),
            "needs TLS ports"
        );
        assert!(!enabled(&Settings { jarm: false, ..on }));
    }

    #[test]
    fn industrial_and_printer_ports_are_never_fingerprinted() {
        for p in [102u16, 502, 2222, 44818, 47808, 9100, 515] {
            assert!(!allowed_port(p), "{p}");
        }
        for p in [443u16, 8443, 993] {
            assert!(allowed_port(p), "{p}");
        }
    }

    #[tokio::test]
    async fn a_tls_server_gets_ten_hellos_and_a_stable_hash() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    return;
                };
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(&server_hello(0xc030, Some("http/1.1"), 0x0303))
                    .await;
            }
        });
        let gate = Gate::unlimited();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let a = fingerprint(ip, port, Duration::from_secs(2), &gate)
            .await
            .unwrap();
        let b = fingerprint(ip, port, Duration::from_secs(2), &gate)
            .await
            .unwrap();
        assert!(is_jarm(&a) && a == b, "{a} {b}");
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 20);
        // A port that answers nothing: all probes empty, 62 zeros.
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cport = closed.local_addr().unwrap().port();
        drop(closed);
        let none = fingerprint(ip, cport, Duration::from_millis(300), &gate)
            .await
            .unwrap();
        assert_eq!(none, "0".repeat(62));
        // Deny list.
        assert_eq!(
            fingerprint(ip, 502, Duration::from_millis(100), &gate).await,
            None
        );
    }
}
