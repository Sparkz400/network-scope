//! TLS inspection. A rustls handshake that validates nothing collects the certificate and the
//! negotiated TLS 1.2/1.3 parameters; a hand-built ClientHello then asks which protocol
//! versions (SSLv3 to TLS 1.2) and cipher suites the server accepts, including legacy and
//! weak ones that rustls refuses to speak. Certificates are inventory data, never trusted.
use crate::core::Gate;
use rustls::{
    ClientConfig, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use x509_parser::{prelude::*, public_key::PublicKey};

pub type Fields = BTreeMap<String, String>;

#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);
impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn connector() -> Result<TlsConnector, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// Opens a TLS session on an already connected socket.
pub async fn wrap(
    tcp: TcpStream,
    ip: IpAddr,
    limit: Duration,
) -> Result<(TlsStream<TcpStream>, Fields), String> {
    let stream = timeout(limit, connector()?.connect(ServerName::from(ip), tcp))
        .await
        .map_err(|_| "TLS handshake timed out".to_string())?
        .map_err(|e| e.to_string())?;
    let (_, conn) = stream.get_ref();
    let mut fields = Fields::new();
    if let Some(v) = conn.protocol_version() {
        fields.insert(
            "negotiated".into(),
            match v {
                rustls::ProtocolVersion::TLSv1_3 => "TLS1.3".into(),
                rustls::ProtocolVersion::TLSv1_2 => "TLS1.2".into(),
                other => format!("{other:?}"),
            },
        );
    }
    if let Some(c) = conn.negotiated_cipher_suite() {
        fields.insert("cipher".into(), format!("{:?}", c.suite()));
    }
    if let Some(cert) = conn.peer_certificates().and_then(|c| c.first()) {
        fields.extend(cert_fields(cert.as_ref()));
    }
    Ok((stream, fields))
}

/// Certificate fields, or `cert_error` when x509-parser cannot read it: an unparseable
/// certificate must not discard the handshake facts (and make the port look like plaintext).
fn cert_fields(der: &[u8]) -> Fields {
    describe_cert(der).unwrap_or_else(|e| Fields::from([("cert_error".to_string(), e)]))
}

pub fn date(ts: i64) -> String {
    let z = ts.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

fn signature_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.4" => "md5WithRSA (weak)",
        "1.2.840.113549.1.1.5" => "sha1WithRSA (weak)",
        "1.2.840.113549.1.1.11" => "sha256WithRSA",
        "1.2.840.113549.1.1.12" => "sha384WithRSA",
        "1.2.840.113549.1.1.13" => "sha512WithRSA",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1 (weak)",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.3.101.112" => "Ed25519",
        other => return other.to_string(),
    }
    .to_string()
}

/// Issuer equals subject, and when both key identifiers are present the authority key
/// identifier names the certificate's own key. (Checking the signature itself would need
/// x509-parser's `verify` feature, which is not enabled.) A CA-issued certificate that
/// happens to carry its issuer's name is thereby not reported as self-signed.
fn is_self_signed(cert: &X509Certificate<'_>) -> bool {
    if cert.subject() != cert.issuer() {
        return false;
    }
    let mut ski = None;
    let mut aki = None;
    for ext in cert.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(k) => ski = Some(k.0),
            ParsedExtension::AuthorityKeyIdentifier(a) => {
                aki = a.key_identifier.as_ref().map(|k| k.0)
            }
            _ => {}
        }
    }
    match (aki, ski) {
        (Some(a), Some(s)) => a == s,
        _ => true,
    }
}

pub fn describe_cert(der: &[u8]) -> Result<Fields, String> {
    let (_, cert) =
        X509Certificate::from_der(der).map_err(|e| format!("Certificate not parseable: {e}"))?;
    let mut f = Fields::new();
    let subject = cert.subject().to_string();
    f.insert("subject".into(), subject.clone());
    if let Some(cn) = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
    {
        f.insert("cn".into(), cn.to_string());
    }
    f.insert("issuer".into(), cert.issuer().to_string());
    f.insert("self_signed".into(), is_self_signed(&cert).to_string());
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        let names: Vec<String> = san
            .value
            .general_names
            .iter()
            .take(32)
            .filter_map(|n| match n {
                GeneralName::DNSName(d) => Some((*d).to_string()),
                GeneralName::IPAddress(b) => match b.len() {
                    4 => Some(IpAddr::from(<[u8; 4]>::try_from(*b).ok()?).to_string()),
                    16 => Some(IpAddr::from(<[u8; 16]>::try_from(*b).ok()?).to_string()),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        if !names.is_empty() {
            f.insert("san".into(), names.join(", "));
        }
    }
    let (from, to) = (
        cert.validity().not_before.timestamp(),
        cert.validity().not_after.timestamp(),
    );
    f.insert("not_before".into(), date(from));
    f.insert("not_after".into(), date(to));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    f.insert("expired".into(), (now > to).to_string());
    f.insert("not_yet_valid".into(), (now < from).to_string());
    f.insert(
        "days_left".into(),
        ((to - now).div_euclid(86_400)).to_string(),
    );
    f.insert(
        "signature".into(),
        signature_name(&cert.signature_algorithm.algorithm.to_id_string()),
    );
    match cert.public_key().parsed() {
        Ok(PublicKey::RSA(rsa)) => {
            f.insert("key".into(), format!("RSA {}", rsa.key_size()));
        }
        Ok(PublicKey::EC(ec)) => {
            f.insert("key".into(), format!("EC {}", ec.key_size()));
        }
        Ok(_) => {
            f.insert("key".into(), "other".into());
        }
        Err(_) => {}
    }
    Ok(f)
}

// ---- raw ClientHello enumeration -------------------------------------------------------

pub const VERSIONS: [(u16, &str); 4] = [
    (0x0300, "SSLv3"),
    (0x0301, "TLS1.0"),
    (0x0302, "TLS1.1"),
    (0x0303, "TLS1.2"),
];

/// (id, name, weakness). Weak ones are broken or deprecated primitives.
pub const SUITES: &[(u16, &str, Option<&str>)] = &[
    (0xC02F, "ECDHE_RSA_AES_128_GCM_SHA256", None),
    (0xC030, "ECDHE_RSA_AES_256_GCM_SHA384", None),
    (0xC02B, "ECDHE_ECDSA_AES_128_GCM_SHA256", None),
    (0xC02C, "ECDHE_ECDSA_AES_256_GCM_SHA384", None),
    (0xCCA8, "ECDHE_RSA_CHACHA20_POLY1305", None),
    (0xCCA9, "ECDHE_ECDSA_CHACHA20_POLY1305", None),
    (0x009E, "DHE_RSA_AES_128_GCM_SHA256", None),
    (0x009F, "DHE_RSA_AES_256_GCM_SHA384", None),
    (0xCCAA, "DHE_RSA_CHACHA20_POLY1305", None),
    (0xC027, "ECDHE_RSA_AES_128_CBC_SHA256", None),
    (0xC028, "ECDHE_RSA_AES_256_CBC_SHA384", None),
    (0xC023, "ECDHE_ECDSA_AES_128_CBC_SHA256", None),
    (0xC024, "ECDHE_ECDSA_AES_256_CBC_SHA384", None),
    (0xC013, "ECDHE_RSA_AES_128_CBC_SHA", None),
    (0xC014, "ECDHE_RSA_AES_256_CBC_SHA", None),
    (0xC009, "ECDHE_ECDSA_AES_128_CBC_SHA", None),
    (0xC00A, "ECDHE_ECDSA_AES_256_CBC_SHA", None),
    (0x0067, "DHE_RSA_AES_128_CBC_SHA256", None),
    (0x006B, "DHE_RSA_AES_256_CBC_SHA256", None),
    (0x0033, "DHE_RSA_AES_128_CBC_SHA", None),
    (0x0039, "DHE_RSA_AES_256_CBC_SHA", None),
    (0x009C, "RSA_AES_128_GCM_SHA256", Some("no forward secrecy")),
    (0x009D, "RSA_AES_256_GCM_SHA384", Some("no forward secrecy")),
    (0x003C, "RSA_AES_128_CBC_SHA256", Some("no forward secrecy")),
    (0x003D, "RSA_AES_256_CBC_SHA256", Some("no forward secrecy")),
    (0x002F, "RSA_AES_128_CBC_SHA", Some("no forward secrecy")),
    (0x0035, "RSA_AES_256_CBC_SHA", Some("no forward secrecy")),
    (0xC012, "ECDHE_RSA_3DES_EDE_CBC_SHA", Some("3DES (Sweet32)")),
    (
        0xC008,
        "ECDHE_ECDSA_3DES_EDE_CBC_SHA",
        Some("3DES (Sweet32)"),
    ),
    (0x0016, "DHE_RSA_3DES_EDE_CBC_SHA", Some("3DES (Sweet32)")),
    (0x000A, "RSA_3DES_EDE_CBC_SHA", Some("3DES (Sweet32)")),
    (0xC011, "ECDHE_RSA_RC4_128_SHA", Some("RC4")),
    (0xC007, "ECDHE_ECDSA_RC4_128_SHA", Some("RC4")),
    (0x0005, "RSA_RC4_128_SHA", Some("RC4")),
    (0x0004, "RSA_RC4_128_MD5", Some("RC4")),
    (0x0009, "RSA_DES_CBC_SHA", Some("single DES")),
    (0x0015, "DHE_RSA_DES_CBC_SHA", Some("single DES")),
    (0x0008, "RSA_EXPORT_DES40_CBC_SHA", Some("export-grade")),
    (0x0003, "RSA_EXPORT_RC4_40_MD5", Some("export-grade")),
    (0x0006, "RSA_EXPORT_RC2_CBC_40_MD5", Some("export-grade")),
    (
        0x0018,
        "DH_anon_RC4_128_MD5",
        Some("anonymous, unauthenticated"),
    ),
    (
        0x001B,
        "DH_anon_3DES_EDE_CBC_SHA",
        Some("anonymous, unauthenticated"),
    ),
    (
        0x0034,
        "DH_anon_AES_128_CBC_SHA",
        Some("anonymous, unauthenticated"),
    ),
    (
        0x003A,
        "DH_anon_AES_256_CBC_SHA",
        Some("anonymous, unauthenticated"),
    ),
    (
        0xC018,
        "ECDH_anon_AES_128_CBC_SHA",
        Some("anonymous, unauthenticated"),
    ),
    (0x0002, "RSA_NULL_SHA", Some("no encryption")),
    (0x0001, "RSA_NULL_MD5", Some("no encryption")),
    (0x003B, "RSA_NULL_SHA256", Some("no encryption")),
    (0xC010, "ECDHE_RSA_NULL_SHA", Some("no encryption")),
];

pub fn suite(id: u16) -> Option<(&'static str, Option<&'static str>)> {
    SUITES.iter().find(|s| s.0 == id).map(|s| (s.1, s.2))
}

fn mix(seed: u64) -> u64 {
    let mut x = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}
fn random32() -> [u8; 32] {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(7)
        ^ COUNTER
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .rotate_left(32);
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        seed = mix(seed);
        chunk.copy_from_slice(&seed.to_le_bytes()[..chunk.len()]);
    }
    out
}

fn extension(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    out.extend(kind.to_be_bytes());
    out.extend((data.len() as u16).to_be_bytes());
    out.extend(data);
}

pub fn client_hello(version: u16, suites: &[u16], random: [u8; 32]) -> Vec<u8> {
    let mut body = vec![];
    body.extend(version.to_be_bytes());
    body.extend(random);
    body.push(0);
    body.extend(((suites.len() * 2) as u16).to_be_bytes());
    for s in suites {
        body.extend(s.to_be_bytes());
    }
    body.extend([1, 0]);
    if version > 0x0300 {
        let mut exts = vec![];
        extension(&mut exts, 10, &[0, 8, 0, 23, 0, 24, 0, 25, 0, 29]);
        extension(&mut exts, 11, &[1, 0]);
        extension(
            &mut exts,
            13,
            &[0, 16, 4, 1, 5, 1, 6, 1, 4, 3, 5, 3, 6, 3, 2, 1, 2, 3],
        );
        extension(&mut exts, 0xff01, &[0]);
        body.extend((exts.len() as u16).to_be_bytes());
        body.extend(exts);
    }
    let mut handshake = vec![1];
    handshake.extend(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend(body);
    let mut record = vec![22];
    record.extend(if version == 0x0300 { [3, 0] } else { [3, 1] });
    record.extend((handshake.len() as u16).to_be_bytes());
    record.extend(handshake);
    record
}

#[derive(Debug, PartialEq)]
pub enum Reply {
    Accepted {
        version: u16,
        cipher: u16,
        cert: Option<Vec<u8>>,
        /// JA4S of the ServerHello.
        ja4s: String,
    },
    Alert(u8),
    Other,
}

/// Parses the server's first flight: concatenates handshake records, then walks the messages.
pub fn parse_flight(data: &[u8]) -> Reply {
    let mut handshake = vec![];
    let mut i = 0;
    while let Some(head) = data.get(i..i + 5) {
        let len = usize::from(u16::from_be_bytes([head[3], head[4]]));
        let Some(payload) = data.get(i + 5..i + 5 + len).or_else(|| data.get(i + 5..)) else {
            break;
        };
        match head[0] {
            21 if handshake.is_empty() => {
                return Reply::Alert(payload.get(1).copied().unwrap_or(0));
            }
            22 => handshake.extend_from_slice(payload),
            _ => return Reply::Other,
        }
        i += 5 + len;
    }
    let (mut version, mut cipher, mut cert, mut ja4s) = (None, None, None, String::new());
    let mut j = 0;
    while let Some(head) = handshake.get(j..j + 4) {
        let len = (usize::from(head[1]) << 16) | (usize::from(head[2]) << 8) | usize::from(head[3]);
        let body = &handshake[(j + 4).min(handshake.len())..(j + 4 + len).min(handshake.len())];
        match head[0] {
            2 if body.len() >= 38 => {
                version = Some(u16::from_be_bytes([body[0], body[1]]));
                let sid = usize::from(body[34]);
                if let Some(c) = body.get(35 + sid..37 + sid) {
                    cipher = Some(u16::from_be_bytes([c[0], c[1]]));
                }
                if let Some(h) = crate::fingerprint::parse_server_hello(body) {
                    ja4s = crate::fingerprint::ja4s(&h);
                }
            }
            11 if body.len() >= 6 => {
                let first = (usize::from(body[3]) << 16)
                    | (usize::from(body[4]) << 8)
                    | usize::from(body[5]);
                cert = body.get(6..6 + first).map(<[u8]>::to_vec);
            }
            _ => {}
        }
        j += 4 + len;
    }
    match (version, cipher) {
        (Some(version), Some(cipher)) => Reply::Accepted {
            version,
            cipher,
            cert,
            ja4s,
        },
        _ => Reply::Other,
    }
}

async fn hello(
    ip: IpAddr,
    port: u16,
    version: u16,
    suites: &[u16],
    limit: Duration,
) -> Result<Reply, String> {
    let mut stream = timeout(limit, TcpStream::connect((ip, port)))
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|e| e.to_string())?;
    stream
        .write_all(&client_hello(version, suites, random32()))
        .await
        .map_err(|e| e.to_string())?;
    let mut data = vec![];
    let mut chunk = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + limit;
    while data.len() < 65_536 {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match timeout(left, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => data.extend_from_slice(&chunk[..n]),
            Ok(Err(_)) => break,
        }
        // ServerHelloDone ends the flight in every version up to TLS 1.2.
        if matches!(parse_flight(&data), Reply::Accepted { .. }) && has_done(&data) {
            break;
        }
        if matches!(parse_flight(&data), Reply::Alert(_)) {
            break;
        }
    }
    if data.is_empty() {
        return Err("closed without a TLS reply".into());
    }
    Ok(parse_flight(&data))
}

pub(crate) fn has_done(data: &[u8]) -> bool {
    let mut handshake = vec![];
    let mut i = 0;
    while let Some(head) = data.get(i..i + 5) {
        let len = usize::from(u16::from_be_bytes([head[3], head[4]]));
        if head[0] == 22 {
            handshake.extend_from_slice(
                data.get(i + 5..(i + 5 + len).min(data.len()))
                    .unwrap_or(&[]),
            );
        }
        i += 5 + len;
    }
    let mut j = 0;
    while let Some(head) = handshake.get(j..j + 4) {
        if head[0] == 14 {
            return true;
        }
        j +=
            4 + ((usize::from(head[1]) << 16) | (usize::from(head[2]) << 8) | usize::from(head[3]));
    }
    false
}

// ---- TLS 1.3 -----------------------------------------------------------------------------

/// The five TLS 1.3 cipher suites (RFC 8446 B.4) and a weakness note.
pub const TLS13_SUITES: [(u16, &str, Option<&str>); 5] = [
    (0x1301, "TLS_AES_128_GCM_SHA256", None),
    (0x1302, "TLS_AES_256_GCM_SHA384", None),
    (0x1303, "TLS_CHACHA20_POLY1305_SHA256", None),
    (0x1304, "TLS_AES_128_CCM_SHA256", None),
    (
        0x1305,
        "TLS_AES_128_CCM_8_SHA256",
        Some("truncated 8-byte tag"),
    ),
];

/// A TLS 1.3-only ClientHello: supported_versions offers only 0x0304 and the key_share carries
/// a random 32-byte x25519 value. No key is ever derived: only the ServerHello is read.
pub fn client_hello13(
    suites: &[u16],
    random: [u8; 32],
    session: [u8; 32],
    share: [u8; 32],
) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend(random);
    body.push(32); // legacy session id (middlebox compatibility)
    body.extend(session);
    body.extend(((suites.len() * 2) as u16).to_be_bytes());
    for s in suites {
        body.extend(s.to_be_bytes());
    }
    body.extend([1, 0]);
    let mut exts = vec![];
    extension(&mut exts, 10, &[0, 6, 0, 0x1d, 0, 0x17, 0, 0x18]);
    extension(
        &mut exts,
        13,
        &[
            0, 20, 4, 3, 5, 3, 6, 3, 8, 4, 8, 5, 8, 6, 8, 7, 4, 1, 5, 1, 6, 1,
        ],
    );
    extension(&mut exts, 43, &[2, 3, 4]);
    extension(&mut exts, 45, &[1, 1]);
    let mut key_share = vec![0, 36, 0, 0x1d, 0, 32];
    key_share.extend(share);
    extension(&mut exts, 51, &key_share);
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

#[derive(Debug, PartialEq)]
pub enum First {
    Hello(crate::fingerprint::ServerHello),
    Alert(u8),
    /// More bytes are needed for a complete first handshake message.
    Incomplete,
    Other,
}

/// The first handshake message of the server's flight. TLS 1.3 servers follow the ServerHello
/// with ChangeCipherSpec and encrypted records, so parsing stops at the first message.
pub fn first_server_hello(data: &[u8]) -> First {
    let mut handshake = vec![];
    let mut i = 0;
    while let Some(head) = data.get(i..i + 5) {
        let len = usize::from(u16::from_be_bytes([head[3], head[4]]));
        let payload = data
            .get(i + 5..(i + 5 + len).min(data.len()))
            .unwrap_or(&[]);
        match head[0] {
            21 if handshake.is_empty() => {
                return match payload.get(1) {
                    Some(d) => First::Alert(*d),
                    None => First::Incomplete,
                };
            }
            22 => handshake.extend_from_slice(payload),
            _ if handshake.is_empty() => return First::Other,
            _ => break,
        }
        i += 5 + len;
    }
    let Some(head) = handshake.get(..4) else {
        return if data.len() < 5 || data.first() == Some(&22) || data.first() == Some(&21) {
            First::Incomplete
        } else {
            First::Other
        };
    };
    let len = (usize::from(head[1]) << 16) | (usize::from(head[2]) << 8) | usize::from(head[3]);
    let Some(body) = handshake.get(4..4 + len) else {
        return First::Incomplete;
    };
    match head[0] {
        2 => crate::fingerprint::parse_server_hello(body).map_or(First::Other, First::Hello),
        _ => First::Other,
    }
}

async fn hello13(ip: IpAddr, port: u16, suites: &[u16], limit: Duration) -> First {
    let Ok(Ok(mut stream)) = timeout(limit, TcpStream::connect((ip, port))).await else {
        return First::Other;
    };
    if stream
        .write_all(&client_hello13(suites, random32(), random32(), random32()))
        .await
        .is_err()
    {
        return First::Other;
    }
    let mut data = vec![];
    let mut chunk = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + limit;
    while data.len() < 65_536 {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        match timeout(left, stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => data.extend_from_slice(&chunk[..n]),
            _ => break,
        }
        if first_server_hello(&data) != First::Incomplete {
            break;
        }
    }
    match first_server_hello(&data) {
        First::Incomplete => First::Other,
        other => other,
    }
}

/// Which TLS 1.3 suites does the server accept? One hello per round, each offering the suites
/// not yet chosen, until the server refuses or `rounds` (at most 6) is spent. A
/// HelloRetryRequest names the chosen suite as well and counts as acceptance. The first hello
/// always offers all five suites, so its ServerHello gives a comparable JA4S.
pub async fn enumerate13(
    ip: IpAddr,
    port: u16,
    limit: Duration,
    rounds: usize,
    gate: &Gate,
) -> (Vec<u16>, bool, Option<String>) {
    let mut offered: Vec<u16> = TLS13_SUITES.iter().map(|s| s.0).collect();
    let mut chosen = vec![];
    let mut ja4s = None;
    let mut budget = rounds.min(6);
    let mut exhausted = false;
    while budget > 0 && !exhausted {
        budget -= 1;
        gate.wait().await;
        match hello13(ip, port, &offered, limit).await {
            First::Hello(h)
                if h.selected_version == Some(0x0304) && offered.contains(&h.cipher) =>
            {
                if chosen.is_empty() && !h.retry {
                    ja4s = Some(crate::fingerprint::ja4s(&h));
                }
                chosen.push(h.cipher);
                offered.retain(|c| *c != h.cipher);
                exhausted = offered.is_empty();
            }
            _ => exhausted = true,
        }
    }
    (chosen, !exhausted, ja4s)
}

fn suite13_name(id: u16) -> (&'static str, Option<&'static str>) {
    TLS13_SUITES
        .iter()
        .find(|s| s.0 == id)
        .map_or(("unknown", None), |s| (s.1, s.2))
}
#[derive(Debug, Default)]
pub struct Support {
    /// For each protocol version the server accepts: the suites it chose, in selection order.
    pub accepted: Vec<(u16, Vec<u16>)>,
    pub cert: Option<Vec<u8>>,
    /// Versions whose suite list is incomplete because the round budget ran out.
    pub truncated: Vec<u16>,
    /// JA4S of the first full-offer hello the server accepted (highest version first).
    pub ja4s: Option<String>,
    /// TLS 1.3 suites in selection order (filled by `enumerate13`).
    pub tls13: Vec<u16>,
    pub tls13_truncated: bool,
}

/// Weakness classes that each map to one finding (tls-broken-cipher, tls-3des, tls-no-pfs).
/// Servers choose by their own preference, so strong suites always win a mixed offer; each
/// class therefore gets a dedicated hello offering only its suites.
const WEAK_CLASSES: [&[&str]; 3] = [
    &[
        "RC4",
        "single DES",
        "export-grade",
        "anonymous, unauthenticated",
        "no encryption",
    ],
    &["3DES (Sweet32)"],
    &["no forward secrecy"],
];

fn in_class(id: u16, class: &[&str]) -> bool {
    suite(id)
        .and_then(|s| s.1)
        .is_some_and(|w| class.contains(&w))
}

/// Which versions and suites does the server accept? `rounds` bounds the hellos per version
/// (at most 4 below TLS 1.2). Per version: one hello offering everything (an unsupported
/// version stops there), then one hello per weakness class not yet seen, then the remaining
/// budget enumerates further suites, each round removing the suite the server picked.
pub async fn enumerate(
    ip: IpAddr,
    port: u16,
    limit: Duration,
    rounds: usize,
    gate: &Gate,
) -> Support {
    let mut support = Support::default();
    for (version, _) in VERSIONS.iter().rev() {
        let mut offered: Vec<u16> = SUITES.iter().map(|s| s.0).collect();
        let mut chosen = vec![];
        let mut budget = if *version == 0x0303 {
            rounds
        } else {
            rounds.min(4)
        };
        let ask = |suites: Vec<u16>| {
            let version = *version;
            async move {
                gate.wait().await;
                match hello(ip, port, version, &suites, limit).await {
                    Ok(Reply::Accepted {
                        version: v,
                        cipher,
                        cert,
                        ja4s,
                    }) if v == version && suites.contains(&cipher) => Some((cipher, cert, ja4s)),
                    _ => None,
                }
            }
        };
        if budget == 0 {
            break;
        }
        budget -= 1;
        let Some((first, cert, ja4s)) = ask(offered.clone()).await else {
            continue;
        };
        if support.ja4s.is_none() && !ja4s.is_empty() {
            support.ja4s = Some(ja4s);
        }
        chosen.push(first);
        offered.retain(|c| *c != first);
        if support.cert.is_none() {
            support.cert = cert;
        }
        for class in WEAK_CLASSES {
            if budget == 0 {
                break;
            }
            if chosen.iter().any(|c| in_class(*c, class)) {
                continue;
            }
            let subset: Vec<u16> = offered
                .iter()
                .copied()
                .filter(|c| in_class(*c, class))
                .collect();
            if subset.is_empty() {
                continue;
            }
            budget -= 1;
            if let Some((cipher, cert, _)) = ask(subset).await {
                chosen.push(cipher);
                offered.retain(|c| *c != cipher);
                if support.cert.is_none() {
                    support.cert = cert;
                }
            }
        }
        let mut exhausted = offered.is_empty();
        while budget > 0 && !exhausted {
            budget -= 1;
            match ask(offered.clone()).await {
                Some((cipher, cert, _)) => {
                    chosen.push(cipher);
                    offered.retain(|c| *c != cipher);
                    exhausted = offered.is_empty();
                    if support.cert.is_none() {
                        support.cert = cert;
                    }
                }
                None => exhausted = true,
            }
        }
        if !exhausted {
            support.truncated.push(*version);
        }
        support.accepted.push((*version, chosen));
    }
    support
}

fn version_name(v: u16) -> &'static str {
    VERSIONS.iter().find(|x| x.0 == v).map_or("?", |x| x.1)
}

/// Summary fields for an inventory: versions, suites and a list of findings.
pub fn summarize(support: &Support, negotiated: Option<&str>) -> Fields {
    let mut f = Fields::new();
    let mut versions: Vec<String> = vec![];
    let mut weak: Vec<String> = vec![];
    let mut ciphers = vec![];
    if negotiated == Some("TLS1.3") || !support.tls13.is_empty() {
        versions.push("TLS1.3".into());
    }
    if !support.tls13.is_empty() {
        let names: Vec<&str> = support
            .tls13
            .iter()
            .map(|id| {
                let (n, w) = suite13_name(*id);
                if let Some(w) = w {
                    weak.push(format!("TLS1.3: {n} - {w}"));
                }
                n
            })
            .collect();
        f.insert("tls13_suites".into(), names.join(", "));
        ciphers.push(format!("TLS1.3: {}", names.join(", ")));
    }
    for (v, suites) in &support.accepted {
        let name = version_name(*v);
        versions.push(if *v <= 0x0302 {
            weak.push(format!("{name} enabled (deprecated)"));
            format!("{name} (deprecated)")
        } else {
            name.to_string()
        });
        let names: Vec<String> = suites
            .iter()
            .map(|id| {
                let (n, w) = suite(*id).unwrap_or(("unknown", None));
                if let Some(w) = w {
                    weak.push(format!("{name}: {n} - {w}"));
                }
                n.to_string()
            })
            .collect();
        ciphers.push(format!("{name}: {}", names.join(", ")));
    }
    if !versions.is_empty() {
        f.insert("versions".into(), versions.join(", "));
    }
    if !ciphers.is_empty() {
        f.insert("ciphers".into(), ciphers.join(" | "));
    }
    weak.sort();
    weak.dedup();
    if !weak.is_empty() {
        f.insert("weak".into(), weak.join("; "));
    }
    let mut truncated: Vec<&str> = vec![];
    if support.tls13_truncated {
        truncated.push("TLS1.3");
    }
    truncated.extend(support.truncated.iter().map(|v| version_name(*v)));
    if !truncated.is_empty() {
        f.insert("suites_truncated".into(), "true".into());
        f.insert("suites_truncated_versions".into(), truncated.join(", "));
    }
    if let Some(j) = &support.ja4s {
        f.insert("ja4s".into(), j.clone());
    }
    f
}

/// Full inspection of one TLS port: certificate, negotiated parameters and enumeration.
/// Service detection uses `wrap` + `inspect_after` so it handshakes only once.
#[cfg(test)]
pub async fn inspect(
    ip: IpAddr,
    port: u16,
    limit: Duration,
    rounds: usize,
    gate: &Gate,
) -> Result<Fields, String> {
    gate.wait().await;
    let tcp = timeout(limit, TcpStream::connect((ip, port)))
        .await
        .map_err(|_| "connect timed out".to_string())?
        .map_err(|e| e.to_string())?;
    // Close the rustls session before enumerating: embedded devices often allow only one or
    // two concurrent TLS connections and would refuse the raw hellos while it is open.
    let modern = wrap(tcp, ip, limit).await.map(|(_, fields)| fields);
    inspect_after(ip, port, limit, rounds, gate, modern).await
}

/// Inspection when the caller already did the rustls handshake (`wrap`) and closed that
/// session: only the raw enumeration runs, so the port sees no duplicate handshake.
pub async fn inspect_after(
    ip: IpAddr,
    port: u16,
    limit: Duration,
    rounds: usize,
    gate: &Gate,
    handshake: Result<Fields, String>,
) -> Result<Fields, String> {
    let mut support = enumerate(ip, port, limit, rounds, gate).await;
    // TLS 1.3 only when the rustls handshake negotiated it: 1.2-only and legacy servers get
    // no extra connection. Its full-offer ServerHello gives the JA4S (preferred over 1.2's).
    // Safe Mode skips these extra hellos; the negotiated version is still reported.
    let modern = handshake
        .as_ref()
        .is_ok_and(|f| f.get("negotiated").map(String::as_str) == Some("TLS1.3"));
    if modern && !gate.is_safe() {
        let (suites, truncated, ja4s) = enumerate13(ip, port, limit, rounds, gate).await;
        support.tls13 = suites;
        support.tls13_truncated = truncated;
        if ja4s.is_some() {
            support.ja4s = ja4s;
        }
    }
    let mut fields = match handshake {
        Ok(fields) => fields,
        Err(e) if support.accepted.is_empty() => return Err(e),
        Err(_) => Fields::new(),
    };
    if !fields.contains_key("subject")
        && let Some(cert) = &support.cert
        && let Ok(extra) = describe_cert(cert)
    {
        fields.extend(extra);
    }
    let negotiated = fields.get("negotiated").cloned();
    fields.extend(summarize(&support, negotiated.as_deref()));
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(951_782_400), "2000-02-29");
        assert_eq!(date(1_700_000_000), "2023-11-14");
        assert_eq!(date(-86_400), "1969-12-31");
    }

    #[test]
    fn suite_table_is_unique() {
        let mut ids: Vec<_> = SUITES.iter().map(|s| s.0).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), SUITES.len());
    }

    #[test]
    fn hello_is_well_formed() {
        let ids: Vec<u16> = SUITES.iter().map(|s| s.0).collect();
        let h = client_hello(0x0303, &ids, [9; 32]);
        assert_eq!(h[0], 22);
        assert_eq!(usize::from(u16::from_be_bytes([h[3], h[4]])), h.len() - 5);
        assert_eq!(h[5], 1);
        let hs_len = (usize::from(h[6]) << 16) | (usize::from(h[7]) << 8) | usize::from(h[8]);
        assert_eq!(hs_len, h.len() - 9);
        assert_eq!(&h[9..11], &[3, 3]);
        let ssl = client_hello(0x0300, &ids, [0; 32]);
        assert_eq!(&ssl[1..3], &[3, 0]);
    }

    fn server_flight(version: u16, cipher: u16, with_cert: Option<&[u8]>, split: bool) -> Vec<u8> {
        let mut hello = vec![];
        hello.extend(version.to_be_bytes());
        hello.extend([0u8; 32]);
        hello.push(0);
        hello.extend(cipher.to_be_bytes());
        hello.push(0);
        let mut hs = vec![2];
        hs.extend(&(hello.len() as u32).to_be_bytes()[1..]);
        hs.extend(hello);
        if let Some(cert) = with_cert {
            let mut body: Vec<u8> = vec![];
            body.extend(&((cert.len() + 3) as u32).to_be_bytes()[1..]);
            body.extend(&(cert.len() as u32).to_be_bytes()[1..]);
            body.extend(cert);
            hs.push(11);
            hs.extend(&(body.len() as u32).to_be_bytes()[1..]);
            hs.extend(body);
        }
        hs.extend([14, 0, 0, 0]);
        let mut out = vec![];
        let pieces: Vec<&[u8]> = if split {
            let (a, b) = hs.split_at(hs.len() / 2);
            vec![a, b]
        } else {
            vec![&hs]
        };
        for p in pieces {
            out.extend([22, 3, 3]);
            out.extend((p.len() as u16).to_be_bytes());
            out.extend(p);
        }
        out
    }

    #[test]
    fn flight_parsing() {
        let flight = server_flight(0x0303, 0xC02F, Some(&[1, 2, 3, 4]), false);
        let Reply::Accepted {
            version,
            cipher,
            cert,
            ja4s,
        } = parse_flight(&flight)
        else {
            panic!("not accepted");
        };
        assert_eq!((version, cipher), (0x0303, 0xC02F));
        assert_eq!(cert, Some(vec![1, 2, 3, 4]));
        assert!(ja4s.starts_with("t120000_c02f_"), "{ja4s}");
        assert!(has_done(&flight));
        // The same flight split mid-message across two records still parses.
        let split = server_flight(0x0301, 0x002F, Some(&[9; 300]), true);
        assert!(matches!(
            parse_flight(&split),
            Reply::Accepted { version: 0x0301, cipher: 0x002F, cert: Some(c), .. } if c == vec![9; 300]
        ));
        assert_eq!(parse_flight(&[21, 3, 3, 0, 2, 2, 40]), Reply::Alert(40));
        assert_eq!(parse_flight(&[0x48, 0x54, 0x54, 0x50, 0x2f]), Reply::Other);
        assert_eq!(parse_flight(&[]), Reply::Other);
        assert_eq!(parse_flight(&flight[..12]), Reply::Other);
    }

    #[test]
    fn summary_flags_legacy_and_weak() {
        let support = Support {
            accepted: vec![(0x0303, vec![0xC02F, 0x002F]), (0x0301, vec![0x0005])],
            ..Default::default()
        };
        let f = summarize(&support, Some("TLS1.3"));
        assert!(!f.contains_key("suites_truncated"));
        assert_eq!(f["versions"], "TLS1.3, TLS1.2, TLS1.0 (deprecated)");
        assert!(f["weak"].contains("TLS1.0 enabled (deprecated)"));
        assert!(f["weak"].contains("RC4"));
        assert!(f["weak"].contains("no forward secrecy"));
        assert!(!f["weak"].contains("ECDHE_RSA_AES_128_GCM"));
    }

    /// A rustls server with a throw-away certificate: exercises the real handshake,
    /// certificate parsing and the raw enumerator against a live TLS implementation.
    #[tokio::test]
    async fn live_tls_server_is_inspected() {
        use rustls::{ServerConfig, pki_types::PrivateKeyDer};
        use tokio_rustls::TlsAcceptor;
        let key = test_identity();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(key.0.clone())],
                PrivateKeyDer::try_from(key.1.clone()).unwrap(),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(mut s) = acceptor.accept(tcp).await {
                        let _ = s.write_all(b"hello").await;
                        let _ = s.shutdown().await;
                    }
                });
            }
        });
        let fields = inspect(
            "127.0.0.1".parse().unwrap(),
            port,
            Duration::from_secs(3),
            6,
            &Gate::unlimited(),
        )
        .await
        .unwrap();
        assert_eq!(fields["negotiated"], "TLS1.3");
        assert!(
            fields["versions"].starts_with("TLS1.3, TLS1.2"),
            "{fields:?}"
        );
        assert!(fields["ciphers"].contains("ECDHE_"), "{fields:?}");
        assert!(!fields.contains_key("weak"), "{fields:?}");
        assert_eq!(fields["cn"], "ns-test.local");
        assert_eq!(fields["self_signed"], "true");
        assert!(fields["san"].contains("ns-test.local"), "{fields:?}");
        assert_eq!(fields["key"], "EC 256");
        // rustls (ring) follows the client's order and has no CCM suites.
        assert_eq!(
            fields["tls13_suites"],
            "TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256",
            "{fields:?}"
        );
        assert!(fields["ciphers"].starts_with("TLS1.3: TLS_AES_128_GCM"));
        assert!(
            !fields
                .get("suites_truncated_versions")
                .is_some_and(|v| v.contains("TLS1.3")),
            "{fields:?}"
        );
        // JA4S of the full-offer TLS 1.3 hello: version 13, cipher 1301.
        assert!(fields["ja4s"].starts_with("t130"), "{fields:?}");
        assert!(fields["ja4s"].contains("00_1301_"), "{fields:?}");
    }

    #[test]
    fn certificate_validity_and_self_signed_checks() {
        // Not yet valid: not_before in the future.
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["future.local".to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2999, 1, 1);
        params.not_after = rcgen::date_time_ymd(3000, 1, 1);
        let f = describe_cert(params.self_signed(&key).unwrap().der()).unwrap();
        assert_eq!(f["not_yet_valid"], "true");
        assert_eq!(f["expired"], "false");
        let (der, _) = test_identity();
        let f = describe_cert(&der).unwrap();
        assert_eq!(f["not_yet_valid"], "false");
        assert_eq!(f["self_signed"], "true");

        // Issued by a CA that carries the same name: issuer == subject, but the authority
        // key identifier names the CA key, not the certificate's own.
        let name = |p: &mut rcgen::CertificateParams| {
            p.distinguished_name
                .push(rcgen::DnType::CommonName, "same-name");
        };
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(vec![]).unwrap();
        name(&mut ca_params);
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let ca_f = describe_cert(ca.der()).unwrap();
        assert_eq!(ca_f["self_signed"], "true");
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let mut leaf_params = rcgen::CertificateParams::new(vec!["leaf.local".into()]).unwrap();
        name(&mut leaf_params);
        leaf_params.is_ca = rcgen::IsCa::ExplicitNoCa;
        leaf_params.use_authority_key_identifier_extension = true;
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        let leaf_f = describe_cert(leaf.der()).unwrap();
        assert_eq!(leaf_f["subject"], leaf_f["issuer"]);
        assert_eq!(leaf_f["self_signed"], "false");
    }

    #[test]
    fn unparseable_certificate_keeps_handshake_facts() {
        let f = cert_fields(&[0x30, 0x03, 1, 2, 3]);
        assert!(f["cert_error"].contains("not parseable"), "{f:?}");
        assert!(!f.contains_key("subject"));
        let (der, _) = test_identity();
        assert!(cert_fields(&der).contains_key("subject"));
    }

    /// A raw TLS 1.2-only server that, like real servers, chooses by its own preference:
    /// strong suites first, weak ones last. Records how many hellos it saw.
    async fn preference_server(
        prefs: &'static [u16],
    ) -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hellos = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = hellos.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    break;
                };
                let count = count.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n < 46 {
                        return;
                    }
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let version = u16::from_be_bytes([buf[9], buf[10]]);
                    let sid = usize::from(buf[43]);
                    let at = 44 + sid;
                    let len = usize::from(u16::from_be_bytes([buf[at], buf[at + 1]]));
                    let offered: Vec<u16> = buf[at + 2..at + 2 + len]
                        .chunks(2)
                        .map(|c| u16::from_be_bytes([c[0], c[1]]))
                        .collect();
                    let pick = prefs.iter().find(|p| offered.contains(p));
                    let reply = match pick {
                        Some(&c) if version == 0x0303 => server_flight(0x0303, c, None, false),
                        _ => vec![21, 3, 3, 0, 2, 2, 40],
                    };
                    let _ = s.write_all(&reply).await;
                });
            }
        });
        (port, hellos)
    }

    #[tokio::test]
    async fn weak_classes_are_found_within_the_safe_mode_budget() {
        // Strong first: a plain enumeration with 4 rounds only ever saw these.
        static PREFS: &[u16] = &[
            0xC02F, 0xC030, 0xCCA8, 0xC027, 0xC013, 0xC014, 0x009C, 0x002F, 0x000A, 0x0005,
        ];
        let (port, hellos) = preference_server(PREFS).await;
        let ip = "127.0.0.1".parse().unwrap();
        let support = enumerate(ip, port, Duration::from_secs(3), 4, &Gate::unlimited()).await;
        let tls12 = &support.accepted.iter().find(|a| a.0 == 0x0303).unwrap().1;
        assert_eq!(tls12, &[0xC02F, 0x0005, 0x000A, 0x009C], "{support:?}");
        assert_eq!(support.truncated, [0x0303]);
        // 4 for TLS 1.2 plus one refused hello for each older version.
        assert_eq!(hellos.load(std::sync::atomic::Ordering::SeqCst), 4 + 3);
        let f = summarize(&support, None);
        assert!(f["weak"].contains("RC4") && f["weak"].contains("3DES"));
        assert!(f["weak"].contains("no forward secrecy"));
        assert_eq!(f["suites_truncated"], "true");
        assert_eq!(f["suites_truncated_versions"], "TLS1.2");

        // With enough budget the list completes and is not marked truncated.
        let (port, _) = preference_server(PREFS).await;
        let support = enumerate(ip, port, Duration::from_secs(3), 20, &Gate::unlimited()).await;
        assert_eq!(support.accepted[0].1.len(), PREFS.len());
        assert!(support.truncated.is_empty());
        assert!(!summarize(&support, None).contains_key("suites_truncated"));
    }

    fn test_identity() -> (Vec<u8>, Vec<u8>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["ns-test.local".to_string()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "ns-test.local");
        let cert = params.self_signed(&key).unwrap();
        (cert.der().to_vec(), key.serialize_der())
    }

    #[test]
    fn tls13_hello_is_well_formed() {
        let ids: Vec<u16> = TLS13_SUITES.iter().map(|s| s.0).collect();
        let h = client_hello13(&ids, [1; 32], [2; 32], [3; 32]);
        assert_eq!(h[0], 22);
        assert_eq!(usize::from(u16::from_be_bytes([h[3], h[4]])), h.len() - 5);
        let hs_len = (usize::from(h[6]) << 16) | (usize::from(h[7]) << 8) | usize::from(h[8]);
        assert_eq!(hs_len, h.len() - 9);
        assert_eq!(&h[9..11], &[3, 3]);
        assert_eq!(h[43], 32, "session id length");
        let at = 44 + 32;
        assert_eq!(u16::from_be_bytes([h[at], h[at + 1]]), 10);
        assert_eq!(&h[at + 2..at + 4], &[0x13, 0x01]);
        // supported_versions = TLS 1.3 only, key share x25519 with the given bytes.
        assert!(h.windows(7).any(|w| w == [0, 43, 0, 3, 2, 3, 4]));
        assert!(h.ends_with(&[3; 32]));
        assert!(h.windows(4).any(|w| w == [8, 4, 8, 5]), "RSA-PSS offered");
    }

    fn sh13(cipher: u16, random: [u8; 32]) -> Vec<u8> {
        let mut b = vec![3, 3];
        b.extend(random);
        b.push(0);
        b.extend(cipher.to_be_bytes());
        b.push(0);
        let exts = [0u8, 43, 0, 2, 3, 4, 0, 51, 0, 4, 0, 0x1d, 0, 0];
        b.extend((exts.len() as u16).to_be_bytes());
        b.extend(exts);
        let mut hs = vec![2];
        hs.extend(&(b.len() as u32).to_be_bytes()[1..]);
        hs.extend(b);
        let mut rec = vec![22, 3, 3];
        rec.extend((hs.len() as u16).to_be_bytes());
        rec.extend(hs);
        rec
    }

    #[test]
    fn first_server_hello_stops_before_encrypted_records() {
        let mut flight = sh13(0x1302, [5; 32]);
        flight.extend([20, 3, 3, 0, 1, 1, 23, 3, 3, 0, 4, 9, 9, 9, 9]);
        let First::Hello(h) = first_server_hello(&flight) else {
            panic!("{:?}", first_server_hello(&flight));
        };
        assert_eq!(
            (h.cipher, h.selected_version, h.retry),
            (0x1302, Some(0x0304), false)
        );
        assert_eq!(first_server_hello(&flight[..20]), First::Incomplete);
        assert_eq!(
            first_server_hello(&[21, 3, 3, 0, 2, 2, 40]),
            First::Alert(40)
        );
        assert_eq!(first_server_hello(&[21, 3, 3]), First::Incomplete);
        assert_eq!(first_server_hello(b"HTTP/1.1 400"), First::Other);
        let First::Hello(hrr) = first_server_hello(&sh13(0x1301, crate::fingerprint::HRR_RANDOM))
        else {
            panic!()
        };
        assert!(hrr.retry);
    }

    /// A raw TLS 1.3 server choosing by its own preference among `prefs`, answering a
    /// HelloRetryRequest when `retry` is set. Counts hellos.
    async fn tls13_server(
        prefs: &'static [u16],
        retry: bool,
    ) -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let hellos = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = hellos.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let count = count.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    if n < 80 {
                        return;
                    }
                    count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let at = 44 + usize::from(buf[43]);
                    let len = usize::from(u16::from_be_bytes([buf[at], buf[at + 1]]));
                    let offered: Vec<u16> = buf[at + 2..at + 2 + len]
                        .chunks(2)
                        .map(|c| u16::from_be_bytes([c[0], c[1]]))
                        .collect();
                    let reply = match prefs.iter().find(|p| offered.contains(p)) {
                        Some(&c) if retry => sh13(c, crate::fingerprint::HRR_RANDOM),
                        Some(&c) => sh13(c, [7; 32]),
                        None => vec![21, 3, 3, 0, 2, 2, 40],
                    };
                    let _ = s.write_all(&reply).await;
                    let _ = s.read(&mut buf).await;
                });
            }
        });
        (port, hellos)
    }

    /// Safe Mode skips the extra TLS 1.3 hellos even when 1.3 was negotiated.
    #[tokio::test]
    async fn safe_mode_skips_tls13_enumeration() {
        let ip = "127.0.0.1".parse().unwrap();
        let limit = Duration::from_millis(500);
        let negotiated = || {
            let mut f = Fields::new();
            f.insert("negotiated".into(), "TLS1.3".into());
            Ok(f)
        };
        let (port, _) = tls13_server(&[0x1301, 0x1302], false).await;
        let normal = inspect_after(ip, port, limit, 6, &Gate::unlimited(), negotiated())
            .await
            .unwrap();
        assert!(normal.contains_key("tls13_suites"));
        let (port, _) = tls13_server(&[0x1301, 0x1302], false).await;
        let safe = Gate::unlimited().with_safe(true);
        let quiet = inspect_after(ip, port, limit, 6, &safe, negotiated())
            .await
            .unwrap();
        assert!(!quiet.contains_key("tls13_suites"));
    }

    #[tokio::test]
    async fn tls13_suites_are_enumerated_within_the_budget() {
        let ip = "127.0.0.1".parse().unwrap();
        let limit = Duration::from_secs(2);
        static PREFS: &[u16] = &[0x1302, 0x1303, 0x1301];
        let (port, hellos) = tls13_server(PREFS, false).await;
        let (suites, truncated, ja4s) = enumerate13(ip, port, limit, 6, &Gate::unlimited()).await;
        assert_eq!(suites, PREFS);
        assert!(!truncated);
        assert!(ja4s.unwrap().starts_with("t130200_1302_"));
        assert_eq!(
            hellos.load(std::sync::atomic::Ordering::SeqCst),
            4,
            "3 accepted + 1 refused"
        );
        // Budget of 2: the list is cut and marked truncated.
        let (port, hellos) = tls13_server(PREFS, false).await;
        let (suites, truncated, _) = enumerate13(ip, port, limit, 2, &Gate::unlimited()).await;
        assert_eq!((suites.as_slice(), truncated), (&PREFS[..2], true));
        assert_eq!(hellos.load(std::sync::atomic::Ordering::SeqCst), 2);
        // HelloRetryRequest still names the suite, but gives no JA4S.
        let (port, _) = tls13_server(PREFS, true).await;
        let (suites, _, ja4s) = enumerate13(ip, port, limit, 6, &Gate::unlimited()).await;
        assert_eq!(suites, PREFS);
        assert_eq!(ja4s, None);
        let s = Support {
            tls13: vec![0x1301, 0x1305],
            tls13_truncated: true,
            ..Default::default()
        };
        let f = summarize(&s, Some("TLS1.3"));
        assert_eq!(f["versions"], "TLS1.3");
        assert_eq!(
            f["tls13_suites"],
            "TLS_AES_128_GCM_SHA256, TLS_AES_128_CCM_8_SHA256"
        );
        assert!(f["weak"].contains("truncated 8-byte tag"));
        assert_eq!(f["suites_truncated_versions"], "TLS1.3");
    }
}
