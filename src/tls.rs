//! TLS inspection. A rustls handshake that validates nothing collects the certificate and the
//! negotiated TLS 1.2/1.3 parameters; a hand-built ClientHello then asks which protocol
//! versions (SSLv3 to TLS 1.2) and cipher suites the server accepts, including legacy and
//! weak ones that rustls refuses to speak. Certificates are inventory data, never trusted.
use crate::core::Gate;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, SignatureScheme,
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
use tokio_rustls::{client::TlsStream, TlsConnector};
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
        fields.extend(describe_cert(cert.as_ref())?);
    }
    Ok((stream, fields))
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
    f.insert(
        "self_signed".into(),
        (cert.subject() == cert.issuer()).to_string(),
    );
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
    let (mut version, mut cipher, mut cert) = (None, None, None);
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

fn has_done(data: &[u8]) -> bool {
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

#[derive(Debug, Default)]
pub struct Support {
    /// For each protocol version the server accepts: the suites it chose, in selection order.
    pub accepted: Vec<(u16, Vec<u16>)>,
    pub cert: Option<Vec<u8>>,
}

/// Which versions and suites does the server accept? One hello per round; each round removes
/// the suite the server picked. `rounds` bounds the connections made per version.
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
        let limit_rounds = if *version == 0x0303 {
            rounds
        } else {
            rounds.min(4)
        };
        for _ in 0..limit_rounds {
            gate.wait().await;
            match hello(ip, port, *version, &offered, limit).await {
                Ok(Reply::Accepted {
                    version: v,
                    cipher,
                    cert,
                }) if v == *version && offered.contains(&cipher) => {
                    chosen.push(cipher);
                    offered.retain(|c| *c != cipher);
                    if support.cert.is_none() {
                        support.cert = cert;
                    }
                }
                _ => break,
            }
        }
        if !chosen.is_empty() {
            support.accepted.push((*version, chosen));
        }
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
    if negotiated == Some("TLS1.3") {
        versions.push("TLS1.3".into());
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
    f
}

/// Full inspection of one TLS port: certificate, negotiated parameters and enumeration.
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
    let modern = wrap(tcp, ip, limit).await;
    let support = enumerate(ip, port, limit, rounds, gate).await;
    let mut fields = match modern {
        Ok((_, fields)) => fields,
        Err(e) if support.accepted.is_empty() => return Err(e),
        Err(_) => Fields::new(),
    };
    if !fields.contains_key("subject") {
        if let Some(cert) = &support.cert {
            if let Ok(extra) = describe_cert(cert) {
                fields.extend(extra);
            }
        }
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
        assert_eq!(
            parse_flight(&flight),
            Reply::Accepted {
                version: 0x0303,
                cipher: 0xC02F,
                cert: Some(vec![1, 2, 3, 4])
            }
        );
        assert!(has_done(&flight));
        // The same flight split mid-message across two records still parses.
        let split = server_flight(0x0301, 0x002F, Some(&[9; 300]), true);
        assert_eq!(
            parse_flight(&split),
            Reply::Accepted {
                version: 0x0301,
                cipher: 0x002F,
                cert: Some(vec![9; 300])
            }
        );
        assert_eq!(parse_flight(&[21, 3, 3, 0, 2, 2, 40]), Reply::Alert(40));
        assert_eq!(parse_flight(&[0x48, 0x54, 0x54, 0x50, 0x2f]), Reply::Other);
        assert_eq!(parse_flight(&[]), Reply::Other);
        assert_eq!(parse_flight(&flight[..12]), Reply::Other);
    }

    #[test]
    fn summary_flags_legacy_and_weak() {
        let support = Support {
            accepted: vec![(0x0303, vec![0xC02F, 0x002F]), (0x0301, vec![0x0005])],
            cert: None,
        };
        let f = summarize(&support, Some("TLS1.3"));
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
        use rustls::{pki_types::PrivateKeyDer, ServerConfig};
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
}
