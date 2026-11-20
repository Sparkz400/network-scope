//! SNMP, read-only, with credentials the user supplies (ROADMAP C20): SNMPv1, v2c and v3 (USM)
//! requests that read the system group, the interface and address tables and the LLDP
//! neighbour table of a device, so a scan can name the device and build a real topology.
//!
//! This is a different thing from the UDP scan's `snmp/161` probe (`udp.rs`), which asks every
//! host for `sysDescr` with the community `public`, and from the `snmp-public` finding that
//! reports an answer to it. Nothing here guesses: the community or the v3 user comes from the
//! command line (`--snmp-community`, `--snmp-v3`, secrets from environment variables), it is
//! never "public" unless the user typed it, and there is no list of communities to try.
//!
//! # Read-only by construction
//!
//! A request is built only from the allow-list [`SnmpPdu`]: GetRequest, GetNextRequest and
//! GetBulkRequest. There is no value for SetRequest, InformRequest or a trap, so none can be
//! constructed, encoded or sent. [`SnmpSocket::send`] accepts only a [`Datagram`], whose only
//! producers are the encoders of this module for those three PDUs, never raw bytes. The walking
//! code in `collect.rs` and `client.rs` holds no socket of its own (a test checks the sources).
//!
//! A SetRequest does not exist:
//!
//! ```compile_fail
//! use network_scope_core::snmp::SnmpPdu;
//! let _ = SnmpPdu::Set;
//! ```
//!
//! ```compile_fail
//! use network_scope_core::snmp::SnmpPdu;
//! let _ = SnmpPdu::SetRequest;
//! let _ = SnmpPdu::Inform;
//! ```
//!
//! The allow-listed requests do:
//!
//! ```
//! use network_scope_core::snmp::{Oid, SnmpPdu, SnmpRequest};
//! let oid = Oid::parse("1.3.6.1.2.1.1.1.0").unwrap();
//! assert_eq!(SnmpRequest::get(std::slice::from_ref(&oid)).pdu(), SnmpPdu::Get);
//! assert_eq!(SnmpRequest::get_next(std::slice::from_ref(&oid)).pdu(), SnmpPdu::GetNext);
//! assert_eq!(SnmpRequest::get_bulk(10, &[oid]).unwrap().pdu(), SnmpPdu::GetBulk);
//! assert_eq!(SnmpPdu::Get.tag(), 0xA0);
//! ```
//!
//! A request has no public fields, so a PDU type cannot be chosen by hand:
//!
//! ```compile_fail
//! use network_scope_core::snmp::{SnmpPdu, SnmpRequest};
//! let _ = SnmpRequest { pdu: SnmpPdu::Get, oids: vec![], non_repeaters: 0, max_repetitions: 0 };
//! ```
//!
//! and the socket takes no raw bytes:
//!
//! ```compile_fail
//! use network_scope_core::snmp::SnmpSocket;
//! async fn raw(socket: &SnmpSocket) {
//!     // 0xA3 is a SetRequest-PDU
//!     let _ = socket.send(&[0x30, 0x05, 0xA3, 0x03, 0x02, 0x01, 0x00]).await;
//! }
//! ```
//!
//! and neither can a datagram be built from parts:
//!
//! ```compile_fail
//! use network_scope_core::snmp::Datagram;
//! let _ = Datagram { bytes: vec![0xA3], label: String::new() };
//! ```
//!
//! # What is sent
//!
//! v1/v2c: one `GetRequest`/`GetNextRequest` (v1) or `GetBulkRequest` (v2c) per reply page, with
//! at most [`MAX_REQUESTS`] datagrams and [`MAX_SECONDS`] seconds per host (fewer in Safe Mode).
//! v3: one unauthenticated discovery `GetRequest` (empty engine ID and user name, no variable
//! bindings) to learn the engine ID, boots and time, then the same requests as above with the
//! user's authentication (HMAC-SHA-1-96 or HMAC-192-SHA-256) and privacy (AES-128-CFB). Every
//! datagram takes a token from the rate gate (`PacketKind::SnmpRequest`).
//!
//! What has not been tested against real devices is stated in `docs/src/snmp.md`.
mod aes;
pub mod ber;
mod client;
mod collect;
#[cfg(test)]
mod testagent;
pub mod usm;
mod wire;

pub use ber::{Oid, Value};
pub use collect::{
    Address, Collected, Interface, LldpNeighbor, MAX_REQUESTS, MAX_SECONDS, SAFE_MAX_REQUESTS,
    SAFE_MAX_SECONDS, System, collect, enabled,
};
pub use usm::{AuthProto, PrivProto};

use crate::sendlog::PacketKind;
use std::{fmt, io, net::SocketAddr};
use tokio::net::UdpSocket;

/// The SNMP request PDUs the scanner may send: GetRequest, GetNextRequest, GetBulkRequest.
/// SetRequest (0xA3), InformRequest (0xA6), the traps and every response type are not here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnmpPdu {
    Get,
    GetNext,
    GetBulk,
}

impl SnmpPdu {
    pub const ALLOWED: [Self; 3] = [Self::Get, Self::GetNext, Self::GetBulk];
    /// The context-specific constructed tag of the PDU on the wire.
    pub const fn tag(self) -> u8 {
        match self {
            Self::Get => 0xA0,
            Self::GetNext => 0xA1,
            Self::GetBulk => 0xA5,
        }
    }
    /// The allow-listed PDU for a tag byte. SetRequest (0xA3), Response (0xA2), InformRequest
    /// (0xA6), the traps (0xA4, 0xA7) and Report (0xA8) are `None`.
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0xA0 => Some(Self::Get),
            0xA1 => Some(Self::GetNext),
            0xA5 => Some(Self::GetBulk),
            _ => None,
        }
    }
    pub const fn name(self) -> &'static str {
        match self {
            Self::Get => "GetRequest",
            Self::GetNext => "GetNextRequest",
            Self::GetBulk => "GetBulkRequest",
        }
    }
    /// The PDU of an encoded SNMP message (v1/v2c, or v3 without privacy): the tag of the PDU
    /// inside, if it is on the allow-list. Used by the tests of this guarantee.
    pub fn of_message(message: &[u8]) -> Option<Self> {
        wire::pdu_tag_of_message(message).and_then(Self::from_tag)
    }
}

/// Most variable bindings (OIDs) in one request.
pub const MAX_OIDS_PER_REQUEST: usize = 8;
/// Largest `max-repetitions` of a GetBulkRequest.
pub const MAX_REPETITIONS: u8 = 25;

/// One request of an allow-listed PDU type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnmpRequest {
    pdu: SnmpPdu,
    oids: Vec<Oid>,
    non_repeaters: u32,
    max_repetitions: u32,
}

impl SnmpRequest {
    /// GetRequest for these objects (at most [`MAX_OIDS_PER_REQUEST`] are kept).
    pub fn get(oids: &[Oid]) -> Self {
        Self::new(SnmpPdu::Get, oids, 0, 0)
    }
    /// GetNextRequest.
    pub fn get_next(oids: &[Oid]) -> Self {
        Self::new(SnmpPdu::GetNext, oids, 0, 0)
    }
    /// GetBulkRequest with no non-repeaters; `max_repetitions` 1 to [`MAX_REPETITIONS`], else
    /// `None`. (SNMPv1 has no GetBulk: the encoder refuses it there.)
    pub fn get_bulk(max_repetitions: u8, oids: &[Oid]) -> Option<Self> {
        (1..=MAX_REPETITIONS)
            .contains(&max_repetitions)
            .then(|| Self::new(SnmpPdu::GetBulk, oids, 0, u32::from(max_repetitions)))
    }
    fn new(pdu: SnmpPdu, oids: &[Oid], non_repeaters: u32, max_repetitions: u32) -> Self {
        Self {
            pdu,
            oids: oids.iter().take(MAX_OIDS_PER_REQUEST).cloned().collect(),
            non_repeaters,
            max_repetitions,
        }
    }
    pub fn pdu(&self) -> SnmpPdu {
        self.pdu
    }
    pub fn oids(&self) -> &[Oid] {
        &self.oids
    }
}

/// SNMP protocol versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    V1,
    V2c,
    V3,
}
impl Version {
    pub const fn wire(self) -> i64 {
        match self {
            Self::V1 => 0,
            Self::V2c => 1,
            Self::V3 => 3,
        }
    }
    pub const fn name(self) -> &'static str {
        match self {
            Self::V1 => "v1",
            Self::V2c => "v2c",
            Self::V3 => "v3",
        }
    }
}

/// An encoded request, ready to send. Only this module's encoders make one.
#[derive(Clone, PartialEq, Eq)]
pub struct Datagram {
    bytes: Vec<u8>,
    label: String,
}
impl Datagram {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// What the plan and the sent log call it: `SNMPv2c: GetBulkRequest (PDU 0xA5)`.
    pub fn label(&self) -> &str {
        &self.label
    }
}
impl fmt::Debug for Datagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Datagram({}, {} bytes)", self.label, self.bytes.len())
    }
}

/// The label of a request in the plan and the sent log.
pub fn label(version: Version, pdu: SnmpPdu) -> String {
    format!(
        "SNMP{}: {} (PDU {:#04X})",
        version.name(),
        pdu.name(),
        pdu.tag()
    )
}

/// Every request the scanner may send with `version`, for the dry run (v1 has no GetBulk).
pub fn catalog(version: Version) -> Vec<String> {
    SnmpPdu::ALLOWED
        .into_iter()
        .filter(|p| !(version == Version::V1 && *p == SnmpPdu::GetBulk))
        .map(|p| label(version, p))
        .collect()
}

/// Decodes `data` as every kind of SNMP reply there is (the entry point of the fuzz target
/// `snmp_response`): v1 and v2c responses, v3 messages without and with authentication and
/// privacy keys, and the raw BER pieces. Must never panic.
#[doc(hidden)]
pub fn decode_reply_for_fuzzing(data: &[u8]) {
    for version in [Version::V1, Version::V2c] {
        let _ = wire::parse_community(data, version);
    }
    // The keys cost a megabyte of hashing each: derive them once.
    static KEYS: std::sync::OnceLock<(Vec<u8>, usm::Privacy)> = std::sync::OnceLock::new();
    let (key, privacy) = KEYS.get_or_init(|| {
        let engine = [0x80, 0, 0x1f, 0x88, 0x80, 1, 2, 3];
        (
            usm::localized_key(AuthProto::Sha1, b"fuzzfuzz", &engine),
            usm::Privacy::new(AuthProto::Sha1, b"fuzzfuzz", &engine),
        )
    });
    let _ = wire::parse_v3(
        data,
        &wire::V3Expect {
            auth: None,
            privacy: None,
        },
    );
    let _ = wire::parse_v3(
        data,
        &wire::V3Expect {
            auth: Some((AuthProto::Sha1, key)),
            privacy: Some(privacy),
        },
    );
    let _ = ber::parse_varbinds(data);
    let _ = Oid::decode(data);
    if let Some((tag, value, _)) = ber::read(data, 0) {
        let _ = Value::decode(tag, value);
    }
    let _ = SnmpPdu::of_message(data);
}

/// The error of a host that does not answer SNMP at all (silence, or an ICMP port unreachable).
/// A scan does not note it on the host: most hosts of a network run no agent, and a wrong
/// community looks the same as no agent.
pub const NO_ANSWER: &str = "no SNMP reply";

/// The packet kind of every datagram this module sends.
pub const KIND: PacketKind = PacketKind::SnmpRequest;

/// A connected UDP socket that can send only [`Datagram`]s.
pub struct SnmpSocket(UdpSocket);

impl SnmpSocket {
    /// Binds an ephemeral port and connects to `target`: datagrams go only to that address.
    pub async fn connect(target: SocketAddr) -> io::Result<Self> {
        let local = if target.ip().is_loopback() {
            if target.is_ipv4() {
                "127.0.0.1:0"
            } else {
                "[::1]:0"
            }
        } else if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(local).await?;
        socket.connect(target).await?;
        Ok(Self(socket))
    }
    pub async fn send(&self, datagram: &Datagram) -> io::Result<usize> {
        self.0.send(&datagram.bytes).await
    }
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.recv(buf).await
    }
}

/// The credentials of an SNMP session. Debug output never shows a secret.
#[derive(Clone, PartialEq, Eq)]
pub enum Credentials {
    /// SNMPv1 or v2c with a community string.
    Community { version: Version, community: String },
    /// SNMPv3 with a user of the user-based security model.
    V3(UsmUser),
}

/// An SNMPv3 user: name, and optionally authentication and privacy with their passwords.
#[derive(Clone, PartialEq, Eq)]
pub struct UsmUser {
    pub name: String,
    pub auth: Option<(AuthProto, String)>,
    /// Privacy needs authentication.
    pub privacy: Option<(PrivProto, String)>,
}

impl fmt::Debug for UsmUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UsmUser({:?}, {}, secrets <hidden>)",
            self.name,
            self.level()
        )
    }
}
impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Community { version, .. } => {
                write!(f, "Community({}, <hidden>)", version.name())
            }
            Self::V3(u) => write!(f, "V3({u:?})"),
        }
    }
}

/// The shortest passphrase USM accepts (RFC 3414 section 11.2).
pub const MIN_PASSPHRASE: usize = 8;

impl UsmUser {
    /// `noAuthNoPriv`, `authNoPriv` or `authPriv`.
    pub fn level(&self) -> &'static str {
        match (&self.auth, &self.privacy) {
            (None, _) => "noAuthNoPriv",
            (Some(_), None) => "authNoPriv",
            (Some(_), Some(_)) => "authPriv",
        }
    }
}

/// The SNMP session settings of a scan (`--snmp-community`, `--snmp-v3`). Opt-in: a scan without
/// this value sends no SNMP request of its own. Not serialised into scan results, so a secret
/// never reaches the database or the JSON output.
#[derive(Clone, PartialEq, Eq)]
pub struct SnmpConfig {
    pub credentials: Credentials,
    /// The agent's UDP port (161).
    pub port: u16,
}

impl fmt::Debug for SnmpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.credentials {
            Credentials::Community { version, .. } => {
                write!(f, "SnmpConfig({}, community <hidden>)", version.name())
            }
            Credentials::V3(u) => write!(
                f,
                "SnmpConfig(v3 {} user {:?}, secrets <hidden>)",
                u.level(),
                u.name
            ),
        }
    }
}

impl SnmpConfig {
    pub const DEFAULT_PORT: u16 = 161;

    /// `--snmp-community COMMUNITY [--snmp-version 1|2c]`.
    pub fn community(version: &str, community: &str) -> Result<Self, String> {
        let version = match version.to_ascii_lowercase().as_str() {
            "1" | "v1" => Version::V1,
            "2c" | "v2c" | "2" => Version::V2c,
            _ => return Err("SNMP version must be 1 or 2c (use --snmp-v3 for SNMPv3)".into()),
        };
        if community.is_empty() || community.len() > 255 {
            return Err("The SNMP community must be 1-255 bytes".into());
        }
        Ok(Self {
            credentials: Credentials::Community {
                version,
                community: community.to_string(),
            },
            port: Self::DEFAULT_PORT,
        })
    }

    /// `--snmp-v3 user[:auth-proto:auth-pass-env[:priv-proto:priv-pass-env]]`. The passphrases
    /// are never on the command line: the spec holds the *names* of environment variables, and
    /// `env` reads them. `auth-proto` is `sha` or `sha256`, `priv-proto` is `aes`.
    pub fn v3(spec: &str, env: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        const FORM: &str =
            "--snmp-v3 takes user[:auth-proto:auth-pass-env[:priv-proto:priv-pass-env]]";
        let parts: Vec<&str> = spec.split(':').collect();
        if ![1, 3, 5].contains(&parts.len()) {
            return Err(FORM.into());
        }
        let name = parts[0];
        if name.is_empty() || name.len() > 32 {
            return Err("The SNMPv3 user name must be 1-32 bytes".into());
        }
        let secret = |what: &str, var: &str| -> Result<String, String> {
            let valid = !var.is_empty()
                && var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !var.starts_with(|c: char| c.is_ascii_digit());
            if !valid {
                // never echo the value: it may be a passphrase typed in the wrong place
                return Err(format!(
                    "{what}: expected the name of an environment variable (the passphrase itself must not be given on the command line)"
                ));
            }
            let value =
                env(var).ok_or_else(|| format!("{what}: environment variable {var} is not set"))?;
            if value.len() < MIN_PASSPHRASE {
                return Err(format!(
                    "{what}: the passphrase in {var} is shorter than {MIN_PASSPHRASE} characters"
                ));
            }
            Ok(value)
        };
        let auth = match parts.get(1) {
            Some(proto) => {
                let proto = AuthProto::parse(proto)
                    .ok_or("SNMPv3 authentication protocol must be sha or sha256")?;
                Some((proto, secret("SNMPv3 authentication", parts[2])?))
            }
            None => None,
        };
        let privacy = match parts.get(3) {
            Some(proto) => {
                let proto = PrivProto::parse(proto).ok_or("SNMPv3 privacy protocol must be aes")?;
                Some((proto, secret("SNMPv3 privacy", parts[4])?))
            }
            None => None,
        };
        Ok(Self {
            credentials: Credentials::V3(UsmUser {
                name: name.to_string(),
                auth,
                privacy,
            }),
            port: Self::DEFAULT_PORT,
        })
    }

    pub fn version(&self) -> Version {
        match &self.credentials {
            Credentials::Community { version, .. } => *version,
            Credentials::V3(_) => Version::V3,
        }
    }
    /// The plan and dry run list these.
    pub fn catalog(&self) -> Vec<String> {
        catalog(self.version())
    }
    /// For the dry run: `SNMPv2c, community` or `SNMPv3 authPriv`; never a secret.
    pub fn credentials_summary(&self) -> String {
        match &self.credentials {
            Credentials::Community { version, .. } => {
                format!("SNMP{}, community string", version.name())
            }
            Credentials::V3(u) => format!("SNMPv3 {}", u.level()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(name: &str) -> Option<String> {
        match name {
            "AUTH_PASS" => Some("authpass-1234".into()),
            "PRIV_PASS" => Some("privpass-5678".into()),
            "SHORT" => Some("abc".into()),
            _ => None,
        }
    }

    #[test]
    fn the_allow_list_is_exactly_get_getnext_getbulk() {
        let accepted: Vec<u8> = (0..=255u8)
            .filter(|t| SnmpPdu::from_tag(*t).is_some())
            .collect();
        assert_eq!(accepted, [0xA0, 0xA1, 0xA5]);
        for pdu in SnmpPdu::ALLOWED {
            assert_eq!(SnmpPdu::from_tag(pdu.tag()), Some(pdu));
        }
        // SetRequest 0xA3, Response 0xA2, trap 0xA4/0xA7, Inform 0xA6, Report 0xA8
        for tag in [0xA2, 0xA3, 0xA4, 0xA6, 0xA7, 0xA8] {
            assert_eq!(SnmpPdu::from_tag(tag), None, "{tag:#x}");
        }
    }

    #[test]
    fn every_encoded_request_decodes_to_the_allow_list() {
        let oid = Oid::parse("1.3.6.1.2.1.1.1.0").unwrap();
        for version in [Version::V1, Version::V2c] {
            for request in [
                SnmpRequest::get(std::slice::from_ref(&oid)),
                SnmpRequest::get_next(std::slice::from_ref(&oid)),
                SnmpRequest::get_bulk(10, std::slice::from_ref(&oid)).unwrap(),
            ] {
                let d = wire::encode_community(version, "c", 7, &request);
                if version == Version::V1 && request.pdu() == SnmpPdu::GetBulk {
                    assert!(d.is_none(), "SNMPv1 has no GetBulk");
                    continue;
                }
                let d = d.unwrap();
                assert_eq!(SnmpPdu::of_message(d.bytes()), Some(request.pdu()));
                assert_eq!(d.label(), label(version, request.pdu()));
            }
        }
    }

    #[test]
    fn changing_the_pdu_tag_of_an_encoded_request_is_rejected() {
        let oid = Oid::parse("1.3.6.1.2.1.1.1.0").unwrap();
        let d =
            wire::encode_community(Version::V2c, "public", 1, &SnmpRequest::get(&[oid])).unwrap();
        let at = d.bytes().iter().position(|b| *b == 0xA0).unwrap();
        for tag in 0..=255u8 {
            let mut m = d.bytes().to_vec();
            m[at] = tag;
            assert_eq!(
                SnmpPdu::of_message(&m).is_some(),
                SnmpPdu::from_tag(tag).is_some(),
                "{tag:#x}"
            );
        }
    }

    #[test]
    fn bulk_repetitions_and_oid_counts_are_bounded() {
        let oid = Oid::parse("1.3.6.1.2.1.1").unwrap();
        assert!(SnmpRequest::get_bulk(0, std::slice::from_ref(&oid)).is_none());
        assert!(SnmpRequest::get_bulk(MAX_REPETITIONS, std::slice::from_ref(&oid)).is_some());
        assert!(SnmpRequest::get_bulk(MAX_REPETITIONS + 1, std::slice::from_ref(&oid)).is_none());
        let many = vec![oid; 50];
        assert_eq!(SnmpRequest::get(&many).oids().len(), MAX_OIDS_PER_REQUEST);
    }

    #[test]
    fn the_catalog_lists_what_may_be_sent() {
        assert_eq!(
            catalog(Version::V2c),
            [
                "SNMPv2c: GetRequest (PDU 0xA0)",
                "SNMPv2c: GetNextRequest (PDU 0xA1)",
                "SNMPv2c: GetBulkRequest (PDU 0xA5)"
            ]
        );
        assert_eq!(catalog(Version::V1).len(), 2);
        assert!(
            catalog(Version::V3)
                .iter()
                .all(|l| l.starts_with("SNMPv3: "))
        );
    }

    #[test]
    fn community_options() {
        let c = SnmpConfig::community("2c", "secret").unwrap();
        assert_eq!(c.version(), Version::V2c);
        assert_eq!(
            SnmpConfig::community("1", "x").unwrap().version(),
            Version::V1
        );
        assert!(SnmpConfig::community("3", "x").is_err());
        assert!(SnmpConfig::community("2c", "").is_err());
        assert!(!format!("{c:?}").contains("secret"));
    }

    #[test]
    fn v3_option_takes_environment_variable_names_not_secrets() {
        let c = SnmpConfig::v3("monitor:sha256:AUTH_PASS:aes:PRIV_PASS", env).unwrap();
        let Credentials::V3(u) = &c.credentials else {
            panic!()
        };
        assert_eq!(u.name, "monitor");
        assert_eq!(u.auth, Some((AuthProto::Sha256, "authpass-1234".into())));
        assert_eq!(u.privacy, Some((PrivProto::Aes128, "privpass-5678".into())));
        assert_eq!(u.level(), "authPriv");
        let shown = format!("{c:?}");
        assert!(
            !shown.contains("authpass") && !shown.contains("privpass"),
            "{shown}"
        );
        assert_eq!(
            SnmpConfig::v3("u:sha:AUTH_PASS", env).unwrap().credentials,
            Credentials::V3(UsmUser {
                name: "u".into(),
                auth: Some((AuthProto::Sha1, "authpass-1234".into())),
                privacy: None
            })
        );
        let Credentials::V3(u) = SnmpConfig::v3("u", env).unwrap().credentials else {
            panic!()
        };
        assert_eq!(u.level(), "noAuthNoPriv");
        // a passphrase typed where a variable name belongs is refused
        let e = SnmpConfig::v3("u:sha:my secret pass", env).unwrap_err();
        assert!(e.contains("name of an environment variable"), "{e}");
        assert!(!e.contains("my secret pass"), "{e}");
        assert!(
            SnmpConfig::v3("u:sha:MISSING", env)
                .unwrap_err()
                .contains("not set")
        );
        assert!(
            SnmpConfig::v3("u:sha:SHORT", env)
                .unwrap_err()
                .contains("shorter than 8")
        );
        assert!(SnmpConfig::v3("u:md5:AUTH_PASS", env).is_err());
        assert!(SnmpConfig::v3("u:sha:AUTH_PASS:des:PRIV_PASS", env).is_err());
        assert!(
            SnmpConfig::v3("u:sha:AUTH_PASS:aes", env).is_err(),
            "four fields"
        );
        assert!(SnmpConfig::v3("", env).is_err());
        assert!(SnmpConfig::v3("u:sha", env).is_err());
    }

    /// The structural half of the guarantee: only `SnmpSocket` touches a socket.
    #[test]
    fn only_the_socket_wrapper_touches_the_network() {
        for (name, source) in [
            ("collect.rs", include_str!("collect.rs")),
            ("client.rs", include_str!("client.rs")),
            ("wire.rs", include_str!("wire.rs")),
            ("ber.rs", include_str!("ber.rs")),
            ("usm.rs", include_str!("usm.rs")),
            ("aes.rs", include_str!("aes.rs")),
        ] {
            let code = source.split("#[cfg(test)]").next().unwrap();
            for forbidden in [
                "UdpSocket",
                "TcpStream",
                "send_to",
                ".send_vectored",
                "socket2",
                "std::net::Udp",
            ] {
                assert!(
                    !code.contains(forbidden),
                    "snmp/{name} must not use {forbidden}"
                );
            }
        }
        // and nothing there names a PDU other than the allow-list
        for (name, source) in [
            ("collect.rs", include_str!("collect.rs")),
            ("client.rs", include_str!("client.rs")),
        ] {
            let code = source.split("#[cfg(test)]").next().unwrap();
            for forbidden in ["0xA3", "0xa3", "SetRequest", "Inform", "Trap"] {
                assert!(
                    !code.contains(forbidden),
                    "snmp/{name} mentions {forbidden}"
                );
            }
        }
    }
}
