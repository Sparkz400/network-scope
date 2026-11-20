//! SNMPv3 User-based Security Model primitives (RFC 3414, RFC 3826, RFC 7860): password to key,
//! key localisation, message authentication (HMAC-MD5-96, HMAC-SHA-1-96 and HMAC-192-SHA-256)
//! and privacy (DES-CBC and AES-128-CFB).
//!
//! MD5 authentication and DES privacy are **weak** (see [`AuthProto::is_weak`] and
//! [`PrivProto::is_weak`]); they are here for older devices that offer nothing else, are
//! never a default and must be named by the user.
use super::{aes, des::Des, md5};
use ring::{digest, hmac};
use std::fmt;

/// Authentication protocols (`usmHMACMD5AuthProtocol`, `usmHMACSHAAuthProtocol`,
/// `usmHMAC192SHA256AuthProtocol`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthProto {
    /// Weak: MD5 is broken as a hash; as a MAC it is not trivially forgeable but offers little
    /// margin.
    Md5,
    Sha1,
    Sha256,
}
/// Privacy protocols (`usmDESPrivProtocol`, `usmAesCfb128Protocol`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivProto {
    /// Weak: a 56-bit key.
    Des,
    Aes128,
}

impl AuthProto {
    pub fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().replace('-', "").as_str() {
            "md5" => Some(Self::Md5),
            "sha" | "sha1" => Some(Self::Sha1),
            "sha256" => Some(Self::Sha256),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
        }
    }
    /// MD5 authentication is offered for old devices only and is reported as weak.
    pub fn is_weak(self) -> bool {
        self == Self::Md5
    }
    fn digest(self) -> &'static digest::Algorithm {
        match self {
            Self::Md5 => unreachable!("MD5 is computed by the md5 module"),
            Self::Sha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => &digest::SHA256,
        }
    }
    fn hmac(self) -> hmac::Algorithm {
        match self {
            Self::Md5 => unreachable!("MD5 is computed by the md5 module"),
            Self::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => hmac::HMAC_SHA256,
        }
    }
    /// Length of `msgAuthenticationParameters`: 12 bytes for HMAC-MD5-96 and HMAC-SHA-1-96, 24
    /// for HMAC-192-SHA-256.
    pub fn mac_len(self) -> usize {
        match self {
            Self::Md5 | Self::Sha1 => 12,
            Self::Sha256 => 24,
        }
    }
}
impl PrivProto {
    pub fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().replace('-', "").as_str() {
            "des" => Some(Self::Des),
            "aes" | "aes128" => Some(Self::Aes128),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Des => "DES",
            Self::Aes128 => "AES-128",
        }
    }
    /// DES privacy is offered for old devices only and is reported as weak.
    pub fn is_weak(self) -> bool {
        self == Self::Des
    }
}

/// A running hash of either kind (MD5 is the hand-written one, the others come from `ring`).
enum Hasher {
    Md5(md5::Md5),
    Ring(digest::Context),
}
impl Hasher {
    fn new(proto: AuthProto) -> Self {
        match proto {
            AuthProto::Md5 => Self::Md5(md5::Md5::new()),
            _ => Self::Ring(digest::Context::new(proto.digest())),
        }
    }
    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Md5(c) => c.update(data),
            Self::Ring(c) => c.update(data),
        }
    }
    fn finish(self) -> Vec<u8> {
        match self {
            Self::Md5(c) => c.finish().to_vec(),
            Self::Ring(c) => c.finish().as_ref().to_vec(),
        }
    }
}

/// RFC 3414 A.2.1/A.2.2: the digest of one mebibyte made of the password repeated (`Ku`).
pub fn password_to_key(proto: AuthProto, password: &[u8]) -> Vec<u8> {
    let mut context = Hasher::new(proto);
    if !password.is_empty() {
        let mut block = [0u8; 64];
        let mut at = 0usize;
        for _ in 0..(1_048_576 / 64) {
            for b in &mut block {
                *b = password[at % password.len()];
                at += 1;
            }
            context.update(&block);
        }
    }
    context.finish()
}

/// `password_to_key`, then the localisation with the authoritative engine ID:
/// `H(Ku || engineID || Ku)`.
pub fn localized_key(proto: AuthProto, password: &[u8], engine_id: &[u8]) -> Vec<u8> {
    let ku = password_to_key(proto, password);
    let mut context = Hasher::new(proto);
    context.update(&ku);
    context.update(engine_id);
    context.update(&ku);
    context.finish()
}

/// The full-length HMAC of a message.
fn full_mac(proto: AuthProto, key: &[u8], message: &[u8]) -> Vec<u8> {
    match proto {
        AuthProto::Md5 => md5::hmac_md5(key, message).to_vec(),
        _ => {
            let key = hmac::Key::new(proto.hmac(), key);
            hmac::sign(&key, message).as_ref().to_vec()
        }
    }
}

/// The HMAC of a whole message (with `msgAuthenticationParameters` zeroed) cut to the protocol's
/// length.
pub fn mac(proto: AuthProto, key: &[u8], message: &[u8]) -> Vec<u8> {
    full_mac(proto, key, message)[..proto.mac_len()].to_vec()
}

/// Constant-time check of a received `msgAuthenticationParameters`.
pub fn verify(proto: AuthProto, key: &[u8], message: &[u8], received: &[u8]) -> bool {
    if received.len() != proto.mac_len() {
        return false;
    }
    let full = full_mac(proto, key, message);
    // The tag is truncated, so `ring::hmac::verify` (full tags) does not apply: fold the
    // differences of the equal-length prefixes without an early exit.
    full[..proto.mac_len()]
        .iter()
        .zip(received)
        .fold(0u8, |d, (a, b)| d | (a ^ b))
        == 0
}

/// A localised privacy key.
#[derive(Clone)]
pub enum Privacy {
    /// `usmAesCfb128Protocol`: the first 16 bytes of the localised key.
    Aes { key: [u8; 16] },
    /// `usmDESPrivProtocol`: the first 8 bytes are the DES key, the next 8 the pre-IV.
    Des { key: [u8; 8], pre_iv: [u8; 8] },
}
impl Privacy {
    /// The key is the first 16 bytes of the localised key (computed with the *authentication*
    /// protocol's hash, RFC 3826 section 1.2 and RFC 3414 section 8.1.1.1).
    pub fn new(auth: AuthProto, proto: PrivProto, password: &[u8], engine_id: &[u8]) -> Self {
        let full = localized_key(auth, password, engine_id);
        let mut key = [0u8; 16];
        key.copy_from_slice(&full[..16]);
        match proto {
            PrivProto::Aes128 => Self::Aes { key },
            PrivProto::Des => {
                let (mut des, mut pre_iv) = ([0u8; 8], [0u8; 8]);
                des.copy_from_slice(&key[..8]);
                pre_iv.copy_from_slice(&key[8..]);
                Self::Des { key: des, pre_iv }
            }
        }
    }
    pub fn proto(&self) -> PrivProto {
        match self {
            Self::Aes { .. } => PrivProto::Aes128,
            Self::Des { .. } => PrivProto::Des,
        }
    }
    /// The 8-byte `msgPrivacyParameters` of a request. AES: a 64-bit counter. DES (RFC 3414
    /// section 8.1.1.1): the 32-bit engine boots counter followed by a 32-bit counter.
    pub fn salt(&self, boots: u32, counter: u64) -> [u8; 8] {
        match self {
            Self::Aes { .. } => counter.to_be_bytes(),
            Self::Des { .. } => {
                let mut salt = [0u8; 8];
                salt[..4].copy_from_slice(&boots.to_be_bytes());
                salt[4..].copy_from_slice(&(counter as u32).to_be_bytes());
                salt
            }
        }
    }
    /// AES: IV = engineBoots || engineTime || salt (RFC 3826 section 3.1.2.1).
    fn aes_iv(boots: u32, time: u32, salt: &[u8; 8]) -> [u8; 16] {
        let mut iv = [0u8; 16];
        iv[..4].copy_from_slice(&boots.to_be_bytes());
        iv[4..8].copy_from_slice(&time.to_be_bytes());
        iv[8..].copy_from_slice(salt);
        iv
    }
    /// DES: IV = pre-IV XOR salt (RFC 3414 section 8.1.1.1).
    fn des_iv(pre_iv: &[u8; 8], salt: &[u8; 8]) -> [u8; 8] {
        let mut iv = *pre_iv;
        for (b, s) in iv.iter_mut().zip(salt) {
            *b ^= s;
        }
        iv
    }
    pub fn encrypt(&self, boots: u32, time: u32, salt: &[u8; 8], plain: &[u8]) -> Vec<u8> {
        match self {
            Self::Aes { key } => aes::cfb128_encrypt(key, &Self::aes_iv(boots, time, salt), plain),
            Self::Des { key, pre_iv } => {
                Des::new(key).cbc_encrypt(&Self::des_iv(pre_iv, salt), plain)
            }
        }
    }
    /// `None` for a salt that is not 8 bytes and, for DES, a ciphertext that is not a whole
    /// number of 8-byte blocks. The result of DES keeps the sender's padding.
    pub fn decrypt(&self, boots: u32, time: u32, salt: &[u8], cipher: &[u8]) -> Option<Vec<u8>> {
        let salt: &[u8; 8] = salt.try_into().ok()?;
        match self {
            Self::Aes { key } => Some(aes::cfb128_decrypt(
                key,
                &Self::aes_iv(boots, time, salt),
                cipher,
            )),
            Self::Des { key, pre_iv } => {
                Des::new(key).cbc_decrypt(&Self::des_iv(pre_iv, salt), cipher)
            }
        }
    }
}
impl fmt::Debug for Privacy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Privacy(<key>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    const ENGINE: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    /// RFC 3414 appendix A.3.1: password "maplesyrup", engine ID 00..02, MD5 (and the
    /// unlocalised key of A.2.1 on the way).
    #[test]
    fn rfc_3414_a_3_1_md5_key_localisation() {
        assert_eq!(
            hex(&password_to_key(AuthProto::Md5, b"maplesyrup")),
            "9faf3283884e92834ebc9847d8edd963"
        );
        assert_eq!(
            hex(&localized_key(AuthProto::Md5, b"maplesyrup", &ENGINE)),
            "526f5eed9fcce26f8964c2930787d82b"
        );
    }

    /// RFC 3414 appendix A.3.2: the same for SHA (and the A.2.2 unlocalised key).
    #[test]
    fn rfc_3414_a_3_2_sha1_key_localisation() {
        assert_eq!(
            hex(&password_to_key(AuthProto::Sha1, b"maplesyrup")),
            "9fb5cc0381497b3793528939ff788d5d79145211"
        );
        assert_eq!(
            hex(&localized_key(AuthProto::Sha1, b"maplesyrup", &ENGINE)),
            "6695febc9288e36282235fc7151f128497b38f3f"
        );
    }

    /// There is no published vector for the SHA-256 variant of this algorithm in RFC 3414 (it
    /// predates it); RFC 7860 uses the same construction with SHA-256. This value was computed
    /// independently with Python's `hashlib` (1 MiB of the password, then H(Ku || id || Ku)).
    #[test]
    fn sha256_key_localisation_matches_an_independent_computation() {
        assert_eq!(
            hex(&localized_key(AuthProto::Sha256, b"maplesyrup", &ENGINE)),
            "8982e0e549e866db361a6b625d84cccc11162d453ee8ce3a6445c2d6776f0f8b"
        );
    }

    /// An empty password has no key (it would loop forever on the modulus): no panic.
    #[test]
    fn an_empty_password_does_not_panic() {
        assert_eq!(localized_key(AuthProto::Sha1, b"", &ENGINE).len(), 20);
        assert_eq!(localized_key(AuthProto::Md5, b"", &ENGINE).len(), 16);
    }

    /// Values from Python: `hmac.new(key, msg, sha1/sha256).hexdigest()` cut to 96 / 192 bits.
    #[test]
    fn hmac_truncation_lengths_and_values() {
        let key = localized_key(AuthProto::Sha1, b"maplesyrup", &ENGINE);
        let msg = b"The quick brown fox jumps over the lazy dog";
        let tag = mac(AuthProto::Sha1, &key, msg);
        assert_eq!(tag.len(), 12);
        assert!(verify(AuthProto::Sha1, &key, msg, &tag));
        let mut bad = tag.clone();
        bad[11] ^= 1;
        assert!(!verify(AuthProto::Sha1, &key, msg, &bad));
        assert!(!verify(AuthProto::Sha1, &key, msg, &tag[..11]));
        assert!(!verify(AuthProto::Sha1, &key, b"other", &tag));
        let key2 = localized_key(AuthProto::Sha256, b"maplesyrup", &ENGINE);
        assert_eq!(mac(AuthProto::Sha256, &key2, msg).len(), 24);
        // RFC 2202 test case 2 (HMAC-SHA-1, key "Jefe"): the leading 96 bits
        assert_eq!(
            hex(&mac(
                AuthProto::Sha1,
                b"Jefe",
                b"what do ya want for nothing?"
            )),
            "effcdf6ae5eb2fa2d27416d5"
        );
        // RFC 4231 test case 2 (HMAC-SHA-256, key "Jefe"): the leading 192 bits
        assert_eq!(
            hex(&mac(
                AuthProto::Sha256,
                b"Jefe",
                b"what do ya want for nothing?"
            )),
            "5bdcc146bf60754e6a042426089575c75a003f089d273983"
        );
        // RFC 2202 test case 2 (HMAC-MD5): the leading 96 bits (HMAC-MD5-96)
        assert_eq!(
            hex(&mac(
                AuthProto::Md5,
                b"Jefe",
                b"what do ya want for nothing?"
            )),
            "750c783e6ab0b503eaa86e31"
        );
        let key3 = localized_key(AuthProto::Md5, b"maplesyrup", &ENGINE);
        let tag = mac(AuthProto::Md5, &key3, msg);
        assert_eq!(tag.len(), 12);
        assert!(verify(AuthProto::Md5, &key3, msg, &tag));
        assert!(!verify(AuthProto::Md5, &key3, b"other", &tag));
        assert!(!verify(AuthProto::Md5, &key3, msg, &tag[..11]));
    }

    #[test]
    fn protocol_names_parse() {
        assert_eq!(AuthProto::parse("SHA"), Some(AuthProto::Sha1));
        assert_eq!(AuthProto::parse("sha-1"), Some(AuthProto::Sha1));
        assert_eq!(AuthProto::parse("SHA-256"), Some(AuthProto::Sha256));
        assert_eq!(AuthProto::parse("MD5"), Some(AuthProto::Md5));
        assert_eq!(AuthProto::parse("sha512"), None);
        assert_eq!(PrivProto::parse("AES"), Some(PrivProto::Aes128));
        assert_eq!(PrivProto::parse("aes-128"), Some(PrivProto::Aes128));
        assert_eq!(PrivProto::parse("des"), Some(PrivProto::Des));
        assert_eq!(PrivProto::parse("3des"), None);
        assert_eq!(PrivProto::parse("aes256"), None);
        // exactly MD5 and DES are weak
        assert!(AuthProto::Md5.is_weak() && PrivProto::Des.is_weak());
        assert!(!AuthProto::Sha1.is_weak() && !AuthProto::Sha256.is_weak());
        assert!(!PrivProto::Aes128.is_weak());
    }

    #[test]
    fn privacy_round_trips_and_binds_the_iv() {
        let p = Privacy::new(AuthProto::Sha1, PrivProto::Aes128, b"privpass", &ENGINE);
        let salt = [1, 2, 3, 4, 5, 6, 7, 8];
        let c = p.encrypt(7, 1234, &salt, b"scoped pdu bytes");
        assert_ne!(c, b"scoped pdu bytes");
        assert_eq!(p.decrypt(7, 1234, &salt, &c).unwrap(), b"scoped pdu bytes");
        assert_ne!(p.decrypt(8, 1234, &salt, &c).unwrap(), b"scoped pdu bytes");
        assert!(p.decrypt(7, 1234, &salt[..7], &c).is_none());
        assert_eq!(format!("{p:?}"), "Privacy(<key>)");
    }

    /// DES privacy: the salt is engineBoots || counter, the IV is pre-IV XOR salt, the key and
    /// pre-IV are the two halves of the localised key (RFC 3414 section 8.1.1.1), with any
    /// authentication protocol.
    #[test]
    fn des_privacy_round_trips_and_follows_the_rfc_construction() {
        for auth in [AuthProto::Md5, AuthProto::Sha1, AuthProto::Sha256] {
            let p = Privacy::new(auth, PrivProto::Des, b"privpass", &ENGINE);
            assert_eq!(p.proto(), PrivProto::Des);
            let salt = p.salt(0x0102_0304, 0x1122_3344_5566_7788);
            assert_eq!(salt, [1, 2, 3, 4, 0x55, 0x66, 0x77, 0x88]);
            let plain = b"scoped pdu bytes, 21 long"; // not a multiple of 8
            let c = p.encrypt(9, 77, &salt, plain);
            assert_eq!(c.len(), 32);
            let back = p.decrypt(9, 77, &salt, &c).unwrap();
            assert_eq!(&back[..plain.len()], plain);
            // boots and time are not part of the DES IV; the salt is
            assert_eq!(&p.decrypt(1, 1, &salt, &c).unwrap()[..plain.len()], plain);
            let other = p.salt(0x0102_0304, 0x1122_3344_5566_7789);
            assert_ne!(&p.decrypt(9, 77, &other, &c).unwrap()[..8], &plain[..8]);
            // not a whole number of blocks, wrong salt length
            assert!(p.decrypt(9, 77, &salt, &c[..31]).is_none());
            assert!(p.decrypt(9, 77, &salt[..7], &c).is_none());
        }
        // the construction itself: key = key[0..8], pre-IV = key[8..16], IV = pre-IV ^ salt
        let full = localized_key(AuthProto::Md5, b"privpass", &ENGINE);
        let salt = [9u8, 8, 7, 6, 5, 4, 3, 2];
        let iv: [u8; 8] = std::array::from_fn(|i| full[8 + i] ^ salt[i]);
        let key: [u8; 8] = full[..8].try_into().unwrap();
        let plain = b"0123456789abcdef";
        assert_eq!(
            Privacy::new(AuthProto::Md5, PrivProto::Des, b"privpass", &ENGINE)
                .encrypt(0, 0, &salt, plain),
            Des::new(&key).cbc_encrypt(&iv, plain)
        );
        // an AES salt is the plain counter
        let a = Privacy::new(AuthProto::Sha1, PrivProto::Aes128, b"privpass", &ENGINE);
        assert_eq!(a.salt(5, 0x0102_0304_0506_0708), [1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
