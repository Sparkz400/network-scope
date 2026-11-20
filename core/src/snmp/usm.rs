//! SNMPv3 User-based Security Model primitives (RFC 3414, RFC 3826, RFC 7860): password to key,
//! key localisation, message authentication (HMAC-SHA-1-96 and HMAC-192-SHA-256) and privacy
//! (AES-128-CFB). MD5 and DES are not offered.
use super::aes;
use ring::{digest, hmac};
use std::fmt;

/// Authentication protocols (`usmHMACSHAAuthProtocol`, `usmHMAC192SHA256AuthProtocol`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthProto {
    Sha1,
    Sha256,
}
/// Privacy protocols (`usmAesCfb128Protocol`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivProto {
    Aes128,
}

impl AuthProto {
    pub fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().replace('-', "").as_str() {
            "sha" | "sha1" => Some(Self::Sha1),
            "sha256" => Some(Self::Sha256),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
        }
    }
    fn digest(self) -> &'static digest::Algorithm {
        match self {
            Self::Sha1 => &digest::SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => &digest::SHA256,
        }
    }
    fn hmac(self) -> hmac::Algorithm {
        match self {
            Self::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => hmac::HMAC_SHA256,
        }
    }
    /// Length of `msgAuthenticationParameters`: 12 bytes for HMAC-SHA-1-96, 24 for
    /// HMAC-192-SHA-256.
    pub fn mac_len(self) -> usize {
        match self {
            Self::Sha1 => 12,
            Self::Sha256 => 24,
        }
    }
}
impl PrivProto {
    pub fn parse(text: &str) -> Option<Self> {
        match text.to_ascii_lowercase().replace('-', "").as_str() {
            "aes" | "aes128" => Some(Self::Aes128),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        "AES-128"
    }
}

/// RFC 3414 A.2.1/A.2.2: the digest of one mebibyte made of the password repeated, then the
/// localisation with the authoritative engine ID: `H(Ku || engineID || Ku)`.
pub fn localized_key(proto: AuthProto, password: &[u8], engine_id: &[u8]) -> Vec<u8> {
    let mut context = digest::Context::new(proto.digest());
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
    let ku = context.finish();
    let mut context = digest::Context::new(proto.digest());
    context.update(ku.as_ref());
    context.update(engine_id);
    context.update(ku.as_ref());
    context.finish().as_ref().to_vec()
}

/// The HMAC of a whole message (with `msgAuthenticationParameters` zeroed) cut to the protocol's
/// length.
pub fn mac(proto: AuthProto, key: &[u8], message: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(proto.hmac(), key);
    hmac::sign(&key, message).as_ref()[..proto.mac_len()].to_vec()
}

/// Constant-time check of a received `msgAuthenticationParameters`.
pub fn verify(proto: AuthProto, key: &[u8], message: &[u8], received: &[u8]) -> bool {
    if received.len() != proto.mac_len() {
        return false;
    }
    let key = hmac::Key::new(proto.hmac(), key);
    let full = hmac::sign(&key, message);
    // The tag is truncated, so `ring::hmac::verify` (full tags) does not apply: fold the
    // differences of the equal-length prefixes without an early exit.
    full.as_ref()[..proto.mac_len()]
        .iter()
        .zip(received)
        .fold(0u8, |d, (a, b)| d | (a ^ b))
        == 0
}

/// A localised privacy key.
#[derive(Clone)]
pub struct Privacy {
    key: [u8; 16],
}
impl Privacy {
    /// The key is the first 16 bytes of the localised key (computed with the *authentication*
    /// protocol's hash, RFC 3826 section 1.2).
    pub fn new(auth: AuthProto, password: &[u8], engine_id: &[u8]) -> Self {
        let full = localized_key(auth, password, engine_id);
        let mut key = [0u8; 16];
        key.copy_from_slice(&full[..16]);
        Self { key }
    }
    /// IV = engineBoots || engineTime || salt (RFC 3826 section 3.1.2.1).
    fn iv(boots: u32, time: u32, salt: &[u8; 8]) -> [u8; 16] {
        let mut iv = [0u8; 16];
        iv[..4].copy_from_slice(&boots.to_be_bytes());
        iv[4..8].copy_from_slice(&time.to_be_bytes());
        iv[8..].copy_from_slice(salt);
        iv
    }
    pub fn encrypt(&self, boots: u32, time: u32, salt: &[u8; 8], plain: &[u8]) -> Vec<u8> {
        aes::cfb128_encrypt(&self.key, &Self::iv(boots, time, salt), plain)
    }
    pub fn decrypt(&self, boots: u32, time: u32, salt: &[u8], cipher: &[u8]) -> Option<Vec<u8>> {
        let salt: &[u8; 8] = salt.try_into().ok()?;
        Some(aes::cfb128_decrypt(
            &self.key,
            &Self::iv(boots, time, salt),
            cipher,
        ))
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

    /// RFC 3414 appendix A.3.2: password "maplesyrup", engine ID 00..02, SHA.
    #[test]
    fn rfc_3414_a_3_2_sha1_key_localisation() {
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
    }

    #[test]
    fn protocol_names_parse() {
        assert_eq!(AuthProto::parse("SHA"), Some(AuthProto::Sha1));
        assert_eq!(AuthProto::parse("sha-1"), Some(AuthProto::Sha1));
        assert_eq!(AuthProto::parse("SHA-256"), Some(AuthProto::Sha256));
        assert_eq!(AuthProto::parse("md5"), None);
        assert_eq!(PrivProto::parse("AES"), Some(PrivProto::Aes128));
        assert_eq!(PrivProto::parse("aes-128"), Some(PrivProto::Aes128));
        assert_eq!(PrivProto::parse("des"), None);
        assert_eq!(PrivProto::parse("aes256"), None);
    }

    #[test]
    fn privacy_round_trips_and_binds_the_iv() {
        let p = Privacy::new(AuthProto::Sha1, b"privpass", &ENGINE);
        let salt = [1, 2, 3, 4, 5, 6, 7, 8];
        let c = p.encrypt(7, 1234, &salt, b"scoped pdu bytes");
        assert_ne!(c, b"scoped pdu bytes");
        assert_eq!(p.decrypt(7, 1234, &salt, &c).unwrap(), b"scoped pdu bytes");
        assert_ne!(p.decrypt(8, 1234, &salt, &c).unwrap(), b"scoped pdu bytes");
        assert!(p.decrypt(7, 1234, &salt[..7], &c).is_none());
        assert_eq!(format!("{p:?}"), "Privacy(<key>)");
    }
}
