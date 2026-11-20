//! SHA-1 and name-based UUIDs (RFC 4122 version 5), for the deterministic STIX identifiers.
//!
//! SHA-1 is used only to derive identifiers, as STIX 2.1 prescribes for observable objects; it
//! protects nothing here.

/// SHA-1 (FIPS 180-4).
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend(bits.to_be_bytes());
    for block in msg.chunks(64) {
        let mut w = [0u32; 80];
        for (i, word) in block.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (s, v) in h.iter_mut().zip([a, b, c, d, e]) {
            *s = s.wrapping_add(v);
        }
    }
    let mut out = [0u8; 20];
    for (chunk, s) in out.chunks_mut(4).zip(h) {
        chunk.copy_from_slice(&s.to_be_bytes());
    }
    out
}

/// The STIX 2.1 namespace for the identifiers of cyber observable objects.
pub const STIX_SCO_NAMESPACE: &str = "00abedb4-aa42-466c-9c01-fed23315a9b7";
/// The namespace this program uses for the identifiers of the objects it creates itself
/// (infrastructure, vulnerability, observed data, relationships). A fixed random value, so the
/// same scan always exports the same identifiers.
pub const NETWORK_SCOPE_NAMESPACE: &str = "6c0a4f8e-5d0b-4b53-9a43-3f6e8f1c7a21";

fn parse_uuid(text: &str) -> Option<[u8; 16]> {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// UUID version 5 of `name` in `namespace` (a UUID in text form), as 36 lowercase characters.
pub fn uuid5(namespace: &str, name: &str) -> String {
    let ns = parse_uuid(namespace).expect("namespace is a UUID");
    let mut data = ns.to_vec();
    data.extend(name.as_bytes());
    let hash = sha1(&data);
    let mut b = [0u8; 16];
    b.copy_from_slice(&hash[..16]);
    b[6] = (b[6] & 0x0f) | 0x50;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = crate::fingerprint::hex(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        crate::fingerprint::hex(b)
    }

    #[test]
    fn sha1_matches_the_fips_test_vectors() {
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        // longer than one block, and the padding boundary
        assert_ne!(sha1(&[0u8; 55]), sha1(&[0u8; 56]));
        assert_eq!(
            hex(&sha1(&[b'a'; 1000])),
            "291e9a6c66994949b57ba5e650361e98fc36b1ba"
        );
    }

    #[test]
    fn uuid5_matches_the_rfc_4122_dns_example() {
        // Python: uuid.uuid5(uuid.NAMESPACE_DNS, "www.example.com")
        assert_eq!(
            uuid5("6ba7b810-9dad-11d1-80b4-00c04fd430c8", "www.example.com"),
            "2ed6657d-e927-568b-95e1-2665a8aea6a2"
        );
    }

    #[test]
    fn uuids_have_version_5_and_the_rfc_variant() {
        let id = uuid5(NETWORK_SCOPE_NAMESPACE, "host:10.0.0.1");
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "5");
        assert!(["8", "9", "a", "b"].contains(&&id[19..20]), "{id}");
        assert_eq!(id, uuid5(NETWORK_SCOPE_NAMESPACE, "host:10.0.0.1"));
        assert_ne!(id, uuid5(NETWORK_SCOPE_NAMESPACE, "host:10.0.0.2"));
    }
}
