//! Fingerprints that can be pivoted on across scans and sites (ROADMAP L70): the Shodan-compatible
//! favicon hash (with the MurmurHash3 it needs) and the JA4X certificate fingerprint.
//!
//! The other pivots already exist next to them: the SHA-256 of the certificate's public key
//! (`tls.<port>.spki_sha256`, see [`crate::tls`]), JA4S and JARM for the TLS stack, HASSH for the
//! SSH stack. [`crate::research::groups`] clusters devices that share one of them.
//!
//! Nothing here sends traffic. In particular the scanner does **not** fetch favicons:
//! [`favicon_hash`] works on a file the user gives (`fingerprints favicon FILE`).
//!
//! # JA4H
//!
//! JA4H (FoxIO) fingerprints the headers of an HTTP *request*, which only a client sends; the
//! scanner is the client and a device's response has no JA4H. No server-side variant is defined,
//! so none is implemented here.
//!
//! # Licensing
//!
//! JA4X belongs to the JA4+ family, whose methods other than JA4 are under the FoxIO License 1.1
//! (see `data/README.md`). Network Scope computes JA4X from the published description and does
//! not use FoxIO code.

/// MurmurHash3, x86 32-bit variant (Austin Appleby, public domain), as used by Shodan.
pub fn murmur3_32(data: &[u8], seed: u32) -> u32 {
    const C1: u32 = 0xcc9e2d51;
    const C2: u32 = 0x1b873593;
    let mut h = seed;
    let (blocks, tail) = data.as_chunks::<4>();
    for block in blocks {
        let mut k = u32::from_le_bytes(*block);
        k = k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h ^= k;
        h = h.rotate_left(13).wrapping_mul(5).wrapping_add(0xe6546b64);
    }
    if !tail.is_empty() {
        let mut k = 0u32;
        for (i, b) in tail.iter().enumerate() {
            k |= u32::from(*b) << (8 * i);
        }
        k = k.wrapping_mul(C1).rotate_left(15).wrapping_mul(C2);
        h ^= k;
    }
    h ^= data.len() as u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85ebca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2ae35);
    h ^= h >> 16;
    h
}

/// Standard base64 with a line break after every 76 characters and one at the end, as Python's
/// `base64.encodebytes` (and so Shodan's favicon hash) writes it. Empty input gives an empty text.
pub fn base64_wrapped(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len() * 4 / 3 + data.len() / 57 + 4);
    let mut line = 0;
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[(n >> (18 - 6 * i) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
        line += 4;
        if line == 76 {
            out.push('\n');
            line = 0;
        }
    }
    if line > 0 {
        out.push('\n');
    }
    out
}

/// The hash Shodan indexes as `http.favicon.hash`: MurmurHash3 (seed 0) of the base64 text of the
/// favicon with line breaks, as a signed 32-bit number.
pub fn favicon_hash(data: &[u8]) -> i32 {
    murmur3_32(base64_wrapped(data).as_bytes(), 0) as i32
}

/// Twelve zeros: the value of a JA4X part with nothing to hash.
const EMPTY_PART: &str = "000000000000";

fn part(oids: &[Vec<u8>]) -> String {
    if oids.is_empty() {
        return EMPTY_PART.into();
    }
    let text = oids
        .iter()
        .map(|o| crate::fingerprint::hex(o))
        .collect::<Vec<_>>()
        .join(",");
    crate::fingerprint::hex(&crate::fingerprint::sha256(text.as_bytes()))[..12].to_string()
}

/// JA4X from the object identifiers of the issuer's name attributes, the subject's name attributes
/// and the extensions, each as the DER content bytes of the OID, in the order they appear in the
/// certificate: `<issuer>_<subject>_<extensions>`, each the first 12 hex digits of the SHA-256 of
/// the comma-separated lower-case hex of the OIDs (twelve zeros for an empty list).
///
/// Self-derived: this follows the JA4X description in the JA4+ documentation as understood when it
/// was written, and has not been compared with FoxIO's reference implementation or its test
/// vectors. It is useful as a pivot (equal certificates structures give equal values) whether or
/// not it matches other tools.
pub fn ja4x_from_oids(issuer: &[Vec<u8>], subject: &[Vec<u8>], extensions: &[Vec<u8>]) -> String {
    format!("{}_{}_{}", part(issuer), part(subject), part(extensions))
}

/// JA4X of a parsed certificate (see [`ja4x_from_oids`]).
pub fn ja4x(cert: &x509_parser::certificate::X509Certificate<'_>) -> String {
    // A certificate has a few dozen attributes and extensions at most; bound them anyway.
    let attributes = |name: &x509_parser::x509::X509Name<'_>| -> Vec<Vec<u8>> {
        name.iter_attributes()
            .take(64)
            .map(|a| a.attr_type().as_bytes().to_vec())
            .collect()
    };
    let extensions: Vec<Vec<u8>> = cert
        .extensions()
        .iter()
        .take(64)
        .map(|e| e.oid.as_bytes().to_vec())
        .collect();
    ja4x_from_oids(
        &attributes(cert.issuer()),
        &attributes(cert.subject()),
        &extensions,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors of MurmurHash3_x86_32 as published with the reference implementation (SMHasher),
    // Wikipedia and common test suites, and confirmed with an independent Python implementation.
    #[test]
    fn murmur3_matches_the_published_vectors() {
        for (data, seed, want) in [
            (&b""[..], 0u32, 0x0000_0000u32),
            (b"", 1, 0x514e_28b7),
            (b"", 0xffff_ffff, 0x81f1_6f39),
            (b"test", 0, 0xba6b_d213),
            (b"Hello, world!", 0, 0xc036_3e43),
            (
                b"The quick brown fox jumps over the lazy dog",
                0,
                0x2e4f_f723,
            ),
            (b"aaaa", 0x9747_b28c, 0x5a97_808a),
            (b"aaa", 0x9747_b28c, 0x283e_0130),
            (b"aa", 0x9747_b28c, 0x5d21_1726),
            (b"a", 0x9747_b28c, 0x7fa0_9ea6),
            (b"abcd", 0x9747_b28c, 0xf047_8627),
            (b"abc", 0, 0xb3dd_93fa),
            (b"foo", 0, 0xf6a5_c420),
            (&[0xff, 0xff, 0xff, 0xff], 0, 0x7629_3b50),
            (&[0x21, 0x43, 0x65, 0x87], 0, 0xf55b_516b),
        ] {
            assert_eq!(murmur3_32(data, seed), want, "{data:?} seed {seed:#x}");
        }
    }

    #[test]
    fn base64_breaks_lines_at_76_characters_like_python() {
        assert_eq!(base64_wrapped(b""), "");
        assert_eq!(base64_wrapped(b"a"), "YQ==\n");
        assert_eq!(base64_wrapped(b"ab"), "YWI=\n");
        assert_eq!(base64_wrapped(b"abc"), "YWJj\n");
        let all: Vec<u8> = (0..=255).collect();
        let text = base64_wrapped(&all);
        let lengths: Vec<usize> = text.split('\n').map(str::len).collect();
        // Python: [76, 76, 76, 76, 40, 0] for bytes(range(256))
        assert_eq!(lengths, [76, 76, 76, 76, 40, 0]);
        assert!(text.starts_with("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd"));
        // exactly one full line of input (57 bytes) ends with a break and no empty line
        assert_eq!(base64_wrapped(&[0u8; 57]).matches('\n').count(), 1);
    }

    /// The hash Shodan computes: `mmh3.hash(codecs.encode(data, "base64"))`. The values come from
    /// an independent Python implementation of the same two steps (MurmurHash3 and base64 with
    /// line breaks); no real favicon and its published Shodan value are included.
    #[test]
    fn the_favicon_hash_is_the_signed_murmur_hash_of_the_wrapped_base64() {
        assert_eq!(favicon_hash(b""), 0);
        assert_eq!(favicon_hash(b"a"), -316_242_180);
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(favicon_hash(&all), -757_223_386);
        let three: Vec<u8> = all.iter().cycle().take(768).copied().collect();
        assert_eq!(favicon_hash(&three), 1_836_528_006);
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend([0u8; 100]);
        assert_eq!(favicon_hash(&png), -120_113_347);
    }

    #[test]
    fn ja4x_parts_are_twelve_hex_digits_of_a_sha256() {
        let cn = vec![0x55, 0x04, 0x03];
        let org = vec![0x55, 0x04, 0x0a];
        let id = ja4x_from_oids(std::slice::from_ref(&cn), &[cn.clone(), org], &[]);
        let parts: Vec<&str> = id.split('_').collect();
        assert_eq!(parts.len(), 3);
        // sha256("550403")[..12] and sha256("550403,55040a")[..12], computed independently
        assert_eq!(parts[0], "7022c563de38");
        assert_eq!(parts[1], "711618dec96d");
        assert_eq!(parts[2], "000000000000", "no extensions");
        // order matters, and so does every OID
        let swapped = ja4x_from_oids(
            std::slice::from_ref(&cn),
            &[vec![0x55, 0x04, 0x0a], cn.clone()],
            &[],
        );
        assert_ne!(id, swapped);
    }
}
