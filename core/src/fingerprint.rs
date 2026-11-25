// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Passive fingerprints computed from what service detection already received: HASSHServer
//! (SSH KEXINIT) and JA3S (TLS ServerHello), plus the two hash functions used here and elsewhere
//! (MD5, which HASSH and JA3S are defined over, and SHA-256). Nothing here touches the network.

/// MD5 (RFC 1321). Only used for HASSH and JA3S, which are defined over MD5; not for security.
pub fn md5(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: Vec<u32> = (0..64)
        .map(|i| ((i as f64 + 1.0).sin().abs() * 4_294_967_296.0) as u32)
        .collect();
    let mut state: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend(bits.to_le_bytes());
    for block in msg.chunks(64) {
        let m: Vec<u32> = block
            .chunks(4)
            .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
            .collect();
        let [mut a, mut b, mut c, mut d] = state;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let rotated = a
                .wrapping_add(f)
                .wrapping_add(k[i])
                .wrapping_add(m[g])
                .rotate_left(S[i]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(rotated);
        }
        for (s, v) in state.iter_mut().zip([a, b, c, d]) {
            *s = s.wrapping_add(v);
        }
    }
    let mut out = [0u8; 16];
    for (chunk, s) in out.chunks_mut(4).zip(state) {
        chunk.copy_from_slice(&s.to_le_bytes());
    }
    out
}

/// SHA-256 (FIPS 180-4).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bits = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend(bits.to_be_bytes());
    for block in msg.chunks(64) {
        let mut w = [0u32; 64];
        for (i, word) in block.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (s, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *s = s.wrapping_add(v);
        }
    }
    let mut out = [0u8; 32];
    for (chunk, s) in out.chunks_mut(4).zip(h) {
        chunk.copy_from_slice(&s.to_be_bytes());
    }
    out
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// HASSHServer (Salesforce HASSH): MD5 over `kex;enc_s2c;mac_s2c;comp_s2c`, each the raw
/// comma-separated name-list exactly as the server's KEXINIT carried it.
/// Returns (hash, the algorithm string it was computed from).
pub fn hassh_server(kex: &str, enc_s2c: &str, mac_s2c: &str, comp_s2c: &str) -> (String, String) {
    let text = format!("{kex};{enc_s2c};{mac_s2c};{comp_s2c}");
    (hex(&md5(text.as_bytes())), text)
}

/// The parts of a ServerHello that JA3S and the TLS inspection use.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerHello {
    /// legacy_version field (0x0303 for TLS 1.2 and 1.3).
    pub legacy_version: u16,
    pub cipher: u16,
    /// Extension types in wire order.
    pub extensions: Vec<u16>,
    /// From the supported_versions extension (TLS 1.3), when present.
    pub selected_version: Option<u16>,
    /// The message is a TLS 1.3 HelloRetryRequest (special random), not a real ServerHello.
    pub retry: bool,
}

/// SHA-256("HelloRetryRequest"), the fixed `random` of a HelloRetryRequest (RFC 8446 4.1.3).
pub const HRR_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// Parses a ServerHello handshake body (after the 4-byte handshake header).
pub fn parse_server_hello(body: &[u8]) -> Option<ServerHello> {
    let legacy_version = u16::from_be_bytes([*body.first()?, *body.get(1)?]);
    let random = body.get(2..34)?;
    let sid = usize::from(*body.get(34)?);
    let at = 35 + sid;
    let cipher = u16::from_be_bytes([*body.get(at)?, *body.get(at + 1)?]);
    let mut hello = ServerHello {
        legacy_version,
        cipher,
        retry: random == HRR_RANDOM,
        ..Default::default()
    };
    // compression method at at+2, then optional extensions.
    let Some(len) = body.get(at + 3..at + 5) else {
        return Some(hello);
    };
    let total = usize::from(u16::from_be_bytes([len[0], len[1]]));
    let exts = body.get(at + 5..(at + 5 + total).min(body.len()))?;
    let mut i = 0;
    while let Some(head) = exts.get(i..i + 4) {
        let kind = u16::from_be_bytes([head[0], head[1]]);
        let n = usize::from(u16::from_be_bytes([head[2], head[3]]));
        let data = exts.get(i + 4..i + 4 + n).unwrap_or(&[]);
        hello.extensions.push(kind);
        match kind {
            43 if data.len() >= 2 => {
                hello.selected_version = Some(u16::from_be_bytes([data[0], data[1]]));
            }
            _ => {}
        }
        i += 4 + n;
    }
    Some(hello)
}

/// The JA3S string of a ServerHello (Salesforce JA3S, github.com/salesforce/ja3):
/// `SSLVersion,Cipher,Extensions`, all decimal. The version is the `legacy_version` field of the
/// message (771 for TLS 1.2 and for 1.3), the cipher the chosen suite, the extensions the
/// extension types in the order the server sent them, joined with `-`. A hello without
/// extensions leaves the last field empty (`771,47,`). The reference implementation
/// (`python/ja3s.py`) does not treat GREASE values specially for the server side, and neither
/// does this function.
pub fn ja3s_string(hello: &ServerHello) -> String {
    let extensions = hello
        .extensions
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join("-");
    format!("{},{},{extensions}", hello.legacy_version, hello.cipher)
}

/// The JA3S fingerprint: the MD5 of a JA3S string (see [`ja3s_string`]) as 32 hex digits.
pub fn ja3s_hash(ja3s: &str) -> String {
    hex(&md5(ja3s.as_bytes()))
}

/// JA3S of a ServerHello: `(hash, the string it was computed from)`.
pub fn ja3s(hello: &ServerHello) -> (String, String) {
    let text = ja3s_string(hello);
    (ja3s_hash(&text), text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_vectors() {
        // RFC 1321 appendix A.5.
        assert_eq!(hex(&md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hex(&md5(b"abc")), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hex(&md5(b"message digest")),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
        assert_eq!(
            hex(&md5(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            )),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    #[test]
    fn sha256_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(sha256(b"HelloRetryRequest"), HRR_RANDOM);
    }

    #[test]
    fn hassh_server_string_and_hash() {
        let (hash, text) = hassh_server(
            "curve25519-sha256,diffie-hellman-group14-sha256",
            "aes128-ctr",
            "hmac-sha2-256",
            "none,zlib@openssh.com",
        );
        assert_eq!(
            text,
            "curve25519-sha256,diffie-hellman-group14-sha256;aes128-ctr;hmac-sha2-256;none,zlib@openssh.com"
        );
        assert_eq!(hash, hex(&md5(text.as_bytes())));
        assert_eq!(hash.len(), 32);
    }

    fn hello_body(version: u16, cipher: u16, exts: &[(u16, &[u8])], random: [u8; 32]) -> Vec<u8> {
        let mut b = version.to_be_bytes().to_vec();
        b.extend(random);
        b.push(32);
        b.extend([7u8; 32]);
        b.extend(cipher.to_be_bytes());
        b.push(0);
        let mut e = vec![];
        for (kind, data) in exts {
            e.extend(kind.to_be_bytes());
            e.extend((data.len() as u16).to_be_bytes());
            e.extend(*data);
        }
        b.extend((e.len() as u16).to_be_bytes());
        b.extend(e);
        b
    }

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The vectors of `ja3s_vectors.rs`: ServerHellos of real and hand-built shapes with the JA3S
    /// string and hash that the reference implementation (salesforce/ja3 `python/ja3s.py`)
    /// printed for the same bytes.
    #[test]
    fn ja3s_equals_the_reference_implementation() {
        assert!(ja3s_vectors::VECTORS.len() >= 20);
        for (what, body, string, hash) in ja3s_vectors::VECTORS {
            let hello = parse_server_hello(&unhex(body)).expect(what);
            assert_eq!(ja3s_string(&hello), *string, "{what}");
            assert_eq!(ja3s_hash(string), *hash, "{what}");
            assert_eq!(
                ja3s(&hello),
                (hash.to_string(), string.to_string()),
                "{what}"
            );
        }
        // Real servers of both protocol generations and the extension-less shapes are in it.
        let strings: Vec<&str> = ja3s_vectors::VECTORS.iter().map(|v| v.2).collect();
        for want in [
            "771,4866,43-51",
            "771,49200,65281-11",
            "769,47,",
            "771,156,",
        ] {
            assert!(strings.contains(&want), "{want}");
        }
    }

    #[test]
    fn ja3s_string_is_version_cipher_and_extensions_in_wire_order() {
        let body = hello_body(0x0303, 0x1301, &[(51, &[0; 36]), (43, &[3, 4])], [1; 32]);
        let h = parse_server_hello(&body).unwrap();
        assert_eq!(h.extensions, [51, 43]);
        assert_eq!(h.selected_version, Some(0x0304));
        assert!(!h.retry);
        // legacy_version 0x0303 = 771 (also for TLS 1.3), 0x1301 = 4865, then 51 and 43 as sent.
        assert_eq!(ja3s_string(&h), "771,4865,51-43");
        let other = hello_body(0x0303, 0x1301, &[(43, &[3, 4]), (51, &[0; 36])], [1; 32]);
        assert_eq!(
            ja3s_string(&parse_server_hello(&other).unwrap()),
            "771,4865,43-51",
            "the order of the extensions matters"
        );
        // No extensions at all (the block is missing) and an empty block: the last field is empty.
        let with_empty_block = hello_body(0x0301, 0x002F, &[], [3; 32]);
        let mut bare = with_empty_block.clone();
        bare.truncate(bare.len() - 2);
        assert_eq!(ja3s_string(&parse_server_hello(&bare).unwrap()), "769,47,");
        assert_eq!(
            ja3s_string(&parse_server_hello(&with_empty_block).unwrap()),
            "769,47,"
        );
        // GREASE values are not filtered on the server side, as in the reference implementation.
        let grease = hello_body(0x0303, 0x1301, &[(0x0a0a, &[]), (43, &[3, 4])], [4; 32]);
        assert_eq!(
            ja3s_string(&parse_server_hello(&grease).unwrap()),
            "771,4865,2570-43"
        );
    }

    #[test]
    fn ja3s_hash_is_the_md5_of_the_string_in_lower_case_hex() {
        // The Trickbot server of the reference README: TLS 1.0, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.
        assert_eq!(
            ja3s_hash("769,49172,65281-11"),
            "623de93db17d313345d7ea481e7443cf"
        );
        assert_eq!(ja3s_hash(""), "d41d8cd98f00b204e9800998ecf8427e");
        let h = ja3s_hash("771,4865,43-51");
        assert_eq!(h.len(), 32);
        assert!(h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    }

    #[test]
    fn a_hello_retry_request_is_marked_and_malformed_input_gives_nothing() {
        let hrr = hello_body(0x0303, 0x1302, &[(43, &[3, 4])], HRR_RANDOM);
        assert!(parse_server_hello(&hrr).unwrap().retry);
        assert_eq!(parse_server_hello(&[3, 3, 0]), None);
        assert_eq!(parse_server_hello(&[]), None);
        // An extension block that claims more bytes than the message has: only the extensions
        // that are complete count.
        let mut cut = hello_body(0x0303, 0x1301, &[(43, &[3, 4])], [1; 32]);
        cut.truncate(cut.len() - 3);
        assert_eq!(ja3s_string(&parse_server_hello(&cut).unwrap()), "771,4865,");
    }
}

#[cfg(test)]
mod ja3s_vectors;
