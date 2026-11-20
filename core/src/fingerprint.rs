//! Passive fingerprints computed from what service detection already received: HASSHServer
//! (SSH KEXINIT) and a JA4S-style TLS ServerHello fingerprint, plus the two hash functions
//! they need (MD5 for HASSH, SHA-256 for JA4S). Nothing here touches the network.

/// MD5 (RFC 1321). Only used for HASSH, which is defined over MD5; not for security.
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

/// The parts of a ServerHello that JA4S uses.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerHello {
    /// legacy_version field (0x0303 for TLS 1.2 and 1.3).
    pub legacy_version: u16,
    pub cipher: u16,
    /// Extension types in wire order.
    pub extensions: Vec<u16>,
    /// From the supported_versions extension (TLS 1.3), when present.
    pub selected_version: Option<u16>,
    /// Protocol the server chose via ALPN, when present.
    pub alpn: Option<Vec<u8>>,
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
            // ALPN: list length (2), then one protocol name (length-prefixed).
            16 if data.len() >= 3 => {
                let l = usize::from(data[2]);
                if let Some(name) = data.get(3..3 + l) {
                    hello.alpn = Some(name.to_vec());
                }
            }
            _ => {}
        }
        i += 4 + n;
    }
    Some(hello)
}

/// The ALPN part of a JA4 fingerprint, from the server's chosen protocol as it came on the wire:
/// `00` for none or an empty one; the first and last character when both are ASCII alphanumeric
/// (a single character is both); otherwise the first and last character of the hexadecimal
/// representation of the whole value (`0x20 0x61` gives `21`). This is the rule of FoxIO's
/// technical details for JA4 (JA4.md, "ALPN Extension Value"). The python implementation in the
/// same repository still substitutes `9` for a non-ASCII end character, and says so; the written
/// rule is followed here. The output is always `00`, an alphanumeric pair or two hex digits, so
/// bytes chosen by a server never reach the fingerprint as control characters.
pub fn alpn_part(alpn: Option<&[u8]>) -> String {
    let Some(a) = alpn.filter(|a| !a.is_empty()) else {
        return "00".into();
    };
    let (first, last) = (a[0], a[a.len() - 1]);
    if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
        format!("{}{}", char::from(first), char::from(last))
    } else {
        let text = hex(a);
        format!("{}{}", &text[..1], &text[text.len() - 1..])
    }
}

/// JA4S (FoxIO): `t<version><ext count><alpn>_<cipher>_<sha256(ext list)[..12]>`.
/// version: 13/12/11/10/s3 (from supported_versions when present), ext count two digits,
/// alpn per [`alpn_part`], extension list lower-case 4-digit hex in wire order, comma-separated;
/// with no extensions the hash part is twelve zeros. Checked against the published examples in
/// the tests.
pub fn ja4s(hello: &ServerHello) -> String {
    let version = match hello.selected_version.unwrap_or(hello.legacy_version) {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    };
    let alpn = alpn_part(hello.alpn.as_deref());
    let list = hello
        .extensions
        .iter()
        .map(|e| format!("{e:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    let hash = if hello.extensions.is_empty() {
        "000000000000".to_string()
    } else {
        hex(&sha256(list.as_bytes()))[..12].to_string()
    };
    format!(
        "t{version}{:02}{alpn}_{:04x}_{hash}",
        hello.extensions.len().min(99),
        hello.cipher
    )
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

    #[test]
    fn ja4s_from_server_hello() {
        let body = hello_body(0x0303, 0x1301, &[(51, &[0; 36]), (43, &[3, 4])], [1; 32]);
        let h = parse_server_hello(&body).unwrap();
        assert_eq!(h.extensions, [51, 43]);
        assert_eq!(h.selected_version, Some(0x0304));
        assert!(!h.retry);
        let fp = ja4s(&h);
        let want_hash = hex(&sha256(b"0033,002b"));
        assert_eq!(fp, format!("t130200_1301_{}", &want_hash[..12]));
        // TLS 1.2 with ALPN h2 and renegotiation_info.
        let body = hello_body(
            0x0303,
            0xC030,
            &[(0xff01, &[0]), (16, &[0, 3, 2, b'h', b'2']), (11, &[1, 0])],
            [2; 32],
        );
        let h = parse_server_hello(&body).unwrap();
        assert_eq!(h.alpn.as_deref(), Some(&b"h2"[..]));
        assert!(ja4s(&h).starts_with("t1203h2_c030_"));
        // A hello without extensions, and a HelloRetryRequest.
        let mut bare = hello_body(0x0301, 0x002F, &[], [3; 32]);
        bare.truncate(bare.len() - 2);
        let h = parse_server_hello(&bare).unwrap();
        assert_eq!(ja4s(&h), "t100000_002f_000000000000");
        let hrr = hello_body(0x0303, 0x1302, &[(43, &[3, 4])], HRR_RANDOM);
        assert!(parse_server_hello(&hrr).unwrap().retry);
        assert_eq!(parse_server_hello(&[3, 3, 0]), None);
    }

    /// The JA4S of a ServerHello with the given legacy version, cipher and extensions (in wire
    /// order); `43` is given the data of a TLS 1.3 supported_versions.
    fn ja4s_of(version: u16, cipher: u16, exts: &[u16]) -> String {
        let data: Vec<(u16, &[u8])> = exts
            .iter()
            .map(|e| {
                (
                    *e,
                    if *e == 43 {
                        &[3u8, 4][..]
                    } else {
                        &[0u8; 4][..]
                    },
                )
            })
            .collect();
        ja4s(&parse_server_hello(&hello_body(version, cipher, &data, [9; 32])).unwrap())
    }

    // Test vectors for JA4S. The first three values are the JA4S examples published in the
    // README of the FoxIO JA4+ project (github.com/FoxIO-LLC/ja4, "Examples" table) and the
    // fourth is the JA4S/JA4S_r pair in that project's python test data. The README gives only
    // the fingerprint; the extension list of a ServerHello is not published with it. The lists
    // below are the ones whose SHA-256 gives the published hash (the order matters: 0033,002b
    // and 002b,0033 hash differently), found by trying the extensions such servers send. That
    // the hash is reproduced with a plausible list is strong evidence that the algorithm is
    // the same; it is not a capture of those servers.
    #[test]
    fn ja4s_matches_the_published_foxio_examples() {
        // Sliver malware: TLS 1.3, TLS_AES_128_GCM_SHA256, supported_versions then key_share.
        assert_eq!(
            ja4s_of(0x0303, 0x1301, &[43, 51]),
            "t130200_1301_a56c5b993250"
        );
        // SoftEther VPN: the same extensions with TLS_AES_256_GCM_SHA384.
        assert_eq!(
            ja4s_of(0x0303, 0x1302, &[43, 51]),
            "t130200_1302_a56c5b993250"
        );
        // IcedID malware: TLS 1.2 ECDHE-RSA-AES256-GCM-SHA384 with renegotiation_info,
        // session_ticket and extended_master_secret.
        assert_eq!(
            ja4s_of(0x0303, 0xc030, &[0xff01, 0x0023, 0x0017]),
            "t120300_c030_5e2616a54c73"
        );
        // The reference implementation's test data: JA4S_r "0033,002b" has the hash below.
        assert_eq!(
            ja4s_of(0x0303, 0x1301, &[51, 43]),
            "t130200_1301_234ea6891581"
        );
        let (a, b) = (hex(&sha256(b"002b,0033")), hex(&sha256(b"0033,002b")));
        assert_eq!((&a[..12], &b[..12]), ("a56c5b993250", "234ea6891581"));
    }

    // The ALPN part: the written rule of the FoxIO JA4 technical details (JA4.md, "ALPN Extension
    // Value"), with its examples, and the alphanumeric cases of the python unit test.
    #[test]
    fn ja4s_alpn_part_follows_the_written_rule() {
        let alpn_in_hello = |name: &[u8]| {
            let mut data = ((name.len() + 1) as u16).to_be_bytes().to_vec();
            data.push(name.len() as u8);
            data.extend(name);
            let body = hello_body(0x0303, 0xc02f, &[(16, &data)], [5; 32]);
            ja4s(&parse_server_hello(&body).unwrap())[5..7].to_string()
        };
        for (alpn, want) in [
            (&b"h2"[..], "h2"),
            (b"http/1.1", "h1"),
            (b"x", "xx"),
            (b"7", "77"),
            // The examples of the specification.
            (&[0xAB], "ab"),
            (&[0x20], "20"),
            (&[0xAB, 0xCD], "ad"),
            (&[0x20, 0x61], "21"),
            (&[0x30, 0xAB], "3b"),
            (&[0x61, 0x20], "60"),
            (&[0x30, 0x31, 0xAB, 0xCD], "3d"),
            (&[0x30, 0xAB, 0xCD, 0x31], "01"),
            // Punctuation and control characters never reach the fingerprint.
            (b"-a-", "2d"),
            (b"\x1b[31m", "1d"),
            (b"a_b\n", "6a"),
            ("\u{e9}x".as_bytes(), "c8"),
        ] {
            let got = alpn_in_hello(alpn);
            assert_eq!(got, want, "{alpn:?}");
            assert!(got.bytes().all(|b| b.is_ascii_alphanumeric()), "{got:?}");
        }
        assert_eq!(alpn_part(None), "00");
        assert_eq!(alpn_part(Some(&[])), "00");
        // No ALPN extension: 00.
        let body = hello_body(0x0303, 0xc02f, &[(0xff01, &[0])], [5; 32]);
        assert_eq!(&ja4s(&parse_server_hello(&body).unwrap())[5..7], "00");
    }
}
