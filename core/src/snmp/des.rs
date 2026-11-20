//! DES (FIPS 46-3) in CBC mode for SNMPv3 `usmDESPrivProtocol` (RFC 3414 section 8).
//!
//! DES has a 56-bit key and is broken by exhaustive search; SNMPv3 offered it first and some old
//! devices offer nothing else. It is opt-in and the documentation says so. `ring` has no DES, so
//! the cipher is written out here from the standard's tables: a plain bit-by-bit implementation
//! (a request is a few hundred bytes, speed is irrelevant). It is not constant-time; the key is
//! derived from a passphrase the user typed for their own agents, and nothing here is exposed to
//! a remote party that could time it. Checked against the FIPS 81 CBC example and known-answer
//! vectors (see the tests).

const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];
const FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];
const E: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];
const P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];
const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];
const PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];
const SHIFTS: [u32; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
const SBOX: [[u8; 64]; 8] = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12,
        11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9,
        1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1,
        10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15,
        4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5,
        14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6,
        9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2,
        12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1,
        13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15,
        10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14,
        2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13,
        14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5,
        15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5,
        12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4,
        10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6,
        11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10,
        8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
];

/// Permutes `input` (`width` bits, bit 1 is the most significant) by `table` (1-based positions).
fn permute(input: u64, width: u32, table: &[u8]) -> u64 {
    let mut out = 0u64;
    for &position in table {
        out = (out << 1) | ((input >> (width - u32::from(position))) & 1);
    }
    out
}

/// The key schedule of one 8-byte key (the parity bits are ignored).
pub struct Des {
    subkeys: [u64; 16],
}

impl Des {
    pub fn new(key: &[u8; 8]) -> Self {
        let permuted = permute(u64::from_be_bytes(*key), 64, &PC1);
        let (mut c, mut d) = ((permuted >> 28) & 0x0fff_ffff, permuted & 0x0fff_ffff);
        let rotate = |v: u64, n: u32| ((v << n) | (v >> (28 - n))) & 0x0fff_ffff;
        let mut subkeys = [0u64; 16];
        for (subkey, shift) in subkeys.iter_mut().zip(SHIFTS) {
            c = rotate(c, shift);
            d = rotate(d, shift);
            *subkey = permute((c << 28) | d, 56, &PC2);
        }
        Self { subkeys }
    }

    fn feistel(r: u32, subkey: u64) -> u32 {
        let x = permute(u64::from(r), 32, &E) ^ subkey;
        let mut out = 0u32;
        for (i, sbox) in SBOX.iter().enumerate() {
            let six = ((x >> (42 - 6 * i)) & 0x3f) as usize;
            let row = ((six & 0x20) >> 4) | (six & 1);
            let column = (six >> 1) & 0xf;
            out = (out << 4) | u32::from(sbox[row * 16 + column]);
        }
        permute(u64::from(out), 32, &P) as u32
    }

    fn crypt(&self, block: u64, decrypt: bool) -> u64 {
        let permuted = permute(block, 64, &IP);
        let (mut l, mut r) = ((permuted >> 32) as u32, permuted as u32);
        for round in 0..16 {
            let subkey = if decrypt {
                self.subkeys[15 - round]
            } else {
                self.subkeys[round]
            };
            let next = l ^ Self::feistel(r, subkey);
            l = r;
            r = next;
        }
        // the halves are swapped before the final permutation
        permute((u64::from(r) << 32) | u64::from(l), 64, &FP)
    }

    pub fn encrypt_block(&self, block: [u8; 8]) -> [u8; 8] {
        self.crypt(u64::from_be_bytes(block), false).to_be_bytes()
    }
    pub fn decrypt_block(&self, block: [u8; 8]) -> [u8; 8] {
        self.crypt(u64::from_be_bytes(block), true).to_be_bytes()
    }

    /// CBC encryption. `plain` is padded with zero bytes to a multiple of 8 (RFC 3414 section
    /// 8.1.1.2: the padding content is not significant and the BER length tells the real size).
    pub fn cbc_encrypt(&self, iv: &[u8; 8], plain: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(plain.len().div_ceil(8) * 8);
        let mut chain = *iv;
        for chunk in plain.chunks(8) {
            let mut block = [0u8; 8];
            block[..chunk.len()].copy_from_slice(chunk);
            for (b, c) in block.iter_mut().zip(chain) {
                *b ^= c;
            }
            chain = self.encrypt_block(block);
            out.extend_from_slice(&chain);
        }
        out
    }

    /// CBC decryption; `None` when the length is not a multiple of 8 (RFC 3414 section 8.3.2).
    pub fn cbc_decrypt(&self, iv: &[u8; 8], cipher: &[u8]) -> Option<Vec<u8>> {
        if !cipher.len().is_multiple_of(8) {
            return None;
        }
        let mut out = Vec::with_capacity(cipher.len());
        let mut chain = *iv;
        for &block in cipher.as_chunks::<8>().0 {
            let mut plain = self.decrypt_block(block);
            for (p, c) in plain.iter_mut().zip(chain) {
                *p ^= c;
            }
            chain = block;
            out.extend_from_slice(&plain);
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }
    fn block(text: &str) -> [u8; 8] {
        h(text).try_into().unwrap()
    }

    /// The worked example every DES description uses (key 133457799BBCDFF1).
    #[test]
    fn the_classic_known_answer() {
        let des = Des::new(&block("133457799BBCDFF1"));
        assert_eq!(
            des.encrypt_block(block("0123456789ABCDEF")),
            block("85E813540F0AB405")
        );
        assert_eq!(
            des.decrypt_block(block("85E813540F0AB405")),
            block("0123456789ABCDEF")
        );
    }

    /// NIST SP 800-17 known answers: the all-zero key with the first variable-plaintext inputs,
    /// and the 0x0101... key (parity-adjusted zero key) with a zero block.
    #[test]
    fn nist_known_answers() {
        let key = Des::new(&block("0101010101010101"));
        for (plain, cipher) in [
            ("8000000000000000", "95F8A5E5DD31D900"),
            ("4000000000000000", "DD7F121CA5015619"),
            ("2000000000000000", "2E8653104F3834EA"),
            ("0000000000000000", "8CA64DE9C1B123A7"),
        ] {
            assert_eq!(key.encrypt_block(block(plain)), block(cipher), "{plain}");
            assert_eq!(key.decrypt_block(block(cipher)), block(plain), "{plain}");
        }
        // variable key: the 0x8001... key, zero block
        assert_eq!(
            Des::new(&block("8001010101010101")).encrypt_block(block("0000000000000000")),
            block("95A8D72813DAA94D")
        );
    }

    /// FIPS 81 appendix, CBC example: key 0123456789abcdef, IV 1234567890abcdef, the 24 bytes
    /// "Now is the time for all ".
    #[test]
    fn fips_81_cbc_example() {
        let des = Des::new(&block("0123456789ABCDEF"));
        let iv = block("1234567890ABCDEF");
        let plain = b"Now is the time for all ";
        let cipher = des.cbc_encrypt(&iv, plain);
        assert_eq!(
            cipher,
            h("E5C7CDDE872BF27C43E934008C389C0F683788499A7C05F6")
        );
        assert_eq!(des.cbc_decrypt(&iv, &cipher).unwrap(), plain);
    }

    #[test]
    fn padding_and_length_rules() {
        let des = Des::new(&block("0123456789ABCDEF"));
        let iv = [7u8; 8];
        for len in 0..=40usize {
            let plain: Vec<u8> = (0..len).map(|i| i as u8 ^ 0x5a).collect();
            let cipher = des.cbc_encrypt(&iv, &plain);
            assert_eq!(cipher.len(), len.div_ceil(8) * 8);
            let back = des.cbc_decrypt(&iv, &cipher).unwrap();
            assert_eq!(&back[..len], &plain[..]);
            assert!(back[len..].iter().all(|b| *b == 0), "zero padding");
        }
        // a ciphertext that is not a whole number of blocks is refused, not truncated
        assert!(des.cbc_decrypt(&iv, &[0u8; 7]).is_none());
        assert!(des.cbc_decrypt(&iv, &[0u8; 9]).is_none());
        assert_eq!(des.cbc_decrypt(&iv, &[]).unwrap(), Vec::<u8>::new());
    }

    /// Complementation property: E(~K, ~P) = ~E(K, P) (checks tables independently of vectors).
    #[test]
    fn complementation_property() {
        let (k, p) = (block("133457799BBCDFF1"), block("0123456789ABCDEF"));
        let c = Des::new(&k).encrypt_block(p);
        let (nk, np) = (k.map(|b| !b), p.map(|b| !b));
        assert_eq!(Des::new(&nk).encrypt_block(np), c.map(|b| !b));
    }
}
