//! AES-128 (encryption direction only) and CFB128 mode for SNMPv3 `usmAesCfb128Protocol`
//! (RFC 3826).
//!
//! `ring` exposes AES only inside its AEAD constructions, so the block cipher is written out
//! here: it is the textbook FIPS-197 construction with the S-box computed at compile time from
//! its definition (multiplicative inverse in GF(2^8) plus the affine map). CFB needs only the
//! forward direction for both encryption and decryption. It is table-driven, so it is not
//! constant-time; the key is derived from a password the user typed for their own agents, and
//! nothing here is exposed to a remote party that could time it.

const fn xtime(a: u8) -> u8 {
    (a << 1) ^ if a & 0x80 != 0 { 0x1b } else { 0 }
}
const fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    p
}
const fn sbox() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut x = 0usize;
    while x < 256 {
        // x^254 is the inverse of x in GF(2^8) (and 0 for 0)
        let mut inv = 1u8;
        let mut e = 0;
        while e < 254 {
            inv = gmul(inv, x as u8);
            e += 1;
        }
        if x == 0 {
            inv = 0;
        }
        let mut s = inv;
        let mut r = 1;
        while r <= 4 {
            s ^= inv.rotate_left(r);
            r += 1;
        }
        table[x] = s ^ 0x63;
        x += 1;
    }
    table
}
const SBOX: [u8; 256] = sbox();

pub struct Aes128 {
    round_keys: [[u8; 16]; 11],
}

impl Aes128 {
    pub fn new(key: &[u8; 16]) -> Self {
        let mut w = [[0u8; 4]; 44];
        for (i, word) in w.iter_mut().enumerate().take(4) {
            word.copy_from_slice(&key[i * 4..i * 4 + 4]);
        }
        let mut rcon = 1u8;
        for i in 4..44 {
            let mut t = w[i - 1];
            if i % 4 == 0 {
                t = [
                    SBOX[usize::from(t[1])] ^ rcon,
                    SBOX[usize::from(t[2])],
                    SBOX[usize::from(t[3])],
                    SBOX[usize::from(t[0])],
                ];
                rcon = xtime(rcon);
            }
            for k in 0..4 {
                w[i][k] = w[i - 4][k] ^ t[k];
            }
        }
        let mut round_keys = [[0u8; 16]; 11];
        for (r, rk) in round_keys.iter_mut().enumerate() {
            for c in 0..4 {
                rk[c * 4..c * 4 + 4].copy_from_slice(&w[r * 4 + c]);
            }
        }
        Self { round_keys }
    }

    /// Encrypts one block (state bytes in column-major order, as in the standard).
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut s = *block;
        let add = |s: &mut [u8; 16], rk: &[u8; 16]| s.iter_mut().zip(rk).for_each(|(a, b)| *a ^= b);
        add(&mut s, &self.round_keys[0]);
        for (round, key) in self.round_keys.iter().enumerate().skip(1) {
            for b in &mut s {
                *b = SBOX[usize::from(*b)];
            }
            // ShiftRows: row r (bytes r, r+4, r+8, r+12) rotates left by r
            let t = s;
            for c in 0..4 {
                for r in 0..4 {
                    s[c * 4 + r] = t[((c + r) % 4) * 4 + r];
                }
            }
            if round != 10 {
                for c in 0..4 {
                    let col = [s[c * 4], s[c * 4 + 1], s[c * 4 + 2], s[c * 4 + 3]];
                    let all = col[0] ^ col[1] ^ col[2] ^ col[3];
                    for r in 0..4 {
                        s[c * 4 + r] = col[r] ^ all ^ xtime(col[r] ^ col[(r + 1) % 4]);
                    }
                }
            }
            add(&mut s, key);
        }
        s
    }
}

/// CFB with a 128-bit segment. `decrypt` feeds the ciphertext back; encryption feeds back what
/// it produced.
fn cfb(key: &[u8; 16], iv: &[u8; 16], data: &[u8], decrypt: bool) -> Vec<u8> {
    let aes = Aes128::new(key);
    let mut feedback = *iv;
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let stream = aes.encrypt_block(&feedback);
        let produced: Vec<u8> = chunk.iter().zip(stream).map(|(a, b)| a ^ b).collect();
        let cipher = if decrypt { chunk } else { &produced };
        if cipher.len() == 16 {
            feedback.copy_from_slice(cipher);
        }
        out.extend_from_slice(&produced);
    }
    out
}

pub fn cfb128_encrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    cfb(key, iv, data, false)
}
pub fn cfb128_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    cfb(key, iv, data, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }
    fn arr(s: &str) -> [u8; 16] {
        hex(s).try_into().unwrap()
    }

    #[test]
    fn the_sbox_is_the_standard_one() {
        // spot values from FIPS-197 figure 7, and it is a permutation
        assert_eq!(
            (SBOX[0x00], SBOX[0x01], SBOX[0x53], SBOX[0xff]),
            (0x63, 0x7c, 0xed, 0x16)
        );
        let mut seen = [false; 256];
        for b in SBOX {
            seen[usize::from(b)] = true;
        }
        assert!(seen.iter().all(|s| *s));
    }

    #[test]
    fn fips_197_appendix_c1() {
        let aes = Aes128::new(&arr("000102030405060708090a0b0c0d0e0f"));
        assert_eq!(
            aes.encrypt_block(&arr("00112233445566778899aabbccddeeff")),
            arr("69c4e0d86a7b0430d8cdb78070b4c55a")
        );
    }

    #[test]
    fn fips_197_appendix_b() {
        let aes = Aes128::new(&arr("2b7e151628aed2a6abf7158809cf4f3c"));
        assert_eq!(
            aes.encrypt_block(&arr("3243f6a8885a308d313198a2e0370734")),
            arr("3925841d02dc09fbdc118597196a0b32")
        );
    }

    #[test]
    fn nist_sp_800_38a_cfb128_aes128() {
        let key = arr("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = arr("000102030405060708090a0b0c0d0e0f");
        let plain = hex(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710"
        ));
        let cipher = hex(concat!(
            "3b3fd92eb72dad20333449f8e83cfb4a",
            "c8a64537a0b3a93fcde3cdad9f1ce58b",
            "26751f67a3cbb140b1808cf187a4f4df",
            "c04b05357c5d1c0eeac4c66f9ff7f2e6"
        ));
        assert_eq!(cfb128_encrypt(&key, &iv, &plain), cipher);
        assert_eq!(cfb128_decrypt(&key, &iv, &cipher), plain);
    }

    #[test]
    fn partial_blocks_round_trip_and_match_the_prefix_of_a_full_block() {
        let key = arr("000102030405060708090a0b0c0d0e0f");
        let iv = [9u8; 16];
        for n in [0usize, 1, 15, 16, 17, 31, 32, 33, 100] {
            let plain: Vec<u8> = (0..n as u8).collect();
            let c = cfb128_encrypt(&key, &iv, &plain);
            assert_eq!(c.len(), n);
            assert_eq!(cfb128_decrypt(&key, &iv, &c), plain, "{n}");
        }
        // a prefix of the data encrypts to a prefix of the ciphertext (CFB is a stream mode)
        let plain: Vec<u8> = (0..40u8).collect();
        let full = cfb128_encrypt(&key, &iv, &plain);
        assert_eq!(cfb128_encrypt(&key, &iv, &plain[..23]), full[..23]);
    }
}
