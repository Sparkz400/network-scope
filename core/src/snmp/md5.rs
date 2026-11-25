// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! MD5 (RFC 1321) and HMAC-MD5 (RFC 2104) for SNMPv3 `usmHMACMD5AuthProtocol` (RFC 3414).
//!
//! `ring` has no MD5, so it is written out here from the RFC. MD5 is broken as a general hash
//! (collisions are cheap); SNMPv3 uses it only as a keyed MAC, where it is weak but not trivially
//! forgeable. It exists because older devices offer nothing else: the option is opt-in and the
//! documentation says so. Checked against the RFC 1321 test suite and the RFC 2202 HMAC-MD5
//! vectors (see the tests).

const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// K[i] = floor(2^32 * abs(sin(i + 1))), the table of RFC 1321 section 3.4. Computed from the
/// definition at compile time would need floating point in a const context, so it is written out.
const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// An MD5 computation that can be fed in pieces (the key derivation hashes a megabyte).
#[derive(Clone)]
pub struct Md5 {
    state: [u32; 4],
    buffer: [u8; 64],
    filled: usize,
    length: u64,
}

impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

impl Md5 {
    pub fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            buffer: [0; 64],
            filled: 0,
            length: 0,
        }
    }

    fn block(state: &mut [u32; 4], chunk: &[u8; 64]) {
        let mut m = [0u32; 16];
        for (word, bytes) in m.iter_mut().zip(chunk.as_chunks::<4>().0) {
            *word = u32::from_le_bytes(*bytes);
        }
        let [mut a, mut b, mut c, mut d] = *state;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let rotated = a
                .wrapping_add(f)
                .wrapping_add(K[i])
                .wrapping_add(m[g])
                .rotate_left(S[i]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(rotated);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        if self.filled > 0 {
            let take = (64 - self.filled).min(data.len());
            self.buffer[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            data = &data[take..];
            if self.filled < 64 {
                return;
            }
            let chunk = self.buffer;
            Self::block(&mut self.state, &chunk);
            self.filled = 0;
        }
        let (chunks, rest) = data.as_chunks::<64>();
        for chunk in chunks {
            Self::block(&mut self.state, chunk);
        }
        self.buffer[..rest.len()].copy_from_slice(rest);
        self.filled = rest.len();
    }

    pub fn finish(mut self) -> [u8; 16] {
        let bits = self.length.wrapping_mul(8);
        self.update(&[0x80]);
        while self.filled != 56 {
            self.update(&[0]);
        }
        self.update(&bits.to_le_bytes());
        debug_assert_eq!(self.filled, 0);
        let mut out = [0u8; 16];
        for (bytes, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.state) {
            *bytes = word.to_le_bytes();
        }
        out
    }
}

pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut context = Md5::new();
    context.update(data);
    context.finish()
}

/// HMAC-MD5 (RFC 2104) with a 64-byte block.
pub fn hmac_md5(key: &[u8], message: &[u8]) -> [u8; 16] {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..16].copy_from_slice(&md5(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Md5::new();
    inner.update(&block.map(|b| b ^ 0x36));
    inner.update(message);
    let inner = inner.finish();
    let mut outer = Md5::new();
    outer.update(&block.map(|b| b ^ 0x5c));
    outer.update(&inner);
    outer.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// RFC 1321 appendix A.5, the test suite.
    #[test]
    fn rfc_1321_test_suite() {
        for (input, expected) in [
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("a", "0cc175b9c0f1b6a831c399e269772661"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                "abcdefghijklmnopqrstuvwxyz",
                "c3fcd3d76192e4007dfb496cca67e13b",
            ),
            (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                "d174ab98d277d9f5a5611c2c9f419d9f",
            ),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ] {
            assert_eq!(hex(&md5(input.as_bytes())), expected, "{input:?}");
        }
    }

    /// Feeding the same bytes in odd pieces gives the same digest (block boundaries at 55, 56,
    /// 63, 64 and 65 bytes are the usual places for a padding bug).
    #[test]
    fn pieces_and_padding_boundaries() {
        let data: Vec<u8> = (0..300u32).map(|i| (i * 7 + 3) as u8).collect();
        for len in [0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 128, 300] {
            let whole = md5(&data[..len]);
            for step in [1, 3, 17, 64, 100] {
                let mut context = Md5::new();
                for piece in data[..len].chunks(step) {
                    context.update(piece);
                }
                assert_eq!(context.finish(), whole, "len {len} step {step}");
            }
        }
    }

    /// RFC 2202 section 2, HMAC-MD5 test cases 1 to 3, 6 and 7.
    #[test]
    fn rfc_2202_hmac_md5() {
        assert_eq!(
            hex(&hmac_md5(&[0x0b; 16], b"Hi There")),
            "9294727a3638bb1c13f48ef8158bfc9d"
        );
        assert_eq!(
            hex(&hmac_md5(b"Jefe", b"what do ya want for nothing?")),
            "750c783e6ab0b503eaa86e310a5db738"
        );
        assert_eq!(
            hex(&hmac_md5(&[0xaa; 16], &[0xdd; 50])),
            "56be34521d144c88dbb8c733f0e8b3f6"
        );
        assert_eq!(
            hex(&hmac_md5(
                &[0xaa; 80],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd"
        );
        assert_eq!(
            hex(&hmac_md5(
                &[0xaa; 80],
                b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
            )),
            "6f630fad67cda0ee1fb1f562db3aa53e"
        );
    }
}
