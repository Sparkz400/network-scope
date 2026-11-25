// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! A minimal BER encoder and decoder for SNMP (ITU-T X.690 definite lengths, the types SNMP
//! uses). Everything decoded here comes from a device on the network: lengths, nesting and the
//! number of items are bounded, and nothing panics on malformed input.
use std::fmt;

/// Most sub-identifiers of an object identifier that are accepted (RFC 3416 allows 128).
pub const MAX_OID_LEN: usize = 128;
/// Longest octet string kept from a reply.
pub const MAX_OCTETS: usize = 2048;
/// Most variable bindings read from one PDU.
pub const MAX_VARBINDS: usize = 96;

pub const INTEGER: u8 = 0x02;
pub const OCTET_STRING: u8 = 0x04;
pub const NULL: u8 = 0x05;
pub const OID: u8 = 0x06;
pub const SEQUENCE: u8 = 0x30;
pub const IP_ADDRESS: u8 = 0x40;
pub const COUNTER32: u8 = 0x41;
pub const GAUGE32: u8 = 0x42;
pub const TIME_TICKS: u8 = 0x43;
pub const OPAQUE: u8 = 0x44;
pub const COUNTER64: u8 = 0x46;
pub const NO_SUCH_OBJECT: u8 = 0x80;
pub const NO_SUCH_INSTANCE: u8 = 0x81;
pub const END_OF_MIB_VIEW: u8 = 0x82;

/// One definite-length TLV at `i`: `(tag, value, index after it)`. Lengths of up to four bytes
/// are read; the value must lie inside `d`. Indefinite lengths and multi-byte tags are rejected.
pub fn read(d: &[u8], i: usize) -> Option<(u8, &[u8], usize)> {
    let tag = *d.get(i)?;
    if tag & 0x1f == 0x1f {
        return None; // high tag numbers do not occur in SNMP
    }
    let first = *d.get(i.checked_add(1)?)?;
    let (len, start) = if first < 0x80 {
        (usize::from(first), i.checked_add(2)?)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for k in 0..n {
            len = (len << 8) | usize::from(*d.get(i.checked_add(2 + k)?)?);
        }
        (len, i.checked_add(2 + n)?)
    };
    let end = start.checked_add(len)?;
    Some((tag, d.get(start..end)?, end))
}

/// The TLV at the start of `d` with the given tag, and the bytes after it.
pub fn expect(d: &[u8], i: usize, tag: u8) -> Option<(&[u8], usize)> {
    let (t, v, next) = read(d, i)?;
    (t == tag).then_some((v, next))
}

/// Encodes one TLV.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(content.len() + 5);
    v.push(tag);
    match content.len() {
        n if n < 0x80 => v.push(n as u8),
        n if n < 0x100 => v.extend([0x81, n as u8]),
        n if n < 0x1_0000 => v.extend([0x82, (n >> 8) as u8, n as u8]),
        n => v.extend([0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]),
    }
    v.extend_from_slice(content);
    v
}

/// A BER INTEGER: minimal two's complement.
pub fn int(v: i64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let mut start = 0;
    while start < 7
        && ((bytes[start] == 0 && bytes[start + 1] & 0x80 == 0)
            || (bytes[start] == 0xff && bytes[start + 1] & 0x80 != 0))
    {
        start += 1;
    }
    tlv(INTEGER, &bytes[start..])
}

pub fn octets(v: &[u8]) -> Vec<u8> {
    tlv(OCTET_STRING, v)
}

/// A signed INTEGER value (up to 8 bytes).
pub fn parse_int(v: &[u8]) -> Option<i64> {
    if v.is_empty() || v.len() > 8 {
        return None;
    }
    let mut n: i64 = if v[0] & 0x80 != 0 { -1 } else { 0 };
    for b in v {
        n = (n << 8) | i64::from(*b);
    }
    Some(n)
}

/// An unsigned value of an application type (Counter32, Gauge32, TimeTicks, Counter64): up to
/// 8 bytes, or 9 with a leading zero.
pub fn parse_unsigned(v: &[u8]) -> Option<u64> {
    let v = match v {
        [0, rest @ ..] if rest.len() == 8 => rest,
        _ => v,
    };
    if v.is_empty() || v.len() > 8 {
        return None;
    }
    Some(v.iter().fold(0u64, |a, b| (a << 8) | u64::from(*b)))
}

/// An object identifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Oid(pub Vec<u32>);

impl Oid {
    /// `1.3.6.1.2.1.1.1.0` (a leading dot is accepted).
    pub fn parse(text: &str) -> Option<Self> {
        let parts: Vec<u32> = text
            .trim_start_matches('.')
            .split('.')
            .map(str::parse)
            .collect::<Result<_, _>>()
            .ok()?;
        (parts.len() >= 2 && parts.len() <= MAX_OID_LEN && parts[0] <= 2).then_some(Self(parts))
    }
    pub fn starts_with(&self, base: &Oid) -> bool {
        self.0.starts_with(&base.0)
    }
    /// The sub-identifiers after `base` (the row index of a table column).
    pub fn suffix(&self, base: &Oid) -> Option<&[u32]> {
        self.starts_with(base).then(|| &self.0[base.0.len()..])
    }
    pub fn child(&self, sub: &[u32]) -> Self {
        let mut v = self.0.clone();
        v.extend_from_slice(sub);
        Self(v)
    }
    /// The encoded OBJECT IDENTIFIER (tag, length and value); `None` when it cannot be encoded.
    pub fn encode(&self) -> Option<Vec<u8>> {
        let (a, b) = (*self.0.first()?, *self.0.get(1)?);
        if a > 2 || (a < 2 && b > 39) {
            return None;
        }
        let mut body = vec![];
        let mut push = |mut n: u32| {
            let mut tmp = [0u8; 5];
            let mut k = 5;
            loop {
                k -= 1;
                tmp[k] = (n & 0x7f) as u8 | if k == 4 { 0 } else { 0x80 };
                n >>= 7;
                if n == 0 {
                    break;
                }
            }
            body.extend_from_slice(&tmp[k..]);
        };
        push(a.checked_mul(40)?.checked_add(b)?);
        for n in &self.0[2..] {
            push(*n);
        }
        Some(tlv(OID, &body))
    }
    /// Decodes the value bytes of an OBJECT IDENTIFIER.
    pub fn decode(v: &[u8]) -> Option<Self> {
        if v.is_empty() {
            return None;
        }
        let mut out = vec![];
        let mut n: u64 = 0;
        let mut open = false;
        for b in v {
            n = (n << 7) | u64::from(b & 0x7f);
            if n > u64::from(u32::MAX) {
                return None;
            }
            if b & 0x80 == 0 {
                if out.is_empty() {
                    let first = (n / 40).min(2) as u32;
                    out.push(first);
                    out.push((n - u64::from(first) * 40) as u32);
                } else {
                    out.push(n as u32);
                }
                n = 0;
                open = false;
            } else {
                open = true;
            }
            if out.len() > MAX_OID_LEN {
                return None;
            }
        }
        (!open).then_some(Self(out))
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, n) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            write!(f, "{n}")?;
        }
        Ok(())
    }
}

/// A variable binding value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Integer(i64),
    Octets(Vec<u8>),
    Null,
    Oid(Oid),
    IpAddress([u8; 4]),
    Counter32(u32),
    Gauge32(u32),
    TimeTicks(u32),
    Opaque(Vec<u8>),
    Counter64(u64),
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
}

impl Value {
    pub fn encode(&self) -> Option<Vec<u8>> {
        let unsigned = |tag, v: u64| {
            let b = v.to_be_bytes();
            let mut s = 0;
            while s < 7 && b[s] == 0 {
                s += 1;
            }
            let mut content = b[s..].to_vec();
            if content[0] & 0x80 != 0 {
                content.insert(0, 0);
            }
            tlv(tag, &content)
        };
        Some(match self {
            Self::Integer(v) => int(*v),
            Self::Octets(v) => octets(v),
            Self::Null => tlv(NULL, &[]),
            Self::Oid(o) => o.encode()?,
            Self::IpAddress(a) => tlv(IP_ADDRESS, a),
            Self::Counter32(v) => unsigned(COUNTER32, u64::from(*v)),
            Self::Gauge32(v) => unsigned(GAUGE32, u64::from(*v)),
            Self::TimeTicks(v) => unsigned(TIME_TICKS, u64::from(*v)),
            Self::Opaque(v) => tlv(OPAQUE, v),
            Self::Counter64(v) => unsigned(COUNTER64, *v),
            Self::NoSuchObject => tlv(NO_SUCH_OBJECT, &[]),
            Self::NoSuchInstance => tlv(NO_SUCH_INSTANCE, &[]),
            Self::EndOfMibView => tlv(END_OF_MIB_VIEW, &[]),
        })
    }
    /// Decodes one value TLV.
    pub fn decode(tag: u8, v: &[u8]) -> Option<Self> {
        let capped = |v: &[u8]| v[..v.len().min(MAX_OCTETS)].to_vec();
        Some(match tag {
            INTEGER => Self::Integer(parse_int(v)?),
            OCTET_STRING => Self::Octets(capped(v)),
            NULL => Self::Null,
            OID => Self::Oid(Oid::decode(v)?),
            IP_ADDRESS => Self::IpAddress(v.try_into().ok()?),
            COUNTER32 => Self::Counter32(u32::try_from(parse_unsigned(v)?).ok()?),
            GAUGE32 => Self::Gauge32(u32::try_from(parse_unsigned(v)?).ok()?),
            TIME_TICKS => Self::TimeTicks(u32::try_from(parse_unsigned(v)?).ok()?),
            OPAQUE => Self::Opaque(capped(v)),
            COUNTER64 => Self::Counter64(parse_unsigned(v)?),
            NO_SUCH_OBJECT => Self::NoSuchObject,
            NO_SUCH_INSTANCE => Self::NoSuchInstance,
            END_OF_MIB_VIEW => Self::EndOfMibView,
            _ => return None,
        })
    }
    /// The end of a walk or a missing object (RFC 3416 exceptions).
    pub fn is_exception(&self) -> bool {
        matches!(
            self,
            Self::NoSuchObject | Self::NoSuchInstance | Self::EndOfMibView
        )
    }
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Integer(v) => Some(*v),
            Self::Counter32(v) | Self::Gauge32(v) | Self::TimeTicks(v) => Some(i64::from(*v)),
            _ => None,
        }
    }
    pub fn as_octets(&self) -> Option<&[u8]> {
        match self {
            Self::Octets(v) | Self::Opaque(v) => Some(v),
            _ => None,
        }
    }
}

/// `(name, value)` variable bindings of a PDU body: a SEQUENCE OF SEQUENCE { OID, value }.
pub fn parse_varbinds(list: &[u8]) -> Option<Vec<(Oid, Value)>> {
    let mut out = vec![];
    let mut i = 0;
    while i < list.len() {
        let (vb, next) = expect(list, i, SEQUENCE)?;
        i = next;
        let (name, at) = expect(vb, 0, OID)?;
        let (tag, value, _) = read(vb, at)?;
        if out.len() >= MAX_VARBINDS {
            return None;
        }
        out.push((Oid::decode(name)?, Value::decode(tag, value)?));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_round_trip_at_the_boundaries() {
        for n in [0usize, 1, 127, 128, 255, 256, 65_535, 65_536, 100_000] {
            let body = vec![7u8; n];
            let e = tlv(OCTET_STRING, &body);
            let (tag, v, next) = read(&e, 0).unwrap();
            assert_eq!((tag, v.len(), next), (OCTET_STRING, n, e.len()), "{n}");
        }
        // short and long form are what X.690 says
        assert_eq!(&tlv(4, &[0; 127])[..2], [4, 127]);
        assert_eq!(&tlv(4, &[0; 128])[..3], [4, 0x81, 128]);
        assert_eq!(&tlv(4, &[0; 256])[..4], [4, 0x82, 1, 0]);
    }

    #[test]
    fn malformed_lengths_are_rejected_not_panicked_on() {
        assert!(read(&[], 0).is_none());
        assert!(read(&[4], 0).is_none());
        assert!(
            read(&[4, 5, 1, 2], 0).is_none(),
            "value shorter than its length"
        );
        assert!(read(&[4, 0x80, 1], 0).is_none(), "indefinite length");
        assert!(
            read(&[4, 0x85, 0, 0, 0, 0, 1], 0).is_none(),
            "five length bytes"
        );
        assert!(read(&[4, 0x84, 0xff, 0xff, 0xff, 0xff], 0).is_none());
        assert!(read(&[0x1f, 1, 0], 0).is_none(), "high tag number");
        assert!(read(&[4, 0], usize::MAX).is_none());
    }

    #[test]
    fn integers_are_minimal_two_complement() {
        for (v, bytes) in [
            (0i64, &[2u8, 1, 0][..]),
            (127, &[2, 1, 127]),
            (128, &[2, 2, 0, 128]),
            (-1, &[2, 1, 0xff]),
            (-128, &[2, 1, 0x80]),
            (-129, &[2, 2, 0xff, 0x7f]),
            (256, &[2, 2, 1, 0]),
        ] {
            assert_eq!(int(v), bytes, "{v}");
            let (_, value, _) = read(bytes, 0).unwrap();
            assert_eq!(parse_int(value), Some(v));
        }
        for v in [i64::MIN, i64::MAX, 0x7fff_ffff, -0x8000_0000, 1 << 40] {
            let e = int(v);
            assert_eq!(parse_int(read(&e, 0).unwrap().1), Some(v));
        }
        assert_eq!(parse_int(&[]), None);
        assert_eq!(parse_int(&[0; 9]), None);
    }

    #[test]
    fn oids_encode_and_decode() {
        let o = Oid::parse("1.3.6.1.2.1.1.1.0").unwrap();
        assert_eq!(o.encode().unwrap(), [6, 8, 0x2b, 6, 1, 2, 1, 1, 1, 0]);
        // multi-byte sub-identifiers: 1.3.6.1.4.1.8072 (net-snmp), 2.999 and the LLDP 1.0.8802
        for text in [
            "1.3.6.1.4.1.8072",
            "2.999.3",
            "1.0.8802.1.1.2.1.4.1.1.9",
            "1.3.4294967295",
        ] {
            let o = Oid::parse(text).unwrap();
            let e = o.encode().unwrap();
            let (tag, v, _) = read(&e, 0).unwrap();
            assert_eq!(tag, OID);
            assert_eq!(Oid::decode(v).unwrap(), o, "{text}");
            assert_eq!(o.to_string(), text);
        }
        assert_eq!(
            Oid::parse("1.3.6.1.4.1.8072").unwrap().encode().unwrap(),
            [6, 7, 0x2b, 6, 1, 4, 1, 0xbf, 0x08]
        );
        assert!(
            Oid::parse("1").is_none() && Oid::parse("3.1").is_none() && Oid::parse("1.x").is_none()
        );
        assert!(
            Oid(vec![1, 40]).encode().is_none(),
            "second arc above 39 under arc 1"
        );
        // truncated or oversized sub-identifiers
        assert!(Oid::decode(&[0x2b, 0x81]).is_none());
        assert!(Oid::decode(&[0x2b, 0xff, 0xff, 0xff, 0xff, 0x7f]).is_none());
        assert!(Oid::decode(&[]).is_none());
        let long: Vec<u8> = std::iter::once(0x2b)
            .chain(std::iter::repeat_n(1, 200))
            .collect();
        assert!(Oid::decode(&long).is_none());
    }

    #[test]
    fn values_round_trip() {
        for v in [
            Value::Integer(-5),
            Value::Octets(b"abc".to_vec()),
            Value::Null,
            Value::Oid(Oid::parse("1.3.6.1.4.1.9").unwrap()),
            Value::IpAddress([10, 0, 0, 1]),
            Value::Counter32(u32::MAX),
            Value::Gauge32(0x8000_0000),
            Value::TimeTicks(123_456),
            Value::Counter64(u64::MAX),
            Value::NoSuchObject,
            Value::NoSuchInstance,
            Value::EndOfMibView,
        ] {
            let e = v.encode().unwrap();
            let (tag, body, _) = read(&e, 0).unwrap();
            assert_eq!(Value::decode(tag, body).unwrap(), v);
        }
        assert!(Value::decode(IP_ADDRESS, &[1, 2, 3]).is_none());
        assert!(
            Value::decode(COUNTER32, &[1, 0, 0, 0, 0]).is_none(),
            "above 32 bits"
        );
        assert!(Value::decode(0x99, &[]).is_none());
    }

    #[test]
    fn varbind_lists_are_bounded() {
        let one = tlv(
            SEQUENCE,
            &[
                Oid::parse("1.3.6.1.2.1.1.5.0").unwrap().encode().unwrap(),
                Value::Null.encode().unwrap(),
            ]
            .concat(),
        );
        assert_eq!(parse_varbinds(&one).unwrap().len(), 1);
        assert!(parse_varbinds(&one.repeat(MAX_VARBINDS)).is_some());
        assert!(parse_varbinds(&one.repeat(MAX_VARBINDS + 1)).is_none());
        assert!(parse_varbinds(&one[..one.len() - 1]).is_none());
        assert!(parse_varbinds(&[SEQUENCE, 2, 4, 0]).is_none());
    }
}
