//! SNMP message encoding (v1, v2c, v3 with USM) and decoding of the replies. The replies come
//! from devices on the network: every length and count is bounded and nothing panics.
use super::{
    Datagram, SnmpRequest, Version,
    ber::{self, Oid, SEQUENCE, Value, expect, int, octets, tlv},
    label,
    usm::{self, AuthProto, Privacy},
};

/// Largest SNMP message accepted (a reply must fit one UDP datagram).
pub const MAX_MESSAGE: usize = 8192;
/// `msgMaxSize` advertised to the agent: replies stay within one unfragmented datagram.
pub const ADVERTISED_MAX_SIZE: i64 = 1472;

pub const RESPONSE: u8 = 0xA2;
pub const REPORT: u8 = 0xA8;

fn encode_pdu(request: &SnmpRequest, request_id: i32) -> Option<Vec<u8>> {
    let mut varbinds = vec![];
    for oid in request.oids() {
        let name = oid.encode()?;
        varbinds.extend(tlv(SEQUENCE, &[name, Value::Null.encode()?].concat()));
    }
    let (second, third) = match request.pdu() {
        super::SnmpPdu::GetBulk => (
            i64::from(request.non_repeaters),
            i64::from(request.max_repetitions),
        ),
        _ => (0, 0),
    };
    Some(tlv(
        request.pdu().tag(),
        &[
            int(i64::from(request_id)),
            int(second),
            int(third),
            tlv(SEQUENCE, &varbinds),
        ]
        .concat(),
    ))
}

/// A v1 or v2c message. SNMPv1 has no GetBulkRequest: `None`.
pub fn encode_community(
    version: Version,
    community: &str,
    request_id: i32,
    request: &SnmpRequest,
) -> Option<Datagram> {
    if version == Version::V3
        || (version == Version::V1 && request.pdu() == super::SnmpPdu::GetBulk)
    {
        return None;
    }
    let pdu = encode_pdu(request, request_id)?;
    let bytes = tlv(
        SEQUENCE,
        &[int(version.wire()), octets(community.as_bytes()), pdu].concat(),
    );
    Some(Datagram {
        bytes,
        label: label(version, request.pdu()),
    })
}

/// What the sender of a v3 message knows about the agent and itself.
pub struct V3Send<'a> {
    pub user: &'a str,
    pub engine_id: &'a [u8],
    pub boots: u32,
    pub time: u32,
    pub auth: Option<(AuthProto, &'a [u8])>,
    pub privacy: Option<(&'a Privacy, [u8; 8])>,
}

fn security_parameters(
    engine_id: &[u8],
    boots: u32,
    time: u32,
    user: &str,
    auth: &[u8],
    privacy: &[u8],
) -> Vec<u8> {
    octets(&tlv(
        SEQUENCE,
        &[
            octets(engine_id),
            int(i64::from(boots)),
            int(i64::from(time)),
            octets(user.as_bytes()),
            octets(auth),
            octets(privacy),
        ]
        .concat(),
    ))
}

fn v3_message(msg_id: i32, flags: u8, security: &[u8], data: &[u8]) -> Vec<u8> {
    tlv(
        SEQUENCE,
        &[
            int(3),
            tlv(
                SEQUENCE,
                &[
                    int(i64::from(msg_id)),
                    int(ADVERTISED_MAX_SIZE),
                    octets(&[flags]),
                    int(3),
                ]
                .concat(),
            ),
            security.to_vec(),
            data.to_vec(),
        ]
        .concat(),
    )
}

fn scoped_pdu(engine_id: &[u8], pdu: &[u8]) -> Vec<u8> {
    tlv(
        SEQUENCE,
        &[octets(engine_id), octets(b""), pdu.to_vec()].concat(),
    )
}

/// The v3 discovery request (RFC 3414 section 4): reportable, no security, an empty engine ID and
/// user name and no variable bindings. The agent answers with a Report naming its engine.
pub fn encode_v3_discovery(msg_id: i32, request_id: i32) -> Datagram {
    let empty = SnmpRequest::get(&[]);
    let pdu = encode_pdu(&empty, request_id).expect("no OIDs to encode");
    let bytes = v3_message(
        msg_id,
        0x04,
        &security_parameters(b"", 0, 0, "", b"", b""),
        &scoped_pdu(b"", &pdu),
    );
    Datagram {
        bytes,
        label: label(Version::V3, super::SnmpPdu::Get),
    }
}

/// A v3 request with the user's security level.
pub fn encode_v3(
    msg_id: i32,
    request_id: i32,
    request: &SnmpRequest,
    s: &V3Send<'_>,
) -> Option<Datagram> {
    let pdu = encode_pdu(request, request_id)?;
    let scoped = scoped_pdu(s.engine_id, &pdu);
    let mut flags = 0x04; // reportable
    let mut priv_params: Vec<u8> = vec![];
    let data = match &s.privacy {
        Some((privacy, salt)) => {
            flags |= 0x02;
            priv_params = salt.to_vec();
            octets(&privacy.encrypt(s.boots, s.time, salt, &scoped))
        }
        None => scoped,
    };
    let mac_len = s.auth.map_or(0, |(proto, _)| proto.mac_len());
    if s.auth.is_some() {
        flags |= 0x01;
    }
    if s.privacy.is_some() && s.auth.is_none() {
        return None; // privacy needs authentication
    }
    let build = |auth: &[u8]| {
        v3_message(
            msg_id,
            flags,
            &security_parameters(s.engine_id, s.boots, s.time, s.user, auth, &priv_params),
            &data,
        )
    };
    let bytes = match s.auth {
        Some((proto, key)) => {
            let zeroed = build(&vec![0u8; mac_len]);
            build(&usm::mac(proto, key, &zeroed))
        }
        None => build(&[]),
    };
    Some(Datagram {
        bytes,
        label: label(Version::V3, request.pdu()),
    })
}

/// The tag of the PDU inside a v1/v2c message or an unencrypted v3 message.
pub fn pdu_tag_of_message(m: &[u8]) -> Option<u8> {
    let (msg, _) = expect(m, 0, SEQUENCE)?;
    let (v, at) = expect(msg, 0, ber::INTEGER)?;
    match ber::parse_int(v)? {
        0 | 1 => {
            let (_, at) = expect(msg, at, ber::OCTET_STRING)?;
            let (tag, _, _) = ber::read(msg, at)?;
            Some(tag)
        }
        3 => {
            let (_, at) = expect(msg, at, SEQUENCE)?;
            let (_, at) = expect(msg, at, ber::OCTET_STRING)?;
            let (scoped, _) = expect(msg, at, SEQUENCE)?;
            let (_, at) = expect(scoped, 0, ber::OCTET_STRING)?;
            let (_, at) = expect(scoped, at, ber::OCTET_STRING)?;
            let (tag, _, _) = ber::read(scoped, at)?;
            Some(tag)
        }
        _ => None,
    }
}

/// A decoded Response or Report PDU.
#[derive(Debug, Clone, PartialEq)]
pub struct Pdu {
    pub report: bool,
    pub request_id: i64,
    pub error_status: i64,
    pub error_index: i64,
    pub varbinds: Vec<(Oid, Value)>,
}

fn parse_pdu(d: &[u8], at: usize) -> Option<Pdu> {
    let (tag, body, _) = ber::read(d, at)?;
    if tag != RESPONSE && tag != REPORT {
        return None;
    }
    let (id, i) = expect(body, 0, ber::INTEGER)?;
    let (status, i) = expect(body, i, ber::INTEGER)?;
    let (index, i) = expect(body, i, ber::INTEGER)?;
    let (list, _) = expect(body, i, SEQUENCE)?;
    Some(Pdu {
        report: tag == REPORT,
        request_id: ber::parse_int(id)?,
        error_status: ber::parse_int(status)?,
        error_index: ber::parse_int(index)?,
        varbinds: ber::parse_varbinds(list)?,
    })
}

/// A v1 or v2c Response: the version must be the one we sent.
pub fn parse_community(m: &[u8], version: Version) -> Result<Pdu, String> {
    if m.len() > MAX_MESSAGE {
        return Err("reply too large".into());
    }
    let (msg, _) = expect(m, 0, SEQUENCE).ok_or("not an SNMP message")?;
    let (v, at) = expect(msg, 0, ber::INTEGER).ok_or("not an SNMP message")?;
    if ber::parse_int(v) != Some(version.wire()) {
        return Err("reply has another SNMP version".into());
    }
    let (_, at) = expect(msg, at, ber::OCTET_STRING).ok_or("not an SNMP message")?;
    parse_pdu(msg, at)
        .filter(|p| !p.report)
        .ok_or_else(|| "not a Response PDU".into())
}

/// The security parameters of a v3 reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Usm {
    pub engine_id: Vec<u8>,
    pub boots: u32,
    pub time: u32,
    pub user: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct V3Reply {
    pub msg_id: i64,
    pub flags: u8,
    pub usm: Usm,
    pub pdu: Pdu,
}

/// How a v3 reply must be protected for us to accept it.
pub struct V3Expect<'a> {
    pub auth: Option<(AuthProto, &'a [u8])>,
    pub privacy: Option<&'a Privacy>,
}

/// Decodes a v3 message. When we authenticated the request, a Response must carry a valid
/// HMAC (and, with privacy, be encrypted); only an unauthenticated Report (the agent says it
/// cannot process the request) is accepted without, and callers treat it as an error message.
pub fn parse_v3(m: &[u8], expect_security: &V3Expect<'_>) -> Result<V3Reply, String> {
    if m.len() > MAX_MESSAGE {
        return Err("reply too large".into());
    }
    let bad = || "malformed SNMPv3 message".to_string();
    let (msg, _) = expect(m, 0, SEQUENCE).ok_or_else(bad)?;
    let (v, at) = expect(msg, 0, ber::INTEGER).ok_or_else(bad)?;
    if ber::parse_int(v) != Some(3) {
        return Err("reply has another SNMP version".into());
    }
    let (global, at) = expect(msg, at, SEQUENCE).ok_or_else(bad)?;
    let (id, i) = expect(global, 0, ber::INTEGER).ok_or_else(bad)?;
    let (_max, i) = expect(global, i, ber::INTEGER).ok_or_else(bad)?;
    let (flags, i) = expect(global, i, ber::OCTET_STRING).ok_or_else(bad)?;
    let (model, _) = expect(global, i, ber::INTEGER).ok_or_else(bad)?;
    if ber::parse_int(model) != Some(3) {
        return Err("reply uses another security model than USM".into());
    }
    let flags = *flags.first().ok_or_else(bad)?;
    let (security, at) = expect(msg, at, ber::OCTET_STRING).ok_or_else(bad)?;
    let (params, _) = expect(security, 0, SEQUENCE).ok_or_else(bad)?;
    let (engine_id, i) = expect(params, 0, ber::OCTET_STRING).ok_or_else(bad)?;
    let (boots, i) = expect(params, i, ber::INTEGER).ok_or_else(bad)?;
    let (time, i) = expect(params, i, ber::INTEGER).ok_or_else(bad)?;
    let (user, i) = expect(params, i, ber::OCTET_STRING).ok_or_else(bad)?;
    let (auth_params, i) = expect(params, i, ber::OCTET_STRING).ok_or_else(bad)?;
    let (priv_params, _) = expect(params, i, ber::OCTET_STRING).ok_or_else(bad)?;
    let usm = Usm {
        engine_id: engine_id[..engine_id.len().min(32)].to_vec(),
        boots: u32::try_from(ber::parse_int(boots).ok_or_else(bad)?).map_err(|_| bad())?,
        time: u32::try_from(ber::parse_int(time).ok_or_else(bad)?).map_err(|_| bad())?,
        user: user[..user.len().min(32)].to_vec(),
    };
    // Authentication: the HMAC covers the whole message with the parameters zeroed.
    let authenticated = flags & 0x01 != 0;
    if authenticated {
        let Some((proto, key)) = expect_security.auth else {
            return Err("reply is authenticated but the request was not".into());
        };
        let offset = (auth_params.as_ptr() as usize)
            .checked_sub(m.as_ptr() as usize)
            .filter(|o| o + auth_params.len() <= m.len())
            .ok_or_else(bad)?;
        let mut zeroed = m.to_vec();
        zeroed[offset..offset + auth_params.len()].fill(0);
        if !usm::verify(proto, key, &zeroed, auth_params) {
            return Err("reply failed authentication (wrong password, or not the agent)".into());
        }
    }
    let data = {
        let (tag, body, _) = ber::read(msg, at).ok_or_else(bad)?;
        match tag {
            SEQUENCE => body.to_vec(),
            ber::OCTET_STRING => {
                if flags & 0x02 == 0 {
                    return Err(bad());
                }
                let Some(privacy) = expect_security.privacy else {
                    return Err("reply is encrypted but the request was not".into());
                };
                // a wrong key decrypts to noise: the parse below fails
                privacy
                    .decrypt(usm.boots, usm.time, priv_params, body)
                    .ok_or_else(bad)?
            }
            _ => return Err(bad()),
        }
    };
    // ScopedPDU body: contextEngineID, contextName, PDU. For a plaintext message `data` is the
    // content of the SEQUENCE; for an encrypted one it is the whole SEQUENCE.
    let scoped: &[u8] = if flags & 0x02 != 0 {
        expect(&data, 0, SEQUENCE)
            .ok_or("decryption failed (wrong privacy password?)")?
            .0
    } else {
        &data
    };
    let (_, i) = expect(scoped, 0, ber::OCTET_STRING).ok_or_else(bad)?;
    let (_, i) = expect(scoped, i, ber::OCTET_STRING).ok_or_else(bad)?;
    let pdu = parse_pdu(scoped, i).ok_or_else(bad)?;
    if expect_security.auth.is_some() && !authenticated && !pdu.report {
        return Err("reply is not authenticated".into());
    }
    Ok(V3Reply {
        msg_id: ber::parse_int(id).ok_or_else(bad)?,
        flags,
        usm,
        pdu,
    })
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::snmp::ber::Value;

    fn oid(s: &str) -> Oid {
        Oid::parse(s).unwrap()
    }

    /// A v2c Response message for the tests.
    pub(crate) fn response(
        version: i64,
        community: &str,
        id: i64,
        status: i64,
        vbs: &[(Oid, Value)],
    ) -> Vec<u8> {
        let mut list = vec![];
        for (o, v) in vbs {
            list.extend(tlv(
                SEQUENCE,
                &[o.encode().unwrap(), v.encode().unwrap()].concat(),
            ));
        }
        let pdu = tlv(
            RESPONSE,
            &[int(id), int(status), int(0), tlv(SEQUENCE, &list)].concat(),
        );
        tlv(
            SEQUENCE,
            &[int(version), octets(community.as_bytes()), pdu].concat(),
        )
    }

    /// The literal bytes of the request the lab and the old UDP probe send (RFC 1157 layout).
    #[test]
    fn a_v2c_get_has_the_documented_bytes() {
        let d = encode_community(
            Version::V2c,
            "public",
            0x01020304,
            &SnmpRequest::get(&[oid("1.3.6.1.2.1.1.1.0")]),
        )
        .unwrap();
        assert_eq!(
            d.bytes(),
            [
                0x30, 0x29, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xA0,
                0x1C, 0x02, 0x04, 1, 2, 3, 4, 0x02, 0x01, 0, 0x02, 0x01, 0, 0x30, 0x0E, 0x30, 0x0C,
                0x06, 0x08, 0x2B, 6, 1, 2, 1, 1, 1, 0, 0x05, 0x00
            ]
        );
        // the old probe in udp.rs produces the same message
        assert_eq!(d.bytes(), crate::udp::snmp_get(1, "public", 0x01020304));
    }

    #[test]
    fn getbulk_carries_non_repeaters_and_repetitions() {
        let d = encode_community(
            Version::V2c,
            "c",
            5,
            &SnmpRequest::get_bulk(12, &[oid("1.3.6.1.2.1.2.2.1.2")]).unwrap(),
        )
        .unwrap();
        let (msg, _) = expect(d.bytes(), 0, SEQUENCE).unwrap();
        let (_, at) = expect(msg, 0, ber::INTEGER).unwrap();
        let (_, at) = expect(msg, at, ber::OCTET_STRING).unwrap();
        let (tag, pdu, _) = ber::read(msg, at).unwrap();
        assert_eq!(tag, 0xA5);
        let (_, i) = expect(pdu, 0, ber::INTEGER).unwrap();
        let (nr, i) = expect(pdu, i, ber::INTEGER).unwrap();
        let (mr, _) = expect(pdu, i, ber::INTEGER).unwrap();
        assert_eq!(
            (ber::parse_int(nr), ber::parse_int(mr)),
            (Some(0), Some(12))
        );
    }

    #[test]
    fn community_replies_parse_and_wrong_versions_are_refused() {
        let m = response(
            1,
            "public",
            9,
            0,
            &[(oid("1.3.6.1.2.1.1.5.0"), Value::Octets(b"sw1".to_vec()))],
        );
        let p = parse_community(&m, Version::V2c).unwrap();
        assert_eq!((p.request_id, p.error_status), (9, 0));
        assert_eq!(p.varbinds[0].1, Value::Octets(b"sw1".to_vec()));
        assert!(parse_community(&m, Version::V1).is_err());
        assert!(parse_community(&m[..m.len() - 3], Version::V2c).is_err());
        // a GetRequest echoed back is not a Response
        let echoed = encode_community(
            Version::V2c,
            "c",
            1,
            &SnmpRequest::get(&[oid("1.3.6.1.2.1.1.5.0")]),
        )
        .unwrap();
        assert!(parse_community(echoed.bytes(), Version::V2c).is_err());
        // every truncation fails cleanly
        for cut in 0..m.len() {
            assert!(parse_community(&m[..cut], Version::V2c).is_err());
        }
        assert!(parse_community(&vec![0x30; MAX_MESSAGE + 1], Version::V2c).is_err());
    }

    fn engine() -> Vec<u8> {
        vec![0x80, 0, 0x1f, 0x88, 0x80, 1, 2, 3, 4, 5, 6, 7, 8]
    }

    /// Builds the reply an agent would send.
    pub(crate) fn agent_reply(
        pdu: &Pdu,
        usm: &Usm,
        auth: Option<(AuthProto, &[u8])>,
        privacy: Option<(&Privacy, [u8; 8])>,
    ) -> Vec<u8> {
        agent_reply_with_id(7, pdu, usm, auth, privacy)
    }

    /// The same with the message ID of the request (the loopback agent echoes it).
    pub(crate) fn agent_reply_with_id(
        msg_id: i64,
        pdu: &Pdu,
        usm: &Usm,
        auth: Option<(AuthProto, &[u8])>,
        privacy: Option<(&Privacy, [u8; 8])>,
    ) -> Vec<u8> {
        let mut list = vec![];
        for (o, v) in &pdu.varbinds {
            list.extend(tlv(
                SEQUENCE,
                &[o.encode().unwrap(), v.encode().unwrap()].concat(),
            ));
        }
        let p = tlv(
            if pdu.report { REPORT } else { RESPONSE },
            &[
                int(pdu.request_id),
                int(pdu.error_status),
                int(pdu.error_index),
                tlv(SEQUENCE, &list),
            ]
            .concat(),
        );
        let scoped = scoped_pdu(&usm.engine_id, &p);
        let mut flags = 0u8;
        let mut priv_params = vec![];
        let data = match privacy {
            Some((pr, salt)) => {
                flags |= 2;
                priv_params = salt.to_vec();
                octets(&pr.encrypt(usm.boots, usm.time, &salt, &scoped))
            }
            None => scoped,
        };
        let mac_len = auth.map_or(0, |(p, _)| p.mac_len());
        if auth.is_some() {
            flags |= 1;
        }
        let user = String::from_utf8_lossy(&usm.user).into_owned();
        let build = |a: &[u8]| {
            v3_message(
                msg_id as i32,
                flags,
                &security_parameters(&usm.engine_id, usm.boots, usm.time, &user, a, &priv_params),
                &data,
            )
        };
        match auth {
            Some((proto, key)) => {
                let zeroed = build(&vec![0; mac_len]);
                build(&usm::mac(proto, key, &zeroed))
            }
            None => build(&[]),
        }
    }

    fn report() -> (Pdu, Usm) {
        (
            Pdu {
                report: true,
                request_id: 0,
                error_status: 0,
                error_index: 0,
                varbinds: vec![(oid("1.3.6.1.6.3.15.1.1.4.0"), Value::Counter32(3))],
            },
            Usm {
                engine_id: engine(),
                boots: 5,
                time: 1000,
                user: vec![],
            },
        )
    }

    #[test]
    fn the_discovery_request_has_no_credentials_and_no_variable_bindings() {
        let d = encode_v3_discovery(1, 2);
        assert_eq!(
            SnmpPdu::of_message(d.bytes()),
            Some(crate::snmp::SnmpPdu::Get)
        );
        let (msg, _) = expect(d.bytes(), 0, SEQUENCE).unwrap();
        let (_, at) = expect(msg, 0, ber::INTEGER).unwrap();
        let (global, _) = expect(msg, at, SEQUENCE).unwrap();
        let (_, i) = expect(global, 0, ber::INTEGER).unwrap();
        let (_, i) = expect(global, i, ber::INTEGER).unwrap();
        let (flags, _) = expect(global, i, ber::OCTET_STRING).unwrap();
        assert_eq!(flags, [0x04], "reportable only");
        // the agent's Report is accepted without authentication when none was requested
        let (pdu, usm) = report();
        let r = parse_v3(
            &agent_reply(&pdu, &usm, None, None),
            &V3Expect {
                auth: None,
                privacy: None,
            },
        )
        .unwrap();
        assert!(r.pdu.report);
        assert_eq!(
            (r.usm.engine_id, r.usm.boots, r.usm.time),
            (engine(), 5, 1000)
        );
    }

    use crate::snmp::SnmpPdu;

    #[test]
    fn authenticated_requests_and_replies_verify_end_to_end() {
        for proto in [AuthProto::Sha1, AuthProto::Sha256] {
            let key = usm::localized_key(proto, b"authpass-1234", &engine());
            let request = SnmpRequest::get(&[oid("1.3.6.1.2.1.1.5.0")]);
            let d = encode_v3(
                11,
                12,
                &request,
                &V3Send {
                    user: "monitor",
                    engine_id: &engine(),
                    boots: 5,
                    time: 1000,
                    auth: Some((proto, &key)),
                    privacy: None,
                },
            )
            .unwrap();
            assert_eq!(SnmpPdu::of_message(d.bytes()), Some(SnmpPdu::Get));
            // flags: reportable + auth
            let m = d.bytes();
            assert!(m.windows(3).any(|w| w == [0x04, 0x01, 0x05]), "{m:02x?}");
            let reply = Pdu {
                report: false,
                request_id: 12,
                error_status: 0,
                error_index: 0,
                varbinds: vec![(oid("1.3.6.1.2.1.1.5.0"), Value::Octets(b"core-sw".to_vec()))],
            };
            let usm = Usm {
                engine_id: engine(),
                boots: 5,
                time: 1001,
                user: b"monitor".to_vec(),
            };
            let bytes = agent_reply(&reply, &usm, Some((proto, &key)), None);
            let ok = parse_v3(
                &bytes,
                &V3Expect {
                    auth: Some((proto, &key)),
                    privacy: None,
                },
            )
            .unwrap();
            assert_eq!(ok.pdu, reply);
            // a flipped byte anywhere in the message fails authentication or parsing
            for i in 0..bytes.len() {
                let mut bad = bytes.clone();
                bad[i] ^= 0x01;
                if let Ok(r) = parse_v3(
                    &bad,
                    &V3Expect {
                        auth: Some((proto, &key)),
                        privacy: None,
                    },
                ) {
                    panic!("byte {i} flipped but accepted: {r:?}");
                }
            }
            // another key
            let other = usm::localized_key(proto, b"another-pass", &engine());
            assert!(
                parse_v3(
                    &bytes,
                    &V3Expect {
                        auth: Some((proto, &other)),
                        privacy: None
                    }
                )
                .unwrap_err()
                .contains("authentication")
            );
            // an unauthenticated Response is refused when we authenticated the request
            let plain = agent_reply(&reply, &usm, None, None);
            assert!(
                parse_v3(
                    &plain,
                    &V3Expect {
                        auth: Some((proto, &key)),
                        privacy: None
                    }
                )
                .unwrap_err()
                .contains("not authenticated")
            );
            // an authenticated reply to an unauthenticated request is refused
            assert!(
                parse_v3(
                    &bytes,
                    &V3Expect {
                        auth: None,
                        privacy: None
                    }
                )
                .is_err()
            );
        }
    }

    #[test]
    fn privacy_hides_the_pdu_and_a_wrong_key_is_detected() {
        let engine = engine();
        let auth_key = usm::localized_key(AuthProto::Sha1, b"authpass-1234", &engine);
        let privacy = Privacy::new(AuthProto::Sha1, b"privpass-5678", &engine);
        let request = SnmpRequest::get(&[oid("1.3.6.1.2.1.1.1.0")]);
        let salt = [0, 0, 0, 0, 0, 0, 0, 1];
        let d = encode_v3(
            1,
            2,
            &request,
            &V3Send {
                user: "u",
                engine_id: &engine,
                boots: 1,
                time: 2,
                auth: Some((AuthProto::Sha1, &auth_key)),
                privacy: Some((&privacy, salt)),
            },
        )
        .unwrap();
        // the OID and the engine ID inside the scoped PDU are not visible on the wire
        let oid_bytes = oid("1.3.6.1.2.1.1.1.0").encode().unwrap();
        assert!(!d.bytes().windows(oid_bytes.len()).any(|w| w == oid_bytes));
        // privacy without authentication is not offered
        assert!(
            encode_v3(
                1,
                2,
                &request,
                &V3Send {
                    user: "u",
                    engine_id: &engine,
                    boots: 1,
                    time: 2,
                    auth: None,
                    privacy: Some((&privacy, salt))
                }
            )
            .is_none()
        );
        // a reply round trip
        let reply = Pdu {
            report: false,
            request_id: 2,
            error_status: 0,
            error_index: 0,
            varbinds: vec![(
                oid("1.3.6.1.2.1.1.1.0"),
                Value::Octets(b"Linux lab 6.1".to_vec()),
            )],
        };
        let usm = Usm {
            engine_id: engine.clone(),
            boots: 1,
            time: 3,
            user: b"u".to_vec(),
        };
        let bytes = agent_reply(
            &reply,
            &usm,
            Some((AuthProto::Sha1, &auth_key)),
            Some((&privacy, [9; 8])),
        );
        let got = parse_v3(
            &bytes,
            &V3Expect {
                auth: Some((AuthProto::Sha1, &auth_key)),
                privacy: Some(&privacy),
            },
        )
        .unwrap();
        assert_eq!(got.pdu, reply);
        let wrong = Privacy::new(AuthProto::Sha1, b"not-the-pass", &engine);
        let e = parse_v3(
            &bytes,
            &V3Expect {
                auth: Some((AuthProto::Sha1, &auth_key)),
                privacy: Some(&wrong),
            },
        );
        assert!(e.is_err(), "{e:?}");
        // an encrypted reply to a request without privacy is refused
        assert!(
            parse_v3(
                &bytes,
                &V3Expect {
                    auth: Some((AuthProto::Sha1, &auth_key)),
                    privacy: None
                }
            )
            .is_err()
        );
    }

    /// The replies of the lab SNMP agent (`lab/simulators.py`, stdlib `hashlib`/`hmac`, its own
    /// BER) are kept as fuzz seeds. They decode here, and the SNMPv3 reply verifies against the key
    /// this crate localises from the lab passphrase: the HMAC, the key derivation and the message
    /// layout agree between two independent implementations.
    #[test]
    fn replies_of_the_independent_lab_agent_decode_and_verify() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../fuzz/corpus/snmp_response/");
        let read = |name: &str| std::fs::read(format!("{dir}{name}")).unwrap();
        let get = parse_community(&read("lab_v2c_get_response"), Version::V2c).unwrap();
        assert_eq!(get.request_id, 5);
        assert_eq!(
            get.varbinds[0],
            (
                oid("1.3.6.1.2.1.1.1.0"),
                Value::Octets(b"Lab Switch 24G (LabOS 3.1.4)".to_vec())
            )
        );
        let bulk = parse_community(&read("lab_v2c_getbulk_response"), Version::V2c).unwrap();
        // ten repetitions: the two lldpRemSysName rows, then whatever follows them in the MIB
        assert_eq!(bulk.varbinds.len(), 10);
        assert_eq!(bulk.varbinds[0].1, Value::Octets(b"dist-sw2".to_vec()));
        assert_eq!(bulk.varbinds[1].1, Value::Octets(b"lab-ap".to_vec()));
        let v1 = parse_community(&read("lab_v1_nosuchname"), Version::V1).unwrap();
        assert_eq!((v1.request_id, v1.error_status), (8, 2));

        let none = V3Expect {
            auth: None,
            privacy: None,
        };
        let report = parse_v3(&read("lab_v3_discovery_report"), &none).unwrap();
        assert!(report.pdu.report);
        assert_eq!(
            report.usm.engine_id,
            [
                0x80, 0, 0x1f, 0x88, 0x80, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81
            ]
        );
        assert_eq!(report.pdu.varbinds[0].0, oid("1.3.6.1.6.3.15.1.1.4.0"));

        let key = usm::localized_key(
            AuthProto::Sha1,
            b"lab-snmp-auth-pass",
            &report.usm.engine_id,
        );
        let reply = read("lab_v3_authnopriv_response");
        let ok = parse_v3(
            &reply,
            &V3Expect {
                auth: Some((AuthProto::Sha1, &key)),
                privacy: None,
            },
        )
        .unwrap();
        assert_eq!(ok.pdu.request_id, 2);
        assert_eq!(ok.usm.user, b"labuser");
        assert_eq!(
            ok.pdu.varbinds[0].1,
            Value::Octets(b"Lab Switch 24G (LabOS 3.1.4)".to_vec())
        );
        let wrong = usm::localized_key(AuthProto::Sha1, b"wrong passphrase", &report.usm.engine_id);
        assert!(
            parse_v3(
                &reply,
                &V3Expect {
                    auth: Some((AuthProto::Sha1, &wrong)),
                    privacy: None
                }
            )
            .is_err()
        );
        let unknown_user = parse_v3(&read("lab_v3_wrong_user_report"), &none).unwrap();
        assert_eq!(
            unknown_user.pdu.varbinds[0].0,
            oid("1.3.6.1.6.3.15.1.1.3.0")
        );
    }

    #[test]
    fn v3_truncations_never_panic() {
        let (pdu, usm) = report();
        let m = agent_reply(&pdu, &usm, None, None);
        for cut in 0..m.len() {
            assert!(
                parse_v3(
                    &m[..cut],
                    &V3Expect {
                        auth: None,
                        privacy: None
                    }
                )
                .is_err(),
                "{cut}"
            );
        }
    }
}
