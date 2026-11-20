//! A small SNMP agent for the tests: a loopback UDP server with a fixed MIB that answers
//! v1/v2c requests (community) and v3 requests (USM discovery, HMAC-MD5/SHA, DES-CBC and
//! AES-CFB). Test code only.
use super::{
    SnmpPdu,
    ber::{self, INTEGER, OCTET_STRING, Oid, SEQUENCE, Value, expect, int, octets, tlv},
    usm::{self, AuthProto, PrivProto, Privacy},
    wire::{Pdu, RESPONSE, Usm},
};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tokio::net::UdpSocket;

pub fn oid(s: &str) -> Oid {
    Oid::parse(s).unwrap()
}

/// A switch with three ports, two addresses and two LLDP neighbours.
pub fn lab_mib() -> BTreeMap<Oid, Value> {
    let mut m = BTreeMap::new();
    let mut put = |o: &str, v: Value| {
        m.insert(oid(o), v);
    };
    let text = |s: &str| Value::Octets(s.as_bytes().to_vec());
    put(
        "1.3.6.1.2.1.1.1.0",
        text("Lab Switch 24G, firmware 3.1.4\r\n(c) Lab"),
    );
    put("1.3.6.1.2.1.1.2.0", Value::Oid(oid("1.3.6.1.4.1.9.1.1208")));
    put("1.3.6.1.2.1.1.3.0", Value::TimeTicks(8_640_000 + 4_523_000));
    put("1.3.6.1.2.1.1.4.0", text("admin@lab.example"));
    put("1.3.6.1.2.1.1.5.0", text("core-sw1"));
    put("1.3.6.1.2.1.1.6.0", text("Rack 4"));
    put("1.3.6.1.2.1.1.7.0", Value::Integer(72));
    for (i, (name, mac, status)) in [
        (
            "GigabitEthernet1/0/1",
            [0x00u8, 0x1b, 0x21, 0x0a, 0x0b, 0x01],
            1,
        ),
        (
            "GigabitEthernet1/0/2",
            [0x00, 0x1b, 0x21, 0x0a, 0x0b, 0x02],
            2,
        ),
        ("Vlan1", [0x00, 0x1b, 0x21, 0x0a, 0x0b, 0xff], 1),
    ]
    .into_iter()
    .enumerate()
    {
        let n = i + 1;
        put(
            &format!("1.3.6.1.2.1.2.2.1.1.{n}"),
            Value::Integer(n as i64),
        );
        put(&format!("1.3.6.1.2.1.2.2.1.2.{n}"), text(name));
        put(
            &format!("1.3.6.1.2.1.2.2.1.6.{n}"),
            Value::Octets(mac.to_vec()),
        );
        put(&format!("1.3.6.1.2.1.2.2.1.8.{n}"), Value::Integer(status));
        // ifXTable ifName
        let short = ["Gi1/0/1", "Gi1/0/2", "Vl1"][i];
        put(&format!("1.3.6.1.2.1.31.1.1.1.1.{n}"), text(short));
    }
    put(
        "1.3.6.1.2.1.4.20.1.1.10.0.0.2",
        Value::IpAddress([10, 0, 0, 2]),
    );
    put("1.3.6.1.2.1.4.20.1.2.10.0.0.2", Value::Integer(3));
    put(
        "1.3.6.1.2.1.4.20.1.3.10.0.0.2",
        Value::IpAddress([255, 255, 255, 0]),
    );
    put(
        "1.3.6.1.2.1.4.20.1.1.192.168.1.1",
        Value::IpAddress([192, 168, 1, 1]),
    );
    put("1.3.6.1.2.1.4.20.1.2.192.168.1.1", Value::Integer(3));
    put(
        "1.3.6.1.2.1.4.20.1.3.192.168.1.1",
        Value::IpAddress([255, 255, 255, 128]),
    );
    // ipAddressTable (RFC 4293): ipAddressIfIndex.<type>.<length>.<address octets>; the IPv4
    // address of the legacy table again, a global IPv6 address, and a zoned link-local one
    put("1.3.6.1.2.1.4.34.1.3.1.4.10.0.0.2", Value::Integer(3));
    put(
        "1.3.6.1.2.1.4.34.1.3.2.16.32.1.13.184.0.0.0.0.0.0.0.0.0.0.0.2",
        Value::Integer(3),
    );
    put(
        "1.3.6.1.2.1.4.34.1.3.4.20.254.128.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.0.3",
        Value::Integer(3),
    );
    // lldpLocPortTable: lldpLocPortNum 1 and 2 are the first two ports
    put(
        "1.0.8802.1.1.2.1.3.7.1.4.1",
        Value::Octets(b"GigabitEthernet1/0/1".to_vec()),
    );
    put(
        "1.0.8802.1.1.2.1.3.7.1.4.2",
        Value::Octets(b"GigabitEthernet1/0/2".to_vec()),
    );
    // lldpRemEntry rows: index = timeMark.localPort.remIndex
    for (row, local, chassis, port, sys) in [
        (
            "0.1.1",
            1,
            vec![0x00u8, 0x1b, 0x21, 0x77, 0x00, 0x01],
            "Gi0/24",
            "dist-sw2",
        ),
        (
            "0.2.1",
            2,
            vec![0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
            "eth0",
            "lab-ap",
        ),
    ] {
        let _ = local;
        put(
            &format!("1.0.8802.1.1.2.1.4.1.1.4.{row}"),
            Value::Integer(4),
        );
        put(
            &format!("1.0.8802.1.1.2.1.4.1.1.5.{row}"),
            Value::Octets(chassis),
        );
        put(
            &format!("1.0.8802.1.1.2.1.4.1.1.6.{row}"),
            Value::Integer(5),
        );
        put(&format!("1.0.8802.1.1.2.1.4.1.1.7.{row}"), text(port));
        put(
            &format!("1.0.8802.1.1.2.1.4.1.1.8.{row}"),
            text(&format!("{port} uplink")),
        );
        put(&format!("1.0.8802.1.1.2.1.4.1.1.9.{row}"), text(sys));
    }
    m
}

/// SNMPv3 side of an agent.
pub struct V3Agent {
    pub user: String,
    pub engine_id: Vec<u8>,
    pub boots: u32,
    pub time: u32,
    pub auth: Option<(AuthProto, Vec<u8>)>,
    pub privacy: Option<Privacy>,
    /// Answer the first authenticated request with notInTimeWindows and boots + 1.
    pub reject_first_as_late: AtomicBool,
}

impl V3Agent {
    pub fn new(user: &str, auth: Option<(AuthProto, &str)>, privacy: Option<&str>) -> Self {
        Self::with_privacy(user, auth, privacy.map(|p| (PrivProto::Aes128, p)))
    }
    pub fn with_privacy(
        user: &str,
        auth: Option<(AuthProto, &str)>,
        privacy: Option<(PrivProto, &str)>,
    ) -> Self {
        let engine_id = vec![
            0x80, 0, 0x1f, 0x88, 0x80, 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 1,
        ];
        Self {
            user: user.into(),
            auth: auth.map(|(p, pw)| (p, usm::localized_key(p, pw.as_bytes(), &engine_id))),
            privacy: auth
                .zip(privacy)
                .map(|((p, _), (proto, pw))| Privacy::new(p, proto, pw.as_bytes(), &engine_id)),
            engine_id,
            boots: 12,
            time: 345_678,
            reject_first_as_late: AtomicBool::new(false),
        }
    }
}

pub struct Agent {
    pub mib: BTreeMap<Oid, Value>,
    /// Accepted v1/v2c community; `None` answers nothing to those versions.
    pub community: Option<String>,
    pub v3: Option<V3Agent>,
    /// Datagrams received, and the PDU tags seen.
    pub received: Mutex<Vec<u8>>,
    pub count: AtomicUsize,
    /// Answer nothing at all.
    pub silent: AtomicBool,
}

impl Agent {
    pub fn community(community: &str) -> Self {
        Self {
            mib: lab_mib(),
            community: Some(community.into()),
            v3: None,
            received: Mutex::new(vec![]),
            count: AtomicUsize::new(0),
            silent: AtomicBool::new(false),
        }
    }
    pub fn v3(v3: V3Agent) -> Self {
        Self {
            community: None,
            v3: Some(v3),
            ..Self::community("")
        }
    }
    pub async fn spawn(self) -> (SocketAddr, Arc<Agent>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let agent = Arc::new(self);
        let a = agent.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 9000];
            loop {
                let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                    return;
                };
                a.count.fetch_add(1, Ordering::SeqCst);
                if a.silent.load(Ordering::SeqCst) {
                    continue;
                }
                if let Some(reply) = a.handle(&buf[..n]) {
                    let _ = socket.send_to(&reply, from).await;
                }
            }
        });
        (addr, agent)
    }

    fn walk(
        &self,
        pdu: u8,
        ids: &[Oid],
        non: i64,
        max: i64,
        v1: bool,
    ) -> Result<Vec<(Oid, Value)>, i64> {
        let next = |after: &Oid| {
            self.mib
                .range((
                    std::ops::Bound::Excluded(after.clone()),
                    std::ops::Bound::Unbounded,
                ))
                .next()
                .map(|(o, v)| (o.clone(), v.clone()))
        };
        let mut out = vec![];
        match pdu {
            0xA0 => {
                for id in ids {
                    match self.mib.get(id) {
                        Some(v) => out.push((id.clone(), v.clone())),
                        None if v1 => return Err(2),
                        None => out.push((id.clone(), Value::NoSuchInstance)),
                    }
                }
            }
            0xA1 => {
                for id in ids {
                    match next(id) {
                        Some(e) => out.push(e),
                        None if v1 => return Err(2),
                        None => out.push((id.clone(), Value::EndOfMibView)),
                    }
                }
            }
            _ => {
                let (fixed, repeat) = ids.split_at((non.max(0) as usize).min(ids.len()));
                for id in fixed {
                    out.push(next(id).unwrap_or((id.clone(), Value::EndOfMibView)));
                }
                let mut cursors: Vec<Oid> = repeat.to_vec();
                for _ in 0..max.clamp(0, 50) {
                    let mut any = false;
                    for c in &mut cursors {
                        match next(c) {
                            Some((o, v)) => {
                                *c = o.clone();
                                out.push((o, v));
                                any = true;
                            }
                            None => out.push((c.clone(), Value::EndOfMibView)),
                        }
                    }
                    if !any {
                        break;
                    }
                }
            }
        }
        Ok(out)
    }

    fn handle(&self, m: &[u8]) -> Option<Vec<u8>> {
        let (msg, _) = expect(m, 0, SEQUENCE)?;
        let (v, at) = expect(msg, 0, INTEGER)?;
        match ber::parse_int(v)? {
            version @ (0 | 1) => {
                let (community, at) = expect(msg, at, OCTET_STRING)?;
                if self.community.as_deref().map(str::as_bytes) != Some(community) {
                    return None; // a wrong community is silently dropped
                }
                let (tag, pdu, _) = ber::read(msg, at)?;
                self.received.lock().unwrap().push(tag);
                SnmpPdu::from_tag(tag)?;
                let (id, i) = expect(pdu, 0, INTEGER)?;
                let (a, i) = expect(pdu, i, INTEGER)?;
                let (b, i) = expect(pdu, i, INTEGER)?;
                let (list, _) = expect(pdu, i, SEQUENCE)?;
                let ids: Vec<Oid> = ber::parse_varbinds(list)?
                    .into_iter()
                    .map(|(o, _)| o)
                    .collect();
                let id = ber::parse_int(id)?;
                let (status, binds) = match self.walk(
                    tag,
                    &ids,
                    ber::parse_int(a)?,
                    ber::parse_int(b)?,
                    version == 0,
                ) {
                    Ok(b) => (0, b),
                    Err(s) => (s, ids.iter().map(|o| (o.clone(), Value::Null)).collect()),
                };
                let mut list = vec![];
                for (o, val) in &binds {
                    list.extend(tlv(SEQUENCE, &[o.encode()?, val.encode()?].concat()));
                }
                let pdu = tlv(
                    RESPONSE,
                    &[int(id), int(status), int(0), tlv(SEQUENCE, &list)].concat(),
                );
                Some(tlv(
                    SEQUENCE,
                    &[int(version), octets(community), pdu].concat(),
                ))
            }
            3 => self.handle_v3(m, msg, at),
            _ => None,
        }
    }

    fn handle_v3(&self, whole: &[u8], msg: &[u8], at: usize) -> Option<Vec<u8>> {
        let v3 = self.v3.as_ref()?;
        let (global, at) = expect(msg, at, SEQUENCE)?;
        let (msg_id, i) = expect(global, 0, INTEGER)?;
        let (_, i) = expect(global, i, INTEGER)?;
        let (flags, _) = expect(global, i, OCTET_STRING)?;
        let flags = *flags.first()?;
        let (security, at) = expect(msg, at, OCTET_STRING)?;
        let (params, _) = expect(security, 0, SEQUENCE)?;
        let (engine, i) = expect(params, 0, OCTET_STRING)?;
        let (_, i) = expect(params, i, INTEGER)?;
        let (_, i) = expect(params, i, INTEGER)?;
        let (user, i) = expect(params, i, OCTET_STRING)?;
        let (auth_params, i) = expect(params, i, OCTET_STRING)?;
        let (priv_params, _) = expect(params, i, OCTET_STRING)?;
        let msg_id = ber::parse_int(msg_id)?;
        let report = |counter: &str, boots: u32| -> Option<Vec<u8>> {
            let pdu = Pdu {
                report: true,
                request_id: 0,
                error_status: 0,
                error_index: 0,
                varbinds: vec![(oid(counter), Value::Counter32(1))],
            };
            Some(super::wire::tests::agent_reply_with_id(
                msg_id,
                &pdu,
                &Usm {
                    engine_id: v3.engine_id.clone(),
                    boots,
                    time: v3.time,
                    user: vec![],
                },
                None,
                None,
            ))
        };
        // discovery: unknown engine ID
        if engine.is_empty() {
            return report("1.3.6.1.6.3.15.1.1.4.0", v3.boots);
        }
        if engine != v3.engine_id {
            return report("1.3.6.1.6.3.15.1.1.4.0", v3.boots);
        }
        if user != v3.user.as_bytes() {
            return report("1.3.6.1.6.3.15.1.1.3.0", v3.boots);
        }
        // authentication
        if let Some((proto, key)) = &v3.auth {
            if flags & 1 == 0 {
                return report("1.3.6.1.6.3.15.1.1.1.0", v3.boots);
            }
            let offset = auth_params.as_ptr() as usize - whole.as_ptr() as usize;
            let mut zeroed = whole.to_vec();
            zeroed[offset..offset + auth_params.len()].fill(0);
            if !usm::verify(*proto, key, &zeroed, auth_params) {
                return report("1.3.6.1.6.3.15.1.1.5.0", v3.boots);
            }
        } else if flags & 1 != 0 {
            return report("1.3.6.1.6.3.15.1.1.1.0", v3.boots);
        }
        if v3.reject_first_as_late.swap(false, Ordering::SeqCst) {
            return report("1.3.6.1.6.3.15.1.1.2.0", v3.boots + 1);
        }
        let (tag, data, _) = ber::read(msg, at)?;
        let scoped_bytes: Vec<u8>;
        let scoped: &[u8] = if tag == OCTET_STRING {
            if flags & 2 == 0 {
                return None;
            }
            let privacy = v3.privacy.as_ref()?;
            // the boots and time are those the sender put in the security parameters
            let (_, i) = expect(params, 0, OCTET_STRING)?;
            let (b, i) = expect(params, i, INTEGER)?;
            let (t, _) = expect(params, i, INTEGER)?;
            let plain = privacy.decrypt(
                ber::parse_int(b)? as u32,
                ber::parse_int(t)? as u32,
                priv_params,
                data,
            )?;
            let Some((s, _)) = expect(&plain, 0, SEQUENCE) else {
                return report("1.3.6.1.6.3.15.1.1.6.0", v3.boots);
            };
            scoped_bytes = s.to_vec();
            &scoped_bytes
        } else {
            if flags & 2 != 0 {
                return None;
            }
            data
        };
        // a wrong privacy key decrypts to noise: whatever fails to parse is a decryption error
        let parsed = (|| {
            let (_, i) = expect(scoped, 0, OCTET_STRING)?;
            let (_, i) = expect(scoped, i, OCTET_STRING)?;
            let (rtag, pdu, _) = ber::read(scoped, i)?;
            SnmpPdu::from_tag(rtag)?;
            let (id, i) = expect(pdu, 0, INTEGER)?;
            let (a, i) = expect(pdu, i, INTEGER)?;
            let (b, i) = expect(pdu, i, INTEGER)?;
            let (list, _) = expect(pdu, i, SEQUENCE)?;
            let ids: Vec<Oid> = ber::parse_varbinds(list)?
                .into_iter()
                .map(|(o, _)| o)
                .collect();
            Some((
                rtag,
                ber::parse_int(id)?,
                ber::parse_int(a)?,
                ber::parse_int(b)?,
                ids,
            ))
        })();
        let Some((rtag, request_id, a, b, ids)) = parsed else {
            return if flags & 2 != 0 {
                report("1.3.6.1.6.3.15.1.1.6.0", v3.boots)
            } else {
                None
            };
        };
        self.received.lock().unwrap().push(rtag);
        let (status, binds) = match self.walk(rtag, &ids, a, b, false) {
            Ok(b) => (0, b),
            Err(s) => (s, vec![]),
        };
        let reply = Pdu {
            report: false,
            request_id,
            error_status: status,
            error_index: 0,
            varbinds: binds,
        };
        let usm = Usm {
            engine_id: v3.engine_id.clone(),
            boots: v3.boots,
            time: v3.time,
            user: v3.user.clone().into_bytes(),
        };
        Some(super::wire::tests::agent_reply_with_id(
            msg_id,
            &reply,
            &usm,
            v3.auth.as_ref().map(|(p, k)| (*p, k.as_slice())),
            v3.privacy.as_ref().map(|p| (p, [0, 0, 0, 0, 0, 0, 0, 9])),
        ))
    }
}
