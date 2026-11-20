//! One SNMP session with an agent: sends allow-listed requests through the rate gate, matches the
//! replies and, for SNMPv3, discovers the engine and keeps the time in step.
use super::{
    Credentials, NO_ANSWER, Oid, SnmpConfig, SnmpRequest, SnmpSocket, UsmUser, Value, Version,
    usm::{self, AuthProto, Privacy},
    wire::{self, Pdu, V3Expect, V3Reply, V3Send},
};
use crate::{core::Gate, sendlog::PacketKind};
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};
use tokio::time::timeout;

/// A reply to a request.
#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    pub error_status: i64,
    pub varbinds: Vec<(Oid, Value)>,
}

/// SNMPv3 state of the session: the engine and the localised keys.
struct V3State {
    user: UsmUser,
    engine_id: Vec<u8>,
    boots: u32,
    /// Engine time at `synced`.
    time: u32,
    synced: Instant,
    auth: Option<(AuthProto, Vec<u8>)>,
    privacy: Option<Privacy>,
    salt: u64,
}

pub struct Session<'a> {
    socket: SnmpSocket,
    gate: &'a Gate,
    credentials: &'a Credentials,
    /// How long to wait for one reply.
    wait: Duration,
    deadline: Instant,
    /// Datagrams left that this session may send.
    budget: usize,
    pub sent: usize,
    next_id: i32,
    v3: Option<V3State>,
}

fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    if SystemRandom::new().fill(&mut b).is_err() {
        // never reached on the platforms ring supports; a clock-derived value still varies
        return std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(1);
    }
    u32::from_be_bytes(b)
}

/// The meaning of an SNMPv3 Report PDU (RFC 3414 section 3.2 statistics, RFC 3412).
fn report_reason(pdu: &Pdu) -> String {
    let counter = Oid::parse("1.3.6.1.6.3.15.1.1").expect("constant");
    for (oid, _) in &pdu.varbinds {
        if let Some(&[n, 0]) = oid.suffix(&counter) {
            return match n {
                1 => "the agent does not support this security level for the user",
                2 => "request outside the agent's time window",
                3 => "unknown SNMPv3 user name",
                4 => "unknown engine ID",
                5 => "wrong authentication password (or digest)",
                6 => "wrong privacy password (decryption error)",
                _ => "the agent reported an error",
            }
            .to_string();
        }
    }
    "the agent reported an error".into()
}

fn is_not_in_time_window(pdu: &Pdu) -> bool {
    let counter = Oid::parse("1.3.6.1.6.3.15.1.1.2.0").expect("constant");
    pdu.varbinds.iter().any(|(o, _)| *o == counter)
}

impl<'a> Session<'a> {
    /// Connects to the agent and, for SNMPv3, discovers its engine and localises the keys.
    pub async fn open(
        ip: IpAddr,
        config: &'a SnmpConfig,
        gate: &'a Gate,
        wait: Duration,
        total: Duration,
        budget: usize,
    ) -> Result<Session<'a>, String> {
        let socket = SnmpSocket::connect(SocketAddr::new(ip, config.port))
            .await
            .map_err(|e| e.to_string())?;
        let mut s = Session {
            socket,
            gate,
            credentials: &config.credentials,
            wait,
            deadline: Instant::now() + total,
            budget,
            sent: 0,
            next_id: (random_u32() & 0x3fff_ffff) as i32,
            v3: None,
        };
        if let Credentials::V3(user) = &config.credentials {
            s.discover(user).await?;
        }
        Ok(s)
    }

    pub fn version(&self) -> Version {
        match self.credentials {
            Credentials::Community { version, .. } => *version,
            Credentials::V3(_) => Version::V3,
        }
    }
    /// The agent's engine ID (SNMPv3).
    pub fn engine_id(&self) -> Option<&[u8]> {
        self.v3.as_ref().map(|v| v.engine_id.as_slice())
    }
    pub fn level(&self) -> String {
        match self.credentials {
            Credentials::Community { version, .. } => version.name().into(),
            Credentials::V3(u) => {
                let mut text = format!("v3 {}", u.level());
                if let Some((a, _)) = &u.auth {
                    text.push_str(&format!(" {}", a.name()));
                }
                if let Some((p, _)) = &u.privacy {
                    text.push_str(&format!(" {}", p.name()));
                }
                text
            }
        }
    }
    pub fn exhausted(&self) -> bool {
        self.budget == 0 || Instant::now() >= self.deadline
    }
    fn id(&mut self) -> i32 {
        self.next_id = (self.next_id + 1) & 0x3fff_ffff;
        self.next_id
    }

    async fn discover(&mut self, user: &UsmUser) -> Result<(), String> {
        let msg_id = self.id();
        let request_id = self.id();
        let datagram = wire::encode_v3_discovery(msg_id, request_id);
        let reply = self
            .exchange_raw(&datagram, |bytes| {
                wire::parse_v3(
                    bytes,
                    &V3Expect {
                        auth: None,
                        privacy: None,
                    },
                )
                .ok()
                .filter(|r| r.pdu.report || r.pdu.request_id == i64::from(request_id))
            })
            .await?;
        if reply.usm.engine_id.is_empty() {
            return Err("the agent did not report an SNMPv3 engine ID".into());
        }
        let engine = reply.usm.engine_id.clone();
        let auth = user
            .auth
            .as_ref()
            .map(|(proto, pass)| (*proto, usm::localized_key(*proto, pass.as_bytes(), &engine)));
        let privacy = match (&user.auth, &user.privacy) {
            (Some((proto, _)), Some((priv_proto, pass))) => {
                Some(Privacy::new(*proto, *priv_proto, pass.as_bytes(), &engine))
            }
            _ => None,
        };
        self.v3 = Some(V3State {
            user: user.clone(),
            engine_id: engine,
            boots: reply.usm.boots,
            time: reply.usm.time,
            synced: Instant::now(),
            auth,
            privacy,
            salt: u64::from(random_u32()) << 32 | u64::from(random_u32()),
        });
        Ok(())
    }

    /// Sends one datagram (a token from the gate each time, retransmissions included) and
    /// returns the first reply that `accept` takes. Two attempts.
    async fn exchange_raw<T>(
        &mut self,
        datagram: &super::Datagram,
        accept: impl Fn(&[u8]) -> Option<T>,
    ) -> Result<T, String> {
        for _ in 0..2 {
            if self.exhausted() {
                return Err("SNMP request limit or time budget reached".into());
            }
            self.budget -= 1;
            self.sent += 1;
            self.gate
                .wait_for(PacketKind::SnmpRequest, datagram.label())
                .await;
            self.socket
                .send(datagram)
                .await
                .map_err(|e| e.to_string())?;
            let attempt_end = Instant::now() + self.wait;
            let mut buf = vec![0u8; wire::MAX_MESSAGE + 1];
            loop {
                let left = attempt_end.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                match timeout(left, self.socket.recv(&mut buf)).await {
                    Ok(Ok(n)) => {
                        if let Some(v) = accept(&buf[..n]) {
                            return Ok(v);
                        }
                    }
                    // ICMP port unreachable (a reset on Windows): nothing listens
                    Ok(Err(e))
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionRefused
                        ) =>
                    {
                        return Err(NO_ANSWER.into());
                    }
                    Ok(Err(e)) => return Err(e.to_string()),
                    Err(_) => break,
                }
            }
        }
        Err(NO_ANSWER.into())
    }

    /// One request/response exchange. `Err` is a transport or security failure; an SNMP error
    /// status is in the [`Response`].
    pub async fn request(&mut self, request: &SnmpRequest) -> Result<Response, String> {
        let request_id = self.id();
        match self.credentials {
            Credentials::Community { version, community } => {
                let datagram = wire::encode_community(*version, community, request_id, request)
                    .ok_or("SNMPv1 has no GetBulk request")?;
                let version = *version;
                let pdu = self
                    .exchange_raw(&datagram, |bytes| {
                        wire::parse_community(bytes, version)
                            .ok()
                            .filter(|p| p.request_id == i64::from(request_id))
                    })
                    .await?;
                Ok(Response {
                    error_status: pdu.error_status,
                    varbinds: pdu.varbinds,
                })
            }
            Credentials::V3(_) => self.request_v3(request, request_id, true).await,
        }
    }

    async fn request_v3(
        &mut self,
        request: &SnmpRequest,
        request_id: i32,
        may_resync: bool,
    ) -> Result<Response, String> {
        let msg_id = self.id();
        let (datagram, auth, privacy, engine_id) = {
            let st = self.v3.as_mut().ok_or("SNMPv3 session is not open")?;
            st.salt = st.salt.wrapping_add(1);
            let elapsed = u32::try_from(st.synced.elapsed().as_secs()).unwrap_or(0);
            let time = st.time.saturating_add(elapsed);
            let datagram = wire::encode_v3(
                msg_id,
                request_id,
                request,
                &V3Send {
                    user: &st.user.name,
                    engine_id: &st.engine_id,
                    boots: st.boots,
                    time,
                    auth: st.auth.as_ref().map(|(p, k)| (*p, k.as_slice())),
                    privacy: st.privacy.as_ref().map(|p| (p, p.salt(st.boots, st.salt))),
                },
            )
            .ok_or("SNMPv3 privacy needs authentication")?;
            (
                datagram,
                st.auth.clone(),
                st.privacy.clone(),
                st.engine_id.clone(),
            )
        };
        let reply: V3Reply = self
            .exchange_raw(&datagram, |bytes| {
                let expect = V3Expect {
                    auth: auth.as_ref().map(|(p, k)| (*p, k.as_slice())),
                    privacy: privacy.as_ref(),
                };
                match wire::parse_v3(bytes, &expect) {
                    Ok(r) if r.usm.engine_id == engine_id || r.pdu.report => {
                        (r.pdu.report || r.pdu.request_id == i64::from(request_id)).then_some(r)
                    }
                    _ => None,
                }
            })
            .await?;
        if reply.pdu.report {
            // The agent's clock moved on (or its boots counter): adopt it once and retry.
            if may_resync && is_not_in_time_window(&reply.pdu) {
                if let Some(st) = self.v3.as_mut() {
                    st.boots = reply.usm.boots;
                    st.time = reply.usm.time;
                    st.synced = Instant::now();
                }
                let id = self.id();
                return Box::pin(self.request_v3(request, id, false)).await;
            }
            return Err(report_reason(&reply.pdu));
        }
        Ok(Response {
            error_status: reply.pdu.error_status,
            varbinds: reply.pdu.varbinds,
        })
    }
}
