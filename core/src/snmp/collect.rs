//! What a scan reads over SNMP: the system group, `ifTable`, `ipAddrTable` and the LLDP
//! remote-systems table, within hard limits, and how that becomes host identity.
use super::{
    Oid, SnmpConfig, SnmpRequest, Value, Version,
    client::{Response, Session},
};
use crate::{core::Gate, scan::Settings};
use std::{collections::BTreeMap, net::IpAddr, time::Duration};

/// Datagrams per host. Safe Mode allows fewer.
pub const MAX_REQUESTS: usize = 240;
pub const SAFE_MAX_REQUESTS: usize = 100;
/// Seconds per host (waiting for the rate gate included).
pub const MAX_SECONDS: u64 = 25;
pub const SAFE_MAX_SECONDS: u64 = 40;
/// Rows kept per table.
const MAX_INTERFACES: usize = 128;
const MAX_ADDRESSES: usize = 64;
const MAX_NEIGHBORS: usize = 64;
/// `max-repetitions` of the GetBulk requests.
const BULK: u8 = 20;
const BULK_SAFE: u8 = 10;
/// Longest text kept from a device.
const MAX_TEXT: usize = 255;

fn oid(text: &str) -> Oid {
    Oid::parse(text).expect("constant OID")
}

/// The system group (RFC 3418), `ifEntry` columns (RFC 2863), `ipAddrEntry` columns (RFC 4293
/// legacy table) and the LLDP-MIB `lldpRemEntry` columns (IEEE 802.1AB) that are read.
mod mib {
    pub const SYSTEM: &str = "1.3.6.1.2.1.1";
    pub const IF_DESCR: &str = "1.3.6.1.2.1.2.2.1.2";
    pub const IF_PHYS_ADDRESS: &str = "1.3.6.1.2.1.2.2.1.6";
    pub const IF_OPER_STATUS: &str = "1.3.6.1.2.1.2.2.1.8";
    pub const IP_AD_ENT_IF_INDEX: &str = "1.3.6.1.2.1.4.20.1.2";
    pub const IP_AD_ENT_NET_MASK: &str = "1.3.6.1.2.1.4.20.1.3";
    pub const LLDP_REM_CHASSIS_ID_SUBTYPE: &str = "1.0.8802.1.1.2.1.4.1.1.4";
    pub const LLDP_REM_CHASSIS_ID: &str = "1.0.8802.1.1.2.1.4.1.1.5";
    pub const LLDP_REM_PORT_ID_SUBTYPE: &str = "1.0.8802.1.1.2.1.4.1.1.6";
    pub const LLDP_REM_PORT_ID: &str = "1.0.8802.1.1.2.1.4.1.1.7";
    pub const LLDP_REM_PORT_DESC: &str = "1.0.8802.1.1.2.1.4.1.1.8";
    pub const LLDP_REM_SYS_NAME: &str = "1.0.8802.1.1.2.1.4.1.1.9";
    /// lldpLocPortDesc: the name of each local port, by lldpLocPortNum (which need not be the
    /// ifIndex).
    pub const LLDP_LOC_PORT_DESC: &str = "1.0.8802.1.1.2.1.3.7.1.4";
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct System {
    pub descr: String,
    pub object_id: String,
    pub name: String,
    pub location: String,
    /// Hundredths of a second since the agent started.
    pub uptime_ticks: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    pub index: u32,
    pub descr: String,
    /// `AA:BB:CC:DD:EE:FF`, empty when the interface has none.
    pub mac: String,
    /// `up`, `down`, `testing`, ... (`ifOperStatus`).
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    pub ip: IpAddr,
    pub if_index: u32,
    pub mask: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LldpNeighbor {
    /// `lldpRemLocalPortNum`: the local port the neighbour was heard on.
    pub local_port: u32,
    pub sys_name: String,
    pub port_id: String,
    pub chassis_id: String,
    pub port_desc: String,
    /// `lldpLocPortDesc` of the local port, when the agent has the local port table.
    pub local_port_desc: String,
}

#[derive(Clone, Debug, Default)]
pub struct Collected {
    pub version: String,
    pub engine_id: Option<Vec<u8>>,
    pub system: System,
    pub interfaces: Vec<Interface>,
    pub addresses: Vec<Address>,
    pub lldp: Vec<LldpNeighbor>,
    /// Limits that were reached and tables that could not be read.
    pub notes: Vec<String>,
    /// Datagrams sent (retransmissions included).
    pub requests: usize,
}

/// SNMP is on for this scan: credentials were given. Safe Mode does not switch it off (the
/// credentials are the opt-in and every request is a read), it only tightens the limits.
pub fn enabled(s: &Settings) -> bool {
    s.snmp.is_some()
}

/// Text from a device: control characters removed, bounded.
fn clean(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(MAX_TEXT)
        .collect()
}

fn mac_text(b: &[u8]) -> String {
    if b.is_empty() || b.len() > 8 {
        return String::new();
    }
    b.iter()
        .map(|v| format!("{v:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// LLDP chassis and port ids: a MAC for subtype 4 (chassis) / 3 (port), text for the readable
/// subtypes, hex for the rest.
fn lldp_id(subtype: Option<i64>, mac_subtype: i64, b: &[u8]) -> String {
    if subtype == Some(mac_subtype) && b.len() == 6 {
        return mac_text(b);
    }
    if !b.is_empty() && b.iter().all(|c| (0x20..0x7f).contains(c)) {
        return clean(b);
    }
    if subtype.is_none() && b.len() == 6 {
        return mac_text(b);
    }
    b.iter().take(32).map(|v| format!("{v:02x}")).collect()
}

fn oper_status(v: i64) -> &'static str {
    match v {
        1 => "up",
        2 => "down",
        3 => "testing",
        4 => "unknown",
        5 => "dormant",
        6 => "notPresent",
        7 => "lowerLayerDown",
        _ => "?",
    }
}

struct Limits {
    bulk: u8,
    safe: bool,
}

/// Walks one column below `base`: GetBulk (v2c, v3) or GetNext (v1), at most `max_rows` rows,
/// stopping at the end of the subtree, the end of the MIB, a non-increasing OID, an error or the
/// session's budget.
async fn walk(
    session: &mut Session<'_>,
    base: &Oid,
    max_rows: usize,
    limits: &Limits,
    notes: &mut Vec<String>,
) -> Vec<(Oid, Value)> {
    let mut rows: Vec<(Oid, Value)> = vec![];
    let mut cursor = base.clone();
    loop {
        let request = if session.version() == Version::V1 {
            SnmpRequest::get_next(&[cursor.clone()])
        } else {
            match SnmpRequest::get_bulk(limits.bulk, &[cursor.clone()]) {
                Some(r) => r,
                None => break,
            }
        };
        let Response {
            error_status,
            varbinds,
        } = match session.request(&request).await {
            Ok(r) => r,
            Err(e) => {
                notes.push(format!("{base}: {e}"));
                break;
            }
        };
        // v1 reports the end of the MIB as noSuchName (2)
        if error_status != 0 {
            if error_status != 2 {
                notes.push(format!("{base}: SNMP error status {error_status}"));
            }
            break;
        }
        let mut finished = varbinds.is_empty();
        for (name, value) in varbinds {
            if !name.starts_with(base) || value == Value::EndOfMibView || name <= cursor {
                finished = true;
                break;
            }
            cursor = name.clone();
            rows.push((name, value));
            if rows.len() >= max_rows {
                notes.push(format!("{base}: stopped after {max_rows} rows"));
                return rows;
            }
        }
        if finished {
            break;
        }
    }
    rows
}

/// Rows of a column as `(row index, value)` where the index is the single sub-identifier after
/// the column.
fn by_index<'a>(rows: &'a [(Oid, Value)], base: &Oid) -> BTreeMap<u32, &'a Value> {
    rows.iter()
        .filter_map(|(o, v)| match o.suffix(base)? {
            [i] => Some((*i, v)),
            _ => None,
        })
        .collect()
}

/// Reads one agent. `Err` only when it did not answer at all (or the credentials were refused);
/// a table that could not be read, or a limit that was reached, is a note on the result.
pub async fn collect(
    ip: IpAddr,
    config: &SnmpConfig,
    safe: bool,
    port_timeout_ms: u32,
    gate: &Gate,
) -> Result<Collected, String> {
    let (budget, seconds, bulk) = if safe {
        (SAFE_MAX_REQUESTS, SAFE_MAX_SECONDS, BULK_SAFE)
    } else {
        (MAX_REQUESTS, MAX_SECONDS, BULK)
    };
    let wait = Duration::from_millis(u64::from(port_timeout_ms.clamp(300, 3000)));
    let mut session =
        Session::open(ip, config, gate, wait, Duration::from_secs(seconds), budget).await?;
    let limits = Limits { bulk, safe };
    let mut out = Collected {
        version: session.level(),
        engine_id: session.engine_id().map(<[u8]>::to_vec),
        ..Default::default()
    };
    let mut notes = vec![];

    // System group: one GetRequest for the five objects decides whether anything answers (an
    // `Err` here is "no reply" or a refused user). An agent that lacks one of them (SNMPv1
    // answers noSuchName for the whole request) is read with a walk of the group instead.
    let group = oid(mib::SYSTEM);
    let wanted: Vec<Oid> = [1, 2, 3, 5, 6]
        .iter()
        .map(|n| group.child(&[*n, 0]))
        .collect();
    let first = session.request(&SnmpRequest::get(&wanted)).await?;
    let system_rows = if first.error_status == 0 {
        first.varbinds
    } else {
        walk(&mut session, &group, 8, &limits, &mut notes).await
    };
    if system_rows.iter().all(|(_, v)| v.is_exception()) {
        return Err("the agent answered but has no system group".into());
    }
    for (o, v) in &system_rows {
        match (o.suffix(&group), v) {
            (Some([1, 0]), Value::Octets(b)) => out.system.descr = clean(b),
            (Some([2, 0]), Value::Oid(id)) => out.system.object_id = id.to_string(),
            (Some([3, 0]), Value::TimeTicks(t)) => out.system.uptime_ticks = Some(*t),
            (Some([5, 0]), Value::Octets(b)) => out.system.name = clean(b),
            (Some([6, 0]), Value::Octets(b)) => out.system.location = clean(b),
            _ => {}
        }
    }

    // LLDP neighbours first: they are the most useful thing a switch can say. Nothing at all in
    // the chassis-id column means no neighbour table; then the other columns are not asked.
    if !session.exhausted() {
        let chassis = walk(
            &mut session,
            &oid(mib::LLDP_REM_CHASSIS_ID),
            MAX_NEIGHBORS,
            &limits,
            &mut notes,
        )
        .await;
        if !chassis.is_empty() {
            let mut columns: BTreeMap<&str, Vec<(Oid, Value)>> = BTreeMap::new();
            for name in [
                mib::LLDP_REM_CHASSIS_ID_SUBTYPE,
                mib::LLDP_REM_PORT_ID_SUBTYPE,
                mib::LLDP_REM_PORT_ID,
                mib::LLDP_REM_PORT_DESC,
                mib::LLDP_REM_SYS_NAME,
            ] {
                if session.exhausted() {
                    break;
                }
                columns.insert(
                    name,
                    walk(&mut session, &oid(name), MAX_NEIGHBORS, &limits, &mut notes).await,
                );
            }
            let loc_base = oid(mib::LLDP_LOC_PORT_DESC);
            let loc = if session.exhausted() {
                vec![]
            } else {
                walk(&mut session, &loc_base, MAX_INTERFACES, &limits, &mut notes).await
            };
            let loc = by_index(&loc, &loc_base);
            let chassis_base = oid(mib::LLDP_REM_CHASSIS_ID);
            let get = |name: &str, row: &[u32]| -> Option<Value> {
                let base = oid(name);
                columns
                    .get(name)?
                    .iter()
                    .find(|(o, _)| o.suffix(&base) == Some(row))
                    .map(|(_, v)| v.clone())
            };
            for (o, v) in &chassis {
                // index: lldpRemTimeMark, lldpRemLocalPortNum, lldpRemIndex
                let Some(row @ [_, local, _]) = o.suffix(&chassis_base) else {
                    continue;
                };
                let text = |name| {
                    get(name, row)
                        .and_then(|v| v.as_octets().map(clean))
                        .unwrap_or_default()
                };
                let subtype = |name| get(name, row).and_then(|v| v.as_int());
                let raw = |name| {
                    get(name, row)
                        .and_then(|v| v.as_octets().map(<[u8]>::to_vec))
                        .unwrap_or_default()
                };
                out.lldp.push(LldpNeighbor {
                    local_port: *local,
                    sys_name: text(mib::LLDP_REM_SYS_NAME),
                    port_id: lldp_id(
                        subtype(mib::LLDP_REM_PORT_ID_SUBTYPE),
                        3,
                        &raw(mib::LLDP_REM_PORT_ID),
                    ),
                    chassis_id: lldp_id(
                        subtype(mib::LLDP_REM_CHASSIS_ID_SUBTYPE),
                        4,
                        v.as_octets().unwrap_or(&[]),
                    ),
                    port_desc: text(mib::LLDP_REM_PORT_DESC),
                    local_port_desc: loc
                        .get(local)
                        .and_then(|v| v.as_octets().map(clean))
                        .unwrap_or_default(),
                });
            }
        }
    }

    // Interfaces.
    if !session.exhausted() {
        let descr_base = oid(mib::IF_DESCR);
        let descr = walk(
            &mut session,
            &descr_base,
            MAX_INTERFACES,
            &limits,
            &mut notes,
        )
        .await;
        let (mac_base, status_base) = (oid(mib::IF_PHYS_ADDRESS), oid(mib::IF_OPER_STATUS));
        let macs = if session.exhausted() {
            vec![]
        } else {
            walk(&mut session, &mac_base, MAX_INTERFACES, &limits, &mut notes).await
        };
        let status = if session.exhausted() {
            vec![]
        } else {
            walk(
                &mut session,
                &status_base,
                MAX_INTERFACES,
                &limits,
                &mut notes,
            )
            .await
        };
        let (macs, status) = (by_index(&macs, &mac_base), by_index(&status, &status_base));
        for (index, v) in by_index(&descr, &descr_base) {
            out.interfaces.push(Interface {
                index,
                descr: v.as_octets().map(clean).unwrap_or_default(),
                mac: macs
                    .get(&index)
                    .and_then(|v| v.as_octets())
                    .map(mac_text)
                    .unwrap_or_default(),
                status: status
                    .get(&index)
                    .and_then(|v| v.as_int())
                    .map(|s| oper_status(s).to_string())
                    .unwrap_or_default(),
            });
        }
    }

    // IPv4 addresses.
    if !session.exhausted() {
        let (index_base, mask_base) = (oid(mib::IP_AD_ENT_IF_INDEX), oid(mib::IP_AD_ENT_NET_MASK));
        let indexes = walk(
            &mut session,
            &index_base,
            MAX_ADDRESSES,
            &limits,
            &mut notes,
        )
        .await;
        let masks = if indexes.is_empty() || session.exhausted() {
            vec![]
        } else {
            walk(&mut session, &mask_base, MAX_ADDRESSES, &limits, &mut notes).await
        };
        for (o, v) in &indexes {
            let (Some(&[a, b, c, d]), Some(index)) = (o.suffix(&index_base), v.as_int()) else {
                continue;
            };
            let Ok(octets) = [a, b, c, d]
                .map(u8::try_from)
                .into_iter()
                .collect::<Result<Vec<_>, _>>()
            else {
                continue;
            };
            let mask = masks
                .iter()
                .find(|(m, _)| m.suffix(&mask_base) == Some(&[a, b, c, d]))
                .and_then(|(_, v)| match v {
                    Value::IpAddress(m) => Some(IpAddr::from(*m).to_string()),
                    _ => None,
                })
                .unwrap_or_default();
            out.addresses.push(Address {
                ip: IpAddr::from([octets[0], octets[1], octets[2], octets[3]]),
                if_index: u32::try_from(index).unwrap_or(0),
                mask,
            });
        }
    }
    if session.exhausted() {
        notes.push(if limits.safe {
            "Safe Mode request or time limit reached; the tables may be incomplete".into()
        } else {
            "request or time limit reached; the tables may be incomplete".into()
        });
    }
    out.notes = notes;
    out.requests = session.sent;
    Ok(out)
}

impl Collected {
    /// The host identity keys (`snmp.*`): see `docs/src/snmp.md`.
    pub fn identity(&self) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("snmp.version".to_string(), self.version.clone());
        let mut put = |k: &str, v: &str| {
            if !v.is_empty() {
                m.insert(k.to_string(), v.to_string());
            }
        };
        put("snmp.sysdescr", &self.system.descr);
        put("snmp.sysobjectid", &self.system.object_id);
        put("snmp.sysname", &self.system.name);
        put("snmp.location", &self.system.location);
        // sysUpTime is not stored: it differs in every scan and would show up in every diff.
        if let Some(e) = &self.engine_id {
            put(
                "snmp.engine_id",
                &e.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            );
        }
        for i in &self.interfaces {
            let mut parts = vec![i.descr.clone()];
            if !i.mac.is_empty() {
                parts.push(i.mac.clone());
            }
            if !i.status.is_empty() {
                parts.push(i.status.clone());
            }
            put(&format!("snmp.if.{}", i.index), &parts.join("; "));
        }
        for a in &self.addresses {
            put(
                &format!("snmp.ip.{}", a.ip),
                &format!(
                    "ifIndex {}{}",
                    a.if_index,
                    if a.mask.is_empty() {
                        String::new()
                    } else {
                        format!(", mask {}", a.mask)
                    }
                ),
            );
        }
        for (n, l) in self.lldp.iter().enumerate() {
            put(
                &format!("snmp.lldp.{n}.local_port"),
                &l.local_port.to_string(),
            );
            put(&format!("snmp.lldp.{n}.sys_name"), &l.sys_name);
            put(&format!("snmp.lldp.{n}.port_id"), &l.port_id);
            put(&format!("snmp.lldp.{n}.chassis_id"), &l.chassis_id);
            put(&format!("snmp.lldp.{n}.port_desc"), &l.port_desc);
            put(
                &format!("snmp.lldp.{n}.local_port_desc"),
                &l.local_port_desc,
            );
        }
        m
    }
}

#[cfg(test)]
#[path = "collect_tests.rs"]
mod tests;
