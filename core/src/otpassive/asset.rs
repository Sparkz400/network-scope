// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Asset inventory: merges the observed OT endpoints into one record per device.
use crate::{devices, oui, passive::Observation};
use serde::Serialize;
use std::{collections::BTreeSet, net::IpAddr};

#[derive(Debug, Clone, Serialize, Default)]
pub struct Asset {
    pub asset_id: String,
    pub ips: Vec<IpAddr>,
    pub mac: String,
    pub vendor: String,
    pub name: String,
    pub product: String,
    pub firmware: String,
    pub serial: String,
    pub protocols: Vec<String>,
    pub roles: Vec<String>,
    pub control_traffic: Vec<String>,
    pub first_seen: i64,
    pub last_seen: i64,
    pub packets: u64,
}

pub fn assets(observations: &[Observation]) -> Vec<Asset> {
    let mut out = vec![];
    for d in devices::merge(&[], observations) {
        let mut a = Asset {
            asset_id: d.id.clone(),
            ips: d.ips.clone(),
            mac: d.mac.clone(),
            vendor: d.vendor.clone(),
            name: d.hostnames.first().cloned().unwrap_or_default(),
            ..Default::default()
        };
        let mut seen = false;
        let mut control: BTreeSet<String> = BTreeSet::new();
        for (protocol, f) in &d.observations {
            let ot = protocol.ends_with("(observed)") || protocol == "Profinet DCP";
            if !ot {
                continue;
            }
            seen = true;
            let proto = protocol.trim_end_matches(" (observed)");
            let (base, role) = proto
                .rsplit_once(' ')
                .filter(|(_, r)| matches!(*r, "server" | "client"))
                .map_or((proto, ""), |(b, r)| (b, r));
            if !a.protocols.iter().any(|p| p == base) {
                a.protocols.push(base.to_string());
            }
            if !role.is_empty() && !a.roles.iter().any(|r| r == role) {
                a.roles.push(role.to_string());
            }
            for (k, v) in f {
                match k.as_str() {
                    "vendor" if a.vendor.is_empty() => a.vendor = v.clone(),
                    "name" if a.name.is_empty() => a.name = v.clone(),
                    "firmware" => a.firmware = v.clone(),
                    // controller model of FINS, MELSEC and MMS (EtherNet/IP uses `name` below)
                    "model" if a.product.is_empty() => a.product = v.clone(),
                    "serial" => a.serial = v.clone(),
                    "vendor_id" if a.vendor.is_empty() => {
                        a.vendor = if base == "EtherNet/IP" {
                            v.parse()
                                .ok()
                                .and_then(oui::cip_vendor)
                                .map_or(format!("CIP vendor ID {v}"), str::to_string)
                        } else {
                            format!("{base} vendor ID {v}")
                        };
                    }
                    "control_traffic" => {
                        for item in v.split(", ") {
                            control.insert(format!("{base}: {item}"));
                        }
                    }
                    "first_seen" => {
                        let t: i64 = v.parse().unwrap_or(0);
                        if a.first_seen == 0 || (t != 0 && t < a.first_seen) {
                            a.first_seen = t;
                        }
                    }
                    "last_seen" => a.last_seen = a.last_seen.max(v.parse().unwrap_or(0)),
                    "packets" => a.packets += v.parse().unwrap_or(0),
                    _ => {}
                }
            }
            if let Some(p) = f.get("name").filter(|_| base == "EtherNet/IP") {
                a.product = p.clone();
            }
        }
        if seen {
            a.control_traffic = control.into_iter().collect();
            out.push(a);
        }
    }
    out
}

pub fn assets_csv(assets: &[Asset]) -> String {
    let mut out = String::from(
        "asset_id,ip,mac,vendor,name,product,firmware,serial,protocols,roles,control_traffic,first_seen,last_seen,packets\r\n",
    );
    for a in assets {
        let cells = [
            a.asset_id.clone(),
            a.ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" "),
            a.mac.clone(),
            a.vendor.clone(),
            a.name.clone(),
            a.product.clone(),
            a.firmware.clone(),
            a.serial.clone(),
            a.protocols.join("; "),
            a.roles.join("; "),
            a.control_traffic.join("; "),
            a.first_seen.to_string(),
            a.last_seen.to_string(),
            a.packets.to_string(),
        ];
        out.push_str(
            &cells
                .iter()
                .map(|c| crate::scan::csv_cell(c))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push_str("\r\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otpassive::Tracker;
    use crate::otpassive::testutil::{HMI, PLC, cip_identity, frame, s7};

    #[test]
    fn assets_merge_protocols_vendor_and_mac() {
        let mut t = Tracker::new();
        // ARP gives the PLC's MAC; its traffic then joins that record.
        let mut arp = vec![0u8; 42];
        arp[12..14].copy_from_slice(&[8, 6]);
        arp[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, 2]);
        arp[22..28].copy_from_slice(&[0x00, 0x00, 0xbc, 1, 2, 3]);
        arp[28..32].copy_from_slice(&PLC);
        t.feed(&arp, 5);
        t.feed(&frame(PLC, HMI, false, 44818, 2222, &cip_identity()), 10);
        t.feed(
            &frame(
                HMI,
                PLC,
                true,
                50000,
                502,
                &[0, 2, 0, 0, 0, 6, 1, 16, 0, 5, 0, 9],
            ),
            11,
        );
        t.feed(&frame(HMI, PLC, true, 50000, 102, &s7(0x28, 1)), 12);
        let a = assets(&t.observations());
        let plc = a
            .iter()
            .find(|a| a.ips.contains(&"10.0.0.10".parse().unwrap()))
            .unwrap();
        assert_eq!(plc.mac, "00:00:BC:01:02:03");
        assert!(plc.vendor.contains("Rockwell"), "{plc:?}");
        assert_eq!(plc.protocols, ["EtherNet/IP", "Modbus/TCP", "S7comm"]);
        assert_eq!(plc.roles, ["server"]);
        assert_eq!(plc.firmware, "20.11");
        assert_eq!(plc.product, "1756-L81E");
        assert_eq!(
            plc.control_traffic,
            [
                "Modbus/TCP: Write Multiple Registers x1",
                "S7comm: PLC Control x1"
            ]
        );
        assert_eq!((plc.first_seen, plc.last_seen), (10, 12));
        let hmi = a
            .iter()
            .find(|a| a.ips.contains(&"10.0.0.50".parse().unwrap()))
            .unwrap();
        assert_eq!(hmi.roles, ["client"]);
        assert!(hmi.control_traffic.iter().any(|c| c.contains("Write")));
        let csv = assets_csv(&a);
        assert!(csv.starts_with("asset_id,ip,mac,vendor,"));
        assert!(csv.contains("00:00:BC:01:02:03"));
        assert!(assets(&[]).is_empty());
    }
}
