// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! LLDP-MED (ANSI/TIA-1057): LLDP organisationally specific TLVs (type 127) with the TIA OUI
//! `00-12-BB`. Read here: capabilities and device class, network policies, and the inventory
//! strings. Location and extended power TLVs are not read. Passive decoding only; nothing here
//! transmits.
use super::{
    be16,
    hints::{self, Hint},
    text,
};
use std::collections::BTreeMap;

/// The TIA OUI of LLDP-MED TLVs.
pub(super) const OUI: [u8; 3] = [0x00, 0x12, 0xbb];

const CAPABILITIES: [(u16, &str); 6] = [
    (0x01, "capabilities"),
    (0x02, "network_policy"),
    (0x04, "location"),
    (0x08, "power_pse"),
    (0x10, "power_pd"),
    (0x20, "inventory"),
];

/// Network policy application types (TIA-1057 10.2.3.8). Each has its own field, so the key set
/// stays closed.
const APPLICATIONS: [&str; 8] = [
    "voice",
    "voice_signaling",
    "guest_voice",
    "guest_voice_signaling",
    "softphone_voice",
    "video_conferencing",
    "streaming_video",
    "video_signaling",
];

/// Inventory TLVs: subtype 5 to 11.
const INVENTORY: [&str; 7] = [
    "hardware_revision",
    "firmware_revision",
    "software_revision",
    "serial_number",
    "manufacturer",
    "model",
    "asset_id",
];

/// One LLDP-MED TLV: `subtype` and the bytes after it. Fields are prefixed `med_`.
pub(super) fn decode(subtype: u8, v: &[u8], fields: &mut BTreeMap<String, String>) {
    match subtype {
        1 if v.len() >= 3 => {
            let Some(bits) = be16(v, 0) else { return };
            let names: Vec<&str> = CAPABILITIES
                .iter()
                .filter(|(bit, _)| bits & bit != 0)
                .map(|(_, n)| *n)
                .collect();
            if !names.is_empty() {
                fields.insert("med_capabilities".into(), names.join(","));
            }
            let (class, hint) = match v[2] {
                1 => ("endpoint_class_1", None),
                2 => ("endpoint_class_2_media", None),
                // Class III is the communication device endpoint: IP phones and conference phones.
                3 => (
                    "endpoint_class_3_communication",
                    Some(Hint::new("voip", true, "LLDP-MED class III endpoint")),
                ),
                4 => (
                    "network_connectivity",
                    Some(Hint::new(
                        "network",
                        true,
                        "LLDP-MED network connectivity device",
                    )),
                ),
                _ => return,
            };
            fields.insert("med_device_class".into(), class.into());
            hints::attach(fields, hint);
        }
        // Network policy: application type, then U, T, X bits, VLAN (12), priority (3), DSCP (6).
        // A switch advertises the voice VLAN to phones too, so a policy is never a device hint.
        2 if v.len() >= 4 => {
            let Some(app) = APPLICATIONS.get(usize::from(v[0]).wrapping_sub(1)) else {
                return;
            };
            let bits = u32::from_be_bytes([0, v[1], v[2], v[3]]);
            let policy = if bits & 0x80_0000 != 0 {
                "unknown".to_string()
            } else {
                format!(
                    "vlan {}{}, priority {}, dscp {}",
                    (bits >> 9) & 0xfff,
                    if bits & 0x40_0000 != 0 { " tagged" } else { "" },
                    (bits >> 6) & 7,
                    bits & 0x3f
                )
            };
            fields.insert(format!("med_policy.{app}"), policy);
        }
        5..=11 => {
            let value: String = text(v).trim().chars().take(128).collect();
            if !value.is_empty() {
                fields.insert(
                    format!("med_{}", INVENTORY[usize::from(subtype - 5)]),
                    value,
                );
            }
        }
        _ => {}
    }
}
