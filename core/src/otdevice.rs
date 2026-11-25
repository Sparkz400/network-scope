// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! The vendor, product and firmware of an industrial device, read from the identity fields an OT
//! identification stored (`S7.*`, `EtherNet/IP.*`, `Modbus.*`, `OPC UA.*`).
//!
//! Both the research tables ([`crate::research`]) and the offline advisory matching
//! ([`crate::csaf`]) use it, so they agree on what "the product" of a device is. Nothing here
//! sends or parses network data: it only reads strings a scan already collected, and every value
//! is bounded.
use std::collections::BTreeMap;

/// Longest value kept (these strings come from the device).
const MAX_VALUE: usize = 120;

/// One identified industrial device (a host can answer several protocols).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OtDevice {
    /// `S7`, `EtherNet/IP`, `Modbus` or `OPC UA`.
    pub protocol: &'static str,
    /// The port the protocol was identified on.
    pub port: u16,
    pub vendor: String,
    /// Names the device calls itself, most specific first: order code or model number, then
    /// product and module names. Compared case-insensitively with advisory product names.
    pub products: Vec<String>,
    /// Firmware or software version as the device reported it (`4.2.1`, `V4.2`, `20.11`).
    pub version: String,
}

impl OtDevice {
    /// All the fields as `key=value` text, for evidence lines.
    pub fn describe(&self) -> String {
        let mut parts = vec![format!("{} on port {}", self.protocol, self.port)];
        if !self.vendor.is_empty() {
            parts.push(format!("vendor {}", self.vendor));
        }
        if let Some(p) = self.products.first() {
            parts.push(format!("product {p}"));
        }
        if !self.version.is_empty() {
            parts.push(format!("firmware {}", self.version));
        }
        parts.join(", ")
    }
}

fn clean(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_VALUE)
        .collect::<String>()
        .trim()
        .to_string()
}

fn field(identity: &BTreeMap<String, String>, protocol: &str, key: &str) -> String {
    identity
        .get(&format!("{protocol}.{key}"))
        .map(|v| clean(v))
        .unwrap_or_default()
}

fn push_unique(list: &mut Vec<String>, value: String) {
    if !value.is_empty() && !list.iter().any(|v| v.eq_ignore_ascii_case(&value)) {
        list.push(value);
    }
}

/// The industrial devices a host's identity describes (empty when it has no OT fields).
pub fn from_identity(identity: &BTreeMap<String, String>) -> Vec<OtDevice> {
    let mut out = vec![];
    // Modbus device identification: vendor, product name and the firmware revision.
    let (vendor, product, version) = (
        field(identity, "Modbus", "vendor"),
        field(identity, "Modbus", "product"),
        field(identity, "Modbus", "firmware"),
    );
    if !(vendor.is_empty() && product.is_empty() && version.is_empty()) {
        let mut products = vec![];
        push_unique(&mut products, product);
        out.push(OtDevice {
            protocol: "Modbus",
            port: 502,
            vendor,
            products,
            version,
        });
    }
    // S7 SZL: the order code (6ES7 ...) is the model number; Siemens is implied by the protocol.
    let version = field(identity, "S7", "firmware");
    let mut products = vec![];
    for key in ["order_code", "cpu_type", "module", "name"] {
        push_unique(&mut products, field(identity, "S7", key));
    }
    if !products.is_empty() || !version.is_empty() {
        out.push(OtDevice {
            protocol: "S7",
            port: 102,
            vendor: "Siemens".into(),
            products,
            version,
        });
    }
    // CIP identity object: vendor name, the product name, and the revision.
    let version = field(identity, "EtherNet/IP", "firmware");
    let mut products = vec![];
    push_unique(&mut products, field(identity, "EtherNet/IP", "name"));
    let vendor = field(identity, "EtherNet/IP", "vendor");
    if !vendor.is_empty() || !products.is_empty() || !version.is_empty() {
        out.push(OtDevice {
            protocol: "EtherNet/IP",
            port: 44818,
            vendor,
            products,
            version,
        });
    }
    // OPC UA: the application and product URIs of the first endpoint; servers do not publish a
    // firmware revision in the discovery reply, so the version stays empty.
    let mut products = vec![];
    for key in ["endpoint_0.name", "endpoint_0.product_uri"] {
        push_unique(&mut products, field(identity, "OPC UA", key));
    }
    if !products.is_empty() {
        out.push(OtDevice {
            protocol: "OPC UA",
            port: 4840,
            vendor: String::new(),
            products,
            version: String::new(),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn the_four_protocols_give_vendor_product_and_firmware() {
        let devices = from_identity(&identity(&[
            ("S7.order_code", "6ES7 214-1AG40-0XB0"),
            ("S7.firmware", "4.2.3"),
            ("S7.module", "CPU 1214C"),
            ("EtherNet/IP.vendor", "Rockwell Automation/Allen-Bradley"),
            ("EtherNet/IP.name", "1756-L81E"),
            ("EtherNet/IP.firmware", "20.11"),
            ("Modbus.vendor", "Schneider Electric"),
            ("Modbus.product", "BMX P34 2020"),
            ("Modbus.firmware", "V2.40"),
            ("OPC UA.endpoint_0.name", "Demo server"),
        ]));
        let by = |p: &str| devices.iter().find(|d| d.protocol == p).unwrap().clone();
        assert_eq!(by("S7").products[0], "6ES7 214-1AG40-0XB0");
        assert_eq!(
            (by("S7").vendor.as_str(), by("S7").version.as_str()),
            ("Siemens", "4.2.3")
        );
        assert_eq!(by("EtherNet/IP").version, "20.11");
        assert_eq!(by("Modbus").products, ["BMX P34 2020"]);
        assert_eq!(by("OPC UA").products, ["Demo server"]);
        assert!(by("OPC UA").version.is_empty());
        assert!(by("S7").describe().contains("firmware 4.2.3"));
    }

    #[test]
    fn a_host_without_ot_fields_has_no_device_and_values_are_bounded() {
        assert!(from_identity(&identity(&[("svc.22", "ssh")])).is_empty());
        let long = "x".repeat(10_000);
        let d = from_identity(&identity(&[("Modbus.product", &long)]));
        assert_eq!(d[0].products[0].len(), MAX_VALUE);
        let d = from_identity(&identity(&[("S7.name", "a\u{0}b\nc")]));
        assert_eq!(d[0].products[0], "abc");
    }
}
