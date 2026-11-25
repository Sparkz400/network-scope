// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! NetBox JSON exports, read offline from files saved from the REST API: `/api/dcim/devices/`
//! (devices with name, status, role, tenant, tags and primary addresses) and
//! `/api/ipam/ip-addresses/` (addresses with the device they are assigned to). The file is either
//! the API's paged object (`{"count": .., "results": [..]}`), a plain array or one object. An
//! address that is assigned to a device is joined to it by name (give both files to one `import`).
//! Devices with the status `active` or `offline` are expected on the network; `planned`, `staged`,
//! `failed`, `inventory` and `decommissioning` are described but not expected. Addresses that are
//! not `active` are skipped.
use super::{Builder, Imported, norm_ip, norm_mac, norm_name, push_unique, tag_with, tags_of};
use serde_json::Value;

fn text<'a>(v: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cur = v;
    for p in path {
        cur = cur.get(*p)?;
    }
    cur.as_str().filter(|s| !s.is_empty())
}

/// A status object (`{"value": "active"}`) or a plain string, lower case.
fn status(v: &Value) -> Option<String> {
    let s = v.get("status")?;
    s.as_str()
        .or_else(|| s.get("value").and_then(Value::as_str))
        .map(|s| s.to_ascii_lowercase())
}

fn tags(v: &Value, d: &mut Imported) {
    for t in v
        .get("tags")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = t.as_str().or_else(|| t.get("name").and_then(Value::as_str));
        for tag in tags_of(name.unwrap_or_default()) {
            push_unique(&mut d.tags, Some(tag));
        }
    }
}

fn device(v: &Value, out: &mut Builder) -> Result<(), String> {
    let mut d = Imported::default();
    push_unique(&mut d.names, text(v, &["name"]).and_then(norm_name));
    for field in ["primary_ip4", "primary_ip6", "primary_ip", "oob_ip"] {
        push_unique(&mut d.ips, text(v, &[field, "address"]).and_then(norm_ip));
    }
    for path in [
        &["mac_address"][..],
        &["primary_mac_address", "mac_address"],
    ] {
        push_unique(&mut d.macs, text(v, path).and_then(norm_mac));
    }
    if let Some(t) = text(v, &["tenant", "name"]).or_else(|| text(v, &["tenant", "display"])) {
        d.owner = t.chars().filter(|c| !c.is_control()).take(100).collect();
    }
    for (prefix, path) in [
        ("role:", &["role", "name"][..]),
        ("role:", &["device_role", "name"]),
        ("site:", &["site", "name"]),
        ("type:", &["device_type", "model"]),
    ] {
        push_unique(&mut d.tags, text(v, path).and_then(|t| tag_with(prefix, t)));
    }
    tags(v, &mut d);
    let st = status(v);
    d.expected = Some(matches!(st.as_deref(), None | Some("active" | "offline")));
    if let Some(s) = st.filter(|s| s != "active") {
        push_unique(&mut d.tags, tag_with("status:", &s));
    }
    out.push(d)
}

fn address(v: &Value, out: &mut Builder) -> Result<(), String> {
    if status(v).is_some_and(|s| s != "active") {
        out.skip("an address that is not active was skipped");
        return Ok(());
    }
    let mut d = Imported::default();
    push_unique(&mut d.ips, text(v, &["address"]).and_then(norm_ip));
    // The device it belongs to, else the DNS name it carries.
    let owner_device = text(v, &["assigned_object", "device", "name"])
        .or_else(|| text(v, &["assigned_object", "device", "display"]));
    push_unique(&mut d.names, owner_device.and_then(norm_name));
    if d.names.is_empty() {
        push_unique(&mut d.names, text(v, &["dns_name"]).and_then(norm_name));
    }
    if let Some(t) = text(v, &["tenant", "name"]) {
        d.owner = t.chars().filter(|c| !c.is_control()).take(100).collect();
    }
    tags(v, &mut d);
    out.push(d)
}

pub(super) fn devices(json: &str, out: &mut Builder) -> Result<(), String> {
    let root: Value = serde_json::from_str(json).map_err(|e| format!("Not valid JSON: {e}"))?;
    let items: Vec<&Value> = match &root {
        Value::Array(a) => a.iter().collect(),
        Value::Object(o) => match o.get("results") {
            Some(Value::Array(a)) => a.iter().collect(),
            Some(_) => return Err("NetBox export: \"results\" is not a list".into()),
            None => vec![&root],
        },
        _ => return Err("Not a NetBox export (expected an object or a list)".into()),
    };
    let mut seen = 0usize;
    for item in items {
        if !item.is_object() {
            out.skip("an entry is not an object");
            continue;
        }
        let has_address = item.get("address").is_some_and(Value::is_string);
        let is_device = item.get("device_type").is_some()
            || item.get("role").is_some()
            || item.get("device_role").is_some()
            || (item.get("name").is_some() && !has_address);
        if has_address {
            address(item, out)?;
        } else if is_device {
            device(item, out)?;
        } else {
            out.skip("an entry is neither a device nor an IP address");
            continue;
        }
        seen += 1;
    }
    if seen == 0 && out.skipped > 0 {
        return Err("Not a NetBox export: no device or IP address entries".into());
    }
    Ok(())
}
