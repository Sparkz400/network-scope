// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! DHCP lease files: ISC `dhcpd.leases`, dnsmasq's lease file and the XML written by the Windows
//! `Export-DhcpServer` cmdlet. (The CSV of `Get-DhcpServerv4Lease | Export-Csv` goes through
//! `csv.rs`.) Leases name a MAC address, which identifies the device; the host name is what the
//! client reported and is not used to recognise it.
use super::{Builder, Imported, MAX_DEVICES, MAX_VALUE, norm_ip, norm_mac, norm_name, push_unique};
use std::{collections::BTreeMap, net::IpAddr};

/// Longest line read from a lease file; longer lines are ignored.
const MAX_LINE: usize = 8192;
/// Deepest nesting of `{ }` blocks followed in `dhcpd.leases`.
const MAX_DEPTH: usize = 8;

fn lease(mac: Option<String>, ip: Option<IpAddr>, name: Option<String>) -> Imported {
    let mut d = Imported::default();
    push_unique(&mut d.macs, mac);
    push_unique(&mut d.ips, ip);
    push_unique(&mut d.names, name);
    d.tags = vec!["dhcp".to_string()];
    d
}

#[derive(Default)]
struct IscLease {
    state: String,
    mac: Option<String>,
    name: Option<String>,
}

/// The text of a quoted string (`"host\"name"`), or of a bare word.
fn unquote(text: &str) -> String {
    let t = text.trim().trim_end_matches(';').trim();
    let Some(inner) = t.strip_prefix('"') else {
        return t.to_string();
    };
    let mut out = String::new();
    let mut escaped = false;
    for c in inner.chars() {
        if escaped {
            out.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            break;
        } else {
            out.push(c);
        }
    }
    out
}

/// ISC dhcpd `dhcpd.leases`. The file is a journal: for every address the last `lease` block
/// wins. Only leases in the binding state `active` are devices (free, expired, abandoned and
/// backup leases are not); a block without a state is read as active.
pub(super) fn isc(text: &str, out: &mut Builder) -> Result<(), String> {
    let mut leases: BTreeMap<IpAddr, IscLease> = BTreeMap::new();
    // Address of the lease block being read, and the brace depth inside it.
    let mut current: Option<(IpAddr, IscLease)> = None;
    let mut depth = 0usize;
    let (mut blocks, mut meaningful) = (0usize, false);
    for line in text.lines() {
        if line.len() > MAX_LINE {
            continue;
        }
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        meaningful = true;
        if current.is_none() && depth == 0 {
            if let Some(rest) = line.strip_prefix("lease ")
                && let Some(addr) = rest.trim().strip_suffix('{')
                && let Some(ip) = norm_ip(addr)
            {
                current = Some((ip, IscLease::default()));
                depth = 1;
                blocks += 1;
            } else if line.ends_with('{') {
                // Another kind of block (`server-duid`, `failover peer`, `host`): skip it.
                depth = 1;
                blocks += 1;
            }
            continue;
        }
        if line.ends_with('{') {
            depth += 1;
            if depth > MAX_DEPTH {
                return Err("dhcpd.leases: blocks nested too deeply".into());
            }
            continue;
        }
        if line.starts_with('}') {
            depth = depth.saturating_sub(1);
            if depth == 0
                && let Some((ip, l)) = current.take()
            {
                if leases.len() >= MAX_DEVICES && !leases.contains_key(&ip) {
                    return Err(format!("More than {MAX_DEVICES} leases; split the file"));
                }
                leases.insert(ip, l);
            }
            continue;
        }
        if let Some((_, l)) = current.as_mut().filter(|_| depth == 1) {
            if let Some(v) = line.strip_prefix("binding state ") {
                l.state = unquote(v).to_ascii_lowercase();
            } else if let Some(v) = line.strip_prefix("hardware ethernet ") {
                l.mac = norm_mac(&unquote(v));
            } else if let Some(v) = line.strip_prefix("client-hostname ") {
                l.name = norm_name(&unquote(v));
            }
        }
    }
    if blocks == 0 && meaningful {
        return Err("Not a dhcpd.leases file (no lease blocks found)".into());
    }
    let mut inactive = 0usize;
    for (ip, l) in leases {
        if !(l.state.is_empty() || l.state == "active") {
            inactive += 1;
            continue;
        }
        if l.mac.is_none() {
            out.skip(format!("lease {ip} has no hardware address"));
            continue;
        }
        out.push(lease(l.mac, Some(ip), l.name))?;
    }
    if inactive > 0 {
        out.skipped += inactive;
        out.note(format!(
            "{inactive} leases that are not active (free, expired, abandoned or backup) were skipped"
        ));
    }
    Ok(())
}

/// dnsmasq's lease file: `EXPIRY MAC ADDRESS HOSTNAME CLIENT-ID` per line (IPv6 leases have an
/// IAID instead of the MAC and a DUID as client id). `*` stands for "none". A `duid` line names
/// the server and is skipped.
pub(super) fn dnsmasq(text: &str, out: &mut Builder) -> Result<(), String> {
    let mut seen_lease = false;
    let mut bad = 0usize;
    for line in text.lines() {
        if line.len() > MAX_LINE || line.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.first() == Some(&"duid") {
            continue;
        }
        let (Some(expiry), Some(second), Some(addr)) = (f.first(), f.get(1), f.get(2)) else {
            bad += 1;
            continue;
        };
        if expiry.parse::<u64>().is_err() {
            bad += 1;
            continue;
        }
        let Some(ip) = norm_ip(addr) else {
            bad += 1;
            continue;
        };
        seen_lease = true;
        let name = f.get(3).filter(|n| **n != "*").and_then(|n| norm_name(n));
        // A MAC for IPv4; an IPv6 lease has an IAID there.
        out.push(lease(norm_mac(second), Some(ip), name))?;
    }
    if !seen_lease && bad > 0 {
        return Err(
            "Not a dnsmasq lease file (no line of the form EXPIRY MAC ADDRESS NAME ID)".into(),
        );
    }
    if bad > 0 {
        out.skipped += bad;
        out.note(format!("{bad} lines were not leases"));
    }
    Ok(())
}

/// The XML of `Export-DhcpServer -Leases`: `<Lease>` elements (address state `Active*`) and
/// `<Reservation>` elements, each with `IPAddress`, `ClientId` (the MAC, `aa-bb-...`) and a host
/// name (`HostName` or `Name`). Matched by element name wherever they appear.
pub(super) fn windows_xml(text: &str, out: &mut Builder) -> Result<(), String> {
    let doc = roxmltree::Document::parse_with_options(
        text,
        roxmltree::ParsingOptions {
            // No DTD, so no entities: the file is untrusted input.
            allow_dtd: false,
            nodes_limit: 4_000_000,
            entity_resolver: None,
        },
    )
    .map_err(|e| format!("Not valid XML: {e}"))?;
    let mut entries = 0usize;
    for n in doc
        .descendants()
        .filter(|n| n.is_element() && (n.has_tag_name("Lease") || n.has_tag_name("Reservation")))
    {
        let get = |name: &str| -> Option<String> {
            n.children()
                .find(|c| c.is_element() && c.has_tag_name(name))
                .and_then(|c| c.text())
                .map(|t| t.chars().take(MAX_VALUE).collect::<String>())
        };
        entries += 1;
        if n.has_tag_name("Lease")
            && let Some(state) = get("AddressState")
            && !state.to_ascii_lowercase().starts_with("active")
        {
            out.skip(format!("lease in state {state} skipped"));
            continue;
        }
        let name = get("HostName").or_else(|| get("Name"));
        out.push(lease(
            get("ClientId").and_then(|m| norm_mac(&m)),
            get("IPAddress").and_then(|i| norm_ip(&i)),
            name.and_then(|n| norm_name(&n)),
        ))?;
    }
    if entries == 0 {
        return Err("No <Lease> or <Reservation> elements: not an Export-DhcpServer file".into());
    }
    Ok(())
}
