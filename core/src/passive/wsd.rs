// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! WS-Discovery (UDP 3702, multicast 239.255.255.250 / ff02::c): SOAP-over-UDP announcements.
//! Only messages that describe the *sender* are used: Hello, ProbeMatches and ResolveMatches.
//! A Probe or Resolve lists what the sender is looking for, and Bye carries no identity, so
//! those are ignored. Passive decoding only; nothing here transmits.
//!
//! The XML is untrusted: it is parsed with roxmltree with DTDs rejected (so no entity
//! expansion), external entities never resolved, a node limit, and a byte limit before
//! parsing. QName prefixes are arbitrary, so types are matched on their local part.
use super::{
    Observation,
    hints::{self, Hint},
    text,
};

/// Largest datagram parsed. SOAP-over-UDP messages must fit one datagram.
const MAX_BYTES: usize = 32 * 1024;
/// Elements and text nodes parsed per message.
const MAX_NODES: u32 = 4096;
const MAX_TOKENS: usize = 16;

pub(super) fn decode(payload: &[u8], o: &mut Observation) -> Option<()> {
    if payload.len() > MAX_BYTES {
        return None;
    }
    let xml = std::str::from_utf8(payload)
        .ok()?
        .trim_matches(|c: char| c == '\0' || c.is_whitespace());
    if !xml.starts_with('<') || !xml.contains("Envelope") {
        return None;
    }
    let doc = roxmltree::Document::parse_with_options(
        xml,
        roxmltree::ParsingOptions {
            allow_dtd: false,
            nodes_limit: MAX_NODES,
            entity_resolver: None,
        },
    )
    .ok()?;
    let action = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "Action")?
        .text()?
        .trim()
        .rsplit('/')
        .next()?
        .to_string();
    if !["Hello", "ProbeMatches", "ResolveMatches"].contains(&action.as_str()) {
        return None;
    }
    o.protocol = "WS-Discovery".into();
    o.fields.insert("action".into(), action);
    let mut types: Vec<String> = vec![];
    let mut xaddrs: Vec<String> = vec![];
    let mut hints: Vec<Hint> = vec![];
    for n in doc.descendants().filter(|n| n.is_element()) {
        let value = n.text().unwrap_or("");
        match n.tag_name().name() {
            "Types" => {
                for qname in value.split_whitespace() {
                    if types.len() >= MAX_TOKENS {
                        break;
                    }
                    let qname = text(qname.as_bytes());
                    let local = qname.rsplit(':').next().unwrap_or("").to_string();
                    hints.extend(hints::matching(
                        &format!("|{local}|"),
                        hints::WSD_TYPES,
                        "WS-Discovery type",
                    ));
                    if !types.contains(&qname) {
                        types.push(qname);
                    }
                }
            }
            "XAddrs" => {
                for url in value.split_whitespace() {
                    if xaddrs.len() >= MAX_TOKENS / 2 {
                        break;
                    }
                    let url = text(url.as_bytes());
                    if !xaddrs.contains(&url) {
                        xaddrs.push(url);
                    }
                }
            }
            "Address"
                if n.parent()
                    .is_some_and(|p| p.tag_name().name() == "EndpointReference") =>
            {
                o.fields
                    .entry("endpoint".into())
                    .or_insert_with(|| text(value.trim().as_bytes()));
            }
            _ => {}
        }
    }
    if !types.is_empty() {
        o.fields.insert("types".into(), types.join(" "));
    }
    if !xaddrs.is_empty() {
        o.fields.insert("xaddrs".into(), xaddrs.join(" "));
    }
    hints::attach(&mut o.fields, hints);
    Some(())
}
