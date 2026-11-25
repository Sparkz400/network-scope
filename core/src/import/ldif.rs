// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! LDIF (RFC 2849) export of Active Directory computer objects (`ldifde -f out.ldf`,
//! `ldapsearch -LLL`), read offline: no directory is contacted and nothing is fetched (`attr:<
//! URL` values are ignored). Only computer objects become devices; disabled accounts
//! (`userAccountControl` bit 2) are skipped.
use super::{Builder, Imported, MAX_VALUE, cn_of, norm_name, push_unique, tag_with};
use std::collections::BTreeMap;

/// Longest logical line (after joining continuation lines).
const MAX_LOGICAL: usize = 64 * 1024;
/// Most attributes kept per entry, and values per attribute.
const MAX_ATTRS: usize = 256;
const MAX_VALUES: usize = 64;
/// Largest value decoded from base64.
const MAX_DECODED: usize = 8192;

/// A base64 text (RFC 4648, padding optional, whitespace ignored) decoded to text. `None` for
/// anything that is not valid base64 or too long.
pub(super) fn base64(text: &str) -> Option<String> {
    let mut out: Vec<u8> = vec![];
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b' ' | b'\t' => continue,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
            acc &= (1 << bits) - 1;
            if out.len() > MAX_DECODED {
                return None;
            }
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

type Entry = BTreeMap<String, Vec<String>>;

fn computer(entry: &Entry, out: &mut Builder) -> Result<bool, String> {
    let first = |name: &str| entry.get(name).and_then(|v| v.first()).map(String::as_str);
    let is_computer = entry
        .get("objectclass")
        .is_some_and(|v| v.iter().any(|c| c.eq_ignore_ascii_case("computer")))
        || (!entry.contains_key("objectclass")
            && (entry.contains_key("dnshostname")
                || first("samaccountname").is_some_and(|s| s.ends_with('$'))));
    if !is_computer {
        return Ok(false);
    }
    let uac: i64 = first("useraccountcontrol")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if uac & 2 != 0 {
        out.skip("a disabled computer account was skipped");
        return Ok(true);
    }
    let mut d = Imported::default();
    for attr in ["dnshostname", "name", "cn", "samaccountname"] {
        for v in entry.get(attr).into_iter().flatten() {
            push_unique(&mut d.names, norm_name(v));
        }
    }
    if let Some(m) = first("managedby") {
        d.owner = cn_of(m);
    }
    push_unique(&mut d.tags, Some("ad".to_string()));
    push_unique(
        &mut d.tags,
        first("operatingsystem").and_then(|os| tag_with("os:", os)),
    );
    out.push(d)?;
    Ok(true)
}

pub(super) fn devices(text: &str, out: &mut Builder) -> Result<(), String> {
    let mut entry: Entry = Entry::new();
    let mut logical = String::new();
    let (mut dn_lines, mut ignored) = (0usize, 0usize);
    let flush_line = |logical: &mut String, entry: &mut Entry, dn_lines: &mut usize| {
        if logical.is_empty() {
            return;
        }
        let line = std::mem::take(logical);
        let Some((attr, rest)) = line.split_once(':') else {
            return;
        };
        let attr = attr.trim().to_ascii_lowercase();
        // `attr:: base64`, `attr:< url` (never fetched) or `attr: value`.
        let value = if let Some(b) = rest.strip_prefix(':') {
            base64(b)
        } else if rest.starts_with('<') {
            None
        } else {
            Some(
                rest.trim_start()
                    .chars()
                    .take(MAX_VALUE)
                    .collect::<String>(),
            )
        };
        if attr == "dn" {
            *dn_lines += 1;
        }
        let Some(value) = value else {
            return;
        };
        if entry.len() >= MAX_ATTRS && !entry.contains_key(&attr) {
            return;
        }
        let values = entry.entry(attr).or_default();
        if values.len() < MAX_VALUES {
            values.push(value);
        }
    };
    let mut end_entry = |entry: &mut Entry, out: &mut Builder| -> Result<(), String> {
        if !entry.is_empty() && !computer(entry, out)? {
            ignored += 1;
        }
        entry.clear();
        Ok(())
    };
    for raw in text.lines() {
        if let Some(cont) = raw.strip_prefix(' ') {
            // A continuation line extends the previous line.
            if !logical.is_empty() && logical.len() < MAX_LOGICAL {
                logical.push_str(cont);
            }
            continue;
        }
        flush_line(&mut logical, &mut entry, &mut dn_lines);
        if raw.trim().is_empty() {
            end_entry(&mut entry, out)?;
        } else if !raw.starts_with('#') {
            logical = raw.chars().take(MAX_LOGICAL).collect();
        }
    }
    flush_line(&mut logical, &mut entry, &mut dn_lines);
    end_entry(&mut entry, out)?;
    if dn_lines == 0 {
        return Err("Not an LDIF file (no dn: lines)".into());
    }
    if ignored > 0 {
        out.skipped += ignored;
        out.note(format!(
            "{ignored} entries that are not computer objects were ignored"
        ));
    }
    Ok(())
}
