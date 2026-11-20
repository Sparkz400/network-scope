//! CSV import: a small bounded RFC 4180 reader and the column mappings for a generic device list,
//! `Get-ADComputer | Export-Csv` and `Get-DhcpServerv4Lease | Export-Csv`. Columns are found by
//! their header names (case, spaces and underscores do not matter), so the order and any extra
//! columns of an export do not matter.
use super::{
    Builder, Imported, MAX_DEVICES, MAX_VALUE, cn_of, norm_ip, norm_mac, norm_name, push_unique,
    tag_with, tags_of,
};
use crate::baseline::Criticality;

/// Columns read per row; more are ignored.
const MAX_COLUMNS: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Preset {
    Generic,
    AdComputer,
    WindowsDhcp,
}

/// Rows of a CSV text (the delimiter is `,`, `;`, a tab or `|`, taken from the header line or
/// from a leading `sep=;` line). Quoted fields may contain delimiters, quotes (`""`) and line
/// breaks. A `#TYPE ...` line (PowerShell without `-NoTypeInformation`) and empty lines are
/// skipped. Bounded: at most [`MAX_DEVICES`] + 1 rows, [`MAX_COLUMNS`] columns, [`MAX_VALUE`]
/// characters per cell.
pub(super) fn rows(text: &str) -> Result<Vec<Vec<String>>, String> {
    let mut text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut delimiter = None;
    // Leading lines that are not data.
    loop {
        let (line, rest) = text.split_once('\n').unwrap_or((text, ""));
        let l = line.trim();
        if let Some(sep) = l.strip_prefix("sep=")
            && sep.chars().count() == 1
        {
            delimiter = sep.chars().next();
        } else if !(l.is_empty() || l.starts_with("#TYPE")) {
            break;
        }
        if rest.is_empty() && text.len() == line.len() {
            return Ok(vec![]);
        }
        text = rest;
    }
    let delimiter = delimiter.unwrap_or_else(|| {
        let first = text.lines().next().unwrap_or_default();
        let mut best = (',', 0);
        for d in [',', ';', '\t', '|'] {
            let mut quoted = false;
            let n = first
                .chars()
                .filter(|c| {
                    if *c == '"' {
                        quoted = !quoted;
                    }
                    *c == d && !quoted
                })
                .count();
            if n > best.1 {
                best = (d, n);
            }
        }
        best.0
    });
    let mut rows: Vec<Vec<String>> = vec![];
    let mut row: Vec<String> = vec![];
    let mut cell = String::new();
    let mut cell_chars = 0usize;
    let (mut quoted, mut was_quoted) = (false, false);
    let mut chars = text.chars().peekable();
    let finish_cell = |row: &mut Vec<String>, cell: &mut String, cell_chars: &mut usize| {
        if row.len() < MAX_COLUMNS {
            row.push(std::mem::take(cell).trim().to_string());
        } else {
            cell.clear();
        }
        *cell_chars = 0;
    };
    let finish_row = |rows: &mut Vec<Vec<String>>, row: &mut Vec<String>| -> Result<(), String> {
        let empty = row.iter().all(String::is_empty);
        if !empty {
            if rows.len() > MAX_DEVICES {
                return Err(format!("More than {MAX_DEVICES} rows; split the file"));
            }
            rows.push(std::mem::take(row));
        } else {
            row.clear();
        }
        Ok(())
    };
    while let Some(c) = chars.next() {
        if quoted {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    if cell_chars < MAX_VALUE {
                        cell.push('"');
                        cell_chars += 1;
                    }
                } else {
                    quoted = false;
                }
            } else if cell_chars < MAX_VALUE {
                cell.push(c);
                cell_chars += 1;
            }
            continue;
        }
        match c {
            '"' if cell.is_empty() && !was_quoted => {
                quoted = true;
                was_quoted = true;
            }
            c if c == delimiter => {
                finish_cell(&mut row, &mut cell, &mut cell_chars);
                was_quoted = false;
            }
            '\r' | '\n' => {
                if c == '\r' && chars.peek() == Some(&'\n') {
                    chars.next();
                }
                finish_cell(&mut row, &mut cell, &mut cell_chars);
                was_quoted = false;
                finish_row(&mut rows, &mut row)?;
            }
            c => {
                if cell_chars < MAX_VALUE {
                    cell.push(c);
                    cell_chars += 1;
                }
            }
        }
    }
    finish_cell(&mut row, &mut cell, &mut cell_chars);
    finish_row(&mut rows, &mut row)?;
    Ok(rows)
}

/// A header name as it is compared: lower case letters and digits only.
fn key(header: &str) -> String {
    header
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

struct Table {
    header: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    fn new(mut rows: Vec<Vec<String>>) -> Result<Self, String> {
        if rows.is_empty() {
            return Err("The file is empty (a CSV needs a header row)".into());
        }
        let header = rows.remove(0).iter().map(|h| key(h)).collect();
        Ok(Self { header, rows })
    }
    fn has(&self, names: &[&str]) -> bool {
        self.header.iter().any(|h| names.contains(&h.as_str()))
    }
    /// The non-empty values of the columns called any of `names` in `row`.
    fn values<'a>(&'a self, row: &'a [String], names: &'a [&str]) -> impl Iterator<Item = &'a str> {
        self.header
            .iter()
            .enumerate()
            .filter(move |(_, h)| names.contains(&h.as_str()))
            .filter_map(move |(i, _)| row.get(i).map(String::as_str))
            .filter(|v| !v.is_empty())
    }
    fn first<'a>(&'a self, row: &'a [String], names: &'a [&str]) -> Option<&'a str> {
        self.values(row, names).next()
    }
}

const IP: &[&str] = &[
    "ip",
    "ipaddress",
    "ipaddr",
    "ipv4",
    "ipv4address",
    "ipv6address",
    "address",
    "fixedaddress",
];
const MAC: &[&str] = &[
    "mac",
    "macaddress",
    "hwaddress",
    "hwaddr",
    "hardwareaddress",
    "ethernet",
    "clientid",
    "physicaladdress",
];
const NAME: &[&str] = &[
    "hostname",
    "host",
    "name",
    "dnsname",
    "dnshostname",
    "fqdn",
    "computername",
    "devicename",
    "clienthostname",
    "samaccountname",
];
const OWNER: &[&str] = &[
    "owner",
    "contact",
    "responsible",
    "assignedto",
    "managedby",
    "manager",
];
const TAGS: &[&str] = &["tags", "tag", "labels", "groups"];
const CRITICALITY: &[&str] = &["criticality", "criticalness", "importance", "priority"];
const EXPECTED: &[&str] = &["expected", "approved", "allowed"];

fn truth(text: &str) -> Option<bool> {
    match text.trim().to_ascii_lowercase().as_str() {
        "yes" | "y" | "true" | "1" | "x" | "ja" => Some(true),
        "no" | "n" | "false" | "0" | "nein" => Some(false),
        _ => None,
    }
}

pub(super) fn devices(text: &str, preset: Preset, out: &mut Builder) -> Result<(), String> {
    let table = Table::new(rows(text)?)?;
    let name_columns: &[&str] = if preset == Preset::AdComputer {
        &["dnshostname", "name", "samaccountname"]
    } else {
        NAME
    };
    let usable = table.has(IP) || table.has(MAC) || table.has(name_columns);
    if !usable {
        return Err(match preset {
            Preset::Generic => "A device CSV needs a header with at least one of: ip, mac, hostname",
            Preset::AdComputer => {
                "Not a Get-ADComputer export: the header has no Name, DNSHostName or SamAccountName column"
            }
            Preset::WindowsDhcp => {
                "Not a DHCP lease export: the header has no IPAddress, ClientId or HostName column"
            }
        }
        .into());
    }
    for row in &table.rows {
        let mut d = Imported::default();
        // Windows DHCP: leases that are not in use are not devices.
        if preset == Preset::WindowsDhcp
            && let Some(state) = table.first(row, &["addressstate"])
        {
            let s = state.to_ascii_lowercase();
            if !(s.starts_with("active") || s.contains("reservation")) {
                out.skip(format!("lease in state {state} skipped"));
                continue;
            }
        }
        // AD: a disabled computer account is not on the network.
        if preset == Preset::AdComputer
            && table.first(row, &["enabled"]).and_then(truth) == Some(false)
        {
            out.skip("a disabled computer account was skipped");
            continue;
        }
        for v in table.values(row, IP) {
            for part in v.split([' ', ';', ',', '|']) {
                push_unique(&mut d.ips, norm_ip(part));
            }
        }
        for v in table.values(row, MAC) {
            push_unique(&mut d.macs, norm_mac(v));
        }
        for v in table.values(row, name_columns) {
            push_unique(&mut d.names, norm_name(v));
        }
        if let Some(o) = table.first(row, OWNER) {
            d.owner = cn_of(o);
        }
        for v in table.values(row, TAGS) {
            for t in tags_of(v) {
                push_unique(&mut d.tags, Some(t));
            }
        }
        if let Some(c) = table.first(row, CRITICALITY) {
            match Criticality::parse(c) {
                Some(c) => d.criticality = Some(c),
                None => out.note(format!(
                    "criticality {c:?} is not low, medium, high or critical"
                )),
            }
        }
        if let Some(e) = table.first(row, EXPECTED) {
            match truth(e) {
                Some(e) => d.expected = Some(e),
                None => out.note(format!("expected {e:?} is not yes or no")),
            }
        }
        match preset {
            Preset::AdComputer => {
                push_unique(&mut d.tags, Some("ad".to_string()));
                push_unique(
                    &mut d.tags,
                    table
                        .first(row, &["operatingsystem"])
                        .and_then(|os| tag_with("os:", os)),
                );
            }
            Preset::WindowsDhcp => push_unique(&mut d.tags, Some("dhcp".to_string())),
            Preset::Generic => {}
        }
        out.push(d)?;
    }
    Ok(())
}
