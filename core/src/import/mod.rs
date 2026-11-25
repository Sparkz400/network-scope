// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Import of known devices from files: a CSV list, DHCP lease files, Active Directory and NetBox
//! exports. The files are read offline (the tool never contacts a directory or an API to import,
//! so it holds no credentials), and what they describe is merged into the inventory and the
//! [baseline](crate::baseline) as *known devices*: they are recorded under a stable device key
//! ([`crate::identity`]) and added to the expected-devices list. They are never saved as scan
//! results: nothing was observed, so no scan, port or finding is created.
//!
//! | Kind | File | What it provides |
//! |---|---|---|
//! | `csv` | a CSV with a header (`ip`, `mac`, `hostname`, `owner`, `tags`, `criticality`, `expected`) | anything the columns give |
//! | `isc-dhcp` | ISC `dhcpd.leases` | active leases: MAC, IP, client host name |
//! | `dnsmasq` | dnsmasq lease file | MAC, IP, host name |
//! | `windows-dhcp` | CSV of `Get-DhcpServerv4Lease \| Export-Csv`, or the XML of `Export-DhcpServer` | MAC (client id), IP, host name |
//! | `ad-csv` | CSV of `Get-ADComputer -Properties * \| Export-Csv` | host name, IP, owner (`ManagedBy`) |
//! | `ad-ldif` | LDIF of computer objects (`ldifde`, `ldapsearch`) | host name, owner |
//! | `netbox` | JSON of `/api/dcim/devices/` and `/api/ipam/ip-addresses/` | name, IPs, status, tenant, role, tags |
//!
//! Host names from CSV, Active Directory and NetBox are *declared* names (see [`crate::identity`]):
//! a scanned device whose name matches is the listed device. Host names that clients report in
//! DHCP are not: leases are matched by MAC address. Every parser bounds its input (file size,
//! number of devices, length of every value) and never panics on malformed data; each has a fuzz
//! target (`import_inventory`).
use crate::{
    baseline::{self, Criticality},
    devices::Device,
    identity::{self, Identifier, Kind as IdKind},
    store,
};
use serde::Serialize;
use std::{collections::HashMap, net::IpAddr, path::Path};

mod csv;
mod dhcp;
mod ldif;
mod netbox;

/// Largest file read.
pub const MAX_FILE_BYTES: usize = 32 * 1024 * 1024;
/// Most devices one import may hold.
pub const MAX_DEVICES: usize = 100_000;
/// Most values (addresses, MACs, names, tags) kept per device.
const MAX_LIST: usize = 16;
/// Most notes about skipped or odd rows kept.
const MAX_NOTES: usize = 20;
/// Longest value read from a file.
pub(crate) const MAX_VALUE: usize = 4096;

/// What a file is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Csv,
    IscDhcp,
    Dnsmasq,
    WindowsDhcp,
    AdCsv,
    AdLdif,
    Netbox,
}

impl Kind {
    pub const ALL: [Kind; 7] = [
        Kind::Csv,
        Kind::IscDhcp,
        Kind::Dnsmasq,
        Kind::WindowsDhcp,
        Kind::AdCsv,
        Kind::AdLdif,
        Kind::Netbox,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Kind::Csv => "csv",
            Kind::IscDhcp => "isc-dhcp",
            Kind::Dnsmasq => "dnsmasq",
            Kind::WindowsDhcp => "windows-dhcp",
            Kind::AdCsv => "ad-csv",
            Kind::AdLdif => "ad-ldif",
            Kind::Netbox => "netbox",
        }
    }
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|k| k.name().eq_ignore_ascii_case(text.trim()))
    }
    /// Whether the host names in this kind of file are the operator's own names for the devices
    /// (matched by name) rather than names clients reported.
    fn declares_names(self) -> bool {
        !matches!(self, Kind::IscDhcp | Kind::Dnsmasq | Kind::WindowsDhcp)
    }
}

/// One device a file describes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Imported {
    /// MAC addresses, `AA:BB:CC:DD:EE:FF`.
    pub macs: Vec<String>,
    pub ips: Vec<IpAddr>,
    /// Host names, lower case, without a trailing dot.
    pub names: Vec<String>,
    pub owner: String,
    pub criticality: Option<Criticality>,
    pub tags: Vec<String>,
    /// `Some(false)` describes the device without expecting it; `None` means expected.
    pub expected: Option<bool>,
}

impl Imported {
    fn has_identity(&self) -> bool {
        !self.macs.is_empty() || !self.ips.is_empty() || !self.names.is_empty()
    }
    /// Takes over what `other` knows (the same device described twice).
    fn absorb(&mut self, other: Imported) {
        fn union<T: PartialEq>(into: &mut Vec<T>, from: Vec<T>) {
            for v in from {
                if !into.contains(&v) && into.len() < MAX_LIST {
                    into.push(v);
                }
            }
        }
        union(&mut self.macs, other.macs);
        union(&mut self.ips, other.ips);
        union(&mut self.names, other.names);
        union(&mut self.tags, other.tags);
        if self.owner.is_empty() {
            self.owner = other.owner;
        }
        self.criticality = self.criticality.or(other.criticality);
        self.expected = self.expected.or(other.expected);
    }
}

/// What parsing a file gave.
#[derive(Clone, Debug, Serialize)]
pub struct Import {
    pub kind: &'static str,
    /// Names are the operator's own (see the module documentation).
    pub declared_names: bool,
    pub devices: Vec<Imported>,
    /// Rows or entries that were not devices (disabled computers, expired leases, rows without
    /// any address or name).
    pub skipped: usize,
    /// Why some of them were skipped or what was ignored (the first few).
    pub notes: Vec<String>,
}

/// Collects devices while a parser runs and enforces the bounds.
pub(crate) struct Builder {
    devices: Vec<Imported>,
    skipped: usize,
    notes: Vec<String>,
}

impl Builder {
    fn new() -> Self {
        Self {
            devices: vec![],
            skipped: 0,
            notes: vec![],
        }
    }
    pub(crate) fn note(&mut self, text: impl Into<String>) {
        if self.notes.len() < MAX_NOTES {
            self.notes.push(text.into());
        }
    }
    pub(crate) fn skip(&mut self, why: impl Into<String>) {
        self.skipped += 1;
        self.note(why);
    }
    pub(crate) fn push(&mut self, device: Imported) -> Result<(), String> {
        if !device.has_identity() {
            self.skip("a row has no address, MAC or name");
            return Ok(());
        }
        if self.devices.len() >= MAX_DEVICES {
            return Err(format!("More than {MAX_DEVICES} devices; split the file"));
        }
        self.devices.push(device);
        Ok(())
    }
}

/// A MAC address in any common notation (`aa:bb:..`, `aa-bb-..`, `aabb.ccdd.eeff`, `aabbccddeeff`)
/// as `AA:BB:CC:DD:EE:FF`. All-zero and broadcast addresses are not devices.
pub(crate) fn norm_mac(text: &str) -> Option<String> {
    let text = text.trim();
    if text.len() > 17
        || !text
            .chars()
            .all(|c| c.is_ascii_hexdigit() || ":-.".contains(c))
    {
        return None;
    }
    let hex: String = text
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if hex.len() != 12 || hex.chars().all(|c| c == '0') || hex.chars().all(|c| c == 'F') {
        return None;
    }
    Some(
        hex.as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap_or_default())
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// An address (a `/prefix` and `[...]` are dropped); unspecified, loopback and multicast
/// addresses are not devices.
pub(crate) fn norm_ip(text: &str) -> Option<IpAddr> {
    let t = text.trim().trim_matches(['[', ']']);
    let t = t.split('/').next().unwrap_or_default();
    // A zone (`fe80::1%eth0`) is local to the machine that wrote it.
    let t = t.split('%').next().unwrap_or_default();
    let ip: IpAddr = t.parse().ok()?;
    let broadcast = ip == IpAddr::from([255, 255, 255, 255]);
    (!ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !broadcast).then_some(ip)
}

/// A host name: lower case, no trailing dot, no Windows `$` suffix; names that are not names
/// (`*`, `localhost`, addresses, anything with spaces or odd characters) are dropped.
pub(crate) fn norm_name(text: &str) -> Option<String> {
    let t = text
        .trim()
        .trim_end_matches('$')
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let ok = !t.is_empty()
        && t.len() <= 253
        && t != "localhost"
        && t.parse::<IpAddr>().is_err()
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        && !t.starts_with(['.', '-'])
        && !t.contains("..");
    ok.then_some(t)
}

pub(crate) fn push_unique<T: PartialEq>(list: &mut Vec<T>, value: Option<T>) {
    if let Some(v) = value
        && !list.contains(&v)
        && list.len() < MAX_LIST
    {
        list.push(v);
    }
}

/// Tags from a text separated by `;`, `|` or `,`; invalid ones are dropped.
pub(crate) fn tags_of(text: &str) -> Vec<String> {
    let mut out = vec![];
    for t in text.split([';', '|', ',']) {
        push_unique(&mut out, baseline::check_tag(t).ok());
    }
    out
}

/// A tag made of `prefix:` and a value cut to the tag limit.
pub(crate) fn tag_with(prefix: &str, value: &str) -> Option<String> {
    let value: String = value
        .chars()
        .filter(|c| !c.is_control() && *c != ',')
        .collect();
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let tag: String = format!("{prefix}{value}").chars().take(40).collect();
    baseline::check_tag(&tag).ok()
}

/// The common name of a distinguished name (`CN=Jane Doe,OU=IT,DC=corp` gives `Jane Doe`); any
/// other text is returned as it is.
pub(crate) fn cn_of(dn: &str) -> String {
    let t = dn.trim();
    let name = if t.len() > 3 && t.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("cn=")) {
        let mut end = t.len();
        let mut escaped = false;
        for (i, c) in t.char_indices().skip(3) {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == ',' {
                end = i;
                break;
            }
        }
        t[3..end].replace('\\', "")
    } else {
        t.to_string()
    };
    name.chars().filter(|c| !c.is_control()).take(100).collect()
}

/// The text of a file: UTF-8, or UTF-16 with a byte order mark (PowerShell's `-Encoding Unicode`)
/// or without one (recognised by its zero bytes). Anything else is read as UTF-8 with
/// replacement characters; NUL characters are dropped.
pub fn decode(bytes: &[u8]) -> Result<String, String> {
    if bytes.len() > MAX_FILE_BYTES {
        return Err(format!(
            "The file is too large (limit {} MB)",
            MAX_FILE_BYTES / 1024 / 1024
        ));
    }
    let utf16 = |data: &[u8], big: bool| -> String {
        let (pairs, _) = data.as_chunks::<2>();
        let units: Vec<u16> = pairs
            .iter()
            .map(|p| {
                if big {
                    u16::from_be_bytes(*p)
                } else {
                    u16::from_le_bytes(*p)
                }
            })
            .collect();
        String::from_utf16_lossy(&units)
    };
    let text = if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        utf16(rest, false)
    } else if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        utf16(rest, true)
    } else {
        let head = &bytes[..bytes.len().min(256)];
        let zeros_odd = head.iter().skip(1).step_by(2).filter(|b| **b == 0).count();
        if head.len() >= 8 && zeros_odd * 3 > head.len() {
            utf16(bytes, false)
        } else {
            String::from_utf8_lossy(bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes))
                .into_owned()
        }
    };
    Ok(text.replace('\0', ""))
}

/// Parses one file. Errors say what is wrong with the file as a whole; rows that do not fit are
/// skipped and counted in the result.
pub fn parse(kind: Kind, bytes: &[u8]) -> Result<Import, String> {
    let text = decode(bytes)?;
    let mut b = Builder::new();
    match kind {
        Kind::Csv => csv::devices(&text, csv::Preset::Generic, &mut b)?,
        Kind::AdCsv => csv::devices(&text, csv::Preset::AdComputer, &mut b)?,
        Kind::WindowsDhcp if text.trim_start().starts_with('<') => {
            dhcp::windows_xml(&text, &mut b)?
        }
        Kind::WindowsDhcp => csv::devices(&text, csv::Preset::WindowsDhcp, &mut b)?,
        Kind::IscDhcp => dhcp::isc(&text, &mut b)?,
        Kind::Dnsmasq => dhcp::dnsmasq(&text, &mut b)?,
        Kind::AdLdif => ldif::devices(&text, &mut b)?,
        Kind::Netbox => netbox::devices(&text, &mut b)?,
    }
    Ok(finish(kind, b))
}

/// Several files of one kind as one import (a NetBox device list and its IP address list
/// describe the same devices).
pub fn parse_files(kind: Kind, files: &[Vec<u8>]) -> Result<Import, String> {
    let mut all: Option<Import> = None;
    for bytes in files {
        let one = parse(kind, bytes)?;
        match all.as_mut() {
            None => all = Some(one),
            Some(a) => {
                a.devices.extend(one.devices);
                a.skipped += one.skipped;
                for n in one.notes {
                    if a.notes.len() < MAX_NOTES {
                        a.notes.push(n);
                    }
                }
            }
        }
    }
    let mut import = all.ok_or("Give at least one file")?;
    if import.devices.len() > MAX_DEVICES {
        return Err(format!("More than {MAX_DEVICES} devices; split the files"));
    }
    import.devices = coalesce(std::mem::take(&mut import.devices), import.declared_names);
    Ok(import)
}

fn finish(kind: Kind, b: Builder) -> Import {
    let declared_names = kind.declares_names();
    Import {
        kind: kind.name(),
        declared_names,
        devices: coalesce(b.devices, declared_names),
        skipped: b.skipped,
        notes: b.notes,
    }
}

/// Entries that describe the same device (the same MAC, or with declared names the same name)
/// become one: a device with several leases, or a NetBox device and its IP addresses.
fn coalesce(devices: Vec<Imported>, by_name: bool) -> Vec<Imported> {
    let n = devices.len();
    let mut parent: Vec<usize> = (0..n).collect();
    fn find(parent: &mut [usize], mut x: usize) -> usize {
        while parent[x] != x {
            parent[x] = parent[parent[x]];
            x = parent[x];
        }
        x
    }
    let mut seen: HashMap<String, usize> = HashMap::new();
    for (i, d) in devices.iter().enumerate() {
        let keys = d
            .macs
            .iter()
            .cloned()
            .chain(if by_name { d.names.clone() } else { vec![] });
        for key in keys {
            match seen.get(&key) {
                Some(&j) => {
                    let (a, b) = (find(&mut parent, i), find(&mut parent, j));
                    if a != b {
                        // The earlier entry stays the representative, so the order is kept.
                        let (low, high) = (a.min(b), a.max(b));
                        parent[high] = low;
                    }
                }
                None => {
                    seen.insert(key, i);
                }
            }
        }
    }
    let mut out: Vec<Imported> = vec![];
    let mut slot: HashMap<usize, usize> = HashMap::new();
    for (i, d) in devices.into_iter().enumerate() {
        let root = find(&mut parent, i);
        match slot.get(&root) {
            Some(&at) => out[at].absorb(d),
            None => {
                slot.insert(root, out.len());
                out.push(d);
            }
        }
    }
    out
}

/// What [`merge`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Merged {
    /// Devices recorded.
    pub devices: usize,
    /// Of those, devices the inventory already knew (a scan or an earlier import).
    pub known: usize,
    /// Of those, devices that were not known before.
    pub new: usize,
    /// Entries without any usable address, MAC or name.
    pub skipped: usize,
}

/// The device an entry stands for, to match it against the inventory like a scanned device.
fn pseudo_device(d: &Imported, declared_names: bool) -> Option<Device> {
    let id = d
        .macs
        .first()
        .cloned()
        .or_else(|| d.ips.first().map(|ip| format!("ip:{ip}")))
        .or_else(|| {
            d.names
                .first()
                .map(|n| format!("name:{}", n.split('.').next().unwrap_or(n)))
        })?;
    let mut identifiers: Vec<Identifier> = vec![];
    let mut add = |kind: IdKind, value: String| {
        if !identifiers
            .iter()
            .any(|i| i.kind == kind && i.value == value)
        {
            identifiers.push(Identifier { kind, value });
        }
    };
    for m in &d.macs {
        add(
            if identity::mac_is_stable(m) {
                IdKind::Mac
            } else {
                IdKind::RandomMac
            },
            m.clone(),
        );
    }
    for ip in &d.ips {
        add(IdKind::Ip, ip.to_string());
    }
    for n in &d.names {
        if declared_names {
            add(IdKind::DeclaredName, n.clone());
        } else {
            add(IdKind::Hostname, n.clone());
        }
    }
    Some(Device {
        id,
        mac: d.macs.first().cloned().unwrap_or_default(),
        ips: d.ips.clone(),
        hostnames: d.names.clone(),
        identifiers,
        ..Default::default()
    })
}

/// Records the devices of `import` in the inventory at `db` (stable keys and identifiers, so the
/// monitor does not call them new) and adds them to the baseline as expected devices, with their
/// owner, criticality and tags. A device the inventory already knows by MAC, address or declared
/// name keeps its key and gets the description added; the baseline is not started (see
/// [`baseline::enable`]). No scan is saved.
pub fn merge(db: &Path, import: &Import, now: i64) -> Result<Merged, String> {
    let mut pseudo = vec![];
    let mut from = vec![];
    let mut report = Merged::default();
    for d in &import.devices {
        match pseudo_device(d, import.declared_names) {
            Some(p) => {
                pseudo.push(p);
                from.push(d);
            }
            None => report.skipped += 1,
        }
    }
    let mut c = store::open(db)?;
    let tx = c.transaction().map_err(|e| e.to_string())?;
    let matches = identity::resolve(&store::registry_of(&tx)?, &pseudo);
    store::record_matches(&tx, &pseudo, &matches, now)?;
    let source = format!("import:{}", import.kind);
    for ((p, m), d) in pseudo.iter().zip(&matches).zip(&from) {
        baseline::upsert_imported(&tx, &m.key, &baseline::label_of(p), d, &source, now)?;
        report.devices += 1;
        if m.new {
            report.new += 1;
        } else {
            report.known += 1;
        }
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(report)
}

#[cfg(test)]
mod tests;
