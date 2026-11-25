// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! Scope guard (ROADMAP H54): confirmation before the scanner touches public addresses or
//! anything outside the scope the user declared.
//!
//! Every entry point that starts active traffic (CLI `scan`, `monitor` and `trace`, the desktop
//! Start button, library users) calls [`enforce`] with the addresses it is about to touch. The
//! rule is the same everywhere:
//!
//! - An address is **public** unless it is in a private or local block: RFC 1918
//!   (10/8, 172.16/12, 192.168/16), carrier-grade NAT (100.64/10), loopback (127/8, `::1`),
//!   link-local (169.254/16, `fe80::/10`), unique local (`fc00::/7`) or "this host" (0/8, `::`).
//!   An IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) counts as the IPv4 address.
//! - A **declared scope** is a list of CIDR blocks, addresses and ranges ([`Scope::parse`]), given
//!   with `--scope` or kept in a [`default_path`] file. When one exists, every address outside it
//!   needs confirmation, and a public address inside it does not (the user declared it).
//! - Confirmation is either a flag ([`Consent`]), or an interactive answer given through the
//!   `confirm` callback. Without both, [`enforce`] returns a [`Refusal`] and nothing is sent.
//!
//! The check works on address ranges, so a /8 is judged without being expanded.
use crate::scan::Targets;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
};

/// IPv4 blocks that are not public: this host, RFC 1918, CGNAT, loopback, link-local.
const NON_PUBLIC_V4: [(u32, u32); 7] = [
    cidr4([0, 0, 0, 0], 8),
    cidr4([10, 0, 0, 0], 8),
    cidr4([100, 64, 0, 0], 10),
    cidr4([127, 0, 0, 0], 8),
    cidr4([169, 254, 0, 0], 16),
    cidr4([172, 16, 0, 0], 12),
    cidr4([192, 168, 0, 0], 16),
];

const fn cidr4(octets: [u8; 4], prefix: u32) -> (u32, u32) {
    let start = u32::from_be_bytes(octets);
    let host_bits = if prefix >= 32 { 0 } else { u32::MAX >> prefix };
    (start & !host_bits, start | host_bits)
}

/// The IPv4 form of an address: itself, or the address inside an IPv4-mapped IPv6 address.
fn as_v4(ip: IpAddr) -> Option<u32> {
    match ip {
        IpAddr::V4(v4) => Some(u32::from(v4)),
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(u32::from),
    }
}

/// True for an address outside the private and local blocks listed in the module documentation.
pub fn is_public(ip: IpAddr) -> bool {
    if let Some(v4) = as_v4(ip) {
        return !NON_PUBLIC_V4.iter().any(|&(a, b)| (a..=b).contains(&v4));
    }
    let IpAddr::V6(v6) = ip else { return true };
    let first = v6.segments()[0];
    let local = v6.is_loopback()
        || v6.is_unspecified()
        || first & 0xfe00 == 0xfc00 // unique local fc00::/7
        || first & 0xffc0 == 0xfe80; // link-local fe80::/10
    !local
}

/// A declared scope: the addresses the user said may be scanned.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Scope {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

/// Most entries a scope file may hold, so an unexpected file cannot make checks slow.
const MAX_SCOPE_ENTRIES: usize = 4096;

fn merge<T: Ord + Copy + Into<u128>>(mut ranges: Vec<(T, T)>) -> Vec<(T, T)> {
    ranges.sort_unstable();
    let mut merged: Vec<(T, T)> = vec![];
    for (a, b) in ranges {
        match merged.last_mut() {
            Some(last) if a.into() <= last.1.into().saturating_add(1) => last.1 = last.1.max(b),
            _ => merged.push((a, b)),
        }
    }
    merged
}

impl Scope {
    /// Parses entries separated by commas, spaces or new lines: `10.0.0.0/8`, `192.168.1.7`,
    /// `10.1.0.1-10.1.0.50`, `10.1.0.1-50`, `fd00::/8`, `2001:db8::1`. `#` starts a comment that
    /// runs to the end of the line. An empty scope is an error (it would mean "nothing is in
    /// scope"), so a mistyped file cannot silently widen or narrow what is allowed.
    pub fn parse(text: &str) -> Result<Self, String> {
        let (mut v4, mut v6) = (vec![], vec![]);
        let mut entries = 0usize;
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("");
            for token in line
                .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
                .filter(|t| !t.is_empty())
            {
                entries += 1;
                if entries > MAX_SCOPE_ENTRIES {
                    return Err(format!(
                        "A scope holds at most {MAX_SCOPE_ENTRIES} entries."
                    ));
                }
                if token.len() > 128 {
                    return Err("Scope entry too long.".into());
                }
                Self::add(token, &mut v4, &mut v6)?;
            }
        }
        if entries == 0 {
            return Err("The scope is empty: list CIDR blocks, addresses or ranges.".into());
        }
        Ok(Self {
            v4: merge(v4),
            v6: merge(v6),
        })
    }
    fn add(
        token: &str,
        v4: &mut Vec<(u32, u32)>,
        v6: &mut Vec<(u128, u128)>,
    ) -> Result<(), String> {
        let bad = || format!("Invalid scope entry: {token}");
        if let Some((ip, prefix)) = token.split_once('/') {
            let prefix: u32 = prefix.parse().map_err(|_| bad())?;
            match ip.parse::<IpAddr>().map_err(|_| bad())? {
                IpAddr::V4(ip) if prefix <= 32 => v4.push(cidr4(ip.octets(), prefix)),
                IpAddr::V6(ip) if prefix <= 128 => {
                    // `/128` is one address: no host bits (a shift by 128 would overflow).
                    let host = u128::MAX.checked_shr(prefix).unwrap_or(0);
                    let start = u128::from(ip);
                    v6.push((start & !host, start | host));
                }
                _ => return Err(bad()),
            }
        } else if let Some((a, b)) = token.split_once('-') {
            let a: Ipv4Addr = a.parse().map_err(|_| bad())?;
            let b: Ipv4Addr = if b.contains('.') {
                b.parse().map_err(|_| bad())?
            } else {
                let mut octets = a.octets();
                octets[3] = b.parse().map_err(|_| bad())?;
                Ipv4Addr::from(octets)
            };
            if u32::from(a) > u32::from(b) {
                return Err(format!("Scope range must run from low to high: {token}"));
            }
            v4.push((u32::from(a), u32::from(b)));
        } else {
            match token.parse::<IpAddr>().map_err(|_| bad())? {
                IpAddr::V4(ip) => v4.push((u32::from(ip), u32::from(ip))),
                IpAddr::V6(ip) => v6.push((u128::from(ip), u128::from(ip))),
            }
        }
        Ok(())
    }
    /// Reads a scope file; `Ok(None)` when the file does not exist.
    pub fn load(path: &Path) -> Result<Option<Self>, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        Self::parse(&text)
            .map(Some)
            .map_err(|e| format!("{}: {e}", path.display()))
    }
    /// True if `ip` (or the IPv4 address inside an IPv4-mapped one) is in the scope.
    pub fn contains(&self, ip: IpAddr) -> bool {
        if let Some(v4) = as_v4(ip) {
            return within(&self.v4, v4);
        }
        match ip {
            IpAddr::V6(v6) => within(&self.v6, u128::from(v6)),
            IpAddr::V4(_) => false,
        }
    }
    fn v4(&self) -> &[(u32, u32)] {
        &self.v4
    }
}

fn within<T: Ord + Copy>(ranges: &[(T, T)], v: T) -> bool {
    let i = ranges.partition_point(|r| r.1 < v);
    ranges.get(i).is_some_and(|r| r.0 <= v)
}

/// `scope.txt` in the per-user configuration folder (see `appdir`), next to the user
/// `cves.json` and `feeds.json`.
pub fn default_path() -> Option<PathBuf> {
    crate::appdir::file("scope.txt")
}

/// The declared scope: the explicit text (`--scope`), else the file at `file` when it exists.
/// `None` means no scope is declared (only the public-address rule applies).
pub fn declared(explicit: Option<&str>, file: Option<&Path>) -> Result<Option<Scope>, String> {
    match (explicit, file) {
        (Some(text), _) => Scope::parse(text).map(Some),
        (None, Some(path)) => Scope::load(path),
        (None, None) => Ok(None),
    }
}

/// The addresses an entry point is about to touch.
pub enum Addresses<'a> {
    Targets(&'a Targets),
    Hosts(&'a [IpAddr]),
}
impl<'a> From<&'a Targets> for Addresses<'a> {
    fn from(t: &'a Targets) -> Self {
        Self::Targets(t)
    }
}
impl<'a> From<&'a [IpAddr]> for Addresses<'a> {
    fn from(h: &'a [IpAddr]) -> Self {
        Self::Hosts(h)
    }
}
impl<'a> From<&'a Vec<IpAddr>> for Addresses<'a> {
    fn from(h: &'a Vec<IpAddr>) -> Self {
        Self::Hosts(h)
    }
}

/// What a set of addresses looks like against the rules.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Assessment {
    /// Addresses examined.
    pub total: u64,
    /// Public addresses that are not covered by a declared scope.
    pub public: u64,
    /// Addresses outside the declared scope (0 when no scope is declared).
    pub out_of_scope: u64,
    /// A scope was declared.
    pub scope_declared: bool,
    /// The first few public addresses, for the message.
    pub public_examples: Vec<IpAddr>,
    /// The first few out-of-scope addresses, for the message.
    pub out_of_scope_examples: Vec<IpAddr>,
}

/// What the user has already agreed to, usually by flags.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Consent {
    /// `--yes-public`: public addresses outside any declared scope may be scanned.
    pub public: bool,
    /// `--allow-out-of-scope`: addresses outside the declared scope may be scanned. This also
    /// covers public addresses outside the scope.
    pub out_of_scope: bool,
}

/// The check refused to continue. Nothing has been sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal(pub String);
impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Refusal {}

const EXAMPLES: usize = 3;

/// Subtracts the sorted, merged `holes` from the sorted, merged `ranges`.
fn subtract(ranges: &[(u32, u32)], holes: &[(u32, u32)]) -> Vec<(u32, u32)> {
    let mut out = vec![];
    for &(start, end) in ranges {
        let mut next = u64::from(start);
        for &(a, b) in holes.iter().filter(|h| h.1 >= start && h.0 <= end) {
            if u64::from(a) > next {
                out.push((next as u32, a - 1));
            }
            next = next.max(u64::from(b) + 1);
        }
        if next <= u64::from(end) {
            out.push((next as u32, end));
        }
    }
    out
}

fn size(ranges: &[(u32, u32)]) -> u64 {
    ranges.iter().map(|&(a, b)| u64::from(b - a) + 1).sum()
}

fn first_addresses(ranges: &[(u32, u32)]) -> Vec<IpAddr> {
    let mut out = vec![];
    for &(a, b) in ranges {
        let mut v = u64::from(a);
        while v <= u64::from(b) && out.len() < EXAMPLES {
            out.push(IpAddr::V4(Ipv4Addr::from(v as u32)));
            v += 1;
        }
    }
    out
}

/// Judges `addresses` against the public-address rule and the declared `scope`.
pub fn assess<'a>(addresses: impl Into<Addresses<'a>>, scope: Option<&Scope>) -> Assessment {
    let mut v4: Vec<(u32, u32)> = vec![];
    let mut v6: Vec<Ipv6Addr> = vec![];
    match addresses.into() {
        Addresses::Targets(t) => {
            let (singles, ranges) = t.spans();
            v4.extend(ranges);
            for ip in singles {
                match as_v4(ip) {
                    Some(v) => v4.push((v, v)),
                    None => {
                        if let IpAddr::V6(a) = ip {
                            v6.push(a)
                        }
                    }
                }
            }
        }
        Addresses::Hosts(hosts) => {
            for &ip in hosts {
                match as_v4(ip) {
                    Some(v) => v4.push((v, v)),
                    None => {
                        if let IpAddr::V6(a) = ip {
                            v6.push(a)
                        }
                    }
                }
            }
        }
    }
    let v4 = merge(v4);
    let mut a = Assessment {
        total: size(&v4) + v6.len() as u64,
        scope_declared: scope.is_some(),
        ..Assessment::default()
    };
    let mut public = subtract(&v4, &NON_PUBLIC_V4);
    if let Some(scope) = scope {
        public = subtract(&public, scope.v4());
        let outside = subtract(&v4, scope.v4());
        a.out_of_scope = size(&outside);
        a.out_of_scope_examples = first_addresses(&outside);
    }
    a.public = size(&public);
    a.public_examples = first_addresses(&public);
    for ip in v6 {
        let ip = IpAddr::V6(ip);
        let outside = scope.is_some_and(|s| !s.contains(ip));
        if outside {
            a.out_of_scope += 1;
            if a.out_of_scope_examples.len() < EXAMPLES {
                a.out_of_scope_examples.push(ip);
            }
        }
        if is_public(ip) && scope.is_none_or(|s| !s.contains(ip)) {
            a.public += 1;
            if a.public_examples.len() < EXAMPLES {
                a.public_examples.push(ip);
            }
        }
    }
    a
}

impl Assessment {
    /// True when the addresses need a confirmation that `consent` does not give.
    pub fn needs_confirmation(&self, consent: Consent) -> bool {
        let out = self.out_of_scope > 0 && !consent.out_of_scope;
        // `--allow-out-of-scope` also covers public addresses (they are outside the scope too).
        let public = self.public > 0 && !consent.public && !consent.out_of_scope;
        out || public
    }
    /// A plain-language description of what needs confirming, for the refusal, the prompt and
    /// the desktop dialog.
    pub fn describe(&self) -> String {
        let list = |ips: &[IpAddr]| {
            ips.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };
        let mut lines = vec![];
        if self.public > 0 {
            lines.push(format!(
                "{} public address(es) (for example {}) are not in a private or local range.",
                self.public,
                list(&self.public_examples)
            ));
        }
        if self.out_of_scope > 0 {
            lines.push(format!(
                "{} address(es) (for example {}) are outside the declared scope.",
                self.out_of_scope,
                list(&self.out_of_scope_examples)
            ));
        }
        lines.join(" ")
    }
}

/// The one scope check. Returns the assessment when scanning may go ahead:
///
/// - the addresses are private (or inside the declared scope), or
/// - `consent` covers everything that needs confirming, or
/// - `confirm` is given and answers yes to the description (an interactive entry point passes a
///   prompt; unattended ones pass `None`).
///
/// Otherwise it returns a [`Refusal`] and the caller must not send anything.
pub fn enforce<'a>(
    addresses: impl Into<Addresses<'a>>,
    scope: Option<&Scope>,
    consent: Consent,
    confirm: Option<&mut dyn FnMut(&str) -> bool>,
) -> Result<Assessment, Refusal> {
    let a = assess(addresses, scope);
    if !a.needs_confirmation(consent) {
        return Ok(a);
    }
    let what = a.describe();
    if let Some(confirm) = confirm
        && confirm(&what)
    {
        return Ok(a);
    }
    let mut flags = vec![];
    if a.out_of_scope > 0 && !consent.out_of_scope {
        flags.push("--allow-out-of-scope");
    }
    if a.public > 0 && !consent.public && !consent.out_of_scope {
        flags.push("--yes-public");
    }
    Err(Refusal(format!(
        "Scope guard: {what} Nothing was sent. Only scan networks you are authorized to test; \
         to proceed anyway, pass {}{}.",
        flags.join(" and "),
        if a.scope_declared {
            ""
        } else {
            " or declare the range with --scope"
        }
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn an_ipv6_host_entry_with_prefix_128_is_one_address() {
        // Found by the scope_file fuzz target: the shift by 128 overflowed and panicked.
        let s = Scope::parse("2001:db8::1/128\n::/0\n").unwrap();
        assert!(s.contains(ip("2001:db8::1")));
        let one = Scope::parse("2001:db8::1/128").unwrap();
        assert!(one.contains(ip("2001:db8::1")));
        assert!(!one.contains(ip("2001:db8::2")));
        assert!(Scope::parse("2001:db8::1/129").is_err());
    }

    #[test]
    fn public_address_table() {
        // (address, public?) including every block edge.
        for (addr, public) in [
            ("10.0.0.0", false),
            ("10.255.255.255", false),
            ("9.255.255.255", true),
            ("11.0.0.0", true),
            ("172.15.255.255", true),
            ("172.16.0.0", false),
            ("172.31.255.255", false),
            ("172.32.0.0", true),
            ("192.167.255.255", true),
            ("192.168.0.0", false),
            ("192.168.255.255", false),
            ("192.169.0.0", true),
            ("100.63.255.255", true),
            ("100.64.0.0", false),
            ("100.127.255.255", false),
            ("100.128.0.0", true),
            ("127.0.0.1", false),
            ("127.255.255.255", false),
            ("128.0.0.0", true),
            ("169.253.255.255", true),
            ("169.254.0.0", false),
            ("169.254.255.255", false),
            ("169.255.0.0", true),
            ("0.0.0.0", false),
            ("0.255.255.255", false),
            ("1.0.0.0", true),
            ("8.8.8.8", true),
            ("1.1.1.1", true),
            ("224.0.0.1", true),
            ("255.255.255.255", true),
            ("::1", false),
            ("::", false),
            ("fc00::", false),
            ("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("fbff::1", true),
            ("fe00::1", true),
            ("fe80::1", false),
            ("febf::1", false),
            ("fec0::1", true),
            ("2001:4860:4860::8888", true),
            ("2606:4700::1111", true),
            // IPv4-mapped IPv6 follows the IPv4 rules.
            ("::ffff:8.8.8.8", true),
            ("::ffff:10.0.0.1", false),
            ("::ffff:127.0.0.1", false),
            ("::ffff:172.32.0.1", true),
        ] {
            assert_eq!(is_public(ip(addr)), public, "{addr}");
        }
    }

    #[test]
    fn scope_parsing_and_membership() {
        let s = Scope::parse(
            "10.0.0.0/8, 192.168.1.7 # a lab host\n172.20.0.1-172.20.0.9\n172.21.0.1-9\nfd00::/8 2001:db8::1",
        )
        .unwrap();
        for (addr, inside) in [
            ("10.1.2.3", true),
            ("11.0.0.1", false),
            ("192.168.1.7", true),
            ("192.168.1.8", false),
            ("172.20.0.5", true),
            ("172.20.0.10", false),
            ("172.21.0.9", true),
            ("172.21.0.10", false),
            ("fd12::1", true),
            ("fe80::1", false),
            ("2001:db8::1", true),
            ("2001:db8::2", false),
            ("::ffff:10.1.2.3", true),
            ("::ffff:11.1.2.3", false),
        ] {
            assert_eq!(s.contains(ip(addr)), inside, "{addr}");
        }
        for bad in [
            "",
            "# only a comment",
            "10.0.0.0/33",
            "10.0.0.0/x",
            "10.0.0.256",
            "banana",
            "10.0.0.9-10.0.0.1",
            "::1/129",
            "10.0.0.1-300",
        ] {
            assert!(Scope::parse(bad).is_err(), "{bad:?}");
        }
        let many = "10.0.0.1 ".repeat(MAX_SCOPE_ENTRIES + 1);
        assert!(Scope::parse(&many).is_err());
        assert!(Scope::parse(&"1".repeat(200)).is_err());
        // /0 covers everything.
        let all = Scope::parse("0.0.0.0/0").unwrap();
        assert!(all.contains(ip("8.8.8.8")) && all.contains(ip("255.255.255.255")));
    }

    #[test]
    fn scope_files_load_and_missing_file_is_no_scope() {
        let dir = std::env::temp_dir().join(format!("ns-scope-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("scope.txt");
        assert_eq!(Scope::load(&file), Ok(None));
        std::fs::write(&file, "# office\n192.168.1.0/24\n").unwrap();
        let s = Scope::load(&file).unwrap().unwrap();
        assert!(s.contains(ip("192.168.1.9")) && !s.contains(ip("192.168.2.9")));
        std::fs::write(&file, "not a scope\n").unwrap();
        assert!(Scope::load(&file).unwrap_err().contains("scope.txt"));
        // The explicit text wins over the file.
        assert!(declared(Some("10.0.0.0/8"), Some(&file)).unwrap().is_some());
        assert_eq!(declared(None, None), Ok(None));
        assert!(declared(Some("junk"), None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn targets(text: &str) -> Targets {
        crate::scan::parse_targets(text, true, crate::scan::MAX_STREAM).unwrap()
    }

    #[test]
    fn assessment_table_without_a_declared_scope() {
        // (targets, public addresses)
        for (text, public) in [
            ("192.168.1.0/24", 0),
            ("10.0.0.0/8", 0),
            ("127.0.0.1", 0),
            ("172.16.0.0/12", 0),
            ("100.64.0.0/10", 0),
            ("169.254.1.1", 0),
            ("::1", 0),
            ("fd00::1", 0),
            ("8.8.8.8", 1),
            ("8.8.8.8 192.168.1.1", 1),
            ("172.15.255.254-172.16.0.2", 2), // 172.15.255.254 and .255 are public
            ("172.32.0.1-172.32.0.4", 4),
            ("2001:4860:4860::8888", 1),
            ("1.0.0.0/24", 254),
        ] {
            let a = assess(&targets(text), None);
            assert_eq!(a.public, public, "{text}");
            assert_eq!(a.out_of_scope, 0, "{text}: no scope declared");
            assert!(!a.scope_declared);
            assert_eq!(
                a.needs_confirmation(Consent::default()),
                public > 0,
                "{text}"
            );
        }
        // A /8 is judged without expanding it; 11.0.0.0/8 is entirely public.
        let big = assess(&targets("11.0.0.0/8"), None);
        assert_eq!(big.public, (1 << 24) - 2);
        assert_eq!(
            big.public_examples,
            [ip("11.0.0.1"), ip("11.0.0.2"), ip("11.0.0.3")]
        );
        // A range straddling private and public space only counts the public part.
        let straddle = assess(&targets("192.167.255.250-192.168.0.5"), None);
        // 192.167.255.250-255: a dash range is judged whole, including the edge it skips.
        assert_eq!(straddle.public, 6);
        let hosts = [
            ip("10.0.0.1"),
            ip("1.2.3.4"),
            ip("::ffff:8.8.4.4"),
            ip("fe80::2"),
        ];
        let a = assess(&hosts[..], None);
        assert_eq!((a.total, a.public), (4, 2));
    }

    #[test]
    fn assessment_with_a_declared_scope() {
        let scope = Scope::parse("192.168.1.0/24, 203.0.113.0/28, fd00::/8").unwrap();
        // Inside the scope: fine, including a public range the user declared.
        let a = assess(&targets("192.168.1.5 203.0.113.3"), Some(&scope));
        assert_eq!((a.public, a.out_of_scope), (0, 0));
        assert!(!a.needs_confirmation(Consent::default()));
        // A private address outside the scope.
        let a = assess(&targets("192.168.2.5"), Some(&scope));
        assert_eq!((a.public, a.out_of_scope), (0, 1));
        assert!(a.needs_confirmation(Consent::default()));
        assert!(a.needs_confirmation(Consent {
            public: true,
            out_of_scope: false
        }));
        assert!(!a.needs_confirmation(Consent {
            public: false,
            out_of_scope: true
        }));
        // A public address outside the scope needs --allow-out-of-scope; --yes-public alone is
        // not enough because the address is also out of scope.
        let a = assess(&targets("8.8.8.8"), Some(&scope));
        assert_eq!((a.public, a.out_of_scope), (1, 1));
        assert!(a.needs_confirmation(Consent {
            public: true,
            out_of_scope: false
        }));
        assert!(!a.needs_confirmation(Consent {
            public: false,
            out_of_scope: true
        }));
        // Part of a range outside: only that part is counted.
        let a = assess(&targets("203.0.113.0/27"), Some(&scope));
        assert_eq!(
            a.out_of_scope, 15,
            "203.0.113.16-30 of the /27 (edges skipped)"
        );
        // IPv6.
        let a = assess(
            &[ip("fd00::5"), ip("fe80::5"), ip("2001:db8::5")][..],
            Some(&scope),
        );
        assert_eq!((a.public, a.out_of_scope), (1, 2));
    }

    #[test]
    fn enforce_refuses_unless_flagged_or_confirmed() {
        let private = targets("192.168.1.0/30");
        assert!(enforce(&private, None, Consent::default(), None).is_ok());
        let public = targets("8.8.8.8");
        let refusal = enforce(&public, None, Consent::default(), None).unwrap_err();
        assert!(refusal.0.contains("1 public address"), "{refusal}");
        assert!(refusal.0.contains("--yes-public") && refusal.0.contains("Nothing was sent"));
        assert!(refusal.0.contains("8.8.8.8") && refusal.0.contains("--scope"));
        // Flags.
        let yes = Consent {
            public: true,
            out_of_scope: false,
        };
        assert!(enforce(&public, None, yes, None).is_ok());
        // Interactive answer: yes and no; the description reaches the prompt.
        let mut asked = vec![];
        let mut yes_prompt = |text: &str| {
            asked.push(text.to_string());
            true
        };
        assert!(enforce(&public, None, Consent::default(), Some(&mut yes_prompt)).is_ok());
        assert_eq!(asked.len(), 1);
        assert!(asked[0].contains("8.8.8.8"));
        let mut no_prompt = |_: &str| false;
        assert!(enforce(&public, None, Consent::default(), Some(&mut no_prompt)).is_err());
        // The prompt is not asked when nothing needs confirming.
        let mut never = |_: &str| panic!("must not prompt for private targets");
        assert!(enforce(&private, None, Consent::default(), Some(&mut never)).is_ok());
        // Out of scope names the right flag.
        let scope = Scope::parse("10.0.0.0/8").unwrap();
        let out = targets("192.168.1.1");
        let refusal = enforce(&out, Some(&scope), Consent::default(), None).unwrap_err();
        assert!(refusal.0.contains("--allow-out-of-scope"), "{refusal}");
        assert!(!refusal.0.contains("--yes-public"), "{refusal}");
        assert!(
            enforce(
                &out,
                Some(&scope),
                Consent {
                    public: false,
                    out_of_scope: true
                },
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn the_check_does_not_touch_the_network() {
        let source = include_str!("scope.rs");
        let code = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "TcpStream",
            "UdpSocket",
            "tokio::net",
            "capture::",
            "connect(",
        ] {
            assert!(
                !code.contains(forbidden),
                "scope.rs must not use {forbidden}"
            );
        }
    }
}
