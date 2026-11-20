//! One record per device. Active scan results and passive observations are merged on the MAC
//! address (or on the IP address when no MAC is known), then enriched with the manufacturer
//! from the embedded IEEE registry and a scored device-type guess.
use crate::{
    evidence::{Evidence, confidence_from_scores},
    oui,
    passive::Observation,
    scan::Host,
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::IpAddr,
};

/// What the classifier looks at: everything known about one device.
pub struct Facts<'a> {
    pub mac: &'a str,
    pub vendor: &'a str,
    pub tcp: &'a [u16],
    pub udp: &'a [u16],
    pub identity: &'a BTreeMap<String, String>,
    pub hostnames: &'a [String],
    pub os: &'a str,
    pub ttl: Option<u8>,
    pub protocols: &'a [String],
}

#[derive(Default)]
struct Scores(BTreeMap<&'static str, (i32, Vec<String>)>);
impl Scores {
    fn add(&mut self, kind: &'static str, points: i32, why: impl Into<String>) {
        let e = self.0.entry(kind).or_default();
        e.0 += points;
        e.1.push(why.into());
    }
}
fn has(text: &str, needles: &[&str]) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    needles
        .iter()
        .find(|n| lower.contains(*n))
        .map(|n| (*n).to_string())
}

const OT: &str = "Industrial controller / OT device";
const PRINTER: &str = "Printer / MFP";
const CAMERA: &str = "IP camera / recorder";
const NETWORK: &str = "Network device (router/switch/AP)";
const WINDOWS: &str = "Windows computer";
const LINUX: &str = "Linux/Unix host";
const APPLE: &str = "Apple device";
const MEDIA: &str = "Media / smart TV device";
const IOT: &str = "IoT / embedded device";
const SBC: &str = "Single-board computer";
const DATABASE: &str = "Database server";
const VOIP: &str = "VoIP phone";
const NAS: &str = "NAS / storage";
const MOBILE: &str = "Smartphone / tablet";

/// Identity keys that carry passive hints (see `passive::hints`): `passive.hint.<category>` for
/// strong and `passive.hint_weak.<category>` for weak evidence, the value being the reason.
const PASSIVE_HINT: &str = "passive.hint.";
const PASSIVE_HINT_WEAK: &str = "passive.hint_weak.";

fn hint_kind(category: &str) -> Option<&'static str> {
    Some(match category {
        "printer" => PRINTER,
        "camera" => CAMERA,
        "network" => NETWORK,
        "windows" => WINDOWS,
        "linux" => LINUX,
        "apple" => APPLE,
        "media" => MEDIA,
        "iot" => IOT,
        "voip" => VOIP,
        "nas" => NAS,
        "mobile" => MOBILE,
        _ => return None,
    })
}

const VIRTUAL_PREFIXES: [&str; 8] = [
    "005056", "000C29", "000569", "001C14", "080027", "525400", "00155D", "00163E",
];

pub fn is_virtual_mac(mac: &str) -> bool {
    let hex: String = mac
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    VIRTUAL_PREFIXES.iter().any(|p| hex.starts_with(p))
}

/// Derived keys that describe software configuration, not the device: CPE names (user
/// templates are free text), SSH HASSH and TLS JA4S fingerprints. Keyword rules skip them.
const NON_EVIDENCE_SUFFIXES: [&str; 9] = [
    ".cpe",
    ".hassh",
    ".hassh_algorithms",
    ".ja4s",
    ".ja4x",
    ".confidence",
    ".jarm",
    ".favicon_mmh3",
    ".self_signature",
];
fn is_device_evidence(key: &str) -> bool {
    // Passive hints are scored by their own rule; their reasons must not feed keyword matching.
    !key.starts_with("passive.")
        && !crate::incremental::is_marker(key)
        && !NON_EVIDENCE_SUFFIXES.iter().any(|s| key.ends_with(s))
}

/// (device type, evidence) when the combined evidence is strong enough.
pub fn classify(e: &Facts) -> Option<(String, String)> {
    classify_detailed(e).map(|(kind, why)| (kind, why.because()))
}

/// The device type with its reasons and a confidence score (0-100): the evidence behind the
/// winning type, plus half of its lead over the runner-up.
pub fn classify_detailed(e: &Facts) -> Option<(String, Evidence)> {
    let mut s = Scores::default();
    let all_text = e
        .identity
        .iter()
        .filter(|(k, _)| is_device_evidence(k))
        .map(|(_, v)| v.clone())
        .chain(e.hostnames.iter().cloned())
        .collect::<Vec<_>>()
        .join(" | ");
    let http_text = e
        .identity
        .iter()
        .filter(|(k, _)| is_device_evidence(k))
        .filter(|(k, _)| {
            k.starts_with("http.")
                || k.starts_with("svc.")
                || k.starts_with("udp.")
                || k.starts_with("banner.")
        })
        .map(|(_, v)| v.as_str())
        .collect::<Vec<_>>()
        .join(" | ");
    let tcp = |p: u16| e.tcp.contains(&p);
    let udp = |p: u16| e.udp.contains(&p);

    for p in [
        102u16, 502, 44818, 4840, 47808, 20000, 2404, 9600, 1911, 34962, 34964,
    ] {
        if tcp(p) {
            s.add(OT, 35, format!("OT port {p}"));
        }
    }
    if e.identity.keys().any(|k| {
        ["Modbus.", "S7.", "OPC UA.", "EtherNet/IP.", "BACnet."]
            .iter()
            .any(|p| k.starts_with(p))
    }) {
        s.add(OT, 60, "OT protocol identity answered");
    }
    if e.protocols.iter().any(|p| p == "Profinet DCP") {
        s.add(OT, 60, "Profinet DCP announcement");
    }
    if let Some(v) = has(
        e.vendor,
        &[
            "siemens",
            "rockwell",
            "schneider",
            "beckhoff",
            "phoenix contact",
            "wago",
            "omron",
            "mitsubishi electric",
            "abb ",
            "honeywell",
            "moxa",
            "hirschmann",
            "pilz",
            "festo",
            "turck",
            "b&r",
            "bosch rexroth",
            "yokogawa",
        ],
    ) && s.0.contains_key(OT)
    {
        s.add(OT, 15, format!("industrial vendor ({v})"));
    }

    for p in [9100u16, 515, 631] {
        if tcp(p) {
            s.add(PRINTER, 25, format!("print port {p}"));
        }
    }
    if let Some(w) = has(
        &all_text,
        &[
            "laserjet",
            "officejet",
            "deskjet",
            "imageclass",
            "bizhub",
            "mfp",
            "printer",
            "ricoh",
            "xerox",
            "kyocera",
            "lexmark",
            "epson",
            "brother",
            "jetdirect",
            "ipp",
        ],
    ) {
        s.add(PRINTER, 40, format!("service text mentions {w}"));
    }
    if has(
        e.vendor,
        &[
            "hewlett",
            "canon",
            "brother",
            "seiko epson",
            "xerox",
            "lexmark",
            "ricoh",
            "kyocera",
            "konica",
            "oki data",
        ],
    )
    .is_some()
        && (tcp(9100) || tcp(515) || tcp(631) || has(&all_text, &["print"]).is_some())
    {
        s.add(PRINTER, 15, "printer vendor OUI");
    }

    for p in [554u16, 8554] {
        if tcp(p) {
            s.add(CAMERA, 30, format!("RTSP port {p}"));
        }
    }
    if let Some(w) = has(
        &http_text,
        &[
            "camera",
            "ipcam",
            "dvr",
            "nvr",
            "hikvision",
            "dahua",
            "axis ",
            "onvif",
            "netcam",
        ],
    ) {
        s.add(CAMERA, 35, format!("service text mentions {w}"));
    }
    if let Some(v) = has(
        e.vendor,
        &[
            "hikvision",
            "dahua",
            "axis comm",
            "hanwha",
            "vivotek",
            "reolink",
            "amcrest",
            "foscam",
            "uniview",
        ],
    ) {
        s.add(CAMERA, 30, format!("camera vendor ({v})"));
    }

    if let Some(v) = has(
        e.vendor,
        &[
            "cisco",
            "juniper",
            "arista",
            "mikrotik",
            "ubiquiti",
            "aruba",
            "ruckus",
            "fortinet",
            "palo alto",
            "netgear",
            "tp-link",
            "d-link",
            "zyxel",
            "huawei",
            "h3c",
            "extreme networks",
            "avm",
            "sagemcom",
        ],
    ) {
        s.add(NETWORK, 25, format!("network vendor ({v})"));
    }
    if e.os.starts_with("Network device") {
        s.add(NETWORK, 30, "OS fingerprint: network device");
    }
    if e.ttl == Some(255) || e.ttl.is_some_and(|t| t > 128) {
        s.add(NETWORK, 10, "initial TTL 255");
    }
    if udp(161) {
        s.add(NETWORK, 10, "SNMP agent");
    }
    if udp(67) {
        s.add(NETWORK, 25, "answers DHCP (router or DHCP server)");
    }
    if let Some(w) = has(
        &http_text,
        &[
            "router",
            "gateway",
            "access point",
            "openwrt",
            "dd-wrt",
            "routeros",
            "pfsense",
            "opnsense",
            "fritz",
            "switch",
            "ubnt",
            "unifi",
        ],
    ) {
        s.add(NETWORK, 35, format!("service text mentions {w}"));
    }
    if has(&all_text, &["internetgatewaydevice"]).is_some() {
        s.add(NETWORK, 40, "UPnP InternetGatewayDevice");
    }
    // Switches send LLDP/CDP, but so do IP phones, access points and servers. The announcement
    // counts only when no passive hint names a more specific kind of device (e.g. a phone).
    let specific_hint = e.identity.keys().any(|k| {
        k.strip_prefix(PASSIVE_HINT)
            .is_some_and(|c| c != "network" && hint_kind(c).is_some())
    });
    if !specific_hint {
        for protocol in ["LLDP", "CDP"] {
            if e.protocols.iter().any(|p| p == protocol) {
                s.add(NETWORK, 25, format!("{protocol} announcement"));
            }
        }
    }
    // Passive hints (mDNS/SSDP/WS-Discovery services, DHCP fingerprints, LLDP/CDP capabilities).
    // A strong hint is enough on its own; weak ones only add up with other evidence. A weak
    // hint is ignored when the same category has a strong one.
    for (key, why) in e.identity {
        let (category, strong) = match (
            key.strip_prefix(PASSIVE_HINT),
            key.strip_prefix(PASSIVE_HINT_WEAK),
        ) {
            (Some(c), _) => (c, true),
            (None, Some(c)) if !e.identity.contains_key(&format!("{PASSIVE_HINT}{c}")) => {
                (c, false)
            }
            _ => continue,
        };
        if let Some(kind) = hint_kind(category) {
            s.add(
                kind,
                if strong { 40 } else { 20 },
                format!("passive: {why}"),
            );
        }
    }

    if e.os == "Windows" {
        s.add(WINDOWS, 40, "OS fingerprint: Windows");
    }
    let win_ports = [445u16, 135, 3389, 5985, 139]
        .iter()
        .filter(|p| tcp(**p))
        .count() as i32;
    if win_ports > 0 {
        s.add(WINDOWS, (win_ports * 10).min(30), "Windows service ports");
    }
    if udp(137) {
        s.add(WINDOWS, 15, "NetBIOS name service");
    }
    if e.os == "Linux" || e.os == "BSD" {
        s.add(LINUX, 30, format!("OS fingerprint: {}", e.os));
    }
    if tcp(22) {
        s.add(LINUX, 12, "SSH");
    }
    if has(e.vendor, &["apple"]).is_some() {
        s.add(APPLE, 40, "Apple vendor OUI");
    }
    if tcp(62078) || has(&all_text, &["airplay", "_companion-link", "_apple-mobdev"]).is_some() {
        s.add(APPLE, 30, "Apple services");
    }
    if e.os == "macOS/iOS" {
        s.add(APPLE, 25, "OS fingerprint: Apple");
    }
    for p in [8008u16, 8009, 8060] {
        if tcp(p) {
            s.add(MEDIA, 25, format!("media port {p}"));
        }
    }
    if let Some(w) = has(
        &all_text,
        &[
            "dlna",
            "roku",
            "chromecast",
            "webos",
            "sonos",
            "smarttv",
            "mediarenderer",
            "mediaserver",
        ],
    ) {
        s.add(MEDIA, 35, format!("service text mentions {w}"));
    }
    if has(e.vendor, &["roku", "sonos", "vizio", "tcl"]).is_some() {
        s.add(MEDIA, 30, "media vendor OUI");
    }
    if has(
        e.vendor,
        &["espressif", "tuya", "shelly", "sonoff", "particle"],
    )
    .is_some()
    {
        s.add(IOT, 45, "IoT module vendor OUI");
    }
    if tcp(1883) {
        s.add(IOT, 30, "MQTT broker");
    }
    if e.os == "Embedded Linux/RTOS" {
        s.add(IOT, 20, "OS fingerprint: embedded");
    }
    if has(e.vendor, &["raspberry"]).is_some() {
        s.add(SBC, 50, "Raspberry Pi vendor OUI");
    }
    for (p, name) in [
        (3306u16, "MySQL"),
        (5432, "PostgreSQL"),
        (1433, "SQL Server"),
        (27017, "MongoDB"),
        (6379, "Redis"),
        (1521, "Oracle"),
    ] {
        if tcp(p) {
            s.add(DATABASE, 40, format!("{name} port {p}"));
        }
    }
    if tcp(5060) || tcp(5061) {
        s.add(VOIP, 25, "SIP port");
    }
    if has(
        e.vendor,
        &[
            "yealink",
            "polycom",
            "grandstream",
            "snom",
            "avaya",
            "mitel",
            "fanvil",
        ],
    )
    .is_some()
    {
        s.add(VOIP, 40, "VoIP vendor OUI");
    }
    if has(
        e.vendor,
        &[
            "synology",
            "qnap",
            "western digital",
            "readynas",
            "asustor",
            "terramaster",
        ],
    )
    .is_some()
    {
        s.add(NAS, 40, "NAS vendor OUI");
    }
    if has(
        &http_text,
        &[
            "diskstation",
            "synology",
            "qnap",
            "truenas",
            "freenas",
            "readynas",
        ],
    )
    .is_some()
    {
        s.add(NAS, 40, "NAS web interface");
    }
    if tcp(2049) || tcp(548) {
        s.add(NAS, 20, "file-sharing ports");
    }

    let mut ranked: Vec<_> = s.0.into_iter().collect();
    ranked.sort_by_key(|(name, (score, _))| (-*score, *name));
    let (name, (score, why)) = ranked.first()?.clone();
    if score < 30 {
        return None;
    }
    let runner_up = ranked.get(1).map_or(0, |(_, (v, _))| *v);
    let mut kind = name.to_string();
    let mut why = why;
    if is_virtual_mac(e.mac) {
        kind.push_str(" [virtual machine]");
        why.push("virtual-machine MAC prefix".into());
    }
    Some((
        kind,
        Evidence::new(why, confidence_from_scores(score, runner_up)),
    ))
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Device {
    pub id: String,
    pub mac: String,
    pub vendor: String,
    /// The MAC is locally administered (randomised or assigned by software), so it can change.
    pub randomized_mac: bool,
    /// The stable device key (see [`crate::identity`]): empty until the device is matched
    /// against the inventory (`store::resolve_devices`); `id` is the key of this scan alone.
    pub key: String,
    /// What the device can be recognised by across scans (MAC, host name, certificate key, ...).
    pub identifiers: Vec<crate::identity::Identifier>,
    pub ips: Vec<IpAddr>,
    pub hostnames: Vec<String>,
    pub device_type: String,
    pub type_evidence: String,
    pub os: String,
    pub os_confidence: String,
    /// Why the device type was concluded, with a 0-100 confidence (also in `type_evidence`).
    #[serde(skip_serializing_if = "Evidence::is_empty")]
    pub device_type_evidence: Evidence,
    /// Why the OS family was guessed, with a 0-100 confidence (also in `os_confidence`).
    #[serde(skip_serializing_if = "Evidence::is_empty")]
    pub os_evidence: Evidence,
    pub open_tcp: Vec<u16>,
    pub open_udp: Vec<u16>,
    pub services: BTreeMap<String, String>,
    pub sources: Vec<String>,
    pub observations: BTreeMap<String, BTreeMap<String, String>>,
    /// Names that came only from SMB/NTLM (`smb.<port>.netbios_name` / `dns_name`); also in
    /// `hostnames`. History ignores them so scans with and without `--services` compare equal.
    #[serde(skip)]
    pub smb_names: Vec<String>,
}

#[derive(Default)]
struct Acc {
    mac: String,
    ips: BTreeSet<IpAddr>,
    hostnames: BTreeSet<String>,
    tcp: BTreeSet<u16>,
    udp: BTreeSet<u16>,
    identity: BTreeMap<String, String>,
    sources: BTreeSet<String>,
    observations: BTreeMap<String, BTreeMap<String, String>>,
    ttl: Option<u8>,
}

fn norm_mac(mac: &str) -> String {
    let hex: String = mac
        .chars()
        .filter(char::is_ascii_hexdigit)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if hex.len() != 12 {
        return String::new();
    }
    hex.as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn merge(hosts: &[Host], observations: &[Observation]) -> Vec<Device> {
    let mut accs: BTreeMap<String, Acc> = BTreeMap::new();
    let mut by_ip: HashMap<IpAddr, String> = HashMap::new();
    // device key -> IP -> other MACs claiming the same IP (IP reassignment, address conflicts,
    // proxy ARP, VRRP/HSRP virtual MACs). Both devices are kept; the conflict is noted on each.
    let mut conflicts: BTreeMap<String, BTreeMap<String, BTreeSet<String>>> = BTreeMap::new();
    let rekey = |accs: &mut BTreeMap<String, Acc>,
                 by_ip: &mut HashMap<IpAddr, String>,
                 from: &str,
                 to: &str| {
        if from == to {
            return;
        }
        if let Some(old) = accs.remove(from) {
            let target = accs.entry(to.to_string()).or_default();
            target.ips.extend(old.ips.iter().copied());
            target.hostnames.extend(old.hostnames);
            target.tcp.extend(old.tcp);
            target.udp.extend(old.udp);
            target.sources.extend(old.sources);
            for (k, v) in old.identity {
                target.identity.entry(k).or_insert(v);
            }
            for (k, v) in old.observations {
                target.observations.entry(k).or_default().extend(v);
            }
            target.ttl = target.ttl.or(old.ttl);
            for ip in old.ips {
                by_ip.insert(ip, to.to_string());
            }
        }
    };
    // Only an IP-keyed record is folded into the MAC that shows up for its address; a record that
    // already has a MAC stays a separate device even if another MAC claims the same IP.
    let mut claim = |accs: &mut BTreeMap<String, Acc>,
                     by_ip: &mut HashMap<IpAddr, String>,
                     ip: IpAddr,
                     key: &str| {
        let Some(existing) = by_ip.get(&ip).cloned() else {
            return;
        };
        if existing.starts_with("ip:") {
            rekey(accs, by_ip, &existing, key);
        } else if existing != key {
            for (a, b) in [(existing.as_str(), key), (key, existing.as_str())] {
                conflicts
                    .entry(a.to_string())
                    .or_default()
                    .entry(ip.to_string())
                    .or_default()
                    .insert(b.to_string());
            }
        }
    };
    for h in hosts.iter().filter(|h| h.responding) {
        let mac = norm_mac(&h.mac);
        let key = if mac.is_empty() {
            format!("ip:{}", h.ip)
        } else {
            mac.clone()
        };
        if !mac.is_empty() {
            claim(&mut accs, &mut by_ip, h.ip, &key);
        }
        let a = accs.entry(key.clone()).or_default();
        a.mac = mac;
        a.ips.insert(h.ip);
        if !h.hostname.is_empty() {
            a.hostnames.insert(h.hostname.clone());
        }
        a.tcp.extend(h.open.iter().copied());
        a.udp.extend(h.udp_open.iter().copied());
        a.identity.extend(h.identity.clone());
        a.sources.insert("active scan".into());
        a.ttl = a.ttl.or(h.ttl);
        // The first device seen at an address keeps it for IP-only records that follow.
        by_ip.entry(h.ip).or_insert(key);
    }
    // A routed Windows host answering on several addresses (no MAC visible) is one device when
    // the addresses report the same SMB server GUID and NetBIOS name. The GUID alone is not
    // enough (cloned VMs share it), and records with a MAC are never merged this way.
    let mut by_smb: BTreeMap<(String, String), String> = BTreeMap::new();
    let ip_keys: Vec<String> = accs
        .keys()
        .filter(|k| k.starts_with("ip:"))
        .cloned()
        .collect();
    for key in ip_keys {
        let Some(identity) = accs.get(&key).map(|a| smb_identity(&a.identity)) else {
            continue;
        };
        let Some(id) = identity else {
            continue;
        };
        match by_smb.get(&id) {
            Some(first) => rekey(&mut accs, &mut by_ip, &key, &first.clone()),
            None => {
                by_smb.insert(id, key);
            }
        }
    }
    for o in observations {
        let mac = norm_mac(&o.mac);
        let key = if !mac.is_empty() {
            if let Some(ip) = o.ip {
                claim(&mut accs, &mut by_ip, ip, &mac);
            }
            mac.clone()
        } else if let Some(k) = o.ip.and_then(|ip| by_ip.get(&ip).cloned()) {
            k
        } else if let Some(ip) = o.ip {
            format!("ip:{ip}")
        } else {
            continue;
        };
        let a = accs.entry(key.clone()).or_default();
        if a.mac.is_empty() {
            a.mac = mac;
        }
        if let Some(ip) = o.ip {
            a.ips.insert(ip);
            by_ip.entry(ip).or_insert_with(|| key.clone());
        }
        for field in ["hostname", "name"] {
            if let Some(n) = o.fields.get(field).filter(|n| !n.is_empty())
                && o.protocol != "ARP"
            {
                a.hostnames.insert(n.clone());
            }
        }
        a.sources.insert(format!("passive {}", o.protocol));
        a.observations
            .entry(o.protocol.clone())
            .or_default()
            .extend(o.fields.clone());
    }
    accs.into_iter()
        .map(|(key, a)| {
            let conflict = conflicts.remove(&key);
            let vendor = if a.mac.is_empty() || oui::locally_administered(&a.mac) {
                String::new()
            } else {
                oui::vendor(&a.mac).unwrap_or("").to_string()
            };
            let smb_names: Vec<String> = smb_names(&a.identity)
                .into_iter()
                .filter(|n| !a.hostnames.contains(n))
                .collect();
            let hostnames: Vec<String> = a
                .hostnames
                .into_iter()
                .chain(smb_names.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let (tcp, udp): (Vec<u16>, Vec<u16>) =
                (a.tcp.into_iter().collect(), a.udp.into_iter().collect());
            let os = a.identity.get("os.guess").cloned().unwrap_or_default();
            let protocols: Vec<String> = a.observations.keys().cloned().collect();
            // Classification input: the active identity plus the passive hints, as if the scan
            // had reported them. `a.identity` itself stays active-only (services, OS).
            let mut identity = a.identity.clone();
            for fields in a.observations.values() {
                for (category, strong, why) in crate::passive::hints::stored(fields) {
                    let key = format!(
                        "{}{category}",
                        if strong {
                            PASSIVE_HINT
                        } else {
                            PASSIVE_HINT_WEAK
                        }
                    );
                    let reasons = identity.entry(key).or_default();
                    if !reasons.contains(&why) && reasons.len() < 300 {
                        if !reasons.is_empty() {
                            reasons.push_str("; ");
                        }
                        reasons.push_str(&why);
                    }
                }
            }
            let (device_type, device_type_evidence) = classify_detailed(&Facts {
                mac: &a.mac,
                vendor: &vendor,
                tcp: &tcp,
                udp: &udp,
                identity: &identity,
                hostnames: &hostnames,
                os: &os,
                ttl: a.ttl,
                protocols: &protocols,
            })
            .unwrap_or_default();
            let services = a
                .identity
                .iter()
                .filter(|(k, _)| k.starts_with("svc.") || k.starts_with("udp."))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let ips: Vec<IpAddr> = a.ips.into_iter().collect();
            let identifiers = crate::identity::identifiers(
                &a.mac,
                &ips,
                &hostnames,
                &a.identity,
                &a.observations,
            );
            Device {
                id: key,
                randomized_mac: !a.mac.is_empty() && oui::locally_administered(&a.mac),
                key: String::new(),
                identifiers,
                mac: a.mac,
                vendor,
                ips,
                hostnames,
                device_type,
                type_evidence: device_type_evidence.because(),
                device_type_evidence,
                os_evidence: Evidence::from_identity(&a.identity, "os").unwrap_or_default(),
                os,
                os_confidence: a.identity.get("os.confidence").cloned().unwrap_or_default(),
                open_tcp: tcp,
                open_udp: udp,
                services,
                sources: a.sources.into_iter().collect(),
                smb_names,
                observations: {
                    let mut observations = a.observations;
                    if let Some(c) = conflict {
                        observations.insert(
                            "IP conflict".into(),
                            c.into_iter()
                                .map(|(ip, macs)| {
                                    (ip, macs.into_iter().collect::<Vec<_>>().join(", "))
                                })
                                .collect(),
                        );
                    }
                    observations
                },
            }
        })
        .collect()
}

/// (server GUID, NetBIOS name) from any SMB port, when both are known.
fn smb_identity(identity: &BTreeMap<String, String>) -> Option<(String, String)> {
    identity
        .iter()
        .filter(|(k, v)| k.starts_with("smb.") && k.ends_with(".guid") && !v.is_empty())
        .find_map(|(k, guid)| {
            let port = k.strip_prefix("smb.")?.strip_suffix(".guid")?;
            identity
                .get(&format!("smb.{port}.netbios_name"))
                .filter(|n| !n.is_empty())
                .map(|n| (guid.to_ascii_lowercase(), n.to_ascii_uppercase()))
        })
}

/// Host names the SMB NTLM challenge reported (`smb.<port>.netbios_name`, `dns_name`).
fn smb_names(identity: &BTreeMap<String, String>) -> BTreeSet<String> {
    identity
        .iter()
        .filter(|(k, v)| {
            k.starts_with("smb.")
                && (k.ends_with(".netbios_name") || k.ends_with(".dns_name"))
                && !v.trim().is_empty()
        })
        .map(|(_, v)| v.trim().to_string())
        .collect()
}

pub fn csv(devices: &[Device]) -> String {
    let mut out = String::from(
        "id,mac,vendor,ips,hostnames,type,os,open_tcp,open_udp,sources,type_confidence,type_evidence,os_confidence,os_evidence\n",
    );
    for d in devices {
        let cells = [
            d.id.clone(),
            d.mac.clone(),
            d.vendor.clone(),
            d.ips
                .iter()
                .map(IpAddr::to_string)
                .collect::<Vec<_>>()
                .join(" "),
            d.hostnames.join(" "),
            d.device_type.clone(),
            d.os.clone(),
            d.open_tcp
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(" "),
            d.open_udp
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(" "),
            d.sources.join("; "),
            d.device_type_evidence.confidence.to_string(),
            d.device_type_evidence.because(),
            d.os_evidence.confidence.to_string(),
            d.os_evidence.because(),
        ];
        out.push_str(
            &cells
                .iter()
                .map(|c| crate::scan::csv_cell(c))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push('\n');
    }
    out
}

/// What a device history is keyed by: a MAC address (any common notation) or an IP address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HistoryKey {
    Mac(String),
    Ip(IpAddr),
}

impl HistoryKey {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(Self::Ip(ip));
        }
        let only_mac_chars = s
            .chars()
            .all(|c| c.is_ascii_hexdigit() || matches!(c, ':' | '-' | '.'));
        match norm_mac(s) {
            mac if only_mac_chars && !mac.is_empty() => Ok(Self::Mac(mac)),
            _ => Err(format!(
                "{s}: give a MAC address (AA:BB:CC:DD:EE:FF) or an IP address"
            )),
        }
    }
    /// Text the stored snapshot JSON must contain (case-insensitively for MACs) for the device to
    /// appear in it; used to skip unrelated scans without parsing them.
    pub fn needles(&self) -> Vec<String> {
        match self {
            Self::Ip(ip) => vec![ip.to_string()],
            Self::Mac(mac) => vec![mac.clone(), mac.replace(':', "-"), mac.replace(':', "")],
        }
    }
}

/// One dated change in a device's history.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct HistoryEvent {
    pub scan_id: i64,
    pub timestamp: i64,
    /// `first-seen`, `ip-changed`, `mac-changed`, `hostname-changed`, `port-opened`,
    /// `port-closed`, `udp-answering`, `udp-silent`, `finding-appeared` or `finding-resolved`.
    pub kind: &'static str,
    pub detail: String,
}

/// A device across all saved scans and captures.
#[derive(Clone, Debug, Default, Serialize)]
pub struct DeviceHistory {
    pub query: String,
    /// `mac` or `ip`.
    pub key: &'static str,
    pub first_seen: Option<i64>,
    pub first_scan: Option<i64>,
    pub last_seen: Option<i64>,
    pub last_scan: Option<i64>,
    /// Scans and captures that saw the device.
    pub sightings: usize,
    /// Scans and captures in the inventory.
    pub scans: usize,
    pub ips: Vec<IpAddr>,
    pub macs: Vec<String>,
    pub hostnames: Vec<String>,
    /// Open TCP ports in the latest completed active scan that saw the device.
    pub open_tcp: Vec<u16>,
    pub events: Vec<HistoryEvent>,
}

/// Port state of the device in one completed active scan.
struct PortState {
    scan_id: i64,
    settings: crate::scan::Settings,
    tcp: BTreeSet<u16>,
    udp: BTreeSet<u16>,
    /// The device's findings in that scan by `Finding::key`: (description, port).
    findings: BTreeMap<String, (String, Option<u16>)>,
}

/// Builds a [`DeviceHistory`] from snapshots fed oldest first.
///
/// Only sightings produce events: a scan that does not mention the device says nothing (it may
/// not have covered the address). Port changes are compared only between completed active scans
/// that checked the device's ports with the same TCP port list; UDP only for ports probed in both.
pub struct HistoryBuilder {
    key: HistoryKey,
    out: DeviceHistory,
    ips: BTreeSet<IpAddr>,
    macs: BTreeSet<String>,
    hostnames: BTreeSet<String>,
    last: Option<(BTreeSet<IpAddr>, BTreeSet<String>, BTreeSet<String>)>,
    ports: Option<PortState>,
}

impl HistoryBuilder {
    pub fn new(key: HistoryKey, query: &str) -> Self {
        let out = DeviceHistory {
            query: query.trim().to_string(),
            key: match key {
                HistoryKey::Mac(_) => "mac",
                HistoryKey::Ip(_) => "ip",
            },
            ..Default::default()
        };
        Self {
            key,
            out,
            ips: BTreeSet::new(),
            macs: BTreeSet::new(),
            hostnames: BTreeSet::new(),
            last: None,
            ports: None,
        }
    }

    /// A scan that was not loaded (filtered out or unreadable) still counts towards `scans`.
    pub fn skip(&mut self) {
        self.out.scans += 1;
    }

    pub fn add(&mut self, scan_id: i64, timestamp: i64, snapshot: &crate::store::Snapshot) {
        self.out.scans += 1;
        let devices: Vec<Device> = merge(&snapshot.hosts, &snapshot.observations)
            .into_iter()
            .filter(|d| match &self.key {
                HistoryKey::Mac(m) => norm_mac(&d.mac) == *m,
                HistoryKey::Ip(ip) => d.ips.contains(ip),
            })
            .collect();
        if devices.is_empty() {
            return;
        }
        let ips: BTreeSet<IpAddr> = devices.iter().flat_map(|d| d.ips.clone()).collect();
        let macs: BTreeSet<String> = devices
            .iter()
            .map(|d| norm_mac(&d.mac))
            .filter(|m| !m.is_empty())
            .collect();
        // SMB-only names depend on whether service detection ran, so they are not compared.
        let hostnames: BTreeSet<String> = devices
            .iter()
            .flat_map(|d| {
                d.hostnames
                    .iter()
                    .filter(|h| !h.is_empty() && !d.smb_names.contains(h))
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .collect();
        let mut event = |kind: &'static str, detail: String| {
            self.out.events.push(HistoryEvent {
                scan_id,
                timestamp,
                kind,
                detail,
            })
        };
        let list = |s: &BTreeSet<String>| s.iter().cloned().collect::<Vec<_>>().join(", ");
        let ip_list = |s: &BTreeSet<IpAddr>| {
            s.iter()
                .map(IpAddr::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };
        match &self.last {
            None => event(
                "first-seen",
                format!(
                    "{}{}",
                    if ips.is_empty() {
                        "no IP address".to_string()
                    } else {
                        ip_list(&ips)
                    },
                    if macs.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", list(&macs))
                    }
                ),
            ),
            Some((old_ips, old_macs, old_names)) => {
                if !old_ips.is_empty() && !ips.is_empty() && *old_ips != ips {
                    event(
                        "ip-changed",
                        format!("{} → {}", ip_list(old_ips), ip_list(&ips)),
                    );
                }
                if !old_macs.is_empty() && !macs.is_empty() && *old_macs != macs {
                    event(
                        "mac-changed",
                        format!("{} → {}", list(old_macs), list(&macs)),
                    );
                }
                if !old_names.is_empty() && !hostnames.is_empty() && *old_names != hostnames {
                    event(
                        "hostname-changed",
                        format!("{} → {}", list(old_names), list(&hostnames)),
                    );
                }
            }
        }
        // Port comparison: active results of this scan for the device's addresses.
        let hosts: Vec<&Host> = snapshot
            .hosts
            .iter()
            .filter(|h| h.responding && ips.contains(&h.ip))
            .collect();
        if snapshot.complete && !hosts.is_empty() && hosts.iter().all(|h| h.ports_checked) {
            let state = PortState {
                scan_id,
                settings: snapshot.settings.clone(),
                tcp: hosts.iter().flat_map(|h| h.open.iter().copied()).collect(),
                udp: hosts
                    .iter()
                    .flat_map(|h| h.udp_open.iter().copied())
                    .collect(),
                findings: crate::risk::analyze_snapshot(snapshot)
                    .into_iter()
                    .filter(|f| ips.contains(&f.ip))
                    .map(|f| {
                        let text = format!(
                            "{} {} ({}) on {}{}",
                            f.severity.name().to_ascii_uppercase(),
                            f.title,
                            f.id,
                            f.ip,
                            f.port.map_or(String::new(), |p| format!(":{p}"))
                        );
                        // Without the address, so a device that moved keeps its findings.
                        let key = format!(
                            "{}|{}",
                            f.port.map_or(String::new(), |p| p.to_string()),
                            f.id
                        );
                        (key, (text, f.port))
                    })
                    .collect(),
            };
            if let Some(prev) = &self.ports {
                let scope = |s: &crate::scan::Settings| crate::scan::parse_ports(&s.ports).ok();
                let same_tcp = scope(&prev.settings).is_some()
                    && scope(&prev.settings) == scope(&state.settings);
                let since = prev.scan_id;
                if same_tcp {
                    for p in state.tcp.difference(&prev.tcp) {
                        event(
                            "port-opened",
                            format!("TCP {p} open (not in scan #{since})"),
                        );
                    }
                    for p in prev.tcp.difference(&state.tcp) {
                        event(
                            "port-closed",
                            format!("TCP {p} no longer observed open (open in scan #{since})"),
                        );
                    }
                }
                // A finding appears or is resolved only between scans that both checked its
                // port: the TCP port lists are the same, or the UDP port was probed in both.
                let udp_both = crate::store::udp_probed_in_both(&prev.settings, &state.settings);
                for (key, (text, port)) in &state.findings {
                    let comparable = match port {
                        None => true,
                        Some(p) if state.udp.contains(p) => udp_both.contains(p),
                        Some(_) => same_tcp,
                    };
                    if comparable && !prev.findings.contains_key(key) {
                        event("finding-appeared", text.clone());
                    }
                }
                for (key, (text, port)) in &prev.findings {
                    let rechecked = match port {
                        None => true,
                        Some(p) if prev.udp.contains(p) => udp_both.contains(p),
                        Some(_) => same_tcp,
                    };
                    if rechecked && !state.findings.contains_key(key) {
                        event("finding-resolved", text.clone());
                    }
                }
                for p in udp_both {
                    match (prev.udp.contains(&p), state.udp.contains(&p)) {
                        (false, true) => event("udp-answering", format!("UDP {p} answering")),
                        (true, false) => event(
                            "udp-silent",
                            format!("UDP {p} no longer answering (not proof of closure)"),
                        ),
                        _ => {}
                    }
                }
            }
            self.out.open_tcp = state.tcp.iter().copied().collect();
            self.ports = Some(state);
        }
        self.out.sightings += 1;
        self.out.first_seen.get_or_insert(timestamp);
        self.out.first_scan.get_or_insert(scan_id);
        self.out.last_seen = Some(timestamp);
        self.out.last_scan = Some(scan_id);
        self.ips.extend(ips.iter().copied());
        self.macs.extend(macs.iter().cloned());
        self.hostnames.extend(hostnames.iter().cloned());
        self.last = Some((ips, macs, hostnames));
    }

    pub fn finish(mut self) -> DeviceHistory {
        self.out.ips = self.ips.into_iter().collect();
        self.out.macs = self.macs.into_iter().collect();
        self.out.hostnames = self.hostnames.into_iter().collect();
        self.out
    }
}

/// `devices --history` output: `text` (default) or `json`.
pub fn history_output(h: &DeviceHistory, format: &str) -> Result<String, String> {
    match format {
        "json" => crate::schema::object("device-history", h),
        "text" => Ok(history_text(h)),
        _ => Err("Choose text or json".into()),
    }
}

pub fn history_text(h: &DeviceHistory) -> String {
    use crate::report::fmt_time;
    use std::fmt::Write as _;
    let mut o = format!("Device history for {} ({})\n", h.query, h.key);
    let (Some(first), Some(last)) = (h.first_scan, h.last_scan) else {
        let _ = write!(o, "Not seen in any of {} saved scans.", h.scans);
        return o;
    };
    let _ = writeln!(
        o,
        "First seen: {} (scan #{first})\nLast seen:  {} (scan #{last})\nSeen in {} of {} saved scans",
        fmt_time(h.first_seen.unwrap_or(0)),
        fmt_time(h.last_seen.unwrap_or(0)),
        h.sightings,
        h.scans
    );
    let join = |v: Vec<String>| {
        if v.is_empty() {
            "-".into()
        } else {
            v.join(", ")
        }
    };
    let _ = writeln!(
        o,
        "Addresses:  {}\nMACs:       {}\nHostnames:  {}\nOpen TCP:   {}",
        join(h.ips.iter().map(IpAddr::to_string).collect()),
        join(h.macs.clone()),
        join(h.hostnames.clone()),
        join(h.open_tcp.iter().map(u16::to_string).collect())
    );
    o.push_str("Events:\n");
    for e in &h.events {
        let _ = writeln!(
            o,
            "  {}  #{:<5} {:<16} {}",
            fmt_time(e.timestamp),
            e.scan_id,
            e.kind,
            e.detail
        );
    }
    o.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(ip: &str, mac: &str, open: &[u16], id: &[(&str, &str)]) -> Host {
        Host {
            ip: ip.parse().unwrap(),
            responding: true,
            ping: None,
            ttl: Some(64),
            hostname: String::new(),
            mac: mac.into(),
            open: open.to_vec(),
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity: id
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            udp_open: vec![],
            trace: vec![],
        }
    }
    fn obs(protocol: &str, mac: &str, ip: Option<&str>, fields: &[(&str, &str)]) -> Observation {
        Observation {
            protocol: protocol.into(),
            mac: mac.into(),
            ip: ip.map(|s| s.parse().unwrap()),
            fields: fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }
    #[test]
    fn passive_hints_are_scored_like_active_evidence() {
        let kind = |fields: &[(&str, &str)]| {
            merge(&[], &[obs("mDNS", "aa:bb:cc:00:00:01", None, fields)])[0]
                .device_type
                .clone()
        };
        let d = merge(
            &[],
            &[obs(
                "mDNS",
                "aa:bb:cc:00:00:01",
                None,
                &[("hint.printer", "mDNS _ipp._tcp")],
            )],
        );
        assert_eq!(d[0].device_type, "Printer / MFP");
        assert_eq!(d[0].type_evidence, "passive: mDNS _ipp._tcp");
        // A weak hint alone is not enough, and a weak hint beside a strong one of the same
        // category does not double count.
        assert_eq!(kind(&[("hint_weak.media", "x")]), "");
        assert_eq!(
            merge(
                &[],
                &[
                    obs("mDNS", "aa:bb:cc:00:00:01", None, &[("hint.media", "a")]),
                    obs(
                        "SSDP/UPnP",
                        "aa:bb:cc:00:00:01",
                        None,
                        &[("hint_weak.media", "b")]
                    ),
                ]
            )[0]
            .type_evidence,
            "passive: a"
        );
        // Weak hints of one category from several protocols count once (a single signal kind).
        let two = merge(
            &[],
            &[
                obs("mDNS", "aa:bb:cc:00:00:01", None, &[("hint_weak.nas", "a")]),
                obs(
                    "SSDP/UPnP",
                    "aa:bb:cc:00:00:01",
                    None,
                    &[("hint_weak.nas", "b")],
                ),
            ],
        );
        assert_eq!(two[0].device_type, "");
        // Unknown categories and arbitrary keys are ignored.
        assert_eq!(
            kind(&[("hint.bogus", "x"), ("passive.hint.printer", "y")]),
            ""
        );
        // The reason text never feeds the keyword rules: "printer" in a reason is not a
        // service banner.
        assert_eq!(kind(&[("hint_weak.media", "printer laserjet ipp")]), "");
        // An LLDP announcement alone (25) stays below the threshold; with a phone hint the
        // announcement no longer counts as network evidence.
        let lldp = |fields: &[(&str, &str)]| {
            merge(&[], &[obs("LLDP", "aa:bb:cc:00:00:01", None, fields)])[0]
                .device_type
                .clone()
        };
        assert_eq!(lldp(&[("name", "x")]), "");
        assert_eq!(lldp(&[("hint.voip", "p")]), "VoIP phone");
    }
    fn ev<'a>(
        vendor: &'a str,
        tcp: &'a [u16],
        identity: &'a BTreeMap<String, String>,
        os: &'a str,
    ) -> Facts<'a> {
        Facts {
            mac: "",
            vendor,
            tcp,
            udp: &[],
            identity,
            hostnames: &[],
            os,
            ttl: None,
            protocols: &[],
        }
    }

    #[test]
    fn active_and_passive_records_merge_on_mac() {
        let hosts = vec![host("10.0.0.7", "aa-bb-cc-00-11-22", &[22], &[])];
        let observations = vec![
            obs(
                "DHCP",
                "AA:BB:CC:00:11:22",
                Some("10.0.0.7"),
                &[("hostname", "printer-7")],
            ),
            obs(
                "SSDP/UPnP",
                "AA:BB:CC:00:11:22",
                None,
                &[("name", "Lab UPnP")],
            ),
            obs("LLDP", "DE:AD:BE:EF:00:01", None, &[("name", "switch-1")]),
            obs(
                "ARP",
                "AA:BB:CC:00:11:99",
                Some("10.0.0.9"),
                &[("operation", "1")],
            ),
        ];
        let devices = merge(&hosts, &observations);
        assert_eq!(devices.len(), 3);
        let d = devices
            .iter()
            .find(|d| d.mac == "AA:BB:CC:00:11:22")
            .unwrap();
        assert_eq!(d.ips, vec!["10.0.0.7".parse::<IpAddr>().unwrap()]);
        assert!(
            d.hostnames.contains(&"printer-7".to_string())
                && d.hostnames.contains(&"Lab UPnP".to_string())
        );
        assert_eq!(
            d.sources,
            ["active scan", "passive DHCP", "passive SSDP/UPnP"]
        );
        assert_eq!(d.open_tcp, vec![22]);
        let arp = devices
            .iter()
            .find(|d| d.mac == "AA:BB:CC:00:11:99")
            .unwrap();
        assert!(arp.hostnames.is_empty(), "ARP carries no names");
    }

    #[test]
    fn ip_only_record_is_upgraded_when_a_mac_appears() {
        let hosts = vec![host("10.0.0.7", "", &[80], &[])];
        let devices = merge(
            &hosts,
            &[obs("DHCP", "AA:BB:CC:00:11:22", Some("10.0.0.7"), &[])],
        );
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].mac, "AA:BB:CC:00:11:22");
        assert_eq!(devices[0].open_tcp, vec![80]);
        // An observation with only an IP joins the host without creating a duplicate.
        let devices = merge(
            &hosts,
            &[obs("SSDP/UPnP", "", Some("10.0.0.7"), &[("name", "TV")])],
        );
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id, "ip:10.0.0.7");
        // Non-responding hosts and observations without any key are ignored.
        let mut dead = host("10.0.0.8", "", &[], &[]);
        dead.responding = false;
        assert!(merge(&[dead], &[obs("X", "", None, &[])]).is_empty());
    }

    #[test]
    fn a_second_mac_on_the_same_ip_does_not_swallow_the_device() {
        // Scanned host 10.0.0.1 is M1; a VRRP/proxy-ARP/conflicting MAC M2 also claims the IP.
        let hosts = vec![host("10.0.0.1", "AA:BB:CC:00:00:01", &[22, 443], &[])];
        let devices = merge(
            &hosts,
            &[
                obs("ARP", "00:00:5E:00:01:01", Some("10.0.0.1"), &[]),
                // An IP-only record still joins the device that was first seen at the address.
                obs("SSDP/UPnP", "", Some("10.0.0.1"), &[("name", "router")]),
            ],
        );
        assert_eq!(devices.len(), 2, "both MACs stay separate devices");
        let m1 = devices
            .iter()
            .find(|d| d.mac == "AA:BB:CC:00:00:01")
            .unwrap();
        assert_eq!(m1.open_tcp, vec![22, 443]);
        assert!(m1.hostnames.contains(&"router".to_string()));
        assert_eq!(m1.sources, ["active scan", "passive SSDP/UPnP"]);
        let m2 = devices
            .iter()
            .find(|d| d.mac == "00:00:5E:00:01:01")
            .unwrap();
        assert!(m2.open_tcp.is_empty());
        assert_eq!(m2.ips, m1.ips);
        // The address conflict is noted on both devices.
        assert_eq!(
            m1.observations["IP conflict"]["10.0.0.1"],
            "00:00:5E:00:01:01"
        );
        assert_eq!(
            m2.observations["IP conflict"]["10.0.0.1"],
            "AA:BB:CC:00:00:01"
        );
        // Two active hosts reporting different MACs are not merged either.
        let devices = merge(
            &[
                host("10.0.0.1", "AA:BB:CC:00:00:01", &[22], &[]),
                host("10.0.0.1", "AA:BB:CC:00:00:02", &[80], &[]),
            ],
            &[],
        );
        assert_eq!(devices.len(), 2);
    }

    #[test]
    fn vendor_and_randomized_macs() {
        let devices = merge(&[host("10.0.0.2", "00:00:0C:11:22:33", &[], &[])], &[]);
        assert!(devices[0].vendor.contains("Cisco"));
        let devices = merge(&[host("10.0.0.3", "02:11:22:33:44:55", &[], &[])], &[]);
        assert!(devices[0].randomized_mac);
        assert_eq!(devices[0].vendor, "");
    }

    #[test]
    fn classification_examples() {
        let none = BTreeMap::new();
        let id = |k: &str, v: &str| BTreeMap::from([(k.to_string(), v.to_string())]);
        assert_eq!(
            classify(&ev("", &[9100, 631], &id("svc.631", "ipp CUPS 2.4"), ""))
                .unwrap()
                .0,
            PRINTER
        );
        assert_eq!(
            classify(&ev("Siemens AG", &[102], &id("S7.name", "CPU 1214C"), ""))
                .unwrap()
                .0,
            OT
        );
        assert_eq!(
            classify(&ev("Hangzhou Hikvision", &[554, 80], &none, ""))
                .unwrap()
                .0,
            CAMERA
        );
        assert_eq!(
            classify(&ev("", &[445, 3389, 135], &none, "Windows"))
                .unwrap()
                .0,
            WINDOWS
        );
        assert_eq!(
            classify(&ev("", &[3306], &none, "Linux")).unwrap().0,
            DATABASE
        );
        assert_eq!(
            classify(&ev("Raspberry Pi Trading Ltd", &[22], &none, "Linux"))
                .unwrap()
                .0,
            SBC
        );
        assert_eq!(
            classify(&ev(
                "Ubiquiti Inc",
                &[22, 443],
                &id("http.443.title", "UniFi"),
                ""
            ))
            .unwrap()
            .0,
            NETWORK
        );
        assert_eq!(
            classify(&ev("", &[80], &none, "")),
            None,
            "a web port alone is not a device type"
        );
        let vm = Facts {
            mac: "00:0C:29:AA:BB:CC",
            ..ev("", &[445, 3389], &none, "Windows")
        };
        assert_eq!(
            classify(&vm).unwrap().0,
            "Windows computer [virtual machine]"
        );
        assert!(is_virtual_mac("08-00-27-00-00-01"));
        assert!(!is_virtual_mac("00:00:0C:00:00:01"));
    }

    #[test]
    fn csv_export_quotes_cells() {
        let d = Device {
            id: "x".into(),
            hostnames: vec!["a\"b".into()],
            ..Default::default()
        };
        let text = csv(&[d]);
        assert!(text.contains("\"a\"\"b\""));
        assert!(text.starts_with("id,mac,"));
    }

    fn history_snapshot(ip: &str, mac: &str, open: &[u16]) -> crate::store::Snapshot {
        crate::store::Snapshot {
            sent: vec![],
            targets: "10.0.0.0/24".into(),
            complete: true,
            settings: crate::scan::Settings {
                ports: "22,80,443".into(),
                ..Default::default()
            },
            hosts: vec![Host {
                ip: ip.parse().unwrap(),
                responding: true,
                ping: None,
                ttl: None,
                hostname: String::new(),
                mac: mac.into(),
                open: open.to_vec(),
                closed: 0,
                unanswered: 0,
                errors: vec![],
                ports_checked: true,
                identity: BTreeMap::new(),
                udp_open: vec![],
                trace: vec![],
            }],
            observations: vec![],
            notes: BTreeMap::new(),
        }
    }

    #[test]
    fn history_key_accepts_ip_and_mac_notations() {
        let mac = HistoryKey::Mac("AA:BB:CC:00:11:22".into());
        for s in [
            "aa:bb:cc:00:11:22",
            "AA-BB-CC-00-11-22",
            "aabb.cc00.1122",
            " aabbcc001122 ",
        ] {
            assert_eq!(HistoryKey::parse(s).unwrap(), mac, "{s}");
        }
        assert_eq!(
            HistoryKey::parse("fe80::1").unwrap(),
            HistoryKey::Ip("fe80::1".parse().unwrap())
        );
        for bad in ["", "host.lan", "aa:bb:cc", "zz:bb:cc:00:11:22"] {
            assert!(HistoryKey::parse(bad).is_err(), "{bad}");
        }
        assert!(mac.needles().contains(&"AABBCC001122".to_string()));
    }

    #[test]
    fn history_compares_ports_only_between_comparable_complete_scans() {
        let mac = "00:11:22:33:44:55";
        let key = HistoryKey::parse(mac).unwrap();
        let mut b = HistoryBuilder::new(key, mac);
        b.add(1, 100, &history_snapshot("10.0.0.5", mac, &[22]));
        // Partial scan: nothing about ports.
        let mut partial = history_snapshot("10.0.0.5", mac, &[]);
        partial.complete = false;
        b.add(2, 200, &partial);
        // Different port list: not compared, but becomes the new reference.
        let mut wider = history_snapshot("10.0.0.5", mac, &[22, 8080]);
        wider.settings.ports = "22,80,443,8080".into();
        b.add(3, 300, &wider);
        // Not seen at all: no event.
        b.add(
            4,
            400,
            &history_snapshot("10.0.0.9", "00:00:00:00:00:01", &[]),
        );
        let mut same = history_snapshot("10.0.0.5", mac, &[443]);
        same.settings.ports = "8080,22,80,443".into();
        b.add(5, 500, &same);
        // Passive sighting only (no active result): updates last seen, no port event.
        let mut passive = history_snapshot("10.0.0.5", mac, &[]);
        passive.hosts.clear();
        passive.observations.push(Observation {
            protocol: "ARP".into(),
            mac: mac.into(),
            ip: Some("10.0.0.7".parse().unwrap()),
            fields: BTreeMap::new(),
        });
        b.add(6, 600, &passive);
        let h = b.finish();
        let events: Vec<(i64, &str, &str)> = h
            .events
            .iter()
            .map(|e| (e.scan_id, e.kind, e.detail.as_str()))
            .collect();
        assert_eq!(
            events,
            [
                (1, "first-seen", "10.0.0.5 (00:11:22:33:44:55)"),
                (5, "port-opened", "TCP 443 open (not in scan #3)"),
                (
                    5,
                    "port-closed",
                    "TCP 22 no longer observed open (open in scan #3)"
                ),
                (
                    5,
                    "port-closed",
                    "TCP 8080 no longer observed open (open in scan #3)"
                ),
                (6, "ip-changed", "10.0.0.5 → 10.0.0.7"),
            ]
        );
        assert_eq!((h.sightings, h.scans), (5, 6));
        assert_eq!((h.first_seen, h.last_seen), (Some(100), Some(600)));
        assert_eq!(h.open_tcp, [443]);
        let text = history_text(&h);
        assert!(
            text.contains("First seen: 1970-01-01 00:01 UTC (scan #1)"),
            "{text}"
        );
        assert!(text.contains("port-opened"));
        let json: serde_json::Value =
            serde_json::from_str(&history_output(&h, "json").unwrap()).unwrap();
        assert_eq!(json["events"][1]["kind"], "port-opened");
        assert!(history_output(&h, "xml").is_err());
        let mut empty = HistoryBuilder::new(HistoryKey::parse("10.1.1.1").unwrap(), "10.1.1.1");
        // A scanned address that did not respond is not a sighting.
        let mut silent = history_snapshot("10.1.1.1", "", &[]);
        silent.hosts[0].responding = false;
        empty.add(7, 700, &silent);
        let empty = empty.finish();
        assert_eq!(
            (empty.sightings, empty.scans, empty.first_seen),
            (0, 1, None)
        );
        assert!(history_text(&empty).contains("Not seen"));
    }
    #[test]
    fn fingerprint_and_cpe_keys_are_not_device_evidence() {
        // A user CPE template or a fingerprint string must not trigger keyword rules.
        let identity = BTreeMap::from([
            (
                "svc.80.cpe".to_string(),
                "cpe:2.3:a:acme:printer_portal:1.0".to_string(),
            ),
            ("tls.443.ja4s".to_string(), "t130200_1301_mfp".to_string()),
        ]);
        assert_eq!(classify(&ev("", &[80], &identity, "")), None);
        assert!(is_device_evidence("svc.80.product"));
        assert!(!is_device_evidence("ssh.22.hassh_algorithms"));
    }

    #[test]
    fn smb_guid_and_netbios_name_join_routed_addresses() {
        let smb = |guid: &str, name: &str| {
            vec![
                ("smb.445.guid", guid.to_string()),
                ("smb.445.netbios_name", name.to_string()),
                (
                    "smb.445.dns_name",
                    format!("{}.corp.example", name.to_lowercase()),
                ),
            ]
        };
        let h = |ip: &str, mac: &str, id: &[(&str, String)]| {
            let id: Vec<(&str, &str)> = id.iter().map(|(k, v)| (*k, v.as_str())).collect();
            host(ip, mac, &[445], &id)
        };
        let devices = merge(
            &[
                h("10.1.0.5", "", &smb("1111", "SRV1")),
                h("10.2.0.5", "", &smb("1111", "SRV1")),
                // Cloned VM: same GUID, other name -> separate device.
                h("10.3.0.5", "", &smb("1111", "SRV2")),
                // Records with a MAC are never merged by GUID.
                h("10.0.0.7", "AA:BB:CC:00:00:07", &smb("2222", "PC7")),
                h("10.0.0.8", "AA:BB:CC:00:00:08", &smb("2222", "PC7")),
            ],
            &[],
        );
        assert_eq!(devices.len(), 4, "{devices:#?}");
        let srv1 = devices.iter().find(|d| d.ips.len() == 2).unwrap();
        assert!(srv1.hostnames.contains(&"SRV1".to_string()));
        assert!(srv1.hostnames.contains(&"srv1.corp.example".to_string()));
        assert_eq!(srv1.smb_names.len(), 2);
    }
    #[test]
    fn device_type_carries_reasons_and_a_confidence() {
        let id: BTreeMap<String, String> = BTreeMap::new();
        // A print port alone (25) is below the threshold; with the vendor OUI and a service
        // text that names the model it is concluded, and every reason is listed.
        assert!(classify_detailed(&ev("", &[9100], &id, "")).is_none());
        let id: BTreeMap<String, String> =
            [("svc.80".to_string(), "http HP LaserJet 4250".to_string())].into();
        let (kind, why) = classify_detailed(&ev("Hewlett-Packard", &[9100, 80], &id, "")).unwrap();
        assert_eq!(kind, PRINTER);
        assert!(
            why.reasons.iter().any(|r| r == "print port 9100"),
            "{why:?}"
        );
        assert!(
            why.reasons.iter().any(|r| r.contains("laserjet")),
            "{why:?}"
        );
        assert!((50..=95).contains(&why.confidence), "{why:?}");
        // More agreeing evidence never lowers the score; a contested call scores lower than
        // an uncontested one.
        let strong = classify_detailed(&ev("Hewlett-Packard", &[9100, 515, 631, 80], &id, ""))
            .unwrap()
            .1
            .confidence;
        assert!(strong >= why.confidence);
        let contested: BTreeMap<String, String> = [
            ("svc.80".to_string(), "http HP LaserJet 4250".to_string()),
            ("svc.22".to_string(), "ssh OpenSSH 9.6".to_string()),
        ]
        .into();
        let (_, mixed) = classify_detailed(&ev("", &[9100, 22, 80], &contested, "Linux")).unwrap();
        assert!(mixed.confidence <= strong, "{mixed:?}");
        // The plain wrapper keeps its text.
        let (k2, text) = classify(&ev("Hewlett-Packard", &[9100, 80], &id, "")).unwrap();
        assert_eq!((k2.as_str(), text), (PRINTER, why.because()));
        // A virtual machine says why.
        let empty = BTreeMap::new();
        let vm = Facts {
            mac: "00:50:56:00:00:01",
            ..ev("", &[3389, 445], &empty, "Windows")
        };
        if let Some((kind, why)) = classify_detailed(&vm) {
            assert!(kind.ends_with("[virtual machine]"));
            assert!(why.reasons.iter().any(|r| r.contains("virtual-machine")));
        }
    }

    #[test]
    fn merged_devices_expose_both_evidence_blocks_and_csv_columns() {
        let id = [
            ("svc.9100", "jetdirect"),
            ("svc.80", "http HP LaserJet 4250"),
            ("os.guess", "Embedded Linux/RTOS"),
            ("os.confidence", "55%"),
            ("os.evidence", "minimal TCP options; initial TTL 64"),
        ];
        let d = merge(
            &[host("10.0.0.9", "00:11:22:33:44:55", &[9100, 80], &id)],
            &[],
        );
        let d = &d[0];
        assert_eq!(d.device_type, PRINTER);
        assert!(d.device_type_evidence.confidence > 0);
        assert_eq!(d.type_evidence, d.device_type_evidence.because());
        assert_eq!(d.os_evidence.confidence, 55);
        assert_eq!(
            d.os_evidence.reasons,
            ["minimal TCP options", "initial TTL 64"]
        );
        let json = serde_json::to_value(d).unwrap();
        assert_eq!(json["os_evidence"]["confidence"], 55);
        assert!(json["device_type_evidence"]["reasons"].is_array());
        let csv = csv(std::slice::from_ref(d));
        assert!(
            csv.lines()
                .next()
                .unwrap()
                .ends_with("type_confidence,type_evidence,os_confidence,os_evidence")
        );
        assert!(csv.contains(",\"55\","), "{csv}");
        // A device with nothing to say has no evidence blocks in the JSON.
        let bare = merge(&[host("10.0.0.10", "", &[], &[])], &[]);
        let json = serde_json::to_value(&bare[0]).unwrap();
        assert!(json.get("os_evidence").is_none() && json.get("device_type_evidence").is_none());
    }
}
