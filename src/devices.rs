//! One record per device. Active scan results and passive observations are merged on the MAC
//! address (or on the IP address when no MAC is known), then enriched with the manufacturer
//! from the embedded IEEE registry and a scored device-type guess.
use crate::{oui, passive::Observation, scan::Host};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::IpAddr,
};

pub struct Evidence<'a> {
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

/// (device type, evidence) when the combined evidence is strong enough.
pub fn classify(e: &Evidence) -> Option<(String, String)> {
    let mut s = Scores::default();
    let all_text = e
        .identity
        .values()
        .cloned()
        .chain(e.hostnames.iter().cloned())
        .collect::<Vec<_>>()
        .join(" | ");
    let http_text = e
        .identity
        .iter()
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
    ) {
        if s.0.contains_key(OT) {
            s.add(OT, 15, format!("industrial vendor ({v})"));
        }
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
    if e.protocols.iter().any(|p| p == "LLDP") {
        s.add(NETWORK, 25, "LLDP announcement");
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
    let mut kind = name.to_string();
    if is_virtual_mac(e.mac) {
        kind.push_str(" [virtual machine]");
    }
    Some((kind, why.join("; ")))
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Device {
    pub id: String,
    pub mac: String,
    pub vendor: String,
    pub randomized_mac: bool,
    pub ips: Vec<IpAddr>,
    pub hostnames: Vec<String>,
    pub device_type: String,
    pub type_evidence: String,
    pub os: String,
    pub os_confidence: String,
    pub open_tcp: Vec<u16>,
    pub open_udp: Vec<u16>,
    pub services: BTreeMap<String, String>,
    pub sources: Vec<String>,
    pub observations: BTreeMap<String, BTreeMap<String, String>>,
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
    for h in hosts.iter().filter(|h| h.responding) {
        let mac = norm_mac(&h.mac);
        let key = if mac.is_empty() {
            format!("ip:{}", h.ip)
        } else {
            mac.clone()
        };
        if !mac.is_empty() {
            if let Some(existing) = by_ip.get(&h.ip).cloned() {
                rekey(&mut accs, &mut by_ip, &existing, &key);
            }
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
        by_ip.insert(h.ip, key);
    }
    for o in observations {
        let mac = norm_mac(&o.mac);
        let key = if !mac.is_empty() {
            if let Some(ip) = o.ip {
                if let Some(existing) = by_ip.get(&ip).cloned() {
                    rekey(&mut accs, &mut by_ip, &existing, &mac);
                }
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
            by_ip.insert(ip, key.clone());
        }
        for field in ["hostname", "name"] {
            if let Some(n) = o.fields.get(field).filter(|n| !n.is_empty()) {
                if o.protocol != "ARP" {
                    a.hostnames.insert(n.clone());
                }
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
            let vendor = if a.mac.is_empty() || oui::locally_administered(&a.mac) {
                String::new()
            } else {
                oui::vendor(&a.mac).unwrap_or("").to_string()
            };
            let hostnames: Vec<String> = a.hostnames.into_iter().collect();
            let (tcp, udp): (Vec<u16>, Vec<u16>) =
                (a.tcp.into_iter().collect(), a.udp.into_iter().collect());
            let os = a.identity.get("os.guess").cloned().unwrap_or_default();
            let protocols: Vec<String> = a.observations.keys().cloned().collect();
            let (device_type, type_evidence) = classify(&Evidence {
                mac: &a.mac,
                vendor: &vendor,
                tcp: &tcp,
                udp: &udp,
                identity: &a.identity,
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
            Device {
                id: key,
                randomized_mac: !a.mac.is_empty() && oui::locally_administered(&a.mac),
                mac: a.mac,
                vendor,
                ips: a.ips.into_iter().collect(),
                hostnames,
                device_type,
                type_evidence,
                os,
                os_confidence: a.identity.get("os.confidence").cloned().unwrap_or_default(),
                open_tcp: tcp,
                open_udp: udp,
                services,
                sources: a.sources.into_iter().collect(),
                observations: a.observations,
            }
        })
        .collect()
}

pub fn csv(devices: &[Device]) -> String {
    let mut out = String::from("id,mac,vendor,ips,hostnames,type,os,open_tcp,open_udp,sources\n");
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
    fn ev<'a>(
        vendor: &'a str,
        tcp: &'a [u16],
        identity: &'a BTreeMap<String, String>,
        os: &'a str,
    ) -> Evidence<'a> {
        Evidence {
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
        let vm = Evidence {
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
}
