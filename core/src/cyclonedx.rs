//! `export ID --format cyclonedx`: a saved scan as a CycloneDX 1.6 JSON document.
//!
//! What it is: an inventory of the **devices** on the network, the **firmware** they reported and
//! the **services** they run, with the known CVEs linked to the component they affect. A scan sees
//! what a device announces (an S7 or Modbus identification, LLDP-MED, a service banner), never the
//! libraries in its firmware image; those come from imported firmware SBOMs ([`crate::sbom`]),
//! nested under the firmware they describe. Every value says where it came from
//! (`network-scope:source`), and only
//! what a device reported becomes a firmware or service component; nothing is guessed into one.
//!
//! The document is deterministic for a given scan: the serial number is a name-based UUID
//! (version 5) of the scan's content and time, and every list is in a fixed order.
use crate::{
    devices::{self, Device},
    otdevice,
    otpassive::{self, Asset},
    risk::{self, Finding, Severity},
    scan::Host,
    store::Snapshot,
};
use serde_json::{Map, Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::IpAddr,
};

/// The CycloneDX version written (`specVersion`).
pub const SPEC_VERSION: &str = "1.6";
/// Namespace of the property names (CycloneDX property taxonomy: `<namespace>:<name>`).
const NS: &str = "network-scope";
/// Longest value kept from a device (they are device-supplied strings).
const MAX_VALUE: usize = 200;

/// The CycloneDX document of a saved scan, as pretty-printed JSON.
pub fn export(snapshot: &Snapshot, timestamp: i64) -> String {
    let findings = risk::analyze_snapshot(snapshot);
    let devices = devices::merge(&snapshot.hosts, &snapshot.observations);
    let assets = otpassive::assets(&snapshot.observations);
    let cves = risk::cve_db();
    let sboms = crate::sbom::active();
    let nvd = crate::nvd::active();
    let vex = crate::vex::active();
    let feeds = crate::feeds::active();
    let bom = build(&Input {
        snapshot,
        devices: &devices,
        assets: &assets,
        findings: &findings,
        cpe: &|product, version| cves.cpe(product, version),
        sboms: &sboms,
        vex: &vex,
        enrich: &|findings| feeds.enrich(findings),
        nvd: &|cpe| {
            nvd.lookup(cpe)
                .into_iter()
                .take(crate::nvd::MAX_FINDINGS_PER_PORT)
                .collect()
        },
        timestamp,
    });
    let devices = bom["components"].as_array().map_or(0, Vec::len);
    if devices <= PRETTY_UP_TO {
        serde_json::to_string_pretty(&bom).unwrap_or_default()
    } else {
        serde_json::to_string(&bom).unwrap_or_default()
    }
}

/// Uploads a CycloneDX document to OWASP Dependency-Track (`POST /api/v1/bom`, multipart form
/// with `projectName`, `projectVersion`, `autoCreate` and `bom`; the API key in `X-Api-Key`).
/// `url` is the server (`https://dtrack.example`) or the full API URL. The project is created
/// when it does not exist; a later upload to the same name and version replaces its BOM.
pub fn push_dependency_track(
    url: &str,
    api_key: &str,
    project: &str,
    version: &str,
    bom: &str,
    timeout: std::time::Duration,
) -> Result<(), String> {
    let url = url.trim();
    let bare = url
        .split_once("://")
        .is_some_and(|(_, rest)| rest.trim_end_matches('/').find('/').is_none());
    let full = if bare {
        format!("{}/api/v1/bom", url.trim_end_matches('/'))
    } else {
        url.to_string()
    };
    if project.trim().is_empty() || version.trim().is_empty() {
        return Err("Dependency-Track needs a project name and version".into());
    }
    let (content_type, body) = multipart(&[
        ("autoCreate", "true"),
        ("projectName", project.trim()),
        ("projectVersion", version.trim()),
        ("bom", bom),
    ]);
    crate::notify::push_with_header(&full, ("X-Api-Key", api_key), &content_type, &body, timeout)
}

/// A `multipart/form-data` body of text fields, with a boundary none of the values contains.
fn multipart(fields: &[(&str, &str)]) -> (String, String) {
    let mut n = 0u32;
    let boundary = loop {
        let b = format!("network-scope-{n:08x}");
        if fields.iter().all(|(_, v)| !v.contains(&b)) {
            break b;
        }
        n += 1;
    };
    let mut body = String::new();
    for (name, value) in fields {
        body.push_str(&format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        ));
    }
    body.push_str(&format!("--{boundary}--\r\n"));
    (format!("multipart/form-data; boundary={boundary}"), body)
}

/// Everything the document is made from. [`export`] fills it from a snapshot; tests fill it
/// directly, so they do not depend on the CVE feeds imported on the machine.
pub struct Input<'a> {
    pub snapshot: &'a Snapshot,
    pub devices: &'a [Device],
    pub assets: &'a [Asset],
    pub findings: &'a [Finding],
    /// CPE 2.3 name of a detected product and version (`CveDb::cpe`); never built from banner
    /// text here.
    pub cpe: &'a dyn Fn(&str, &str) -> Option<String>,
    /// Imported firmware SBOMs (`feeds import sbom`), nested under the firmware they describe.
    pub sboms: &'a crate::sbom::Library,
    /// Imported VEX statements, for the CVEs of SBOM components (the scan's own findings carry
    /// theirs already, see [`crate::vex::apply`]).
    pub vex: &'a crate::vex::Library,
    /// CVEs of the imported NVD feed for a CPE name (an SBOM component's).
    pub nvd: &'a dyn Fn(&str) -> Vec<crate::nvd::Hit>,
    /// Adds KEV and EPSS data of the imported feeds to findings (the CVEs of SBOM components;
    /// the scan's own findings have theirs already).
    pub enrich: &'a dyn Fn(&mut [Finding]),
    pub timestamp: i64,
}

/// Addresses listed per vulnerability in `network-scope:found-on`.
const MAX_FOUND_ON: usize = 100;
/// Above this many devices the document is written without indentation (a 65,536-host scan is
/// about 100 MB instead of 180).
const PRETTY_UP_TO: usize = 1_000;

/// Most CVE links raised for the components of nested SBOMs in one document (one per CVE,
/// component and device); more are counted in `network-scope:sbom-cves-not-linked`.
const MAX_SBOM_FINDINGS: usize = 200_000;

/// What nesting the SBOMs did, for the document's metadata.
struct SbomStats<'a> {
    /// The VEX statements for the components' CVEs.
    vex: &'a crate::vex::Library,
    /// Firmware components that got an SBOM nested.
    firmware: usize,
    /// Distinct SBOMs nested.
    sboms: BTreeSet<String>,
    /// CVE links not made because of [`MAX_SBOM_FINDINGS`].
    not_linked: usize,
    /// NVD answers per CPE name, so a firmware on many devices is looked up once.
    lookups: HashMap<String, Vec<crate::nvd::Hit>>,
    /// CVEs of SBOM components (from the NVD feed), with the component they affect.
    findings: Vec<(Finding, String)>,
}

/// A service component, for linking the findings of its port.
struct Service {
    bom_ref: String,
    /// The product name as reported, lowercase.
    product: String,
    /// Its CPE names (from the CVE table and from the scan), lowercase.
    cpes: Vec<String>,
}

/// The CycloneDX document.
pub fn build(input: &Input) -> Value {
    let hosts: HashMap<IpAddr, &Host> = input.snapshot.hosts.iter().map(|h| (h.ip, h)).collect();
    let mut refs = Refs::default();
    // (address, port) -> bom-ref of the service component; address -> bom-ref of its device;
    // (address, port) -> firmware component identified on that port (S7, Modbus, ...).
    let mut services: HashMap<(IpAddr, u16), Service> = HashMap::new();
    let mut firmware_refs: HashMap<(IpAddr, u16), String> = HashMap::new();
    let mut device_refs: HashMap<IpAddr, String> = HashMap::new();
    let mut stats = SbomStats {
        vex: input.vex,
        firmware: 0,
        sboms: BTreeSet::new(),
        not_linked: 0,
        lookups: HashMap::new(),
        findings: vec![],
    };

    let mut components = vec![];
    for d in input.devices {
        let device_ref = refs.unique(&format!("device:{}", ref_part(&d.id)));
        for ip in &d.ips {
            device_refs.entry(*ip).or_insert_with(|| device_ref.clone());
        }
        let mut children = vec![];
        let mut seen_firmware = BTreeSet::new();
        let mut properties = Props::default();
        let mut manufacturer: Option<(String, &str)> = None;
        // Per firmware component (index in `children`): vendor, names and version, for the SBOM.
        let mut firmware: Vec<(usize, String, Vec<String>, String)> = vec![];

        // Firmware an industrial protocol identification reported (active scan).
        for ip in &d.ips {
            let Some(h) = hosts.get(ip) else { continue };
            for ot in otdevice::from_identity(&h.identity) {
                if manufacturer.is_none() && !ot.vendor.is_empty() {
                    manufacturer = Some((ot.vendor.clone(), ot.protocol));
                }
                let name = ot.products.first().cloned().unwrap_or_default();
                if name.is_empty() && ot.version.is_empty() {
                    continue;
                }
                let key = (name.to_lowercase(), ot.version.to_lowercase());
                if !seen_firmware.insert(key) {
                    continue;
                }
                let r = refs.unique(&format!(
                    "{device_ref}:firmware:{}:{}",
                    ref_part(ot.protocol),
                    ot.port
                ));
                firmware_refs.insert((*ip, ot.port), r.clone());
                let mut p = Props::default();
                p.add("source", format!("{} identification", ot.protocol));
                p.add("address", ip.to_string());
                p.add("port", ot.port.to_string());
                for other in ot.products.iter().skip(1) {
                    p.add("product-name", other.clone());
                }
                firmware.push((
                    children.len(),
                    ot.vendor.clone(),
                    ot.products.clone(),
                    ot.version.clone(),
                ));
                children.push(component(
                    "firmware",
                    &r,
                    if name.is_empty() {
                        format!("{} firmware", ot.protocol)
                    } else {
                        name
                    },
                    &ot.version,
                    Some(&ot.vendor),
                    None,
                    p,
                ));
            }
        }

        // Firmware seen in passive industrial traffic (matched to this device by MAC or address).
        for a in input.assets.iter().filter(|a| asset_matches(a, d)) {
            if manufacturer.is_none() && !a.vendor.is_empty() {
                manufacturer = Some((a.vendor.clone(), "passive industrial traffic"));
            }
            let name = if a.product.is_empty() {
                a.name.clone()
            } else {
                a.product.clone()
            };
            if !a.serial.is_empty() {
                properties.add("serial-number", a.serial.clone());
            }
            if name.is_empty() && a.firmware.is_empty() {
                continue;
            }
            if !seen_firmware.insert((name.to_lowercase(), a.firmware.to_lowercase())) {
                continue;
            }
            let r = refs.unique(&format!("{device_ref}:firmware:passive"));
            let mut p = Props::default();
            p.add(
                "source",
                format!("passive {}", a.protocols.join(", "))
                    .trim()
                    .to_string(),
            );
            // Only the product is a product name (`name` can be a station or host name).
            firmware.push((
                children.len(),
                a.vendor.clone(),
                vec![a.product.clone()],
                a.firmware.clone(),
            ));
            children.push(component(
                "firmware",
                &r,
                if name.is_empty() {
                    "firmware".to_string()
                } else {
                    name
                },
                &a.firmware,
                Some(&a.vendor),
                None,
                p,
            ));
        }

        // LLDP-MED inventory (phones, access points, switches announce it).
        if let Some(lldp) = d.observations.get("LLDP") {
            let get = |k: &str| lldp.get(k).map(|v| clean(v)).unwrap_or_default();
            let (model, maker) = (get("med_model"), get("med_manufacturer"));
            if manufacturer.is_none() && !maker.is_empty() {
                manufacturer = Some((maker.clone(), "LLDP-MED"));
            }
            for (field, label) in [
                ("med_firmware_revision", "firmware revision"),
                ("med_software_revision", "software revision"),
            ] {
                let version = get(field);
                if version.is_empty()
                    || !seen_firmware.insert((model.to_lowercase(), version.to_lowercase()))
                {
                    continue;
                }
                let r = refs.unique(&format!("{device_ref}:firmware:lldp-med"));
                let mut p = Props::default();
                p.add("source", format!("LLDP-MED {label}"));
                firmware.push((
                    children.len(),
                    maker.clone(),
                    vec![model.clone()],
                    version.clone(),
                ));
                children.push(component(
                    "firmware",
                    &r,
                    if model.is_empty() {
                        format!("LLDP-MED {label}")
                    } else {
                        model.clone()
                    },
                    &version,
                    Some(&maker),
                    None,
                    p,
                ));
            }
            for (field, name) in [
                ("med_hardware_revision", "hardware-revision"),
                ("med_serial_number", "serial-number"),
                ("med_model", "model"),
            ] {
                let v = get(field);
                if !v.is_empty() {
                    properties.add(name, v);
                }
            }
        }

        // The imported SBOM of each firmware, nested inside it.
        for (index, vendor, names, version) in firmware {
            let Some(sbom) = input.sboms.find(&vendor, &names, &version) else {
                continue;
            };
            let target = &mut children[index];
            let firmware_ref = target["bom-ref"].as_str().unwrap_or_default().to_string();
            let ip = d
                .ips
                .first()
                .copied()
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            nest_sbom(
                target,
                &firmware_ref,
                sbom,
                &mut refs,
                input.nvd,
                ip,
                &mut stats,
            );
        }

        // Services that named their product in a banner or handshake.
        for ip in &d.ips {
            let Some(h) = hosts.get(ip) else { continue };
            let id = &h.identity;
            let get = |k: String| id.get(&k).map(|v| clean(v)).unwrap_or_default();
            for &port in &h.open {
                let product = get(format!("svc.{port}.product"));
                if product.is_empty() {
                    continue;
                }
                let version = get(format!("svc.{port}.version"));
                let r = refs.unique(&format!("service:{}:{port}/tcp", ref_part(&ip.to_string())));
                let cpe = (input.cpe)(&product, &version);
                services.insert(
                    (*ip, port),
                    Service {
                        bom_ref: r.clone(),
                        product: product.to_lowercase(),
                        cpes: [cpe.clone(), Some(get(format!("svc.{port}.cpe")))]
                            .into_iter()
                            .flatten()
                            .filter(|c| !c.is_empty())
                            .map(|c| c.to_lowercase())
                            .collect(),
                    },
                );
                let mut p = Props::default();
                p.add("source", "service banner".to_string());
                p.add("address", ip.to_string());
                p.add("port", port.to_string());
                p.add("protocol", "tcp".to_string());
                let service = get(format!("svc.{port}"));
                if let Some(name) = service.split_whitespace().next() {
                    p.add("service", name.to_string());
                }
                children.push(component(
                    "application",
                    &r,
                    product,
                    &version,
                    None,
                    cpe,
                    p,
                ));
            }
            let descr = get("snmp.sysdescr".to_string());
            if !descr.is_empty() {
                properties.add("snmp-sysdescr", descr);
            }
            // Installed software the device listed over SNMP (HOST-RESOURCES-MIB): the name as the
            // agent gives it, which often includes the version.
            // Split before cleaning: `clean` cuts a value to its length limit, and the list is
            // far longer than one name.
            let software = id.get("snmp.software").map_or("", String::as_str);
            for (n, name) in software
                .split("; ")
                .map(clean)
                .filter(|s| !s.is_empty())
                .take(crate::snmp::MAX_SOFTWARE)
                .enumerate()
            {
                let r = refs.unique(&format!("{device_ref}:snmp-sw:{n}"));
                let mut p = Props::default();
                p.add("source", "SNMP hrSWInstalledName".to_string());
                p.add("address", ip.to_string());
                children.push(component("application", &r, name, "", None, None, p));
            }
        }

        // The device itself.
        for ip in &d.ips {
            properties.add("address", ip.to_string());
        }
        if !d.mac.is_empty() {
            properties.add("mac", d.mac.clone());
        }
        if d.randomized_mac {
            properties.add("mac-randomized", "true".to_string());
        }
        for name in &d.hostnames {
            properties.add("hostname", clean(name));
        }
        if !d.device_type.is_empty() {
            properties.add("device-type", clean(&d.device_type));
            if !d.type_evidence.is_empty() {
                properties.add("device-type-evidence", clean(&d.type_evidence));
            }
        }
        if !d.os.is_empty() {
            // A guess from fingerprints, so a property and not an operating-system component.
            properties.add(
                "os-guess",
                format!("{} {}", d.os, d.os_confidence).trim().into(),
            );
        }
        let ports = |list: &[u16]| {
            list.iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        if !d.open_tcp.is_empty() {
            properties.add("open-tcp-ports", ports(&d.open_tcp));
        }
        if !d.open_udp.is_empty() {
            properties.add("open-udp-ports", ports(&d.open_udp));
        }
        for s in &d.sources {
            properties.add("source", s.clone());
        }
        let maker = match manufacturer {
            Some((name, from)) => {
                properties.add("manufacturer-source", from.to_string());
                Some(name)
            }
            None if !d.vendor.is_empty() => {
                // The OUI names the maker of the network interface, which is often but not
                // always the maker of the device.
                properties.add("manufacturer-source", "MAC address (OUI)".to_string());
                Some(d.vendor.clone())
            }
            None => None,
        };
        let mut device = component(
            "device",
            &device_ref,
            device_name(d),
            "",
            maker.as_deref(),
            None,
            properties,
        );
        if !d.device_type.is_empty() {
            device["description"] = json!(clean(&d.device_type));
        }
        if !children.is_empty() {
            device["components"] = Value::Array(children);
        }
        components.push(device);
    }

    // The component a finding's CVE affects. Only version-based findings (`cve-...`: the NVD
    // feed, the CVE table, CISA advisories) name a product; they point at the service whose
    // product or CPE they matched, or at the firmware identified on that port. Every other
    // finding with a CVE (Heartbleed, SMBv1, BlueKeep: a probe or a setting, not the product's
    // version) points at the device, so no product is blamed for a CVE it does not have.
    for (f, _) in stats.findings.iter_mut() {
        (input.enrich)(std::slice::from_mut(f));
    }
    let target = |f: &Finding| {
        if let Some(port) = f.port
            && f.id.starts_with("cve-")
        {
            let evidence = f.evidence.to_lowercase();
            if let Some(s) = services.get(&(f.ip, port))
                && (evidence.starts_with(&s.product)
                    || s.cpes.iter().any(|c| evidence.contains(c.as_str())))
            {
                return Some(s.bom_ref.clone());
            }
            if let Some(r) = firmware_refs.get(&(f.ip, port)) {
                return Some(r.clone());
            }
        }
        device_refs.get(&f.ip).cloned()
    };
    let mut pairs: Vec<(&Finding, String)> = input
        .findings
        .iter()
        .filter_map(|f| target(f).map(|r| (f, r)))
        .collect();
    pairs.extend(stats.findings.iter().map(|(f, r)| (f, r.clone())));
    let vulnerabilities = vulnerabilities(&pairs);

    let mut bom = Map::new();
    bom.insert("bomFormat".into(), json!("CycloneDX"));
    bom.insert("specVersion".into(), json!(SPEC_VERSION));
    // Before the serial number, which covers the components' properties.
    let dependencies = uplinks(input, &device_refs, &mut components);
    bom.insert(
        "serialNumber".into(),
        json!(serial_number(
            input.snapshot,
            input.timestamp,
            &components,
            &vulnerabilities
        )),
    );
    bom.insert("version".into(), json!(1));
    bom.insert(
        "metadata".into(),
        metadata(input.snapshot, input.timestamp, &stats),
    );
    bom.insert("components".into(), Value::Array(components));
    if !dependencies.is_empty() {
        bom.insert("dependencies".into(), Value::Array(dependencies));
    }
    if !vulnerabilities.is_empty() {
        bom.insert("vulnerabilities".into(), Value::Array(vulnerabilities));
    }
    Value::Object(bom)
}

/// Whether a device type is network gear a device can hang off.
fn is_network_gear(device_type: &str) -> bool {
    let t = device_type.to_ascii_lowercase();
    [
        "network device",
        "switch",
        "router",
        "access point",
        "firewall",
    ]
    .iter()
    .any(|w| t.contains(w))
}

/// The switch each device hangs off, from the LLDP neighbour tables read over SNMP (the links of
/// the network map), as CycloneDX `dependencies`: the device `dependsOn` the switch. Of the two
/// ends of a link the uplink is the network gear (device type), else the end with more links;
/// a link between two ends that neither rule tells apart, or to a neighbour that is no device of
/// the scan, gives no dependency. Each device also gets `network-scope:connected-to` (the
/// switch's address and port).
fn uplinks(
    input: &Input,
    device_refs: &HashMap<IpAddr, String>,
    components: &mut [Value],
) -> Vec<Value> {
    let hosts = &input.snapshot.hosts;
    if !hosts
        .iter()
        .any(|h| h.identity.contains_key("snmp.lldp.0.local_port"))
    {
        return vec![];
    }
    let graph = crate::topology::build(hosts);
    let ip_of = |node: usize| graph.nodes[node].id.parse::<IpAddr>().ok();
    let gear: HashMap<IpAddr, bool> = input
        .devices
        .iter()
        .flat_map(|d| {
            let g = is_network_gear(&d.device_type);
            d.ips.iter().map(move |ip| (*ip, g))
        })
        .collect();
    let mut degree: HashMap<usize, usize> = HashMap::new();
    for l in &graph.links {
        *degree.entry(l.a).or_default() += 1;
        *degree.entry(l.b).or_default() += 1;
    }
    // device ref -> (switch ref -> "address port")
    let mut depends: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for l in &graph.links {
        let (Some(a), Some(b)) = (ip_of(l.a), ip_of(l.b)) else {
            continue;
        };
        let (Some(ra), Some(rb)) = (device_refs.get(&a), device_refs.get(&b)) else {
            continue;
        };
        if ra == rb {
            continue;
        }
        let (ga, gb) = (
            gear.get(&a).copied().unwrap_or(false),
            gear.get(&b).copied().unwrap_or(false),
        );
        let (da, db) = (degree[&l.a], degree[&l.b]);
        // true: a is the uplink of b
        let a_up = if ga != gb {
            ga
        } else if da != db {
            da > db
        } else {
            continue;
        };
        let (device, switch, switch_ip, port) = if a_up {
            (rb, ra, a, &l.a_port)
        } else {
            (ra, rb, b, &l.b_port)
        };
        depends
            .entry(device.clone())
            .or_default()
            .entry(switch.clone())
            .or_insert_with(|| clean(&format!("{switch_ip} {port}")));
    }
    for c in components.iter_mut() {
        let Some(r) = c["bom-ref"].as_str() else {
            continue;
        };
        let Some(up) = depends.get(r) else { continue };
        let mut p = Props::default();
        for place in up.values() {
            p.add("connected-to", place.clone());
        }
        match c["properties"].as_array_mut() {
            Some(list) => list.extend(p.0),
            None => c["properties"] = Value::Array(p.0),
        }
    }
    depends
        .into_iter()
        .map(|(r, up)| json!({ "ref": r, "dependsOn": up.into_keys().collect::<Vec<_>>() }))
        .collect()
}

fn metadata(s: &Snapshot, timestamp: i64, stats: &SbomStats<'_>) -> Value {
    let mut p = Props::default();
    p.add("targets", clean(&s.targets));
    p.add("scan-complete", s.complete.to_string());
    p.add(
        "scope",
        if stats.firmware == 0 {
            "devices, reported firmware and services; firmware contents only where an SBOM was imported (none matched)".to_string()
        } else {
            format!(
                "devices, reported firmware and services; firmware contents from {} imported SBOM(s) for {} firmware component(s), none for the others",
                stats.sboms.len(),
                stats.firmware
            )
        },
    );
    if stats.not_linked > 0 {
        p.add("sbom-cves-not-linked", stats.not_linked.to_string());
    }
    let mut metadata = json!({
        // Observed on a running network, not built or shipped.
        "lifecycles": [{ "phase": "operations" }],
        "tools": {
            "components": [{
                "type": "application",
                "name": "Network Scope",
                "version": env!("CARGO_PKG_VERSION"),
                "externalReferences": [{
                    "type": "website",
                    "url": "https://github.com/Sparkz400/network-scope"
                }]
            }]
        },
        "component": {
            "type": "platform",
            "bom-ref": "network",
            "name": if s.targets.trim().is_empty() { "Network".to_string() } else { format!("Network {}", clean(&s.targets)) },
        },
        "properties": p.0,
    });
    // Without a recorded scan time the field is left out instead of claiming 1970.
    if timestamp > 0 {
        metadata["timestamp"] = json!(crate::notify::rfc3339(timestamp));
    }
    metadata
}

/// One vulnerability per CVE, affecting every component a finding names it for. The rating is
/// the finding's severity from Network Scope's rules (method `other`), not a CVSS score.
fn vulnerabilities(pairs: &[(&Finding, String)]) -> Vec<Value> {
    struct Entry<'a> {
        severity: Severity,
        refs: BTreeSet<String>,
        first: &'a Finding,
        rules: BTreeSet<&'a str>,
        found_on: BTreeSet<String>,
        confidence: u8,
        kev: bool,
        epss: Option<f64>,
        vex: Option<&'a crate::vex::Applied>,
    }
    // One vulnerability per CVE and vendor statement: devices the vendor says are not affected
    // are listed apart from the affected ones.
    let mut by_cve: BTreeMap<(String, Option<crate::vex::State>), Entry> = BTreeMap::new();
    for (f, r) in pairs {
        for cve in &f.cve {
            let cve = cve.trim();
            if cve.is_empty() {
                continue;
            }
            let state = f.vex.as_ref().map(|v| v.state);
            let e = by_cve
                .entry((cve.to_string(), state))
                .or_insert_with(|| Entry {
                    severity: f.severity,
                    refs: BTreeSet::new(),
                    first: f,
                    rules: BTreeSet::new(),
                    found_on: BTreeSet::new(),
                    confidence: f.confidence,
                    kev: false,
                    epss: None,
                    vex: f.vex.as_ref(),
                });
            e.severity = e.severity.max(f.severity);
            e.refs.insert(r.clone());
            e.rules.insert(&f.id);
            if !f.ip.is_unspecified() {
                e.found_on.insert(match f.port {
                    Some(p) => format!("{}:{p}", f.ip),
                    None => f.ip.to_string(),
                });
            }
            e.confidence = e.confidence.max(f.confidence);
            e.kev |= f.exploit.kev;
            if let Some(score) = f.exploit.epss {
                let v = score.as_f64();
                e.epss = Some(e.epss.map_or(v, |old: f64| old.max(v)));
            }
        }
    }
    by_cve
        .into_iter()
        .map(|((cve, state), e)| {
            let mut p = Props::default();
            for rule in &e.rules {
                p.add("rule", rule.to_string());
            }
            // The affected components already say where; the addresses are a readable summary,
            // cut for a CVE on thousands of hosts (the total stays).
            for place in e.found_on.iter().take(MAX_FOUND_ON) {
                p.add("found-on", place.clone());
            }
            if e.found_on.len() > MAX_FOUND_ON {
                p.add("found-on-total", e.found_on.len().to_string());
            }
            if e.confidence > 0 {
                p.add("confidence", e.confidence.to_string());
            }
            if e.kev {
                p.add("cisa-kev", "true".to_string());
            }
            if let Some(epss) = e.epss {
                p.add("epss", format!("{epss:.5}"));
            }
            let bom_ref = match state {
                None => format!("vulnerability:{}", ref_part(&cve)),
                Some(s) => format!("vulnerability:{}:{}", ref_part(&cve), s.cyclonedx()),
            };
            let mut v = json!({
                "bom-ref": bom_ref,
                "id": cve,
                "ratings": [{
                    "source": { "name": "Network Scope" },
                    "severity": e.severity.name(),
                    "method": "other",
                    "justification": "Severity of the Network Scope finding; version-based hints can be false positives where a vendor backported the fix."
                }],
                "description": clean(&e.first.title),
                "detail": clean(&e.first.evidence),
                "recommendation": clean(&e.first.advice),
                "affects": e.refs.iter().map(|r| json!({ "ref": r })).collect::<Vec<_>>(),
                "properties": p.0,
            });
            if let Some(vex) = e.vex {
                let mut analysis = json!({ "state": vex.state.cyclonedx() });
                if let Some(j) = justification(&vex.justification) {
                    analysis["justification"] = json!(j);
                }
                let detail = format!(
                    "{} (VEX {}{})",
                    clean(&vex.detail),
                    clean(&vex.source),
                    if vex.justification.is_empty() {
                        String::new()
                    } else {
                        format!(", {}", clean(&vex.justification))
                    }
                );
                analysis["detail"] = json!(detail.trim());
                v["analysis"] = analysis;
            }
            if cve.starts_with("CVE-") {
                v["source"] = json!({
                    "name": "NVD",
                    "url": format!("https://nvd.nist.gov/vuln/detail/{cve}")
                });
            }
            v
        })
        .collect()
}

/// The CycloneDX `analysis.justification` of a VEX justification: CycloneDX values as they are,
/// CSAF flag labels mapped to the closest one; `None` when there is none.
fn justification(text: &str) -> Option<&'static str> {
    Some(match text.trim() {
        "code_not_present" | "component_not_present" | "vulnerable_code_not_present" => {
            "code_not_present"
        }
        "code_not_reachable" | "vulnerable_code_not_in_execute_path" => "code_not_reachable",
        "requires_configuration" => "requires_configuration",
        "requires_dependency" => "requires_dependency",
        "requires_environment" => "requires_environment",
        "protected_by_compiler" => "protected_by_compiler",
        "protected_at_runtime" => "protected_at_runtime",
        "protected_at_perimeter" => "protected_at_perimeter",
        "protected_by_mitigating_control"
        | "inline_mitigations_already_exist"
        | "vulnerable_code_cannot_be_controlled_by_adversary" => "protected_by_mitigating_control",
        _ => return None,
    })
}

/// Nests an imported SBOM's components inside a firmware component, says which SBOM it was, and
/// adds the CVEs the NVD feed has for the components' CPE names (version-based hints, like the
/// scan's own: a vendor may have backported the fix).
fn nest_sbom(
    firmware: &mut Value,
    firmware_ref: &str,
    sbom: &crate::sbom::Sbom,
    refs: &mut Refs,
    nvd: &dyn Fn(&str) -> Vec<crate::nvd::Hit>,
    ip: IpAddr,
    stats: &mut SbomStats<'_>,
) {
    stats.firmware += 1;
    stats.sboms.insert(sbom.sha256.clone());
    let mut children = vec![];
    // Single files (Syft lists every file of an unpacked image) are left out: they would repeat
    // under every device on that firmware, and the packages are what CVEs and VEX refer to.
    let mut files = 0usize;
    for (i, c) in sbom.components.iter().enumerate() {
        if c.kind == "file" {
            files += 1;
            continue;
        }
        // By position: unique without searching, however often a name repeats.
        let r = refs.unique(&format!("{firmware_ref}:sbom:{i}"));
        let mut p = Props::default();
        p.add("source", format!("SBOM {}", sbom.source));
        let mut value = component(
            &c.kind,
            &r,
            c.name.clone(),
            &c.version,
            None,
            (!c.cpe.is_empty()).then(|| clean(&c.cpe)),
            p,
        );
        if !c.supplier.is_empty() {
            value["supplier"] = json!({ "name": clean(&c.supplier) });
        }
        if !c.purl.is_empty() {
            value["purl"] = json!(clean(&c.purl));
        }
        if !c.licenses.is_empty() {
            value["licenses"] = Value::Array(
                c.licenses
                    .iter()
                    .map(|l| json!({ "license": { "name": clean(l) } }))
                    .collect(),
            );
        }
        if !c.cpe.is_empty() {
            let hits = stats
                .lookups
                .entry(c.cpe.clone())
                .or_insert_with(|| nvd(&c.cpe));
            for hit in hits.iter() {
                if stats.findings.len() >= MAX_SBOM_FINDINGS {
                    stats.not_linked += 1;
                    continue;
                }
                stats.findings.push((
                    Finding {
                        severity: hit.severity,
                        id: format!("sbom-cve-{}", hit.cve.to_ascii_lowercase()),
                        title: if hit.title.is_empty() {
                            hit.cve.clone()
                        } else {
                            hit.title.clone()
                        },
                        ip,
                        port: None,
                        evidence: format!(
                            "{} {} in the firmware SBOM {}: {} in the NVD range {}. Version-based hint.",
                            c.name, c.version, sbom.source, c.cpe, hit.range
                        ),
                        cve: vec![hit.cve.clone()],
                        advice: "Update the firmware to a release that fixes the component, or confirm with the vendor that it is not affected.".into(),
                        exploit: Default::default(),
                        reference: None,
                        confidence: 40,
                        vex: {
                            let firmware_names: Vec<String> = std::iter::once(&sbom.product)
                                .chain(&sbom.aliases)
                                .cloned()
                                .collect();
                            // The component's own package URL is the most exact; then the
                            // firmware; then the component by name.
                            (!c.purl.is_empty())
                                .then(|| stats.vex.lookup_purl(&hit.cve, &c.purl, &c.version))
                                .flatten()
                                .or_else(|| {
                                    stats.vex.lookup(
                                        &hit.cve,
                                        &sbom.vendor,
                                        &firmware_names,
                                        &sbom.version,
                                    )
                                })
                                .or_else(|| {
                                    stats.vex.lookup(
                                        &hit.cve,
                                        &c.supplier,
                                        std::slice::from_ref(&c.name),
                                        &c.version,
                                    )
                                })
                                .map(crate::vex::Applied::from)
                        },
                    },
                    r.clone(),
                ));
            }
        }
        children.push(value);
    }
    let mut props: Vec<Value> = firmware["properties"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut p = Props::default();
    p.add("sbom", sbom.source.clone());
    p.add("sbom-sha256", sbom.sha256.clone());
    p.add("sbom-format", sbom.format.clone());
    p.add(
        "sbom-match",
        format!(
            "vendor, product and version: {} {} {}",
            sbom.vendor, sbom.product, sbom.version
        )
        .trim()
        .to_string(),
    );
    if sbom.truncated > 0 {
        p.add("sbom-components-not-kept", sbom.truncated.to_string());
    }
    if files > 0 {
        p.add("sbom-files-left-out", files.to_string());
    }
    props.extend(p.0);
    firmware["properties"] = Value::Array(props);
    if !children.is_empty() {
        firmware["components"] = Value::Array(children);
    }
}

/// A component with the fields every kind shares; empty values are left out.
fn component(
    kind: &str,
    bom_ref: &str,
    name: String,
    version: &str,
    manufacturer: Option<&str>,
    cpe: Option<String>,
    properties: Props,
) -> Value {
    let mut c = Map::new();
    c.insert("type".into(), json!(kind));
    c.insert("bom-ref".into(), json!(bom_ref));
    let name = clean(&name);
    c.insert(
        "name".into(),
        json!(if name.is_empty() {
            "unknown".into()
        } else {
            name
        }),
    );
    let version = clean(version);
    if !version.is_empty() {
        c.insert("version".into(), json!(version));
    }
    if let Some(m) = manufacturer.map(clean).filter(|m| !m.is_empty()) {
        c.insert("manufacturer".into(), json!({ "name": m }));
    }
    if let Some(cpe) = cpe {
        c.insert("cpe".into(), json!(cpe));
    }
    if !properties.0.is_empty() {
        c.insert("properties".into(), Value::Array(properties.0));
    }
    Value::Object(c)
}

fn device_name(d: &Device) -> String {
    d.hostnames
        .first()
        .map(|n| clean(n))
        .filter(|n| !n.is_empty())
        .or_else(|| d.ips.first().map(IpAddr::to_string))
        .unwrap_or_else(|| d.mac.clone())
}

fn asset_matches(a: &Asset, d: &Device) -> bool {
    (!a.mac.is_empty() && !d.mac.is_empty() && a.mac.eq_ignore_ascii_case(&d.mac))
        || a.ips.iter().any(|ip| d.ips.contains(ip))
}

/// `network-scope:<name>` properties in the order they were added.
#[derive(Default)]
struct Props(Vec<Value>);
impl Props {
    fn add(&mut self, name: &str, value: String) {
        let value = clean(&value);
        if !value.is_empty() {
            self.0
                .push(json!({ "name": format!("{NS}:{name}"), "value": value }));
        }
    }
}

/// bom-refs are unique in a document; a second use of the same text gets a counter.
#[derive(Default)]
struct Refs(BTreeSet<String>);
impl Refs {
    fn unique(&mut self, base: &str) -> String {
        let mut candidate = base.to_string();
        let mut n = 2;
        while !self.0.insert(candidate.clone()) {
            candidate = format!("{base}:{n}");
            n += 1;
        }
        candidate
    }
}

/// Text for a bom-ref: printable ASCII without spaces.
fn ref_part(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_graphic() { c } else { '_' })
        .take(80)
        .collect()
}

/// A device-supplied string on one line, without control characters, at most `MAX_VALUE` chars.
fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_VALUE)
        .collect::<String>()
        .trim()
        .to_string()
}

/// A name-based UUID (RFC 9562 version 5, SHA-1) of the document's content (the components and
/// vulnerabilities, which already reflect the imported SBOMs and feeds), the scan's targets and
/// time: the same content gives the same serial number, other content another one.
fn serial_number(
    s: &Snapshot,
    timestamp: i64,
    components: &[Value],
    vulnerabilities: &[Value],
) -> String {
    // A fixed namespace for Network Scope BOMs (a random UUID chosen once).
    const NAMESPACE: [u8; 16] = [
        0x6b, 0x8f, 0x3a, 0x52, 0x1d, 0x4e, 0x4c, 0x9a, 0x9e, 0x21, 0x7c, 0x0d, 0x5a, 0x33, 0x18,
        0xe4,
    ];
    // The components are in a fixed order (devices by key, addresses sorted), so sorting the
    // desktop's table does not change the serial number of the same data.
    let content = serde_json::to_string(&(components, vulnerabilities)).unwrap_or_default();
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    ctx.update(&NAMESPACE);
    ctx.update(timestamp.to_string().as_bytes());
    ctx.update(b"\n");
    ctx.update(s.targets.as_bytes());
    ctx.update(b"\n");
    ctx.update(content.as_bytes());
    let digest = ctx.finish();
    let mut b = [0u8; 16];
    b.copy_from_slice(&digest.as_ref()[..16]);
    b[6] = (b[6] & 0x0f) | 0x50; // version 5
    b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "urn:uuid:{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
#[path = "cyclonedx_tests.rs"]
mod tests;
