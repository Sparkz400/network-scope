//! nmap XML interchange. Export writes the subset of the nmaprun format that common importers
//! read (hosts, addresses, hostnames, ports with services, OS match, trace); import reads the same
//! subset back into a snapshot so nmap results can be diffed, reported and merged with ours.
use crate::{
    scan::{Host, Settings},
    store::Snapshot,
    trace::Hop,
};
use std::{collections::BTreeMap, fmt::Write as _, net::IpAddr};

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c if c.is_control() && c != '\n' && c != '\t' => {}
            c => out.push(c),
        }
    }
    out
}

fn service_attrs(h: &Host, port: u16) -> Option<String> {
    let svc = h.identity.get(&format!("svc.{port}"))?;
    if svc.starts_with("unidentified") {
        return None;
    }
    let name_word = svc.split_whitespace().next().unwrap_or("");
    let (name, tunnel) = match name_word {
        "https" => ("http", true),
        w if w.starts_with("ssl/") => (&w[4..], true),
        w => (w, false),
    };
    let product = h
        .identity
        .get(&format!("svc.{port}.product"))
        .map_or("", String::as_str);
    let version = h
        .identity
        .get(&format!("svc.{port}.version"))
        .map_or("", String::as_str);
    let extra = svc
        .rsplit_once(" (")
        .and_then(|(_, e)| e.strip_suffix(')'))
        .unwrap_or("");
    let mut s = format!("name=\"{}\"", esc(name));
    if !product.is_empty() {
        let _ = write!(s, " product=\"{}\"", esc(product));
    }
    if !version.is_empty() {
        let _ = write!(s, " version=\"{}\"", esc(version));
    }
    if !extra.is_empty() {
        let _ = write!(s, " extrainfo=\"{}\"", esc(extra));
    }
    if tunnel {
        s.push_str(" tunnel=\"ssl\"");
    }
    s.push_str(" method=\"probed\" conf=\"10\"");
    Some(s)
}

pub fn export(snapshot: &Snapshot, timestamp: i64) -> String {
    let mut x = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let up: Vec<&Host> = snapshot.hosts.iter().filter(|h| h.responding).collect();
    let mut ports: Vec<u16> = snapshot
        .hosts
        .iter()
        .flat_map(|h| h.open.iter().copied())
        .collect();
    ports.sort_unstable();
    ports.dedup();
    let _ = writeln!(
        x,
        "<nmaprun scanner=\"network-scope\" args=\"{}\" start=\"{timestamp}\" startstr=\"{}\" version=\"{}\" xmloutputversion=\"1.05\">",
        esc(&format!("network-scope scan {}", snapshot.targets)),
        crate::tls::date(timestamp),
        env!("CARGO_PKG_VERSION")
    );
    let _ = writeln!(
        x,
        "<scaninfo type=\"connect\" protocol=\"tcp\" numservices=\"{}\" services=\"{}\"/>",
        snapshot.settings.ports.split(',').count(),
        esc(&snapshot.settings.ports)
    );
    for h in &up {
        let _ = writeln!(
            x,
            "<host starttime=\"{timestamp}\" endtime=\"{timestamp}\">"
        );
        let _ = writeln!(
            x,
            "<status state=\"up\" reason=\"{}\" reason_ttl=\"{}\"/>",
            if h.ping.is_some() {
                "echo-reply"
            } else {
                "syn-ack"
            },
            h.ttl.unwrap_or(0)
        );
        let _ = writeln!(
            x,
            "<address addr=\"{}\" addrtype=\"{}\"/>",
            h.ip,
            if h.ip.is_ipv4() { "ipv4" } else { "ipv6" }
        );
        if !h.mac.is_empty() {
            let vendor = h.identity.get("mac.vendor").map_or("", String::as_str);
            let _ = writeln!(
                x,
                "<address addr=\"{}\" addrtype=\"mac\" vendor=\"{}\"/>",
                esc(&h.mac),
                esc(vendor)
            );
        }
        x.push_str("<hostnames>");
        if !h.hostname.is_empty() {
            let _ = write!(x, "<hostname name=\"{}\" type=\"PTR\"/>", esc(&h.hostname));
        }
        x.push_str("</hostnames>\n<ports>");
        if h.ports_checked {
            let _ = write!(x, "<extraports state=\"closed\" count=\"{}\"/>", h.closed);
        }
        for p in &h.open {
            let _ = write!(x, "<port protocol=\"tcp\" portid=\"{p}\"><state state=\"open\" reason=\"syn-ack\" reason_ttl=\"0\"/>");
            if let Some(attrs) = service_attrs(h, *p) {
                let _ = write!(x, "<service {attrs}/>");
            }
            if let Some(subject) = h.identity.get(&format!("tls.{p}.subject")) {
                let mut out = format!("Subject: {subject}");
                for (label, key) in [
                    ("Issuer", "issuer"),
                    ("Subject Alternative Name", "san"),
                    ("Not valid before", "not_before"),
                    ("Not valid after", "not_after"),
                ] {
                    if let Some(v) = h.identity.get(&format!("tls.{p}.{key}")) {
                        let _ = write!(out, "\n{label}: {v}");
                    }
                }
                let _ = write!(x, "<script id=\"ssl-cert\" output=\"{}\"/>", esc(&out));
            }
            x.push_str("</port>");
        }
        for p in &h.udp_open {
            let _ = write!(x, "<port protocol=\"udp\" portid=\"{p}\"><state state=\"open\" reason=\"udp-response\" reason_ttl=\"0\"/>");
            if let Some(info) = h.identity.get(&format!("udp.{p}")) {
                let _ = write!(x, "<script id=\"banner\" output=\"{}\"/>", esc(info));
            }
            x.push_str("</port>");
        }
        x.push_str("</ports>\n");
        if let Some(os) = h.identity.get("os.guess") {
            let accuracy = h
                .identity
                .get("os.confidence")
                .map_or("0", |c| c.trim_end_matches('%'));
            let _ = writeln!(
                x,
                "<os><osmatch name=\"{}\" accuracy=\"{}\" line=\"0\"/></os>",
                esc(os),
                esc(accuracy)
            );
        }
        if !h.trace.is_empty() {
            x.push_str("<trace>");
            for hop in &h.trace {
                let _ = write!(
                    x,
                    "<hop ttl=\"{}\" ipaddr=\"{}\" rtt=\"{}\"/>",
                    hop.ttl,
                    hop.ip.map_or("*".to_string(), |i| i.to_string()),
                    hop.rtt.unwrap_or(0)
                );
            }
            x.push_str("</trace>\n");
        }
        x.push_str("</host>\n");
    }
    let _ = writeln!(
        x,
        "<runstats><finished time=\"{timestamp}\" timestr=\"{}\" elapsed=\"0\" exit=\"{}\"/><hosts up=\"{}\" down=\"{}\" total=\"{}\"/></runstats>",
        crate::tls::date(timestamp),
        if snapshot.complete { "success" } else { "error" },
        up.len(),
        snapshot.hosts.len() - up.len(),
        snapshot.hosts.len()
    );
    x.push_str("</nmaprun>\n");
    x
}

fn child<'a, 'b>(n: roxmltree::Node<'a, 'b>, name: &str) -> Option<roxmltree::Node<'a, 'b>> {
    n.children().find(|c| c.has_tag_name(name))
}

pub const MAX_IMPORT_BYTES: usize = 256 * 1024 * 1024;

pub fn import(xml: &str) -> Result<Snapshot, String> {
    if xml.len() > MAX_IMPORT_BYTES {
        return Err("XML file is too large (limit 256 MB)".into());
    }
    let doc = roxmltree::Document::parse_with_options(
        xml,
        roxmltree::ParsingOptions {
            allow_dtd: true,
            nodes_limit: 8_000_000,
        },
    )
    .map_err(|e| format!("Not valid XML: {e}"))?;
    let root = doc.root_element();
    if root.tag_name().name() != "nmaprun" {
        return Err("Not an nmap XML file (root element is not <nmaprun>)".into());
    }
    let mut hosts = vec![];
    for host in root.children().filter(|n| n.has_tag_name("host")) {
        if child(host, "status").and_then(|s| s.attribute("state")) != Some("up") {
            continue;
        }
        let (mut ip, mut mac) = (None::<IpAddr>, String::new());
        let mut identity = BTreeMap::new();
        for a in host.children().filter(|n| n.has_tag_name("address")) {
            match a.attribute("addrtype") {
                Some("ipv4" | "ipv6") if ip.is_none() => {
                    ip = a.attribute("addr").and_then(|v| v.parse().ok())
                }
                Some("mac") => {
                    mac = a.attribute("addr").unwrap_or("").to_string();
                    if let Some(v) = a.attribute("vendor").filter(|v| !v.is_empty()) {
                        identity.insert("mac.vendor".to_string(), v.to_string());
                    }
                }
                _ => {}
            }
        }
        let Some(ip) = ip else { continue };
        let hostname = child(host, "hostnames")
            .and_then(|h| child(h, "hostname"))
            .and_then(|h| h.attribute("name"))
            .unwrap_or("")
            .to_string();
        let (mut open, mut udp_open, mut closed) = (vec![], vec![], 0usize);
        let ports = child(host, "ports");
        if let Some(ports) = ports {
            if let Some(e) =
                child(ports, "extraports").filter(|e| e.attribute("state") == Some("closed"))
            {
                closed = e
                    .attribute("count")
                    .and_then(|c| c.parse().ok())
                    .unwrap_or(0);
            }
            for p in ports.children().filter(|n| n.has_tag_name("port")) {
                let Some(id) = p.attribute("portid").and_then(|v| v.parse::<u16>().ok()) else {
                    continue;
                };
                if child(p, "state").and_then(|s| s.attribute("state")) != Some("open") {
                    continue;
                }
                if p.attribute("protocol") == Some("udp") {
                    udp_open.push(id);
                    continue;
                }
                open.push(id);
                if let Some(s) = child(p, "service") {
                    let attr = |n: &str| s.attribute(n).unwrap_or("").trim();
                    let mut name = attr("name").to_string();
                    if s.attribute("tunnel") == Some("ssl") {
                        name = if name == "http" {
                            "https".into()
                        } else {
                            format!("ssl/{name}")
                        };
                    }
                    let mut summary = name;
                    for part in [attr("product"), attr("version")] {
                        if !part.is_empty() {
                            summary.push(' ');
                            summary.push_str(part);
                        }
                    }
                    let extra = attr("extrainfo")
                        .trim_start_matches('(')
                        .trim_end_matches(')');
                    if !extra.is_empty() {
                        summary.push_str(&format!(" ({extra})"));
                    }
                    if !summary.is_empty() {
                        identity.insert(format!("svc.{id}"), summary);
                    }
                    if !attr("product").is_empty() {
                        identity.insert(format!("svc.{id}.product"), attr("product").to_string());
                    }
                    if !attr("version").is_empty() {
                        identity.insert(format!("svc.{id}.version"), attr("version").to_string());
                    }
                }
            }
        }
        if let Some(m) = child(host, "os").and_then(|os| {
            os.children()
                .filter(|n| n.has_tag_name("osmatch"))
                .max_by_key(|n| {
                    n.attribute("accuracy")
                        .and_then(|a| a.parse::<u32>().ok())
                        .unwrap_or(0)
                })
        }) {
            identity.insert(
                "os.guess".into(),
                m.attribute("name").unwrap_or("").to_string(),
            );
            identity.insert(
                "os.confidence".into(),
                format!("{}%", m.attribute("accuracy").unwrap_or("0")),
            );
        }
        let trace = child(host, "trace")
            .map(|t| {
                t.children()
                    .filter(|n| n.has_tag_name("hop"))
                    .filter_map(|n| {
                        Some(Hop {
                            ttl: n.attribute("ttl")?.parse().ok()?,
                            ip: n.attribute("ipaddr").and_then(|a| a.parse().ok()),
                            rtt: n
                                .attribute("rtt")
                                .and_then(|r| r.parse::<f64>().ok())
                                .map(|r| r.round() as u32),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let status = child(host, "status");
        hosts.push(Host {
            ip,
            responding: true,
            ping: None,
            ttl: status
                .and_then(|s| s.attribute("reason_ttl"))
                .and_then(|t| t.parse().ok())
                .filter(|t| *t > 0),
            hostname,
            mac,
            open,
            closed,
            unanswered: 0,
            errors: vec![],
            ports_checked: ports.is_some(),
            identity,
            udp_open,
            trace,
        });
    }
    let complete = root
        .descendants()
        .find(|n| n.has_tag_name("finished"))
        .and_then(|f| f.attribute("exit"))
        .is_none_or(|e| e == "success");
    let mut settings = Settings::default();
    if let Some(s) = root
        .descendants()
        .find(|n| n.has_tag_name("scaninfo") && n.attribute("protocol") == Some("tcp"))
    {
        if let Some(p) = s.attribute("services").filter(|p| !p.is_empty()) {
            settings.ports = p.to_string();
        }
    }
    let targets = root
        .attribute("args")
        .filter(|a| !a.is_empty())
        .unwrap_or("imported nmap scan")
        .to_string();
    Ok(Snapshot {
        targets,
        complete,
        settings,
        hosts,
        observations: vec![],
        notes: BTreeMap::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> Snapshot {
        let mut identity = BTreeMap::new();
        for (k, v) in [
            ("svc.22", "ssh OpenSSH 9.6p1 (protocol 2.0)"),
            ("svc.22.product", "OpenSSH"),
            ("svc.22.version", "9.6p1"),
            ("svc.443", "https nginx 1.24.0 (200 OK)"),
            ("svc.443.product", "nginx"),
            ("svc.443.version", "1.24.0"),
            ("svc.8080", "unidentified"),
            ("tls.443.subject", "CN=\"x\" <y>"),
            ("tls.443.not_after", "2027-01-01"),
            ("udp.161", "SNMP sysDescr: Linux & co"),
            ("os.guess", "Linux"),
            ("os.confidence", "70%"),
            ("mac.vendor", "Raspberry Pi Trading Ltd"),
        ] {
            identity.insert(k.to_string(), v.to_string());
        }
        let host = Host {
            ip: "10.0.0.5".parse().unwrap(),
            responding: true,
            ping: Some(1),
            ttl: Some(64),
            hostname: "pi<1>".into(),
            mac: "DC:A6:32:00:00:01".into(),
            open: vec![22, 443, 8080],
            closed: 97,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity,
            udp_open: vec![161],
            trace: vec![
                Hop {
                    ttl: 1,
                    ip: Some("10.0.0.1".parse().unwrap()),
                    rtt: Some(2),
                },
                Hop {
                    ttl: 2,
                    ip: None,
                    rtt: None,
                },
            ],
        };
        let mut down = host.clone();
        down.ip = "10.0.0.6".parse().unwrap();
        down.responding = false;
        Snapshot {
            targets: "10.0.0.0/24".into(),
            complete: true,
            settings: Settings {
                ports: "22,443,8080".into(),
                ..Settings::default()
            },
            hosts: vec![host, down],
            observations: vec![],
            notes: BTreeMap::new(),
        }
    }

    #[test]
    fn export_is_well_formed_and_escaped() {
        let xml = export(&snapshot(), 1_700_000_000);
        assert!(xml.starts_with("<?xml"));
        let doc = roxmltree::Document::parse(&xml).expect("export must be valid XML");
        let run = doc.root_element();
        assert_eq!(run.tag_name().name(), "nmaprun");
        assert_eq!(
            doc.descendants().filter(|n| n.has_tag_name("host")).count(),
            1,
            "down hosts are not listed"
        );
        let up = doc.descendants().find(|n| n.has_tag_name("hosts")).unwrap();
        assert_eq!(
            (
                up.attribute("up"),
                up.attribute("down"),
                up.attribute("total")
            ),
            (Some("1"), Some("1"), Some("2"))
        );
        assert!(xml.contains("tunnel=\"ssl\""));
        assert!(xml.contains("pi&lt;1&gt;"));
        assert!(xml.contains("id=\"ssl-cert\""));
        assert!(!xml.contains("<y>"), "attribute values must be escaped");
        let svc8080 = doc
            .descendants()
            .filter(|n| n.has_tag_name("port"))
            .find(|p| p.attribute("portid") == Some("8080"))
            .unwrap();
        assert!(
            !svc8080.children().any(|c| c.has_tag_name("service")),
            "unidentified ports carry no service element"
        );
    }

    #[test]
    fn export_then_import_round_trips() {
        let original = snapshot();
        let back = import(&export(&original, 1_700_000_000)).unwrap();
        assert_eq!(back.hosts.len(), 1);
        let h = &back.hosts[0];
        assert_eq!(h.ip, original.hosts[0].ip);
        assert_eq!(
            (h.open.clone(), h.udp_open.clone()),
            (vec![22, 443, 8080], vec![161])
        );
        assert_eq!(h.mac, "DC:A6:32:00:00:01");
        assert_eq!(h.hostname, "pi<1>");
        assert_eq!(h.closed, 97);
        assert_eq!(h.identity["svc.22"], "ssh OpenSSH 9.6p1 (protocol 2.0)");
        assert_eq!(h.identity["svc.443"], "https nginx 1.24.0 (200 OK)");
        assert_eq!(h.identity["svc.22.version"], "9.6p1");
        assert_eq!(h.identity["os.guess"], "Linux");
        assert_eq!(h.identity["os.confidence"], "70%");
        assert_eq!(h.identity["mac.vendor"], "Raspberry Pi Trading Ltd");
        assert_eq!(h.trace.len(), 2);
        assert_eq!(h.trace[1].ip, None);
        assert_eq!(h.ttl, Some(64));
        assert!(back.complete);
        assert_eq!(back.settings.ports, "22,443,8080");
    }

    #[test]
    fn imports_a_real_nmap_document() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<nmaprun scanner="nmap" args="nmap -sV -O 192.168.1.0/24" start="1" startstr="x" version="7.94" xmloutputversion="1.05">
<scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1000"/>
<host starttime="1" endtime="2"><status state="up" reason="arp-response" reason_ttl="0"/>
<address addr="192.168.1.10" addrtype="ipv4"/><address addr="00:0C:29:AA:BB:CC" addrtype="mac" vendor="VMware"/>
<hostnames><hostname name="web.lan" type="PTR"/></hostnames>
<ports><extraports state="closed" count="998"><extrareasons reason="resets" count="998"/></extraports>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="http" product="Apache httpd" version="2.4.49" extrainfo="(Unix)" method="probed" conf="10"/></port>
<port protocol="tcp" portid="81"><state state="filtered" reason="no-response"/></port>
<port protocol="udp" portid="161"><state state="open|filtered" reason="no-response"/></port>
</ports>
<os><osmatch name="Linux 5.4" accuracy="90" line="1"/><osmatch name="Linux 4.x" accuracy="95" line="2"/></os>
<trace><hop ttl="1" ipaddr="192.168.1.1" rtt="0.45"/></trace>
</host>
<host><status state="down" reason="no-response"/><address addr="192.168.1.11" addrtype="ipv4"/></host>
<runstats><finished time="2" exit="success"/><hosts up="1" down="1" total="2"/></runstats>
</nmaprun>"#;
        let s = import(xml).unwrap();
        assert_eq!(s.targets, "nmap -sV -O 192.168.1.0/24");
        assert_eq!(s.hosts.len(), 1);
        let h = &s.hosts[0];
        assert_eq!(h.open, [80]);
        assert!(h.udp_open.is_empty(), "open|filtered is not open");
        assert_eq!(h.closed, 998);
        assert_eq!(h.identity["svc.80"], "http Apache httpd 2.4.49 (Unix)");
        assert_eq!(h.identity["os.guess"], "Linux 4.x", "highest accuracy wins");
        assert_eq!(h.trace[0].rtt, Some(0));
        assert_eq!(h.ttl, None);
        assert_eq!(s.settings.ports, "1-1000");
        // Imported nmap data feeds the same analysis as our own scans.
        assert!(crate::risk::analyze(&s.hosts)
            .iter()
            .any(|f| f.cve.contains(&"CVE-2021-41773".to_string())));
    }

    #[test]
    fn rejects_bad_input() {
        assert!(import("not xml").is_err());
        assert!(import("<html/>").unwrap_err().contains("nmaprun"));
        assert!(
            import("<nmaprun><host><status state=\"up\"/></host></nmaprun>")
                .unwrap()
                .hosts
                .is_empty(),
            "host without an address is skipped"
        );
        // An entity bomb must fail or stay bounded rather than exhaust memory.
        let bomb = "<?xml version=\"1.0\"?><!DOCTYPE nmaprun [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\"><!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;\"><!ENTITY d \"&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;\"><!ENTITY e \"&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;\"><!ENTITY f \"&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;\"><!ENTITY g \"&f;&f;&f;&f;&f;&f;&f;&f;&f;&f;\"><!ENTITY h \"&g;&g;&g;&g;&g;&g;&g;&g;&g;&g;\"><!ENTITY i \"&h;&h;&h;&h;&h;&h;&h;&h;&h;&h;\"><!ENTITY j \"&i;&i;&i;&i;&i;&i;&i;&i;&i;&i;\">]><nmaprun args=\"&j;\"/>";
        assert!(import(bomb).is_err(), "roxmltree caps entity expansion");
    }
}
