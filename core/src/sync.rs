//! Export of a saved scan to other systems, and an opt-in push to some of them: NetBox, Snipe-IT,
//! Splunk (HTTP Event Collector), Elastic and a ServiceNow-ready CSV. Each export is one record
//! per device (active scan and passive observations merged, see [`crate::devices`]) with its
//! risks; the text is what the target's own import or API takes.
//!
//! | Target | Output | Push |
//! |---|---|---|
//! | `netbox` | JSON array of IP addresses (`address`, `status`, `dns_name`, `description`) for `POST /api/ipam/ip-addresses/` | yes |
//! | `netbox-devices` | JSON array of devices; needs a site, a role and a device type | yes |
//! | `snipeit` | CSV for the Snipe-IT asset importer | no |
//! | `splunk` | HTTP Event Collector events (concatenated JSON objects) | yes |
//! | `elastic` | `_bulk` NDJSON (an action line and a document per device) | yes |
//! | `servicenow` | CSV with `cmdb_ci` column names for an import set | no |
//!
//! A push is never automatic: it needs a URL and the *name of an environment variable* that holds
//! the token ([`push`]); the token is sent only in the `Authorization` header, never in the URL.
//! The field names follow the vendors' documentation; the exports have not been tested against a
//! real NetBox, Snipe-IT, Splunk, Elastic or ServiceNow instance.
use crate::{devices::Device, notify, report, risk::Finding, scan::csv_cell, store::Snapshot};
use serde_json::{Value, json};
use std::{net::IpAddr, time::Duration};

/// What to export to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Netbox,
    NetboxDevices,
    SnipeIt,
    Splunk,
    Elastic,
    ServiceNow,
}

impl Target {
    pub const ALL: [Target; 6] = [
        Target::Netbox,
        Target::NetboxDevices,
        Target::SnipeIt,
        Target::Splunk,
        Target::Elastic,
        Target::ServiceNow,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Target::Netbox => "netbox",
            Target::NetboxDevices => "netbox-devices",
            Target::SnipeIt => "snipeit",
            Target::Splunk => "splunk",
            Target::Elastic => "elastic",
            Target::ServiceNow => "servicenow",
        }
    }
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|t| t.name().eq_ignore_ascii_case(text.trim()))
    }
    /// Whether [`push`] can send this export.
    pub fn can_push(self) -> bool {
        !matches!(self, Target::SnipeIt | Target::ServiceNow)
    }
    fn content_type(self) -> &'static str {
        match self {
            Target::Netbox | Target::NetboxDevices | Target::Splunk => "application/json",
            Target::Elastic => "application/x-ndjson",
            Target::SnipeIt | Target::ServiceNow => "text/csv",
        }
    }
    /// The API path used when the push URL names only a server.
    fn default_path(self) -> &'static str {
        match self {
            Target::Netbox => "/api/ipam/ip-addresses/",
            Target::NetboxDevices => "/api/dcim/devices/",
            Target::Splunk => "/services/collector/event",
            Target::Elastic => "/_bulk",
            Target::SnipeIt | Target::ServiceNow => "/",
        }
    }
    /// The `Authorization` scheme for `token`: NetBox v2 tokens (`nbt_...`) are `Bearer`, v1
    /// tokens `Token`; Splunk HEC `Splunk`; Elastic API keys `ApiKey`.
    fn scheme(self, token: &str) -> &'static str {
        match self {
            Target::Netbox | Target::NetboxDevices if token.starts_with("nbt_") => "Bearer",
            Target::Netbox | Target::NetboxDevices => "Token",
            Target::Splunk => "Splunk",
            _ => "ApiKey",
        }
    }
}

/// Settings some targets need.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// `netbox-devices`: names of the site, device role and device type (NetBox requires them).
    pub site: String,
    pub role: String,
    pub device_type: String,
    /// `elastic`: the index (default `network-scope`); `splunk`: the index, only when given.
    pub index: String,
}

/// A device as the exports describe it.
struct Row<'a> {
    device: &'a Device,
    name: String,
    findings: Vec<&'a Finding>,
}

impl Row<'_> {
    /// One line about the device, for description fields.
    fn summary(&self) -> String {
        let d = self.device;
        let mut parts = vec![];
        if !d.device_type.is_empty() {
            parts.push(d.device_type.clone());
        }
        if !d.os.is_empty() {
            parts.push(format!("OS {}", d.os));
        }
        if !d.open_tcp.is_empty() {
            parts.push(format!(
                "TCP {}",
                d.open_tcp
                    .iter()
                    .take(20)
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
        if !self.findings.is_empty() {
            parts.push(format!("{} findings", self.findings.len()));
        }
        format!("Network Scope: {}", parts.join("; "))
    }
}

fn rows<'a>(devices: &'a [Device], findings: &'a [Finding]) -> Vec<Row<'a>> {
    devices
        .iter()
        .map(|d| Row {
            name: d
                .hostnames
                .first()
                .cloned()
                .or_else(|| d.ips.first().map(ToString::to_string))
                .unwrap_or_else(|| d.id.clone()),
            findings: findings.iter().filter(|f| d.ips.contains(&f.ip)).collect(),
            device: d,
        })
        .collect()
}

fn cut(text: &str, max: usize) -> String {
    text.chars().filter(|c| !c.is_control()).take(max).collect()
}

fn host_prefix(ip: &IpAddr) -> String {
    format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 })
}

/// The export of `snapshot` (scanned at `timestamp`, Unix seconds; 0 when not recorded).
pub fn render(
    target: Target,
    snapshot: &Snapshot,
    timestamp: i64,
    opts: &Options,
) -> Result<String, String> {
    let devices = crate::devices::merge(&snapshot.hosts, &snapshot.observations);
    let findings = crate::risk::analyze_snapshot(snapshot);
    let rows = rows(&devices, &findings);
    let json_err = |e: serde_json::Error| e.to_string();
    Ok(match target {
        Target::Netbox => {
            let mut out: Vec<Value> = vec![];
            for r in &rows {
                for ip in &r.device.ips {
                    let mut o = json!({
                        "address": host_prefix(ip),
                        "status": "active",
                        "description": cut(&r.summary(), 200),
                    });
                    // NetBox accepts only plain DNS characters in dns_name.
                    if let Some(n) = r
                        .device
                        .hostnames
                        .iter()
                        .find_map(|h| crate::import::norm_name(h))
                    {
                        o["dns_name"] = json!(n);
                    }
                    out.push(o);
                }
            }
            serde_json::to_string_pretty(&out).map_err(json_err)?
        }
        Target::NetboxDevices => {
            for (what, v) in [
                ("--netbox-site", &opts.site),
                ("--netbox-role", &opts.role),
                ("--netbox-device-type", &opts.device_type),
            ] {
                if v.trim().is_empty() {
                    return Err(format!(
                        "netbox-devices needs {what}: NetBox requires a site, a role and a device type for every device"
                    ));
                }
            }
            let out: Vec<Value> = rows
                .iter()
                .map(|r| {
                    json!({
                        "name": cut(&r.name, 64),
                        "device_type": {"model": opts.device_type},
                        "role": {"name": opts.role},
                        "site": {"name": opts.site},
                        "status": "active",
                        "comments": cut(&r.summary(), 500),
                    })
                })
                .collect();
            serde_json::to_string_pretty(&out).map_err(json_err)?
        }
        Target::SnipeIt => {
            let mut out = String::from(
                "Name,Asset Tag,Category,Manufacturer,Model,Asset Notes,MAC Address,IP Address\r\n",
            );
            for r in &rows {
                let d = r.device;
                let tag_source = if d.mac.is_empty() {
                    d.ips.first().map(ToString::to_string).unwrap_or_default()
                } else {
                    d.mac.clone()
                };
                let tag: String = tag_source
                    .chars()
                    .filter(char::is_ascii_alphanumeric)
                    .collect();
                let model = if d.device_type.is_empty() {
                    "Network device"
                } else {
                    &d.device_type
                };
                let category = match d.device_type.as_str() {
                    t if t.starts_with("Printer") => "Printers",
                    t if t.starts_with("Network") => "Network devices",
                    t if t.starts_with("Industrial") => "Industrial controllers",
                    t if t.contains("computer") || t.contains("host") => "Computers",
                    _ => "Other devices",
                };
                let cells = [
                    cut(&r.name, 255),
                    format!("NS-{tag}"),
                    category.to_string(),
                    if d.vendor.is_empty() {
                        "Unknown".to_string()
                    } else {
                        d.vendor.clone()
                    },
                    model.to_string(),
                    cut(&r.summary(), 1000),
                    d.mac.clone(),
                    d.ips
                        .iter()
                        .map(IpAddr::to_string)
                        .collect::<Vec<_>>()
                        .join(" "),
                ];
                push_row(&mut out, &cells);
            }
            out
        }
        Target::Splunk => {
            let mut out = String::new();
            for r in &rows {
                let mut e = json!({
                    "source": "network-scope",
                    "sourcetype": "network-scope:device",
                    "event": event(r, timestamp),
                });
                if timestamp > 0 {
                    e["time"] = json!(timestamp);
                }
                if !opts.index.trim().is_empty() {
                    e["index"] = json!(opts.index.trim());
                }
                out.push_str(&serde_json::to_string(&e).map_err(json_err)?);
                out.push('\n');
            }
            out
        }
        Target::Elastic => {
            let index = if opts.index.trim().is_empty() {
                "network-scope"
            } else {
                opts.index.trim()
            };
            let mut out = String::new();
            for r in &rows {
                let mut doc = event(r, timestamp);
                if timestamp > 0 {
                    doc["@timestamp"] = json!(notify::rfc3339(timestamp));
                }
                // The id makes a repeated export of the same scan replace, not duplicate.
                let action = json!({"index": {"_index": index, "_id": format!("{timestamp}-{}", r.device.id)}});
                out.push_str(&serde_json::to_string(&action).map_err(json_err)?);
                out.push('\n');
                out.push_str(&serde_json::to_string(&doc).map_err(json_err)?);
                out.push('\n');
            }
            out
        }
        Target::ServiceNow => {
            let mut out = String::from(
                "name,sys_class_name,ip_address,mac_address,manufacturer,os,short_description,discovery_source,operational_status\r\n",
            );
            for r in &rows {
                let d = r.device;
                let class = match d.device_type.as_str() {
                    t if t.starts_with("Printer") => "cmdb_ci_printer",
                    t if t.starts_with("Network") => "cmdb_ci_netgear",
                    t if t.contains("computer") || t.contains("host") => "cmdb_ci_computer",
                    _ => "cmdb_ci_hardware",
                };
                let cells = [
                    cut(&r.name, 255),
                    class.to_string(),
                    d.ips.first().map(ToString::to_string).unwrap_or_default(),
                    d.mac.clone(),
                    d.vendor.clone(),
                    d.os.clone(),
                    cut(&r.summary(), 160),
                    "Network Scope".to_string(),
                    "1".to_string(),
                ];
                push_row(&mut out, &cells);
            }
            out
        }
    })
}

fn push_row(out: &mut String, cells: &[String]) {
    out.push_str(
        &cells
            .iter()
            .map(|c| csv_cell(c))
            .collect::<Vec<_>>()
            .join(","),
    );
    out.push_str("\r\n");
}

/// The event or document of one device (Splunk, Elastic).
fn event(r: &Row, timestamp: i64) -> Value {
    let d = r.device;
    json!({
        "device_id": d.id,
        "name": r.name,
        "ips": d.ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "mac": d.mac,
        "randomized_mac": d.randomized_mac,
        "vendor": d.vendor,
        "hostnames": d.hostnames,
        "device_type": d.device_type,
        "os": d.os,
        "open_tcp": d.open_tcp,
        "open_udp": d.open_udp,
        "sources": d.sources,
        "scan_time": if timestamp > 0 { report::fmt_time(timestamp) } else { String::new() },
        "findings": r.findings.iter().map(|f| json!({
            "id": f.id,
            "severity": f.severity,
            "title": f.title,
            "port": f.port,
            "ip": f.ip.to_string(),
            "cve": f.cve,
        })).collect::<Vec<_>>(),
    })
}

/// The token for a push, read from the environment variable `var`. A missing or empty variable
/// is an error that names it (the value is never printed).
pub fn token_from_env(var: &str) -> Result<String, String> {
    if var.trim().is_empty() || var.contains(['=', '\0']) {
        return Err("--token-env needs the name of an environment variable".into());
    }
    match std::env::var(var.trim()) {
        Ok(v) if !v.trim().is_empty() => Ok(v.trim().to_string()),
        _ => Err(format!(
            "The environment variable {var} is not set or empty; the push token is read from it"
        )),
    }
}

/// Sends `body` (from [`render`]) to `url`. A URL without a path gets the target's API path.
/// `token` goes in the `Authorization` header only (see [`notify::push`] for the URL and
/// `http://` rules). Only [`Target::can_push`] targets can be pushed.
pub fn push(
    target: Target,
    url: &str,
    token: &str,
    body: &str,
    timeout: Duration,
) -> Result<(), String> {
    if !target.can_push() {
        return Err(format!(
            "{} is a file for the target's own importer and cannot be pushed",
            target.name()
        ));
    }
    let url = url.trim();
    let bare = url
        .split_once("://")
        .is_some_and(|(_, rest)| rest.trim_end_matches('/').find('/').is_none());
    let full = if bare {
        format!("{}{}", url.trim_end_matches('/'), target.default_path())
    } else {
        url.to_string()
    };
    notify::push(
        &full,
        (target.scheme(token), token),
        target.content_type(),
        body,
        timeout,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{Host, Settings};
    use std::{
        io::{Read, Write},
        net::TcpListener,
    };

    fn host(ip: &str, mac: &str, name: &str, open: &[u16], id: &[(&str, &str)]) -> Host {
        Host {
            ip: ip.parse().unwrap(),
            responding: true,
            ping: None,
            ttl: Some(64),
            hostname: name.into(),
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

    fn snapshot() -> Snapshot {
        Snapshot {
            targets: "10.0.0.0/24".into(),
            complete: true,
            settings: Settings::default(),
            hosts: vec![
                host(
                    "10.0.0.5",
                    "00:00:0C:00:00:01",
                    "plc-1.corp.local",
                    &[23, 502],
                    &[("svc.23", "telnet")],
                ),
                host("10.0.0.6", "", "=HYPERLINK(\"http://x\")", &[80], &[]),
                host("10.0.0.7", "", "", &[], &[]),
            ],
            observations: vec![],
            notes: Default::default(),
        }
    }

    const TS: i64 = 1_763_500_000;

    fn render_ok(t: Target) -> String {
        let o = Options {
            site: "HQ".into(),
            role: "Server".into(),
            device_type: "Generic".into(),
            index: String::new(),
        };
        render(t, &snapshot(), TS, &o).unwrap()
    }

    #[test]
    fn netbox_ip_addresses_use_the_bulk_import_shape() {
        let v: Value = serde_json::from_str(&render_ok(Target::Netbox)).unwrap();
        let list = v.as_array().unwrap();
        assert_eq!(list.len(), 3);
        assert_eq!(list[0]["address"], "10.0.0.5/32");
        assert_eq!(list[0]["status"], "active");
        assert_eq!(list[0]["dns_name"], "plc-1.corp.local");
        let desc = list[0]["description"].as_str().unwrap();
        assert!(
            desc.starts_with("Network Scope:") && desc.contains("TCP 23,502"),
            "{desc}"
        );
        assert!(desc.chars().count() <= 200);
        // A name NetBox would refuse is left out, not sent.
        assert!(list[1].get("dns_name").is_none(), "{:?}", list[1]);
        assert!(list[2].get("dns_name").is_none());
    }

    #[test]
    fn netbox_devices_need_a_site_a_role_and_a_device_type() {
        let v: Value = serde_json::from_str(&render_ok(Target::NetboxDevices)).unwrap();
        let d = &v[0];
        assert_eq!(d["name"], "plc-1.corp.local");
        assert_eq!(d["site"]["name"], "HQ");
        assert_eq!(d["role"]["name"], "Server");
        assert_eq!(d["device_type"]["model"], "Generic");
        assert_eq!(d["status"], "active");
        for missing in ["site", "role", "device_type"] {
            let mut o = Options {
                site: "HQ".into(),
                role: "R".into(),
                device_type: "T".into(),
                index: String::new(),
            };
            match missing {
                "site" => o.site.clear(),
                "role" => o.role.clear(),
                _ => o.device_type = "  ".into(),
            }
            let e = render(Target::NetboxDevices, &snapshot(), TS, &o).unwrap_err();
            assert!(e.contains("--netbox-"), "{missing}: {e}");
        }
    }

    #[test]
    fn snipeit_and_servicenow_csv_cannot_start_formulas() {
        for t in [Target::SnipeIt, Target::ServiceNow] {
            let text = render_ok(t);
            let lines: Vec<&str> = text.lines().collect();
            assert_eq!(lines.len(), 4, "{t:?}: header and three devices");
            assert!(text.contains("'=HYPERLINK("), "{t:?}: {text}");
            assert!(!text.contains(",\"=HYPERLINK"), "{t:?}");
        }
        let snipe = render_ok(Target::SnipeIt);
        assert!(snipe.starts_with("Name,Asset Tag,Category,Manufacturer,Model,"));
        assert!(snipe.contains("\"NS-00000C000001\""), "{snipe}");
        let sn = render_ok(Target::ServiceNow);
        assert!(sn.starts_with("name,sys_class_name,ip_address,mac_address,"));
        assert!(sn.contains("\"Network Scope\""));
        assert!(!Target::SnipeIt.can_push() && !Target::ServiceNow.can_push());
    }

    #[test]
    fn splunk_events_and_elastic_bulk_are_line_oriented_json() {
        let splunk = render_ok(Target::Splunk);
        assert!(splunk.ends_with('\n'));
        let events: Vec<Value> = splunk
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0]["time"], TS);
        assert_eq!(events[0]["sourcetype"], "network-scope:device");
        assert!(events[0].get("index").is_none());
        assert_eq!(events[0]["event"]["ips"][0], "10.0.0.5");
        let findings = events[0]["event"]["findings"].as_array().unwrap();
        assert!(
            findings.iter().any(|f| f["id"] == "telnet-open"),
            "{findings:?}"
        );
        let with_index = render(
            Target::Splunk,
            &snapshot(),
            0,
            &Options {
                index: "ot".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let first: Value = serde_json::from_str(with_index.lines().next().unwrap()).unwrap();
        assert_eq!(first["index"], "ot");
        assert!(
            first.get("time").is_none(),
            "no time when none was recorded"
        );

        let bulk = render_ok(Target::Elastic);
        assert!(bulk.ends_with('\n'), "the last line needs its newline");
        let lines: Vec<&str> = bulk.lines().collect();
        assert_eq!(lines.len(), 6, "an action line and a document per device");
        let action: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(action["index"]["_index"], "network-scope");
        assert_eq!(
            action["index"]["_id"],
            format!("{TS}-00:00:0C:00:00:01").as_str()
        );
        let doc: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(doc["@timestamp"], notify::rfc3339(TS).as_str());
        assert_eq!(doc["name"], "plc-1.corp.local");
        // Not pretty-printed: newlines are the delimiters.
        assert!(lines.iter().all(|l| l.starts_with('{') && l.ends_with('}')));
    }

    /// A one-request HTTP server: the raw request it received, and the status it answers with.
    fn mock_server(status: &'static str) -> (u16, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut raw = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = s.read(&mut buf).unwrap_or(0);
                raw.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&raw).into_owned();
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let len = head
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if body.len() >= len {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            let _ = write!(
                s,
                "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            String::from_utf8_lossy(&raw).into_owned()
        });
        (port, handle)
    }

    fn timeout() -> Duration {
        Duration::from_secs(5)
    }

    #[test]
    fn a_push_sends_the_token_in_the_header_only() {
        let body = render_ok(Target::Netbox);
        let secret = "s3cr3t-token-value";
        // NetBox: the server's own path is appended to a bare URL; v1 tokens use `Token`.
        let (port, server) = mock_server("201 Created");
        push(
            Target::Netbox,
            &format!("http://127.0.0.1:{port}"),
            secret,
            &body,
            timeout(),
        )
        .unwrap();
        let req = server.join().unwrap();
        let (head, sent) = req.split_once("\r\n\r\n").unwrap();
        assert!(
            head.starts_with("POST /api/ipam/ip-addresses/ HTTP/1.1\r\n"),
            "{head}"
        );
        assert!(
            head.contains(&format!("Authorization: Token {secret}\r\n")),
            "{head}"
        );
        assert!(
            head.contains("Content-Type: application/json\r\n"),
            "{head}"
        );
        assert_eq!(sent, body);
        assert!(
            !head.lines().next().unwrap().contains(secret),
            "never in the request line"
        );
        // NetBox v2 tokens are Bearer tokens; Splunk and Elastic have their own schemes.
        for (target, token, want, path, ctype) in [
            (
                Target::Netbox,
                "nbt_abc.def",
                "Bearer nbt_abc.def",
                "/api/ipam/ip-addresses/",
                "application/json",
            ),
            (
                Target::NetboxDevices,
                "abc",
                "Token abc",
                "/api/dcim/devices/",
                "application/json",
            ),
            (
                Target::Splunk,
                "guid-1",
                "Splunk guid-1",
                "/services/collector/event",
                "application/json",
            ),
            (
                Target::Elastic,
                "enc==",
                "ApiKey enc==",
                "/_bulk",
                "application/x-ndjson",
            ),
        ] {
            let (port, server) = mock_server("200 OK");
            push(
                target,
                &format!("http://127.0.0.1:{port}/"),
                token,
                "{}",
                timeout(),
            )
            .unwrap_or_else(|e| panic!("{target:?}: {e}"));
            let req = server.join().unwrap();
            let head = req.split("\r\n\r\n").next().unwrap();
            assert!(
                head.contains(&format!("Authorization: {want}\r\n")),
                "{target:?}: {head}"
            );
            assert!(
                head.contains(&format!("Content-Type: {ctype}\r\n")),
                "{target:?}: {head}"
            );
            // A URL that names only a server (with or without a trailing slash) gets the API path.
            assert!(
                head.starts_with(&format!("POST {path} HTTP/1.1\r\n")),
                "{target:?}: {head}"
            );
        }
        // An explicit path is used as given.
        let (port, server) = mock_server("200 OK");
        push(
            Target::Splunk,
            &format!("http://127.0.0.1:{port}/custom/hec"),
            "t",
            "{}",
            timeout(),
        )
        .unwrap();
        assert!(
            server
                .join()
                .unwrap()
                .starts_with("POST /custom/hec HTTP/1.1")
        );
    }

    #[test]
    fn a_push_refuses_credentials_in_urls_and_clear_text_tokens() {
        let body = "{}";
        let e = |url: &str, token: &str| {
            push(Target::Splunk, url, token, body, Duration::from_millis(300)).unwrap_err()
        };
        assert!(e("https://splunk.example.com/x?token=abc", "t").contains("query string"));
        assert!(e("https://splunk.example.com/x#frag", "t").contains("query string"));
        assert!(e("https://user:pass@splunk.example.com/", "t").contains("user:password@"));
        // Plain http:// away from this machine is refused before any connection is made.
        for url in [
            "http://192.0.2.1:8088/",
            "http://splunk.example.com/",
            "http://10.0.0.5/",
        ] {
            let m = e(url, "t");
            assert!(m.contains("only sent over https"), "{url}: {m}");
        }
        assert!(e("ftp://x/", "t").contains("http"));
        // A token that could end the header or start another is refused.
        for bad in ["", "a\r\nX-Evil: 1", "a b", "a\nb"] {
            let m = e("http://127.0.0.1:9/", bad);
            assert!(m.contains("Token"), "{bad:?}: {m}");
        }
        // Targets that are files for an importer cannot be pushed.
        let m = push(
            Target::SnipeIt,
            "https://x.example.com/",
            "t",
            body,
            timeout(),
        )
        .unwrap_err();
        assert!(m.contains("cannot be pushed"));
        // A server error and a refused connection are errors, not successes.
        let (port, server) = mock_server("500 Internal Server Error");
        let m = push(
            Target::Elastic,
            &format!("http://127.0.0.1:{port}/_bulk"),
            "k",
            body,
            timeout(),
        )
        .unwrap_err();
        assert_eq!(m, "HTTP 500");
        server.join().unwrap();
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        assert!(
            push(
                Target::Elastic,
                &format!("http://127.0.0.1:{port}/"),
                "k",
                body,
                Duration::from_millis(500)
            )
            .is_err()
        );
    }

    #[test]
    fn the_token_comes_from_a_named_environment_variable() {
        let e = token_from_env("NETWORK_SCOPE_TEST_TOKEN_THAT_IS_NOT_SET").unwrap_err();
        assert!(
            e.contains("NETWORK_SCOPE_TEST_TOKEN_THAT_IS_NOT_SET"),
            "{e}"
        );
        for bad in ["", " ", "A=B", "A\0B"] {
            assert!(
                token_from_env(bad)
                    .unwrap_err()
                    .contains("name of an environment"),
                "{bad:?}"
            );
        }
        let name = format!("NETWORK_SCOPE_TEST_TOKEN_{}", std::process::id());
        // SAFETY: the variable has a name no other test or thread uses.
        unsafe { std::env::set_var(&name, "  value-1 \n") };
        assert_eq!(token_from_env(&name).unwrap(), "value-1");
        unsafe { std::env::set_var(&name, "   ") };
        assert!(token_from_env(&name).is_err(), "blank counts as missing");
        unsafe { std::env::remove_var(&name) };
    }

    #[test]
    fn only_this_machine_may_receive_a_token_in_clear_text() {
        for host in ["localhost", "LOCALHOST", "127.0.0.1", "127.9.9.9", "::1"] {
            assert!(notify::is_loopback_host(host), "{host}");
        }
        for host in [
            "10.0.0.5",
            "example.com",
            "localhost.example.com",
            "0.0.0.0",
        ] {
            assert!(!notify::is_loopback_host(host), "{host}");
        }
    }

    #[test]
    fn targets_parse_by_name() {
        for t in Target::ALL {
            assert_eq!(Target::parse(t.name()), Some(t));
        }
        assert_eq!(Target::parse(" Splunk "), Some(Target::Splunk));
        assert_eq!(Target::parse("json"), None);
    }
}
