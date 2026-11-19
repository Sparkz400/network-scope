//! The data-driven probe database: `data/probes.json` plus an optional user file, the
//! rule matching that turns a reply into a [`Service`], and the UDP probe list `udp.rs` sends.
use super::{Service, is_ot_udp_port};
use regex::bytes::{Regex, RegexBuilder};
use serde::Deserialize;
use std::{
    path::Path,
    sync::{Arc, OnceLock, RwLock},
    time::Duration,
};

static BUILTIN: &str = include_str!("../../../data/probes.json");

#[derive(Deserialize)]
pub(super) struct RawRule {
    pub(super) re: String,
    pub(super) service: String,
    #[serde(default)]
    pub(super) product: String,
    #[serde(default)]
    pub(super) version: String,
    #[serde(default)]
    pub(super) info: String,
}
#[derive(Deserialize)]
pub(super) struct RawProbe {
    pub(super) name: String,
    /// "tcp" (default) or "udp".
    #[serde(default)]
    pub(super) proto: String,
    #[serde(default)]
    pub(super) ports: Vec<u16>,
    #[serde(default)]
    pub(super) send: String,
    #[serde(default)]
    pub(super) send_hex: String,
    #[serde(default)]
    pub(super) wait_ms: u64,
    #[serde(default)]
    pub(super) rules: Vec<RawRule>,
}
#[derive(Deserialize)]
pub(super) struct RawDb {
    pub(super) probes: Vec<RawProbe>,
}

#[derive(Clone, Debug)]
pub struct Rule {
    re: Regex,
    service: String,
    product: String,
    version: String,
    info: String,
}
#[derive(Clone, Debug)]
pub struct Probe {
    pub name: String,
    pub ports: Vec<u16>,
    pub payload: Vec<u8>,
    pub wait: Duration,
    pub rules: Vec<Rule>,
}
#[derive(Clone, Debug)]
pub struct ProbeDb {
    /// TCP probes (the null probe included).
    pub probes: Vec<Probe>,
    /// `"proto": "udp"` probes: one datagram to the listed ports, used by `udp.rs` for ports
    /// without a built-in protocol handler. Never sent to OT ports.
    pub udp: Vec<Probe>,
}

pub(super) fn unhex(text: &str) -> Result<Vec<u8>, String> {
    // Validate per character: slicing the string by byte offsets panics on multi-byte input.
    let nibbles: Vec<u8> = text
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| {
            c.to_digit(16)
                .map(|d| d as u8)
                .ok_or_else(|| format!("send_hex contains a non-hex character {c:?}"))
        })
        .collect::<Result<_, _>>()?;
    if !nibbles.len().is_multiple_of(2) {
        return Err("send_hex has an odd number of digits".into());
    }
    Ok(nibbles.chunks(2).map(|d| (d[0] << 4) | d[1]).collect())
}
pub(super) fn sanitize(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .filter(|c| !c.is_control())
        .take(120)
        .collect::<String>()
        .trim()
        .to_string()
}
fn expand(template: &str, caps: &regex::bytes::Captures) -> String {
    let mut out = String::new();
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$'
            && let Some(d) = chars.peek().and_then(|d| d.to_digit(10))
        {
            chars.next();
            if let Some(m) = caps.get(d as usize) {
                out.push_str(&sanitize(m.as_bytes()));
            }
            continue;
        }
        out.push(c);
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

impl ProbeDb {
    /// (TCP probes, UDP probes)
    fn parse(json: &str, origin: &str) -> Result<(Vec<Probe>, Vec<Probe>), String> {
        let raw: RawDb = serde_json::from_str(json).map_err(|e| format!("{origin}: {e}"))?;
        let mut udp = vec![];
        let mut tcp = vec![];
        for p in raw.probes {
            let is_udp = match p.proto.to_ascii_lowercase().as_str() {
                "" | "tcp" => false,
                "udp" => true,
                other => return Err(format!("{origin}: {}: unknown proto {other:?}", p.name)),
            };
            if is_udp {
                if p.ports.is_empty() || (p.send.is_empty() && p.send_hex.trim().is_empty()) {
                    return Err(format!(
                        "{origin}: {}: a UDP probe needs ports and a payload",
                        p.name
                    ));
                }
                if let Some(port) = p.ports.iter().find(|port| is_ot_udp_port(**port)) {
                    return Err(format!(
                        "{origin}: {}: UDP port {port} is an industrial or printer port and is never probed",
                        p.name
                    ));
                }
            }
            let probe = Self::parse_probe(p, origin)?;
            if is_udp {
                udp.push(probe);
            } else {
                tcp.push(probe);
            }
        }
        Ok((tcp, udp))
    }
    fn parse_probe(p: RawProbe, origin: &str) -> Result<Probe, String> {
        let mut payload = p.send.into_bytes();
        payload.extend(unhex(&p.send_hex).map_err(|e| format!("{origin}: {}: {e}", p.name))?);
        let rules = p
            .rules
            .into_iter()
            .map(|r| {
                Ok(Rule {
                    re: RegexBuilder::new(&r.re)
                        .unicode(false)
                        .dot_matches_new_line(true)
                        .build()
                        .map_err(|e| format!("{origin}: {}: bad regex {:?}: {e}", p.name, r.re))?,
                    service: r.service,
                    product: r.product,
                    version: r.version,
                    info: r.info,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Probe {
            wait: Duration::from_millis(if p.wait_ms == 0 { 1200 } else { p.wait_ms }),
            name: p.name,
            ports: p.ports,
            payload,
            rules,
        })
    }
    /// The text of the built-in `data/probes.json` (what `probes lint` checks when no file is given).
    pub fn builtin_json() -> &'static str {
        BUILTIN
    }
    pub fn builtin() -> Self {
        let (probes, udp) =
            Self::parse(BUILTIN, "built-in probes").expect("built-in probe database is valid");
        Self { probes, udp }
    }
    /// Built-in probes plus the user file (same probe name replaces, new names are added).
    pub fn with_user_file(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::builtin().merge_user(&text, &path.display().to_string())
    }
    /// Adds the probes of a user file named `origin` (contents `text`) to this database.
    pub(crate) fn merge_user(self, text: &str, origin: &str) -> Result<Self, String> {
        let mut db = self;
        let (tcp, udp) = Self::parse(text, origin)?;
        for (probe, is_udp) in tcp
            .into_iter()
            .map(|p| (p, false))
            .chain(udp.into_iter().map(|p| (p, true)))
        {
            // A name lives in one list: a user probe may also move a name from TCP to UDP.
            let (same, other) = if is_udp {
                (&mut db.udp, &mut db.probes)
            } else {
                (&mut db.probes, &mut db.udp)
            };
            other.retain(|p| p.name != probe.name);
            match same.iter_mut().find(|p| p.name == probe.name) {
                Some(slot) => *slot = probe,
                None => same.push(probe),
            }
        }
        Ok(db)
    }
    /// Loads the explicit path, else `%LOCALAPPDATA%/NetworkScope/probes.json` when it exists.
    /// The UDP probes of the result become the ones `udp.rs` sends (see `udp_probes`).
    pub fn load(explicit: &str) -> Result<Self, String> {
        let db = Self::load_files(explicit)?;
        if let Ok(mut slot) = udp_slot().write() {
            *slot = Some(Arc::new(db.udp.clone()));
        }
        Ok(db)
    }
    fn load_files(explicit: &str) -> Result<Self, String> {
        if !explicit.is_empty() {
            return Self::with_user_file(Path::new(explicit));
        }
        let default = std::env::var_os("LOCALAPPDATA")
            .or_else(|| std::env::var_os("XDG_CONFIG_HOME"))
            .map(|p| Path::new(&p).join("NetworkScope").join("probes.json"));
        match default {
            Some(p) if p.exists() => Self::with_user_file(&p),
            _ => Ok(Self::builtin()),
        }
    }
    pub(super) fn null_probe(&self) -> Option<&Probe> {
        self.probes
            .iter()
            .find(|p| p.ports.is_empty() && p.payload.is_empty())
    }
    pub fn identify(probe: &Probe, data: &[u8]) -> Option<Service> {
        probe.rules.iter().find_map(|r| {
            let caps = r.re.captures(data)?;
            Some(Service {
                name: expand(&r.service, &caps),
                product: expand(&r.product, &caps),
                version: expand(&r.version, &caps),
                info: expand(&r.info, &caps),
            })
        })
    }
}

fn udp_slot() -> &'static RwLock<Option<Arc<Vec<Probe>>>> {
    static SLOT: OnceLock<RwLock<Option<Arc<Vec<Probe>>>>> = OnceLock::new();
    SLOT.get_or_init(|| RwLock::new(None))
}

/// The UDP probes of the most recently loaded probe database (the scan loads it with its
/// `--probes` file). Before any load: the default user file when valid, else the built-in
/// probes (tests: always built-in).
pub fn udp_probes() -> Arc<Vec<Probe>> {
    if let Some(p) = udp_slot().read().ok().and_then(|s| s.clone()) {
        return p;
    }
    #[cfg(test)]
    let probes = ProbeDb::builtin().udp;
    #[cfg(not(test))]
    let probes = ProbeDb::load_files("")
        .unwrap_or_else(|_| ProbeDb::builtin())
        .udp;
    let probes = Arc::new(probes);
    if let Ok(mut slot) = udp_slot().write() {
        if let Some(existing) = slot.as_ref() {
            return existing.clone();
        }
        *slot = Some(probes.clone());
    }
    probes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_match(db: &ProbeDb, probe: &str, data: &[u8]) -> Option<String> {
        let p = db.probes.iter().find(|p| p.name == probe).unwrap();
        ProbeDb::identify(p, data).map(|s| s.summary())
    }

    #[test]
    fn builtin_database_loads_and_payloads_are_consistent() {
        let db = ProbeDb::builtin();
        assert!(db.probes.len() >= 10);
        assert!(db.null_probe().is_some());
        let get = |n: &str| &db.probes.iter().find(|p| p.name == n).unwrap().payload;
        assert_eq!(get("mssql").len(), 26);
        assert_eq!(
            usize::from(u16::from_be_bytes([get("mssql")[2], get("mssql")[3]])),
            26
        );
        assert_eq!(get("mongodb").len(), 52);
        assert_eq!(
            u32::from_le_bytes(get("mongodb")[..4].try_into().unwrap()),
            52
        );
        assert_eq!(get("rdp").len(), 19);
        assert_eq!(usize::from(get("rdp")[3]), 19);
        assert_eq!(get("mqtt").len(), 14);
        assert_eq!(usize::from(get("mqtt")[1]), get("mqtt").len() - 2);
        assert_eq!(get("dns-tcp").len(), 32);
        assert_eq!(
            usize::from(u16::from_be_bytes([get("dns-tcp")[0], get("dns-tcp")[1]])),
            30
        );
        assert_eq!(get("ldap").len(), 14);
    }

    #[test]
    fn banner_rules() {
        let db = ProbeDb::builtin();
        let m = |d: &[u8]| rule_match(&db, "banner", d);
        assert_eq!(
            m(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n").unwrap(),
            "ssh OpenSSH 8.9p1 (protocol 2.0 Ubuntu-3ubuntu0.1)"
        );
        assert_eq!(
            m(b"SSH-2.0-dropbear_2022.83\r\n").unwrap(),
            "ssh dropbear_2022.83 (protocol 2.0)"
        );
        assert_eq!(m(b"220 (vsFTPd 3.0.3)\r\n").unwrap(), "ftp vsFTPd 3.0.3");
        assert_eq!(
            m(b"220 mail.example.com ESMTP Postfix (Debian)\r\n").unwrap(),
            "smtp Postfix"
        );
        assert_eq!(
            m(b"220 Microsoft FTP Service\r\n").unwrap(),
            "ftp Microsoft FTP Service"
        );
        assert_eq!(m(b"+OK Dovecot ready.\r\n").unwrap(), "pop3 Dovecot");
        assert_eq!(m(b"* OK IMAP4rev1 ready\r\n").unwrap(), "imap");
        assert_eq!(m(b"RFB 003.008\n").unwrap(), "vnc (protocol 003.008)");
        assert_eq!(m(b"\xff\xfd\x18\xff\xfd\x20").unwrap(), "telnet");
        let mut mysql = vec![0x4a, 0, 0, 0, 0x0a];
        mysql.extend(b"8.0.33-0ubuntu0.22.04.2\0rest");
        assert_eq!(m(&mysql).unwrap(), "mysql MySQL 8.0.33-0ubuntu0.22.04.2");
        let mut maria = vec![0x4a, 0, 0, 0, 0x0a];
        maria.extend(b"10.6.12-MariaDB-0ubuntu0.22.04.1\0");
        assert_eq!(m(&maria).unwrap(), "mysql MariaDB 10.6.12");
        assert_eq!(m(b"garbage that matches nothing"), None);
        assert_eq!(m(b""), None);
    }

    #[test]
    fn binary_protocol_rules() {
        let db = ProbeDb::builtin();
        assert_eq!(
            rule_match(&db, "mqtt", &[0x20, 2, 0, 0]).unwrap(),
            "mqtt (anonymous connection accepted)"
        );
        assert_eq!(
            rule_match(&db, "mqtt", &[0x20, 2, 0, 5]).unwrap(),
            "mqtt (authentication required)"
        );
        let rdp = |proto: u8| {
            let mut r = vec![
                3, 0, 0, 0x13, 0x0e, 0xd0, 0, 0, 0x12, 0x34, 0, 2, 0, 8, 0, proto, 0, 0, 0,
            ];
            r.truncate(19);
            rule_match(&db, "rdp", &r).unwrap()
        };
        assert_eq!(
            rdp(0),
            "ms-wbt-server RDP (standard RDP security (no TLS/NLA))"
        );
        assert_eq!(rdp(1), "ms-wbt-server RDP (TLS security)");
        assert_eq!(rdp(2), "ms-wbt-server RDP (NLA (CredSSP))");
        assert_eq!(
            rdp(8),
            "ms-wbt-server RDP (NLA with early user authentication)"
        );
        assert_eq!(
            rule_match(&db, "postgresql", b"S").unwrap(),
            "postgresql (TLS supported)"
        );
        assert_eq!(
            rule_match(
                &db,
                "redis",
                b"$100\r\n# Server\r\nredis_version:7.0.11\r\n"
            )
            .unwrap(),
            "redis Redis 7.0.11"
        );
        assert_eq!(
            rule_match(&db, "redis", b"-NOAUTH Authentication required.\r\n").unwrap(),
            "redis Redis (authentication required)"
        );
        assert_eq!(
            rule_match(&db, "mssql", &[4, 1, 0, 0x20, 0, 0, 1, 0]).unwrap(),
            "ms-sql-s Microsoft SQL Server"
        );
        assert_eq!(
            rule_match(
                &db,
                "ldap",
                &[0x30, 0x0c, 2, 1, 1, 0x61, 7, 0x0a, 1, 0, 4, 0, 4, 0]
            )
            .unwrap(),
            "ldap (anonymous bind accepted)"
        );
        // resultCode 48 (inappropriateAuthentication): answered, but not accepted.
        assert_eq!(
            rule_match(
                &db,
                "ldap",
                &[0x30, 0x0c, 2, 1, 1, 0x61, 7, 0x0a, 1, 48, 4, 0, 4, 0]
            )
            .unwrap(),
            "ldap (anonymous bind refused)"
        );
        // Active Directory style long-form BER lengths (0x84 + 4 bytes).
        let ad = [
            0x30, 0x84, 0, 0, 0, 0x10, 2, 1, 1, 0x61, 0x84, 0, 0, 0, 7, 0x0a, 1, 0, 4, 0, 4, 0,
        ];
        assert_eq!(
            rule_match(&db, "ldap", &ad).unwrap(),
            "ldap (anonymous bind accepted)"
        );
        let mut ad_refused = ad;
        ad_refused[17] = 49;
        assert_eq!(
            rule_match(&db, "ldap", &ad_refused).unwrap(),
            "ldap (anonymous bind refused)"
        );
        let mut dns = vec![0x00, 0x2e, 0x05, 0x39, 0x84, 0x00, 0, 1, 0, 1, 0, 0, 0, 0];
        dns.extend(b"\x07version\x04bind\x00\x00\x10\x00\x03\xc0\x0c\x00\x10\x00\x03\x00\x00\x00\x00\x00\x0a\x099.16.1-Ubuntu");
        assert_eq!(
            rule_match(&db, "dns-tcp", &dns).unwrap(),
            "domain 9.16.1-Ubuntu (version.bind)"
        );
    }

    #[test]
    fn user_file_replaces_and_adds_probes() {
        let path = std::env::temp_dir().join(format!("ns-probes-{}.json", std::process::id()));
        std::fs::write(
            &path,
            r#"{"probes":[
              {"name":"banner","rules":[{"re":"^HELLO (\\w+)","service":"custom","product":"$1"}]},
              {"name":"lab","ports":[7777],"send":"PING\n","rules":[{"re":"PONG","service":"labd"}]}]}"#,
        )
        .unwrap();
        let db = ProbeDb::with_user_file(&path).unwrap();
        assert_eq!(
            rule_match(&db, "banner", b"HELLO world").unwrap(),
            "custom world"
        );
        assert_eq!(
            rule_match(&db, "banner", b"SSH-2.0-x"),
            None,
            "same name replaces the built-in"
        );
        assert_eq!(rule_match(&db, "lab", b"PONG").unwrap(), "labd");
        assert!(db.probes.iter().any(|p| p.name == "redis"));
        std::fs::write(
            &path,
            r#"{"probes":[{"name":"x","rules":[{"re":"(","service":"y"}]}]}"#,
        )
        .unwrap();
        assert!(
            ProbeDb::with_user_file(&path)
                .unwrap_err()
                .contains("bad regex")
        );
        std::fs::write(
            &path,
            r#"{"probes":[{"name":"x","send_hex":"abc","rules":[]}]}"#,
        )
        .unwrap();
        assert!(ProbeDb::with_user_file(&path).unwrap_err().contains("odd"));
        // A multi-byte character at an even byte offset used to panic in the slicing parser.
        std::fs::write(
            &path,
            "{\"probes\":[{\"name\":\"x\",\"send_hex\":\"a\u{e9}1\",\"rules\":[]}]}",
        )
        .unwrap();
        assert!(
            ProbeDb::with_user_file(&path)
                .unwrap_err()
                .contains("non-hex")
        );
        std::fs::write(
            &path,
            r#"{"probes":[{"name":"x","send_hex":"zz","rules":[]}]}"#,
        )
        .unwrap();
        assert!(
            ProbeDb::with_user_file(&path)
                .unwrap_err()
                .contains("non-hex")
        );
        assert_eq!(unhex("0A ff\n10").unwrap(), [0x0a, 0xff, 0x10]);
        std::fs::write(&path, "not json").unwrap();
        assert!(ProbeDb::with_user_file(&path).is_err());
        let _ = std::fs::remove_file(&path);
        assert!(ProbeDb::with_user_file(&path).is_err());
    }

    #[test]
    fn udp_probes_load_merge_and_validate() {
        let db = ProbeDb::builtin();
        assert!(db.udp.iter().any(|p| p.name == "udp-sip"));
        assert!(
            !db.probes.iter().any(|p| p.name.starts_with("udp-")),
            "UDP probes never become TCP candidates"
        );
        let path = std::env::temp_dir().join(format!("ns-udp-probes-{}.json", std::process::id()));
        let load = |json: &str| {
            std::fs::write(&path, json).unwrap();
            ProbeDb::with_user_file(&path)
        };
        let db = load(
            r#"{"probes":[
              {"name":"udp-sip","proto":"udp","ports":[5062],"send":"X","rules":[]},
              {"name":"lab-udp","proto":"UDP","ports":[7001],"send_hex":"01","rules":[{"re":"^ok","service":"labd"}]}]}"#,
        )
        .unwrap();
        let sip = db.udp.iter().find(|p| p.name == "udp-sip").unwrap();
        assert_eq!(
            (sip.ports.as_slice(), sip.payload.as_slice()),
            (&[5062u16][..], &b"X"[..])
        );
        assert!(db.udp.iter().any(|p| p.name == "lab-udp"));
        assert_eq!(db.udp.len(), ProbeDb::builtin().udp.len() + 1);
        assert!(!db.probes.iter().any(|p| p.name == "lab-udp"));
        // A user probe may move a name between TCP and UDP.
        let db = load(
            r#"{"probes":[{"name":"redis","proto":"udp","ports":[6379],"send":"x","rules":[]}]}"#,
        )
        .unwrap();
        assert!(!db.probes.iter().any(|p| p.name == "redis"));
        assert!(db.udp.iter().any(|p| p.name == "redis"));
        for (json, want) in [
            (
                r#"{"probes":[{"name":"b","proto":"udp","ports":[47808],"send":"x","rules":[]}]}"#,
                "industrial",
            ),
            (
                r#"{"probes":[{"name":"b","proto":"udp","ports":[34964],"send":"x","rules":[]}]}"#,
                "industrial",
            ),
            (
                r#"{"probes":[{"name":"b","proto":"udp","ports":[2222],"send":"x","rules":[]}]}"#,
                "industrial",
            ),
            (
                r#"{"probes":[{"name":"b","proto":"udp","ports":[9100],"send":"x","rules":[]}]}"#,
                "printer",
            ),
            (
                r#"{"probes":[{"name":"b","proto":"udp","ports":[],"send":"x","rules":[]}]}"#,
                "needs ports",
            ),
            (
                r#"{"probes":[{"name":"b","proto":"udp","ports":[7000],"rules":[]}]}"#,
                "payload",
            ),
            (
                r#"{"probes":[{"name":"b","proto":"sctp","ports":[7000],"send":"x","rules":[]}]}"#,
                "unknown proto",
            ),
        ] {
            let err = load(json).unwrap_err();
            assert!(err.contains(want), "{json}: {err}");
        }
        let _ = std::fs::remove_file(&path);
    }
}
