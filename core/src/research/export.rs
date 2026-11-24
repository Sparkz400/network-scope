//! Exports of the research data: CSV and NDJSON per table (a layout DuckDB and pandas read
//! directly), and a STIX 2.1 bundle or OCSF events for one scan.
//!
//! Parquet files come from the in-house writer in [`super::parquet`] (uncompressed, PLAIN
//! encoding, no library). Nothing here sends traffic.
//!
//! # STIX 2.1
//!
//! Each responding host becomes an `infrastructure` object that `consists-of` its `ipv4-addr`
//! or `ipv6-addr` (and `mac-addr`) observable; an `observed-data` object lists the host's
//! observables and the `software` it runs; each CVE of a finding becomes a `vulnerability`
//! object and the infrastructure `has` it. Identifiers are UUIDv5, so exporting the same scan
//! twice gives the same bundle: observables use the STIX namespace over the canonical JSON of
//! their identifying properties, as the specification prescribes; the other objects use a
//! namespace of this program ([`super::uuid::NETWORK_SCOPE_NAMESPACE`]). The bundle passes
//! `stix2-validator`; its only warnings are that the identifiers of the non-observable objects
//! are not UUIDv4 (they are deterministic on purpose).
//!
//! # OCSF
//!
//! Events follow the OCSF 1.3 class layouts, one JSON object per line: Device Inventory Info
//! (5001) per host, Vulnerability Finding (2002) per finding that names a CVE (that class
//! requires one) and Detection Finding (2004) per finding without. Fields without a safe mapping
//! go to `unmapped`. `scripts/validate_research_exports.py` checks the events against the
//! schema of OCSF 1.3.0.
use super::{cell_text, open_read_only, parquet, uuid};
use crate::{risk::Finding, store::Snapshot};
use serde_json::{Value, json};
use std::{collections::BTreeMap, io::Write, path::Path};

/// One written file.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ExportedTable {
    pub table: String,
    pub file: String,
    pub rows: u64,
    pub columns: Vec<String>,
}

/// What `research export csv|ndjson` wrote.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ExportReport {
    pub directory: String,
    pub format: String,
    pub tables: Vec<ExportedTable>,
}

/// Writes every research table to `dir` as `<table>.csv`, `<table>.ndjson` or `<table>.parquet`
/// (`format` is `csv`, `ndjson` or `parquet`). Parquet columns follow the declared SQL types
/// (INTEGER is a 64-bit integer, REAL a double, TEXT UTF-8; NOT NULL columns are required), one
/// file per table, so `scan_time` stays Unix seconds. CSV has a header row, numbers and text as they are, NULL as an empty cell, and
/// the formula-injection guard every CSV export of the program has. NDJSON is one JSON object per
/// row with the column names as keys and NULL as `null`; it carries no `schema` member so that
/// the files load as plain tables. A `manifest.json` lists the files.
pub fn export_tables(db: &Path, dir: &Path, format: &str) -> Result<ExportReport, String> {
    if !["csv", "ndjson", "parquet"].contains(&format) {
        return Err("Choose csv, ndjson or parquet".into());
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let c = open_read_only(db)?;
    let mut tables = vec![];
    for t in super::TABLES {
        let file = format!("{}.{format}", t.name);
        let path = dir.join(&file);
        let mut out = std::io::BufWriter::new(
            std::fs::File::create(&path).map_err(|e| format!("{}: {e}", path.display()))?,
        );
        let mut statement = c
            .prepare(&format!("SELECT * FROM {} ORDER BY id", t.name))
            .map_err(|e| e.to_string())?;
        let columns: Vec<String> = statement.column_names().map(|n| n.to_string()).collect();
        if format == "parquet" {
            let rows = write_parquet(&mut statement, t, &columns, out)?;
            tables.push(ExportedTable {
                table: t.name.into(),
                file,
                rows,
                columns,
            });
            continue;
        }
        if format == "csv" {
            let header: Vec<String> = columns.iter().map(|c| format!("\"{c}\"")).collect();
            write!(out, "{}\r\n", header.join(",")).map_err(|e| e.to_string())?;
        }
        let mut rows = statement.query([]).map_err(|e| e.to_string())?;
        let mut n = 0u64;
        while let Some(row) = rows.next().map_err(|e| e.to_string())? {
            let values: Vec<Value> = (0..columns.len())
                .map(|i| row.get_ref(i).map(super::json_value))
                .collect::<Result<_, _>>()
                .map_err(|e| e.to_string())?;
            if format == "csv" {
                let cells: Vec<String> = values
                    .iter()
                    .map(|v| match v {
                        Value::Number(num) => num.to_string(),
                        other => crate::scan::csv_cell(&cell_text(other)),
                    })
                    .collect();
                write!(out, "{}\r\n", cells.join(",")).map_err(|e| e.to_string())?;
            } else {
                let object: serde_json::Map<String, Value> =
                    columns.iter().cloned().zip(values).collect();
                writeln!(out, "{}", Value::Object(object)).map_err(|e| e.to_string())?;
            }
            n += 1;
        }
        out.flush().map_err(|e| e.to_string())?;
        tables.push(ExportedTable {
            table: t.name.into(),
            file,
            rows: n,
            columns,
        });
    }
    let report = ExportReport {
        directory: dir.display().to_string(),
        format: format.into(),
        tables,
    };
    let manifest = crate::schema::object("research-export", &report)?;
    std::fs::write(dir.join("manifest.json"), manifest).map_err(|e| e.to_string())?;
    Ok(report)
}

/// The Parquet schema of a table, from the declared SQL types.
fn parquet_columns(t: &super::Table) -> Vec<parquet::Column> {
    super::COMMON_COLUMNS
        .iter()
        .chain(t.columns)
        .map(|(name, sql, _)| parquet::Column {
            name: (*name).into(),
            kind: if sql.starts_with("INTEGER") {
                parquet::Kind::Int64
            } else if sql.starts_with("REAL") {
                parquet::Kind::Double
            } else {
                parquet::Kind::Text
            },
            nullable: !sql.contains("NOT NULL") && !sql.contains("PRIMARY KEY"),
        })
        .collect()
}

fn write_parquet(
    statement: &mut rusqlite::Statement<'_>,
    t: &super::Table,
    columns: &[String],
    out: impl Write,
) -> Result<u64, String> {
    use rusqlite::types::ValueRef;
    let schema = parquet_columns(t);
    if schema.iter().map(|c| &c.name).ne(columns.iter()) {
        return Err(format!("table {}: columns differ from the schema", t.name));
    }
    let mut writer = parquet::Writer::new(out, schema.clone()).map_err(|e| e.to_string())?;
    let mut rows = statement.query([]).map_err(|e| e.to_string())?;
    let mut n = 0u64;
    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
        let mut cells = Vec::with_capacity(schema.len());
        for (i, col) in schema.iter().enumerate() {
            let value = row.get_ref(i).map_err(|e| e.to_string())?;
            cells.push(match (value, col.kind) {
                (ValueRef::Null, _) => parquet::Cell::Null,
                (ValueRef::Integer(v), parquet::Kind::Int64) => parquet::Cell::Int(v),
                (ValueRef::Integer(v), parquet::Kind::Double) => parquet::Cell::Double(v as f64),
                (ValueRef::Real(v), parquet::Kind::Double) => parquet::Cell::Double(v),
                (ValueRef::Text(t), parquet::Kind::Text) => {
                    parquet::Cell::Text(String::from_utf8_lossy(t).into_owned())
                }
                (ValueRef::Blob(b), parquet::Kind::Text) => {
                    parquet::Cell::Text(format!("x'{}'", crate::fingerprint::hex(b)))
                }
                (other, kind) => {
                    return Err(format!(
                        "table {}, column {}: a {:?} value in a {kind:?} column",
                        t.name,
                        col.name,
                        other.data_type()
                    ));
                }
            });
        }
        writer.row(cells)?;
        n += 1;
    }
    writer.finish().map_err(|e| e.to_string())?;
    Ok(n)
}

// ---- STIX 2.1 ------------------------------------------------------------------------------

/// `YYYY-MM-DDThh:mm:ss.000Z` for Unix seconds.
pub fn rfc3339(ts: i64) -> String {
    let secs = ts.rem_euclid(86_400);
    format!(
        "{}T{:02}:{:02}:{:02}.000Z",
        crate::tls::date(ts),
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

/// The canonical JSON (RFC 8785) of a flat object with text values: members sorted by name, no
/// white space. Only the escapes JSON requires are written, as the canonical form says.
pub fn canonical_json(members: &BTreeMap<&str, String>) -> String {
    let mut out = String::from("{");
    for (i, (k, v)) in members.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&Value::from(*k).to_string());
        out.push(':');
        out.push_str(&Value::from(v.as_str()).to_string());
    }
    out.push('}');
    out
}

/// The deterministic identifier of an observable: `<type>--<uuid5>` over the canonical JSON of
/// its identifying properties.
pub fn sco_id(kind: &str, properties: &BTreeMap<&str, String>) -> String {
    format!(
        "{kind}--{}",
        uuid::uuid5(uuid::STIX_SCO_NAMESPACE, &canonical_json(properties))
    )
}

fn own_id(kind: &str, name: &str) -> String {
    format!(
        "{kind}--{}",
        uuid::uuid5(uuid::NETWORK_SCOPE_NAMESPACE, name)
    )
}

/// A STIX 2.1 bundle of one scan (see the module documentation for the mapping).
pub fn stix_bundle(snapshot: &Snapshot, findings: &[Finding], timestamp: i64) -> Value {
    let created = rfc3339(timestamp);
    let mut objects: Vec<Value> = vec![];
    let mut vulnerabilities: BTreeMap<String, Value> = BTreeMap::new();
    let relationship = |source: &str, kind: &str, target: &str| {
        json!({
            "type": "relationship",
            "spec_version": "2.1",
            "id": own_id("relationship", &format!("{source}|{kind}|{target}")),
            "created": created,
            "modified": created,
            "relationship_type": kind,
            "source_ref": source,
            "target_ref": target,
        })
    };
    for h in snapshot.hosts.iter().filter(|h| h.responding) {
        let ip = h.ip.to_string();
        let ip_kind = if h.ip.is_ipv4() {
            "ipv4-addr"
        } else {
            "ipv6-addr"
        };
        let ip_id = sco_id(ip_kind, &BTreeMap::from([("value", ip.clone())]));
        let infra_id = own_id("infrastructure", &format!("host:{ip}"));
        let mut observables = vec![ip_id.clone()];
        objects.push(json!({"type": ip_kind, "spec_version": "2.1", "id": ip_id, "value": ip}));
        if !h.mac.is_empty() {
            let mac = h.mac.to_ascii_lowercase();
            let id = sco_id("mac-addr", &BTreeMap::from([("value", mac.clone())]));
            objects
                .push(json!({"type": "mac-addr", "spec_version": "2.1", "id": id, "value": mac}));
            observables.push(id);
        }
        let mut description = vec![];
        for key in ["device.type", "os.guess", "mac.vendor"] {
            if let Some(v) = h.identity.get(key) {
                description.push(format!("{key}: {v}"));
            }
        }
        objects.push(json!({
            "type": "infrastructure",
            "spec_version": "2.1",
            "id": infra_id,
            "created": created,
            "modified": created,
            "name": if h.hostname.is_empty() { ip.clone() } else { h.hostname.clone() },
            "description": description.join("; "),
            "infrastructure_types": ["unknown"],
        }));
        objects.push(relationship(&infra_id, "consists-of", &ip_id));
        for d in crate::otdevice::from_identity(&h.identity) {
            let name = d
                .products
                .first()
                .cloned()
                .unwrap_or_else(|| d.protocol.into());
            let mut props = BTreeMap::from([("name", name.clone())]);
            if !d.version.is_empty() {
                props.insert("version", d.version.clone());
            }
            if !d.vendor.is_empty() {
                props.insert("vendor", d.vendor.clone());
            }
            let id = sco_id("software", &props);
            let mut software = json!({"type": "software", "spec_version": "2.1", "id": id});
            for (k, v) in &props {
                software[*k] = json!(v);
            }
            objects.push(software);
            observables.push(id);
        }
        for &p in &h.open {
            let (product, version) = (
                h.identity.get(&format!("svc.{p}.product")),
                h.identity.get(&format!("svc.{p}.version")),
            );
            let Some(product) = product.filter(|p| !p.is_empty()) else {
                continue;
            };
            let mut props = BTreeMap::from([("name", product.clone())]);
            if let Some(v) = version.filter(|v| !v.is_empty()) {
                props.insert("version", v.clone());
            }
            if let Some(cpe) = h
                .identity
                .get(&format!("svc.{p}.cpe"))
                .filter(|c| !c.is_empty())
            {
                props.insert("cpe", cpe.clone());
            }
            let id = sco_id("software", &props);
            let mut software = json!({"type": "software", "spec_version": "2.1", "id": id});
            for (k, v) in &props {
                software[*k] = json!(v);
            }
            objects.push(software);
            observables.push(id);
        }
        observables.sort();
        observables.dedup();
        objects.push(json!({
            "type": "observed-data",
            "spec_version": "2.1",
            "id": own_id("observed-data", &format!("host:{ip}:{timestamp}")),
            "created": created,
            "modified": created,
            "first_observed": created,
            "last_observed": created,
            "number_observed": 1,
            "object_refs": observables,
        }));
        for f in findings.iter().filter(|f| f.ip == h.ip) {
            for cve in &f.cve {
                let cve = cve.to_ascii_uppercase();
                let id = own_id("vulnerability", &format!("cve:{cve}"));
                vulnerabilities.entry(id.clone()).or_insert_with(|| {
                    json!({
                        "type": "vulnerability",
                        "spec_version": "2.1",
                        "id": id,
                        "created": created,
                        "modified": created,
                        "name": cve,
                        "external_references": [{"source_name": "cve", "external_id": cve}],
                    })
                });
                objects.push(relationship(&infra_id, "has", &id));
            }
        }
    }
    objects.extend(vulnerabilities.into_values());
    // The same relationship can come from two findings of one host.
    let mut seen = std::collections::BTreeSet::new();
    objects.retain(|o| seen.insert(o["id"].as_str().unwrap_or("").to_string()));
    json!({
        "type": "bundle",
        "id": own_id("bundle", &format!("scan:{}:{timestamp}", snapshot.targets)),
        "objects": objects,
    })
}

// ---- OCSF ----------------------------------------------------------------------------------

/// The OCSF schema version the events follow.
pub const OCSF_VERSION: &str = "1.3.0";

fn ocsf_metadata() -> Value {
    json!({
        "version": OCSF_VERSION,
        "product": {
            "name": "Network Scope",
            "vendor_name": "Network Scope",
            "version": env!("CARGO_PKG_VERSION"),
        },
    })
}

fn ocsf_severity(s: crate::risk::Severity) -> (u8, &'static str) {
    use crate::risk::Severity::*;
    match s {
        Info => (1, "Informational"),
        Low => (2, "Low"),
        Medium => (3, "Medium"),
        High => (4, "High"),
        Critical => (5, "Critical"),
    }
}

/// OCSF events of one scan: a Device Inventory Info (5001, Collect) per responding host, then per
/// finding a Vulnerability Finding (2002, Create) when it names a CVE, else a Detection Finding
/// (2004, Create).
pub fn ocsf_events(snapshot: &Snapshot, findings: &[Finding], timestamp: i64) -> Vec<Value> {
    let time_ms = timestamp.saturating_mul(1000);
    let mut out = vec![];
    for h in snapshot.hosts.iter().filter(|h| h.responding) {
        let mut device = json!({"ip": h.ip.to_string(), "type_id": 0});
        if !h.hostname.is_empty() {
            device["hostname"] = json!(h.hostname);
            device["name"] = json!(h.hostname);
        }
        if !h.mac.is_empty() {
            device["mac"] = json!(h.mac);
        }
        if let Some(os) = h.identity.get("os.guess") {
            device["os"] = json!({"name": os, "type_id": 0});
        }
        let mut unmapped = serde_json::Map::new();
        for key in ["device.type", "mac.vendor"] {
            if let Some(v) = h.identity.get(key) {
                unmapped.insert(key.into(), json!(v));
            }
        }
        let ports: Vec<u16> = h.open.clone();
        unmapped.insert("open_tcp_ports".into(), json!(ports));
        out.push(json!({
            "class_uid": 5001,
            "class_name": "Device Inventory Info",
            "category_uid": 5,
            "category_name": "Discovery",
            "activity_id": 2,
            "activity_name": "Collect",
            "type_uid": 500102,
            "type_name": "Device Inventory Info: Collect",
            "time": time_ms,
            "severity_id": 1,
            "severity": "Informational",
            "metadata": ocsf_metadata(),
            "device": device,
            "unmapped": unmapped,
        }));
    }
    for f in findings {
        let (severity_id, severity) = ocsf_severity(f.severity);
        let uid = format!(
            "{}:{}:{}",
            f.id,
            f.ip,
            f.port.map_or(String::new(), |p| p.to_string())
        );
        // A Vulnerability Finding must list a vulnerability with a CVE or CWE; a finding without
        // a CVE (an open Telnet port, a weak algorithm) is a Detection Finding.
        let (class_uid, class_name) = if f.cve.is_empty() {
            (2004, "Detection Finding")
        } else {
            (2002, "Vulnerability Finding")
        };
        let mut event = json!({
            "class_uid": class_uid,
            "class_name": class_name,
            "category_uid": 2,
            "category_name": "Findings",
            "activity_id": 1,
            "activity_name": "Create",
            "type_uid": class_uid * 100 + 1,
            "type_name": format!("{class_name}: Create"),
            "time": time_ms,
            "severity_id": severity_id,
            "severity": severity,
            "confidence_id": 0,
            "metadata": ocsf_metadata(),
            "finding_info": {
                "uid": uid,
                "title": f.title,
                "desc": f.evidence,
                "types": [f.id],
            },
            "resources": [{
                "uid": f.ip.to_string(),
                "name": f.ip.to_string(),
                "type": "Device",
            }],
            "unmapped": {
                "port": f.port,
                "advice": f.advice,
                "confidence": f.confidence,
                "kev": f.exploit.kev,
                "epss": f.exploit.epss.map(|s| s.as_f64()),
            },
        });
        if !f.cve.is_empty() {
            event["vulnerabilities"] = Value::Array(
                f.cve
                    .iter()
                    .map(|c| json!({"cve": {"uid": c.to_ascii_uppercase()}, "title": f.title}))
                    .collect(),
            );
        }
        out.push(event);
    }
    out
}

/// OCSF events as NDJSON text (one event per line).
pub fn ocsf_ndjson(events: &[Value]) -> String {
    events
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::super::tests::{host, remove_db, snapshot, temp_db};
    use super::*;
    use crate::{risk::Severity, store};

    fn findings_for(s: &Snapshot) -> Vec<Finding> {
        let mut f = crate::risk::analyze_snapshot(s);
        f.push(Finding {
            severity: Severity::High,
            id: "cve-cve-2014-0160".into(),
            title: "Heartbleed".into(),
            ip: "10.0.0.5".parse().unwrap(),
            port: Some(443),
            evidence: "OpenSSL 1.0.1f".into(),
            cve: vec!["CVE-2014-0160".into()],
            advice: "Upgrade".into(),
            exploit: Default::default(),
            reference: None,
            confidence: 40,
            vex: None,
        });
        f
    }

    fn scan() -> Snapshot {
        let mut h = host(
            "10.0.0.5",
            &[443, 502],
            &[
                ("svc.443", "https nginx 1.2"),
                ("svc.443.product", "nginx"),
                ("svc.443.version", "1.2"),
                ("Modbus.vendor", "Schneider Electric"),
                ("Modbus.product", "BMX P34"),
                ("Modbus.firmware", "V2.4"),
            ],
        );
        h.mac = "00:80:F4:01:02:03".into();
        let mut silent = host("10.0.0.6", &[], &[]);
        silent.responding = false;
        snapshot(vec![h, silent])
    }

    #[test]
    fn canonical_json_sorts_members_and_escapes_minimally() {
        let m = BTreeMap::from([("version", "1\"2".to_string()), ("name", "ü\n".to_string())]);
        assert_eq!(
            canonical_json(&m),
            "{\"name\":\"ü\\n\",\"version\":\"1\\\"2\"}"
        );
    }

    #[test]
    fn observable_ids_are_uuid5_over_the_canonical_json() {
        // Python: uuid.uuid5(UUID("00abedb4-aa42-466c-9c01-fed23315a9b7"), '{"value":"198.51.100.3"}')
        let id = sco_id(
            "ipv4-addr",
            &BTreeMap::from([("value", "198.51.100.3".to_string())]),
        );
        assert_eq!(id, "ipv4-addr--28bb3599-77cd-5a82-a950-b5bc3caf07c4");
    }

    #[test]
    fn rfc3339_formats_utc_times() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20.000Z");
        assert_eq!(rfc3339(-1), "1969-12-31T23:59:59.000Z");
    }

    #[test]
    fn the_stix_bundle_is_deterministic_and_well_formed() {
        let s = scan();
        let findings = findings_for(&s);
        let a = stix_bundle(&s, &findings, 1_700_000_000);
        let b = stix_bundle(&s, &findings, 1_700_000_000);
        assert_eq!(a, b, "the same scan exports the same bundle");
        assert_eq!(a["type"], "bundle");
        let objects = a["objects"].as_array().unwrap();
        let of = |t: &str| {
            objects
                .iter()
                .filter(|o| o["type"] == t)
                .collect::<Vec<_>>()
        };
        assert_eq!(of("infrastructure").len(), 1, "only the responding host");
        assert_eq!(of("ipv4-addr")[0]["value"], "10.0.0.5");
        assert_eq!(
            of("mac-addr")[0]["value"],
            "00:80:f4:01:02:03",
            "MAC addresses are lower case"
        );
        let software: Vec<&str> = of("software")
            .iter()
            .map(|o| o["name"].as_str().unwrap())
            .collect();
        assert!(
            software.contains(&"nginx") && software.contains(&"BMX P34"),
            "{software:?}"
        );
        assert_eq!(of("vulnerability")[0]["name"], "CVE-2014-0160");
        // every reference points at an object of the bundle
        let ids: std::collections::BTreeSet<&str> =
            objects.iter().map(|o| o["id"].as_str().unwrap()).collect();
        assert_eq!(ids.len(), objects.len(), "identifiers are unique");
        for o in objects {
            for key in ["source_ref", "target_ref"] {
                if let Some(r) = o[key].as_str() {
                    assert!(ids.contains(r), "{key} {r} dangles");
                }
            }
            for r in o["object_refs"].as_array().into_iter().flatten() {
                assert!(ids.contains(r.as_str().unwrap()), "object_refs {r} dangles");
            }
            if o["type"] != "ipv4-addr" && o["type"] != "mac-addr" && o["type"] != "software" {
                assert_eq!(o["spec_version"], "2.1");
            }
        }
        let rel = of("relationship");
        assert!(rel.iter().any(|r| r["relationship_type"] == "has"));
        assert!(rel.iter().any(|r| r["relationship_type"] == "consists-of"));
        // a different scan time changes the object versions but never an observable's id
        let later = stix_bundle(&s, &findings, 1_700_000_999);
        let ip_id = |bundle: &Value| {
            bundle["objects"]
                .as_array()
                .unwrap()
                .iter()
                .find(|o| o["type"] == "ipv4-addr")
                .unwrap()["id"]
                .clone()
        };
        assert_eq!(ip_id(&a), ip_id(&later));
    }

    #[test]
    fn ocsf_events_use_the_two_classes() {
        let s = scan();
        let findings = findings_for(&s);
        let events = ocsf_events(&s, &findings, 1_700_000_000);
        let inventory: Vec<_> = events.iter().filter(|e| e["class_uid"] == 5001).collect();
        let vulns: Vec<_> = events.iter().filter(|e| e["class_uid"] == 2002).collect();
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0]["device"]["ip"], "10.0.0.5");
        assert_eq!(inventory[0]["time"], 1_700_000_000_000i64);
        assert_eq!(inventory[0]["type_uid"], 500102);
        assert!(!vulns.is_empty());
        // OCSF: a Vulnerability Finding must list a vulnerability with a CVE; findings without one
        // are Detection Findings (2004)
        for e in &vulns {
            assert!(e["vulnerabilities"][0]["cve"]["uid"].is_string(), "{e}");
        }
        let detections: Vec<_> = events.iter().filter(|e| e["class_uid"] == 2004).collect();
        assert!(!detections.is_empty(), "the Modbus finding has no CVE");
        for e in &detections {
            assert!(e.get("vulnerabilities").is_none());
            assert_eq!(e["type_uid"], 200401);
            assert_eq!(e["class_name"], "Detection Finding");
        }
        let heartbleed = vulns
            .iter()
            .find(|e| e["finding_info"]["types"][0] == "cve-cve-2014-0160")
            .unwrap();
        assert_eq!(heartbleed["severity_id"], 4);
        assert_eq!(
            heartbleed["vulnerabilities"][0]["cve"]["uid"],
            "CVE-2014-0160"
        );
        for e in &events {
            assert_eq!(e["metadata"]["version"], OCSF_VERSION);
            // type_uid = class_uid * 100 + activity_id (the OCSF rule)
            assert_eq!(
                e["type_uid"].as_i64().unwrap(),
                e["class_uid"].as_i64().unwrap() * 100 + e["activity_id"].as_i64().unwrap()
            );
        }
        let text = ocsf_ndjson(&events);
        assert_eq!(text.lines().count(), events.len());
        assert!(
            text.lines()
                .all(|l| serde_json::from_str::<Value>(l).is_ok())
        );
    }

    #[test]
    fn tables_export_as_csv_and_ndjson_with_a_manifest() {
        let path = temp_db("export");
        store::save_at(&path, &scan(), 1_700_000_000).unwrap();
        let dir = std::env::temp_dir().join(format!("ns-research-export-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let report = export_tables(&path, &dir, "ndjson").unwrap();
        assert_eq!(report.tables.len(), super::super::TABLES.len());
        let hosts = std::fs::read_to_string(dir.join("hosts.ndjson")).unwrap();
        let rows: Vec<Value> = hosts
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["ip"], "10.0.0.5");
        assert_eq!(rows[0]["scan_time"], 1_700_000_000);
        assert!(rows[1]["os_guess"].is_null(), "NULL stays null");
        assert!(
            rows[0].get("schema").is_none(),
            "table rows carry no envelope"
        );
        let manifest: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["schema"], "network-scope/research-export/v1");
        assert_eq!(manifest["tables"][0]["rows"], 2);
        let csv_report = export_tables(&path, &dir, "csv").unwrap();
        let csv = std::fs::read_to_string(dir.join("hosts.csv")).unwrap();
        assert!(csv.starts_with("\"id\",\"scan_id\",\"scan_time\",\"ip\""));
        assert_eq!(csv.lines().count(), 3);
        assert!(csv.contains("1700000000,\"10.0.0.5\""), "{csv}");
        assert_eq!(csv_report.format, "csv");
        assert!(export_tables(&path, &dir, "xml").is_err());
        let _ = std::fs::remove_dir_all(&dir);
        remove_db(&path);
    }

    #[test]
    fn parquet_files_hold_the_same_rows_as_the_ndjson_export() {
        let path = temp_db("export-parquet");
        let s = scan();
        store::save_at(&path, &s, 1_700_000_000).unwrap();
        {
            // a REAL value and a NULL in the same column, as feeds would leave them
            let c = rusqlite::Connection::open(&path).unwrap();
            c.execute(
                "UPDATE findings SET epss = 0.25 WHERE id = (SELECT min(id) FROM findings)",
                [],
            )
            .unwrap();
        }
        let dir = std::env::temp_dir().join(format!("ns-research-parquet-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let report = export_tables(&path, &dir, "parquet").unwrap();
        let ndjson = std::env::temp_dir().join(format!("ns-research-pq-nd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&ndjson);
        let reference = export_tables(&path, &ndjson, "ndjson").unwrap();
        assert_eq!(report.format, "parquet");
        assert_eq!(report.tables.len(), super::super::TABLES.len());
        let mut checked_real = false;
        for (table, wanted) in report.tables.iter().zip(&reference.tables) {
            assert_eq!(table.file, format!("{}.parquet", table.table));
            assert_eq!(table.rows, wanted.rows);
            assert_eq!(table.columns, wanted.columns);
            let columns =
                parquet::tests::columns_of(&std::fs::read(dir.join(&table.file)).unwrap());
            assert_eq!(columns.len(), table.columns.len(), "{}", table.table);
            let text = std::fs::read_to_string(ndjson.join(&wanted.file)).unwrap();
            let rows: Vec<Value> = text
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect();
            for (name, cells) in table.columns.iter().zip(&columns) {
                assert_eq!(cells.len(), rows.len(), "{}.{name}", table.table);
                for (cell, row) in cells.iter().zip(&rows) {
                    let want = &row[name];
                    let same = match cell {
                        parquet::Cell::Null => want.is_null(),
                        parquet::Cell::Int(v) => want.as_i64() == Some(*v),
                        parquet::Cell::Double(v) => {
                            checked_real = true;
                            want.as_f64() == Some(*v)
                        }
                        parquet::Cell::Text(v) => want.as_str() == Some(v.as_str()),
                    };
                    assert!(same, "{}.{name}: {cell:?} vs {want}", table.table);
                }
            }
        }
        assert!(checked_real, "a REAL cell was compared");
        let manifest: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest["format"], "parquet");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&ndjson);
        remove_db(&path);
    }

    #[test]
    fn csv_cells_cannot_start_a_formula() {
        let path = temp_db("export-csv");
        let mut s = scan();
        s.hosts[0].hostname = "=HYPERLINK(\"http://x\")".into();
        store::save_at(&path, &s, 1).unwrap();
        let dir = std::env::temp_dir().join(format!("ns-research-csv-{}", std::process::id()));
        export_tables(&path, &dir, "csv").unwrap();
        let csv = std::fs::read_to_string(dir.join("hosts.csv")).unwrap();
        assert!(csv.contains("\"'=HYPERLINK("), "{csv}");
        let _ = std::fs::remove_dir_all(&dir);
        remove_db(&path);
    }
}
