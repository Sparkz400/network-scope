// SPDX-FileCopyrightText: Copyright the Network Scope contributors
// SPDX-License-Identifier: MIT
//! The research data layer (ROADMAP L67): hosts, services, certificates, fingerprints, findings
//! and observations as queryable SQLite tables next to the per-scan `snapshot` text.
//!
//! Every [`crate::store::save_at`] fills the tables in the same transaction as the snapshot, so
//! the tables always agree with the scans they describe. A database written before the tables
//! existed gets them empty from the migration; `research rebuild` ([`rebuild`]) derives the rows
//! of every stored scan again (findings are then evaluated with today's rules and feeds, which is
//! stated in the documentation). [`query`] runs one read-only statement; [`schema_text`] documents
//! every table and column, and a test keeps that documentation and the real schema in step.
//!
//! The write path is deliberately forgiving: the rows are inserted inside a savepoint, and a
//! failure rolls only that savepoint back. A scan is never lost because its research rows could
//! not be written (`research rebuild` repairs them later).
//!
//! Nothing here sends traffic; the tables are derived from what scans already collected.
use crate::{risk::Finding, store::Snapshot};
use rusqlite::{Connection, OpenFlags, params};
use serde_json::Value;
use std::path::Path;

pub mod export;
pub mod groups;
pub mod parquet;
pub mod uuid;

/// `(name, SQL type and constraints, description)` of a column.
pub type Column = (&'static str, &'static str, &'static str);

/// One research table.
pub struct Table {
    pub name: &'static str,
    pub doc: &'static str,
    /// Columns after the three every table starts with (`id`, `scan_id`, `scan_time`).
    pub columns: &'static [Column],
    /// Extra columns the index statements use; each entry is the column list of one index.
    pub indexes: &'static [&'static str],
}

/// The columns every table starts with.
pub const COMMON_COLUMNS: [Column; 3] = [
    (
        "id",
        "INTEGER PRIMARY KEY",
        "Row number, unique within the table.",
    ),
    (
        "scan_id",
        "INTEGER NOT NULL",
        "The scan the row comes from (`scans.id`, `history` lists them).",
    ),
    (
        "scan_time",
        "INTEGER NOT NULL",
        "When that scan was taken, Unix seconds (UTC). Every table has it, so a time window needs no join.",
    ),
];

/// All research tables, in the order they are created and exported.
pub const TABLES: &[Table] = &[
    Table {
        name: "hosts",
        doc: "One row per host record of a scan (responding or not).",
        columns: &[
            ("ip", "TEXT NOT NULL", "IPv4 or IPv6 address."),
            (
                "mac",
                "TEXT NOT NULL",
                "MAC address, upper case, empty when unknown.",
            ),
            (
                "hostname",
                "TEXT NOT NULL",
                "Reverse DNS or NetBIOS name, empty when unknown.",
            ),
            (
                "responding",
                "INTEGER NOT NULL",
                "1 when the host answered, else 0.",
            ),
            ("ttl", "INTEGER", "IP time to live of the first reply."),
            (
                "ping_ms",
                "INTEGER",
                "Round trip time of the first reply in milliseconds.",
            ),
            ("open_tcp", "INTEGER NOT NULL", "Number of open TCP ports."),
            (
                "open_udp",
                "INTEGER NOT NULL",
                "Number of UDP ports that answered.",
            ),
            (
                "vendor",
                "TEXT NOT NULL",
                "Vendor of the MAC address (`mac.vendor`), empty when unknown.",
            ),
            (
                "os_guess",
                "TEXT",
                "The operating system guess (`os.guess`).",
            ),
            (
                "device_type",
                "TEXT",
                "The device type conclusion (`device.type`).",
            ),
            ("targets", "TEXT NOT NULL", "The target list of the scan."),
        ],
        indexes: &["scan_id", "ip, scan_time", "mac"],
    },
    Table {
        name: "services",
        doc: "One row per open port with what service detection and OT identification found.",
        columns: &[
            ("ip", "TEXT NOT NULL", "Host address."),
            ("port", "INTEGER NOT NULL", "Port number."),
            ("protocol", "TEXT NOT NULL", "`tcp` or `udp`."),
            (
                "name",
                "TEXT NOT NULL",
                "Service name (`http`, `ssh`, `S7`, `EtherNet/IP`, ...).",
            ),
            (
                "product",
                "TEXT NOT NULL",
                "Product name from the banner or the OT identification.",
            ),
            (
                "version",
                "TEXT NOT NULL",
                "Version from the banner, or the firmware of an OT device.",
            ),
            (
                "cpe",
                "TEXT NOT NULL",
                "CPE 2.3 name derived from product and version, empty when none.",
            ),
            (
                "banner",
                "TEXT NOT NULL",
                "The service description line (`svc.PORT`) or UDP answer.",
            ),
            (
                "http_server",
                "TEXT NOT NULL",
                "The HTTP `Server` header, empty when none.",
            ),
            (
                "http_title",
                "TEXT NOT NULL",
                "The HTML title, empty when none.",
            ),
            (
                "attributes",
                "TEXT NOT NULL",
                "JSON object of the protocol fields of an OT identification (`vendor`, `order_code`, ...), `{}` otherwise.",
            ),
        ],
        indexes: &["scan_id", "ip, scan_time", "name, product, version"],
    },
    Table {
        name: "certificates",
        doc: "One row per TLS certificate a port presented. `spki_sha256` is the hash of the public key: it stays the same when a certificate is renewed with the same key.",
        columns: &[
            ("ip", "TEXT NOT NULL", "Host address."),
            (
                "port",
                "INTEGER NOT NULL",
                "Port that presented the certificate.",
            ),
            (
                "spki_sha256",
                "TEXT NOT NULL",
                "SHA-256 of the SubjectPublicKeyInfo, 64 lower-case hex digits.",
            ),
            ("subject", "TEXT NOT NULL", "Certificate subject."),
            ("issuer", "TEXT NOT NULL", "Certificate issuer."),
            (
                "san",
                "TEXT NOT NULL",
                "Subject alternative names, comma separated.",
            ),
            (
                "not_before",
                "TEXT NOT NULL",
                "Start of validity, YYYY-MM-DD.",
            ),
            ("not_after", "TEXT NOT NULL", "End of validity, YYYY-MM-DD."),
            (
                "self_signed",
                "INTEGER",
                "1 when subject and issuer are the same, 0 when not, NULL when unknown.",
            ),
            ("key", "TEXT NOT NULL", "Key type and size (`RSA 2048`)."),
            ("signature", "TEXT NOT NULL", "Signature algorithm."),
        ],
        indexes: &["spki_sha256", "scan_id", "ip, scan_time"],
    },
    Table {
        name: "fingerprints",
        doc: "Fingerprints that identify software, keys or devices across hosts and scans, one row each. `kind` is one of `spki_sha256`, `ja3s`, `jarm`, `hassh`, `favicon_mmh3`; new kinds are added without changing the columns.",
        columns: &[
            ("ip", "TEXT NOT NULL", "Host address."),
            (
                "port",
                "INTEGER",
                "Port, NULL for a fingerprint of the whole host.",
            ),
            ("kind", "TEXT NOT NULL", "What the value is (see above)."),
            ("value", "TEXT NOT NULL", "The fingerprint."),
        ],
        indexes: &["kind, value", "scan_id", "ip, scan_time"],
    },
    Table {
        name: "findings",
        doc: "The findings of a scan as `findings` prints them, evaluated when the scan was saved.",
        columns: &[
            ("ip", "TEXT NOT NULL", "Host address."),
            (
                "port",
                "INTEGER",
                "Port, NULL for a finding about the whole host.",
            ),
            (
                "severity",
                "TEXT NOT NULL",
                "`info`, `low`, `medium`, `high` or `critical`.",
            ),
            (
                "rule_id",
                "TEXT NOT NULL",
                "The rule (`telnet-open`, `cve-cve-2014-0160`, ...); see the finding pages.",
            ),
            ("title", "TEXT NOT NULL", "One-line description."),
            (
                "cve",
                "TEXT NOT NULL",
                "CVE ids, comma separated, empty when none.",
            ),
            ("evidence", "TEXT NOT NULL", "What was observed."),
            (
                "confidence",
                "INTEGER NOT NULL",
                "0-100, how sure the rule is.",
            ),
            (
                "kev",
                "INTEGER NOT NULL",
                "1 when an imported CISA KEV catalog lists one of the CVEs.",
            ),
            (
                "epss",
                "REAL",
                "Highest imported EPSS probability among the CVEs, NULL without feeds.",
            ),
        ],
        indexes: &["scan_id", "ip, scan_time", "rule_id"],
    },
    Table {
        name: "observations",
        doc: "Passive observations of a scan or capture (ARP, DHCP, mDNS, observed OT clients and servers, ...).",
        columns: &[
            ("protocol", "TEXT NOT NULL", "Observation protocol label."),
            ("mac", "TEXT NOT NULL", "MAC address, empty when none."),
            ("ip", "TEXT", "IP address, NULL when none."),
            (
                "fields",
                "TEXT NOT NULL",
                "JSON object with everything the observation carries.",
            ),
        ],
        indexes: &["scan_id", "protocol", "ip"],
    },
];

/// The `CREATE TABLE` and `CREATE INDEX` statements of the research tables (idempotent).
pub fn ddl() -> String {
    let mut out = String::new();
    for t in TABLES {
        let columns: Vec<String> = COMMON_COLUMNS
            .iter()
            .chain(t.columns)
            .map(|(name, sql, _)| format!("{name} {sql}"))
            .collect();
        out.push_str(&format!(
            "CREATE TABLE IF NOT EXISTS {}({});",
            t.name,
            columns.join(", ")
        ));
        for (n, cols) in t.indexes.iter().enumerate() {
            out.push_str(&format!(
                "CREATE INDEX IF NOT EXISTS {}_idx{n} ON {}({cols});",
                t.name, t.name
            ));
        }
    }
    out
}

/// Migration 5: the empty research tables. The rows come from `save_at` and `research rebuild`.
pub(crate) fn migrate(c: &Connection) -> rusqlite::Result<()> {
    c.execute_batch(&ddl())
}

/// The documentation of the schema, Markdown (`research schema`).
pub fn schema_text() -> String {
    let mut out = String::from(
        "# Research tables\n\nEvery table starts with `id`, `scan_id` and `scan_time`. Times are Unix seconds in UTC.\n",
    );
    for t in TABLES {
        out.push_str(&format!("\n## {}\n\n{}\n\n", t.name, t.doc));
        out.push_str("| Column | Type | Meaning |\n|---|---|---|\n");
        for (name, sql, doc) in COMMON_COLUMNS.iter().chain(t.columns) {
            out.push_str(&format!("| `{name}` | {sql} | {doc} |\n"));
        }
    }
    out
}

/// "Every host that presented this certificate key in the last six months", as one SQL query
/// (ROADMAP L67's test). Replace `<SPKI_SHA256>` with the 64-digit key hash (the `spki_sha256`
/// column of `certificates`, or `tls.PORT.spki_sha256` in a host's identity). One row per host,
/// newest first, with the ports it presented the key on.
pub const HOSTS_WITH_KEY_QUERY: &str = "SELECT h.ip, h.hostname, h.mac, group_concat(DISTINCT c.port) AS ports, MAX(c.scan_time) AS last_seen FROM certificates c JOIN hosts h ON h.scan_id = c.scan_id AND h.ip = c.ip WHERE c.spki_sha256 = '<SPKI_SHA256>' AND c.scan_time >= CAST(strftime('%s', 'now', '-6 months') AS INTEGER) GROUP BY h.ip ORDER BY last_seen DESC";

fn port_of(key: &str, family: &str, field: &str) -> Option<u16> {
    let mut parts = key.split('.');
    (parts.next()? == family).then_some(())?;
    let port = parts.next()?.parse().ok()?;
    (parts.next()? == field && parts.next().is_none()).then_some(port)
}

/// Fingerprint kinds taken from identity keys: `(family, field, kind)`.
const FINGERPRINT_KEYS: &[(&str, &str, &str)] = &[
    ("tls", "spki_sha256", "spki_sha256"),
    ("tls", "ja3s", "ja3s"),
    ("tls", "jarm", "jarm"),
    ("ssh", "hassh", "hassh"),
    ("http", "favicon_mmh3", "favicon_mmh3"),
];

fn text(identity: &std::collections::BTreeMap<String, String>, key: &str) -> String {
    identity.get(key).cloned().unwrap_or_default()
}

/// Inserts the rows of one scan. `findings` are the scan's findings (computed by the caller,
/// outside any transaction). Errors are the database's.
pub(crate) fn insert_scan(
    c: &Connection,
    scan_id: i64,
    scan_time: i64,
    snapshot: &Snapshot,
    findings: &[Finding],
) -> rusqlite::Result<()> {
    let mut host = c.prepare_cached(
        "INSERT INTO hosts(scan_id,scan_time,ip,mac,hostname,responding,ttl,ping_ms,open_tcp,open_udp,vendor,os_guess,device_type,targets) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",
    )?;
    let mut service = c.prepare_cached(
        "INSERT INTO services(scan_id,scan_time,ip,port,protocol,name,product,version,cpe,banner,http_server,http_title,attributes) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
    )?;
    let mut cert = c.prepare_cached(
        "INSERT INTO certificates(scan_id,scan_time,ip,port,spki_sha256,subject,issuer,san,not_before,not_after,self_signed,key,signature) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
    )?;
    let mut fingerprint = c.prepare_cached(
        "INSERT INTO fingerprints(scan_id,scan_time,ip,port,kind,value) VALUES(?1,?2,?3,?4,?5,?6)",
    )?;
    for h in &snapshot.hosts {
        let ip = h.ip.to_string();
        let id = &h.identity;
        host.execute(params![
            scan_id,
            scan_time,
            ip,
            h.mac,
            h.hostname,
            h.responding,
            h.ttl,
            h.ping,
            h.open.len() as i64,
            h.udp_open.len() as i64,
            text(id, "mac.vendor"),
            id.get("os.guess"),
            id.get("device.type"),
            snapshot.targets,
        ])?;
        let mut ports: Vec<u16> = h.open.clone();
        ports.sort_unstable();
        ports.dedup();
        for p in ports {
            let svc = text(id, &format!("svc.{p}"));
            service.execute(params![
                scan_id,
                scan_time,
                ip,
                p,
                "tcp",
                svc.split_whitespace().next().unwrap_or(""),
                text(id, &format!("svc.{p}.product")),
                text(id, &format!("svc.{p}.version")),
                text(id, &format!("svc.{p}.cpe")),
                svc,
                text(id, &format!("http.{p}.server")),
                text(id, &format!("http.{p}.title")),
                "{}",
            ])?;
        }
        for &p in &h.udp_open {
            let banner = text(id, &format!("udp.{p}"));
            service.execute(params![
                scan_id, scan_time, ip, p, "udp", "", "", "", "", banner, "", "", "{}",
            ])?;
        }
        for d in crate::otdevice::from_identity(id) {
            let attributes: std::collections::BTreeMap<&str, &String> = id
                .iter()
                .filter_map(|(k, v)| Some((k.strip_prefix(d.protocol)?.strip_prefix('.')?, v)))
                .collect();
            service.execute(params![
                scan_id,
                scan_time,
                ip,
                d.port,
                if d.protocol == "BACnet" { "udp" } else { "tcp" },
                d.protocol,
                d.products.first().cloned().unwrap_or_default(),
                d.version,
                "",
                d.describe(),
                "",
                "",
                serde_json::to_string(&attributes).unwrap_or_else(|_| "{}".into()),
            ])?;
        }
        // Certificates: one per port that has a subject or a key hash.
        let mut cert_ports: Vec<u16> = id
            .keys()
            .filter_map(|k| {
                port_of(k, "tls", "spki_sha256").or_else(|| port_of(k, "tls", "subject"))
            })
            .collect();
        cert_ports.sort_unstable();
        cert_ports.dedup();
        for p in cert_ports {
            let t = |f: &str| text(id, &format!("tls.{p}.{f}"));
            let self_signed = id
                .get(&format!("tls.{p}.self_signed"))
                .map(|v| i64::from(v == "true"));
            cert.execute(params![
                scan_id,
                scan_time,
                ip,
                p,
                t("spki_sha256"),
                t("subject"),
                t("issuer"),
                t("san"),
                t("not_before"),
                t("not_after"),
                self_signed,
                t("key"),
                t("signature"),
            ])?;
        }
        for (key, value) in id {
            for (family, field, kind) in FINGERPRINT_KEYS {
                if let Some(port) = port_of(key, family, field)
                    && !value.is_empty()
                {
                    fingerprint.execute(params![scan_id, scan_time, ip, port, kind, value])?;
                }
            }
        }
    }
    let mut finding = c.prepare_cached(
        "INSERT INTO findings(scan_id,scan_time,ip,port,severity,rule_id,title,cve,evidence,confidence,kev,epss) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
    )?;
    for f in findings {
        finding.execute(params![
            scan_id,
            scan_time,
            f.ip.to_string(),
            f.port,
            f.severity.name(),
            f.id,
            f.title,
            f.cve.join(","),
            f.evidence,
            i64::from(f.confidence),
            f.exploit.kev,
            f.exploit.epss.map(|s| s.as_f64()),
        ])?;
    }
    let mut observation = c.prepare_cached(
        "INSERT INTO observations(scan_id,scan_time,protocol,mac,ip,fields) VALUES(?1,?2,?3,?4,?5,?6)",
    )?;
    for o in &snapshot.observations {
        observation.execute(params![
            scan_id,
            scan_time,
            o.protocol,
            o.mac,
            o.ip.map(|ip| ip.to_string()),
            serde_json::to_string(&o.fields).unwrap_or_else(|_| "{}".into()),
        ])?;
    }
    Ok(())
}

/// [`insert_scan`] inside a savepoint: a failure rolls back the research rows only.
pub(crate) fn insert_scan_guarded(
    c: &Connection,
    scan_id: i64,
    scan_time: i64,
    snapshot: &Snapshot,
    findings: &[Finding],
) {
    if let Err(e) = c.execute_batch("SAVEPOINT research") {
        eprintln!(
            "scan #{scan_id}: research rows skipped ({e}); run `research rebuild` to index it"
        );
        return;
    }
    match insert_scan(c, scan_id, scan_time, snapshot, findings) {
        Ok(()) => {
            let _ = c.execute_batch("RELEASE research");
        }
        Err(e) => {
            let _ = c.execute_batch("ROLLBACK TO research; RELEASE research");
            // The scan itself is kept; surface the gap so a systematic failure is not silent.
            eprintln!(
                "scan #{scan_id}: research rows not written ({e}); run `research rebuild` to index it"
            );
        }
    }
}

/// What `research rebuild` did.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct RebuildReport {
    /// Scans read and indexed.
    pub scans: usize,
    /// Scans whose snapshot could not be read (left without rows).
    pub skipped: usize,
    /// Rows now in each table, in [`TABLES`] order.
    pub rows: std::collections::BTreeMap<String, i64>,
}

/// Derives the research rows of every stored scan again, replacing the existing rows. One
/// transaction: a failure leaves the tables as they were.
pub fn rebuild(path: &Path) -> Result<RebuildReport, String> {
    let mut c = crate::store::open(path)?;
    let ids: Vec<i64> = c
        .prepare("SELECT id FROM scans ORDER BY id")
        .map_err(|e| e.to_string())?
        .query_map([], |r| r.get(0))
        .map_err(|e| e.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    let tx = c
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;
    for t in TABLES {
        tx.execute(&format!("DELETE FROM {}", t.name), [])
            .map_err(|e| e.to_string())?;
    }
    let mut report = RebuildReport::default();
    for id in ids {
        let (time, data): (i64, String) = tx
            .query_row(
                "SELECT timestamp,snapshot FROM scans WHERE id=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|e| e.to_string())?;
        let Ok(snapshot) = serde_json::from_str::<Snapshot>(&data) else {
            report.skipped += 1;
            continue;
        };
        let findings = crate::risk::analyze_snapshot(&snapshot);
        insert_scan(&tx, id, time, &snapshot, &findings).map_err(|e| e.to_string())?;
        report.scans += 1;
    }
    for t in TABLES {
        let n: i64 = tx
            .query_row(&format!("SELECT count(*) FROM {}", t.name), [], |r| {
                r.get(0)
            })
            .map_err(|e| e.to_string())?;
        report.rows.insert(t.name.to_string(), n);
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(report)
}

/// The result of [`query`].
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct QueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Value>>,
    /// More rows matched than the limit allowed.
    pub truncated: bool,
}

/// First keyword of a statement, after whitespace and SQL comments.
fn first_keyword(sql: &str) -> String {
    let mut rest = sql.trim_start();
    loop {
        if let Some(r) = rest.strip_prefix("--") {
            rest = r.split_once('\n').map_or("", |(_, tail)| tail).trim_start();
        } else if let Some(r) = rest.strip_prefix("/*") {
            rest = r.split_once("*/").map_or("", |(_, tail)| tail).trim_start();
        } else {
            break;
        }
    }
    rest.split(|c: char| !c.is_ascii_alphabetic())
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn json_value(v: rusqlite::types::ValueRef<'_>) -> Value {
    use rusqlite::types::ValueRef;
    match v {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => Value::from(i),
        ValueRef::Real(f) => serde_json::Number::from_f64(f).map_or(Value::Null, Value::Number),
        ValueRef::Text(t) => Value::String(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Blob(b) => Value::String(format!("x'{}'", crate::fingerprint::hex(b))),
    }
}

/// Opens the database for queries: created and migrated first (so the tables exist), then reopened
/// read-only with `query_only` on.
fn open_read_only(path: &Path) -> Result<Connection, String> {
    drop(crate::store::open(path)?);
    let c = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| e.to_string())?;
    c.busy_timeout(crate::store::BUSY_TIMEOUT)
        .map_err(|e| e.to_string())?;
    c.execute_batch("PRAGMA query_only=ON")
        .map_err(|e| e.to_string())?;
    Ok(c)
}

/// Runs one read-only statement (`SELECT`, `WITH ... SELECT` or `VALUES`) and returns at most
/// `limit` rows. Several guards apply, any one of which stops a write: only those statement
/// kinds are accepted, one statement only, SQLite must report it as read-only, the connection is
/// opened read-only and `query_only` is on.
pub fn query(path: &Path, sql: &str, limit: usize) -> Result<QueryResult, String> {
    run_query(&open_read_only(path)?, sql, limit)
}

fn run_query(c: &Connection, sql: &str, limit: usize) -> Result<QueryResult, String> {
    let keyword = first_keyword(sql);
    if !["select", "with", "values"].contains(&keyword.as_str()) {
        return Err(format!(
            "Only read-only SELECT queries are accepted (the statement starts with {:?})",
            if keyword.is_empty() {
                "nothing"
            } else {
                &keyword
            }
        ));
    }
    let mut statement = c.prepare(sql).map_err(|e| e.to_string())?;
    if !statement.readonly() {
        return Err(
            "The statement would change the database; only read-only queries are accepted".into(),
        );
    }
    let columns: Vec<String> = statement.column_names().map(|n| n.to_string()).collect();
    let mut rows = statement.query([]).map_err(|e| e.to_string())?;
    let mut out = vec![];
    let mut truncated = false;
    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
        if out.len() >= limit {
            truncated = true;
            break;
        }
        out.push(
            (0..columns.len())
                .map(|i| row.get_ref(i).map(json_value))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?,
        );
    }
    Ok(QueryResult {
        columns,
        rows: out,
        truncated,
    })
}

/// A value of a result as plain text for CSV.
pub fn cell_text(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        scan::{Host, Settings},
        store,
    };
    use std::collections::BTreeMap;

    pub(crate) fn temp_db(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "netscope-research-{tag}-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
    pub(crate) fn remove_db(path: &Path) {
        for suffix in ["", "-wal", "-shm"] {
            let mut p = path.as_os_str().to_owned();
            p.push(suffix);
            let _ = std::fs::remove_file(p);
        }
    }

    pub(crate) fn host(ip: &str, open: &[u16], identity: &[(&str, &str)]) -> Host {
        Host {
            ip: ip.parse().unwrap(),
            responding: true,
            ping: Some(3),
            ttl: Some(64),
            hostname: format!("host-{ip}"),
            mac: String::new(),
            open: open.to_vec(),
            closed: 0,
            unanswered: 0,
            errors: vec![],
            ports_checked: true,
            identity: identity
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            udp_open: vec![],
            trace: vec![],
        }
    }
    pub(crate) fn snapshot(hosts: Vec<Host>) -> Snapshot {
        Snapshot {
            targets: "10.0.0.0/24".into(),
            complete: true,
            settings: Settings::default(),
            hosts,
            observations: vec![],
            notes: BTreeMap::new(),
            sent: vec![],
        }
    }

    const DAY: i64 = 86_400;
    const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn tls_host(ip: &str, key: &str) -> Host {
        host(
            ip,
            &[443],
            &[
                ("svc.443", "https nginx 1.2"),
                ("tls.443.subject", "CN=plc.local"),
                ("tls.443.spki_sha256", key),
                ("tls.443.ja3s", "0123456789abcdef0123456789abcdef"),
                ("tls.443.self_signed", "true"),
            ],
        )
    }

    /// The test of ROADMAP L67: "every host that presented this certificate key in the last
    /// six months" is one SQL query, the one in `HOSTS_WITH_KEY_QUERY` (and in the docs).
    #[test]
    fn every_host_that_presented_a_key_in_the_last_six_months_is_one_query() {
        let path = temp_db("key-query");
        let now = store::now();
        // a fresh sighting, one a month ago on a second host, one seven months ago, another key
        store::save_at(
            &path,
            &snapshot(vec![tls_host("10.0.0.5", KEY_A)]),
            now - DAY,
        )
        .unwrap();
        store::save_at(
            &path,
            &snapshot(vec![
                tls_host("10.0.0.5", KEY_A),
                tls_host("10.0.0.6", KEY_A),
            ]),
            now - 30 * DAY,
        )
        .unwrap();
        store::save_at(
            &path,
            &snapshot(vec![tls_host("10.0.0.7", KEY_A)]),
            now - 210 * DAY,
        )
        .unwrap();
        store::save_at(
            &path,
            &snapshot(vec![tls_host("10.0.0.8", KEY_B)]),
            now - DAY,
        )
        .unwrap();

        let sql = HOSTS_WITH_KEY_QUERY.replace("<SPKI_SHA256>", KEY_A);
        let result = query(&path, &sql, 100).unwrap();
        assert_eq!(
            result.columns,
            ["ip", "hostname", "mac", "ports", "last_seen"]
        );
        let ips: Vec<&str> = result.rows.iter().map(|r| r[0].as_str().unwrap()).collect();
        assert_eq!(
            ips,
            ["10.0.0.5", "10.0.0.6"],
            "newest first; the seven-month-old host and the other key are left out"
        );
        assert_eq!(result.rows[0][3], "443");
        assert_eq!(result.rows[0][4], now - DAY);
        remove_db(&path);
    }

    /// The documentation carries the query verbatim and describes every table and column.
    #[test]
    fn the_docs_page_has_the_query_and_the_schema() {
        let page = include_str!("../../../docs/src/research.md");
        assert!(
            page.contains(HOSTS_WITH_KEY_QUERY),
            "docs/src/research.md must contain HOSTS_WITH_KEY_QUERY exactly"
        );
        for t in TABLES {
            assert!(page.contains(&format!("### {}", t.name)), "{}", t.name);
            for (name, _, _) in t.columns {
                assert!(page.contains(&format!("`{name}`")), "{}.{name}", t.name);
            }
        }
    }

    #[test]
    fn saving_a_scan_fills_every_table() {
        let path = temp_db("fill");
        let mut s = snapshot(vec![
            tls_host("10.0.0.5", KEY_A),
            host(
                "10.0.0.10",
                &[102, 23],
                &[
                    ("svc.23", "telnet"),
                    ("S7.order_code", "6ES7 214-1AG40-0XB0"),
                    ("S7.firmware", "4.2.3"),
                    ("ssh.22.hassh", "deadbeef"),
                ],
            ),
        ]);
        s.observations.push(crate::passive::Observation {
            protocol: "ARP".into(),
            mac: "AA:BB:CC:00:00:01".into(),
            ip: Some("10.0.0.99".parse().unwrap()),
            fields: BTreeMap::from([("note".to_string(), "x".to_string())]),
        });
        let id = store::save_at(&path, &s, 1_700_000_000).unwrap();
        let count = |table: &str| -> i64 {
            query(
                &path,
                &format!("SELECT count(*) FROM {table} WHERE scan_id = {id}"),
                1,
            )
            .unwrap()
            .rows[0][0]
                .as_i64()
                .unwrap()
        };
        assert_eq!(count("hosts"), 2);
        assert_eq!(count("certificates"), 1);
        assert_eq!(count("observations"), 1);
        assert!(
            count("services") >= 4,
            "tcp ports plus the S7 identification"
        );
        assert!(count("findings") >= 1, "telnet is a finding");
        // fingerprints carry the key, the JA3S and the HASSH of the hosts
        let kinds = query(&path, "SELECT kind FROM fingerprints ORDER BY kind", 10).unwrap();
        let kinds: Vec<&str> = kinds.rows.iter().map(|r| r[0].as_str().unwrap()).collect();
        assert_eq!(kinds, ["hassh", "ja3s", "spki_sha256"]);
        // the OT identification is a service row with the firmware as its version
        let s7 = query(
            &path,
            "SELECT product, version, attributes FROM services WHERE name = 'S7'",
            5,
        )
        .unwrap();
        assert_eq!(s7.rows[0][0], "6ES7 214-1AG40-0XB0");
        assert_eq!(s7.rows[0][1], "4.2.3");
        assert!(s7.rows[0][2].as_str().unwrap().contains("order_code"));
        let time = query(&path, "SELECT DISTINCT scan_time FROM hosts", 5).unwrap();
        assert_eq!(time.rows, [[Value::from(1_700_000_000)]]);
        remove_db(&path);
    }

    #[test]
    fn rebuild_fills_an_older_database_and_is_repeatable() {
        let path = temp_db("rebuild");
        // A database from before the tables: the scans exist, the research rows do not.
        let id = store::save_at(&path, &snapshot(vec![tls_host("10.0.0.5", KEY_A)]), 100).unwrap();
        {
            let c = Connection::open(&path).unwrap();
            for t in TABLES {
                c.execute(&format!("DELETE FROM {}", t.name), []).unwrap();
            }
        }
        let rows = |sql: &str| query(&path, sql, 10).unwrap().rows.len();
        assert_eq!(rows("SELECT * FROM hosts"), 0);
        let report = rebuild(&path).unwrap();
        assert_eq!((report.scans, report.skipped), (1, 0));
        assert_eq!(report.rows["hosts"], 1);
        assert_eq!(rows("SELECT * FROM certificates"), 1);
        let again = rebuild(&path).unwrap();
        assert_eq!(again, report, "a second rebuild changes nothing");
        assert_eq!(
            query(&path, "SELECT scan_id FROM hosts", 1).unwrap().rows[0][0],
            id
        );
        // an unreadable snapshot is skipped, not fatal
        {
            let c = Connection::open(&path).unwrap();
            c.execute(
                "INSERT INTO scans(timestamp,targets,complete,hosts,snapshot) VALUES(5,'x',1,0,'not json')",
                [],
            )
            .unwrap();
        }
        let report = rebuild(&path).unwrap();
        assert_eq!((report.scans, report.skipped), (1, 1));
        remove_db(&path);
    }

    #[test]
    fn a_database_from_before_the_tables_upgrades_with_empty_ones() {
        let path = temp_db("upgrade");
        {
            // What version 4 left behind: no research tables and user_version 4.
            let c = store::open(&path).unwrap();
            for t in TABLES {
                c.execute_batch(&format!("DROP TABLE {}", t.name)).unwrap();
            }
            c.execute_batch("PRAGMA user_version=4").unwrap();
        }
        let result = query(&path, "SELECT count(*) FROM hosts", 1).unwrap();
        assert_eq!(result.rows[0][0], 0);
        remove_db(&path);
    }

    #[test]
    fn the_documentation_names_every_column_of_the_real_schema() {
        let path = temp_db("schema-doc");
        let c = store::open(&path).unwrap();
        for t in TABLES {
            let real: Vec<String> = c
                .prepare(&format!("SELECT name FROM pragma_table_info('{}')", t.name))
                .unwrap()
                .query_map([], |r| r.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            let documented: Vec<String> = COMMON_COLUMNS
                .iter()
                .chain(t.columns)
                .map(|(n, _, _)| n.to_string())
                .collect();
            assert_eq!(real, documented, "{}", t.name);
        }
        let text = schema_text();
        for t in TABLES {
            assert!(text.contains(&format!("## {}", t.name)));
        }
        drop(c);
        remove_db(&path);
    }

    #[test]
    fn query_refuses_everything_that_is_not_a_read() {
        let path = temp_db("readonly");
        store::save_at(&path, &snapshot(vec![tls_host("10.0.0.5", KEY_A)]), 100).unwrap();
        for sql in [
            "INSERT INTO hosts(scan_id,scan_time,ip,responding,open_tcp,open_udp,targets,mac,hostname,vendor) VALUES(1,1,'x',1,0,0,'','','','')",
            "DELETE FROM hosts",
            "UPDATE hosts SET ip = 'x'",
            "DROP TABLE hosts",
            "CREATE TABLE x(a)",
            "ATTACH DATABASE ':memory:' AS other",
            "PRAGMA query_only = OFF",
            "PRAGMA journal_mode = DELETE",
            "VACUUM",
            "BEGIN",
            "  -- a comment first\n DELETE FROM hosts",
            "WITH x AS (SELECT 1) DELETE FROM hosts",
            "SELECT 1; DELETE FROM hosts",
            "",
        ] {
            assert!(query(&path, sql, 10).is_err(), "{sql:?} must be refused");
        }
        assert_eq!(
            query(&path, "SELECT count(*) FROM hosts", 1).unwrap().rows[0][0],
            1,
            "nothing was changed"
        );
        // reads still work: comments, WITH, VALUES, joins
        assert!(query(&path, "/* c */ SELECT 1 AS one", 1).is_ok());
        assert!(query(&path, "WITH x AS (SELECT 2 AS n) SELECT n FROM x", 1).is_ok());
        assert!(query(&path, "VALUES (1),(2)", 5).is_ok());
        // and a read-only connection refuses a write even when the text checks are bypassed
        let c = open_read_only(&path).unwrap();
        assert!(c.execute("DELETE FROM hosts", []).is_err());
        assert!(
            c.execute_batch("PRAGMA query_only=OFF; DELETE FROM hosts")
                .is_err()
        );
        remove_db(&path);
    }

    #[test]
    fn query_limits_rows_and_converts_every_type() {
        let path = temp_db("limit");
        let r = query(
            &path,
            "SELECT 1 AS i, 1.5 AS f, 'x' AS t, NULL AS n, x'0a0b' AS b UNION ALL SELECT 2, 2.5, 'y', NULL, x''",
            1,
        )
        .unwrap();
        assert!(r.truncated);
        assert_eq!(r.rows.len(), 1);
        assert_eq!(
            r.rows[0],
            [
                Value::from(1),
                Value::from(1.5),
                Value::from("x"),
                Value::Null,
                Value::from("x'0a0b'")
            ]
        );
        assert!(!query(&path, "SELECT 1", 1).unwrap().truncated);
        assert_eq!(cell_text(&Value::Null), "");
        assert_eq!(cell_text(&Value::from(3)), "3");
        remove_db(&path);
    }

    #[test]
    fn first_keyword_skips_comments_and_whitespace() {
        assert_eq!(first_keyword("  SELECT 1"), "select");
        assert_eq!(
            first_keyword("-- x\n/* y */ with a as (select 1) select 1"),
            "with"
        );
        assert_eq!(first_keyword("/* unterminated"), "");
        assert_eq!(first_keyword("(select 1)"), "");
    }
}
