# Research data layer

Network Scope keeps every scan as a JSON snapshot. For research questions ("which hosts presented this key?", "which devices run this firmware?") the same data is also stored in ordinary SQLite tables of the inventory database. They are filled when a scan is saved, in the same transaction as the snapshot, so the tables and the scans never disagree. Nothing here sends a packet: the tables are derived from what scans already collected, and the read-only promise is unchanged.

```sh
network-scope-cli research query "SELECT ip, port, product, version FROM services WHERE name = 'S7'"
network-scope-cli research schema
network-scope-cli research rebuild
network-scope-cli research export ndjson --output research/
network-scope-cli research export stix 12 --output scan-12.stix.json
```

You can also open the database with any SQLite tool (`sqlite3 inventory.sqlite`, DuckDB's `sqlite` extension, DB Browser). The default location is `%LOCALAPPDATA%\NetworkScope\inventory.sqlite`.

## One query: who presented this key?

The test of the feature is that "every host that presented this certificate key in the last six months" is a single query. Replace `<SPKI_SHA256>` with the key hash (the `tls.PORT.spki_sha256` value of a host, or the `spki_sha256` column of `certificates`):

```sql
SELECT h.ip, h.hostname, h.mac, group_concat(DISTINCT c.port) AS ports, MAX(c.scan_time) AS last_seen FROM certificates c JOIN hosts h ON h.scan_id = c.scan_id AND h.ip = c.ip WHERE c.spki_sha256 = '<SPKI_SHA256>' AND c.scan_time >= CAST(strftime('%s', 'now', '-6 months') AS INTEGER) GROUP BY h.ip ORDER BY last_seen DESC
```

The result has one row per host, newest first, with the ports it presented the key on. The key hash is the SHA-256 of the certificate's SubjectPublicKeyInfo, so a renewed certificate with the same key still matches, and a vendor default key shows up on every device that ships it.

A few more questions in the same style:

```sql
-- every S7 answer that reported this firmware version
SELECT ip, product, version FROM services WHERE name = 'S7' AND version = '4.2.3';

-- how often each JA4S fingerprint occurs, and on how many hosts
SELECT value, count(*) AS rows, count(DISTINCT ip) AS hosts FROM fingerprints WHERE kind = 'ja4s' GROUP BY value ORDER BY hosts DESC;

-- known-exploited findings
SELECT DISTINCT ip, port, rule_id, cve FROM findings WHERE kev = 1;
```

## `research query`

`research query "SQL"` runs exactly one read-only statement (`SELECT`, `WITH ... SELECT` or `VALUES`) and prints the result as JSON (the default), CSV or tab-separated text. `--top N` limits the number of rows (default 10000). Several independent guards stop anything that would write: only those statement kinds are accepted, a second statement is refused, SQLite must report the statement as read-only, and the database is opened read-only with `query_only` on. `PRAGMA`, `ATTACH`, `INSERT`, `DROP` and the rest are refused. A query still uses CPU and the database file's read lock for as long as it runs: there is no time limit, so keep an eye on queries with large joins on a big database.

## Schema

`research schema` prints this section. Every table starts with `id`, `scan_id` and `scan_time` (Unix seconds, UTC), so a time window needs no join. Rows are never updated; a new scan adds new rows.

### hosts

One row per host record of a scan (responding or not).

| Column | Meaning |
|---|---|
| `ip` | IPv4 or IPv6 address |
| `mac` | MAC address, upper case, empty when unknown |
| `hostname` | Reverse DNS or NetBIOS name, empty when unknown |
| `responding` | 1 when the host answered, else 0 |
| `ttl`, `ping_ms` | IP time to live and round trip time of the first reply |
| `open_tcp`, `open_udp` | Number of open TCP ports and of UDP ports that answered |
| `vendor` | Vendor of the MAC address, empty when unknown |
| `os_guess`, `device_type` | The operating system guess and the device type conclusion |
| `targets` | The target list of the scan |

### services

One row per open port with what service detection and OT identification found. An OT identification (S7, EtherNet/IP, Modbus, OPC UA) adds a row named after the protocol: `product` is the order code or product name, `version` the firmware, and `attributes` the protocol fields as JSON.

| Column | Meaning |
|---|---|
| `ip`, `port`, `protocol` | Host, port and `tcp` or `udp` |
| `name` | Service name (`http`, `ssh`, `S7`, `EtherNet/IP`, ...) |
| `product`, `version`, `cpe` | From the banner or the OT identification, CPE 2.3 name when derived |
| `banner` | The service description line, or the UDP answer |
| `http_server`, `http_title` | HTTP `Server` header and HTML title |
| `attributes` | JSON object of the OT protocol fields, `{}` otherwise |

### certificates

One row per TLS certificate a port presented. `spki_sha256` is the hash of the public key: it stays the same when a certificate is renewed with the same key.

| Column | Meaning |
|---|---|
| `ip`, `port` | Host and port |
| `spki_sha256` | SHA-256 of the SubjectPublicKeyInfo, 64 lower-case hex digits |
| `subject`, `issuer`, `san` | Subject, issuer, alternative names |
| `not_before`, `not_after` | Validity, YYYY-MM-DD |
| `self_signed` | 1, 0 or NULL when unknown |
| `key`, `signature` | Key type and size, signature algorithm |
| `ja4x` | JA4X certificate fingerprint, empty when not computed |

### fingerprints

Fingerprints that identify software, keys or devices across hosts and scans, one row each: `kind` is `spki_sha256`, `ja4s`, `jarm`, `ja4x`, `hassh` or `favicon_mmh3`. New kinds are added without changing the columns.

| Column | Meaning |
|---|---|
| `ip`, `port` | Host and port (NULL for a fingerprint of the whole host) |
| `kind`, `value` | What the value is, and the value |

### findings

The findings of a scan as `findings` prints them, evaluated when the scan was saved.

| Column | Meaning |
|---|---|
| `ip`, `port` | Host and port (NULL for the whole host) |
| `severity`, `rule_id`, `title` | The finding; see the finding pages |
| `cve` | CVE ids, comma separated |
| `evidence`, `confidence` | What was observed, and how sure the rule is (0-100) |
| `kev`, `epss` | Imported CISA KEV membership and the highest EPSS probability, NULL without feeds |

### observations

Passive observations of a scan or capture (ARP, DHCP, mDNS, observed OT clients and servers, ...).

| Column | Meaning |
|---|---|
| `protocol`, `mac`, `ip` | Observation protocol label, MAC and IP (NULL when none) |
| `fields` | JSON object with everything the observation carries |

## Fingerprints you can pivot on

The `fingerprints` table holds what can link devices across scans and sites:

| `kind` | What it is | Comes from |
| --- | --- | --- |
| `spki_sha256` | SHA-256 of the certificate's public key; the same private key on several devices | every TLS port (`tls.PORT.spki_sha256`) |
| `ja4x` | JA4X certificate fingerprint: the same issuer and subject fields and extensions, whatever the key | every TLS port (`tls.PORT.ja4x`) |
| `ja4s`, `jarm` | The TLS stack and its configuration | `--services`; `--jarm` for JARM |
| `hassh` | The SSH stack and its configuration | `--services` |
| `favicon_mmh3` | Shodan-compatible hash of the web interface's favicon | `http.PORT.favicon_mmh3`, see below |
| `ot_firmware` | Industrial vendor, product and firmware version (derived from `services` when `research groups` runs) | `--ot` |

**JA4X.** The three parts are the first 12 hex digits of the SHA-256 of the comma-separated hex of the object identifiers of the issuer's name attributes, of the subject's name attributes and of the extensions, in certificate order (`000000000000` for an empty list). It is **self-derived** from the published JA4X description: it was implemented from that text, the hashing and the extraction of the OIDs are tested against independent computations, but it has not been compared with FoxIO's reference implementation or its test vectors, so a value may differ from other tools'. As a pivot inside Network Scope it works either way: certificates built from one template give the same value. JA4X belongs to the JA4+ methods under the FoxIO License 1.1 (see `data/README.md`).

**Favicon hash.** `fingerprints favicon FILE` prints `http.favicon.hash:N`, the value Shodan indexes: MurmurHash3 (x86, 32 bit, seed 0) of the favicon's base64 text with a line break every 76 characters, as a signed number. The algorithm is checked against published MurmurHash3 test vectors and an independent Python implementation of the two steps; no real favicon with a published Shodan value is in the tests. **The scanner does not fetch favicons**: that would be one more request per web port, and the hash is computed only from a file you give. The `favicon_mmh3` kind is therefore empty unless an import fills the `http.PORT.favicon_mmh3` identity key.

**JA4H** fingerprints the headers of an HTTP *request*, which only a client sends. The scanner is the client, a device's reply has no JA4H, and no server-side variant is defined, so it is not implemented.

### `research groups`

```sh
network-scope-cli research groups                    # text
network-scope-cli research groups --format json --top 50
```

lists the devices that share a fingerprint across scans and sites: a *group* is one fingerprint value with at least two different devices. A device is its MAC address when a scan saw one, else its IP address, so a device that changed address counts once; a *site* is the target list of the scan that saw it. The `strength` says what a group means: `key` (the devices use the same private key: a vendor default key or a cloned image, so whoever holds the key can impersonate all of them), `firmware` (the same industrial vendor, product and firmware version) or `software` (likely the same TLS or SSH stack, certificate template or web interface: evidence, not proof). Keys come first, then groups by size. `--top N` bounds how many fingerprints are examined (default 200); at most 50 members are listed per group, the count is always complete. The same grouping is one SQL query over `fingerprints` and `services`, which you can adapt (see `core/src/research/groups.rs`).

## Existing databases: `research rebuild`

A database written by an earlier version gets the tables empty. `research rebuild` derives the rows of every stored scan again and replaces what is there (one transaction; a failure changes nothing). The findings of a rebuilt scan are evaluated with today's rules and feed caches, not with the ones of the day of the scan, so a rebuilt `findings` table can show CVE matches that did not exist then. Scans saved after the upgrade keep the findings of their day. A scan whose stored snapshot cannot be read is skipped and counted.

## Exports

`research export csv|ndjson|parquet --output DIR` writes one file per table (`hosts.ndjson`, `services.parquet`, ...) and a `manifest.json` listing them (it carries the usual `schema` member; the table files are plain rows without it, so they load as tables). CSV files have a header row, `NULL` is an empty cell, and cells that a spreadsheet would read as a formula are prefixed with `'` like every other CSV export.

Parquet files come from a small writer inside the program (no library): uncompressed, PLAIN encoding, no statistics or dictionaries, one data page per column and row group, at most 50 000 rows per row group (so memory does not grow with the table; an empty table is a file without row groups). Columns follow the declared SQL types: `INTEGER` is a 64-bit integer (`scan_time` stays Unix seconds, `BIGINT` in DuckDB), `REAL` a double, `TEXT` a UTF-8 string; `NOT NULL` columns are required, the others optional. The files are bigger than a compressed Parquet file would be; DuckDB or pandas can recompress them (`COPY (SELECT * FROM 'hosts.parquet') TO 'hosts.zstd.parquet' (COMPRESSION zstd)`):

```sh
duckdb -c "SELECT ip, port, name FROM 'services.parquet' WHERE name = 'S7'"
python -c "import pandas; print(pandas.read_parquet('hosts.parquet'))"
```

`research export stix [SCAN_ID]` writes a STIX 2.1 bundle of one scan (default: the newest completed scan). Each responding host becomes an `infrastructure` object that `consists-of` its `ipv4-addr`/`ipv6-addr` (and `mac-addr`); an `observed-data` object lists the host's observables and the `software` it runs (including identified OT firmware); each CVE of a finding becomes a `vulnerability` object that the infrastructure `has`. Identifiers are UUIDv5, so exporting the same scan twice gives the same bundle. Observables use the STIX namespace over the canonical JSON of their identifying properties, as the specification prescribes.

`research export ocsf [SCAN_ID]` writes OCSF 1.3 events, one JSON object per line: a Device Inventory Info event (class 5001) per responding host, a Vulnerability Finding event (class 2002) per finding that names a CVE (OCSF requires a CVE or CWE in that class) and a Detection Finding event (class 2004) per finding without one. Fields without a safe mapping are under `unmapped`.

### What was checked, and with what

Checked on 2026-11-20 (Windows, Python 3.13), on a scan of the lab simulators (`lab/simulators.py`, `--fast --deep --ot`: one host, 10 services, 12 findings) and on a 163 840-row `services` table, with `scripts/validate_research_exports.py` (it needs `pip install pyarrow duckdb stix2-validator stix2 jsonschema` and is not part of CI):

| Export | Checked with | Result |
|---|---|---|
| Parquet | pyarrow 26.0.1 and DuckDB 2.0.0 read every table; the rows equal the NDJSON export; the 163 840-row table (4 row groups) equals the SQLite rows | identical |
| STIX 2.1 | `stix2-validator` 3.3.2 (version 2.1) | valid, 0 errors, 16 warnings, all "identifier is not a UUIDv4": the bundle, infrastructure, relationship, observed-data and vulnerability objects use deterministic UUIDv5 ids on purpose |
| STIX 2.1 observable ids | `stix2` 3.0.2 (OASIS cti-python-stix2) computes the id of each `ipv4-addr` and `software` object | the 7 ids are identical (no `mac-addr` or `ipv6-addr` was in the bundle) |
| OCSF 1.3 | the compiled OCSF 1.3.0 schema from `schema.ocsf.io` (built from `ocsf/ocsf-schema`, tag v1.3.0) turned into a JSON Schema per class, validated with `jsonschema` 4.26.0 | 13 of 13 events valid |

The OCSF check found a real defect that is fixed: findings without a CVE were Vulnerability Findings without the required `vulnerabilities` (7 of 13 events invalid); they are now Detection Findings. The scan had no TLS service, so the `certificates` table and certificate-related fields were not part of these runs. Two cautions: the OCSF check uses a JSON Schema derived from the server's compiled schema by `scripts/validate_research_exports.py`, not an official OCSF JSON Schema file for events (the `metaschema/` folder of the OCSF repository validates schema definitions, not events, and the class pages of `schema.ocsf.io` answered HTML, or `406 Not Acceptable` to `Accept: application/json`, on 2026-11-20), and passing a validator is not a statement that a particular SIEM ingests the events unchanged.
