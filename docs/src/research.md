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

## Existing databases: `research rebuild`

A database written by an earlier version gets the tables empty. `research rebuild` derives the rows of every stored scan again and replaces what is there (one transaction; a failure changes nothing). The findings of a rebuilt scan are evaluated with today's rules and feed caches, not with the ones of the day of the scan, so a rebuilt `findings` table can show CVE matches that did not exist then. Scans saved after the upgrade keep the findings of their day. A scan whose stored snapshot cannot be read is skipped and counted.

## Exports

`research export csv|ndjson --output DIR` writes one file per table (`hosts.ndjson`, `services.ndjson`, ...) and a `manifest.json` listing them (it carries the usual `schema` member; the table files are plain rows without it, so they load as tables). CSV files have a header row, `NULL` is an empty cell, and cells that a spreadsheet would read as a formula are prefixed with `'` like every other CSV export. There is no Parquet writer in the program (that would need a library); DuckDB converts the files in one line:

```sh
duckdb -c "COPY (SELECT * FROM read_ndjson('hosts.ndjson')) TO 'hosts.parquet'"
```

`research export stix [SCAN_ID]` writes a STIX 2.1 bundle of one scan (default: the newest completed scan). Each responding host becomes an `infrastructure` object that `consists-of` its `ipv4-addr`/`ipv6-addr` (and `mac-addr`); an `observed-data` object lists the host's observables and the `software` it runs (including identified OT firmware); each CVE of a finding becomes a `vulnerability` object that the infrastructure `has`. Identifiers are UUIDv5, so exporting the same scan twice gives the same bundle. Observables use the STIX namespace over the canonical JSON of their identifying properties, as the specification prescribes; this was derived from the specification text and has not been compared with another implementation's output.

`research export ocsf [SCAN_ID]` writes OCSF 1.3 events, one JSON object per line: a Device Inventory Info event (class 5001) per responding host and a Vulnerability Finding event (class 2002) per finding. The layouts follow the published class definitions as understood when this was written; they have not been run through the OCSF validator, and fields without a safe mapping are under `unmapped`.
