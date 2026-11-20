# Findings and CVE hints

Findings are derived from what a scan collected, so run it with `--services` (or `--deep`). They work on stored snapshots and never send traffic.

```sh
network-scope-cli findings ID --min-severity low
```

The desktop shows them in the **Findings** window (sortable, filterable by severity and text). Severities: info, low, medium, high, critical. Every finding has a page in the [Finding reference](findings/index.md) that explains it in plain language, states exactly what the tool looked at and how to fix it.

## Checks

- Certificates: expired, not yet valid, soon expiring, self-signed, weak signature hashes, short RSA keys.
- TLS: SSLv3, TLS 1.0/1.1; RC4/DES/3DES/export/anonymous suites; missing forward secrecy.
- SSH: weak and legacy algorithms (including Terrapin, CVE-2023-48795), SSH protocol 1.
- Cleartext and unauthenticated services: Telnet, FTP, VNC, cleartext mail, unauthenticated Redis/memcached/MQTT, HTTP Basic over plain HTTP, exposed Docker API, public SNMP.
- Windows services: RDP without NLA, SMBv1, unsigned SMB, SMB without encryption, LDAP anonymous bind.
- Industrial ports reachable from the scanner (`ot-reachable`).
- PHP end of life, date-aware (table `PHP_EOL` in `risk.rs`; branches not in the table are never flagged).

## Evidence and confidence

Each finding states its evidence (what was observed) and a `confidence` from 0 to 100 that depends on how the rule decides: direct observation, banner text, port number only or a version-based hint. See [Evidence and confidence](detection.md#evidence-and-confidence).

## Reference links

Some findings carry an optional `reference`: a link to official documentation on the problem and how to fix it. Currently `smb1-enabled` and `smb-signing` (Microsoft Learn), `rdp-no-nla` (Microsoft Learn), `telnet-open` (CISA) and the weak-TLS rules `tls-sslv3`, `tls-deprecated-protocol`, `tls-broken-cipher`, `tls-3des`, `tls-no-pfs`, `tls-weak-signature` and `tls-weak-key` (Mozilla Server Side TLS). The link appears in the HTML report, in a `Reference` column of the Markdown summary, as `reference` in the JSON and JSONL exports (omitted when a finding has none) and in the Findings window. Only HTTPS links are shown. Exports written before this field existed still load.

## CVE hints

**CVE entries are version-based hints only.** Distributions backport fixes without changing the version string, so confirm with the vendor advisory or an authenticated check. Network Scope is not a vulnerability scanner.

The rules live in [`data/cves.json`](https://github.com/Sparkz400/network-scope/blob/main/data/cves.json) (built in). A user file merges like `probes.json`: `%LOCALAPPDATA%/NetworkScope/cves.json` (or `$XDG_CONFIG_HOME/NetworkScope/cves.json`, else `~/.config/NetworkScope/cves.json`), or `--cves FILE` on any command, or the **CVE rules file** field in the GUI Settings (with a Browse button; the path is kept with the preferences and, like `--cves FILE`, replaces the default user file). A rule or CPE entry with the same `id` replaces the built-in one. In the GUI the file is loaded at start-up and when the field is changed; if it cannot be read or parsed, the error is shown under the field and the previous rules stay active.

Rule fields:

| Field | Meaning |
| --- | --- |
| `id` | Rule id |
| `product` | Lower-case substring of the detected product (`svc.<port>.product` or the HTTP Server header name) |
| `exclude` | Optional product substrings the rule does not apply to |
| `min` / `max` | Optional inclusive / exclusive dotted versions with optional `pN` (`8.5p1`) |
| `severity` | info, low, medium, high, critical |
| `cve` | List of `CVE-YYYY-NNNN`; the finding id is `cve-<first cve>` |
| `title` | Finding title |

A broken file stops the command with a message naming the file and rule. A broken user file found at start-up is reported (CLI: stderr, desktop: error line) and the built-in rules are used.

## Known exploited and EPSS (offline feeds)

Findings that carry CVE ids can be enriched with two public data sets, so the list shows what is being exploited right now instead of only what is severe on paper:

- **CISA KEV**, the Known Exploited Vulnerabilities catalog: CVEs with evidence of exploitation in the wild.
- **FIRST EPSS**, the Exploit Prediction Scoring System: a daily probability (0 to 1) that a CVE is exploited in the next 30 days, with a percentile.

Network Scope never downloads them. You fetch the two files yourself, on a machine that is allowed to, and import them from disk:

```sh
curl -L -o kev.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
curl -L -o epss_scores-current.csv.gz https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
gunzip epss_scores-current.csv.gz        # the importer reads plain CSV only
network-scope-cli feeds import --kev kev.json --epss epss_scores-current.csv
network-scope-cli feeds status
```

Either option may be given alone; the part not imported keeps its previous content. Repeat the import to refresh (EPSS changes daily, KEV several times a week). A file that cannot be parsed is rejected and the cache stays as it was. Gzip is not read directly because the project avoids extra dependencies; the importer detects a `.gz` file and says so.

**Cache.** The import writes `feeds.json` next to the user `cves.json`: `%LOCALAPPDATA%/NetworkScope/feeds.json`, or `$XDG_CONFIG_HOME/NetworkScope/feeds.json`, else `~/.config/NetworkScope/feeds.json`; `--feeds FILE` selects another file for any command. It is a global lookup table, not part of a scan, so it is a file and not part of the SQLite inventory (`--db` is per inventory and would otherwise need one copy per database). It holds the KEV entries (date added, ransomware use) and about 300,000 EPSS scores kept with five decimals, roughly 10 MB. Saved scans are not modified: the data is looked up when findings are computed, so older scans also show current feed data.

**What changes.**

- `findings`, `export --format json` and the other JSON output gain the optional fields `kev`, `kev_added`, `kev_ransomware`, `epss` and `epss_percentile` (highest values over the finding's CVEs) on findings that match. Without an imported cache these fields are absent and the output is identical to before; exports written earlier still load.
- Findings are ranked by in KEV first, then severity, then EPSS, then host, port and id. Without a cache the order is the usual severity order. `findings ID --sort severity` restores the usual order even with feeds; `--sort exploited` is the default.
- The HTML report shows a "Known exploited" badge (with the date CISA added it and "Ransomware use" where KEV says so) and "EPSS NN %" next to the CVE links.

**Limits.** KEV and EPSS describe a CVE, not your host: a version-based hint that matches a known exploited CVE is still only a hint (see above). EPSS is a statistical estimate, not a prediction for one device. The desktop Findings window does not show these fields yet. The NVD import is described next.

Sources and terms: KEV is published by the US government (CISA); EPSS is published free of charge by the EPSS Special Interest Group at FIRST. See [data/README.md](https://github.com/Sparkz400/network-scope/blob/main/data/README.md). The EPSS download address was checked on FIRST's data page (`first.org/epss/data`) on 2026-11-19.

## Risk score and fix list

Every host and the whole network get a score from 0 to 100, and a list of the ten things to fix first.

**Points of one finding** = severity weight x known-exploited factor x EPSS factor x exposure factor x confidence.

| Factor | Value |
| --- | --- |
| Severity weight | critical 40, high 20, medium 8, low 3, info 1 |
| Known exploited (CISA KEV, needs imported feeds) | x 2.0; x 2.5 when KEV lists ransomware use |
| EPSS (needs imported feeds) | x (1 + EPSS), EPSS from 0 to 1 |
| Exposure: cleartext or unauthenticated remote access or administration (`telnet-open`, `ftp-cleartext`, `mail-cleartext`, `http-basic-cleartext`, `vnc-exposed`, `rdp-no-nla`, `smb1-enabled`, `redis-noauth`, `memcached-open`, `mqtt-anonymous`, `ldap-anonymous`, `docker-api`, `snmp-public`, `ot-reachable`, `ot-control-traffic`) | x 1.5 |
| Confidence of the rule (0 to 100, see [Evidence and confidence](detection.md#evidence-and-confidence)) | x confidence / 100, so a version-based hint (40) counts 40 % |

**Host score** = 100 x (1 - e^(-P/60)), P being the sum of the points of the host's findings. The curve saturates: one critical finding scores about 49, two about 74, a KEV-listed critical also about 74, and 100 is never exceeded. **Network score** = 0.7 x the worst host score + 0.3 x the mean of the ten highest host scores, so one very exposed host dominates but many exposed hosts rank above a single one. Bands: 0 none, 1-24 low, 25-49 medium, 50-74 high, 75-100 critical.

**Fix these first.** Findings with the same id on several hosts (the same CVE, the same weak setting) form one entry. Its *risk lowered* is the sum, over the affected hosts, of how far the host score drops when the entry is fixed there, computed for each entry alone against the current state. Entries are ranked by that number, then by severity and id, so a medium issue on 40 hosts can outrank one critical on a single host. Each entry shows the hosts, the severity, "known exploited" when a CVE is in KEV and the advice of the rule.

```sh
network-scope-cli findings 1 --top 10              # text: network score, riskiest hosts, fix list
network-scope-cli findings 1 --top 10 --format json
```

The HTML report shows the network score as a card, a "Fix these first" table and the riskiest hosts; the Markdown summary has a "Risk score and fix list" section; the JSONL export has `risk_score` per host. For programs, `network_scope_core::score::assess(&findings, 10)` returns the network score, the host scores and the fix list (`score::host_scores`, `score::network_score`, `score::top_fixes` and `score::finding_points` are public as well).

The score is a ranking aid for deciding what to do first, not a measure of how likely a compromise is. It inherits the limits of the findings: version-based hints count less but are still not confirmed. Without `--min-severity` the list includes info findings (weight 1).

## NVD import (offline)

The built-in rules in `data/cves.json` cover a handful of well-known products. For everything else you can import the NVD (National Vulnerability Database) CVE feed, and the scanner matches the CPE names it derives (`svc.<port>.cpe`) against it:

```sh
# nvdcve-2.0-2024.json and friends: the "CVE JSON 2.0" feed files, downloaded by you
gunzip nvdcve-2.0-2024.json.gz           # gzip is not read directly (no extra dependency)
network-scope-cli feeds import nvd nvdcve-2.0-2023.json nvdcve-2.0-2024.json
network-scope-cli feeds status
network-scope-cli findings 1
```

Network Scope never downloads the files. Files saved from the NVD API 2.0 (`/rest/json/cves/2.0`) have the same layout and import too. A `.gz` file is detected and refused with the `gunzip` hint. You can import several files in one call and repeat the import to refresh: a CVE that is imported again replaces the earlier entry, everything else is kept.

**Cache.** The import writes a compact index (`nvd.json`, next to `feeds.json`; `--nvd FILE` on any command selects another one), not the whole feed: for each CVE the rating (CVSS 4.0, 3.1, 3.0 or 2, the newest present; `info` when NVD has not rated it), a short title and its vulnerable CPE ranges. The file is read while parsing, so memory use does not grow with the size of the feed (an unpacked year file is a few hundred MB). The cache is loaded only when a scan has a CPE to look up. It is a file for the same reason as `feeds.json`: a global lookup table, not part of a scan or the SQLite inventory (no store migration is involved).

**What becomes a finding.** For every open port with a `svc.<port>.cpe`, each CVE whose vulnerable range contains the CPE's version becomes a finding `cve-cve-YYYY-NNNN` (see [Version-based CVE hint](findings/cve-hints.md)) with the NVD rating as its severity, the first sentence of the NVD description as its title and the matching range in the evidence ("8.5 <= v < 9.8"). KEV and EPSS data rank them like every CVE finding. At most 50 per port are listed, highest severity first. The NVD feed comes before the hand-written rules (see [Order of sources](#order-of-sources)): a CVE the feed raises on a port is not raised again by a rule of `data/cves.json`, which stays the fallback for what the feed does not know. Without an imported cache nothing changes.

**Matching is deliberately conservative:**

- only matches marked `vulnerable` count; a match without any version bound (all versions) or with the "not applicable" version `-` is ignored, because it would flag every host running the product;
- a configuration that combines the application with a platform (AND, for example "on this operating system or hardware") is not matched, since the scan cannot confirm the platform;
- versions are compared with their letter suffixes and patch levels (`1.0.1e` is older than `1.0.1f`, `9.6` older than `9.6p1`, `1.0rc1` older than `1.0`), start and end bounds may be inclusive or exclusive, and a CPE without a version with digits matches nothing;
- rejected CVEs and CVEs that name no usable product are dropped; only application (`a`) and operating-system (`o`) and hardware (`h`) CPEs are matched, and only for the products the scanner derives a CPE for (see below).

Like every version-based hint, a match is **not** a confirmed vulnerability: distributions backport fixes without changing the version string, and the product and vendor names of the derived CPEs were written from memory and not checked against the NVD dictionary (see CPE names). The fixture in `tests/fixtures/nvd-sample.json` was written by hand following the NVD 2.0 schema (two real CVE ids with paraphrased text, the rest synthetic `CVE-2099-*`); the importer has not been run on a full real NVD download in this project's tests. The feed parser is fuzzed (`nvd_import`).

NVD data is a work of the US government (NIST) and free to use; see [data/README.md](https://github.com/Sparkz400/network-scope/blob/main/data/README.md).

## CISA ICS advisories for OT devices (CSAF, offline)

Industrial devices are rarely in the NVD with usable version ranges, but CISA publishes its ICS advisories in the machine-readable CSAF 2.0 format (repository `cisagov/CSAF`). You download them and import them; the scanner matches the vendor, product and firmware that the S7, EtherNet/IP (CIP), Modbus and OPC UA identification already collected:

```sh
network-scope-cli feeds import csaf advisories/          # a folder of *.json, or single files
network-scope-cli scan 10.0.0.0/24 --ot --ports 102,502,4840,44818
network-scope-cli findings 12
```

`feeds import csaf` reads each file's `product_tree` (vendor, product family and name, version or `vers:` range, model numbers and SKUs from `product_identification_helper`, and `relationships`, see below) and its `vulnerabilities` (CVE, title, CVSS score per product, `product_status.known_affected`, the first remediation of each product), and keeps the result in a small cache (`csaf.json` next to `feeds.json`; `--csaf FILE` on any command selects another one). A file that is not a CSAF advisory is reported and skipped; a gzip file is refused with the `gunzip` hint; importing an advisory again replaces its earlier entries. `feeds status` shows what the cache holds. Network Scope never downloads the advisories.

**What becomes a finding.** A device whose vendor agrees with the advisory (when both are known), whose product name, order code or model number matches an advisory product, and whose firmware lies in the affected range, gets a finding `cve-cve-YYYY-NNNN` on the protocol's port (102, 502, 4840 or 44818). The severity is the advisory's CVSS rating, the evidence names the advisory, the affected range, the score and the vendor's remediation, and the advisory's own address is the finding's reference link. KEV and EPSS data rank these findings like every other CVE finding. A device without a firmware version (OPC UA discovery gives none; an S7, CIP or Modbus identification can also fail to read it) matches only advisories that list **all versions**: this is intended, because a bounded range such as "below V4.5.1" cannot be confirmed or excluded without a version, and flagging every unversioned device would drown real findings. A Siemens CPU is also known by its family (`CPU 1214C` is an S7-1200, `CPU 1511-1 PN` an S7-1500), because advisories name families rather than CPU models.

**Relationships.** An advisory often names the affected firmware only as a pair, for example "firmware below V4.5.1" `installed_on` "SIMATIC S7-1200 CPU", and lists the pair's own product id under `product_status`. The categories `default_component_of`, `installed_on`, `installed_with`, `optional_component_of` and `external_component_of` are followed: the pair gets the vendor of the platform (else of the component), the names, model numbers and SKUs of both, and the version (range) of the component, or of the platform when the component has none. A pair may be part of another pair (up to 8 levels). A pair whose parts the advisory does not define, a pair without any version information and a product id that nothing defines are skipped and counted at import.

**Limits.** Matching is by name: a hardware variant that an advisory does not tell apart can be reported although it is not affected, and a device that an advisory names only by a family this table does not know (for example by an order-number range) is missed. A product with no version information is skipped (importing counts these). Like every version-based hint, a match is **not** a confirmed vulnerability. The fixtures in `tests/fixtures/csaf/` were written by hand in the layout of the CISA advisories, with invented advisory ids and `CVE-2099-*` ids; the importer has not been run on the full CISA repository in this project's tests. The parser is fuzzed (`csaf_import`).

## Order of sources

For one port, or one industrial device, the sources are used in this order:

1. imported **CSAF advisories** (OT devices),
2. the imported **NVD feed** (ports with a CPE),
3. the hand-written rules in `data/cves.json` and your own `--cves` file, **only for the CVEs the feeds did not already raise there**.

The hand-written rules are therefore a fallback for what the feeds do not cover, not the main source. When an advisory or an NVD record names a CVE for the device, that is the finding you see (with the feed's severity, title and range); a hand-written rule for the same CVE is skipped, and a rule for another CVE still fires. Without imported feeds the rules are the only source, as before. A hand-written rule can also name an industrial device: its `product` text is matched against the device's names (order code, CPU or product name) and its `min`/`max` against the firmware.

## CPE names

`cpe` entries (`id`, exact lower-case `products`, `template` with `{version}`, `{base}`, `{update}`) produce `svc.<port>.cpe` such as `cpe:2.3:a:openbsd:openssh:7.4:p1:*:*:*:*:*:*`; distribution suffixes are dropped. The CPE vendor/product names were written from memory of the NVD dictionary and **have not been checked against it**; spot-check them before relying on them.

## Contributing rules

New CVE rules are welcome. Keep them version-based, cite the CVE ids, and add a test for the version boundaries. See [CONTRIBUTING.md](https://github.com/Sparkz400/network-scope/blob/main/CONTRIBUTING.md).
