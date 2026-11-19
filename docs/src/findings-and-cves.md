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

The rules live in [`data/cves.json`](https://github.com/Sparkz400/network-scope/blob/main/data/cves.json) (built in). A user file merges like `probes.json`: `%LOCALAPPDATA%/NetworkScope/cves.json` (or `$XDG_CONFIG_HOME/NetworkScope/cves.json`), or `--cves FILE` on any command, or the **CVE rules file** field in the GUI Settings (with a Browse button; the path is kept with the preferences and, like `--cves FILE`, replaces the default user file). A rule or CPE entry with the same `id` replaces the built-in one. In the GUI the file is loaded at start-up and when the field is changed; if it cannot be read or parsed, the error is shown under the field and the previous rules stay active.

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

**Cache.** The import writes `feeds.json` next to the user `cves.json`: `%LOCALAPPDATA%/NetworkScope/feeds.json`, or `$XDG_CONFIG_HOME/NetworkScope/feeds.json`; `--feeds FILE` selects another file for any command. It is a global lookup table, not part of a scan, so it is a file and not part of the SQLite inventory (`--db` is per inventory and would otherwise need one copy per database). It holds the KEV entries (date added, ransomware use) and about 300,000 EPSS scores kept with five decimals, roughly 10 MB. Saved scans are not modified: the data is looked up when findings are computed, so older scans also show current feed data.

**What changes.**

- `findings`, `export --format json` and the other JSON output gain the optional fields `kev`, `kev_added`, `kev_ransomware`, `epss` and `epss_percentile` (highest values over the finding's CVEs) on findings that match. Without an imported cache these fields are absent and the output is identical to before; exports written earlier still load.
- Findings are ranked by in KEV first, then severity, then EPSS, then host, port and id. Without a cache the order is the usual severity order. `findings ID --sort severity` restores the usual order even with feeds; `--sort exploited` is the default.
- The HTML report shows a "Known exploited" badge (with the date CISA added it and "Ransomware use" where KEV says so) and "EPSS NN %" next to the CVE links.

**Limits.** KEV and EPSS describe a CVE, not your host: a version-based hint that matches a known exploited CVE is still only a hint (see above). EPSS is a statistical estimate, not a prediction for one device. The desktop Findings window does not show these fields yet. The NVD import is described next.

Sources and terms: KEV is published by the US government (CISA); EPSS is published free of charge by the EPSS Special Interest Group at FIRST. See [data/README.md](https://github.com/Sparkz400/network-scope/blob/main/data/README.md). The EPSS download address was checked on FIRST's data page (`first.org/epss/data`) on 2026-11-19.

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

**What becomes a finding.** For every open port with a `svc.<port>.cpe`, each CVE whose vulnerable range contains the CPE's version becomes a finding `cve-cve-YYYY-NNNN` (see [Version-based CVE hint](findings/cve-hints.md)) with the NVD rating as its severity, the first sentence of the NVD description as its title and the matching range in the evidence ("8.5 <= v < 9.8"). KEV and EPSS data rank them like every CVE finding. At most 50 per port are listed, highest severity first. A CVE that a built-in rule already raised on the port is not repeated, and `data/cves.json` stays the fallback: without an imported cache nothing changes.

**Matching is deliberately conservative:**

- only matches marked `vulnerable` count; a match without any version bound (all versions) or with the "not applicable" version `-` is ignored, because it would flag every host running the product;
- a configuration that combines the application with a platform (AND, for example "on this operating system or hardware") is not matched, since the scan cannot confirm the platform;
- versions are compared with their letter suffixes and patch levels (`1.0.1e` is older than `1.0.1f`, `9.6` older than `9.6p1`, `1.0rc1` older than `1.0`), start and end bounds may be inclusive or exclusive, and a CPE without a version with digits matches nothing;
- rejected CVEs and CVEs that name no usable product are dropped; only application (`a`) and operating-system (`o`) and hardware (`h`) CPEs are matched, and only for the products the scanner derives a CPE for (see below).

Like every version-based hint, a match is **not** a confirmed vulnerability: distributions backport fixes without changing the version string, and the product and vendor names of the derived CPEs were written from memory and not checked against the NVD dictionary (see CPE names). The fixture in `tests/fixtures/nvd-sample.json` was written by hand following the NVD 2.0 schema (two real CVE ids with paraphrased text, the rest synthetic `CVE-2099-*`); the importer has not been run on a full real NVD download in this project's tests. The feed parser is fuzzed (`nvd_import`).

NVD data is a work of the US government (NIST) and free to use; see [data/README.md](https://github.com/Sparkz400/network-scope/blob/main/data/README.md).

## CPE names

`cpe` entries (`id`, exact lower-case `products`, `template` with `{version}`, `{base}`, `{update}`) produce `svc.<port>.cpe` such as `cpe:2.3:a:openbsd:openssh:7.4:p1:*:*:*:*:*:*`; distribution suffixes are dropped. The CPE vendor/product names were written from memory of the NVD dictionary and **have not been checked against it**; spot-check them before relying on them.

## Contributing rules

New CVE rules are welcome. Keep them version-based, cite the CVE ids, and add a test for the version boundaries. See [CONTRIBUTING.md](https://github.com/Sparkz400/network-scope/blob/main/CONTRIBUTING.md).
