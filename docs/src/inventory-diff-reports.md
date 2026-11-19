# Inventory, diffs and reports

## Inventory

Every scan and passive capture is stored in a SQLite database, by default `%LOCALAPPDATA%\NetworkScope\inventory.sqlite` on Windows; `--db FILE` selects another. SQLite is bundled into the executable. Scan settings are recorded per snapshot; notes are retained in JSON/CSV exports. Completed, stopped and partial runs are stored and marked as such.

`network-scope history` lists the saved snapshots as JSON.

## Diff

```sh
network-scope-cli diff OLD NEW [--format lines|json|text] [--ignore K,K]
```

- `lines` (default) is a JSON array of change lines.
- `json` is a structured report for CI and monitors: a summary with `highest_new_severity`, changes tagged by `kind`, new/resolved/unconfirmed findings, ignored keys.
- `text` is plain lines.

A finding counts as **resolved** only if the new scan looked at its evidence again (host answered; TCP ports checked; UDP port probed in both); otherwise it is **unconfirmed**.

`--ignore` adds exact keys, globs (`http.*.title`) or suffixes (`.server`) to the always-ignored volatile keys `*.days_left`, `*.clock_skew`, `*.boot_time`, `*.confidence` and `*.evidence` (the reasons and scores behind OS and device-type guesses; a changed guess itself is still reported).

Comparisons are meaningful only between completed scans with matching scope and settings. A timeout never proves that a device is offline.

## Device history

`devices --history MAC|IP [--format text|json]` gives the timeline of one device across all saved scans and captures: first/last seen, addresses, MACs, names, the open ports of the latest completed scan, and events (`first-seen`, `ip-changed`, `mac-changed`, `hostname-changed`, `port-opened`, `port-closed`, `udp-answering`, `udp-silent`).

- Only sightings create events: a scan that does not mention the device produces no "not seen" event.
- Port events come only from **completed** active scans that checked the device's ports with the same TCP port set; UDP is compared only for ports probed in both; SMB-only names are not compared.

## Reports

```sh
network-scope-cli report ID [--baseline ID] --output report.html
```

One self-contained HTML file with summary cards (including the network risk score), a "Fix these first" table with the riskiest hosts (see [Risk score and fix list](findings-and-cves.md#risk-score-and-fix-list)), SVG charts, findings with NVD links, a findings-by-host table (highest severity, count per severity), a CPE column when any host has a CPE, changes since a baseline ("New findings", "Resolved findings" and "Findings not re-checked"), a network map from traceroute data, a device table, per-host details and passive observations.

The report contains no scripts, sets a restrictive Content-Security-Policy, and HTML-escapes every scanned string. Captured metadata is treated as untrusted input.

`export ID --format html` produces the same report.

## Exports

| Format | Content |
| --- | --- |
| `json` | Full snapshot |
| `csv` | One row per host. CSV cells that start with `=`, `+`, `-`, `@`, TAB or CR get a leading `'` (CSV injection); purely numeric cells such as `-1` are unchanged |
| `md` | Markdown summary: scope, totals, findings, findings by host, devices, changes since `--baseline` |
| `jsonl` | One JSON object per responding host (passive-only devices: use `devices ID --format json`) |
| `html` | The HTML report |
| `nmap` | nmap-compatible XML |
| `compliance-iec62443`, `compliance-nis2`, `compliance-cis` | Asset inventory with findings mapped to controls, as Markdown; add `-csv` (`compliance-nis2-csv`) for CSV. See [Compliance exports](#compliance-exports) |

Exports carry the real scan time: the stored time for saved or reopened scans, the current time for live GUI results.

## Compliance exports

```sh
network-scope-cli export 3 --format compliance-iec62443 --output iec62443.md
network-scope-cli export 3 --format compliance-nis2-csv --output nis2.csv
network-scope-cli export 3 --format compliance-cis --output cis.md
```

Each export is the asset inventory of the scan (one row per device: addresses, MAC, vendor, type, OS, open ports, risk score) with the findings of every asset mapped to the controls of one framework:

- **`compliance-iec62443`**: IEC 62443 foundational requirements FR 1 to FR 7. Each asset also gets a **zone** and a **criticality**: zone `OT / control` for industrial controllers and assets with an industrial protocol port (or observed control traffic), `Network infrastructure`, `Peripherals and IoT` (printers, cameras, phones, embedded) or `IT systems`; criticality High for controllers and network infrastructure, Medium for database and storage servers and for other assets with industrial ports, Low otherwise, `Unclassified` when the device type is unknown. These are defaults from the asset's role; replace them with your own zone model.
- **`compliance-nis2`**: the measures of NIS2 Article 21(2), points (a) to (j).
- **`compliance-cis`**: CIS Controls v8 safeguards (1.1 inventory, 1.2 unauthorized assets, 1.3 and 1.5 discovery, 2.1, 3.10, 4.1, 4.7, 4.8, 7.1 to 7.7, 12.2 and 12.6). The export itself is the evidence for 1.1; 1.2 needs a comparison with an approved baseline (`diff --baseline`).

The Markdown version has the inventory, a coverage table (findings and assets per control; a control with no findings is not proof of compliance), what the scan evidences, the findings per control and the findings without a mapping. The CSV version has one row per asset and finding (assets without findings once) with the control ids in a `controls` column; user-script findings have no mapping and say `not mapped`. CSV cells are protected against formula injection like the other CSV exports.

**The mapping is this project's judgment, not an official crosswalk.** [`data/compliance.json`](https://github.com/Sparkz400/network-scope/blob/main/data/compliance.json) holds the table (control identifiers and short titles only; no text of the standards). The identifiers and titles were written from memory of the published documents and have not been compared with the licensed IEC text, the NIS2 text or the CIS workbook, so check them before using an export as audit evidence. Every finding rule id must have an entry (a test fails otherwise). A scan sees only what is reachable from the scanner, CVE findings are version-based hints, and an export is an aid for preparing an assessment: it is not a compliance assessment and not a certification.

## nmap XML interchange

- `export ID --format nmap` writes nmap XML (`scanner="network-scope"`), with product names in nmap spelling (`Microsoft-IIS` → `Microsoft IIS httpd`, `Apache` → `Apache httpd`, …; `OpenSSH for Windows 8.1` → product `OpenSSH`, version `for_Windows_8.1`) and `svc.<port>.cpe` as `<cpe>` elements.
- `import FILE.xml` reads nmap XML (up to 256 MB) into the inventory as a normal scan and maps product names back, so the CVE rules fire on imports and Windows OpenSSH does not look like a vulnerable portable OpenSSH. `<cpe>` children become `svc.<port>.cpe`.
- The `svc.<port>` summary keeps the imported wording except for files written by Network Scope, so export → import is lossless.
- Imports stored by 0.4 have the original spellings in `svc.<port>.product`, so a diff against a new import shows those keys once.
- Down hosts and non-open ports are not imported.

Network Scope only reads and writes the documented XML format; it is not a drop-in replacement for nmap and contains no nmap code or data.
