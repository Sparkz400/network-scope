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

`devices --history MAC|IP [--format text|json]` gives the timeline of one device across all saved scans and captures: first/last seen, addresses, MACs, names, the open ports of the latest completed scan, and events (`first-seen`, `ip-changed`, `mac-changed`, `hostname-changed`, `port-opened`, `port-closed`, `udp-answering`, `udp-silent`, `finding-appeared`, `finding-resolved`).

- Only sightings create events: a scan that does not mention the device produces no "not seen" event.
- A finding appears or is resolved only between scans that both checked its port (the same TCP port list, or a UDP port probed in both); findings are matched without their address, so a device that moved keeps its findings.
- Port events come only from **completed** active scans that checked the device's ports with the same TCP port set; UDP is compared only for ports probed in both; SMB-only names are not compared.

## What changed

```sh
network-scope-cli changes [--since last|12h|7d|2w|2026-11-01|2026-11-01T08:30] [--format text|json]
```

`changes` answers "what is different now?" in one list: **new devices**, devices **not observed** any more, **changed devices** (address, MAC, host name, ports opened or closed, service details) and **new** and **resolved risks**. It compares the newest completed scan with

- the completed scan before it (`--since last`, the default), or
- the state at the start of a window (`12h`, `7d`, `2w`) or at a UTC date or time: the newest comparable scan taken at or before it.

It works on devices, not addresses (see [Device identity](device-identity.md)): a device that moved to another address or randomised MAC is *changed*, not "gone" plus "new". When a [baseline](#approved-baseline) exists, new devices that are not on it are marked, and the number of devices not on the baseline is reported.

Only comparable scans are compared: the same targets and the same detection settings, as for `diff`. If the newest comparable partner is not the previous scan, an older one is used; if there is none, the answer is empty and a `notice` says why (no scans yet, only one scan, only partial scans, settings differ, or nothing was scanned inside the window). A window that starts before the oldest scan compares with the oldest scan and says so. These cases are answers, not errors.

Two cautions are built in. A device that is not observed is not proof that it is offline. A risk that disappeared counts as **resolved** only when the newer scan checked its evidence again (the host answered and the port was probed); otherwise it is listed as *not checked again*. A device known only from passive traffic is not called gone by a scan that captured nothing.

`--format json` prints the `Changes` structure of the core library (`network_scope_core::changes::changes(db, &Since::Last, now)`), which the desktop app uses for its home screen: `summary` (counts), `current` and `previous` scans, `new_devices`, `gone_devices`, `changed_devices` (with the list of changes), `new_risks`, `resolved_risks`, `unconfirmed_risks`, `unknown_devices` and `notice`.

## Approved baseline

```sh
network-scope-cli baseline approve [SCAN_ID]
network-scope-cli baseline enable
network-scope-cli baseline set DEVICE [--owner TEXT] [--tag a,b] [--untag a,b] [--criticality low|medium|high|critical|none] [--expected yes|no]
network-scope-cli baseline show [--format text|json]
network-scope-cli baseline remove DEVICE
network-scope-cli baseline clear
```

A baseline is the list of devices you expect on the network, with an owner, a criticality and tags for each. `baseline approve` takes the devices of a completed scan (the newest one, or `SCAN_ID`) as the expected devices; it records them in the inventory like `monitor` does and only ever adds, so approving again after a scan found a new device approves that one too and keeps what you described for the others. `approve` is also what starts the baseline: until one is approved, nothing is checked. A list of expected devices that was [imported](import-export.md) starts it with `baseline enable` (it needs at least one expected device).

`baseline set` describes one device. `DEVICE` is a device key (as shown by `devices ID`), a MAC address in any notation, an IP address (the device that held it last) or a host name; if a name or MAC matches several devices, use the key. `--tag` adds tags, `--untag` removes them (comma-separated; at most 20 tags, 40 characters each), `--owner ""` clears the owner, `--criticality none` clears the criticality. `--expected no` keeps the description but takes the device off the expected list.

Entries are keyed by the stable [device key](device-identity.md), so a device keeps its place on the baseline when it changes address or randomised MAC address. The baseline is stored in the inventory database (schema version 4).

Once a baseline exists, `monitor` raises an [`unknown-device` alert](monitoring-alerts.md#alert-kinds) (Medium) for every device that is not on the expected list. This does not depend on `--learn` or on the first run, because the baseline is what you declared, not what was seen. `baseline clear` deletes the baseline and with it the alert.

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
| `cyclonedx` | CycloneDX 1.6 JSON: the devices, the firmware they reported and their services, with known CVEs. See [CycloneDX inventory](#cyclonedx-inventory) |
| `compliance-iec62443`, `compliance-nis2`, `compliance-cis` | Asset inventory with findings mapped to controls, as Markdown; add `-csv` (`compliance-nis2-csv`) for CSV. See [Compliance exports](#compliance-exports) |

Exports carry the real scan time: the stored time for saved or reopened scans, the current time for live GUI results.

## CycloneDX inventory

```sh
network-scope-cli export 3 --format cyclonedx --output network.cdx.json
```

In the desktop: **File → Export → CycloneDX inventory (all devices)…**, which exports every result and observation, not only the visible rows.

The file is a [CycloneDX](https://cyclonedx.org/) 1.6 document for tools that read bills of materials, such as OWASP Dependency-Track. **On its own it is an inventory of what the network shows, not a software bill of materials of what is inside each device.** A scan sees what a device announces about itself; the libraries in its firmware image (a Linux kernel, OpenSSL, BusyBox) only come from the vendor's own SBOM or from analysing the image. Import those SBOMs ([Firmware SBOMs](#firmware-sboms)) and the export nests them under the firmware they describe, which makes it a full SBOM for those devices.

| CycloneDX | From |
| --- | --- |
| A `device` component per device | The merged devices of the scan (one per MAC, or per address without one): addresses, MAC, host names, device type and its evidence, the OS guess, open ports and the sources, as `network-scope:*` properties. The manufacturer comes from the industrial identification or LLDP-MED when there is one, else from the MAC address (OUI), and `network-scope:manufacturer-source` says which. |
| A `firmware` component inside it | Only what the device reported: S7 (order code, firmware), Modbus device identification, EtherNet/IP and OPC UA identity, passive industrial traffic, and the LLDP-MED firmware and software revision. |
| An `application` component inside it | A service whose banner or handshake named its product (OpenSSH 7.4 on port 22), with the CPE name when the CVE table knows the product. An open port that named nothing stays a property of the device. |
| `dependencies` | The switch each device hangs off, from the LLDP neighbour tables read over SNMP (the links of the network map): the device `dependsOn` the switch, and the device gets `network-scope:connected-to` with the switch's address and port. Of the two ends of a link the uplink is the network gear (switch, router, access point by device type), else the end with more links; a link the rules cannot orient (two equal ends) or to a neighbour that is not a device of the scan gives no dependency. Without SNMP LLDP data there is no `dependencies` section. |
| `vulnerabilities` | One entry per CVE of the findings. A version-based finding points at the component whose product or CPE it matched (the service, or the firmware an industrial identification reported); a CVE from a probe or a setting (Heartbleed, SMBv1, BlueKeep) points at the device, so no product is blamed for a CVE that is not about its version. `network-scope:found-on` lists the address and port (the first 100; `network-scope:found-on-total` gives the count when there are more). With an imported vendor statement (VEX) the entry has an `analysis` (state, justification, detail), and devices with and without a statement are separate entries. The rating is the finding's severity with method `other`, not a CVSS score; version-based hints carry their confidence (`network-scope:confidence`) and can be false positives where a vendor backported a fix. KEV and EPSS appear when the feeds are imported. Findings without a CVE (Telnet open, a self-signed certificate) are not in this file; see the other exports. |

Every value carries its source (`network-scope:source`: `S7 identification`, `LLDP-MED firmware revision`, `service banner`, ...). The serial number is derived from the scan's content and time, so exporting the same saved scan twice gives the same file (a desktop export of live results is stamped with the current time). The OS guess is a property, not an `operating-system` component, because it is inferred from fingerprints and not reported. Up to 1,000 devices the file is indented for reading; above that it is written compact (a scan of 65,536 hosts gives about 86 MB instead of 180 MB; see [Lab and testing](lab-and-testing.md#large-cyclonedx-export)).

The file holds what the inventory holds: addresses, MAC addresses, host names and serial numbers. Treat it like the inventory before sharing it.

CI checks the export of a sample network (firmware, services, CVEs) and of an imported nmap scan against the official CycloneDX 1.6 schema with `cyclonedx-cli`. Not tried: importing the file into Dependency-Track or another BOM tool.

### Upload to Dependency-Track

```sh
export DTRACK_KEY=odt_...      # an API key with BOM_UPLOAD (and PROJECT_CREATION_UPLOAD to create the project)
network-scope-cli export 3 --format cyclonedx --push https://dtrack.example --token-env DTRACK_KEY --dt-project "Plant A" --dt-version 2026-11
```

`--push` uploads the document to [OWASP Dependency-Track](https://dependencytrack.org/) (`POST /api/v1/bom`, a multipart form with `projectName`, `projectVersion`, `autoCreate=true` and the BOM) instead of printing it; `--output FILE` writes it as well. The project defaults to `Network Scope` and the version to the scan's targets; uploading again to the same name and version replaces that project's BOM, so one version per site or network keeps a current picture. The API key comes from the environment variable named by `--token-env` and is sent only in the `X-Api-Key` header, only over `https://` (plain `http://` to localhost only), never in the URL. The form fields are those of Dependency-Track's `BomResource` (`POST /api/v1/bom`, read in its source); not tried against a real server yet, a test checks the request against a local listener.

### Firmware SBOMs

```sh
# A vendor's SBOM that names its product and version
network-scope-cli feeds import sbom vendor-sboms/
# An SBOM made from a firmware image names the image or its file system: say what it is.
# Unpack the image first (for example with unblob or binwalk), then e.g. Syft on the root file system:
syft dir:rootfs -o spdx-json > fw.spdx.json
network-scope-cli feeds import sbom fw.spdx.json --sbom-vendor Siemens --sbom-product "6ES7 214-1AG40-0XB0" --sbom-version V4.2.1
network-scope-cli feeds status    # "sboms": what the cache holds
```

`feeds import sbom` reads CycloneDX JSON (1.2 to 1.7) and SPDX JSON (2.2, 2.3) files, or the `.json` files of a folder, into `sboms.json` next to `feeds.json` (`--sboms FILE` picks another). Each SBOM describes one product version: the CycloneDX `metadata.component` or the package an SPDX document `DESCRIBES`, overridden by `--sbom-vendor`, `--sbom-product` and `--sbom-version` (they describe one file and are refused for a folder). A file without a product name or version is skipped and the import says which option it needs. Importing the same vendor, product and version again replaces the earlier SBOM. Nothing is fetched: you download or generate the files yourself.

When the CycloneDX export finds a firmware a device reported (S7, Modbus, EtherNet/IP, OPC UA, passive industrial traffic, LLDP-MED), it looks for an SBOM with **the same version** (`V4.2.1` is `4.2.1`), **a matching name** (letters and digits only, at least 5 characters, one containing the other; Siemens CPUs also by their family, so `CPU 1214C` matches an SBOM for `S7-1200`) and **the same vendor** when both name one. A matching SBOM's components are nested inside the firmware component, with their versions, package URLs, CPE names, suppliers and licences (single files are left out and counted in `network-scope:sbom-files-left-out`: Syft lists every file of an image, which would repeat under each device on that firmware); the firmware says which SBOM it was (`network-scope:sbom`, its SHA-256 and format). With the NVD feed imported (`feeds import nvd`), every nested component with a CPE name is looked up there, and its CVEs become vulnerabilities pointing at that library (rule `sbom-cve-...`, a version-based hint: the vendor may have backported the fix).

With the NVD feed, the same CPE is looked up once however many devices run that firmware; more than 200,000 CVE links in one document are counted in `network-scope:sbom-cves-not-linked` instead of written. CVEs of SBOM components get KEV and EPSS data from the imported feeds like every other finding. In the desktop, **File → Import firmware SBOMs…** imports files that name their own product and version (use the command line for `--sbom-product` and the other options); the next export uses them without a restart. The document's `network-scope:scope` says how many firmware components got an SBOM.

Tried on a real image: Syft 1.57.2 on the root file system of OpenWrt 25.12.6 (x86-64) gives 179 packages and 890 files, as CycloneDX 1.7 and as SPDX 2.3; both import (`--sbom-vendor OpenWrt --sbom-product OpenWrt --sbom-version 25.12.6`), nest under a device that announces that firmware over LLDP-MED, and the export passes the CycloneDX 1.6 schema ([Lab and testing](lab-and-testing.md#real-public-files)). Not tried: an SBOM published by a device vendor, and the output of Trivy or EMBA.

Limits: matching is by name, so an SBOM for a product name the device does not report (an order code against a marketing name) is not found; pass the name the device reports with `--sbom-product` (see the device's firmware component in the export). An SBOM is kept up to 20,000 components; files up to 64 MB.

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
