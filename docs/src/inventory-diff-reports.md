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

`--ignore` adds exact keys, globs (`http.*.title`) or suffixes (`.server`) to the always-ignored volatile keys `*.days_left`, `*.clock_skew` and `*.boot_time`.

Comparisons are meaningful only between completed scans with matching scope and settings. A timeout never proves that a device is offline.

## Device history

`devices --history MAC|IP [--format text|json]` gives the timeline of one device across all saved scans and captures: first/last seen, addresses, MACs, names, the open ports of the latest completed scan, and events (`first-seen`, `ip-changed`, `mac-changed`, `hostname-changed`, `port-opened`, `port-closed`, `udp-answering`, `udp-silent`).

- Only sightings create events: a scan that does not mention the device produces no "not seen" event.
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
network-scope-cli baseline set DEVICE [--owner TEXT] [--tag a,b] [--untag a,b] [--criticality low|medium|high|critical|none] [--expected yes|no]
network-scope-cli baseline show [--format text|json]
network-scope-cli baseline remove DEVICE
network-scope-cli baseline clear
```

A baseline is the list of devices you expect on the network, with an owner, a criticality and tags for each. `baseline approve` takes the devices of a completed scan (the newest one, or `SCAN_ID`) as the expected devices; it records them in the inventory like `monitor` does and only ever adds, so approving again after a scan found a new device approves that one too and keeps what you described for the others. `approve` is also what starts the baseline: until one is approved, nothing is checked.

`baseline set` describes one device. `DEVICE` is a device key (as shown by `devices ID`), a MAC address in any notation, an IP address (the device that held it last) or a host name; if a name or MAC matches several devices, use the key. `--tag` adds tags, `--untag` removes them (comma-separated; at most 20 tags, 40 characters each), `--owner ""` clears the owner, `--criticality none` clears the criticality. `--expected no` keeps the description but takes the device off the expected list.

Entries are keyed by the stable [device key](device-identity.md), so a device keeps its place on the baseline when it changes address or randomised MAC address. The baseline is stored in the inventory database (schema version 4).

Once a baseline exists, `monitor` raises an [`unknown-device` alert](monitoring-alerts.md#alert-kinds) (Medium) for every device that is not on the expected list. This does not depend on `--learn` or on the first run, because the baseline is what you declared, not what was seen. `baseline clear` deletes the baseline and with it the alert.

## Reports

```sh
network-scope-cli report ID [--baseline ID] --output report.html
```

One self-contained HTML file with summary cards, SVG charts, findings with NVD links, a findings-by-host table (highest severity, count per severity), a CPE column when any host has a CPE, changes since a baseline ("New findings", "Resolved findings" and "Findings not re-checked"), a network map from traceroute data, a device table, per-host details and passive observations.

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

Exports carry the real scan time: the stored time for saved or reopened scans, the current time for live GUI results.

## nmap XML interchange

- `export ID --format nmap` writes nmap XML (`scanner="network-scope"`), with product names in nmap spelling (`Microsoft-IIS` → `Microsoft IIS httpd`, `Apache` → `Apache httpd`, …; `OpenSSH for Windows 8.1` → product `OpenSSH`, version `for_Windows_8.1`) and `svc.<port>.cpe` as `<cpe>` elements.
- `import FILE.xml` reads nmap XML (up to 256 MB) into the inventory as a normal scan and maps product names back, so the CVE rules fire on imports and Windows OpenSSH does not look like a vulnerable portable OpenSSH. `<cpe>` children become `svc.<port>.cpe`.
- The `svc.<port>` summary keeps the imported wording except for files written by Network Scope, so export → import is lossless.
- Imports stored by 0.4 have the original spellings in `svc.<port>.product`, so a diff against a new import shows those keys once.
- Down hosts and non-open ports are not imported.

Network Scope only reads and writes the documented XML format; it is not a drop-in replacement for nmap and contains no nmap code or data.
