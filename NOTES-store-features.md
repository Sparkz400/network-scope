# Store / report features: requests and notes

This change touched src/store.rs, src/devices.rs, src/nmap.rs and src/report.rs. It did not touch
src/topology.rs or src/main.rs, and there are no Cargo or schema changes (`SCHEMA_VERSION` is still 1).

## CLI wiring requests (src/ui.rs)

New option keys must be added to the option allowlist in `ui.rs` `options()`: `ignore` and `history`.
`history` is an option that takes a value.

### 1. `diff OLD_ID NEW_ID [--format lines|json|text] [--ignore K,K,...] [--db FILE]`
```rust
"diff" => {
    let ignore = store::IgnoreList::parse(opts.get("ignore").map(String::as_str).unwrap_or(""));
    let format = opts.get("format").map(String::as_str).unwrap_or("lines");
    output(&store::diff_output(&store::load(&db, id(0)?)?, &store::load(&db, id(1)?)?, format, &ignore)?, &opts)
}
```
- `lines` is the default and gives today's output unchanged: a JSON array of change lines.
- `json` gives the structured `DiffReport`:
  - `summary`: counts per category, plus `highest_new_severity`.
  - `changes`: each item is tagged by `kind`. The kinds are `host_added`, `host_silent`, `host_removed`, `port_opened`, `port_closed` (with `protocol` tcp or udp), `identity_added`, `identity_changed`, `identity_removed`, `attribute_changed`, `observation_new` and `observation_changed`.
  - `new_findings`, `resolved_findings` and `unconfirmed_findings`: full `risk::Finding` objects, matched by `Finding::key`.
  - `ignored_keys`: the patterns that were skipped.
- `text` gives the change lines, then `new finding: …`, `resolved finding: …` and `finding not re-checked …` lines, or `No changes.` when there is nothing.
- A finding counts as "resolved" only if the new scan looked at its evidence again:
  - its host answered;
  - for a TCP port, the ports were checked;
  - for a UDP port, the port was probed in both scans.

  A passive (port-less) finding on a silent host counts as resolved if the new snapshot has any observations. Anything else is "unconfirmed" and is never counted as resolved.
- `--ignore` is a comma-separated list that is added to the built-in volatile keys (`*.days_left`). Matching rules:
  - an exact key, for example `snmp.uptime`
  - a glob where `*` matches any run of characters, for example `http.*.title`
  - an entry starting with `.` is a suffix, for example `.server` means `*.server`
- Suggested HELP line: `network-scope diff OLD_ID NEW_ID [--format lines|json|text] [--ignore KEY,KEY]`

### 2. `devices --history MAC|IP [--format text|json] [--db FILE]`
```rust
// in "devices", before reading the scan ID:
if let Some(q) = opts.get("history") {
    let h = store::device_history(&db, q)?;
    return output(&devices::history_output(&h, opts.get("format").map(String::as_str).unwrap_or("text"))?, &opts);
}
```
- The MAC can be written as `AA:BB:..`, `aa-bb-..`, `aabb.cc..` or `aabbcc...`. An IPv4 or IPv6 address also works.
- GUI entry point: `store::device_history(path, query) -> Result<devices::DeviceHistory, String>`. Run it on the store worker thread, because it reads every scan row. Rows that cannot contain the address are skipped with a substring pre-filter before any JSON is parsed.
- `DeviceHistory` contains:
  - `first_seen`, `first_scan`, `last_seen`, `last_scan`
  - `sightings` and `scans`
  - `ips`, `macs`, `hostnames`
  - `open_tcp`: the open ports from the latest completed active scan that checked the device's ports
  - `events`, each with `scan_id`, `timestamp`, `kind` and `detail`. The kinds are `first-seen`, `ip-changed`, `mac-changed`, `hostname-changed`, `port-opened`, `port-closed`, `udp-answering` and `udp-silent`.
- `devices::history_text(&h)` gives the plain-text rendering.
- Rules:
  - Only sightings create events. A scan that does not mention the device produces no "not seen" event, because it may not have covered the address.
  - Port events are created only between **completed** active scans that checked the device's ports with the same TCP port set.
  - UDP is compared only for ports probed in both scans.
  - Passive captures count as sightings, through `devices::merge`.
- Suggested HELP line: `network-scope devices --history MAC|IP [--format text|json]   Timeline of one device across saved scans`

### 3. `--format md|jsonl` for `export`, `scan`, `listen`/`dcp`
- `store::export_at(&snapshot, format, timestamp)` accepts `json`, `csv`, `html`, `nmap`/`xml`, `md`/`markdown` and `jsonl`. `store::export(&snapshot, format)` is unchanged; it is `export_at(…, 0)`.
- `md`: a Markdown summary with the scope, totals, findings by severity, findings, findings by host, devices, and changes since a baseline when one is given. All cells are escaped. `report::markdown(snapshot, baseline, ts)` takes a baseline exactly like `report::html`, so `export ID --format md --baseline B` can reuse `report_html`'s baseline loading.
- `jsonl`: one compact JSON object per responding host. Fields: `timestamp`, `scope`, `complete`, `ip`, `mac`, `vendor`, `hostname`, `device_type`, `os`, `open_tcp`, `open_udp`, `services` (port, protocol, summary, product, version, cpe), `findings` (key, severity, id, title, port, evidence, cve), `identity` and `note`. Passive-only devices are not included; `devices ID --format json` covers those.
- In `ui.rs`, the scan format whitelist (`["json", "csv", "html", "nmap"]` at about line 509) must gain `"md"` and `"jsonl"`. The error text there should become "Choose json, csv, html, nmap, md or jsonl".
- In `export`, add `"md" | "markdown" => report::markdown(&snapshot, baseline, stamp)`. `baseline` currently exists only inside `report_html`, so factor the `--baseline` loading out of it first. Otherwise call `store::export_at(&snapshot, other, stamp)` so md/jsonl carry the stored time.
- md/jsonl already work today through `export ID --format md|jsonl` and `listen`/`dcp`, because they call `store::export` without a whitelist. Until the calls are switched to `export_at`, the time shows as "time not recorded" (0). Only `scan` rejects the new formats.
- Update the HELP text: `export ID --format json|csv|html|nmap|md|jsonl`, and `--format json|csv|html|nmap|md|jsonl` under scan options.

## Fix 6: `scan --format html|nmap` exported with timestamp 0 (cause fixed in store.rs; call-site change pending)
- **Cause (store.rs):** `store::export` hardcoded `0` for the html and nmap formats.
- **Fix in store.rs:** the new `store::export_at(snapshot, format, timestamp)`.
  - `export` keeps 0 on purpose. The GUI can export a historic snapshot that was opened from the inventory, and for that snapshot "time not recorded" is better than a made-up current time.
- **Call sites to change (not my files):**
  - `ui.rs` `scan` (about line 537): `output(&store::export_at(&snapshot, format, store::timestamp(&db, id)?)?, &opts)?;`
  - `ui.rs` `listen`/`dcp` (about line 590): the same, with the capture's `id`.
  - `ui.rs` `export` (`other => store::export(...)`): `store::export_at(&snapshot, other, stamp)`.
  - `gui/mod.rs:636` (`Scanner::export`):
    - for an inventory snapshot that was opened from the store, pass that scan's stored timestamp (`store::timestamp(path, id)`, or keep the timestamp from `Entry` when opening);
    - for live results, pass the current Unix time.

## Report (HTML) changes
- **Baseline section:** "Changes since …" keeps the change list. It now adds "New findings (n)" and "Resolved findings (n)" tables, plus "Findings not re-checked" when a host stopped answering. All of these come from `store::diff_report`.
- **Findings by host:** a new table under Findings with one row per host: highest severity, a count per severity and a total. It is pre-sorted by highest severity, then by counts from critical down, then by IP. Sorting happens at build time because the report has no scripts.
- **CPE column:** findings tables get a CPE column only when some host has an `svc.<port>.cpe` key. Markdown does the same.

## nmap interchange
- **Export:**
  - Product names from our identity keys are written in nmap spelling, for example `Microsoft-IIS` → `Microsoft IIS httpd`, `Apache` → `Apache httpd`, `vsFTPd` → `vsftpd`, `Exim` → `Exim smtpd`. The table is `nmap::PRODUCT_NAMES`.
  - `OpenSSH for Windows 8.1` is written as product `OpenSSH`, version `for_Windows_8.1`, which is how nmap writes it.
  - `svc.<port>.cpe` is written as `<service …><cpe>…</cpe></service>`, one element per space-separated value.
- **Import:**
  - nmap product names map back to ours, case-insensitively, in `svc.<port>.product` and `.version`, so the CVE rules fire on imports. Example: "Microsoft IIS httpd" 6.0 now raises CVE-2017-7269.
  - nmap's Windows OpenSSH no longer triggers regreSSHion, because `for_Windows_x` was previously parsed as a portable OpenSSH version.
  - The `svc.<port>` summary keeps nmap's wording, for example "http Apache httpd 2.4.49 (Unix)". The exception is files written by network-scope (`scanner="network-scope"`): there the summary uses our names, so export → import is lossless and diffs to empty.
  - `<cpe>` children of `<service>` go into `svc.<port>.cpe`. When there are several, they are joined with a single space; values containing whitespace are dropped.
- **Re-exporting an nmap import** writes nmap's product/version again, for example `OpenSSH` / `for_Windows_8.9`. Re-importing that file (`scanner="network-scope"`) gives the same product/version/cpe keys, but the `svc.<port>` summary changes to our wording (for example "Apache httpd" becomes "Apache").
- **Older imports:** imports stored before this change have `svc.<p>.product` in nmap spelling (for example `Apache httpd`). A fresh import of the same file stores `Apache`, so diffing an old import against a new one shows `identity_changed` for those keys once.
- **For the CPE agent:** please store `svc.<port>.cpe` in the same way (one or more CPE names separated by a space) so the report and nmap export treat both sources alike. Report, Markdown and JSONL show the value as it is.

## `allow(dead_code)` to remove once wired
- `store::IgnoreList::parse`: `diff --ignore`
- `store::diff_output`: `diff --format`
- `store::device_history`: `devices --history` and the GUI
- `devices::history_output`: `devices --history`

## README text (for the README owner)
- **Diff:** add `--format json` (structured report for CI and monitors, including new, resolved and unconfirmed findings) and `--ignore`, with the matching rules above. Volatile keys (`*.days_left`) are always ignored.
- **Exports:** add `md` (Markdown summary) and `jsonl` (one JSON object per responding host).
- **Report:** mention the findings-by-host table, the new/resolved findings tables in the baseline section, and the CPE column.
- **nmap:** document the product-name mapping in both directions, the CPE support and the Windows OpenSSH handling.
- **Devices:** add `devices --history MAC|IP` and the rules above, in particular that partial scans never produce port events.
