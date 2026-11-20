# GUI guide

The desktop app (`network-scope.exe`, or either binary started without arguments) runs the same engine as the CLI.

## Overview: what changed

The first view is the **Overview** (switch with **Overview** and **Hosts** under the scan controls). It reads the saved inventory in the background and shows:

- **What changed** between the newest completed scan and the scan before it (**Since the last scan**), or between the newest scan and the state 24 hours or 7 days ago (**Last 24 hours**, **Last 7 days**): new, gone and changed devices, new and resolved risks. A device that moved to another address counts as changed, not as gone plus new, and a risk counts as resolved only when the newer scan looked at it again; see [What changed](inventory-diff-reports.md#what-changed).
- The **network risk score** (0 to 100) and the five things to **fix first** (the same list as `findings`; a fix that helps several hosts is one entry, ranked by how much it lowers the host scores). A **KEV** badge marks a fix with a CVE that is known to be exploited.
- With an [approved baseline](inventory-diff-reports.md#approved-baseline): how many devices are **not on the baseline**.

Every device and risk is a link; a click opens that host's details. When the host is not in the results on screen, the scan it belongs to is opened first (not while a scan or capture is running). **Learn more** next to a fix opens the documentation page of that finding in the browser. Until the first scan the overview shows an empty state with a **Scan my network** button.

## Scanning

Enter an IP, an IPv4 range, a CIDR block, or comma/space-separated addresses, then **Start**. Nothing scans automatically. After a scan the status line shows how many packets it sent; hover it for the breakdown by packet kind (the same log is saved with the scan). If the targets include public addresses, or addresses outside the scope declared in `scope.txt` (see the [scope guard](cli-reference.md#scope-guard)), a dialog asks for confirmation first; Cancel sends nothing. The desktop accepts up to 65,536 addresses per scan.

### Scan my network

**Scan my network** (Overview, Scan menu, command palette) finds the networks this computer is connected to and scans them in Safe Mode with one click. The addresses and prefix lengths of the interfaces are read from the operating system (`ip -4 -o addr` on Linux, `ifconfig` on macOS, `Get-NetIPAddress` in PowerShell or `route print` on Windows); nothing is sent to the network for that. A network is scanned when it is

- a **private** (RFC 1918) network, and
- no larger than a /22 (1,022 hosts), and
- not loopback, link-local (169.254.x.x), a single address or point-to-point link (/31, /32; what VPN clients add), and not an interface whose name looks like a VPN, container or virtual machine adapter (docker, vmnet, tun, wg, vEthernet, ...).

A larger private network (a /16 has 65,534 hosts) is listed in a dialog and scanned only after you tick it. The networks left out are listed under **Left out** with the reason. The scan then starts through the normal Start path, so the scope guard applies; the Safe Mode setting is switched on for it, all other settings stay as they are.

### Presets

The **Preset** picker next to the TCP ports field applies a named bundle of settings; the CLI has the same bundles as `--preset` (see [Presets](cli-reference.md#presets)). Hover a preset to see what it turns on.

| Preset | Traffic | What it turns on |
| --- | --- | --- |
| Quick | active, Safe Mode | Ping and TCP connect to 80, 443 and 8080; nothing else (the defaults) |
| Office | active, Safe Mode | Common office and server ports, service identification, OS / manufacturer / device-type guess, MAC lookup; no UDP, OT or traceroute |
| Plant (passive) | **no packets** | Nothing is scanned: it opens the passive capture window (Listen (OT), pcap files). **Start** explains this until you choose another preset |
| Full audit | active, Safe Mode **off** | Everything the engine can do: up to 256 hosts at a time, ports 1-1024 plus the 100 most common, services, UDP, OS, read-only OT identification, JARM, ICMP traceroute, DNS names and MACs, the SYN engine and ARP sweep when an interface is set. The scope guard and the automatic back-off still apply |

The picker shows **Custom** as soon as a setting differs from every preset. Interface, source addresses, script and probe file are never changed by a preset. The **Standard** button is the same as Quick.

### Targets from a file, random order

**Scan → Import address list…** reads a text file into the Addresses field (one entry per line or separated by spaces or commas; `#` and `;` start a comment). The CLI has `scan --targets-file FILE`. **Probe the addresses in random order** in Settings (CLI: `scan --randomize`) changes only the order in which the addresses are probed, not which addresses or probes.

**Record the scan's traffic** in Settings (CLI: `scan --record FILE --record-wire`) writes a pcapng file per scan to `NetworkScope/recordings/scan-<unix time>.pcapng`, next to the preferences. When the capture driver allows it (Npcap on Windows, libpcap elsewhere) and there are at most 256 targets, it is a wire capture of the targets while the scan runs; otherwise, or when the capture saw no frame, it is the scan's own application-level record (its requests and replies, labelled as not a wire capture). The status line says which one was written and why. Recording sends nothing extra. See [Reproducible scans](reproducible-scans.md).

### Settings and controls

- **Settings** enables ARP discovery, industrial identification, services/UDP/OS detection, traceroute and the opt-in transmitting features (ARP sweep, adaptive SYN, trace method and port; these are greyed out in Safe Mode).
- **Check for updates on start** in Settings (off by default) asks GitHub once, in the background, when the program starts. If a newer release exists the status bar shows *Version X is available* (a link to the release page), *How to verify…* (the checksum, `gh attestation verify` and `slsa-verifier` commands, with a copy button) and *Dismiss*. It never downloads or installs anything; see [Checking for updates](installation.md#checking-for-updates).
- **CVE rules file** in Settings (type a path or **Browse…**; **Clear** returns to the default rules) merges your own CVE/CPE rules over the built-in ones, like `--cves FILE`; see [Findings and CVE hints](findings-and-cves.md). It is saved with the other preferences and loaded when you leave the field, press Enter or pick a file. A file that fails to parse is reported under the field and the previous rules stay in use; findings on screen are recomputed with new rules.
- **Use industrial ports** selects the relevant TCP ports for OT identification. To find ICMP-silent TCP services, also enable scanning of nonresponders.
- **Scheduled scans** (Settings, bottom): scan given targets every N minutes (5 to 10,080) while the window is open. Off by default; always Safe Mode; saved to the inventory. For monitoring with the window closed, see [Service and scheduling](service-and-scheduling.md).
- **Safe Mode** is on by default; see [Safe Mode and OT safety](safe-mode-and-ot-safety.md). The status bar at the bottom shows the current profile: a green **Safe Mode** badge (at most 8 hosts at a time, at least 100 ms between probes; no SYN, ARP sweep or TCP/UDP traceroute) or an amber **Fast** badge whose tooltip lists the enabled opt-in features (SYN, ARP sweep, rate cap). It follows the setting immediately, and a click opens Settings.
- **Fast** selects async TCP discovery with up to 1,024 hosts at once; Settings allows up to 4,096. These are concurrency limits, not benchmark results.
- **Pause** lets in-flight hosts finish; **Stop** aborts asynchronous work and keeps hosts that had already finished (an already issued native request can still finish later).
- The **Standard** preset and **Restore defaults** keep interface, source IPv4/MAC, script path and probe file.

Click a host for its identity fields, probe errors and notes. Notes are stored with the host (empty notes are not stored). Preferences are saved about a second after a change.

**Scan → Clear results and captures** clears active results and passive observations from the window; the saved inventory is untouched. Starting a scan does not clear passive observations and starting a capture does not clear scan results, so the Devices window merges both.

## Host actions, favorites and Wake-on-LAN

Right-click a host in the table, or use **Actions** in its details window (the keyboard way to the same menu):

- **Add to favorites / Remove from favorites**: a star in front of the address; the **Starred** filter and **Favorites → Show starred devices** list them. Stars are kept in the preferences file, not in the inventory, and follow the device by its MAC address (by its IP address when it has none).
- **Open in browser** (`http://` or `https://` for the web ports found open), **Open SSH** (`ssh://`, needs port 22), **Open remote desktop** (`mstsc` on Windows, the `rdp://` handler elsewhere; needs port 3389) and **Ping in a terminal**. The entries for ports that were not found open are greyed out.
- **Wake-on-LAN…**: a dialog with the MAC address and the destination (the broadcast address of the host's network when known, else 255.255.255.255); only **Send** sends one magic packet. See [Wake-on-LAN](cli-reference.md#wake-on-lan): it goes through the rate gate with the packet kind `wake-on-lan`, public destinations are refused and the scope guard checks a directed broadcast address.
- **Copy IP address**, **Copy MAC address**.

Programs are started without a shell: the command line is a program name plus a list of arguments, and the host is only used when it is an IP address or a plain host name (letters, digits, `-`, `_` and dots; never starting with `-`). Anything else is refused.

## Command palette and search

`Ctrl+K` (`Cmd+K` on macOS), or **Commands** in the menu bar, opens the command palette. Type a few letters of an action ("new scan", "settings", "export", "map", "dark", "full", a language) and it lists the fuzzy matches; Up and Down choose, Enter runs, Escape closes. The text is also searched in **all saved scans** (about a quarter of a second after you stop typing): an IP address, MAC address (or vendor prefix such as `00:0c:29`), host name, vendor, device type or finding id. Each hit shows who was seen, in which scan and when, newest first; choosing one opens that scan and the host. This is the same search as the CLI `search QUERY` command; see [Search across all scans](cli-reference.md#search-across-all-scans).

## Inventory

**Inventory** reopens SQLite snapshots, selects baseline A and scan B for a comparison, and exports JSON, CSV, HTML or a Markdown summary. Completed and stopped scans are stored separately. Comparisons require completed scans with matching scope and settings; a timeout never proves that a device is offline.

The **Scan details** section at the bottom of the window says where the scan on screen came from (a saved scan with its number, or one not saved yet), whether it finished, and its provenance stamp: the tool version and the hashes of the rules and feeds the scan ran with, with a **Copy** button for the line to cite (tool and combined hash). Scans started in the window are stamped when they start, like scans from the CLI; a scan opened from the inventory shows the stamp it was saved with, or says it has none. See [Reproducible scans](reproducible-scans.md).

Exports are written in the background; the status line shows "Saved FILE" or the error. Exports of a reopened snapshot carry its stored scan time; exports of live results carry the current time.

## Findings and Devices

**Findings** and **Devices** sort by column header (click again to reverse) and filter by severity (Devices: highest finding, *Risk* column) and text. Clicking a row selects and opens that host in the main table. See [Findings and CVE hints](findings-and-cves.md).

With imported feeds (`feeds import`, see [Findings and CVE hints](findings-and-cves.md)) the Findings table has a **KEV** column (the CVE is in the CISA catalog of vulnerabilities exploited in the wild; *ransomware* when the catalog lists ransomware use) and an **EPSS** column (the estimated probability of exploitation in the next 30 days). Both sort (KEV first, then ransomware use; EPSS highest first) and filter (**Known exploited (KEV) only**, **EPSS 1 % / 10 % / 50 % or more**); typing `kev` or `ransomware` in the filter box works too. The app reads the default feeds cache (`feeds.json` in the `NetworkScope` folder under `%LOCALAPPDATA%`, the file `feeds import` writes) when it first needs it; without a cache the two columns stay empty. The last column has **Learn more** (the documentation page of the finding, [published here](findings/index.md)) and, where the rule has one, **Reference** (the vendor or standard document). Every link in the app opens in your default browser, through the operating system's opener (`rundll32 url.dll,FileProtocolHandler` on Windows, `open` on macOS, `xdg-open` elsewhere); only web, `ssh://` and `rdp://` links with a plain host are passed on. The opener was run for a real documentation link on Windows (2026-11-20): `rundll32.exe url.dll,FileProtocolHandler https://sparkz400.github.io/network-scope/findings/telnet-open.html` was started and the default browser (Firefox, already running) showed the page in a new tab; `file:`, `javascript:`, links with spaces and plain program names were refused without starting anything (`cargo test --lib live_link_opener -- --ignored` repeats this by hand). The app is built without eframe's own link support, which needs an extra crate, so links did nothing before this opener was added.

## Unknown devices

**Devices → Unknown devices…** (or `Ctrl+K`, "unknown-device workbench") is the desktop face of `fingerprints groups`, `compare` and `draft` (see [Contributing fingerprints](contributing-fingerprints.md#the-workbench-group-compare-draft)). It reads every saved scan on the background worker and lists the groups of similar banners that no rule identified, with the hosts, distinct banners and ports of each. A click on a group shows its variants (hosts, banner text, version numbers) and what differs between them. **Compare with** puts a second group beside it row by row and says how alike their commonest banners are (the Jaccard index the grouping uses, against its 0.6 threshold). **Draft a probe rule** builds the rule and the pull request checklist (or says why it refuses: banners that differ from the start would claim unrelated services); **Save probe file…** asks for a name and writes `FILE` (a complete probe file) and `FILE.checklist.md`, exactly as `fingerprints draft --output` does. The window reads the local inventory only and sends nothing; the banners in the files are the texts the store kept, so read and redact them before sharing. The draft, the checklist and the differences are produced by the engine and stay English.

## Network map

**Network map** (the menu bar) draws the path map from traceroute data (enable traceroute in Settings) as a graph: the scanner in the middle, the routers it found on the way and the hosts behind them. Drag to move the map, scroll or pinch to zoom, **Fit to window** shows all of it, and a click on a host opens its details. Dots are coloured by device type (controller / HMI, network device, server / storage, workstation, printer, camera, other; the legend is above the map) and a small dot in the corner of a node is the colour of the worst finding of that host. Nodes and text keep their pixel size when you zoom, at most 60 labels are drawn (the most important first: selected node, scanner, hosts with a high finding, routers) and none that would overlap another; hover a node for its details. With no hosts the map says so; with hundreds of hosts it stays usable (300 hosts were checked). **Show the devices as a list** below the map offers the same hosts as a list, which is also the way to reach them with the keyboard. The positions come from a layered ring layout relaxed by a force pass (`netmap::layout`, plain Rust, no extra crates). Links that other discovery features add to the topology (for example LLDP or SNMP neighbours) are drawn without changes, because the map only reads the node and link lists of `topology::Graph`.

## Passive / DCP

Select an Ethernet interface and a capture duration (needs Npcap/libpcap). Passive capture sends no discovery packets and decodes mDNS, SSDP/UPnP, LLDP, NetBIOS, DHCP and ARP. The separate **DCP Identify** button sends one read-only Profinet multicast request; it never assigns IPs or changes a device. MAC-keyed observations retain devices that advertise no IP.

Capture visibility depends on the network interface, multicast delivery and switch mirroring; it does not expose all traffic on a switched LAN. Observations are bounded to 10,000; a full capture queue or the cap marks the capture partial and collection continues with what still fits.

## OT passive asset discovery

The same window has an OT passive section:

- **Open pcap…** reads a capture file on a worker thread with a progress bar (percent, frames/s) and **Cancel**.
- **Listen (OT)** listens receive-only on the selected interface for the chosen number of seconds (disabled while another capture or a scan runs); **Stop** ends it early.
- Cancelled or stopped runs are marked partial.
- The asset table lists address, vendor, product, firmware, serial, protocols, roles, first/last seen and control traffic; rows with observed control traffic are red.
- **Export assets CSV/JSON** writes the `ot-assets` formats.
- Each finished OT capture is saved to the inventory like `ot-listen`; closing the window saves a running one as partial, and reopening a saved `ot-passive:` capture refills the asset table.

See [OT / industrial](ot-industrial.md).

## Device timeline

**Host details → Timeline…** opens the timeline of that device from the saved scans: when it was first seen, when its address, MAC or name changed, which ports opened or closed, and which findings appeared or were resolved, newest first, with a summary (first and last sighting, addresses, MACs, names, open ports). The device is looked up by its MAC address when it has one (so the history follows it across address changes), otherwise by its IP address. The data comes from the same function as `devices --history` (see [Device history](inventory-diff-reports.md#device-history)) and is read in the background. **Refresh** reads it again, **Copy as text** copies the text form. Nothing is shown for a scan that did not mention the device.

## Scripts

**Host details → Test script…** dry-runs the configured or a chosen `.rhai` file on a copy of the host; **Apply** adds the result to the host in the window only. See [Scripting](scripting.md).

## Languages

The app is available in English and German. **Settings → Appearance and language → Language** chooses Automatic (the language of the operating system; German when it is German, else English), English or Deutsch, and applies at once. The environment variable `NETWORK_SCOPE_LANG` (`en` or `de`) overrides the system language, for example for screenshots.

Text in the code is English and goes through a lookup keyed by that English text; a text without a translation shows in English, so a missing entry never breaks anything. The German catalog is the plain file `src/gui/lang/de.txt` (`English text || Deutscher Text`, one per line); a test fails when a text in the interface has no entry, when an entry appears twice, or when the placeholders of the two sides differ. Adding a language is a new catalog file and one entry in `i18n.rs`.

Coverage: the main window, the menus and the scan controls, the Settings window, the Overview, Scan my network, the network map, the host menu and Wake-on-LAN, the command palette, the host details, the Findings, Devices and Inventory windows, the confirmation dialogs, the update notice and the scheduled-scan section are translated: 522 catalog entries, which now include the OT passive section, the device timeline window, the Scan details section and the unknown-device workbench (the test checks every text of those files). The text the engine itself produces (finding titles, advice, evidence, protocol fields, the CLI) is not translated.

## Accessibility

- **Keyboard only.** Tab and Shift+Tab move through every button, checkbox, text field, menu and table header; Space or Enter activates, the arrow keys move in menus and the palette. `Ctrl+K` opens the command palette from anywhere, which reaches every window and action without the mouse. The right-click menu of a host is also the **Actions** button of its details window, and the network map has a list of the same hosts below it. Table rows are selectable with the keyboard through their address cell.
- **Visible focus.** The widget with keyboard focus is drawn with a 2 pixel outline and the "active" colours, in the light and the dark theme.
- **Screen readers.** The app is built with eframe's `accesskit` feature, so egui publishes the widget tree (names, roles, values) through the platform accessibility API (UI Automation on Windows, AT-SPI on Linux, NSAccessibility on macOS). Text fields and the number fields of the settings are labelled by their visible label or hint text; the colour badges (KEV, severity, score band) are also written out as words. The tree was read back through Windows UI Automation (`System.Windows.Automation` from PowerShell, 2026-11-20, a Windows 11 build of this program with the Overview, Settings, Inventory, Findings, Devices, unknown-device workbench, Passive / DCP, About and command palette windows open): the menu buttons, the text boxes, checkboxes, number fields, combo boxes, the slider and the toggle buttons appear with their roles and names. That check found text boxes, number fields and combo boxes without a name (the hint text of a box is only its "placeholder" and the suffix of a number field became its name); they are named now and unit tests build the tree and fail for an unnamed control. Two kinds of elements still have no name because they come from egui itself: the title bar of every window (a focusable "custom" element used to drag the window) and the column resize handles of the tables. The app has **not been tried with a screen reader** (NVDA, Narrator, Orca, VoiceOver), only read through the UI Automation API; if something is read wrongly, please open an issue. The feature adds about 60 crates to `Cargo.lock` (the AccessKit adapters and, for Linux, the `zbus` D-Bus stack and the Windows `windows` bindings); `cargo deny check` reports no problem for them in its advisories, licenses and sources checks; its bans check fails with "wildcard dependency" for the workspace's own path dependency, exactly as it did before this change.
- **High DPI and scaling.** The window follows the scale factor of the operating system, per monitor. **Settings → Interface scale** (0.75 to 2.0, also `Ctrl` and `+` / `-`) enlarges the interface on top of that.
- **Colours.** **Settings → Theme** switches between the light and the dark theme; the colours of severities, risks and the map are chosen for both. Information is never only a colour: severities and the score band are also words, and favorites are a star.

## Screenshot mode

`network-scope --screenshot FILE.png` renders the window to a PNG without scanning or touching preferences or the inventory. `NETWORK_SCOPE_SCREENSHOT_STATE=main|findings|devices|ot|script|timeline|scan-details|workbench|workbench-compare|workbench-draft|settings|home|home-empty|map|map-large|quick|palette|wake` renders a larger window with sample data in that view (append `-small` for the default 800x450 size, `-fast` for Safe Mode off, `-dark` for the dark theme and `-de` for German, in any order, e.g. `main-small-fast` or `home-dark-de`). Screenshots are in English unless the state ends in `-de`. This is used for the documentation images.
