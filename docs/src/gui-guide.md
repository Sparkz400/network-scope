# GUI guide

The desktop app (`network-scope.exe`, or either binary started without arguments) runs the same engine as the CLI.

## Scanning

Enter an IP, an IPv4 range, a CIDR block, or comma/space-separated addresses, then **Start**. Nothing scans automatically. The desktop accepts up to 65,536 addresses per scan.

- **Settings** enables ARP discovery, industrial identification, services/UDP/OS detection, traceroute and the opt-in transmitting features (ARP sweep, adaptive SYN, trace method and port; these are greyed out in Safe Mode).
- **CVE rules file** in Settings (type a path or **Browse…**; **Clear** returns to the default rules) merges your own CVE/CPE rules over the built-in ones, like `--cves FILE`; see [Findings and CVE hints](findings-and-cves.md). It is saved with the other preferences and loaded when you leave the field, press Enter or pick a file. A file that fails to parse is reported under the field and the previous rules stay in use; findings on screen are recomputed with new rules.
- **Use industrial ports** selects the relevant TCP ports for OT identification. To find ICMP-silent TCP services, also enable scanning of nonresponders.
- **Safe Mode** is on by default; see [Safe Mode and OT safety](safe-mode-and-ot-safety.md). The status bar at the bottom shows the current profile: a green **Safe Mode** badge (at most 8 hosts at a time, at least 100 ms between probes; no SYN, ARP sweep or TCP/UDP traceroute) or an amber **Fast** badge whose tooltip lists the enabled opt-in features (SYN, ARP sweep, rate cap). It follows the setting immediately, and a click opens Settings.
- **Fast** selects async TCP discovery with up to 1,024 hosts at once; Settings allows up to 4,096. These are concurrency limits, not benchmark results.
- **Pause** lets in-flight hosts finish; **Stop** aborts asynchronous work and keeps hosts that had already finished (an already issued native request can still finish later).
- The **Standard** preset and **Restore defaults** keep interface, source IPv4/MAC, script path and probe file.

Click a host for its identity fields, probe errors and notes. Notes are stored with the host (empty notes are not stored). Preferences are saved about a second after a change.

**Scan → Clear results and captures** clears active results and passive observations from the window; the saved inventory is untouched. Starting a scan does not clear passive observations and starting a capture does not clear scan results, so the Devices window merges both.

## Inventory

**Inventory** reopens SQLite snapshots, selects baseline A and scan B for a comparison, and exports JSON, CSV, HTML or a Markdown summary. Completed and stopped scans are stored separately. Comparisons require completed scans with matching scope and settings; a timeout never proves that a device is offline.

Exports are written in the background; the status line shows "Saved FILE" or the error. Exports of a reopened snapshot carry its stored scan time; exports of live results carry the current time.

## Findings and Devices

**Findings** and **Devices** sort by column header (click again to reverse) and filter by severity (Devices: highest finding, *Risk* column) and text. Clicking a row selects and opens that host in the main table. See [Findings and CVE hints](findings-and-cves.md).

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

## Topology

The **Topology** window draws the merged path map from traceroute data (enable traceroute in Settings).

## Screenshot mode

`network-scope --screenshot FILE.png` renders the window to a PNG without scanning or touching preferences or the inventory. `NETWORK_SCOPE_SCREENSHOT_STATE=main|findings|devices|ot|script|timeline` renders a larger window with sample data in that view (append `-small` for the default 800x450 size, then `-fast` for Safe Mode off, e.g. `main-small-fast`). This is used for the documentation images.
