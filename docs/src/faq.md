# FAQ and troubleshooting

## Do I need administrator rights or Npcap?

No, not for normal use. TCP connect scanning, service detection, ICMP/ARP through the OS, UDP probes, inventory, reports, monitoring and pcap file analysis all work without them. SYN scanning, the ARP sweep, TCP traceroute, live capture and DCP need Npcap (Windows) or libpcap plus capture rights; UDP traceroute needs administrator/root. See [Installation](installation.md#privileges).

## The shell does not wait for `network-scope.exe` and `$LASTEXITCODE` is wrong

`network-scope.exe` is a GUI-subsystem program. Use `network-scope-cli.exe` for scripts: it is a console build of the same program. If you must use the GUI binary, run it with `Start-Process -Wait -NoNewWindow` or pipe it to `Out-Host`.

## Windows SmartScreen warns about the download

The binaries and installer are not code-signed. Verify the file against `SHA256SUMS` from the release page.

## "SYN unavailable; TCP connect fallback: …" in the host notes

The SYN engine could not be used: Npcap/libpcap missing, no capture rights, wrong `--interface`/`--source-ip`/`--source-mac`, a silent gateway, or the route leaves through another interface. The scan continued with TCP connect. Check `network-scope-cli interfaces` and make sure the source values belong to that interface. SYN is never used in Safe Mode; add `--fast`.

## "ARP sweep unavailable; per-host lookup: …"

Same causes as above, or the target is routed or IPv6. The ARP sweep only works for on-link IPv4 targets.

## The scan is slow

Safe Mode is on by default (8 hosts, 100 ms between application probes). On networks without fragile equipment use `--fast`. Silent, firewalled addresses are limited by `--timeout` and `--retries`; lower them if appropriate.

## A host I know is up is reported as not responding

A timeout never proves a device is offline. The host may drop ICMP and have none of the scanned ports open. Every CLI scan also checks the ports of nonresponders; add more `--ports` or `--top-ports`, or `--arp` / `--arp-sweep` on the local network. On Linux a STALE neighbor entry does not count as proof that a host is up.

## A device is missing from the OT results

OT identification only runs on standard ports of hosts that answered something. In the desktop, enable **Use industrial ports** and scanning of nonresponders. A device that answers only BACnet/IP is not found. Passive discovery only sees the traffic that reaches your interface; use a SPAN/mirror port or tap.

## A CVE finding is wrong; the host is patched

CVE entries are version-based hints. Distributions backport fixes without changing version strings. Confirm with the vendor advisory or an authenticated check. A user `cves.json` entry with the same `id` replaces the built-in rule, for example with a narrower version range or an `exclude` list.

## The diff shows changes I do not care about

Use `--ignore` with exact keys, globs (`http.*.title`) or suffixes (`.server`). `*.days_left`, `*.clock_skew` and `*.boot_time` are always ignored.

## My webhook uses HTTPS

HTTPS webhooks are not supported (no CA store is bundled). Use an http:// relay on localhost.

## Where are my settings and the database?

`%LOCALAPPDATA%\NetworkScope` on Windows: preferences, `inventory.sqlite`, and optional user `probes.json` / `cves.json`.

## Reporting a bug

Open an issue with the bug report template. Redact IP addresses, MAC addresses and host names from logs and screenshots. Security issues go through private vulnerability reporting, see [SECURITY.md](https://github.com/Sparkz400/network-scope/blob/main/SECURITY.md).
