# Quick start

Read [Responsible use](responsible-use.md) first: only scan networks you are authorized to scan.

## Desktop

1. Start `network-scope.exe` (or `network-scope` / `cargo run --release`).
2. Enter an IP, an IPv4 range (`192.168.1.10-50`), a CIDR block (`192.168.1.0/24`) or several comma/space-separated addresses.
3. Press **Start**. Nothing scans automatically.
4. Click a host for its identity, probe errors and notes. Open **Findings** and **Inventory** in the sidebar on the left (or `Ctrl+4`, `Ctrl+7`), and **By device** on the Hosts page (`Ctrl+3`) for one row per device; the host details stay docked on the right. `F1` lists all keyboard shortcuts.

See the [GUI guide](gui-guide.md).

## Command line

On Windows use `network-scope-cli` for the command line. Everything below works the same with `network-scope` on Linux and macOS.

```sh
# Discover a /24 and identify services, OS and UDP services, with the live terminal view
network-scope-cli scan 192.168.1.0/24 --deep --tui

# Industrial identification on standard OT ports, saved as JSON as well
network-scope-cli scan 192.168.1.10 --arp --ot --output inventory.json

# What was saved, and what changed between scan 1 and scan 2
network-scope-cli history
network-scope-cli diff 1 2 --format text

# Findings and an HTML report against a baseline
network-scope-cli findings 2 --min-severity medium
network-scope-cli report 2 --baseline 1 --output report.html

# Passive OT asset discovery from a capture file (sends nothing)
network-scope-cli ot-listen --pcap plant.pcapng --progress
network-scope-cli ot-assets 3 --format csv --output assets.csv
```

Every scan is stored in the inventory database (`%LOCALAPPDATA%\NetworkScope\inventory.sqlite` on Windows; `--db FILE` selects another). The numbers in `diff 1 2` are the snapshot IDs printed by `history`.

## Faster scans

Safe Mode (the default) keeps traffic gentle: at most eight hosts at a time and at least 100 ms between application probes. On networks without fragile equipment, `--fast` lifts those limits:

```sh
network-scope-cli scan 10.0.0.0/22 --fast --tcp-only --workers 1024 --ports 22,80,443,445
```

With Npcap/libpcap installed, SYN scanning is available too; see [Installation](installation.md#privileges) and the [Scanning engine](scanning-engine.md).

## Next steps

- [CLI reference](cli-reference.md): every command and option
- [Monitoring and alerts](monitoring-alerts.md): scheduled scans with alerts
- [OT / industrial](ot-industrial.md): identification and passive discovery
