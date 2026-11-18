# Safe Mode and OT safety

## Safe Mode

**Safe Mode is enabled by default** in the desktop and on the CLI. `--fast` (or unchecking Safe Mode) turns it off.

| | Safe Mode (default) | `--fast` |
| --- | --- | --- |
| Active hosts at once | at most 8 | `--workers` (default 1024, max 4096) |
| Spacing between application probes | at least 100 ms (token bucket) | none, unless `--rate PPS` |
| Port probes per host in parallel | at most 4 | `--parallel` (default 64) |
| SYN scan, ARP sweep | disabled | opt-in |
| Traceroute | ICMP only | ICMP, TCP, UDP |
| SMB NTLM SESSION_SETUP | not sent | sent (no AUTHENTICATE) |
| TLS 1.3 suite enumeration | not sent | sent |
| OT operations | identification only | identification only |

In the desktop the disabled controls are greyed out. Safe Mode is a conservative traffic profile, **not a guarantee** for every PLC.

## Rules that always apply

These hold with Safe Mode on or off:

- All OT protocol operations are **read-only identification**: no writes, no program or block access, no control commands, no authentication. See [OT / industrial](ot-industrial.md) for exactly what is sent.
- OT identification runs only on standard ports. TCP probes go only to hosts with that port open; a silent host gets at most one BACnet Who-Is, and only when nonresponders are scanned.
- Generic service probes never touch industrial ports (102, 502, 4840, 44818, 47808 and similar).
- Printer ports 9100-9107 and 515 only get a passive banner wait; nothing is ever sent.
- 2222/tcp is listen-only unless it greets with SSH.
- The UDP scan never sends to industrial or printer ports; such ports in `--udp-ports` are skipped with a host note and probes listing them are rejected.
- TCP traceroute never uses OT or printer ports.
- Passive modes (`listen`, `ot-listen`, pcap import) send nothing. A test fails the build if the passive modules contain socket or send code.
- Nothing scans automatically; every scan starts with an explicit Start or command.

## Recommendations for plant networks

- Read-only traffic can still affect fragile equipment. Older controllers, serial gateways and devices with small TCP stacks may slow down, drop connections or fault under any active traffic.
- **Prefer passive discovery** (`ot-listen` on a SPAN port or an existing capture) on production OT networks.
- Coordinate with operations before an active scan, scan during a maintenance window, and start with a small target range.
- Keep Safe Mode on. Do not use `--fast`, `--syn` or `--arp-sweep` against control networks.
- Know how to stop: Stop in the desktop, or Q/Escape in the TUI, saves what was collected.

See also [Responsible use](responsible-use.md).
