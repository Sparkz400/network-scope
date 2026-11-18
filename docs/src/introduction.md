# Introduction

Network Scope is a portable network discovery and inventory tool written in Rust. One code base provides three front ends:

- an **egui desktop app** (`network-scope.exe` on Windows),
- a **scriptable CLI** (`network-scope-cli.exe` on Windows, a console-subsystem build of the same program),
- a **ratatui live terminal view** (`scan --tui`).

It finds the hosts on a network, identifies their services, TLS and SMB configuration, operating system family, manufacturer and device type, derives risk findings and version-based CVE hints, and stores every run in a local SQLite inventory. Snapshots can be compared, exported (HTML, Markdown, JSON, JSON Lines, CSV, nmap XML) and monitored over time with alerts.

Network Scope has a strong focus on **industrial (OT) networks**: Modbus/TCP, S7, EtherNet/IP, BACnet/IP and OPC UA devices are identified with read-only requests only, and a passive mode reads pcap/pcapng files or a live interface to build an OT asset inventory without transmitting anything. **Safe Mode** is enabled by default.

Normal TCP connect scans work without administrator rights or Npcap.

## What it is not

- It is **not a vulnerability scanner**. CVE entries are hints derived from version strings; distributions backport fixes without changing versions.
- It is **not a drop-in replacement** for other scanners. It reads and writes nmap XML for interchange only.
- It does not exploit, authenticate, write to devices or change device configuration.

## Status

Version 0.5. The [changelog](changelog.md) lists what changed and, importantly, what has **not** been tested. In short: everything that needs Npcap/libpcap on a real interface (SYN, ARP sweep, TCP traceroute, live capture, DCP) has only been tested against a fake wire, the OT decoders only against synthetic frames, and no live production network was scanned during development.

## Where to go next

- [Installation](installation.md) and [Quick start](quick-start.md)
- [Responsible use](responsible-use.md) and [Safe Mode and OT safety](safe-mode-and-ot-safety.md), before scanning anything you do not own
- [CLI reference](cli-reference.md) for every command and option
