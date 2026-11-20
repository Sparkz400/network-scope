# Third-party notices

Network Scope is an original, independent Rust application, licensed under the MIT license ([LICENSE.txt](LICENSE.txt)). Protocol parsers and UI integration are independently implemented. This file lists the third-party libraries it links and the data it embeds.

## Rust crates (direct dependencies)

Licenses as declared by each crate's metadata for the versions in `Cargo.lock` (`cargo metadata`). Each crate pulls in further transitive dependencies; `Cargo.lock` records the exact set and versions. A complete transitive license report can be generated with a tool such as `cargo about` or `cargo license`.

| Crate | Used for | License |
| --- | --- | --- |
| eframe, egui_extras | Desktop GUI | MIT OR Apache-2.0 |
| accesskit and its platform adapters (via eframe's `accesskit` feature) | Screen reader integration of the desktop GUI | Apache-2.0 OR MIT |
| winit (macOS only) | Windowing | Apache-2.0 |
| image | PNG encoding (screenshot mode) | MIT OR Apache-2.0 |
| rfd | File dialogs | MIT |
| ratatui | Terminal UI | MIT |
| crossterm | Terminal I/O | MIT |
| tokio | Async runtime | MIT |
| socket2 | Raw and datagram sockets, socket options | MIT OR Apache-2.0 |
| dns-lookup | Reverse DNS | MIT OR Apache-2.0 |
| pnet_packet | Packet construction and parsing | MIT OR Apache-2.0 |
| libloading | Run-time loading of Npcap/libpcap | ISC |
| rustls | TLS handshakes | Apache-2.0 OR ISC OR MIT |
| tokio-rustls | Async TLS | MIT OR Apache-2.0 |
| rustls-platform-verifier | HTTPS webhook certificates verified by the OS store | MIT OR Apache-2.0 |
| ring (via rustls) | Cryptographic primitives | Apache-2.0 AND ISC |
| x509-parser | Certificate parsing | MIT OR Apache-2.0 |
| rusqlite | SQLite inventory | MIT |
| SQLite (bundled via libsqlite3-sys) | Database engine | Public domain |
| serde, serde_json | Serialization | MIT OR Apache-2.0 |
| regex | Probe match rules | MIT OR Apache-2.0 |
| roxmltree | nmap XML import | MIT OR Apache-2.0 |
| rhai | Scripting | MIT OR Apache-2.0 |
| rcgen (tests only) | Test certificates | MIT OR Apache-2.0 |

## Notable transitive components

- **Fonts embedded in the desktop app** by egui (`epaint_default_fonts`): Ubuntu Light (Ubuntu Font Licence 1.0), Hack (MIT; derived from Bitstream Vera, Bitstream Vera License), Noto Emoji (SIL Open Font License 1.1) and emoji-icon-font (MIT). The font files are compiled into the executable unmodified.
- **smartstring** (pulled in by Rhai) is licensed MPL-2.0. It is used unmodified; its source is available on [crates.io](https://crates.io/crates/smartstring).

`deny.toml` lists every license allowed in the dependency tree; `cargo deny check licenses` verifies it.

## Operating system components and optional drivers

- Windows ICMP, ARP and routing functions are provided by the operating system.
- [Npcap](https://npcap.com/) (Windows) and libpcap (Linux/macOS) are optional, installed separately under their own licenses, and loaded at run time. They are not bundled or redistributed.

## Embedded data

See [data/README.md](data/README.md) for provenance and licensing details.

- `data/oui.tsv`: derived from the IEEE Registration Authority MA-L, MA-M and MA-S public registries (standards-oui.ieee.org, retrieved 2026-11-16). © IEEE.
- `data/cip_vendors.tsv`: ODVA CIP vendor ID → vendor name list, extracted from the vendor table in Wireshark's `epan/dissectors/packet-cip.c` (Wireshark is GPL-2.0-or-later). Only the vendor ID/name pairs are used; no Wireshark code is included. See the note in data/README.md.
- `data/probes.json`, `data/cves.json`: original to Network Scope.

## Test captures

`tests/fixtures/ics/` holds public industrial-protocol packet captures (Modbus/TCP, S7comm, EtherNet/IP, IEC 60870-5-104, DNP3, BACnet, OPC UA, Profinet and others) used only as test input and fuzz seeds; they are not part of the application binary. They come unmodified from [ITI/ICS-Security-Tools](https://github.com/ITI/ICS-Security-Tools) (`pcaps/`, commit `bcb93ee1cdf395a457cc08f639cf29aab5975f01`), licensed [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/). Attribution, per-file upstream paths and SHA-256 checksums are in [tests/fixtures/ics/PROVENANCE.md](tests/fixtures/ics/PROVENANCE.md).

## Trademarks

nmap is a trademark of its owners; Network Scope reads and writes the documented nmap XML format and contains no nmap code or data. Modbus, PROFINET, EtherNet/IP, CIP, BACnet, OPC UA and other protocol and product names are trademarks of their respective owners and are used only to describe interoperability.

- JARM structure (`core/src/jarm.rs`): the ten-probe design and the hash composition follow the public description of JARM, https://github.com/salesforce/jarm, Copyright (c) 2020, salesforce.com, inc., BSD-3-Clause. No JARM source code is included; the cipher table and extension bodies are original to Network Scope and not verified against the reference.

## Protocol references

[OPC UA mappings](https://reference.opcfoundation.org/specs/OPC-10000-6/full), [Modbus specification](https://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf), [Npcap API](https://npcap.com/guide/wpcap/pcap.html). The lab simulators are original code.
