# Credits

Network Scope is an original, independent Rust application. Third-party libraries and data sources it uses are listed below.

Direct libraries: eframe and egui_extras (MIT OR Apache-2.0), image (MIT OR Apache-2.0), serde and serde_json (MIT OR Apache-2.0), rfd (MIT), and dns-lookup (MIT OR Apache-2.0). Cargo.lock records the dependency versions. Windows ICMP and ARP functions are provided by the operating system.

Added libraries: Tokio (MIT), rusqlite (MIT; bundled SQLite is public domain), ratatui (MIT), crossterm (MIT), libloading (ISC), and pnet_packet (MIT OR Apache-2.0). Npcap is an optional separately installed driver under its own license and is not bundled. Protocol parsers and UI integration are independently implemented; protocol references are linked in README.md.

Detection data and libraries: data/oui.tsv is derived from the IEEE Registration Authority MA-L, MA-M and MA-S public registries (standards-oui.ieee.org, downloaded 2026-11-16). data/cip_vendors.tsv is the ODVA CIP vendor ID list, extracted from the public table in Wireshark's packet-cip.c (vendor IDs are public facts; Wireshark is GPL-2.0-or-later, and no Wireshark code is included). Added libraries: rustls and tokio-rustls (Apache-2.0 OR ISC OR MIT), ring (ISC-style), x509-parser (MIT OR Apache-2.0), regex (MIT OR Apache-2.0), socket2 (MIT OR Apache-2.0); rcgen (dev-only, MIT OR Apache-2.0).

Phase 3 libraries: Rhai (MIT OR Apache-2.0) for scripting and roxmltree (MIT OR Apache-2.0) for nmap XML import. nmap is a trademark of its owners; Network Scope only reads and writes the documented XML format and contains no nmap code or data. The lab simulators are original code.
