# Third-party notices

Network Scope is an original, independent Rust application, licensed under the MIT license ([LICENSE.txt](LICENSE.txt)). Protocol parsers and UI integration are independently implemented. This file lists the third-party libraries it links and the data it embeds.

## Rust crates (direct dependencies)

Licenses as declared by each crate's metadata for the versions in `Cargo.lock` (`cargo metadata`). Each crate pulls in further transitive dependencies; `Cargo.lock` records the exact set and versions. A complete transitive license report can be generated with a tool such as `cargo about` or `cargo license`.

| Crate | Used for | License |
| --- | --- | --- |
| eframe, egui_extras | Desktop GUI | MIT OR Apache-2.0 |
| accesskit and its platform adapters (via eframe's `accesskit` feature) | Screen reader integration of the desktop GUI | Apache-2.0 OR MIT |
| arboard (via eframe's `clipboard` feature) | Copy and paste with the system clipboard in the desktop GUI | MIT OR Apache-2.0 |
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
| winresource (build only, Windows) | Embeds the icon, version block and manifest into the .exe files | MIT |

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

- JARM (`core/src/jarm.rs`, `core/src/jarm_reference_*.txt`, `lab/jarm_reference.py`, `lab/jarm_compare.py`): the ClientHello builder, the reading of the ServerHello, the cipher table and the hash of `core/src/jarm.rs` are a transcription of `jarm.py` from https://github.com/salesforce/jarm (commit e00ad79b02166568048266054a38470f4814c868), so that the fingerprints equal those of the reference; the test vectors in `jarm_reference_*.txt` are output of that code. `jarm.py` itself is not included in this repository or in the binaries. See the license below.

## JARM (Salesforce)

The JARM files named in the list above derive from `jarm.py` and are used under its license:

    Copyright (c) 2020, Salesforce.com, Inc.
    All rights reserved.

    Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

    * Neither the name of Salesforce.com nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Protocol references

[OPC UA mappings](https://reference.opcfoundation.org/specs/OPC-10000-6/full), [Modbus specification](https://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf), [Npcap API](https://npcap.com/guide/wpcap/pcap.html). The lab simulators are original code.
