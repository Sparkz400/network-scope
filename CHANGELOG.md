# Changelog

All notable changes to Network Scope are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Safe Mode badge** in the status bar of the desktop: a green "Safe Mode" or amber "Fast" label next to the status text, updated as soon as the setting changes. The tooltip lists the limits (Safe Mode) or the enabled opt-in features (Fast); a click opens Settings. `NETWORK_SCOPE_SCREENSHOT_STATE` accepts a `-fast` suffix (for example `main-small-fast`) to render with Safe Mode off.

### Changed

- Internal: `src/otpassive.rs` is split into the module directory `src/otpassive/` (reassembly, packet parsing, one file per protocol decoder, asset inventory, control findings, capture ingest). No behaviour change.
- **OT read-only guarantee is now a type-level property** (ROADMAP H51, partly): all active OT requests (Modbus Read Device Identification, S7 setup and SZL reads, EtherNet/IP List Identity, BACnet Who-Is, OPC UA discovery) are built from allow-list enums in `ot::readonly` and sent only through socket wrappers that accept nothing but those request types, so a write or control function code cannot be sent without adding an enum variant. Tests cover every function code byte, and the bytes on the wire are unchanged. See [Safe Mode and OT safety](docs/src/safe-mode-and-ot-safety.md).

## [0.5.1] - 2026-11-19

Fuzzing, a container image and signed SLSA provenance for releases; the desktop GUI moves to egui 0.37 and several dependencies get major upgrades.

### Added

- **Fuzzing**: cargo-fuzz targets for the parsers of untrusted input (pcap/pcapng, passive frames, OT tracker with TCP reassembly, TLS, SMB, NTLM, SSH, HTTP, RDP, banners, Modbus, EtherNet/IP, BACnet, S7, OPC UA, UDP replies, ARP, SYN-ACK and TCP options, ICMP/ICMPv6 ping and traceroute replies, nmap XML, `probes.json`, `cves.json`) with seed corpora, run on pull requests and weekly by ClusterFuzzLite. The code now builds as a library (`src/lib.rs`) that both binaries call; their behaviour is unchanged.
- **Container image** of the CLI on GitHub Container Registry, `ghcr.io/sparkz400/network-scope:<version>` and `:latest` (linux/amd64; Debian slim, unprivileged user, libpcap included), with a build provenance attestation in the registry (`gh attestation verify oci://ghcr.io/sparkz400/network-scope:<version> --owner Sparkz400`). Pull requests that change the Dockerfile or Cargo files build and smoke-test the image in CI. Not yet built outside CI; raw-socket and capture features in the container are untested.
- **SLSA level 3 provenance** for the release files from slsa-github-generator, attached as `network-scope-<version>.intoto.jsonl` (verify with `slsa-verifier`, see SECURITY.md).

### Changed

- **Desktop GUI on egui/eframe 0.37** (from 0.31): same windows and behaviour. Controls are a few pixels taller, the Findings window opens narrower, and windows opened at the same time stack instead of tiling. Scans and captures keep processing while the window is minimised.
- Dependencies: rusqlite 0.43 (bundled SQLite), rfd 0.18, libloading 0.9, x509-parser 0.18, socket2 0.6, roxmltree 0.21, dns-lookup 4; rcgen 0.14 (tests only). The lab image is Python 3.15, pinned by digest.

### Security

- nmap XML import sets roxmltree's new `entity_resolver` explicitly to none, so imported files can never resolve external entities (no XXE).
- Reviewed "unmaintained" advisories are also recorded for `fuzz/Cargo.lock`; secret scanning with push protection, CodeQL and gitleaks guard the repository.

## [0.5.0] - 2026-11-19

First public release. The [documentation](https://sparkz400.github.io/network-scope/) describes current behaviour; this entry lists what changed since 0.4 and what has not been verified.

### Added

- **Console binary** `network-scope-cli` (Windows console subsystem; shells wait, exit codes work), installed and put on PATH by the installer, built by CI.
- **SYN to routed IPv4 targets** via the gateway MAC (OS routing table).
- **`--adaptive-syn`**: RFC 6298 per-target reply windows and an AIMD congestion window.
- **`--arp-sweep`**: ARP who-has sweep through the capture handle.
- **Traceroute methods** `--trace-method icmp|tcp|udp`, `--trace-port N`; ICMPv6 traceroute; `trace --fast --trace-method`.
- **SMB** 3.1.1 negotiate contexts and NTLM challenge (dialect, GUID, encryption, compression, signing, clock skew, OS build, NetBIOS/DNS names); findings `smb-no-encryption`, CVE-2020-0796 hint. The NTLM SESSION_SETUP is not sent in Safe Mode.
- **TLS 1.3 suite enumeration** (not in Safe Mode), **JA4S-style fingerprint** (`tls.<port>.ja4s`), **HASSHServer** (`ssh.<port>.hassh`).
- **CVE rules in `data/cves.json`**, user override file and `--cves FILE`; CPE names (`svc.<port>.cpe`).
- **UDP payload probes** from probes.json (`"proto": "udp"`): SQL Server Browser, rpcbind, memcached, SIP. `probes` lists UDP probes too; `--probes` applies to UDP-only scans.
- **OS evidence** from the SMB NTLM version, Dropbear, Cisco/MikroTik SSH.
- **Diff** `--format lines|json|text` with new/resolved/unconfirmed findings and `--ignore`.
- **`devices --history MAC|IP`** timeline across saved scans.
- **Exports** `md` and `jsonl`; report findings-by-host table, new/resolved findings vs. baseline, CPE column. GUI: Markdown export.
- **nmap XML** product-name mapping both ways, CPE, Windows OpenSSH handling.
- **Monitor alert sinks** `--webhook` (http only), `--syslog` (UDP/TCP, RFC 5424), `--alert-timeout`; de-duplication across cycles (`--no-dedup`, `--renotify-hours`); `--quiet` silences monitor progress; `--report-missing` hint.
- **pcap link types** Linux SLL/SLL2 and raw IP; **ingest progress** (`ot-listen --progress`, GUI progress bar and Cancel).
- **OT TCP reassembly** for Modbus, S7, IEC 104, EtherNet/IP, OPC UA (`--no-reassembly`).
- **GUI**: OT passive section (pcap/live, asset table, exports, saved to inventory, saved as partial on close, refilled when reopened); sortable/filterable Findings and Devices; script dry-run; background exports; Settings for ARP sweep, adaptive SYN, trace method/port (off in Safe Mode); Clear results and captures; debounced preference saving.
- **TUI** row selection, host details, sort; **shell completions** (`completions powershell|bash`), global `--quiet`.
- **Device identity**: routed hosts with the same SMB GUID and NetBIOS name merge; SMB names become host names; CPE/HASSH/JA4S values are not device-type evidence.
- **UDP scan** never sends to OT or printer ports (skipped with a host note).
- **Diff noise**: `*.clock_skew` and `*.boot_time` are volatile like `*.days_left`.
- **Repository**: documentation book (`docs/`), community health files, issue templates, release and documentation workflows, data provenance (`data/README.md`), third-party notices.

### Changed

- Rust edition 2024 (toolchain pinned to 1.100.0); ratatui 0.30 and crossterm 0.29.
- First scan after upgrading: `tls.<port>.ciphers` gains a `TLS1.3:` part on TLS 1.3 servers, and nmap imports stored by 0.4 differ in `svc.<port>.product` spelling; both show as identity changes once.
- A diff of an old /23-or-larger snapshot against a new one can list inner .0/.255 addresses as new devices.
- OT passive `packets` counts messages, not segments, on the reassembled ports.
- Routed hosts merged by SMB GUID + NetBIOS name keep the device id of the lowest address; an existing monitor database may raise one `new-device` or `device-missing` alert for such hosts after the upgrade.
- On Linux a rescan may report a host found earlier only through a now-STALE ARP entry as not responding.
- Monitor: `device-missing` is Low, `address-changed` Medium; new `capture-incomplete` (Low).
- 2222/tcp is listen-only (SSH greeting → SSH exchange, else industrial). Printer ports 9100-9107 and 515 get a passive banner wait only.
- Scripts: 250 ms wall limit per host across all scripts; Rhai `sleep()` disabled.
- `CREDITS.md` is now `THIRD-PARTY-NOTICES.md`.

### Fixed

**Engine**

- `--syn --rate N`: one rate token per transmitted SYN (retransmits included), taken by the SYN I/O thread only; a probe's reply window starts when it is sent, so queued probes are never reported unanswered. Retransmits go first and double the wait up to the port timeout.
- SYN capture is non-promiscuous with the BPF filter `tcp and dst host <source-ip>`; SYN probes share the global 4,096 in-flight bound. After Stop, probes whose caller went away are dropped before a token is taken.
- The global socket permit is taken before a probe task is spawned (large `--workers` × `--parallel` no longer park millions of tasks). Blocking slots are held until the native call really ends.
- Stop keeps hosts that had already finished.
- OT identification runs for hosts that responded to something and, when nonresponders are scanned, for silent hosts, which then get only the single BACnet Who-Is (wait capped at 2 s). Devices that answer only BACnet/IP are still found.
- "Skip .0 and .255": CIDR blocks skip only their own network and broadcast address; /31 and /32 are never trimmed; dash ranges keep the old rule.
- CSV exports neutralise formula-leading cells (`=`, `+`, `-`, `@`, TAB, CR) with `'`.
- libpcap library names on macOS/Linux; MAC lookup skipped for routed IPv4 targets on Linux; a cached Linux neighbor entry counts as alive only if REACHABLE or new after the poke; the miss path is one poke and one 250 ms wait.
- Traceroute replies are matched by a per-trace ICMP id and the quoted destination; echo matching checks the sequence (and the id where the OS keeps it).
- Windows: the GUI binary attaches to the parent console whenever it has none and rebinds only unusable std handles, so stderr is no longer lost when only stdout is redirected.

**Services / TLS / risk**

- SMBv1 detected with a separate SMB1 negotiate; smb1 and signing reported independently.
- RDP: a second connection tests whether NLA is actually required.
- LDAP anonymous-bind finding needs resultCode 0.
- TLS: weak-first per-version budget (`suites_truncated`), `not_yet_valid` (+ finding), `cert_error`, self-signed also requires AKI == SKI.
- OpenSSH CVE-2018-15473 range fixed (7.7p1 now matched). PHP end of life is date-aware.
- HTTP Host header carries `:port` for non-80/443 ports and brackets IPv6.

**Passive / OT / monitor**

- A capture error or the observation cap no longer ends `monitor`. New-device alerts treat 2222/tcp as OT (High).
- DHCP observations keep the client in `ip`/`mac` and record servers per `dhcp_server.<ip>`.
- Capture thread tolerates transient read errors; a full queue reports one non-fatal error. `listen`/`dcp` treat error items as warnings and keep collecting.
- BACnet wait clamped to 200-2000 ms; port unreachable means "no BACnet".
- CIP object-specific services decoded by path; Unconnected Send / Multiple Service Packet unwrapped.
- Requests to broadcast/multicast destinations record only the client.
- pcapng `if_tsresol`, oversized blocks skipped, classic pcap FCS stripping and link-type masking.

**CLI / GUI**

- `scan`, `listen`, `dcp` save partial results on errors and exit 1. TUI stops on `q`, `Q`, Esc.
- Exports carry the real scan time (stored time for saved/reopened scans, current time for live GUI results) instead of "time not recorded".
- GUI: the OT pcap import now flushes partially reassembled messages; a cancelled import is partial, not an error.

- **Npcap was never loaded on Windows:** the driver path used forward slashes, which `LoadLibraryExW` rejects with `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR`, so SYN scanning, the ARP sweep, TCP traceroute, `listen`, DCP and live OT capture always reported "Capture driver unavailable" even with Npcap installed. Found in the first real-hardware test.

### Security

- **Bundled SQLite 3.54.1** (rusqlite 0.41): fixes RUSTSEC-2026-0459 / CVE-2026-119375, where a crafted database and `-wal` file pair could make queries return uninitialised memory. Only inventory files from an untrusted source were exposed.
- Checks in CI: `cargo deny` (advisories, licenses, sources) and `cargo audit` on every change and weekly, and a gitleaks secret scan of the full history on every push; CodeQL static analysis; every GitHub Action pinned to a commit SHA. Release files carry signed build provenance (`gh attestation verify`), and the Sigstore bundle is attached to the release.
- `osv-scanner.toml` lists the six transitive "unmaintained" advisories (no vulnerabilities) with a reason and an expiry date for review.

### Not done

Deliberately, or for lack of a test setup:

- JARM: needs byte-exact hellos to match public databases and too many connections for Safe Mode.
- x509 signature verification for self-signed detection (would need the `verify` feature of x509-parser).
- `store::list_alerts_since` (exact alert de-duplication restore with several monitors on one database).
- A GUI field for a CVE rules file (the user file in LOCALAPPDATA and `--cves` cover it).
- HTTPS webhooks (no bundled CA store).

### Untested

- Npcap/libpcap features not yet run on a real interface: SYN to routed targets, ARP sweep, TCP traceroute, live OT capture, DCP; libpcap on Linux/macOS. (Verified on Windows with Npcap: on-link SYN, passive `listen`; see the lab and testing page.)
- UDP traceroute with administrator/root rights; ICMPv6 hop-limit expiry from a real router on Windows.
- Linux/macOS glue (`next_hop`, neighbor states, raw ICMP/ICMPv6, UDP hop): not compiled on the development machine; CI is the first compile.
- The GUI binary's console attach when started from a shell; the installer script (never compiled with `iscc`); the CI, release and documentation workflows.
- Webhook/syslog delivery against real receivers; SMB against Samba; TLS 1.3 enumeration against OpenSSL/Schannel; JA4S against the reference implementation; CPE names against the NVD dictionary.
- OT decoders and reassembly against real industrial traffic (synthetic frames only).

## [0.4.0]

Internal version, not published and not tagged. Summary of the state that 0.5.0 builds on:

- egui desktop app, CLI and ratatui live terminal view sharing one scan engine.
- Async TCP connect scanning, ICMP and ARP discovery, optional on-link IPv4 SYN scanning via Npcap, Safe Mode on by default.
- Service, HTTP, TLS, SMB2, UDP and OS/manufacturer/device-type detection with a data-driven probe database.
- Risk findings, SQLite inventory with snapshot diffs, HTML/JSON/CSV exports, nmap XML import and export.
- Monitoring with JSON-line alerts and rogue DHCP detection.
- Rhai scripting.
- Read-only OT identification (Modbus/TCP, S7, EtherNet/IP, BACnet/IP, OPC UA), passive discovery, Profinet DCP Identify and passive OT analysis of pcap/pcapng files.
- Lab simulators and the Inno Setup installer script.

[Unreleased]: https://github.com/Sparkz400/network-scope/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/Sparkz400/network-scope/releases/tag/v0.5.0
