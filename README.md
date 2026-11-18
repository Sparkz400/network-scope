# Network Scope

Portable Rust network discovery and inventory, with an egui desktop, CLI and ratatui live terminal view. Normal TCP connect scans work without administrator rights or Npcap.

## Desktop

Enter an IP, IPv4 range, CIDR, or comma/space-separated addresses, then Start. Nothing scans automatically. Settings enables ARP discovery and industrial identification; **Use industrial ports** selects the relevant TCP ports. Click a host for identity, probe errors and notes. **Inventory** reopens SQLite snapshots, selects baseline A and scan B, and exports JSON, CSV or HTML. Completed and stopped scans are stored separately. Comparisons require completed scans with matching scope and settings; a timeout never proves that a device is offline.

**Safe Mode** is enabled by default: at most eight active hosts and at least 100 ms between application probes; SYN is disabled. All OT operations are identification-only, even when Safe Mode is off. Safe Mode is a conservative traffic profile, not a guarantee for every PLC. **Fast** selects async TCP discovery with up to 1,024 hosts; Settings allows 4,096. These are concurrency limits, not benchmark results. Native ICMP, ARP and DNS use a separately bounded blocking pool. Pause lets in-flight hosts finish; Stop aborts asynchronous work, although an already issued native request can finish later.

**Passive / DCP** selects an Ethernet interface and capture duration. Passive capture sends no discovery packets and decodes mDNS, SSDP/UPnP, LLDP, NetBIOS, DHCP and ARP. The separate DCP Identify button sends one read-only Profinet multicast request; it never assigns IPs or changes a device. MAC-keyed observations retain devices that advertise no IP. Capture visibility depends on the network interface, multicast delivery and switch mirroring; it does not expose all traffic on a switched LAN. Observations are bounded to 10,000; queue overflow is an explicit partial-capture error.

## CLI and TUI

Use PowerShell's call operator or a normal terminal. The same executable opens the desktop when invoked without arguments.

```powershell
.\network-scope.exe --help
.\network-scope.exe scan 192.168.1.0/24 --tcp-only --fast --workers 1024 --ports 80,443
.\network-scope.exe scan 192.168.1.10 --arp --ot --tui --output inventory.json
.\network-scope.exe history
.\network-scope.exe diff 1 2
.\network-scope.exe export 2 --format html --output report.html
.\network-scope.exe scan 192.168.1.0/24 --deep --trace --script scripts\example.rhai
.\network-scope.exe findings 3 --min-severity medium
.\network-scope.exe report 3 --baseline 2 --output report.html
.\network-scope.exe export 3 --format nmap --output scan.xml
.\network-scope.exe import nmap-result.xml
.\network-scope.exe monitor 192.168.1.0/24 --deep --interval 300 --dhcp-allow 192.168.1.1 --alerts alerts.jsonl
.\network-scope.exe ot-listen --pcap plant.pcapng
.\network-scope.exe ot-assets 4 --format csv --output assets.csv
.\network-scope.exe interfaces
.\network-scope.exe listen --interface "INTERFACE_ID" --seconds 60
.\network-scope.exe dcp --interface "INTERFACE_ID" --source-mac "AA:BB:CC:DD:EE:FF"
```

TUI keys: Space pauses/resumes; Q or Escape stops and saves a partial result. `--db FILE` selects the inventory database; `--format json|csv|html` and `--output FILE` select an export. CLI errors return nonzero exit status. Progress is on stderr; JSON/CSV/HTML output goes to stdout or the selected file. A forced process kill cannot save in-memory work.

Windows preferences and the default SQLite database reside in `%LOCALAPPDATA%\NetworkScope`. SQLite is bundled into the executable. Scan settings are recorded per snapshot; notes are retained in JSON/CSV exports.

## Engine (v0.2)

- **Rate control:** Safe Mode uses a token bucket (one probe per 100 ms or the configured spacing, never faster). Outside Safe Mode there is no limiter at all unless you set `--rate PPS` (desktop: "Rate cap"), which applies a token bucket of that many probes per second. The old behaviour, a global 20 ms gate on every probe, is gone.
- **Concurrency:** ping probes of a host run in parallel, and so do its port probes (`--parallel`, default 64; at most 4 in Safe Mode). A global cap of 4,096 open sockets and 256 blocking native calls bounds resources.
- **Retries and timeouts:** ports that stay silent are retried (`--retries`, default 1; each retry doubles the timeout up to the configured port timeout). The adaptive timeout from measured ping still sets the first attempt.
- **Ports:** `--top-ports N` or `top:N` in the port field adds the N most common TCP ports (1-100). The ordering is approximate, recalled from public scanner statistics, and not generated from nmap-services.
- **Streaming targets:** ranges are expanded lazily. The CLI accepts up to 16,777,216 addresses (a /8); above 65,536 only responding hosts are kept and saved. The desktop keeps the 65,536 limit because its table holds every row.
- **SYN engine:** one Npcap/libpcap handle is owned by one I/O thread that both sends and receives (libpcap handles are not safe for concurrent use). Replies are matched on target, target port and local port and validated against a hashed sequence cookie; unanswered probes are retransmitted. Each target MAC is resolved once and cached. It still supports only on-link IPv4 targets: there is no gateway MAC discovery yet.
- **Platforms:** ICMP and neighbor lookup work on Linux and macOS as well. ICMP uses an unprivileged datagram socket when the OS allows it and falls back to a raw socket (root). MAC lookup reads `/proc/net/arp`, then `ip neigh`, then `arp -n`. The non-Windows paths are covered by parser unit tests that run on every platform, but have not been run against a live Linux or macOS network.

## Detection (v0.3)

All of this is opt-in (Settings checkboxes, or `--services`, `--udp`, `--os`, `--trace`, `--deep` on the CLI) and read-only.

- **Services (`--services`):** every open TCP port gets a banner wait plus data-driven probes from `data/probes.json` (SSH, FTP, SMTP, POP3, IMAP, MySQL/MariaDB, VNC, Telnet, Redis, memcached, MQTT, PostgreSQL, SQL Server, MongoDB, RDP, LDAP, DNS, RTSP). HTTP reports status, server, title, redirect and auth realm. SMB sends a negotiate request and reports the dialect (2.0.2 to 3.1.1), whether signing is required, and flags SMBv1. Industrial ports (102, 502, 4840, 44818, 47808 and the like) are never probed generically; they stay with the identification-only OT probes.
- **TLS:** certificate subject/CN/SAN/issuer/validity/days left/key/signature algorithm/self-signed, the negotiated version, and an enumeration of the accepted versions (SSLv3 to TLS 1.2) and cipher suites by raw ClientHello, so legacy and weak suites that rustls refuses to speak are still found. Certificates are inventory data and are never validated. TLS 1.3 is detected from the handshake but its suites are not enumerated.
- **Extending the probe database:** put `probes.json` in `%LOCALAPPDATA%/NetworkScope` or pass `--probes FILE`. A probe with the same name replaces the built-in one; new names are added. The file format and rule syntax are described in the `_comment` field of `data/probes.json`. `network-scope probes` lists and validates what is loaded; a bad regex or hex string stops the scan with an error instead of being ignored.
- **UDP (`--udp`, `--udp-ports`):** DNS (version.bind), NTP client request, SNMP get of sysDescr (community `public` only, v2c then v1; no guessing of other communities), SSDP unicast M-SEARCH, mDNS service enumeration, NetBIOS node status (also yields the MAC), and DHCPINFORM (needs local UDP port 68; fails with a clear error if another DHCP client holds it). A reply means open, an ICMP port-unreachable means closed, silence is "open or filtered" and is not reported as open.
- **OS, manufacturer, device type (`--os`):** the OS guess is a scored rule set over the IP TTL, the target's SYN-ACK window and TCP option order (only available with `--syn`, which now sends a realistic option set), and service evidence such as SSH, HTTP and SNMP banners. It reports a family and a confidence, never a version, and says nothing when the evidence is weak. The manufacturer comes from the embedded IEEE registry (MA-L, MA-M and MA-S; locally administered/randomised MACs are marked instead of looked up), EtherNet/IP vendor IDs from the ODVA list. Device type is a second scored guess with its evidence listed.
- **Devices:** `network-scope devices ID` (and the Devices window) merges active results and passive observations into one record per MAC, or per IP when no MAC is known.
- **Traceroute (`--trace`, `network-scope trace IP`):** all TTLs are probed in parallel with ICMP echo. IPv4 only. On Linux and macOS this needs a raw socket, so root. `network-scope topology ID --format ascii|dot` and the Topology window draw the merged path map; routers shared by several hosts appear once.
- **Not done:** SYN-ACK fingerprinting needs the SYN engine, so TCP-connect scans get TTL and service evidence only. TLS 1.3 suites, SSH key-exchange algorithms, SNMPv3 and UDP version probes beyond the list above are not implemented. Guesses are heuristics: verify before acting on them.
## Analysis (v0.4)

Everything here works on stored snapshots or passive data; the only new network traffic is an optional DHCPDISCOVER (below).

- **Findings (`findings ID [--min-severity low]`, Findings window):** derived from what a scan collected, so run it with `--services` (or `--deep`). Checks cover expired or soon-expiring certificates, self-signed certificates, weak signature hashes and short RSA keys, SSLv3/TLS 1.0/1.1, RC4/DES/3DES/export/anonymous suites, missing forward secrecy, SSH weak and legacy algorithms (including Terrapin, CVE-2023-48795), SSH protocol 1, Telnet, FTP, VNC, cleartext mail, unauthenticated Redis/memcached/MQTT, RDP without NLA, SMBv1 and unsigned SMB, HTTP Basic over plain HTTP, exposed Docker API, public SNMP, and industrial ports reachable from the scanner. **CVE entries are version-based hints only.** The built-in table is small (OpenSSH, Apache httpd 2.4.49/50, nginx, vsFTPd 2.3.4, Exim, IIS 6, Heartbleed-era OpenSSL, PHP end of life); distributions backport fixes without changing the version string, so confirm with the vendor advisory or an authenticated check. It is not a vulnerability scanner.
- **Reports (`report ID [--baseline ID] --output report.html`):** one self-contained HTML file with summary cards, SVG charts (findings by severity, common ports, device types, OS families), findings with NVD links, changes since a baseline, a network map from traceroute data, device table, per-host details and passive observations. No scripts, a restrictive Content-Security-Policy, and every scanned string is HTML-escaped. `export ID --format html` produces the same report.
- **nmap interchange:** `export ID --format nmap` writes nmap XML (`scanner="network-scope"`: hosts, addresses, hostnames, ports with service/product/version, TLS certificate, OS match, trace). `import FILE.xml` reads nmap XML (up to 256 MB) into the inventory as a normal scan, so nmap results can be diffed, reported and analysed. Down hosts and non-open ports are not imported. Network Scope is **not** a drop-in nmap replacement: there is no NSE, no raw-socket scan types other than SYN, and far fewer fingerprints.
- **Monitoring (`monitor TARGETS [scan options] --interval 300 [--cycles N]`):** repeats the scan, stores every run, and compares it with the previous completed scan of the same targets and with all devices ever seen. Alerts (JSON lines on stdout, `--alerts FILE`, and the `alerts` command): new device (high for OT devices), TCP/UDP port newly opened (high for risky ports), port no longer open (info), new finding, address change for a MAC, and with `--report-missing` a device not seen. Only ports probed by both scans are compared, and partial scans never raise change alerts, because a timeout is not proof of closure. The first run (or `--learn`) records devices without alerting. `--min-severity` filters. **Rogue DHCP:** `--dhcp-allow IP,IP` lists legitimate servers (anything else is critical; without it, more than one server is high). Servers come from DHCPINFORM replies, passive OFFER/ACK traffic (`--interface ID --listen-seconds N`), and `--dhcp-discover`, which broadcasts one DHCPDISCOVER and collects offers. It never sends a REQUEST, so no lease is taken, but a server may briefly reserve the address it offered. It needs local UDP port 68 and has not been tested on a live network with competing DHCP servers.
- **Scripting (`--script FILE|DIR`, `scripts PATH` to check):** [Rhai](https://rhai.rs) scripts define `fn on_host(h)` and run after each host is scanned. API: `h.ip h.hostname h.mac h.ttl h.ping h.open h.udp h.os h.vendor h.device`, `h.has_port(n)`, `h.has_service("name")`, `h.service(port)`, `h.identity("key")`, `h.set("key","value")` (adds `script.key`), `h.finding("severity","id","title","evidence")` and `h.note("text")`. Scripts cannot touch files, the network or processes; `eval` and modules are disabled, and operations, sizes, recursion depth and wall time (250 ms per host) are bounded. A failing script adds a note to the host and never stops the scan. See `scripts/example.rhai`.
- **OT passive mode (`ot-listen --interface ID --seconds N` or `--pcap FILE`, `ot-assets ID [--format csv]`):** reads traffic and never transmits. A live capture goes through a wrapper with no send call, and a test fails the build if the passive modules contain socket or send code. Capture files (pcap and pcapng, Ethernet) are parsed in pure Rust. Recognised: Modbus/TCP, S7comm, DNP3, IEC 60870-5-104, EtherNet/IP (List Identity replies and CIP services), BACnet/IP (I-Am, Who-Is, confirmed services) and OPC UA. Control traffic (writes, program download, PLC stop, operate and restart commands, setpoints, WriteProperty, ReinitializeDevice, and so on) is counted per server and client and raised as `ot-control-traffic` findings, so you can see who writes to a controller. The asset export gives vendor, product, firmware, serial, protocols, roles, first/last seen and control traffic per asset. Limits: no TCP reassembly (a message split over segments is missed), IPv4 only, standard ports only, decoders validated with synthetic frames only. A SPAN/mirror port or tap is needed to see more than your own segment.

## Lab and verification

`lab/simulators.py` (standard library only) emulates deliberately weak services: FTP banner vsFTPd 2.3.4, Telnet, SSH offering weak algorithms, Apache 2.4.49 with Basic auth, open Redis, Modbus/TCP, EtherNet/IP and BACnet/IP identity. They are fake: they only produce what a scanner observes. `lab/docker-compose.yml` runs them (plus a real Redis) on an internal Docker network `172.28.0.0/24`. `python lab/verify.py target/release/network-scope` starts the simulators on loopback, scans them and asserts the identities and findings; CI runs it on Windows, Linux and macOS. The Docker compose file has **not** been run (no Docker on the development machine); `verify.py` has, on Windows. The lab has no S7, DNP3, IEC 104 or OPC UA simulator.

## Packaging and CI

`.github/workflows/ci.yml` runs format, clippy with `-D warnings`, tests and the lab check on Windows, Linux and macOS, then builds the Windows installer. `installer/network-scope.iss` is an Inno Setup script (per-user install by default, optional PATH entry and shortcut). `iscc /DAppVersion=0.4.0 installer\network-scope.iss` writes `dist/NetworkScope-0.4.0-setup.exe`. The installer is unsigned, so Windows SmartScreen will warn. The CI workflow has not been run on GitHub from this tree.

## Discovery implementations and boundaries

- Tokio TCP connect works with IPv4/IPv6. ARP discovery uses Windows SendARP independently of ICMP and only reaches the local IPv4 network. ICMP uses Windows APIs.
- Optional SYN uses pnet packet construction and runtime-loaded Npcap Ethernet injection/capture. Supply `--fast --syn --interface ID --source-ip IP --source-mac MAC`. Source values must match that interface. This implementation supports untagged local IPv4 neighbors, not routed targets or IPv6 SYN. Driver/configuration errors trigger an explicit TCP-connect fallback; a missing reply is reported as unanswered. Npcap must be installed separately, with capture permissions; the app does not install drivers or request elevation. Its dependent DLLs are loaded from the driver's directory and Windows default trusted locations.
- Modbus TCP: one Basic Read Device Identification request (43/14), with configurable unit ID; vendor, product and firmware when returned. Additional object pages are marked partial.
- S7: COTP connection, communication setup and read-only SZL 0x0011/0x001C, with configurable rack/slot. Extracts order code, CPU type, firmware and serial when advertised. Segmented SZLs, denied access and unsupported devices return explicit errors. No S7plus, authentication, program/block access or control operations.
- OPC UA: UA Binary HEL/OpenSecureChannel, GetEndpoints and FindServers without a session, followed by CloseSecureChannel. Records names, application/product URIs, security policies and certificate DER as hex. Product URI is not a verified manufacturer identity. Only unsecured sessionless discovery is supported; servers denying it produce errors. Discovery certificates are inventory data, not trusted certificates. Message sizes, chunk counts and parser recursion are bounded.
- EtherNet/IP: TCP List Identity, including vendor ID, product, serial and revision. Vendor IDs are retained without an embedded vendor-name database.
- BACnet/IP: one unicast Who-Is per selected IPv4 target, parsing I-Am device/vendor identity; no broad broadcast or property writes. IPv6 BACnet and forwarded/router NPDU forms are not supported.
- Passive IPv4/IPv6 UDP decoding supports ordinary unfragmented packets; IPv6 extension headers and reassembly are not implemented. Ethernet VLAN tags are supported by passive decoders. Captured metadata is untrusted input; HTML reports escape it.

OT identification probes standard ports only. In the desktop, select industrial ports and enable nonresponders to find ICMP-silent TCP services. The CLI does both when `--ot` is used without `--ports`. Passive and DCP records are preserved alongside scan inventory but do not imply open TCP ports. Generic HTTP, SSH and TLS service fingerprinting is available through the opt-in Detection features above.

## Benchmark (one machine, one day: indicative, not rigorous)

Windows 11 host scanning a Windows VM and its /24 over VMware NAT. nmap 7.92 (`nmap -sT -Pn -n --unprivileged -T4 --max-retries 1 --max-rtt-timeout 1500ms`) against Network Scope (`scan --fast --tcp-only --timeout 1500`). Both TCP connect scans, no Npcap.

| Scenario | nmap | Network Scope | Same result? |
| --- | --- | --- | --- |
| 1 host, ports 1-1000 (target drops most ports) | 46.7 s (one run) | 49.0 s (one run) | yes, 7 open ports each |
| /24, ports 22,80,445 | 38.4 s and 40.7 s | 3.3 s and 3.4 s | not compared: nmap `-Pn` lists every address as up, so only our run's 2 responding hosts were checked |

Reading it: on one host whose firewall silently drops most ports, both tools are limited by the timeout and are about equal. The /24 gap comes from how each handles mostly empty address space under these settings, not from a faster packet path; nmap with different timing or host-discovery options may close it. Single-digit runs, one network, no warm-up control: treat the numbers as a sanity check. Reproduce with the commands above.
## Build and verify

```powershell
cargo build --release --locked
cargo test --release --locked
cargo clippy --all-targets --locked -- -D warnings
cargo run --release -- --screenshot screenshot.png
```

Screenshot mode does not scan or modify preferences/inventory. Layout: `core` (scheduler/rate gate), `scan` (targets and model), `service`, `tls`, `udp`, `osfp`, `oui`, `devices`, `trace`, `topology`, `risk`, `report`, `nmap`, `monitor`, `script`, `probes`, `capture`, `passive`, `otpassive`, `pcapfile`, `ot` (including `ot/opcua`), `store`, `ui` (CLI/TUI) and `gui` (egui: `mod`, `controls`, `settings`, `details`, `windows`); `main` only dispatches.

Tests exercise real loopback networking and protocol fixtures, SQLite round trips, scan changes, parser bounds and report escaping.

Protocol references: [OPC UA mappings](https://reference.opcfoundation.org/specs/OPC-10000-6/full), [Modbus specification](https://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf), [Npcap API](https://npcap.com/guide/wpcap/pcap.html).
