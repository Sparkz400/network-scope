# Detection

All detection is opt-in: Settings checkboxes in the desktop, or `--services`, `--udp`, `--os`, `--trace`, `--deep` on the CLI. Guesses are heuristics: verify before acting on them.

## Services (`--services`)

Every open TCP port gets a banner wait plus data-driven probes from `data/probes.json`: SSH, FTP, SMTP, POP3, IMAP, MySQL/MariaDB, VNC, Telnet, Redis, memcached, MQTT, PostgreSQL, SQL Server, MongoDB, RDP, LDAP, DNS, RTSP.

- **HTTP** reports status, server, title, redirect and auth realm. The Host header carries `:port` for ports other than 80/443 and brackets IPv6 literals.
- **Industrial ports** (102, 502, 4840, 44818, 47808 and the like) are never probed generically; they stay with the identification-only [OT probes](ot-industrial.md).
- **Printer ports** 9100-9107 (raw) and 515 (LPD) only get a passive banner wait: nothing is ever sent, and user probes for those ports are ignored.
- **2222/tcp** is listen-only: only an SSH greeting leads to the SSH algorithm exchange; anything else is treated as industrial (EtherNet/IP) and gets the `ot-reachable` finding.
- **RDP**: when the server selects NLA, a second connection offers only standard RDP security to learn whether NLA is actually required ("NLA required", or "… also accepted (NLA not required)", which raises `rdp-no-nla`).
- **LDAP**: the anonymous-bind finding needs a BindResponse with resultCode 0; "anonymous bind refused" is reported without a finding.

### Extending the probe database

Put a `probes.json` in `%LOCALAPPDATA%/NetworkScope` or pass `--probes FILE`. A probe with the same name replaces the built-in one; new names are added (a name can move between TCP and UDP). The file format and rule syntax are described in the `_comment` field of [`data/probes.json`](https://github.com/Sparkz400/network-scope/blob/main/data/probes.json): fields `name`, `proto` (tcp|udp), `ports`, `send`, `send_hex`, `wait_ms`, `rules[{re, service, product, version, info}]`; rules are regular expressions over the raw reply bytes, `$1..$9` expand capture groups, and the first matching rule wins.

`network-scope probes` lists and validates TCP and UDP probes; a bad regex or hex string stops the scan with an error. `--probes` applies to UDP-only scans too.

## TLS

- Certificate subject, CN, SAN, issuer, validity, days left, key and signature algorithm, and self-signed status (name equality plus AKI == SKI when both are present). A certificate that counts as self-signed has its signature verified with its own key (ring, through x509-parser's `verify` feature): `tls.<port>.self_signature` is `valid`, `invalid` or `unchecked (reason)`; `invalid` raises `tls-self-signed-bad-signature` instead of `tls-self-signed`, and `unchecked` (MD5, RSA below 1024 bits, curves other than P-256/P-384, anything ring does not verify) is never reported as a problem. Certificates are inventory data and are never validated against a trust store.
- The negotiated version and an enumeration of the accepted versions (SSLv3 to TLS 1.3) and cipher suites by raw ClientHello, so legacy and weak suites that rustls refuses to speak are still found.
- Per version the budget is one general hello, up to three weakness-class hellos (broken, 3DES, static RSA) and general enumeration with what is left, so weak suites are found first. When the budget runs out the strong-suite list is cut (`tls.<port>.suites_truncated`, `suites_truncated_versions`).
- **TLS 1.3 suites**: with Safe Mode off, servers that negotiated TLS 1.3 get TLS 1.3-only hellos (x25519 key share with random bytes; nothing is derived, only the ServerHello is read) until all five suites are known or refused, at most `min(rounds, 6)` hellos. Safe Mode sends none and reports only the negotiated version. Keys: `tls.<port>.tls13_suites` and a `TLS1.3:` part in `ciphers`; TLS_AES_128_CCM_8_SHA256 is listed as weak without a finding.
- `not_yet_valid` (finding `tls-cert-not-yet-valid`, Medium) and `cert_error` (certificate not parseable, handshake facts kept).
- `tls.<port>.ja4s` is a JA4S-style server fingerprint (FoxIO format, ALPN part `00` because our hellos offer none) of the first full-offer hello the server accepted. It is comparable between Network Scope scans, and comparable with other tools only for a similar client hello; it has not been cross-checked against the reference implementation.

### JARM-style TLS fingerprint (`--jarm`)

`scan --services --fast --jarm` sends ten more ClientHellos to every port that service detection found to speak TLS and stores `tls.<port>.jarm`, a 62 character hash: for each probe the selected cipher (2 hex characters) and version (1 letter), then 32 hex characters of the SHA-256 over the ALPN and extension lists of the ten replies (62 zeros when no probe got a ServerHello). It follows the structure of [JARM](https://github.com/salesforce/jarm) (Salesforce, BSD-3-Clause): TLS 1.2, 1.1 and 1.3 hellos with forward, reverse, top-half, bottom-half and middle-out cipher order, GREASE, rare ALPN lists and different extension orders. The hellos are built with the raw TLS code of the scanner, not rustls.

- **Off by default, never in Safe Mode.** The option is ignored in Safe Mode and without `--services` (the GUI checkbox is greyed out), because it adds ten connections per TLS port. Each connection goes through the rate gate; ports are probed one after the other; industrial and printer ports are never contacted. Each probe reads at most 1484 bytes and closes.
- **Not verified against the reference implementation.** The probe parameters follow the public description, but the cipher table, ALPN lists and extension bodies were written without the reference source at hand, so the hash has the JARM format and is stable for a given server (use it to spot servers with the same TLS stack inside one scan or between scans) but **must not be compared with hashes from public JARM databases** until the tables have been compared with `jarm.py`. The tests use synthetic server replies and check the format and the composition, not published hashes. Not tested against real servers beyond a local test server.
- The reply parser is fuzzed (`jarm_response`). The key is a volatile-free identity key like `ja4s` and is not used as evidence for the device type or OS.

## SSH

`ssh.<port>.hassh` is HASSHServer (MD5 of `kex;enc_s2c;mac_s2c;comp_s2c` from the server KEXINIT); `ssh.<port>.hassh_algorithms` holds the hashed string. MD5 and SHA-256 are implemented in-crate and checked against the RFC 1321 / FIPS 180 test vectors.

## SMB

- The SMB2 NEGOTIATE offers dialects 2.0.2 to 3.1.1 with the 3.1.1 negotiate contexts (preauth integrity, encryption, compression, signing), so the server reports its own.
- On the same connection a credential-less SESSION_SETUP carrying an NTLMSSP NEGOTIATE asks for the NTLM challenge. The exchange stops there: no AUTHENTICATE, so no logon attempt and no failed-logon event. **Safe Mode skips the SESSION_SETUP**, so `os_version` and the NetBIOS/DNS names are only collected with Safe Mode off.
- A second connection sends an SMB1 negotiate offering only "NT LM 0.12" to detect SMBv1 (`smb.<port>.smb1` = accepted/refused). smb1-enabled and smb-signing are reported independently.
- Identity keys `smb.<port>.`: `dialect`, `guid` (server GUID), `capabilities`, `encryption` (negotiated cipher, `supported`, `not supported`, `not supported (SMB 2.x)`), `compression` (3.1.1), `signing_algorithms`, `preauth_integrity`, `clock_skew` (coarse: `in sync (< 2 min)`, `+5 min`, …), `boot_time` (old Windows), `auth_mechs` (Kerberos/NTLM/NEGOEX), `os_version` (NTLM `major.minor.build`; Samba reports 6.1.0), `netbios_name`, `netbios_domain`, `dns_name`, `dns_domain`, `dns_forest`.
- Findings `smb-no-encryption` (Info) and `cve-cve-2020-0796` (High, version hint: only for dialect 3.1.1 with compression and NTLM build 18362/18363; the patch level is not visible remotely, so patched hosts are reported too).

Checked once against Windows 11, **not against Samba**.

## UDP (`--udp`, `--udp-ports`)

Built-in handlers: DNS (version.bind), NTP client request, SNMP get of sysDescr (community `public` only, v2c then v1), SSDP unicast M-SEARCH, mDNS service enumeration, NetBIOS node status (also yields the MAC), and DHCPINFORM (needs local UDP port 68).

probes.json entries with `"proto": "udp"` are sent as one datagram to listed ports without a built-in handler, instead of an empty datagram. Built in: SQL Server Browser (1434), rpcbind NULL call (111), memcached `version` (11211), SIP OPTIONS (5060).

The UDP scan **never sends anything to industrial or printer ports**: the TCP OT list plus 2222, EtherNet/IP 2221-2223, BACnet/IP 47808-47823, Profinet 34962-34964, DNP3 20000, FF HSE 1089-1091, MELSEC 5006/5007, CODESYS 1740-1743, EtherCAT 34980, VxWorks WDB 17185, printer 515 and 9100-9107. Such ports in `--udp-ports` are skipped with a host note, and probes listing them are rejected when loading. BACnet is identified only by `--ot`.

A reply means open, an ICMP port-unreachable means closed, silence is "open or filtered" and is not reported as open.

## OS, manufacturer and device type (`--os`)

- The **OS guess** is a scored rule set over the IP TTL, the SYN-ACK window and TCP option order (only with `--syn`), and service evidence: SSH, HTTP and SNMP banners, the SMB NTLM version (Windows release and build, strong; build 0 counted as Samba/Linux, weighted lightly), Dropbear (embedded), Cisco/MikroTik SSH banners (network device). It reports a family and a confidence, never a version.
- CPE and fingerprint keys (`.cpe`, `.hassh`, `.ja4s`) are not evidence for the OS or the device type.
- The **manufacturer** comes from the embedded IEEE registry (MA-L, MA-M and MA-S); locally administered/randomised MACs are marked instead of looked up. EtherNet/IP vendor names come from the ODVA vendor list. See [Data sources](data-sources.md).
- The **device type** is a second scored guess with its evidence listed.

### Evidence and confidence

Every conclusion says why. The OS guess, the device type and each finding carry an `Evidence`: a list of short reasons (`print port 9100`, `service text mentions laserjet`, `initial TTL 64`) and a confidence from 0 to 100.

- **OS guess and device type:** the confidence is the score of the winning candidate plus half of its lead over the runner-up, limited to 10 to 95. It says how much independent evidence agrees and how far ahead the answer is; it is not a calibrated probability. In a scan result the reasons are the identity keys `os.evidence` / `device.evidence` and the scores `os.confidence` / `device.confidence` (`"70%"`). `devices ID` adds `device_type_evidence` and `os_evidence` objects (`{"reasons": [...], "confidence": 70}`) to each device, and the CSV gets `type_confidence`, `type_evidence`, `os_confidence` and `os_evidence` columns at the end. A guess imported from Nmap XML carries Nmap's accuracy as its confidence and no reasons.
- **Findings:** `confidence` is a property of the rule: 95 when the server itself reported the condition (a TLS parameter, an SMB flag, an unauthenticated answer), 90 when the rule reads a service name or banner (Telnet, FTP, HTTP Basic), 70 for the PHP end-of-life table, 50 when only an open port number is the evidence (`ot-reachable`), 40 for version-based hints (`cve-*`, `heartbleed`, SMBGhost) because distributions backport fixes, and 60 for findings from user scripts. It is in the JSON and JSONL exports, the HTML and Markdown reports (under the evidence) and the TUI host details; exports written before the score existed load with it unset.
- **Where it is shown:** the TUI host details (`OS: Linux (70 %) because ...`, `Type: ...`), the GUI host details (hover the OS and Type lines for the reasons), the Devices table of the HTML report (confidence next to the value, reasons as a tooltip), the Markdown summary (a `Why` column) and the JSON/JSONL exports.
- The reasons and scores are not compared by `diff` and `monitor`: a scan that could see more or less gives different reasons for the same device, which is not a change of the device. A changed guess (`os.guess`, `device.type`) is still reported.

SYN-ACK fingerprinting needs the SYN engine, so TCP-connect scans get TTL and service evidence only.

## Devices

`network-scope devices ID` (and the Devices window) merges active results and passive observations into one record per MAC, or per IP when no MAC is known.

- Routed hosts without a MAC that report the same SMB server GUID and NetBIOS name are one device (the GUID alone is not enough: cloned VMs share it). They keep the device id of the lowest address.
- SMB NetBIOS/DNS names are added to the host names.

Device timelines (`devices --history`) are described in [Inventory, diffs and reports](inventory-diff-reports.md#device-history).

## Passive evidence (`listen`)

`network-scope listen` and the desktop Passive window decode traffic that is already on the wire; nothing is transmitted. Each observation is attached to the sender's MAC (and IP when the frame has one) and merged into the device record (`devices ID`, Devices window) next to the active evidence.

| Protocol | What is read | What it tells about the device |
|---|---|---|
| ARP | MAC and IP | address binding, IP conflicts |
| LLDP | chassis, port, name, description, management IPv4, **system capabilities** | name; capabilities bridge, router, WLAN AP, repeater give a network device, telephone gives a VoIP phone |
| CDP | device ID, platform, software version, port, native VLAN, duplex, capabilities, management/interface IPv4 (802.3 LLC/SNAP to `01:00:0C:CC:CC:CC`) | name; router, switch, bridge, repeater give a network device, the phone capability or an "IP Phone" platform gives a VoIP phone |
| mDNS | records, `<host>.local` name (only when the A/AAAA address is the packet source), `service.<type>` for known service types, `model=` of `_device-info._tcp` | service types give a type hint (see below); Apple model identifiers give Apple/media |
| NetBIOS | name-service replies, and **name registration/refresh broadcasts** (workstation `<00>` / server `<20>` name, workgroup) | host name; a weak Windows hint |
| SSDP/UPnP | SERVER, ST, NT, USN, LOCATION of NOTIFY and search replies | IGD or `MiniUPnPd` gives a router, MediaRenderer/DIAL/Roku/Sonos a media device, printers and cameras by device type, `Microsoft-Windows` a Windows host |
| WS-Discovery | Hello, ProbeMatches and ResolveMatches on UDP 3702: types, XAddrs, endpoint address (Probe, Resolve and Bye are ignored) | `PrintDeviceType`/`ScanDeviceType` give a printer, `NetworkVideoTransmitter` a camera, `Computer` a weak Windows hint (Samba's `wsdd` also publishes it) |
| DHCP | client messages: option 55 request list, 60 vendor class, 12 host name; server replies as before | `os_hint` and a type hint (Windows 10/11, macOS, iOS, Android, ISC dhclient, IP phones, printers) |
| Profinet DCP | name, vendor, IDs, IP settings | industrial controller |

Device-type hints are stored in the observation as `hint.<category>` (strong) and `hint_weak.<category>` (weak) fields with the reason, and scored like active evidence: a strong hint (40 points) is enough for a device type, a weak one (20) only adds to other evidence, and a weak hint beside a strong one of the same category is ignored. When a passive hint names a specific kind of device, a plain LLDP/CDP announcement no longer counts as a network-device hint. The reason text is never used for keyword matching.

mDNS service types used as hints: `_ipp`, `_ipps`, `_printer`, `_pdl-datastream` (printer); `_airplay`, `_raop`, `_googlecast`, `_sonos` (media); `_hap`, `_matter`, `_hue`, `_esphomelib` (IoT); `_companion-link`, `_apple-mobdev2` (Apple); `_airport` (network); `_axis-video` (camera); weak: `_scanner`, `_rtsp`, `_workstation`, `_smb`, `_adisk`, `_afpovertcp`, `_spotify-connect`, `_mqtt`.

The fingerprint tables (DHCP request lists and vendor classes, default host names such as `DESKTOP-xxxxxxx` and `NPIxxxxxx`, service-type lists) are **heuristics written for this project** and kept small. They are checked against hand-built frames only, not against captures from real devices, and a device can announce services it does not offer. Treat the result as a hint. Observations are bounded: the number of distinct `service.*` fields per device comes from a closed list, XML is parsed with DTDs rejected and a size and node limit, and every parser ignores truncated or malformed input.

Not covered: WS-Discovery device metadata (a TCP request to port 5357 would be needed), the NetBIOS browser (UDP 138) host announcements, LLDP-MED, and DHCPv6/DHCP option 82 fingerprints.

## Not implemented

- **Reference-exact JARM**: `--jarm` produces a JARM-style hash whose tables are not verified against `jarm.py` (see above), so it cannot be compared with public JARM databases.
- **SNMPv3**.
