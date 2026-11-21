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

`network-scope probes` lists the TCP and UDP probes; a bad regex or hex string stops the scan with an error. `probes validate FILE` checks a probe file the way a scan would load it, and `probes lint [FILE]` runs the safety linter. `--probes` applies to UDP-only scans too. To contribute a fingerprint, see [Contributing fingerprints](contributing-fingerprints.md).

## TLS

- Certificate subject, CN, SAN, issuer, validity, days left, key and signature algorithm, and self-signed status (name equality plus AKI == SKI when both are present). A certificate that counts as self-signed has its signature verified with its own key (ring, through x509-parser's `verify` feature): `tls.<port>.self_signature` is `valid`, `invalid` or `unchecked (reason)`; `invalid` raises `tls-self-signed-bad-signature` instead of `tls-self-signed`, and `unchecked` (MD5, RSA below 1024 bits, curves other than P-256/P-384, anything ring does not verify) is never reported as a problem. Certificates are inventory data and are never validated against a trust store.
- The negotiated version and an enumeration of the accepted versions (SSLv3 to TLS 1.3) and cipher suites by raw ClientHello, so legacy and weak suites that rustls refuses to speak are still found.
- Per version the budget is one general hello, up to three weakness-class hellos (broken, 3DES, static RSA) and general enumeration with what is left, so weak suites are found first. When the budget runs out the strong-suite list is cut (`tls.<port>.suites_truncated`, `suites_truncated_versions`).
- **TLS 1.3 suites**: with Safe Mode off, servers that negotiated TLS 1.3 get TLS 1.3-only hellos (the x25519 key share is a fresh, valid public key from the crypto provider, because Windows Schannel rejects random bytes; its private half is dropped at once, nothing is derived, only the ServerHello is read) until all five suites are known or refused, at most `min(rounds, 6)` hellos. Safe Mode sends none and reports only the negotiated version. Keys: `tls.<port>.tls13_suites` and a `TLS1.3:` part in `ciphers`; TLS_AES_128_CCM_8_SHA256 is listed as weak without a finding.
- `not_yet_valid` (finding `tls-cert-not-yet-valid`, Medium) and `cert_error` (certificate not parseable, handshake facts kept).
- `tls.<port>.ja3s` is the JA3S fingerprint of the first full-offer hello the server accepted, and `tls.<port>.ja3s_string` the string it is the MD5 of (`SSLVersion,Cipher,Extensions`, decimal, extensions in the order received, for example `771,4866,43-51`). It is computed from the ServerHello that the handshake already returns, so it costs no packet. It is comparable between Network Scope scans, and with other tools only for a similar client hello. The algorithm is the one of Salesforce's JA3S (BSD-3-Clause); our values were compared with the reference `ja3s.py` on a wire capture of local TLS servers, see [Lab and testing](lab-and-testing.md#ja3s). The JA4+ fingerprints (JA4S, JA4X) are not implemented: their FoxIO License 1.1 does not fit this project's MIT licence (`data/README.md`). The certificate is identified by `spki_sha256`, the SHA-256 of its public key.

### Favicon hash (`--favicon`)

`scan --services --fast --favicon` sends **one** `GET /favicon.ico` to every web port that service detection found to answer as HTTP or HTTPS and stores `http.<port>.favicon_mmh3`: the value Shodan indexes as `http.favicon.hash` (MurmurHash3 of the base64 text of the icon, a signed 32-bit number), so a device or product can be searched for on the pivot side too. `fingerprints favicon FILE` computes the same value from a local file.

- **Off by default, never in Safe Mode.** Like JARM, the option is ignored in Safe Mode and without `--services`. The scan's ordinary `GET /` is unchanged.
- **Not on hosts this scan found to be industrial.** A host with an industrial or printer port open (`102, 502, 4840, 44818, 9100`, and so on), with an industrial identification (S7, Modbus, EtherNet/IP, BACnet fields) or an open BACnet UDP port gets no favicon request, even on its web port. **This only knows what the scan itself saw**: with `--ports 80,443` and no `--ot`, a PLC's web server looks like any other web server and gets the favicon request exactly as it gets the scan's ordinary `GET /`. Use `--ot` and the industrial ports in the port list on networks with controllers, or leave `--favicon` off there.
- **One request per port, bounded.** The request goes through the scan's rate gate (sent log: `http-request` / `GET /favicon.ico`; `--dry-run` lists it), ports are asked one after the other, the back-off governor can pause the host (and is told when a port stops answering). At most 256 KiB of the answer are read, a larger icon gives no hash, and redirects are not followed.
- **Only real icons.** A hash is stored when the server answered `200` with an `image/*` content type or an icon, PNG, GIF, JPEG, BMP, WebP or SVG signature. Many servers answer every path with their start page; an HTML body never becomes a favicon hash. A site that names its icon only in a `<link rel="icon">` (a different path) is not found: only `/favicon.ico` is requested.
- Checked on the lab web server (`lab/verify.py`: the hash the program stores equals the one an independent Python implementation of Shodan's recipe computes for the icon the simulator serves) and with local servers in the unit tests. The response parser is fuzzed (`favicon_response`). No hash was compared with a value Shodan published for a real device.

### JARM-style TLS fingerprint (`--jarm`)

`scan --services --fast --jarm` sends ten more ClientHellos to every port that service detection found to speak TLS and stores `tls.<port>.jarm`, a 62 character hash: for each probe the selected cipher (2 hex characters) and version (1 letter), then 32 hex characters of the SHA-256 over the ALPN and extension lists of the ten replies (62 zeros when no probe got a ServerHello). It is [JARM](https://github.com/salesforce/jarm) (Salesforce, BSD-3-Clause) and gives the hash `jarm.py` gives: TLS 1.2, 1.1 and 1.3 hellos with forward, reverse, top-half, bottom-half and middle-out cipher order, GREASE, rare ALPN lists and reversed ALPN and version lists. The hellos are built with the raw TLS code of the scanner, not rustls.

- **Off by default, never in Safe Mode.** The option is ignored in Safe Mode and without `--services` (the GUI checkbox is greyed out), because it adds ten connections per TLS port. Each connection goes through the rate gate; ports are probed one after the other; industrial and printer ports are never contacted. Each probe reads at most 1484 bytes and closes.
- **Checked against the reference implementation (`jarm.py`).** The hellos, the reading of the replies and the hash are a transcription of `jarm.py`, so the 62 characters are the ones public JARM databases use. Two checks back this: unit tests compare the ten hellos byte for byte and 270 replies and hashes (real-server shapes, no extensions, odd ALPN values, every truncation of two replies) with vectors that `lab/jarm_reference.py` generated by running the reference code, and `lab/jarm_compare.py` runs `jarm.py` and Network Scope against live servers. The comparison below is the last one run. The first version of this feature was written without the reference source and differed from it (the cipher byte used the position in the offered list instead of the reference's sorted table, the extension order, supported-groups and signature-algorithm bodies, the TLS 1.2 record version and the top-half order were different); none of its hashes matched `jarm.py`.
- **The server name is the address.** Both tools put the address they were given into the server name extension, so a fingerprint taken with `jarm.py` by host name (a name in the SNI) can differ from the one this scanner takes from the IP address; compare like with like (`jarm.py 192.0.2.7` against the scan of 192.0.2.7).
- **Differences that remain on purpose.** The random bytes and GREASE values are this program's own (the reference randomises them too, and servers ignore them). The connect and read timeout is the scan's port timeout (0.5 to 5 seconds), the reference waits 20 seconds. Like the reference, a timeout on any probe ends the fingerprint with 62 zeros (and no further hello is sent), while a refused, reset or closed connection only empties that probe. A server that is slow but answers within 20 seconds can therefore give zeros here and a hash in `jarm.py`; raise `--timeout` (up to 5000 ms counts) if that matters. A TLS server is fingerprinted only when service detection identified it as TLS, which for a server that offers no TLS 1.2 or 1.3 suite rustls can use (RSA key exchange only, SSL 3.0 to TLS 1.1) happens only on the well-known TLS ports.

Last comparison (2026-11-20, Windows 11 10.0.26300, `jarm.py` at commit e00ad79b02166568048266054a38470f4814c868, SHA-256 of the file 8b44d084d8fa49307d401a9be5ec4cd2e6fde6705ee913684d08c301f14524a1; Python 3.13.17 with OpenSSL 3.5.9, Git's OpenSSL 3.5.9 `s_server`, .NET 11 Schannel; all servers on 127.0.0.1; `python -I lab/jarm_compare.py --jarm-py JARM_PY --cli network-scope-cli.exe --schannel`):

| Server | `jarm.py` and Network Scope (identical) |
| --- | --- |
| openssl s_server, TLS 1.3 only, two suites | `00000000000000000043d43d0000009535d5979f591ae8e547c5e5743e5b64` |
| openssl s_server, TLS 1.2 + 1.3, one suite each | `2ad2ad0002ad2ad00041d41d000000ad9bf51cc3f5a1e29eecb81d0c7b06eb` |
| openssl s_server, TLS 1.2 only, RSA key exchange (port 5671) | `14d14d00014d14d00014d14d14d14dcdfe7f0b77f33e9e6b7374a546c1af73` |
| openssl s_server, TLS 1.2 + 1.3, defaults | `07d14d16d21d21d00042d43d000000aa99ce74e2c6d013c745aa52b5cc042d` |
| Python `ssl`, defaults, ALPN h2 and http/1.1 | `2ad2ad0002ad2ad00042d42d00000045d9c61f898d3d72d7a153fdd2347f3c` |
| Python `ssl`, TLS 1.2 only, ChaCha20 | `3fd3fd0003fd3fd0003fd3fd3fd3fd04320b71a5a1a86999cfc20df5bd6320` |
| Python `ssl`, TLS 1.3 only | `00000000000000000042d42d0000009535d5979f591ae8e547c5e5743e5b64` |
| Python `ssl`, TLS 1.2, RSA key exchange (port 5061) | `14d14d00014d14d00014d14d14d14dcdfe7f0b77f33e9e6b7374a546c1af73` |
| Python `ssl`, TLS 1.0 and up, security level 0 | `2ad2ad0002ad2ad22c42d42d000000faabb8fd156aa8b4d8a37853e1063261` |
| Windows Schannel (.NET `SslStream`, `lab/schannel_server.ps1`) | `2ad2ad0002ad2ad22c000000000000217f0fec773ec97f0b3fdd2de2993c31` |

Ten servers, ten identical fingerprints. Three servers that never give a ServerHello (an HTTP 400, an immediate close, silence) give 62 zeros in `jarm.py`; Network Scope does not run JARM on them because service detection does not identify them as TLS, so the zeros and the timeout rule are covered by the unit tests only. Not compared: SSL 3.0 servers (no maintained server was at hand), servers behind load balancers and CDNs, and any server on another operating system. The Schannel server is a single-threaded PowerShell script that drops hellos when it is hit in parallel: run the reference against it one connection at a time.

- Every JARM hello takes a token from the scan's rate gate and is counted in the sent log as `tls-client-hello` / `JARM fingerprint hello`; `--dry-run` lists it (and says when it would not be sent: Safe Mode, or without `--services`). A host that the back-off paused gets no JARM hellos.
- The reply parser is fuzzed (`jarm_response`). The key is a volatile-free identity key like `ja3s` and is not used as evidence for the device type or OS.

## SSH

`ssh.<port>.hassh` is HASSHServer (MD5 of `kex;enc_s2c;mac_s2c;comp_s2c` from the server KEXINIT); `ssh.<port>.hassh_algorithms` holds the hashed string. MD5 and SHA-256 are implemented in-crate and checked against the RFC 1321 / FIPS 180 test vectors.

## SMB

- The SMB2 NEGOTIATE offers dialects 2.0.2 to 3.1.1 with the 3.1.1 negotiate contexts (preauth integrity, encryption, compression, signing), so the server reports its own.
- On the same connection a credential-less SESSION_SETUP carrying an NTLMSSP NEGOTIATE asks for the NTLM challenge. The exchange stops there: no AUTHENTICATE, so no logon attempt and no failed-logon event. **Safe Mode skips the SESSION_SETUP**, so `os_version` and the NetBIOS/DNS names are only collected with Safe Mode off.
- A second connection sends an SMB1 negotiate offering only "NT LM 0.12" to detect SMBv1 (`smb.<port>.smb1` = accepted/refused). smb1-enabled and smb-signing are reported independently.
- Identity keys `smb.<port>.`: `dialect`, `guid` (server GUID), `capabilities`, `encryption` (negotiated cipher, `supported`, `not supported`, `not supported (SMB 2.x)`), `compression` (3.1.1), `signing_algorithms`, `preauth_integrity`, `clock_skew` (coarse: `in sync (< 2 min)`, `+5 min`, …), `boot_time` (old Windows), `auth_mechs` (Kerberos/NTLM/NEGOEX), `os_version` (NTLM `major.minor.build`; Samba reports 6.1.0), `netbios_name`, `netbios_domain`, `dns_name`, `dns_domain`, `dns_forest`.
- Findings `smb-no-encryption` (Info) and `cve-cve-2020-0796` (High, version hint: only for dialect 3.1.1 with compression and NTLM build 18362/18363; the patch level is not visible remotely, so patched hosts are reported too).

Checked against Windows 11; the check against Samba is in the `real-servers` CI job (see [Lab and testing](lab-and-testing.md#real-servers)) and passes.

## UDP (`--udp`, `--udp-ports`)

Built-in handlers: DNS (version.bind), NTP client request, SNMP get of sysDescr (community `public` only, v2c then v1), SSDP unicast M-SEARCH, mDNS service enumeration, NetBIOS node status (also yields the MAC), and DHCPINFORM (needs local UDP port 68).

probes.json entries with `"proto": "udp"` are sent as one datagram to listed ports without a built-in handler, instead of an empty datagram. Built in: SQL Server Browser (1434), rpcbind NULL call (111), memcached `version` (11211), SIP OPTIONS (5060).

The UDP scan **never sends anything to industrial or printer ports**: the TCP OT list plus 2222, EtherNet/IP 2221-2223, BACnet/IP 47808-47823, Profinet 34962-34964, DNP3 20000, FF HSE 1089-1091, MELSEC 5006/5007, CODESYS 1740-1743, EtherCAT 34980, VxWorks WDB 17185, printer 515 and 9100-9107. Such ports in `--udp-ports` are skipped with a host note, and probes listing them are rejected when loading. BACnet is identified only by `--ot`.

A reply means open, an ICMP port-unreachable means closed, silence is "open or filtered" and is not reported as open.

## OS, manufacturer and device type (`--os`)

- The **OS guess** is a scored rule set over the IP TTL, the SYN-ACK window and TCP option order (only with `--syn`), and service evidence: SSH, HTTP and SNMP banners, the SMB NTLM version (Windows release and build, strong; build 0 counted as Samba/Linux, weighted lightly), Dropbear (embedded), Cisco/MikroTik SSH banners (network device). It reports a family and a confidence, never a version.
- CPE and fingerprint keys (`.cpe`, `.hassh`, `.ja3s`) are not evidence for the OS or the device type.
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
| LLDP-MED | TIA-1057 TLVs (OUI `00-12-BB`) inside LLDP: `med_capabilities`, `med_device_class`, network policies per application (`med_policy.voice` and so on: VLAN, tagged, priority, DSCP), inventory (`med_hardware_revision`, `med_firmware_revision`, `med_software_revision`, `med_serial_number`, `med_manufacturer`, `med_model`, `med_asset_id`) | class III (communication endpoint) gives a VoIP phone, network connectivity a network device; an endpoint class drops the network hint of the bridge capability (a phone's PC port). Network policies are never a hint: switches advertise the voice VLAN too |
| CDP | device ID, platform, software version, port, native VLAN, duplex, capabilities, management/interface IPv4 (802.3 LLC/SNAP to `01:00:0C:CC:CC:CC`) | name; router, switch, bridge, repeater give a network device, the phone capability or an "IP Phone" platform gives a VoIP phone |
| mDNS | records, `<host>.local` name (only when the A/AAAA address is the packet source), `service.<type>` for known service types, `model=` of `_device-info._tcp` | service types give a type hint (see below); Apple model identifiers give Apple/media |
| NetBIOS | name-service replies, and **name registration/refresh broadcasts** (workstation `<00>` / server `<20>` name, workgroup); **browser announcements** on UDP 138 (MS-BRWS Host, Local Master and Domain Announcements in an SMB mailslot `\MAILSLOT\BROWSE` datagram): host name, workgroup (from the destination name, or the name of a Domain Announcement), OS version, server type bits (workstation, server, domain controller, print server, Unix, NT, browser roles ...), comment, master browser | host name; with the Unix bit (Samba) a weak Linux hint, otherwise with the NT bit a weak Windows hint and an `os_hint` from the version (5.1 Windows XP ... 10.0 Windows 10/11 / Server 2016+) |
| SSDP/UPnP | SERVER, ST, NT, USN, LOCATION of NOTIFY and search replies | IGD or `MiniUPnPd` gives a router, MediaRenderer/DIAL/Roku/Sonos a media device, printers and cameras by device type, `Microsoft-Windows` a Windows host |
| WS-Discovery | Hello, ProbeMatches and ResolveMatches on UDP 3702: types, XAddrs, endpoint address (Probe, Resolve and Bye are ignored) | `PrintDeviceType`/`ScanDeviceType` give a printer, `NetworkVideoTransmitter` a camera, `Computer` a weak Windows hint (Samba's `wsdd` also publishes it) |
| DHCP | client messages: option 55 request list, 60 vendor class, 12 host name; server replies as before | `os_hint` and a type hint (Windows 10/11, macOS, iOS, Android, ISC dhclient, IP phones, printers) |
| DHCPv6 | client messages to UDP 547 (Solicit, Request, Confirm, Renew, Rebind, Release, Decline, Information-request; server and relay messages are ignored): DUID as `client_id` with `duid_type` and the DUID's link-layer address `duid_mac` (kept as a field: it may belong to another interface), option 6 request list `oro`, option 16 vendor class and enterprise number, option 39 client FQDN (`fqdn`, first label as `hostname`) | host name; the DUID is a device identifier like the DHCP client identifier; the vendor class and host name go through the DHCP tables (`MSFT 5.0`, `DESKTOP-xxxxxxx` ...). The `oro` list is recorded, not matched against a table |
| Profinet DCP | name, vendor, IDs, IP settings, device role, options, instance, OEM ID | industrial controller |

Device-type hints are stored in the observation as `hint.<category>` (strong) and `hint_weak.<category>` (weak) fields with the reason, and scored like active evidence: a strong hint (40 points) is enough for a device type, a weak one (20) only adds to other evidence, and a weak hint beside a strong one of the same category is ignored. When a passive hint names a specific kind of device, a plain LLDP/CDP announcement no longer counts as a network-device hint. The reason text is never used for keyword matching.

mDNS service types used as hints: `_ipp`, `_ipps`, `_printer`, `_pdl-datastream` (printer); `_airplay`, `_raop`, `_googlecast`, `_sonos` (media); `_hap`, `_matter`, `_hue`, `_esphomelib` (IoT); `_companion-link`, `_apple-mobdev2` (Apple); `_airport` (network); `_axis-video` (camera); weak: `_scanner`, `_rtsp`, `_workstation`, `_smb`, `_adisk`, `_afpovertcp`, `_spotify-connect`, `_mqtt`.

The fingerprint tables (DHCP request lists and vendor classes, default host names such as `DESKTOP-xxxxxxx` and `NPIxxxxxx`, service-type lists) are **heuristics written for this project** and kept small. They are checked against hand-built frames only (the NetBIOS browser decoder also against one real Local Master Announcement in a public capture, see [Lab and testing](lab-and-testing.md)), and a device can announce services it does not offer. Treat the result as a hint. Observations are bounded: the number of distinct `service.*` fields per device comes from a closed list, XML is parsed with DTDs rejected and a size and node limit, and every parser ignores truncated or malformed input.

Not covered: WS-Discovery device metadata (a TCP request to port 5357 would be needed), LLDP-MED location and extended power TLVs, DHCPv6 messages inside a relay, a table of DHCPv6 request lists, and DHCP option 82.

## Not implemented

- **SNMPv3 in the UDP scan**: the built-in `snmp/161` probe sends only SNMPv1/v2c `sysDescr` requests with the community `public`. Reading devices with your own v1/v2c/v3 credentials is a separate option, see [SNMP](snmp.md).
