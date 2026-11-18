# Notes from the service-features wave

Files changed: src/service.rs, src/tls.rs, src/risk.rs, src/osfp.rs, src/udp.rs,
data/probes.json. New: src/fingerprint.rs (MD5, SHA-256, HASSHServer, JA4S), data/cves.json.
src/main.rs got the single line `mod fingerprint;`. No new crates (MD5 and SHA-256 are
implemented in fingerprint.rs and checked against the RFC 1321 / FIPS 180 test vectors;
`ring` is only a transitive dependency of rustls and cannot be named from this crate).

## Requests for other owners

1. **CLI flag `--cves FILE`** (ui.rs / scan settings): call
   `crate::risk::load_cves(Some(Path::new(file)))` before analysis and report its `Err`
   (bad JSON, bad version strings, unknown severity, bad CVE ids, malformed CPE templates).
   Without the flag call `crate::risk::load_cves(None)` once at start-up (CLI and GUI) so a
   broken `%LOCALAPPDATA%/NetworkScope/cves.json` is reported instead of silently replaced by
   the built-in rules. Until this is wired, `risk::cve_db()` lazily loads the default user file
   and falls back to the built-in rules with a message on stderr. `load_cves` is marked
   `#[allow(dead_code)]` until a caller exists; remove the attribute when wiring it.
   GUI: an optional "CVE rules file" path in Settings next to the probe file would call the
   same function.
2. **store.rs `VOLATILE_IDENTITY_SUFFIXES`**: add `".clock_skew"`. The SMB clock offset is stored
   coarsely (`in sync (< 2 min)`, `+5 min`, `+3 h`, `-2 days`) so it is stable while the server
   clock is right, but a drifting server would otherwise show up as an identity change. The raw
   SMB system time is deliberately NOT stored (it would change on every scan).
3. **core.rs (UDP)**: `udp::probe` now picks up the `"proto": "udp"` probes of the probe database
   that `ProbeDb::load(&s.probe_file)` registered (process-global, last load wins). When service
   detection is off, core does not load the probe database, so UDP falls back to the default user
   file / built-in probes and ignores `--probes FILE`. Fix: load the probe database when
   `s.services || s.udp` (the returned value can be dropped when only UDP runs).
4. **core.rs (UDP OT ports, pre-existing behaviour)**: the UDP scan still sends an *empty*
   datagram to any port in the UDP port list, including OT ports such as 47808. Payloads from
   probes.json never go there (`service::is_ot_udp_port`), but consider skipping
   `is_ot_udp_port` ports in the generic UDP loop entirely (the OT identification already
   covers BACnet etc.).
5. **ui.rs `probes` command**: lists only TCP probes (`db.probes`). UDP probes are in `db.udp`
   (same `Probe` struct); list them with a `udp` marker.
6. **devices.rs (device identity)**: `smb.<port>.guid` (SMB server GUID) is stable per Windows
   installation and survives IP/MAC changes (but cloned VMs share it); `smb.<port>.netbios_name`
   and `smb.<port>.dns_name` name the host. Good merge/display keys for device identity.
   `tls.<port>.ja4s` and `ssh.<port>.hassh` identify the server software configuration, not a
   device: do not merge on them.
7. **devices.rs `classify`**: `all_text` / `http_text` scan every identity value (including
   `svc.<port>.*`) for words like "ipp", "printer", "switch", "gateway". The new derived keys
   (`svc.<port>.cpe`, `ssh.<port>.hassh`, `ssh.<port>.hassh_algorithms`, `tls.<port>.ja4s`) are
   not device evidence; filter keys ending in those suffixes out, as osfp.rs now does. No false
   match is known with the shipped CPE table, but user CPE templates are free text.
8. **JARM (`jarm` setting)**: not implemented, so no flag needed. JARM needs 10 specially crafted
   ClientHellos per port with exact cipher orderings, GREASE and ALPN variants; a non-byte-exact
   implementation produces hashes that do not match public JARM databases, which is worse than
   none, and 10 extra connections per TLS port exceed what Safe Mode should spend.

## README text (please merge)

### Services: SMB
The SMB2 NEGOTIATE now offers dialects 2.0.2 to 3.1.1 with the 3.1.1 negotiate contexts
(preauth integrity SHA-512, encryption AES-128/256-CCM/GCM, compression LZNT1/LZ77/
LZ77+Huffman/Pattern_V1/LZ4, signing HMAC-SHA256/AES-CMAC/AES-GMAC) and client capabilities
set, so the server reports its own. On the same connection a credential-less SESSION_SETUP
carrying an NTLMSSP NEGOTIATE asks for the NTLM challenge; the exchange stops there (no
AUTHENTICATE message, so no logon attempt and no failed-logon event). New identity keys:

| key | content |
|---|---|
| `smb.<port>.dialect` | 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1 |
| `smb.<port>.guid` | server GUID |
| `smb.<port>.capabilities` | DFS, leasing, large MTU, multichannel, persistent handles, directory leasing, encryption, notifications |
| `smb.<port>.encryption` | negotiated cipher (3.1.1), `supported` (3.0/3.0.2 capability), `not supported`, `not supported (SMB 2.x)` |
| `smb.<port>.compression` | algorithms the server accepted, `(chained)` when chaining is on, or `none` (3.1.1 only) |
| `smb.<port>.signing_algorithms`, `smb.<port>.preauth_integrity` | 3.1.1 contexts |
| `smb.<port>.clock_skew` | server clock against the scanner, coarse |
| `smb.<port>.boot_time` | server start date when the server reports it (old Windows) |
| `smb.<port>.auth_mechs` | Kerberos / NTLM / NEGOEX from the SPNEGO hint |
| `smb.<port>.os_version` | NTLM version `major.minor.build` (Samba reports 6.1.0) |
| `smb.<port>.netbios_name`, `netbios_domain`, `dns_name`, `dns_domain`, `dns_forest` | from the NTLM challenge |

New findings: `smb-no-encryption` (Info) when the server offers no SMB encryption;
`cve-cve-2020-0796` (High, version-based hint) only when the dialect is 3.1.1, compression is
accepted and the NTLM build is 18362 or 18363 (Windows 10 / Server 1903 and 1909). The patch
level (KB4551762) is not visible remotely, so a patched host is reported as well; never raised
on compression alone.

### Services: TLS
When the handshake negotiated TLS 1.3, raw TLS 1.3-only ClientHellos (supported_versions 1.3,
key_share x25519 with random bytes; no key is derived, only the ServerHello is read) enumerate
the five TLS 1.3 suites: each round offers the suites not chosen yet until the server refuses,
at most `min(rounds, 6)` hellos (typically 4 for a server with 3 suites). A HelloRetryRequest
counts as acceptance of its suite. New keys `tls.<port>.tls13_suites`, `TLS1.3:` part in
`tls.<port>.ciphers`, `TLS1.3` in `suites_truncated_versions` when the budget ran out.
TLS_AES_128_CCM_8_SHA256 is listed in `tls.<port>.weak` (truncated tag), without a finding.
Servers that did not negotiate TLS 1.3 get no extra connection.

`tls.<port>.ja4s`: JA4S-style server fingerprint (`t<ver><ext count><alpn>_<cipher>_<sha256 of
the extension list, 12 hex>`, FoxIO JA4S format) of the first full-offer hello the server
accepted: the TLS 1.3 hello when TLS 1.3 was negotiated, else the TLS 1.2 (or highest legacy)
all-suites hello. Our hellos offer no ALPN, so the ALPN part is `00`. Values are comparable
between NetworkScope scans; they match JA4S from other tools only when those used a similar
client hello (JA4S depends on what the client offered).

### Services: SSH
`ssh.<port>.hassh`: HASSHServer, MD5 of `kex;enc_s2c;mac_s2c;comp_s2c` from the raw
server KEXINIT name-lists; `ssh.<port>.hassh_algorithms` holds the hashed string.

### CVE rules and CPE names
The version-based CVE table moved to `data/cves.json` (built in). A user file
`%LOCALAPPDATA%/NetworkScope/cves.json` or `--cves FILE` merges like probes.json: a rule or CPE
entry with the same `id` replaces the built-in one, new ids are added. Rule fields: `id`,
`product` (lower-case substring of the detected product), optional `exclude` (product
substrings the rule does not apply to, e.g. `for windows`), optional `min` (inclusive) and `max`
(exclusive) as dotted versions with optional `pN` (`8.5p1`), `severity`
(info/low/medium/high/critical), `cve` (non-empty list of `CVE-YYYY-NNNN`; the finding id is
`cve-<first cve>`), `title`. Loading fails with a message naming the file and rule on a bad
version string, min not below max, unknown severity, empty or malformed CVE list.
`cpe` entries (`id`, exact lower-case `products`, `template` with `{version}`, `{base}`,
`{update}`) produce identity `svc.<port>.cpe`, e.g.
`cpe:2.3:a:openbsd:openssh:7.4:p1:*:*:*:*:*:*`. Versions are cut at the first character that is
not a letter, digit, `.` or `_` (distribution suffixes like `-0ubuntu0.22.04.2` are dropped) and
must start with a digit.

### UDP payload probes
probes.json entries with `"proto": "udp"` (needs `ports` and `send`/`send_hex`, rules as for TCP)
are sent as one datagram to listed UDP ports that have no built-in handler (instead of the empty
datagram); a matching rule becomes the `udp.<port>` text (`ms-sql-m Microsoft SQL Server
15.0.2000.5 (server SQL01, instance MSSQLSERVER)`). Built in: SQL Server Browser (1434),
rpcbind NULL call (111), memcached `version` (11211), SIP OPTIONS (5060). User probes merge by
name like TCP probes (a name can move between TCP and UDP). Probes listing an industrial or
printer port are rejected when loading, and nothing from probes.json is ever sent to those
ports: the TCP OT list plus 2222, EtherNet/IP 2221-2223, BACnet/IP 47808-47823, Profinet
34962-34964, DNP3 20000, FF HSE 1089-1091, MELSEC 5006/5007, CODESYS 1740-1743, EtherCAT 34980,
VxWorks WDB 17185, printer 515 and 9100-9107.

### OS guess
New evidence: the SMB NTLM version (Windows release and build, strong; NTLM build 0 = Samba,
counted as Linux), Dropbear SSH (embedded), Cisco/MikroTik SSH banners (network device).
CPE and fingerprint keys (`.cpe`, `.hassh`, `.ja4s`) are excluded from OS evidence (the OpenSSH
CPE vendor `openbsd` must not count as BSD).

## Safety notes

- Every new connection or datagram goes through the gate (`gate.wait()` before each TLS 1.3
  hello; the SMB session setup reuses the negotiate connection, no extra connection).
- Safe Mode: TLS 1.3 enumeration spends at most `min(rounds, 6)` hellos and only on servers
  that negotiated TLS 1.3. SMB: still two connections (SMB2 with session setup, SMB1).
- Printer ports and 2222 still return before any of this (listen-only policies); core still
  skips `is_ot_port` ports for service detection.

## Verification and open points

- SMB was checked once against a real Windows 11 SMB server (127.0.0.1:445, temporary ignored
  test, removed again): SMB 3.1.1, signing required, non-zero GUID, encryption AES-128-GCM,
  compression "LZNT1, Pattern_V1", signing AES-GMAC, preauth SHA-512, SPNEGO mechs
  Kerberos/NEGOEX/NTLM, NTLM os_version 10.0.26100 (the machine reports build 26300; NTLM carries
  the base build), NetBIOS name equal to %COMPUTERNAME%, SMB1 refused. Not checked against Samba.
- JA4S format follows the FoxIO spec as I know it; not cross-checked against the reference
  implementation on captured traffic. TLS 1.3 enumeration is tested against rustls and a raw
  test server, not against OpenSSL/Schannel servers.
- Samba's NTLM version (6.1, build 0) is from memory of Samba's source; the OS guess calls it
  "Samba-style" and weights it lightly.
- CPE vendor/product names in data/cves.json (e.g. `beasts:vsftpd`, `f5:nginx`,
  `filezilla-project:filezilla_server`) are from memory of the NVD dictionary; spot-check them
  against NVD before relying on CPE matching.
- One-time identity diff: `tls.<port>.ciphers` now starts with a `TLS1.3:` part on TLS 1.3
  servers, so the first scan after this change reports that key as changed.
