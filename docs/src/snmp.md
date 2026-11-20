# SNMP (read-only, with your credentials)

`--snmp-community` (or `--snmp-community-env`) and `--snmp-v3` make a scan read every responding host over SNMP: the system group, the interfaces and their short names, the IPv4 and IPv6 addresses and the LLDP neighbours. That names the device, gives its engine ID as a strong [identity](device-identity.md) and draws real links in the topology (`devices topology`).

Off by default. A scan without these options sends no SNMP request of its own.

## How this differs from the `snmp-public` check

The UDP scan (`--udp`, port 161 in its default list) sends one GetRequest for `sysDescr` with the community `public` (SNMPv2c, then SNMPv1) to every host it probes, and the [`snmp-public` finding](findings/snmp-public.md) reports an answer. That is a check *for* a well-known default, not a way to read devices.

The SNMP read described here is a different code path:

- It uses the community or the SNMPv3 user **you give it**. It is never `public` unless you type `public`.
- It never tries a list of communities and never guesses a user or password. A wrong community is one request with two attempts; the host is then treated like any host without an agent (silence is not an error and is not noted on the host).
- It runs only against hosts that answered something else, and only when credentials were given.

## Options

| Option | Meaning |
| --- | --- |
| `--snmp-community STRING` | SNMPv2c with this community (SNMPv1 with `--snmp-version 1`). Used for this run only; it is **not saved** |
| `--snmp-community-env NAME` | The same, but the community is read from the environment variable `NAME`. Only the name is saved (see [Saved settings](#saved-settings-scheduled-scans-services-replay)) |
| `--snmp-v3 USER[:AUTH:AUTH_ENV[:PRIV:PRIV_ENV]]` | SNMPv3 (USM). `AUTH` is `sha` (HMAC-SHA-1-96), `sha256` (HMAC-192-SHA-256) or the **weak** `md5` (HMAC-MD5-96); `PRIV` is `aes` (AES-128-CFB) or the **weak** `des` (DES-CBC). `AUTH_ENV` and `PRIV_ENV` are **names of environment variables**; the passphrases are never taken from the command line. A passphrase must have at least 8 characters |

Security levels: `USER` alone is noAuthNoPriv, `USER:sha:ENV` is authNoPriv, and the five-part form is authPriv. A community string is sent in clear text and is visible on the command line and in the process list; prefer SNMPv3 where the device supports it.

### MD5 and DES are weak

Older devices (and some current ones configured years ago) offer nothing but `usmHMACMD5AuthProtocol` and `usmDESPrivProtocol`. Network Scope can use them, only when you name `md5` or `des`, never as a default and never as a fallback after a better algorithm failed. **MD5** is broken as a hash (collisions are cheap); as the keyed MAC of USM it is not trivially forgeable, but it has little margin left. **DES** has a 56-bit key and can be searched exhaustively; the encryption of an SNMPv3 message with DES should be treated as obfuscation. A scan that uses either prints a warning (`SNMP warning: ...`) and the host's `snmp.version` names the algorithms (`v3 authPriv MD5 DES`), so a stored scan shows that a weak pair was used. Prefer `sha256` and `aes`, and replace the devices that cannot do it. MD5 and DES do not make a scan more dangerous for the device: the requests are the same read-only Get, GetNext and GetBulk.

```sh
export SNMP_AUTH='a long passphrase'
export SNMP_PRIV='another long passphrase'
network-scope-cli scan 10.0.0.0/24 --snmp-v3 monitor:sha256:SNMP_AUTH:aes:SNMP_PRIV
```

## What is sent

Only GetRequest, GetNextRequest (SNMPv1) and GetBulkRequest (v2c and v3) PDUs. There is no SetRequest, InformRequest or trap anywhere in the code: the PDU type is a closed list (`SnmpPdu`), a request has no public fields, and the socket wrapper (`SnmpSocket`) accepts only an encoded request, never raw bytes. `compile_fail` doctests in `snmp` show that a SetRequest does not compile, and tests check every PDU tag byte, like the OT read-only types.

Per host, in this order: one GetRequest for `sysDescr`, `sysObjectID`, `sysUpTime`, `sysName` and `sysLocation` (`sysUpTime` is read but not stored: it changes in every scan and would appear in every diff; an agent that lacks one of them is walked instead); the LLDP-MIB `lldpRemChassisId` column, and only when that has rows the other `lldpRem` columns (`lldpRemChassisIdSubtype`, `lldpRemPortIdSubtype`, `lldpRemPortId`, `lldpRemPortDesc`, `lldpRemSysName`) and the local port names (`lldpLocPortDesc`); `ifDescr`, `ifPhysAddress` and `ifOperStatus`; `ipAdEntIfIndex` and `ipAdEntNetMask`; and last, so that a small budget (Safe Mode) goes to the older tables first, `ifName` (IF-MIB `ifXTable`, the short port name such as `Gi1/0/1`) and `ipAddressIfIndex` (IP-MIB `ipAddressTable`, which also lists IPv6 addresses; its row index is the address, including the zoned address types, and an IPv4 address that the older table already has is not listed twice).

SNMPv3 starts with one unauthenticated discovery request (empty engine ID and user name, no variable bindings) to learn the agent's engine ID, boots counter and clock, then localises the keys (RFC 3414) and sends authenticated, optionally encrypted requests. Replies must carry a valid HMAC (and be encrypted when the request was); an unauthenticated Response to an authenticated request is refused. When the agent's clock has moved on (`usmStatsNotInTimeWindows`), the session adopts the agent's boots and time once and repeats the request.

Limits, per host: at most 240 datagrams and 25 seconds (retransmissions and the rate gate's waiting included), at most 128 interface rows, 64 addresses and 64 LLDP neighbours; a limit that is reached ends the walk and is noted on the host (`SNMP: ...`). Every datagram takes a token from the rate gate, is counted in the sent log as `snmp-request` with its PDU and version, and is listed by `--dry-run`.

## Safe Mode

SNMP is allowed in Safe Mode because the credentials are the opt-in and every request is a read. Safe Mode uses smaller GetBulk pages (10 instead of 20 rows), at most 100 datagrams and 40 seconds per host, and the Safe Mode rate gate (at least 100 ms between probes) applies to every datagram.

## Saved settings: scheduled scans, services, replay

A scan's settings are saved with it (inventory database, JSON export), and the desktop keeps its settings between runs. The SNMP setting is saved as **names only**: for `--snmp-v3` the spec itself (the user name, the protocols and the names of the environment variables), for `--snmp-community-env` the version and the variable name. The community string and the passphrases are never written anywhere: they exist in memory while a scan runs, are read from the environment each time a scan starts, and the saved form has no field they could be in. A test runs scans against a test agent with marker secrets and searches the database file, its write-ahead log, the JSON, JSON Lines, Markdown and HTML exports and the debug output for them.

What that gives you:

- **Desktop:** Settings has a "Read devices over SNMP" section (off, community, SNMPv3 user) where you type the *names* of the variables. A scheduled scan uses the saved setting and reads the variables when it starts. Set them in the environment the desktop is started from.
- **`monitor` and `service`:** the options are part of the command line (`service install` stores the command line in the service configuration). `--snmp-community STRING` is therefore refused by `service install`; use `--snmp-community-env NAME` or `--snmp-v3`, and set the variables in the environment of the service (for a Windows service: system-wide variables or the service's environment).
- **`scan --replay-check ID`:** repeats a stored scan with the stored settings, so the SNMP setting is read again from the same variable names. A community that was typed with `--snmp-community` has no saved form and is not read again.
- **A variable that is not set** where the scan runs does not stop the scan and is not skipped quietly: nothing is sent over SNMP, and every responding host gets the note `SNMP not read: environment variable NAME is not set`. `--dry-run` says the same.

## Results

The host identity gets these keys (all text from the device is stripped of control characters and cut to 255 characters):

| Key | Content |
| --- | --- |
| `snmp.version` | `v2c`, `v1` or the v3 level, for example `v3 authPriv SHA-256 AES-128` |
| `snmp.sysdescr`, `snmp.sysobjectid`, `snmp.sysname`, `snmp.location` | the system group |
| `snmp.engine_id` | the SNMPv3 engine ID in lower-case hex; [device identity](device-identity.md) treats it as a strong identifier |
| `snmp.if.<ifIndex>` | `description; MAC; up/down/...` |
| `snmp.ifname.<ifIndex>` | the short port name (`ifName`); the topology names a link's local port with it when the agent has no LLDP local port description |
| `snmp.ip.<address>` | `ifIndex N, mask M` for an IPv4 address of the older table; `ifIndex N` for an IPv6 address (and an IPv4 address only the newer table has) |
| `snmp.lldp.<n>.local_port`, `.local_port_desc`, `.sys_name`, `.port_id`, `.chassis_id`, `.port_desc` | one LLDP neighbour; `local_port` is `lldpRemLocalPortNum`, `local_port_desc` its name from the LLDP local port table (`lldpLocPortDesc`; the port number is not necessarily the `ifIndex`) |

`snmp.sysdescr` also feeds the OS guess like the UDP scan's `sysDescr`. The LLDP neighbours become **links** in the topology: a neighbour is matched to a scanned host by its chassis MAC (the host's own or one of its interfaces) or by system name; a neighbour that no scanned host matches becomes a node of its own. `topology ID --format ascii` lists them under "Links (LLDP ...)", `--format dot` draws them dashed with the port at each end. Both ends of a link usually report each other; the pair is listed once.

## What has been tested, and what has not

Tested against published values: the BER encoder and decoder (lengths, integers, OIDs, every truncation); the key derivation and localisation against RFC 3414 appendix A.2 and A.3 for **MD5** (`526f5eed...`, A.3.1) and SHA (`6695febc...`, A.3.2); MD5 against the RFC 1321 test suite and HMAC-MD5 against RFC 2202; HMAC-SHA-1 and HMAC-SHA-256 against RFC 2202 and RFC 4231; the AES-128 block cipher and CFB mode against FIPS-197 and NIST SP 800-38A; **DES** against the FIPS 46 worked example, the NIST SP 800-17 known answers and the FIPS 81 CBC example (the same values were reproduced with `pycryptodomex`). MD5 and DES are written out in `core/src/snmp/md5.rs` and `des.rs` because `ring` has neither; they are table- or bit-by-bit implementations, not constant-time, and the key is derived from a passphrase you gave for your own agents.

Tested with complete sessions: v1, v2c and v3 (every combination of noAuthNoPriv, MD5, SHA-1 and SHA-256 authentication with no privacy, AES and DES; wrong passwords, unknown users, clock resynchronisation, limits) against a simulator agent written for the tests, and against the lab simulator (`lab/simulators.py`, UDP 161 on loopback; `lab/verify.py` scans it with v2c, v1, v3 SHA-1 and v3 MD5, and counts the PDUs the agent received).

**Cross-checked against an independent implementation (pysnmp).** `lab/interop/pysnmp_agent.py` is a command responder made with pysnmp 7.1.33 (Python 3.13.17, `cryptography` 50.0.2, Windows 11, 2026-11-20); `lab/interop/run_pysnmp_check.py` starts it on a free loopback port and runs the ignored test `pysnmp_agent_accepts_every_v3_level_and_its_replies_decode`, in which this scanner reads that agent: noAuthNoPriv, authNoPriv with MD5, SHA-1 and SHA-256, and authPriv with each of those and AES-128 and DES (ten SNMPv3 users), SNMPv2c and SNMPv1, plus a wrong authentication passphrase for every authenticated user. Result: every one of the ten v3 levels, v2c and v1 returned the agent's system group, and every wrong passphrase was refused. So the key localisation, the HMACs (including SHA-256, for which RFC 3414 has no vector), AES-CFB and DES-CBC, the IV rules and the message layout match code that shares nothing with this project, in both directions (pysnmp authenticated and decrypted our requests; we verified and decrypted its replies). pysnmp's own request counters after the run (which PDUs it received, by user and security level): 84 requests in total, 12 GetRequest, 66 GetBulkRequest, 6 GetNextRequest, **no other PDU type**; 7 per v3 level, 7 for v2c and 7 for v1 (the wrong-passphrase attempts are rejected by pysnmp before they are counted). Without the `cryptography` package pysnmp 7 cannot decrypt anything, so every authPriv request ends in a decryption error; the run documents that.

Not tested: any real device (Net-SNMP, a switch, a router). The interoperability check shows the protocol layer, not how a particular firmware behaves with `ipAddressTable` or `ifXTable`. The pysnmp agent serves only the standard MIB-II system and snmp groups, so the interface, address and LLDP tables are read from the test agent and the lab simulator, not from pysnmp. Report a device that does not interoperate.

Not implemented: AES-192/256, SHA-384/512 (and SHA-224), SNMP over TCP or DTLS, and writing anything.
