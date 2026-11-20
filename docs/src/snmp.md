# SNMP (read-only, with your credentials)

`--snmp-community` and `--snmp-v3` make a scan read every responding host over SNMP: the system group, the interfaces, the IPv4 addresses and the LLDP neighbours. That names the device, gives its engine ID as a strong [identity](device-identity.md) and draws real links in the topology (`devices topology`).

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
| `--snmp-community STRING` | SNMPv2c with this community (SNMPv1 with `--snmp-version 1`) |
| `--snmp-v3 USER[:AUTH:AUTH_ENV[:PRIV:PRIV_ENV]]` | SNMPv3 (USM). `AUTH` is `sha` (HMAC-SHA-1-96) or `sha256` (HMAC-192-SHA-256), `PRIV` is `aes` (AES-128-CFB). `AUTH_ENV` and `PRIV_ENV` are **names of environment variables**; the passphrases are never taken from the command line. A passphrase must have at least 8 characters |

Security levels: `USER` alone is noAuthNoPriv, `USER:sha:ENV` is authNoPriv, and the five-part form is authPriv. MD5 and DES are not offered. A community string is sent in clear text and is visible on the command line and in the process list; prefer SNMPv3 where the device supports it.

```sh
export SNMP_AUTH='a long passphrase'
export SNMP_PRIV='another long passphrase'
network-scope-cli scan 10.0.0.0/24 --snmp-v3 monitor:sha256:SNMP_AUTH:aes:SNMP_PRIV
```

## What is sent

Only GetRequest, GetNextRequest (SNMPv1) and GetBulkRequest (v2c and v3) PDUs. There is no SetRequest, InformRequest or trap anywhere in the code: the PDU type is a closed list (`SnmpPdu`), a request has no public fields, and the socket wrapper (`SnmpSocket`) accepts only an encoded request, never raw bytes. `compile_fail` doctests in `snmp` show that a SetRequest does not compile, and tests check every PDU tag byte, like the OT read-only types.

Per host, in this order: one GetRequest for `sysDescr`, `sysObjectID`, `sysUpTime`, `sysName` and `sysLocation` (`sysUpTime` is read but not stored: it changes in every scan and would appear in every diff; an agent that lacks one of them is walked instead); the LLDP-MIB `lldpRemChassisId` column, and only when that has rows the other `lldpRem` columns (`lldpRemChassisIdSubtype`, `lldpRemPortIdSubtype`, `lldpRemPortId`, `lldpRemPortDesc`, `lldpRemSysName`) and the local port names (`lldpLocPortDesc`); `ifDescr`, `ifPhysAddress` and `ifOperStatus`; `ipAdEntIfIndex` and `ipAdEntNetMask`.

SNMPv3 starts with one unauthenticated discovery request (empty engine ID and user name, no variable bindings) to learn the agent's engine ID, boots counter and clock, then localises the keys (RFC 3414) and sends authenticated, optionally encrypted requests. Replies must carry a valid HMAC (and be encrypted when the request was); an unauthenticated Response to an authenticated request is refused. When the agent's clock has moved on (`usmStatsNotInTimeWindows`), the session adopts the agent's boots and time once and repeats the request.

Limits, per host: at most 240 datagrams and 25 seconds (retransmissions and the rate gate's waiting included), at most 128 interface rows, 64 addresses and 64 LLDP neighbours; a limit that is reached ends the walk and is noted on the host (`SNMP: ...`). Every datagram takes a token from the rate gate, is counted in the sent log as `snmp-request` with its PDU and version, and is listed by `--dry-run`.

## Safe Mode

SNMP is allowed in Safe Mode because the credentials are the opt-in and every request is a read. Safe Mode uses smaller GetBulk pages (10 instead of 20 rows), at most 100 datagrams and 40 seconds per host, and the Safe Mode rate gate (at least 100 ms between probes) applies to every datagram.

## Results

The host identity gets these keys (all text from the device is stripped of control characters and cut to 255 characters):

| Key | Content |
| --- | --- |
| `snmp.version` | `v2c`, `v1` or the v3 level, for example `v3 authPriv SHA-256 AES-128` |
| `snmp.sysdescr`, `snmp.sysobjectid`, `snmp.sysname`, `snmp.location` | the system group |
| `snmp.engine_id` | the SNMPv3 engine ID in lower-case hex; [device identity](device-identity.md) treats it as a strong identifier |
| `snmp.if.<ifIndex>` | `description; MAC; up/down/...` |
| `snmp.ip.<address>` | `ifIndex N, mask M` |
| `snmp.lldp.<n>.local_port`, `.local_port_desc`, `.sys_name`, `.port_id`, `.chassis_id`, `.port_desc` | one LLDP neighbour; `local_port` is `lldpRemLocalPortNum`, `local_port_desc` its name from the LLDP local port table (`lldpLocPortDesc`; the port number is not necessarily the `ifIndex`) |

`snmp.sysdescr` also feeds the OS guess like the UDP scan's `sysDescr`. The LLDP neighbours become **links** in the topology: a neighbour is matched to a scanned host by its chassis MAC (the host's own or one of its interfaces) or by system name; a neighbour that no scanned host matches becomes a node of its own. `topology ID --format ascii` lists them under "Links (LLDP ...)", `--format dot` draws them dashed with the port at each end. Both ends of a link usually report each other; the pair is listed once.

## What has been tested, and what has not

Tested: the BER encoder and decoder (lengths, integers, OIDs, every truncation), the key localisation against RFC 3414 appendix A.3.2 (SHA), HMAC-SHA-1 and HMAC-SHA-256 against RFC 2202 and RFC 4231, the AES-128 block cipher and CFB mode against FIPS-197 and NIST SP 800-38A, and complete v1, v2c and v3 sessions (all five security levels, wrong passwords, unknown users, clock resynchronisation, limits) against a simulator agent written for the tests and against the lab simulator (`lab/simulators.py`, UDP 161 on loopback, a small MIB with LLDP rows; `lab/verify.py` scans it).

Not tested: any real device. The SHA-256 key localisation has no published RFC 3414 vector (SHA-256 came with RFC 7860); the expected value was computed independently with Python's `hashlib`. The AES-CFB privacy path and the SNMPv3 message layout are checked against the standards' test vectors and against an agent written by the same author, not against Net-SNMP or a switch. The block cipher is a table-driven implementation (`ring` exposes AES only inside its AEAD constructions) and not constant-time; the key is derived from a passphrase you gave for your own agents. Report a device that does not interoperate.

Not implemented: MD5 authentication, DES privacy, AES-192/256, SHA-384/512, the IPv6 address table (`ipAddressTable`), the interface extension table (`ifName`), SNMP over TCP or DTLS, and writing anything.
