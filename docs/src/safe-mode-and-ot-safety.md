# Safe Mode and OT safety

## Safe Mode

**Safe Mode is enabled by default** in the desktop and on the CLI. `--fast` (or unchecking Safe Mode) turns it off.

| | Safe Mode (default) | `--fast` |
| --- | --- | --- |
| Active hosts at once | at most 8 | `--workers` (default 1024, max 4096) |
| Spacing between application probes | at least 100 ms (token bucket) | none, unless `--rate PPS` |
| Port probes per host in parallel | at most 4 | `--parallel` (default 64) |
| SYN scan, ARP sweep | disabled | opt-in |
| Traceroute | ICMP only | ICMP, TCP, UDP |
| SMB NTLM SESSION_SETUP | not sent | sent (no AUTHENTICATE) |
| TLS 1.3 suite enumeration | not sent | sent |
| OT operations | identification only | identification only |

In the desktop the disabled controls are greyed out. Safe Mode is a conservative traffic profile, **not a guarantee** for every PLC.

## Rules that always apply

These hold with Safe Mode on or off:

- All OT protocol operations are **read-only identification**: no writes, no program or block access, no control commands, no authentication. See [OT / industrial](ot-industrial.md) for exactly what is sent.
- OT identification runs only on standard ports. TCP probes go only to hosts with that port open; a silent host gets at most one BACnet Who-Is, and only when nonresponders are scanned.
- Generic service probes never touch industrial ports (102, 502, 4840, 44818, 47808 and similar).
- Printer ports 9100-9107 and 515 only get a passive banner wait; nothing is ever sent.
- 2222/tcp is listen-only unless it greets with SSH.
- The UDP scan never sends to industrial or printer ports; such ports in `--udp-ports` are skipped with a host note and probes listing them are rejected.
- TCP traceroute never uses OT or printer ports.
- Passive modes (`listen`, `ot-listen`, pcap import) send nothing. A test fails the build if the passive modules contain socket or send code.
- Nothing scans automatically; every scan starts with an explicit Start or command.

## The read-only promise is a type, not a convention

The active OT code (`src/ot.rs`, `src/ot/`) cannot send a write or control request, because such a request has no value in the type system:

- Every OT request is built by `ot::readonly` from an **allow-list enum**: `ModbusFunction`, `S7Szl`, `EnipCommand`, `BacnetService`, `OpcUaMessage`. The request types (`ModbusRequest`, `S7Request`, `EnipRequest`, `BacnetRequest`, `OpcUaRequest`) have private fields, so the enums are the only way in.
- The only functions that put OT bytes on a socket, `OtStream::send` and `OtUdp::send`, accept nothing but a `ReadOnlyRequest`. That trait is sealed (only `ot::readonly` implements it) and is not implemented for `&[u8]`. The rest of the OT code holds sockets only through these wrappers, which can read but not write; a test fails the build if `ot.rs` or `ot/opcua.rs` use a raw socket or `write_all`.
- Sending anything else needs a **new enum variant**, which is a reviewed code change, and the tests fail until the allow-list in the test is changed deliberately too.

What the allow-lists contain (exactly what is sent today):

| Protocol | Allowed |
| --- | --- |
| Modbus/TCP | function 0x2B with MEI type 0x0E (Read Device Identification); not the other MEI types (for example 0x0D CANopen), not any write or diagnostic function |
| S7comm | COTP connection request, Setup communication (job function 0xF0), Userdata CPU functions / Read SZL for SZL 0x0011 and 0x001C; no Read/Write Var, PLC control or stop, download, upload or block access |
| EtherNet/IP | encapsulation command 0x0063 (List Identity); no SendRRData, SendUnitData or sessions |
| BACnet/IP | unicast Who-Is (unconfirmed service 8); no confirmed requests (ReadProperty, WriteProperty, ReinitializeDevice) and no broadcast BVLC function |
| OPC UA | HEL, OpenSecureChannel (node 446), GetEndpoints (428), FindServers (422), CloseSecureChannel (452), SecurityPolicy None; no CreateSession, Read, Write or Call |

Tests (`cargo test`) check this for every possible byte: all 256 function codes (and all 65,536 MEI/group/subfunction pairs, EtherNet/IP commands and OPC UA node IDs) are accepted by the constructors exactly when they are on the allow-list, every encoded request decodes back to an allow-listed service, changing any discriminator byte of an encoded request to any other value is rejected, and the encoded bytes equal the literals used before the types existed. `compile_fail` doctests in `ot::readonly` show that a Modbus write, an S7 stop and a raw `&[u8]` send do not compile.

Limits of the guarantee: it covers the active OT requests listed above. The Profinet DCP Identify frame (`dcp`, built in `passive.rs`) and the generic service probes are separate code paths with their own tests and deny lists, and the type does not say anything about what a device does with a read-only request.

## Recommendations for plant networks

- Read-only traffic can still affect fragile equipment. Older controllers, serial gateways and devices with small TCP stacks may slow down, drop connections or fault under any active traffic.
- **Prefer passive discovery** (`ot-listen` on a SPAN port or an existing capture) on production OT networks.
- Coordinate with operations before an active scan, scan during a maintenance window, and start with a small target range.
- Keep Safe Mode on. Do not use `--fast`, `--syn` or `--arp-sweep` against control networks.
- Know how to stop: Stop in the desktop, or Q/Escape in the TUI, saves what was collected.

See also [Responsible use](responsible-use.md).
