# OT / industrial

Network Scope identifies industrial devices in two ways: **active identification** with single read-only requests on standard ports, and **passive discovery** from captured traffic, which sends nothing. Read [Safe Mode and OT safety](safe-mode-and-ot-safety.md) before using either on a production network.

## Active identification (`--ot`)

All OT operations are identification-only, even when Safe Mode is off. OT identification probes standard ports only, and only for hosts that responded to something (ARP, ICMP, any TCP answer or UDP).

In the desktop, select **Use industrial ports** and enable nonresponders to find ICMP-silent TCP services. The CLI does both when `--ot` is used without `--ports` (ports `80,443,102,502,1883,1911,4840,9600,44818`).

| Protocol | Port | What is sent | What is read |
| --- | --- | --- | --- |
| Modbus/TCP | 502 | One Read Device Identification request (function 43/14), configurable unit ID (`--unit`) | Vendor, product, firmware when returned; additional object pages are marked partial |
| S7comm | 102 | COTP connection, communication setup, read-only SZL 0x0011/0x001C, configurable rack/slot (`--rack`, `--slot`) | Order code, CPU type, firmware, serial when advertised |
| EtherNet/IP | 44818 | TCP List Identity | Vendor ID (with ODVA vendor name), product, serial, revision |
| BACnet/IP | 47808/udp | One unicast Who-Is per IPv4 target (responding hosts, plus silent hosts when nonresponders are scanned) | Device instance |
| OPC UA | 4840 | UA Binary HEL/OpenSecureChannel, GetEndpoints and FindServers without a session, CloseSecureChannel | Names, application/product URIs, security policies, certificate DER as hex |
| Omron FINS | 9600/udp | One Controller Data Read (command 0x0501), the 13-byte frame of a real capture, to hosts that answered something else | Controller model and version strings |
| Niagara Fox | 1911 | The `fox a 1 -1 fox hello` message (what nmap's `fox-info` sends; no authentication) | Station name, application, VM and OS versions, host name and ID |
| MQTT | 1883 | CONNECT (clean session, no credentials, no will) and DISCONNECT; no SUBSCRIBE or PUBLISH. Not sent with `--services`, whose MQTT service probe already sends the same CONNECT | The broker's CONNACK: accepted, or authentication / client ID required |
| KNXnet/IP | 3671/udp | One unicast DESCRIPTION_REQUEST (never the multicast search, no connection or tunnelling), to hosts that answered something else | Friendly name, individual address, serial number, MAC, medium, supported services |

Details and limits:

- **S7**: segmented SZLs, denied access and unsupported devices return explicit errors. No S7plus, authentication, program/block access or control operations.
- **2222/tcp**: only an SSH greeting leads to SSH probing; anything else is treated as industrial (EtherNet/IP) and gets the `ot-reachable` finding.
- **BACnet/IP**: waits the port timeout clamped to 200-2000 ms; ICMP port unreachable means "no BACnet" without an error. Silent hosts get this Who-Is only when nonresponders are scanned (the CLI does with `--ot`), so a device that answers only BACnet/IP is found; each silent address costs at most that wait. No broadcast and no property writes. IPv6 BACnet and forwarded/router NPDU forms are not supported.
- **OPC UA**: only unsecured sessionless discovery is supported; servers denying it produce errors. The product URI is not a verified manufacturer identity. Discovery certificates are inventory data, not trusted certificates. Message sizes, chunk counts and parser recursion are bounded.
- **FINS, Fox, MQTT, KNX**: the requests are the allow-listed ones in `ot::readonly` (a write, Run/Stop, a PUBLISH, a tunnelling frame or an authentication have no value in the types, and the tests check every code byte). The UDP requests (FINS, KNX) go only to hosts that answered something else, never to silent hosts; BACnet remains the only OT request a silent host can get. The FINS request frame is byte for byte the one in `tests/fixtures/ics/omron_test.pcap`; the Fox hello has the layout of the client hello in `fox_info.pcap`. The MQTT and KNX layouts come from the MQTT 3.1.1 and KNXnet/IP specifications and have **no capture** among the fixtures; they have been run against the lab simulators only. FINS over TCP is not sent.
- **Not sent**: IEC 61850 MMS (an association needs the ISO session, presentation and ACSE layers, whose bytes this project cannot cite from a capture), DNP3 (a request needs the outstation's link address, which cannot be guessed, and the broadcast addresses are never used), MELSEC (the MC protocol port is user-configured and the MELSOFT capture is another protocol) and CODESYS. These are passive only.
- **Profinet DCP**: `dcp --interface ID --source-mac MAC` (or the desktop's DCP Identify button) sends one read-only Identify multicast request. It never assigns IPs or names and never changes a device.

Generic service probes and the UDP scan never touch industrial ports; see [Detection](detection.md).

## Passive OT discovery

```sh
network-scope-cli ot-listen --pcap plant.pcapng --progress
network-scope-cli ot-listen --interface ID --seconds 600
network-scope-cli ot-assets ID --format csv --output assets.csv
```

Passive mode (`ot-listen`) reads traffic and never transmits. A live capture goes through a wrapper with no send call, and a test fails the build if the passive modules contain socket or send code.

- **Capture files** are parsed in pure Rust: pcap and pcapng with Ethernet, Linux cooked (SLL/SLL2, e.g. `tcpdump -i any`) and raw IP link types, pcapng `if_tsresol` (nanosecond captures), FCS stripping. Other link types fail with a message naming the type. `--progress` prints percent, frames and frames/s on stderr.
- **Recognised protocols**: Modbus/TCP, S7comm, IEC 61850 MMS, DNP3, IEC 60870-5-104, EtherNet/IP (List Identity, CIP services including Unconnected Send / Multiple Service Packet unwrapping; object-specific services decoded by path), BACnet/IP, OPC UA, Omron FINS, Niagara Fox, MQTT, MELSEC, KNXnet/IP and CODESYS (by port only). What each one contributes is in the table below.
| Protocol (port) | Passive decoder | Control traffic flagged |
| --- | --- | --- |
| Modbus/TCP (502) | function codes, unit IDs | writes, diagnostics that restart or silence the device |
| S7comm (102) | job functions | write, download, PLC control and stop |
| IEC 61850 MMS (102) | PDU types and confirmed services of bare MMS and of MMS inside ISO session and presentation; vendor, model and revision of an Identify response | Write, Start, Stop, Resume, Reset and Kill of a program invocation, FileRename, FileDelete |
| DNP3 (20000) | data link frames (several per segment), function codes, outstation and master link addresses, IIN flags of responses (restart, trouble, ...) | write, select/operate, restarts, freezes, file delete, save/activate configuration |
| IEC 60870-5-104 (2404) | ASDU types | commands, setpoints, reset process, clock sync |
| EtherNet/IP (44818) | List Identity, CIP services | CIP writes, start/stop/reset |
| BACnet/IP (47808) | services, I-Am | WriteProperty, ReinitializeDevice, ... |
| OPC UA (4840) | message types | none |
| Omron FINS (9600, TCP and UDP) | command names, controller model and version from a Controller Data Read response | memory/parameter/program writes, Run, Stop, clock write, file operations, forced set/reset |
| Niagara Fox (1911) | hello of station and client (host, application, VM, OS, station name), message names | none (no Fox command is classed as a write) |
| MQTT (1883) | packet types, client protocol level, user name and will flags of a CONNECT, the CONNACK | none: a PUBLISH is as often telemetry as a command; topics and payloads are not kept |
| MELSEC (5006/5007 TCP and UDP; UDP 5560/5561) | MC protocol 3E/4E command names; MELSOFT direct connection frames and the CPU model | MC batch/random/block writes, remote run/stop/pause/reset/latch clear; nothing for MELSOFT |
| KNXnet/IP (3671/udp) | service types, device information of description and search responses, the telegram service inside tunnelling requests and routing indications | group value write, individual address write, memory write, restart |
| Profinet DCP (layer 2, `0x8892`) | Identify responses: station name, vendor, vendor/device ID, IP settings, **device role** (IO-Device, IO-Controller, IO-Multidevice, IO-Supervisor), **device options**, **device instance** and **OEM vendor/device ID** | none |
| CODESYS (UDP 1740-1743, TCP 1217, 2455, 11740-11743) | **presence by port only**; the observation says so (`evidence`) | none |

MMS and S7comm are told apart by what the connection carries (the first byte after the COTP data header: `0x32`/`0x72` for S7, an MMS PDU tag or an ISO session SPDU for MMS), not by the port. A connection request that looks like S7 (S7 TSAPs) counts as S7, any other waits for the first data; a connection that never says what it is is dropped, not guessed.

- **TCP reassembly**: messages split across TCP segments are reassembled in order for Modbus, S7, IEC 104, EtherNet/IP and OPC UA (16 KiB per flow, 1,024 flows, 4 MiB total). A missing segment means that message is decoded only as far as it was captured. DNP3, FINS, Fox, MQTT and MELSEC are decoded per segment. `--no-reassembly` turns it off. On those ports the `packets` counter counts messages, not segments.
- **Control traffic** (writes, program download, PLC stop, operate and restart commands, setpoints, WriteProperty, ReinitializeDevice, …) is counted per server and client and raised as `ot-control-traffic` findings.
- **Asset inventory**: `ot-assets ID` lists address, vendor, product, firmware, serial, protocols, roles, first/last seen and control traffic, as JSON or CSV. Each capture is saved to the inventory as `ot-passive:…`.

Limits: IPv4 only, standard ports only. The decoders for Modbus, S7comm, MMS, DNP3, IEC 104, EtherNet/IP, BACnet, OPC UA, FINS, Fox, MELSEC and Profinet DCP are tested on real captures (`tests/fixtures/ics`, see [Lab and testing](lab-and-testing.md)); KNXnet/IP, MQTT, MMS inside the full ISO stack, MC protocol and the DNP3 IIN flags are tested with frames built from the specifications only, and CODESYS is not decoded at all. The MELSOFT decoder is written from one capture (an FX5U) and reads the CPU model from the response that carries it. A SPAN/mirror port or tap is needed to see more than your own segment.

## General passive discovery

`listen --interface ID --seconds N` (and the desktop's Passive section) decodes mDNS, SSDP/UPnP, LLDP, CDP, NetBIOS, WS-Discovery, DHCP, ARP and IPv6 Neighbor Discovery (see [IPv6 discovery](ipv6-discovery.md)) without sending discovery packets. MAC-keyed observations retain devices that advertise no IP. What each protocol contributes to device identification is in [Detection](detection.md#passive-evidence-listen). Switch and PLC neighbours that announce themselves with LLDP or CDP (name, port, platform, software, management address) appear as observations with those fields.

- Passive IPv4/IPv6 UDP decoding supports ordinary unfragmented packets; IPv6 extension headers and reassembly are not implemented. Ethernet VLAN tags are supported.
- Requests to broadcast or multicast destinations record only the client.
- Observations are bounded to 10,000; a full capture queue or the cap marks the capture partial and collection continues with what still fits. The capture thread tolerates transient read errors.
- Passive and DCP records are kept alongside the scan inventory but do not imply open TCP ports.

## Protocol references

[OPC UA mappings](https://reference.opcfoundation.org/specs/OPC-10000-6/full), [Modbus specification](https://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf), [Npcap API](https://npcap.com/guide/wpcap/pcap.html).
