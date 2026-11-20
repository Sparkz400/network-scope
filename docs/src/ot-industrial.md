# OT / industrial

Network Scope identifies industrial devices in two ways: **active identification** with single read-only requests on standard ports, and **passive discovery** from captured traffic, which sends nothing. Read [Safe Mode and OT safety](safe-mode-and-ot-safety.md) before using either on a production network.

## Active identification (`--ot`)

All OT operations are identification-only, even when Safe Mode is off. OT identification probes standard ports only (the one exception is the MELSEC MC port, which only you can name with `--melsec-port`), and only for hosts that responded to something (ARP, ICMP, any TCP answer or UDP).

In the desktop, select **Use industrial ports** and enable nonresponders to find ICMP-silent TCP services. The CLI does both when `--ot` is used without `--ports` (ports `80,443,102,502,1883,1911,4840,9600,44818`).

| Protocol | Port | What is sent | What is read |
| --- | --- | --- | --- |
| Modbus/TCP | 502 | One Read Device Identification request (function 43/14), configurable unit ID (`--unit`) | Vendor, product, firmware when returned; additional object pages are marked partial |
| S7comm | 102 | COTP connection, communication setup, read-only SZL 0x0011/0x001C, configurable rack/slot (`--rack`, `--slot`) | Order code, CPU type, firmware, serial when advertised |
| EtherNet/IP | 44818 | TCP List Identity | Vendor ID (with ODVA vendor name), product, serial, revision |
| BACnet/IP | 47808/udp | One unicast Who-Is per IPv4 target (responding hosts, plus silent hosts when nonresponders are scanned) | Device instance |
| OPC UA | 4840 | UA Binary HEL/OpenSecureChannel, GetEndpoints and FindServers without a session, CloseSecureChannel | Names, application/product URIs, security policies, certificate DER as hex |
| Omron FINS | 9600/udp | One Controller Data Read (command 0x0501), the 13-byte frame of a real capture, to hosts that answered something else | Controller model and version strings |
| Omron FINS/TCP | 9600 | The node address exchange (FINS/TCP command 0, no FINS command) and one Controller Data Read in a FINS/TCP frame, both frames of a real capture, only if tcp/9600 was found open; the connection is closed right after the reply | Controller model and version strings |
| MELSEC MC protocol | **the port you give** | Only with `--melsec-port PORT` (and the port in `--ports`, found open): one Read CPU Model Name (command 0x0101) in a 3E binary frame. No default port, no guessing | CPU model name and model code |
| DNP3 | 20000 | Only with `--dnp3-address N` (outstation data link address; `--dnp3-master M` is the address the request comes from, default 1) and tcp/20000 found open: one unconfirmed data link frame carrying Read of class 0 (object group 60, variation 1). Never a broadcast or reserved address, nothing is confirmed, the connection is closed after the reply | Link address of the outstation, its internal indications (IIN), the size of the static data |
| Niagara Fox | 1911 | The `fox a 1 -1 fox hello` message (what nmap's `fox-info` sends; no authentication) | Station name, application, VM and OS versions, host name and ID |
| MQTT | 1883 | CONNECT (clean session, no credentials, no will) and DISCONNECT; no SUBSCRIBE or PUBLISH. Not sent with `--services`, whose MQTT service probe already sends the same CONNECT | The broker's CONNACK: accepted, or authentication / client ID required |
| KNXnet/IP | 3671/udp | One unicast DESCRIPTION_REQUEST (never the multicast search, no connection or tunnelling), to hosts that answered something else | Friendly name, individual address, serial number, MAC, medium, supported services |

Details and limits:

- **S7**: segmented SZLs, denied access and unsupported devices return explicit errors. No S7plus, authentication, program/block access or control operations.
- **2222/tcp**: only an SSH greeting leads to SSH probing; anything else is treated as industrial (EtherNet/IP) and gets the `ot-reachable` finding.
- **BACnet/IP**: waits the port timeout clamped to 200-2000 ms; ICMP port unreachable means "no BACnet" without an error. Silent hosts get this Who-Is only when nonresponders are scanned (the CLI does with `--ot`), so a device that answers only BACnet/IP is found; each silent address costs at most that wait. No broadcast and no property writes. IPv6 BACnet and forwarded/router NPDU forms are not supported.
- **OPC UA**: only unsecured sessionless discovery is supported; servers denying it produce errors. The product URI is not a verified manufacturer identity. Discovery certificates are inventory data, not trusted certificates. Message sizes, chunk counts and parser recursion are bounded.
- **FINS, Fox, MQTT, KNX**: the requests are the allow-listed ones in `ot::readonly` (a write, Run/Stop, a PUBLISH, a tunnelling frame or an authentication have no value in the types, and the tests check every code byte). The UDP requests (FINS, KNX) go only to hosts that answered something else, never to silent hosts; BACnet remains the only OT request a silent host can get. The FINS request frame is byte for byte the one in `tests/fixtures/ics/omron_test.pcap`; the Fox hello has the layout of the client hello in `fox_info.pcap`. The MQTT and KNX layouts come from the MQTT 3.1.1 and KNXnet/IP specifications and have **no capture** among the fixtures; they have been run against the lab simulators only.
- **FINS/TCP**: the two client frames equal packets 5 and 7 of `omron_test.pcap` byte for byte (a test compares them), only the server node number (byte 20 of the second frame, the node the server named in its reply to the first) varies. Memory writes, Run, Stop and every other FINS command have no value in the types. The controller keeps few FINS/TCP connections, so the connection is not held: it is dropped as soon as the reply is read. The identity keys are `Omron FINS/TCP.*` (the UDP request's are `Omron FINS.*`), so an answer over TCP is never listed as an open UDP port.
- **MELSEC MC (opt-in, user port)**: the MC protocol has no standard port and a request to a port that speaks something else is a misdirected request, so it is sent only with `--melsec-port`, only to a port above 1023 that has no protocol of its own here (502, 44818, 20000 and the other industrial ports are refused), only if the port is in `--ports` and was found open, and the port is not given to the generic service probes. The 15 bytes are the 3E binary frame of the MC protocol reference for command 0x0101, subcommand 0x0000, to the own station (network 0, PC 0xFF, module I/O 0x03FF, station 0); **no capture of an MC 3E exchange is among the fixtures** (the MELSOFT capture is another protocol), so the frame and its decoder were written from the reference and checked against the lab simulator and tests built from the reference only. A PLC that does not support the command answers an end code, which is reported, not hidden.
- **DNP3 (opt-in, address given)**: a request needs the outstation's data link address, which cannot be guessed; `--dnp3-address N` gives it. The frame is the data link frame of the capture `dnp3_read_and_response.pcap` (same header and CRC algorithm, checked against the captured CRCs `0xED8F` and `0x518A`) with the application layer reduced to Read of class 0, the static part of an integrity poll; classes 1 to 3 (event data) are not read, so no event buffer is consumed. Link addresses of 0xFFF0 and above (reserved and the broadcast addresses 0xFFFC to 0xFFFF) are refused, as is a destination equal to the master address; the check is in the request type and again in the option parsing. The frame is unconfirmed user data (link function 4): the outstation is asked for no link state. If the response asks for an application confirm (CON bit), none is sent. The reply's CRCs are verified; a frame with a wrong CRC is an error, not data.
- **IEC 61850 MMS is not sent.** The capture fixtures hold two MMS exchanges (`mms_read_request.pcap`, `mms_stop_request.pcap`), but both are **bare MMS PDUs in TPKT/COTP**, without the ISO session, presentation and ACSE layers that every IEC 61850 server speaks. An Initiate-RequestPDU that works against a real device needs those layers (session CONNECT SPDU, presentation CP-type, ACSE AARQ around the MMS initiate), and neither a public capture of that sequence nor an independent implementation to check it against was used: the test data of libiec61850 was not fetched (a download that was not approved), and `tshark`, which the verification rules do allow, was not installed in this work, so the untried route is to build the sequence and have `tshark` dissect it. A request built only from the standards' text could not be shown to work, and an association that does not complete can leave a connection slot of the device occupied, so the active Identify request is **not implemented** (not done, and the `tshark` check was not attempted); MMS stays passive.
- **Not sent**: CODESYS (passive only).
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
| CODESYS (UDP 1740-1743, TCP 1200, 1217, 2455, 11740-11743) | the V2 identification handshake (request `BB BB 01 00 00 xx 01`, reply with operating system name, type and product); everything else, and the whole of V3, is **presence by port only**; the observation says which (`evidence`). TCP 1200 counts only with the `0xBB` marker | none |

MMS and S7comm are told apart by what the connection carries (the first byte after the COTP data header: `0x32`/`0x72` for S7, an MMS PDU tag or an ISO session SPDU for MMS), not by the port. A connection request that looks like S7 (S7 TSAPs) counts as S7, any other waits for the first data; a connection that never says what it is is dropped, not guessed.

- **TCP reassembly**: messages split across TCP segments are reassembled in order for Modbus, S7, IEC 104, EtherNet/IP and OPC UA (16 KiB per flow, 1,024 flows, 4 MiB total). A missing segment means that message is decoded only as far as it was captured. DNP3, FINS, Fox, MQTT and MELSEC are decoded per segment. `--no-reassembly` turns it off. On those ports the `packets` counter counts messages, not segments.
- **Control traffic** (writes, program download, PLC stop, operate and restart commands, setpoints, WriteProperty, ReinitializeDevice, …) is counted per server and client and raised as `ot-control-traffic` findings.
- **Asset inventory**: `ot-assets ID` lists address, vendor, product, firmware, serial, protocols, roles, first/last seen and control traffic, as JSON or CSV. Each capture is saved to the inventory as `ot-passive:…`.

Limits: IPv4 only, standard ports only. The decoders for Modbus, S7comm, MMS, DNP3, IEC 104, EtherNet/IP, BACnet, OPC UA, FINS, Fox, MELSEC and Profinet DCP are tested on real captures (`tests/fixtures/ics`, see [Lab and testing](lab-and-testing.md)); see the table below for what is anchored on a capture and what is **spec only**. The MELSOFT decoder is written from one capture (an FX5U) and reads the CPU model from the response that carries it. A SPAN/mirror port or tap is needed to see more than your own segment.

### Which decoders have a real capture behind them

| Decoder | Anchored on a public capture (`tests/fixtures/ics`) | Spec only (frames built from the specification or a public description) |
| --- | --- | --- |
| Modbus/TCP, S7comm, EtherNet/IP, BACnet, OPC UA, IEC 104, Profinet DCP | yes | function codes the captures do not contain |
| DNP3 | link addresses, Read, Select, Operate, Write, the response frame with its CRCs and an empty IIN (3 captures) | the IIN bits that are set (a flagged outstation: restart, need time, trouble...) |
| IEC 61850 MMS | bare MMS PDUs (Initiate, Read, Start/Stop Program Invocation, Conclude) in TPKT/COTP (2 captures) | MMS inside the full ISO session/presentation/ACSE stack; the service names the captures do not contain |
| Omron FINS | UDP and TCP, Controller Data Read (1 capture) | other commands |
| Niagara Fox | the hello exchange (1 capture) | |
| MELSEC | the MELSOFT direct connection (1 capture of an FX5U) | **MC protocol 3E/4E** (command names, the active CPU model request) |
| KNXnet/IP | | **everything** (no KNX capture is among the fixtures) |
| MQTT | | **everything** (no MQTT capture is among the fixtures) |
| CODESYS | | **everything**: the V2 identification layout comes from a public description (the Digital Bond/nmap script `codesys-v2-discover`, facts only, no code); V3 is not decoded |

Captures for KNX, MQTT, MC protocol 3E and CODESYS were looked for among the fixtures and the other local material and are not there. Public captures exist (for example the ITI/ICS-Security-Tools repository the fixtures come from has further directories, and other collections), but fetching them needs a download that has to be approved and a licence check for each; none was added. Until then these decoders are spec only, and their tests say so.

## Learning normal traffic (`ot-learn`, `ot-listen --model`)

Passive discovery says what is there; learning says what is normal. `ot-learn` reads a capture (a pcap or pcapng file, or a live receive-only capture) and records, for every device that answers an industrial protocol, **who talks to it**, **with which functions** (Modbus function codes, S7 job types, CIP services, DNP3 and IEC 104 commands), **how often** (messages per minute) and **when** (messages per hour of the day, UTC). The result is a model file (JSON, `ot-model` schema; `--model FILE`, default `ot-model.json` next to the inventory database):

```sh
network-scope-cli ot-learn --pcap normal-week.pcapng --model plant.model.json
network-scope-cli ot-listen --pcap today.pcapng --model plant.model.json --maintenance "Sat 02:00-06:00"
network-scope-cli ot-listen --interface 3 --seconds 3600 --model plant.model.json --format text
```

`ot-listen --model` checks the traffic against the model while it does what `ot-listen` always does (the observations are saved as a scan) and prints the alerts (`ot-alerts` schema, or `--format text`) instead of the asset list. `--fail-on-findings` turns "at least one alert" into exit status 3. Both commands are receive-only: the events come from the passive decoders, which have no transmit path.

| Alert | When |
| --- | --- |
| `new-asset` | A device that is not in the model receives industrial traffic. |
| `new-station` | A client that never talked to this device in the learned traffic: a new engineering station, HMI or scanner. |
| `stop-outside-window` | A Stop, restart or PLC-control function outside the maintenance window. With no window declared, every Stop. |
| `first-write` | A write or control function this device never received in the learned traffic. |
| `new-function` | A read-type function this device never received. |
| `unusual-hour` | A write or control function at an hour of the day with no learned control traffic. Only judged when at least 24 hours were learned. |
| `rate-anomaly` | A minute with more than three times the messages of the busiest learned minute (and at least 30 more). |

One message gives one alert that lists all of its reasons (`kinds`): a write from a new station is one `new-station` alert that also names the first write. Repeats of the same message are counted in `occurrences`. The severity is high for writes and Stops, medium for a new station or device, low for a new read function.

**Maintenance window.** `--maintenance "Sat 02:00-06:00"` declares when Stops are expected. Several windows are separated by `;`; a window is `DAYS HH:MM-HH:MM [UTC+H[:MM]]` with `DAYS` a day (`Sat`), a range (`Mon-Fri`), a list (`Sat,Sun`) or `daily`. A window whose end is before its start runs over midnight (`Sat 22:00-02:00` ends on Sunday at 02:00). Without a zone the times are **UTC**, which is also what the model uses for the hour of the day.

**Limits.** The model is only as good as the capture it came from: rare traffic (a yearly maintenance job) is new the first time it appears after learning, so learn over a representative period and re-learn after planned changes. Peers are IP addresses, so a station that gets a new DHCP lease looks new. Only protocols the passive decoders understand are learned; OPC UA and BACnet requests carry no function name there, so only peers and rates are learned for them. Time stamps come from the capture, so a capture with scrambled times gives scrambled rates and hours. Capture-based learning was tested on the public captures in `tests/fixtures/ics/` and on synthetic events; it has not been run on a long recording of a real plant.

The lab replay test of this feature learns `modbus_test_data_part1.pcap`, injects one Modbus write from a new address (a copy of a real read request with the function code changed), replays the result and expects exactly one alert; see `core/src/otmodel_tests.rs`.

## General passive discovery

`listen --interface ID --seconds N` (and the desktop's Passive section) decodes mDNS, SSDP/UPnP, LLDP, CDP, NetBIOS, WS-Discovery, DHCP, ARP and IPv6 Neighbor Discovery (see [IPv6 discovery](ipv6-discovery.md)) without sending discovery packets. MAC-keyed observations retain devices that advertise no IP. What each protocol contributes to device identification is in [Detection](detection.md#passive-evidence-listen). Switch and PLC neighbours that announce themselves with LLDP or CDP (name, port, platform, software, management address) appear as observations with those fields.

- Passive IPv4/IPv6 UDP decoding supports ordinary unfragmented packets; IPv6 extension headers and reassembly are not implemented. Ethernet VLAN tags are supported.
- Requests to broadcast or multicast destinations record only the client.
- Observations are bounded to 10,000; a full capture queue or the cap marks the capture partial and collection continues with what still fits. The capture thread tolerates transient read errors.
- Passive and DCP records are kept alongside the scan inventory but do not imply open TCP ports.

## Protocol references

[OPC UA mappings](https://reference.opcfoundation.org/specs/OPC-10000-6/full), [Modbus specification](https://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf), [Npcap API](https://npcap.com/guide/wpcap/pcap.html).
