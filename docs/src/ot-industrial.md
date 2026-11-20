# OT / industrial

Network Scope identifies industrial devices in two ways: **active identification** with single read-only requests on standard ports, and **passive discovery** from captured traffic, which sends nothing. Read [Safe Mode and OT safety](safe-mode-and-ot-safety.md) before using either on a production network.

## Active identification (`--ot`)

All OT operations are identification-only, even when Safe Mode is off. OT identification probes standard ports only, and only for hosts that responded to something (ARP, ICMP, any TCP answer or UDP).

In the desktop, select **Use industrial ports** and enable nonresponders to find ICMP-silent TCP services. The CLI does both when `--ot` is used without `--ports` (ports `80,443,102,502,4840,44818`).

| Protocol | Port | What is sent | What is read |
| --- | --- | --- | --- |
| Modbus/TCP | 502 | One Read Device Identification request (function 43/14), configurable unit ID (`--unit`) | Vendor, product, firmware when returned; additional object pages are marked partial |
| S7comm | 102 | COTP connection, communication setup, read-only SZL 0x0011/0x001C, configurable rack/slot (`--rack`, `--slot`) | Order code, CPU type, firmware, serial when advertised |
| EtherNet/IP | 44818 | TCP List Identity | Vendor ID (with ODVA vendor name), product, serial, revision |
| BACnet/IP | 47808/udp | One unicast Who-Is per IPv4 target (responding hosts, plus silent hosts when nonresponders are scanned) | Device instance |
| OPC UA | 4840 | UA Binary HEL/OpenSecureChannel, GetEndpoints and FindServers without a session, CloseSecureChannel | Names, application/product URIs, security policies, certificate DER as hex |

Details and limits:

- **S7**: segmented SZLs, denied access and unsupported devices return explicit errors. No S7plus, authentication, program/block access or control operations.
- **2222/tcp**: only an SSH greeting leads to SSH probing; anything else is treated as industrial (EtherNet/IP) and gets the `ot-reachable` finding.
- **BACnet/IP**: waits the port timeout clamped to 200-2000 ms; ICMP port unreachable means "no BACnet" without an error. Silent hosts get this Who-Is only when nonresponders are scanned (the CLI does with `--ot`), so a device that answers only BACnet/IP is found; each silent address costs at most that wait. No broadcast and no property writes. IPv6 BACnet and forwarded/router NPDU forms are not supported.
- **OPC UA**: only unsecured sessionless discovery is supported; servers denying it produce errors. The product URI is not a verified manufacturer identity. Discovery certificates are inventory data, not trusted certificates. Message sizes, chunk counts and parser recursion are bounded.
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
- **Recognised protocols**: Modbus/TCP, S7comm, DNP3, IEC 60870-5-104, EtherNet/IP (List Identity, CIP services including Unconnected Send / Multiple Service Packet unwrapping; object-specific services decoded by path), BACnet/IP and OPC UA.
- **TCP reassembly**: messages split across TCP segments are reassembled in order for Modbus, S7, IEC 104, EtherNet/IP and OPC UA (16 KiB per flow, 1,024 flows, 4 MiB total). A missing segment means that message is decoded only as far as it was captured. DNP3 is still per segment. `--no-reassembly` turns it off. On those ports the `packets` counter counts messages, not segments.
- **Control traffic** (writes, program download, PLC stop, operate and restart commands, setpoints, WriteProperty, ReinitializeDevice, …) is counted per server and client and raised as `ot-control-traffic` findings.
- **Asset inventory**: `ot-assets ID` lists address, vendor, product, firmware, serial, protocols, roles, first/last seen and control traffic, as JSON or CSV. Each capture is saved to the inventory as `ot-passive:…`.

Limits: IPv4 only, standard ports only, decoders validated with **synthetic frames only**, not with real industrial traffic. A SPAN/mirror port or tap is needed to see more than your own segment.

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

`listen --interface ID --seconds N` (and the desktop's Passive section) decodes mDNS, SSDP/UPnP, LLDP, CDP, NetBIOS, WS-Discovery, DHCP and ARP without sending discovery packets. MAC-keyed observations retain devices that advertise no IP. What each protocol contributes to device identification is in [Detection](detection.md#passive-evidence-listen). Switch and PLC neighbours that announce themselves with LLDP or CDP (name, port, platform, software, management address) appear as observations with those fields.

- Passive IPv4/IPv6 UDP decoding supports ordinary unfragmented packets; IPv6 extension headers and reassembly are not implemented. Ethernet VLAN tags are supported.
- Requests to broadcast or multicast destinations record only the client.
- Observations are bounded to 10,000; a full capture queue or the cap marks the capture partial and collection continues with what still fits. The capture thread tolerates transient read errors.
- Passive and DCP records are kept alongside the scan inventory but do not imply open TCP ports.

## Protocol references

[OPC UA mappings](https://reference.opcfoundation.org/specs/OPC-10000-6/full), [Modbus specification](https://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf), [Npcap API](https://npcap.com/guide/wpcap/pcap.html).
