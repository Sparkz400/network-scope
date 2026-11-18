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

## General passive discovery

`listen --interface ID --seconds N` (and the desktop's Passive section) decodes mDNS, SSDP/UPnP, LLDP, NetBIOS, DHCP and ARP without sending discovery packets. MAC-keyed observations retain devices that advertise no IP.

- Passive IPv4/IPv6 UDP decoding supports ordinary unfragmented packets; IPv6 extension headers and reassembly are not implemented. Ethernet VLAN tags are supported.
- Requests to broadcast or multicast destinations record only the client.
- Observations are bounded to 10,000; a full capture queue or the cap marks the capture partial and collection continues with what still fits. The capture thread tolerates transient read errors.
- Passive and DCP records are kept alongside the scan inventory but do not imply open TCP ports.

## Protocol references

[OPC UA mappings](https://reference.opcfoundation.org/specs/OPC-10000-6/full), [Modbus specification](https://www.modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf), [Npcap API](https://npcap.com/guide/wpcap/pcap.html).
