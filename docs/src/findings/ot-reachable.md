# Industrial protocol port is reachable from the scanner

| | |
| --- | --- |
| Finding id | `ot-reachable` |
| Severity | Medium |
| Applies to | TCP ports of industrial protocols |

## What it means

A TCP port that is normally used by industrial control protocols is open and reachable from the place where the scan ran. Industrial protocols were designed for closed networks and usually have no login or encryption.

## Why it matters

Whoever can reach such a port can often read and sometimes change the process data and programs of a controller without any password. That is why industrial devices belong in a separate, controlled network.

## How it is detected

The finding is based on the port number only. It is raised when one of these TCP ports is open: 102, 502, 789, 1911, 1962, 2404, 4840, 9600, 18245, 20000, 34962, 34963, 34964, 44818, 47808 or 48898, or 2222, unless the service on the port is identified as SSH (2222 is a common SSH port; a service imported from Nmap XML or a server moved onto an industrial port number also counts as not industrial when it is SSH). These ports are used by protocols such as S7comm, Modbus/TCP, IEC 60870-5-104, OPC UA, DNP3, PROFINET, EtherNet/IP and BACnet. The evidence reads like `TCP 502 open`.

Generic service detection never sends probes to these ports (to avoid disturbing fragile equipment), and this finding does not use the result of the separate `--ot` identification, so it does not say what really runs there. UDP ports are not part of this finding.

## Possible false positives

- Another application on a port that is also used by an industrial protocol (several of the ports are used by ordinary software too), or a simulator or test setup.
- The finding says that the port is reachable from the scanner, which is intended information when the scan ran from an office network.

## How to fix

- **Segment the network.** Industrial devices belong in a control network; allow access from the office or Internet side only through a firewall or a DMZ with explicit rules for named engineering stations.
- **Restrict the port** with firewall rules or the device's own access lists to the systems that need it.
- **Follow the vendor's guidance** for each device and make firewall or configuration changes only in an agreed maintenance window, with the plant operators informed. Test on a spare device if available.
- Prefer passive discovery (`ot-listen` on a mirror port) over active scanning on live control networks; see Safe Mode and OT safety.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [NIST SP 800-82 Rev. 3, Guide to OT security](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
- [CISA, Industrial control systems](https://www.cisa.gov/topics/industrial-control-systems)
- [ISA/IEC 62443 series of standards](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards)

[All findings](index.md)
