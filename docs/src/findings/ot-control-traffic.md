# Control traffic observed on an industrial protocol

| | |
| --- | --- |
| Finding id | `ot-control-traffic` |
| Severity | Medium or High |
| Applies to | Passively captured traffic (no port) |

## What it means

While listening to network traffic, the tool saw commands that change something in an industrial device, such as writing a value, loading a program, or stopping or restarting a controller. The finding names the device that received them and the machines that sent them.

## Why it matters

Such commands are normal when an engineer or the control system sends them, and dangerous when someone else does. A write or a stop command can change a process or halt it. The finding helps to check that only the expected stations send them.

## How it is detected

This finding comes from passive discovery (`ot-listen` on a live capture or a capture file, stored in the snapshot); it is never created by sending anything. The tool decodes Modbus/TCP, S7comm, DNP3, IEC 60870-5-104, EtherNet/IP and BACnet/IP and counts the functions that change state ("control traffic") per server device, with the clients that sent them. OPC UA is recognised, but its writes are not classed as control traffic.

Examples of what counts as control traffic: Modbus write functions and the Restart Communications and Force Listen Only Mode diagnostics; S7 Write Var, program download and PLC Control/Stop; DNP3 Write, Select, Operate, Direct Operate, restart and Stop Application; IEC 104 commands, setpoints, clock synchronisation and reset process; EtherNet/IP Set Attribute, Reset and tag writes; BACnet WriteProperty, DeviceCommunicationControl, ReinitializeDevice and AtomicWriteFile.

The severity is **High** if the text of the observed functions contains "Stop", "Download", "Restart" or "PLC Control"; otherwise **Medium**. The evidence reads like "Modbus/TCP server: control traffic observed (Write Single Register x2) from 10.0.0.5". The finding has no port.

## Possible false positives

- Routine writes from the real SCADA or engineering station are exactly what this finding shows; it does not say the traffic is unauthorised. Many sites will see it on every scan of a live plant.
- A capture only shows the traffic that passes the capture point, and the decoders were tested with synthetic traffic only (see OT / industrial).
- The severity depends on the wording of the function names. Some state-changing commands, for example a CIP Reset, a BACnet ReinitializeDevice or a DNP3 Direct Operate, are rated Medium.

## How to fix

- **Check the clients** named in the evidence against the list of authorised engineering and control stations. Unknown sources deserve an investigation, with the plant operator.
- **Restrict who may send commands:** firewall or industrial-firewall rules between zones, and the access protection of the controller (password-protected programming access, keyswitch/mode settings) as described by the vendor.
- **Segment and monitor** the control network and keep a baseline of expected writers (see ISA/IEC 62443 zones and conduits).
- Make changes on controllers and network equipment only with the vendor's guidance and in agreed change windows; never test commands on a running process.

## References

- [NIST SP 800-82 Rev. 3, Guide to OT security](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
- [CISA, Industrial control systems](https://www.cisa.gov/topics/industrial-control-systems)
- [ISA/IEC 62443 series of standards](https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards)

[All findings](index.md)
