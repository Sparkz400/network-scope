# SNMP answers the community string 'public'

| | |
| --- | --- |
| Finding id | `snmp-public` |
| Severity | High |
| Applies to | UDP port 161 |

## What it means

A device answers SNMP (the monitoring protocol of network devices) to the default password "public". SNMP versions 1 and 2c use that "community string" as their only secret.

## Why it matters

Anyone who can reach the port can read information about the device: system description, interfaces, addresses, running software, neighbours, often more. If a write community is also left at its default, devices can be reconfigured.

## How it is detected

On UDP 161 the tool sends an SNMP GET request for the system description (`sysDescr`) with the community `public`, alternating between SNMP v2c and v1 on repeated tries. If the device returns the text successfully, the finding is raised and the evidence is "SNMP sysDescr: ..." with the returned text. An answer with an error status ("community may differ") is not reported. The tool reads one value and does not walk the device or try other community strings or write operations.

## Possible false positives

- A device that is intentionally monitored with the read community `public` inside a protected management network.

## How to fix

- **Use SNMPv3** with authentication and encryption (`authPriv`), and disable v1 and v2c where possible.
- If v2c must stay: change the community string to a long random value and restrict the source addresses to the monitoring system. **Net-SNMP:** `rocommunity NAME SOURCE` in `snmpd.conf`; **Windows:** the SNMP Service, Security tab.
- **Switches, UPS units, printers, controllers:** use the vendor's SNMP settings. Update the monitoring system at the same time, otherwise monitoring stops; plan it in a maintenance window.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [CISA TA17-156A, reducing the risk of SNMP abuse](https://www.cisa.gov/news-events/alerts/2017/06/05/reducing-risk-snmp-abuse)
- [RFC 3414, User-based Security Model for SNMPv3](https://www.rfc-editor.org/rfc/rfc3414)
- [Net-SNMP, snmpd.conf manual](https://www.net-snmp.org/docs/man/snmpd.conf.html)

[All findings](index.md)
