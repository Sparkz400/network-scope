# UPnP/SSDP is answering

| | |
| --- | --- |
| Finding id | `upnp-exposed` |
| Severity | Low |
| Applies to | UDP port 1900 |

## What it means

The device answers discovery requests for UPnP (Universal Plug and Play) on port 1900. UPnP lets programs and devices find each other and, on routers, open ports in the firewall automatically.

## Why it matters

UPnP discovery reveals what the device is and where its description is served, and a UPnP service on a router can be used by malware inside the network to open ports to the Internet. Devices that answer from the Internet can be abused for traffic amplification.

## How it is detected

On UDP 1900 the tool sends a single unicast SSDP search request (`M-SEARCH`). If the device replies, the finding is raised, and the evidence is the decoded reply (server text, device type and description URL). It says that the device answers discovery, not that a firewall-opening UPnP function is switched on.

## Possible false positives

- Many televisions, media players, printers and routers answer SSDP on a home or office network as part of normal operation.

## How to fix

- **Routers and gateways:** turn off UPnP in the router settings unless you need it, and make sure UDP 1900 is not reachable from the Internet.
- **Other devices:** disable UPnP/DLNA/media-sharing options that you do not use, or block UDP 1900 between network segments.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [CISA TA14-017A, UDP-based amplification attacks (SSDP)](https://www.cisa.gov/news-events/alerts/2014/01/17/udp-based-amplification-attacks)
- [CERT/CC VU#357851, UPnP requests accepted over router WAN interfaces](https://www.kb.cert.org/vuls/id/357851)

[All findings](index.md)
