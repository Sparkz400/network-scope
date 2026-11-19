# NetBIOS name service is exposed

| | |
| --- | --- |
| Finding id | `netbios-ns` |
| Severity | Low |
| Applies to | UDP port 137 |

## What it means

The device answers NetBIOS name queries, an old Windows name-resolution service. The answer reveals the computer name, workgroup or domain and often the MAC address.

## Why it matters

Names and domains help an attacker to map the network, and the old name resolution can be spoofed to capture credentials in local networks.

## How it is detected

On UDP 137 the tool sends a NetBIOS node status query and records the reply. If the port answers, the finding is raised and the evidence is the decoded name list.

## Possible false positives

- Environments that still depend on NetBIOS for name resolution of old clients.

## How to fix

- **Windows:** disable NetBIOS over TCP/IP in the adapter's advanced TCP/IP settings (WINS tab), or through the DHCP server's NetBIOS option for all clients.
- **Samba:** `disable netbios = yes`.
- Block UDP 137 between network segments.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [RFC 1001, NetBIOS over TCP/UDP: concepts and methods](https://www.rfc-editor.org/rfc/rfc1001)
- [RFC 1002, NetBIOS over TCP/UDP: detailed specifications](https://www.rfc-editor.org/rfc/rfc1002)

[All findings](index.md)
