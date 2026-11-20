# Device identity

A scan result is keyed by MAC address, or by IP address when no MAC is visible. Phones and laptops rotate "private" (randomised) MAC addresses and DHCP hands out new IP addresses, so those keys alone make one device look like several. Network Scope therefore keeps a **stable device key** for each device in the inventory database and recognises a device again from the identifiers it reports.

The monitor uses the key: a device that came back with a new address and a new random MAC is not a `new-device` alert and not `device-missing`. `devices ID` shows it as `key`.

## What counts as an identifier

| Identifier | Points | Notes |
| --- | --- | --- |
| Globally unique MAC address (also the fixed virtual-NIC prefixes such as `52:54:00`) | 100 | decides alone |
| SNMP engine ID | 100 | decides alone; used when a scan reported one |
| SMB server GUID | 70 | cloned VMs share it |
| SSH host key fingerprint | 70 | golden images share it; used when a scan reported one |
| DHCP client identifier (option 61, from passive capture) | 60 | usually derived from the MAC, so it rotates with it |
| TLS certificate public-key hash (`tls.PORT.spki_sha256`) | 40 | the same key survives a certificate renewal; vendor default certificates are shared |
| Host name declared by an [import](import-export.md#how-an-imported-device-matches-a-scanned-one) (AD, NetBox, CSV) | 100 | decides alone; names are not authenticated |
| Randomised (locally administered) MAC | 40 | may change at any time |
| Host name (mDNS, DHCP, NetBIOS, reverse DNS) | 30 | names get reused; names built from the IP address are ignored |
| IP address | 15 | addresses get reassigned |
| HASSH and JA3S of the same host | 10 | identifies the software, not the device |

Two records are the same device when the points of their **matching** identifiers add up to 100 or more. One strong identifier decides; weak ones only add up. A shared default certificate, a common host name or an identical SSH stack never merge two devices on their own, and a cloned image that shares an SSH key still needs a second matching identifier.

Some identifiers can **veto** a match: two different globally unique MACs, two different SMB GUIDs or two different SNMP engine IDs are two devices, however much else they share. A device that shows up again under exactly the same id as before (its MAC, or `ip:ADDRESS` when it has none) is the same device, unless its SMB GUID or SNMP engine ID now differs and its MAC is not globally unique.

In one scan a recorded device is matched at most once: if two devices report the same identifiers (a cloned image), the better match keeps the key and the other one is new.

## Randomised MAC addresses

A MAC address with the locally administered bit (`0x02` in the first octet) is randomised or assigned by software. Network Scope marks such a device `randomized_mac`, shows no manufacturer for it (the OUI of a random address means nothing) and never lets the MAC decide alone: it counts for 40 points, so another identifier has to match too. Hypervisor prefixes such as `52:54:00` are locally administered but assigned once; they are treated as stable.

## The key

The key of a device is the id it was first seen with (its MAC, or `ip:ADDRESS`), kept for as long as the device is recognised. It does not change when the device changes address or MAC. Databases written by earlier versions keep their keys: opening one adds the identifier tables (schema version 3) and seeds them from the devices already known.

The keys are recorded by `monitor` (after it compared the scan with what was known, and only for complete scans) and by the baseline and import commands. A device that is not in the inventory yet is shown with the id it has in the scan.

## Limits

- Identifiers come from replies the scan already collected; nothing extra is sent. SSH host key fingerprints and SNMP engine IDs are used when a scan reports them (`ssh.PORT.hostkey_sha256`, `snmp.engine_id`); this version does not request them itself.
- A phone with a rotating MAC that offers nothing but its host name and address cannot be followed: those two add up to 45 points. It shows up as a new device after each rotation.
- An identifier that is shared by two devices at the same time can only be told apart by the veto rules above.
