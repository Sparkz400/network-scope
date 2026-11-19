# Import, export and sync

## Import known devices

```sh
network-scope-cli import KIND FILE... [--format json]
network-scope-cli baseline enable
```

`import KIND FILE` reads a list of devices from a file and merges it into the inventory and the [baseline](inventory-diff-reports.md#approved-baseline) as **known devices**. It is not a scan: nothing was observed, so no scan, port or finding is created (`history` does not list it, and `report` and `export` do not show it). The device is recorded under a stable [device key](device-identity.md) so that `monitor` does not call it new, and it is added to the expected-devices list with the owner, criticality and tags the file gives. Importing the same list again changes nothing; importing a richer list adds to what is there and never clears an owner or tag.

The tool stays credential-free: it never connects to a directory, a DHCP server or NetBox. Export the data there and give the file to `import`. (`import FILE.xml` without a kind still imports an nmap XML scan.)

| Kind | File | What it provides |
| --- | --- | --- |
| `csv` | CSV with a header row | whatever the columns give |
| `isc-dhcp` | ISC `dhcpd.leases` | active leases: MAC, address, client host name |
| `dnsmasq` | dnsmasq lease file (`dnsmasq.leases`) | MAC, address, host name (IPv6 leases without MAC) |
| `windows-dhcp` | CSV of `Get-DhcpServerv4Lease \| Export-Csv`, or the XML of `Export-DhcpServer` | MAC (client id), address, host name |
| `ad-csv` | CSV of `Get-ADComputer -Filter * -Properties * \| Export-Csv` | host name, `IPv4Address`, owner (`ManagedBy`), operating system |
| `ad-ldif` | LDIF of computer objects (`ldifde -f out.ldf`, `ldapsearch -LLL`) | host name, owner, operating system |
| `netbox` | JSON saved from `/api/dcim/devices/` and `/api/ipam/ip-addresses/` | name, addresses, status, tenant, role, site, tags |

Several files of one kind can be given together (`import netbox devices.json ip-addresses.json`): a NetBox address assigned to a device is joined to it by name.

### CSV columns

Columns are found by their header name; case, spaces and underscores do not matter, order and extra columns are ignored. The delimiter (`,`, `;`, tab or `|`) is taken from the header line; a `sep=;` line, a `#TYPE` line, a byte order mark and UTF-16 (PowerShell's `-Encoding Unicode`) are understood. At least one of the address, MAC and name columns is needed.

| Meaning | Header names |
| --- | --- |
| IP address | `ip`, `ip address`, `ipv4address`, `address` |
| MAC address | `mac`, `mac address`, `hardware address`, `client id` |
| Host name | `hostname`, `name`, `dnshostname`, `fqdn`, `computername` |
| Owner | `owner`, `contact`, `managedby` |
| Tags | `tags`, `labels` (separated by `;`, `\|` or `,` inside the field) |
| Criticality | `criticality` (`low`, `medium`, `high`, `critical`) |
| Expected | `expected` (`yes` or `no`: `no` describes the device without expecting it) |

### How an imported device matches a scanned one

- **MAC address.** A globally unique MAC decides alone. This is the safest column: DHCP lease files and anything with a MAC column match by it.
- **Declared host name.** Names from `csv`, `ad-csv`, `ad-ldif` and `netbox` are the list's own names for its devices, so a scanned device whose name matches (the first label, e.g. `pc-01` for `PC-01.corp.local`; two full names must be equal) *is* the listed device. Names are not authenticated: a hostile device can call itself `pc-01`. For an allow-list on a network you do not trust, list MAC addresses as well.
- **Client-reported host names** in DHCP leases are not declarations. A lease is matched by its MAC; its name is only a weak hint.
- **Address.** An entry with an address but neither MAC nor name is keyed by `ip:ADDRESS`, like a scanned host without a MAC. An address alone is weak evidence. An entry with several addresses is recognised by its first address, its MAC or its name.

### What is skipped

Rows without an address, MAC or name; leases that are not active (ISC `free`, `expired`, `abandoned`, `backup`; Windows states other than `Active*` and reservations); disabled Active Directory computers (`Enabled` false, `userAccountControl` bit 2); LDIF entries that are not computers; NetBox addresses whose status is not `active`. The command reports how many and why (the first few). NetBox devices with the status `planned`, `staged`, `failed`, `inventory` or `decommissioning` are imported but not expected.

### Starting the alerts

Importing fills the expected list but does not turn on alerting: a partial list would make every other device "unknown". When the list is complete, run `baseline enable` (or `baseline approve` after a scan); from then on `monitor` raises `unknown-device` for devices that are not on it.

### Limits

Files up to 32 MB and 100,000 devices; every value is cut at 4,096 characters. The parsers never panic on malformed input and have a fuzz target (`import_inventory`). The Windows DHCP XML and the NetBox shapes follow the vendors' documentation and sample exports; they have not been tested against a real server or a real instance. The formats differ between versions, so a file that does not import is reported with the reason.
