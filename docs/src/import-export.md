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

## Export to other systems

```sh
network-scope-cli export ID --format netbox|netbox-devices|snipeit|splunk|elastic|servicenow [--output FILE]
```

One record per device of the saved scan (active scan and passive observations merged), with its risks. The files are what the target's own import or API takes.

| Format | Output | Fields |
| --- | --- | --- |
| `netbox` | JSON array for `POST /api/ipam/ip-addresses/` (NetBox bulk create) | `address` (`/32` or `/128`), `status` (`active`), `dns_name` (when the host name is a plain DNS name), `description` |
| `netbox-devices` | JSON array for `POST /api/dcim/devices/` | `name`, `device_type` (`{"model": ..}`), `role` (`{"name": ..}`), `site` (`{"name": ..}`), `status`, `comments`; needs `--netbox-site`, `--netbox-role` and `--netbox-device-type`, because NetBox requires them |
| `snipeit` | CSV for the Snipe-IT asset importer | `Name`, `Asset Tag` (`NS-` and the MAC or address), `Category`, `Manufacturer`, `Model`, `Asset Notes`, `MAC Address`, `IP Address` (the last two are custom fields to map in the importer's column mapper) |
| `splunk` | HTTP Event Collector events, one JSON object per line (concatenated JSON, which HEC accepts) | `time`, `source`, `sourcetype` (`network-scope:device`), `index` (only with `--index`), `event` with the device, its ports and its findings |
| `elastic` | `_bulk` NDJSON: an action line and a document per device, the last line ends with a newline | index `network-scope` (or `--index`), `_id` from scan time and device, `@timestamp`, the same document as the Splunk event |
| `servicenow` | CSV with `cmdb_ci` column names | `name`, `sys_class_name`, `ip_address`, `mac_address`, `manufacturer`, `os`, `short_description`, `discovery_source` (`Network Scope`), `operational_status` |

CSV cells that a spreadsheet would read as a formula get a leading `'`. The ServiceNow file is meant for an import set with your own transform map; the class names (`cmdb_ci_computer`, `cmdb_ci_netgear`, `cmdb_ci_printer`, `cmdb_ci_hardware`) are a suggestion.

### Pushing

```sh
export NETBOX_TOKEN=...
network-scope-cli export 12 --format netbox --push https://netbox.example.com --token-env NETBOX_TOKEN
```

`--push URL --token-env VAR` sends the export to NetBox, Splunk HEC or Elastic instead of (or besides, with `--output`) writing it. Nothing is ever sent without both options.

- **The token is read from the environment variable you name, and is sent only in the `Authorization` header.** A URL with `user:password@`, a query string or a fragment is refused, so no credential ends up in a URL, a log or the shell history. A missing or empty variable fails before any connection is made. The token is never printed.
- **`https://` is verified against the operating system's certificate store**, like webhooks. Plain `http://` is accepted only for this machine (`localhost`, `127.0.0.0/8`, `::1`): a token does not cross a network in clear text.
- A URL that names only a server gets the target's API path (`/api/ipam/ip-addresses/`, `/api/dcim/devices/`, `/services/collector/event`, `/_bulk`); a URL with a path is used as given. The scheme is chosen by the target: NetBox `Token` (or `Bearer` for `nbt_` tokens), Splunk `Splunk`, Elastic `ApiKey` (the base64 `encoded` value of the API key).
- The request is bounded by a 30 second timeout and fails unless the server answers 2xx. It is one request; nothing is retried.
- NetBox bulk creation is all-or-none: if any address already exists, the whole request is rejected. Push to a fresh NetBox, or import the file after removing what it already holds.
- `snipeit` and `servicenow` are files for the target's importer and cannot be pushed.

The field names follow the vendors' documentation. The exports and the pushes were tested against a local mock server only, not against a real NetBox, Snipe-IT, Splunk, Elastic or ServiceNow instance.
