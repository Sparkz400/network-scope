# Data sources

Network Scope embeds four data files at build time. Their provenance and licensing are documented in [`data/README.md`](https://github.com/Sparkz400/network-scope/blob/main/data/README.md).

| File | Content | Source |
| --- | --- | --- |
| `data/oui.tsv` | MAC address prefix → organization name | IEEE Registration Authority public registries (MA-L, MA-M, MA-S) |
| `data/cip_vendors.tsv` | EtherNet/IP (CIP) vendor ID → vendor name | ODVA CIP vendor ID list, as extracted from a public table (see `data/README.md`) |
| `data/probes.json` | Service probes and match rules | Original to Network Scope |
| `data/cves.json` | Version-based CVE hints and CPE templates | Original to Network Scope |

## Imported feeds

CISA KEV and FIRST EPSS are not embedded. You download them and import them with `feeds import`; the cache is `feeds.json` next to the user `cves.json` (or `--feeds FILE`). See [Findings and CVE hints](findings-and-cves.md#known-exploited-and-epss-offline-feeds) for the download addresses and what changes. The NVD CVE JSON 2.0 feed is imported the same way (`feeds import nvd FILE...`, cache `nvd.json`); see [NVD import](findings-and-cves.md#nvd-import-offline). CISA ICS advisories in CSAF format are imported with `feeds import csaf` (cache `csaf.json`); see [CISA ICS advisories](findings-and-cves.md#cisa-ics-advisories-for-ot-devices-csaf-offline).

## User overrides

`probes.json` and `cves.json` can be extended without rebuilding:

- `%LOCALAPPDATA%/NetworkScope/probes.json` or `--probes FILE`: entries with the same `name` replace built-in probes, new names are added. See [Detection](detection.md#extending-the-probe-database).
- `%LOCALAPPDATA%/NetworkScope/cves.json` (or `$XDG_CONFIG_HOME/NetworkScope/cves.json`, else `~/.config/NetworkScope/cves.json`) or `--cves FILE`: entries with the same `id` replace built-in rules. See [Findings and CVE hints](findings-and-cves.md).

## Limits of the data

- The MAC vendor list reflects the registry on its retrieval date; newer assignments are unknown. Locally administered (randomised) MACs are marked as such instead of looked up.
- CPE vendor/product names in `cves.json` were written from memory of the NVD dictionary and have not been checked against it.
- The top-ports ordering is approximate, recalled from public scanner statistics, and not generated from any third-party services file.

Third-party libraries and their licenses are listed in [THIRD-PARTY-NOTICES.md](https://github.com/Sparkz400/network-scope/blob/main/THIRD-PARTY-NOTICES.md).
