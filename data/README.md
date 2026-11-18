# Data files

These files are embedded into the executables at build time (`include_str!`). This page records where each one comes from and under which terms it is used.

| File | Content | Origin |
| --- | --- | --- |
| `oui.tsv` | MAC prefix (hex) → organization name, tab-separated | IEEE Registration Authority public registries |
| `cip_vendors.tsv` | CIP vendor ID (decimal) → vendor name, tab-separated | Extracted from Wireshark's CIP dissector (see below) |
| `probes.json` | Service probes and match rules | Original to Network Scope |
| `cves.json` | Version-based CVE hint rules and CPE templates | Original to Network Scope |

## oui.tsv

- **Source:** the IEEE Registration Authority public registries MA-L, MA-M and MA-S, downloaded from `standards-oui.ieee.org` on 2026-11-16.
- **Processing:** reduced to prefix and organization name; addresses and other columns are dropped.
- **Rights:** the registry data is published by the IEEE (© IEEE) for public lookup. The organization names are factual assignment records. The list reflects the registry on the retrieval date; newer assignments are unknown.
- **Update:** download the three registries again and regenerate the file in the same two-column format, then update the date here and in `THIRD-PARTY-NOTICES.md`.

## cip_vendors.tsv

- **Source:** the ODVA CIP vendor ID list as it appears in the vendor table of Wireshark's CIP dissector, `epan/dissectors/packet-cip.c`.
- **Processing:** only the numeric vendor IDs and vendor names were taken. No Wireshark code, comments or structure is included.
- **Licensing note:** Wireshark is licensed under **GPL-2.0-or-later**. Network Scope is MIT-licensed. The vendor ID → name pairs are treated as factual data (public registry assignments maintained by ODVA), not as copyrightable expression of the Wireshark source. This is the maintainers' assessment, not legal advice. If you redistribute Network Scope under terms where this matters to you, you can replace this file with a list obtained directly from ODVA; only the IDs and names are needed.
- **Use:** EtherNet/IP identification (`--ot`) and passive OT discovery show the vendor name next to the vendor ID.

## probes.json

Original work of the Network Scope authors, under the project's MIT license. The `_comment` field documents the format. Users can extend or override probes with their own file; see [Detection](../docs/src/detection.md#extending-the-probe-database).

## cves.json

Original work of the Network Scope authors, under the project's MIT license. The rules are hand-written version ranges that reference public CVE identifiers. The CPE vendor/product names were written from memory of the NVD CPE dictionary and have not been checked against it. See [Findings and CVE hints](../docs/src/findings-and-cves.md).
