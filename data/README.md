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

Original work of the Network Scope authors, under the project's MIT license. The rules are hand-written version ranges that reference public CVE identifiers. The CPE vendor/product names were written from memory; on 2026-11-19 they were looked up in the NVD CPE API (one was wrong and is fixed, see [Lab and testing](../docs/src/lab-and-testing.md#cpe-names-against-the-nvd-dictionary)), and `lab/check_cpe.py` compares them with the official NVD CPE dictionary in CI. See [Findings and CVE hints](../docs/src/findings-and-cves.md).

## JA4X and JA4H

JA4X (`tls.<port>.ja4x`, `core/src/pivot.rs`) is also part of JA4+ and under the FoxIO License 1.1, like JA4S (see below); the same open question applies. It was implemented from the published description (the SHA-256 of the hex OIDs of the issuer, the subject and the extensions, 12 hex digits each) without FoxIO code or test files. On 2026-11-20 it was compared, once and outside the repository, with the JA4X values and raw OID lists in FoxIO's own test data (github.com/FoxIO-LLC/ja4, commit `7388fa0dd43f43ba63eabf36b0867b4920f2ca52`, `wireshark/test/testdata`; the DER certificates were extracted from the 11 captures with `tshark` 4.6.10): 60 of 60 equal. Those vectors and captures are under the FoxIO License 1.1 (non-commercial use only), so they are **not** part of this repository. JA4H fingerprints an HTTP request, which a scanner sends but a device does not, so it is not implemented. The MurmurHash3 and favicon hash code (`pivot.rs`) is written from the public-domain algorithm and checked with published test vectors.

## JA4S test values

The tests in `core/src/fingerprint.rs` contain three JA4S example fingerprints (`t120300_c030_5e2616a54c73`, `t130200_1301_a56c5b993250`, `t130200_1302_a56c5b993250`) and one pair from the python test data (`t130200_1301_234ea6891581` for the extensions `0033,002b`), all published by FoxIO in the JA4+ repository (github.com/FoxIO-LLC/ja4, README examples table and `python/test/testdata`). Only these fingerprint strings are used, as published facts for checking our implementation; no code or test files were copied. JA4S is part of JA4+, which FoxIO licenses under the FoxIO License 1.1 (permissive for internal use, not for monetization) and describes as patent pending; Network Scope is MIT-licensed. Whether shipping a JA4S implementation is acceptable is an open question for the maintainers.

## compliance.json

Original work of the Network Scope authors, under the project's MIT license. It maps finding rule ids to control identifiers of IEC 62443 (FR 1 to FR 7), the NIS2 Directive (Article 21(2)) and the CIS Controls v8 (safeguard numbers) for the compliance exports. Only identifiers and short titles are used, no text of the standards. They were written from memory of the published documents and not compared with the licensed texts; the assignment of findings to controls is the authors' judgment, not an official crosswalk. See [Inventory, diffs and reports](../docs/src/inventory-diff-reports.md#compliance-exports).

## Imported feeds (not shipped): CISA KEV and FIRST EPSS

Network Scope does **not** embed or download these. `feeds import` reads files that the user downloaded and stores them in a local cache (`feeds.json` next to the user `cves.json`); see [Findings and CVE hints](../docs/src/findings-and-cves.md#known-exploited-and-epss-offline-feeds). The test fixtures `tests/fixtures/kev.json` and `tests/fixtures/epss.csv` are invented examples in the same shape, not copies of the real data.

- **CISA Known Exploited Vulnerabilities (KEV)**: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`, published by the US Cybersecurity and Infrastructure Security Agency. Works of the US federal government are generally not subject to copyright in the United States, and CISA publishes the catalog for free use; this is the maintainers' reading, not legal advice, and users should follow CISA's website policies.
- **FIRST EPSS**: `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` (the file moved there from `epss.cyentia.com`; the address was read from FIRST's data page `first.org/epss/data` on 2026-11-19, through a page-summarizing tool, not by hand). The EPSS Special Interest Group at FIRST states that the scores are published daily, free of charge and without registration. No separate licence text or required attribution wording was found on that page; check the FIRST EPSS pages for current terms before redistributing the data. Network Scope keeps scores only in the user's local cache and shows them in reports the user generates; it does not redistribute the data set.
