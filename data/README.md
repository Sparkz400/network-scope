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

## JA4+ is not implemented; JA3S, JARM, HASSH and key hashes are

The JA4+ fingerprints other than JA4 itself (JA4S, JA4X, JA4H and the rest) are under the **FoxIO License 1.1**, which does not permit monetization, and FoxIO describes them as patent pending. That does not fit the MIT licence of Network Scope, so none of them is implemented, and no FoxIO code, test data or example values are in the repository (an earlier version had JA4S and JA4X; they were removed on 2026-11-20). What is used instead:

- **TLS server stack:** JA3S (Salesforce, BSD-3-Clause; `tls.<port>.ja3s` and `ja3s_string`, `core/src/fingerprint.rs`), computed passively from the ServerHello, and JARM (Salesforce, BSD-3-Clause; `--jarm`). Only the published algorithm is used; the test vectors in `core/src/fingerprint/ja3s_vectors.rs` are ServerHellos of local servers that were generated for this project and confirmed with the reference `ja3s.py` (see [Lab and testing](../docs/src/lab-and-testing.md#ja3s)).
- **SSH server stack:** HASSHServer (Salesforce, BSD-3-Clause).
- **Certificates:** the SHA-256 of the public key (`tls.<port>.spki_sha256`).
- **Web interface:** the Shodan-compatible favicon hash. The MurmurHash3 and favicon hash code (`core/src/pivot.rs`) is written from the public-domain algorithm and checked with published test vectors.

## compliance.json

Original work of the Network Scope authors, under the project's MIT license. It maps finding rule ids to control identifiers of IEC 62443 (FR 1 to FR 7), the NIS2 Directive (Article 21(2)) and the CIS Controls v8 (safeguard numbers) for the compliance exports. Only identifiers and short titles are used, no text of the standards. They were written from memory of the published documents and not compared with the licensed texts; the assignment of findings to controls is the authors' judgment, not an official crosswalk. See [Inventory, diffs and reports](../docs/src/inventory-diff-reports.md#compliance-exports).

## Imported feeds (not shipped): CISA KEV and FIRST EPSS

Network Scope does **not** embed or download these. `feeds import` reads files that the user downloaded and stores them in a local cache (`feeds.json` next to the user `cves.json`); see [Findings and CVE hints](../docs/src/findings-and-cves.md#known-exploited-and-epss-offline-feeds). The test fixtures `tests/fixtures/kev.json` and `tests/fixtures/epss.csv` are invented examples in the same shape, not copies of the real data.

- **CISA Known Exploited Vulnerabilities (KEV)**: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`, published by the US Cybersecurity and Infrastructure Security Agency. Works of the US federal government are generally not subject to copyright in the United States, and CISA publishes the catalog for free use; this is the maintainers' reading, not legal advice, and users should follow CISA's website policies.
- **FIRST EPSS**: `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` (the file moved there from `epss.cyentia.com`; the address was read from FIRST's data page `first.org/epss/data` on 2026-11-19, through a page-summarizing tool, not by hand). The EPSS Special Interest Group at FIRST states that the scores are published daily, free of charge and without registration. No separate licence text or required attribution wording was found on that page; check the FIRST EPSS pages for current terms before redistributing the data. Network Scope keeps scores only in the user's local cache and shows them in reports the user generates; it does not redistribute the data set.

## Protocol layouts taken from public descriptions (no capture)

Some decoders and requests rest on a published description of the protocol and on no capture. Facts only (field offsets, magic bytes, command codes) are used; no code and no text is copied. Each is marked "spec only" in [OT / industrial](../docs/src/ot-industrial.md).

- **CODESYS V2 identification handshake** (`core/src/otpassive/codesys.rs`): the request `BB BB 01 00 00 xx 01` (xx 0 little endian, 1 big endian), the 0xBB marker of the reply and the offsets of the operating system name (64), operating system type (96) and product name (128), read on 2026-11-20 from the description of the script `codesys-v2-discover.nse` in Digital Bond's Redpoint repository (github.com/digitalbond/Redpoint; the file's licence header says "Same as Nmap"). The string widths (32 bytes) are inferred from the spacing of the offsets, which the description states only implicitly. No CODESYS capture was used or added.
- **MELSEC MC protocol 3E binary frame** (`core/src/ot/readonly/tcp_more.rs`, `core/src/ot/extra.rs`): the layout of the request and response frames and the codes of Read CPU Model Name (0x0101) as in Mitsubishi's MELSEC Communication Protocol Reference Manual (the same command names the passive decoder already uses). No capture of this protocol was used; the MELSOFT capture in `tests/fixtures/ics` is another protocol.
- **DNP3 data link framing** (`tcp_more.rs`): the layout and the CRC-16/DNP of IEEE 1815, checked against the header and data CRCs of a request in `dnp3_read_and_response.pcap` (the ITI/ICS-Security-Tools capture, see `tests/fixtures/ics/PROVENANCE.md`), whose class 0 object header (g60 v1) the Read class 0 request reuses.
- **FINS/TCP** (`tcp_more.rs`): the two client frames are packets 5 and 7 of `omron_test.pcap` (same provenance file).
- **MQTT 3.1.1 and KNXnet/IP** frames (existing requests): from the specifications; no capture.
