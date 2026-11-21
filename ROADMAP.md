# Roadmap

End goals for Network Scope after 0.5.0. Each goal has a "done when" test where one applies, so it is clear when it is met.

## North star

**Point it at any network and, in under a minute, get a correct, explained answer to: what's here, what changed, and what's risky. It must never harm a device.**

## Priority order

1. Real-hardware testing to clear the changelog's "Untested" section (A1, A7)
2. Ground-truth accuracy benchmark in CI (A2)
3. Published speed comparison (B10)
4. Fuzz the parsers (A5)
5. Code signing and winget (I55, I56)
6. "What changed" home screen plus approved baseline (E31, E32)
7. Passive mDNS/SSDP/LLDP/DHCP discovery (C19)
8. CISA KEV/EPSS ranking (D25)
9. Explain every conclusion (A9)
10. Library crate and split the largest files (G50, J61)

Items 1–4 are what back a claim of "fastest and most accurate". The rest make it the most useful.

---

## A. Trust and accuracy (prove it works)

1. **Clear the "Untested" list in the changelog.** Run SYN (on-link and routed), the ARP sweep, TCP traceroute, live OT capture and DCP on real Npcap/libpcap. *Done when that changelog section is empty.* *Status: on-link SYN, the ARP sweep, TCP traceroute, live OT capture and DCP ran on a real home LAN (Windows 11, Npcap, not elevated, 2026-11-20); SYN and traceroute to routed targets and libpcap on Linux/macOS remain.*
2. **Ground-truth lab benchmark.** Use a lab where every host and port is known, and measure how many real hosts are found, how many reported ports are real, how many open ports are found, and how often the service and OS are named correctly. *Done when each release publishes these numbers and CI fails if they get worse.* *Status: done (`lab/benchmark.py` with a CI gate; Windows and Linux baselines).*
3. **Automatic nmap comparison.** Scan the same targets with both tools, import nmap's result (the XML import already exists) and diff ports and services automatically. *Done when every difference is explained or fixed.* *Status: done (`lab/nmap_compare.py`, every difference explained in `lab/nmap_differences.json`).*
4. **Real industrial traffic for tests.** Collect public ICS pcaps for Modbus, S7, EtherNet/IP, IEC 104 and OPC UA and use them as test fixtures. Today the OT decoders are only tested on synthetic frames. *Status: done (licence-checked public captures as tests, provenance recorded).*
5. **Fuzz every parser** (TLS, SMB, pcap/pcapng, OT decoders, nmap XML) with `cargo-fuzz`. *Done when 24 hours of fuzzing produce no crashes.* *Status: every parser has a cargo-fuzz target; the weekly `fuzz-long` workflow fuzzes all of them for about 24 h in five shards. Done once a full run ends without a crash.*
6. **Test against real servers:** Samba, OpenSSL/Schannel (TLS 1.3 suites), the JA3S reference implementation and the NVD CPE dictionary. *Status: done (Samba, OpenSSH, OpenSSL, nginx, Windows Schannel, the JA3S reference `ja3s.py` and JARM `jarm.py`; NVD CPE names).*
7. **Run Linux and macOS on a real network.** Today CI is the only place that code compiles.
8. **A false-alarm budget for each risk rule.** Every rule in `src/risk.rs` gets a test that must trigger it and one that must not. Track the false-alarm rate. *Status: done.*
9. **Explain every conclusion.** Each device type, OS guess and finding shows its evidence ("printer because port 9100, PJL banner, HP MAC prefix") and a confidence score. *Status: done.*

## B. Speed (the fastest tool that needs no admin rights)

10. **Published speed comparison** against nmap -T4, RustScan and Advanced IP Scanner. Measure a /24, a /16 and the 100/1000 most common ports. *Target: the fastest tool that needs no driver.* *Status: `lab/speed_compare.py`, the `speed` workflow (nmap 7.94 and RustScan 2.4.1 on Ubuntu) and `docs/src/speed.md`; the Linux CI table (2026-11-21) has nmap and RustScan on a loopback /24 with the top 100 and 1000 ports: Network Scope 0.17 s / 1.23 s, nmap `-sS` 0.24 s / 1.22 s, nmap `-sT` 0.20 s / 1.76 s, RustScan 0.93 s / 8.66 s, all correct; a home /24 with the top 100 ports is measured for Network Scope only (28 s `--fast --tcp-only`). Open: the /16 cell (weekly run), other tools on a real LAN, and Advanced IP Scanner (no CLI, not measured).*
11. **First result in under 200 ms**, with results appearing as they arrive rather than at the end. *Status: done (`scan --stream`, live rows in the desktop and the terminal view).*
12. **Adaptive timing for the normal TCP scan too,** not only SYN (per-host round-trip time, like `--adaptive-syn`). *Status: done; on by default since 2026-11-21 (`--no-adaptive-tcp` turns it off).*
13. **Probe the likeliest ports first** for each device type, and stop early once the device is identified. *Status: done (`--early-stop` opt-in).*
14. **Fast repeat scans:** skip hosts that haven't changed and only check what's likely to have changed. This makes monitoring cheap. *Status: done (`--incremental`).*
15. **Scale:** handle a /8 or 1M+ targets with flat memory use, by generating targets on the fly and writing to SQLite in batches. *Status: done (batched writing above 65,536 addresses).*
16. **Scan several subnets and network interfaces at the same time.** *Status: done for several subnets and `--interface a,b`; one scan over a real Ethernet adapter and a VMware adapter checked (2026-11-20).*
17. **Resource budgets checked in CI:** starts in under 150 ms, uses under 200 MB on a /16, and the GUI stays at 60 fps with 65k rows. *Status: done (budgets in CI).*
18. **Performance tests in CI** (criterion benchmarks) so a slow change can't be merged unnoticed. *Status: done (criterion benchmarks in CI).*

## C. Discovery breadth (find more, send less)

19. **Learn from traffic that's already there:** mDNS/Bonjour, SSDP/UPnP, LLDP/CDP, NetBIOS, WS-Discovery and DHCP fingerprints. This identifies devices without sending a single packet. *Status: done (also NetBIOS browser announcements, LLDP-MED and DHCPv6; the last two checked on spec-built frames only).*
20. **SNMP read-only** (v1/v2c/v3 with user-supplied credentials): system description, interfaces, and LLDP neighbours to build a real topology. *Status: done (read-only v1/v2c/v3, LLDP links, checked against pysnmp).*
21. **Full IPv6 discovery:** NDP and multicast ping (ff02::1). *Status: done (`--ipv6-discover`, passive NDP; checked against real neighbours on a home LAN on Windows; not run on Linux/macOS).*
22. **Optional logins for exact versions:** read-only SSH, WinRM or WMI give the exact OS and patch level, which makes CVE hints far more accurate. *Declined (2026-11-19): the tool stays credential-free.*
23. **More OT protocols, all read-only:** DNP3, IEC 61850 MMS, Omron FINS, Mitsubishi MELSEC, CODESYS, KNX, MQTT, Niagara Fox, plus fuller Profinet. *Status: done for FINS (UDP/TCP), Fox, MQTT, KNX, MELSEC MC and DNP3 (opt-in), passive MMS and CODESYS V2; active MMS Identify not done (no capture to verify against).*
24. **Device identity that survives IP changes and randomized MAC addresses.** *Status: done.*

## D. Findings and vulnerabilities

25. **Offline CVE feeds:** import NVD plus CISA KEV and EPSS, and rank findings by "being exploited right now". *Status: done (KEV, EPSS and NVD).*
26. **A risk score per host and per network**, plus a "fix these 10 things first" list. *Status: done.*
27. **Fix steps and reference links for every finding.** *Status: done (an official reference link and fix steps for every rule; a test fails for a rule without them).*
28. **HTTPS webhooks** via the OS certificate store (`rustls-platform-verifier`). Removes an item from "Not done". *Status: done.*
29. **Close the rest of "Not done":** verify the signature on self-signed certificates, and add optional JARM fingerprints when Safe Mode is off. *Status: done.*
30. **Compliance exports:** asset inventory mapped to IEC 62443, NIS2 and the CIS Controls. *Status: done.*

## E. Inventory and change tracking

31. **A "what changed" home screen:** new, gone and changed devices and new risks since the last scan or the last week. *Status: done.*
32. **An approved baseline:** tags, owners, how critical each device is, and an "expected devices" list, with an alert for anything unknown. *Status: done.*
33. **Import** from CSV, DHCP leases, Active Directory and NetBox. *Status: done.*
34. **Export and sync** to NetBox, Snipe-IT, Splunk HEC, Elastic and a ServiceNow-ready CSV. *Status: done.*
35. **A device timeline view in the GUI** (the CLI already has `devices --history`). *Status: done.*

## F. User experience

36. **"Scan my network" in one click,** with interfaces and subnets detected automatically. *Status: done.*
37. **An interactive network map** built from traceroute, LLDP and SNMP. *Status: done.*
38. **Everyday convenience features:** openers (browser, SSH, RDP, ping), favorites, reading targets from an IP list file, random order and Wake-on-LAN. *Status: done.*
39. **Command palette and search across all scans** ("where did 10.0.5.17 last appear?"). *Status: done.*
40. **Scan presets:** Quick, Office, Plant (passive), Full audit. *Status: done.*
41. **Plain-language findings** with an "explain this" tooltip, written for non-experts. *Status: done (an "explain this" button per finding, English and German, tied to the finding pages by a test).*
42. **Translations** (German, for example) and accessibility: keyboard-only use, screen readers, high DPI. *Status: done (German, dark theme, scale, screen reader names checked in the accessibility tree).*
43. **A visible Safe Mode indicator** that always shows what the scan is about to send. *Status: done (the status-bar badge lists what the next scan sends, computed from the dry-run plan and updated live).*

## G. Automation and integration

44. **A versioned JSON output format and stable exit codes,** so the tool is reliable in scripts and CI. *Status: done (exit codes and versioned JSON with schema files).*
45. **Headless server mode with a REST API and web UI.** *Declined (2026-11-19).*
46. **Remote sensors:** lightweight scanners at each site that report to one central inventory. *Declined (2026-11-19).*
47. **An MCP server,** so AI assistants can query the inventory ("which hosts gained SMBv1 this month?"). *Status: done (stdio, read-only queries and a Safe Mode scan, in the call or in the background with `scan_status`; protocol revisions up to 2025-11-25 and the stateless 2026-07-28; tried with Claude Code 2.1.302).*
48. **A Windows service and systemd unit for `monitor`,** and a scheduler in the GUI. *Status: done.*
49. **A shared library of Rhai scripts,** plus scripts that run when an alert fires. *Status: done.*
50. **Split the engine into a library crate** (`network-scope-core`) so other tools can build on it. *Status: done.*

## H. Safety (a guarantee that can be proven)

51. **A compile-time guarantee for OT:** make it a type error to send a write or control function code, backed by property tests. This turns the read-only promise into something provable. *Status: done for all active OT requests including Profinet DCP Identify.*
52. **Automatic back-off** when a device starts resetting connections or dropping packets, with per-device-type rate limits. *Status: done.*
53. **A dry run** that shows exactly which packet types a scan would send to each host, plus a log of every packet type actually sent. *Status: done.*
54. **A scope guard** that asks for confirmation before scanning public IPs or anything outside the declared scope. *Status: done.*

## I. Distribution and trust

55. **Code signing:** Windows Authenticode and macOS notarization, so SmartScreen stops warning. *Status: signing steps in the release workflow (Azure Artifact Signing, macOS notarization) that run once the secrets exist; no certificate or account yet.*
56. **Package managers:** winget, Scoop, Chocolatey, Homebrew, AUR/apt, `cargo install` and a Docker image. *Status: winget, Scoop, Chocolatey, Homebrew and AUR manifests rendered for every release; submitting them is manual (`packaging/README.md`); Docker image done.*
57. **Supply-chain checks:** reproducible builds, an SBOM (CycloneDX), `cargo-deny`/`cargo-audit` in CI, and signed releases. *Status: done (SBOM; two Windows builds byte-identical; Linux check in CI).*
58. **Build and test the installer in CI** (`installer/network-scope.iss` has never been compiled with `iscc`). *Status: done (CI compiles the installer, installs it silently, runs both binaries and uninstalls it).*
59. **Opt-in auto-update** that checks signatures. *Status: done (notify only).*
60. **A small CLI-only build** without the GUI dependencies, for servers and jump hosts. *Status: done.*

## J. Code health

61. **Split the largest files** (`src/service.rs` 2.8k lines, `src/otpassive.rs` 2.3k (done: `src/otpassive/`, no file over 600 lines), `src/ui.rs` 2k) into focused modules. *Status: done.*
62. **Coverage targets:** at least 80% on parsers and risk rules. *Status: done.*
63. **Run the lab end-to-end check with more scenarios in CI,** such as a simulated slow WAN, packet loss and fragile OT devices. *Status: done.*

## K. Product and community

64. **A comparison page** against Advanced IP Scanner, nmap, Lansweeper and RustScan, backed by the benchmark numbers. *Status: done.*
65. **A way for users to contribute fingerprints and probes** through pull requests, with safety review and without telemetry. *Status: done.*
66. **A documentation page for each finding,** linked from the GUI. *Status: done (pages, GUI Learn more links).*

## L. Security research

Turn the inventory into something you can ask research questions of, without giving up the read-only promise. Suggested order: L67 first (the others build on it), then L68 and L69. Out of scope on purpose: exploitation, credential brute-forcing and evasion, which conflict with the north star.

67. **A research data layer.** Store hosts, services, certificates, fingerprints and findings in queryable SQLite tables instead of only the per-scan `snapshot` text, and export to Parquet/DuckDB and to STIX 2.1 and OCSF. *Done when "every host that presented this certificate key in the last six months" is one SQL query.* *Status: done (SQL tables, read-only query, CSV/NDJSON/Parquet/STIX/OCSF validated).*
68. **Offline vulnerability intelligence for OT.** Match versions against an offline copy of the NVD feed, rank by KEV and EPSS (builds on D25), and match the S7, CIP and OPC UA vendor, product and firmware fields against CISA ICS advisories in CSAF format. *Done when the hand-written rules in `data/cves.json` are a fallback, not the main source.* *Status: done (CSAF advisories and NVD before the hand-written rules).*
69. **Learn normal OT traffic.** From a pcap or live capture, learn who talks to each PLC, with which function codes and how often, and alert on anything new: a new engineering station, a first-ever write, a Stop outside a maintenance window. Builds on the control-traffic detection in `src/otpassive/`. *Done when the lab replays a capture with one injected write from a new station and exactly that is reported.* *Status: done.*
70. **Fingerprints you can pivot on.** Add JA4X (certificates), JA4H (HTTP), a Shodan-compatible favicon hash and certificate key hashes next to JA4S and HASSH, and group devices that likely share firmware or a key across scans and sites. *Status: done for the favicon hash, JA3S, JARM, HASSH, key hashes and device groups; JA4X and JA4H not implemented (FoxIO License 1.1 conflicts with MIT).*
71. **Check network segmentation.** Scan from several vantage points (sensors, or "as if from VLAN X"), compare what each can reach against the declared zones and conduits, and report every unexpected path. *Done when a segmentation report lists each path that breaks the intended IEC 62443 zone model.* *Status: done for a single vantage point (lab-checked).*
72. **Reproducible scans.** Record the tool's own scan traffic as pcapng and stamp each result with the tool version and a hash of the rules files, so a finding can be cited and re-run exactly. Extends H53. *Status: done (provenance stamp, `--replay-check`, `--record` and `--record-wire`).*
73. **A workbench for unknown devices.** Queue responses that nothing identifies, group similar banners, compare responses across firmware versions, and turn the result into a pull request for `data/probes.json`. Feeds K65. *Status: done.*
74. **A deliberately vulnerable OT lab.** Grow `lab/` from simulators into a small test plant (OpenPLC and similar) with planted weaknesses, used as a benchmark for findings and for L69. Extends A2. *Status: done.*
