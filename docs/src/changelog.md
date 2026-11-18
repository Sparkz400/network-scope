# Changelog

The full changelog, in [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format, is maintained in the repository: [CHANGELOG.md](https://github.com/Sparkz400/network-scope/blob/main/CHANGELOG.md).

Release downloads and per-release notes: [GitHub Releases](https://github.com/Sparkz400/network-scope/releases).

## 0.5.0 at a glance

- Console binary `network-scope-cli` for scripts on Windows.
- SYN to routed IPv4 targets, adaptive SYN timing, ARP sweep, TCP/UDP/ICMPv6 traceroute.
- SMB 3.1.1 negotiate contexts and NTLM challenge, TLS 1.3 suite enumeration, JA4S-style and HASSHServer fingerprints.
- CVE hints from `data/cves.json` with user overrides, CPE names; UDP payload probes.
- Diff formats with new/resolved/unconfirmed findings; device history; Markdown and JSON Lines exports.
- Monitor alert sinks (webhook, syslog) with de-duplication.
- OT TCP reassembly, more pcap link types, passive OT section in the GUI.

Read the "Behaviour changes", "Not done" and "Untested" sections of the changelog before upgrading.
