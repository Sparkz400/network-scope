# Reproducible scans

A finding you cite in a report should be possible to check later. Network Scope stamps every scan it runs with the version of the tool and a SHA-256 of the rules and feeds that shaped the result, can keep the payloads the scan sent, and can run a stored scan again and say what differs.

## The stamp

Scans started by `scan`, `monitor`, the MCP `scan` tool and the desktop app carry `settings.provenance`, so it is in the stored snapshot and in every JSON export:

```json
"provenance": {
  "tool": "network-scope 0.5.1",
  "rules": { "probes.json": "sha256:...", "cves.json": "sha256:...", "compliance.json": "sha256:..." },
  "feeds": { "nvd": "sha256:..." },
  "combined": "sha256:..."
}
```

What is hashed is the rule set *in effect*: the built-in service probes merged with the user file, the built-in CVE rules merged with the user's `--cves` file, the embedded compliance table, and, when imported, the KEV/EPSS data, the NVD cache and the CSAF advisories (`feeds`; absent when not in use). The NVD hash covers the import time, the source files and every CVE with its rating, not the CPE ranges (the cache can be a gigabyte). `combined` is one hash over the tool string and all entries: the value to cite. Imports (nmap XML, device lists) and scans saved by older versions have no stamp. In the desktop app the stamp is taken when a scan starts (scheduled scans included) and shown in the *Scan details* section of the Inventory window, with a button that copies the tool and the combined hash to cite; a scan opened from the inventory shows the stamp it was saved with, or says it has none, and is never stamped again.

## `scan --replay-check ID`

```sh
network-scope-cli scan --replay-check 12 [--format text|json] [--fail-on-findings]
```

runs stored scan 12 again with **its own targets and settings** (scan options on the command line are refused; only the scope and consent options, `--dry-run`, `--record` and `--db` apply), saves the new scan, and compares the two: the results (hosts, ports, identity, findings), the provenance stamps and the sent logs. It is a normal scan: it sends the same traffic, goes through the scope guard, and `--dry-run` shows what it would send. The output says whether the scan was **reproduced** (same result and same rules) or not and lists the differences: changed rules or feeds (by name), changes in the result, and packets sent a different number of times. A difference in the result can be a real change in the network, a changed rule, or timing (slow hosts, packet loss); the report does not decide which. With `--fail-on-findings` the exit status is 3 when the scan was not reproduced. A scan without a stamp can be re-run, but is never "reproduced": which rules it used is unknown.

## `scan --record FILE.pcapng`

Keeps the bytes the scan handed to its sockets and received, with time, peer and direction, and writes them as pcapng. **This is an application-level record, not a wire capture.** The scanner uses ordinary sockets and never sees the headers it sends, so the file puts each payload into a *synthetic* Ethernet/IP/TCP or UDP frame: the MAC addresses, the scanner's address (a documentation address) and port and all sequence numbers are made up, there are no handshake, acknowledgement or closing frames, long payloads are split at 1,400 bytes, and the time stamps are the moments the scan handed the bytes over or received them. The file header and a comment on every packet say so. Wireshark, `tshark` and `ot-listen --pcap` read it; the passive decoders find the Modbus request of a recorded scan.

Recorded: the read-only OT requests and their replies (Modbus, S7, EtherNet/IP, OPC UA, BACnet) and the payloads of service identification (probes, the HTTP request and reply, the SMB and RDP negotiate requests; HTTP inside TLS is recorded decrypted and labelled so). **Not recorded:** the TCP connects, ICMP, ARP, the UDP scan's probes, DNS lookups, the TLS handshake, SSH and traceroute; the sent log (`--sent-log`) still counts them, and `scan --record` prints how many packets the sent log lists. The record is bounded (500,000 payloads, 128 MB, 4 KB per payload); what does not fit is counted and reported.

## Tested and not tested

Tested with real scans of a loopback listener (the record reads back as frames holding the request and its reply and the passive decoders decode a recorded Modbus request; a replay is reproduced, and a stamp of other rules is reported) and with synthetic scans. The desktop app's stamp is covered by unit tests (the stamp equals the CLI's, survives the inventory, the preferences never hold it) and was looked at in screenshots, but a scan started by clicking Start in the window was not run in this check. Not tested: a replay against a changing real network, and the pcapng file in Wireshark itself (it was read back with this program's reader and its checksums verified, not opened in another tool).
