# Comparison with other tools

This page compares Network Scope with nmap, RustScan, Advanced IP Scanner and Lansweeper. The feature table is facts only. The measured section has numbers from one machine and one lab, and only for the tools that were actually run (Network Scope and nmap). Port-scan speed on a /24 and a /16 with the top 100 and top 1000 ports, including RustScan, has its own page: [Speed comparison](speed.md).

## Features

A dash (—) means "not checked or not stated in the sources used here". It does not mean the tool lacks the feature. Statements about other tools are taken from each tool's public documentation as read on 2026-11-19 (the nmap manual at nmap.org, the RustScan README, the Advanced IP Scanner product page) and may be out of date. The Lansweeper site refused automated access, so that column is empty; check its documentation yourself.

| | Network Scope | nmap | RustScan | Advanced IP Scanner | Lansweeper |
| --- | --- | --- | --- | --- | --- |
| Scanning without a driver or raw sockets | Yes: async TCP connect scan, no driver, no admin rights | Yes: connect scan (`-sT`) uses the operating system's `connect`, per its manual | — | — | — |
| SYN scan | Yes, optional (`--syn`; needs Npcap or libpcap and capture rights) | Yes (`-sS`, the default when raw packets are possible, per its manual) | — | — | — |
| UDP scan | Yes (`--udp`: DNS, DHCP, NTP, NetBIOS, SNMP, SSDP, mDNS) | Yes (`-sU`, per its manual) | — | — | — |
| Service and version detection | Yes (banners, data-driven probes, HTTP, TLS, SSH, SMB, RDP, databases) | Yes (`-sV`, per its manual) | Per its README it pipes the ports it finds into nmap; whether that includes version detection is not stated there | — | — |
| OS guess | Yes (`--os`, from banners, TTL and fingerprints) | Yes (`-O`, per its manual) | — | — | — |
| OT / ICS, passive | Yes (pcap or live interface, control-traffic detection) | — | — | — | — |
| OT / ICS, active and read-only | Yes (Modbus/TCP, S7, EtherNet/IP, BACnet/IP, OPC UA identification) | — (it has a scripting engine, NSE; ICS scripts were not checked here) | — | — | — |
| Safe Mode (conservative defaults) | Yes, on by default: 8 hosts, at least 100 ms between probes, no SYN, no ARP sweep | — | — | — | — |
| Risk findings | Yes (weak TLS/SSH, cleartext protocols, unauthenticated services, SMB, CVE hints) | — (NSE scripts; not checked here) | — | — | — |
| Inventory, diff, monitoring | Yes (SQLite inventory, scan diffs, repeated scans with alerts) | Ndiff compares two XML scan files, per its documentation; no inventory or monitoring found there | — | — | — |
| GUI | Yes (desktop) | — | — | The product page shows a program window | — |
| CLI | Yes (plus a live terminal view) | Yes | — | — | — |
| Licence | MIT | Distributed under the Nmap Public Source License, per its documentation | — | Free to download per its page; licence terms not stated there | — |
| Platforms | Windows, Linux, macOS (Linux and macOS are built and tested in CI only and have not been used on a real network yet) | — | — | Windows 11, 10, 8 and 7, per its page | — |

Other things the sources say that are not rows above: Advanced IP Scanner offers access to network shares and remote control through RDP and Radmin and can switch computers on and off remotely (product page). These are not rows above because they are not what this comparison is about.

Network Scope's rows are what this repository documents; the parts that have not run on real hardware are listed in [Lab and testing](lab-and-testing.md#what-has-not-been-tested).

## Measured on the lab

These are timings and accuracy for Network Scope and nmap on the loopback lab described in [Lab and testing](lab-and-testing.md#accuracy-benchmark): six simulated hosts on `127.0.10.1` to `127.0.10.6` and three addresses where nothing runs, each scanned on the same 11 TCP ports (the 11 open ones plus 25, 2222, 8081 and 9999, which are closed). RustScan, Advanced IP Scanner and Lansweeper were not measured here: they are not installed on this machine. RustScan is part of the [speed comparison](speed.md), which CI runs on Linux.

Setup:

- Machine: Windows 11 Pro (10.0.26300), Intel Core Ultra 7 155H (22 logical processors), 64 GB RAM. Run on 2026-11-19, everything on loopback.
- Network Scope 0.5.1, release build of the repository state `59f3947` plus the nmap comparison script. nmap 7.98 (Windows build).
- Python 3.13 runs the simulators and `lab/nmap_compare.py`.
- Wall time is measured by the script around each process (`time.monotonic`), five runs per configuration, median with minimum and maximum. The simulators run in the same Python process as the script.

Commands, as printed by the script (`<addresses>` is the nine lab addresses, `<ports>` is `21,22,23,25,502,2222,6379,8080,8081,9999,44818`):

```sh
python -I lab/nmap_compare.py --cli <path>/network-scope-cli --explain lab/nmap_differences.json --timing --repeat 5

nmap -sT -Pn -n -T4 -p <ports> -oX nmap.xml <addresses>          # "nmap -sT -T4"
nmap -sT -Pn -n -T4 -p <ports> -sV -oX nmap.xml <addresses>      # "nmap -sT -sV -T4"
network-scope-cli scan <addresses> --fast --tcp-only --ports <ports> --timeout 1500 --quiet
network-scope-cli scan <addresses> --fast --services --tcp-only --ports <ports> --timeout 1500 --quiet
network-scope-cli scan <addresses> --fast --deep --ot --tcp-only --ports <ports> --timeout 1500 --quiet
```

(each Network Scope scan also gets `--db` and `--output` paths). `-Pn` skips nmap's host discovery because every `127.x.x.x` address answers ping. `--tcp-only` is the matching choice for Network Scope, as in the benchmark. The simulators wait 12 s for a client that speaks first (`--idle 12`); see below for what the lab's own 2 s does to nmap.

### Wall time and accuracy

Accuracy is scored against the lab's ground truth (`lab/ground_truth.json`): 11 open TCP ports, 11 service names and 8 product-and-version pairs (for example vsFTPd 2.3.4, Apache 2.4.49). nmap's XML is scored after it has gone through Network Scope's importer, which maps nmap's product names to Network Scope's (for example "Apache httpd" to "Apache"). A configuration without service detection is scored "n/a" for services and products: names that a port table would give are not detection.

| Configuration | Wall time, median (min to max) | Open ports found | Reported open ports that are real | Service names | Product and version |
| --- | --- | --- | --- | --- | --- |
| `nmap -sT -T4` | 0.14 s (0.12 to 0.17) | 11/11 | 11/11 | n/a | n/a |
| `network-scope-cli scan --fast --tcp-only` | 3.17 s (3.13 to 3.18) | 11/11 | 11/11 | n/a | n/a |
| `nmap -sT -sV -T4` | 6.41 s (6.40 to 6.51) | 11/11 | 11/11 | 10/11 | 8/8 |
| `network-scope-cli scan --fast --services --tcp-only` | 3.58 s (3.56 to 3.59) | 11/11 | 11/11 | 9/11 | 8/8 |
| `network-scope-cli scan --fast --deep --ot --tcp-only` | 6.59 s (6.58 to 6.62) | 11/11 | 11/11 | 11/11 | 8/8 |

How to read it:

- Pair like with like: `nmap -sT -T4` with Network Scope's port scan, `nmap -sT -sV` with `--services`. The `--deep --ot` line does more than `nmap -sV`: it also probes UDP, guesses the OS and identifies industrial protocols, which is where its 11/11 service names come from (Modbus and EtherNet/IP are named through the OT identification).
- The one service name nmap misses is EtherNet/IP on port 44818, which it calls `ethernet-ip-2` and the ground truth calls `ethernet/ip`: a naming difference, scored as a miss. `--services` alone misses ports 502 and 44818 because Network Scope never sends generic service probes to industrial ports by design; `--ot` covers them.
- The two port scans differ by 3 s, and that is not the cost of Network Scope's scanning work. On this Windows machine a refused connection to a closed loopback port takes about 2.0 s to be reported (a plain Python socket: 2.01 s), longer than the 1500 ms timeout, so Network Scope waits out its timeouts and records the 88 closed ports as unanswered rather than closed. nmap reported them as closed and finished in 0.14 s; how it avoids the wait was not investigated. On Linux, where a refusal is immediate, this gap is not expected, but that was not measured. See [Comparison with nmap](lab-and-testing.md#comparison-with-nmap).
- The nmap `-sV` time depends on the lab. With the simulators' own 2 s idle timeout the median over three runs was 4.38 s (4.37 to 4.47), and nmap reported Redis and Modbus as `tcpwrapped`: 8/11 service names and 7/8 products instead of 10/11 and 8/8. nmap waits several seconds for a banner from a service that speaks only after the client does, and the simulators closed the connection first. A real Redis keeps the connection open, so `--idle 12` is the fairer setting, but it also makes nmap slower. Network Scope's times did not change between the two settings (3.17 s, 3.59 s and 6.61 s at 2 s).
- Port recall and precision are both 11/11 for every configuration, so the two tools agree on open ports; the lab has no filtered ports.

### Accuracy diff between the tools

The same run diffs Network Scope's `--deep --ot` result against nmap's `-sV` result for every host and port (see [Comparison with nmap](lab-and-testing.md#comparison-with-nmap)). All 11 open ports agree, as do 9 of the 11 service names and all products and versions except the OpenSSH one named below. Six differences remain and each is explained in `lab/nmap_differences.json`: Modbus on port 502 and EtherNet/IP on port 44818 (nmap names them, Network Scope stores the identity under `Modbus.*` and `EtherNet/IP.*` and does not probe industrial ports generically), the Debian package revision in the OpenSSH version of `127.0.10.4` (nmap puts it into the version, Network Scope into the info), and the 88 closed ports that Network Scope on Windows records as unanswered.

### What this does not show

- It is one machine, on loopback, with simulators that answer their own protocol cleanly: no latency, no loss, no firewall, no real operating system or device. Times on a LAN or the internet will be different, and the ranking of the tools can change.
- The times are dominated by waits in the lab and the operating system (the closed-port wait on Windows, nmap's banner wait on the simulators), not by CPU work. They are not a general statement about which tool is faster.
- Only TCP was scored. UDP, SYN scans and host discovery were not compared. nmap was run without administrator rights as a connect scan, like Network Scope.
- Network Scope's scoring rules are the ones of its own benchmark, and the lab was built by the same project, so the ground truth reflects what those simulators serve.
- Ubuntu's nmap, other nmap versions and other operating systems were not run.
