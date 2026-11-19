# Lab and testing

## Automated tests

```sh
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --check
```

The tests exercise real loopback networking and protocol fixtures, SQLite round trips, scan changes, parser bounds, report escaping, and the SYN, ARP and TCP-traceroute I/O loops against a fake wire. A source-level test fails the build if the passive capture modules contain socket or send code.

CI ([`.github/workflows/ci.yml`](https://github.com/Sparkz400/network-scope/blob/main/.github/workflows/ci.yml)) runs format, clippy with `-D warnings`, the tests and the lab check below on Windows, Linux and macOS, uploads both binaries as build artifacts, measures coverage (below) and builds the Windows installer. On Linux it also runs the [accuracy benchmark](#accuracy-benchmark) and fails when an accuracy metric drops below the baseline; if nmap can be installed with apt it also runs the [nmap comparison](#comparison-with-nmap) and fails on an unexplained difference. Tagged releases are built by `release.yml`.

## Real industrial traffic

The OT decoders are also tested on public captures of real equipment, not only on frames built by the tests. `tests/fixtures/ics/` holds 22 pcap/pcapng files from the [ITI/ICS-Security-Tools](https://github.com/ITI/ICS-Security-Tools) collection (CC-BY-4.0; per-file origin, commit and SHA-256 in `PROVENANCE.md` there): Modbus/TCP, S7comm (including a block download and a PLC stop), EtherNet/IP (List Identity, a CIP stop), IEC 60870-5-104, DNP3 (read, select/operate, write), BACnet, OPC UA, Profinet DCP, and some protocols without a decoder yet (Omron FINS, Niagara Fox, MELSEC, IEC 61850 MMS). `core/src/otpassive/real_traffic.rs` reads each one with the function `ot-listen --pcap` uses and asserts what is really found: the protocol, device and client addresses, identity fields (EtherNet/IP vendor, product, firmware, serial; Profinet DCP name; the S7 SZL order code and firmware and the OPC UA endpoints through the probe parsers), and which captures contain control traffic (and at which severity). Where a capture shows a limit of a decoder (OPC UA on a port other than 4840, S7CommPlus and IEC 61850 MMS on port 102, fragmented SZL replies) the test says so. The files below 64 KB also seed the fuzz targets.

## Coverage targets

The goal is at least 80% line coverage of every parser and risk-rule file: `risk.rs`, `pcapfile.rs`, `tls.rs`, `service`, `otpassive/`, `ot` and `ot/`, `nmap.rs`, `passive.rs`, `udp.rs`, `arp.rs`, `osfp.rs` and `fingerprint.rs`. The `coverage` CI job (Ubuntu) runs the tests with [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov) (version pinned in `ci.yml`, installed with `--locked`), writes the JSON summary, an lcov file and an HTML report (uploaded as the artifact `coverage-report`), and then runs [`scripts/coverage_gate.py`](https://github.com/Sparkz400/network-scope/blob/main/scripts/coverage_gate.py) (Python standard library only, `python -I`). The gate fails the job if any file matching a target is below its threshold, or if a target no longer matches any file (a renamed file needs its pattern updated).

The targets are in [`scripts/coverage_targets.json`](https://github.com/Sparkz400/network-scope/blob/main/scripts/coverage_targets.json): a regular expression per target, matched against the source path, so the same entry covers `src/` and `core/src/`. The first matching target wins, so a file with a lower floor is listed before its group.

Not every file is at 80% yet. Measured on 2026-11-19 (cargo-llvm-cov 0.9.1 on Windows, 333 unit tests; three runs gave identical line counts for every file), these are below it and have a threshold at their measured value, rounded down, marked `"ratchet_to": 80`:

| File | Measured | Threshold today |
| --- | --- | --- |
| `ot.rs` (active OT identification) | 66.60% | 66% |
| `passive.rs` | 65.05% | 65% |
| `otpassive/s7.rs` | 76.19% | 76% |
| `otpassive/dnp3.rs` | 42.86% | 42% |
| `otpassive/iec104.rs` | 35.71% | 35% |

The floors can only go up: when the gate prints "raise the threshold" for a file, raise it in the same change, and once a file reaches 80% drop its `ratchet_to`. A threshold is never set above a measured value. The files not listed were between 82% and 99% at that measurement. The numbers include the `#[cfg(test)]` modules in the same files, and Linux and Windows compile different platform code, so the first Linux run in CI may differ from the Windows numbers by a little; recalibrate from the uploaded `summary.json` if a floor is hit by that alone.

Run it locally (needs the `llvm-tools-preview` rustup component):

```sh
cargo install cargo-llvm-cov --locked
cargo llvm-cov --locked --workspace --no-report
cargo llvm-cov report --json --summary-only --output-path target/llvm-cov/summary.json
python -I scripts/coverage_gate.py target/llvm-cov/summary.json
cargo llvm-cov report --html     # target/llvm-cov/html/index.html
```

The gate has its own unit tests (`python -I -m unittest discover -s scripts -p "test_*.py"`), which CI runs first.

## Fuzzing

The parsers of untrusted input (capture files, Ethernet frames for the passive listener and the OT tracker with TCP reassembly, TLS records and certificates, SMB, NTLM, SSH, HTTP and RDP replies, service banners, Modbus, EtherNet/IP, BACnet, S7 and OPC UA replies, the UDP probe replies, ARP, SYN-ACK/RST and TCP options, ICMP/ICMPv6 ping and traceroute replies, nmap XML and the user `probes.json` and `cves.json`) have [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets in `fuzz/`, one per parser, with seed inputs in `fuzz/corpus/`. The seeds also run as a unit test, so every input that once crashed a parser stays a regression test. [ClusterFuzzLite](https://google.github.io/clusterfuzzlite/) (`.github/workflows/cflite.yml`) fuzzes pull requests for 5 minutes and all targets weekly for 30 minutes. How to run a target locally is in [CONTRIBUTING.md](https://github.com/Sparkz400/network-scope/blob/main/CONTRIBUTING.md#fuzzing).

## Lab simulators

[`lab/simulators.py`](https://github.com/Sparkz400/network-scope/blob/main/lab/simulators.py) (Python standard library only) emulates deliberately weak services: an FTP banner of vsFTPd 2.3.4, Telnet, SSH offering weak algorithms, Apache 2.4.49 with Basic auth, open Redis, Modbus/TCP, EtherNet/IP and BACnet/IP identity. They are fake: they only produce what a scanner observes and never execute anything received from the network.

```sh
python lab/simulators.py --bind 127.0.0.1 --offset 20000   # unprivileged ports 20021, 20022, ...
```

### End-to-end check

```sh
cargo build --release --locked
python lab/verify.py target/release/network-scope        # .exe on Windows
```

`verify.py` starts the simulators on loopback, scans them with the built binary and asserts the expected identities and findings (exit code 0 = all passed). CI runs it on Windows, Linux and macOS.

### Accuracy benchmark

[`lab/benchmark.py`](https://github.com/Sparkz400/network-scope/blob/main/lab/benchmark.py) measures how accurate a scan is against a lab where every host and port is known. The ground truth is [`lab/ground_truth.json`](https://github.com/Sparkz400/network-scope/blob/main/lab/ground_truth.json): six simulated hosts on loopback addresses `127.0.10.1` to `127.0.10.6` (a weak Unix server, a PLC with Modbus, EtherNet/IP and BACnet, a web server, a Debian web server, a Redis server, an IIS web server) and three addresses where nothing runs. The benchmark starts the simulators, scans every address with `--fast --deep --ot --tcp-only`, compares the JSON result with the ground truth and writes `benchmark.json` and `benchmark.md`.

```sh
cargo build --release --locked
python -I lab/benchmark.py --cli /absolute/path/to/target/release/network-scope-cli --check
```

Only loopback addresses (`127.0.0.0/8`) are ever contacted; a ground truth with any other address is refused. Before starting, the benchmark checks that nothing already listens on the lab ports (for example a web server on a wildcard address) and that every simulator accepts connections; a dirty machine exits with code 2, which is a lab error, not a regression. Port 80 is not used because Windows machines often run IIS there. On Linux the lab needs the low ports (`sudo sysctl -w net.ipv4.ip_unprivileged_port_start=0`, and port 22 must be free).

| Metric | Meaning |
| --- | --- |
| Host recall / precision | Real hosts found / real hosts; real hosts / hosts reported (an absent address that is reported counts against precision) |
| Port recall | Open ports found / open ports; also split into TCP and UDP (`udp_open`) |
| Port precision | Reported open ports that are real / reported open ports |
| Service accuracy | Services named correctly / services served (`svc.<port>`, or the OT identity fields for Modbus, EtherNet/IP and BACnet) |
| Product accuracy | Product and version correct / products with a known product (for example vsFTPd 2.3.4, Apache 2.4.49) |
| Device type, OS accuracy | Correct / hosts with a known device type, or a known OS (named by their banners) |
| Wall time | Reported, not gated |

`--check` exits with code 1 when an accuracy metric is below [`lab/benchmark_baseline.json`](https://github.com/Sparkz400/network-scope/blob/main/lab/benchmark_baseline.json) (one entry per platform). CI runs it on Linux after the lab check, writes the table to the job summary and uploads `benchmark.json` as the `benchmark-Linux` artifact. Each release attaches `network-scope-<version>-benchmark.json` and `.md`, measured with the Linux release binary. To raise the baseline after an improvement (or to record a new platform), run `--update-baseline` and review the diff.

Numbers of the last local run (Windows 11, debug build of the 0.5.1 sources, 2026-11-19; the first run on Linux in CI is what the Linux baseline will be recorded from):

| Metric | Result | Found |
| --- | --- | --- |
| Host recall | 100.0% | 6/6 |
| Host precision | 100.0% | 6/6 |
| Port recall | 91.7% | 11/12 |
| TCP port recall | 100.0% | 11/11 |
| UDP port recall | 0.0% | 0/1 |
| Port precision | 100.0% | 11/11 |
| Service accuracy | 100.0% | 12/12 |
| Product accuracy | 100.0% | 8/8 |
| Device type accuracy | 100.0% | 4/4 |
| OS accuracy | 100.0% | 2/2 |

What the numbers do not say:

- The one miss is real: the BACnet simulator is identified through `--ot` (`BACnet.device_id`), but UDP 47808 is not listed in `udp_open`, which only reports the default UDP probe ports (DNS, DHCP, NTP, NetBIOS, SNMP, SSDP, mDNS). Nothing in the lab serves those, so the UDP check is a single port.
- The lab is small and cooperative: every service answers its own protocol cleanly, nothing is firewalled, filtered, slow or lossy, and no real network or operating system is involved. 100% here means "no regression on these cases", not "100% in the field". Loopback also hides ICMP: every `127.x.x.x` address answers ping, so the gated run uses `--tcp-only`; with ICMP discovery the absent addresses would be reported as live hosts (a lab artefact, not a scanner bug).
- Only OS and device types that the simulators' banners name are in the ground truth (Debian, IIS, a Redis server, a PLC). TTL-only OS guessing is not measured, and the simulators on `127.0.10.1` to `127.0.10.3` carry no OS evidence, so the tool correctly names none.
- Only loopback addresses are used, so ARP, SYN scanning and routing are not covered.

### Comparison with nmap

[`lab/nmap_compare.py`](https://github.com/Sparkz400/network-scope/blob/main/lab/nmap_compare.py) (Python standard library only) scans the same lab as the benchmark with both tools and diffs the result. It starts the simulators, runs `nmap -sT -Pn -n -T4 -sV -p <lab ports> -oX` against every lab address and Network Scope (`--fast --deep --ot --tcp-only`, the benchmark's options) against the same addresses and ports, then imports nmap's XML through Network Scope's own importer (`import`, then `export --format json`, so the importer and its product-name mapping are part of what is tested) and compares per host and port: open or closed, service name, product and version. It also compares the totals of closed and unanswered ports, which the importer does not keep. Only loopback addresses are contacted.

```sh
cargo build --release --locked
python -I lab/nmap_compare.py --cli /absolute/path/to/target/release/network-scope-cli --explain lab/nmap_differences.json
```

Every difference has to be explained in [`lab/nmap_differences.json`](https://github.com/Sparkz400/network-scope/blob/main/lab/nmap_differences.json): host, port, field, both values and a reason. An entry matches exactly (no wildcards), so a difference that changes, for example another version string, is not explained by the old entry. The exit code is 0 when every difference is explained, 1 when at least one is not, and 2 when the lab, nmap or the CLI could not be run. An entry that matches nothing is printed as a warning. `--timing --repeat 3` also times Network Scope with ports only and with `--services`, and `nmap -sT -T4` without version detection, and scores every configuration against the ground truth; `--out-dir` keeps nmap's XML and the JSON of both scans.

One setting differs from `verify.py` and `benchmark.py`: the comparison runs the simulators with `--idle 12`, so a client-first service (Redis, Modbus) waits 12 s for the client instead of 2 s. nmap waits several seconds for a banner before it sends its probes; against the 2 s lab it found the connection closed without data and reported Redis and Modbus as `tcpwrapped`. That was the lab, not Network Scope, and a real Redis does not drop an idle connection after 2 s.

CI installs nmap with apt on Linux, after the benchmark, and runs the comparison; when `apt` fails the step is skipped with a warning, and when it runs, an unexplained difference fails the job.

Run on 2026-11-19 (Windows 11, nmap 7.98, release build of the 0.5.1 sources), the comparison listed 8 differences with the lab at its usual 2 s (`--idle 2`): port 502 and Redis on port 6379 as `tcpwrapped` in nmap (four rows) plus the four rows below that do not depend on the idle time. With `--idle 12` nmap names Redis (`redis`, Redis, 5.0.7, the same as Network Scope) and Modbus, which leaves six differences, every one explained:

| Host and port | Field | Network Scope | nmap | Explanation |
| --- | --- | --- | --- | --- |
| 127.0.10.2:502 | service | none | `modbus` | By design: no generic probe is sent to industrial ports; the Modbus identity (vendor, product, firmware) is under `Modbus.*` |
| 127.0.10.2:502 | product | none | `Modbus TCP` | Same; nmap's product is the protocol name, Network Scope's `Modbus.product` is `PLC-1000` |
| 127.0.10.2:44818 | service | none | `ethernet-ip-2` | Same; the identity is under `EtherNet/IP.*`; `ethernet-ip-2` is nmap's own name for the match |
| 127.0.10.4:22 | version | `8.4p1` | `8.4p1 Debian 5+deb11u1` | Naming: nmap puts the distribution's package revision into the version, Network Scope keeps the upstream version and shows the revision in the info part |
| all hosts | closed ports | 0 | 88 | Windows, see below |
| all hosts | unanswered ports | 88 | 0 | Windows, see below |

All 11 open ports, their service names (apart from the three above), products and versions agree: FTP vsFTPd 2.3.4, SSH OpenSSH 7.4 and 8.4p1, Telnet, Apache 2.4.49 and 2.4.56, Microsoft IIS 10.0 and Redis 5.0.7. The importer's open ports also matched nmap's XML read directly.

The last two rows are a real finding about Network Scope on Windows, not a lab artefact. A refused TCP connect to a closed loopback port takes about 2.0 s on this machine (a plain Python socket: 2.01 s; 0.0003 s when the socket option `SIO_TCP_INITIAL_RTO` turns off SYN retransmission). That is longer than the 1500 ms port timeout of this run and than the default of 2000 ms, so Network Scope records the closed ports as unanswered instead of closed, and with `--tcp-only` a host with no open port is not reported as responding. nmap reported the same ports as closed (`conn-refused`) and finished the plain port scan of the lab in 0.14 s, against 3.2 s for Network Scope; this document does not claim to know how nmap avoids the wait. This was measured on loopback only, and the engine has not been changed for it: switching off SYN retransmission is not safe for lossy real networks, and the benchmark's 100% host precision on Windows currently depends on it (on Linux a refusal is immediate, so the three absent addresses would be reported as responding with `--tcp-only`). Both rows are expected to be absent on Linux; that, and the explanations of the other four rows against the older nmap of Ubuntu's apt repository, has not been run (the comparison has only run on Windows with nmap 7.98).

The numbers behind the wall times and the accuracy of both tools are in the [comparison](comparison.md#measured-on-the-lab).

### Scenarios: slow WAN, packet loss, fragile OT devices

The same simulators can misbehave on purpose, and `verify.py --scenario` checks that the scanner copes. CI runs each scenario as its own step on Linux after the normal check (`all` runs them all; without `--scenario` only the normal check runs).

```sh
python lab/verify.py target/release/network-scope --scenario slow-wan   # or lossy, fragile-ot, all
python lab/simulators.py --scenario lossy --loss 0.5 --seed 7           # to scan by hand
```

All of this runs on loopback. The simulators sit above the kernel's TCP stack, so they cannot drop a SYN or add latency to the handshake itself: the connect always completes. What they change is what happens after it.

| Scenario | The simulators | `verify.py` asserts |
| --- | --- | --- |
| `slow-wan` | Every reply (banner, HTTP response, Modbus, EtherNet/IP, BACnet) waits 150-300 ms (`--delay-min-ms`, `--delay-max-ms`, seeded) | The simulator really delays (banner after at least 0.14 s); with the **default** timeouts all 7 open ports, every expected identity value and every expected finding are still found, in under 60 s |
| `lossy` | 3 of every 10 TCP connections per port (seeded, exact, `--loss`, `--seed`) are reset right after the connect; 3 of 10 BACnet Who-Is requests get no reply | Self-checks: exactly 3 of 10 test connections and 3 of 10 UDP requests are lost. Every scan reports all 7 open ports. The first scan finds at least 30% of the 17 expected identity values and findings; repeated scans (at most 6) find all of them |
| `fragile-ot` | Modbus (502), EtherNet/IP (44818) and S7 (102, only in this scenario) count connections and requests and **crash** (close the listener for good) on a write or control request (Modbus functions 5, 6, 8, 15, 16, 21, 22, 23; EtherNet/IP SendRRData and SendUnitData; S7 write variable, block download and upload, PI service, PLC stop) or on more than `--conn-limit` (4) new connections within one second. `--stats FILE` receives the counters | First, four self-checks prove the tripwires: a Modbus write, an EtherNet/IP SendRRData, an S7 write and a connection burst each crash a device. Then three scans (Safe Mode, `--fast`, `--fast --deep`) of the fragile devices: no device crashed, zero writes, at most 4 connections per device in any second, every device received requests, and the Modbus, EtherNet/IP and S7 identities came out |

Measured on Windows on 2026-11-19, which the expectations above were set from:

- **slow-wan:** the banner arrived 0.18-0.28 s after the connect; the deep scan took 5.4 s with the default timeouts and 4.4 s with `--timeout 1500` (3.6 s without delay) and found all 44 identity values and 11 findings, the same as without delay. A delay above the port timeout (default 2000 ms) would lose services; that was not measured.
- **lossy (loss 0.3):** with the default seed 1 the first scan found 11 of the 17 expected values (65%) in each of four runs and the second scan all 17. Over seeds 1 to 20 (`--seed`) the first scan found between 7 of 17 (41%, seed 3) and all 17; two scans completed the picture for 14 seeds (two of them already after the first), three scans for 5 seeds, and the worst seed (7) needed five. So the check allows a first scan with at least 30% and up to 6 scans. Open ports were never lost, because the connect itself succeeds. `--retries 0`, `1` and `3` made no difference (same 33 identity values): Network Scope retries unanswered probes, not a service or OT request on a connection that was reset, so a lossy path is made up for by scanning again (monitoring does) and not by `--retries`.
- **fragile-ot:** per scan, each device saw 2 connections (the port check and the identification) with at most 2 in any second, and 1 request (Modbus, EtherNet/IP) or 3 (S7: setup and two SZL reads), never a write. The limit of 4 per second leaves a factor of 2 over that.

What this does not show: loss and latency of the real network stack (SYN loss, retransmission timers, the SYN scan mode), because nothing here drops packets; real devices, which can fail in ways a counter does not; BACnet and the other UDP services are not made fragile (only `lossy` touches the BACnet reply); DNP3, IEC 104 and OPC UA have no simulator. The scenarios have run on Windows; the first Linux run is the CI.

### Docker lab

[`lab/docker-compose.yml`](https://github.com/Sparkz400/network-scope/blob/main/lab/docker-compose.yml) runs the simulators (plus a real Redis) on an internal Docker network `172.28.0.0/24` with no outside access:

```sh
cd lab
docker compose up -d --build
network-scope scan 172.28.0.0/24 --deep --ot --script ../scripts
```

The Docker compose file has **not** been run (no Docker on the development machine); `verify.py`, including all scenarios, has, on Windows. The lab has no DNP3, IEC 104 or OPC UA simulator, and an S7 simulator only in the `fragile-ot` scenario.

## What has been tested on real hardware

Verified on real hardware (2026-11-18, one Windows 11 machine with Npcap, Wi-Fi adapter): a Safe Mode scan of a real /24 (78 responding hosts, 187 s), an on-link SYN scan through Npcap (open and closed ports correct, no fallback), a passive `listen` (ARP and LLDP decoded), and `network-scope-cli` in `cmd.exe` and PowerShell (both wait; exit code 0 on success, 1 on a bad option).

## What has not been tested

Be aware of these gaps before relying on a feature:

- Npcap/libpcap features not yet run on a real interface: SYN to routed targets, the ARP sweep, TCP traceroute, live OT capture, DCP; and everything with libpcap on Linux/macOS.
- UDP traceroute with administrator/root rights; ICMPv6 hop-limit expiry from a real router on Windows.
- Linux/macOS glue (`next_hop`, neighbor states, raw ICMP/ICMPv6, UDP hop): not compiled on the development machine (CI is the first compile) and not exercised on a real network.
- The GUI binary's console attach when started from a shell (use `network-scope-cli` for scripting).
- The Inno Setup installer script (never compiled with `iscc` yet) and the CI, release and documentation workflows (not run yet). That includes the accuracy benchmark steps in `ci.yml` and `release.yml`; the benchmark itself has only been run on Windows, so the Linux baseline is not recorded yet. The nmap comparison has also only been run on Windows with nmap 7.98; its explanations are calibrated on that run and may not cover the older nmap of Ubuntu's apt repository.
- The ClusterFuzzLite build (`.clusterfuzzlite/`) and workflow (`cflite.yml`): not run yet. The fuzz targets themselves were built and run locally on Windows (cargo-fuzz, AddressSanitizer), every target for at least 3 minutes, without a crash.
- Webhook/syslog delivery against real receivers; SMB against Samba; TLS 1.3 enumeration against OpenSSL/Schannel; JA4S against the reference implementation; CPE names against the NVD dictionary.
- OT decoders and reassembly against real industrial traffic (synthetic frames only); industrial-device interoperability in general.

No industrial production network was scanned during development. Reports from real-world use, especially from OT networks, are very welcome; see the protocol support issue template.

## Screenshots

`cargo run --release -- --screenshot screenshot.png` renders the desktop to a PNG without scanning or modifying preferences or the inventory. `NETWORK_SCOPE_SCREENSHOT_STATE=main|findings|devices|settings|ot|script` renders a larger window with sample data in that view (append `-small` for the default 800x450 size, then `-fast` for Safe Mode off, e.g. `main-small-fast`).
