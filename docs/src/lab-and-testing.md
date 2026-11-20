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

`verify.py` starts the simulators on loopback, scans them with the built binary and asserts the expected identities and findings (exit code 0 = all passed). CI runs it on Windows, Linux and macOS. It also checks the safety features: a loopback device that accepts one connection and then stops listening must produce a `backed off:` host note (and none with `--no-backoff`), the healthy lab host must not be backed off, the scan's JSON must carry the sent log, and `scan --dry-run` against a counting listener must print the plan, save nothing and never connect.

### Accuracy benchmark

[`lab/benchmark.py`](https://github.com/Sparkz400/network-scope/blob/main/lab/benchmark.py) measures how accurate a scan is against a lab where every host and port is known. The ground truth is [`lab/ground_truth.json`](https://github.com/Sparkz400/network-scope/blob/main/lab/ground_truth.json): six simulated hosts on loopback addresses `127.0.10.1` to `127.0.10.6` (a weak Unix server, a PLC with Modbus, EtherNet/IP and BACnet, a web server, a Debian web server, a Redis server, an IIS web server) and three addresses where nothing runs. The benchmark starts the simulators, scans every address with `--fast --deep --ot --tcp-only`, compares the JSON result with the ground truth and writes `benchmark.json` and `benchmark.md`.

```sh
cargo build --release --locked
python -I lab/benchmark.py --cli /absolute/path/to/target/release/network-scope-cli --check
```

Only loopback addresses (`127.0.0.0/8`) are ever contacted; a ground truth with any other address is refused. Before starting, the benchmark checks that nothing already listens on the lab ports (for example a web server on a wildcard address) and that every simulator accepts connections; a dirty machine exits with code 2, which is a lab error, not a regression. Port 80 is not used because Windows machines often run IIS there. On Linux the lab needs the low ports (`sudo sysctl -w net.ipv4.ip_unprivileged_port_start=0`, and port 22 must be free).

| Metric | Meaning |
| --- | --- |
| Host recall / precision | Real hosts found / real hosts; real hosts / hosts reported with an open port or identity (an absent address reported that way counts against precision) |
| Port recall | Open ports found / open ports; also split into TCP and UDP (`udp_open`) |
| Port precision | Reported open ports that are real / reported open ports |
| Service accuracy | Services named correctly / services served (`svc.<port>`, or the OT identity fields for Modbus, EtherNet/IP and BACnet) |
| Product accuracy | Product and version correct / products with a known product (for example vsFTPd 2.3.4, Apache 2.4.49) |
| Device type, OS accuracy | Correct / hosts with a known device type, or a known OS (named by their banners) |
| Finding recall | Findings the ground truth expects (`findings` per host) that were raised / expected findings |
| False alarms | Count, lower is better: findings raised on a host whose ground truth lists exactly which rule ids its lab condition warrants, but not that rule. Per-rule detail is in `benchmark.json` (`metrics.false_alarms.by_rule`) and in the deviations list. `--check` fails when the count rises above the baseline (a missing baseline value means 0) |
| Back-off notes | Count, lower is better: `backed off:` notes on lab hosts (the [automatic back-off](scanning-engine.md#automatic-back-off) reacted to a reset connection or a port that stopped answering). A healthy lab never trips it; a note explains a long scan time that is not noise. `--check` fails when the count rises above the baseline (a missing baseline value means 0) |
| First result | Milliseconds from starting `scan --stream` to its first output line (the first host or open port the engine reports, process start included), median of five runs. Reported always; gated at 200 ms with `--gate-first-result`, which CI sets (the roadmap target; measured 35-42 ms on an idle Windows machine and 235-557 ms while other builds ran on it, which is why it is not gated by default) |
| Wall time | Reported. `--max-scan-seconds N` (CI uses 60) fails a gross slowdown only; finer gating would trip on shared machines: on a Windows laptop the same scan took 6.2 s idle and about 29 s while 70 busy processes competed for the CPU, with or without the back-off, and with no back-off note. Check the back-off notes row and the machine load before blaming a change |

The risk rules run over the same scan (`findings 1`). A host that has a `findings` list in the ground truth states exactly which rule ids its simulators warrant (for example `redis-noauth` for the Redis host, nothing for the IIS host); everything else raised there is a false alarm. A host without the key states nothing and is skipped.

The rules also have a unit-level false-alarm budget: `core/src/risk_budget.rs` holds one host that must trigger each rule and one near-miss host that must not (same port and keys, different value). A test reads the rule ids out of `core/src/risk.rs`, so a new rule without both cases fails `cargo test`. `cargo test false_alarm -- --nocapture` prints the per-rule counts (all zero).

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
- The lab is small and cooperative: every service answers its own protocol cleanly, nothing is firewalled, filtered, slow or lossy, and no real network or operating system is involved. 100% here means "no regression on these cases", not "100% in the field". Loopback also hides ICMP: every `127.x.x.x` address answers ping, so the gated run uses `--tcp-only`; with ICMP discovery the absent addresses would be reported as live hosts (a lab artefact, not a scanner bug). The OS also answers every port of every `127.x` address with a RST, so the absent addresses respond to TCP too; host precision therefore counts only hosts reported with an open port or an identity.
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

### Test plant: planted weaknesses and replayable traffic

`lab/plant.py` is a small plant of four fake devices on loopback addresses (`127.0.20.1`-`4`), built on the handlers of `simulators.py`, with the weaknesses planted in them written down in `lab/plant_truth.json` (the ground truth):

| Device | Planted |
| --- | --- |
| `plc-s7` (127.0.20.1) | an S7 CPU 1214C with firmware 4.2.3, inside the affected range of the synthetic advisory `ICSA-TEST-0001` (`tests/fixtures/csaf`); the engineering port 102 exposed |
| `plc-modbus` (127.0.20.2) | Modbus/TCP with **writable registers** (the trap), a Telnet console that names the factory credentials, a cleartext web admin page on Apache 2.4.49 |
| `plc-enip` (127.0.20.3) | a ControlLogix 1756-L81E with firmware 20.11, inside the range of `ICSA-TEST-0002`; EtherNet/IP exposed |
| `hmi` (127.0.20.4) | vsFTPd 2.3.4, OpenSSH 7.4 with weak algorithms, Apache 2.4.49 with Basic authentication |

`lab/plant_benchmark.py` starts the plant, imports the CSAF fixtures into a temporary cache, scans it (Safe Mode, then `--fast`) and reports:

- **weakness recall**: the planted weaknesses (17, each a rule id on an address and port) that came out as findings, over all of them;
- **writes**: every write or control request that reaches a device is counted (the Modbus registers really change); **any write fails the run**, whatever else was found. The scanner sends none;
- the findings the truth does not list (informational);
- the **L69 replay**: `lab/plant_traffic.py` writes a capture of six hours of normal traffic between an HMI, an engineering station and two PLCs (nothing is sent on a network) and two copies of it, one with a single Modbus write injected from a station that never appears in the normal capture and one with a single S7 PLC Stop at 05:00, outside the maintenance window. `ot-learn` learns the normal capture and `ot-listen --model` must report nothing for it and exactly the injected event for each replay.

```sh
python -I lab/plant_benchmark.py --cli /absolute/path/to/network-scope-cli --check
python lab/plant.py                       # serve the plant to scan it by hand (loopback only)
python lab/plant_traffic.py --out DIR     # only the capture files
python -I -m unittest discover -s lab -p "test_plant.py"
```

`--check` also fails when the recall is below `lab/plant_baseline.json` (a separate file: `benchmark_baseline.json` and `ground_truth.json` are not touched). The machine must be clean: if something already listens on a plant address and port (a wildcard listener such as Siemens software on 102 or 4840), the run refuses; `--allow-busy` skips that check on a development machine and then fails unless a connection of the scan reached every plant device.

Measured on Windows 11 (10.0.26300), 2026-11-20, debug build of the CLI, `--allow-busy` because Siemens software listens on 102 and 4840 of this machine: recall 17 of 17 in Safe Mode (14.3 s for the scan, which includes the Safe Mode pacing) and 17 of 17 with `--fast` (4.4 s), 0 writes, the replay reported exactly the two injected events and nothing for the normal capture. The three extra findings were `ot-reachable` on port 102 of the other three plant addresses, answered by that foreign listener, not by the plant. The CI step (Linux) has not run yet.

What the plant is not: the devices emulate what a scanner can observe, not real PLC software. A lab with real controller software (OpenPLC) is prepared in `lab/docker-compose.yml` (profile `plant-ci`) and has **not** been run: there is no Docker on the development machine, and the image name and tag there were written from memory and must be checked before use. There is no OPC UA, DNP3 or IEC 104 device in the plant.

### Docker lab

[`lab/docker-compose.yml`](https://github.com/Sparkz400/network-scope/blob/main/lab/docker-compose.yml) runs the simulators (plus a real Redis) on an internal Docker network `172.28.0.0/24` with no outside access:

```sh
cd lab
docker compose up -d --build
network-scope scan 172.28.0.0/24 --deep --ot --script ../scripts
```

The Docker compose file has **not** been run (no Docker on the development machine); `verify.py`, including all scenarios, has, on Windows. The lab has no DNP3, IEC 104 or OPC UA simulator, and an S7 simulator only in the `fragile-ot` scenario.

## Real servers

The simulators above are written by us, so they can only confirm what we already believe a server sends. These checks run Network Scope against software written by others (roadmap A6).

### Windows Schannel (local, ran)

[`lab/schannel_server.ps1`](https://github.com/Sparkz400/network-scope/blob/main/lab/schannel_server.ps1) is a TLS server served by Windows Schannel (PowerShell 7 and .NET `SslStream`; no administrator rights, nothing is added to a certificate store: the self-signed certificate is created in memory). The test `tls::tests::windows_schannel_server_is_inspected` starts it, runs the TLS inspection against it and compares the TLS 1.3 suites with the ones the operating system lists (`Get-TlsCipherSuite`), not with a list written in the test:

```sh
cargo test -p network-scope-core windows_schannel -- --ignored --nocapture
```

It is ignored by default because it starts PowerShell; CI runs it on the Windows runner. It passes without running anything when `pwsh` is not installed. Result on Windows 11 (10.0.26300, 2026-11-20): TLS 1.3 negotiated, suites `TLS_AES_256_GCM_SHA384` and `TLS_AES_128_GCM_SHA256`, JA4S `t130200_1302_a56c5b993250`, TLS 1.2 and the deprecated 1.1 and 1.0 enabled with their suite lists cut by the round budget.

This test found a real defect: the TLS 1.3 hello carried a random 32-byte string as its X25519 key share, and Schannel validates it, answering about eleven of twelve probes with a `decode_error` alert, so the TLS 1.3 suite list of a Windows server was empty. The key share is now a real public key generated by the crypto provider (the private half is dropped immediately).

### Samba, OpenSSH, OpenSSL and nginx (CI, ubuntu)

The CI job `real-servers` installs the servers with apt and runs [`lab/real_servers.sh`](https://github.com/Sparkz400/network-scope/blob/main/lab/real_servers.sh), which starts them on loopback, scans them with `--fast --services` and runs [`lab/real_servers_check.py`](https://github.com/Sparkz400/network-scope/blob/main/lab/real_servers_check.py):

| Server | Configured | Asserted |
| --- | --- | --- |
| Samba (`smbd`, port 445, as root) | SMB 2.1 up to 3.1.1 (`SMB2_10` to `SMB3_11`), SMB1 off, signing mandatory, `AES-128-GCM` encryption, NetBIOS name `NSLABSMB` | dialect `3.1.1`, SMB1 `refused`, signing required, the encryption cipher, the NetBIOS name from the NTLM challenge |
| `openssl s_server` A (8443) | TLS 1.3 only, `TLS_CHACHA20_POLY1305_SHA256` then `TLS_AES_256_GCM_SHA384`, server preference | exactly these suites, in this order; JA4S equal to an independent computation |
| `openssl s_server` B (9443) | TLS 1.2 `ECDHE-RSA-AES256-GCM-SHA384` and TLS 1.3 `TLS_AES_128_GCM_SHA256` | exactly these suites per version, no weak or deprecated entry |
| nginx (6443) | TLS 1.2 `ECDHE-RSA-AES128-GCM-SHA256`, TLS 1.3 two suites | the suites, product `nginx`, a `cpe:2.3:a:f5:nginx:` CPE |
| OpenSSH (`sshd`, port 2200) | one ed25519 host key | product `OpenSSH`, the CPE, and `ssh.<port>.hassh` equal to HASSHServer computed from the server's KEXINIT over a raw socket with `hashlib.md5` |

The ports, suites and names are defined once, in the `LAB` table of `real_servers_check.py`; the shell script reads them from there, so a server's configuration and the expected result cannot drift apart. Only the lab scripts' own unit tests (`python -I -m unittest discover -s lab -p "test_*.py"`, fake peers and synthetic scans) run anywhere; `INSTALL=1 bash lab/real_servers.sh` needs a Linux machine with sudo. The `openssl s_server` part (`PARTS=tls`) was run on Windows with Git's OpenSSL 3.5: the TLS 1.3 suites came out in the configured order and the JA4S equalled the independent one. **The Samba, OpenSSH and nginx parts, and the job itself, have not been run**; they were written for the Ubuntu 24.04 runner image (Samba 4.19, OpenSSH 9.6, nginx 1.24) and may need an adjusted expectation on the first run (for example a Samba parameter name).

### JA4S

The unit tests in `core/src/fingerprint.rs` check the algorithm against the JA4S examples published in the README of the FoxIO JA4+ project (IcedID, Sliver, SoftEther) and a pair from its python test data, and the ALPN rule against its unit test cases. The README gives only the fingerprints, not the ServerHellos: the extension lists in the tests are the ones whose SHA-256 reproduces the published hash. This is not FoxIO's reference implementation run on a capture (it needs tshark and pcap files); the independent JA4S in `real_servers_check.py` is also our own code, written from the documented algorithm. Comparing against the reference tool on a capture of the real servers is still open. Two differences from FoxIO's description were found and fixed: a ServerHello with no extensions has the hash part `000000000000` (not the hash of an empty string), and the ALPN part follows the written rule of `technical_details/JA4.md` (the first and last character when both are alphanumeric, otherwise the first and last hexadecimal digit of the whole value, so `0x20 0x61` gives `21`). FoxIO's python implementation still substitutes `9` for a non-ASCII end character and says so in a comment; the written rule was followed. The ALPN part is therefore always `00`, two alphanumeric characters or two hex digits: bytes a server chose never reach the fingerprint (and from there the TUI, CSV and report output) as control characters. Network Scope's own hellos offer no ALPN, so the part is `00` unless the server sends an ALPN extension anyway.

Licensing note: the FoxIO License 1.1 covers JA4S and the other JA4+ methods (the JA4 client fingerprint itself is BSD-3-Clause), is permissive for internal use but not for monetization, and the project states that JA4+ is patent pending. Network Scope is MIT-licensed. The tests quote only the three published example fingerprints; no FoxIO code or test data was copied. Whether the JA4S implementation can ship under the MIT license is a decision for the maintainers (see `data/README.md`).

### CPE names against the NVD dictionary

`lab/check_cpe.py` reads the `cpe` table of `data/cves.json` (the table behind every `svc.<port>.cpe` value) and checks the format of every template; with `--dictionary FILE` or `--download FILE` it also checks that every vendor:product pair is a current name in the official NVD CPE 2.0 feed (`https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz`, scanned in blocks without extracting; a pair that is missing, or that exists only as a deprecated name, fails). CI runs the download check in the `real-servers` job; the feed is 85 MB and changes daily, so the URL is pinned, not the content, and a truncated download is refused (fewer than 100,000 names). Locally only the format is checked here. As a one-off, the 14 pairs were also looked up on 2026-11-19 through the NVD CPE API 2.0: 13 exist; `beasts:vsftpd` did not, and the table now uses `vsftpd_project:vsftpd`. The feed's inner file layout and the position of the `deprecated` flag were taken from the API's answer and are unverified for the feed; if the flag is not recognised the check compares names only and says so.

## What has been tested on real hardware

Verified on real hardware (2026-11-18, one Windows 11 machine with Npcap, Wi-Fi adapter): a Safe Mode scan of a real /24 (78 responding hosts, 187 s), an on-link SYN scan through Npcap (open and closed ports correct, no fallback), a passive `listen` (ARP and LLDP decoded), and `network-scope-cli` in `cmd.exe` and PowerShell (both wait; exit code 0 on success, 1 on a bad option).

## What has not been tested

Be aware of these gaps before relying on a feature:

- Npcap/libpcap features not yet run on a real interface: SYN to routed targets, the ARP sweep, TCP traceroute, live OT capture, DCP; and everything with libpcap on Linux/macOS.
- UDP traceroute with administrator/root rights; ICMPv6 hop-limit expiry from a real router on Windows.
- Linux/macOS glue (`next_hop`, neighbor states, raw ICMP/ICMPv6, UDP hop): not compiled on the development machine (CI is the first compile) and not exercised on a real network.
- The GUI binary's console attach when started from a shell (use `network-scope-cli` for scripting).
- The Inno Setup installer script (never compiled with `iscc` yet) and the CI, release and documentation workflows (not run yet). That includes the accuracy benchmark steps in `ci.yml` and `release.yml` and the test plant step; the benchmark itself has only been run on Windows, so the Linux baseline is not recorded yet. The nmap comparison has also only been run on Windows with nmap 7.98; its explanations are calibrated on that run and may not cover the older nmap of Ubuntu's apt repository.
- The ClusterFuzzLite build (`.clusterfuzzlite/`) and workflow (`cflite.yml`): not run yet. The fuzz targets themselves were built and run locally on Windows (cargo-fuzz, AddressSanitizer), every target for at least 3 minutes, without a crash (the later `mcp_message` target: 60 seconds, about 28,000 runs, without a crash).
- Webhook/syslog delivery against real receivers. SMB against Samba, and the TLS 1.3 and SSH checks against nginx and OpenSSH, are written ([Real servers](#real-servers)) but the CI job has not run yet; TLS 1.3 enumeration was run against OpenSSL (Git's build) and Windows Schannel. JA4S is checked against the published FoxIO examples, not against their tool on a capture. CPE names were looked up in the NVD CPE API once; the dictionary check runs in CI only.
- OT decoders and reassembly against real industrial traffic (synthetic frames only); industrial-device interoperability in general.

No industrial production network was scanned during development. Reports from real-world use, especially from OT networks, are very welcome; see the protocol support issue template.

## Screenshots

`cargo run --release -- --screenshot screenshot.png` renders the desktop to a PNG without scanning or modifying preferences or the inventory. `NETWORK_SCOPE_SCREENSHOT_STATE=main|findings|devices|settings|ot|script|timeline` renders a larger window with sample data in that view (append `-small` for the default 800x450 size, then `-fast` for Safe Mode off, e.g. `main-small-fast`).

## Resource budgets

`scripts/resource_budget.py` (Python standard library) checks the roadmap's budgets (B17) against a release build and runs in CI on Ubuntu (`--check` fails on a breach):

```sh
python -I scripts/resource_budget.py --cli /absolute/path/to/network-scope-cli --check --gui
```

| Budget | Limit | What is measured |
| --- | --- | --- |
| Startup | 150 ms | Median of 21 runs of `network-scope-cli --version`, process start to exit |
| Memory, /16 dry run | 200 MB | Peak memory of `scan 10.0.0.0/16 --dry-run` |
| Memory, /16 scan | 200 MB | Peak memory of a real scan of 127.0.0.0/16 on loopback (65,534 targets, `--fast --tcp-only --ports 1 --timeout 300`) |
| Memory, batch-written scan | 200 MB | The same over 127.0.0.0/15 (131,070 targets): above 65,536 addresses the hosts go to the database in batches |
| GUI frame | 16.6 ms | `cargo test --release --lib frame_budget -- --ignored`: a headless egui table of 65,536 hosts, an idle frame and a frame that also sorts and filters the rows |

Loopback only; nothing leaves the machine. Peak memory is the operating system's figure for the process (`ru_maxrss` from `wait4`, or the peak working set on Windows).

Measured on Windows 11, 22 logical cores, release build, 2026-11-20 (the CI limits are enforced on Ubuntu, where nothing was measured by the author):

| Measurement | Result |
| --- | --- |
| Startup (`--version`) | 86 ms median (81.5 to 212 ms over 31 runs; 94 to 158 ms before `--version` and `--help` stopped loading the rule database). A trivial `cmd /c ver` takes 58 ms in the same harness, so most of it is the process start of this Windows machine |
| `scan 10.0.0.0/16 --dry-run` | 12.2 MB, 0.2 s |
| `scan 10.0.0.0/8 --dry-run` (`--dry-run-8`) | 12.2 MB, 0.23 s |
| Scan of 127.0.0.0/16 | 69.6 MB, 14 s |
| Scan of 127.0.0.0/15 (batch-written) | 26.0 MB, 29 s; 127.0.0.0/14: 26.1 MB, 52 s |
| GUI frame, 65,536 rows | idle frame 0.40 ms median (the rows are virtual: only the visible ones are laid out); a frame with sort, filter and draw 10.95 ms median, worst of 30 frames 18.9 ms. The median meets 60 fps; one frame in 30 can miss it while a scan feeds the table |

The GUI test cannot drive the real window (that needs a display): it draws the same `TableBuilder` columns and cells as the results table and repeats the sort and the row filter, so a change to the table code itself (not these helpers) is not covered.

## Performance tests

`core/benches/hot_paths.rs` holds [criterion](https://criterion-rs.github.io/book/) benchmarks of the hot paths: parsing a 2,000-frame pcap, decoding 2,000 passive frames, the risk analysis of a 1,000-host snapshot, the diff of two 1,000-host snapshots, expanding and parsing targets, and matching banners against every service probe. They touch no network.

```sh
cargo bench -p network-scope-core                                  # run them
cargo bench -p network-scope-core -- --save-baseline before        # keep the numbers
cargo bench -p network-scope-core -- --baseline before             # compare with them
python -I scripts/bench_compare.py target/criterion --threshold 15 # exit 1 on a regression
```

The workflow `bench.yml` runs on every pull request: one job builds the base branch and saves its numbers as the baseline, runs the same benchmarks on the change on the same runner, and `scripts/bench_compare.py` fails the job when a benchmark's mean got more than 15 percent slower and criterion's confidence interval for the change excludes zero. A base branch without benchmarks (the pull request that adds them) has nothing to compare with and passes with a notice.

Runner noise is real. On a shared workstation with other builds running, two runs of identical code differed by up to +25 % in the pcap and diff benchmarks (measured 2026-11-20, Windows 11, release build), so the comparison on a hosted runner can fail without a real slowdown: re-run the job once before believing a failure, and look at the interval in the job summary. Numbers on that workstation (middle value): pcap parse 82 microseconds, passive decode 1.17 ms (2,000 frames), risk analysis 2.8 ms, diff 8.3 ms, expanding a /16 138 microseconds, parsing mixed ranges 0.46 microseconds, probe matching 16 microseconds.

`criterion` is a dev-dependency of the core crate only (version 0.8.2, no default features: no plotting, no rayon); `cargo deny check` reports no new advisory, licence or source problem (a pre-existing `wildcard` error for the path dependency `network-scope-core` shows with cargo-deny 0.21 with or without it).

## Fast repeat scans

`scan --incremental` ([Fast repeat scans](scanning-engine.md#fast-repeat-scans)) measured on the lab (9 loopback addresses, 11 ports each, `--fast --deep --ot --tcp-only --timeout 1500`, release build, Windows 11, 2026-11-20): the full scan took 6.5 s; three repeat scans of the same database took 1.32, 1.41 and 1.56 s, about a fifth. Every repeat scan diffed empty against the full scan and against each other (`diff 1 3`, `diff 1 4`, `diff 2 4`). The third scan carried over the identification of every unchanged banner or web service (`incr.carried`: for example `svc:21,22,23,8080;udp` on the weak Unix server) and the UDP answers of every host that answered before. On a busy machine the same full scan took 28.9 s and the repeat scans 2.5 s (see the note on machine load above).

The saving in this lab comes from skipping the service identification and the UDP probes; with only 11 ports per host the port sample covers every port. On a real network the port probing of silent hosts is the larger part, and a repeat scan probes about 16 ports per host (plus the known open ones) instead of all of them. That figure was not measured on a real network.
