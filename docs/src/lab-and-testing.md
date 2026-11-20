# Lab and testing

## Automated tests

```sh
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --check
```

The tests exercise real loopback networking and protocol fixtures, SQLite round trips, scan changes, parser bounds, report escaping, and the SYN, ARP and TCP-traceroute I/O loops against a fake wire. A source-level test fails the build if the passive capture modules contain socket or send code.

CI ([`.github/workflows/ci.yml`](https://github.com/Sparkz400/network-scope/blob/main/.github/workflows/ci.yml)) runs format, clippy with `-D warnings`, the tests and the lab check below on Windows, Linux and macOS, uploads both binaries as build artifacts, and builds the Windows installer. On Linux it also runs the [accuracy benchmark](#accuracy-benchmark) and fails when an accuracy metric drops below the baseline. Tagged releases are built by `release.yml`.

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

### Docker lab

[`lab/docker-compose.yml`](https://github.com/Sparkz400/network-scope/blob/main/lab/docker-compose.yml) runs the simulators (plus a real Redis) on an internal Docker network `172.28.0.0/24` with no outside access:

```sh
cd lab
docker compose up -d --build
network-scope scan 172.28.0.0/24 --deep --ot --script ../scripts
```

The Docker compose file has **not** been run (no Docker on the development machine); `verify.py` has, on Windows. The lab has no S7, DNP3, IEC 104 or OPC UA simulator.

## What has been tested on real hardware

Verified on real hardware (2026-11-18, one Windows 11 machine with Npcap, Wi-Fi adapter): a Safe Mode scan of a real /24 (78 responding hosts, 187 s), an on-link SYN scan through Npcap (open and closed ports correct, no fallback), a passive `listen` (ARP and LLDP decoded), and `network-scope-cli` in `cmd.exe` and PowerShell (both wait; exit code 0 on success, 1 on a bad option).

## What has not been tested

Be aware of these gaps before relying on a feature:

- Npcap/libpcap features not yet run on a real interface: SYN to routed targets, the ARP sweep, TCP traceroute, live OT capture, DCP; and everything with libpcap on Linux/macOS.
- UDP traceroute with administrator/root rights; ICMPv6 hop-limit expiry from a real router on Windows.
- Linux/macOS glue (`next_hop`, neighbor states, raw ICMP/ICMPv6, UDP hop): not compiled on the development machine (CI is the first compile) and not exercised on a real network.
- The GUI binary's console attach when started from a shell (use `network-scope-cli` for scripting).
- The Inno Setup installer script (never compiled with `iscc` yet) and the CI, release and documentation workflows (not run yet). That includes the accuracy benchmark steps in `ci.yml` and `release.yml`; the benchmark itself has only been run on Windows, so the Linux baseline is not recorded yet.
- The ClusterFuzzLite build (`.clusterfuzzlite/`) and workflow (`cflite.yml`): not run yet. The fuzz targets themselves were built and run locally on Windows (cargo-fuzz, AddressSanitizer), every target for at least 3 minutes, without a crash (the later `mcp_message` target: 60 seconds, about 28,000 runs, without a crash).
- Webhook/syslog delivery against real receivers; SMB against Samba; TLS 1.3 enumeration against OpenSSL/Schannel; JA4S against the reference implementation; CPE names against the NVD dictionary.
- OT decoders and reassembly against real industrial traffic (synthetic frames only); industrial-device interoperability in general.

No industrial production network was scanned during development. Reports from real-world use, especially from OT networks, are very welcome; see the protocol support issue template.

## Screenshots

`cargo run --release -- --screenshot screenshot.png` renders the desktop to a PNG without scanning or modifying preferences or the inventory. `NETWORK_SCOPE_SCREENSHOT_STATE=main|findings|devices|settings|ot|script` renders a larger window with sample data in that view (append `-small` for the default 800x450 size, then `-fast` for Safe Mode off, e.g. `main-small-fast`).
