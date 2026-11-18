# Lab and testing

## Automated tests

```sh
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --check
```

The tests exercise real loopback networking and protocol fixtures, SQLite round trips, scan changes, parser bounds, report escaping, and the SYN, ARP and TCP-traceroute I/O loops against a fake wire. A source-level test fails the build if the passive capture modules contain socket or send code.

CI ([`.github/workflows/ci.yml`](https://github.com/Sparkz400/network-scope/blob/main/.github/workflows/ci.yml)) runs format, clippy with `-D warnings`, the tests and the lab check below on Windows, Linux and macOS, uploads both binaries as build artifacts, and builds the Windows installer. Tagged releases are built by `release.yml`.

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
- The Inno Setup installer script (never compiled with `iscc` yet) and the CI, release and documentation workflows (not run yet).
- Webhook/syslog delivery against real receivers; SMB against Samba; TLS 1.3 enumeration against OpenSSL/Schannel; JA4S against the reference implementation; CPE names against the NVD dictionary.
- OT decoders and reassembly against real industrial traffic (synthetic frames only); industrial-device interoperability in general.

No industrial production network was scanned during development. Reports from real-world use, especially from OT networks, are very welcome; see the protocol support issue template.

## Screenshots

`cargo run --release -- --screenshot screenshot.png` renders the desktop to a PNG without scanning or modifying preferences or the inventory. `NETWORK_SCOPE_SCREENSHOT_STATE=main|findings|devices|ot|script` renders a larger window with sample data in that view (append `-small` for the default 800x450 size).
