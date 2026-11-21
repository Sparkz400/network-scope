# Speed comparison

How long a port scan takes with Network Scope, nmap and RustScan on the same targets and the same ports (roadmap B10). The goal is to be the fastest tool that needs no driver. Every number on this page was measured. A cell with no measurement says so and is not estimated.

The short version: on the Linux CI runner's loopback lab, Network Scope's TCP connect scan is about as fast as nmap's SYN scan and faster than nmap's connect scan and RustScan, with every tool finding exactly the open ports; nmap uses the least memory. On a real home LAN only Network Scope has been timed. The numbers are below, with what they do not show.

## What is measured

`lab/speed_compare.py` (Python standard library only) starts the lab simulators of the [accuracy benchmark](lab-and-testing.md#accuracy-benchmark) on `127.0.10.1` to `127.0.10.6`. It then times each tool in each *cell*, where a cell is a target range plus a port list:

| Cell | Targets | Ports |
| --- | --- | --- |
| `24-top100` | `127.0.10.0/24` (254 addresses) | nmap's top 100 |
| `24-top1000` | `127.0.10.0/24` | nmap's top 1000 |
| `16-top100` | `127.0.0.0/16` (65,534 addresses) | nmap's top 100 |
| `16-top1000` | `127.0.0.0/16` | nmap's top 1000 (65 million connects per run; only on request, `--cells`) |

All of `127.0.0.0/8` is loopback, so nothing leaves the machine and no real network is needed. Both ranges contain the lab hosts.

- **Port lists.** The lists are taken from the installed nmap (`nmap -sT --top-ports N -v -oG -`), and every tool gets the same explicit list. Without nmap, the top 100 falls back to Network Scope's own `top:100` list (a different list) and the top 1000 to ports 1 to 1000. `speed.json` records which lists were used (`port_source`).
- **Repetitions.** Each tool runs `--repeat` times (default 3). The tools take turns, so drift on the machine hits all of them alike.
- **What is recorded.** Wall time is measured around the process, from start to exit, including writing the result file. Peak memory is the operating system's figure for the process: `ru_maxrss` from `wait4` on Linux, or the peak working set on Windows. The tool versions, the machine and the commit go into `speed.json`.
- **Time limit.** A run longer than `--limit` seconds (default 1800) is stopped and reported as stopped.

### The commands

`<ports>` is the cell's list, comma separated:

```sh
network-scope-cli scan <range> --fast --tcp-only --ports <ports> --scope 127.0.0.0/8 --quiet --db <file> --output <file>.json
nmap -sT -T4 -Pn -n -p <ports> -oX <file>.xml <range>
rustscan -g --no-config -a <range> -p <ports> --ulimit 65535
sudo -n nmap -sS -T4 -Pn -n -p <ports> -oX <file>.xml <range>      # only with --syn-nmap, reported separately
```

- **Network Scope.** It runs its normal TCP connect scan: no driver, no administrator rights. `--fast` leaves Safe Mode, whose deliberate pacing (8 hosts at a time, at least 100 ms between probes) is not what a speed test should time. `--tcp-only` matches the other tools, which scan TCP only.
- **nmap.** `-sT` is nmap's connect scan, the fair no-driver comparison. `-T4` is the timing the roadmap names. `-Pn` turns off host discovery, because every `127.x` address answers it.
- **RustScan.** `-g` prints the open ports and does not hand them to nmap. RustScan's own defaults are used for batch size and timeout.
- **nmap SYN scan.** `-sS` needs raw sockets and root, so it is not part of the no-driver comparison. CI runs it under `sudo` and lists it on its own line.

### "Correct" means correct

A fast wrong answer does not count. For every cell, the script reads the operating system's table of listening sockets once the lab is up (Linux `/proc/net/tcp`, otherwise `netstat -an`). That table gives every (address, port) of the cell that really listens: the lab's simulators, plus any other listener on loopback. A listener on `0.0.0.0` is open on every `127.x` address.

Each tool's open ports are compared with that table:

- **Lab ports found.** Every lab port in the cell must be found, in every run.
- **Reported open but not listening.** Must be 0.
- **Other listeners found.** Connections to the machine's own services. These are reported but not gated, because a system service's wildcard listener can refuse when hundreds of connections reach it at the same moment. That refusal comes from the operating system, not from the scanner (see below).

A port that a tool missed in one run counts as missed.

### Run it

```sh
python -I lab/speed_compare.py --cli /absolute/path/to/network-scope-cli --repeat 3 --out-dir speed-results
python -I lab/speed_compare.py --cli ... --cells 24-top100,24-top1000,16-top100,16-top1000 --syn-nmap "sudo -n nmap"
```

On Linux, binding the lab's ports below 1024 needs `sudo sysctl -w net.ipv4.ip_unprivileged_port_start=0`, as in CI. RustScan needs a high open-file limit: run `ulimit -n 65535` first. The script writes `speed.json` (everything), `speed.md` (the table) and `baseline-candidate.json` (Network Scope's medians, ready to copy into `lab/speed_baseline.json`).

### CI

The `speed` workflow (`.github/workflows/speed.yml`) runs weekly, on manual dispatch, and on pull requests that change the comparison. It runs on `ubuntu-24.04` with pinned versions:

- nmap `7.94+git20230807.3be01efb1+dfsg-3build2`, Ubuntu's package
- RustScan 2.4.1, built from crates.io with `cargo install --locked`
- Network Scope from the shipped release profile

The pull-request runs cover only the /24 cells. The weekly and manual runs add `16-top100`. The results are uploaded as the `speed-comparison` artifact and shown in the job summary.

The job fails only for Network Scope, in two cases:

- it reports a wrong open set
- its median is more than 50 % above its own baseline in `lab/speed_baseline.json` (a platform or cell missing from the baseline passes with a notice). Shared runners differ in speed from run to run (one run had every tool two to three times slower), so when nmap `-sT` ran in the same cell, the ratio of the two times is compared with the baseline's ratio instead of the seconds

The other tools are reported, never gated: their speed is not this project's to regress, and a tool that cannot be installed is skipped with a warning. The baseline holds the Linux medians of the run in the table below; there is no Windows or macOS baseline.

Peak memory on Linux is GNU time's figure (`/usr/bin/time -f %M`, installed by the workflow). The kernel's `wait4` figure is not used: a child keeps the high-water mark of the process it was forked from, so every small tool showed the Python harness's 28 MB (the first run, on 2026-11-20, had 28.2 MB for both nmap and Network Scope). A unit test in the workflow checks that a trivial command measures far below that.

## Measured

### Network Scope on Windows (local, without the other tools)

| | |
| --- | --- |
| Machine | Windows 11 Pro (10.0.26300), AMD Ryzen 7 9800X3D (8 cores, 16 logical processors), 64 GB RAM |
| Date | 2026-11-20 |
| Build | Network Scope 0.5.1, release build (shipped profile, `--no-default-features --bin network-scope-cli`) of commit `a439126` |
| Python | 3.14 |

WSL and Docker are not available on this machine and neither nmap nor RustScan is installed, so only Network Scope ran. Without nmap the ports are Network Scope's own `top:100` list, not nmap's, and the top-1000 cells were not run.

| Cell | Wall time, median (min to max) | Peak memory | Lab ports found | Other listeners found | Reported open but not listening |
| --- | --- | --- | --- | --- | --- |
| `127.0.10.0/24`, top 100, 5 runs | 1.68 s (1.66 to 2.96) | 30.5 MB | 8/8 | 1,166/1,524 | 0 |
| `127.0.0.0/16`, top 100 | not measured: the first run had not finished when the measuring session ended, so there is no time to report | | | | |

The /16 cell is 6.5 million connects per run. On this machine 393,204 of them (six wildcard listeners on 65,534 addresses) are open, and every open one ends in a full connection and a result entry. It is left to the Linux CI run.

How to read it:

- **Other listeners.** This machine runs services on `0.0.0.0` (ports 80, 135, 445, 5357, 5432 and 5900), so each of those ports is open on all 254 addresses, which gives 1,524 pairs. Ports 80, 445, 5357 and 5432 were found on every address in every run. Ports 135 (Windows RPC) and 5900 (a VNC server) were refused on some addresses, a different number in each run (1,224 to 1,381 open pairs per run). In the table, a pair missed in any one of the five runs counts as missed.
- **Why they were refused.** A plain Python test with no Network Scope involved sent 254 simultaneous non-blocking connects to port 5900: 13 were refused (WSAECONNREFUSED). The same test with port 135 was not refused, so for port 135 the cause is likely, not shown: the scanner sends about 25,000 connects within a second or two, far more than this test. Every lab port was found in every run, and nothing was reported open that does not listen.
- **Closed ports.** An earlier measurement on another Windows machine ([Comparison with other tools](comparison.md#measured-on-the-lab)) saw a refused loopback connection take about 2 s. Here the whole /24 scan takes 1.7 s, so that wait did not show up on this machine.

### Small home LAN, Network Scope only (`--fast`); nmap and RustScan not installed

This is one real network: the owner's home LAN (a private /24), scanned with the owner's permission from the Windows machine above over wired Ethernet, on 2026-11-20. It is a small network of consumer devices behind one router; only a few dozen ports are open on the whole range. The script's `--lan` mode refuses anything but a private range of at most 256 addresses, and it has no ground truth. It reports how stable the result was across runs instead of whether it was correct.

```sh
python -I lab/speed_compare.py --cli <path>/network-scope-cli --lan <home-lan>/24 --fast --cells 24-top100 --repeat 3
# runs: network-scope-cli scan <home-lan>/24 --fast --tcp-only --ports <top:100> --scope <home-lan>/24 --quiet --db ... --output ...
```

| Range and ports | Runs | Wall time, median (min to max) | Peak memory | Open ports |
| --- | --- | --- | --- | --- |
| home /24, Network Scope's `top:100` | 3 | 28.20 s (24.54 to 28.23) | 29.7 MB | 29 in every run, 30 in at least one |
| home /24, ports 1 to 1000 | not run | | | |

How to read it:

- **Where the time goes.** The scan takes about 28 s here and 1.7 s on loopback for a range of the same size. The difference is the network: most of the 254 addresses have no device. Measured separately on 2026-11-21: one unused address costs 16.2 s with `--tcp-only` (100 ports, at most 32 at a time for an unclassified host, each waiting out its timeout and a retry), a device that answers 0.17 s. Without `--tcp-only`, Windows now skips unused on-link addresses after one ARP lookup ([details](scanning-engine.md#unused-addresses-on-the-local-network-windows)): the same /24 with discovery took 19.1 s instead of 29.9 s. What is left is the live devices that drop SYNs: the 11 hosts that answered took 18.2 s on their own, because three of them are firewalled (about 99 silent ports each, at most 32 at a time for an unclassified host, each waiting the 2 s timeout and a retry). `--adaptive-tcp` did not reliably shorten that (15.6 s and 18.6 s against 17.8 s twice, and one run lost a responding host), so it stays opt-in; waiting less per silent port would risk missing open ones.
- **The extra port.** One device answered on one port in one run only. That run-to-run difference comes from a real device, which the loopback lab does not have.
- **The 1000-port row.** It was not run: the measuring session's automatic permission check refused it, so it is not measured.
- **Safe Mode.** The default Safe Mode was not timed to the end. It allows at most about 10 probes a second for the whole scan (at least 100 ms between probes), so 254 addresses × 100 ports take more than 40 minutes by design. A first Safe Mode run was stopped after 30 minutes.

### Cross-tool table (Linux CI, loopback lab)

[`speed` run 44900787669](https://github.com/Sparkz400/network-scope/actions/runs/44900787669), 2026-11-21, GitHub's `ubuntu-24.04` runner, 3 runs per tool interleaved, nmap 7.94 (Ubuntu package) and RustScan 2.4.1. Network Scope is the release build of the change that stopped holding one record per probe (see the changelog); the run on main the day before had the same times (0.16 s and 1.20 s) and 67.7 MB at 1000 ports.

| Cell | Tool | Wall time, median (min to max) | Peak memory | Lab ports found | Reported open but not listening | Correct |
| --- | --- | --- | --- | --- | --- | --- |
| `127.0.10.0/24`, top 100 | Network Scope | 0.17 s (0.17 to 0.18) | 20.4 MB | 8/8 | 0 | yes |
| | nmap `-sT -T4` | 0.20 s (0.20 to 0.21) | 16.6 MB | 8/8 | 0 | yes |
| | nmap `-sS -T4` (root) | 0.24 s (0.24 to 0.26) | 18.1 MB | 8/8 | 0 | yes |
| | RustScan | 0.93 s (0.91 to 0.95) | 355.6 MB | 8/8 | 0 | yes |
| `127.0.10.0/24`, top 1000 | Network Scope | 1.23 s (1.20 to 1.26) | 42.6 MB | 8/8 | 0 | yes |
| | nmap `-sT -T4` | 1.76 s (1.74 to 1.78) | 25.2 MB | 8/8 | 0 | yes |
| | nmap `-sS -T4` (root) | 1.22 s (1.22 to 1.25) | 26.5 MB | 8/8 | 0 | yes |
| | RustScan | 8.66 s (7.98 to 8.77) | 356.1 MB | 8/8 | 0 | yes |

How to read it:

- **Loopback only.** This is each tool's own overhead (see the caveats). Refusals are instant on Linux loopback, so filtered-port timeouts, which dominate a real LAN, do not appear.
- **RustScan's memory** is its default batch of file descriptors and buffers sized by `--ulimit 65535`; its time is its default batch size and timeout, untuned.
- **`16-top100`** (a /16) runs only weekly and on manual dispatch; it is not in this run.

### Advanced IP Scanner

Not measured. It is a Windows GUI program. Its product page, read on 2026-11-19, documents no command-line interface, and no scriptable way to start a scan with a given range and port list was found. It is not installed on this machine, and it cannot run on the Linux CI runner. Timing it by hand with a stopwatch would not be comparable to the scripted runs.

## Caveats

- **Loopback is not a network.** There is no latency, no loss and no firewall, and refusals are instant (on Linux). The measurement shows how fast each tool can create, track and finish connections. That is a fair test of a scanner's own overhead, but on a real LAN the time is dominated by round trips and timeouts, so the ranking can change. Before treating any result as general, measure on a real /24 and /16.
- **Mostly closed ports.** The lab has open ports only on a few addresses. A range with many open ports or many filtered (silent) ports behaves differently. Filtered ports make every tool wait for its timeout, and those timeouts differ: Network Scope's default is 2000 ms, RustScan keeps its own default (the script does not set it), and nmap adapts its timeout to measured round-trip times.
- **Each tool at its defaults.** No tool was tuned beyond the options shown. Every tool has options that change its parallelism and timeouts, so the comparison is between default behaviours, not best cases.
- **Memory includes the result.** Peak memory includes building the result: the JSON report for Network Scope, the XML for nmap.
- **Platform matters.** Windows and Linux differ, both in how fast a refused connection is reported and in how listeners on the machine react to a burst. The cross-tool table is Linux CI; the Windows and home LAN numbers are Network Scope only.
