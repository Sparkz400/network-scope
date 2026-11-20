# Speed comparison

How long a port scan takes with Network Scope, nmap and RustScan on the same targets and the same ports (roadmap B10). The goal is to be the fastest tool that needs no driver. Every number on this page was measured. A cell with no measurement says so and is not estimated.

The short version: so far only Network Scope has been timed, on one Windows machine. The cross-tool numbers come from the `speed` CI workflow, which has not run yet.

## What is measured

`lab/speed_compare.py` (Python standard library only) starts the lab simulators of the [accuracy benchmark](lab-and-testing.md#accuracy-benchmark) on `127.0.10.1` to `127.0.10.6`. It then times each tool in each *cell*, where a cell is a target range plus a port list:

| Cell | Targets | Ports |
| --- | --- | --- |
| `24-top100` | `127.0.10.0/24` (254 addresses) | nmap's top 100 |
| `24-top1000` | `127.0.10.0/24` | nmap's top 1000 |
| `16-top100` | `127.0.0.0/16` (65,534 addresses) | nmap's top 100 |
| `16-top1000` | `127.0.0.0/16` | nmap's top 1000 (65 million connects per run; only on request, `--cells`) |

All of `127.0.0.0/8` is loopback, so nothing leaves the machine and no real network is needed. Both ranges contain the lab hosts.

- **Port lists.** The lists are taken from the installed nmap (`nmap -sT --top-ports N -v -oG -`), and every tool gets the same explicit list. Without nmap, the top 100 falls back to Network Scope's own `top:100` list (a different list) and the top 1000 is not run.
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
- its median is more than 50 % above its own baseline in `lab/speed_baseline.json` (a platform or cell missing from the baseline passes with a notice)

The other tools are reported, never gated: their speed is not this project's to regress, and a tool that cannot be installed is skipped with a warning. The workflow has not run yet, and the baseline is still empty.

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

### Cross-tool table

Not measured yet. The `speed` CI workflow produces it with nmap 7.94 and RustScan 2.4.1 on Ubuntu 24.04. Its table will be copied here, with the run's link, once it has run.

### Advanced IP Scanner

Not measured. It is a Windows GUI program. Its product page, read on 2026-11-19, documents no command-line interface, and no scriptable way to start a scan with a given range and port list was found. It is not installed on this machine, and it cannot run on the Linux CI runner. Timing it by hand with a stopwatch would not be comparable to the scripted runs.

## Caveats

- **Loopback is not a network.** There is no latency, no loss and no firewall, and refusals are instant (on Linux). The measurement shows how fast each tool can create, track and finish connections. That is a fair test of a scanner's own overhead, but on a real LAN the time is dominated by round trips and timeouts, so the ranking can change. Before treating any result as general, measure on a real /24 and /16.
- **Mostly closed ports.** The lab has open ports only on a few addresses. A range with many open ports or many filtered (silent) ports behaves differently. Filtered ports make every tool wait for its timeout, and those timeouts differ: Network Scope's default is 2000 ms, RustScan keeps its own default (the script does not set it), and nmap adapts its timeout to measured round-trip times.
- **Each tool at its defaults.** No tool was tuned beyond the options shown. Every tool has options that change its parallelism and timeouts, so the comparison is between default behaviours, not best cases.
- **Memory includes the result.** Peak memory includes building the result: the JSON report for Network Scope, the XML for nmap.
- **Platform matters.** Windows and Linux differ, both in how fast a refused connection is reported and in how listeners on the machine react to a burst. The numbers above are Windows and Network Scope only. The comparison is designed for Linux CI.
