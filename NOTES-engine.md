# Engine notes (wave 1 bug fixes)

Requests and decisions for files this wave did not own (README.md, Cargo.toml, ui.rs, gui/*).

## Requests

### README.md
- **Engine / Rate control.** With `--syn --rate N`, the SYN I/O thread takes one token per transmitted SYN, retransmits included, from the same bucket as every other probe. Core no longer takes a second token for SYN probes. A probe's reply window starts when its SYN is actually sent, so probes queued behind the rate cap are never reported as unanswered. Retransmits are sent before new probes. The RST that closes an open port's half-open connection is a reply and is not rate limited (unchanged).
- **Engine / SYN engine.** Each retransmit now doubles the wait, capped at the port timeout, the same as TCP connect. The capture is opened non-promiscuous with the kernel BPF filter `tcp and dst host <source-ip>`. In-flight SYN probes share the global 4,096 in-flight bound with TCP connect.
- **Engine / Platforms.**
  - libpcap is loaded from `libpcap.A.dylib` or `libpcap.dylib` on macOS and from `libpcap.so.1`, `libpcap.so` or `libpcap.so.0.8` on Linux.
  - MAC lookup is skipped for IPv4 targets that are not on a local subnet, using on-link routes from `/proc/net/route` (Linux). Without that file (macOS) every target is treated as on-link, as before.
  - On Linux, a cached `/proc/net/arp` entry gives the MAC, but the host only counts as responding if `ip neigh` reports it REACHABLE or the entry appeared after the scanner's one UDP/9 datagram. STALE entries have the same 0x2 flag, so the flag alone does not prove a host is up.
  - The miss path is now one poke, one 250 ms wait and one re-read, down from three waits totalling 760 ms and up to 8 process spawns.
- **Engine / Concurrency.** The global socket permit is taken before a port-probe task is spawned. Large `--workers` × `--parallel` values therefore no longer create millions of parked tasks. Scripts, DNS, ARP and ICMP calls hold their blocking-pool slot until the native call really ends, including after a timeout or Stop.
- **Desktop / Stop.** Stop now keeps hosts that had already finished when Stop was pressed.
- **Discovery / OT.** `ot::identify`, including the BACnet Who-Is, now runs only for hosts that responded to something: ARP (fresh), ICMP, any TCP port answer, or UDP. ICMP-silent devices with an open or closed OT TCP port still qualify.
  - What is lost: a device that answers *only* BACnet/IP (UDP 47808), with no ICMP, ARP or TCP answer, is no longer found.
  - The README line "one unicast Who-Is per selected IPv4 target" should become "per responding target".
  - The README sentence "enable nonresponders to find ICMP-silent TCP services" remains true.
- **Targets / "Skip .0 and .255".**
  - CIDR blocks with a prefix of 30 or shorter now skip only their own network and broadcast address. For example, `10.0.0.255` and `10.0.1.0` inside `10.0.0.0/23` are scanned, and `10.0.0.128/25` skips `.128` and `.255`.
  - `/31` and `/32` are never trimmed, and single addresses never were.
  - Dash ranges (`a-b`, `a.b.c.d-e`) keep the legacy rule of skipping every `x.x.x.0` and `x.x.x.255`, because the GUI label documents that rule for "ranges".
  - Consequence for comparisons: an old snapshot of a /23 or larger was scanned without the inner .0/.255 addresses. A diff against a new snapshot of the same target text can therefore report those addresses as new devices.
- **Exports.** CSV cells that start with `=`, `+`, `-`, `@`, TAB or CR get a leading `'` (OWASP CSV-injection guidance). Purely numeric cells such as `-1` are left unchanged.
- **CLI on Windows.** The stderr behaviour and the trade-off described under "Console binary" below should be documented.

### gui/settings.rs (label only)
- Change `"Skip .0 and .255 in ranges and subnets"` to something like `"Skip network/broadcast addresses (CIDR: true edges; ranges: .0 and .255)"`.

### ui.rs (decision for its owner)
- `scan_settings` sets `scan_nonresponders: true` for every CLI scan and monitor run. This is not a bug fix in my scope, but it means every CLI scan probes every address's ports. Keep it if that is the intended CLI behaviour.

### Console binary (Cargo.toml + packaging), for bug 7
- **Fixed in main.rs.** When CLI arguments are given and the process has no console, it calls `AttachConsole(ATTACH_PARENT_PROCESS)`, regardless of whether stdout is redirected. It then rebinds only the standard handles that were NULL, invalid or of unknown type to `CONIN$`/`CONOUT$`. Redirected handles (files, pipes) are kept.
  - Before, the attach only happened when stdout was NULL. With `> out.txt`, stderr (progress and error messages) was therefore lost whenever stderr itself was not redirected.
  - The exit code is still set (`std::process::exit(1)` on CLI errors).
- **Not fixable in-process.** A release build is a `windows`-subsystem binary, so `cmd.exe` and PowerShell do not wait for it when it is started without redirection. The prompt returns immediately, output interleaves with the next prompt, and `$LASTEXITCODE`/`%ERRORLEVEL%` do not reflect the scan. Only the PE subsystem decides this.
- **Request:** ship a second, console-subsystem binary for scripting, for example a `[[bin]] name = "network-scope-cli"` with the same `main` but without `windows_subsystem`, or a tiny wrapper. Keep the GUI binary for double-click use. The installer should put the CLI binary on PATH.
  - Workaround until then: `Start-Process -Wait -NoNewWindow`, or redirect output (`| Out-Host`), which makes PowerShell wait.

### Cargo.toml
- No new dependencies were needed.

## Verified but changed less than suggested
- **Bug 13, which states count as live.** The review suggested REACHABLE or DELAY. I count only REACHABLE (or "absent before the poke, present after"). DELAY and PROBE only mean that traffic was sent recently, possibly by this scanner's own ping, without a confirmation. PERMANENT is a static entry.
- **Bug 9, process spawns.** On Linux, a cache hit still costs one `ip neigh show` spawn to read the entry's state, which bug 13 needs. A miss spawns nothing when `/proc/net/arp` exists. `ip neigh` / `arp -n` are only the lookup itself when `/proc/net/arp` is unavailable (macOS, IPv6).
- **Bug 15, echo matching.** The sequence number is always checked. The identifier is checked for raw sockets and macOS/BSD datagram sockets, which leave it unchanged and deliver every echo reply on the host. It is not checked for Linux datagram sockets, because the kernel rewrites it to the socket's own id and already delivers only that socket's replies.
- **Bug 5, the ARP part of the filter.** It was not needed: the SYN engine resolves MACs through the OS (`platform::mac`) and never reads ARP frames, so the filter is just `tcp and dst host <src>`.
- **Bug 3, the scope of the id.** It is unique per trace (one id per `trace::trace` call, counter-based) and never equal to the pid-based id that ping echoes use. Matching also requires the quoted inner destination (Time Exceeded/Unreachable) or the reply source (echo reply) to be the traced destination, and both IHLs to be at least 5.
- **Bug 8, the SYN in-flight bound.** SYN probes now also take a slot of the global 4,096 in-flight bound before their task is spawned. This bounds the engine's queue; it was previously unbounded apart from the per-host limit.

## Side effects the caller should know about
- **Stop with SYN.** Because queued probes no longer expire, the I/O thread now drops every probe whose caller went away (Stop aborts the host tasks). It does this before a token is taken and on every 5 ms sweep, so no queued SYN or retransmit leaves after Stop. There is a regression test with a fake wire.
- **SYN priority under `--rate`.** `Gate::try_take` (the SYN thread) never goes into debt, while `Gate::wait` (async probes) reserves future tokens. Under a rate cap, SYNs therefore yield to ICMP, ARP and service probes. This affects throughput only, not safety.
- **Bug 13 on Linux.** STALE entries linger while the neighbor table is small. A device that answers neither ICMP nor TCP is found via ARP on the first scan, while its entry is fresh. On a rescan or monitor cycle the entry may be STALE, so it is reported as not responding, which interacts with `monitor --report-missing`. This follows from the requested fix: a stale cache entry is not proof of life. A fix would need an active ARP request (raw socket or capture), which is out of scope for a bug-fix wave.

## Without a regression test
- **Bug 8 (permit before spawn).** This is a structural change: the permit is acquired before `JoinSet::spawn`. Observing it would need task-count instrumentation in the scheduler, which does not exist, so there is no regression test. Existing loopback scan tests cover that scans still complete.
- **Bugs 5, 6, 7.** Tested only at the pure-function level: library candidates, the `c_char` buffer, the filter string and the std-handle decision. The driver calls themselves are not exercised.

## Untested on this machine (Windows only; Unix code is not even compiled here)
- `platform.rs` Unix glue: `neighbor_unix` (routes, `/proc/net/arp`, `ip neigh`, the poke), `hop_unix` (raw-socket traceroute with the per-trace id), and the datagram/raw echo matching in `mod unix`. The decision logic is in platform-neutral functions with unit tests (`parse_proc_route`, `on_link`, `ip_neigh_reachable`, `neighbor_outcome`, `echo_matches`, `parse_hop_reply`, `parse_echo_reply`). The cfg'd glue was only reviewed by eye. CI on Linux and macOS (clippy `-D warnings`) is the first compile.
- `capture.rs`: the non-Windows library candidate loop, `pcap_compile`/`pcap_setfilter` on any OS, and non-promiscuous open. Npcap is not installed here, so no capture or SYN path was run live. The SYN I/O loop is tested against a fake wire (rate, doubling, priority, SYN-ACK to RST).
- `main.rs` console attach: fixed from code reading and **not verified** in a real console. In this harness, GUI-subsystem builds of both the old and the new `main.rs` printed stderr when only stdout was redirected through `Start-Process`, because the harness passes a pipe as stderr. The original failure was therefore not reproduced. Please check by hand in `cmd.exe` and PowerShell with `> out.txt`, with `2> err.txt`, and without redirection.
