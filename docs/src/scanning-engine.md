# Scanning engine

## Discovery methods

- **TCP connect** (default): Tokio, IPv4 and IPv6, no driver and no special rights.
- **ICMP**: Windows ICMP APIs; on Linux and macOS an unprivileged datagram socket when the OS allows it, else a raw socket (root). `--tcp-only` skips it.
- **ARP / neighbor lookup** (`--arp`): Windows `SendARP`, independently of ICMP, local IPv4 network only. On Linux and macOS the neighbor table is used (see [Platforms](#platforms)).
- **SYN** (`--fast --syn`): optional, needs Npcap/libpcap; see [SYN engine](#syn-engine).
- **ARP sweep** (`--fast --arp-sweep`): optional, needs Npcap/libpcap; see [ARP sweep](#arp-sweep).

A timeout never proves that a device is offline or a port closed.

### Unused addresses on the local network (Windows)

The CLI (and `monitor`, the desktop with "Check ports even when ping gets no reply", and the MCP `scan` tool) also probes the ports of addresses that did not answer ping, because many devices drop ICMP. On a local Ethernet or Wi-Fi subnet that wastes the whole port list on addresses nobody uses: the OS has to resolve an address by ARP before it can send it a single TCP packet, and an unused address never answers, so every probe just waits out its timeout.

So on Windows an IPv4 address also gets one OS neighbor lookup alongside its ping (`SendARP`, the same ARP request the first connect would cause; one `neighbor-lookup` in the sent log and the dry run). Its answer is used only when the ping gets none, so a host that answers ping is reported exactly as before; running both at once means an unused address holds its scan slot for about 4 s instead of 6 s:

- **ARP answer**: the device is there; it counts as responding (as with `--arp`), its MAC is recorded and its ports are probed. This finds devices that drop ping and have none of the scanned ports open.
- **No ARP answer, and the address is on a directly attached Ethernet or Wi-Fi subnet** (the OS route has no gateway, and the address is not one of this computer's): the address is unused. Its ports, UDP and the BACnet Who-Is of `--ot` are skipped, and the host says so in a note ("no ARP answer on the local link"). It is not responding, exactly like an address that stays silent today.
- **Anything else** (a routed address, a VPN, tunnel or loopback adapter, IPv6, any other error): nothing changes, the ports are probed as before.

`--tcp-only` keeps its meaning, no host discovery of any kind: every address gets every port. `--arp`, `--mac` and `--os` already do the lookup and use its answer the same way; the ARP sweep's silence on an on-link address counts as unused too. Measured on a home /24 (Windows, `--fast`, top 100 ports, 2026-11-21): 29.9 s → 19.1 s with the same open ports on every host that answered, and 3 more devices found (they drop ping but answer ARP). On Linux and macOS the lookup is not added yet (its timing has not been tried on a real network), so nothing changes there.

## Rate control

Safe Mode uses a token bucket: one probe per 100 ms or the configured spacing, never faster. Outside Safe Mode there is no limiter unless you set `--rate PPS` (desktop: "Rate cap").

With `--syn --rate N` the SYN I/O thread takes one token per transmitted SYN, retransmits included, from the same bucket as every other probe. A probe's reply window starts when it is actually sent, so probes queued behind the cap are never reported as unanswered. Under a rate cap SYNs yield to ICMP, ARP and service probes. The RST that closes a half-open connection is a reply and is not rate limited.

## Concurrency

- Ping probes of a host run in parallel, and so do its port probes (`--parallel`, default 64; at most 4 in Safe Mode).
- Hosts: `--workers` (default 1024, max 4096); Safe Mode allows at most eight active hosts.
- A global cap of 4,096 in-flight probes (TCP connect and SYN) and 256 blocking native calls bounds resources. The permit is taken before a probe task is spawned.
- Scripts, DNS, ARP and ICMP calls hold their blocking slot until the native call really ends, including after a timeout or Stop.

## Retries and timeouts

Ports that stay silent are retried (`--retries`, default 1). Each retry doubles the timeout up to the port timeout, for SYN as for TCP connect. The adaptive timeout from measured ping still sets the first attempt.

### Adaptive TCP connect timing

`--adaptive-tcp` (opt-in, also usable in Safe Mode; named like `--adaptive-syn`, since `--timeout` already adapts to the ping RTT by default):

- Each host keeps its own RFC 6298 estimate (the same estimator as `--adaptive-syn`) from its completed connects. An accepted connect (SYN-ACK) and a refused one (RST) are both samples; a timeout or a local error is not.
- A probe's first connect waits `SRTT + 4·RTTVAR`, clamped between the minimum timeout (100 ms) and the port timeout, and never longer than the wait the scan would use without the flag. Retries still double up to the port timeout, so a slow answer is found on a retry.
- Before the first sample exists a host's first three ports are probed alone, so the remaining ports already get the measured timeout: a fast LAN host does not wait the full port timeout on filtered ports. A host that answers nothing waits at most 250 ms extra, once.
- It only shortens waits. Rate limits are unchanged: every attempt, retries included, still takes a gate token (Safe Mode: 100 ms spacing, 8 hosts, 4 parallel probes), and nothing is sent faster.
- The SYN engine ignores it (use `--adaptive-syn`); when SYN falls back to TCP connect it applies.
- Trade-off: a closed port that answers later than the measured RTT is reported as unanswered, not closed. Windows reports a refused connect only after about 2 s (it retransmits the SYN), so with this flag closed ports on a host that also has open ports usually show as unanswered there; open ports are unaffected. Use it on Linux/macOS scanners, or where distinguishing closed from filtered does not matter.

## Very large scans

Targets are never expanded into a list: a /8 (16,777,214 addresses, the limit of 2^24) is a range that the scheduler walks one address at a time, the scope guard judges as a range, and `--dry-run` plans without holding. A test (`core/tests/flat_memory.rs`, a counting allocator) walks 10.0.0.0/8 through the generator, the planner and the scope check and fails above 1 MiB of live memory. Measured on Windows 11 (peak working set of the whole process, 2026-11-20): `scan 10.0.0.0/8 --dry-run` 12.2 MB and 0.23 s, the same as for a /16.

Above 65,536 addresses only responding hosts are kept, and they are not kept in memory: the CLI writes them to the inventory in transactions of 1,000 hosts (`store_stream::ScanWriter`, table `scan_hosts`, database migration 5) while the scan runs. The scan row is inserted when the scan starts and marked incomplete, so an interrupted scan is on record as a partial scan with the hosts written so far. Reading a scan (`export`, `diff`, the desktop) puts the hosts back, so nothing else changes. Measured with real loopback scans of 127.0.0.0/15 (131,070 targets) and 127.0.0.0/14 (262,142): 26.0 and 26.1 MB peak, against 69.6 MB for the /16 (65,534 targets), which is below the limit and kept in memory. The report of a big scan is the exception: it is built from the stored scan and needs every responding host in memory, so very large scans are best run with `--no-report` (or `--stream`) and read later with `export ID`.

## Fast repeat scans

`scan --incremental` (and `monitor --incremental`) check a network that was scanned before without looking at everything again. The base is the newest complete scan of exactly the same targets in the inventory; if there is none, or it used other ports or detection settings, a full scan runs and the message says why.

| Per host | What a repeat scan does |
| --- | --- |
| Ports | probes the ports that were open (that are still requested) plus a sample: the 8 likeliest of the others and a rotating slice of 8 more, moved by one slice per base scan, so every port is reached after a few scans. A host that was silent gets the sample only, which is where a sparse network saves most. A scan with 16 ports or fewer is always probed completely |
| Services (`--services`) | connects once and hashes what the service says first (its greeting banner) or, for a web server, its status line, `Server` header and title. Unchanged: the identification of the base scan is kept. Changed, new or not hashable (a TLS port, a silent one): identified in full as usual. The hash is stored as `incr.fp.PORT` |
| UDP, traceroute | copied from the base scan for a host that answered then |
| Ping, ARP, OT identification, DNS, OS and device guess | run as usual |

**Nothing carried over is presented as checked again.** A host that was not probed on every requested port has `ports_checked: false`, the ports it did probe in the identity key `incr.rechecked`, the base scan in `incr.base`, and what was copied in `incr.carried` (for example `svc:22,80;udp`). `diff` and `monitor` compare exactly the ports both scans looked at: a known port that closed or a sampled port that opened is reported, a port the repeat scan did not probe is not, and the `incr.*` keys are bookkeeping that never shows up as a change. A repeat of an unchanged host diffs empty (a test checks it); a test also closes a port between a full and a repeat scan and checks the diff names it.

The price is stated plainly: a repeat scan can miss a new service on a port outside the sample, or a changed UDP answer, until the rotation reaches it. Run a full scan now and then; `monitor --incremental` does it every 10th cycle (`--full-every N`). Run time depends on how much of the cost is port probing and identification; the lab numbers are in [Lab and testing](lab-and-testing.md#fast-repeat-scans).

## Several subnets and interfaces at once

Several target ranges (`10.0.1.0/24,10.0.2.0/24,192.168.1.0/24`) are scanned at the same time, not one after the other: the targets are handed to the scheduler one address of each range in turn, so a slow or silent subnet cannot hold the others back. There is one rate gate, one worker limit and one back-off for the whole scan, so `--rate` and Safe Mode spacing apply to the scan as a whole, however many subnets it covers. A test scans two loopback ranges concurrently.

The raw features can use several interfaces: `--interface eth0,eth1 --source-ip 10.0.0.5,192.168.1.5 --source-mac M1,M2` (paired by position) opens a SYN engine and an ARP sweep engine per interface, and each target goes out through the interface the operating system's routing table picks for it: one on whose subnet the target lies, else the first that routes to it, else the connect scan. The pairing and the choice are unit-tested, and one SYN + ARP sweep scan over a wired adapter and a VMware adapter ran on Windows with Npcap, without administrator rights (see [Lab and testing](lab-and-testing.md#what-has-been-tested-on-real-hardware)); not run with libpcap.

## Probe order and early stop

A host's ports are probed likeliest first, not in numeric order: first the order of the built-in top-100 frequency list, then the rest by number. As evidence for a device class arrives (the MAC vendor from the ARP answer, the initial TTL from the ping, and the ports found open so far), the class's priority ports move to the front: printers 9100, 631, 515; controllers 502, 102, 44818; Windows 445, 135, 3389; and so on (`data/port_classes.json`). The scan only reorders the ports you asked for, never adds one, and the result of a host is sorted by port at the end, so the order never changes what is reported; a test scans the same host with two different orders and compares the results. The order matters when probes are paced (Safe Mode, `--rate`) or capped (`--parallel`): the answers that identify a host arrive first.

`--early-stop` (off by default) uses that: once a host's class is certain (two signature ports open, or one plus a vendor match, the device classifier agrees, and the class's priority ports have been probed), its remaining ports are skipped. With the flag the number of probes in flight per host is capped at 16, so answers arrive while ports are left to skip. A host that stopped early has `ports_checked: false` and a note ("early stop: identified as Printer / MFP ... N port(s) were not probed"), so `diff` and `monitor` treat its unprobed ports as unknown, not closed. Use it for a quick inventory; do not use it where a complete port list matters.

## Automatic back-off

A scan must never harm a device, so each host has its own pacing controller (on by default; `--no-backoff` or the Settings checkbox turns it off). It only ever slows a host down: it never raises a limit above what Safe Mode, `--parallel` or `--rate` allow.

**Limits per device type.** The type is learned from the ports found open during the scan, and caps the parallel probes to that host:

| Type | Recognised by | Parallel probes | Back-off step | Paused after |
| --- | --- | --- | --- | --- |
| OT controller or printer | an OT port (102, 502, 4840, 44818, 47808, ...) or a printer port (515, 9100-9107) is open | at most 2 | 250 ms | 3 strikes |
| Unclassified (every host at the start) | everything else | at most 32 | 100 ms | 4 strikes |
| Computer | two or more typical computer ports are open (22, 135, 139, 445, 3389, 5985, databases, ...) and no OT or printer port | no extra cap | 50 ms | 6 strikes |

**What counts as trouble.** A closed port answers with a refusal and a filtered port with silence on a perfectly healthy host, so neither says anything about an ordinary computer; a scan of a host with thousands of closed ports is never slowed. These do count:

- A connection that is **reset or aborted while connecting**, and a port the scan found open that **stops answering** when service or OT identification connects to it again (the "refuses after N connections" pattern). Each is a *strike*: the host's parallel probes are halved, the delay between its probes doubles (starting at the step above, at most 2 s) and, after enough strikes, the host is **paused for the rest of the scan**: no further probes of any kind are sent to it. Ports that were not probed because of a pause are unknown, not closed: the host is marked as not fully checked, so `monitor` and `diff` do not report them as closed.
- On OT controllers and printers only: a burst of 12 refusals in a row, or 6 timeouts among the last 8 connections, after the host had answered. That slows the host down once and never pauses it.

Every reaction is recorded in the host's notes, first in the list, as `backed off: ...` with the reason and the new limits. The controller is a pure state machine (`core/src/backoff.rs`) with tests for these rules, including the negative cases above.

## Ports

`--top-ports N` or `top:N` in the port field adds the N most common TCP ports (1-100). The ordering is approximate, recalled from public scanner statistics, and not generated from any third-party services file.

## Targets

Ranges are expanded lazily. The CLI accepts up to 16,777,216 addresses (a /8); above 65,536 only responding hosts are kept and saved. The desktop keeps the 65,536 limit.

"Skip network/broadcast addresses":

- CIDR blocks of /30 or shorter skip only their own network and broadcast address (`10.0.0.255` and `10.0.1.0` inside `10.0.0.0/23` are scanned).
- /31 and /32 are never trimmed.
- Dash ranges keep skipping every `x.x.x.0` and `x.x.x.255`.

A diff of an old (0.4) /23-or-larger snapshot against a new one of the same text can therefore report the inner .0/.255 addresses as new.

## SYN engine

`--fast --syn --interface ID --source-ip IP --source-mac MAC`. Source values must match that interface.

- One Npcap/libpcap handle, opened non-promiscuous with the kernel filter `tcp and dst host <source-ip>`, is owned by one I/O thread that sends and receives.
- Replies are matched on target, ports and a hashed sequence cookie.
- **Routed IPv4 targets** are scanned too: the next hop comes from the OS routing table (Windows `GetBestRoute`, Linux longest-prefix match in `/proc/net/route`, macOS/BSD `route -n get`). An on-link target is sent to its own MAC, a routed one to the gateway MAC, resolved once per gateway. The route must leave through the capture interface.
- A failed lookup, a silent gateway or another interface falls back to TCP connect with a note "SYN unavailable; TCP connect fallback: …". So does an address of this computer (the source address; on Windows any of its adapters' addresses): a frame to it leaves on the wire and is never looped back. TCP traceroute to such an address says so. Driver or configuration errors trigger the same explicit fallback; a missing reply is reported as unanswered.
- IPv4 only, untagged frames; no IPv6 SYN.
- After Stop no queued SYN or retransmit leaves.

Packet construction uses `pnet_packet`; Npcap/libpcap is loaded at run time.

### Adaptive SYN timing

`--adaptive-syn` (opt-in, only with SYN, so never in Safe Mode):

- A target's reply window is `SRTT + max(1 ms, 4·RTTVAR)` from its own samples (RFC 6298, Karn's rule), clamped between the minimum and the port timeout. Targets without samples keep the usual window, and a fast neighbour never shortens a slow target's window.
- An answer after a retransmit records an upper bound, so a target that slowed down gets longer windows again.
- New probes are limited by an AIMD congestion window (start 10, max 4,096); an answer to a retransmitted probe halves it, at most once per reply window. A probe with no answer at all counts as completed, not as loss, so firewalled ranges are not held at 10 in flight.
- Every SYN still takes a `--rate` token.

## ARP sweep

`--arp-sweep` (opt-in, not in Safe Mode, needs Npcap/libpcap):

- A second capture handle with the filter `arp` broadcasts who-has requests for on-link IPv4 targets (never the scanner's own address), at most 256 unanswered at a time, one `--rate` token each.
- Requests repeat up to `--retries` times (at most 3 requests per target), each waiting the ping timeout clamped to 100-300 ms.
- A reply gives the MAC and proves the host is up now; a silent target gets no further per-host lookup.
- Each host task submits its own address, so throughput is also bounded by `--workers` (a silent address holds its worker for wait × requests).
- Routed and IPv6 targets, Safe Mode, and a missing driver, interface, source IPv4 or source MAC use the per-host OS lookup instead (host note "ARP sweep unavailable; per-host lookup: …").

## Traceroute

`--trace`, or `network-scope trace IP`. `--trace-method icmp|tcp|udp` implies `--trace`; the default is ICMP.

- **ICMP** probes all TTLs in parallel. IPv6 targets use ICMPv6 echo with an increasing hop limit (Windows `Icmp6SendEcho2`, Linux/macOS raw ICMPv6 socket, root).
- **TCP** sends TTL-limited SYNs through the capture interface (same settings as `--syn`) to `--trace-port` or the host's first open port. OT ports (including 2222) and printer ports are never used; without an allowed open port ICMP is used. Routed targets go via the gateway MAC.
- **UDP** sends datagrams to ports 33435-33498 (33434 + TTL) and reads answers from a raw ICMP socket (administrator/root).
- TCP and UDP send TTLs in waves of three and stop after the wave in which the target answered, one `--rate` token per probe. A silent target (filtered port) receives one probe per remaining TTL up to `--max-hops`.
- Safe Mode, IPv6 targets, no eligible port and local failures fall back to ICMP with a host note.
- `network-scope trace` takes `--fast --trace-method udp`, or `--fast --trace-method tcp --trace-port N` with the SYN interface options (`--rate` applies). Without `--fast` only ICMP is allowed.
- Replies are matched by a per-trace ICMP id and the quoted destination; echo matching checks the sequence (and the id where the OS keeps it).

`network-scope topology ID --format ascii|dot` and the Topology window draw the merged path map.

## Platforms

- ICMP and neighbor lookup work on Linux and macOS as well.
- libpcap is loaded from `libpcap.A.dylib`/`libpcap.dylib` (macOS) or `libpcap.so.1`/`libpcap.so`/`libpcap.so.0.8` (Linux).
- MAC lookup is skipped for IPv4 targets that are not on a local subnet (on-link routes from `/proc/net/route`; without it, macOS treats every target as on-link).
- On Linux a cached `/proc/net/arp` entry gives the MAC, but the host only counts as responding if `ip neigh` reports it REACHABLE or the entry appeared after the scanner's one UDP/9 datagram. STALE entries do not prove a host is up, so on a rescan a device that answers neither ICMP nor TCP may be reported as not responding (use `--arp-sweep`). The miss path is one poke, one 250 ms wait and one re-read.

## Benchmark (indicative only)

One machine, one day: a Windows 11 host scanning a Windows VM and its /24 over VMware NAT. nmap 7.92 (`nmap -sT -Pn -n --unprivileged -T4 --max-retries 1 --max-rtt-timeout 1500ms`) against Network Scope (`scan --fast --tcp-only --timeout 1500`). Both TCP connect scans, no Npcap.

| Scenario | nmap | Network Scope | Same result? |
| --- | --- | --- | --- |
| 1 host, ports 1-1000 (target drops most ports) | 46.7 s (one run) | 49.0 s (one run) | yes, 7 open ports each |
| /24, ports 22,80,445 | 38.4 s and 40.7 s | 3.3 s and 3.4 s | not compared: nmap `-Pn` lists every address as up, so only our run's 2 responding hosts were checked |

On one host whose firewall silently drops most ports, both tools are limited by the timeout and are about equal. The /24 gap comes from how each handles mostly empty address space under these settings, not from a faster packet path; other timing or host-discovery options may close it. Single-digit runs, one network, no warm-up control: treat the numbers as a sanity check. Reproduce with the commands above. The numbers predate 0.5.

## Source layout

The repository is a Cargo workspace of two crates.

`network-scope-core` (`core/`, library `network_scope_core`) is the engine without any GUI code: `core` (scheduler/rate gate), `scan` (targets and model), `syn`, `arp`, `service`, `tls`, `fingerprint`, `udp`, `osfp`, `oui`, `devices`, `trace`, `topology`, `risk`, `report`, `nmap`, `monitor`, `notify`, `script`, `probes`, `capture`, `passive`, `otpassive`, `pcapfile`, `observations`, `ot` (including `ot/opcua`), `platform` and `store`. Its crate documentation (`cargo doc -p network-scope-core --open`) lists the entry points for other tools: scan a target list, parse and import, analyze risk, open the store.

`network-scope` (the repository root) is the application: `ui` (CLI/TUI, `src/ui/`: option parsing, one file per command under `src/ui/commands/`, the live view) and `gui` (egui). Its library (`src/lib.rs`) exports only `run` (CLI/TUI/GUI dispatch) and the fuzzing entry points (`fuzz`, re-exported from the core crate). `main.rs` (GUI subsystem on Windows) and `bin/network-scope-cli.rs` (console twin) just call `network_scope::run`.
