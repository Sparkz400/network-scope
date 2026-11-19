# Scanning engine

## Discovery methods

- **TCP connect** (default): Tokio, IPv4 and IPv6, no driver and no special rights.
- **ICMP**: Windows ICMP APIs; on Linux and macOS an unprivileged datagram socket when the OS allows it, else a raw socket (root). `--tcp-only` skips it.
- **ARP / neighbor lookup** (`--arp`): Windows `SendARP`, independently of ICMP, local IPv4 network only. On Linux and macOS the neighbor table is used (see [Platforms](#platforms)).
- **SYN** (`--fast --syn`): optional, needs Npcap/libpcap; see [SYN engine](#syn-engine).
- **ARP sweep** (`--fast --arp-sweep`): optional, needs Npcap/libpcap; see [ARP sweep](#arp-sweep).

A timeout never proves that a device is offline or a port closed.

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
- A failed lookup, a silent gateway or another interface falls back to TCP connect with a note "SYN unavailable; TCP connect fallback: …". Driver or configuration errors trigger the same explicit fallback; a missing reply is reported as unanswered.
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

`core` (scheduler/rate gate), `scan` (targets and model), `syn`, `arp`, `service`, `tls`, `fingerprint`, `udp`, `osfp`, `oui`, `devices`, `trace`, `topology`, `risk`, `report`, `nmap`, `monitor`, `notify`, `script`, `probes`, `capture`, `passive`, `otpassive`, `pcapfile`, `ot` (including `ot/opcua`), `platform`, `store`, `ui` (CLI/TUI) and `gui` (egui). All of them are crate-private modules of the library (`src/lib.rs`), which exports only `run` (CLI/TUI/GUI dispatch) and the fuzzing entry points (`fuzz`). `main.rs` (GUI subsystem on Windows) and `bin/network-scope-cli.rs` (console twin) just call `network_scope::run`.
