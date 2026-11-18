# Engine features (wave 2)

Requests for files this wave did not own (README.md, ui.rs, gui/*), and the documentation text for each feature.

All new transmitting behaviour is **off by default**. It is disabled in Safe Mode and goes through the scan's shared rate gate (`core::Gate`). The new `Settings` fields use serde defaults, so old snapshots load with every feature off.

| Setting (scan.rs) | Type / default | Feature |
|---|---|---|
| `arp_sweep` | bool, false | ARP sweep through the capture handle |
| `syn_adaptive` | bool, false | Adaptive SYN timing and congestion control |
| `trace_method` | `trace::TraceMethod` (`"icmp"` / `"tcp"` / `"udp"`), `icmp` | Traceroute method |
| `trace_port` | u16, 0 | TCP traceroute port (0 = automatic) |

Gateway MAC resolution and ICMPv6 traceroute are not options: they make existing settings (`--syn`, `--trace`) work for more targets.

## Requests

### ui.rs (CLI flags)
In `scan_settings`:
- `--arp-sweep` → `s.arp_sweep = true`.
- `--adaptive-syn` → `s.syn_adaptive = true`. Only has an effect with `--syn`.
- `--trace-method icmp|tcp|udp` → `s.trace_method`. Suggested parse:
  `serde_json::from_value(serde_json::Value::String(v.to_lowercase())).map_err(|_| "Trace method must be icmp, tcp or udp")`, or a plain `match`. Setting it should also imply `s.trace = true`.
- `--trace-port N` (1-65535) → `s.trace_port`.
- The CLI already sets `s.safe = !opts.contains_key("fast")`. ARP sweep, adaptive SYN, and TCP/UDP traceroute therefore only take effect together with `--fast`, the same as `--syn`. The help text should say so.

`trace` subcommand (optional):
- It still calls `crate::trace::trace` (ICMP). That call now also works for IPv6 targets (hop limit), with no change needed.
- To offer `--method udp` there, call `crate::trace::trace_udp(v4, hops, timeout, &blocking, &Gate::unlimited())`.
- To offer `--method tcp --port N` there, build a `Settings` with `interface` / `source_ip` / `source_mac` from the usual flags. Then call `crate::syn::tcp_trace(&settings, v4, port, hops, timeout, &gate)` and pass the result through `crate::trace::assemble`. Check `crate::trace::trace_port_allowed(port)` first.

### gui/settings.rs (controls)
- Next to the "ARP" checkbox: `ui.add_enabled(!s.safe, egui::Checkbox::new(&mut s.arp_sweep, "Fast ARP sweep through the capture interface (needs Npcap)"))`.
- Next to the SYN checkbox: `ui.add_enabled(!s.safe && s.syn, egui::Checkbox::new(&mut s.syn_adaptive, "Adaptive SYN timing (RTT-based timeouts, slows down on packet loss)"))`.
- Under the traceroute checkbox, while `s.trace` is set:
  - A `ComboBox` "Method" with `TraceMethod::Icmp` "ICMP", `TraceMethod::Tcp` "TCP SYN (needs Npcap)" and `TraceMethod::Udp` "UDP (needs administrator)". TCP and UDP are greyed out, or labelled "ICMP in Safe Mode", while `s.safe`.
  - While `trace_method == Tcp`: `DragValue` on `s.trace_port` with range `0..=65535` and hint "0 = first open port; OT and printer ports are never used".
- `standard_settings` in gui/mod.rs needs no change: the fields default to off.

### README.md (documentation text)

**Engine / SYN engine: routed targets.**
- The SYN engine now scans routed IPv4 targets too.
- The next hop comes from the OS routing table:
  - Windows: `GetBestRoute`.
  - Linux: longest-prefix match in `/proc/net/route`, lowest metric on ties.
  - macOS/BSD: `route -n get`.
- An on-link target is sent to its own MAC. A routed target is sent to the gateway's MAC, which is resolved once per gateway and cached for the whole scan.
- The route must leave through the capture interface. On Windows this is the interface that owns the source IPv4. On Linux and macOS it is the selected interface name.
- If the lookup fails, the gateway does not answer ARP, or the route uses another interface, that target falls back to TCP connect and the host shows "SYN unavailable; TCP connect fallback: …". This is unchanged behaviour.

**Engine / ARP sweep (`--arp-sweep`, opt-in, not in Safe Mode).**
- Opens a second capture handle with the kernel filter `arp` and broadcasts ARP who-has requests for on-link IPv4 targets. The scanner's own address is never included.
- Requests go out in batches, with at most 256 unanswered at any time. Each request takes one token from the `--rate` gate.
- An unanswered request is repeated up to `--retries` times (at most 3 requests per target). Each request waits for the ping timeout, clamped to 100-300 ms.
- **Throughput.** Each host task submits its own address, so the number of ARP requests in progress is bounded by `--workers` as well as by the 256 window. A silent address holds its worker for wait × requests (default 300 ms × 2).
- A reply gives the MAC and marks the host as responding. Unlike a cached neighbor entry, it proves the host is up right now.
- A target that stays silent gets no further per-host lookup.
- The per-host OS lookup (SendARP / neighbor table) is used instead in these cases:
  - routed or IPv6 targets;
  - no capture driver, or interface / source IPv4 / source MAC not set (the host gets a note "ARP sweep unavailable; per-host lookup: …");
  - Safe Mode.

**Engine / Adaptive SYN timing (`--adaptive-syn`, opt-in, SYN is never used in Safe Mode).**
- **Reply windows.**
  - A target's reply window comes from its own smoothed RTT, as in RFC 6298: `SRTT + max(1 ms, 4·RTTVAR)`. It is clamped between `minimum_timeout` and the port timeout.
  - A target without its own samples keeps the usual window (from its ping RTT or the port timeout). A fast neighbour never shortens a slow target's window.
  - Precise samples come only from probes that were sent once (Karn's rule).
  - When an answer arrives only after a retransmit, the time since the first SYN is recorded as an upper bound. A target that slowed down therefore gets longer windows again.
  - Retransmits still double the wait, up to the port timeout.
- **Congestion window.** New probes are limited by an AIMD congestion window over the SYNs in flight. It starts at 10 and never exceeds 4,096. It grows by one per completed probe below the threshold, and by about one per window above it.
- **Loss signal.** The loss signal is an answer to a probe that had to be retransmitted. A loss halves the window, at most once per reply window.
- **Silent ports.** A probe that ends with no answer at all counts as completed, not as loss. Firewalled networks drop probes silently, so the window still grows there, and a silent range is not held at 10 probes in flight.
- **Rate limit.** Every SYN still takes a `--rate` token, so the configured rate is never exceeded.

**Traceroute methods (`--trace-method icmp|tcp|udp`, default icmp).**
- **ICMP** (default): unchanged for IPv4. IPv6 targets are now traced with ICMPv6 echo and an increasing hop limit:
  - Windows: `Icmp6SendEcho2`.
  - Linux/macOS: raw ICMPv6 socket, needs root.
- **TCP**: TTL-limited SYNs to an open port through the capture interface (Npcap/libpcap, same interface settings as `--syn`).
  - The port is `--trace-port`, or else the host's first open port.
  - OT protocol ports (including 2222) and printer ports (515, 9100-9107) are never used. If no allowed port is open, ICMP is used instead.
  - Routers answer with ICMP Time Exceeded. The target answers with SYN-ACK, which is reset at once, or RST.
  - Routed targets go via the gateway MAC.
- **UDP**: datagrams with increasing TTL to ports 33435-33498 (33434 + TTL). Answers are read from a raw ICMP socket, which needs administrator rights on Windows and root on Linux/macOS.
- **Waves and rate limit.** TCP and UDP send TTLs in ascending waves of three and stop after the wave in which the target answered. Every probe takes a `--rate` token.
  - If the target answers, at most three probes reach it.
  - If the target stays silent (a firewall drops the SYNs or the UDP datagrams), every TTL beyond the path length, up to `--max-hops`, also reaches it. TCP traceroute picks an *open* port by default, which the target normally answers. An explicit `--trace-port` that is filtered gets one SYN per remaining TTL.
- **Fallbacks.** In Safe Mode, for IPv6 targets, without an eligible port, or after a local failure (no driver, no raw socket), the trace falls back to ICMP. The host gets a note explaining why.

**CLI on Windows: `network-scope-cli.exe`.**
- The installer now also installs `network-scope-cli.exe`, a console-subsystem build of the same program, and the "Add to PATH" task covers it.
- `cmd.exe` and PowerShell wait for it, and `%ERRORLEVEL%` / `$LASTEXITCODE` reflect the run (1 on error). Its output never interleaves with the next prompt.
- `network-scope.exe` stays a GUI-subsystem program for double-click use. Started from a shell it still returns immediately (see NOTES-engine.md).
- Use `network-scope-cli` in scripts. Started without arguments it opens the GUI like the main binary, with a console window.

### Packaging / CI
- Release builds now produce `target/release/network-scope-cli.exe` next to `network-scope.exe`.
- The installer has a new define, `CliExePath` (default `..\target\release\network-scope-cli.exe`). Pass `/DCliExePath=…` if the build script overrides `ExePath`.
- CI artifacts / release uploads should include the second binary.

### Cargo.toml
- Only a `[[bin]] network-scope-cli` entry was added, with `test = false` because its tests are the main binary's. No new dependencies.

### For every agent adding modules
- `src/bin/network-scope-cli.rs` compiles `src/main.rs` as a module (`#[path = "../main.rs"] mod app; use app::*;`). Modules declared in main.rs must therefore be `pub(crate) mod x;`. A private `mod x;` is unreachable as `crate::x` from the console binary and breaks its build.
- The test `tests::modules_are_visible_to_the_console_binary` in main.rs checks this.

## Implementation notes
- `platform::next_hop(dest, source, interface) -> Result<NextHop, String>` with pure helpers `route_decision`, `parse_proc_route_table`, `best_route` and `parse_route_get`. `NextHop::l2_address(dest)` is the address whose MAC the frames carry.
- `syn::SynEngine` caches target → next-hop address and next-hop address → MAC. Route and neighbor lookups are injectable (`with_parts`), which the unit tests use.
- `syn::Timing`, `RttEstimator` and `Window` are pure and unit-tested. `io_loop` tracks the probes in flight and applies the window only to new probes; retransmits are always allowed. RTT estimates are per target only, with no global fallback.
- `arp.rs` (new): `request`, `parse_reply`, `ArpEngine` (I/O thread, the same `Wire` trait as the SYN engine), and a window of 256. Abandoned requests (Stop) are dropped before they are sent.
- `syn::tcp_trace` opens its own capture handle per traced host with the filter `(icmp or tcp) and dst host <source>`. Local ports are 40001-49023, below the SYN engine's 49152-65535. The sequence number is a cookie, so parallel traces and SYN scans do not confuse replies.
- `trace::plan` (pure) picks the method and port, and `trace::in_waves` runs the waves. `trace::trace` keeps its signature (ui.rs calls it).
- `platform::udp_hop` / `parse_udp_hop_reply` handle UDP. `parse_hop6_reply` / `hop6_unix` and `win::hop6` handle ICMPv6.

## Tested
- **Unit tests:** ARP frame build and parse; the ARP engine against a fake wire (replies, duplicates, retries, rate gate, 256-window bound, Stop); route-table parsing, best route, `route -n get` parsing, route decision; RFC 6298 estimator; AIMD window; adaptive reply window and initial-window bound against the SYN fake wire; per-target windows against a delayed-reply fake wire (a fast target does not shorten a slow one's window; an answer after a retransmit is accepted and lengthens the estimate); one gateway MAC lookup for many routed targets, with errors leading to fallback; TCP traceroute against a fake routed path (waves, stop at target, RST of SYN-ACKs, rate gate, reply matching); UDP and ICMPv6 hop-reply parsing; UDP trace ports and TCP trace port exclusions (OT and printer); trace plan fallbacks; wave runner; serde defaults of the new settings; the module-visibility guard.
- **Live on Windows (this machine, not administrator):**
  - `GetBestRoute` + `GetIpAddrTable`: the gateway for 8.8.8.8 matches `Find-NetRoute`, the same answer comes back with the source address given, a loopback source address is refused (interface mismatch), and loopback is on-link.
  - ICMPv6 hop-limit trace to `::1` (`Icmp6SendEcho2` with options).
  - UDP traceroute without privileges returns the clear "raw ICMP socket" error.
- **PE subsystem check:** both binaries were built with the GUI attribute forced on. `network-scope.exe` had subsystem 2 (GUI) and `network-scope-cli.exe` had subsystem 3 (console), and the CLI build produced no `unused_attributes` warning.

## Untested (cannot run here)
- Everything that needs Npcap: the ARP sweep and TCP traceroute on a real capture handle, and SYN to a routed target via the gateway MAC. Npcap is not installed here; only the fake-wire loops ran.
- UDP traceroute with administrator/root rights (raw ICMP socket receive on Windows, including the bind-to-source-address requirement).
- ICMPv6 hop-limit expiry from a real router on Windows. As for IPv4, a hop is taken only from a returned reply structure (count > 0); only the loopback case ran.
- Unix glue, which is not even compiled on this machine:
  - `next_hop` via `/proc/net/route` or `route -n get` (the parsers are unit-tested);
  - `hop6_unix` (raw ICMPv6 with `set_unicast_hops_v6`);
  - `udp_hop` on Linux/macOS.

  CI on Linux/macOS is the first compile.
- `network-scope-cli.exe` in a real `cmd.exe` / PowerShell session (wait and exit code). The subsystem field was checked, but the shell behaviour was not.
- The installer script was edited but not compiled with `iscc`.
