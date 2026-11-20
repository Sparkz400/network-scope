# Architecture

This page describes how Network Scope is put together: the parts, how a scan flows through them, and where the boundaries are. The security argument built on this design is in the [assurance case](assurance-case.md).

## Parts

The repository is a Cargo workspace with two crates.

```text
┌──────────────────────── network-scope (application) ────────────────────────┐
│  src/gui/   desktop app (egui)          src/ui/   CLI, live TUI (ratatui),   │
│                                                   MCP server on stdio        │
└───────────────────────────────┬──────────────────────────────────────────────┘
                                │  calls only the public API
┌───────────────────────────────▼─────── network-scope-core (engine) ──────────┐
│ scope ─▶ plan ─▶ scan (scheduler, rate gate, sendlog) ─▶ probes              │
│                    │   tcp/syn/udp · service/* · tls · jarm · snmp · ot/*    │
│                    ▼                                                         │
│                  Event per host ─▶ risk · devices · identity · score         │
│                                      │                                       │
│   passive: capture · pcapfile ·      ▼                                       │
│   otpassive · passive (receive only) store (SQLite) ─▶ report · diff ·       │
│   import: nmap · csv · netbox · …                     monitor ─▶ notify      │
└──────────────────────────────────────────────────────────────────────────────┘
                 data/  (probes, CVE rules, vendor lists) — embedded at compile time
```

- **`network-scope-core`** (`core/`) is the engine and contains no GUI code. Other programs can use it as a library; its crate documentation lists the entry points.
- **`network-scope`** (root package) is the application. `src/gui/` is the egui desktop app, the cargo feature `gui` (on by default). `src/ui/` holds the CLI, the TUI and the [MCP server](mcp.md); `--no-default-features --bin network-scope-cli` builds them without any GUI crate.
- **`data/`** holds service probes, CVE rules, OUI and vendor lists. The engine embeds these files at compile time, so a release binary never loads probe definitions from somewhere else unless the user passes a probe file explicitly.

## How a scan runs

1. **Targets and scope.** `scan::parse_targets` and `scan::parse_ports` expand the target syntax. `scope::enforce` refuses public addresses, and addresses outside a declared scope, unless the user has confirmed them.
2. **Plan.** `plan::host` lists every packet a host will receive for the chosen options. The dry run prints this list without sending anything.
3. **Scheduler and rate gate.** Every transmitted packet takes a token from the rate gate, retransmissions included, and is recorded in the sent log (`sendlog`). Safe Mode, on by default, adds spacing and turns off everything beyond a single connection or request per port. A test fails if a real scan sends anything the plan does not list.
4. **Probes.** These include host discovery (ARP, ICMP, TCP), port scans (connect, SYN, UDP), service detection (`service/`, `probes`), and TLS, SSH, SMB, RDP and SNMP inspection. Industrial identification (`ot/`) builds requests only from the allow-listed read-only types in `ot::readonly`. Generic probes never send to OT or printer ports.
5. **Results.** Each host produces one `scan::Event`. `risk` turns it into findings, `devices` and `identity` merge active and passive observations into one record per device, and `score` ranks hosts.
6. **Store.** `store` saves snapshots to an SQLite inventory. `report` (HTML, Markdown, CSV, JSON), `store::diff_report`, and `monitor` with `notify` (webhooks, syslog) work from the stored snapshots.

The passive modes only receive. `pcapfile`, `otpassive` and the `PassiveCapture` wrapper in `capture` contain no send code, and the test `this_module_cannot_transmit` enforces that. The `passive` listener is receive-only by convention. Imports (`nmap`, `import/`) convert other tools' files into the same snapshot type.

## Extension points

- **Probe files**: JSON in the format of `data/probes.json`, checked by `probes lint` and `probes validate`.
- **Rhai scripts** (`script`): run per host in a sandbox with limits on operations, call depth, string size and array size. Scripts have no file, network or process access.
- **Alert scripts and webhooks** (`alertscript`, `notify`): run on monitor alerts.
- **Library use** of `network-scope-core`.

## Platforms

The same code builds for Windows, Linux and macOS. Platform-specific code sits mainly in `platform`, `capture` (Npcap or libpcap, loaded at run time), `ipv6` and `interfaces`. The project's `unsafe` blocks are used for two things only:

- **Operating-system and capture-library calls.** Most are in `platform`, `capture` and `ipv6`. A few Windows API calls are elsewhere: socket ioctls in `probes`, the user locale in the GUI, service control, and attaching to the console.
- **Setting environment variables in tests.** Recent Rust editions require `unsafe` for this.

## Where to read more

- [Scanning engine](scanning-engine.md): timing, retries and the rate gate in detail.
- [Detection](detection.md) and [Findings and CVE hints](findings-and-cves.md).
- [Safe Mode and OT safety](safe-mode-and-ot-safety.md).
- [Supply chain](supply-chain.md): how releases are built and verified.
