# Assurance case

This page explains why Network Scope's security requirements are met. It covers what the requirements are, what the program has to defend against (the threat model), where untrusted data comes in (the trust boundaries), how the design applies secure design principles, and how common implementation weaknesses are countered. It also lists what is *not* covered. The design it relies on is described in [Architecture](architecture.md).

## Security requirements

What users can expect, in short. The details and the scope of vulnerability reports are in [SECURITY.md](https://github.com/Sparkz400/network-scope/blob/main/SECURITY.md#scope).

1. **Hostile replies cannot take over the scanner.** Network devices, capture files and imported files may be malicious. They must not cause code execution, and must not cause crashes, hangs or unbounded memory use.
2. **The scanner sends only what it documents.** It does not write to or control OT devices, does not send to printer ports, sends nothing in passive modes, and limits traffic in Safe Mode.
3. **Scope.** Without confirmation, it does not scan public addresses or addresses outside a declared scope.
4. **Outputs are safe to open.** HTML, CSV, Markdown and JSON exports cannot inject script, spreadsheet formulas or broken structure.
5. **Scripts stay in their sandbox.** User scripts get no access to files, the network or processes, and stay within time and operation limits.
6. **Secrets stay local.** There is no telemetry. Webhook credentials, SNMP credentials and the inventory are stored only where the user puts them. TLS connections the program makes itself are verified.
7. **Releases are what they claim to be.** Every release file is built by CI from the tagged commit and comes with signed provenance.

## Threat model

| Actor | Can | Wants |
| --- | --- | --- |
| Malicious or compromised device on the scanned network | Answer probes with arbitrary bytes, slowly, or endlessly | Crash or hang the scanner, run code on the analyst's machine, hide from the inventory |
| Author of a capture, nmap XML, CSV or NetBox file | Craft any file content | The same, through import |
| Author of a report viewer's input | Put strings in banners, hostnames or certificate fields | Script or formula injection when the analyst opens a report |
| Careless or rushed user | Mistype a target, scan the wrong network, run against fragile OT | Not malicious, but can cause outages; the tool must make the safe path the default |
| Script author (user or shared script) | Run Rhai code | Escape the sandbox |
| Attacker on the path to a webhook or update server | Intercept TLS | Read alert contents or credentials, fake an update notice |
| Supply-chain attacker | Compromise a dependency or the build | Ship malicious code in a release |

Out of scope: an attacker who already controls the local user account or the inventory database file. Sending probes to the targets the user specified is also out of scope, because that is the tool's purpose.

## Trust boundaries

```text
 untrusted                         │ trusted
 ──────────────────────────────────┼───────────────────────────────────────
 network replies (all protocols)   │
 capture / import files            │  network-scope-core parsers ─▶ typed
 banners, certs, hostnames         │  values (bounded, never panic)
 Rhai scripts                      │  sandboxed engine with limits
 webhook / update endpoints        │  TLS with platform certificate store
 ──────────────────────────────────┼───────────────────────────────────────
                                   │  user's command line and settings,
                                   │  the inventory file, data/ (compiled in)
```

Data crosses the boundary in only a few places: the parsers, the import functions, the script engine and the TLS clients. Everything past them is typed Rust data.

## Secure design principles applied

- **Safe defaults (fail-safe defaults).** Safe Mode is on by default. Transmitting features are opt-in. Scope enforcement refuses public addresses unless the user confirms. Update checks are off by default and never download anything.
- **Least privilege.** Raw sockets and capture are needed only for the features that use them. The CLI runs unprivileged otherwise, and the container image runs as a non-root user. CI workflows use read-only tokens with per-job grants.
- **Complete mediation.** Every transmitted packet passes the rate gate and the sent log. Tests fail if a sender bypasses the gate or sends something the plan does not list.
- **Economy of mechanism and allow-lists.** OT requests can only be built from allow-listed read-only types (`ot::readonly`), so a write or control request cannot be expressed in the code. Printer and OT ports are on one deny list shared by all generic probes.
- **Separation.** Passive modules contain no send code, and a test checks this. The engine has no GUI dependency, and the scripting engine is separated from file, network and process APIs.
- **Open design.** All code, probes and rules are public. Verification of releases needs no secret.
- **Psychological acceptability.** The dry run shows exactly what would be sent, so users can check before scanning OT networks.

## Common weaknesses countered

| Weakness (CWE) | Countermeasure | Evidence |
| --- | --- | --- |
| Memory-safety bugs (CWE-119, -416, -787) | Written in Rust. `unsafe` is limited to OS and FFI calls in a few platform modules. | [Architecture: Platforms](architecture.md#platforms) |
| Panics and crashes on malformed input (CWE-20, -248) | Parsers bound lengths, counts and recursion and return errors. | 55 fuzz targets run in CI (ClusterFuzzLite) with a committed seed corpus; tests with truncated and oversized input |
| Resource exhaustion (CWE-400, -770) | Read limits and timeouts on every reply. Bounded in-flight probes. Script operation limits. | Unit tests; `lab/` scenarios `slow-wan` and `lossy` |
| Cross-site scripting in reports (CWE-79) | HTML escaping, plus a Content-Security-Policy of `default-src 'none'` in every report. | Tests in `core/src/report.rs` |
| CSV formula injection (CWE-1236) | Cells that start like a formula are neutralised. | `csv_cells_cannot_start_formulas` |
| Improper certificate validation (CWE-295) | rustls with the operating system's certificate store for webhooks and update checks. TLS 1.2 or later only. | `core/src/notify.rs`, `core/src/update.rs` |
| Sandbox escape (CWE-693) | The Rhai engine has no file, network or process modules and is limited in operations, call depth, string size and array size. | `core/src/script.rs` tests |
| Unintended transmissions, an OT safety issue (CWE-691) | Rate gate, plan and sent-log checks, read-only OT types, passive modules without send code. | Tests named in [CONTRIBUTING](https://github.com/Sparkz400/network-scope/blob/main/CONTRIBUTING.md#safety-rules-for-new-probes-and-features) |
| Vulnerable dependencies (CWE-1395) | `cargo deny` and `cargo audit` on every change. Dependabot. Locked builds. | `security` workflow |
| Supply-chain tampering in the build (CWE-494) | Actions pinned by commit hash. Least-privilege tokens. Signed provenance and SBOM for every release. Reproducible-build check. | `release.yml`, `reproducible.yml`, [Supply chain](supply-chain.md) |
| Leaked secrets in the repository (CWE-798) | gitleaks scan of the full history on every push. | `secrets` workflow |

Static analysis runs on every change: `cargo clippy` with warnings as errors, and CodeQL for Rust and for the workflows. Line coverage of the test suite is measured in CI (`coverage` job) and was 86% for the whole workspace in November 2026.

## Residual risks and limits

- **Release binaries are not code-signed** by an operating-system vendor certificate. Provenance and checksums are the verification path; see [Installation](installation.md#verifying-downloads-and-the-image).
- **Real-device coverage.** Many OT decoders are tested against simulators and sanitized captures, not against every device family. The protocol pages say what was tested.
- **Single maintainer.** Reviews are not yet done by a second person; see [GOVERNANCE.md](https://github.com/Sparkz400/network-scope/blob/main/GOVERNANCE.md#continuity).
- **Privileged features.** SYN scans, ARP sweeps and capture need raw-socket rights. A bug in those paths runs with those rights.
