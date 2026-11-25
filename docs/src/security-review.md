# Security review

This page records the security reviews of Network Scope: what was reviewed, how, what was found and what was done about it. It checks the code against the [assurance case](assurance-case.md): its security requirements, threat model and trust boundaries.

## November 2026

**Date and scope.** 2026-11-25, the `main` branch after 0.6.0 (commit `2b26d8c` plus the license headers), all Rust code in `core/` and `src/`, the Windows service, the CI and release workflows.

**Method.**

- **Three code reviews, one per trust boundary**, each against the requirements of the assurance case. They were done with AI assistance (Claude Code agents reading the code), and the findings were checked by hand against the source before anything was fixed:
  1. untrusted network replies and captured traffic: protocol parsers, capture, and how device text reaches the inventory, exports and the terminal;
  2. local inputs and interfaces: imports, scripts, the MCP server, the scope file, the Windows service, file paths;
  3. what the program sends and stores: webhooks, syslog, the update check, secrets, privileges, the OT and printer safety rules, the CI and release pipeline.
- Where a finding depended on the system, it was measured on Windows 11: memory use of a crafted import, and the access lists of `C:\ProgramData`, `C:\` and the service registry key (`icacls`, `sc sdshow`, `Get-Acl`).
- **Tools** that run on every change and were part of the review: clippy with warnings as errors, CodeQL, `cargo deny` and `cargo audit`, gitleaks, and fuzzing of every parser of untrusted input (ClusterFuzzLite).
- **Human review.** The maintainer read the findings, the fixes and this page. *Approval: pending.*

### Findings

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | A device that sent its reply one byte at a time could hold a port for up to an hour during service detection (and longer for SSH), so a scan or a monitor cycle never ended. Requirement 1. | Medium | Fixed: one deadline for a whole read. |
| 2 | Some text from devices (NTP reference ID, NetBIOS names, the DHCP domain, certificate names, OPC UA strings) kept control characters, so a device could put terminal escape sequences into `diff --format text` or CSV on the terminal. Requirement 4. | Medium | Fixed: control characters removed and the length capped at the source. |
| 3 | A small crafted nmap XML file could use gigabytes of memory on import by repeating a reference to a large XML entity (66 KB measured at 509 MB). Requirement 1. | Medium | Fixed: files that define XML entities are refused; nmap never writes them. |
| 4 | The Windows service runs as LocalSystem, but its folder `%ProgramData%\NetworkScope` inherited write access for all users. Another local user could read the inventory, pre-create the folder, or replace the alert-script folder with a junction so that the service wrote files elsewhere. | Medium | Fixed: the folder gets SYSTEM and Administrators only, is locked before it is checked, and links or foreign owners are refused; alert scripts refuse a folder that is a link. |
| 5 | The service registered the running program wherever it was, for example a portable copy in a folder every user may change, and the same for the files it reads (`--script`, `--on-alert`, `--probes`, `--scope-file`). Another local user could replace them and run code as LocalSystem. | Low to medium | Fixed: `service install` refuses program and files that are not on a local disk or that accounts other than SYSTEM, Administrators and TrustedInstaller may change, along the whole path. |
| 6 | Webhook URLs (whose path is the secret for Slack, Teams or Discord) were copied into the service's command line, which every local user can read, and printed in delivery errors. Requirement 6. | Low | Fixed: `--webhook-env NAME`; `service install` refuses a literal webhook URL with a path; messages show only scheme, host and port. |

Every fix has a regression test, listed in the change that fixed it.

### Checked and found sound

- **Exports.** The HTML report escapes every device field and has a `default-src 'none'` content security policy; Markdown and CSV escaping (including the spreadsheet formula prefix) cover every producer; JSON goes through serde.
- **Inventory.** All SQL values are bound parameters; the research query interface is read-only.
- **Parsers.** Length fields are checked before allocation; capture, reassembly, SNMP walks, OPC UA chunks and imports have size and count caps; the pure parsers are fuzzed.
- **Scripts** (rhai): no `eval`, no modules, limits on operations, time, call depth and sizes; file names are checked.
- **MCP server.** stdio only, no client-supplied paths, Safe Mode forced, private addresses only, scope guard without consent flags, read-only inventory access for queries.
- **Scope and safety.** Every command and desktop action that sends traffic goes through the scope guard; OT and printer ports are excluded from generic and UDP probes and from TCP traceroute, as [Safe Mode and OT safety](safe-mode-and-ot-safety.md) describes.
- **Outbound TLS** (webhooks, update check): rustls with the operating system's certificate verifier, no insecure fallback, no redirects followed, capped reads and timeouts.
- **Secrets.** SNMP credentials are saved as environment variable names only and never echoed.
- **Launching programs** (browser, SSH, RDP, ping): argument arrays, no shell, host names validated.
- **CI and releases.** Actions pinned by commit, read-only default permissions, no `pull_request_target`, no untrusted `${{ }}` values in `run:` steps, no caches in the release workflow.

### Residual risks

- The service's access checks were tested on folders the tests create, not by installing a real service with administrator rights.
- `--webhook-env` keeps a webhook secret out of the command line and messages, but a Windows service's environment is stored in its registry key, which local users can read.
- Files inside a `--script` folder are not checked one by one (the folder and its parents are), and `--alerts`, `--on-alert-dir`, `--cves` and `--feeds` are not checked for other writers.
- Short windows remain between the checks and the use of a file (alert-script folder, program file before the service starts).
- The general limits in the [assurance case](assurance-case.md#residual-risks-and-limits) still apply.

The next review is due with the next minor release, or within a year.
