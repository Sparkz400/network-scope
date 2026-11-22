# Security policy

## Supported versions

Only the latest release receives security fixes.

| Version | Supported |
| --- | --- |
| 0.5.x | Yes |
| < 0.5 | No |

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through GitHub's private vulnerability reporting:
<https://github.com/Sparkz400/network-scope/security/advisories/new>

Include, where possible:

- the Network Scope version and operating system,
- the command or GUI action, and the scan options (Safe Mode on/off),
- a minimal reproducer: for parser bugs a small, sanitized pcap or the raw reply bytes,
- the impact you observed (crash, hang, memory growth, wrong output, code execution).

Remove real IP addresses, MAC addresses, host names and credentials from anything you send.

## What to expect

This is a volunteer-maintained project. As a guideline:

- acknowledgement within 7 days,
- an initial assessment within 14 days,
- a fix or mitigation for confirmed issues as soon as practical, coordinated with you before public disclosure.

You will be credited in the advisory and the changelog unless you prefer otherwise.

## Verifying releases

Release files and the container image are built by GitHub Actions from the tagged commit
(`.github/workflows/release.yml`) and carry signed provenance. The binaries are not code-signed.

- **Checksums**: `SHA256SUMS` lists the SHA-256 of every release file.
- **GitHub artifact attestation** (Sigstore-signed SLSA build provenance) for each release file,
  also attached as `network-scope-<version>.sigstore.json` for offline use:

  ```sh
  gh attestation verify network-scope-0.6.0-linux-x86_64.tar.gz --repo Sparkz400/network-scope
  gh attestation verify network-scope-0.6.0-linux-x86_64.tar.gz --repo Sparkz400/network-scope \
    --bundle network-scope-0.6.0.sigstore.json
  ```

- **`network-scope-<version>.intoto.jsonl`** is the same provenance bundle under the in-toto
  file name and verifies the same way (`--bundle network-scope-<version>.intoto.jsonl`).
  Release v0.5.1 attached SLSA level 3 provenance from
  [slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator) under this
  name instead; verify that file with
  [slsa-verifier](https://github.com/slsa-framework/slsa-verifier):

  ```sh
  slsa-verifier verify-artifact network-scope-0.5.1-linux-x86_64.tar.gz \
    --provenance-path network-scope-0.5.1.intoto.jsonl \
    --source-uri github.com/Sparkz400/network-scope --source-tag v0.5.1
  ```

- **Container image** `ghcr.io/sparkz400/network-scope`: build provenance attestation stored in
  the registry next to the image (plus BuildKit provenance and SBOM attestations):

  ```sh
  gh attestation verify oci://ghcr.io/sparkz400/network-scope:0.6.0 --owner Sparkz400
  ```

## Scope

In scope, for example:

- Crashes, panics, hangs, unbounded memory or CPU use caused by **malicious or malformed network replies, packets or capture files** (service banners, TLS, SMB, OT protocol replies, pcap/pcapng files, nmap XML imports).
- Injection into exports: HTML report escaping or Content-Security-Policy bypasses, CSV formula injection, Markdown or JSON output that breaks its format.
- Escaping the Rhai script sandbox (file, network or process access; exceeding the time or operation limits).
- Network Scope sending traffic it documents it will not send: anything other than read-only identification to OT devices, anything to printer ports, transmissions from passive modes, SYN/ARP sweep/TCP/UDP traceroute in Safe Mode.
- DLL or library search-path issues when loading Npcap/libpcap.
- Unsafe handling of webhook or syslog destinations (for example credentials leaking).

Not in scope:

- "It scans networks." Sending probes to the targets you specify is the purpose of the tool.
- Findings that are false positives or false negatives (please open a normal issue).
- Vulnerabilities in third-party dependencies that do not affect Network Scope; please report those upstream. If a dependency issue does affect Network Scope, report it here.
- Issues that require an attacker who already controls the local user account or the inventory database file.
- Missing code signing of release binaries (known; see the documentation).
