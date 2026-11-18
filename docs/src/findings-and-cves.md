# Findings and CVE hints

Findings are derived from what a scan collected, so run it with `--services` (or `--deep`). They work on stored snapshots and never send traffic.

```sh
network-scope-cli findings ID --min-severity low
```

The desktop shows them in the **Findings** window (sortable, filterable by severity and text). Severities: info, low, medium, high, critical.

## Checks

- Certificates: expired, not yet valid, soon expiring, self-signed, weak signature hashes, short RSA keys.
- TLS: SSLv3, TLS 1.0/1.1; RC4/DES/3DES/export/anonymous suites; missing forward secrecy.
- SSH: weak and legacy algorithms (including Terrapin, CVE-2023-48795), SSH protocol 1.
- Cleartext and unauthenticated services: Telnet, FTP, VNC, cleartext mail, unauthenticated Redis/memcached/MQTT, HTTP Basic over plain HTTP, exposed Docker API, public SNMP.
- Windows services: RDP without NLA, SMBv1, unsigned SMB, SMB without encryption, LDAP anonymous bind.
- Industrial ports reachable from the scanner (`ot-reachable`).
- PHP end of life, date-aware (table `PHP_EOL` in `risk.rs`; branches not in the table are never flagged).

## CVE hints

**CVE entries are version-based hints only.** Distributions backport fixes without changing the version string, so confirm with the vendor advisory or an authenticated check. Network Scope is not a vulnerability scanner.

The rules live in [`data/cves.json`](https://github.com/Sparkz400/network-scope/blob/main/data/cves.json) (built in). A user file merges like `probes.json`: `%LOCALAPPDATA%/NetworkScope/cves.json` (or `$XDG_CONFIG_HOME/NetworkScope/cves.json`), or `--cves FILE` on any command. A rule or CPE entry with the same `id` replaces the built-in one.

Rule fields:

| Field | Meaning |
| --- | --- |
| `id` | Rule id |
| `product` | Lower-case substring of the detected product (`svc.<port>.product` or the HTTP Server header name) |
| `exclude` | Optional product substrings the rule does not apply to |
| `min` / `max` | Optional inclusive / exclusive dotted versions with optional `pN` (`8.5p1`) |
| `severity` | info, low, medium, high, critical |
| `cve` | List of `CVE-YYYY-NNNN`; the finding id is `cve-<first cve>` |
| `title` | Finding title |

A broken file stops the command with a message naming the file and rule. A broken user file found at start-up is reported (CLI: stderr, desktop: error line) and the built-in rules are used.

## CPE names

`cpe` entries (`id`, exact lower-case `products`, `template` with `{version}`, `{base}`, `{update}`) produce `svc.<port>.cpe` such as `cpe:2.3:a:openbsd:openssh:7.4:p1:*:*:*:*:*:*`; distribution suffixes are dropped. The CPE vendor/product names were written from memory of the NVD dictionary and **have not been checked against it**; spot-check them before relying on them.

## Contributing rules

New CVE rules are welcome. Keep them version-based, cite the CVE ids, and add a test for the version boundaries. See [CONTRIBUTING.md](https://github.com/Sparkz400/network-scope/blob/main/CONTRIBUTING.md).
