# Scripting

Network Scope runs [Rhai](https://rhai.rs) scripts against every scanned host to add your own identity fields, findings and notes, for example site policies ("Telnet is not allowed").

```sh
network-scope-cli scripts scripts/example.rhai                    # check a script or folder
network-scope-cli scan 192.168.1.0/24 --deep --script scripts/example.rhai
```

`--script` takes a file or a folder of `.rhai` files. In the desktop, set the script path in Settings; **Host details → Test script…** dry-runs it on a copy of one host, and **Apply** adds the result to that host in the window only.

## Host API

A script defines `fn on_host(h)`, which runs after each host is scanned.

| Member | Meaning |
| --- | --- |
| `h.ip`, `h.hostname`, `h.mac`, `h.ttl`, `h.ping` | Address, name, MAC, TTL, ping time |
| `h.open`, `h.udp` | Open TCP ports, answering UDP ports |
| `h.os`, `h.vendor`, `h.device` | OS guess, manufacturer, device type |
| `h.has_port(n)` | Is TCP port `n` open |
| `h.has_service("name")` | Was a service with that name detected |
| `h.service(port)` | Service summary of a port |
| `h.identity("key")` | Any identity field, e.g. `svc.22.product` |
| `h.set("key", "value")` | Add the identity field `script.key` |
| `h.finding("severity", "id", "title", "evidence")` | Add a finding (info, low, medium, high, critical) |
| `h.note("text")` | Add a note to the host |

## Example

From [`scripts/example.rhai`](https://github.com/Sparkz400/network-scope/blob/main/scripts/example.rhai):

```rust
fn on_host(h) {
    if h.has_port(23) {
        h.finding("high", "policy-telnet", "Telnet is not allowed by policy", "port 23 open on " + h.ip);
    }
    if h.has_port(3389) && !h.has_port(443) {
        h.finding("low", "policy-rdp", "RDP exposed without a web front end", "port 3389 open");
    }
    h.set("zone", if h.ip.starts_with("10.") { "internal" } else { "other" });
}
```

## The script library

`scripts/library/` in the repository holds ready-made, read-only scripts. They are also built into the program, so an installed binary has them:

```sh
network-scope-cli scripts list                      # names, what they do, safety notes
network-scope-cli scripts show smbv1-hosts          # print one to copy and edit
network-scope-cli scan 192.168.1.0/24 --services --script library:smbv1-hosts
network-scope-cli scan 192.168.1.0/24 --deep --ot --script library        # all host scripts
```

| Script | What it does |
| --- | --- |
| `smbv1-hosts` | Hosts that accept SMBv1 (needs `--services`) |
| `cert-expiry-report` | Certificates that expired or expire within 60 days; sets `script.cert_days_left` |
| `weak-tls-summary` | One finding per host listing every TLS port with weak protocols or suites |
| `unexpected-admin-ports` | Open Telnet, RDP, VNC, WinRM, Docker API, WinBox or Webmin ports |
| `ot-asset-summary` | Vendor, product and firmware found by read-only OT identification (`--ot`), one line per host |
| `service-baseline` | Open ports outside a baseline list you edit in the script |
| `default-credentials-hint` | Marks devices that are often left with a factory password. It is a hint from the scan result; **it never tries a login** |
| `device-class-tags` | Sets `script.class` (ot, printer, camera, network, server, workstation, other) for grouping |
| `on-alert/log-alerts`, `on-alert/new-service-log` | Alert scripts, see below |

Every script starts with a header comment (`name`, `description`, `safety`, `kind`). The scripts read identity keys the engine writes (`tls.<port>.days_left`, `smb.<port>.smb1`, `<Protocol>.<field>` for OT, `svc.<port>`), so they report only what the scan collected: a script that needs `--services` finds nothing on a scan without it. A test runs every library script against a positive and a clean fixture host.

## Scripts that run on an alert

`monitor --on-alert SCRIPT.rhai` runs `fn on_alert(a)` once for every alert that is raised (after de-duplication, so a persisting condition runs it once, like the alert itself).

```rust
fn on_alert(a) {
    log(`${a.severity} ${a.kind} ${a.host}: ${a.details}`);
    if a.kind == "port-opened" {
        append_file("new-services.log", `${a.timestamp} ${a.details}` + "\n");
    }
}
```

| Member | Meaning |
| --- | --- |
| `a.kind` | Alert kind: `new-device`, `port-opened`, `port-closed`, `new-finding`, `device-missing`, `address-changed`, `rogue-dhcp`, ... |
| `a.severity` | `info`, `low`, `medium`, `high` or `critical` |
| `a.host` | The alert subject (usually the device address) |
| `a.details` | The alert message |
| `a.timestamp` | Unix seconds |
| `log(text)` | Prints `on-alert: text` on stderr (not with `--quiet`); at most 32 lines per alert |
| `append_file(name, text)`, `write_file(name, text)` | Append to or replace a file in `--on-alert-dir` |

The script gets **no network access, no processes and no file access except those two functions**. A file name is a plain name of 1-64 letters, digits, `.`, `_` or `-`: no separators, no `..`, no leading or trailing dot, no drive or stream syntax, no Windows device names (`CON`, `NUL`, `COM1`, ...), and a name that is a link is refused. A call writes at most 64 KB, a file stops growing at 1 MB, and a run makes at most 16 writes. A run is limited to 200,000 operations and 500 ms; `eval` and `sleep` are disabled. A script that fails or hits a limit prints `on-alert script failed: ...` on stderr and monitoring carries on. The alert is delivered to the other sinks (stdout, `--alerts`, webhook, syslog) whatever the script does. Tagging a device from a script is not available: the inventory has no place for tags yet.

`library:log-alerts` and `library:new-service-log` are ready-made examples (`new-service-log` records every `port-opened` alert: the baseline is the previous scan of the same targets).

## Sandbox

- Scripts cannot touch files, the network or processes. `eval`, modules and `sleep()` are disabled.
- Operations, sizes, recursion depth and wall time are bounded: 250 ms per host across all scripts. Scripts that would start after the budget is spent are skipped with a note.
- A failing script adds a note to the host and never stops the scan.
