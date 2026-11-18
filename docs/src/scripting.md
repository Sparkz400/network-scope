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

## Sandbox

- Scripts cannot touch files, the network or processes. `eval`, modules and `sleep()` are disabled.
- Operations, sizes, recursion depth and wall time are bounded: 250 ms per host across all scripts. Scripts that would start after the budget is spent are skipped with a note.
- A failing script adds a note to the host and never stops the scan.
