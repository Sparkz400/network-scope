# Monitoring and alerts

```sh
network-scope-cli monitor TARGETS [scan options] --interval 300 [--cycles N]
```

`monitor` repeats the scan, stores every run, and compares it with the previous completed scan of the same targets and with all devices ever seen. Alerts go to stdout as JSON lines, to `--alerts FILE`, and to the `alerts` command. See the [CLI reference](cli-reference.md#monitor-options) for all options.

## Alert kinds

| Alert | Severity |
| --- | --- |
| New device | High for OT devices (including a device whose only hint is 2222/tcp), else Medium. A device is recognised across address and randomised-MAC changes, see [Device identity](device-identity.md) |
| TCP/UDP port newly opened | High for risky ports |
| Port no longer open | Info (a timeout does not prove a port closed) |
| New finding | Severity of the finding (not for a finding an imported vendor statement clears, see [VEX](findings-and-cves.md#vendor-statements-vex-offline)) |
| Device not on the approved baseline (`unknown-device`, only once a [baseline](inventory-diff-reports.md#approved-baseline) exists; the subject is the device key) | Medium |
| Address change for a known MAC (`address-changed`) | Medium |
| Device not seen (`device-missing`, only with `--report-missing`) | Low |
| Passive capture lost data (`capture-incomplete`) | Low |
| A cycle failed (`monitor-cycle-failed`: the inventory was locked, an adapter was down, ...) | Medium |
| Rogue DHCP server | Critical with `--dhcp-allow`, else High when more than one server answers |

- Only ports probed by both scans are compared, and partial scans never raise change alerts.
- The first run (or `--learn`) records devices without alerting.
- `--min-severity` filters; with `--report-missing` a hint names the alert kinds it hides.

## A cycle that fails

A cycle that fails (the inventory is locked by another program for longer than 30 seconds, the adapter is down after standby, a file is briefly unreadable) does not end the monitor: the error is printed (also with `--quiet`), raised as a `monitor-cycle-failed` alert and the next cycle runs after the interval. Nothing is lost by it: a scan is only saved once everything the comparison needs was read, so the next cycle compares with the same previous scan. After five failed cycles in a row the monitor gives up with an error; the systemd unit and the Windows service restart it then. A run with `--cycles N` in which a cycle failed exits with status 1.

`--keep N` deletes all but the newest N scans of the monitored targets after every cycle, see [Deleting old scans](inventory-diff-reports.md#deleting-old-scans). Without it the inventory grows by one scan per cycle.

## De-duplication

A condition that persists is alerted once, again after a complete cycle without it, or after `--renotify-hours` (default 24; 0 = only after it resolved). `--no-dedup` alerts every cycle. A restarted monitor restores this state from the alerts it stored: a condition it raised before the restart is not repeated while it persists, and the `--renotify-hours` timer continues from the original alert (with 0, any stored alert counts, however old). Only alerts of scans of the same targets count, so several monitors with different targets can share one database without suppressing each other's alerts (two monitors with the identical targets text share their history). One limit remains: a condition that resolved and came back during the downtime, or in the first cycle after the restart, cannot be told from one that persisted, and is not raised until it has resolved once more or the renotify time has passed.

## Rogue DHCP

`--dhcp-allow IP,IP` lists legitimate servers (anything else is critical; without it, more than one server is high). Servers come from:

- DHCPINFORM replies (UDP scan),
- passive OFFER/ACK traffic (`--interface ID --listen-seconds N`; server = option 54 or the IP source),
- `--dhcp-discover`, which broadcasts one DHCPDISCOVER and collects offers. It never sends a REQUEST.

DHCP observations keep the client in `ip`/`mac` and record servers per `dhcp_server.<ip>`. A capture error or the 10,000-observation cap never ends monitoring.

## Alert delivery

Opt-in; nothing is sent unless a sink is configured.

- **Webhook**: `--webhook http(s)://host[:port]/path[,…]` POSTs each alert as JSON (2xx = delivered). The default port is 80 for `http://` and 443 for `https://`; `user:pass@` URLs and other schemes are rejected.
  - **Secret URLs**: chat webhooks (Slack, Teams, Discord) carry their secret in the path. `--webhook-env NAME` reads one webhook URL from the environment variable `NAME` instead, so it is not on the command line, in the process list or in a service's configuration; an unset or invalid variable stops the monitor at start-up with a message that names the variable, never its value. Delivery warnings name a webhook by scheme, host and port only. `service install` refuses a `--webhook` URL with a path or query.
  - **HTTPS** verifies the server certificate against the operating system's certificate store (Windows, macOS, or the system CA bundle on Linux), so public CAs and a corporate CA your administrator installed both work. The host name in the URL must match the certificate (it is also sent as SNI). An IP-literal host works only if the certificate lists that IP address as a subject alternative name. There is no option to skip verification: an untrusted, expired or mismatching certificate fails the delivery with a warning that says why, and no alert is sent. For a receiver with a private CA, install that CA in the system store (on Linux, in the system CA bundle, or point `SSL_CERT_FILE` at it) or use `http://` on a trusted network.
  - Plain `http://` sends the alerts unencrypted; use it only for localhost or a trusted network.
- **Syslog**: `--syslog udp://host[:514]`, `tcp://host[:601]` (RFC 6587 octet counting) or `host[:port]` sends RFC 5424 messages, facility local0, severity critical→crit … info→informational. Control characters become spaces; messages are cut at 2048 bytes.
- Each operation times out after `--alert-timeout` seconds (default 5, 1-60). After the first failure a destination's remaining alerts of that cycle are not tried, at most 30 s per destination per cycle. Failures are printed and never stop the monitor. What a destination did not take is kept (up to 1,000 alerts per destination, the oldest are dropped beyond that) and sent first with the next cycle, in order, so a receiver that was down for a while gets every alert once it is back; a syslog destination that failed in the middle of a batch gets that batch again. The queue is also written to the inventory, per monitor (its targets) and per destination (a hash of it, not the URL), so a monitor that is restarted sends what the last run could not deliver; a write that fails (a locked inventory) is tried again with the next cycle and the alerts stay queued in memory. A monitor that is killed between sending and writing sends those alerts a second time, and alerts for a destination that is no longer configured are dropped at the start.
- Feed data imported while the monitor runs (`feeds import`, also SBOM and VEX) is used from the next cycle: each cache file is checked at the start of a cycle and read again when it changed. A cache that is missing or damaged at that moment keeps the data already loaded.

The unit tests deliver to loopback test listeners. The CI job `alert-receivers` (`lab/alert_receivers.sh`) also delivers to **real receivers** on loopback: `monitor` runs two cycles, a port opens in between, and the resulting alert must reach **rsyslog** over UDP and over TCP with octet counting (rsyslog's own parser must find facility local0, the mapped severity, app-name `network-scope` and the alert kind as MSGID) and **nginx** over HTTP and over HTTPS with a certificate from a private CA given through `SSL_CERT_FILE` (the body nginx received must be the alert line exactly). A second HTTPS nginx server with an ordinary certificate that no trusted CA issued must receive nothing, and `monitor` must report the failed delivery as an unknown issuer. The job passes on `ubuntu-latest` (rsyslog 8.2512.0, nginx 1.28.3). Still not tried: a publicly trusted certificate through the system store (a hosted chat or incident service) and receivers on another machine.

## Upgrade notes

Routed hosts merged by SMB GUID + NetBIOS name (new in 0.5) keep the device id of the lowest address; an existing monitor database may raise one `new-device` or `device-missing` alert for such hosts after the upgrade.
