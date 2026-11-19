# Monitoring and alerts

```sh
network-scope-cli monitor TARGETS [scan options] --interval 300 [--cycles N]
```

`monitor` repeats the scan, stores every run, and compares it with the previous completed scan of the same targets and with all devices ever seen. Alerts go to stdout as JSON lines, to `--alerts FILE`, and to the `alerts` command. See the [CLI reference](cli-reference.md#monitor-options) for all options.

## Alert kinds

| Alert | Severity |
| --- | --- |
| New device | High for OT devices (including a device whose only hint is 2222/tcp), else Medium |
| TCP/UDP port newly opened | High for risky ports |
| Port no longer open | Info (a timeout does not prove a port closed) |
| New finding | Severity of the finding |
| Address change for a known MAC (`address-changed`) | Medium |
| Device not seen (`device-missing`, only with `--report-missing`) | Low |
| Passive capture lost data (`capture-incomplete`) | Low |
| Rogue DHCP server | Critical with `--dhcp-allow`, else High when more than one server answers |

- Only ports probed by both scans are compared, and partial scans never raise change alerts.
- The first run (or `--learn`) records devices without alerting.
- `--min-severity` filters; with `--report-missing` a hint names the alert kinds it hides.

## De-duplication

A condition that persists is alerted once, again after a complete cycle without it, or after `--renotify-hours` (default 24; 0 = only after it resolved). `--no-dedup` alerts every cycle. A restarted monitor does not repeat alerts raised within two intervals before start.

## Rogue DHCP

`--dhcp-allow IP,IP` lists legitimate servers (anything else is critical; without it, more than one server is high). Servers come from:

- DHCPINFORM replies (UDP scan),
- passive OFFER/ACK traffic (`--interface ID --listen-seconds N`; server = option 54 or the IP source),
- `--dhcp-discover`, which broadcasts one DHCPDISCOVER and collects offers. It never sends a REQUEST.

DHCP observations keep the client in `ip`/`mac` and record servers per `dhcp_server.<ip>`. A capture error or the 10,000-observation cap never ends monitoring.

## Alert delivery

Opt-in; nothing is sent unless a sink is configured.

- **Webhook**: `--webhook http(s)://host[:port]/path[,…]` POSTs each alert as JSON (2xx = delivered). The default port is 80 for `http://` and 443 for `https://`; `user:pass@` URLs and other schemes are rejected.
  - **HTTPS** verifies the server certificate against the operating system's certificate store (Windows, macOS, or the system CA bundle on Linux), so public CAs and a corporate CA your administrator installed both work. The host name in the URL must match the certificate (it is also sent as SNI). An IP-literal host works only if the certificate lists that IP address as a subject alternative name. There is no option to skip verification: an untrusted, expired or mismatching certificate fails the delivery with a warning that says why, and no alert is sent. For a receiver with a private CA, install that CA in the system store (on Linux, in the system CA bundle, or point `SSL_CERT_FILE` at it) or use `http://` on a trusted network.
  - Plain `http://` sends the alerts unencrypted; use it only for localhost or a trusted network.
- **Syslog**: `--syslog udp://host[:514]`, `tcp://host[:601]` (RFC 6587 octet counting) or `host[:port]` sends RFC 5424 messages, facility local0, severity critical→crit … info→informational. Control characters become spaces; messages are cut at 2048 bytes.
- Each operation times out after `--alert-timeout` seconds (default 5, 1-60). After the first failure a destination's remaining alerts of that cycle are skipped, at most 30 s per destination per cycle. Failures are printed and never stop the monitor.

Webhook and syslog delivery are tested against loopback test listeners only, **not against real receivers**. For HTTPS this means: the rejection of untrusted and mismatching certificates and the delivery to a server whose CA is added as an extra root are tested; the system-store path with a publicly trusted certificate (for example a hosted chat or incident service) has not been tried.

## Upgrade notes

Routed hosts merged by SMB GUID + NetBIOS name (new in 0.5) keep the device id of the lowest address; an existing monitor database may raise one `new-device` or `device-missing` alert for such hosts after the upgrade.
