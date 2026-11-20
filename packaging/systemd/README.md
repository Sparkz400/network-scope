# systemd units for `monitor`

Two ways to run [`monitor`](../../docs/src/monitoring-alerts.md) unattended on Linux. Pick one.

| Files | Use when |
| --- | --- |
| `network-scope-monitor.service` | A process that keeps running, scans every `--interval` seconds and restarts on failure. |
| `network-scope-monitor-once.service` + `.timer` | A scan every N minutes is enough; each run is one cycle (`--cycles 1`) and the timer survives reboots (`Persistent=true`). |

Install (as root; edit the `ExecStart` line first: targets, interval and options):

```sh
install -m 0755 network-scope-cli /usr/local/bin/network-scope-cli
install -m 0644 packaging/systemd/network-scope-monitor.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now network-scope-monitor.service
journalctl -u network-scope-monitor -f
# or the timer variant:
install -m 0644 packaging/systemd/network-scope-monitor-once.* /etc/systemd/system/
systemctl enable --now network-scope-monitor-once.timer
```

The inventory is `/var/lib/network-scope/inventory.sqlite` (read it with `--db` from a root shell: `network-scope-cli history --db ...`). The units run as a dynamic user with no capabilities, a read-only file system except that folder, and only IPv4/IPv6 sockets; raw features are opt-in (see the end of the service file). Safe Mode stays on. A `systemctl stop` sends SIGTERM, which ends the process at once: a scan in progress is lost, the saved scans and alert history are not (SQLite WAL).

Full documentation: [docs/src/service-and-scheduling.md](../../docs/src/service-and-scheduling.md).
