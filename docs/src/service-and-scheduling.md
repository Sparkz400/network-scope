# Service and scheduling

Three ways to scan on a schedule, from lightest to always-on:

| | Runs when | Needs |
| --- | --- | --- |
| **Scheduled scans in the GUI** | The window is open | Nothing |
| **systemd units** (Linux) | Always, from boot | `network-scope-cli` installed, root to install |
| **Windows service** | Always, from boot | `network-scope-cli.exe`, an administrator prompt to install |

All of them run [`monitor`](monitoring-alerts.md) (or, in the GUI, an ordinary scan) in **Safe Mode**: the unattended paths never lift the safety limits.

## Scheduled scans in the GUI

**Settings → Scheduled scans.** Tick *Scan on a schedule while Network Scope is open*, enter the targets (or *Use main window*), and the interval in minutes (5 to 10,080). Off by default; the setting is saved with the other preferences. The first scan starts one interval after you enable it (or after the program starts with it enabled), then every interval.

- A scheduled scan uses your current settings **but always in Safe Mode**, whatever the Safe Mode checkbox says, and is saved to the inventory like any scan, so *History* and *Compare* show it. It replaces the results on screen, as pressing Start does.
- A scan, a passive capture or an inventory load that is in progress delays the next scheduled scan; scans never overlap.
- The schedule runs only while the window is open (also minimised). Closing it stops it. The settings show the command that keeps `monitor` running without the window.

## Windows service

```powershell
# In an elevated prompt (administrator). Check the command first:
network-scope-cli service install 192.168.1.0/24 --interval 300 --dry-run
network-scope-cli service install 192.168.1.0/24 --interval 300 --learn
sc start NetworkScopeMonitor
network-scope-cli service uninstall
```

`service install TARGETS [monitor options]` takes the same options as `monitor` (checked at install time, so a typo fails there and not inside a stopped service) plus `--service-name NAME` (default `NetworkScopeMonitor`) and `--dry-run`, which only prints the command line the service would get. `--cycles` is refused: a service runs until it is stopped.

- The service runs `"<path>\network-scope-cli.exe" service run ...` with the same arguments. The path is always quoted.
- The inventory is an explicit absolute file: `--db FILE`, else `%ProgramData%\NetworkScope\inventory.sqlite`. The default location of the other commands (`%LOCALAPPDATA%`) belongs to the installing user, not to the service account. To read the service's inventory use `--db` with the same path. File options (`--alerts`, `--on-alert`, `--script`, `--cves`, ...) are stored as absolute paths.
- It starts automatically (delayed), is restarted after a failure (three times, 60 s apart) and runs as `LocalSystem`, which can write to `%ProgramData%` and use the capture driver without further setup. To narrow the account: `sc config NetworkScopeMonitor obj= "NT AUTHORITY\LocalService"` and give that account modify rights on the inventory folder.
- `sc stop` (or a shutdown) ends the loop cleanly: the scan in progress is cancelled and saved as partial, the wait between cycles is cut short. Lifecycle lines and errors go to `service.log` next to the inventory, since a service has no console. Alerts go to the inventory (`alerts`), `--alerts FILE`, the webhook and syslog sinks; nothing is printed on stdout.
- `service run` started from a terminal is refused at once with a pointer to `monitor`; it is the entry point for the Service Control Manager only.

The service code talks to the Service Control Manager through direct system calls (`StartServiceCtrlDispatcherW`, `RegisterServiceCtrlHandlerExW`, `SetServiceStatus`, `CreateServiceW`) and has **not been run as an installed service by the automated tests**; they cover the command-line building, the structure layouts and the refusal outside the manager. Try it on a test machine before relying on it.

## systemd (Linux)

`packaging/systemd/` holds two variants; the [README there](https://github.com/Sparkz400/network-scope/blob/main/packaging/systemd/README.md) has the install steps.

- **`network-scope-monitor.service`**: a long-running process (`monitor --interval 300`), restarted on failure.
- **`network-scope-monitor-once.service` + `.timer`**: one cycle (`monitor --cycles 1`) every 15 minutes, surviving reboots (`Persistent=true`). A persisting alert is not repeated, because the alert history is read from the inventory.

The units run as a dynamic user without capabilities (`CapabilityBoundingSet=` empty), `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp`, `PrivateDevices`, only `AF_INET`/`AF_INET6` sockets, no namespaces, no writable-executable memory and a system-call filter; the inventory is `/var/lib/network-scope/inventory.sqlite`. `CAP_NET_RAW` (ICMP over raw sockets, SYN scans, ARP sweep, capture) is opt-in and described at the end of the service file; without it the scanner uses TCP connect probes. `systemctl stop` sends SIGTERM, which ends the process immediately: a scan in progress is lost, the saved scans and the alert history are not. A test checks that the hardening settings are present and that each `ExecStart` is accepted by the real option parser.
