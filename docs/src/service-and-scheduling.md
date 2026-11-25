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
- Scheduled scans go through the same [scope guard](safe-mode-and-ot-safety.md) as the Start button, but nobody is there to confirm: public or out-of-scope targets are refused (the reason is shown as the error) instead of asking.
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
- The service runs as SYSTEM what it is given, so `service install` checks the program and every `--script`, `--on-alert`, `--probes` or `--scope-file` file. It refuses when an account other than SYSTEM, Administrators or TrustedInstaller owns or may change the file or the folder it is in, when a link (symlink or junction) sits anywhere on its path, or when another account owns a folder further up or may rename or replace what is in it (creating folders, as every user may in `C:\`, is fine). Install the service from an all-users install (`C:\Program Files\Network Scope`; a per-user install lives in the installing user's profile and is refused) or copy the portable program and those files to a folder only administrators can change; a new folder in the root of a drive (`C:\Tools`) inherits write access for every user.
- The [scope guard](safe-mode-and-ot-safety.md) applies: a service has nobody to ask, so `service install` refuses public or out-of-scope targets unless `--yes-public` / `--allow-out-of-scope` is given (the flags are passed on to the service; without them `service run` stops with the refusal in `service.log`). A scope file in the default place is passed on as `--scope-file` with its absolute path, because the service account has its own config folder; use `--scope CIDR` or `--scope-file FILE` to name one explicitly.
- The inventory is an explicit absolute file: `--db FILE`, else `%ProgramData%\NetworkScope\inventory.sqlite`. The default location of the other commands (`%LOCALAPPDATA%`) belongs to the installing user, not to the service account. To read the service's inventory use `--db` with the same path from an elevated prompt. File options (`--alerts`, `--on-alert`, `--script`, `--cves`, ...) are stored as absolute paths.
- It starts automatically (delayed), is restarted after a failure (three times, 60 s apart) and runs as `LocalSystem`, which can write to `%ProgramData%` and use the capture driver without further setup. To narrow the account: `sc config NetworkScopeMonitor obj= "NT AUTHORITY\LocalService"` and give that account modify rights on the inventory folder.
- The inventory folder is the service's alone: `service install` creates `%ProgramData%\NetworkScope` with access for SYSTEM and Administrators only (not inherited from `%ProgramData%`, where every user may create files), and gives an existing one that access. Other users cannot read or change the inventory, `service.log` or `alert-scripts`. Install refuses a folder that holds a link (symlink or junction) or anything owned by an account other than SYSTEM, LocalService, NetworkService or Administrators. A folder named with `--db` keeps its access but is refused when every user may write to it.
- `sc stop` (or a shutdown) ends the loop cleanly: the scan in progress is cancelled and saved as partial, the wait between cycles is cut short. Lifecycle lines and errors go to `service.log` next to the inventory, since a service has no console. Alerts go to the inventory (`alerts`), `--alerts FILE`, the webhook and syslog sinks; nothing is printed on stdout.
- `service run` started from a terminal is refused at once with a pointer to `monitor`; it is the entry point for the Service Control Manager only.

The service code talks to the Service Control Manager through direct system calls (`StartServiceCtrlDispatcherW`, `RegisterServiceCtrlHandlerExW`, `SetServiceStatus`, `CreateServiceW`) and has **not been run as an installed service by the automated tests**; they cover the command-line building, the structure layouts and the refusal outside the manager. Try it on a test machine before relying on it.

## systemd (Linux)

`packaging/systemd/` holds two variants; the [README there](https://github.com/Sparkz400/network-scope/blob/main/packaging/systemd/README.md) has the install steps.

- **`network-scope-monitor.service`**: a long-running process (`monitor --interval 300`), restarted on failure.
- **`network-scope-monitor-once.service` + `.timer`**: one cycle (`monitor --cycles 1`) every 15 minutes, surviving reboots (`Persistent=true`). A persisting alert is not repeated, because the alert history is read from the inventory.

The units run as a dynamic user without capabilities (`CapabilityBoundingSet=` empty), `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp`, `PrivateDevices`, only `AF_INET`/`AF_INET6` sockets, no namespaces, no writable-executable memory and a system-call filter; the inventory is `/var/lib/network-scope/inventory.sqlite`. `CAP_NET_RAW` (ICMP over raw sockets, SYN scans, ARP sweep, capture) is opt-in and described at the end of the service file; without it the ICMP ping may fail (noted on the host) and the TCP connect probes decide whether a host is up. `systemctl stop` sends SIGTERM, which ends the process immediately: a scan in progress is lost, the saved scans and the alert history are not. A test checks that the hardening settings are present and that each `ExecStart` is accepted by the real option parser. The units have **not been loaded by systemd** in the automated tests or on the machine they were written on; run `systemd-analyze verify` and `systemd-analyze security network-scope-monitor.service` before relying on them.
