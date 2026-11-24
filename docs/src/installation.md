# Installation

## Windows

Download from the [latest GitHub release](https://github.com/Sparkz400/network-scope/releases/latest):

| File | What it is |
| --- | --- |
| `NetworkScope-<version>-setup.exe` | Inno Setup installer |
| `network-scope-<version>-windows-x64.zip` | Portable binaries |
| `SHA256SUMS` | SHA-256 checksums of all release files |

Verify a download in PowerShell:

```powershell
Get-FileHash .\network-scope-0.6.0-windows-x64.zip -Algorithm SHA256
```

and compare the hash with the line in `SHA256SUMS`.

### Installer

The installer installs per user by default (no administrator rights needed; the setup dialog lets you choose an all-users install). Optional tasks: a desktop shortcut and adding the install folder to your user `PATH` so `network-scope-cli` works from any shell. It installs `network-scope.exe`, `network-scope-cli.exe`, the README, third-party notices, the example scripts and the lab files.

The installer and binaries are **not code-signed** yet, so Windows SmartScreen will warn: the release workflow signs them once the maintainer has set up a signing account ([Code signing](supply-chain.md#code-signing)); the project is applying for free signing by SignPath Foundation ([code signing policy](code-signing-policy.md)). CI compiles the installer on every change and installs it silently, runs both installed binaries and uninstalls it again (`scripts/installer_smoke.ps1`); release builds run the same test.

### Portable

Unzip anywhere and run `network-scope.exe` (GUI) or `network-scope-cli.exe` (CLI).

### Two executables

- `network-scope-cli.exe` is a **console-subsystem** build: `cmd.exe` and PowerShell wait for it, and `%ERRORLEVEL%` / `$LASTEXITCODE` reflect the run (1 on error). Use it for scripting.
- `network-scope.exe` is a **GUI-subsystem** program for double-click use. Started from a shell with arguments it attaches to the console and runs the command, but the shell does not wait for it and its exit code is not seen (workaround: `Start-Process -Wait -NoNewWindow` or `| Out-Host`). Redirected stdout/stderr stay redirected.

Without arguments both binaries open the desktop. On Linux and macOS both binaries are built and behave identically.

Preferences and the default SQLite database live in `%LOCALAPPDATA%\NetworkScope`.

## Privileges

Most features need no administrator rights and no driver: TCP connect scanning, service, TLS and SMB detection, ICMP and ARP lookups through Windows APIs, UDP probes, inventory, reports, monitoring and pcap file analysis.

| Feature | Needs |
| --- | --- |
| SYN scan (`--fast --syn`) | Npcap/libpcap, capture rights, `--interface`, `--source-ip`, `--source-mac` |
| ARP sweep (`--fast --arp-sweep`) | Npcap/libpcap, capture rights, interface and source addresses |
| TCP traceroute (`--trace-method tcp`) | Npcap/libpcap, capture rights, `--fast` |
| UDP traceroute (`--trace-method udp`) | Administrator / root (raw ICMP socket), `--fast` |
| ICMPv6 traceroute on Linux/macOS | root (raw ICMPv6 socket) |
| Passive capture (`listen`, `ot-listen --interface`) | Npcap/libpcap, capture rights |
| Profinet DCP Identify (`dcp`) | Npcap/libpcap, capture rights, `--source-mac` |

### Npcap (Windows)

Install [Npcap](https://npcap.com/) separately; it is under its own license and not bundled. Network Scope never installs drivers or requests elevation. If Npcap was installed with "Restrict Npcap driver's access to Administrators only", run Network Scope as administrator for capture features. Npcap's dependent DLLs are loaded from the driver's directory and Windows default trusted locations.

`network-scope-cli interfaces` lists the capture interfaces and their IDs. Source IPv4 and MAC values must match that interface.

If the driver or configuration is missing, a SYN scan falls back to TCP connect with the host note "SYN unavailable; TCP connect fallback: …"; the ARP sweep falls back to per-host lookups.

### Linux and macOS

libpcap is loaded at run time from `libpcap.A.dylib`/`libpcap.dylib` (macOS) or `libpcap.so.1`/`libpcap.so`/`libpcap.so.0.8` (Linux). ICMP uses an unprivileged datagram socket when the OS allows it and falls back to a raw socket (root). Run capture features as root; granting `cap_net_raw,cap_net_admin` with `setcap` should also work on Linux but is untested.

## Linux and macOS binaries

Release archives `network-scope-<version>-linux-x86_64.tar.gz` and `network-scope-<version>-macos-arm64.tar.gz` contain `network-scope` and `network-scope-cli`. On macOS, `network-scope-<version>-macos-arm64-app.zip` holds the desktop app as `Network Scope.app` (with its icon in Finder, the Dock and Launchpad): unzip it and drag it to Applications. macOS asks once for Local Network access before the first scan. The Linux and macOS platform glue (routes, neighbor states, raw sockets) is not compiled on the development machine; CI is its first compile, and it has not been exercised on a real network.

## Container image

Each release tag publishes the CLI as `ghcr.io/sparkz400/network-scope:<version>` and `:latest` (linux/amd64 only):

```sh
docker run --rm ghcr.io/sparkz400/network-scope:latest scan 192.168.1.0/24 --tcp-only
```

- The entrypoint is `network-scope-cli`; without arguments the image prints the help.
- The image runs as an unprivileged user (`scanner`, UID 10001). TCP connect scanning, service and TLS detection and UDP probes need nothing more.
- Raw sockets, ICMP fallbacks, ARP and capture features (SYN, ARP sweep, `listen`, `dcp`, TCP/UDP traceroute) need `--user root --cap-add NET_RAW` (capture may additionally need `--cap-add NET_ADMIN`). A capability granted with `--cap-add` reaches a process running as root in the container; the unprivileged default user does not receive it. This combination has not been tested yet.
- Use `--network host` (Linux) to see the local LAN directly; on the default bridge network ARP, neighbor discovery and capture only see the container's own network.
- Safe Mode is on by default inside the container as well.
- The inventory database defaults to `/data/NetworkScope/inventory.sqlite`; mount a volume to keep it: `-v network-scope:/data`.
- The runtime image contains libpcap (`libpcap0.8t64`) for capture features and CA certificates for HTTPS webhooks; the GUI libraries are not included and the desktop app does not run in the container.

Build the image yourself with `docker build -t network-scope .` from the repository root.

## Package managers and cargo

Manifests for winget, Scoop, Chocolatey, Homebrew and the AUR are prepared in [`packaging/`](https://github.com/Sparkz400/network-scope/tree/main/packaging) and attached to each release as `network-scope-<version>-packaging.tar.gz`, but **none of them has been submitted yet**, so `winget install` and the others do not find Network Scope today.

With a Rust toolchain you can build and install both binaries from source:

```sh
cargo install --locked --git https://github.com/Sparkz400/network-scope network-scope
```

(on Linux with the development packages listed under [Build from source](#build-from-source)). The crate is not published on crates.io.

## Verifying downloads and the image

Every release has signed proofs of origin (details in [SECURITY.md](https://github.com/Sparkz400/network-scope/blob/main/SECURITY.md#verifying-releases)):

```sh
# GitHub artifact attestation (Sigstore-signed SLSA build provenance) for a release file
gh attestation verify network-scope-0.6.0-linux-x86_64.tar.gz --repo Sparkz400/network-scope

# The same check offline, with the provenance bundle attached to the release
gh attestation verify network-scope-0.6.0-linux-x86_64.tar.gz --repo Sparkz400/network-scope \
  --bundle network-scope-0.6.0.sigstore.json

# Container image
gh attestation verify oci://ghcr.io/sparkz400/network-scope:0.6.0 --owner Sparkz400
```

Each release also has a CycloneDX SBOM. Rebuilding a release and comparing the hash is documented in [Supply chain: SBOM and reproducible builds](supply-chain.md#what-is-reproducible-where): the Windows binaries were measured identical on one machine, the Linux check passes in CI, and releases up to v0.5.1 cannot be reproduced.

## Checking for updates

Network Scope tells you when a newer release exists; it **never downloads or replaces anything**. The check is off until you ask for it:

```sh
network-scope-cli update check
```

prints either `Network Scope 0.6.0 is up to date.` or `Version X is available`, followed by the release page and the commands that verify a download (the checksum with `sha256sum`, `gh attestation verify`, the ones above). You download the file for your platform, verify it and install it yourself.

In the desktop app, **Settings > Check for updates on start** (off by default) does the same once when the program starts and shows a notice in the status bar when a newer release exists. Without that setting, and without running the command, the program never contacts GitHub for this.

What the check does:

- One HTTPS request to `https://api.github.com/repos/Sparkz400/network-scope/releases/latest`, with the headers `Host`, `User-Agent: network-scope/<version>`, `Accept` and `Connection: close`. It sends no identifier, no cookie and no scan data. GitHub sees the IP address of the connection, as for any request.
- The server certificate is verified against the operating system's certificate store (the same code as the [HTTPS webhooks](monitoring-alerts.md)); an untrusted certificate fails the check.
- Only the release tag is used from the answer, after it has been checked as a strict semantic version (`vMAJOR.MINOR.PATCH`). The release link and the commands are built from that version, not copied from the answer. Pre-releases and drafts are not offered. Versions are compared by semantic versioning, so `0.10.0` is newer than `0.9.0`.
- The answer is read up to 1 MiB within a time limit, redirects are not followed. A failed check (no network, rate limit, an answer that is not a release) is an error message (exit status 1 on the command line), never a reason to do anything else.

The unit tests use an in-process server on 127.0.0.1 and a hand-written fixture shaped like GitHub's answer (with a hostile `html_url` and release text to show that they are ignored); they make no network calls. A run of `update check` against the real endpoint on Windows (2026-11-19) completed the TLS handshake with the system certificate store and recognised GitHub's rate-limit answer (HTTP 403 for an address that had used up its 60 unauthenticated requests per hour); a successful answer from the live endpoint has not been seen yet.

## Build from source

Requires a current stable Rust toolchain ([rustup](https://rustup.rs/)).

```sh
git clone https://github.com/Sparkz400/network-scope
cd network-scope
cargo build --release --locked
```

The binaries are `target/release/network-scope` and `target/release/network-scope-cli` (`.exe` on Windows). `cargo run --release` starts the GUI; `cargo run --release --bin network-scope-cli -- scan …` runs the CLI.

Linux GUI build dependencies (Debian/Ubuntu):

```sh
sudo apt-get install libxkbcommon-dev libwayland-dev libx11-dev libgl1-mesa-dev \
  libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev
```

### CLI-only build

The GUI is an optional cargo feature (`gui`, on by default). For servers, containers and CI, where no window system exists, build the command-line program alone:

```sh
cargo build --release --locked --no-default-features --bin network-scope-cli
```

This compiles none of the GUI crates (eframe, egui, the file dialogs) and needs none of the Linux development packages above; the result is a considerably smaller `network-scope-cli` with the complete CLI and TUI (`scan --tui` included). Started without a command it prints `built without the GUI; see --help` and exits with status 2 instead of opening a window. The `network-scope` GUI binary is not built in this configuration.

### Windows installer from source

With [Inno Setup 6](https://jrsoftware.org/isinfo.php):

```powershell
cargo build --release --locked
iscc /DAppVersion=0.6.0 installer\network-scope.iss
```

writes `dist\NetworkScope-0.6.0-setup.exe`. Pass `/DExePath=…` and `/DCliExePath=…` for other build directories.

## Shell completions

```powershell
network-scope-cli completions powershell | Out-String | Invoke-Expression
```

```sh
source <(network-scope completions bash)
```

The scripts cover both binary names.
