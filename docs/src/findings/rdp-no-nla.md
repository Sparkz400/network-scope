# RDP uses legacy security without TLS or NLA

| | |
| --- | --- |
| Finding id | `rdp-no-nla` |
| Other title | RDP does not require Network Level Authentication |
| Severity | Medium or High |
| Applies to | TCP ports running Remote Desktop (RDP) |

## What it means

The Remote Desktop service accepts connections that do not require Network Level Authentication (NLA). With NLA, a user must authenticate before the server builds the remote session. Without it, anyone who can connect gets as far as the sign-in screen and can use the server's resources before logging in.

## Why it matters

Without NLA, the server is more exposed to password guessing and to denial of service, and it exposes more code to unauthenticated clients. The oldest RDP mode ("standard RDP security") has weaker encryption and was the setting that the BlueKeep vulnerability (CVE-2019-0708) affected on older Windows versions.

## How it is detected

The tool sends a read-only RDP connection request that offers TLS and NLA, and no login is attempted. The reply tells which security method the server selects. If the server selects NLA, a second request follows that offers only the oldest method ("standard RDP security"); the reply shows whether the server really requires NLA or would also accept TLS-only or standard security. The result is the service description. Two outcomes are reported:

- **High**: the description contains "standard RDP security": the server selected the oldest method, or accepted it in the second request. The CVE-2019-0708 hint is attached.
- **Medium**: the description contains "TLS security" (and not the legacy text): the server selected TLS instead of NLA, or accepted TLS-only in the second request.

NLA counts as required only when the second request is refused ("NLA required"). The evidence is the service description.

## Possible false positives

- In the High case the title reads “legacy security without TLS or NLA”, but the same finding is raised when the server prefers NLA and merely also accepts the legacy method (“NLA (CredSSP); standard RDP security also accepted”). Read the evidence text to see which case applies.
- The BlueKeep CVE hint is attached from the configuration alone. BlueKeep affects older Windows versions (for example Windows 7 and Windows Server 2008 R2) that lack the 2019 security updates; the tool cannot see the patch level.

## How to fix

- **Windows:** in System Properties, Remote, choose “Allow connections only from computers running Remote Desktop with Network Level Authentication”. Group policy: Computer Configuration, Administrative Templates, Windows Components, Remote Desktop Services, Remote Desktop Session Host, Security: enable “Require user authentication for remote connections by using Network Level Authentication” and set “Require use of specific security layer for remote (RDP) connections” to SSL.
- **Install the Windows security updates** (the 2019 BlueKeep fixes for older systems) and plan the replacement of systems that no longer receive updates.
- **xrdp (Linux):** set `security_layer=tls` in `xrdp.ini`.
- Do not expose RDP to the Internet; use a VPN or a Remote Desktop Gateway and restrict the port in the firewall.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- Scan the host again: with NLA required the finding goes away; with TLS only, High becomes Medium.

## References

- [Microsoft, allow access to your PC (Remote Desktop)](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remotepc/remote-desktop-allow-access)
- [NVD, CVE-2019-0708 (BlueKeep)](https://nvd.nist.gov/vuln/detail/CVE-2019-0708)

[All findings](index.md)
