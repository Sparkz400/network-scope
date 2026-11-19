# SMBv1 is enabled

| | |
| --- | --- |
| Finding id | `smb1-enabled` |
| Severity | High |
| Applies to | TCP port 445 (SMB) |

## What it means

The server still speaks SMB version 1, the original Windows file-sharing protocol from the 1980s and 90s. It has been replaced by SMB 2 and 3.

## Why it matters

SMBv1 contains design weaknesses and was the entry point of the 2017 WannaCry and NotPetya outbreaks (the EternalBlue flaw, MS17-010, CVE-2017-0144). Microsoft recommends removing it everywhere.

## How it is detected

The tool sends a separate, read-only SMB1 negotiate request that offers only the dialect `NT LM 0.12`. If the server accepts it, or if the first reply was already SMB1, the finding is raised. Modern servers answer SMB2 requests even when SMB1 is still on, so only this separate request shows it. The evidence is the service description, extended with "SMB1 negotiate (NT LM 0.12) accepted" where applicable.

CVE-2017-0144 is attached as a hint because SMBv1 is enabled. The tool cannot see whether the MS17-010 patch is installed.

## Possible false positives

- The CVE hint does not mean the host is vulnerable: a patched system with SMB1 enabled still gets it, and this tool only sees that SMB1 is on.

## How to fix

- **Windows 10/11 and Server:** `Set-SmbServerConfiguration -EnableSMB1Protocol $false`, and remove the feature with `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`. Check first which clients or devices still use SMB1 (the SMB audit setting `AuditSmb1Access` logs them).
- **Samba:** `server min protocol = SMB2` in `smb.conf`.
- **NAS and other appliances:** turn SMB1 off in the file-sharing settings or update the firmware.
- **Install MS17-010** (March 2017) on systems that cannot disable SMB1 yet, and isolate them. This reduces the risk but does not clear the finding, because SMB1 stays on.
- Old scanners, multifunction printers and legacy machines may need an update or replacement; in industrial setups clear the change with the vendor and plan it in a maintenance window.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- Scan the host again: the finding goes away once SMB1 no longer answers.

## References

- [Microsoft, detect, enable and disable SMBv1, SMBv2 and SMBv3](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3)
- [Microsoft Security Bulletin MS17-010](https://learn.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)
- [NVD, CVE-2017-0144](https://nvd.nist.gov/vuln/detail/CVE-2017-0144)

[All findings](index.md)
