# SMB server does not offer encryption

| | |
| --- | --- |
| Finding id | `smb-no-encryption` |
| Severity | Info |
| Applies to | TCP port 445 (SMB) |

## What it means

The file-sharing server cannot encrypt its traffic. File names and file contents cross the network readable by anyone who can capture them.

## Why it matters

Only relevant for sensitive data or untrusted networks. It is reported as information, not as a flaw: SMB encryption is an optional feature.

## How it is detected

From the SMB2 negotiate reply the tool records the encryption support: SMB 3.1.1 with no cipher announced, SMB 3.0 or 3.0.2 without the encryption capability, or SMB 2.x. The finding is raised when the value begins with "not supported". The evidence shows the dialect and the encryption value.

## Possible false positives

- Encryption is normally optional per server or per share, so a server that supports it but has it switched off looks fine; and the reverse is not detected.

## How to fix

- **Windows:** enable encryption for a share with `Set-SmbShare -Name SHARE -EncryptData $true`, or for the whole server with `Set-SmbServerConfiguration -EncryptData $true`. Old clients (SMB 2.x) cannot connect to an encrypted share.
- **Samba:** `server smb encrypt = required` (or `desired`).
- Update systems that only offer SMB 2.x.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [Microsoft, SMB security enhancements](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security)

[All findings](index.md)
