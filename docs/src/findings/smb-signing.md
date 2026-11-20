# SMB signing is not required

| | |
| --- | --- |
| Finding id | `smb-signing` |
| Severity | Medium |
| Applies to | TCP port 445 (SMB) |

## What it means

The file-sharing server does not insist that messages are digitally signed. Signing proves that a message has not been altered on the way and that it comes from the right party.

## Why it matters

Without required signing, an attacker in the network path can relay authentication to the server ("SMB relay") and act with the victim's rights. Requiring signing is the usual protection against it.

## How it is detected

The tool sends an SMB2 negotiate request and reads the signing flags from the reply. "Signing disabled" or "signing enabled, not required" raises the finding; "signing required" does not. The evidence is the service description.

## Possible false positives

- Windows servers other than domain controllers do not require signing by default, so on a Windows network this finding is common and expected until a policy requires it.

## How to fix

- **Windows:** group policy “Microsoft network server: Digitally sign communications (always)” set to Enabled; or `Set-SmbServerConfiguration -RequireSecuritySignature $true`. Test first, because old clients may fail to connect and signing costs some performance.
- **Samba:** `server signing = mandatory`.
- **NAS and appliances:** look for an SMB signing option in the file-sharing settings.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [Microsoft, overview of SMB signing](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing-overview)
- [Microsoft, SMB security enhancements](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security)
- [Samba, smb.conf manual](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html)

[All findings](index.md)
