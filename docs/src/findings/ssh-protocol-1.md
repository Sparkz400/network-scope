# SSH protocol 1 in use

| | |
| --- | --- |
| Finding id | `ssh-protocol-1` |
| Severity | High |
| Applies to | TCP ports running SSH |

## What it means

The server announces that it speaks version 1 of the SSH protocol. Version 1 has serious design flaws and was replaced by version 2 more than twenty years ago.

## Why it matters

SSH protocol 1 is open to attacks that allow session hijacking and data injection. Current software does not support it at all, so a server that announces it is very old or heavily outdated.

## How it is detected

The first line the server sends (its banner, for example `SSH-1.5-...`) names the protocol version. The tool stores it as "protocol 1.5" or similar and raises the finding when the service is identified as SSH and its description contains `protocol 1.` but not `protocol 1.99`. The value 1.99 means "supports both 1 and 2" and is not flagged. The evidence is the service description.

## Possible false positives

- Only services identified as SSH count; another service whose banner says `protocol 1.x` for its own protocol does not trigger the rule (the false-alarm budget test covers this).
- A server announcing 1.99 can still allow version 1; it is not reported.

## How to fix

- **Use protocol 2 only.** Modern OpenSSH has no protocol 1 at all (removed in OpenSSH 7.6); upgrade the software.
- For old appliances: update the firmware, or replace the device. If neither is possible, restrict access to a management network and plan the replacement.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [RFC 4253, SSH transport layer protocol](https://www.rfc-editor.org/rfc/rfc4253)
- [OpenSSH 7.6 release notes (SSH protocol 1 removed)](https://www.openssh.org/txt/release-7.6)

[All findings](index.md)
