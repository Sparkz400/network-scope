# FTP sends credentials in clear text

| | |
| --- | --- |
| Finding id | `ftp-cleartext` |
| Severity | Medium |
| Applies to | TCP ports running FTP |

## What it means

An FTP server is reachable. Plain FTP transmits user names, passwords and file contents without encryption.

## Why it matters

Anyone who can observe the traffic can read the credentials and the transferred files, and can reuse the credentials elsewhere if they are shared with other systems.

## How it is detected

The tool identifies FTP from the server's greeting on a plain connection: a line starting with `220` that is not recognised as SMTP (known FTP servers such as vsFTPd, ProFTPD, Pure-FTPd, FileZilla Server and Microsoft FTP Service are named; any other `220` greeting is called FTP). It does not log in, does not test anonymous access and does not check whether the server also offers encryption (`AUTH TLS`). The evidence is the service description.

## Possible false positives

- A server that supports explicit FTPS and refuses logins without it shows the same greeting. The tool cannot tell the difference.
- A mail server whose greeting starts with `220` but does not contain `SMTP` or `ESMTP` can be misidentified as FTP.

## How to fix

- **Use SFTP (over SSH) or FTPS** and disable plain FTP logins.
- **vsftpd:** `ssl_enable=YES`, `force_local_logins_ssl=YES`, `force_local_data_ssl=YES`.
- **IIS FTP:** set the SSL policy for the FTP site to require SSL connections.
- **Devices (cameras, printers, cell gateways):** choose SFTP/FTPS in their upload settings if available, otherwise keep the FTP server on an isolated segment.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [RFC 959, File Transfer Protocol](https://www.rfc-editor.org/rfc/rfc959)
- [RFC 4217, Securing FTP with TLS](https://www.rfc-editor.org/rfc/rfc4217)

[All findings](index.md)
