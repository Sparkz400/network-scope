# 3DES cipher suites are accepted

| | |
| --- | --- |
| Finding id | `tls-3des` |
| Severity | Medium |
| Applies to | TCP ports that speak TLS |

## What it means

The server accepts Triple-DES (3DES) cipher suites. 3DES uses a small block size, which makes it possible, in long sessions, to recover parts of the plaintext.

## Why it matters

The weakness is known as Sweet32 (CVE-2016-2183). Exploiting it needs a long-lived connection and a lot of traffic, which keeps the practical risk moderate; it is nevertheless on all deprecation lists.

## How it is detected

The tool offers the server only 3DES suites and records whether it picks one. The finding is raised if it does and no suite from the broken classes (RC4, DES, export, anonymous, NULL) was found on the same port; in that case `tls-broken-cipher` is reported instead. The evidence lists the weaknesses recorded for the port. The CVE is attached as a hint.

## Possible false positives

- Kept on purpose for very old clients.

## How to fix

- **Remove 3DES suites** from the cipher list:
- **nginx / Apache:** use the cipher list produced by the Mozilla generator.
- **Windows / IIS:** disable `Triple DES 168` in the Schannel registry settings.
- **Appliances and devices:** update the firmware or use the cipher setting in the management interface.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [Mozilla, Server Side TLS recommendations](https://wiki.mozilla.org/Security/Server_Side_TLS)
- [NVD, CVE-2016-2183 (Sweet32)](https://nvd.nist.gov/vuln/detail/CVE-2016-2183)
- [RFC 9325, Recommendations for secure use of TLS](https://www.rfc-editor.org/rfc/rfc9325)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [Microsoft, TLS registry settings (Schannel)](https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings)

[All findings](index.md)
