# Deprecated TLS 1.0/1.1 is enabled

| | |
| --- | --- |
| Finding id | `tls-deprecated-protocol` |
| Severity | Medium |
| Applies to | TCP ports that speak TLS |

## What it means

The server still accepts TLS 1.0 or TLS 1.1. Both were formally retired by the standards body in 2021 because they depend on outdated cryptography and have no safe modern cipher suites.

## Why it matters

An attacker who can force a client to use an old version gets a weaker connection to attack. Compliance frameworks and current browsers no longer accept these versions.

## How it is detected

The tool offers TLS 1.0 and 1.1 in separate handshakes and records whether the server completes them. The finding is raised if either was accepted. The evidence is the list of protocol versions the server accepted on that port.

Handshakes per port are limited, so a version that was not seen is not proof that it is off.

## Possible false positives

- A compatibility setting that is needed on purpose for very old clients (old industrial panels, scanners, Windows XP). That is a risk to accept knowingly, not a measurement error.

## How to fix

- **Disable TLS 1.0 and 1.1** and leave TLS 1.2 and 1.3 enabled:
- **nginx:** `ssl_protocols TLSv1.2 TLSv1.3;`, then `nginx -t` and reload. See the ngx_http_ssl_module documentation.
- **Apache httpd:** `SSLProtocol -all +TLSv1.2 +TLSv1.3` (mod_ssl), then reload.
- **Windows / IIS:** control the protocols through the Schannel registry settings (see the Microsoft page below); a reboot is required.
- A starting configuration for common servers is generated at ssl-config.mozilla.org.
- Before switching off, check which clients still use the old versions (server logs) so that nothing breaks unannounced.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [RFC 8996, Deprecating TLS 1.0 and TLS 1.1](https://www.rfc-editor.org/rfc/rfc8996)
- [RFC 9325, Recommendations for secure use of TLS](https://www.rfc-editor.org/rfc/rfc9325)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [Microsoft, TLS registry settings (Schannel)](https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings)

[All findings](index.md)
