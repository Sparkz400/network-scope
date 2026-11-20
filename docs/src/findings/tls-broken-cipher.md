# Broken TLS cipher suites are accepted

| | |
| --- | --- |
| Finding id | `tls-broken-cipher` |
| Severity | High |
| Applies to | TCP ports that speak TLS |

## What it means

The server agrees to use encryption methods that are broken or provide no protection at all: RC4, single DES, "export-grade" ciphers from the 1990s, anonymous key exchange (no server authentication) or NULL ciphers (no encryption).

## Why it matters

Traffic protected with these suites can be decrypted or altered by an attacker with modest resources, or is not encrypted at all.

## How it is detected

For each protocol version the server accepts, the tool offers it only suites from the weak classes and records whether the server picks one. Suites are matched by their weakness label: RC4, single DES, export-grade, anonymous or NULL (no encryption). The finding is raised if any such suite was accepted; the evidence lists all weaknesses the tool recorded for the port.

If a broken suite is found, the weaker-but-different `tls-3des` finding is not raised for the same port. The number of handshakes is limited (fewer in Safe Mode), so suites can be missed.

## Possible false positives

- A device in front of the real server answers for it.

## How to fix

- **Remove the listed suites** from the server configuration. Use a maintained template rather than editing suite lists by hand:
- **nginx / Apache:** set the cipher list to the Mozilla generator's output (`ssl_ciphers` / `SSLCipherSuite`).
- **Windows / IIS:** disable the cipher in the Schannel registry settings, or use the group policy for the SSL cipher suite order.
- **Appliances and devices:** update the firmware or use the cipher setting in the management interface.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [Mozilla, Server Side TLS recommendations](https://wiki.mozilla.org/Security/Server_Side_TLS)
- [RFC 7465, Prohibiting RC4 cipher suites](https://www.rfc-editor.org/rfc/rfc7465)
- [RFC 9325, Recommendations for secure use of TLS](https://www.rfc-editor.org/rfc/rfc9325)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [Microsoft, TLS registry settings (Schannel)](https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings)

[All findings](index.md)
