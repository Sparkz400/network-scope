# SSLv3 is enabled

| | |
| --- | --- |
| Finding id | `tls-sslv3` |
| Severity | High |
| Applies to | TCP ports that speak TLS |

## What it means

The server still accepts connections with SSL version 3, a protocol from 1996 that has been broken for years. It was replaced by TLS.

## Why it matters

SSLv3 has design flaws, the best known being POODLE (CVE-2014-3566), which can let an attacker decrypt parts of an encrypted session under the right conditions. The finding carries that CVE as a hint; the risk comes from the protocol being enabled, not from a specific exploit being confirmed.

## How it is detected

The tool sends its own TLS handshakes that offer only SSLv3 and records whether the server completes one. This works even though modern TLS libraries refuse SSLv3. The finding is raised when SSLv3 was accepted; the evidence is the tool's list of weak protocol and cipher observations for the port.

The number of handshakes per port is limited (fewer in Safe Mode), so a protocol that was not seen is not proof that it is off.

## Possible false positives

- A device in front of the real server (load balancer, appliance) answers for it.

## How to fix

- **Disable SSLv3** and keep TLS 1.2 and 1.3. Typical settings:
- **nginx:** `ssl_protocols TLSv1.2 TLSv1.3;`, then `nginx -t` and reload. See the ngx_http_ssl_module documentation.
- **Apache httpd:** `SSLProtocol -all +TLSv1.2 +TLSv1.3` (mod_ssl), then reload.
- **Windows / IIS:** control the protocols through the Schannel registry settings (see the Microsoft page below); a reboot is required.
- A starting configuration for common servers is generated at ssl-config.mozilla.org.
- **Appliances and devices:** use the TLS or protocol setting in the management interface, or update the firmware.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [RFC 7568, Deprecating SSL 3.0](https://www.rfc-editor.org/rfc/rfc7568)
- [NVD, CVE-2014-3566 (POODLE)](https://nvd.nist.gov/vuln/detail/CVE-2014-3566)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [Microsoft, TLS registry settings (Schannel)](https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings)

[All findings](index.md)
