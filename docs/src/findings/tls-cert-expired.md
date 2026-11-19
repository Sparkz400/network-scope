# TLS certificate has expired

| | |
| --- | --- |
| Finding id | `tls-cert-expired` |
| Severity | High |
| Applies to | TCP ports that speak TLS |

## What it means

The server presented a certificate for encrypted connections (HTTPS, mail over TLS, a device's web interface) whose validity period has ended. A certificate is a time-limited identity card for the service; after the end date, clients can no longer rely on it.

## Why it matters

Browsers and other clients show a warning or refuse to connect. People learn to click through such warnings, which makes a real attack harder to notice, and automated clients (monitoring, backups, APIs) fail outright. An expired certificate also tends to mean that nobody is looking after the service.

## How it is detected

During service inspection (`--services` or `--deep`) the tool completes a TLS handshake, reads the certificate the server sends and compares its "not after" date with the clock of the machine running the scan. If the scan machine's time is later than that date, the finding is raised. The evidence line shows the "not after" date.

The tool connects by IP address and sends no server name, so a host that serves several sites may present a default certificate instead of the one a browser would see.

## Possible false positives

- The clock of the scanning machine is wrong (the check uses that clock, not an external time source).
- A name-based virtual host or load balancer returned a default or leftover certificate to a client that sends no server name, while real clients get a valid one.
- The port serves a certificate that no client actually uses (an old default certificate on a management port).

## How to fix

- **Renew the certificate** with the issuer (public CA, your internal CA, or the device's own certificate tool), then install it where the service reads it.
- **Web servers:** after replacing the files, reload the service (`nginx -s reload`, `systemctl reload apache2`, or rebind the certificate in IIS Manager under Site Bindings).
- **Automate renewal** for public names with an ACME client; see the Let's Encrypt documentation.
- **Check the clock** of the device if a freshly issued certificate is still reported as expired.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [RFC 5280, X.509 certificate profile (validity period)](https://www.rfc-editor.org/rfc/rfc5280)
- [Let's Encrypt documentation](https://letsencrypt.org/docs/)

[All findings](index.md)
