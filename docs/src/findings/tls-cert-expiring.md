# TLS certificate expires within 30 days

| | |
| --- | --- |
| Finding id | `tls-cert-expiring` |
| Severity | Medium |
| Applies to | TCP ports that speak TLS |

## What it means

The server's certificate is still valid but will expire within the next 30 days. After that date clients will treat the service as untrusted.

## Why it matters

It is a warning ahead of an outage: when the date passes, browsers and automated clients start failing. Renewing early costs little; renewing during an incident does not.

## How it is detected

The tool reads the certificate's "not after" date during the TLS handshake and computes the whole days left (rounded down) against the scanning machine's clock. The finding is raised when the certificate has not expired and 30 days or fewer are left; an already expired certificate gets `tls-cert-expired` instead. The evidence shows the days left and the date.

## Possible false positives

- Certificates that are renewed automatically in the last weeks of their life show up here until the renewal job runs.
- The scanning machine's clock is ahead of real time.
- A default certificate returned because the tool sends no server name (see `tls-cert-expired`).

## How to fix

- **Renew and install the new certificate** before the date shown, then reload the service.
- If you use an ACME client, check that its renewal job runs and that the service is reloaded afterwards.
- Put the expiry date in a calendar or monitoring system for certificates that are renewed by hand (devices, appliances).
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [RFC 5280, X.509 certificate profile (validity period)](https://www.rfc-editor.org/rfc/rfc5280)
- [Let's Encrypt documentation](https://letsencrypt.org/docs/)

[All findings](index.md)
