# TLS certificate is not yet valid

| | |
| --- | --- |
| Finding id | `tls-cert-not-yet-valid` |
| Severity | Medium |
| Applies to | TCP ports that speak TLS |

## What it means

The certificate's start date lies in the future. Clients reject it, just like an expired one, until that date arrives.

## Why it matters

Connections fail or show certificate errors. The usual cause is a wrong clock: a device that lost its time while it generated its own certificate, or a certificate issued with a wrong start date.

## How it is detected

The tool reads the "not before" date of the certificate during the TLS handshake. If it is later than the clock of the scanning machine, the finding is raised. The evidence shows the "not before" date.

## Possible false positives

- The scanning machine's clock is behind real time.
- The certificate was issued a moment ago and the clocks of issuer and scanner differ by a few minutes.

## How to fix

- **Check the time source** of the device (NTP) and correct its clock.
- **Reissue the certificate** with a correct validity period if it was generated while the clock was wrong. Self-generated device certificates are usually recreated from the device's certificate settings; some devices need a factory reset or vendor guidance.
- Check the clock of the scanning machine as well before assuming a device problem.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [RFC 5280, X.509 certificate profile (validity period)](https://www.rfc-editor.org/rfc/rfc5280)

[All findings](index.md)
