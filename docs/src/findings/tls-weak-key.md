# Certificate uses a short RSA key

| | |
| --- | --- |
| Finding id | `tls-weak-key` |
| Severity | High |
| Applies to | TCP ports that speak TLS |

## What it means

The certificate's RSA key is shorter than 2048 bits. Short keys can be broken with far less effort than current ones.

## Why it matters

Whoever recovers the private key can decrypt recorded traffic that used RSA key exchange and can impersonate the server. 1024-bit RSA is considered within reach of well-funded attackers.

## How it is detected

The tool reads the public key of the certificate the server presents. If it is an RSA key with fewer than 2048 bits, the finding is raised and the evidence shows the size (for example `RSA 1024`). Other key types (elliptic-curve keys) are not judged.

## Possible false positives

- Rarely: the certificate is not the one real clients are served (see `tls-cert-expired` on server names).

## How to fix

- **Generate a new key pair** (never reuse the old key): RSA 2048 or larger, or an elliptic-curve key such as P-256, for example `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256`.
- Request a new certificate for the new key from your CA and install it.
- Older devices may not support long keys or elliptic curves; check the firmware release notes.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [RFC 5280, X.509 certificate profile](https://www.rfc-editor.org/rfc/rfc5280)
- [CA/Browser Forum Baseline Requirements](https://cabforum.org/working-groups/server/baseline-requirements/documents/)

[All findings](index.md)
