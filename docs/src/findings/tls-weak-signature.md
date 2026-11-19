# Certificate signed with a weak hash

| | |
| --- | --- |
| Finding id | `tls-weak-signature` |
| Severity | Medium |
| Applies to | TCP ports that speak TLS |

## What it means

The certificate was signed with an outdated hash function (MD5 or SHA-1). These functions are no longer considered safe for signatures, because attackers can craft two documents with the same hash.

## Why it matters

A weak signature makes it feasible, in principle, to forge a certificate that looks genuine. Modern clients reject such certificates, so users also see errors.

## How it is detected

The tool reads the signature algorithm of the certificate the server presents. It raises the finding for `md5WithRSA`, `sha1WithRSA` and `ecdsa-with-SHA1`. Other algorithms, including less common weak ones that the tool does not know by name, are not flagged. The evidence shows the algorithm.

## Possible false positives

- Only the certificate the server presents first is judged; the chain behind it is not examined.

## How to fix

- **Reissue the certificate** with SHA-256 or stronger (for RSA keys `sha256WithRSAEncryption`, or an ECDSA key with SHA-256).
- With OpenSSL a new request is created with `openssl req -new -sha256 -key server.key -out server.csr`; most CAs and device interfaces create the request for you.
- Replace the certificate on the service and reload it.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [RFC 5280, X.509 certificate profile](https://www.rfc-editor.org/rfc/rfc5280)
- [CA/Browser Forum Baseline Requirements](https://cabforum.org/working-groups/server/baseline-requirements/documents/)

[All findings](index.md)
