# Self-signed TLS certificate

| | |
| --- | --- |
| Finding id | `tls-self-signed` |
| Severity | Low |
| Applies to | TCP ports that speak TLS |

## What it means

The certificate was signed by itself instead of by a certificate authority (CA) that clients trust. Such a certificate encrypts traffic, but a client has no independent way to tell whether it is talking to the genuine server.

## Why it matters

Clients either show warnings or are configured to accept any certificate, and in that case an attacker in the network path can impersonate the server without being noticed. Self-signed certificates are common on devices and test systems, which is why the severity is low.

## How it is detected

The tool compares the certificate's issuer with its subject. If they are identical and, when both key identifiers are present, the authority key identifier names the certificate's own key, the certificate counts as self-signed. The signature is then verified with the certificate's own key (`tls.<port>.self_signature` is `valid`, `invalid` or `unchecked`). When it is `invalid` the certificate is not what it claims to be and [a different finding](tls-self-signed-bad-signature.md) is raised instead; `valid` and `unchecked` (an algorithm or key size the verifier cannot check) both give this finding.

The tool does not check trust: a certificate issued by a private or unknown CA is not reported here.

## Possible false positives

- Expected on lab systems and on devices that ship with their own certificate (printers, switches, controllers).
- A certificate that is pinned by clients on purpose.

## How to fix

- **Where clients must verify the server,** install a certificate from a CA those clients trust: a public CA (for example through ACME) for public names, or your organisation's internal CA for internal names.
- Where a self-signed certificate is accepted, record the fingerprint and let clients pin it instead of disabling verification.
- Many devices only offer a certificate import in their web interface or need a newer firmware; check the vendor's documentation.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [RFC 5280, X.509 certificate profile](https://www.rfc-editor.org/rfc/rfc5280)
- [Let's Encrypt documentation](https://letsencrypt.org/docs/)

[All findings](index.md)
