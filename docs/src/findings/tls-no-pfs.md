# Cipher suites without forward secrecy are accepted

| | |
| --- | --- |
| Finding id | `tls-no-pfs` |
| Severity | Low |
| Applies to | TCP ports that speak TLS |

## What it means

The server accepts suites that use the server's long-term RSA key to protect the session key. If that key is ever stolen, all recorded traffic from the past can be decrypted. "Forward secrecy" (ephemeral key exchange, ECDHE) prevents that.

## Why it matters

Low in practice today, but an easy hardening step. An attacker who records traffic now and obtains the key later (by compromise, legal request or a future weakness) can read everything.

## How it is detected

The tool offers the server only static-RSA suites (names such as `RSA_AES_128_GCM_SHA256`) and records whether it picks one. The finding is raised if it does. The evidence text is fixed: "static RSA key exchange offered". TLS 1.3 always has forward secrecy and does not trigger this finding.

## Possible false positives

- Needed by very old clients that cannot use ECDHE.

## How to fix

- **Prefer ECDHE suites** and drop static-RSA suites from the cipher list; the Mozilla generator's output already does this.
- Enable TLS 1.3 where the software supports it.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [Mozilla, Server Side TLS recommendations](https://wiki.mozilla.org/Security/Server_Side_TLS)
- [RFC 9325, Recommendations for secure use of TLS](https://www.rfc-editor.org/rfc/rfc9325)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)

[All findings](index.md)
