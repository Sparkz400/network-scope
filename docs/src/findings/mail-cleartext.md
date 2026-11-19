# Mail retrieval without TLS

| | |
| --- | --- |
| Finding id | `mail-cleartext` |
| Severity | Low |
| Applies to | TCP ports running POP3 or IMAP |

## What it means

A POP3 or IMAP mail server answers on a plain, unencrypted connection. Mail clients connecting this way may send their password in clear text.

## Why it matters

Passwords and mail content can be read by anyone on the network path. Mail passwords are often reused for other accounts.

## How it is detected

The tool identifies POP3 (`+OK` greeting) or IMAP (`* OK` greeting) on a plain connection. Servers on TLS ports such as 993 and 995 are identified as TLS services and do not trigger the finding. The tool does not check whether the server offers or enforces STARTTLS. The evidence is the service description.

## Possible false positives

- A server that requires STARTTLS before login (IMAP `LOGINDISABLED`, POP3 `STLS` enforcement) is reported although credentials are never sent in clear text.

## How to fix

- **Require TLS:** offer only IMAPS (993) and POP3S (995), or enforce STARTTLS before authentication.
- **Dovecot:** `ssl = required` and `disable_plaintext_auth = yes`.
- Switch off the plain ports in the firewall once clients are migrated.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [RFC 8314, Cleartext considered obsolete for mail](https://www.rfc-editor.org/rfc/rfc8314)
- [RFC 2595, Using TLS with IMAP, POP3 and ACAP](https://www.rfc-editor.org/rfc/rfc2595)

[All findings](index.md)
