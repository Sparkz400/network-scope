# LDAP answers an anonymous bind

| | |
| --- | --- |
| Finding id | `ldap-anonymous` |
| Severity | Low |
| Applies to | TCP ports 389 and 3268 (LDAP and global catalog) |

## What it means

A directory server (LDAP, for example Active Directory or OpenLDAP) accepts a connection without a user name or password.

## Why it matters

Depending on the directory's access rules, anonymous users may be able to list users, groups and computers, which helps attackers prepare attacks. Many directories allow limited anonymous access by design.

## How it is detected

On ports 389 and 3268 the tool sends an LDAP version 3 bind request with an empty name and an empty simple password and reads the result. A "success" result raises the finding; the evidence is the service description. The tool does not search the directory, so it does not know what an anonymous client could read.

## Possible false positives

- Directories commonly allow anonymous reading of their basic server description (rootDSE) and nothing else.

## How to fix

- **Disable anonymous binds** unless an application needs them, and restrict what anonymous users can read. **OpenLDAP:** `disallow bind_anon` and `require authc`.
- Prefer LDAPS or StartTLS for all client connections.
- In Active Directory, check that the directory settings for anonymous access have not been loosened beyond the defaults.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [RFC 4513, LDAP authentication methods](https://www.rfc-editor.org/rfc/rfc4513)
- [OpenLDAP Administrator's Guide](https://www.openldap.org/doc/admin26/)

[All findings](index.md)
