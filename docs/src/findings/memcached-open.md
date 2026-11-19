# memcached answers without authentication

| | |
| --- | --- |
| Finding id | `memcached-open` |
| Severity | High |
| Applies to | TCP port 11211 |

## What it means

A memcached cache server answered a command without asking for credentials. Memcached has no login by default, so anyone who can reach the port can read and overwrite cached data.

## Why it matters

Cached data (sessions, user data, database results) can be stolen or manipulated. Exposed memcached servers have also been abused as amplifiers for denial-of-service attacks.

## How it is detected

On port 11211 the tool sends the `version` command and reads the reply. A `VERSION x.y.z` answer raises the finding; the evidence is the service description. Only TCP is considered by this finding. The tool does not read or write cache entries.

## Possible false positives

- A cache on a private network that is intended to be open to a small number of application servers. It is still better to restrict it.

## How to fix

- **Listen only on the interfaces that need it** (`-l 127.0.0.1` or the private address) and **disable UDP** (`-U 0`).
- Restrict the port in the firewall to the application servers.
- Use SASL authentication where the clients support it.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [memcached project documentation](https://docs.memcached.org/)
- [memcached wiki, configuring the server](https://github.com/memcached/memcached/wiki/ConfiguringServer)

[All findings](index.md)
