# Redis answers without authentication

| | |
| --- | --- |
| Finding id | `redis-noauth` |
| Severity | Critical |
| Applies to | TCP port 6379 |

## What it means

A Redis database answered a command without asking for a password. Anyone who can reach the port can read and change its data.

## Why it matters

An open Redis lets an attacker read all stored data (sessions, tokens, caches) and, through its administrative commands, frequently write files on the server and run code. Redis servers without authentication that are reachable from the Internet are attacked routinely.

## How it is detected

On port 6379 the tool sends one harmless command, `INFO server`, and reads the reply. If the reply contains a `redis_version:` line, the server answered without authentication and the finding is raised; the evidence is the service description with the version. A reply that asks for authentication (`NOAUTH`/`DENIED`) is not flagged. The tool does not write anything, does not run administrative commands and does not probe other ports.

## Possible false positives

- A honeypot or a deliberately open cache on an isolated network.
- Redis 6 and later can limit what an unauthenticated default user may do, and still answer `INFO`.

## How to fix

- **Require authentication:** configure ACL users (Redis 6 and later) or `requirepass`, with a long random password.
- **Bind to a private interface** (`bind 127.0.0.1` or the internal address) and keep `protected-mode yes`; do not publish the port.
- Use TLS if clients connect over a network, and limit access in the firewall.
- Restart the service, then test with `redis-cli` that a command without credentials is refused.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [Redis documentation, Security](https://redis.io/docs/latest/operate/oss_and_stack/management/security/)

[All findings](index.md)
