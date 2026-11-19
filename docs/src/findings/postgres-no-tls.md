# PostgreSQL does not offer TLS

| | |
| --- | --- |
| Finding id | `postgres-no-tls` |
| Severity | Low |
| Applies to | TCP port 5432 |

## What it means

The PostgreSQL database server answers on its network port but does not support encrypted connections. Clients connect in clear text, including passwords (depending on the authentication method) and query results.

## Why it matters

Data and credentials can be read on the network path. The risk is higher when the database is reached over untrusted networks.

## How it is detected

On port 5432 the tool sends PostgreSQL's SSL request (the first step of a connection) and reads the single-character answer. `N` means TLS is not supported and raises the finding; `S` (supported) is fine. No login is attempted.

## Possible false positives

- A database that is reached only over a local socket or a trusted private link, but also listens on the network.

## How to fix

- **Enable TLS:** set `ssl = on` with `ssl_cert_file` and `ssl_key_file` in `postgresql.conf` and reload.
- Force encrypted connections for remote clients with `hostssl` lines (and no `host` lines) in `pg_hba.conf`.
- Restrict the listen addresses and the firewall to the application servers.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [PostgreSQL documentation, secure TCP/IP connections with SSL](https://www.postgresql.org/docs/current/ssl-tcp.html)
- [PostgreSQL documentation, pg_hba.conf](https://www.postgresql.org/docs/current/auth-pg-hba-conf.html)

[All findings](index.md)
