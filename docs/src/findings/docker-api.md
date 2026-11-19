# Docker Engine API is exposed

| | |
| --- | --- |
| Finding id | `docker-api` |
| Severity | Critical |
| Applies to | TCP ports serving HTTP or HTTPS |

## What it means

A web endpoint identifies itself as the Docker Engine. The Docker API, if reachable without protection, lets anyone start containers on the host.

## Why it matters

Access to the Docker API is effectively root access to the host: an attacker can start a container that mounts the host's file system and read or change anything, or install persistent backdoors.

## How it is detected

The tool reads the HTTP `Server` header of the response. If it starts with `Docker/` (the Engine API announces itself as `Docker/<version> (<os>)`), the finding is raised, and the evidence is the header value. The tool does not call any API function and does not check whether authentication is required.

## Possible false positives

- An API that requires TLS client certificates would normally refuse the connection before the header is seen, so such a daemon is usually not reported. A TLS endpoint without client authentication is reported.
- A proxy or tool that imitates the Docker header.

## How to fix

- **Do not publish the Docker socket on TCP without protection.** Remove `tcp://0.0.0.0:2375` from the daemon's `hosts` setting (or `-H` flag) and use the local Unix socket, or SSH (`docker context` with an `ssh://` endpoint).
- If TCP access is needed: enable TLS with client certificate verification (`--tlsverify`), and limit the port in the firewall to the administrators' addresses.
- Check the host for unknown containers and images, and rotate secrets that containers had access to, if the port was reachable from untrusted networks.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [Docker documentation, protect the Docker daemon socket](https://docs.docker.com/engine/security/protect-access/)
- [Docker documentation, Docker Engine security](https://docs.docker.com/engine/security/)

[All findings](index.md)
