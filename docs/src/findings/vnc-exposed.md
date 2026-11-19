# VNC is reachable

| | |
| --- | --- |
| Finding id | `vnc-exposed` |
| Severity | Medium |
| Applies to | TCP ports running VNC |

## What it means

A VNC remote-desktop server answers on the network. VNC gives full control of the screen, keyboard and mouse of the machine.

## Why it matters

VNC is often protected only by a short password, sometimes by none, and frequently does not encrypt the session. Reachable VNC servers are a standard target for password guessing.

## How it is detected

The tool identifies VNC from the server's version greeting (`RFB 003.008` and similar). It does not test which authentication method the server uses and does not try passwords. The evidence is the service description, so it says "reachable", not "unprotected".

## Possible false positives

- A VNC server with strong authentication and encryption on a controlled network is still reported; the finding is about exposure.

## How to fix

- **Do not expose VNC directly.** Bind it to `localhost` and reach it through an SSH tunnel or VPN, or restrict the port in the firewall to the administrators' addresses.
- Use strong passwords and enable the encryption options of your VNC software.
- **Embedded and industrial HMIs:** follow the vendor's remote-access guidance; plan changes in a maintenance window, because a changed password affects every operator station.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [RFC 6143, The Remote Framebuffer Protocol](https://www.rfc-editor.org/rfc/rfc6143)

[All findings](index.md)
