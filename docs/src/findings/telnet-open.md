# Telnet exposes credentials in clear text

| | |
| --- | --- |
| Finding id | `telnet-open` |
| Severity | High |
| Applies to | TCP ports running Telnet |

## What it means

A Telnet service is reachable. Telnet sends everything, including the user name and password, without encryption.

## Why it matters

Anyone who can observe the network path (a compromised device, a mirrored switch port, an attacker on the same segment) can read the credentials and the whole session, and take over the device with them. Telnet also has no protection against tampering.

## How it is detected

Service detection identifies Telnet from the data the server sends right after the connection is made: the protocol's option negotiation bytes. Only an identified Telnet service counts. A port that is merely open on 23 and returned nothing is shown as "unidentified (port suggests telnet)" and is not reported here. Services imported from Nmap XML count if Nmap named them `telnet`. The evidence is the service description.

## Possible false positives

- A service that uses Telnet-style negotiation bytes for something that is not a login shell.
- Not a false positive, but not caught: a Telnet service that sends nothing until the client speaks is not identified.

## How to fix

- **Disable the Telnet service and use SSH** instead. Linux: `systemctl disable --now telnet.socket` (or the matching service name) and install an SSH server. Windows: remove the optional feature `TelnetServer`.
- **Network devices and appliances:** turn Telnet off in the management configuration and allow SSH only (on IOS-style devices `transport input ssh` on the VTY lines).
- If Telnet cannot be disabled, restrict it to a dedicated management network with access lists and plan the replacement.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [RFC 854, Telnet protocol specification](https://www.rfc-editor.org/rfc/rfc854)

[All findings](index.md)
