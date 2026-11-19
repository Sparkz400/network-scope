# MQTT broker accepts anonymous clients

| | |
| --- | --- |
| Finding id | `mqtt-anonymous` |
| Severity | High |
| Applies to | TCP port 1883 |

## What it means

An MQTT message broker (common in building automation, IoT and industrial gateways) accepts a connection without a user name or password.

## Why it matters

Anonymous clients may be able to listen to all messages and publish their own, for example to send commands to devices. Whether they can depends on the broker's topic rules, which the tool does not test.

## How it is detected

On port 1883 the tool sends an MQTT 3.1.1 CONNECT packet without credentials and with an empty client identifier, then reads the acknowledgement. A "connection accepted" result raises the finding; the evidence is the service description. The tool disconnects without subscribing or publishing. Brokers on the TLS port (8883) are not covered.

## Possible false positives

- A broker that accepts the connection but denies every topic to anonymous clients through access rules. The tool cannot see those rules.

## How to fix

- **Require authentication** and per-topic access rules. **Mosquitto:** `allow_anonymous false`, a `password_file` and an ACL file.
- Offer TLS (port 8883), ideally with client certificates, and close the plain port.
- **Industrial and building gateways:** publishers and subscribers must be given credentials at the same time; schedule the change in a window and follow the vendor's documentation.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [OASIS, MQTT version 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/mqtt-v3.1.1.html)
- [Eclipse Mosquitto, authentication methods](https://mosquitto.org/documentation/authentication-methods/)

[All findings](index.md)
