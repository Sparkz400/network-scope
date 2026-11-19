# SSH server offers legacy algorithms

| | |
| --- | --- |
| Finding id | `ssh-legacy-algorithms` |
| Severity | Low |
| Applies to | TCP ports running SSH |

## What it means

The SSH server also offers older methods that are no longer recommended but are not broken outright: SHA-1 based key exchange or signatures, and CBC-mode ciphers.

## Why it matters

These methods have known weaknesses or are being phased out. They are listed so that you can plan their removal; the practical risk is lower than for the weak methods in `ssh-weak-algorithms`.

## How it is detected

The tool reads the algorithm list the server sends before login (KEXINIT, no authentication) and flags: key exchange `diffie-hellman-group14-sha1` and `diffie-hellman-group-exchange-sha1`; the host key type `ssh-rsa` (RSA with SHA-1 signatures); and ciphers whose name ends in `-cbc` that are not already counted as weak. The evidence lists the matches.

## Possible false positives

- Many servers still list `diffie-hellman-group14-sha1` or CBC ciphers for compatibility with old clients. It is a recommendation, not an incident.

## How to fix

- **OpenSSH:** remove the entries with `KexAlgorithms`, `Ciphers` and `HostKeyAlgorithms` in `sshd_config` (for example prefix a list with `-` to remove entries from the defaults), then reload `sshd`.
- **Network devices and appliances:** use the vendor's SSH settings or update the firmware.
- Check which clients still need the old methods first.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [RFC 4253, SSH transport layer protocol](https://www.rfc-editor.org/rfc/rfc4253)
- [OpenBSD manual, sshd_config](https://man.openbsd.org/sshd_config)
- [OpenSSH legacy options](https://www.openssh.org/legacy.html)

[All findings](index.md)
