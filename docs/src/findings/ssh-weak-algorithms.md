# SSH server offers weak algorithms

| | |
| --- | --- |
| Finding id | `ssh-weak-algorithms` |
| Severity | Medium |
| Applies to | TCP ports running SSH |

## What it means

The SSH server advertises encryption or key-exchange methods that are considered broken, for example 1024-bit Diffie-Hellman with SHA-1, DSA host keys, RC4/3DES/Blowfish ciphers or MD5-based integrity checks. A client may end up using one of them.

## Why it matters

Weak methods can allow an attacker in the network path to read or alter an SSH session. When the Terrapin hint is shown, an attacker who can intercept the connection may be able to remove messages at the start of a session (CVE-2023-48795).

## How it is detected

The SSH server sends its list of supported algorithms (the KEXINIT message) to every client before any login. The tool reads that list; it does not authenticate. Entries are flagged as weak when they match:

- key exchange `diffie-hellman-group1-sha1`;
- host key `ssh-dss`;
- ciphers containing `arcfour`, `3des`, `des-cbc`, `blowfish` or `cast128`, or `none`;
- MACs containing `md5` or `-96`, starting with `umac-64`, or `none`;
- the Terrapin condition: ChaCha20-Poly1305, or a CBC cipher together with an encrypt-then-MAC (`-etm`) MAC, is offered while the server does not list the strict key exchange marker (`kex-strict-s-v00@openssh.com`).

The evidence lists the matches. CVE-2023-48795 is attached only when the Terrapin condition applies. This is a statement about what the server offers, not about what a particular client negotiates.

## Possible false positives

- A server that offers a weak method last, for old clients only, and never selects it for modern ones. It is still reachable by a client that asks for it.
- Terrapin: the condition is derived from the offered algorithms and the strict key exchange marker. Whether an attack is possible also depends on the client; the finding is a hint to update, not a proof.

## How to fix

- **OpenSSH (Linux, BSD, macOS, Windows):** limit the algorithms in `sshd_config` (`KexAlgorithms`, `Ciphers`, `MACs`, `HostKeyAlgorithms`) and reload `sshd`. `sshd -T` prints the effective values. On Windows the file is `%ProgramData%\ssh\sshd_config`.
- **Terrapin:** update to OpenSSH 9.6 or later, or to a vendor release that includes strict key exchange, on both server and clients.
- **Network devices and appliances:** look for an SSH cipher or algorithm setting in the vendor's documentation, or update the firmware.
- Check first which clients and automation still need the old methods, so that nothing breaks unannounced.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After the change, scan the host again to confirm that the finding is gone.

## References

- [RFC 4253, SSH transport layer protocol](https://www.rfc-editor.org/rfc/rfc4253)
- [OpenBSD manual, sshd_config](https://man.openbsd.org/sshd_config)
- [OpenSSH 9.6 release notes (strict key exchange)](https://www.openssh.org/txt/release-9.6)
- [NVD, CVE-2023-48795 (Terrapin)](https://nvd.nist.gov/vuln/detail/CVE-2023-48795)

[All findings](index.md)
