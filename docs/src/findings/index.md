# Finding reference

Every finding that Network Scope reports has a page here that explains it in plain language: what it means, why it matters, exactly what the tool looked at, when it can be wrong and how to fix it. The finding id (shown in the Findings window, in reports and in exports) is the name of the page.

The pages describe what the scan can observe. A finding is evidence that something deserves a look, not a verdict: several rules work from banners and version text, and the tool never exploits anything. Severities are the ones the program assigns (info, low, medium, high, critical).

Two families have one page each because their ids are built from other data: version-based CVE hints (ids `cve-cve-YYYY-NNNN`, see [Version-based CVE hint](cve-hints.md)) and findings raised by user scripts (ids `script-<id>`, see [Finding raised by a user script](script-findings.md)). The built-in SMBGhost rule `cve-cve-2020-0796` is a special case with its own page.

Hosts imported from Nmap XML go through the same rules by service name and version, so findings can also appear for imported data that this tool did not probe itself.

For how findings are produced and filtered, see [Findings and CVE hints](../findings-and-cves.md).

## TLS and certificates

| Id | Severity | Title | Page |
| --- | --- | --- | --- |
| `tls-cert-expired` | High | TLS certificate has expired | [tls-cert-expired](tls-cert-expired.md) |
| `tls-cert-expiring` | Medium | TLS certificate expires within 30 days | [tls-cert-expiring](tls-cert-expiring.md) |
| `tls-cert-not-yet-valid` | Medium | TLS certificate is not yet valid | [tls-cert-not-yet-valid](tls-cert-not-yet-valid.md) |
| `tls-self-signed` | Low | Self-signed TLS certificate | [tls-self-signed](tls-self-signed.md) |
| `tls-self-signed-bad-signature` | Medium | Certificate claims to be self-signed but its signature does not verify | [tls-self-signed-bad-signature](tls-self-signed-bad-signature.md) |
| `tls-weak-signature` | Medium | Certificate signed with a weak hash | [tls-weak-signature](tls-weak-signature.md) |
| `tls-weak-key` | High | Certificate uses a short RSA key | [tls-weak-key](tls-weak-key.md) |
| `tls-sslv3` | High | SSLv3 is enabled | [tls-sslv3](tls-sslv3.md) |
| `tls-deprecated-protocol` | Medium | Deprecated TLS 1.0/1.1 is enabled | [tls-deprecated-protocol](tls-deprecated-protocol.md) |
| `tls-broken-cipher` | High | Broken TLS cipher suites are accepted | [tls-broken-cipher](tls-broken-cipher.md) |
| `tls-3des` | Medium | 3DES cipher suites are accepted | [tls-3des](tls-3des.md) |
| `tls-no-pfs` | Low | Cipher suites without forward secrecy are accepted | [tls-no-pfs](tls-no-pfs.md) |

## SSH

| Id | Severity | Title | Page |
| --- | --- | --- | --- |
| `ssh-weak-algorithms` | Medium | SSH server offers weak algorithms | [ssh-weak-algorithms](ssh-weak-algorithms.md) |
| `ssh-legacy-algorithms` | Low | SSH server offers legacy algorithms | [ssh-legacy-algorithms](ssh-legacy-algorithms.md) |
| `ssh-protocol-1` | High | SSH protocol 1 in use | [ssh-protocol-1](ssh-protocol-1.md) |

## Cleartext and unauthenticated services

| Id | Severity | Title | Page |
| --- | --- | --- | --- |
| `telnet-open` | High | Telnet exposes credentials in clear text | [telnet-open](telnet-open.md) |
| `ftp-cleartext` | Medium | FTP sends credentials in clear text | [ftp-cleartext](ftp-cleartext.md) |
| `vnc-exposed` | Medium | VNC is reachable | [vnc-exposed](vnc-exposed.md) |
| `mail-cleartext` | Low | Mail retrieval without TLS | [mail-cleartext](mail-cleartext.md) |
| `redis-noauth` | Critical | Redis answers without authentication | [redis-noauth](redis-noauth.md) |
| `memcached-open` | High | memcached answers without authentication | [memcached-open](memcached-open.md) |
| `mqtt-anonymous` | High | MQTT broker accepts anonymous clients | [mqtt-anonymous](mqtt-anonymous.md) |
| `ldap-anonymous` | Low | LDAP answers an anonymous bind | [ldap-anonymous](ldap-anonymous.md) |
| `postgres-no-tls` | Low | PostgreSQL does not offer TLS | [postgres-no-tls](postgres-no-tls.md) |

## Windows and file sharing

| Id | Severity | Title | Page |
| --- | --- | --- | --- |
| `rdp-no-nla` | Medium or High | RDP uses legacy security without TLS or NLA / RDP does not require Network Level Authentication | [rdp-no-nla](rdp-no-nla.md) |
| `smb1-enabled` | High | SMBv1 is enabled | [smb1-enabled](smb1-enabled.md) |
| `smb-signing` | Medium | SMB signing is not required | [smb-signing](smb-signing.md) |
| `smb-no-encryption` | Info | SMB server does not offer encryption | [smb-no-encryption](smb-no-encryption.md) |
| `cve-cve-2020-0796` | High | SMBv3 compression on a Windows build affected by SMBGhost | [cve-cve-2020-0796](cve-cve-2020-0796.md) |

## Web services

| Id | Severity | Title | Page |
| --- | --- | --- | --- |
| `http-basic-cleartext` | Medium | HTTP Basic authentication over an unencrypted connection | [http-basic-cleartext](http-basic-cleartext.md) |
| `docker-api` | Critical | Docker Engine API is exposed | [docker-api](docker-api.md) |
| `heartbleed` | Critical | Server header names a Heartbleed-vulnerable OpenSSL | [heartbleed](heartbleed.md) |
| `php-eol` | Low | PHP release is no longer supported | [php-eol](php-eol.md) |

## Other network services

| Id | Severity | Title | Page |
| --- | --- | --- | --- |
| `snmp-public` | High | SNMP answers the community string 'public' | [snmp-public](snmp-public.md) |
| `netbios-ns` | Low | NetBIOS name service is exposed | [netbios-ns](netbios-ns.md) |
| `upnp-exposed` | Low | UPnP/SSDP is answering | [upnp-exposed](upnp-exposed.md) |

## Industrial (OT)

| Id | Severity | Title | Page |
| --- | --- | --- | --- |
| `ot-reachable` | Medium | Industrial protocol port is reachable from the scanner | [ot-reachable](ot-reachable.md) |
| `ot-control-traffic` | Medium or High | Control traffic observed on an industrial protocol | [ot-control-traffic](ot-control-traffic.md) |

## Generic finding families

| Id | Severity | Title | Page |
| --- | --- | --- | --- |
| `cve-cve-YYYY-NNNN`, for example `cve-cve-2021-41773` | As set by the rule (Info to Critical) | Version-based CVE hint | [cve-hints](cve-hints.md) |
| `script-<id>`, where `<id>` is chosen by the script | As set by the script | Finding raised by a user script | [script-findings](script-findings.md) |
