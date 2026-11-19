# Server header names a Heartbleed-vulnerable OpenSSL

| | |
| --- | --- |
| Finding id | `heartbleed` |
| Severity | Critical |
| Applies to | TCP ports serving HTTP or HTTPS |

## What it means

The web server's own description of itself mentions an OpenSSL version that was affected by Heartbleed (CVE-2014-0160), a 2014 flaw that let remote clients read chunks of the server's memory, including private keys and passwords.

## Why it matters

If the flaw is present, anyone can steal secrets from the server without leaving traces. A critical severity is assigned because of the impact if the version is genuine; the tool only sees the version text.

## How it is detected

The tool reads the HTTP `Server` header. The finding is raised when it contains `OpenSSL/1.0.1`, with no letter or a lower-case letter up to `f` (1.0.1 to 1.0.1f). The evidence shows the version found. Version 1.0.1g and later are not reported. No Heartbleed request is sent; this is a version-based hint only.

## Possible false positives

- Distributions backported the fix without changing the version string (for example builds labelled `1.0.1e-fips` that contain the patch).
- The header may be a build-time text that does not match the library that is actually linked at run time, or may have been edited.
- OpenSSL builds with the heartbeat feature disabled are not affected.

## How to fix

- **Check the real version:** `openssl version -a` on the host and the package changelog of your distribution (the Debian, Red Hat and Ubuntu security trackers list backports).
- **Upgrade OpenSSL** to a current supported release (1.0.1 has been out of support since 2016) and restart every service that uses it.
- If the server was running an affected version while reachable: reissue and replace its certificates, and rotate passwords and keys that passed through it.
- Hide the version with `ServerTokens Prod` (Apache) or `server_tokens off` (nginx) if you wish, but that only hides it; it does not fix anything.
- Embedded and industrial devices: ask the vendor for a firmware with a fixed OpenSSL and schedule it in a maintenance window.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- After an upgrade the Server header no longer names OpenSSL 1.0.1 and the finding goes away. A backported fix behind an unchanged header leaves the finding in place; keep the result of your check as the record.

## References

- [OpenSSL security advisory of 7 April 2014](https://openssl-library.org/news/secadv/20140407.txt)
- [NVD, CVE-2014-0160](https://nvd.nist.gov/vuln/detail/CVE-2014-0160)

[All findings](index.md)
