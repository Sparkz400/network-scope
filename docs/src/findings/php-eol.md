# PHP release is no longer supported

| | |
| --- | --- |
| Finding id | `php-eol` |
| Severity | Low |
| Applies to | TCP ports serving HTTP or HTTPS |

## What it means

The web server announces a PHP version whose upstream support has ended. Releases that are out of support no longer get security fixes from the PHP project.

## Why it matters

Known flaws in old PHP versions stay unfixed, and attackers scan for such servers.

## How it is detected

The tool reads the `X-Powered-By: PHP/x.y.z` response header and checks the branch (for example 8.1) against a table of end-of-life dates built into the program (`PHP_EOL` in `risk.rs`, last reviewed 2026-11). The finding is raised when the branch's date lies before today's date, or when the branch is older than the oldest entry in the table. Branches that are not in the table, for example newer ones, are never reported. The evidence shows the version and the end-of-life date. "Today" is the date when the findings are computed, so analysing an old scan later can raise this finding.

## Possible false positives

- Distributions and vendors with extended support (for example enterprise Linux or paid long-term support) keep fixing old PHP versions while the header still shows the upstream version number.
- For branches older than the table, the evidence gives the oldest table date (“before ...”) rather than the true end-of-life date.
- Servers that hide the header (`expose_php = Off`) are not reported at all.

## How to fix

- **Upgrade to a supported PHP branch** (see php.net/supported-versions) after testing the application; or use the distribution's supported package stream.
- If an old version must stay: confirm that your vendor still backports fixes, and keep the server isolated.
- Set `expose_php = Off` in `php.ini` to stop announcing the version; this reduces information leakage but does not make the version safe.
- **Industrial and embedded devices (OT):** settings like this can often only be changed with the vendor's tools or a firmware update. Follow the vendor's guidance, try the change on a spare unit first, and apply it in an agreed change window with the plant operators informed; a changed setting can interrupt communication with a running process.
- The finding goes away when the header shows a supported PHP branch or no version. A vendor-supported old branch keeps showing the old version and stays flagged.

## References

- [PHP, supported versions](https://www.php.net/supported-versions.php)

[All findings](index.md)
