# Finding raised by a user script

| | |
| --- | --- |
| Finding id | `script-<id>`, where `<id>` is chosen by the script |
| Severity | As set by the script |
| Applies to | Hosts processed by a user script |

## What it means

A script that you or your organisation added to Network Scope produced this finding. The program itself has no opinion about it: the id, severity, title and evidence come from the script.

## Why it matters

Scripts express site policies such as "Telnet is not allowed" or "this host must not run a web server". The importance of a finding therefore depends on that policy.

## How it is detected

A script calls `h.finding("severity", "id", "title", "evidence")`. The result is stored with the host and reported with the id `script-` plus the id given by the script, no port, the severity given (an unknown severity becomes info), and the advice "Raised by a user script". A `|` character in the title is replaced by `/`. See the Scripting page for the script interface.

## Possible false positives

- Depends entirely on the script's logic.

## How to fix

- Follow the policy that the script's author encoded. The script's source (and its comments) is the place to find out what it checks and why.
- To change or remove the finding, edit the script.

## References

- [Scripting](../scripting.md)

[All findings](index.md)
