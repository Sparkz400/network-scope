# Code signing policy

Free code signing provided by [SignPath.io](https://signpath.io), certificate by [SignPath Foundation](https://signpath.org).

**Status:** the project has applied, or is about to apply, to SignPath Foundation. Until a release says in its notes that it was signed this way, the Windows files of Network Scope are not code-signed, and SmartScreen warns when you start them. See [Supply chain: Code signing](supply-chain.md#code-signing) for how signing is set up.

## What is signed

Only files built from this repository's source by its own release workflow:

- `network-scope.exe` (desktop app) and `network-scope-cli.exe` (command line), as shipped in `network-scope-<version>-windows-x64.zip` and in the installer;
- the installer `NetworkScope-<version>-setup.exe`.

The release workflow (`.github/workflows/release.yml`) runs on GitHub-hosted runners when a version tag `v*` is pushed. It builds the binaries, uploads the unsigned files as an artifact of that run, and submits them to SignPath. SignPath checks that the artifact comes from a workflow run of this repository (origin verification) before signing. Third-party programs, libraries in other repositories and files built anywhere else are never signed with this certificate. The uninstaller inside the installer (`unins000.exe`) is not signed.

## Team roles

| Role | Who |
| --- | --- |
| Committers and reviewers | Members of the [Sparkz400/network-scope](https://github.com/Sparkz400/network-scope) repository with write access. Changes reach `main` only through pull requests that pass CI. |
| Approvers | The repository owner ([Sparkz400](https://github.com/Sparkz400)). Every signing request of a release is approved by hand in SignPath before anything is signed. |

All team members use multi-factor authentication for GitHub and for SignPath.

## Privacy policy

This program will not transfer any information to other networked systems unless specifically requested by the user or the person installing or operating it.

What that means for Network Scope:

- **Scans** send packets only to the targets you enter, as documented per scan type ([Safe Mode](safe-mode-and-ot-safety.md), `--dry-run` lists every packet type in advance). Passive modes send nothing.
- **Alerts** go to a webhook or syslog server only when you configure one (`--webhook`, `--syslog`); see [Monitoring and alerts](monitoring-alerts.md#alert-delivery).
- **The update check** asks GitHub's API whether a newer release exists, only when you run `update check` or turn the check on in the desktop app; it never downloads anything. See [Checking for updates](installation.md#checking-for-updates).
- There is **no telemetry**: scan results, banners and statistics are never sent anywhere. Feeds (CISA KEV, EPSS, NVD, CSAF) are imported from files you downloaded yourself.

## Reporting a misuse

If you find a file signed with this project's certificate that was not built from this repository, or a signed release behaving against this policy, report it through the [security policy](https://github.com/Sparkz400/network-scope/security/policy) and to [SignPath Foundation](https://signpath.org).
