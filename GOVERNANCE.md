# Governance

Network Scope is a small, volunteer-run open source project under the [MIT license](LICENSE.txt). This document says who decides what, which roles exist and what each role is responsible for.

## Model

The project uses a **maintainer-led** model. The maintainers make the final decision on every change, release and policy. Until there is more than one maintainer, that is one person (see [Current role holders](#current-role-holders)).

Decisions are made in public wherever possible:

- **Changes** are proposed as pull requests. A pull request is merged when CI passes and a maintainer approves it. The rules every change must follow are in [CONTRIBUTING.md](CONTRIBUTING.md), including the [safety rules for probes](CONTRIBUTING.md#safety-rules-for-new-probes-and-features) and the [testing policy](CONTRIBUTING.md#testing-policy).
- **Features and direction** are discussed in issues and [Discussions](https://github.com/Sparkz400/network-scope/discussions). The [roadmap](ROADMAP.md) records what is planned and what was declined, with the reason.
- **Security reports** are handled privately as described in [SECURITY.md](SECURITY.md) and published as GitHub security advisories once fixed.
- **Disagreements** are settled by discussion. If that does not reach agreement, the maintainers decide and write down the reason in the issue or pull request. With two or more maintainers, they decide by consensus; if they cannot agree, the change is not made.

Some decisions are not open for a vote, because they are what makes the tool safe to use on industrial networks: OT protocol code stays read-only, transmitting features stay opt-in, and the project has no telemetry.

## Roles and responsibilities

| Role | Who | Responsibilities |
| --- | --- | --- |
| **Maintainer** | Listed below; has admin rights on the repository | Reviews and merges pull requests; triages issues; cuts releases (tag, CHANGELOG section, checking the release workflow); answers security reports within the times in SECURITY.md; keeps CI, dependencies and documentation current; enforces the [Code of Conduct](CODE_OF_CONDUCT.md). |
| **Security contact** | The maintainers | Receives private vulnerability reports, coordinates the fix and the disclosure, credits the reporter, publishes the advisory. |
| **Release manager** | A maintainer | Only maintainers can push `v*` tags; a tag starts `.github/workflows/release.yml`, which builds, signs and publishes the release. |
| **Reviewer** | Any contributor a maintainer asks to review, listed in `.github/CODEOWNERS` once there are more | Reviews pull requests in their area against CONTRIBUTING.md. A reviewer's approval counts towards merging; merging stays with a maintainer. |
| **Contributor** | Anyone | Opens issues, discussions and pull requests following CONTRIBUTING.md and the Code of Conduct. |

### Current role holders

| Role | Person |
| --- | --- |
| Maintainer, security contact, release manager | [@Sparkz400](https://github.com/Sparkz400) |
| Reviewer | none yet |

### Becoming a reviewer or maintainer

A contributor with several merged, non-trivial pull requests who has shown they follow the safety rules can be invited as a reviewer. A reviewer who has been active for some months can be invited as a maintainer. The existing maintainers decide on the invitation; the change is made in this file by pull request. A maintainer who is inactive for 12 months, or who asks to step down, moves to an emeritus list here.

## Continuity

The project must be able to keep going if one person is no longer able or willing to work on it: within a week, someone must be able to create and close issues, accept changes and publish a release.

Status (November 2026): **the project has a single maintainer, so its bus factor is 1.** The plan to change that, in order:

1. **Account successor.** The maintainer designates a GitHub [account successor](https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-personal-account-on-github/managing-access-to-your-personal-repositories/maintaining-ownership-continuity-of-your-personal-accounts-repositories), who can take over the repository if the maintainer's account becomes inactive. This file will name the successor once designated.
2. **Second maintainer.** The project wants a second maintainer with admin rights, so releases and security fixes do not depend on one person. If you are interested, open a discussion.

Nothing except the repository itself is needed to continue the project: the website is GitHub Pages built from `docs/`, releases are built and signed by GitHub Actions with keyless (Sigstore) signing, and there are no private signing keys, domains or servers to hand over.
