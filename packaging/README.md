# Packaging

| Folder | What |
| --- | --- |
| `systemd/` | Units for the monitoring service on Linux ([docs](systemd/README.md)) |
| `winget/` | winget manifests (schema 1.10), package `Sparkz400.NetworkScope`, runs the Inno Setup installer per user or for all users |
| `scoop/` | Scoop manifest with `checkver` and `autoupdate` (portable zip, hash from `SHA256SUMS`) |
| `chocolatey/` | Chocolatey package `network-scope` (runs the installer for all users, checksum from the release) |
| `homebrew/` | Homebrew formula, builds from the release tag's source (macOS) |
| `aur/` | AUR package `network-scope-bin` (prebuilt Linux x86_64 binaries) |

The files in `winget/`, `scoop/`, `chocolatey/`, `homebrew/` and `aur/` are templates: `@VERSION@`, `@SHA256_…@` and `@RELEASE_DATE@` are filled in by `scripts/render_packaging.py`. Every tagged release runs it and attaches the result as `network-scope-<version>-packaging.tar.gz` (listed in `SHA256SUMS` and covered by the provenance), so the files are ready to submit as they are. Nothing is submitted automatically; none of these packages exists in a registry yet.

To render them by hand (for example for an older release):

```sh
# DIST holds the release files; the source hash is of GitHub's tag archive
curl -fsSLO https://github.com/Sparkz400/network-scope/archive/refs/tags/v0.5.1.tar.gz
python -I scripts/render_packaging.py 0.5.1 DIST "$(sha256sum v0.5.1.tar.gz | cut -d' ' -f1)" out
```

## Submitting (maintainer, manual)

Each needs an account of the maintainer; take the files from the release's `network-scope-<version>-packaging.tar.gz`.

- **winget**: fork `microsoft/winget-pkgs`, copy `winget/*.yaml` to `manifests/s/Sparkz400/NetworkScope/<version>/`, run `winget validate --manifest <that folder>` and `winget install --manifest <that folder>` in Windows Sandbox, open a pull request. Later versions: `wingetcreate update Sparkz400.NetworkScope --version <v> --urls <setup url>` or the same copy.
- **Scoop**: create a bucket repository (for example `Sparkz400/scoop-bucket`) with `bucket/network-scope.json`; users run `scoop bucket add network-scope https://github.com/Sparkz400/scoop-bucket` and `scoop install network-scope`. `checkver`/`autoupdate` let Scoop's Excavator action update it. The main `extras` bucket is an alternative once the project is known enough.
- **Chocolatey**: in `chocolatey/`, `choco pack`, then `choco push network-scope.<version>.nupkg --source https://push.chocolatey.org/ --api-key <key>`; the first version goes through moderation (automated checks plus a human review).
- **Homebrew**: create a tap `Sparkz400/homebrew-tap` with `Formula/network-scope.rb`; check it with `brew install --build-from-source Formula/network-scope.rb`, `brew test network-scope` and `brew audit --strict --new network-scope`. homebrew-core needs a notable project (stars, forks, users) and accepts only source builds, which this formula is.
- **AUR**: `git clone ssh://aur@aur.archlinux.org/network-scope-bin.git`, copy `aur/PKGBUILD`, run `makepkg --printsrcinfo > .SRCINFO` (the shipped `.SRCINFO` is written by hand and was not checked with `makepkg`), `makepkg -si` to test, commit both files and push.

## Not a package

- **cargo**: `cargo install --locked --git https://github.com/Sparkz400/network-scope network-scope` (or `cargo install --locked --path .` in a clone) builds and installs both binaries. The crate is not on crates.io: `Cargo.toml` has `publish = false` and depends on `network-scope-core` by path, so both crates would have to be published.
- **Container image**: `ghcr.io/sparkz400/network-scope`, pushed by the `container` job of `release.yml` for every tag ([docs](../docs/src/installation.md#container-image)).
