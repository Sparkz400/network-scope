# Contributing to Network Scope

Thanks for your interest. Bug reports, protocol samples, documentation fixes and pull requests are welcome.

- **Questions** go to [GitHub Discussions](https://github.com/Sparkz400/network-scope/discussions), not issues. See [SUPPORT.md](SUPPORT.md).
- **Security issues** go through private reporting; see [SECURITY.md](SECURITY.md).
- Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).

For larger changes, open an issue or discussion first so we can agree on the approach.

## Building and testing

The Rust version is pinned in `rust-toolchain.toml`; rustup installs it on the first `cargo` command. On Linux install the GUI build dependencies listed in [docs/src/installation.md](docs/src/installation.md#build-from-source). `.editorconfig` sets line endings and indentation for editors that support it.

The quickest start is the dev container (`.devcontainer/`): open the repository in GitHub Codespaces or with VS Code's Dev Containers extension and everything above is installed for you, including Python for the lab simulators. The desktop GUI needs a display, so in a container work on the CLI, the engine and the tests.

```sh
cargo build --locked
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --check
```

End-to-end check against the lab simulators (Python 3, standard library only):

```sh
cargo build --release --locked
python lab/verify.py target/release/network-scope        # .exe on Windows
```

Dependency checks (RustSec advisories, licenses, sources), the same ones the `security` workflow runs:

```sh
cargo install --locked cargo-deny cargo-audit
cargo deny check
cargo audit
```

The `secrets` workflow scans the whole git history with [gitleaks](https://github.com/gitleaks/gitleaks) on every push; run `gitleaks git .` locally before pushing if you handle configs or captures. A new dependency must use a license from the `allow` list in `deny.toml`; if it needs another one, say so in the pull request.

CI runs all of the above on Windows, Linux and macOS. A pull request must pass CI.

Documentation lives in `docs/src` (mdBook). Preview it with `mdbook serve docs` if you have [mdBook](https://rust-lang.github.io/mdBook/) installed. Keep pages plain Markdown with relative links between them.

## Fuzzing

Every parser of network or file input has a [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) target in `fuzz/fuzz_targets` (a one-line call into `src/fuzz.rs`) and seeds in `fuzz/corpus/<target>`. cargo-fuzz needs a nightly toolchain (the pinned stable one is used for everything else):

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked
cd fuzz
cargo +nightly fuzz list
# a scratch corpus first, so new inputs do not land in the committed seeds
mkdir -p /tmp/corpus-pcapfile
cargo +nightly fuzz run -O -a pcapfile /tmp/corpus-pcapfile corpus/pcapfile -- -max_total_time=60
```

`-a` turns on overflow checks and `debug_assert!`. On Windows (MSVC) the AddressSanitizer runtime must be on `PATH`: add the `VC/Tools/MSVC/<version>/bin/Hostx64/x64` folder of your Visual Studio installation, or the target exits with `STATUS_DLL_NOT_FOUND`.

A crash input is written to `fuzz/artifacts/<target>/`; reproduce it with `cargo +nightly fuzz run <target> <file>`. Fix the parser (bounded, no panics on untrusted data), add a unit test with the input next to the parser, and copy the input into `fuzz/corpus/<target>/` so `seed_corpus_runs_cleanly` keeps checking it. A new parser gets a new entry in `TARGETS` in `src/fuzz.rs`, a target file, a `[[bin]]` in `fuzz/Cargo.toml` and a few small seeds; a unit test checks that these match. ClusterFuzzLite (`.github/workflows/cflite.yml`, `.clusterfuzzlite/`) builds the same targets on Linux.

## Safety rules for new probes and features

Network Scope is used on industrial networks. Every change that sends traffic must follow these rules; reviews will check them.

1. **Opt-in.** New transmitting behaviour is off by default and enabled by an explicit option or Settings checkbox.
2. **Rate gate.** Every transmitted probe goes through the scheduler's rate gate (one token per packet, retransmits included) and respects the global in-flight bounds. No side channels that bypass `--rate` or Safe Mode spacing.
3. **Safe Mode.** Anything beyond a single connection or a single read-only request per port must be disabled in Safe Mode, with the GUI control greyed out and the behaviour documented.
4. **Never OT or printer ports.** Generic TCP and UDP probes, traceroute ports and user probe files must never send to industrial ports (the OT port list in the code, including 2222, 2221-2223, 47808-47823, 34962-34964, 20000, 1089-1091, 5006/5007, 1740-1743, 34980, 17185) or printer ports (515, 9100-9107). Extend the existing deny lists rather than adding new ones.
5. **OT is read-only.** OT protocol code may only send identification requests. No writes, no program/block access, no control or diagnostic commands that change state, no authentication attempts.
6. **Passive modules are send-free.** `otpassive`, `pcapfile` and the `PassiveCapture` wrapper in `capture` must not contain socket or send code; the test `this_module_cannot_transmit` enforces this. Do not weaken it, and keep the passive listener (`passive`) receive-only as well.
7. **Bounded parsing.** Every parser of network or file input must bound lengths, counts and recursion and must never panic on malformed input. Add a test with truncated and oversized input, and a fuzz target (see [Fuzzing](#fuzzing)).
8. **Honest documentation.** Document what a probe sends, and state plainly what has not been tested against real devices.

## Adding data

- **Service probes** (`data/probes.json`) and **CVE rules** (`data/cves.json`): add a test that exercises the new rule. CVE rules are version-based hints; cite the CVE ids.
- **Protocol samples** for new OT decoders are welcome as small, **sanitized** pcap files (no real addresses, names or process data). Use the protocol support issue template.
- Do not copy code or data from other projects without checking that the license is compatible with MIT, and record the source in `data/README.md` or `THIRD-PARTY-NOTICES.md`.

## Commit style

- Short imperative subject line (about 72 characters max), e.g. `TLS: report truncated suite lists`; an optional area prefix (`Engine:`, `GUI:`, `OT:`) helps.
- A body explaining *why* when it is not obvious.
- One logical change per commit; keep formatting-only changes separate.
- Update `CHANGELOG.md` under `[Unreleased]` for user-visible changes.

## License

By contributing you agree that your contributions are licensed under the [MIT license](LICENSE.txt).
