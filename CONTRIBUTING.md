# Contributing to Network Scope

Thanks for your interest. Bug reports, protocol samples, documentation fixes and pull requests are welcome.

- **Questions** go to [GitHub Discussions](https://github.com/Sparkz400/network-scope/discussions), not issues. See [SUPPORT.md](SUPPORT.md).
- **Security issues** go through private reporting; see [SECURITY.md](SECURITY.md).
- Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).

For larger changes, open an issue or discussion first so we can agree on the approach.

## Project layout

The repository is a Cargo workspace with two crates; plain `cargo build`, `cargo test` and `cargo clippy` cover both.

- `core/` is `network-scope-core`, the engine without any GUI code: scanning, parsers, risk analysis, the SQLite store, reports, monitoring, passive OT discovery. Other tools can depend on it; its crate documentation (`cargo doc -p network-scope-core --open`) lists the entry points. It embeds `data/` (service probes, CVE rules, vendor lists) at compile time.
- The root package `network-scope` is the application: `src/gui/` (egui desktop app) and `src/ui/` (CLI and TUI). Engine code never depends on these, so a change to the engine belongs in `core/`.
- The GUI is the cargo feature `gui` (on by default). `cargo build --no-default-features --bin network-scope-cli` builds the CLI/TUI without any GUI crate (CI checks it on Linux without the window-system packages); keep `src/ui/` and `core/` free of GUI types.
- Adding a CLI command: create `src/ui/commands/<name>.rs` and register it in `src/ui/commands/mod.rs`; the module documentation in `src/ui/mod.rs` has the steps (options go in `src/ui/args.rs`, the help text in `src/ui/help.rs`).

## Building and testing

The Rust version is pinned in `rust-toolchain.toml`; rustup installs it on the first `cargo` command. On Linux install the GUI build dependencies listed in [docs/src/installation.md](docs/src/installation.md#build-from-source). `.editorconfig` sets line endings and indentation for editors that support it.

The quickest start is the dev container (`.devcontainer/`): open the repository in GitHub Codespaces or with VS Code's Dev Containers extension and everything above is installed for you, including Python for the lab simulators. The desktop GUI needs a display, so in a container work on the CLI, the engine and the tests.

```sh
cargo build --locked
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --check
```

Git hooks run the quick part of this for you. Turn them on once per clone with `git config core.hooksPath .githooks`: `pre-commit` runs `cargo fmt --check` when a commit stages Rust code, and `pre-push` runs clippy and the tests of the crates the pushed commits can reach (only the root crate when just `src/` or `tests/*.rs` changed; nothing when no file a Rust build or test reads changed). CI still runs everything, in release mode on three platforms; `git push --no-verify` skips the hook, not CI.

End-to-end check against the lab simulators (Python 3, standard library only):

```sh
cargo build --release --locked
python lab/verify.py target/release/network-scope        # .exe on Windows
```

Accuracy benchmark against the ground truth in `lab/ground_truth.json` (needs an absolute path to the CLI; CI fails when a metric drops below `lab/benchmark_baseline.json`, see [Lab and testing](docs/src/lab-and-testing.md#accuracy-benchmark)):

```sh
python -I lab/benchmark.py --cli /absolute/path/to/target/release/network-scope-cli --check
```

Comparison with nmap on the same lab (needs nmap on `PATH`; exit code 1 when a difference between the two tools is not explained in `lab/nmap_differences.json`, see [Lab and testing](docs/src/lab-and-testing.md#comparison-with-nmap)):

```sh
python -I lab/nmap_compare.py --cli /absolute/path/to/target/release/network-scope-cli --explain lab/nmap_differences.json
```

Tests of the lab scripts (Python standard library only), and the checks against real servers (Samba, OpenSSH, OpenSSL, nginx, the NVD CPE dictionary), which run in the CI job `real-servers` and are described in [Lab and testing](docs/src/lab-and-testing.md#real-servers):

```sh
python -I -m unittest discover -s lab -p "test_*.py"
python -I lab/check_cpe.py                 # format of the CPE table only; --download compares with NVD
cargo test -p network-scope-core windows_schannel -- --ignored   # Windows with PowerShell 7
```

Performance: `cargo bench -p network-scope-bench` runs the criterion benchmarks of the hot paths (`bench/benches`); pull requests are compared with the base branch by the `bench` workflow and fail above +15 %, see [Lab and testing](docs/src/lab-and-testing.md#performance-tests). Resource budgets (startup, memory, GUI frame): `python -I scripts/resource_budget.py --cli /absolute/path/to/network-scope-cli --check`.

Dependency checks (RustSec advisories, licenses, sources), the same ones the `security` workflow runs:

```sh
cargo install --locked cargo-deny cargo-audit
cargo deny check
cargo audit
```

The `secrets` workflow scans the whole git history with [gitleaks](https://github.com/gitleaks/gitleaks) on every push; run `gitleaks git .` locally before pushing if you handle configs or captures. A new dependency must use a license from the `allow` list in `deny.toml`; if it needs another one, say so in the pull request.

CI runs all of the above on Windows, Linux and macOS. A pull request must pass CI.

Documentation lives in `docs/src` (mdBook). Preview it with `mdbook serve docs` if you have [mdBook](https://rust-lang.github.io/mdBook/) installed. Keep pages plain Markdown with relative links between them. Every finding rule id in `core/src/risk.rs` needs a page `docs/src/findings/<id>.md` (same sections as the existing pages, listed in `SUMMARY.md` and `findings/index.md`); `python -I docs/check_finding_pages.py` checks this and runs in CI. Every rule id also needs a case in `core/src/risk_budget.rs` (a host that must trigger it and a near miss that must not); a test fails when a rule id in `risk.rs` has none.

## Testing policy

These rules are mandatory for every pull request. Reviews check them, and a pull request that breaks them is not merged.

- **New functionality comes with automated tests** in the same pull request: unit tests next to the code, and for scanning or detection features a lab case (`lab/`) where one is possible. A feature that cannot be tested automatically, for example one that needs real hardware, says so in the pull request and in its documentation.
- **Bug fixes come with a regression test** that fails before the fix and passes after it, unless that is impractical (say why in the pull request).
- **Parsers of untrusted input** also get truncated and oversized test input and a fuzz target (see [Fuzzing](#fuzzing)).
- **Coverage must not drop.** The `coverage` job fails when a gated file falls below its threshold in `scripts/coverage_targets.json`. The target for the workspace as a whole is at least 80% line coverage (86% in November 2026); the job's report shows the total.
- **All tests run in CI** on Windows, Linux and macOS on every push and pull request. A red CI blocks the merge.

The project's governance, roles and decision-making are described in [GOVERNANCE.md](GOVERNANCE.md).

## Fuzzing

The parsers of network replies and imported files have [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets in `fuzz/fuzz_targets` (`cargo +nightly fuzz list` shows them) (a one-line call into `core/src/fuzz.rs`) and seeds in `fuzz/corpus/<target>`. cargo-fuzz needs a nightly toolchain (the pinned stable one is used for everything else):

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

A crash input is written to `fuzz/artifacts/<target>/`; reproduce it with `cargo +nightly fuzz run <target> <file>`. Fix the parser (bounded, no panics on untrusted data), add a unit test with the input next to the parser, and copy the input into `fuzz/corpus/<target>/` so `seed_corpus_runs_cleanly` keeps checking it. A new parser gets a new entry in `TARGETS` in `core/src/fuzz.rs`, a target file, a `[[bin]]` in `fuzz/Cargo.toml` and a few small seeds; a unit test checks that these match. ClusterFuzzLite (`.github/workflows/cflite.yml`, `.clusterfuzzlite/`) builds the same targets on Linux.

## Safety rules for new probes and features

Network Scope is used on industrial networks. Every change that sends traffic must follow these rules; reviews will check them.

1. **Opt-in.** New transmitting behaviour is off by default and enabled by an explicit option or Settings checkbox.
2. **Rate gate.** Every transmitted probe goes through the scheduler's rate gate (one token per packet, retransmits included) and respects the global in-flight bounds. No side channels that bypass `--rate` or Safe Mode spacing.
   A new kind of packet is also registered with the dry run and the sent log: add (or reuse) a `PacketKind` in `core/src/sendlog.rs`, take the token with `Gate::wait_for(kind, detail)` / `Gate::try_take_for` (or `Gate::note` for a payload on an already-gated connection; OT requests record themselves through `OtStream`/`OtUdp::with_log`), and list the same `(kind, detail)` in `plan::host` (`core/src/plan.rs`). A test runs a real scan and fails when something was sent that the plan does not list, and another fails on a bare `gate.wait()` in a sender.
3. **Safe Mode.** Anything beyond a single connection or a single read-only request per port must be disabled in Safe Mode, with the GUI control greyed out and the behaviour documented.
4. **Never OT or printer ports.** Generic TCP and UDP probes, traceroute ports and user probe files must never send to industrial ports (the OT port list in the code, including 2222, 2221-2223, 47808-47823, 34962-34964, 20000, 1089-1091, 5006/5007, 1740-1743, 34980, 17185) or printer ports (515, 9100-9107). Extend the existing deny lists rather than adding new ones.
5. **OT is read-only.** OT protocol code may only send identification requests. No writes, no program/block access, no control or diagnostic commands that change state, no authentication attempts. This is enforced by types: build requests only with the allow-listed request types in `core/src/ot/readonly.rs` and send them only through `OtStream::send` / `OtUdp::send` (TCP and UDP) or `DcpFrameTx::send` (the layer-2 DCP Identify frame), never with a raw socket write or a raw `Capture::send`. Adding a variant to an allow-list enum (and the matching test expectation) needs an explicit review; the tests in that module check every function code byte.
6. **Passive modules are send-free.** `otpassive`, `pcapfile` and the `PassiveCapture` wrapper in `capture` must not contain socket or send code; the test `this_module_cannot_transmit` enforces this. Do not weaken it, and keep the passive listener (`passive`) receive-only as well.
7. **Bounded parsing.** Every parser of network or file input must bound lengths, counts and recursion and must never panic on malformed input. Add a test with truncated and oversized input, and a fuzz target (see [Fuzzing](#fuzzing)).
8. **Honest documentation.** Document what a probe sends, and state plainly what has not been tested against real devices.

## Adding data

- **Service probes** (`data/probes.json`) and **CVE rules** (`data/cves.json`): add a test that exercises the new rule. CVE rules are version-based hints; cite the CVE ids. For probes see [Contributing fingerprints](docs/src/contributing-fingerprints.md): collect banners with `network-scope-cli fingerprints export-unknown` (local only, no upload; read and redact the file), check the change with `network-scope-cli probes lint` and `probes validate FILE` (CI runs the lint on `data/probes.json`; it rejects payloads for OT and printer ports, write-like verbs, long payloads and nested regex quantifiers), and open the pull request with `?template=fingerprint.md`. Network Scope has no telemetry and will not get any.
- **Protocol samples** for new OT decoders are welcome as small, **sanitized** pcap files (no real addresses, names or process data). Use the protocol support issue template.
- Do not copy code or data from other projects without checking that the license is compatible with MIT, and record the source in `data/README.md` or `THIRD-PARTY-NOTICES.md`.

## Commit style

- Short imperative subject line (about 72 characters max), e.g. `TLS: report truncated suite lists`; an optional area prefix (`Engine:`, `GUI:`, `OT:`) helps.
- A body explaining *why* when it is not obvious.
- One logical change per commit; keep formatting-only changes separate.
- Update `CHANGELOG.md` under `[Unreleased]` for user-visible changes.
- Sign off every commit with `git commit -s` (see [Developer Certificate of Origin](#developer-certificate-of-origin)).

## License

By contributing you agree that your contributions are licensed under the [MIT license](LICENSE.txt).

### Developer Certificate of Origin

Every commit in a pull request must carry a `Signed-off-by: Your Name <email>` line, which `git commit -s` adds. With it you certify the [Developer Certificate of Origin 1.1](https://developercertificate.org/): you wrote the change, or otherwise have the right to submit it under the project's license. Use your real name or a consistent pseudonym you are known by. Forgot it? `git commit --amend -s` fixes the last commit, `git rebase --signoff main` all commits of the branch.
