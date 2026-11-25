## What and why

<!-- What does this change, and why? Link the issue: "Fixes #123". -->

## How it was tested

<!-- Tests added, lab/verify.py, real devices (which?), platforms. Say what was NOT tested. -->

## Checklist

- [ ] `cargo test --locked` passes
- [ ] `cargo clippy --all-targets --locked -- -D warnings` passes
- [ ] `cargo fmt --check` passes
- [ ] Every commit is signed off (`git commit -s`, [DCO](https://developercertificate.org/))
- [ ] New behaviour has tests (parsers: truncated and oversized input)
- [ ] Docs in `docs/src` and `CHANGELOG.md` (`[Unreleased]`) updated for user-visible changes
- [ ] No real IP addresses, MAC addresses, host names or captures from production networks in code, tests or fixtures

### If this change sends network traffic

- [ ] Opt-in (off by default)
- [ ] Every probe goes through the rate gate and respects the in-flight bounds
- [ ] Disabled or reduced in Safe Mode, GUI control greyed out
- [ ] Never sends to OT or printer ports (generic probes, UDP, traceroute)
- [ ] OT code sends read-only identification requests only
- [ ] Passive modules remain send-free
- [ ] Documented what is sent
