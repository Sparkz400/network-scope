<!--
Use this template for changes to data/probes.json (new service fingerprints and probes):
add ?template=fingerprint.md to the new pull request URL.
See docs/src/contributing-fingerprints.md. Network Scope sends no telemetry; you decide what to share.
-->

## What does this identify?

<!-- Product, model and firmware or version. Port and protocol. -->

## Where did the banner come from?

- [ ] My own lab or a device I own or am allowed to share data about
- [ ] Not from a production network I do not own

<!-- A short description is enough ("lab, firmware 2.1.4"). Do not name customers or sites. -->

## Evidence

<!-- The banner or reply, redacted (hex for binary replies). The reviewed output of
`network-scope-cli fingerprints export-unknown` works well. -->

```text

```

## Checklist

- [ ] `network-scope-cli probes lint` and `probes validate data/probes.json` report 0 errors
- [ ] A test in `core/src/service/probes.rs` matches the banner above to the expected service, product and version (and a similar banner that must not match)
- [ ] The data above contains no real IP or MAC addresses, host names, user names, serial numbers or site names
- [ ] If this adds a probe that sends data: it asks only (no write, delete, login, mail or control verbs), is at most a few dozen bytes, and does not list an industrial or printer port (CONTRIBUTING.md, safety rule 4)
- [ ] The probe is documented: what is sent, to which ports
- [ ] The source is my own work, or its license allows MIT and it is recorded in `data/README.md`
- [ ] Not tested on real devices other than those named above (say which)
