# Script library

Read-only [Rhai](https://rhai.rs) scripts for Network Scope. They are embedded in the program (`network-scope-cli scripts list`), so an installed copy has them without this folder.

- `*.rhai` define `fn on_host(h)` and run against every scanned host: `scan TARGETS --script library:NAME`.
- `on-alert/*.rhai` define `fn on_alert(a)` and run when a monitor alert fires: `monitor TARGETS --on-alert library:NAME`.

Every script starts with a header comment: `name`, `description`, `safety` and `kind` (`host` or `alert`). The rules for a new script:

1. **Read-only.** A script reads the scan result or the alert. It never sends traffic and never tries a login; "default credentials" scripts only point at devices worth checking by hand.
2. Read the identity keys the engine actually writes (see `docs/src/detection.md`), not invented ones, and say in the header which scan options a script needs.
3. Add the script to `LIBRARY` or `ALERT_LIBRARY` in `core/src/script.rs` and a positive and a clean case to the tests there (`library_scripts_fire_on_a_positive_host_and_stay_silent_on_a_clean_one`); a test fails when a file here is missing from the table or has no test case.

The API is documented in [docs/src/scripting.md](../../docs/src/scripting.md).
