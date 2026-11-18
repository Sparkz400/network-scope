# Notes from the GUI/CLI/TUI feature wave (requests for files outside ui/gui/script)

## Requests for other files
- **monitor.rs**: its progress lines (`Cycle N: warning: ...` ~411 and the summary ~506) go
  straight to stderr, so `--quiet` does not silence them. `ui.rs` passes `opts` only through
  `RunConfig`; please add a `quiet: bool` to `monitor::RunConfig` (the lead can set it from
  `opts.contains_key("quiet")` in the `monitor` arm) and skip those `eprintln!`s when it is set.
- **CLI flags for the new backend features**: `ui.rs` now has a `COMMANDS` table next to
  `FLAGS`/`VALUES`. A test (`commands_table_matches_the_dispatcher`) fails if a new
  `"name" =>` arm in `run` is missing from `COMMANDS` (or the other way round), and the
  completion scripts are generated from these three tables. New options therefore only need to
  be added to `FLAGS`/`VALUES` (and to `FILE_VALUES` if they take a file name).
- **otpassive.rs** (optional): `read_pcap_file`/`listen_live` hold `&mut Tracker` until they
  return, so the GUI reimplements their loops (`gui/ot.rs`, using `pcapfile::Reader`,
  `capture::PassiveCapture` and `Tracker::feed`) to show frames during ingest. A progress
  callback on those two functions would let the GUI reuse them directly.

## README suggestions (not edited)
- GUI, **Passive / DCP** window: new section *OT passive asset discovery*. **Open pcap...** reads
  a capture file, **Listen (OT)** listens on the selected interface for the chosen number of
  seconds (receive-only; disabled while another capture or a scan runs). Frames processed are
  shown while it runs and **Stop** ends it early (marked partial). The asset table lists address,
  vendor, product, firmware, serial, protocols, roles, first/last seen and control traffic; rows
  with observed control traffic (writes, program changes, stop/start) are shown in red. **Export
  assets CSV/JSON** writes the same formats as `ot-assets`. Each finished OT capture is saved to
  the inventory like `ot-listen`, so `network-scope ot-assets ID` works on it.
- GUI, **Findings** and **Devices**: click a column header to sort (again to reverse); a
  severity selector (Devices: by the highest finding of the device, new *Risk* column) and a
  text filter narrow the rows. Clicking a row selects that host in the main table, scrolls to it
  and opens its details (the main filter/search are cleared if they hid it). Devices seen only
  passively have no host details; the status line says so.
- GUI, **Host details**: **Test script...** runs the configured script (Settings) or a chosen
  `.rhai` file against a copy of the host in the background and lists the fields set, findings
  and notes/errors. Nothing is rescanned or changed until **Apply**, which adds the result to the
  host in the window (not to the saved inventory; export or rescan to keep it). **Discard** drops
  it.
- GUI: exports (CSV/JSON/HTML and OT assets) are written in the background; the status line
  shows "Saved FILE" or the error.
- TUI (`scan --tui`): Up/Down/PgUp/PgDn/Home/End select a row, **Enter** shows the host's open
  ports with identified services, findings and identity fields (Up/Down/PgUp/PgDn scroll it;
  Enter or Backspace returns),
  **S** cycles the sort order (newest, address, open ports). Space pauses, Q/Esc stop as before.
- CLI: `network-scope completions powershell|bash` prints a completion script:
  `network-scope completions powershell | Out-String | Invoke-Expression` (add to `$PROFILE`),
  or `source <(network-scope completions bash)`.
- CLI: `--quiet` (before or after the command) suppresses progress lines on stderr
  ("Saved scan #N", "Listening passively ...", "Imported ..."); errors still print and the exit
  status is unchanged. (monitor's own lines: see request above.)
- Screenshots (developer aid): `NETWORK_SCOPE_SCREENSHOT_STATE=findings|devices|ot|script`
  with `--screenshot FILE` renders a larger window with sample data in that view (append
  `-small`, e.g. `ot-small`, to keep the default 800x450 size). Screenshot
  runs never write the inventory or preferences.

## Observations, not changed
- Opening a saved `ot-passive:` capture from the inventory shows its observations in the
  Passive list but does not refill the OT asset table (that table shows the last OT run).
- Live **Listen (OT)** was not run against a real interface here; the pcap/pcapng path, the
  ingest loop and the asset table are covered by tests and screenshots.
- On exit a running OT capture is cancelled and not saved (passive/active runs are saved as
  partial in `on_exit`); the OT thread owns its tracker, so saving it would mean waiting for it.
- Script dry-runs run on the shared inventory worker; a script is bounded by the 250 ms wall
  limit, so this only delays queued saves briefly.
