# Notes from the CLI/TUI/GUI bug-fix wave (requests for files outside ui/gui/script)

## Requested change: otpassive.rs should use the indexed merge
`ui::merge` keeps its signature and semantics, but a `&mut Vec<Observation>` has no room for an
index, so it stays a linear scan. A fast variant with identical semantics now exists:

```rust
pub struct ui::ObservationIndex;            // Default, clear()
pub fn ui::merge_indexed(&mut Vec<Observation>, &mut ObservationIndex, Observation) -> Result<(), String>
```

Please switch `otpassive::Tracker::feed` (otpassive.rs ~303) to it: add a
`passive_index: crate::ui::ObservationIndex` field to `Tracker` and call
`crate::ui::merge_indexed(&mut self.passive, &mut self.passive_index, o)`. The index rebuilds
itself if the Vec is replaced or edited elsewhere, so no other bookkeeping is needed. The CLI
`listen`/`dcp` commands and the GUI capture already use it.

## README suggestions (not edited)
- GUI: the Scan menu entry is now **Clear results and captures**. It clears active results and
  passive observations from the window (saved inventory is untouched). Starting an active scan no
  longer clears passive observations, and starting a capture no longer clears scan results, so
  the Devices window merges both. The inventory still stores them separately: an active scan is
  saved with its hosts, a capture with its observations (as the CLI does); exports and the HTML
  report from the window contain both.
- GUI: the **Standard** preset and **Restore defaults** keep the capture interface, source IPv4/MAC,
  script path and probe file. Preferences (settings, favourites, notes) are now saved about a
  second after changes, not only on exit; empty notes are not stored.
- CLI: `listen`/`dcp` and `scan` now save what was collected when a capture/scan error occurs
  (marked partial) and then exit with status 1 and the error. Errors with nothing collected still
  fail without saving.
- TUI: `q`, `Q` and Esc stop the scan.
- Scripts: the 250 ms wall limit is per host across all scripts (as the README already says);
  scripts that would start after the budget is spent are skipped with a note on the host.

## Observations, not changed (outside scope or not bugs)
- GUI `export()` (file dialog + write) still runs on the UI thread; it was not in the list.
- `scan --format html|nmap` passes timestamp 0 to the report/nmap exporters through
  `store::export`, whereas `export ID` uses the stored timestamp (store.rs).
