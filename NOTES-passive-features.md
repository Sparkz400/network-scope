# Wave 2 notes: passive / OT / monitor features

Files changed: src/pcapfile.rs, src/otpassive.rs, src/passive.rs, src/monitor.rs, src/ot.rs (test only),
new src/notify.rs (+ `mod notify;` in src/main.rs). src/ot/opcua.rs unchanged.

## 1. Capture formats (pcapfile.rs)

- Classic pcap and pcapng now read link types 1 (Ethernet), 113 (Linux cooked SLL), 276 (SLL2),
  101 (raw IP), 228 (raw IPv4), 229 (raw IPv6). Non-Ethernet frames are translated to an
  Ethernet-style frame (synthesised 14-byte header) so every decoder is unchanged:
  - SLL/SLL2: ethertype = the cooked protocol field; source MAC = the link-layer address when it
    is 6 bytes long (else 00:00:00:00:00:00); destination = ff:ff:ff:ff:ff:ff for packet type 1
    (broadcast), 01:00:5e:00:00:00 for type 2 (multicast), else 00:00:00:00:00:00. Frames whose
    protocol is not an ethertype (< 0x0600: 802.3/LLC, CAN, ...) are skipped (counted in `skipped`).
  - Raw IP: ethertype from the IP version nibble; 228 accepts only IPv4, 229 only IPv6.
- `passive::decode` no longer reports an all-zero source MAC (that is a synthesised header): such
  observations have an empty `mac`, so raw-IP devices are not merged into one "00:00:..." device.
- Other link types (802.11, radiotap, BSD loopback, ...) still fail with a message naming the type.

## 2. Progress for pcap ingest

- `pcapfile::Progress { frames, bytes, total_bytes, elapsed, done }` with `percent()`
  (`None` if the size is unknown), `frames_per_second()` and `line()` (one status line, e.g.
  `42.0% 1200000 frames, 80.1 MB of 190.7 MB, 250000 frames/s`).
- `pcapfile::Reader::bytes_read()` / `frames()`.
- `otpassive::read_pcap_file_with_progress(path, &mut tracker, cancel: Option<&AtomicBool>,
  &mut |p: &Progress| ...)`: calls back about every `otpassive::PROGRESS_INTERVAL` (250 ms) and
  once more at the end with `done: true` (also after an error or cancel). Cancel returns
  `Err("Reading the capture file was cancelled; results are partial")`; what was read stays in
  the tracker. `read_pcap_file` is unchanged (no progress).
- It is a callback, not a channel, on purpose: the passive modules must not contain `.send(` (the
  structural send-free test). The GUI can forward `*p` into its own mpsc channel from the closure.

### Requested wiring (ui.rs / GUI owner)

- `ot-listen --pcap FILE --progress`: use `read_pcap_file_with_progress`; print `\r{p.line()}` to
  stderr (newline when `p.done`). Suggested default: on when stderr is a terminal.
- GUI pcap import: run on a worker thread, forward `Progress` through a channel, show
  `percent()` as a progress bar and `frames_per_second()`; a Cancel button sets the AtomicBool.

## 3. Alert sinks (src/notify.rs, configured in `monitor::Policy::notify`)

- `monitor::Policy` has a new field `notify: monitor::Notify { sinks, timeout, dedup, renotify }`
  (`Policy` is built with `..Default::default()` in ui.rs, so nothing breaks; `RunConfig` and
  `Alert` are unchanged).
- `notify::Sink::webhook("http://host[:port][/path]")`: one `POST` per alert, body = the alert
  JSON (same object as the stdout JSON lines), `Content-Type: application/json`; 2xx = delivered.
  **HTTPS is rejected** with a clear error: no trusted CA store is bundled (no webpki-roots /
  native-certs dependency), and unverified TLS would only look secure. Use an http:// relay.
  `user:pass@` URLs are rejected.
- `notify::Sink::syslog(spec)`: `udp://host[:port]` (default 514), `tcp://host[:port]`
  (default 601, RFC 6587 octet counting) or `host[:port]` (UDP). RFC 5424:
  `<PRI>1 TIMESTAMP HOST network-scope PID KIND - SEVERITY SUBJECT: MESSAGE`, facility local0
  (16; `Syslog::facility` is pub), severity critical->2 (crit), high->3 (err), medium->4
  (warning), low->5 (notice), info->6. Control characters/newlines in device-supplied text become
  spaces; messages are cut at 2048 bytes.
- Bounded: connect/read/write timeout `notify.timeout` (default 5 s) per operation; after the
  first failure a destination's remaining alerts of that cycle are skipped; at most 30 s per
  destination per cycle. DNS resolution uses the system resolver (std has no timeout for it).
- Failures are printed as `Cycle N: alert delivery failed: <dest>: <error>; X of Y alerts not
  delivered` and never stop the monitor loop. Nothing is sent unless a sink is configured.

### Requested CLI flags (monitor)

- `--webhook URL[,URL...]` -> `policy.notify.sinks.push(notify::Sink::webhook(url)?)`
- `--syslog DEST[,DEST...]` -> `policy.notify.sinks.push(notify::Sink::syslog(dest)?)`
- `--alert-timeout SECONDS` (default 5, suggest clamp 1-60) -> `policy.notify.timeout`
- `--no-dedup` -> `policy.notify.dedup = false`
- `--renotify-hours N` (default 24; `0` = never repeat while the condition persists) ->
  `policy.notify.renotify = (N > 0).then(|| Duration::from_secs(N * 3600))`

## 4. Alert de-duplication across cycles (monitor.rs)

- `monitor::alert_key(&Alert)`: kind + subject + stable detail. `rogue-dhcp` without an
  allow-list uses the sorted set of server IPs (the offered address changes every cycle);
  `capture-incomplete`, `dhcp-discover-failed` and per-server `rogue-dhcp` use kind + subject
  only (their counters change every cycle). Everything else (`new-device`, `device-missing`,
  `new-finding`, port and address alerts) uses the full message: the subject of device alerts
  is only the first IP, and findings must stay as fine-grained as `risk::Finding::key`.
- `monitor::Dedup` (in memory): a key raised once is suppressed while it keeps being produced; it
  is raised again after a **complete** cycle without it (resolved, then recurred) or after
  `renotify` (default 24 h). An incomplete cycle (cancelled scan; comparisons are skipped) never
  counts as "resolved". On by default (`Notify::dedup`).
- Suppressed alerts are not stored, not emitted and not delivered; the cycle line says
  `(N still-active alerts not repeated)`.
- Startup: state is reconstructed from `store::list_alerts(db, 2000)`: alerts raised within
  `2 x interval + 300 s` before start count as active, so a restarted monitor does not repeat
  them. A failing lookup is only a stderr warning.

### Request for store.rs owner (optional)

`list_alerts` cannot filter by target set or time and does not return `scan_id`. With several
monitors sharing one database, an alert with the same key from another monitor's targets could
suppress one here (keys contain IPs, so this is unlikely). A
`list_alerts_since(path, since_ts, targets: Option<&str>)` would make the restore exact.

## 5. Hint for --report-missing

`monitor::severity_hint(&Policy)` is printed by `monitor::run` itself (no wiring needed) when
`report_missing` is set and `min_severity` hides whole alert kinds, e.g.
`Hint: --min-severity high hides these alert kinds: port-closed (info), device-missing (low),
address-changed (medium); --report-missing has no visible effect (use --min-severity low)`.
With the default (low) it names `port-closed (info)`.

## 6. OT passive TCP reassembly-lite (otpassive.rs)

- Modbus/TCP (MBAP length), S7comm (TPKT length), IEC 104 (APCI length), EtherNet/IP
  (encapsulation length) and OPC UA (message size) messages split across 2+ segments are buffered
  per flow (src, sport, dst, dport) and decoded once complete. Several messages in one segment are
  now each decoded. DNP3 is still per segment (its length excludes CRC blocks).
- In order only: the next segment must start at the expected sequence number (wrapping
  arithmetic). A retransmission of buffered bytes is ignored, an overlap adds only new bytes. A
  gap, FIN/RST, a snap-length-truncated segment, 120 s of capture-time idleness or the end of the
  capture gives up the partial message, which is decoded best-effort (as before reassembly).
- Bounds: 16 KiB per flow (longer messages are decoded from the first segment), 1024 flows,
  4 MiB in total; beyond the limits segments are decoded on their own.
- Framing is validated (protocol id 0 / TPKT 3,0 / 0x68 / known ENIP commands / OPC UA message
  types) before anything is buffered; a length field followed by bytes that are not a message is
  decoded as one piece, as before.
- A buffered start that turns out not to be a message (e.g. a 1-byte TCP keep-alive probe) is
  decoded separately from the next segment, so it cannot swallow the following message.
  Given-up fragments are decoded with the capture time of their last segment.
- Behaviour change: on these five ports the `packets` counter of an observed server/client now
  counts messages (a message split over 3 segments counts once; 2 messages in one segment
  count twice), not segments.
- `Tracker::flush()` is called by `read_pcap_file*` and `listen_live`; callers that `feed()`
  frames themselves should call it before `observations()`.
- `Tracker::set_reassembly(false)` turns buffering off; `Tracker::reassembly_stats()` returns
  (messages reassembled, partial messages given up).

### Requested CLI flags (ot-listen)

- `--no-reassembly` -> `tracker.set_reassembly(false)`
- optional: after reading, print `reassembly_stats()` to stderr when non-zero.

## 7. OT active

- EtherNet/IP ODVA vendor names: already present. `oui::cip_vendor` (data/cip_vendors.tsv,
  embedded by oui.rs) is called by `ot::parse_list_identity` (active scan) and therefore also by
  the passive List Identity decoder. Added a direct unit test in ot.rs. OPC UA: nothing new.

## README text (for the README owner)

- Capture files: "pcap and pcapng files with Ethernet, Linux cooked (SLL/SLL2, e.g. `tcpdump -i
  any`) and raw IP link types are supported."
- OT passive: replace "TCP streams are not reassembled" with "messages split across TCP
  segments are reassembled in order (bounded memory); a missing segment means that message is
  decoded only as far as it was captured."
- Monitor: document `--webhook`, `--syslog`, `--alert-timeout`, `--no-dedup`, `--renotify-hours`
  (see above), that HTTPS webhooks are not supported, and that a persisting condition is alerted
  once (again after it resolves and recurs, or every 24 h by default).
