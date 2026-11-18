# Wave 1 notes: passive / OT / monitor fixes

Files changed: src/passive.rs, src/monitor.rs, src/ot.rs, src/otpassive.rs, src/pcapfile.rs.
src/ot/opcua.rs was not changed (no bug was assigned there).

## Decisions

- **Monitor alert severities (bug 2).** `device-missing` (only produced with `--report-missing`)
  is now **Low** and `address-changed` (known MAC on a new IP) is now **Medium**. Both now pass
  the default `min_severity` of Low. `port-closed` stays Info on purpose: a timeout does not prove
  a port closed.
- **DHCP server identity (bug 1).** A passive `DHCP` observation still describes the client
  (`ip` = yiaddr/ciaddr, `mac` = chaddr). New fields: `server_id` (option 54), `ip_source`
  (IP header source) and, for server messages (BOOTREPLY with type 2/5/6), one key per server,
  `dhcp_server.<ip>` = message type. The server is option 54, or the IP source when option 54 is
  missing (a relay's address is not used when option 54 is present). The per-server key exists
  because `ui::merge` merges observations with the same mac/protocol/ip by extending fields, so a
  single `server_id` field would be overwritten when two servers answer the same client.
  `monitor::dhcp_servers` reads only these keys; DHCP observations stored by older versions
  (whose `ip` was the client) are ignored, not reported as servers.
- **Monitor capture problems (bug 4).** A capture error item or the 10,000-observation cap no
  longer ends `monitor`: extra observations are dropped, a warning goes to stderr and a
  `capture-incomplete` alert (Low, added after filtering like `dhcp-discover-failed`) is
  emitted. The scan snapshot is not marked partial because of this (the active scan is complete).
- **Capture thread (bug 5).** Up to 20 consecutive `cap.next()` errors are tolerated with backoff
  (10 ms doubling, max 1 s); any frame or idle poll resets the count. A full queue drops the
  observation and counts it; at the end one `Err("Capture queue full: N observations were
  dropped; results are partial")` item is sent. The GUI already treats `Err` items as partial.
- **BACnet Who-Is (bug 6).** The BACnet wait is `port_timeout` clamped to 200–2000 ms (other OT
  probes are unchanged: 4 x port_timeout). ConnectionReset/ConnectionRefused (ICMP port
  unreachable; WSAECONNRESET on Windows) and IPv6 targets mean "no BACnet": no error and the
  host is not marked responding.
- **CIP (bug 8).** Object-specific codes are decoded by the request path: Connection Manager
  (class 0x06): 0x4E Forward Close, 0x52 Unconnected Send, 0x54 Forward Open, 0x5B Large Forward
  Open. Logix tags (symbolic path or class 0x6B): 0x4E Read Modify Write Tag (control), 0x52 Read
  Tag Fragmented. 0x4C/0x4D/0x53 keep their tag names on any path. Unconnected Send and Multiple
  Service Packet (0x0A) are unwrapped (depth <= 4, <= 32 services per message).
- **Broadcast destinations (bug 9).** A request to a limited broadcast, a multicast address or a
  frame with a group destination MAC (ff:ff:ff:ff:ff:ff, multicast MACs) records only the client.
- **pcap (bugs 12, 13).** pcapng `if_tsresol` is honoured per interface (10^-n and 2^-n). pcapng
  blocks larger than 266 KB are skipped by a streaming discard (no large allocation) and counted in
  `skipped`. Classic pcap masks the link-type word to 28 bits and strips the FCS when the FCS
  flag is set. Unsupported link types give an error naming the type (e.g. "113 (Linux cooked
  capture SLL)"); for pcapng that happens at end of file when no Ethernet frame was found.
  Classic pcap frames larger than 256 KB are still an error (that is a corrupt record header,
  and the rest of the file cannot be trusted).

## Requests for other owners

- **src/ui.rs (`listen` / `dcp` commands):** `for item in &run.receiver { let o = item?; ... }`
  aborts the whole capture on the first `Err` item. Since the capture thread now reports a full
  queue as a final non-fatal `Err` item, please treat `Err` items as warnings (eprintln, mark the
  snapshot `complete: false`) instead of returning, as the GUI and `monitor` already do.
  Same for the `merge(...)?` observation-cap error there.
- **README.md:** if it documents monitor alert severities, update: `device-missing` Low,
  `address-changed` Medium, new `capture-incomplete` (Low). Mention that BACnet identification
  waits at most 2 s per host and that pcapng nanosecond (`if_tsresol`) captures are supported.
- **src/core.rs:** nothing required; `ot::identify` no longer reports "BACnet: ..." errors for
  hosts that do not run BACnet.
- **Wave 2:** Linux SLL/SLL2 (113/276) capture files are not supported yet; they now fail with a
  clear message.
