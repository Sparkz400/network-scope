# IPv6 discovery

IPv6 has no address range to sweep, so a scan cannot find hosts by trying addresses. `scan --ipv6-discover` finds the hosts on the **local link** instead, from three sources, and joins them to the scanned hosts by MAC address. Passive NDP decoding needs no option.

| Source | Sends | When |
| --- | --- | --- |
| **Multicast echo**: one ICMPv6 Echo Request to `ff02::1` (all nodes) per selected interface, hop limit 1 | one datagram per interface, through the rate gate (`ipv6-echo` in the [sent log](cli-reference.md#dry-run-and-sent-log)) | only with `--ipv6-discover`, after the scan; also in Safe Mode (one request per interface, like the ICMP ping) |
| **The OS neighbour cache** (Windows `GetIpNetTable2`, Linux `ip -6 neigh show`, macOS `ndp -an`) | nothing | with `--ipv6-discover`; the echo fills the cache with every host that answered |
| **Passive NDP**: Neighbor and Router Advertisements and Solicitations in `listen`, `ot-listen`, `monitor` and capture files | nothing | always, wherever frames are decoded |

## Options and behaviour

- `--ipv6-discover` (scan only, off by default). `--interface` selects one interface by **index** or part of its **name** (`Ethernet`, `eth0`, `en0`); without it every interface that has a preferred link-local address gets one echo, at most 8. On Windows the pcap device name used by `--arp-sweep` is not matched; use the index or the adapter name.
- The echo goes to the link-local all-nodes group, never to the scan targets, so the [scope guard](cli-reference.md#scope-guard) of the scan does not apply to it (a scope cannot describe a link). It is not routed (hop limit 1). `--dry-run` lists it under "once per scan".
- Our own addresses, multicast and unspecified addresses are removed from the answers.
- The cache is read before and after the echo; an entry that is new afterwards (and not one of our own addresses) counts as having answered it.
- A neighbour becomes a **host** when it answered the echo or its cache entry is reachable, delay or probe, and no scanned host has its MAC. It is added with its best address (global, then unique local, then link-local), `ipv6.addresses` (up to 8), `ipv6.source` and `ipv6.interface` in its identity. A **stale** entry, or an answer without a MAC, is only an `IPv6 neighbor` observation: a stale entry shows that the host was there, not that it is.
- A scanned host with the same MAC gets `ipv6.addresses` and `ipv6.source` instead; [`devices`](device-identity.md) then shows the IPv4 and IPv6 addresses as one device. The observations are saved with the scan, so the join also works later.

## Passive NDP

`passive::decode` reads ICMPv6 types 133 to 136 with hop limit 255 (a message that crossed a router has a lower one and is ignored), code 0. An observation `NDP` has the sender's MAC (the link-layer address option, else the Ethernet source), its address, and: for a Router Advertisement the flags (managed, other config), router lifetime, hop limit, prefixes, MTU and RDNSS servers; for a Neighbor Advertisement the router, solicited and override flags and the target; for a Solicitation from `::` (duplicate address detection) the address about to be used. Options are bounded (16, a zero length ends the list), extension headers are not followed.

## What has been verified, and what has not

- Verified on a Windows 11 machine with real calls: the interface and address table (`GetUnicastIpAddressTable`) and the neighbour table (`GetIpNetTable2`) decode to the same addresses, interface indexes and states as `Get-NetNeighbor` / `Get-NetIPAddress` (the row offsets for address, interface, state and MAC length; the MAC field itself only against all-zero entries, because this machine's cache held no resolved neighbour). The multicast echo ran on this machine's three interfaces and waited the full timeout each (the ICMP API collects replies until it expires), and Windows' own ICMPv6 counter (`netstat -s -p icmpv6`, "Echos") rose by exactly three, one per interface, so the datagrams did leave; **no host on that network answered**, so the decoding of several replies in one buffer is unverified on real traffic. The cache is read before and after the echo for exactly that reason: an entry that appears during the echo counts as an answer, whatever the ICMP API handed back.
- Tested with built input only: the parsers of `ip -6 neigh`, `ndp -an`, `/proc/net/if_inet6` and `ifconfig` (samples written from the formats; fuzzed), the NDP decoder (frames built from RFC 4861), the merge by MAC, the run with the operating system replaced by test doubles (one gate token per interface, the sent log and plan agree).
- **Not run at all**: the Linux and macOS socket code (`socket_echo`, an unprivileged datagram ICMPv6 socket or a raw one; compiled on Windows, never executed), Linux and macOS neighbour tables on a real system, and any interface with real IPv6 neighbours. Please report a platform where it does not work.

Not implemented: routers' prefix-based scanning of a /64 (infeasible), DHCPv6, mDNS-based IPv6 discovery (the passive `listen` already reads mDNS), IPv6 router discovery by sending a Router Solicitation, and MLD queries.
