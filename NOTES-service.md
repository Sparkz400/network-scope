# Notes from the service/TLS/risk bug-fix wave

Requests for files outside this wave's ownership (core.rs, monitor.rs, README.md, Cargo.toml),
plus the facts behind version/date decisions.

## Requested changes elsewhere

1. **monitor.rs:125** (new-device severity): use `crate::service::is_ot_port_candidate(p)`
   instead of `is_ot_port(p)`. 2222 was taken out of `OT_PORTS` so that `core.rs:366` lets
   service detection run on it (listen-only, see below). Without this change a new device
   whose only industrial hint is 2222/tcp is alerted as Medium instead of High.
2. **core.rs:363** (`rounds`): the TLS enumeration now spends its per-version budget as
   1 general hello + up to 3 weakness-class hellos (broken / 3DES / static RSA) + general
   enumeration with what is left. With Safe Mode's 4 rounds, weak suites are always found
   but the list of strong suites is cut to the first pick (marked
   `tls.<port>.suites_truncated=true`). Optionally raise Safe Mode to 5-6 rounds for TLS 1.2
   if a longer suite list matters more than one or two more connections per TLS port.
3. **Cargo.toml** (optional): enabling x509-parser's `verify` feature would let
   `tls::is_self_signed` check the signature with the certificate's own key. Without it the
   check is name equality plus AKI == SKI when both are present.
4. **README.md** updates:
   - Services: printer raw ports 9100-9107 and LPD 515 only get a passive banner wait
     (nothing is ever sent, user probes for those ports are ignored). 2222/tcp is listen-only:
     only an SSH greeting leads to the SSH algorithm exchange; anything else is treated as
     industrial (EtherNet/IP) and gets the ot-reachable finding.
   - SMB: an additional SMB1 negotiate offering only "NT LM 0.12" detects SMBv1
     (identity key `smb.<port>.smb1` = accepted/refused). smb1-enabled and smb-signing are
     now reported independently.
   - RDP: when the server selects NLA, a second connection offers only standard RDP security
     to learn whether NLA is actually required ("NLA required", or "... also accepted (NLA not
     required)" which raises rdp-no-nla).
   - LDAP: the finding needs a BindResponse with resultCode 0 ("anonymous bind accepted");
     "anonymous bind refused" is reported in the service string without a finding.
   - TLS: new keys `tls.<port>.not_yet_valid`, `cert_error` (certificate not parseable; the
     handshake facts are kept), `suites_truncated` / `suites_truncated_versions`.
     Self-signed now also requires AKI == SKI when both are present. New finding
     `tls-cert-not-yet-valid` (Medium) when not_before lies in the future.
   - Findings: PHP end of life is date-aware (table in risk.rs, `PHP_EOL`).

## Version / date facts used

- **OpenSSH CVE-2018-15473** (username enumeration): affected through OpenSSH 7.7, fixed in
  7.8 (released 2018-08). The rule's exclusive max is now `7.8`. `parse_version("7.7p1")` is
  `[7, 7, 1]`, which compares above `[7, 7]`, so the old max `7.7` missed both 7.7 and 7.7p1.
- **PHP end of life** (php.net/supported-versions, security support end):
  8.0 2023-11-26, 8.1 2025-12-31, 8.2 2026-12-31, 8.3 2027-12-31, 8.4 2028-12-31.
  As of 2026-11-18, 8.1 and older are EOL; 8.2 is still supported until 2026-12-31 and will
  be flagged automatically from 2027-01-01. Branches not in the table (8.5+) are never flagged
  until the table is extended (conservative). The 8.3/8.4 dates follow the published 2+2 year
  policy; re-check php.net when touching the table.
- **2222/tcp**: IANA lists 2222 tcp/udp as "EtherNet/IP-1" (implicit I/O is normally UDP);
  legacy Allen-Bradley CSP also used it. It is just as often an alternative SSH port, hence
  listen-only detection.
- **RDP failure codes** (MS-RDPBCGR 2.2.1.2.2): SSL_REQUIRED_BY_SERVER = 1,
  HYBRID_REQUIRED_BY_SERVER = 5. With only PROTOCOL_RDP offered, code 5 means NLA is required,
  code 1 means TLS is required but NLA is not.

## Not changed / left open

- HTTP Host header: IPv6 literals are bracketed, and `:port` is now added for every port
  other than 80/443 (IPv4 too), e.g. `Host: [::1]:8443`, `Host: 10.0.0.5:8080`.
- Monitor regression until item 1 above lands: a new device whose only OT hint is 2222/tcp
  alerts Medium instead of High.
- The legacy-only TLS branch in `service::tls_service` (rustls fails on a well-known TLS port
  -> raw enumeration, up to 4 gated hellos per version) has no dedicated test.
- TLS 1.3 suites are still not enumerated (documented limitation, not a bug).
- udp.rs, oui.rs, probes.rs: no bugs found.
