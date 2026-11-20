# Contributing fingerprints and probes

Network Scope identifies services with the rules in [`data/probes.json`](https://github.com/Sparkz400/network-scope/blob/main/data/probes.json). When a device shows up as `unidentified`, or is identified wrongly, you can fix that for everybody with a pull request. This page describes the path, the safety review and what stays on your machine.

**No telemetry, no upload.** Network Scope never sends scan results, banners or statistics anywhere, and nothing on this page changes that. You collect the data yourself, read it, remove what you do not want to share, and attach it to an issue or pull request yourself.

## 1. Find what is unidentified

Scan with service detection (`--services`, or `--deep`) so that banners are collected, then export the banners nothing recognised, from the local store:

```sh
network-scope-cli scan 192.168.1.0/24 --services --db my.sqlite
network-scope-cli fingerprints export-unknown --db my.sqlite --output unknown.json
```

`fingerprints export-unknown [SCAN_ID]` reads the stored scan with that ID, or every stored scan when you give none, and writes a JSON file with one entry per distinct banner (most widespread first, at most 500):

```json
{
  "schema": "network-scope/unknown-banners/v1",
  "format": "network-scope-unknown-banners",
  "version": 1,
  "generated_by": "network-scope 0.5.1",
  "review": "Read every entry and remove or redact ...",
  "entries": [
    { "proto": "tcp", "port": 9999, "banner": "ACME-GW 2.1 ready", "hosts": 3 }
  ],
  "truncated": false
}
```

What the file contains and what it does not (an entry also has a `port_hint`, such as `ftp`, when the port number alone suggests a service):

- It has **no IP address, MAC address, host name or scan time** of any host, only the port, the banner text and how many hosts showed that banner. The host's own address, MAC address and name are also removed from inside the banner text (`<ip>`, `<mac>`, `<host>`).
- A banner can still contain whatever the device chose to say: a user name, a serial number, a site or product name, an address of another machine. **Open the file and read it.** Delete entries you cannot share and edit the rest. The command prints this reminder, and the file repeats it in its `review` field.
- The store keeps banners as text: control characters are dropped and the text is cut at 120 characters, so a binary reply is not reproduced exactly. For a binary protocol capture the raw reply yourself (for example with `nc` and `xxd`, or Wireshark) and paste the hex.
- The command only reads the local database. It sends nothing.

### The workbench: group, compare, draft

For more than a handful of banners, the workbench does the sorting. It reads the same unidentified banners from the local store, sends nothing and writes nothing unless you ask:

```sh
network-scope-cli fingerprints groups                  # the queue: similar banners together
network-scope-cli fingerprints compare 7ab264f8        # one group side by side, versions that differ
network-scope-cli fingerprints draft 7ab264f8 --output acme.json
network-scope-cli probes validate acme.json
```

`fingerprints groups [SCAN_ID]` lists every group with its id (the first 8 hex digits of the SHA-256 of its template), the number of hosts and distinct banners and the ports. Banners are lower-cased, every digit becomes `#`, and two banners are similar when their three-character shingle sets have a Jaccard index of at least 0.6; groups are the connected components of that relation, so one product in several firmware versions (`ACME-GW 2.1 ready`, `ACME-GW 3.0.4 ready`) lands in one group. `fingerprints compare GROUP [SCAN_ID]` shows the group's variants, which hosts and MAC vendors sent them, and where they differ: the version-like numbers by position (`number 1 varies: 2.0, 2.1, 3.0.4`, in version order), or, when the banners have different shapes, how many. Both take `--format json` (`banner-groups` schema); a group may be named by any prefix of at least 4 characters of its id.

`fingerprints draft GROUP [SCAN_ID] --output FILE` writes a draft rule and a checklist: `FILE` is a complete probe file with one rule for the `banner` probe (the probe that only listens; `probes validate FILE` takes it) and `FILE.checklist.md` is the pull request checklist (read the banners and redact them, confirm the product and version names, capture a raw reply, run the validator and the linter, add a test, open the pull request with the fingerprint template). Without `--output` the same is printed (`--format json` gives the `fingerprint-draft` schema). When all banners of a group have one shape, the rule is that shape as a regular expression with a capture group around the first version-like number (`$1` is the version); when the shapes differ the rule only anchors on their common start and says so, and when that start is shorter than 5 characters the draft is refused, because such a rule would claim unrelated services. The draft always passes `probes lint` and matches every banner of its group (both are checked when it is made). **`service` and `product` are guesses** from the banner text; the number the rule captures may be a model number rather than a version. Check them before you share anything.

Limits: only TCP banners are grouped (the same input as `export-unknown`), the store keeps them with control characters removed and cut at 120 characters, at most the 1,500 commonest distinct banners are looked at, and the workbench has no idea what a device really is: it sorts text.

## 2. Write the rule

A probe is a small JSON object (the format is described in the `_comment` field of `data/probes.json` and in [Detection](detection.md#extending-the-probe-database)). Most contributions need only a **rule** for the existing `banner` probe, which sends nothing and only listens for the greeting the service sends on its own:

```json
{ "re": "^ACME-GW ([\\d.]+) ready", "service": "acme-gw", "product": "ACME GW-200", "version": "$1" }
```

Rules are regular expressions over the raw reply bytes (the first match wins, `$1`..`$9` insert capture groups). Put specific rules before general ones. A new **probe** that sends a request is only needed when the service stays silent until asked; keep it to the shortest harmless request (a version query, an `OPTIONS` or `INFO`).

Test your file against the real database before you open anything:

```sh
network-scope-cli probes validate my-probes.json     # loads it like a scan with --probes would, then lints it
network-scope-cli scan 192.168.1.50 --ports 9999 --services --probes my-probes.json
```

## 3. The safety review

Network Scope is used on industrial networks, so every probe is reviewed against the [safety rules](https://github.com/Sparkz400/network-scope/blob/main/CONTRIBUTING.md#safety-rules-for-new-probes-and-features). The linter, `network-scope-cli probes lint [FILE]`, checks the mechanical part, and CI runs it on `data/probes.json` for every pull request. It rejects:

| Code | What it rejects |
| --- | --- |
| `ot-port` | A probe that sends a payload to an industrial or printer port (the engine's own list: Modbus 502, S7 102, EtherNet/IP 44818 and 2222, BACnet 47808-47823, Profinet, DNP3, IEC 104, OPC UA 4840, printer 515 and 9100-9107, and the rest of the OT list in `core/src/service/mod.rs`). Rules for banners from those ports are fine; probes that send there are not. |
| `write-payload` | A payload with a line that starts with a verb that changes something, runs something or sends mail: `PUT`, `POST`, `DELETE`, `STOR`, `SET`, `FLUSHALL`, `DROP`, `MAIL`, `EXEC`, `REBOOT` and similar. Probes ask, they never change. |
| `payload-too-long` | A payload over 512 bytes (the longest built-in one is 52). |
| `wait-too-long` | A reply wait over 10 seconds. |
| `regex-too-long`, `regex-too-big` | A pattern over 512 characters, or one that compiles to more than 256 KiB (for example big nested repeat counts). |
| `regex-nested-quantifier` | A repeated group whose content is itself repeated without bound and ambiguous, like `(a+)+` or `(.*)*x`. |
| `bad-regex`, `bad-payload` | A pattern or hex string that does not parse. |

Warnings (`bad-capture`, `duplicate-name`, `unused-payload`) do not fail the check but deserve a look. `probes lint` exits with status 1 when there is an error and prints every issue.

The regular-expression engine of Network Scope matches in linear time, so a pattern cannot make it hang. The pattern checks exist because a probe file is also read by people and other tools, and because a huge pattern costs memory. The nested-quantifier check is a heuristic and does not find every ambiguous pattern (it does not look at overlapping alternatives like `(a|a)*`).

The linter does not replace review. A maintainer reads every added probe: what it sends, to which ports, and whether the reply could expose something that should not be stored. Probes that log in, guess credentials, or send anything beyond a one-line request are not accepted.

## 4. Share it

Either way works:

- **Pull request** (preferred): change `data/probes.json`, add a test next to the others in `core/src/service/probes.rs` (the banner you saw must give the expected `service`, `product` and `version`, and a near miss must not match), run `cargo test`, and open the pull request with the fingerprint template: add `?template=fingerprint.md` to the *new pull request* URL, or copy [`.github/PULL_REQUEST_TEMPLATE/fingerprint.md`](https://github.com/Sparkz400/network-scope/blob/main/.github/PULL_REQUEST_TEMPLATE/fingerprint.md) into the description.
- **Issue**: use the [Fingerprint or probe contribution](https://github.com/Sparkz400/network-scope/issues/new?template=fingerprint.yml) form, paste the redacted banner, and a maintainer writes the rule.

Rules you write yourself are your own work and are accepted under the project's MIT license. Do not copy rules from other projects (nmap's `nmap-service-probes` is not MIT-compatible) without recording the source and checking its license; see [Adding data](https://github.com/Sparkz400/network-scope/blob/main/CONTRIBUTING.md#adding-data).

## What has not been tested

The banner export and the linter are tested with built files and a built-in database check, not against a large body of real contributions. The nested-quantifier check is a heuristic with the limits described above. Network Scope does not check that a rule is *correct* for a device you have not tried it on; that is what the test and your lab device are for.
