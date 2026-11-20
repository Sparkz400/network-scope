# Segmentation check

IEC 62443 divides a plant into **zones** (groups of assets with the same security needs) joined by **conduits**, the only paths allowed between zones. `segmentation check` compares what a scan could reach with such a model and lists every path that breaks it. It reads a stored scan and a small JSON file and **sends nothing**.

```sh
# 1. scan the other zones from a host that sits in the zone you want to test (Safe Mode applies)
network-scope-cli scan 10.0.1.0/24,10.0.2.0/24,10.0.9.0/28 --ports 22,80,443,502,102,4840,44818 --ot --scope 10.0.0.0/8
# 2. check the result against the model
network-scope-cli segmentation check --zones zones.json --from enterprise
network-scope-cli segmentation check --zones zones.json --from enterprise 12 --format json --fail-on-findings
```

`SCAN_ID` defaults to the newest completed scan. `--from ZONE` names the zone the scan was run from: a scan does not record where it ran (except the `--source-ip` of a SYN or ARP scan, which is used when `--from` is left out and the address lies in a declared zone). `--fail-on-findings` ends with exit status 3 when at least one path breaks the model.

## The zones file

```json
{
  "zones": {
    "enterprise": ["10.0.0.0/24"],
    "dmz": ["10.0.1.0/24"],
    "control": ["10.0.2.0/24", "fd00:2::/64"],
    "safety": ["10.0.9.0/28"]
  },
  "conduits": [
    { "from": "enterprise", "to": "dmz", "ports": ["tcp/443", "icmp"] },
    { "from": "dmz", "to": "control", "ports": ["tcp/44818", "502"] }
  ]
}
```

- `zones` maps a zone name to a list of CIDR ranges (IPv4 or IPv6; a bare address is a /32 or /128). A host in several ranges belongs to the zone with the longest prefix; two zones that declare the very same range are refused.
- `conduits` lists the allowed paths. A conduit lets the `from` zone start connections to the listed ports of the `to` zone; it is one direction, declare the reverse separately. A port is `tcp/443`, `udp/161`, a range `tcp/8000-8100`, a bare `443` (TCP), `tcp/any`, `udp/any`, `icmp` (the host answers probes) or `any`.
- Traffic inside one zone is not checked. The file is limited to 4 MB, 1,000 zones and 100,000 ranges; a mistake (a conduit that names an undeclared zone, a bad range or port) is an error that names it, never silently ignored.

## What is reported

For every host that answered the scan:

| Kind | Meaning | Severity |
| --- | --- | --- |
| `no-conduit` | The host is in another zone and no conduit leads from the scan's zone to it, yet it answers. The message lists its open ports. | high when an industrial port is open, else medium |
| `port-not-allowed` | A conduit exists, but not for this open TCP or UDP port. | high for an industrial port, else medium |
| `unzoned-host` | The host belongs to no declared zone. | medium |

A host in the same zone as the scan is not reported. The report (`text`, or `--format json` with the `segmentation-report` schema) also counts the hosts per zone that answered, and carries three notes you should read: a scan is **one vantage point** (paths from other places are not seen), only the **ports the scan probed** can be reported (a port that did not answer proves nothing about the conduit, and a host that did not answer is not evidence of a block), and traffic inside a zone is not checked. A partial scan says so.

This is a check of what is *reachable*, not of what is *allowed to pass*: a firewall that lets a SYN through and then resets, or filters by application, looks reachable here. It also cannot tell an intended exposure from a mistake; the model says what is intended.

## Several vantage points

The roadmap asks for scans from several vantage points. Network Scope sends only from the machine it runs on and has no remote sensors. Run the scan from a machine in each zone you want to test (or from a laptop plugged into that VLAN), keep each scan in the database, and check each one with its own `--from`.

The model and the check are tested with synthetic scans (`core/src/segmentation_tests.rs`) and, since 2026-11-20, against a real scan of the lab: `lab/verify.py` starts five simulator sets on `127.0.0.1` to `127.0.0.5`, scans them with the built binary, writes a zones file (one zone per address, conduits that allow some ports and forbid others, one that points the wrong way, and one address in no zone) and requires that `segmentation check --from enterprise` reports exactly the 12 paths that follow from the model, written out by hand in the check (ten ports that no conduit allows, one unzoned host, one zone without a conduit), with the severities, the host counts per zone, exit status 3 with `--fail-on-findings`, no report for the host in the scan's own zone, the mirror result when the scan is said to come from another zone, an empty result for a model that allows everything, and an error for an undeclared `--from` zone. It has not been run on a real plant network. The file parser is fuzzed (`zones_file`).
