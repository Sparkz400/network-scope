#!/usr/bin/env python3
"""End-to-end check: start the simulators on loopback, scan them with the built binary and
assert that the expected identities and findings come out. Exit code 0 means all passed.

  python lab/verify.py target/release/network-scope[.exe]
  python lab/verify.py target/release/network-scope --scenario slow-wan|lossy|fragile-ot|all

The scenarios (see simulators.py) run the same scan against a slow WAN, a lossy network and
fragile OT devices; their expectations and the numbers they were set from are in
docs/src/lab-and-testing.md.
"""
import argparse
import codecs
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import simulators  # noqa: E402  (only for the icon the lab web server serves)
PORTS = "21,22,23,502,6379,8080,44818"
OPEN_PORTS = [21, 22, 23, 502, 6379, 8080, 44818]
OT_PORTS = "102,502,44818"

EXPECT_IDENTITY = {
    "svc.21.product": "vsFTPd",
    "svc.21.version": "2.3.4",
    "svc.22.version": "7.4",
    "svc.6379.product": "Redis",
    "svc.8080.version": "2.4.49",
    "Modbus.vendor": "LabWorks",
    "EtherNet/IP.vendor": "Rockwell Automation/Allen-Bradley",
    "BACnet.device_id": "1000",
    "device.type": "Industrial controller / OT device",
}


def murmur3_32(data, seed=0):
    """MurmurHash3 x86 32-bit, written independently of the Rust implementation (reference: SMHasher)."""
    c1, c2, mask = 0xCC9E2D51, 0x1B873593, 0xFFFFFFFF
    rotl = lambda x, r: ((x << r) | (x >> (32 - r))) & mask
    h = seed
    for i in range(0, len(data) - len(data) % 4, 4):
        k = int.from_bytes(data[i:i + 4], "little")
        h ^= rotl(k * c1 & mask, 15) * c2 & mask
        h = (rotl(h, 13) * 5 + 0xE6546B64) & mask
    tail = data[len(data) - len(data) % 4:]
    if tail:
        k = int.from_bytes(tail, "little")
        h ^= rotl(k * c1 & mask, 15) * c2 & mask
    h ^= len(data)
    h ^= h >> 16
    h = h * 0x85EBCA6B & mask
    h ^= h >> 13
    h = h * 0xC2B2AE35 & mask
    h ^= h >> 16
    return h


def shodan_favicon_hash(icon):
    """Shodan's http.favicon.hash: signed mmh3 of base64.encodebytes(icon)."""
    h = murmur3_32(codecs.encode(icon, "base64"))
    return h - (1 << 32) if h >= 1 << 31 else h


EXPECT_FAVICON = {"http.8080.favicon_mmh3": str(shodan_favicon_hash(simulators.FAVICON))}
EXPECT_FINDINGS = {
    "cve-cve-2011-2523", "cve-cve-2021-41773", "redis-noauth", "telnet-open",
    "ftp-cleartext", "ssh-weak-algorithms", "http-basic-cleartext", "ot-reachable",
}
EXPECT_S7 = {"S7.order_code": "6ES7 315-2EH14-0AB0", "S7.firmware": "3.2.1"}

# slow-wan: every reply of the simulators waits 150-300 ms.
SLOW_WAN_MAX_SCAN_SECONDS = 60
# lossy: 3 of 10 connections per port are reset after the connect (seeded), and 3 of 10 BACnet
# replies are dropped. Network Scope does not retry a reset service or OT request (--retries is
# for unanswered probes, not for resets), so one scan loses some values; a repeated scan (as
# monitoring does) picks them up. Measured on Windows, 2026-11-19, with `--seed 1..20`: the first
# scan finds 41-100% of the 17 expected identity values and findings (seed 1, the default: 11 of
# 17 = 65%, in every run), all of them are found within 1-3 scans, and within 5 for the worst
# seed (7). The limits are set past the worst seed, so that a different connection order on
# another platform does not fail the check.
LOSSY_LOSS = 0.3
LOSSY_SEED = 1
LOSSY_FIRST_SCAN_MIN = 0.3
LOSSY_MAX_SCANS = 6
# fragile-ot: a device crashes above this many new connections per second. A scan makes 2 per
# device (the port check and the identification) and was measured at 2 in any one second.
FRAGILE_CONN_LIMIT = 4


class Sim:
    """The simulators as a child process (killed on exit)."""

    def __init__(self, *args):
        cmd = [sys.executable, os.path.join(HERE, "simulators.py"), "--bind", "127.0.0.1", "--skip", "80", *args]
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
        self.proc.stdout.readline()
        time.sleep(0.5)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.proc.kill()
        self.proc.wait()


def scan(exe, work, name, *options):
    """Runs one scan of 127.0.0.1; returns (host, finding ids, seconds)."""
    db, out = os.path.join(work, name + ".sqlite"), os.path.join(work, name + ".json")
    started = time.time()
    subprocess.run([exe, "scan", "127.0.0.1", *options, "--db", db, "--output", out], check=True, timeout=120)
    seconds = time.time() - started
    document = json.load(open(out))
    host = document["hosts"][0]
    host["sent_in_output"] = document.get("sent")
    found = subprocess.run([exe, "findings", "1", "--db", db], check=True, capture_output=True, text=True, timeout=60).stdout
    return host, {f["id"] for f in json.loads(found)["findings"]}, seconds


def deep_scan(exe, work, name, *extra):
    return scan(exe, work, name, "--fast", "--deep", "--ot", "--ports", PORTS, *extra)


def missing_identity(host, expect=EXPECT_IDENTITY):
    return {key: want for key, want in expect.items() if host["identity"].get(key) != want}


def check_normal(exe, work, failures):
    snmp_stats = os.path.join(work, "snmp-stats.json")
    ot_stats = os.path.join(work, "ot-stats.json")
    with Sim("--snmp-stats", snmp_stats, "--ot-stats", ot_stats):
        host, ids, _ = deep_scan(exe, work, "normal", "--timeout", "1500", "--favicon")
        slowed = [e for e in host["errors"] if e.startswith("backed off:")]
        if slowed:
            failures.append(f"healthy lab host was backed off: {slowed}")
        check_backoff(exe, work, failures)
        check_dry_run_and_sent_log(exe, work, host, failures)
        check_snmp(exe, work, snmp_stats, failures)
        check_ot_extra(exe, work, ot_stats, failures)
        check_ot_tcp(exe, work, ot_stats, failures)
    for key, want in missing_identity(host).items():
        failures.append(f"identity {key}: expected {want!r}, got {host['identity'].get(key)!r}")
    # --favicon was on, but this host has industrial ports open: it must not be asked for an icon
    if any(e["detail"] == "GET /favicon.ico" for e in host["sent_in_output"] or []) or "http.8080.favicon_mmh3" in host["identity"]:
        failures.append("favicon: a host with industrial ports open was asked for /favicon.ico")
    check_favicon(exe, work, failures)
    for want in sorted(EXPECT_FINDINGS - ids):
        failures.append(f"finding missing: {want}")
    check_segmentation(exe, work, failures)


# L71: `segmentation check` against a real scan of five lab hosts (127.0.0.1-5, one simulator set
# each). The model puts the scan in zone "enterprise" (127.0.0.5), and the expected violations
# below are written by hand from the model, not computed by the code under test.
SEG_PORTS = "21,22,23,502,6379,8080,44818"
SEG_ZONES = {
    "zones": {
        "enterprise": ["127.0.0.5/32"],
        "dmz": ["127.0.0.1/32"],
        "control": ["127.0.0.2/32"],
        "safety": ["127.0.0.4/32"],
    },
    "conduits": [
        {"from": "enterprise", "to": "dmz", "ports": ["tcp/22", "tcp/8080", "icmp"]},
        {"from": "enterprise", "to": "control", "ports": ["502", "tcp/44818"]},
        # the wrong direction: it must not open enterprise -> safety
        {"from": "safety", "to": "enterprise", "ports": ["any"]},
        {"from": "dmz", "to": "safety", "ports": ["any"]},
    ],
}
# (kind, host, port, severity): 127.0.0.1 and .2 have all seven ports open, .3 is in no zone, .4
# has 22 and 502 open and no conduit from enterprise, .5 is the scan's own zone.
SEG_EXPECT = {
    ("port-not-allowed", "127.0.0.1", 21, "medium"),
    ("port-not-allowed", "127.0.0.1", 23, "medium"),
    ("port-not-allowed", "127.0.0.1", 502, "high"),
    ("port-not-allowed", "127.0.0.1", 6379, "medium"),
    ("port-not-allowed", "127.0.0.1", 44818, "high"),
    ("port-not-allowed", "127.0.0.2", 21, "medium"),
    ("port-not-allowed", "127.0.0.2", 22, "medium"),
    ("port-not-allowed", "127.0.0.2", 23, "medium"),
    ("port-not-allowed", "127.0.0.2", 6379, "medium"),
    ("port-not-allowed", "127.0.0.2", 8080, "medium"),
    ("unzoned-host", "127.0.0.3", None, "medium"),
    ("no-conduit", "127.0.0.4", None, "high"),
}


def segmentation(exe, db, zones, *options):
    return subprocess.run([exe, "segmentation", "check", "--zones", zones, "--db", db, *options],
                          capture_output=True, text=True, timeout=60)


def check_segmentation(exe, work, failures):
    import contextlib
    # Five loopback addresses are needed. Linux and Windows route all of 127.0.0.0/8 to the
    # loopback interface; macOS has 127.0.0.1 only (unless aliases were added to lo0), and the
    # check says so and skips there instead of failing on a lab limitation.
    unusable = []
    for n in range(1, 6):
        probe = socket.socket()
        try:
            probe.bind((f"127.0.0.{n}", 0))
        except OSError as e:
            unusable.append(f"127.0.0.{n} ({e})")
        finally:
            probe.close()
    if unusable:
        print("segmentation: SKIPPED, this machine cannot bind", ", ".join(unusable))
        return
    with contextlib.ExitStack() as stack:
        for n in range(1, 6):
            skip = ["80"]
            if n == 4:
                skip = ["80", "21", "23", "6379", "8080", "44818"]
            if n == 5:
                skip = ["80", "21", "23", "502", "6379", "8080", "44818"]
            stack.enter_context(Sim("--bind", f"127.0.0.{n}", "--skip", *skip))
        host_db = os.path.join(work, "segmentation.sqlite")
        out = os.path.join(work, "segmentation-scan.json")
        subprocess.run([exe, "scan", "127.0.0.1-5", "--ports", SEG_PORTS, "--timeout", "1500", "--db", host_db, "--output", out],
                       check=True, capture_output=True, timeout=120)
    hosts = {h["ip"]: h for h in json.load(open(out))["hosts"]}
    all_ports = [21, 22, 23, 502, 6379, 8080, 44818]
    want_open = {"127.0.0.1": all_ports, "127.0.0.2": all_ports, "127.0.0.3": all_ports,
                 "127.0.0.4": [22, 502], "127.0.0.5": [22]}
    for ip, ports in want_open.items():
        if hosts.get(ip, {}).get("open") != ports:
            failures.append(f"segmentation: scan of {ip}: open {hosts.get(ip, {}).get('open')}, expected {ports}")
    zones = os.path.join(work, "zones.json")
    json.dump(SEG_ZONES, open(zones, "w"))
    r = segmentation(exe, host_db, zones, "--from", "enterprise", "--format", "json")
    if r.returncode != 0:
        failures.append(f"segmentation check failed ({r.returncode}): {r.stderr.strip()[:300]}")
        return
    report = json.loads(r.stdout)
    got = [(v["kind"], v["host"], v["port"], v["severity"]) for v in report["violations"]]
    if len(got) != len(set(got)) or set(got) != SEG_EXPECT:
        failures.append(f"segmentation: missing {sorted(SEG_EXPECT - set(got), key=str)}, unexpected {sorted(set(got) - SEG_EXPECT, key=str)}, "
                        f"{len(got)} reported (duplicates: {len(got) != len(set(got))})")
    counts = (report["hosts_reachable"], report["hosts_in_other_zones"], report["unzoned_hosts"], report["reachable_per_zone"])
    if counts != (5, 3, 1, {"enterprise": 1, "dmz": 1, "control": 1, "safety": 1}):
        failures.append(f"segmentation: host counts {counts}")
    if report["vantage_zone"] != "enterprise" or report["scan_id"] != 1:
        failures.append(f"segmentation: vantage/scan id {report['vantage_zone']} {report['scan_id']}")
    # no violation names a host of the scan's own zone
    if any(v["host"] == "127.0.0.5" for v in report["violations"]):
        failures.append("segmentation: a host in the scan's own zone was reported")
    # exit status 3 with --fail-on-findings, 0 without; the text report names the hosts
    if segmentation(exe, host_db, zones, "--from", "enterprise", "--fail-on-findings").returncode != 3:
        failures.append("segmentation: --fail-on-findings did not exit with 3")
    text = segmentation(exe, host_db, zones, "--from", "enterprise")
    if text.returncode != 0 or "127.0.0.4" not in text.stdout:
        failures.append(f"segmentation: text report: exit {text.returncode}")
    # the other direction: from safety no conduit leads to dmz or control
    r = segmentation(exe, host_db, zones, "--from", "safety", "--format", "json")
    other = {(v["kind"], v["host"]) for v in json.loads(r.stdout)["violations"]} if r.returncode == 0 else None
    want_other = {("no-conduit", "127.0.0.1"), ("no-conduit", "127.0.0.2"), ("unzoned-host", "127.0.0.3")}
    if other != want_other:
        failures.append(f"segmentation from safety: {other}, expected {sorted(want_other)}")
    # a model that allows everything has nothing to report
    open_model = {"zones": {**SEG_ZONES["zones"], "extra": ["127.0.0.3/32"]},
                  "conduits": [{"from": "enterprise", "to": z, "ports": ["any"]} for z in ("dmz", "control", "safety", "extra")]}
    json.dump(open_model, open(zones, "w"))
    r = segmentation(exe, host_db, zones, "--from", "enterprise", "--format", "json", "--fail-on-findings")
    if r.returncode != 0 or json.loads(r.stdout)["violations"]:
        failures.append(f"segmentation: an allow-all model still reported violations (exit {r.returncode})")
    # mistakes in the input are errors, not silence
    if segmentation(exe, host_db, zones, "--from", "nowhere").returncode == 0:
        failures.append("segmentation: an undeclared --from zone was accepted")
    print(f"segmentation: {len(got)} violations from enterprise, exactly the expected ones")


# C20: the SNMP read with the credentials of the lab agent (simulators.py, UDP 161).
EXPECT_SNMP = {
    "snmp.sysdescr": "Lab Switch 24G (LabOS 3.1.4)",
    "snmp.sysname": "lab-sw1",
    "snmp.sysobjectid": "1.3.6.1.4.1.8072.3.2.10",
    "snmp.if.1": "Gi1/0/1; 00:1B:21:0A:0B:01; up",
    "snmp.if.2": "Gi1/0/2; 00:1B:21:0A:0B:02; down",
    "snmp.ip.10.77.0.2": "ifIndex 3, mask 255.255.255.0",
    # ifName (IF-MIB ifXTable) and the IPv6 address of ipAddressTable
    "snmp.ifname.1": "Gi1/0/1",
    "snmp.ifname.3": "Vlan1",
    "snmp.ip.fd00:0:0:77::2": "ifIndex 3",
    "snmp.lldp.0.sys_name": "dist-sw2",
    "snmp.lldp.0.port_id": "Gi0/24",
    "snmp.lldp.0.chassis_id": "00:1B:21:77:00:01",
    "snmp.lldp.1.sys_name": "lab-ap",
}


def check_snmp(exe, work, stats_file, failures):
    """v2c, v1 and v3 (authNoPriv, SHA-1 and the weak MD5, passphrase from an environment variable)
    read the lab agent in Safe Mode; the community may come from an environment variable; a wrong community reads nothing; the agent never receives anything but
    GetRequest, GetNextRequest and GetBulkRequest."""
    options = ("--ports", "8080", "--timeout", "1500", "--tcp-only")
    os.environ["LAB_SNMP_AUTH"] = "lab-snmp-auth-pass"
    os.environ["LAB_SNMP_COMMUNITY"] = "lab-community"
    runs = (("v2c", ("--snmp-community", "lab-community"), {}),
            ("v2c", ("--snmp-community-env", "LAB_SNMP_COMMUNITY"), {}),
            ("v3-md5", ("--snmp-v3", "labuser-md5:md5:LAB_SNMP_AUTH"), {"snmp.engine_id": "80001f88801a2b3c4d5e6f7081"}),
            ("v1", ("--snmp-community", "lab-community", "--snmp-version", "1"), {}),
            ("v3", ("--snmp-v3", "labuser:sha:LAB_SNMP_AUTH"), {"snmp.engine_id": "80001f88801a2b3c4d5e6f7081"}))
    for name, snmp_options, extra in runs:
        host, _, _ = scan(exe, work, f"snmp-{name}", *options, *snmp_options)
        for key, want in {**EXPECT_SNMP, **extra}.items():
            if host["identity"].get(key) != want:
                failures.append(f"snmp {name}: {key}: expected {want!r}, got {host['identity'].get(key)!r}")
        kinds = {(e["kind"], e["detail"].split(":")[0]) for e in host.get("sent_in_output") or []}
        want_kind = ("snmp-request", "SNMPv3" if name.startswith("v3") else f"SNMP{name}")
        if want_kind not in kinds:
            failures.append(f"snmp {name}: {want_kind} missing from the sent log: {sorted(kinds)}")
        if 161 not in host["udp_open"]:
            failures.append(f"snmp {name}: udp 161 not listed as open: {host['udp_open']}")
    # a wrong community: no identity, no noise, no guessing (one request, two attempts)
    before = read_stats(stats_file).get("datagrams", 0)
    host, _, _ = scan(exe, work, "snmp-wrong", *options, "--snmp-community", "public")
    if any(k.startswith("snmp.") for k in host["identity"]):
        failures.append(f"snmp wrong community: identity was filled: {host['identity']}")
    if any(e.startswith("SNMP:") for e in host["errors"]):
        failures.append(f"snmp wrong community: silence is not an error, got {host['errors']}")
    time.sleep(0.3)
    used = read_stats(stats_file).get("datagrams", 0) - before
    if used != 2:
        failures.append(f"snmp wrong community: {used} datagrams reached the agent, expected 2 (one request, two attempts)")
    # a wrong v3 passphrase is refused by the agent's report, not by a timeout
    os.environ["LAB_SNMP_AUTH"] = "another-passphrase"
    host, _, _ = scan(exe, work, "snmp-v3-wrong", *options, "--snmp-v3", "labuser:sha:LAB_SNMP_AUTH")
    if not any("wrong authentication password" in e for e in host["errors"]):
        failures.append(f"snmp v3 wrong passphrase: no reason in {host['errors']}")
    # read-only: the agent saw only Get (0xa0), GetNext (0xa1) and GetBulk (0xa5)
    stats = read_stats(stats_file)
    tags = set(stats.get("pdu_tags", {}))
    if not tags or not tags <= {"0xa0", "0xa1", "0xa5"} or stats.get("other_pdus"):
        failures.append(f"snmp: the agent received other PDUs than Get/GetNext/GetBulk: {stats}")
    print(f"snmp: PDU tags seen by the agent {sorted(tags)}, {stats.get('datagrams')} datagrams")


# C23: Omron FINS (UDP 9600), Niagara Fox (TCP 1911), MQTT (TCP 1883) and KNXnet/IP (UDP 3671).
EXPECT_OT_EXTRA = {
    "Omron FINS.model": "LabPLC-FINS",
    "Omron FINS.firmware": "01.00",
    "Niagara Fox.station_name": "LabStation",
    "Niagara Fox.os_name": "QNX",
    "Niagara Fox.app_version": "4.8.0.1",
    "MQTT.connack": "refused: not authorized",
    "MQTT.connack_info": "authentication required",
    "KNXnet/IP.name": "Lab KNX IP Router",
    "KNXnet/IP.individual_address": "1.1.250",
    "KNXnet/IP.mac": "00:1B:21:AA:BB:CC",
    "KNXnet/IP.services": "Core 1, Device Management 1, Tunnelling 1, Routing 1",
}
EXPECT_OT_REQUESTS = (
    "Omron FINS/UDP: Controller Data Read (command 0x0501)",
    "Niagara Fox: hello (fox a 1 -1 fox hello)",
    "MQTT: CONNECT (packet type 1, clean session, no credentials)",
    "MQTT: DISCONNECT (packet type 14)",
    "KNXnet/IP: DESCRIPTION_REQUEST (service type 0x0203, unicast)",
)


def check_ot_extra(exe, work, stats_file, failures):
    """--ot in Safe Mode reads the four devices, and they receive nothing but the one read-only
    request each: FINS 0x0501, MQTT CONNECT and DISCONNECT, KNX 0x0203, the Fox hello."""
    def counted():
        time.sleep(0.3)
        return read_stats(stats_file)

    def delta(after, before):
        return {proto: {k: n - before.get(proto, {}).get(k, 0) for k, n in kinds.items() if n != before.get(proto, {}).get(k, 0)}
                for proto, kinds in after.items()}

    start = counted()
    host, _, _ = scan(exe, work, "ot-extra", "--ot", "--ports", "1883,1911", "--timeout", "1500", "--tcp-only")
    for key, want in EXPECT_OT_EXTRA.items():
        if host["identity"].get(key) != want:
            failures.append(f"ot extra: {key}: expected {want!r}, got {host['identity'].get(key)!r}")
    sent = {e["detail"] for e in host.get("sent_in_output") or [] if e["kind"] == "ot-request"}
    for want in EXPECT_OT_REQUESTS:
        if want not in sent:
            failures.append(f"ot extra: {want!r} missing from the sent log: {sorted(sent)}")
    for udp in (9600, 3671):
        if udp not in host["udp_open"]:
            failures.append(f"ot extra: udp {udp} not listed as open: {host['udp_open']}")
    stats = delta(counted(), start)
    if stats.get("fins") != {"0501": 1} or stats.get("knx") != {"0x203": 1}:
        failures.append(f"ot extra: FINS/KNX received more than the one identification request: {stats}")
    if stats.get("mqtt") != {"1": 1, "14": 1} or stats.get("fox") != {"hello": 1}:
        failures.append(f"ot extra: MQTT/Fox received more than CONNECT+DISCONNECT / the hello: {stats}")
    print(f"ot extra: devices received {stats}")
    # with --services the MQTT service probe has sent the CONNECT: --ot must not send a second one
    before = counted()
    scan(exe, work, "ot-extra-services", "--ot", "--services", "--ports", "1883", "--timeout", "1500", "--tcp-only")
    connects = delta(counted(), before).get("mqtt", {}).get("1", 0)
    if connects != 1:
        failures.append(f"ot extra: --ot --services sent {connects} MQTT CONNECTs, expected one (the service probe's)")


def check_favicon(exe, work, failures):
    """`--favicon` on the lab web server alone (the simulators' other ports are not scanned): the hash
    Shodan would index, computed here independently of the Rust code, must come out."""
    with Sim():
        host, _, _ = scan(exe, work, "favicon", "--fast", "--deep", "--favicon", "--ports", "8080", "--timeout", "1500")
    for key, want in missing_identity(host, EXPECT_FAVICON).items():
        failures.append(f"favicon hash {key}: expected {want!r} (computed independently in Python), got {host['identity'].get(key)!r}")
    asked = [e for e in host["sent_in_output"] or [] if e["kind"] == "http-request" and e["detail"] == "GET /favicon.ico"]
    if [e["count"] for e in asked] != [1]:
        failures.append(f"sent log: expected one favicon request, got {asked}")


def check_ot_tcp(exe, work, stats_file, failures):
    """C23: FINS over TCP (9600, `--ot`), the MELSEC MC protocol (only on `--melsec-port`) and DNP3
    (only to `--dnp3-address`). The lab devices count what they receive: FINS/TCP gets its two
    captured frames, MC the one CPU model read, DNP3 one Read of class 0 whose CRCs the Python
    code (written independently) verifies; a scan without the two options sends nothing to their
    ports, and a broadcast address is refused before anything is sent."""
    def counted():
        time.sleep(0.3)
        return read_stats(stats_file)

    def delta(after, before, proto):
        a, b = after.get(proto, {}), before.get(proto, {})
        return {k: n - b.get(k, 0) for k, n in a.items() if n != b.get(k, 0)}

    # FINS over TCP: --ot and tcp/9600 found open
    before = counted()
    host, _, _ = scan(exe, work, "ot-fins-tcp", "--ot", "--ports", "9600", "--timeout", "1500", "--tcp-only")
    sent = {e["detail"] for e in host.get("sent_in_output") or [] if e["kind"] == "ot-request"}
    for want in ("Omron FINS/TCP: node address data (FINS/TCP command 0)", "Omron FINS/TCP: Controller Data Read (command 0x0501)"):
        if want not in sent:
            failures.append(f"ot tcp: {want!r} missing from the sent log: {sorted(sent)}")
    if host["identity"].get("Omron FINS/TCP.model") != "LabPLC-FINS":
        failures.append(f"ot tcp: FINS/TCP model: {host['identity'].get('Omron FINS/TCP.model')!r}")
    got = delta(counted(), before, "fins_tcp")
    if got != {"node-address": 1, "0501": 1}:
        failures.append(f"ot tcp: the FINS/TCP device received {got}, expected the node address request and one 0x0501")
    # MC and DNP3 need their options: without them nothing goes to those ports
    before = counted()
    host, _, _ = scan(exe, work, "ot-no-optin", "--ot", "--ports", "15007,20000", "--timeout", "1500", "--tcp-only")
    # (--ot always sends its BACnet, FINS and KNX requests; none of them is an MC or DNP3 request)
    optin_sent = [e for e in host.get("sent_in_output") or [] if e["kind"] == "ot-request" and e["detail"].startswith(("MELSEC", "DNP3"))]
    if optin_sent:
        failures.append(f"ot tcp: --ot alone sent MC or DNP3 requests: {optin_sent}")
    after = counted()
    if delta(after, before, "mc") or delta(after, before, "dnp3"):
        failures.append(f"ot tcp: the MC/DNP3 devices received something without their options: {delta(after, before, 'mc')} {delta(after, before, 'dnp3')}")
    # with the options: one CPU model read, one Read class 0
    before = counted()
    host, _, _ = scan(exe, work, "ot-optin", "--ot", "--ports", "15007,20000", "--melsec-port", "15007", "--dnp3-address", "10",
                      "--timeout", "1500", "--tcp-only")
    for key, want in {"MELSEC.model": "LabQ03UDE", "MELSEC.model_code": "0268", "DNP3.link_address": "10", "DNP3.iin_raw": "0000"}.items():
        if host["identity"].get(key) != want:
            failures.append(f"ot tcp: {key}: expected {want!r}, got {host['identity'].get(key)!r}")
    sent = {e["detail"] for e in host.get("sent_in_output") or [] if e["kind"] == "ot-request"}
    for want in ("MELSEC MC 3E: Read CPU Model Name (command 0x0101, subcommand 0x0000)",
                 "DNP3: Read class 0 data (function 0x01, object group 60 variation 1)"):
        if want not in sent:
            failures.append(f"ot tcp: {want!r} missing from the sent log: {sorted(sent)}")
    after = counted()
    if delta(after, before, "mc") != {"0101": 1}:
        failures.append(f"ot tcp: the MC device received {delta(after, before, 'mc')}, expected one 0x0101")
    if delta(after, before, "dnp3") != {"read-class0": 1}:
        failures.append(f"ot tcp: the DNP3 outstation received {delta(after, before, 'dnp3')}, expected one Read of class 0 with valid CRCs")
    # a broadcast address and an MC port that is another protocol's are refused up front
    for bad, text in ((("--dnp3-address", "65535"), "unicast"), (("--melsec-port", "502"), "above 1023")):
        run = subprocess.run([exe, "scan", "127.0.0.1", "--ot", "--ports", "20000,502", *bad, "--db", os.path.join(work, "refused.sqlite")],
                             capture_output=True, text=True, timeout=60)
        if run.returncode == 0 or text not in run.stderr:
            failures.append(f"ot tcp: {bad} was not refused ({run.returncode}): {run.stderr.strip()[:200]}")
    if delta(counted(), after, "dnp3") or delta(counted(), after, "mc"):
        failures.append("ot tcp: a refused option still sent something")
    # the dry run lists them, and only with the options
    plan = subprocess.run([exe, "scan", "127.0.0.1", "--ot", "--ports", "15007,20000", "--melsec-port", "15007", "--dnp3-address", "10", "--dry-run"],
                          capture_output=True, text=True, timeout=60).stdout
    for want in ("MELSEC MC 3E: Read CPU Model Name", "DNP3: Read class 0 data", "tcp/15007", "Omron FINS/TCP"):
        if want not in plan:
            failures.append(f"ot tcp: the dry run does not list {want!r}")
    plain = subprocess.run([exe, "scan", "127.0.0.1", "--ot", "--ports", "15007,20000", "--dry-run"], capture_output=True, text=True, timeout=60).stdout
    if "MELSEC MC 3E" in plain or "DNP3: Read" in plain:
        failures.append("ot tcp: the dry run lists MC or DNP3 requests without their options")
    print(f"ot tcp: FINS/TCP, MC (port 15007) and DNP3 (outstation 10) devices received exactly the allowed requests")


def banner_wait(port):
    """Seconds until the first byte of a connection, or None if it is closed without one."""
    started = time.time()
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
            sock.settimeout(3)
            return time.time() - started if sock.recv(64) else None
    except OSError:
        return None


def check_slow_wan(exe, work, failures):
    """Every reply 150-300 ms late: the default timeouts must still find everything."""
    with Sim("--scenario", "slow-wan"):
        waits = [banner_wait(21) for _ in range(3)]
        if None in waits or min(waits) < 0.14:
            failures.append(f"slow-wan: the simulator does not delay its replies (banner after {waits} s)")
        waits = [w for w in waits if w]
        host, ids, seconds = deep_scan(exe, work, "slow")  # no --timeout: the defaults
    print(f"slow-wan: banner after {min(waits, default=0):.2f}-{max(waits, default=0):.2f} s, scan took {seconds:.1f} s with the default timeouts")
    if host["open"] != OPEN_PORTS:
        failures.append(f"slow-wan: open ports {host['open']}, expected {OPEN_PORTS}")
    for key, want in missing_identity(host).items():
        failures.append(f"slow-wan identity {key}: expected {want!r}, got {host['identity'].get(key)!r}")
    for want in sorted(EXPECT_FINDINGS - ids):
        failures.append(f"slow-wan finding missing: {want}")
    if seconds > SLOW_WAN_MAX_SCAN_SECONDS:
        failures.append(f"slow-wan: the scan took {seconds:.0f} s (limit {SLOW_WAN_MAX_SCAN_SECONDS} s)")


def check_lossy(exe, work, failures):
    """3 of 10 connections reset: ports are still found, identities come back on a repeated scan."""
    total = len(EXPECT_IDENTITY) + len(EXPECT_FINDINGS)
    with Sim("--scenario", "lossy", "--loss", str(LOSSY_LOSS), "--seed", str(LOSSY_SEED)):
        # Self-check, UDP: 3 of 10 Who-Is requests get no reply. Both checks come first, while the
        # seeded blocks of ten are still aligned with the first request.
        replies = 0
        for _ in range(10):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(0.5)
                sock.sendto(bytes([0x81, 0x0B, 0x00, 0x0C, 0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08]), ("127.0.0.1", 47808))
                try:
                    replies += bool(sock.recv(64))
                except OSError:
                    pass
        if replies != 10 - round(LOSSY_LOSS * 10):
            failures.append(f"lossy: {replies} of 10 BACnet requests answered, expected {10 - round(LOSSY_LOSS * 10)}")
        # Self-check: exactly 3 of 10 connections to one port must be lost, or the scenario is a no-op.
        lost = sum(banner_wait(21) is None for _ in range(10))
        if lost != round(LOSSY_LOSS * 10):
            failures.append(f"lossy: {lost} of 10 test connections lost, expected {round(LOSSY_LOSS * 10)}")
        have_identity, have_findings = set(), set()
        for number in range(1, LOSSY_MAX_SCANS + 1):
            host, ids, _ = deep_scan(exe, work, f"lossy{number}", "--timeout", "1500")
            if host["open"] != OPEN_PORTS:
                failures.append(f"lossy scan {number}: open ports {host['open']}, expected {OPEN_PORTS}")
            have_identity |= set(EXPECT_IDENTITY) - set(missing_identity(host))
            have_findings |= ids & EXPECT_FINDINGS
            recovered = (len(have_identity) + len(have_findings)) / total
            print(f"lossy: after scan {number}: {len(have_identity) + len(have_findings)} of {total} expected values found ({recovered:.0%})")
            if number == 1 and recovered < LOSSY_FIRST_SCAN_MIN:
                failures.append(f"lossy: the first scan found {recovered:.0%}, expected at least {LOSSY_FIRST_SCAN_MIN:.0%}")
            if recovered == 1:
                break
        else:
            failures.append(f"lossy: {total - len(have_identity) - len(have_findings)} expected values still missing after {LOSSY_MAX_SCANS} scans")


def read_stats(path):
    for _ in range(20):
        try:
            return json.load(open(path))
        except (OSError, ValueError):
            time.sleep(0.1)
    return {}


def fragile_control(kind, offset, work, failures):
    """The tripwires work: a write or a connection flood really takes a device down."""
    stats_file = os.path.join(work, f"control-{kind}.json")
    port = {"modbus-write": 502, "enip-write": 44818, "s7-write": 102, "flood": 502}[kind] + offset
    with Sim("--scenario", "fragile-ot", "--offset", str(offset), "--conn-limit", str(FRAGILE_CONN_LIMIT), "--stats", stats_file):
        if kind == "flood":
            socks = []
            for _ in range(FRAGILE_CONN_LIMIT + 3):
                try:
                    socks.append(socket.create_connection(("127.0.0.1", port), timeout=1))
                except OSError:
                    break
        else:
            sock = socket.create_connection(("127.0.0.1", port), timeout=2)
            if kind == "modbus-write":
                sock.sendall(struct.pack(">HHHBBHH", 1, 0, 6, 1, 6, 0, 1))  # write single register
            elif kind == "enip-write":
                sock.sendall(struct.pack("<HHII8sI", 0x6F, 0, 0, 0, b"NETSCOPE", 0))  # SendRRData
            else:
                sock.sendall(bytes([3, 0, 0, 22, 17, 0xE0, 0, 0, 0, 1, 0, 0xC1, 2, 1, 0, 0xC2, 2, 1, 2, 0xC0, 1, 10]))
                sock.settimeout(2)
                sock.recv(64)
                sock.sendall(bytes([3, 0, 0, 19, 2, 0xF0, 0x80, 0x32, 1, 0, 0, 0, 1, 0, 2, 0, 0, 0x05, 0x01]))  # write variable
        time.sleep(1)
        stats = read_stats(stats_file)
        device = next((d for d in stats.values() if d["port"] == port), {})
        refused = False
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
        except OSError:
            refused = True
    if not device.get("crashed") or not refused:
        failures.append(f"fragile-ot control {kind}: the device did not crash ({device})")
    if kind != "flood" and device.get("writes") != 1:
        failures.append(f"fragile-ot control {kind}: expected one counted write ({device})")
    print(f"fragile-ot control {kind}: crashed={bool(device.get('crashed'))} ({device.get('crashed')})")


def check_fragile_ot(exe, work, failures):
    """The scanner never writes to, nor floods, fragile OT devices (Safe Mode and --fast)."""
    for kind, offset in (("modbus-write", 10000), ("enip-write", 12000), ("s7-write", 14000), ("flood", 16000)):
        fragile_control(kind, offset, work, failures)
    stats_file = os.path.join(work, "fragile-stats.json")
    runs = (("safe mode", ("--ot", "--ports", OT_PORTS, "--timeout", "1500")),
            ("--fast", ("--fast", "--ot", "--ports", OT_PORTS, "--timeout", "1500")),
            ("--fast --deep", ("--fast", "--deep", "--ot", "--ports", PORTS + ",102", "--timeout", "1500")))
    with Sim("--scenario", "fragile-ot", "--conn-limit", str(FRAGILE_CONN_LIMIT), "--stats", stats_file):
        for name, options in runs:
            host, _, seconds = scan(exe, work, "fragile", *options)
            for key, want in {**EXPECT_S7, "Modbus.vendor": "LabWorks", "EtherNet/IP.vendor": "Rockwell Automation/Allen-Bradley"}.items():
                if host["identity"].get(key) != want:
                    failures.append(f"fragile-ot ({name}): identity {key}: expected {want!r}, got {host['identity'].get(key)!r}")
            stats = read_stats(stats_file)
            print(f"fragile-ot ({name}, {seconds:.1f} s): " + ", ".join(
                f"{n} {d['connections']} connections (max {d['max_connections_per_second']}/s), {d['requests']} requests, {d['writes']} writes" for n, d in stats.items()))
            for device_name, device in stats.items():
                if device["crashed"]:
                    failures.append(f"fragile-ot ({name}): {device_name} crashed: {device['crashed']}")
                if device["writes"]:
                    failures.append(f"fragile-ot ({name}): {device_name} received {device['writes']} write/control request(s)")
                if device["max_connections_per_second"] > FRAGILE_CONN_LIMIT:
                    failures.append(f"fragile-ot ({name}): {device_name} saw {device['max_connections_per_second']} connections in one second")
                if not device["requests"]:
                    failures.append(f"fragile-ot ({name}): {device_name} received no request, nothing was checked")
            time.sleep(1.2)  # the rate window of the devices is one second


CHECKS = {"normal": check_normal, "slow-wan": check_slow_wan, "lossy": check_lossy, "fragile-ot": check_fragile_ot}


def flaky_device(accepts):
    """A loopback 'device' that accepts `accepts` connections and then stops listening, so every
    later connect is refused (or silently dropped, depending on the OS). Returns its port."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    port = server.getsockname()[1]

    def serve():
        for _ in range(accepts):
            try:
                connection, _ = server.accept()
                connection.close()
            except OSError:
                break
        server.close()

    threading.Thread(target=serve, daemon=True).start()
    return port


def backoff_notes(exe, work, name, port, extra):
    out = os.path.join(work, f"{name}.json")
    # --rate 5: 200 ms between the port probe and the identification connect, so the device's
    # thread has closed its listener by then. Without it, macOS runners lost that race every time.
    subprocess.run([exe, "scan", "127.0.0.1", "--fast", "--tcp-only", "--services", "--ports", str(port),
                    "--rate", "5",
                    "--timeout", "1500", "--retries", "0", "--db", os.path.join(work, f"{name}.sqlite"),
                    "--output", out, "--quiet"] + extra, check=True, timeout=120)
    host = json.load(open(out))["hosts"][0]
    return host, [e for e in host["errors"] if e.startswith("backed off:")]


def check_backoff(exe, work, failures):
    """H52: a device that refuses after its first connection gets a 'backed off' note, and
    --no-backoff turns that off. The healthy lab host (main scan) must not get one."""
    # The fake device closes its listener on a thread; on a slow runner the identification
    # connect can still reach the backlog, and then the device has not stopped answering yet (no
    # error at all). Such a run proves nothing: try a fresh device a few times.
    for attempt in range(5):
        port = flaky_device(1)
        host, notes = backoff_notes(exe, work, f"flaky-{attempt}", port, [])
        if host["errors"]:
            break
    if port not in host["open"]:
        failures.append(f"back-off: the flaky port {port} was not found open")
    if not any(f"port {port} stopped answering after it was found open" in n for n in notes):
        failures.append(f"back-off: no note for a device that stops answering: {host['errors']}")
    port = flaky_device(1)
    _, notes = backoff_notes(exe, work, "flaky-off", port, ["--no-backoff"])
    if notes:
        failures.append(f"back-off: --no-backoff still backed off: {notes}")


def check_dry_run_and_sent_log(exe, work, host, failures):
    """H53: the real scan's JSON carries the sent log; --dry-run lists the plan and sends nothing
    (a listener that counts connections is the target)."""
    sent = host.get("sent_in_output")
    kinds = {e["kind"] for e in sent or []}
    for want in ("icmp-echo", "tcp-connect", "udp-probe", "ot-request"):
        if want not in kinds:
            failures.append(f"sent log: {want} missing from {sorted(kinds)}")
    counter = socket.socket()
    counter.bind(("127.0.0.1", 0))
    counter.listen(8)
    counter.settimeout(0.5)
    port = counter.getsockname()[1]
    db = os.path.join(work, "dry.sqlite")
    out = subprocess.run([exe, "scan", "127.0.0.1", "--dry-run", "--fast", "--deep", "--ot", "--favicon", "--ports",
                          str(port), "--db", db], check=True, capture_output=True, text=True, timeout=60).stdout
    if "DRY RUN: nothing was sent." not in out or "tcp-connect" not in out:
        failures.append(f"dry run output unexpected: {out[:200]!r}")
    if "GET /favicon.ico" not in out:
        failures.append("dry run does not list the favicon request")
    if os.path.exists(db):
        failures.append("dry run saved a scan")
    try:
        counter.accept()
        failures.append("dry run connected to the target")
    except socket.timeout:
        pass
    finally:
        counter.close()


def main():
    global LOSSY_SEED
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1], formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exe", help="the built network-scope binary")
    ap.add_argument("--scenario", choices=[*CHECKS, "all"], default="normal")
    ap.add_argument("--seed", type=int, default=LOSSY_SEED, help="seed of the lossy scenario (to try others)")
    args = ap.parse_args()
    # The scope guard reads a default scope file from the config folder; a developer's own file
    # must not change the result of the lab (it only knows loopback addresses).
    os.environ["LOCALAPPDATA"] = os.environ["XDG_CONFIG_HOME"] = tempfile.mkdtemp(prefix="ns-config-")
    LOSSY_SEED = args.seed
    exe = os.path.abspath(args.exe)
    work = tempfile.mkdtemp(prefix="ns-lab-")
    failures = []
    for name in (CHECKS if args.scenario == "all" else [args.scenario]):
        before = len(failures)
        CHECKS[name](exe, work, failures)
        print(f"scenario {name}:", "FAILED" if len(failures) > before else "ok")
    for f in failures:
        print("FAIL", f)
    print("lab verification:", "FAILED" if failures else "all checks passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
