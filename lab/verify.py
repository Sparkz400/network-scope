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
    with Sim():
        host, ids, _ = deep_scan(exe, work, "normal", "--timeout", "1500", "--favicon")
        slowed = [e for e in host["errors"] if e.startswith("backed off:")]
        if slowed:
            failures.append(f"healthy lab host was backed off: {slowed}")
        check_backoff(exe, work, failures)
        check_dry_run_and_sent_log(exe, work, host, failures)
    for key, want in missing_identity(host).items():
        failures.append(f"identity {key}: expected {want!r}, got {host['identity'].get(key)!r}")
    # --favicon was on, but this host has industrial ports open: it must not be asked for an icon
    if any(e["detail"] == "GET /favicon.ico" for e in host["sent_in_output"] or []) or "http.8080.favicon_mmh3" in host["identity"]:
        failures.append("favicon: a host with industrial ports open was asked for /favicon.ico")
    check_favicon(exe, work, failures)
    for want in sorted(EXPECT_FINDINGS - ids):
        failures.append(f"finding missing: {want}")


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
    subprocess.run([exe, "scan", "127.0.0.1", "--fast", "--tcp-only", "--services", "--ports", str(port),
                    "--timeout", "1500", "--retries", "0", "--db", os.path.join(work, f"{name}.sqlite"),
                    "--output", out, "--quiet"] + extra, check=True, timeout=120)
    host = json.load(open(out))["hosts"][0]
    return host, [e for e in host["errors"] if e.startswith("backed off:")]


def check_backoff(exe, work, failures):
    """H52: a device that refuses after its first connection gets a 'backed off' note, and
    --no-backoff turns that off. The healthy lab host (main scan) must not get one."""
    port = flaky_device(1)
    host, notes = backoff_notes(exe, work, "flaky", port, [])
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
