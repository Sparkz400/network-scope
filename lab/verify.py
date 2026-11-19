#!/usr/bin/env python3
"""End-to-end check: start the simulators on loopback, scan them with the built binary and
assert that the expected identities and findings come out. Exit code 0 means all passed.

  python lab/verify.py target/release/network-scope[.exe]
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PORTS = "21,22,23,502,6379,8080,44818"

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
EXPECT_FINDINGS = {
    "cve-cve-2011-2523", "cve-cve-2021-41773", "redis-noauth", "telnet-open",
    "ftp-cleartext", "ssh-weak-algorithms", "http-basic-cleartext", "ot-reachable",
}


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
    out = subprocess.run([exe, "scan", "127.0.0.1", "--dry-run", "--fast", "--deep", "--ot", "--ports", str(port),
                          "--db", db], check=True, capture_output=True, text=True, timeout=60).stdout
    if "DRY RUN: nothing was sent." not in out or "tcp-connect" not in out:
        failures.append(f"dry run output unexpected: {out[:200]!r}")
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
    exe = sys.argv[1]
    work = tempfile.mkdtemp(prefix="ns-lab-")
    db, out = os.path.join(work, "lab.sqlite"), os.path.join(work, "scan.json")
    sim = subprocess.Popen([sys.executable, os.path.join(HERE, "simulators.py"), "--bind", "127.0.0.1", "--skip", "80"],
                           stdout=subprocess.PIPE, text=True)
    failures = []
    try:
        sim.stdout.readline()
        time.sleep(0.5)
        subprocess.run([exe, "scan", "127.0.0.1", "--fast", "--deep", "--ot", "--ports", PORTS,
                        "--timeout", "1500", "--db", db, "--output", out], check=True, timeout=120)
        document = json.load(open(out))
        host = document["hosts"][0]
        host["sent_in_output"] = document.get("sent")
        slowed = [e for e in host["errors"] if e.startswith("backed off:")]
        if slowed:
            failures.append(f"healthy lab host was backed off: {slowed}")
        check_backoff(exe, work, failures)
        check_dry_run_and_sent_log(exe, work, host, failures)
        for key, want in EXPECT_IDENTITY.items():
            got = host["identity"].get(key)
            if got != want:
                failures.append(f"identity {key}: expected {want!r}, got {got!r}")
        found = subprocess.run([exe, "findings", "1", "--db", db], check=True, capture_output=True, text=True, timeout=60).stdout
        ids = {f["id"] for f in json.loads(found)}
        for want in sorted(EXPECT_FINDINGS - ids):
            failures.append(f"finding missing: {want}")
    finally:
        sim.kill()
    for f in failures:
        print("FAIL", f)
    print("lab verification:", "FAILED" if failures else "all checks passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
