#!/usr/bin/env python3
"""End-to-end check: start the simulators on loopback, scan them with the built binary and
assert that the expected identities and findings come out. Exit code 0 means all passed.

  python lab/verify.py target/release/network-scope[.exe]
"""
import json
import os
import subprocess
import sys
import tempfile
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
        host = json.load(open(out))["hosts"][0]
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
