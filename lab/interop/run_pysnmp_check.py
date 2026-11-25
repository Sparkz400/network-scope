#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright the Network Scope contributors
# SPDX-License-Identifier: MIT
"""Runs Network Scope's SNMP client against the pysnmp agent (an independent implementation) and
prints what the agent received.

  python -m venv venv && venv/bin/pip install pysnmp cryptography        (Scripts/ on Windows)
  (pysnmp 7 uses `cryptography` for DES and AES; without it every authPriv request fails with a
  decryption error)
  python lab/interop/run_pysnmp_check.py --agent-python venv/bin/python

It starts `pysnmp_agent.py` on a free loopback port, runs the ignored cargo test
`pysnmp_agent_accepts_every_v3_level_and_its_replies_decode` against it and prints the agent's
own counts (requests by PDU type and by user and security level). Exit status 0: every level
worked and the agent saw only Get, GetNext and GetBulk requests.
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent-python", required=True, help="the python of a venv with pysnmp installed")
    args = parser.parse_args()
    port = free_port()
    stats = os.path.join(tempfile.mkdtemp(prefix="ns-pysnmp-"), "stats.json")
    agent = subprocess.Popen(
        [args.agent_python, "-I", os.path.join(HERE, "pysnmp_agent.py"), "--port", str(port), "--stats", stats],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        if not agent.stdout.readline().startswith("READY"):
            print("the pysnmp agent did not start", file=sys.stderr)
            return 2
        time.sleep(0.5)
        env = dict(os.environ, NS_PYSNMP_PORT=str(port))
        test = subprocess.run(
            ["cargo", "test", "-p", "network-scope-core", "--lib", "pysnmp_agent_accepts", "--",
             "--ignored", "--nocapture"],
            cwd=REPO, env=env, timeout=1200,
        )
        time.sleep(0.5)
        seen = json.load(open(stats))
        print("\npysnmp agent received:", json.dumps(seen, indent=2))
        bad = set(seen["pdu_types"]) - {"GetRequestPDU", "GetNextRequestPDU", "GetBulkRequestPDU"}
        if bad:
            print(f"the agent received PDU types other than Get/GetNext/GetBulk: {sorted(bad)}")
            return 1
        return test.returncode
    finally:
        agent.kill()
        agent.wait()


if __name__ == "__main__":
    sys.exit(main())
