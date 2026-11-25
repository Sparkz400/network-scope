# SPDX-FileCopyrightText: Copyright the Network Scope contributors
# SPDX-License-Identifier: MIT
"""Linux check of the unused-address skip on a real link: the runner's Docker bridge.

Run as an unprivileged user, so no ICMP: every address that answers no port is a candidate.

Single scans, `--fast`, 100 ports unless said otherwise:
- an unused address: marked unused, and faster than probing every port
- the same with 3 ports (the launch loop ends before the check is due)
- a live container with a listener: found as before, not unused
- a container that rejects every port but one with ICMP host-prohibited (what firewalld does by
  default; the kernel reports it as "no route to host", like a failed ARP): fully probed, its
  open port found, not unused
- a container stopped just before the scan, whose MAC is still in the neighbor table: not
  marked unused (an entry with a MAC proves nothing either way)

And one Safe Mode sweep of the bridge /27 with 3 ports (shared rate gate, 8 hosts at a time):
every unused address is marked unused, the containers are not.

Nothing leaves the machine. Needs Docker; Linux only. Usage:
    python -I lab/neighbor_check.py --cli target/release/network-scope-cli
"""
import argparse
import json
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

NOTE = "no ARP answer on the local link"
UNUSED = "172.17.0.200"
# Before the skip one unused address took 12.3 s, with it 3.6 s (ubuntu runner, 2026-11-21).
UNUSED_LIMIT_S = 6.0
BUSYBOX = "busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
ALPINE = "alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
LISTEN = "nc -lk -p 8080 -e true"


def docker(*args: str) -> str:
    return subprocess.run(["docker", *args], check=True, capture_output=True, text=True).stdout.strip()


def container(name: str, *args: str) -> str:
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    docker("run", "-d", "--name", name, *args)
    # Per network: newer Docker releases dropped the top-level IPAddress field.
    return docker("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name)


def wait_open(ip: str, port: int) -> None:
    for _ in range(120):
        try:
            socket.create_connection((ip, port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.5)
    sys.exit(f"{ip}:{port} never opened")


def scan(cli: str, target: str, work: Path, *extra: str) -> tuple[dict, float]:
    """Scans `target`; returns the hosts by address (each with an `unused` flag) and the time."""
    out = work / "scan.json"
    start = time.monotonic()
    subprocess.run(
        [cli, "scan", target, "--scope", "172.17.0.0/16", "--quiet",
         "--db", str(work / "n.sqlite"), "--output", str(out), *extra],
        check=False,
    )
    took = time.monotonic() - start
    hosts = {}
    for host in json.loads(out.read_text())["hosts"]:
        host["unused"] = any(e.startswith(NOTE) for e in host.get("errors", []))
        hosts[host["ip"]] = host
    return hosts, took


def show(host: dict, took: float | None = None) -> None:
    when = f"{took:.1f} s, " if took is not None else ""
    print(f"{host['ip']}: {when}responding {host['responding']}, open {host['open']}, "
          f"closed {host['closed']}, unanswered {host['unanswered']}, unused {host['unused']}, "
          f"notes {[e[:80] for e in host.get('errors', [])[:3]]}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", required=True)
    cli = parser.parse_args().cli
    work = Path(tempfile.mkdtemp(prefix="neighbor-check-"))
    failures = []

    def check(ok: bool, what: str) -> None:
        print(("ok   " if ok else "FAIL ") + what)
        if not ok:
            failures.append(what)

    fast100 = ("--fast", "--ports", "top:100")
    live = container("ns-live", BUSYBOX, "sh", "-c", LISTEN)
    reject = container(
        "ns-reject", "--cap-add", "NET_ADMIN", ALPINE, "sh", "-c",
        "apk add --no-cache iptables >/dev/null"
        " && iptables -A INPUT -p tcp --dport 8080 -j ACCEPT"
        " && iptables -A INPUT -p tcp -j REJECT --reject-with icmp-host-prohibited"
        f" && {LISTEN}",
    )
    gone = container("ns-gone", BUSYBOX, "sh", "-c", LISTEN)
    for ip in (live, reject, gone):
        wait_open(ip, 8080)
    assert UNUSED not in (live, reject, gone)

    hosts, took = scan(cli, UNUSED, work, *fast100)
    host = hosts[UNUSED]
    show(host, took)
    check(host["unused"] and not host["responding"], f"unused {UNUSED} is marked unused")
    check(took < UNUSED_LIMIT_S, f"unused address took {took:.1f} s (< {UNUSED_LIMIT_S} s)")

    hosts, took = scan(cli, "172.17.0.201", work, "--fast", "--ports", "22,80,8080")
    show(hosts["172.17.0.201"], took)
    check(hosts["172.17.0.201"]["unused"], "unused address with 3 ports is marked unused")

    hosts, took = scan(cli, live, work, *fast100)
    show(hosts[live], took)
    check(hosts[live]["responding"] and 8080 in hosts[live]["open"] and not hosts[live]["unused"],
          "live container")

    hosts, took = scan(cli, reject, work, *fast100)
    show(hosts[reject], took)
    check(hosts[reject]["responding"] and 8080 in hosts[reject]["open"]
          and not hosts[reject]["unused"], "host-prohibited container: open port found, not unused")

    docker("rm", "-f", "ns-gone")
    hosts, took = scan(cli, gone, work, *fast100)
    show(hosts[gone], took)
    check(not hosts[gone]["responding"] and not hosts[gone]["unused"],
          "stopped container with a cached MAC")

    # Safe Mode (no --fast): the rate gate delays each host's first SYN, which the 3.5 s
    # must be counted from.
    hosts, took = scan(cli, "172.17.0.0/27", work, "--ports", "22,80,8080")
    print(f"Safe Mode /27, 3 ports: {took:.1f} s")
    for ip in sorted(hosts, key=lambda a: int(a.split(".")[-1])):
        show(hosts[ip])
    # The stopped container is left out: by now its cached MAC may have expired, and then its
    # address really is unused. 172.17.0.1 is the runner itself.
    known = {live, reject, gone, "172.17.0.1"}
    expected_unused = [ip for ip in hosts if ip not in known]
    missed = [ip for ip in expected_unused if not hosts[ip]["unused"]]
    check(not missed, f"Safe Mode sweep: {len(expected_unused) - len(missed)}/"
          f"{len(expected_unused)} unused addresses marked (missed {missed})")
    check(all(8080 in hosts[ip]["open"] and not hosts[ip]["unused"] for ip in (live, reject)),
          "Safe Mode sweep: live and host-prohibited containers found")

    for name in ("ns-live", "ns-reject"):
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    if failures:
        sys.exit(f"{len(failures)} check(s) failed")


if __name__ == "__main__":
    main()
