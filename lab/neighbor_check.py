"""Linux check of the unused-address skip on a real link: the runner's Docker bridge.

Four cases, each one scan of 100 ports (`--fast`, as an unprivileged user, so no ICMP):

- an unused address on the bridge: marked unused, and faster than probing every port
- a live container with a listener: found as before, not unused
- a container that rejects every port but one with ICMP host-prohibited (what firewalld does by
  default; the kernel reports it as "no route to host", like a failed ARP): fully probed, its
  open port found, not unused
- a container stopped just before the scan, whose MAC is still in the neighbor table: not
  marked unused (an entry with a MAC proves nothing either way)

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

NOTE = "no ARP answer on the local link: the address is unused"
UNUSED = "172.17.0.200"
# Measured before the skip (probe run on ubuntu-24.04, 2026-11-21): 12.3 s for one unused address.
UNUSED_LIMIT_S = 8.0


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


def scan(cli: str, ip: str, work: Path) -> tuple[dict, float]:
    out = work / f"{ip}.json"
    start = time.monotonic()
    subprocess.run(
        [cli, "scan", ip, "--fast", "--ports", "top:100", "--scope", "172.17.0.0/16",
         "--quiet", "--db", str(work / "n.sqlite"), "--output", str(out)],
        check=False,
    )
    took = time.monotonic() - start
    host = json.loads(out.read_text())["hosts"][0]
    unused = any(e.startswith(NOTE) for e in host.get("errors", []))
    print(f"{ip}: {took:.1f} s, responding {host['responding']}, open {host['open']}, "
          f"closed {host['closed']}, unanswered {host['unanswered']}, unused {unused}, "
          f"notes {host.get('errors', [])[:3]}")
    host["unused"] = unused
    return host, took


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

    live = container("ns-live", "busybox:1.36", "sh", "-c", "nc -lk -p 8080 -e true")
    reject = container(
        "ns-reject", "--cap-add", "NET_ADMIN", "alpine:3.20", "sh", "-c",
        "apk add --no-cache iptables >/dev/null"
        " && iptables -A INPUT -p tcp --dport 8080 -j ACCEPT"
        " && iptables -A INPUT -p tcp -j REJECT --reject-with icmp-host-prohibited"
        " && nc -lk -p 8080 -e true",
    )
    gone = container("ns-gone", "busybox:1.36", "sh", "-c", "nc -lk -p 8080 -e true")
    for ip in (live, reject, gone):
        wait_open(ip, 8080)
    assert UNUSED not in (live, reject, gone)

    host, took = scan(cli, UNUSED, work)
    check(host["unused"] and not host["responding"], f"unused {UNUSED} is marked unused")
    check(took < UNUSED_LIMIT_S, f"unused address took {took:.1f} s (< {UNUSED_LIMIT_S} s)")

    host, _ = scan(cli, live, work)
    check(host["responding"] and 8080 in host["open"] and not host["unused"], "live container")

    host, _ = scan(cli, reject, work)
    check(host["responding"] and 8080 in host["open"] and not host["unused"],
          "host-prohibited container: open port found, not unused")

    docker("rm", "-f", "ns-gone")
    host, _ = scan(cli, gone, work)
    check(not host["responding"] and not host["unused"], "stopped container with a cached MAC")

    print(subprocess.run(["ip", "neigh", "show", "dev", "docker0"], capture_output=True, text=True).stdout)
    for name in ("ns-live", "ns-reject"):
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    if failures:
        sys.exit(f"{len(failures)} check(s) failed")


if __name__ == "__main__":
    main()
