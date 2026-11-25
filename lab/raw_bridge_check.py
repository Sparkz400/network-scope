# SPDX-FileCopyrightText: Copyright the Network Scope contributors
# SPDX-License-Identifier: MIT
"""The capture-driver features on Linux (libpcap), on a real link: the runner's Docker bridge.

Run as root (raw frames need it). Everything stays on the runner: the bridge, its containers
and a private routed network (10.200.0.0/24) that exists only behind a router container.

- SYN scan, on-link: a live container's open and closed ports, an unused address silent, no
  fallback to TCP connect
- SYN scan, routed: a target behind a router container, reached through the router's MAC
- ARP sweep: the containers found with their MAC
- TCP traceroute: hop 1 is the target on-link
- DCP Identify: exactly the one read-only frame on the wire (tcpdump)
- live OT capture (`ot-listen`): a Modbus/TCP request between a container and the host's lab
  simulator shows up as a Modbus asset
- DHCPv6 (`listen`): Solicits of real clients (busybox udhcpc6, ISC dhclient) on an IPv6 bridge

Usage (CI, after building the CLI and installing libpcap):
    sudo python3 -I lab/raw_bridge_check.py --cli target/release/network-scope-cli
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BUSYBOX = "busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
ALPINE = "alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
IFACE = "docker0"
ROUTED = "10.200.0.1"
UNUSED = "172.17.0.201"
SCOPE = "172.17.0.0/16,10.200.0.0/24"


def sh(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), check=check, capture_output=True, text=True)


def container(name: str, *args: str) -> str:
    sh("docker", "rm", "-f", name, check=False)
    sh("docker", "run", "-d", "--name", name, *args)
    return sh("docker", "inspect", "-f",
              "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name).stdout.strip()


def wait_open(ip: str, port: int) -> None:
    for _ in range(120):
        if sh("bash", "-c", f"exec 3<>/dev/tcp/{ip}/{port}", check=False).returncode == 0:
            return
        time.sleep(0.5)
    sys.exit(f"{ip}:{port} never opened")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli", required=True)
    cli = str(Path(parser.parse_args().cli).resolve())
    work = Path(tempfile.mkdtemp(prefix="raw-bridge-"))
    failures = []

    def check(ok: bool, what: str) -> None:
        print(("ok   " if ok else "FAIL ") + what, flush=True)
        if not ok:
            failures.append(what)

    source_ip = sh("bash", "-c", f"ip -4 -o addr show {IFACE} | awk '{{print $4}}' | cut -d/ -f1").stdout.strip()
    source_mac = Path(f"/sys/class/net/{IFACE}/address").read_text().strip()
    raw = ("--interface", IFACE, "--source-ip", source_ip, "--source-mac", source_mac)
    print(f"{IFACE}: {source_ip} {source_mac}")
    print(sh(cli, "interfaces", check=False).stdout)

    live = container("raw-live", BUSYBOX, "sh", "-c", "nc -lk -p 8080 -e true")
    router = container(
        "raw-router", "--cap-add", "NET_ADMIN", ALPINE, "sh", "-c",
        f"ip addr add {ROUTED}/32 dev lo && nc -lk -p 8080 -e true",
    )
    wait_open(live, 8080)
    wait_open(router, 8080)
    sh("ip", "route", "replace", "10.200.0.0/24", "via", router)
    wait_open(ROUTED, 8080)

    def scan(name: str, targets: list[str], *extra: str) -> tuple[dict, str]:
        out = work / f"{name}.json"
        run = sh(cli, "scan", *targets, "--fast", "--scope", SCOPE, "--quiet", "--sent-log",
                 "--db", str(work / "raw.sqlite"), "--output", str(out), *extra, check=False)
        hosts = {h["ip"]: h for h in json.loads(out.read_text())["hosts"]} if out.exists() else {}
        print(f"== {name} (exit {run.returncode})")
        for h in hosts.values():
            if h["responding"] or h["ip"] in targets:
                print(f"  {h['ip']}: responding {h['responding']}, mac {h.get('mac')!r}, open {h['open']}, "
                      f"closed {h['closed']}, unanswered {h['unanswered']}, notes {h.get('errors', [])[:3]}")
        print("  sent log:", " | ".join(run.stderr.strip().splitlines()[-6:]))
        return hosts, run.stderr

    def no_fallback(h: dict) -> bool:
        return not any("SYN unavailable" in e for e in h.get("errors", []))

    hosts, _ = scan("syn-onlink", [live, UNUSED], "--syn", "--ports", "22,80,8080", *raw)
    h = hosts.get(live, {})
    check(h.get("open") == [8080] and h.get("closed") == 2 and no_fallback(h),
          "SYN on-link: 8080 open, 22 and 80 closed, no TCP fallback")
    check(not hosts.get(UNUSED, {}).get("responding", True), "SYN on-link: unused address silent")

    hosts, _ = scan("syn-routed", [ROUTED], "--syn", "--ports", "22,8080", *raw)
    h = hosts.get(ROUTED, {})
    check(h.get("open") == [8080] and no_fallback(h),
          "SYN routed (via the router's MAC): 8080 open, no TCP fallback")

    hosts, _ = scan("arp-sweep", ["172.17.0.0/28"], "--arp-sweep", "--ports", "8080", *raw)
    for ip in (live, router):
        check(bool(hosts.get(ip, {}).get("mac")), f"ARP sweep: {ip} found with its MAC")

    trace = sh(cli, "trace", live, "--fast", "--trace-method", "tcp", "--trace-port", "8080",
               "--scope", SCOPE, "--sent-log", *raw, check=False)
    print("== tcp trace\n" + trace.stdout + trace.stderr[-600:])
    check(trace.returncode == 0 and live in trace.stdout, "TCP traceroute on-link reaches the target")

    if not shutil.which("tcpdump"):
        sh("apt-get", "install", "-y", "tcpdump")
    pcap = work / "dcp.pcap"
    dump = subprocess.Popen(["tcpdump", "-i", IFACE, "-U", "-w", str(pcap), "ether proto 0x8892"],
                            stderr=subprocess.DEVNULL)
    time.sleep(2)
    dcp = sh(cli, "dcp", "--interface", IFACE, "--source-mac", source_mac, "--seconds", "3",
             "--sent-log", check=False)
    time.sleep(1)
    dump.terminate()
    dump.wait()
    # One line per frame starts with its timestamp; tcpdump may add continuation lines.
    frames = [line for line in sh("tcpdump", "-r", str(pcap), check=False).stdout.splitlines()
              if re.match(r"\d\d:\d\d:\d\d", line)]
    print("== dcp (exit", dcp.returncode, ")\n" + dcp.stdout + dcp.stderr[-400:] + "\n" + "\n".join(frames))
    check(dcp.returncode == 0 and len(frames) == 1, f"DCP: one Identify frame on the wire ({len(frames)})")

    # The host's lab simulators (Modbus on 502) and a container as the Modbus client.
    sims = subprocess.Popen([sys.executable, "-I", "lab/simulators.py", "--bind", source_ip,
                             "--skip", "22", "53"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_open(source_ip, 502)
    ot_out = work / "ot.json"
    listen = subprocess.Popen([cli, "ot-listen", "--interface", IFACE, "--seconds", "12",
                               "--output", str(ot_out)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(3)
    # Modbus/TCP read holding register 0 (function 3), as octal escapes for busybox printf.
    request = r"\000\001\000\000\000\006\001\003\000\000\000\001"
    sh("docker", "run", "--rm", BUSYBOX, "sh", "-c",
       f"printf '{request}' | nc -w 2 {source_ip} 502 | od -An -tx1", check=False)
    out, err = listen.communicate(timeout=60)
    sims.terminate()
    assets = json.loads(ot_out.read_text()).get("assets", []) if ot_out.exists() else []
    print("== ot-listen (exit", listen.returncode, ")", err[-400:])
    print(json.dumps(assets, indent=1)[:1500])
    check(any("modbus" in json.dumps(a).lower() and source_ip in json.dumps(a) for a in assets),
          "live OT capture: the Modbus server is an asset")

    # DHCPv6 from real client implementations: a Solicit on an IPv6 bridge, decoded by `listen`.
    sh("docker", "network", "rm", "raw-v6", check=False)
    net = sh("docker", "network", "create", "--ipv6", "--subnet", "fd00:5c::/64", "raw-v6").stdout.strip()
    bridge = f"br-{net[:12]}"
    v6_out = work / "v6.json"
    capture = subprocess.Popen([cli, "listen", "--interface", bridge, "--seconds", "40",
                                "--db", str(work / "v6.sqlite"), "--output", str(v6_out)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(3)
    clients = {
        "busybox udhcpc6": ["docker", "run", "--rm", "--network", "raw-v6", "--cap-add", "NET_ADMIN",
                            BUSYBOX, "sh", "-c", "timeout 8 udhcpc6 -i eth0 -n -q -t 3"],
        "ISC dhclient": ["docker", "run", "--rm", "--network", "raw-v6", "--cap-add", "NET_ADMIN",
                         ALPINE, "sh", "-c", "apk add --no-cache dhclient >/dev/null"
                         " && timeout 8 dhclient -6 -1 -v eth0"],
    }
    for name, command in clients.items():
        run = subprocess.run(command, capture_output=True, text=True)
        print(f"== DHCPv6 client {name} (exit {run.returncode}):", (run.stdout + run.stderr)[-400:])
    out, err = capture.communicate(timeout=90)
    print("== listen on", bridge, "(exit", capture.returncode, ")", err[-300:])
    observations = json.loads(v6_out.read_text()).get("observations", []) if v6_out.exists() else []
    v6 = [o for o in observations if o.get("protocol") == "DHCPv6"]
    for o in v6:
        print("  ", o.get("mac"), o.get("ip"), o.get("fields"))
    check(any(o.get("fields", {}).get("message_type") == "solicit" and o.get("fields", {}).get("duid_type")
              for o in v6), f"DHCPv6: a real client's Solicit decoded ({len(v6)} DHCPv6 observations)")
    sh("docker", "network", "rm", "raw-v6", check=False)

    sh("ip", "route", "del", "10.200.0.0/24", check=False)
    for name in ("raw-live", "raw-router"):
        sh("docker", "rm", "-f", name, check=False)
    if failures:
        sys.exit(f"{len(failures)} check(s) failed")


if __name__ == "__main__":
    main()
