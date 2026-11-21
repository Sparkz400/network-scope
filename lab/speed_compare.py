#!/usr/bin/env python3
"""Speed comparison of Network Scope with nmap and RustScan (roadmap B10). Python standard library only.

  python -I lab/speed_compare.py --cli /abs/path/to/network-scope-cli [--rustscan rustscan] \
      [--repeat 3] [--cells 24-top100,24-top1000,16-top100] [--check] [--out-dir speed-results]

Starts the lab simulators (lab/ground_truth.json, on 127.0.10.1-6) and times, per cell (a target
range and a port list), every tool on exactly the same targets and ports:

  Network Scope  scan <range> --fast --tcp-only --ports <list>     (TCP connect, no driver, no admin)
  nmap           nmap -sT -T4 -Pn -n -p <list> -oX <file> <range>  (connect scan, no driver)
  RustScan       rustscan -g --no-config -a <range> -p <list>      (connect scan, greppable, no nmap)
  nmap -sS       only with --syn-nmap "sudo -n nmap": SYN scan with raw sockets, reported separately

Cells: 24-top100, 24-top1000 (127.0.10.0/24), 16-top100, 16-top1000 (127.0.0.0/16). The port lists
are nmap's own top 100 / top 1000 (`nmap --top-ports N -oG - -v`), so all tools scan the same
ports. Without nmap the top 100 falls back to Network Scope's `top:100` list and top 1000 to ports
1-1000 (recorded as port_source; not comparable with nmap's lists).

A fast wrong answer does not count: the open (address, port) pairs a tool reports are compared
with what really listens, read from the operating system's table of listening sockets (Linux
/proc/net/tcp, otherwise `netstat -an`) after the lab has started. That includes the lab and
anything else on loopback (a listener on 0.0.0.0 is open on every 127.x address). A result is
correct when every lab port is found and nothing is reported open that does not listen; ports of
other listeners that were missed are reported separately (a system service's wildcard listener can
refuse when hundreds of connections reach it at once, which is the OS, not the scanner).

Each tool runs --repeat times, interleaved; wall time (median, min, max) and peak memory (the OS's
figure: GNU time's %M on Linux, ru_maxrss from wait4 on macOS, the peak working set on Windows) are
reported. Linux's wait4 figure is not used: a child's ru_maxrss keeps the high-water mark of the
process it was forked from (this Python harness), so every small tool would show the harness's
size; GNU time forks the tool from a process of about 2 MB. Without /usr/bin/time, Linux peaks are
reported as n/a. A run longer than
--limit seconds is stopped and reported as timed out.

--check fails (exit 1) only on Network Scope: when it reports a wrong open set in any cell, or its
median is more than --tolerance above lab/speed_baseline.json for this platform and cell (a missing
value passes with a notice). Other tools are reported, never gated. Exit 2: the lab or Network
Scope could not be run (not a measurement).

Only loopback addresses (127.0.0.0/8) are ever contacted, unless --lan names a real private /24
(or smaller) to time Network Scope on, in Safe Mode, with the network owner's permission.
"""
import argparse
import importlib.util
import ipaddress
import json
import os
import platform
import re
import shlex
import statistics
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PLATFORMS = {"win32": "windows", "linux": "linux", "darwin": "macos"}
CELLS = {"24-top100": ("127.0.10.0/24", 100), "24-top1000": ("127.0.10.0/24", 1000),
         "16-top100": ("127.0.0.0/16", 100), "16-top1000": ("127.0.0.0/16", 1000)}
DEFAULT_CELLS = "24-top100,24-top1000,16-top100"  # /16 x 1000 is 65 million connects per run


class SpeedError(Exception):
    """The lab or Network Scope could not be run (exit 2)."""


def load(name, path):
    # `python -I` keeps the script folder off sys.path, so load sibling modules by path.
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GNU_TIME = "/usr/bin/time" if sys.platform.startswith("linux") and os.access("/usr/bin/time", os.X_OK) else None


def gnu_time_peak(text):
    """Bytes from GNU time's `-f %M` output (KiB on the last line; a non-zero exit adds a line before it)."""
    lines = text.strip().splitlines()
    return int(lines[-1]) * 1024 if lines and lines[-1].strip().isdigit() else None


def run(cmd, limit_s):
    """(seconds, peak bytes or None, stdout, stderr, exit code or None when timed out)."""
    linux = sys.platform.startswith("linux")
    peak_file = None
    if linux and GNU_TIME:
        fd, peak_file = tempfile.mkstemp(prefix="speed-peak-")
        os.close(fd)
        cmd = [GNU_TIME, "-f", "%M", "-o", peak_file, *cmd]
    started = time.monotonic()
    try:
        # Own process group, so a timeout also stops the tool behind GNU time.
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=linux)
    except OSError as e:
        raise SpeedError(f"could not run {cmd[0]}: {e}") from None
    outs = {}
    readers = [threading.Thread(target=lambda n, s: outs.__setitem__(n, s.read()), args=(n, s))
               for n, s in (("out", proc.stdout), ("err", proc.stderr))]
    for t in readers:
        t.start()
    def stop():
        try:
            os.killpg(proc.pid, 9) if linux else proc.kill()
        except OSError:
            pass
    timer = threading.Timer(limit_s, stop)
    timer.start()
    peak = None
    if sys.platform == "win32":
        proc.wait()
        seconds = time.monotonic() - started
        try:
            peak = load("resource_budget", os.path.join(ROOT, "scripts", "resource_budget.py"))._windows_peak(proc._handle)
        except Exception:
            peak = None
        code = proc.returncode
    else:
        _, status, usage = os.wait4(proc.pid, 0)
        seconds = time.monotonic() - started
        code = os.waitstatus_to_exitcode(status)
        proc.returncode = code
        if sys.platform == "darwin":
            peak = usage.ru_maxrss
        elif peak_file:
            with open(peak_file, encoding="utf-8", errors="replace") as f:
                peak = gnu_time_peak(f.read())
            os.remove(peak_file)
    timed_out = not timer.is_alive()
    timer.cancel()
    for t in readers:
        t.join()
    return (seconds, peak, outs.get("out", b"").decode("utf-8", "replace"),
            outs.get("err", b"").decode("utf-8", "replace"), None if timed_out else code)


def parse_port_spec(text):
    """'1,3-4,7' -> [1, 3, 4, 7]."""
    ports = []
    for item in filter(None, (s.strip() for s in text.split(","))):
        a, _, b = item.partition("-")
        ports.extend(range(int(a), int(b or a) + 1))
    return ports


def nmap_ports_from_grepable(text):
    """The port list of nmap's '# Ports scanned: TCP(N;...)' header line."""
    m = re.search(r"Ports scanned: TCP\((\d+);([^)]*)\)", text)
    if not m:
        raise ValueError("no 'Ports scanned' line in nmap's output")
    ports = parse_port_spec(m.group(2))
    if len(ports) != int(m.group(1)):
        raise ValueError(f"nmap said {m.group(1)} ports but listed {len(ports)}")
    return ports


def nmap_top_ports(nmap, n):
    # No target: nmap prints the plan (including the port list) and scans nothing.
    _, _, out, err, _ = run([nmap, "-sT", "--top-ports", str(n), "-v", "-oG", "-"], 60)
    return nmap_ports_from_grepable(out + err)


def builtin_top100():
    """Network Scope's own `top:100` list, read from its source (used only when nmap is missing)."""
    with open(os.path.join(ROOT, "core", "src", "scan.rs"), encoding="utf-8") as f:
        m = re.search(r"pub const TOP_PORTS: \[u16; 100\] = \[([^\]]*)\]", f.read())
    return [int(p) for p in re.findall(r"\d+", m.group(1))]


def proc_net_listeners(text, v6=False):
    """LISTEN sockets of /proc/net/tcp or tcp6 -> {(address or '*', port)}."""
    found = set()
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 4 or cols[3] != "0A":  # 0A: TCP_LISTEN
            continue
        addr, port = cols[1].split(":")
        port = int(port, 16)
        if v6:
            if set(addr) == {"0"}:  # [::] accepts IPv4 too unless v6only (the Linux default is dual stack)
                found.add(("*", port))
            elif addr[:24].upper() == "0000000000000000FFFF0000":  # ::ffff:a.b.c.d
                found.add((str(ipaddress.IPv4Address(bytes(reversed(bytes.fromhex(addr[24:]))))), port))
            continue
        ip = str(ipaddress.IPv4Address(bytes(reversed(bytes.fromhex(addr)))))
        found.add(("*" if ip == "0.0.0.0" else ip, port))
    return found


def netstat_listeners(text):
    """IPv4 LISTEN sockets of `netstat -an` (Windows '127.0.0.1:80', macOS '127.0.0.1.80' or '*.80').

    A listener is recognised by its foreign address (0.0.0.0:0 or *.*), so a localised state
    column (German Windows: ABHÖREN) does not matter."""
    found = set()
    for line in text.splitlines():
        cols = line.split()
        if not cols or not cols[0].lower().startswith("tcp"):
            continue
        i = next((i for i, c in enumerate(cols) if re.fullmatch(r"(\d+\.\d+\.\d+\.\d+|\*)[.:]\d+", c)), None)
        if i is None or i + 1 >= len(cols) or cols[i + 1] not in ("0.0.0.0:0", "*.*"):
            continue
        addr, port = re.fullmatch(r"(.*)[.:](\d+)", cols[i]).groups()
        found.add(("*" if addr in ("*", "0.0.0.0") else addr, int(port)))
    return found


def listeners():
    if sys.platform.startswith("linux"):
        found = set()
        for name, v6 in (("tcp", False), ("tcp6", True)):
            try:
                with open(f"/proc/net/{name}", encoding="ascii") as f:
                    found |= proc_net_listeners(f.read(), v6)
            except OSError:
                pass
        return found
    out = subprocess.run(["netstat", "-an"], capture_output=True, text=True).stdout
    return netstat_listeners(out)


def expected_open(listening, hosts, ports):
    """Every (address, port) of the cell that something listens on."""
    port_set = set(ports)
    exact = {(a, p) for a, p in listening if a in hosts and p in port_set}
    wildcard = sorted(p for a, p in listening if a == "*" and p in port_set)
    return exact | {(h, p) for h in hosts for p in wildcard}


def lan_network(text):
    """The --lan range, refused unless it is a private IPv4 network of at most 256 addresses."""
    lan = ipaddress.IPv4Network(text)
    # is_private excludes 100.64.0.0/10 (shared address space, e.g. Tailscale): it reaches other sites.
    if not lan.is_private or lan.is_loopback or lan.is_link_local or lan.prefixlen < 24:
        raise ValueError(f"{text} is not a private IPv4 network of at most 256 addresses (e.g. 192.168.1.0/24)")
    return str(lan)


def ns_open(snapshot):
    return {(h["ip"], p) for h in snapshot.get("hosts", []) for p in h.get("open", [])}


def rustscan_open(text):
    """Greppable output: '127.0.10.1 -> [21,22,23]'."""
    found = set()
    for m in re.finditer(r"^\s*(\S+) -> \[([\d,\s]*)\]", text, re.M):
        found |= {(m.group(1), int(p)) for p in re.findall(r"\d+", m.group(2))}
    return found


# Shared runners differ in speed from run to run (seen: every tool 2 to 3 times slower in one run), so
# Network Scope is gated relative to this tool's time in the same run when both are in the baseline.
REFERENCE = "nmap -sT -T4"


def regressions(cells, baseline, tolerance, refs=None):
    """(failures, notices) for Network Scope's medians against the baseline of this platform.

    A baseline cell is seconds, or {"seconds", "reference_seconds"}: then, when the reference tool ran
    in this cell (refs), the ratio of the two times is compared instead of the seconds."""
    failures, notices = [], []
    refs = refs or {}
    allowed = f"allowed +{100 * tolerance:.0f}%"
    for cell, median in cells.items():
        base = baseline.get(cell)
        if base is None:
            notices.append(f"{cell}: no baseline for this platform; measured {median:.2f} s")
            continue
        seconds, ref_base = (base.get("seconds"), base.get("reference_seconds")) if isinstance(base, dict) else (base, None)
        if not isinstance(seconds, (int, float)) or seconds <= 0:
            notices.append(f"{cell}: the baseline has no usable seconds; measured {median:.2f} s")
            continue
        ref = refs.get(cell)
        if ref and ref_base:
            ratio, base_ratio = median / ref, seconds / ref_base
            if ratio > base_ratio * (1 + tolerance):
                failures.append(f"{cell}: Network Scope took {median:.2f} s, {ratio:.2f} x {REFERENCE} ({ref:.2f} s) "
                                f"in this run; baseline {base_ratio:.2f} x (+{100 * (ratio / base_ratio - 1):.0f}%, {allowed})")
        elif median > seconds * (1 + tolerance):
            failures.append(f"{cell}: Network Scope took {median:.2f} s, baseline {seconds:.2f} s "
                            f"(+{100 * (median / seconds - 1):.0f}%, {allowed})")
    return failures, notices


def version_of(cmd):
    try:
        _, _, out, err, code = run(cmd, 30)
    except SpeedError:
        return None
    if code != 0:
        return None
    lines = (out or err).strip().splitlines()
    return lines[0].strip() if lines else None


def machine():
    info = {"platform": platform.platform(), "machine": platform.machine(), "processor": platform.processor(),
            "logical_cpus": os.cpu_count(), "python": platform.python_version()}
    try:
        with open("/proc/meminfo", encoding="ascii") as f:
            info["memory_kb"] = int(re.search(r"MemTotal:\s+(\d+)", f.read()).group(1))
        with open("/proc/cpuinfo", encoding="ascii") as f:
            m = re.search(r"model name\s*:\s*(.*)", f.read())
            info["processor"] = m.group(1).strip() if m else info["processor"]
    except OSError:
        pass
    try:
        info["soft_open_files_limit"] = __import__("resource").getrlimit(__import__("resource").RLIMIT_NOFILE)[0]
    except ImportError:
        pass
    try:
        info["commit"] = subprocess.run(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"],
                                        capture_output=True, text=True).stdout.strip() or None
    except OSError:
        pass
    return info


def tool_commands(args, work):
    """label -> function(range, ports, run number) -> (cmd, parse(stdout) -> open set or None on failure)."""
    tools = {}

    def ns(cidr, ports, i):
        db, out = os.path.join(work, f"ns{i}.sqlite"), os.path.join(work, f"ns{i}.json")
        for path in (db, out):
            if os.path.exists(path):
                os.remove(path)
        # On a real LAN Network Scope stays in Safe Mode unless --fast: the owner's devices are real.
        mode = ["--fast"] if args.fast or not args.lan else []
        cmd = [args.cli, "scan", cidr] + mode + ["--tcp-only", "--ports", ",".join(map(str, ports)),
               "--scope", args.lan or "127.0.0.0/8", "--quiet", "--db", db, "--output", out]

        def parse(_stdout):
            with open(out, encoding="utf-8") as f:
                return ns_open(json.load(f))
        return cmd, parse
    tools["Network Scope"] = ns
    # On a real LAN the other tools run only with --fast, which the owner agrees to: they have no
    # Safe Mode, and nmap -T4 is what the lab compares with.
    if args.lan and not args.fast:
        return tools

    def nmap_with(prefix, scan_type):
        def make(cidr, ports, i):
            xml = os.path.join(work, f"nmap{scan_type}{i}.xml")
            cmd = prefix + [scan_type, "-T4", "-Pn", "-n", "-p", ",".join(map(str, ports)), "-oX", xml, cidr]

            def parse(_stdout):
                hosts = args.nmap_compare.nmap_open_ports(xml)
                return {(a, p) for a, ps in hosts.items() for p in ps}
            return cmd, parse
        return make
    if args.nmap_version:
        tools["nmap -sT -T4"] = nmap_with([args.nmap], "-sT")
    if args.syn_version:
        tools["nmap -sS -T4 (root)"] = nmap_with(shlex.split(args.syn_nmap), "-sS")
    if args.rustscan_version:
        def rs(cidr, ports, _i):
            cmd = [args.rustscan, "-g", "--no-config", "-a", cidr, "-p", ",".join(map(str, ports)),
                   "--ulimit", str(args.ulimit)]
            return cmd, rustscan_open
        tools["RustScan"] = rs
    return tools


def show_cmd(cmd, cidr, ports):
    text = " ".join(cmd).replace(",".join(map(str, ports)), f"<{len(ports)} ports>")
    return re.sub(r"\S*(ns\d+\.(sqlite|json)|nmap-s[TS]\d+\.xml)", lambda m: os.path.basename(m.group(0)), text)


def summarize(times, peaks):
    out = {"runs": [round(t, 2) for t in times]}
    if times:
        out.update(median_s=round(statistics.median(times), 2), min_s=round(min(times), 2), max_s=round(max(times), 2))
    if peaks:
        out.update(peak_mb=round(max(peaks) / 1e6, 1))
    return out


def markdown(result):
    lines = ["| Cell | Tool | Wall time, median (min to max) | Peak memory | Lab ports found | Other listeners found "
             "| Reported open but not listening | Correct |",
             "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for cell, data in result["cells"].items():
        for label, r in data["tools"].items():
            if r.get("error"):
                timing = r["error"]
            else:
                timing = f"{r['median_s']:.2f} s ({r['min_s']:.2f} to {r['max_s']:.2f})"
            if r.get("timed_out"):
                timing += f"; stopped after {result['limit_s']} s"
            peak = f"{r['peak_mb']} MB" if "peak_mb" in r else "n/a"
            correct = {True: "yes", False: "no", None: "n/a"}[r.get("correct")]
            if data.get("lan") and "open" in r:
                lab, extra = "n/a (real LAN)", "n/a"
                other = f"{r['open']} open in every run, {r['open_any']} in any run"
            elif r.get("correct") is None:
                lab = other = extra = "n/a"
            else:
                lab = f"{data['lab_open'] - r['lab_missed']}/{data['lab_open']}"
                others = data["expected_open"] - data["lab_open"]
                other, extra = f"{others - r['other_missed']}/{others}", str(r["extra"])
            lines.append(f"| {cell} ({data['range']}, {data['ports']} ports) | {label} | {timing} | {peak} | "
                         f"{lab} | {other} | {extra} | {correct} |")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cli", required=True, help="absolute path to network-scope-cli")
    ap.add_argument("--nmap", default="nmap", help="nmap executable (default: nmap on PATH; skipped when missing)")
    ap.add_argument("--rustscan", default="rustscan", help="RustScan executable (skipped when missing)")
    ap.add_argument("--syn-nmap", help='command prefix for a root nmap SYN scan, e.g. "sudo -n nmap" (not run by default)')
    ap.add_argument("--cells", default=DEFAULT_CELLS, help=f"comma separated, of {', '.join(CELLS)} (default {DEFAULT_CELLS})")
    ap.add_argument("--repeat", type=int, default=3, help="runs per tool and cell (default 3)")
    ap.add_argument("--limit", type=int, default=1800, help="seconds before a single run is stopped (default 1800)")
    ap.add_argument("--ulimit", type=int, default=65535, help="RustScan's --ulimit (default 65535)")
    ap.add_argument("--check", action="store_true", help="fail on a wrong or regressed Network Scope result")
    ap.add_argument("--baseline", default=os.path.join(HERE, "speed_baseline.json"))
    ap.add_argument("--tolerance", type=float, default=0.5, help="allowed slowdown over the baseline (default 0.5 = +50%%)")
    ap.add_argument("--lan", help="time Network Scope (Safe Mode, no other tool) on this real private /24 or smaller "
                    "instead of the loopback lab; only with the network owner's permission. No correctness check, no gate")
    ap.add_argument("--fast", action="store_true", help="with --lan: leave Safe Mode and time the other tools too "
                    "(nmap -sT -T4, RustScan); only when the owner agreed")
    ap.add_argument("--out-dir", help="write speed.json, speed.md and baseline-candidate.json here")
    args = ap.parse_args()
    cells = [c.strip() for c in args.cells.split(",") if c.strip()]
    unknown = [c for c in cells if c not in CELLS]
    if unknown:
        ap.error(f"unknown cell(s): {', '.join(unknown)}")
    if args.lan:
        try:
            args.lan = lan_network(args.lan)
        except ValueError as e:
            ap.error(f"--lan: {e}")
        if any(not c.startswith("24-") for c in cells):
            ap.error("--lan takes only the 24-* cells")
    # A developer's own scope file must not change the run (see lab/nmap_compare.py).
    os.environ["LOCALAPPDATA"] = os.environ["XDG_CONFIG_HOME"] = tempfile.mkdtemp(prefix="ns-config-")
    sys.stdout.reconfigure(encoding="utf-8")
    bench = load("lab_benchmark", os.path.join(HERE, "benchmark.py"))
    args.nmap_compare = load("lab_nmap_compare", os.path.join(HERE, "nmap_compare.py"))
    args.cli = os.path.abspath(args.cli)
    if not os.path.isfile(args.cli):
        print(f"speed comparison error: CLI not found: {args.cli}", file=sys.stderr)
        return 2
    args.nmap_version = version_of([args.nmap, "--version"])
    args.rustscan_version = version_of([args.rustscan, "--version"])
    args.syn_version = version_of(shlex.split(args.syn_nmap) + ["--version"]) if args.syn_nmap else None
    versions = {"network_scope": version_of([args.cli, "--version"]), "nmap": args.nmap_version,
                "rustscan": args.rustscan_version,
                "nmap_syn": args.syn_version}
    for name in ("nmap", "rustscan"):
        if not versions[name]:
            print(f"note: {name} not found; it is not measured")
    work = tempfile.mkdtemp(prefix="ns-speed-")
    tools = tool_commands(args, work)
    port_lists = {}
    port_source = "nmap --top-ports" if args.nmap_version else "no nmap: Network Scope top:100, and ports 1-1000 for 1000"
    for n in sorted({CELLS[c][1] for c in cells}):
        try:
            port_lists[n] = nmap_top_ports(args.nmap, n) if args.nmap_version else (builtin_top100() if n == 100 else list(range(1, 1001)))
        except (SpeedError, ValueError) as e:
            print(f"speed comparison error: top {n} ports from nmap: {e}", file=sys.stderr)
            return 2
    lab_tcp = []
    try:
        if not args.lan:
            truth, addresses = bench.load_truth(os.path.join(HERE, "ground_truth.json"))
            lab_ports = sorted({s["port"] for h in truth["hosts"] for s in h["tcp"]})
            lab_tcp, _ = bench.start_lab(truth, addresses, lab_ports)
    except bench.LabError as e:
        print(f"speed comparison error: {e}", file=sys.stderr)
        return 2

    result = {"machine": machine(), "versions": versions, "port_source": port_source, "repeat": args.repeat,
              "limit_s": args.limit, "commands": {}, "cells": {}}
    ns_medians, ref_medians, failures = {}, {}, []
    for cell in cells:
        cidr, n = CELLS[cell]
        cidr = args.lan or cidr
        ports = port_lists[n]
        hosts = {str(h) for h in ipaddress.ip_network(cidr).hosts()}
        listening = set() if args.lan else listeners()
        expected = expected_open(listening, hosts, ports)
        lab_in_cell = {(a, p) for a, p in lab_tcp if a in hosts and p in set(ports)}
        if not lab_in_cell <= expected:  # the listener table must at least see the lab
            print(f"speed comparison error: the listening-socket table misses lab ports {sorted(lab_in_cell - expected)}",
                  file=sys.stderr)
            return 2
        times = {label: [] for label in tools}
        peaks = {label: [] for label in tools}
        found, errors, timed_out = {}, {}, set()
        print(f"{cell}: {cidr}, {len(ports)} ports, {len(hosts)} hosts, {len(expected)} open pairs expected "
              f"({len(lab_in_cell)} from the lab)", flush=True)
        for i in range(args.repeat):
            for label, make in tools.items():  # interleaved, so drift hits every tool alike
                if label in errors or label in timed_out:
                    continue
                cmd, parse = make(cidr, ports, i)
                result["commands"].setdefault(label, show_cmd(cmd, cidr, ports))
                seconds, peak, out, err, code = run(cmd, args.limit)
                if code is None:
                    timed_out.add(label)
                    print(f"  {label}: stopped after {args.limit} s", flush=True)
                    continue
                if code not in (0,):
                    errors[label] = f"failed (exit {code}): {(err or out).strip()[-300:]}"
                    print(f"  {label}: {errors[label]}", flush=True)
                    continue
                try:
                    got = {(a, p) for a, p in parse(out) if a in hosts and p in set(ports)}
                except (OSError, ValueError, KeyError) as e:
                    errors[label] = f"unreadable output: {e}"
                    continue
                # (in every run, in any run): a port missed once counts as missed, one reported once as extra
                every, anyrun = found.get(label, (got, got))
                if got != every:
                    print(f"  {label}: run {i + 1} found a different open set than run 1", flush=True)
                found[label] = (every & got, anyrun | got)
                times[label].append(seconds)
                if peak:
                    peaks[label].append(peak)
                print(f"  {label}: run {i + 1} {seconds:.2f} s, {len(got)} open", flush=True)
        cell_result = {"range": cidr, "ports": len(ports), "port_list": ports, "hosts": len(hosts),
                       "expected_open": len(expected), "lab_open": len(lab_in_cell), "lan": bool(args.lan), "tools": {}}
        for label in tools:
            r = summarize(times[label], peaks[label])
            if label in errors:  # also after successful runs: a crash on a later repeat is not a timing
                r["error"] = errors[label]
            elif label in timed_out and not times[label]:
                r["error"] = f"> {args.limit} s"
            if label in timed_out:
                r["timed_out"] = True
            if label in found and args.lan:  # nothing to compare with: report how stable the result was
                r.update(open=len(found[label][0]), open_any=len(found[label][1]), correct=None,
                         unstable_sample=[f"{a}:{p}" for a, p in sorted(found[label][1] - found[label][0])[:10]])
            elif label in found:
                # Correct: every lab port found and nothing reported open that does not listen. A missed
                # connection to another listener is reported only: a system service's wildcard listener
                # can refuse when hundreds of connections arrive at once (its backlog), which is the OS.
                missed, extra = expected - found[label][0], found[label][1] - expected
                lab_missed = missed & lab_in_cell
                r.update(open=len(found[label][0]), lab_missed=len(lab_missed), other_missed=len(missed - lab_missed),
                         extra=len(extra), correct=not lab_missed and not extra,
                         missed_sample=[f"{a}:{p}" for a, p in sorted(missed, key=lambda x: (x not in lab_in_cell, x))[:10]],
                         extra_sample=[f"{a}:{p}" for a, p in sorted(extra)[:10]])
            else:
                r["correct"] = None
            cell_result["tools"][label] = r
        ns = cell_result["tools"]["Network Scope"]
        if args.lan:
            pass  # a real network is not a regression signal
        elif ns.get("error") or ns.get("timed_out"):
            failures.append(f"{cell}: Network Scope {ns.get('error') or 'timed out'}")
        elif not ns["correct"]:
            failures.append(f"{cell}: Network Scope reported a wrong open set ({ns['lab_missed']} lab port(s) missed "
                            f"{ns['missed_sample']}, {ns['extra']} reported open but not listening {ns['extra_sample']})")
        else:
            ns_medians[cell] = ns["median_s"]
            ref = cell_result["tools"].get(REFERENCE, {})
            if ref.get("correct") and ref.get("median_s"):
                ref_medians[cell] = ref["median_s"]
        result["cells"][cell] = cell_result

    plat = PLATFORMS.get(sys.platform, sys.platform)
    try:
        with open(args.baseline, encoding="utf-8") as f:
            baseline = json.load(f).get("platforms", {}).get(plat, {})
    except FileNotFoundError:
        baseline = {}
    slow, notices = regressions(ns_medians, baseline, args.tolerance, ref_medians)
    failures += slow
    result.update(failures=failures, notices=notices)
    table = markdown(result)
    print()
    print(table)
    print()
    for label, cmd in result["commands"].items():
        print(f"  {label}: {cmd}")
    for n in notices:
        print(f"notice: {n}")
    candidate = {"platforms": {plat: {
        cell: {"seconds": s, "reference_seconds": ref_medians[cell]} if cell in ref_medians else s
        for cell, s in ns_medians.items()}}}
    if args.out_dir:
        os.makedirs(args.out_dir, exist_ok=True)
        for name, data in (("speed.json", result), ("baseline-candidate.json", candidate)):
            with open(os.path.join(args.out_dir, name), "w", encoding="utf-8", newline="\n") as f:
                json.dump(data, f, indent=2)
                f.write("\n")
        with open(os.path.join(args.out_dir, "speed.md"), "w", encoding="utf-8", newline="\n") as f:
            f.write(table + "\n")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as f:
            f.write("## Speed comparison (B10)\n\n" + table + "\n\n```json\n" + json.dumps(candidate, indent=2) + "\n```\n")
    if args.check and failures:
        print("speed comparison FAILED: " + "; ".join(failures), file=sys.stderr)
        return 1
    for f in failures:
        print(f"warning: {f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
