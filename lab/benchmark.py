#!/usr/bin/env python3
"""Ground-truth accuracy benchmark for Network Scope. Python standard library only.

Starts the lab simulators on loopback addresses, scans them with the CLI and compares the JSON
result with lab/ground_truth.json (every host, port and expected identity is known):

  host recall / precision, port precision / recall (TCP and UDP), service accuracy, product
  accuracy, device-type accuracy, OS accuracy, finding recall, plus the wall time of the scan.

The risk rules run over the same scan (`findings 1`). A host whose ground truth has a
"findings" list states exactly which rule ids its lab condition warrants (a trailing * matches
a family such as "cve-*"); every other finding raised on it is a false alarm. A host without
the key states nothing and is skipped. `false_alarms` is a count, lower is better, and --check
fails when it rises above the baseline (a missing baseline value means 0).

  python -I lab/benchmark.py --cli /abs/path/to/network-scope-cli --check

Only loopback addresses (127.0.0.0/8) are ever contacted: the ground truth is refused otherwise.
Writes benchmark.json and benchmark.md to --out-dir, prints the Markdown table and appends it to
$GITHUB_STEP_SUMMARY when that is set.

Exit codes: 0 ok, 1 an accuracy metric is below the baseline (--check), 2 the lab or the run
failed (port already in use, CLI missing or crashed): not a measurement, so not a regression.
"""
import argparse
import concurrent.futures
import importlib.util
import ipaddress
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
EPSILON = 1e-4  # baseline values are stored with 4 decimals
PLATFORMS = {"win32": "windows", "linux": "linux", "darwin": "macos"}

# (key, title, one line description); all are ratios in 0..1 and all are gated by --check.
METRICS = [
    ("host_recall", "Host recall", "real hosts found / real hosts"),
    ("host_precision", "Host precision", "real hosts / hosts reported with an open port or identity (absent addresses count against it)"),
    ("port_recall", "Port recall", "open ports found / open ports (TCP and UDP)"),
    ("tcp_port_recall", "TCP port recall", "open TCP ports found / open TCP ports"),
    ("udp_port_recall", "UDP port recall", "open UDP ports reported in udp_open / open UDP ports"),
    ("port_precision", "Port precision", "reported open ports that are real / reported open ports"),
    ("service_accuracy", "Service accuracy", "services named correctly / services served"),
    ("product_accuracy", "Product accuracy", "product (and version) named correctly / products known"),
    ("device_type_accuracy", "Device type accuracy", "device types correct / hosts with a known type"),
    ("os_accuracy", "OS accuracy", "OS family correct / hosts with a known OS"),
    ("finding_recall", "Finding recall", "expected findings raised / expected findings"),
]


class LabError(Exception):
    """The lab could not be set up or the CLI run failed (exit code 2)."""


def load_simulators():
    # `python -I` keeps the script folder off sys.path, so load the module by path.
    sys.dont_write_bytecode = True  # no __pycache__ in the repository
    spec = importlib.util.spec_from_file_location("lab_simulators", os.path.join(HERE, "simulators.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_truth(path):
    with open(path, encoding="utf-8") as f:
        truth = json.load(f)
    addresses = [h["address"] for h in truth["hosts"]] + truth["absent_hosts"]
    if len(set(addresses)) != len(addresses):
        raise LabError("ground truth lists an address twice")
    for a in addresses:
        try:
            ip = ipaddress.ip_address(a)
        except ValueError:
            raise LabError(f"ground truth: {a!r} is not an IP address") from None
        if not (ip.version == 4 and ip.is_loopback):
            raise LabError(f"ground truth: {a} is not a loopback address; refusing to scan anything else")
    return truth, addresses


def tcp_connects(address, port, timeout=3.0):
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_all(pairs):
    """Connect to every (address, port); returns the set that accepted."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        results = list(pool.map(lambda p: tcp_connects(*p), pairs))
    return {p for p, ok in zip(pairs, results) if ok}


def udp_bindable(address, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((address, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def start_lab(truth, addresses, scan_ports, idle_timeout=None):
    """Starts the simulators in this process. Raises LabError when the machine is not clean.

    idle_timeout (seconds) overrides how long a simulator waits for a client that speaks first.
    """
    sim = load_simulators()
    if idle_timeout is not None:
        sim.IDLE_TIMEOUT = idle_timeout
    handlers = {h.__name__: h for h in sim.TCP.values()}
    handlers.update(sim.VARIANTS)
    udp_handlers = {"bacnet": sim.bacnet}

    # Nothing may listen on any address/port the scan will touch (for example a wildcard
    # listener of the host), otherwise the ground truth is wrong before the first probe.
    busy = probe_all([(a, p) for a in addresses for p in scan_ports])
    if busy:
        raise LabError("ports already open before the lab started (not a clean machine): "
                       + ", ".join(f"{a}:{p}" for a, p in sorted(busy)))
    errors = []

    def guarded(target, *args):
        try:
            target(*args)
        except Exception as e:  # a bind failure must not stay silent in a daemon thread
            errors.append(f"{args[0]}:{args[1]}: {e}")

    expected_tcp, expected_udp = [], []
    for host in truth["hosts"]:
        for svc in host["tcp"]:
            if svc["handler"] not in handlers:
                raise LabError(f"ground truth: unknown TCP handler {svc['handler']!r}")
            expected_tcp.append((host["address"], svc["port"]))
            threading.Thread(target=guarded, args=(sim.serve_tcp, host["address"], svc["port"],
                                                   handlers[svc["handler"]]), daemon=True).start()
        for svc in host["udp"]:
            if svc["handler"] not in udp_handlers:
                raise LabError(f"ground truth: unknown UDP handler {svc['handler']!r}")
            if not udp_bindable(host["address"], svc["port"]):
                raise LabError(f"UDP port {host['address']}:{svc['port']} is already in use")
            expected_udp.append((host["address"], svc["port"]))
            threading.Thread(target=guarded, args=(udp_handlers[svc["handler"]], host["address"],
                                                   svc["port"]), daemon=True).start()
    deadline = time.time() + 5
    while True:
        up = probe_all(expected_tcp)
        if up == set(expected_tcp) or time.time() > deadline:
            break
        time.sleep(0.2)
    missing = sorted(set(expected_tcp) - up)
    if missing or errors:
        raise LabError("simulators did not start: " + ", ".join(
            [f"{a}:{p} not accepting" for a, p in missing] + errors))
    for address, port in expected_udp:  # Who-Is, the simulator answers with an I-Am
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        try:
            s.sendto(b"\x81\x0a\x00\x04", (address, port))
            s.recvfrom(1500)
        except OSError:
            raise LabError(f"UDP simulator {address}:{port} does not answer") from None
        finally:
            s.close()
    return expected_tcp, expected_udp


def run_scan(cli, addresses, ports, timeout_ms, limit_s):
    work = tempfile.mkdtemp(prefix="ns-bench-")
    db, out = os.path.join(work, "bench.sqlite"), os.path.join(work, "scan.json")
    options = ["--fast", "--deep", "--ot", "--tcp-only", "--ports", ",".join(str(p) for p in ports),
               "--timeout", str(timeout_ms)]
    cmd = [cli, "scan", ",".join(addresses)] + options + ["--db", db, "--output", out, "--quiet"]
    started = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=limit_s)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise LabError(f"could not run the CLI: {e}") from None
    elapsed = time.monotonic() - started
    if proc.returncode != 0 or not os.path.exists(out):
        raise LabError(f"scan failed (exit {proc.returncode}): {proc.stderr.strip()[-500:]}")
    with open(out, encoding="utf-8") as f:
        scan = json.load(f)
    findings_out = os.path.join(work, "findings.json")
    try:
        proc = subprocess.run([cli, "findings", "1", "--db", db, "--sort", "severity", "--output", findings_out,
                               "--quiet"], capture_output=True, text=True, timeout=limit_s)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise LabError(f"could not run the CLI (findings): {e}") from None
    if proc.returncode != 0 or not os.path.exists(findings_out):
        raise LabError(f"findings failed (exit {proc.returncode}): {proc.stderr.strip()[-500:]}")
    with open(findings_out, encoding="utf-8") as f:
        loaded = json.load(f)
        # Versioned output (G44): {"schema": ..., "findings": [...]}; older builds wrote a bare list.
        scan["findings"] = loaded["findings"] if isinstance(loaded, dict) else loaded
    return scan, elapsed, options


def ratio(num, den):
    return {"value": round(num / den, 4) if den else None, "num": num, "den": den}


def compare(truth, scan):
    """Returns (metrics, misses). `misses` lists every deviation from the ground truth."""
    hosts = {h["ip"]: h for h in scan["hosts"]}
    real = {h["address"]: h for h in truth["hosts"]}
    misses = []

    # On loopback the OS answers for every 127.x address (ICMP echo and a RST on every port),
    # so an address without services cannot look absent. A host counts as found when it
    # responds and shows something real: an open port or an identity. Phantom open ports on
    # the absent addresses still count against port precision.
    found = {
        ip
        for ip, h in hosts.items()
        if h.get("responding") and (h.get("open") or h.get("udp_open") or h.get("identity"))
    }
    for ip in sorted(set(real) - found):
        misses.append(f"host {ip} not found")
    for ip in sorted(found - set(real)):
        misses.append(f"host {ip} reported but does not exist")

    truth_tcp = {(a, s["port"]) for a, h in real.items() for s in h["tcp"]}
    truth_udp = {(a, s["port"]) for a, h in real.items() for s in h["udp"]}
    rep_tcp = {(ip, p) for ip, h in hosts.items() for p in h.get("open", [])}
    rep_udp = {(ip, p) for ip, h in hosts.items() for p in h.get("udp_open", [])}
    for a, p in sorted(truth_tcp - rep_tcp):
        misses.append(f"open TCP port {a}:{p} not found")
    for a, p in sorted(truth_udp - rep_udp):
        misses.append(f"open UDP port {a}:{p} not reported in udp_open")
    for a, p in sorted(rep_tcp - truth_tcp):
        misses.append(f"TCP port {a}:{p} reported open but is closed")
    for a, p in sorted(rep_udp - truth_udp):
        misses.append(f"UDP port {a}:{p} reported open but is closed")

    svc_ok = svc_n = prod_ok = prod_n = 0
    for a, host in real.items():
        ident = hosts.get(a, {}).get("identity", {})
        for proto, entries in (("tcp", host["tcp"]), ("udp", host["udp"])):
            for s in entries:
                want, port = s["expect"], s["port"]
                token = ident.get(f"svc.{port}", "").split(" ")[0].lower() if proto == "tcp" else ""
                by_identity = any(ident.get(k) == v for k, v in want.get("identity", {}).items())
                svc_n += 1
                if token == want["service"] or by_identity:
                    svc_ok += 1
                else:
                    misses.append(f"service {a}:{port}/{proto} expected {want['service']!r}, "
                                  f"got {token or 'nothing'!r}")
                if "product" in want:
                    prod_n += 1
                    got_p, got_v = ident.get(f"svc.{port}.product", ""), ident.get(f"svc.{port}.version", "")
                    if got_p.lower() == want["product"].lower() and want.get("version", got_v) == got_v:
                        prod_ok += 1
                    else:
                        misses.append(f"product {a}:{port} expected {want['product']} {want.get('version', '')}".rstrip()
                                      + f", got {(got_p + ' ' + got_v).strip() or 'nothing'}")
    dev_ok = dev_n = os_ok = os_n = 0
    for a, host in real.items():
        ident = hosts.get(a, {}).get("identity", {})
        for key, field, tag in (("device_type", "device.type", "device"), ("os", "os.guess", "os")):
            want = host.get("expect", {}).get(key)
            if want is None:
                continue
            got = ident.get(field, "")
            ok = got.lower() == want.lower()
            if tag == "device":
                dev_n, dev_ok = dev_n + 1, dev_ok + ok
            else:
                os_n, os_ok = os_n + 1, os_ok + ok
            if not ok:
                misses.append(f"{tag} {a} expected {want!r}, got {got or 'nothing'!r}")

    allowed_hit = allowed_n = 0
    reported_n = 0
    false_alarms = {}  # rule id -> list of "ip[:port]" the ground truth does not warrant
    by_host = {}
    for f in scan.get("findings", []):
        by_host.setdefault(f["ip"], []).append(f)
    for a, host in real.items():
        if "findings" not in host:
            continue  # nothing stated about this host
        allowed = host["findings"]
        raised = by_host.get(a, [])

        def warranted(rule_id, patterns=allowed):
            return any(rule_id == p or (p.endswith("*") and rule_id.startswith(p[:-1])) for p in patterns)

        for f in raised:
            reported_n += 1
            if not warranted(f["id"]):
                where = a if f.get("port") is None else f"{a}:{f['port']}"
                false_alarms.setdefault(f["id"], []).append(where)
                misses.append(f"false alarm: {f['id']} on {where} but the ground truth says the condition is absent")
        for pattern in allowed:
            allowed_n += 1
            if any(f["id"] == pattern or (pattern.endswith("*") and f["id"].startswith(pattern[:-1]))
                   for f in raised):
                allowed_hit += 1
            else:
                misses.append(f"expected finding {pattern} on {a} was not raised")
    real_found = len(found & set(real))
    metrics = {
        "host_recall": ratio(real_found, len(real)),
        "host_precision": ratio(real_found, len(found)),
        "port_recall": ratio(len(truth_tcp & rep_tcp) + len(truth_udp & rep_udp), len(truth_tcp) + len(truth_udp)),
        "tcp_port_recall": ratio(len(truth_tcp & rep_tcp), len(truth_tcp)),
        "udp_port_recall": ratio(len(truth_udp & rep_udp), len(truth_udp)),
        "port_precision": ratio(len((truth_tcp & rep_tcp)) + len(truth_udp & rep_udp), len(rep_tcp) + len(rep_udp)),
        "service_accuracy": ratio(svc_ok, svc_n),
        "product_accuracy": ratio(prod_ok, prod_n),
        "device_type_accuracy": ratio(dev_ok, dev_n),
        "os_accuracy": ratio(os_ok, os_n),
        "finding_recall": ratio(allowed_hit, allowed_n),
    }
    # A healthy lab never trips the back-off (H52): a "backed off:" note on a lab host means the
    # scan was slowed down by a strike (reset connection, or a port that stopped answering), the
    # cause of long wall times that are not noise. It is a count, lower is better, like false_alarms.
    backoff = sorted(f"{h['ip']}: {e}" for h in scan["hosts"] for e in h.get("errors", [])
                     if e.startswith("backed off:"))
    count = sum(len(v) for v in false_alarms.values())
    metrics["false_alarms"] = {"value": count, "num": count, "den": reported_n,
                               "by_rule": {k: sorted(v) for k, v in sorted(false_alarms.items())}}
    metrics["backoff_notes"] = {"value": len(backoff), "num": len(backoff), "den": len(scan["hosts"]),
                                "notes": backoff}
    for note in backoff:
        misses.append(f"back-off during the scan: {note}")
    return metrics, misses


def check(metrics, platform, baseline_path):
    """Returns (rows, regressions, note). rows maps metric -> baseline value or None."""
    try:
        with open(baseline_path, encoding="utf-8") as f:
            base = json.load(f).get("platforms", {}).get(platform)
    except FileNotFoundError:
        base = None
    if base is None:
        return {}, [], (f"No baseline recorded for platform '{platform}' in {os.path.basename(baseline_path)}: "
                        "nothing was gated. Commit the metrics of a benchmark.json run on this platform "
                        "(or run with --update-baseline) to enable the check.")
    regressions = []
    for key, _, _ in METRICS:
        want = base.get(key)
        got = metrics[key]["value"]
        if want is not None and (got is None or got < want - EPSILON):
            regressions.append(f"{key}: {'n/a' if got is None else f'{got:.4f}'} is below the baseline {want:.4f}")
    # False alarms are a count where lower is better: it must never rise above the baseline.
    allowed = base.get("false_alarms", 0)
    if metrics["false_alarms"]["value"] > allowed:
        regressions.append(f"false_alarms: {metrics['false_alarms']['value']} is above the baseline {allowed}")
    allowed = base.get("backoff_notes", 0)
    if metrics["backoff_notes"]["value"] > allowed:
        regressions.append(f"backoff_notes: {metrics['backoff_notes']['value']} is above the baseline {allowed}")
    return base, regressions, ""


def fmt(value):
    return "n/a" if value is None else f"{value * 100:.1f}%"


def markdown(result, baseline, regressions, note):
    lines = [f"### Accuracy benchmark ({result['platform']})", "",
             "| Metric | Result | Found | Baseline | |", "| --- | --- | --- | --- | --- |"]
    for key, title, _ in METRICS:
        m = result["metrics"][key]
        want = baseline.get(key)
        mark = ""
        if baseline:
            bad = want is not None and (m["value"] is None or m["value"] < want - EPSILON)
            mark = "REGRESSION" if bad else "ok"
        lines.append(f"| {title} | {fmt(m['value'])} | {m['num']}/{m['den']} | "
                     f"{fmt(want) if baseline else '-'} | {mark} |")
    fa = result["metrics"]["false_alarms"]
    allowed = baseline.get("false_alarms", 0)
    mark = "" if not baseline else ("REGRESSION" if fa["value"] > allowed else "ok")
    lines.append(f"| False alarms (lower is better) | {fa['value']} | {fa['num']}/{fa['den']} findings | "
                 f"{allowed if baseline else '-'} | {mark} |")
    bn = result["metrics"]["backoff_notes"]
    allowed = baseline.get("backoff_notes", 0)
    mark = "" if not baseline else ("REGRESSION" if bn["value"] > allowed else "ok")
    lines.append(f"| Back-off notes (lower is better) | {bn['value']} | {bn['num']}/{bn['den']} hosts | "
                 f"{allowed if baseline else '-'} | {mark} |")
    t = result["timing"]
    lines += ["", f"Scan wall time {t['scan_seconds']:.1f} s for {result['lab']['addresses']} addresses "
              f"x {result['lab']['ports_per_host']} ports (reported, not gated). "
              f"Ground truth: {result['lab']['hosts']} hosts, {result['lab']['open_tcp']} open TCP ports, "
              f"{result['lab']['open_udp']} open UDP ports, {result['lab']['absent']} absent addresses."]
    if note:
        lines += ["", note]
    if regressions:
        lines += ["", "Below baseline:"] + [f"- {r}" for r in regressions]
    if result["misses"]:
        lines += ["", "Deviations from the ground truth:"] + [f"- {m}" for m in result["misses"][:40]]
    return "\n".join(lines) + "\n"


def update_baseline(path, platform, metrics):
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {}
    data["schema"] = 1
    data.setdefault("platforms", {})[platform] = {k: metrics[k]["value"] for k, _, _ in METRICS
                                                  if metrics[k]["value"] is not None}
    data["platforms"][platform]["false_alarms"] = metrics["false_alarms"]["value"]
    data["platforms"][platform]["backoff_notes"] = metrics["backoff_notes"]["value"]
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cli", required=True, help="absolute path to network-scope-cli (or network-scope)")
    ap.add_argument("--ground-truth", default=os.path.join(HERE, "ground_truth.json"))
    ap.add_argument("--baseline", default=os.path.join(HERE, "benchmark_baseline.json"))
    ap.add_argument("--out-dir", default=".", help="where benchmark.json and benchmark.md are written")
    ap.add_argument("--check", action="store_true", help="exit 1 if an accuracy metric is below the baseline")
    ap.add_argument("--update-baseline", action="store_true",
                    help="record this run as the baseline of this platform (review the diff!)")
    ap.add_argument("--timeout", type=int, default=1500, help="port timeout in ms passed to the CLI")
    ap.add_argument("--max-scan-seconds", type=float, default=None,
                    help="with --check: fail when the scan takes longer (a sanity bound for gross slowdowns; "
                         "wall time is otherwise reported only, because shared machines are noisy)")
    args = ap.parse_args()
    # The scope guard reads a default scope file from the config folder; a developer's own file
    # must not change the result of the lab (it only knows loopback addresses).
    os.environ["LOCALAPPDATA"] = os.environ["XDG_CONFIG_HOME"] = tempfile.mkdtemp(prefix="ns-config-")
    platform = PLATFORMS.get(sys.platform, sys.platform)
    try:
        cli = os.path.abspath(args.cli)
        if not os.path.isfile(cli):
            raise LabError(f"CLI not found: {cli}")
        truth, addresses = load_truth(args.ground_truth)
        open_tcp = sorted({s["port"] for h in truth["hosts"] for s in h["tcp"]})
        scan_ports = sorted(set(open_tcp) | set(truth["scan"]["closed_tcp_ports"]))
        start_lab(truth, addresses, scan_ports)
        scan, elapsed, cli_args = run_scan(cli, addresses, scan_ports, args.timeout, 600)
    except LabError as e:
        print(f"benchmark error: {e}", file=sys.stderr)
        return 2

    metrics, misses = compare(truth, scan)
    result = {
        "schema": 1,
        "platform": platform,
        "commit": os.environ.get("GITHUB_SHA", ""),
        "ref": os.environ.get("GITHUB_REF_NAME", ""),
        "metrics": metrics,
        "timing": {"scan_seconds": round(elapsed, 2)},
        "lab": {"hosts": len(truth["hosts"]), "absent": len(truth["absent_hosts"]), "addresses": len(addresses),
                "ports_per_host": len(scan_ports), "open_tcp": sum(len(h["tcp"]) for h in truth["hosts"]),
                "open_udp": sum(len(h["udp"]) for h in truth["hosts"])},
        "scan_arguments": ["scan", "<every lab address>"] + cli_args,
        "misses": misses,
    }
    baseline, regressions, note = check(metrics, platform, args.baseline) if args.check else ({}, [], "")
    if args.update_baseline:
        update_baseline(args.baseline, platform, metrics)
        note = f"Baseline for '{platform}' written to {os.path.basename(args.baseline)}."
    text = markdown(result, baseline, regressions, note)

    os.makedirs(args.out_dir, exist_ok=True)
    with open(os.path.join(args.out_dir, "benchmark.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(result, f, indent=2)
        f.write("\n")
    with open(os.path.join(args.out_dir, "benchmark.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    sys.stdout.reconfigure(encoding="utf-8")
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(text + "\n")
    if note and args.check:
        print("::warning::" + note if os.environ.get("GITHUB_ACTIONS") else note)
    if args.check and args.max_scan_seconds is not None and elapsed > args.max_scan_seconds:
        regressions.append(f"scan wall time {elapsed:.1f} s is above the bound of {args.max_scan_seconds:.0f} s")
    if regressions:
        print("benchmark FAILED: a metric fell below the baseline or the scan was too slow", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
