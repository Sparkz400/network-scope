#!/usr/bin/env python3
"""Compare Network Scope with nmap on the loopback lab. Python standard library only.

Starts the lab simulators (lab/ground_truth.json, loopback only), scans every lab address with
nmap (`-sT -sV`) and with Network Scope, imports nmap's XML through Network Scope's own importer
(`import`, then `export --format json`, so the importer is part of what is tested) and prints a
per-host, per-port diff: open/closed, service name, product and version.

  python -I lab/nmap_compare.py --cli /abs/path/to/network-scope-cli --explain lab/nmap_differences.json

Every difference must be explained in the --explain file (host, port, field, both values and a
reason). Exit codes: 0 no unexplained difference, 1 at least one unexplained difference,
2 the lab, nmap or the CLI could not be run (not a measurement).

Only loopback addresses (127.0.0.0/8) are ever contacted. The simulators wait 12 s for a client
that speaks first (--idle): nmap waits for a banner much longer than the lab's own 2 s.

--timing adds Network Scope with ports only and with --services, and `nmap -sT -T4` without version
detection, and scores every configuration against the ground truth (TCP ports, service and product
names); --repeat N repeats every scan N times and reports the median wall time.
"""
import argparse
import importlib.util
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
FIELDS = ("state", "service", "product", "version")
# Counts over all scanned ports of all lab addresses: closed (connection refused) and unanswered
# (no answer in time, nmap: filtered). Row port is "*" and host is "(all)".
COUNT_FIELDS = ("closed", "unanswered")


class CompareError(Exception):
    """Lab, nmap or CLI failure (exit code 2)."""


def load_benchmark():
    # `python -I` keeps the script folder off sys.path, so load the sibling module by path.
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("lab_benchmark", os.path.join(HERE, "benchmark.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(cmd, limit=600):
    started = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=limit)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise CompareError(f"could not run {cmd[0]}: {e}") from None
    return proc, time.monotonic() - started


def nmap_command(nmap, addresses, ports, xml_path, version_detection=True):
    # -Pn: no host discovery (every 127.x address answers ping, which says nothing about ports).
    # -n: no DNS. -T4 is what the timing section uses; it does not change what is found.
    cmd = [nmap, "-sT", "-Pn", "-n", "-T4", "-p", ",".join(str(p) for p in ports)]
    if version_detection:
        cmd.append("-sV")
    return cmd + ["-oX", xml_path] + list(addresses)


def run_nmap(nmap, addresses, ports, xml_path, version_detection=True):
    proc, elapsed = run(nmap_command(nmap, addresses, ports, xml_path, version_detection))
    if proc.returncode != 0 or not os.path.exists(xml_path):
        raise CompareError(f"nmap failed (exit {proc.returncode}): {proc.stderr.strip()[-500:]}")
    return elapsed


def nmap_version(nmap):
    proc, _ = run([nmap, "--version"], 30)
    return proc.stdout.splitlines()[0].strip() if proc.stdout else "unknown"


def import_nmap_xml(cli, xml_path, work, name="imported"):
    """nmap XML -> Network Scope's importer -> JSON snapshot (the importer's own naming)."""
    db, out = os.path.join(work, f"{name}.sqlite"), os.path.join(work, f"{name}.json")
    proc, _ = run([cli, "import", xml_path, "--db", db, "--quiet"], 120)
    if proc.returncode != 0:
        raise CompareError(f"import failed (exit {proc.returncode}): {proc.stderr.strip()[-500:]}")
    proc, _ = run([cli, "export", "1", "--format", "json", "--db", db, "--output", out, "--quiet"], 120)
    if proc.returncode != 0 or not os.path.exists(out):
        raise CompareError(f"export failed (exit {proc.returncode}): {proc.stderr.strip()[-500:]}")
    with open(out, encoding="utf-8") as f:
        return json.load(f)


def nmap_open_ports(xml_path):
    """Open TCP ports per address, read straight from nmap's XML (independent of the importer)."""
    result = {}
    for host in ET.parse(xml_path).getroot().iter("host"):
        addr = next((a.get("addr") for a in host.findall("address") if a.get("addrtype") == "ipv4"), None)
        if addr is None:
            continue
        result[addr] = {int(p.get("portid")) for p in host.iter("port")
                        if p.get("protocol") == "tcp" and p.find("state").get("state") == "open"}
    return result


NS_FULL = ["--fast", "--deep", "--ot", "--tcp-only"]  # the options of lab/benchmark.py
NS_SERVICES = ["--fast", "--services", "--tcp-only"]
NS_PORTS = ["--fast", "--tcp-only"]


def run_ns(cli, addresses, ports, timeout_ms, options):
    work = tempfile.mkdtemp(prefix="ns-nmap-scan-")
    db, out = os.path.join(work, "scan.sqlite"), os.path.join(work, "scan.json")
    cmd = [cli, "scan", ",".join(addresses)] + options + [
        "--ports", ",".join(str(p) for p in ports), "--timeout", str(timeout_ms),
        "--db", db, "--output", out, "--quiet"]
    proc, elapsed = run(cmd)
    if proc.returncode != 0 or not os.path.exists(out):
        raise CompareError(f"scan failed (exit {proc.returncode}): {proc.stderr.strip()[-500:]}")
    with open(out, encoding="utf-8") as f:
        return json.load(f), elapsed


def score(truth, snapshot, ports):
    """TCP accuracy against the ground truth: (metrics, misses). Same rules as lab/benchmark.py."""
    hosts = {h["ip"]: h for h in snapshot.get("hosts", [])}
    real = {h["address"]: h for h in truth["hosts"]}
    truth_tcp = {(a, s["port"]) for a, h in real.items() for s in h["tcp"]}
    rep_tcp = {(ip, p) for ip, h in hosts.items() for p in h.get("open", []) if p in ports}
    svc_ok = svc_n = prod_ok = prod_n = 0
    misses = []
    for a, host in real.items():
        ident = hosts.get(a, {}).get("identity", {})
        for s in host["tcp"]:
            want, port = s["expect"], s["port"]
            token = ident.get(f"svc.{port}", "").split(" ")[0].lower()
            by_identity = any(ident.get(k) == v for k, v in want.get("identity", {}).items())
            svc_n += 1
            if token == want["service"] or by_identity:
                svc_ok += 1
            else:
                misses.append(f"service {a}:{port} expected {want['service']!r}, got {token or 'nothing'!r}")
            if "product" in want:
                prod_n += 1
                got_p, got_v = ident.get(f"svc.{port}.product", ""), ident.get(f"svc.{port}.version", "")
                if got_p.lower() == want["product"].lower() and want.get("version", got_v) == got_v:
                    prod_ok += 1
                else:
                    misses.append(f"product {a}:{port} expected {want['product']} {want.get('version', '')}".rstrip()
                                  + f", got {(got_p + ' ' + got_v).strip() or 'nothing'}")
    metrics = {"tcp_port_recall": (len(truth_tcp & rep_tcp), len(truth_tcp)),
               "tcp_port_precision": (len(truth_tcp & rep_tcp), len(rep_tcp)),
               "service": (svc_ok, svc_n), "product": (prod_ok, prod_n)}
    return metrics, misses


def facts(snapshot, ports):
    """{(address, port): {state, service, product, version}} for every scanned port."""
    out = {}
    hosts = {h["ip"]: h for h in snapshot.get("hosts", [])}
    for address, host in hosts.items():
        ident = host.get("identity", {})
        open_ports = set(host.get("open", []))
        for port in ports:
            if port not in open_ports:
                out[(address, port)] = {"state": "closed", "service": "", "product": "", "version": ""}
                continue
            summary = ident.get(f"svc.{port}", "").strip()
            out[(address, port)] = {
                "state": "open",
                "service": summary.split(" ")[0].lower() if summary else "",
                "product": ident.get(f"svc.{port}.product", "").strip(),
                "version": ident.get(f"svc.{port}.version", "").strip(),
            }
    return out


def counts_ns(snapshot):
    hosts = snapshot.get("hosts", [])
    return {"closed": sum(h.get("closed", 0) for h in hosts), "unanswered": sum(h.get("unanswered", 0) for h in hosts)}


def counts_nmap(xml_path, ports):
    """Closed and filtered TCP ports in nmap's XML (read directly: the importer keeps only the
    `extraports` count, not the closed ports nmap lists one by one)."""
    closed = unanswered = 0
    for host in ET.parse(xml_path).getroot().iter("host"):
        listed = 0
        for p in host.iter("port"):
            if p.get("protocol") != "tcp":
                continue
            listed += 1
            state = p.find("state").get("state")
            closed += state == "closed"
            unanswered += state in ("filtered", "open|filtered")
        for e in host.iter("extraports"):
            n = int(e.get("count", "0"))
            closed += n if e.get("state") == "closed" else 0
            unanswered += n if e.get("state") in ("filtered", "open|filtered") else 0
    return {"closed": closed, "unanswered": unanswered}


def count_rows(ours, theirs):
    return [{"host": "(all)", "port": "*", "field": f, "network_scope": str(ours[f]), "nmap": str(theirs[f])}
            for f in COUNT_FIELDS if ours[f] != theirs[f]]


def diff(ours, theirs, addresses, ports):
    """Every (address, port, field) where the two tools disagree, in a stable order."""
    blank = {"state": "closed", "service": "", "product": "", "version": ""}
    rows = []
    for address in addresses:
        for port in ports:
            a, b = ours.get((address, port), blank), theirs.get((address, port), blank)
            for field in FIELDS:
                if a[field].lower() != b[field].lower():
                    rows.append({"host": address, "port": port, "field": field,
                                 "network_scope": a[field], "nmap": b[field]})
    return rows


def load_explanations(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    entries = data["differences"]
    for e in entries:
        for key in ("host", "port", "field", "network_scope", "nmap", "reason"):
            if key not in e:
                raise CompareError(f"{path}: an entry lacks {key!r}: {e}")
        if not str(e["reason"]).strip():
            raise CompareError(f"{path}: an entry has an empty reason: {e}")
        if e["field"] not in FIELDS + COUNT_FIELDS:
            raise CompareError(f"{path}: unknown field {e['field']!r}")
    return entries


def matches(entry, row):
    # Exact, no wildcards: when a difference changes (another value, another port) the old entry
    # no longer explains it, so a regression cannot hide behind an entry written for something else.
    return all(str(entry[key]).lower() == str(row[key]).lower()
               for key in ("host", "port", "field", "network_scope", "nmap"))


def classify(rows, entries):
    explained, unexplained, used = [], [], set()
    for row in rows:
        hit = next((i for i, e in enumerate(entries) if matches(e, row)), None)
        if hit is None:
            unexplained.append(row)
        else:
            used.add(hit)
            explained.append((row, entries[hit]["reason"]))
    stale = [e for i, e in enumerate(entries) if i not in used]
    return explained, unexplained, stale


def show(value):
    return repr(value) if value else "-"


def table(rows):
    lines = [f"  {'host':<12} {'port':>5}  {'field':<8} {'Network Scope':<24} nmap"]
    for r in rows:
        lines.append(f"  {r['host']:<12} {r['port']:>5}  {r['field']:<8} {show(r['network_scope']):<24} {show(r['nmap'])}")
    return "\n".join(lines)


def timed(label, times):
    return {"label": label, "runs": [round(t, 2) for t in times], "median": round(statistics.median(times), 2),
            "min": round(min(times), 2), "max": round(max(times), 2)}




def pct(pair):
    if pair is None:
        return "n/a"
    num, den = pair
    return "n/a" if not den else f"{100 * num / den:.1f}% ({num}/{den})"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cli", required=True, help="absolute path to network-scope-cli (or network-scope)")
    ap.add_argument("--nmap", default="nmap", help="the nmap executable (default: nmap on PATH)")
    ap.add_argument("--explain", help="JSON file of known, explained differences (see lab/nmap_differences.json)")
    ap.add_argument("--ground-truth", default=os.path.join(HERE, "ground_truth.json"))
    ap.add_argument("--out-dir", help="keep nmap.xml, scan.json, imported.json and result.json here")
    ap.add_argument("--timeout", type=int, default=1500, help="port timeout in ms passed to Network Scope")
    ap.add_argument("--idle", type=float, default=12.0,
                    help="seconds a simulator waits for a client that speaks first (default 12; the lab's own 2 s "
                         "makes nmap, which waits for a banner much longer, report tcpwrapped)")
    ap.add_argument("--timing", action="store_true",
                    help="also run Network Scope with ports only and with --services, and nmap -sT -T4 without "
                         "version detection; score every configuration against the ground truth")
    ap.add_argument("--repeat", type=int, default=1, help="repeat every scan this many times (median wall time)")
    args = ap.parse_args()
    # The scope guard reads a default scope file from the config folder; a developer's own file
    # must not change the result of the lab (it only knows loopback addresses).
    os.environ["LOCALAPPDATA"] = os.environ["XDG_CONFIG_HOME"] = tempfile.mkdtemp(prefix="ns-config-")
    sys.stdout.reconfigure(encoding="utf-8")
    bench = load_benchmark()
    work = tempfile.mkdtemp(prefix="ns-nmap-")
    repeat = max(1, args.repeat)
    try:
        cli = os.path.abspath(args.cli)
        if not os.path.isfile(cli):
            raise CompareError(f"CLI not found: {cli}")
        try:
            version = nmap_version(args.nmap)
        except CompareError:
            raise CompareError(f"nmap not found or not runnable: {args.nmap!r}") from None
        entries = load_explanations(args.explain) if args.explain else []
        try:
            truth, addresses = bench.load_truth(args.ground_truth)
            open_tcp = sorted({s["port"] for h in truth["hosts"] for s in h["tcp"]})
            ports = sorted(set(open_tcp) | set(truth["scan"]["closed_tcp_ports"]))
            bench.start_lab(truth, addresses, ports, args.idle)
        except bench.LabError as e:
            raise CompareError(str(e)) from None

        # label -> {"times": [...], "snapshot": first run's result as a JSON snapshot}
        runs = {}

        def ns(label, options):
            times, snap = [], None
            for _ in range(repeat):
                s, elapsed = run_ns(cli, addresses, ports, args.timeout, options)
                snap = snap or s
                times.append(elapsed)
            runs[label] = {"times": times, "snapshot": snap, "detects": bool({"--services", "--deep"} & set(options))}

        def nm(label, version_detection):
            times, snap, xml_path = [], None, os.path.join(work, label.replace(" ", "_") + ".xml")
            for _ in range(repeat):
                times.append(run_nmap(args.nmap, addresses, ports, xml_path, version_detection))
            snap = import_nmap_xml(cli, xml_path, work, label.replace(" ", "_"))
            runs[label] = {"times": times, "snapshot": snap, "xml": xml_path, "detects": version_detection}

        ns("Network Scope " + " ".join(NS_FULL), NS_FULL)
        nm("nmap -sT -sV -T4", True)
        if args.timing:
            ns("Network Scope " + " ".join(NS_PORTS), NS_PORTS)
            ns("Network Scope " + " ".join(NS_SERVICES), NS_SERVICES)
            nm("nmap -sT -T4", False)
    except CompareError as e:
        print(f"nmap comparison error: {e}", file=sys.stderr)
        return 2

    scan = runs["Network Scope " + " ".join(NS_FULL)]["snapshot"]
    imported, xml_path = runs["nmap -sT -sV -T4"]["snapshot"], runs["nmap -sT -sV -T4"]["xml"]
    ours, theirs = facts(scan, ports), facts(imported, ports)
    rows = diff(ours, theirs, addresses, ports)
    rows += count_rows(counts_ns(scan), counts_nmap(xml_path, ports))
    # The importer must not hide a port: cross-check it against nmap's XML read directly.
    raw = nmap_open_ports(xml_path)
    importer_gaps = [f"{a}:{p}" for a in addresses for p in ports
                     if ((p in raw.get(a, set())) != (theirs.get((a, p), {}).get("state") == "open"))]
    explained, unexplained, stale = classify(rows, entries)

    open_ns = sum(1 for f in ours.values() if f["state"] == "open")
    open_nm = sum(1 for f in theirs.values() if f["state"] == "open")
    print(f"Network Scope vs {version}")
    print(f"Lab: {len(addresses)} loopback addresses, {len(ports)} TCP ports each, simulators idle timeout "
          f"{args.idle:g} s; open ports: Network Scope {open_ns}, nmap {open_nm}")
    print("nmap:          " + " ".join(nmap_command(args.nmap, ["<every lab address>"], ports, "nmap.xml")))
    print("Network Scope: scan <every lab address> " + " ".join(NS_FULL) + " --ports <the same ports> "
          f"--timeout {args.timeout} --quiet")
    print(f"\n{len(rows)} difference(s): {len(explained)} explained, {len(unexplained)} unexplained\n")
    if explained:
        print("Explained:")
        print(table([r for r, _ in explained]))
        for r, reason in explained:
            print(f"  - {r['host']}:{r['port']} {r['field']}: {reason}")
        print()
    if unexplained:
        print("UNEXPLAINED:")
        print(table(unexplained))
        print()
    for e in stale:
        print(f"warning: explanation no longer needed ({e['host']}:{e['port']} {e['field']}): {e['reason']}")
    if importer_gaps:
        print("warning: the importer's open ports differ from nmap's XML at: " + ", ".join(importer_gaps))

    summary = {}
    print("Wall time and accuracy against the ground truth (TCP only; repeats: %d)" % repeat)
    print(f"  {'configuration':<62} {'median s':>8} {'min':>6} {'max':>6}  ports found / reported-real  service  product")
    for label, r in runs.items():
        t = timed(label, r["times"])
        metrics, misses = score(truth, r["snapshot"], ports)
        if not r["detects"]:  # a name from a port table is not service detection
            metrics["service"] = metrics["product"] = None
            misses = []
        summary[label] = {"timing": t, "accuracy": {k: (list(v) if v else None) for k, v in metrics.items()},
                          "misses": misses}
        print(f"  {label:<62} {t['median']:>8.2f} {t['min']:>6.2f} {t['max']:>6.2f}  "
              f"{pct(metrics['tcp_port_recall'])} / {pct(metrics['tcp_port_precision'])}  "
              f"{pct(metrics['service'])}  {pct(metrics['product'])}")
    for label, s in summary.items():
        for m in s["misses"]:
            print(f"  [{label}] {m}")
    print("  n/a: the configuration does no service detection. nmap's results are scored after the import\n"
          "  through Network Scope's importer, which maps nmap's product names to Network Scope's.\n"
          "  Reported-real: reported open ports that are really open.")
    print()

    result = {"nmap_version": version, "addresses": addresses, "ports": ports, "idle_timeout": args.idle,
              "differences": rows, "explained": [dict(r, reason=reason) for r, reason in explained],
              "unexplained": unexplained, "runs": summary}
    if args.out_dir:
        os.makedirs(args.out_dir, exist_ok=True)
        for name, data in (("scan.json", scan), ("imported.json", imported), ("result.json", result)):
            with open(os.path.join(args.out_dir, name), "w", encoding="utf-8", newline="\n") as f:
                json.dump(data, f, indent=2)
                f.write("\n")
        with open(xml_path, encoding="utf-8") as src, \
                open(os.path.join(args.out_dir, "nmap.xml"), "w", encoding="utf-8", newline="\n") as dst:
            dst.write(src.read())
    if unexplained:
        print(f"nmap comparison FAILED: {len(unexplained)} unexplained difference(s)", file=sys.stderr)
        return 1
    print("nmap comparison passed: every difference is explained")
    return 0


if __name__ == "__main__":
    sys.exit(main())
