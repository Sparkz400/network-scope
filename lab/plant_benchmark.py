#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright the Network Scope contributors
# SPDX-License-Identifier: MIT
"""Benchmark of Network Scope against the test plant (ROADMAP L74). Standard library only.

Starts the plant of lab/plant.py (four fake devices on 127.0.20.1-4, weaknesses planted and written
down in lab/plant_truth.json), scans it with the CLI and reports:

  weakness recall   planted weaknesses reported as a finding with the expected rule id / planted
  writes            write or control requests that reached a plant device; must be 0 (a scanner
                    that writes to a PLC fails the benchmark, whatever else it finds)
  extra findings    findings on the plant that the truth does not list (informational)
  traffic replay    the L69 check: lab/plant_traffic.py writes a capture of normal traffic and two
                    replays, each with one injected event; `ot-learn` learns the first and
                    `ot-listen --model` must report exactly the injected event in each replay and
                    nothing in the normal capture

The advisory-based weaknesses need the CSAF advisories of tests/fixtures/csaf (synthetic ids), which
are imported into a temporary cache (`feeds import csaf`). Only loopback addresses are contacted.

  python -I lab/plant_benchmark.py --cli /abs/path/to/network-scope-cli [--check] [--skip-fast]

The machine must be clean: no other service may listen on a plant address and port (a wildcard
listener such as Siemens software on 102 or 4840 is). --allow-busy skips that check for a
development machine; the run then still fails when a plant device did not receive a connection of
the scan, which means another service answered in its place.

Exit codes: 0 ok, 1 a check failed (a write reached the plant, the replay reported the wrong alerts,
or with --check the recall is below the baseline), 2 the lab or a run failed: not a measurement.
"""
import argparse
import importlib.util
import ipaddress
import json
import os
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
BASELINE = os.path.join(HERE, "plant_baseline.json")
PLATFORMS = {"win32": "windows", "linux": "linux", "darwin": "macos"}
EPSILON = 1e-4


class LabError(Exception):
    """The lab could not be set up or the CLI run failed (exit code 2)."""


def load_module(name, filename):
    sys.dont_write_bytecode = True  # no __pycache__ in the repository
    spec = importlib.util.spec_from_file_location(name, os.path.join(HERE, filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_truth(truth):
    """The truth must only name loopback addresses and known devices; returns the planted list."""
    addresses = [d["address"] for d in truth["devices"]]
    for a in addresses:
        ip = ipaddress.ip_address(a)
        if not (ip.version == 4 and ip.is_loopback):
            raise LabError(f"plant truth: {a} is not a loopback address; refusing to scan anything else")
    ids = [w["id"] for w in truth["weaknesses"]]
    if len(set(ids)) != len(ids):
        raise LabError("plant truth: a weakness id is used twice")
    for w in truth["weaknesses"]:
        if w["address"] not in addresses:
            raise LabError(f"plant truth: {w['id']} names the unknown device {w['address']}")
    return truth["weaknesses"]


def run_cli(cli, args, limit_s=300):
    try:
        proc = subprocess.run([cli] + args, capture_output=True, text=True, timeout=limit_s)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise LabError(f"could not run the CLI ({args[0]}): {e}") from None
    return proc


def scan_plant(cli, truth, work, csaf_cache, mode):
    """Scans the plant (Safe Mode or --fast) and returns (findings, seconds)."""
    db = os.path.join(work, f"{mode}.sqlite")
    out = os.path.join(work, f"{mode}-scan.json")
    findings_out = os.path.join(work, f"{mode}-findings.json")
    addresses = ",".join(d["address"] for d in truth["devices"])
    ports = ",".join(str(p) for p in truth["scan"]["ports"])
    cmd = ["scan", addresses, "--ports", ports, "--ot", "--services", "--tcp-only", "--timeout", "2000",
           "--db", db, "--output", out, "--quiet"]
    if mode == "fast":
        cmd.append("--fast")
    started = time.monotonic()
    proc = run_cli(cli, cmd)
    elapsed = time.monotonic() - started
    if proc.returncode != 0 or not os.path.exists(out):
        raise LabError(f"scan failed (exit {proc.returncode}): {proc.stderr.strip()[-500:]}")
    proc = run_cli(cli, ["findings", "1", "--db", db, "--csaf", csaf_cache, "--sort", "severity",
                         "--output", findings_out, "--quiet"])
    if proc.returncode != 0 or not os.path.exists(findings_out):
        raise LabError(f"findings failed (exit {proc.returncode}): {proc.stderr.strip()[-500:]}")
    with open(findings_out, encoding="utf-8") as f:
        loaded = json.load(f)
    return (loaded["findings"] if isinstance(loaded, dict) else loaded), elapsed


def weakness_recall(weaknesses, findings):
    """Returns (found ids, missed ids, extra findings as 'rule@address:port')."""
    raised = {(f["ip"], f.get("port"), f["id"]) for f in findings}
    found, missed = [], []
    expected = set()
    for w in weaknesses:
        key = (w["address"], w["port"], w["finding"])
        expected.add(key)
        (found if key in raised else missed).append(w["id"])
    extra = sorted(f"{rule}@{ip}:{port}" if port else f"{rule}@{ip}"
                   for ip, port, rule in raised if (ip, port, rule) not in expected)
    return found, missed, extra


def traffic_replay(cli, work):
    """The L69 check; returns a dict with the result per capture and `ok`."""
    traffic = load_module("lab_plant_traffic", "plant_traffic.py")
    directory = os.path.join(work, "traffic")
    expected = traffic.generate(directory)
    model = os.path.join(work, "plant.model.json")
    proc = run_cli(cli, ["ot-learn", "--pcap", os.path.join(directory, "normal.pcap"), "--model", model, "--quiet"])
    if proc.returncode != 0:
        raise LabError(f"ot-learn failed (exit {proc.returncode}): {proc.stderr.strip()[-500:]}")
    with open(model, encoding="utf-8") as f:
        learned = json.load(f)
    results = {}
    ok = True
    want_assets = sorted(expected["learn"]["assets"])
    got_assets = sorted(learned["assets"])
    learn_ok = got_assets == want_assets and all(
        sorted(learned["assets"][a]["peers"]) == sorted(peers) for a, peers in expected["learn"]["peers"].items())
    ok &= learn_ok
    for name, want in expected["replays"].items():
        proc = run_cli(cli, ["ot-listen", "--pcap", os.path.join(directory, name), "--model", model,
                             "--maintenance", expected["maintenance"], "--quiet"])
        if proc.returncode != 0:
            raise LabError(f"ot-listen failed (exit {proc.returncode}): {proc.stderr.strip()[-500:]}")
        report = json.loads(proc.stdout)
        got = [{k: a[k] for k in ("kind", "client", "server", "function")} for a in report["alerts"]]
        same = got == want["alerts"]
        results[name] = {"expected": want["alerts"], "reported": got, "ok": same}
        ok &= same
    return {"learned_assets": got_assets, "learn_ok": learn_ok, "replays": results, "ok": ok}


def regressions(metrics, platform, baseline_path):
    """Baseline comparison: returns (baseline value or None, regressed?)."""
    try:
        with open(baseline_path, encoding="utf-8") as f:
            base = json.load(f).get("platforms", {}).get(platform)
    except FileNotFoundError:
        base = None
    want = (base or {}).get("weakness_recall")
    return want, want is not None and metrics["weakness_recall"] + EPSILON < want


def markdown(result):
    m = result["modes"]["safe"]
    lines = ["| Metric | Value |", "| --- | --- |",
             f"| Weakness recall (Safe Mode) | {m['found']}/{m['planted']} = {m['weakness_recall']:.4f} |"]
    if "fast" in result["modes"]:
        f = result["modes"]["fast"]
        lines.append(f"| Weakness recall (--fast) | {f['found']}/{f['planted']} = {f['weakness_recall']:.4f} |")
    lines.append(f"| Writes that reached the plant | {result['writes']} |")
    lines.append(f"| Extra findings (informational) | {len(m['extra'])} |")
    if "traffic" in result:
        t = result["traffic"]
        lines.append(f"| Traffic replay (L69) | {'ok' if t['ok'] else 'FAILED'} |")
    if m["missed"]:
        lines += ["", "Missed: " + ", ".join(m["missed"])]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cli", required=True, help="absolute path of the network-scope-cli binary")
    ap.add_argument("--check", action="store_true", help="fail when the recall is below lab/plant_baseline.json")
    ap.add_argument("--allow-busy", action="store_true",
                    help="do not refuse when something already listens on a plant port (development machines)")
    ap.add_argument("--skip-fast", action="store_true", help="scan in Safe Mode only")
    ap.add_argument("--skip-traffic", action="store_true", help="skip the traffic replay (L69)")
    ap.add_argument("--out-dir", default=".", help="where plant_benchmark.json and .md are written")
    args = ap.parse_args()
    if not os.path.isabs(args.cli) or not os.path.exists(args.cli):
        print("--cli must be the absolute path of an existing binary", file=sys.stderr)
        return 2
    try:
        plant_mod = load_module("lab_plant", "plant.py")
        bench = load_module("lab_benchmark", "benchmark.py")
        truth = plant_mod.load_truth()
        weaknesses = check_truth(truth)
        busy = bench.probe_all([(d["address"], s["port"]) for d in truth["devices"] for s in d["tcp"]]
                               + [(d["address"], p) for d in truth["devices"] for p in truth["scan"]["ports"]])
        if busy and not args.allow_busy:
            raise LabError("ports already open before the plant started: " + ", ".join(f"{a}:{p}" for a, p in sorted(busy)))
        plant = plant_mod.Plant()
        try:
            plant.start()
        except RuntimeError as e:
            raise LabError(str(e)) from None
        work = tempfile.mkdtemp(prefix="ns-plant-")
        csaf_cache = os.path.join(work, "csaf.json")
        proc = run_cli(args.cli, ["feeds", "import", "csaf", os.path.join(REPO, "tests", "fixtures", "csaf"),
                                  "--csaf", csaf_cache, "--quiet"])
        if proc.returncode != 0:
            raise LabError(f"feeds import csaf failed (exit {proc.returncode}): {proc.stderr.strip()[-500:]}")
        result = {"schema": 1, "modes": {}}
        for mode in ("safe",) if args.skip_fast else ("safe", "fast"):
            findings, seconds = scan_plant(args.cli, truth, work, csaf_cache, mode)
            found, missed, extra = weakness_recall(weaknesses, findings)
            result["modes"][mode] = {
                "planted": len(weaknesses), "found": len(found), "missed": missed, "extra": extra,
                "weakness_recall": len(found) / len(weaknesses), "seconds": round(seconds, 1),
            }
        unreached = sorted(a for a, d in plant.devices.items() if d.connections == 0)
        if unreached:
            raise LabError("no connection of the scan reached the plant device(s) " + ", ".join(unreached)
                           + ": another service answered on that address")
        result["writes"] = plant.writes
        result["write_log"] = plant.write_log()
        if not args.skip_traffic:
            result["traffic"] = traffic_replay(args.cli, work)
    except LabError as e:
        print(f"plant benchmark could not run: {e}", file=sys.stderr)
        return 2
    platform = PLATFORMS.get(sys.platform, sys.platform)
    baseline, regressed = regressions(result["modes"]["safe"], platform, BASELINE)
    result["platform"], result["baseline_recall"] = platform, baseline
    os.makedirs(args.out_dir, exist_ok=True)
    with open(os.path.join(args.out_dir, "plant_benchmark.json"), "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    table = markdown(result)
    with open(os.path.join(args.out_dir, "plant_benchmark.md"), "w", encoding="utf-8") as f:
        f.write(table + "\n")
    print(table)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("### Test plant\n\n" + table + "\n")
    failed = []
    if result["writes"]:
        failed.append(f"{result['writes']} write request(s) reached the plant: {result['write_log']}")
    if "traffic" in result and not result["traffic"]["ok"]:
        failed.append("the traffic replay did not report exactly the injected events")
    if args.check and regressed:
        failed.append(f"weakness recall {result['modes']['safe']['weakness_recall']:.4f} is below the baseline {baseline}")
    for message in failed:
        print("FAILED:", message, file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
