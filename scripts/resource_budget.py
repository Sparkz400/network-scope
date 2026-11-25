#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright the Network Scope contributors
# SPDX-License-Identifier: MIT
"""Resource budgets of the CLI (ROADMAP B17). Python standard library only.

  python -I scripts/resource_budget.py --cli /abs/path/to/network-scope-cli --check

Measures, with every CLI call using its own temporary database and configuration folder:

  startup      median wall time of `network-scope-cli --version` over --runs runs (process start to exit)
  dry-run /16  peak memory of `scan 10.0.0.0/16 --dry-run` (plans 65,534 hosts, sends nothing)
  scan /16     peak memory and time of a real scan of 127.0.0.0/16 on loopback: one port, a short
               timeout, --fast --tcp-only (65,534 targets, the largest scan that is kept in memory)
  scan /15     peak memory of the same scan over 127.0.0.0/15 (131,070 targets): above 65,536
               addresses the hosts go to the database in batches (ROADMAP B15)

and, with --dry-run-8, the peak memory of `scan 10.0.0.0/8 --dry-run` (16.7 million addresses).
Loopback only: nothing leaves this machine, and no real network is touched.

`--check` fails (exit 1) when a budget is exceeded: startup 150 ms, 200 MB peak for the /16 runs
(the roadmap targets). The /15 and /8 runs are reported with a 200 MB limit as well. The GUI budget
(65k rows at 60 fps) is a Rust test, `cargo test --release --lib frame_budget -- --ignored
--nocapture`, whose numbers `--gui` prints and checks against 16.6 ms.

Peak memory is the OS's own figure for the process: ru_maxrss from wait4 (Linux, macOS) or
PeakWorkingSetSize (Windows). Wall times depend on the machine: the CI limits are the roadmap's, the
numbers in the docs were measured on the machine named there.

Exit codes: 0 within budget (or no --check), 1 a budget is exceeded, 2 the measurement failed.
"""
import argparse
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time

STARTUP_LIMIT_MS = 150
MEMORY_LIMIT_MB = 200
FRAME_LIMIT_MS = 1000 / 60
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


class MeasureError(Exception):
    pass


def _windows_peak(handle):
    import ctypes
    from ctypes import wintypes

    class Counters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]

    counters = Counters()
    counters.cb = ctypes.sizeof(counters)
    get = ctypes.WinDLL("psapi", use_last_error=True).GetProcessMemoryInfo
    get.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
    if not get(wintypes.HANDLE(int(handle)), ctypes.byref(counters), counters.cb):
        raise MeasureError("GetProcessMemoryInfo failed")
    return counters.PeakWorkingSetSize


def run(cmd, env, limit_s=900):
    """Runs a command; returns (seconds, peak memory in bytes, stdout, returncode)."""
    started = time.monotonic()
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        if sys.platform == "win32":
            out, err = proc.communicate(timeout=limit_s)
            seconds = time.monotonic() - started
            peak = _windows_peak(proc._handle)
            code = proc.returncode
        else:
            import resource
            outs = {}
            import threading
            # Drain the pipes while waiting, so a chatty process cannot block on a full pipe.
            readers = [threading.Thread(target=lambda n, s: outs.__setitem__(n, s.read()), args=(n, s))
                       for n, s in (("out", proc.stdout), ("err", proc.stderr))]
            for t in readers:
                t.start()
            _, status, usage = os.wait4(proc.pid, 0)
            seconds = time.monotonic() - started
            for t in readers:
                t.join()
            out, err = outs.get("out", b""), outs.get("err", b"")
            code = os.waitstatus_to_exitcode(status)
            proc.returncode = code
            peak = usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise MeasureError(f"could not run {cmd[1:3]}: {e}") from None
    return seconds, peak, out.decode("utf-8", "replace"), code


def environment():
    """The CLI reads the scope file of the user's config folder; use an empty one."""
    config = tempfile.mkdtemp(prefix="ns-budget-config-")
    env = dict(os.environ)
    env["LOCALAPPDATA"] = env["XDG_CONFIG_HOME"] = env["HOME"] = config
    return env


def startup(cli, env, runs):
    samples = []
    for _ in range(runs):
        seconds, _, out, code = run([cli, "--version"], env)
        if code != 0 or "network-scope" not in out:
            raise MeasureError(f"--version failed (exit {code})")
        samples.append(seconds * 1000)
    return {"median_ms": round(statistics.median(samples), 1), "min_ms": round(min(samples), 1),
            "max_ms": round(max(samples), 1), "runs": runs}


def scan_run(cli, env, targets, dry, limit_s=900):
    work = tempfile.mkdtemp(prefix="ns-budget-")
    cmd = [cli, "scan", targets, "--ports", "1", "--quiet", "--db", os.path.join(work, "budget.sqlite"),
           "--output", os.path.join(work, "out.json"), "--scope", "127.0.0.0/8,10.0.0.0/8"]
    if dry:
        cmd += ["--dry-run", "--fast"]
    else:
        # --no-report: the scan itself is measured; a report of a big scan needs every responding
        # host in memory (and on loopback every address responds).
        cmd += ["--fast", "--tcp-only", "--timeout", "300", "--no-report"]
    seconds, peak, _, code = run(cmd, env, limit_s)
    if code not in (0, 2):  # 2: partial (a scan that stopped early); anything else is a failure
        raise MeasureError(f"scan {targets} failed (exit {code})")
    return {"seconds": round(seconds, 2), "peak_mb": round(peak / 1e6, 1), "exit": code}


def gui_frame():
    """Runs the ignored Rust frame test and reads its `GUI_FRAME_MS` line."""
    cmd = ["cargo", "test", "--release", "--locked", "--lib", "frame_budget", "--",
           "--ignored", "--nocapture"]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    for line in (proc.stdout + proc.stderr).splitlines():
        if line.startswith("GUI_FRAME_MS"):
            fields = dict(p.split("=") for p in line.split()[1:])
            return {k: float(v) for k, v in fields.items()}
    raise MeasureError("the GUI frame test printed no GUI_FRAME_MS line:\n" + (proc.stdout + proc.stderr)[-800:])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cli", required=True, help="absolute path to network-scope-cli")
    ap.add_argument("--runs", type=int, default=21, help="runs of --version for the startup median")
    ap.add_argument("--check", action="store_true", help="exit 1 when a budget is exceeded")
    ap.add_argument("--dry-run-8", action="store_true", help="also measure scan 10.0.0.0/8 --dry-run")
    ap.add_argument("--skip-scans", action="store_true", help="only the startup time")
    ap.add_argument("--gui", action="store_true", help="also run the GUI frame test (needs cargo)")
    ap.add_argument("--json", help="write the numbers to this file")
    args = ap.parse_args()
    cli = os.path.abspath(args.cli)
    if not os.path.isfile(cli):
        print(f"CLI not found: {cli}", file=sys.stderr)
        return 2
    env = environment()
    result = {"platform": sys.platform}
    failures = []
    try:
        result["startup"] = startup(cli, env, args.runs)
        if result["startup"]["median_ms"] > STARTUP_LIMIT_MS:
            failures.append(f"startup {result['startup']['median_ms']} ms is above {STARTUP_LIMIT_MS} ms")
        if not args.skip_scans:
            result["dry_run_16"] = scan_run(cli, env, "10.0.0.0/16", dry=True)
            result["scan_16"] = scan_run(cli, env, "127.0.0.0/16", dry=False)
            result["scan_15"] = scan_run(cli, env, "127.0.0.0/15", dry=False)
            for key in ("dry_run_16", "scan_16", "scan_15"):
                if result[key]["peak_mb"] > MEMORY_LIMIT_MB:
                    failures.append(f"{key}: peak memory {result[key]['peak_mb']} MB is above {MEMORY_LIMIT_MB} MB")
        if args.dry_run_8:
            result["dry_run_8"] = scan_run(cli, env, "10.0.0.0/8", dry=True)
        if args.gui:
            result["gui_frame"] = gui_frame()
            for key in ("idle_median", "live_median"):
                if result["gui_frame"][key] > FRAME_LIMIT_MS:
                    failures.append(f"GUI {key} {result['gui_frame'][key]} ms is above {FRAME_LIMIT_MS:.1f} ms")
    except MeasureError as e:
        print(f"resource budget error: {e}", file=sys.stderr)
        return 2
    result["limits"] = {"startup_ms": STARTUP_LIMIT_MS, "memory_mb": MEMORY_LIMIT_MB, "frame_ms": round(FRAME_LIMIT_MS, 1)}
    result["failures"] = failures
    text = json.dumps(result, indent=2)
    print(text)
    if args.json:
        with open(args.json, "w", encoding="utf-8", newline="\n") as f:
            f.write(text + "\n")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write("### Resource budgets\n\n```json\n" + text + "\n```\n")
    if failures and args.check:
        print("resource budget FAILED: " + "; ".join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
