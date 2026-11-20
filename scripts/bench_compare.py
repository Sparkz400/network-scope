#!/usr/bin/env python3
"""Fails when a criterion benchmark got slower than the baseline by more than a threshold (B18).

  python -I scripts/bench_compare.py CRITERION_HOME [--threshold 15]

Criterion itself only prints a comparison. After `cargo bench -- --save-baseline base` on the base
branch and `cargo bench -- --baseline base` on the change, every benchmark has a
`change/estimates.json` under CRITERION_HOME (default: target/criterion); this script reads the
change of the mean from all of them. A benchmark is a regression when the mean got slower by more
than the threshold percent AND criterion's confidence interval for the change excludes zero (so
a noisy runner that widens the interval does not fail a build on its own). Python standard library
only.

Exit codes: 0 no regression (or no comparison available), 1 at least one regression, 2 bad input.
Runner noise: shared CI machines vary by several percent from run to run; the 15 percent default
leaves room for that, and a failure is worth re-running once before it is believed.
"""
import argparse
import json
import os
import sys


def collect(home):
    """Returns {benchmark name: (change, lower, upper)} for every change/estimates.json."""
    found = {}
    for root, _, files in os.walk(home):
        if os.path.basename(root) != "change" or "estimates.json" not in files:
            continue
        with open(os.path.join(root, "estimates.json"), encoding="utf-8") as f:
            mean = json.load(f)["mean"]
        name = os.path.relpath(os.path.dirname(root), home).replace(os.sep, "/")
        interval = mean["confidence_interval"]
        found[name] = (mean["point_estimate"], interval["lower_bound"], interval["upper_bound"])
    return found


def judge(changes, threshold):
    """Returns (rows, regressions); a row is (name, percent, lower percent, upper percent, verdict)."""
    rows, regressions = [], []
    for name in sorted(changes):
        change, lower, upper = (v * 100 for v in changes[name])
        slower = change > threshold and lower > 0
        verdict = "REGRESSION" if slower else ("slower, within noise" if change > threshold else "ok")
        rows.append((name, change, lower, upper, verdict))
        if slower:
            regressions.append(f"{name}: {change:+.1f}% (interval {lower:+.1f}% to {upper:+.1f}%)")
    return rows, regressions


def table(rows, threshold):
    lines = [f"### Benchmarks against the base branch (fail above +{threshold:g}%)", "",
             "| Benchmark | Change of the mean | Interval | |", "| --- | --- | --- | --- |"]
    for name, change, lower, upper, verdict in rows:
        lines.append(f"| {name} | {change:+.1f}% | {lower:+.1f}% to {upper:+.1f}% | {verdict} |")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("home", nargs="?", default="target/criterion", help="criterion output directory")
    ap.add_argument("--threshold", type=float, default=15.0, help="percent slower that fails (default 15)")
    args = ap.parse_args()
    if not os.path.isdir(args.home):
        print(f"bench_compare: {args.home} does not exist", file=sys.stderr)
        return 2
    changes = collect(args.home)
    if not changes:
        print("bench_compare: no comparison available (the base branch has no benchmarks yet, or no baseline "
              "was saved); nothing to check")
        return 0
    rows, regressions = judge(changes, args.threshold)
    text = table(rows, args.threshold)
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(text + "\n")
    if regressions:
        print("benchmark regression:\n  " + "\n  ".join(regressions), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
