#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright the Network Scope contributors
# SPDX-License-Identifier: MIT
"""Coverage gate: fail if a parser or risk-rule file is below its line-coverage threshold.

Reads the JSON summary of cargo-llvm-cov and the targets in scripts/coverage_targets.json.
Standard library only; run it isolated:

  cargo llvm-cov report --json --summary-only --output-path target/llvm-cov/summary.json
  python -I scripts/coverage_gate.py target/llvm-cov/summary.json

Targets are regular expressions matched (re.search) against the source path with forward slashes,
so `(^|/)src/risk\\.rs$` matches `src/risk.rs` and `core/src/risk.rs` alike. Every covered file is
checked against the FIRST target whose pattern matches it, so a file with a lower floor goes
before the group it belongs to. A target that matches no file fails the gate: the file was renamed
or moved and the pattern has to follow.

A target with "ratchet_to" is below its goal today: "threshold" is the measured floor, the gate
fails if coverage drops under it, and the goal is the number to raise it to. Raise the threshold
when coverage improves (the gate says when); never lower it, and never set it above a measured
value. Exit code: 0 passed, 1 a file is below its threshold, 2 bad input or configuration.
"""
import argparse
import json
import os
import re
import sys

DEFAULT_TARGETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "coverage_targets.json")
# Measured coverage this far above a ratcheting floor is reported as "raise the floor".
RATCHET_SLACK = 1.0


class GateError(Exception):
    """Bad summary or configuration (exit code 2)."""


def normalize(path):
    return path.replace("\\", "/")


def short(path):
    """The part of an absolute path from `src/` or `core/src/` on, for the table."""
    found = re.search(r"(?:^|/)((?:core/)?src/.*)$", path)
    return found.group(1) if found else path


def load_targets(path):
    try:
        with open(path, encoding="utf-8") as handle:
            config = json.load(handle)
    except (OSError, ValueError) as err:
        raise GateError(f"cannot read targets {path}: {err}")
    targets = config.get("targets") if isinstance(config, dict) else None
    if not isinstance(targets, list) or not targets:
        raise GateError(f"{path}: 'targets' must be a non-empty list")
    for target in targets:
        if not isinstance(target, dict):
            raise GateError(f"{path}: every target must be an object")
        name = target.get("name", "?")
        try:
            re.compile(target["pattern"])
            threshold = float(target["threshold"])
        except (KeyError, TypeError, ValueError, re.error) as err:
            raise GateError(f"{path}: target {name!r} needs a valid 'pattern' and a numeric 'threshold': {err}")
        if not 0 <= threshold <= 100:
            raise GateError(f"{path}: target {name!r}: threshold {threshold} is not a percentage")
        goal = target.get("ratchet_to")
        if goal is not None and not (isinstance(goal, (int, float)) and threshold < goal <= 100):
            raise GateError(f"{path}: target {name!r}: 'ratchet_to' must be above the threshold and at most 100")
    return targets


def load_summary(path):
    """Returns {normalized filename: (covered lines, lines, percent)} from `llvm-cov --json`."""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        files = {}
        for export in data["data"]:
            for entry in export["files"]:
                lines = entry["summary"]["lines"]
                files[normalize(entry["filename"])] = (lines["covered"], lines["count"], lines["percent"])
    except (OSError, ValueError, KeyError, TypeError) as err:
        raise GateError(f"{path} is not a cargo-llvm-cov JSON summary: {err!r}")
    if not files:
        raise GateError(f"{path} lists no files")
    return files


def load_workspace_threshold(path):
    """The optional floor for the line coverage of the whole workspace ("workspace_threshold")."""
    with open(path, encoding="utf-8") as handle:
        floor = json.load(handle).get("workspace_threshold")
    if floor is not None and not (isinstance(floor, (int, float)) and 0 <= floor <= 100):
        raise GateError(f"{path}: 'workspace_threshold' must be a percentage")
    return floor


def check_workspace(files, floor):
    """A failure message when the lines of all files together are below the floor, else None."""
    covered = sum(c for c, _, _ in files.values())
    lines = sum(n for _, n, _ in files.values())
    percent = 100.0 * covered / lines if lines else 100.0
    line = f"workspace: {percent:.2f}% of {lines} lines"
    if floor is not None and percent + 1e-9 < floor:
        return line, f"{line}, below {floor:g}%"
    return line, None


def check(files, targets):
    """Returns (rows, failures, notes). A row is (file, covered, lines, percent, target)."""
    compiled = [(re.compile(t["pattern"]), t) for t in targets]
    rows, failures, notes = [], [], []
    matched = set()
    for filename in sorted(files):
        for index, (regex, target) in enumerate(compiled):
            if regex.search(filename):
                matched.add(index)
                covered, lines, percent = files[filename]
                rows.append((filename, covered, lines, percent, target))
                break
    for index, (_, target) in enumerate(compiled):
        if index not in matched and not target.get("optional"):
            failures.append(f"target {target.get('name', target['pattern'])!r}: pattern {target['pattern']!r} matches no file in the report")
    for filename, covered, lines, percent, target in rows:
        threshold = float(target["threshold"])
        if lines == 0:
            continue  # no executable lines: nothing to cover
        if percent + 1e-9 < threshold:
            failures.append(f"{filename}: {percent:.2f}% of {lines} lines, below {threshold:g}% ({target.get('name', '')})")
        elif target.get("ratchet_to") and percent >= threshold + RATCHET_SLACK:
            notes.append(f"{filename}: {percent:.2f}% is above its floor of {threshold:g}%, raise the threshold (goal {target['ratchet_to']:g}%)")
    return rows, failures, notes


def report(rows, failures, notes, out):
    width = max((len(short(r[0])) for r in rows), default=4)
    print(f"{'file':<{width}}  {'lines':>11}  {'cover':>7}  {'min':>6}  goal", file=out)
    for filename, covered, lines, percent, target in rows:
        goal = target.get("ratchet_to")
        shown = "-" if lines == 0 else f"{percent:.2f}%"
        print(f"{short(filename):<{width}}  {covered:>5}/{lines:<5}  {shown:>7}  {target['threshold']:>5g}%  {'' if goal is None else f'{goal:g}%'}", file=out)
    for note in notes:
        print("note:", note, file=out)
    for failure in failures:
        print("FAIL", failure, file=out)
    print("coverage gate:", "FAILED" if failures else "passed", f"({len(rows)} files)", file=out)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("summary", help="cargo llvm-cov --json --summary-only output")
    parser.add_argument("--targets", default=DEFAULT_TARGETS, help="targets file (default: coverage_targets.json next to this script)")
    args = parser.parse_args(argv)
    try:
        targets = load_targets(args.targets)
        floor = load_workspace_threshold(args.targets)
        files = load_summary(args.summary)
    except GateError as err:
        print("coverage gate:", err, file=sys.stderr)
        return 2
    rows, failures, notes = check(files, targets)
    total, below = check_workspace(files, floor)
    notes.append(total if floor is None else f"{total} (floor {floor:g}%)")
    if below:
        failures.append(below)
    report(rows, failures, notes, sys.stdout)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
