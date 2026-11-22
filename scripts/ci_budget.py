#!/usr/bin/env python3
"""CI time budgets: fail when a job of the `ci` workflow got slower over many runs on main.

Reads the recent successful `ci` runs that a push to main started (GitHub API) and compares, per
job, the 95th percentile of the job's run time with its budget in scripts/ci_budgets.json. One
budget covers the four required checks together: the time from the start of the run until the
last of them finished, queueing included. Standard library only; run it isolated:

  python -I scripts/ci_budget.py --repo Sparkz400/network-scope

A single run never fails on time: runners are noisy, so no job has a time limit of its own, and
the percentile is taken at a rank (the 19th of 20 values, sorted) that leaves the slowest run out.
A budget fails when at least two of the last twenty runs were over it.

Budgets only go down. After a change that makes a job faster, lower its number in
scripts/ci_budgets.json to the measured p95 plus about ten percent and move "since" to the merge
(runs from before a change must not count for or against it). With fewer than "minimum_runs" runs
since then nothing is checked yet, and the output says so.

Exit code: 0 within budget (or not enough runs yet), 1 a budget is exceeded, 2 bad input.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime

DEFAULT_BUDGETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ci_budgets.json")
REQUIRED = "required checks"


class BudgetError(Exception):
    """Bad configuration or an API answer that cannot be used (exit code 2)."""


def seconds(start, end):
    def parse(text):
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    return (parse(end) - parse(start)).total_seconds()


def p95(values):
    """The value at rank floor(0.95 * (n - 1)) of the sorted list: with 20 values the 19th, so
    the slowest run alone never decides."""
    ordered = sorted(values)
    return ordered[int(0.95 * (len(ordered) - 1))]


def load_budgets(path):
    try:
        with open(path, encoding="utf-8") as handle:
            budgets = json.load(handle)
    except (OSError, ValueError) as error:
        raise BudgetError(f"{path}: {error}") from error
    for key, kind in (("since", str), ("runs", int), ("minimum_runs", int),
                      ("required_checks", list), ("p95_seconds", dict)):
        if not isinstance(budgets.get(key), kind):
            raise BudgetError(f"{path}: \"{key}\" is missing or not a {kind.__name__}")
    for name, limit in budgets["p95_seconds"].items():
        if not isinstance(limit, (int, float)) or isinstance(limit, bool) or limit <= 0:
            raise BudgetError(f"{path}: the budget of \"{name}\" must be a positive number")
    if REQUIRED not in budgets["p95_seconds"]:
        raise BudgetError(f"{path}: \"p95_seconds\" needs an entry \"{REQUIRED}\"")
    return budgets


def durations(runs, required):
    """Per name, the seconds of every run. `runs` is a list of {"run_started_at", "jobs"}; a job
    counts when it succeeded, and the required checks count when all of them did."""
    times = {}
    for run in runs:
        ends = []
        for job in run["jobs"]:
            if job.get("conclusion") != "success" or not job.get("started_at") or not job.get("completed_at"):
                continue
            times.setdefault(job["name"], []).append(seconds(job["started_at"], job["completed_at"]))
            if job["name"] in required:
                ends.append(job["completed_at"])
        if len(ends) == len(required):
            times.setdefault(REQUIRED, []).append(seconds(run["run_started_at"], max(ends)))
    return times


def evaluate(budgets, runs):
    """Returns (rows, failures, notes). A row is (name, runs counted, measured p95 or None, budget)."""
    times = durations(runs, set(budgets["required_checks"]))
    rows, failures, notes = [], [], []
    for name, limit in budgets["p95_seconds"].items():
        values = times.get(name, [])
        if len(values) < budgets["minimum_runs"]:
            rows.append((name, len(values), None, limit))
            continue
        measured = p95(values)
        rows.append((name, len(values), measured, limit))
        if measured > limit:
            over = sum(1 for value in values if value > limit)
            failures.append(f"{name}: p95 {measured:.0f} s is over its budget of {limit:.0f} s "
                            f"({over} of {len(values)} runs were over it)")
    waiting = sum(1 for row in rows if row[2] is None)
    if waiting:
        notes.append(f"{waiting} of {len(rows)} budgets not checked yet: fewer than "
                     f"{budgets['minimum_runs']} runs since {budgets['since']}")
    for name in sorted(set(times) - set(budgets["p95_seconds"])):
        notes.append(f"{name}: no budget (p95 {p95(times[name]):.0f} s over {len(times[name])} runs); "
                     "add one to scripts/ci_budgets.json")
    return rows, failures, notes


def api(url, token):
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "ci-budget"})
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except (urllib.error.URLError, ValueError) as error:
        raise BudgetError(f"{url}: {error}") from error


def fetch_runs(repo, workflow, branch, since, count, token):
    base = f"https://api.github.com/repos/{repo}/actions"
    listing = api(f"{base}/workflows/{workflow}/runs?branch={branch}&event=push&status=success"
                  f"&created=%3E%3D{since}&per_page={min(count, 100)}", token)
    runs = []
    for run in listing.get("workflow_runs", [])[:count]:
        jobs = api(f"{base}/runs/{run['id']}/jobs?per_page=100", token)
        runs.append({"id": run["id"], "run_started_at": run["run_started_at"], "jobs": jobs.get("jobs", [])})
    return runs


def table(rows):
    lines = ["| Job | Runs | p95 | Budget |", "|---|---|---|---|"]
    for name, count, measured, limit in rows:
        shown = "not enough runs" if measured is None else f"{measured:.0f} s"
        mark = " (over)" if measured is not None and measured > limit else ""
        lines.append(f"| {name} | {count} | {shown}{mark} | {limit:.0f} s |")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--repo", help="owner/name; fetches the runs from the GitHub API")
    parser.add_argument("--input", help="a JSON file of runs instead of the API (as --dump writes it)")
    parser.add_argument("--dump", help="write the fetched runs to this JSON file")
    parser.add_argument("--budgets", default=DEFAULT_BUDGETS)
    parser.add_argument("--workflow", default="ci.yml")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--summary", help="append the table to this file (GITHUB_STEP_SUMMARY)")
    args = parser.parse_args(argv)
    try:
        budgets = load_budgets(args.budgets)
        if args.input:
            with open(args.input, encoding="utf-8") as handle:
                runs = json.load(handle)
        elif args.repo:
            runs = fetch_runs(args.repo, args.workflow, args.branch, budgets["since"], budgets["runs"],
                              os.environ.get("GITHUB_TOKEN"))
        else:
            raise BudgetError("give --repo or --input")
        if args.dump:
            with open(args.dump, "w", encoding="utf-8") as handle:
                json.dump(runs, handle)
        rows, failures, notes = evaluate(budgets, runs)
    except (BudgetError, OSError, ValueError, KeyError) as error:
        print(f"ci_budget: {error}", file=sys.stderr)
        return 2
    report = (f"`{args.workflow}` on `{args.branch}`: {len(runs)} successful push run(s) since "
              f"{budgets['since']} (the last {budgets['runs']} at most).\n\n{table(rows)}")
    print(report)
    for note in notes:
        print(f"note: {note}")
    for failure in failures:
        print(f"OVER BUDGET: {failure}")
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as handle:
            handle.write(report + "\n\n" + "\n".join(f"- {line}" for line in failures + notes) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
