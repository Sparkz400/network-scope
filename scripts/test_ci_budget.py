"""Unit tests of scripts/ci_budget.py (the time budgets of the ci workflow).

Run: python -I -m unittest discover -s scripts -p "test_*.py"
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ci_budget  # noqa: E402

REQUIRED = ["windows-latest", "ubuntu-latest"]


def run(windows, ubuntu=100, extra=None, conclusion="success"):
    """One run that started at 12:00:00; each job started then and took the given seconds."""
    def job(name, took, result="success"):
        return {"name": name, "conclusion": result, "started_at": "2026-11-21T12:00:00Z",
                "completed_at": f"2026-11-21T12:{took // 60:02d}:{took % 60:02d}Z"}
    jobs = [job("windows-latest", windows, conclusion), job("ubuntu-latest", ubuntu)]
    if extra:
        jobs.append(job(*extra))
    return {"run_started_at": "2026-11-21T12:00:00Z", "jobs": jobs}


def budgets(**limits):
    return {"since": "2026-11-20T00:00:00Z", "runs": 20, "minimum_runs": 5, "required_checks": REQUIRED,
            "p95_seconds": {"required checks": 600, "windows-latest": 500, "ubuntu-latest": 300, **limits}}


class Percentile(unittest.TestCase):
    def test_the_slowest_of_twenty_is_left_out(self):
        self.assertEqual(ci_budget.p95([400] * 19 + [3000]), 400)

    def test_two_slow_runs_of_twenty_count(self):
        self.assertEqual(ci_budget.p95([400] * 18 + [900, 3000]), 900)

    def test_five_values(self):
        self.assertEqual(ci_budget.p95([5, 1, 4, 2, 3]), 4)


class Evaluate(unittest.TestCase):
    def test_within_budget(self):
        rows, failures, notes = ci_budget.evaluate(budgets(), [run(450)] * 20)
        self.assertEqual((failures, notes), ([], []))
        self.assertIn(("windows-latest", 20, 450.0, 500), rows)
        self.assertIn(("required checks", 20, 450.0, 600), rows)

    def test_one_slow_run_does_not_fail(self):
        _, failures, _ = ci_budget.evaluate(budgets(), [run(450)] * 19 + [run(3000)])
        self.assertEqual(failures, [])

    def test_two_slow_runs_fail_the_job_and_the_required_checks(self):
        _, failures, _ = ci_budget.evaluate(budgets(), [run(450)] * 18 + [run(700), run(800)])
        self.assertEqual(len(failures), 2)
        self.assertIn("windows-latest: p95 700 s is over its budget of 500 s (2 of 20 runs were over it)", failures)
        self.assertTrue(failures[0].startswith("required checks: p95 700 s"))

    def test_too_few_runs_are_not_checked(self):
        rows, failures, notes = ci_budget.evaluate(budgets(), [run(3000)] * 4)
        self.assertEqual(failures, [])
        self.assertEqual(notes, ["3 of 3 budgets not checked yet: fewer than 5 runs since 2026-11-20T00:00:00Z"])
        self.assertIn(("windows-latest", 4, None, 500), rows)

    def test_a_failed_job_counts_for_nothing(self):
        runs = [run(450)] * 5 + [run(3000, conclusion="failure")] * 5
        rows, failures, _ = ci_budget.evaluate(budgets(), runs)
        self.assertEqual(failures, [])
        self.assertIn(("windows-latest", 5, 450.0, 500), rows)
        # The required checks only count in runs where all of them succeeded.
        self.assertIn(("required checks", 5, 450.0, 600), rows)

    def test_a_job_without_a_budget_is_reported(self):
        _, failures, notes = ci_budget.evaluate(budgets(), [run(450, extra=("new job", 60))] * 5)
        self.assertEqual(failures, [])
        self.assertEqual(notes, ["new job: no budget (p95 60 s over 5 runs); add one to scripts/ci_budgets.json"])


class CommandLine(unittest.TestCase):
    def call(self, runs, limits=None):
        with tempfile.TemporaryDirectory() as folder:
            paths = {name: os.path.join(folder, name) for name in ("runs.json", "budgets.json", "summary.md")}
            with open(paths["runs.json"], "w", encoding="utf-8") as handle:
                json.dump(runs, handle)
            with open(paths["budgets.json"], "w", encoding="utf-8") as handle:
                json.dump(limits if limits is not None else budgets(), handle)
            code = ci_budget.main(["--input", paths["runs.json"], "--budgets", paths["budgets.json"],
                                   "--summary", paths["summary.md"]])
            summary = open(paths["summary.md"], encoding="utf-8").read() if os.path.exists(paths["summary.md"]) else ""
        return code, summary

    def test_exit_codes(self):
        self.assertEqual(self.call([run(450)] * 20)[0], 0)
        code, summary = self.call([run(450)] * 10 + [run(900)] * 10)
        self.assertEqual(code, 1)
        self.assertIn("| windows-latest | 20 | 900 s (over) | 500 s |", summary)
        self.assertEqual(self.call([run(450)] * 20, {"since": "x"})[0], 2)

    def test_the_shipped_budgets_load(self):
        shipped = ci_budget.load_budgets(ci_budget.DEFAULT_BUDGETS)
        self.assertEqual(shipped["required_checks"],
                         ["windows-latest", "ubuntu-latest", "macos-latest", "windows installer"])
        for name in shipped["required_checks"]:
            self.assertIn(name, shipped["p95_seconds"])


if __name__ == "__main__":
    unittest.main()
