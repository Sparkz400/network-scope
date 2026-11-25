# SPDX-FileCopyrightText: Copyright the Network Scope contributors
# SPDX-License-Identifier: MIT
"""Tests for coverage_gate.py, with a tiny llvm-cov summary as fixture.

  python -I -m unittest discover -s scripts -p "test_*.py"
"""
import contextlib
import io
import json
import os
import tempfile
import unittest

import coverage_gate


def summary(files):
    """A cargo-llvm-cov `--json --summary-only` document; files = {path: (covered, count)}."""
    entries = []
    for name, (covered, count) in files.items():
        percent = 100.0 * covered / count if count else 0.0
        entries.append({"filename": name, "summary": {"lines": {"count": count, "covered": covered, "percent": percent}}})
    return {"type": "llvm.coverage.json.export", "version": "2.0.1", "data": [{"files": entries, "totals": {}}]}


FIXTURE = summary({
    "/work/core/src/risk.rs": (90, 100),
    "C:\\work\\core\\src\\udp.rs": (60, 100),
    "/work/src/service/http.rs": (85, 100),
    "/work/src/service/ssh.rs": (50, 100),
    "/work/src/ui.rs": (1, 100),
    "/work/src/empty.rs": (0, 0),
})


class GateTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)

    def write(self, name, content):
        path = os.path.join(self.dir.name, name)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(content, handle)
        return path

    def run_gate(self, files, targets):
        summary_path = self.write("summary.json", files)
        targets_path = self.write("targets.json", {"targets": targets})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = coverage_gate.main([summary_path, "--targets", targets_path])
        return code, out.getvalue(), err.getvalue()

    def test_passes_when_every_file_meets_its_threshold(self):
        code, out, _ = self.run_gate(FIXTURE, [
            {"name": "risk", "pattern": r"(^|/)src/risk\.rs$", "threshold": 80},
            {"name": "udp", "pattern": r"(^|/)src/udp\.rs$", "threshold": 60, "ratchet_to": 80},
        ])
        self.assertEqual(code, 0, out)
        self.assertIn("passed", out)

    def test_paths_match_with_and_without_the_core_prefix_and_windows_separators(self):
        targets = [{"name": "any", "pattern": r"(^|/)src/(risk|udp)\.rs$", "threshold": 10}]
        rows, failures, _ = coverage_gate.check(coverage_gate.load_summary(self.write("s.json", FIXTURE)), targets)
        self.assertEqual([r[0] for r in rows], ["/work/core/src/risk.rs", "C:/work/core/src/udp.rs"])
        self.assertEqual(failures, [])

    def test_fails_below_the_threshold(self):
        code, out, _ = self.run_gate(FIXTURE, [{"name": "udp", "pattern": r"(^|/)src/udp\.rs$", "threshold": 80}])
        self.assertEqual(code, 1)
        self.assertIn("FAIL C:/work/core/src/udp.rs: 60.00%", out)

    def test_every_file_of_a_group_is_checked(self):
        code, out, _ = self.run_gate(FIXTURE, [{"name": "service", "pattern": r"(^|/)src/service/", "threshold": 80}])
        self.assertEqual(code, 1)
        self.assertIn("src/service/ssh.rs", out)
        self.assertNotIn("FAIL /work/src/service/http.rs", out)

    def test_first_matching_target_wins_so_a_floor_can_precede_its_group(self):
        code, out, _ = self.run_gate(FIXTURE, [
            {"name": "ssh", "pattern": r"(^|/)src/service/ssh\.rs$", "threshold": 50, "ratchet_to": 80},
            {"name": "service", "pattern": r"(^|/)src/service/", "threshold": 80},
        ])
        self.assertEqual(code, 0, out)

    def test_a_target_without_a_file_fails(self):
        code, out, _ = self.run_gate(FIXTURE, [{"name": "gone", "pattern": r"(^|/)src/nmap\.rs$", "threshold": 80}])
        self.assertEqual(code, 1)
        self.assertIn("matches no file", out)

    def test_an_optional_target_without_a_file_passes(self):
        code, _, _ = self.run_gate(FIXTURE, [{"name": "gone", "pattern": r"nmap\.rs$", "threshold": 80, "optional": True},
                                             {"name": "risk", "pattern": r"src/risk\.rs$", "threshold": 80}])
        self.assertEqual(code, 0)

    def test_a_file_without_executable_lines_is_not_a_failure(self):
        code, out, _ = self.run_gate(FIXTURE, [{"name": "empty", "pattern": r"src/empty\.rs$", "threshold": 80}])
        self.assertEqual(code, 0, out)

    def test_untargeted_files_are_ignored(self):
        _, out, _ = self.run_gate(FIXTURE, [{"name": "risk", "pattern": r"src/risk\.rs$", "threshold": 80}])
        self.assertNotIn("ui.rs", out)

    def test_improved_coverage_asks_for_a_higher_floor(self):
        code, out, _ = self.run_gate(FIXTURE, [{"name": "udp", "pattern": r"src/udp\.rs$", "threshold": 40, "ratchet_to": 80}])
        self.assertEqual(code, 0)
        self.assertIn("raise the threshold", out)

    def test_exactly_the_threshold_passes(self):
        code, _, _ = self.run_gate(summary({"/w/src/a.rs": (1, 3)}), [{"name": "a", "pattern": r"src/a\.rs$", "threshold": 100 / 3}])
        self.assertEqual(code, 0)

    def test_bad_configuration_exits_2(self):
        for targets in (
            [],
            [{"name": "x", "pattern": "(", "threshold": 80}],
            [{"name": "x", "pattern": "a", "threshold": 120}],
            [{"name": "x", "pattern": "a", "threshold": 90, "ratchet_to": 80}],
            [{"name": "x", "pattern": "a"}],
        ):
            code, _, err = self.run_gate(FIXTURE, targets)
            self.assertEqual(code, 2, targets)
            self.assertIn("coverage gate:", err)

    def test_a_summary_that_is_not_llvm_cov_output_exits_2(self):
        for document in ({"nope": 1}, {"data": [{"files": []}]}, [1, 2]):
            code, _, err = self.run_gate(document, [{"name": "x", "pattern": "a", "threshold": 1}])
            self.assertEqual(code, 2, document)
            self.assertIn("coverage gate:", err)

    def test_the_committed_targets_file_is_valid(self):
        targets = coverage_gate.load_targets(coverage_gate.DEFAULT_TARGETS)
        names = [t["name"] for t in targets]
        self.assertEqual(len(names), len(set(names)), "duplicate target names")


if __name__ == "__main__":
    unittest.main()
