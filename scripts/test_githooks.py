"""Tests of .githooks/pre-push: which checks a push starts, from the files it changes.

Each test builds a small repository, pushes one change through the hook with `cargo` replaced by
a script that only records its arguments, and compares what was recorded.
Run: python -I -m unittest discover -s scripts -p "test_*.py"
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HOOK = Path(__file__).resolve().parent.parent / ".githooks" / "pre-push"
ZERO = "0" * 40
SH = shutil.which("sh") or r"C:\Program Files\Git\bin\sh.exe"
CLIPPY = "clippy --workspace --all-targets --locked -- -D warnings"


@unittest.skipUnless(shutil.which("git") and Path(SH).exists(), "needs git and sh")
class PrePush(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="hooktest-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        stub = self.tmp / "bin"
        stub.mkdir()
        (stub / "cargo").write_text('#!/bin/sh\necho "$*" >> "$CARGO_LOG"\n', newline="\n")
        os.chmod(stub / "cargo", 0o755)
        self.env = dict(os.environ, PATH=f"{stub}{os.pathsep}{os.environ['PATH']}",
                        CARGO_LOG=str(self.tmp / "cargo.log"), GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_CONFIG_NOSYSTEM="1")
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "test")
        for path in ("core/src/scan.rs", "src/gui/mod.rs", "tests/cli_mcp.rs", "tests/fixtures/kev.json",
                     "docs/src/installation.md", "docs/src/findings/telnet-open.md", "lab/verify.py",
                     "README.md", "ROADMAP.md", "data/probes.json", "assets/icon.png"):
            self.write(path, "one\n")
        self.base = self.commit("base")
        self.git("update-ref", "refs/remotes/origin/main", self.base)

    def git(self, *args):
        out = subprocess.run(["git", *args], cwd=self.repo, env=self.env, capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stderr)
        return out.stdout.strip()

    def write(self, path, text):
        file = self.repo / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text, newline="\n")

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")

    def push(self, local, remote):
        """Runs the hook as git does for one pushed branch; returns the cargo calls it made."""
        log = Path(self.env["CARGO_LOG"])
        log.unlink(missing_ok=True)
        out = subprocess.run([SH, str(HOOK), "origin", "url"], cwd=self.repo, env=self.env,
                             input=f"refs/heads/x {local} refs/heads/x {remote}\n",
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        return log.read_text().splitlines() if log.exists() else []

    def changed(self, *paths):
        for path in paths:
            self.write(path, "two\n")
        return self.push(self.commit("change"), self.base)

    def test_files_no_build_or_test_reads_start_nothing(self):
        self.assertEqual(self.changed("docs/src/installation.md", "lab/verify.py", "ROADMAP.md",
                                      ".github/workflows/ci.yml"), [])

    def test_root_crate_only(self):
        self.assertEqual(self.changed("src/gui/mod.rs", "tests/cli_mcp.rs", "ROADMAP.md"),
                         [CLIPPY, "test --locked -p network-scope"])

    def test_core_crate_runs_both(self):
        self.assertEqual(self.changed("core/src/scan.rs"), [CLIPPY, "test --locked"])

    def test_files_that_tests_or_the_installer_read_run_both(self):
        for path in ("docs/src/findings/telnet-open.md", "docs/schema/scan.v1.schema.json",
                     "docs/src/research.md", "tests/fixtures/kev.json", "data/probes.json",
                     "README.md", "assets/icon.png", "Cargo.lock", "a-new-top-level-file"):
            with self.subTest(path=path):
                self.assertEqual(self.changed(path), [CLIPPY, "test --locked"])

    def test_a_file_moved_out_of_a_crate_is_not_a_docs_change(self):
        self.git("mv", "core/src/scan.rs", "docs/scan.rs")
        self.assertEqual(self.push(self.commit("move"), self.base), [CLIPPY, "test --locked"])

    def test_a_new_branch_is_compared_with_origin_main(self):
        self.write("src/gui/mod.rs", "two\n")
        self.assertEqual(self.push(self.commit("change"), ZERO),
                         [CLIPPY, "test --locked -p network-scope"])

    def test_without_a_base_everything_runs(self):
        self.git("update-ref", "-d", "refs/remotes/origin/main")
        self.write("docs/src/installation.md", "two\n")
        self.assertEqual(self.push(self.commit("change"), ZERO), [CLIPPY, "test --locked"])

    def test_deleting_a_branch_starts_nothing(self):
        self.assertEqual(self.push(ZERO, self.base), [])


if __name__ == "__main__":
    unittest.main()
