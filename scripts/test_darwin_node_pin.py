#!/usr/bin/env python3
"""Tests of darwin-node-pin.py's --release check, on a local repository.

The repository stands for darwin-node: main holds `before`, then `release`
(node release 1a's commit) and `after`; `branch` is a commit off main.
A client release may be tested against `release` or `after` only, and
against nothing while node release 1a's commit is unset.

    python3 scripts/test_darwin_node_pin.py
"""

import importlib.util
import pathlib
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parent / "darwin-node-pin.py"
spec = importlib.util.spec_from_file_location("darwin_node_pin", SCRIPT)
pin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pin)


def git(cwd, *args):
    return subprocess.run(
        ["git", "-c", "user.name=test", "-c", "user.email=test@example.invalid",
         "-c", "commit.gpgsign=false", *args],
        cwd=cwd, capture_output=True, text=True, check=True,
    ).stdout.strip()


class ReleaseCheck(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory()
        repo = cls.scratch.name
        git(repo, "init", "--quiet", "--initial-branch=main")
        commits = {}
        for name in ("before", "release", "after"):
            git(repo, "commit", "--quiet", "--allow-empty", "-m", name)
            commits[name] = git(repo, "rev-parse", "HEAD")
        git(repo, "checkout", "--quiet", "-b", "side", commits["release"])
        git(repo, "commit", "--quiet", "--allow-empty", "-m", "branch")
        commits["branch"] = git(repo, "rev-parse", "HEAD")
        git(repo, "checkout", "--quiet", "main")
        cls.repository = pathlib.Path(repo).as_uri()
        cls.commits = commits

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def check(self, name, oldest="release"):
        oldest = self.commits[oldest] if oldest else None
        pin.check_release(self.repository, self.commits[name], oldest)

    def test_node_release_1a_and_later_main_commits_pass(self):
        self.check("release")
        self.check("after")

    def test_a_main_commit_from_before_node_release_1a_fails(self):
        with self.assertRaisesRegex(pin.Mismatch, "from before node release 1a"):
            self.check("before")

    def test_a_commit_off_main_fails(self):
        with self.assertRaisesRegex(pin.Mismatch, "not on darwin-node's main"):
            self.check("branch")

    def test_nothing_passes_while_node_release_1a_is_unset(self):
        for name in ("before", "release", "after"):
            with self.assertRaisesRegex(pin.Mismatch, "node release 1a has no commit"):
                self.check(name, oldest=None)

    def test_the_default_is_the_scripts_node_release_1a(self):
        self.assertEqual(
            pin.check_release.__defaults__, (pin.NODE_RELEASE_1A,),
            "--release checks against NODE_RELEASE_1A",
        )


if __name__ == "__main__":
    unittest.main()
