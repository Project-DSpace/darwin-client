#!/usr/bin/env python3
"""Tests of darwin-node-pin.py's --release and --vendored checks, on local
repositories.

For --release, the repository stands for darwin-node: main holds `before`,
then `release` (node release 1a's commit) and `after`; `branch` is a commit
off main. A client release may be tested against `release` or `after` only,
and against nothing while node release 1a's commit is unset.

For --vendored, one repository stands for darwin-node and another for this
one, each with a vendor/ant-protocol and a vendor/saorsa-core. The check
passes only when both copies here are the same git trees as darwin-node's at
the revision, so a change to either copy alone, on either side, fails it.

    python3 scripts/test_darwin_node_pin.py
"""

import importlib.util
import pathlib
import shutil
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


# Both vendored copies, as each side commits them unless a test changes them.
COPIES = {
    "vendor/ant-protocol/Cargo.toml": '[package]\nname = "ant-protocol"\n',
    "vendor/ant-protocol/src/payment/pricing.rs": "// the price curve\n",
    "vendor/saorsa-core/Cargo.toml": '[package]\nname = "saorsa-core"\n',
    "vendor/saorsa-core/VENDORED.md": "# the dial order\n",
    "vendor/saorsa-core/src/peer_record.rs": "// Direct before Relay\n",
}


class VendoredCheck(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory()
        cls.root = pathlib.Path(cls.scratch.name)
        cls.node = cls.root / "darwin-node"
        cls.node.mkdir()
        git(cls.node, "init", "--quiet", "--initial-branch=main")
        # The check fetches the revision by its id, as GitHub serves it.
        git(cls.node, "config", "uploadpack.allowAnySHA1InWant", "true")

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    @staticmethod
    def commit(repo, files):
        """Commits exactly `files` ({path: text}) as `repo`'s vendor/."""
        shutil.rmtree(repo / "vendor", ignore_errors=True)
        for path, text in files.items():
            (repo / path).parent.mkdir(parents=True, exist_ok=True)
            (repo / path).write_text(text, encoding="utf-8", newline="\n")
        git(repo, "add", "--all")
        git(repo, "commit", "--quiet", "--allow-empty", "-m", "vendor")
        return git(repo, "rev-parse", "HEAD")

    def check(self, ours, theirs):
        """The check of `ours`, committed here, against `theirs`, committed in
        darwin-node: (its result, darwin-node's revision)."""
        here = pathlib.Path(tempfile.mkdtemp(dir=self.root))
        git(here, "init", "--quiet", "--initial-branch=main")
        self.commit(here, ours)
        revision = self.commit(self.node, theirs)
        return pin.check_vendored(self.node.as_uri(), revision, root=here), revision

    def mismatch(self, ours, theirs):
        with self.assertRaises(pin.Mismatch) as caught:
            self.check(ours, theirs)
        return str(caught.exception)

    def test_both_copies_are_checked(self):
        self.assertEqual(pin.VENDORED, ("vendor/ant-protocol", "vendor/saorsa-core"))
        self.assertEqual(pin.check_vendored.__defaults__, (pin.ROOT,))

    def test_copies_that_are_darwin_nodes_pass(self):
        trees, revision = self.check(COPIES, COPIES)
        self.assertEqual(list(trees), list(pin.VENDORED))
        for copy, tree in trees.items():
            self.assertEqual(tree, git(self.node, "rev-parse", f"{revision}:{copy}"))

    def test_a_change_to_saorsa_core_alone_fails(self):
        changed = {**COPIES, "vendor/saorsa-core/src/peer_record.rs": "// Relay before Direct\n"}
        for ours, theirs in ((COPIES, changed), (changed, COPIES)):
            message = self.mismatch(ours, theirs)
            self.assertIn("vendor/saorsa-core at HEAD is tree", message)
            self.assertIn("  differs: src/peer_record.rs", message)
            self.assertNotIn("vendor/ant-protocol", message)

    def test_a_change_to_ant_protocol_alone_fails(self):
        theirs = {**COPIES, "vendor/ant-protocol/src/payment/pricing.rs": "// another curve\n"}
        message = self.mismatch(COPIES, theirs)
        self.assertIn("vendor/ant-protocol at HEAD is tree", message)
        self.assertIn("  differs: src/payment/pricing.rs", message)
        self.assertNotIn("vendor/saorsa-core", message)

    def test_a_file_on_one_side_only_fails(self):
        ours = {**COPIES, "vendor/saorsa-core/src/here.rs": "// here only\n"}
        theirs = {**COPIES, "vendor/saorsa-core/src/there.rs": "// darwin-node only\n"}
        message = self.mismatch(ours, theirs)
        self.assertIn("  only here: src/here.rs", message)
        self.assertIn("  only in darwin-node: src/there.rs", message)

    def test_a_copy_missing_from_either_side_fails(self):
        without = {path: text for path, text in COPIES.items()
                   if not path.startswith("vendor/saorsa-core/")}
        message = self.mismatch(COPIES, without)
        self.assertIn("vendor/saorsa-core is missing from darwin-node at", message)
        message = self.mismatch(without, COPIES)
        self.assertIn("vendor/saorsa-core is missing from HEAD here", message)


if __name__ == "__main__":
    unittest.main()
