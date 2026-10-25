#!/usr/bin/env python3
"""The darwin-node revision this repository's tests run, checked in one place.

ant-core's tests and its `devnet` feature build darwin-node, the Darwin
network's node, at a pinned git revision, and the browser harness runs that
revision's ant-devnet. The revision is written in four places, which this
script checks agree:

- ant-core/browser-tests/node-revision: the repository, then the revision;
- ant-core/Cargo.toml: the `ant-node` dependency and dev-dependency;
- Cargo.toml: the `webrtc` patch, darwin-node's patched copy;
- Cargo.lock: every package resolved from darwin-node.

With --vendored it also fetches that revision, into a temporary repository,
and checks that this repository's vendor/ant-protocol, as committed at HEAD,
is darwin-node's vendor/ant-protocol at the revision: the same git tree, so
every file is byte for byte the same, as committed. The workspace's `[patch]`
builds darwin-node against this repository's copy, so a copy that drifted
from darwin-node's would never show in a build.

With --release, which release.yml runs before a client is published, it also
checks that the revision is on darwin-node's main (a released node, never an
unmerged branch commit) and is none of the revisions in TOO_OLD, which a
client release must not be tested against.

    darwin-node-pin.py             check that the pins agree
    darwin-node-pin.py --vendored  and that vendor/ant-protocol is darwin-node's
    darwin-node-pin.py --release   and that the revision may be released against

Needs Python 3.11+ (tomllib), and git for --vendored.
"""

import pathlib
import re
import subprocess
import sys
import tempfile
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
NODE_REVISION = ROOT / "ant-core" / "browser-tests" / "node-revision"
VENDORED = "vendor/ant-protocol"

# Revisions a client release must not be pinned to, with why. Client release
# 1a's busy handling (a dial refused within REFUSAL_DETECTION_WINDOW, reads
# waiting on refused peers at most MAX_REFUSAL_WAITS times) needs nodes that
# refuse a browser session while busy, which node release 1a brings: it has
# to have run against those nodes before it is released.
# Node release 1a has no commit on darwin-node main yet, so this is a
# deny-list of main's head today; once it lands, a lower bound replaces it
# (the revision must have node release 1a's main commit as an ancestor).
TOO_OLD = {
    "94bf3425e31f77e150bc98306d02705fc33b1037": (
        "darwin-node main from before node release 1a; client release 1a's busy "
        "handling has never run against a node that refuses a session while busy. "
        "Move the pin to node release 1a's commit on darwin-node main first"
    ),
}


class Mismatch(Exception):
    pass


def pinned():
    """(repository, revision) from node-revision."""
    words = NODE_REVISION.read_text(encoding="utf-8").split()
    if len(words) != 2 or not re.fullmatch(r"[0-9a-f]{40}", words[1]):
        raise Mismatch(
            f"{NODE_REVISION.relative_to(ROOT)} must hold darwin-node's repository URL, "
            "then a 40-character revision"
        )
    return words[0], words[1]


def load(path):
    with open(ROOT / path, "rb") as file:
        return tomllib.load(file)


def check_pins(repository, revision):
    """Every pin names `repository` at `revision`; returns what was checked."""
    problems = []
    manifests = [
        ("ant-core/Cargo.toml", "dependencies", "ant-node"),
        ("ant-core/Cargo.toml", "dev-dependencies", "ant-node"),
        ("Cargo.toml", "patch.crates-io", "webrtc"),
    ]
    for path, table, name in manifests:
        entry = load(path)
        for key in table.split("."):
            entry = entry.get(key, {})
        entry = entry.get(name)
        if not isinstance(entry, dict):
            problems.append(f"{path} has no [{table}] {name}")
            continue
        found = (entry.get("git"), entry.get("rev"))
        if found != (repository, revision):
            problems.append(f"{path} [{table}] {name} is {found}, not {(repository, revision)}")

    source = f"git+{repository}?rev={revision}#{revision}"
    from_node = []
    for package in load("Cargo.lock").get("package", []):
        package_source = package.get("source", "")
        if package_source.startswith(f"git+{repository}"):
            from_node.append(package["name"])
            if package_source != source:
                problems.append(
                    f"Cargo.lock resolves {package['name']} from {package_source}, not {source}"
                )
    for name in ("ant-node", "webrtc"):
        if name not in from_node:
            problems.append(f"Cargo.lock resolves no {name} from {repository}")
    if problems:
        raise Mismatch("\n".join(problems))
    return sorted(from_node)


def git(*args, cwd=ROOT):
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
    ).stdout.strip()


def tree_entries(tree, cwd):
    """path -> (mode, object) for every file under `tree`."""
    entries = {}
    for line in git("ls-tree", "-r", "--full-tree", tree, cwd=cwd).splitlines():
        meta, path = line.split("\t", 1)
        mode, _, obj = meta.split(" ")
        entries[path] = (mode, obj)
    return entries


def check_vendored(repository, revision):
    """This repository's vendor/ant-protocol at HEAD is darwin-node's at `revision`."""
    ours = git("rev-parse", f"HEAD:{VENDORED}")
    with tempfile.TemporaryDirectory() as scratch:
        git("init", "--quiet", "--bare", scratch, cwd=scratch)
        git("fetch", "--quiet", "--depth", "1", "--no-tags", repository, revision, cwd=scratch)
        theirs = git("rev-parse", f"{revision}:{VENDORED}", cwd=scratch)
        if ours == theirs:
            return ours
        their_files = tree_entries(theirs, scratch)
    our_files = tree_entries(ours, ROOT)
    lines = [
        f"{VENDORED} at HEAD is tree {ours}; darwin-node's at {revision} is {theirs}:"
    ]
    for path in sorted(our_files.keys() | their_files.keys()):
        if path not in their_files:
            lines.append(f"  only here: {path}")
        elif path not in our_files:
            lines.append(f"  only in darwin-node: {path}")
        elif our_files[path] != their_files[path]:
            lines.append(f"  differs: {path}")
    raise Mismatch("\n".join(lines))


def check_release(repository, revision):
    """`revision` is on darwin-node's main and is not in TOO_OLD."""
    if revision in TOO_OLD:
        raise Mismatch(f"{revision} can't be released against: {TOO_OLD[revision]}")
    with tempfile.TemporaryDirectory() as scratch:
        git("init", "--quiet", "--bare", scratch, cwd=scratch)
        git(
            "fetch", "--quiet", "--filter=blob:none", "--no-tags", repository,
            "+refs/heads/main:refs/heads/main", cwd=scratch,
        )
        on_main = subprocess.run(
            ["git", "merge-base", "--is-ancestor", revision, "refs/heads/main"],
            cwd=scratch, capture_output=True, text=True,
        )
        if on_main.returncode != 0:
            raise Mismatch(
                f"{revision} is not on darwin-node's main: a client release is "
                "tested against a released node, never an unmerged branch commit"
            )


def main(argv):
    if argv[1:] not in ([], ["--vendored"], ["--release"]):
        print(__doc__, file=sys.stderr)
        return 2
    try:
        repository, revision = pinned()
        packages = check_pins(repository, revision)
        print(f"darwin-node {revision} ({repository}): {', '.join(packages)}")
        if argv[1:] in (["--vendored"], ["--release"]):
            tree = check_vendored(repository, revision)
            print(f"{VENDORED} is darwin-node's at {revision} (tree {tree})")
        if argv[1:] == ["--release"]:
            check_release(repository, revision)
            print(f"darwin-node {revision} is on its main, and may be released against")
    except Mismatch as mismatch:
        print(f"darwin-node-pin: {mismatch}", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as error:
        print(f"darwin-node-pin: {' '.join(error.cmd)} failed: {error.stderr}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
