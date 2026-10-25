#!/usr/bin/env python3
"""Where CI runs each of ant-core's test targets.

Every file in ant-core/tests/*.rs is a test target, and each one runs in
exactly one place, or is skipped by name with its reason:

- test.yml runs the end-to-end targets, one job each, against in-process
  darwin-node nodes and a local Anvil chain. Its matrix is every target this
  file doesn't name below, so a new test file runs there without being added
  to any list.
- build.yml runs the targets in NO_NODES, which start neither nodes nor a
  chain, beside the unit tests.
- SKIPPED names the targets CI doesn't run, each with why. They still build in
  build.yml's clippy run, which lints every target.

The check fails when a test target would be neither run nor skipped: when
Cargo's test targets of ant-core aren't exactly the files in ant-core/tests
(a target the matrix can't see, or a file Cargo doesn't build), when a name
below isn't a test target, when a target is both run and skipped, or when a
target requires a feature its job doesn't enable.

    test-targets.py e2e        the end-to-end targets, as a JSON array
    test-targets.py no-nodes   build.yml's targets, as cargo test arguments
    test-targets.py check      the check alone, listing where each target runs

Every mode runs the check first and exits 1 if it fails. Needs Python 3.8+
and cargo (for `cargo metadata --no-deps`, which fetches nothing).
"""

import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
TESTS = ROOT / "ant-core" / "tests"

# Targets that start neither nodes nor a chain; build.yml runs them with the
# unit tests. daemon_integration and node_add_integration test the node
# manager the node image ships. census_probe starts two of the network
# library's peers on loopback, no storage node, to probe one that restarted.
NO_NODES = [
    "census_probe",
    "daemon_integration",
    "datamap_file",
    "log_forward_integration",
    "merkle_unit",
    "node_add_integration",
    "unit_self_encrypt",
]

# Targets CI doesn't run, and why.
SKIPPED = {
    "e2e_huge_file": (
        "uploads files of 1, 4 and 8 GB to in-process nodes to show memory "
        "stays bounded: more disk and time than a hosted runner has. Run by hand."
    ),
    "e2e_upload_costs": (
        "a table of what uploads of 10 MB to 4 GB cost on in-process nodes: a "
        "measurement, not a pin, with more disk and time than a hosted runner "
        "has. Run by hand, with --release."
    ),
}

# The features each job builds ant-core with; `native` is its default.
FEATURES = {
    "e2e": {"native", "test-utils"},
    "no-nodes": {"native"},
}


def cargo_test_targets():
    """ant-core's test targets, as Cargo builds them: name -> (path, features)."""
    output = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    package = next(p for p in json.loads(output)["packages"] if p["name"] == "ant-core")
    return {
        target["name"]: (
            pathlib.Path(target["src_path"]).resolve(),
            set(target.get("required-features") or []),
        )
        for target in package["targets"]
        if "test" in target["kind"]
    }


def plan():
    """(e2e, no_nodes, problems): where each target runs, and what's wrong."""
    files = {path.stem for path in TESTS.glob("*.rs")}
    targets = cargo_test_targets()
    problems = []

    for name, (path, _) in sorted(targets.items()):
        if path != (TESTS / f"{name}.rs").resolve():
            problems.append(
                f"test target {name} is built from {path}, not ant-core/tests/{name}.rs, "
                "so neither the matrix nor these lists can see it"
            )
    for name in sorted(files - targets.keys()):
        problems.append(f"ant-core/tests/{name}.rs is not a test target Cargo builds")
    for name in NO_NODES:
        if name not in files:
            problems.append(f"NO_NODES names {name}, which is not in ant-core/tests")
    for name in SKIPPED:
        if name not in files:
            problems.append(f"SKIPPED names {name}, which is not in ant-core/tests")
    for name in sorted(set(NO_NODES) & SKIPPED.keys()):
        problems.append(f"{name} is in NO_NODES and in SKIPPED: run it, or skip it")
    if len(set(NO_NODES)) != len(NO_NODES):
        problems.append("NO_NODES names a target twice")

    e2e = sorted(files - set(NO_NODES) - SKIPPED.keys())
    for job, names in (("e2e", e2e), ("no-nodes", NO_NODES)):
        for name in names:
            missing = targets.get(name, (None, set()))[1] - FEATURES[job]
            if missing:
                problems.append(
                    f"{name} requires features {sorted(missing)}, which its job "
                    f"({job}) doesn't enable"
                )
    if not e2e:
        problems.append("no end-to-end targets: the matrix would be empty")
    return e2e, NO_NODES, problems


def main(argv):
    if len(argv) != 2 or argv[1] not in ("e2e", "no-nodes", "check"):
        print(__doc__, file=sys.stderr)
        return 2
    e2e, no_nodes, problems = plan()
    if problems:
        for problem in problems:
            print(f"test-targets: {problem}", file=sys.stderr)
        return 1
    mode = argv[1]
    if mode == "e2e":
        print(json.dumps(e2e))
    elif mode == "no-nodes":
        print(" ".join(f"--test {name}" for name in no_nodes))
    else:
        for name in e2e:
            print(f"{name}: test.yml, against darwin-node")
        for name in no_nodes:
            print(f"{name}: build.yml, no nodes")
        for name, why in SKIPPED.items():
            print(f"{name}: skipped, {why}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
