---
name: update-ant-node-ref
description: Move ant-core's tests, devnet and browser harness to another darwin-node revision, keeping every pin alike and vendor/ant-protocol equal to darwin-node's copy, then verify and commit. Use when asked to update ant-node or darwin-node, or /update-ant-node-ref.
allowed-tools: Bash, Read, Edit, Glob, Grep, AskUserQuestion
---

# Update the darwin-node revision

ant-core's tests (the `ant-node` dev-dependency), its `devnet` feature (the `ant-node`
dependency), the workspace's `webrtc` patch and the browser harness all build darwin-node, the
Darwin network's node, at one git revision. `scripts/darwin-node-pin.py`, which CI runs, fails
unless every pin names it and `vendor/ant-protocol` equals darwin-node's copy at it.

## Procedure

### Step 1: Ask for the revision

Ask the user: **Which darwin-node commit should the tests run?** (the full 40-character hash, for
example a release tag's commit). Do not proceed without one.

### Step 2: Change every pin

Replace the old hash with the new one in:

- `ant-core/Cargo.toml`: the `ant-node` dependency and the `ant-node` dev-dependency (`rev`);
- `Cargo.toml`: `[patch.crates-io] webrtc` (`rev`);
- `ant-core/browser-tests/node-revision`: its second line (the first is the repository).

### Step 3: Update the lockfile for darwin-node only

```bash
cargo update -p ant-node
```

Never a bare `cargo update`: it moves every dependency.

### Step 4: Check the pins and the vendored copy

```bash
python3 scripts/darwin-node-pin.py --vendored
```

If `vendor/ant-protocol` differs from darwin-node's, stop and report the files the script lists:
the client's copy follows the node's in a change of its own, reviewed against the fork features.

### Step 5: Build and test

```bash
cargo test --locked -p ant-core --features test-utils --no-run
```

Then run the end-to-end cases, with `anvil` on PATH: the whole `e2e` target, or at least its
`refusals` group and the payment-recovery cases
(`cargo test --locked -p ant-core --features test-utils --test e2e -- refusals payment_recovery native_payment`),
and the browser harness as `ant-core/browser-tests/README.md` describes. If the build or a test
fails, stop and report it, with what changed in darwin-node to cause it. Do not change the tests to
make them pass without the user's say.

Some refusals are pinned only by darwin-node's tests, the client's own cases having gone for them.
Check they still exist at the new revision before committing, and if they moved, update the doc
that names them; if one is gone with no replacement, stop and report it:

- a proof of 0 bytes and a proof of random bytes, refused (named in `ant-core/tests/e2e/security.rs`):
  `test_attack_empty_proof_bytes` and `test_attack_garbage_bytes_as_proof` in
  `tests/e2e/security_attacks.rs`, or the rows "0 bytes" and "garbage" of
  `test_chunk_rejected_without_payment` in `tests/e2e/data_types/chunk.rs`;
- the read and merge rules of pointers (named in `ant-core/tests/e2e/pointer.rs`):
  `tests/pointer_convergence.rs`.

### Step 6: Commit

Stage the three files and `Cargo.lock`, and commit in this repository's style (read `git log`),
naming the new revision and the release it is. Push or open a pull request only if asked.
