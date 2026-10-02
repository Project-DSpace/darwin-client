# CLAUDE.md

Development guide for the `ant-protocol` crate.

## Project Overview

`ant-protocol` is the wire contract between
[`ant-client`](https://github.com/WithAutonomi/ant-client) and
[`ant-node`](https://github.com/WithAutonomi/ant-node). It holds the
types and helpers both sides must agree on. Nothing else belongs here.

## Scope (what goes in vs what stays out)

**In:**
- Wire message types (`ChunkMessage`, put/get/quote request + response).
- Protocol constants (`CHUNK_PROTOCOL_ID`, size limits, close-group sizing, proof tags).
- `ProtocolError`.
- Content-addressing helpers that are pure functions on 32 bytes.
- `send_and_await_chunk_response` (shared send/receive helper on `P2PNode`).
- `PaymentProof` + `SingleNodePayment` (construction, `pay`, `verify`).
- ML-DSA-65 signature verification for quotes and merkle candidates.
- Re-exports of shared transitive deps under `evm`, `transport`, `pqc`.

**Out:**
- Node-side quote generation and signing keys (live in `ant-node`).
- On-chain payment verification state machine / cache (live in `ant-node`).
- `LocalDevnet`, node process management, binary supervision (live in `ant-client`).
- DHT-internal `saorsa-core` types used only inside the node
  (`DHTNode`, `TrustEvent`, `DhtNetworkEvent`, …). `ant-node` keeps
  its own `saorsa-core` dep; Cargo unifies the version because this
  crate pins it.

Rule of thumb: if only one side needs it, it doesn't belong here.

## The version pinning rule

`ant-protocol` is the single version-pin for `evmlib`, `saorsa-core`,
and `saorsa-pqc`. **`ant-client` must not declare direct dependencies
on those three crates** — it must go through `ant_protocol::{evm,
transport, pqc}`. This prevents silent version skew that would
otherwise produce two incompatible copies of `ProofOfPayment` or
`P2PNode` at runtime.

`ant-node` legitimately touches node-only `saorsa-core` surface
(DHT internals) and keeps a direct `saorsa-core` dep for that. Cargo
still unifies the version because both declarations must be
compatible with `ant-protocol`'s pin.

When adding a new type to the re-export modules, check that it is
actually used on both sides — if only one side needs it, it stays as
a direct dep on that side, not a re-export here.

## Design Principles

1. **Small surface.** Every item in `lib.rs` is either a wire type both
   sides use, a pure helper, or a shared protocol function. Think twice
   before adding anything else.
2. **No panics in production code.** `#[deny(clippy::unwrap_used,
   expect_used, panic)]` is on. Tests may relax this with
   `#[allow(clippy::unwrap_used, expect_used, panic)]` locally.
3. **`pay` and `verify` co-located.** The client calls `pay`; the node
   calls `verify`. Tests exercise both ends against Anvil. Splitting
   them would let the two sides drift silently.
4. **Logging is optional and zero-cost when off.** The `logging`
   feature re-exports `tracing` macros. With `--no-default-features`
   the macros expand to `()`.
5. **No I/O except what the shared protocol requires.** The only I/O
   in this crate is the P2P send/receive in `chunk_protocol` and the
   Anvil-backed payment flows in `SingleNodePayment`. If you find
   yourself adding a third I/O path, ask whether it really belongs in
   both crates.

## Development Commands

```bash
# Fast compile check
cargo check --all-features

# Full test suite (includes Anvil-backed tests — needs Foundry installed)
cargo test --all-features -- --test-threads=1

# Unit tests only (fast, no Anvil)
cargo test --lib

# Lint + format
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all

# Docs
cargo doc --all-features --no-deps

# Confirm no-default-features still builds
cargo build --no-default-features

# Pre-publish verification
cargo publish --dry-run
```

## Release Process

1. Bump `version` in `Cargo.toml` (semver: bump **major** for any wire
   change, **minor** for additive wire-compatible changes, **patch**
   for fixes).
2. Update `CHANGELOG.md`.
3. Commit, push, open PR.
4. After merge, create and push a tag matching the Cargo version:
   `git tag v2.1.0 && git push origin v2.1.0`.
5. The `Release` workflow validates, runs the full test suite,
   publishes to crates.io, and creates a GitHub Release.

Manual publish path (if CI is unavailable) is just `cargo publish`
from a clean checkout of the tagged commit, with
`CARGO_REGISTRY_TOKEN` in the environment.

## When to bump

- Change a wire message field (add, remove, rename, retype): **major**.
- Add a new `ChunkMessageBody` variant (existing variants unchanged): **minor**
  — serde enum encoding preserves unknown variants through postcard's
  discriminant strategy, so old decoders reject the new variant cleanly.
- Add a new helper, new constant, new optional field: **minor**.
- Fix a bug that doesn't change the wire: **patch**.

## Pull requests: fill the template

When you open a pull request, you MUST use `.github/PULL_REQUEST_TEMPLATE.md` as
the PR body and fill it in completely — do not open a PR with an empty or ad-hoc
description.

- **Fill every field.** Leave nothing blank; if a value isn't determinable, ask
  before opening the PR.
- **Link the Linear issue with a closing magic word** — write `Closes V2-123` in
  the `## Linear issue` section, one line per issue. Any of Linear's closing
  words works, in any tense (`close` / `fix` / `resolve` / `complete` /
  `implement`, plus their `-s`, `-d` and `-ing` forms), and the key may be a
  `linear.app` issue URL. A bare `V2-123` does **not** link the PR at all, and
  the linking-only words (`ref`, `part of`, `towards`, `relates to`) attach it
  without driving the Merged transition — CI rejects both. An issue key in the
  branch name or PR title also links, but write the closing form anyway; it is
  what moves the issue to Merged when the PR lands on `main`.
- **Check exactly one Risk tier box and exactly one Semver impact box.** Propose
  them from the change; a human confirms them at review.
- An **ADR link is required for Tier 2/3**.

CI enforces the Linear link and the template fields (`linear-link` and
`pr-template` status checks); a PR that omits them fails its checks.
