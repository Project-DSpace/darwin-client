# CLAUDE.md

This is the development guide for the `autonomi-client` project (the Unified CLI + `ant-core` library).

## Project Overview

A Rust workspace with two crates:
- **ant-core** (`ant-core/`) — Headless library containing all business logic. No UI code, no terminal output.
- **ant-cli** (`ant-cli/`) — Thin CLI adapter. Parses arguments via clap, calls `ant-core`, formats output. The binary is named `darwin`.

## Design Principles

These are non-negotiable. Every contribution must follow them.

### 1. No printing, no UI assumptions in ant-core
All `ant-core` functions return structured result types. Long-running operations report progress through the `ProgressReporter` trait and lifecycle events through the `EventListener` trait. Zero `println!`, `eprintln!`, or direct terminal output.

### 2. Option structs replace long parameter lists
Every operation takes an options struct rather than many function parameters. This keeps APIs ergonomic and forward-compatible.

### 3. Async-first
All I/O operations are `async`. The daemon runs on a tokio runtime.

### 4. Serializable types
All result types and status models derive `serde::Serialize` + `serde::Deserialize`. This enables `--json` CLI output, REST API responses, and frontend integration.

### 5. Cancellation support
Long-running operations accept a `CancellationToken` so any frontend can abort cleanly.

### 6. No OS service managers
Nodes run as regular processes managed by the daemon. The only platform-specific code is process detachment, isolated in `ant-core::node::process::detach`.

### 7. AI agent friendly
The REST API is the primary integration point for AI agents. All operations available through the CLI are also available through the REST API. The API is self-describing via OpenAPI spec at `/api/v1/openapi.json`. Real-time events are available via SSE.

## Architecture

```
┌──────────┐     HTTP      ┌──────────────────────────────────┐
│darwin CLI│──────────────▶│         darwin daemon             │
└──────────┘  127.0.0.1    │                                  │
                           │  ┌────────────┐ ┌────────────┐  │
┌──────────┐     HTTP      │  │  antnode 1  │ │  antnode 2  │  │
│  Web UI  │──────────────▶│  └────────────┘ └────────────┘  │
└──────────┘               │  ┌────────────┐ ┌────────────┐  │
                           │  │  antnode 3  │ │  antnode N  │  │
┌──────────┐     HTTP      │  └────────────┘ └────────────┘  │
│ AI Agent │──────────────▶│                                  │
└──────────┘               └──────────────────────────────────┘
                                       │
                                       ▼
                              node_registry.json
```

The daemon is a long-running process that manages all node processes on the machine, exposing a REST API on localhost. No admin privileges required on any platform.

## Crate Structure

```
ant-core/src/
├── lib.rs
├── error.rs                  # Unified error type (thiserror)
├── config.rs                 # Platform-appropriate data/log directory paths
├── data/                     # Data storage and retrieval
│   ├── mod.rs                # Re-exports (Client, DataMap, Wallet, PaymentMode, etc.)
│   ├── error.rs              # Data operation errors
│   ├── network.rs            # P2P network wrapper (DHT, peer discovery)
│   └── client/               # High-level client API
│       ├── mod.rs            # Client, ClientConfig
│       ├── chunk.rs          # chunk_put, chunk_get, chunk_exists
│       ├── data.rs           # data_upload, data_download, data_map_store/fetch
│       ├── file.rs           # file_upload, file_download (streaming self-encryption)
│       ├── payment.rs        # pay_for_storage, approve_token_spend
│       ├── quote.rs          # get_store_quotes from network peers
│       ├── merkle.rs         # Merkle batch payment (PaymentMode enum)
│       ├── pointer.rs        # pointer_create/update/get/resolve (ADR-0016), transfer/finality (ADR-0018)
│       └── cache.rs          # In-memory LRU chunk cache
│   └── manifest/             # File manifests and darwin:// links (ADR-0006)
│       ├── mod.rs            # Manifest, ManifestEntry, ContentRef, encode/decode, limits
│       ├── path.rs           # Portable path rules (cross-platform, enforced everywhere)
│       ├── link.rs           # darwin://<address> and darwin://manifest/<base64url> links (ant:// read too)
│       ├── file.rs           # .darwin file read/write (.ant files read too)
│       ├── history.rs        # Upload history: one .darwin per readable upload under <data dir>/darwin-uploads
│       ├── wire.rs           # Manifest-owned DataMap layout; pre-decode structure check
│       ├── build.rs          # ManifestBuilder (uploads files, embedded or compact refs)
│       ├── embed.rs          # Root-vs-shrunk DataMap choice for embedding
│       ├── compact.rs        # Plan/apply compaction (embedded DataMaps -> addresses; publishes nothing)
│       └── extract.rs        # Containment-safe extraction with per-entry results
└── node/                     # Node management
    ├── mod.rs                # add_nodes, remove_node, reset
    ├── types.rs              # DaemonConfig, DaemonStatus, NodeConfig, NodeInfo, AddNodeOpts, etc.
    ├── events.rs             # NodeEvent enum, EventListener trait
    ├── binary.rs             # Binary resolution (download/cache/validate), ProgressReporter trait
    ├── registry.rs           # Node registry (CRUD, JSON persistence, file locking)
    ├── devnet.rs             # LocalDevnet (local network + Anvil EVM blockchain)
    ├── daemon/
    │   ├── mod.rs
    │   ├── client.rs         # Daemon client API (start/stop/status via HTTP)
    │   ├── server.rs         # HTTP server (axum), REST API handlers
    │   ├── supervisor.rs     # Process supervision with backoff
    │   └── forward/          # Opt-in beta log forwarding (V2-1021)
    │       ├── mod.rs        # Status/result types, enable-request merging
    │       ├── config.rs     # Persisted opt-in + token (0600), LogLevel
    │       ├── parse.rs      # Log line -> LogEvent (text and JSON layouts)
    │       ├── tail.rs       # Rotation-aware tailing, multi-line events
    │       ├── offsets.rs    # Persisted tail positions
    │       ├── document.rs   # Tagging into the beta index's field names
    │       ├── sink.rs       # LogSink trait, bounded queue, batching, retry
    │       ├── es.rs         # Elasticsearch _bulk sink
    │       └── runner.rs     # The background forwarding task
    └── process/
        ├── mod.rs
        ├── spawn.rs          # Spawning node processes
        └── detach.rs         # Platform-specific session detachment

ant-cli/src/
├── main.rs                   # Entry point, client/wallet/EVM initialization
├── cli.rs                    # Top-level clap definition
└── commands/
    ├── data/
    │   ├── file.rs           # darwin file upload/download
    │   ├── chunk.rs          # darwin chunk get (put is off in this build: RAW_CHUNK_PUT)
    │   ├── pointer.rs        # darwin pointer keygen/address/create/update/get/resolve/transfer/finality/controller
    │   ├── manifest.rs       # darwin manifest create/list/show/link/export/download
    │   └── wallet.rs         # darwin wallet address/balance
    └── node/                 # darwin node: off in this build (NODE_MANAGER in mod.rs)
        ├── mod.rs
        ├── add.rs            # darwin node add command
        ├── daemon.rs         # daemon start/stop/status/info/run commands
        ├── logs.rs           # darwin node logs forward enable/disable/status
        ├── start.rs          # darwin node start
        ├── stop.rs           # darwin node stop
        ├── status.rs         # darwin node status
        └── reset.rs          # darwin node reset
```

## Common Commands

```bash
cargo check              # Fast compilation check
cargo test --all         # Run all unit and integration tests
cargo clippy --all-targets --all-features -- -D warnings  # Lint
cargo fmt --all -- --check  # Format check
cargo run --bin darwin -- --help  # Run the CLI
```

## Key Conventions

- **Error handling**: Use `thiserror` in ant-core, `anyhow` in ant-cli. ant-core defines `error::Error` and `error::Result<T>`.
- **CLI output**: All commands support `--json` global flag. Human-readable output by default, structured JSON when `--json` is passed.
- **Hidden commands**: `darwin node daemon run` is hidden (runs daemon in foreground, used internally by `daemon start`).
- **REST API conflict responses**: All 409 responses include a `current_state` field so retrying clients can confirm desired state already exists.
- **Platform paths**: Use `ant_core::config::data_dir()` and `ant_core::config::log_dir()` for platform-appropriate paths. Never hardcode paths.
- **OpenAPI schema**: Types exposed in the REST API derive `utoipa::ToSchema`. Use `#[schema(value_type = String)]` for `PathBuf` fields.
- **Tests**: Unit tests go in `#[cfg(test)] mod tests` inside the source file. Integration tests go in `ant-core/tests/`.
- **Progress reporting**: Long-running operations (e.g., binary downloads) accept a `&dyn ProgressReporter` from `ant_core::node::binary`. CLI provides a terminal-printing implementation; use `NoopProgress` in tests and daemon API handlers.
- **Registry file locking**: Use `NodeRegistry::load_locked()` for read-modify-write operations to prevent concurrent CLI invocations from corrupting the registry. The returned `File` handle holds the lock until dropped.
- **Dual-path CLI commands**: Commands that modify the registry (like `darwin node add`) check if the daemon is running. If so, they route through the REST API; otherwise, they operate directly on the registry file.
- **Binary source resolution**: Node binary sources are represented by the `BinarySource` enum (Latest, Version, Url, LocalPath). Download variants are stubbed until release infrastructure is available.
- **Manifests never touch the network**: a manifest (`.darwin` file or `darwin://manifest/...` link)
  is shared off-network; only the files it references live on the network. `darwin://<hex>` is always
  a plain file link. `darwin://` links and `.darwin` files are what the client writes; upstream's
  `ant://` and `.ant` are also read, and the format's magic (`\xC1ANT`) and version stay upstream's.
  Every readable upload (`darwin file upload` by its address, `darwin manifest create` as written) is
  also recorded as a manifest under `<data dir>/darwin-uploads/` (Autonomi's `ant` uses `uploads/`);
  private uploads are not recorded, so no private data map is kept in the data directory.
  `darwin manifest list` shows them and `show`/`link`/`export`/`download` accept a record id. Entry paths obey the portable rules in `data/manifest/path.rs` at build,
  decode and extract time, and extraction never follows symlinks inside the output directory.
  See `docs/adr/ADR-0006-file-manifests-and-links.md`.
- **Log forwarding is opt-in and node-logging-dependent**: `darwin node logs forward enable` is the
  consent act. It only forwards nodes whose `NodeConfig.log_dir` is `Some` — node file logging is
  off unless the node was added with `--log-dir-path` — and reports the nodes it is skipping.
  Enabling never restarts a node or changes its arguments. See
  `ant-core/src/node/daemon/forward/` and the V2-1016 ingest contract documented at the top of
  `forward/es.rs` (`create` actions, per-position `items[].status`, deterministic `_id`s).

## Commands that are off in this build

`darwin chunk put` (`RAW_CHUNK_PUT` in `commands/data/chunk.rs`) and every `darwin node` command
(`NODE_MANAGER` in `commands/node/mod.rs`) are refused before they read a key, touch the data
directories or reach a network; so is `darwin update` (`SELF_UPDATE` in `commands/update.rs`).
`ant-cli/tests/darwin_cli.rs` runs the binary to check the first two. A `darwin node` command a
merge adds is refused too, and fails `the_node_commands_are_the_ones_checked_off` (cli.rs) until
it is added to that file's list.

## Linear Project

This project tracks work under the "Unified CLI" project in Linear (team: v2.0).

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
Release-promotion PRs — a `chore(release):` title from an `rc-*` head branch —
are exempt from both checks (they are mechanical version-bump PRs generated by
the release process).
