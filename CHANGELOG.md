# Changelog

All notable changes to the `ant` binary will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Darwin fork

Our changes on top of upstream 0.3.9 (ant-core 0.11.0). There are no tagged releases; builds are
told apart by the commit `darwin --version` prints. Upstream's entries follow.

- The default network is ours: Robinhood Chain (chain ID 4663), with the seeds, token, vault and
  RPCs bundled in `ant-core/resources/`.
- Payments in DARWIN (`0x511f76A3…`, vault `0xE0f62798…`), priced like Autonomi with a price
  multiplier of 32 in the vendored ant-protocol. Builds before `0995cba` pay the retired test token.
- Listings v2: envelopes on every visibility, optional payment fields, upload records and proofs
  (`darwin file prove`, `darwin file verify`), and the listings index (`darwin listings`,
  `darwin listing`) read with quorum checks.
- Uploads paid by an outside payer; merkle batches paid in exact powers of two.
- Uploads pay per chunk: `darwin file upload` and `darwin file cost` no longer use batch (merkle)
  payments, which the vault lets a payer steer and can charge twice when re-sent, and refuse
  `--merkle`; `--no-merkle` is accepted and does nothing (2026-10-09).
- Uploads read every paid quote's vault record back after paying. A quote someone else recorded
  first (the vault then skips the payment, with no revert and no event) is quoted again and paid
  again, up to 3 times per chunk; after that the chunk fails with a `quotes occupied` error naming
  the node that issued the quotes. Applies to uploads paid by the wallet or an outside payer, and
  to single records (`chunk_put`, pointers). Browser builds don't read records back.
- A record whose quotes storers refuse for rate (darwin-node's per-peer and per-IP quote limits,
  met by several uploads at once from one address) is quoted again after 1, 2 and 4 seconds
  instead of failing the upload.
- Uploads no longer take a node's word that it already holds a chunk. A chunk is skipped, unpaid,
  only when `CLOSE_GROUP_MAJORITY` (4) of the 7 nearest nodes claim it and prove it by serving
  it: the client reads it from the claimants one at a time, nearest first, and checks the bytes
  against the address, stopping once 4 have. A failed, timed-out or wrong answer doesn't count.
  Otherwise the chunk is quoted, paid and stored as usual, and the claimants that didn't prove
  it aren't paid, as before for claims short of a majority. Before, 4 nodes placed near an
  address could keep any new chunk there from being paid for or stored, and the upload
  reported success. Re-running an interrupted upload still pays nothing for the chunks it
  stored, and now reads each of them back from 4 nodes (4 × the chunk's size, at most 16 MB per
  chunk). Applies to every quote: uploads, `chunk_put`, cost estimates and merkle preflight.
  Pointer states are never proven this way (honest nodes make no such claim for them), so a
  claim about one is ignored.
- A new chunk is sent to its `CLOSE_GROUP_SIZE` (7) nearest nodes at once instead of the first
  `CLOSE_GROUP_MAJORITY` (4), each one that fails or is full replaced by the next nearest as
  before, and still counts as stored once 4 accept it. Every PUT started runs to its end, so 4
  nodes that answer first, and need not store anything, can no longer keep a chunk from the rest
  of its close group. Costs about 7/4 of the upload traffic of before, and a store now waits for
  the slowest of its 7 nodes (each PUT has its usual time limit). Applies to the native client
  and the browser build alike.
- A chunk read that gets bytes not matching the address from one node asks the next node, like
  after a timeout, instead of failing the whole read (downloads, range reads, the browser
  viewer's reads and read-ahead, `chunk_get`). It fails with the same `InvalidData` error only
  when no node serves the chunk intact. Before, one node serving bad bytes could block a file.
  The node is named in a warning.
- An upload paid by an outside payer (`file_upload_with_payer`) has a checkpoint of its own,
  named by the payer's `checkpoint_scope()`, with an envelope or without. Before, uploads of the
  same file without an envelope shared one checkpoint whoever paid: one payer's upload could
  resume another's payment state, and since an upload holds its checkpoint's lock while it
  waits for its payment, a second payer's upload of the same file waited for the first (through
  dspace-gateway, until the first payer paid or gave up). Wallet uploads without an envelope
  keep their shared checkpoint. A payer's upload interrupted under an earlier build, without an
  envelope, isn't resumed by this one: finish or drain such uploads before upgrading.
- An optional price ceiling: `--max-chunk-price <BASE_UNITS>`, or `ClientConfig::max_chunk_price`
  in the library, the most a node's quote may ask to store one chunk, in the token's base units.
  A quote or merkle candidate asking more is dropped as if its node hadn't answered, and the
  payment planner refuses to plan a payment on one as a last line, so a chunk costs at most 3
  times the ceiling. Unset, the default, there is no ceiling, as before: nodes can ask up to the
  price of the 1,000,000 records a commitment may count, 31,250 DARWIN, so 93,750 DARWIN for one
  chunk. A payment planned before the ceiling and saved by an interrupted upload is resumed as
  saved, never made twice.
- `PaymentMode::Single` is the default of the library (`PaymentMode::default()`,
  `Client::file_upload`, `file_prepare_upload`) and of the browser API, so programs built on
  ant-core pay per chunk unless they ask for batches.
- Reads of payments fall back to other RPCs, and uploads recover a payment the RPC errored on.
- Payments are signed for the payment network's chain only (4663, or a devnet manifest's
  `evm.chain_id`), so an RPC that reports another chain gets nothing signed.
- The CLI is `darwin`, shows costs in the payment token, and has self-update turned off.
- `darwin-linux-x64.tar.gz` from CI carries license notices: `LICENSE-MIT`, `LICENSE-APACHE`,
  `THIRD-PARTY-NOTICES.txt` and `RUST-STD-COPYRIGHT.html` next to `darwin`, like upstream's archives.

## [Unreleased]

### Added
- `ant` is distributed on npm as `@withautonomi/ant`, so `npm install -g @withautonomi/ant`
  works in agent sandboxes and CI runners that allow package-manager traffic but block direct
  binary downloads (V2-1152). Packaging only: the published packages carry the same signed
  binaries as the GitHub release, verified against `SHA256SUMS.txt` and their ML-DSA-65
  signatures during packaging, and published from the release workflow with npm provenance. A
  per-platform companion package guarded by `os`/`cpu` means only one binary is downloaded. The
  `beta` dist-tag tracks beta releases and `rc` tracks release candidates, so a plain
  `npm install -g @withautonomi/ant` only ever serves a stable build; `install.sh`, `install.ps1`
  and the release assets are unchanged. See [`npm/README.md`](npm/README.md).
- `ant` falls back to the bootstrap seeds already bundled into the binary
  (`network_defaults::bundled_bootstrap_seeds`) when no `bootstrap_peers.toml` is present in the
  config directory, instead of failing with `NoBootstrapPeers`. Priority is otherwise unchanged
  — explicit `-b` peers, then a devnet manifest, then the config file, then the bundled seeds —
  and an explicitly selected devnet manifest still errors rather than reaching for mainnet peers.
  This is what makes an npm install usable out of the box: npm 12 blocks package install scripts
  by default, so the step that copies that file into the config directory frequently does not
  run.

### Changed
- `ant update` no longer replaces the binary when `ant` was installed by a package manager. It
  still reports whether a newer version is available, then prints the command that will install
  it (`npm update -g @withautonomi/ant`). Self-replacing an npm-managed binary left npm's
  metadata describing a file that was no longer there, so the next `npm update` silently rolled
  the user back.

## [0.3.6] - 2026-09-01

### Fixed
- A client whose routing table has been starved of peers now recovers at runtime
  instead of needing a restart. The fix is in `saorsa-core` 0.27.3 and reaches `ant`
  through this release's dependency uplift — see
  [WithAutonomi/saorsa-core#153](https://github.com/WithAutonomi/saorsa-core/pull/153) (V2-1036).

### Internal
- Release notes are now extracted per version rather than always taking the first
  CHANGELOG section, so each release ships its own notes (#183).

## [0.3.5] - 2026-08-31

### Added
- Resumable external-signer finalize for **both** payment paths, so a post-payment storage shortfall no longer strands the payment (#172). `Client::finalize_upload_resumable` (wave-batch) and `Client::finalize_upload_merkle_multi_resumable` (merkle) — each with a `_with_progress` variant — return a `FinalizeOutcome`: `Complete(FileUploadResult)`, or `Partial { result, resume }` carrying an opaque `FinalizeResume` handle (`Wave` / `Merkle`) that owns the already-paid material (the wave path's paid chunks, or the merkle path's on-disk spill + signed proofs). `Client::finalize_resume` (+ `_with_progress`) takes that handle and re-drives storage for only the still-unstored chunks against the **same** on-chain payment — no re-quoting, no second signature, no double payment — and is loopable until `Complete` (bound the loop: persistent store failures return `Partial` on every call, never `Err`). The merkle resumable finalize requires **every** sub-batch to be paid — a resume handle cannot acquire proofs for unpaid chunks, so a partial payment is rejected up front with a pointer at the non-resumable path. The existing consuming `finalize_upload` / `finalize_upload_merkle_multi` are unchanged (they still accept partial payment and surface a shortfall as `Error::PartialUpload`).
- `NetworkHealth`: one implementation of the write-readiness/peer-count computation for every embedded-client consumer (antd, ant-gui, ant-ffi, ant-tui), moved down from antd (#174). `Network::health` and `Client::network_health` return `NetworkHealth { write_ready, connected_peers, routing_table_size, rebootstrap_threshold }`, where `write_ready` is `max(routing_table_size, connected_peers) >= rebootstrap_threshold` — a client-mode routing table under-reports while stores still succeed, and the connected count alone misses the dead-network case. Both node reads are in-memory, so the snapshot is cheap enough to compute per call.

### Fixed
- `ant node start`/`ant node stop` with `--service-name` now resolve the node ID through the daemon API instead of reading `node_registry.json` directly, eliminating a race against concurrent registry mutations by the daemon.
- `ant node add --json` no longer interleaves binary-download progress with the JSON result; progress output now goes to stderr (was stdout) and is suppressed entirely in JSON mode.

### Changed
- `--evm-network` still defaults to `arbitrum-one`, **except** when a devnet manifest carrying an EVM block is loaded: that combination now errors and asks for an explicit choice (`local` to use the manifest, or a preset to override it). The old behavior silently overrode the manifest's EVM config, producing no-op mainnet-vault transactions on other chains that spent gas and set a useless ANT allowance before every chunk PUT failed payment verification. An explicit preset selected alongside a manifest EVM block now prints a warning that the manifest's EVM config is ignored. No change for mainnet users or read-only operations.

### Internal
- CLI-audit thinning (V2-189): `PortRange` parsing (`FromStr`), env `KEY=VALUE` parsing (`AddNodeOpts::parse_env_vars`), and bootstrap-peer resolution (`config::resolve_bootstrap_peers`) moved from ant-cli into ant-core; `node add`/`node reset` daemon calls now go through `ant_core::node::daemon::client` (new `add_node`/`reset`/`resolve_node_id_by_name` functions) instead of hand-rolled HTTP; the two CLI `ProgressReporter` impls collapsed into one.

## [0.3.4] - 2026-08-27

### Changed (breaking — ant-core update API)
- The `ant` client is beta-channel aware (#173): a `-beta.N` build tracks the beta channel by default — `ant update` takes later `-beta.N` builds and stable releases, never a release candidate — while stable builds keep tracking stable. `ANT_CHANNEL` / `ANT_VERSION` environment variables override channel and target-version resolution. Breaking on three `ant-core` public items (`resolve_binary`, `check_for_update`, `UpdateCheck`); the JSON output surface is additive.

## [0.3.3] - 2026-08-12

### Changed (breaking — external-signer merkle API, ADR-0003)
- External-signer merkle uploads are no longer capped at one payment batch (`MAX_LEAVES` = 256 chunks ≈ 1 GiB): `file_prepare_upload*` now partitions the to-upload set into `MerkleTree`-sized sub-batches (`ExternalPaymentInfo::Merkle` carries `prepared_batches: Vec<PreparedMerkleBatch>`), the signer pays one transaction per batch, and the new `Client::finalize_upload_merkle_multi` takes one winner hash per batch. `finalize_upload_merkle` remains as the single-batch special case. A batch the signer never paid (`None` hash) no longer aborts the upload: paid batches store and the unpaid chunks surface via `Error::PartialUpload`.
- External-signer merkle prepared uploads no longer hold the encrypted file in memory: chunk bodies stay in the on-disk encryption spill (opaque `ExternalChunkStore` inside `ExternalPaymentInfo::Merkle`, replacing the resident `chunk_contents: Vec<Bytes>`), and finalize stores them via the wallet path's bounded spill fan-out — peak RAM ~256 MB regardless of file size, plus deferred-retry rounds the external path previously lacked.

### Added
- `Client::file_prepare_upload_with_mode`: external-signer prepare with an explicit `PaymentMode` override, mirroring the wallet path's `file_upload_with_mode`.
- `ClientConfig::merkle_external_batch_cap`: clamped test seam (`3..=MAX_LEAVES`) so E2E tests exercise real multi-batch external signing with kilobyte files.

### Fixed
- External-signer merkle finalize (`Client::finalize_upload_merkle`) now returns `Error::PartialUpload` when chunks remain short of quorum after all retries, matching the wave-batch finalize. Previously it returned `Ok` with `chunks_failed > 0`, which callers (desktop app, mobile FFI) took as success — reporting a paid but not fully retrievable file as complete (#166).

## [0.3.2] - 2026-07-29

_No entries were recorded at release time. Backfill from the release-train manifests is tracked in Linear V2-1107._

## [0.3.1] - 2026-07-23

_No entries were recorded at release time. Backfill from the release-train manifests is tracked in Linear V2-1107._

## [0.3.0] - 2026-07-09

_No entries were recorded at release time. Backfill from the release-train manifests is tracked in Linear V2-1107._

## [0.2.2 – 0.2.11]

_Ten releases between 2026-04-30 and 2026-07-08; no entries were recorded for them. Backfill is tracked in Linear V2-1107._

## [0.2.1] - 2026-04-30

### Changed
- `ant file upload` now writes datamaps as `<filename>.<extension>.datamap` instead of stripping the extension. Uploading `photo.jpg` produces `photo.jpg.datamap` (was `photo.datamap`). Existing datamaps remain readable.
- `ant file upload` no longer silently overwrites an existing datamap. Repeated uploads of the same source path produce `name-2.datamap`, `name-3.datamap`, … capped at 100 attempts. Pass `--overwrite` to restore the previous behaviour.

### Added
- `ant file upload --overwrite`: replace any existing `<filename>.datamap` rather than writing a suffixed sibling.
- `ant file download --datamap` no longer requires `-o/--output` — defaults to the original filename derived from the datamap basename (`photo.jpg.datamap` → `photo.jpg`, written to the current directory). Pass `-o` to override.
- `ant file download --datamap` now reads both msgpack (canonical) and legacy JSON datamaps, so datamaps produced by older versions of the GUI download cleanly via the CLI.

### Internal
- New `ant_core::datamap_file` module owns the on-disk datamap format (msgpack canonical, JSON legacy auto-detect on read) and naming convention. `ant-cli` and consumers like `ant-gui` route through this single helper instead of reimplementing serialization.

## [0.2.0] - 2026-04-24

### Changed
- Default network binding changed from IPv4-only to IPv6 dual-stack. Hosts without a working IPv6 stack should pass `--ipv4-only` to avoid advertising unreachable v6 addresses to the DHT (which causes slow connects and junk address records).

## [0.1.1] - 2026-03-28

### Added
- Node management: `ant node add`, `ant node start`, `ant node stop`, `ant node status`, `ant node reset`
- Daemon management: `ant node daemon start`, `ant node daemon stop`, `ant node daemon status`
- Data operations: `ant file upload`, `ant file download`, `ant chunk put`, `ant chunk get`
- Wallet management: `ant wallet address`, `ant wallet balance`
- Automatic bootstrap peer loading from `bootstrap_peers.toml` config file
- `--json` global flag for structured output
- Cross-platform support (Linux, macOS, Windows)
