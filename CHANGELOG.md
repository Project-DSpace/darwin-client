# Changelog

All notable changes to the `ant` binary will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Darwin fork

Our changes on top of upstream 0.3.11 (ant-core 0.13.0). There are no tagged releases; builds are
told apart by the commit `darwin --version` prints. Upstream's entries follow.

- The default network is ours: Robinhood Chain (chain ID 4663), with the seeds, token, vault and
  RPCs bundled in `ant-core/resources/`.
- Payments in DARWIN (`0x511f76A3…`, vault `0xE0f62798…`), priced like Autonomi with a price
  multiplier of 32 in the vendored ant-protocol. Builds before `0995cba` pay the retired test token.
- Listings v2: envelopes on every visibility, optional payment fields, upload records and proofs
  (`darwin file prove`, `darwin file verify`), and the listings index (`darwin listings`,
  `darwin listing`) read with quorum checks.
- darwin-listings is vendored at v0.3.1. 0.3.0 added nodes' change feeds (digest entries, set
  hashes, address ranges, pushes to watchers and `FeedSync`); the client routes their answers and
  pushes by request id. 0.3.1 dates a listing whose nearest nodes give fewer than 4 dates that pass
  their checks by the latest of those dates, not their median, so fewer than 4 nodes can't date it
  earlier. The index as small static files, `listings/v1/`, is specified in `docs/listings-v1.md`,
  with its types in `ant_core::data::client::listings_v1`.
- `darwin listings serve --state-dir DIR --out-dir DIR [--carry FILE]` keeps the index published
  as the files of `listings/v1/`, deciding what `darwin listings --state --carry` decides, with
  envelopes and final chain facts kept (paced and batched RPC calls), and writes only the files
  whose bytes change. It keeps a census of the nodes, built from witnessed lookups, instead of
  finding them anew each time; each minute it asks every node with a change feed (ds.15 or later)
  what changed in its part of the address space, and reads the others with one `listings.v2`
  request a minute and a full pass at most hourly. It decides again only the addresses whose
  copies, nearest nodes or chain facts changed (and every address once a day), those a quorum
  may serve or that are published first, for a minute from when deciding starts, and publishes a
  new listing a node pushes within seconds, deciding between cycles only the addresses pushes
  change, until the next cycle is due, and only from copies pushed since the cycle read the nodes.
  A node's requests wait at most two requests' timeouts a cycle, so a slow node can't hold the
  cycle open, and a node whose push comes behind its mirror is asked again in the same cycle. A
  node whose feed can't be read is read with `listings.v2` requests meanwhile, its feed asked for
  again hourly with one request; and on a stop the producer ends its watches on the nodes. A cycle
  decides nothing when fewer than 7 nodes, or under three quarters as many as in any of the 10
  cycles before, answered, as a read's guard counts the nodes it finds. A search for a payment that
  isn't on the chain goes on, the next time, from the last final block it searched. The full
  listings behind the nodes' entries are
  fetched once, one request at a time to a node, those a quorum names first and the others
  within each node's allowance, and kept, in the bytes a `GetResponse` carries them in, up to a page's share of a
  message; a node that doesn't hand one over can't keep an address from being decided, or other
  listings from being fetched. An entry is dropped only when, in one cycle, all 7 of
  its nearest nodes answered without a copy, a witnessed lookup confirms them, and each of them
  and the nodes that last served it answers a request for the address with none. An entry that
  itself shows a payment from before the payment vault was deployed is removed (`rejected`), not
  kept as carried. The size of a readable file whose data map is shrunk (into at most 3 chunks,
  as uploads shrink it) is read from its root map once, within bounds (no chunk decrypted past its
  declared size), at most 8 a cycle in a task of its own, each in its turn, and filled in to its
  entry as a put. Deciding every address again, after each start
  and once a day, is spread over cycles, for what is left of each minute. What grows with the index (the mirrors, full listings, what is known of each address) is
  kept in the store, and addresses are decided 256 at a time, each batch recorded before the next
  and the files written once, with `rejected.json` and `pages.json` written a row at a time, so
  the producer's memory doesn't grow with the index, but for a name's shard, built whole (about
  1.6 KB an entry while it is written: one name with about 550,000 entries would take 1 GiB).
- Envelopes are darwin's default: `darwin file upload`, `darwin manifest create` and the
  library's file upload shortcuts store each upload in an envelope, with its payment record, a
  listing when listed, and a `.record`. The other ways of using the network remain, with no
  envelope: raw chunks (`darwin chunk put`), a file's encrypted chunks whose data map the caller
  keeps (`data_upload`), plain data maps (`Visibility::Public`,
  `darwin manifest export --compact --yes`), the browser core's uploads and pointer writes, and
  other clients.
- Uploads paid by an outside payer; merkle batches paid in exact powers of two.
- Uploads pay per chunk: `darwin file upload` and `darwin file cost` no longer use batch (merkle)
  payments, which the vault lets a payer steer and can charge twice when re-sent, and refuse
  `--merkle`; `--no-merkle` is accepted and does nothing (2026-10-09).
- Uploads read every paid quote's vault record back after paying. A quote someone else recorded
  first (the vault then skips the payment, with no revert and no event) is quoted again and paid
  again, up to 3 times per chunk; after that the chunk fails with a `quotes occupied` error naming
  the node that issued the quotes. Applies to uploads paid by the wallet or an outside payer
  (`UploadPayer`), and to single records (`chunk_put`, pointer create, update and transfer). A
  payment made outside the client and handed to it to store is read back before anything is sent:
  `finalize_upload` and `finalize_upload_resumable` don't send a chunk whose quote was occupied,
  which fails with the same error (a finalize can't quote it again, so the upload has to be
  prepared again), hold the envelope back, report the cost without the skipped payment, and leave
  the chunk out of the resume handle, which lists it (`WaveFinalizeResume::occupied`);
  `finalize_chunk` and `pointer_put_paid` refuse it before sending. These four read through the
  client's EVM network (`with_evm_network` or `with_wallet`); a client with neither reads nothing
  back and logs a warning. The merkle finalize paths and the raw building blocks (`batch_pay`,
  `chunk_put_with_proof`, `finalize_batch_payment`, `SingleNodeQuotePayment::pay`) read nothing
  back; `batch_upload_chunks` is the batch path that does. The records are read through the
  payment network's RPC and then, on the bundled network, the RPCs reads of payments fall back
  to, each call within 15 seconds; before, through its RPC alone, with no time limit.
  Browser builds don't read records back.
- The browser core's uploads and pointer writes (`uploadPublicFile`, `uploadStagedPublicFile`,
  `uploadRecords`, `createPointer`, `updatePointer`, `transferPointer` and `storePaidPointer`)
  are available, as upstream's are. A browser upload stores a plain data map, or the staged
  records, with no envelope: no payment record, listing or `.record`. The browser core doesn't
  yet read paid quotes back, and has no price ceiling option. A page that names no payment mode
  pays per chunk (`single`).
- A record whose quotes storers refuse for rate is quoted again after 1, 2 and 4 seconds instead
  of failing the upload. No released darwin-node limits quote requests yet: the per-peer and
  per-IP quote limits this retry waits out (met by several uploads at once from one address) are
  on darwin-node's unmerged branch `refuse-batch-rate-limit`.
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
  waits for its payment, a second payer's upload of the same file waited for the first (on a
  gateway serving several payers, until the first payer paid or gave up). Wallet uploads without
  an envelope keep their shared checkpoint. A payer's upload interrupted under an earlier build,
  without an envelope, isn't resumed by this one: finish or drain such uploads before upgrading.
- An optional price ceiling: `--max-chunk-price <BASE_UNITS>`, or `ClientConfig::max_chunk_price`
  in the library, the most a node's quote may ask to store one chunk, in the token's base units.
  A quote or merkle candidate asking more is dropped as if its node hadn't answered, and the
  payment planner refuses to plan a payment on one as a last line, so a chunk costs at most 3
  times the ceiling. Unset, the default, there is no ceiling, as before: nodes can ask up to the
  price of the 1,000,000 records a commitment may count, 31,250 DARWIN, so 93,750 DARWIN for one
  chunk. A payment planned before the ceiling and saved by an interrupted upload is resumed as
  saved, never made twice.
- Chunk and pointer reads also ask the bootstrap peers whose peer IDs the client knows, from the
  start, nearest to the address first: the nodes that were nearest to a record when it was
  stored may still hold it after the nodes nearest to it have changed. A read asks the 9
  nearest the address, or all of them when fewer are configured: 9 is the nodes' storage
  retention width, the close group (7) plus the storage admission margin (2). A node is
  responsible for a record, and replication stores it there, while the node is among the 9
  nodes nearest the record by its own routing table, and a bootstrap peer among the 9 nearest
  out of the whole network is also among the 9 nearest out of the bootstrap peers, so these 9
  include every bootstrap peer responsible for the record. A chunk an upload left farther out,
  past close-group nodes that failed or were full (up to the 20th nearest), stays there while
  the node's disk has room, and is not looked for on a bootstrap peer past the 9th.
  `bootstrap_peers.toml` lists all 16 server nodes on QUIC (both nodes of each server, on 10000
  and 10001, every server's 10000 node first) with their peer IDs; the CLI and
  `Client::connect_multiaddrs` hand the selected seeds that carry one to reads
  (`Client::with_bootstrap_peers` for a client built from a node; `Network::bootstrap_peers`
  lists them), and a browser client asks its seeds. Bootstrap addresses without a peer ID add
  nothing.
- A chunk read asks those bootstrap peers one after another in one of its two GET slots, from
  the start of each round until each has been asked; discovery's hints, then the close group,
  keep the other. A slow or silent bootstrap peer holds up only the next one, and a stalled hint
  is raced only once the bootstrap peers have all been asked. Every chunk read sends its first
  GET to the bootstrap peer nearest the chunk, connected or not, and a chunk is reported missing
  only once all of them have answered. A missing chunk therefore costs up to 9 more GETs in
  each round, and a bootstrap peer that doesn't answer makes the read take its second round,
  which asks them again, as an unanswering close-group node does.
- A pointer read asks those bootstrap peers from the start and the close group once it is found,
  each set on its own quorum and corroboration (of 9 bootstrap peers, 5 must answer and 2 name
  the state), a peer in both once, and returns the newer of the two states. A state the
  bootstrap peers agree on is returned even when the close group holds none or does not answer.
  When too few of a set answer, the state those that did agree on still holds the read back: it
  fails with that shortfall rather than return an older state, or none. The close group is read
  as upstream reads it: it is asked further while only one of its peers names a state newer than
  the one it would return, or while a final state is named that no majority of it holds. The
  bootstrap peers are waited for until a quorum of them has answered and two of them agree on a
  state (not one side of a fork), or, once the close group has a state, none of them names a
  newer one; otherwise until every one has answered or failed, so a pointer is reported absent
  only then. So when two bootstrap peers agree on a state, the read does not wait for a newer one
  that a single bootstrap peer names. A read takes as long as the slower set, up to the GET
  timeout when bootstrap peers don't answer, and sends one GET to each bootstrap peer it asks
  that is outside the close group (9 at most, of the 16 bundled seeds; a pointer is at most
  5.3 KB). In either set, a final state a majority of it holds is its answer, and two final
  states that no majority holds are a fork, which fails the read unless only the bootstrap peers
  report it and the close group holds a final state. Creating, updating and transferring a
  pointer read it this way first, so they wait the same way; the check an update or a transfer
  makes before paying, whether any peer holds a final state, asks every peer of the close group
  and none of the bootstrap peers.
- `PaymentMode::Single` is the default of the library (`PaymentMode::default()`,
  `Client::file_upload`, `file_prepare_upload`) and of the browser API, so programs built on
  ant-core pay per chunk unless they ask for batches.
- Reads of payments fall back to other RPCs, and uploads recover a payment the RPC errored on.
- Records paid one at a time recover a payment the RPC errored on, as uploads do:
  `darwin chunk put`, `darwin pointer create`, `update` and `transfer`, and the data maps
  `darwin manifest export --compact --yes` publishes (in the library, `pay_for_storage`,
  `pay_for_storage_split`, `chunk_put`, `data_map_store`, `publish_data_maps`, `pointer_put` and
  the pointer writes). The payment is journaled before its transaction is signed, in a
  checkpoint under the data directory (`payments/record/`) named by the payment network, the
  wallet and the record's address (a pointer's `state_id`). A payment whose outcome is unknown is
  checked on the chain again 10 seconds later; if it still can't be seen, the command fails,
  keeping the journal, and says that running it again carries on without paying twice, which the
  next attempt at the same record with the same wallet does by reconciling the journaled
  transaction. The paid proof stays in the checkpoint until the record is stored (`chunk_put`,
  `pointer_put`), so a record whose store failed after it was paid is stored by the next attempt
  with that proof; `pay_for_storage` and `pay_for_storage_split`, whose callers store the record,
  remove the checkpoint once they return the proof. Before, these payments had no journal: when
  the RPC answered a payment with an error after taking it, the wallet's own retry sent a second
  transaction, or the command failed and running it again paid again.
- The seeds bundled in `darwin` are replaced only by a `darwin_bootstrap_peers.toml` in the config
  directory (`config::DARWIN_BOOTSTRAP_PEERS_FILE`), and the client peer cache is
  `darwin_client_peer_cache.json` in the data directory. Before, `bootstrap_peers.toml` and
  `client_peer_cache.json` were read, which Autonomi's `ant` and its installers write in the
  same directories: on a machine that also has `ant`, uploads and lookups went to Autonomi's
  network (whose quotes fail the price check, so nothing was paid there) and reads lost the
  bundled seeds. A seed file written for an earlier build is read again once renamed.
  Precedence is unchanged: `--bootstrap`, then a devnet manifest, then the seed file, then the
  bundled seeds.
- Payments are signed for the payment network's chain only (4663, or a devnet manifest's
  `evm.chain_id`), so an RPC that reports another chain gets nothing signed.
- `--evm-network` takes `robinhood`, the default, or `local` (a devnet manifest's chain).
  Upstream's `arbitrum-one` and `arbitrum-sepolia`, which paid Autonomi's ANT on Arbitrum, are
  refused when the command line is read, before `SECRET_KEY` or the network, and
  `ant_core::config::resolve_evm_network` refuses them too (`UnsupportedEvmNetwork`);
  `token_symbol` names no token but the bundled network's.
- The CLI is `darwin`, shows costs in the payment token, and has self-update turned off.
- `darwin chunk put` stores a raw chunk, as upstream's does. A raw chunk has no data map, so it
  carries no envelope: no payment record, listing or `.record`. `darwin file upload` is the
  standard way to store a file.
- `darwin node`, upstream's node manager, is off: it installed Autonomi's `ant-node` from
  WithAutonomi's releases, which joins Autonomi's network and is paid on Arbitrum, and its log
  forwarding shipped node logs to Autonomi's endpoint. Every `darwin node` command, the hidden
  `daemon run` and its REST API included, fails before it downloads, writes or starts anything.
  Darwin storage nodes run from the storage-node image (the darwin-node repository's
  `docker/README.md`); nodes an earlier build added are managed with Autonomi's `ant`. The
  library's `ant_core::node` is unchanged.
- `darwin-linux-x64.tar.gz` from CI carries license notices: `LICENSE-MIT`, `LICENSE-APACHE`,
  `THIRD-PARTY-NOTICES.txt` and `RUST-STD-COPYRIGHT.html` next to `darwin`, like upstream's archives.
- Upstream's installers are removed: `install.sh`, `install.ps1`, the npm packages (`npm/`), the
  winget manifest (`resources/winget/`) and the release-signing key
  (`resources/release-signing-key.pub`). They installed or verified Autonomi's `ant`, not
  `darwin`, and the installers wrote Autonomi's `bootstrap_peers.toml` into the config directory
  `darwin` shares. CI fails if any of them is tracked again. `darwin` is built from source or
  taken from the `darwin-linux-x64` CI artifact.
- In the library, the upload calls that take no visibility (`file_upload`, `file_upload_with_mode`,
  `file_upload_with_progress`, `estimate_upload_cost`, `file_prepare_upload`,
  `data_prepare_upload`) store the private envelope `darwin file upload` stores, with every
  payment field shown, and `file_upload_public_with_mode` and `file_upload_public_with_progress`
  the unlisted envelope `--public` stores; before, they stored no envelope, or a plain data map.
  `Visibility::Private` and `Visibility::Public` still upload with no envelope when asked for by
  name, and the raw building blocks (`data_upload`, `data_upload_with_mode`, `chunk_put`,
  `data_map_store`, `upload_records`, `batch_upload_chunks`, `pay_for_storage`,
  `SingleNodeQuotePayment`), which store or pay as upstream's do, say in their documentation
  that they store no envelope, what else they leave out, and what stores one.
- The merge of upstream 0.3.11 (ant-core 0.13.0) brings pointer transfer, finality and controller
  (`darwin pointer transfer`, `finality`, `controller`), file manifests and links
  (`darwin manifest`), large-file downloads in the browser, and concurrent reads that share their
  chunk fetches. Here links are `darwin://` links and manifest files `.darwin` files; upstream's
  `ant://` links and `.ant` files are also read, and the manifest format's magic bytes and
  version stay upstream's. Readable uploads are recorded in the upload history, as manifests
  that `darwin manifest list` lists and `darwin manifest download` fetches again, under
  `<data dir>/darwin-uploads/`: darwin's own folder, since Autonomi's `ant` keeps its history in
  `uploads/` in the same data directory. A `darwin file upload` is recorded by the address it
  stored (its envelope's), whatever its metadata or hidden fields. Private uploads are not
  recorded, so no private data map is kept under the data directory: it stays in the upload's
  `.datamap` and `.record`, or in the manifest file written.
  Here `darwin pointer finality` (`Client::pointer_finality`, the browser's `pointerFinality`,
  and the check `pointer transfer` reports) asks the close group and the bootstrap peers nearest
  the address: while the close group shows no final state, the pointer is read as
  `darwin pointer get` reads it, so it is reported open at the counter of the state that read
  returns, settling on a final state only the bootstrap peers hold, and open with no state only
  when neither set holds one, once every bootstrap peer asked has answered;
  `PointerFinality::seeds` says what they hold. The checks an update and a transfer make before
  paying still ask the close group alone.
  `darwin pointer transfer` pays for the final state as `pointer create` and `pointer update` pay
  for theirs: one record in DARWIN, its paid quote read back and quoted again if someone recorded
  it first, under `--max-chunk-price`, with a wallet that signs for the payment chain only. Like
  them, it recovers a payment the RPC answered with an error, as an upload does.
  Here `darwin manifest create` uploads each file as `darwin file upload` uploads it, with the
  same `--visibility`, `--public`, `--readable`, `--index` and `--hide` choices: private by
  default, in an envelope that shows every payment field, with the same warnings first, paid
  per chunk (`--merkle` is refused). Each file's record is saved in `<manifest>.records/` next
  to the manifest, also when the build fails or is cancelled. In the library,
  `Visibility::default()` (so `BuildOptions::default()`) is that private envelope, and
  `BuildResult::envelopes` carries each uploaded file's envelope and record.
  `darwin manifest create --embed-public` adds a file stored with an envelope by the envelope's
  address, which keeps its payment record, without embedding its data map, and refuses a
  private file's envelope.
  `darwin manifest export --compact` replaces embedded data maps with addresses for files
  already readable by address, including files uploaded with `darwin file upload --public`. A
  file not yet readable is listed with the standard way to make it so (`darwin file upload
  --visibility unlisted`, an envelope); with `--yes`, as upstream, its data map is published as a
  plain chunk instead, after a warning that it gets no envelope (no payment record, listing or
  `.record`). It needs a wallet only with `--yes`. In the library, `plan_compaction` finds a file
  in a readable envelope (`PublicForm`), `apply_compaction` takes the plan, `publish_data_maps`
  stores plain data maps as upstream's does, and `CompactPlan::published` gives the plan after
  it. The vendored ant-protocol is 5.0.0, still
  with the price multiplier, darwin-listings is vendored at 0.2.1 to match, and rustls is
  0.23.46, as on upstream's main.

## [Unreleased]

### Added
- Pointer ownership transfer (ADR-0018 in `ant-node`). `ant pointer transfer --key <FILE>
  <RECIPIENT>` signs the pointer's final state, at counter `u64::MAX`, pointing at the new
  owner's pointer: readers of the address are redirected there by every node that holds it, the
  address stays the same, and no node that holds it gives it up, because a final state is
  replaced by nothing. It is refused before paying if any peer of the close group holds a final
  state for the pointer, if not every peer answers, or if the recipient does not exist or leads
  back. `ant pointer finality <ADDRESS>` asks the whole close group whether a pointer is `open`,
  `settling`, `unconfirmed` (final on a majority, but not every peer answered), `final` or
  `forked`, which is what a recipient checks before relying on a transfer, and `ant pointer controller <ADDRESS>` follows transfers to the pointer that now
  decides. In `ant-core`: `Client::pointer_transfer`, `pointer_sign_transfer`,
  `pointer_finality` and `pointer_controller`, and the new `Error::PointerFinal` and
  `Error::PointerForked`. In the browser: `transferPointer` and `pointerFinality`.

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
- A pointer read that meets a final state returns the final state a majority of the close group
  holds, rather than the merge winner, and asks the whole group until one is found. Two
  different final states are a fork only the owner can make, by racing them to different nodes;
  with no majority on either, the read fails with `Error::PointerForked` instead of guessing.
  Updating a final pointer is refused with `Error::PointerFinal`, before anything is paid.
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
