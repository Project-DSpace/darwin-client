# Changelog

All notable changes to the `ant` binary will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Darwin fork

Our changes on top of upstream 0.3.13 (ant-core 0.15.0) from `v0.3.13+ds.12`, and on top of
upstream 0.3.11 (ant-core 0.13.0) before it. Releases are tagged `vX.Y.Z+ds.N`, with ant-cli's
version set to match; other builds are told apart by the commit `darwin --version` prints.
Upstream's entries follow.

- `v0.3.13+ds.13`, one send per payment: ant-cli's version is 0.3.13+ds.13 (ant-core stays
  0.15.0). A payment's first send that the RPC refused with "nonce too low" was taken as never
  sent and signed again, but the wallet library re-sends the same bytes after an answer it lost
  and returns the last answer, so a first send the chain had taken came back refused, and a
  second transaction was sent for the same payment (seen once, 2026-11-14, on the root vault: it
  moved no tokens, cost gas, and the upload reported it as the payment with a cost of zero). Now
  the chain is read for the refused transaction up to three times, one second apart, and the
  vault (the root vault's wave record, or the per-quote vault's quote records, for single
  payments and shared waves) before anything is signed again; a payment the vault shows is
  reported by the transaction that recorded it, found by its log in the same bounded reads, with
  that transaction's cost, and where it can't be found or a read fails, the upload stops saying
  the cost isn't known, with the signed transaction kept in its checkpoint. A root wave recorded
  by an earlier transaction of the same payer is counted as paid. New pins: a lost answer on
  either vault, a receipt held back past the reads with the vault showing the payment (root,
  per-quote, shared wave), its recording transaction unreadable, a failed chain read, a real stale
  nonce, and a second send's report. Left as they are, at the cost of gas only: token approvals
  and the library payment functions the CLI never calls, which use the library's older send.
- `v0.3.13+ds.12`, upstream 0.3.13: ant-cli's version is 0.3.13+ds.12 and ant-core's 0.15.0,
  upstream's ant-cli 0.3.13 / ant-core 0.15.0 merged in, with every change of ours kept. The ds
  number goes on counting across the new base, as darwin-node's does. The tests and devnet run
  darwin-node 0.24.0+ds.22 (upstream node v0.24.0 merged into node release ds.21), and
  `vendor/ant-protocol` and `vendor/saorsa-core` are its copies, ant-protocol 6.0.0 and
  saorsa-core 0.30.0 with our changes (ant-core requires exactly ant-protocol 6.0.0);
  `vendor/ant-listings` is darwin-listings v0.4.0's code on ant-protocol 6.0.0. From upstream:
  - Chunk reads through a client-driven Kademlia lookup (ADR-0020), which asks the peers it finds
    likely to hold a chunk for it as it goes: a peer whose agent announces get-or-closer with the
    new get-or-closer request, every other peer, as every node of the network today, with
    FIND_NODE and a GET. Our reads stay around it: a chunk read asks the node that served it in the
    last few minutes first, and the lookup only once that node has answered without it or not
    within the hedge delay; a chunk the lookup finds notes the node that sent it for the next
    read; a lookup that finds nothing hands its peers to the progressive read, which still asks
    the bootstrap peers nearest the chunk in a lane of their own; a node that sends bytes that
    don't match the address is passed over and named.
  - First reads spread over the close group (ADR-0023), and an early read is raced only once it
    has waited the hedge delay since it was sent, never while it waits on the client's own limits.
    With the bootstrap peers' lane, a read still runs at most two GETs: the lane takes the second
    once no early read is left in flight.
  - Uploads report the file's SHA-256: `darwin file upload` prints it (`SHA-256:`) and puts it in
    its JSON (`sha256`), always the plaintext's, whatever envelope stores the file. Manifest
    entries record it (written only when known, so older manifests keep their bytes, and older
    clients read new ones without it); `darwin manifest show` lists it, extraction checks each
    downloaded file against it, and the upload history's entry, still naming the file by its
    envelope's address, records it.
  - The browser library builds manifests and file links (`createManifest`, `createFileLink`,
    writing `.darwin` bytes and `darwin://` links), recovers a pointer write's payment from the
    checkpoint `onPrepared` is given and the receipt or broadcast the wallet reported
    (`recoverPointerPayment`, `onSubmission`; recovering pays nothing), types pointer write
    errors, gives up on a dial whose ICE checks no node answers within 3 s, and paces its reads
    for DataChannel transfers.
  - zip 9 with only Deflate for the node manager's release archives, and tokio 1.53.3,
    rustls-webpki 0.103.16 and webpki-root-certs 1.0.10 for RustSec advisories.
  Left out: upstream's unversioned quote retry (every quote request names its settlement version;
  a census test now fails if an unversioned one is sent), its installers, workflows, release
  scripts and AGENTS.md, and its merkle finalize-resume test (our nodes refuse batch payments).
  New pins: the read engine's bootstrap lane beside stalled early reads and after a lookup's miss,
  the holder asked before the lookup, the lookup's reads of nodes that do and don't announce
  get-or-closer (the e2e target starts a second network for a rolling upgrade), the lookup's
  dials going through the direct-first dial plan, the SHA-256 of envelope uploads (private,
  unlisted, resumed, already stored) and of manifests built and extracted, a finalize resumed
  after a storage outage paying nothing again, manifests written before SHA-256, and
  `darwin://` from the browser's manifest export.
- `v0.3.11+ds.11`, direct before relay: ant-cli's version is 0.3.11+ds.11 (ant-core stays 0.13.0).
  The client dials a peer's verified direct address before its
  relay. `vendor/saorsa-core` is the network library saorsa-core 0.29.1 as darwin-node vendors it
  (since its ds.17; this copy is its `v0.23.0+ds.20`'s, byte for byte), changed only in the order
  a peer's addresses are dialled in (its `VENDORED.md`), and the workspace's `[patch.crates-io]`
  puts it in place of the crates.io release. A native client now dials a LAN address first when
  the peer is behind the client's own public IP address, then a verified direct address, then the
  relay (skipped when the relay is behind the client's own public IP address), then an unverified
  address, and a LAN address only when nothing else is known. Upstream's dials the relay first, so
  the client reached even nodes it could reach directly through other nodes' relays, and depended
  on those relays staying up. A node behind NAT has no verified direct address, so its relay is
  still dialled first. The library orders a peer's addresses the same way
  (`AddressType::priority`, `DHTNode::addresses_by_priority`), and the in-process nodes of the
  tests and devnet are built with the copy, as darwin-node's nodes are. A project that takes
  `ant-core` by git repeats the new `saorsa-core` entry of `[patch.crates-io]` from the same tag
  (README, "Rust Library API"); without it, the library dials a relay first, as before.
  `vendor/saorsa-core` is a workspace member, so that its own unit tests run under this lock, and
  is optimised in dev and test builds as the other dependencies are. The Build workflow runs those
  tests (`cargo test --locked -p saorsa-core --lib`) and checks the copy's git objects against its
  `VENDORED.md`, and `lock_pins` pins the patch, the one saorsa-core in `Cargo.lock`, the address
  priority and the copy's tests of the order. `scripts/darwin-node-pin.py --vendored` checks that
  `vendor/saorsa-core`, like `vendor/ant-protocol`, is darwin-node's copy at the revision the tests
  run, the same git tree. The Build workflow's clippy run, and the lint command in the README,
  take `--no-deps`, so that clippy doesn't lint `vendor/saorsa-core`: clippy lints every workspace
  member it builds, and upstream's code has findings such as `too_many_arguments`.
  `vendor/ant-listings`, which that run linted before as a member ant-core builds, gets a run of
  its own with the same flags (`cargo clippy -p ant-listings --all-targets --all-features
  --no-deps -- -D warnings`). saorsa-transport stays 0.38.2.
- `v0.3.11+ds.10`, the producer on a new socket: ant-cli's version is 0.3.11+ds.10 (ant-core stays
  0.13.0). `darwin listings serve` starts again on a new socket when a
  node that left its census ignores its own. A node can keep ignoring every new connection from
  one socket (an address and port), as after a relay that socket reached it through closed, while
  it answers any other; the producer keeps one socket for as long as it runs, so such a node
  answered none of its probes until the producer was restarted, and `refresh-census` didn't help.
  Each cycle's census upkeep now also probes the nodes that left 10 minutes ago or more and don't
  answer the producer's own probe from a node started for that round alone (client mode, port 0,
  a new identity, the client's transport settings, no bootstrap peers, shut down after the round),
  at most once every 10 minutes. When a round is due, the upkeep probes those nodes before the
  others, 64 at a time, the ones no round has probed first, then those one probed longest ago, so
  the rounds reach every one of them in turn. A node's time out counts from the producer's start
  if it left before, so each start watches it fail 10 minutes itself first, and a node that
  answers new sockets but never the producer's restarts it at most once every 10 minutes or so. If
  one answers the fresh probe, then once the cycle ends the producer logs a warning naming the
  nodes, stops as on SIGTERM (ending its watches and saving its peer cache) and exits with an
  error, so that its service manager (systemd's `Restart=always`) starts it again, on a new
  socket, from its state; `darwin listings serve --help` says so. Each round is logged at info
  level (`Census: 3 nodes out 10 minutes or more probed from a fresh socket; 1 answered`), and
  the round's node is made, started and stopped within 10 seconds each, so a stuck call can't hold
  the producer without a restart. In the library: `listings_census::probe_fresh`,
  `listings_census::FRESH_PROBE_AFTER`, `CensusChange::ignored_socket` and
  `CensusChange::fresh_round`, and `Producer::run` returns that error.
- `v0.3.11+ds.9`, the producer's lists: ant-cli's version is 0.3.11+ds.9 (ant-core stays
  0.13.0). `darwin listings serve` takes three new options, all off by default. `--hide-list
  FILE` names addresses the producer publishes nothing of: no entry, support, row in
  `rejected.json` or feed record, in any file or its `.gz` and `.zst` copies. `--hold-until-cleared
  FILE` holds each new readable entry, published in no file, until its address is on that list,
  and then publishes it at its own key, keeping its listing time; entries published before stay
  published, and an address on both lists is hidden (Dan, 2026-10-30, choosing to hold new entries
  rather than publish them first: "1. hold"). It needs `--held-file FILE`, outside the out dir,
  where the entries held are written whole at every cycle, each with its data map and
  `held_since`, under `generated_at` and `lists_read_at`. Both lists take one address per line,
  any case, `0x` or not, with `#` comments; each is read again when its file changes, and the last
  list read is kept in the producer's state while its file is missing or unreadable. The feed
  starts again under a new epoch, keeping every published entry not hidden, when asked with the
  new `darwin listings new-epoch --state-dir DIR` and at the start of any cycle at which a hidden
  address has an entry published, so a hidden entry leaves the index with no removal record. A new
  epoch deletes the time pages and feed segments it doesn't name at once, rather than a day later,
  and finishes that at the next start if the producer stopped part way. In the library these are
  `ServeOptions` with `Producer::open_with` (`Producer::open` takes the defaults),
  `Producer::request_new_epoch` (its file is `listings_serve::NEW_EPOCH_FILE`),
  `Publisher::start_epoch` and `ant_core::data::client::listings_lists`. `docs/listings-v1.md` describes what readers see. It
  is tested against darwin-node 0.23.0+ds.20 (`363640e`), the revision its tests pin. Its notes are
  `release-notes/v0.3.11+ds.9.md`.
- `v0.3.11+ds.8`, root by default in the library: ant-cli's version is 0.3.11+ds.8 (ant-core
  stays 0.13.0). After upgrading, a library client given a wallet (`Client::with_wallet`) pays
  through the root vault wherever its network's root vault is known (the bundled network's, or
  the one the client names with `Client::with_root_vault`, before or after the wallet), as the
  darwin CLI has since v0.3.11+ds.7 (Dan, 2026-10-29: "do what you recommend"). Its first root
  payment is preceded by a one-time approval of the root vault to spend the wallet's DARWIN. The
  root vault's wallet is made from the client's wallet's own signer
  (`ant_core::config::root_wallet_of`), the wallet `with_root_payments_from_key` makes from the
  key. `Client::without_root_payments` opts out and keeps the payment vault;
  `with_root_payments` and `with_root_payments_from_key` opt back in, and a root vault's wallet the
  caller gives is kept. In native builds every payment the client sends, default root payments and
  merkle batches included, holds the lock of the wallet given to `with_wallet` (`Wallet::lock`,
  shared by its clones), after the key's lock and before the root vault's wallet's, so a caller
  paying with a clone of that wallet under its lock is serialised with them. Browser builds
  (without `native`) make no root payments, and their `pay_for_storage` and single-node payments
  still take no lock, as before. A wallet whose transaction settings
  were changed (`Wallet::set_transaction_config`) gets no root vault's wallet by default and pays
  the payment vault, unless given one with `with_root_payments`. Outside payers stay opt-in
  (`UploadPayer::pays_root_waves`, false by default), and prepared uploads and chunks, external
  signers and a pointer's quoted state stay on the payment vault. `UploadPayer::payer_address`
  (none by default) names the address a payer's transactions are sent from: when another
  transaction recorded a root wave it paid, a recording from that address counts the wave's total
  in the upload's cost, whether or not the returned transaction can be read; without an address
  the senders of both transactions are compared, as before. On a devnet, `darwin listings`,
  `darwin listing` and `darwin file verify` read the root vault the manifest names
  (`ListingChain::new_with_root_vault`) beside the payment vault. The CLI builds its client on the
  library's default; `--no-root-payments` calls `without_root_payments`. It is tested against
  darwin-node 0.23.0+ds.20 (`363640e`), the revision its tests pin. Its notes are
  `release-notes/v0.3.11+ds.8.md`.
- `v0.3.11+ds.7`, the root switch: ant-cli's version is 0.3.11+ds.7 (ant-core stays 0.13.0). The
  darwin CLI pays through the root vault by default; `--no-root-payments` pays today's payment
  vault only, and `--root-payments`, the opt-in of v0.3.11+ds.6, still parses, hidden. Each record
  still falls back on its own to the payment vault when its close group holds a node that can't
  check a root proof, and the split and envelope rules of v0.3.11+ds.6 are unchanged. On a devnet
  (`--evm-network local`) the CLI reads and pays the root vault its manifest names
  (`evm.root_vault_address`, read by `ant_core::config::manifest_root_vault`); where none is
  known, it pays the payment vault and prints a warning instead of stopping. The library's default
  stays the payment vault: `Client::with_root_payments` opts in as before, and the new
  `Client::with_root_payments_from_key` builds both wallets from one key. A client can name a root
  vault without a wallet to pay it (`Client::with_root_vault`, read by `Client::root_vault`;
  `ListingChain::new_with_root_vault` for a reader), and its envelope records and payment
  read-backs read that vault. The network's payment vault is never taken as its root vault:
  `with_root_vault` ignores it with a warning once the network is known, `with_wallet` and
  `with_evm_network` drop a root vault named earlier that the new network pays per quote, and
  `manifest_root_vault` refuses a manifest naming its payment vault as its root vault. An outside
  payer (`UploadPayer`) is quoted for the root vault only when it asks (`pays_root_waves`, false
  by default) and the client knows the root vault; it pays each root wave in one `payForQuotes`
  call to the root vault, and the client reads the vault's record of the wave back, finds the
  transaction that recorded it (the payer's own from its receipt, else by the vault's `RootPaid`
  log, so a returned transaction that reverted or never gets a receipt doesn't hold the wave
  back) and builds each record's proof naming that transaction, paying nothing again when another
  transaction recorded it. The upload's cost counts the wave's total when the recording transaction was
  sent from the payer's own address (its wallet sped up or replaced the one returned), and nothing
  when it came from another address or the senders can't be read. `exact_approvals` (true by
  default) says the payer approves each vault for exactly what it pays: its payments use both
  vaults only from 5 records that can pay the root vault (3 for the client's own wallets).
  Prepared uploads and chunks finished with `finalize_upload*` or `finalize_chunk`, other external
  signers, and a pointer's state quoted with `prepare_pointer_payment` stay on the payment vault.
  It is tested against darwin-node 0.23.0+ds.20 (`363640e`), the revision its tests pin. Its notes
  are `release-notes/v0.3.11+ds.7.md`.
- `v0.3.11+ds.6`, root payments: ant-cli's version is 0.3.11+ds.6 (ant-core stays 0.13.0). A
  client can pay through the root vault (DarwinRootVault, `0xf6675722f443132b045857546E57e35360Bb03b9`
  on the bundled network), opting in with `darwin --root-payments` or the library's
  `Client::with_root_payments`: a payment's records are paid as one wave in one transaction, the
  vault keeps one record for the wave under its key, and each record's proof (tag 0x03) carries its
  leaf, its place and its path. Root-paid records are quoted at settlement version 3, others at
  version 2. Each record falls back on its own to today's payment vault when its close group holds
  a node that can't check a root proof; a payment pays both vaults only when at least 3 of its
  records pay root, and the envelope never pays alone in either. Records kept from an
  interrupted attempt never move: they pay the vault that attempt chose. What an `UploadPayer` or
  an external signer pays (`file_upload_with_payer`, prepared uploads finished with
  `finalize_upload*`, prepared chunks finished with `finalize_chunk`, a pointer's state quoted with
  `prepare_pointer_payment`) is quoted for today's payment vault. An envelope paid in a root wave
  gets a payment record checked against the root vault, naming the transaction that recorded the
  wave. Without the flag, every payment goes through today's payment vault, which stays the
  default. Quotes on either price curve of v0.3.11+ds.5 are accepted. A checkpoint holding a root
  plan or proof is written in a second format, which older clients refuse. Payment reads on the
  bundled network go to PublicNode, then Robinhood's RPC, then ordofi last (Dan, 2026-10-28); log
  queries keep Robinhood's RPC, PublicNode, then ordofi. It is tested against darwin-node
  0.23.0+ds.20 (`363640e`), the revision its tests pin. Its notes are
  `release-notes/v0.3.11+ds.6.md`.
- `v0.3.11+ds.5`, the price curve: ant-cli's version is 0.3.11+ds.5 (ant-core stays 0.13.0). The
  vendored `calculate_price` is 100 DARWIN per GB of full chunks on empty nodes (0.1396736 DARWIN a
  quote) with divisor 2,000 (Dan, 2026-10-28); every quote check (native, merkle and browser)
  accepts a price in the band of this curve or of the earlier ×32 curve, each with the same rules,
  so quotes from ds.19 nodes and from ds.20 nodes before and after their switch at
  2026-10-29T00:00:00Z all pass. Settlement version, size classes, the band, the price ceiling,
  payment recovery and envelopes are unchanged. v0.3.11+ds.4 and older clients refuse new-curve
  quotes after the switch. It is tested against darwin-node `5d97082` (main after
  0.23.0+ds.19, adding only the price curve that 0.23.0+ds.20 ships), the revision its tests pin
  and whose `vendor/ant-protocol` this copy matches. Its notes are `release-notes/v0.3.11+ds.5.md`.
- `v0.3.11+ds.4`, the pricing switch: ant-cli's version is 0.3.11+ds.4 (ant-core stays 0.13.0).
  The client settles at version 2 and pays each record by its size class (below): a record's paid
  quote receives 3 × the median quote × the record's weight, from 259/1,024 for a record of 16 KiB
  or less to exactly 1 for a full 4 MiB chunk, which pays as before. A quote's price is checked
  against a band in place of the exact price; nodes older than node release 2 answer
  `StorerUpdateRequired` and are skipped before anything is paid. The browser core's own uploads
  pay by class; a JavaScript caller pays the weighted amount only on a quote from a size-priced
  `quote_chunk`, at the next browser protocol version, and a full chunk's amount otherwise. How
  payments are made, read back and recovered is unchanged, and old clients keep working at a full
  chunk's price. It is tested against darwin-node 0.23.0+ds.18 (`81dbac7`, node release 2, the
  revision its tests pin). Its notes are `release-notes/v0.3.11+ds.4.md`, which say how to go back
  to v0.3.11+ds.3.
- `v0.3.11+ds.3`, the readers release: ant-cli's version is 0.3.11+ds.3 (ant-core stays 0.13.0).
  Every reader of payments reads two vaults, the per-quote payment vault and the root vault
  (DarwinRootVault, `0xf6675722f443132b045857546E57e35360Bb03b9` on the bundled network), which
  records each wave of payments under one key. `ListingChain::new` reads both on the bundled
  network, so the listings producer, `darwin file verify`, listing lookups and envelope records
  accept a payment from either vault, each checked by the vault whose log it is; a root vault's
  payment counts only where its receipt shows the whole wave, the key its tree gives, its total and
  its token transfers. A reader on any other network reads the per-quote vault alone, as before.
  Each vault is asked in its own `eth_getLogs` naming one address, both sent in one batch:
  Robinhood's RPC allows 10,000,000 blocks per log query with one value in each filter position but
  only 100,000 when any position is a list, so a list of both addresses would fail a quote's search
  on its first query. Kept receipts are keyed by the vaults read. A root vault can record a quote
  again in a later wave, so a reader with one searches again when none of a quote's kept payments
  is the one a listing shows, and keeps what it finds beside them. How far a search that found none
  went is kept per listing log index for a reader with a root vault, so it never skips a payment at
  another index that was dropped before it was kept; a reader of the per-quote vault alone keeps one
  search for every index, as before. With a root vault, a quote's search is up to 64 rounds of two
  log queries (128 queries), and a quote paid nowhere costs two to four a time. The first start
  after upgrading with a root vault drops the receipts and quote payments kept for the per-quote
  vault alone (they lack the root vault's logs), so each is read again once, with both vaults'
  logs, as listings need it: a one-time burst of chain reads, paced like any other, after which
  they are kept again. Nothing in this client pays the root vault, and no price, quote, payment or
  checkpoint changes.
  `vendor/ant-listings` is darwin-listings 0.4.0. Readers that aren't updated (older
  darwin-listings, older CLIs, other indexers) will report root-paid listings and upload proofs as
  unpaid until they update. A census test (`every_payment_reader_reads_the_vault_set`) lists every
  reader of payments. It is tested against darwin-node 0.23.0+ds.17 (`0deb787`, the revision its
  tests pin). Its notes are `release-notes/v0.3.11+ds.3.md`, which say how to go back to
  v0.3.11+ds.2.
- `v0.3.11+ds.2`: ant-cli's version is 0.3.11+ds.2 (ant-core stays 0.13.0). It changes how
  uploads pay and resume, with prices and quotes unchanged: upload checkpoints in a format of their
  own (below), one wallet's small payments shared in waves of up to 64 records, paid proofs kept
  until stored and paid again at most once, pointer writes paid only when 5 of the 7 quote, and the
  listings reader's log queries sent to Robinhood Chain's RPC first. It is tested against
  darwin-node 0.23.0+ds.17 (`0deb787` on darwin-node's main), whose full nodes decline to quote a
  pointer they don't hold, which its pointer-write check counts. Its notes are
  `release-notes/v0.3.11+ds.2.md`, which say how to go back to v0.3.11+ds.1.
- `v0.3.11+ds.1`, the first published release: ant-cli's version is 0.3.11+ds.1 (ant-core stays
  0.13.0; library users take it by the tag, README "Rust Library API"). It is tested against
  darwin-node 0.23.0+ds.16 (node release 1a, `1315dcc` on darwin-node's main), the first node
  release that declines a busy browser session quickly. Everything below is in it, apart from what
  v0.3.11+ds.2 and v0.3.11+ds.4 bring; its notes are `release-notes/v0.3.11+ds.1.md`.
- Releases: `.github/workflows/release.yml` publishes `darwin-linux-x64.tar.gz` and its
  `SHA256SUMS.txt` for a `vX.Y.Z+ds.N` tag a person pushes, only after the tagged commit's Test run
  (the end-to-end and browser tests) and its Build run from the push to main both succeeded, and
  after approval in the `release` environment, which the workflow first checks exists and asks for
  approval. The archive is that Build run's artifact, checked against its sums, with a `darwin`
  that reports the tag's version and the tagged commit. `scripts/check-workflows.sh`, run by Build
  and Test and tested by `scripts/test_check_workflows.sh`, fails if the workflows lose that order
  or a run could succeed without running every pin. A release's notes are a fixed text, then the
  tagged commit's `release-notes/<tag>.md` when it has one. The `darwin-linux-x64` artifact every
  push uploads is CI output, not for deployment.
- The default network is ours: Robinhood Chain (chain ID 4663), with the seeds, token, vault and
  RPCs bundled in `ant-core/resources/`.
- Size-aware payments: a record's paid quote receives 3 × its price × the record's weight,
  rounded up, the weight being the vendored `pricing::record_weight` of its data type and the size
  class of its bytes (a full chunk weighs 1 and pays 3 × its price, as before).
  `SingleNodeQuotePayment::from_quotes` and the browser's `select_storage_quote` and
  `verify_storage_quote` take the weight; `verifyStorageQuote` takes an optional chunk length and
  pays a full chunk's amount without it. `chunk_put`, the upload engine and `pointer_put` pay by
  the record's class; `pay_for_storage`, which is given a size and no bytes, pays a chunk at a full
  chunk's amount, which every node accepts. The cost estimate prices each chunk paid on its own by
  its class, merkle leaves at a full chunk's price. A quote's price is checked against a band, from
  `calculate_price` of the smallest weight's share of its committed key count to
  `calculate_price` of the count, in place of the exact price, in native, merkle and browser quote
  checks alike.
- Settlement version 2 (`CURRENT_SETTLEMENT_VERSION`, with `MIN_SUPPORTED_SETTLEMENT_VERSION`
  still 1): the client declares it on every quote request, and nodes at version 1 answer
  `StorerUpdateRequired` and are skipped before anything is paid. The unversioned quote retry, on
  the single-node and merkle paths, is gone: a node asked without a version quotes as for version 1
  and would refuse the weighted payment made on that quote. A node that can't decode a versioned
  request is a peer that didn't quote.
- The browser core's quote requests are `chunk_protocol` frames at `BROWSER_PROTOCOL_VERSION`
  whose `QuoteRequestV2` declares settlement version 2, so a node that prices by size quotes them
  by weight and a node that predates it answers `StorerUpdateRequired`, which the core skips.
  `BROWSER_QUOTE_PROTOCOL_VERSION`, one above `BROWSER_PROTOCOL_VERSION`, is for a `quote_chunk`
  with no content alone, sent only to a node that advertises `size_priced_quote` in hello
  (`SIZE_PRICED_QUOTE_CAPABILITY`): a node that doesn't can't parse such a frame and closes the
  channel, dropping any requests in flight on it. JavaScript passes `chunk_length` to
  `verifyStorageQuote` only for a quote obtained by such a `quote_chunk`. A `quote_chunk` at that
  version that ends in a closed channel or an `invalid_request` answer (how darwin-node
  0.23.0+ds.17 and older refuse a version they can't parse) fails as `unsupported_version`, with
  no quote, so the node is skipped, as a native client skips `StorerUpdateRequired`.
- The tests run darwin-node 0.23.0+ds.18 (`81dbac7`), node release 2, which prices records by
  size; `vendor/ant-protocol` is its copy, the same tree.
- `pay_for_storage` and `pay_for_storage_split` quote and plan a pointer at its wire length,
  whatever size is declared, so an interrupted payment's journal restores.
- Upload checkpoints have a format of their own (`DSCK` and a version byte, then msgpack). The
  browser core still hands `on_checkpoint` a string, now the checkpoint's bytes as base64: store
  it as text, as it is, and pass it back to resume. It also takes the bytes as a `Uint8Array` or
  as hex, and reads the JSON text earlier browser clients saved. A native checkpoint keeps its
  paid proofs in `<stem>.proofs`, appended once each. An earlier client stops with an error on a
  checkpoint in this format: finish interrupted uploads with this client before going back to an
  earlier one. A `batch_upload_chunks` receipt (`payments/single/`) keeps the format earlier
  clients read: the marks of a file's chunks paid again are kept apart, in
  `payments/single-marks/`, which they don't read, and the receipt is then named with `_marked` at
  its end. This client stops an upload whose marks can't be read, or are gone from a receipt named
  so, rather than pay for a chunk a third time.
- Payments in DARWIN (`0x511f76A3…`, vault `0xE0f62798…`), priced like Autonomi with a price
  multiplier of 32 in the vendored ant-protocol. Builds before `0995cba` pay the retired test token.
  `ant-core` requires exactly `ant-protocol` 5.0.0, the vendored copy's version, and doesn't compile
  against crates.io's copy; a project that takes `ant-core` by git repeats the `[patch.crates-io]`
  entry from the same tag (README, "Rust Library API").
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
  change, until the next cycle is due, and only once at least 4 of an address's nearest nodes
  pushed copies that pass its checks since the cycle read the nodes (copies the cycle read only add
  to support).
  A node's requests wait at most two requests' timeouts a cycle, so a slow node can't hold the
  cycle open, and a node whose push comes behind its mirror is asked again in the same cycle. A
  node whose feed can't be read is read with `listings.v2` requests meanwhile, its feed asked for
  again hourly with one request (and the next cycle, if it has answered its feed since the producer
  started and leaves that request unanswered); and on a stop the producer ends its watches on the
  nodes. A cycle decides nothing when fewer than 7 nodes answered, or when the census holds under
  three quarters as many nodes as in any of the 10 cycles before, as a read's guard counts the
  nodes it finds. A search for a payment that isn't on the chain goes on, the next time, from the
  last final block it searched. The full listings behind the nodes' entries are fetched once, one
  request at a time to a node, those a quorum names first and the others
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
  An earlier version can run on the same state, and this one after it again: a deferral's time is
  kept as Unix seconds alone, its reason in a row of its own with that time, so a deferral an
  earlier version ended and began again isn't given the reason of the one before (rows kept the
  earlier way are read and rewritten), and each start makes the order `rejected.json` lists its
  rows in, and the deferrals' reasons, match the rows an earlier version left.
  A node that misses 3 polls and isn't found by the lookups that close its leaf is probed before
  it leaves the census (pinged over the producer's connection to it, and if that doesn't answer
  within a second, the connection dropped and the node dialed afresh, not taking
  the word of the 30-minute dial-failure cache), and one that left is probed each cycle for a day
  and is back in the census on its first answer; an id that answered no lookup is looked for again
  when a node names it again. `darwin listings refresh-census --state-dir DIR` has the producer's
  next cycle close every leaf of its census, in place of editing its store by hand. Each request is
  taken once, by the time it holds, even one whose file the producer can't remove: one made no
  later than the latest taken, or than the latest refresh began, is answered.
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
- Chunk and pointer reads may also ask the bootstrap peers whose peer IDs the client knows,
  nearest to the address first: of the 9 nearest the address (all of them when fewer are
  configured), those the read's own lookup leaves among the 9 nearest of what it knows (the
  seeds and the peers the lookup found), or all 9 when the lookup finds no peer
  (`seeds_for_read`). 9 is the nodes' storage retention width, the close group (7) plus the
  storage admission margin (2): a node is responsible for a record, and replication stores it
  there, while the node is among the 9 nodes nearest the record by its own routing table. A
  seed that 9 nearer peers pass over is not responsible for the record, so it isn't asked:
  while the seeds are most of the network they are most of every read's nearest nodes, and as
  other nodes join, each read asks fewer of them, and none of those farther out. Before, every
  read asked the 9 seeds nearest the address from the start, whatever the network's size, so a
  copy a seed kept after it stopped being among a record's nearest nodes was looked for there;
  it is now found only through the nodes nearest the record, which replication copies it to. A
  chunk an upload left farther out, past close-group nodes that failed or were full (up to the
  20th nearest), stays there while the node's disk has room, and is not looked for on a seed.
  A pointer read asks at least 2 seeds once its lookup answers, the nearest of the rest making
  up the number when the filter leaves fewer (`MIN_POINTER_READ_SEEDS`), so 2 seeds can still
  corroborate a state; a chunk read has no floor, its content being checked against its
  address. The trade-off: a pointer read now asks its seeds after its close-group lookup
  answers, not beside it, so each pointer read takes one lookup's time before any seed is
  asked. The close-group part of the read waits for that lookup anyway, and asking the seeds
  before it would ask the ones the filter leaves out.
  `bootstrap_peers.toml` lists all 16 server nodes on QUIC (both nodes of each server, on 10000
  and 10001) with their peer IDs; the CLI and `Client::connect_multiaddrs` hand the selected
  seeds that carry one to reads (`Client::with_bootstrap_peers` for a client built from a node;
  `Network::bootstrap_peers` lists them), and a browser client asks its seeds. Bootstrap
  addresses without a peer ID add nothing.
- A chunk read asks no bootstrap peer before its lookup answers, except as it reads any
  connected peer early. Then it asks those the lookup leaves among the nearest one after
  another in one of its two GET slots, while the close group keeps the other, so a slow or
  silent one holds up only the next, and a chunk is reported missing only once each of them has
  answered. A bootstrap peer that doesn't answer makes the read take its second round, which
  asks it again, as an unanswering close-group node does.
- A pointer read looks its close group up, then asks it and the bootstrap peers that lookup
  leaves among the nearest (all 9 nearest when the lookup fails), each set on its own quorum
  and corroboration (of 9 bootstrap peers, 5 must answer and 2 name the state), a peer in both
  once, and returns the newer of the two states. A state the
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
  that is outside the close group (9 at most; a pointer is at most 5.3 KB). In either set, a final state a majority of it holds is its answer, and two final
  states that no majority holds are a fork, which fails the read unless only the bootstrap peers
  report it and the close group holds a final state. Creating, updating and transferring a
  pointer read it this way first, so they wait the same way; the check an update or a transfer
  makes before paying, whether any peer holds a final state, asks every peer of the close group
  and none of the bootstrap peers.
- `PaymentMode::Single` is the default of the library (`PaymentMode::default()`,
  `Client::file_upload`, `file_prepare_upload`) and of the browser API, so programs built on
  ant-core pay per chunk unless they ask for batches.
- darwin-node's refusal of batch payments (`BATCH_PAYMENTS_REFUSED`, its own sentence) comes back
  typed, as `Error::BatchPaymentsRefused`, when a candidate pool can't fill because a node asked
  refused: before anything is paid, and ranked above a pool that heard no answer in time, so a
  timeout or a short lookup no longer hides it. `PaymentMode::Auto` and the external signer's
  prepare pay per chunk instead, as for a network too small for a batch; a forced
  `PaymentMode::Merkle` fails with it. It is not a settlement refusal and sets no latch.
- The end-to-end tests run against darwin-node: each test of a forced batch payment pins its
  refusal (`BATCH_PAYMENTS_REFUSED` at quote time, the wallet unchanged, nothing stored), and the
  batch arithmetic is tested with no nodes (`ant-core/tests/merkle_unit.rs`). An external signer
  paying only some sub-batches is left without an end-to-end test on purpose, since only nodes
  that accept a batch payment store the paid ones' chunks; the accounting of the chunks no paid
  sub-batch gave a proof (each failed for its missing proof, beside the chunks stored, the counts
  covering the file) is unit-tested with no nodes in `ant-core/src/data/client/file/native.rs`.
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
  library's `ant_core::node` keeps upstream's manager, but for its disk-pressure eviction (below).
- The node manager deletes no node's data. `ant_core::node` loses upstream's disk-pressure
  eviction, for every build: at 500 MiB free on a partition shared by two or more nodes, it stopped
  the node holding the least data and deleted its data directory, with no check that the network
  held its records elsewhere. The daemon's disk monitor now only reports: the fleet health warns at
  1 GiB free or less and is critical at 500 MiB or less, names no node, and says the manager deletes
  nothing (`GET /api/v1/health` keeps `overall` and each check's `level`, `partition` and `summary`;
  `eviction_threshold_bytes` is now `critical_threshold_bytes`, and the eviction candidate and the
  `node_evicted` event are gone). It measures each partition's free space only, no longer walking
  every data directory, and from the daemon's start. A node an earlier manager evicted keeps its
  marker, reports as `evicted` and is never started again; a pin checks that no level of disk
  pressure stops a node, deletes a file or writes a marker, and a census
  (`the_node_manager_deletes_no_node_data`) lists every deletion in the node manager's code.
  Another (`the_node_manager_reaches_outside_its_code_only_where_reviewed`) lists every path from
  that code into the rest of ant-core and of the darwin binary, so a call from the manager into
  code that deletes elsewhere needs review too.
- `darwin-nodes`, a second binary of `ant-cli`, is the storage-node image's node manager, in place
  of Autonomi's `ant` 0.3.9. Only darwin-node's image build ships it, from a darwin-client commit it
  pins (`cargo build --release --locked -p ant-cli --bin darwin-nodes`); this repository's CI builds
  it only to check it (`scripts/check-darwin-nodes.sh`), and never packages it. It has `ant node`'s
  commands the image runs (`add`, `daemon`, `dismiss`, `start`, `status`, `stop`), the same
  registry in `$XDG_DATA_HOME/ant`, REST API and node start arguments (`--evm-network arbitrum-one`
  included), and no reset, no log forwarding and no download source: `add` requires `--path`, and
  its daemon (`ant_core::node::daemon::server::start_image_manager`) serves neither reset nor
  log-forwarding routes and refuses an add naming any other source. The binary carries neither
  "WithAutonomi" nor "logs.autonomi.com". `darwin node` stays off.
- `darwin-linux-x64.tar.gz` from CI carries license notices: `LICENSE-MIT`, `LICENSE-APACHE`,
  `THIRD-PARTY-NOTICES.txt` and `RUST-STD-COPYRIGHT.html` next to `darwin`, like upstream's archives.
- Upstream's installers are removed: `install.sh`, `install.ps1`, the npm packages (`npm/`), the
  winget manifest (`resources/winget/`) and the release-signing key
  (`resources/release-signing-key.pub`). They installed or verified Autonomi's `ant`, not
  `darwin`, and the installers wrote Autonomi's `bootstrap_peers.toml` into the config directory
  `darwin` shares. CI fails if any of them is tracked again. `darwin` is built from source or
  taken from a release.
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
  the address its lookup leaves among the nearest, the census and the read sharing one lookup:
  while the close group shows no final state, the pointer is read as
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
- saorsa-transport is 0.38.2 at least, in ant-core's requirement and in the lock: it reaps a QUIC
  reader task once its connection ends, where 0.38.1 kept every past connection's reader
  allocated for as long as the endpoint lived. A test (`lock_pins`) holds the lock to one copy, at
  0.38.2 or later.
- When storers refuse this client's settlement version (`ClientUpdateRequired`), the error is in
  darwin's own words: the client settles under version X and the network requires at least Y, no
  quote was issued and nothing was charged, and a new darwin is built from
  https://github.com/Project-DSpace/darwin-client (see its README); the browser core says to
  reload the page instead. Before, it repeated the vendored storer wording, which told users to
  run another client's `ant update`. The vendored ant-protocol is unchanged, and tests that model
  a storer's own wording keep it.
- A client dials its seeds in a random order (`in_random_order`): the `darwin` CLI after the
  peers it cached, and a library client built from seeds, so client starts spread over every
  seed instead of landing on the first few listed.
- A browser client keeps sessions with 3 of its seeds, not all of them: `connect()` dials 3 in
  a random order, leaving out those it holds off, replaces each that fails or declines with the
  next, and takes 3 more only when lookups through those fall short. Lookups find every other
  node through them, and a seed's session stays open until the node closes it for idleness, so
  a seed that holds a record is read on its open session.
  A seed that declines a session because it is busy is held off for 15 seconds, not the 30
  minutes of a failed dial (ported from upstream ant-client #225): the browser counts a dial as
  declined when the association fails within 3 seconds of its ICE checks starting, before ICE
  connected (a full node's transport answers the check with an error), or when the node closes
  it right after DTLS or the handshake. A DTLS failure after ICE connected (another node at the
  address) and every other failure keep the 30 minutes. `BrowserNetwork::refused_peers` lists
  the peers held off, with the time left; a read whose possible holders declined waits for the
  first of them to come back, up to 3 times, and then fails with "the nodes that may hold chunk
  ... are busy; try again shortly", not as a missing chunk. A pointer read too few of whose close
  group answered, some of the rest held off, fails at once with "the nodes that may hold pointer
  ... are busy; try again shortly" in place of a shortfall; it does not wait for them to come
  back. With every seed held off, `connect()` says how many are busy.
- The library's default chunk cache (`ChunkCache::default`, every client's) holds at most 1,024
  chunks and an eighth of the memory free for use when the client is built, at least 4 MiB and
  at most 256 MiB (`default_cache_bytes`); before, up to 1,024 full chunks, 4 GiB, whatever
  the memory. `ChunkCache::with_byte_budget` builds one with other bounds, and `ChunkCache::new`
  one bounded by chunks alone, as before.
- A client keeps which node served each chunk it read in the last 15 minutes (1,024 chunks at
  most). A read of a chunk no longer in the chunk cache asks that node first, and looks the
  chunk up only once the node answers without it or hasn't answered within the 1-second hedge
  delay of early reads (`read_from_holder`); a node that no longer serves it is forgotten, and
  what it answers never makes a chunk missing.
- `darwin-nodes` caps its own log: `daemon run --log-path PATH` writes `<PATH>.<UTC time>.log`,
  a new file every 10 MiB or hour and on every start, and after each new file deletes the oldest
  closed files of the family (the daily files earlier builds wrote included) until it holds at
  most 50 MiB with the new file full, and closed files older than a month. With 1 GiB free or
  less on the log's disk (the nodes' full line, and the manager's own low-disk warning level) it
  deletes its closed files and writes only warnings and errors, counting the lines it leaves
  out, and writes one line saying how many once space returns. The erasure census lists its two
  deletions of log files.

## [Unreleased]

### Changed
- `install.sh` puts `ant` on `PATH`, as `install.ps1` already did on Windows, so `ant --version`
  works in a new terminal straight after installing (#194). When `INSTALL_DIR` is not already on
  `PATH` it adds a guarded line to `~/.profile`, to the user's existing bash startup files, to
  `~/.zshenv` when zsh is installed and to fish's `conf.d` when fish is, and lists each file it
  changed. A directory whose name contains `$`, a backtick, `"` or `\` is not added, because
  shells can run part of such a PATH entry as code (macOS login shells re-read `PATH` through
  `path_helper` without escaping it). The installer says so and prints an escaped line for the
  current shell instead. A name with `:`, which separates `PATH` entries, can't be added at all,
  and an install directory containing a newline (in `INSTALL_DIR`, or in the current directory
  for a relative one) is rejected before anything is installed.
  `--no-modify-path` or `ANT_NO_MODIFY_PATH=1` (also honoured by `install.ps1`) restores
  the old print-the-line behaviour. The macOS default install directory moves from
  `/usr/local/bin`, which is root-owned without Homebrew so the install failed without `sudo`, to
  `~/.local/bin`, matching Linux. If another `ant` is already on `PATH` — an earlier macOS
  install in `/usr/local/bin`, or an unrelated program such as Apache Ant — the installer says
  so, since it may shadow the new one.
- In the browser, a complete download's per-chunk progress names the node that served the chunk
  and the GETs it cost: `Downloaded chunk 3/147 from <peer hex> after 1 attempts`, or
  `from cache after 0 attempts` when the client's chunk cache answered it (V2-1872). Read
  investigations could previously see only `Downloaded chunk n/total`. The count covers every
  GET the chunk cost — the deferred retry rounds that found nothing included, and the GETs of a
  fetch shared with a concurrent download of the same chunk — so a costly retry shows up rather
  than being reported as the succeeding round alone. The
  `Downloaded chunk n/total` prefix is unchanged, so startup probes that match on it still work
  (#249).

## [0.3.12] - 2026-10-22

### Changed (breaking — `ant-core` browser API)
- In the browser, `createPointer`, `updatePointer` and `transferPointer` take their callbacks as
  an options object, `{ onPrepared, onSubmission, onPaid }`; a bare `onPaid` function as the last
  argument is no longer accepted. In `ant-core`, `ManifestInput::create` returns a typed
  `ManifestInputError` instead of a `String` (#230).

### Added
- Uploads report the file's SHA-256 (V2-1564). `ant file upload` prints it (and `--json` adds
  `sha256`); it is computed in the same read that feeds the encryptor, so it costs no extra pass.
  Manifest entries (ADR-0006) gain an optional `sha256`: uploads record it in the upload history
  and in `ant manifest create` manifests, `ant manifest show` prints it, and
  `ant manifest download` checks every downloaded file against it, failing the entry (and leaving
  nothing at the target) on a mismatch. Entries without it encode exactly as before, and older
  readers ignore it. In `ant-core`: `FileUploadResult::sha256`, `PreparedUpload::sha256`,
  `DataUploadResult::sha256`, `ManifestEntry::sha256` and `ManifestError::Sha256Mismatch`.
- Browser manifest export and pointer payment recovery (ADR-0007, proposed; V2-1478, V2-1354).
  `createManifest` and `createFileLink` build the same `.ant` manifests and `ant://` links as the
  CLI, which reads them unchanged. A pointer write can checkpoint its signed state and verified
  plan through `onPrepared` before anything is paid, and `onSubmission` reports each transaction
  the wallet broadcasts. If the page is lost between payment and receipt, `recoverPointerPayment`
  rebuilds the paid proof from that checkpoint and the transaction hash without paying again, and
  `storePaidPointer` stores it (#230).

### Changed
- Reads spread their first request for a record across the whole close group, instead of every
  client asking the nearest holder first, so many clients reading the same data no longer pile
  onto one node (ADR-0023 in `ant-node`; V2-1508, #225). Pointer reads already asked the whole
  group and are unaffected.
- In the browser, a node that declines a connection because it is full is skipped for 15 s
  rather than the 30-minute dial-failure cooldown, and a read whose holders are all declining
  waits them out (up to three times) and then fails with "the nodes that may hold chunk … are
  busy; try again shortly" instead of reporting the record not found. Native reads are
  unchanged. `BrowserNetwork` gains `refused_peers()`, with a default that reports none (#225).

### Security
- `rustls` 0.23.46, for RUSTSEC-2026-0346, -0347, -0348 and -0349 (V2-1595, #232). Of the four,
  only RUSTSEC-2026-0349 applies to `ant`'s configuration: an on-path attacker could make later
  resumed connections to a server name use classical-only key exchange.

## [0.3.11] - 2026-10-16

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
- File manifests, `ant://` links and an upload history (ADR-0006, V2-1478). A manifest is a `.ant`
  file listing a set of files together with what is needed to download them (a public address or
  an embedded DataMap per entry). It is never stored on the network, so it can be kept or shared
  as a file or as an `ant://manifest/...` link. `ant manifest create` uploads files or
  directories and writes the manifest (`--public` also stores each DataMap chunk, `--public-file`
  and `--embed-public` add files that are already public by address, `--link` also prints the
  link). `ant manifest list` shows every recorded upload; `show` and `link` take a `.ant` file, a
  link or an upload id; `export` writes a manifest out as a `.ant` file, and `--compact` swaps
  embedded DataMaps for public addresses (publishing DataMaps that are still private is paid and
  asks first); `download` extracts the files, all of them or those named with `--select`. Paths
  are checked for portability and containment before anything is written. `ant file upload` now
  records every upload in the history (the record id is printed, and `manifest_id` is added to
  `--json`), and `ant file download` accepts an `ant://<hex>` link and, with `-o` omitted, names
  the output after the address (it was an error). In `ant-core`: the `ant_core::data::manifest`
  module (types, encode/decode, links, builder, extraction, history, compaction), and
  `Client::file_upload_with_visibility_and_progress` is now public. In the browser:
  `parseManifestLink` and `decodeManifest`, whose entries feed `downloadPrivateFile` and
  `openPrivateFile`. (#219)
- In the browser: `BrowserFileReader.pipeTo(writable, { start?, end?, signal?, onProgress? })`
  for public and private files streams a file of any size to a `WritableStream` (for example one
  in the origin private file system) with backpressure and cancellation, holding at most 32 MiB
  of plaintext at a time. `downloadPublicFile` and `downloadPrivateFile` take a trailing
  `{ maxMemoryBytes?, signal? }` argument: a download over the memory budget fails before any
  transfer and points to `pipeTo`, and `signal` cancels it. Files over 1 GB are no longer
  rejected, file offsets are 64-bit throughout browser reads (they were 32-bit on wasm32), and
  manifest validation accepts up to 262,144 chunks. Chunk positions and decryption now come from
  `self_encryption::DataMapIndex` (`self_encryption` 0.36.2). (V2-1398, #214)

### Changed (breaking — browser WASM API)
- `PublicFileDescriptor.size` is `u64` rather than `usize`, and the WASM exports that carry sizes
  and offsets change with it. Existing JavaScript call forms keep working, but sizes and offsets
  are now validated as non-negative safe integers: `readRange` rejects fractional, negative,
  missing or imprecise arguments that were previously coerced (an omitted length read nothing,
  and `1.5` read from byte 1). A DataMap whose range reads are rejected, such as one with
  non-contiguous indices, now fails at `openPublicFile`/`openPrivateFile` instead of opening with
  read-ahead off, and `BrowserFileReader.close()` releases that reader's records without
  clearing the client's shared chunk cache. Native `data_download_range` is unchanged. (V2-1398,
  #214)

### Changed
- A pointer read that meets a final state returns the final state a majority of the close group
  holds, rather than the merge winner, and asks the whole group until one is found. Two
  different final states are a fork only the owner can make, by racing them to different nodes;
  with no majority on either, the read fails with `Error::PointerForked` instead of guessing.
  Updating a final pointer is refused with `Error::PointerFinal`, before anything is paid.
- Concurrent reads of the same chunk share one fetch per `Client`, native and WASM alike.
  `chunk_get`, `chunk_get_from_closest_peers` and the observed download path send one GET per
  address while a fetch is in flight; later callers wait for its result, and nothing is kept
  after it ends, so caching stays the chunk cache's job. A failed shared fetch fails every waiter
  with the same error and each caller's own retry policy still applies; if the caller running the
  fetch is dropped, a waiter runs it instead. Downloads with diagnostics enabled neither share
  nor lend a fetch, so their records describe only their own GETs. This removes duplicate GETs
  where reads overlap, such as parallel ranged reads of one object (part boundaries, and every
  part resolving the same DataMap chunks): on a 25-node devnet, a cold 64 MiB download through
  antd's S3 gateway went from 82-99 to 46-49 GETs received by the nodes, with the same bytes.
  No signature changes; the browser's read-ahead readers share fetches too. (V2-1433, #218)

### Security
- `quinn-proto` is bumped from 0.11.15 to 0.11.19 in `Cargo.lock`, clearing RUSTSEC-2026-0338,
  0339, 0340, 0341 and 0342. Nothing in this workspace builds `quinn` or `quinn-proto` (they
  appear in the lockfile only as `reqwest`'s optional dependency), so the shipped binaries were
  not exposed and are unchanged; the bump clears the Security Audit job. (V2-1527, #227)

### Internal
- CI: release-promotion PRs (`chore(release):` titles from `rc-*` branches) are exempt from the
  `linear-link` and `pr-template` checks. (V2-1092, #181)

## [0.3.10] - 2026-10-08

### Added
- Licence texts and third-party notices now ship with the CLI. The release archives and the npm
  platform packages gain `LICENSE-MIT`, `LICENSE-APACHE`, `THIRD-PARTY-NOTICES.txt` (generated
  from `Cargo.lock` for each target, with the licence, copyright and notice files of every
  statically linked crate, OpenSSL and other bundled C code) and `RUST-STD-COPYRIGHT.html`; the
  npm meta package gains the two licence files. The `ant` binary is unchanged, and `ant update`,
  `install.sh` and `install.ps1` pick entries from the archive by name, so the extra files do not
  affect them. (V2-1392, #213)
- In the browser: `BrowserFileReader` reads ahead during sequential reads, so media keeps
  streaming while records are still being discovered. A sequential read fetches up to four
  records of the next 32 MiB in parallel (a streaming reader also fetches the last record, where
  a video's index usually is), within bounds that do not trust DataMap metadata: at most 24
  records held or in flight across all readers of a client, and speculative GETs never take more
  than half of the read budget. `openPublicFile` and `openPrivateFile` take an optional third
  argument `{ streaming: true }`; existing callers are unaffected. Read-ahead records are kept
  out of the shared chunk cache. (V2-1355, #209)

### Changed
- Native and WASM reads: once a record's early-GET allowance is used up, a hint with fewer than
  `CLOSE_GROUP_SIZE` attempted peers nearer the target stays eligible, so a slow lookup that
  finally names a record's actual holders is acted on at once instead of after discovery ends.
  Speculative GETs are capped at twice the allowance, and the two-GET limit, hedge delay and
  absence rules are unchanged. (V2-1355, #209)
- In the browser: DHT lookups query six peers per round rather than three
  (`BROWSER_LOOKUP_ALPHA`). In headless Chromium against mainnet, the mean cold read of a 612 MB
  video's records dropped from 11.5 s to 6.1 s and quoting an 8 MB upload from 155 s to 120 s, at
  the cost of about 40% more connections. Native lookups, the grace period and the dial timeout
  are unchanged. (V2-1357, #211)

### Fixed
- A pointer read could return the state a successful write had replaced: a write lands on five
  of the seven peers, and three peers replaying the older state could answer first. A read now
  keeps asking while a state that would replace its answer has been named by too few peers, until
  that state is backed by two peers or the group is exhausted. A newer state only one peer names
  still never wins, so no single peer decides what a pointer says. (V2-1363, #208)
- Pointer write and read quorums are counted over the configured close group rather than over
  however many peers a lookup returned, so a lookup that comes back short is a shortfall instead
  of a completed write or read. One peer answering that the pointer "had moved on" no longer ends
  a write that other peers stored, and a native write no longer drops the proof it paid for: a
  read confirms the move first, any other refusal is final only when no peer stored the record
  and a second peer refused as well, and a node's own storage error (a full disk, for example) is
  not a refusal. Anything short of that is retried with the proof already paid for. (#208)
- In the browser: `createPointer` and `updatePointer` no longer call the wallet for a write that
  cannot land. While nodes are being upgraded, some of a close group do not advertise pointers
  and the browser never sends them one; before quoting, the client now asks each member whether
  it would take a pointer write and refuses once a write quorum cannot be reached. A node that
  cannot be asked within 20 seconds is not counted against the write. A paid state is also
  stored when the page's `onPaid` callback never settles (after 30 seconds), and
  `ant pointer resolve` prints the kind when the target is not a chunk. In `ant-core`: the `BrowserNetwork`
  trait gains the provided method `accepts_pointer_writes`, which answers `true` by default, so
  existing implementations compile and behave as before. (#208)
- In the browser: connections the browser reports `failed` or `closed` are never reused, and a
  failed connection now fails all its lanes at once, so waiting requests are retried elsewhere
  instead of waiting out their 10 s response deadline. Safari (WebKit) leaves a lost
  connection's DataChannels reading `"open"`, which made downloads and media playback stall for
  minutes. (V2-1355, #215)
- In the browser: ICE gathering is taken one connection at a time, page-wide. WebKit allows 256
  WebRTC UDP sockets per page and silently closed established connections past that, and
  connections gathering at once opened 12-30 sockets each instead of 2. (V2-1355, #216)

### Internal
- CI: the browser integration job builds the pinned `ant-node` without `-D warnings`, moves the
  pin past its Rust 1.99 fix (the job had failed on every PR since stable moved to 1.99), refuses
  to start unless the sibling checkout is the pinned revision, and fails a run in which any test
  was skipped. (V2-1399, #217)

## [0.3.9] - 2026-10-01

### Added
- Pointers: a mutable reference to a chunk or to another pointer, signed by an owner key that can
  never change (ADR-0016 in `ant-node`). Every state is paid for; reads are free. The owner key
  is a 32-byte seed kept in a file only its owner can read (`0600` on Unix), and losing it means
  the pointer can never be updated again. New CLI commands: `ant pointer keygen --output <FILE>`
  (never overwrites an existing file), `ant pointer address --key <FILE>` (needs no network),
  `ant pointer create --key <FILE> <TARGET> [--kind chunk|pointer]` (refused before paying if the
  pointer already exists), `ant pointer update`, `ant pointer get <ADDRESS>` and
  `ant pointer resolve <ADDRESS>`, which follows a chain of pointers to the target at its end. In `ant-core`:
  `Client::pointer_create`, `pointer_update`, `pointer_put`, `pointer_get` and `pointer_resolve`,
  `pointer_sign_create` and `pointer_sign_update` for external payers, `prepare_pointer_payment`
  and `pointer_put_paid` for a proof paid outside this client, `ChunkPaymentPlan::proof` and
  `MAX_POINTER_RESOLVE_DEPTH`. An update signs one past the counter the network serves, each
  state is paid under its own identifier, and a read needs two peers to agree. In the browser:
  `getPointer`, `resolvePointer`, `createPointer`, `updatePointer` and `storePaidPointer` on
  `BrowserNetworkClient`, and `pointerAddress(seed)`; the browser only asks nodes whose HELLO
  advertises `pointer_protocol`. Additive: a client that never calls the pointer API sends
  nothing new. (V2-1277, #200)
- In the browser: the seven mainnet WebRTC Direct bootstrap addresses (certificate-pinned) are
  bundled in the `webrtc` list of `bootstrap_peers.toml` and exposed through WASM, so a browser
  client can connect to mainnet without supplying seeds; explicit seeds and profiles are still
  honoured. The native CLI reads the `quic` list and is unaffected. (V2-1305, #206)

### Changed (breaking — browser WASM API)
- `BrowserNodeClient` and `BrowserNodeSession` are no longer exported from the production WASM
  build: `BrowserNetworkClient` is the single browser networking client. Use it for
  authentication, discovery and transfers; a one-seed client supports authenticated HELLO checks.
  `BrowserNetworkClient.connect(expectedPayment)` now authenticates through the pool that later
  transfers use: at most four seed attempts run concurrently, the first authenticated seed that
  passes the capability and expected-payment checks makes the client ready, and discovery starts
  with the ready seeds and takes later candidates as they arrive. Rejected seeds cannot re-enter
  the pool through read or discovery fallback, and later callers can retry transient failures
  with bounded backoff. Native Rust APIs and the high-level SDK overloads keep their
  signatures. (V2-1305, #206)

### Fixed
- In the browser: a closed RPC session or failed response inbox no longer counts as a live
  connection, even while the DataChannel still reports open. The dead session is retired before
  admission is retried, so recovery waits for a fresh connection instead of uploaders spinning on
  a closed session for 400 seconds (the reproduction now completes in about 340 ms). (V2-1305,
  #206)
- Faster cold reads, native and WASM: the shared read scheduler allows a second early GET after a
  one-second stall while keeping the two-GET bound, deduplication, fallback allowance and fatal
  integrity errors. Browser cold-start measurements on mainnet (three alternated pairs) put the
  median connection time at 2.11 s instead of 5.27 s and the first chunk, including connection,
  at 18.6 s instead of 28.5 s. In the browser, queued lanes recheck the shared failed-dial cache
  instead of repeating a failed connection attempt, and early hints require authenticated
  connections. (V2-1305, #206)

### Internal
- CI: repo checks run on pull requests only; the duplicate `push` runs on `main` and `rc-*` are
  dropped from `ci.yml` and `adr-governance.yml`. (V2-1353, #207)

## [0.3.8] - 2026-09-24

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
- `ant-core` builds for the browser as WASM and shares the native client's own routing, quote and
  witness policy, content addressing, self-encryption, DataMap encoding, payment preparation and
  per-record storage policy, rather than keeping a second implementation (ADR-0004, V2-803).
  `ant-core` gains a `native` feature (on by default, so ordinary consumers keep the existing
  API; filesystem, daemon and node code sit behind it) and a `browser-wasm` feature, built with
  `--no-default-features --features browser-wasm`. The browser client speaks browser protocol v5
  over WebRTC Direct with the shared post-quantum transport session, resolves public downloads
  and bounded range reads of ordinary native-compatible DataMaps, and runs the same batched and
  Merkle payment coordinator as native uploads, with prepared and paid checkpoints, bounded
  transfers and recovery. Browser recovery tells a verified failed payment from an unknown
  outcome, keeps durable evidence, never treats an unknown outcome as permission to pay again,
  and blocks new wallet submissions after the client is closed; confirmed Merkle batches stay
  storable when a later payment or reconciliation fails, with the partial progress and spend
  kept. See [`README.md`](README.md) and
  [`docs/portable-client-recovery.md`](docs/portable-client-recovery.md). (#186)
- In the browser: `BrowserNetworkClient.uploadRecords(batch, …)` quotes, pays for and stores one
  batch of caller-staged, content-addressed records, so a file larger than the origin's
  IndexedDB quota can be uploaded in storage-bounded windows, each with its own payment and
  checkpoint scope (the coordinator picks single-node or Merkle payment per batch under the
  native rules). `downloadPrivateFile` and `openPrivateFile` read a file from the canonical
  MessagePack DataMap its holder kept, the same bytes as a native `.datamap` file, resolving
  nested DataMap records from the network. Every upload result now reports `paymentMode`
  (`single` or `merkle`), like native `payment_mode_used`. (V2-1285, #203)

### Changed (breaking — browser client)
- Browser protocol v5 requires matching nodes, and the browser-WASM bindings change, so consumers
  such as the browser SDK must refresh their generated bindings together with the client. Native
  QUIC behaviour and the native entry points are unchanged. (V2-803, #186)

### Changed
- `bootstrap_peers.toml` is now a shared resource (`ant-core/resources/bootstrap_peers.toml`,
  ADR-0005) with a `quic` list of native multiaddresses and a `webrtc` list of complete WebRTC
  Direct multiaddresses; release packaging still installs it under the same filename, and legacy
  `peers = [...]` files stay readable. `-b/--bootstrap` accepts QUIC multiaddresses such as
  `/ip4/1.2.3.4/udp/10000/quic`, including an optional `/p2p/<peer-id>` pin that is kept all the
  way to the transport; the old `ip:port` form is still accepted. In `ant-core`: the new
  `network_defaults` module (`bundled_bootstrap_seeds`, `parse_bootstrap_seeds`,
  `parse_quic_seed`) and `config::load_bootstrap_multiaddrs` / `resolve_bootstrap_multiaddrs`
  alongside the existing `SocketAddr` functions. (V2-803, #186)
- `ant update` no longer replaces the binary when `ant` was installed by a package manager. It
  still reports whether a newer version is available, then prints the command that will install
  it (`npm update -g @withautonomi/ant`). Self-replacing an npm-managed binary left npm's
  metadata describing a file that was no longer there, so the next `npm update` silently rolled
  the user back.

### Fixed
- Uploads no longer fail outright when the public RPC briefly answers the fee estimate with a 429
  or `-32000 context deadline exceeded` (`Could not get current gas price: ...`). The fee read in
  the payment journal's `prepare_payment` now retries, as the released client already did through
  `send_transaction_with_retries`; native and WASM uploads are both covered. Picked up by pinning
  `evmlib` 8ad5ec0 and `ant-protocol` 17949f8. (V2-1288, #204)
- Native uploads persist the signed payment transaction before it is broadcast and reconcile it
  on retry: the journal is retained while the outcome is unfinalised or cannot be observed, a
  verified finalised replacement clears the attempt for a fresh payment, and a same-intent
  replacement recovers its settlement receipt. A payment whose outcome is unknown is not paid
  again, and a journal signed in the current call and rejected with `nonce too low` (a stale read
  from a lagging RPC replica) is discarded and prepared once more, since nothing was sent.
  (V2-803, #186)

### Internal
- Dependency pins: `ant-protocol`, `saorsa-core` and `saorsa-transport` advance to the V2-834
  merges (pins only, no source change; the three must name the same revisions so the graph keeps
  a single copy of each). (V2-834, #202)

## [0.3.7] - 2026-09-16

### Added
- Quote requests declare the settlement version the client pays under (`QuoteRequestV2` and
  `MerkleCandidateQuoteRequestV2`, on both the single-node and the merkle path), so a client
  settling under superseded rules is refused before it pays. A merkle batch pays on-chain before
  any storer sees a PUT and merkle receipts are not refundable, so without this the refusal came
  after the money was gone. `Error::ClientUpdateRequired` is terminal: the upload aborts before
  payment and shows the storer's own wording, which tells the user to run `ant update` and that
  nothing was charged. `Error::StorerUpdateRequired` is not: the storer is the old side, so the
  upload quietly uses other peers, and fails for lack of quotes (still before payment) if too few
  remain. A corroborated refusal is latched for the run, so the wave-batch payment path
  (`prepare_chunk_payment`, `batch_pay`) and an external signer are also stopped from paying by
  another route, and a refusal in flight is no longer cancelled when a sibling candidate pool
  fails first. When this landed the minimum and current settlement versions were equal, so
  nothing refused the build yet; the gate takes effect on the first settlement bump that makes
  the minimum load-bearing. (V2-975, #171)
- `ant file download --download-diagnostics <PATH>` writes an opt-in JSONL sidecar (schema v4) of
  the download for troubleshooting: request IDs, the local client peer ID, expected and
  authenticated peers, transport source and route, timings, DHT context, retries, outcomes and
  concurrency snapshots. The records go through a bounded, non-blocking channel; with the flag
  absent no file, channel or writer is created and ordinary downloads are unchanged. In
  `ant-core`: `spawn_download_diagnostics_writer`, `DownloadDiagnosticsRecord`,
  `DownloadDiagnosticsOutcome` and `DownloadDiagnosticsSender`. (V2-903, #193)

### Fixed
- A command-line file upload that stops because storers refused a merkle payment now says so.
  The failure used to read `N chunk(s) short of quorum after 4 attempts`; it now carries the
  storer's refusal, and an externally unpaid sub-batch is reported as having no proof rather than
  as a refusal. This covers `ant file upload` only: the in-memory `data_put` path still returns a
  bare `Missing merkle proof for chunk <hex>`. (V2-1175, #195)

### Internal
- The test harness builds against `ant-node`'s file-per-chunk `ChunkStore` instead of
  `LmdbStorage`, which had stopped all seven e2e test binaries compiling once ant-core pointed at
  an ant-node carrying that change; the dependency stays on one line so the release tooling can
  retarget it. (V2-1033, #196, #197)
- CI: the PR template check requires one of Linear's closing magic words (`Closes`, `Fixes`, ...)
  rather than accepting a bare issue key or URL. (V2-1161, #191)

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
