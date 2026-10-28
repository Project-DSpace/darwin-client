# Shared client routing and upload recovery

Client portability does not enable nodes in WASM. `saorsa_core::client_routing`
contains the native client report-selection and witness-normalization functions.
The native DHT manager and browser client call those same functions. Node
listeners, routing-table maintenance, admission services, and background tasks
remain behind the native feature.

Browser FIND_NODE responses optionally carry the complete serialized native peer
record, preserving address tags and publish sequence. The browser converts that
record to `DHTNode` before selecting reports or assembling witness views. A peer
without a WebRTC endpoint still appears in witness votes; only the dialing
adapter filters it out as a connection candidate. Legacy responses without the
record continue to decode, with their reduced metadata.

`data::client::upload_state::UploadState` owns verified single-node payment plans
and confirmed proof bytes keyed by content address. Native payment finalization
and browser confirmation share its transition and proof builder. Native disk
receipts import their proofs into the same state for reuse. Quote expiry and
future-clock tolerance use the native constants on both platforms.

The shared coordinator preflights every staged record's bytes, length, and
content address before payment. It reads one record at a time and retains the
adapter's staging session through storage and recovery.

Before invoking a wallet, the coordinator checkpoints the exact payment intent
as an unresolved attempt. Browser adapters journal submission evidence and the
raw wallet result before validating it. An interrupted or malformed result
cannot trigger another submission: recovery observes the original transaction
through the wallet's separate `recover`/`recoverMerkle` methods. Ethers and wagmi
check the application-owned chain, vault, transaction calldata, and confirmed
receipt. Without usable transaction evidence the attempt remains unresolved.
Native adapters without a recovery observer also stop on an unresolved attempt;
this change does not add automatic chain reconciliation to native wallets.

After confirmed payment, a retry refreshes peers and quotes but attaches the
original paid proof to current PUT targets. Missing per-quote transactions fail
confirmation atomically.

Checkpoints contain plans, proofs, and wallet evidence, not file bytes or wallet
secrets. The WASM adapter binds them to record addresses/sizes and payment-network
identity. Raw paid WASM uploads require an awaited checkpoint persistence
callback. The SDK persists checkpoints to IndexedDB by default; an application
can replace that storage with `onCheckpoint`. After a reload,
`storedUploadCheckpoints()` retrieves the saved journals; reselect the original
input and pass its checkpoint to `upload({ checkpoint })`. The page-owned
`resumeUpload` handle additionally retains staged input and settlement observers.
Applications remain responsible for retaining the original input across reloads.
An unresolved checkpoint alone is not evidence that a transaction confirmed.

`data::client::upload::Client::upload_records` coordinates native memory uploads,
native spilled files, and browser buffered/staged uploads. It selects Auto,
Single, or Merkle payment with native thresholds, partitions batches, pipelines
single-node waves, and applies the same store retry and recovery policies.
Platform adapters supply bytes, wallet settlement, checkpoint persistence, and
progress callbacks. Browser transport admission checks remain in its adapter.

Prepared Merkle checkpoints preserve the exact salted tree and payment request;
confirmed checkpoints retain native tagged proofs. Native file checkpoints are
atomically persisted under a file/payment-network scope and protected by a file
lock. Browser adapters use the awaited persistence callback described above.

A checkpoint starts with `DSCK` and a format version byte, then its body in
msgpack, with proofs as byte strings. A client from before the format parses
the whole checkpoint as msgpack, fails, and stops with an error rather than
paying again. A native checkpoint (`<stem>.msgpack`) keeps its paid proofs
apart, in `<stem>.proofs`: `DSPF` and a version byte, then one record per
proof (its 32-byte address, a 4-byte little-endian length, the proof, and the
first 8 bytes of a BLAKE3 hash of the three; a length of 0 forgets the
address's proof), appended once each rather than rewritten at every step. A
torn last record is left out on reading and cut off before the next append.
The `.msgpack` records the proof file's length at each save; a checkpoint
whose proof file is missing, or shorter in whole records than that, is
refused with an error that names it and says to keep it, rather than opened
to pay for those records again. `upload_checkpoint_files` lists a checkpoint's files (`.msgpack`, `.proofs`,
`.salt`, `.lock`), for servers that remove what ended uploads leave. The
browser's checkpoint is the same format, with its file/payment-network scope
inside, handed to `on_checkpoint` as text: its bytes as standard base64, a
string, as the browser client before it handed its JSON. Store it as text, as
it is (`localStorage.setItem`, a JSON field, an IndexedDB string), and pass it
back as `checkpoint` to resume. An upload also takes the checkpoint's bytes as
a `Uint8Array`, or as hex in either case, and still reads the JSON text
earlier browser clients saved; the next checkpoint saved replaces it. Other
text, such as `Uint8Array.toString()` gives (`68,83,67,75,...`), is refused
with an error that says so, and nothing is paid. `reconcileFailedUploadPayment`
takes and returns the checkpoint the same way. A snapshot is at most 128 MiB
of bytes, counted after its text is decoded. A native checkpoint
in the format before (one msgpack file holding every proof) is migrated when
opened: its proofs are written to a new proof file first, then the new
checkpoint replaces the old one by rename.

Restoring checks every saved plan's quotes against their signatures and the
nodes they name, and its amounts against exactly two recomputations from
those signed quotes: the full amount (three times the median quote), or the
weighted amount for the size class of the plan's own `data_size` (a pointer's
plan at its 5,303 bytes). So a checkpoint saved by a client that pays either
way restores in either. A plan matching neither is dropped and its record
quoted again, unless a pending payment names it: then the whole checkpoint is
refused, and the error names the file and says not to delete it, since it may
hold a payment still to be settled.

Native uploads paying from the client's own wallet share payment waves: a
payment of fewer records than a wave (64) joins the wallet's open wave, and
the wave pays every member's quotes in one transaction, still one in flight
per wallet. The wave closes once every member has journaled its place, and it
is full, or holds every upload the client has in progress, or 500 ms have
passed since it opened. Each member's journal names the wave before anything
is signed for it, and saves the signed transaction before it is sent; the
transaction is also written whole to `payments/waves/<id>.json` until every
member has saved it, and never removed by age, since a member's checkpoint
that names the wave is kept while its payment is pending. No member is quoted
again before the wave ends: a resume reconciles the wave's transaction from
that file, else from the member's own copy, and a member left out of the wave
starts afresh. A member whose journal names a wave whose file is gone first
reads its quotes back from the vault: if any is recorded as paid, or the
vault can't be read, its journal is kept and the upload fails rather than pay
again. Each member's payment
record, proofs and reported cost show only its own quotes and its share of
the gas. Waves are per client process: for higher rates, run one wallet per
worker, as the gateway's agents each pay from their own.
The SDK ethers and wagmi providers submit calldata encoded by evmlib and decode
settlement with its canonical event ABI. Custom providers can implement
`payMerkle`; applications using only single-node payments can select `single`.

Content addresses call `ant_protocol::compute_address`. Public DataMap records
use `client_engine::files::public_map_record` for both serialization and address
calculation. Whole-file BLAKE3 checksums retain their separate checksum meaning.

## Protocol definitions used by browser adapters

The WebRTC transport has no payment-policy module. Native and WASM clients
import the same definitions at their original application-protocol layer:

| Concern | Canonical definition |
| --- | --- |
| Close-group size and majority | `ant_protocol::{CLOSE_GROUP_SIZE, CLOSE_GROUP_MAJORITY}` |
| Lookup K, concurrency and iteration grace defaults | `saorsa_core::dht_lookup` (re-exported by `ant_protocol::transport`) |
| Pricing curve | `ant_protocol::payment::calculate_price` (and `calculate_price_legacy`, still accepted) |
| Commitment type, limits, domains, signature bytes, verification and pin | `ant_protocol::payment::commitment` |
| Quote signing bytes and hash | `ant_protocol::evm::PaymentQuote` (from evmlib) |
| ML-DSA public-key size | `ant_protocol::pqc::api::MlDsaVariant::MlDsa65.public_key_size()` |

Browser quote envelopes only translate JSON/hex fields and check that duplicated
envelope fields match their native encoded payload. Browser test-node fixtures
also construct native quotes and commitments. Native commitment signing uses
the same canonical payload function as verification.

WebRTC frame limits, DataChannel chunk sizes and transfer deadlines remain in
transport: these describe the transport profile, not close-group or payment
policy. Browser memory and connection-pool limits remain adapter settings.
