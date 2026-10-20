# darwin — Darwin Storage Network Client

A CLI and Rust library for storing data on the Darwin storage network.

Based on Autonomi's [ant-client](https://github.com/WithAutonomi/ant-client), licensed MIT or Apache-2.0.

## Overview

This project provides two Rust crates:

- **ant-core** — A headless Rust library containing the client's business logic: data storage/retrieval with self-encryption and EVM payments, node lifecycle management, and local devnet tooling. Its `browser` module shares manifest validation, protocol framing, authenticated WebRTC Direct access, lookup, quote verification, and complete public-file workflows with browser applications through the `browser-wasm` feature.
- **ant-cli** — A thin CLI binary (`darwin`) built on `ant-core`.

Data on Darwin is **content-addressed**. Files are split into encrypted chunks (via [self-encryption](https://en.wikipedia.org/wiki/Convergent_encryption)), each stored at an XOR address derived from its content. A `DataMap` tracks which chunks belong to a file. Storage is paid in DARWIN on Robinhood Chain (chain ID 4663), through the payment vault `0xE0f627986c0438De0E314B644f3C8aA21D3f4f6B`. The token, the vault and the RPCs are bundled in `ant-core/resources/payment_network.toml`; `--evm-network robinhood`, the default, selects them.

Envelopes are darwin's default. `darwin file upload`, `darwin manifest create` and the library's file upload shortcuts store each upload in an envelope: its payment record, with every payment field shown unless you hide some, a listing when it is listed, and a `.record` proof of the payment. The other ways of using the network remain, and store no envelope, so no payment record, listing or `.record`: raw chunks (`darwin chunk put`), a file's encrypted chunks whose data map the caller keeps (`data_upload`), plain data maps (`Visibility::Public`, `darwin manifest export --compact --yes`), the browser core's uploads, and other clients.

### Browser WebAssembly client

Build `ant-core` for browsers without changing native callers:

```bash
wasm-pack build --target web ant-core \
  --no-default-features --features browser-wasm
```

This produces the low-level `wasm-bindgen` API backed by the shared Rust
implementation. The companion
[`ant-client-browser-sdk`](https://github.com/WithAutonomi/ant-client-browser-sdk)
project owns the TypeScript API, wallet adapters, browser storage and worker
integration, media streaming bridge, runnable examples, and browser end-to-end
tests.

Uploads from the browser core (`uploadPublicFile`, `uploadStagedPublicFile`,
`uploadRecords`) store a plain data map, or the staged records, with no
envelope: no payment record, listing or `.record`, which `darwin file upload`
stores by default. The browser core doesn't yet read paid quotes back, as the
native client does, and has no price ceiling option like `--max-chunk-price`.
A page that names no payment mode pays per chunk (`single`).

Native and WASM reads share `ant-core/src/client_engine/read.rs` and
`client_engine/files.rs`. The engine owns XOR-ordered peer selection, bounded
known-peer fallback, close-group retries, adaptive batch scheduling, deferred
file retries, recursive DataMap resolution, and plaintext range reads. Both
transports use `record.rs` for BLAKE3 verification. Native
`Client::data_download_range` and the browser media reader call the same range
implementation.

Browser downloads and range reads have no 1 GB file cap. File sizes and offsets
use 64-bit arithmetic internally; the JavaScript API accepts exact, nonnegative
`number` positions through `Number.MAX_SAFE_INTEGER` (just under 8 PiB). The
resolved DataMap and seek index still occupy memory proportional to the number
of chunks; content buffers stay bounded, including for seeks past 4 GiB.
Uploads retain their existing size limits.

`downloadPublicFile(file, concurrency?, onProgress?, { maxMemoryBytes?, signal? })`
and its private-file counterpart allocate the output as one JavaScript
`Uint8Array` and copy each decrypted chunk into place as it arrives, so WASM
holds only the records in flight. Progress is reported as
`Downloaded chunk n/total`, and an `AbortSignal` cancels the download. `maxMemoryBytes` limits the output buffer,
not total process memory; without it, allocation is attempted up to the
JavaScript engine's buffer limit. Allocation errors reject with guidance to use
streaming, since browsers do not expose a reliable amount of free memory.

For large downloads, pass a `WritableStream` to `BrowserFileReader.pipeTo`.
For example, after the application obtains a file handle from a user gesture:

```js
const reader = await client.openPublicFile(address);
try {
  const writable = await fileHandle.createWritable();
  const { bytesWritten, hash } = await reader.pipeTo(writable);
} finally {
  reader.close();
}
```

The same API works with `openPrivateFile({ data_map })`. `pipeTo(writable,
{ start?, end?, signal?, onProgress? })` optionally streams a half-open byte
range and reports `(bytesWritten, totalBytes)` after each write. Chunks are
fetched concurrently and written in order, at most 4 MiB per write; fetching
continues during writes until 32 MiB of plaintext is held. Invalid calls reject
without touching the destination; otherwise the destination is closed on
success, aborted on failure (an abort during its close may come too late to
undo the commit), and its writer lock released. The result contains
the byte count and BLAKE3 of the written range, and an `AbortSignal` cancels
the call. `reader.close()` releases the records read-ahead holds and makes later
calls fail. `readRange(start, length)` remains available for media and custom
sinks, with a 4 MiB per-call limit. The application chooses a memory budget and
supplies its disk destination; the core does not open file pickers or silently
select a path.

The adapters supply QUIC or WebRTC discovery/GET requests, runtime timers,
caches, progress callbacks, and output handling. Browser descriptors and wallet
callbacks remain browser API concerns. Native filesystem streaming still uses
its synchronous self-encryption iterator bridge, but its map resolution and
batch retry policy now come from the shared engine. In-memory downloads and
DataMap resolution no longer require a multi-threaded Tokio runtime.

Reads retry an inconclusive close-group sweep after one second. Each sweep
tries the discovered peers followed by at most twenty additional known peers;
failed discovery does not exclude a known holder from direct GET. File batches
retry only missing records, immediately once and then after 15 and 45 seconds,
as native file downloads do. Browser concurrency and range-memory limits remain
platform-specific ceilings on the shared adaptive scheduler.
Omitting the WASM download concurrency uses that scheduler automatically;
an explicit value remains a ceiling. Fetch epochs can learn after two seconds
and at least two completed waves (minimum eight samples), on both native and
WASM. In-flight work from a previous concurrency does not train a new probe.
Browser physical GETs, including speculative reads, also reserve worst-case
response bytes from a 128 MiB transient budget. Sustained GET processing above half
the event loop, with repeated processing or scheduling stalls above 50 ms, reduces
local admission. Eight-response windows avoid reacting to isolated slow responses
or background timer clamping; healthy windows recover gradually. This does not bound complete-file storage or reconstruction memory;
range reads remain preferable for large media.

Upload discovery follows native's witnessed lookup contract: request twenty
initial responders and, if that lookup fails, retry at seven. Both attempts
use normal iterative lookup, endpoint failure handling, and grace deadlines.
The endpoint cache records only connection-establishment failures, matching
native's dial-failure semantics. A failed FIND_NODE or a request dropped at the
lookup grace deadline does not suppress that endpoint for future uploads.
Established connections remain eligible and successful connection establishment
clears the failure entry.
There is no browser-specific recovery probe or relaxed payment threshold.
The requested responder count must be satisfied before quote witnessing and
storage-majority checks proceed.

Pointers work from the browser too: `getPointer`, `resolvePointer`,
`createPointer` and `updatePointer` on `BrowserNetworkClient`, and
`pointerAddress(seed)` offline. They run the native client's own read quorum,
corroboration and write quorum, and pay each state through the same wallet
callback file uploads take. The owner key is passed as its 32-byte seed. Only
nodes that advertise `pointer_protocol` are asked. A write can hand the paid
record and proof to an `onPaid` callback; `storePaidPointer` stores them later
without paying again. `transferPointer` hands a pointer over for good.
`pointerFinality` asks the whole close group whether a pointer is final, and
the bootstrap peers nearest it before calling it open, in `seeds` (see
`darwin pointer transfer` and `darwin pointer finality` below). Like the
browser's uploads, its pointer writes read no paid quote back and take no price
ceiling.

Browser protocol v5 and browser manifest v6 advertise only the payment chain ID
and token/vault addresses. RPC providers belong to the application or wallet;
the node's verification RPC URL is never sent to the browser. Paid uploads
check that every selected node advertises the same chain and contracts. Deploy
matching node, Rust/WASM client, and SDK versions together.

## Installation

Build the `darwin` binary from source with a stable Rust toolchain:

```bash
cargo build --release --locked -p ant-cli --bin darwin
# The binary is target/release/darwin (darwin.exe on Windows).
```

Every push to `main` also builds a Linux x86-64 binary in CI, uploaded as the
`darwin-linux-x64` workflow artifact (`darwin-linux-x64.tar.gz` and its `SHA256SUMS.txt`).
Next to `darwin`, the archive holds its license files (`LICENSE-MIT`, `LICENSE-APACHE`) and the
notices for the third-party code in it (`THIRD-PARTY-NOTICES.txt`, `RUST-STD-COPYRIGHT.html`).

`darwin --version` prints the package version and, on a second line, the git commit the binary
was built from (`unknown` outside a git checkout of this repository; uncommitted changes don't
show). The version is upstream's, 0.3.11 now and 0.3.9 in earlier builds, so go by the
commit: builds before `0995cba` (2026-10-06) pay the retired test token and can't upload to
the current network.

`darwin` keeps the data and configuration directories of the `ant` name (for example
`~/.local/share/ant` and `~/.config/ant` on Linux), so files written by earlier builds are found
where they were. Autonomi's `ant` keeps its upload history in `uploads/` there; darwin's is
`darwin-uploads/`, so neither lists or loads the other's.

The seeds bundled in `darwin` are replaced only by a `darwin_bootstrap_peers.toml` in that config
directory, and `darwin` keeps its peer cache in `darwin_client_peer_cache.json` in the data
directory. The `bootstrap_peers.toml` and `client_peer_cache.json` that Autonomi's `ant` and its
installers leave in the same directories name Autonomi's network, and `darwin` never reads them.
A seed file written for an earlier `darwin` build is read again once renamed
`darwin_bootstrap_peers.toml`. See [Bootstrap multiaddresses and browser defaults](#bootstrap-multiaddresses-and-browser-defaults).

This repository has no installer or npm package for darwin: build from source or take the
`darwin-linux-x64` CI artifact.

## Quick Start

### Store and retrieve a file

The network's seeds are bundled, so no `--bootstrap` is needed. The wallet behind `SECRET_KEY`
needs DARWIN for storage and a little ETH on Robinhood Chain for gas.

```bash
# What it will cost
darwin file cost notes.txt
# Output (an 8 KB file):
#   Chunks: 4 (3 + 1 envelope)
#   Cost:   1.50 DARWIN (gas: 0.000150 ETH)

# Upload (private: the data map is saved locally)
SECRET_KEY=0x... darwin file upload notes.txt
# Output (in part):
#   Upload complete!
#     Datamap:  notes.txt.datamap
#     Record:   notes.txt.record
#     Chunks:   4 (3 + 1 envelope)
#     Cost:     1.50 DARWIN (gas: 0.000005 ETH)

# Download using the local data map
darwin file download --datamap notes.txt.datamap -o notes_copy.txt
```

Each chunk costs three times the median quote of the nodes that store it: about 0.375 DARWIN
on today's network, rising as nodes fill. The gas in `darwin file cost` is upstream's fixed
estimate; an upload's actual gas on Robinhood Chain is far lower.

### Store and retrieve a file (local devnet)

```bash
# 1. Start a local devnet (spins up 25 nodes + a local Anvil EVM chain)
cargo run --release --example start-local-devnet

# 2. Upload a file (the manifest is auto-written to the shared data dir)
SECRET_KEY=0x... darwin file upload photo.jpg --public \
    --devnet-manifest ~/.local/share/ant/devnet-manifest.json --allow-loopback --evm-network local

# 3. Download it back
darwin file download abc123... -o photo_copy.jpg \
    --devnet-manifest ~/.local/share/ant/devnet-manifest.json --allow-loopback --evm-network local
```

### Low-level chunk operations

```bash
# Store a single raw chunk (< 1 MB), with no envelope
echo "hello darwin" | SECRET_KEY=0x... darwin chunk put
# Output: abc123def456...

# Retrieve it
darwin chunk get abc123def456...
# Output: hello darwin
```

A raw chunk has no data map, so it carries no envelope: no payment record, listing or `.record`.
`darwin file upload` is the standard way to store a file.

---

## CLI Reference

### Global Flags

| Flag | Description |
|------|-------------|
| `--json` | Output structured JSON instead of human-readable text |
| `-b, --bootstrap <ADDR>` | Bootstrap peers as QUIC multiaddresses (`/ip4/1.2.3.4/udp/10000/quic`) or `ip:port`, comma-separated or repeated. Default: the bundled seeds, unless `darwin_bootstrap_peers.toml` in the config directory names others |
| `--devnet-manifest <PATH>` | Path to devnet manifest JSON file |
| `--allow-loopback` | Allow loopback connections (required for local devnet) |
| `--timeout-secs <N>` | Network operation timeout in seconds (default: 60) |
| `-v, --verbose` | Increase verbosity: `-v` info, `-vv` debug, `-vvv` trace. Default: no logs (privacy by design) |
| `--evm-network <NET>` | Payment network: `robinhood` (default: Robinhood Chain, DARWIN) or `local` (the devnet manifest's chain). Upstream's `arbitrum-one` and `arbitrum-sepolia`, which pay Autonomi's ANT, are refused |
| `--max-chunk-price <BASE_UNITS>` | The most a node's quote may ask to store one chunk, in the token's base units (10^-18 DARWIN, a whole number). Quotes asking more are ignored, as if their node hadn't answered; a chunk then costs at most 3 times this. Default: no ceiling |

### `darwin file` — File Operations

Upload and download files with automatic chunking, self-encryption, and EVM payment.

#### `darwin file upload <PATH>`

Upload a file to the network. The file is split into encrypted chunks, each paid for via the configured EVM network. Requires `SECRET_KEY` environment variable.

```
$ SECRET_KEY=0x... darwin file upload my_data.bin --public
warning: the payment fields shown give away the paying wallet to anyone with the envelope's address
Encrypted into 3 chunks

Upload complete!
  Address:  a1b2c3d4e5f6...
  Payment:  all fields shown
  Record:   my_data.bin.record
  Chunks:   4 (3 + 1 envelope)
  Size:     8.0 KB
  Cost:     1.50 DARWIN (gas: 0.000005 ETH)
  Time:     6.3s

Anyone can download this file with:
  darwin file download a1b2c3d4e5f6... -o <FILE>
Recorded as 20261017T091502Z-my_data.bin (darwin manifest download 20261017T091502Z-my_data.bin)
Prove this upload to anyone with:
  darwin file prove my_data.bin.record
```

The `warning:` and `Encrypted` lines go to stderr. The default, a private upload, keeps the data map local and says what its envelope makes public:

```
$ SECRET_KEY=0x... darwin file upload my_data.bin
warning: the payment fields shown give away the paying wallet to anyone with the envelope's address
Encrypted into 3 chunks

Upload complete!
  Datamap:  my_data.bin.datamap
  Envelope: 9f8e7d6c5b4a... (its payment record is public, the file is not)
  Payment:  all fields shown
  Record:   my_data.bin.record
  Chunks:   4 (3 + 1 envelope)
  Size:     8.0 KB
  Cost:     1.50 DARWIN (gas: 0.000005 ETH)
  Time:     6.1s

Download this file with:
  darwin file download --datamap my_data.bin.datamap
Not recorded in the upload history: a private upload's data map stays only in its .datamap and .record.
Prove this upload to anyone with:
  darwin file prove my_data.bin.record
Keep the record as safe as the data map: it holds the data map and the salt, so it reads the file, and its salt is what proves which file this is. `darwin file prove --no-reveal` proves only the payment.
```

Mistakes in `--hide`, `--name` or `--content-type` are reported before `SECRET_KEY` is read or the network is joined.

**Options:**

| Flag | Description |
|------|-------------|
| `--readable <yes\|no>` | Whether anyone with the address can read the file. `no` (default): the data map is saved to a local `.datamap` file, and the envelope stores only a salted hash of it. `yes`: the data map is stored on the network. |
| `--index <yes\|no>` | Whether the file appears in the network's listings index (see `darwin listings`). Default `no`. |
| `--visibility <private\|unlisted\|listed>` | Shorthand for the two above: `private` (`no`, `no`; the default), `unlisted` (`yes`, `no`) or `listed` (`yes`, `yes`). The fourth combination, `--readable no --index yes`, is a public, dated record of a file nobody can read until you reveal it. |
| `--public` | Same as `--visibility unlisted`. |
| `--hide <FIELDS>` | Payment fields to hide, comma-separated: `tx-hash`, `block`, `timestamp`, `log-index`, `quote`, or `all`. All five are shown by default. |
| `--name <NAME>` | A name stored in the envelope, on any visibility (1–255 bytes, no control characters or path separators). Public and permanent. |
| `--content-type <TYPE>` | A content type stored in the envelope, as `type/subtype`, on any visibility. Public and permanent. |
| `--merkle` | Refused: batch (merkle) payments are off on the Darwin network (see step 3). |

**How it works:**
1. The file is streamed through self-encryption in 8KB reads (never fully loaded into memory).
2. Each encrypted chunk is stored on the network at its XOR content address. A chunk the nearest nodes say they already hold is skipped, unpaid, only once 4 of its 7 nearest nodes prove it by serving it: the client reads it from them one at a time and checks the bytes against the address. Claims that aren't proven are set aside and the chunk is paid for and stored as usual. So a re-run of an interrupted upload pays nothing for the chunks it already stored, and reads each of them back from 4 nodes. A new chunk is sent to its 7 nearest nodes at once, each that fails or is full replaced by the next nearest, and counts as stored once 4 of them accept it.
3. Payment is made per chunk, in transactions of up to 64 chunks each. Batch (merkle) payments are off on the Darwin network since 2026-10-09: the DARWIN vault picks a batch's paid pool from inputs the payer chooses, so a payer can steer the payout, and a re-sent batch can be charged twice. Upstream pays uploads of 64 chunks or more in batches. After each payment the client reads every paid quote's record back from the vault. The vault keeps a quote hash's first payment and skips later ones without reverting, so someone who knew a quote hash first (such as the node that issued it) can record it with a dust payment of their own; the client's payment for it then moves no tokens. A chunk whose record isn't the client's payment (another rewards address, or less than the quote) is quoted again, which gives a new quote hash, and paid again, up to 3 times. If its quotes are occupied every time, that chunk fails, with an error starting `quotes occupied` that names the node that issued them; the rest of the upload is stored. A chunk is paid 3 times the median of its quotes. With `--max-chunk-price`, a quote asking more than the ceiling is ignored, as if its node hadn't answered, and no payment is planned on one, so a chunk costs at most 3 times the ceiling; a chunk left without a quote under it fails before anything is paid.
4. A `DataMap` is produced that records which chunks compose the file.
5. Unless the upload hides every payment field, is not in the index and has no name or content type, the client stores an **envelope**: a small chunk holding the data map (readable uploads) or a salted hash of it (private uploads), the name and content type, and flags saying which payment fields its listing shows and whether it is in the index. Its address is the file's address. Nodes that keep listings record the envelope's payment, so anyone with the address can check it against the chain. The envelope is paid in the same payment as the content (one payment for any upload under 64 chunks; from 64, with the chunks left after the merkle batches, or alone) and stored after every content chunk, so it never points at missing content.
6. Without an envelope, a readable upload stores the DataMap itself as a chunk and returns its address; a private one stores nothing extra.
7. The client saves the data map of a private upload to `<filename>.datamap`, and the envelope's record to `<filename>.record`: the envelope, its payment's transaction and paid quote, and for a private file the data map and the salt. Keep the record with the data map: it proves the upload from the chain alone (`darwin file prove`), even for fields you hid. **A private upload's record reads the file, like the `.datamap`**: whoever has it can download the file (`darwin file download --proof`), so keep it as safe as the data map, and hand over `darwin file prove --no-reveal` to prove only the payment. Until the record is saved, the client keeps a copy of it under its data directory (`payments/upload/records/<envelope address>.<payer>.record`, the same text as the `.record` file; for a private upload without a record, its salt as `.salt`), so a crash between paying and saving doesn't lose the paid quote and tx hash, which nothing else may hold once the quote is hidden. The upload removes its checkpoint only after that copy is written; a later upload of the same file with the same choices and wallet that finds the envelope already stored gets the kept record back. Saving the `.record` removes the copy.
8. A readable upload is also recorded in the upload history (`darwin manifest list`, below): a manifest in `darwin-uploads/` under the client's data directory that names the file by the address the upload stored, its envelope's (or, with no envelope, its data map chunk's). It is owner-only on Unix (`0600`). A private upload is not recorded, and says so: its data map stays only in its `.datamap` and `.record`.

`darwin file cost <PATH>` takes the same `--readable`, `--index`, `--visibility`, `--public`, `--hide`, `--name` and `--content-type` flags, and counts the envelope or data map chunk the upload adds. When the sampled content is already stored, it prices that chunk alone, and says the content is only likely stored unless every content chunk was sampled.

At upload the client warns about what your choices give away: a hidden field that a shown one gives away (a hidden timestamp with the block number shown, for example, or a hidden log index with the tx hash shown when the transaction paid for the envelope alone: a transaction's quotes are paid in quote-hash order, so the envelope's log isn't always its last), a tx hash shown without the quote (the payment can't then be tied to this file), a name or content type on a private file (readable by anyone with the envelope's address, though the file is not), and that shown payment fields, or being listed, show the paying wallet. **Envelopes, their metadata and listings are public and permanent.**

#### `darwin file download [ADDRESS]`

Download a file from the network.

```
# Public download (by address)
$ darwin file download a1b2c3d4e5f6... -o restored.bin
Connecting to network... done
Downloading from network...
Download complete!
  File: restored.bin
  Size: 8.0 KB
  Time: 0.4s

# Private download (from local DataMap)
$ darwin file download --datamap my_data.bin.datamap -o restored.bin
Connecting to network... done
Downloading from network...
Download complete!
  File: restored.bin
  Size: 8.0 KB
  Time: 0.4s
```

**Options:**

| Flag | Description |
|------|-------------|
| `ADDRESS` | A public DataMap or envelope address: 64 hex characters, or a `darwin://ADDRESS` link (upstream's `ant://ADDRESS` is read too). |
| `--datamap <PATH>` | Path to a local `.datamap` file (for private downloads). With an address too (a private file's envelope), the data map is used, and checked against the envelope when the upload's `.record` is next to it. |
| `--proof <PATH>` | Path to an upload record or proof (`darwin file prove`) whose envelope carries the data map, or reveals it. |
| `-o, --output <PATH>` | Output file path. Default, in the current directory: with `--datamap`, the data map's file name without `.datamap` (`my_data.bin.datamap` gives `my_data.bin`; other names need `-o`), also when an address comes with it; otherwise the address, in hex. Required with `--proof`. |

A private file's envelope address can't be downloaded from: its envelope stores only a salted hash of the data map, and the download says so. Use `--datamap`, or `--proof` with a proof that reveals it.

Every chunk read is checked against its address. A node that serves bytes that don't match is passed over for the next nearest node (and named in the `-v` log); a read fails on bad bytes only when no node serves the chunk intact. The same holds in the browser build. Reads also ask the bootstrap peers nearest the chunk, from the start; see [Bootstrap multiaddresses and browser defaults](#bootstrap-multiaddresses-and-browser-defaults).

#### `darwin file prove <RECORD>`

Writes a proof of an upload from its record (`<filename>.record`) to `<filename>.proof` (or `-o <PATH>`). For a private file the proof reveals the data map and salt, so whoever has it can read the file and check that the envelope is for it; `--no-reveal` proves only that the envelope was paid for. Hand it to anyone who should be able to check the upload, including fields you hid. It never writes over the record (which holds the salt), and replaces an existing proof only with `--force`.

#### `darwin file verify <PROOF> [--file <PATH>]`

Checks a proof (or record) against the payment chain alone: the envelope hashes to its address, the quote names it and is signed, and the transaction paid it. Prints the payment (block, time, log index, transaction). With `--file`, also checks that a local file encrypts to the proof's data map. Needs no storage node. A proof shows the address was paid for by a block; it doesn't show who uploaded the file, since anyone who has the envelope can pay for the same address. Only a revealed data map and salt tie a private envelope to its file.

### `darwin manifest` — Manifests and the Upload History

A manifest is a `.darwin` file, or a `darwin://manifest/...` link, that names files and holds what reads each one: its data map, embedded, or the address of its public data map chunk ([ADR-0006](docs/adr/ADR-0006-file-manifests-and-links.md)). Whoever has a manifest with embedded data maps can read those files. `darwin://` links and `.darwin` files are what `darwin` writes; upstream's `ant://` links and `.ant` files, the same bytes under upstream's names, are also read. A manifest file is read by its content, whatever its name.

- `darwin manifest create [PATH]...` uploads files, or one directory's contents, and writes a manifest of them (`<name>.darwin`, or `-o <PATH>`). Each file is uploaded as `darwin file upload` uploads it, with the same `--visibility`, `--public`, `--readable`, `--index` and `--hide` choices: private by default, in an envelope that shows every payment field. The same warnings are given before anything is paid, mistakes in the choices are reported before `SECRET_KEY` is read or the network is joined, and it pays per chunk and refuses `--merkle`. Each file's record is saved in `<manifest>.records/` next to the manifest (`photos.records/` for `photos.darwin`, under the file's own directories), never over an older record; a private file's record holds its data map and salt, so keep it as safe as the manifest. A build that fails or is cancelled still saves the records of the files it uploaded. `--name` names the manifest; files get no envelope name or content type. `--public-file ADDRESS[=PATH]` adds a file that is already public, without uploading anything. `--embed-public ADDRESS[=PATH]` does too, and embeds the file's data map so recipients skip fetching it; a file stored with an envelope (as `darwin file upload --public` stores it) is added by its envelope address instead, which keeps its payment record, and its data map is not embedded. A private file's envelope address is refused, before anything is uploaded.
- `darwin manifest list` lists the upload history, newest first: the readable uploads of `darwin file upload` and `darwin manifest create`, recorded as manifests in `darwin-uploads/` under the client's data directory. A `darwin file upload` is recorded by the address it stored, a `darwin manifest create` as the manifest written. Private uploads are not recorded, so no private data map is kept there: theirs stay in their `.datamap` and `.record` files, or in the manifest file written. Autonomi's `ant` keeps its own history in `uploads/` in the same data directory, and neither lists the other's.
- `darwin manifest show`, `link`, `download` and `export` take a `.darwin` file, a `darwin://manifest/...` link, or an id from `darwin manifest list`. `export --compact` replaces embedded data maps with addresses for files already readable by address, including files uploaded with `darwin file upload --public`. A file is found in the envelope `--public` (or `--visibility listed`) stores when it has no name, content type or hidden payment field, since that envelope's address follows from the data map alone, or as a plain data map chunk (`--hide all`). A file not yet readable is listed with the standard way to make it so, `darwin file upload --visibility unlisted`, which stores it in an envelope, and nothing is written. With `--yes`, as upstream, the data maps of those files are published as plain chunks instead, after a warning: paid, and with no envelope, so no payment record, listing or `.record`. Each is paid as `darwin chunk put` pays for a chunk, recovering a payment the RPC answered with an error; if one still can't be seen, the export fails and says so, and running the same export again finds it on the chain instead of paying twice. It needs the network, and `SECRET_KEY` only with `--yes`.

### `darwin listings` — The Listings Index

```
$ darwin listings
$ darwin listings --since 1767225600 --json
$ darwin listings --json --state walks.json --carry index.json > index.new.json
```

Collects listings from every node the client can find (`listings.v2`), merges the copies of each (nodes record their own `first_seen` for a listing that hides its time, so copies that differ only there are merged), checks each one as far as its shown fields allow, and prints them in index order: time, address, size, content type, name, the payment fields it hides (`hidden: tx-hash,quote`, or `-` when it shows all five), and the check.

- `verified n/7`: the listing shows its quote, and the payment is checked on chain and tied to this address. Of several payments for one address, the one a quorum of the 7 nodes nearest it serve counts; `(no quorum)` marks the earliest standing in when none has one.
- `reported n/7`: the listing hides its quote. Its shown fields are checked against the chain, and it counts only when at least 4 of the 7 nodes nearest its address serve it (fewer only on a network of fewer than 7 nodes). A lookup that finds fewer of the nearest nodes than the network has never lowers the bar: the listing is left out as "too few nearest nodes found", to try again.

Listings are decided as the nodes decide them when they repair one. Until 4 of the nearest nodes serve one copy of a listing, the nearest nodes not heard from yet are asked for it (a walk of a node's whole index that began well after the listing's time counts as its answer), whether or not it shows its quote. If the payment chain can't be read for the copy 4 of them serve, the address is left out for now, to try again, rather than shown with a copy fewer nodes serve. A copy that can't check out whatever the chain says (it doesn't match its envelope, its quote names another address or isn't signed, or the block or block timestamp it shows is earlier than the payment vault's deployment, in block 81897121 at 2026-10-06 20:01:56 UTC, so it paid something else) is never looked up on chain, and is refused however many of the nearest nodes serve it. A listing showing its quote is looked up only among the payments of that quote it can describe (at its shown log index, in a block of its shown timestamp), so earlier payments of the same quote by others don't hide the upload's.

A listing that hides its block timestamp shows `~` and the hour it was first seen. Only the dates of the 7 nodes nearest its address count. For a listing that counts, each of those dates is checked on its own against the clock and, where the listing locates its payment, the payment's block, with those out of bounds left out. Where at least 4 of those dates pass, the listing is dated by the latest of the earliest 4, so that 4 of them date it then or earlier: their median when all 7 pass. Where fewer than 4 pass, or fewer than 4 of the nodes serve it, it is dated by the latest date that passes. So fewer than 4 nodes can't date it earlier than every other date that passes, whatever they send: early dates, dates out of bounds, or none. One node can date it later, though: where no more than 4 dates pass, up to the reader's clock plus an hour. A listing that doesn't count, which `--all`, `darwin listing` and the producer's `rejected.json` show too, is dated by its nearest nodes' dates before any check: the latest of the earliest 4 where at least 4 of them serve it, otherwise their median.

A listing that shows none of its block, block timestamp and transaction is also refused without reading the chain when the date 4 of its nearest nodes give it is more than two hours (the hour's rounding, and an hour for clocks) before the vault's first payment, in block 81942857 at 2026-10-06 21:20:03 UTC (bundled beside the deployment; the chain holds no log of the vault's in between): no node stores a listing before its payment, so it paid something else. 3 nodes dating it early can't get it refused, and a payment to the vault, stored by nodes whose clocks are within the hour, never is. One that shows its transaction is left to the chain, which shows the vault it paid, and a listing outside the index has no date to refuse it by. What this can't refuse is a payment to another vault, hiding its block, block timestamp and transaction, that 4 of its nearest nodes date 20:00 (UTC) on 2026-10-06 or later: one dated 20:00 could be a payment to the vault at 21:20 that nodes whose clocks were an hour behind stored at once. The vault in use before this one took its last payment at 19:18:41 UTC, so its listings escape only where 4 of their nodes first stored them, by their clocks, at 20:00 or later.

A read has no cap on how many listings the index holds, and a node can't make it slow by serving listings nobody else has. The client walks every node's index a page at a time: each node is read for 8 pages, and earns 2 more listings' worth of pages for each listing it sends whose address at least 4 of the 7 nodes nearest that address serve (if the node is itself among the 20 nearest), so the walk of a node holding real listings runs to the end, and that of a node serving made-up ones stops after 8 pages. Only an address at least 4 of its 7 nearest nodes serve is worked on (its envelope fetched, nearest nodes asked, the chain read); any other costs nothing but its pages and waits for a later read, shown with `--all` as `undecided (try again)`, even when a single node serves it, with a line for each copy its nearest nodes serve: the node, the block the copy shows and its time, and, where that block or the block timestamp it shows is earlier than the payment vault's deployment (block 81897121 at 2026-10-06 20:01:56 UTC, bundled beside the vault's address), that it can't have paid the vault. The date one node gives a copy that hides its block timestamp never marks it: it isn't the date 4 of the nearest nodes give. The walks have a deadline: at most 30 minutes, and once half of them are done, four times as long as that took (at least a minute). On stderr, the command counts the walks that stopped early and the addresses left for a later read, and warns when a read found too few nodes to trust (fewer than 7, or under three quarters as many as recent reads): such a read decides nothing.

`--state` keeps the walks' state in a file between reads, so walks stopped early carry on where they stopped, and recent reads' node counts are known. `--carry` takes the previous `--json` output and prints its entries again, as they were, for every address this read didn't decide, marked `"carried": true`: a read never drops a listing it didn't decide, however few nodes answered. A listing whose file the network no longer stores is dropped, but only when each of the nodes nearest its address walked past where it would be without serving it. Where the read decided an address, its own entry replaces the earlier one, or nothing does if it rejected the address. With `--since`, a listing the read dates before that time is left out, and the earlier entry for its address is kept, since the read says nothing about earlier listings. Nor does a read with `--since` drop a listing as no longer stored: a node dates a listing that hides its time by its own clock, which can be well before the date shown and before where the read began, so the read can't tell a node that still serves it from one that doesn't. On a timer, run the third example and, when it succeeds, move `index.new.json` over `index.json`: the file then holds the index so far.

| Flag | Description |
|------|-------------|
| `--since <UNIX_SECONDS>` | Only listings from this time on (block timestamp, or first seen). |
| `--all` | Also show listings that fail their checks, with the reason. |
| `--state <FILE>` | Keep the walks' state in this file: read if it exists, replaced after the read. |
| `--carry <FILE>` | A previous `--json` output of this command, whose entries for addresses this read didn't decide are printed again. Needs `--json`. A missing file carries nothing; one that can't be read fails the command before anything is printed. |

With `--json`, hidden payment fields are absent, and each listing carries `check` (`verified` or `reported`), `nodes` and `nearest`, `first_seen` where it has one, and for a readable listing its `data_map` (hex), which is enough to read the file without fetching the envelope. A listing too few of its nearest nodes serve yet also carries `copies`: for each of those nodes' copies, the `node` (hex), the `block_number`, `block_timestamp` and `first_seen` it shows, its `time`, and `"before_vault_deployment": true` where its block or block timestamp is earlier than the vault's deployment. Download a listed file with `darwin file download <ADDRESS>`.

### `darwin listings serve` — Publishing the Index

```
$ darwin listings serve --state-dir /var/lib/listings --out-dir /var/www/listings/v1 --carry listings.json
```

Runs until SIGINT or SIGTERM (the cycle in hand finishes writing first) and keeps the listings index published as the static files of `listings/v1/`: the newest entries (`head.json`), shards by address, name and content type, pages of the whole index in key order, a feed of every change, `status.json` (how the producer is doing, rewritten every cycle after its other files, so it goes stale when they can't be written) and `rejected.json`. [docs/listings-v1.md](docs/listings-v1.md) specifies them for readers in any language. Each file is replaced whole, and only when its bytes change, with `.gz` and `.zst` copies of the same bytes beside it, so any static file server can serve the directory and a reader polling with conditional requests gets a `304` while nothing changed. Time pages are named by their content and never change. A full feed segment doesn't change within its epoch, but a new epoch writes its segments under the same names, so serve segments to be revalidated rather than cached. An address every copy of which its nearest nodes serve shows a payment from before the payment vault was deployed is rejected for good in `rejected.json` (unless its entry is still listed, kept unconfirmed as `carried`: then it has no row there and stays listed), not deferred: none of its copies can count, however many nodes come to serve them, so it stays out of `status.json`'s deferred groups (`darwin listings --all` still shows it as `undecided (try again)`). `darwin listings` without `serve` reads the index once, as above.

| Flag | Description |
|------|-------------|
| `--state-dir <DIR>` | Where the producer keeps its state, created if missing. One process uses it at a time. |
| `--out-dir <DIR>` | Where it publishes the files of `listings/v1/`, created if missing. |
| `--carry <FILE>` | On a first start, an earlier `--json` output of `darwin listings` (such as a `listings.json` the producer takes over from), whose entries are published as carried until cycles decide their addresses, so nothing in it is lost meanwhile. The carry doesn't start the support files' 10 minutes: the first cycle that changes any support, as deciding any of those entries does, publishes it at once, and support that changes later waits for the 10 minutes that write starts. Ignored once the state holds an index. |

**Its state** is one store, `listings.mdb` in the state directory: the census of nodes, a mirror of what each node serves in its part of the address space, the nodes that served each address when it was last decided, chain facts, envelopes, the published index, and since when each address has been deferred or listed below full support (what `status.json`'s `deferred` and `below_full` give). Back it up like other server state. Without it the producer starts cold: it reads every listing again, and starts a new feed under a new `epoch`, which tells readers to read the index afresh.

It decides what `darwin listings --state --carry` decides, with the same rules and the same code: each address that at least 4 of its 7 nearest nodes serve is decided, and the others wait. What differs is how it learns what the nodes serve:

- **The census.** It keeps a census of the nodes instead of finding them anew each time: the address space is split into leaves of at least 7 nodes each, and each leaf is closed with witnessed lookups, which give only nodes that answered. Every leaf is closed at the first start and once a day, and a leaf again when one of its nodes misses 3 polls in a row or a node names peers the census lacks.
- **Each minute** (a cycle) it asks every census node, 64 at a time, about its own leaf. A node that keeps a change feed (`node/<version>+ds.15` or later) is asked for the changes since its last answer, which are applied to a mirror of what it serves, checked against the count and set hash the node gives; a node without one is sent one `listings.v2` request a minute, with a full pass of its index at most once an hour. A node's copies count while its mirror is in sync (or, without a feed, while it answers). The full listing behind a copy is fetched once with a request for its address, and checked against the node's entry for it. A cycle in which fewer than 7 census nodes answered, or under three quarters of them, decides and removes nothing.
- **Deciding again.** An address is decided again only when its copies, its 7 nearest nodes or a chain fact it rests on changed, every cycle while it waits or is kept unconfirmed, and once a day with all the others, when a change nothing explains is logged as a warning. A restart decides every address again in its first cycle. Envelopes and final chain facts are kept, so an address decided before costs no chain call again.
- **Pushes.** Each request to a node with a change feed also asks it to push its new records as they come: an address a push changes is decided and published at once, between cycles. Publications are at least a second apart, so a file written twice is never written twice in the same second.
- **Removals.** An entry is removed when deciding its address again rejects it, or when in one cycle all 7 of its nearest nodes answered and none serves a copy, a witnessed lookup of the address finds the same 7, and a request for the address, at least 2 hours after its time, to each of them and to each node that served it when it was last decided (unless that node has left the census) finds none. Otherwise it stays, marked `carried` in its support file, and has no row in `rejected.json`, which lists only what the producer doesn't list.
- **Chain facts** (a transaction's receipt, a block's time, a quote's payments) are used as soon as they are read, and kept for good only once their block is at or below the RPC's `finalized` block and a second provider returns the same. A fact not found, an error, or a time in the future is never kept.
- **Its log.** Nothing is logged by default. `RUST_LOG=ant_core=warn,ant_core::data::client::listings_serve=info` logs its warnings, such as a cycle that failed, and one line per cycle: nodes answering (through their change feeds or with `listings.v2` requests), addresses decided and looked at, entries put, removed and carried, the cycle's time, traffic and RPC calls, and the pushes taken and publications made since the cycle before.

### `darwin listing <ADDRESS>` — One Listing

```
$ darwin listing be4ec238e14701164b2b97d73013039b28f2c747adaa2062cf0e4ecf3f3b0181
```

Asks the 7 nodes nearest the address for its listing, in the index or not, and checks it the same way: every field, with hidden ones shown as hidden, the check level and how many of the nearest nodes serve it. `--json` prints the listing and any copies that failed. Without a valid listing the command exits non-zero, with or without `--json`.

### `darwin chunk` — Single-Chunk Operations

Low-level put/get for individual chunks (max ~1 MB each). Useful for small data or building custom data structures.

#### `darwin chunk put [FILE]`

Store a single raw chunk. Reads from `FILE` or stdin. Requires `SECRET_KEY`. A raw chunk has no
data map, so it carries no envelope: no payment record, listing or `.record`, unlike
`darwin file upload`, the standard way to store a file. It is paid per chunk in DARWIN, with the
read-back of paid quotes and `--max-chunk-price`, as uploads are. Like an upload, it recovers a
payment the RPC answered with an error: it checks the chain again 10 seconds later, and if the
payment still can't be seen, the command fails and says so; running the same command again finds
the payment on the chain and carries on without paying twice. A chunk paid for and not stored is
stored by running the same command again, with the same payment (see
[Records paid one at a time](#records-paid-one-at-a-time)).

```
$ echo "small payload" | SECRET_KEY=0x... darwin chunk put
a1b2c3d4...
```

#### `darwin chunk get <ADDRESS>`

Retrieve a single chunk by its hex-encoded XOR address.

```
$ darwin chunk get a1b2c3d4... -o output.bin
```

**Options:**

| Flag | Description |
|------|-------------|
| `-o, --output <PATH>` | Write to file instead of stdout. |

### `darwin pointer` — Pointer Operations

A pointer is a mutable reference to a chunk or to another pointer, signed by an
owner key that can never change. Every state is paid for; reads are free. The
owner key is kept as a 32-byte seed in a file only its owner can read (`0600`
on Unix; on Windows it takes its directory's permissions, so keep it in your
user profile). Losing it means the pointer can never be updated again.

The key cannot change hands, but the pointer can: `darwin pointer transfer` signs
its final state, pointing at a pointer the new owner holds the key to. Readers
of the address are redirected there, the address stays the same, and the
former owner's key can change nothing any more (ADR-0018 in Autonomi's
`ant-node`).

Pointer writes (`create`, `update` and `transfer`) are paid in DARWIN, one
record per payment, with the checks uploads have: the paid quote's vault record
is read back, and a quote someone else recorded first is quoted and paid again,
up to 3 times; `--max-chunk-price` applies; and the wallet signs for the
payment chain only. A pointer record holds no data map, so no envelope or
`.record` is stored for it. Like an upload, a pointer write recovers a payment
the RPC answered with an error: it checks the chain again 10 seconds later, and
if the payment still can't be seen, the command fails and says so. Running the
same command again (the same key, and the same target or recipient) signs the
same state, finds its payment on the chain and carries on without paying twice;
a state paid for and not stored, such as a write that fell short, is stored the
same way, with the same payment (see
[Records paid one at a time](#records-paid-one-at-a-time)).

#### `darwin pointer keygen --output <FILE>`

Create a new owner key and print the address of the pointer it controls. Never
overwrites an existing file.

```
$ darwin pointer keygen --output owner.key
Owner key written to owner.key
9f3c...
```

#### `darwin pointer address --key <FILE>`

Print the address of the pointer a key controls. Needs no network.

#### `darwin pointer create --key <FILE> <TARGET> [--kind chunk|pointer]`

Create the pointer, pointing at `TARGET` (hex). Requires `SECRET_KEY` to pay.
Refused before paying if the pointer already exists.

#### `darwin pointer update --key <FILE> <TARGET> [--kind chunk|pointer]`

Point it at `TARGET`, one past the counter the network serves (or create it).
Requires `SECRET_KEY` to pay for the new state.

#### `darwin pointer get <ADDRESS>`

Print a pointer's counter, target and state. The close group and the bootstrap
peers nearest the pointer (nine at most) are asked at once, and the newer state
either set agrees on is printed. Once a final state has been named (see
`darwin pointer transfer`), a set's answer is the final state a majority of it
holds. Two final states that no majority holds are a fork, and the read fails,
unless the fork is among the bootstrap peers and the close group holds a final
state. `darwin pointer update` first asks every peer of the close group, and is
refused before paying if any peer that answers holds a final state.

```
$ darwin pointer get 9f3c...
address:  9f3c...
counter:  1
kind:     chunk
target:   a1b2...
state_id: 5e7d...
```

#### `darwin pointer resolve <ADDRESS>`

Follow a chain of pointers to the target at its end.

#### `darwin pointer transfer --key <FILE> <RECIPIENT>`

Hand the pointer over for good to the pointer at `RECIPIENT` (hex), which the
new owner creates first, with a fresh key for each pointer they receive.
Requires `SECRET_KEY` to pay for the final state, which is paid as any pointer
write is (above). Refused before paying if any
peer of the close group holds a final state for the pointer, if not every peer
of the group answers, or if `RECIPIENT` does not exist or leads back to this
pointer. Irreversible once stored. Prints the stored state and the result of
`finality`; a failed `finality` check after the write does not mean the
transfer failed.

#### `darwin pointer finality <ADDRESS>`

Ask every peer of the close group whether a pointer is final, and on what.
`finality` asks the close group and the bootstrap peers nearest the address;
it reports a pointer open with no state only when neither holds one. While
the close group shows no final state, the pointer is read as
`darwin pointer get` reads it, from the close group and the bootstrap peers
nearest it (nine at most), and a `seeds:` line says how many of those were
asked and answered and what they hold. Final, unconfirmed, settling and
forked are otherwise the close group's to decide.

- `open` — no peer of the close group that answered holds a final state, and
  the read returns none; its owner can still move it. The counter is the one
  of the state that read returns, whichever set holds it. With no state, it
  is reported only once every bootstrap peer asked has answered or failed.
  Check `answered`: a peer of the close group that did not answer could hold
  a final state. A read that fails fails the check too, as `darwin pointer
  get` would.
- `settling` — one final state, not yet on a majority of the group; or one
  only the bootstrap peers hold (held by 0 of the group).
- `unconfirmed` — one final state on a majority, but not every peer answered,
  so a rival could be unseen. Ask again.
- `final` — one final state, held by a majority, every peer answered and none
  holds a rival. The only status to rely on before treating a transfer as
  done.
- `forked` — its owner signed more than one final state. Reads return the one a
  majority holds, or fail if none does.

```
$ darwin pointer finality 9f3c...
address:  9f3c...
answered: 7 of 7
status:   final
state:    pointer 4b1e... (state 77a0..., held by 7 of 7)

$ darwin pointer finality 2d08...
address:  2d08...
answered: 7 of 7
status:   open (counter 3; its owner can move it)
seeds:    5 of 9 answered; 5 hold counter 3 (state c41f...)
```

#### `darwin pointer controller <ADDRESS>`

Follow a pointer's transfers to the pointer whose owner now decides what it
resolves to.

### `darwin wallet` — Wallet Operations

Inspect the EVM wallet derived from `SECRET_KEY`.

#### `darwin wallet address`

Print the wallet's EVM address.

```
$ SECRET_KEY=0x... darwin wallet address
0x1234567890abcdef...
```

#### `darwin wallet balance`

Print the wallet's payment-token balance (DARWIN by default) in its smallest unit, 10⁻¹⁸ of a token.

```
$ SECRET_KEY=0x... darwin wallet balance
1000000000000000000
```

### `darwin node` — Node Management

Off in this build: every `darwin node` command exits with an error, before it downloads, writes
or starts anything, or reaches the network. Upstream's node manager would install Autonomi's
`ant-node` from WithAutonomi's GitHub releases, and those nodes join Autonomi's network and take
payment on Arbitrum; its log forwarding (`darwin node logs forward`) ships node logs to
Autonomi's endpoint, and its daemon serves both through a REST API. Darwin storage nodes run from
the storage-node image (see the darwin-node repository's `docker/README.md`). Nodes added by an
earlier build are managed with Autonomi's `ant`.

### `darwin update` — Self-Update

Off in this build: `darwin update` exits with an error. Upstream's release feed (the `ant-cli-v*`
releases of `WithAutonomi/ant-client`) would replace `darwin` with Autonomi's `ant`, and Darwin
publishes no releases yet. Update by building a new `darwin` or taking the latest
`darwin-linux-x64` CI artifact.

---

## Beta Programme

Off in this build. Upstream's beta programme is Autonomi's, for `ant` and `ant-node`: beta builds
of the client through `darwin update`, nodes on the beta channel through
`darwin node add --upgrade-channel beta`, and the optional forwarding of node logs to Autonomi's
beta log endpoint through `darwin node logs forward`. Darwin has no beta channel, and
`darwin update` and `darwin node` are off.

---

## REST API

Off in this build: the REST API is served by the node daemon (`darwin node daemon`), which
`darwin` never starts while `darwin node` is off. `ant-core` still holds upstream's daemon
(`ant_core::node::daemon`).

---

## Rust Library API (`ant-core`)

The `ant-core` crate exposes the full API programmatically. Add it as a dependency:

```toml
[dependencies]
ant-core = { path = "ant-core" }
```

### Connecting to the Network

```rust
use ant_core::config::{self, bundled_payment_network, resolve_bootstrap_multiaddrs};
use ant_core::data::{Client, ClientConfig};

// Connect through the bundled seeds (or a config file's; see the bootstrap section below)
let peers = resolve_bootstrap_multiaddrs(&[], None)?;
let client = Client::connect_multiaddrs(&peers, ClientConfig::default()).await?;

// Attach a wallet for paid operations (uploads), on the bundled network: Robinhood Chain, DARWIN.
// It signs for chain 4663 only, refusing an RPC that reports another chain.
let network = bundled_payment_network()?;
let wallet = config::wallet(network.clone(), "0xprivate_key...", config::chain_id(&network))?;
let client = client.with_wallet(wallet);
client.approve_token_spend().await?;
```

### Uploading and Downloading Files

```rust
use std::path::Path;
use ant_core::data::{EnvelopeOptions, PaymentMode};

// Upload a file (streamed, never fully loaded into memory) as `darwin file upload`
// stores it: in a private envelope that shows every payment field, paid per chunk.
// `result.envelope` holds the envelope, its salt and the record proving its payment
// (save the record, then call `forget_upload_record`: see below).
let result = client.file_upload(Path::new("photo.jpg")).await?;
println!("Stored {} chunks", result.chunks_stored);

// Readable by anyone with its address, as `darwin file upload --public` stores it:
// the data map in an unlisted envelope (`file_upload_public_with_mode` does the same).
let options = EnvelopeOptions::unlisted();
let public = client
    .file_upload_with_visibility_and_progress(
        Path::new("photo.jpg"), PaymentMode::Single, options.into_visibility(), None)
    .await?;
let address = public.data_map_address.expect("the envelope's address");

// Download a public file: the data map is read from its envelope.
let data_map = client.data_map_fetch(&address).await?;
client.file_download(&data_map, Path::new("photo_copy.jpg")).await?;
```

### Uploading and Downloading In-Memory Data

```rust
use bytes::Bytes;
use ant_core::data::EnvelopeOptions;

// Raw: `data_upload` (and `data_upload_with_mode`) stores the content's chunks with no
// envelope, so no payment record, listing or `.record`. Keep the data map: nothing else
// leads back to the content.
let result = client.data_upload(Bytes::from("hello darwin")).await?;

// The standard way stores an envelope: upload a file with `file_upload`, or prepare
// in-memory content with an envelope for an outside signer to pay, then `finalize_upload`.
let prepared = client
    .data_prepare_upload_with_visibility(
        Bytes::from("hello darwin"), EnvelopeOptions::private().into_visibility())
    .await?;

// Download and decrypt with a data map
let content = client.data_download(&result.data_map).await?;
```

### Envelopes, Proofs and Listings

```rust
use ant_core::ant_listings::{Metadata, PaymentField};
use ant_core::data::{EnvelopeOptions, ListingChain, PaymentMode, WalkState};

// A private upload whose envelope hides its tx hash, with a name.
let options = EnvelopeOptions::private()
    .hiding([PaymentField::TxHash])
    .with_metadata(Metadata { content_type: None, name: Some("photo.jpg".into()) });
for warning in options.warnings() {
    eprintln!("warning: {warning}");
}
let result = client
    .file_upload_with_visibility_and_progress(
        Path::new("photo.jpg"), PaymentMode::Single, options.into_visibility(), None)
    .await?;
// The envelope, the salt of a private one, and the record proving its payment.
let envelope = result.envelope.expect("an envelope");
let record = envelope.proof.clone().expect("this upload paid for the envelope");
// Save the record, then drop the copy the upload kept until it was saved.
ant_core::datamap_file::write_record(Path::new("photo.jpg.record"), &record)?;
ant_core::data::forget_upload_record(&envelope.address())?;

// Anyone can check a proof from the chain alone.
let chain = ListingChain::new(&evm_network)?;
let proven = chain.check_proof(&record).await?;

// The index, merged across nodes and checked; one listing by address. The
// walk state carries walks a read stopped early on to the next read.
let mut state = WalkState::default();
let index = client.index_listings_with(0, &chain, &mut state).await?;
let one = client.listing(&envelope.address(), &chain).await?;
// Knowing the network's size from that read, only the nearest nodes are looked up.
let again = client
    .listing_with(&envelope.address(), &chain, Some(index.nodes_asked))
    .await?;
```

`index_listings` and `listing` merge, date, check and decide listings as the nodes do when they repair one. `listing` also finds how many nodes the network has, with the lookups a read makes to find nodes to walk, so that a lookup of the address that comes back short can't lower the quorum; `listing_with` takes that size from a caller that knows it, such as a recent read's `nodes_asked`, and then makes only the lookup of the nodes nearest the address; a size under 7 is found again, as `listing` finds it, so no size given lowers the quorum. `index_listings_with` carries on from the `WalkState` of earlier reads (save it between them: it serialises), where `index_listings` starts afresh, and `ListingsIndex::carry` says what to do with a listing an earlier read published: replace it with what this read decided, keep it, or drop it because the network no longer stores its file (only after a read of the whole index, from time 0). An indexer of its own can use the same rules from `ant_core::data::client::listings`: `listing_to_check` (what to look up on chain for a group of copies), `check_copies` (the group's date and check, given what was fetched), `quorum_listing` and `decide_address`, with `ant_listings::IndexWalk` to walk the nodes' indexes.

The index can also be published as small static files, `listings/v1/`: the newest entries, shards by address, name and content type, pages of the whole index, and a feed of every change, each file replaced only when it changes. [docs/listings-v1.md](docs/listings-v1.md) specifies them for readers in any language, and `ant_core::data::client::listings_v1` holds their types and the rules that lay them out.

The upload calls that take no visibility (`file_upload`, `file_upload_with_mode`, `file_upload_with_progress`, `estimate_upload_cost`, `file_prepare_upload` and `data_prepare_upload`) store the private envelope `darwin file upload` stores, `Visibility::default()`, and `file_upload_public_with_mode` and `file_upload_public_with_progress` the unlisted one `--public` stores. `Visibility::Private` and `Visibility::Public` upload exactly as they always have, with no envelope, when asked for by name; `EnvelopeOptions::into_visibility` picks them when no envelope is needed. The raw building blocks (`data_upload`, `data_upload_with_mode`, `chunk_put`, `chunk_put_with_proof`, `data_map_store`, `upload_records`, `upload_records_then`, `batch_upload_chunks`, `pay_for_storage`, `SingleNodeQuotePayment::from_quotes` and `pay`) store or pay with no envelope; their documentation says what else each leaves out and what to use instead. An envelope upload's checkpoint and kept record belong to whoever pays: the wallet, or an `UploadPayer`'s `checkpoint_scope()`, which a payer serving several accounts must set to each account's id, so one account never resumes another's interrupted upload or gets its record. An `UploadPayer`'s upload without an envelope has a checkpoint of its own too, so uploads of the same file by different payers neither share a payment nor wait for each other's (an upload holds its checkpoint's lock while its payment is awaited). Only a wallet upload without an envelope shares its file's checkpoint, as before. `file_upload_with_payer` and the external-signer `file_prepare_upload_with_mode`/`finalize_upload*` take `Visibility::Envelope` too; the external path pays an envelope upload per chunk, in one wave batch (its payment intent lists the quotes in quote-hash order: pay them in that order), and fills in the record at finalize once every chunk is stored (unchecked if the client has no EVM network). It refuses, before quoting, an envelope upload the payment mode would pay in merkle batches (`PaymentMode::Auto` from 64 chunks, or `PaymentMode::Merkle`): use `file_upload_with_payer`, or `PaymentMode::Single` to pay every chunk per chunk with all of them held in memory.

Paid quotes are read back from the vault (see "How it works" above) by the upload engine (`file_upload*`, `file_upload_with_payer`, `upload_records`, `batch_upload_chunks`), by `pay_for_storage` (so `chunk_put` and pointer create, update and transfer), and, before anything is stored, by `finalize_upload`, `finalize_upload_resumable`, `finalize_chunk` and `pointer_put_paid`, which store what a payer outside the client paid. These four read through the client's EVM network, so build the client `with_evm_network` (or `with_wallet`): one with neither, as an outside signer's client may be, reads nothing back and logs a warning. A finalize can't quote a chunk again: one whose quote was occupied isn't sent and fails with a `quotes occupied` error naming the node, the envelope is held back, the cost reported leaves the skipped payment out, and a resume handle leaves the chunk out and lists it (`WaveFinalizeResume::occupied`), so prepare the upload again; `finalize_chunk` and `pointer_put_paid` refuse it before sending. The merkle finalize paths, the raw building blocks `batch_pay`, `chunk_put_with_proof`, `finalize_batch_payment` and `SingleNodeQuotePayment::pay`, and the browser build read nothing back; `batch_upload_chunks` is the batch path that does. Records are read through the payment network's RPC and, on the bundled network, the RPCs reads of payments fall back to.

### Records paid one at a time

`pay_for_storage` and `pay_for_storage_split` pay for one record, a chunk or a pointer's state, as `chunk_put`, `data_map_store` (so `publish_data_maps`), `pointer_put` and pointer create, update and transfer do. With the client's wallet, such a payment is journaled as an upload's is: before its transaction is signed, the payment is saved in a checkpoint under the data directory, `payments/record/`, named by the payment network, the wallet and the record's address (a pointer's `state_id`), and its lock is held while the record is paid for and stored. When the RPC answers the payment with an error and its outcome is unknown, the chain is checked again 10 seconds later. If the outcome is still unknown, the call fails with a payment error and the journal stays, and the next call for the same record with the same wallet on the same network reconciles the journaled transaction from the chain, sending at most the same signed transaction again, instead of paying again. Once paid, the proof stays in the checkpoint until the record is stored: `chunk_put` and `pointer_put` remove the checkpoint after the store, so a record whose store failed is stored by the next call with that proof (a chunk on the targets a fresh quote names), while `pay_for_storage` and `pay_for_storage_split`, whose callers store the record themselves, remove it once they return the proof. A call that fails with neither a journal nor a proof to keep, as when the payment was refused before anything was sent, removes it too. A proof too old for nodes to take is not used again: the record is quoted and paid again. The `darwin` commands that pay for single records (`chunk put`, `pointer create`, `update` and `transfer`, `manifest export --compact --yes`) say after a payment error that running the same command again carries on without paying twice. Browser builds keep no such checkpoint.

### Low-Level Chunk Operations

```rust
use ant_core::data::XorName;

// Store a single chunk (< MAX_CHUNK_SIZE bytes)
let address: XorName = client.chunk_put(Bytes::from("small data")).await?;

// Retrieve it
if let Some(chunk) = client.chunk_get(&address).await? {
    println!("Got {} bytes", chunk.content.len());
}

// Check existence without downloading
let exists: bool = client.chunk_exists(&address).await?;
```

### Payment Modes

Darwin supports two payment strategies:

| Mode | Description |
|------|-------------|
| `PaymentMode::Single` | Default. Per-chunk payments, in transactions of up to 64 chunks; every paid quote's vault record is read back, and an occupied quote is quoted and paid again (see "How it works" above). |
| `PaymentMode::Merkle` | Single EVM transaction for a batch of chunks via merkle proof. Darwin's nodes refuse batch payments (the DARWIN vault lets the payer steer a batch's payout and can charge a re-sent batch twice), so it fails before paying. |
| `PaymentMode::Auto` | Merkle from 64 chunks, otherwise per chunk; since nodes refuse batch payments, from 64 chunks it falls back to per-chunk payments. |

`PaymentMode::default()`, `Client::file_upload` and the browser API (no `paymentMode`) pay per chunk. Until 2026-10 they defaulted to `Auto`.

`ClientConfig::max_chunk_price` sets a price ceiling, the most a node's quote may ask to store one chunk, in the token's base units (`None`, the default: no ceiling). Every quote the client collects is checked against it, for its own wallet, an `UploadPayer` or the external-signer preparation, and so is every merkle candidate: one asking more is dropped as if its node hadn't answered, and the payment planner refuses to plan a payment on one. A chunk then costs at most 3 times the ceiling. A payment planned before the ceiling was set or lowered, and saved by an interrupted upload, is resumed as saved, so it is never made twice.

### Local Development with Devnet

Two ready-made examples spin up a local network and write a manifest to the shared data directory (`~/.local/share/ant/` on Linux, `~/Library/Application Support/ant/` on macOS, `%APPDATA%\ant\` on Windows). Any consumer that checks this directory — ant-gui, ant-cli, ant-tui — will auto-detect the devnet.

```bash
# Local Anvil devnet (25 nodes + embedded EVM blockchain)
# Includes a pre-funded wallet key in the manifest
cargo run --release --example start-local-devnet

# Sepolia testnet devnet (25 nodes + real Arbitrum Sepolia contracts)
# No wallet key — connect your own funded Sepolia wallet
cargo run --release --example start-devnet-sepolia
```

Both write `devnet-manifest.json` to the shared data dir and clean it up on Ctrl+C.

The [ant-gui](https://github.com/WithAutonomi/ant-ui) desktop app auto-detects the manifest on startup and switches to devnet/Sepolia mode — no manual configuration needed. The manifest can also be passed to the CLI explicitly via `--devnet-manifest <path>`.

#### Programmatic usage

```rust
use ant_core::data::LocalDevnet;

// Start a devnet (25 nodes + Anvil EVM chain)
let devnet = LocalDevnet::start(DevnetConfig::default()).await?;

// Create a client with a pre-funded wallet (ready to upload)
let client = devnet.create_funded_client().await?;

// Write manifest for discovery by other tools
let manifest_path = ant_core::config::data_dir()?.join("devnet-manifest.json");
devnet.write_manifest(&manifest_path).await?;

// Clean up
devnet.shutdown().await?;
```

### Chunk Cache

The client includes an in-memory LRU cache for recently accessed chunks:

```rust
let cache = client.chunk_cache();
cache.put(address, content);
if let Some(data) = cache.get(&address) { /* ... */ }
```

### Node Management (Programmatic)

`ant-core` keeps upstream's node manager, which `darwin node` used before it was turned off. It
installs and runs Autonomi's `ant-node`, which joins Autonomi's network, not Darwin's, and takes
payment on Arbitrum. Darwin storage nodes run from the storage-node image.

```rust
use ant_core::node::{add_nodes, AddNodeOpts, BinarySource};
use ant_core::node::binary::NoopProgress;
use ant_core::config::data_dir;

let opts = AddNodeOpts {
    count: 3,
    rewards_address: "0xYourWallet".to_string(),
    binary_source: BinarySource::LocalPath("/path/to/antnode".into()),
    ..Default::default()
};

let result = add_nodes(opts, &data_dir()?.join("node_registry.json"), &NoopProgress).await?;
```

---

## Architecture

The node manager below is upstream's, kept in `ant-core`. `darwin node` is off in this build, so
`darwin` never starts its daemon.

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

The daemon manages node processes, exposing a REST API on localhost. No admin privileges required. The CLI, web UI, and AI agents all communicate over HTTP.

Data operations (upload/download) go directly to the P2P network — they do not require the daemon. The daemon is only needed for node management.

## Project Structure

```
├── ant-core/                    # Headless library — all business logic
│   ├── src/
│   │   ├── lib.rs
│   │   ├── config.rs            # Platform-appropriate data/log paths
│   │   ├── error.rs             # Unified error type
│   │   ├── data/                # Data storage and retrieval
│   │   │   ├── mod.rs           # Re-exports and module declarations
│   │   │   ├── error.rs         # Data operation errors
│   │   │   ├── network.rs       # P2P network wrapper
│   │   │   └── client/          # High-level client API
│   │   │       ├── mod.rs       # Client, ClientConfig
│   │   │       ├── chunk.rs     # chunk_put, chunk_get, chunk_exists
│   │   │       ├── data.rs      # data_upload, data_download, data_map_store/fetch
│   │   │       ├── file.rs      # file_upload, file_download (streaming)
│   │   │       ├── payment.rs   # pay_for_storage, approve_token_spend
│   │   │       ├── quote.rs     # get_store_quotes from peers
│   │   │       ├── merkle.rs    # Merkle batch payment (PaymentMode)
│   │   │       └── cache.rs     # In-memory LRU chunk cache
│   │   └── node/                # Node management
│   │       ├── mod.rs           # add_nodes, remove_node, reset
│   │       ├── types.rs         # DaemonConfig, NodeConfig, AddNodeOpts, etc.
│   │       ├── events.rs        # NodeEvent enum, EventListener trait
│   │       ├── binary.rs        # Binary resolution, ProgressReporter trait
│   │       ├── registry.rs      # Node registry (CRUD, JSON, file locking)
│   │       ├── devnet.rs        # LocalDevnet (local network + Anvil EVM)
│   │       ├── daemon/
│   │       │   ├── mod.rs
│   │       │   ├── client.rs    # Daemon client (start/stop/status via HTTP)
│   │       │   ├── server.rs    # HTTP server (axum), REST API handlers
│   │       │   └── supervisor.rs # Process supervision with backoff
│   │       └── process/
│   │           ├── mod.rs
│   │           ├── spawn.rs     # Spawning node processes
│   │           └── detach.rs    # Platform-specific session detachment
│   └── tests/                   # Integration tests
├── ant-cli/                     # CLI binary (thin adapter layer)
│   └── src/
│       ├── main.rs              # Entry point, client/wallet initialization
│       ├── cli.rs               # clap argument definitions
│       └── commands/
│           ├── data/
│           │   ├── file.rs      # darwin file upload/download
│           │   ├── chunk.rs     # darwin chunk put/get
│           │   └── wallet.rs    # darwin wallet address/balance
│           └── node/            # darwin node: off in this build
│               ├── add.rs       # darwin node add
│               ├── daemon.rs    # darwin node daemon start/stop/status/info/run
│               ├── logs.rs      # darwin node logs forward enable/disable/status
│               ├── start.rs     # darwin node start
│               ├── stop.rs      # darwin node stop
│               ├── status.rs    # darwin node status
│               └── reset.rs     # darwin node reset
└── docs/                        # Architecture documentation
```

## EVM Networks

| Value | Network | Use case |
|-------|---------|----------|
| `robinhood` | Robinhood Chain (4663), DARWIN, from `ant-core/resources/payment_network.toml` | Default: the Darwin network |
| `local` | Custom (Anvil) | Local development (requires `--devnet-manifest`) |

Payments are made in DARWIN only. Upstream's `arbitrum-one` and `arbitrum-sepolia` presets, which
pay Autonomi's ANT on Arbitrum, are refused when the command line is read, before `SECRET_KEY` or
the network, and `ant_core::config::resolve_evm_network` refuses them too.

Payments on `robinhood` are signed for chain 4663 only: an RPC that reports another chain is refused before anything is signed. On `local` the same check uses the devnet manifest's `evm.chain_id` when it has one (`"chain_id": 4663` for your own Robinhood Chain RPC); without one, payments are signed for whatever chain the RPC reports.

## Environment Variables

| Variable | Required for | Description |
|----------|-------------|-------------|
| `SECRET_KEY` | Uploads, wallet commands | EVM private key (hex, with or without `0x` prefix) |

## Development

```bash
# Build
cargo build

# Run all tests
cargo test --all

# Lint
cargo clippy --all-targets --all-features -- -D warnings

# Format check
cargo fmt --all -- --check

# Run the CLI
cargo run --bin darwin -- --help
cargo run --bin darwin -- file upload photo.jpg --public --devnet-manifest ~/.local/share/ant/devnet-manifest.json --allow-loopback --evm-network local
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

## Bootstrap multiaddresses and browser defaults

`ant-core/resources/bootstrap_peers.toml` is the shared release resource. Its
`quic` list holds both nodes of every storage server (ports 10000 and 10001),
each with its `/p2p/` peer ID. Its `webrtc` list holds every node's WebRTC
Direct address (ports 11000 and 11001) with its certificate hash and peer ID,
the same list as storage-viewer's `network.json`; a node's entries change when
its identity or certificate does. A node's QUIC port is its WebRTC port minus
1000, under the same peer ID.

The CLI accepts `--bootstrap /ip4/127.0.0.1/udp/10000/quic` (including optional
`/p2p/<peer-id>`). Legacy `ip:port` arguments and a `peers = [...]` list in the
seed file remain readable. Explicit peers take precedence over a selected
devnet manifest, which takes precedence over a `darwin_bootstrap_peers.toml` in
the config directory, which takes precedence over the bundled seeds. Only QUIC seeds
are selected for native dialing. `darwin -v` logs "using N bundled bootstrap
seed(s)" when it falls back to the bundled ones.

Chunk and pointer reads also ask the bootstrap peers whose peer IDs the client
knows (the selected QUIC seeds that carry `/p2p/<peer-id>`, or a browser
client's seeds): the nine nearest the address read, or all of them when there
are fewer. The nodes that were nearest to a record when it was stored may still
hold it after the nodes nearest to it have changed. Nine is the nodes' storage
retention width, the close group of seven plus a margin of two: a node is
responsible for a record, and replication stores it there, while the node is
among the nine nodes nearest the record by its own routing table. A bootstrap
peer that is among the nine nodes nearest an address out of the whole network is
also among the nine nearest out of the bootstrap peers, so the nine bootstrap
peers nearest the address include every bootstrap peer responsible for the
record. An upload can also leave a chunk farther out: it moves past close-group
nodes that fail or are full to the next nearest, up to the twentieth, and nodes
keep what they hold while their disk has room. A copy left that way on a
bootstrap peer past the ninth is not looked for there.

A chunk read asks them from the start of each round, nearest to the chunk first
and one at a time, in one of its two GET slots; discovery's hints, then the
close group, keep the other, so a slow or silent bootstrap peer holds up only
the next one. It reports a chunk missing only once each of them has answered.
A pointer read asks them from the start and the close group once it is found,
each set on its own quorum and corroboration (a peer in both is asked once; of
nine bootstrap peers, five must answer and two name the state), and returns the
newer of the two states: a state the bootstrap peers agree on is returned even
when the close group holds none or does not answer. When the close group has a
state, the read waits for a quorum of the bootstrap peers; when it has none, for
all of them, so it takes as long as the slower set, up to the GET timeout when a
bootstrap peer doesn't answer. Bootstrap addresses without a peer ID are only
dialled, as before.

So every read reaches the bootstrap peers: a chunk read sends its first GET to
the one nearest the chunk, connected or not, and one to each of them in a round
that finds nothing; a pointer read sends one to each of them that is not in the
close group, all at once, dialling any it is not yet connected to. With the 16
bundled seeds, a read asks nine of them as bootstrap peers, not all 16. A chunk
read can still reach other seeds the way it reaches any node: as discovery's
hints, or among the known peers (20 at most) a round falls back to before it
reports a chunk missing.

The config directory is `ant`'s: `~/.config/ant` on Linux,
`~/Library/Application Support/ant` on macOS, `%APPDATA%\ant` on Windows.
`darwin` reads its seed file there only as `darwin_bootstrap_peers.toml`, never
the `bootstrap_peers.toml` that Autonomi's `ant` and its installers write, which
names Autonomi's network; and its peer cache, whose peers are dialled before the
seeds, is `darwin_client_peer_cache.json` in the data directory, never `ant`'s
`client_peer_cache.json`. So `darwin` keeps to its own network on a machine that
also has `ant`. Before, it joined Autonomi's network there; the price check
refused to pay Autonomi's nodes, but uploads and lookups went to them.

Native library callers can use `config::resolve_bootstrap_multiaddrs()` and
`Client::connect_multiaddrs()` to retain peer pins, which reads then use; a
client built from a node (`Client::from_node`) gets them through
`Client::with_bootstrap_peers()`, and `Network::bootstrap_peers()` lists them.
Existing socket-address APIs remain available. `network_defaults::browser_mainnet_defaults()` and the WASM
`mainnetNetworkDefaults()` export return the bundled WebRTC seeds, the payment
identity (chain 4663, the DARWIN token and vault) and the bundled RPC URL,
without connecting to any network.

To change the seeds, edit the TOML resource, commit it, and rebuild the WASM
artifact for browser apps that use these defaults.
See [ADR-0005](docs/adr/ADR-0005-bootstrap-multiaddresses.md).
