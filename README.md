# ant — Autonomi Network Client

A unified CLI and Rust library for storing data on the Autonomi decentralized network and managing Autonomi nodes.

## Overview

This project provides two Rust crates:

- **ant-core** — A headless Rust library containing the Autonomi business logic: data storage/retrieval with self-encryption and EVM payments, node lifecycle management, and local devnet tooling. Its `browser` module shares manifest validation, protocol framing, authenticated WebRTC Direct access, lookup, quote verification, and complete public-file workflows with browser applications through the `browser-wasm` feature.
- **ant-cli** — A thin CLI binary (`ant`) built on `ant-core`.

Data on Autonomi is **content-addressed**. Files are split into encrypted chunks (via [self-encryption](https://en.wikipedia.org/wiki/Convergent_encryption)), each stored at an XOR address derived from its content. A `DataMap` tracks which chunks belong to a file. Payments for storage are made on an EVM-compatible blockchain (Arbitrum).

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

Native and WASM reads share `ant-core/src/client_engine/read.rs` and
`client_engine/files.rs`. The engine owns XOR-ordered peer selection, bounded
known-peer fallback, close-group retries, adaptive batch scheduling, deferred
file retries, recursive DataMap resolution, and plaintext range reads. Both
transports use `record.rs` for BLAKE3 verification. Native
`Client::data_download_range` and the browser media reader call the same range
implementation.

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
without paying again.

Browser protocol v5 and browser manifest v6 advertise only the payment chain ID
and token/vault addresses. RPC providers belong to the application or wallet;
the node's verification RPC URL is never sent to the browser. Paid uploads
check that every selected node advertises the same chain and contracts. Deploy
matching node, Rust/WASM client, and SDK versions together.

## Installation

### Linux / macOS

```bash
curl -fsSL https://raw.githubusercontent.com/WithAutonomi/ant-client/main/install.sh | bash
```

### Windows

```powershell
irm https://raw.githubusercontent.com/WithAutonomi/ant-client/main/install.ps1 | iex
```

> **Note:** the `curl ... | bash` installer is for Linux/macOS only. Running it inside WSL installs a Linux binary that is only usable from within WSL — to use `ant` from PowerShell or cmd, install with the PowerShell command above.

Both installers take the same environment variables:

| Variable | Description |
|----------|-------------|
| `ANT_CHANNEL` | Release channel: `stable` (default) or `beta`. See [Beta Programme](#beta-programme). |
| `ANT_VERSION` | Install one specific version, e.g. `0.3.3`. Overrides `ANT_CHANNEL`. |
| `INSTALL_DIR` | Where to put the binary. Defaults to `~/.local/bin` on Linux, `/usr/local/bin` on macOS, `%LOCALAPPDATA%\ant\bin` on Windows. |

### npm

`ant` is also on npm, which is useful in agent sandboxes and CI runners that allow
package-manager traffic but block direct binary downloads:

```bash
npm install -g @withautonomi/ant
```

This installs the same signed binary as the release page — a per-platform companion package
carries it, so only the one your machine needs is downloaded. Use `@withautonomi/ant@beta` for
the beta channel, and `npm update -g @withautonomi/ant` to upgrade; `ant update` recognises an
npm-managed install and points you at npm rather than replacing itself.

> **Note:** npm 12 blocks package install scripts by default, so an npm install may not write
> `bootstrap_peers.toml` into your config directory. `ant` works either way — it falls back to
> the bootstrap seeds compiled into the binary — but if you want the editable file, install with
> `npm install -g --allow-scripts=@withautonomi/ant @withautonomi/ant`. See
> [`npm/README.md`](npm/README.md).

## Quick Start

### Store and retrieve a file (production)

```bash
# Upload (private — DataMap saved locally)
SECRET_KEY=0x... ant file upload photo.jpg -b 1.2.3.4:12000
# Output:
#   Upload complete!
#     Datamap: photo.datamap
#     Chunks:  3

# Download using the local DataMap
ant file download --datamap photo.datamap -o photo_copy.jpg -b 1.2.3.4:12000
```

### Store and retrieve a file (local devnet)

```bash
# 1. Start a local devnet (spins up 25 nodes + a local Anvil EVM chain)
cargo run --release --example start-local-devnet

# 2. Upload a file (the manifest is auto-written to the shared data dir)
SECRET_KEY=0x... ant file upload photo.jpg --public \
    --devnet-manifest ~/.local/share/ant/devnet-manifest.json --allow-loopback --evm-network local

# 3. Download it back
ant file download abc123... -o photo_copy.jpg \
    --devnet-manifest ~/.local/share/ant/devnet-manifest.json --allow-loopback --evm-network local
```

### Store and retrieve a file (Arbitrum mainnet)

```bash
# Upload (private — DataMap saved locally)
SECRET_KEY=0x... ant file upload photo.jpg \
    --bootstrap 1.2.3.4:12000 --evm-network arbitrum-one
# Output: DATAMAP_FILE=photo.jpg.datamap

# Download using the local DataMap
ant file download --datamap photo.jpg.datamap -o photo_copy.jpg \
    --bootstrap 1.2.3.4:12000 --evm-network arbitrum-one
```

### Low-level chunk operations

```bash
# Store a single chunk (< 1 MB)
echo "hello autonomi" | SECRET_KEY=0x... ant chunk put --bootstrap ...
# Output: abc123def456...

# Retrieve it
ant chunk get abc123def456... --bootstrap ...
# Output: hello autonomi
```

---

## CLI Reference

### Global Flags

| Flag | Description |
|------|-------------|
| `--json` | Output structured JSON instead of human-readable text |
| `-b, --bootstrap <IP:PORT>` | Bootstrap peer addresses, comma-separated or repeated (`-b 1.2.3.4:10000,5.6.7.8:10000`) |
| `--devnet-manifest <PATH>` | Path to devnet manifest JSON file |
| `--allow-loopback` | Allow loopback connections (required for local devnet) |
| `--timeout-secs <N>` | Network operation timeout in seconds (default: 60) |
| `-v, --verbose` | Increase verbosity: `-v` info, `-vv` debug, `-vvv` trace. Default: no logs (privacy by design) |
| `--evm-network <NET>` | EVM network: `arbitrum-one` (default), `arbitrum-sepolia`, or `local` |

### `ant file` — File Operations

Upload and download files with automatic chunking, self-encryption, and EVM payment.

#### `ant file upload <PATH>`

Upload a file to the network. The file is split into encrypted chunks, each paid for via the configured EVM network. Requires `SECRET_KEY` environment variable.

```
$ SECRET_KEY=0x... ant file upload my_data.bin --public
warning: the payment fields shown give away the paying wallet to anyone with the envelope's address
Encrypted into 7 chunks

Upload complete!
  Address:  a1b2c3d4e5f6...
  Payment:  all fields shown
  Record:   my_data.bin.record
  Chunks:   7 (6 + 1 envelope)
  Size:     439.5 KB
  Cost:     0.0042 ANT (gas: 0.000150 ETH)
  Time:     12.3s

Anyone can download this file with:
  ant file download a1b2c3d4e5f6... -o <FILE>
Prove this upload to anyone with:
  ant file prove my_data.bin.record
```

The `warning:` and `Encrypted` lines go to stderr. The default, a private upload, keeps the data map local and says what its envelope makes public:

```
$ SECRET_KEY=0x... ant file upload my_data.bin
warning: the payment fields shown give away the paying wallet to anyone with the envelope's address
Encrypted into 7 chunks

Upload complete!
  Datamap:  my_data.bin.datamap
  Envelope: 9f8e7d6c5b4a... (its payment record is public, the file is not)
  Payment:  all fields shown
  Record:   my_data.bin.record
  Chunks:   7 (6 + 1 envelope)
  Size:     439.5 KB
  Cost:     0.0042 ANT (gas: 0.000150 ETH)
  Time:     12.1s

Download this file with:
  ant file download --datamap my_data.bin.datamap
Prove this upload to anyone with:
  ant file prove my_data.bin.record
Keep the record as safe as the data map: it holds the data map and the salt, so it reads the file, and its salt is what proves which file this is. `ant file prove --no-reveal` proves only the payment.
```

Mistakes in `--hide`, `--name` or `--content-type` are reported before `SECRET_KEY` is read or the network is joined.

**Options:**

| Flag | Description |
|------|-------------|
| `--readable <yes\|no>` | Whether anyone with the address can read the file. `no` (default): the data map is saved to a local `.datamap` file, and the envelope stores only a salted hash of it. `yes`: the data map is stored on the network. |
| `--index <yes\|no>` | Whether the file appears in the network's listings index (see `ant listings`). Default `no`. |
| `--visibility <private\|unlisted\|listed>` | Shorthand for the two above: `private` (`no`, `no`; the default), `unlisted` (`yes`, `no`) or `listed` (`yes`, `yes`). The fourth combination, `--readable no --index yes`, is a public, dated record of a file nobody can read until you reveal it. |
| `--public` | Same as `--visibility unlisted`. |
| `--hide <FIELDS>` | Payment fields to hide, comma-separated: `tx-hash`, `block`, `timestamp`, `log-index`, `quote`, or `all`. All five are shown by default. |
| `--name <NAME>` | A name stored in the envelope, on any visibility (1–255 bytes, no control characters or path separators). Public and permanent. |
| `--content-type <TYPE>` | A content type stored in the envelope, as `type/subtype`, on any visibility. Public and permanent. |
| `--merkle` | Force merkle batch payment from 2 chunks, instead of from 64. Reduces gas costs for multi-chunk uploads. |
| `--no-merkle` | Disable merkle, always use per-chunk payments. |

**How it works:**
1. The file is streamed through self-encryption in 8KB reads (never fully loaded into memory).
2. Each encrypted chunk is stored on the network at its XOR content address.
3. Payment is made per-chunk or via merkle batch transactions (auto-selected by default when >= 64 chunks). The payment vault charges a batch for the next power of two of its chunks, so an upload is paid in exact power-of-two batches (256, 128, 64 and 32 chunks), and a remainder under 32 chunks is paid per chunk.
4. A `DataMap` is produced that records which chunks compose the file.
5. Unless the upload hides every payment field, is not in the index and has no name or content type, the client stores an **envelope**: a small chunk holding the data map (readable uploads) or a salted hash of it (private uploads), the name and content type, and flags saying which payment fields its listing shows and whether it is in the index. Its address is the file's address. Nodes that keep listings record the envelope's payment, so anyone with the address can check it against the chain. The envelope is paid in the same payment as the content (one payment for any upload under 64 chunks; from 64, with the chunks left after the merkle batches, or alone) and stored after every content chunk, so it never points at missing content.
6. Without an envelope, a readable upload stores the DataMap itself as a chunk and returns its address; a private one stores nothing extra.
7. The client saves the data map of a private upload to `<filename>.datamap`, and the envelope's record to `<filename>.record`: the envelope, its payment's transaction and paid quote, and for a private file the data map and the salt. Keep the record with the data map: it proves the upload from the chain alone (`ant file prove`), even for fields you hid. **A private upload's record reads the file, like the `.datamap`**: whoever has it can download the file (`ant file download --proof`), so keep it as safe as the data map, and hand over `ant file prove --no-reveal` to prove only the payment. Until the record is saved, the client keeps a copy of it under its data directory (`payments/upload/records/<envelope address>.<payer>.record`, the same text as the `.record` file; for a private upload without a record, its salt as `.salt`), so a crash between paying and saving doesn't lose the paid quote and tx hash, which nothing else may hold once the quote is hidden. The upload removes its checkpoint only after that copy is written; a later upload of the same file with the same choices and wallet that finds the envelope already stored gets the kept record back. Saving the `.record` removes the copy.

`ant file cost <PATH>` takes the same `--readable`, `--index`, `--visibility`, `--public`, `--hide`, `--name` and `--content-type` flags, and counts the envelope or data map chunk the upload adds. When the sampled content is already stored, it prices that chunk alone, and says the content is only likely stored unless every content chunk was sampled.

At upload the client warns about what your choices give away: a hidden field that a shown one gives away (a hidden timestamp with the block number shown, for example, or a hidden log index with the tx hash shown when the transaction paid for the envelope alone: a transaction's quotes are paid in quote-hash order, so the envelope's log isn't always its last), a tx hash shown without the quote (the payment can't then be tied to this file), a name or content type on a private file (readable by anyone with the envelope's address, though the file is not), and that shown payment fields, or being listed, show the paying wallet. **Envelopes, their metadata and listings are public and permanent.**

#### `ant file download [ADDRESS]`

Download a file from the network.

```
# Public download (by address)
$ ant file download a1b2c3d4e5f6... -o restored.bin
Connecting to network... done
Downloading from network...
Download complete!
  File: restored.bin
  Size: 439.5 KB
  Time: 3.2s

# Private download (from local DataMap)
$ ant file download --datamap my_data.bin.datamap -o restored.bin
Connecting to network... done
Downloading from network...
Download complete!
  File: restored.bin
  Size: 439.5 KB
  Time: 2.8s
```

**Options:**

| Flag | Description |
|------|-------------|
| `ADDRESS` | Hex-encoded public DataMap or envelope address (64 hex chars). |
| `--datamap <PATH>` | Path to a local `.datamap` file (for private downloads). With an address too (a private file's envelope), the data map is used, and checked against the envelope when the upload's `.record` is next to it. |
| `--proof <PATH>` | Path to an upload record or proof (`ant file prove`) whose envelope carries the data map, or reveals it. |
| `-o, --output <PATH>` | Output file path (default: `downloaded_file`). |

A private file's envelope address can't be downloaded from: its envelope stores only a salted hash of the data map, and the download says so. Use `--datamap`, or `--proof` with a proof that reveals it.

#### `ant file prove <RECORD>`

Writes a proof of an upload from its record (`<filename>.record`) to `<filename>.proof` (or `-o <PATH>`). For a private file the proof reveals the data map and salt, so whoever has it can read the file and check that the envelope is for it; `--no-reveal` proves only that the envelope was paid for. Hand it to anyone who should be able to check the upload, including fields you hid. It never writes over the record (which holds the salt), and replaces an existing proof only with `--force`.

#### `ant file verify <PROOF> [--file <PATH>]`

Checks a proof (or record) against the payment chain alone: the envelope hashes to its address, the quote names it and is signed, and the transaction paid it. Prints the payment (block, time, log index, transaction). With `--file`, also checks that a local file encrypts to the proof's data map. Needs no storage node. A proof shows the address was paid for by a block; it doesn't show who uploaded the file, since anyone who has the envelope can pay for the same address. Only a revealed data map and salt tie a private envelope to its file.

### `ant listings` — The Listings Index

```
$ ant listings
$ ant listings --since 1767225600 --json
$ ant listings --json --state walks.json --carry index.json > index.new.json
```

Collects listings from every node the client can find (`listings.v2`), merges the copies of each (nodes record their own `first_seen` for a listing that hides its time, so copies that differ only there are merged), checks each one as far as its shown fields allow, and prints them in index order: time, address, size, content type, name, the payment fields it hides (`hidden: tx-hash,quote`, or `-` when it shows all five), and the check.

- `verified n/7`: the listing shows its quote, and the payment is checked on chain and tied to this address. Of several payments for one address, the one a quorum of the 7 nodes nearest it serve counts; `(no quorum)` marks the earliest standing in when none has one.
- `reported n/7`: the listing hides its quote. Its shown fields are checked against the chain, and it counts only when at least 4 of the 7 nodes nearest its address serve it (fewer only on a network of fewer than 7 nodes). A lookup that finds fewer of the nearest nodes than the network has never lowers the bar: the listing is left out as "too few nearest nodes found", to try again.

Listings are decided as the nodes decide them when they repair one. Until 4 of the nearest nodes serve one copy of a listing, the nearest nodes not heard from yet are asked for it (a walk of a node's whole index that began well after the listing's time counts as its answer), whether or not it shows its quote. If the payment chain can't be read for the copy 4 of them serve, the address is left out for now, to try again, rather than shown with a copy fewer nodes serve. A copy that can't check out whatever the chain says (it doesn't match its envelope, or its quote names another address or isn't signed) is never looked up on chain. A listing showing its quote is looked up only among the payments of that quote it can describe (at its shown log index, in a block of its shown timestamp), so earlier payments of the same quote by others don't hide the upload's.

A listing that hides its block timestamp shows `~` and the hour it was first seen. Only the dates of the 7 nodes nearest its address count. A listing at least 4 of them serve is dated by the latest of the earliest 4 dates they give, so that 4 of them date it then or earlier: their median when all 7 answer, and with fewer, 3 nodes dating it early can't move it before the date another gives. Any other listing takes the median of its nearest nodes' dates, each checked on its own against the clock and, where the listing locates its payment, the payment's block, with those out of bounds left out.

A read has no cap on how many listings the index holds, and a node can't make it slow by serving listings nobody else has. The client walks every node's index a page at a time: each node is read for 8 pages, and earns 2 more listings' worth of pages for each listing it sends whose address at least 4 of the 7 nodes nearest that address serve (if the node is itself among the 20 nearest), so the walk of a node holding real listings runs to the end, and that of a node serving made-up ones stops after 8 pages. Only an address at least 4 of its 7 nearest nodes serve is worked on (its envelope fetched, nearest nodes asked, the chain read); any other costs nothing but its pages and waits for a later read, shown with `--all` as `undecided (try again)`. The walks have a deadline: at most 30 minutes, and once half of them are done, four times as long as that took (at least a minute). On stderr, the command counts the walks that stopped early and the addresses left for a later read, and warns when a read found too few nodes to trust (fewer than 7, or under three quarters as many as recent reads): such a read decides nothing.

`--state` keeps the walks' state in a file between reads, so walks stopped early carry on where they stopped, and recent reads' node counts are known. `--carry` takes the previous `--json` output and prints its entries again, as they were, for every address this read didn't decide, marked `"carried": true`: a read never drops a listing it didn't decide, however few nodes answered. A listing whose file the network no longer stores is dropped, but only when each of the nodes nearest its address walked past where it would be without serving it. Where the read decided an address, its own entry replaces the earlier one, or nothing does if it rejected the address. On a timer, run the third example and, when it succeeds, move `index.new.json` over `index.json`: the file then holds the index so far.

| Flag | Description |
|------|-------------|
| `--since <UNIX_SECONDS>` | Only listings from this time on (block timestamp, or first seen). |
| `--all` | Also show listings that fail their checks, with the reason. |
| `--state <FILE>` | Keep the walks' state in this file: read if it exists, replaced after the read. |
| `--carry <FILE>` | A previous `--json` output of this command, whose entries for addresses this read didn't decide are printed again. Needs `--json`. A missing file carries nothing; one that can't be read fails the command before anything is printed. |

With `--json`, hidden payment fields are absent, and each listing carries `check` (`verified` or `reported`), `nodes` and `nearest`, `first_seen` where it has one, and for a readable listing its `data_map` (hex), which is enough to read the file without fetching the envelope. Download a listed file with `ant file download <ADDRESS>`.

### `ant listing <ADDRESS>` — One Listing

```
$ ant listing be4ec238e14701164b2b97d73013039b28f2c747adaa2062cf0e4ecf3f3b0181
```

Asks the 7 nodes nearest the address for its listing, in the index or not, and checks it the same way: every field, with hidden ones shown as hidden, the check level and how many of the nearest nodes serve it. `--json` prints the listing and any copies that failed. Without a valid listing the command exits non-zero, with or without `--json`.

### `ant chunk` — Single-Chunk Operations

Low-level put/get for individual chunks (max ~1 MB each). Useful for small data or building custom data structures.

#### `ant chunk put [FILE]`

Store a single chunk. Reads from `FILE` or stdin. Requires `SECRET_KEY`.

```
$ echo "small payload" | SECRET_KEY=0x... ant chunk put
a1b2c3d4...
```

#### `ant chunk get <ADDRESS>`

Retrieve a single chunk by its hex-encoded XOR address.

```
$ ant chunk get a1b2c3d4... -o output.bin
```

**Options:**

| Flag | Description |
|------|-------------|
| `-o, --output <PATH>` | Write to file instead of stdout. |

### `ant pointer` — Pointer Operations

A pointer is a mutable reference to a chunk or to another pointer, signed by an
owner key that can never change. Every state is paid for; reads are free. The
owner key is kept as a 32-byte seed in a file only its owner can read (`0600`
on Unix; on Windows it takes its directory's permissions, so keep it in your
user profile). Losing it means the pointer can never be updated again.

#### `ant pointer keygen --output <FILE>`

Create a new owner key and print the address of the pointer it controls. Never
overwrites an existing file.

```
$ ant pointer keygen --output owner.key
Owner key written to owner.key
9f3c...
```

#### `ant pointer address --key <FILE>`

Print the address of the pointer a key controls. Needs no network.

#### `ant pointer create --key <FILE> <TARGET> [--kind chunk|pointer]`

Create the pointer, pointing at `TARGET` (hex). Requires `SECRET_KEY` to pay.
Refused before paying if the pointer already exists.

#### `ant pointer update --key <FILE> <TARGET> [--kind chunk|pointer]`

Point it at `TARGET`, one past the counter the network serves (or create it).
Requires `SECRET_KEY` to pay for the new state.

#### `ant pointer get <ADDRESS>`

Print a pointer's counter, target and state.

```
$ ant pointer get 9f3c...
address:  9f3c...
counter:  1
kind:     chunk
target:   a1b2...
state_id: 5e7d...
```

#### `ant pointer resolve <ADDRESS>`

Follow a chain of pointers to the target at its end.

### `ant wallet` — Wallet Operations

Inspect the EVM wallet derived from `SECRET_KEY`.

#### `ant wallet address`

Print the wallet's EVM address.

```
$ SECRET_KEY=0x... ant wallet address
0x1234567890abcdef...
```

#### `ant wallet balance`

Query the token balance on the configured EVM network.

```
$ SECRET_KEY=0x... ant wallet balance --evm-network arbitrum-one
1000000000000000000
```

### `ant node` — Node Management

Manage Autonomi network nodes via a local daemon process. The daemon runs in the background, exposes a REST API on `127.0.0.1`, and supervises all node processes.

#### `ant node daemon start`

Launch the daemon as a detached background process. By default it binds to a random free port on `127.0.0.1` and writes the chosen port to `daemon.port` for discovery.

```
$ ant node daemon start
Daemon started (pid: 12345, port: 48532)
```

**Options:**

| Flag | Description |
|------|-------------|
| `--port <PORT>` | Pin the HTTP port. `0` means OS-assigned (the default behavior). |
| `--listen-addr <IP>` | Bind address. Defaults to `127.0.0.1`. |

Pin the port and bind on all interfaces — useful when the daemon runs inside a container and the API needs to be reachable through a port mapping:

```
$ ant node daemon start --listen-addr 0.0.0.0 --port 8765
```

```
$ docker run -d -p 8765:8765 my/ant-image \
    ant node daemon start --listen-addr 0.0.0.0 --port 8765
```

> **Warning:** the daemon has no authentication. Binding to a non-loopback address exposes node management — start, stop, reset, registry mutation — to anyone who can reach the port. Only do this when the network path is controlled (e.g. a container with an explicit port mapping or a trusted private network).

#### `ant node daemon stop`

Shut down the running daemon. Sends SIGTERM and waits for exit.

```
$ ant node daemon stop
Daemon stopped (pid: 12345)
```

#### `ant node daemon status`

Show daemon status and node count summary.

```
$ ant node daemon status
Daemon is running
  PID:           12345
  Port:          48532
  Uptime:        3600s
  Nodes total:   3
  Nodes running: 2
  Nodes stopped: 1
  Nodes errored: 0
```

#### `ant node daemon info`

Output connection details as JSON (always JSON, regardless of `--json` flag). AI agents use this to discover the daemon's REST API.

```json
{
  "running": true,
  "pid": 12345,
  "port": 48532,
  "api_base": "http://127.0.0.1:48532/api/v1"
}
```

#### `ant node add`

Register one or more nodes in the registry. Does **not** start them. Does **not** require the daemon.

```
$ ant node add --rewards-address 0xYourWallet --count 3 --node-port 12000-12002 --path /path/to/antnode
Added 3 node(s):
  Node 1: port 12000
  Node 2: port 12001
  Node 3: port 12002
```

If the daemon is running, the command routes through its REST API. Otherwise, it operates directly on the registry file.

**Options:**

| Flag | Description |
|------|-------------|
| `--rewards-address <ADDR>` | Required. EVM wallet address for node earnings. |
| `--count <N>` | Number of nodes to add (default: 1). |
| `--node-port <PORT\|RANGE>` | Port or range (e.g., `12000` or `12000-12004`). |
| `--data-dir-path <PATH>` | Custom data directory prefix. |
| `--log-dir-path <PATH>` | Custom log directory prefix. |
| `--path <PATH>` | Path to a local `antnode` binary. |
| `--version <X.Y.Z>` | Download a specific version (accepts pre-releases, e.g. `0.17.0-beta.1`). |
| `--url <URL>` | Download binary from a URL archive. |
| `--bootstrap <IP:PORT>` | Bootstrap peer(s), comma-separated. |
| `--evm-network <NET>` | EVM network for storage payments: `arbitrum-one` (default) or `arbitrum-sepolia`. |
| `--upgrade-channel <CHAN>` | Release channel the node tracks for automatic upgrades: `stable` (default) or `beta`. Also selects which release the binary is downloaded from when no `--path`/`--version`/`--url` is given. |
| `--env <K=V>` | Environment variables, comma-separated. |

With none of `--path`, `--version` or `--url`, the binary is downloaded from the newest release
eligible for the chosen channel: the latest stable release on `stable`, and the highest of the
`-beta.N` and stable releases on `beta`. Release candidates (`-rc.N`) are never installed on
either channel — they are cut before the release gates have given a verdict.

#### `ant node start`

Start registered node(s). Requires the daemon to be running.

```
$ ant node start                          # Start all
$ ant node start --service-name node1     # Start specific node
```

#### `ant node stop`

Stop running node(s). Requires the daemon.

```
$ ant node stop                           # Stop all
$ ant node stop --service-name node1      # Stop specific node
```

#### `ant node status`

Display all nodes and their current status.

#### `ant node reset`

Remove all node data, log directories, and clear the registry. All nodes must be stopped first.

```
$ ant node reset --force
```

#### `ant node logs forward`

Optionally ship this machine's node logs to the Autonomi beta log endpoint, to help judge a beta
build. Off by default and never enabled for you — running `enable` yourself is the whole of the
consent, and `disable` stops it. See
[Forwarding your node logs](#forwarding-your-node-logs-optional) for the walkthrough.

```
$ ant node logs forward enable --token <token>
$ ant node logs forward status
$ ant node logs forward disable
```

**`enable` options:**

| Flag | Description |
|------|-------------|
| `--token <TOKEN>` | The write-only token issued with your beta enrolment. Only needed the first time; re-enabling after a `disable` reuses the stored one. |
| `--endpoint <URL>` | Send somewhere other than the default endpoint. Intended for testing against a local sink. |
| `--level <LEVEL>` | Lowest level to forward: `trace`, `debug`, `info`, `warn`, `error`. Defaults to `info`. |

`status` reports whether forwarding is on, which nodes are being tailed, which are being skipped and
why, and how many events have been delivered:

```
$ ant node logs forward status
Log forwarding: on
  Endpoint: https://logs.autonomi.com   Level: INFO and above
  Token:    75f57160d2c2

  Forwarding (1)
    ● node1 (1)

  Not forwarding (2)
    ○ node2 (2) — logging is not enabled for this node — re-add it with --log-dir-path to forward its logs
    ○ node3 (3) — logging is not enabled for this node — re-add it with --log-dir-path to forward its logs

  Node logging is off unless a node was added with --log-dir-path.

  Delivery
    Forwarded: 1284   Batches: 7 sent, 0 failed
```

The token is stored at `~/.config/ant/log_forward.json` with owner-only permissions and is never
printed back or returned by the API — `status` shows a short fingerprint of it instead, enough to
tell which token is in use.

### `ant update` — Self-Update

Replace the running `ant` binary with the newest release from GitHub. The downloaded archive's
ML-DSA-65 signature is verified against the embedded release signing key before anything is
installed, and the extracted binary must report the expected version.

```
$ ant update
Current version: 0.3.3
Checking for updates on the stable channel...
Update available: v0.3.3 -> v0.3.4
Updated successfully: v0.3.3 -> v0.3.4
```

**Options:**

| Flag | Description |
|------|-------------|
| `--channel <CHAN>` | Release channel to update along: `stable` or `beta`. Defaults to the channel the running binary belongs to. |
| `--force` | Re-download and reinstall even when already on the newest release. |

The default channel is inferred from the running binary's own version, so there is nothing to
configure: a `-beta.N` build tracks `beta` and every other build tracks `stable`. On `beta`,
both `-beta.N` and stable releases are accepted and the highest wins; `-rc.N` releases are
rejected on both channels.

Because a beta version outranks the stable release it was cut from, `--channel stable` cannot
walk a beta build backwards — it will report that you are already up to date. Leaving the beta
channel means installing a stable build manually.

---

## Beta Programme

The beta channel carries the week's build ahead of the stable train, for people who want to soak it
and report back.

Taking part means [running beta builds](#running-beta-builds). That is the whole requirement.

Separately, and entirely optionally, you can [forward your node logs](#forwarding-your-node-logs-optional)
to us. It is off by default, it is not a condition of being on the beta channel, and choosing not to
turn it on costs you nothing.

### Running beta builds

The client and the nodes have separate beta channels, opted into separately.

```bash
# 1. Install the beta client. Pass ANT_CHANNEL=beta to the quick-start installer:
$ curl -fsSL https://raw.githubusercontent.com/WithAutonomi/ant-client/main/install.sh \
      | ANT_CHANNEL=beta bash

#    On Windows:
#      $env:ANT_CHANNEL="beta"; irm https://raw.githubusercontent.com/WithAutonomi/ant-client/main/install.ps1 | iex

# 2. From then on, self-update stays on beta with no flag needed.
$ ant update

# 3. Add nodes that track the beta channel. The binary is downloaded from the newest
#    beta-eligible ant-node release.
$ ant node add --rewards-address 0xYourWallet --count 3 --upgrade-channel beta
```

Existing nodes are not switched to the beta channel by any of this — `--upgrade-channel` applies
to nodes at the point they are added, so opting in means adding new nodes.

### Forwarding your node logs (optional)

**This is opt-in and stays off until you ask for it.** Nothing leaves your machine unless you run
`ant node logs forward enable` yourself, and running it is the whole of the consent. You can skip
this section entirely and still run beta builds.

If you do want to help: beta enrolment comes with a write-only token, and handing it to that command
makes the daemon tail your nodes' log files and ship them to the Autonomi beta log endpoint. It is
the difference between us judging a build on a handful of self-reported problems and judging it on
what the nodes actually did, so it is genuinely useful — but it is your call, and `disable` stops it
at any point.

**If you do turn it on, the order of these three steps matters:**

```bash
# 1. Add nodes WITH LOGGING ENABLED. Node file logging is off by default; without
#    --log-dir-path a node writes no log files at all and there is nothing to forward.
$ ant node add --rewards-address 0xYourWallet --count 3 \
      --upgrade-channel beta --log-dir-path ~/.local/share/ant

# 2. Enable forwarding BEFORE starting the nodes.
$ ant node logs forward enable --token <your-token>

# 3. Now start them.
$ ant node start
```

#### Why the order matters

**`--log-dir-path` has to be set when the node is added.** The value is a prefix — each node gets
`<prefix>/node-<id>/logs` — and there is no way to turn logging on for an existing node short of
removing it and adding it again. If you forget, `enable` will tell you —
those nodes appear under "Not forwarding" in `ant node logs forward status` — but the node has to be
re-added to fix it.

**Enable before you start, not after.** Enabling forwarding is forward-looking consent: for any log
file that *already exists*, the daemon starts reading from the end of it, so nothing written before
you opted in is ever uploaded. A node that has not run yet has no log file, so the one it creates
when it starts is read from its first line.

The practical difference is the node's startup line, which is where its version, commit and peer ID
are recorded, along with the bootstrap and listen-address lines that show whether it actually joined
the network. Enable first and those are captured. Enable afterwards and they are skipped, so every
event forwarded from that run is missing the fields that identify which build produced it — which is
most of what makes the logs useful.

If you have already started a node, restarting it does not necessarily help: the node appends to the
same daily file, so a restart on the same day resumes from where the daemon had got to rather than
from the new run's first line.

#### What gets sent

Worth knowing before you decide. Only events at `INFO` and above, from nodes with logging enabled.
Every event is tagged with the node ID, service name, binary version, release channel, and the OS
and architecture of the machine.

Each event also carries a random identifier generated when you first enable forwarding, stored in
`~/.config/ant/log_forward.json`. Because every participant writes into the same daily index, it is
there to stop two machines' events colliding and overwriting one another. It is generated from
random bytes — not from your hostname, MAC address or username — so it distinguishes your
installation from others without describing it.

Your machine's hostname is **not** sent. Your wallet and rewards address are not part of what the
daemon adds. Beyond those tags, the content is whatever `ant-node` itself wrote to its log at `INFO`
or above — the same lines you can read yourself in the node's log directory.

#### If something looks wrong

`ant node logs forward status` is the place to look. `Batches: N sent, M failed` with an error line
underneath means the endpoint is unreachable or rejecting the token. Delivery is best-effort by
design: it is bounded in memory, it retries a few times and then gives up on a batch, and it never
blocks or slows a node. Losing some log lines is an acceptable outcome; a stalled node is not.

`disable` takes effect immediately: it waits for any request already in flight to be abandoned
before reporting that forwarding has stopped, so nothing is still being uploaded once the command
returns.

Forwarding survives a daemon restart, picking up where it left off without re-sending what it had
already delivered. If you want a genuinely clean slate, `disable` first, then delete
`~/.local/share/ant/log_forward_offsets.json`.

### Turning forwarding off

You can stop forwarding at any time, without leaving the beta channel and without giving a reason:

```bash
$ ant node logs forward disable
```

Nothing else about your nodes changes — no restart, no change to how they run, no data touched. They
keep writing their own logs to disk exactly as before; the daemon just stops reading them.

### Leaving the beta channel

Separate from the above, and manual. Because a beta version outranks the stable release it was cut
from, `ant update --channel stable` cannot walk a beta build backwards — installing a stable build
means downloading it yourself. Nodes already on `--upgrade-channel beta` stay on it.

---

## REST API

When the daemon is running, it exposes a REST API on `127.0.0.1:<port>`. Discover the port via `ant node daemon info` or by reading `~/.local/share/ant/daemon.port`.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/status` | Daemon health, uptime, node count summary |
| GET | `/api/v1/events` | SSE stream of real-time node events |
| GET | `/api/v1/nodes/status` | Node status summary |
| POST | `/api/v1/nodes` | Add nodes to the registry |
| DELETE | `/api/v1/nodes/{id}` | Remove a node |
| POST | `/api/v1/nodes/{id}/start` | Start a specific node |
| POST | `/api/v1/nodes/start-all` | Start all registered nodes |
| POST | `/api/v1/nodes/{id}/stop` | Stop a specific node |
| POST | `/api/v1/nodes/stop-all` | Stop all running nodes |
| POST | `/api/v1/reset` | Reset all node state (fails if nodes running) |
| GET | `/api/v1/logs/forward` | Beta log-forwarding status, tailed nodes, delivery counters |
| POST | `/api/v1/logs/forward/enable` | Enable beta log forwarding |
| POST | `/api/v1/logs/forward/disable` | Disable beta log forwarding |
| GET | `/api/v1/openapi.json` | OpenAPI 3.1 specification |
| GET | `/console` | Web status console (HTML) |

### Error Envelope

All error responses use a consistent envelope:

```json
{
  "error": {
    "code": "NODE_NOT_FOUND",
    "message": "No node with id 42"
  }
}
```

### Idempotency

409 Conflict responses include `current_state` so retrying clients can confirm the desired state already exists:

```json
{
  "error": {
    "code": "NODE_ALREADY_RUNNING",
    "message": "Node 3 is already running"
  },
  "current_state": {
    "node_id": 3,
    "status": "running",
    "pid": 12345,
    "uptime_secs": 3600
  }
}
```

### SSE Events

`GET /api/v1/events` streams real-time node lifecycle events:

```
event: node_started
data: {"node_id": 1, "pid": 12345}

event: node_crashed
data: {"node_id": 2, "exit_code": 1}
```

Event types: `node_starting`, `node_started`, `node_stopping`, `node_stopped`, `node_crashed`, `node_restarting`, `node_errored`, `download_started`, `download_progress`, `download_complete`.

---

## Rust Library API (`ant-core`)

The `ant-core` crate exposes the full API programmatically. Add it as a dependency:

```toml
[dependencies]
ant-core = { path = "ant-core" }
```

### Connecting to the Network

```rust
use ant_core::data::{Client, ClientConfig};

// Connect to bootstrap peers
let client = Client::connect(&["1.2.3.4:12000".parse()?], ClientConfig::default()).await?;

// Attach a wallet for paid operations (uploads)
use ant_core::data::{Wallet, EvmNetwork};
let wallet = Wallet::new_from_private_key(EvmNetwork::ArbitrumOne, "0xprivate_key...")?;
let client = client.with_wallet(wallet);
client.approve_token_spend().await?;
```

### Uploading and Downloading Files

```rust
use std::path::Path;
use ant_core::data::PaymentMode;

// Upload a file (streamed, never fully loaded into memory)
let result = client.file_upload(Path::new("photo.jpg")).await?;
println!("Stored {} chunks", result.chunks_stored);

// Upload with explicit payment mode
let result = client.file_upload_with_mode(Path::new("photo.jpg"), PaymentMode::Merkle).await?;

// Store DataMap publicly (anyone with the address can download)
let public_address = client.data_map_store(&result.data_map).await?;

// Download a public file
let data_map = client.data_map_fetch(&public_address).await?;
client.file_download(&data_map, Path::new("photo_copy.jpg")).await?;
```

### Uploading and Downloading In-Memory Data

```rust
use bytes::Bytes;

// Upload bytes (encrypted + chunked automatically)
let result = client.data_upload(Bytes::from("hello autonomi")).await?;

// Download and decrypt
let content = client.data_download(&result.data_map).await?;
assert_eq!(content, Bytes::from("hello autonomi"));
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
        Path::new("photo.jpg"), PaymentMode::Auto, options.into_visibility(), None)
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
```

`index_listings` and `listing` merge, date, check and decide listings as the nodes do when they repair one. `index_listings_with` carries on from the `WalkState` of earlier reads (save it between them: it serialises), where `index_listings` starts afresh, and `ListingsIndex::carry` says what to do with a listing an earlier read published: replace it with what this read decided, keep it, or drop it because the network no longer stores its file. An indexer of its own can use the same rules from `ant_core::data::client::listings`: `listing_to_check` (what to look up on chain for a group of copies), `check_copies` (the group's date and check, given what was fetched), `quorum_listing` and `decide_address`, with `ant_listings::IndexWalk` to walk the nodes' indexes.

`Visibility::Private` and `Visibility::Public` upload exactly as they always have; `EnvelopeOptions::into_visibility` picks them when no envelope is needed. An envelope upload's checkpoint and kept record belong to whoever pays: the wallet, or an `UploadPayer`'s `checkpoint_scope()`, which a payer serving several accounts must set to each account's id, so one account never resumes another's interrupted upload or gets its record. `file_upload_with_payer` and the external-signer `file_prepare_upload_with_mode`/`finalize_upload*` take `Visibility::Envelope` too; the external path pays an envelope upload per chunk, in one wave batch (its payment intent lists the quotes in quote-hash order: pay them in that order), and fills in the record at finalize once every chunk is stored (unchecked if the client has no EVM network). It refuses, before quoting, an envelope upload the payment mode would pay in merkle batches (`PaymentMode::Auto` from 64 chunks, or `PaymentMode::Merkle`): use `file_upload_with_payer`, or `PaymentMode::Single` to pay every chunk per chunk with all of them held in memory.

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

Autonomi supports two payment strategies:

| Mode | Description |
|------|-------------|
| `PaymentMode::Single` | One EVM transaction per chunk. Simple but more gas for many chunks. |
| `PaymentMode::Merkle` | Single EVM transaction for a batch of chunks via merkle proof. Lower gas for large uploads. |
| `PaymentMode::Auto` | Default. Uses merkle when chunk count >= 64, otherwise per-chunk. |

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

```
┌──────────┐     HTTP      ┌──────────────────────────────────┐
│  ant CLI │──────────────▶│         ant daemon                │
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
│           │   ├── file.rs      # ant file upload/download
│           │   ├── chunk.rs     # ant chunk put/get
│           │   └── wallet.rs    # ant wallet address/balance
│           └── node/
│               ├── add.rs       # ant node add
│               ├── daemon.rs    # ant node daemon start/stop/status/info/run
│               ├── logs.rs      # ant node logs forward enable/disable/status
│               ├── start.rs     # ant node start
│               ├── stop.rs      # ant node stop
│               ├── status.rs    # ant node status
│               └── reset.rs     # ant node reset
└── docs/                        # Architecture documentation
```

## EVM Networks

| Value | Network | Use case |
|-------|---------|----------|
| `arbitrum-one` | Arbitrum mainnet | Production |
| `arbitrum-sepolia` | Arbitrum Sepolia testnet | Staging / testing |
| `local` | Custom (Anvil) | Local development (requires `--devnet-manifest`) |

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
cargo run --bin ant -- --help
cargo run --bin ant -- file upload photo.jpg --public --devnet-manifest ~/.local/share/ant/devnet-manifest.json --allow-loopback --evm-network local
cargo run --bin ant -- node daemon status
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
`quic` list contains native multiaddresses; its `webrtc` list contains complete
WebRTC Direct multiaddresses with certificate and peer identity pins. The
WebRTC list includes seven mainnet bootstrap nodes and is exposed through WASM
for the browser SDK's default mainnet connection.

The CLI accepts `--bootstrap /ip4/127.0.0.1/udp/10000/quic` (including optional
`/p2p/<peer-id>`). Legacy `ip:port` arguments and installed `peers = [...]`
configuration remain readable. Explicit peers take precedence over a selected
devnet manifest, which takes precedence over the installed bootstrap file.
Only QUIC seeds are selected for native dialing. Existing installed configuration
is preserved by the installer; replace it explicitly to adopt new bundled seeds.

Native library callers can use `config::resolve_bootstrap_multiaddrs()` and
`Client::connect_multiaddrs()` to retain peer pins. Existing socket-address APIs
remain available. `network_defaults::browser_mainnet_defaults()` and the WASM
`mainnetNetworkDefaults()` export return only WebRTC seeds, the expected payment
identity, and evmlib's mainnet RPC URL without connecting to any network.

Add verified WebRTC seeds to the shared TOML resource, commit the source, and
regenerate the browser SDK's WASM artifact to activate its mainnet defaults.
See [ADR-0005](docs/adr/ADR-0005-bootstrap-multiaddresses.md).
