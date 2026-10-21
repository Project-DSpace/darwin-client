# Listings index files, version 1

A producer reads the listings the storage network's nodes serve, checks them
as `darwin listings` does (see the README), and publishes the index as static
JSON files under `listings/v1/`. Each file is small, is replaced only when its
content changes, and is never written in part, so a reader polls with
conditional requests and fetches only what changed. Anyone can serve and read
them; this document is enough to read them without the code.

The Rust types and the rules that lay the files out are in
`ant_core::data::client::listings_v1`.

## The files

All paths are relative to the directory the files are published in, such as
`https://example.org/listings/v1/`.

| File | What it holds | Changes |
|---|---|---|
| `head.json` | Where the index stands, its newest 50 entries, and links to the rest | When the index changes |
| `by-address/<prefix>.json` (4,096 files) | Every entry whose address starts with `<prefix>`, with its data map | When one of its entries changes |
| `by-address/<prefix>.support.json` (4,096 files) | How many of each of those addresses' nearest nodes serve it | When that changes, at most every 10 minutes (see below) |
| `by-name/<prefix>.json` (4,096 files) | The entries of each exact name whose hash starts with `<prefix>`, newest first | When one of its entries changes |
| `by-type/<prefix>/index.json` (4,096 files) | Each exact content type whose hash starts with `<prefix>`, with its first and last page | When one of its types changes |
| `by-type/<prefix>/<type id>-<n>.json` | Page `n` of one content type's entries, in key order, linked to the pages before and after | When its entries change |
| `pages.json` | The time pages that hold the whole index, in key order | When the index changes |
| `pages/<first key>-<hash>.json` | One time page | Never: a page whose entries change gets a new name |
| `feed/index.json` | The feed's segments | When the feed grows |
| `feed/<first seq>.json` | Up to 1,000 of the feed's records | Until it holds 1,000, then not within its epoch |
| `status.json` | How the producer is doing | Every cycle (each minute), after the cycle's other files |
| `rejected.json` | Listings the producer didn't list, with why | When one changes |

## Conventions

**JSON.** Every file is UTF-8 JSON, written compactly (no spaces or line
breaks). A file's bytes depend only on its content: fields come in the order
this document gives them, and the same content is always written the same
way, so an unchanged file keeps its `ETag`.

**New fields.** Fields may be added to any object in version 1, and new values
may appear where this document says so. A reader ignores fields it doesn't
know. A change that removes a field or changes what one means is published
under a new directory, `listings/v2/`.

**Numbers.** Times are Unix seconds (UTC). Every number is a whole number of
at least 0. A listing's `size` is the uploader's word and can exceed 2^53, the
largest whole number a JavaScript number holds exactly; other numbers stay
well below it.

**Hex.** Lowercase. An address or node id is 64 hex digits (32 bytes). A
transaction or quote hash is `0x` and 64 hex digits, as the chain shows it.

**Keys.** The index is in key order. A listing's key is its `time`, its
`block_number` (0 when hidden), its `log_index` (0 when hidden), and its
address, compared in that order. As text, a key is 112 hex digits: the three
numbers as 8 bytes big-endian each, then the address's 32 bytes. Keys as text
sort the same way as keys, so they can be compared as strings, and the first
16 digits are the time.

**Prefixes.** Files are sharded by a prefix of three hex digits, `000` to
`fff`:

- an address's prefix is its own first three hex digits;
- a name's prefix is the first three hex digits of the BLAKE3 hash of its
  UTF-8 bytes, exactly as the listing declares it (no change of case,
  spacing or Unicode normalisation): `a.txt` hashes to `0c1…`, so its entries
  are in `by-name/0c1.json`;
- a content type's id is the BLAKE3 hash of its bytes, exactly as declared,
  as 64 hex digits, and its prefix the id's first three: `text/plain` has id
  `d1acb144aa06cec156c391172ed53277ec72ff75ff1a08e0dab4c84efbdadbbc`, so it
  is listed in `by-type/d1a/index.json`.

Every prefix has its files, empty or not, so a missing file is an error, not
an empty shard.

**Writing.** A file is written only when its bytes change, and replaced whole
(written beside it, then renamed over it), so a reader never sees a part of
one. Beside each file are `<file>.gz` and `<file>.zst`, the same bytes
compressed, which a server can send as they are to a reader that accepts
gzip or zstd. A file is written only after every file it names is in place;
`head.json` is written after the other files of a change, and `status.json`
last, after every other file of the cycle, so a fresh `status.json` means the
cycle's files are all in place. (So in a new directory, the first `head.json`
comes a moment before the `status.json` it links to.)

**Caching.** Time pages are named by their content, so they never change:
keep them (they are served to be cached for a day). Every other file can
change at any time: revalidate it (`If-None-Match` or `If-Modified-Since`);
an unchanged one is answered `304 Not Modified`, with no body. That includes
full feed segments: a full segment doesn't change within its epoch, but a new
epoch (a producer that starts without its state begins one) writes its
segments under the same names, so segments are served to be revalidated, not
cached.

A web page on another origin reads the files only where the server allows
its origin (`Access-Control-Allow-Origin`). It can revalidate by hand,
keeping a file's `ETag` and sending it back as `If-None-Match`, only where
the server also exposes `ETag` to it (`Access-Control-Expose-Headers`) and
allows `If-None-Match` in its CORS preflights
(`Access-Control-Allow-Headers`). Otherwise it should let the browser
revalidate, as `fetch(url, { cache: "no-cache" })` does: the browser sends
its own conditional request and, on a `304`, hands the page the copy it
holds.

## The entry

Every file but the support files and `rejected.json` lists entries. An entry
is one listed address: what its listing shows, and how far it was checked.
There is at most one entry per address. A listing hides the payment fields
its uploader chose to hide, and those fields are absent from its entry.

| Field | Value |
|---|---|
| `address` | The file's address: its envelope's, 64 hex digits |
| `name` | The name the uploader declared, or `null`. Treat it as untrusted text, not a path |
| `content_type` | The content type the uploader declared, or `null` |
| `size` | The file's size in bytes, as its data map gives it. The data map of a file over about 12.5 MB is shrunk into a child map, which gives no size: the producer reads its root map once to find it, and until then it is `null`, so a size can be filled in later for an entry already published, which the feed records as an ordinary put. It stays `null` where the root map can't give one. A data map shrunk more than once (a file over about 658 GB) comes from self-encryption labelled as shrunk once, the map in between labelled a root; it gives what self-encryption resolves it to, the length of the root map shrunk away rather than the file's size, and the file can't be downloaded either. `null` when the data map is withheld. The listings the nodes serve give no size for a shrunk data map, so a reader that compares entries with its own read of the nodes must not count a size an entry has and its read lacks as a difference |
| `readable` | Whether anyone with the address can read the file: the envelope holds its data map rather than withholding it |
| `hidden` | The payment fields the uploader hid, of `tx-hash`, `block`, `timestamp`, `log-index` and `quote`, in that order |
| `tx_hash` | The payment's transaction hash. Absent when hidden |
| `block_number` | The payment's block. Absent when hidden |
| `block_timestamp` | The payment's block timestamp. Absent when hidden |
| `log_index` | The position in its block of the payment vault's `DataPaymentMade` event for the envelope. Absent when hidden |
| `quote_hash` | The hash of the paid quote, which that event names. Absent when the quote is hidden, or doesn't decode as a quote |
| `first_seen` | For a listing that hides its block timestamp: when the nodes nearest its address first stored it, rounded down to the hour. Of their dates that pass the checks, the latest of the earliest 4, so that at least 4 of them date it then or earlier; where fewer than 4 pass, the latest of them. Absent otherwise |
| `time` | The time the index sorts by: `block_timestamp`, else `first_seen`, else 0 |
| `check` | `verified`: the quote is shown, and the payment is checked on the chain and tied to the address. `reported`: the quote is hidden; the shown fields are checked, and the listing counts because at least 4 of the 7 nodes nearest its address serve it |
| `decided_at` | When the producer decided the entry as it stands: when the publication that decided it began, a cycle's start, or for a listing pushed between cycles, when that publication began. Deciding it again with the same result leaves it unchanged, and so does filling in its `size` |

A verified listing whose payment shows every field:

```json
{
  "address": "1111111111111111111111111111111111111111111111111111111111111111",
  "name": "a.txt",
  "content_type": "text/plain",
  "size": 20480,
  "readable": true,
  "hidden": [],
  "tx_hash": "0x2222222222222222222222222222222222222222222222222222222222222222",
  "block_number": 81942857,
  "block_timestamp": 1791321603,
  "log_index": 7,
  "quote_hash": "0x4c10e4ae831c5a287c8f92d65bfc964201171696de4f11aa4d568f7e1cbf4ebd",
  "time": 1791321603,
  "check": "verified",
  "decided_at": 1791321660
}
```

A private file's listing that shows only its block, dated by the nodes:

```json
{
  "address": "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0",
  "name": null,
  "content_type": null,
  "size": null,
  "readable": false,
  "hidden": ["tx-hash", "timestamp", "log-index", "quote"],
  "block_number": 81950000,
  "first_seen": 1791324000,
  "time": 1791324000,
  "check": "reported",
  "decided_at": 1791324060
}
```

The examples here are laid out for reading; the files themselves are compact.

## head.json

Where the index stands. Poll it to learn of changes: it changes whenever the
index does, and only then.

| Field | Value |
|---|---|
| `epoch` | The feed's epoch: 16 hex digits, chosen at random when the producer starts a new feed. When it changes, everything a reader holds from earlier files is void: read the index afresh |
| `seq` | The number of the feed's latest record, 0 if it has none |
| `count` | How many entries the index holds |
| `generated_at` | When the index last changed: when the publication that wrote the feed's latest record began (see the feed's `at`), or, before any, the cycle that began the epoch |
| `listings` | The newest 50 entries (fewer if the index is smaller), newest first: the largest keys first. Without data maps |
| `links` | Where the other files are, relative to this one: `status`, `rejected`, `pages` and `feed` name files; `by_address`, `support`, `by_name` and `by_type` are patterns in which `{prefix}` stands for a prefix |

```json
{
  "epoch": "8c1f0e2d3b4a5968",
  "seq": 12,
  "count": 2,
  "generated_at": 1791324060,
  "listings": [{ "address": "a0a0…", "…": "…" }, { "address": "1111…", "…": "…" }],
  "links": {
    "status": "status.json",
    "rejected": "rejected.json",
    "pages": "pages.json",
    "feed": "feed/index.json",
    "by_address": "by-address/{prefix}.json",
    "support": "by-address/{prefix}.support.json",
    "by_name": "by-name/{prefix}.json",
    "by_type": "by-type/{prefix}/index.json"
  }
}
```

## by-address/

`by-address/<prefix>.json` holds every entry whose address starts with
`<prefix>`, in address order, each with one more field:

| Field | Value |
|---|---|
| `data_map` | The file's data map, hex-encoded, exactly as the envelope holds it (what an unlisted upload of the file stores): enough to read the file without fetching the envelope. `null` when the envelope withholds it |

```json
{ "prefix": "a0a", "listings": [{ "address": "a0a0…", "…": "…", "decided_at": 1791324060, "data_map": null }] }
```

`by-address/<prefix>.support.json` says, for each of those addresses, how
many of the nodes nearest it serve its listing, as the producer last measured
it. It is written when that changes, and at most every 10 minutes, so it can
lag the shard by that much: an address in the shard and not yet in its
support file has support not yet published, and an address in the support
file and not in the shard is no longer listed. An epoch's first publication
that takes entries from an earlier index (see `carried`) doesn't start the
10 minutes, so the support write after it isn't held back: the first cycle
that changes any support, as deciding any of those entries does, publishes
it at once, and support that changes later waits for the 10 minutes that
write starts.

| Field | Value |
|---|---|
| `address` | The file's address |
| `nodes` | How many of the nodes nearest the address answered and serve its listing |
| `nearest` | How many nearest nodes count: 7, unless the network has fewer |
| `quorum` | Whether `nodes` reaches the quorum, 4 of 7. Always true for a `reported` listing. A `verified` one without it is the earliest of several payments for its address, none of which a quorum of those nodes serves: a node asked to quote for the upload could have paid first |
| `carried` | Whether the entry is kept from an earlier decision that the latest cycle couldn't make again (too few of the nearest nodes answered, or serve it), while what it takes to remove it isn't shown either. An epoch's first publication may also take entries from an earlier index, marked carried until a cycle decides them |

```json
{ "prefix": "a0a", "support": [{ "address": "a0a0…", "nodes": 6, "nearest": 7, "quorum": true, "carried": false }] }
```

The nearest nodes are those of the producer's census: the nodes it found
answering witnessed lookups. A node that misses 3 of its polls in a row
leaves the census when its part of the address space is closed again, and
the next nearest takes its place. So for a while after a node stops, while
the network still lists it, what the producer publishes can differ from what
a one-off read of the network gives: these counts (and `rejected.json`'s,
and `status.json`'s `below_full`), and also whether an address is listed,
left for later or dropped. A reader comparing entries or support with its
own read should allow for it during that time.

## by-name/

`by-name/<prefix>.json` holds the entries of every name whose prefix is
`<prefix>`, grouped by exact name: `names` lists each name with its entries,
newest first, the names in the byte order of their UTF-8. Entries without a
name are in no group.

```json
{ "prefix": "0c1", "names": [{ "name": "a.txt", "listings": [{ "address": "1111…", "…": "…" }] }] }
```

## by-type/

`by-type/<prefix>/index.json` lists every content type whose prefix is
`<prefix>`, in byte order, each with:

| Field | Value |
|---|---|
| `content_type` | The content type, exactly as declared |
| `count` | How many entries have it |
| `pages` | How many pages hold them: `count` divided by 256, rounded up |
| `first` | The page with its oldest entries |
| `last` | The page with its newest entries |

A content type's pages are `by-type/<prefix>/<type id>-<n>.json`, `n` from 0.
Page `n` holds its entries `256 × n` to `256 × n + 255` in key order, so
every page but the last holds 256. Each page gives:

| Field | Value |
|---|---|
| `content_type` | The content type |
| `page` | `n` |
| `prev` | The page before, with older entries; `null` for the first |
| `next` | The page after, with newer entries; `null` for the last |
| `listings` | Its entries, in key order |

Oldest first, start at `first` and follow `next`; newest first, start at
`last`, follow `prev`, and read each page backwards. The pages move as entries
come and go: between two requests an entry can shift to a neighbouring page,
so drop entries already seen, by address. Entries without a content type are
on no page.

```json
{ "prefix": "d1a", "types": [{ "content_type": "text/plain", "count": 1, "pages": 1,
  "first": "by-type/d1a/d1acb144aa06cec156c391172ed53277ec72ff75ff1a08e0dab4c84efbdadbbc-0.json",
  "last": "by-type/d1a/d1acb144aa06cec156c391172ed53277ec72ff75ff1a08e0dab4c84efbdadbbc-0.json" }] }
```

```json
{ "content_type": "text/plain", "page": 0, "prev": null, "next": null, "listings": [{ "address": "1111…", "…": "…" }] }
```

## pages.json and pages/

The whole index, in key order, as time pages. `pages.json` gives:

| Field | Value |
|---|---|
| `epoch` | The feed's epoch |
| `seq` | The number of the feed's latest record the pages hold: the index after that record |
| `count` | How many entries they hold |
| `pages` | The pages, in key order, each with `path`, `first` and `last` (its first and last entry's keys, as text) and `count` |

A page, `pages/<first key>-<hash>.json`, is `{"listings": [...]}`: its
entries, in key order. Its name is its first entry's key, as text, then the
BLAKE3 hash of the page's bytes (the JSON file itself, uncompressed), as 64
hex digits, so its content never changes, and a page whose entries change is
written under a new name. A page `pages.json` no longer lists stays for at
least a day, for readers part way through.

```json
{ "epoch": "8c1f0e2d3b4a5968", "seq": 12, "count": 2, "pages": [{
  "path": "pages/000000006ac566030000000004e2594900000000000000071111111111111111111111111111111111111111111111111111111111111111-d40d8c4970af03f36cbb63c8599efa580b278f3027232ca7b24f6f103f24c50d.json",
  "first": "000000006ac566030000000004e2594900000000000000071111111111111111111111111111111111111111111111111111111111111111",
  "last": "000000006ac56f600000000004e275300000000000000000a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0",
  "count": 2 }] }
```

Where pages end follows from the entries, so that an entry coming or going
changes only its own page: a page ends after an entry whose address's BLAKE3
hash (of its 32 bytes), read as a big-endian number, is a multiple of 1,000,
or after 4,000 entries, whichever comes first, and the last page ends with
the index. Pages hold about 1,000 entries on average. A reader never needs to
work this out; it is how the producer keeps pages stable.

## feed/

The feed is every change to the index, in order, numbered from 1 within its
epoch, and kept for good. A record is either:

- a put: `{"seq": …, "at": …, "op": "put", "listing": {entry}}`. The
  address's entry is now `listing`, without its data map: new to the index,
  or replacing the address's entry;
- a removal: `{"seq": …, "at": …, "op": "remove", "address": "…",
  "reason": "…"}`. The address has no entry any more. `reason` is
  `no_longer_served` (in one cycle, every node nearest the address showed
  that it serves no listing there: the network no longer stores the file,
  though its payment stays on the chain) or `rejected` (deciding it again
  rejected it, or the entry shows a payment from before the payment vault
  was deployed, which can never count); other reasons may be added.

`at` is when the publication that made the change began: a cycle's start,
or for a change published between cycles (a listing a node pushed, a size
filled in), when that publication began. The records of one publication
share it. Applying records 1 to `n`, in order, to an empty index gives the
index after record `n`. A removal of an address that has no entry changes
nothing.

Records are kept in segments of 1,000: `feed/1.json` holds records 1 to
1,000, `feed/1001.json` records 1,001 to 2,000, and so on, so the segment
holding record `s` starts at `⌊(s − 1) / 1,000⌋ × 1,000 + 1`. A segment is
`{"epoch": "…", "first": 1001, "records": [...]}`. The latest grows until it
holds 1,000 records; from then on it doesn't change within its epoch, though
a new epoch writes its own segments under the same names. `feed/index.json`
lists the segments: `{"epoch", "seq", "segments": [{"path", "first", "last"}]}`.

```json
{ "epoch": "8c1f0e2d3b4a5968", "first": 1, "records": [
  { "seq": 1, "at": 1791324060, "op": "put", "listing": { "address": "a0a0…", "…": "…" } },
  { "seq": 2, "at": 1791327660, "op": "remove", "address": "a0a0…", "reason": "no_longer_served" } ] }
```

## status.json

How the producer is doing, written at the end of every cycle (each minute),
after every other file of the cycle: a fresh one means they are all in
place. A `generated_at` more than a few minutes old means the producer has
stopped, is stuck, or can't write its files.

| Field | Value |
|---|---|
| `epoch`, `seq`, `count` | As in `head.json` |
| `generated_at` | When this file was written |
| `started_at` | When the producer started; `totals` count from then |
| `cycle` | The latest cycle: `started_at`; `millis`, how long it took; `bytes_in` and `bytes_out`, the listings messages received from nodes and sent to them (see below); `rpc_calls` and `rpc_errors`, to the payment chain's RPC providers; `decided`, addresses decided; `too_few_answered`, true when the cycle decided and removed nothing because too few of the nodes it knows answered (see below) |
| `totals` | Since `started_at`: `cycles`, `bytes_in` and `bytes_out` (counted as the cycle's are, those between cycles, such as pushes, with the next cycle's), and `rpc`, for each provider its host name (`provider`), `calls` and `errors` |
| `census` | The nodes the producer knows: `nodes`; `answering`, those that answered in the latest cycle; `leaves`, the parts the address space is split into; `versions`, how many nodes (`nodes`) give each `version` in their user agent (`null` when unknown); `silent`, each node that didn't answer (`node`, and `last_answered`, or `null` if never) |
| `deferred` | Addresses left for a later cycle, grouped by `reason`, each group with `addresses`, how many, and `oldest_since`, since when the longest-waiting has waited: every address left so, by the reason it was last left for. An entry kept unconfirmed (`carried`) whose address was left for later counts too, though `rejected.json` doesn't list it |
| `below_full` | Entries fewer than all of their nearest nodes serve: `listings`, how many, and `oldest_since`, since when the longest-standing has been (`null` if none) |
| `drops` | `removed`, entries the latest cycle removed, with those removed between it and the cycle before (what pushes changed, decided at once); `carried`, entries kept unconfirmed (see the support files) among those the cycle decided |
| `resources` | What the producer uses, each `null` where it can't tell: `rss_bytes` (its own memory resident, not counting the pages of its store's file the system maps in and can drop at any time), `store_bytes`, `files_bytes` (what it publishes) and `disk_free_bytes` |

`bytes_in` and `bytes_out` count only the listings messages the producer
receives from nodes and sends to them, each message's payload: not the DHT
lookups that find the nodes, nor envelope fetches, nor the transport's own
overhead.

`too_few_answered` is true when fewer than 7 of the census's nodes
answered the cycle, or the census holds under three quarters as many nodes
as in any of the 10 cycles before it, as `darwin listings` measures the
nodes a read finds against its recent reads: nodes that answer lookups but
not the cycle's requests stay in the census and don't stop deciding, and a
census that loses a quarter of its nodes at once stops it until those
cycles have all seen the loss. `census.answering` counts the
nodes that answered the cycle's request with an answer the producer's checks
took, and `silent` lists the others.

`decided` counts the addresses whose decision stands: listed, or rejected for
good. The producer decides every address again after it starts, a batch at a
time, over more than one cycle where the index is large: until it has, the
first cycles' `decided` counts only the addresses decided since the start.
`deferred` counts every address left for later, by the reason it was last
left for, whether or not the cycle decided it again; `drops.carried` counts
among the addresses the cycle decided, so while more changed than a cycle's
minute holds, it can count fewer than the support files mark.

A deferral's `reason` is one of: `below_quorum` (fewer than 4 of the 7 nodes
nearest the address serve it yet), `nodes_unanswered` (nodes nearest it have
yet to answer for it), `envelope_unavailable` (no node serving it handed over
its envelope), `chain_unread` (the payment chain couldn't be read for it),
`not_on_chain_yet` (its payment isn't on the chain yet), `future_time` (it is
dated in the future), and `other`; other reasons may be added. An address is
not deferred when every copy its nearest nodes serve shows a payment from
before the payment vault was deployed (`before_vault_deployment` in
`rejected.json`): none of them can count, however many nodes come to serve
them, so it is rejected for good, in `rejected.json` with `again` false. An
entry still listed that itself shows such a payment is removed (`rejected`)
whenever its address is decided again, rather than kept unconfirmed: every
copy of it shows that payment.

```json
{ "epoch": "8c1f0e2d3b4a5968", "seq": 12, "count": 2, "generated_at": 1791324061, "started_at": 1791320000,
  "cycle": { "started_at": 1791324060, "millis": 312, "bytes_in": 210000, "bytes_out": 180000,
             "rpc_calls": 2, "rpc_errors": 0, "decided": 1, "too_few_answered": false },
  "totals": { "cycles": 68, "bytes_in": 14000000, "bytes_out": 12000000,
              "rpc": [{ "provider": "rpc.example.org", "calls": 40, "errors": 1 }] },
  "census": { "nodes": 20, "answering": 19, "leaves": 2,
              "versions": [{ "version": "node/0.23.0", "nodes": 19 }, { "version": null, "nodes": 1 }],
              "silent": [{ "node": "0505…", "last_answered": 1791323000 }] },
  "deferred": [{ "reason": "below_quorum", "addresses": 2, "oldest_since": 1791144080 }],
  "below_full": { "listings": 1, "oldest_since": 1791320000 },
  "drops": { "removed": 0, "carried": 0 },
  "resources": { "rss_bytes": 104857600, "store_bytes": 1048576, "files_bytes": 524288, "disk_free_bytes": null } }
```

## rejected.json

`{"listings": [...]}`: the listings the producer didn't list, in key order,
each address's latest rejection or deferral. An address the producer lists
has no row, even while its entry is kept unconfirmed (`carried`) because the
cycle left the address for later (`status.json` counts it as deferred). Each
row has the entry's fields from `address` to `time` (no `check`), then:

| Field | Value |
|---|---|
| `problem` | Why it doesn't count, in words |
| `again` | True when nothing final was decided, so it may be listed later (deferred); false when it is rejected for good |
| `nodes` | How many of the nodes nearest its address serve it |
| `nearest` | How many nearest nodes count |
| `decided_at` | When the publication that decided this began, as for an entry |
| `copies` | For a listing too few of its nearest nodes serve yet, each of their copies: `node`, the `block_number`, `block_timestamp` and `first_seen` it shows (each absent when it doesn't), its `time`, and `before_vault_deployment: true` where the block or block timestamp it shows is earlier than the payment vault's deployment, so it paid something else. Absent otherwise |

A rejected or deferred listing's `first_seen`, and so its `time`, is not
dated as a listed entry's is: it is the date the nodes nearest its address
give it before any check. That is the latest of the earliest 4 of their dates
where at least 4 of them serve it, otherwise their median (of two dates, the
later). Its `size` is the listing's own: `null` for a data map shrunk into a
child map, as only listed entries have their root maps read.

A private file's listing that 2 of the 7 nodes nearest its address serve,
left for a later cycle: both copies show the same payment, and the nodes
first stored it an hour apart, so it is dated by the later hour.

```json
{ "listings": [{
  "address": "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0",
  "name": null, "content_type": null, "size": null, "readable": false,
  "hidden": ["tx-hash", "timestamp", "log-index", "quote"],
  "block_number": 81950000, "first_seen": 1791327600, "time": 1791327600,
  "problem": "served by 2 of the 7 nodes nearest its address so far, needs 4; try again",
  "again": true, "nodes": 2, "nearest": 7, "decided_at": 1791327660,
  "copies": [{ "node": "0303…", "block_number": 81950000, "first_seen": 1791324000, "time": 1791324000 },
             { "node": "0505…", "block_number": 81950000, "first_seen": 1791327600, "time": 1791327600 }] }] }
```

## Reading

**Newest first.** `head.json` holds the newest 50. For more, read `pages.json`
and its pages from the last backwards, each page backwards.

**Oldest first.** Read `pages.json`'s pages from the first, each in order.

**A time range.** Keep the pages whose `first` to `last` overlaps the range
(the first 16 hex digits of a key are its time), and the entries in them
whose `time` is in it.

**One address.** Fetch `by-address/<its first three hex digits>.json` and
find the entry with that `address`; its support is in the matching
`.support.json`. An address in neither is not listed: `rejected.json` may say
why.

**An exact name.** Hash the name's UTF-8 bytes with BLAKE3, fetch
`by-name/<first three hex digits>.json`, and take the group whose `name` is
exactly the name. Its entries are newest first; reversed, oldest first.

**A content type.** Fetch `by-type/<first three hex digits of its id>/index.json`,
find the type, and page from `first` or `last` as above.

**Following changes.**

1. Read `pages.json` and every page it lists, and keep its `epoch` and
   `seq`: that is the index after record `seq`. A page that is missing means
   `pages.json` has moved on: read it again.
2. Revalidate `head.json` as often as you like (a reader polling every 10
   seconds costs a `304` while nothing changes; a web page on another origin
   revalidates as **Caching** says). When its `epoch` differs from yours,
   start again at step 1.
3. When its `seq` is past yours, fetch the segments holding the records after
   yours, each with revalidation, and apply those records in order. A
   segment that is missing, or of another epoch, means starting again at
   step 1.
4. Revalidate the support files you use about every 10 minutes.

A reader can also follow the feed from record 1 without reading the pages.
Files are fetched one at a time, so a file can be newer than the
`head.json` that led to it; a record already applied, by `seq`, is skipped.

## How the producer keeps the files

- Each minute (a cycle), it asks every node it knows what changed in what
  it serves (a node slow to answer is waited for no longer than two
  requests' timeouts a cycle, and asked for the rest in the next), decides
  again the addresses whose copies, nearest nodes or chain facts changed,
  first those at least 4 of whose nearest nodes may serve a listing and
  those published or in `rejected.json`, and writes the files those
  decisions change, as many as a minute of deciding holds (what doesn't
  fit, the next cycle decides). It decides every address again after it
  starts and once a day, a batch at a time for what is left of each cycle's
  minute of deciding, over as many cycles as that takes. A node that stores
  a new listing pushes it, and the producer publishes it within seconds,
  without waiting for the next cycle, once at least 4 of its nearest nodes
  have pushed it since the cycle read the nodes: between cycles it decides
  the addresses pushes changed, and only those, as many as fit before the
  next cycle is due, and only on such a quorum of pushes; copies the cycle
  read, or that were pushed before or while it read them, count toward the
  listing's support too, which the next cycle measures again (what doesn't
  fit, and every other change, that cycle decides). While every address is
  being decided again, a listing pushed during a cycle is published with the
  next.
  An address is decided only once at least 4 of its 7 nearest nodes serve a
  listing for it.
- It removes an entry only when, in one cycle, every node nearest its
  address answers that it serves no listing there, and a witnessed lookup
  of the address and a request for it to each of those nodes and to the
  nodes that last served it confirm it (`no_longer_served`), or when
  deciding the address again rejects it, or the entry shows a payment from
  before the payment vault was deployed (`rejected`). An entry it can't
  confirm otherwise is kept, marked `carried` in its support file.
- An entry whose file's data map is shrunk is published without a `size`
  until the producer has read the file's root map, and is then put again
  with it, in a later cycle or between cycles. A data map whose root map
  can't give a size leaves it without (see `size`).
- It writes a file only when its bytes change; the files a change touches
  first, then `pages.json`, `feed/index.json` and `head.json`. Time pages
  that `pages.json` no longer lists are deleted a day later.
- `rejected.json` is written when a rejection or deferral changes, and
  `status.json` every cycle, last: once every other file of the cycle is in
  place and the producer has recorded it as written. A cycle that can't
  write its files leaves `status.json` as it was, so its `generated_at` goes
  stale.
