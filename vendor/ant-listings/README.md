# ant-listings

Envelopes and listings for storage networks built on Autonomi's protocol
(`ant-protocol`).

An upload makes three independent choices:

| Choice | Options |
|---|---|
| Who can read it | the uploader keeps the data map (private) / the data map is stored in the envelope |
| In the index | yes / no |
| Payment fields | each of tx hash, block number, block timestamp, log index and paid quote shown or hidden |

The usual names cover three of the read and index combinations:

| Visibility | What is stored | Who can read it | In the index |
|---|---|---|---|
| private | content chunks, plus an envelope with a salted hash of the data map | whoever holds the data map | no |
| unlisted | content chunks and the data map in an envelope | anyone with the address | no |
| listed | as unlisted | anyone | yes |

The fourth, in the index with the data map withheld, is a public, dated record
of a file nobody can read until the uploader reveals it. An upload that hides
all five payment fields, stays out of the index and has no metadata needs no
envelope, and is stored as plain Darwin data.

Nodes that support envelopes recognise them as they store chunks, find the
on-chain payment for each one, record a listing with the fields the envelope
shows, and answer listing requests on their own topic. Anyone can collect
listings from the nodes and check each one against the chain as far as its
shown fields allow. A listing can't exist without a stored, paid envelope.

This crate holds what nodes and clients share: the envelope format, the listing
record, the payment checks, upload proofs and the protocol messages. It does no
I/O.

## Envelope format (version 2)

| Bytes | Field |
|---|---|
| 8 | magic, `00 41 4E 54 4C 49 53 54` (`"\0ANTLIST"`) |
| 1 | version, `02` |
| 1 | flags (below) |
| 1 | content type length `n`; `0` means none |
| n | content type, printable ASCII |
| 1 | name length `m`; `0` means none |
| m | name, UTF-8 |
| rest | the data map, msgpack-encoded exactly as an unlisted upload stores it, with nothing after it; or, if withheld, exactly 32 bytes of salted hash |

Flags:

| Bit | Set means |
|---|---|
| 0 | tx hash shown |
| 1 | block number shown |
| 2 | block timestamp shown |
| 3 | log index shown |
| 4 | paid quote shown |
| 5 | in the index |
| 6 | data map withheld |
| 7 | reserved: an envelope with it set is invalid |

- The envelope is stored as one chunk. Its address, `blake3(envelope)`, is the
  file's address. The flags are part of the bytes, so they can't change after
  upload.
- Salted hash: `blake3(salt ‖ data map)`, over the data map's bytes exactly as
  an unlisted upload stores them, with 32 random bytes of salt kept by the
  uploader. Revealing the data map and salt proves which file it was. Without
  the salt, anyone with the file could compute its data map and confirm it was
  uploaded.
- The data map must be encoded exactly as `encode_data_map` encodes it (no
  other msgpack form of the same map, no trailing bytes), and its chunk sizes
  must add up to less than 2^64. So each data map has one envelope for each
  choice of flags and metadata. The chunk indexes and sizes in a data map
  aren't checked against the content, so a file's data map can be varied and
  wrapped again at another address, and a listing's size is the uploader's
  word, like its metadata.
- Content type: `type/subtype` with optional parameters, at most 127 bytes.
- Name: at most 255 bytes; no control characters; no format, line or
  paragraph separator characters (Unicode categories Cf, Zl and Zp, such as
  right-to-left overrides, zero-width spaces and line separators), which
  reorder, split or hide text; no path separators (`/`, `\` and characters
  that look like them); not `.` or `..`. Three kinds of Cf character are
  allowed, since ordinary names need them: the soft hyphen, the zero-width
  non-joiner and joiner (in Persian and Indic words, and emoji such as 👩‍💻),
  and tag characters, only as flags such as Scotland's (U+1F3F4, then up to
  7 tag digits and lower-case letters, then U+E007F). Anywhere else, tag
  characters are invisible copies of ASCII that would hide text.
- Metadata is allowed with any flags. It is declared by the uploader and not
  checked. It is readable by anyone with the address, even when the data map
  is withheld. Treat names as untrusted when saving files.

Version 1 (`01`) has no flags byte and is still read: it counts as all shown,
in the index, with the data map, and re-encodes byte for byte. Its names
follow version 1's looser rule (no control characters, `/` or `\`), so every
version 1 envelope stored before version 2 still reads. New envelopes are
always version 2, and a node taking a new upload (a chunk that arrives with
its payment proof) holds its metadata to version 2's rules whatever its
version (`Envelope::check_new_upload`), so nobody can upload a name version 2
forbids by writing a version 1 envelope.

To read a file, fetch its address, check the magic, and download using the data
map in the envelope. A withheld envelope can't be read without the uploader's
data map.

## Listings

A listing holds the envelope's address, its flags and metadata, the file size
when the data map gives it directly, and the shown payment fields: transaction
hash, block number, block timestamp, the log index of the payment vault's
`DataPaymentMade` event, and the paid quote. Hidden fields are never recorded.

A listing in the index that hides the block timestamp also has `first_seen`:
when the node first stored it, in Unix seconds rounded down to the hour, or the
hour of the payment's block if the node's clock is behind it. Each node records
its own, so copies of a listing can differ there. Copies equal apart from
`first_seen` are one listing, dated by the values the nodes nearest its
address returned that pass the checks below on their own. Where at least
`min(4, majority of the nodes asked)` of them serve it, its `first_seen` is the
latest of the earliest that many, so that a quorum of them date it then or
earlier: with all seven answering, their median. Otherwise it is the median of
those values: the later of the two middle ones for an even count, so moving it
earlier takes more than half of them. Other nodes can't move it, however many
there are.

Listings in the index are sorted by key: time, block number, log index and
address, where the time is the block timestamp if shown, otherwise
`first_seen`, and hidden numbers count as zero. As bytes, the key is the three
numbers as 8 bytes big-endian each, then the address: 56 bytes whose byte order
is the key order. For listings that show everything this is the order their
payments were made in.

Listing records stored by version 1 of this crate (all five payment fields, no
flags) read as `ListingV1` and convert to the listing a node records now, so a
node can carry its stored listings over. A listing with the flags a version 1
envelope reads as (`3f`: all shown, in the index, readable) may describe one,
so its name is checked under version 1's rule; any other flags come from a
version 2 envelope, and its name is held to version 2's. Checking a listing
against its envelope holds it to the envelope's own version's rule.

## Checks

A listing is checked against the envelope at its address and against the
chain. The envelope check comes first and is always made: the listing's
address, flags, metadata and size must be the envelope's. So a node can't
serve a file outside the index as if it were in it, forge its name, or show a
field the uploader hid.

What can be checked against the chain depends on the payment fields shown:

| Shown | Fetched from the chain | Checked | Level |
|---|---|---|---|
| the quote (any others) | the tx receipt, by tx hash or through the quote's hash in the vault event | the quote names the address and is signed; the tx succeeded and paid it to the vault; every shown field matches | verified |
| tx hash, no quote | the tx receipt | the tx succeeded and has a vault payment, at the shown log index if shown; shown block and time match | reported |
| block and log index, no tx hash or quote | the receipt of the tx with that vault log | that log is a vault payment; the shown time matches | reported |
| block, no log index, tx hash or quote | the block | the block exists; the shown time matches | reported |
| none of the above | nothing | nothing about the payment | reported |

The paid quote is carried with its timestamp in whole seconds, which is all its
signature and hash cover, so each quote has exactly one encoding.

A verified listing proves that its address was paid for by the block its quote
was paid in, not that this was the upload's payment. Nothing on chain ties a
quote's signing key to the nodes that stored the file, and paying a quote
needs only the address, not the envelope's bytes. The quoting nodes learn the
address before the uploader pays: the uploader sends it to each node it asks
for a quote, and a gateway that builds the envelope knows it too. So any of
them can sign a quote of their own for the address, pay it to themselves
before the uploader's payment lands, and serve the listing built from it once
the envelope is stored; anyone who fetches the envelope can do the same
later. The earliest payment for an address only dates when the address was
first known.

What ties a verified listing to the upload is the nodes nearest its address:
each recorded the payment that came with the upload's PUT, found in that
transaction only. So of several verified listings for one address, the one to
keep is the one that `min(4, majority of the nodes asked)` of those nodes
serve (`choose_verified`). The payment made first only breaks a tie between
copies that both have that many, or, marked as such, stands in when none has:
a fallback a quoting node could have front-run.

A quote can also be paid more than once, which the vault allows. Found through
its hash, each payment is checked, and the earliest that checks out counts
(`verify_listing_receipts`), so a later payment of the same quote never moves
the listing.

Only the quote ties a payment to the file, since it names the envelope's
address. Without it, a listing rests on the nodes that recorded it at upload,
which checked the full payment. Such a listing counts only when at least
`min(4, majority of the nodes asked)` of the nodes nearest its address return
it: 4 of the 7. A node that hasn't been asked for the address is not a node
that doesn't serve it, so a client asks the nearest nodes it hasn't heard from
before deciding. Merging copies counts each node once per address, leaves out
a node that returned two different copies of one, and leaves out copies that
don't fit their flags.

`first_seen` can't be checked exactly. It must not be in the future: no later
than the checker's clock plus an hour for clocks that disagree. The same bound
holds for a shown block timestamp, which is the listing's time in the index
too, and is its only check when nothing locates the payment. And a node
records a listing only after its payment is in a block, so wherever that
block is known, its timestamp must be no later than `first_seen` plus an hour
of rounding plus that hour, so a node can't move a listing earlier in the
index than its payment. A listing that shows none of the tx hash, quote and
block has only the first bound.

Each nearest node's `first_seen` is checked against these bounds on its own,
and values outside them are dropped before the date is taken (`check_copies`,
for node repair and indexers alike). So a few nodes sending a value out of
bounds can neither fail a listing nor move its time, and within the bounds it
takes a quorum to move it earlier. This holds for a verified listing too: its
quote proves the payment, not `first_seen`.

The uploader keeps a proof: the envelope's bytes, the tx hash and the paid
quote, and for a withheld data map the data map and salt. Anyone can check it
with the chain alone: the envelope hashes to the address, the reveal matches
the salted hash, and the quote names the address, is signed and was paid. It
gives back every payment field, hidden ones included.

Like a verified listing, a proof shows that the address was paid for by the
block its quote was paid in. A node asked to quote for the upload can write
one for a payment of its own made before the uploader's, and anyone who
fetches the envelope can write one for a later payment, so of two proofs for
one address, the one paid first is not necessarily the upload's. The
upload's payment is the one the nodes nearest the address recorded from its
PUT. Only a reveal shows who uploaded the file: a proof without one says
nothing about that.

Making a proof checks it: the quote must name the envelope's address and be
signed, and a reveal must match the envelope's salted hash, so a wrong quote
(such as a content chunk's, paid in the same transaction) or salt is refused
before the uploader saves the record rather than when it is needed.

A proof travels as text: the lowercase hex of `01` (the format version)
followed by the postcard-encoded record. A proof file holds that text, and a
JSON field carries it as a string.

## Protocol

Messages travel on the topic `listings.v2`, encoded with postcard:

| Message | Meaning |
|---|---|
| `ListRequest { from, limit }` | listings in the index with keys from `from` onwards, at most `min(limit, 256)` |
| `ListResponse { listings, more }` | listings in key order, at most 256; `more` if the node holds later ones |
| `GetRequest { address }` | the listing for one address, in the index or not |
| `GetResponse { listing }` | the listing, if the node holds it |
| `Error { message }` | the request was refused |

A response with more than 256 listings doesn't decode. A client checks each
page against its request: no more listings than asked for, each in the index,
with keys from `from` onwards and strictly increasing. The next page starts
just after the last key, and paging stops when the node has no more, a page is
empty or the last key is the largest. So a node can't make a client read a
page twice, but it can keep serving new listings, made up or not: see below
for how a walk is bounded. Whether each listing is valid is left to merging, so one listing
a node can't help serving (carried over from an older version, say) doesn't
hide the rest of its index. A `GetResponse` must hold a valid listing for the
address asked for, or none.

Keys are payment times, not the times a node stored its listings. A node can
store a listing after a walk passed its place: one that hides its time is
keyed by the hour it was stored (by the node's clock), and one that shows it
by its block time, however late its PUT came. So a later walk that carries on
from the last key seen misses them. Walk again from `ListingKey::since(when
the previous walk began, longest PUT delay to catch)`, which goes back two
hours plus that delay, and drop the listings already seen. A listing repaired
onto a node keeps its key however old; other nodes stored it first, so only a
walk from the start finds every copy.

### Reading the whole index

An indexer walks every node at once with `IndexWalk`, a state machine that
does no I/O. A fixed cap on what one walk takes from a node would cap the index
too, so each node is read instead for as long as other nodes back what it
sends: 2,048 listings' worth of pages (eight full pages, however few listings
a page holds), and two more for each listing it sends whose address at least
four of the seven nodes nearest it serve, counted where the node is among the
twenty nearest the address. A node holding real listings earns as it goes and
its walk runs to the end; one serving listings nobody else has stops after
eight pages. The nodes furthest behind are asked first, so the walks keep pace
and a node's listings meet the copies that earn it more. A walk stopped early,
by its allowance or the indexer's deadline, gives a key to carry on from in
the next read.

An address's support is how many of the seven nodes nearest it serve some
listing for it; copies from nodes further away don't count. An indexer does
per-address work (fetching the envelope, asking nodes, reading the chain) only
where support reaches four, so nodes fewer than a quorum, however they
collude, cost it nothing beyond their pages, and no fixed number limits how
many real listings the index holds. An address fewer nodes serve waits for a
later read rather than being dropped.

Before deciding an address that no listing has a quorum for yet, ask the
nearest nodes not yet heard from (`MergedListing::unheard_among`). A walk of a
node's whole index answers for a listing only if the listing is in the index
and the walk began at least two hours after the listing's time.

Version 1 (`listings.v1`) is no longer served.

## Licence

MIT or Apache-2.0, at your option.
