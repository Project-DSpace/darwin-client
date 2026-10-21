//! The listings producer behind `darwin listings serve`: one long-lived
//! process that follows what the nodes serve and publishes the index as the
//! files of `listings/v1/` (`docs/listings-v1.md`).
//!
//! It keeps its client and connections, the census of nodes
//! ([`Census`]), a mirror of each node's part of the index ([`Feeds`]),
//! the full listings behind the mirrors' entries, chain facts and envelopes
//! ([`ListingChain::with_store`]) and the published index ([`Publisher`])
//! in one store ([`ListingsStore`]), so a restart starts where the last run
//! stopped.
//!
//! Each cycle ([`Producer::cycle`], every [`CYCLE`]):
//!
//! 1. **Census.** Its upkeep ([`Census::maintain`]): every leaf is closed
//!    with witnessed lookups at the first start and once a day, and a leaf
//!    is closed again when a member misses polls or a node names peers the
//!    census lacks.
//! 2. **Poll.** One request to each census node, [`POLL_CONCURRENCY`] at a
//!    time ([`Feeds::poll`]). A node whose user agent shows the feed
//!    release ([`Census::supports_feed`]) is sent a `ChangesRequest` for its
//!    leaf ([`Census::leaf_of`]), with a watch, and its answer is applied to
//!    its mirror ([`ant_listings::FeedSync`]'s rules). The mirror's count and
//!    set hash must equal the node's; otherwise, as after a new epoch, the
//!    node is read afresh with `RangeListRequest`s and its copies don't count
//!    until that is done. A node without the release is sent one listings v2
//!    request: the next page of a full pass of its index (a new pass starts
//!    at most once every [`V2_PASS_INTERVAL`]), or between passes a read
//!    from the key after the newest listing seen from it. A node that claims
//!    the release but doesn't answer one, or answers its feed requests only
//!    with errors, is read the v2 way, and asked for its feed again an hour
//!    later with one request, its mirror kept until that is answered. The
//!    poll's time starts once the nodes followed are brought in line with
//!    the census, and a node's requests may wait twice a request's timeout
//!    in all: one that has more to send then is asked for it in the next
//!    cycle, so a slow node can't hold the poll open. A node whose push
//!    comes behind its mirror once its requests are answered is asked again
//!    to catch up.
//! 3. **Guard.** If fewer than 7 census nodes answered with answers the
//!    checks took, or the census holds under three quarters as many nodes
//!    as in any of the 10 cycles before ([`Census::guard_ok`]: an index
//!    read's guard, the census standing for the nodes a read finds), the
//!    cycle decides and drops nothing, and every entry is kept, marked
//!    carried, as an index read that finds too few nodes keeps them.
//! 4. **Support.** An address's copies are those of the census's 7 nodes
//!    nearest it ([`Census::nearest`]) whose copies count this cycle: from
//!    the node's mirror when it is in sync, and for a node without the
//!    release from its latest pass, while it keeps answering. A mirror holds
//!    digest entries: the full listing behind each is fetched once with a
//!    `GetRequest`, checked against its entry
//!    ([`ant_listings::DigestEntry::describes`]) and kept in the store, in
//!    the bytes a `GetResponse` carries it in; one of more than
//!    [`MAX_LISTING_BYTES`] is out of spec, and never kept. Fetching is
//!    bounded: it takes at most [`CYCLE`], however long the poll took; every
//!    listing a quorum of an address's nearest nodes name is fetched before
//!    any that fewer name; a node is sent one request at a time, for
//!    listings fewer than a quorum name at most its allowance in pages a
//!    cycle ([`Feeds::page_allowance`]), and nothing more that cycle once it
//!    leaves one unanswered; and a node that failed
//!    to hand over the listing behind its entry isn't asked for it again
//!    until its entry changes, or [`RETRY_INTERVAL`] has passed.
//! 5. **Work per address**, as an index read decides it, a batch of
//!    [`DECIDE_BATCH`] addresses at a time: an address fewer than 4 of its
//!    nearest nodes serve is left for later, shown with its copies; any
//!    other is decided by the read's own code
//!    ([`Client::decide_backed`](crate::data::client::Client)): its envelope,
//!    kept for good; chain facts; `decide_address`, `check_copies` and the
//!    earliest paid with a quorum. The census's nodes stand in for the
//!    nodes a read walks, and a mirror that holds all a node serves stands
//!    in for a walk of its whole index. A node whose full listing couldn't
//!    be had counts as a node not heard from: a listing a quorum of the
//!    other copies serve is decided without it, and otherwise the address
//!    waits, as a read waits for a node that hasn't answered.
//! 6. **Deciding again.** An address is decided again only when an input
//!    changed: its copies or their `first_seen` in a mirror, a node's
//!    copies starting or ceasing to count, or its 7 nearest nodes. It is
//!    also decided again every cycle while its last result was "try again"
//!    for any of its listings, a time in the future, left it for later or
//!    kept it unconfirmed, rests on nodes that serve none of its listings
//!    having been heard (no listing of it has a quorum), or while a chain
//!    fact it was decided on isn't final ([`ListingChain::settled`]); and
//!    once more when a date of one of its copies that the checks left out
//!    for being in the future (later than the clock plus `CLOCK_MARGIN`)
//!    stops being so (one such date is kept for an address, the latest,
//!    and none past the next sweep). Deciding gets a [`CYCLE`] from when it
//!    starts, however long the poll and fetching took. What changed is decided
//!    first where at least a quorum of the address's nearest nodes hold an
//!    entry for it, or it is published or has a row in `rejected.json`
//!    (new listings, changes to what is published, drops), then the rest,
//!    each a batch at a time in address order, for that time (at least a
//!    batch); a pass cut short goes on from where it stopped in the next
//!    cycle, so what a node makes up, however much, can't hold back what a
//!    quorum serves. Every address is decided again at each start and every
//!    [`REDECIDE_INTERVAL`], by a sweep: after what changed, a batch at a
//!    time, for what is left of that time (at least a batch), over as many
//!    cycles as it takes. Within a batch, an address that needs the chain
//!    read or an envelope is begun only while there is time (or as the
//!    first of a pass), and one not begun is left pending for the next
//!    cycle, so a few slow chain reads can't hold a cycle open. A change no
//!    input explains is logged as an alert (but in the sweep after a
//!    start).
//! 7. **Drops.** A published address is removed as `no_longer_served` only
//!    when, within one cycle, all 7 of its nearest nodes answered and none
//!    serves a copy at any key, and then [`Census::confirm_drop`] confirms
//!    it: a witnessed lookup of it finds the same 7, in a leaf closed in
//!    full that cycle (once a cycle, shared by every drop in it), and a
//!    `GetRequest` to each of them, begun at or after the address's key
//!    time plus `FIRST_SEEN_ROUNDING` and `CLOCK_MARGIN`, returns none, as
//!    does one to each node that served it when it was last decided, unless
//!    that node has left the census. Otherwise it stays, marked carried.
//!    Before that time no check is made. A drop the evidence refused (a
//!    node serves the listing, or the lookup found other nodes) isn't
//!    checked again for [`RETRY_INTERVAL`] unless its nearest nodes, its
//!    copies, its last holders or which of them are still members change;
//!    one that only nodes that didn't answer, or a lookup that failed, kept
//!    is checked again at the next cycle, once, before that. Drops are
//!    checked for a [`CYCLE`] from when deciding starts, at least one a
//!    cycle. An entry
//!    decided and rejected is removed as `rejected`, as is one that itself
//!    shows a payment from before the payment vault was deployed: every copy
//!    of it shows that payment, so it can never count.
//! 8. **Publishing.** Each batch's decisions are staged in the publisher's
//!    store as they are made ([`Publisher::stage`]), and once every batch
//!    is decided, the files they changed are written, then `status.json`
//!    after every other file ([`Publisher::write_staged`]).
//!
//! **Sizes.** The listing of a file whose data map is shrunk into a child
//! map gives no size. The producer reads such a file's root map once, as a
//! download does but within bounds (`read_root_size`), and keeps the size
//! it gives for good: an entry is published with its size once known, and
//! until then without, and an entry published without it has it filled in
//! once it is read (a put). The reading never holds up a cycle or a push:
//! after each cycle, once what the last task read is taken, a task of its
//! own reads at most [`SIZES_PER_CYCLE`] root maps, for at most a
//! [`CYCLE`]. Each read is marked before it begins, so a map that couldn't
//! be read, or whose reading was cut short, even by a stop, is read again
//! only after [`RETRY_INTERVAL`]; one that can never give a size isn't
//! read again, and its entry keeps none.
//!
//! Between cycles, nodes push the new records of the leaves they are asked
//! about: a push that brings a mirror to the node's new head is applied
//! ([`Feeds::push`]), and the addresses it changes are decided and
//! published at once, after the guard of the latest cycle, with that
//! cycle's `status.json`: only those, a batch at a time until the next
//! cycle is due, at least a batch, so what else waits to be decided, or
//! what doesn't fit, is left to the cycles' bounded passes. Only an address
//! whose quorum's copies were each pushed since the latest poll is decided
//! so: a mirror shows what its node served at its latest answer or push,
//! and one that has since gone, or changed without its push coming, would
//! still show it. So between cycles a listing is put only on copies just
//! pushed, as when its nearest nodes store a new one; every other change
//! waits for the next cycle. One near a node whose push came behind its
//! mirror, or was dropped, waits too ([`Feeds::behind`]). A node can have
//! only so many pushes waiting (`PUSHES_WAITING_PER_NODE`, in `listings`).
//! Pushes that come during a cycle's poll are decided with the cycle: while
//! a sweep takes the rest of each cycle's time, they wait for the next
//! cycle, but what a quorum serves is decided before anything else. Every
//! publication begins in a later second than the one before it ended in, so
//! a file written twice is never written twice in the same second: a server
//! that tags files by their time to the second and their size then tags
//! every version differently (unless the clock is set back).
//!
//! **Memory.** What grows with the index is in the store, not in memory:
//! the mirrors ([`Feeds`]), the full listings fetched, what is known of
//! each address decided (its nearest nodes when last decided, whether to
//! decide it again, whether its decision stands), the drops the evidence
//! refused, the full listings a node failed to hand over, and the sizes to
//! read. Addresses are worked on a batch at a time, read from the store in
//! address order, and each batch's decisions are staged and let go before
//! the next batch's are made; fetching takes the addresses a batch at a
//! time too. So the producer holds a batch's work at a time, whatever the
//! index holds. What is known of each address is this process's own: it is
//! cleared at each start, and the sweep that starts with the first cycle
//! decides every address again, as an index read does every cycle, from the
//! kept mirrors, listings, facts and envelopes, fetching nothing it fetched
//! before. The nodes whose copies counted when an address was last decided
//! are kept across starts, for drops, and so are the sizes still to read.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::ops::Bound;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ant_listings::{
    AddressWalk, ChangesResponse, DigestEntry, Listing, ListingError, ListingKey, ListingsBody,
    ListingsMessage, Pushed, CLOCK_MARGIN, FIRST_SEEN_ROUNDING, MAX_LIST_LIMIT, NEAREST_NODES,
    QUORUM_THRESHOLD,
};
use ant_protocol::transport::PeerId;
use ant_protocol::{XorName, MAX_WIRE_MESSAGE_SIZE};
use futures::stream::{self, StreamExt};
use heed::byteorder::BigEndian;
use heed::types::{Bytes, DecodeIgnore, U64};
use heed::{Database, RoTxn, RwTxn};
use self_encryption::{DataMap, DataMapIndex, MAX_CHUNK_SIZE};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::sync::Semaphore;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::listings::{
    listings_traffic, push_channel, unix_now, Carry, CheckedListing, Decision, ListingChain,
    ListingsIndex, ListingsRequests, PendingCopy, PushReceiver, PushSink, ReadContext,
    RejectedListing, CHECK_CONCURRENCY, REQUEST_TIMEOUT,
};
use super::listings_census::{user_agent_of, Census, Refusal};
use super::listings_feeds::{FeedNode, Feeds, PollReport};
use super::listings_publish::{IndexChange, Publication, Publisher, RejectedChange};
use super::listings_store::{store_error, ListingsStore};
use super::listings_v1::{
    BelowFull, CycleStatus, DeferredGroup, Drops, Entry, ListingFields, RejectedEntry,
    RemoveReason, Resources, RpcCalls, ShardEntry, Status, Support, Totals,
};
use crate::data::client::Client;
use crate::data::error::{Error, Result};

/// How often a cycle starts: each minute. New listings arrive sooner, by
/// push.
pub const CYCLE: Duration = Duration::from_secs(60);

/// How many nodes are polled at once.
pub const POLL_CONCURRENCY: usize = 64;

/// A node without the feed release starts a new full pass of its index at
/// most this often.
pub const V2_PASS_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Every address is decided again from its stored inputs this often: once
/// a day.
pub const REDECIDE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// How many pushes from the nodes' watches can wait to be taken. One that
/// doesn't fit is dropped, as pushes may be, and the node's next poll
/// catches up.
pub const PUSH_CAPACITY: usize = 1_024;

/// How many addresses are worked on at a time: read from the store, their
/// copies built, decided, staged for publishing and let go before the next
/// batch's. A page's worth ([`MAX_LIST_LIMIT`]).
pub const DECIDE_BATCH: usize = MAX_LIST_LIMIT as usize;

/// A check that failed is made again no sooner than this, unless what it
/// rests on changes first: a drop the evidence refused
/// ([`Census::confirm_drop`]), unless its nearest nodes, its copies in a
/// mirror, the nodes that last served it or which of those are still
/// members change (a drop that only what wasn't heard kept, nodes that
/// didn't answer or a lookup that failed, is checked again once at the next
/// cycle first); a node that failed to hand over the full listing behind its
/// entry, unless its entry changes; a root map that couldn't be read.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// How many root maps of shrunk data maps are read a cycle, all at once: as
/// many as addresses are decided at once (8).
pub const SIZES_PER_CYCLE: usize = CHECK_CONCURRENCY;

/// The most bytes a full listing kept for a digest entry may take, as a
/// `GetResponse` carries it: a page's share of a message, since a node
/// answers with up to [`MAX_LIST_LIMIT`] listings in one message of at most
/// [`MAX_WIRE_MESSAGE_SIZE`] bytes. The largest listing the format allows
/// (every field shown, the longest name and content type, an ML-DSA quote)
/// takes about half of it. A node that hands over a larger one counts as
/// having failed to hand over the listing behind its entry, and nothing of
/// it is kept.
pub const MAX_LISTING_BYTES: usize = MAX_WIRE_MESSAGE_SIZE / MAX_LIST_LIMIT as usize;

/// How many chunks a data map shrunk once holds: self-encryption shrinks a
/// map of more than 3 chunks by encrypting it, as content, into 3 chunks, as
/// long as it takes at most 3 times [`MAX_CHUNK_SIZE`].
const SHRUNK_CHUNKS: usize = 3;

/// The most bytes of root map read for a file's size: what a map shrunk
/// once holds in its [`SHRUNK_CHUNKS`] chunks, the root map of a file of up
/// to about 658 GB. A file whose map declares more, or holds more chunks,
/// keeps no size: its root map isn't read. (Self-encryption labels a map
/// shrunk more than once as shrunk once: see [`read_root_size`].) The root
/// maps being read at once hold this much between them at most.
const MAX_ROOT_MAP_BYTES: usize = SHRUNK_CHUNKS * MAX_CHUNK_SIZE;

/// The store's directory inside the state directory.
pub const STORE_DIR: &str = "listings.mdb";

/// Since when each address has been deferred, or listed below full
/// support: a tag ([`DEFERRED_TAG`] or [`BELOW_FULL_TAG`]) and the
/// address, to Unix seconds, and nothing else, as every version of the
/// producer reads them; and the code of each deferral's latest reason, in a
/// row of its own ([`REASON_TAG`]).
const SINCE_DB: &str = "serve_since";

/// The nodes whose copies counted when each address was last decided: the
/// address, to their ids, 32 bytes each.
const HOLDERS_DB: &str = "serve_holders";

/// The full listings behind the mirrors' digest entries, as `GetRequest`s
/// fetched them: the address and the digest, to the listing without
/// `first_seen`, in the bytes a `GetResponse` carries it in
/// ([`kept_bytes`]), at most [`MAX_LISTING_BYTES`].
const LISTINGS_DB: &str = "serve_listings";

/// The size of each listed file whose data map is shrunk, as its root map
/// gives it: the address, to the size in bytes. Kept for good, since an
/// envelope's address fixes its data map.
const SIZES_DB: &str = "serve_sizes";

/// Each listed file whose data map is shrunk and whose size isn't known: the
/// address, to when its root map may be read next (Unix seconds, 8 bytes
/// big-endian: 0 at once, [`u64::MAX`] never) and the data map, in
/// MessagePack. Kept across starts, so a read that a stop cut short isn't
/// begun again at once.
const SIZE_WANTED_DB: &str = "serve_size_wanted";

/// What this process knows of the addresses it works on, by a tag and the
/// address ([`KNOWN_TAG`], [`AGAIN_TAG`], [`BACKOFF_TAG`], [`FAILED_TAG`],
/// [`FUTURE_TAG`], [`FUTURE_AT_TAG`], [`PUSHED_TAG`]). Cleared at each
/// start.
const KNOWN_DB: &str = "serve_known";

/// [`SINCE_DB`]: an address deferred since then.
const DEFERRED_TAG: u8 = b'd';

/// [`SINCE_DB`]: a deferred address, to the code of the reason it was last
/// deferred for ([`reason_code`]). Kept apart from its [`DEFERRED_TAG`]
/// row, which holds the time alone: a version of the producer that keeps no
/// reasons reads that row as Unix seconds, and leaves these rows be (so one
/// whose address is no longer deferred goes at the next open,
/// [`settle_deferrals`]).
const REASON_TAG: u8 = b'r';

/// The reasons a deferral can have, as `status.json` gives them
/// ([`deferral_reason`]): a deferral's reason row keeps its reason's place
/// here, plus one, as its code ([`reason_code`]).
const DEFERRAL_REASONS: [&str; 7] = [
    "below_quorum",
    "nodes_unanswered",
    "envelope_unavailable",
    "chain_unread",
    "not_on_chain_yet",
    "future_time",
    "other",
];

/// The bits of a [`DEFERRED_TAG`] row that hold its time. An earlier
/// version of the producer kept the deferral's reason's code in the byte
/// above; such a row is read as the time and that code
/// ([`deferral_of`]), and is written again as the time alone, with the code
/// in its reason row, when the producer opens ([`settle_deferrals`]).
const SINCE_TIME: u64 = (1 << 56) - 1;

/// [`SINCE_DB`]: a listed address fewer than all of its nearest nodes have
/// served since then.
const BELOW_FULL_TAG: u8 = b'b';

/// [`KNOWN_DB`]: an address decided, to what is known of it ([`Known`]).
const KNOWN_TAG: u8 = b'k';

/// [`KNOWN_DB`]: an address to decide again next cycle, whatever changes
/// (no value).
const AGAIN_TAG: u8 = b'a';

/// [`KNOWN_DB`]: an address whose drop the evidence refused, to the
/// [`DropBackoff`].
const BACKOFF_TAG: u8 = b'r';

/// [`KNOWN_DB`]: an address, a node and the digest of its entry, to when the
/// node may be asked again for the full listing it failed to hand over
/// (Unix seconds). It isn't asked before then while its entry stays the
/// same.
const FAILED_TAG: u8 = b'f';

/// [`KNOWN_DB`]: when (Unix seconds, 8 bytes big-endian), then an address,
/// that the address is to be decided again (no value): a copy deciding it
/// left out was dated later than the clock plus `CLOCK_MARGIN`, and is no
/// longer from then on ([`Producer::mark_due`]). One row an address, whose
/// time [`FUTURE_AT_TAG`] keeps.
const FUTURE_TAG: u8 = b't';

/// [`KNOWN_DB`]: an address, to the time (Unix seconds, 8 bytes big-endian)
/// of its [`FUTURE_TAG`] row, so that it has only one.
const FUTURE_AT_TAG: u8 = b'u';

/// [`KNOWN_DB`]: an address, then a node that pushed a change to its entry
/// for it since the latest poll (no value). Between cycles, an address is
/// decided only from copies pushed so ([`Producer::decide_pushed`]). Cleared
/// at each poll.
const PUSHED_TAG: u8 = b'p';

/// How [`Client::decide_backed`] begins the problem of a listing it rejects
/// without looking it up, because another one a quorum serves counts: its
/// chain facts were never read, and don't decide anything.
const NOT_LOOKED_UP: &str = "not looked up";

/// What one cycle did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CycleReport {
    /// `status.json` as the cycle wrote it: the cycle's time, traffic, RPC
    /// calls and decisions, the census, deferrals, listings below full
    /// support, drops and resources.
    pub status: Status,
    /// Entries the cycle put: new to the index, or replacing an address's
    /// entry.
    pub put: u64,
    /// How the cycle's poll went: the nodes read through their feeds and
    /// with v2 requests, and the pushes applied during it.
    pub poll: PollReport,
    /// Addresses the cycle decided again.
    pub considered: u64,
    /// Pushes taken between the previous cycle and this one.
    pub pushes_between: u64,
    /// Publications made between the previous cycle and this one: for
    /// pushes taken, or sizes filled in.
    pub published_between: u64,
}

/// A full listing's place among those fetched: its address and digest.
type ListingId = (XorName, [u8; 32]);

/// An address's copies as digest entries, each with its node.
type DigestCopies = Vec<(PeerId, DigestEntry)>;

/// A range of a table's keys.
type KeyRange<'a> = (Bound<&'a [u8]>, Bound<&'a [u8]>);

/// An address to decide, the census's nodes nearest it, and the copies of
/// those whose copies count.
type Work = (XorName, Vec<PeerId>, DigestCopies);

/// A full listing to fetch, the nodes whose entries name it, and whether
/// at least [`QUORUM_THRESHOLD`] of the address's nearest nodes name it.
type Wanted = (ListingId, DigestCopies, bool);

/// Addresses to decide, each with whether a change of its inputs explains
/// deciding it ([`Producer::next_batch`]).
type Batch = Vec<(XorName, bool)>;

/// What the producer keeps of an address between cycles ([`KNOWN_TAG`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Known {
    /// The census's nodes nearest it when it was last decided
    /// ([`nearest_hash`]).
    nearest: u64,
    /// Whether to decide it again next cycle, whatever changes.
    again: bool,
    /// Whether its decision stands: listed, or rejected for good.
    decided: bool,
    /// The cycle of this process it was last decided in, or after
    /// ([`Producer::cycles`]): a sweep passes over an address its cycle
    /// already decided.
    cycle: u32,
}

impl Known {
    fn encode(self) -> [u8; 13] {
        let mut bytes = [0u8; 13];
        bytes[..8].copy_from_slice(&self.nearest.to_be_bytes());
        bytes[8] = u8::from(self.again) | (u8::from(self.decided) << 1);
        bytes[9..].copy_from_slice(&self.cycle.to_be_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; 13] = bytes.try_into().ok()?;
        Some(Self {
            nearest: u64::from_be_bytes(bytes[..8].try_into().ok()?),
            again: bytes[8] & 1 != 0,
            decided: bytes[8] & 2 != 0,
            cycle: u32::from_be_bytes(bytes[9..].try_into().ok()?),
        })
    }
}

/// What deciding an address keeps of its copies, once they are decided.
struct Seen {
    address: XorName,
    /// [`nearest_hash`] of its nearest nodes.
    nearest: u64,
    /// The nodes whose copies counted.
    holders: Vec<PeerId>,
    /// When the earliest date of its copies that is in the future, later
    /// than the clock plus `CLOCK_MARGIN`, stops being so, if one is: until
    /// then a check leaves it out, and once it is in, deciding the address
    /// may give another listing or date.
    future: Option<u64>,
}

/// Every address decided again, a batch at a time in address order, over as
/// many cycles as it takes: each cycle goes on from where the last stopped,
/// for what is left of the cycle's time.
#[derive(Debug, Clone, Copy)]
struct Sweep {
    /// The last address decided, if any yet.
    after: Option<XorName>,
    /// When it began (Unix seconds): once done, every address has been
    /// decided again since then.
    began: u64,
    /// Whether a change no input explains is logged as an alert: not in the
    /// first after a start, or after a cycle that decided nothing.
    alert: bool,
}

impl Sweep {
    /// Whether `address` is still to come in the sweep.
    fn ahead(&self, address: &XorName) -> bool {
        self.after.is_none_or(|after| *address > after)
    }
}

/// A pass over addresses a batch at a time in address order, from where the
/// latest stopped, past the last address round to the first and on to
/// there ([`Producer::decide_changed`]).
#[derive(Debug, Clone, Copy)]
struct Rotation {
    /// Where the pass began: after this address, or at the first.
    began: Option<XorName>,
    /// The last address of the latest batch read.
    after: Option<XorName>,
    /// Whether the pass went past the last address, round to the first.
    round: bool,
}

impl Rotation {
    /// A pass beginning after `after`, or at the first address.
    fn new(after: Option<XorName>) -> Self {
        Self {
            began: after,
            after,
            round: false,
        }
    }

    /// Leave out of `batch`, read after [`Self::after`], what comes after
    /// where the pass began once it went round: that was read already.
    fn keep(&self, batch: &mut Batch) {
        if self.round {
            if let Some(began) = self.began {
                batch.retain(|(address, _)| *address <= began);
            }
        }
    }

    /// Go on after a batch whose last address is `last`, `done` if no more
    /// came after it. Returns whether the pass goes on.
    fn advance(&mut self, last: Option<XorName>, done: bool) -> bool {
        let back = self.round
            && self
                .began
                .is_some_and(|began| last.is_none_or(|last| last >= began));
        match last {
            Some(last) if !done && !back => {
                self.after = Some(last);
                true
            }
            _ if self.round || self.began.is_none() => false,
            _ => {
                self.round = true;
                self.after = None;
                true
            }
        }
    }
}

/// A drop that wasn't confirmed: checked again once its inputs change, or
/// at `retry_at` ([`BACKOFF_TAG`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DropBackoff {
    /// [`drop_inputs`] when it was refused.
    inputs: u64,
    /// Unix seconds.
    retry_at: u64,
    /// Whether it is checked again at the next cycle, as once after a
    /// refusal only by what wasn't heard: nodes that didn't answer, or a
    /// lookup that failed.
    soon: bool,
}

impl DropBackoff {
    fn encode(self) -> [u8; 17] {
        let mut bytes = [0u8; 17];
        bytes[..8].copy_from_slice(&self.inputs.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.retry_at.to_be_bytes());
        bytes[16] = u8::from(self.soon);
        bytes
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; 17] = bytes.try_into().ok()?;
        Some(Self {
            inputs: u64::from_be_bytes(bytes[..8].try_into().ok()?),
            retry_at: u64::from_be_bytes(bytes[8..16].try_into().ok()?),
            soon: bytes[16] != 0,
        })
    }
}

/// Which addresses a cycle works on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// Every address a mirror holds, that is published, has a row in
    /// `rejected.json`, is deferred, pending or to decide again.
    All,
    /// The addresses whose copies changed ([`Feeds::pending_after`]), and
    /// with `again` those to decide again whatever changes.
    Pending {
        /// Whether those to decide again come too.
        again: bool,
    },
}

/// The drop checks of a cycle: at least one, then while there is time.
#[derive(Debug)]
struct DropCheck {
    /// Whether one was checked this cycle.
    checked: bool,
    /// When the cycle's time is out.
    deadline: Instant,
}

/// A pass of deciding, over batches of addresses: how long it may go on
/// deciding addresses at least a quorum of whose nearest nodes may serve a
/// listing, the work that reads the chain and fetches envelopes. One is
/// begun only before `until`, or as the first of the pass, so a pass always
/// decides something, and no batch holds its pass past `until` by more than
/// the decisions already begun. One not begun is left to a later cycle.
#[derive(Debug)]
struct Pass {
    until: Instant,
    /// Whether the pass has begun one.
    begun: AtomicBool,
}

impl Pass {
    /// A pass until `until`, which may begin one decision after it unless
    /// `begun`: it isn't the first of its kind in the cycle.
    fn new(until: Instant, begun: bool) -> Self {
        Self {
            until,
            begun: AtomicBool::new(begun),
        }
    }

    /// A pass with no end: for tests.
    #[cfg(test)]
    fn unbounded() -> Self {
        Self::new(Instant::now() + REDECIDE_INTERVAL, false)
    }

    /// Whether another decision may begin now.
    fn may_begin(&self) -> bool {
        let first = !self.begun.swap(true, Ordering::Relaxed);
        first || Instant::now() < self.until
    }
}

/// What deciding a batch of addresses gave, to publish and then keep
/// ([`Producer::keep`]).
struct Decided {
    /// The addresses of the batch.
    addresses: Vec<XorName>,
    /// What was decided, as an index read gives it.
    index: ListingsIndex,
    /// Each published entry of an address decided and not listed, with why
    /// it is removed, if it is.
    unlisted: Vec<(ListingKey, Option<RemoveReason>)>,
    /// What to keep of each address decided; `None` to forget it.
    known: Vec<(XorName, Option<Known>)>,
    /// The nodes whose copies counted, for each address decided with some.
    holders: Vec<(XorName, Vec<PeerId>)>,
    /// Addresses no node nearest them serves any more, and that nothing is
    /// published for: their kept holders and listings go.
    forget: Vec<XorName>,
    /// Every address decided: settled in the mirrors once staged.
    settle: Vec<XorName>,
    /// Addresses left for later because none of their copies could be had,
    /// each with its deferral's reason: shown in no row of `rejected.json`,
    /// as there is no listing to show, but counted as deferred.
    waiting: Vec<(XorName, &'static str)>,
    /// Full listings kept that couldn't be read back: they go, to be fetched
    /// again.
    unreadable: Vec<ListingId>,
    /// Addresses decided with a copy dated in the future, not to be decided
    /// again before: each with when its date stops being in the future
    /// ([`FUTURE_TAG`]).
    future: Vec<(XorName, u64)>,
    /// Addresses the batch held that its pass had no time left to decide
    /// ([`Pass`]): not decided, they are made pending, for a later cycle.
    later: Vec<XorName>,
}

/// What reading a file's root map gave ([`read_root_size`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SizeRead {
    /// The file's size.
    Sized(u64),
    /// The map can't give one, however often it is read: malformed, or of
    /// more than [`SHRUNK_CHUNKS`] chunks or [`MAX_ROOT_MAP_BYTES`].
    Never,
    /// It couldn't be read this time: a chunk wasn't handed over.
    Later,
}

/// The root maps being read, by a task of their own ([`SIZES_PER_CYCLE`]).
struct SizeJob {
    /// Each address read, with what reading it gave. Those not read by the
    /// deadline aren't in it.
    results: tokio::sync::oneshot::Receiver<Vec<(XorName, SizeRead)>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for SizeJob {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The listings producer. See the module docs.
pub struct Producer {
    client: Arc<Client>,
    chain: ListingChain,
    store: ListingsStore,
    census: Census,
    feeds: Feeds,
    publisher: Publisher,
    since: Database<Bytes, U64<BigEndian>>,
    holders: Database<Bytes, Bytes>,
    /// The full listings behind digest entries ([`LISTINGS_DB`]).
    listings: Database<Bytes, Bytes>,
    /// The size of each listed file whose data map is shrunk
    /// ([`SIZES_DB`]).
    sizes: Database<Bytes, U64<BigEndian>>,
    /// The sizes still to read ([`SIZE_WANTED_DB`]).
    size_wanted: Database<Bytes, Bytes>,
    /// What is known of each address ([`KNOWN_DB`]).
    known: Database<Bytes, Bytes>,
    /// Routes the answers to listings requests, and the nodes' pushes to
    /// `pushes`: started at the first cycle.
    requests: Option<ListingsRequests>,
    /// Where `requests` sends pushes, until it starts.
    sink: Option<PushSink>,
    pushes: PushReceiver,
    /// How many addresses' decisions stand: listed, or rejected for good.
    standing: u64,
    /// How many more `GetRequest`s for full listings each node may be sent
    /// this cycle: its allowance in pages ([`Feeds::page_allowance`]) at
    /// the cycle's start.
    fetch_budget: FetchBudget,
    /// Nodes to ask for their nearest peers at the next poll.
    want_peers: BTreeSet<PeerId>,
    /// When this process last decided every address (Unix seconds): when
    /// the latest sweep that went to the end began.
    decided_all_at: Option<u64>,
    /// The sweep under way, deciding every address again, if any.
    sweep: Option<Sweep>,
    /// Where the latest cycle's pass over what changed stopped, for want of
    /// time: the next goes on from there ([`Self::decide_changed`]).
    changed_after: Option<XorName>,
    /// Where its first pass, over what a quorum may serve or is published,
    /// stopped so.
    first_after: Option<XorName>,
    /// Cycles run by this process, wrapping: the latest's number.
    cycles: u32,
    /// Whether the latest cycle's guard let it decide: pushes are decided
    /// between cycles only then.
    guard_ok: bool,
    /// `status.json` as the latest cycle gave it, for publications between
    /// cycles.
    last_status: Option<Status>,
    /// The second (Unix) in which the latest publication ended.
    published_second: u64,
    /// Pushes taken between cycles since the latest one.
    pushes_between: u64,
    /// Publications made between cycles since the latest one.
    published_between: u64,
    /// Entries those publications removed: counted into the next cycle's
    /// `status.json`, as a cycle that found them gone would count them.
    removed_between: u64,
    /// The root maps being read, if any.
    size_job: Option<SizeJob>,
    /// The last row of [`SIZE_WANTED_DB`] the latest reading took: the next
    /// goes on after it, round to the first, so every row due gets its
    /// turn, however the rows before it fare.
    size_after: Option<XorName>,
    /// Room for the root maps being read at once: [`MAX_ROOT_MAP_BYTES`],
    /// in permits of a KiB.
    size_room: Arc<Semaphore>,
    /// When this process started, in Unix seconds.
    started_at: u64,
    /// Counts since then.
    totals: Totals,
    /// The listings traffic counted into `totals` so far, received and
    /// sent: traffic between cycles is added with the next cycle's.
    traffic_counted: (u64, u64),
}

impl Producer {
    /// The producer keeping its state in `state_dir` (the store, in
    /// [`STORE_DIR`]) and publishing the files of `listings/v1/` in
    /// `out_dir`, reading the network through `client` and the payment
    /// chain of `client`'s EVM network ([`Client::with_evm_network`]).
    ///
    /// # Errors
    ///
    /// If `client` has no EVM network, another process has the store open,
    /// or the store or `out_dir` can't be opened.
    pub fn open(state_dir: &Path, out_dir: &Path, client: Client) -> Result<Self> {
        let network = client.require_evm_network()?.clone();
        let store = ListingsStore::open(&state_dir.join(STORE_DIR))?;
        let chain = ListingChain::new(&network)?.with_store(&store)?;
        let census = Census::open(&store)?;
        let feeds = Feeds::open(&store)?;
        let publisher = Publisher::open(out_dir, &store)?;
        let since: Database<Bytes, U64<BigEndian>> = store.database(SINCE_DB)?;
        let holders: Database<Bytes, Bytes> = store.database(HOLDERS_DB)?;
        let listings: Database<Bytes, Bytes> = store.database(LISTINGS_DB)?;
        let sizes: Database<Bytes, U64<BigEndian>> = store.database(SIZES_DB)?;
        let size_wanted: Database<Bytes, Bytes> = store.database(SIZE_WANTED_DB)?;
        let known: Database<Bytes, Bytes> = store.database(KNOWN_DB)?;
        // What an earlier process knew of each address is its own: this
        // one decides every address again, starting in its first cycle.
        let mut txn = store.env().write_txn().map_err(store_error)?;
        known.clear(&mut txn).map_err(store_error)?;
        settle_deferrals(since, &mut txn)?;
        txn.commit().map_err(store_error)?;
        let (sink, pushes) = push_channel(PUSH_CAPACITY);
        let now = unix_now();
        let traffic_counted = listings_traffic();
        Ok(Self {
            client: Arc::new(client),
            chain,
            store,
            census,
            feeds,
            publisher,
            since,
            holders,
            listings,
            sizes,
            size_wanted,
            known,
            requests: None,
            sink: Some(sink),
            pushes,
            standing: 0,
            fetch_budget: FetchBudget::default(),
            want_peers: BTreeSet::new(),
            decided_all_at: None,
            sweep: None,
            changed_after: None,
            first_after: None,
            cycles: 0,
            guard_ok: false,
            last_status: None,
            // An earlier process may have published in this second.
            published_second: now,
            pushes_between: 0,
            published_between: 0,
            removed_between: 0,
            size_job: None,
            size_after: None,
            size_room: Arc::new(Semaphore::new(MAX_ROOT_MAP_BYTES.div_ceil(1024))),
            started_at: now,
            totals: Totals::default(),
            traffic_counted,
        })
    }

    /// On a first start, while the store holds no index yet, take the
    /// entries of `previous`, an earlier `darwin listings --json` output
    /// (such as the `listings.json` the producer replaces), into the index
    /// as carried: published as they were, marked carried in their support,
    /// until a cycle decides their addresses or shows them no longer served.
    /// So nothing published is lost before the first cycles confirm it.
    /// Their support files are written at once and don't start the support
    /// files' interval, so the support write after them isn't held back: the
    /// first cycle that changes any support, as deciding any of them does,
    /// publishes it at once ([`Publisher::publish_carry`]). Returns how many
    /// were taken: none, without reading `previous`, once the store holds an
    /// index, and none if `previous` doesn't exist. Entries marked as failing
    /// their checks (`"valid": false`) are not taken; every other one is, as
    /// it was published.
    ///
    /// # Errors
    ///
    /// If `previous` can't be read or isn't such an output, or the index
    /// can't be published.
    pub fn carry_from(&mut self, previous: &Path) -> Result<usize> {
        let status = self.base_status();
        let taken = carry_into(&mut self.publisher, previous, status)?;
        if taken > 0 {
            self.published_second = unix_now();
        }
        Ok(taken)
    }

    /// Run cycles until `cancel` fires: one every [`CYCLE`], the first at
    /// once, and between them, the pushes of the nodes' watches as they
    /// come, and the sizes read. A cycle that fails is logged and the next
    /// one runs on time. On `cancel`, a cycle still reading the network is
    /// abandoned where it stands: the batches it staged stay staged, and
    /// the next start's first publication writes their files; one writing
    /// its files finishes first. After each cycle, and once it stops, the
    /// client's peer cache and adaptive snapshot are saved
    /// ([`Client::save_peer_cache`]), so a restart, even after the process
    /// was killed, joins through the peers it knew. Once it stops, it also
    /// ends its watch on each node read through its feed
    /// ([`Feeds::unwatch_requests`]), waiting at most a request's timeout
    /// for the answers: a node keeps only so many watchers, and the next
    /// start comes back as another reader, which would otherwise wait for
    /// these watches to lapse.
    ///
    /// # Errors
    ///
    /// Only if the producer can't go on at all: when its store can't be
    /// read or written.
    pub async fn run(&mut self, cancel: CancellationToken) -> Result<()> {
        let result = self.run_cycles(&cancel).await;
        self.size_job = None;
        self.end_watches().await;
        self.save_client_state().await;
        result
    }

    /// End this process's watch on each node read through its feed
    /// ([`Feeds::unwatch_requests`]), all at once, waiting at most a
    /// request's timeout for the answers, which change nothing.
    async fn end_watches(&self) {
        let Some(requests) = self.requests.as_ref() else {
            return;
        };
        let asks = self.feeds.unwatch_requests();
        if asks.is_empty() {
            return;
        }
        let count = asks.len();
        let sent = futures::future::join_all(
            asks.into_iter()
                .map(|(peer, body)| async move { requests.ask(&peer, body).await }),
        );
        match tokio::time::timeout(REQUEST_TIMEOUT, sent).await {
            Ok(answers) => debug!(
                "Ended the watches on {count} nodes: {} answered",
                answers.iter().filter(|answer| answer.is_some()).count()
            ),
            Err(_) => debug!("Ended the watches on {count} nodes: not all answered in time"),
        }
    }

    async fn run_cycles(&mut self, cancel: &CancellationToken) -> Result<()> {
        loop {
            let next = Instant::now() + CYCLE;
            // On the heap: a cycle's future is too large for a main thread's
            // stack on some systems.
            let cycle = Box::pin(self.cycle());
            tokio::select! {
                () = cancel.cancelled() => return Ok(()),
                result = cycle => match result {
                    Ok(report) => log_cycle(&report),
                    Err(e @ Error::Storage(_)) => return Err(e),
                    Err(e) => warn!("A listings cycle failed: {e}"),
                },
            }
            self.save_client_state().await;
            // Sizes read while the cycle ran are taken first, so the next
            // reads can start.
            if self
                .size_job
                .as_ref()
                .is_some_and(|job| job.task.is_finished())
            {
                let read = sizes_read(&mut self.size_job).await;
                self.size_job = None;
                let taken = Box::pin(self.take_sizes(read));
                let result = tokio::select! {
                    () = cancel.cancelled() => return Ok(()),
                    result = taken => result,
                };
                match result {
                    Ok(()) => {}
                    Err(e @ Error::Storage(_)) => return Err(e),
                    Err(e) => warn!("Publishing sizes failed: {e}"),
                }
            }
            if let Err(e) = self.start_sizes() {
                if matches!(e, Error::Storage(_)) {
                    return Err(e);
                }
                warn!("Could not start reading sizes: {e}");
            }
            loop {
                let event = tokio::select! {
                    () = cancel.cancelled() => return Ok(()),
                    () = tokio::time::sleep_until(next) => break,
                    push = self.pushes.recv() => Between::Push(push),
                    sizes = sizes_read(&mut self.size_job) => Between::Sizes(sizes),
                };
                let event = match event {
                    Between::Push(None) => {
                        // No sender is left: wait for the next cycle, and
                        // the sizes being read.
                        tokio::select! {
                            () = cancel.cancelled() => return Ok(()),
                            () = tokio::time::sleep_until(next) => break,
                            sizes = sizes_read(&mut self.size_job) => Between::Sizes(sizes),
                        }
                    }
                    event => event,
                };
                let handled = match event {
                    Between::Push(None) => Ok(()),
                    Between::Push(Some(push)) => {
                        // What pushes change is fetched until the next cycle
                        // is due.
                        let taken = Box::pin(self.take_pushes(push, next));
                        tokio::select! {
                            () = cancel.cancelled() => return Ok(()),
                            result = taken => result,
                        }
                    }
                    Between::Sizes(sizes) => {
                        self.size_job = None;
                        let taken = Box::pin(self.take_sizes(sizes));
                        tokio::select! {
                            () = cancel.cancelled() => return Ok(()),
                            result = taken => result,
                        }
                    }
                };
                match handled {
                    Ok(()) => {}
                    Err(e @ Error::Storage(_)) => return Err(e),
                    Err(e) => warn!("Publishing between cycles failed: {e}"),
                }
            }
        }
    }

    /// Save what the client learned of the network, as the one-shot
    /// commands do when they end: its peer cache and adaptive snapshot.
    async fn save_client_state(&self) {
        self.client.save_peer_cache().await;
        self.client.save_adaptive_snapshot();
    }

    /// Start routing listings requests' answers, and pushes, if not yet.
    fn start_requests(&mut self) {
        if self.requests.is_none() {
            let sink = self.sink.take();
            self.requests = Some(ListingsRequests::start(self.client.network().node(), sink));
        }
    }

    /// Run one cycle (see the module docs) and publish what it changed.
    ///
    /// # Errors
    ///
    /// If the store or the published files can't be written. Nodes and RPCs
    /// that fail are no error: the cycle decides less.
    pub async fn cycle(&mut self) -> Result<CycleReport> {
        let clock = std::time::Instant::now();
        let began = Instant::now();
        let at = unix_now();
        let before = Counters::now(&self.chain);
        let pushes_between = std::mem::take(&mut self.pushes_between);
        let published_between = std::mem::take(&mut self.published_between);
        self.cycles = self.cycles.wrapping_add(1);
        self.start_requests();
        // Each node's allowance of full-listing requests starts again.
        self.fetch_budget.clear();

        if let Err(e) = Box::pin(self.census.maintain(&self.client)).await {
            warn!("The census's upkeep failed in part: {e}");
        }
        let change = self.census.take_changes();
        if !change.unanswered.is_empty() {
            debug!(
                "Census: {} ids named by other nodes answered no lookup",
                change.unanswered.len()
            );
        }

        let asked = std::mem::take(&mut self.want_peers);
        let nodes = FeedNode::from_census(&self.census, |peer| asked.contains(peer));
        // The nodes followed are brought in line with the census before the
        // poll's time starts: what that takes, which grows with the index
        // when nodes leave, never takes the nodes' time.
        self.feeds.reconcile(&self.census, &nodes, at)?;
        // The poll reads every node afresh: what was pushed before it, or
        // dropped for want of room, is read with it.
        self.forget_pushed()?;
        let _ = self.pushes.take_dropped();
        let deadline = Instant::now() + CYCLE;
        let Some(requests) = self.requests.as_ref() else {
            return Err(Error::Network("listings requests are not routed".into()));
        };
        // A node no lookup has connected to since this process started is
        // dialed at the addresses the census keeps for it, and the watches
        // of nodes that left the census end.
        requests.set_addresses(
            self.census
                .nodes()
                .map(|node| (node.peer, node.addresses.clone())),
        );
        let census = &self.census;
        requests.keep_watches(|peer| census.get(peer).is_some());
        let poll = Box::pin(self.feeds.poll(
            requests,
            &self.census,
            &nodes,
            at,
            deadline,
            Some(&mut self.pushes),
        ))
        .await?;
        let answered = self.note_answers(at, &asked).await;
        let guard_ok = self.census.guard_ok(answered);
        self.census.note_cycle();
        self.guard_ok = guard_ok;

        // Nothing below reads the network but fetching listings, deciding
        // and confirming drops: a cancelled cycle has written nothing but the
        // mirrors, the census, the listings fetched and the batches staged,
        // which the next cycle finds as they were.
        let mut tally = Tally::default();
        let mut considered = 0;
        if guard_ok {
            // Every address is decided again from its kept inputs at each
            // start, after a cycle that decided nothing, and once a day: by
            // a sweep, over as many cycles as it takes.
            let due = self
                .decided_all_at
                .is_none_or(|all| at.saturating_sub(all) >= REDECIDE_INTERVAL.as_secs());
            if self.sweep.is_none() && due {
                self.sweep = Some(Sweep {
                    after: None,
                    began: at,
                    // Deciding every address again after a start, nothing
                    // needs explaining.
                    alert: self.decided_all_at.is_some(),
                });
            }
            if !change.is_empty() {
                self.mark_moved()?;
            }
            self.mark_due(at)?;
            // However long the poll took, fetching gets as long as a poll
            // may take, and deciding as long again from when it starts: what
            // changed first, those a quorum of their nearest nodes hold or
            // that are published or have a row before the rest, then the
            // sweep, each for what is left of deciding's time and at least
            // a batch, and drops within the same time, at least one check.
            let source = Source::Pending { again: true };
            let fetch_deadline = Instant::now() + CYCLE;
            Box::pin(self.fetch_for(source, fetch_deadline)).await?;
            let until = Instant::now() + CYCLE;
            let mut drops = DropCheck {
                checked: false,
                deadline: until,
            };
            considered = Box::pin(self.decide_changed(at, until, &mut drops, &mut tally)).await?;
            considered += Box::pin(self.sweep_on(at, until, &mut drops, &mut tally)).await?;
            // The nodes' backing, counted again after who is followed
            // changed, for what is left of the time, at least a batch.
            self.feeds.recount_some(&self.census, until)?;
        } else {
            // As an index read that finds too few nodes: nothing is decided
            // or dropped, and every entry is kept, carried, until a sweep
            // decides every address again.
            self.carry_all(at, &mut tally)?;
            self.decided_all_at = None;
            self.sweep = None;
            self.feeds.recount_some(&self.census, began + CYCLE)?;
        }
        // Removals published between cycles count with this cycle's.
        tally.removed += std::mem::take(&mut self.removed_between);
        // A cycle that decides nothing counts no decision, as an index read
        // that finds too few nodes counts none.
        let decided = if guard_ok { self.standing } else { 0 };
        let status = self.status(at, clock, before, !guard_ok, decided, &tally)?;
        self.write_spaced(at, &status).await?;
        self.census.save()?;
        self.last_status = Some(status.clone());
        Ok(CycleReport {
            status: self.published_status(status),
            put: tally.put,
            poll,
            considered,
            pushes_between,
            published_between,
        })
    }

    /// Note in the census how each of its nodes answered the poll that began
    /// at `at`, and its view; `asked` are the nodes asked for their nearest
    /// peers. A node counts as answering only with answers the checks took.
    /// Returns how many answered.
    async fn note_answers(&mut self, at: u64, asked: &BTreeSet<PeerId>) -> usize {
        let peers: Vec<PeerId> = self.census.nodes().map(|node| node.peer).collect();
        let network = self.client.network();
        let mut answered = 0;
        for peer in peers {
            if self.feeds.read(&peer).is_some_and(|read| read.answered) {
                answered += 1;
                let agent = user_agent_of(network, &peer).await;
                self.census.record_answer(&peer, at, agent);
                if asked.contains(&peer) {
                    match self.feeds.view_peers(&peer) {
                        Some(peers) => {
                            let queued = self.census.note_peers(&peer, peers);
                            if queued > 0 {
                                debug!("Census: {peer} names nodes it lacks in {queued} leaves");
                            }
                        }
                        None => {
                            self.want_peers.insert(peer);
                        }
                    }
                }
            } else {
                self.census.record_miss(&peer);
                if asked.contains(&peer) {
                    self.want_peers.insert(peer);
                }
            }
            if let Some(view) = self.feeds.view(&peer) {
                if self.census.record_view(&peer, view) {
                    self.want_peers.insert(peer);
                }
            }
        }
        answered
    }

    /// Make pending every address whose nearest nodes changed since it was
    /// last decided, as after the census changed: those a mirror holds and
    /// those decided, a batch at a time. One this process hasn't decided yet
    /// is left to the sweep under way where that is still to come to it.
    ///
    /// # Errors
    ///
    /// If the store can't be read or written.
    fn mark_moved(&mut self) -> Result<()> {
        for held in [true, false] {
            let mut after: Option<XorName> = None;
            loop {
                let batch = if held {
                    self.feeds.held_after(after.as_ref(), DECIDE_BATCH)?
                } else {
                    let txn = self.store.env().read_txn().map_err(store_error)?;
                    tagged_after(self.known, &txn, KNOWN_TAG, after.as_ref(), DECIDE_BATCH)?
                };
                let moved: Vec<XorName> = {
                    let txn = self.store.env().read_txn().map_err(store_error)?;
                    let mut moved = Vec::new();
                    for address in &batch {
                        let nearest = nearest_hash(&self.census.nearest(address, NEAREST_NODES));
                        let moved_on = match self.known_of(&txn, address)? {
                            Some(known) => known.nearest != nearest,
                            None => !self.sweep.is_some_and(|sweep| sweep.ahead(address)),
                        };
                        if moved_on {
                            moved.push(*address);
                        }
                    }
                    moved
                };
                self.feeds.mark_pending(&moved)?;
                match batch.last() {
                    Some(last) if batch.len() == DECIDE_BATCH => after = Some(*last),
                    _ => break,
                }
            }
        }
        Ok(())
    }

    /// Make pending every address to be decided again by `now` (Unix
    /// seconds), as a date of its copies in the future then no longer is
    /// ([`FUTURE_TAG`]), and forget that it was to be.
    ///
    /// # Errors
    ///
    /// If the store can't be read or written.
    fn mark_due(&mut self, now: u64) -> Result<()> {
        let from = [FUTURE_TAG];
        let mut through = vec![FUTURE_TAG];
        through.extend_from_slice(&now.to_be_bytes());
        through.extend_from_slice(&[0xff; 32]);
        loop {
            let keys: Vec<Vec<u8>> = {
                let txn = self.store.env().read_txn().map_err(store_error)?;
                let range = (Bound::Included(&from[..]), Bound::Included(&through[..]));
                let mut keys = Vec::new();
                for row in self
                    .known
                    .remap_data_type::<DecodeIgnore>()
                    .range(&txn, &range)
                    .map_err(store_error)?
                {
                    if keys.len() == DECIDE_BATCH {
                        break;
                    }
                    let (key, ()) = row.map_err(store_error)?;
                    keys.push(key.to_vec());
                }
                keys
            };
            if keys.is_empty() {
                return Ok(());
            }
            let due: Vec<XorName> = keys
                .iter()
                .filter_map(|key| key.get(9..).and_then(|rest| XorName::try_from(rest).ok()))
                .collect();
            self.feeds.mark_pending(&due)?;
            let mut txn = self.store.env().write_txn().map_err(store_error)?;
            for key in &keys {
                self.known.delete(&mut txn, key).map_err(store_error)?;
            }
            for address in &due {
                self.known
                    .delete(&mut txn, &tagged(FUTURE_AT_TAG, address))
                    .map_err(store_error)?;
            }
            txn.commit().map_err(store_error)?;
        }
    }

    /// What is known of `address`, if it was decided ([`KNOWN_TAG`]).
    fn known_of(&self, txn: &RoTxn, address: &XorName) -> Result<Option<Known>> {
        Ok(self
            .known
            .get(txn, &tagged(KNOWN_TAG, address))
            .map_err(store_error)?
            .and_then(Known::decode))
    }

    /// The next batch of addresses from `source` after `after` (or from the
    /// first): up to [`DECIDE_BATCH`] of them, in address order, each with
    /// whether a change of its inputs explains deciding it (it is pending,
    /// or to decide again).
    ///
    /// # Errors
    ///
    /// If the store can't be read.
    fn next_batch(&self, source: Source, after: Option<&XorName>) -> Result<Batch> {
        let limit = DECIDE_BATCH;
        let pending = self.feeds.pending_after(after, limit)?;
        let again = match source {
            Source::All | Source::Pending { again: true } => {
                let txn = self.store.env().read_txn().map_err(store_error)?;
                tagged_after(self.known, &txn, AGAIN_TAG, after, limit)?
            }
            Source::Pending { again: false } => Vec::new(),
        };
        let explained: HashSet<XorName> = pending.iter().chain(&again).copied().collect();
        let mut addresses: BTreeSet<XorName> = explained.iter().copied().collect();
        if source == Source::All {
            addresses.extend(self.feeds.held_after(after, limit)?);
            addresses.extend(self.publisher.listed_after(after, limit)?);
            addresses.extend(self.publisher.rejected_after(after, limit)?);
            let txn = self.store.env().read_txn().map_err(store_error)?;
            addresses.extend(tagged_after(self.since, &txn, DEFERRED_TAG, after, limit)?);
        }
        Ok(addresses
            .into_iter()
            .take(limit)
            .map(|address| (address, explained.contains(&address)))
            .collect())
    }

    /// The next batch of `source` after `after` ([`Self::next_batch`]), with
    /// the address to go on from and whether it was the last.
    ///
    /// # Errors
    ///
    /// If the store can't be read.
    fn batch_of(
        &self,
        source: Source,
        after: Option<&XorName>,
    ) -> Result<(Batch, Option<XorName>, bool)> {
        let batch = self.next_batch(source, after)?;
        let last = batch.last().map(|(address, _)| *address);
        let done = batch.len() < DECIDE_BATCH;
        Ok((batch, last, done))
    }

    /// Decide every address of `source`, a batch at a time
    /// ([`Self::decide_batch`]), whatever the time: for tests. Returns how
    /// many addresses were decided, and whether any batch staged a change.
    ///
    /// # Errors
    ///
    /// If the store can't be read or written.
    #[cfg(test)]
    async fn decide_all(
        &mut self,
        source: Source,
        at: u64,
        mut drops: Option<&mut DropCheck>,
        alert: bool,
        tally: &mut Tally,
    ) -> Result<(u64, bool)> {
        let mut decided_count = 0;
        let mut staged = false;
        let mut after: Option<XorName> = None;
        let pass = Pass::unbounded();
        loop {
            let (batch, last, done) = self.batch_of(source, after.as_ref())?;
            let (count, changed) =
                Box::pin(self.decide_batch(batch, at, drops.as_deref_mut(), alert, &pass, tally))
                    .await?;
            decided_count += count;
            staged |= changed;
            match last {
                Some(last) if !done => after = Some(last),
                _ => break,
            }
        }
        Ok((decided_count, staged))
    }

    /// Decide `batch`, addresses each with whether a change of its inputs
    /// explains deciding it ([`Self::next_batch`]): decided within `pass`'s
    /// time ([`Self::decide`]), its publication staged at `at`
    /// ([`Publisher::stage`]) and what it decided kept ([`Self::keep`]).
    /// With `drops`, published addresses no node serves any more are checked
    /// for dropping, within its time. With `alert`, a change no input
    /// explains is logged. What is published is counted into `tally`.
    /// Returns how many addresses it decided (those `pass` had no time for
    /// are left pending), and whether it staged a change.
    ///
    /// # Errors
    ///
    /// If the store can't be read or written.
    async fn decide_batch(
        &mut self,
        batch: Batch,
        at: u64,
        drops: Option<&mut DropCheck>,
        alert: bool,
        pass: &Pass,
        tally: &mut Tally,
    ) -> Result<(u64, bool)> {
        if batch.is_empty() {
            return Ok((0, false));
        }
        let explained: BTreeSet<XorName> = batch
            .iter()
            .filter(|(_, explained)| *explained)
            .map(|(address, _)| *address)
            .collect();
        let addresses: Vec<XorName> = batch.iter().map(|(address, _)| *address).collect();
        let mut decided = Box::pin(self.decide(addresses, drops, pass)).await?;
        let publication = self.publication(&mut decided, at, tally)?;
        if alert {
            alert_unexplained(&publication, &explained);
        }
        let staged = !publication.changes.is_empty()
            || !publication.support.is_empty()
            || !publication.rejected.is_empty();
        if staged {
            self.publisher.stage(&publication)?;
        }
        drop(publication);
        let count = (decided.addresses.len()) as u64;
        self.keep(decided)?;
        Ok((count, staged))
    }

    /// Decide what changed, until `until`, at least a batch, each batch as
    /// [`Self::decide_batch`] decides it, in two passes. First the addresses
    /// whose copies changed that at least a quorum of their nearest nodes'
    /// mirrors hold, or that are published or have a row in `rejected.json`
    /// ([`Self::first_to_decide`]): new listings, changes to what is
    /// published, and drops. Then, while there is time, every address
    /// waiting to be decided (`Source::Pending { again: true }`) that this
    /// cycle hasn't decided. Each pass goes a batch at a time in address
    /// order, from where the latest cycle's stopped, past the last address
    /// round to the first and on to there. So whatever else waits, such as
    /// entries one node made up and changes all the time, can't hold back
    /// what a quorum serves, and a pass cut short is gone on with by the next
    /// cycle, so every address comes in turn, however much changed. Returns
    /// how many addresses it decided.
    ///
    /// # Errors
    ///
    /// If the store can't be read or written.
    async fn decide_changed(
        &mut self,
        at: u64,
        until: Instant,
        drops: &mut DropCheck,
        tally: &mut Tally,
    ) -> Result<u64> {
        let pass = Pass::new(until, false);
        let mut decided = 0;
        let mut rotation = Rotation::new(self.first_after.take());
        loop {
            let source = Source::Pending { again: false };
            let (mut batch, last, done) = self.batch_of(source, rotation.after.as_ref())?;
            rotation.keep(&mut batch);
            let mut first: Batch = Vec::with_capacity(batch.len());
            for (address, explained) in batch {
                if self.first_to_decide(&address)? {
                    first.push((address, explained));
                }
            }
            let (count, _) =
                Box::pin(self.decide_batch(first, at, Some(&mut *drops), false, &pass, tally))
                    .await?;
            decided += count;
            if !rotation.advance(last, done) {
                break;
            }
            if Instant::now() >= until {
                self.first_after = rotation.after;
                break;
            }
        }
        let mut rotation = Rotation::new(self.changed_after.take());
        let mut first = decided == 0;
        loop {
            if !first && Instant::now() >= until {
                self.changed_after = rotation.after;
                break;
            }
            first = false;
            let source = Source::Pending { again: true };
            let (mut batch, last, done) = self.batch_of(source, rotation.after.as_ref())?;
            rotation.keep(&mut batch);
            let batch = self.not_this_cycle(batch)?;
            let (count, _) =
                Box::pin(self.decide_batch(batch, at, Some(&mut *drops), false, &pass, tally))
                    .await?;
            decided += count;
            if !rotation.advance(last, done) {
                break;
            }
        }
        Ok(decided)
    }

    /// Whether `address`, waiting to be decided, is among those decided
    /// first ([`Self::decide_changed`]): at least [`QUORUM_THRESHOLD`] of
    /// the [`NEAREST_NODES`] census nodes nearest it hold an entry for it in
    /// their mirrors ([`Feeds::is_backed`]), or it is published, or has a
    /// row in `rejected.json`.
    ///
    /// # Errors
    ///
    /// If the store can't be read.
    fn first_to_decide(&self, address: &XorName) -> Result<bool> {
        Ok(self.feeds.is_backed(address)? || self.publisher.lists_or_rejects(address)?)
    }

    /// `batch` without the addresses this cycle decided already.
    ///
    /// # Errors
    ///
    /// If the store can't be read.
    fn not_this_cycle(&self, batch: Batch) -> Result<Batch> {
        let txn = self.store.env().read_txn().map_err(store_error)?;
        let mut fresh = Vec::with_capacity(batch.len());
        for (address, explained) in batch {
            let this_cycle = self
                .known_of(&txn, &address)?
                .is_some_and(|known| known.cycle == self.cycles);
            if !this_cycle {
                fresh.push((address, explained));
            }
        }
        Ok(fresh)
    }

    /// Go on with the sweep under way, if any, until `until`, at least a
    /// batch: each batch of every address ([`Source::All`]) from where it
    /// stopped, its full listings fetched, then decided at `at` as
    /// [`Self::decide_batch`] decides one, but for the addresses this cycle
    /// decided already. A sweep that reaches the last address is done:
    /// every address has been decided again since it began. Returns how many
    /// addresses it decided.
    ///
    /// # Errors
    ///
    /// If the store can't be read or written.
    async fn sweep_on(
        &mut self,
        at: u64,
        until: Instant,
        drops: &mut DropCheck,
        tally: &mut Tally,
    ) -> Result<u64> {
        let mut decided = 0;
        let mut first = true;
        let pass = Pass::new(until, false);
        while let Some(sweep) = self.sweep {
            if !first && Instant::now() >= until {
                break;
            }
            first = false;
            let (batch, last, done) = self.batch_of(Source::All, sweep.after.as_ref())?;
            let batch = self.not_this_cycle(batch)?;
            if !batch.is_empty() {
                let addresses: Vec<XorName> = batch.iter().map(|(address, _)| *address).collect();
                Box::pin(self.fetch_addresses(&addresses, until)).await?;
                let (count, _) = Box::pin(self.decide_batch(
                    batch,
                    at,
                    Some(&mut *drops),
                    sweep.alert,
                    &pass,
                    tally,
                ))
                .await?;
                decided += count;
            }
            self.sweep = match last {
                Some(last) if !done => Some(Sweep {
                    after: Some(last),
                    ..sweep
                }),
                _ => {
                    self.decided_all_at = Some(sweep.began);
                    None
                }
            };
        }
        Ok(decided)
    }

    /// As an index read that finds too few nodes: every published entry is
    /// kept, marked carried, staged a batch at a time, and every address a
    /// mirror holds counts as left for later.
    ///
    /// # Errors
    ///
    /// If the store can't be read or written.
    fn carry_all(&mut self, at: u64, tally: &mut Tally) -> Result<()> {
        let held = self.feeds.held_count()?;
        let index = ListingsIndex::too_few(usize::try_from(held).unwrap_or(usize::MAX));
        let listed = BTreeMap::new();
        let mut after: Option<XorName> = None;
        loop {
            let batch = self.publisher.listed_after(after.as_ref(), DECIDE_BATCH)?;
            let mut unlisted = Vec::with_capacity(batch.len());
            for address in &batch {
                if let Some(key) = self
                    .publisher
                    .entry(address)?
                    .and_then(|entry| entry.entry.key())
                {
                    unlisted.push((key, None));
                }
            }
            let publication = read_publication(
                &self.publisher,
                &index,
                &listed,
                &unlisted,
                |_| None,
                at,
                tally,
            )?;
            if !publication.support.is_empty() {
                self.publisher.stage(&publication)?;
            }
            match batch.last() {
                Some(last) if batch.len() == DECIDE_BATCH => after = Some(*last),
                _ => break,
            }
        }
        if held > 0 {
            tally.groups.insert("nodes_unanswered", (held, at));
        }
        Ok(())
    }

    /// Decide `addresses`, a batch (see the module docs), from the full
    /// listings fetched for them. An address at least a quorum of whose
    /// nearest nodes may serve a listing is decided only while `pass` has
    /// time ([`Pass`]); one it has none for is left out of what is decided,
    /// and made pending for a later cycle. With `drops`, an address none of
    /// whose nearest nodes serves a copy is looked at too: its published
    /// entry is dropped on the evidence [`Census::confirm_drop`] finds,
    /// checked while the cycle has time (at least one a cycle), and its row
    /// in `rejected.json` cleared once every node nearest it has been read in
    /// full long enough after its time. Without, such an address is left for
    /// the next cycle.
    ///
    /// # Errors
    ///
    /// If the store can't be read or written.
    async fn decide(
        &mut self,
        mut addresses: Vec<XorName>,
        mut drops: Option<&mut DropCheck>,
        pass: &Pass,
    ) -> Result<Decided> {
        let mut index = ListingsIndex::default();
        let mut pending: Vec<AddressWalk<PeerId>> = Vec::new();
        let mut backed: Vec<(AddressWalk<PeerId>, Vec<PeerId>)> = Vec::new();
        let mut waiting: Vec<(XorName, Vec<PeerId>, &'static str)> = Vec::new();
        let mut empty: Vec<(XorName, Vec<PeerId>)> = Vec::new();
        let mut unheard_addresses = 0usize;
        let mut with_copies: Vec<XorName> = Vec::new();
        let mut unreadable: Vec<ListingId> = Vec::new();
        for address in &addresses {
            let nearest = self.census.nearest(address, NEAREST_NODES);
            let copies = self.feeds.copies(address, &nearest)?;
            if copies.is_empty() {
                empty.push((*address, nearest));
                continue;
            }
            with_copies.push(*address);
            let (taken, unheard) = {
                let txn = self.store.env().read_txn().map_err(store_error)?;
                let fetched = |digest: &[u8; 32]| match self.kept_listing(&txn, address, digest) {
                    Kept::Listing(listing) => Some(*listing),
                    Kept::Unreadable => {
                        unreadable.push((*address, *digest));
                        None
                    }
                    Kept::None => None,
                };
                copies_from(fetched, &copies)
            };
            if !unheard.is_empty() {
                unheard_addresses += 1;
            }
            if taken.is_empty() && unheard.is_empty() {
                empty.push((*address, nearest));
                continue;
            }
            if taken.is_empty() {
                // Nothing to show of it: it waits, as a read waits for nodes
                // that haven't answered.
                let reason = if unheard.len() < QUORUM_THRESHOLD {
                    "below_quorum"
                } else {
                    "nodes_unanswered"
                };
                waiting.push((*address, nearest, reason));
                continue;
            }
            let found = AddressWalk {
                address: *address,
                support: taken.len(),
                nearest,
                copies: taken,
            };
            if found.support + unheard.len() < QUORUM_THRESHOLD {
                pending.push(found);
            } else {
                backed.push((found, unheard));
            }
        }
        if unheard_addresses > 0 {
            debug!("{unheard_addresses} addresses have copies whose full listings couldn't be had");
        }
        if !unreadable.is_empty() {
            warn!(
                "{} full listings kept couldn't be read back: they are fetched again",
                unreadable.len()
            );
        }
        // Some node serves a copy: no drop to back off from.
        self.forget_backoffs(with_copies.iter())?;
        index.defer(&pending, &self.chain);
        let now = unix_now();
        let pending_seen: Vec<Seen> = pending.iter().map(|found| Seen::of(found, now)).collect();
        let mut backed_seen: Vec<Seen> = backed
            .iter()
            .map(|(found, _)| Seen::of(found, now))
            .collect();
        drop(pending);
        let mut decisions: Vec<Decision> = Vec::new();
        let mut later: Vec<XorName> = Vec::new();
        if !backed.is_empty() {
            let Some(requests) = self.requests.as_ref() else {
                return Err(Error::Network("listings requests are not routed".into()));
            };
            let context = self.read_context();
            let (client, chain, context) = (&self.client, &self.chain, &context);
            let decided: Vec<std::result::Result<Decision, XorName>> = stream::iter(backed)
                .map(|(found, unheard)| async move {
                    if !pass.may_begin() {
                        return Err(found.address);
                    }
                    Ok(client
                        .decide_backed(found, context, requests, chain, &unheard)
                        .await)
                })
                .buffer_unordered(CHECK_CONCURRENCY)
                .collect()
                .await;
            for decision in decided {
                match decision {
                    Ok(decision) => decisions.push(decision),
                    Err(address) => later.push(address),
                }
            }
        }
        if !later.is_empty() {
            debug!(
                "{} addresses are left for a later cycle: deciding had no time left",
                later.len()
            );
            let left: HashSet<XorName> = later.iter().copied().collect();
            backed_seen.retain(|seen| !left.contains(&seen.address));
            addresses.retain(|address| !left.contains(address));
        }

        // Addresses none of whose nearest nodes serves a copy.
        let mut gone: HashSet<XorName> = HashSet::new();
        let mut removed: HashSet<XorName> = HashSet::new();
        let mut kept: HashSet<XorName> = HashSet::new();
        let mut forget: Vec<XorName> = Vec::new();
        if let Some(drops) = drops.as_deref_mut() {
            Box::pin(self.check_drops(
                &empty,
                drops,
                &mut gone,
                &mut removed,
                &mut kept,
                &mut forget,
            ))
            .await?;
        }

        index.finish_decided(decisions, gone);
        let listed: HashMap<XorName, &CheckedListing> = index
            .listings
            .iter()
            .map(|checked| (checked.listing.address, checked))
            .collect();
        // Addresses one of whose listings was left to try again, was
        // rejected on chain facts that aren't final yet, or was refused for
        // a time in the future, which a later cycle's clock may pass.
        let in_future = ListingError::TimeInFuture.to_string();
        let rows_again: HashSet<XorName> = index
            .rejected
            .iter()
            .filter(|row| {
                row.again || unsettled(&self.chain, row) || row.problem.contains(&in_future)
            })
            .map(|row| row.listing.address)
            .collect();
        // Addresses a listing of which a quorum of their nearest nodes
        // serves: what nodes that serve none of their listings say can't
        // change their decision. One decided without, a verified listing
        // without a quorum or listings too few serve rejected, rests on those
        // nodes having been heard: it is decided again each cycle, as an
        // index read decides it.
        let quorum_held: HashSet<XorName> = index
            .rejected
            .iter()
            .filter(|row| row.nodes >= QUORUM_THRESHOLD)
            .map(|row| row.listing.address)
            .chain(
                index
                    .listings
                    .iter()
                    .filter(|checked| checked.quorum)
                    .map(|checked| checked.listing.address),
            )
            .collect();
        let mut decided = Decided {
            addresses,
            index: ListingsIndex::default(),
            unlisted: Vec::new(),
            known: Vec::new(),
            holders: Vec::new(),
            forget,
            settle: Vec::new(),
            waiting: Vec::new(),
            unreadable,
            future: Vec::new(),
            later,
        };
        let mut considered: Vec<(XorName, u64, bool)> = Vec::new();
        for seen in pending_seen {
            considered.push((seen.address, seen.nearest, true));
            decided.holders.push((seen.address, seen.holders));
        }
        for seen in backed_seen {
            let address = seen.address;
            // A copy whose full listing couldn't be had doesn't make its
            // address decided again: one that waits for it isn't decided,
            // and one decided without it can't be decided otherwise with it,
            // as no other listing can have a quorum. It is fetched again
            // when its entry changes, or by the next sweep.
            let again = !index.was_decided(&address)
                || rows_again.contains(&address)
                || !quorum_held.contains(&address)
                || listed
                    .get(&address)
                    .is_some_and(|checked| !self.chain.settled(&checked.listing));
            // A copy's date that was in the future, and left out, is in once
            // the clock passes it: the address is decided again then, as a
            // read would decide it then, and not every cycle until.
            if !again {
                decided.future.extend(seen.future.map(|due| (address, due)));
            }
            considered.push((address, seen.nearest, again));
            decided.holders.push((address, seen.holders));
        }
        for (address, nearest, reason) in waiting {
            considered.push((address, nearest_hash(&nearest), true));
            decided.waiting.push((address, reason));
        }
        if drops.is_some() {
            for (address, nearest) in empty {
                if kept.contains(&address) {
                    considered.push((address, nearest_hash(&nearest), true));
                } else {
                    decided.settle.push(address);
                    decided.known.push((address, None));
                    if removed.contains(&address) {
                        if let Some(key) = self
                            .publisher
                            .entry(&address)?
                            .and_then(|entry| entry.entry.key())
                        {
                            decided
                                .unlisted
                                .push((key, Some(RemoveReason::NoLongerServed)));
                        }
                    }
                }
            }
        }
        for (address, nearest, again) in considered {
            decided.settle.push(address);
            decided.known.push((
                address,
                Some(Known {
                    nearest,
                    again,
                    // Set once published ([`Self::publication`]).
                    decided: false,
                    cycle: self.cycles,
                }),
            ));
            if listed.contains_key(&address) {
                continue;
            }
            let Some(published) = self.publisher.entry(&address)? else {
                continue;
            };
            if let Some(key) = published.entry.key() {
                let reason = removal(
                    &index,
                    &address,
                    &key,
                    &published.entry.listing,
                    &self.chain,
                );
                decided.unlisted.push((key, reason));
            }
        }
        drop(listed);
        decided.index = index;
        Ok(decided)
    }

    /// The drop checks of `empty`, addresses none of whose nearest nodes
    /// serves a copy, each with its nearest nodes, within `drops`' time:
    /// what goes, what is removed from the index, what is kept, and what is
    /// forgotten, noted in the sets given.
    ///
    /// # Errors
    ///
    /// If the store can't be read or written.
    async fn check_drops(
        &mut self,
        empty: &[(XorName, Vec<PeerId>)],
        drops: &mut DropCheck,
        gone: &mut HashSet<XorName>,
        removed: &mut HashSet<XorName>,
        kept: &mut HashSet<XorName>,
        forget: &mut Vec<XorName>,
    ) -> Result<()> {
        let now = unix_now();
        for (address, nearest) in empty {
            let read_whole = nearest.len() >= NEAREST_NODES
                && nearest.iter().all(|peer| {
                    self.feeds
                        .read(peer)
                        .is_some_and(|read| read.counts && read.complete)
                });
            let published = self
                .publisher
                .entry(address)?
                .and_then(|entry| entry.entry.key());
            if let Some(key) = published {
                // Before its time plus FIRST_SEEN_ROUNDING and CLOCK_MARGIN,
                // a node that stored it may not show it yet, so no check can
                // drop it ([`Census::confirm_drop`]): none is made, and none
                // is backed off from.
                let too_soon = now < key.time.saturating_add(FIRST_SEEN_ROUNDING + CLOCK_MARGIN);
                if !read_whole || too_soon {
                    kept.insert(*address);
                    continue;
                }
                let last = self.last_holders(address)?;
                let inputs = drop_inputs(nearest, &last, |peer| self.census.get(peer).is_some());
                let changed = self.feeds.is_pending(address)?;
                let backoff = self.backoff_of(address)?;
                let backing_off = !changed
                    && backoff
                        .is_some_and(|backoff| backoff.inputs == inputs && now < backoff.retry_at);
                let out_of_time = drops.checked && Instant::now() >= drops.deadline;
                if backing_off || out_of_time {
                    kept.insert(*address);
                    continue;
                }
                drops.checked = true;
                let Some(requests) = self.requests.as_ref() else {
                    kept.insert(*address);
                    continue;
                };
                match Box::pin(self.census.confirm_drop(
                    &self.client,
                    requests,
                    address,
                    key.time,
                    nearest,
                    &last,
                ))
                .await
                {
                    Ok(()) => {
                        removed.insert(*address);
                        gone.insert(*address);
                        forget.push(*address);
                    }
                    Err(refusal) => {
                        info!(
                            "Keeping {}, which its nearest nodes no longer serve: {refusal}",
                            hex::encode(address)
                        );
                        kept.insert(*address);
                        self.set_backoff(address, drop_backoff(&refusal, backoff, inputs, now))?;
                    }
                }
            } else if let Some(row) = self.publisher.rejected_entry(address)? {
                let Some(key) = row.listing.key() else {
                    forget.push(*address);
                    continue;
                };
                // As an index read clears it: every node nearest it read in
                // full long enough after its time to have stored it.
                let read_since = nearest
                    .iter()
                    .map(|peer| self.feeds.complete_since(peer))
                    .collect::<Option<Vec<u64>>>()
                    .and_then(|since| since.into_iter().min());
                let stored_by = key.time.saturating_add(FIRST_SEEN_ROUNDING + CLOCK_MARGIN);
                if read_whole && read_since.is_some_and(|since| since >= stored_by) {
                    gone.insert(*address);
                    forget.push(*address);
                } else {
                    kept.insert(*address);
                }
            } else {
                forget.push(*address);
            }
        }
        Ok(())
    }

    /// The drop of `address` the evidence refused, if one was.
    fn backoff_of(&self, address: &XorName) -> Result<Option<DropBackoff>> {
        let txn = self.store.env().read_txn().map_err(store_error)?;
        Ok(self
            .known
            .get(&txn, &tagged(BACKOFF_TAG, address))
            .map_err(store_error)?
            .and_then(DropBackoff::decode))
    }

    /// Note that the evidence refused the drop of `address`.
    fn set_backoff(&self, address: &XorName, backoff: DropBackoff) -> Result<()> {
        let mut txn = self.store.env().write_txn().map_err(store_error)?;
        self.known
            .put(&mut txn, &tagged(BACKOFF_TAG, address), &backoff.encode())
            .map_err(store_error)?;
        txn.commit().map_err(store_error)
    }

    /// Forget the refused drops of `addresses`, which have copies to show.
    fn forget_backoffs<'a>(&self, addresses: impl Iterator<Item = &'a XorName>) -> Result<()> {
        let mut txn = self.store.env().write_txn().map_err(store_error)?;
        let mut any = false;
        for address in addresses {
            any |= self
                .known
                .delete(&mut txn, &tagged(BACKOFF_TAG, address))
                .map_err(store_error)?;
        }
        if any {
            txn.commit().map_err(store_error)?;
        }
        Ok(())
    }

    /// The full listing behind the entry of `address` with `digest`, as
    /// fetched and kept, without `first_seen` ([`kept_listing`]).
    fn kept_listing(&self, txn: &RoTxn<'_>, address: &XorName, digest: &[u8; 32]) -> Kept {
        match self.listings.get(txn, &listing_key(address, digest)) {
            Ok(Some(bytes)) => kept_listing(bytes)
                .map_or(Kept::Unreadable, |listing| Kept::Listing(Box::new(listing))),
            Ok(None) => Kept::None,
            Err(_) => Kept::Unreadable,
        }
    }

    /// Fetch, with a `GetRequest` to the nodes holding it, the full listing
    /// behind each digest entry of the addresses of `source` not kept yet,
    /// and keep the first that the node's entry describes and that takes at
    /// most [`MAX_LISTING_BYTES`]. The addresses are read a batch at a time,
    /// twice: first for the digests a quorum of their nearest nodes name,
    /// then for the others, so every listing a quorum serves is fetched
    /// before any that fewer do. How the fetches go is [`fetch_wanted`]'s:
    /// [`POLL_CONCURRENCY`] at once, one request at a time to a node, each
    /// node sent at most its allowance in pages a cycle
    /// ([`Feeds::page_allowance`]) and nothing more once it leaves one
    /// unanswered. A node that failed to hand over the listing behind its
    /// entry isn't asked for it again for [`RETRY_INTERVAL`], unless its
    /// entry changes. What hasn't come by `deadline` is left for later: its
    /// copies can't be had this time.
    ///
    /// # Errors
    ///
    /// If the store can't be read or written.
    async fn fetch_for(&self, source: Source, deadline: Instant) -> Result<()> {
        let now = unix_now();
        let error: std::cell::RefCell<Option<Error>> = std::cell::RefCell::new(None);
        let mut sink = FetchSink::new(self, now);
        for quorum in [true, false] {
            if Instant::now() >= deadline {
                break;
            }
            let wanted = WantedIter::new(self, source, quorum, now, deadline, &error);
            self.fetch_wanted_into(wanted, deadline, &mut sink).await;
            sink.flush()?;
            if let Some(e) = error.borrow_mut().take() {
                return Err(e);
            }
        }
        sink.flush()
    }

    /// Fetch the full listings behind the digest entries of `addresses`, as
    /// [`Self::fetch_for`] fetches those of a source: those a quorum of
    /// their nearest nodes name first.
    ///
    /// # Errors
    ///
    /// If the store can't be read or written.
    async fn fetch_addresses(&self, addresses: &[XorName], deadline: Instant) -> Result<()> {
        let now = unix_now();
        let work = self.work_of(addresses)?;
        let mut wanted = self.wanted_of(&work, true, now)?;
        wanted.extend(self.wanted_of(&work, false, now)?);
        if wanted.is_empty() {
            return Ok(());
        }
        let mut sink = FetchSink::new(self, now);
        self.fetch_wanted_into(wanted.into_iter(), deadline, &mut sink)
            .await;
        sink.flush()
    }

    /// Fetch `wanted` ([`fetch_wanted`]) through this producer's requests,
    /// within each node's allowance this cycle, into `sink`.
    async fn fetch_wanted_into(
        &self,
        wanted: impl Iterator<Item = Wanted>,
        deadline: Instant,
        sink: &mut FetchSink<'_>,
    ) {
        let Some(requests) = self.requests.as_ref() else {
            return;
        };
        let (client, feeds, budget) = (&self.client, &self.feeds, &self.fetch_budget);
        let take = move |peer: &PeerId, quorum: bool| {
            budget.take(peer, quorum, || feeds.page_allowance(peer))
        };
        let unanswered = move |peer: &PeerId| budget.exhaust(peer);
        let ask = move |peer: PeerId, address: XorName| async move {
            client
                .ask_for_listing(requests, &address, &[peer])
                .await
                .into_iter()
                .next()
                .and_then(|(_, answer)| answer)
        };
        fetch_wanted(
            wanted,
            take,
            unanswered,
            deadline,
            ask,
            |key, listing, failed| sink.add(key, listing, failed),
        )
        .await;
    }

    /// The full listings to fetch for the next batch of `source` after
    /// `after` ([`Self::batch_of`]): of the digests a quorum of each
    /// address's nearest nodes name if `quorum`, else of the others
    /// ([`Self::wanted_of`]). Also returns the batch's last address, and
    /// whether the batch was the last.
    ///
    /// # Errors
    ///
    /// If the store can't be read.
    fn wanted_after(
        &self,
        source: Source,
        after: Option<&XorName>,
        quorum: bool,
        now: u64,
    ) -> Result<(Vec<Wanted>, Option<XorName>, bool)> {
        let (batch, last, done) = self.batch_of(source, after)?;
        let addresses: Vec<XorName> = batch.iter().map(|(address, _)| *address).collect();
        let work = self.work_of(&addresses)?;
        Ok((self.wanted_of(&work, quorum, now)?, last, done))
    }

    /// Each of `addresses` that has copies this cycle, with them.
    ///
    /// # Errors
    ///
    /// If the store can't be read.
    fn work_of(&self, addresses: &[XorName]) -> Result<Vec<Work>> {
        let mut work: Vec<Work> = Vec::new();
        for address in addresses {
            let nearest = self.census.nearest(address, NEAREST_NODES);
            let copies = self.feeds.copies(address, &nearest)?;
            if !copies.is_empty() {
                work.push((*address, Vec::new(), copies));
            }
        }
        Ok(work)
    }

    /// The full listings to fetch for `work` ([`fetches_wanted`]): each
    /// digest an entry names that isn't kept, of those a quorum of the
    /// address's nearest nodes name if `quorum`, else of the others, with
    /// the nodes whose entries name it but those that failed to hand it over
    /// less than [`RETRY_INTERVAL`] before `now`.
    ///
    /// # Errors
    ///
    /// If the store can't be read.
    fn wanted_of(&self, work: &[Work], quorum: bool, now: u64) -> Result<Vec<Wanted>> {
        let txn = self.store.env().read_txn().map_err(store_error)?;
        let failed = |peer: &PeerId, (address, digest): &ListingId| {
            self.known
                .get(&txn, &failed_key(address, peer, digest))
                .ok()
                .flatten()
                .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
                .is_some_and(|retry_at| now < u64::from_be_bytes(retry_at))
        };
        let kept = |(address, digest): &ListingId| {
            self.listings
                .get(&txn, &listing_key(address, digest))
                .is_ok_and(|kept| kept.is_some())
        };
        Ok(fetches_wanted(work, quorum, failed, kept))
    }

    /// What deciding an address needs to know of the nodes, as an index
    /// read gives it from its walks: since when each node's mirror has held
    /// all it serves, for nodes that answered this cycle; the nodes that
    /// didn't, which are asked nothing more; and each node's addresses.
    fn read_context(&self) -> ReadContext {
        let mut full_walks = HashMap::new();
        let mut silent = HashSet::new();
        let mut addresses = HashMap::new();
        for node in self.census.nodes() {
            addresses.insert(node.peer, node.addresses.clone());
            if self
                .feeds
                .read(&node.peer)
                .is_some_and(|read| read.answered)
            {
                if let Some(since) = self.feeds.complete_since(&node.peer) {
                    full_walks.insert(node.peer, since);
                }
            } else {
                silent.insert(node.peer);
            }
        }
        ReadContext {
            full_walks,
            silent,
            addresses,
            demoted: Mutex::new(HashSet::new()),
        }
    }

    /// The nodes whose copies of `address` counted when it was last
    /// decided, or if none are kept, every node whose mirror holds it.
    ///
    /// # Errors
    ///
    /// If the store can't be read.
    fn last_holders(&self, address: &XorName) -> Result<Vec<PeerId>> {
        let kept: Vec<PeerId> = {
            let txn = self.store.env().read_txn().map_err(store_error)?;
            self.holders
                .get(&txn, address)
                .map_err(store_error)?
                .map(|bytes| {
                    let (ids, _) = bytes.as_chunks::<32>();
                    ids.iter().map(|id| PeerId::from_bytes(*id)).collect()
                })
                .unwrap_or_default()
        };
        if kept.is_empty() {
            return self.feeds.holders(address);
        }
        Ok(kept)
    }

    /// What `decided`, a batch decided at `at`, changes in what is
    /// published, and since when its addresses are deferred or below full
    /// support; counted into `tally`. Notes in `decided` which addresses'
    /// decisions stand: listed, or rejected for good. A listed file whose
    /// data map is shrunk is published with the size kept for it
    /// ([`SIZES_DB`]), or if none is, without, and its root map is to be
    /// read ([`SIZE_WANTED_DB`]).
    ///
    /// # Errors
    ///
    /// If the store can't be read or written.
    fn publication(
        &mut self,
        decided: &mut Decided,
        at: u64,
        tally: &mut Tally,
    ) -> Result<Publication> {
        let Decided {
            addresses,
            index,
            unlisted,
            known,
            waiting,
            ..
        } = decided;
        let listed: BTreeMap<XorName, &CheckedListing> = index
            .listings
            .iter()
            .map(|checked| (checked.listing.address, checked))
            .collect();
        let publication = {
            let txn = self.store.env().read_txn().map_err(store_error)?;
            let sizes = |address: &XorName| self.sizes.get(&txn, address).ok().flatten();
            read_publication(&self.publisher, index, &listed, unlisted, sizes, at, tally)?
        };
        tally.deferred.extend(waiting.iter().copied());
        self.update_since(&listed, &publication, addresses, at, tally)?;
        for (address, known) in known.iter_mut() {
            if let Some(known) = known {
                known.decided = listed.contains_key(address) || tally.for_good.contains(address);
            }
        }
        tally.for_good.clear();
        // Sizes to read, and those no longer wanted.
        let wanted = std::mem::take(&mut tally.wanted_sizes);
        let mut txn = self.store.env().write_txn().map_err(store_error)?;
        for (address, map) in wanted {
            // One already wanted keeps when it may be read next: a read
            // begun before a stop isn't begun again at once.
            if self
                .size_wanted
                .get(&txn, &address)
                .map_err(store_error)?
                .is_none()
            {
                let mut value = 0u64.to_be_bytes().to_vec();
                value.extend(
                    rmp_serde::to_vec(&map)
                        .map_err(|e| Error::Serialization(format!("a data map: {e}")))?,
                );
                self.size_wanted
                    .put(&mut txn, &address, &value)
                    .map_err(store_error)?;
            }
        }
        for change in &publication.changes {
            if let IndexChange::Remove { address, .. } = change {
                self.size_wanted
                    .delete(&mut txn, address)
                    .map_err(store_error)?;
            }
        }
        txn.commit().map_err(store_error)?;
        Ok(publication)
    }

    /// Keep what `decided` decided, once staged: what is known of each
    /// address, the nodes whose copies counted, and the full listings still
    /// held; and settle its addresses in the mirrors.
    ///
    /// # Errors
    ///
    /// If the store can't be written.
    fn keep(&mut self, decided: Decided) -> Result<()> {
        let now = unix_now();
        let mut txn = self.store.env().write_txn().map_err(store_error)?;
        for (address, holders) in &decided.holders {
            let bytes: Vec<u8> = holders
                .iter()
                .flat_map(|peer| peer.as_bytes().to_vec())
                .collect();
            self.holders
                .put(&mut txn, address, &bytes)
                .map_err(store_error)?;
        }
        for address in &decided.forget {
            self.holders
                .delete(&mut txn, address)
                .map_err(store_error)?;
            self.known
                .delete(&mut txn, &tagged(BACKOFF_TAG, address))
                .map_err(store_error)?;
        }
        // One row an address for when to decide it again for a date of its
        // copies in the future, replaced each time it is decided: none where
        // the next sweep, which decides every address again, comes first.
        let future: HashMap<XorName, u64> = decided.future.iter().copied().collect();
        let latest = now.saturating_add(REDECIDE_INTERVAL.as_secs());
        for (address, _) in &decided.known {
            let at_key = tagged(FUTURE_AT_TAG, address);
            let old = self
                .known
                .get(&txn, &at_key)
                .map_err(store_error)?
                .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
                .map(u64::from_be_bytes);
            let due = future.get(address).copied().filter(|due| *due <= latest);
            if old == due {
                continue;
            }
            if let Some(old) = old {
                self.known
                    .delete(&mut txn, &future_key(old, address))
                    .map_err(store_error)?;
            }
            match due {
                Some(due) => {
                    self.known
                        .put(&mut txn, &future_key(due, address), &[])
                        .map_err(store_error)?;
                    self.known
                        .put(&mut txn, &at_key, &due.to_be_bytes())
                        .map_err(store_error)?;
                }
                None => {
                    self.known.delete(&mut txn, &at_key).map_err(store_error)?;
                }
            }
        }
        // A kept listing that can't be read back goes, to be fetched again.
        for (address, digest) in &decided.unreadable {
            self.listings
                .delete(&mut txn, &listing_key(address, digest))
                .map_err(store_error)?;
        }
        for address in &decided.settle {
            // Only the listings behind entries some mirror still holds stay,
            // and only the failures of entries still held.
            let mut held: HashSet<(PeerId, [u8; 32])> = HashSet::new();
            for peer in self.feeds.holders(address)? {
                if let Some(entry) = self.feeds.entry(&peer, address)? {
                    held.insert((peer, entry.digest));
                }
            }
            let digests: HashSet<[u8; 32]> = held.iter().map(|(_, digest)| *digest).collect();
            let mut stale: Vec<Vec<u8>> = Vec::new();
            for row in self
                .listings
                .remap_data_type::<DecodeIgnore>()
                .prefix_iter(&txn, address)
                .map_err(store_error)?
            {
                let (key, ()) = row.map_err(store_error)?;
                let digest: Option<[u8; 32]> = key.get(32..).and_then(|d| d.try_into().ok());
                if digest.is_none_or(|digest| !digests.contains(&digest)) {
                    stale.push(key.to_vec());
                }
            }
            for key in stale {
                self.listings.delete(&mut txn, &key).map_err(store_error)?;
            }
            let mut stale: Vec<Vec<u8>> = Vec::new();
            for row in self
                .known
                .prefix_iter(&txn, &tagged(FAILED_TAG, address))
                .map_err(store_error)?
            {
                let (key, value) = row.map_err(store_error)?;
                let peer: Option<[u8; 32]> = key.get(33..65).and_then(|p| p.try_into().ok());
                let digest: Option<[u8; 32]> = key.get(65..).and_then(|d| d.try_into().ok());
                let retry_at = <[u8; 8]>::try_from(value).map_or(0, u64::from_be_bytes);
                let still = match (peer, digest) {
                    (Some(peer), Some(digest)) => {
                        held.contains(&(PeerId::from_bytes(peer), digest))
                    }
                    _ => false,
                };
                if !still || retry_at <= now {
                    stale.push(key.to_vec());
                }
            }
            for key in stale {
                self.known.delete(&mut txn, &key).map_err(store_error)?;
            }
        }
        for (address, known) in &decided.known {
            let row = tagged(KNOWN_TAG, address);
            let was = self
                .known
                .get(&txn, &row)
                .map_err(store_error)?
                .and_then(Known::decode)
                .is_some_and(|known| known.decided);
            let is = known.is_some_and(|known| known.decided);
            match known {
                Some(known) => {
                    self.known
                        .put(&mut txn, &row, &known.encode())
                        .map_err(store_error)?;
                    if known.again {
                        self.known
                            .put(&mut txn, &tagged(AGAIN_TAG, address), &[])
                            .map_err(store_error)?;
                    } else {
                        self.known
                            .delete(&mut txn, &tagged(AGAIN_TAG, address))
                            .map_err(store_error)?;
                    }
                }
                None => {
                    self.known.delete(&mut txn, &row).map_err(store_error)?;
                    self.known
                        .delete(&mut txn, &tagged(AGAIN_TAG, address))
                        .map_err(store_error)?;
                }
            }
            match (was, is) {
                (false, true) => self.standing += 1,
                (true, false) => self.standing = self.standing.saturating_sub(1),
                _ => {}
            }
        }
        txn.commit().map_err(store_error)?;
        self.feeds.settle(&decided.settle)?;
        // What there was no time for waits, pending, for a later cycle.
        self.feeds.mark_pending(&decided.later)
    }

    /// Take `first`, a push from a node's watch, and every other push that
    /// comes before the latest publication's second is out; decide the
    /// addresses they changed at once, after the latest cycle's guard,
    /// fetching what they need, until `deadline` ([`Self::decide_pushed`]),
    /// and publish it with the latest cycle's `status.json`. Only those
    /// addresses: any other address waiting to be decided, such as what the
    /// latest cycle had no time for, is left to the next cycle, so the time
    /// this takes follows what the pushes changed, not what waits. A node a
    /// push from which was dropped for want of room holds a record its
    /// mirror lacks: it is taken as one whose push came behind its mirror
    /// ([`Feeds::mark_behind`]) until the next cycle reads it again.
    ///
    /// # Errors
    ///
    /// If the store or the published files can't be written.
    async fn take_pushes(
        &mut self,
        first: (PeerId, ChangesResponse),
        deadline: Instant,
    ) -> Result<()> {
        let mut changed: BTreeSet<XorName> = BTreeSet::new();
        self.take_push(first, &mut changed)?;
        wait_past(self.published_second).await;
        while let Some(push) = self.pushes.try_recv() {
            self.take_push(push, &mut changed)?;
        }
        for peer in self.pushes.take_dropped() {
            self.feeds.mark_behind(&peer);
        }
        self.feeds.save()?;
        if changed.is_empty() {
            return Ok(());
        }
        let Some(status) = self.last_status.clone() else {
            return Ok(());
        };
        if !self.guard_ok {
            return Ok(());
        }
        let at = unix_now();
        let mut tally = Tally::default();
        let (decided, staged) =
            Box::pin(self.decide_pushed(&changed, at, deadline, &mut tally)).await?;
        if staged {
            self.write_spaced(at, &status).await?;
            self.published_between += 1;
            // Counted with the next cycle's, as a read would count them.
            self.removed_between += tally.removed;
        }
        debug!(
            "Pushes changed {} addresses: {decided} decided, {} put, {} removed",
            changed.len(),
            tally.put,
            tally.removed
        );
        Ok(())
    }

    /// Take one push, and if it was applied to its node's mirror, note the
    /// addresses it changed in `changed`, and that its node pushed them
    /// ([`PUSHED_TAG`]).
    ///
    /// # Errors
    ///
    /// If the store can't be written.
    fn take_push(
        &mut self,
        (source, push): (PeerId, ChangesResponse),
        changed: &mut BTreeSet<XorName>,
    ) -> Result<()> {
        self.pushes_between += 1;
        if let Pushed::Applied(addresses) = self.feeds.push(&self.census, &source, &push)? {
            let mut txn = self.store.env().write_txn().map_err(store_error)?;
            for address in &addresses {
                self.known
                    .put(&mut txn, &pushed_key(address, &source), &[])
                    .map_err(store_error)?;
            }
            txn.commit().map_err(store_error)?;
            changed.extend(addresses);
        }
        Ok(())
    }

    /// Forget which nodes pushed what since the latest poll
    /// ([`PUSHED_TAG`]): a poll is about to read every node again.
    ///
    /// # Errors
    ///
    /// If the store can't be written.
    fn forget_pushed(&mut self) -> Result<()> {
        let from = [PUSHED_TAG];
        let end = [PUSHED_TAG + 1];
        let range = (Bound::Included(&from[..]), Bound::Excluded(&end[..]));
        let mut txn = self.store.env().write_txn().map_err(store_error)?;
        self.known
            .delete_range(&mut txn, &range)
            .map_err(store_error)?;
        txn.commit().map_err(store_error)
    }

    /// Whether `address` may be decided between cycles: the copies of the
    /// listing at least [`QUORUM_THRESHOLD`] of its nearest nodes serve were
    /// each pushed since the latest poll ([`PUSHED_TAG`]). A mirror shows
    /// what its node served at its latest answer, or push: a node that has
    /// since gone, or stopped serving the listing without its push coming,
    /// still shows it until the next poll, so a quorum that rests on such a
    /// copy is left to that poll, which reads every node. So between cycles
    /// a listing is put only on copies just pushed, as when a new one is
    /// stored and its nearest nodes push it, and every other change waits
    /// for the cycle.
    ///
    /// # Errors
    ///
    /// If the store can't be read.
    fn pushed_quorum(&self, address: &XorName) -> Result<bool> {
        let nearest = self.census.nearest(address, NEAREST_NODES);
        let copies = self.feeds.copies(address, &nearest)?;
        let mut groups: BTreeMap<[u8; 32], Vec<PeerId>> = BTreeMap::new();
        for (peer, entry) in &copies {
            groups.entry(entry.digest).or_default().push(*peer);
        }
        let Some(group) = groups
            .into_values()
            .find(|holders| holders.len() >= QUORUM_THRESHOLD)
        else {
            return Ok(false);
        };
        let txn = self.store.env().read_txn().map_err(store_error)?;
        for peer in &group {
            let pushed = self
                .known
                .get(&txn, &pushed_key(address, peer))
                .map_err(store_error)?
                .is_some();
            if !pushed {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Decide `addresses`, those pushes changed between cycles, at `at`: a
    /// batch of [`DECIDE_BATCH`] at a time in address order, each batch's
    /// full listings fetched first ([`Self::fetch_addresses`]), until
    /// `deadline`, at least a batch, as [`Self::decide_batch`] decides one,
    /// without drops. Only an address whose quorum's copies were all pushed
    /// since the latest poll is decided ([`Self::pushed_quorum`]); one of
    /// whose nearest nodes' pushes came behind its mirror is left out too,
    /// for the next cycle to decide once the node is read again
    /// ([`Feeds::behind`]); and so is what doesn't fit before `deadline`.
    /// They all stay pending. What is published is counted into `tally`.
    /// Returns how many addresses were decided, and whether any batch
    /// staged a change.
    ///
    /// # Errors
    ///
    /// If the store can't be read or written.
    async fn decide_pushed(
        &mut self,
        addresses: &BTreeSet<XorName>,
        at: u64,
        deadline: Instant,
        tally: &mut Tally,
    ) -> Result<(u64, bool)> {
        let mut ready: Vec<XorName> = Vec::new();
        for address in addresses {
            let near_behind = self.feeds.any_behind()
                && self
                    .census
                    .nearest(address, NEAREST_NODES)
                    .iter()
                    .any(|peer| self.feeds.behind(peer));
            if !near_behind && self.pushed_quorum(address)? {
                ready.push(*address);
            }
        }
        let mut decided = 0;
        let mut staged = false;
        let pass = Pass::new(deadline, false);
        for (n, chunk) in ready.chunks(DECIDE_BATCH).enumerate() {
            if n > 0 && Instant::now() >= deadline {
                break;
            }
            Box::pin(self.fetch_addresses(chunk, deadline)).await?;
            let batch: Batch = chunk.iter().map(|address| (*address, true)).collect();
            let (count, changed) =
                Box::pin(self.decide_batch(batch, at, None, false, &pass, tally)).await?;
            decided += count;
            staged |= changed;
        }
        Ok((decided, staged))
    }

    /// Start reading the root maps of up to [`SIZES_PER_CYCLE`] listed files
    /// whose sizes aren't known yet ([`read_root_size`]), in a task of its
    /// own, for at most a [`CYCLE`]; unless such a task is still reading, or
    /// what it read is still to be taken. The files are taken in address
    /// order, going on after the last one the latest reading took, round to
    /// the first, so files whose maps keep failing can't keep the others
    /// from their turn. Each read is marked before it begins, so the map
    /// isn't read again for [`RETRY_INTERVAL`] unless it gives a size: one
    /// that couldn't be read, that the end cut short, or that a stop of the
    /// process cut short waits as long.
    ///
    /// # Errors
    ///
    /// If the store can't be read or written.
    fn start_sizes(&mut self) -> Result<()> {
        if self.size_job.is_some() {
            return Ok(());
        }
        let until = Instant::now() + CYCLE;
        let now = unix_now();
        let next = now.saturating_add(RETRY_INTERVAL.as_secs());
        let mut due: Vec<(XorName, DataMap)> = Vec::new();
        {
            let mut txn = self.store.env().write_txn().map_err(store_error)?;
            let rows = self.sizes_due(&txn, now)?;
            if let Some((last, _)) = rows.last() {
                self.size_after = Some(*last);
            }
            for (address, map) in rows {
                // A map that can't be decoded never gives a size.
                let decoded = rmp_serde::from_slice::<DataMap>(&map).ok();
                let mut value = decoded
                    .as_ref()
                    .map_or(u64::MAX, |_| next)
                    .to_be_bytes()
                    .to_vec();
                value.extend_from_slice(&map);
                self.size_wanted
                    .put(&mut txn, &address, &value)
                    .map_err(store_error)?;
                due.extend(decoded.map(|map| (address, map)));
            }
            txn.commit().map_err(store_error)?;
        }
        if due.is_empty() {
            return Ok(());
        }
        let client = Arc::clone(&self.client);
        let room = Arc::clone(&self.size_room);
        let (sender, results) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let (client, room) = (&client, &room);
            let mut reads = stream::iter(due)
                .map(|(address, map)| async move {
                    let started = std::time::Instant::now();
                    let fetch = |chunk: [u8; 32]| client.data_record(chunk);
                    let read = read_root_size(&map, fetch, room).await;
                    debug!(
                        "Reading the root map of {} gave {read:?} in {} ms",
                        hex::encode(address),
                        started.elapsed().as_millis()
                    );
                    (address, read)
                })
                .buffer_unordered(SIZES_PER_CYCLE);
            let mut read = Vec::new();
            while let Ok(Some(size)) = tokio::time::timeout_at(until, reads.next()).await {
                read.push(size);
            }
            let _ = sender.send(read);
        });
        self.size_job = Some(SizeJob { results, task });
        Ok(())
    }

    /// Up to [`SIZES_PER_CYCLE`] rows of [`SIZE_WANTED_DB`] that may be read
    /// at `now` (Unix seconds), each the address and its data map's bytes:
    /// from after the last row the latest reading took, round to the first
    /// and on to that row.
    ///
    /// # Errors
    ///
    /// If the store can't be read.
    fn sizes_due(&self, txn: &RoTxn, now: u64) -> Result<Vec<(XorName, Vec<u8>)>> {
        let after = self.size_after;
        let ranges: Vec<KeyRange<'_>> = match &after {
            Some(after) => vec![
                (Bound::Excluded(&after[..]), Bound::Unbounded),
                (Bound::Unbounded, Bound::Included(&after[..])),
            ],
            None => vec![(Bound::Unbounded, Bound::Unbounded)],
        };
        let mut rows: Vec<(XorName, Vec<u8>)> = Vec::new();
        for range in &ranges {
            for row in self.size_wanted.range(txn, range).map_err(store_error)? {
                if rows.len() == SIZES_PER_CYCLE {
                    return Ok(rows);
                }
                let (key, value) = row.map_err(store_error)?;
                let Ok(address) = XorName::try_from(key) else {
                    continue;
                };
                let Some((retry_at, map)) = value.split_first_chunk::<8>() else {
                    continue;
                };
                if u64::from_be_bytes(*retry_at) > now {
                    continue;
                }
                rows.push((address, map.to_vec()));
            }
        }
        Ok(rows)
    }

    /// Take what the root maps `read` gave: keep each size read, and fill it
    /// in to its entry where that has none, as a put published with the
    /// latest cycle's `status.json`. A map that can never give a size isn't
    /// read again: its entry keeps none. One that couldn't be read is read
    /// again once [`RETRY_INTERVAL`] has passed since it began.
    ///
    /// # Errors
    ///
    /// If the store or the published files can't be written.
    async fn take_sizes(&mut self, read: Vec<(XorName, SizeRead)>) -> Result<()> {
        if read.is_empty() {
            return Ok(());
        }
        let now = unix_now();
        let mut sized: Vec<(XorName, u64)> = Vec::new();
        let mut txn = self.store.env().write_txn().map_err(store_error)?;
        for (address, read) in read {
            match read {
                SizeRead::Sized(size) => {
                    self.sizes
                        .put(&mut txn, &address, &size)
                        .map_err(store_error)?;
                    self.size_wanted
                        .delete(&mut txn, &address)
                        .map_err(store_error)?;
                    sized.push((address, size));
                }
                SizeRead::Never => {
                    info!(
                        "The data map of {} gives no size that can be read: its entry keeps none",
                        hex::encode(address)
                    );
                    let value = self
                        .size_wanted
                        .get(&txn, &address)
                        .map_err(store_error)?
                        .map(|value| {
                            let mut value = value.to_vec();
                            if value.len() >= 8 {
                                value[..8].copy_from_slice(&u64::MAX.to_be_bytes());
                            }
                            value
                        });
                    if let Some(value) = value {
                        self.size_wanted
                            .put(&mut txn, &address, &value)
                            .map_err(store_error)?;
                    }
                }
                // When it may be read next was set as it began.
                SizeRead::Later => {}
            }
        }
        txn.commit().map_err(store_error)?;
        let mut changes = Vec::new();
        for (address, size) in sized {
            let Some(mut entry) = self.publisher.entry(&address)? else {
                continue;
            };
            if entry.entry.listing.size.is_none() && entry.data_map.is_some() {
                entry.entry.listing.size = Some(size);
                changes.push(IndexChange::Put(Box::new(entry)));
            }
        }
        let Some(status) = self.last_status.clone() else {
            return Ok(());
        };
        if changes.is_empty() {
            return Ok(());
        }
        debug!("Filling in {} sizes read from root maps", changes.len());
        self.publisher.stage(&Publication {
            at: now,
            changes,
            ..Publication::default()
        })?;
        self.write_spaced(now, &status).await?;
        self.published_between += 1;
        Ok(())
    }

    /// Write what was staged, and `status`, once the clock is past the
    /// second in which the latest publication ended: so each file written
    /// again is written in a later second than before.
    ///
    /// # Errors
    ///
    /// If the store or the published files can't be written.
    async fn write_spaced(&mut self, at: u64, status: &Status) -> Result<()> {
        wait_past(self.published_second).await;
        let published = self.publisher.write_staged(at, status);
        self.published_second = unix_now();
        published.map(|_| ())
    }

    /// Note since when each address of `addresses`, a batch, has been
    /// deferred, and why, and each listed one below full support, and count
    /// them into `tally`: an address of the batch not deferred loses its
    /// rows.
    ///
    /// # Errors
    ///
    /// If the store can't be read or written.
    fn update_since(
        &self,
        listed: &BTreeMap<XorName, &CheckedListing>,
        publication: &Publication,
        addresses: &[XorName],
        at: u64,
        tally: &mut Tally,
    ) -> Result<()> {
        let deferred: HashMap<XorName, &'static str> = tally.deferred.drain(..).collect();
        let mut txn = self.store.env().write_txn().map_err(store_error)?;
        for address in addresses {
            let row = tagged(DEFERRED_TAG, address);
            let reason_row = tagged(REASON_TAG, address);
            let Some(reason) = deferred.get(address) else {
                self.since.delete(&mut txn, &row).map_err(store_error)?;
                self.since
                    .delete(&mut txn, &reason_row)
                    .map_err(store_error)?;
                continue;
            };
            // Since it was first deferred, as Unix seconds alone, and its
            // latest reason in a row of its own.
            let old = self.since.get(&txn, &row).map_err(store_error)?;
            let since = old.map_or(at, |old| deferral_of(old, None).0);
            if old != Some(since) {
                self.since
                    .put(&mut txn, &row, &since)
                    .map_err(store_error)?;
            }
            let code = reason_code(reason);
            if self.since.get(&txn, &reason_row).map_err(store_error)? != Some(code) {
                self.since
                    .put(&mut txn, &reason_row, &code)
                    .map_err(store_error)?;
            }
            let group = tally.groups.entry(reason).or_insert((0, since));
            group.0 += 1;
            group.1 = group.1.min(since);
        }
        for checked in listed.values() {
            let row = tagged(BELOW_FULL_TAG, &checked.listing.address);
            if checked.nodes < checked.nearest {
                if self.since.get(&txn, &row).map_err(store_error)?.is_none() {
                    self.since.put(&mut txn, &row, &at).map_err(store_error)?;
                }
            } else {
                self.since.delete(&mut txn, &row).map_err(store_error)?;
            }
        }
        for change in &publication.changes {
            if let IndexChange::Remove { address, .. } = change {
                self.since
                    .delete(&mut txn, &tagged(BELOW_FULL_TAG, address))
                    .map_err(store_error)?;
            }
        }
        txn.commit().map_err(store_error)
    }

    /// `status.json` for the cycle that began at `at` (`clock`), which
    /// decided nothing if `too_few` of the census answered, after which
    /// `decided` addresses' decisions stand, as `tally` counted it. The
    /// deferrals are every address deferred, by its latest reason, as their
    /// rows keep them, however many the cycle decided; as an index read
    /// that finds too few nodes gives them, after a cycle that decided
    /// nothing. The publisher fills in the feed's fields.
    ///
    /// # Errors
    ///
    /// If the store can't be read.
    fn status(
        &mut self,
        at: u64,
        clock: std::time::Instant,
        before: Counters,
        too_few: bool,
        decided: u64,
        tally: &Tally,
    ) -> Result<Status> {
        let mut below = BelowFull::default();
        let mut groups: BTreeMap<&'static str, (u64, u64)> = BTreeMap::new();
        {
            let txn = self.store.env().read_txn().map_err(store_error)?;
            for row in self
                .since
                .prefix_iter(&txn, &[BELOW_FULL_TAG])
                .map_err(store_error)?
            {
                let (_, since) = row.map_err(store_error)?;
                below.listings += 1;
                below.oldest_since = Some(below.oldest_since.map_or(since, |old| old.min(since)));
            }
            if !too_few {
                for row in self
                    .since
                    .prefix_iter(&txn, &[DEFERRED_TAG])
                    .map_err(store_error)?
                {
                    let (key, value) = row.map_err(store_error)?;
                    let code = match key.get(1..).and_then(|rest| XorName::try_from(rest).ok()) {
                        Some(address) => self
                            .since
                            .get(&txn, &tagged(REASON_TAG, &address))
                            .map_err(store_error)?,
                        None => None,
                    };
                    let (since, reason) = deferral_of(value, code);
                    let group = groups.entry(reason).or_insert((0, since));
                    group.0 += 1;
                    group.1 = group.1.min(since);
                }
            }
        }
        if too_few {
            groups.clone_from(&tally.groups);
        }
        let after = Counters::now(&self.chain);
        let cycle = CycleStatus {
            started_at: at,
            millis: u64::try_from(clock.elapsed().as_millis()).unwrap_or(u64::MAX),
            bytes_in: after.bytes_in.saturating_sub(before.bytes_in),
            bytes_out: after.bytes_out.saturating_sub(before.bytes_out),
            rpc_calls: after.rpc_calls.saturating_sub(before.rpc_calls),
            rpc_errors: after.rpc_errors.saturating_sub(before.rpc_errors),
            decided,
            too_few_answered: too_few,
        };
        // Totals count every listings message, those between cycles (pushes,
        // and what they led to fetch) with the next cycle's.
        self.totals.cycles += 1;
        let (counted_in, counted_out) = self.traffic_counted;
        self.totals.bytes_in += after.bytes_in.saturating_sub(counted_in);
        self.totals.bytes_out += after.bytes_out.saturating_sub(counted_out);
        self.traffic_counted = (after.bytes_in, after.bytes_out);
        self.totals.rpc = self.chain.rpc_calls();
        Ok(Status {
            cycle,
            census: self.census.status(at),
            deferred: groups
                .iter()
                .map(|(reason, (addresses, oldest_since))| DeferredGroup {
                    reason: (*reason).to_string(),
                    addresses: *addresses,
                    oldest_since: *oldest_since,
                })
                .collect(),
            below_full: below,
            drops: Drops {
                removed: tally.removed,
                carried: tally.carried,
            },
            ..self.base_status()
        })
    }

    /// `status.json`'s fields that don't depend on a cycle.
    fn base_status(&self) -> Status {
        Status {
            started_at: self.started_at,
            totals: self.totals.clone(),
            resources: Resources {
                rss_bytes: rss_bytes(),
                store_bytes: self.store.size_bytes().ok(),
                files_bytes: None,
                disk_free_bytes: fs2::available_space(self.store.dir()).ok(),
            },
            ..Status::default()
        }
    }

    /// `status`, with the feed's fields as the publisher wrote them.
    fn published_status(&self, status: Status) -> Status {
        Status {
            epoch: self.publisher.epoch().to_string(),
            seq: self.publisher.seq(),
            count: self.publisher.count(),
            ..status
        }
    }

    /// The client the producer reads the network through.
    #[must_use]
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// The payment chain reader, with its store.
    #[must_use]
    pub fn chain(&self) -> &ListingChain {
        &self.chain
    }

    /// The store.
    #[must_use]
    pub fn store(&self) -> &ListingsStore {
        &self.store
    }

    /// The census.
    #[must_use]
    pub fn census(&self) -> &Census {
        &self.census
    }

    /// The mirrors of the nodes' indexes.
    #[must_use]
    pub fn feeds(&self) -> &Feeds {
        &self.feeds
    }

    /// The publisher.
    #[must_use]
    pub fn publisher(&self) -> &Publisher {
        &self.publisher
    }
}

/// What happened between cycles ([`Producer::run`]).
enum Between {
    /// A push came, or no sender is left.
    Push(Option<(PeerId, ChangesResponse)>),
    /// The sizes being read were read.
    Sizes(Vec<(XorName, SizeRead)>),
}

/// The sizes `job` read, once it has; never while there is no job.
async fn sizes_read(job: &mut Option<SizeJob>) -> Vec<(XorName, SizeRead)> {
    match job {
        Some(job) => (&mut job.results).await.unwrap_or_default(),
        None => std::future::pending().await,
    }
}

/// The full listings fetched, and the nodes that failed to hand theirs
/// over, written to the store a chunk at a time.
struct FetchSink<'a> {
    producer: &'a Producer,
    /// When the fetching began (Unix seconds).
    now: u64,
    /// Each listing fetched, in the bytes it is kept in ([`kept_bytes`]).
    fetched: Vec<(ListingId, Vec<u8>)>,
    failed: Vec<(PeerId, ListingId)>,
    error: Option<Error>,
}

impl<'a> FetchSink<'a> {
    fn new(producer: &'a Producer, now: u64) -> Self {
        Self {
            producer,
            now,
            fetched: Vec::new(),
            failed: Vec::new(),
            error: None,
        }
    }

    /// One listing fetched, or not, and the nodes that failed to hand it
    /// over: written once a chunk has come.
    fn add(&mut self, key: ListingId, listing: Option<Vec<u8>>, failed: Vec<PeerId>) {
        if let Some(listing) = listing {
            self.fetched.push((key, listing));
        }
        self.failed
            .extend(failed.into_iter().map(|peer| (peer, key)));
        if self.fetched.len() + self.failed.len() >= DECIDE_BATCH {
            if let Err(e) = self.write() {
                self.error.get_or_insert(e);
            }
        }
    }

    /// Write what has come, and say if any write failed.
    fn flush(&mut self) -> Result<()> {
        self.write()?;
        match self.error.take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn write(&mut self) -> Result<()> {
        if self.fetched.is_empty() && self.failed.is_empty() {
            return Ok(());
        }
        let producer = self.producer;
        let retry_at = self.now.saturating_add(RETRY_INTERVAL.as_secs());
        let mut txn = producer.store.env().write_txn().map_err(store_error)?;
        for ((address, digest), bytes) in self.fetched.drain(..) {
            producer
                .listings
                .put(&mut txn, &listing_key(&address, &digest), &bytes)
                .map_err(store_error)?;
        }
        for (peer, (address, digest)) in self.failed.drain(..) {
            producer
                .known
                .put(
                    &mut txn,
                    &failed_key(&address, &peer, &digest),
                    &retry_at.to_be_bytes(),
                )
                .map_err(store_error)?;
        }
        txn.commit().map_err(store_error)
    }
}

/// The full listings to fetch for the addresses of a source, a batch at a
/// time ([`Producer::wanted_after`]), as an iterator: a store error ends it,
/// kept in `error`, and so does `deadline`, checked before each batch is
/// read, so that reading what waits to be decided, however much does, takes
/// no longer than the fetching may.
struct WantedIter<'a> {
    producer: &'a Producer,
    source: Source,
    /// Whether for the digests a quorum names ([`Producer::wanted_of`]).
    quorum: bool,
    now: u64,
    deadline: Instant,
    after: Option<XorName>,
    done: bool,
    queue: VecDeque<Wanted>,
    error: &'a std::cell::RefCell<Option<Error>>,
}

impl<'a> WantedIter<'a> {
    fn new(
        producer: &'a Producer,
        source: Source,
        quorum: bool,
        now: u64,
        deadline: Instant,
        error: &'a std::cell::RefCell<Option<Error>>,
    ) -> Self {
        Self {
            producer,
            source,
            quorum,
            now,
            deadline,
            after: None,
            done: false,
            queue: VecDeque::new(),
            error,
        }
    }
}

impl Iterator for WantedIter<'_> {
    type Item = Wanted;

    fn next(&mut self) -> Option<Wanted> {
        loop {
            if let Some(wanted) = self.queue.pop_front() {
                return Some(wanted);
            }
            if self.done || Instant::now() >= self.deadline {
                return None;
            }
            match self.producer.wanted_after(
                self.source,
                self.after.as_ref(),
                self.quorum,
                self.now,
            ) {
                Ok((wanted, last, done)) => {
                    self.queue.extend(wanted);
                    self.after = last;
                    self.done = done || last.is_none();
                }
                Err(e) => {
                    *self.error.borrow_mut() = Some(e);
                    self.done = true;
                }
            }
        }
    }
}

/// Each of `copies` of an address, digest entries, as the full listing its
/// node serves: the listing `fetched` gives for the entry's digest (the full
/// listings fetched, without `first_seen`), with the node's own
/// `first_seen`, as the node's entry describes it. Those [`Listing::validate`]
/// refuses, or that the node's entry doesn't describe, are left out, as an
/// index walk leaves out a copy that fails its checks. Also returns the
/// nodes whose listing isn't fetched: their copies can't be had this time,
/// and they count as nodes not heard from ([`Client::decide_backed`]), so
/// no one node can keep an address from being decided by failing to hand
/// over its listing. Each digest is read once, however many copies share
/// it.
fn copies_from(
    mut fetched: impl FnMut(&[u8; 32]) -> Option<Listing>,
    copies: &[(PeerId, DigestEntry)],
) -> (Vec<(PeerId, Listing)>, Vec<PeerId>) {
    let mut read: HashMap<[u8; 32], Option<Listing>> = HashMap::new();
    let mut listed = Vec::with_capacity(copies.len());
    let mut unheard = Vec::new();
    for (peer, entry) in copies {
        let listing = read
            .entry(entry.digest)
            .or_insert_with(|| fetched(&entry.digest));
        let Some(listing) = listing else {
            unheard.push(*peer);
            continue;
        };
        let copy = Listing {
            first_seen: entry.first_seen,
            ..listing.clone()
        };
        if entry.describes(&copy) && copy.validate().is_ok() {
            listed.push((*peer, copy));
        }
    }
    (listed, unheard)
}

/// A full listing as the store keeps it ([`Producer::kept_listing`]).
enum Kept {
    /// The listing, without `first_seen`.
    Listing(Box<Listing>),
    /// None is kept.
    None,
    /// One is kept that can't be read back: it is let go, to be fetched
    /// again.
    Unreadable,
}

/// The bytes `listing` is kept in, without `first_seen`: those a
/// `GetResponse` carries it in, the crate's wire encoding. `None` if it
/// takes more than [`MAX_LISTING_BYTES`], or can't be encoded: out of
/// spec, not kept.
fn kept_bytes(listing: &Listing) -> Option<Vec<u8>> {
    let message = ListingsMessage {
        request_id: 0,
        body: ListingsBody::GetResponse {
            listing: Some(Listing {
                first_seen: None,
                ..listing.clone()
            }),
        },
    };
    let bytes = message.encode().ok()?;
    (bytes.len() <= MAX_LISTING_BYTES).then_some(bytes)
}

/// The listing `bytes` keep ([`kept_bytes`]), if they can be read back.
fn kept_listing(bytes: &[u8]) -> Option<Listing> {
    if bytes.len() > MAX_LISTING_BYTES {
        return None;
    }
    match ListingsMessage::decode(bytes).ok()?.body {
        ListingsBody::GetResponse {
            listing: Some(listing),
        } if listing.first_seen.is_none() => Some(listing),
        _ => None,
    }
}

/// How many more `GetRequest`s for full listings each node may be sent
/// this cycle, and the nodes that left one unanswered this cycle.
#[derive(Debug, Default)]
struct FetchBudget(Mutex<Budgets>);

#[derive(Debug, Default)]
struct Budgets {
    /// What is left of each node's allowance.
    left: HashMap<PeerId, usize>,
    /// The nodes sent nothing more this cycle.
    unanswered: HashSet<PeerId>,
}

impl FetchBudget {
    /// A new cycle: every node's allowance starts again.
    fn clear(&mut self) {
        if let Ok(budgets) = self.0.get_mut() {
            budgets.left.clear();
            budgets.unanswered.clear();
        }
    }

    /// Take one request for `peer`: whether it may be sent one. Not once it
    /// left one unanswered this cycle. For a listing at least a quorum of
    /// its address's nearest nodes name (`quorum`), the request is taken
    /// from no allowance: no node can make up such a listing on its own,
    /// and each is fetched once and kept, so what they cost is bounded by
    /// what the nodes' mirrors may hold, not by a cycle's allowance, and a
    /// burst of new listings is fetched as soon as the nodes hand them over.
    /// Any other is taken from `peer`'s allowance, `allowance` a cycle.
    fn take(&self, peer: &PeerId, quorum: bool, allowance: impl FnOnce() -> usize) -> bool {
        let Ok(mut budgets) = self.0.lock() else {
            return false;
        };
        if budgets.unanswered.contains(peer) {
            return false;
        }
        if quorum {
            return true;
        }
        let left = budgets.left.entry(*peer).or_insert_with(allowance);
        if *left == 0 {
            return false;
        }
        *left -= 1;
        true
    }

    /// `peer` left a request unanswered: it is sent nothing more this cycle.
    fn exhaust(&self, peer: &PeerId) {
        if let Ok(mut budgets) = self.0.lock() {
            budgets.unanswered.insert(*peer);
        }
    }
}

/// The full listings to fetch for `work`: each digest an entry names that
/// isn't `kept` yet, with the nodes holding an entry with it, nearest first,
/// but those that `failed` to hand it over lately. With `quorum`, only the
/// digests at least [`QUORUM_THRESHOLD`] of the address's nearest nodes
/// name; without, only the others. In address order, and for an address,
/// the digests most nodes name first. So a node that makes up entries,
/// named by it alone, can't keep the listing a quorum serves from being
/// fetched: [`Producer::fetch_for`] fetches every digest a quorum names
/// before any other.
fn fetches_wanted(
    work: &[Work],
    quorum: bool,
    failed: impl Fn(&PeerId, &ListingId) -> bool,
    kept: impl Fn(&ListingId) -> bool,
) -> Vec<Wanted> {
    let mut wanted = Vec::new();
    for (address, _, copies) in work {
        // Each digest its entries name: how many name it, and whom to ask.
        let mut digests: BTreeMap<[u8; 32], (usize, DigestCopies)> = BTreeMap::new();
        for (peer, entry) in copies {
            let slot = digests.entry(entry.digest).or_default();
            slot.0 += 1;
            if !failed(peer, &(*address, entry.digest)) {
                slot.1.push((*peer, *entry));
            }
        }
        let mut named: Vec<(usize, ListingId, DigestCopies)> = digests
            .into_iter()
            .filter(|(digest, (count, holders))| {
                (*count >= QUORUM_THRESHOLD) == quorum
                    && !holders.is_empty()
                    && !kept(&(*address, *digest))
            })
            .map(|(digest, (count, holders))| (count, (*address, digest), holders))
            .collect();
        named.sort_by_key(|(count, _, _)| std::cmp::Reverse(*count));
        wanted.extend(
            named
                .into_iter()
                .map(|(_, key, holders)| (key, holders, quorum)),
        );
    }
    wanted
}

/// Fetch each of `wanted` ([`fetches_wanted`]), taken as the fetches go,
/// from its holders, until one hands over a listing its entry describes,
/// through `ask` (a `GetRequest` to a node for an address: `None` if it
/// didn't answer, `Some(None)` if it holds none), [`POLL_CONCURRENCY`] at a
/// time. A node is sent one request at a time: a fetch whose next holder is
/// busy asks the first of its holders that isn't, or waits for whichever is
/// free first. A holder is asked only if `take` gives it a request, given
/// whether a quorum names the listing ([`FetchBudget::take`]); one that
/// leaves a request unanswered goes to `unanswered`, after which it is sent
/// nothing more, so a node that never answers costs at most one request's
/// wait a cycle. A listing that takes more than
/// [`MAX_LISTING_BYTES`] isn't taken: its node failed to hand it over. What
/// hasn't come by `deadline` is left. Each fetch, when it ends, goes to
/// `done`: the listing, in the bytes it is kept in ([`kept_bytes`]), if one
/// was handed over, and each holder that was asked and failed to hand one
/// over.
async fn fetch_wanted<A, Fut>(
    wanted: impl Iterator<Item = Wanted>,
    take: impl Fn(&PeerId, bool) -> bool + Copy,
    unanswered: impl Fn(&PeerId) + Copy,
    deadline: Instant,
    ask: A,
    mut done: impl FnMut(ListingId, Option<Vec<u8>>, Vec<PeerId>),
) where
    A: Fn(PeerId, XorName) -> Fut + Copy,
    Fut: std::future::Future<Output = Option<Option<Listing>>>,
{
    let slots = NodeSlots::default();
    let slots = &slots;
    let mut fetches = stream::iter(wanted)
        .map(|(key, holders, quorum)| async move {
            let mut left = holders;
            let mut failed = Vec::new();
            while !left.is_empty() {
                let Some((index, _slot)) = slots.first_free(&left).await else {
                    break;
                };
                let (peer, entry) = left.remove(index);
                if !take(&peer, quorum) {
                    continue;
                }
                match ask(peer, key.0).await {
                    None => {
                        unanswered(&peer);
                        failed.push(peer);
                    }
                    Some(Some(listing)) if entry.describes(&listing) => {
                        match kept_bytes(&listing) {
                            Some(bytes) => return (key, Some(bytes), failed),
                            None => {
                                debug!(
                                    "{peer} handed over a listing for {} larger than \
                                     {MAX_LISTING_BYTES} bytes",
                                    hex::encode(key.0)
                                );
                                failed.push(peer);
                            }
                        }
                    }
                    Some(_) => failed.push(peer),
                }
            }
            (key, None, failed)
        })
        .buffer_unordered(POLL_CONCURRENCY);
    loop {
        match tokio::time::timeout_at(deadline, fetches.next()).await {
            Ok(Some((key, listing, failed))) => done(key, listing, failed),
            Ok(None) => break,
            Err(_) => {
                debug!("Fetching full listings reached its deadline");
                break;
            }
        }
    }
}

/// One request in flight to each node at a time ([`fetch_wanted`]).
#[derive(Debug, Default)]
struct NodeSlots(Mutex<HashMap<PeerId, Arc<Semaphore>>>);

impl NodeSlots {
    /// `peer`'s slot.
    fn slot(&self, peer: &PeerId) -> Arc<Semaphore> {
        let mut slots = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(
            slots
                .entry(*peer)
                .or_insert_with(|| Arc::new(Semaphore::new(1))),
        )
    }

    /// The place among `holders` of the first with no request in flight, with
    /// its slot held; if all have one, of the first to be free. `None` if
    /// none is left.
    async fn first_free(
        &self,
        holders: &[(PeerId, DigestEntry)],
    ) -> Option<(usize, tokio::sync::OwnedSemaphorePermit)> {
        for (index, (peer, _)) in holders.iter().enumerate() {
            if let Ok(permit) = self.slot(peer).try_acquire_owned() {
                return Some((index, permit));
            }
        }
        if holders.is_empty() {
            return None;
        }
        let waits = holders
            .iter()
            .map(|(peer, _)| Box::pin(self.slot(peer).acquire_owned()));
        let (permit, index, _) = futures::future::select_all(waits).await;
        permit.ok().map(|permit| (index, permit))
    }
}

/// A fetched listing's key in [`LISTINGS_DB`]: its address, then its
/// digest.
fn listing_key(address: &XorName, digest: &[u8; 32]) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(address);
    key[32..].copy_from_slice(digest);
    key
}

/// A failed fetch's key in [`KNOWN_DB`] ([`FAILED_TAG`]): the address, the
/// node and the digest of its entry.
fn failed_key(address: &XorName, peer: &PeerId, digest: &[u8; 32]) -> [u8; 97] {
    let mut key = [0u8; 97];
    key[0] = FAILED_TAG;
    key[1..33].copy_from_slice(address);
    key[33..65].copy_from_slice(peer.as_bytes());
    key[65..].copy_from_slice(digest);
    key
}

/// The key in [`KNOWN_DB`] ([`PUSHED_TAG`]) noting that `peer` pushed a
/// change to its entry for `address`: the tag, the address, then the node.
fn pushed_key(address: &XorName, peer: &PeerId) -> [u8; 65] {
    let mut key = [0u8; 65];
    key[0] = PUSHED_TAG;
    key[1..33].copy_from_slice(address);
    key[33..].copy_from_slice(peer.as_bytes());
    key
}

/// The key in [`KNOWN_DB`] ([`FUTURE_TAG`]) of `address`, to be decided
/// again at `due` (Unix seconds): the tag, the time, then the address, so
/// the rows due come first.
fn future_key(due: u64, address: &XorName) -> [u8; 41] {
    let mut key = [0u8; 41];
    key[0] = FUTURE_TAG;
    key[1..9].copy_from_slice(&due.to_be_bytes());
    key[9..].copy_from_slice(address);
    key
}

/// Up to `limit` of the addresses of `db`'s rows tagged `tag` (the tag, then
/// the address), after `after` (or from the first), in address order.
///
/// # Errors
///
/// If the store can't be read.
fn tagged_after<DC>(
    db: Database<Bytes, DC>,
    txn: &RoTxn,
    tag: u8,
    after: Option<&XorName>,
    limit: usize,
) -> Result<Vec<XorName>> {
    let from = match after {
        Some(after) => tagged(tag, after),
        None => vec![tag],
    };
    let end = [tag.saturating_add(1)];
    let low = if after.is_some() {
        Bound::Excluded(&from[..])
    } else {
        Bound::Included(&from[..])
    };
    let range = (low, Bound::Excluded(&end[..]));
    let mut addresses = Vec::new();
    for row in db
        .remap_data_type::<DecodeIgnore>()
        .range(txn, &range)
        .map_err(store_error)?
    {
        if addresses.len() == limit {
            break;
        }
        let (key, ()) = row.map_err(store_error)?;
        if let Some(address) = key.get(1..).and_then(|rest| XorName::try_from(rest).ok()) {
            addresses.push(address);
        }
    }
    Ok(addresses)
}

/// A hash of an address's nearest nodes, in order: to tell whether they
/// changed without keeping them. Only compared within one process.
fn nearest_hash(nearest: &[PeerId]) -> u64 {
    let mut hasher = DefaultHasher::new();
    for peer in nearest {
        peer.as_bytes().hash(&mut hasher);
    }
    hasher.finish()
}

/// When a drop that `refusal` kept at `now` (Unix seconds), resting on
/// `inputs` ([`drop_inputs`]), is checked again, `before` being its backoff
/// until then: when only what wasn't heard kept it (nodes that didn't
/// answer, a lookup that failed), at the next cycle, once, as a read would
/// check it again; otherwise, or after that once, not for
/// [`RETRY_INTERVAL`].
fn drop_backoff(
    refusal: &Refusal,
    before: Option<DropBackoff>,
    inputs: u64,
    now: u64,
) -> DropBackoff {
    let soon =
        !refusal.evidence && !before.is_some_and(|before| before.inputs == inputs && before.soon);
    let retry_at = if soon {
        now.saturating_add(1)
    } else {
        now.saturating_add(RETRY_INTERVAL.as_secs())
    };
    DropBackoff {
        inputs,
        retry_at,
        soon,
    }
}

/// What a drop's evidence rests on, besides the address's copies: its
/// nearest nodes, and the nodes that last served it with whether each is
/// still a member (`member`), as one that left needn't answer, as a hash.
fn drop_inputs(
    nearest: &[PeerId],
    last_holders: &[PeerId],
    member: impl Fn(&PeerId) -> bool,
) -> u64 {
    let mut hasher = DefaultHasher::new();
    nearest_hash(nearest).hash(&mut hasher);
    let mut last: Vec<&PeerId> = last_holders.iter().collect();
    last.sort_unstable();
    for peer in last {
        peer.as_bytes().hash(&mut hasher);
        member(peer).hash(&mut hasher);
    }
    hasher.finish()
}

/// Whether `row`, a listing rejected for good, was rejected on chain facts
/// that aren't final yet ([`ListingChain::settled`]), so deciding its
/// address again once they are could change it. Not one rejected without
/// being looked up, as a listing a quorum serves counts instead, nor one
/// that shows it was paid before the payment vault was deployed, which reads
/// no fact.
fn unsettled(chain: &ListingChain, row: &RejectedListing) -> bool {
    let payment = &row.listing.payment;
    let before_vault = payment
        .block_number
        .is_some_and(|block| chain.before_vault_deployment(block))
        || payment
            .block_timestamp
            .is_some_and(|time| chain.timed_before_vault_deployment(time));
    !row.problem.starts_with(NOT_LOOKED_UP) && !before_vault && !chain.settled(&row.listing)
}

impl Seen {
    /// What deciding at `now` (Unix seconds) keeps of `found`, whose copies
    /// were taken.
    fn of(found: &AddressWalk<PeerId>, now: u64) -> Self {
        let latest = now.saturating_add(CLOCK_MARGIN);
        let future = found
            .copies
            .iter()
            .flat_map(|(_, copy)| [copy.first_seen, copy.payment.block_timestamp])
            .flatten()
            .filter(|time| *time > latest)
            .min()
            .map(|time| time - CLOCK_MARGIN);
        Self {
            address: found.address,
            nearest: nearest_hash(&found.nearest),
            holders: found.copies.iter().map(|(peer, _)| *peer).collect(),
            future,
        }
    }
}

/// Wait until the clock is past second `second` (Unix seconds), the second
/// the latest publication ended in: until the next second, at most. A
/// clock that is behind `second` was set back since: waiting for it to
/// catch up would hold every publication up for as long, so none is waited
/// for, and the second may repeat.
async fn wait_past(second: u64) {
    loop {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        match now.as_secs().cmp(&second) {
            std::cmp::Ordering::Greater => return,
            std::cmp::Ordering::Less => {
                warn!(
                    "The clock is {} s behind the latest publication: it was set back",
                    second - now.as_secs()
                );
                return;
            }
            std::cmp::Ordering::Equal => {
                let rest = Duration::from_secs(1)
                    .saturating_sub(Duration::from_nanos(u64::from(now.subsec_nanos())));
                tokio::time::sleep(rest).await;
            }
        }
    }
}

/// Log, as an alert, the addresses whose published files `publication`, a
/// cycle that decided every address again, changes although nothing in
/// `explained` (the addresses whose inputs changed) says why.
fn alert_unexplained(publication: &Publication, explained: &BTreeSet<XorName>) {
    let mut changed: BTreeSet<XorName> = BTreeSet::new();
    changed.extend(publication.changes.iter().filter_map(IndexChange::address));
    changed.extend(publication.support.iter().filter_map(|support| {
        hex::decode(&support.address)
            .ok()
            .and_then(|bytes| XorName::try_from(bytes).ok())
    }));
    changed.extend(
        publication
            .rejected
            .iter()
            .filter_map(|change| match change {
                RejectedChange::Set(entry) => entry.listing.address(),
                RejectedChange::Clear(address) => Some(*address),
            }),
    );
    let unexplained: Vec<String> = changed.difference(explained).map(hex::encode).collect();
    if !unexplained.is_empty() {
        warn!(
            "Deciding every address again changed {} that no change of their inputs explains: {}",
            unexplained.len(),
            unexplained.join(", ")
        );
    }
}

/// Traffic to and from nodes, and calls to the chain, so far: a cycle's are
/// the difference between two.
#[derive(Debug, Clone, Copy)]
struct Counters {
    bytes_in: u64,
    bytes_out: u64,
    rpc_calls: u64,
    rpc_errors: u64,
}

impl Counters {
    fn now(chain: &ListingChain) -> Self {
        let (bytes_in, bytes_out) = listings_traffic();
        let (rpc_calls, rpc_errors) = rpc_sums(&chain.rpc_calls());
        Self {
            bytes_in,
            bytes_out,
            rpc_calls,
            rpc_errors,
        }
    }
}

/// What a cycle counted, for `status.json`, its batches' counts added up.
#[derive(Debug, Clone, Default)]
struct Tally {
    put: u64,
    removed: u64,
    carried: u64,
    /// The latest batch's listings and rejections for good.
    decided: u64,
    rejected_for_good: u64,
    /// The addresses of the latest batch rejected for good.
    for_good: HashSet<XorName>,
    /// Each address of the latest batch deferred, with its reason's code.
    deferred: Vec<(XorName, &'static str)>,
    /// The addresses deferred, by reason: how many, and since when the
    /// longest-waiting has waited.
    groups: BTreeMap<&'static str, (u64, u64)>,
    /// Each listed file of the latest batch whose data map is shrunk and
    /// whose size isn't known yet, with its data map.
    wanted_sizes: Vec<(XorName, DataMap)>,
}

/// Log what a cycle did.
fn log_cycle(report: &CycleReport) {
    let status = &report.status;
    let poll = &report.poll;
    info!(
        "Listings cycle: {} of {} nodes answered ({} through their feed, {} with v2 requests, \
         {} fell back), {} looked at, {} decided, {} put, {} removed, {} carried, {} entries \
         (seq {}), {} ms, {} B in, {} B out, {} RPC calls, {} pushes during the poll, {} pushes \
         and {} publications since the previous cycle",
        status.census.answering,
        status.census.nodes,
        poll.feed,
        poll.v2,
        poll.fell_back,
        report.considered,
        status.cycle.decided,
        report.put,
        status.drops.removed,
        status.drops.carried,
        status.count,
        status.seq,
        status.cycle.millis,
        status.cycle.bytes_in,
        status.cycle.bytes_out,
        status.cycle.rpc_calls,
        poll.pushes,
        report.pushes_between,
        report.published_between,
    );
}

/// What `index`, the read of the cycle that began at `at`, changes in what
/// `publisher` has published. `listed` is what the read listed, by address;
/// `unlisted`, each entry published before that the read didn't list, with
/// why it is removed, or `None` to keep it; `sizes`, the size of a listed
/// file whose data map is shrunk, where it is known: one whose size isn't is
/// counted into `tally` as wanted. A listed entry is put where it changed,
/// with its support where that changed; a removed one goes, with its
/// support; a kept one is marked carried in its support. Unless the read
/// found too few nodes, its rejections and deferrals go to `rejected.json`
/// ([`rejected_changes`]), from the rows of the addresses the read is about.
/// What it does is counted into `tally`.
///
/// # Errors
///
/// If the store can't be read.
fn read_publication(
    publisher: &Publisher,
    index: &ListingsIndex,
    listed: &BTreeMap<XorName, &CheckedListing>,
    unlisted: &[(ListingKey, Option<RemoveReason>)],
    sizes: impl Fn(&XorName) -> Option<u64>,
    at: u64,
    tally: &mut Tally,
) -> Result<Publication> {
    let mut publication = Publication {
        at,
        ..Publication::default()
    };
    for checked in &index.listings {
        let address = checked.listing.address;
        let mut entry = Entry::new(&checked.listing, checked.level, at);
        if let Some(map) = shrunk_map(checked) {
            entry.listing.size = sizes(&address);
            if entry.listing.size.is_none() {
                tally.wanted_sizes.push((address, map.clone()));
            }
        }
        let fresh = ShardEntry::new(entry, &checked.envelope);
        let unchanged = publisher
            .entry(&address)?
            .is_some_and(|old| same_entry(&old, &fresh));
        if !unchanged {
            publication.changes.push(IndexChange::Put(Box::new(fresh)));
            tally.put += 1;
        }
        let support = Support {
            address: hex::encode(address),
            nodes: checked.nodes,
            nearest: checked.nearest,
            quorum: checked.quorum,
            carried: false,
        };
        if publisher.support(&address)?.as_ref() != Some(&support) {
            publication.support.push(support);
        }
    }
    let mut carried = HashSet::new();
    for (key, removal) in unlisted {
        let address = key.address;
        if let Some(reason) = *removal {
            publication
                .changes
                .push(IndexChange::Remove { address, reason });
            tally.removed += 1;
        } else {
            tally.carried += 1;
            carried.insert(address);
            if let Some(mut support) = publisher.support(&address)? {
                if !support.carried {
                    support.carried = true;
                    publication.support.push(support);
                }
            }
        }
    }
    if !index.too_few_nodes {
        // The rows of the addresses this read is about: listed, kept,
        // rejected, deferred or shown gone. Any other row stays as it is.
        let mut about: BTreeSet<XorName> = listed.keys().copied().collect();
        about.extend(unlisted.iter().map(|(key, _)| key.address));
        about.extend(index.rejected.iter().map(|row| row.listing.address));
        about.extend(index.decided_addresses());
        let mut rows = Vec::new();
        for address in &about {
            rows.extend(publisher.rejected_entry(address)?);
        }
        publication.rejected = rejected_changes(rows, index, listed, &carried, at, tally);
    }
    tally.decided = listed.len() as u64 + tally.rejected_for_good;
    Ok(publication)
}

/// Whether `fresh` is `old` decided again: the same apart from when.
fn same_entry(old: &ShardEntry, fresh: &ShardEntry) -> bool {
    old.entry.listing == fresh.entry.listing
        && old.entry.check == fresh.entry.check
        && old.data_map == fresh.data_map
}

/// The data map of `checked`'s envelope, if it is shrunk into a child map,
/// so that the listing gives no size ([`Envelope::file_size`]).
fn shrunk_map(checked: &CheckedListing) -> Option<&DataMap> {
    checked
        .envelope
        .data_map()
        .filter(|map| map.is_child() && checked.listing.size.is_none())
}

/// The sum of a root map's chunk sizes, or `None` if it overflows: the file's
/// size, as its uploader gave it.
fn root_size(root: &DataMap) -> Option<u64> {
    if root.is_child() {
        return None;
    }
    root.infos().iter().try_fold(0u64, |total, chunk| {
        total.checked_add(u64::try_from(chunk.src_size).ok()?)
    })
}

/// The size of the file whose data map is `map`, read from its root map
/// ([`root_size`]) within bounds, fetching the chunks it needs through
/// `fetch` (a chunk's record by its address). `map` must be shrunk once:
/// at most [`SHRUNK_CHUNKS`] chunks, declaring at most
/// [`MAX_ROOT_MAP_BYTES`] between them, that decrypt to a root map. Each
/// chunk's record must have its address, and each decrypts to no more than
/// the size `map` declares for it, with the hash it declares
/// ([`DataMapIndex::decrypt_chunk`]), so no chunk can expand past what
/// `map` declares. The bytes declared are held in `room` (a permit a KiB)
/// while they are read, so the reads at once hold at most what `room`
/// gives. A map that breaks any of this never gives a size
/// ([`SizeRead::Never`]); one whose chunk wasn't handed over, or not as its
/// address says, may later ([`SizeRead::Later`]).
///
/// A map shrunk more than once (a file over about 658 GB) comes from
/// self-encryption (0.36) labelled as shrunk once, and the map in between,
/// whose chunks are encrypted as a child's, labelled a root: it decodes as
/// a root map, and gives what self-encryption itself resolves the map to,
/// the length of the root map shrunk away rather than the file's size.
/// Such a file can't be downloaded either.
async fn read_root_size<F, Fut>(map: &DataMap, fetch: F, room: &Semaphore) -> SizeRead
where
    F: Fn([u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Result<bytes::Bytes>>,
{
    if !map.is_child() {
        return root_size(map).map_or(SizeRead::Never, SizeRead::Sized);
    }
    let Ok(index) = DataMapIndex::new(map) else {
        return SizeRead::Never;
    };
    let declared = usize::try_from(index.file_size()).unwrap_or(usize::MAX);
    if index.infos().len() > SHRUNK_CHUNKS || declared > MAX_ROOT_MAP_BYTES {
        return SizeRead::Never;
    }
    let permits = u32::try_from(declared.div_ceil(1024)).unwrap_or(u32::MAX);
    let Ok(_room) = room.acquire_many(permits).await else {
        return SizeRead::Later;
    };
    let mut content = Vec::with_capacity(declared);
    for (chunk, info) in index.infos().iter().enumerate() {
        let address = info.dst_hash.0;
        let Ok(record) = fetch(address).await else {
            return SizeRead::Later;
        };
        if crate::record::verify(&address, &record).is_err() {
            return SizeRead::Later;
        }
        match index.decrypt_chunk(chunk, &record) {
            Ok(plain) => content.extend_from_slice(&plain),
            Err(_) => return SizeRead::Never,
        }
    }
    match DataMap::from_bytes(&content) {
        Ok(root) if !root.is_child() => root_size(&root).map_or(SizeRead::Never, SizeRead::Sized),
        _ => SizeRead::Never,
    }
}

/// Why the published entry at `address`, with key `key` and showing
/// `shown`, that `index` didn't list goes, if it does: `rejected` when
/// `index` decided the address and rejected it, or when the entry itself
/// shows a payment from before the payment vault was deployed
/// ([`shows_payment_before_vault`]). Every copy of such a listing shows that
/// payment, so it can never count, however many nodes come to serve it, and
/// it never shows. Otherwise (left for later) it is kept, carried: what
/// copies of other listings for the address show, or which nodes answered
/// this cycle, doesn't remove it.
fn removal(
    index: &ListingsIndex,
    address: &XorName,
    key: &ListingKey,
    shown: &ListingFields,
    chain: &ListingChain,
) -> Option<RemoveReason> {
    let rejected =
        index.carry(address, key) == Carry::Decided || shows_payment_before_vault(shown, chain);
    rejected.then_some(RemoveReason::Rejected)
}

/// Whether `shown`, what a published entry shows, shows a payment from
/// before `chain`'s payment vault was deployed: a block before the one it
/// was deployed in, or a block timestamp before that block's, as a pending
/// copy is marked ([`PendingCopy::before_vault_deployment`]).
fn shows_payment_before_vault(shown: &ListingFields, chain: &ListingChain) -> bool {
    shown
        .block_number
        .is_some_and(|block| chain.before_vault_deployment(block))
        || shown
            .block_timestamp
            .is_some_and(|time| chain.timed_before_vault_deployment(time))
}

/// Why an address is rejected for good when every copy its nearest nodes
/// serve was paid before the payment vault was deployed
/// ([`paid_before_vault`]).
const PAID_BEFORE_VAULT: &str =
    "every copy the nodes nearest its address serve shows it paid before the payment vault was \
     deployed: not a payment to the vault";

/// Whether `copies`, those the nearest nodes serve of an address too few of
/// them serve to decide yet, all show a payment from before the payment vault
/// was deployed ([`PendingCopy::before_vault_deployment`]). None of them can
/// ever count, however many nodes come to serve them, so the address is
/// rejected for good rather than left for a later cycle. An address with no
/// copies, or with any copy not marked so, is not.
fn paid_before_vault(copies: &[PendingCopy]) -> bool {
    !copies.is_empty() && copies.iter().all(|copy| copy.before_vault_deployment)
}

/// The changes to `rejected.json`, whose rows are `existing`, that `index`, a
/// read, makes. `rejected.json` lists only addresses the producer didn't
/// list: an address the read listed (`listed`), or whose published entry is
/// kept unconfirmed (`carried`), has no row there, and loses any it had.
/// Each other address the read rejected or deferred gets its latest
/// rejection or deferral (the first in index order), left as it was where
/// only the time it was decided would change. An address it deferred is
/// rejected for good instead when every copy its nearest nodes serve was
/// paid before the payment vault was deployed ([`paid_before_vault`]).
/// Every address the read rejected or deferred and didn't list, carried or
/// not, is counted into `tally`, as deferred (for `status.json`'s deferred
/// groups) or as rejected for good. A row is cleared once its address is
/// listed or carried, decided without a rejection, or walked past by its
/// whole close group.
fn rejected_changes(
    existing: Vec<RejectedEntry>,
    index: &ListingsIndex,
    listed: &BTreeMap<XorName, &CheckedListing>,
    carried: &HashSet<XorName>,
    at: u64,
    tally: &mut Tally,
) -> Vec<RejectedChange> {
    let existing: HashMap<String, RejectedEntry> = existing
        .into_iter()
        .map(|entry| (entry.listing.address.clone(), entry))
        .collect();
    let mut changes = Vec::new();
    let mut seen = HashSet::new();
    for rejected in &index.rejected {
        let address = rejected.listing.address;
        if listed.contains_key(&address) || !seen.insert(address) {
            continue;
        }
        let copies = index
            .pending_copies
            .get(&address)
            .map_or(&[][..], Vec::as_slice);
        let mut entry = RejectedEntry::new(rejected, copies, at);
        if entry.again && paid_before_vault(copies) {
            entry.again = false;
            entry.problem = PAID_BEFORE_VAULT.to_owned();
        }
        if entry.again {
            let pending = index.pending_copies.contains_key(&address);
            tally
                .deferred
                .push((address, deferral_reason(&rejected.problem, pending)));
        } else {
            tally.rejected_for_good += 1;
            tally.for_good.insert(address);
        }
        if carried.contains(&address) {
            // Still listed, unconfirmed, and counted above: it gets no row,
            // and any it has is cleared below. (An entry that itself shows a
            // payment from before the vault isn't kept carried: it goes,
            // rejected ([`removal`]).)
            continue;
        }
        let unchanged = existing.get(&entry.listing.address).is_some_and(|old| {
            RejectedEntry {
                decided_at: old.decided_at,
                ..entry.clone()
            } == *old
        });
        if !unchanged {
            changes.push(RejectedChange::Set(Box::new(entry)));
        }
    }
    for old in existing.values() {
        let Some(address) = old.listing.address() else {
            continue;
        };
        if listed.contains_key(&address) || carried.contains(&address) {
            changes.push(RejectedChange::Clear(address));
            continue;
        }
        if seen.contains(&address) {
            continue;
        }
        let keep = old
            .listing
            .key()
            .is_some_and(|key| index.carry(&address, &key) == Carry::Keep);
        if !keep {
            changes.push(RejectedChange::Clear(address));
        }
    }
    changes
}

/// The code a deferral's reason row keeps ([`REASON_TAG`]) for `reason`:
/// its place in [`DEFERRAL_REASONS`], plus one; a reason not among them is
/// kept as `other`.
fn reason_code(reason: &str) -> u64 {
    let code = DEFERRAL_REASONS
        .iter()
        .position(|known| *known == reason)
        .map_or(DEFERRAL_REASONS.len(), |at| at + 1);
    u64::try_from(code).unwrap_or(0)
}

/// A deferral read back: since when, from `value`, its [`DEFERRED_TAG`]
/// row, and its latest reason, from `code`, what its reason row holds
/// ([`reason_code`]). A row an earlier version of the producer wrote holds
/// the time with the code in its top byte ([`SINCE_TIME`]), newer than any
/// reason row then; a deferral with no code, as a version that keeps no
/// reasons left it, gives `other` until its address is decided again.
fn deferral_of(value: u64, code: Option<u64>) -> (u64, &'static str) {
    let code = match value >> 56 {
        0 => code.unwrap_or(0),
        top => top,
    };
    let reason = usize::try_from(code)
        .ok()
        .and_then(|code| code.checked_sub(1))
        .and_then(|at| DEFERRAL_REASONS.get(at))
        .copied()
        .unwrap_or("other");
    (value & SINCE_TIME, reason)
}

/// Bring the deferrals' rows in `since` ([`SINCE_DB`]) to the form this
/// version keeps, in `txn`, as the producer opens: [`DECIDE_BATCH`] rows
/// at a time, every row read once. A [`DEFERRED_TAG`] row an earlier
/// version wrote with its reason's code in its top byte ([`SINCE_TIME`]) is
/// written again as the time alone, with the code in its reason row
/// ([`REASON_TAG`]): so it reads as Unix seconds to every version, the one
/// before reasons were kept among them. A reason row whose address is no
/// longer deferred goes: a version that keeps no reason rows ended the
/// deferral without it.
///
/// # Errors
///
/// If the store can't be read or written.
fn settle_deferrals(since: Database<Bytes, U64<BigEndian>>, txn: &mut RwTxn) -> Result<()> {
    let mut after: Option<XorName> = None;
    loop {
        let batch = tagged_after(since, txn, DEFERRED_TAG, after.as_ref(), DECIDE_BATCH)?;
        for address in &batch {
            let row = tagged(DEFERRED_TAG, address);
            let Some(value) = since.get(txn, &row).map_err(store_error)? else {
                continue;
            };
            let code = value >> 56;
            if code != 0 {
                since
                    .put(txn, &row, &(value & SINCE_TIME))
                    .map_err(store_error)?;
                since
                    .put(txn, &tagged(REASON_TAG, address), &code)
                    .map_err(store_error)?;
            }
        }
        match batch.last() {
            Some(last) if batch.len() == DECIDE_BATCH => after = Some(*last),
            _ => break,
        }
    }
    let mut after: Option<XorName> = None;
    loop {
        let batch = tagged_after(since, txn, REASON_TAG, after.as_ref(), DECIDE_BATCH)?;
        for address in &batch {
            let deferred = since
                .get(txn, &tagged(DEFERRED_TAG, address))
                .map_err(store_error)?
                .is_some();
            if !deferred {
                since
                    .delete(txn, &tagged(REASON_TAG, address))
                    .map_err(store_error)?;
            }
        }
        match batch.last() {
            Some(last) if batch.len() == DECIDE_BATCH => after = Some(*last),
            _ => break,
        }
    }
    Ok(())
}

/// A deferral's reason, as `status.json` gives it, from the problem the read
/// gave: `pending` when fewer than a quorum of the nearest nodes serve it.
fn deferral_reason(problem: &str, pending: bool) -> &'static str {
    if pending {
        "below_quorum"
    } else if problem.contains("envelope") {
        "envelope_unavailable"
    } else if problem.contains("payment chain") {
        "chain_unread"
    } else if problem.contains("not on the chain yet") {
        "not_on_chain_yet"
    } else if problem.contains("future") {
        "future_time"
    } else if problem.contains("haven't answered") || problem.contains("too few nearest nodes") {
        "nodes_unanswered"
    } else {
        "other"
    }
}

/// The calls made to all providers, and how many failed.
fn rpc_sums(calls: &[RpcCalls]) -> (u64, u64) {
    calls.iter().fold((0, 0), |(calls, errors), provider| {
        (calls + provider.calls, errors + provider.errors)
    })
}

/// `tag`, then `address`.
fn tagged(tag: u8, address: &XorName) -> Vec<u8> {
    let mut row = Vec::with_capacity(1 + address.len());
    row.push(tag);
    row.extend_from_slice(address);
    row
}

/// This process's own resident memory, in bytes, where the system says:
/// its anonymous pages (`RssAnon`), not the store's file pages mapped in,
/// which the system can drop at any time and which grow with the store.
fn rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("RssAnon:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    kib.checked_mul(1024)
}

/// [`Producer::carry_from`] into `publisher`, with `status` for
/// `status.json`.
///
/// # Errors
///
/// As [`Producer::carry_from`].
fn carry_into(publisher: &mut Publisher, previous: &Path, status: Status) -> Result<usize> {
    if publisher.seq() > 0 || publisher.count() > 0 {
        return Ok(0);
    }
    let bytes = match std::fs::read(previous) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(Error::Io(e)),
    };
    let at = unix_now();
    let carried = previous_entries(&bytes, at)?;
    let taken = carried.len();
    let mut publication = Publication {
        at,
        status,
        ..Publication::default()
    };
    for (entry, support) in carried {
        publication.changes.push(IndexChange::Put(Box::new(entry)));
        publication.support.push(support);
    }
    publisher.publish_carry(&publication)?;
    Ok(taken)
}

/// The entries of `bytes`, an earlier `darwin listings --json` output, but
/// those marked as failing their checks: each as published, decided at
/// `at`, with its support marked carried. An entry without `valid`, as one
/// carried over from an older output may be, is taken: a `listings.json`
/// written from such outputs publishes it.
///
/// # Errors
///
/// If it isn't a list of such entries.
fn previous_entries(bytes: &[u8], at: u64) -> Result<Vec<(ShardEntry, Support)>> {
    let entries: Vec<Map<String, Value>> = serde_json::from_slice(bytes)
        .map_err(|e| Error::InvalidData(format!("not a list of listings: {e}")))?;
    let mut carried = Vec::new();
    for (n, mut entry) in entries.into_iter().enumerate() {
        let bad = |e: String| Error::InvalidData(format!("entry {}: {e}", n + 1));
        if entry.get("valid").and_then(Value::as_bool) == Some(false) {
            continue;
        }
        let number =
            |entry: &Map<String, Value>, field: &str| entry.get(field).and_then(Value::as_u64);
        if !entry.contains_key("time") {
            // Output from before `time` was printed: the time it sorted by.
            let time = number(&entry, "block_timestamp")
                .or(number(&entry, "first_seen"))
                .unwrap_or(0);
            entry.insert("time".into(), Value::from(time));
        }
        let check = entry
            .get("check")
            .cloned()
            .ok_or_else(|| bad("no check".into()))?;
        let check = serde_json::from_value(check).map_err(|e| bad(format!("check: {e}")))?;
        let count = |field: &str| {
            number(&entry, field).map_or(0, |n| usize::try_from(n).unwrap_or(usize::MAX))
        };
        let (nodes, nearest) = (count("nodes"), count("nearest"));
        let quorum = entry
            .get("quorum")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let data_map = entry
            .get("data_map")
            .and_then(Value::as_str)
            .map(str::to_string);
        let listing: ListingFields =
            serde_json::from_value(Value::Object(entry)).map_err(|e| bad(e.to_string()))?;
        let support = Support {
            address: listing.address.clone(),
            nodes,
            nearest,
            quorum,
            carried: true,
        };
        let entry = ShardEntry {
            entry: Entry {
                listing,
                check,
                decided_at: at,
            },
            data_map,
        };
        carried.push((entry, support));
    }
    Ok(carried)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::client::listings::RejectedListing;
    use crate::data::client::listings_v1::SupportShard;
    use ant_listings::{
        AddressRange, CheckLevel, Envelope, Flags, Listing, ListingPayment, Metadata, PaymentField,
        ShownFields, SALTED_HASH_LEN,
    };

    const ADDRESS: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn printed(extra: &str) -> String {
        format!(
            r#"{{"address":"{ADDRESS}","name":"a.txt","content_type":"text/plain","size":5,
            "readable":true,"in_index":true,"hidden":[],"block_number":81942857,
            "block_timestamp":1791321603,"log_index":7,"check":"verified","nodes":6,
            "nearest":7,"quorum":true,"data_map":"abcd","valid":true,"problem":null{extra}}}"#
        )
    }

    #[test]
    fn earlier_output_is_taken_as_carried_entries() {
        let rejected = r#"{"address":"2222222222222222222222222222222222222222222222222222222222222222","time":5,"nodes":2,"nearest":7,"valid":false,"problem":"try again"}"#;
        // An entry with no `valid`, as one carried over unchanged from an
        // older output may be: published, so taken.
        let unmarked = printed("")
            .replace(ADDRESS, &"33".repeat(32))
            .replace(r#","valid":true"#, "");
        assert!(!unmarked.contains("valid"));
        let bytes = format!(
            "[{},{rejected},{unmarked}]",
            printed(r#","time":1791321603"#)
        );
        let taken = previous_entries(bytes.as_bytes(), 100).unwrap();
        let addresses: Vec<&str> = taken
            .iter()
            .map(|(entry, _)| entry.entry.listing.address.as_str())
            .collect();
        assert_eq!(
            addresses,
            [ADDRESS, "33".repeat(32).as_str()],
            "an entry that failed its checks isn't taken; one not marked is"
        );
        let (entry, support) = &taken[0];
        assert_eq!(entry.entry.listing.address, ADDRESS);
        assert_eq!(entry.entry.listing.time, 1_791_321_603);
        assert_eq!(entry.entry.listing.block_number, Some(81_942_857));
        assert_eq!(entry.entry.check, CheckLevel::Verified);
        assert_eq!(entry.entry.decided_at, 100);
        assert_eq!(entry.data_map.as_deref(), Some("abcd"));
        assert_eq!(
            *support,
            Support {
                address: ADDRESS.into(),
                nodes: 6,
                nearest: 7,
                quorum: true,
                carried: true,
            }
        );
    }

    #[test]
    fn earlier_output_without_time_sorts_as_it_did() {
        let bytes = format!("[{}]", printed(""));
        let taken = previous_entries(bytes.as_bytes(), 100).unwrap();
        assert_eq!(taken[0].0.entry.listing.time, 1_791_321_603);
    }

    #[test]
    fn output_that_is_not_a_list_of_entries_is_refused() {
        assert!(previous_entries(b"{}", 1).is_err());
        let no_check = printed("").replace(r#""check":"verified","#, "");
        assert!(previous_entries(format!("[{no_check}]").as_bytes(), 1).is_err());
    }

    #[test]
    fn deciding_the_same_entry_again_changes_nothing() {
        let bytes = format!("[{}]", printed(""));
        let old = previous_entries(bytes.as_bytes(), 100).unwrap().remove(0).0;
        let mut fresh = old.clone();
        fresh.entry.decided_at = 200;
        assert!(same_entry(&old, &fresh));
        fresh.entry.check = CheckLevel::Reported;
        assert!(!same_entry(&old, &fresh));
    }

    #[test]
    fn deferrals_are_grouped_by_the_reasons_the_format_names() {
        let reason = |problem: &str| deferral_reason(problem, false);
        assert_eq!(deferral_reason("anything", true), "below_quorum");
        assert_eq!(
            reason("none of the nodes serving it handed over its envelope; try again"),
            "envelope_unavailable"
        );
        assert_eq!(
            reason("could not fetch the envelope: timeout; try again"),
            "envelope_unavailable"
        );
        assert_eq!(
            reason("could not read the payment chain: refused; try again"),
            "chain_unread"
        );
        assert_eq!(
            reason(
                "not decided: the payment chain could not be read for the listing a quorum \
                 of the nearest nodes serve; try again"
            ),
            "chain_unread"
        );
        assert_eq!(
            reason("its payment is not on the chain yet; try again"),
            "not_on_chain_yet"
        );
        assert_eq!(
            reason(
                "no listing for it has a quorum of its nearest nodes yet: 3 serve the one \
                 most serve, 2 haven't answered; try again"
            ),
            "nodes_unanswered"
        );
        assert_eq!(reason("something else; try again"), "other");
    }

    /// The block the payment vault was deployed in, on the bundled network.
    const VAULT_BLOCK: u64 = 81_897_121;

    /// When the cycle began.
    const AT: u64 = 1_791_324_060;

    /// A listing at `address` that shows only its block, `block`.
    fn showing_block(address: XorName, block: u64) -> Listing {
        Listing {
            address,
            flags: Flags {
                shown: ShownFields::NONE.with(PaymentField::BlockNumber),
                in_index: true,
                withheld: true,
            },
            metadata: Metadata::default(),
            size: None,
            payment: ListingPayment {
                block_number: Some(block),
                ..ListingPayment::default()
            },
            first_seen: Some(1_791_324_000),
        }
    }

    /// Leave `address` in `index` as a read does when fewer than 4 of its 7
    /// nearest nodes serve it: one copy per node, each showing only its
    /// block, `blocks`, and marked where that is before [`VAULT_BLOCK`].
    fn defer(index: &mut ListingsIndex, address: XorName, blocks: &[u64]) {
        index.deferred += 1;
        index.rejected.push(RejectedListing {
            listing: showing_block(address, blocks[0]),
            problem: format!(
                "served by {} of the 7 nodes nearest its address so far, needs 4; try again",
                blocks.len()
            ),
            nodes: blocks.iter().filter(|&&block| block == blocks[0]).count(),
            nearest: 7,
            again: true,
        });
        let copies = blocks
            .iter()
            .zip(1u8..)
            .map(|(&block, node)| PendingCopy {
                node: PeerId::from_bytes([node; 32]),
                block_number: Some(block),
                block_timestamp: None,
                first_seen: Some(1_791_324_000),
                before_vault_deployment: block < VAULT_BLOCK,
            })
            .collect();
        index.pending_copies.insert(address, copies);
    }

    /// The rows `changes` sets in `rejected.json`, failing on any it clears.
    fn set_rows(changes: &[RejectedChange]) -> Vec<RejectedEntry> {
        changes
            .iter()
            .map(|change| match change {
                RejectedChange::Set(entry) => (**entry).clone(),
                RejectedChange::Clear(address) => panic!("{} cleared", hex::encode(address)),
            })
            .collect()
    }

    #[test]
    fn an_address_every_copy_of_which_was_paid_before_the_vault_is_rejected_for_good() {
        // As rejected.json shows two addresses: fewer than 4 of their 7
        // nearest nodes serve them, and every copy those nodes serve was paid
        // before the payment vault was deployed.
        let (two, one) = ([0x3d; 32], [0x7e; 32]);
        let mut index = ListingsIndex::default();
        defer(&mut index, two, &[80_204_042, 80_204_042]);
        defer(&mut index, one, &[80_204_042]);
        let mut tally = Tally::default();
        let changes = rejected_changes(
            Vec::new(),
            &index,
            &BTreeMap::new(),
            &HashSet::new(),
            AT,
            &mut tally,
        );
        // Neither is left for a later cycle, so status.json's deferred
        // groups, which the watchdog alerts on after a day, leave them out.
        assert!(tally.deferred.is_empty(), "deferred: {:?}", tally.deferred);
        assert_eq!(tally.rejected_for_good, 2);
        // Both decisions stand, as status.json's cycle.decided counts them.
        assert_eq!(tally.for_good, HashSet::from([two, one]));
        // Both stay in rejected.json, rejected for good, with their copies.
        let rows = set_rows(&changes);
        assert_eq!(rows.len(), 2);
        for (row, address, copies) in [(&rows[0], two, 2), (&rows[1], one, 1)] {
            assert_eq!(row.listing.address, hex::encode(address));
            assert!(!row.again);
            assert_eq!(
                row.problem,
                "every copy the nodes nearest its address serve shows it paid before the \
                 payment vault was deployed: not a payment to the vault"
            );
            assert_eq!((row.nodes, row.nearest), (copies, 7));
            assert_eq!(row.copies.len(), copies);
            assert!(row.copies.iter().all(|copy| copy.before_vault_deployment));
            assert_eq!(row.decided_at, AT);
        }
        // The next cycle finds them the same: nothing to write.
        let mut next = Tally::default();
        let changes = rejected_changes(
            rows,
            &index,
            &BTreeMap::new(),
            &HashSet::new(),
            AT + 60,
            &mut next,
        );
        assert!(changes.is_empty(), "{changes:?}");
        assert!(next.deferred.is_empty());
        assert_eq!(next.rejected_for_good, 2);
    }

    #[test]
    fn an_address_with_any_copy_not_paid_before_the_vault_stays_deferred() {
        // One copy was paid before the payment vault was deployed and one
        // after it: the later one can still count once 4 nodes serve it.
        let mixed = [0x3d; 32];
        // And no copies at all to go by: the chain couldn't be read for it.
        let unread = [0x7e; 32];
        let mut index = ListingsIndex::default();
        defer(&mut index, mixed, &[80_204_042, 81_950_000]);
        index.rejected.push(RejectedListing {
            listing: showing_block(unread, 81_950_000),
            problem: "could not read the payment chain: refused; try again".into(),
            nodes: 4,
            nearest: 7,
            again: true,
        });
        let mut tally = Tally::default();
        let changes = rejected_changes(
            Vec::new(),
            &index,
            &BTreeMap::new(),
            &HashSet::new(),
            AT,
            &mut tally,
        );
        assert_eq!(
            tally.deferred,
            [(mixed, "below_quorum"), (unread, "chain_unread")]
        );
        assert_eq!(tally.rejected_for_good, 0);
        let rows = set_rows(&changes);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|row| row.again));
        assert_eq!(
            rows[0].problem,
            "served by 2 of the 7 nodes nearest its address so far, needs 4; try again"
        );
        assert_eq!(rows[0].copies.len(), 2);
        assert!(rows[1].copies.is_empty());
    }

    /// A publisher of files in a temporary directory, as the producer's,
    /// with its store.
    fn publisher() -> (tempfile::TempDir, Publisher) {
        let dir = tempfile::tempdir().unwrap();
        let store =
            ListingsStore::open_with_map_size(&dir.path().join("store"), 64 * 1024 * 1024).unwrap();
        let mut publisher = Publisher::open(&dir.path().join("v1"), &store).unwrap();
        publisher.set_flush(false);
        (dir, publisher)
    }

    /// The listing at `address`, showing only its block, as a read lists it
    /// when all 7 of its nearest nodes serve it.
    fn checked(address: XorName) -> CheckedListing {
        checked_at(address, 81_950_000)
    }

    /// [`checked`], paid in `block`.
    fn checked_at(address: XorName, block: u64) -> CheckedListing {
        let shown = ShownFields::NONE.with(PaymentField::BlockNumber);
        CheckedListing {
            listing: showing_block(address, block),
            envelope: Envelope::withheld_hash(
                [0x5a; SALTED_HASH_LEN],
                Metadata::default(),
                shown,
                true,
            )
            .unwrap(),
            level: CheckLevel::Reported,
            nodes: 7,
            nearest: 7,
            quorum: true,
        }
    }

    /// Publish what `index`, the read of the cycle that began at `at`,
    /// changes in what `publisher` has published, as a cycle does: each
    /// published entry the read didn't list is removed for `removal`, or
    /// kept if that is `None`. Returns the publication and what the cycle
    /// counted.
    fn publish_read(
        publisher: &mut Publisher,
        index: &ListingsIndex,
        removal: Option<RemoveReason>,
        at: u64,
    ) -> (Publication, Tally) {
        let listed: BTreeMap<XorName, &CheckedListing> = index
            .listings
            .iter()
            .map(|checked| (checked.listing.address, checked))
            .collect();
        let unlisted: Vec<(ListingKey, Option<RemoveReason>)> = publisher
            .keys()
            .unwrap()
            .into_iter()
            .filter(|key| !listed.contains_key(&key.address))
            .map(|key| (key, removal))
            .collect();
        let mut tally = Tally::default();
        let publication = read_publication(
            publisher,
            index,
            &listed,
            &unlisted,
            |_| None,
            at,
            &mut tally,
        )
        .unwrap();
        publisher.publish(&publication).unwrap();
        (publication, tally)
    }

    #[test]
    fn rejected_json_lists_only_addresses_the_producer_does_not_list() {
        // One address through its life: listed, carried, rejected for good
        // and removed, then listed and carried again.
        let x: XorName = [0x3d; 32];
        let (_dir, mut publisher) = publisher();
        let rows = |publisher: &Publisher| publisher.rejected_entries().unwrap();
        let carried = |publisher: &Publisher| {
            publisher
                .support(&x)
                .unwrap()
                .map(|support| support.carried)
        };
        let listing = || {
            let mut index = ListingsIndex::default();
            index.listings.push(checked(x));
            index
        };
        // 2 of its 7 nearest nodes serve it, both copies paid to the vault:
        // too few to decide it, so it is left for a later cycle.
        let deferring = || {
            let mut index = ListingsIndex::default();
            defer(&mut index, x, &[81_950_000, 81_950_000]);
            index
        };

        // Listed.
        let (_, tally) = publish_read(&mut publisher, &listing(), None, AT);
        assert_eq!(tally.put, 1);
        assert_eq!(carried(&publisher), Some(false));
        assert!(rows(&publisher).is_empty());
        // A row for it in rejected.json too, as an earlier version wrote
        // when a cycle kept it carried.
        let old = deferring();
        let row = RejectedEntry::new(&old.rejected[0], &old.pending_copies[&x], AT + 30);
        publisher
            .publish(&Publication {
                at: AT + 30,
                rejected: vec![RejectedChange::Set(Box::new(row))],
                ..Publication::default()
            })
            .unwrap();
        assert_eq!(rows(&publisher).len(), 1);

        // Carried: the cycle can't decide it, so its entry stays, marked
        // carried. It has no row in rejected.json, and the earlier one goes,
        // while status.json counts it as deferred and as carried.
        let (publication, tally) = publish_read(&mut publisher, &deferring(), None, AT + 60);
        assert_eq!(publication.rejected, [RejectedChange::Clear(x)]);
        assert_eq!(tally.deferred, [(x, "below_quorum")]);
        assert_eq!(tally.carried, 1);
        assert!(publisher.entry(&x).unwrap().is_some());
        assert_eq!(carried(&publisher), Some(true));
        assert!(rows(&publisher).is_empty());
        // The next cycle finds it the same: nothing to write.
        let (publication, tally) = publish_read(&mut publisher, &deferring(), None, AT + 120);
        assert!(publication.rejected.is_empty());
        assert!(publication.support.is_empty());
        assert_eq!(tally.deferred, [(x, "below_quorum")]);

        // Rejected for good: deciding it again rejects it, so it is removed,
        // and rejected.json says why.
        let mut rejecting = ListingsIndex::default();
        rejecting.rejected.push(RejectedListing {
            listing: showing_block(x, 81_950_000),
            problem: "its payment is for another address".into(),
            nodes: 4,
            nearest: 7,
            again: false,
        });
        let removal = Some(RemoveReason::Rejected);
        let (_, tally) = publish_read(&mut publisher, &rejecting, removal, AT + 180);
        assert_eq!((tally.removed, tally.rejected_for_good), (1, 1));
        assert!(tally.deferred.is_empty());
        assert_eq!(publisher.entry(&x).unwrap(), None);
        let rejected = rows(&publisher);
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0].listing.address, hex::encode(x));
        assert!(!rejected[0].again);

        // And back: listed again, its row goes.
        let (publication, _) = publish_read(&mut publisher, &listing(), None, AT + 240);
        assert_eq!(publication.rejected, [RejectedChange::Clear(x)]);
        assert!(publisher.entry(&x).unwrap().is_some());
        assert_eq!(carried(&publisher), Some(false));
        assert!(rows(&publisher).is_empty());
        // Carried again: no row, and counted as deferred.
        let (publication, tally) = publish_read(&mut publisher, &deferring(), None, AT + 300);
        assert!(publication.rejected.is_empty());
        assert_eq!(tally.deferred, [(x, "below_quorum")]);
        assert_eq!(carried(&publisher), Some(true));
        assert!(rows(&publisher).is_empty());
    }

    #[test]
    fn a_listed_entry_that_shows_a_payment_before_the_vault_is_removed() {
        // An entry that itself shows a payment from before the payment vault
        // was deployed, at an address the next cycle can't decide: 2 of its
        // 7 nearest nodes serve it.
        let x: XorName = [0x3d; 32];
        let chain = vault_chain();
        let (_dir, mut publisher) = publisher();
        let mut listing = ListingsIndex::default();
        listing.listings.push(checked_at(x, 80_204_042));
        publish_read(&mut publisher, &listing, None, AT);
        let key = publisher.keys().unwrap()[0];
        let shown = publisher.entry(&x).unwrap().unwrap().entry.listing;
        let mut deferring = ListingsIndex::default();
        defer(&mut deferring, x, &[80_204_042, 80_204_042]);
        // Every copy of it shows that payment, so it can never count, however
        // many nodes come to serve it: it goes, rejected, rather than staying
        // carried.
        let reason = removal(&deferring, &x, &key, &shown, &chain);
        assert_eq!(reason, Some(RemoveReason::Rejected));
        let (publication, tally) = publish_read(&mut publisher, &deferring, reason, AT + 60);
        assert_eq!(
            publication.changes,
            [IndexChange::Remove {
                address: x,
                reason: RemoveReason::Rejected
            }]
        );
        assert_eq!((tally.removed, tally.carried), (1, 0));
        // It is rejected for good: status.json leaves it out of its deferred
        // groups and counts it as decided.
        assert!(tally.deferred.is_empty(), "deferred: {:?}", tally.deferred);
        assert_eq!((tally.rejected_for_good, tally.decided), (1, 1));
        assert!(publisher.entry(&x).unwrap().is_none());
        assert!(publisher.support(&x).unwrap().is_none());
        // rejected.json says why, with its copies.
        let rows = publisher.rejected_entries().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].listing.address, hex::encode(x));
        assert!(!rows[0].again);
        assert_eq!(rows[0].problem, PAID_BEFORE_VAULT);
        assert_eq!(rows[0].copies.len(), 2);
        assert!(rows[0]
            .copies
            .iter()
            .all(|copy| copy.before_vault_deployment));
        // Whatever other listings for the address its nodes serve, and
        // however its address is left for later.
        let mut mixed = ListingsIndex::default();
        defer(&mut mixed, x, &[81_950_000, 81_950_000]);
        assert_eq!(
            removal(&mixed, &x, &key, &shown, &chain),
            Some(RemoveReason::Rejected)
        );
        assert_eq!(
            removal(&ListingsIndex::default(), &x, &key, &shown, &chain),
            Some(RemoveReason::Rejected)
        );
        // So does one that shows only a block timestamp from before then.
        let timed = ListingFields {
            block_number: None,
            block_timestamp: Some(VAULT_TIME - 1),
            ..shown.clone()
        };
        assert_eq!(
            removal(&mixed, &x, &key, &timed, &chain),
            Some(RemoveReason::Rejected)
        );
    }

    #[test]
    fn a_listed_entry_paid_to_the_vault_is_kept_whatever_other_copies_show() {
        // An entry paid to the vault, at an address the cycle can't decide:
        // the only copies that count this cycle show another listing, paid
        // before the vault was deployed (its own nodes didn't count, say).
        let x: XorName = [0x3d; 32];
        let chain = vault_chain();
        let (_dir, mut publisher) = publisher();
        let mut listing = ListingsIndex::default();
        listing.listings.push(checked(x));
        publish_read(&mut publisher, &listing, None, AT);
        let key = publisher.keys().unwrap()[0];
        let shown = publisher.entry(&x).unwrap().unwrap().entry.listing;
        let mut stale = ListingsIndex::default();
        defer(&mut stale, x, &[80_204_042, 80_204_042]);
        // It stays, carried, as an index read keeps it.
        assert_eq!(removal(&stale, &x, &key, &shown, &chain), None);
        let (publication, tally) = publish_read(&mut publisher, &stale, None, AT + 60);
        assert!(publication.changes.is_empty());
        assert_eq!((tally.removed, tally.carried), (0, 1));
        assert!(publisher.entry(&x).unwrap().is_some());
        // It gets no row while carried.
        assert!(publisher.rejected_entries().unwrap().is_empty());
        // Nor does one rejected for a reason a later cycle may undo, or one
        // no copy of which shows anything.
        let mut unread = ListingsIndex::default();
        unread.rejected.push(RejectedListing {
            listing: showing_block(x, 81_950_000),
            problem: "could not read the payment chain: refused; try again".into(),
            nodes: 4,
            nearest: 7,
            again: true,
        });
        assert_eq!(removal(&unread, &x, &key, &shown, &chain), None);
        assert_eq!(
            removal(&ListingsIndex::default(), &x, &key, &shown, &chain),
            None
        );
    }

    #[test]
    fn the_first_cycle_after_a_carry_publishes_its_support_at_once() {
        let (dir, mut publisher) = publisher();
        let previous = dir.path().join("listings.json");
        std::fs::write(&previous, format!("[{}]", printed(""))).unwrap();
        let taken = carry_into(&mut publisher, &previous, Status::default()).unwrap();
        assert_eq!(taken, 1);
        let published = |publisher: &Publisher| {
            let path = publisher.out_dir().join("by-address/111.support.json");
            let bytes = std::fs::read(path).unwrap();
            serde_json::from_slice::<SupportShard>(&bytes)
                .unwrap()
                .support[0]
                .clone()
        };
        let carried = Support {
            address: ADDRESS.into(),
            nodes: 6,
            nearest: 7,
            quorum: true,
            carried: true,
        };
        assert_eq!(published(&publisher), carried);
        // The first cycle decides it: all 7 of its nearest nodes serve it.
        // Its support is published at once, not 10 minutes after the carry.
        let confirmed = Support {
            nodes: 7,
            carried: false,
            ..carried
        };
        publisher
            .publish(&Publication {
                at: unix_now() + 60,
                support: vec![confirmed.clone()],
                ..Publication::default()
            })
            .unwrap();
        assert_eq!(published(&publisher), confirmed);
        // Once the store holds an index, a carry takes nothing.
        let taken = carry_into(&mut publisher, &previous, Status::default()).unwrap();
        assert_eq!(taken, 0);
    }

    /// A payment chain reader that is never asked anything.
    fn idle_chain() -> ListingChain {
        ListingChain::with_rpc("http://127.0.0.1:9".into(), [0x69; 20]).unwrap()
    }

    /// When the payment vault was deployed, as [`vault_chain`] knows it.
    const VAULT_TIME: u64 = 1_791_316_916;

    /// [`idle_chain`], knowing when the payment vault was deployed.
    fn vault_chain() -> ListingChain {
        idle_chain()
            .with_vault_deployment_block(VAULT_BLOCK)
            .with_vault_deployment_time(VAULT_TIME)
    }

    #[test]
    fn each_nodes_copy_is_the_fetched_listing_with_its_own_first_seen() {
        let x: XorName = [0x3d; 32];
        // A listing that hides its time: each node keys it by its own
        // first_seen, so their entries differ but share the digest.
        let first = showing_block(x, 81_950_000);
        let later = Listing {
            first_seen: Some(1_791_327_600),
            ..first.clone()
        };
        let (a, b, c) = (
            PeerId::from_bytes([1; 32]),
            PeerId::from_bytes([2; 32]),
            PeerId::from_bytes([3; 32]),
        );
        let (entry_a, entry_b) = (DigestEntry::new(&first), DigestEntry::new(&later));
        assert_eq!(entry_a.digest, entry_b.digest);
        assert_ne!(entry_a.time, entry_b.time);
        // An entry that doesn't describe what the listing would be with its
        // first_seen: its key's time is another.
        let entry_c = DigestEntry { time: 5, ..entry_a };
        let mut listings: BTreeMap<[u8; 32], Listing> = BTreeMap::new();
        // Not fetched: its node isn't heard from.
        assert_eq!(
            copies_from(|digest| listings.get(digest).cloned(), &[(a, entry_a)]),
            (Vec::new(), vec![a])
        );
        listings.insert(
            entry_a.digest,
            Listing {
                first_seen: None,
                ..first.clone()
            },
        );
        let (copies, unheard) = copies_from(
            |digest| listings.get(digest).cloned(),
            &[(a, entry_a), (b, entry_b), (c, entry_c)],
        );
        assert_eq!(
            copies,
            vec![(a, first.clone()), (b, later.clone())],
            "each copy is the node's own, and one its entry doesn't describe is left out"
        );
        assert!(unheard.is_empty());
        // Merged as an index walk's pages would merge them: one listing, two
        // nodes, each with its own first_seen.
        let groups = ant_listings::merge_copies(copies);
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[0].peers(),
            [(a, first.first_seen), (b, later.first_seen)]
        );
    }

    #[test]
    fn a_cycle_that_decides_nothing_again_changes_nothing() {
        let x: XorName = [0x3d; 32];
        let (_dir, mut publisher) = publisher();
        let mut listing = ListingsIndex::default();
        listing.listings.push(checked(x));
        publish_read(&mut publisher, &listing, None, AT);
        let key = publisher.keys().unwrap()[0];
        let chain = idle_chain();

        // An entry whose address the cycle didn't look at stays as it is.
        let quiet = ListingsIndex::decided(&[], Vec::new(), HashSet::new(), &chain);
        let mut tally = Tally::default();
        let publication = read_publication(
            &publisher,
            &quiet,
            &BTreeMap::new(),
            &[],
            |_| None,
            AT + 60,
            &mut tally,
        )
        .unwrap();
        assert_eq!(
            publication,
            Publication {
                at: AT + 60,
                ..Publication::default()
            }
        );
        assert_eq!((tally.put, tally.removed, tally.carried), (0, 0, 0));

        // One the cycle looked at and couldn't decide is kept, carried.
        let mut tally = Tally::default();
        let publication = read_publication(
            &publisher,
            &quiet,
            &BTreeMap::new(),
            &[(key, None)],
            |_| None,
            AT + 60,
            &mut tally,
        )
        .unwrap();
        assert!(publication.changes.is_empty());
        assert_eq!(publication.support.len(), 1);
        assert!(publication.support[0].carried);
        assert_eq!(tally.carried, 1);
    }

    /// A data map of 3 chunks of `src_size` bytes, shrunk into a child map
    /// when `child`.
    fn three_chunks(src_size: usize, child: bool) -> DataMap {
        let infos = (0..3u8)
            .map(|n| self_encryption::ChunkInfo {
                index: usize::from(n),
                dst_hash: xor_name::XorName([n + 1; 32]),
                src_hash: xor_name::XorName([n + 100; 32]),
                src_size,
            })
            .collect();
        if child {
            DataMap::with_child(infos, 1)
        } else {
            DataMap::new(infos)
        }
    }

    #[test]
    fn a_shrunk_data_map_is_published_with_its_root_maps_size() {
        // A readable listing whose data map is shrunk gives no size of its
        // own: its entry takes the one its root map gives, once known.
        let x: XorName = [0x4e; 32];
        let mut shrunk = checked(x);
        shrunk.envelope = Envelope::readable(
            &three_chunks(1_024, true),
            Metadata::default(),
            shrunk.listing.flags.shown,
            true,
        )
        .unwrap();
        shrunk.listing.flags = shrunk.envelope.flags();
        assert_eq!(shrunk.envelope.file_size(), None);
        // One whose data map is withheld has no size, whatever `sizes` says.
        let y: XorName = [0x4f; 32];
        let mut index = ListingsIndex::default();
        index.listings.push(shrunk);
        index.listings.push(checked(y));
        let listed: BTreeMap<XorName, &CheckedListing> = index
            .listings
            .iter()
            .map(|checked| (checked.listing.address, checked))
            .collect();
        let (_dir, mut publisher) = publisher();
        let publish = |publisher: &mut Publisher, sizes: &HashMap<XorName, u64>, at| {
            let mut tally = Tally::default();
            let size = |address: &XorName| sizes.get(address).copied();
            let publication =
                read_publication(publisher, &index, &listed, &[], size, at, &mut tally).unwrap();
            publisher.publish(&publication).unwrap();
            let wanted: Vec<XorName> = tally
                .wanted_sizes
                .iter()
                .map(|(address, _)| *address)
                .collect();
            (tally.put, wanted)
        };
        let size = |publisher: &Publisher, address| {
            publisher
                .entry(&address)
                .unwrap()
                .unwrap()
                .entry
                .listing
                .size
        };

        // Before its root map is read, it is listed without a size, and its
        // root map is to be read; the withheld one's never is.
        assert_eq!(publish(&mut publisher, &HashMap::new(), AT), (2, vec![x]));
        assert_eq!(size(&publisher, x), None);

        // Once read, the entry changes to show it; the withheld one doesn't.
        let sizes = HashMap::from([(x, 92_000_000), (y, 5)]);
        assert_eq!(publish(&mut publisher, &sizes, AT + 60), (1, Vec::new()));
        assert_eq!(size(&publisher, x), Some(92_000_000));
        assert_eq!(size(&publisher, y), None);

        // Decided again with the size kept, nothing changes.
        assert_eq!(publish(&mut publisher, &sizes, AT + 120), (0, Vec::new()));
    }

    #[test]
    fn a_root_maps_size_is_the_sum_of_its_chunks() {
        assert_eq!(root_size(&three_chunks(1_024, false)), Some(3_072));
        // A map still shrunk isn't a root map.
        assert_eq!(root_size(&three_chunks(1_024, true)), None);
        // Sizes that overflow give none.
        assert_eq!(root_size(&three_chunks(usize::MAX, false)), None);
    }

    #[test]
    fn only_an_address_shown_gone_loses_its_row() {
        let x: XorName = [0x3d; 32];
        let (_dir, mut publisher) = publisher();
        let mut deferring = ListingsIndex::default();
        defer(&mut deferring, x, &[81_950_000, 81_950_000]);
        publish_read(&mut publisher, &deferring, None, AT);
        let rows = publisher.rejected_entries().unwrap();
        assert_eq!(rows.len(), 1);
        let chain = idle_chain();
        let changes = |index: &ListingsIndex| {
            rejected_changes(
                rows.clone(),
                index,
                &BTreeMap::new(),
                &HashSet::new(),
                AT + 60,
                &mut Tally::default(),
            )
        };
        // A cycle that didn't look at it, or looked and kept it, leaves it.
        let quiet = ListingsIndex::decided(&[], Vec::new(), HashSet::new(), &chain);
        assert!(changes(&quiet).is_empty());
        // Once every node nearest it is shown to serve none, it goes.
        let gone = ListingsIndex::decided(&[], Vec::new(), HashSet::from([x]), &chain);
        assert_eq!(
            gone.carry(&x, &rows[0].listing.key().unwrap()),
            Carry::NoLongerServed
        );
        assert_eq!(changes(&gone), [RejectedChange::Clear(x)]);
    }

    /// A listing at `address`, as a node would store it.
    fn stored(address: XorName) -> Listing {
        showing_block(address, 81_950_000)
    }

    /// How a node answers a `GetRequest` in [`fetch_round`].
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Answers {
        /// With its listing, after 250 ms.
        Honestly,
        /// Never: the request times out after 10 s.
        Never,
        /// Never, and the request never ends.
        Hangs,
        /// With a listing its entry describes, but of `n` bytes of quote.
        Oversized(usize),
    }

    /// What a round of fetching gave ([`fetch_round`]).
    struct Round {
        /// The listings fetched, as kept.
        fetched: Vec<(ListingId, Vec<u8>)>,
        /// The holders that failed to hand one over.
        refused: Vec<(PeerId, ListingId)>,
        /// The requests each node was sent.
        asked: HashMap<PeerId, usize>,
        /// The most requests in flight to one node at once.
        most_in_flight: usize,
        /// How long it took.
        took: Duration,
    }

    /// One cycle's fetching of what `work` wants, but what `failed` refused
    /// lately and what is `kept`, as [`Producer::fetch_for`] fetches: the
    /// digests a quorum names first, each node within `allowance` requests,
    /// answering as `answers` says (honestly if it says nothing).
    async fn fetch_round(
        work: &[Work],
        failed: &HashMap<(PeerId, ListingId), u64>,
        kept: &HashSet<ListingId>,
        answers: &HashMap<PeerId, Answers>,
        allowance: impl Fn(&PeerId) -> usize + Copy,
        budget: &FetchBudget,
        deadline: Instant,
    ) -> Round {
        let failed = |peer: &PeerId, key: &ListingId| failed.contains_key(&(*peer, *key));
        let kept = |key: &ListingId| kept.contains(key);
        let mut wanted = fetches_wanted(work, true, failed, kept);
        wanted.extend(fetches_wanted(work, false, failed, kept));
        let started = Instant::now();
        let asked: Mutex<HashMap<PeerId, usize>> = Mutex::new(HashMap::new());
        let in_flight: Mutex<(HashMap<PeerId, usize>, usize)> = Mutex::new((HashMap::new(), 0));
        let (asked_ref, in_flight_ref) = (&asked, &in_flight);
        let take = |peer: &PeerId, quorum: bool| budget.take(peer, quorum, || allowance(peer));
        let unanswered = |peer: &PeerId| budget.exhaust(peer);
        let ask = move |peer: PeerId, address: XorName| async move {
            *asked_ref.lock().unwrap().entry(peer).or_default() += 1;
            {
                let mut flight = in_flight_ref.lock().unwrap();
                let now = {
                    let count = flight.0.entry(peer).or_default();
                    *count += 1;
                    *count
                };
                flight.1 = flight.1.max(now);
            }
            let answer = match answers.get(&peer).copied().unwrap_or(Answers::Honestly) {
                Answers::Honestly => {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    Some(Some(stored(address)))
                }
                Answers::Never => {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    None
                }
                Answers::Hangs => std::future::pending().await,
                Answers::Oversized(bytes) => Some(Some(with_quote(address, bytes))),
            };
            *in_flight_ref.lock().unwrap().0.entry(peer).or_default() -= 1;
            answer
        };
        let mut fetched = Vec::new();
        let mut refused = Vec::new();
        fetch_wanted(
            wanted.into_iter(),
            take,
            unanswered,
            deadline,
            ask,
            |key, listing, failed| {
                fetched.extend(listing.map(|listing| (key, listing)));
                refused.extend(failed.into_iter().map(|peer| (peer, key)));
            },
        )
        .await;
        let most_in_flight = in_flight.lock().unwrap().1;
        Round {
            fetched,
            refused,
            asked: asked.into_inner().unwrap(),
            most_in_flight,
            took: started.elapsed(),
        }
    }

    /// A listing at `address` whose entry describes it, as [`stored`], but
    /// showing a quote of `bytes` bytes.
    fn with_quote(address: XorName, bytes: usize) -> Listing {
        let mut listing = stored(address);
        listing.flags.shown = listing.flags.shown.with(PaymentField::Quote);
        listing.payment.quote = Some(vec![7; bytes]);
        listing
    }

    /// An address from `n`, spread over the address space.
    fn spread(n: u32) -> XorName {
        let mut address = [0x80; 32];
        address[..4].copy_from_slice(&n.to_be_bytes());
        address
    }

    #[tokio::test(start_paused = true)]
    async fn a_node_that_never_answers_costs_one_request_a_cycle() {
        let faulty = PeerId::from_bytes([1; 32]);
        let x: XorName = [0x3d; 32];
        // The faulty node advertises 2,048 made-up addresses, each its own;
        // five honest nodes serve x.
        let mut work: Vec<Work> = (0..2_048u32)
            .map(|n| {
                let address = spread(n);
                (
                    address,
                    Vec::new(),
                    vec![(faulty, DigestEntry::new(&stored(address)))],
                )
            })
            .collect();
        let entry = DigestEntry::new(&stored(x));
        let copies: Vec<(PeerId, DigestEntry)> = (2..=6u8)
            .map(|n| (PeerId::from_bytes([n; 32]), entry))
            .collect();
        work.push((x, Vec::new(), copies));
        // The listing a quorum names is fetched first.
        let wanted = fetches_wanted(&work, true, |_, _| false, |_| false);
        assert_eq!(wanted.len(), 1);
        assert_eq!(wanted[0].0, (x, entry.digest));

        let answers = HashMap::from([(faulty, Answers::Never)]);
        let mut failed: HashMap<(PeerId, ListingId), u64> = HashMap::new();
        let mut budget = FetchBudget::default();
        let deadline = Instant::now() + CYCLE;
        let round = fetch_round(
            &work,
            &failed,
            &HashSet::new(),
            &answers,
            |_| 8,
            &budget,
            deadline,
        )
        .await;
        assert_eq!(round.fetched.len(), 1, "x is fetched");
        assert_eq!(round.fetched[0].0, (x, entry.digest));
        // One request, unanswered: nothing more this cycle, whatever it
        // advertises and whatever its allowance.
        assert_eq!(round.asked.get(&faulty), Some(&1));
        assert_eq!(round.refused.len(), 1);
        assert!(round.took <= Duration::from_secs(11), "{:?}", round.took);
        failed.extend(round.refused.into_iter().map(|failure| (failure, u64::MAX)));

        // The next cycle: the one it failed isn't asked again, and it gets
        // one request more.
        budget.clear();
        let kept = HashSet::from([(x, entry.digest)]);
        let deadline = Instant::now() + CYCLE;
        let round = fetch_round(&work, &failed, &kept, &answers, |_| 8, &budget, deadline).await;
        assert_eq!(round.asked.get(&faulty), Some(&1));
        assert!(round
            .refused
            .iter()
            .all(|failure| !failed.contains_key(failure)));
        assert!(round.took <= Duration::from_secs(11), "{:?}", round.took);
    }

    #[tokio::test(start_paused = true)]
    async fn made_up_entries_never_hold_back_a_listing_a_quorum_serves() {
        // At 30,000 addresses, six honest nodes serve the listing they hold
        // (fetched before), and a faulty node, with an allowance of 438
        // requests a cycle, advertises a made-up one it never hands over.
        // After them all in address order, seven honest nodes serve a new
        // listing.
        let faulty = PeerId::from_bytes([1; 32]);
        let honest: Vec<PeerId> = (2..=8u8).map(|n| PeerId::from_bytes([n; 32])).collect();
        let mut kept: HashSet<ListingId> = HashSet::new();
        let mut work: Vec<Work> = (0..30_000u32)
            .map(|n| {
                let address = spread(n);
                let entry = DigestEntry::new(&stored(address));
                kept.insert((address, entry.digest));
                let mut copies: Vec<(PeerId, DigestEntry)> =
                    honest[..6].iter().map(|peer| (*peer, entry)).collect();
                let made_up = DigestEntry::new(&with_quote(address, 1));
                copies.push((faulty, made_up));
                (address, Vec::new(), copies)
            })
            .collect();
        let new: XorName = [0xff; 32];
        let entry = DigestEntry::new(&stored(new));
        work.push((
            new,
            Vec::new(),
            honest.iter().map(|peer| (*peer, entry)).collect(),
        ));
        let answers = HashMap::from([(faulty, Answers::Never)]);
        let allowance = move |peer: &PeerId| if *peer == faulty { 438 } else { 8 };
        let mut budget = FetchBudget::default();
        let mut failed: HashMap<(PeerId, ListingId), u64> = HashMap::new();
        for cycle in 0..5 {
            budget.clear();
            let deadline = Instant::now() + CYCLE;
            let round = fetch_round(
                &work, &failed, &kept, &answers, allowance, &budget, deadline,
            )
            .await;
            assert!(
                round
                    .fetched
                    .iter()
                    .any(|(key, _)| *key == (new, entry.digest)),
                "the new listing is fetched in cycle {cycle}"
            );
            assert_eq!(round.asked.get(&faulty), Some(&1), "cycle {cycle}");
            assert!(round.took <= Duration::from_secs(11), "{:?}", round.took);
            failed.extend(round.refused.into_iter().map(|failure| (failure, u64::MAX)));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_node_has_one_request_in_flight_at_a_time() {
        // 300 new listings at consecutive addresses, with the same nearest
        // holder first, and six others each: as at a start without the
        // listings kept.
        let first = PeerId::from_bytes([1; 32]);
        let others: Vec<PeerId> = (2..=7u8).map(|n| PeerId::from_bytes([n; 32])).collect();
        let work: Vec<Work> = (0..300u32)
            .map(|n| {
                let address = spread(n);
                let entry = DigestEntry::new(&stored(address));
                let mut copies = vec![(first, entry)];
                copies.extend(others.iter().map(|peer| (*peer, entry)));
                (address, Vec::new(), copies)
            })
            .collect();
        let budget = FetchBudget::default();
        let deadline = Instant::now() + CYCLE;
        let round = fetch_round(
            &work,
            &HashMap::new(),
            &HashSet::new(),
            &HashMap::new(),
            |_| 438,
            &budget,
            deadline,
        )
        .await;
        assert_eq!(round.fetched.len(), 300);
        assert_eq!(round.most_in_flight, 1);
        // A busy first holder doesn't hold the others up: all seven share
        // the requests.
        assert_eq!(round.asked.len(), 7);
        assert!(round.took < CYCLE, "{:?}", round.took);
    }

    #[tokio::test(start_paused = true)]
    async fn fetching_ends_at_its_deadline() {
        let (faulty, honest) = (PeerId::from_bytes([1; 32]), PeerId::from_bytes([2; 32]));
        let (x, y): (XorName, XorName) = ([0x3d; 32], [0x7e; 32]);
        let work: Vec<Work> = vec![
            (x, Vec::new(), vec![(honest, DigestEntry::new(&stored(x)))]),
            (y, Vec::new(), vec![(faulty, DigestEntry::new(&stored(y)))]),
        ];
        let answers = HashMap::from([(faulty, Answers::Hangs)]);
        let budget = FetchBudget::default();
        let deadline = Instant::now() + CYCLE;
        let round = fetch_round(
            &work,
            &HashMap::new(),
            &HashSet::new(),
            &answers,
            |_| 8,
            &budget,
            deadline,
        )
        .await;
        assert_eq!(round.fetched.len(), 1);
        assert_eq!(round.asked.get(&faulty), Some(&1));
        // Cut short, not refused: it is asked again next time.
        assert!(round.refused.is_empty());
        assert_eq!(round.took, CYCLE);
    }

    #[tokio::test(start_paused = true)]
    async fn an_oversized_listing_is_never_kept() {
        // A node hands over a listing its entry describes and that passes
        // every check a GetResponse gets, but with 4.5 MB of quote: under the
        // wire limit, over a page's share of it.
        let x: XorName = [0x3d; 32];
        let big = with_quote(x, 4_500_000);
        assert!(big.validate().is_ok());
        assert_eq!(
            ant_listings::check_get_response(&x, Some(big.clone())),
            Ok(Some(big.clone()))
        );
        assert_eq!(kept_bytes(&big), None);
        let (faulty, honest) = (PeerId::from_bytes([1; 32]), PeerId::from_bytes([2; 32]));
        let entry = DigestEntry::new(&big);
        let work: Vec<Work> = vec![(x, Vec::new(), vec![(faulty, entry), (honest, entry)])];
        let answers = HashMap::from([
            (faulty, Answers::Oversized(4_500_000)),
            (honest, Answers::Oversized(4_500_000)),
        ]);
        let budget = FetchBudget::default();
        let round = fetch_round(
            &work,
            &HashMap::new(),
            &HashSet::new(),
            &answers,
            |_| 8,
            &budget,
            Instant::now() + CYCLE,
        )
        .await;
        // Neither is kept: both failed to hand over the listing behind
        // their entry, and their copies can't be had.
        assert!(round.fetched.is_empty());
        assert_eq!(round.refused.len(), 2);
        // One kept by a version without the bound isn't read back.
        let message = ListingsMessage {
            request_id: 0,
            body: ListingsBody::GetResponse {
                listing: Some(Listing {
                    first_seen: None,
                    ..big
                }),
            },
        };
        assert_eq!(kept_listing(&message.encode().unwrap()), None);
        // A listing of the largest size the format allows is kept.
        let largest = with_quote(x, 9_000);
        let bytes = kept_bytes(&largest).unwrap();
        assert!(bytes.len() <= MAX_LISTING_BYTES);
        assert_eq!(
            kept_listing(&bytes),
            Some(Listing {
                first_seen: None,
                ..largest
            })
        );
    }

    #[test]
    fn a_nodes_allowance_of_requests_is_kept_for_the_cycle() {
        let peer = PeerId::from_bytes([1; 32]);
        let mut budget = FetchBudget::default();
        assert!((0..8).all(|_| budget.take(&peer, false, || 8)));
        assert!(!budget.take(&peer, false, || 8));
        // A listing a quorum names takes from no allowance.
        assert!(budget.take(&peer, true, || 8));
        budget.clear();
        assert!(budget.take(&peer, false, || 8));
        // Once it leaves one unanswered, nothing more this cycle.
        budget.exhaust(&peer);
        assert!(!budget.take(&peer, true, || 8));
        assert!(!budget.take(&peer, false, || 8));
        budget.clear();
        assert!(budget.take(&peer, true, || 8));
    }

    #[tokio::test(start_paused = true)]
    async fn a_burst_of_new_listings_a_quorum_serves_is_fetched_in_one_cycle() {
        // 400 new listings, each on its 7 nearest of 20 honest nodes, more
        // than the nodes' allowances (9 requests each) hold together.
        let peers: Vec<PeerId> = (1..=20u8).map(|n| PeerId::from_bytes([n; 32])).collect();
        let work: Vec<Work> = (0..400u32)
            .map(|n| {
                let address = spread(n);
                let entry = DigestEntry::new(&stored(address));
                let copies = (0..NEAREST_NODES)
                    .map(|k| (peers[(n as usize + k) % peers.len()], entry))
                    .collect();
                (address, Vec::new(), copies)
            })
            .collect();
        let budget = FetchBudget::default();
        let round = fetch_round(
            &work,
            &HashMap::new(),
            &HashSet::new(),
            &HashMap::new(),
            |_| 9,
            &budget,
            Instant::now() + CYCLE,
        )
        .await;
        assert_eq!(round.fetched.len(), 400);
        assert!(round.refused.is_empty());
        assert_eq!(round.most_in_flight, 1);
        assert!(round.took < CYCLE, "{:?}", round.took);
    }

    #[tokio::test]
    async fn a_publication_waits_until_the_second_of_the_last_is_out() {
        let second = unix_now();
        wait_past(second).await;
        assert!(unix_now() > second);
        // A second already out isn't waited for.
        let started = std::time::Instant::now();
        wait_past(second.saturating_sub(10)).await;
        assert!(started.elapsed() < Duration::from_millis(100));
        // Nor is one the clock is behind, as after it was set back an hour:
        // nothing waits for it to catch up.
        let started = std::time::Instant::now();
        wait_past(unix_now() + 3_600).await;
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    /// A producer keeping its state in `dir`, whose client's node never
    /// started and whose payment RPC is a closed port: anything it asked of
    /// the network or the chain would fail. Its chain knows the block the
    /// payment vault was deployed in ([`VAULT_BLOCK`]). Also returns the
    /// node, to keep it alive.
    async fn offline_producer(dir: &Path) -> (Producer, crate::data::Network) {
        let closed = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };
        let node = crate::data::Network::unstarted(&[], true, false)
            .await
            .unwrap();
        let client = Client::from_node(Arc::clone(node.node()), Default::default())
            .with_evm_network(crate::data::client::native_payment::test_plans::network(
                closed,
            ));
        let mut producer = Producer::open(&dir.join("state"), &dir.join("v1"), client).unwrap();
        producer.publisher.set_flush(false);
        producer.chain = ListingChain::with_rpc(format!("http://127.0.0.1:{closed}"), [0x22; 20])
            .unwrap()
            .with_vault_deployment_block(VAULT_BLOCK)
            .with_store(&producer.store)
            .unwrap();
        (producer, node)
    }

    /// `count` census nodes, spread over the address space.
    fn census_nodes(producer: &mut Producer, count: u8) -> Vec<PeerId> {
        let peers: Vec<PeerId> = (0..count)
            .map(|n| PeerId::from_bytes([n.wrapping_mul(255 / count).wrapping_add(1); 32]))
            .collect();
        for peer in &peers {
            producer.census.admit(*peer, Vec::new(), AT);
        }
        peers
    }

    /// Serve `listings` from `holders` of each one's nearest nodes, as their
    /// mirrors show it, with the full listings fetched and kept.
    fn serve(producer: &mut Producer, listings: &[Listing], holders: usize) {
        let mut mirrors: BTreeMap<PeerId, Vec<DigestEntry>> = BTreeMap::new();
        let mut txn = producer.store.env().write_txn().unwrap();
        for listing in listings {
            let entry = DigestEntry::new(listing);
            for peer in producer
                .census
                .nearest(&listing.address, NEAREST_NODES)
                .into_iter()
                .take(holders)
            {
                mirrors.entry(peer).or_default().push(entry);
            }
            let kept = Listing {
                first_seen: None,
                ..listing.clone()
            };
            producer
                .listings
                .put(
                    &mut txn,
                    &listing_key(&listing.address, &entry.digest),
                    &kept_bytes(&kept).unwrap(),
                )
                .unwrap();
        }
        txn.commit().unwrap();
        for peer in producer
            .census
            .nodes()
            .map(|node| node.peer)
            .collect::<Vec<_>>()
        {
            let mut entries = mirrors.remove(&peer).unwrap_or_default();
            entries.sort_by_key(|entry| entry.address);
            producer.feeds.seed(peer, AddressRange::ALL, &entries);
        }
    }

    /// An address from `n`.
    fn numbered(n: u32) -> XorName {
        ant_protocol::compute_address(&n.to_be_bytes())
    }

    #[tokio::test]
    async fn every_address_is_decided_a_batch_at_a_time() {
        // More addresses than three batches, each served by 2 of its 7
        // nearest nodes: too few to decide, so each is left for later, shown
        // in rejected.json with its copies.
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        census_nodes(&mut producer, 8);
        let count = 3 * DECIDE_BATCH as u32 + 10;
        let listings: Vec<Listing> = (0..count)
            .map(|n| showing_block(numbered(n), 81_950_000))
            .collect();
        serve(&mut producer, &listings, 2);

        let mut tally = Tally::default();
        let mut drops = DropCheck {
            checked: false,
            deadline: Instant::now() + CYCLE,
        };
        let (decided, staged) = producer
            .decide_all(Source::All, AT, Some(&mut drops), false, &mut tally)
            .await
            .unwrap();
        assert_eq!(decided, u64::from(count));
        assert!(staged);
        assert_eq!(
            tally.groups.get("below_quorum"),
            Some(&(u64::from(count), AT))
        );
        // Each batch let go of what it held: nothing is left in the tally
        // but its counts.
        assert!(tally.deferred.is_empty() && tally.for_good.is_empty());
        producer.write_spaced(AT, &Status::default()).await.unwrap();
        let rows = producer.publisher.rejected_entries().unwrap();
        assert_eq!(rows.len(), count as usize);
        assert!(rows.iter().all(|row| row.again && row.copies.len() == 2));
        // Each is to be decided again next cycle, whatever changes.
        let again = {
            let txn = producer.store.env().read_txn().unwrap();
            tagged_after(producer.known, &txn, AGAIN_TAG, None, usize::MAX).unwrap()
        };
        assert_eq!(again.len(), count as usize);
        assert_eq!(producer.feeds.pending_count().unwrap(), 0);

        // The next cycle decides them again, and finds nothing to change.
        let mut tally = Tally::default();
        let (decided, staged) = producer
            .decide_all(
                Source::Pending { again: true },
                AT + 60,
                None,
                false,
                &mut tally,
            )
            .await
            .unwrap();
        assert_eq!(decided, u64::from(count));
        assert!(!staged);
        // A restart forgets what this process knew of them, and decides
        // every address again.
        drop(producer);
        let (producer, _node) = offline_producer(dir.path()).await;
        let txn = producer.store.env().read_txn().unwrap();
        assert!(producer.known.is_empty(&txn).unwrap());
    }

    #[tokio::test]
    async fn the_addresses_of_every_source_are_read_once_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        census_nodes(&mut producer, 8);
        // Held by a mirror, published, with a row in rejected.json, deferred,
        // pending, and to decide again: some in more than one.
        let held: Vec<XorName> = (0..300).map(numbered).collect();
        let listings: Vec<Listing> = held
            .iter()
            .map(|address| showing_block(*address, 81_950_000))
            .collect();
        serve(&mut producer, &listings, 2);
        let published: Vec<XorName> = (250..400).map(numbered).collect();
        let mut index = ListingsIndex::default();
        for address in &published {
            index.listings.push(checked(*address));
        }
        let rejected: Vec<XorName> = (380..500).map(numbered).collect();
        for address in &rejected {
            defer(&mut index, *address, &[81_950_000]);
        }
        publish_read(&mut producer.publisher, &index, None, AT);
        let deferred: Vec<XorName> = (490..520).map(numbered).collect();
        let pending: Vec<XorName> = (510..530).map(numbered).collect();
        let again: Vec<XorName> = (0..10).chain(525..540).map(numbered).collect();
        {
            let mut txn = producer.store.env().write_txn().unwrap();
            for address in &deferred {
                producer
                    .since
                    .put(&mut txn, &tagged(DEFERRED_TAG, address), &AT)
                    .unwrap();
            }
            for address in &again {
                producer
                    .known
                    .put(&mut txn, &tagged(AGAIN_TAG, address), &[])
                    .unwrap();
            }
            txn.commit().unwrap();
        }
        producer.feeds.mark_pending(&pending).unwrap();

        let read = |producer: &Producer, source: Source| {
            let mut all: Vec<(XorName, bool)> = Vec::new();
            let mut after: Option<XorName> = None;
            loop {
                let batch = producer.next_batch(source, after.as_ref()).unwrap();
                assert!(batch.len() <= DECIDE_BATCH);
                all.extend(batch.iter().copied());
                match batch.last() {
                    Some((last, _)) if batch.len() == DECIDE_BATCH => after = Some(*last),
                    _ => return all,
                }
            }
        };
        let explained: BTreeSet<XorName> = pending.iter().chain(&again).copied().collect();
        let mut every: BTreeSet<XorName> = explained.clone();
        for addresses in [&held, &published, &rejected, &deferred] {
            every.extend(addresses.iter().copied());
        }
        let all = read(&producer, Source::All);
        assert_eq!(
            all.iter().map(|(address, _)| *address).collect::<Vec<_>>(),
            every.iter().copied().collect::<Vec<_>>()
        );
        for (address, why) in &all {
            assert_eq!(*why, explained.contains(address));
        }
        let changed = read(&producer, Source::Pending { again: true });
        assert_eq!(
            changed
                .iter()
                .map(|(address, _)| *address)
                .collect::<Vec<_>>(),
            explained.iter().copied().collect::<Vec<_>>()
        );
        let pushed = read(&producer, Source::Pending { again: false });
        let mut pending_sorted = pending.clone();
        pending_sorted.sort_unstable();
        assert_eq!(
            pushed
                .iter()
                .map(|(address, _)| *address)
                .collect::<Vec<_>>(),
            pending_sorted
        );
    }

    #[tokio::test]
    async fn a_cycle_removes_a_listed_entry_that_shows_a_payment_before_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        census_nodes(&mut producer, 8);
        let x = numbered(7);
        // An entry showing a block before the vault was deployed, as an
        // earlier index may have listed it; two of its nearest nodes serve
        // it.
        let mut listed = ListingsIndex::default();
        listed.listings.push(checked_at(x, 80_204_042));
        publish_read(&mut producer.publisher, &listed, None, AT);
        serve(&mut producer, &[showing_block(x, 80_204_042)], 2);

        let mut tally = Tally::default();
        producer
            .decide_all(Source::All, AT + 60, None, false, &mut tally)
            .await
            .unwrap();
        producer
            .write_spaced(AT + 60, &Status::default())
            .await
            .unwrap();
        assert_eq!((tally.removed, tally.carried), (1, 0));
        assert!(producer.publisher.entry(&x).unwrap().is_none());
        let rows = producer.publisher.rejected_entries().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].again);
        assert_eq!(rows[0].problem, PAID_BEFORE_VAULT);
        // Its decision stands, as status.json counts it.
        assert_eq!(producer.standing, 1);
        assert!(tally.groups.is_empty());
    }

    /// A listed file at `address` whose data map is shrunk, as a read lists
    /// it.
    fn shrunk_listing(address: XorName) -> CheckedListing {
        let mut shrunk = checked(address);
        shrunk.envelope = Envelope::readable(
            &three_chunks(1_024, true),
            Metadata::default(),
            shrunk.listing.flags.shown,
            true,
        )
        .unwrap();
        shrunk.listing.flags = shrunk.envelope.flags();
        shrunk
    }

    impl Decided {
        /// What deciding a batch gives when it decides `index`, for tests of
        /// publishing.
        fn of(index: ListingsIndex) -> Self {
            Self {
                addresses: index
                    .listings
                    .iter()
                    .map(|checked| checked.listing.address)
                    .collect(),
                index,
                unlisted: Vec::new(),
                known: Vec::new(),
                holders: Vec::new(),
                forget: Vec::new(),
                settle: Vec::new(),
                waiting: Vec::new(),
                unreadable: Vec::new(),
                future: Vec::new(),
                later: Vec::new(),
            }
        }
    }

    #[tokio::test]
    async fn a_size_read_is_filled_in_to_its_entry() {
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        let x: XorName = [0x4e; 32];
        let mut index = ListingsIndex::default();
        index.listings.push(shrunk_listing(x));
        let listed: BTreeMap<XorName, &CheckedListing> = index
            .listings
            .iter()
            .map(|checked| (checked.listing.address, checked))
            .collect();
        let mut tally = Tally::default();
        let publication = read_publication(
            &producer.publisher,
            &index,
            &listed,
            &[],
            |_| None,
            AT,
            &mut tally,
        )
        .unwrap();
        producer.publisher.publish(&publication).unwrap();
        assert_eq!(tally.wanted_sizes.len(), 1);
        let published = producer.publisher.entry(&x).unwrap().unwrap();
        assert_eq!(published.entry.listing.size, None);
        let seq = producer.publisher.seq();

        // Its root map is to be read: a read is marked before it begins, so
        // one that a stop cuts short isn't begun again at once.
        let wanted = |producer: &Producer, address: &XorName| {
            let txn = producer.store.env().read_txn().unwrap();
            producer
                .size_wanted
                .get(&txn, address)
                .unwrap()
                .map(|value| u64::from_be_bytes(value[..8].try_into().unwrap()))
        };
        let mut index = ListingsIndex::default();
        index.listings.push(shrunk_listing(x));
        {
            let mut decided = Decided::of(index);
            let mut tally = Tally::default();
            producer.publication(&mut decided, AT, &mut tally).unwrap();
        }
        assert_eq!(wanted(&producer, &x), Some(0));
        let before = unix_now();
        producer.start_sizes().unwrap();
        assert!(producer.size_job.is_some());
        // Stopped before it read anything.
        producer.size_job = None;
        let next = wanted(&producer, &x).unwrap();
        assert!(next >= before + RETRY_INTERVAL.as_secs(), "{next}");
        producer.start_sizes().unwrap();
        assert!(producer.size_job.is_none(), "nothing is due yet");
        // A read that couldn't be done leaves it so.
        producer.last_status = Some(Status::default());
        producer
            .take_sizes(vec![(x, SizeRead::Later)])
            .await
            .unwrap();
        assert_eq!(wanted(&producer, &x), Some(next));
        assert_eq!(producer.publisher.seq(), seq);

        // Read: the entry is put again with it, decided when it was.
        producer
            .take_sizes(vec![(x, SizeRead::Sized(92_000_000))])
            .await
            .unwrap();
        let filled = producer.publisher.entry(&x).unwrap().unwrap();
        assert_eq!(filled.entry.listing.size, Some(92_000_000));
        assert_eq!(filled.entry.decided_at, published.entry.decided_at);
        assert_eq!(producer.publisher.seq(), seq + 1);
        {
            let txn = producer.store.env().read_txn().unwrap();
            assert_eq!(producer.sizes.get(&txn, &x).unwrap(), Some(92_000_000));
        }
        assert_eq!(wanted(&producer, &x), None);

        // A map that can never give a size is never read again, though its
        // address is decided again, and its entry keeps none.
        let y: XorName = [0x4f; 32];
        let mut index = ListingsIndex::default();
        index.listings.push(shrunk_listing(y));
        let mut decided = Decided::of(index.clone());
        producer
            .publication(&mut decided, AT, &mut Tally::default())
            .unwrap();
        producer
            .take_sizes(vec![(y, SizeRead::Never)])
            .await
            .unwrap();
        assert_eq!(wanted(&producer, &y), Some(u64::MAX));
        let mut decided = Decided::of(index);
        producer
            .publication(&mut decided, AT + 60, &mut Tally::default())
            .unwrap();
        assert_eq!(wanted(&producer, &y), Some(u64::MAX));
        producer.start_sizes().unwrap();
        assert!(producer.size_job.is_none());
    }

    // Producers over fake nodes: two side by side, one deciding what changed
    // each cycle as `Producer::cycle` does after its first, one deciding
    // every address each cycle, as an index read does, from the same inputs.
    // What they publish differently is an address the first decided
    // differently, or later.

    use crate::data::client::listings_feeds::tests::{Behaviour, FakeNet, FakeNode};

    /// An envelope withholding its data map and showing no payment field,
    /// in the index: its listings are reported, with no chain call.
    fn hidden_envelope(seed: u8) -> Envelope {
        Envelope::withheld_hash(
            [seed; SALTED_HASH_LEN],
            Metadata::default(),
            ShownFields::NONE,
            true,
        )
        .unwrap()
    }

    /// The listing of `envelope` first stored in the hour of `first_seen`;
    /// with `name`, one that doesn't match its envelope.
    fn hidden_listing(envelope: &Envelope, first_seen: u64, name: Option<&str>) -> Listing {
        Listing {
            address: envelope.address(),
            flags: envelope.flags(),
            metadata: Metadata {
                name: name.map(str::to_string),
                ..envelope.metadata().clone()
            },
            size: None,
            payment: ListingPayment::default(),
            first_seen: Some(first_seen - first_seen % 3_600),
        }
    }

    /// Keep `listing`'s full listing, as fetching it does.
    fn keep_listing(producer: &Producer, listing: &Listing) {
        let entry = DigestEntry::new(listing);
        let mut txn = producer.store.env().write_txn().unwrap();
        producer
            .listings
            .put(
                &mut txn,
                &listing_key(&listing.address, &entry.digest),
                &kept_bytes(listing).unwrap(),
            )
            .unwrap();
        txn.commit().unwrap();
    }

    /// One cycle, as `Producer::cycle` runs it but for the census's upkeep
    /// and fetching (the full listings are kept already): poll the fake
    /// nodes, note who answered, make pending the addresses whose nearest
    /// nodes changed, then decide `source` with drops checked. Returns what
    /// the cycle counted.
    async fn fake_cycle(producer: &mut Producer, net: &FakeNet, now: u64, source: Source) -> Tally {
        producer.cycles += 1;
        let nodes: Vec<FeedNode> = producer
            .census
            .nodes()
            .map(|node| FeedNode {
                peer: node.peer,
                range: producer.census.leaf_of(node.peer.as_bytes()),
                feed: true,
                want_peers: false,
            })
            .collect();
        let deadline = Instant::now() + CYCLE;
        producer
            .feeds
            .poll(net, &producer.census, &nodes, now, deadline, None)
            .await
            .unwrap();
        let answered = producer.note_answers(now, &BTreeSet::new()).await;
        assert!(producer.census.guard_ok(answered), "guard");
        let change = producer.census.take_changes();
        if !change.is_empty() && source != Source::All {
            producer.mark_moved().unwrap();
        }
        let mut tally = Tally::default();
        let mut drops = DropCheck {
            checked: false,
            deadline: Instant::now() + CYCLE,
        };
        producer
            .decide_all(source, now, Some(&mut drops), false, &mut tally)
            .await
            .unwrap();
        tally
    }

    /// What a producer published, `decided_at` aside, and what its latest
    /// cycle counted for `status.json`.
    #[derive(Debug, PartialEq)]
    struct Shown {
        entries: BTreeMap<String, (ListingFields, CheckLevel)>,
        support: BTreeMap<String, Support>,
        rejected: BTreeMap<String, RejectedEntry>,
        standing: u64,
        deferred: BTreeMap<&'static str, u64>,
        below_full: u64,
    }

    fn shown(producer: &Producer, tally: &Tally) -> Shown {
        let mut entries = BTreeMap::new();
        let mut support = BTreeMap::new();
        for key in producer.publisher.keys().unwrap() {
            let entry = producer.publisher.entry(&key.address).unwrap().unwrap();
            entries.insert(
                hex::encode(key.address),
                (entry.entry.listing.clone(), entry.entry.check),
            );
            if let Some(row) = producer.publisher.support(&key.address).unwrap() {
                support.insert(hex::encode(key.address), row);
            }
        }
        let rejected = producer
            .publisher
            .rejected_entries()
            .unwrap()
            .into_iter()
            .map(|mut row| {
                row.decided_at = 0;
                (row.listing.address.clone(), row)
            })
            .collect();
        let deferred = tally
            .groups
            .iter()
            .map(|(reason, (count, _))| (*reason, *count))
            .collect();
        let below_full = {
            let txn = producer.store.env().read_txn().unwrap();
            producer
                .since
                .prefix_iter(&txn, &[BELOW_FULL_TAG])
                .unwrap()
                .count() as u64
        };
        Shown {
            entries,
            support,
            rejected,
            standing: producer.standing,
            deferred,
            below_full,
        }
    }

    /// Two producers over the same census of `count` nodes, their requests
    /// routed: one to decide what changed, one every address.
    async fn producer_pair(
        dirs: &(tempfile::TempDir, tempfile::TempDir),
        count: u8,
    ) -> (
        (Producer, crate::data::Network),
        (Producer, crate::data::Network),
        Vec<PeerId>,
    ) {
        let (mut changed, node_changed) = offline_producer(dirs.0.path()).await;
        let (mut every, node_every) = offline_producer(dirs.1.path()).await;
        let peers = census_nodes(&mut changed, count);
        census_nodes(&mut every, count);
        changed.start_requests();
        every.start_requests();
        ((changed, node_changed), (every, node_every), peers)
    }

    #[tokio::test]
    async fn a_nearest_node_serving_nothing_there_going_silent_is_decided_as_a_read_decides_it() {
        // An address no listing of which has a quorum of its nearest nodes:
        // 3 of them serve one listing, 1 another (not matching the
        // envelope), and 3 serve nothing. Deciding it rests on those 3 having
        // been heard: once one of them stops answering, a read leaves it to
        // try again, and so must the producer that decides what changed.
        let now = unix_now();
        let old = now - 10 * 3_600;
        let dirs = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let ((mut changed, _a), (mut every, _b), peers) = producer_pair(&dirs, 8).await;
        let envelope = hidden_envelope(0x61);
        let a = envelope.address();
        let nearest = changed.census.nearest(&a, NEAREST_NODES);
        let one = hidden_listing(&envelope, old, None);
        let other = hidden_listing(&envelope, old, Some("other.txt"));
        // A control: every one of its nearest nodes serves its listing.
        let envelope_b = hidden_envelope(0x62);
        let b = envelope_b.address();
        let listing_b = hidden_listing(&envelope_b, old, None);
        for producer in [&changed, &every] {
            producer.chain.keep_envelope(&a, &envelope.to_bytes());
            producer.chain.keep_envelope(&b, &envelope_b.to_bytes());
            keep_listing(producer, &one);
            keep_listing(producer, &other);
            keep_listing(producer, &listing_b);
        }
        let mut served: BTreeMap<PeerId, Vec<DigestEntry>> = BTreeMap::new();
        for peer in &nearest[..3] {
            served
                .entry(*peer)
                .or_default()
                .push(DigestEntry::new(&one));
        }
        served
            .entry(nearest[3])
            .or_default()
            .push(DigestEntry::new(&other));
        for peer in changed.census.nearest(&b, NEAREST_NODES) {
            served
                .entry(peer)
                .or_default()
                .push(DigestEntry::new(&listing_b));
        }
        let net = FakeNet::with(
            peers
                .iter()
                .map(|peer| {
                    let entries = served.remove(peer).unwrap_or_default();
                    (*peer, FakeNode::serving(Behaviour::Honest, entries))
                })
                .collect(),
        );
        let tc = fake_cycle(&mut changed, &net, now, Source::All).await;
        let te = fake_cycle(&mut every, &net, now, Source::All).await;
        assert_eq!(shown(&changed, &tc), shown(&every, &te), "cycle 1");

        // One of A's nearest nodes that serves nothing there stops answering.
        let silent = nearest[4];
        net.node(&silent, |node| node.behaviour = Behaviour::Silent);
        let tc = fake_cycle(
            &mut changed,
            &net,
            now + 60,
            Source::Pending { again: true },
        )
        .await;
        let te = fake_cycle(&mut every, &net, now + 60, Source::All).await;
        let (sc, se) = (shown(&changed, &tc), shown(&every, &te));
        assert!(
            se.rejected[&hex::encode(a)].again,
            "a read leaves it to try again"
        );
        assert_eq!(sc, se, "cycle 2");

        // It answers again: both decide it again.
        net.node(&silent, |node| node.behaviour = Behaviour::Honest);
        let tc = fake_cycle(
            &mut changed,
            &net,
            now + 120,
            Source::Pending { again: true },
        )
        .await;
        let te = fake_cycle(&mut every, &net, now + 120, Source::All).await;
        assert_eq!(shown(&changed, &tc), shown(&every, &te), "cycle 3");
    }

    #[tokio::test]
    async fn a_listing_dated_in_the_future_is_decided_again_each_cycle() {
        // All 7 nearest nodes date a listing 3 h ahead of the producer's
        // clock: it is refused for that, and decided again every cycle, as
        // a read decides it, so it is listed once the time comes.
        let now = unix_now();
        let ahead = now + 3 * 3_600;
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        let peers = census_nodes(&mut producer, 8);
        producer.start_requests();
        let envelope = hidden_envelope(0x71);
        let a = envelope.address();
        let listing = hidden_listing(&envelope, ahead, None);
        producer.chain.keep_envelope(&a, &envelope.to_bytes());
        keep_listing(&producer, &listing);
        let nearest = producer.census.nearest(&a, NEAREST_NODES);
        let net = FakeNet::with(
            peers
                .iter()
                .map(|peer| {
                    let entries = if nearest.contains(peer) {
                        vec![DigestEntry::new(&listing)]
                    } else {
                        Vec::new()
                    };
                    (*peer, FakeNode::serving(Behaviour::Honest, entries))
                })
                .collect(),
        );
        fake_cycle(&mut producer, &net, now, Source::All).await;
        let rows = producer.publisher.rejected_entries().unwrap();
        assert!(rows.iter().any(|row| row
            .problem
            .contains(&ListingError::TimeInFuture.to_string())));
        let txn = producer.store.env().read_txn().unwrap();
        assert!(
            producer
                .known
                .get(&txn, &tagged(AGAIN_TAG, &a))
                .unwrap()
                .is_some(),
            "decided again next cycle"
        );
    }

    #[tokio::test]
    async fn an_address_is_decided_again_once_a_copy_dated_in_the_future_no_longer_is() {
        // 4 of an address's 7 nearest nodes serve its listing: 3 dated 10 h
        // ago, the 4th 3 h ahead of the producer's clock. That date is left
        // out, and the listing is listed by the others'. Once the clock
        // passes it, a read would take it in: the address is decided again
        // then, and not every cycle until.
        let now = unix_now();
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        let peers = census_nodes(&mut producer, 8);
        producer.start_requests();
        let envelope = hidden_envelope(0x72);
        let a = envelope.address();
        let early = hidden_listing(&envelope, now - 10 * 3_600, None);
        let ahead = hidden_listing(&envelope, now + 3 * 3_600, None);
        producer.chain.keep_envelope(&a, &envelope.to_bytes());
        keep_listing(&producer, &early);
        let nearest = producer.census.nearest(&a, NEAREST_NODES);
        let net = FakeNet::with(
            peers
                .iter()
                .map(|peer| {
                    let entries = match nearest.iter().position(|near| near == peer) {
                        Some(0..=2) => vec![DigestEntry::new(&early)],
                        Some(3) => vec![DigestEntry::new(&ahead)],
                        _ => Vec::new(),
                    };
                    (*peer, FakeNode::serving(Behaviour::Honest, entries))
                })
                .collect(),
        );
        fake_cycle(&mut producer, &net, now, Source::All).await;
        let listed = producer.publisher.entry(&a).unwrap().unwrap();
        assert_eq!(listed.entry.listing.first_seen, early.first_seen);
        let again = |producer: &Producer| {
            let txn = producer.store.env().read_txn().unwrap();
            producer
                .known
                .get(&txn, &tagged(AGAIN_TAG, &a))
                .unwrap()
                .is_some()
        };
        assert!(!again(&producer), "not decided again every cycle");
        assert!(!producer.feeds.is_pending(&a).unwrap());
        let due = ahead.first_seen.unwrap() - CLOCK_MARGIN;
        producer.mark_due(due - 1).unwrap();
        assert!(!producer.feeds.is_pending(&a).unwrap(), "not yet");
        producer.mark_due(due).unwrap();
        assert!(producer.feeds.is_pending(&a).unwrap(), "decided again then");
        // Once.
        producer.feeds.settle(&[a]).unwrap();
        producer.mark_due(due + 3_600).unwrap();
        assert!(!producer.feeds.is_pending(&a).unwrap());
    }

    #[tokio::test]
    async fn every_size_due_gets_its_turn_whatever_the_rows_before_it_give() {
        // Rows to read at the lowest addresses that keep failing, due again
        // each time, and one never read at a high address: the reading goes
        // on after the last row taken, so that one is taken in its turn.
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        let map = rmp_serde::to_vec(&three_chunks(1_024, true)).unwrap();
        let row = |retry_at: u64| {
            let mut value = retry_at.to_be_bytes().to_vec();
            value.extend_from_slice(&map);
            value
        };
        let fresh: XorName = [0xf0; 32];
        let failing: Vec<XorName> = (0..SIZES_PER_CYCLE as u8)
            .map(|n| {
                let mut address = [0u8; 32];
                address[1] = n;
                address
            })
            .collect();
        let fail_again = |producer: &Producer| {
            let mut txn = producer.store.env().write_txn().unwrap();
            for address in &failing {
                producer
                    .size_wanted
                    .put(&mut txn, address, &row(unix_now() - 1))
                    .unwrap();
            }
            txn.commit().unwrap();
        };
        fail_again(&producer);
        {
            let mut txn = producer.store.env().write_txn().unwrap();
            producer.size_wanted.put(&mut txn, &fresh, &row(0)).unwrap();
            txn.commit().unwrap();
        }
        let retry_at = |producer: &Producer, address: &XorName| {
            let txn = producer.store.env().read_txn().unwrap();
            let value = producer.size_wanted.get(&txn, address).unwrap().unwrap();
            u64::from_be_bytes(value[..8].try_into().unwrap())
        };
        producer.start_sizes().unwrap();
        producer.size_job = None;
        assert_eq!(retry_at(&producer, &fresh), 0, "the first rows' turn");
        fail_again(&producer);
        producer.start_sizes().unwrap();
        producer.size_job = None;
        assert!(retry_at(&producer, &fresh) > unix_now(), "its turn");
    }

    #[tokio::test]
    async fn a_drop_too_soon_after_its_time_is_neither_checked_nor_backed_off() {
        // A published entry whose time is an hour ago, that none of its
        // nearest nodes serves any more: until 2 h after its time, a node
        // that stored it may not show it yet, so its drop can't be checked.
        // Nothing is checked, and nothing backs it off: the first cycle after
        // the 2 h checks it.
        let now = unix_now();
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        let peers = census_nodes(&mut producer, 8);
        producer.start_requests();
        let x = numbered(42);
        let mut index = ListingsIndex::default();
        let mut entry = checked(x);
        entry.listing.flags.shown = ShownFields::NONE
            .with(PaymentField::BlockNumber)
            .with(PaymentField::BlockTimestamp);
        entry.listing.payment.block_timestamp = Some(now - 3_600);
        entry.listing.first_seen = None;
        index.listings.push(entry);
        publish_read(&mut producer.publisher, &index, None, now - 60);
        let net = FakeNet::with(
            peers
                .iter()
                .map(|peer| (*peer, FakeNode::new(Behaviour::Honest)))
                .collect(),
        );
        let tally = fake_cycle(&mut producer, &net, now, Source::All).await;
        assert_eq!((tally.removed, tally.carried), (0, 1));
        assert_eq!(producer.backoff_of(&x).unwrap(), None);
        // Kept, carried, and looked at again next cycle.
        let txn = producer.store.env().read_txn().unwrap();
        assert!(producer
            .known
            .get(&txn, &tagged(AGAIN_TAG, &x))
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn an_entry_paid_to_the_vault_stays_while_its_holders_are_silent() {
        // A listed entry paid after the vault was deployed, served by 5 of
        // its 7 nearest nodes; 2 others serve an old listing for the same
        // address, paid before. The 5 stop answering for a cycle (a
        // restart), the census of 20 still passes the guard: the only copies
        // that count show the old payment, but they are copies of another
        // listing, so the entry stays, carried, as a read keeps it.
        let now = unix_now();
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        let peers = census_nodes(&mut producer, 20);
        producer.start_requests();
        let x = numbered(7);
        let mut listed = ListingsIndex::default();
        listed.listings.push(checked(x));
        publish_read(&mut producer.publisher, &listed, None, now - 60);
        let valid = showing_block(x, 81_950_000);
        let old = showing_block(x, 80_204_042);
        keep_listing(&producer, &valid);
        keep_listing(&producer, &old);
        let nearest = producer.census.nearest(&x, NEAREST_NODES);
        let net = FakeNet::with(
            peers
                .iter()
                .map(|peer| {
                    let rank = nearest.iter().position(|near| near == peer);
                    let entries = match rank {
                        Some(0..=4) => vec![DigestEntry::new(&valid)],
                        Some(_) => vec![DigestEntry::new(&old)],
                        None => Vec::new(),
                    };
                    (*peer, FakeNode::serving(Behaviour::Honest, entries))
                })
                .collect(),
        );
        fake_cycle(&mut producer, &net, now, Source::All).await;
        for peer in &nearest[..5] {
            net.node(peer, |node| node.behaviour = Behaviour::Silent);
        }
        let tally = fake_cycle(
            &mut producer,
            &net,
            now + 60,
            Source::Pending { again: true },
        )
        .await;
        assert_eq!((tally.removed, tally.carried), (0, 1));
        let kept = producer.publisher.entry(&x).unwrap().unwrap();
        assert_eq!(kept.entry.listing.block_number, Some(81_950_000));
        assert!(producer.publisher.support(&x).unwrap().unwrap().carried);
        // While carried, it has no row.
        assert!(producer.publisher.rejected_entries().unwrap().is_empty());
    }

    #[tokio::test]
    async fn deciding_what_changed_agrees_with_deciding_every_address() {
        // Random uploads, repairs, other listings, competing listings,
        // removals, nodes going silent and answering again, new feed epochs,
        // and nodes joining and leaving the census: after each, the producer
        // that decides what changed publishes what one deciding every
        // address publishes.
        use rand::{Rng, SeedableRng};
        for seed in 0..4u64 {
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
            let start = unix_now();
            let old = start - 10 * 3_600;
            let dirs = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
            let (mut changed, node_changed) = offline_producer(dirs.0.path()).await;
            let (mut every, node_every) = offline_producer(dirs.1.path()).await;
            let _nodes = (node_changed, node_every);
            // 12 nodes in all, 10 in the census at first.
            let all: Vec<PeerId> = (0u8..12)
                .map(|n| PeerId::from_bytes([n.wrapping_mul(21).wrapping_add(3); 32]))
                .collect();
            for peer in &all[..10] {
                changed.census.admit(*peer, Vec::new(), AT);
                every.census.admit(*peer, Vec::new(), AT);
            }
            let _ = changed.census.take_changes();
            let _ = every.census.take_changes();
            changed.start_requests();
            every.start_requests();
            let envelopes: Vec<Envelope> = (0u8..12).map(|n| hidden_envelope(0x10 + n)).collect();
            let main: Vec<Listing> = envelopes
                .iter()
                .map(|envelope| hidden_listing(envelope, old, None))
                .collect();
            let alt: Vec<Listing> = envelopes
                .iter()
                .map(|envelope| hidden_listing(envelope, old, Some("alt.txt")))
                .collect();
            for producer in [&changed, &every] {
                for (envelope, (one, other)) in envelopes.iter().zip(main.iter().zip(&alt)) {
                    producer
                        .chain
                        .keep_envelope(&envelope.address(), &envelope.to_bytes());
                    keep_listing(producer, one);
                    keep_listing(producer, other);
                }
            }
            let net = FakeNet::with(
                all.iter()
                    .map(|peer| (*peer, FakeNode::new(Behaviour::Honest)))
                    .collect(),
            );
            let mut silent: Option<PeerId> = None;
            let mut holds: BTreeSet<(PeerId, usize)> = BTreeSet::new();
            let mut epoch = 100u64;
            let mut now = start;
            for step in 0..40 {
                let census: Vec<PeerId> = changed.census.nodes().map(|node| node.peer).collect();
                let event = match rng.gen_range(0..100) {
                    0..=19 => {
                        let i = rng.gen_range(0..main.len());
                        let near = changed.census.nearest(&main[i].address, NEAREST_NODES);
                        let k = rng.gen_range(4..=near.len());
                        for n in &near[..k] {
                            net.node(n, |node| node.put(DigestEntry::new(&main[i])));
                            holds.insert((*n, i));
                        }
                        "upload"
                    }
                    20..=29 => {
                        let i = rng.gen_range(0..main.len());
                        let near = changed.census.nearest(&main[i].address, 9);
                        let n = near[rng.gen_range(0..near.len())];
                        net.node(&n, |node| node.put(DigestEntry::new(&main[i])));
                        holds.insert((n, i));
                        "repair"
                    }
                    30..=39 => {
                        let i = rng.gen_range(0..main.len());
                        let near = changed.census.nearest(&main[i].address, NEAREST_NODES);
                        let n = near[rng.gen_range(0..near.len())];
                        net.node(&n, |node| node.put(DigestEntry::new(&alt[i])));
                        holds.insert((n, i));
                        "another listing"
                    }
                    40..=44 => {
                        // Two listings, neither with a quorum: 3 of its
                        // nearest serve one, 1 another, 3 nothing.
                        let i = rng.gen_range(0..main.len());
                        let near = changed.census.nearest(&main[i].address, NEAREST_NODES);
                        for (rank, n) in near.iter().enumerate() {
                            match rank {
                                0..=2 => {
                                    net.node(n, |node| node.put(DigestEntry::new(&main[i])));
                                    holds.insert((*n, i));
                                }
                                3 => {
                                    net.node(n, |node| node.put(DigestEntry::new(&alt[i])));
                                    holds.insert((*n, i));
                                }
                                _ => {
                                    net.node(n, |node| node.remove(&main[i].address));
                                    holds.remove(&(*n, i));
                                }
                            }
                        }
                        "competing listings"
                    }
                    45..=49 => {
                        let i = rng.gen_range(0..main.len());
                        let n = all[rng.gen_range(0..all.len())];
                        net.node(&n, |node| node.remove(&main[i].address));
                        holds.remove(&(n, i));
                        "remove"
                    }
                    50..=64 => {
                        if let Some(peer) = silent.take() {
                            net.node(&peer, |node| node.behaviour = Behaviour::Honest);
                            "answers again"
                        } else {
                            // Where there is one, a nearest node of some
                            // address that serves nothing there.
                            let i = rng.gen_range(0..main.len());
                            let near = changed.census.nearest(&main[i].address, NEAREST_NODES);
                            let free: Vec<PeerId> = near
                                .iter()
                                .filter(|peer| !holds.contains(&(**peer, i)))
                                .copied()
                                .collect();
                            let peer = if free.is_empty() {
                                census[rng.gen_range(0..census.len())]
                            } else {
                                free[rng.gen_range(0..free.len())]
                            };
                            net.node(&peer, |node| node.behaviour = Behaviour::Silent);
                            silent = Some(peer);
                            "silent"
                        }
                    }
                    65..=72 => {
                        let n = census[rng.gen_range(0..census.len())];
                        epoch += 1;
                        net.node(&n, |node| node.renumber(epoch));
                        "new epoch"
                    }
                    73..=81 => {
                        let outside: Vec<PeerId> = all
                            .iter()
                            .filter(|peer| changed.census.get(peer).is_none())
                            .copied()
                            .collect();
                        if outside.is_empty() {
                            "nothing"
                        } else {
                            let peer = outside[rng.gen_range(0..outside.len())];
                            changed.census.admit(peer, Vec::new(), now);
                            every.census.admit(peer, Vec::new(), now);
                            "joins"
                        }
                    }
                    82..=89 => {
                        if census.len() <= 9 {
                            "nothing"
                        } else {
                            let candidates: Vec<PeerId> = census
                                .iter()
                                .filter(|peer| Some(**peer) != silent)
                                .copied()
                                .collect();
                            let peer = candidates[rng.gen_range(0..candidates.len())];
                            changed.census.remove(&peer);
                            every.census.remove(&peer);
                            "leaves"
                        }
                    }
                    _ => "nothing",
                };
                now += 60;
                let source = if step == 0 {
                    Source::All
                } else {
                    Source::Pending { again: true }
                };
                let tc = fake_cycle(&mut changed, &net, now, source).await;
                let te = fake_cycle(&mut every, &net, now, Source::All).await;
                assert_eq!(
                    shown(&changed, &tc),
                    shown(&every, &te),
                    "seed {seed}, step {step}, after '{event}'"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_sweep_decides_every_address_over_as_many_cycles_as_it_takes() {
        // More addresses than three batches, each served by 2 of its 7
        // nearest nodes, and no time left in any cycle: each cycle's sweep
        // decides one batch, and goes on from there the next.
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        census_nodes(&mut producer, 8);
        let count = 3 * DECIDE_BATCH as u32 + 10;
        let listings: Vec<Listing> = (0..count)
            .map(|n| showing_block(numbered(n), 81_950_000))
            .collect();
        serve(&mut producer, &listings, 2);
        producer.start_requests();
        producer.sweep = Some(Sweep {
            after: None,
            began: AT,
            alert: false,
        });
        let mut decided = Vec::new();
        for cycle in 0..4 {
            producer.cycles += 1;
            let mut drops = DropCheck {
                checked: false,
                deadline: Instant::now(),
            };
            let mut tally = Tally::default();
            let swept = producer
                .sweep_on(AT + 60 * cycle, Instant::now(), &mut drops, &mut tally)
                .await
                .unwrap();
            decided.push(swept);
        }
        let batch = DECIDE_BATCH as u64;
        assert_eq!(decided, [batch, batch, batch, 10]);
        assert!(producer.sweep.is_none());
        assert_eq!(producer.decided_all_at, Some(AT));
        // Each was decided, and is to be decided again each cycle.
        let txn = producer.store.env().read_txn().unwrap();
        let again = tagged_after(producer.known, &txn, AGAIN_TAG, None, usize::MAX).unwrap();
        assert_eq!(again.len(), count as usize);
    }

    #[tokio::test]
    async fn what_changed_is_decided_round_from_where_the_last_cycle_stopped() {
        // More changed addresses than three batches, and no time left in any
        // cycle: each cycle decides a batch, going on from where the last
        // stopped, and once past the last address, round from the first.
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        census_nodes(&mut producer, 8);
        let count = 3 * DECIDE_BATCH as u32 + 10;
        let mut addresses: Vec<XorName> = (0..count).map(numbered).collect();
        addresses.sort_unstable();
        let listings: Vec<Listing> = addresses
            .iter()
            .map(|address| showing_block(*address, 81_950_000))
            .collect();
        serve(&mut producer, &listings, 2);
        producer.start_requests();
        producer.feeds.mark_pending(&addresses).unwrap();
        let mut decided = Vec::new();
        let mut cursors = Vec::new();
        for cycle in 0..5u64 {
            producer.cycles += 1;
            let mut drops = DropCheck {
                checked: false,
                deadline: Instant::now(),
            };
            let swept = producer
                .decide_changed(
                    AT + 60 * cycle,
                    Instant::now(),
                    &mut drops,
                    &mut Tally::default(),
                )
                .await
                .unwrap();
            decided.push(swept);
            cursors.push(producer.changed_after);
        }
        let batch = DECIDE_BATCH as u64;
        assert_eq!(decided, [batch, batch, batch, 10, batch]);
        assert_eq!(
            cursors,
            [
                Some(addresses[DECIDE_BATCH - 1]),
                Some(addresses[2 * DECIDE_BATCH - 1]),
                Some(addresses[3 * DECIDE_BATCH - 1]),
                None,
                Some(addresses[DECIDE_BATCH - 1]),
            ]
        );
        assert_eq!(producer.feeds.pending_count().unwrap(), 0);
        // With time enough, a pass goes round once, from where it stopped
        // to there: every address is decided once.
        producer.cycles += 1;
        let mut drops = DropCheck {
            checked: false,
            deadline: Instant::now() + CYCLE,
        };
        let swept = producer
            .decide_changed(
                AT + 600,
                Instant::now() + CYCLE,
                &mut drops,
                &mut Tally::default(),
            )
            .await
            .unwrap();
        assert_eq!(swept, u64::from(count));
        assert_eq!(producer.changed_after, None);
    }

    #[tokio::test]
    async fn a_sweep_passes_over_what_its_cycle_decided_already() {
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        census_nodes(&mut producer, 8);
        let addresses: Vec<XorName> = (0..40).map(numbered).collect();
        let listings: Vec<Listing> = addresses
            .iter()
            .map(|address| showing_block(*address, 81_950_000))
            .collect();
        serve(&mut producer, &listings, 2);
        producer.start_requests();
        // A cycle decides what changed first, then sweeps: what it decided
        // isn't decided twice, which would count it twice.
        producer.cycles += 1;
        producer.feeds.mark_pending(&addresses[..15]).unwrap();
        let mut drops = DropCheck {
            checked: false,
            deadline: Instant::now() + CYCLE,
        };
        let mut tally = Tally::default();
        let (first, _) = producer
            .decide_all(
                Source::Pending { again: false },
                AT,
                Some(&mut drops),
                false,
                &mut tally,
            )
            .await
            .unwrap();
        assert_eq!(first, 15);
        producer.sweep = Some(Sweep {
            after: None,
            began: AT,
            alert: false,
        });
        let swept = producer
            .sweep_on(AT, Instant::now() + CYCLE, &mut drops, &mut tally)
            .await
            .unwrap();
        assert_eq!(swept, 25);
        assert_eq!(tally.groups.get("below_quorum"), Some(&(40, AT)));
        // The next cycle's sweep decides them all.
        producer.cycles += 1;
        producer.sweep = Some(Sweep {
            after: None,
            began: AT + 60,
            alert: true,
        });
        let swept = producer
            .sweep_on(
                AT + 60,
                Instant::now() + CYCLE,
                &mut drops,
                &mut Tally::default(),
            )
            .await
            .unwrap();
        assert_eq!(swept, 40);
    }

    #[tokio::test]
    async fn the_census_changing_marks_only_what_the_sweep_has_passed() {
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        census_nodes(&mut producer, 8);
        let mut addresses: Vec<XorName> = (0..20).map(numbered).collect();
        addresses.sort_unstable();
        let listings: Vec<Listing> = addresses
            .iter()
            .map(|address| showing_block(*address, 81_950_000))
            .collect();
        serve(&mut producer, &listings, 2);
        // After a start, nothing is decided yet, and the sweep is still to
        // come to every address: a census change marks nothing.
        producer.sweep = Some(Sweep {
            after: None,
            began: AT,
            alert: false,
        });
        producer.mark_moved().unwrap();
        assert_eq!(producer.feeds.pending_count().unwrap(), 0);
        // Once the sweep has passed the first half, those it passed are
        // marked, where nothing is known of them.
        producer.sweep = Some(Sweep {
            after: Some(addresses[9]),
            began: AT,
            alert: false,
        });
        producer.mark_moved().unwrap();
        assert_eq!(producer.feeds.pending_count().unwrap(), 10);
        for address in &addresses[..10] {
            assert!(producer.feeds.is_pending(address).unwrap());
        }
    }

    #[tokio::test]
    async fn between_cycles_an_address_near_a_node_behind_its_push_waits() {
        // Between cycles, a push from a node came behind its mirror: the
        // node holds what its mirror doesn't show. What it serves near the
        // addresses pushes changed is waited for: they stay pending, to be
        // decided with the next cycle, which reads the node again. Every
        // copy of the others was pushed since the latest poll.
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        census_nodes(&mut producer, 20);
        let listings = hidden_listings(&producer, 0x80, 40);
        let addresses: Vec<XorName> = listings.iter().map(|listing| listing.address).collect();
        serve(&mut producer, &listings, QUORUM_THRESHOLD);
        mark_pushed(&producer, &addresses, QUORUM_THRESHOLD);
        producer.start_requests();
        producer.feeds.mark_pending(&addresses).unwrap();
        let behind = producer.census.nearest(&addresses[0], NEAREST_NODES)[0];
        producer.feeds.mark_behind(&behind);
        let near_behind: BTreeSet<XorName> = addresses
            .iter()
            .filter(|address| {
                producer
                    .census
                    .nearest(address, NEAREST_NODES)
                    .contains(&behind)
            })
            .copied()
            .collect();
        assert!(!near_behind.is_empty() && near_behind.len() < addresses.len());
        let mut tally = Tally::default();
        let pushed: BTreeSet<XorName> = addresses.iter().copied().collect();
        let (decided, _) = producer
            .decide_pushed(&pushed, AT, Instant::now() + CYCLE, &mut tally)
            .await
            .unwrap();
        assert_eq!(decided as usize, addresses.len() - near_behind.len());
        for address in &addresses {
            assert_eq!(
                producer.feeds.is_pending(address).unwrap(),
                near_behind.contains(address)
            );
        }
    }

    /// `count` listings, each of an envelope of its own (seeds from
    /// `first`) withholding its data map and showing no payment field,
    /// stored this hour less ten, their envelopes kept, as fetching them
    /// keeps them: reported, decided with no chain call and nothing fetched.
    fn hidden_listings(producer: &Producer, first: u8, count: u8) -> Vec<Listing> {
        let now = unix_now();
        (0..count)
            .map(|n| {
                let envelope = hidden_envelope(first.wrapping_add(n));
                producer
                    .chain
                    .keep_envelope(&envelope.address(), &envelope.to_bytes());
                hidden_listing(&envelope, now - 10 * 3_600, None)
            })
            .collect()
    }

    /// Note that `holders` of the nearest nodes of each of `addresses`
    /// pushed their copies of it since the latest poll, as taking their
    /// pushes notes it.
    fn mark_pushed(producer: &Producer, addresses: &[XorName], holders: usize) {
        let mut txn = producer.store.env().write_txn().unwrap();
        for address in addresses {
            for peer in producer
                .census
                .nearest(address, NEAREST_NODES)
                .into_iter()
                .take(holders)
            {
                producer
                    .known
                    .put(&mut txn, &pushed_key(address, &peer), &[])
                    .unwrap();
            }
        }
        txn.commit().unwrap();
    }

    /// The entries `serve` gave `peer`'s mirror, of `listings` served by
    /// `holders` of each one's nearest nodes, in address order.
    fn mirror_of(
        producer: &Producer,
        peer: &PeerId,
        listings: &[Listing],
        holders: usize,
    ) -> Vec<DigestEntry> {
        let mut entries: Vec<DigestEntry> = listings
            .iter()
            .filter(|listing| {
                producer
                    .census
                    .nearest(&listing.address, NEAREST_NODES)
                    .iter()
                    .take(holders)
                    .any(|near| near == peer)
            })
            .map(DigestEntry::new)
            .collect();
        entries.sort_by_key(|entry| entry.address);
        entries
    }

    /// A push from a node whose mirror `serve` seeded with `mirrored`, at
    /// record 1 of epoch 7: `change`, as record 2, with the node's count and
    /// set hash after it.
    fn push_after(mirrored: &[DigestEntry], change: ant_listings::FeedChange) -> ChangesResponse {
        let mut served: BTreeMap<XorName, DigestEntry> = mirrored
            .iter()
            .map(|entry| (entry.address, *entry))
            .collect();
        match change {
            ant_listings::FeedChange::Entry { entry, .. } => {
                served.insert(entry.address, entry);
            }
            ant_listings::FeedChange::Removed { address, .. } => {
                served.remove(&address);
            }
        }
        ChangesResponse {
            epoch: 7,
            head: 2,
            next: 2,
            count: served.len() as u64,
            set_hash: ant_listings::SetHash::of(served.values()),
            changes: vec![change],
            more: false,
            view: [0; 32],
            peers: Vec::new(),
        }
    }

    #[tokio::test]
    async fn a_push_between_cycles_decides_only_what_it_changed() {
        // What changed waits, more than the latest cycle had time for: its
        // pass over what changed decided a batch, and goes on next cycle.
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        census_nodes(&mut producer, 8);
        let count = 4 * DECIDE_BATCH as u32;
        let mut addresses: Vec<XorName> = (0..count).map(numbered).collect();
        addresses.sort_unstable();
        let listings: Vec<Listing> = addresses
            .iter()
            .map(|address| showing_block(*address, 81_950_000))
            .collect();
        serve(&mut producer, &listings, 2);
        producer.start_requests();
        producer.feeds.mark_pending(&addresses).unwrap();
        producer.guard_ok = true;
        producer.last_status = Some(Status::default());
        producer.cycles += 1;
        let mut drops = DropCheck {
            checked: false,
            deadline: Instant::now(),
        };
        let in_cycle = producer
            .decide_changed(AT, Instant::now(), &mut drops, &mut Tally::default())
            .await
            .unwrap();
        assert_eq!(in_cycle, DECIDE_BATCH as u64);
        let waiting = producer.feeds.pending_count().unwrap();
        assert_eq!(waiting, u64::from(count) - DECIDE_BATCH as u64);

        // Between cycles, a new listing is stored by its nearest nodes, each
        // pushing it, and the next cycle is due already: once a quorum of
        // them has pushed it, its address is decided and listed, and nothing
        // else is.
        let fresh = hidden_listings(&producer, 0x30, 1).remove(0);
        keep_listing(&producer, &fresh);
        let entry = DigestEntry::new(&fresh);
        let nearest = producer.census.nearest(&fresh.address, NEAREST_NODES);
        for (n, peer) in nearest.iter().take(QUORUM_THRESHOLD).enumerate() {
            let mirrored = mirror_of(&producer, peer, &listings, 2);
            let push = push_after(&mirrored, ant_listings::FeedChange::Entry { seq: 2, entry });
            producer
                .take_pushes((*peer, push), Instant::now())
                .await
                .unwrap();
            assert_eq!(
                producer.feeds.entry(peer, &fresh.address).unwrap(),
                Some(entry)
            );
            let quorum = n + 1 == QUORUM_THRESHOLD;
            assert_eq!(producer.feeds.is_pending(&fresh.address).unwrap(), !quorum);
            assert_eq!(
                producer.publisher.entry(&fresh.address).unwrap().is_some(),
                quorum
            );
        }
        // Nothing else waiting was decided.
        assert_eq!(producer.feeds.pending_count().unwrap(), waiting);
        assert_eq!(producer.pushes_between, QUORUM_THRESHOLD as u64);
        assert_eq!(producer.published_between, 1);
    }

    #[tokio::test]
    async fn between_cycles_what_has_no_time_left_waits_for_the_cycle() {
        // What pushes changed, each copy pushed since the latest poll, with
        // the next cycle due already: one address is decided, as a pass
        // always decides one, and the rest waits for the cycle, pending.
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        census_nodes(&mut producer, 8);
        let listings = hidden_listings(&producer, 0x40, 10);
        let addresses: Vec<XorName> = listings.iter().map(|listing| listing.address).collect();
        serve(&mut producer, &listings, QUORUM_THRESHOLD);
        mark_pushed(&producer, &addresses, QUORUM_THRESHOLD);
        producer.start_requests();
        producer.feeds.mark_pending(&addresses).unwrap();
        let pushed: BTreeSet<XorName> = addresses.iter().copied().collect();
        let (decided, _) = producer
            .decide_pushed(&pushed, AT, Instant::now(), &mut Tally::default())
            .await
            .unwrap();
        assert_eq!(decided, 1);
        assert_eq!(producer.feeds.pending_count().unwrap(), 9);
        // With time, the rest.
        let (decided, _) = producer
            .decide_pushed(&pushed, AT, Instant::now() + CYCLE, &mut Tally::default())
            .await
            .unwrap();
        assert_eq!(decided, 10);
        assert_eq!(producer.feeds.pending_count().unwrap(), 0);
    }

    #[tokio::test]
    async fn a_removal_between_cycles_counts_with_the_next_cycle() {
        // A published entry showing a payment from before the vault. Between
        // cycles, a quorum of its nearest nodes store it and push it: decided
        // at once, it is removed, as such an entry is whenever its address is
        // decided, and the next cycle's status.json counts the removal, as a
        // cycle that removed it would.
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        census_nodes(&mut producer, 8);
        let envelope = Envelope::withheld_hash(
            [0x5b; SALTED_HASH_LEN],
            Metadata::default(),
            ShownFields::NONE.with(PaymentField::BlockNumber),
            true,
        )
        .unwrap();
        let x = envelope.address();
        producer.chain.keep_envelope(&x, &envelope.to_bytes());
        let mut listed = ListingsIndex::default();
        let mut published = checked_at(x, 80_204_042);
        published.envelope = envelope;
        listed.listings.push(published);
        publish_read(&mut producer.publisher, &listed, None, AT);
        let listing = showing_block(x, 80_204_042);
        keep_listing(
            &producer,
            &Listing {
                first_seen: None,
                ..listing.clone()
            },
        );
        serve(&mut producer, &[], 0);
        producer.start_requests();
        producer.guard_ok = true;
        producer.last_status = Some(Status::default());
        let entry = DigestEntry::new(&listing);
        for peer in producer
            .census
            .nearest(&x, NEAREST_NODES)
            .into_iter()
            .take(QUORUM_THRESHOLD)
        {
            let push = push_after(&[], ant_listings::FeedChange::Entry { seq: 2, entry });
            producer
                .take_pushes((peer, push), Instant::now() + CYCLE)
                .await
                .unwrap();
        }
        assert!(producer.publisher.entry(&x).unwrap().is_none());
        assert_eq!(producer.published_between, 1);
        assert_eq!(producer.removed_between, 1);
    }

    #[tokio::test]
    async fn a_root_map_is_read_within_its_bounds() {
        use self_encryption::{bytes::Bytes as Content, test_helpers::random_bytes};
        // A file of 8 chunks, its data map shrunk once into 3, as an upload
        // shrinks a map of more than 3 chunks.
        let content = random_bytes(8 * 1_024);
        let (root, _) = self_encryption::encrypt(content).unwrap();
        let mut root_infos = root.infos().to_vec();
        // A root map of more than 3 chunks: 8 chunks of 1 KiB each claimed.
        while root_infos.len() < 8 {
            let mut info = root_infos[0].clone();
            info.index = root_infos.len();
            root_infos.push(info);
        }
        let root = DataMap::new(root_infos);
        let mut records: HashMap<[u8; 32], Content> = HashMap::new();
        let (shrunk, _) = self_encryption::shrink_data_map(root.clone(), |address, bytes| {
            records.insert(address.0, bytes);
            Ok(())
        })
        .unwrap();
        assert!(shrunk.is_child());
        assert_eq!(shrunk.infos().len(), SHRUNK_CHUNKS);
        let records = &records;
        let fetch = |address: [u8; 32]| async move {
            records
                .get(&address)
                .cloned()
                .ok_or_else(|| Error::NotFound("no such chunk".into()))
        };
        let room = Semaphore::new(MAX_ROOT_MAP_BYTES.div_ceil(1024));
        assert_eq!(
            read_root_size(&shrunk, fetch, &room).await,
            SizeRead::Sized(root_size(&root).unwrap())
        );
        // A chunk no node hands over: later.
        let missing = |_: [u8; 32]| async { Err(Error::NotFound("no such chunk".into())) };
        assert_eq!(
            read_root_size(&shrunk, missing, &room).await,
            SizeRead::Later
        );
        // A record that isn't the chunk its address names: later, from
        // another node.
        let wrong = |_: [u8; 32]| async { Ok(Content::from_static(b"not the chunk")) };
        assert_eq!(read_root_size(&shrunk, wrong, &room).await, SizeRead::Later);
        // A map that declares each chunk smaller than it decrypts to: the
        // decryption stops at what it declares, and the map never gives a
        // size.
        let mut small = shrunk.infos().to_vec();
        for info in &mut small {
            info.src_size = 10;
        }
        let small = DataMap::with_child(small, shrunk.child().unwrap());
        assert_eq!(read_root_size(&small, fetch, &room).await, SizeRead::Never);
        // One that declares more than a map shrunk once holds, or more
        // chunks, is never fetched.
        let fetched = std::sync::atomic::AtomicUsize::new(0);
        let fetched = &fetched;
        let never_fetched = |_: [u8; 32]| async move {
            fetched.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Err::<Content, Error>(Error::NotFound("no such chunk".into()))
        };
        let mut large = shrunk.infos().to_vec();
        large[0].src_size = MAX_ROOT_MAP_BYTES;
        let large = DataMap::with_child(large, shrunk.child().unwrap());
        assert_eq!(
            read_root_size(&large, never_fetched, &room).await,
            SizeRead::Never
        );
        let mut more = shrunk.infos().to_vec();
        let mut extra = more[0].clone();
        extra.index = more.len();
        more.push(extra);
        let more = DataMap::with_child(more, shrunk.child().unwrap());
        assert_eq!(
            read_root_size(&more, never_fetched, &room).await,
            SizeRead::Never
        );
        assert_eq!(fetched.load(std::sync::atomic::Ordering::Relaxed), 0);
        // The room held is given back.
        assert_eq!(room.available_permits(), MAX_ROOT_MAP_BYTES.div_ceil(1024));
    }

    #[tokio::test]
    async fn between_cycles_a_quorum_resting_on_a_copy_not_pushed_waits_for_the_cycle() {
        // Three of a new listing's nearest nodes serve it as the latest poll
        // read them, and a fourth stores it and pushes it between cycles.
        // One of the three may have gone, or stopped serving it, since the
        // poll, with no push to say so: the quorum rests on what the poll
        // read, so the address waits, pending, for the next cycle, which
        // reads every node again. Once each copy of a quorum was pushed since
        // the poll, it is listed at once.
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        census_nodes(&mut producer, 8);
        let fresh = hidden_listings(&producer, 0x50, 1).remove(0);
        serve(&mut producer, std::slice::from_ref(&fresh), 3);
        producer.start_requests();
        producer.guard_ok = true;
        producer.last_status = Some(Status::default());
        let nearest = producer.census.nearest(&fresh.address, NEAREST_NODES);
        let entry = DigestEntry::new(&fresh);
        let push = push_after(&[], ant_listings::FeedChange::Entry { seq: 2, entry });
        producer
            .take_pushes((nearest[3], push), Instant::now() + CYCLE)
            .await
            .unwrap();
        assert_eq!(
            producer
                .feeds
                .copies(&fresh.address, &nearest)
                .unwrap()
                .len(),
            QUORUM_THRESHOLD
        );
        assert!(producer.publisher.entry(&fresh.address).unwrap().is_none());
        assert!(producer.feeds.is_pending(&fresh.address).unwrap());
        assert_eq!(producer.published_between, 0);
        // Had the three pushed theirs since the poll too, it is listed.
        mark_pushed(&producer, &[fresh.address], 3);
        let (decided, staged) = producer
            .decide_pushed(
                &BTreeSet::from([fresh.address]),
                AT,
                Instant::now() + CYCLE,
                &mut Tally::default(),
            )
            .await
            .unwrap();
        assert_eq!((decided, staged), (1, true));
        assert!(producer.publisher.entry(&fresh.address).unwrap().is_some());
        assert!(!producer.feeds.is_pending(&fresh.address).unwrap());
        // A poll forgets what was pushed: it reads every node again.
        producer.forget_pushed().unwrap();
        assert!(!producer.pushed_quorum(&fresh.address).unwrap());
    }

    #[tokio::test]
    async fn between_cycles_a_node_whose_push_was_dropped_is_taken_as_behind() {
        // Nine pushes from one node while none is taken: the ninth doesn't
        // fit and is dropped, so the node holds a record its mirror lacks.
        // Between cycles it is taken as behind its mirror: its copies don't
        // count, and what they would decide waits for the next cycle.
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        census_nodes(&mut producer, 8);
        serve(&mut producer, &[], 0);
        producer.guard_ok = true;
        producer.last_status = Some(Status::default());
        let peer = producer.census.nodes().next().unwrap().peer;
        let entry = DigestEntry::new(&showing_block(numbered(1), 81_950_000));
        let push = push_after(&[], ant_listings::FeedChange::Entry { seq: 2, entry });
        let sink = producer.sink.as_ref().unwrap();
        let offered: Vec<bool> = (0..9).map(|_| sink.offer(peer, push.clone())).collect();
        assert_eq!(offered.iter().filter(|kept| !**kept).count(), 1);
        let first = producer.pushes.try_recv().unwrap();
        producer
            .take_pushes(first, Instant::now() + CYCLE)
            .await
            .unwrap();
        assert_eq!(producer.pushes_between, 8);
        assert!(producer.feeds.behind(&peer));
        assert!(producer
            .feeds
            .copies(&entry.address, &[peer])
            .unwrap()
            .is_empty());
        assert!(producer.feeds.is_pending(&entry.address).unwrap());
    }

    /// Fake nodes, of which `slow` answers each request only after `delay`,
    /// and before each answer replaces the 200 entries it made up last time
    /// with 200 new ones: it always has more to page through.
    struct ChurningNet<'a> {
        net: &'a FakeNet,
        slow: PeerId,
        delay: Duration,
        made_up: Mutex<(u32, Vec<XorName>)>,
    }

    impl crate::data::client::listings_feeds::FeedIo for ChurningNet<'_> {
        async fn ask(&self, peer: &PeerId, body: ListingsBody) -> Option<ListingsBody> {
            if *peer == self.slow {
                tokio::time::sleep(self.delay).await;
                let (old, fresh) = {
                    let mut made_up = self.made_up.lock().unwrap();
                    made_up.0 += 1;
                    let base = 9_000_000 + made_up.0 * 1_000;
                    let fresh: Vec<XorName> = (0..200).map(|n| numbered(base + n)).collect();
                    let old = std::mem::replace(&mut made_up.1, fresh.clone());
                    (old, fresh)
                };
                self.net.node(peer, |node| {
                    for address in &old {
                        node.remove(address);
                    }
                    for address in &fresh {
                        node.put(DigestEntry {
                            address: *address,
                            time: 1_791_324_000,
                            block_number: 81_950_000,
                            log_index: 0,
                            first_seen: Some(1_791_324_000),
                            digest: [9; 32],
                        });
                    }
                });
            }
            self.net.ask(peer, body).await
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_node_making_entries_up_cant_hold_back_what_a_quorum_serves() {
        // Fault injection: of 8 census nodes, one answers each request just
        // inside a request's timeout and churns entries it makes up. Each
        // cycle runs as `Producer::cycle` runs it, the census fixed and
        // nothing to fetch: the poll, then what changed decided for a CYCLE
        // from when deciding starts. The poll ends once the slow node's
        // share is used, what it makes up doesn't pile up, and new listings,
        // each served by the healthy nodes nearest it, are published in the
        // cycle that first reads them.
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        let peers = census_nodes(&mut producer, 8);
        producer.start_requests();
        let slow = peers[7];
        let net = FakeNet::with(
            peers
                .iter()
                .map(|peer| (*peer, FakeNode::serving(Behaviour::Honest, Vec::new())))
                .collect(),
        );
        let io = ChurningNet {
            net: &net,
            slow,
            delay: Duration::from_millis(9_900),
            made_up: Mutex::new((0, Vec::new())),
        };
        let nodes: Vec<FeedNode> = producer
            .census
            .nodes()
            .map(|node| FeedNode {
                peer: node.peer,
                range: producer.census.leaf_of(node.peer.as_bytes()),
                feed: true,
                want_peers: false,
            })
            .collect();
        let now = unix_now();
        let mut fresh: Vec<XorName> = Vec::new();
        for cycle in 0..16u64 {
            if cycle == 8 {
                for listing in hidden_listings(&producer, 0xa0, 7) {
                    keep_listing(&producer, &listing);
                    for peer in peers.iter().filter(|peer| **peer != slow) {
                        net.node(peer, |node| node.put(DigestEntry::new(&listing)));
                    }
                    fresh.push(listing.address);
                }
            }
            producer.cycles += 1;
            let at = now + cycle * 60;
            let started = Instant::now();
            producer
                .feeds
                .poll(&io, &producer.census, &nodes, at, started + CYCLE, None)
                .await
                .unwrap();
            let took = started.elapsed();
            assert!(took <= Duration::from_secs(21), "cycle {cycle}: {took:?}");
            let answered = producer.note_answers(at, &BTreeSet::new()).await;
            assert!(producer.census.guard_ok(answered), "cycle {cycle}");
            producer.census.note_cycle();
            producer.mark_due(at).unwrap();
            let until = Instant::now() + CYCLE;
            let mut drops = DropCheck {
                checked: false,
                deadline: until,
            };
            producer
                .decide_changed(at, until, &mut drops, &mut Tally::default())
                .await
                .unwrap();
            assert_eq!(producer.feeds.pending_count().unwrap(), 0, "cycle {cycle}");
            for address in &fresh {
                assert!(
                    producer.publisher.entry(address).unwrap().is_some(),
                    "cycle {cycle}"
                );
            }
        }
        assert_eq!(fresh.len(), 7);
    }

    /// Rows of [`FUTURE_TAG`] and of [`FUTURE_AT_TAG`] in `serve_known`.
    fn future_rows(producer: &Producer) -> (usize, usize) {
        let txn = producer.store.env().read_txn().unwrap();
        let count = |tag: u8| {
            producer
                .known
                .remap_data_type::<DecodeIgnore>()
                .prefix_iter(&txn, &[tag])
                .unwrap()
                .count()
        };
        (count(FUTURE_TAG), count(FUTURE_AT_TAG))
    }

    #[tokio::test]
    async fn a_node_redating_its_copies_keeps_one_future_row_an_address() {
        // Fault injection: one census node, among the 7 nearest of 40 listed
        // addresses, serves each listing (the same digest) dated further in
        // the future every cycle, while 6 honest nodes list it. Each address
        // keeps one row for when to decide it again, replaced each time it
        // is decided, not one more a cycle; and none for a date past the
        // next sweep.
        let now = unix_now();
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        let peers = census_nodes(&mut producer, 8);
        producer.start_requests();
        let faulty = peers[0];
        let mut chosen: Vec<Envelope> = Vec::new();
        let mut served: BTreeMap<PeerId, Vec<DigestEntry>> = BTreeMap::new();
        for seed in 0..=255u8 {
            let envelope = hidden_envelope(seed);
            let a = envelope.address();
            let nearest = producer.census.nearest(&a, NEAREST_NODES);
            if !nearest.contains(&faulty) {
                continue;
            }
            let early = hidden_listing(&envelope, now - 10 * 3_600, None);
            producer.chain.keep_envelope(&a, &envelope.to_bytes());
            keep_listing(&producer, &early);
            for peer in &nearest {
                let copy = if *peer == faulty {
                    hidden_listing(&envelope, now + 3 * 3_600, None)
                } else {
                    early.clone()
                };
                served
                    .entry(*peer)
                    .or_default()
                    .push(DigestEntry::new(&copy));
            }
            chosen.push(envelope);
            if chosen.len() == 40 {
                break;
            }
        }
        let net = FakeNet::with(
            peers
                .iter()
                .map(|peer| {
                    let entries = served.remove(peer).unwrap_or_default();
                    (*peer, FakeNode::serving(Behaviour::Honest, entries))
                })
                .collect(),
        );
        fake_cycle(&mut producer, &net, now, Source::All).await;
        let listed = chosen
            .iter()
            .filter(|envelope| {
                producer
                    .publisher
                    .entry(&envelope.address())
                    .unwrap()
                    .is_some()
            })
            .count();
        assert_eq!(listed, chosen.len());
        assert_eq!(future_rows(&producer), (chosen.len(), chosen.len()));
        for cycle in 1..=6u64 {
            net.node(&faulty, |node| {
                for envelope in &chosen {
                    node.put(DigestEntry::new(&hidden_listing(
                        envelope,
                        now + (3 + cycle) * 3_600,
                        None,
                    )));
                }
            });
            producer.mark_due(now + cycle * 60).unwrap();
            fake_cycle(
                &mut producer,
                &net,
                now + cycle * 60,
                Source::Pending { again: true },
            )
            .await;
            assert_eq!(
                future_rows(&producer),
                (chosen.len(), chosen.len()),
                "cycle {cycle}"
            );
        }
        // A date past the next sweep keeps no row: the sweep decides the
        // address again before.
        net.node(&faulty, |node| {
            for envelope in &chosen {
                node.put(DigestEntry::new(&hidden_listing(
                    envelope,
                    now + 30 * 86_400,
                    None,
                )));
            }
        });
        fake_cycle(
            &mut producer,
            &net,
            now + 420,
            Source::Pending { again: true },
        )
        .await;
        assert_eq!(future_rows(&producer), (0, 0));
    }

    #[test]
    fn a_drop_kept_only_by_what_wasnt_heard_is_checked_again_at_the_next_cycle_once() {
        let unheard = Refusal {
            why: "of the 7 nodes asked, 0 serve a listing for it and 1 didn't answer".into(),
            evidence: false,
        };
        let refused = Refusal {
            why: "of the 7 nodes asked, 1 serve a listing for it and 0 didn't answer".into(),
            evidence: true,
        };
        let hour = RETRY_INTERVAL.as_secs();
        // Only what wasn't heard kept it: checked again at the next cycle.
        let first = drop_backoff(&unheard, None, 7, AT);
        assert_eq!(
            first,
            DropBackoff {
                inputs: 7,
                retry_at: AT + 1,
                soon: true,
            }
        );
        // Kept so again: backed off.
        let second = drop_backoff(&unheard, Some(first), 7, AT + 60);
        assert_eq!((second.retry_at, second.soon), (AT + 60 + hour, false));
        // Once that is over, kept so again: at the next cycle once more.
        let third = drop_backoff(&unheard, Some(second), 7, AT + 60 + hour);
        assert!(third.soon);
        // Other inputs: a check of its own.
        assert!(drop_backoff(&unheard, Some(first), 8, AT + 60).soon);
        // Refused by what was heard: backed off at once.
        let evidence = drop_backoff(&refused, None, 7, AT);
        assert_eq!((evidence.retry_at, evidence.soon), (AT + hour, false));
        // Kept across a write and a read of the store's bytes.
        assert_eq!(DropBackoff::decode(&first.encode()), Some(first));
        assert_eq!(DropBackoff::decode(&evidence.encode()), Some(evidence));
        assert_eq!(DropBackoff::decode(&[0; 16]), None);
    }

    #[tokio::test]
    async fn status_counts_every_address_deferred_whatever_the_cycle_decided() {
        // Addresses deferred in one cycle are counted by the status of a
        // cycle that decided none of them, as while more waits to be decided
        // than a cycle holds: by their latest reasons, since they were first
        // deferred.
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        census_nodes(&mut producer, 8);
        let listings: Vec<Listing> = (0..300)
            .map(|n| showing_block(numbered(n), 81_950_000))
            .collect();
        serve(&mut producer, &listings, 2);
        producer.start_requests();
        producer.cycles += 1;
        let mut tally = Tally::default();
        producer
            .decide_all(Source::All, AT, None, false, &mut tally)
            .await
            .unwrap();
        assert_eq!(tally.groups.get("below_quorum"), Some(&(300, AT)));
        // A row from before reasons were kept.
        {
            let mut txn = producer.store.env().write_txn().unwrap();
            producer
                .since
                .put(
                    &mut txn,
                    &tagged(DEFERRED_TAG, &numbered(9_999)),
                    &(AT - 60),
                )
                .unwrap();
            txn.commit().unwrap();
        }
        let groups = |status: &Status| -> Vec<(String, u64, u64)> {
            status
                .deferred
                .iter()
                .map(|group| (group.reason.clone(), group.addresses, group.oldest_since))
                .collect()
        };
        let before = Counters::now(&producer.chain);
        let status = producer
            .status(
                AT + 60,
                std::time::Instant::now(),
                before,
                false,
                0,
                &Tally::default(),
            )
            .unwrap();
        assert_eq!(
            groups(&status),
            [
                ("below_quorum".to_string(), 300, AT),
                ("other".to_string(), 1, AT - 60)
            ]
        );
        // Deciding them again keeps when they were first deferred.
        producer.cycles += 1;
        producer
            .decide_all(Source::All, AT + 120, None, false, &mut Tally::default())
            .await
            .unwrap();
        let status = producer
            .status(
                AT + 120,
                std::time::Instant::now(),
                before,
                false,
                0,
                &Tally::default(),
            )
            .unwrap();
        assert_eq!(groups(&status), [("below_quorum".to_string(), 300, AT)]);
        // A cycle that decided nothing gives what an index read that finds
        // too few nodes gives.
        let mut too_few = Tally::default();
        too_few.groups.insert("nodes_unanswered", (5, AT + 180));
        let status = producer
            .status(
                AT + 180,
                std::time::Instant::now(),
                before,
                true,
                0,
                &too_few,
            )
            .unwrap();
        assert_eq!(
            groups(&status),
            [("nodes_unanswered".to_string(), 5, AT + 180)]
        );
        // Every reason is kept as it is, in its row or, as an earlier version
        // kept it, in the top byte of the time's.
        for reason in DEFERRAL_REASONS {
            let code = reason_code(reason);
            assert_eq!(deferral_of(AT, Some(code)), (AT, reason));
            assert_eq!(deferral_of(AT | (code << 56), None), (AT, reason));
            assert_eq!(deferral_of(AT | (code << 56), Some(1)), (AT, reason));
        }
        assert_eq!(reason_code("not a reason"), reason_code("other"));
        assert_eq!(deferral_of(AT, None), (AT, "other"));
    }

    /// The deferrals' rows ([`DEFERRED_TAG`]) and their reason rows
    /// ([`REASON_TAG`]), each by address, with their values.
    fn deferral_rows(producer: &Producer) -> (BTreeMap<XorName, u64>, BTreeMap<XorName, u64>) {
        let txn = producer.store.env().read_txn().unwrap();
        let rows = |tag: u8| -> BTreeMap<XorName, u64> {
            producer
                .since
                .prefix_iter(&txn, &[tag])
                .unwrap()
                .map(|row| {
                    let (key, value) = row.unwrap();
                    (XorName::try_from(&key[1..]).unwrap(), value)
                })
                .collect()
        };
        (rows(DEFERRED_TAG), rows(REASON_TAG))
    }

    /// What the version of the producer from before reasons were kept does
    /// with the deferrals' rows after a cycle at `at` that deferred
    /// `deferred` and nothing else, as its `update_since` does: each of them
    /// keeps the time its row holds, or is given `at`, and every other
    /// deferral's row goes; it knows of no reason rows. Returns the oldest of
    /// their times, as it publishes it (`oldest_since`): the rows read as
    /// Unix seconds.
    fn defer_without_reasons(producer: &Producer, deferred: &[XorName], at: u64) -> u64 {
        let (rows, _) = deferral_rows(producer);
        let mut txn = producer.store.env().write_txn().unwrap();
        for address in rows.keys().filter(|address| !deferred.contains(address)) {
            producer
                .since
                .delete(&mut txn, &tagged(DEFERRED_TAG, address))
                .unwrap();
        }
        let mut oldest = u64::MAX;
        for address in deferred {
            let row = tagged(DEFERRED_TAG, address);
            let since = if let Some(since) = producer.since.get(&txn, &row).unwrap() {
                since
            } else {
                producer.since.put(&mut txn, &row, &at).unwrap();
                at
            };
            oldest = oldest.min(since);
        }
        txn.commit().unwrap();
        oldest
    }

    /// `status.json`'s deferrals for a cycle at `at` that decided none of
    /// them: each reason, how many and since when.
    fn deferred_groups(producer: &mut Producer, at: u64) -> Vec<(String, u64, u64)> {
        let before = Counters::now(&producer.chain);
        producer
            .status(
                at,
                std::time::Instant::now(),
                before,
                false,
                0,
                &Tally::default(),
            )
            .unwrap()
            .deferred
            .iter()
            .map(|group| (group.reason.clone(), group.addresses, group.oldest_since))
            .collect()
    }

    #[tokio::test]
    async fn deferrals_are_read_as_seconds_by_a_version_without_reasons_and_back() {
        // Deferrals as this producer's earlier version kept them, each with
        // its reason's code in the top byte of its time, are read in that form
        // too, and kept as the time alone once the producer opens, the code in
        // a row of its own. Then a rollback to the version from before reasons
        // were kept, which reads every row as Unix seconds, and forward again.
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        census_nodes(&mut producer, 8);
        let mut addresses: Vec<XorName> = (0..300).map(numbered).collect();
        addresses.sort_unstable();
        let listings: Vec<Listing> = addresses
            .iter()
            .map(|address| showing_block(*address, 81_950_000))
            .collect();
        serve(&mut producer, &listings, 2);
        producer.start_requests();
        producer.cycles += 1;
        producer
            .decide_all(Source::All, AT, None, false, &mut Tally::default())
            .await
            .unwrap();
        let below_quorum = reason_code("below_quorum");
        let (rows, reasons) = deferral_rows(&producer);
        assert_eq!((rows.len(), reasons.len()), (300, 300));
        assert!(rows.values().all(|since| *since == AT));
        assert!(reasons.values().all(|code| *code == below_quorum));

        // As the earlier version wrote them: the code in the top byte, and no
        // reason rows; a third deferred for another reason.
        let chain_unread = reason_code("chain_unread");
        let code_of = |n: usize| {
            if n.is_multiple_of(3) {
                chain_unread
            } else {
                below_quorum
            }
        };
        {
            let mut txn = producer.store.env().write_txn().unwrap();
            for (n, address) in addresses.iter().enumerate() {
                producer
                    .since
                    .put(
                        &mut txn,
                        &tagged(DEFERRED_TAG, address),
                        &(AT | (code_of(n) << 56)),
                    )
                    .unwrap();
                producer
                    .since
                    .delete(&mut txn, &tagged(REASON_TAG, address))
                    .unwrap();
            }
            txn.commit().unwrap();
        }
        let both = vec![
            ("below_quorum".to_string(), 200, AT),
            ("chain_unread".to_string(), 100, AT),
        ];
        assert_eq!(deferred_groups(&mut producer, AT + 60), both);
        // Opened again, each row holds the time alone, and its reason is in
        // its own row.
        drop(producer);
        let (mut producer, _node) = offline_producer(dir.path()).await;
        let (rows, reasons) = deferral_rows(&producer);
        assert_eq!(rows.len(), 300);
        assert!(rows.values().all(|since| *since == AT));
        for (n, address) in addresses.iter().enumerate() {
            assert_eq!(reasons.get(address), Some(&code_of(n)));
        }
        assert_eq!(deferred_groups(&mut producer, AT + 120), both);

        // Rolled back to the version from before reasons were kept: it reads
        // each row as Unix seconds. Its cycle defers the first half of them,
        // and an address of its own, and ends every other deferral.
        let other = numbered(9_999);
        let mut deferred = addresses[..150].to_vec();
        deferred.push(other);
        assert_eq!(defer_without_reasons(&producer, &deferred, AT + 600), AT);
        drop(producer);

        // Forward again: the reasons of the deferrals it ended go, and its
        // own deferral reads as `other` until its address is decided again.
        let (mut producer, _node) = offline_producer(dir.path()).await;
        let (rows, reasons) = deferral_rows(&producer);
        assert_eq!((rows.len(), reasons.len()), (151, 150));
        assert!(reasons.keys().all(|address| rows.contains_key(address)));
        assert_eq!(rows.get(&other), Some(&(AT + 600)));
        assert_eq!(
            deferred_groups(&mut producer, AT + 660),
            [
                ("below_quorum".to_string(), 100, AT),
                ("chain_unread".to_string(), 50, AT),
                ("other".to_string(), 1, AT + 600),
            ]
        );
        // Deciding every address again: each is below a quorum, since it was
        // first deferred, those deferred throughout since then; and the
        // address no node serves is deferred no more.
        census_nodes(&mut producer, 8);
        serve(&mut producer, &listings, 2);
        producer.start_requests();
        producer.cycles += 1;
        producer
            .decide_all(Source::All, AT + 720, None, false, &mut Tally::default())
            .await
            .unwrap();
        let (rows, reasons) = deferral_rows(&producer);
        assert_eq!((rows.len(), reasons.len()), (300, 300));
        assert!(reasons.values().all(|code| *code == below_quorum));
        for (n, address) in addresses.iter().enumerate() {
            let since = if n < 150 { AT } else { AT + 720 };
            assert_eq!(rows.get(address), Some(&since));
        }
        assert_eq!(
            deferred_groups(&mut producer, AT + 780),
            [("below_quorum".to_string(), 300, AT)]
        );
    }

    #[tokio::test]
    async fn listings_whose_payment_isnt_on_the_chain_cost_a_log_query_a_cycle() {
        // Fault injection: listings showing only their quote, served by all 7
        // of their nearest nodes (out of spec, or colluding), whose payment no
        // log holds. Each is "try again", so decided every cycle: after the
        // first, whole, search, each costs a log query a cycle; and a batch
        // with no time left begins one and leaves the rest for the next.
        use crate::data::client::listings::test_chain::{serve as serve_rpc, MockChain, VAULT};
        use ant_listings::Payment;
        let k: u64 = 16;
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        // Blocks every 2 s up to just after the quotes' time, logs answered
        // 10,000 blocks at a time at most, the last thousand not final.
        let mut mock = MockChain::with_blocks(700_000, 1_789_700_000);
        mock.max_log_range = Some(10_000);
        mock.finalized = Some(699_000);
        let mock = Arc::new(Mutex::new(mock));
        let url = serve_rpc(Arc::clone(&mock)).await;
        producer.chain = ListingChain::with_rpc(url, VAULT)
            .unwrap()
            .unpaced()
            .with_vault_deployment_block(1)
            .with_store(&producer.store)
            .unwrap();
        census_nodes(&mut producer, 8);
        let quote_time: u64 = 1_791_000_000;
        let identity = ant_protocol::transport::NodeIdentity::generate().unwrap();
        let (map, _) = self_encryption::encrypt(bytes::Bytes::from(vec![3u8; 4_000])).unwrap();
        let mut listings = Vec::new();
        for n in 0..k {
            let metadata = Metadata {
                name: Some(format!("made-up-{n}")),
                ..Metadata::default()
            };
            let envelope = Envelope::readable(
                &map,
                metadata,
                ShownFields::NONE.with(PaymentField::Quote),
                true,
            )
            .unwrap();
            let address = envelope.address();
            producer.chain.keep_envelope(&address, &envelope.to_bytes());
            let mut quote = ant_protocol::evm::PaymentQuote {
                content: xor_name::XorName(address),
                timestamp: UNIX_EPOCH + Duration::from_secs(quote_time),
                price: ant_protocol::evm::Amount::from(20u64),
                rewards_address: ant_protocol::evm::RewardsAddress::new([20u8; 20]),
                pub_key: identity.public_key().as_bytes().to_vec(),
                signature: Vec::new(),
                committed_key_count: 0,
                commitment_pin: None,
            };
            quote.signature = identity
                .sign(&quote.bytes_for_sig())
                .unwrap()
                .as_bytes()
                .to_vec();
            let payment = Payment {
                tx_hash: [9; 32],
                block_number: 150,
                block_timestamp: quote_time + 60,
                log_index: 4,
                quote: rmp_serde::to_vec(&quote).unwrap(),
            };
            listings.push(Listing::new(&envelope, &payment, quote_time + 3_600));
        }
        serve(&mut producer, &listings, NEAREST_NODES);
        producer.start_requests();
        let log_queries = || mock.lock().unwrap().calls_to("eth_getLogs");
        // The first cycle after a start decides every address: a whole
        // search for each.
        producer.cycles += 1;
        let mut tally = Tally::default();
        producer
            .decide_all(Source::All, unix_now(), None, false, &mut tally)
            .await
            .unwrap();
        assert_eq!(
            tally.groups.get("not_on_chain_yet").map(|group| group.0),
            Some(k)
        );
        let first = log_queries();
        assert!(first > 10 * k as usize, "{first}");
        for cycle in 0..3 {
            producer.cycles += 1;
            let before = log_queries();
            let mut drops = DropCheck {
                checked: false,
                deadline: Instant::now() + CYCLE,
            };
            let decided = producer
                .decide_changed(
                    unix_now(),
                    Instant::now() + CYCLE,
                    &mut drops,
                    &mut Tally::default(),
                )
                .await
                .unwrap();
            assert_eq!(decided, k, "cycle {cycle}");
            let queries = log_queries() - before;
            assert!(queries <= k as usize, "cycle {cycle}: {queries}");
        }
        // With no time left, one is begun, and the rest wait for the next
        // cycle.
        producer.cycles += 1;
        let mut drops = DropCheck {
            checked: false,
            deadline: Instant::now(),
        };
        let decided = producer
            .decide_changed(
                unix_now(),
                Instant::now(),
                &mut drops,
                &mut Tally::default(),
            )
            .await
            .unwrap();
        assert_eq!(decided, 1);
        assert_eq!(producer.feeds.pending_count().unwrap(), k - 1);
    }
}
