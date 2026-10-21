//! Following what each node serves, for the listings producer
//! ([`Producer`](super::listings_serve::Producer)): a mirror of each census
//! node's part of the index, kept in the producer's store, and the set of
//! addresses whose copies changed.
//!
//! **Nodes with the change feed** (the feed release,
//! [`FEED_RELEASE`](super::listings_census::FEED_RELEASE) on) are followed
//! with `MirrorSync` (`listings_mirror`), `ant-listings`'s reader state
//! machine ([`FeedSync`](ant_listings::FeedSync)) with the mirror's entries
//! kept in the store instead of in memory. It checks every answer and push
//! as that crate defines (sequence numbers, ranges, one record per address,
//! counts and set hashes, peers against the view) and bounds what a node
//! can make the reader take. Each node is asked about its own leaf only
//! ([`FeedNode::range`]):
//!
//! - the first time, it is asked where its feed stands, and the range is read
//!   afresh with `RangeListRequest`s;
//! - from then on, each round asks for the changes after the mirror's head
//!   (`ChangesRequest`), page by page while the node has more, and once the
//!   mirror reaches the node's head, checks the node's count and set hash for
//!   the range against the mirror's;
//! - a new epoch, a head behind the mirror's, or a count or set hash that
//!   doesn't match reads the range afresh.
//!
//! Every `ChangesRequest` sets a watch, so the node pushes its new records in
//! the range as they commit: a push that brings the mirror exactly to the
//! node's new head is applied at once ([`Feeds::push`]); any other is left to
//! the next request. Each request replaces the node's last watch, so there is
//! one watch per node from the producer, renewed by the round's first
//! request every [`CYCLE`](super::listings_serve::CYCLE), well within the
//! node's [`WATCH_LEASE`](ant_listings::WATCH_LEASE). A node that already
//! has [`MAX_WATCHERS`](ant_listings::MAX_WATCHERS) other watchers refuses
//! the watch without saying so; its next poll finds every change anyway. On
//! a stop, the producer ends its watches ([`Feeds::unwatch_requests`]), so
//! they don't hold a place among each node's watchers until they lapse.
//!
//! **Nodes without it** are read with listings v2 requests
//! (`ListRequest`), one a round: the next page of a full pass of their index,
//! a new pass starting at most once every [`V2_PASS_INTERVAL`], or between
//! passes a read from the key after the newest listing seen from the node.
//! Copies from a pass's pages count at once; one the node no longer serves
//! leaves the mirror when a pass that reached the end of its index didn't
//! see it. A node whose user agent shows the feed release but that refuses a
//! feed request as `unsupported`, never answers one, or answers its feed
//! requests only with errors (its feed can't be read, as until it starts
//! again after failing to number or total it), is read this way too, from
//! the same round on, and asked for its feed again after
//! [`V2_PASS_INTERVAL`].
//!
//! **What counts.** A node's copies count in a cycle ([`NodeRead::counts`])
//! when it is in sync: it answered this round, and its mirror is at the head
//! it reported with the count and set hash it reported
//! (`MirrorSync::in_sync`). A node read with v2 requests counts when it
//! answered this round's request with a page the checks take; its mirror then
//! holds what its pages showed. Only entries in the node's own range are
//! kept, and only listings that pass [`Listing::validate`]
//! (`ant_listings::Listing`) are taken from v2 pages, as
//! [`merge_copies`](ant_listings::merge_copies) would leave the rest out.
//!
//! **Faulty and out-of-spec nodes.** Nothing a node sends is taken on
//! trust:
//!
//! - every answer and push is checked as `ant-listings` checks it, and one
//!   the checks refuse ends that node's round and changes nothing;
//! - an answer carries at most [`MAX_LIST_LIMIT`] records, and a node is
//!   asked for at most its allowance of pages a round, and its mirror holds
//!   at most its allowance of entries, as an index walk reads a node:
//!   [`WALK_FREE_LISTINGS`] entries, and [`WALK_PER_BACKED`] more for each
//!   entry it holds whose address at least [`QUORUM_THRESHOLD`] of the
//!   census's [`NEAREST_NODES`] nodes nearest it serve, where it is among the
//!   [`WALK_EARNING_RANKS`] nearest. Pushes count against the same pages;
//! - a node's answers change only its own mirror, only within its own range;
//!   what it says of other nodes (the `view` hash and `peers` of an answer)
//!   is kept as a hint for the census ([`Feeds::view`],
//!   [`Feeds::view_peers`]), which must find such nodes itself before they
//!   join it. Nothing here adds a node.
//!
//! **What the producer calls.** Each cycle:
//!
//! 1. [`Feeds::poll`] with every census node ([`FeedNode`]: its leaf, whether
//!    its user agent shows the feed release, whether to ask for its peers),
//!    a deadline for the round, and the receiver of the pushes its
//!    `ListingsRequests` routes (pushes that come during the round are taken
//!    as they come). It reads every node, at most
//!    [`POLL_CONCURRENCY`] requests at once.
//! 2. For the guard and support: [`Feeds::read`] says how each node's round
//!    went (answered, counts, complete); [`Feeds::copies`] gives an address's
//!    copies from those of its nearest nodes whose copies count, as digest
//!    entries (the full listing comes from a `GetRequest`, checked with
//!    [`DigestEntry::describes`]); [`Feeds::holders`] every node whose mirror
//!    holds it, counting or not.
//! 3. The addresses whose copies changed since they were last settled, in
//!    any mirror, by an answer, a push, a node leaving or changing range or
//!    way of reading, or a node's copies starting or ceasing to count
//!    ([`Feeds::pending_after`], a batch at a time; [`Feeds::is_pending`]).
//! 4. Once what it decided from them is published, [`Feeds::settle`] with
//!    those addresses.
//!
//! Between cycles, it passes each push its `ListingsRequests` routes to
//! [`Feeds::push`]: the addresses a push changes become pending, to be
//! decided at once.
//!
//! **Memory.** Everything that grows with the index is in the producer's
//! store ([`ListingsStore`]): each node's entries ([`ENTRIES_DB`], and
//! [`HELD_DB`] by address), the pending addresses ([`CHANGED_DB`]), which
//! nodes each backed address credits ([`BACKING_DB`]) and what a v2 pass has
//! seen ([`SEEN_DB`]). In memory are only each node's place in its feed and
//! round, its count of entries and their set hash, and its count of backed
//! entries: a few hundred bytes a node, whatever the index holds. Each
//! answer and push is applied in one write transaction, with the node's
//! record ([`NODES_DB`]), so the store always holds a mirror and the place
//! in the feed it reflects: a restart follows each node's feed on from
//! where the mirror stood, with a `ChangesRequest`, not a fresh read of the
//! range. A v2 pass in progress is not kept: after a restart, the next
//! starts once [`V2_PASS_INTERVAL`] has passed since it began.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::ops::Bound;

use ant_listings::{
    check_list_page, AddressRange, ChangesRequest, ChangesResponse, DigestEntry, FeedOutcome,
    ListingKey, ListingsBody, Pushed, SetHash, MAX_LIST_LIMIT, NEAREST_NODES, QUORUM_THRESHOLD,
    WALK_EARNING_RANKS, WALK_FREE_LISTINGS, WALK_PER_BACKED,
};
use ant_protocol::transport::PeerId;
use ant_protocol::XorName;
use futures::stream::{FuturesUnordered, StreamExt};
use heed::types::Bytes;
use heed::{Database, RoTxn, RwTxn};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use super::listings::ListingsRequests;
use super::listings_census::Census;
use super::listings_mirror::{Entries, MirrorSync};
use super::listings_serve::{POLL_CONCURRENCY, V2_PASS_INTERVAL};
use super::listings_store::{store_error, ListingsStore};
use crate::data::error::{Error, Result};

/// Each node's way of reading and where its mirror stands, by node id.
pub const NODES_DB: &str = "serve_feed_nodes";

/// Each node's mirror: the node id and the address, to the entry.
pub const ENTRIES_DB: &str = "serve_feed_entries";

/// The same mirrors by address: the address and the node id (no value), to
/// find every node holding an address, and every address held, in address
/// order.
pub const HELD_DB: &str = "serve_feed_held";

/// The addresses whose copies changed and that are not settled yet.
pub const CHANGED_DB: &str = "serve_feed_changed";

/// For each backed address, the nodes among its [`WALK_EARNING_RANKS`]
/// nearest whose mirrors hold it: the address, to their ids, 32 bytes each.
pub const BACKING_DB: &str = "serve_feed_backing";

/// The addresses each node read with v2 requests showed in its pass in
/// progress: the node id and the address (no value).
pub const SEEN_DB: &str = "serve_feed_seen";

/// What a node answers a request of a kind it doesn't know (darwin-node's
/// listings service): a node that answers a feed request so doesn't keep a
/// feed, whatever its user agent says.
const UNSUPPORTED: &str = "unsupported";

/// The entries a full page counts for against a node's allowance.
const PAGE: usize = MAX_LIST_LIMIT as usize;

/// How many rows are read at a time when a mirror or a table is scanned: a
/// page's worth.
const SCAN: usize = PAGE;

/// An entry's bytes in [`ENTRIES_DB`], after the node id and address of the
/// key: time, block number and log index (8 bytes each, big-endian), whether
/// it has a `first_seen` (1 byte) and the `first_seen` (8 bytes, 0 if none),
/// and the digest (32 bytes).
const ENTRY_LEN: usize = 8 * 3 + 1 + 8 + 32;

/// The receiving end of the pushes a producer's `ListingsRequests` routes,
/// each with the node it came from.
pub use super::listings::PushReceiver;

/// Sends listings requests to nodes: the producer's `ListingsRequests`, or a
/// stand-in in tests.
pub trait FeedIo: Sync {
    /// Send `body` to `peer` and wait for its answer, or `None` if none
    /// came in time. An [`Error`](ListingsBody::Error) is the answer it is.
    fn ask(
        &self,
        peer: &PeerId,
        body: ListingsBody,
    ) -> impl Future<Output = Option<ListingsBody>> + Send;
}

impl FeedIo for ListingsRequests {
    fn ask(
        &self,
        peer: &PeerId,
        body: ListingsBody,
    ) -> impl Future<Output = Option<ListingsBody>> + Send {
        ListingsRequests::ask(self, peer, body)
    }
}

/// Which nodes are nearest an address: the census, or a stand-in in tests.
pub trait NearestNodes {
    /// The `n` nodes nearest `address` by XOR distance, nearest first.
    fn nearest(&self, address: &XorName, n: usize) -> Vec<PeerId>;
}

impl NearestNodes for Census {
    fn nearest(&self, address: &XorName, n: usize) -> Vec<PeerId> {
        Census::nearest(self, address, n)
    }
}

/// A census node, as the producer gives it to [`Feeds::poll`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedNode {
    /// The node.
    pub peer: PeerId,
    /// The range it is asked about: its leaf
    /// ([`Census::leaf_of`] its id).
    pub range: AddressRange,
    /// Whether its user agent shows the feed release
    /// ([`Census::supports_feed`]).
    pub feed: bool,
    /// Whether to ask it for its nearest peers this round, such as after
    /// its view hash changed ([`Feeds::view`]).
    pub want_peers: bool,
}

impl FeedNode {
    /// Every node of `census`, in id order, as [`Feeds::poll`] takes them:
    /// each asked about its own leaf, through its feed where its user agent
    /// shows the release, and asked for its peers where `want_peers` says.
    pub fn from_census(census: &Census, want_peers: impl Fn(&PeerId) -> bool) -> Vec<Self> {
        census
            .nodes()
            .map(|node| Self {
                peer: node.peer,
                range: census.leaf_of(node.peer.as_bytes()),
                feed: census.supports_feed(&node.peer),
                want_peers: want_peers(&node.peer),
            })
            .collect()
    }
}

/// How a node is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadKind {
    /// Through its change feed.
    Feed,
    /// With listings v2 requests.
    V2,
}

/// How a node's latest round went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRead {
    /// How it was read.
    pub kind: ReadKind,
    /// Whether it answered this round with answers the checks took: of the
    /// kind asked for, none refused. Only then does it count as answering,
    /// for the census and the cycle's guard.
    pub answered: bool,
    /// Whether it sent any answer this round, whatever the checks made of
    /// it.
    pub replied: bool,
    /// Whether its copies count this cycle: in sync with its feed, or for a
    /// node read with v2 requests, it answered this round's request with a
    /// page the checks take.
    pub counts: bool,
    /// Whether its copies count and its mirror holds everything it served in
    /// its range when last read in full: in sync with its feed, or for a node
    /// read with v2 requests, its latest finished pass reached the end of its
    /// index with room for every entry. Only then does a copy missing from
    /// the mirror say the node serves none.
    pub complete: bool,
    /// For a node read through its feed, how its round ended.
    pub outcome: Option<FeedOutcome>,
    /// Why its answer was refused, if it was.
    pub problem: Option<String>,
    /// Whether it was read with v2 requests this round although its user
    /// agent shows the feed release: it refused a feed request, or never
    /// answered one.
    pub fell_back: bool,
    /// How many entries its mirror holds.
    pub entries: usize,
}

impl NodeRead {
    fn new(kind: ReadKind) -> Self {
        Self {
            kind,
            answered: false,
            replied: false,
            counts: false,
            complete: false,
            outcome: None,
            problem: None,
            fell_back: false,
            entries: 0,
        }
    }
}

/// What a round of [`Feeds::poll`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollReport {
    /// The nodes read.
    pub nodes: usize,
    /// Those read through their feed.
    pub feed: usize,
    /// Those read with listings v2 requests.
    pub v2: usize,
    /// Those that answered a request, whatever the checks made of the
    /// answer.
    pub answered: usize,
    /// Those whose copies count this cycle.
    pub counting: usize,
    /// Those whose answer the checks refused.
    pub refused: usize,
    /// Those read with v2 requests although their user agent shows the feed
    /// release.
    pub fell_back: usize,
    /// Pushes applied during the round.
    pub pushes: usize,
    /// Addresses waiting to be settled after the round.
    pub pending: usize,
}

/// The databases [`Feeds`] keeps the mirrors in.
#[derive(Debug, Clone, Copy)]
struct Dbs {
    nodes: Database<Bytes, Bytes>,
    entries: Database<Bytes, Bytes>,
    held: Database<Bytes, Bytes>,
    changed: Database<Bytes, Bytes>,
    backing: Database<Bytes, Bytes>,
    seen: Database<Bytes, Bytes>,
}

impl Dbs {
    fn open(store: &ListingsStore) -> Result<Self> {
        Ok(Self {
            nodes: store.database(NODES_DB)?,
            entries: store.database(ENTRIES_DB)?,
            held: store.database(HELD_DB)?,
            changed: store.database(CHANGED_DB)?,
            backing: store.database(BACKING_DB)?,
            seen: store.database(SEEN_DB)?,
        })
    }

    /// `peer`'s entry for `address`.
    fn entry(
        &self,
        txn: &RoTxn,
        peer: &PeerId,
        address: &XorName,
    ) -> heed::Result<Option<DigestEntry>> {
        Ok(self
            .entries
            .get(txn, &entry_key(peer, address))?
            .and_then(|bytes| decode_entry(*address, bytes)))
    }

    /// Up to `limit` of the addresses `peer`'s mirror holds from `from`
    /// through `through`, in order.
    fn scan(
        &self,
        txn: &RoTxn,
        peer: &PeerId,
        from: Bound<XorName>,
        through: &XorName,
        limit: usize,
    ) -> heed::Result<Vec<XorName>> {
        let low = match from {
            Bound::Included(address) => Bound::Included(entry_key(peer, &address)),
            Bound::Excluded(address) => Bound::Excluded(entry_key(peer, &address)),
            Bound::Unbounded => Bound::Included(entry_key(peer, &[0; 32])),
        };
        let high = entry_key(peer, through);
        if match &low {
            Bound::Included(low) => low > &high,
            Bound::Excluded(low) => low >= &high,
            Bound::Unbounded => false,
        } {
            return Ok(Vec::new());
        }
        let low = match &low {
            Bound::Included(key) => Bound::Included(&key[..]),
            Bound::Excluded(key) => Bound::Excluded(&key[..]),
            Bound::Unbounded => Bound::Unbounded,
        };
        let range = (low, Bound::Included(&high[..]));
        let mut addresses = Vec::new();
        for row in self.entries.range(txn, &range)? {
            if addresses.len() == limit {
                break;
            }
            let (key, _) = row?;
            if let Some((_, address)) = split_key(key) {
                addresses.push(address);
            }
        }
        Ok(addresses)
    }

    /// Every node whose mirror holds `address`, in id order.
    fn holders(&self, txn: &RoTxn, address: &XorName) -> heed::Result<Vec<PeerId>> {
        let mut holders = Vec::new();
        for row in self.held.prefix_iter(txn, address)? {
            let (key, _) = row?;
            if let Some((_, peer)) = split_held(key) {
                holders.push(peer);
            }
        }
        Ok(holders)
    }

    /// Up to `limit` of the addresses some mirror holds, after `after` (or
    /// from the first), each once, in order.
    fn held_after(
        &self,
        txn: &RoTxn,
        after: Option<&XorName>,
        limit: usize,
    ) -> heed::Result<Vec<XorName>> {
        let mut addresses: Vec<XorName> = Vec::new();
        // Past every row of an address: its id, then the largest node id.
        let past = |address: &XorName| held_key(address, &PeerId::from_bytes([0xff; 32]));
        let mut from: Option<[u8; 64]> = after.map(past);
        while addresses.len() < limit {
            let range = match &from {
                Some(key) => (Bound::Excluded(&key[..]), Bound::Unbounded),
                None => (Bound::Unbounded, Bound::Unbounded),
            };
            let Some(row) = self.held.range(txn, &range)?.next() else {
                break;
            };
            let (key, _) = row?;
            let Some((address, _)) = split_held(key) else {
                break;
            };
            addresses.push(address);
            from = Some(past(&address));
        }
        Ok(addresses)
    }

    /// Up to `limit` of the pending addresses after `after` (or from the
    /// first), in order.
    fn pending_after(
        &self,
        txn: &RoTxn,
        after: Option<&XorName>,
        limit: usize,
    ) -> heed::Result<Vec<XorName>> {
        let range = match after {
            Some(after) => (Bound::Excluded(&after[..]), Bound::Unbounded),
            None => (Bound::Unbounded, Bound::Unbounded),
        };
        let mut addresses = Vec::new();
        for row in self.changed.range(txn, &range)? {
            if addresses.len() == limit {
                break;
            }
            let (key, _) = row?;
            if let Ok(address) = XorName::try_from(key) {
                addresses.push(address);
            }
        }
        Ok(addresses)
    }

    /// Every node with rows in [`ENTRIES_DB`], in id order.
    fn entry_peers(&self, txn: &RoTxn) -> heed::Result<Vec<PeerId>> {
        let mut peers = Vec::new();
        let mut from = [0u8; 64];
        let mut first = true;
        loop {
            let range = if first {
                (Bound::Included(&from[..]), Bound::Unbounded)
            } else {
                (Bound::Excluded(&from[..]), Bound::Unbounded)
            };
            let Some(row) = self.entries.range(txn, &range)?.next() else {
                break;
            };
            let (key, _) = row?;
            let Some((peer, _)) = split_key(key) else {
                break;
            };
            peers.push(peer);
            from = entry_key(&peer, &[0xff; 32]);
            first = false;
        }
        Ok(peers)
    }

    /// The count and set hash of `peer`'s entries in `range`. Any outside
    /// it are deleted, a chunk at a time, each chunk committed.
    fn tally(
        &self,
        env: &heed::Env<heed::WithoutTls>,
        peer: &PeerId,
        range: AddressRange,
    ) -> heed::Result<(u64, SetHash)> {
        let mut count = 0;
        let mut set_hash = SetHash::EMPTY;
        let mut from = Bound::Unbounded;
        loop {
            let mut txn = env.write_txn()?;
            let chunk = self.scan(&txn, peer, from, &[0xff; 32], SCAN)?;
            let Some(last) = chunk.last().copied() else {
                return Ok((count, set_hash));
            };
            for address in &chunk {
                match self.entry(&txn, peer, address)? {
                    Some(entry) if range.contains(address) => {
                        count += 1;
                        set_hash.insert(&entry);
                    }
                    _ => {
                        self.entries.delete(&mut txn, &entry_key(peer, address))?;
                        self.held.delete(&mut txn, &held_key(address, peer))?;
                    }
                }
            }
            txn.commit()?;
            if chunk.len() < SCAN {
                return Ok((count, set_hash));
            }
            from = Bound::Excluded(last);
        }
    }
}

/// Which nodes each backed address credits, and how many backed entries
/// each node holds: what a node's allowance grows with. The nodes each
/// address credits are in the store ([`BACKING_DB`]); only the counts, a
/// number a node, are in memory.
#[derive(Debug, Default)]
struct Backing {
    /// For each node, how many backed addresses credit it.
    counts: HashMap<PeerId, usize>,
    /// The nodes whose counts changed since they were last taken.
    affected: BTreeSet<PeerId>,
}

impl Backing {
    fn count(&self, peer: &PeerId) -> usize {
        self.counts.get(peer).copied().unwrap_or(0)
    }

    /// Count `address` again from what the mirrors hold: the nodes among
    /// its [`WALK_EARNING_RANKS`] nearest whose mirrors hold it, if at least
    /// [`QUORUM_THRESHOLD`] of its [`NEAREST_NODES`] nearest do.
    fn recount<C: NearestNodes + ?Sized>(
        &mut self,
        txn: &mut RwTxn,
        dbs: Dbs,
        census: &C,
        address: &XorName,
    ) -> heed::Result<()> {
        let near = census.nearest(address, WALK_EARNING_RANKS);
        let mut holds = Vec::with_capacity(near.len());
        for peer in &near {
            holds.push(dbs.entries.get(txn, &entry_key(peer, address))?.is_some());
        }
        let support = holds
            .iter()
            .take(NEAREST_NODES)
            .filter(|held| **held)
            .count();
        let credited: Vec<PeerId> = if support >= QUORUM_THRESHOLD {
            near.iter()
                .zip(&holds)
                .filter(|(_, held)| **held)
                .map(|(peer, _)| *peer)
                .collect()
        } else {
            Vec::new()
        };
        let old: Vec<PeerId> = dbs
            .backing
            .get(txn, address)?
            .map(decode_peers)
            .unwrap_or_default();
        if old == credited {
            return Ok(());
        }
        for peer in &old {
            if let Some(count) = self.counts.get_mut(peer) {
                *count = count.saturating_sub(1);
            }
        }
        for peer in &credited {
            *self.counts.entry(*peer).or_default() += 1;
        }
        self.affected.extend(old.iter().chain(&credited).copied());
        if credited.is_empty() {
            dbs.backing.delete(txn, address)?;
        } else {
            dbs.backing.put(txn, address, &encode_peers(&credited))?;
        }
        Ok(())
    }
}

/// One node's mirror in the store, as its [`MirrorSync`] or v2 read reads
/// and writes it, in a write transaction: each address whose entry changes
/// becomes pending and has its backing counted again.
///
/// Work that touches many addresses, such as emptying a mirror, is
/// committed a chunk at a time ([`SCAN`] touched addresses), so a write
/// transaction never holds more than a chunk of changes. The first such
/// commit deletes the node's record, so a process stopped part way leaves
/// a mirror without a record, which [`Feeds::open`] drops, and the node is
/// read afresh; the caller writes the record again with what the work left
/// ([`Self::finish`]). The first store error stops every later read and
/// write, and the caller fails.
struct StoreEntries<'a, C: ?Sized> {
    env: &'a heed::Env<heed::WithoutTls>,
    txn: Option<RwTxn<'a>>,
    dbs: Dbs,
    peer: PeerId,
    census: &'a C,
    backing: &'a mut Backing,
    error: RefCell<Option<heed::Error>>,
    /// Whether anything was written: an entry, or what a pass saw.
    changed: bool,
    /// Addresses touched since the last commit.
    touched: usize,
    /// Whether part of the work was committed, the node's record deleted.
    checkpointed: bool,
}

/// What a [`StoreEntries`] did.
#[derive(Debug, Clone, Copy)]
struct Done {
    /// Whether anything was written: an entry, or what a pass saw.
    changed: bool,
    /// Whether part of the work was committed, the node's record deleted.
    checkpointed: bool,
}

impl<'a, C: NearestNodes + ?Sized> StoreEntries<'a, C> {
    fn begin(
        store: &'a ListingsStore,
        dbs: Dbs,
        peer: PeerId,
        census: &'a C,
        backing: &'a mut Backing,
    ) -> Result<Self> {
        let env = store.env();
        let txn = env.write_txn().map_err(store_error)?;
        Ok(Self {
            env,
            txn: Some(txn),
            dbs,
            peer,
            census,
            backing,
            error: RefCell::new(None),
            changed: false,
            touched: 0,
            checkpointed: false,
        })
    }

    fn failed(&self) -> bool {
        self.error.borrow().is_some() || self.txn.is_none()
    }

    fn fail(&self, error: heed::Error) {
        let mut slot = self.error.borrow_mut();
        if slot.is_none() {
            *slot = Some(error);
        }
    }

    /// The transaction, with what this has written in it, and what was
    /// done; or the first store error, if one stopped this.
    fn finish(self) -> Result<(RwTxn<'a>, Done)> {
        if let Some(error) = self.error.into_inner() {
            return Err(store_error(error));
        }
        let done = Done {
            changed: self.changed,
            checkpointed: self.checkpointed,
        };
        match self.txn {
            Some(txn) => Ok((txn, done)),
            None => Err(Error::Storage(
                "listings store: a mirror's transaction was lost".into(),
            )),
        }
    }

    /// Commit what is written so far and go on in a new transaction, the
    /// node's record deleted first (see the type's docs).
    fn checkpoint(&mut self) {
        let Some(mut txn) = self.txn.take() else {
            return;
        };
        let committed = self
            .dbs
            .nodes
            .delete(&mut txn, self.peer.as_bytes())
            .and_then(|_| txn.commit());
        match committed.and_then(|()| self.env.write_txn()) {
            Ok(txn) => {
                self.txn = Some(txn);
                self.touched = 0;
                self.checkpointed = true;
            }
            Err(e) => self.fail(e),
        }
    }

    /// Note that a v2 pass in progress saw `address`.
    fn see(&mut self, address: &XorName) {
        if self.failed() {
            return;
        }
        let Some(txn) = self.txn.as_mut() else {
            return;
        };
        self.changed = true;
        if let Err(e) = self.dbs.seen.put(txn, &entry_key(&self.peer, address), &[]) {
            self.fail(e);
        }
    }

    /// Whether the v2 pass in progress saw `address`.
    fn seen(&self, address: &XorName) -> bool {
        if self.failed() {
            return false;
        }
        let Some(txn) = self.txn.as_ref() else {
            return false;
        };
        match self.dbs.seen.get(txn, &entry_key(&self.peer, address)) {
            Ok(seen) => seen.is_some(),
            Err(e) => {
                self.fail(e);
                false
            }
        }
    }

    /// Forget what any pass of this node saw.
    fn forget_seen(&mut self) {
        if self.failed() {
            return;
        }
        let Some(txn) = self.txn.as_mut() else {
            return;
        };
        self.changed = true;
        if let Err(e) = delete_prefix(txn, self.dbs.seen, self.peer.as_bytes()) {
            self.fail(e);
        }
    }

    /// Remove every entry of the mirror, each touched.
    fn wipe(&mut self) {
        loop {
            let chunk = self.scan(Bound::Unbounded, [0xff; 32], SCAN);
            if chunk.is_empty() || self.failed() {
                break;
            }
            for address in &chunk {
                self.delete(address);
                self.touched(*address);
            }
        }
        self.forget_seen();
    }
}

impl<C: NearestNodes + ?Sized> Entries for StoreEntries<'_, C> {
    fn get(&self, address: &XorName) -> Option<DigestEntry> {
        if self.failed() {
            return None;
        }
        let txn = self.txn.as_ref()?;
        match self.dbs.entry(txn, &self.peer, address) {
            Ok(entry) => entry,
            Err(e) => {
                self.fail(e);
                None
            }
        }
    }

    fn insert(&mut self, entry: DigestEntry) {
        if self.failed() {
            return;
        }
        let Some(txn) = self.txn.as_mut() else {
            return;
        };
        self.changed = true;
        let key = entry_key(&self.peer, &entry.address);
        let held = held_key(&entry.address, &self.peer);
        let result = self
            .dbs
            .entries
            .put(txn, &key, &encode_entry(&entry))
            .and_then(|()| self.dbs.held.put(txn, &held, &[]));
        if let Err(e) = result {
            self.fail(e);
        }
    }

    fn delete(&mut self, address: &XorName) {
        if self.failed() {
            return;
        }
        let Some(txn) = self.txn.as_mut() else {
            return;
        };
        self.changed = true;
        let key = entry_key(&self.peer, address);
        let held = held_key(address, &self.peer);
        let result = self
            .dbs
            .entries
            .delete(txn, &key)
            .and_then(|_| self.dbs.held.delete(txn, &held));
        if let Err(e) = result {
            self.fail(e);
        }
    }

    fn scan(&self, from: Bound<XorName>, through: XorName, limit: usize) -> Vec<XorName> {
        if self.failed() {
            return Vec::new();
        }
        let Some(txn) = self.txn.as_ref() else {
            return Vec::new();
        };
        match self.dbs.scan(txn, &self.peer, from, &through, limit) {
            Ok(addresses) => addresses,
            Err(e) => {
                self.fail(e);
                Vec::new()
            }
        }
    }

    fn touched(&mut self, address: XorName) {
        if self.failed() {
            return;
        }
        let Some(txn) = self.txn.as_mut() else {
            return;
        };
        let result = self
            .dbs
            .changed
            .put(txn, &address, &[])
            .and_then(|()| self.backing.recount(txn, self.dbs, self.census, &address));
        if let Err(e) = result {
            self.fail(e);
            return;
        }
        self.touched += 1;
        if self.touched >= SCAN {
            self.checkpoint();
        }
    }
}

/// A node's mirror: its place in its feed, or its v2 reads. Its entries are
/// in the store.
#[derive(Debug)]
enum Mirror {
    Feed(MirrorSync),
    V2(V2Read),
}

impl Mirror {
    fn new(kind: ReadKind, range: AddressRange) -> Self {
        match kind {
            ReadKind::Feed => Self::Feed(MirrorSync::new(range)),
            ReadKind::V2 => Self::V2(V2Read::default()),
        }
    }

    fn kind(&self) -> ReadKind {
        match self {
            Self::Feed(_) => ReadKind::Feed,
            Self::V2(_) => ReadKind::V2,
        }
    }

    /// How many entries it holds.
    fn len(&self) -> u64 {
        match self {
            Self::Feed(sync) => sync.len(),
            Self::V2(read) => read.count,
        }
    }
}

/// A node read with listings v2 requests: one a round.
#[derive(Debug, Default)]
struct V2Read {
    /// How many entries its pages showed in its range.
    count: u64,
    /// The newest key seen from it.
    newest: Option<ListingKey>,
    /// The pass in progress.
    pass: Option<Pass>,
    /// When the latest pass began (Unix seconds).
    pass_began: Option<u64>,
    /// When the latest finished pass began (Unix seconds).
    finished_began: Option<u64>,
    /// Whether the latest finished pass reached the end of its index with
    /// room for every entry in its range, and every read since had room.
    complete: bool,
    /// Between passes, where the next read carries on from, while the node
    /// has more after the newest key.
    cursor: Option<ListingKey>,
    /// The `from` of the request waiting for its answer.
    asked: Option<ListingKey>,
    /// Whether this round's request has been sent.
    asked_this_round: bool,
    /// Whether it answered this round's request with a page the checks
    /// take.
    answered: bool,
    problem: Option<String>,
}

/// A full pass of a node's index in progress. What it has seen is in the
/// store ([`SEEN_DB`]).
#[derive(Debug)]
struct Pass {
    cursor: ListingKey,
    pages: usize,
    /// Whether an entry in the node's range was left out for want of room.
    capped: bool,
}

impl V2Read {
    fn begin_round(&mut self) {
        self.asked = None;
        self.asked_this_round = false;
        self.answered = false;
        self.problem = None;
    }

    /// This round's request, once a round.
    fn next_request(&mut self, now: u64) -> Option<ListingsBody> {
        if self.asked_this_round {
            return None;
        }
        self.asked_this_round = true;
        let from = if let Some(pass) = &self.pass {
            pass.cursor
        } else if self
            .pass_began
            .is_none_or(|began| now >= began.saturating_add(V2_PASS_INTERVAL.as_secs()))
        {
            self.pass = Some(Pass {
                cursor: ListingKey::MIN,
                pages: 0,
                capped: false,
            });
            self.pass_began = Some(now);
            // Reads between passes start again from the newest key after it.
            self.cursor = None;
            ListingKey::MIN
        } else {
            self.cursor
                .or_else(|| self.newest.map(ListingKey::next))
                .unwrap_or(ListingKey::MIN)
        };
        self.asked = Some(from);
        Some(ListingsBody::ListRequest {
            from,
            limit: MAX_LIST_LIMIT,
        })
    }

    /// The node's answer to this round's request, for a node asked about
    /// `range` with `allowance` entries' worth of room, applied to
    /// `entries`. Each address whose entry changes is touched.
    fn answer<C: NearestNodes + ?Sized>(
        &mut self,
        range: AddressRange,
        allowance: usize,
        answer: Option<ListingsBody>,
        entries: &mut StoreEntries<'_, C>,
    ) {
        let Some(from) = self.asked.take() else {
            return;
        };
        let Some(ListingsBody::ListResponse { listings, more }) = answer else {
            // No answer, or a refusal: it doesn't count this round. A pass
            // carries on in the next.
            return;
        };
        let next = match check_list_page(from, MAX_LIST_LIMIT, &listings, more) {
            Ok(next) => next,
            Err(e) => {
                self.problem = Some(e.to_string());
                // Its pass can't be trusted to have seen everything.
                self.pass = None;
                return;
            }
        };
        self.answered = true;
        if self.pass.as_ref().is_some_and(|pass| pass.pages == 0) {
            // A new pass: what an earlier one saw doesn't count.
            entries.forget_seen();
        }
        let room = u64::try_from(allowance).unwrap_or(u64::MAX);
        let mut capped = false;
        for listing in &listings {
            let key = listing.key();
            self.newest = Some(self.newest.map_or(key, |newest| newest.max(key)));
            if !range.contains(&listing.address) || listing.validate().is_err() {
                continue;
            }
            let address = listing.address;
            if self.pass.is_some() {
                entries.see(&address);
            }
            let held = entries.get(&address);
            if held.is_none() && self.count >= room {
                capped = true;
                continue;
            }
            let entry = DigestEntry::new(listing);
            if held != Some(entry) {
                if held.is_none() {
                    self.count += 1;
                }
                entries.insert(entry);
                entries.touched(address);
            }
        }
        match self.pass.as_mut() {
            Some(pass) => {
                pass.pages += 1;
                pass.capped |= capped;
                match next {
                    None => {
                        let Some(pass) = self.pass.take() else {
                            return;
                        };
                        self.drop_unseen(entries);
                        entries.forget_seen();
                        self.complete = !pass.capped;
                        self.finished_began = self.pass_began;
                        self.cursor = None;
                    }
                    Some(_) if PAGE.saturating_mul(pass.pages + 1) > allowance => {
                        // It has been read for all its allowance: the pass
                        // ends unfinished, and the next starts afresh.
                        self.pass = None;
                    }
                    Some(next) => pass.cursor = next,
                }
            }
            None => {
                if capped {
                    self.complete = false;
                }
                self.cursor = next;
            }
        }
    }

    /// At the end of a pass that reached the end of the node's index: every
    /// entry the pass didn't see leaves, touched.
    fn drop_unseen<C: NearestNodes + ?Sized>(&mut self, entries: &mut StoreEntries<'_, C>) {
        let mut from = Bound::Unbounded;
        loop {
            let chunk = entries.scan(from, [0xff; 32], SCAN);
            let Some(&last) = chunk.last() else {
                break;
            };
            for address in &chunk {
                if !entries.seen(address) {
                    entries.delete(address);
                    entries.touched(*address);
                    self.count = self.count.saturating_sub(1);
                }
            }
            if chunk.len() < SCAN || entries.failed() {
                break;
            }
            from = Bound::Excluded(last);
        }
    }

    /// Follow `range` instead of `old`: entries outside it leave, touched,
    /// and if it reaches outside `old`, the mirror is complete again only
    /// after a pass.
    fn rescope<C: NearestNodes + ?Sized>(
        &mut self,
        old: AddressRange,
        range: AddressRange,
        entries: &mut StoreEntries<'_, C>,
    ) {
        if !old.covers(&range) {
            self.complete = false;
        }
        let mut from = Bound::Unbounded;
        loop {
            let chunk = entries.scan(from, [0xff; 32], SCAN);
            let Some(&last) = chunk.last() else {
                break;
            };
            for address in chunk.iter().filter(|address| !range.contains(address)) {
                entries.delete(address);
                entries.touched(*address);
                self.count = self.count.saturating_sub(1);
            }
            if chunk.len() < SCAN || entries.failed() {
                break;
            }
            from = Bound::Excluded(last);
        }
    }
}

/// One census node's state. Its entries are in the store.
#[derive(Debug)]
struct NodeState {
    range: AddressRange,
    mirror: Mirror,
    want_peers: bool,
    /// Whether its user agent shows the feed release.
    claims_feed: bool,
    /// When it last refused a feed request, answered its feed requests
    /// only with errors, or answered none when nothing of its feed was known
    /// (Unix seconds).
    feed_refused_at: Option<u64>,
    /// Whether its copies counted in the last round.
    counted: bool,
    /// Whether a push since its last round showed its mirror to lag it: its
    /// copies don't count until it is read again ([`Feeds::behind`]).
    behind: bool,
    read: NodeRead,
    /// Whether it answered a request this round, other than with an
    /// [`Error`](ListingsBody::Error).
    answered: bool,
    /// Whether it answered a request this round with an
    /// [`Error`](ListingsBody::Error).
    errored: bool,
    /// Whether a request to it this round went unanswered.
    missed: bool,
    /// Whether it has answered a feed request since this process began.
    feed_answered: bool,
    /// Its record as the store holds it, if known.
    written: Option<NodeRecord>,
}

impl NodeState {
    fn new(range: AddressRange, kind: ReadKind) -> Self {
        Self {
            range,
            mirror: Mirror::new(kind, range),
            want_peers: false,
            claims_feed: kind == ReadKind::Feed,
            feed_refused_at: None,
            counted: false,
            behind: false,
            read: NodeRead::new(kind),
            answered: false,
            errored: false,
            missed: false,
            feed_answered: false,
            written: None,
        }
    }

    /// Whether it is read through its feed at `now`: its user agent shows
    /// the release (`feed`), and it hasn't refused the feed within the last
    /// [`V2_PASS_INTERVAL`].
    fn wants_feed(&self, feed: bool, now: u64) -> bool {
        feed && self
            .feed_refused_at
            .is_none_or(|at| now >= at.saturating_add(V2_PASS_INTERVAL.as_secs()))
    }

    /// Read it the `kind` way from now on, with an empty mirror: every
    /// entry its old mirror held leaves, touched.
    fn switch<C: NearestNodes + ?Sized>(
        &mut self,
        kind: ReadKind,
        entries: &mut StoreEntries<'_, C>,
    ) {
        entries.wipe();
        self.mirror = Mirror::new(kind, self.range);
    }

    /// Follow `range` instead: the entries outside it leave, touched.
    fn rescope<C: NearestNodes + ?Sized>(
        &mut self,
        range: AddressRange,
        entries: &mut StoreEntries<'_, C>,
    ) {
        let old = self.range;
        self.range = range;
        match &mut self.mirror {
            Mirror::Feed(sync) => sync.rescope(range, entries),
            Mirror::V2(read) => read.rescope(old, range, entries),
        }
    }

    fn set_backed(&mut self, backed: usize) {
        if let Mirror::Feed(sync) = &mut self.mirror {
            sync.set_backed(backed);
        }
    }

    fn begin_round(&mut self, backed: usize) {
        self.answered = false;
        self.errored = false;
        self.missed = false;
        self.behind = false;
        self.read = NodeRead::new(self.mirror.kind());
        match &mut self.mirror {
            Mirror::Feed(sync) => {
                sync.begin_round();
                sync.set_backed(backed);
            }
            Mirror::V2(read) => read.begin_round(),
        }
    }

    fn next_request(&mut self, now: u64) -> Option<ListingsBody> {
        match &mut self.mirror {
            // Every feed request watches, so the node's watch stays set.
            Mirror::Feed(sync) => sync.next_request(self.want_peers, true),
            Mirror::V2(read) => read.next_request(now),
        }
    }

    /// Take the node's answer (`None`: it didn't answer in time), applied to
    /// `entries`. Returns whether it has another request to send this round.
    fn take_answer<C: NearestNodes + ?Sized>(
        &mut self,
        answer: Option<ListingsBody>,
        now: u64,
        allowance: usize,
        entries: &mut StoreEntries<'_, C>,
    ) -> bool {
        match &answer {
            Some(ListingsBody::Error { .. }) => self.errored = true,
            Some(_) => self.answered = true,
            None => self.missed = true,
        }
        let range = self.range;
        match &mut self.mirror {
            Mirror::Feed(sync) => {
                let refused = matches!(
                    &answer,
                    Some(ListingsBody::Error { message }) if message == UNSUPPORTED
                );
                self.feed_answered |= self.answered;
                match answer {
                    Some(body) if !refused => sync.answer(body, entries),
                    _ => sync.no_answer(),
                }
                // A node never heard from through its feed, with nothing
                // kept of it, may not keep one: older nodes drop a request
                // they don't know.
                let never_followed = !self.feed_answered && sync.epoch() == 0 && sync.is_empty();
                let no_answer = sync.outcome() == Some(FeedOutcome::NoAnswer);
                let silent = no_answer && never_followed;
                // One that answers its feed requests only with errors can't
                // have its feed read now, as until it starts again after
                // failing to number or total it, but may serve listings v2
                // requests still. (One that also lets a request go
                // unanswered may only be slow: it is asked again next round.)
                let unavailable = no_answer && self.errored && !self.answered && !self.missed;
                if refused || silent || unavailable {
                    self.fall_back(now, entries);
                    return true;
                }
                !sync.idle()
            }
            Mirror::V2(read) => {
                read.answer(range, allowance, answer, entries);
                false
            }
        }
    }

    /// Read it with v2 requests from now on, as one that doesn't keep a
    /// feed, until [`V2_PASS_INTERVAL`] has passed: its feed mirror's
    /// entries leave, touched.
    fn fall_back<C: NearestNodes + ?Sized>(&mut self, now: u64, entries: &mut StoreEntries<'_, C>) {
        debug!("Reading a node that claims the feed release with listings v2 requests");
        self.feed_refused_at = Some(now);
        self.switch(ReadKind::V2, entries);
    }

    /// End the round: how it went. A push that came behind the mirror during
    /// the round is behind it no more: the round read the node since.
    fn end_round(&mut self) {
        self.behind = false;
        let fell_back = self.claims_feed && self.mirror.kind() == ReadKind::V2;
        let entries = usize::try_from(self.mirror.len()).unwrap_or(usize::MAX);
        self.read = match &mut self.mirror {
            Mirror::Feed(sync) => {
                sync.stop();
                let in_sync = sync.in_sync();
                NodeRead {
                    kind: ReadKind::Feed,
                    answered: self.answered && sync.problem().is_none(),
                    replied: self.answered || self.errored,
                    counts: in_sync,
                    complete: in_sync,
                    outcome: sync.outcome(),
                    problem: sync.problem().map(str::to_string),
                    fell_back,
                    entries,
                }
            }
            Mirror::V2(read) => {
                read.asked = None;
                NodeRead {
                    kind: ReadKind::V2,
                    // A page the checks took: an answer of another kind, or
                    // a page they refused, isn't one.
                    answered: read.answered && read.problem.is_none(),
                    replied: self.answered || self.errored,
                    counts: read.answered,
                    complete: read.answered && read.complete,
                    outcome: None,
                    problem: read.problem.clone(),
                    fell_back,
                    entries,
                }
            }
        };
    }

    fn record(&self) -> NodeRecord {
        let (epoch, head, set_hash) = match &self.mirror {
            Mirror::Feed(sync) => (
                sync.epoch(),
                sync.head(),
                Some(hex::encode(sync.set_hash().to_bytes())),
            ),
            Mirror::V2(_) => (0, 0, None),
        };
        let v2 = match &self.mirror {
            Mirror::V2(read) => Some(V2Record {
                newest: read.newest.map(|key| hex::encode(key.to_bytes())),
                pass_began: read.pass_began,
                finished_began: read.finished_began,
                complete: read.complete,
                cursor: read.cursor.map(|key| hex::encode(key.to_bytes())),
            }),
            Mirror::Feed(_) => None,
        };
        NodeRecord {
            prefix: hex::encode(self.range.prefix()),
            bits: self.range.bits(),
            kind: self.mirror.kind(),
            epoch,
            head,
            feed_refused_at: self.feed_refused_at,
            v2,
            count: Some(self.mirror.len()),
            set_hash,
        }
    }
}

/// A node's row in [`NODES_DB`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct NodeRecord {
    /// The range's prefix, in hex.
    prefix: String,
    bits: u8,
    kind: ReadKind,
    /// For a node read through its feed, the epoch and head of its mirror.
    epoch: u64,
    head: u64,
    #[serde(default)]
    feed_refused_at: Option<u64>,
    /// For a node read with v2 requests.
    #[serde(default)]
    v2: Option<V2Record>,
    /// How many entries the mirror holds, as written with them. A record
    /// without it (or, for a feed mirror, without `set_hash`) is counted
    /// again from the entries when the store opens.
    #[serde(default)]
    count: Option<u64>,
    /// For a node read through its feed, the set hash of its entries, in
    /// hex.
    #[serde(default)]
    set_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct V2Record {
    /// Keys in hex ([`ListingKey::to_bytes`]).
    newest: Option<String>,
    pass_began: Option<u64>,
    #[serde(default)]
    finished_began: Option<u64>,
    complete: bool,
    cursor: Option<String>,
}

impl NodeRecord {
    /// Its range, if the record can be read.
    fn range(&self) -> Option<AddressRange> {
        let prefix: XorName = hex::decode(&self.prefix).ok()?.try_into().ok()?;
        Some(AddressRange::new(prefix, self.bits))
    }

    /// Its count and set hash, if the record has them.
    fn totals(&self) -> Option<(u64, SetHash)> {
        let count = self.count?;
        let set_hash = match self.kind {
            ReadKind::Feed => {
                let bytes: [u8; 32] = hex::decode(self.set_hash.as_ref()?).ok()?.try_into().ok()?;
                SetHash::from_bytes(bytes)
            }
            ReadKind::V2 => SetHash::EMPTY,
        };
        Some((count, set_hash))
    }

    /// The node's state, with a mirror of `count` entries with `set_hash`.
    /// `None` if the record can't be read.
    fn state(&self, count: u64, set_hash: SetHash) -> Option<NodeState> {
        let range = self.range()?;
        let key = |hex_key: &Option<String>| -> Option<Option<ListingKey>> {
            match hex_key {
                None => Some(None),
                Some(text) => ListingKey::from_bytes(&hex::decode(text).ok()?).map(Some),
            }
        };
        let mirror = match self.kind {
            ReadKind::Feed => Mirror::Feed(MirrorSync::resume(
                range, self.epoch, self.head, count, set_hash,
            )),
            ReadKind::V2 => {
                let record = self.v2.clone()?;
                Mirror::V2(V2Read {
                    count,
                    newest: key(&record.newest)?,
                    pass_began: record.pass_began,
                    finished_began: record.finished_began,
                    // A record from before the start of the finished pass was
                    // kept can't say since when the mirror is complete.
                    complete: record.complete && record.finished_began.is_some(),
                    cursor: key(&record.cursor)?,
                    ..V2Read::default()
                })
            }
        };
        Some(NodeState {
            range,
            read: NodeRead::new(mirror.kind()),
            mirror,
            want_peers: false,
            claims_feed: self.kind == ReadKind::Feed,
            feed_refused_at: self.feed_refused_at,
            counted: false,
            behind: false,
            answered: false,
            errored: false,
            missed: false,
            feed_answered: false,
            written: Some(self.clone()),
        })
    }
}

/// A node's allowance: the entries it may have its mirror hold, and the
/// pages' worth it may be asked for in a round, with `backed` backed entries.
fn allowance(backed: usize) -> usize {
    WALK_FREE_LISTINGS.saturating_add(WALK_PER_BACKED.saturating_mul(backed))
}

/// The mirrors of every census node. See the module docs.
pub struct Feeds {
    store: ListingsStore,
    dbs: Dbs,
    nodes: BTreeMap<PeerId, NodeState>,
    backing: Backing,
    /// The nodes the backing was counted with, in id order.
    members: Option<Vec<PeerId>>,
    /// When the latest round began (Unix seconds): the time a node read
    /// through its feed was last read in full ([`Self::complete_since`]).
    round_at: u64,
}

impl std::fmt::Debug for Feeds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Feeds")
            .field("nodes", &self.nodes.len())
            .finish_non_exhaustive()
    }
}

impl Feeds {
    /// The mirrors kept in `store`: none the first time. A node's record
    /// this version can't read is dropped with its entries, and the node
    /// read afresh; one without its count and set hash has them counted
    /// again from its entries.
    ///
    /// # Errors
    ///
    /// If its databases can't be opened, read or written.
    pub fn open(store: &ListingsStore) -> Result<Self> {
        let dbs = Dbs::open(store)?;
        let env = store.env();
        let mut records: BTreeMap<PeerId, NodeRecord> = BTreeMap::new();
        let mut dropped: Vec<PeerId> = Vec::new();
        {
            let txn = env.read_txn().map_err(store_error)?;
            for row in dbs.nodes.iter(&txn).map_err(store_error)? {
                let (key, value) = row.map_err(store_error)?;
                let Ok(id) = <[u8; 32]>::try_from(key) else {
                    continue;
                };
                let peer = PeerId::from_bytes(id);
                match serde_json::from_slice::<NodeRecord>(value) {
                    Ok(record) if record.range().is_some() => {
                        records.insert(peer, record);
                    }
                    Ok(_) => dropped.push(peer),
                    Err(e) => {
                        debug!("Dropping an unreadable mirror record for {peer}: {e}");
                        dropped.push(peer);
                    }
                }
            }
            // Entries of nodes without a record go.
            for peer in dbs.entry_peers(&txn).map_err(store_error)? {
                if !records.contains_key(&peer) && !dropped.contains(&peer) {
                    dropped.push(peer);
                }
            }
        }
        for peer in &dropped {
            let mut txn = env.write_txn().map_err(store_error)?;
            dbs.nodes
                .delete(&mut txn, peer.as_bytes())
                .map_err(store_error)?;
            txn.commit().map_err(store_error)?;
            drop_entries(env, dbs, peer).map_err(store_error)?;
        }
        index_held(env, dbs).map_err(store_error)?;
        let mut nodes = BTreeMap::new();
        for (peer, record) in records {
            let (totals, recounted) = match record.totals() {
                Some(totals) => (totals, false),
                None => {
                    let Some(range) = record.range() else {
                        continue;
                    };
                    debug!("Counting the kept mirror of {peer} again");
                    (dbs.tally(env, &peer, range).map_err(store_error)?, true)
                }
            };
            match record.state(totals.0, totals.1) {
                Some(mut state) => {
                    if recounted {
                        // Written again, with its count and set hash.
                        state.written = None;
                    }
                    nodes.insert(peer, state);
                }
                None => {
                    let mut txn = env.write_txn().map_err(store_error)?;
                    dbs.nodes
                        .delete(&mut txn, peer.as_bytes())
                        .map_err(store_error)?;
                    txn.commit().map_err(store_error)?;
                    drop_entries(env, dbs, &peer).map_err(store_error)?;
                }
            }
        }
        // Each node's backing is counted again at the first poll.
        let mut txn = env.write_txn().map_err(store_error)?;
        dbs.backing.clear(&mut txn).map_err(store_error)?;
        txn.commit().map_err(store_error)?;
        let mut feeds = Self {
            store: store.clone(),
            dbs,
            nodes,
            backing: Backing::default(),
            members: None,
            round_at: 0,
        };
        feeds.save()?;
        Ok(feeds)
    }

    /// Read every node of `nodes` once, as the cycle's poll: see the module
    /// docs. At most [`POLL_CONCURRENCY`] requests are in flight at once,
    /// each through `io`; the round ends when no node has more to ask, or at
    /// `deadline`, whichever is first. Pushes from `pushes` are taken as they
    /// come. Nodes not in `nodes` leave, with their mirrors; `census` says
    /// which nodes are nearest an address, for the nodes' allowances. Pass
    /// every census node: a change in who is passed counts every address's
    /// backing again. `now` is the cycle's time (Unix seconds). Each answer
    /// is written to the store as it is taken.
    ///
    /// # Errors
    ///
    /// If the store can't be read or written. Nodes that fail are no error.
    pub async fn poll<I, C>(
        &mut self,
        io: &I,
        census: &C,
        nodes: &[FeedNode],
        now: u64,
        deadline: tokio::time::Instant,
        pushes: Option<&mut PushReceiver>,
    ) -> Result<PollReport>
    where
        I: FeedIo,
        C: NearestNodes + ?Sized,
    {
        self.round_at = now;
        self.reconcile(census, nodes, now)?;
        let peers: Vec<PeerId> = self.nodes.keys().copied().collect();
        for peer in &peers {
            let backed = self.backing.count(peer);
            if let Some(node) = self.nodes.get_mut(peer) {
                node.begin_round(backed);
            }
        }
        let mut ready: VecDeque<PeerId> = peers.into();
        let mut running = FuturesUnordered::new();
        let mut pushes = pushes;
        let mut pushes_open = pushes.is_some();
        let mut pushed = 0;
        let sleep = tokio::time::sleep_until(deadline);
        tokio::pin!(sleep);
        loop {
            while running.len() < POLL_CONCURRENCY {
                let Some(peer) = ready.pop_front() else {
                    break;
                };
                let Some(node) = self.nodes.get_mut(&peer) else {
                    continue;
                };
                if let Some(body) = node.next_request(now) {
                    running.push(async move {
                        let answer = io.ask(&peer, body).await;
                        (peer, answer)
                    });
                }
            }
            if running.is_empty() {
                break;
            }
            tokio::select! {
                () = &mut sleep => {
                    debug!("The feed poll reached its deadline");
                    break;
                }
                Some((peer, answer)) = running.next() => {
                    if self.take_answer(census, &peer, answer, now)? {
                        ready.push_back(peer);
                    }
                }
                push = next_push(&mut pushes), if pushes_open => match push {
                    Some((source, push)) => {
                        if matches!(self.push(census, &source, &push)?, Pushed::Applied(_)) {
                            pushed += 1;
                        }
                    }
                    None => pushes_open = false,
                },
            }
        }
        drop(running);
        let report = self.end_round(pushed)?;
        self.save()?;
        Ok(report)
    }

    /// Take a push from `peer`'s watch, routed between polls: applied if
    /// `peer` is read through its feed and the push brings its mirror
    /// exactly to the push's head, within its allowance (see
    /// [`FeedSync::push`](ant_listings::FeedSync::push)). The addresses it
    /// changes become pending, in the store at once. `peer` must be the node
    /// the push came from, as the transport gives it.
    ///
    /// # Errors
    ///
    /// If the store can't be read or written.
    pub fn push<C: NearestNodes + ?Sized>(
        &mut self,
        census: &C,
        peer: &PeerId,
        push: &ChangesResponse,
    ) -> Result<Pushed> {
        let Self {
            store,
            dbs,
            nodes,
            backing,
            ..
        } = self;
        let Some(node) = nodes.get_mut(peer) else {
            return Ok(Pushed::Ignored);
        };
        let Mirror::Feed(sync) = &mut node.mirror else {
            return Ok(Pushed::Ignored);
        };
        let mut entries = StoreEntries::begin(store, *dbs, *peer, census, backing)?;
        let pushed = sync.push(push, &mut entries);
        if pushed == Pushed::Behind {
            // Its mirror is known not to be at the head it reported: its
            // copies don't count until it is read again, as for a node out
            // of sync.
            node.behind = true;
            node.read.counts = false;
            node.read.complete = false;
        }
        let (txn, done) = entries.finish()?;
        commit_node(txn, done, *dbs, peer, node)?;
        self.apply_backing();
        Ok(pushed)
    }

    /// Write the records of the nodes that changed since they were last
    /// written, in one transaction. Each answer and push already wrote its
    /// node's; this writes what changed without one, such as the start of a
    /// v2 pass.
    ///
    /// # Errors
    ///
    /// If the store can't be written; what changed is written at the next
    /// save.
    pub fn save(&mut self) -> Result<()> {
        if self
            .nodes
            .values()
            .all(|node| node.written.as_ref() == Some(&node.record()))
        {
            return Ok(());
        }
        let mut txn = self.store.env().write_txn().map_err(store_error)?;
        let mut written = Vec::new();
        for (peer, node) in &self.nodes {
            let record = node.record();
            if node.written.as_ref() != Some(&record) {
                put_record(&mut txn, self.dbs, peer, &record)?;
                written.push((*peer, record));
            }
        }
        txn.commit().map_err(store_error)?;
        for (peer, record) in written {
            if let Some(node) = self.nodes.get_mut(&peer) {
                node.written = Some(record);
            }
        }
        Ok(())
    }

    /// Up to `limit` of the addresses whose copies changed since they were
    /// last settled, after `after` (or from the first), in address order: in
    /// a node's mirror, by a node's copies starting or ceasing to count, or
    /// marked ([`Self::mark_pending`]). Decide these, and settle them once
    /// published ([`Self::settle`]).
    ///
    /// # Errors
    ///
    /// If the store can't be read.
    pub fn pending_after(&self, after: Option<&XorName>, limit: usize) -> Result<Vec<XorName>> {
        let txn = self.store.env().read_txn().map_err(store_error)?;
        self.dbs
            .pending_after(&txn, after, limit)
            .map_err(store_error)
    }

    /// Whether `address` is pending ([`Self::pending_after`]).
    ///
    /// # Errors
    ///
    /// If the store can't be read.
    pub fn is_pending(&self, address: &XorName) -> Result<bool> {
        let txn = self.store.env().read_txn().map_err(store_error)?;
        Ok(self
            .dbs
            .changed
            .get(&txn, address)
            .map_err(store_error)?
            .is_some())
    }

    /// How many addresses are pending.
    ///
    /// # Errors
    ///
    /// If the store can't be read.
    pub fn pending_count(&self) -> Result<u64> {
        let txn = self.store.env().read_txn().map_err(store_error)?;
        self.dbs.changed.len(&txn).map_err(store_error)
    }

    /// Make `addresses` pending, to be decided, as when the nodes nearest
    /// them changed.
    ///
    /// # Errors
    ///
    /// If the store can't be written.
    pub fn mark_pending<'a>(
        &mut self,
        addresses: impl IntoIterator<Item = &'a XorName>,
    ) -> Result<()> {
        let mut txn = self.store.env().write_txn().map_err(store_error)?;
        for address in addresses {
            self.dbs
                .changed
                .put(&mut txn, address, &[])
                .map_err(store_error)?;
        }
        txn.commit().map_err(store_error)
    }

    /// Note that what was decided from `addresses` is published: they stop
    /// being pending until their copies change again.
    ///
    /// # Errors
    ///
    /// If the store can't be written.
    pub fn settle<'a>(&mut self, addresses: impl IntoIterator<Item = &'a XorName>) -> Result<()> {
        let mut txn = self.store.env().write_txn().map_err(store_error)?;
        for address in addresses {
            self.dbs
                .changed
                .delete(&mut txn, address)
                .map_err(store_error)?;
        }
        txn.commit().map_err(store_error)
    }

    /// How `peer`'s latest round went, if it is followed. A push since that
    /// showed its mirror to lag it ([`Self::behind`]) leaves its copies not
    /// counting, and its mirror not complete.
    #[must_use]
    pub fn read(&self, peer: &PeerId) -> Option<&NodeRead> {
        self.nodes.get(peer).map(|node| &node.read)
    }

    /// Whether a push from `peer` since its latest round came behind its
    /// mirror: the node is ahead of what the mirror holds, so its copies
    /// don't count until the next round reads it again. What its copies
    /// would decide waits for that round.
    #[must_use]
    pub fn behind(&self, peer: &PeerId) -> bool {
        self.nodes.get(peer).is_some_and(|node| node.behind)
    }

    /// Whether any node is [`Self::behind`].
    #[must_use]
    pub fn any_behind(&self) -> bool {
        self.nodes.values().any(|node| node.behind)
    }

    /// The entry `peer`'s mirror holds for `address`, counting or not.
    ///
    /// # Errors
    ///
    /// If the store can't be read.
    pub fn entry(&self, peer: &PeerId, address: &XorName) -> Result<Option<DigestEntry>> {
        let txn = self.store.env().read_txn().map_err(store_error)?;
        self.dbs.entry(&txn, peer, address).map_err(store_error)
    }

    /// The copies of `address` held by those of `nearest` whose copies count
    /// this cycle ([`NodeRead::counts`]), in the order of `nearest`.
    ///
    /// # Errors
    ///
    /// If the store can't be read.
    pub fn copies(
        &self,
        address: &XorName,
        nearest: &[PeerId],
    ) -> Result<Vec<(PeerId, DigestEntry)>> {
        let txn = self.store.env().read_txn().map_err(store_error)?;
        let mut copies = Vec::new();
        for peer in nearest {
            if !self.nodes.get(peer).is_some_and(|node| node.read.counts) {
                continue;
            }
            if let Some(entry) = self.dbs.entry(&txn, peer, address).map_err(store_error)? {
                copies.push((*peer, entry));
            }
        }
        Ok(copies)
    }

    /// Every node whose mirror holds `address`, counting or not, in id
    /// order.
    ///
    /// # Errors
    ///
    /// If the store can't be read.
    pub fn holders(&self, address: &XorName) -> Result<Vec<PeerId>> {
        let txn = self.store.env().read_txn().map_err(store_error)?;
        self.dbs.holders(&txn, address).map_err(store_error)
    }

    /// Up to `limit` of the addresses some node's mirror holds, counting or
    /// not, after `after` (or from the first), each once, in address order.
    ///
    /// # Errors
    ///
    /// If the store can't be read.
    pub fn held_after(&self, after: Option<&XorName>, limit: usize) -> Result<Vec<XorName>> {
        let txn = self.store.env().read_txn().map_err(store_error)?;
        self.dbs.held_after(&txn, after, limit).map_err(store_error)
    }

    /// How many addresses some node's mirror holds, counting or not: a scan
    /// of them, a batch at a time.
    ///
    /// # Errors
    ///
    /// If the store can't be read.
    pub fn held_count(&self) -> Result<u64> {
        let mut count = 0;
        let mut after: Option<XorName> = None;
        loop {
            let batch = self.held_after(after.as_ref(), SCAN)?;
            count += batch.len() as u64;
            match batch.last() {
                Some(last) if batch.len() == SCAN => after = Some(*last),
                _ => return Ok(count),
            }
        }
    }

    /// `peer`'s latest view hash, from its last answer or push, for a node
    /// read through its feed: a hint for the census only.
    #[must_use]
    pub fn view(&self, peer: &PeerId) -> Option<[u8; 32]> {
        match &self.nodes.get(peer)?.mirror {
            Mirror::Feed(sync) => sync.view(),
            Mirror::V2(_) => None,
        }
    }

    /// The nearest peers `peer` listed in its last answer that was asked for
    /// them ([`FeedNode::want_peers`]): its word only, checked against its
    /// view hash, never a reason to take a node into the census.
    #[must_use]
    pub fn view_peers(&self, peer: &PeerId) -> Option<&[[u8; 32]]> {
        match &self.nodes.get(peer)?.mirror {
            Mirror::Feed(sync) => sync.peers(),
            Mirror::V2(_) => None,
        }
    }

    /// Since when `peer`'s mirror has held everything it serves in its range,
    /// if it does this cycle ([`NodeRead::complete`]): for a node read
    /// through its feed, the start of the latest round, which found it in
    /// sync; for one read with v2 requests, when its latest finished pass
    /// began. Like the start of a walk of a node's whole index in an index
    /// read: a listing the node stored before then is in its mirror.
    #[must_use]
    pub fn complete_since(&self, peer: &PeerId) -> Option<u64> {
        let node = self.nodes.get(peer)?;
        if !node.read.complete {
            return None;
        }
        match &node.mirror {
            Mirror::Feed(_) => Some(self.round_at),
            Mirror::V2(read) => read.finished_began,
        }
    }

    /// The requests that end this reader's watch on each node read through
    /// its feed: for each, a `ChangesRequest` for its range from where its
    /// mirror stands, setting no watch. A node keeps one watch per reader,
    /// for at most [`MAX_WATCHERS`](ant_listings::MAX_WATCHERS) readers, and
    /// a request that sets none ends the reader's at once. A reader that
    /// stops without sending them keeps its place among each node's watchers
    /// until its watch lapses ([`WATCH_LEASE`](ant_listings::WATCH_LEASE)),
    /// and the same reader started again comes back as another.
    #[must_use]
    pub fn unwatch_requests(&self) -> Vec<(PeerId, ListingsBody)> {
        self.nodes
            .iter()
            .filter_map(|(peer, node)| match &node.mirror {
                Mirror::Feed(sync) => Some((
                    *peer,
                    ListingsBody::ChangesRequest(ChangesRequest {
                        epoch: sync.epoch(),
                        after: sync.head(),
                        prefix: node.range.prefix(),
                        bits: node.range.bits(),
                        limit: MAX_LIST_LIMIT,
                        want_peers: false,
                        watch: false,
                    }),
                )),
                Mirror::V2(_) => None,
            })
            .collect()
    }

    /// `peer`'s allowance in pages a round: what it may be asked for in one,
    /// as [`MAX_LIST_LIMIT`]-entry pages of its allowance of entries.
    #[must_use]
    pub fn page_allowance(&self, peer: &PeerId) -> usize {
        allowance(self.backing.count(peer)).div_ceil(PAGE)
    }

    /// How many entries `peer`'s mirror holds, if it is followed.
    #[must_use]
    pub fn mirror_len(&self, peer: &PeerId) -> Option<u64> {
        self.nodes.get(peer).map(|node| node.mirror.len())
    }

    /// The nodes followed, in id order.
    pub fn nodes(&self) -> impl Iterator<Item = &PeerId> {
        self.nodes.keys()
    }

    /// How many nodes are followed.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether none is.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Give the nodes whose counts of backed entries changed their new
    /// counts.
    fn apply_backing(&mut self) {
        for peer in std::mem::take(&mut self.backing.affected) {
            let backed = self.backing.count(&peer);
            if let Some(node) = self.nodes.get_mut(&peer) {
                node.set_backed(backed);
            }
        }
    }

    /// Bring the nodes followed in line with `nodes`: drop those not in it,
    /// take in new ones, switch the way a node is read, and follow its new
    /// range, each in a transaction of its own. Counts the backing again if
    /// who is followed changed.
    fn reconcile<C: NearestNodes + ?Sized>(
        &mut self,
        census: &C,
        nodes: &[FeedNode],
        now: u64,
    ) -> Result<()> {
        let wanted: BTreeMap<PeerId, &FeedNode> =
            nodes.iter().map(|node| (node.peer, node)).collect();
        let leaving: Vec<PeerId> = self
            .nodes
            .keys()
            .filter(|peer| !wanted.contains_key(peer))
            .copied()
            .collect();
        for peer in leaving {
            self.nodes.remove(&peer);
            let mut entries =
                StoreEntries::begin(&self.store, self.dbs, peer, census, &mut self.backing)?;
            entries.wipe();
            let (mut txn, _) = entries.finish()?;
            self.dbs
                .nodes
                .delete(&mut txn, peer.as_bytes())
                .map_err(store_error)?;
            txn.commit().map_err(store_error)?;
        }
        for (peer, wanted) in &wanted {
            let Self {
                store,
                dbs,
                nodes,
                backing,
                ..
            } = self;
            let node = nodes.entry(*peer).or_insert_with(|| {
                let kind = if wanted.feed {
                    ReadKind::Feed
                } else {
                    ReadKind::V2
                };
                NodeState::new(wanted.range, kind)
            });
            node.want_peers = wanted.want_peers;
            node.claims_feed = wanted.feed;
            let kind = if node.wants_feed(wanted.feed, now) {
                ReadKind::Feed
            } else {
                ReadKind::V2
            };
            let switch = node.mirror.kind() != kind;
            let rescope = node.range != wanted.range;
            if !switch && !rescope {
                continue;
            }
            let mut entries = StoreEntries::begin(store, *dbs, *peer, census, backing)?;
            if switch {
                info!(
                    "Reading {peer} {} from now on",
                    match kind {
                        ReadKind::Feed => "through its change feed",
                        ReadKind::V2 => "with listings v2 requests",
                    }
                );
                node.switch(kind, &mut entries);
            }
            if rescope {
                node.rescope(wanted.range, &mut entries);
            }
            let (txn, done) = entries.finish()?;
            commit_node(txn, done, *dbs, peer, node)?;
        }
        let members: Vec<PeerId> = self.nodes.keys().copied().collect();
        if self.members.as_ref() != Some(&members) {
            self.members = Some(members);
            self.recount_all(census)?;
        }
        self.apply_backing();
        Ok(())
    }

    /// Count every address's backing again, as after a change in who is
    /// followed: a batch of addresses at a time, each in a transaction of
    /// its own.
    fn recount_all<C: NearestNodes + ?Sized>(&mut self, census: &C) -> Result<()> {
        self.backing = Backing::default();
        let env = self.store.env();
        let mut txn = env.write_txn().map_err(store_error)?;
        self.dbs.backing.clear(&mut txn).map_err(store_error)?;
        txn.commit().map_err(store_error)?;
        let mut after: Option<XorName> = None;
        loop {
            let mut txn = env.write_txn().map_err(store_error)?;
            let batch = self
                .dbs
                .held_after(&txn, after.as_ref(), SCAN)
                .map_err(store_error)?;
            for address in &batch {
                self.backing
                    .recount(&mut txn, self.dbs, census, address)
                    .map_err(store_error)?;
            }
            txn.commit().map_err(store_error)?;
            match batch.last() {
                Some(last) if batch.len() == SCAN => after = Some(*last),
                _ => break,
            }
        }
        let counts: Vec<(PeerId, usize)> = self
            .nodes
            .keys()
            .map(|peer| (*peer, self.backing.count(peer)))
            .collect();
        for (peer, backed) in counts {
            if let Some(node) = self.nodes.get_mut(&peer) {
                node.set_backed(backed);
            }
        }
        self.backing.affected.clear();
        Ok(())
    }

    /// Take `peer`'s answer, in a write transaction of its own. Returns
    /// whether it has another request to send this round.
    fn take_answer<C: NearestNodes + ?Sized>(
        &mut self,
        census: &C,
        peer: &PeerId,
        answer: Option<ListingsBody>,
        now: u64,
    ) -> Result<bool> {
        let room = allowance(self.backing.count(peer));
        let Self {
            store,
            dbs,
            nodes,
            backing,
            ..
        } = self;
        let Some(node) = nodes.get_mut(peer) else {
            return Ok(false);
        };
        let mut entries = StoreEntries::begin(store, *dbs, *peer, census, backing)?;
        let again = node.take_answer(answer, now, room, &mut entries);
        let (txn, done) = entries.finish()?;
        commit_node(txn, done, *dbs, peer, node)?;
        self.apply_backing();
        Ok(again)
    }

    /// End the round for every node, and say how it went. The addresses of a
    /// node whose copies start or cease to count become pending.
    fn end_round(&mut self, pushes: usize) -> Result<PollReport> {
        let mut report = PollReport {
            nodes: self.nodes.len(),
            pushes,
            ..PollReport::default()
        };
        let mut flipped = Vec::new();
        for (peer, node) in &mut self.nodes {
            node.end_round();
            let read = &node.read;
            match read.kind {
                ReadKind::Feed => report.feed += 1,
                ReadKind::V2 => report.v2 += 1,
            }
            report.answered += usize::from(read.replied);
            report.counting += usize::from(read.counts);
            report.refused += usize::from(read.problem.is_some());
            report.fell_back += usize::from(read.fell_back);
            if read.counts != node.counted {
                // Its copies start or cease to count: every address it holds
                // has other inputs now.
                flipped.push(*peer);
                node.counted = read.counts;
            }
        }
        for peer in flipped {
            self.mark_held(&peer)?;
        }
        report.pending = usize::try_from(self.pending_count()?).unwrap_or(usize::MAX);
        Ok(report)
    }

    /// Make every address `peer`'s mirror holds pending, a chunk at a time,
    /// each in a transaction of its own.
    fn mark_held(&mut self, peer: &PeerId) -> Result<()> {
        let env = self.store.env();
        let mut from = Bound::Unbounded;
        loop {
            let mut txn = env.write_txn().map_err(store_error)?;
            let chunk = self
                .dbs
                .scan(&txn, peer, from, &[0xff; 32], SCAN)
                .map_err(store_error)?;
            for address in &chunk {
                self.dbs
                    .changed
                    .put(&mut txn, address, &[])
                    .map_err(store_error)?;
            }
            txn.commit().map_err(store_error)?;
            match chunk.last() {
                Some(last) if chunk.len() == SCAN => from = Bound::Excluded(*last),
                _ => return Ok(()),
            }
        }
    }

    /// Follow `peer` through its feed in `range`, its mirror holding
    /// `entries` and in sync this round, as if it had just been read: for
    /// tests of what is decided from the mirrors.
    #[cfg(test)]
    pub(crate) fn seed(&mut self, peer: PeerId, range: AddressRange, entries: &[DigestEntry]) {
        let mut txn = self.store.env().write_txn().unwrap();
        let mut set_hash = SetHash::EMPTY;
        for entry in entries {
            self.dbs
                .entries
                .put(
                    &mut txn,
                    &entry_key(&peer, &entry.address),
                    &encode_entry(entry),
                )
                .unwrap();
            self.dbs
                .held
                .put(&mut txn, &held_key(&entry.address, &peer), &[])
                .unwrap();
            set_hash.insert(entry);
        }
        let count = entries.len() as u64;
        let mut node = NodeState::new(range, ReadKind::Feed);
        node.mirror = Mirror::Feed(MirrorSync::resume(range, 7, 1, count, set_hash));
        node.read = NodeRead {
            answered: true,
            replied: true,
            counts: true,
            complete: true,
            outcome: Some(FeedOutcome::Synced),
            entries: entries.len(),
            ..NodeRead::new(ReadKind::Feed)
        };
        node.counted = true;
        let record = node.record();
        put_record(&mut txn, self.dbs, &peer, &record).unwrap();
        txn.commit().unwrap();
        node.written = Some(record);
        self.nodes.insert(peer, node);
    }

    /// Take `peer` as if a push from it had come behind its mirror
    /// ([`Self::behind`]): for tests of what is decided between cycles.
    #[cfg(test)]
    pub(crate) fn mark_behind(&mut self, peer: &PeerId) {
        if let Some(node) = self.nodes.get_mut(peer) {
            node.behind = true;
            node.read.counts = false;
            node.read.complete = false;
        }
    }

    /// The addresses pending, all of them: for tests.
    #[cfg(test)]
    fn pending_set(&self) -> BTreeSet<XorName> {
        let mut all = BTreeSet::new();
        let mut after = None;
        loop {
            let batch = self.pending_after(after.as_ref(), SCAN).unwrap();
            all.extend(batch.iter().copied());
            match batch.last() {
                Some(last) if batch.len() == SCAN => after = Some(*last),
                _ => return all,
            }
        }
    }

    /// The entries `peer`'s mirror holds, in address order: for tests.
    #[cfg(test)]
    fn mirrored(&self, peer: &PeerId) -> Vec<DigestEntry> {
        let txn = self.store.env().read_txn().unwrap();
        self.dbs
            .entries
            .prefix_iter(&txn, peer.as_bytes())
            .unwrap()
            .map(|row| {
                let (key, value) = row.unwrap();
                let (_, address) = split_key(key).unwrap();
                decode_entry(address, value).unwrap()
            })
            .collect()
    }
}

/// Write `record`, `peer`'s.
fn put_record(txn: &mut RwTxn, dbs: Dbs, peer: &PeerId, record: &NodeRecord) -> Result<()> {
    let bytes = serde_json::to_vec(record)
        .map_err(|e| Error::Serialization(format!("mirror record: {e}")))?;
    dbs.nodes
        .put(txn, peer.as_bytes(), &bytes)
        .map_err(store_error)
}

/// Finish the work `done` on `peer`'s mirror in `txn`: its record written
/// where it changed (or where part of the work was committed without it),
/// and the transaction committed if anything was written; otherwise it is
/// dropped, and nothing was.
fn commit_node(
    mut txn: RwTxn,
    done: Done,
    dbs: Dbs,
    peer: &PeerId,
    node: &mut NodeState,
) -> Result<()> {
    if done.checkpointed {
        node.written = None;
    }
    let record = node.record();
    let rewrite = node.written.as_ref() != Some(&record);
    if rewrite {
        put_record(&mut txn, dbs, peer, &record)?;
    }
    if rewrite || done.changed {
        txn.commit().map_err(store_error)?;
    }
    if rewrite {
        node.written = Some(record);
    }
    Ok(())
}

/// Delete every row of `peer`'s mirror, its rows by address and what its
/// pass saw, a chunk at a time, each committed. The addresses aren't
/// touched: for a node whose record is gone.
fn drop_entries(env: &heed::Env<heed::WithoutTls>, dbs: Dbs, peer: &PeerId) -> heed::Result<()> {
    loop {
        let mut txn = env.write_txn()?;
        let chunk = dbs.scan(&txn, peer, Bound::Unbounded, &[0xff; 32], SCAN)?;
        for address in &chunk {
            dbs.entries.delete(&mut txn, &entry_key(peer, address))?;
            dbs.held.delete(&mut txn, &held_key(address, peer))?;
        }
        if chunk.is_empty() {
            delete_prefix(&mut txn, dbs.seen, peer.as_bytes())?;
            return txn.commit();
        }
        txn.commit()?;
    }
}

/// Index the kept mirrors by address ([`HELD_DB`]), for a store from before
/// they were: a chunk at a time, each committed. Nothing to do once the
/// index holds anything, or there are no mirrors.
fn index_held(env: &heed::Env<heed::WithoutTls>, dbs: Dbs) -> heed::Result<()> {
    {
        let txn = env.read_txn()?;
        if !dbs.held.is_empty(&txn)? || dbs.entries.is_empty(&txn)? {
            return Ok(());
        }
    }
    info!("Indexing the kept mirrors by address");
    let mut from: Option<[u8; 64]> = None;
    loop {
        let mut txn = env.write_txn()?;
        let range = match &from {
            Some(key) => (Bound::Excluded(&key[..]), Bound::Unbounded),
            None => (Bound::Unbounded, Bound::Unbounded),
        };
        let keys: Vec<[u8; 64]> = dbs
            .entries
            .range(&txn, &range)?
            .take(SCAN)
            .filter_map(|row| row.ok().and_then(|(key, _)| key.try_into().ok()))
            .collect();
        for key in &keys {
            if let Some((peer, address)) = split_key(key) {
                dbs.held.put(&mut txn, &held_key(&address, &peer), &[])?;
            }
        }
        txn.commit()?;
        match keys.last() {
            Some(last) if keys.len() == SCAN => from = Some(*last),
            _ => return Ok(()),
        }
    }
}

/// Delete every row of `db` whose key starts with `prefix`, a chunk at a
/// time.
fn delete_prefix(txn: &mut RwTxn, db: Database<Bytes, Bytes>, prefix: &[u8]) -> heed::Result<()> {
    loop {
        let keys: Vec<Vec<u8>> = db
            .prefix_iter(txn, prefix)?
            .take(SCAN)
            .map(|row| row.map(|(key, _)| key.to_vec()))
            .collect::<heed::Result<_>>()?;
        if keys.is_empty() {
            return Ok(());
        }
        for key in keys {
            db.delete(txn, &key)?;
        }
    }
}

/// The next push from `pushes`, or never if there are none to take.
async fn next_push(pushes: &mut Option<&mut PushReceiver>) -> Option<(PeerId, ChangesResponse)> {
    match pushes {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

/// `peer`'s id, then `address`: an entry's key in [`ENTRIES_DB`].
fn entry_key(peer: &PeerId, address: &XorName) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(peer.as_bytes());
    key[32..].copy_from_slice(address);
    key
}

/// [`entry_key`] read back.
fn split_key(key: &[u8]) -> Option<(PeerId, XorName)> {
    let (peer, address) = key.split_first_chunk::<32>()?;
    Some((PeerId::from_bytes(*peer), address.try_into().ok()?))
}

/// `address`, then `peer`'s id: a row's key in [`HELD_DB`].
fn held_key(address: &XorName, peer: &PeerId) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(address);
    key[32..].copy_from_slice(peer.as_bytes());
    key
}

/// [`held_key`] read back.
fn split_held(key: &[u8]) -> Option<(XorName, PeerId)> {
    let (address, peer) = key.split_first_chunk::<32>()?;
    Some((*address, PeerId::from_bytes(peer.try_into().ok()?)))
}

/// Node ids, 32 bytes each.
fn encode_peers(peers: &[PeerId]) -> Vec<u8> {
    peers.iter().flat_map(|peer| *peer.as_bytes()).collect()
}

/// [`encode_peers`] read back.
fn decode_peers(bytes: &[u8]) -> Vec<PeerId> {
    let (ids, _) = bytes.as_chunks::<32>();
    ids.iter().map(|id| PeerId::from_bytes(*id)).collect()
}

/// `entry`'s bytes in [`ENTRIES_DB`]: see [`ENTRY_LEN`].
fn encode_entry(entry: &DigestEntry) -> [u8; ENTRY_LEN] {
    let mut bytes = [0u8; ENTRY_LEN];
    bytes[..8].copy_from_slice(&entry.time.to_be_bytes());
    bytes[8..16].copy_from_slice(&entry.block_number.to_be_bytes());
    bytes[16..24].copy_from_slice(&entry.log_index.to_be_bytes());
    bytes[24] = u8::from(entry.first_seen.is_some());
    bytes[25..33].copy_from_slice(&entry.first_seen.unwrap_or(0).to_be_bytes());
    bytes[33..].copy_from_slice(&entry.digest);
    bytes
}

/// [`encode_entry`] read back, for `address`.
fn decode_entry(address: XorName, bytes: &[u8]) -> Option<DigestEntry> {
    let bytes: &[u8; ENTRY_LEN] = bytes.try_into().ok()?;
    let number = |at: usize| -> Option<u64> {
        Some(u64::from_be_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
    };
    let first_seen = match bytes[24] {
        0 => None,
        1 => Some(number(25)?),
        _ => return None,
    };
    Some(DigestEntry {
        address,
        time: number(0)?,
        block_number: number(8)?,
        log_index: number(16)?,
        first_seen,
        digest: bytes[33..].try_into().ok()?,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ant_listings::{
        nearest_by_distance, view_hash, ChangesRequest, FeedChange, Flags, Listing, ListingPayment,
        Metadata, PaymentField, RangeListRequest, RangeListResponse, SetHash, ShownFields,
    };
    use ant_protocol::compute_address;
    use std::ops::Bound;
    use std::sync::Mutex;
    use std::time::Duration;

    const TEST_MAP: usize = 16 * 1024 * 1024;

    /// When the first round runs.
    const NOW: u64 = 1_791_324_060;

    /// The most feed records a fake node reads for one request, as
    /// darwin-node reads for one.
    const MAX_FEED_READ: usize = 4_096;

    /// The most pages a node that earned nothing answers in a round: its
    /// free allowance's worth.
    const FREE_PAGES: usize = WALK_FREE_LISTINGS / PAGE;

    fn peer(byte: u8) -> PeerId {
        PeerId::from_bytes([byte; 32])
    }

    fn address(n: u32) -> XorName {
        compute_address(&n.to_be_bytes())
    }

    /// An entry for `address`; `version` tells its listings apart.
    fn entry(address: XorName, version: u8) -> DigestEntry {
        DigestEntry {
            address,
            time: 1_791_324_000,
            block_number: 81_950_000,
            log_index: 0,
            first_seen: Some(1_791_324_000),
            digest: [version; 32],
        }
    }

    fn entries(from: u32, count: u32) -> Vec<DigestEntry> {
        (from..from + count).map(|n| entry(address(n), 1)).collect()
    }

    /// A listing in the index at `address`, showing only its block, stored in
    /// the hour of `first_seen`.
    fn listing(address: XorName, first_seen: u64) -> Listing {
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
                block_number: Some(81_950_000),
                ..ListingPayment::default()
            },
            first_seen: Some(first_seen),
        }
    }

    /// The census, as a list of node ids.
    struct Ids(Vec<PeerId>);

    impl NearestNodes for Ids {
        fn nearest(&self, address: &XorName, n: usize) -> Vec<PeerId> {
            let ids: Vec<[u8; 32]> = self.0.iter().map(|peer| *peer.as_bytes()).collect();
            nearest_by_distance(address, &ids, n)
                .into_iter()
                .map(|at| self.0[at])
                .collect()
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Behaviour {
        Honest,
        /// Answers nothing.
        Silent,
        /// Never answers, and holds the request open.
        Hang,
        /// Refuses feed requests as a node without the feed does.
        Unsupported,
        /// Gives a set hash that never matches what it serves.
        WrongHash,
        /// Answers with addresses outside the range asked about.
        OutOfRange,
        /// Makes up new records before each answer, so it always has more.
        Endless,
        /// Answers feed requests with an error, as a node does while its
        /// feed can't be read, and listings v2 requests as it should.
        Unavailable,
    }

    /// A node, as a change feed and a listings v2 index.
    pub(crate) struct FakeNode {
        pub(crate) behaviour: Behaviour,
        epoch: u64,
        head: u64,
        rows: BTreeMap<u64, FeedChange>,
        seq_of: HashMap<XorName, u64>,
        served: BTreeMap<XorName, DigestEntry>,
        listings: BTreeMap<ListingKey, Listing>,
        peers: Vec<[u8; 32]>,
        watch: Option<AddressRange>,
        pushes: Vec<ChangesResponse>,
        made_up: u32,
    }

    impl FakeNode {
        pub(crate) fn new(behaviour: Behaviour) -> Self {
            Self {
                behaviour,
                epoch: 7,
                head: 0,
                rows: BTreeMap::new(),
                seq_of: HashMap::new(),
                served: BTreeMap::new(),
                listings: BTreeMap::new(),
                peers: Vec::new(),
                watch: None,
                pushes: Vec::new(),
                made_up: 0,
            }
        }

        pub(crate) fn serving(behaviour: Behaviour, served: Vec<DigestEntry>) -> Self {
            let mut node = Self::new(behaviour);
            for entry in served {
                node.put(entry);
            }
            node
        }

        fn listing(behaviour: Behaviour, listings: Vec<Listing>) -> Self {
            let mut node = Self::new(behaviour);
            for listing in listings {
                node.listings.insert(listing.key(), listing);
            }
            node
        }

        pub(crate) fn put(&mut self, entry: DigestEntry) {
            self.record(entry.address, Some(entry));
        }

        pub(crate) fn remove(&mut self, address: &XorName) {
            self.record(*address, None);
        }

        fn record(&mut self, address: XorName, entry: Option<DigestEntry>) {
            self.head += 1;
            let seq = self.head;
            if let Some(old) = self.seq_of.insert(address, seq) {
                self.rows.remove(&old);
            }
            let change = match entry {
                Some(entry) => {
                    self.served.insert(address, entry);
                    FeedChange::Entry { seq, entry }
                }
                None => {
                    self.served.remove(&address);
                    FeedChange::Removed { seq, address }
                }
            };
            self.rows.insert(seq, change);
            if let Some(range) = self.watch.filter(|range| range.contains(&address)) {
                let (count, set_hash) = self.totals(range);
                self.pushes.push(ChangesResponse {
                    epoch: self.epoch,
                    head: seq,
                    next: seq,
                    count,
                    set_hash,
                    changes: vec![change],
                    more: false,
                    view: view_hash(&self.peers),
                    peers: Vec::new(),
                });
            }
        }

        /// Number what it serves afresh under `epoch`, as after a wipe.
        pub(crate) fn renumber(&mut self, epoch: u64) {
            self.epoch = epoch;
            self.head = 0;
            self.rows.clear();
            self.seq_of.clear();
            let served: Vec<DigestEntry> = self.served.values().copied().collect();
            for entry in served {
                self.head += 1;
                let seq = self.head;
                self.seq_of.insert(entry.address, seq);
                self.rows.insert(seq, FeedChange::Entry { seq, entry });
            }
        }

        fn totals(&self, range: AddressRange) -> (u64, SetHash) {
            let held: Vec<&DigestEntry> = self
                .served
                .values()
                .filter(|entry| range.contains(&entry.address))
                .collect();
            (held.len() as u64, SetHash::of(held))
        }

        fn answer(&mut self, body: ListingsBody) -> Option<ListingsBody> {
            if matches!(self.behaviour, Behaviour::Silent | Behaviour::Hang) {
                return None;
            }
            let unsupported = Some(ListingsBody::Error {
                message: UNSUPPORTED.into(),
            });
            let unavailable = Some(ListingsBody::Error {
                message: "the change feed is unavailable".into(),
            });
            match body {
                ListingsBody::ChangesRequest(request) => {
                    if self.behaviour == Behaviour::Unsupported {
                        return unsupported;
                    }
                    if self.behaviour == Behaviour::Unavailable {
                        return unavailable;
                    }
                    self.watch = request.watch.then(|| request.range());
                    Some(ListingsBody::ChangesResponse(self.changes(&request)))
                }
                ListingsBody::RangeListRequest(request) => {
                    if self.behaviour == Behaviour::Unsupported {
                        return unsupported;
                    }
                    if self.behaviour == Behaviour::Unavailable {
                        return unavailable;
                    }
                    Some(ListingsBody::RangeListResponse(self.range_list(&request)))
                }
                ListingsBody::ListRequest { from, limit } => {
                    let limit = limit.min(MAX_LIST_LIMIT) as usize;
                    let mut listings: Vec<Listing> = self
                        .listings
                        .range(from..)
                        .map(|(_, listing)| listing.clone())
                        .take(limit + 1)
                        .collect();
                    let more = listings.len() > limit;
                    listings.truncate(limit);
                    Some(ListingsBody::ListResponse { listings, more })
                }
                _ => None,
            }
        }

        fn changes(&mut self, request: &ChangesRequest) -> ChangesResponse {
            let range = request.range();
            if self.behaviour == Behaviour::Endless {
                for _ in 0..300 {
                    self.made_up += 1;
                    self.put(entry(address(1_000_000 + self.made_up), 9));
                }
            }
            let (count, mut set_hash) = self.totals(range);
            if self.behaviour == Behaviour::WrongHash {
                set_hash = SetHash::of_entry(&entry([0xee; 32], 1));
            }
            let view = view_hash(&self.peers);
            let peers = if request.want_peers {
                self.peers.clone()
            } else {
                Vec::new()
            };
            if request.epoch != self.epoch || request.after > self.head {
                return ChangesResponse {
                    epoch: self.epoch,
                    head: self.head,
                    next: self.head,
                    count,
                    set_hash,
                    changes: Vec::new(),
                    more: false,
                    view,
                    peers,
                };
            }
            let limit = request.limit.min(MAX_LIST_LIMIT) as usize;
            let mut changes = Vec::new();
            let mut last = request.after;
            for (read, (&seq, change)) in self.rows.range(request.after + 1..).enumerate() {
                if range.contains(&change.address()) || self.behaviour == Behaviour::OutOfRange {
                    if changes.len() == limit {
                        break;
                    }
                    changes.push(*change);
                }
                last = seq;
                if read + 1 == MAX_FEED_READ {
                    break;
                }
            }
            let next = if self.rows.range(last + 1..).next().is_none() {
                self.head
            } else {
                last
            };
            ChangesResponse {
                epoch: self.epoch,
                head: self.head,
                next,
                count,
                set_hash,
                changes,
                more: next < self.head,
                view,
                peers,
            }
        }

        fn range_list(&self, request: &RangeListRequest) -> RangeListResponse {
            let range = request.range();
            let limit = request.limit.min(MAX_LIST_LIMIT) as usize;
            let from = request
                .after
                .map_or(Bound::Included(range.first()), Bound::Excluded);
            let mut entries: Vec<DigestEntry> = self
                .served
                .range((from, Bound::Included(range.last())))
                .map(|(_, entry)| *entry)
                .take(limit + 1)
                .collect();
            let more = entries.len() > limit;
            entries.truncate(limit);
            if self.behaviour == Behaviour::OutOfRange {
                let mut outside = range.last();
                outside[0] ^= 0x80;
                entries.insert(0, entry(outside, 1));
                entries.truncate(limit);
            }
            RangeListResponse { entries, more }
        }
    }

    /// Fake nodes, and every request sent to them.
    #[derive(Default)]
    pub(crate) struct FakeNet {
        nodes: Mutex<HashMap<PeerId, FakeNode>>,
        asked: Mutex<Vec<(PeerId, ListingsBody)>>,
    }

    impl FakeNet {
        pub(crate) fn with(nodes: Vec<(PeerId, FakeNode)>) -> Self {
            Self {
                nodes: Mutex::new(nodes.into_iter().collect()),
                asked: Mutex::default(),
            }
        }

        pub(crate) fn node<T>(&self, peer: &PeerId, f: impl FnOnce(&mut FakeNode) -> T) -> T {
            f(self.nodes.lock().unwrap().get_mut(peer).unwrap())
        }

        /// The requests sent to `peer` so far, and forget them.
        fn take_asked(&self, peer: &PeerId) -> Vec<ListingsBody> {
            let mut asked = self.asked.lock().unwrap();
            let (to_peer, rest): (Vec<_>, Vec<_>) = asked.drain(..).partition(|(to, _)| to == peer);
            *asked = rest;
            to_peer.into_iter().map(|(_, body)| body).collect()
        }

        /// Whether the node serves exactly what `feeds` mirrors of it, by
        /// node and by address.
        fn mirrored(&self, feeds: &Feeds, peer: &PeerId) -> bool {
            let mirrored = feeds.mirrored(peer);
            let by_address = mirrored
                .iter()
                .all(|entry| feeds.holders(&entry.address).unwrap().contains(peer));
            let counted = feeds.mirror_len(peer) == Some(mirrored.len() as u64);
            by_address
                && counted
                && self.node(peer, |node| {
                    mirrored == node.served.values().copied().collect::<Vec<_>>()
                })
        }
    }

    impl FeedIo for FakeNet {
        async fn ask(&self, peer: &PeerId, body: ListingsBody) -> Option<ListingsBody> {
            self.asked.lock().unwrap().push((*peer, body.clone()));
            let (hang, answer) = {
                let mut nodes = self.nodes.lock().unwrap();
                let node = nodes.get_mut(peer)?;
                (node.behaviour == Behaviour::Hang, node.answer(body))
            };
            if hang {
                std::future::pending::<()>().await;
            }
            answer
        }
    }

    fn store(dir: &std::path::Path) -> ListingsStore {
        ListingsStore::open_with_map_size(dir, TEST_MAP).unwrap()
    }

    fn feed_node(peer: PeerId) -> FeedNode {
        FeedNode {
            peer,
            range: AddressRange::ALL,
            feed: true,
            want_peers: false,
        }
    }

    fn v2_node(peer: PeerId) -> FeedNode {
        FeedNode {
            feed: false,
            ..feed_node(peer)
        }
    }

    async fn poll(feeds: &mut Feeds, net: &FakeNet, nodes: &[FeedNode], now: u64) -> PollReport {
        let ids = Ids(nodes.iter().map(|node| node.peer).collect());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        feeds
            .poll(net, &ids, nodes, now, deadline, None)
            .await
            .unwrap()
    }

    fn settle_all(feeds: &mut Feeds) {
        let settled: Vec<XorName> = feeds.pending_set().iter().copied().collect();
        feeds.settle(&settled).unwrap();
    }

    fn kinds(asked: &[ListingsBody]) -> Vec<&'static str> {
        asked
            .iter()
            .map(|body| match body {
                ListingsBody::ChangesRequest(_) => "changes",
                ListingsBody::RangeListRequest(_) => "range",
                ListingsBody::ListRequest { .. } => "list",
                _ => "other",
            })
            .collect()
    }

    #[tokio::test]
    async fn a_node_is_read_afresh_then_followed_by_its_changes() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let mut feeds = Feeds::open(&store).unwrap();
        let a = peer(1);
        let net = FakeNet::with(vec![(
            a,
            FakeNode::serving(Behaviour::Honest, entries(0, 300)),
        )]);
        let nodes = [feed_node(a)];

        let report = poll(&mut feeds, &net, &nodes, NOW).await;
        assert_eq!((report.answered, report.counting, report.feed), (1, 1, 1));
        // Read to the end, the mirror matches what the node said it served
        // when the read began: it is in sync at once.
        assert_eq!(kinds(&net.take_asked(&a)), ["changes", "range", "range"]);
        assert!(net.mirrored(&feeds, &a));
        let read = feeds.read(&a).unwrap();
        assert!(read.counts && read.complete && read.answered);
        assert_eq!(read.entries, 300);
        assert_eq!(feeds.pending_set().len(), 300);
        let first = address(0);
        assert_eq!(
            feeds.copies(&first, &[a]).unwrap(),
            vec![(a, entry(first, 1))]
        );
        assert_eq!(feeds.holders(&first).unwrap(), vec![a]);

        // Once settled, only what changes next is pending.
        settle_all(&mut feeds);
        assert!(feeds.pending_set().is_empty());
        net.node(&a, |node| {
            node.put(entry(address(1_000), 1));
            node.put(entry(address(1), 2));
            node.remove(&address(2));
        });
        poll(&mut feeds, &net, &nodes, NOW + 60).await;
        let asked = net.take_asked(&a);
        assert_eq!(kinds(&asked), ["changes"]);
        // Every feed request watches.
        assert!(asked
            .iter()
            .all(|body| matches!(body, ListingsBody::ChangesRequest(r) if r.watch)));
        assert!(net.mirrored(&feeds, &a));
        let expected = BTreeSet::from([address(1_000), address(1), address(2)]);
        assert_eq!(feeds.pending_set(), expected);
        assert!(feeds.read(&a).unwrap().counts);
    }

    #[tokio::test]
    async fn a_restart_follows_on_from_the_kept_mirror() {
        let dir = tempfile::tempdir().unwrap();
        let a = peer(1);
        let net = FakeNet::with(vec![(
            a,
            FakeNode::serving(Behaviour::Honest, entries(0, 300)),
        )]);
        let nodes = [feed_node(a)];
        let head = {
            let store = store(dir.path());
            let mut feeds = Feeds::open(&store).unwrap();
            poll(&mut feeds, &net, &nodes, NOW).await;
            let settled: Vec<XorName> = feeds.pending_set().iter().take(100).copied().collect();
            feeds.settle(&settled).unwrap();
            net.node(&a, |node| node.head)
        };
        net.take_asked(&a);
        net.node(&a, |node| node.put(entry(address(5_000), 1)));

        let store = store(dir.path());
        let mut feeds = Feeds::open(&store).unwrap();
        // What wasn't settled is still pending.
        assert_eq!(feeds.pending_set().len(), 200);
        assert_eq!(feeds.mirror_len(&a), Some(300));
        poll(&mut feeds, &net, &nodes, NOW + 60).await;
        let asked = net.take_asked(&a);
        assert_eq!(kinds(&asked), ["changes"]);
        let ListingsBody::ChangesRequest(request) = &asked[0] else {
            unreachable!()
        };
        assert_eq!((request.epoch, request.after), (7, head));
        assert!(net.mirrored(&feeds, &a));
        assert!(feeds.read(&a).unwrap().counts);
        // Its copies count again after the restart: every address it holds
        // is pending, to be decided afresh.
        assert_eq!(feeds.pending_set().len(), 301);
    }

    #[tokio::test]
    async fn a_new_epoch_reads_the_range_afresh() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let mut feeds = Feeds::open(&store).unwrap();
        let a = peer(1);
        let net = FakeNet::with(vec![(
            a,
            FakeNode::serving(Behaviour::Honest, entries(0, 50)),
        )]);
        let nodes = [feed_node(a)];
        poll(&mut feeds, &net, &nodes, NOW).await;
        net.take_asked(&a);

        net.node(&a, |node| {
            for n in 0..10 {
                node.remove(&address(n));
            }
            node.put(entry(address(77_777), 1));
            node.renumber(8);
        });
        poll(&mut feeds, &net, &nodes, NOW + 60).await;
        assert_eq!(kinds(&net.take_asked(&a)), ["changes", "range"]);
        assert!(net.mirrored(&feeds, &a));
        assert!(feeds.read(&a).unwrap().counts);
        assert_eq!(feeds.mirror_len(&a), Some(41));
    }

    #[tokio::test]
    async fn pushes_that_fit_are_taken_between_polls() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let mut feeds = Feeds::open(&store).unwrap();
        let (a, stranger) = (peer(1), peer(9));
        let net = FakeNet::with(vec![(
            a,
            FakeNode::serving(Behaviour::Honest, entries(0, 20)),
        )]);
        let nodes = [feed_node(a)];
        let ids = Ids(vec![a]);
        poll(&mut feeds, &net, &nodes, NOW).await;
        settle_all(&mut feeds);

        // A new listing is pushed, and taken at once, from its node only.
        net.node(&a, |node| node.put(entry(address(500), 1)));
        let push = net.node(&a, |node| node.pushes.pop().unwrap());
        assert_eq!(feeds.push(&ids, &stranger, &push).unwrap(), Pushed::Ignored);
        assert_eq!(
            feeds.push(&ids, &a, &push).unwrap(),
            Pushed::Applied(vec![address(500)])
        );
        assert!(feeds.read(&a).unwrap().counts);
        assert_eq!(feeds.pending_set(), BTreeSet::from([address(500)]));
        // The same push again changes nothing.
        assert_eq!(feeds.push(&ids, &a, &push).unwrap(), Pushed::Ignored);

        // A push that skips a record is left for the next poll.
        net.node(&a, |node| {
            node.put(entry(address(501), 1));
            node.put(entry(address(502), 1));
        });
        let pushes = net.node(&a, |node| std::mem::take(&mut node.pushes));
        assert_eq!(feeds.push(&ids, &a, &pushes[1]).unwrap(), Pushed::Behind);
        assert!(feeds.entry(&a, &address(502)).unwrap().is_none());
        // The node is ahead of its mirror: its copies don't count, and its
        // mirror isn't complete, until it is read again.
        assert!(feeds.behind(&a));
        let read = feeds.read(&a).unwrap();
        assert!(!read.counts && !read.complete);
        assert!(feeds.copies(&address(3), &[a]).unwrap().is_empty());
        // One from another epoch, or with peers, is left alone.
        let mut other_epoch = pushes[0].clone();
        other_epoch.epoch = 99;
        assert_eq!(feeds.push(&ids, &a, &other_epoch).unwrap(), Pushed::Ignored);
        let mut with_peers = pushes[0].clone();
        with_peers.peers = vec![[3; 32]];
        assert_eq!(feeds.push(&ids, &a, &with_peers).unwrap(), Pushed::Ignored);
        feeds.save().unwrap();

        poll(&mut feeds, &net, &nodes, NOW + 60).await;
        assert!(net.mirrored(&feeds, &a));
        assert!(feeds.read(&a).unwrap().counts);
        assert!(!feeds.behind(&a));
        // Its copies counted at both polls: only what changed is pending,
        // not every address it holds.
        assert_eq!(
            feeds.pending_set(),
            BTreeSet::from([address(500), address(501), address(502)])
        );
    }

    #[tokio::test]
    async fn pushes_during_a_poll_are_taken() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let mut feeds = Feeds::open(&store).unwrap();
        let a = peer(1);
        let net = FakeNet::with(vec![(
            a,
            FakeNode::serving(Behaviour::Honest, entries(0, 20)),
        )]);
        let nodes = [feed_node(a)];
        poll(&mut feeds, &net, &nodes, NOW).await;
        net.node(&a, |node| node.put(entry(address(500), 1)));
        let push = net.node(&a, |node| node.pushes.pop().unwrap());
        let (sender, mut receiver) = crate::data::client::listings::push_channel(8);
        assert!(sender.offer(a, push));
        drop(sender);
        let ids = Ids(vec![a]);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
        let report = feeds
            .poll(&net, &ids, &nodes, NOW + 60, deadline, Some(&mut receiver))
            .await
            .unwrap();
        assert!(report.pushes <= 1);
        assert!(feeds.entry(&a, &address(500)).unwrap().is_some());
        assert!(feeds.read(&a).unwrap().counts);
    }

    #[tokio::test]
    async fn a_node_whose_totals_never_match_never_counts() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let mut feeds = Feeds::open(&store).unwrap();
        let (a, b) = (peer(1), peer(2));
        let net = FakeNet::with(vec![
            (a, FakeNode::serving(Behaviour::WrongHash, entries(0, 300))),
            (b, FakeNode::serving(Behaviour::Honest, entries(0, 300))),
        ]);
        let nodes = [feed_node(a), feed_node(b)];
        for round in 0..3 {
            poll(&mut feeds, &net, &nodes, NOW + 60 * round).await;
            let asked = net.take_asked(&a).len();
            assert!(asked <= FREE_PAGES + 1, "{asked} requests in a round");
            assert!(!feeds.read(&a).unwrap().counts);
            assert!(feeds.read(&a).unwrap().answered);
            assert!(feeds.read(&b).unwrap().counts);
        }
        assert_eq!(
            feeds.copies(&address(0), &[a, b]).unwrap(),
            vec![(b, entry(address(0), 1))]
        );
    }

    #[tokio::test]
    async fn answers_outside_the_range_are_refused_and_change_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let mut feeds = Feeds::open(&store).unwrap();
        let a = peer(1);
        let half = AddressRange::new([0; 32], 1);
        let served: Vec<DigestEntry> = entries(0, 100)
            .into_iter()
            .filter(|entry| half.contains(&entry.address))
            .collect();
        let net = FakeNet::with(vec![(a, FakeNode::serving(Behaviour::OutOfRange, served))]);
        let nodes = [FeedNode {
            range: half,
            ..feed_node(a)
        }];
        let report = poll(&mut feeds, &net, &nodes, NOW).await;
        assert_eq!((report.refused, report.counting), (1, 0));
        let read = feeds.read(&a).unwrap();
        assert_eq!(read.outcome, Some(FeedOutcome::BadPage));
        assert!(read.problem.is_some());
        // It replied, but with nothing the checks took: it doesn't count as
        // answering, for the census or the cycle's guard.
        assert!(read.replied && !read.answered);
        assert_eq!(report.answered, 1);
        assert_eq!(read.entries, 0);
        assert!(feeds.pending_set().is_empty());
    }

    #[tokio::test]
    async fn a_flooding_node_is_held_to_its_allowance() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let mut feeds = Feeds::open(&store).unwrap();
        let (flood, endless, v2_flood) = (peer(1), peer(2), peer(3));
        let made_up: Vec<Listing> = (0..5_000)
            .map(|n| listing(address(n), 1_791_324_000))
            .collect();
        let net = FakeNet::with(vec![
            (
                flood,
                FakeNode::serving(Behaviour::Honest, entries(0, 5_000)),
            ),
            (endless, FakeNode::new(Behaviour::Endless)),
            (v2_flood, FakeNode::listing(Behaviour::Honest, made_up)),
        ]);
        let nodes = [feed_node(flood), feed_node(endless), v2_node(v2_flood)];
        for round in 0..30 {
            poll(&mut feeds, &net, &nodes, NOW + 60 * round).await;
            for peer in [flood, endless] {
                let asked = net.take_asked(&peer).len();
                assert!(asked <= FREE_PAGES + 1, "{asked} requests in a round");
                assert!(feeds.mirror_len(&peer).unwrap() <= WALK_FREE_LISTINGS as u64);
            }
            assert_eq!(net.take_asked(&v2_flood).len(), 1);
            assert!(feeds.mirror_len(&v2_flood).unwrap() <= WALK_FREE_LISTINGS as u64);
        }
        // The v2 node's passes stop at its allowance, so it never seems
        // complete.
        assert!(!feeds.read(&v2_flood).unwrap().complete);
    }

    #[tokio::test]
    async fn backed_entries_raise_a_nodes_allowance() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let mut feeds = Feeds::open(&store).unwrap();
        let peers: Vec<PeerId> = (1..=7).map(peer).collect();
        let net = FakeNet::with(
            peers
                .iter()
                .map(|peer| {
                    (
                        *peer,
                        FakeNode::serving(Behaviour::Honest, entries(0, 3_000)),
                    )
                })
                .collect(),
        );
        let nodes: Vec<FeedNode> = peers.iter().copied().map(feed_node).collect();
        for round in 0..3 {
            poll(&mut feeds, &net, &nodes, NOW + 60 * round).await;
        }
        for peer in &peers {
            assert!(feeds.read(peer).unwrap().counts, "{peer}");
            assert!(net.mirrored(&feeds, peer));
        }
        assert_eq!(feeds.backing.count(&peers[0]), 3_000);
    }

    #[tokio::test]
    async fn nodes_without_the_feed_are_read_in_passes() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let mut feeds = Feeds::open(&store).unwrap();
        let a = peer(1);
        let mut listings: Vec<Listing> = (0..600)
            .map(|n| listing(address(n), 1_791_324_000))
            .collect();
        // Last in key order, so the first page holds 256 valid listings.
        let mut invalid = listing(address(600), 1_791_327_600);
        invalid.payment.block_number = None;
        listings.push(invalid);
        let net = FakeNet::with(vec![(a, FakeNode::listing(Behaviour::Honest, listings))]);
        let nodes = [v2_node(a)];

        let from_of = |asked: Vec<ListingsBody>| -> Vec<ListingKey> {
            asked
                .into_iter()
                .map(|body| match body {
                    ListingsBody::ListRequest { from, .. } => from,
                    other => panic!("{other:?}"),
                })
                .collect()
        };
        let mut now = NOW;
        poll(&mut feeds, &net, &nodes, now).await;
        assert_eq!(from_of(net.take_asked(&a)), [ListingKey::MIN]);
        let read = feeds.read(&a).unwrap();
        assert!(read.counts && !read.complete);
        assert_eq!((read.kind, read.entries), (ReadKind::V2, 256));
        for _ in 0..2 {
            now += 60;
            poll(&mut feeds, &net, &nodes, now).await;
            assert_eq!(net.take_asked(&a).len(), 1);
        }
        let read = feeds.read(&a).unwrap();
        assert!(read.counts && read.complete);
        // The listing that fails its checks is left out.
        assert_eq!(read.entries, 600);
        assert_eq!(feeds.pending_set().len(), 600);

        // Between passes, a read from after the newest key finds a new
        // listing; one removed stays until the next pass.
        let newer = listing(address(9_000), 1_791_327_600);
        net.node(&a, |node| {
            node.listings.insert(newer.key(), newer.clone());
            let gone = node.listings.keys().next().copied().unwrap();
            node.listings.remove(&gone);
        });
        now += 60;
        poll(&mut feeds, &net, &nodes, now).await;
        let asked = from_of(net.take_asked(&a));
        assert!(asked[0] > ListingKey::MIN, "{asked:?}");
        assert!(feeds.entry(&a, &address(9_000)).unwrap().is_some());
        assert_eq!(feeds.read(&a).unwrap().entries, 601);

        // No new pass before the interval; one at it, which drops the
        // listing no longer served.
        now = NOW + V2_PASS_INTERVAL.as_secs() - 1;
        poll(&mut feeds, &net, &nodes, now).await;
        assert!(from_of(net.take_asked(&a))[0] > ListingKey::MIN);
        now = NOW + V2_PASS_INTERVAL.as_secs();
        poll(&mut feeds, &net, &nodes, now).await;
        assert_eq!(from_of(net.take_asked(&a)), [ListingKey::MIN]);
        for _ in 0..2 {
            now += 60;
            poll(&mut feeds, &net, &nodes, now).await;
        }
        let read = feeds.read(&a).unwrap();
        assert!(read.complete);
        assert_eq!(read.entries, 600);

        // A request it doesn't answer counts it out.
        net.node(&a, |node| node.behaviour = Behaviour::Silent);
        poll(&mut feeds, &net, &nodes, now + 60).await;
        let read = feeds.read(&a).unwrap();
        assert!(!read.counts && !read.answered);
        assert!(feeds.copies(&address(1), &[a]).unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_node_that_refuses_the_feed_is_read_the_old_way() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let mut feeds = Feeds::open(&store).unwrap();
        let a = peer(1);
        let listings: Vec<Listing> = (0..10)
            .map(|n| listing(address(n), 1_791_324_000))
            .collect();
        let net = FakeNet::with(vec![(
            a,
            FakeNode::listing(Behaviour::Unsupported, listings),
        )]);
        let nodes = [feed_node(a)];

        let report = poll(&mut feeds, &net, &nodes, NOW).await;
        assert_eq!((report.fell_back, report.counting, report.v2), (1, 1, 1));
        assert_eq!(kinds(&net.take_asked(&a)), ["changes", "list"]);
        let read = feeds.read(&a).unwrap();
        assert!(read.fell_back && read.counts && read.complete);
        assert_eq!(read.entries, 10);

        poll(&mut feeds, &net, &nodes, NOW + 60).await;
        assert_eq!(kinds(&net.take_asked(&a)), ["list"]);
        assert!(feeds.read(&a).unwrap().fell_back);

        // Its feed is tried again after the interval.
        poll(&mut feeds, &net, &nodes, NOW + V2_PASS_INTERVAL.as_secs()).await;
        assert_eq!(kinds(&net.take_asked(&a)), ["changes", "list"]);
    }

    #[tokio::test]
    async fn a_node_whose_feed_cant_be_read_is_read_the_old_way() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let mut feeds = Feeds::open(&store).unwrap();
        let a = peer(1);
        let listings: Vec<Listing> = (0..10)
            .map(|n| listing(address(n), 1_791_324_000))
            .collect();
        let served: Vec<DigestEntry> = listings.iter().map(DigestEntry::new).collect();
        let mut node = FakeNode::serving(Behaviour::Honest, served);
        for listing in &listings {
            node.listings.insert(listing.key(), listing.clone());
        }
        let net = FakeNet::with(vec![(a, node)]);
        let nodes = [feed_node(a)];
        poll(&mut feeds, &net, &nodes, NOW).await;
        assert!(feeds.read(&a).unwrap().counts);
        net.take_asked(&a);

        // Its feed can't be read any more, as until it starts again, but it
        // still serves listings v2 requests: once its feed requests are
        // answered only with errors, it is read the old way, that round.
        net.node(&a, |node| node.behaviour = Behaviour::Unavailable);
        poll(&mut feeds, &net, &nodes, NOW + 60).await;
        assert_eq!(kinds(&net.take_asked(&a)), ["changes", "changes", "list"]);
        let read = feeds.read(&a).unwrap();
        assert_eq!(read.kind, ReadKind::V2);
        assert!(read.fell_back && read.replied && read.answered && read.counts);
        assert_eq!(feeds.copies(&address(0), &[a]).unwrap().len(), 1);
        poll(&mut feeds, &net, &nodes, NOW + 120).await;
        assert_eq!(kinds(&net.take_asked(&a)), ["list"]);

        // Its feed is asked for again once V2_PASS_INTERVAL has passed.
        net.node(&a, |node| node.behaviour = Behaviour::Honest);
        poll(
            &mut feeds,
            &net,
            &nodes,
            NOW + 60 + V2_PASS_INTERVAL.as_secs(),
        )
        .await;
        assert_eq!(kinds(&net.take_asked(&a))[0], "changes");
        let read = feeds.read(&a).unwrap();
        assert_eq!(read.kind, ReadKind::Feed);
        assert!(read.counts);
    }

    #[tokio::test]
    async fn a_silent_new_node_is_read_the_old_way_and_a_known_one_only_misses() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let mut feeds = Feeds::open(&store).unwrap();
        let (new, known) = (peer(1), peer(2));
        let net = FakeNet::with(vec![
            (new, FakeNode::new(Behaviour::Silent)),
            (known, FakeNode::serving(Behaviour::Honest, entries(0, 20))),
        ]);
        let nodes = [feed_node(new), feed_node(known)];
        poll(&mut feeds, &net, &nodes, NOW).await;
        // Asked twice through its feed, then once the old way.
        assert_eq!(kinds(&net.take_asked(&new)), ["changes", "changes", "list"]);
        assert!(feeds.read(&new).unwrap().fell_back);
        settle_all(&mut feeds);

        net.node(&known, |node| node.behaviour = Behaviour::Silent);
        poll(&mut feeds, &net, &nodes, NOW + 60).await;
        let read = feeds.read(&known).unwrap();
        assert_eq!(read.kind, ReadKind::Feed);
        assert!(!read.counts && !read.fell_back);
        assert_eq!(read.outcome, Some(FeedOutcome::NoAnswer));
        // Its copies no longer count: every address it holds is pending.
        assert_eq!(feeds.pending_set().len(), 20);
        assert!(feeds.copies(&address(0), &[known]).unwrap().is_empty());
        assert_eq!(feeds.holders(&address(0)).unwrap(), vec![known]);
    }

    #[tokio::test]
    async fn a_node_part_read_through_its_feed_only_misses_when_silent() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let mut feeds = Feeds::open(&store).unwrap();
        let a = peer(1);
        // More than it may be read for in a round: its first read of the
        // range goes on into the next round.
        let net = FakeNet::with(vec![(
            a,
            FakeNode::serving(Behaviour::Honest, entries(0, 3_000)),
        )]);
        let nodes = [feed_node(a)];
        poll(&mut feeds, &net, &nodes, NOW).await;
        assert!(!feeds.read(&a).unwrap().counts);
        let held = feeds.mirror_len(&a).unwrap();
        assert!(held > 0 && held <= WALK_FREE_LISTINGS as u64, "{held}");

        net.node(&a, |node| node.behaviour = Behaviour::Silent);
        poll(&mut feeds, &net, &nodes, NOW + 60).await;
        let read = feeds.read(&a).unwrap();
        assert_eq!(read.kind, ReadKind::Feed);
        assert!(!read.fell_back);
        assert_eq!(read.outcome, Some(FeedOutcome::NoAnswer));
    }

    #[tokio::test]
    async fn a_hanging_node_doesnt_hold_up_the_poll() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let mut feeds = Feeds::open(&store).unwrap();
        let (hang, honest) = (peer(1), peer(2));
        let net = FakeNet::with(vec![
            (hang, FakeNode::new(Behaviour::Hang)),
            (honest, FakeNode::serving(Behaviour::Honest, entries(0, 20))),
        ]);
        let nodes = [feed_node(hang), feed_node(honest)];
        let ids = Ids(vec![hang, honest]);
        let started = tokio::time::Instant::now();
        let deadline = started + Duration::from_millis(300);
        feeds
            .poll(&net, &ids, &nodes, NOW, deadline, None)
            .await
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(feeds.read(&honest).unwrap().counts);
        let read = feeds.read(&hang).unwrap();
        assert!(!read.counts && !read.answered);
        assert_eq!(read.outcome, Some(FeedOutcome::Deadline));
    }

    #[tokio::test]
    async fn nodes_leaving_or_changing_range_drop_their_entries() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (peer(1), peer(2));
        let net = FakeNet::with(vec![
            (a, FakeNode::serving(Behaviour::Honest, entries(0, 100))),
            (b, FakeNode::serving(Behaviour::Honest, entries(0, 100))),
        ]);
        let half = AddressRange::new([0; 32], 1);
        let inside = entries(0, 100)
            .iter()
            .filter(|entry| half.contains(&entry.address))
            .count();
        {
            let store = store(dir.path());
            let mut feeds = Feeds::open(&store).unwrap();
            poll(&mut feeds, &net, &[feed_node(a), feed_node(b)], NOW).await;
            settle_all(&mut feeds);

            let nodes = [FeedNode {
                range: half,
                ..feed_node(a)
            }];
            poll(&mut feeds, &net, &nodes, NOW + 60).await;
            assert!(feeds.read(&b).is_none());
            assert_eq!(feeds.read(&a).unwrap().entries, inside);
            assert!(feeds.read(&a).unwrap().counts);
            // Every address either node held is pending: b's left with b,
            // and a's outside its new range left its mirror.
            assert_eq!(feeds.pending_set().len(), 100);
        }
        let store = store(dir.path());
        let feeds = Feeds::open(&store).unwrap();
        assert_eq!(feeds.len(), 1);
        assert_eq!(feeds.nodes[&a].range, half);
        assert_eq!(feeds.mirror_len(&a), Some(inside as u64));
        let txn = store.env().read_txn().unwrap();
        assert_eq!(feeds.dbs.entries.len(&txn).unwrap(), inside as u64);
        assert_eq!(feeds.dbs.held.len(&txn).unwrap(), inside as u64);
    }

    #[tokio::test]
    async fn view_peers_are_hints_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let mut feeds = Feeds::open(&store).unwrap();
        let a = peer(1);
        let mut node = FakeNode::serving(Behaviour::Honest, entries(0, 5));
        node.peers = vec![[0x42; 32], [0x43; 32]];
        let net = FakeNet::with(vec![(a, node)]);
        let nodes = [FeedNode {
            want_peers: true,
            ..feed_node(a)
        }];
        poll(&mut feeds, &net, &nodes, NOW).await;
        assert_eq!(feeds.view_peers(&a), Some(&[[0x42; 32], [0x43; 32]][..]));
        assert_eq!(feeds.view(&a), Some(view_hash(&[[0x42; 32], [0x43; 32]])));
        assert_eq!(feeds.len(), 1);
        assert!(feeds.read(&a).unwrap().counts);
    }

    #[tokio::test]
    async fn a_long_change_is_committed_a_chunk_at_a_time() {
        // A node whose mirror holds more than a chunk stops answering
        // through its feed: its mirror is emptied as it is read the old
        // way, a chunk at a time.
        let dir = tempfile::tempdir().unwrap();
        let a = peer(1);
        let net = FakeNet::with(vec![(
            a,
            FakeNode::serving(Behaviour::Honest, entries(0, 700)),
        )]);
        let nodes = [feed_node(a)];
        {
            let store = store(dir.path());
            let mut feeds = Feeds::open(&store).unwrap();
            for round in 0..2 {
                poll(&mut feeds, &net, &nodes, NOW + 60 * round).await;
            }
            assert!(feeds.read(&a).unwrap().counts);
            assert_eq!(feeds.mirror_len(&a), Some(700));
            settle_all(&mut feeds);
            let listings: Vec<Listing> =
                (0..3).map(|n| listing(address(n), 1_791_324_000)).collect();
            net.node(&a, |node| {
                node.behaviour = Behaviour::Unsupported;
                for listing in listings {
                    node.listings.insert(listing.key(), listing);
                }
            });
            poll(&mut feeds, &net, &nodes, NOW + 120).await;
            let read = feeds.read(&a).unwrap();
            assert!(read.fell_back && read.counts);
            assert_eq!(read.entries, 3);
            // Every address it held is pending, and its record says what
            // the store holds.
            assert_eq!(feeds.pending_set().len(), 700);
            assert_eq!(feeds.mirrored(&a).len(), 3);
        }
        let store = store(dir.path());
        let feeds = Feeds::open(&store).unwrap();
        assert_eq!(feeds.mirror_len(&a), Some(3));
        assert_eq!(feeds.read(&a).unwrap().kind, ReadKind::V2);
    }

    #[tokio::test]
    async fn a_mirror_left_part_changed_is_read_afresh() {
        // A process stopped while emptying a mirror, after a chunk was
        // committed: the node's record is gone, so the next start drops what
        // is left of its mirror, and the node is read afresh.
        let dir = tempfile::tempdir().unwrap();
        let a = peer(1);
        let net = FakeNet::with(vec![(
            a,
            FakeNode::serving(Behaviour::Honest, entries(0, 700)),
        )]);
        let nodes = [feed_node(a)];
        let ids = Ids(vec![a]);
        {
            let store = store(dir.path());
            let mut feeds = Feeds::open(&store).unwrap();
            for round in 0..2 {
                poll(&mut feeds, &net, &nodes, NOW + 60 * round).await;
            }
            assert_eq!(feeds.mirror_len(&a), Some(700));
            let mut entries =
                StoreEntries::begin(&store, feeds.dbs, a, &ids, &mut feeds.backing).unwrap();
            let doomed = entries.scan(Bound::Unbounded, [0xff; 32], 300);
            for address in &doomed {
                entries.delete(address);
                entries.touched(*address);
            }
            // Stopped here: the first chunk was committed, the rest not.
            drop(entries);
        }
        let store = store(dir.path());
        let mut feeds = Feeds::open(&store).unwrap();
        assert!(feeds.is_empty());
        {
            let txn = store.env().read_txn().unwrap();
            assert!(feeds.dbs.entries.is_empty(&txn).unwrap());
            assert!(feeds.dbs.held.is_empty(&txn).unwrap());
        }
        poll(&mut feeds, &net, &nodes, NOW + 120).await;
        poll(&mut feeds, &net, &nodes, NOW + 180).await;
        assert!(net.mirrored(&feeds, &a));
        assert!(feeds.read(&a).unwrap().counts);
    }

    #[tokio::test]
    async fn a_record_without_its_totals_is_counted_again() {
        let dir = tempfile::tempdir().unwrap();
        let a = peer(1);
        let net = FakeNet::with(vec![(
            a,
            FakeNode::serving(Behaviour::Honest, entries(0, 50)),
        )]);
        let nodes = [feed_node(a)];
        {
            let store = store(dir.path());
            let mut feeds = Feeds::open(&store).unwrap();
            poll(&mut feeds, &net, &nodes, NOW).await;
            // As an earlier version wrote it: no count or set hash.
            let mut record = feeds.nodes[&a].record();
            record.count = None;
            record.set_hash = None;
            let mut txn = store.env().write_txn().unwrap();
            put_record(&mut txn, feeds.dbs, &a, &record).unwrap();
            txn.commit().unwrap();
        }
        let store = store(dir.path());
        let mut feeds = Feeds::open(&store).unwrap();
        assert_eq!(feeds.mirror_len(&a), Some(50));
        let written = feeds.nodes[&a].written.clone().unwrap();
        assert_eq!(written.count, Some(50));
        net.take_asked(&a);
        poll(&mut feeds, &net, &nodes, NOW + 60).await;
        // Followed on from where it stood, and in sync at once.
        assert_eq!(kinds(&net.take_asked(&a)), ["changes"]);
        assert!(feeds.read(&a).unwrap().counts);
    }

    #[tokio::test]
    async fn every_address_held_is_found_once_a_batch_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let mut feeds = Feeds::open(&store).unwrap();
        let (a, b) = (peer(1), peer(2));
        let net = FakeNet::with(vec![
            (a, FakeNode::serving(Behaviour::Honest, entries(0, 600))),
            (b, FakeNode::serving(Behaviour::Honest, entries(300, 600))),
        ]);
        let nodes = [feed_node(a), feed_node(b)];
        for round in 0..2 {
            poll(&mut feeds, &net, &nodes, NOW + 60 * round).await;
        }
        let mut found = Vec::new();
        let mut after = None;
        loop {
            let batch = feeds.held_after(after.as_ref(), 100).unwrap();
            found.extend(batch.iter().copied());
            match batch.last() {
                Some(last) if batch.len() == 100 => after = Some(*last),
                _ => break,
            }
        }
        let mut expected: Vec<XorName> = (0..900).map(address).collect();
        expected.sort_unstable();
        assert_eq!(found, expected);
        assert_eq!(feeds.held_count().unwrap(), 900);
        assert_eq!(feeds.holders(&address(450)).unwrap(), vec![a, b]);
        assert_eq!(feeds.holders(&address(800)).unwrap(), vec![b]);
    }

    #[test]
    fn census_nodes_are_asked_about_their_leaves() {
        let dir = tempfile::tempdir().unwrap();
        let store = store(dir.path());
        let mut census = Census::open(&store).unwrap();
        for byte in 1..=16u8 {
            census.admit(peer(byte.wrapping_mul(16)), Vec::new(), NOW);
        }
        census.record_answer(&peer(16), NOW, Some("node/0.23.0+ds.15".into()));
        census.record_answer(&peer(32), NOW, Some("node/0.23.0+ds.14".into()));
        let nodes = FeedNode::from_census(&census, |peer| *peer == PeerId::from_bytes([16; 32]));
        assert_eq!(nodes.len(), 16);
        for node in &nodes {
            assert_eq!(node.range, census.leaf_of(node.peer.as_bytes()));
            assert!(node.range.contains(node.peer.as_bytes()));
            assert_eq!(node.feed, node.peer == peer(16));
            assert_eq!(node.want_peers, node.peer == peer(16));
        }
        // 16 nodes split the space in two leaves.
        assert!(nodes.iter().any(|node| node.range != AddressRange::ALL));
    }

    #[test]
    fn entries_are_kept_as_they_were() {
        for first_seen in [None, Some(1_791_324_000)] {
            let entry = DigestEntry {
                first_seen,
                ..entry(address(3), 4)
            };
            assert_eq!(
                decode_entry(entry.address, &encode_entry(&entry)),
                Some(entry)
            );
        }
        assert_eq!(decode_entry(address(3), &[0; ENTRY_LEN - 1]), None);
        let key = entry_key(&peer(5), &address(6));
        assert_eq!(split_key(&key), Some((peer(5), address(6))));
    }
}
