//! Following what each node serves, for the listings producer
//! ([`Producer`](super::listings_serve::Producer)): a mirror of each census
//! node's part of the index, kept in the producer's store, and the set of
//! addresses whose copies changed.
//!
//! **Nodes with the change feed** (the feed release,
//! [`FEED_RELEASE`](super::listings_census::FEED_RELEASE) on) are followed
//! with [`FeedSync`], the reader's state machine of `ant-listings`, which
//! checks every answer and push as that crate defines (sequence numbers,
//! ranges, one record per address, counts and set hashes, peers against the
//! view) and bounds what a node can make the reader take. Each node is asked
//! about its own leaf only ([`FeedNode::range`]):
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
//! the watch without saying so; its next poll finds every change anyway.
//!
//! **Nodes without it** are read with listings v2 requests
//! (`ListRequest`), one a round: the next page of a full pass of their index,
//! a new pass starting at most once every [`V2_PASS_INTERVAL`], or between
//! passes a read from the key after the newest listing seen from the node.
//! Copies from a pass's pages count at once; one the node no longer serves
//! leaves the mirror when a pass that reached the end of its index didn't
//! see it. A node whose user agent shows the feed release but that refuses a
//! feed request as `unsupported`, or never answers one, is read this way too,
//! from the same round on, and asked for its feed again after
//! [`V2_PASS_INTERVAL`].
//!
//! **What counts.** A node's copies count in a cycle ([`NodeRead::counts`])
//! when it is in sync: it answered this round, and its mirror is at the head
//! it reported with the count and set hash it reported
//! ([`FeedSync::in_sync`]). A node read with v2 requests counts when it
//! answered this round's request with a page the checks take; its mirror then
//! holds what its pages showed. Only entries in the node's own range are
//! kept, and only listings that pass [`Listing::validate`]
//! (`ant_listings::Listing`) are taken from v2 pages, as
//! [`merge_copies`](ant_listings::merge_copies) would leave the rest out.
//!
//! **Hostile nodes.** Nothing a node sends is taken on trust:
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
//!    [`POLL_CONCURRENCY`] requests at once, and saves the mirrors.
//! 2. For the guard and support: [`Feeds::read`] says how each node's round
//!    went (answered, counts, complete); [`Feeds::copies`] gives an address's
//!    copies from those of its nearest nodes whose copies count, as digest
//!    entries (the full listing comes from a `GetRequest`, checked with
//!    [`DigestEntry::describes`]); [`Feeds::holders`] every node whose mirror
//!    holds it, counting or not.
//! 3. [`Feeds::pending`]: the addresses whose copies changed since they were
//!    last settled, in any mirror, by an answer, a push, a node leaving or
//!    changing range or way of reading, or a node's copies starting or
//!    ceasing to count. Kept in the store until settled.
//! 4. Once what it decided from them is published, [`Feeds::settle`] with
//!    those addresses.
//!
//! Between cycles, it passes each push its `ListingsRequests` routes to
//! [`Feeds::push`]: the addresses a push changes join [`Feeds::pending`], to
//! be decided at once; it calls [`Feeds::save`] when it has handled them.
//!
//! The mirrors are kept in the producer's store ([`ListingsStore`],
//! databases [`NODES_DB`], [`ENTRIES_DB`] and [`CHANGED_DB`]), so a restart
//! follows each node's feed on from where the mirror stood, and its first
//! request is a `ChangesRequest`, not a fresh read of the range. A v2 pass in
//! progress is not kept: after a restart, the next starts once
//! [`V2_PASS_INTERVAL`] has passed since it began.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::future::Future;

use ant_listings::{
    check_list_page, AddressRange, ChangesResponse, DigestEntry, FeedOutcome, FeedSync, ListingKey,
    ListingsBody, Pushed, MAX_LIST_LIMIT, NEAREST_NODES, QUORUM_THRESHOLD, WALK_EARNING_RANKS,
    WALK_FREE_LISTINGS, WALK_PER_BACKED,
};
use ant_protocol::transport::PeerId;
use ant_protocol::XorName;
use futures::stream::{FuturesUnordered, StreamExt};
use heed::types::Bytes;
use heed::Database;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

use super::listings::ListingsRequests;
use super::listings_census::Census;
use super::listings_serve::{POLL_CONCURRENCY, V2_PASS_INTERVAL};
use super::listings_store::{store_error, ListingsStore};
use crate::data::error::Result;

/// Each node's way of reading and where its mirror stands, by node id.
pub const NODES_DB: &str = "serve_feed_nodes";

/// Each node's mirror: the node id and the address, to the entry.
pub const ENTRIES_DB: &str = "serve_feed_entries";

/// The addresses whose copies changed and that are not settled yet.
pub const CHANGED_DB: &str = "serve_feed_changed";

/// What a node answers a request of a kind it doesn't know (darwin-node's
/// listings service): a node that answers a feed request so doesn't keep a
/// feed, whatever its user agent says.
const UNSUPPORTED: &str = "unsupported";

/// The entries a full page counts for against a node's allowance.
const PAGE: usize = MAX_LIST_LIMIT as usize;

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
    /// Addresses waiting to be settled after the round ([`Feeds::pending`]).
    pub pending: usize,
}

/// A node's mirror.
#[derive(Debug)]
enum Mirror {
    Feed(FeedSync),
    V2(V2Read),
}

impl Mirror {
    fn kind(&self) -> ReadKind {
        match self {
            Self::Feed(_) => ReadKind::Feed,
            Self::V2(_) => ReadKind::V2,
        }
    }

    fn get(&self, address: &XorName) -> Option<&DigestEntry> {
        match self {
            Self::Feed(sync) => sync.get(address),
            Self::V2(read) => read.entries.get(address),
        }
    }

    fn addresses(&self) -> Vec<XorName> {
        match self {
            Self::Feed(sync) => sync.entries().map(|entry| entry.address).collect(),
            Self::V2(read) => read.entries.keys().copied().collect(),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Feed(sync) => sync.len(),
            Self::V2(read) => read.entries.len(),
        }
    }
}

/// A node read with listings v2 requests: one a round.
#[derive(Debug, Default)]
struct V2Read {
    /// What its pages showed in its range, by address.
    entries: BTreeMap<XorName, DigestEntry>,
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

/// A full pass of a node's index in progress.
#[derive(Debug)]
struct Pass {
    cursor: ListingKey,
    seen: HashSet<XorName>,
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
                seen: HashSet::new(),
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
    /// `range` with `allowance` entries' worth of room. Returns the
    /// addresses whose entries changed.
    fn answer(
        &mut self,
        range: AddressRange,
        allowance: usize,
        answer: Option<ListingsBody>,
    ) -> Vec<XorName> {
        let Some(from) = self.asked.take() else {
            return Vec::new();
        };
        let Some(ListingsBody::ListResponse { listings, more }) = answer else {
            // No answer, or a refusal: it doesn't count this round. A pass
            // carries on in the next.
            return Vec::new();
        };
        let next = match check_list_page(from, MAX_LIST_LIMIT, &listings, more) {
            Ok(next) => next,
            Err(e) => {
                self.problem = Some(e.to_string());
                // Its pass can't be trusted to have seen everything.
                self.pass = None;
                return Vec::new();
            }
        };
        self.answered = true;
        let mut touched = Vec::new();
        let mut capped = false;
        for listing in &listings {
            let key = listing.key();
            self.newest = Some(self.newest.map_or(key, |newest| newest.max(key)));
            if !range.contains(&listing.address) || listing.validate().is_err() {
                continue;
            }
            let address = listing.address;
            if let Some(pass) = self.pass.as_mut() {
                pass.seen.insert(address);
            }
            if !self.entries.contains_key(&address) && self.entries.len() >= allowance {
                capped = true;
                continue;
            }
            let entry = DigestEntry::new(listing);
            if self.entries.insert(address, entry) != Some(entry) {
                touched.push(address);
            }
        }
        match self.pass.as_mut() {
            Some(pass) => {
                pass.pages += 1;
                pass.capped |= capped;
                match next {
                    None => {
                        let Some(pass) = self.pass.take() else {
                            return touched;
                        };
                        let gone: Vec<XorName> = self
                            .entries
                            .keys()
                            .filter(|address| !pass.seen.contains(*address))
                            .copied()
                            .collect();
                        for address in gone {
                            self.entries.remove(&address);
                            touched.push(address);
                        }
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
        touched
    }

    /// Follow `range` instead of `old`: entries outside it leave, and if it
    /// reaches outside `old`, the mirror is complete again only after a
    /// pass. Returns the addresses that left.
    fn rescope(&mut self, old: AddressRange, range: AddressRange) -> Vec<XorName> {
        if !old.covers(&range) {
            self.complete = false;
        }
        let outside: Vec<XorName> = self
            .entries
            .keys()
            .filter(|address| !range.contains(address))
            .copied()
            .collect();
        for address in &outside {
            self.entries.remove(address);
        }
        outside
    }
}

/// One census node's state.
#[derive(Debug)]
struct NodeState {
    range: AddressRange,
    mirror: Mirror,
    want_peers: bool,
    /// Whether its user agent shows the feed release.
    claims_feed: bool,
    /// When it last refused a feed request, or answered none when nothing
    /// of its feed was known (Unix seconds).
    feed_refused_at: Option<u64>,
    /// Whether its copies counted in the last round.
    counted: bool,
    read: NodeRead,
    /// Whether it answered a request this round.
    answered: bool,
    /// Whether it has answered a feed request since this process began.
    feed_answered: bool,
    /// Addresses whose entries changed since the last save.
    dirty: BTreeSet<XorName>,
    /// Whether its record changed since the last save.
    meta_dirty: bool,
}

impl NodeState {
    fn new(range: AddressRange, kind: ReadKind) -> Self {
        let mirror = match kind {
            ReadKind::Feed => Mirror::Feed(FeedSync::new(range)),
            ReadKind::V2 => Mirror::V2(V2Read::default()),
        };
        Self {
            range,
            mirror,
            want_peers: false,
            claims_feed: kind == ReadKind::Feed,
            feed_refused_at: None,
            counted: false,
            read: NodeRead::new(kind),
            answered: false,
            feed_answered: false,
            dirty: BTreeSet::new(),
            meta_dirty: true,
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

    /// Read it the `kind` way from now on, with an empty mirror. Returns the
    /// addresses its old mirror held.
    fn switch(&mut self, kind: ReadKind) -> Vec<XorName> {
        let touched = self.mirror.addresses();
        self.mirror = match kind {
            ReadKind::Feed => Mirror::Feed(FeedSync::new(self.range)),
            ReadKind::V2 => Mirror::V2(V2Read::default()),
        };
        self.dirty.extend(touched.iter().copied());
        self.meta_dirty = true;
        touched
    }

    /// Follow `range` instead. Returns the addresses whose entries left.
    fn rescope(&mut self, range: AddressRange) -> Vec<XorName> {
        let old = self.range;
        self.range = range;
        self.meta_dirty = true;
        let touched = match &mut self.mirror {
            Mirror::Feed(sync) => sync.rescope(range),
            Mirror::V2(read) => read.rescope(old, range),
        };
        self.dirty.extend(touched.iter().copied());
        touched
    }

    fn set_backed(&mut self, backed: usize) {
        if let Mirror::Feed(sync) = &mut self.mirror {
            sync.set_backed(backed);
        }
    }

    fn begin_round(&mut self, backed: usize) {
        self.answered = false;
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

    /// Take the node's answer (`None`: it didn't answer in time). Returns
    /// the addresses whose entries changed, and whether it has another
    /// request to send this round.
    fn take_answer(
        &mut self,
        answer: Option<ListingsBody>,
        now: u64,
        allowance: usize,
    ) -> (Vec<XorName>, bool) {
        if matches!(
            &answer,
            Some(body) if !matches!(body, ListingsBody::Error { .. })
        ) {
            self.answered = true;
        }
        let range = self.range;
        match &mut self.mirror {
            Mirror::Feed(sync) => {
                let refused = matches!(
                    &answer,
                    Some(ListingsBody::Error { message }) if message == UNSUPPORTED
                );
                self.feed_answered |= self.answered;
                let touched = match answer {
                    Some(body) if !refused => sync.answer(body),
                    _ => {
                        sync.no_answer();
                        Vec::new()
                    }
                };
                self.meta_dirty = true;
                self.dirty.extend(touched.iter().copied());
                // A node never heard from through its feed, with nothing
                // kept of it, may not keep one: older nodes drop a request
                // they don't know.
                let never_followed = !self.feed_answered && sync.epoch() == 0 && sync.is_empty();
                let silent = sync.outcome() == Some(FeedOutcome::NoAnswer) && never_followed;
                if refused || silent {
                    let mut touched = touched;
                    touched.extend(self.fall_back(now));
                    return (touched, true);
                }
                (touched, !sync.idle())
            }
            Mirror::V2(read) => {
                let touched = read.answer(range, allowance, answer);
                self.meta_dirty = true;
                self.dirty.extend(touched.iter().copied());
                (touched, false)
            }
        }
    }

    /// Read it with v2 requests from now on, as one that doesn't keep a
    /// feed, until [`V2_PASS_INTERVAL`] has passed. Returns the addresses its
    /// feed mirror held.
    fn fall_back(&mut self, now: u64) -> Vec<XorName> {
        debug!("Reading a node that claims the feed release with listings v2 requests");
        self.feed_refused_at = Some(now);
        self.switch(ReadKind::V2)
    }

    /// End the round: how it went.
    fn end_round(&mut self) {
        let fell_back = self.claims_feed && self.mirror.kind() == ReadKind::V2;
        let entries = self.mirror.len();
        self.read = match &mut self.mirror {
            Mirror::Feed(sync) => {
                sync.stop();
                let in_sync = sync.in_sync();
                NodeRead {
                    kind: ReadKind::Feed,
                    answered: self.answered && sync.problem().is_none(),
                    replied: self.answered,
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
                    replied: self.answered,
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
        let (epoch, head) = match &self.mirror {
            Mirror::Feed(sync) => (sync.epoch(), sync.head()),
            Mirror::V2(_) => (0, 0),
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
    /// The node's state, with `entries` as its mirror. `None` if the record
    /// can't be read.
    fn state(&self, entries: Vec<DigestEntry>) -> Option<NodeState> {
        let prefix: XorName = hex::decode(&self.prefix).ok()?.try_into().ok()?;
        let range = AddressRange::new(prefix, self.bits);
        let key = |hex_key: &Option<String>| -> Option<Option<ListingKey>> {
            match hex_key {
                None => Some(None),
                Some(text) => ListingKey::from_bytes(&hex::decode(text).ok()?).map(Some),
            }
        };
        let mirror = match self.kind {
            ReadKind::Feed => Mirror::Feed(FeedSync::resume(range, self.epoch, self.head, entries)),
            ReadKind::V2 => {
                let record = self.v2.clone()?;
                Mirror::V2(V2Read {
                    entries: entries
                        .into_iter()
                        .filter(|entry| range.contains(&entry.address))
                        .map(|entry| (entry.address, entry))
                        .collect(),
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
            answered: false,
            feed_answered: false,
            dirty: BTreeSet::new(),
            meta_dirty: false,
        })
    }
}

/// Which nodes each backed address credits, and how many backed entries
/// each node holds: what a node's allowance grows with.
#[derive(Debug, Default)]
struct Backing {
    /// For each backed address, the nodes among its
    /// [`WALK_EARNING_RANKS`] nearest whose mirrors hold it.
    credited: HashMap<XorName, Vec<PeerId>>,
    /// For each node, how many backed addresses credit it.
    counts: HashMap<PeerId, usize>,
}

impl Backing {
    fn count(&self, peer: &PeerId) -> usize {
        self.counts.get(peer).copied().unwrap_or(0)
    }

    /// Count `address` again from what the mirrors in `nodes` hold. Returns
    /// the nodes whose counts changed.
    fn recount<C: NearestNodes + ?Sized>(
        &mut self,
        census: &C,
        nodes: &BTreeMap<PeerId, NodeState>,
        address: &XorName,
    ) -> Vec<PeerId> {
        let near = census.nearest(address, WALK_EARNING_RANKS);
        let holds = |peer: &PeerId| {
            nodes
                .get(peer)
                .is_some_and(|node| node.mirror.get(address).is_some())
        };
        let support = near
            .iter()
            .take(NEAREST_NODES)
            .filter(|&peer| holds(peer))
            .count();
        let credited: Vec<PeerId> = if support >= QUORUM_THRESHOLD {
            near.iter().filter(|&peer| holds(peer)).copied().collect()
        } else {
            Vec::new()
        };
        let old = self.credited.remove(address).unwrap_or_default();
        if old == credited {
            if !credited.is_empty() {
                self.credited.insert(*address, credited);
            }
            return Vec::new();
        }
        for peer in &old {
            if let Some(count) = self.counts.get_mut(peer) {
                *count = count.saturating_sub(1);
            }
        }
        for peer in &credited {
            *self.counts.entry(*peer).or_default() += 1;
        }
        let mut changed: Vec<PeerId> = old.into_iter().chain(credited.iter().copied()).collect();
        changed.sort_unstable();
        changed.dedup();
        if !credited.is_empty() {
            self.credited.insert(*address, credited);
        }
        changed
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
    nodes_db: Database<Bytes, Bytes>,
    entries_db: Database<Bytes, Bytes>,
    changed_db: Database<Bytes, Bytes>,
    nodes: BTreeMap<PeerId, NodeState>,
    /// Nodes whose rows go at the next save.
    removed: BTreeSet<PeerId>,
    /// Addresses whose copies changed and that are not settled yet.
    pending: BTreeSet<XorName>,
    /// Those added since the last save.
    pending_new: BTreeSet<XorName>,
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
            .field("pending", &self.pending.len())
            .finish_non_exhaustive()
    }
}

impl Feeds {
    /// The mirrors kept in `store`: none the first time.
    ///
    /// # Errors
    ///
    /// If its databases can't be opened or read. A row this version can't
    /// read is dropped, and that node read afresh.
    pub fn open(store: &ListingsStore) -> Result<Self> {
        let nodes_db: Database<Bytes, Bytes> = store.database(NODES_DB)?;
        let entries_db: Database<Bytes, Bytes> = store.database(ENTRIES_DB)?;
        let changed_db: Database<Bytes, Bytes> = store.database(CHANGED_DB)?;
        let txn = store.env().read_txn().map_err(store_error)?;
        let mut records: BTreeMap<PeerId, NodeRecord> = BTreeMap::new();
        let mut removed = BTreeSet::new();
        for row in nodes_db.iter(&txn).map_err(store_error)? {
            let (key, value) = row.map_err(store_error)?;
            let Ok(id) = <[u8; 32]>::try_from(key) else {
                continue;
            };
            let peer = PeerId::from_bytes(id);
            match serde_json::from_slice::<NodeRecord>(value) {
                Ok(record) => {
                    records.insert(peer, record);
                }
                Err(e) => {
                    debug!("Dropping an unreadable mirror record for {peer}: {e}");
                    removed.insert(peer);
                }
            }
        }
        let mut entries: HashMap<PeerId, Vec<DigestEntry>> = HashMap::new();
        for row in entries_db.iter(&txn).map_err(store_error)? {
            let (key, value) = row.map_err(store_error)?;
            let Some((peer, address)) = split_key(key) else {
                continue;
            };
            if !records.contains_key(&peer) {
                removed.insert(peer);
                continue;
            }
            if let Some(entry) = decode_entry(address, value) {
                entries.entry(peer).or_default().push(entry);
            }
        }
        let mut pending = BTreeSet::new();
        for row in changed_db.iter(&txn).map_err(store_error)? {
            let (key, _) = row.map_err(store_error)?;
            if let Ok(address) = XorName::try_from(key) {
                pending.insert(address);
            }
        }
        drop(txn);
        let mut nodes = BTreeMap::new();
        for (peer, record) in records {
            let held = entries.remove(&peer).unwrap_or_default();
            match record.state(held) {
                Some(state) => {
                    nodes.insert(peer, state);
                }
                None => {
                    removed.insert(peer);
                }
            }
        }
        Ok(Self {
            store: store.clone(),
            nodes_db,
            entries_db,
            changed_db,
            nodes,
            removed,
            pending,
            pending_new: BTreeSet::new(),
            backing: Backing::default(),
            members: None,
            round_at: 0,
        })
    }

    /// Read every node of `nodes` once, as the cycle's poll: see the module
    /// docs. At most [`POLL_CONCURRENCY`] requests are in flight at once,
    /// each through `io`; the round ends when no node has more to ask, or at
    /// `deadline`, whichever is first. Pushes from `pushes` are taken as they
    /// come. Nodes not in `nodes` leave, with their mirrors; `census` says
    /// which nodes are nearest an address, for the nodes' allowances. Pass
    /// every census node: a change in who is passed counts every address's
    /// backing again. `now` is the cycle's time (Unix seconds). The mirrors
    /// are saved at the end.
    ///
    /// # Errors
    ///
    /// If the store can't be written. Nodes that fail are no error.
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
        self.reconcile(census, nodes, now);
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
                    if self.take_answer(census, &peer, answer, now) {
                        ready.push_back(peer);
                    }
                }
                push = next_push(&mut pushes), if pushes_open => match push {
                    Some((source, push)) => {
                        if matches!(self.push(census, &source, &push), Pushed::Applied(_)) {
                            pushed += 1;
                        }
                    }
                    None => pushes_open = false,
                },
            }
        }
        drop(running);
        let report = self.end_round(pushed);
        self.save()?;
        Ok(report)
    }

    /// Take a push from `peer`'s watch, routed between polls: applied if
    /// `peer` is read through its feed and the push brings its mirror
    /// exactly to the push's head, within its allowance (see
    /// [`FeedSync::push`]). The addresses it changes join
    /// [`Self::pending`]. `peer` must be the node the push came from, as the
    /// transport gives it. Call [`Self::save`] once the pushes at hand are
    /// handled.
    pub fn push<C: NearestNodes + ?Sized>(
        &mut self,
        census: &C,
        peer: &PeerId,
        push: &ChangesResponse,
    ) -> Pushed {
        let Some(node) = self.nodes.get_mut(peer) else {
            return Pushed::Ignored;
        };
        let Mirror::Feed(sync) = &mut node.mirror else {
            return Pushed::Ignored;
        };
        let pushed = sync.push(push);
        if let Pushed::Applied(touched) = &pushed {
            node.meta_dirty = true;
            node.dirty.extend(touched.iter().copied());
            self.note_touched(census, touched);
        }
        pushed
    }

    /// Write what changed since the last save, in one transaction.
    ///
    /// # Errors
    ///
    /// If the store can't be written; what changed is kept for the next
    /// save.
    pub fn save(&mut self) -> Result<()> {
        let mut txn = self.store.env().write_txn().map_err(store_error)?;
        for peer in &self.removed {
            self.nodes_db
                .delete(&mut txn, peer.as_bytes())
                .map_err(store_error)?;
            let keys: Vec<Vec<u8>> = self
                .entries_db
                .prefix_iter(&txn, peer.as_bytes())
                .map_err(store_error)?
                .map(|row| row.map(|(key, _)| key.to_vec()))
                .collect::<std::result::Result<_, _>>()
                .map_err(store_error)?;
            for key in keys {
                self.entries_db
                    .delete(&mut txn, &key)
                    .map_err(store_error)?;
            }
        }
        for (peer, node) in &self.nodes {
            if node.meta_dirty {
                let record = serde_json::to_vec(&node.record()).map_err(|e| {
                    crate::data::error::Error::Serialization(format!("mirror record: {e}"))
                })?;
                self.nodes_db
                    .put(&mut txn, peer.as_bytes(), &record)
                    .map_err(store_error)?;
            }
            for address in &node.dirty {
                let key = entry_key(peer, address);
                match node.mirror.get(address) {
                    Some(entry) => self
                        .entries_db
                        .put(&mut txn, &key, &encode_entry(entry))
                        .map_err(store_error)?,
                    None => {
                        self.entries_db
                            .delete(&mut txn, &key)
                            .map_err(store_error)?;
                    }
                }
            }
        }
        for address in &self.pending_new {
            self.changed_db
                .put(&mut txn, address, &[])
                .map_err(store_error)?;
        }
        txn.commit().map_err(store_error)?;
        self.removed.clear();
        self.pending_new.clear();
        for node in self.nodes.values_mut() {
            node.meta_dirty = false;
            node.dirty.clear();
        }
        Ok(())
    }

    /// The addresses whose copies changed since they were last settled: in
    /// a node's mirror, or by a node's copies starting or ceasing to count.
    /// Decide these, and settle them once published ([`Self::settle`]).
    #[must_use]
    pub fn pending(&self) -> &BTreeSet<XorName> {
        &self.pending
    }

    /// Note that what was decided from `addresses` is published: they leave
    /// [`Self::pending`] until their copies change again.
    ///
    /// # Errors
    ///
    /// If the store can't be written.
    pub fn settle<'a>(&mut self, addresses: impl IntoIterator<Item = &'a XorName>) -> Result<()> {
        let mut txn = self.store.env().write_txn().map_err(store_error)?;
        let mut settled = Vec::new();
        for address in addresses {
            self.changed_db
                .delete(&mut txn, address)
                .map_err(store_error)?;
            settled.push(*address);
        }
        txn.commit().map_err(store_error)?;
        for address in settled {
            self.pending.remove(&address);
            self.pending_new.remove(&address);
        }
        Ok(())
    }

    /// How `peer`'s latest round went, if it is followed.
    #[must_use]
    pub fn read(&self, peer: &PeerId) -> Option<&NodeRead> {
        self.nodes.get(peer).map(|node| &node.read)
    }

    /// The entry `peer`'s mirror holds for `address`, counting or not.
    #[must_use]
    pub fn entry(&self, peer: &PeerId, address: &XorName) -> Option<&DigestEntry> {
        self.nodes.get(peer)?.mirror.get(address)
    }

    /// The copies of `address` held by those of `nearest` whose copies count
    /// this cycle ([`NodeRead::counts`]), in the order of `nearest`.
    #[must_use]
    pub fn copies(&self, address: &XorName, nearest: &[PeerId]) -> Vec<(PeerId, DigestEntry)> {
        nearest
            .iter()
            .filter_map(|peer| {
                let node = self.nodes.get(peer)?;
                if !node.read.counts {
                    return None;
                }
                node.mirror.get(address).map(|entry| (*peer, *entry))
            })
            .collect()
    }

    /// Every node whose mirror holds `address`, counting or not, in id
    /// order.
    #[must_use]
    pub fn holders(&self, address: &XorName) -> Vec<PeerId> {
        self.nodes
            .iter()
            .filter(|(_, node)| node.mirror.get(address).is_some())
            .map(|(peer, _)| *peer)
            .collect()
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

    /// `peer`'s allowance in pages a round: what it may be asked for in one,
    /// as [`MAX_LIST_LIMIT`]-entry pages of its allowance of entries.
    #[must_use]
    pub fn page_allowance(&self, peer: &PeerId) -> usize {
        allowance(self.backing.count(peer)).div_ceil(PAGE)
    }

    /// Every address some node's mirror holds, counting or not.
    #[must_use]
    pub fn addresses(&self) -> BTreeSet<XorName> {
        self.nodes
            .values()
            .flat_map(|node| node.mirror.addresses())
            .collect()
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

    /// Bring the nodes followed in line with `nodes`: drop those not in it,
    /// take in new ones, switch the way a node is read, and follow its new
    /// range. Counts the backing again if who is followed changed.
    fn reconcile<C: NearestNodes + ?Sized>(&mut self, census: &C, nodes: &[FeedNode], now: u64) {
        let wanted: BTreeMap<PeerId, &FeedNode> =
            nodes.iter().map(|node| (node.peer, node)).collect();
        let leaving: Vec<PeerId> = self
            .nodes
            .keys()
            .filter(|peer| !wanted.contains_key(peer))
            .copied()
            .collect();
        let mut touched = Vec::new();
        for peer in leaving {
            if let Some(node) = self.nodes.remove(&peer) {
                touched.extend(node.mirror.addresses());
                self.removed.insert(peer);
            }
        }
        for (peer, wanted) in &wanted {
            let node = self.nodes.entry(*peer).or_insert_with(|| {
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
            if node.mirror.kind() != kind {
                info!(
                    "Reading {peer} {} from now on",
                    match kind {
                        ReadKind::Feed => "through its change feed",
                        ReadKind::V2 => "with listings v2 requests",
                    }
                );
                touched.extend(node.switch(kind));
            }
            if node.range != wanted.range {
                touched.extend(node.rescope(wanted.range));
            }
        }
        let members: Vec<PeerId> = self.nodes.keys().copied().collect();
        if self.members.as_ref() != Some(&members) {
            self.members = Some(members);
            self.recount_all(census);
        }
        self.note_touched(census, &touched);
    }

    /// Count every address's backing again, as after a change in who is
    /// followed.
    fn recount_all<C: NearestNodes + ?Sized>(&mut self, census: &C) {
        self.backing = Backing::default();
        let addresses: BTreeSet<XorName> = self
            .nodes
            .values()
            .flat_map(|node| node.mirror.addresses())
            .collect();
        for address in &addresses {
            self.backing.recount(census, &self.nodes, address);
        }
        for (peer, node) in &mut self.nodes {
            node.set_backed(self.backing.count(peer));
        }
    }

    /// Note that `touched`'s entries changed in some mirror: they wait to be
    /// settled, and their backing is counted again.
    fn note_touched<C: NearestNodes + ?Sized>(&mut self, census: &C, touched: &[XorName]) {
        let mut affected = BTreeSet::new();
        for address in touched {
            if self.pending.insert(*address) {
                self.pending_new.insert(*address);
            }
            affected.extend(self.backing.recount(census, &self.nodes, address));
        }
        for peer in affected {
            let backed = self.backing.count(&peer);
            if let Some(node) = self.nodes.get_mut(&peer) {
                node.set_backed(backed);
            }
        }
    }

    /// Take `peer`'s answer. Returns whether it has another request to send
    /// this round.
    fn take_answer<C: NearestNodes + ?Sized>(
        &mut self,
        census: &C,
        peer: &PeerId,
        answer: Option<ListingsBody>,
        now: u64,
    ) -> bool {
        let room = allowance(self.backing.count(peer));
        let Some(node) = self.nodes.get_mut(peer) else {
            return false;
        };
        let (touched, again) = node.take_answer(answer, now, room);
        self.note_touched(census, &touched);
        again
    }

    /// End the round for every node, and say how it went.
    fn end_round(&mut self, pushes: usize) -> PollReport {
        let mut report = PollReport {
            nodes: self.nodes.len(),
            pushes,
            ..PollReport::default()
        };
        let mut flipped = Vec::new();
        for node in self.nodes.values_mut() {
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
                flipped.extend(node.mirror.addresses());
                node.counted = read.counts;
            }
        }
        for address in flipped {
            if self.pending.insert(address) {
                self.pending_new.insert(address);
            }
        }
        report.pending = self.pending.len();
        report
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
mod tests {
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
    enum Behaviour {
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
    }

    /// A node, as a change feed and a listings v2 index.
    struct FakeNode {
        behaviour: Behaviour,
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
        fn new(behaviour: Behaviour) -> Self {
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

        fn serving(behaviour: Behaviour, served: Vec<DigestEntry>) -> Self {
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

        fn put(&mut self, entry: DigestEntry) {
            self.record(entry.address, Some(entry));
        }

        fn remove(&mut self, address: &XorName) {
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
        fn renumber(&mut self, epoch: u64) {
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
            match body {
                ListingsBody::ChangesRequest(request) => {
                    if self.behaviour == Behaviour::Unsupported {
                        return unsupported;
                    }
                    self.watch = request.watch.then(|| request.range());
                    Some(ListingsBody::ChangesResponse(self.changes(&request)))
                }
                ListingsBody::RangeListRequest(request) => {
                    if self.behaviour == Behaviour::Unsupported {
                        return unsupported;
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
    struct FakeNet {
        nodes: Mutex<HashMap<PeerId, FakeNode>>,
        asked: Mutex<Vec<(PeerId, ListingsBody)>>,
    }

    impl FakeNet {
        fn with(nodes: Vec<(PeerId, FakeNode)>) -> Self {
            Self {
                nodes: Mutex::new(nodes.into_iter().collect()),
                asked: Mutex::default(),
            }
        }

        fn node<T>(&self, peer: &PeerId, f: impl FnOnce(&mut FakeNode) -> T) -> T {
            f(self.nodes.lock().unwrap().get_mut(peer).unwrap())
        }

        /// The requests sent to `peer` so far, and forget them.
        fn take_asked(&self, peer: &PeerId) -> Vec<ListingsBody> {
            let mut asked = self.asked.lock().unwrap();
            let (to_peer, rest): (Vec<_>, Vec<_>) = asked.drain(..).partition(|(to, _)| to == peer);
            *asked = rest;
            to_peer.into_iter().map(|(_, body)| body).collect()
        }

        /// Whether the node serves exactly what `feeds` mirrors of it.
        fn mirrored(&self, feeds: &Feeds, peer: &PeerId) -> bool {
            self.node(peer, |node| {
                let mirrored: Vec<DigestEntry> = feeds.nodes[peer]
                    .mirror
                    .addresses()
                    .iter()
                    .filter_map(|address| feeds.entry(peer, address).copied())
                    .collect();
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
        let settled: Vec<XorName> = feeds.pending().iter().copied().collect();
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
        assert_eq!(feeds.pending().len(), 300);
        let first = address(0);
        assert_eq!(feeds.copies(&first, &[a]), vec![(a, entry(first, 1))]);
        assert_eq!(feeds.holders(&first), vec![a]);

        // Once settled, only what changes next is pending.
        settle_all(&mut feeds);
        assert!(feeds.pending().is_empty());
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
        assert_eq!(feeds.pending(), &expected);
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
            let settled: Vec<XorName> = feeds.pending().iter().take(100).copied().collect();
            feeds.settle(&settled).unwrap();
            net.node(&a, |node| node.head)
        };
        net.take_asked(&a);
        net.node(&a, |node| node.put(entry(address(5_000), 1)));

        let store = store(dir.path());
        let mut feeds = Feeds::open(&store).unwrap();
        // What wasn't settled is still pending.
        assert_eq!(feeds.pending().len(), 200);
        assert_eq!(feeds.nodes[&a].mirror.len(), 300);
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
        assert_eq!(feeds.pending().len(), 301);
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
        assert_eq!(feeds.nodes[&a].mirror.len(), 41);
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
        assert_eq!(feeds.push(&ids, &stranger, &push), Pushed::Ignored);
        assert_eq!(
            feeds.push(&ids, &a, &push),
            Pushed::Applied(vec![address(500)])
        );
        assert!(feeds.read(&a).unwrap().counts);
        assert_eq!(feeds.pending(), &BTreeSet::from([address(500)]));
        // The same push again changes nothing.
        assert_eq!(feeds.push(&ids, &a, &push), Pushed::Ignored);

        // A push that skips a record is left for the next poll.
        net.node(&a, |node| {
            node.put(entry(address(501), 1));
            node.put(entry(address(502), 1));
        });
        let pushes = net.node(&a, |node| std::mem::take(&mut node.pushes));
        assert_eq!(feeds.push(&ids, &a, &pushes[1]), Pushed::Behind);
        assert!(feeds.entry(&a, &address(502)).is_none());
        // One from another epoch, or with peers, is left alone.
        let mut other_epoch = pushes[0].clone();
        other_epoch.epoch = 99;
        assert_eq!(feeds.push(&ids, &a, &other_epoch), Pushed::Ignored);
        let mut with_peers = pushes[0].clone();
        with_peers.peers = vec![[3; 32]];
        assert_eq!(feeds.push(&ids, &a, &with_peers), Pushed::Ignored);
        feeds.save().unwrap();

        poll(&mut feeds, &net, &nodes, NOW + 60).await;
        assert!(net.mirrored(&feeds, &a));
        assert!(feeds.read(&a).unwrap().counts);
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
        assert!(feeds.entry(&a, &address(500)).is_some());
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
            feeds.copies(&address(0), &[a, b]),
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
        assert!(feeds.pending().is_empty());
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
                assert!(feeds.nodes[&peer].mirror.len() <= WALK_FREE_LISTINGS);
            }
            assert_eq!(net.take_asked(&v2_flood).len(), 1);
            assert!(feeds.nodes[&v2_flood].mirror.len() <= WALK_FREE_LISTINGS);
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
        assert_eq!(feeds.pending().len(), 600);

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
        assert!(feeds.entry(&a, &address(9_000)).is_some());
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
        assert!(feeds.copies(&address(1), &[a]).is_empty());
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
        assert_eq!(feeds.pending().len(), 20);
        assert!(feeds.copies(&address(0), &[known]).is_empty());
        assert_eq!(feeds.holders(&address(0)), vec![known]);
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
        let held = feeds.nodes[&a].mirror.len();
        assert!(held > 0 && held <= WALK_FREE_LISTINGS, "{held}");

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
            assert_eq!(feeds.pending().len(), 100);
        }
        let store = store(dir.path());
        let feeds = Feeds::open(&store).unwrap();
        assert_eq!(feeds.len(), 1);
        assert_eq!(feeds.nodes[&a].range, half);
        assert_eq!(feeds.nodes[&a].mirror.len(), inside);
        let txn = store.env().read_txn().unwrap();
        assert_eq!(feeds.entries_db.len(&txn).unwrap(), inside as u64);
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
