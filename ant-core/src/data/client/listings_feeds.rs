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
pub type PushReceiver = tokio::sync::mpsc::Receiver<(PeerId, ChangesResponse)>;

/// Sends listings requests to nodes: the producer's `ListingsRequests`, or a
/// stand-in in tests.
#[async_trait::async_trait]
pub trait FeedIo: Sync {
    /// Send `body` to `peer` and wait for its answer, or `None` if none
    /// came in time. An [`Error`](ListingsBody::Error) is the answer it is.
    async fn ask(&self, peer: &PeerId, body: ListingsBody) -> Option<ListingsBody>;
}

#[async_trait::async_trait]
impl FeedIo for ListingsRequests {
    async fn ask(&self, peer: &PeerId, body: ListingsBody) -> Option<ListingsBody> {
        ListingsRequests::ask(self, peer, body).await
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
    /// Whether it answered a request this round, whatever the checks made of
    /// the answer.
    pub answered: bool,
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
    /// Those that answered a request.
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
    /// When it last refused a feed request, or didn't answer one before it
    /// had ever answered one (Unix seconds).
    feed_refused_at: Option<u64>,
    /// Whether its copies counted in the last round.
    counted: bool,
    read: NodeRead,
    /// Whether it answered a request this round.
    answered: bool,
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
                let touched = match answer {
                    Some(body) if !refused => sync.answer(body),
                    _ => {
                        sync.no_answer();
                        Vec::new()
                    }
                };
                self.meta_dirty = true;
                self.dirty.extend(touched.iter().copied());
                let never_followed = sync.epoch() == 0 && !self.answered;
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
                    answered: self.answered,
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
                    answered: self.answered,
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
                    complete: record.complete,
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
        I: FeedIo + ?Sized,
        C: NearestNodes + ?Sized,
    {
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
            report.answered += usize::from(read.answered);
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
