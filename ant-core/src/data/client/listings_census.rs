//! The listings producer's census: every node of the network it knows, and
//! the leaves the address space is split into for asking them.
//!
//! An index read used to find the nodes to ask anew each time, with a few
//! random lookups, which miss close groups as the network grows. The
//! producer keeps a census instead:
//!
//! - **Proof of life.** A node joins the census only once it has answered a
//!   lookup: a witnessed lookup gives as the nodes nearest its target only
//!   nodes that answered it
//!   ([`Network::find_witnessed_close_group_with_view_count`]). The ids the
//!   responders' views name are merged, and those that answered no lookup
//!   are reported ([`CensusChange::unanswered`]) but never join, so an id a
//!   peer slips into its view or its list of peers never becomes one of an
//!   address's nearest nodes.
//! - **Leaves.** The address space is split as [`ant_listings::leaves`]
//!   splits it over the census's ids: a range is halved only while both
//!   halves hold at least [`NEAREST_NODES`] nodes, so the [`NEAREST_NODES`]
//!   nodes nearest any address are all in its leaf. Each node is asked about
//!   its own leaf ([`Census::leaf_of`]).
//! - **Closing a range.** The census looks up an address in the range
//!   ([`LOOKUP_NODES`] nodes, each naming [`VIEW_PEERS`] in its view). Every
//!   node that shares more leading bits with that address than the farthest
//!   of those that answered does is nearer it than that node, so every such
//!   node that answers is among them: that part of the range is closed. If
//!   the farthest is outside the range, all of it is; otherwise the rest of
//!   it is closed in the same way, part by part ([`Census::close_leaf`]).
//!   Every node that answered joins. A member in a closed part that wasn't
//!   found, and didn't answer its latest poll either, leaves.
//! - **When.** A leaf is closed again when a member misses
//!   [`MISSES_BEFORE_CLOSE`] polls in a row ([`Census::record_miss`]), when a
//!   node's view changes ([`Census::record_view`]) and its list of peers
//!   names a node the census lacks ([`Census::note_peers`]), and before any
//!   listing in it is dropped ([`Census::witness`]); and every leaf is closed
//!   once every [`REFRESH_INTERVAL`] ([`Census::refresh`]). The first two
//!   queue the leaf, kept in the store, and [`Census::maintain`], once a
//!   cycle, closes what is queued, or every leaf when the refresh is due.
//! - **Drops.** A published listing is dropped only on evidence for its
//!   address within one cycle ([`Census::confirm_drop`]): all
//!   [`NEAREST_NODES`] of the census's nodes nearest it answered and serve no
//!   copy at any key (the producer's poll); a witnessed lookup of the
//!   address itself, closing its leaf, finds the same nodes nearest it
//!   ([`Census::witness`], [`Witness::check`]); a `GetRequest` to each of
//!   them, sent at or after the address's key time plus
//!   [`FIRST_SEEN_ROUNDING`] and [`CLOCK_MARGIN`], returns none; and so does
//!   one to each node that served it when it was last decided, unless that
//!   node has left the census ([`DropCheck`]).
//! - **Versions.** Each node's user agent says which release it runs, read
//!   as a node reads its peers' when it tallies their versions
//!   ([`user_agent_of`]). One from [`FEED_RELEASE`] on answers change feeds
//!   ([`Census::supports_feed`]), and older ones are read with the listings
//!   v2 requests.
//! - **Guard.** A cycle in which fewer than [`NEAREST_NODES`] of the
//!   census answered, or under three quarters of it, decides and drops
//!   nothing ([`Census::guard_ok`]).
//!
//! The census is kept in the producer's store
//! ([`ListingsStore`], databases [`NODES_DB`], [`QUEUE_DB`] and
//! [`META_DB`]); changes are written once a cycle ([`Census::save`]).
//!
//! **Each cycle**, the producer:
//!
//! 1. calls [`Census::maintain`] (at its first start this closes every leaf);
//! 2. polls each of [`Census::nodes`], asking a node that
//!    [`Census::supports_feed`] about its leaf ([`Census::leaf_of`]), and
//!    notes each answer ([`Census::record_answer`], [`Census::record_view`],
//!    and [`Census::note_peers`] for a list of peers asked for after a
//!    changed view) or miss ([`Census::record_miss`]);
//! 3. decides only if [`Census::guard_ok`] for the nodes that answered;
//! 4. counts an address's support among [`Census::nearest`];
//! 5. drops a listing only through [`Census::confirm_drop`];
//! 6. writes the census ([`Census::save`]) and its status
//!    ([`Census::status`]).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use std::time::Duration;

use ant_listings::{
    leaf_index, leaves, nearest_by_distance, AddressRange, Leaf, CLOCK_MARGIN, FIRST_SEEN_ROUNDING,
    NEAREST_NODES, VIEW_PEERS,
};
use ant_protocol::transport::{MultiAddr, PeerId, WitnessedCloseGroup};
use ant_protocol::XorName;
use futures::stream::{FuturesUnordered, StreamExt};
use heed::types::{Bytes, SerdeJson, Str, Unit, U64};
use heed::{byteorder::BigEndian, Database};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::data::client::listings::{unix_now, ListingsRequests};
use crate::data::client::listings_store::{store_error, ListingsStore};
use crate::data::client::listings_v1::{CensusStatus, SilentNode, VersionCount};
use crate::data::client::Client;
use crate::data::error::{Error, Result};
use crate::data::network::Network;

/// A member's leaf is closed again once it has missed this many polls in a
/// row.
pub const MISSES_BEFORE_CLOSE: u32 = 3;

/// Every leaf is closed again this often: once a day.
pub const REFRESH_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// The first node release that keeps a change feed and answers
/// `ChangesRequest` and `RangeListRequest`: `ds.15`, as a node's user agent
/// gives it (`node/0.23.0+ds.15`).
pub const FEED_RELEASE: u64 = 15;

/// How many nodes a lookup that closes part of the address space asks for:
/// the DHT's bucket size, as many as the nearest peers a node lists in its
/// view ([`VIEW_PEERS`]). Where the network has too few nodes for a lookup
/// that wide, the lookup asks for [`NEAREST_NODES`] instead.
pub const LOOKUP_NODES: usize = VIEW_PEERS;

/// How many lookups closing runs at once: as many as an index read's crawl
/// of the network makes at once.
pub const CLOSE_CONCURRENCY: usize = 8;

/// The census's nodes, by id.
pub const NODES_DB: &str = "census_nodes";

/// The leaves queued to be closed again ([`Census::queued`]), each as its
/// prefix's 32 bytes and then how many bits it fixes.
pub const QUEUE_DB: &str = "census_queue";

/// The census's other state: when it was last refreshed.
pub const META_DB: &str = "census_meta";

/// The key in [`META_DB`] of when every leaf was last closed (Unix seconds).
const REFRESHED_AT: &str = "refreshed_at";

/// What a node's user agent starts with: clients' don't.
const NODE_AGENT: &str = "node/";

/// A node the census knows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CensusNode {
    /// The node's id.
    pub peer: PeerId,
    /// Where it can be reached, as the lookup that found it gave them.
    pub addresses: Vec<MultiAddr>,
    /// When it joined the census, having answered (Unix seconds).
    pub first_seen: u64,
    /// When it last answered a poll (Unix seconds); `None` if it never has.
    pub last_answered: Option<u64>,
    /// The user agent it gave, such as `node/0.23.0+ds.15`, if known: its
    /// own word for the release it runs.
    pub user_agent: Option<String>,
    /// How many polls in a row it has missed.
    pub missed: u32,
    /// The view it gave in its latest answer to a change feed's request: a
    /// hash of its nearest peers ([`ant_listings::view_hash`]), if known.
    #[serde(default)]
    pub view: Option<[u8; 32]>,
}

impl CensusNode {
    /// Whether it answered its latest poll.
    fn answered_latest_poll(&self) -> bool {
        self.last_answered.is_some() && self.missed == 0
    }
}

/// What closing leaves changed in the census.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CensusChange {
    /// Nodes that joined, having answered a lookup.
    pub joined: Vec<PeerId>,
    /// Nodes that left: not found answering when their part of the address
    /// space was closed, and silent at their latest poll.
    pub left: Vec<PeerId>,
    /// Ids that the views of nodes that answered named in the part closed,
    /// but that answered no lookup: made up, gone, or out of reach. They
    /// didn't join.
    pub unanswered: Vec<PeerId>,
}

impl CensusChange {
    /// Whether nothing changed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.joined.is_empty() && self.left.is_empty()
    }

    /// Add what `later` changed after this: a node that joined and then
    /// left counts as left, and one that left and then joined as joined.
    pub fn absorb(&mut self, later: CensusChange) {
        let joined: BTreeSet<PeerId> = later.joined.iter().copied().collect();
        let left: BTreeSet<PeerId> = later.left.iter().copied().collect();
        self.joined.retain(|peer| !left.contains(peer));
        self.left.retain(|peer| !joined.contains(peer));
        for peer in later.joined {
            if !self.joined.contains(&peer) {
                self.joined.push(peer);
            }
        }
        for peer in later.left {
            if !self.left.contains(&peer) {
                self.left.push(peer);
            }
        }
        for peer in later.unanswered {
            if !self.unanswered.contains(&peer) {
                self.unanswered.push(peer);
            }
        }
    }
}

/// How a node answered a `GetRequest` for an address, sent to confirm that
/// a listing there is no longer served.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Served {
    /// It answered with no listing for the address at any key, or with one
    /// that [`ant_listings::check_get_response`] refuses (for another
    /// address, or malformed), as an index read's lookup of one address
    /// counts it.
    Nothing,
    /// It answered with a listing for the address.
    Listing,
    /// It didn't answer.
    Silent,
}

/// A witnessed lookup of an address that closed its leaf: what a drop of a
/// listing there needs to confirm its nearest nodes ([`Census::witness`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witness {
    /// The address looked up.
    pub address: XorName,
    /// Its leaf, as the census split the address space before the lookups.
    pub leaf: AddressRange,
    /// The [`NEAREST_NODES`] nodes nearest the address that answered a
    /// witnessed lookup of it, nearest first: fewer only if fewer answered.
    pub nearest: Vec<PeerId>,
    /// The census's [`NEAREST_NODES`] nodes nearest the address once it took
    /// in what the lookups found, nearest first.
    pub census_nearest: Vec<PeerId>,
    /// Whether every part of the leaf was closed: false when a lookup of
    /// some part of it failed.
    pub closed: bool,
    /// What closing the leaf changed in the census.
    pub change: CensusChange,
}

impl Witness {
    /// Whether this confirms that `expected`, the census's nodes nearest the
    /// address that a cycle found serving nothing there, are its nearest:
    /// the whole leaf was closed, and both the lookup of the address and the
    /// census after it give the same [`NEAREST_NODES`] nodes as `expected`,
    /// in any order.
    ///
    /// # Errors
    ///
    /// Why it doesn't, as text for the log.
    pub fn check(&self, expected: &[PeerId]) -> std::result::Result<(), String> {
        let expected_set: BTreeSet<&PeerId> = expected.iter().collect();
        if expected_set.len() < NEAREST_NODES {
            return Err(format!(
                "only {} nodes nearest it were expected, not {NEAREST_NODES}",
                expected_set.len()
            ));
        }
        if !self.closed {
            return Err(format!(
                "the lookups closing its leaf {} didn't all succeed",
                range_text(&self.leaf)
            ));
        }
        let witnessed: BTreeSet<&PeerId> = self.nearest.iter().collect();
        if witnessed != expected_set {
            return Err(format!(
                "a witnessed lookup of it found {} of the {} nodes nearest it the census gave",
                witnessed.intersection(&expected_set).count(),
                expected_set.len()
            ));
        }
        let census: BTreeSet<&PeerId> = self.census_nearest.iter().collect();
        if census != expected_set {
            return Err(format!(
                "after closing its leaf, the census's nodes nearest it are {} of the {} it gave \
                 before",
                census.intersection(&expected_set).count(),
                expected_set.len()
            ));
        }
        Ok(())
    }
}

/// What a drop of the listing at an address needs to hear, once its
/// nearest nodes are witnessed ([`Census::drop_check`]): whom to ask with a
/// `GetRequest`, and from when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropCheck {
    /// The address.
    pub address: XorName,
    /// Ask none before this (Unix seconds): the address's key time plus
    /// [`FIRST_SEEN_ROUNDING`] and [`CLOCK_MARGIN`]. A node that stored the
    /// listing when the quorum did keys it by its own date, up to that much
    /// later than the key time.
    pub ask_from: u64,
    /// The nodes to ask: the witnessed nearest, then the last holders still
    /// in the census, once each.
    pub ask: Vec<PeerId>,
    /// The last holders no longer in the census: they left, and aren't
    /// asked.
    pub left: Vec<PeerId>,
    /// Why no answers can confirm the drop, if none can: the witness didn't
    /// confirm the nearest nodes.
    pub refused: Option<String>,
}

impl DropCheck {
    /// Whether `answers` to `GetRequest`s sent from `asked_at` (Unix
    /// seconds) confirm the drop: the witness confirmed the nearest nodes,
    /// the round began no earlier than [`Self::ask_from`], and every node in
    /// [`Self::ask`] answered serving nothing.
    ///
    /// # Errors
    ///
    /// Why the listing stays, as text for the log.
    pub fn verdict(
        &self,
        asked_at: u64,
        answers: &[(PeerId, Served)],
    ) -> std::result::Result<(), String> {
        if let Some(refused) = &self.refused {
            return Err(refused.clone());
        }
        if asked_at < self.ask_from {
            return Err(format!(
                "asked at {asked_at}, before {}, when every node that stored it has keyed it",
                self.ask_from
            ));
        }
        let answers: BTreeMap<&PeerId, Served> = answers
            .iter()
            .map(|(peer, served)| (peer, *served))
            .collect();
        let (mut serving, mut silent) = (0usize, 0usize);
        for peer in &self.ask {
            match answers.get(peer) {
                Some(Served::Nothing) => {}
                Some(Served::Listing) => serving += 1,
                Some(Served::Silent) | None => silent += 1,
            }
        }
        if serving > 0 || silent > 0 {
            return Err(format!(
                "of the {} nodes asked, {serving} serve a listing for it and {silent} didn't answer",
                self.ask.len()
            ));
        }
        Ok(())
    }
}

/// The census's nodes in id order, with their leaves: worked out once after
/// each change to who is in the census.
#[derive(Debug)]
struct Index {
    peers: Vec<PeerId>,
    ids: Vec<[u8; 32]>,
    leaves: Vec<Leaf>,
}

impl Index {
    fn new(nodes: &BTreeMap<PeerId, CensusNode>) -> Self {
        // A peer's order is its id's, so `ids` is sorted.
        let peers: Vec<PeerId> = nodes.keys().copied().collect();
        let ids: Vec<[u8; 32]> = peers.iter().map(|peer| *peer.as_bytes()).collect();
        let leaves = leaves(&ids);
        Self { peers, ids, leaves }
    }

    /// Where the ids in `range` are in [`Self::ids`].
    fn span(&self, range: &AddressRange) -> std::ops::Range<usize> {
        let (first, last) = (range.first(), range.last());
        let start = self.ids.partition_point(|id| *id < first);
        let end = self.ids.partition_point(|id| *id <= last);
        start..end
    }
}

/// The census. See the module docs.
pub struct Census {
    store: ListingsStore,
    nodes_db: Database<Bytes, SerdeJson<CensusNode>>,
    queue_db: Database<Bytes, Unit>,
    meta_db: Database<Str, U64<BigEndian>>,
    nodes: BTreeMap<PeerId, CensusNode>,
    /// Nodes changed since the last save.
    dirty: BTreeSet<PeerId>,
    /// Nodes removed since the last save.
    removed: BTreeSet<PeerId>,
    /// Ranges queued to be closed again.
    queue: BTreeSet<AddressRange>,
    /// Whether the queue changed since the last save.
    queue_dirty: bool,
    refreshed_at: Option<u64>,
    refreshed_dirty: bool,
    /// What changed in the census since [`Self::take_changes`] was last
    /// called.
    changes: CensusChange,
    index: OnceLock<Index>,
}

impl std::fmt::Debug for Census {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Census")
            .field("nodes", &self.nodes.len())
            .field("refreshed_at", &self.refreshed_at)
            .finish_non_exhaustive()
    }
}

impl Census {
    /// The census kept in `store`: empty the first time.
    ///
    /// # Errors
    ///
    /// If its databases can't be opened or read.
    pub fn open(store: &ListingsStore) -> Result<Self> {
        let nodes_db: Database<Bytes, SerdeJson<CensusNode>> = store.database(NODES_DB)?;
        let queue_db: Database<Bytes, Unit> = store.database(QUEUE_DB)?;
        let meta_db: Database<Str, U64<BigEndian>> = store.database(META_DB)?;
        let txn = store.env().read_txn().map_err(store_error)?;
        let mut nodes = BTreeMap::new();
        for row in nodes_db.iter(&txn).map_err(store_error)? {
            let (_, node) = row.map_err(store_error)?;
            nodes.insert(node.peer, node);
        }
        let mut queue = BTreeSet::new();
        for row in queue_db.iter(&txn).map_err(store_error)? {
            let (key, ()) = row.map_err(store_error)?;
            // A row that isn't a range is skipped: the next refresh closes
            // every leaf anyway.
            if let Some(range) = range_from_key(key) {
                queue.insert(range);
            }
        }
        let refreshed_at = meta_db.get(&txn, REFRESHED_AT).map_err(store_error)?;
        drop(txn);
        Ok(Self {
            store: store.clone(),
            nodes_db,
            queue_db,
            meta_db,
            nodes,
            dirty: BTreeSet::new(),
            removed: BTreeSet::new(),
            queue,
            queue_dirty: false,
            refreshed_at,
            refreshed_dirty: false,
            changes: CensusChange::default(),
            index: OnceLock::new(),
        })
    }

    /// The census's upkeep, once a cycle before the poll: every leaf is
    /// closed when the refresh is due ([`Self::refresh_due`], and so at the
    /// first start), and otherwise each range queued ([`Self::queued`]) is
    /// closed, as the leaves now split it: the leaf holding it, or itself
    /// where it holds several. A range closed leaves the queue; one whose
    /// lookups failed stays for the next cycle.
    ///
    /// # Errors
    ///
    /// If a lookup fails: what the others found is taken in all the same
    /// ([`Self::take_changes`]), and the parts not closed stay queued.
    pub async fn maintain(&mut self, client: &Client) -> Result<CensusChange> {
        let mut rng = StdRng::from_entropy();
        let now = unix_now();
        self.maintain_with(&NetworkLookups(client.network()), now, &mut rng)
            .await
    }

    /// [`Self::maintain`] through `lookups`, at `now` (Unix seconds).
    pub(crate) async fn maintain_with<L: Lookups>(
        &mut self,
        lookups: &L,
        now: u64,
        rng: &mut StdRng,
    ) -> Result<CensusChange> {
        if self.refresh_due(now) {
            return self.refresh_with(lookups, now, rng).await;
        }
        let mut change = CensusChange::default();
        let mut failure = None;
        for range in self.ranges_to_close() {
            match self.close_with(lookups, range, now, rng).await {
                Ok(closed) => change.absorb(closed),
                Err(e) => failure = Some(e),
            }
        }
        match failure {
            None => Ok(change),
            Some(e) => Err(e),
        }
    }

    /// What closing the queue closes: for each range queued, the leaf that
    /// holds it, or the range itself where it holds one or more leaves;
    /// none held by another.
    fn ranges_to_close(&self) -> Vec<AddressRange> {
        let leaves = self.leaves();
        let mut ranges: BTreeSet<AddressRange> = BTreeSet::new();
        for queued in &self.queue {
            let holder = leaves.iter().find(|leaf| leaf.covers(queued));
            ranges.insert(holder.copied().unwrap_or(*queued));
        }
        let all: Vec<AddressRange> = ranges.iter().copied().collect();
        ranges
            .into_iter()
            .filter(|range| {
                !all.iter()
                    .any(|other| other != range && other.covers(range))
            })
            .collect()
    }

    /// Queue `range` to be closed again at the next [`Self::maintain`].
    pub fn queue_close(&mut self, range: AddressRange) {
        if self.queue.insert(range) {
            self.queue_dirty = true;
        }
    }

    /// The ranges queued to be closed again, in address order.
    #[must_use]
    pub fn queued(&self) -> Vec<AddressRange> {
        self.queue.iter().copied().collect()
    }

    /// After closing `range`: take out of the queue every range it covers,
    /// and queue the parts of it whose lookups `failed`.
    fn requeue(&mut self, range: &AddressRange, failed: &[AddressRange]) {
        let before = self.queue.len();
        self.queue.retain(|queued| !range.covers(queued));
        if self.queue.len() != before {
            self.queue_dirty = true;
        }
        for part in failed {
            self.queue_close(*part);
        }
    }

    /// Note the list of nearest peers `peer` gave after its view changed
    /// ([`Self::record_view`]): the leaves of the ids in it that the census
    /// lacks ([`Self::lacking`]) are queued to be closed again. Returns how
    /// many leaves that queued.
    pub fn note_peers(&mut self, peers: &[[u8; 32]]) -> usize {
        let lacking = self.lacking(peers);
        let mut queued = 0;
        for range in lacking {
            if self.queue.insert(range) {
                queued += 1;
            }
        }
        if queued > 0 {
            self.queue_dirty = true;
        }
        queued
    }

    /// A witnessed lookup of `address`, closing its leaf (see the module
    /// docs): before a listing there is dropped, to confirm the nodes
    /// nearest it. The first lookup is of the address itself, so the nodes
    /// that answered it nearest it are its witnessed nearest; the rest of the
    /// leaf is closed as [`Self::close_leaf`] closes one, and what it finds
    /// is taken in the same way.
    ///
    /// # Errors
    ///
    /// If the lookup of the address itself fails: then nothing of the leaf
    /// was closed, and nothing may be dropped on its account. A failure of
    /// a later lookup is no error: the witness says the leaf wasn't closed
    /// ([`Witness::closed`]).
    pub async fn witness(&mut self, client: &Client, address: &XorName) -> Result<Witness> {
        let mut rng = StdRng::from_entropy();
        let now = unix_now();
        self.witness_with(&NetworkLookups(client.network()), address, now, &mut rng)
            .await
    }

    /// [`Self::witness`] through `lookups`, at `now` (Unix seconds).
    pub(crate) async fn witness_with<L: Lookups>(
        &mut self,
        lookups: &L,
        address: &XorName,
        now: u64,
        rng: &mut StdRng,
    ) -> Result<Witness> {
        let leaf = self.leaf_of(address);
        let found = explore(lookups, leaf, Some(*address), rng).await;
        let mut agents = BTreeMap::new();
        for peer in found.answered.keys() {
            agents.insert(*peer, lookups.user_agent(peer).await);
        }
        let change = self.take_in(&found, &agents, now);
        self.requeue(&leaf, &found.failed);
        let sighting = match &found.first {
            Some(Ok(sighting)) => sighting,
            Some(Err(e)) => {
                return Err(Error::Network(format!(
                    "a witnessed lookup of {} failed: {e}",
                    hex::encode(address)
                )))
            }
            None => {
                return Err(Error::Network(format!(
                    "no witnessed lookup of {} was made",
                    hex::encode(address)
                )))
            }
        };
        let closed = found.failed.is_empty();
        let mut answered: Vec<PeerId> = sighting.answered.iter().map(|(peer, _)| *peer).collect();
        answered.sort_unstable_by_key(|peer| distance(peer.as_bytes(), address));
        answered.dedup();
        answered.truncate(NEAREST_NODES);
        debug!(
            "Census: witnessed {} with {} lookups closing {}: {} joined, {} left",
            hex::encode(address),
            found.lookups,
            range_text(&leaf),
            change.joined.len(),
            change.left.len()
        );
        Ok(Witness {
            address: *address,
            leaf,
            nearest: answered,
            census_nearest: self.nearest(address, NEAREST_NODES),
            closed,
            change,
        })
    }

    /// Whom a drop of the listing at `address` must hear serve nothing
    /// there, and from when, given `witness` of its nearest nodes,
    /// `expected` (the census's nodes nearest it that the cycle found
    /// answering and serving nothing), the nodes that served it when it was
    /// last decided (`last_holders`), and its key time (Unix seconds).
    #[must_use]
    pub fn drop_check(
        &self,
        witness: &Witness,
        expected: &[PeerId],
        last_holders: &[PeerId],
        key_time: u64,
    ) -> DropCheck {
        let mut ask: Vec<PeerId> = Vec::new();
        let mut left: Vec<PeerId> = Vec::new();
        for peer in &witness.nearest {
            if !ask.contains(peer) {
                ask.push(*peer);
            }
        }
        for peer in last_holders {
            if ask.contains(peer) || left.contains(peer) {
                continue;
            }
            if self.nodes.contains_key(peer) {
                ask.push(*peer);
            } else {
                left.push(*peer);
            }
        }
        DropCheck {
            address: witness.address,
            ask_from: key_time.saturating_add(FIRST_SEEN_ROUNDING + CLOCK_MARGIN),
            ask,
            left,
            refused: witness.check(expected).err(),
        }
    }

    /// Whether the listing at `address`, with key time `key_time` (Unix
    /// seconds), may be dropped: call it only for a published address all
    /// of whose `expected` nodes (the census's [`NEAREST_NODES`] nearest it)
    /// answered this cycle and serve no copy at any key. It needs, now: a
    /// witnessed lookup of the address that closes its leaf and finds the
    /// same nodes ([`Self::witness`]), and then a `GetRequest` to each of
    /// them and of `last_holders` (the nodes that served it when it was last
    /// decided) still in the census, each answering with none
    /// ([`DropCheck::verdict`]). Before the key time plus
    /// [`FIRST_SEEN_ROUNDING`] and [`CLOCK_MARGIN`] nothing is looked up and
    /// the listing stays. What closing the leaf changed in the census is
    /// given by [`Self::take_changes`].
    ///
    /// # Errors
    ///
    /// When the listing stays: why, as text for the log.
    pub async fn confirm_drop(
        &mut self,
        client: &Client,
        address: &XorName,
        key_time: u64,
        expected: &[PeerId],
        last_holders: &[PeerId],
    ) -> std::result::Result<(), String> {
        let mut rng = StdRng::from_entropy();
        self.confirm_drop_with(
            &NetworkLookups(client.network()),
            &NetworkGets(client),
            address,
            key_time,
            expected,
            last_holders,
            &mut rng,
        )
        .await
    }

    /// [`Self::confirm_drop`] through `lookups` and `gets`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn confirm_drop_with<L: Lookups, G: Gets>(
        &mut self,
        lookups: &L,
        gets: &G,
        address: &XorName,
        key_time: u64,
        expected: &[PeerId],
        last_holders: &[PeerId],
        rng: &mut StdRng,
    ) -> std::result::Result<(), String> {
        let ask_from = key_time.saturating_add(FIRST_SEEN_ROUNDING + CLOCK_MARGIN);
        if gets.now() < ask_from {
            return Err(format!(
                "too soon: not every node that stored it has keyed it before {ask_from}"
            ));
        }
        let witness = self
            .witness_with(lookups, address, gets.now(), rng)
            .await
            .map_err(|e| e.to_string())?;
        let check = self.drop_check(&witness, expected, last_holders, key_time);
        if let Some(refused) = check.refused {
            return Err(refused);
        }
        let asked_at = gets.now();
        let answers = gets.get(address, &check.ask).await;
        check.verdict(asked_at, &answers)
    }

    /// Close every leaf: the whole address space, closed part by part with
    /// witnessed lookups (see the module docs), at first from an empty
    /// census, and then once every [`REFRESH_INTERVAL`]
    /// ([`Self::refresh_due`]). Nodes found answering join; members not found
    /// answering, and silent at their latest poll, leave. The census is then
    /// marked refreshed now; parts whose lookups failed are queued
    /// ([`Self::queued`]), so the next [`Self::maintain`] closes only them,
    /// not the whole space again.
    ///
    /// # Errors
    ///
    /// If a lookup fails, even with fewer nodes: what the others found is
    /// taken in all the same, and its part is queued.
    pub async fn refresh(&mut self, client: &Client) -> Result<CensusChange> {
        let mut rng = StdRng::from_entropy();
        let now = unix_now();
        self.refresh_with(&NetworkLookups(client.network()), now, &mut rng)
            .await
    }

    /// Close `range` (usually one of [`Self::leaves`]) again with witnessed
    /// lookups (see the module docs), as [`Self::maintain`] does for what is
    /// queued. Nodes found answering join; members not found answering, and
    /// silent at their latest poll, leave. The leaves may change. Ranges
    /// queued within `range` leave the queue.
    ///
    /// # Errors
    ///
    /// If a lookup fails, even with fewer nodes: then `range` isn't closed,
    /// and its part whose lookup failed is queued. What the other lookups
    /// found is taken in all the same: nodes that answered join, and members
    /// of the parts closed leave as above.
    pub async fn close_leaf(
        &mut self,
        client: &Client,
        range: AddressRange,
    ) -> Result<CensusChange> {
        let mut rng = StdRng::from_entropy();
        let now = unix_now();
        self.close_with(&NetworkLookups(client.network()), range, now, &mut rng)
            .await
    }

    /// [`Self::refresh`] through `lookups`, at `now` (Unix seconds).
    pub(crate) async fn refresh_with<L: Lookups>(
        &mut self,
        lookups: &L,
        now: u64,
        rng: &mut StdRng,
    ) -> Result<CensusChange> {
        let closed = self.close_with(lookups, AddressRange::ALL, now, rng).await;
        self.set_refreshed_at(now);
        closed
    }

    /// [`Self::close_leaf`] through `lookups`, at `now` (Unix seconds).
    pub(crate) async fn close_with<L: Lookups>(
        &mut self,
        lookups: &L,
        range: AddressRange,
        now: u64,
        rng: &mut StdRng,
    ) -> Result<CensusChange> {
        let found = explore(lookups, range, None, rng).await;
        let mut agents = BTreeMap::new();
        for peer in found.answered.keys() {
            agents.insert(*peer, lookups.user_agent(peer).await);
        }
        let change = self.take_in(&found, &agents, now);
        debug!(
            "Census: closing {} took {} lookups: {} joined, {} left, {} named that didn't \
             answer, {} parts closed, {} not",
            range_text(&range),
            found.lookups,
            change.joined.len(),
            change.left.len(),
            change.unanswered.len(),
            found.closed.len(),
            found.failed.len()
        );
        self.requeue(&range, &found.failed);
        match found.error {
            None => Ok(change),
            Some(error) => Err(Error::Network(format!(
                "the census couldn't close {} of the {} parts of {} it looked up: {error}",
                found.failed.len(),
                found.lookups,
                range_text(&range)
            ))),
        }
    }

    /// Take in what closing found: nodes that answered join (or are brought
    /// up to date), unless their user agent says they aren't nodes; members
    /// in the closed parts that weren't found and were silent at their
    /// latest poll leave.
    fn take_in(
        &mut self,
        found: &Exploration,
        agents: &BTreeMap<PeerId, Option<String>>,
        now: u64,
    ) -> CensusChange {
        let mut change = CensusChange::default();
        for (peer, addresses) in &found.answered {
            let agent = agents.get(peer).cloned().flatten();
            if agent
                .as_deref()
                .is_some_and(|agent| node_version(agent).is_none())
            {
                continue;
            }
            if self.admit(*peer, addresses.clone(), now) {
                change.joined.push(*peer);
            }
            if let Some(agent) = agent {
                self.set_user_agent(peer, agent);
            }
        }
        let closed = Closed::new(&found.closed);
        let leaving: Vec<PeerId> = self
            .nodes
            .values()
            .filter(|node| {
                !found.answered.contains_key(&node.peer)
                    && !node.answered_latest_poll()
                    && closed.contains(node.peer.as_bytes())
            })
            .map(|node| node.peer)
            .collect();
        for peer in leaving {
            self.remove(&peer);
            change.left.push(peer);
        }
        change.unanswered = found
            .named
            .iter()
            .filter(|peer| !self.nodes.contains_key(peer) && closed.contains(peer.as_bytes()))
            .copied()
            .collect();
        change
    }

    /// Whether every leaf is due to be closed again: never refreshed, or
    /// last refreshed [`REFRESH_INTERVAL`] or more before `now` (Unix
    /// seconds).
    #[must_use]
    pub fn refresh_due(&self, now: u64) -> bool {
        self.refreshed_at
            .is_none_or(|at| now.saturating_sub(at) >= REFRESH_INTERVAL.as_secs())
    }

    /// When every leaf was last closed (Unix seconds), if ever.
    #[must_use]
    pub fn refreshed_at(&self) -> Option<u64> {
        self.refreshed_at
    }

    /// Note that every leaf was closed at `at` (Unix seconds).
    pub fn set_refreshed_at(&mut self, at: u64) {
        self.refreshed_at = Some(at);
        self.refreshed_dirty = true;
    }

    /// Take `peer` into the census, or update it: a node that has just
    /// answered (a responder of a witnessed lookup, or a request), at `at`
    /// (Unix seconds), reachable at `addresses` (kept as they were if
    /// empty). Returns whether it is new.
    pub fn admit(&mut self, peer: PeerId, addresses: Vec<MultiAddr>, at: u64) -> bool {
        self.dirty.insert(peer);
        self.removed.remove(&peer);
        match self.nodes.get_mut(&peer) {
            Some(node) => {
                if !addresses.is_empty() {
                    node.addresses = addresses;
                }
                false
            }
            None => {
                self.nodes.insert(
                    peer,
                    CensusNode {
                        peer,
                        addresses,
                        first_seen: at,
                        last_answered: None,
                        user_agent: None,
                        missed: 0,
                        view: None,
                    },
                );
                self.index = OnceLock::new();
                self.changes.absorb(CensusChange {
                    joined: vec![peer],
                    ..CensusChange::default()
                });
                true
            }
        }
    }

    /// Take `peer` out of the census. Returns whether it was in it.
    pub fn remove(&mut self, peer: &PeerId) -> bool {
        if self.nodes.remove(peer).is_none() {
            return false;
        }
        self.dirty.remove(peer);
        self.removed.insert(*peer);
        self.index = OnceLock::new();
        self.changes.absorb(CensusChange {
            left: vec![*peer],
            ..CensusChange::default()
        });
        true
    }

    /// Everything that changed in who is in the census since this was last
    /// called, by any of its calls, failed ones too: the producer starts
    /// reading the nodes that joined and stops reading those that left.
    /// After a restart it starts from [`Self::nodes`] instead.
    pub fn take_changes(&mut self) -> CensusChange {
        std::mem::take(&mut self.changes)
    }

    /// Note that `peer` answered a poll at `at` (Unix seconds), giving
    /// `user_agent` if known: its misses start again from none. Returns
    /// false, changing nothing, if `peer` isn't in the census.
    pub fn record_answer(&mut self, peer: &PeerId, at: u64, user_agent: Option<String>) -> bool {
        let Some(node) = self.nodes.get_mut(peer) else {
            return false;
        };
        node.last_answered = Some(at);
        node.missed = 0;
        if user_agent.is_some() {
            node.user_agent = user_agent;
        }
        self.dirty.insert(*peer);
        true
    }

    /// Note that `peer` missed a poll. Returns true when this is its
    /// [`MISSES_BEFORE_CLOSE`]th miss in a row: its leaf is then queued to be
    /// closed again ([`Self::maintain`]). False for a node not in the
    /// census.
    pub fn record_miss(&mut self, peer: &PeerId) -> bool {
        let Some(node) = self.nodes.get_mut(peer) else {
            return false;
        };
        node.missed = node.missed.saturating_add(1);
        let third = node.missed == MISSES_BEFORE_CLOSE;
        self.dirty.insert(*peer);
        if third {
            let leaf = self.leaf_of(peer.as_bytes());
            self.queue_close(leaf);
        }
        third
    }

    /// Note the view `peer` gave in an answer to a change feed's request (a
    /// hash of its nearest peers). Returns true when it differs from the one
    /// it gave before: ask it for the list of its nearest peers, and close
    /// again the leaves of any it names that the census lacks
    /// ([`Self::lacking`]). False the first time, and for a node not in the
    /// census.
    pub fn record_view(&mut self, peer: &PeerId, view: [u8; 32]) -> bool {
        let Some(node) = self.nodes.get_mut(peer) else {
            return false;
        };
        let before = node.view.replace(view);
        if before != Some(view) {
            self.dirty.insert(*peer);
        }
        before.is_some_and(|before| before != view)
    }

    /// Note the user agent `peer` gave, if it is in the census.
    fn set_user_agent(&mut self, peer: &PeerId, user_agent: String) {
        if let Some(node) = self.nodes.get_mut(peer) {
            if node.user_agent.as_deref() != Some(user_agent.as_str()) {
                node.user_agent = Some(user_agent);
                self.dirty.insert(*peer);
            }
        }
    }

    /// Write what changed since the last save, in one transaction: once a
    /// cycle.
    ///
    /// # Errors
    ///
    /// If the store can't be written; what changed is kept for the next
    /// save.
    pub fn save(&mut self) -> Result<()> {
        if self.dirty.is_empty()
            && self.removed.is_empty()
            && !self.refreshed_dirty
            && !self.queue_dirty
        {
            return Ok(());
        }
        let mut txn = self.store.env().write_txn().map_err(store_error)?;
        for peer in &self.dirty {
            if let Some(node) = self.nodes.get(peer) {
                self.nodes_db
                    .put(&mut txn, peer.as_bytes(), node)
                    .map_err(store_error)?;
            }
        }
        for peer in &self.removed {
            self.nodes_db
                .delete(&mut txn, peer.as_bytes())
                .map_err(store_error)?;
        }
        if self.queue_dirty {
            self.queue_db.clear(&mut txn).map_err(store_error)?;
            for range in &self.queue {
                self.queue_db
                    .put(&mut txn, &range_key(range), &())
                    .map_err(store_error)?;
            }
        }
        if let (true, Some(at)) = (self.refreshed_dirty, self.refreshed_at) {
            self.meta_db
                .put(&mut txn, REFRESHED_AT, &at)
                .map_err(store_error)?;
        }
        txn.commit().map_err(store_error)?;
        self.dirty.clear();
        self.removed.clear();
        self.refreshed_dirty = false;
        self.queue_dirty = false;
        Ok(())
    }

    /// How many nodes the census holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether it holds none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Every node, in id order.
    pub fn nodes(&self) -> impl Iterator<Item = &CensusNode> {
        self.nodes.values()
    }

    /// The node `peer`, if the census holds it.
    #[must_use]
    pub fn get(&self, peer: &PeerId) -> Option<&CensusNode> {
        self.nodes.get(peer)
    }

    /// The `n` nodes of the census nearest `address` by XOR distance,
    /// nearest first, whether or not they answer: all of them if there are
    /// fewer.
    #[must_use]
    pub fn nearest(&self, address: &XorName, n: usize) -> Vec<PeerId> {
        let index = self.index();
        // Every node in the leaf holding `address` is nearer it than every
        // node outside, so the leaf's nearest are the census's while the
        // leaf holds enough of them.
        if let Some(leaf) = leaf_index(&index.leaves, address).map(|at| &index.leaves[at]) {
            if n <= leaf.nodes.len() {
                let ids: Vec<[u8; 32]> = leaf.nodes.iter().map(|&at| index.ids[at]).collect();
                return nearest_by_distance(address, &ids, n)
                    .into_iter()
                    .map(|at| index.peers[leaf.nodes[at]])
                    .collect();
            }
        }
        nearest_by_distance(address, &index.ids, n)
            .into_iter()
            .map(|at| index.peers[at])
            .collect()
    }

    /// The leaf holding `address`: the range a node whose id is `address` is
    /// asked about, and in which the [`NEAREST_NODES`] nodes nearest it all
    /// are. The whole address space while the census can't be split.
    #[must_use]
    pub fn leaf_of(&self, address: &XorName) -> AddressRange {
        let index = self.index();
        leaf_index(&index.leaves, address).map_or(AddressRange::ALL, |at| index.leaves[at].range)
    }

    /// Every leaf, in address order.
    #[must_use]
    pub fn leaves(&self) -> Vec<AddressRange> {
        self.index().leaves.iter().map(|leaf| leaf.range).collect()
    }

    /// The nodes whose ids are in `range`, in id order.
    #[must_use]
    pub fn members(&self, range: &AddressRange) -> Vec<PeerId> {
        let index = self.index();
        index.peers[index.span(range)].to_vec()
    }

    /// The leaves to close again because `peers`, a node's nearest peers as
    /// its latest view lists them, name nodes the census lacks: the leaf of
    /// each such id, once each, in address order. Empty when the census
    /// holds every one of them.
    #[must_use]
    pub fn lacking(&self, peers: &[[u8; 32]]) -> Vec<AddressRange> {
        peers
            .iter()
            .filter(|id| !self.nodes.contains_key(&PeerId::from_bytes(**id)))
            .map(|id| self.leaf_of(id))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Whether `peer`'s user agent shows a release that keeps a change feed
    /// ([`supports_feed`]). False for a node not in the census, or whose
    /// user agent isn't known.
    #[must_use]
    pub fn supports_feed(&self, peer: &PeerId) -> bool {
        self.nodes
            .get(peer)
            .and_then(|node| node.user_agent.as_deref())
            .is_some_and(supports_feed)
    }

    /// Whether a cycle in which `answered` census nodes answered may decide
    /// and drop listings: at least [`NEAREST_NODES`] of them, and at
    /// least three quarters of the census.
    #[must_use]
    pub fn guard_ok(&self, answered: usize) -> bool {
        answered >= NEAREST_NODES
            && answered.saturating_mul(4) >= self.nodes.len().saturating_mul(3)
    }

    /// The census as `status.json` gives it, for a cycle that started at
    /// `cycle_started_at` (Unix seconds): a node answered in the cycle when
    /// its last answer is from then or later. Versions are the first word of
    /// each node's user agent ([`node_version`]), most common first; nodes
    /// whose user agent isn't known count under no version, last.
    #[must_use]
    pub fn status(&self, cycle_started_at: u64) -> CensusStatus {
        let mut versions: BTreeMap<Option<&str>, u64> = BTreeMap::new();
        let mut silent = Vec::new();
        let mut answering = 0u64;
        for node in self.nodes.values() {
            let version = node.user_agent.as_deref().and_then(node_version);
            *versions.entry(version).or_default() += 1;
            if node.last_answered.is_some_and(|at| at >= cycle_started_at) {
                answering += 1;
            } else {
                silent.push(SilentNode {
                    node: hex::encode(node.peer.as_bytes()),
                    last_answered: node.last_answered,
                });
            }
        }
        let mut versions: Vec<VersionCount> = versions
            .into_iter()
            .map(|(version, nodes)| VersionCount {
                version: version.map(str::to_owned),
                nodes,
            })
            .collect();
        versions.sort_by(|a, b| {
            a.version
                .is_none()
                .cmp(&b.version.is_none())
                .then(b.nodes.cmp(&a.nodes))
                .then_with(|| a.version.cmp(&b.version))
        });
        CensusStatus {
            nodes: self.nodes.len() as u64,
            answering,
            leaves: self.index().leaves.len() as u64,
            versions,
            silent,
        }
    }

    fn index(&self) -> &Index {
        self.index.get_or_init(|| Index::new(&self.nodes))
    }
}

/// The version a node's user agent gives: its first word, such as
/// `node/0.23.0+ds.15`. `None` for a user agent that isn't a node's: one
/// that doesn't start with `node/`, as clients' don't. Read as a node reads
/// its peers' user agents when it tallies their versions.
#[must_use]
pub fn node_version(user_agent: &str) -> Option<&str> {
    if !user_agent.starts_with(NODE_AGENT) {
        return None;
    }
    user_agent.split_whitespace().next()
}

/// Whether `user_agent` is a node's of a release that keeps a change feed:
/// its version ([`node_version`]) is `node/<version>+ds.<n>` with `n` at
/// least [`FEED_RELEASE`], whatever the version before it.
#[must_use]
pub fn supports_feed(user_agent: &str) -> bool {
    node_version(user_agent)
        .and_then(|version| version.strip_prefix(NODE_AGENT))
        .and_then(|version| semver::Version::parse(version).ok())
        .and_then(|version| {
            version
                .build
                .as_str()
                .strip_prefix("ds.")
                .and_then(|release| release.split('.').next())
                .and_then(|release| release.parse::<u64>().ok())
        })
        .is_some_and(|release| release >= FEED_RELEASE)
}

/// The user agent `peer` gave when it connected, read as a node reads its
/// peers' when it tallies their versions: the transport keeps a peer's user
/// agent only while the peer is connected, so if there is none but the peer
/// is connected (it came back between the two reads), it is read again.
/// `None` when the peer isn't connected, or never gave one.
pub async fn user_agent_of(network: &Network, peer: &PeerId) -> Option<String> {
    if let Some(agent) = network.peer_user_agent(peer).await {
        return Some(agent);
    }
    if !network.is_peer_connected(peer).await {
        return None;
    }
    network.peer_user_agent(peer).await
}

/// What one witnessed lookup gave.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Sighting {
    /// The nodes that answered it, nearest its target first, with the
    /// addresses the lookup gave for them.
    pub(crate) answered: Vec<(PeerId, Vec<MultiAddr>)>,
    /// Every other id the views of those nodes named.
    pub(crate) named: Vec<PeerId>,
}

impl Sighting {
    /// What `group` gives: its nearest responders, and the other ids their
    /// views name.
    pub(crate) fn of(group: &WitnessedCloseGroup) -> Self {
        let answered: Vec<(PeerId, Vec<MultiAddr>)> = group
            .initial_closest
            .iter()
            .map(|node| (node.peer_id, node.addresses_by_priority()))
            .collect();
        let answering: BTreeSet<PeerId> = answered.iter().map(|(peer, _)| *peer).collect();
        let named: BTreeSet<PeerId> = group
            .responder_views
            .iter()
            .flat_map(|view| view.closest.iter().map(|node| node.peer_id))
            .filter(|peer| !answering.contains(peer))
            .collect();
        Self {
            answered,
            named: named.into_iter().collect(),
        }
    }
}

/// The lookups closing needs: the network's, or in tests a synthetic one.
pub(crate) trait Lookups {
    /// A witnessed lookup of `target`: the `count` nodes nearest it that
    /// answered, and what their views of `view_count` nodes named. An error
    /// when fewer than `count` answered.
    async fn witnessed(
        &self,
        target: &XorName,
        count: usize,
        view_count: usize,
    ) -> Result<Sighting>;

    /// The user agent `peer` gave ([`user_agent_of`]).
    async fn user_agent(&self, peer: &PeerId) -> Option<String>;
}

/// The `GetRequest`s a drop needs: the network's, or in tests a synthetic
/// one.
pub(crate) trait Gets {
    /// Unix seconds now.
    fn now(&self) -> u64;

    /// Ask each of `peers` for its listing of `address`, at any key.
    async fn get(&self, address: &XorName, peers: &[PeerId]) -> Vec<(PeerId, Served)>;
}

/// The network's `GetRequest`s, sent as an index read's lookup of one
/// address sends them, with answers routed as it routes them.
struct NetworkGets<'a>(&'a Client);

impl Gets for NetworkGets<'_> {
    fn now(&self) -> u64 {
        unix_now()
    }

    async fn get(&self, address: &XorName, peers: &[PeerId]) -> Vec<(PeerId, Served)> {
        let requests = ListingsRequests::start(self.0.network().node(), None);
        self.0
            .ask_for_listing(&requests, address, peers)
            .await
            .into_iter()
            .map(|(peer, answer)| {
                let served = match answer {
                    None => Served::Silent,
                    Some(None) => Served::Nothing,
                    Some(Some(_)) => Served::Listing,
                };
                (peer, served)
            })
            .collect()
    }
}

/// The network's lookups.
struct NetworkLookups<'a>(&'a Network);

impl Lookups for NetworkLookups<'_> {
    async fn witnessed(
        &self,
        target: &XorName,
        count: usize,
        view_count: usize,
    ) -> Result<Sighting> {
        // Boxed, as other lookups are: the transport's future is large.
        let lookup: futures::future::BoxFuture<'_, _> = Box::pin(
            self.0
                .find_witnessed_close_group_with_view_count(target, count, view_count),
        );
        Ok(Sighting::of(&lookup.await?))
    }

    async fn user_agent(&self, peer: &PeerId) -> Option<String> {
        user_agent_of(self.0, peer).await
    }
}

/// What closing a range found.
#[derive(Debug, Default)]
struct Exploration {
    /// Every node that answered a lookup, with the addresses it was given
    /// with.
    answered: BTreeMap<PeerId, Vec<MultiAddr>>,
    /// The other ids the views of nodes that answered named.
    named: BTreeSet<PeerId>,
    /// The parts of the range closed: every node in them that answers was
    /// found. They don't overlap.
    closed: Vec<AddressRange>,
    /// The parts whose lookups failed.
    failed: Vec<AddressRange>,
    /// The latest failure.
    error: Option<String>,
    /// How many lookups closing made, failed ones too.
    lookups: usize,
    /// What the lookup of the first target given gave, if one was given.
    first: Option<std::result::Result<Sighting, String>>,
}

/// Close `range` (see the module docs): look up `first` (an address in
/// `range`) if given, else a random address in it, and then a random
/// address in each part still open, [`CLOSE_CONCURRENCY`] at a time, until
/// every part is closed or its lookup failed.
async fn explore<L: Lookups>(
    lookups: &L,
    range: AddressRange,
    first: Option<XorName>,
    rng: &mut StdRng,
) -> Exploration {
    let mut found = Exploration::default();
    let mut open = vec![(range, first.filter(|first| range.contains(first)))];
    let mut running = FuturesUnordered::new();
    loop {
        while running.len() < CLOSE_CONCURRENCY {
            let Some((part, given)) = open.pop() else {
                break;
            };
            let target = given.unwrap_or_else(|| address_in(&part, rng));
            running.push(async move {
                let sighting = lookup_to_close(lookups, &target).await;
                (part, target, given.is_some(), sighting)
            });
        }
        let Some((part, target, is_first, sighting)) = running.next().await else {
            break;
        };
        found.lookups += 1;
        if is_first {
            found.first = Some(match &sighting {
                Ok(sighting) => Ok(sighting.clone()),
                Err(e) => Err(e.to_string()),
            });
        }
        let sighting = match sighting {
            Ok(sighting) => sighting,
            Err(e) => {
                found.failed.push(part);
                found.error = Some(e.to_string());
                continue;
            }
        };
        match closed_by(&part, &target, &sighting) {
            Some(Split { closed, rest }) => {
                found.closed.push(closed);
                open.extend(rest.into_iter().map(|rest| (rest, None)));
            }
            None => {
                found.failed.push(part);
                found.error = Some(format!(
                    "a lookup of {} gave nodes that can't close any part of {}",
                    hex::encode(target),
                    range_text(&part)
                ));
            }
        }
        for (peer, addresses) in sighting.answered {
            let known = found.answered.entry(peer).or_default();
            if known.is_empty() {
                *known = addresses;
            }
        }
        found.named.extend(sighting.named);
    }
    let answered = &found.answered;
    found.named.retain(|peer| !answered.contains_key(peer));
    found
}

/// A witnessed lookup of `target` for closing: [`LOOKUP_NODES`] wide, or
/// [`NEAREST_NODES`] wide where that fails (as it does where the network has
/// too few nodes), each node naming [`VIEW_PEERS`] in its view.
async fn lookup_to_close<L: Lookups>(lookups: &L, target: &XorName) -> Result<Sighting> {
    let wide = match lookups.witnessed(target, LOOKUP_NODES, VIEW_PEERS).await {
        Ok(sighting) => enough(sighting, LOOKUP_NODES),
        Err(e) => Err(e),
    };
    match wide {
        Ok(sighting) => Ok(sighting),
        Err(e) => {
            debug!(
                "Census: a lookup of {} for {LOOKUP_NODES} nodes failed ({e}); asking for \
                 {NEAREST_NODES}",
                hex::encode(target)
            );
            let sighting = lookups.witnessed(target, NEAREST_NODES, VIEW_PEERS).await?;
            enough(sighting, NEAREST_NODES)
        }
    }
}

/// `sighting`, if at least `count` different nodes answered it.
fn enough(sighting: Sighting, count: usize) -> Result<Sighting> {
    let answered: BTreeSet<&PeerId> = sighting.answered.iter().map(|(peer, _)| peer).collect();
    if answered.len() < count {
        return Err(Error::InsufficientPeers(format!(
            "{} nodes answered a lookup, not {count}",
            answered.len()
        )));
    }
    Ok(sighting)
}

/// What a lookup closes of a part of the address space.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Split {
    /// The part closed: all of the part looked up, or the part of it around
    /// the lookup's target.
    closed: AddressRange,
    /// What is left of the part looked up, to be closed by lookups of their
    /// own: the halves the target isn't in, from each level below the part's
    /// down to the part closed.
    rest: Vec<AddressRange>,
}

/// What a lookup of `target`, an address in `part`, that `sighting` gives
/// closes of `part`. Every node that shares more leading bits with the
/// target than the farthest node that answered does is nearer the target
/// than that node, so every such node that answers is among those that did.
/// `None` when no node answered, or those that did are all so near the
/// target that they close next to nothing.
fn closed_by(part: &AddressRange, target: &XorName, sighting: &Sighting) -> Option<Split> {
    let farthest = sighting
        .answered
        .iter()
        .map(|(peer, _)| peer.as_bytes())
        .max_by_key(|id| distance(id, target))?;
    let shared = shared_bits(target, farthest);
    if shared < u32::from(part.bits()) {
        // The farthest is outside the part: every node in it that answers
        // was found.
        return Some(Split {
            closed: *part,
            rest: Vec::new(),
        });
    }
    // The part closed fixes one bit more than the target shares with the
    // farthest; a range fixes at most 255 bits.
    let bits = u8::try_from(shared + 1).ok()?;
    let rest = (part.bits() + 1..=bits)
        .map(|level| AddressRange::new(flip_bit(target, level - 1), level))
        .collect();
    Some(Split {
        closed: AddressRange::new(*target, bits),
        rest,
    })
}

/// The closed parts of a range, to tell quickly whether an id is in one.
struct Closed(Vec<AddressRange>);

impl Closed {
    fn new(parts: &[AddressRange]) -> Self {
        let mut parts = parts.to_vec();
        parts.sort_unstable_by_key(AddressRange::first);
        Self(parts)
    }

    /// Whether `id` is in a closed part. The parts don't overlap, so the
    /// only one that can hold it is the last that starts at or before it.
    fn contains(&self, id: &[u8; 32]) -> bool {
        let after = self.0.partition_point(|part| part.first() <= *id);
        after
            .checked_sub(1)
            .is_some_and(|at| self.0[at].contains(id))
    }
}

/// A random address in `range`.
fn address_in(range: &AddressRange, rng: &mut StdRng) -> XorName {
    let mut address: XorName = rng.gen();
    let prefix = range.prefix();
    let mut bits = usize::from(range.bits());
    for (byte, fixed) in address.iter_mut().zip(prefix) {
        let mask = match bits.min(8) {
            0 => 0,
            taken => 0xffu8 << (8 - taken),
        };
        *byte = (*byte & !mask) | (fixed & mask);
        bits = bits.saturating_sub(8);
    }
    address
}

/// `range` as a key of [`QUEUE_DB`]: its prefix's 32 bytes, then how many
/// bits it fixes.
fn range_key(range: &AddressRange) -> [u8; 33] {
    let mut key = [0u8; 33];
    key[..32].copy_from_slice(&range.prefix());
    key[32] = range.bits();
    key
}

/// The range a key of [`QUEUE_DB`] gives ([`range_key`]): `None` if it isn't
/// one.
fn range_from_key(key: &[u8]) -> Option<AddressRange> {
    let key: &[u8; 33] = key.try_into().ok()?;
    let mut prefix: XorName = [0; 32];
    prefix.copy_from_slice(&key[..32]);
    Some(AddressRange::new(prefix, key[32]))
}

/// `range` as text: the hex digits of the bytes its prefix fixes, and how
/// many bits it fixes, such as `a0/3`; `/0` for the whole address space.
fn range_text(range: &AddressRange) -> String {
    let bytes = usize::from(range.bits()).div_ceil(8);
    format!("{}/{}", hex::encode(&range.prefix()[..bytes]), range.bits())
}

/// The XOR distance between `a` and `b`, as a big-endian number.
fn distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut distance = [0u8; 32];
    for (out, (x, y)) in distance.iter_mut().zip(a.iter().zip(b)) {
        *out = x ^ y;
    }
    distance
}

/// How many leading bits `a` and `b` share: 256 when they are equal.
fn shared_bits(a: &[u8; 32], b: &[u8; 32]) -> u32 {
    for (at, (x, y)) in a.iter().zip(b).enumerate() {
        let differ = x ^ y;
        if differ != 0 {
            // At most 31 * 8 + 7.
            return u32::try_from(at).unwrap_or(31) * 8 + differ.leading_zeros();
        }
    }
    256
}

/// `address` with bit `bit` (counted from the first, 0 to 255) flipped.
fn flip_bit(address: &XorName, bit: u8) -> XorName {
    let mut flipped = *address;
    flipped[usize::from(bit / 8)] ^= 0x80 >> (bit % 8);
    flipped
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TEST_MAP: usize = 16 * 1024 * 1024;

    /// The DHT's bucket size, and how many nodes a node names in an answer.
    const K: usize = 20;

    /// How many nodes a synthetic lookup asks at once, as the DHT's do.
    const ALPHA: usize = 3;

    fn peer(byte: u8) -> PeerId {
        PeerId::from_bytes([byte; 32])
    }

    fn census(dir: &std::path::Path) -> Census {
        let store = ListingsStore::open_with_map_size(dir, TEST_MAP).unwrap();
        Census::open(&store).unwrap()
    }

    fn rng(seed: u64) -> StdRng {
        StdRng::seed_from_u64(seed)
    }

    /// Runs `future` to its end; synthetic lookups never wait.
    fn run<F: std::future::Future>(future: F) -> F::Output {
        futures::executor::block_on(future)
    }

    /// How a synthetic node answers.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Behaviour {
        /// As it should.
        Honest,
        /// It leaves out the nearer half of the nodes it would name.
        LeavesOut,
        /// It names made-up ids nearer the target than any node, in place of
        /// the nearer half of the nodes it would name.
        SlipsIn,
    }

    #[derive(Debug, Clone)]
    struct SimNode {
        alive: bool,
        table: Vec<[u8; 32]>,
        behaviour: Behaviour,
        agent: Option<String>,
    }

    /// A synthetic network: nodes with routing tables as a settled Kademlia
    /// network's (every node of each of a node's buckets, or twenty of them
    /// at random where there are more), some of which lie, and nodes gone
    /// that others' tables still name; and the iterative lookups a client
    /// makes through it, as the DHT's: ask the three nearest the target not
    /// yet asked, take in what they name, and stop when no node named is
    /// nearer than the farthest of the `count` nearest that answered.
    struct Sim {
        nodes: BTreeMap<[u8; 32], SimNode>,
        client: Vec<[u8; 32]>,
        lookups: AtomicUsize,
    }

    /// 32 bytes spread from `seed` (splitmix64).
    fn id(seed: u64) -> [u8; 32] {
        let mut state = seed;
        let mut bytes = [0u8; 32];
        for chunk in bytes.chunks_mut(8) {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            chunk.copy_from_slice(&(z ^ (z >> 31)).to_be_bytes());
        }
        bytes
    }

    /// The `count` of `ids` nearest `target`, nearest first.
    fn nearest_of(
        ids: impl IntoIterator<Item = [u8; 32]>,
        target: &[u8; 32],
        count: usize,
    ) -> Vec<[u8; 32]> {
        let mut ids: Vec<[u8; 32]> = ids.into_iter().collect();
        ids.sort_unstable_by_key(|id| distance(id, target));
        ids.dedup();
        ids.truncate(count);
        ids
    }

    /// A routing table for `own` over the sorted `ids`: each bucket (the ids
    /// sharing exactly so many leading bits with `own`) whole, or twenty of
    /// its ids at random.
    fn table(own: &[u8; 32], ids: &[[u8; 32]], rng: &mut StdRng) -> Vec<[u8; 32]> {
        let span = |range: &AddressRange| {
            ids.partition_point(|id| *id < range.first())
                ..ids.partition_point(|id| *id <= range.last())
        };
        let mut table = Vec::new();
        for bit in 0..=254u8 {
            let bucket = &ids[span(&AddressRange::new(flip_bit(own, bit), bit + 1))];
            if bucket.len() <= K {
                table.extend_from_slice(bucket);
            } else {
                table.extend(
                    rand::seq::index::sample(rng, bucket.len(), K)
                        .into_iter()
                        .map(|at| bucket[at]),
                );
            }
            // Nothing else shares more bits with `own`.
            if span(&AddressRange::new(*own, bit + 1))
                .filter(|&at| ids[at] != *own)
                .count()
                == 0
            {
                break;
            }
        }
        table
    }

    impl Sim {
        /// `live` nodes answering (every tenth leaving ids out, and every
        /// tenth after those slipping made-up ones in), and `gone` nodes that
        /// left but that tables still name.
        fn new(live: usize, gone: usize, seed: u64) -> Self {
            let mut rng = rng(seed);
            let count = live + gone;
            let all: Vec<[u8; 32]> = (0..count as u64)
                .map(|n| id(seed * 1_000_003 + n))
                .collect();
            let mut sorted = all.clone();
            sorted.sort_unstable();
            let mut nodes = BTreeMap::new();
            for (n, own) in all.iter().enumerate() {
                let behaviour = match n % 10 {
                    _ if n >= live => Behaviour::Honest,
                    3 => Behaviour::LeavesOut,
                    7 => Behaviour::SlipsIn,
                    _ => Behaviour::Honest,
                };
                nodes.insert(
                    *own,
                    SimNode {
                        alive: n < live,
                        table: table(own, &sorted, &mut rng),
                        behaviour,
                        agent: Some(if n % 4 == 0 {
                            "node/0.23.0+ds.13".to_owned()
                        } else {
                            "node/0.23.0+ds.15".to_owned()
                        }),
                    },
                );
            }
            let client = table(&id(seed ^ 0x00c1_1e47), &sorted, &mut rng);
            Self {
                nodes,
                client,
                lookups: AtomicUsize::new(0),
            }
        }

        fn live(&self) -> BTreeSet<PeerId> {
            self.nodes
                .iter()
                .filter(|(_, node)| node.alive)
                .map(|(id, _)| PeerId::from_bytes(*id))
                .collect()
        }

        /// The made-up ids `node` names for `target`: nearer it than any node.
        fn made_up(node: &[u8; 32], target: &[u8; 32], count: usize) -> Vec<[u8; 32]> {
            (0..count)
                .map(|n| {
                    let mut fake = *target;
                    let noise =
                        blake3::hash(&[&node[..], &target[..], &n.to_be_bytes()[..]].concat());
                    fake[24..].copy_from_slice(&noise.as_bytes()[..8]);
                    fake
                })
                .collect()
        }

        /// What `node` names for `target` from `known`, as it behaves.
        fn names(
            node: &[u8; 32],
            behaviour: Behaviour,
            known: Vec<[u8; 32]>,
            target: &[u8; 32],
            count: usize,
        ) -> Vec<[u8; 32]> {
            let near = nearest_of(known, target, count);
            match behaviour {
                Behaviour::Honest => near,
                Behaviour::LeavesOut => near[count.min(near.len()) / 2..].to_vec(),
                Behaviour::SlipsIn => {
                    let mut named = near[count.min(near.len()) / 2..].to_vec();
                    named.extend(Self::made_up(node, target, count / 2));
                    named
                }
            }
        }

        /// A node's answer to a lookup of `target`: the nodes it knows
        /// nearest it.
        fn answer(&self, node: &[u8; 32], target: &[u8; 32]) -> Vec<[u8; 32]> {
            let sim = &self.nodes[node];
            Self::names(node, sim.behaviour, sim.table.clone(), target, K)
        }

        /// A node's view for a witnessed lookup: itself and the nodes it
        /// knows, nearest the target.
        fn view(&self, node: &[u8; 32], target: &[u8; 32], count: usize) -> Vec<[u8; 32]> {
            let sim = &self.nodes[node];
            let mut known = sim.table.clone();
            known.push(*node);
            Self::names(node, sim.behaviour, known, target, count)
        }

        /// A node's nearest peers, as its view in a change feed's answer
        /// lists them.
        fn peers_of(&self, node: &[u8; 32]) -> Vec<[u8; 32]> {
            self.view(node, node, VIEW_PEERS)
                .into_iter()
                .filter(|id| id != node)
                .collect()
        }

        /// A node joins: the nodes nearest it learn of it.
        fn join(&mut self, own: [u8; 32], rng: &mut StdRng) {
            let mut sorted: Vec<[u8; 32]> = self.nodes.keys().copied().collect();
            sorted.push(own);
            sorted.sort_unstable();
            let neighbours = nearest_of(
                self.nodes
                    .iter()
                    .filter(|(_, n)| n.alive)
                    .map(|(id, _)| *id),
                &own,
                K,
            );
            for neighbour in neighbours {
                self.nodes.get_mut(&neighbour).unwrap().table.push(own);
            }
            self.nodes.insert(
                own,
                SimNode {
                    alive: true,
                    table: table(&own, &sorted, rng),
                    behaviour: Behaviour::Honest,
                    agent: Some("node/0.23.0+ds.15".to_owned()),
                },
            );
        }
    }

    impl Lookups for Sim {
        async fn witnessed(
            &self,
            target: &XorName,
            count: usize,
            view_count: usize,
        ) -> Result<Sighting> {
            self.lookups.fetch_add(1, Ordering::Relaxed);
            let mut candidates: BTreeMap<[u8; 32], [u8; 32]> =
                nearest_of(self.client.clone(), target, K)
                    .into_iter()
                    .map(|id| (distance(&id, target), id))
                    .collect();
            let mut asked: HashSet<[u8; 32]> = HashSet::new();
            let mut answered: BTreeMap<[u8; 32], [u8; 32]> = BTreeMap::new();
            loop {
                let bound = answered.keys().nth(count - 1).copied();
                let batch: Vec<([u8; 32], [u8; 32])> = candidates
                    .iter()
                    .filter(|(far, _)| bound.is_none_or(|bound| **far < bound))
                    .take(ALPHA)
                    .map(|(far, id)| (*far, *id))
                    .collect();
                if batch.is_empty() {
                    break;
                }
                for (far, node) in batch {
                    candidates.remove(&far);
                    asked.insert(node);
                    if !self.nodes.get(&node).is_some_and(|sim| sim.alive) {
                        continue;
                    }
                    answered.insert(far, node);
                    for named in self.answer(&node, target) {
                        if !asked.contains(&named) {
                            candidates.insert(distance(&named, target), named);
                        }
                    }
                }
            }
            let nearest: Vec<[u8; 32]> = answered.values().take(count).copied().collect();
            if nearest.len() < count {
                return Err(Error::InsufficientPeers(format!(
                    "{} answered, need {count}",
                    nearest.len()
                )));
            }
            let named: BTreeSet<[u8; 32]> = nearest
                .iter()
                .flat_map(|node| self.view(node, target, view_count))
                .filter(|id| !nearest.contains(id))
                .collect();
            Ok(Sighting {
                answered: nearest
                    .into_iter()
                    .map(|id| (PeerId::from_bytes(id), Vec::new()))
                    .collect(),
                named: named.into_iter().map(PeerId::from_bytes).collect(),
            })
        }

        async fn user_agent(&self, peer: &PeerId) -> Option<String> {
            self.nodes
                .get(peer.as_bytes())
                .and_then(|node| node.agent.clone())
        }
    }

    fn ids(census: &Census) -> BTreeSet<PeerId> {
        census.nodes().map(|node| node.peer).collect()
    }

    /// Every address's nearest known nodes lie in its leaf, and are the
    /// nearest nodes that answer: checked at random addresses, at each node's
    /// id and its neighbours, at each leaf's ends, and at the made-up ids.
    fn assert_nearest_in_leaves(
        census: &Census,
        live: &BTreeSet<PeerId>,
        extra: &[[u8; 32]],
        seed: u64,
    ) {
        let live_ids: Vec<[u8; 32]> = live.iter().map(|peer| *peer.as_bytes()).collect();
        let leaves = census.leaves();
        for leaf in &leaves {
            assert!(
                census.members(leaf).len() >= NEAREST_NODES.min(census.len()),
                "{leaf:?} holds {} nodes",
                census.members(leaf).len()
            );
        }
        let mut addresses: Vec<[u8; 32]> = (0..500).map(|n| id(seed * 7_919 + n)).collect();
        for leaf in &leaves {
            addresses.push(leaf.first());
            addresses.push(leaf.last());
        }
        for node in live_ids.iter().step_by(3) {
            addresses.push(*node);
            let mut next = *node;
            next[31] ^= 1;
            addresses.push(next);
        }
        addresses.extend_from_slice(extra);
        for address in &addresses {
            let leaf = census.leaf_of(address);
            assert!(leaf.contains(address));
            let nearest = census.nearest(address, NEAREST_NODES);
            let expected: Vec<PeerId> = nearest_by_distance(address, &live_ids, NEAREST_NODES)
                .into_iter()
                .map(|at| PeerId::from_bytes(live_ids[at]))
                .collect();
            assert_eq!(nearest, expected, "at {}", hex::encode(address));
            for node in &nearest {
                assert!(leaf.contains(node.as_bytes()), "{node} isn't in {leaf:?}");
            }
        }
    }

    /// The census simulation: closing every leaf of a network of `live`
    /// nodes, with liars and nodes gone, finds every node that answers and
    /// no other, and every address's nearest known nodes lie in its leaf.
    /// Then nodes leave and join, and closing the leaves the plan says to
    /// close again keeps it so.
    fn simulate(live: usize, seed: u64) {
        let dir = tempfile::tempdir().unwrap();
        let store = ListingsStore::open_with_map_size(dir.path(), 256 * 1024 * 1024).unwrap();
        let mut census = Census::open(&store).unwrap();
        let mut sim = Sim::new(live, live / 20, seed);
        let mut rng = rng(seed);
        let fakes: Vec<[u8; 32]> = sim
            .nodes
            .iter()
            .filter(|(_, node)| node.behaviour == Behaviour::SlipsIn)
            .take(5)
            .flat_map(|(node, _)| Sim::made_up(node, node, 3))
            .collect();

        let change = run(census.refresh_with(&sim, 1_000, &mut rng)).unwrap();
        let live_set = sim.live();
        assert_eq!(
            ids(&census),
            live_set,
            "the census is every node that answers"
        );
        assert_eq!(change.joined.len(), live);
        assert!(change.left.is_empty());
        assert!(
            !change.unanswered.is_empty(),
            "the made-up and gone ids views named are reported"
        );
        for peer in &change.unanswered {
            assert!(!live_set.contains(peer));
        }
        assert_eq!(census.refreshed_at(), Some(1_000));
        assert!(!census.refresh_due(1_000 + REFRESH_INTERVAL.as_secs() - 1));
        let feeding = census
            .nodes()
            .filter(|node| census.supports_feed(&node.peer))
            .count();
        assert_eq!(feeding, live - live.div_ceil(4), "user agents are taken in");
        assert_nearest_in_leaves(&census, &live_set, &fakes, seed);
        let lookups = sim.lookups.load(Ordering::Relaxed);
        assert!(lookups < live, "{lookups} lookups closed {live} nodes");
        census.save().unwrap();

        // Every member answers its polls but a few, which then leave the
        // network; new nodes join it.
        let leaving: Vec<PeerId> = live_set.iter().step_by(37).copied().collect();
        for peer in &leaving {
            sim.nodes.get_mut(peer.as_bytes()).unwrap().alive = false;
        }
        let joining: Vec<[u8; 32]> = (0..live as u64 / 40 + 1)
            .map(|n| id(seed * 31 + 5_000_000 + n))
            .collect();
        for own in &joining {
            sim.join(*own, &mut rng);
        }
        let members: Vec<PeerId> = ids(&census).into_iter().collect();
        let mut to_close = BTreeSet::new();
        for round in 0..MISSES_BEFORE_CLOSE {
            for member in &members {
                if leaving.contains(member) {
                    if census.record_miss(member) {
                        assert_eq!(round + 1, MISSES_BEFORE_CLOSE);
                        to_close.insert(census.leaf_of(member.as_bytes()));
                    }
                } else {
                    census.record_answer(member, 2_000 + u64::from(round), None);
                }
            }
        }
        assert!(!to_close.is_empty());
        // The neighbours of new nodes list them in their nearest peers; a
        // node that slips made-up ids in lists those.
        for own in &joining {
            let honest = sim
                .nodes
                .iter()
                .filter(|(id, node)| {
                    node.alive && node.behaviour == Behaviour::Honest && *id != own
                })
                .map(|(id, _)| *id);
            let peers = nearest_of(honest, own, K)
                .into_iter()
                .map(|neighbour| sim.peers_of(&neighbour))
                .find(|peers| peers.contains(own))
                .expect("a neighbour lists the new node");
            let leaves = census.lacking(&peers);
            assert!(
                leaves.contains(&census.leaf_of(own)),
                "a new node's leaf is closed"
            );
            to_close.extend(leaves);
        }
        let liar = *sim
            .nodes
            .iter()
            .find(|(_, node)| node.alive && node.behaviour == Behaviour::SlipsIn)
            .unwrap()
            .0;
        let liar_peers = sim.peers_of(&liar);
        assert!(
            !census.lacking(&liar_peers).is_empty(),
            "made-up ids are lacking"
        );
        to_close.extend(census.lacking(&liar_peers));

        let mut left = BTreeSet::new();
        let mut joined = BTreeSet::new();
        for leaf in to_close {
            // A leaf closed earlier in this loop may have split.
            for part in census
                .leaves()
                .into_iter()
                .filter(|part| leaf.covers(part) || part.covers(&leaf))
            {
                let change = run(census.close_with(&sim, part, 3_000, &mut rng)).unwrap();
                left.extend(change.left);
                joined.extend(change.joined);
            }
        }
        let live_set = sim.live();
        assert_eq!(left, leaving.iter().copied().collect::<BTreeSet<_>>());
        for own in &joining {
            assert!(joined.contains(&PeerId::from_bytes(*own)), "new nodes join");
        }
        assert_eq!(ids(&census), live_set);
        for fake in liar_peers.iter().chain(&fakes) {
            assert!(
                census.get(&PeerId::from_bytes(*fake)).is_none()
                    || live_set.contains(&PeerId::from_bytes(*fake))
            );
        }
        let mut extra = fakes.clone();
        extra.extend(joining.iter().copied());
        assert_nearest_in_leaves(&census, &live_set, &extra, seed + 1);

        // What changed is kept.
        census.save().unwrap();
        drop(census);
        let reopened = Census::open(&store).unwrap();
        assert_eq!(ids(&reopened), live_set);
        assert_eq!(reopened.refreshed_at(), Some(1_000));
    }

    #[test]
    fn census_simulation_of_a_thousand_nodes() {
        simulate(1_000, 1);
    }

    #[test]
    #[ignore = "ten thousand nodes: slow in a debug build"]
    fn census_simulation_of_ten_thousand_nodes() {
        simulate(10_000, 2);
    }

    #[test]
    fn a_small_network_is_closed_with_narrower_lookups() {
        // Fifteen nodes: a lookup for twenty fails, one for seven doesn't.
        for (live, seed) in [(7, 3), (15, 4), (21, 5)] {
            let dir = tempfile::tempdir().unwrap();
            let mut census = census(dir.path());
            let sim = Sim::new(live, 1, seed);
            let mut rng = rng(seed);
            run(census.refresh_with(&sim, 10, &mut rng)).unwrap();
            assert_eq!(ids(&census), sim.live(), "{live} nodes");
            if live < 2 * NEAREST_NODES {
                assert_eq!(census.leaves(), vec![AddressRange::ALL]);
            }
            assert_nearest_in_leaves(&census, &sim.live(), &[], seed);
        }
        // Six: no lookup can close anything. The whole space is queued for
        // the next upkeep, not refreshed again every cycle.
        let dir = tempfile::tempdir().unwrap();
        let mut census = census(dir.path());
        let sim = Sim::new(6, 0, 6);
        let error = run(census.refresh_with(&sim, 10, &mut rng(6))).unwrap_err();
        assert!(matches!(error, Error::Network(_)), "{error}");
        assert_eq!(census.refreshed_at(), Some(10));
        assert!(!census.refresh_due(11));
        assert_eq!(census.queued(), vec![AddressRange::ALL]);
    }

    /// Lookups that fail for targets in one half of the address space.
    struct HalfDown<'a>(&'a Sim);

    impl Lookups for HalfDown<'_> {
        async fn witnessed(
            &self,
            target: &XorName,
            count: usize,
            view_count: usize,
        ) -> Result<Sighting> {
            if target[0] >= 0x80 {
                return Err(Error::Network("unreachable".to_owned()));
            }
            self.0.witnessed(target, count, view_count).await
        }

        async fn user_agent(&self, peer: &PeerId) -> Option<String> {
            self.0.user_agent(peer).await
        }
    }

    #[test]
    fn a_failed_lookup_closes_nothing_of_its_part() {
        let dir = tempfile::tempdir().unwrap();
        let mut census = census(dir.path());
        let sim = Sim::new(200, 0, 7);
        run(census.refresh_with(&sim, 10, &mut rng(7))).unwrap();
        let before = ids(&census);
        // Every node is silent at its latest poll, so any member of a closed
        // part that wasn't found would leave.
        for peer in &before {
            census.record_miss(peer);
        }
        let error = run(census.refresh_with(&HalfDown(&sim), 20, &mut rng(8))).unwrap_err();
        assert!(matches!(error, Error::Network(_)), "{error}");
        assert_eq!(ids(&census), before, "nothing left from parts not closed");
        // The parts not closed are queued, and only they: the upper half.
        let queued = census.queued();
        assert!(!queued.is_empty());
        let upper = AddressRange::new([0x80; 32], 1);
        for part in &queued {
            assert!(upper.covers(part) || *part == AddressRange::ALL, "{part:?}");
        }
        assert_eq!(census.refreshed_at(), Some(20));
        // The next upkeep closes them.
        run(census.maintain_with(&sim, 30, &mut rng(9))).unwrap();
        assert!(census.queued().is_empty());
        assert_eq!(ids(&census), before);
    }

    #[test]
    fn a_member_not_found_leaves_only_if_silent_at_its_latest_poll() {
        let dir = tempfile::tempdir().unwrap();
        let mut census = census(dir.path());
        let mut sim = Sim::new(100, 0, 9);
        run(census.refresh_with(&sim, 10, &mut rng(9))).unwrap();
        let members: Vec<PeerId> = ids(&census).into_iter().collect();
        let (answering, silent, unpolled) = (members[10], members[20], members[30]);
        for gone in [answering, silent, unpolled] {
            sim.nodes.get_mut(gone.as_bytes()).unwrap().alive = false;
        }
        census.record_answer(&answering, 15, None);
        census.record_answer(&silent, 15, None);
        census.record_miss(&silent);
        let change = run(census.refresh_with(&sim, 20, &mut rng(10))).unwrap();
        let left: BTreeSet<PeerId> = change.left.into_iter().collect();
        assert_eq!(left, BTreeSet::from([silent, unpolled]));
        assert!(
            census.get(&answering).is_some(),
            "it answered its latest poll"
        );
        assert!(change.joined.is_empty());
    }

    /// Lookups whose nodes give user agents of their own choosing.
    struct Agents<'a>(&'a Sim, HashMap<PeerId, Option<String>>);

    impl Lookups for Agents<'_> {
        async fn witnessed(
            &self,
            target: &XorName,
            count: usize,
            view_count: usize,
        ) -> Result<Sighting> {
            self.0.witnessed(target, count, view_count).await
        }

        async fn user_agent(&self, peer: &PeerId) -> Option<String> {
            match self.1.get(peer) {
                Some(agent) => agent.clone(),
                None => self.0.user_agent(peer).await,
            }
        }
    }

    #[test]
    fn nodes_that_answer_join_with_their_user_agents_and_others_dont() {
        let dir = tempfile::tempdir().unwrap();
        let mut census = census(dir.path());
        let sim = Sim::new(60, 0, 11);
        let live: Vec<PeerId> = sim.live().into_iter().collect();
        let agents = HashMap::from([
            (live[0], Some("client/0.9.0".to_owned())),
            (live[1], None),
            (live[2], Some("node/0.24.0+ds.16 extra".to_owned())),
        ]);
        run(census.refresh_with(&Agents(&sim, agents), 10, &mut rng(11))).unwrap();
        assert!(census.get(&live[0]).is_none(), "a client isn't a node");
        assert_eq!(census.get(&live[1]).unwrap().user_agent, None);
        assert!(census.supports_feed(&live[2]));
        assert_eq!(census.len(), live.len() - 1);
        let node = census.get(&live[3]).unwrap();
        assert_eq!(node.first_seen, 10);
        assert_eq!(node.last_answered, None, "a lookup isn't a poll");
    }

    #[test]
    fn closing_covers_the_range_without_overlap() {
        let sim = Sim::new(300, 10, 12);
        for range in [
            AddressRange::ALL,
            AddressRange::new([0x40; 32], 2),
            AddressRange::new([0xa7; 32], 9),
        ] {
            let found = run(explore(&sim, range, None, &mut rng(13)));
            assert!(found.failed.is_empty());
            let mut closed = found.closed.clone();
            closed.sort_unstable();
            for part in &closed {
                assert!(range.covers(part), "{part:?} is outside {range:?}");
            }
            for pair in closed.windows(2) {
                assert!(pair[0].last() < pair[1].first(), "{pair:?} overlap");
            }
            // Together they are the range: their sizes add up to its size.
            let size =
                |part: &AddressRange| 2f64.powi(i32::from(range.bits()) - i32::from(part.bits()));
            let total: f64 = closed.iter().map(size).sum();
            assert!(
                (total - 1.0).abs() < 1e-9,
                "the parts cover {total} of the range"
            );
            assert_eq!(found.lookups, closed.len());
            for peer in sim.live() {
                if range.contains(peer.as_bytes()) {
                    assert!(found.answered.contains_key(&peer), "{peer} not found");
                }
            }
        }
    }

    #[test]
    fn a_lookup_closes_the_part_around_its_target() {
        let target = [0b1010_0000; 32];
        let part = AddressRange::new(target, 1);
        let answered = |ids: &[[u8; 32]]| Sighting {
            answered: ids
                .iter()
                .map(|id| (PeerId::from_bytes(*id), Vec::new()))
                .collect(),
            named: Vec::new(),
        };
        // The farthest is outside the part: all of it is closed.
        let mut outside = target;
        outside[0] = 0b0010_0000;
        let split = closed_by(&part, &target, &answered(&[target, outside])).unwrap();
        assert_eq!(
            split,
            Split {
                closed: part,
                rest: Vec::new()
            }
        );
        // The farthest shares 3 bits: the part fixing 4 is closed, and the
        // halves along the way are left.
        let mut inside = target;
        inside[0] = 0b1011_0000;
        let split = closed_by(&part, &target, &answered(&[inside, target])).unwrap();
        assert_eq!(split.closed, AddressRange::new(target, 4));
        assert_eq!(
            split.rest,
            vec![
                AddressRange::new([0b1110_0000; 32], 2),
                AddressRange::new([0b1000_0000; 32], 3),
                AddressRange::new([0b1011_0000; 32], 4),
            ]
        );
        assert!(split
            .rest
            .iter()
            .all(|rest| part.covers(rest) && !rest.contains(&target)));
        // Nothing answered, or all at the target: nothing closed.
        assert_eq!(closed_by(&part, &target, &answered(&[])), None);
        assert_eq!(closed_by(&part, &target, &answered(&[target])), None);
        assert_eq!(shared_bits(&target, &target), 256);
        assert_eq!(shared_bits(&target, &inside), 3);
    }

    #[test]
    fn addresses_are_drawn_within_their_range() {
        let mut rng = rng(14);
        for bits in [0u8, 1, 7, 8, 9, 100, 255] {
            let range = AddressRange::new(id(u64::from(bits)), bits);
            for _ in 0..20 {
                assert!(range.contains(&address_in(&range, &mut rng)));
            }
        }
        let parts = Closed::new(&[
            AddressRange::new([0x10; 32], 4),
            AddressRange::new([0x80; 32], 1),
        ]);
        assert!(parts.contains(&[0x1f; 32]));
        assert!(parts.contains(&[0xff; 32]));
        assert!(!parts.contains(&[0x20; 32]));
        assert!(!parts.contains(&[0x00; 32]));
        assert!(!Closed::new(&[]).contains(&[0; 32]));
        assert_eq!(range_text(&AddressRange::ALL), "/0");
        assert_eq!(range_text(&AddressRange::new([0xa5; 32], 3)), "a0/3");
        assert_eq!(range_text(&AddressRange::new([0xa5; 32], 9)), "a580/9");
    }

    #[test]
    fn nearest_within_a_leaf_is_nearest_of_all() {
        let dir = tempfile::tempdir().unwrap();
        let mut census = census(dir.path());
        let ids: Vec<[u8; 32]> = (0..300).map(|n| id(n + 77)).collect();
        for (n, own) in ids.iter().enumerate() {
            census.admit(PeerId::from_bytes(*own), Vec::new(), 0);
            if n % 50 == 49 {
                for n in [1, 7, 8, 20, 300] {
                    for at in 0..40u64 {
                        let address = id(at * 13 + n as u64);
                        let expected: Vec<PeerId> =
                            nearest_by_distance(&address, &census.index().ids, n)
                                .into_iter()
                                .map(|at| census.index().peers[at])
                                .collect();
                        assert_eq!(census.nearest(&address, n), expected);
                    }
                }
                for leaf in census.leaves() {
                    let expected: Vec<PeerId> = census
                        .nodes()
                        .map(|node| node.peer)
                        .filter(|peer| leaf.contains(peer.as_bytes()))
                        .collect();
                    assert_eq!(census.members(&leaf), expected);
                }
            }
        }
    }

    #[test]
    fn a_changed_view_is_told_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut census = census(dir.path());
            census.admit(peer(1), Vec::new(), 0);
            assert!(
                !census.record_view(&peer(1), [1; 32]),
                "the first isn't a change"
            );
            assert!(!census.record_view(&peer(1), [1; 32]));
            assert!(census.record_view(&peer(1), [2; 32]));
            assert!(!census.record_view(&peer(9), [2; 32]), "not in the census");
            census.save().unwrap();
        }
        let mut census = census(dir.path());
        assert_eq!(census.get(&peer(1)).unwrap().view, Some([2; 32]));
        assert!(!census.record_view(&peer(1), [2; 32]));
        assert!(census.record_view(&peer(1), [3; 32]));
        // A node kept before views were has none.
        let mut old = serde_json::to_value(census.get(&peer(1)).unwrap()).unwrap();
        old.as_object_mut().unwrap().remove("view");
        let old: CensusNode = serde_json::from_value(old).unwrap();
        assert_eq!(old.view, None);
    }

    #[test]
    fn ids_a_node_lists_that_the_census_lacks_name_their_leaves() {
        let dir = tempfile::tempdir().unwrap();
        let mut census = census(dir.path());
        for n in 0..40 {
            census.admit(PeerId::from_bytes(id(n)), Vec::new(), 0);
        }
        let known: Vec<[u8; 32]> = (0..10).map(id).collect();
        assert!(census.lacking(&known).is_empty());
        assert!(census.lacking(&[]).is_empty());
        let unknown = [id(1_000), id(1_001), id(1_000)];
        let mut expected: Vec<AddressRange> = unknown.iter().map(|id| census.leaf_of(id)).collect();
        expected.sort_unstable();
        expected.dedup();
        let mut listed = known.clone();
        listed.extend(unknown);
        assert_eq!(census.lacking(&listed), expected);
    }

    #[test]
    fn the_status_counts_answers_versions_and_the_silent() {
        let dir = tempfile::tempdir().unwrap();
        let mut census = census(dir.path());
        for byte in 1..=9u8 {
            census.admit(peer(byte), Vec::new(), 0);
        }
        for byte in 1..=4u8 {
            census.record_answer(&peer(byte), 100, Some("node/0.23.0+ds.15".into()));
        }
        census.record_answer(
            &peer(5),
            100,
            Some("node/0.23.0+ds.13 migration=files".into()),
        );
        census.record_answer(&peer(6), 99, Some("node/0.23.0+ds.13".into()));
        census.record_answer(&peer(7), 100, Some("client/1.0".into()));
        let status = census.status(100);
        assert_eq!(status.nodes, 9);
        assert_eq!(status.answering, 6);
        assert_eq!(status.leaves, 1);
        assert_eq!(
            status.versions,
            vec![
                VersionCount {
                    version: Some("node/0.23.0+ds.15".into()),
                    nodes: 4
                },
                VersionCount {
                    version: Some("node/0.23.0+ds.13".into()),
                    nodes: 2
                },
                VersionCount {
                    version: None,
                    nodes: 3
                },
            ]
        );
        assert_eq!(
            status.silent,
            vec![
                SilentNode {
                    node: hex::encode([6; 32]),
                    last_answered: Some(99)
                },
                SilentNode {
                    node: hex::encode([8; 32]),
                    last_answered: None
                },
                SilentNode {
                    node: hex::encode([9; 32]),
                    last_answered: None
                },
            ]
        );
    }

    #[test]
    fn closing_is_send() {
        fn send<T: Send>(_: &T) {}
        // Only built: closing the network's leaves can be awaited from a
        // spawned task.
        let _ = |census: &mut Census, client: &Client| {
            send(&census.close_leaf(client, AddressRange::ALL));
            send(&census.refresh(client));
        };
        let _ = |census: &mut Census, client: &Client| send(&census.maintain(client));
        let _ = |census: &mut Census, client: &Client| send(&census.witness(client, &[0; 32]));
        let _ = |census: &mut Census, client: &Client| {
            send(&census.confirm_drop(client, &[0; 32], 0, &[], &[]));
        };
    }

    #[test]
    fn user_agents_from_the_feed_release_on_support_feeds() {
        for agent in [
            "node/0.23.0+ds.15",
            "node/0.23.1+ds.16",
            "node/0.24.0+ds.15.1",
            "node/1.0.0+ds.100",
            "node/0.23.0+ds.15 migration=files",
        ] {
            assert!(supports_feed(agent), "{agent}");
        }
        for agent in [
            "node/0.23.0+ds.13",
            "node/0.23.0+ds.14",
            "node/0.21.0+ds.11",
            "node/0.21.0+ds.11 migration=legacy",
            "node/0.23.0",
            "client/0.23.0+ds.15",
            "node/0.23.0+dsx.15",
            "node/0.23.0+ds.",
            "node/garbage",
            " node/0.23.0+ds.15",
            "",
        ] {
            assert!(!supports_feed(agent), "{agent}");
        }
        assert_eq!(
            node_version("node/0.23.0+ds.13 migration=files"),
            Some("node/0.23.0+ds.13")
        );
        assert_eq!(node_version("node/0.23.0+ds.15"), Some("node/0.23.0+ds.15"));
        assert_eq!(node_version("client/0.23.0"), None);
    }

    #[test]
    fn the_census_is_kept_across_opens() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut census = census(dir.path());
            assert!(census.is_empty());
            assert!(census.refresh_due(0));
            assert!(census.admit(peer(1), Vec::new(), 100));
            assert!(census.admit(peer(2), Vec::new(), 100));
            assert!(!census.admit(peer(1), Vec::new(), 200));
            assert!(census.record_answer(&peer(1), 160, Some("node/0.23.0+ds.15".into())));
            assert!(!census.record_answer(&peer(9), 160, None));
            census.set_refreshed_at(100);
            census.save().unwrap();
            assert!(census.remove(&peer(2)));
            census.save().unwrap();
        }
        let census = census(dir.path());
        assert_eq!(census.len(), 1);
        let node = census.get(&peer(1)).unwrap();
        assert_eq!(node.first_seen, 100);
        assert_eq!(node.last_answered, Some(160));
        assert!(census.supports_feed(&peer(1)));
        assert_eq!(census.refreshed_at(), Some(100));
        assert!(!census.refresh_due(100 + REFRESH_INTERVAL.as_secs() - 1));
        assert!(census.refresh_due(100 + REFRESH_INTERVAL.as_secs()));
    }

    #[test]
    fn a_leaf_is_closed_again_at_the_third_miss_in_a_row() {
        let dir = tempfile::tempdir().unwrap();
        let mut census = census(dir.path());
        census.admit(peer(1), Vec::new(), 0);
        assert!(!census.record_miss(&peer(1)));
        assert!(!census.record_miss(&peer(1)));
        assert!(census.record_miss(&peer(1)));
        assert!(!census.record_miss(&peer(1)));
        census.record_answer(&peer(1), 5, None);
        assert_eq!(census.get(&peer(1)).unwrap().missed, 0);
        assert!(!census.record_miss(&peer(2)));
    }

    #[test]
    fn nearest_nodes_lie_in_the_addresss_leaf() {
        let dir = tempfile::tempdir().unwrap();
        let mut census = census(dir.path());
        for byte in 0..40u8 {
            census.admit(peer(byte.wrapping_mul(37)), Vec::new(), 0);
        }
        let leaves = census.leaves();
        assert!(leaves.len() > 1);
        for target in [[0u8; 32], [0x80; 32], [0xff; 32], [0x5a; 32]] {
            let leaf = census.leaf_of(&target);
            let nearest = census.nearest(&target, NEAREST_NODES);
            assert_eq!(nearest.len(), NEAREST_NODES);
            for node in &nearest {
                assert!(leaf.contains(node.as_bytes()));
                assert!(census.members(&leaf).contains(node));
            }
        }
        // An empty census asks about the whole space.
        let empty_dir = tempfile::tempdir().unwrap();
        let empty = super::tests::census(empty_dir.path());
        assert_eq!(empty.leaf_of(&[7; 32]), AddressRange::ALL);
        assert!(empty.nearest(&[7; 32], NEAREST_NODES).is_empty());
    }

    #[test]
    fn the_guard_needs_seven_and_three_quarters() {
        let dir = tempfile::tempdir().unwrap();
        let mut census = census(dir.path());
        for byte in 0..20u8 {
            census.admit(peer(byte), Vec::new(), 0);
        }
        assert!(!census.guard_ok(14));
        assert!(census.guard_ok(15));
        let small_dir = tempfile::tempdir().unwrap();
        let mut small = super::tests::census(small_dir.path());
        for byte in 0..6u8 {
            small.admit(peer(byte), Vec::new(), 0);
        }
        assert!(!small.guard_ok(6));
    }

    /// `GetRequest` answers of a synthetic network: every node serves
    /// nothing unless told otherwise.
    struct FakeGets {
        now: u64,
        answers: HashMap<PeerId, Served>,
        asked: std::sync::Mutex<Vec<PeerId>>,
    }

    impl FakeGets {
        fn at(now: u64) -> Self {
            Self {
                now,
                answers: HashMap::new(),
                asked: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn with(mut self, peer: PeerId, served: Served) -> Self {
            self.answers.insert(peer, served);
            self
        }

        fn asked(&self) -> Vec<PeerId> {
            self.asked.lock().unwrap().clone()
        }
    }

    impl Gets for FakeGets {
        fn now(&self) -> u64 {
            self.now
        }

        async fn get(&self, _address: &XorName, peers: &[PeerId]) -> Vec<(PeerId, Served)> {
            self.asked.lock().unwrap().extend_from_slice(peers);
            peers
                .iter()
                .map(|peer| {
                    let served = self.answers.get(peer).copied().unwrap_or(Served::Nothing);
                    (*peer, served)
                })
                .collect()
        }
    }

    /// The key time of the listings the drop tests drop, and the first
    /// moment a drop of one may be confirmed.
    const KEY_TIME: u64 = 1_790_000_000;
    const ASK_FROM: u64 = KEY_TIME + FIRST_SEEN_ROUNDING + CLOCK_MARGIN;

    /// A census of a synthetic network of `live` nodes, closed whole.
    fn closed_census(dir: &std::path::Path, live: usize, seed: u64) -> (Census, Sim) {
        let mut census = census(dir);
        let sim = Sim::new(live, live / 20, seed);
        run(census.refresh_with(&sim, 10, &mut rng(seed))).unwrap();
        assert_eq!(ids(&census), sim.live());
        assert_eq!(census.take_changes().joined.len(), live);
        (census, sim)
    }

    #[test]
    fn a_witness_finds_an_addresss_nearest_and_closes_its_leaf() {
        let dir = tempfile::tempdir().unwrap();
        let (mut census, sim) = closed_census(dir.path(), 300, 21);
        let live: Vec<[u8; 32]> = sim.live().iter().map(|peer| *peer.as_bytes()).collect();
        let mut rng = rng(22);
        for n in 0..40 {
            let address = id(9_000 + n);
            let before = census.nearest(&address, NEAREST_NODES);
            let leaf = census.leaf_of(&address);
            let witness = run(census.witness_with(&sim, &address, 20, &mut rng)).unwrap();
            let truth: Vec<PeerId> = nearest_by_distance(&address, &live, NEAREST_NODES)
                .into_iter()
                .map(|at| PeerId::from_bytes(live[at]))
                .collect();
            assert_eq!(witness.address, address);
            assert_eq!(witness.leaf, leaf);
            assert_eq!(witness.nearest, truth, "nearest first");
            assert_eq!(witness.census_nearest, truth);
            assert!(witness.closed);
            assert!(witness.change.is_empty(), "nothing changed in the network");
            assert_eq!(witness.check(&before), Ok(()));
            // Any order; but not other nodes, nor fewer.
            let mut reversed = before.clone();
            reversed.reverse();
            assert_eq!(witness.check(&reversed), Ok(()));
            let mut other = before.clone();
            other[6] = PeerId::from_bytes(id(77));
            assert!(witness.check(&other).is_err());
            assert!(witness.check(&before[..6]).is_err());
        }
    }

    #[test]
    fn a_witness_finds_a_node_that_joined_near_the_address() {
        let dir = tempfile::tempdir().unwrap();
        let (mut census, mut sim) = closed_census(dir.path(), 200, 23);
        let mut rng = rng(24);
        let address = id(31_337);
        let expected = census.nearest(&address, NEAREST_NODES);
        // A node joins right next to the address: it is now its nearest.
        let mut own = address;
        own[31] ^= 1;
        sim.join(own, &mut rng);
        let witness = run(census.witness_with(&sim, &address, 30, &mut rng)).unwrap();
        let newcomer = PeerId::from_bytes(own);
        assert_eq!(witness.nearest[0], newcomer);
        assert_eq!(witness.census_nearest[0], newcomer);
        assert_eq!(witness.change.joined, vec![newcomer]);
        let refused = witness.check(&expected).unwrap_err();
        assert!(refused.contains("found 6 of the 7"), "{refused}");
        assert_eq!(census.take_changes().joined, vec![newcomer]);
    }

    #[test]
    fn a_failed_witness_is_an_error_and_an_unclosed_leaf_confirms_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (mut census, sim) = closed_census(dir.path(), 200, 25);
        let mut rng = rng(26);
        // The lookup of the address itself fails.
        let mut high = id(5);
        high[0] |= 0x80;
        let error = run(census.witness_with(&HalfDown(&sim), &high, 20, &mut rng)).unwrap_err();
        assert!(matches!(error, Error::Network(_)), "{error}");
        // A witness whose leaf wasn't closed confirms nothing.
        let mut low = id(6);
        low[0] &= 0x7f;
        let expected = census.nearest(&low, NEAREST_NODES);
        let mut witness = run(census.witness_with(&sim, &low, 20, &mut rng)).unwrap();
        assert_eq!(witness.check(&expected), Ok(()));
        witness.closed = false;
        assert!(witness.check(&expected).is_err());
        // Nor one of a network too small to have 7 nearest.
        let small_dir = tempfile::tempdir().unwrap();
        let (mut small, small_sim) = closed_census(small_dir.path(), 7, 27);
        let expected = small.nearest(&low, NEAREST_NODES);
        let witness = run(small.witness_with(&small_sim, &low, 20, &mut rng)).unwrap();
        assert_eq!(witness.check(&expected), Ok(()));
        assert!(witness.check(&expected[..5]).is_err());
    }

    #[test]
    fn a_drop_is_confirmed_only_when_every_node_asked_serves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let (mut census, sim) = closed_census(dir.path(), 200, 28);
        let mut rng = rng(29);
        let address = id(4_242);
        let expected = census.nearest(&address, NEAREST_NODES);
        let members: Vec<PeerId> = ids(&census).into_iter().collect();
        let holder = *members
            .iter()
            .find(|peer| !expected.contains(peer))
            .unwrap();
        let gone_holder = PeerId::from_bytes(id(66_666));

        // Every node asked serves nothing: dropped. The nearest are asked,
        // then the last holders still in the census; one that left isn't.
        let gets = FakeGets::at(ASK_FROM);
        let confirmation = run(census.confirm_drop_with(
            &sim,
            &gets,
            &address,
            KEY_TIME,
            &expected,
            &[holder, gone_holder, expected[0]],
            &mut rng,
        ));
        assert_eq!(confirmation, Ok(()));
        let mut asked = expected.clone();
        asked.push(holder);
        assert_eq!(gets.asked(), asked);

        // A nearest node serving a listing, a last holder serving one, or
        // either not answering: kept.
        for (peer, served) in [
            (expected[3], Served::Listing),
            (expected[6], Served::Silent),
            (holder, Served::Listing),
            (holder, Served::Silent),
        ] {
            let gets = FakeGets::at(ASK_FROM).with(peer, served);
            let confirmation = run(census.confirm_drop_with(
                &sim,
                &gets,
                &address,
                KEY_TIME,
                &expected,
                &[holder],
                &mut rng,
            ));
            assert!(confirmation.is_err(), "{peer} {served:?}");
        }

        // Too soon: nothing is looked up or asked.
        let lookups = sim.lookups.load(Ordering::Relaxed);
        let gets = FakeGets::at(ASK_FROM - 1);
        let confirmation = run(census.confirm_drop_with(
            &sim,
            &gets,
            &address,
            KEY_TIME,
            &expected,
            &[],
            &mut rng,
        ));
        let kept = confirmation.unwrap_err();
        assert!(kept.contains("too soon"), "{kept}");
        assert_eq!(sim.lookups.load(Ordering::Relaxed), lookups);
        assert!(gets.asked().is_empty());

        // Other nodes than the witness finds: refused before asking anyone.
        let mut wrong = expected.clone();
        wrong[2] = holder;
        let gets = FakeGets::at(ASK_FROM);
        let confirmation =
            run(census.confirm_drop_with(&sim, &gets, &address, KEY_TIME, &wrong, &[], &mut rng));
        assert!(confirmation.is_err());
        assert!(gets.asked().is_empty());

        // The lookup fails: kept.
        let mut high = address;
        high[0] |= 0x80;
        let expected_high = census.nearest(&high, NEAREST_NODES);
        let confirmation = run(census.confirm_drop_with(
            &HalfDown(&sim),
            &FakeGets::at(ASK_FROM),
            &high,
            KEY_TIME,
            &expected_high,
            &[],
            &mut rng,
        ));
        assert!(confirmation.is_err());
    }

    #[test]
    fn a_drop_check_asks_from_two_hours_after_the_key_time() {
        let dir = tempfile::tempdir().unwrap();
        let (mut census, sim) = closed_census(dir.path(), 100, 30);
        let address = id(8);
        let expected = census.nearest(&address, NEAREST_NODES);
        let witness = run(census.witness_with(&sim, &address, 20, &mut rng(31))).unwrap();
        let check = census.drop_check(&witness, &expected, &[], KEY_TIME);
        assert_eq!(check.ask_from, KEY_TIME + 2 * 60 * 60);
        assert_eq!(check.refused, None);
        let nothing: Vec<(PeerId, Served)> = expected
            .iter()
            .map(|peer| (*peer, Served::Nothing))
            .collect();
        assert_eq!(check.verdict(ASK_FROM, &nothing), Ok(()));
        assert!(check.verdict(ASK_FROM - 1, &nothing).is_err());
        // An answer missing counts as none given.
        assert!(check.verdict(ASK_FROM, &nothing[1..]).is_err());
        // A refused check confirms nothing, whatever the answers.
        let refused = census.drop_check(&witness, &expected[..6], &[], KEY_TIME);
        assert!(refused.refused.is_some());
        assert!(refused.verdict(ASK_FROM, &nothing).is_err());
    }

    #[test]
    fn maintain_refreshes_when_due_and_closes_what_is_queued() {
        let dir = tempfile::tempdir().unwrap();
        let store = ListingsStore::open_with_map_size(dir.path(), TEST_MAP).unwrap();
        let mut census = Census::open(&store).unwrap();
        let mut sim = Sim::new(200, 0, 32);
        let mut rng = rng(33);

        // The first upkeep closes every leaf.
        let change = run(census.maintain_with(&sim, 100, &mut rng)).unwrap();
        assert_eq!(change.joined.len(), 200);
        assert_eq!(ids(&census), sim.live());
        assert_eq!(census.refreshed_at(), Some(100));
        assert_eq!(census.take_changes().joined.len(), 200);

        // Nothing queued, nothing due: no lookups.
        let lookups = sim.lookups.load(Ordering::Relaxed);
        let change = run(census.maintain_with(&sim, 200, &mut rng)).unwrap();
        assert!(change.is_empty());
        assert_eq!(sim.lookups.load(Ordering::Relaxed), lookups);

        // A member goes: its third miss queues its leaf, which upkeep closes.
        let gone = *ids(&census).iter().nth(50).unwrap();
        sim.nodes.get_mut(gone.as_bytes()).unwrap().alive = false;
        for peer in ids(&census) {
            if peer != gone {
                census.record_answer(&peer, 150, None);
            }
        }
        census.record_miss(&gone);
        census.record_miss(&gone);
        assert!(census.queued().is_empty());
        census.record_miss(&gone);
        assert_eq!(census.queued(), vec![census.leaf_of(gone.as_bytes())]);
        // The queue is kept.
        census.save().unwrap();
        assert_eq!(
            Census::open(&store).unwrap().queued(),
            vec![census.leaf_of(gone.as_bytes())]
        );
        let change = run(census.maintain_with(&sim, 300, &mut rng)).unwrap();
        assert_eq!(change.left, vec![gone]);
        assert!(census.queued().is_empty());
        assert_eq!(census.take_changes().left, vec![gone]);

        // A node joins; a neighbour's list of peers names it, which queues
        // its leaf; upkeep takes it in.
        let own = id(424_242);
        sim.join(own, &mut rng);
        let peers = nearest_of(sim.live().iter().map(|peer| *peer.as_bytes()), &own, K)
            .into_iter()
            .filter(|neighbour| *neighbour != own)
            .map(|neighbour| sim.peers_of(&neighbour))
            .find(|peers| peers.contains(&own))
            .unwrap();
        assert_eq!(census.note_peers(&peers), 1);
        assert_eq!(census.note_peers(&peers), 0, "queued once");
        let change = run(census.maintain_with(&sim, 400, &mut rng)).unwrap();
        assert_eq!(change.joined, vec![PeerId::from_bytes(own)]);
        assert!(census.queued().is_empty());

        // A queued range whose lookups fail stays queued.
        let mut high = id(7);
        high[0] |= 0x80;
        let leaf = census.leaf_of(&high);
        census.queue_close(leaf);
        assert!(run(census.maintain_with(&HalfDown(&sim), 500, &mut rng)).is_err());
        assert_eq!(census.queued(), vec![leaf]);

        // A day on, upkeep closes every leaf again, and the queue with them.
        let lookups = sim.lookups.load(Ordering::Relaxed);
        let day = 100 + REFRESH_INTERVAL.as_secs();
        run(census.maintain_with(&sim, day, &mut rng)).unwrap();
        assert!(sim.lookups.load(Ordering::Relaxed) > lookups);
        assert_eq!(census.refreshed_at(), Some(day));
        assert!(census.queued().is_empty());
        census.save().unwrap();
        assert!(Census::open(&store).unwrap().queued().is_empty());
    }

    #[test]
    fn a_queued_range_is_closed_as_the_leaves_now_split_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut census = census(dir.path());
        for n in 0..60 {
            census.admit(PeerId::from_bytes(id(n + 500)), Vec::new(), 0);
        }
        let leaves = census.leaves();
        assert!(leaves.len() >= 4);
        // Inside a leaf: that leaf. Holding several: itself. One range held
        // by another queued is closed with it.
        let inner = AddressRange::new(leaves[1].first(), leaves[1].bits() + 3);
        census.queue_close(inner);
        census.queue_close(AddressRange::ALL);
        assert_eq!(census.ranges_to_close(), vec![AddressRange::ALL]);
        census.queue.clear();
        census.queue_close(inner);
        let last = *leaves.last().unwrap();
        census.queue_close(last);
        assert_eq!(census.ranges_to_close(), vec![leaves[1], last]);
        // The lower half holds several leaves, the second among them.
        let half = AddressRange::new([0; 32], 1);
        assert!(half.covers(&leaves[1]) && !half.covers(&last));
        assert!(!leaves.iter().any(|leaf| leaf.covers(&half)));
        census.queue_close(half);
        assert_eq!(census.ranges_to_close(), vec![half, last]);
    }

    #[test]
    fn changes_add_up_until_taken() {
        let dir = tempfile::tempdir().unwrap();
        let mut census = census(dir.path());
        census.admit(peer(1), Vec::new(), 0);
        census.admit(peer(2), Vec::new(), 0);
        census.admit(peer(3), Vec::new(), 0);
        census.remove(&peer(2));
        let change = census.take_changes();
        assert_eq!(change.joined, vec![peer(1), peer(3)]);
        assert_eq!(change.left, vec![peer(2)], "joined, then left");
        assert!(census.take_changes().is_empty());
        census.remove(&peer(1));
        census.admit(peer(1), Vec::new(), 5);
        census.remove(&peer(3));
        let change = census.take_changes();
        assert_eq!(change.joined, vec![peer(1)]);
        assert_eq!(change.left, vec![peer(3)]);
    }

    #[test]
    fn queued_ranges_are_kept_as_keys() {
        for range in [
            AddressRange::ALL,
            AddressRange::new([0xa5; 32], 3),
            AddressRange::new(id(3), 255),
        ] {
            assert_eq!(range_from_key(&range_key(&range)), Some(range));
        }
        assert_eq!(range_from_key(&[0; 32]), None);
        assert_eq!(range_from_key(&[0; 34]), None);
    }
}
