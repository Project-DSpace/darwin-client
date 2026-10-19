//! The listings producer's census: every node of the network it knows, and
//! the leaves the address space is split into for asking them.
//!
//! An index read used to find the nodes to ask anew each time, with a few
//! random lookups, which miss close groups as the network grows. The
//! producer keeps a census instead:
//!
//! - **Proof of life.** A node joins the census only once it has answered:
//!   as a responder of a witnessed lookup, which returns only nodes that
//!   answered ([`Network::find_witnessed_close_group_with_view_count`]), or
//!   by answering a request. An id a peer slips into the view it gives never
//!   becomes one of an address's nearest nodes by itself.
//! - **Leaves.** The address space is split as [`ant_listings::leaves`]
//!   splits it over the census's ids: a range is halved only while both
//!   halves hold at least [`NEAREST_NODES`] nodes, so the [`NEAREST_NODES`]
//!   nodes nearest any address are all in its leaf. Each node is asked about
//!   its own leaf ([`Census::leaf_of`]).
//! - **Closing leaves.** A leaf is closed by witnessed lookups that find
//!   every node in it, merging the responders' views ([`Census::close_leaf`]).
//!   It is closed again when a member misses [`MISSES_BEFORE_CLOSE`] polls in
//!   a row ([`Census::record_miss`]), when a node's view names a node the
//!   census lacks, and before any listing in it is dropped; and every leaf is
//!   closed once every [`REFRESH_INTERVAL`] ([`Census::refresh`]).
//! - **Versions.** Each node's user agent says which release it runs; one
//!   from [`FEED_RELEASE`] on answers change feeds
//!   ([`Census::supports_feed`]), and older ones are read with the
//!   listings v2 requests.
//! - **Guard.** A cycle in which fewer than [`NEAREST_NODES`] of the
//!   census answered, or under three quarters of it, decides and drops
//!   nothing ([`Census::guard_ok`]).
//!
//! The census is kept in the producer's store
//! ([`ListingsStore`], databases [`NODES_DB`] and [`META_DB`]); changes are
//! written once a cycle ([`Census::save`]).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;
use std::time::Duration;

use ant_listings::{leaf_index, leaves, nearest_by_distance, AddressRange, Leaf, NEAREST_NODES};
use ant_protocol::transport::{MultiAddr, PeerId};
use ant_protocol::XorName;
use heed::types::{Bytes, SerdeJson, Str, U64};
use heed::{byteorder::BigEndian, Database};
use serde::{Deserialize, Serialize};

use crate::data::client::listings_store::{store_error, ListingsStore};
use crate::data::client::Client;
use crate::data::error::Result;
#[cfg(doc)]
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

/// The census's nodes, by id.
pub const NODES_DB: &str = "census_nodes";

/// The census's other state: when it was last refreshed.
pub const META_DB: &str = "census_meta";

/// The key in [`META_DB`] of when every leaf was last closed (Unix seconds).
const REFRESHED_AT: &str = "refreshed_at";

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
}

/// What closing leaves changed in the census.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CensusChange {
    /// Nodes that joined.
    pub joined: Vec<PeerId>,
    /// Nodes that left: not found answering when their leaf was closed.
    pub left: Vec<PeerId>,
}

impl CensusChange {
    /// Whether nothing changed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.joined.is_empty() && self.left.is_empty()
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
        let peers: Vec<PeerId> = nodes.keys().copied().collect();
        let ids: Vec<[u8; 32]> = peers.iter().map(|peer| *peer.as_bytes()).collect();
        let leaves = leaves(&ids);
        Self { peers, ids, leaves }
    }
}

/// The census. See the module docs.
pub struct Census {
    store: ListingsStore,
    nodes_db: Database<Bytes, SerdeJson<CensusNode>>,
    meta_db: Database<Str, U64<BigEndian>>,
    nodes: BTreeMap<PeerId, CensusNode>,
    /// Nodes changed since the last save.
    dirty: BTreeSet<PeerId>,
    /// Nodes removed since the last save.
    removed: BTreeSet<PeerId>,
    refreshed_at: Option<u64>,
    refreshed_dirty: bool,
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
        let meta_db: Database<Str, U64<BigEndian>> = store.database(META_DB)?;
        let txn = store.env().read_txn().map_err(store_error)?;
        let mut nodes = BTreeMap::new();
        for row in nodes_db.iter(&txn).map_err(store_error)? {
            let (_, node) = row.map_err(store_error)?;
            nodes.insert(node.peer, node);
        }
        let refreshed_at = meta_db.get(&txn, REFRESHED_AT).map_err(store_error)?;
        drop(txn);
        Ok(Self {
            store: store.clone(),
            nodes_db,
            meta_db,
            nodes,
            dirty: BTreeSet::new(),
            removed: BTreeSet::new(),
            refreshed_at,
            refreshed_dirty: false,
            index: OnceLock::new(),
        })
    }

    /// Close every leaf, finding the nodes in each with witnessed lookups:
    /// at first, from an empty census, and then once every
    /// [`REFRESH_INTERVAL`] ([`Self::refresh_due`]). Nodes found answering
    /// join; members not found answering leave.
    ///
    /// # Errors
    ///
    /// If no lookup can be made.
    pub async fn refresh(&mut self, client: &Client) -> Result<CensusChange> {
        let _ = client;
        todo!("close every leaf with witnessed lookups")
    }

    /// Close the leaf `range` (one of [`Self::leaves`]) again with witnessed
    /// lookups: when a member has missed [`MISSES_BEFORE_CLOSE`] polls in a
    /// row, when a node's view names a node the census lacks, and before any
    /// listing in the leaf is dropped. Nodes found answering join; members
    /// not found answering leave. The leaves may change.
    ///
    /// # Errors
    ///
    /// If no lookup can be made.
    pub async fn close_leaf(
        &mut self,
        client: &Client,
        range: AddressRange,
    ) -> Result<CensusChange> {
        let _ = (client, range);
        todo!("close one leaf with witnessed lookups")
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
                    },
                );
                self.index = OnceLock::new();
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
        true
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
    /// [`MISSES_BEFORE_CLOSE`]th miss in a row: its leaf is to be closed
    /// again ([`Self::close_leaf`]). False for a node not in the census.
    pub fn record_miss(&mut self, peer: &PeerId) -> bool {
        let Some(node) = self.nodes.get_mut(peer) else {
            return false;
        };
        node.missed = node.missed.saturating_add(1);
        self.dirty.insert(*peer);
        node.missed == MISSES_BEFORE_CLOSE
    }

    /// Write what changed since the last save, in one transaction: once a
    /// cycle.
    ///
    /// # Errors
    ///
    /// If the store can't be written; what changed is kept for the next
    /// save.
    pub fn save(&mut self) -> Result<()> {
        if self.dirty.is_empty() && self.removed.is_empty() && !self.refreshed_dirty {
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
        if let (true, Some(at)) = (self.refreshed_dirty, self.refreshed_at) {
            self.meta_db
                .put(&mut txn, REFRESHED_AT, &at)
                .map_err(store_error)?;
        }
        txn.commit().map_err(store_error)?;
        self.dirty.clear();
        self.removed.clear();
        self.refreshed_dirty = false;
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
        index
            .peers
            .iter()
            .zip(&index.ids)
            .filter(|(_, id)| range.contains(id))
            .map(|(peer, _)| *peer)
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

    fn index(&self) -> &Index {
        self.index.get_or_init(|| Index::new(&self.nodes))
    }
}

/// Whether `user_agent` is a node's of a release that keeps a change feed:
/// `node/<version>+ds.<n>` with `n` at least [`FEED_RELEASE`], whatever the
/// version before it.
#[must_use]
pub fn supports_feed(user_agent: &str) -> bool {
    user_agent
        .strip_prefix("node/")
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

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MAP: usize = 16 * 1024 * 1024;

    fn peer(byte: u8) -> PeerId {
        PeerId::from_bytes([byte; 32])
    }

    fn census(dir: &std::path::Path) -> Census {
        let store = ListingsStore::open_with_map_size(dir, TEST_MAP).unwrap();
        Census::open(&store).unwrap()
    }

    #[test]
    fn user_agents_from_the_feed_release_on_support_feeds() {
        for agent in [
            "node/0.23.0+ds.15",
            "node/0.23.1+ds.16",
            "node/0.24.0+ds.15.1",
            "node/1.0.0+ds.100",
        ] {
            assert!(supports_feed(agent), "{agent}");
        }
        for agent in [
            "node/0.23.0+ds.13",
            "node/0.23.0+ds.14",
            "node/0.21.0+ds.11",
            "node/0.23.0",
            "client/0.23.0+ds.15",
            "node/0.23.0+dsx.15",
            "node/0.23.0+ds.",
            "node/garbage",
            "",
        ] {
            assert!(!supports_feed(agent), "{agent}");
        }
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
}
