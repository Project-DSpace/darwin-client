//! The listings producer behind `darwin listings serve`: one long-lived
//! process that follows what the nodes serve and publishes the index as the
//! files of `listings/v1/` (`docs/listings-v1.md`).
//!
//! It keeps its client and connections, the census of nodes
//! ([`Census`]), a mirror of each node's part of the index, chain facts and
//! envelopes ([`ListingChain::with_store`]) and the published index
//! ([`Publisher`]) in one store ([`ListingsStore`]), so a restart starts
//! where the last run stopped.
//!
//! Each cycle ([`Producer::cycle`], every [`CYCLE`]):
//!
//! 1. **Poll.** One request to each census node, [`POLL_CONCURRENCY`] at a
//!    time. A node whose user agent shows the feed release
//!    ([`Census::supports_feed`]) is sent a `ChangesRequest` for its leaf
//!    ([`Census::leaf_of`]), with a watch, and its answer is applied to its
//!    mirror ([`ant_listings::FeedSync`]). The mirror's count and set hash
//!    must equal the node's; otherwise, as after a new epoch, the node is
//!    read afresh with `RangeListRequest`s and counts as silent until that is
//!    done. A node without the release is sent one listings v2 request: the
//!    next page of a full pass of its index (a new pass starts at most once
//!    every [`V2_PASS_INTERVAL`]), or between passes a read from the key
//!    after the newest listing seen from it. A node that claims the release
//!    but doesn't answer one is read the v2 way.
//! 2. **Guard.** If fewer than 7 census nodes answered, or under three
//!    quarters of them ([`Census::guard_ok`]), the cycle decides and drops
//!    nothing.
//! 3. **Support.** An address's support is how many of the census's 7 nodes
//!    nearest it ([`Census::nearest`]) answered this cycle and serve a valid
//!    copy: from the node's mirror when it is in sync, and for a node without
//!    the release from its latest pass, while it keeps answering.
//! 4. **Work per address**, only at support 4 or more: one `GetRequest` per
//!    group of copies for the full listing, checked against its digest
//!    entry; the envelope, kept for good; chain facts; then the decision
//!    code of an index read, unchanged (`decide_address`, `check_copies`,
//!    and the earliest paid with a quorum). If one group has a quorum only
//!    it is checked; otherwise every group is.
//! 5. **Deciding again.** An address is decided again only when an input
//!    changed (its copies or their `first_seen` among its 7 nearest, its 7
//!    nearest themselves, or a chain fact becoming final), and every cycle
//!    while its last result was "try again" or a time in the future. Once
//!    every [`REDECIDE_INTERVAL`] every published address is decided again
//!    from its stored inputs, and a difference is logged as an alert.
//! 6. **Drops.** A published address is removed only when, within one
//!    cycle, all 7 of its nearest answered and none serves a copy at any
//!    key; closing its leaf again finds the same 7 ([`Census::close_leaf`]);
//!    a `GetRequest` to each of the 7, begun at or after the address's key
//!    time plus `FIRST_SEEN_ROUNDING` and `CLOCK_MARGIN`, returns none; and
//!    the nodes that served it when it was last decided return none too, or
//!    have left the census. Otherwise it stays, marked carried while
//!    unconfirmed.
//! 7. **Publishing** what changed ([`Publisher::publish`]), and
//!    `status.json`.
//!
//! Between cycles, nodes push the new records of the leaves they are asked
//! about: a push that brings a mirror to the node's new head is applied,
//! and the addresses it changes are decided and published at once; any
//! other waits for the next poll.

use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use super::listings::ListingChain;
use super::listings_census::Census;
use super::listings_publish::Publisher;
use super::listings_store::ListingsStore;
use super::listings_v1::Status;
use crate::data::client::Client;
use crate::data::error::Result;

/// How often a cycle starts: each minute. New listings arrive sooner, by
/// push.
pub const CYCLE: Duration = Duration::from_secs(60);

/// How many nodes are polled at once.
pub const POLL_CONCURRENCY: usize = 64;

/// A node without the feed release starts a new full pass of its index at
/// most this often.
pub const V2_PASS_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Every published address is decided again from its stored inputs this
/// often: once a day.
pub const REDECIDE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// The store's directory inside the state directory.
pub const STORE_DIR: &str = "listings.mdb";

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
}

/// The listings producer. See the module docs.
pub struct Producer {
    client: Client,
    chain: ListingChain,
    store: ListingsStore,
    census: Census,
    publisher: Publisher,
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
        let publisher = Publisher::open(out_dir, &store)?;
        Ok(Self {
            client,
            chain,
            store,
            census,
            publisher,
        })
    }

    /// On a first start, while the store holds no index yet, take the
    /// entries of `previous`, an earlier `darwin listings --json` output
    /// (such as the `listings.json` the producer replaces), into the index
    /// as carried: published as they were, marked carried in their support,
    /// until a cycle decides their addresses or shows them no longer served.
    /// So nothing published is lost before the first cycles confirm it.
    /// Returns how many were taken: none, without reading `previous`, once
    /// the store holds an index.
    ///
    /// # Errors
    ///
    /// If `previous` can't be read or isn't such an output, or the index
    /// can't be published.
    pub fn carry_from(&mut self, previous: &Path) -> Result<usize> {
        let _ = previous;
        todo!("take an earlier read's entries as carried")
    }

    /// Run cycles until `cancel` fires: one every [`CYCLE`], the first at
    /// once, taking nodes' pushes between them. A cycle that fails is logged
    /// and the next one runs on time. On `cancel`, the cycle or push in hand
    /// finishes writing its changes first.
    ///
    /// # Errors
    ///
    /// Only if the producer can't go on at all, such as when its store can't
    /// be written.
    pub async fn run(&mut self, cancel: CancellationToken) -> Result<()> {
        let _ = cancel;
        todo!("run cycles and take pushes until cancelled")
    }

    /// Run one cycle (see the module docs) and publish what it changed.
    ///
    /// # Errors
    ///
    /// If the store or the published files can't be written. Nodes and RPCs
    /// that fail are no error: the cycle decides less.
    pub async fn cycle(&mut self) -> Result<CycleReport> {
        todo!("poll, guard, support, decide, drop and publish")
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

    /// The publisher.
    #[must_use]
    pub fn publisher(&self) -> &Publisher {
        &self.publisher
    }
}
