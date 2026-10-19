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
//!
//! **What this version does.** Each cycle is an index read as `darwin
//! listings --state --carry` makes one ([`Client::index_listings_with`],
//! reading every node with listings v2 requests), with the walks' state kept
//! in the store between cycles, and with the reader's chain facts and
//! envelopes kept ([`ListingChain::with_store`]). What the read lists is
//! published. An entry it didn't decide is kept, marked carried, as `--carry`
//! keeps it ([`ListingsIndex::carry`]). One it decided and rejected is
//! removed as `rejected`. One whose whole close group walked past it is
//! removed as `no_longer_served` only once a `GetRequest` to each of the
//! nodes nearest it, sent after that read, finds none. The census, the
//! nodes' change feeds and their pushes are not used yet.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

use ant_listings::NEAREST_NODES;
use ant_protocol::transport::PeerId;
use ant_protocol::XorName;
use heed::byteorder::BigEndian;
use heed::types::{Bytes, Str, U64};
use heed::Database;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::listings::{
    listings_traffic, unix_now, Carry, CheckedListing, ListingChain, ListingsIndex, WalkState,
};
use super::listings_census::Census;
use super::listings_publish::{IndexChange, Publication, Publisher, RejectedChange};
use super::listings_store::{store_error, ListingsStore};
use super::listings_v1::{
    BelowFull, CensusStatus, CycleStatus, DeferredGroup, Drops, Entry, ListingFields,
    RejectedEntry, RemoveReason, Resources, RpcCalls, ShardEntry, SilentNode, Status, Support,
    Totals, VersionCount,
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

/// Every published address is decided again from its stored inputs this
/// often: once a day.
pub const REDECIDE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// The store's directory inside the state directory.
pub const STORE_DIR: &str = "listings.mdb";

/// The producer's own values: the walks' state of its index reads.
const META_DB: &str = "serve_meta";

/// Since when each address has been deferred, or listed below full
/// support: a tag ([`DEFERRED_TAG`] or [`BELOW_FULL_TAG`]) and the
/// address, to Unix seconds.
const SINCE_DB: &str = "serve_since";

/// The key in [`META_DB`] of the walks' state, as `--state` saves it.
const WALK_STATE: &str = "walk_state";

/// [`SINCE_DB`]: an address deferred since then.
const DEFERRED_TAG: u8 = b'd';

/// [`SINCE_DB`]: a listed address fewer than all of its nearest nodes have
/// served since then.
const BELOW_FULL_TAG: u8 = b'b';

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
    meta: Database<Str, Bytes>,
    since: Database<Bytes, U64<BigEndian>>,
    /// The walks' state after the latest published read.
    walk_state: WalkState,
    /// When this process started, in Unix seconds.
    started_at: u64,
    /// Counts since then.
    totals: Totals,
    /// When each node last answered, since this process started.
    last_answered: HashMap<PeerId, u64>,
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
        let meta: Database<Str, Bytes> = store.database(META_DB)?;
        let since: Database<Bytes, U64<BigEndian>> = store.database(SINCE_DB)?;
        let walk_state = {
            let txn = store.env().read_txn().map_err(store_error)?;
            // A state this version can't read starts afresh, as a deleted
            // `--state` file does.
            meta.get(&txn, WALK_STATE)
                .map_err(store_error)?
                .and_then(|bytes| serde_json::from_slice(bytes).ok())
                .unwrap_or_default()
        };
        Ok(Self {
            client,
            chain,
            store,
            census,
            publisher,
            meta,
            since,
            walk_state,
            started_at: unix_now(),
            totals: Totals::default(),
            last_answered: HashMap::new(),
        })
    }

    /// On a first start, while the store holds no index yet, take the
    /// entries of `previous`, an earlier `darwin listings --json` output
    /// (such as the `listings.json` the producer replaces), into the index
    /// as carried: published as they were, marked carried in their support,
    /// until a cycle decides their addresses or shows them no longer served.
    /// So nothing published is lost before the first cycles confirm it.
    /// Returns how many were taken: none, without reading `previous`, once
    /// the store holds an index, and none if `previous` doesn't exist.
    /// Entries that failed their checks (`"valid": false`) are not taken.
    ///
    /// # Errors
    ///
    /// If `previous` can't be read or isn't such an output, or the index
    /// can't be published.
    pub fn carry_from(&mut self, previous: &Path) -> Result<usize> {
        if self.publisher.seq() > 0 || self.publisher.count() > 0 {
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
            status: self.base_status(),
            ..Publication::default()
        };
        for (entry, support) in carried {
            publication.changes.push(IndexChange::Put(Box::new(entry)));
            publication.support.push(support);
        }
        self.publisher.publish(&publication)?;
        Ok(taken)
    }

    /// Run cycles until `cancel` fires: one every [`CYCLE`], the first at
    /// once. A cycle that fails is logged and the next one runs on time. On
    /// `cancel`, a cycle still reading the network is abandoned before it
    /// has written anything; one writing its changes finishes first.
    ///
    /// # Errors
    ///
    /// Only if the producer can't go on at all: when its store can't be
    /// read or written.
    pub async fn run(&mut self, cancel: CancellationToken) -> Result<()> {
        loop {
            let next = tokio::time::Instant::now() + CYCLE;
            // On the heap: an index read's future is too large for a main
            // thread's stack on some systems.
            let cycle = Box::pin(self.cycle());
            tokio::select! {
                () = cancel.cancelled() => return Ok(()),
                result = cycle => match result {
                    Ok(report) => log_cycle(&report),
                    Err(e @ Error::Storage(_)) => return Err(e),
                    Err(e) => warn!("A listings cycle failed: {e}"),
                },
            }
            tokio::select! {
                () = cancel.cancelled() => return Ok(()),
                () = tokio::time::sleep_until(next) => {}
            }
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
        let at = unix_now();
        let before = Counters::now(&self.chain);
        let mut walk_state = self.walk_state.clone();
        let read = Box::pin(
            self.client
                .index_listings_with(0, &self.chain, &mut walk_state),
        )
        .await;
        let index = match read {
            Ok(index) => index,
            Err(e) => {
                // No node found: nothing is decided or dropped, and the
                // status says so.
                warn!("The index read found no nodes: {e}");
                let status = self.status(at, clock, before, None, Tally::default());
                let publication = Publication {
                    at,
                    status,
                    ..Publication::default()
                };
                self.publisher.publish(&publication)?;
                return Ok(CycleReport {
                    status: self.published_status(publication.status),
                    put: 0,
                });
            }
        };
        let versions = self.versions(&index).await;
        let published = self.publisher.keys()?;
        let listed: BTreeMap<XorName, &CheckedListing> = index
            .listings
            .iter()
            .map(|checked| (checked.listing.address, checked))
            .collect();
        // Entries whose whole close group walked past them: each is removed
        // only once its nearest nodes, asked now, serve none.
        let mut gone = HashSet::new();
        for key in &published {
            if !listed.contains_key(&key.address)
                && index.carry(&key.address, key) == Carry::NoLongerServed
                && Box::pin(self.confirm_gone(&key.address, index.nodes_asked)).await
            {
                gone.insert(key.address);
            }
        }

        // Nothing below awaits: a cancelled cycle has written nothing.
        let mut tally = Tally {
            versions,
            ..Tally::default()
        };
        let mut publication = Publication {
            at,
            ..Publication::default()
        };
        for checked in &index.listings {
            let address = checked.listing.address;
            let fresh = ShardEntry::new(
                Entry::new(&checked.listing, checked.level, at),
                &checked.envelope,
            );
            let unchanged = self
                .publisher
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
            if self.publisher.support(&address)?.as_ref() != Some(&support) {
                publication.support.push(support);
            }
        }
        for key in &published {
            let address = key.address;
            if listed.contains_key(&address) {
                continue;
            }
            let reason = match index.carry(&address, key) {
                Carry::Decided => Some(RemoveReason::Rejected),
                Carry::NoLongerServed if gone.contains(&address) => {
                    Some(RemoveReason::NoLongerServed)
                }
                Carry::NoLongerServed | Carry::Keep => None,
            };
            if let Some(reason) = reason {
                publication
                    .changes
                    .push(IndexChange::Remove { address, reason });
                tally.removed += 1;
            } else {
                tally.carried += 1;
                if let Some(mut support) = self.publisher.support(&address)? {
                    if !support.carried {
                        support.carried = true;
                        publication.support.push(support);
                    }
                }
            }
        }
        if !index.too_few_nodes {
            publication.rejected = self.rejected_changes(&index, &listed, at, &mut tally)?;
        }
        tally.decided = listed.len() as u64 + tally.rejected_for_good;
        self.update_since(&index, &listed, &publication, at, &mut tally)?;
        publication.status = self.status(at, clock, before, Some(&index), tally.clone());
        self.publisher.publish(&publication)?;
        self.save_walk_state(&walk_state)?;
        self.walk_state = walk_state;
        Ok(CycleReport {
            status: self.published_status(publication.status),
            put: tally.put,
        })
    }

    /// The changes to `rejected.json` this read makes. Each address it
    /// rejected or deferred and didn't list gets its latest rejection or
    /// deferral (the first in index order), left as it was where only the
    /// time it was decided would change. A row is cleared once its address
    /// is listed, decided without a rejection, or walked past by its whole
    /// close group.
    fn rejected_changes(
        &self,
        index: &ListingsIndex,
        listed: &BTreeMap<XorName, &CheckedListing>,
        at: u64,
        tally: &mut Tally,
    ) -> Result<Vec<RejectedChange>> {
        let existing: HashMap<String, RejectedEntry> = self
            .publisher
            .rejected_entries()?
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
            let entry = RejectedEntry::new(rejected, copies, at);
            if rejected.again {
                let pending = index.pending_copies.contains_key(&address);
                tally
                    .deferred
                    .push((address, deferral_reason(&rejected.problem, pending)));
            } else {
                tally.rejected_for_good += 1;
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
            if seen.contains(&address) {
                continue;
            }
            let keep = !listed.contains_key(&address)
                && old
                    .listing
                    .key()
                    .is_some_and(|key| index.carry(&address, &key) == Carry::Keep);
            if !keep {
                changes.push(RejectedChange::Clear(address));
            }
        }
        Ok(changes)
    }

    /// Note since when each address has been deferred, and each listed one
    /// below full support, and count them into `tally`.
    fn update_since(
        &self,
        index: &ListingsIndex,
        listed: &BTreeMap<XorName, &CheckedListing>,
        publication: &Publication,
        at: u64,
        tally: &mut Tally,
    ) -> Result<()> {
        let mut txn = self.store.env().write_txn().map_err(store_error)?;
        if !index.too_few_nodes {
            let deferred: HashSet<XorName> =
                tally.deferred.iter().map(|(address, _)| *address).collect();
            let mut stale = Vec::new();
            for row in self
                .since
                .prefix_iter(&txn, &[DEFERRED_TAG])
                .map_err(store_error)?
            {
                let (key, _) = row.map_err(store_error)?;
                let address: Option<XorName> = key.get(1..).and_then(|a| a.try_into().ok());
                if address.is_none_or(|address| !deferred.contains(&address)) {
                    stale.push(key.to_vec());
                }
            }
            for key in stale {
                self.since.delete(&mut txn, &key).map_err(store_error)?;
            }
        }
        let mut groups: BTreeMap<&'static str, (u64, u64)> = BTreeMap::new();
        for (address, reason) in &tally.deferred {
            let row = tagged(DEFERRED_TAG, address);
            let since = if let Some(since) = self.since.get(&txn, &row).map_err(store_error)? {
                since
            } else {
                self.since.put(&mut txn, &row, &at).map_err(store_error)?;
                at
            };
            let group = groups.entry(reason).or_insert((0, since));
            group.0 += 1;
            group.1 = group.1.min(since);
        }
        if index.too_few_nodes && index.deferred > 0 {
            groups.insert("nodes_unanswered", (index.deferred as u64, at));
        }
        tally.deferred_groups = groups
            .into_iter()
            .map(|(reason, (addresses, oldest_since))| DeferredGroup {
                reason: reason.to_string(),
                addresses,
                oldest_since,
            })
            .collect();

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
        let mut below = BelowFull::default();
        for row in self
            .since
            .prefix_iter(&txn, &[BELOW_FULL_TAG])
            .map_err(store_error)?
        {
            let (_, since) = row.map_err(store_error)?;
            below.listings += 1;
            below.oldest_since = Some(below.oldest_since.map_or(since, |old| old.min(since)));
        }
        tally.below_full = below;
        txn.commit().map_err(store_error)?;
        Ok(())
    }

    /// Whether `address`, whose whole close group walked past it, is no
    /// longer served: every one of the nodes nearest it, looked up now,
    /// answers a `GetRequest` for it, and none serves a listing for it at any
    /// key.
    async fn confirm_gone(&self, address: &XorName, network_size: usize) -> bool {
        match self
            .client
            .listing_with(address, &self.chain, Some(network_size))
            .await
        {
            Ok(lookup) => {
                let gone = lookup.nearest >= NEAREST_NODES
                    && lookup.answered == lookup.nearest
                    && lookup.listing.is_none()
                    && lookup.rejected.is_empty();
                if !gone {
                    info!(
                        "Keeping {}: its nearest nodes walked past it, but {} of {} answered \
                         a lookup of it, and {} listings for it were served",
                        hex::encode(address),
                        lookup.answered,
                        lookup.nearest,
                        usize::from(lookup.listing.is_some()) + lookup.rejected.len()
                    );
                }
                gone
            }
            Err(e) => {
                warn!("Could not confirm {} is gone: {e}", hex::encode(address));
                false
            }
        }
    }

    /// How many of the nodes this read walked give each user agent; and note
    /// when those that answered did.
    async fn versions(&mut self, index: &ListingsIndex) -> Vec<VersionCount> {
        let mut counts: BTreeMap<Option<String>, u64> = BTreeMap::new();
        let now = unix_now();
        for walk in &index.walks {
            if walk.pages > 0 {
                self.last_answered.insert(walk.peer, now);
            }
            let agent = self.client.network().peer_user_agent(&walk.peer).await;
            *counts.entry(agent).or_default() += 1;
        }
        counts
            .into_iter()
            .map(|(version, nodes)| VersionCount { version, nodes })
            .collect()
    }

    /// `status.json` for the cycle that began at `at` (`clock`), with what
    /// `index` read, if anything. The publisher fills in the feed's fields.
    fn status(
        &mut self,
        at: u64,
        clock: std::time::Instant,
        before: Counters,
        index: Option<&ListingsIndex>,
        tally: Tally,
    ) -> Status {
        let after = Counters::now(&self.chain);
        let cycle = CycleStatus {
            started_at: at,
            millis: u64::try_from(clock.elapsed().as_millis()).unwrap_or(u64::MAX),
            bytes_in: after.bytes_in.saturating_sub(before.bytes_in),
            bytes_out: after.bytes_out.saturating_sub(before.bytes_out),
            rpc_calls: after.rpc_calls.saturating_sub(before.rpc_calls),
            rpc_errors: after.rpc_errors.saturating_sub(before.rpc_errors),
            decided: tally.decided,
            too_few_answered: index.is_none_or(|index| index.too_few_nodes),
        };
        self.totals.cycles += 1;
        self.totals.bytes_in += cycle.bytes_in;
        self.totals.bytes_out += cycle.bytes_out;
        self.totals.rpc = self.chain.rpc_calls();
        let census = match index {
            Some(index) => CensusStatus {
                nodes: index.nodes_asked as u64,
                answering: index.nodes_answered as u64,
                // Every node is asked about the whole address space.
                leaves: 1,
                versions: tally.versions,
                silent: index
                    .walks
                    .iter()
                    .filter(|walk| walk.pages == 0)
                    .map(|walk| SilentNode {
                        node: hex::encode(walk.peer.as_bytes()),
                        last_answered: self.last_answered.get(&walk.peer).copied(),
                    })
                    .collect(),
            },
            None => CensusStatus::default(),
        };
        Status {
            cycle,
            census,
            deferred: tally.deferred_groups,
            below_full: tally.below_full,
            drops: Drops {
                removed: tally.removed,
                carried: tally.carried,
            },
            ..self.base_status()
        }
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

    /// Keep `state`, the walks' state after a published read.
    fn save_walk_state(&self, state: &WalkState) -> Result<()> {
        let bytes = serde_json::to_vec(state)
            .map_err(|e| Error::Serialization(format!("walk state: {e}")))?;
        let mut txn = self.store.env().write_txn().map_err(store_error)?;
        self.meta
            .put(&mut txn, WALK_STATE, &bytes)
            .map_err(store_error)?;
        txn.commit().map_err(store_error)
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

/// What a cycle counted, for `status.json`.
#[derive(Debug, Clone, Default)]
struct Tally {
    put: u64,
    removed: u64,
    carried: u64,
    decided: u64,
    rejected_for_good: u64,
    /// Each address deferred, with its reason's code.
    deferred: Vec<(XorName, &'static str)>,
    deferred_groups: Vec<DeferredGroup>,
    below_full: BelowFull,
    versions: Vec<VersionCount>,
}

/// Log what a cycle did.
fn log_cycle(report: &CycleReport) {
    let status = &report.status;
    info!(
        "Listings cycle: {} of {} nodes answered, {} decided, {} put, {} removed, {} carried, \
         {} entries (seq {}), {} ms, {} B in, {} B out, {} RPC calls",
        status.census.answering,
        status.census.nodes,
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
    );
}

/// Whether `fresh` is `old` decided again: the same apart from when.
fn same_entry(old: &ShardEntry, fresh: &ShardEntry) -> bool {
    old.entry.listing == fresh.entry.listing
        && old.entry.check == fresh.entry.check
        && old.data_map == fresh.data_map
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

/// This process's resident memory, in bytes, where the system says.
fn rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    kib.checked_mul(1024)
}

/// The entries of `bytes`, an earlier `darwin listings --json` output, that
/// passed their checks: each as published, decided at `at`, with its support
/// marked carried.
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
        if entry.get("valid").and_then(Value::as_bool) != Some(true) {
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
    use ant_listings::CheckLevel;

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
        let bytes = format!("[{},{rejected}]", printed(r#","time":1791321603"#));
        let taken = previous_entries(bytes.as_bytes(), 100).unwrap();
        assert_eq!(
            taken.len(),
            1,
            "an entry that failed its checks isn't taken"
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
}
