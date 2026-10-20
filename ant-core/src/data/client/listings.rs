//! Reading the listings index, and checking listings and upload proofs.
//!
//! Nodes that support listings answer requests on [`ant_listings::TOPIC`]
//! (`listings.v2`). A listing shows only the payment fields its uploader
//! chose, so it is checked as far as they allow:
//!
//! - one that shows its quote is checked against the chain, tied to its
//!   address, and is [`CheckLevel::Verified`];
//! - one that hides it is [`CheckLevel::Reported`]: its shown fields are
//!   checked against the chain, and it counts only when a quorum of the
//!   nodes nearest its address serve it.
//!
//! Either way, where the reader knows when the payment vault was deployed,
//! a listing showing a block or block timestamp from before then is refused
//! without reading the chain, and so is one showing none of those and its
//! transaction that a quorum of those nodes date long enough before the
//! vault's first payment, or its deployment where that isn't known
//! ([`ListingChain::with_vault_first_payment_time`]).
//!
//! Each node records its own `first_seen` for a listing in the index that
//! hides its time, so copies are merged across nodes
//! ([`ant_listings::merge_copies`]) and dated as the nodes date them
//! ([`check_copies`]): only the values of the nodes nearest the address
//! count, each checked on its own first. Where a quorum of them pass, the
//! listing is dated so that a quorum of them date it then or earlier
//! ([`quorum_listing`]'s date, where every value passes); where fewer pass,
//! by the latest that does. So nodes fewer than a quorum can't move its date
//! earlier, however few others answer.
//!
//! [`Client::index_listings`] reads the whole index; [`Client::listing`]
//! reads one listing, in the index or not. [`ListingChain`] reads payments
//! from the chain, for these and for upload proofs
//! ([`ListingChain::check_proof`]).
//!
//! A node's pages are only shape-checked, so a node can serve as many
//! made-up listings as it likes. An index read therefore walks every node
//! with [`IndexWalk`], which reads each node for as long as other nodes back
//! what it sends, and does work for an address (fetching its envelope,
//! asking nodes, reading the chain) only where at least
//! [`QUORUM_THRESHOLD`] of the [`NEAREST_NODES`] nodes nearest it serve a
//! listing for it. Listings fewer nodes serve cost nothing but their pages,
//! and wait for a later read, so no fixed number limits the index. A walk
//! stopped early carries on in the next read ([`WalkState`]), and a read
//! never says a listing it didn't decide is gone ([`ListingsIndex::carry`]).

use crate::data::client::listings_facts::{Facts, Keep, Known, VaultLog, FINALIZED_REFRESH};
use crate::data::client::listings_rpc::{Answer, Call, Kind, Rpc};
use crate::data::client::listings_store::ListingsStore;
use crate::data::client::listings_v1::RpcCalls;
use crate::data::client::occupied::VaultRecord;
use crate::data::client::Client;
use crate::data::error::{Error, Result};
#[cfg(doc)]
use ant_listings::choose_verified;
pub use ant_listings::{check_copies, listing_to_check, quorum_listing};
use ant_listings::{
    check_get_response, check_offline, merge_copies, nearest_by_distance, payment_lookup,
    push_request_id, quorum_needed, verify_listing_receipts, AddressWalk, ChangesResponse,
    CheckLevel, Envelope, EnvelopeProof, IndexWalk, Listing, ListingCheck, ListingKey,
    ListingPayment, ListingsBody, ListingsMessage, Lookup, MergedListing, NodeReport, PaidAt,
    PaymentError, PaymentLog, PaymentReceipt, ProvenUpload, WalkOutcome, WalkResult, CLOCK_MARGIN,
    DATA_PAYMENT_MADE_TOPIC, FIRST_SEEN_ROUNDING, MAX_LIST_LIMIT, QUORUM_THRESHOLD, TOPIC,
    WALK_FREE_LISTINGS, WATCH_LEASE,
};
use ant_protocol::evm::{Amount, Network as EvmNetwork, QuoteHash};
use ant_protocol::transport::{MultiAddr, P2PEvent, P2PNode, PeerId};
use ant_protocol::{XorName, CLOSE_GROUP_SIZE};
use futures::stream::{self, FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::oneshot;
use tokio::time::Instant;
use tracing::debug;

/// How long to wait for a node to answer a listings request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Random lookups made to find nodes beyond those in the routing table.
const CRAWL_LOOKUPS: usize = 8;

/// Nodes asked for per lookup.
const CRAWL_WIDTH: usize = 20;

/// How long the lookups that find nodes to walk may take.
const CRAWL_TIMEOUT: Duration = Duration::from_secs(30);

/// Requests in flight at once, to different nodes. A node that doesn't
/// answer (an older one, or one that is down) costs one request timeout,
/// paid alongside the others.
const PEER_CONCURRENCY: usize = 64;

/// Addresses decided at once. Each fetches its envelope from the nodes that
/// served it and reads the payment from the chain.
pub(crate) const CHECK_CONCURRENCY: usize = 8;

/// The walk phase of a read lasts at most this, or [`WALK_PHASE_FACTOR`]
/// times as long as half the walks took, whichever is longer: a node that
/// stalls can't hold a read open, and walks it stops carry on in the next
/// read.
const WALK_PHASE_MIN: Duration = Duration::from_secs(60);

/// See [`WALK_PHASE_MIN`].
const WALK_PHASE_FACTOR: u32 = 4;

/// The longest the walk phase lasts however the walks go.
const WALK_PHASE_MAX: Duration = Duration::from_secs(30 * 60);

/// How long to wait for one node to hand over an envelope before asking the
/// next node that served its listing too.
const ENVELOPE_HEDGE: Duration = Duration::from_secs(1);

/// How many recent reads' node counts [`WalkState`] keeps: a read that finds
/// far fewer nodes than recent ones decides nothing.
const RECENT_READS: usize = 10;

/// How many nodes nearest an address count for its listing.
pub const NEAREST_NODES: usize = CLOSE_GROUP_SIZE;

/// The fewest blocks one `eth_getLogs` call is narrowed to when the chain
/// refuses a wider range.
const MIN_LOG_RANGE: u64 = 64;

/// The most `eth_getLogs` calls one search for a quote's payment makes.
const MAX_LOG_CALLS: usize = 64;

/// The fewest blocks each `eth_getLogs` call covers when a search for a
/// quote's payment looks back from the quote's time, unless the chain
/// already refused a wider range.
const BACK_LOG_RANGE: u64 = 10_000;

/// What one lookup on the chain found: each receipt with its block's
/// timestamp, as [`ant_listings::verify_listing_receipts`] takes them.
pub type Fetched = Vec<(Option<PaymentReceipt>, Option<u64>)>;

/// How one node's walk went in an index read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalkReport {
    /// The node.
    pub peer: PeerId,
    /// How the walk ended.
    pub outcome: WalkOutcome,
    /// Why a page was refused, for [`WalkOutcome::BadPage`].
    pub problem: Option<String>,
    /// Pages the node answered.
    pub pages: usize,
    /// Listings those pages held.
    pub listings: usize,
    /// Listings it sent whose addresses a quorum of their nearest nodes
    /// serve, which earn it more pages.
    pub backed: usize,
    /// Where the next read carries on this node's walk, for a walk stopped
    /// before the end.
    pub resume: Option<ListingKey>,
}

impl From<&NodeReport<PeerId>> for WalkReport {
    fn from(report: &NodeReport<PeerId>) -> Self {
        Self {
            peer: report.peer,
            outcome: report.outcome,
            problem: report.problem.clone(),
            pages: report.pages,
            listings: report.listings,
            backed: report.backed,
            resume: report.resume(),
        }
    }
}

/// What index reads keep from one read to the next: where to carry on walks
/// that stopped early, and how many nodes recent reads found. Save it
/// between reads (it serialises) and pass it to
/// [`Client::index_listings_with`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalkState {
    /// Where to carry on each node's walk: the node's id and the key, each
    /// as hex.
    #[serde(default)]
    resume: BTreeMap<String, String>,
    /// How many nodes each recent read found, the latest last.
    #[serde(default)]
    recent_nodes: Vec<usize>,
}

impl WalkState {
    /// Where to carry on `peer`'s walk, if its last walk stopped early.
    fn resume_for(&self, peer: &PeerId) -> Option<ListingKey> {
        let key = self.resume.get(&hex::encode(peer.as_bytes()))?;
        ListingKey::from_bytes(&hex::decode(key).ok()?)
    }

    /// The most nodes a recent read found.
    fn recent_max(&self) -> usize {
        self.recent_nodes.iter().copied().max().unwrap_or(0)
    }

    /// Note a read: how many nodes it found, and where each walk carries on.
    /// Only the nodes this read walked are kept: one that is back after a
    /// read without it is walked from the start.
    fn record(&mut self, nodes: usize, walks: &[WalkReport]) {
        self.recent_nodes.push(nodes);
        let excess = self.recent_nodes.len().saturating_sub(RECENT_READS);
        self.recent_nodes.drain(..excess);
        self.resume = walks
            .iter()
            .filter_map(|walk| {
                let key = walk.resume?;
                Some((
                    hex::encode(walk.peer.as_bytes()),
                    hex::encode(key.to_bytes()),
                ))
            })
            .collect();
    }

    /// The nodes whose walks carry on in the next read.
    #[must_use]
    pub fn resuming(&self) -> usize {
        self.resume.len()
    }
}

/// What to do with a listing published from an earlier read, given this one
/// ([`ListingsIndex::carry`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Carry {
    /// This read decided its address: publish what it found instead, the
    /// listing it lists or nothing if it rejected the address.
    Decided,
    /// This read didn't decide its address: keep the entry as it is.
    Keep,
    /// Every node nearest its address walked past where it would be, late
    /// enough to have stored it, without serving it: the network no longer
    /// stores its file. Drop the entry. The payment stays on chain, and the
    /// uploader's proof still proves it.
    NoLongerServed,
}

/// What a read covered, for [`ListingsIndex::carry`].
#[derive(Debug, Clone, Default)]
struct Coverage {
    /// The time the read took listings from (Unix seconds, 0 for the whole
    /// index): its walks began at [`walk_start`] of it.
    since: u64,
    /// Each node walked, as [`IndexWalk`] gave them.
    walks: Vec<NodeReport<PeerId>>,
    /// The nodes' ids, in the same order.
    ids: Vec<[u8; 32]>,
    /// Addresses at least one of their nearest nodes served.
    served: HashSet<XorName>,
    /// Addresses this read decided.
    decided: HashSet<XorName>,
    /// Addresses shown to be no longer served by other means than this
    /// read's walks ([`ListingsIndex::decided`]).
    gone: HashSet<XorName>,
}

/// A listing that passed its checks.
#[derive(Debug, Clone)]
pub struct CheckedListing {
    /// The listing, with `first_seen` (if it has one) set by the nearest
    /// nodes' values as [`check_copies`] sets it.
    pub listing: Listing,
    /// The envelope at the listing's address.
    pub envelope: Envelope,
    /// How far the payment was checked.
    pub level: CheckLevel,
    /// How many of the nodes nearest the address serve this listing.
    pub nodes: usize,
    /// How many nearest nodes were considered: [`NEAREST_NODES`] unless the
    /// network is smaller.
    pub nearest: usize,
    /// Whether `nodes` reaches [`ant_listings::quorum_needed`] of the nearest
    /// nodes there should be ([`expected_nearest`]), however many a lookup
    /// found. Always true for a reported listing (it is dropped otherwise). A verified listing
    /// without one is the earliest of several payments for its address, none
    /// of which a quorum serves: a node asked to quote could have paid first.
    pub quorum: bool,
}

/// A listing that failed its checks, with why.
#[derive(Debug, Clone)]
pub struct RejectedListing {
    /// The listing as the nearest nodes (or any node) sent it.
    pub listing: Listing,
    /// Why it doesn't count.
    pub problem: String,
    /// How many of the nodes nearest its address serve it.
    pub nodes: usize,
    /// How many nearest nodes were considered, as for a
    /// [`CheckedListing`]: [`NEAREST_NODES`] unless the network is smaller
    /// or the lookup came back short.
    pub nearest: usize,
    /// Whether nothing final was decided, so a later read may list it: too
    /// few of its nearest nodes serve it yet, or the chain or its nodes
    /// couldn't be read.
    pub again: bool,
}

/// One node's copy of the listing for an address fewer than a quorum of its
/// nearest nodes serve yet ([`ListingsIndex::pending_copies`]): what it
/// shows of when the listing was paid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCopy {
    /// The node, one of those nearest the address.
    pub node: PeerId,
    /// The payment's block, if the copy shows it.
    pub block_number: Option<u64>,
    /// The payment's block timestamp, if the copy shows it.
    pub block_timestamp: Option<u64>,
    /// When the node first saw the listing, rounded down to the hour: for a
    /// listing in the index that hides its block timestamp.
    pub first_seen: Option<u64>,
    /// Whether the block it shows is earlier than the one the payment vault
    /// was deployed in ([`ListingChain::before_vault_deployment`]), or the
    /// block timestamp it shows is earlier than that block's
    /// ([`ListingChain::timed_before_vault_deployment`]): nothing in it paid
    /// the vault, so the copy can never check out. `first_seen` never sets
    /// it: one node's date isn't the date a quorum of the nearest nodes
    /// give.
    pub before_vault_deployment: bool,
}

impl PendingCopy {
    /// `node`'s copy `listing`, its block and block timestamp checked
    /// against `chain`'s vault.
    fn new(node: PeerId, listing: &Listing, chain: &ListingChain) -> Self {
        let payment = &listing.payment;
        Self {
            node,
            block_number: payment.block_number,
            block_timestamp: payment.block_timestamp,
            first_seen: listing.first_seen,
            before_vault_deployment: payment
                .block_number
                .is_some_and(|block| chain.before_vault_deployment(block))
                || payment
                    .block_timestamp
                    .is_some_and(|time| chain.timed_before_vault_deployment(time)),
        }
    }

    /// The time the copy sorts by, as [`Listing::key`] takes it: the block
    /// timestamp, else `first_seen`, else 0.
    #[must_use]
    pub fn time(&self) -> u64 {
        self.block_timestamp.or(self.first_seen).unwrap_or(0)
    }
}

/// The index as read from the network.
#[derive(Debug, Clone, Default)]
pub struct ListingsIndex {
    /// Listings that passed their checks, in index order.
    pub listings: Vec<CheckedListing>,
    /// Listings that didn't, in index order. Those [`RejectedListing::again`]
    /// marks may still count.
    pub rejected: Vec<RejectedListing>,
    /// Nodes asked for their index.
    pub nodes_asked: usize,
    /// Nodes that answered.
    pub nodes_answered: usize,
    /// Each node's walk.
    pub walks: Vec<WalkReport>,
    /// Addresses this read left undecided: fewer than a quorum of their
    /// nearest nodes served them, or something couldn't be read. A later
    /// read decides them.
    pub deferred: usize,
    /// For each address fewer than a quorum of its nearest nodes served,
    /// every copy those nodes served, nearest node first. Each such address
    /// has its entry in `rejected`, to try again.
    pub pending_copies: BTreeMap<XorName, Vec<PendingCopy>>,
    /// Whether the read found too few nodes to trust its view of the network
    /// (fewer than [`NEAREST_NODES`], or under three quarters as many as
    /// recent reads found), and so decided nothing.
    pub too_few_nodes: bool,
    coverage: Coverage,
}

impl ListingsIndex {
    /// What to do with a listing at `address`, with index key `key`,
    /// published from an earlier read: replace it with what this read
    /// decided, keep it, or drop it because the network no longer stores its
    /// file. Only the whole close group, walked past it in a read of the
    /// whole index, says a listing is gone; a read that didn't decide an
    /// address otherwise keeps it, however few nodes answered, so publishing
    /// what it decided over what was published loses nothing.
    #[must_use]
    pub fn carry(&self, address: &XorName, key: &ListingKey) -> Carry {
        let coverage = &self.coverage;
        if coverage.decided.contains(address) {
            return Carry::Decided;
        }
        if coverage.gone.contains(address) {
            return Carry::NoLongerServed;
        }
        // A read from a time walked no node's index before `walk_start` of
        // it, and a node keys a listing that hides its time by its own date:
        // up to three of the nearest can date it well before the one
        // published, the latest of the earliest four. Such a read can't tell
        // a node that keys the listing earlier from one that doesn't serve
        // it.
        if self.too_few_nodes
            || coverage.since > 0
            || coverage.served.contains(address)
            || coverage.ids.len() < NEAREST_NODES
        {
            return Carry::Keep;
        }
        // A node that stored the listing when the quorum did keys it by its
        // own date, up to this much earlier than the one published.
        let lookback = FIRST_SEEN_ROUNDING + CLOCK_MARGIN;
        let earliest = ListingKey {
            time: key.time.saturating_sub(lookback),
            ..ListingKey::MIN
        };
        let stored_by = key.time.saturating_add(lookback);
        let gone = nearest_by_distance(address, &coverage.ids, NEAREST_NODES)
            .into_iter()
            .all(|node| {
                let walk = &coverage.walks[node];
                walk.covered(&earliest)
                    && walk.covered(key)
                    && walk.began.is_some_and(|began| began >= stored_by)
            });
        if gone {
            Carry::NoLongerServed
        } else {
            Carry::Keep
        }
    }

    /// The index of what was decided outside an index read, as the listings
    /// producer decides it from its census and its mirrors of the nodes'
    /// indexes: `pending`, addresses fewer than a quorum of their nearest
    /// nodes serve, left for later as a read leaves them; `decisions`, what
    /// [`Client::decide_backed`] decided for the others; and `gone`,
    /// addresses shown to be no longer served ([`Self::carry`] says
    /// [`Carry::NoLongerServed`] for them). Every other address is left as it
    /// was ([`Carry::Keep`]).
    #[cfg(test)]
    pub(crate) fn decided(
        pending: &[AddressWalk<PeerId>],
        decisions: Vec<Decision>,
        gone: HashSet<XorName>,
        chain: &ListingChain,
    ) -> Self {
        let mut index = Self::default();
        index.defer(pending, chain);
        index.finish_decided(decisions, gone);
        index
    }

    /// Leave `pending` for later in an index decided outside an index read,
    /// as [`Self::decided`] does: one batch of addresses at a time, before
    /// [`Self::finish_decided`].
    pub(crate) fn defer(&mut self, pending: &[AddressWalk<PeerId>], chain: &ListingChain) {
        self.defer_pending(pending, chain);
    }

    /// Take in `decisions` and `gone` into an index decided outside an index
    /// read, as [`Self::decided`] does, once every batch is deferred
    /// ([`Self::defer`]).
    pub(crate) fn finish_decided(&mut self, decisions: Vec<Decision>, gone: HashSet<XorName>) {
        self.coverage.gone = gone;
        self.settle(decisions);
    }

    /// Whether this index decided `address`: listed it, or rejected it for
    /// good.
    pub(crate) fn was_decided(&self, address: &XorName) -> bool {
        self.coverage.decided.contains(address)
    }

    /// The index of a cycle in which too few nodes answered to decide
    /// anything: `deferred` addresses left for later, every earlier entry
    /// kept ([`Self::carry`]).
    pub(crate) fn too_few(deferred: usize) -> Self {
        Self {
            deferred,
            too_few_nodes: true,
            ..Self::default()
        }
    }

    /// Leave `pending`, addresses fewer than a quorum of their nearest nodes
    /// serve, for a later read. Each is shown in `rejected`, to try again,
    /// with every copy those nodes served in `pending_copies`, its block and
    /// block timestamp checked against `chain`'s vault: an address a single
    /// node serves can be as stuck as one three serve, and the copies show
    /// what keeps it from counting.
    fn defer_pending(&mut self, pending: &[AddressWalk<PeerId>], chain: &ListingChain) {
        self.deferred += pending.len();
        for found in pending {
            if let Some(shown) = pending_listing(found) {
                self.rejected.push(shown);
                self.pending_copies
                    .insert(found.address, pending_copies(found, chain));
            }
        }
    }

    /// Take in what this read decided for each address it worked on, then
    /// keep the listings and rejections from the read's `since` on, in index
    /// order.
    ///
    /// A listing this read dated before `since` is left out, and so its
    /// address doesn't count as decided ([`Self::carry`]): the read says
    /// nothing about listings before `since`, so an entry an earlier read
    /// published for the address is kept, not dropped for one this read
    /// leaves out. An address rejected for good stays decided.
    fn settle(&mut self, decisions: Vec<Decision>) {
        let since = self.coverage.since;
        for decision in decisions {
            if decision.decided {
                self.coverage.decided.insert(decision.address);
            } else {
                self.deferred += 1;
            }
            self.listings.extend(decision.listing);
            self.rejected.extend(decision.rejected);
        }
        let decided = &mut self.coverage.decided;
        self.listings.retain(|checked| {
            let kept = checked.listing.key().time >= since;
            if !kept {
                decided.remove(&checked.listing.address);
            }
            kept
        });
        let pending_copies = &mut self.pending_copies;
        self.rejected.retain(|rejected| {
            let kept = since == 0 || rejected.listing.key().time >= since;
            if !kept {
                pending_copies.remove(&rejected.listing.address);
            }
            kept
        });
        self.listings.sort_by_key(|checked| checked.listing.key());
        self.rejected.sort_by_key(|rejected| rejected.listing.key());
    }
}

/// One address's listing, as the nodes nearest it serve it.
#[derive(Debug, Clone, Default)]
pub struct ListingLookup {
    /// The listing, if one passed its checks.
    pub listing: Option<CheckedListing>,
    /// Listings for the address that didn't.
    pub rejected: Vec<RejectedListing>,
    /// Nodes asked: the nodes nearest the address.
    pub nearest: usize,
    /// How many of them answered.
    pub answered: usize,
}

/// The hash of a listing's paid quote (the msgpack quote a listing or proof
/// carries): what the vault's `DataPaymentMade` event names in its fourth
/// topic. `None` if the bytes aren't a quote.
#[must_use]
pub fn paid_quote_hash(quote: &[u8]) -> Option<[u8; 32]> {
    rmp_serde::from_slice::<ant_protocol::evm::PaymentQuote>(quote)
        .ok()
        .map(|quote| quote.hash().0)
}

/// Unix seconds now.
pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// Where to start walking nodes' indexes for listings from time `since`:
/// a node keys a listing that hides its time by its own `first_seen`, which
/// can be earlier than the merged one by up to `FIRST_SEEN_ROUNDING +
/// CLOCK_MARGIN`.
#[must_use]
pub fn walk_start(since: u64) -> ListingKey {
    if since == 0 {
        return ListingKey::MIN;
    }
    ListingKey {
        time: since.saturating_sub(FIRST_SEEN_ROUNDING + CLOCK_MARGIN),
        ..ListingKey::MIN
    }
}

/// The listing that counts for an address: the listing, its check level, how
/// many of the nearest nodes serve it, and whether that is a quorum.
pub type CountingListing = (Listing, CheckLevel, usize, bool);

/// Groups of copies that don't count: each one's index and why.
pub type RejectedGroups = Vec<(usize, String)>;

/// Why a group of copies didn't check out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckProblem {
    /// It doesn't check out, or can't whatever the chain says.
    Invalid(String),
    /// The payment chain couldn't be read for it: it may check out later.
    ChainUnread(String),
}

impl fmt::Display for CheckProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(problem) => f.write_str(problem),
            Self::ChainUnread(e) => write!(f, "could not read the payment chain: {e}; try again"),
        }
    }
}

impl From<PaymentError> for CheckProblem {
    fn from(error: PaymentError) -> Self {
        Self::Invalid(error.to_string())
    }
}

/// How many nodes nearest an address there should be on a network of
/// `network_size` known nodes: [`NEAREST_NODES`], or all of them on a
/// smaller network.
#[must_use]
pub fn expected_nearest(network_size: usize) -> usize {
    NEAREST_NODES.min(network_size)
}

/// How many nodes nearest an address there should be on a network of
/// `network_size` nodes, as a caller of [`Client::listing_with`] gives it:
/// [`NEAREST_NODES`], for a size of at least that. A smaller size, or none,
/// is `None`, and the size is then found as [`Client::listing`] finds it: a
/// size given too small would let a lookup of the address that comes back
/// short lower the quorum.
fn expected_nearest_given(network_size: Option<usize>) -> Option<usize> {
    network_size
        .filter(|size| *size >= NEAREST_NODES)
        .map(expected_nearest)
}

/// Decide which groups of copies for one address count, from each group's
/// check against the chain (`checked`, in the same order as `groups`; see
/// [`check_copies`]).
///
/// `expected` is how many nodes nearest the address there should be
/// ([`expected_nearest`]); `nearest` is those a lookup found. The quorum is
/// [`quorum_needed`] of `expected`, so a lookup that comes back short never
/// lowers it.
///
/// Of the verified groups, the one a quorum of `nearest` serve counts, else
/// the earliest paid, marked as without a quorum (as [`choose_verified`]
/// decides). A reported group counts when at least a quorum of `nearest`
/// serve it; of several, the one most serve. Every other group is rejected,
/// with why; a reported group short of a quorum because the lookup found too
/// few nearest nodes is rejected as worth trying again.
///
/// If the chain couldn't be read for a group a quorum serves, nothing
/// counts: as a node does, the others are not decided on without it, so a
/// failed read can't let a copy that fewer nodes serve stand in.
pub fn decide_address<P: PartialEq>(
    groups: &[MergedListing<P>],
    checked: Vec<std::result::Result<(Listing, ListingCheck), CheckProblem>>,
    nearest: &[P],
    expected: usize,
) -> (Option<CountingListing>, RejectedGroups) {
    let expected = expected.max(nearest.len());
    let needed = quorum_needed(expected);
    let quorum_unread = groups.iter().zip(&checked).any(|(group, result)| {
        matches!(result, Err(CheckProblem::ChainUnread(_))) && group.count_among(nearest) >= needed
    });
    if quorum_unread {
        let rejected = checked
            .into_iter()
            .enumerate()
            .map(|(index, result)| match result {
                Err(problem) => (index, problem.to_string()),
                Ok(_) => (
                    index,
                    "not decided: the payment chain could not be read for the listing a \
                     quorum of the nearest nodes serve; try again"
                        .into(),
                ),
            })
            .collect();
        return (None, rejected);
    }
    let mut rejected = Vec::new();
    let mut verified = Vec::new();
    let mut reported = Vec::new();
    for (index, (group, result)) in groups.iter().zip(checked).enumerate() {
        match result {
            Err(problem) => rejected.push((index, problem.to_string())),
            Ok((listing, check)) => {
                let count = group.count_among(nearest);
                match (check.level, check.paid_at) {
                    (CheckLevel::Verified, Some(paid_at)) => {
                        verified.push(((index, listing), count, paid_at));
                    }
                    (CheckLevel::Verified, None) => {
                        rejected.push((index, "verified without where its quote was paid".into()))
                    }
                    (CheckLevel::Reported, _) if count >= needed => {
                        reported.push((index, listing, count));
                    }
                    (CheckLevel::Reported, _) if nearest.len() < expected => rejected.push((
                        index,
                        format!(
                            "too few nearest nodes found: {} of the {expected} nodes nearest \
                             its address, {count} of them serving it, needs {needed}; try again",
                            nearest.len()
                        ),
                    )),
                    (CheckLevel::Reported, _) => rejected.push((
                        index,
                        format!(
                            "reported by {count} of the {} nodes nearest its address, \
                             needs {needed}",
                            nearest.len()
                        ),
                    )),
                }
            }
        }
    }
    let verified_indexes: Vec<usize> = verified.iter().map(|((index, _), _, _)| *index).collect();
    if let Some(((chosen_index, listing), count, _, quorum)) =
        choose_verified_with_quorum(verified, needed)
    {
        for index in verified_indexes {
            if index != chosen_index {
                rejected.push((
                    index,
                    "another payment for this address is the one that counts".into(),
                ));
            }
        }
        for (index, _, _) in reported {
            rejected.push((index, "a verified listing for this address counts".into()));
        }
        rejected.sort_by_key(|(index, _)| *index);
        return (
            Some((listing, CheckLevel::Verified, count, quorum)),
            rejected,
        );
    }
    // Disjoint groups can't both reach a quorum of the same nodes, but keep
    // the one most serve if they somehow do.
    reported.sort_by_key(|(index, _, count)| (std::cmp::Reverse(*count), *index));
    let mut reported = reported.into_iter();
    let best = reported
        .next()
        .map(|(_, listing, count)| (listing, CheckLevel::Reported, count, true));
    for (index, _, _) in reported {
        rejected.push((index, "another listing for this address counts".into()));
    }
    rejected.sort_by_key(|(index, _)| *index);
    (best, rejected)
}

/// Of verified candidates (the item, how many nearest nodes serve it, where
/// its quote was paid), the one that counts, with whether it has a quorum:
/// the earliest paid of those at least `needed` nearest nodes serve, else the
/// earliest paid of all. The first on a tie.
///
/// [`choose_verified`] decides the same, with the quorum taken from how many
/// nearest nodes a lookup found; this takes it from how many there should be
/// ([`decide_address`]), so a lookup that comes back short can't lower it.
fn choose_verified_with_quorum<T>(
    candidates: Vec<(T, usize, PaidAt)>,
    needed: usize,
) -> Option<(T, usize, PaidAt, bool)> {
    let quorum = candidates.iter().any(|(_, count, _)| *count >= needed);
    let mut chosen: Option<(T, usize, PaidAt)> = None;
    for (item, count, paid_at) in candidates {
        if quorum && count < needed {
            continue;
        }
        if chosen
            .as_ref()
            .is_none_or(|(_, _, earliest)| paid_at < *earliest)
        {
            chosen = Some((item, count, paid_at));
        }
    }
    chosen.map(|(item, count, paid_at)| (item, count, paid_at, quorum))
}

/// The nearest nodes to ask for an address's listing before deciding it.
/// None if a group of copies already has a quorum of `nearest` (`needed`):
/// that group decides, and no other can reach one. Otherwise, for each
/// group, those of `nearest` that didn't serve it, aren't in `heard` (they
/// sent a copy for the address, or were asked for it) and whose walk doesn't
/// answer for it ([`MergedListing::unheard_among`]). This holds whether or
/// not the listing shows its quote: which of several payments counts, and a
/// listing's date, rest on a quorum of the nearest nodes as well.
fn peers_to_ask<P: Eq + std::hash::Hash + Copy>(
    groups: &[MergedListing<P>],
    nearest: &[P],
    needed: usize,
    heard: &HashSet<P>,
    walked: &HashMap<P, u64>,
) -> Vec<P> {
    if groups
        .iter()
        .any(|group| group.count_among(nearest) >= needed)
    {
        return Vec::new();
    }
    let mut to_ask = Vec::new();
    for group in groups {
        for peer in group.unheard_among(
            nearest,
            |peer| heard.contains(peer),
            |peer| walked.get(peer).copied(),
        ) {
            if !to_ask.contains(peer) {
                to_ask.push(*peer);
            }
        }
    }
    to_ask
}

impl Client {
    /// The index: every node's listings from time `since` on (Unix seconds,
    /// 0 for all), merged across nodes, each checked, in index order. Starts
    /// afresh: [`Self::index_listings_with`] carries walks on from earlier
    /// reads.
    ///
    /// # Errors
    ///
    /// Returns an error only if no node can be found.
    pub async fn index_listings(&self, since: u64, chain: &ListingChain) -> Result<ListingsIndex> {
        self.index_listings_with(since, chain, &mut WalkState::default())
            .await
    }

    /// The index, as [`Self::index_listings`], carrying on from `state`:
    /// walks the last read stopped early carry on where they stopped, and a
    /// read that finds far fewer nodes than recent ones decides nothing.
    /// `state` is updated for the next read.
    ///
    /// The read walks every node it can find ([`IndexWalk`]), then decides
    /// each address that at least [`QUORUM_THRESHOLD`] of the
    /// [`NEAREST_NODES`] nodes nearest it serve: it fetches the envelope from
    /// those nodes, checks the listing a quorum of them serve first, and asks
    /// nearest nodes it hasn't heard from only where no listing has a
    /// quorum. Addresses fewer nodes serve cost nothing, and wait for a later
    /// read.
    ///
    /// # Errors
    ///
    /// Returns an error only if no node can be found.
    pub async fn index_listings_with(
        &self,
        since: u64,
        chain: &ListingChain,
        state: &mut WalkState,
    ) -> Result<ListingsIndex> {
        let nodes = self.walk_nodes().await;
        if nodes.is_empty() {
            return Err(Error::InsufficientPeers(
                "no nodes found to ask for listings".into(),
            ));
        }
        let too_few_nodes = nodes.len() < NEAREST_NODES
            || nodes.len().saturating_mul(4) < state.recent_max().saturating_mul(3);
        let base = walk_start(since);
        let walk = IndexWalk::new(nodes.iter().map(|(peer, _)| {
            let from = state
                .resume_for(peer)
                .filter(|key| *key > base)
                .unwrap_or(base);
            (*peer, *peer.as_bytes(), from)
        }));
        let requests = ListingsRequests::start(self.network().node(), None);
        let found = self.run_walk(walk, &requests).await;
        let walks: Vec<WalkReport> = found.nodes.iter().map(WalkReport::from).collect();
        state.record(nodes.len(), &walks);
        debug!(
            "Walked the index of {} nodes, {} to the end",
            walks.len(),
            walks
                .iter()
                .filter(|walk| walk.outcome == WalkOutcome::Complete)
                .count()
        );

        let mut index = ListingsIndex {
            nodes_asked: walks.len(),
            nodes_answered: walks.iter().filter(|walk| walk.pages > 0).count(),
            walks,
            too_few_nodes,
            coverage: Coverage {
                since,
                walks: found.nodes.clone(),
                ids: found
                    .nodes
                    .iter()
                    .map(|walk| *walk.peer.as_bytes())
                    .collect(),
                served: found
                    .addresses
                    .iter()
                    .map(|address| address.address)
                    .collect(),
                decided: HashSet::new(),
                gone: HashSet::new(),
            },
            ..ListingsIndex::default()
        };
        if too_few_nodes {
            debug!(
                "Found {} nodes, against {} in recent reads: deciding nothing",
                nodes.len(),
                state.recent_max()
            );
            index.deferred = found.addresses.len();
            return Ok(index);
        }

        let context = ReadContext::new(&found.nodes, nodes.into_iter().collect());
        let (backed, pending): (Vec<_>, Vec<_>) = found
            .addresses
            .into_iter()
            .partition(|found| found.support >= QUORUM_THRESHOLD);
        index.defer_pending(&pending, chain);
        let context = &context;
        let requests = &requests;
        let decisions: Vec<Decision> = stream::iter(backed)
            .map(|found| self.decide_backed(found, context, requests, chain, &[]))
            .buffer_unordered(CHECK_CONCURRENCY)
            .collect()
            .await;
        index.settle(decisions);
        Ok(index)
    }

    /// Run `walk` until nothing is left to ask, or to the walk phase's
    /// deadline: at most [`WALK_PHASE_MAX`], and once half the walks have
    /// settled, [`WALK_PHASE_FACTOR`] times as long as they took (at least
    /// [`WALK_PHASE_MIN`]).
    async fn run_walk(
        &self,
        mut walk: IndexWalk<PeerId>,
        requests: &ListingsRequests,
    ) -> WalkResult<PeerId> {
        let started = Instant::now();
        let mut deadline = started + WALK_PHASE_MAX;
        let mut deadline_set = false;
        let mut running = FuturesUnordered::new();
        loop {
            let slots = PEER_CONCURRENCY.saturating_sub(running.len());
            for (peer, from) in walk.next_requests(slots, unix_now()) {
                running.push(async move {
                    let request = ListingsBody::ListRequest {
                        from,
                        limit: MAX_LIST_LIMIT,
                    };
                    (peer, requests.ask(&peer, request).await)
                });
            }
            let Ok(next) = tokio::time::timeout_at(deadline, running.next()).await else {
                debug!("The walk phase reached its deadline");
                walk.stop();
                break;
            };
            let Some((peer, answer)) = next else {
                break;
            };
            match answer {
                Some(ListingsBody::ListResponse { listings, more }) => {
                    walk.answer(&peer, listings, more);
                }
                _ => walk.no_answer(&peer),
            }
            if !deadline_set && walk.settled() * 2 >= walk.len() {
                deadline_set = true;
                let phase = WALK_PHASE_MIN.max(started.elapsed() * WALK_PHASE_FACTOR);
                deadline = deadline.min(started + phase);
            }
        }
        walk.finish()
    }

    /// Decide an address at least a quorum of its nearest nodes serve.
    ///
    /// `unheard` are nearest nodes that serve a copy this read couldn't
    /// take (the listings producer couldn't fetch the full listing behind
    /// the node's entry): they count as nodes not heard from, whose walk
    /// doesn't answer for the address, and aren't asked again. A listing a
    /// quorum of the other copies serve is decided without them, as no other
    /// can reach a quorum; otherwise the address waits for them, as for any
    /// node that hasn't answered. An index read passes none.
    pub(crate) async fn decide_backed(
        &self,
        found: AddressWalk<PeerId>,
        context: &ReadContext,
        requests: &ListingsRequests,
        chain: &ListingChain,
        unheard: &[PeerId],
    ) -> Decision {
        let senders: Vec<PeerId> = found
            .nearest
            .iter()
            .copied()
            .filter(|peer| found.copies.iter().any(|(sender, _)| sender == peer))
            .collect();
        let envelope = match self
            .fetch_envelope(&found.address, &senders, context, chain)
            .await
        {
            Ok(Some(envelope)) => envelope,
            Ok(None) => {
                return Decision::again(
                    found.address,
                    &merge_copies(found.copies),
                    &found.nearest,
                    "none of the nodes serving it handed over its envelope; try again",
                    Vec::new(),
                )
            }
            Err(problem) => {
                return Decision::rejected(
                    found.address,
                    &merge_copies(found.copies),
                    &found.nearest,
                    &problem,
                )
            }
        };
        let ask = |address, peers: Vec<PeerId>| async move {
            self.ask_for_listing(requests, &address, &peers).await
        };
        decide_found(found, envelope, context, chain, unheard, unix_now(), ask).await
    }
}

/// What [`Client::decide_backed`] decides of `found` once it has its
/// `envelope`, at `now` (Unix seconds), asking nearest nodes for their
/// listing of the address with `ask` (as [`Client::ask_for_listing`] asks
/// them). See [`Client::decide_backed`] for `unheard`.
pub(crate) async fn decide_found<F, Fut>(
    found: AddressWalk<PeerId>,
    envelope: Envelope,
    context: &ReadContext,
    chain: &ListingChain,
    unheard: &[PeerId],
    now: u64,
    ask: F,
) -> Decision
where
    F: Fn(XorName, Vec<PeerId>) -> Fut,
    Fut: std::future::Future<Output = Vec<(PeerId, Option<Option<Listing>>)>>,
{
    let AddressWalk {
        address,
        nearest,
        mut copies,
        ..
    } = found;
    let needed = QUORUM_THRESHOLD;
    // A node whose copy wasn't taken hasn't been heard for this address,
    // whatever its walk.
    let walked: std::borrow::Cow<'_, HashMap<PeerId, u64>> = if unheard.is_empty() {
        std::borrow::Cow::Borrowed(&context.full_walks)
    } else {
        let mut walked = context.full_walks.clone();
        for peer in unheard {
            walked.remove(peer);
        }
        std::borrow::Cow::Owned(walked)
    };
    let mut heard: HashSet<PeerId> = copies.iter().map(|(peer, _)| *peer).collect();
    let mut failed: Vec<Listing> = Vec::new();
    let mut rejected: Vec<RejectedListing> = Vec::new();
    let mut asked = false;
    let groups = loop {
        let groups: Vec<MergedListing<PeerId>> = merge_copies(copies.clone())
            .into_iter()
            .filter(|group| !failed.iter().any(|listing| same_listing(group, listing)))
            .collect();
        // The listing a quorum serves is checked first, and only it: no
        // other can have a quorum of the same nodes.
        if let Some(group) = groups
            .iter()
            .find(|group| group.count_among(&nearest) >= needed)
        {
            match check_quorum_group(group, &envelope, &nearest, chain, now).await {
                Ok(checked) => {
                    let (chosen, problems) = decide_address(
                        std::slice::from_ref(group),
                        vec![Ok(checked)],
                        &nearest,
                        NEAREST_NODES,
                    );
                    for other in groups.iter().filter(|other| !std::ptr::eq(*other, group)) {
                        rejected.push(rejected_group(
                            other,
                            &nearest,
                            needed,
                            "not looked up: the listing a quorum of the nearest nodes serve                                  counts"
                                .into(),
                            false,
                        ));
                    }
                    return Decision::from_groups(
                        address,
                        std::slice::from_ref(group),
                        &nearest,
                        chosen,
                        problems,
                        envelope,
                        rejected,
                    );
                }
                Err(GroupProblem::Again(problem)) => {
                    return Decision::again(address, &groups, &nearest, &problem, rejected);
                }
                Err(GroupProblem::Invalid(problem)) => {
                    // No other listing for the address is left.
                    if groups.len() == 1 {
                        return Decision::refused(address, group, &nearest, problem, rejected);
                    }
                    rejected.push(rejected_group(group, &nearest, needed, problem, false));
                    failed.push(group_listing(group, &nearest, needed));
                    continue;
                }
            }
        }
        if asked {
            break groups;
        }
        asked = true;
        let to_ask: Vec<PeerId> = peers_to_ask(&groups, &nearest, needed, &heard, &walked)
            .into_iter()
            .filter(|peer| {
                !context.silent.contains(peer)
                    && !context.is_demoted(peer)
                    && !unheard.contains(peer)
            })
            .collect();
        if to_ask.is_empty() {
            break groups;
        }
        for (peer, answer) in ask(address, to_ask).await {
            match answer {
                Some(listing) => {
                    heard.insert(peer);
                    copies.extend(listing.map(|listing| (peer, listing)));
                }
                None => context.demote(peer),
            }
        }
    };
    if groups.is_empty() {
        return Decision {
            address,
            listing: None,
            rejected,
            decided: true,
        };
    }
    // No listing has a quorum: one may still get one if the nodes not
    // heard from serve it, so nothing is decided until they answer.
    let unheard: HashSet<&PeerId> = groups
        .iter()
        .flat_map(|group| {
            group.unheard_among(
                &nearest,
                |peer| heard.contains(peer),
                |peer| walked.get(peer).copied(),
            )
        })
        .collect();
    let most = groups
        .iter()
        .map(|group| group.count_among(&nearest))
        .max()
        .unwrap_or(0);
    if most + unheard.len() >= needed {
        let problem = format!(
            "no listing for it has a quorum of its nearest nodes yet: {most} serve the one \
             most serve, {} haven't answered; try again",
            unheard.len()
        );
        return Decision::again(address, &groups, &nearest, &problem, rejected);
    }
    let mut checked = Vec::with_capacity(groups.len());
    for group in &groups {
        checked.push(check_group(group, &envelope, &nearest, needed, chain, now).await);
    }
    let (chosen, problems) = decide_address(&groups, checked, &nearest, NEAREST_NODES);
    Decision::from_groups(
        address, &groups, &nearest, chosen, problems, envelope, rejected,
    )
}

impl Client {
    /// The envelope at `address`: the one `chain` keeps for it
    /// ([`ListingChain::kept_envelope`]), else from the nodes that served its
    /// listing (`senders`, nearest first), never through a DHT lookup, and
    /// then kept ([`ListingChain::keep_envelope`]). One node is asked at a
    /// time, and the next as well whenever none has answered within
    /// [`ENVELOPE_HEDGE`]. A node that fails, hands over nothing, or is
    /// beaten by another is demoted: asked last for the rest of the read.
    ///
    /// `Ok(None)` if none of them handed it over.
    ///
    /// # Errors
    ///
    /// Returns why the chunk at the address, which hashes to it, isn't an
    /// envelope.
    pub(crate) async fn fetch_envelope(
        &self,
        address: &XorName,
        senders: &[PeerId],
        context: &ReadContext,
        chain: &ListingChain,
    ) -> std::result::Result<Option<Envelope>, String> {
        if let Some(envelope) = chain.kept_envelope(address) {
            return Ok(Some(envelope));
        }
        let mut order = senders.to_vec();
        order.sort_by_key(|peer| context.is_demoted(peer));
        let fetch = |peer: PeerId| {
            let addresses = context.addresses.get(&peer).cloned().unwrap_or_default();
            async move {
                let fetched = self.chunk_get_from_peer(address, &peer, &addresses).await;
                (peer, fetched)
            }
        };
        let mut queue = order.into_iter();
        let mut running = FuturesUnordered::new();
        let mut started: Vec<PeerId> = Vec::new();
        let mut finished: Vec<PeerId> = Vec::new();
        loop {
            if running.is_empty() {
                let Some(peer) = queue.next() else {
                    return Ok(None);
                };
                started.push(peer);
                running.push(fetch(peer));
            }
            let next = if queue.as_slice().is_empty() {
                running.next().await
            } else {
                match tokio::time::timeout(ENVELOPE_HEDGE, running.next()).await {
                    Ok(next) => next,
                    Err(_) => {
                        if let Some(peer) = queue.next() {
                            started.push(peer);
                            running.push(fetch(peer));
                        }
                        continue;
                    }
                }
            };
            let Some((peer, fetched)) = next else {
                continue;
            };
            finished.push(peer);
            match fetched {
                Ok(Some(chunk)) => {
                    for beaten in started.iter().filter(|peer| !finished.contains(peer)) {
                        context.demote(*beaten);
                    }
                    let envelope = Envelope::from_bytes(&chunk.content)
                        .map_err(|e| format!("bad envelope: {e}"))?;
                    chain.keep_envelope(address, &chunk.content);
                    return Ok(Some(envelope));
                }
                Ok(None) | Err(_) => context.demote(peer),
            }
        }
    }

    /// The listing for `address`, in the index or not, from the nodes
    /// nearest it, checked on `chain`.
    ///
    /// Alongside the lookup of the nodes nearest the address, it finds how
    /// many nodes the network has, as an index read finds the nodes to walk,
    /// to know how many nearest nodes there should be when the lookup comes
    /// back short. A caller that already knows passes it to
    /// [`Self::listing_with`] instead.
    ///
    /// # Errors
    ///
    /// Returns an error if no node near the address can be found.
    pub async fn listing(&self, address: &XorName, chain: &ListingChain) -> Result<ListingLookup> {
        self.listing_with(address, chain, None).await
    }

    /// The listing for `address`, as [`Self::listing`] reads it, on a
    /// network of `network_size` nodes, such as a recent index read's
    /// [`ListingsIndex::nodes_asked`]. A size of at least [`NEAREST_NODES`]
    /// saves finding it: only the nodes nearest the address are looked up,
    /// and all [`NEAREST_NODES`] of them are expected however few the lookup
    /// finds. A smaller size, or `None`, is found as [`Self::listing`] finds
    /// it, so no size given lowers the quorum below what [`Self::listing`]
    /// needs.
    ///
    /// # Errors
    ///
    /// Returns an error if no node near the address can be found.
    pub async fn listing_with(
        &self,
        address: &XorName,
        chain: &ListingChain,
        network_size: Option<usize>,
    ) -> Result<ListingLookup> {
        let (nearest, expected) = match expected_nearest_given(network_size) {
            Some(expected) => (self.nearest_nodes(address).await, expected),
            None => {
                // How many nodes the network has, to know how many nearest
                // nodes there should be when the lookup comes back short.
                let (nearest, nodes) =
                    futures::join!(self.nearest_nodes(address), self.walk_nodes());
                let expected = expected_nearest(nodes.len().max(nearest.len()));
                (nearest, expected)
            }
        };
        if nearest.is_empty() {
            return Err(Error::InsufficientPeers(format!(
                "no nodes found near {}",
                hex::encode(address)
            )));
        }
        let requests = ListingsRequests::start(self.network().node(), None);
        let answers = self.ask_for_listing(&requests, address, &nearest).await;
        let answered = answers
            .iter()
            .filter(|(_, answer)| answer.is_some())
            .count();
        let copies = answers
            .into_iter()
            .filter_map(|(peer, answer)| answer.flatten().map(|listing| (peer, listing)))
            .collect();
        // Every nearest node was asked: asking again can't change the answer.
        let heard = nearest.iter().copied().collect();
        let (listing, rejected) = self
            .decide_from_copies(
                &requests,
                *address,
                copies,
                &nearest,
                expected,
                heard,
                &HashMap::new(),
                chain,
            )
            .await;
        Ok(ListingLookup {
            listing,
            rejected,
            nearest: nearest.len(),
            answered,
        })
    }

    /// Merge the copies for one address, ask the nearest nodes not yet heard
    /// from when their answers decide it, check each group, and decide: for
    /// [`Self::listing`], which asks every nearest node of one address.
    ///
    /// `expected` is how many nearest nodes there should be
    /// ([`expected_nearest`]). `heard` holds the nodes already heard from for
    /// this address: those that sent a copy, or were asked for it.
    #[allow(clippy::too_many_arguments)]
    async fn decide_from_copies(
        &self,
        requests: &ListingsRequests,
        address: XorName,
        mut copies: Vec<(PeerId, Listing)>,
        nearest: &[PeerId],
        expected: usize,
        heard: HashSet<PeerId>,
        walked: &HashMap<PeerId, u64>,
        chain: &ListingChain,
    ) -> (Option<CheckedListing>, Vec<RejectedListing>) {
        let any_copy = copies.first().map(|(_, listing)| listing.clone());
        let needed = quorum_needed(expected.max(nearest.len()));
        let mut groups = merge_copies(copies.clone());
        let to_ask = peers_to_ask(&groups, nearest, needed, &heard, walked);
        if !to_ask.is_empty() {
            for (peer, answer) in self.ask_for_listing(requests, &address, &to_ask).await {
                copies.extend(answer.flatten().map(|listing| (peer, listing)));
            }
            groups = merge_copies(copies);
        }
        if groups.is_empty() {
            let rejected = any_copy.map(|listing| RejectedListing {
                listing,
                problem: "no valid copy".into(),
                nodes: 0,
                nearest: nearest.len(),
                again: false,
            });
            return (None, rejected.into_iter().collect());
        }
        let reject_all = |problem: String, again: bool| {
            groups
                .iter()
                .map(|group| RejectedListing {
                    listing: group_listing(group, nearest, needed),
                    problem: problem.clone(),
                    nodes: group.count_among(nearest),
                    nearest: nearest.len(),
                    again,
                })
                .collect::<Vec<_>>()
        };
        let fetched = match chain.kept_envelope(&address) {
            Some(envelope) => Ok(Some(Ok(envelope))),
            None => self.chunk_get(&address).await.map(|chunk| {
                chunk.map(|chunk| {
                    let envelope = Envelope::from_bytes(&chunk.content);
                    if envelope.is_ok() {
                        chain.keep_envelope(&address, &chunk.content);
                    }
                    envelope
                })
            }),
        };
        let envelope = match fetched {
            Ok(Some(Ok(envelope))) => envelope,
            Ok(Some(Err(e))) => return (None, reject_all(format!("bad envelope: {e}"), false)),
            Ok(None) => {
                return (
                    None,
                    reject_all("the envelope is not on the network".into(), false),
                )
            }
            Err(e) => {
                return (
                    None,
                    reject_all(
                        format!("could not fetch the envelope: {e}; try again"),
                        true,
                    ),
                )
            }
        };
        let now = unix_now();
        let mut checked = Vec::with_capacity(groups.len());
        for group in &groups {
            checked.push(check_group(group, &envelope, nearest, needed, chain, now).await);
        }
        let (chosen, rejected) = decide_address(&groups, checked, nearest, expected);
        let rejected = rejected
            .into_iter()
            .map(|(index, problem)| {
                let again = is_again(&problem);
                rejected_group(&groups[index], nearest, needed, problem, again)
            })
            .collect();
        let chosen = chosen.map(|(listing, level, nodes, quorum)| CheckedListing {
            listing,
            envelope,
            level,
            nodes,
            nearest: nearest.len(),
            quorum,
        });
        (chosen, rejected)
    }

    /// The nodes nearest `address`, or none if the lookup fails.
    async fn nearest_nodes(&self, address: &XorName) -> Vec<PeerId> {
        match self
            .network()
            .find_closest_peers(address, NEAREST_NODES)
            .await
        {
            Ok(found) => found
                .into_iter()
                .map(|(peer, _)| peer)
                .take(NEAREST_NODES)
                .collect(),
            Err(e) => {
                debug!(
                    "Could not find the nodes nearest {}: {e}",
                    hex::encode(address)
                );
                Vec::new()
            }
        }
    }

    /// Ask each of `peers` for its listing of `address`. `None`: no answer;
    /// `Some(None)`: the node has no listing for it (or sent one that
    /// [`check_get_response`] refuses).
    pub(crate) async fn ask_for_listing(
        &self,
        requests: &ListingsRequests,
        address: &XorName,
        peers: &[PeerId],
    ) -> Vec<(PeerId, Option<Option<Listing>>)> {
        let address = *address;
        stream::iter(peers.to_vec())
            .map(|peer| async move {
                let answer = match requests
                    .ask(&peer, ListingsBody::GetRequest { address })
                    .await
                {
                    Some(ListingsBody::GetResponse { listing }) => {
                        Some(check_get_response(&address, listing).unwrap_or_else(|e| {
                            debug!(
                                "{peer} sent a bad listing for {}: {e}",
                                hex::encode(address)
                            );
                            None
                        }))
                    }
                    _ => None,
                };
                (peer, answer)
            })
            .buffer_unordered(PEER_CONCURRENCY)
            .collect()
            .await
    }

    /// The nodes to walk, each with its addresses: those in the routing
    /// table, and those a few random lookups find, which may take at most
    /// [`CRAWL_TIMEOUT`]. Only DHT nodes, never this client.
    async fn walk_nodes(&self) -> Vec<(PeerId, Vec<MultiAddr>)> {
        let network = self.network();
        let mut nodes: HashMap<PeerId, Vec<MultiAddr>> = network
            .known_peers()
            .await
            .into_iter()
            .map(|node| {
                let addresses = node.addresses_by_priority();
                (node.peer_id, addresses)
            })
            .collect();
        let targets: Vec<[u8; 32]> = (0..CRAWL_LOOKUPS).map(|_| rand::random()).collect();
        let lookups = futures::future::join_all(targets.iter().map(|target| {
            tokio::time::timeout(
                CRAWL_TIMEOUT,
                network.find_closest_peers(target, CRAWL_WIDTH),
            )
        }))
        .await;
        for lookup in lookups {
            match lookup {
                Ok(Ok(found)) => {
                    for (peer, addresses) in found {
                        nodes.entry(peer).or_insert(addresses);
                    }
                }
                Ok(Err(e)) => debug!("Listing crawl lookup failed: {e}"),
                Err(_) => debug!("A listing crawl lookup timed out"),
            }
        }
        nodes.remove(network.peer_id());
        nodes.into_iter().collect()
    }
}

/// Bytes of listings requests this process has sent to nodes.
static LISTINGS_BYTES_SENT: AtomicU64 = AtomicU64::new(0);

/// Bytes of listings answers and pushes this process has received from
/// nodes, counting each message once: the one router it is routed to.
static LISTINGS_BYTES_RECEIVED: AtomicU64 = AtomicU64::new(0);

/// The bytes of listings messages this process has received from nodes and
/// sent to them so far: each message's payload, without the transport's
/// signature and framing, and without DHT lookups.
pub(crate) fn listings_traffic() -> (u64, u64) {
    (
        LISTINGS_BYTES_RECEIVED.load(Ordering::Relaxed),
        LISTINGS_BYTES_SENT.load(Ordering::Relaxed),
    )
}

/// How many pushes from one node can wait to be taken: a node's free
/// allowance in pages, [`WALK_FREE_LISTINGS`] over [`MAX_LIST_LIMIT`]. A push
/// taken counts as a page against the node's allowance, so a node can't have
/// more taken in a round; one beyond this is dropped, and the node's next
/// `ChangesRequest` catches up. So no node can fill the room the others'
/// pushes wait in.
pub(crate) const PUSHES_WAITING_PER_NODE: usize = WALK_FREE_LISTINGS / MAX_LIST_LIMIT as usize;

/// How many pushes from each node wait to be taken.
type PushesWaiting = Arc<Mutex<HashMap<PeerId, usize>>>;

/// Where pushes from nodes' watches go, each with the node it came from: a
/// channel of a fixed size, of which each node may fill at most
/// [`PUSHES_WAITING_PER_NODE`]. The router never waits for room: a push that
/// doesn't fit is dropped, as pushes may be, and the next `ChangesRequest` to
/// the node catches up. Made with [`push_channel`].
pub(crate) struct PushSink {
    sender: tokio::sync::mpsc::Sender<(PeerId, ChangesResponse)>,
    waiting: PushesWaiting,
}

impl PushSink {
    /// Queue `push` from `source`, unless the channel is full or `source`
    /// already has [`PUSHES_WAITING_PER_NODE`] pushes waiting. Returns
    /// whether it was queued.
    pub(crate) fn offer(&self, source: PeerId, push: ChangesResponse) -> bool {
        let Ok(mut waiting) = self.waiting.lock() else {
            return false;
        };
        let count = waiting.entry(source).or_default();
        if *count >= PUSHES_WAITING_PER_NODE {
            return false;
        }
        if self.sender.try_send((source, push)).is_err() {
            if *count == 0 {
                waiting.remove(&source);
            }
            return false;
        }
        *count += 1;
        true
    }
}

/// The receiving end of the pushes a [`PushSink`] queues, each with the node
/// it came from.
#[derive(Debug)]
pub struct PushReceiver {
    receiver: tokio::sync::mpsc::Receiver<(PeerId, ChangesResponse)>,
    waiting: PushesWaiting,
}

impl PushReceiver {
    /// The next push, waiting for one; `None` once no sink is left.
    pub async fn recv(&mut self) -> Option<(PeerId, ChangesResponse)> {
        let push = self.receiver.recv().await?;
        self.taken(&push.0);
        Some(push)
    }

    /// The next push if one is waiting.
    pub fn try_recv(&mut self) -> Option<(PeerId, ChangesResponse)> {
        let push = self.receiver.try_recv().ok()?;
        self.taken(&push.0);
        Some(push)
    }

    fn taken(&self, source: &PeerId) {
        if let Ok(mut waiting) = self.waiting.lock() {
            if let Some(count) = waiting.get_mut(source) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    waiting.remove(source);
                }
            }
        }
    }
}

/// A channel for pushes from nodes' watches, with room for `capacity`.
pub(crate) fn push_channel(capacity: usize) -> (PushSink, PushReceiver) {
    let (sender, receiver) = tokio::sync::mpsc::channel(capacity);
    let waiting = PushesWaiting::default();
    (
        PushSink {
            sender,
            waiting: Arc::clone(&waiting),
        },
        PushReceiver { receiver, waiting },
    )
}

/// A request id for a listings request: random, with the top bit clear. The
/// id a node's pushes come with ([`push_request_id`], the bitwise
/// complement) then always has the top bit set, so no request's id is ever
/// the complement of another's, and a push is never taken for an answer.
fn new_request_id() -> u64 {
    rand::random::<u64>() >> 1
}

/// Where answers and pushes go, by node and request id.
#[derive(Default)]
struct Routes {
    /// Requests waiting for their answers.
    waiting: HashMap<(PeerId, u64), oneshot::Sender<ListingsBody>>,
    /// Each node's watch: the request id its pushes come with,
    /// [`push_request_id`] of the id of the latest `ChangesRequest` sent to
    /// it, when that one set a watch; and when it was set. It lapses after
    /// [`WATCH_LEASE`], as the node's does.
    watches: HashMap<PeerId, (u64, Instant)>,
}

/// What a message received on the listings topic is for.
#[derive(Debug)]
enum Route {
    /// The answer to the request waiting for it, to hand over. An
    /// [`Error`](ListingsBody::Error) is an answer too: the node refused the
    /// request, as one does a kind of request it doesn't know (`unsupported`),
    /// so it costs no timeout.
    Answer(oneshot::Sender<ListingsBody>, ListingsBody),
    /// A push from the node's watch.
    Push(ChangesResponse),
    /// Nothing waits for it: a late answer, a push from a watch that has
    /// ended, or a message that is neither.
    Drop,
}

impl Routes {
    /// Wait for `peer`'s answer to `body`, sent as request `request_id`. A
    /// `ChangesRequest` replaces the node's watch, as the node does: one that
    /// sets a watch routes the node's pushes from now on, if `take_pushes`
    /// (there is a sink for them), and one that doesn't ends the routing of
    /// the node's earlier watch.
    fn expect(
        &mut self,
        peer: PeerId,
        request_id: u64,
        body: &ListingsBody,
        take_pushes: bool,
    ) -> oneshot::Receiver<ListingsBody> {
        let (sender, receiver) = oneshot::channel();
        self.waiting.insert((peer, request_id), sender);
        if let ListingsBody::ChangesRequest(request) = body {
            if request.watch && take_pushes {
                self.watches
                    .insert(peer, (push_request_id(request_id), Instant::now()));
            } else {
                self.watches.remove(&peer);
            }
        }
        receiver
    }

    /// Stop waiting for `peer`'s answer to request `request_id`.
    fn forget(&mut self, peer: &PeerId, request_id: u64) {
        self.waiting.remove(&(*peer, request_id));
    }

    /// Where `message`, received from `source`, goes: a
    /// [`ChangesResponse`] with the id of the node's watch is a push, and
    /// any message with the id of a request waiting for the node's answer is
    /// that answer. Pushes and answers are told apart by id alone, never by
    /// the order they arrive in, since a push can overtake the answer.
    fn route(&mut self, source: PeerId, message: ListingsMessage) -> Route {
        let ListingsMessage { request_id, body } = message;
        if let Some((watch, set_at)) = self.watches.get(&source) {
            if *watch == request_id {
                if set_at.elapsed() >= Duration::from_secs(WATCH_LEASE) {
                    // Lapsed on the node too: a node's pushes past it aren't
                    // taken.
                    self.watches.remove(&source);
                    return Route::Drop;
                }
                return match body {
                    ListingsBody::ChangesResponse(push) => Route::Push(push),
                    _ => Route::Drop,
                };
            }
        }
        match self.waiting.remove(&(source, request_id)) {
            Some(sender) => Route::Answer(sender, body),
            None => Route::Drop,
        }
    }

    /// End the routing of the watches of nodes `keep` doesn't keep.
    fn keep_watches(&mut self, keep: impl Fn(&PeerId) -> bool) {
        self.watches.retain(|peer, _| keep(peer));
    }
}

/// Listings requests in flight. One subscriber decodes each message once
/// and hands it to the request waiting for it, by node and request id,
/// rather than each request reading every message the client receives; a
/// push from a node's watch goes to the push sink, if there is one. A
/// message that doesn't decode, such as an answer of a kind this client
/// doesn't know, is dropped: the request it answers times out.
pub(crate) struct ListingsRequests {
    node: Arc<P2PNode>,
    routes: Arc<Mutex<Routes>>,
    /// Whether pushes have somewhere to go.
    take_pushes: bool,
    router: tokio::task::JoinHandle<()>,
    /// Where nodes can be reached, to dial one this process isn't connected
    /// to ([`Self::set_addresses`]).
    addresses: Mutex<HashMap<PeerId, Vec<MultiAddr>>>,
}

impl ListingsRequests {
    /// Start routing answers, and pushes to `pushes` if given. Without a
    /// sink, a `ChangesRequest` that sets a watch is still answered, but the
    /// node's pushes are dropped.
    pub(crate) fn start(node: &Arc<P2PNode>, pushes: Option<PushSink>) -> Self {
        let routes: Arc<Mutex<Routes>> = Arc::default();
        let take_pushes = pushes.is_some();
        // Subscribe before anything is sent, so no answer can be missed.
        let mut events = node.subscribe_events();
        let router_routes = Arc::clone(&routes);
        let router = tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(P2PEvent::Message {
                        topic,
                        source: Some(source),
                        data,
                        ..
                    }) if topic == TOPIC => {
                        let Ok(message) = ListingsMessage::decode(&data) else {
                            continue;
                        };
                        let route = match router_routes.lock() {
                            Ok(mut routes) => routes.route(source, message),
                            Err(_) => Route::Drop,
                        };
                        if !matches!(route, Route::Drop) {
                            LISTINGS_BYTES_RECEIVED.fetch_add(data.len() as u64, Ordering::Relaxed);
                        }
                        match route {
                            Route::Answer(waiting, body) => {
                                let _ = waiting.send(body);
                            }
                            Route::Push(push) => {
                                let full = pushes
                                    .as_ref()
                                    .is_some_and(|sink| !sink.offer(source, push));
                                if full {
                                    debug!("Dropped a listings push from {source}");
                                }
                            }
                            Route::Drop => {}
                        }
                    }
                    Ok(_) => {}
                    Err(RecvError::Lagged(missed)) => {
                        debug!("The listings router missed {missed} messages");
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        });
        Self {
            node: Arc::clone(node),
            routes,
            take_pushes,
            router,
            addresses: Mutex::new(HashMap::new()),
        }
    }

    /// Reach each node at the addresses `addresses` gives for it, such as a
    /// census's, when this process isn't connected to it: without them, a
    /// request to a node no lookup has connected to fails. Replaces those
    /// given before.
    pub(crate) fn set_addresses(
        &self,
        addresses: impl IntoIterator<Item = (PeerId, Vec<MultiAddr>)>,
    ) {
        let addresses: HashMap<PeerId, Vec<MultiAddr>> = addresses.into_iter().collect();
        if let Ok(mut known) = self.addresses.lock() {
            *known = addresses;
        }
    }

    /// End the routing of pushes from the watches of nodes `keep` doesn't
    /// keep, such as nodes that left the census: their pushes are dropped,
    /// and use no room among those waiting to be taken.
    pub(crate) fn keep_watches(&self, keep: impl Fn(&PeerId) -> bool) {
        if let Ok(mut routes) = self.routes.lock() {
            routes.keep_watches(keep);
        }
    }

    /// Send `body` to `peer` and wait for its answer, at most
    /// [`REQUEST_TIMEOUT`]. An [`Error`](ListingsBody::Error) is returned
    /// as the answer it is: the node refused the request.
    pub(crate) async fn ask(&self, peer: &PeerId, body: ListingsBody) -> Option<ListingsBody> {
        let request_id = new_request_id();
        let receiver = self
            .routes
            .lock()
            .ok()?
            .expect(*peer, request_id, &body, self.take_pushes);
        // A request dropped before its answer, such as at a poll's deadline,
        // stops waiting too: no route is left behind for an answer that may
        // never come.
        let _forget = Forget {
            routes: &self.routes,
            peer: *peer,
            request_id,
        };
        let request = ListingsMessage { request_id, body }.encode();
        let addresses = self
            .addresses
            .lock()
            .ok()
            .and_then(|known| known.get(peer).cloned())
            .unwrap_or_default();
        let answer = match request {
            Ok(request) => {
                LISTINGS_BYTES_SENT.fetch_add(request.len() as u64, Ordering::Relaxed);
                match self
                    .node
                    .send_message(peer, TOPIC, request, &addresses)
                    .await
                {
                    Ok(()) => tokio::time::timeout(REQUEST_TIMEOUT, receiver)
                        .await
                        .ok()
                        .and_then(std::result::Result::ok),
                    Err(e) => {
                        debug!("Could not ask {peer} for listings: {e}");
                        None
                    }
                }
            }
            Err(e) => {
                debug!("Could not encode a listings request: {e}");
                None
            }
        };
        if answer.is_none() {
            debug!("{peer} did not answer a listings request");
        }
        answer
    }
}

/// Stops waiting for one request's answer when dropped, however the request
/// ends ([`ListingsRequests::ask`]).
struct Forget<'a> {
    routes: &'a Mutex<Routes>,
    peer: PeerId,
    request_id: u64,
}

impl Drop for Forget<'_> {
    fn drop(&mut self) {
        if let Ok(mut routes) = self.routes.lock() {
            routes.forget(&self.peer, self.request_id);
        }
    }
}

impl Drop for ListingsRequests {
    fn drop(&mut self) {
        self.router.abort();
    }
}

/// What deciding an address needs from its read's walks.
pub(crate) struct ReadContext {
    /// When each node's walk began, for walks of its whole index, from the
    /// start ([`ListingKey::MIN`]) to the end: such a walk returned every
    /// listing the node held as it passed it. A walk from a later key, as in
    /// a read from a time ([`walk_start`]), doesn't count: a node keys a
    /// listing that hides its time by its own date, which can be well before
    /// the date the nearest nodes give it.
    pub(crate) full_walks: HashMap<PeerId, u64>,
    /// Nodes that answered no page: not asked anything more this read.
    pub(crate) silent: HashSet<PeerId>,
    /// Each node's addresses, to fetch from it.
    pub(crate) addresses: HashMap<PeerId, Vec<MultiAddr>>,
    /// Nodes that failed a request while deciding: asked last, or not
    /// again, for the rest of the read.
    pub(crate) demoted: Mutex<HashSet<PeerId>>,
}

impl ReadContext {
    /// The context of a read whose nodes' walks went as `walks`.
    pub(crate) fn new(
        walks: &[NodeReport<PeerId>],
        addresses: HashMap<PeerId, Vec<MultiAddr>>,
    ) -> Self {
        let full_walks = walks
            .iter()
            .filter(|walk| walk.outcome == WalkOutcome::Complete && walk.from == ListingKey::MIN)
            .filter_map(|walk| walk.began.map(|began| (walk.peer, began)))
            .collect();
        let silent = walks
            .iter()
            .filter(|walk| walk.pages == 0)
            .map(|walk| walk.peer)
            .collect();
        Self {
            full_walks,
            silent,
            addresses,
            demoted: Mutex::new(HashSet::new()),
        }
    }

    pub(crate) fn demote(&self, peer: PeerId) {
        if let Ok(mut demoted) = self.demoted.lock() {
            demoted.insert(peer);
        }
    }

    pub(crate) fn is_demoted(&self, peer: &PeerId) -> bool {
        self.demoted
            .lock()
            .is_ok_and(|demoted| demoted.contains(peer))
    }
}

/// What a read decided for one address it worked on.
pub(crate) struct Decision {
    pub(crate) address: XorName,
    pub(crate) listing: Option<CheckedListing>,
    pub(crate) rejected: Vec<RejectedListing>,
    /// False if nothing final was decided, to try again in a later read.
    pub(crate) decided: bool,
}

impl Decision {
    /// Nothing decided, for `problem`: each group is rejected to try again,
    /// after `rejected`.
    pub(crate) fn again(
        address: XorName,
        groups: &[MergedListing<PeerId>],
        nearest: &[PeerId],
        problem: &str,
        mut rejected: Vec<RejectedListing>,
    ) -> Self {
        rejected.extend(
            groups.iter().map(|group| {
                rejected_group(group, nearest, QUORUM_THRESHOLD, problem.into(), true)
            }),
        );
        Self {
            address,
            listing: None,
            rejected,
            decided: false,
        }
    }

    /// Every group rejected for good, for `problem`.
    pub(crate) fn rejected(
        address: XorName,
        groups: &[MergedListing<PeerId>],
        nearest: &[PeerId],
        problem: &str,
    ) -> Self {
        Self {
            address,
            listing: None,
            rejected: groups
                .iter()
                .map(|group| {
                    rejected_group(group, nearest, QUORUM_THRESHOLD, problem.into(), false)
                })
                .collect(),
            decided: true,
        }
    }

    /// `group`, the listing a quorum of `nearest` serve, failed its check
    /// for good, for `problem`, and no other listing for the address is
    /// left: nothing is listed, and `group` is rejected after `rejected`.
    /// The address is decided, so an entry an earlier read published for it
    /// is dropped ([`ListingsIndex::carry`]), however many nodes serve it.
    pub(crate) fn refused(
        address: XorName,
        group: &MergedListing<PeerId>,
        nearest: &[PeerId],
        problem: String,
        mut rejected: Vec<RejectedListing>,
    ) -> Self {
        rejected.push(rejected_group(
            group,
            nearest,
            QUORUM_THRESHOLD,
            problem,
            false,
        ));
        Self {
            address,
            listing: None,
            rejected,
            decided: true,
        }
    }

    /// What [`decide_address`] decided for `groups`, after `rejected`.
    pub(crate) fn from_groups(
        address: XorName,
        groups: &[MergedListing<PeerId>],
        nearest: &[PeerId],
        chosen: Option<CountingListing>,
        problems: RejectedGroups,
        envelope: Envelope,
        mut rejected: Vec<RejectedListing>,
    ) -> Self {
        let mut again = false;
        for (index, problem) in problems {
            let retry = is_again(&problem);
            again |= retry;
            rejected.push(rejected_group(
                &groups[index],
                nearest,
                QUORUM_THRESHOLD,
                problem,
                retry,
            ));
        }
        let listing = chosen.map(|(listing, level, nodes, quorum)| CheckedListing {
            listing,
            envelope,
            level,
            nodes,
            nearest: nearest.len(),
            quorum,
        });
        let decided = listing.is_some() || !again;
        Self {
            address,
            listing,
            rejected,
            decided,
        }
    }
}

/// Why the group a quorum serves didn't check out.
pub(crate) enum GroupProblem {
    /// Nothing final: the chain couldn't be read, or doesn't have the
    /// payment yet.
    Again(String),
    /// It doesn't check out.
    Invalid(String),
}

/// Check the group a quorum of `nearest` serve, as [`check_group`] does,
/// saying whether a failure is final. A quorum of nodes checked its payment
/// on chain when they stored it, so a chain that couldn't be read, or that
/// doesn't have the payment (yet), is worth trying again.
pub(crate) async fn check_quorum_group(
    group: &MergedListing<PeerId>,
    envelope: &Envelope,
    nearest: &[PeerId],
    chain: &ListingChain,
    now: u64,
) -> std::result::Result<(Listing, ListingCheck), GroupProblem> {
    let needed = QUORUM_THRESHOLD;
    let listing = listing_to_check(group, nearest, needed).ok_or_else(|| {
        GroupProblem::Invalid("none of the nodes nearest its address gives it a first_seen".into())
    })?;
    check_offline(&listing, envelope, chain.vault())
        .map_err(|e| GroupProblem::Invalid(e.to_string()))?;
    check_vault_deployment(group, nearest, needed, chain).map_err(GroupProblem::Invalid)?;
    let lookup = payment_lookup(&listing).map_err(|e| GroupProblem::Invalid(e.to_string()))?;
    let fetched = chain
        .fetch(&lookup, &listing.payment)
        .await
        .map_err(|e| GroupProblem::Again(CheckProblem::ChainUnread(e).to_string()))?;
    check_copies(group, nearest, needed, |listing| {
        verify_listing_receipts(listing, envelope, &fetched, chain.vault(), now)
    })
    .map_err(|e| match e {
        PaymentError::NotFound => {
            GroupProblem::Again("its payment is not on the chain yet; try again".into())
        }
        e => GroupProblem::Invalid(e.to_string()),
    })
}

/// The listing to show for an address too few of its nearest nodes serve
/// to decide yet: the one most of them serve.
pub(crate) fn pending_listing(found: &AddressWalk<PeerId>) -> Option<RejectedListing> {
    let groups = merge_copies(found.copies.clone());
    let group = groups
        .iter()
        .max_by_key(|group| group.count_among(&found.nearest))?;
    let problem = format!(
        "served by {} of the {} nodes nearest its address so far, needs {QUORUM_THRESHOLD}; \
         try again",
        found.support,
        found.nearest.len()
    );
    Some(rejected_group(
        group,
        &found.nearest,
        QUORUM_THRESHOLD,
        problem,
        true,
    ))
}

/// Every copy the nearest nodes served for an address too few of them serve
/// to decide yet, nearest node first, each with its block and block
/// timestamp checked against `chain`'s vault.
pub(crate) fn pending_copies(
    found: &AddressWalk<PeerId>,
    chain: &ListingChain,
) -> Vec<PendingCopy> {
    let rank = |node: &PeerId| found.nearest.iter().position(|peer| peer == node);
    let mut copies: Vec<&(PeerId, Listing)> = found.copies.iter().collect();
    copies.sort_by_key(|(node, _)| rank(node));
    copies
        .into_iter()
        .map(|(node, listing)| PendingCopy::new(*node, listing, chain))
        .collect()
}

/// `group`, rejected for `problem`; `needed` dates it as [`group_listing`]
/// does.
pub(crate) fn rejected_group(
    group: &MergedListing<PeerId>,
    nearest: &[PeerId],
    needed: usize,
    problem: String,
    again: bool,
) -> RejectedListing {
    RejectedListing {
        listing: group_listing(group, nearest, needed),
        problem,
        nodes: group.count_among(nearest),
        nearest: nearest.len(),
        again,
    }
}

/// Whether `group` is `listing`, apart from `first_seen`.
fn same_listing(group: &MergedListing<PeerId>, listing: &Listing) -> bool {
    group.address() == listing.address
        && group.flags() == listing.flags
        && group.metadata() == &listing.metadata
        && group.size() == listing.size
        && group.payment() == &listing.payment
}

/// Whether a rejection is worth trying again: the checks say so.
pub(crate) fn is_again(problem: &str) -> bool {
    problem.ends_with("try again")
}

/// A group's listing for showing: as the nearest nodes give it
/// ([`listing_to_check`]), or as any node sent it.
pub(crate) fn group_listing(
    group: &MergedListing<PeerId>,
    nearest: &[PeerId],
    needed: usize,
) -> Listing {
    listing_to_check(group, nearest, needed).unwrap_or_else(|| Listing {
        address: group.address(),
        flags: group.flags(),
        metadata: group.metadata().clone(),
        size: group.size(),
        payment: group.payment().clone(),
        first_seen: group.peers().iter().find_map(|(_, first_seen)| *first_seen),
    })
}

/// Check one group of copies against the chain, as a node checks its close
/// group's copies: offline first, then fetch once for
/// [`listing_to_check`], then [`check_copies`].
pub(crate) async fn check_group<P: PartialEq>(
    group: &MergedListing<P>,
    envelope: &Envelope,
    nearest: &[P],
    needed: usize,
    chain: &ListingChain,
    now: u64,
) -> std::result::Result<(Listing, ListingCheck), CheckProblem> {
    let listing = listing_to_check(group, nearest, needed).ok_or_else(|| {
        CheckProblem::Invalid("none of the nodes nearest its address gives it a first_seen".into())
    })?;
    // A copy that can't check out is never looked up.
    check_offline(&listing, envelope, chain.vault())?;
    check_vault_deployment(group, nearest, needed, chain).map_err(CheckProblem::Invalid)?;
    let lookup = payment_lookup(&listing)?;
    let fetched = chain
        .fetch(&lookup, &listing.payment)
        .await
        .map_err(CheckProblem::ChainUnread)?;
    Ok(check_copies(group, nearest, needed, |listing| {
        verify_listing_receipts(listing, envelope, &fetched, chain.vault(), now)
    })?)
}

/// Why the listing `group` holds can't have paid `chain`'s vault, whatever
/// the chain says: it was paid, or first stored, before the vault was
/// deployed or took its first payment. Only what `chain` knows of these is
/// used (the bundled network's: [`crate::config::vault_deployment_block`],
/// [`crate::config::vault_deployment_time`] and
/// [`crate::config::vault_first_payment_time`]); where it knows nothing,
/// nothing is refused. It is refused when:
///
/// - the block it shows is earlier than the block the vault was deployed
///   in;
/// - the block timestamp it shows is earlier than that block's: block
///   timestamps never go back, so no payment to the vault is in a block
///   timed earlier. A payment at the deployment's second or later is never
///   refused;
/// - showing none of its block, block timestamp and transaction, its date
///   is too early: the hour its nodes first stored it, as `needed` of the
///   `nearest` nodes date it then or earlier ([`quorum_listing`]). A node
///   records a listing only once its payment is in a block, so the payment
///   is no later than that hour plus [`FIRST_SEEN_ROUNDING`] and
///   [`CLOCK_MARGIN`] ([`Listing::latest_payment_time`]), and it is refused
///   when that is still before the vault's first payment (where that isn't
///   known, its deployment): no payment to the vault is earlier. So a
///   payment to the vault, first stored by nodes whose clocks are within
///   [`CLOCK_MARGIN`], is never refused. Only the quorum's date counts:
///   fewer than `needed` nodes dating it early can't move it before the date
///   another gives, so they can't get a listing refused, and a listing fewer
///   than `needed` of them serve is not refused by its date.
///
/// A listing that shows its transaction, but neither its block nor its
/// block timestamp, is left to the chain: the transaction shows which vault
/// it paid, for good, whatever dates its nodes give. A listing outside the
/// index has no date, so one that hides its block, block timestamp and
/// transaction isn't refused here: if it hides its quote too, it rests on
/// its nearest nodes.
///
/// What this can't refuse: a payment to another vault that hides its block,
/// block timestamp and transaction, and that a quorum of its nodes date no
/// more than the margin, two hours, before the vault's first payment, or
/// later, as they could date a payment to the vault. Its date plus the
/// margin isn't before the first payment, so it is checked as any other
/// listing: one that hides its quote too rests on its nearest nodes. On the
/// bundled network, the vault took its first payment at 21:20:03 UTC on
/// 2026-10-06, so that is a listing a quorum of its nodes date 20:00 or
/// later: one dated 20:00 could be a payment to the vault at 21:20:03 that
/// nodes whose clocks were an hour behind stored at once. A payment to the
/// vault in use before this one, whose last was at 19:18:41 UTC (block
/// 81,871,668), escapes only where a quorum of its nodes first stored it,
/// by their clocks, at 20:00 or later.
fn check_vault_deployment<P: PartialEq>(
    group: &MergedListing<P>,
    nearest: &[P],
    needed: usize,
    chain: &ListingChain,
) -> std::result::Result<(), String> {
    let payment = group.payment();
    if let (Some(block), Some(deployed)) = (payment.block_number, chain.vault_deployment_block) {
        if block < deployed {
            return Err(format!(
                "paid in block {block}, before the payment vault was deployed in block \
                 {deployed}: not a payment to the vault"
            ));
        }
    }
    if let Some(time) = payment.block_timestamp {
        return match chain.vault_deployment_time {
            Some(deployed_at) if time < deployed_at => Err(format!(
                "paid in a block timed {time}, before the payment vault was deployed at \
                 {deployed_at} (Unix seconds): not a payment to the vault"
            )),
            _ => Ok(()),
        };
    }
    if payment.block_number.is_some() || payment.tx_hash.is_some() {
        return Ok(());
    }
    let Some(first_paid) = chain.no_payment_before() else {
        return Ok(());
    };
    let Some(dated) = quorum_listing(group, nearest, needed) else {
        return Ok(());
    };
    match (dated.first_seen, dated.latest_payment_time()) {
        (Some(date), Some(latest)) if latest < first_paid => Err(format!(
            "dated {date} or earlier by {needed} of the nodes nearest its address, so paid by \
             {latest}, before the payment vault's first payment, at {first_paid} or later \
             (Unix seconds): not a payment to the vault"
        )),
        _ => Ok(()),
    }
}

/// The environment variable that, on the bundled network, replaces the RPCs
/// a [`ListingChain`] reads payments through ([`ListingChain::new`]): their
/// URLs, separated by spaces, asked in that order for every call. Each must
/// say it is on the network's chain before it is used. Other networks read
/// through their own RPC alone.
pub const RPC_URLS_ENV: &str = "RPC_URLS";

/// The most block timestamps kept to narrow later searches for the block at
/// a time. When full, every other one is dropped. darwin-node's number for
/// the same search.
const MAX_KNOWN_BLOCKS: usize = 4_096;

/// Reads payments from the payment chain, for checking listings and upload
/// proofs, and for the vault records an upload reads back after paying
/// ([`Self::completed_payment`]).
///
/// Every call goes through the reader's RPC providers in a fixed order per
/// kind of call, in batches where calls are known together, each with its
/// own id, paced per provider, holding off a provider that is busy, and
/// never showing a provider's URL in an error.
///
/// With a store ([`Self::with_store`]), it keeps what it reads: envelopes,
/// and the vault's chain facts once final, so they are read once for good.
/// Its checks are the same either way: a fact is used as soon as it is
/// read.
pub struct ListingChain {
    rpc: Rpc,
    vault: [u8; 20],
    /// The block the vault was deployed in, where known.
    vault_deployment_block: Option<u64>,
    /// That block's timestamp (Unix seconds), where known.
    vault_deployment_time: Option<u64>,
    /// The timestamp (Unix seconds) of the block of the vault's first
    /// payment, where known.
    vault_first_payment_time: Option<u64>,
    /// The timestamps of blocks read so far, by block number, used only to
    /// narrow searches for the block at a time.
    known_blocks: Mutex<BTreeMap<u64, u64>>,
    /// Where envelopes and chain facts are kept, if anywhere
    /// ([`Self::with_store`]).
    facts: Option<Facts>,
}

/// A fact a lookup read, to be confirmed by another provider before it is
/// kept for good.
enum Unconfirmed {
    /// A receipt, read through a provider.
    Receipt(PaymentReceipt, usize),
    /// A block's timestamp, read through a provider.
    Block(u64, u64, usize),
}

impl Unconfirmed {
    /// The provider it was read through.
    fn source(&self) -> usize {
        match self {
            Self::Receipt(_, source) | Self::Block(_, _, source) => *source,
        }
    }

    /// The call that reads it again.
    fn call(&self) -> Call {
        match self {
            Self::Receipt(receipt, _) => Call::new(
                "eth_getTransactionReceipt",
                json!([format!("0x{}", hex::encode(receipt.tx_hash))]),
            ),
            Self::Block(number, _, _) => {
                Call::new("eth_getBlockByNumber", json!([quantity(*number), false]))
            }
        }
    }

    /// Whether `answer`, to [`Self::call`], says the same.
    fn agrees(&self, answer: &Value, vault: &[u8; 20]) -> bool {
        match self {
            Self::Receipt(receipt, _) => {
                !answer.is_null()
                    && parse_receipt(receipt.tx_hash, answer, vault)
                        .is_ok_and(|read| read == *receipt)
            }
            Self::Block(_, timestamp, _) => {
                answer["timestamp"].as_str().and_then(parse_u64) == Some(*timestamp)
            }
        }
    }

    /// Drop it from what `facts` hold.
    fn forget(&self, facts: &Facts) {
        match self {
            Self::Receipt(receipt, _) => facts.forget_receipt(&receipt.tx_hash),
            Self::Block(number, _, _) => facts.forget_block(*number),
        }
    }

    fn describe(&self) -> String {
        match self {
            Self::Receipt(receipt, _) => format!("the receipt of {}", hex::encode(receipt.tx_hash)),
            Self::Block(number, _, _) => format!("the timestamp of block {number}"),
        }
    }
}

impl ListingChain {
    /// A reader for `network`'s chain and payment vault, knowing the block
    /// the vault was deployed in and its timestamp, and the timestamp of the
    /// vault's first payment, where the network gives them
    /// ([`crate::config::vault_deployment_block`],
    /// [`crate::config::vault_deployment_time`],
    /// [`crate::config::vault_first_payment_time`]).
    ///
    /// It reads through `network`'s RPC and then the RPCs it falls back to
    /// ([`crate::config::fallback_rpc_urls`]), except that log queries go to
    /// the first fallback first: on the bundled network, receipts and blocks
    /// go to PublicNode first and log queries to ordofi first, which
    /// PublicNode refuses, and Robinhood's RPC comes last for both. On the
    /// bundled network, [`RPC_URLS_ENV`] replaces them when set.
    ///
    /// # Errors
    ///
    /// Returns an error if [`RPC_URLS_ENV`] holds something other than
    /// URLs, or the HTTP client can't be built.
    pub fn new(network: &EvmNetwork) -> Result<Self> {
        let listed = std::env::var(RPC_URLS_ENV).ok();
        let RpcSetup {
            urls,
            logs_order,
            chain_id,
        } = rpc_setup(network, listed.as_deref()).map_err(Error::Network)?;
        let mut vault = [0u8; 20];
        vault.copy_from_slice(network.payment_vault_address().as_slice());
        let mut reader = Self::with_rpc_setup(urls, logs_order, chain_id, vault)?;
        if let Some(block) = crate::config::vault_deployment_block(network) {
            reader = reader.with_vault_deployment_block(block);
        }
        if let Some(time) = crate::config::vault_deployment_time(network) {
            reader = reader.with_vault_deployment_time(time);
        }
        if let Some(time) = crate::config::vault_first_payment_time(network) {
            reader = reader.with_vault_first_payment_time(time);
        }
        Ok(reader)
    }

    /// The RPCs this reader reads through, in the order of everything but
    /// log queries.
    #[cfg(test)]
    pub(crate) fn rpc_urls(&self) -> Vec<String> {
        self.rpc.urls()
    }

    /// Tests: this reader, calling as fast as calls come, unpaced.
    #[cfg(test)]
    pub(crate) fn unpaced(mut self) -> Self {
        self.rpc.unpaced();
        self
    }

    /// A reader for the chain at `rpc_url` and the vault at `vault`.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client can't be built.
    pub fn with_rpc(rpc_url: String, vault: [u8; 20]) -> Result<Self> {
        Self::with_rpcs(vec![rpc_url], vault)
    }

    /// A reader for the chain through `rpc_urls`, in that order for every
    /// call, and the vault at `vault`.
    ///
    /// # Errors
    ///
    /// Returns an error if `rpc_urls` is empty or the HTTP client can't be
    /// built.
    pub fn with_rpcs(rpc_urls: Vec<String>, vault: [u8; 20]) -> Result<Self> {
        Self::with_rpc_setup(rpc_urls, None, None, vault)
    }

    fn with_rpc_setup(
        urls: Vec<String>,
        logs_order: Option<Vec<usize>>,
        chain_id: Option<u64>,
        vault: [u8; 20],
    ) -> Result<Self> {
        let rpc = Rpc::new(urls, logs_order, chain_id).map_err(Error::Network)?;
        Ok(Self {
            rpc,
            vault,
            vault_deployment_block: None,
            vault_deployment_time: None,
            vault_first_payment_time: None,
            known_blocks: Mutex::new(BTreeMap::new()),
            facts: None,
        })
    }

    /// This reader, keeping in `store` what it reads that never changes, so
    /// a restart reads it no more: the envelopes it is given
    /// ([`Self::keep_envelope`]), and the vault's chain facts once final, in
    /// the databases named `facts_…` (see `listings_facts` in this crate's
    /// source). A fact is kept once its block is at or below the block the
    /// RPC reports as finalized and a second provider returns the same;
    /// "not found", errors and times in the future never are.
    ///
    /// # Errors
    ///
    /// If the store's databases can't be opened.
    pub fn with_store(mut self, store: &ListingsStore) -> Result<Self> {
        let facts = Facts::open(store, self.vault)?;
        for (number, timestamp) in facts.kept_blocks() {
            self.remember_block(number, timestamp);
        }
        self.facts = Some(facts);
        Ok(self)
    }

    /// The envelope kept for `address` ([`Self::keep_envelope`]), if any.
    /// It is content-addressed: bytes that don't hash to `address`, or don't
    /// decode, are not returned. `None` without a store.
    #[must_use]
    pub fn kept_envelope(&self, address: &XorName) -> Option<Envelope> {
        self.facts.as_ref()?.envelope(address)
    }

    /// Keep `chunk`, the envelope chunk fetched for `address`, for good, if
    /// this reader has a store ([`Self::with_store`]) and the chunk hashes
    /// to `address`. A failure to keep it is logged, not returned: the
    /// envelope is fetched again when next needed.
    pub fn keep_envelope(&self, address: &XorName, chunk: &[u8]) {
        if let Some(facts) = &self.facts {
            facts.keep_envelope(address, chunk);
        }
    }

    /// Whether everything checking `listing` reads from the chain is kept
    /// for good ([`Self::with_store`]): checking it again reads nothing, and
    /// can't decide differently from what the chain says. False while a fact
    /// it needs is not final, or not found, and always without a store. A
    /// caller that decided from facts not yet final decides again once this
    /// is true.
    #[must_use]
    pub fn settled(&self, listing: &Listing) -> bool {
        let Some(facts) = &self.facts else {
            return false;
        };
        let Ok(lookup) = payment_lookup(listing) else {
            // Malformed: its check reads nothing.
            return true;
        };
        let transaction_kept = |tx_hash: &[u8; 32]| {
            facts
                .kept_receipt(tx_hash)
                .is_some_and(|receipt| facts.kept_block(receipt.block_number).is_some())
        };
        match lookup {
            Lookup::Nothing => true,
            Lookup::Block { block_number } => facts.kept_block(block_number).is_some(),
            Lookup::Transaction { tx_hash } => transaction_kept(&tx_hash),
            Lookup::BlockLog {
                block_number,
                log_index,
            } => facts
                .kept_block_log(block_number, log_index)
                .is_some_and(|tx_hash| transaction_kept(&tx_hash)),
            Lookup::Quote { quote_hash, .. } => facts
                .kept_quote(&quote_hash)
                .is_some_and(|payments| payments.iter().all(|p| transaction_kept(&p.tx_hash))),
        }
    }

    /// The calls this reader has made to each RPC provider since it was
    /// made, and how many failed: each provider by its host name alone,
    /// never its full URL, which can hold a key. A batch counts each call in
    /// it.
    #[must_use]
    pub fn rpc_calls(&self) -> Vec<RpcCalls> {
        self.rpc.calls()
    }

    /// This reader, knowing that the vault was deployed in block `block`:
    /// no payment to it is earlier, so a listing showing an earlier block
    /// fails its check without a call to the chain.
    #[must_use]
    pub fn with_vault_deployment_block(mut self, block: u64) -> Self {
        self.vault_deployment_block = Some(block);
        self
    }

    /// This reader, knowing that the block the vault was deployed in is
    /// timed `time` (Unix seconds): block timestamps never go back, so no
    /// payment to the vault is in a block timed earlier. A listing showing
    /// an earlier block timestamp fails its check without a call to the
    /// chain, and so does, where the time of the vault's first payment isn't
    /// known ([`Self::with_vault_first_payment_time`]), one showing none of
    /// its block, block timestamp and transaction that a quorum of its
    /// nearest nodes date more than [`FIRST_SEEN_ROUNDING`] plus
    /// [`CLOCK_MARGIN`] before then.
    #[must_use]
    pub fn with_vault_deployment_time(mut self, time: u64) -> Self {
        self.vault_deployment_time = Some(time);
        self
    }

    /// This reader, knowing that the block of the vault's first payment is
    /// timed `time` (Unix seconds), so that no payment to the vault is in a
    /// block timed earlier. A listing showing none of its block, block
    /// timestamp and transaction that a quorum of its nearest nodes date
    /// more than [`FIRST_SEEN_ROUNDING`] plus [`CLOCK_MARGIN`] before then
    /// fails its check without a call to the chain. Only that date is
    /// measured from the first payment: a block or block timestamp a listing
    /// shows is measured from the deployment
    /// ([`Self::with_vault_deployment_block`],
    /// [`Self::with_vault_deployment_time`]).
    #[must_use]
    pub fn with_vault_first_payment_time(mut self, time: u64) -> Self {
        self.vault_first_payment_time = Some(time);
        self
    }

    /// The payment vault's address.
    #[must_use]
    pub fn vault(&self) -> &[u8; 20] {
        &self.vault
    }

    /// The block the payment vault was deployed in, where known.
    #[must_use]
    pub fn vault_deployment_block(&self) -> Option<u64> {
        self.vault_deployment_block
    }

    /// The timestamp (Unix seconds) of the block the payment vault was
    /// deployed in, where known.
    #[must_use]
    pub fn vault_deployment_time(&self) -> Option<u64> {
        self.vault_deployment_time
    }

    /// The timestamp (Unix seconds) of the block of the payment vault's
    /// first payment, where known.
    #[must_use]
    pub fn vault_first_payment_time(&self) -> Option<u64> {
        self.vault_first_payment_time
    }

    /// The time no payment to the vault is in a block timed earlier than,
    /// where known: the later of its deployment's and its first payment's.
    fn no_payment_before(&self) -> Option<u64> {
        self.vault_deployment_time
            .max(self.vault_first_payment_time)
    }

    /// Whether a block timed `time` (Unix seconds) is timed earlier than the
    /// block the payment vault was deployed in, so that nothing in it can be
    /// a payment to the vault. False where that time isn't known.
    #[must_use]
    pub fn timed_before_vault_deployment(&self, time: u64) -> bool {
        self.vault_deployment_time
            .is_some_and(|deployed_at| time < deployed_at)
    }

    /// Whether block `block` is earlier than the one the payment vault was
    /// deployed in, so that nothing in it can be a payment to the vault.
    /// False where that block isn't known.
    #[must_use]
    pub fn before_vault_deployment(&self, block: u64) -> bool {
        self.vault_deployment_block
            .is_some_and(|deployed| block < deployed)
    }

    /// Check an upload proof from the chain alone: the receipt of its
    /// transaction and that block's timestamp.
    ///
    /// # Errors
    ///
    /// Returns why the proof fails, or why the chain couldn't be read.
    pub async fn check_proof(
        &self,
        proof: &EnvelopeProof,
    ) -> std::result::Result<ProvenUpload, String> {
        let (receipt, timestamp) = self
            .transaction(&proof.tx_hash)
            .await?
            .ok_or("the payment transaction is not on chain")?;
        ant_listings::check_proof(proof, &receipt, timestamp, &self.vault)
            .map_err(|e| e.to_string())
    }

    /// The vault's record of the payment for `quote_hash`, as its
    /// `completedPayments(bytes32)` holds it: the first 16 bytes of the
    /// rewards address paid, and the amount, zero when nothing is recorded.
    /// An upload reads back the record of every quote it paid. Read anew
    /// every time: it is the vault's state, not a fact.
    ///
    /// # Errors
    ///
    /// Returns every RPC's error if none answers, or why the answer can't be
    /// decoded.
    pub async fn completed_payment(
        &self,
        quote_hash: &QuoteHash,
    ) -> std::result::Result<VaultRecord, String> {
        use alloy::sol_types::SolCall as _;
        use ant_protocol::evm::contract::payment_vault::interface::IPaymentVault;

        let data = IPaymentVault::completedPaymentsCall(*quote_hash).abi_encode();
        let answer = self
            .rpc
            .call(
                "eth_call",
                json!([
                    {
                        "to": format!("0x{}", hex::encode(self.vault)),
                        "data": format!("0x{}", hex::encode(data)),
                    },
                    "latest",
                ]),
            )
            .await?
            .value;
        let bytes = answer
            .as_str()
            .and_then(|hex| hex::decode(hex.trim_start_matches("0x")).ok())
            .ok_or("payment chain eth_call: the answer is not hex")?;
        let record = IPaymentVault::completedPaymentsCall::abi_decode_returns(&bytes)
            .map_err(|e| format!("payment chain eth_call: {e}"))?;
        Ok(VaultRecord {
            rewards_prefix: record.rewardsAddress.0,
            amount: Amount::from(record.amount),
        })
    }

    /// The receipt of `tx_hash` (as little of it as a check reads: whether
    /// it succeeded, its block, and the vault's logs in it) and its block's
    /// timestamp, or `None` if the chain doesn't know the transaction (yet).
    ///
    /// # Errors
    ///
    /// Returns an error if a call fails or the answer is malformed.
    pub async fn transaction(
        &self,
        tx_hash: &[u8; 32],
    ) -> std::result::Result<Option<(PaymentReceipt, u64)>, String> {
        Ok(self.transactions(&[*tx_hash]).await?.pop().flatten())
    }

    /// Everything the chain has for `lookup` (see
    /// [`ant_listings::payment_lookup`]), made for a listing showing `shown`:
    /// the receipts it locates, each with its block's timestamp, or for
    /// [`Lookup::Block`] only the block's timestamp. Empty when nothing was
    /// found.
    ///
    /// For [`Lookup::Quote`], only payments of the quote that could be the
    /// one the listing describes are read: those at its log index and in a
    /// block of its timestamp, where it shows them. Without a block number
    /// the search starts at the block of `search_from` and runs forwards, up
    /// to the block of `not_after` (or the latest), stopping at the first
    /// range with such a payment, since the earliest payment is the one that
    /// counts; if that finds nothing, it runs backwards from `search_from`.
    /// A shown timestamp narrows the search to the blocks of that second
    /// instead. Either way it makes at most 64 log queries. The blocks at a
    /// time are found as darwin-node finds them: between the nearest blocks
    /// already read, guessed from their timestamps. A quote's payments, once
    /// found and final, are kept with a store, and the search is not made
    /// again: the vault records a quote's payment once.
    ///
    /// # Errors
    ///
    /// Returns an error if a call fails or an answer is malformed.
    pub async fn fetch(
        &self,
        lookup: &Lookup,
        shown: &ListingPayment,
    ) -> std::result::Result<Fetched, String> {
        match *lookup {
            Lookup::Transaction { tx_hash } => Ok(self
                .transaction(&tx_hash)
                .await?
                .map(|(receipt, timestamp)| vec![(Some(receipt), Some(timestamp))])
                .unwrap_or_default()),
            Lookup::Quote {
                quote_hash,
                block_number,
                search_from,
                not_after,
            } => {
                let known = self
                    .facts
                    .as_ref()
                    .and_then(|facts| facts.quote(&quote_hash));
                let logs = match known {
                    Some(payments) => {
                        self.payments_shown(&payments.value, block_number, not_after, shown)
                            .await?
                    }
                    None => {
                        let topics = [Some(DATA_PAYMENT_MADE_TOPIC), None, None, Some(quote_hash)];
                        let (logs, seen) = match block_number {
                            // One block: one timestamp, so only the log index
                            // can tell its payments apart.
                            Some(block) => {
                                let seen = self.vault_logs(&topics, block, block).await?;
                                (at_log_index(seen.clone(), shown.log_index), seen)
                            }
                            None => {
                                self.search_quote_logs(&topics, search_from, not_after, shown)
                                    .await?
                            }
                        };
                        if let Some(facts) = &self.facts {
                            if !seen.is_empty() {
                                let payments: BTreeSet<VaultLog> = seen.into_iter().collect();
                                facts.hold_quote(quote_hash, payments.into_iter().collect());
                            }
                        }
                        logs
                    }
                };
                let fetched = self.receipts_for(&logs).await?;
                self.settle_quote(&quote_hash).await;
                Ok(fetched)
            }
            Lookup::BlockLog {
                block_number,
                log_index,
            } => {
                let known = self
                    .facts
                    .as_ref()
                    .and_then(|facts| facts.block_log(block_number, log_index));
                let logs = match known {
                    Some(tx_hash) => vec![VaultLog {
                        tx_hash: tx_hash.value,
                        block_number,
                        log_index,
                    }],
                    None => {
                        let topics = [Some(DATA_PAYMENT_MADE_TOPIC), None, None, None];
                        let logs = at_log_index(
                            self.vault_logs(&topics, block_number, block_number).await?,
                            Some(log_index),
                        );
                        if let (Some(facts), Some(log)) = (&self.facts, logs.first()) {
                            facts.hold_block_log(block_number, log_index, log.tx_hash);
                        }
                        logs
                    }
                };
                let fetched = self.receipts_for(&logs).await?;
                self.settle_block_log(block_number, log_index).await;
                Ok(fetched)
            }
            Lookup::Block { block_number } => {
                let known = self.block_times(&[block_number]).await?.pop().flatten();
                if let Some(known) = &known {
                    self.settle(&[], &[(block_number, known.clone())]).await;
                }
                Ok(vec![(None, known.map(|known| known.value))])
            }
            Lookup::Nothing => Ok(Vec::new()),
        }
    }

    /// Of a quote's payments (all it has: the vault records a quote's
    /// payment once), those its search would find for a listing showing
    /// `shown`: at its log index; in block `block_number` if given; else in
    /// a block of its timestamp, where it shows one, or timed no later than
    /// `not_after`, where given.
    async fn payments_shown(
        &self,
        payments: &[VaultLog],
        block_number: Option<u64>,
        not_after: Option<u64>,
        shown: &ListingPayment,
    ) -> std::result::Result<Vec<VaultLog>, String> {
        let candidates: Vec<VaultLog> = at_log_index(payments.to_vec(), shown.log_index)
            .into_iter()
            .filter(|payment| block_number.is_none_or(|block| payment.block_number == block))
            .collect();
        let timed = |timestamp: u64| match (block_number, shown.block_timestamp, not_after) {
            (Some(_), _, _) | (None, None, None) => true,
            (None, Some(shown), _) => timestamp == shown,
            (None, None, Some(not_after)) => timestamp <= not_after,
        };
        if block_number.is_some() || (shown.block_timestamp.is_none() && not_after.is_none()) {
            return Ok(candidates);
        }
        let numbers: Vec<u64> = candidates
            .iter()
            .map(|payment| payment.block_number)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let times = self.block_times(&numbers).await?;
        let known: Vec<(u64, Known<u64>)> = numbers
            .iter()
            .zip(&times)
            .filter_map(|(number, time)| Some((*number, time.clone()?)))
            .collect();
        self.settle(&[], &known).await;
        Ok(candidates
            .into_iter()
            .filter(|payment| {
                known
                    .iter()
                    .any(|(number, time)| *number == payment.block_number && timed(time.value))
            })
            .collect())
    }

    /// The receipt and block timestamp of each of `tx_hashes`, `None` where
    /// the chain doesn't know the transaction: each as kept or held where it
    /// is, else read, those unknown together. What was read is then kept
    /// where it is final ([`Self::settle`]).
    async fn transactions(
        &self,
        tx_hashes: &[[u8; 32]],
    ) -> std::result::Result<Vec<Option<(PaymentReceipt, u64)>>, String> {
        let receipts = self.receipts(tx_hashes).await?;
        let numbers: Vec<u64> = receipts
            .iter()
            .flatten()
            .map(|receipt| receipt.value.block_number)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let times = self.block_times(&numbers).await?;
        let mut blocks: Vec<(u64, Known<u64>)> = Vec::with_capacity(numbers.len());
        for (number, time) in numbers.into_iter().zip(times) {
            blocks.push((number, time.ok_or("the receipt's block is missing")?));
        }
        let read: Vec<Known<PaymentReceipt>> = receipts.iter().flatten().cloned().collect();
        self.settle(&read, &blocks).await;
        Ok(receipts
            .into_iter()
            .map(|receipt| {
                let receipt = receipt?.value;
                let (_, time) = blocks
                    .iter()
                    .find(|(number, _)| *number == receipt.block_number)?;
                Some((receipt, time.value))
            })
            .collect())
    }

    /// The receipt of each of `tx_hashes`, `None` where the chain doesn't
    /// know it: kept or held where it is, else read in one batch.
    async fn receipts(
        &self,
        tx_hashes: &[[u8; 32]],
    ) -> std::result::Result<Vec<Option<Known<PaymentReceipt>>>, String> {
        let mut found: Vec<Option<Known<PaymentReceipt>>> = tx_hashes
            .iter()
            .map(|tx_hash| self.facts.as_ref().and_then(|facts| facts.receipt(tx_hash)))
            .collect();
        let missing: Vec<usize> = (0..tx_hashes.len())
            .filter(|i| found[*i].is_none())
            .collect();
        if missing.is_empty() {
            return Ok(found);
        }
        let calls: Vec<Call> = missing
            .iter()
            .map(|i| {
                Call::new(
                    "eth_getTransactionReceipt",
                    json!([format!("0x{}", hex::encode(tx_hashes[*i]))]),
                )
            })
            .collect();
        for (i, answer) in missing.into_iter().zip(self.rpc.batch(&calls).await) {
            let Answer { value, provider } = answer?;
            if value.is_null() {
                continue;
            }
            let receipt = parse_receipt(tx_hashes[i], &value, &self.vault)?;
            found[i] = Some(Known::read(receipt, provider));
        }
        Ok(found)
    }

    /// The timestamp of each of blocks `numbers`, `None` where there is no
    /// such block: kept or held where it is, else read in one batch.
    async fn block_times(
        &self,
        numbers: &[u64],
    ) -> std::result::Result<Vec<Option<Known<u64>>>, String> {
        let mut found: Vec<Option<Known<u64>>> = numbers
            .iter()
            .map(|number| self.facts.as_ref().and_then(|facts| facts.block(*number)))
            .collect();
        let missing: Vec<usize> = (0..numbers.len()).filter(|i| found[*i].is_none()).collect();
        if missing.is_empty() {
            return Ok(found);
        }
        let calls: Vec<Call> = missing
            .iter()
            .map(|i| {
                Call::new(
                    "eth_getBlockByNumber",
                    json!([quantity(numbers[*i]), false]),
                )
            })
            .collect();
        for (i, answer) in missing.into_iter().zip(self.rpc.batch(&calls).await) {
            let Answer { value, provider } = answer?;
            if value.is_null() {
                continue;
            }
            let timestamp = value["timestamp"]
                .as_str()
                .and_then(parse_u64)
                .ok_or("the block has no timestamp")?;
            self.remember_block(numbers[i], timestamp);
            found[i] = Some(Known::read(timestamp, provider));
        }
        Ok(found)
    }

    /// Hold what a lookup read and isn't kept yet, then keep for good every
    /// fact held that is final: each receipt and block timestamp whose block
    /// is at or below the finalized block, once a second provider returns
    /// the same ([`Self::confirm`]), and each quote's payments and block
    /// log whose receipts are then kept and show them. Facts above the
    /// finalized block stay held, and are used again until they are final;
    /// final ones that can't be kept are dropped, to be read again when
    /// next needed, so only facts not final yet are held for long. A block
    /// timestamp later than the clock is never held or kept. Nothing happens
    /// without a store.
    async fn settle(&self, receipts: &[Known<PaymentReceipt>], blocks: &[(u64, Known<u64>)]) {
        let Some(facts) = &self.facts else {
            return;
        };
        let now = unix_now();
        for known in receipts.iter().filter(|known| !known.kept) {
            if let Some(source) = known.source {
                facts.hold_receipt(&known.value, source);
            }
        }
        for (number, known) in blocks.iter().filter(|(_, known)| !known.kept) {
            match known.source {
                // A time in the future: never kept.
                _ if known.value > now => facts.forget_block(*number),
                Some(source) => facts.hold_block(*number, known.value, source),
                None => {}
            }
        }
        let Some(highest) = facts.highest_held() else {
            return;
        };
        let Some(finalized) = self.finalized_for(highest).await else {
            return;
        };
        let (final_receipts, final_blocks) = facts.take_final(finalized);
        let unconfirmed: Vec<Unconfirmed> =
            final_receipts
                .into_iter()
                .map(|(receipt, source)| Unconfirmed::Receipt(receipt, source))
                .chain(final_blocks.into_iter().map(|(number, timestamp, source)| {
                    Unconfirmed::Block(number, timestamp, source)
                }))
                .collect();
        if !unconfirmed.is_empty() {
            let keep = self.confirm(facts, unconfirmed).await;
            facts.keep(&keep);
        }
        let (quotes, block_logs) = facts.take_final_payments(finalized);
        let kept_and_shown = |payment: &VaultLog, quote_hash: Option<&[u8; 32]>| {
            facts
                .kept_receipt(&payment.tx_hash)
                .is_some_and(|receipt| shows_payment(&receipt, payment, quote_hash))
        };
        let mut keep = Keep::default();
        for (quote_hash, payments) in quotes {
            if payments
                .iter()
                .all(|payment| kept_and_shown(payment, Some(&quote_hash)))
            {
                keep.quotes.push((quote_hash, payments));
            }
        }
        for ((block, log_index), tx_hash) in block_logs {
            let payment = VaultLog {
                tx_hash,
                block_number: block,
                log_index,
            };
            if kept_and_shown(&payment, None) {
                keep.block_logs.push(((block, log_index), tx_hash));
            }
        }
        facts.keep(&keep);
    }

    /// Of facts read through one provider, those another returns the same:
    /// each is asked of the providers on another host in turn, until one
    /// agrees, those asked of one provider together. A fact none agrees
    /// with is dropped from what `facts` hold.
    async fn confirm(&self, facts: &Facts, unconfirmed: Vec<Unconfirmed>) -> Keep {
        let mut keep = Keep::default();
        let mut left: Vec<(Unconfirmed, Vec<usize>)> = unconfirmed
            .into_iter()
            .map(|fact| {
                let others = self.rpc.others(Kind::Chain, fact.source());
                (fact, others)
            })
            .collect();
        while !left.is_empty() {
            let mut asking: BTreeMap<usize, Vec<(Unconfirmed, Vec<usize>)>> = BTreeMap::new();
            for (fact, mut others) in left.drain(..) {
                others.retain(|provider| !self.rpc.is_held(*provider));
                match others.first() {
                    Some(provider) => asking.entry(*provider).or_default().push((fact, others)),
                    None => {
                        debug!(
                            "No other RPC confirmed {}: not kept, read again when needed",
                            fact.describe()
                        );
                        fact.forget(facts);
                    }
                }
            }
            for (provider, facts_asked) in asking {
                let calls: Vec<Call> = facts_asked.iter().map(|(fact, _)| fact.call()).collect();
                let answers = self.rpc.batch_to(provider, Kind::Chain, &calls).await;
                for ((fact, mut others), answer) in facts_asked.into_iter().zip(answers) {
                    match answer {
                        Ok(value) if fact.agrees(&value, &self.vault) => match fact {
                            Unconfirmed::Receipt(receipt, _) => keep.receipts.push(receipt),
                            Unconfirmed::Block(number, timestamp, _) => {
                                keep.blocks.push((number, timestamp));
                            }
                        },
                        Ok(_) => {
                            debug!(
                                "The RPCs at {} and {} disagree on {}",
                                self.rpc.host(fact.source()),
                                self.rpc.host(provider),
                                fact.describe()
                            );
                            others.remove(0);
                            left.push((fact, others));
                        }
                        Err(e) => {
                            debug!("Could not confirm {}: {e}", fact.describe());
                            others.remove(0);
                            left.push((fact, others));
                        }
                    }
                }
            }
        }
        keep
    }

    /// The finalized block, for a fact in block `block`: as last read, read
    /// again only when it is below `block` and was last asked for at least
    /// [`FINALIZED_REFRESH`] ago. `None` if never read.
    async fn finalized_for(&self, block: u64) -> Option<u64> {
        let facts = self.facts.as_ref()?;
        let mut finalized = facts.finalized.lock().await;
        let fresh = finalized
            .asked_at
            .is_some_and(|asked_at| asked_at.elapsed() < FINALIZED_REFRESH);
        if fresh || finalized.block.is_some_and(|known| known >= block) {
            return finalized.block;
        }
        finalized.asked_at = Some(tokio::time::Instant::now());
        match self.finalized_block().await {
            // Finality never goes back, whatever one provider says.
            Ok(number) => finalized.block = finalized.block.max(Some(number)),
            Err(e) => debug!("Could not read the finalized block: {e}"),
        }
        finalized.block
    }

    /// The number of the latest block the chain has finalized: nothing at
    /// or before it can change.
    async fn finalized_block(&self) -> std::result::Result<u64, String> {
        self.rpc
            .call("eth_getBlockByNumber", json!(["finalized", false]))
            .await?
            .value["number"]
            .as_str()
            .and_then(parse_u64)
            .ok_or_else(|| "the finalized block has no number".into())
    }

    /// Keep the payments held for `quote_hash` for good if the receipt of
    /// each is kept and shows it, reading the receipts not read yet (of
    /// payments at another log index than the listing's) as any other
    /// ([`Self::transactions`]). Otherwise they stay held until they are
    /// final, and are then kept or dropped ([`Self::settle`]).
    async fn settle_quote(&self, quote_hash: &[u8; 32]) {
        let Some(facts) = &self.facts else {
            return;
        };
        let Some(held) = facts.quote(quote_hash).filter(|known| !known.kept) else {
            return;
        };
        if self.payments_kept(&held.value, Some(quote_hash)).await {
            facts.keep(&Keep {
                quotes: vec![(*quote_hash, held.value)],
                ..Keep::default()
            });
        }
    }

    /// Keep the transaction held for the vault's log at `log_index` in block
    /// `block` for good if its receipt is kept and shows the log, as
    /// [`Self::settle_quote`] keeps a quote's payments.
    async fn settle_block_log(&self, block: u64, log_index: u64) {
        let Some(facts) = &self.facts else {
            return;
        };
        let Some(held) = facts
            .block_log(block, log_index)
            .filter(|known| !known.kept)
        else {
            return;
        };
        let payment = VaultLog {
            tx_hash: held.value,
            block_number: block,
            log_index,
        };
        if self.payments_kept(&[payment], None).await {
            facts.keep(&Keep {
                block_logs: vec![((block, log_index), held.value)],
                ..Keep::default()
            });
        }
    }

    /// Whether the receipt of each of `payments`, found by log queries, is
    /// kept and shows it ([`shows_payment`], of `quote_hash` where given),
    /// once the receipts neither kept nor held are read.
    async fn payments_kept(&self, payments: &[VaultLog], quote_hash: Option<&[u8; 32]>) -> bool {
        let Some(facts) = &self.facts else {
            return false;
        };
        let unread: Vec<[u8; 32]> = payments
            .iter()
            .map(|payment| payment.tx_hash)
            .filter(|tx_hash| facts.receipt(tx_hash).is_none())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if !unread.is_empty() && self.transactions(&unread).await.is_err() {
            return false;
        }
        payments.iter().all(|payment| {
            facts
                .kept_receipt(&payment.tx_hash)
                .is_some_and(|receipt| shows_payment(&receipt, payment, quote_hash))
        })
    }

    /// The latest block's number.
    async fn latest_block(&self) -> std::result::Result<u64, String> {
        self.rpc
            .call("eth_blockNumber", json!([]))
            .await?
            .value
            .as_str()
            .and_then(parse_u64)
            .ok_or_else(|| "no block number".into())
    }

    /// Keep the timestamp of block `number` for later searches by time.
    fn remember_block(&self, number: u64, timestamp: u64) {
        let mut known = self
            .known_blocks
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if known.len() >= MAX_KNOWN_BLOCKS && !known.contains_key(&number) {
            // Every other one goes: the rest still spread over every time
            // searched for, a little less finely.
            let mut keep = false;
            known.retain(|_, _| {
                keep = !keep;
                keep
            });
        }
        known.insert(number, timestamp);
    }

    /// The timestamp of block `number` as read before, if it was.
    fn known_block(&self, number: u64) -> Option<u64> {
        self.known_blocks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&number)
            .copied()
    }

    /// The timestamp of block `number`, as read before or kept, else read
    /// (and remembered, but not kept: a search reads many blocks only to
    /// find its way); an error if there is no such block.
    async fn timestamp_of(&self, number: u64) -> std::result::Result<u64, String> {
        if let Some(timestamp) = self.known_block(number) {
            return Ok(timestamp);
        }
        if let Some(known) = self.facts.as_ref().and_then(|facts| facts.block(number)) {
            self.remember_block(number, known.value);
            return Ok(known.value);
        }
        let block = self
            .rpc
            .call("eth_getBlockByNumber", json!([quantity(number), false]))
            .await?
            .value;
        if block.is_null() {
            return Err("a block before the latest is missing".into());
        }
        let timestamp = block["timestamp"]
            .as_str()
            .and_then(parse_u64)
            .ok_or("the block has no timestamp")?;
        self.remember_block(number, timestamp);
        Ok(timestamp)
    }

    /// The last block up to `latest` whose timestamp is at most `time`, or
    /// block 0 if there is none. The search starts between the nearest
    /// blocks already read on either side of `time`, and guesses from their
    /// timestamps where in between it is, as if blocks came at an even pace;
    /// after a guess that doesn't halve the range, the next step halves it.
    /// One call per step: a few where the chain's pace is steady or a nearby
    /// time was searched for before, at most about twice as many as halving
    /// alone where it isn't. darwin-node's search, ported.
    async fn block_at(&self, time: u64, latest: u64) -> std::result::Result<u64, String> {
        let latest_time = self.timestamp_of(latest).await?;
        if latest_time <= time {
            return Ok(latest);
        }
        // The answer is in `low..high`; `high`'s timestamp is after `time`,
        // `low`'s at most `time` once known.
        let (mut low, mut low_time) = (0, None);
        let (mut high, mut high_time) = (latest, latest_time);
        {
            let known = self
                .known_blocks
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            for (&number, &timestamp) in known.range(..latest) {
                if timestamp > time {
                    (high, high_time) = (number, timestamp);
                    break;
                }
                (low, low_time) = (number, Some(timestamp));
            }
        }
        let mut low_time = if let Some(timestamp) = low_time {
            timestamp
        } else {
            let timestamp = self.timestamp_of(low).await?;
            if timestamp > time {
                return Ok(low);
            }
            timestamp
        };
        let mut halve = false;
        while low + 1 < high {
            let width = high - low;
            let middle = if halve {
                low + width / 2
            } else {
                guess_block(time, (low, low_time), (high, high_time))
            };
            let timestamp = self.timestamp_of(middle).await?;
            if timestamp <= time {
                (low, low_time) = (middle, timestamp);
            } else {
                (high, high_time) = (middle, timestamp);
            }
            halve = !halve && (high - low) > width / 2;
        }
        Ok(low)
    }

    /// The first and last blocks up to `latest` timed exactly `time`, or
    /// `None` if no block is.
    async fn blocks_at(
        &self,
        time: u64,
        latest: u64,
    ) -> std::result::Result<Option<(u64, u64)>, String> {
        let last = self.block_at(time, latest).await?;
        if self.timestamp_of(last).await? != time {
            return Ok(None);
        }
        let Some(before) = time.checked_sub(1) else {
            return Ok(Some((0, last)));
        };
        // Before `last`, whose timestamp is after `before`; block 0 if no
        // block is timed before `time`.
        let previous = self.block_at(before, last).await?;
        if self.timestamp_of(previous).await? > before {
            return Ok(Some((previous, last)));
        }
        Ok(Some((previous + 1, last)))
    }

    /// The payments of a quote that could be the one a listing showing
    /// `shown` describes, searched for from the block at `search_from`, or in
    /// the blocks of the shown timestamp (see [`Self::fetch`]); and every
    /// payment of the quote the search's log queries came across, at any log
    /// index.
    async fn search_quote_logs(
        &self,
        topics: &[Option<[u8; 32]>; 4],
        search_from: u64,
        not_after: Option<u64>,
        shown: &ListingPayment,
    ) -> std::result::Result<(Vec<VaultLog>, Vec<VaultLog>), String> {
        let mut seen = Vec::new();
        let latest = self.latest_block().await?;
        let (first, last) = if let Some(time) = shown.block_timestamp {
            let Some(blocks) = self.blocks_at(time, latest).await? else {
                return Ok((Vec::new(), seen));
            };
            blocks
        } else {
            let last = match not_after {
                Some(time) => self.block_at(time, latest).await?,
                None => latest,
            };
            (self.block_at(search_from, last).await?, last)
        };
        let mut budget = MAX_LOG_CALLS;
        let mut range = last - first + 1;
        let mut narrowed = false;
        // Forwards from the quote's time.
        let mut from = first;
        while from <= last && budget > 0 {
            let to = from.saturating_add(range - 1).min(last);
            budget -= 1;
            match self.vault_logs(topics, from, to).await {
                Ok(logs) => {
                    seen.extend(logs.iter().copied());
                    let logs = at_log_index(logs, shown.log_index);
                    if !logs.is_empty() {
                        return Ok((logs, seen));
                    }
                    match to.checked_add(1) {
                        Some(next) => from = next,
                        None => break,
                    }
                }
                Err(e) if range > MIN_LOG_RANGE => {
                    debug!("Narrowing a log search after: {e}");
                    range = (range / 2).max(MIN_LOG_RANGE);
                    narrowed = true;
                }
                Err(e) => return Err(e),
            }
        }
        if shown.block_timestamp.is_some() {
            // The payment is in one of those blocks, or not on chain.
            return Ok((Vec::new(), seen));
        }
        // The quote's time is its signer's word: look back from it too, as
        // widely as the chain allows.
        if !narrowed {
            range = range.max(BACK_LOG_RANGE);
        }
        let mut to = first;
        while to > 0 && budget > 0 {
            let to_block = to - 1;
            let from_block = to_block.saturating_sub(range - 1);
            budget -= 1;
            match self.vault_logs(topics, from_block, to_block).await {
                Ok(logs) => {
                    seen.extend(logs.iter().copied());
                    let logs = at_log_index(logs, shown.log_index);
                    if !logs.is_empty() {
                        return Ok((logs, seen));
                    }
                    to = from_block;
                }
                Err(e) if range > MIN_LOG_RANGE => {
                    debug!("Narrowing a log search after: {e}");
                    range = (range / 2).max(MIN_LOG_RANGE);
                }
                Err(e) => return Err(e),
            }
        }
        Ok((Vec::new(), seen))
    }

    /// The vault's logs matching `topics` (`None` = any) in blocks
    /// `from..=to`.
    async fn vault_logs(
        &self,
        topics: &[Option<[u8; 32]>; 4],
        from: u64,
        to: u64,
    ) -> std::result::Result<Vec<VaultLog>, String> {
        let topics: Vec<Value> = topics
            .iter()
            .map(|topic| match topic {
                Some(topic) => json!(format!("0x{}", hex::encode(topic))),
                None => Value::Null,
            })
            .collect();
        let filter = json!({
            "address": format!("0x{}", hex::encode(self.vault)),
            "fromBlock": quantity(from),
            "toBlock": quantity(to),
            "topics": topics,
        });
        let logs = self.rpc.call("eth_getLogs", json!([filter])).await?.value;
        logs.as_array()
            .ok_or("logs are not a list")?
            .iter()
            .map(|log| parse_vault_log(log).ok_or_else(|| "a log is incomplete".to_string()))
            .collect()
    }

    /// The receipt of each transaction among `logs`, once, with its block's
    /// timestamp. Transactions the chain no longer knows are left out.
    async fn receipts_for(&self, logs: &[VaultLog]) -> std::result::Result<Fetched, String> {
        let tx_hashes: Vec<[u8; 32]> = logs
            .iter()
            .map(|log| log.tx_hash)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(self
            .transactions(&tx_hashes)
            .await?
            .into_iter()
            .flatten()
            .map(|(receipt, timestamp)| (Some(receipt), Some(timestamp)))
            .collect())
    }
}

/// The RPCs a reader of `network` reads through, the order of its log
/// queries (indexes into them; `None` for the same order), and the chain
/// each must say it is on, where checked: on the bundled network with
/// `listed` (the value of [`RPC_URLS_ENV`]), those listed, in that order for
/// everything, each checked to be on the network's chain; otherwise the
/// network's own RPC and then the RPCs it falls back to
/// ([`crate::config::fallback_rpc_urls`]), log queries going to the first
/// fallback first.
fn rpc_setup(network: &EvmNetwork, listed: Option<&str>) -> std::result::Result<RpcSetup, String> {
    if let (Some(chain_id), Some(listed)) = (crate::config::chain_id(network), listed) {
        let urls: Vec<String> = listed.split_whitespace().map(str::to_string).collect();
        if !urls.is_empty() {
            for (n, url) in urls.iter().enumerate() {
                let parsed = url::Url::parse(url).ok().filter(|url| {
                    matches!(url.scheme(), "http" | "https") && url.host_str().is_some()
                });
                if parsed.is_none() {
                    // The entry itself may hold a key: only its place is
                    // named.
                    return Err(format!(
                        "payment chain client: entry {} of {RPC_URLS_ENV} is not an http(s) URL",
                        n + 1
                    ));
                }
            }
            return Ok(RpcSetup {
                urls,
                logs_order: None,
                chain_id: Some(chain_id),
            });
        }
    }
    let mut urls = vec![network.rpc_url().to_string()];
    urls.extend(crate::config::fallback_rpc_urls(network));
    let logs_order = (urls.len() > 1).then(|| {
        let mut order = vec![1, 0];
        order.extend(2..urls.len());
        order
    });
    Ok(RpcSetup {
        urls,
        logs_order,
        chain_id: None,
    })
}

/// The RPCs a reader reads through ([`rpc_setup`]).
#[derive(Debug, Clone, PartialEq, Eq)]
struct RpcSetup {
    /// Their URLs, in the order of everything but log queries.
    urls: Vec<String>,
    /// The order of log queries, as indexes into `urls`; `None` for the
    /// same order.
    logs_order: Option<Vec<usize>>,
    /// The chain each must say it is on before it is used, where checked.
    chain_id: Option<u64>,
}

/// The receipt in `answer`, an `eth_getTransactionReceipt` answer for
/// `tx_hash`, as little of it as a check reads: whether it succeeded, its
/// block, and `vault`'s logs in it.
fn parse_receipt(
    tx_hash: [u8; 32],
    answer: &Value,
    vault: &[u8; 20],
) -> std::result::Result<PaymentReceipt, String> {
    let block_number = answer["blockNumber"]
        .as_str()
        .and_then(parse_u64)
        .ok_or("the receipt has no block number")?;
    Ok(PaymentReceipt {
        tx_hash,
        success: answer["status"].as_str() == Some("0x1"),
        block_number,
        logs: answer["logs"]
            .as_array()
            .map(|logs| {
                logs.iter()
                    .filter_map(parse_log)
                    .filter(|log| log.address == *vault)
                    .collect()
            })
            .unwrap_or_default(),
    })
}

/// Whether `receipt` shows `payment`: it is the payment's transaction, in
/// its block, with the vault's `DataPaymentMade` log at its log index, of
/// `quote_hash` where given. `receipt` holds only the vault's logs.
fn shows_payment(
    receipt: &PaymentReceipt,
    payment: &VaultLog,
    quote_hash: Option<&[u8; 32]>,
) -> bool {
    receipt.tx_hash == payment.tx_hash
        && receipt.block_number == payment.block_number
        && receipt.logs.iter().any(|log| {
            log.log_index == payment.log_index
                && log.topics.first() == Some(&DATA_PAYMENT_MADE_TOPIC)
                && quote_hash.is_none_or(|quote_hash| log.topics.get(3) == Some(quote_hash))
        })
}

/// Where between blocks `low` and `high` the last block timed at most `time`
/// should be, from their timestamps, if blocks came at an even pace: a block
/// strictly between them. `low`'s timestamp is at most `time`, `high`'s after
/// it, and at least one block lies between them.
fn guess_block(time: u64, (low, low_time): (u64, u64), (high, high_time): (u64, u64)) -> u64 {
    let blocks = u128::from(high - low);
    let elapsed = u128::from(time.saturating_sub(low_time));
    let span = u128::from(high_time.saturating_sub(low_time)).max(1);
    let offset = u64::try_from(elapsed * blocks / span).unwrap_or(u64::MAX);
    low.saturating_add(offset).clamp(low + 1, high - 1)
}

/// The logs at `log_index`, or all of them if it is hidden. A listing that
/// shows its log index describes no payment elsewhere.
fn at_log_index(logs: Vec<VaultLog>, log_index: Option<u64>) -> Vec<VaultLog> {
    match log_index {
        Some(index) => logs
            .into_iter()
            .filter(|log| log.log_index == index)
            .collect(),
        None => logs,
    }
}

fn parse_log(log: &Value) -> Option<PaymentLog> {
    Some(PaymentLog {
        address: parse_bytes(log["address"].as_str()?)?,
        topics: log["topics"]
            .as_array()?
            .iter()
            .map(|topic| topic.as_str().and_then(parse_bytes))
            .collect::<Option<Vec<[u8; 32]>>>()?,
        log_index: parse_u64(log["logIndex"].as_str()?)?,
    })
}

/// Where an `eth_getLogs` log is, or `None` if it is incomplete (a pending
/// log has no block).
fn parse_vault_log(log: &Value) -> Option<VaultLog> {
    Some(VaultLog {
        tx_hash: parse_bytes(log["transactionHash"].as_str()?)?,
        block_number: parse_u64(log["blockNumber"].as_str()?)?,
        log_index: parse_u64(log["logIndex"].as_str()?)?,
    })
}

fn quantity(number: u64) -> String {
    format!("0x{number:x}")
}

fn parse_u64(hex: &str) -> Option<u64> {
    u64::from_str_radix(hex.trim_start_matches("0x"), 16).ok()
}

fn parse_bytes<const N: usize>(hex: &str) -> Option<[u8; N]> {
    hex::decode(hex.trim_start_matches("0x"))
        .ok()?
        .try_into()
        .ok()
}

/// A JSON-RPC payment chain in memory, served over HTTP, for tests.
#[cfg(test)]
pub(crate) mod test_chain {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// The vault the tests pay into.
    pub(crate) const VAULT: [u8; 20] = [0x69; 20];

    /// Receipts (each with the block it is in), and block timestamps.
    #[derive(Default)]
    pub(crate) struct MockChain {
        pub(crate) receipts: HashMap<[u8; 32], PaymentReceipt>,
        pub(crate) blocks: BTreeMap<u64, u64>,
        /// The widest block range `eth_getLogs` answers, as providers cap
        /// it; wider ones get a JSON-RPC error.
        pub(crate) max_log_range: Option<u64>,
        /// Methods answered with HTTP 403, as PublicNode answers
        /// `eth_getLogs`.
        pub(crate) refused: Vec<&'static str>,
        /// Methods answered with a JSON-RPC error of this code, such as
        /// -32005 from a provider over its request limit.
        pub(crate) failing: Vec<(&'static str, i64)>,
        /// The vault's `completedPayments` records by quote hash: the first
        /// 16 bytes of the rewards address paid, and the amount.
        pub(crate) vault_records: HashMap<[u8; 32], ([u8; 16], u128)>,
        /// The block the chain reports as finalized; the latest when
        /// `None`.
        pub(crate) finalized: Option<u64>,
        /// The chain `eth_chainId` names.
        pub(crate) chain_id: u64,
        /// The methods called, in order.
        pub(crate) calls: Vec<String>,
        /// The id of every call, in order.
        pub(crate) ids: Vec<u64>,
        /// How many HTTP requests came: a batch is one.
        pub(crate) requests: usize,
    }

    impl MockChain {
        /// Blocks `0..blocks`, two seconds apart from `start`.
        pub(crate) fn with_blocks(blocks: u64, start: u64) -> Self {
            Self {
                blocks: (0..blocks)
                    .map(|number| (number, start + number * 2))
                    .collect(),
                ..Self::default()
            }
        }

        pub(crate) fn add_receipt(&mut self, receipt: PaymentReceipt) {
            self.receipts.insert(receipt.tx_hash, receipt);
        }

        /// How many calls of `method` were made.
        pub(crate) fn calls_to(&self, method: &str) -> usize {
            self.calls.iter().filter(|call| *call == method).count()
        }

        /// The result of a call, or a JSON-RPC error message.
        fn answer(&self, method: &str, params: &Value) -> std::result::Result<Value, String> {
            if method == "eth_getLogs" {
                let filter = &params[0];
                let bound = |key: &str| filter[key].as_str().and_then(parse_u64).unwrap_or(0);
                let blocks = bound("toBlock").saturating_sub(bound("fromBlock")) + 1;
                if self.max_log_range.is_some_and(|max| blocks > max) {
                    return Err(format!("block range too wide: {blocks}"));
                }
            }
            Ok(self.result(method, params))
        }

        fn result(&self, method: &str, params: &Value) -> Value {
            match method {
                "eth_getTransactionReceipt" => {
                    let hash = params[0].as_str().and_then(parse_bytes::<32>);
                    match hash.and_then(|hash| self.receipts.get(&hash)) {
                        Some(receipt) => receipt_json(receipt),
                        None => Value::Null,
                    }
                }
                "eth_getBlockByNumber" => {
                    let latest = self.blocks.keys().next_back().copied().unwrap_or(0);
                    let number = match params[0].as_str() {
                        Some("finalized") => Some(self.finalized.unwrap_or(latest)),
                        Some("latest") => Some(latest),
                        Some(number) => parse_u64(number),
                        None => None,
                    };
                    match number.and_then(|number| Some((number, self.blocks.get(&number)?))) {
                        Some((number, timestamp)) => json!({
                            "number": quantity(number),
                            "timestamp": quantity(*timestamp),
                        }),
                        None => Value::Null,
                    }
                }
                "eth_blockNumber" => json!(quantity(
                    self.blocks.keys().next_back().copied().unwrap_or(0)
                )),
                "eth_chainId" => json!(quantity(self.chain_id)),
                "eth_getLogs" => {
                    let filter = &params[0];
                    let from = filter["fromBlock"]
                        .as_str()
                        .and_then(parse_u64)
                        .unwrap_or(0);
                    let to = filter["toBlock"].as_str().and_then(parse_u64).unwrap_or(0);
                    // Only the contract asked about, as a chain answers.
                    let address = filter["address"].as_str().and_then(parse_bytes::<20>);
                    let topics: Vec<Option<[u8; 32]>> = filter["topics"]
                        .as_array()
                        .map(|topics| {
                            topics
                                .iter()
                                .map(|topic| topic.as_str().and_then(parse_bytes::<32>))
                                .collect()
                        })
                        .unwrap_or_default();
                    let mut logs = Vec::new();
                    for receipt in self.receipts.values() {
                        if receipt.block_number < from || receipt.block_number > to {
                            continue;
                        }
                        for log in &receipt.logs {
                            let matches = address.is_none_or(|address| log.address == address)
                                && topics.iter().enumerate().all(|(i, topic)| {
                                    topic.is_none_or(|topic| log.topics.get(i) == Some(&topic))
                                });
                            if matches {
                                logs.push(json!({
                                    "transactionHash": format!("0x{}", hex::encode(receipt.tx_hash)),
                                    "blockNumber": quantity(receipt.block_number),
                                    "logIndex": quantity(log.log_index),
                                }));
                            }
                        }
                    }
                    Value::Array(logs)
                }
                "eth_call" => self.vault_call(&params[0]),
                _ => Value::Null,
            }
        }

        /// An `eth_call` of the vault's `completedPayments(bytes32)`, ABI
        /// encoded as the vault returns it; `0x`, as a chain answers a call
        /// to an address with no such function, for anything else.
        fn vault_call(&self, call: &Value) -> Value {
            let to = call["to"].as_str().and_then(parse_bytes::<20>);
            let data = call["data"]
                .as_str()
                .and_then(|data| hex::decode(data.trim_start_matches("0x")).ok())
                .unwrap_or_default();
            let selector = alloy::primitives::keccak256(b"completedPayments(bytes32)");
            if to != Some(VAULT) || data.len() != 36 || data[..4] != selector[..4] {
                return json!("0x");
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&data[4..]);
            let (prefix, amount) = self.vault_records.get(&hash).copied().unwrap_or_default();
            let mut words = [0u8; 64];
            words[..16].copy_from_slice(&prefix);
            words[48..].copy_from_slice(&amount.to_be_bytes());
            json!(format!("0x{}", hex::encode(words)))
        }
    }

    fn receipt_json(receipt: &PaymentReceipt) -> Value {
        json!({
            "status": if receipt.success { "0x1" } else { "0x0" },
            "blockNumber": quantity(receipt.block_number),
            "logs": receipt.logs.iter().map(|log| json!({
                "address": format!("0x{}", hex::encode(log.address)),
                "topics": log.topics.iter().map(|t| format!("0x{}", hex::encode(t))).collect::<Vec<_>>(),
                "logIndex": quantity(log.log_index),
            })).collect::<Vec<_>>(),
        })
    }

    /// Serve `chain` on a local port; the RPC URL. It answers one call, or
    /// a batch of them, each by its own id. A request with a call of a
    /// method it refuses gets HTTP 403.
    pub(crate) async fn serve(chain: Arc<Mutex<MockChain>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("address"));
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let chain = Arc::clone(&chain);
                tokio::spawn(async move {
                    let Some(body) = read_request(&mut socket).await else {
                        return;
                    };
                    let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                    let (calls, batch) = match &request {
                        Value::Array(calls) => (calls.clone(), true),
                        _ => (vec![request.clone()], false),
                    };
                    let answers = {
                        let mut chain = chain.lock().expect("chain lock");
                        chain.requests += 1;
                        let mut refused = false;
                        let mut answers = Vec::new();
                        for call in &calls {
                            let method = call["method"].as_str().unwrap_or_default().to_string();
                            let id = call["id"].clone();
                            if let Some(id) = id.as_u64() {
                                chain.ids.push(id);
                            }
                            chain.calls.push(method.clone());
                            refused |= chain.refused.iter().any(|refused| *refused == method);
                            let answer =
                                match chain.failing.iter().find(|(name, _)| *name == method) {
                                    Some((_, code)) => Err((*code, format!("{method} refused"))),
                                    None => chain
                                        .answer(&method, &call["params"])
                                        .map_err(|message| (-32_000, message)),
                                };
                            answers.push(match answer {
                                Ok(result) => {
                                    json!({ "jsonrpc": "2.0", "id": id, "result": result })
                                }
                                Err((code, message)) => json!({
                                    "jsonrpc": "2.0",
                                    "id": id,
                                    "error": { "code": code, "message": message },
                                }),
                            });
                        }
                        (!refused).then_some(answers)
                    };
                    let Some(mut answers) = answers else {
                        let _ = socket
                            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                            .await;
                        let _ = socket.shutdown().await;
                        return;
                    };
                    let body = if batch {
                        Value::Array(answers)
                    } else {
                        answers.pop().unwrap_or(Value::Null)
                    }
                    .to_string();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        url
    }

    async fn read_request(socket: &mut tokio::net::TcpStream) -> Option<Vec<u8>> {
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let read = socket.read(&mut chunk).await.ok()?;
            if read == 0 {
                return None;
            }
            buffer.extend_from_slice(&chunk[..read]);
            let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            let head = String::from_utf8_lossy(&buffer[..end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            let body_start = end + 4;
            while buffer.len() < body_start + length {
                let read = socket.read(&mut chunk).await.ok()?;
                if read == 0 {
                    return None;
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
            return Some(buffer[body_start..body_start + length].to_vec());
        }
    }

    /// A vault log paying `quote` (rewards address and amount as the vault
    /// emits them).
    pub(crate) fn paying_log(
        quote: &ant_protocol::evm::PaymentQuote,
        log_index: u64,
    ) -> PaymentLog {
        let mut rewards = [0u8; 32];
        rewards[12..].copy_from_slice(quote.rewards_address.as_slice());
        let mut amount = [0u8; 32];
        amount[31] = 30;
        PaymentLog {
            address: VAULT,
            topics: vec![DATA_PAYMENT_MADE_TOPIC, rewards, amount, quote.hash().0],
            log_index,
        }
    }

    /// A signed quote for `content`, at a whole second.
    pub(crate) fn signed_quote(content: [u8; 32], price: u64) -> ant_protocol::evm::PaymentQuote {
        use ant_protocol::evm::{Amount, PaymentQuote, RewardsAddress};
        let identity = ant_protocol::transport::NodeIdentity::generate().expect("identity");
        let mut quote = PaymentQuote {
            content: xor_name::XorName(content),
            timestamp: std::time::UNIX_EPOCH + Duration::from_secs(1_800_000_000),
            price: Amount::from(price),
            rewards_address: RewardsAddress::new([price as u8; 20]),
            pub_key: identity.public_key().as_bytes().to_vec(),
            signature: Vec::new(),
            committed_key_count: 0,
            commitment_pin: None,
        };
        quote.signature = identity
            .sign(&quote.bytes_for_sig())
            .expect("sign")
            .as_bytes()
            .to_vec();
        quote
    }

    /// A chain reader for `url` with the test vault.
    pub(crate) fn reader(url: String) -> ListingChain {
        ListingChain::with_rpc(url, VAULT).expect("reader")
    }
}

#[cfg(test)]
mod tests {
    use super::test_chain::{paying_log, reader, serve, signed_quote, MockChain, VAULT};
    use super::*;
    use ant_listings::{
        first_seen_at, Flags, ListingError, Metadata, Payment, PaymentField, ShownFields,
    };
    use ant_protocol::compute_address;
    use std::sync::{Arc, Mutex};

    const NEAREST: [u8; 7] = [1, 2, 3, 4, 5, 6, 7];

    fn reported_listing(block_number: u64, first_seen: u64) -> Listing {
        Listing {
            address: [7; 32],
            flags: Flags {
                shown: ShownFields::NONE.with(PaymentField::BlockNumber),
                in_index: true,
                withheld: false,
            },
            metadata: Metadata::default(),
            size: Some(4_000),
            payment: ListingPayment {
                block_number: Some(block_number),
                ..ListingPayment::default()
            },
            first_seen: Some(first_seen),
        }
    }

    fn reported(_: &Listing) -> std::result::Result<ListingCheck, ant_listings::PaymentError> {
        Ok(ListingCheck {
            level: CheckLevel::Reported,
            paid_at: None,
        })
    }

    /// Merge `copies`, check each group with `check` among `nearest` as
    /// [`check_copies`] does, and decide with `expected` nearest nodes.
    fn decide_among(
        copies: Vec<(u8, Listing)>,
        nearest: &[u8],
        expected: usize,
        check: impl Fn(&Listing) -> std::result::Result<ListingCheck, PaymentError>,
    ) -> (Option<CountingListing>, RejectedGroups) {
        let groups = merge_copies(copies);
        let needed = quorum_needed(expected.max(nearest.len()));
        let checked = groups
            .iter()
            .map(|group| check_copies(group, nearest, needed, &check).map_err(CheckProblem::from))
            .collect();
        decide_address(&groups, checked, nearest, expected)
    }

    /// Merge `copies`, check each group with `check` among [`NEAREST`], and
    /// decide.
    fn decide(
        copies: Vec<(u8, Listing)>,
        check: impl Fn(&Listing) -> std::result::Result<ListingCheck, PaymentError>,
    ) -> (Option<CountingListing>, RejectedGroups) {
        decide_among(copies, &NEAREST, NEAREST.len(), check)
    }

    #[test]
    fn copies_differing_only_in_first_seen_merge_and_a_quorum_dates_them() {
        let hour = FIRST_SEEN_ROUNDING;
        let base = 1_790_996_400;
        let copies: Vec<(u8, Listing)> = [(1, 0), (2, 1), (3, 1), (4, 2), (5, 3)]
            .into_iter()
            .map(|(peer, hours)| (peer, reported_listing(100, base + hours * hour)))
            .collect();
        let groups = merge_copies(copies.clone());
        assert_eq!(groups.len(), 1);
        let (chosen, rejected) = decide(copies, reported);
        assert!(rejected.is_empty());
        let (listing, level, nodes, quorum) = chosen.expect("a quorum serves it");
        assert_eq!(level, CheckLevel::Reported);
        assert_eq!((nodes, quorum), (5, true));
        // Of 0, 1, 1, 2, 3 hours, four date it at 2 hours or earlier (the
        // median, 1 hour, has only three).
        assert_eq!(listing.first_seen, Some(base + 2 * hour));
    }

    #[test]
    fn a_listing_without_its_quote_needs_four_of_the_seven_nearest() {
        let first_seen = 1_790_996_400;
        let served_by = |peers: &[u8]| -> Vec<(u8, Listing)> {
            peers
                .iter()
                .map(|peer| (*peer, reported_listing(100, first_seen)))
                .collect()
        };
        let (chosen, _) = decide(served_by(&[1, 2, 3, 4]), reported);
        assert_eq!(chosen.map(|(_, _, nodes, _)| nodes), Some(4));
        let (chosen, rejected) = decide(served_by(&[1, 2, 3]), reported);
        assert!(chosen.is_none());
        assert_eq!(rejected.len(), 1);
        assert!(rejected[0]
            .1
            .contains("reported by 3 of the 7 nodes nearest its address, needs 4"));
        // Copies from nodes that aren't among the nearest don't count.
        let (chosen, _) = decide(served_by(&[1, 2, 3, 40, 41, 42]), reported);
        assert!(chosen.is_none());
        // A node serving a listing nobody else has.
        let (chosen, rejected) = decide(served_by(&[1]), reported);
        assert!(chosen.is_none());
        assert_eq!(rejected.len(), 1);
    }

    #[test]
    fn three_nodes_serving_a_changed_listing_are_outvoted() {
        let first_seen = 1_790_996_400;
        let mut copies: Vec<(u8, Listing)> = [1, 2, 3, 4]
            .into_iter()
            .map(|peer| (peer, reported_listing(100, first_seen)))
            .collect();
        copies.extend(
            [5, 6, 7]
                .into_iter()
                .map(|peer| (peer, reported_listing(99, first_seen))),
        );
        let (chosen, rejected) = decide(copies, reported);
        let (listing, _, nodes, _) = chosen.expect("the four agree");
        assert_eq!(listing.payment.block_number, Some(100));
        assert_eq!(nodes, 4);
        assert_eq!(rejected.len(), 1);
        assert!(rejected[0].1.contains("reported by 3"));
        // A peer that sent two different copies counts for neither.
        let mut copies: Vec<(u8, Listing)> = [1, 2, 3, 4]
            .into_iter()
            .map(|peer| (peer, reported_listing(100, first_seen)))
            .collect();
        copies.push((4, reported_listing(99, first_seen)));
        let (chosen, _) = decide(copies, reported);
        assert!(chosen.is_none());
    }

    /// Merge `copies`, check each group as reported among `nearest`, and
    /// decide with `expected` nearest nodes.
    fn decide_reported_among(
        copies: Vec<(u8, Listing)>,
        nearest: &[u8],
        expected: usize,
    ) -> (Option<CountingListing>, RejectedGroups) {
        decide_among(copies, nearest, expected, reported)
    }

    fn served_by(peers: &[u8]) -> Vec<(u8, Listing)> {
        peers
            .iter()
            .map(|peer| (*peer, reported_listing(100, 1_790_996_400)))
            .collect()
    }

    #[test]
    fn a_short_lookup_never_lowers_the_quorum() {
        assert_eq!(expected_nearest(10_000), NEAREST_NODES);
        assert_eq!(expected_nearest(3), 3);
        // The lookup found 1 or 2 of the 7: one or two nodes serving a
        // listing that hides its quote are not a quorum, and the reason says
        // to try again.
        for found in [&[1u8][..], &[1, 2]] {
            let (chosen, rejected) = decide_reported_among(served_by(found), found, 7);
            assert!(chosen.is_none());
            assert_eq!(rejected.len(), 1);
            assert!(
                rejected[0].1.contains("too few nearest nodes found"),
                "{}",
                rejected[0].1
            );
        }
        // Four of the five found serve it: a quorum of the seven all the same.
        let (chosen, _) = decide_reported_among(served_by(&[1, 2, 3, 4]), &[1, 2, 3, 4, 5], 7);
        assert_eq!(
            chosen.map(|(_, _, nodes, quorum)| (nodes, quorum)),
            Some((4, true))
        );
        // On a network of three nodes, two of them are a quorum.
        let (chosen, _) =
            decide_reported_among(served_by(&[1, 2]), &[1, 2, 3], expected_nearest(3));
        assert_eq!(chosen.map(|(_, _, nodes, _)| nodes), Some(2));
        // A lookup that finds more than expected counts as found.
        let (chosen, rejected) = decide_reported_among(served_by(&[1, 2]), &NEAREST, 2);
        assert!(chosen.is_none());
        assert!(rejected[0].1.contains("reported by 2 of the 7"));
    }

    #[test]
    fn a_network_size_given_never_lowers_the_quorum() {
        // A size under the close group's, or none, is found as
        // `Client::listing` finds it.
        assert_eq!(expected_nearest_given(None), None);
        for size in 0..NEAREST_NODES {
            assert_eq!(expected_nearest_given(Some(size)), None, "size {size}");
        }
        // Any other: all 7 nearest nodes are expected, and 4 of them are a
        // quorum.
        for size in [NEAREST_NODES, 20, usize::MAX] {
            let expected = expected_nearest_given(Some(size));
            assert_eq!(expected, Some(7), "size {size}");
            assert_eq!(expected.map(quorum_needed), Some(4), "size {size}");
        }
        // So on a network of 20 nodes, a lookup that finds a single node,
        // serving a listing that hides its quote, is no quorum whatever size
        // is given (one under 7 is found again, as the network's 20): the
        // listing is left out, to try again.
        for given in [Some(1), Some(NEAREST_NODES), Some(20), None] {
            let expected = expected_nearest_given(given).unwrap_or_else(|| expected_nearest(20));
            let (chosen, rejected) = decide_reported_among(served_by(&[1]), &[1], expected);
            assert!(chosen.is_none(), "{given:?}");
            assert!(
                rejected[0].1.contains("too few nearest nodes found"),
                "{given:?}: {}",
                rejected[0].1
            );
        }
    }

    #[test]
    fn nodes_already_heard_from_are_not_asked_again() {
        let groups = merge_copies(served_by(&[1, 2]));
        let needed = quorum_needed(NEAREST.len());
        let asked = |heard: &[u8], walked: &[(u8, u64)]| {
            let heard: HashSet<u8> = heard.iter().copied().collect();
            let walked: HashMap<u8, u64> = walked.iter().copied().collect();
            let mut to_ask = peers_to_ask(&groups, &NEAREST, needed, &heard, &walked);
            to_ask.sort_unstable();
            to_ask
        };
        // Reading the index: the nodes that sent a copy are heard; the other
        // nearest nodes are asked, unless a walk of their whole index began
        // late enough to answer for it.
        assert_eq!(asked(&[1, 2], &[]), vec![3, 4, 5, 6, 7]);
        let late = 1_790_996_400 + 3 * FIRST_SEEN_ROUNDING;
        assert_eq!(asked(&[1, 2], &[(3, late)]), vec![4, 5, 6, 7]);
        // `ant listing`: every nearest node was asked already, so none is
        // asked again.
        assert!(asked(&NEAREST, &[]).is_empty());
        // A listing a quorum serves needs no more answers, nor does any
        // other copy for its address: none can reach a quorum.
        let groups = merge_copies(served_by(&[1, 2, 3, 4]));
        assert!(peers_to_ask(
            &groups,
            &NEAREST,
            needed,
            &[1, 2, 3, 4].into_iter().collect(),
            &HashMap::new()
        )
        .is_empty());
        let mut copies = served_by(&[1, 2, 3, 4]);
        copies.push((5, reported_listing(99, 1_790_996_400)));
        let groups = merge_copies(copies);
        assert_eq!(groups.len(), 2);
        assert!(peers_to_ask(
            &groups,
            &NEAREST,
            needed,
            &[1, 2, 3, 4, 5].into_iter().collect(),
            &HashMap::new()
        )
        .is_empty());
    }

    #[test]
    fn a_listing_showing_its_quote_without_a_quorum_asks_the_others_too() {
        // A quoting node's own payment and the upload's, two nearest nodes
        // each: which counts, and whether it has a quorum, rests on the
        // nearest nodes not heard from yet.
        let mut copies = vec![(1, verified_listing(1)), (2, verified_listing(1))];
        copies.extend([(3, verified_listing(2)), (4, verified_listing(2))]);
        let groups = merge_copies(copies);
        let needed = quorum_needed(NEAREST.len());
        let heard: HashSet<u8> = [1, 2, 3, 4].into_iter().collect();
        let mut to_ask = peers_to_ask(&groups, &NEAREST, needed, &heard, &HashMap::new());
        to_ask.sort_unstable();
        assert_eq!(to_ask, vec![5, 6, 7]);
        // Once four serve one of them, nothing more is asked.
        let mut copies = vec![(1, verified_listing(1))];
        copies.extend([2, 3, 4, 5].map(|peer| (peer, verified_listing(2))));
        let groups = merge_copies(copies);
        let heard: HashSet<u8> = [1, 2, 3, 4, 5].into_iter().collect();
        assert!(peers_to_ask(&groups, &NEAREST, needed, &heard, &HashMap::new()).is_empty());
    }

    fn verified_listing(quote: u8) -> Listing {
        Listing {
            address: [7; 32],
            flags: Flags {
                shown: ShownFields::ALL,
                in_index: true,
                withheld: false,
            },
            metadata: Metadata::default(),
            size: Some(4_000),
            payment: ListingPayment {
                tx_hash: Some([quote; 32]),
                block_number: Some(100 + u64::from(quote)),
                block_timestamp: Some(1_790_996_400 + u64::from(quote)),
                log_index: Some(1),
                quote: Some(vec![quote; 8]),
            },
            first_seen: None,
        }
    }

    #[test]
    fn of_several_verified_payments_the_one_a_quorum_serves_counts() {
        // A quoting node paid first (block 101) and serves its own copy; the
        // close group serves the uploader's (block 102).
        let mut copies = vec![(1, verified_listing(1))];
        copies.extend(
            [2, 3, 4, 5]
                .into_iter()
                .map(|peer| (peer, verified_listing(2))),
        );
        let verified = |listing: &Listing| {
            Ok(ListingCheck {
                level: CheckLevel::Verified,
                paid_at: Some(PaidAt {
                    block_number: listing.payment.block_number.unwrap_or_default(),
                    log_index: 1,
                }),
            })
        };
        let (chosen, rejected) = decide(copies.clone(), verified);
        let (listing, level, nodes, quorum) = chosen.expect("verified");
        assert_eq!(level, CheckLevel::Verified);
        assert_eq!(listing.payment.block_number, Some(102));
        assert_eq!((nodes, quorum), (4, true));
        assert_eq!(rejected.len(), 1);
        // Without a quorum for any, the earliest stands in, marked.
        let (chosen, _) = decide(copies[..3].to_vec(), verified);
        let (listing, _, nodes, quorum) = chosen.expect("verified");
        assert_eq!(listing.payment.block_number, Some(101));
        assert_eq!((nodes, quorum), (1, false));
    }

    #[test]
    fn a_short_lookup_marks_a_verified_listing_without_a_quorum() {
        let verified = |listing: &Listing| {
            Ok(ListingCheck {
                level: CheckLevel::Verified,
                paid_at: Some(PaidAt {
                    block_number: listing.payment.block_number.unwrap_or_default(),
                    log_index: 1,
                }),
            })
        };
        // Three nearest nodes found of seven: two serving the later payment
        // are not a quorum, so the earliest stands in, marked.
        let copies = vec![
            (1, verified_listing(1)),
            (2, verified_listing(2)),
            (3, verified_listing(2)),
        ];
        let (chosen, rejected) = decide_among(copies, &[1u8, 2, 3], 7, verified);
        let (listing, level, nodes, quorum) = chosen.expect("verified");
        assert_eq!(level, CheckLevel::Verified);
        assert_eq!(listing.payment.block_number, Some(101));
        assert_eq!((nodes, quorum), (1, false));
        assert_eq!(rejected.len(), 1);
    }

    #[test]
    fn the_verified_choice_prefers_a_quorum_then_the_earliest() {
        let at = |block_number| PaidAt {
            block_number,
            log_index: 0,
        };
        assert_eq!(
            choose_verified_with_quorum(Vec::<((), usize, PaidAt)>::new(), 4),
            None
        );
        // The quorum's payment, though a later one.
        assert_eq!(
            choose_verified_with_quorum(vec![('a', 1, at(5)), ('b', 4, at(9)), ('c', 5, at(7))], 4),
            Some(('c', 5, at(7), true))
        );
        // None with a quorum: the earliest, unmarked; the first on a tie.
        assert_eq!(
            choose_verified_with_quorum(vec![('a', 3, at(9)), ('b', 2, at(5)), ('c', 1, at(5))], 4),
            Some(('b', 2, at(5), false))
        );
    }

    #[test]
    fn walks_from_a_time_start_early_enough_for_every_first_seen() {
        assert_eq!(walk_start(0), ListingKey::MIN);
        let start = walk_start(1_790_996_400);
        assert_eq!(
            start.time,
            1_790_996_400 - FIRST_SEEN_ROUNDING - CLOCK_MARGIN
        );
        assert_eq!(start.block_number, 0);
        assert_eq!(walk_start(5).time, 0);
    }

    #[tokio::test]
    async fn the_chain_is_read_for_every_lookup() {
        let quote = signed_quote([7; 32], 20);
        let mut chain = MockChain::with_blocks(200, 1_800_000_000);
        chain.add_receipt(PaymentReceipt {
            tx_hash: [0xaa; 32],
            success: true,
            block_number: 150,
            logs: vec![paying_log(&quote, 4)],
        });
        let url = serve(Arc::new(Mutex::new(chain))).await;
        let chain = reader(url);
        let shown = ListingPayment::default();
        assert_eq!(chain.vault(), &VAULT);

        let fetch = |lookup: Lookup| {
            let (chain, shown) = (&chain, &shown);
            async move { chain.fetch(&lookup, shown).await.unwrap() }
        };

        let by_tx = fetch(Lookup::Transaction {
            tx_hash: [0xaa; 32],
        })
        .await;
        assert_eq!(by_tx.len(), 1);
        assert_eq!(by_tx[0].1, Some(1_800_000_300));
        assert!(fetch(Lookup::Transaction {
            tx_hash: [0xbb; 32]
        })
        .await
        .is_empty());

        let by_quote = |block_number| Lookup::Quote {
            quote_hash: quote.hash().0,
            block_number,
            search_from: 1_800_000_000,
            not_after: None,
        };
        assert_eq!(fetch(by_quote(Some(150))).await.len(), 1);
        assert!(fetch(by_quote(Some(149))).await.is_empty());
        assert_eq!(fetch(by_quote(None)).await.len(), 1);

        let at = |log_index| Lookup::BlockLog {
            block_number: 150,
            log_index,
        };
        assert_eq!(fetch(at(4)).await.len(), 1);
        assert!(fetch(at(5)).await.is_empty());

        let block = fetch(Lookup::Block { block_number: 10 }).await;
        assert_eq!(block, vec![(None, Some(1_800_000_020))]);
        let missing = fetch(Lookup::Block { block_number: 999 }).await;
        assert_eq!(missing, vec![(None, None)]);
        assert!(fetch(Lookup::Nothing).await.is_empty());
    }

    #[tokio::test]
    async fn a_listing_hiding_its_quote_is_checked_as_far_as_it_shows() {
        // An envelope paid in block 150, log 4, of a transaction that paid
        // other chunks too.
        let map = {
            let (map, _) = self_encryption::encrypt(bytes::Bytes::from(vec![1u8; 4000])).unwrap();
            map
        };
        let shown = ShownFields::NONE
            .with(PaymentField::BlockNumber)
            .with(PaymentField::LogIndex);
        let envelope = Envelope::readable(&map, Metadata::default(), shown, true).unwrap();
        let quote = signed_quote(envelope.address(), 20);
        let mut chain = MockChain::with_blocks(200, 1_800_000_000);
        chain.add_receipt(PaymentReceipt {
            tx_hash: [0xaa; 32],
            success: true,
            block_number: 150,
            logs: vec![
                paying_log(&signed_quote([3; 32], 20), 3),
                paying_log(&quote, 4),
            ],
        });
        let url = serve(Arc::new(Mutex::new(chain))).await;
        let chain = reader(url);
        let payment = ant_listings::Payment {
            tx_hash: [0xaa; 32],
            block_number: 150,
            block_timestamp: 1_800_000_300,
            log_index: 4,
            quote: rmp_serde::to_vec(&quote).unwrap(),
        };
        let listing = Listing::new(&envelope, &payment, 1_800_000_400);
        assert_eq!(listing.payment.tx_hash, None);
        let now = 1_800_000_500;
        let copies: Vec<(u8, Listing)> = NEAREST[..4]
            .iter()
            .map(|peer| (*peer, listing.clone()))
            .collect();
        let groups = merge_copies(copies);
        let checked = check_group(&groups[0], &envelope, &NEAREST, 4, &chain, now).await;
        let (checked_listing, check) = checked.expect("checks out");
        assert_eq!(check.level, CheckLevel::Reported);
        assert_eq!(checked_listing.first_seen, listing.first_seen);
        let (chosen, rejected) = decide_address(
            &groups,
            vec![Ok((checked_listing, check))],
            &NEAREST,
            NEAREST.len(),
        );
        assert!(rejected.is_empty());
        assert_eq!(chosen.map(|(_, _, nodes, _)| nodes), Some(4));

        // A changed log index points at another chunk's payment: still a
        // vault payment, so only the quorum stands behind it; a log index
        // with no vault payment fails.
        let mut tampered = listing.clone();
        tampered.payment.log_index = Some(9);
        let groups = merge_copies(vec![(1u8, tampered)]);
        assert!(check_group(&groups[0], &envelope, &NEAREST, 4, &chain, now)
            .await
            .is_err());
    }

    /// When the upload's payment was made: block 150 of a
    /// [`MockChain::with_blocks`] chain from 1,800,000,000.
    const BLOCK_TIME: u64 = 1_800_000_300;

    /// A readable envelope showing `shown`, in the index if `in_index`.
    fn envelope_showing(shown: ShownFields, in_index: bool) -> Envelope {
        let (map, _) = self_encryption::encrypt(bytes::Bytes::from(vec![1u8; 4000])).unwrap();
        Envelope::readable(&map, Metadata::default(), shown, in_index).unwrap()
    }

    /// The upload's payment of `envelope`: block 150, log index 4.
    fn upload_payment(envelope: &Envelope) -> Payment {
        Payment {
            tx_hash: [0xaa; 32],
            block_number: 150,
            block_timestamp: BLOCK_TIME,
            log_index: 4,
            quote: rmp_serde::to_vec(&signed_quote(envelope.address(), 20)).unwrap(),
        }
    }

    /// `listing` as each of `peers` sent it, with the date it gave.
    fn dated_copies(listing: &Listing, peers: &[u8], dates: &[u64]) -> Vec<(u8, Listing)> {
        peers
            .iter()
            .zip(dates)
            .map(|(peer, date)| {
                let mut copy = listing.clone();
                copy.first_seen = Some(*date);
                (*peer, copy)
            })
            .collect()
    }

    #[test]
    fn a_quorum_of_the_nearest_dates_a_listing_as_the_nodes_do() {
        // In the index, nothing shown: dated by first_seen alone, with
        // nothing on chain to bound it from below.
        let envelope = envelope_showing(ShownFields::NONE, true);
        let listing = Listing::new(&envelope, &upload_payment(&envelope), BLOCK_TIME);
        let hour = first_seen_at(BLOCK_TIME);
        assert_eq!(listing.first_seen, Some(hour));
        let h = FIRST_SEEN_ROUNDING;
        let now = hour + 3 * h;
        let check =
            |listing: &Listing| verify_listing_receipts(listing, &envelope, &[], &VAULT, now);
        let dated_by = |dates: &[u64]| {
            let (chosen, _) = decide(dated_copies(&listing, &NEAREST, dates), check);
            chosen.map(|(listing, ..)| listing.first_seen.expect("dated"))
        };

        // All seven answer: their median.
        assert_eq!(
            dated_by(&[0, 0, 1, 1, 2, 2, 3].map(|n| hour + n * h)),
            Some(hour + h)
        );
        // Fewer: the latest of the earliest four, so that four date it then
        // or earlier (the median would be an hour earlier). One dating it in
        // the future is not needed for that.
        assert_eq!(
            dated_by(&[0, 0, 1, 2, 100].map(|n| hour + n * h)),
            Some(hour + 2 * h)
        );
        // Three dating it in 1970 can't move it before the earliest date
        // another gives, however few others answer: the median of
        // [1970, 1970, 1970, hour, hour] would be 1970.
        assert_eq!(dated_by(&[0, 0, 0, hour]), Some(hour));
        assert_eq!(dated_by(&[0, 0, 0, hour, hour]), Some(hour));
        assert_eq!(dated_by(&[0, 0, 0, hour, hour - h]), Some(hour - h));
        // Nor with a date that fails: two dating it in 1970 and one in the
        // future leave three dates that pass, fewer than four, so the latest
        // of them dates it. Their median would be 1970.
        assert_eq!(dated_by(&[0, 0, hour + 100 * h, hour]), Some(hour));
        // Four answer and one dates it in the future: that date is dropped,
        // so one node can't fail a listing three others date honestly.
        assert_eq!(dated_by(&[hour, hour, hour, hour + 100 * h]), Some(hour));
        // Three: not a quorum, so a listing hiding its quote doesn't count.
        assert_eq!(dated_by(&[hour, hour, hour]), None);
    }

    #[test]
    fn only_the_nearest_nodes_date_a_listing() {
        let envelope = envelope_showing(ShownFields::NONE, true);
        let listing = Listing::new(&envelope, &upload_payment(&envelope), BLOCK_TIME);
        let hour = first_seen_at(BLOCK_TIME);
        let check =
            |listing: &Listing| verify_listing_receipts(listing, &envelope, &[], &VAULT, hour);
        // Four of the nearest date it at `hour`; ten other nodes dating it
        // in 1970 neither count nor move it.
        let mut copies = dated_copies(&listing, &NEAREST[..4], &[hour; 4]);
        let others: Vec<u8> = (40..50).collect();
        copies.extend(dated_copies(&listing, &others, &[0; 10]));
        let (chosen, rejected) = decide(copies, check);
        assert!(rejected.is_empty());
        let (dated, _, nodes, quorum) = chosen.expect("four of the nearest serve it");
        assert_eq!((dated.first_seen, nodes, quorum), (Some(hour), 4, true));
        // Served by other nodes alone, it doesn't count.
        let (chosen, rejected) = decide(dated_copies(&listing, &others, &[hour; 10]), check);
        assert!(chosen.is_none());
        assert_eq!(rejected.len(), 1);
    }

    /// A verified listing that hides its block timestamp, so it is dated by
    /// `first_seen`.
    fn dated_verified_listing(first_seen: u64) -> Listing {
        let mut listing = verified_listing(1);
        listing.flags.shown = ShownFields::ALL.without(PaymentField::BlockTimestamp);
        listing.payment.block_timestamp = None;
        listing.first_seen = Some(first_seen);
        listing
    }

    #[test]
    fn dates_out_of_bounds_count_only_as_the_nodes_count_them() {
        // The payment's block is timed `paid`: a date more than the rounding
        // and clock margin before it is too early; one after `now` is in the
        // future.
        let paid = 1_790_996_400;
        let h = FIRST_SEEN_ROUNDING;
        let now = paid + 10 * h;
        let check = |listing: &Listing| {
            let first_seen = listing.first_seen.expect("dated");
            if first_seen + FIRST_SEEN_ROUNDING + CLOCK_MARGIN < paid {
                Err(PaymentError::FirstSeenTooEarly)
            } else if first_seen > now + CLOCK_MARGIN {
                Err(PaymentError::Malformed(ListingError::TimeInFuture))
            } else {
                Ok(ListingCheck {
                    level: CheckLevel::Verified,
                    paid_at: Some(PaidAt {
                        block_number: 101,
                        log_index: 1,
                    }),
                })
            }
        };
        let dated_by = |dates: &[u64]| {
            let copies = dated_copies(&dated_verified_listing(paid), &NEAREST, dates);
            let (chosen, _) = decide(copies, check);
            chosen.map(|(listing, _, nodes, quorum)| (listing.first_seen, nodes, quorum))
        };
        let early = 0;

        // Without a quorum each date is checked on its own and the latest of
        // those that pass taken: one too early or in the future neither
        // fails the listing nor moves its date.
        assert_eq!(
            dated_by(&[early, paid, paid + h]),
            Some((Some(paid + h), 3, false))
        );
        assert_eq!(
            dated_by(&[early, paid, now + 100 * h]),
            Some((Some(paid), 3, false))
        );
        // With a quorum, dates that fail their own check are dropped first:
        // three dating it before its payment neither fail it nor date it.
        // Fewer than four dates are left, so it takes the latest of them.
        assert_eq!(
            dated_by(&[early, early, early, paid, paid + h]),
            Some((Some(paid + h), 5, true))
        );
        // Nor can three date it earlier by sending a date that fails: two
        // dating it as early as passes and one in the future leave three
        // dates that pass, fewer than four, so the latest of them dates it,
        // not their median, two hours before the payment.
        assert_eq!(
            dated_by(&[paid - 2 * h, paid - 2 * h, now + 100 * h, paid]),
            Some((Some(paid), 4, true))
        );
        // Where every date passes, the latest of the earliest four.
        assert_eq!(
            dated_by(&[paid, paid, paid, paid + h, paid + h]),
            Some((Some(paid + h), 5, true))
        );
        assert_eq!(
            dated_by(&[paid, paid, paid, paid, paid + h]),
            Some((Some(paid), 5, true))
        );
        // Four dating it before its payment, which no node can: those dates
        // are dropped, and the one that checks out dates it.
        assert_eq!(
            dated_by(&[early, early, early, early, paid]),
            Some((Some(paid), 5, true))
        );
    }

    fn peer(n: u8) -> PeerId {
        PeerId::from_bytes([n; 32])
    }

    /// A walk of `peer` from `from`, stopped at `reached` (`None`: to the
    /// end), begun at `began`.
    fn walk_of(
        peer: PeerId,
        from: ListingKey,
        reached: Option<ListingKey>,
        began: u64,
    ) -> NodeReport<PeerId> {
        NodeReport {
            peer,
            outcome: if reached.is_none() {
                WalkOutcome::Complete
            } else {
                WalkOutcome::Deadline
            },
            problem: None,
            from,
            reached,
            began: Some(began),
            pages: 3,
            listings: 600,
            backed: 300,
        }
    }

    #[test]
    fn walk_state_carries_on_stopped_walks_and_forgets_finished_ones() {
        let key = ListingKey {
            time: 1_800_000_000,
            block_number: 5,
            log_index: 1,
            address: [9; 32],
        };
        let stopped = WalkReport {
            peer: peer(1),
            outcome: WalkOutcome::Budget,
            problem: None,
            pages: 8,
            listings: 2_048,
            backed: 0,
            resume: Some(key),
        };
        let finished = WalkReport {
            peer: peer(2),
            outcome: WalkOutcome::Complete,
            problem: None,
            pages: 3,
            listings: 600,
            backed: 600,
            resume: None,
        };
        let mut state = WalkState::default();
        state.record(24, &[stopped.clone(), finished]);
        assert_eq!(state.resume_for(&peer(1)), Some(key));
        assert_eq!(state.resume_for(&peer(2)), None);
        assert_eq!(state.resuming(), 1);

        // It survives being saved, and an empty file is no state.
        let saved = serde_json::to_string(&state).unwrap();
        assert_eq!(serde_json::from_str::<WalkState>(&saved).unwrap(), state);
        assert_eq!(
            serde_json::from_str::<WalkState>("{}").unwrap(),
            WalkState::default()
        );

        // A walk that finishes forgets where it stopped before.
        state.record(
            24,
            &[WalkReport {
                resume: None,
                ..stopped
            }],
        );
        assert_eq!(state.resume_for(&peer(1)), None);

        // Only recent reads say how many nodes there should be.
        for nodes in [30, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10] {
            state.record(nodes, &[]);
        }
        assert_eq!(state.recent_max(), 10);
    }

    #[test]
    fn a_read_carries_what_it_did_not_decide() {
        let key = ListingKey {
            time: 1_800_000_000,
            block_number: 7,
            log_index: 0,
            address: [0x42; 32],
        };
        let late_enough = key.time + FIRST_SEEN_ROUNDING + CLOCK_MARGIN;
        let peers: Vec<PeerId> = (1..=8).map(peer).collect();
        let index_with = |walks: Vec<NodeReport<PeerId>>, served: bool, decided: bool| {
            let only = |yes: bool| {
                if yes {
                    HashSet::from([key.address])
                } else {
                    HashSet::new()
                }
            };
            ListingsIndex {
                coverage: Coverage {
                    since: 0,
                    ids: walks.iter().map(|walk| *walk.peer.as_bytes()).collect(),
                    walks,
                    served: only(served),
                    decided: only(decided),
                    gone: HashSet::new(),
                },
                ..ListingsIndex::default()
            }
        };
        let full = |began: u64| -> Vec<NodeReport<PeerId>> {
            peers
                .iter()
                .map(|peer| walk_of(*peer, ListingKey::MIN, None, began))
                .collect()
        };
        let carry = |index: &ListingsIndex| index.carry(&key.address, &key);

        assert_eq!(
            carry(&index_with(full(late_enough), true, true)),
            Carry::Decided
        );
        assert_eq!(
            carry(&index_with(full(late_enough), true, false)),
            Carry::Keep
        );
        // Every node nearest it walked past it, late enough, without
        // serving it.
        assert_eq!(
            carry(&index_with(full(late_enough), false, false)),
            Carry::NoLongerServed
        );
        // Walks that began too soon after its time may have passed its place
        // before the nodes stored it.
        assert_eq!(
            carry(&index_with(full(late_enough - 1), false, false)),
            Carry::Keep
        );
        // One of its nearest nodes stopped before reaching it.
        let ids: Vec<[u8; 32]> = peers.iter().map(|peer| *peer.as_bytes()).collect();
        let nearest = nearest_by_distance(&key.address, &ids, NEAREST_NODES);
        let mut walks = full(late_enough);
        walks[nearest[0]] = walk_of(peers[nearest[0]], ListingKey::MIN, Some(key), late_enough);
        assert_eq!(carry(&index_with(walks, false, false)), Carry::Keep);
        // A node further away doesn't count.
        let far = (0..peers.len())
            .find(|node| !nearest.contains(node))
            .expect("eight nodes");
        let mut walks = full(late_enough);
        walks[far] = walk_of(peers[far], ListingKey::MIN, Some(key), late_enough);
        assert_eq!(
            carry(&index_with(walks, false, false)),
            Carry::NoLongerServed
        );
        // A read that saw too few nodes never says a listing is gone.
        let mut index = index_with(full(late_enough), false, false);
        index.too_few_nodes = true;
        assert_eq!(carry(&index), Carry::Keep);
        assert_eq!(
            carry(&index_with(full(late_enough)[..6].to_vec(), false, false)),
            Carry::Keep
        );
    }

    #[test]
    fn a_listing_dated_before_since_leaves_the_earlier_entry_carried() {
        // An earlier read published a listing at `since`. This read, from
        // `since`, decides its address but dates it an hour earlier, as
        // another set of its nearest nodes can.
        let since = 1_800_000_000;
        let envelope = envelope_showing(ShownFields::NONE, true);
        let mut redated = Listing::new(&envelope, &upload_payment(&envelope), BLOCK_TIME);
        redated.first_seen = Some(since - FIRST_SEEN_ROUNDING);
        let address = redated.address;
        let published = ListingKey {
            time: since,
            block_number: 0,
            log_index: 0,
            address,
        };
        let listed = Decision {
            address,
            listing: Some(CheckedListing {
                listing: redated.clone(),
                envelope: envelope.clone(),
                level: CheckLevel::Reported,
                nodes: 4,
                nearest: 7,
                quorum: true,
            }),
            rejected: Vec::new(),
            decided: true,
        };
        // A read from `from`: every node walked, from the start of the read,
        // and four of the nearest served the address.
        let read = |from: u64| {
            let walks: Vec<NodeReport<PeerId>> = (1..=8)
                .map(|n| walk_of(peer(n), walk_start(from), None, since + 3_600))
                .collect();
            ListingsIndex {
                coverage: Coverage {
                    since: from,
                    ids: walks.iter().map(|walk| *walk.peer.as_bytes()).collect(),
                    walks,
                    served: HashSet::from([address]),
                    decided: HashSet::new(),
                    gone: HashSet::new(),
                },
                ..ListingsIndex::default()
            }
        };

        // Read from `since`: the listing is left out, and the earlier entry
        // kept as it was, since the read says nothing about listings
        // before `since`. It isn't lost.
        let mut index = read(since);
        index.settle(vec![listed]);
        assert!(index.listings.is_empty());
        assert_eq!(index.carry(&address, &published), Carry::Keep);

        // Read from the start: it is listed, and replaces the earlier entry.
        let listed = Decision {
            address,
            listing: Some(CheckedListing {
                listing: redated.clone(),
                envelope,
                level: CheckLevel::Reported,
                nodes: 4,
                nearest: 7,
                quorum: true,
            }),
            rejected: Vec::new(),
            decided: true,
        };
        let mut index = read(0);
        index.settle(vec![listed]);
        assert_eq!(index.listings.len(), 1);
        assert_eq!(index.carry(&address, &published), Carry::Decided);

        // An address rejected for good stays decided whatever the date of
        // what was rejected: the earlier entry goes.
        let rejected = Decision {
            address,
            listing: None,
            rejected: vec![RejectedListing {
                listing: redated,
                problem: "the payment is not on chain".into(),
                nodes: 4,
                nearest: 7,
                again: false,
            }],
            decided: true,
        };
        let mut index = read(since);
        index.settle(vec![rejected]);
        assert!(index.rejected.is_empty());
        assert_eq!(index.carry(&address, &published), Carry::Decided);
    }

    #[test]
    fn a_read_from_a_time_never_says_a_listing_is_gone() {
        // Three of the nearest nodes stored a listing that hides its time in
        // hour `stored`; four more were given it six hours later, so it was
        // published dated then, the latest of the earliest four. Those four
        // have since gone, and the first three still key it at `stored`.
        let stored = 1_790_996_400;
        let published = ListingKey {
            time: stored + 6 * FIRST_SEEN_ROUNDING,
            block_number: 0,
            log_index: 0,
            address: [0x42; 32],
        };
        let began = published.time + 3 * FIRST_SEEN_ROUNDING;
        let read = |since: u64| {
            let walks: Vec<NodeReport<PeerId>> = (1..=8)
                .map(|n| walk_of(peer(n), walk_start(since), None, began))
                .collect();
            ListingsIndex {
                coverage: Coverage {
                    since,
                    ids: walks.iter().map(|walk| *walk.peer.as_bytes()).collect(),
                    walks,
                    served: HashSet::new(),
                    decided: HashSet::new(),
                    gone: HashSet::new(),
                },
                ..ListingsIndex::default()
            }
        };

        // A read from the published time walks every node from two hours
        // before it, past the listing's place, late enough, and none sends
        // it: the three still serving it key it earlier. The read says
        // nothing about that, so the entry is kept.
        assert!(walk_start(published.time).time > stored);
        assert_eq!(
            read(published.time).carry(&published.address, &published),
            Carry::Keep
        );
        // A read of the whole index walks past every key a node can give
        // it: there, every nearest node walked late enough without a copy
        // still says it is gone.
        assert_eq!(
            read(0).carry(&published.address, &published),
            Carry::NoLongerServed
        );
    }

    #[test]
    fn only_a_walk_of_a_whole_index_answers_for_its_node() {
        // Three of the nearest nodes serve a listing in the index, dated
        // `hour`; the other four sent nothing for it.
        let hour = 1_790_996_400;
        let copies: Vec<(PeerId, Listing)> = (5..=7)
            .map(|n| (peer(n), reported_listing(100, hour)))
            .collect();
        let heard: HashSet<PeerId> = copies.iter().map(|(peer, _)| *peer).collect();
        let groups = merge_copies(copies);
        let nearest: Vec<PeerId> = (1..=7).map(peer).collect();
        let late = hour + 3 * FIRST_SEEN_ROUNDING;
        let context = ReadContext::new(
            &[
                // Node 1's whole index, from the start to the end.
                walk_of(peer(1), ListingKey::MIN, None, late),
                // Node 2's from a time, to the end, as a read from that time
                // walks it: the node may key the listing earlier.
                walk_of(peer(2), walk_start(hour), None, late),
                // Node 3's from the start, stopped before the end.
                walk_of(
                    peer(3),
                    ListingKey::MIN,
                    Some(ListingKey {
                        time: hour,
                        ..ListingKey::MIN
                    }),
                    late,
                ),
            ],
            HashMap::new(),
        );
        assert_eq!(context.full_walks, HashMap::from([(peer(1), late)]));
        // Only node 1's walk answers for it: the others are asked.
        assert_eq!(
            peers_to_ask(
                &groups,
                &nearest,
                QUORUM_THRESHOLD,
                &heard,
                &context.full_walks
            ),
            [peer(2), peer(3), peer(4)]
        );
    }

    #[test]
    fn an_address_too_few_serve_is_shown_to_try_again() {
        let nearest: Vec<PeerId> = (1..=7).map(peer).collect();
        let listing = verified_listing(1);
        let found = AddressWalk {
            address: listing.address,
            nearest,
            copies: vec![
                (peer(1), listing.clone()),
                (peer(2), listing.clone()),
                (peer(3), verified_listing(2)),
            ],
            support: 3,
        };
        let shown = pending_listing(&found).expect("served");
        assert!(shown.again);
        assert_eq!((shown.nodes, shown.nearest), (2, 7));
        assert_eq!(shown.listing, listing);
        assert!(shown.problem.contains("3 of the 7"), "{}", shown.problem);
    }

    #[test]
    fn every_address_too_few_serve_is_shown_with_each_copy() {
        let nearest: Vec<PeerId> = (1..=7).map(peer).collect();
        // The vault was deployed in block 102.
        let chain = reader("http://127.0.0.1:9".into()).with_vault_deployment_block(102);
        // One node alone serves a listing paid in block 101, hiding its time.
        let first_seen = 1_790_996_400;
        let early = dated_verified_listing(first_seen);
        let alone = AddressWalk {
            address: early.address,
            nearest: nearest.clone(),
            copies: vec![(peer(3), early)],
            support: 1,
        };
        // Two serve one paid in block 102, the farther one's copy first.
        let mut later = verified_listing(2);
        later.address = [8; 32];
        let pair = AddressWalk {
            address: later.address,
            nearest,
            copies: vec![(peer(2), later.clone()), (peer(1), later.clone())],
            support: 2,
        };
        let mut index = ListingsIndex::default();
        index.defer_pending(&[alone, pair], &chain);

        // Both are left for a later read and shown, the one a single node
        // serves too.
        assert_eq!(index.deferred, 2);
        let shown: Vec<(XorName, usize, bool)> = index
            .rejected
            .iter()
            .map(|rejected| (rejected.listing.address, rejected.nodes, rejected.again))
            .collect();
        assert_eq!(shown, [([7; 32], 1, true), ([8; 32], 2, true)]);
        // With each copy: its node, nearest first, what it shows of its
        // payment, and whether its block is before the vault was deployed.
        assert_eq!(
            index.pending_copies[&[7; 32]],
            [PendingCopy {
                node: peer(3),
                block_number: Some(101),
                block_timestamp: None,
                first_seen: Some(first_seen),
                before_vault_deployment: true,
            }]
        );
        let copy = |node| PendingCopy {
            node,
            block_number: later.payment.block_number,
            block_timestamp: later.payment.block_timestamp,
            first_seen: None,
            before_vault_deployment: false,
        };
        assert_eq!(
            index.pending_copies[&[8; 32]],
            [copy(peer(1)), copy(peer(2))]
        );
        assert_eq!(index.pending_copies[&[7; 32]][0].time(), first_seen);
        assert_eq!(index.pending_copies[&[8; 32]][0].time(), 1_790_996_402);

        // Where the block the vault was deployed in isn't known, no copy is
        // marked.
        let found = AddressWalk {
            address: [7; 32],
            nearest: (1..=7).map(peer).collect(),
            copies: vec![(peer(3), dated_verified_listing(first_seen))],
            support: 1,
        };
        let unknown = reader("http://127.0.0.1:9".into());
        assert!(!pending_copies(&found, &unknown)[0].before_vault_deployment);
    }

    #[test]
    fn a_pending_copy_is_marked_by_the_block_timestamp_it_shows_too() {
        // The vault was deployed in block 102, timed `deployed_at`.
        let deployed_at = 1_790_996_402;
        let chain = reader("http://127.0.0.1:9".into())
            .with_vault_deployment_block(102)
            .with_vault_deployment_time(deployed_at);
        // A copy showing its block timestamp but not its block.
        let timed = |time: u64| {
            let mut listing = verified_listing(2);
            listing.flags.shown = ShownFields::ALL.without(PaymentField::BlockNumber);
            listing.payment.block_number = None;
            listing.payment.block_timestamp = Some(time);
            listing
        };
        let marked = |listing: Listing| {
            let found = AddressWalk {
                address: listing.address,
                nearest: (1..=7).map(peer).collect(),
                copies: vec![(peer(1), listing)],
                support: 1,
            };
            pending_copies(&found, &chain)[0].before_vault_deployment
        };
        // Timed a second before the deployment: it can't have paid the
        // vault. At the deployment's second or later, it may have.
        assert!(marked(timed(deployed_at - 1)));
        assert!(!marked(timed(deployed_at)));
        assert!(!marked(timed(deployed_at + 3_600)));
        // A copy hiding its block timestamp is never marked by the date its
        // node gives it, however early, showing its block or not: one node's
        // date isn't its nearest nodes'.
        let mut dated = timed(0);
        dated.flags.shown = ShownFields::ALL.without(PaymentField::BlockTimestamp);
        dated.payment.block_number = Some(102);
        dated.payment.block_timestamp = None;
        dated.first_seen = Some(0);
        assert!(!marked(dated.clone()));
        dated.flags.shown = dated.flags.shown.without(PaymentField::BlockNumber);
        dated.payment.block_number = None;
        assert!(!marked(dated));
        // Where the deployment's time isn't known, no timestamp is marked.
        let unknown = reader("http://127.0.0.1:9".into()).with_vault_deployment_block(102);
        let found = AddressWalk {
            address: [7; 32],
            nearest: (1..=7).map(peer).collect(),
            copies: vec![(peer(1), timed(0))],
            support: 1,
        };
        assert!(!pending_copies(&found, &unknown)[0].before_vault_deployment);
        // A timestamp is marked from the deployment, not from the vault's
        // first payment.
        let first_paid_later = reader("http://127.0.0.1:9".into())
            .with_vault_deployment_block(102)
            .with_vault_deployment_time(deployed_at)
            .with_vault_first_payment_time(deployed_at + 7_200);
        let found = AddressWalk {
            copies: vec![(peer(1), timed(deployed_at))],
            ..found
        };
        assert!(!pending_copies(&found, &first_paid_later)[0].before_vault_deployment);
    }

    #[test]
    fn a_decision_with_nothing_final_is_tried_again() {
        let nearest: Vec<PeerId> = (1..=7).map(peer).collect();
        let groups = merge_copies([(peer(1), verified_listing(1))]);
        let envelope = envelope_showing(ShownFields::ALL, true);
        let decide = |problem: &str| {
            Decision::from_groups(
                [1; 32],
                &groups,
                &nearest,
                None,
                vec![(0, problem.into())],
                envelope.clone(),
                Vec::new(),
            )
        };
        let again = decide("could not read the payment chain: refused; try again");
        assert!(!again.decided);
        assert!(again.rejected[0].again);
        let done = decide("the payment is not on chain");
        assert!(done.decided);
        assert!(!done.rejected[0].again);
    }

    #[tokio::test]
    async fn the_listing_a_quorum_serves_is_tried_again_unless_it_fails() {
        // In the index, the tx hash shown: one receipt to read.
        let envelope = envelope_showing(ShownFields::NONE.with(PaymentField::TxHash), true);
        let payment = upload_payment(&envelope);
        let listing = Listing::new(&envelope, &payment, BLOCK_TIME);
        let nearest: Vec<PeerId> = (1..=7).map(peer).collect();
        let groups = merge_copies(nearest[..4].iter().map(|peer| (*peer, listing.clone())));
        let now = BLOCK_TIME + 3_600;
        let mock = || MockChain::with_blocks(200, 1_800_000_000);

        // The chain has no such transaction (yet): a quorum checked it on
        // chain when they stored it, so try again.
        let empty = reader(serve(Arc::new(Mutex::new(mock()))).await);
        let checked = check_quorum_group(&groups[0], &envelope, &nearest, &empty, now).await;
        assert!(
            matches!(&checked, Err(GroupProblem::Again(problem)) if is_again(problem)),
            "{:?}",
            checked.as_ref().err().map(|_| ())
        );

        // Once the chain has it, it checks out.
        let mut chain = mock();
        let quote: ant_protocol::evm::PaymentQuote = rmp_serde::from_slice(&payment.quote).unwrap();
        chain.add_receipt(PaymentReceipt {
            tx_hash: payment.tx_hash,
            success: true,
            block_number: 150,
            logs: vec![paying_log(&quote, 4)],
        });
        let chain = reader(serve(Arc::new(Mutex::new(chain))).await);
        let (dated, check) =
            match check_quorum_group(&groups[0], &envelope, &nearest, &chain, now).await {
                Ok(checked) => checked,
                Err(GroupProblem::Again(p) | GroupProblem::Invalid(p)) => panic!("{p}"),
            };
        assert_eq!(check.level, CheckLevel::Reported);
        assert_eq!(dated.first_seen, listing.first_seen);

        // A listing that doesn't describe its envelope fails for good.
        let mut changed = listing.clone();
        changed.metadata.name = Some("other.txt".into());
        let groups = merge_copies(nearest[..4].iter().map(|peer| (*peer, changed.clone())));
        assert!(matches!(
            check_quorum_group(&groups[0], &envelope, &nearest, &chain, now).await,
            Err(GroupProblem::Invalid(_))
        ));
    }

    /// The context of a read in which every one of `nearest` was read in
    /// full late enough to answer for any listing.
    fn read_in_full(nearest: &[PeerId]) -> ReadContext {
        ReadContext {
            full_walks: nearest.iter().map(|peer| (*peer, u64::MAX / 2)).collect(),
            silent: HashSet::new(),
            addresses: HashMap::new(),
            demoted: Mutex::new(HashSet::new()),
        }
    }

    #[tokio::test]
    async fn a_copy_that_cant_be_had_doesnt_keep_an_address_from_being_decided() {
        // Six of the seven nearest serve the uploader's listing; the seventh
        // advertises a copy whose full listing it never hands over.
        let envelope = envelope_showing(ShownFields::NONE.with(PaymentField::TxHash), true);
        let payment = upload_payment(&envelope);
        let listing = Listing::new(&envelope, &payment, BLOCK_TIME);
        let nearest: Vec<PeerId> = (1..=7).map(peer).collect();
        let liar = nearest[6];
        let mut chain = MockChain::with_blocks(200, 1_800_000_000);
        let quote: ant_protocol::evm::PaymentQuote = rmp_serde::from_slice(&payment.quote).unwrap();
        chain.add_receipt(PaymentReceipt {
            tx_hash: payment.tx_hash,
            success: true,
            block_number: 150,
            logs: vec![paying_log(&quote, 4)],
        });
        let chain = reader(serve(Arc::new(Mutex::new(chain))).await);
        let now = BLOCK_TIME + 3_600;
        let context = read_in_full(&nearest);
        let never_asked = |_: XorName, peers: Vec<PeerId>| async move {
            assert!(peers.is_empty(), "{} nodes asked", peers.len());
            Vec::new()
        };
        let walk = |copies: Vec<(PeerId, Listing)>| AddressWalk {
            address: listing.address,
            nearest: nearest.clone(),
            support: copies.len(),
            copies,
        };
        let honest: Vec<(PeerId, Listing)> = nearest[..6]
            .iter()
            .map(|peer| (*peer, listing.clone()))
            .collect();

        // An index read, where the liar's copy is another listing: the one
        // six serve is listed.
        let mut made_up = listing.clone();
        made_up.metadata.name = Some("made-up.txt".into());
        let mut with_liar = honest.clone();
        with_liar.push((liar, made_up));
        let read = decide_found(
            walk(with_liar),
            envelope.clone(),
            &context,
            &chain,
            &[],
            now,
            never_asked,
        )
        .await;
        // The producer, which couldn't have the liar's copy: the same.
        let produced = decide_found(
            walk(honest.clone()),
            envelope.clone(),
            &context,
            &chain,
            &[liar],
            now,
            never_asked,
        )
        .await;
        for decision in [&read, &produced] {
            assert!(decision.decided);
            let listed = decision.listing.as_ref().expect("listed");
            assert_eq!(listed.listing, listing);
            assert_eq!((listed.nodes, listed.nearest, listed.quorum), (6, 7, true));
        }

        // Three serve it and the liar's copy can't be had: no listing has a
        // quorum, and it may if the liar serves the same, so it waits, as
        // for a node that hasn't answered, without asking the liar again.
        let three = walk(honest[..3].to_vec());
        let waiting =
            decide_found(three, envelope, &context, &chain, &[liar], now, never_asked).await;
        assert!(!waiting.decided);
        assert!(waiting.listing.is_none());
        assert!(waiting.rejected.iter().all(|row| row.again));
        assert!(
            waiting.rejected[0].problem.contains("1 haven't answered"),
            "{}",
            waiting.rejected[0].problem
        );
    }

    #[test]
    fn a_chain_unread_for_the_copy_a_quorum_serves_decides_nothing() {
        // A quoting node paid first (block 101) and serves its own copy; four
        // of the nearest serve the uploader's (block 102).
        let mut copies = vec![(1, verified_listing(1))];
        copies.extend([2, 3, 4, 5].map(|peer| (peer, verified_listing(2))));
        let groups = merge_copies(copies);
        let paid_in = |quote: u8| {
            Ok((
                verified_listing(quote),
                ListingCheck {
                    level: CheckLevel::Verified,
                    paid_at: Some(PaidAt {
                        block_number: 100 + u64::from(quote),
                        log_index: 1,
                    }),
                },
            ))
        };
        let counted = |chosen: Option<CountingListing>| {
            chosen.map(|(listing, _, nodes, quorum)| (listing.payment.block_number, nodes, quorum))
        };

        // The chain can't be read for the close group's copy: the earlier
        // payment doesn't stand in for it; both are left to try again.
        let unread = || Err(CheckProblem::ChainUnread("connection refused".into()));
        let (chosen, rejected) = decide_address(&groups, vec![paid_in(1), unread()], &NEAREST, 7);
        assert!(chosen.is_none());
        assert_eq!(rejected.len(), 2);
        assert!(
            rejected[0].1.starts_with("not decided"),
            "{}",
            rejected[0].1
        );
        assert_eq!(
            rejected[1].1,
            "could not read the payment chain: connection refused; try again"
        );

        // The close group's copy doesn't check out: the earliest stands in,
        // marked.
        let invalid = Err(CheckProblem::Invalid("not paid".into()));
        let (chosen, _) = decide_address(&groups, vec![paid_in(1), invalid], &NEAREST, 7);
        assert_eq!(counted(chosen), Some((Some(101), 1, false)));

        // The chain can't be read for a copy fewer serve: the quorum's
        // counts all the same.
        let (chosen, rejected) = decide_address(&groups, vec![unread(), paid_in(2)], &NEAREST, 7);
        assert_eq!(counted(chosen), Some((Some(102), 4, true)));
        assert_eq!(rejected.len(), 1);
    }

    #[tokio::test]
    async fn a_chain_that_cant_be_read_is_reported_as_such() {
        // In the index, only the block shown: checked against its timestamp.
        let envelope = envelope_showing(ShownFields::NONE.with(PaymentField::BlockNumber), true);
        let listing = Listing::new(&envelope, &upload_payment(&envelope), BLOCK_TIME);
        let copies: Vec<(u8, Listing)> = NEAREST[..4]
            .iter()
            .map(|peer| (*peer, listing.clone()))
            .collect();
        let groups = merge_copies(copies);
        let unreachable = reader("http://127.0.0.1:9".into());
        let checked =
            check_group(&groups[0], &envelope, &NEAREST, 4, &unreachable, BLOCK_TIME).await;
        assert!(
            matches!(checked, Err(CheckProblem::ChainUnread(_))),
            "{checked:?}"
        );
        let (chosen, rejected) = decide_address(&groups, vec![checked], &NEAREST, 7);
        assert!(chosen.is_none());
        assert!(rejected[0].1.ends_with("; try again"), "{}", rejected[0].1);
    }

    #[tokio::test]
    async fn an_index_reader_dates_a_listing_as_the_nodes_do() {
        // In the index, nothing shown: nothing to read on chain.
        let envelope = envelope_showing(ShownFields::NONE, true);
        let listing = Listing::new(&envelope, &upload_payment(&envelope), BLOCK_TIME);
        let hour = first_seen_at(BLOCK_TIME);
        // Three of the nearest date it in 1970 and only two others answer.
        let groups = merge_copies(dated_copies(&listing, &NEAREST, &[0, 0, 0, hour, hour]));
        let unreachable = reader("http://127.0.0.1:9".into());
        let (dated, check) = check_group(&groups[0], &envelope, &NEAREST, 4, &unreachable, hour)
            .await
            .expect("checks out");
        assert_eq!(check.level, CheckLevel::Reported);
        assert_eq!(dated.first_seen, Some(hour));
        // What is shown for it is dated the same way.
        assert_eq!(listing_to_check(&groups[0], &NEAREST, 4), Some(dated));
        // Without a quorum, the median of the nearest nodes' dates.
        let groups = merge_copies(dated_copies(&listing, &NEAREST, &[0, hour, hour]));
        assert_eq!(quorum_listing(&groups[0], &NEAREST, 4), None);
        assert_eq!(
            listing_to_check(&groups[0], &NEAREST, 4).and_then(|listing| listing.first_seen),
            Some(hour)
        );
        // That median, taken before any check, is what a listing that doesn't
        // count is shown with: two of three nodes dating it in 1970 date it
        // so. Checked, as a listing that counts is, it is dated by the latest
        // date that passes.
        let groups = merge_copies(dated_copies(&listing, &NEAREST, &[0, 0, hour]));
        assert_eq!(
            listing_to_check(&groups[0], &NEAREST, 4).and_then(|listing| listing.first_seen),
            Some(0)
        );
        let (dated, _) = check_group(&groups[0], &envelope, &NEAREST, 4, &unreachable, hour)
            .await
            .expect("checks out");
        assert_eq!(dated.first_seen, Some(hour));
    }

    #[tokio::test]
    async fn copies_that_cant_check_out_are_never_looked_up() {
        let envelope = envelope_showing(ShownFields::ALL, true);
        let mock = Arc::new(Mutex::new(MockChain::with_blocks(200, 1_800_000_000)));
        let chain = reader(serve(Arc::clone(&mock)).await);
        // A quote for another address, and a listing naming the file
        // otherwise than its envelope does.
        let other_quote = Payment {
            quote: rmp_serde::to_vec(&signed_quote([3; 32], 20)).unwrap(),
            ..upload_payment(&envelope)
        };
        let wrong_quote = Listing::new(&envelope, &other_quote, BLOCK_TIME);
        let mut renamed = Listing::new(&envelope, &upload_payment(&envelope), BLOCK_TIME);
        renamed.metadata.name = Some("other.txt".into());
        for listing in [wrong_quote, renamed] {
            let copies: Vec<(u8, Listing)> = NEAREST
                .iter()
                .map(|peer| (*peer, listing.clone()))
                .collect();
            let groups = merge_copies(copies);
            assert_eq!(groups.len(), 1);
            let checked = check_group(&groups[0], &envelope, &NEAREST, 4, &chain, BLOCK_TIME).await;
            assert!(
                matches!(checked, Err(CheckProblem::Invalid(_))),
                "{checked:?}"
            );
        }
        assert!(mock.lock().unwrap().calls.is_empty());
    }

    #[tokio::test]
    async fn a_payment_to_another_vault_never_counts_however_many_nodes_serve_it() {
        // Each of the seven nodes nearest the address serves the listing,
        // first stored in the hour of its payment. The payment, in block
        // 150, went to another vault; the reader's vault was deployed nearly
        // three hours later, in block 5,000.
        let other_vault = [0x70; 20];
        let nearest: Vec<PeerId> = (1..=7).map(peer).collect();
        let (deployed, deployed_at) = (5_000, 1_800_010_000);
        let mock = Arc::new(Mutex::new(MockChain::with_blocks(5_200, 1_800_000_000)));
        assert_eq!(mock.lock().unwrap().blocks[&deployed], deployed_at);
        let now = deployed_at + 3_600;
        let url = serve(Arc::clone(&mock)).await;
        let vault_only = reader(url.clone());
        let knowing = reader(url)
            .with_vault_deployment_block(deployed)
            .with_vault_deployment_time(deployed_at);
        for shown in ShownFields::every() {
            let envelope = envelope_showing(shown, true);
            let payment = upload_payment(&envelope);
            let quote: ant_protocol::evm::PaymentQuote =
                rmp_serde::from_slice(&payment.quote).unwrap();
            mock.lock().unwrap().add_receipt(PaymentReceipt {
                tx_hash: payment.tx_hash,
                success: true,
                block_number: payment.block_number,
                logs: vec![PaymentLog {
                    address: other_vault,
                    ..paying_log(&quote, payment.log_index)
                }],
            });
            let listing = Listing::new(&envelope, &payment, BLOCK_TIME);
            let groups = merge_copies(nearest.iter().map(|peer| (*peer, listing.clone())));
            let shows = |field| shown.contains(field);

            if shows(PaymentField::TxHash) {
                // The vault check alone refuses it: the transaction paid
                // another vault.
                let checked =
                    check_quorum_group(&groups[0], &envelope, &nearest, &vault_only, now).await;
                assert!(
                    matches!(checked, Err(GroupProblem::Invalid(_))),
                    "{shown:?}"
                );
            }
            // Knowing when the vault was deployed, a reader refuses every
            // one, for good: by the block or the block timestamp it shows,
            // or, showing none of those and its transaction, by the date its
            // nearest nodes give it, without reading the chain; one showing
            // its transaction but neither of the others, by the
            // transaction, which paid another vault.
            let calls = mock.lock().unwrap().calls.len();
            let checked = check_quorum_group(&groups[0], &envelope, &nearest, &knowing, now).await;
            let Err(GroupProblem::Invalid(problem)) = checked else {
                panic!("{shown:?} is not refused for good");
            };
            let (refused_by, offline) = if shows(PaymentField::BlockNumber) {
                (
                    "before the payment vault was deployed in block 5000".into(),
                    true,
                )
            } else if shows(PaymentField::BlockTimestamp) {
                (
                    format!(
                        "paid in a block timed {BLOCK_TIME}, before the payment vault was \
                         deployed at {deployed_at}"
                    ),
                    true,
                )
            } else if shows(PaymentField::TxHash) {
                ("no payment to the vault".to_string(), false)
            } else {
                let date = first_seen_at(BLOCK_TIME);
                (
                    format!(
                        "dated {date} or earlier by 4 of the nodes nearest its address, so \
                         paid by {}, before the payment vault's first payment, at \
                         {deployed_at} or later",
                        date + FIRST_SEEN_ROUNDING + CLOCK_MARGIN
                    ),
                    true,
                )
            };
            assert!(problem.contains(&refused_by), "{shown:?}: {problem}");
            if offline {
                assert_eq!(mock.lock().unwrap().calls.len(), calls, "{shown:?}");
            }
            // The read then decides its address with nothing listed, as
            // whenever the listing a quorum serves is refused for good and
            // no other is left, so an entry an earlier read published for it
            // is dropped.
            let decision =
                Decision::refused(listing.address, &groups[0], &nearest, problem, Vec::new());
            assert!(decision.decided, "{shown:?}");
            assert!(decision.listing.is_none(), "{shown:?}");
            assert_eq!(decision.rejected.len(), 1, "{shown:?}");
            assert_eq!(decision.rejected[0].nodes, 7, "{shown:?}");
            assert!(!decision.rejected[0].again, "{shown:?}");
            let mut index = ListingsIndex::default();
            index.settle(vec![decision]);
            assert!(index.listings.is_empty(), "{shown:?}");
            assert_eq!(
                index.carry(&listing.address, &listing.key()),
                Carry::Decided,
                "{shown:?}"
            );
            // Served by fewer than a quorum, and checked once the other
            // nearest nodes have answered, it is rejected for good too.
            let few = merge_copies(nearest[..3].iter().map(|peer| (*peer, listing.clone())));
            let checked = check_group(&few[0], &envelope, &nearest, 4, &knowing, now).await;
            let (chosen, problems) = decide_address(&few, vec![checked], &nearest, 7);
            let decision = Decision::from_groups(
                listing.address,
                &few,
                &nearest,
                chosen,
                problems,
                envelope.clone(),
                Vec::new(),
            );
            assert!(decision.decided, "{shown:?}");
            assert!(decision.listing.is_none(), "{shown:?}");
            assert!(!decision.rejected[0].again, "{shown:?}");
        }
    }

    /// A chain on which `payment` (as [`upload_payment`] makes it, in block
    /// 150) paid the vault: two seconds a block from 1,800,000,000.
    fn chain_paid_by(payment: &Payment) -> MockChain {
        let quote: ant_protocol::evm::PaymentQuote = rmp_serde::from_slice(&payment.quote).unwrap();
        let mut chain = MockChain::with_blocks(200, 1_800_000_000);
        chain.add_receipt(PaymentReceipt {
            tx_hash: payment.tx_hash,
            success: true,
            block_number: payment.block_number,
            logs: vec![paying_log(&quote, payment.log_index)],
        });
        chain
    }

    /// What [`check_quorum_group`] gave for a listing showing `shown`, which
    /// must have checked out.
    fn checked_out(
        checked: std::result::Result<(Listing, ListingCheck), GroupProblem>,
        shown: ShownFields,
    ) -> (Listing, ListingCheck) {
        match checked {
            Ok(checked) => checked,
            Err(GroupProblem::Again(problem) | GroupProblem::Invalid(problem)) => {
                panic!("{shown:?}: {problem}")
            }
        }
    }

    /// `listing` as each of `nearest`, in turn, serves it, with the date
    /// each gives: one copy per date.
    fn served_dated(
        listing: &Listing,
        nearest: &[PeerId],
        dates: &[u64],
    ) -> Vec<MergedListing<PeerId>> {
        merge_copies(nearest.iter().zip(dates).map(|(peer, date)| {
            let mut copy = listing.clone();
            copy.first_seen = Some(*date);
            (*peer, copy)
        }))
    }

    /// The payment fields a listing dated by its nodes alone shows: none of
    /// its block, block timestamp and transaction.
    fn dated_by_its_nodes(shown: &ShownFields) -> bool {
        [
            PaymentField::BlockNumber,
            PaymentField::BlockTimestamp,
            PaymentField::TxHash,
        ]
        .into_iter()
        .all(|field| !shown.contains(field))
    }

    #[tokio::test]
    async fn a_listing_first_seen_in_the_hour_of_the_vaults_first_payment_is_never_refused() {
        // The vault was deployed in block 140, 20 seconds before the upload
        // paid it in block 150, its first payment, and the nodes nearest the
        // address first stored the listing in the hour of both.
        let nearest: Vec<PeerId> = (1..=7).map(peer).collect();
        let deployed_at = 1_800_000_280;
        let hour = first_seen_at(deployed_at);
        assert_eq!(first_seen_at(BLOCK_TIME), hour);
        let h = FIRST_SEEN_ROUNDING;
        let now = BLOCK_TIME + 3_600;
        for shown in ShownFields::every().filter(dated_by_its_nodes) {
            let envelope = envelope_showing(shown, true);
            let payment = upload_payment(&envelope);
            let mock = Arc::new(Mutex::new(chain_paid_by(&payment)));
            assert_eq!(mock.lock().unwrap().blocks[&140], deployed_at);
            let chain = reader(serve(Arc::clone(&mock)).await)
                .with_vault_deployment_block(140)
                .with_vault_deployment_time(deployed_at)
                .with_vault_first_payment_time(BLOCK_TIME);
            let listing = Listing::new(&envelope, &payment, BLOCK_TIME);
            assert_eq!(listing.first_seen, Some(hour), "{shown:?}");
            let level = if shown.contains(PaymentField::Quote) {
                CheckLevel::Verified
            } else {
                CheckLevel::Reported
            };
            let check_dated = |date: u64| {
                let groups = served_dated(&listing, &nearest, &[date; 7]);
                let (envelope, nearest, chain) = (&envelope, &nearest, &chain);
                async move { check_quorum_group(&groups[0], envelope, nearest, chain, now).await }
            };

            // It checks out, dated that hour.
            let (dated, check) = checked_out(check_dated(hour).await, shown);
            assert_eq!(dated.first_seen, Some(hour), "{shown:?}");
            assert_eq!(check.level, level, "{shown:?}");
            // So does one dated an hour earlier: a payment can come up to
            // two hours after the date a node gives it, the hour's rounding
            // and an hour for clocks.
            let (dated, _) = checked_out(check_dated(hour - h).await, shown);
            assert_eq!(dated.first_seen, Some(hour - h), "{shown:?}");
            // Dated two hours earlier, it was paid before the first payment.
            let calls = mock.lock().unwrap().calls.len();
            let Err(GroupProblem::Invalid(problem)) = check_dated(hour - 2 * h).await else {
                panic!("{shown:?} is not refused for good");
            };
            assert!(
                problem.contains(&format!(
                    "before the payment vault's first payment, at {BLOCK_TIME} or later"
                )),
                "{shown:?}: {problem}"
            );
            assert_eq!(mock.lock().unwrap().calls.len(), calls, "{shown:?}");
        }
    }

    #[tokio::test]
    async fn a_block_timestamp_at_or_after_the_deployment_is_never_refused() {
        // The upload paid the vault in block 150, timed BLOCK_TIME; its
        // listing shows that time, but not the block.
        let nearest: Vec<PeerId> = (1..=7).map(peer).collect();
        let now = BLOCK_TIME + 3_600;
        let timed = ShownFields::NONE.with(PaymentField::BlockTimestamp);
        for (shown, level) in [
            (timed, CheckLevel::Reported),
            (
                timed.with(PaymentField::Quote).with(PaymentField::LogIndex),
                CheckLevel::Verified,
            ),
        ] {
            let envelope = envelope_showing(shown, true);
            let payment = upload_payment(&envelope);
            let mock = Arc::new(Mutex::new(chain_paid_by(&payment)));
            let url = serve(Arc::clone(&mock)).await;
            let listing = Listing::new(&envelope, &payment, BLOCK_TIME);
            assert_eq!(listing.payment.block_timestamp, Some(BLOCK_TIME));
            let groups = merge_copies(nearest.iter().map(|peer| (*peer, listing.clone())));
            // The vault deployed a second before the payment, or in the same
            // second: it checks out.
            for deployed_at in [BLOCK_TIME - 1, BLOCK_TIME] {
                let chain = reader(url.clone()).with_vault_deployment_time(deployed_at);
                let checked =
                    check_quorum_group(&groups[0], &envelope, &nearest, &chain, now).await;
                let (_, check) = checked_out(checked, shown);
                assert_eq!(check.level, level, "{shown:?}");
            }
            // Deployed a second after it: the payment was to something else.
            let chain = reader(url).with_vault_deployment_time(BLOCK_TIME + 1);
            let calls = mock.lock().unwrap().calls.len();
            let checked = check_quorum_group(&groups[0], &envelope, &nearest, &chain, now).await;
            let Err(GroupProblem::Invalid(problem)) = checked else {
                panic!("{shown:?} is not refused for good");
            };
            assert!(
                problem.contains(&format!(
                    "paid in a block timed {BLOCK_TIME}, before the payment vault was deployed \
                     at {}",
                    BLOCK_TIME + 1
                )),
                "{shown:?}: {problem}"
            );
            assert_eq!(mock.lock().unwrap().calls.len(), calls, "{shown:?}");
        }
    }

    #[tokio::test]
    async fn nodes_fewer_than_a_quorum_dating_a_listing_early_never_get_it_refused() {
        // The vault was deployed in block 140 and the upload paid it in
        // block 150, 20 seconds later; honest nodes first stored the listing
        // in that hour. Some of the nodes nearest its address date it in
        // 1970 instead.
        let nearest: Vec<PeerId> = (1..=7).map(peer).collect();
        let hour = first_seen_at(BLOCK_TIME);
        let early = 0;
        let now = BLOCK_TIME + 3_600;
        let reader_of = |payment: &Payment| {
            let mock = Arc::new(Mutex::new(chain_paid_by(payment)));
            async move {
                reader(serve(mock).await)
                    .with_vault_deployment_block(140)
                    .with_vault_deployment_time(1_800_000_280)
            }
        };
        // Resting on its nodes alone, or checked on chain by its quote.
        let resting = ShownFields::NONE;
        let quoted = ShownFields::NONE
            .with(PaymentField::Quote)
            .with(PaymentField::LogIndex);
        for shown in [resting, quoted] {
            let envelope = envelope_showing(shown, true);
            let payment = upload_payment(&envelope);
            let chain = reader_of(&payment).await;
            let listing = Listing::new(&envelope, &payment, BLOCK_TIME);
            let check = |dates: &[u64]| {
                let groups = served_dated(&listing, &nearest, dates);
                let (envelope, nearest, chain) = (&envelope, &nearest, &chain);
                async move { check_quorum_group(&groups[0], envelope, nearest, chain, now).await }
            };
            // Three of the seven, or three of the four serving it: the date
            // the others give stands, and it checks out.
            for dates in [
                &[early, early, early, hour, hour, hour, hour][..],
                &[early, early, early, hour],
            ] {
                let (dated, _) = checked_out(check(dates).await, shown);
                assert_eq!(dated.first_seen, Some(hour), "{shown:?} {dates:?}");
            }
            // Four, a quorum, can: a quorum of the nearest nodes dates every
            // listing that hides its time.
            let four = [early, early, early, early, hour, hour, hour];
            assert!(
                matches!(check(&four).await, Err(GroupProblem::Invalid(_))),
                "{shown:?}"
            );
        }
        // A listing that shows its transaction is left to the chain, which
        // shows it paid the vault: four dating it early don't get it
        // refused, and their dates, before its payment, are dropped.
        let shown = ShownFields::NONE.with(PaymentField::TxHash);
        let envelope = envelope_showing(shown, true);
        let payment = upload_payment(&envelope);
        let chain = reader_of(&payment).await;
        let listing = Listing::new(&envelope, &payment, BLOCK_TIME);
        let groups = served_dated(
            &listing,
            &nearest,
            &[early, early, early, early, hour, hour, hour],
        );
        let checked = check_quorum_group(&groups[0], &envelope, &nearest, &chain, now).await;
        let (dated, check) = checked_out(checked, shown);
        assert_eq!(dated.first_seen, Some(hour));
        assert_eq!(check.level, CheckLevel::Reported);
    }

    #[test]
    fn a_reader_of_the_bundled_network_refuses_what_was_paid_before_its_vault() {
        // The vault was deployed in block 81,897,121, timed 2026-10-06
        // 20:01:56 UTC; block 81,897,120 is timed the same second. It took
        // its first payment in block 81,942,857, timed 21:20:03 UTC: the
        // chain holds no log of the vault's in between.
        let bundled = crate::config::bundled_payment_network().unwrap();
        let chain = ListingChain::new(&bundled).unwrap();
        let deployed_at = 1_791_316_916;
        let first_paid = 1_791_321_603;
        assert_eq!(chain.vault_deployment_time(), Some(deployed_at));
        let nearest: Vec<PeerId> = (1..=7).map(peer).collect();
        let refused = |shown: ShownFields, payment: &Payment, date: u64| {
            let envelope = envelope_showing(shown, true);
            let mut listing = Listing::new(&envelope, payment, payment.block_timestamp);
            if listing.first_seen.is_some() {
                listing.first_seen = Some(date);
            }
            let groups = merge_copies(nearest.iter().map(|peer| (*peer, listing.clone())));
            check_vault_deployment(&groups[0], &nearest, QUORUM_THRESHOLD, &chain).is_err()
        };
        let paid = |block_number: u64, block_timestamp: u64| Payment {
            block_number,
            block_timestamp,
            ..upload_payment(&envelope_showing(ShownFields::ALL, true))
        };
        let at_deployment = paid(81_897_121, deployed_at);
        let first_payment = paid(81_942_857, first_paid);
        // A block or block timestamp it shows is measured from the
        // deployment.
        let block = ShownFields::NONE.with(PaymentField::BlockNumber);
        let timed = ShownFields::NONE.with(PaymentField::BlockTimestamp);
        assert!(refused(block, &paid(81_897_120, deployed_at), 0));
        assert!(!refused(block, &at_deployment, 0));
        assert!(refused(timed, &paid(81_897_120, deployed_at - 1), 0));
        assert!(!refused(timed, &at_deployment, 0));
        // Dated by its nodes alone, it is measured from the first payment:
        // refused when 4 of the 7 nearest date it 19:00 UTC or earlier, as
        // they date a payment to the vault in use before, whose last was
        // at 19:18:41, stored then. One they date 20:00 can't be told from
        // a payment at 21:20:03 that a node whose clock is an hour behind
        // stored at once: the window the date leaves open.
        let (nineteen, h) = (1_791_313_200, FIRST_SEEN_ROUNDING);
        assert_eq!(nineteen + 2 * h + 1_203, first_paid);
        let dated = ShownFields::NONE;
        assert!(refused(dated, &first_payment, nineteen - h));
        assert!(refused(dated, &first_payment, nineteen));
        assert!(!refused(dated, &first_payment, nineteen + h));
        // Dated 21:00, the first payment's hour, or later, it is never
        // refused.
        for date in [nineteen + 2 * h, nineteen + 3 * h, nineteen + 24 * h] {
            assert!(!refused(dated, &first_payment, date), "{date}");
        }
        // Nor is any payment to the vault, by the date a node gives it when
        // it stores it, its clock up to an hour behind or ahead.
        for paid_at in (first_paid..first_paid + 6 * h).step_by(300) {
            for clock in [paid_at - CLOCK_MARGIN, paid_at, paid_at + CLOCK_MARGIN] {
                let date = first_seen_at(clock);
                assert!(!refused(dated, &first_payment, date), "{paid_at} {date}");
            }
        }
        // Only a quorum's date counts: 3 of the 7 dating it 19:00 don't get
        // it refused, and 4 do.
        let envelope = envelope_showing(dated, true);
        let listing = Listing::new(&envelope, &first_payment, first_paid);
        let refused_by = |dates: &[u64]| {
            let groups = served_dated(&listing, &nearest, dates);
            check_vault_deployment(&groups[0], &nearest, QUORUM_THRESHOLD, &chain).is_err()
        };
        let (early, genuine) = (nineteen, nineteen + 2 * h);
        assert!(!refused_by(&[
            early, early, early, genuine, genuine, genuine, genuine
        ]));
        assert!(refused_by(&[
            early, early, early, early, genuine, genuine, genuine
        ]));
    }

    #[tokio::test]
    async fn a_call_an_rpc_refuses_goes_to_the_next_one() {
        // The first RPC refuses eth_getLogs, as PublicNode does; the second
        // answers everything. A listing hiding its transaction hash is found
        // by its logs, through the second.
        let envelope = envelope_showing(
            ShownFields::NONE
                .with(PaymentField::Quote)
                .with(PaymentField::LogIndex),
            true,
        );
        let quote = signed_quote(envelope.address(), 20);
        let receipt = PaymentReceipt {
            tx_hash: [0xaa; 32],
            success: true,
            block_number: 150,
            logs: vec![paying_log(&quote, 4)],
        };
        let mut refusing = MockChain::with_blocks(200, 1_800_000_000);
        refusing.add_receipt(receipt.clone());
        refusing.refused = vec!["eth_getLogs"];
        let refusing = Arc::new(Mutex::new(refusing));
        let mut answering = MockChain::with_blocks(200, 1_800_000_000);
        answering.add_receipt(receipt);
        let answering = Arc::new(Mutex::new(answering));
        let urls = vec![
            serve(Arc::clone(&refusing)).await,
            serve(Arc::clone(&answering)).await,
        ];
        let lookup = Lookup::Quote {
            quote_hash: quote.hash().0,
            block_number: None,
            search_from: 1_800_000_000,
            not_after: None,
        };
        let showing = ListingPayment {
            log_index: Some(4),
            ..ListingPayment::default()
        };

        // Through the refusing RPC alone, the search fails.
        let alone = reader(urls[0].clone());
        let error = alone.fetch(&lookup, &showing).await.unwrap_err();
        assert!(error.contains("403"), "{error}");

        // With the second behind it, the payment is found.
        let chain = ListingChain::with_rpcs(urls, VAULT).unwrap();
        let fetched = chain.fetch(&lookup, &showing).await.unwrap();
        let blocks: Vec<u64> = fetched
            .into_iter()
            .map(|(receipt, _)| receipt.expect("a receipt").block_number)
            .collect();
        assert_eq!(blocks, vec![150]);
        assert!(answering.lock().unwrap().calls_to("eth_getLogs") > 0);
        // Later log queries skip the RPC that refused them, which still
        // answers everything else first.
        let refused_before = refusing.lock().unwrap().calls_to("eth_getLogs");
        let answered_before = answering.lock().unwrap().calls_to("eth_getLogs");
        chain.fetch(&lookup, &showing).await.unwrap();
        assert_eq!(
            refusing.lock().unwrap().calls_to("eth_getLogs"),
            refused_before
        );
        assert!(answering.lock().unwrap().calls_to("eth_getLogs") > answered_before);
        assert_eq!(
            answering
                .lock()
                .unwrap()
                .calls_to("eth_getTransactionReceipt"),
            0
        );
    }

    #[test]
    fn only_the_bundled_network_falls_back_to_other_rpcs() {
        let bundled = crate::config::bundled_payment_network().unwrap();
        let fallbacks = crate::config::fallback_rpc_urls(&bundled);
        assert!(!fallbacks.is_empty());
        assert!(!fallbacks.contains(&bundled.rpc_url().to_string()));
        let local = EvmNetwork::Custom(crate::data::CustomNetwork {
            rpc_url_http: "http://127.0.0.1:8545".parse().unwrap(),
            payment_token_address: *bundled.payment_token_address(),
            payment_vault_address: *bundled.payment_vault_address(),
        });
        assert!(crate::config::fallback_rpc_urls(&local).is_empty());
    }

    #[tokio::test]
    async fn calls_are_counted_by_provider_host_alone() {
        let mut refusing = MockChain::with_blocks(10, 1_800_000_000);
        refusing.refused = vec!["eth_blockNumber"];
        let refusing = serve(Arc::new(Mutex::new(refusing))).await;
        let answering = serve(Arc::new(Mutex::new(MockChain::with_blocks(
            10,
            1_800_000_000,
        ))))
        .await;
        // A key in a URL's path never shows.
        let chain =
            ListingChain::with_rpcs(vec![format!("{refusing}/a-key"), answering], VAULT).unwrap();
        let counted = |calls, errors| {
            vec![RpcCalls {
                provider: "127.0.0.1".into(),
                calls,
                errors,
            }]
        };
        assert_eq!(chain.rpc_calls(), counted(0, 0));
        chain.latest_block().await.unwrap();
        assert_eq!(chain.rpc_calls(), counted(2, 1));
        // Later calls start at the RPC that answered.
        chain.latest_block().await.unwrap();
        assert_eq!(chain.rpc_calls(), counted(3, 1));
    }

    #[test]
    fn envelopes_are_kept_by_address_and_checked_when_read() {
        let dir = tempfile::tempdir().unwrap();
        let open = || ListingsStore::open_with_map_size(dir.path(), 16 * 1024 * 1024).unwrap();
        let envelope = envelope_showing(ShownFields::NONE, true);
        let bytes = envelope.to_bytes();
        let address = compute_address(&bytes);
        assert_eq!(address, envelope.address());
        {
            let store = open();
            let chain = reader("http://127.0.0.1:9".into())
                .with_store(&store)
                .unwrap();
            assert!(chain.kept_envelope(&address).is_none());
            chain.keep_envelope(&address, &bytes);
            assert_eq!(
                chain.kept_envelope(&address).map(|kept| kept.to_bytes()),
                Some(bytes.clone())
            );
            // Bytes that don't hash to the address are never kept.
            chain.keep_envelope(&[1; 32], &bytes);
            assert!(chain.kept_envelope(&[1; 32]).is_none());
        }
        // Kept across a restart, and checked when read: bytes changed in the
        // store are not taken for the envelope.
        let store = open();
        let chain = reader("http://127.0.0.1:9".into())
            .with_store(&store)
            .unwrap();
        assert!(chain.kept_envelope(&address).is_some());
        let envelopes: heed::Database<heed::types::Bytes, heed::types::Bytes> = store
            .database(crate::data::client::listings_facts::ENVELOPES_DB)
            .unwrap();
        let mut txn = store.env().write_txn().unwrap();
        envelopes
            .put(&mut txn, address.as_slice(), &bytes[1..])
            .unwrap();
        txn.commit().unwrap();
        assert!(chain.kept_envelope(&address).is_none());
        // Without a store, nothing is kept.
        let bare = reader("http://127.0.0.1:9".into());
        bare.keep_envelope(&address, &bytes);
        assert!(bare.kept_envelope(&address).is_none());
    }

    #[test]
    fn a_reader_of_the_bundled_network_knows_when_its_vault_was_deployed() {
        let bundled = crate::config::bundled_payment_network().unwrap();
        let chain = ListingChain::new(&bundled).unwrap();
        assert_eq!(chain.vault_deployment_block(), Some(81_897_121));
        assert_eq!(chain.vault_deployment_time(), Some(1_791_316_916));
        assert_eq!(chain.vault_first_payment_time(), Some(1_791_321_603));
        assert!(chain.before_vault_deployment(81_897_120));
        assert!(!chain.before_vault_deployment(81_897_121));
        assert!(chain.timed_before_vault_deployment(1_791_316_915));
        assert!(!chain.timed_before_vault_deployment(1_791_316_916));
        // Any other vault's isn't known, so no block is before it.
        let other = reader("http://127.0.0.1:9".into());
        assert_eq!(other.vault_deployment_block(), None);
        assert_eq!(other.vault_deployment_time(), None);
        assert_eq!(other.vault_first_payment_time(), None);
        assert!(!other.before_vault_deployment(0));
        assert!(!other.timed_before_vault_deployment(0));
        let other = other
            .with_vault_deployment_block(160)
            .with_vault_deployment_time(1_800_000_320)
            .with_vault_first_payment_time(1_800_000_340);
        assert!(other.before_vault_deployment(159));
        assert!(!other.before_vault_deployment(160));
        assert_eq!(other.vault_deployment_time(), Some(1_800_000_320));
        assert_eq!(other.vault_first_payment_time(), Some(1_800_000_340));
    }

    #[test]
    fn only_the_date_its_nodes_give_is_measured_from_the_vaults_first_payment() {
        // The vault was deployed in block 160 at 08:00 UTC, an hour's start,
        // and took its first payment at 11:01:40.
        let h = FIRST_SEEN_ROUNDING;
        let deployed_at = 1_800_000_000;
        assert_eq!(first_seen_at(deployed_at), deployed_at);
        let first_paid = deployed_at + 3 * h + 100;
        let deployed = reader("http://127.0.0.1:9".into())
            .with_vault_deployment_block(160)
            .with_vault_deployment_time(deployed_at);
        let both = reader("http://127.0.0.1:9".into())
            .with_vault_deployment_block(160)
            .with_vault_deployment_time(deployed_at)
            .with_vault_first_payment_time(first_paid);
        let nearest: Vec<PeerId> = (1..=7).map(peer).collect();
        let paid = Payment {
            block_number: 160,
            block_timestamp: deployed_at,
            ..upload_payment(&envelope_showing(ShownFields::ALL, true))
        };
        let check = |chain: &ListingChain, shown: ShownFields, date: u64| {
            let envelope = envelope_showing(shown, true);
            let mut listing = Listing::new(&envelope, &paid, deployed_at);
            if listing.first_seen.is_some() {
                listing.first_seen = Some(date);
            }
            let groups = merge_copies(nearest.iter().map(|peer| (*peer, listing.clone())));
            check_vault_deployment(&groups[0], &nearest, QUORUM_THRESHOLD, chain)
        };
        let dated = ShownFields::NONE;
        let quoted = dated.with(PaymentField::Quote).with(PaymentField::LogIndex);
        for shown in [dated, quoted] {
            // Knowing only the deployment, it is measured from that: a
            // quorum dating it 06:00 or later doesn't get it refused.
            for date in [
                deployed_at - 2 * h,
                deployed_at - h,
                deployed_at,
                deployed_at + h,
            ] {
                assert!(check(&deployed, shown, date).is_ok(), "{shown:?} {date}");
            }
            assert!(check(&deployed, shown, deployed_at - 3 * h).is_err());
            // Knowing the first payment too, it is measured from that: dated
            // 09:00 or earlier, it was paid by 11:00, before the first
            // payment; dated 10:00, it may have been the first.
            for date in [deployed_at - h, deployed_at, deployed_at + h] {
                let Err(problem) = check(&both, shown, date) else {
                    panic!("{shown:?} dated {date} is not refused");
                };
                assert!(
                    problem.contains(&format!(
                        "before the payment vault's first payment, at {first_paid} or later"
                    )),
                    "{problem}"
                );
            }
            assert!(check(&both, shown, deployed_at + 2 * h).is_ok());
        }
        // A block or block timestamp it shows is still measured from the
        // deployment: shown at the deployment, before the first payment, it
        // is left to the chain.
        let block = ShownFields::NONE.with(PaymentField::BlockNumber);
        let timed = ShownFields::NONE.with(PaymentField::BlockTimestamp);
        for shown in [block, timed, block.with(PaymentField::BlockTimestamp)] {
            assert!(check(&both, shown, 0).is_ok(), "{shown:?}");
        }
        // Knowing the first payment alone, the date its nodes give is
        // measured from it, and a block timestamp it shows by nothing.
        let first_only =
            reader("http://127.0.0.1:9".into()).with_vault_first_payment_time(first_paid);
        assert!(check(&first_only, dated, deployed_at + h).is_err());
        assert!(check(&first_only, dated, deployed_at + 2 * h).is_ok());
        let early = Payment {
            block_timestamp: 0,
            ..paid.clone()
        };
        let envelope = envelope_showing(timed, true);
        let listing = Listing::new(&envelope, &early, deployed_at);
        let groups = merge_copies(nearest.iter().map(|peer| (*peer, listing.clone())));
        assert!(
            check_vault_deployment(&groups[0], &nearest, QUORUM_THRESHOLD, &first_only).is_ok()
        );
        // Given a first payment before the deployment, the later of the two
        // counts.
        let earlier = reader("http://127.0.0.1:9".into())
            .with_vault_deployment_time(deployed_at)
            .with_vault_first_payment_time(deployed_at - 5 * h);
        assert!(check(&earlier, dated, deployed_at - 2 * h).is_ok());
        assert!(check(&earlier, dated, deployed_at - 3 * h).is_err());
    }

    #[tokio::test]
    async fn reads_only_the_payments_of_a_quote_a_listing_can_describe() {
        // Others paid the upload's quote first, at log index 9 in blocks 50
        // to 53; the upload paid it at log index 4 in block 150. The
        // provider answers at most 64 blocks of logs at once.
        let envelope = envelope_showing(
            ShownFields::NONE
                .with(PaymentField::Quote)
                .with(PaymentField::LogIndex),
            true,
        );
        let quote = signed_quote(envelope.address(), 20);
        let mut mock = MockChain::with_blocks(200, 1_800_000_000);
        for block in 50..54u8 {
            mock.add_receipt(PaymentReceipt {
                tx_hash: [block; 32],
                success: true,
                block_number: block.into(),
                logs: vec![paying_log(&quote, 9)],
            });
        }
        mock.add_receipt(PaymentReceipt {
            tx_hash: [0xaa; 32],
            success: true,
            block_number: 150,
            logs: vec![paying_log(&quote, 4)],
        });
        mock.max_log_range = Some(64);
        let mock = Arc::new(Mutex::new(mock));
        let chain = reader(serve(Arc::clone(&mock)).await);
        let lookup = Lookup::Quote {
            quote_hash: quote.hash().0,
            block_number: None,
            search_from: 1_800_000_000,
            not_after: None,
        };
        let blocks_of = |fetched: Fetched| -> Vec<u64> {
            fetched
                .into_iter()
                .map(|(receipt, _)| receipt.expect("a receipt").block_number)
                .collect()
        };
        let log_calls = || mock.lock().unwrap().calls_to("eth_getLogs");
        let showing = |log_index, block_timestamp| ListingPayment {
            log_index,
            block_timestamp,
            ..ListingPayment::default()
        };

        // Nothing shown to tell them apart: the earliest payments.
        let fetched = chain.fetch(&lookup, &showing(None, None)).await.unwrap();
        assert_eq!(blocks_of(fetched), vec![50, 51, 52, 53]);
        // The log index shown: the search goes on past the others' payments.
        let fetched = chain.fetch(&lookup, &showing(Some(4), None)).await.unwrap();
        assert_eq!(blocks_of(fetched), vec![150]);
        // The timestamp shown: only the blocks of that second, in one call.
        let before = log_calls();
        let fetched = chain
            .fetch(&lookup, &showing(None, Some(BLOCK_TIME)))
            .await
            .unwrap();
        assert_eq!(blocks_of(fetched), vec![150]);
        assert_eq!(log_calls() - before, 1);
        // A second no block has: nothing, and no logs read.
        let before = log_calls();
        let fetched = chain
            .fetch(&lookup, &showing(None, Some(BLOCK_TIME + 1)))
            .await
            .unwrap();
        assert!(fetched.is_empty());
        assert_eq!(log_calls(), before);
        // In one block, the log index still filters.
        let in_block = Lookup::Quote {
            quote_hash: quote.hash().0,
            block_number: Some(150),
            search_from: 1_800_000_000,
            not_after: None,
        };
        let fetched = chain.fetch(&in_block, &showing(Some(9), None)).await;
        assert!(fetched.unwrap().is_empty());
        let fetched = chain.fetch(&in_block, &showing(Some(4), None)).await;
        assert_eq!(blocks_of(fetched.unwrap()), vec![150]);

        // Four of the nearest serve the upload's listing, one the payment
        // made first: the upload's is found, checks out and counts.
        let now = BLOCK_TIME + 100;
        let upload = Payment {
            quote: rmp_serde::to_vec(&quote).unwrap(),
            ..upload_payment(&envelope)
        };
        let first = Payment {
            tx_hash: [50; 32],
            block_number: 50,
            block_timestamp: 1_800_000_100,
            log_index: 9,
            quote: rmp_serde::to_vec(&quote).unwrap(),
        };
        let mut copies: Vec<(u8, Listing)> = NEAREST[..4]
            .iter()
            .map(|peer| (*peer, Listing::new(&envelope, &upload, now)))
            .collect();
        copies.push((5, Listing::new(&envelope, &first, now)));
        let groups = merge_copies(copies);
        let mut checked = Vec::new();
        for group in &groups {
            checked.push(check_group(group, &envelope, &NEAREST, 4, &chain, now).await);
        }
        let (listing, check) = checked[0].clone().expect("the upload's payment is found");
        assert_eq!(
            check.paid_at,
            Some(PaidAt {
                block_number: 150,
                log_index: 4
            })
        );
        let (chosen, rejected) = decide_address(&groups, checked, &NEAREST, 7);
        assert_eq!(chosen, Some((listing, CheckLevel::Verified, 4, true)));
        assert_eq!(rejected.len(), 1);
    }

    #[tokio::test]
    async fn a_quote_dated_after_its_payment_is_looked_up_back_widely() {
        // The quote says 1,800,000,000; the chain's latest block is older,
        // and the quote was paid in block 50.
        let quote = signed_quote([7; 32], 20);
        let mut mock = MockChain::with_blocks(200, 1_799_000_000);
        mock.add_receipt(PaymentReceipt {
            tx_hash: [0xaa; 32],
            success: true,
            block_number: 50,
            logs: vec![paying_log(&quote, 4)],
        });
        let mock = Arc::new(Mutex::new(mock));
        let chain = reader(serve(Arc::clone(&mock)).await);
        let lookup = Lookup::Quote {
            quote_hash: quote.hash().0,
            block_number: None,
            search_from: 1_800_000_000,
            not_after: None,
        };
        let shown = ListingPayment::default();
        assert_eq!(chain.fetch(&lookup, &shown).await.unwrap().len(), 1);
        // One call forwards (the latest block alone), one back over the rest.
        assert_eq!(mock.lock().unwrap().calls_to("eth_getLogs"), 2);
        // A provider that answers 64 blocks at a time: found all the same.
        mock.lock().unwrap().max_log_range = Some(64);
        assert_eq!(chain.fetch(&lookup, &shown).await.unwrap().len(), 1);
    }

    /// A `ChangesRequest` for the whole address space after record `after`.
    fn changes_request(after: u64, watch: bool) -> ListingsBody {
        ListingsBody::ChangesRequest(ant_listings::ChangesRequest {
            epoch: 9,
            after,
            prefix: [0; 32],
            bits: 0,
            limit: MAX_LIST_LIMIT,
            want_peers: false,
            watch,
        })
    }

    /// A `ChangesResponse` of no changes, at `head`.
    fn changes_response(head: u64) -> ChangesResponse {
        ChangesResponse {
            epoch: 9,
            head,
            next: head,
            count: 0,
            set_hash: ant_listings::SetHash::EMPTY,
            changes: Vec::new(),
            more: false,
            view: [0; 32],
            peers: Vec::new(),
        }
    }

    fn message(request_id: u64, body: ListingsBody) -> ListingsMessage {
        ListingsMessage { request_id, body }
    }

    #[test]
    fn request_ids_are_never_the_complement_of_another() {
        for _ in 0..1_000 {
            let id = new_request_id();
            assert_eq!(id >> 63, 0, "{id:#x}");
            assert_eq!(push_request_id(id) >> 63, 1, "{id:#x}");
        }
    }

    #[test]
    fn answers_go_to_the_request_by_node_and_id() {
        let mut routes = Routes::default();
        let mut receiver = routes.expect(peer(1), 5, &changes_request(0, false), true);
        // Another node's message with the same id, or this node's with
        // another id, isn't the answer.
        for (source, id) in [(peer(2), 5), (peer(1), 6)] {
            let routed = routes.route(
                source,
                message(id, ListingsBody::ChangesResponse(changes_response(3))),
            );
            assert!(matches!(routed, Route::Drop), "{routed:?}");
        }
        let routed = routes.route(
            peer(1),
            message(5, ListingsBody::ChangesResponse(changes_response(3))),
        );
        let Route::Answer(sender, body) = routed else {
            panic!("{routed:?}");
        };
        sender.send(body).unwrap();
        assert_eq!(
            receiver.try_recv().unwrap(),
            ListingsBody::ChangesResponse(changes_response(3))
        );
        // Answered once: a second answer is dropped.
        let again = routes.route(
            peer(1),
            message(5, ListingsBody::ChangesResponse(changes_response(4))),
        );
        assert!(matches!(again, Route::Drop), "{again:?}");
    }

    #[test]
    fn a_refusal_is_the_answer() {
        // A node that doesn't know a kind of request answers `unsupported`:
        // that is its answer, not a timeout.
        let mut routes = Routes::default();
        let request = ListingsBody::RangeListRequest(ant_listings::RangeListRequest {
            prefix: [0; 32],
            bits: 0,
            after: None,
            limit: MAX_LIST_LIMIT,
        });
        let mut receiver = routes.expect(peer(1), 7, &request, true);
        let refusal = ListingsBody::Error {
            message: "unsupported".into(),
        };
        let Route::Answer(sender, body) = routes.route(peer(1), message(7, refusal.clone())) else {
            panic!("a refusal is an answer");
        };
        sender.send(body).unwrap();
        assert_eq!(receiver.try_recv().unwrap(), refusal);
    }

    #[test]
    fn pushes_go_by_the_complement_of_the_watching_request() {
        let mut routes = Routes::default();
        let mut answer = routes.expect(peer(1), 5, &changes_request(0, true), true);
        let push_id = push_request_id(5);
        // A push can come before the answer, and leaves the request waiting.
        let push = routes.route(
            peer(1),
            message(push_id, ListingsBody::ChangesResponse(changes_response(1))),
        );
        assert!(
            matches!(&push, Route::Push(push) if push.head == 1),
            "{push:?}"
        );
        // Others' messages with the push id aren't pushes, and nor is any
        // other kind of message from the node with it.
        let other = routes.route(
            peer(2),
            message(push_id, ListingsBody::ChangesResponse(changes_response(1))),
        );
        assert!(matches!(other, Route::Drop), "{other:?}");
        let not_a_push = routes.route(
            peer(1),
            message(push_id, ListingsBody::GetResponse { listing: None }),
        );
        assert!(matches!(not_a_push, Route::Drop), "{not_a_push:?}");
        // The answer, by the request's own id.
        let Route::Answer(sender, body) = routes.route(
            peer(1),
            message(5, ListingsBody::ChangesResponse(changes_response(1))),
        ) else {
            panic!("the answer");
        };
        sender.send(body).unwrap();
        assert!(answer.try_recv().is_ok());
        // Pushes keep coming after the answer, while the watch lasts.
        let later = routes.route(
            peer(1),
            message(push_id, ListingsBody::ChangesResponse(changes_response(2))),
        );
        assert!(matches!(later, Route::Push(_)), "{later:?}");
    }

    #[test]
    fn the_next_changes_request_replaces_the_watch() {
        let mut routes = Routes::default();
        let _first = routes.expect(peer(1), 5, &changes_request(0, true), true);
        // A new watch: pushes from the old one are dropped (the next
        // answer covers what they carried), the new one's are taken.
        let _second = routes.expect(peer(1), 6, &changes_request(3, true), true);
        let old = routes.route(
            peer(1),
            message(
                push_request_id(5),
                ListingsBody::ChangesResponse(changes_response(4)),
            ),
        );
        assert!(matches!(old, Route::Drop), "{old:?}");
        let new = routes.route(
            peer(1),
            message(
                push_request_id(6),
                ListingsBody::ChangesResponse(changes_response(4)),
            ),
        );
        assert!(matches!(new, Route::Push(_)), "{new:?}");
        // Other requests leave the watch alone.
        let _get = routes.expect(
            peer(1),
            8,
            &ListingsBody::GetRequest { address: [1; 32] },
            true,
        );
        let still = routes.route(
            peer(1),
            message(
                push_request_id(6),
                ListingsBody::ChangesResponse(changes_response(5)),
            ),
        );
        assert!(matches!(still, Route::Push(_)), "{still:?}");
        // A ChangesRequest without a watch ends it, as it does on the node.
        let _third = routes.expect(peer(1), 9, &changes_request(5, false), true);
        let ended = routes.route(
            peer(1),
            message(
                push_request_id(6),
                ListingsBody::ChangesResponse(changes_response(6)),
            ),
        );
        assert!(matches!(ended, Route::Drop), "{ended:?}");
    }

    #[test]
    fn without_a_sink_pushes_are_dropped() {
        let mut routes = Routes::default();
        let _answer = routes.expect(peer(1), 5, &changes_request(0, true), false);
        let push = routes.route(
            peer(1),
            message(
                push_request_id(5),
                ListingsBody::ChangesResponse(changes_response(1)),
            ),
        );
        assert!(matches!(push, Route::Drop), "{push:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_watch_lapses_with_its_lease_and_ends_when_its_node_leaves() {
        let mut routes = Routes::default();
        let _first = routes.expect(peer(1), 5, &changes_request(0, true), true);
        let _second = routes.expect(peer(2), 6, &changes_request(0, true), true);
        let push = |routes: &mut Routes, node: u8, id: u64| {
            routes.route(
                peer(node),
                message(
                    push_request_id(id),
                    ListingsBody::ChangesResponse(changes_response(1)),
                ),
            )
        };
        assert!(matches!(push(&mut routes, 1, 5), Route::Push(_)));
        assert!(matches!(push(&mut routes, 2, 6), Route::Push(_)));
        // Node 2 left: its pushes are no longer taken.
        routes.keep_watches(|node| *node != peer(2));
        assert!(matches!(push(&mut routes, 2, 6), Route::Drop));
        assert!(matches!(push(&mut routes, 1, 5), Route::Push(_)));
        // Node 1's watch lapses on the node with its lease: so it does here.
        tokio::time::advance(Duration::from_secs(WATCH_LEASE)).await;
        assert!(matches!(push(&mut routes, 1, 5), Route::Drop));
    }

    #[test]
    fn a_node_can_have_only_so_many_pushes_waiting() {
        let (sink, mut receiver) = push_channel(64);
        for _ in 0..PUSHES_WAITING_PER_NODE {
            assert!(sink.offer(peer(1), changes_response(1)));
        }
        assert!(
            !sink.offer(peer(1), changes_response(2)),
            "its share is full"
        );
        assert!(
            sink.offer(peer(2), changes_response(1)),
            "another node's push still fits"
        );
        // Taking one makes room for one more.
        let (source, _) = receiver.try_recv().unwrap();
        assert_eq!(source, peer(1));
        assert!(sink.offer(peer(1), changes_response(3)));
        // A full channel takes nothing.
        let (small, _small_receiver) = push_channel(1);
        assert!(small.offer(peer(1), changes_response(1)));
        assert!(!small.offer(peer(2), changes_response(1)));
    }

    #[test]
    fn a_forgotten_request_takes_no_late_answer() {
        let mut routes = Routes::default();
        let _answer = routes.expect(
            peer(1),
            5,
            &ListingsBody::GetRequest { address: [1; 32] },
            true,
        );
        routes.forget(&peer(1), 5);
        let late = routes.route(
            peer(1),
            message(5, ListingsBody::GetResponse { listing: None }),
        );
        assert!(matches!(late, Route::Drop), "{late:?}");
    }

    /// Blocks long past, so their times are never "in the future".
    const PAST: u64 = 1_700_000_000;

    /// A store for one test.
    fn test_store(dir: &std::path::Path) -> ListingsStore {
        ListingsStore::open_with_map_size(dir, 16 * 1024 * 1024).unwrap()
    }

    /// A payment of a quote in block 150, at log index 4.
    fn paid_receipt() -> (ant_protocol::evm::PaymentQuote, PaymentReceipt) {
        let quote = signed_quote([1; 32], 20);
        let receipt = PaymentReceipt {
            tx_hash: [0xaa; 32],
            success: true,
            block_number: 150,
            logs: vec![paying_log(&quote, 4)],
        };
        (quote, receipt)
    }

    /// A chain of 200 blocks from `start` holding `receipt`, finalized up
    /// to `finalized`.
    fn chain_with(receipt: &PaymentReceipt, start: u64, finalized: u64) -> Arc<Mutex<MockChain>> {
        let mut chain = MockChain::with_blocks(200, start);
        chain.add_receipt(receipt.clone());
        chain.finalized = Some(finalized);
        Arc::new(Mutex::new(chain))
    }

    /// The URLs of `first` and `second` as two providers: the second on
    /// another host name, as a second provider is.
    async fn two_providers(
        first: &Arc<Mutex<MockChain>>,
        second: &Arc<Mutex<MockChain>>,
    ) -> Vec<String> {
        vec![
            serve(Arc::clone(first)).await,
            serve(Arc::clone(second))
                .await
                .replace("127.0.0.1", "localhost"),
        ]
    }

    fn calls(chain: &Arc<Mutex<MockChain>>) -> usize {
        chain.lock().unwrap().calls.len()
    }

    #[tokio::test]
    async fn chain_facts_are_kept_once_final_and_another_provider_agrees() {
        let (_, receipt) = paid_receipt();
        let first = chain_with(&receipt, PAST, 100);
        let second = chain_with(&receipt, PAST, 100);
        let urls = two_providers(&first, &second).await;
        let dir = tempfile::tempdir().unwrap();
        let store = test_store(dir.path());
        let chain = ListingChain::with_rpcs(urls.clone(), VAULT)
            .unwrap()
            .with_store(&store)
            .unwrap();
        let lookup = Lookup::Transaction {
            tx_hash: [0xaa; 32],
        };
        let shown = ListingPayment::default();
        let expected = vec![(Some(receipt.clone()), Some(PAST + 300))];

        // Above the finalized block: used at once, not kept.
        assert_eq!(chain.fetch(&lookup, &shown).await.unwrap(), expected);
        let facts = chain.facts.as_ref().unwrap();
        assert_eq!(facts.kept_receipt(&[0xaa; 32]), None);
        assert_eq!(facts.kept_block(150), None);
        assert_eq!(calls(&second), 0);
        // Held while not final: used again without reading it again.
        let read = calls(&first);
        assert_eq!(chain.fetch(&lookup, &shown).await.unwrap(), expected);
        assert_eq!(calls(&first), read);

        // Final now: the other provider is asked, agrees, and both facts
        // are kept.
        first.lock().unwrap().finalized = Some(160);
        facts.finalized.lock().await.asked_at = None;
        assert_eq!(chain.fetch(&lookup, &shown).await.unwrap(), expected);
        assert_eq!(
            second.lock().unwrap().calls_to("eth_getTransactionReceipt"),
            1
        );
        assert_eq!(second.lock().unwrap().calls_to("eth_getBlockByNumber"), 1);
        assert_eq!(facts.kept_receipt(&[0xaa; 32]), Some(receipt.clone()));
        assert_eq!(facts.kept_block(150), Some(PAST + 300));

        // After a restart, nothing is read again.
        drop(chain);
        let (before_first, before_second) = (calls(&first), calls(&second));
        let again = ListingChain::with_rpcs(urls, VAULT)
            .unwrap()
            .with_store(&store)
            .unwrap();
        assert_eq!(again.fetch(&lookup, &shown).await.unwrap(), expected);
        assert_eq!(calls(&first), before_first);
        assert_eq!(calls(&second), before_second);
    }

    #[tokio::test]
    async fn a_fact_another_provider_disagrees_with_is_used_but_not_kept() {
        let (_, receipt) = paid_receipt();
        let first = chain_with(&receipt, PAST, 199);
        let second = chain_with(&receipt, PAST, 199);
        second.lock().unwrap().blocks.insert(150, PAST + 301);
        let urls = two_providers(&first, &second).await;
        let dir = tempfile::tempdir().unwrap();
        let chain = ListingChain::with_rpcs(urls, VAULT)
            .unwrap()
            .with_store(&test_store(dir.path()))
            .unwrap();
        let fetched = chain
            .fetch(
                &Lookup::Transaction {
                    tx_hash: [0xaa; 32],
                },
                &ListingPayment::default(),
            )
            .await
            .unwrap();
        assert_eq!(fetched, vec![(Some(receipt.clone()), Some(PAST + 300))]);
        let facts = chain.facts.as_ref().unwrap();
        // The receipt both return is kept; the timestamp they disagree on
        // is neither kept nor held, so it is read again when next needed.
        assert_eq!(facts.kept_receipt(&[0xaa; 32]), Some(receipt));
        assert_eq!(facts.kept_block(150), None);
        assert!(facts.block(150).is_none());
    }

    #[tokio::test]
    async fn a_single_provider_is_never_enough_to_keep_a_fact() {
        let (_, receipt) = paid_receipt();
        let only = chain_with(&receipt, PAST, 199);
        let dir = tempfile::tempdir().unwrap();
        let chain = reader(serve(Arc::clone(&only)).await)
            .with_store(&test_store(dir.path()))
            .unwrap();
        chain
            .fetch(
                &Lookup::Transaction {
                    tx_hash: [0xaa; 32],
                },
                &ListingPayment::default(),
            )
            .await
            .unwrap();
        let facts = chain.facts.as_ref().unwrap();
        assert_eq!(facts.kept_receipt(&[0xaa; 32]), None);
        assert_eq!(facts.kept_block(150), None);
    }

    #[tokio::test]
    async fn not_found_errors_and_future_times_are_never_kept() {
        let (_, receipt) = paid_receipt();
        let dir = tempfile::tempdir().unwrap();
        let store = test_store(dir.path());
        let shown = ListingPayment::default();

        // Not found.
        let first = chain_with(&receipt, PAST, 199);
        let second = chain_with(&receipt, PAST, 199);
        let urls = two_providers(&first, &second).await;
        let chain = ListingChain::with_rpcs(urls, VAULT)
            .unwrap()
            .with_store(&store)
            .unwrap();
        let unknown = Lookup::Transaction {
            tx_hash: [0xbb; 32],
        };
        assert_eq!(chain.fetch(&unknown, &shown).await.unwrap(), Vec::new());
        let facts = chain.facts.as_ref().unwrap();
        assert!(facts.receipt(&[0xbb; 32]).is_none());
        let missing_block = Lookup::Block { block_number: 500 };
        assert_eq!(
            chain.fetch(&missing_block, &shown).await.unwrap(),
            vec![(None, None)]
        );
        assert!(facts.block(500).is_none());
        // A quote no log query finds a payment of.
        let nothing_paid = Lookup::Quote {
            quote_hash: [0xcc; 32],
            block_number: Some(150),
            search_from: PAST,
            not_after: None,
        };
        assert_eq!(
            chain.fetch(&nothing_paid, &shown).await.unwrap(),
            Vec::new()
        );
        assert!(facts.quote(&[0xcc; 32]).is_none());
        drop(chain);

        // Errors.
        let failing = chain_with(&receipt, PAST, 199);
        failing.lock().unwrap().failing = vec![("eth_getTransactionReceipt", -32_000)];
        let failing_too = chain_with(&receipt, PAST, 199);
        failing_too.lock().unwrap().failing = vec![("eth_getTransactionReceipt", -32_000)];
        let urls = two_providers(&failing, &failing_too).await;
        let chain = ListingChain::with_rpcs(urls, VAULT)
            .unwrap()
            .with_store(&store)
            .unwrap();
        let lookup = Lookup::Transaction {
            tx_hash: [0xaa; 32],
        };
        assert!(chain.fetch(&lookup, &shown).await.is_err());
        let facts = chain.facts.as_ref().unwrap();
        assert!(facts.receipt(&[0xaa; 32]).is_none());
        drop(chain);

        // A block timed later than the clock: the receipt is kept, its
        // block's time is used but never kept or held.
        let future = unix_now() + 3_600;
        let first = chain_with(&receipt, future, 199);
        let second = chain_with(&receipt, future, 199);
        let urls = two_providers(&first, &second).await;
        let chain = ListingChain::with_rpcs(urls, VAULT)
            .unwrap()
            .with_store(&store)
            .unwrap();
        assert_eq!(
            chain.fetch(&lookup, &shown).await.unwrap(),
            vec![(Some(receipt.clone()), Some(future + 300))]
        );
        let facts = chain.facts.as_ref().unwrap();
        assert_eq!(facts.kept_receipt(&[0xaa; 32]), Some(receipt));
        assert_eq!(facts.kept_block(150), None);
        assert!(facts.block(150).is_none());
    }

    #[tokio::test]
    async fn a_listing_showing_only_its_quote_is_searched_for_once() {
        let (quote, receipt) = paid_receipt();
        let first = chain_with(&receipt, PAST, 199);
        let second = chain_with(&receipt, PAST, 199);
        let urls = two_providers(&first, &second).await;
        let dir = tempfile::tempdir().unwrap();
        let store = test_store(dir.path());
        let lookup = Lookup::Quote {
            quote_hash: quote.hash().0,
            block_number: None,
            search_from: PAST + 200,
            not_after: None,
        };
        let shown = ListingPayment {
            log_index: Some(4),
            ..ListingPayment::default()
        };
        let expected = vec![(Some(receipt.clone()), Some(PAST + 300))];
        {
            let chain = ListingChain::with_rpcs(urls.clone(), VAULT)
                .unwrap()
                .with_store(&store)
                .unwrap();
            assert_eq!(chain.fetch(&lookup, &shown).await.unwrap(), expected);
            assert!(first.lock().unwrap().calls_to("eth_getLogs") > 0);
            let facts = chain.facts.as_ref().unwrap();
            assert_eq!(
                facts.kept_quote(&quote.hash().0),
                Some(vec![VaultLog {
                    tx_hash: [0xaa; 32],
                    block_number: 150,
                    log_index: 4,
                }])
            );
        }
        // Read again, after a restart: no search and no call at all.
        let (before_first, before_second) = (calls(&first), calls(&second));
        let chain = ListingChain::with_rpcs(urls, VAULT)
            .unwrap()
            .with_store(&store)
            .unwrap();
        assert_eq!(chain.fetch(&lookup, &shown).await.unwrap(), expected);
        // A listing showing another log index finds nothing, still with no
        // call: the vault records a quote's payment once.
        let elsewhere = ListingPayment {
            log_index: Some(5),
            ..ListingPayment::default()
        };
        assert_eq!(chain.fetch(&lookup, &elsewhere).await.unwrap(), Vec::new());
        assert_eq!(calls(&first), before_first);
        assert_eq!(calls(&second), before_second);
    }

    #[tokio::test]
    async fn every_call_has_its_own_id_and_calls_known_together_go_in_batches_of_100() {
        let mut mock = MockChain::with_blocks(200, PAST);
        let tx_hashes: Vec<[u8; 32]> = (0..150u8).map(|n| [n; 32]).collect();
        for (block, tx_hash) in (0u64..).zip(&tx_hashes) {
            mock.add_receipt(PaymentReceipt {
                tx_hash: *tx_hash,
                success: true,
                block_number: block,
                logs: Vec::new(),
            });
        }
        let mock = Arc::new(Mutex::new(mock));
        let chain = reader(serve(Arc::clone(&mock)).await).unpaced();
        let found = chain.transactions(&tx_hashes).await.unwrap();
        assert_eq!(found.len(), 150);
        assert!(found.iter().all(Option::is_some));
        let mock = mock.lock().unwrap();
        // 150 receipts and 150 blocks: two requests each, of 100 and 50.
        assert_eq!(mock.calls.len(), 300);
        assert_eq!(mock.requests, 4);
        let ids: HashSet<u64> = mock.ids.iter().copied().collect();
        assert_eq!(ids.len(), 300);
    }

    #[tokio::test]
    async fn a_busy_provider_is_held_off_and_calls_go_to_the_next() {
        let busy = Arc::new(Mutex::new(MockChain::with_blocks(10, PAST)));
        busy.lock().unwrap().failing = vec![(
            "eth_blockNumber",
            crate::data::client::listings_rpc::BUSY_CODE,
        )];
        let answering = Arc::new(Mutex::new(MockChain::with_blocks(10, PAST)));
        let urls = vec![
            serve(Arc::clone(&busy)).await,
            serve(Arc::clone(&answering)).await,
        ];
        let chain = ListingChain::with_rpcs(urls, VAULT).unwrap();
        assert_eq!(chain.latest_block().await.unwrap(), 9);
        assert_eq!(busy.lock().unwrap().calls_to("eth_blockNumber"), 1);
        // Held off now: the next call goes straight to the next provider.
        assert_eq!(chain.latest_block().await.unwrap(), 9);
        assert_eq!(busy.lock().unwrap().calls_to("eth_blockNumber"), 1);
        assert_eq!(answering.lock().unwrap().calls_to("eth_blockNumber"), 2);
    }

    #[tokio::test]
    async fn errors_never_show_an_rpc_url() {
        // Nothing listens on port 9 here: the request itself fails.
        let chain = reader("http://127.0.0.1:9/a-secret-key".into());
        let error = chain.latest_block().await.unwrap_err();
        assert!(!error.contains("a-secret-key"), "{error}");
        assert!(!error.contains("http://"), "{error}");
        assert!(error.contains("127.0.0.1"), "{error}");
        // Nor an HTTP error.
        let mut refusing = MockChain::with_blocks(10, PAST);
        refusing.refused = vec!["eth_blockNumber"];
        let url = serve(Arc::new(Mutex::new(refusing))).await;
        let chain = reader(format!("{url}/a-secret-key"));
        let error = chain.latest_block().await.unwrap_err();
        assert!(error.contains("403"), "{error}");
        assert!(!error.contains("a-secret-key"), "{error}");
        assert!(!error.contains("http://"), "{error}");
    }

    #[test]
    fn the_bundled_network_reads_through_publicnode_ordofi_for_logs_and_robinhood_last() {
        let bundled = crate::config::bundled_payment_network().unwrap();
        let setup = rpc_setup(&bundled, None).unwrap();
        let host = |index: usize| crate::data::client::listings_rpc::rpc_host(&setup.urls[index]);
        assert_eq!(setup.urls.len(), 3);
        assert_eq!(host(0), "robinhood-rpc.publicnode.com");
        assert_eq!(host(1), "rpc.ordofi.network");
        assert_eq!(host(2), "rpc.mainnet.chain.robinhood.com");
        assert_eq!(setup.logs_order, Some(vec![1, 0, 2]));
        assert_eq!(setup.chain_id, None);
        let rpc = Rpc::new(setup.urls, setup.logs_order, None).unwrap();
        assert_eq!(rpc.order(Kind::Chain), vec![0, 1, 2]);
        assert_eq!(rpc.order(Kind::Logs), vec![1, 0, 2]);
    }

    #[test]
    fn a_list_of_rpcs_overrides_the_bundled_ones_and_each_is_checked_for_the_chain() {
        let bundled = crate::config::bundled_payment_network().unwrap();
        let setup = rpc_setup(&bundled, Some(" https://a.example/k1  http://b.example ")).unwrap();
        assert_eq!(
            setup,
            RpcSetup {
                urls: vec!["https://a.example/k1".into(), "http://b.example".into()],
                logs_order: None,
                chain_id: crate::config::chain_id(&bundled),
            }
        );
        assert!(setup.chain_id.is_some());
        // Something other than a URL: named by its place alone.
        let error = rpc_setup(&bundled, Some("https://a.example ftp://secret")).unwrap_err();
        assert!(error.contains("entry 2"), "{error}");
        assert!(!error.contains("secret"), "{error}");
        // Empty: the bundled ones.
        assert_eq!(rpc_setup(&bundled, Some("  ")).unwrap().urls.len(), 3);
        // Another network reads through its own RPC alone.
        let local = EvmNetwork::Custom(crate::data::CustomNetwork {
            rpc_url_http: "http://127.0.0.1:8545".parse().unwrap(),
            payment_token_address: *bundled.payment_token_address(),
            payment_vault_address: *bundled.payment_vault_address(),
        });
        let setup = rpc_setup(&local, Some("https://a.example")).unwrap();
        assert_eq!(setup.urls, vec![local.rpc_url().to_string()]);
        assert_eq!(setup.chain_id, None);
    }

    #[tokio::test]
    async fn an_rpc_on_another_chain_is_never_used() {
        let other = Arc::new(Mutex::new(MockChain::with_blocks(10, PAST)));
        other.lock().unwrap().chain_id = 1;
        let right = Arc::new(Mutex::new(MockChain::with_blocks(20, PAST)));
        right.lock().unwrap().chain_id = 4_663;
        let urls = vec![
            serve(Arc::clone(&other)).await,
            serve(Arc::clone(&right)).await,
        ];
        let chain = ListingChain::with_rpc_setup(urls, None, Some(4_663), VAULT).unwrap();
        assert_eq!(chain.latest_block().await.unwrap(), 19);
        assert_eq!(chain.latest_block().await.unwrap(), 19);
        let other = other.lock().unwrap();
        assert_eq!(other.calls, vec!["eth_chainId".to_string()]);
    }

    #[test]
    fn the_block_at_a_time_is_guessed_from_the_blocks_either_side() {
        // An even pace: the guess is the block.
        assert_eq!(
            guess_block(1_000 + 2 * 345, (0, 1_000), (1_000, 3_000)),
            345
        );
        // Always strictly between the two.
        assert_eq!(guess_block(1_000, (10, 1_000), (20, 1_020)), 11);
        assert_eq!(guess_block(1_019, (10, 1_000), (20, 1_020)), 19);
        assert_eq!(guess_block(5, (10, 1_000), (12, 1_000)), 11);
    }

    #[tokio::test]
    async fn the_block_at_a_time_takes_a_few_calls_on_a_steady_chain() {
        let mock = Arc::new(Mutex::new(MockChain::with_blocks(100_000, PAST)));
        let chain = reader(serve(Arc::clone(&mock)).await).unpaced();
        let time = PAST + 2 * 12_345 + 1;
        assert_eq!(chain.block_at(time, 99_999).await.unwrap(), 12_345);
        let asked = mock.lock().unwrap().calls_to("eth_getBlockByNumber");
        // Halving alone takes 17 steps over 100,000 blocks.
        assert!(asked <= 6, "{asked}");
        // A time near one searched for before costs fewer still.
        let before = calls(&mock);
        assert_eq!(chain.block_at(time + 4, 99_999).await.unwrap(), 12_347);
        let more = calls(&mock) - before;
        assert!(more <= 4, "{more}");
        // And the answer is always the last block timed at or before it.
        for time in [
            PAST - 1,
            PAST,
            PAST + 1,
            PAST + 199_997,
            PAST + 199_998,
            PAST + 500_000,
        ] {
            let expected = if time < PAST {
                0
            } else {
                ((time - PAST) / 2).min(99_999)
            };
            assert_eq!(
                chain.block_at(time, 99_999).await.unwrap(),
                expected,
                "{time}"
            );
        }
    }
}
