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
//!    the release but doesn't answer one is read the v2 way.
//! 3. **Guard.** If fewer than 7 census nodes answered with answers the
//!    checks took, or under three quarters of them ([`Census::guard_ok`]),
//!    the cycle decides and drops nothing, and every entry is kept, marked
//!    carried, as an index read that finds too few nodes keeps them.
//! 4. **Support.** An address's copies are those of the census's 7 nodes
//!    nearest it ([`Census::nearest`]) whose copies count this cycle: from
//!    the node's mirror when it is in sync, and for a node without the
//!    release from its latest pass, while it keeps answering. A mirror holds
//!    digest entries: the full listing behind each is fetched once with a
//!    `GetRequest`, checked against its entry
//!    ([`ant_listings::DigestEntry::describes`]) and kept in the store.
//!    Fetching is bounded: it takes at most [`CYCLE`], however long the
//!    poll took, addresses most of whose nearest nodes hold an entry first,
//!    each node asked at most its allowance in pages a cycle
//!    ([`Feeds::page_allowance`]), and a node that failed to hand over the
//!    listing behind its entry isn't asked for it again until its entry
//!    changes, or [`RETRY_INTERVAL`] has passed.
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
//!    for any of its listings, left it for later or kept it unconfirmed,
//!    while a copy of it couldn't be had, or while a chain fact it was
//!    decided on isn't final ([`ListingChain::settled`]). Every
//!    [`REDECIDE_INTERVAL`], and at each start, every address is decided
//!    again, and a change no input explains is logged as an alert.
//! 7. **Drops.** A published address is removed as `no_longer_served` only
//!    when, within one cycle, all 7 of its nearest nodes answered and none
//!    serves a copy at any key, and then [`Census::confirm_drop`] confirms
//!    it: a witnessed lookup of it finds the same 7, in a leaf closed in
//!    full that cycle (once a cycle, shared by every drop in it), and a
//!    `GetRequest` to each of them, begun at or after the address's key
//!    time plus `FIRST_SEEN_ROUNDING` and `CLOCK_MARGIN`, returns none, as
//!    does one to each node that served it when it was last decided, unless
//!    that node has left the census. Otherwise it stays, marked carried. A
//!    drop the evidence refused isn't checked again for
//!    [`RETRY_INTERVAL`] unless its nearest nodes, its copies or its
//!    last holders change, and drops are checked within the cycle's time,
//!    at least one a cycle. One decided and rejected is removed as
//!    `rejected`, as is one every copy of which shows a payment from before
//!    the payment vault was deployed.
//! 8. **Publishing.** Each batch's decisions are staged in the publisher's
//!    store as they are made ([`Publisher::stage`]), and once every batch
//!    is decided, the files they changed are written, then `status.json`
//!    after every other file ([`Publisher::write_staged`]).
//!
//! **Sizes.** The listing of a file whose data map is shrunk into a child
//! map gives no size. The producer reads such a file's root map once, as a
//! download does, and keeps the size it gives for good: an entry is
//! published with its size once known, and until then without, and an
//! entry published without it has it filled in once it is read (a put).
//! The reading never holds up a cycle or a push: after each cycle, once
//! what the last task read is taken, a task of its own reads at most
//! [`SIZES_PER_CYCLE`] root maps, for at most a [`CYCLE`]; one that can't be
//! read is tried again after [`RETRY_INTERVAL`].
//!
//! Between cycles, nodes push the new records of the leaves they are asked
//! about: a push that brings a mirror to the node's new head is applied
//! ([`Feeds::push`]), and the addresses it changes are decided and
//! published at once, after the guard of the latest cycle, with that
//! cycle's `status.json`. A node can have only so many pushes waiting
//! ([`PUSHES_WAITING_PER_NODE`](super::listings::PUSHES_WAITING_PER_NODE)).
//! Pushes that come during a cycle's poll are decided with the cycle, so
//! while a node is slow to answer the poll, they wait for it. Every
//! publication begins in a later second than the one before it ended in,
//! so a file written twice is never written twice in the same second: a
//! server that tags files by their time to the second and their size then
//! tags every version differently.
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
//! cleared at each start, which decides every address again in its first
//! cycle, as an index read does every cycle, from the kept mirrors,
//! listings, facts and envelopes, fetching nothing it fetched before. The
//! nodes whose copies counted when an address was last decided are kept
//! across starts, for drops.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::ops::Bound;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ant_listings::{
    AddressWalk, ChangesResponse, DigestEntry, Listing, ListingKey, Pushed, CLOCK_MARGIN,
    FIRST_SEEN_ROUNDING, MAX_LIST_LIMIT, NEAREST_NODES, QUORUM_THRESHOLD,
};
use ant_protocol::transport::PeerId;
use ant_protocol::XorName;
use futures::stream::{self, StreamExt};
use heed::byteorder::BigEndian;
use heed::types::{Bytes, DecodeIgnore, U64};
use heed::{Database, RoTxn};
use self_encryption::DataMap;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::listings::{
    listings_traffic, push_channel, unix_now, Carry, CheckedListing, Decision, ListingChain,
    ListingsIndex, ListingsRequests, PendingCopy, PushReceiver, PushSink, ReadContext,
    RejectedListing, CHECK_CONCURRENCY,
};
use super::listings_census::{user_agent_of, Census};
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
/// mirror or the nodes that last served it change; a node that failed to
/// hand over the full listing behind its entry, unless its entry changes;
/// a root map that couldn't be read.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// How many root maps of shrunk data maps are read a cycle, all at once: as
/// many as addresses are decided at once (8).
pub const SIZES_PER_CYCLE: usize = CHECK_CONCURRENCY;

/// The store's directory inside the state directory.
pub const STORE_DIR: &str = "listings.mdb";

/// Since when each address has been deferred, or listed below full
/// support: a tag ([`DEFERRED_TAG`] or [`BELOW_FULL_TAG`]) and the
/// address, to Unix seconds.
const SINCE_DB: &str = "serve_since";

/// The nodes whose copies counted when each address was last decided: the
/// address, to their ids, 32 bytes each.
const HOLDERS_DB: &str = "serve_holders";

/// The full listings behind the mirrors' digest entries, as `GetRequest`s
/// fetched them: the address and the digest, to the listing without
/// `first_seen`, in MessagePack.
const LISTINGS_DB: &str = "serve_listings";

/// The size of each listed file whose data map is shrunk, as its root map
/// gives it: the address, to the size in bytes. Kept for good, since an
/// envelope's address fixes its data map.
const SIZES_DB: &str = "serve_sizes";

/// What this process knows of the addresses it works on, by a tag and the
/// address ([`KNOWN_TAG`], [`AGAIN_TAG`], [`BACKOFF_TAG`], [`FAILED_TAG`],
/// [`SIZE_WANTED_TAG`]). Cleared at each start.
const KNOWN_DB: &str = "serve_known";

/// [`SINCE_DB`]: an address deferred since then.
const DEFERRED_TAG: u8 = b'd';

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

/// [`KNOWN_DB`]: a listed address whose data map is shrunk and whose size
/// isn't known yet, to when its root map may be read (Unix seconds, 0 at
/// once) and the data map, in MessagePack.
const SIZE_WANTED_TAG: u8 = b'w';

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
    /// Publications those pushes led to.
    pub published_between: u64,
}

/// A full listing's place among those fetched: its address and digest.
type ListingId = (XorName, [u8; 32]);

/// An address's copies as digest entries, each with its node.
type DigestCopies = Vec<(PeerId, DigestEntry)>;

/// An address to decide, the census's nodes nearest it, and the copies of
/// those whose copies count.
type Work = (XorName, Vec<PeerId>, DigestCopies);

/// A full listing to fetch, and the nodes whose entries name it.
type Wanted = (ListingId, DigestCopies);

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
}

impl Known {
    fn encode(self) -> [u8; 9] {
        let mut bytes = [0u8; 9];
        bytes[..8].copy_from_slice(&self.nearest.to_be_bytes());
        bytes[8] = u8::from(self.again) | (u8::from(self.decided) << 1);
        bytes
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; 9] = bytes.try_into().ok()?;
        Some(Self {
            nearest: u64::from_be_bytes(bytes[..8].try_into().ok()?),
            again: bytes[8] & 1 != 0,
            decided: bytes[8] & 2 != 0,
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
    /// Whether a copy couldn't be had: the full listing behind a node's
    /// entry wasn't fetched.
    unheard: bool,
}

/// A drop the evidence refused: checked again once its inputs change, or
/// at `retry_at` ([`BACKOFF_TAG`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DropBackoff {
    /// [`drop_inputs`] when it was refused.
    inputs: u64,
    /// Unix seconds.
    retry_at: u64,
}

impl DropBackoff {
    fn encode(self) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&self.inputs.to_be_bytes());
        bytes[8..].copy_from_slice(&self.retry_at.to_be_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; 16] = bytes.try_into().ok()?;
        Some(Self {
            inputs: u64::from_be_bytes(bytes[..8].try_into().ok()?),
            retry_at: u64::from_be_bytes(bytes[8..].try_into().ok()?),
        })
    }
}

/// Which addresses a cycle, or what pushes changed, works on.
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
}

/// The root maps being read, by a task of their own ([`SIZES_PER_CYCLE`]).
struct SizeJob {
    /// Each address read, with the size its root map gave, or `None` if it
    /// couldn't be read. Those not read by the deadline aren't in it.
    results: tokio::sync::oneshot::Receiver<Vec<(XorName, Option<u64>)>>,
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
    /// When this process last decided every address (Unix seconds).
    decided_all_at: Option<u64>,
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
    /// The root maps being read, if any.
    size_job: Option<SizeJob>,
    /// When this process started, in Unix seconds.
    started_at: u64,
    /// Counts since then.
    totals: Totals,
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
        let known: Database<Bytes, Bytes> = store.database(KNOWN_DB)?;
        // What an earlier process knew of each address is its own: this
        // one decides every address again in its first cycle.
        let mut txn = store.env().write_txn().map_err(store_error)?;
        known.clear(&mut txn).map_err(store_error)?;
        txn.commit().map_err(store_error)?;
        let (sink, pushes) = push_channel(PUSH_CAPACITY);
        let now = unix_now();
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
            known,
            requests: None,
            sink: Some(sink),
            pushes,
            standing: 0,
            fetch_budget: FetchBudget::default(),
            want_peers: BTreeSet::new(),
            decided_all_at: None,
            guard_ok: false,
            last_status: None,
            // An earlier process may have published in this second.
            published_second: now,
            pushes_between: 0,
            published_between: 0,
            size_job: None,
            started_at: now,
            totals: Totals::default(),
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
    /// was killed, joins through the peers it knew.
    ///
    /// # Errors
    ///
    /// Only if the producer can't go on at all: when its store can't be
    /// read or written.
    pub async fn run(&mut self, cancel: CancellationToken) -> Result<()> {
        let result = self.run_cycles(&cancel).await;
        self.size_job = None;
        self.save_client_state().await;
        result
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
        let at = unix_now();
        let before = Counters::now(&self.chain);
        let pushes_between = std::mem::take(&mut self.pushes_between);
        let published_between = std::mem::take(&mut self.published_between);
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
        self.guard_ok = guard_ok;

        // Nothing below reads the network but fetching listings, deciding
        // and confirming drops: a cancelled cycle has written nothing but the
        // mirrors, the census, the listings fetched and the batches staged,
        // which the next cycle finds as they were.
        let mut tally = Tally::default();
        let mut considered = 0;
        if guard_ok {
            let full = self
                .decided_all_at
                .is_none_or(|all| at.saturating_sub(all) >= REDECIDE_INTERVAL.as_secs());
            // Deciding every address again after a start, nothing needs
            // explaining.
            let alert = full && self.decided_all_at.is_some();
            if !change.is_empty() && (alert || !full) {
                self.mark_moved()?;
            }
            let source = if full {
                Source::All
            } else {
                Source::Pending { again: true }
            };
            // However long the poll took, fetching gets as long as a poll
            // may take; drops get the rest of the cycle's time, and at least
            // one check.
            let fetch_deadline = Instant::now() + CYCLE;
            Box::pin(self.fetch_for(source, fetch_deadline)).await?;
            let mut drops = DropCheck {
                checked: false,
                deadline,
            };
            let (decided, _) =
                Box::pin(self.decide_all(source, at, Some(&mut drops), alert, &mut tally)).await?;
            considered = decided;
            if full {
                self.decided_all_at = Some(at);
            }
        } else {
            // As an index read that finds too few nodes: nothing is decided
            // or dropped, and every entry is kept, carried, until a cycle
            // decides every address again.
            self.carry_all(at, &mut tally)?;
            self.decided_all_at = None;
        }
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
    /// those decided, a batch at a time.
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
                        if self
                            .known_of(&txn, address)?
                            .is_none_or(|known| known.nearest != nearest)
                        {
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
    fn next_batch(&self, source: Source, after: Option<&XorName>) -> Result<Vec<(XorName, bool)>> {
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

    /// Decide every address of `source`, a batch at a time: each batch
    /// decided ([`Self::decide`]), its publication staged at `at`
    /// ([`Publisher::stage`]) and what it decided kept ([`Self::keep`])
    /// before the next. With `drops`, published addresses no node serves
    /// any more are checked for dropping, within its time. With `alert`, a
    /// change no input explains is logged. What is published is counted into
    /// `tally`. Returns how many addresses were decided, and whether any
    /// batch staged a change.
    ///
    /// # Errors
    ///
    /// If the store can't be read or written.
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
        loop {
            let batch = self.next_batch(source, after.as_ref())?;
            let Some(&(last, _)) = batch.last() else {
                break;
            };
            decided_count += batch.len() as u64;
            let explained: BTreeSet<XorName> = batch
                .iter()
                .filter(|(_, explained)| *explained)
                .map(|(address, _)| *address)
                .collect();
            let addresses: Vec<XorName> = batch.iter().map(|(address, _)| *address).collect();
            let full = batch.len() == DECIDE_BATCH;
            let mut decided = Box::pin(self.decide(addresses, drops.as_deref_mut())).await?;
            let publication = self.publication(&mut decided, at, tally)?;
            if alert {
                alert_unexplained(&publication, &explained);
            }
            if !publication.changes.is_empty()
                || !publication.support.is_empty()
                || !publication.rejected.is_empty()
            {
                self.publisher.stage(&publication)?;
                staged = true;
            }
            drop(publication);
            self.keep(decided)?;
            if !full {
                break;
            }
            after = Some(last);
        }
        Ok((decided_count, staged))
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
    /// listings fetched for them. With `drops`, an address none of whose
    /// nearest nodes serves a copy is looked at too: its published entry is
    /// dropped on the evidence [`Census::confirm_drop`] finds, checked while
    /// the cycle has time (at least one a cycle), and its row in
    /// `rejected.json` cleared once every node nearest it has been read in
    /// full long enough after its time. Without, such an address is left for
    /// the next cycle.
    ///
    /// # Errors
    ///
    /// If the store can't be read or written.
    async fn decide(
        &mut self,
        addresses: Vec<XorName>,
        mut drops: Option<&mut DropCheck>,
    ) -> Result<Decided> {
        let mut index = ListingsIndex::default();
        let mut pending: Vec<AddressWalk<PeerId>> = Vec::new();
        let mut backed: Vec<(AddressWalk<PeerId>, Vec<PeerId>)> = Vec::new();
        let mut waiting: Vec<(XorName, Vec<PeerId>, &'static str)> = Vec::new();
        let mut empty: Vec<(XorName, Vec<PeerId>)> = Vec::new();
        let mut unheard_addresses = 0usize;
        let mut with_copies: Vec<XorName> = Vec::new();
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
                copies_from(|digest| self.stored_listing(&txn, address, digest), &copies)
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
        // Some node serves a copy: no drop to back off from.
        self.forget_backoffs(with_copies.iter())?;
        index.defer(&pending, &self.chain);
        let pending_seen: Vec<Seen> = pending.iter().map(|found| Seen::of(found, false)).collect();
        let backed_seen: Vec<Seen> = backed
            .iter()
            .map(|(found, unheard)| Seen::of(found, !unheard.is_empty()))
            .collect();
        drop(pending);
        let mut decisions: Vec<Decision> = Vec::new();
        if !backed.is_empty() {
            let Some(requests) = self.requests.as_ref() else {
                return Err(Error::Network("listings requests are not routed".into()));
            };
            let context = self.read_context();
            let (client, chain, context) = (&self.client, &self.chain, &context);
            decisions = stream::iter(backed)
                .map(|(found, unheard)| async move {
                    client
                        .decide_backed(found, context, requests, chain, &unheard)
                        .await
                })
                .buffer_unordered(CHECK_CONCURRENCY)
                .collect()
                .await;
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
        // Addresses one of whose listings was left to try again, or was
        // rejected on chain facts that aren't final yet.
        let rows_again: HashSet<XorName> = index
            .rejected
            .iter()
            .filter(|row| row.again || unsettled(&self.chain, row))
            .map(|row| row.listing.address)
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
        };
        let mut considered: Vec<(XorName, u64, bool)> = Vec::new();
        for seen in pending_seen {
            considered.push((seen.address, seen.nearest, true));
            decided.holders.push((seen.address, seen.holders));
        }
        for seen in backed_seen {
            let address = seen.address;
            let again = seen.unheard
                || !index.was_decided(&address)
                || rows_again.contains(&address)
                || listed
                    .get(&address)
                    .is_some_and(|checked| !self.chain.settled(&checked.listing));
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
                }),
            ));
            if listed.contains_key(&address) {
                continue;
            }
            if let Some(key) = self
                .publisher
                .entry(&address)?
                .and_then(|entry| entry.entry.key())
            {
                decided
                    .unlisted
                    .push((key, removal(&index, &address, &key)));
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
                if !read_whole {
                    kept.insert(*address);
                    continue;
                }
                let last = self.last_holders(address)?;
                let inputs = drop_inputs(nearest, &last);
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
                    Err(why) => {
                        info!(
                            "Keeping {}, which its nearest nodes no longer serve: {why}",
                            hex::encode(address)
                        );
                        kept.insert(*address);
                        self.set_backoff(
                            address,
                            DropBackoff {
                                inputs,
                                retry_at: now.saturating_add(RETRY_INTERVAL.as_secs()),
                            },
                        )?;
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
    /// fetched and kept, without `first_seen`: `None` if it isn't kept, or
    /// can't be read.
    fn stored_listing(
        &self,
        txn: &RoTxn<'_>,
        address: &XorName,
        digest: &[u8; 32],
    ) -> Option<Listing> {
        let bytes = self
            .listings
            .get(txn, &listing_key(address, digest))
            .ok()
            .flatten()?;
        rmp_serde::from_slice(bytes).ok()
    }

    /// Fetch, with a `GetRequest` to the nodes holding it, the full listing
    /// behind each digest entry of the addresses of `source` not kept yet,
    /// and keep the first that the node's entry describes. The addresses
    /// are read a batch at a time, and their fetches started as they are,
    /// [`POLL_CONCURRENCY`] at once: those of addresses at least a quorum of
    /// whose nearest nodes hold an entry first, then the others. Each node
    /// is sent at most its allowance in pages a cycle
    /// ([`Feeds::page_allowance`]), and a node that failed to hand over the
    /// listing behind its entry isn't asked for it again for
    /// [`RETRY_INTERVAL`], unless its entry changes. What hasn't come by
    /// `deadline` is left for later: its copies can't be had this time.
    ///
    /// # Errors
    ///
    /// If the store can't be read or written.
    async fn fetch_for(&self, source: Source, deadline: Instant) -> Result<()> {
        let Some(requests) = self.requests.as_ref() else {
            return Ok(());
        };
        let now = unix_now();
        let (client, feeds, budget) = (&self.client, &self.feeds, &self.fetch_budget);
        let take = move |peer: &PeerId| budget.take(peer, || feeds.page_allowance(peer));
        let ask = move |peer: PeerId, address: XorName| async move {
            client
                .ask_for_listing(requests, &address, &[peer])
                .await
                .into_iter()
                .next()
                .and_then(|(_, answer)| answer)
        };
        let error: std::cell::RefCell<Option<Error>> = std::cell::RefCell::new(None);
        let mut sink = FetchSink::new(self, now);
        for backed in [true, false] {
            if Instant::now() >= deadline {
                break;
            }
            let wanted = WantedIter::new(self, source, backed, now, &error);
            fetch_wanted(wanted, take, deadline, ask, |key, listing, failed| {
                sink.add(key, listing, failed);
            })
            .await;
            sink.flush()?;
            if let Some(e) = error.borrow_mut().take() {
                return Err(e);
            }
        }
        sink.flush()
    }

    /// The full listings to fetch for the next batch of `source` after
    /// `after`, of addresses at least a quorum of whose nearest nodes hold an
    /// entry if `backed`, else of the others: each digest an entry names
    /// that isn't kept, with the nodes whose entries name it but those that
    /// failed to hand it over less than [`RETRY_INTERVAL`] before `now`.
    /// Also returns the batch's last address, and whether the batch was the
    /// last.
    ///
    /// # Errors
    ///
    /// If the store can't be read.
    fn wanted_after(
        &self,
        source: Source,
        after: Option<&XorName>,
        backed: bool,
        now: u64,
    ) -> Result<(Vec<Wanted>, Option<XorName>, bool)> {
        let batch = self.next_batch(source, after)?;
        let last = batch.last().map(|(address, _)| *address);
        let done = batch.len() < DECIDE_BATCH;
        let mut work: Vec<Work> = Vec::new();
        for (address, _) in &batch {
            let nearest = self.census.nearest(address, NEAREST_NODES);
            let copies = self.feeds.copies(address, &nearest)?;
            if (copies.len() >= QUORUM_THRESHOLD) == backed && !copies.is_empty() {
                work.push((*address, Vec::new(), copies));
            }
        }
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
        Ok((fetches_wanted(&work, failed, kept), last, done))
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
    /// read ([`SIZE_WANTED_TAG`]).
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
            let row = tagged(SIZE_WANTED_TAG, &address);
            if self.known.get(&txn, &row).map_err(store_error)?.is_none() {
                let mut value = 0u64.to_be_bytes().to_vec();
                value.extend(
                    rmp_serde::to_vec(&map)
                        .map_err(|e| Error::Serialization(format!("a data map: {e}")))?,
                );
                self.known
                    .put(&mut txn, &row, &value)
                    .map_err(store_error)?;
            }
        }
        for change in &publication.changes {
            if let IndexChange::Remove { address, .. } = change {
                self.known
                    .delete(&mut txn, &tagged(SIZE_WANTED_TAG, address))
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
        self.feeds.settle(&decided.settle)
    }

    /// Take `first`, a push from a node's watch, and every other push that
    /// comes before the latest publication's second is out; decide what they
    /// changed at once, after the latest cycle's guard, fetching what it
    /// needs until `deadline`, and publish it with the latest cycle's
    /// `status.json`.
    ///
    /// # Errors
    ///
    /// If the store or the published files can't be written.
    async fn take_pushes(
        &mut self,
        first: (PeerId, ChangesResponse),
        deadline: Instant,
    ) -> Result<()> {
        let mut applied = self.take_push(first)?;
        wait_past(self.published_second).await;
        while let Some(push) = self.pushes.try_recv() {
            applied |= self.take_push(push)?;
        }
        self.feeds.save()?;
        if !applied {
            return Ok(());
        }
        let Some(status) = self.last_status.clone() else {
            return Ok(());
        };
        if !self.guard_ok {
            return Ok(());
        }
        let at = unix_now();
        let source = Source::Pending { again: false };
        Box::pin(self.fetch_for(source, deadline)).await?;
        let mut tally = Tally::default();
        let (_, staged) = Box::pin(self.decide_all(source, at, None, false, &mut tally)).await?;
        if staged {
            self.write_spaced(at, &status).await?;
            self.published_between += 1;
            debug!(
                "Published what pushes changed: {} put, {} removed",
                tally.put, tally.removed
            );
        }
        Ok(())
    }

    /// Take one push: whether it was applied to its node's mirror.
    ///
    /// # Errors
    ///
    /// If the store can't be written.
    fn take_push(&mut self, (source, push): (PeerId, ChangesResponse)) -> Result<bool> {
        self.pushes_between += 1;
        Ok(matches!(
            self.feeds.push(&self.census, &source, &push)?,
            Pushed::Applied(_)
        ))
    }

    /// Start reading the root maps of up to [`SIZES_PER_CYCLE`] listed files
    /// whose sizes aren't known yet, in a task of its own, for at most a
    /// [`CYCLE`]; unless such a task is still reading, or what it read is
    /// still to be taken. A root map that couldn't be read before is read
    /// again only [`RETRY_INTERVAL`] after; one not read by the end is read
    /// again by a later task.
    ///
    /// # Errors
    ///
    /// If the store can't be read.
    fn start_sizes(&mut self) -> Result<()> {
        if self.size_job.is_some() {
            return Ok(());
        }
        let until = Instant::now() + CYCLE;
        let now = unix_now();
        let mut due: Vec<(XorName, DataMap)> = Vec::new();
        {
            let txn = self.store.env().read_txn().map_err(store_error)?;
            for row in self
                .known
                .prefix_iter(&txn, &[SIZE_WANTED_TAG])
                .map_err(store_error)?
            {
                if due.len() == SIZES_PER_CYCLE {
                    break;
                }
                let (key, value) = row.map_err(store_error)?;
                let Some(address) = key.get(1..).and_then(|a| XorName::try_from(a).ok()) else {
                    continue;
                };
                let Some((retry_at, map)) = value.split_first_chunk::<8>() else {
                    continue;
                };
                if u64::from_be_bytes(*retry_at) > now {
                    continue;
                }
                if let Ok(map) = rmp_serde::from_slice::<DataMap>(map) {
                    due.push((address, map));
                }
            }
        }
        if due.is_empty() {
            return Ok(());
        }
        let client = Arc::clone(&self.client);
        let (sender, results) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let client = &client;
            let mut reads = stream::iter(due)
                .map(|(address, map)| async move {
                    let started = std::time::Instant::now();
                    match client.data_map_resolve_root(&map).await {
                        Ok(root) => {
                            debug!(
                                "Read the root map of {} in {} ms",
                                hex::encode(address),
                                started.elapsed().as_millis()
                            );
                            (address, root_size(&root))
                        }
                        Err(error) => {
                            debug!(
                                "Could not read the root map of {} in {} ms: {error}",
                                hex::encode(address),
                                started.elapsed().as_millis()
                            );
                            (address, None)
                        }
                    }
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

    /// Take the sizes `read`: keep each one read, and fill it in to its
    /// entry where that has none, as a put published with the latest
    /// cycle's `status.json`; a root map that couldn't be read is read again
    /// after [`RETRY_INTERVAL`].
    ///
    /// # Errors
    ///
    /// If the store or the published files can't be written.
    async fn take_sizes(&mut self, read: Vec<(XorName, Option<u64>)>) -> Result<()> {
        if read.is_empty() {
            return Ok(());
        }
        let now = unix_now();
        let retry_at = now.saturating_add(RETRY_INTERVAL.as_secs());
        let mut sized: Vec<(XorName, u64)> = Vec::new();
        let mut txn = self.store.env().write_txn().map_err(store_error)?;
        for (address, size) in read {
            let row = tagged(SIZE_WANTED_TAG, &address);
            match size {
                Some(size) => {
                    self.sizes
                        .put(&mut txn, &address, &size)
                        .map_err(store_error)?;
                    self.known.delete(&mut txn, &row).map_err(store_error)?;
                    sized.push((address, size));
                }
                None => {
                    let value = self
                        .known
                        .get(&txn, &row)
                        .map_err(store_error)?
                        .map(|value| {
                            let mut value = value.to_vec();
                            if value.len() >= 8 {
                                value[..8].copy_from_slice(&retry_at.to_be_bytes());
                            }
                            value
                        });
                    if let Some(value) = value {
                        self.known
                            .put(&mut txn, &row, &value)
                            .map_err(store_error)?;
                    }
                }
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
    /// deferred, and each listed one below full support, and count them into
    /// `tally`: an address of the batch not deferred loses its row.
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
            let Some(reason) = deferred.get(address) else {
                self.since.delete(&mut txn, &row).map_err(store_error)?;
                continue;
            };
            let since = if let Some(since) = self.since.get(&txn, &row).map_err(store_error)? {
                since
            } else {
                self.since.put(&mut txn, &row, &at).map_err(store_error)?;
                at
            };
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
    /// publisher fills in the feed's fields.
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
        self.totals.cycles += 1;
        self.totals.bytes_in += cycle.bytes_in;
        self.totals.bytes_out += cycle.bytes_out;
        self.totals.rpc = self.chain.rpc_calls();
        Ok(Status {
            cycle,
            census: self.census.status(at),
            deferred: tally
                .groups
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
    Sizes(Vec<(XorName, Option<u64>)>),
}

/// The sizes `job` read, once it has; never while there is no job.
async fn sizes_read(job: &mut Option<SizeJob>) -> Vec<(XorName, Option<u64>)> {
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
    fetched: Vec<(ListingId, Listing)>,
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
    fn add(&mut self, key: ListingId, listing: Option<Listing>, failed: Vec<PeerId>) {
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
        for ((address, digest), listing) in self.fetched.drain(..) {
            let listing = Listing {
                first_seen: None,
                ..listing
            };
            let bytes = rmp_serde::to_vec(&listing)
                .map_err(|e| Error::Serialization(format!("a fetched listing: {e}")))?;
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
/// kept in `error`.
struct WantedIter<'a> {
    producer: &'a Producer,
    source: Source,
    backed: bool,
    now: u64,
    after: Option<XorName>,
    done: bool,
    queue: VecDeque<Wanted>,
    error: &'a std::cell::RefCell<Option<Error>>,
}

impl<'a> WantedIter<'a> {
    fn new(
        producer: &'a Producer,
        source: Source,
        backed: bool,
        now: u64,
        error: &'a std::cell::RefCell<Option<Error>>,
    ) -> Self {
        Self {
            producer,
            source,
            backed,
            now,
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
            if self.done {
                return None;
            }
            match self.producer.wanted_after(
                self.source,
                self.after.as_ref(),
                self.backed,
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
/// over its listing.
fn copies_from(
    fetched: impl Fn(&[u8; 32]) -> Option<Listing>,
    copies: &[(PeerId, DigestEntry)],
) -> (Vec<(PeerId, Listing)>, Vec<PeerId>) {
    let mut listed = Vec::with_capacity(copies.len());
    let mut unheard = Vec::new();
    for (peer, entry) in copies {
        let Some(listing) = fetched(&entry.digest) else {
            unheard.push(*peer);
            continue;
        };
        let copy = Listing {
            first_seen: entry.first_seen,
            ..listing
        };
        if entry.describes(&copy) && copy.validate().is_ok() {
            listed.push((*peer, copy));
        }
    }
    (listed, unheard)
}

/// How many more `GetRequest`s for full listings each node may be sent
/// this cycle.
#[derive(Debug, Default)]
struct FetchBudget(Mutex<HashMap<PeerId, usize>>);

impl FetchBudget {
    /// A new cycle: every node's allowance starts again.
    fn clear(&mut self) {
        if let Ok(left) = self.0.get_mut() {
            left.clear();
        }
    }

    /// Take one request from `peer`'s allowance, `allowance` a cycle:
    /// whether it had one left.
    fn take(&self, peer: &PeerId, allowance: impl FnOnce() -> usize) -> bool {
        let Ok(mut left) = self.0.lock() else {
            return false;
        };
        let left = left.entry(*peer).or_insert_with(allowance);
        if *left == 0 {
            return false;
        }
        *left -= 1;
        true
    }
}

/// The full listings to fetch for `work`: each digest an entry names that
/// isn't `kept` yet, with the nodes holding an entry with it, but those that
/// `failed` to hand it over lately. Those of addresses at least a quorum of
/// whose nearest nodes hold an entry first, then the others, each in
/// address order.
fn fetches_wanted(
    work: &[Work],
    failed: impl Fn(&PeerId, &ListingId) -> bool,
    kept: impl Fn(&ListingId) -> bool,
) -> Vec<Wanted> {
    let mut wanted: BTreeMap<ListingId, (bool, DigestCopies)> = BTreeMap::new();
    for (address, _, copies) in work {
        let backed = copies.len() >= QUORUM_THRESHOLD;
        for (peer, entry) in copies {
            let key = (*address, entry.digest);
            if failed(peer, &key) {
                continue;
            }
            let slot = wanted.entry(key).or_insert((backed, Vec::new()));
            slot.0 |= backed;
            slot.1.push((*peer, *entry));
        }
    }
    let mut wanted: Vec<(bool, ListingId, DigestCopies)> = wanted
        .into_iter()
        .filter(|(key, _)| !kept(key))
        .map(|(key, (backed, holders))| (backed, key, holders))
        .collect();
    wanted.sort_by_key(|(backed, _, _)| !*backed);
    wanted
        .into_iter()
        .map(|(_, key, holders)| (key, holders))
        .collect()
}

/// Fetch each of `wanted` ([`fetches_wanted`]), taken as the fetches go,
/// from its holders, one after another until one hands over a listing its
/// entry describes, through `ask` (a `GetRequest` to a node for an address:
/// `None` if it didn't answer, `Some(None)` if it holds none),
/// [`POLL_CONCURRENCY`] at a time. A holder is asked only if `take` gives it
/// a request from its allowance. What hasn't come by `deadline` is left.
/// Each fetch, when it ends, goes to `done`: the listing, if one was handed
/// over, and each holder that was asked and failed to hand one over.
async fn fetch_wanted<A, Fut>(
    wanted: impl Iterator<Item = Wanted>,
    take: impl Fn(&PeerId) -> bool + Copy,
    deadline: Instant,
    ask: A,
    mut done: impl FnMut(ListingId, Option<Listing>, Vec<PeerId>),
) where
    A: Fn(PeerId, XorName) -> Fut + Copy,
    Fut: std::future::Future<Output = Option<Option<Listing>>>,
{
    let mut fetches = stream::iter(wanted)
        .map(|(key, holders)| async move {
            let mut failed = Vec::new();
            for (peer, entry) in holders {
                if !take(&peer) {
                    continue;
                }
                match ask(peer, key.0).await {
                    Some(Some(listing)) if entry.describes(&listing) => {
                        return (key, Some(listing), failed);
                    }
                    _ => failed.push(peer),
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

/// What a drop's evidence rests on, besides the address's copies: its
/// nearest nodes and the nodes that last served it, as a hash.
fn drop_inputs(nearest: &[PeerId], last_holders: &[PeerId]) -> u64 {
    let mut hasher = DefaultHasher::new();
    nearest_hash(nearest).hash(&mut hasher);
    let mut last: Vec<&PeerId> = last_holders.iter().collect();
    last.sort_unstable();
    for peer in last {
        peer.as_bytes().hash(&mut hasher);
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
    /// What deciding keeps of `found`, whose copies were taken, and of which
    /// some couldn't be had if `unheard`.
    fn of(found: &AddressWalk<PeerId>, unheard: bool) -> Self {
        Self {
            address: found.address,
            nearest: nearest_hash(&found.nearest),
            holders: found.copies.iter().map(|(peer, _)| *peer).collect(),
            unheard,
        }
    }
}

/// Wait until the clock is past second `second` (Unix seconds).
async fn wait_past(second: u64) {
    loop {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        if now.as_secs() > second {
            return;
        }
        let rest = Duration::from_secs(1)
            .saturating_sub(Duration::from_nanos(u64::from(now.subsec_nanos())));
        let ahead = Duration::from_secs(second.saturating_sub(now.as_secs()));
        tokio::time::sleep(ahead + rest).await;
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

/// Why the published entry at `address`, with key `key`, that `index`
/// didn't list goes, if it does: `rejected` when `index` decided the address
/// and rejected it, or left it for later with every copy its nearest nodes
/// serve showing a payment from before the payment vault was deployed
/// ([`paid_before_vault`]), which can never count however many nodes come to
/// serve it, so such a listing never shows. Otherwise (left for later) it is
/// kept, carried.
fn removal(index: &ListingsIndex, address: &XorName, key: &ListingKey) -> Option<RemoveReason> {
    let rejected = index.carry(address, key) == Carry::Decided
        || index
            .pending_copies
            .get(address)
            .is_some_and(|copies| paid_before_vault(copies));
    rejected.then_some(RemoveReason::Rejected)
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
            // and any it has is cleared below. (An address every copy of
            // which was paid before the vault isn't kept carried: its entry
            // goes, rejected ([`removal`]).)
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
        let shown = ShownFields::NONE.with(PaymentField::BlockNumber);
        CheckedListing {
            listing: showing_block(address, 81_950_000),
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
    fn a_listed_address_every_copy_of_which_was_paid_before_the_vault_is_removed() {
        // A listed address that the next cycle can't decide: 2 of its 7
        // nearest nodes serve it, and both copies were paid before the
        // payment vault was deployed.
        let x: XorName = [0x3d; 32];
        let (_dir, mut publisher) = publisher();
        let mut listing = ListingsIndex::default();
        listing.listings.push(checked(x));
        publish_read(&mut publisher, &listing, None, AT);
        let key = publisher.keys().unwrap()[0];
        let mut deferring = ListingsIndex::default();
        defer(&mut deferring, x, &[80_204_042, 80_204_042]);
        // None of its copies can ever count, however many nodes come to
        // serve them: its entry goes, rejected, rather than staying carried.
        let reason = removal(&deferring, &x, &key);
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

        // One with a copy paid after the vault was deployed can still count
        // once 4 nodes serve it: it stays, carried. So does one rejected for
        // a reason a later cycle may undo, and one too few copies show
        // anything of.
        let mut mixed = ListingsIndex::default();
        defer(&mut mixed, x, &[80_204_042, 81_950_000]);
        assert_eq!(removal(&mixed, &x, &key), None);
        let mut unread = ListingsIndex::default();
        unread.rejected.push(RejectedListing {
            listing: showing_block(x, 81_950_000),
            problem: "could not read the payment chain: refused; try again".into(),
            nodes: 4,
            nearest: 7,
            again: true,
        });
        assert_eq!(removal(&unread, &x, &key), None);
        assert_eq!(removal(&ListingsIndex::default(), &x, &key), None);
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

    /// The fetches a faulty node `faulty` costs when it advertises `made_up` entries
    /// no other node holds and never answers for them, beside an honest
    /// node's entry for `x`: what is fetched and who failed, how many
    /// requests the faulty node got, and how long it took.
    async fn fetch_round(
        work: &[Work],
        failed: &HashMap<(PeerId, ListingId), u64>,
        faulty: PeerId,
        budget: &FetchBudget,
        deadline: Instant,
        faulty_hangs: bool,
    ) -> (
        Vec<(ListingId, Listing)>,
        Vec<(PeerId, ListingId)>,
        usize,
        Duration,
    ) {
        let asked = std::sync::atomic::AtomicUsize::new(0);
        let wanted = fetches_wanted(
            work,
            |peer, key| failed.contains_key(&(*peer, *key)),
            |_| false,
        );
        let started = Instant::now();
        let asked_ref = &asked;
        let take = |peer: &PeerId| budget.take(peer, || 8);
        let ask = move |peer: PeerId, address: XorName| async move {
            if peer == faulty {
                asked_ref.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if faulty_hangs {
                    std::future::pending::<()>().await;
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
                None
            } else {
                Some(Some(stored(address)))
            }
        };
        let mut fetched = Vec::new();
        let mut refused = Vec::new();
        fetch_wanted(
            wanted.into_iter(),
            take,
            deadline,
            ask,
            |key, listing, failed| {
                fetched.extend(listing.map(|listing| (key, listing)));
                refused.extend(failed.into_iter().map(|peer| (peer, key)));
            },
        )
        .await;
        (
            fetched,
            refused,
            asked.load(std::sync::atomic::Ordering::Relaxed),
            started.elapsed(),
        )
    }

    #[tokio::test(start_paused = true)]
    async fn a_node_that_never_hands_over_listings_costs_only_its_allowance() {
        let (faulty, honest) = (PeerId::from_bytes([1; 32]), PeerId::from_bytes([2; 32]));
        let x: XorName = [0x3d; 32];
        // The faulty node advertises 2,048 made-up addresses, each its own; an honest
        // node and three others serve x.
        let mut work: Vec<Work> = (0..2_048u32)
            .map(|n| {
                let mut address = [0x80; 32];
                address[..4].copy_from_slice(&n.to_be_bytes());
                let entry = DigestEntry::new(&stored(address));
                (address, Vec::new(), vec![(faulty, entry)])
            })
            .collect();
        let entry = DigestEntry::new(&stored(x));
        let others: Vec<(PeerId, DigestEntry)> = (3..=6u8)
            .map(|n| (PeerId::from_bytes([n; 32]), entry))
            .collect();
        let mut copies = vec![(honest, entry)];
        copies.extend(others);
        work.push((x, Vec::new(), copies));
        // The address most nodes hold is fetched first.
        let wanted = fetches_wanted(&work, |_, _| false, |_| false);
        assert_eq!(wanted[0].0, (x, entry.digest));

        let mut failed: HashMap<(PeerId, ListingId), u64> = HashMap::new();
        let mut budget = FetchBudget::default();
        let deadline = Instant::now() + CYCLE;
        let (fetched, refused, asked, took) =
            fetch_round(&work, &failed, faulty, &budget, deadline, false).await;
        assert_eq!(fetched.len(), 1, "x is fetched");
        assert_eq!(fetched[0].0, (x, entry.digest));
        // Its allowance of 8 requests, all at once: one request's wait.
        assert_eq!(asked, 8);
        assert_eq!(refused.len(), 8);
        assert!(took <= Duration::from_secs(11), "{took:?}");
        failed.extend(refused.into_iter().map(|failure| (failure, u64::MAX)));

        // The next cycle: none of those 8 is asked again, and the faulty node gets
        // its 8 requests, no more, whatever it advertises.
        budget.clear();
        let deadline = Instant::now() + CYCLE;
        let (_, refused, asked, took) =
            fetch_round(&work, &failed, faulty, &budget, deadline, false).await;
        assert_eq!(asked, 8);
        assert!(refused.iter().all(|failure| !failed.contains_key(failure)));
        assert!(took <= Duration::from_secs(11), "{took:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn fetching_ends_at_its_deadline() {
        let (faulty, honest) = (PeerId::from_bytes([1; 32]), PeerId::from_bytes([2; 32]));
        let (x, y): (XorName, XorName) = ([0x3d; 32], [0x7e; 32]);
        let work: Vec<Work> = vec![
            (x, Vec::new(), vec![(honest, DigestEntry::new(&stored(x)))]),
            (y, Vec::new(), vec![(faulty, DigestEntry::new(&stored(y)))]),
        ];
        let budget = FetchBudget::default();
        let deadline = Instant::now() + CYCLE;
        let (fetched, refused, asked, took) =
            fetch_round(&work, &HashMap::new(), faulty, &budget, deadline, true).await;
        assert_eq!(fetched.len(), 1);
        assert_eq!(asked, 1);
        // Cut short, not refused: it is asked again next time.
        assert!(refused.is_empty());
        assert_eq!(took, CYCLE);
    }

    #[test]
    fn a_nodes_allowance_of_requests_is_kept_for_the_cycle() {
        let peer = PeerId::from_bytes([1; 32]);
        let mut budget = FetchBudget::default();
        assert!((0..8).all(|_| budget.take(&peer, || 8)));
        assert!(!budget.take(&peer, || 8));
        budget.clear();
        assert!(budget.take(&peer, || 8));
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
                    &rmp_serde::to_vec(&kept).unwrap(),
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
    async fn a_cycle_removes_a_listed_entry_whose_copies_were_all_paid_before_the_vault() {
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
        census_nodes(&mut producer, 8);
        let x = numbered(7);
        let mut listed = ListingsIndex::default();
        listed.listings.push(checked(x));
        publish_read(&mut producer.publisher, &listed, None, AT);
        // Two of its nearest nodes serve copies that show a block before the
        // vault was deployed.
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

    #[tokio::test]
    async fn a_size_read_is_filled_in_to_its_entry() {
        let dir = tempfile::tempdir().unwrap();
        let (mut producer, _node) = offline_producer(dir.path()).await;
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
        let mut index = ListingsIndex::default();
        index.listings.push(shrunk);
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

        // Its root map couldn't be read: it is tried again only later.
        {
            let mut txn = producer.store.env().write_txn().unwrap();
            let mut value = 0u64.to_be_bytes().to_vec();
            value.extend(rmp_serde::to_vec(&three_chunks(1_024, true)).unwrap());
            producer
                .known
                .put(&mut txn, &tagged(SIZE_WANTED_TAG, &x), &value)
                .unwrap();
            txn.commit().unwrap();
        }
        producer.last_status = Some(Status::default());
        producer.take_sizes(vec![(x, None)]).await.unwrap();
        producer.start_sizes().unwrap();
        assert!(producer.size_job.is_none(), "nothing is due yet");
        assert_eq!(producer.publisher.seq(), seq);

        // Read: the entry is put again with it, decided when it was.
        producer
            .take_sizes(vec![(x, Some(92_000_000))])
            .await
            .unwrap();
        let filled = producer.publisher.entry(&x).unwrap().unwrap();
        assert_eq!(filled.entry.listing.size, Some(92_000_000));
        assert_eq!(filled.entry.decided_at, published.entry.decided_at);
        assert_eq!(producer.publisher.seq(), seq + 1);
        let txn = producer.store.env().read_txn().unwrap();
        assert_eq!(producer.sizes.get(&txn, &x).unwrap(), Some(92_000_000));
        assert!(producer
            .known
            .get(&txn, &tagged(SIZE_WANTED_TAG, &x))
            .unwrap()
            .is_none());
    }
}
