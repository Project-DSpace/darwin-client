//! The published listings index, version 1: the files a producer writes
//! under `listings/v1/` and followers (a gateway, a viewer, anyone) read.
//!
//! `docs/listings-v1.md` in this repository specifies every file for
//! consumers in any language; these are its types, and the rules that lay
//! the files out. Nothing here does I/O.
//!
//! The index holds one entry per listed address ([`Entry`]): what the
//! listing shows and how far it was checked, as `darwin listings --json`
//! prints it, less what changes from minute to minute. How many of the
//! nodes nearest an address serve it is published apart, in support files
//! ([`Support`]), so that the files holding entries change only when an
//! entry does.
//!
//! - [`Head`] (`head.json`): where the index stands, and the newest
//!   [`HEAD_LISTINGS`] entries.
//! - [`AddressShard`] and [`SupportShard`] (`by-address/`): every entry, and
//!   its support, by the first [`PREFIX_DIGITS`] hex digits of its address.
//! - [`NameShard`] (`by-name/`): entries by exact name.
//! - [`TypeIndex`] and [`TypePage`] (`by-type/`): entries by exact content
//!   type, in pages of [`TYPE_PAGE_LISTINGS`].
//! - [`Pages`] and [`Page`] (`pages.json`, `pages/`): the whole index in key
//!   order, in content-addressed pages ([`time_pages`]).
//! - [`FeedIndex`] and [`FeedSegment`] (`feed/`): every change, numbered,
//!   kept for good.
//! - [`Status`] (`status.json`) and [`Rejected`] (`rejected.json`): how the
//!   producer is doing, and what it didn't list.

use std::ops::Range;
use std::time::Duration;

use ant_listings::{CheckLevel, Envelope, Listing, ListingKey, PaymentField};
use ant_protocol::XorName;
use serde::{Deserialize, Serialize};

use super::listings::{paid_quote_hash, PendingCopy, RejectedListing};

/// How many entries `head.json` holds: the newest.
pub const HEAD_LISTINGS: usize = 50;

/// The hex digits that name a shard: the first three of an address, or of
/// the BLAKE3 hash of a name or content type.
pub const PREFIX_DIGITS: usize = 3;

/// How many shards each of `by-address/`, `by-name/` and `by-type/` has:
/// one for each [`PREFIX_DIGITS`]-digit prefix, `000` to `fff`.
pub const SHARDS: usize = 1 << (4 * PREFIX_DIGITS);

/// How many entries each page of a content type holds, but its last: as
/// many as one answer of a node's carries.
pub const TYPE_PAGE_LISTINGS: usize = 256;

/// A time page ends after an address whose BLAKE3 hash, read as a
/// big-endian number, is a multiple of this ([`ends_page`]).
pub const PAGE_BREAK_MODULUS: u64 = 1_000;

/// The most entries a time page holds: one ends after this many, wherever
/// [`ends_page`] would end it.
pub const MAX_PAGE_LISTINGS: usize = 4_000;

/// How many records a feed segment holds once closed.
pub const FEED_SEGMENT_RECORDS: u64 = 1_000;

/// Support files are written at most this often. An epoch's first
/// publication, when it takes entries from an earlier index (marked
/// [`carried`](Support::carried)), doesn't start it: the first cycle to
/// decide those entries publishes their support at once.
pub const SUPPORT_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// How long a time page that `pages.json` no longer lists is kept, for
/// readers part way through the pages.
pub const SUPERSEDED_KEPT: Duration = Duration::from_secs(24 * 60 * 60);

/// Where the index stands: [`Head`].
pub const HEAD_FILE: &str = "head.json";

/// The time pages, in key order: [`Pages`].
pub const PAGES_FILE: &str = "pages.json";

/// The feed's segments: [`FeedIndex`].
pub const FEED_INDEX_FILE: &str = "feed/index.json";

/// How the producer is doing: [`Status`].
pub const STATUS_FILE: &str = "status.json";

/// What the producer didn't list: [`Rejected`].
pub const REJECTED_FILE: &str = "rejected.json";

/// What a listing shows: its address, what the uploader declared, and the
/// payment fields its uploader chose to show. Hidden payment fields are
/// absent, and named in `hidden`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListingFields {
    /// The file's address, as 64 lowercase hex digits.
    pub address: String,
    /// The name the uploader declared, if any.
    pub name: Option<String>,
    /// The content type the uploader declared, if any.
    pub content_type: Option<String>,
    /// The file's size in bytes, when the data map gives it directly.
    pub size: Option<u64>,
    /// Whether anyone with the address can read the file: the envelope
    /// holds its data map, rather than withholding it.
    pub readable: bool,
    /// The payment fields the uploader hid, in this order: `tx-hash`,
    /// `block`, `timestamp`, `log-index`, `quote`.
    #[serde(default)]
    pub hidden: Vec<String>,
    /// The payment's transaction hash, `0x` and 64 hex digits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    /// The payment's block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
    /// The payment's block timestamp, in Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_timestamp: Option<u64>,
    /// The position in its block of the vault's payment event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_index: Option<u64>,
    /// The hash of the paid quote, `0x` and 64 hex digits, when the quote is
    /// shown: what the vault's payment event names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote_hash: Option<String>,
    /// For a listing that hides its block timestamp: when the nodes nearest
    /// it first stored it, as they date it, in Unix seconds rounded down to
    /// the hour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<u64>,
    /// The time the index sorts by: the block timestamp, else `first_seen`,
    /// else 0.
    pub time: u64,
}

impl ListingFields {
    /// What `listing` shows.
    #[must_use]
    pub fn new(listing: &Listing) -> Self {
        let payment = &listing.payment;
        Self {
            address: hex::encode(listing.address),
            name: listing.metadata.name.clone(),
            content_type: listing.metadata.content_type.clone(),
            size: listing.size,
            readable: !listing.flags.withheld,
            hidden: listing
                .flags
                .shown
                .hidden()
                .map(PaymentField::name)
                .map(str::to_string)
                .collect(),
            tx_hash: payment
                .tx_hash
                .map(|hash| format!("0x{}", hex::encode(hash))),
            block_number: payment.block_number,
            block_timestamp: payment.block_timestamp,
            log_index: payment.log_index,
            quote_hash: payment
                .quote
                .as_deref()
                .and_then(paid_quote_hash)
                .map(|hash| format!("0x{}", hex::encode(hash))),
            first_seen: listing.first_seen,
            time: listing.key().time,
        }
    }

    /// The file's address, if `address` is one.
    #[must_use]
    pub fn address(&self) -> Option<XorName> {
        parse_hex32(&self.address)
    }

    /// The listing's place in the index: its time, its block and log index
    /// (each 0 when hidden), and its address. `None` if `address` isn't one.
    #[must_use]
    pub fn key(&self) -> Option<ListingKey> {
        Some(ListingKey {
            time: self.time,
            block_number: self.block_number.unwrap_or(0),
            log_index: self.log_index.unwrap_or(0),
            address: self.address()?,
        })
    }
}

/// One listed address: what its listing shows, how far it was checked, and
/// when the producer decided it as it stands. Every file but the support
/// files and `rejected.json` carries entries like this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// What the listing shows.
    #[serde(flatten)]
    pub listing: ListingFields,
    /// `verified`: the quote is shown, and the payment is checked on chain
    /// and tied to the address; or `reported`: the quote is hidden, the
    /// shown fields are checked, and the listing rests on the nodes nearest
    /// its address.
    pub check: CheckLevel,
    /// When the producer decided the entry as it stands: the start of that
    /// cycle, in Unix seconds. A decision that finds the same entry again
    /// leaves it as it is.
    pub decided_at: u64,
}

impl Entry {
    /// The entry for `listing`, checked to `check`, decided in the cycle
    /// that began at `decided_at`.
    #[must_use]
    pub fn new(listing: &Listing, check: CheckLevel, decided_at: u64) -> Self {
        Self {
            listing: ListingFields::new(listing),
            check,
            decided_at,
        }
    }

    /// The listing's place in the index ([`ListingFields::key`]).
    #[must_use]
    pub fn key(&self) -> Option<ListingKey> {
        self.listing.key()
    }
}

/// An entry as its address's shard holds it: with the data map, for a
/// readable listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardEntry {
    /// The entry.
    #[serde(flatten)]
    pub entry: Entry,
    /// The file's data map, hex-encoded, exactly as the envelope holds it:
    /// enough to read the file without fetching the envelope. `None` when
    /// the envelope withholds it.
    pub data_map: Option<String>,
}

impl ShardEntry {
    /// `entry`, with the data map `envelope` (the envelope at its address)
    /// holds.
    #[must_use]
    pub fn new(entry: Entry, envelope: &Envelope) -> Self {
        Self {
            entry,
            data_map: envelope.data_map_bytes().map(hex::encode),
        }
    }
}

/// How many of the nodes nearest a listed address serve its listing, as the
/// producer last measured it. Written at most every [`SUPPORT_INTERVAL`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Support {
    /// The file's address, as 64 lowercase hex digits.
    pub address: String,
    /// How many of the nodes nearest the address answered and serve the
    /// listing.
    pub nodes: usize,
    /// How many nearest nodes count: 7, unless the network has fewer.
    pub nearest: usize,
    /// Whether `nodes` reaches the quorum, 4 of 7. Always true for a
    /// reported listing; a verified one without it is the earliest of
    /// several payments for its address, none of which a quorum serves.
    pub quorum: bool,
    /// Whether the entry is kept from an earlier decision that the latest
    /// cycle couldn't make again (too few of the nearest nodes answered, or
    /// serve it), while what it takes to remove it isn't shown either. An
    /// epoch's first publication may also take entries from an earlier
    /// index, marked carried until a cycle decides them.
    pub carried: bool,
}

/// `head.json`: where the index stands, its newest entries, and where the
/// other files are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Head {
    /// The feed's epoch ([`new_epoch`]): a follower that sees it change
    /// reads the index afresh.
    pub epoch: String,
    /// The number of the feed's latest record, 0 if it has none.
    pub seq: u64,
    /// How many entries the index holds.
    pub count: u64,
    /// When the index last changed: the start of the cycle that wrote the
    /// feed's latest record, or that began the epoch if it has none, in
    /// Unix seconds.
    pub generated_at: u64,
    /// The newest [`HEAD_LISTINGS`] entries, newest first, without data
    /// maps.
    pub listings: Vec<Entry>,
    /// Where the other files are.
    pub links: Links,
}

/// Where the other files are, relative to the directory `head.json` is in.
/// In the sharded ones, `{prefix}` stands for a shard's three hex digits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Links {
    /// [`STATUS_FILE`].
    pub status: String,
    /// [`REJECTED_FILE`].
    pub rejected: String,
    /// [`PAGES_FILE`].
    pub pages: String,
    /// [`FEED_INDEX_FILE`].
    pub feed: String,
    /// An address's shard ([`address_shard_path`]).
    pub by_address: String,
    /// An address's support file ([`support_path`]).
    pub support: String,
    /// A name's shard ([`name_shard_path`]).
    pub by_name: String,
    /// A content type's index ([`type_index_path`]).
    pub by_type: String,
}

impl Default for Links {
    fn default() -> Self {
        Self {
            status: STATUS_FILE.into(),
            rejected: REJECTED_FILE.into(),
            pages: PAGES_FILE.into(),
            feed: FEED_INDEX_FILE.into(),
            by_address: address_shard_path("{prefix}"),
            support: support_path("{prefix}"),
            by_name: name_shard_path("{prefix}"),
            by_type: type_index_path("{prefix}"),
        }
    }
}

/// `by-address/<prefix>.json`: every entry whose address starts with
/// `prefix`, in address order, with data maps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressShard {
    /// The shard's three hex digits.
    pub prefix: String,
    /// Its entries, in address order.
    pub listings: Vec<ShardEntry>,
}

/// `by-address/<prefix>.support.json`: the support of every entry whose
/// address starts with `prefix`, in address order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportShard {
    /// The shard's three hex digits.
    pub prefix: String,
    /// Each entry's support, in address order.
    pub support: Vec<Support>,
}

/// `by-name/<prefix>.json`: the entries of every name whose BLAKE3 hash
/// starts with `prefix` ([`name_prefix`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameShard {
    /// The shard's three hex digits.
    pub prefix: String,
    /// Each name and its entries, the names in byte order.
    pub names: Vec<NameGroup>,
}

/// The entries with one exact name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameGroup {
    /// The name, exactly as the listings declare it.
    pub name: String,
    /// Its entries, newest first.
    pub listings: Vec<Entry>,
}

/// `by-type/<prefix>/index.json`: every content type whose BLAKE3 hash
/// starts with `prefix` ([`type_prefix`]), and where its pages are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeIndex {
    /// The shard's three hex digits.
    pub prefix: String,
    /// Each content type, in byte order.
    pub types: Vec<TypeSummary>,
}

/// One content type's entries: how many, and its first and last page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeSummary {
    /// The content type, exactly as the listings declare it.
    pub content_type: String,
    /// How many entries have it.
    pub count: u64,
    /// How many pages hold them ([`type_pages`]).
    pub pages: u64,
    /// The first page, with the oldest entries ([`type_page_path`]).
    pub first: String,
    /// The last page, with the newest.
    pub last: String,
}

/// `by-type/<prefix>/<type id>-<page>.json`: one page of a content type's
/// entries, in key order. Every page but the last holds
/// [`TYPE_PAGE_LISTINGS`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypePage {
    /// The content type.
    pub content_type: String,
    /// The page's number, from 0 for the oldest entries.
    pub page: u64,
    /// The page before, with older entries: `None` for the first.
    pub prev: Option<String>,
    /// The page after, with newer entries: `None` for the last.
    pub next: Option<String>,
    /// The entries, in key order.
    pub listings: Vec<Entry>,
}

/// `pages.json`: the time pages that hold the whole index, in key order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pages {
    /// The feed's epoch.
    pub epoch: String,
    /// The number of the feed's latest record that the pages hold: follow
    /// the feed after it.
    pub seq: u64,
    /// How many entries the pages hold.
    pub count: u64,
    /// The pages, in key order.
    pub pages: Vec<PageRef>,
}

/// A time page, as `pages.json` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageRef {
    /// Where it is ([`page_path`]).
    pub path: String,
    /// Its first entry's key, as 112 hex digits ([`key_hex`]).
    pub first: String,
    /// Its last entry's key.
    pub last: String,
    /// How many entries it holds.
    pub count: u64,
}

/// `pages/<first key>-<hash>.json`: a time page, its entries in key order.
/// Its name holds the BLAKE3 hash of its bytes, so it never changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page {
    /// The entries, in key order.
    pub listings: Vec<Entry>,
}

/// `feed/index.json`: the feed's segments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedIndex {
    /// The feed's epoch.
    pub epoch: String,
    /// The number of its latest record, 0 if it has none.
    pub seq: u64,
    /// Its segments, in order.
    pub segments: Vec<SegmentRef>,
}

/// A feed segment, as `feed/index.json` lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentRef {
    /// Where it is ([`segment_path`]).
    pub path: String,
    /// The number of its first record.
    pub first: u64,
    /// The number of its last record. A segment of
    /// [`FEED_SEGMENT_RECORDS`] records is closed: it doesn't change within
    /// its epoch (a new epoch writes its own segments under the same names).
    pub last: u64,
}

/// `feed/<first>.json`: up to [`FEED_SEGMENT_RECORDS`] of the feed's
/// records, from record `first` on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedSegment {
    /// The feed's epoch.
    pub epoch: String,
    /// The number of its first record.
    pub first: u64,
    /// The records, in order.
    pub records: Vec<FeedRecord>,
}

/// One change to the index, numbered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedRecord {
    /// The record's number: 1 for the epoch's first, then one more for each.
    pub seq: u64,
    /// When the change was made: the start of that cycle, in Unix seconds.
    pub at: u64,
    /// The change.
    #[serde(flatten)]
    pub change: Change,
}

/// A change to the index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Change {
    /// The address's entry is now this one: it is new to the index, or
    /// replaces the address's earlier entry.
    Put {
        /// The entry, without data map.
        listing: Box<Entry>,
    },
    /// The address has no entry any more.
    Remove {
        /// The file's address, as 64 lowercase hex digits.
        address: String,
        /// Why.
        reason: RemoveReason,
    },
}

/// Why an address left the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoveReason {
    /// The network no longer stores its file: in one cycle, every node
    /// nearest the address showed it serves none. The payment stays on
    /// chain.
    NoLongerServed,
    /// Deciding it again rejected it.
    Rejected,
    /// A reason this version doesn't know.
    #[serde(other)]
    Other,
}

/// `rejected.json`: listings the producer didn't list, with why.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rejected {
    /// The latest rejection or deferral of each such address, in key order.
    pub listings: Vec<RejectedEntry>,
}

/// A listing the producer didn't list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedEntry {
    /// What the listing shows, with `first_seen` as the nodes nearest its
    /// address date it before any check.
    #[serde(flatten)]
    pub listing: ListingFields,
    /// Why it doesn't count.
    pub problem: String,
    /// Whether nothing final was decided, so it may be listed later
    /// (deferred); false for a listing rejected for good.
    pub again: bool,
    /// How many of the nodes nearest its address serve it.
    pub nodes: usize,
    /// How many nearest nodes count.
    pub nearest: usize,
    /// When the producer decided this: the start of that cycle, in Unix
    /// seconds.
    pub decided_at: u64,
    /// For a listing too few of its nearest nodes serve yet, each of their
    /// copies; empty otherwise.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub copies: Vec<CopyFields>,
}

impl RejectedEntry {
    /// `rejected`, with the copies its nearest nodes serve if it is
    /// pending, decided in the cycle that began at `decided_at`.
    #[must_use]
    pub fn new(rejected: &RejectedListing, copies: &[PendingCopy], decided_at: u64) -> Self {
        Self {
            listing: ListingFields::new(&rejected.listing),
            problem: rejected.problem.clone(),
            again: rejected.again,
            nodes: rejected.nodes,
            nearest: rejected.nearest,
            decided_at,
            copies: copies.iter().map(CopyFields::from).collect(),
        }
    }
}

/// One node's copy of a listing too few of the nodes nearest its address
/// serve yet: what it shows of when the listing was paid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CopyFields {
    /// The node's id, as 64 lowercase hex digits.
    pub node: String,
    /// The block the copy shows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
    /// The block timestamp it shows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_timestamp: Option<u64>,
    /// The node's own `first_seen`, for a copy that hides its block
    /// timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<u64>,
    /// The time the copy sorts by: the block timestamp, else `first_seen`.
    pub time: u64,
    /// Whether the block or block timestamp it shows is earlier than the
    /// payment vault's deployment, so it paid something else.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub before_vault_deployment: bool,
}

impl From<&PendingCopy> for CopyFields {
    fn from(copy: &PendingCopy) -> Self {
        Self {
            node: hex::encode(copy.node.as_bytes()),
            block_number: copy.block_number,
            block_timestamp: copy.block_timestamp,
            first_seen: copy.first_seen,
            time: copy.time(),
            before_vault_deployment: copy.before_vault_deployment,
        }
    }
}

/// `status.json`: how the producer is doing, written every cycle.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    /// The feed's epoch.
    pub epoch: String,
    /// The number of the feed's latest record.
    pub seq: u64,
    /// How many entries the index holds.
    pub count: u64,
    /// When this file was written, at the end of the latest cycle, in Unix
    /// seconds.
    pub generated_at: u64,
    /// When the producer started, in Unix seconds: `totals` count from then.
    pub started_at: u64,
    /// The latest cycle.
    pub cycle: CycleStatus,
    /// Counts since `started_at`.
    pub totals: Totals,
    /// The nodes the producer knows.
    pub census: CensusStatus,
    /// Addresses left for a later cycle, by why.
    pub deferred: Vec<DeferredGroup>,
    /// Entries that fewer than all of their nearest nodes serve.
    pub below_full: BelowFull,
    /// Entries removed, and entries kept unconfirmed.
    pub drops: Drops,
    /// What the producer uses of its machine, where it can tell.
    pub resources: Resources,
}

/// The latest cycle, in `status.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CycleStatus {
    /// When it began, in Unix seconds.
    pub started_at: u64,
    /// How long it took, in milliseconds.
    pub millis: u64,
    /// Bytes received from nodes.
    pub bytes_in: u64,
    /// Bytes sent to nodes.
    pub bytes_out: u64,
    /// Calls made to the payment chain's RPC providers.
    pub rpc_calls: u64,
    /// Those that failed.
    pub rpc_errors: u64,
    /// Addresses decided.
    pub decided: u64,
    /// Whether too few nodes answered (fewer than 7, or under three
    /// quarters of the census) for the cycle to decide or drop anything.
    pub too_few_answered: bool,
}

/// Counts since the producer started, in `status.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totals {
    /// Cycles run.
    pub cycles: u64,
    /// Bytes received from nodes.
    pub bytes_in: u64,
    /// Bytes sent to nodes.
    pub bytes_out: u64,
    /// Calls to each RPC provider, and how many failed.
    pub rpc: Vec<RpcCalls>,
}

/// Calls to one RPC provider.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcCalls {
    /// The provider's host name.
    pub provider: String,
    /// Calls made.
    pub calls: u64,
    /// Calls that failed.
    pub errors: u64,
}

/// The nodes the producer knows (its census), in `status.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CensusStatus {
    /// How many nodes it knows.
    pub nodes: u64,
    /// How many answered in the latest cycle.
    pub answering: u64,
    /// How many parts the address space is split into, each asked of its
    /// own nodes.
    pub leaves: u64,
    /// How many nodes run each version, by the version their user agent
    /// gives.
    pub versions: Vec<VersionCount>,
    /// The nodes that didn't answer in the latest cycle.
    pub silent: Vec<SilentNode>,
}

/// How many nodes run one version.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionCount {
    /// The version, as the node's user agent gives it; `None` if unknown.
    pub version: Option<String>,
    /// How many nodes.
    pub nodes: u64,
}

/// A node that didn't answer in the latest cycle.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SilentNode {
    /// The node's id, as 64 lowercase hex digits.
    pub node: String,
    /// When it last answered, in Unix seconds; `None` if never.
    pub last_answered: Option<u64>,
}

/// Addresses left for a later cycle for one reason, in `status.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredGroup {
    /// Why, as a short code (see the format's documentation).
    pub reason: String,
    /// How many addresses.
    pub addresses: u64,
    /// Since when the longest-deferred of them has been, in Unix seconds.
    pub oldest_since: u64,
}

/// Entries that fewer than all of their nearest nodes serve, in
/// `status.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BelowFull {
    /// How many.
    pub listings: u64,
    /// Since when the longest-standing of them has been below, in Unix
    /// seconds; `None` if there are none.
    pub oldest_since: Option<u64>,
}

/// Entries removed, and kept unconfirmed, in `status.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Drops {
    /// Entries the latest cycle removed.
    pub removed: u64,
    /// Entries kept though the producer's latest checks don't confirm them
    /// ([`Support::carried`]).
    pub carried: u64,
}

/// What the producer uses of its machine, in `status.json`. `None` where it
/// can't tell.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resources {
    /// Its resident memory, in bytes.
    pub rss_bytes: Option<u64>,
    /// The size of its store, in bytes.
    pub store_bytes: Option<u64>,
    /// The size of the files it publishes, in bytes.
    pub files_bytes: Option<u64>,
    /// Free space on the disk the store is on, in bytes.
    pub disk_free_bytes: Option<u64>,
}

/// A new epoch for a feed: random, never 0, as 16 lowercase hex digits.
#[must_use]
pub fn new_epoch() -> String {
    loop {
        let epoch: u64 = rand::random();
        if epoch != 0 {
            return format!("{epoch:016x}");
        }
    }
}

/// The bytes a file holds: `value` as compact JSON. A time page's name
/// holds the BLAKE3 hash of exactly these ([`page_path`]).
///
/// # Errors
///
/// If `value` can't be written as JSON, which none of this module's types
/// can fail.
pub fn file_bytes<T: Serialize>(value: &T) -> serde_json::Result<Vec<u8>> {
    serde_json::to_vec(value)
}

/// Every shard prefix, `000` to `fff`, in order.
pub fn prefixes() -> impl Iterator<Item = String> {
    (0..SHARDS).map(|shard| format!("{shard:0width$x}", width = PREFIX_DIGITS))
}

/// The shard prefix of an address: its first [`PREFIX_DIGITS`] hex digits.
#[must_use]
pub fn address_prefix(address: &XorName) -> String {
    let mut prefix = hex::encode(address);
    prefix.truncate(PREFIX_DIGITS);
    prefix
}

/// The shard prefix of a name: the first [`PREFIX_DIGITS`] hex digits of
/// the BLAKE3 hash of its UTF-8 bytes, exactly as the listing declares it.
#[must_use]
pub fn name_prefix(name: &str) -> String {
    let mut prefix = blake3::hash(name.as_bytes()).to_hex().to_string();
    prefix.truncate(PREFIX_DIGITS);
    prefix
}

/// A content type's id: the BLAKE3 hash of its bytes, exactly as the
/// listing declares it, as 64 lowercase hex digits.
#[must_use]
pub fn type_id(content_type: &str) -> String {
    blake3::hash(content_type.as_bytes()).to_hex().to_string()
}

/// The shard prefix of a content type: the first [`PREFIX_DIGITS`] hex
/// digits of its [`type_id`].
#[must_use]
pub fn type_prefix(content_type: &str) -> String {
    let mut prefix = type_id(content_type);
    prefix.truncate(PREFIX_DIGITS);
    prefix
}

/// Where the entries whose addresses start with `prefix` are.
#[must_use]
pub fn address_shard_path(prefix: &str) -> String {
    format!("by-address/{prefix}.json")
}

/// Where the support of the entries whose addresses start with `prefix` is.
#[must_use]
pub fn support_path(prefix: &str) -> String {
    format!("by-address/{prefix}.support.json")
}

/// Where the entries of the names whose prefix ([`name_prefix`]) is
/// `prefix` are.
#[must_use]
pub fn name_shard_path(prefix: &str) -> String {
    format!("by-name/{prefix}.json")
}

/// Where the content types whose prefix ([`type_prefix`]) is `prefix` are
/// listed.
#[must_use]
pub fn type_index_path(prefix: &str) -> String {
    format!("by-type/{prefix}/index.json")
}

/// Where page `page` (from 0) of `content_type`'s entries is.
#[must_use]
pub fn type_page_path(content_type: &str, page: u64) -> String {
    let id = type_id(content_type);
    format!("by-type/{}/{id}-{page}.json", &id[..PREFIX_DIGITS])
}

/// How many pages hold `count` entries of one content type.
#[must_use]
pub fn type_pages(count: u64) -> u64 {
    count.div_ceil(TYPE_PAGE_LISTINGS as u64)
}

/// A key as 112 lowercase hex digits: its time, block and log index as 8
/// bytes big-endian each, then the address. Their order as text is the
/// keys' order.
#[must_use]
pub fn key_hex(key: &ListingKey) -> String {
    hex::encode(key.to_bytes())
}

/// Read [`key_hex`] back. `None` unless `text` is 112 hex digits.
#[must_use]
pub fn parse_key(text: &str) -> Option<ListingKey> {
    ListingKey::from_bytes(&hex::decode(text).ok()?)
}

/// Whether a time page ends after the entry at `address`: the BLAKE3 hash
/// of its 32 bytes, read as a big-endian number, is a multiple of
/// [`PAGE_BREAK_MODULUS`]. The pages' ends then move only where entries
/// come or go, so a change to the index changes few pages.
#[must_use]
pub fn ends_page(address: &XorName) -> bool {
    let hash = blake3::hash(address);
    hash.as_bytes().iter().fold(0, |rest, byte| {
        (rest * 256 + u64::from(*byte)) % PAGE_BREAK_MODULUS
    }) == 0
}

/// Split entries in key order, by their addresses, into time pages: each
/// ends after an address [`ends_page`] ends one at, or after
/// [`MAX_PAGE_LISTINGS`] entries, whichever comes first; the last ends with
/// the entries. The ranges of `addresses` each page holds, in order.
#[must_use]
pub fn time_pages(addresses: &[XorName]) -> Vec<Range<usize>> {
    let mut pages = Vec::new();
    let mut start = 0;
    for (index, address) in addresses.iter().enumerate() {
        if ends_page(address) || index + 1 - start == MAX_PAGE_LISTINGS {
            pages.push(start..index + 1);
            start = index + 1;
        }
    }
    if start < addresses.len() {
        pages.push(start..addresses.len());
    }
    pages
}

/// Where a time page is: named by its first entry's key and the BLAKE3
/// hash of its bytes ([`file_bytes`]), so that a page whose entries change
/// gets a new name.
#[must_use]
pub fn page_path(first: &ListingKey, bytes: &[u8]) -> String {
    format!(
        "pages/{}-{}.json",
        key_hex(first),
        blake3::hash(bytes).to_hex()
    )
}

/// The number of the first record of the segment holding record `seq`
/// (from 1): segments hold records 1 to 1,000, 1,001 to 2,000, and so on.
#[must_use]
pub fn segment_first(seq: u64) -> u64 {
    seq.saturating_sub(1) / FEED_SEGMENT_RECORDS * FEED_SEGMENT_RECORDS + 1
}

/// Where the segment whose first record is `first` is.
#[must_use]
pub fn segment_path(first: u64) -> String {
    format!("feed/{first}.json")
}

/// 32 bytes from 64 hex digits.
fn parse_hex32(text: &str) -> Option<[u8; 32]> {
    hex::decode(text).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ant_listings::{Flags, ListingPayment, Metadata, ShownFields};
    use ant_protocol::evm::{Amount, PaymentQuote, RewardsAddress};
    use ant_protocol::transport::PeerId;
    use serde::de::DeserializeOwned;
    use std::fmt::Debug;

    /// A quote with fixed fields, as a listing carries it.
    fn quote_bytes() -> Vec<u8> {
        let quote = PaymentQuote {
            content: xor_name::XorName([0x11; 32]),
            timestamp: std::time::UNIX_EPOCH + Duration::from_secs(1_790_000_000),
            price: Amount::from(20u64),
            rewards_address: RewardsAddress::new([0x33; 20]),
            pub_key: vec![0x44; 4],
            signature: vec![0x55; 4],
            committed_key_count: 0,
            commitment_pin: None,
        };
        rmp_serde::to_vec(&quote).unwrap()
    }

    /// A listing showing every payment field.
    fn shown() -> Listing {
        Listing {
            address: [0x11; 32],
            flags: Flags::V1,
            metadata: Metadata {
                content_type: Some("text/plain".into()),
                name: Some("a.txt".into()),
            },
            size: Some(20_480),
            payment: ListingPayment {
                tx_hash: Some([0x22; 32]),
                block_number: Some(81_942_857),
                block_timestamp: Some(1_791_321_603),
                log_index: Some(7),
                quote: Some(quote_bytes()),
            },
            first_seen: None,
        }
    }

    /// A private listing showing only its block: dated by `first_seen`.
    fn hiding() -> Listing {
        Listing {
            address: [0xa0; 32],
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
            first_seen: Some(1_791_324_000),
        }
    }

    const SHOWN_FIELDS: &str = concat!(
        r#""address":"1111111111111111111111111111111111111111111111111111111111111111","#,
        r#""name":"a.txt","content_type":"text/plain","size":20480,"readable":true,"hidden":[],"#,
        r#""tx_hash":"0x2222222222222222222222222222222222222222222222222222222222222222","#,
        r#""block_number":81942857,"block_timestamp":1791321603,"log_index":7,"#,
        r#""quote_hash":"0x"#,
    );

    const HIDING_ENTRY: &str = concat!(
        r#"{"address":"a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0","#,
        r#""name":null,"content_type":null,"size":null,"readable":false,"#,
        r#""hidden":["tx-hash","timestamp","log-index","quote"],"#,
        r#""block_number":81950000,"first_seen":1791324000,"time":1791324000,"#,
        r#""check":"reported","decided_at":1791324060}"#,
    );

    fn shown_entry() -> Entry {
        Entry::new(&shown(), CheckLevel::Verified, 1_791_321_660)
    }

    fn hiding_entry() -> Entry {
        Entry::new(&hiding(), CheckLevel::Reported, 1_791_324_060)
    }

    /// The hash of [`quote_bytes`]' quote, as the vault's event names it.
    const QUOTE_HASH: &str = "4c10e4ae831c5a287c8f92d65bfc964201171696de4f11aa4d568f7e1cbf4ebd";

    /// The shown entry's JSON, with its quote's hash.
    fn shown_entry_json() -> String {
        format!(
            r#"{{{SHOWN_FIELDS}{QUOTE_HASH}","time":1791321603,"check":"verified","decided_at":1791321660}}"#
        )
    }

    /// `value` written as its file is, and read back.
    fn pinned<T: Serialize + DeserializeOwned + PartialEq + Debug>(value: &T, json: &str) {
        let bytes = file_bytes(value).unwrap();
        assert_eq!(String::from_utf8(bytes.clone()).unwrap(), json);
        assert_eq!(&serde_json::from_slice::<T>(&bytes).unwrap(), value);
    }

    #[test]
    fn entries_are_pinned() {
        pinned(&shown_entry(), &shown_entry_json());
        pinned(&hiding_entry(), HIDING_ENTRY);
        // The quote's hash is the one the vault's event names.
        assert_eq!(
            shown_entry().listing.quote_hash,
            paid_quote_hash(&quote_bytes()).map(|hash| format!("0x{}", hex::encode(hash)))
        );
    }

    #[test]
    fn a_quote_that_does_not_decode_has_no_hash() {
        let mut listing = shown();
        listing.payment.quote = Some(vec![1, 2, 3]);
        let entry = Entry::new(&listing, CheckLevel::Verified, 1);
        assert_eq!(entry.listing.quote_hash, None);
        assert!(entry.listing.hidden.is_empty());
    }

    #[test]
    fn an_entry_gives_the_listings_key() {
        for listing in [shown(), hiding()] {
            let entry = Entry::new(&listing, CheckLevel::Reported, 0);
            assert_eq!(entry.key(), Some(listing.key()));
            assert_eq!(entry.listing.address(), Some(listing.address));
        }
        let mut entry = hiding_entry();
        entry.listing.address = "a0".into();
        assert_eq!(entry.key(), None);
    }

    #[test]
    fn shard_entries_carry_the_data_map() {
        let readable = ShardEntry {
            entry: hiding_entry(),
            data_map: Some("93c4".into()),
        };
        let json = HIDING_ENTRY.replace('}', r#","data_map":"93c4"}"#);
        pinned(&readable, &json);
        let withheld = ShardEntry {
            entry: hiding_entry(),
            data_map: None,
        };
        pinned(
            &withheld,
            &HIDING_ENTRY.replace('}', r#","data_map":null}"#),
        );
    }

    #[test]
    fn head_is_pinned() {
        let head = Head {
            epoch: "8c1f0e2d3b4a5968".into(),
            seq: 12,
            count: 2,
            generated_at: 1_791_324_060,
            listings: vec![hiding_entry(), shown_entry()],
            links: Links::default(),
        };
        let json = format!(
            concat!(
                r#"{{"epoch":"8c1f0e2d3b4a5968","seq":12,"count":2,"generated_at":1791324060,"#,
                r#""listings":[{},{}],"links":{{"status":"status.json","rejected":"rejected.json","#,
                r#""pages":"pages.json","feed":"feed/index.json","by_address":"by-address/{{prefix}}.json","#,
                r#""support":"by-address/{{prefix}}.support.json","by_name":"by-name/{{prefix}}.json","#,
                r#""by_type":"by-type/{{prefix}}/index.json"}}}}"#
            ),
            HIDING_ENTRY,
            shown_entry_json()
        );
        pinned(&head, &json);
    }

    #[test]
    fn shards_are_pinned() {
        let shard = AddressShard {
            prefix: "a0a".into(),
            listings: vec![ShardEntry {
                entry: hiding_entry(),
                data_map: None,
            }],
        };
        pinned(
            &shard,
            &format!(
                r#"{{"prefix":"a0a","listings":[{}]}}"#,
                HIDING_ENTRY.replace('}', r#","data_map":null}"#)
            ),
        );
        let support = SupportShard {
            prefix: "a0a".into(),
            support: vec![Support {
                address: "a0".repeat(32),
                nodes: 6,
                nearest: 7,
                quorum: true,
                carried: false,
            }],
        };
        pinned(
            &support,
            &format!(
                r#"{{"prefix":"a0a","support":[{{"address":"{}","nodes":6,"nearest":7,"quorum":true,"carried":false}}]}}"#,
                "a0".repeat(32)
            ),
        );
        let names = NameShard {
            prefix: name_prefix("a.txt"),
            names: vec![NameGroup {
                name: "a.txt".into(),
                listings: vec![shown_entry()],
            }],
        };
        pinned(
            &names,
            &format!(
                r#"{{"prefix":"{}","names":[{{"name":"a.txt","listings":[{}]}}]}}"#,
                name_prefix("a.txt"),
                shown_entry_json()
            ),
        );
        // An empty shard is written too.
        pinned(
            &AddressShard {
                prefix: "000".into(),
                listings: Vec::new(),
            },
            r#"{"prefix":"000","listings":[]}"#,
        );
    }

    #[test]
    fn content_types_are_pinned() {
        let id = type_id("text/plain");
        let prefix = type_prefix("text/plain");
        let first = type_page_path("text/plain", 0);
        assert_eq!(first, format!("by-type/{prefix}/{id}-0.json"));
        let index = TypeIndex {
            prefix: prefix.clone(),
            types: vec![TypeSummary {
                content_type: "text/plain".into(),
                count: 1,
                pages: type_pages(1),
                first: first.clone(),
                last: first.clone(),
            }],
        };
        pinned(
            &index,
            &format!(
                r#"{{"prefix":"{prefix}","types":[{{"content_type":"text/plain","count":1,"pages":1,"first":"{first}","last":"{first}"}}]}}"#
            ),
        );
        let page = TypePage {
            content_type: "text/plain".into(),
            page: 0,
            prev: None,
            next: None,
            listings: vec![shown_entry()],
        };
        pinned(
            &page,
            &format!(
                r#"{{"content_type":"text/plain","page":0,"prev":null,"next":null,"listings":[{}]}}"#,
                shown_entry_json()
            ),
        );
    }

    #[test]
    fn time_pages_are_pinned() {
        let page = Page {
            listings: vec![shown_entry(), hiding_entry()],
        };
        let bytes = file_bytes(&page).unwrap();
        pinned(
            &page,
            &format!(r#"{{"listings":[{},{HIDING_ENTRY}]}}"#, shown_entry_json()),
        );
        let first = shown().key();
        let path = page_path(&first, &bytes);
        // Its first key, then the BLAKE3 hash of its bytes.
        assert_eq!(
            path,
            concat!(
                "pages/000000006ac566030000000004e25949000000000000000711111111111111",
                "11111111111111111111111111111111111111111111111111",
                "-d40d8c4970af03f36cbb63c8599efa580b278f3027232ca7b24f6f103f24c50d.json"
            )
        );
        assert_eq!(
            path,
            format!(
                "pages/{}-{}.json",
                key_hex(&first),
                blake3::hash(&bytes).to_hex()
            )
        );
        let pages = Pages {
            epoch: "8c1f0e2d3b4a5968".into(),
            seq: 12,
            count: 2,
            pages: vec![PageRef {
                path: path.clone(),
                first: key_hex(&first),
                last: key_hex(&hiding().key()),
                count: 2,
            }],
        };
        pinned(
            &pages,
            &format!(
                r#"{{"epoch":"8c1f0e2d3b4a5968","seq":12,"count":2,"pages":[{{"path":"{path}","first":"{}","last":"{}","count":2}}]}}"#,
                key_hex(&first),
                key_hex(&hiding().key())
            ),
        );
    }

    #[test]
    fn the_feed_is_pinned() {
        let segment = FeedSegment {
            epoch: "8c1f0e2d3b4a5968".into(),
            first: 1,
            records: vec![
                FeedRecord {
                    seq: 1,
                    at: 1_791_324_060,
                    change: Change::Put {
                        listing: Box::new(hiding_entry()),
                    },
                },
                FeedRecord {
                    seq: 2,
                    at: 1_791_327_660,
                    change: Change::Remove {
                        address: "a0".repeat(32),
                        reason: RemoveReason::NoLongerServed,
                    },
                },
            ],
        };
        pinned(
            &segment,
            &format!(
                concat!(
                    r#"{{"epoch":"8c1f0e2d3b4a5968","first":1,"records":["#,
                    r#"{{"seq":1,"at":1791324060,"op":"put","listing":{}}},"#,
                    r#"{{"seq":2,"at":1791327660,"op":"remove","address":"{}","reason":"no_longer_served"}}]}}"#
                ),
                HIDING_ENTRY,
                "a0".repeat(32)
            ),
        );
        let index = FeedIndex {
            epoch: "8c1f0e2d3b4a5968".into(),
            seq: 2,
            segments: vec![SegmentRef {
                path: segment_path(1),
                first: 1,
                last: 2,
            }],
        };
        pinned(
            &index,
            r#"{"epoch":"8c1f0e2d3b4a5968","seq":2,"segments":[{"path":"feed/1.json","first":1,"last":2}]}"#,
        );
        // A reason a later version adds still reads.
        let later: FeedRecord = serde_json::from_str(&format!(
            r#"{{"seq":3,"at":1,"op":"remove","address":"{}","reason":"moved"}}"#,
            "a0".repeat(32)
        ))
        .unwrap();
        assert_eq!(
            later.change,
            Change::Remove {
                address: "a0".repeat(32),
                reason: RemoveReason::Other,
            }
        );
    }

    #[test]
    fn rejected_is_pinned() {
        let listing = hiding();
        let rejected = RejectedListing {
            listing: listing.clone(),
            problem: "2 of the 7 nodes nearest its address serve it, needs 4; try again".into(),
            nodes: 2,
            nearest: 7,
            again: true,
        };
        let copies = [
            PendingCopy {
                node: PeerId::from_bytes([3; 32]),
                block_number: Some(80_204_042),
                block_timestamp: None,
                first_seen: Some(1_791_324_000),
                before_vault_deployment: true,
            },
            PendingCopy {
                node: PeerId::from_bytes([5; 32]),
                block_number: Some(81_950_000),
                block_timestamp: None,
                first_seen: Some(1_791_327_600),
                before_vault_deployment: false,
            },
        ];
        let file = Rejected {
            listings: vec![RejectedEntry::new(&rejected, &copies, 1_791_324_060)],
        };
        let fields = HIDING_ENTRY
            .strip_suffix(r#","check":"reported","decided_at":1791324060}"#)
            .unwrap();
        pinned(
            &file,
            &format!(
                concat!(
                    r#"{{"listings":[{},"problem":"2 of the 7 nodes nearest its address serve it, needs 4; try again","#,
                    r#""again":true,"nodes":2,"nearest":7,"decided_at":1791324060,"copies":["#,
                    r#"{{"node":"{}","block_number":80204042,"first_seen":1791324000,"time":1791324000,"before_vault_deployment":true}},"#,
                    r#"{{"node":"{}","block_number":81950000,"first_seen":1791327600,"time":1791327600}}]}}]}}"#
                ),
                fields,
                "03".repeat(32),
                "05".repeat(32)
            ),
        );
    }

    #[test]
    fn status_is_pinned() {
        let status = Status {
            epoch: "8c1f0e2d3b4a5968".into(),
            seq: 12,
            count: 2,
            generated_at: 1_791_324_061,
            started_at: 1_791_320_000,
            cycle: CycleStatus {
                started_at: 1_791_324_060,
                millis: 312,
                bytes_in: 210_000,
                bytes_out: 180_000,
                rpc_calls: 2,
                rpc_errors: 0,
                decided: 1,
                too_few_answered: false,
            },
            totals: Totals {
                cycles: 68,
                bytes_in: 14_000_000,
                bytes_out: 12_000_000,
                rpc: vec![RpcCalls {
                    provider: "rpc.example.org".into(),
                    calls: 40,
                    errors: 1,
                }],
            },
            census: CensusStatus {
                nodes: 20,
                answering: 19,
                leaves: 2,
                versions: vec![
                    VersionCount {
                        version: Some("node/0.23.0".into()),
                        nodes: 19,
                    },
                    VersionCount {
                        version: None,
                        nodes: 1,
                    },
                ],
                silent: vec![SilentNode {
                    node: "05".repeat(32),
                    last_answered: Some(1_791_323_000),
                }],
            },
            deferred: vec![DeferredGroup {
                reason: "below_quorum".into(),
                addresses: 2,
                oldest_since: 1_791_144_080,
            }],
            below_full: BelowFull {
                listings: 1,
                oldest_since: Some(1_791_320_000),
            },
            drops: Drops {
                removed: 0,
                carried: 0,
            },
            resources: Resources {
                rss_bytes: Some(104_857_600),
                store_bytes: Some(1_048_576),
                files_bytes: Some(524_288),
                disk_free_bytes: None,
            },
        };
        pinned(
            &status,
            &format!(
                concat!(
                    r#"{{"epoch":"8c1f0e2d3b4a5968","seq":12,"count":2,"generated_at":1791324061,"started_at":1791320000,"#,
                    r#""cycle":{{"started_at":1791324060,"millis":312,"bytes_in":210000,"bytes_out":180000,"rpc_calls":2,"rpc_errors":0,"decided":1,"too_few_answered":false}},"#,
                    r#""totals":{{"cycles":68,"bytes_in":14000000,"bytes_out":12000000,"rpc":[{{"provider":"rpc.example.org","calls":40,"errors":1}}]}},"#,
                    r#""census":{{"nodes":20,"answering":19,"leaves":2,"versions":[{{"version":"node/0.23.0","nodes":19}},{{"version":null,"nodes":1}}],"#,
                    r#""silent":[{{"node":"{}","last_answered":1791323000}}]}},"#,
                    r#""deferred":[{{"reason":"below_quorum","addresses":2,"oldest_since":1791144080}}],"#,
                    r#""below_full":{{"listings":1,"oldest_since":1791320000}},"drops":{{"removed":0,"carried":0}},"#,
                    r#""resources":{{"rss_bytes":104857600,"store_bytes":1048576,"files_bytes":524288,"disk_free_bytes":null}}}}"#
                ),
                "05".repeat(32)
            ),
        );
    }

    #[test]
    fn readers_ignore_fields_they_do_not_know() {
        let json = HIDING_ENTRY.replace('}', r#","added_later":{"x":[1,null]}}"#);
        assert_eq!(
            serde_json::from_str::<Entry>(&json).unwrap(),
            hiding_entry()
        );
        let head = concat!(
            r#"{"epoch":"01","seq":0,"count":0,"generated_at":5,"listings":[],"#,
            r#""links":{"status":"status.json","rejected":"rejected.json","pages":"pages.json","#,
            r#""feed":"feed/index.json","by_address":"by-address/{prefix}.json","#,
            r#""support":"by-address/{prefix}.support.json","by_name":"by-name/{prefix}.json","#,
            r#""by_type":"by-type/{prefix}/index.json","more":"later.json"},"next":1}"#
        );
        let head: Head = serde_json::from_str(head).unwrap();
        assert_eq!(head.generated_at, 5);
        assert_eq!(head.links, Links::default());
    }

    #[test]
    fn prefixes_name_every_shard_once() {
        let all: Vec<String> = prefixes().collect();
        assert_eq!(all.len(), SHARDS);
        assert_eq!(all.len(), 4_096);
        assert_eq!(all.first().map(String::as_str), Some("000"));
        assert_eq!(all.last().map(String::as_str), Some("fff"));
        assert!(all.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(address_prefix(&[0x3d; 32]), "3d3");
        assert_eq!(address_prefix(&[0x0a; 32]), "0a0");
        // BLAKE3 of the bytes, exactly: the empty string's hash is
        // af1349b9..., and case or spaces make another name.
        assert_eq!(name_prefix(""), "af1");
        assert_eq!(
            type_id(""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
        assert_eq!(type_prefix(""), "af1");
        assert_eq!(name_prefix("a.txt"), "0c1");
        assert_ne!(name_prefix("a.txt"), name_prefix("A.txt"));
        assert_eq!(
            type_id("text/plain"),
            "d1acb144aa06cec156c391172ed53277ec72ff75ff1a08e0dab4c84efbdadbbc"
        );
        assert_eq!(type_prefix("text/plain"), "d1a");
        assert_eq!(address_shard_path("3d3"), "by-address/3d3.json");
        assert_eq!(support_path("3d3"), "by-address/3d3.support.json");
        assert_eq!(name_shard_path("af1"), "by-name/af1.json");
        assert_eq!(type_index_path("af1"), "by-type/af1/index.json");
    }

    #[test]
    fn keys_as_text_sort_as_keys() {
        let keys = [
            ListingKey::MIN,
            ListingKey {
                time: 1,
                ..ListingKey::MIN
            },
            hiding().key(),
            shown().key(),
            ListingKey {
                time: u64::MAX,
                block_number: u64::MAX,
                log_index: u64::MAX,
                address: [0xff; 32],
            },
        ];
        let mut sorted = keys;
        sorted.sort();
        let texts: Vec<String> = sorted.iter().map(key_hex).collect();
        assert!(texts.windows(2).all(|pair| pair[0] < pair[1]));
        for (key, text) in sorted.iter().zip(&texts) {
            assert_eq!(text.len(), 112);
            assert_eq!(parse_key(text), Some(*key));
        }
        assert_eq!(
            key_hex(&shown().key()),
            format!(
                "000000006ac56603{:016x}{:016x}{}",
                81_942_857,
                7,
                "11".repeat(32)
            )
        );
        assert_eq!(parse_key("00"), None);
        assert_eq!(parse_key(&"zz".repeat(56)), None);
    }

    /// An address from `seed`.
    fn address(seed: u64) -> XorName {
        *blake3::hash(&seed.to_be_bytes()).as_bytes()
    }

    /// The first `count` addresses from `seeds` that [`ends_page`] ends a
    /// page at, or doesn't, as `ending` asks.
    fn addresses_ending(ending: bool, count: usize, seeds: Range<u64>) -> Vec<XorName> {
        seeds
            .map(address)
            .filter(|address| ends_page(address) == ending)
            .take(count)
            .collect()
    }

    #[test]
    fn a_page_ends_after_an_address_whose_hash_is_a_multiple_of_a_thousand() {
        let ends = addresses_ending(true, 3, 0..100_000);
        assert_eq!(ends.len(), 3);
        for address in &ends {
            let hash = blake3::hash(address);
            // Read as a big-endian number: its value mod 1,000, digit by
            // digit, from the hex.
            let rest = hash.to_hex().chars().fold(0u64, |rest, digit| {
                (rest * 16 + u64::from(digit.to_digit(16).unwrap())) % 1_000
            });
            assert_eq!(rest, 0);
        }
        // About one in a thousand.
        let count = (0..20_000).map(address).filter(ends_page).count();
        assert!((5..=50).contains(&count), "{count}");
    }

    #[test]
    fn time_pages_end_at_those_addresses_or_at_four_thousand() {
        let ends = addresses_ending(true, 2, 0..100_000);
        let others = addresses_ending(false, 9_000, 200_000..300_000);
        assert!(time_pages(&[]).is_empty());
        // 10 entries, then one that ends a page, then 5 more: two pages.
        let mut addresses: Vec<XorName> = others[..10].to_vec();
        addresses.push(ends[0]);
        addresses.extend_from_slice(&others[10..15]);
        assert_eq!(time_pages(&addresses), vec![0..11, 11..16]);
        // An entry that ends a page last: no empty page after it.
        assert_eq!(time_pages(&addresses[..11]), vec![0..11]);
        // A run of 9,000 that none ends: pages of 4,000, 4,000 and 1,000.
        assert_eq!(
            time_pages(&others),
            vec![0..4_000, 4_000..8_000, 8_000..9_000]
        );
    }

    #[test]
    fn an_entry_coming_or_going_changes_only_its_page() {
        let ends = addresses_ending(true, 3, 0..100_000);
        let others = addresses_ending(false, 31, 200_000..300_000);
        let mut addresses = Vec::new();
        for (index, end) in ends.iter().enumerate() {
            addresses.extend_from_slice(&others[index * 10..index * 10 + 10]);
            addresses.push(*end);
        }
        let pages = |addresses: &[XorName]| -> Vec<Vec<XorName>> {
            time_pages(addresses)
                .into_iter()
                .map(|range| addresses[range].to_vec())
                .collect()
        };
        let before = pages(&addresses);
        assert_eq!(before.len(), 3);
        // One more in the middle page: the others are the same pages.
        let mut added = addresses.clone();
        added.insert(15, others[30]);
        let after = pages(&added);
        assert_eq!(after.len(), 3);
        assert_eq!(after[0], before[0]);
        assert_eq!(after[2], before[2]);
        assert_eq!(after[1].len(), before[1].len() + 1);
        // One fewer in the first page: the others are the same pages.
        let mut removed = addresses.clone();
        removed.remove(3);
        let after = pages(&removed);
        assert_eq!(after[1..], before[1..]);
    }

    #[test]
    fn content_types_are_paged_by_256() {
        assert_eq!(type_pages(0), 0);
        assert_eq!(type_pages(1), 1);
        assert_eq!(type_pages(256), 1);
        assert_eq!(type_pages(257), 2);
        assert_eq!(type_pages(1_000_000), 3_907);
        let id = type_id("image/png");
        assert_eq!(
            type_page_path("image/png", 3),
            format!("by-type/{}/{id}-3.json", &id[..3])
        );
    }

    #[test]
    fn feed_segments_hold_a_thousand_records_each() {
        assert_eq!(segment_first(1), 1);
        assert_eq!(segment_first(1_000), 1);
        assert_eq!(segment_first(1_001), 1_001);
        assert_eq!(segment_first(2_000), 1_001);
        assert_eq!(segment_first(2_001), 2_001);
        assert_eq!(segment_path(1_001), "feed/1001.json");
    }

    #[test]
    fn epochs_are_sixteen_hex_digits_never_zero() {
        for _ in 0..100 {
            let epoch = new_epoch();
            assert_eq!(epoch.len(), 16);
            assert!(epoch
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
            assert_ne!(epoch, "0".repeat(16));
        }
    }
}
