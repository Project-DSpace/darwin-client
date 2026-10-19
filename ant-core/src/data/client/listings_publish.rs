//! Publishing the listings index as the files of `listings/v1/`, exactly as
//! `docs/listings-v1.md` specifies them (types and layout rules in
//! [`listings_v1`](super::listings_v1)).
//!
//! The [`Publisher`] keeps the published index in the producer's store, in
//! databases named [`PUBLISH`]`…`: each entry by address with its data map,
//! its place in key order, by name and by content type, each listed
//! address's support, the rejected and deferred listings, the time pages,
//! and the feed of numbered changes with its epoch. Each cycle the producer
//! hands it what changed ([`Publication`]). The publisher numbers the
//! changes in the feed and writes the files they touch:
//!
//! - each file only when its bytes change, whole (written beside it, flushed
//!   to disk, then renamed over it), with `.gz` and `.zst` copies of the
//!   same bytes;
//! - the files a change touches first, then `pages.json`,
//!   `feed/index.json`, and `head.json` last, so a file is written only
//!   after every file it names is in place;
//! - every prefix's shard files, empty or not;
//! - support files at most every [`SUPPORT_INTERVAL`];
//! - `status.json` every cycle, and `rejected.json` when it changes;
//! - time pages that `pages.json` no longer lists are deleted
//!   [`SUPERSEDED_KEPT`] later.
//!
//! There is no hide list: every listed entry is published.
//!
//! **Work follows what changed, not the size of the index.** A shard is
//! built again only when one of its entries changed, and a content type's
//! pages only from the first one a change moves. A time page ends after an
//! address [`ends_page`] ends one at, or after [`MAX_PAGE_LISTINGS`]
//! entries, so a change can move page ends only up to the next address
//! that ends a page: only the pages between the ends around a change are
//! built again, and every other page keeps its name.
//!
//! **Failures and restarts.** The store records which files a publication
//! leaves to write in the same transaction as its changes, and clears the
//! record once they are written. A publication that fails part way, or a
//! process stopped part way, leaves the record, and the next publication
//! writes them. When the publisher opens and `head.json` is missing or
//! behind what the store says was written (the directory was emptied or
//! moved), it writes every file again.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::ops::Bound;
use std::path::{Path, PathBuf};

use ant_listings::{ListingKey, LISTING_KEY_LEN};
use ant_protocol::XorName;
use heed::byteorder::BigEndian;
use heed::types::{Bytes, Str, U64};
use heed::{Database, RoTxn, RwTxn};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::listings::unix_now;
use super::listings_store::{store_error, ListingsStore};
use super::listings_v1::{
    address_shard_path, ends_page, file_bytes, key_hex, name_shard_path, new_epoch, page_path,
    parse_key, segment_first, segment_path, support_path, time_pages, type_index_path, type_pages,
    AddressShard, Change, Entry, FeedIndex, FeedRecord, FeedSegment, Head, Links, NameGroup,
    NameShard, Page, PageRef, Pages, Rejected, RejectedEntry, RemoveReason, SegmentRef, ShardEntry,
    Status, Support, SupportShard, TypeIndex, TypePage, TypeSummary, FEED_INDEX_FILE,
    FEED_SEGMENT_RECORDS, HEAD_FILE, HEAD_LISTINGS, PAGES_FILE, PREFIX_DIGITS, REJECTED_FILE,
    SHARDS, STATUS_FILE, SUPERSEDED_KEPT, SUPPORT_INTERVAL, TYPE_PAGE_LISTINGS,
};
use crate::data::error::{Error, Result};

#[cfg(doc)]
use super::{listings_store::PUBLISH, listings_v1::MAX_PAGE_LISTINGS};

/// The publisher's position in its feed: its epoch, as text, and the files
/// its latest publication left to write.
pub const META_TEXT_DB: &str = "publish_meta_text";

/// The publisher's position in its feed: its latest record's number, the
/// count of entries, and when the index and the support files were last
/// changed and written.
pub const META_NUMBERS_DB: &str = "publish_meta_numbers";

/// Each listed address's entry, with its data map, as its shard holds it.
pub const ENTRIES_DB: &str = "publish_entries";

/// Where the entries are: in key order, by name and by content type, and how
/// many entries each content type has.
pub const ORDER_DB: &str = "publish_order";

/// The time pages `pages.json` lists, and those it no longer lists, until
/// they are deleted.
pub const PAGES_DB: &str = "publish_pages";

/// Each listed address's support, and the latest rejection or deferral of
/// each address the producer didn't list.
pub const SIDE_DB: &str = "publish_side";

/// The feed's records, by number.
pub const FEED_DB: &str = "publish_feed";

/// The key of the epoch in [`META_TEXT_DB`].
const EPOCH: &str = "epoch";

/// The key in [`META_TEXT_DB`] of the files left to write.
const PENDING: &str = "pending";

/// The key of the latest record's number in [`META_NUMBERS_DB`].
const SEQ: &str = "seq";

/// The key of the number of entries in [`META_NUMBERS_DB`].
const COUNT: &str = "count";

/// The key in [`META_NUMBERS_DB`] of when the index last changed: `at` of
/// the latest record, or of the epoch's first publication before any.
const GENERATED_AT: &str = "generated_at";

/// The key in [`META_NUMBERS_DB`] of when the support files were last
/// written (absent: never).
const SUPPORT_AT: &str = "support_at";

/// The key in [`META_NUMBERS_DB`] of the latest record the written files
/// hold.
const FEED_WRITTEN: &str = "feed_written";

/// [`ORDER_DB`]: a key, in key order (no value).
const KEY_TAG: u8 = b'k';
/// [`ORDER_DB`]: a name's shard (2 bytes) and an address (no value).
const NAME_TAG: u8 = b'n';
/// [`ORDER_DB`]: a content type's id and a key (no value).
const TYPE_TAG: u8 = b't';
/// [`ORDER_DB`]: a content type's id, to the type and its count.
const TYPE_COUNT_TAG: u8 = b'c';
/// [`PAGES_DB`]: a time page's first key, to its path, last key and count.
const PAGE_TAG: u8 = b'p';
/// [`PAGES_DB`]: when a time page left `pages.json` and its path (no value).
const SUPERSEDED_TAG: u8 = b'x';
/// [`SIDE_DB`]: an address, to its support.
const SUPPORT_TAG: u8 = b's';
/// [`SIDE_DB`]: an address, to its latest rejection or deferral.
const REJECTED_TAG: u8 = b'r';

/// A file being written is first written under a name like this one, in the
/// directory of the file it replaces, and then renamed over it.
const TEMP_PREFIX: &str = ".publish-";
/// The end of such a name.
const TEMP_SUFFIX: &str = ".tmp";

/// A listing's key as bytes, in key order ([`ListingKey::to_bytes`]).
type Key = [u8; LISTING_KEY_LEN];

// Shard numbers are three hex digits: 12 bits.
const _: () = assert!(PREFIX_DIGITS == 3 && SHARDS == 1 << 12);

/// What one cycle changed, for the [`Publisher`] to publish.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Publication {
    /// When the cycle (or the push it handled) began, in Unix seconds: the
    /// `at` of the feed records it makes.
    pub at: u64,
    /// Changes to the index, in the order they were decided; each becomes
    /// one record of the feed, numbered in this order. A put of the entry
    /// an address already has changes nothing and makes no record.
    pub changes: Vec<IndexChange>,
    /// The support of listed addresses that changed, one per address,
    /// applied after `changes`: support for an address that isn't listed
    /// then is left out. An address removed from the index loses its
    /// support with it.
    pub support: Vec<Support>,
    /// Changes to `rejected.json`: each address's latest rejection or
    /// deferral, or none once it is listed or no longer served.
    pub rejected: Vec<RejectedChange>,
    /// How the producer is doing, for `status.json`, which every
    /// publication writes: a publication between cycles passes the latest
    /// cycle's. The publisher fills in `epoch`, `seq`, `count` and
    /// `generated_at`, and `resources.files_bytes` where it is `None`; the
    /// rest is written as given.
    pub status: Status,
}

/// A change to the index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexChange {
    /// The address's entry is now this one, with its data map: new to the
    /// index, or replacing the address's entry. Its feed record leaves the
    /// data map out.
    Put(Box<ShardEntry>),
    /// The address has no entry any more. A removal of an address without
    /// one changes nothing and makes no record.
    Remove {
        /// The file's address.
        address: XorName,
        /// Why.
        reason: RemoveReason,
    },
}

impl IndexChange {
    /// The address the change is for, if its entry's `address` is one.
    #[must_use]
    pub fn address(&self) -> Option<XorName> {
        match self {
            Self::Put(entry) => entry.entry.listing.address(),
            Self::Remove { address, .. } => Some(*address),
        }
    }

    /// The key of the entry a put adds, if its fields give one.
    #[must_use]
    pub fn key(&self) -> Option<ListingKey> {
        match self {
            Self::Put(entry) => entry.entry.key(),
            Self::Remove { .. } => None,
        }
    }
}

/// A change to `rejected.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectedChange {
    /// The address's latest rejection or deferral is this one.
    Set(Box<RejectedEntry>),
    /// The address has none any more.
    Clear(XorName),
}

/// What a [`Publisher::publish`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Published {
    /// The feed's epoch.
    pub epoch: String,
    /// The number of its latest record.
    pub seq: u64,
    /// How many entries the index holds.
    pub count: u64,
    /// Files written (each with its compressed copies counting once).
    pub files_written: u64,
    /// The bytes of those files, uncompressed.
    pub bytes_written: u64,
}

/// Publishes the index's files in a directory. See the module docs.
#[derive(Debug)]
pub struct Publisher {
    store: ListingsStore,
    dbs: Dbs,
    files: Files,
    epoch: String,
    seq: u64,
    count: u64,
    generated_at: Option<u64>,
    support_at: Option<u64>,
    feed_written: u64,
    /// Unix seconds now: `status.json`'s `generated_at`.
    clock: fn() -> u64,
}

impl Publisher {
    /// The publisher of the files in `out_dir` (the `listings/v1/`
    /// directory itself), keeping the published index in `store`. The
    /// first time, it starts a feed under a new epoch ([`new_epoch`]), with
    /// no records and no entries, and its first publication writes every
    /// file. Leftovers of an interrupted write are removed.
    ///
    /// # Errors
    ///
    /// If `out_dir` can't be created or read, or the store can't be read or
    /// written.
    pub fn open(out_dir: &Path, store: &ListingsStore) -> Result<Self> {
        let files = Files::open(out_dir)?;
        let dbs = Dbs::open(store)?;
        let mut txn = store.env().write_txn().map_err(store_error)?;
        let (epoch, fresh) = match dbs.meta_text.get(&txn, EPOCH).map_err(store_error)? {
            Some(epoch) => (epoch.to_string(), false),
            None => {
                let epoch = new_epoch();
                dbs.meta_text
                    .put(&mut txn, EPOCH, &epoch)
                    .map_err(store_error)?;
                (epoch, true)
            }
        };
        let number = |key: &str| dbs.meta_numbers.get(&txn, key).map_err(store_error);
        let seq = number(SEQ)?.unwrap_or(0);
        let count = number(COUNT)?.unwrap_or(0);
        let generated_at = number(GENERATED_AT)?;
        let mut support_at = number(SUPPORT_AT)?;
        let mut feed_written = number(FEED_WRITTEN)?.unwrap_or(0);
        if fresh || !files.holds(&epoch, feed_written, seq) {
            // Every file is written again, as on the first publication.
            let mut pending = dbs.pending(&txn)?;
            dbs.pend_everything(&txn, &mut pending)?;
            dbs.save_pending(&mut txn, &pending)?;
            feed_written = 0;
            dbs.meta_numbers
                .put(&mut txn, FEED_WRITTEN, &feed_written)
                .map_err(store_error)?;
            support_at = None;
            dbs.meta_numbers
                .delete(&mut txn, SUPPORT_AT)
                .map_err(store_error)?;
            if fresh {
                // Time pages of an earlier feed in the directory go as any
                // page `pages.json` no longer lists does.
                for path in files.stray_pages()? {
                    dbs.pages
                        .put(&mut txn, &superseded_row(unix_now(), &path), &[])
                        .map_err(store_error)?;
                }
            }
        }
        txn.commit().map_err(store_error)?;
        Ok(Self {
            store: store.clone(),
            dbs,
            files,
            epoch,
            seq,
            count,
            generated_at,
            support_at,
            feed_written,
            clock: unix_now,
        })
    }

    /// Publish `publication`: number its changes in the feed after the
    /// latest record, apply them to the published index, and write every
    /// file they change, as the module docs say. The store is updated in the
    /// same transaction as the feed, so a restart neither loses nor repeats
    /// a record; a file left unwritten by a failure is written by the next
    /// publication.
    ///
    /// # Errors
    ///
    /// If an entry's, a support's or a rejection's `address` isn't an
    /// address as 64 lowercase hex digits (the publication then changes
    /// nothing), or the store or a file can't be written.
    pub fn publish(&mut self, publication: &Publication) -> Result<Published> {
        let pending = self.record(publication)?;
        self.write(publication.at, &publication.status, pending)
    }

    /// Apply `publication` to the published index in one transaction, with
    /// the files it leaves to write, which this returns.
    fn record(&mut self, publication: &Publication) -> Result<Pending> {
        let at = publication.at;
        let dbs = self.dbs;
        let mut txn = self.store.env().write_txn().map_err(store_error)?;
        let mut pending = dbs.pending(&txn)?;
        let mut applied = Applied {
            seq: self.seq,
            count: self.count,
            moved: Vec::new(),
        };
        for change in &publication.changes {
            dbs.apply(&mut txn, change, at, &mut applied, &mut pending)?;
        }
        for support in &publication.support {
            dbs.set_support(&mut txn, support, &mut pending)?;
        }
        for change in &publication.rejected {
            dbs.set_rejected(&mut txn, change, &mut pending)?;
        }
        dbs.repage(&mut txn, applied.moved, at, &mut pending)?;
        let generated_at = if applied.seq > self.seq {
            at
        } else {
            self.generated_at.unwrap_or(at)
        };
        dbs.meta_numbers
            .put(&mut txn, SEQ, &applied.seq)
            .map_err(store_error)?;
        dbs.meta_numbers
            .put(&mut txn, COUNT, &applied.count)
            .map_err(store_error)?;
        dbs.meta_numbers
            .put(&mut txn, GENERATED_AT, &generated_at)
            .map_err(store_error)?;
        dbs.save_pending(&mut txn, &pending)?;
        txn.commit().map_err(store_error)?;
        self.seq = applied.seq;
        self.count = applied.count;
        self.generated_at = Some(generated_at);
        Ok(pending)
    }

    /// The published entry for `address`, with its data map, if it is
    /// listed.
    ///
    /// # Errors
    ///
    /// If the store can't be read.
    pub fn entry(&self, address: &XorName) -> Result<Option<ShardEntry>> {
        let txn = self.store.env().read_txn().map_err(store_error)?;
        self.dbs.entry(&txn, address)
    }

    /// The support last given for `address`, if it is listed and has some.
    /// Support files may not show it yet ([`SUPPORT_INTERVAL`]).
    ///
    /// # Errors
    ///
    /// If the store can't be read.
    pub fn support(&self, address: &XorName) -> Result<Option<Support>> {
        let txn = self.store.env().read_txn().map_err(store_error)?;
        self.dbs
            .side
            .get(&txn, &tagged(SUPPORT_TAG, address))
            .map_err(store_error)?
            .map(parse)
            .transpose()
    }

    /// The directory the files are published in.
    #[must_use]
    pub fn out_dir(&self) -> &Path {
        &self.files.dir
    }

    /// The feed's epoch: 16 hex digits ([`Head::epoch`]).
    #[must_use]
    pub fn epoch(&self) -> &str {
        &self.epoch
    }

    /// The number of the feed's latest record, 0 if it has none.
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// How many entries the published index holds.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count
    }

    /// What the published files take on disk, in bytes, compressed copies
    /// included: `status.json`'s `resources.files_bytes`.
    #[must_use]
    pub fn files_bytes(&self) -> u64 {
        self.files.bytes
    }

    /// Write the files `pending` names, in the order the module docs give,
    /// and `status.json`; then clear what was written from the store.
    fn write(&mut self, at: u64, status: &Status, pending: Pending) -> Result<Published> {
        let dbs = self.dbs;
        self.files.written = 0;
        self.files.written_bytes = 0;
        let support_written = !pending.support.is_empty()
            && self
                .support_at
                .is_none_or(|last| at.saturating_sub(last) >= SUPPORT_INTERVAL.as_secs());
        let txn = self.store.env().read_txn().map_err(store_error)?;
        for &shard in &pending.address {
            let bytes = dbs.address_shard(&txn, shard)?;
            self.files
                .put(&address_shard_path(&shard_text(shard)), &bytes)?;
        }
        if support_written {
            for &shard in &pending.support {
                let bytes = dbs.support_shard(&txn, shard)?;
                self.files.put(&support_path(&shard_text(shard)), &bytes)?;
            }
        }
        for &shard in &pending.names {
            let bytes = dbs.name_shard(&txn, shard)?;
            self.files
                .put(&name_shard_path(&shard_text(shard)), &bytes)?;
        }
        let mut stale = Vec::new();
        for (id, todo) in &pending.types {
            dbs.write_type_pages(&txn, &mut self.files, id, todo, &mut stale)?;
        }
        for &shard in &pending.type_indexes {
            let bytes = dbs.type_index(&txn, shard)?;
            self.files
                .put(&type_index_path(&shard_text(shard)), &bytes)?;
        }
        for path in &stale {
            self.files.remove(path)?;
        }
        let mut fixes = Vec::new();
        for first in &pending.pages {
            dbs.write_page(&txn, &mut self.files, first, &mut fixes)?;
        }
        if self.seq > self.feed_written {
            let mut first = segment_first(self.feed_written + 1);
            while first <= self.seq {
                let bytes = dbs.segment(&txn, &self.epoch, first, self.seq)?;
                self.files.put(&segment_path(first), &bytes)?;
                first += FEED_SEGMENT_RECORDS;
            }
        }
        if pending.rejected {
            let bytes = dbs.rejected(&txn)?;
            self.files.put(REJECTED_FILE, &bytes)?;
        }
        drop(txn);
        if !fixes.is_empty() {
            dbs.fix_pages(self.store.env(), at, &fixes)?;
        }
        let mut status = status.clone();
        status.epoch.clone_from(&self.epoch);
        status.seq = self.seq;
        status.count = self.count;
        status.generated_at = (self.clock)();
        if status.resources.files_bytes.is_none() {
            status.resources.files_bytes = Some(self.files.bytes);
        }
        self.files.put(STATUS_FILE, &json(&status)?)?;
        let txn = self.store.env().read_txn().map_err(store_error)?;
        if pending.lists || !fixes.is_empty() {
            let bytes = dbs.pages_file(&txn, &self.epoch, self.seq, self.count)?;
            self.files.put(PAGES_FILE, &bytes)?;
        }
        if pending.lists {
            self.files
                .put(FEED_INDEX_FILE, &json(&feed_index(&self.epoch, self.seq))?)?;
            let generated_at = self.generated_at.unwrap_or(at);
            let bytes = dbs.head(&txn, &self.epoch, self.seq, self.count, generated_at)?;
            self.files.put(HEAD_FILE, &bytes)?;
        }
        let expired = dbs.expired_pages(&txn, at)?;
        drop(txn);
        for page in &expired {
            if !page.listed {
                self.files.remove(&page.path)?;
            }
        }
        let mut txn = self.store.env().write_txn().map_err(store_error)?;
        let left = Pending {
            support: if support_written {
                BTreeSet::new()
            } else {
                pending.support
            },
            ..Pending::default()
        };
        dbs.save_pending(&mut txn, &left)?;
        dbs.meta_numbers
            .put(&mut txn, FEED_WRITTEN, &self.seq)
            .map_err(store_error)?;
        if support_written {
            dbs.meta_numbers
                .put(&mut txn, SUPPORT_AT, &at)
                .map_err(store_error)?;
        }
        for page in &expired {
            dbs.pages.delete(&mut txn, &page.row).map_err(store_error)?;
        }
        txn.commit().map_err(store_error)?;
        self.feed_written = self.seq;
        if support_written {
            self.support_at = Some(at);
        }
        Ok(Published {
            epoch: self.epoch.clone(),
            seq: self.seq,
            count: self.count,
            files_written: self.files.written,
            bytes_written: self.files.written_bytes,
        })
    }

    /// Whether to flush each file to disk before renaming it into place, as
    /// a publisher always does: tests, which write many files, may not.
    #[cfg(test)]
    fn set_flush(&mut self, flush: bool) {
        self.files.durable = flush;
    }

    /// Take `status.json`'s `generated_at` from `clock`.
    #[cfg(test)]
    fn set_clock(&mut self, clock: fn() -> u64) {
        self.clock = clock;
    }
}

/// What applying a publication's changes has done so far.
struct Applied {
    /// The latest record's number.
    seq: u64,
    /// How many entries the index holds.
    count: u64,
    /// The keys whose entries came, went or changed: their time pages are
    /// built again.
    moved: Vec<Key>,
}

/// Files a publication leaves to write: recorded in the transaction that
/// changes the index, cleared once they are written.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
struct Pending {
    /// Address shards (`by-address/<prefix>.json`).
    address: BTreeSet<u16>,
    /// Support files, written at most every [`SUPPORT_INTERVAL`].
    support: BTreeSet<u16>,
    /// Name shards.
    names: BTreeSet<u16>,
    /// Content type indexes (`by-type/<prefix>/index.json`).
    type_indexes: BTreeSet<u16>,
    /// The pages of content types, by type id.
    types: BTreeMap<String, TypeTodo>,
    /// Time pages, by first key as text.
    pages: BTreeSet<String>,
    /// `rejected.json`.
    rejected: bool,
    /// `pages.json`, `feed/index.json` and `head.json`.
    lists: bool,
}

/// A content type's pages to write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TypeTodo {
    /// The smallest key among its entries that came, went or changed, as
    /// text: pages from the one holding it on are written.
    from: String,
    /// The most pages it may have on disk: those past its last are deleted.
    pages: u64,
}

/// A content type and how many entries have it ([`TYPE_COUNT_TAG`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TypeCount {
    content_type: String,
    count: u64,
}

/// A time page `pages.json` lists ([`PAGE_TAG`]): the row's key holds its
/// first entry's key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PageRow {
    path: String,
    /// Its last entry's key, as text.
    last: String,
    count: u64,
}

/// A time page whose bytes don't match the name its row gives: written under
/// its true name, and its row corrected.
struct PageFix {
    first: Key,
    row: PageRow,
    old_path: String,
}

/// A time page `pages.json` stopped listing at least [`SUPERSEDED_KEPT`]
/// ago.
struct Expired {
    /// Its row in [`PAGES_DB`].
    row: Vec<u8>,
    path: String,
    /// Whether `pages.json` lists it again, so it stays.
    listed: bool,
}

/// The publisher's databases.
#[derive(Debug, Clone, Copy)]
struct Dbs {
    meta_text: Database<Str, Str>,
    meta_numbers: Database<Str, U64<BigEndian>>,
    entries: Database<Bytes, Bytes>,
    order: Database<Bytes, Bytes>,
    pages: Database<Bytes, Bytes>,
    side: Database<Bytes, Bytes>,
    feed: Database<U64<BigEndian>, Bytes>,
}

impl Dbs {
    fn open(store: &ListingsStore) -> Result<Self> {
        Ok(Self {
            meta_text: store.database(META_TEXT_DB)?,
            meta_numbers: store.database(META_NUMBERS_DB)?,
            entries: store.database(ENTRIES_DB)?,
            order: store.database(ORDER_DB)?,
            pages: store.database(PAGES_DB)?,
            side: store.database(SIDE_DB)?,
            feed: store.database(FEED_DB)?,
        })
    }

    fn pending(&self, txn: &RoTxn) -> Result<Pending> {
        match self.meta_text.get(txn, PENDING).map_err(store_error)? {
            Some(text) => parse(text.as_bytes()),
            None => Ok(Pending::default()),
        }
    }

    fn save_pending(&self, txn: &mut RwTxn, pending: &Pending) -> Result<()> {
        let text = serde_json::to_string(pending).map_err(json_error)?;
        self.meta_text.put(txn, PENDING, &text).map_err(store_error)
    }

    /// Mark every file to be written: on a feed's first publication, and
    /// whenever the directory doesn't hold what the store says it does.
    fn pend_everything(&self, txn: &RoTxn, pending: &mut Pending) -> Result<()> {
        let all: BTreeSet<u16> = (0..SHARDS).filter_map(|s| u16::try_from(s).ok()).collect();
        pending.address.clone_from(&all);
        pending.support.clone_from(&all);
        pending.names.clone_from(&all);
        pending.type_indexes = all;
        let from = key_hex(&ListingKey::MIN);
        for row in self
            .order
            .prefix_iter(txn, &[TYPE_COUNT_TAG])
            .map_err(store_error)?
        {
            let (key, value) = row.map_err(store_error)?;
            let count: TypeCount = parse(value)?;
            let todo = pending
                .types
                .entry(hex::encode(&key[1..]))
                .or_insert_with(|| TypeTodo {
                    from: from.clone(),
                    pages: 0,
                });
            todo.from.clone_from(&from);
            todo.pages = todo.pages.max(type_pages(count.count));
        }
        for row in self
            .pages
            .prefix_iter(txn, &[PAGE_TAG])
            .map_err(store_error)?
        {
            let (key, _) = row.map_err(store_error)?;
            pending.pages.insert(hex::encode(&key[1..]));
        }
        pending.rejected = true;
        pending.lists = true;
        Ok(())
    }

    fn entry(&self, txn: &RoTxn, address: &[u8]) -> Result<Option<ShardEntry>> {
        self.entries
            .get(txn, address)
            .map_err(store_error)?
            .map(parse)
            .transpose()
    }

    /// The entry at `address`, which the index must hold.
    fn listed(&self, txn: &RoTxn, address: &[u8]) -> Result<Entry> {
        self.entry(txn, address)?
            .map(|entry| entry.entry)
            .ok_or_else(|| {
                Error::Storage(format!(
                    "listings store: no published entry for {}, which the index names",
                    hex::encode(address)
                ))
            })
    }

    fn apply(
        &self,
        txn: &mut RwTxn,
        change: &IndexChange,
        at: u64,
        applied: &mut Applied,
        pending: &mut Pending,
    ) -> Result<()> {
        let (address, change) = match change {
            IndexChange::Put(entry) => {
                let address = address_of(&entry.entry.listing.address)?;
                let old = self.entry(txn, &address)?;
                if old.as_ref() == Some(&**entry) {
                    return Ok(());
                }
                match &old {
                    Some(old) => self.unindex(txn, &address, &old.entry, applied, pending)?,
                    None => applied.count += 1,
                }
                self.entries
                    .put(txn, &address, &json(entry)?)
                    .map_err(store_error)?;
                self.index(txn, &address, &entry.entry, applied, pending)?;
                let listing = Box::new(entry.entry.clone());
                (address, Change::Put { listing })
            }
            IndexChange::Remove { address, reason } => {
                let Some(old) = self.entry(txn, address)? else {
                    return Ok(());
                };
                self.unindex(txn, address, &old.entry, applied, pending)?;
                self.entries.delete(txn, address).map_err(store_error)?;
                if self
                    .side
                    .delete(txn, &tagged(SUPPORT_TAG, address))
                    .map_err(store_error)?
                {
                    pending.support.insert(shard_of(address));
                }
                applied.count = applied.count.saturating_sub(1);
                let change = Change::Remove {
                    address: hex::encode(address),
                    reason: *reason,
                };
                (*address, change)
            }
        };
        applied.seq += 1;
        let record = FeedRecord {
            seq: applied.seq,
            at,
            change,
        };
        self.feed
            .put(txn, &applied.seq, &json(&record)?)
            .map_err(store_error)?;
        pending.address.insert(shard_of(&address));
        pending.lists = true;
        Ok(())
    }

    /// Place `entry`, the entry at `address`, in key order, by name and by
    /// content type.
    fn index(
        &self,
        txn: &mut RwTxn,
        address: &XorName,
        entry: &Entry,
        applied: &mut Applied,
        pending: &mut Pending,
    ) -> Result<()> {
        let key = key_of_entry(entry)?;
        self.order
            .put(txn, &tagged(KEY_TAG, &key), &[])
            .map_err(store_error)?;
        applied.moved.push(key);
        if let Some(name) = &entry.listing.name {
            let shard = shard_of(blake3::hash(name.as_bytes()).as_bytes());
            self.order
                .put(txn, &name_row(shard, address), &[])
                .map_err(store_error)?;
            pending.names.insert(shard);
        }
        if let Some(content_type) = &entry.listing.content_type {
            self.count_type(txn, content_type, &key, true, pending)?;
        }
        Ok(())
    }

    /// Take `entry`, the entry at `address`, out of key order, its name and
    /// its content type.
    fn unindex(
        &self,
        txn: &mut RwTxn,
        address: &XorName,
        entry: &Entry,
        applied: &mut Applied,
        pending: &mut Pending,
    ) -> Result<()> {
        let key = key_of_entry(entry)?;
        self.order
            .delete(txn, &tagged(KEY_TAG, &key))
            .map_err(store_error)?;
        applied.moved.push(key);
        if let Some(name) = &entry.listing.name {
            let shard = shard_of(blake3::hash(name.as_bytes()).as_bytes());
            self.order
                .delete(txn, &name_row(shard, address))
                .map_err(store_error)?;
            pending.names.insert(shard);
        }
        if let Some(content_type) = &entry.listing.content_type {
            self.count_type(txn, content_type, &key, false, pending)?;
        }
        Ok(())
    }

    /// Add the entry with `key` to `content_type`'s, or take it out.
    fn count_type(
        &self,
        txn: &mut RwTxn,
        content_type: &str,
        key: &Key,
        add: bool,
        pending: &mut Pending,
    ) -> Result<()> {
        let id = *blake3::hash(content_type.as_bytes()).as_bytes();
        let count_row = tagged(TYPE_COUNT_TAG, &id);
        let before = match self.order.get(txn, &count_row).map_err(store_error)? {
            Some(value) => parse::<TypeCount>(value)?.count,
            None => 0,
        };
        let after = if add {
            before + 1
        } else {
            before.saturating_sub(1)
        };
        if after == 0 {
            self.order.delete(txn, &count_row).map_err(store_error)?;
        } else {
            let count = TypeCount {
                content_type: content_type.to_string(),
                count: after,
            };
            self.order
                .put(txn, &count_row, &json(&count)?)
                .map_err(store_error)?;
        }
        let member = [&[TYPE_TAG][..], &id[..], &key[..]].concat();
        if add {
            self.order.put(txn, &member, &[]).map_err(store_error)?;
        } else {
            self.order.delete(txn, &member).map_err(store_error)?;
        }
        let key = hex::encode(key);
        let todo = pending
            .types
            .entry(hex::encode(id))
            .or_insert_with(|| TypeTodo {
                from: key.clone(),
                pages: 0,
            });
        if key < todo.from {
            todo.from = key;
        }
        todo.pages = todo.pages.max(type_pages(before));
        pending.type_indexes.insert(shard_of(&id));
        Ok(())
    }

    fn set_support(&self, txn: &mut RwTxn, support: &Support, pending: &mut Pending) -> Result<()> {
        let address = address_of(&support.address)?;
        if self
            .entries
            .get(txn, &address)
            .map_err(store_error)?
            .is_none()
        {
            return Ok(());
        }
        let row = tagged(SUPPORT_TAG, &address);
        let bytes = json(support)?;
        if self.side.get(txn, &row).map_err(store_error)? == Some(&bytes[..]) {
            return Ok(());
        }
        self.side.put(txn, &row, &bytes).map_err(store_error)?;
        pending.support.insert(shard_of(&address));
        Ok(())
    }

    fn set_rejected(
        &self,
        txn: &mut RwTxn,
        change: &RejectedChange,
        pending: &mut Pending,
    ) -> Result<()> {
        match change {
            RejectedChange::Set(entry) => {
                let address = address_of(&entry.listing.address)?;
                let row = tagged(REJECTED_TAG, &address);
                let bytes = json(entry)?;
                if self.side.get(txn, &row).map_err(store_error)? != Some(&bytes[..]) {
                    self.side.put(txn, &row, &bytes).map_err(store_error)?;
                    pending.rejected = true;
                }
            }
            RejectedChange::Clear(address) => {
                if self
                    .side
                    .delete(txn, &tagged(REJECTED_TAG, address))
                    .map_err(store_error)?
                {
                    pending.rejected = true;
                }
            }
        }
        Ok(())
    }

    /// Build again the time pages around `moved`, the keys whose entries
    /// came, went or changed, and mark those whose bytes changed to be
    /// written.
    ///
    /// Each key's stretch runs from the page end before it (the last
    /// address before it that [`ends_page`] ends a page at) to the one after
    /// it, both excluded from what moved: only the pages in it can change,
    /// as the [`MAX_PAGE_LISTINGS`] pages counted from a page end hold the
    /// same entries until the next one. Stretches that overlap, or meet at
    /// a key that moved, are joined, so each stretch found starts and ends
    /// at a page end that both the old pages and the new ones have.
    fn repage(
        &self,
        txn: &mut RwTxn,
        mut moved: Vec<Key>,
        at: u64,
        pending: &mut Pending,
    ) -> Result<()> {
        moved.sort_unstable();
        moved.dedup();
        let mut stretches: Vec<(Option<Key>, Option<Key>)> = Vec::new();
        for key in &moved {
            if let Some((_, end)) = stretches.last() {
                match end {
                    None => continue,
                    Some(last) if key < last => continue,
                    Some(last) if key == last => {
                        let next = self.page_end_after(txn, key)?;
                        if let Some((_, end)) = stretches.last_mut() {
                            *end = next;
                        }
                        continue;
                    }
                    Some(_) => {}
                }
            }
            let start = self.page_end_before(txn, key)?;
            let end = self.page_end_after(txn, key)?;
            stretches.push((start, end));
        }
        for (after, through) in stretches {
            self.repage_stretch(txn, after.as_ref(), through.as_ref(), at, pending)?;
        }
        Ok(())
    }

    /// The last key before `key` whose address ends a page.
    fn page_end_before(&self, txn: &RoTxn, key: &Key) -> Result<Option<Key>> {
        let start = [KEY_TAG];
        let end = tagged(KEY_TAG, key);
        let range = (Bound::Included(&start[..]), Bound::Excluded(&end[..]));
        for row in self.order.rev_range(txn, &range).map_err(store_error)? {
            let (row, _) = row.map_err(store_error)?;
            let key = row_key(&row[1..])?;
            if ends_page(&key_address(&key)) {
                return Ok(Some(key));
            }
        }
        Ok(None)
    }

    /// The first key after `key` whose address ends a page.
    fn page_end_after(&self, txn: &RoTxn, key: &Key) -> Result<Option<Key>> {
        let start = tagged(KEY_TAG, key);
        let end = [KEY_TAG + 1];
        let range = (Bound::Excluded(&start[..]), Bound::Excluded(&end[..]));
        for row in self.order.range(txn, &range).map_err(store_error)? {
            let (row, _) = row.map_err(store_error)?;
            let key = row_key(&row[1..])?;
            if ends_page(&key_address(&key)) {
                return Ok(Some(key));
            }
        }
        Ok(None)
    }

    /// Build again the time pages of the entries after `after` up to and
    /// including `through` (from the first, or to the last, when `None`).
    fn repage_stretch(
        &self,
        txn: &mut RwTxn,
        after: Option<&Key>,
        through: Option<&Key>,
        at: u64,
        pending: &mut Pending,
    ) -> Result<()> {
        let (start, end) = stretch_bounds(KEY_TAG, after, through);
        let range = (bound_slice(&start), bound_slice(&end));
        let keys = self
            .order
            .range(txn, &range)
            .map_err(store_error)?
            .map(|row| row_key(&row.map_err(store_error)?.0[1..]))
            .collect::<Result<Vec<Key>>>()?;
        let addresses: Vec<XorName> = keys.iter().map(key_address).collect();
        let mut rows = Vec::new();
        for page in time_pages(&addresses) {
            let page_keys = &keys[page];
            let (Some(first), Some(last)) = (page_keys.first(), page_keys.last()) else {
                continue;
            };
            let bytes = self.page_bytes(txn, page_keys)?;
            let row = PageRow {
                path: page_path(&listing_key(first)?, &bytes),
                last: hex::encode(last),
                count: page_keys.len() as u64,
            };
            rows.push((*first, row));
        }
        let (start, end) = stretch_bounds(PAGE_TAG, after, through);
        let range = (bound_slice(&start), bound_slice(&end));
        let old = self
            .pages
            .range(txn, &range)
            .map_err(store_error)?
            .map(|row| {
                let (key, value) = row.map_err(store_error)?;
                Ok((key.to_vec(), parse::<PageRow>(value)?))
            })
            .collect::<Result<Vec<(Vec<u8>, PageRow)>>>()?;
        let new_paths: HashSet<&str> = rows.iter().map(|(_, row)| row.path.as_str()).collect();
        let old_paths: HashSet<&str> = old.iter().map(|(_, row)| row.path.as_str()).collect();
        for (key, row) in &old {
            self.pages.delete(txn, key).map_err(store_error)?;
            if !new_paths.contains(row.path.as_str()) {
                self.pages
                    .put(txn, &superseded_row(at, &row.path), &[])
                    .map_err(store_error)?;
            }
        }
        for (first, row) in &rows {
            self.pages
                .put(txn, &tagged(PAGE_TAG, first), &json(row)?)
                .map_err(store_error)?;
            if !old_paths.contains(row.path.as_str()) {
                pending.pages.insert(hex::encode(first));
            }
        }
        Ok(())
    }

    /// The bytes of the time page holding the entries at `keys`.
    fn page_bytes(&self, txn: &RoTxn, keys: &[Key]) -> Result<Vec<u8>> {
        let listings = keys
            .iter()
            .map(|key| self.listed(txn, &key_address(key)))
            .collect::<Result<Vec<Entry>>>()?;
        json(&Page { listings })
    }

    fn address_shard(&self, txn: &RoTxn, shard: u16) -> Result<Vec<u8>> {
        let (start, end) = shard_bounds(None, shard);
        let range = (bound_slice(&start), bound_slice(&end));
        let listings = self
            .entries
            .range(txn, &range)
            .map_err(store_error)?
            .map(|row| parse(row.map_err(store_error)?.1))
            .collect::<Result<Vec<ShardEntry>>>()?;
        json(&AddressShard {
            prefix: shard_text(shard),
            listings,
        })
    }

    fn support_shard(&self, txn: &RoTxn, shard: u16) -> Result<Vec<u8>> {
        let (start, end) = shard_bounds(Some(SUPPORT_TAG), shard);
        let range = (bound_slice(&start), bound_slice(&end));
        let support = self
            .side
            .range(txn, &range)
            .map_err(store_error)?
            .map(|row| parse(row.map_err(store_error)?.1))
            .collect::<Result<Vec<Support>>>()?;
        json(&SupportShard {
            prefix: shard_text(shard),
            support,
        })
    }

    fn name_shard(&self, txn: &RoTxn, shard: u16) -> Result<Vec<u8>> {
        let prefix = name_row(shard, &[]);
        let mut groups: BTreeMap<String, Vec<Entry>> = BTreeMap::new();
        for row in self.order.prefix_iter(txn, &prefix).map_err(store_error)? {
            let (row, _) = row.map_err(store_error)?;
            let entry = self.listed(txn, &row[prefix.len()..])?;
            if let Some(name) = entry.listing.name.clone() {
                groups.entry(name).or_default().push(entry);
            }
        }
        let names = groups
            .into_iter()
            .map(|(name, mut listings)| {
                listings.sort_by_key(|entry| std::cmp::Reverse(entry.key()));
                NameGroup { name, listings }
            })
            .collect();
        json(&NameShard {
            prefix: shard_text(shard),
            names,
        })
    }

    fn type_index(&self, txn: &RoTxn, shard: u16) -> Result<Vec<u8>> {
        let (start, end) = shard_bounds(Some(TYPE_COUNT_TAG), shard);
        let range = (bound_slice(&start), bound_slice(&end));
        let mut types = Vec::new();
        for row in self.order.range(txn, &range).map_err(store_error)? {
            let (key, value) = row.map_err(store_error)?;
            let count: TypeCount = parse(value)?;
            let id = hex::encode(&key[1..]);
            let pages = type_pages(count.count);
            types.push(TypeSummary {
                content_type: count.content_type,
                count: count.count,
                pages,
                first: type_page_at(&id, 0),
                last: type_page_at(&id, pages.saturating_sub(1)),
            });
        }
        types.sort_by(|a, b| a.content_type.cmp(&b.content_type));
        json(&TypeIndex {
            prefix: shard_text(shard),
            types,
        })
    }

    /// Write the pages of the content type `id` from the one holding
    /// `todo.from` on, and note those past its last to delete.
    fn write_type_pages(
        &self,
        txn: &RoTxn,
        files: &mut Files,
        id: &str,
        todo: &TypeTodo,
        stale: &mut Vec<String>,
    ) -> Result<()> {
        let id_bytes = hex32(id)?;
        let from = parse_key(&todo.from)
            .map(|key| key.to_bytes())
            .ok_or_else(|| Error::Storage(format!("listings store: bad key {}", todo.from)))?;
        let (content_type, count) = match self
            .order
            .get(txn, &tagged(TYPE_COUNT_TAG, &id_bytes))
            .map_err(store_error)?
        {
            Some(value) => {
                let count: TypeCount = parse(value)?;
                (count.content_type, count.count)
            }
            None => (String::new(), 0),
        };
        let pages = type_pages(count);
        stale.extend((pages..todo.pages).map(|page| type_page_at(id, page)));
        if count == 0 {
            return Ok(());
        }
        // Its keys from the last back: first those from `from` on, which
        // give the page `from` is in, then back to that page's start (or to
        // the old last page's, whose link to the next changes when the
        // number of pages does).
        let per_page = TYPE_PAGE_LISTINGS as u64;
        let prefix = tagged(TYPE_TAG, &id_bytes);
        let mut rows = self
            .order
            .rev_prefix_iter(txn, &prefix)
            .map_err(store_error)?;
        let mut tail = Vec::new();
        let mut before_from = None;
        for row in rows.by_ref() {
            let key = row_key(&row.map_err(store_error)?.0[prefix.len()..])?;
            if key < from {
                before_from = Some(key);
                break;
            }
            tail.push(key);
        }
        let position = count.saturating_sub(tail.len() as u64);
        let mut first_page = position / per_page;
        if pages != todo.pages {
            first_page = first_page.min(pages.min(todo.pages).saturating_sub(1));
        }
        let wanted = usize::try_from(count - first_page * per_page).unwrap_or(usize::MAX);
        if let Some(key) = before_from {
            if tail.len() < wanted {
                tail.push(key);
            }
        }
        while tail.len() < wanted {
            match rows.next() {
                Some(row) => tail.push(row_key(&row.map_err(store_error)?.0[prefix.len()..])?),
                None => break,
            }
        }
        drop(rows);
        tail.reverse();
        for (page, keys) in (first_page..).zip(tail.chunks(TYPE_PAGE_LISTINGS)) {
            let listings = keys
                .iter()
                .map(|key| self.listed(txn, &key_address(key)))
                .collect::<Result<Vec<Entry>>>()?;
            let bytes = json(&TypePage {
                content_type: content_type.clone(),
                page,
                prev: page.checked_sub(1).map(|prev| type_page_at(id, prev)),
                next: (page + 1 < pages).then(|| type_page_at(id, page + 1)),
                listings,
            })?;
            files.put(&type_page_at(id, page), &bytes)?;
        }
        Ok(())
    }

    /// Write the time page whose first key is `first` (as text), if
    /// `pages.json` lists it.
    fn write_page(
        &self,
        txn: &RoTxn,
        files: &mut Files,
        first: &str,
        fixes: &mut Vec<PageFix>,
    ) -> Result<()> {
        let first = parse_key(first)
            .map(|key| key.to_bytes())
            .ok_or_else(|| Error::Storage(format!("listings store: bad key {first}")))?;
        let Some(value) = self
            .pages
            .get(txn, &tagged(PAGE_TAG, &first))
            .map_err(store_error)?
        else {
            return Ok(());
        };
        let row: PageRow = parse(value)?;
        let last = parse_key(&row.last)
            .map(|key| key.to_bytes())
            .ok_or_else(|| Error::Storage(format!("listings store: bad key {}", row.last)))?;
        let (start, end) = (tagged(KEY_TAG, &first), tagged(KEY_TAG, &last));
        let range = (Bound::Included(&start[..]), Bound::Included(&end[..]));
        let keys = self
            .order
            .range(txn, &range)
            .map_err(store_error)?
            .map(|row| row_key(&row.map_err(store_error)?.0[1..]))
            .collect::<Result<Vec<Key>>>()?;
        let bytes = self.page_bytes(txn, &keys)?;
        let path = page_path(&listing_key(&first)?, &bytes);
        if path != row.path {
            tracing::error!(
                "listings: the time page from {} doesn't hold what its name says; writing it as {path}",
                hex::encode(first)
            );
            fixes.push(PageFix {
                first,
                row: PageRow {
                    path: path.clone(),
                    last: row.last.clone(),
                    count: keys.len() as u64,
                },
                old_path: row.path,
            });
        }
        files.put(&path, &bytes)
    }

    /// Correct the rows of pages that didn't hold what their names said.
    fn fix_pages(
        &self,
        env: &heed::Env<heed::WithoutTls>,
        at: u64,
        fixes: &[PageFix],
    ) -> Result<()> {
        let mut txn = env.write_txn().map_err(store_error)?;
        for fix in fixes {
            self.pages
                .put(&mut txn, &tagged(PAGE_TAG, &fix.first), &json(&fix.row)?)
                .map_err(store_error)?;
            self.pages
                .put(&mut txn, &superseded_row(at, &fix.old_path), &[])
                .map_err(store_error)?;
        }
        txn.commit().map_err(store_error)
    }

    /// The bytes of the feed segment whose first record is `first`.
    fn segment(&self, txn: &RoTxn, epoch: &str, first: u64, seq: u64) -> Result<Vec<u8>> {
        let last = (first + FEED_SEGMENT_RECORDS - 1).min(seq);
        let records = self
            .feed
            .range(txn, &(first..=last))
            .map_err(store_error)?
            .map(|row| parse(row.map_err(store_error)?.1))
            .collect::<Result<Vec<FeedRecord>>>()?;
        json(&FeedSegment {
            epoch: epoch.to_string(),
            first,
            records,
        })
    }

    fn rejected(&self, txn: &RoTxn) -> Result<Vec<u8>> {
        let mut listings = self
            .side
            .prefix_iter(txn, &[REJECTED_TAG])
            .map_err(store_error)?
            .map(|row| parse(row.map_err(store_error)?.1))
            .collect::<Result<Vec<RejectedEntry>>>()?;
        listings.sort_by_key(|entry| entry.listing.key());
        json(&Rejected { listings })
    }

    fn pages_file(&self, txn: &RoTxn, epoch: &str, seq: u64, count: u64) -> Result<Vec<u8>> {
        let pages = self
            .pages
            .prefix_iter(txn, &[PAGE_TAG])
            .map_err(store_error)?
            .map(|row| {
                let (key, value) = row.map_err(store_error)?;
                let row: PageRow = parse(value)?;
                Ok(PageRef {
                    path: row.path,
                    first: hex::encode(&key[1..]),
                    last: row.last,
                    count: row.count,
                })
            })
            .collect::<Result<Vec<PageRef>>>()?;
        json(&Pages {
            epoch: epoch.to_string(),
            seq,
            count,
            pages,
        })
    }

    fn head(
        &self,
        txn: &RoTxn,
        epoch: &str,
        seq: u64,
        count: u64,
        generated_at: u64,
    ) -> Result<Vec<u8>> {
        let mut listings = Vec::new();
        for row in self
            .order
            .rev_prefix_iter(txn, &[KEY_TAG])
            .map_err(store_error)?
            .take(HEAD_LISTINGS)
        {
            let key = row_key(&row.map_err(store_error)?.0[1..])?;
            listings.push(self.listed(txn, &key_address(&key))?);
        }
        json(&Head {
            epoch: epoch.to_string(),
            seq,
            count,
            generated_at,
            listings,
            links: Links::default(),
        })
    }

    /// The time pages `pages.json` stopped listing at least
    /// [`SUPERSEDED_KEPT`] before `at`.
    fn expired_pages(&self, txn: &RoTxn, at: u64) -> Result<Vec<Expired>> {
        let Some(cutoff) = at.checked_sub(SUPERSEDED_KEPT.as_secs()) else {
            return Ok(Vec::new());
        };
        let start = [SUPERSEDED_TAG];
        let end = match cutoff.checked_add(1) {
            Some(after) => [&[SUPERSEDED_TAG][..], &after.to_be_bytes()[..]].concat(),
            None => vec![SUPERSEDED_TAG + 1],
        };
        let range = (Bound::Included(&start[..]), Bound::Excluded(&end[..]));
        let mut expired = Vec::new();
        for row in self.pages.range(txn, &range).map_err(store_error)? {
            let (row, _) = row.map_err(store_error)?;
            let path = String::from_utf8_lossy(row.get(9..).unwrap_or_default()).into_owned();
            expired.push(Expired {
                row: row.to_vec(),
                listed: false,
                path,
            });
        }
        for page in &mut expired {
            page.listed = self.lists_page(txn, &page.path)?;
        }
        Ok(expired)
    }

    /// Whether `pages.json` lists the time page at `path`.
    fn lists_page(&self, txn: &RoTxn, path: &str) -> Result<bool> {
        let first = path
            .strip_prefix("pages/")
            .and_then(|name| name.get(..2 * LISTING_KEY_LEN))
            .and_then(parse_key);
        let Some(first) = first else {
            return Ok(false);
        };
        Ok(self
            .pages
            .get(txn, &tagged(PAGE_TAG, &first.to_bytes()))
            .map_err(store_error)?
            .map(parse::<PageRow>)
            .transpose()?
            .is_some_and(|row| row.path == path))
    }
}

/// `feed/index.json` for a feed whose latest record is `seq`.
fn feed_index(epoch: &str, seq: u64) -> FeedIndex {
    let segments = (0..)
        .map(|segment| 1 + segment * FEED_SEGMENT_RECORDS)
        .take_while(|first| *first <= seq)
        .map(|first| SegmentRef {
            path: segment_path(first),
            first,
            last: (first + FEED_SEGMENT_RECORDS - 1).min(seq),
        })
        .collect();
    FeedIndex {
        epoch: epoch.to_string(),
        seq,
        segments,
    }
}

/// Writes the published files: each whole, and only when its bytes change,
/// with compressed copies beside it.
#[derive(Debug)]
struct Files {
    dir: PathBuf,
    /// Flush each file to disk before renaming it into place.
    durable: bool,
    /// What the files in `dir` take, in bytes.
    bytes: u64,
    /// Directories known to exist.
    dirs: HashSet<PathBuf>,
    /// Temporary files made, for their names.
    temps: u64,
    /// Files written since the count was last reset, each with its copies
    /// counting once, and their bytes.
    written: u64,
    written_bytes: u64,
}

impl Files {
    /// The files in `dir`, created if missing. Temporary files an
    /// interrupted write left are removed.
    fn open(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir).map_err(|e| {
            Error::Storage(format!(
                "could not create the listings directory {}: {e}",
                dir.display()
            ))
        })?;
        let bytes = measure(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            durable: true,
            bytes,
            dirs: HashSet::new(),
            temps: 0,
            written: 0,
            written_bytes: 0,
        })
    }

    /// Whether the directory holds the files of the feed `epoch` from
    /// record `written` (what the store says was written) to `seq`: its
    /// `head.json` is of that epoch and between them.
    fn holds(&self, epoch: &str, written: u64, seq: u64) -> bool {
        fs::read(self.dir.join(HEAD_FILE))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Head>(&bytes).ok())
            .is_some_and(|head| head.epoch == epoch && (written..=seq).contains(&head.seq))
    }

    /// The time pages in the directory, as paths from it.
    fn stray_pages(&self) -> Result<BTreeSet<String>> {
        let dir = self.dir.join("pages");
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
            Err(e) => return Err(io_error(&dir, &e)),
        };
        let mut pages = BTreeSet::new();
        for entry in entries {
            let name = entry.map_err(|e| io_error(&dir, &e))?.file_name();
            let name = name.to_string_lossy();
            let base = name
                .strip_suffix(".gz")
                .or_else(|| name.strip_suffix(".zst"))
                .unwrap_or(&name);
            if base.ends_with(".json") {
                pages.insert(format!("pages/{base}"));
            }
        }
        Ok(pages)
    }

    /// Write `bytes` as the file at `path` (from the directory), with its
    /// `.gz` and `.zst` copies: each only if it differs or is missing.
    fn put(&mut self, path: &str, bytes: &[u8]) -> Result<()> {
        let path = self.dir.join(path);
        let gz = with_suffix(&path, ".gz");
        let zst = with_suffix(&path, ".zst");
        let old = match fs::read(&path) {
            Ok(old) => Some(old),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(io_error(&path, &e)),
        };
        let same = old.as_deref() == Some(bytes);
        let gz_len = file_len(&gz)?;
        let zst_len = file_len(&zst)?;
        if same && gz_len.is_some() && zst_len.is_some() {
            return Ok(());
        }
        if let Some(dir) = path.parent() {
            self.ensure_dir(dir)?;
        }
        if !same || gz_len.is_none() {
            let packed = gzip(bytes).map_err(|e| io_error(&gz, &e))?;
            self.replace(&gz, &packed, gz_len)?;
        }
        if !same || zst_len.is_none() {
            let packed = zstd(bytes).map_err(|e| io_error(&zst, &e))?;
            self.replace(&zst, &packed, zst_len)?;
        }
        if !same {
            self.replace(&path, bytes, old.map(|old| old.len() as u64))?;
            self.written += 1;
            self.written_bytes += bytes.len() as u64;
        }
        Ok(())
    }

    /// Delete the file at `path` (from the directory) and its copies: the
    /// copies first, so a reader is never sent a copy without its file.
    fn remove(&mut self, path: &str) -> Result<()> {
        let path = self.dir.join(path);
        for file in [with_suffix(&path, ".gz"), with_suffix(&path, ".zst"), path] {
            if let Some(len) = file_len(&file)? {
                match fs::remove_file(&file) {
                    Ok(()) => self.bytes = self.bytes.saturating_sub(len),
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    Err(e) => return Err(io_error(&file, &e)),
                }
            }
        }
        Ok(())
    }

    /// Write `bytes` beside `path`, then rename them over it: a reader sees
    /// the old file or the new one, never part of one.
    fn replace(&mut self, path: &Path, bytes: &[u8], old_len: Option<u64>) -> Result<()> {
        let dir = path.parent().unwrap_or(&self.dir);
        self.temps += 1;
        let temp = dir.join(format!(
            "{TEMP_PREFIX}{}-{}{TEMP_SUFFIX}",
            std::process::id(),
            self.temps
        ));
        if let Err(e) = write_then_rename(&temp, path, bytes, self.durable) {
            let _ = fs::remove_file(&temp);
            return Err(io_error(path, &e));
        }
        self.bytes = self
            .bytes
            .saturating_sub(old_len.unwrap_or(0))
            .saturating_add(bytes.len() as u64);
        Ok(())
    }

    fn ensure_dir(&mut self, dir: &Path) -> Result<()> {
        if !self.dirs.contains(dir) {
            fs::create_dir_all(dir).map_err(|e| io_error(dir, &e))?;
            self.dirs.insert(dir.to_path_buf());
        }
        Ok(())
    }
}

/// Write `bytes` as a new file at `temp`, flushed to disk if `durable`, and
/// rename it to `path`, replacing any file there.
fn write_then_rename(temp: &Path, path: &Path, bytes: &[u8], durable: bool) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(temp)?;
    file.write_all(bytes)?;
    if durable {
        file.sync_data()?;
    }
    drop(file);
    fs::rename(temp, path)
}

/// What the files under `dir` take, in bytes, removing the temporary files
/// an interrupted write left.
fn measure(dir: &Path) -> Result<u64> {
    let mut bytes = 0u64;
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir).map_err(|e| io_error(&dir, &e))? {
            let entry = entry.map_err(|e| io_error(&dir, &e))?;
            let kind = entry.file_type().map_err(|e| io_error(&entry.path(), &e))?;
            if kind.is_dir() {
                dirs.push(entry.path());
            } else if kind.is_file() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with(TEMP_PREFIX) && name.ends_with(TEMP_SUFFIX) {
                    fs::remove_file(entry.path()).map_err(|e| io_error(&entry.path(), &e))?;
                } else {
                    let meta = entry.metadata().map_err(|e| io_error(&entry.path(), &e))?;
                    bytes = bytes.saturating_add(meta.len());
                }
            }
        }
    }
    Ok(bytes)
}

/// The length of the file at `path`, if there is one.
fn file_len(path: &Path) -> Result<Option<u64>> {
    match fs::metadata(path) {
        Ok(meta) => Ok(Some(meta.len())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_error(path, &e)),
    }
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// The `.gz` copy of a file's bytes: gzip at the library's default level,
/// with no name or time in its header, so the same bytes always give the
/// same copy.
fn gzip(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut encoder = flate2::write::GzEncoder::new(
        Vec::with_capacity(bytes.len() / 4),
        flate2::Compression::default(),
    );
    encoder.write_all(bytes)?;
    encoder.finish()
}

/// The `.zst` copy of a file's bytes: zstd at the library's default level.
fn zstd(bytes: &[u8]) -> io::Result<Vec<u8>> {
    zstd::bulk::compress(bytes, zstd::DEFAULT_COMPRESSION_LEVEL)
}

fn io_error(path: &Path, error: &io::Error) -> Error {
    Error::Storage(format!("listings files: {}: {error}", path.display()))
}

fn json_error(error: serde_json::Error) -> Error {
    Error::Serialization(format!("listings files: {error}"))
}

/// `value` as a file's bytes ([`file_bytes`]).
fn json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    file_bytes(value).map_err(json_error)
}

fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes)
        .map_err(|e| Error::Storage(format!("listings store: unreadable row: {e}")))
}

/// The address `text` gives: 64 lowercase hex digits.
fn address_of(text: &str) -> Result<XorName> {
    match hex32(text) {
        Ok(address) if hex::encode(address) == text => Ok(address),
        _ => Err(Error::InvalidData(format!(
            "listings: {text:?} isn't an address as 64 lowercase hex digits"
        ))),
    }
}

fn hex32(text: &str) -> Result<[u8; 32]> {
    hex::decode(text)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| Error::InvalidData(format!("listings: {text:?} isn't 32 bytes in hex")))
}

fn key_of_entry(entry: &Entry) -> Result<Key> {
    entry.key().map(|key| key.to_bytes()).ok_or_else(|| {
        Error::InvalidData(format!(
            "listings: {:?} isn't an address",
            entry.listing.address
        ))
    })
}

fn row_key(bytes: &[u8]) -> Result<Key> {
    bytes
        .try_into()
        .map_err(|_| Error::Storage("listings store: a key of the wrong length".into()))
}

fn listing_key(key: &Key) -> Result<ListingKey> {
    ListingKey::from_bytes(key)
        .ok_or_else(|| Error::Storage("listings store: a key of the wrong length".into()))
}

/// The address a key ends with.
fn key_address(key: &Key) -> XorName {
    let mut address = [0u8; 32];
    address.copy_from_slice(&key[LISTING_KEY_LEN - 32..]);
    address
}

/// The shard of 32 bytes (an address, or the BLAKE3 hash of a name or
/// content type): its first three hex digits, as a number.
fn shard_of(bytes: &[u8; 32]) -> u16 {
    (u16::from(bytes[0]) << 4) | u16::from(bytes[1] >> 4)
}

/// A shard's three hex digits.
fn shard_text(shard: u16) -> String {
    format!("{shard:03x}")
}

/// Page `page` of the content type whose id is `id` (64 hex digits), as
/// [`type_page_path`](super::listings_v1::type_page_path) names it.
fn type_page_at(id: &str, page: u64) -> String {
    format!("by-type/{}/{id}-{page}.json", &id[..PREFIX_DIGITS])
}

fn tagged(tag: u8, bytes: &[u8]) -> Vec<u8> {
    let mut row = Vec::with_capacity(1 + bytes.len());
    row.push(tag);
    row.extend_from_slice(bytes);
    row
}

/// A name's row: its shard, then `address` (empty for the shard's prefix).
fn name_row(shard: u16, address: &[u8]) -> Vec<u8> {
    let mut row = Vec::with_capacity(3 + address.len());
    row.push(NAME_TAG);
    row.extend_from_slice(&shard.to_be_bytes());
    row.extend_from_slice(address);
    row
}

/// A row noting that the time page at `path` left `pages.json` at `at`.
fn superseded_row(at: u64, path: &str) -> Vec<u8> {
    [
        &[SUPERSEDED_TAG][..],
        &at.to_be_bytes()[..],
        path.as_bytes(),
    ]
    .concat()
}

/// The rows, under `tag` (or none), of 32 bytes in `shard`: those whose
/// first 12 bits are its number.
fn shard_bounds(tag: Option<u8>, shard: u16) -> (Bound<Vec<u8>>, Bound<Vec<u8>>) {
    let start = |shard: u16| -> Vec<u8> {
        tag.into_iter()
            .chain([(shard >> 4) as u8, ((shard & 0xf) << 4) as u8])
            .collect()
    };
    let end = if usize::from(shard) + 1 < SHARDS {
        Bound::Excluded(start(shard + 1))
    } else {
        match tag {
            Some(tag) => Bound::Excluded(vec![tag + 1]),
            None => Bound::Unbounded,
        }
    };
    (Bound::Included(start(shard)), end)
}

/// The rows under `tag` of the keys after `after` up to and including
/// `through`.
fn stretch_bounds(
    tag: u8,
    after: Option<&Key>,
    through: Option<&Key>,
) -> (Bound<Vec<u8>>, Bound<Vec<u8>>) {
    let start = match after {
        Some(key) => Bound::Excluded(tagged(tag, key)),
        None => Bound::Included(vec![tag]),
    };
    let end = match through {
        Some(key) => Bound::Included(tagged(tag, key)),
        None => Bound::Excluded(vec![tag + 1]),
    };
    (start, end)
}

fn bound_slice(bound: &Bound<Vec<u8>>) -> Bound<&[u8]> {
    bound.as_ref().map(Vec::as_slice)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Read;
    use std::ops::Range;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::{Instant, SystemTime};

    use ant_listings::CheckLevel;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use serde_json::Value;

    use super::*;
    use crate::data::client::listings_v1::{
        address_prefix, name_prefix, type_id, type_page_path, CensusStatus, CopyFields,
        CycleStatus, ListingFields, Resources, RpcCalls, Totals, MAX_PAGE_LISTINGS,
    };

    /// A small map: tests open many stores.
    const TEST_MAP: usize = 64 * 1024 * 1024;

    /// The cycle the fixtures were decided in.
    const AT: u64 = 1_791_324_060;

    /// When `status.json` is written.
    const NOW: u64 = 1_791_324_061;

    const EPOCH_TEXT: &str = "8c1f0e2d3b4a5968";

    const TEXT_PLAIN_ID: &str = "d1acb144aa06cec156c391172ed53277ec72ff75ff1a08e0dab4c84efbdadbbc";

    /// The format's first example of an entry, as its files hold it.
    const SHOWN: &str = concat!(
        r#"{"address":"1111111111111111111111111111111111111111111111111111111111111111","#,
        r#""name":"a.txt","content_type":"text/plain","size":20480,"readable":true,"hidden":[],"#,
        r#""tx_hash":"0x2222222222222222222222222222222222222222222222222222222222222222","#,
        r#""block_number":81942857,"block_timestamp":1791321603,"log_index":7,"#,
        r#""quote_hash":"0x4c10e4ae831c5a287c8f92d65bfc964201171696de4f11aa4d568f7e1cbf4ebd","#,
        r#""time":1791321603,"check":"verified","decided_at":1791321660}"#
    );

    /// The format's second example.
    const HIDING: &str = concat!(
        r#"{"address":"a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0","#,
        r#""name":null,"content_type":null,"size":null,"readable":false,"#,
        r#""hidden":["tx-hash","timestamp","log-index","quote"],"#,
        r#""block_number":81950000,"first_seen":1791324000,"time":1791324000,"#,
        r#""check":"reported","decided_at":1791324060}"#
    );

    const LINKS: &str = concat!(
        r#"{"status":"status.json","rejected":"rejected.json","pages":"pages.json","#,
        r#""feed":"feed/index.json","by_address":"by-address/{prefix}.json","#,
        r#""support":"by-address/{prefix}.support.json","by_name":"by-name/{prefix}.json","#,
        r#""by_type":"by-type/{prefix}/index.json"}"#
    );

    fn now() -> u64 {
        NOW
    }

    /// A store and a publisher in a temporary directory, under a fixed
    /// epoch.
    struct Fixture {
        dir: tempfile::TempDir,
        store: ListingsStore,
        publisher: Publisher,
    }

    impl Fixture {
        fn new() -> Self {
            Self::with_map(TEST_MAP)
        }

        fn with_map(map: usize) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let store = ListingsStore::open_with_map_size(&dir.path().join("store"), map).unwrap();
            let meta: Database<Str, Str> = store.database(META_TEXT_DB).unwrap();
            let mut txn = store.env().write_txn().unwrap();
            meta.put(&mut txn, EPOCH, EPOCH_TEXT).unwrap();
            txn.commit().unwrap();
            let publisher = open(&dir.path().join("v1"), &store);
            Self {
                dir,
                store,
                publisher,
            }
        }

        /// Open the publisher again, as after a restart.
        fn reopen(&mut self) {
            self.publisher = open(&self.out(), &self.store);
        }

        fn out(&self) -> PathBuf {
            self.dir.path().join("v1")
        }

        fn publish(&mut self, publication: &Publication) -> Published {
            self.publisher.publish(publication).unwrap()
        }

        fn bytes(&self, path: &str) -> Vec<u8> {
            fs::read(self.out().join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
        }

        fn text(&self, path: &str) -> String {
            String::from_utf8(self.bytes(path)).unwrap()
        }

        fn file<T: DeserializeOwned>(&self, path: &str) -> T {
            serde_json::from_slice(&self.bytes(path)).unwrap()
        }

        fn exists(&self, path: &str) -> bool {
            self.out().join(path).exists()
        }

        fn modified(&self, path: &str) -> SystemTime {
            fs::metadata(self.out().join(path))
                .unwrap()
                .modified()
                .unwrap()
        }
    }

    fn open(out: &Path, store: &ListingsStore) -> Publisher {
        let mut publisher = Publisher::open(out, store).unwrap();
        publisher.set_flush(false);
        publisher.set_clock(now);
        publisher
    }

    /// The format's first example: a verified listing showing every payment
    /// field ([`SHOWN`]).
    fn shown() -> ShardEntry {
        ShardEntry {
            entry: Entry {
                listing: ListingFields {
                    address: "11".repeat(32),
                    name: Some("a.txt".into()),
                    content_type: Some("text/plain".into()),
                    size: Some(20_480),
                    readable: true,
                    hidden: Vec::new(),
                    tx_hash: Some(format!("0x{}", "22".repeat(32))),
                    block_number: Some(81_942_857),
                    block_timestamp: Some(1_791_321_603),
                    log_index: Some(7),
                    quote_hash: Some(
                        "0x4c10e4ae831c5a287c8f92d65bfc964201171696de4f11aa4d568f7e1cbf4ebd".into(),
                    ),
                    first_seen: None,
                    time: 1_791_321_603,
                },
                check: CheckLevel::Verified,
                decided_at: 1_791_321_660,
            },
            data_map: Some("93c4".into()),
        }
    }

    /// The format's second example: a private file's listing that shows
    /// only its block, dated by the nodes ([`HIDING`]).
    fn hiding() -> ShardEntry {
        ShardEntry {
            entry: Entry {
                listing: ListingFields {
                    address: "a0".repeat(32),
                    name: None,
                    content_type: None,
                    size: None,
                    readable: false,
                    hidden: ["tx-hash", "timestamp", "log-index", "quote"]
                        .map(String::from)
                        .to_vec(),
                    tx_hash: None,
                    block_number: Some(81_950_000),
                    block_timestamp: None,
                    log_index: None,
                    quote_hash: None,
                    first_seen: Some(1_791_324_000),
                    time: 1_791_324_000,
                },
                check: CheckLevel::Reported,
                decided_at: AT,
            },
            data_map: None,
        }
    }

    /// An entry's JSON with one more field at its end.
    fn with_field(entry: &str, field: &str) -> String {
        format!("{},{field}}}", &entry[..entry.len() - 1])
    }

    /// A verified entry at `address`, sorting at `time`, with nothing else.
    fn lean(address: XorName, time: u64) -> ShardEntry {
        ShardEntry {
            entry: Entry {
                listing: ListingFields {
                    address: hex::encode(address),
                    name: None,
                    content_type: None,
                    size: Some(1),
                    readable: true,
                    hidden: Vec::new(),
                    tx_hash: None,
                    block_number: Some(time / 2),
                    block_timestamp: Some(time),
                    log_index: Some(0),
                    quote_hash: None,
                    first_seen: None,
                    time,
                },
                check: CheckLevel::Verified,
                decided_at: AT,
            },
            data_map: None,
        }
    }

    fn put(entry: ShardEntry) -> IndexChange {
        IndexChange::Put(Box::new(entry))
    }

    fn remove(address: XorName) -> IndexChange {
        IndexChange::Remove {
            address,
            reason: RemoveReason::NoLongerServed,
        }
    }

    fn support(address: &str, nodes: usize) -> Support {
        Support {
            address: address.into(),
            nodes,
            nearest: 7,
            quorum: nodes >= 4,
            carried: false,
        }
    }

    /// A deferred listing, as the format's example of `rejected.json` has
    /// it.
    fn deferred() -> RejectedEntry {
        let mut listing = hiding().entry.listing;
        listing.address = "c0".repeat(32);
        listing.block_number = Some(80_204_042);
        RejectedEntry {
            listing,
            problem: "2 of the 7 nodes nearest its address serve it, needs 4; try again".into(),
            again: true,
            nodes: 2,
            nearest: 7,
            decided_at: AT,
            copies: vec![CopyFields {
                node: "03".repeat(32),
                block_number: Some(80_204_042),
                block_timestamp: None,
                first_seen: Some(1_791_324_000),
                time: 1_791_324_000,
                before_vault_deployment: true,
            }],
        }
    }

    /// The producer's word on how it is doing in the cycle that began at
    /// `started_at`.
    fn status(started_at: u64) -> Status {
        Status {
            started_at: 1_791_320_000,
            cycle: CycleStatus {
                started_at,
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
                ..CensusStatus::default()
            },
            resources: Resources {
                files_bytes: Some(524_288),
                ..Resources::default()
            },
            ..Status::default()
        }
    }

    /// A publication of nothing but the status of the cycle at `at`.
    fn quiet(at: u64) -> Publication {
        Publication {
            at,
            status: status(at),
            ..Publication::default()
        }
    }

    fn first_publication() -> Publication {
        Publication {
            at: AT,
            changes: vec![put(shown()), put(hiding())],
            support: vec![support(&"11".repeat(32), 7), support(&"a0".repeat(32), 6)],
            rejected: vec![RejectedChange::Set(Box::new(deferred()))],
            status: status(AT),
        }
    }

    /// An address from `seed`.
    fn address(seed: u64) -> XorName {
        *blake3::hash(&seed.to_be_bytes()).as_bytes()
    }

    /// The first `count` addresses from `seeds` that end a time page, or
    /// don't, as `ending` asks.
    fn addresses_ending(ending: bool, count: usize, seeds: Range<u64>) -> Vec<XorName> {
        seeds
            .map(address)
            .filter(|address| ends_page(address) == ending)
            .take(count)
            .collect()
    }

    /// Every file under `dir`, by its path from it, with its bytes.
    fn tree(dir: &Path) -> BTreeMap<String, Vec<u8>> {
        let mut files = BTreeMap::new();
        let mut dirs = vec![dir.to_path_buf()];
        while let Some(at) = dirs.pop() {
            for entry in fs::read_dir(&at).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    dirs.push(entry.path());
                } else {
                    let name = entry
                        .path()
                        .strip_prefix(dir)
                        .unwrap()
                        .to_string_lossy()
                        .replace('\\', "/");
                    files.insert(name, fs::read(entry.path()).unwrap());
                }
            }
        }
        files
    }

    fn assert_same_files(left: &Path, right: &Path) {
        let (left, right) = (tree(left), tree(right));
        let names = |tree: &BTreeMap<String, Vec<u8>>| tree.keys().cloned().collect::<Vec<_>>();
        assert_eq!(names(&left), names(&right));
        for (name, bytes) in &left {
            assert!(right[name] == *bytes, "{name} differs");
        }
    }

    fn gunzip(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(bytes)
            .read_to_end(&mut out)
            .unwrap();
        out
    }

    #[test]
    fn a_feed_keeps_its_epoch_across_opens() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("listings").join("v1");
        let epoch = {
            let store =
                ListingsStore::open_with_map_size(&dir.path().join("store"), TEST_MAP).unwrap();
            let publisher = Publisher::open(&out, &store).unwrap();
            assert!(out.is_dir());
            assert_eq!(publisher.out_dir(), out);
            assert_eq!(publisher.epoch().len(), 16);
            assert_eq!((publisher.seq(), publisher.count()), (0, 0));
            publisher.epoch().to_string()
        };
        let store = ListingsStore::open_with_map_size(&dir.path().join("store"), TEST_MAP).unwrap();
        assert_eq!(Publisher::open(&out, &store).unwrap().epoch(), epoch);
        // Another store starts another feed.
        let other = ListingsStore::open_with_map_size(&dir.path().join("other"), TEST_MAP).unwrap();
        assert_ne!(Publisher::open(&out, &other).unwrap().epoch(), epoch);
    }

    #[test]
    fn every_kind_of_file_is_pinned() {
        let mut f = Fixture::new();
        let published = f.publish(&first_publication());
        assert_eq!(published.epoch, EPOCH_TEXT);
        assert_eq!((published.seq, published.count), (2, 2));
        assert_eq!(f.publisher.entry(&[0x11; 32]).unwrap(), Some(shown()));

        assert_eq!(
            f.text("head.json"),
            format!(
                r#"{{"epoch":"{EPOCH_TEXT}","seq":2,"count":2,"generated_at":{AT},"listings":[{HIDING},{SHOWN}],"links":{LINKS}}}"#
            )
        );
        assert_eq!(
            f.text("by-address/111.json"),
            format!(
                r#"{{"prefix":"111","listings":[{}]}}"#,
                with_field(SHOWN, r#""data_map":"93c4""#)
            )
        );
        assert_eq!(
            f.text("by-address/a0a.json"),
            format!(
                r#"{{"prefix":"a0a","listings":[{}]}}"#,
                with_field(HIDING, r#""data_map":null"#)
            )
        );
        assert_eq!(
            f.text("by-address/000.json"),
            r#"{"prefix":"000","listings":[]}"#
        );
        assert_eq!(
            f.text("by-address/111.support.json"),
            format!(
                r#"{{"prefix":"111","support":[{{"address":"{}","nodes":7,"nearest":7,"quorum":true,"carried":false}}]}}"#,
                "11".repeat(32)
            )
        );
        assert_eq!(
            f.text("by-address/a0a.support.json"),
            format!(
                r#"{{"prefix":"a0a","support":[{{"address":"{}","nodes":6,"nearest":7,"quorum":true,"carried":false}}]}}"#,
                "a0".repeat(32)
            )
        );
        assert_eq!(
            f.text("by-address/fff.support.json"),
            r#"{"prefix":"fff","support":[]}"#
        );
        assert_eq!(name_prefix("a.txt"), "0c1");
        assert_eq!(
            f.text("by-name/0c1.json"),
            format!(r#"{{"prefix":"0c1","names":[{{"name":"a.txt","listings":[{SHOWN}]}}]}}"#)
        );
        assert_eq!(f.text("by-name/fff.json"), r#"{"prefix":"fff","names":[]}"#);
        let type_page = format!("by-type/d1a/{TEXT_PLAIN_ID}-0.json");
        assert_eq!(type_page, type_page_path("text/plain", 0));
        assert_eq!(
            f.text("by-type/d1a/index.json"),
            format!(
                r#"{{"prefix":"d1a","types":[{{"content_type":"text/plain","count":1,"pages":1,"first":"{type_page}","last":"{type_page}"}}]}}"#
            )
        );
        assert_eq!(
            f.text(&type_page),
            format!(
                r#"{{"content_type":"text/plain","page":0,"prev":null,"next":null,"listings":[{SHOWN}]}}"#
            )
        );
        assert_eq!(
            f.text("by-type/000/index.json"),
            r#"{"prefix":"000","types":[]}"#
        );
        // The format's example of pages.json: neither address ends a page.
        let first = "000000006ac566030000000004e2594900000000000000071111111111111111111111111111111111111111111111111111111111111111";
        let last = "000000006ac56f600000000004e275300000000000000000a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0";
        let page = format!(
            "pages/{first}-d40d8c4970af03f36cbb63c8599efa580b278f3027232ca7b24f6f103f24c50d.json"
        );
        assert_eq!(
            f.text("pages.json"),
            format!(
                r#"{{"epoch":"{EPOCH_TEXT}","seq":2,"count":2,"pages":[{{"path":"{page}","first":"{first}","last":"{last}","count":2}}]}}"#
            )
        );
        assert_eq!(
            f.text(&page),
            format!(r#"{{"listings":[{SHOWN},{HIDING}]}}"#)
        );
        assert_eq!(
            f.text("feed/index.json"),
            format!(
                r#"{{"epoch":"{EPOCH_TEXT}","seq":2,"segments":[{{"path":"feed/1.json","first":1,"last":2}}]}}"#
            )
        );
        assert_eq!(
            f.text("feed/1.json"),
            format!(
                concat!(
                    r#"{{"epoch":"{epoch}","first":1,"records":["#,
                    r#"{{"seq":1,"at":{at},"op":"put","listing":{shown}}},"#,
                    r#"{{"seq":2,"at":{at},"op":"put","listing":{hiding}}}]}}"#
                ),
                epoch = EPOCH_TEXT,
                at = AT,
                shown = SHOWN,
                hiding = HIDING
            )
        );
        assert_eq!(
            f.text("status.json"),
            format!(
                concat!(
                    r#"{{"epoch":"{epoch}","seq":2,"count":2,"generated_at":{now},"started_at":1791320000,"#,
                    r#""cycle":{{"started_at":{at},"millis":312,"bytes_in":210000,"bytes_out":180000,"rpc_calls":2,"rpc_errors":0,"decided":1,"too_few_answered":false}},"#,
                    r#""totals":{{"cycles":68,"bytes_in":14000000,"bytes_out":12000000,"rpc":[{{"provider":"rpc.example.org","calls":40,"errors":1}}]}},"#,
                    r#""census":{{"nodes":20,"answering":19,"leaves":2,"versions":[],"silent":[]}},"#,
                    r#""deferred":[],"below_full":{{"listings":0,"oldest_since":null}},"drops":{{"removed":0,"carried":0}},"#,
                    r#""resources":{{"rss_bytes":null,"store_bytes":null,"files_bytes":524288,"disk_free_bytes":null}}}}"#
                ),
                epoch = EPOCH_TEXT,
                now = NOW,
                at = AT
            )
        );
        assert_eq!(
            f.text("rejected.json"),
            format!(
                concat!(
                    r#"{{"listings":[{{"address":"{address}","name":null,"content_type":null,"size":null,"#,
                    r#""readable":false,"hidden":["tx-hash","timestamp","log-index","quote"],"#,
                    r#""block_number":80204042,"first_seen":1791324000,"time":1791324000,"#,
                    r#""problem":"2 of the 7 nodes nearest its address serve it, needs 4; try again","#,
                    r#""again":true,"nodes":2,"nearest":7,"decided_at":{at},"copies":["#,
                    r#"{{"node":"{node}","block_number":80204042,"first_seen":1791324000,"time":1791324000,"before_vault_deployment":true}}]}}]}}"#
                ),
                address = "c0".repeat(32),
                node = "03".repeat(32),
                at = AT
            )
        );
        // Beside each file, the same bytes compressed.
        for path in [
            "head.json",
            "by-address/111.json",
            "by-address/000.support.json",
            "by-name/0c1.json",
            "by-type/d1a/index.json",
            type_page.as_str(),
            "pages.json",
            page.as_str(),
            "feed/index.json",
            "feed/1.json",
            "status.json",
            "rejected.json",
        ] {
            let bytes = f.bytes(path);
            assert_eq!(gunzip(&f.bytes(&format!("{path}.gz"))), bytes, "{path}.gz");
            assert_eq!(
                zstd::decode_all(&f.bytes(&format!("{path}.zst"))[..]).unwrap(),
                bytes,
                "{path}.zst"
            );
        }
        // Every prefix has its files, empty or not.
        let count = |dir: &str, suffix: &str| {
            fs::read_dir(f.out().join(dir))
                .unwrap()
                .filter(|entry| {
                    entry
                        .as_ref()
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .ends_with(suffix)
                })
                .count()
        };
        assert_eq!(count("by-address", ".support.json"), SHARDS);
        assert_eq!(count("by-address", ".json"), 2 * SHARDS);
        assert_eq!(count("by-address", ".json.gz"), 2 * SHARDS);
        assert_eq!(count("by-address", ".json.zst"), 2 * SHARDS);
        assert_eq!(count("by-name", ".json"), SHARDS);
        assert_eq!(count("by-type", ""), SHARDS);
        for prefix in ["000", "7ff", "fff"] {
            assert!(f.exists(&format!("by-type/{prefix}/index.json.zst")));
        }

        // The second listing is no longer served.
        let later = AT + 3_600;
        let published = f.publish(&Publication {
            changes: vec![remove([0xa0; 32])],
            ..quiet(later)
        });
        assert_eq!((published.seq, published.count), (3, 1));
        assert_eq!(
            f.text("head.json"),
            format!(
                r#"{{"epoch":"{EPOCH_TEXT}","seq":3,"count":1,"generated_at":{later},"listings":[{SHOWN}],"links":{LINKS}}}"#
            )
        );
        assert_eq!(
            f.text("by-address/a0a.json"),
            r#"{"prefix":"a0a","listings":[]}"#
        );
        // Its support goes with it (the support files were last written an
        // hour ago).
        assert_eq!(
            f.text("by-address/a0a.support.json"),
            r#"{"prefix":"a0a","support":[]}"#
        );
        assert_eq!(
            f.text("feed/1.json"),
            format!(
                concat!(
                    r#"{{"epoch":"{epoch}","first":1,"records":["#,
                    r#"{{"seq":1,"at":{at},"op":"put","listing":{shown}}},"#,
                    r#"{{"seq":2,"at":{at},"op":"put","listing":{hiding}}},"#,
                    r#"{{"seq":3,"at":{later},"op":"remove","address":"{address}","reason":"no_longer_served"}}]}}"#
                ),
                epoch = EPOCH_TEXT,
                at = AT,
                later = later,
                shown = SHOWN,
                hiding = HIDING,
                address = "a0".repeat(32)
            )
        );
        assert_eq!(
            f.text("feed/index.json"),
            format!(
                r#"{{"epoch":"{EPOCH_TEXT}","seq":3,"segments":[{{"path":"feed/1.json","first":1,"last":3}}]}}"#
            )
        );
        let only = format!(r#"{{"listings":[{SHOWN}]}}"#);
        let only_page = page_path(&parse_key(first).unwrap(), only.as_bytes());
        assert_eq!(
            f.text("pages.json"),
            format!(
                r#"{{"epoch":"{EPOCH_TEXT}","seq":3,"count":1,"pages":[{{"path":"{only_page}","first":"{first}","last":"{first}","count":1}}]}}"#
            )
        );
        assert_eq!(f.text(&only_page), only);
        // The page it replaced stays, for readers part way through.
        assert!(f.exists(&page));
    }

    #[test]
    fn files_are_written_only_when_their_bytes_change() {
        let mut f = Fixture::new();
        let first = f.publish(&first_publication());
        assert!(first.files_written > 4 * SHARDS as u64);
        let watched = [
            "head.json",
            "pages.json",
            "feed/index.json",
            "feed/1.json",
            "by-address/111.json",
            "by-address/111.support.json",
            "by-name/0c1.json",
            "by-type/d1a/index.json",
            "rejected.json",
            "status.json",
        ];
        let times = |f: &Fixture| watched.map(|path| f.modified(path));
        let before = times(&f);
        // The same changes again change nothing: no record, no file.
        let again = f.publish(&first_publication());
        assert_eq!(
            (
                again.seq,
                again.count,
                again.files_written,
                again.bytes_written
            ),
            (2, 2, 0, 0)
        );
        assert_eq!(f.publish(&quiet(AT)).files_written, 0);
        assert_eq!(times(&f), before);
        // A new cycle's status is the only file written.
        let next = f.publish(&quiet(AT + 60));
        assert_eq!(next.files_written, 1);
        let after = times(&f);
        for (at, path) in watched.iter().enumerate() {
            assert_eq!(after[at] == before[at], *path != "status.json", "{path}");
        }
        // Nor does a restart write anything.
        f.reopen();
        assert_eq!(f.publish(&quiet(AT + 60)).files_written, 0);
        assert_eq!(times(&f), after);
    }

    #[test]
    fn the_feed_closes_a_segment_at_each_thousand_records() {
        let mut f = Fixture::new();
        let batch = |seeds: Range<u64>, at: u64| Publication {
            changes: seeds
                .map(|seed| put(lean(address(seed), 1_700_000_000 + seed)))
                .collect(),
            ..quiet(at)
        };
        f.publish(&batch(0..999, AT));
        assert_eq!(f.file::<FeedSegment>("feed/1.json").records.len(), 999);
        f.publish(&batch(999..1_001, AT + 60));
        assert_eq!(f.file::<FeedSegment>("feed/1.json").records.len(), 1_000);
        assert_eq!(f.file::<FeedSegment>("feed/1001.json").records.len(), 1);
        let closed = f.modified("feed/1.json");
        f.publish(&batch(1_001..2_500, AT + 120));
        f.publish(&Publication {
            changes: vec![remove(address(5)), remove(address(1_500))],
            ..quiet(AT + 180)
        });
        // A closed segment is never written again.
        assert_eq!(f.modified("feed/1.json"), closed);
        let index: FeedIndex = f.file("feed/index.json");
        assert_eq!(index.seq, 2_502);
        let segments: Vec<(String, u64, u64)> = index
            .segments
            .iter()
            .map(|segment| (segment.path.clone(), segment.first, segment.last))
            .collect();
        assert_eq!(
            segments,
            [
                ("feed/1.json".to_string(), 1, 1_000),
                ("feed/1001.json".to_string(), 1_001, 2_000),
                ("feed/2001.json".to_string(), 2_001, 2_502),
            ]
        );
        // Records 1 to n, applied in order to an empty index, give the index.
        let mut replayed: BTreeMap<String, Entry> = BTreeMap::new();
        let mut seq = 0;
        for segment in &index.segments {
            let file: FeedSegment = f.file(&segment.path);
            assert_eq!(
                (file.epoch.as_str(), file.first),
                (EPOCH_TEXT, segment.first)
            );
            for record in file.records {
                seq += 1;
                assert_eq!(record.seq, seq);
                match record.change {
                    Change::Put { listing } => {
                        replayed.insert(listing.listing.address.clone(), *listing);
                    }
                    Change::Remove { address, .. } => {
                        replayed.remove(&address);
                    }
                }
            }
        }
        assert_eq!(seq, 2_502);
        let pages: Pages = f.file("pages.json");
        let paged: BTreeMap<String, Entry> = pages
            .pages
            .iter()
            .flat_map(|page| f.file::<Page>(&page.path).listings)
            .map(|entry| (entry.listing.address.clone(), entry))
            .collect();
        assert_eq!(replayed.len(), 2_498);
        assert_eq!(replayed, paged);
    }

    #[test]
    fn time_pages_end_after_page_ends_and_at_four_thousand() {
        let mut f = Fixture::with_map(256 * 1024 * 1024);
        // 9,000 entries none of which ends a page, one that does, and 10
        // more, in key order.
        let others = addresses_ending(false, 9_010, 0..20_000);
        let end = addresses_ending(true, 1, 0..100_000)[0];
        let mut order: Vec<XorName> = others[..9_000].to_vec();
        order.push(end);
        order.extend_from_slice(&others[9_000..9_010]);
        let time = |at: usize| 1_700_000_000 + 10 * at as u64;
        f.publish(&Publication {
            changes: order
                .iter()
                .enumerate()
                .map(|(at, address)| put(lean(*address, time(at))))
                .collect(),
            ..quiet(AT)
        });
        let pages: Pages = f.file("pages.json");
        let counts: Vec<u64> = pages.pages.iter().map(|page| page.count).collect();
        assert_eq!(counts, [4_000, 4_000, 1_001, 10]);
        assert_eq!(MAX_PAGE_LISTINGS, 4_000);
        // Each page is named by its first key and the BLAKE3 hash of its
        // bytes, and holds its entries in key order.
        let mut oldest_first = Vec::new();
        for page in &pages.pages {
            let bytes = f.bytes(&page.path);
            assert_eq!(
                page.path,
                format!(
                    "pages/{}-{}.json",
                    page.first,
                    blake3::hash(&bytes).to_hex()
                )
            );
            let listings = f.file::<Page>(&page.path).listings;
            assert_eq!(listings.len() as u64, page.count);
            assert_eq!(key_hex(&listings[0].key().unwrap()), page.first);
            assert_eq!(
                key_hex(&listings[listings.len() - 1].key().unwrap()),
                page.last
            );
            oldest_first.extend(listings.iter().map(|entry| entry.listing.address.clone()));
        }
        let expected: Vec<String> = order.iter().map(hex::encode).collect();
        assert_eq!(oldest_first, expected);
        // Newest first: the pages from the last back, each read backwards.
        let newest_first: Vec<String> = pages
            .pages
            .iter()
            .rev()
            .flat_map(|page| f.file::<Page>(&page.path).listings.into_iter().rev())
            .map(|entry| entry.listing.address)
            .collect();
        assert_eq!(
            newest_first,
            expected.iter().rev().cloned().collect::<Vec<_>>()
        );
        // An entry added in the run's second page moves the ends after it,
        // up to the page end, and no others: the first page and the last
        // keep their names.
        let added = addresses_ending(false, 1, 30_000..40_000)[0];
        f.publish(&Publication {
            changes: vec![put(lean(added, time(5_000) + 5))],
            ..quiet(AT + 60)
        });
        let after: Pages = f.file("pages.json");
        let counts: Vec<u64> = after.pages.iter().map(|page| page.count).collect();
        assert_eq!(counts, [4_000, 4_000, 1_002, 10]);
        assert_eq!(after.pages[0], pages.pages[0]);
        assert_eq!(after.pages[3], pages.pages[3]);
        assert_ne!(after.pages[1].path, pages.pages[1].path);
        // Taking out the entry that ends a page joins its run with the 10
        // after it.
        f.publish(&Publication {
            changes: vec![remove(end)],
            ..quiet(AT + 120)
        });
        let joined: Pages = f.file("pages.json");
        let counts: Vec<u64> = joined.pages.iter().map(|page| page.count).collect();
        assert_eq!(counts, [4_000, 4_000, 1_011]);
        assert_eq!(joined.pages[0], pages.pages[0]);
    }

    /// The pages `pages.json` lists match those a whole build of `model`
    /// (each key, in key order, to its address) gives.
    fn assert_pages_match(f: &Fixture, model: &BTreeMap<Key, XorName>) {
        let pages: Pages = f.file("pages.json");
        let keys: Vec<&Key> = model.keys().collect();
        let addresses: Vec<XorName> = model.values().copied().collect();
        let expected: Vec<(String, String, u64)> = time_pages(&addresses)
            .into_iter()
            .map(|range| {
                (
                    hex::encode(keys[range.start]),
                    hex::encode(keys[range.end - 1]),
                    range.len() as u64,
                )
            })
            .collect();
        let listed: Vec<(String, String, u64)> = pages
            .pages
            .iter()
            .map(|page| (page.first.clone(), page.last.clone(), page.count))
            .collect();
        assert_eq!(listed, expected);
        assert_eq!(pages.count, model.len() as u64);
    }

    /// The index as a test keeps it: each key to its address, and each
    /// address's key.
    #[derive(Default)]
    struct Model {
        keys: BTreeMap<Key, XorName>,
        addresses: HashMap<XorName, Key>,
        changes: Vec<IndexChange>,
    }

    impl Model {
        fn put(&mut self, entry: ShardEntry) {
            let address = entry.entry.listing.address().unwrap();
            if let Some(old) = self.addresses.remove(&address) {
                self.keys.remove(&old);
            }
            let key = entry.entry.key().unwrap().to_bytes();
            self.keys.insert(key, address);
            self.addresses.insert(address, key);
            self.changes.push(put(entry));
        }

        fn remove(&mut self, address: XorName) {
            if let Some(key) = self.addresses.remove(&address) {
                self.keys.remove(&key);
            }
            self.changes.push(remove(address));
        }

        fn any(&self, rng: &mut StdRng) -> XorName {
            let mut listed: Vec<XorName> = self.addresses.keys().copied().collect();
            listed.sort_unstable();
            listed[rng.gen_range(0..listed.len())]
        }

        fn publication(&mut self, at: u64) -> Publication {
            Publication {
                changes: std::mem::take(&mut self.changes),
                ..quiet(at)
            }
        }
    }

    #[test]
    fn pages_built_change_by_change_are_those_built_whole() {
        let mut rng = StdRng::seed_from_u64(7);
        let mut f = Fixture::with_map(256 * 1024 * 1024);
        let mut model = Model::default();
        let mut ends = addresses_ending(true, 40, 0..200_000).into_iter();
        let mut plain = (1_000_000u64..)
            .map(address)
            .filter(|address| !ends_page(address));
        let time = |rng: &mut StdRng| rng.gen_range(1_700_000_000..1_700_100_000u64);
        // A run longer than a page holds, with a few page ends among them.
        for _ in 0..4_500 {
            let at = time(&mut rng);
            model.put(lean(plain.next().unwrap(), at));
        }
        for _ in 0..3 {
            let at = time(&mut rng);
            model.put(lean(ends.next().unwrap(), at));
        }
        f.publish(&model.publication(AT));
        assert_pages_match(&f, &model.keys);
        for round in 1..=30u64 {
            for _ in 0..rng.gen_range(1..=6) {
                let at = time(&mut rng);
                match rng.gen_range(0..4) {
                    0 => model.put(lean(plain.next().unwrap(), at)),
                    1 => {
                        if let Some(end) = ends.next() {
                            model.put(lean(end, at));
                        }
                    }
                    2 => {
                        let address = model.any(&mut rng);
                        model.remove(address);
                    }
                    _ => {
                        // An entry decided again with another date moves.
                        let address = model.any(&mut rng);
                        model.put(lean(address, at));
                    }
                }
            }
            f.publish(&model.publication(AT + 60 * round));
            assert_pages_match(&f, &model.keys);
        }
        // Every page listed is on disk, holding what its name says.
        let pages: Pages = f.file("pages.json");
        let mut paged = Vec::new();
        for page in &pages.pages {
            let bytes = f.bytes(&page.path);
            assert_eq!(
                page_path(&parse_key(&page.first).unwrap(), &bytes),
                page.path
            );
            paged.extend(
                f.file::<Page>(&page.path)
                    .listings
                    .iter()
                    .map(|entry| entry.key().unwrap().to_bytes()),
            );
        }
        assert_eq!(paged, model.keys.keys().copied().collect::<Vec<_>>());
    }

    #[test]
    fn content_type_pages_are_linked_both_ways() {
        let mut f = Fixture::new();
        let typed = |seed: u64, content_type: &str| {
            let mut entry = lean(address(seed), 1_700_000_000 + seed);
            entry.entry.listing.content_type = Some(content_type.into());
            entry
        };
        let mut changes: Vec<IndexChange> =
            (0..600).map(|seed| put(typed(seed, "image/png"))).collect();
        changes.extend((600..603).map(|seed| put(typed(seed, "text/plain"))));
        f.publish(&Publication {
            changes,
            ..quiet(AT)
        });
        let id = type_id("image/png");
        let index_path = type_index_path(&id[..3]);
        let summary = |f: &Fixture| {
            f.file::<TypeIndex>(&index_path)
                .types
                .into_iter()
                .find(|summary| summary.content_type == "image/png")
        };
        let walk = |f: &Fixture| {
            let summary = summary(f).unwrap();
            // Oldest first: from the first page, following `next`.
            let mut oldest_first = Vec::new();
            let mut sizes = Vec::new();
            let mut at = Some(summary.first.clone());
            while let Some(path) = at {
                let page: TypePage = f.file(&path);
                assert_eq!(page.page, sizes.len() as u64);
                assert_eq!(path, type_page_path("image/png", page.page));
                sizes.push(page.listings.len());
                oldest_first.extend(page.listings.iter().map(|entry| entry.key().unwrap()));
                at = page.next;
            }
            // Newest first: from the last, following `prev`, each page
            // backwards.
            let mut newest_first = Vec::new();
            let mut at = Some(summary.last.clone());
            while let Some(path) = at {
                let page: TypePage = f.file(&path);
                newest_first.extend(page.listings.iter().rev().map(|entry| entry.key().unwrap()));
                at = page.prev;
            }
            let mut sorted = oldest_first.clone();
            sorted.sort();
            assert_eq!(oldest_first, sorted);
            newest_first.reverse();
            assert_eq!(newest_first, oldest_first);
            assert_eq!(oldest_first.len() as u64, summary.count);
            assert_eq!(sizes.len() as u64, summary.pages);
            sizes
        };
        assert_eq!(walk(&f), [256, 256, 88]);
        assert_eq!(summary(&f).unwrap().last, type_page_path("image/png", 2));
        // Fewer entries: the third page goes, and the second is the last.
        f.publish(&Publication {
            changes: (512..600).map(|seed| remove(address(seed))).collect(),
            ..quiet(AT + 60)
        });
        assert_eq!(walk(&f), [256, 256]);
        let gone = type_page_path("image/png", 2);
        for suffix in ["", ".gz", ".zst"] {
            assert!(!f.exists(&format!("{gone}{suffix}")));
        }
        // Two more and an old one taken out: three pages again, every
        // page's entries moved by one.
        f.publish(&Publication {
            changes: vec![
                put(typed(700, "image/png")),
                put(typed(701, "image/png")),
                remove(address(0)),
            ],
            ..quiet(AT + 120)
        });
        assert_eq!(walk(&f), [256, 256, 1]);
        // A content type with no entries left leaves its index, and its
        // page goes.
        f.publish(&Publication {
            changes: (600..603).map(|seed| remove(address(seed))).collect(),
            ..quiet(AT + 180)
        });
        let text_index: TypeIndex = f.file("by-type/d1a/index.json");
        assert!(text_index
            .types
            .iter()
            .all(|summary| summary.content_type != "text/plain"));
        assert!(!f.exists(&type_page_path("text/plain", 0)));
    }

    #[test]
    fn names_and_the_head_list_newest_first() {
        let mut f = Fixture::new();
        // Two names in one shard.
        let names: Vec<String> = (0..10_000).map(|n| format!("n{n}")).collect();
        let (first, second) = names
            .iter()
            .enumerate()
            .find_map(|(at, name)| {
                names[..at]
                    .iter()
                    .find(|other| name_prefix(other) == name_prefix(name))
                    .map(|other| (other.clone(), name.clone()))
            })
            .unwrap();
        let named = |seed: u64, name: &str| {
            let mut entry = lean(address(seed), 1_700_000_000 + seed);
            entry.entry.listing.name = Some(name.into());
            entry
        };
        let mut changes = vec![
            put(named(1, &second)),
            put(named(2, &first)),
            put(named(3, &second)),
            put(named(4, &first)),
            put(named(5, &first)),
        ];
        changes.extend((10..70).map(|seed| put(lean(address(seed), 1_700_000_000 + seed))));
        f.publish(&Publication {
            changes,
            ..quiet(AT)
        });
        let shard: NameShard = f.file(&name_shard_path(&name_prefix(&first)));
        let mut expected = vec![(first.clone(), vec![5, 4, 2]), (second.clone(), vec![3, 1])];
        expected.sort();
        let groups: Vec<(String, Vec<u64>)> = shard
            .names
            .iter()
            .map(|group| {
                let seeds = group
                    .listings
                    .iter()
                    .map(|entry| entry.listing.time - 1_700_000_000)
                    .collect();
                (group.name.clone(), seeds)
            })
            .collect();
        assert_eq!(groups, expected);
        // The newest 50 of 65, newest first.
        let head: Head = f.file("head.json");
        assert_eq!(head.count, 65);
        let times: Vec<u64> = head
            .listings
            .iter()
            .map(|entry| entry.listing.time - 1_700_000_000)
            .collect();
        assert_eq!(times, (20..70).rev().collect::<Vec<u64>>());
    }

    #[test]
    fn a_reader_never_sees_part_of_a_file() {
        let mut f = Fixture::new();
        f.publish(&first_publication());
        // Then as in production: each file flushed before it is renamed in.
        f.publisher.set_flush(true);
        let done = Arc::new(AtomicBool::new(false));
        let reader = {
            let out = f.out();
            let done = Arc::clone(&done);
            std::thread::spawn(move || {
                let files = [
                    "head.json",
                    "head.json.gz",
                    "head.json.zst",
                    "pages.json",
                    "feed/index.json",
                    "feed/1.json",
                    "by-address/111.json",
                    "status.json",
                ];
                let mut seen = BTreeSet::new();
                let mut reads = 0u64;
                while !done.load(Ordering::Relaxed) {
                    for file in files {
                        let bytes = fs::read(out.join(file))
                            .unwrap_or_else(|e| panic!("{file} unreadable: {e}"));
                        let bytes = if file.ends_with(".gz") {
                            gunzip(&bytes)
                        } else if file.ends_with(".zst") {
                            zstd::decode_all(&bytes[..]).unwrap()
                        } else {
                            bytes
                        };
                        let value: Value = serde_json::from_slice(&bytes)
                            .unwrap_or_else(|e| panic!("{file} read in part: {e}"));
                        if file == "head.json" {
                            seen.insert(value["seq"].as_u64().unwrap());
                        }
                        reads += 1;
                    }
                }
                (reads, seen.len())
            })
        };
        for round in 1..=60u64 {
            let at = AT + 60 * round;
            let mut again = shown();
            again.entry.decided_at = at;
            f.publish(&Publication {
                changes: vec![put(again), put(lean(address(round), at))],
                ..quiet(at)
            });
        }
        done.store(true, Ordering::Relaxed);
        let (reads, versions) = reader.join().unwrap();
        assert!(reads > 0);
        assert!(
            versions > 1,
            "the reader saw {versions} versions of head.json"
        );
    }

    #[test]
    fn files_left_unwritten_are_written_by_the_next_publication() {
        let second = Publication {
            changes: vec![remove([0xa0; 32]), put(lean(address(1), AT + 3_000))],
            support: vec![support(&hex::encode(address(1)), 7)],
            ..quiet(AT + 3_600)
        };
        // As it should be.
        let mut whole = Fixture::new();
        whole.publish(&first_publication());
        whole.publish(&second);
        // Stopped after the store took the second publication, before any of
        // its files were written.
        let mut cut = Fixture::new();
        cut.publish(&first_publication());
        cut.publisher.record(&second).unwrap();
        cut.reopen();
        assert_eq!((cut.publisher.seq(), cut.publisher.count()), (4, 2));
        let resumed = cut.publish(&quiet(AT + 3_600));
        assert_eq!(resumed.seq, 4);
        assert!(resumed.files_written > 0);
        assert_same_files(&whole.out(), &cut.out());
    }

    #[test]
    fn a_publication_after_a_failed_write_finishes_it() {
        let mut f = Fixture::new();
        f.publish(&first_publication());
        // A directory where the next time page is to go: its write fails.
        let only = format!(r#"{{"listings":[{SHOWN}]}}"#);
        let first = parse_key(&f.file::<Pages>("pages.json").pages[0].first).unwrap();
        let only_page = page_path(&first, only.as_bytes());
        fs::create_dir_all(f.out().join(&only_page)).unwrap();
        let failed = f.publisher.publish(&Publication {
            changes: vec![remove([0xa0; 32])],
            ..quiet(AT + 60)
        });
        assert!(failed.is_err());
        // The change is in the store; the files that name the page aren't
        // written.
        assert_eq!(f.publisher.seq(), 3);
        assert_eq!(f.file::<Head>("head.json").seq, 2);
        assert_eq!(f.file::<Pages>("pages.json").seq, 2);
        // The next publication writes them.
        fs::remove_dir_all(f.out().join(&only_page)).unwrap();
        let next = f.publish(&quiet(AT + 120));
        assert_eq!(next.seq, 3);
        assert_eq!(f.text(&only_page), only);
        let head: Head = f.file("head.json");
        assert_eq!((head.seq, head.count), (3, 1));
        assert_eq!(f.file::<Pages>("pages.json").pages[0].path, only_page);
        assert_eq!(f.file::<FeedIndex>("feed/index.json").seq, 3);
    }

    #[test]
    fn lost_files_are_written_again_when_the_publisher_opens() {
        let mut f = Fixture::new();
        f.publish(&first_publication());
        let before = tree(&f.out());
        // head.json and a shard lost: every file is checked, and those two
        // written again.
        for path in ["head.json", "head.json.zst", "by-name/0c1.json"] {
            fs::remove_file(f.out().join(path)).unwrap();
        }
        f.reopen();
        assert_eq!(f.publish(&quiet(AT)).files_written, 2);
        assert_eq!(tree(&f.out()), before);
        // The directory emptied, or a new one: written again whole.
        fs::remove_dir_all(f.out()).unwrap();
        f.reopen();
        f.publish(&quiet(AT));
        assert_eq!(tree(&f.out()), before);
    }

    #[test]
    fn a_page_pages_json_no_longer_lists_is_deleted_a_day_later() {
        let mut f = Fixture::new();
        f.publish(&first_publication());
        let both = f.file::<Pages>("pages.json").pages[0].path.clone();
        let copies = |path: &str| {
            [
                path.to_string(),
                format!("{path}.gz"),
                format!("{path}.zst"),
            ]
        };
        let day = SUPERSEDED_KEPT.as_secs();
        let left = AT + 100;
        f.publish(&Publication {
            changes: vec![remove([0xa0; 32])],
            ..quiet(left)
        });
        f.publish(&quiet(left + day - 1));
        assert!(copies(&both).iter().all(|path| f.exists(path)));
        let bytes_before = f.publisher.files_bytes();
        f.publish(&quiet(left + day));
        assert!(copies(&both).iter().all(|path| !f.exists(path)));
        assert!(f.publisher.files_bytes() < bytes_before);
        // Listed again, it is written again.
        f.publish(&Publication {
            changes: vec![put(hiding())],
            ..quiet(left + day + 10)
        });
        assert_eq!(f.file::<Pages>("pages.json").pages[0].path, both);
        assert!(copies(&both).iter().all(|path| f.exists(path)));
        // A page listed again before its day is up stays.
        let again = left + day + 20;
        f.publish(&Publication {
            changes: vec![remove([0xa0; 32])],
            ..quiet(again)
        });
        f.publish(&Publication {
            changes: vec![put(hiding())],
            ..quiet(again + 30)
        });
        f.publish(&quiet(again + day + 60));
        assert!(copies(&both).iter().all(|path| f.exists(path)));
        assert_eq!(f.publisher.files_bytes(), measure(&f.out()).unwrap());
    }

    #[test]
    fn support_files_are_written_at_most_every_ten_minutes() {
        let mut f = Fixture::new();
        f.publish(&first_publication());
        let path = "by-address/111.support.json";
        let nodes = |f: &Fixture| f.file::<SupportShard>(path).support[0].nodes;
        assert_eq!(nodes(&f), 7);
        let interval = SUPPORT_INTERVAL.as_secs();
        assert_eq!(interval, 600);
        f.publish(&Publication {
            support: vec![support(&"11".repeat(32), 5)],
            ..quiet(AT + 60)
        });
        assert_eq!(nodes(&f), 7);
        assert_eq!(f.publisher.support(&[0x11; 32]).unwrap().unwrap().nodes, 5);
        f.publish(&quiet(AT + interval - 1));
        assert_eq!(nodes(&f), 7);
        f.publish(&quiet(AT + interval));
        assert_eq!(nodes(&f), 5);
        // Support for an address that isn't listed is left out.
        f.publish(&Publication {
            support: vec![support(&"ee".repeat(32), 7)],
            ..quiet(AT + 2 * interval)
        });
        assert_eq!(f.publisher.support(&[0xee; 32]).unwrap(), None);
    }

    #[test]
    fn status_gives_where_the_index_stands() {
        let mut f = Fixture::new();
        let mut given = status(AT);
        given.epoch = "elsewhere".into();
        given.seq = 99;
        given.count = 99;
        given.generated_at = 1;
        given.resources.files_bytes = None;
        f.publish(&Publication {
            changes: vec![put(shown())],
            status: given,
            ..quiet(AT)
        });
        let written: Status = f.file("status.json");
        assert_eq!(
            (
                written.epoch.as_str(),
                written.seq,
                written.count,
                written.generated_at
            ),
            (EPOCH_TEXT, 1, 1, NOW)
        );
        assert!(written.resources.files_bytes.unwrap() > 0);
        assert_eq!(written.cycle, status(AT).cycle);
        // What the files take is kept exactly as they are written, and
        // measured again on opening.
        assert_eq!(f.publisher.files_bytes(), measure(&f.out()).unwrap());
        f.reopen();
        assert_eq!(f.publisher.files_bytes(), measure(&f.out()).unwrap());
    }

    #[test]
    fn a_publication_with_a_bad_address_changes_nothing() {
        let mut f = Fixture::new();
        f.publish(&first_publication());
        let before = tree(&f.out());
        let mut upper = lean([0xab; 32], AT);
        upper.entry.listing.address = "AB".repeat(32);
        let mut short = lean([0xab; 32], AT);
        short.entry.listing.address = "ab".into();
        let mut bad_support = support(&"11".repeat(32), 7);
        bad_support.address = "11".into();
        let mut bad_rejection = deferred();
        bad_rejection.listing.address = "C0".repeat(32);
        for publication in [
            Publication {
                changes: vec![put(lean([0xcd; 32], AT)), put(upper)],
                ..quiet(AT + 60)
            },
            Publication {
                changes: vec![put(short)],
                ..quiet(AT + 60)
            },
            Publication {
                changes: vec![put(lean([0xcd; 32], AT))],
                support: vec![bad_support],
                ..quiet(AT + 60)
            },
            Publication {
                changes: vec![put(lean([0xcd; 32], AT))],
                rejected: vec![RejectedChange::Set(Box::new(bad_rejection))],
                ..quiet(AT + 60)
            },
        ] {
            let result = f.publisher.publish(&publication);
            assert!(matches!(result, Err(Error::InvalidData(_))), "{result:?}");
            assert_eq!((f.publisher.seq(), f.publisher.count()), (2, 2));
            assert_eq!(f.publisher.entry(&[0xcd; 32]).unwrap(), None);
        }
        assert_eq!(tree(&f.out()), before);
        // Taking out an address that isn't listed makes no record.
        let published = f.publish(&Publication {
            changes: vec![IndexChange::Remove {
                address: [0xee; 32],
                reason: RemoveReason::Rejected,
            }],
            ..quiet(AT)
        });
        assert_eq!(published.seq, 2);
        assert_eq!(tree(&f.out()), before);
    }

    #[test]
    fn leftovers_are_cleared_when_the_publisher_opens() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("v1");
        fs::create_dir_all(out.join("by-address")).unwrap();
        fs::create_dir_all(out.join("pages")).unwrap();
        // A write a stopped process left part done.
        let temp = out.join("by-address").join(".publish-7-1.tmp");
        fs::write(&temp, b"{\"pre").unwrap();
        // A time page of an earlier feed.
        let stray = out.join("pages").join("old.json");
        fs::write(&stray, b"{}").unwrap();
        let store = ListingsStore::open_with_map_size(&dir.path().join("store"), TEST_MAP).unwrap();
        let mut publisher = open(&out, &store);
        assert!(!temp.exists());
        assert_eq!(publisher.files_bytes(), 2);
        // The earlier feed's page goes a day after the new feed begins.
        publisher.publish(&quiet(unix_now())).unwrap();
        assert!(stray.exists());
        publisher
            .publish(&quiet(unix_now() + SUPERSEDED_KEPT.as_secs() + 60))
            .unwrap();
        assert!(!stray.exists());
    }

    #[test]
    fn shards_and_type_pages_are_named_as_the_format_names_them() {
        for address in [[0u8; 32], [0x3d; 32], [0xff; 32], address(9)] {
            assert_eq!(shard_text(shard_of(&address)), address_prefix(&address));
        }
        for name in ["", "a.txt", "A.txt", "\u{fc}ber"] {
            assert_eq!(
                shard_text(shard_of(blake3::hash(name.as_bytes()).as_bytes())),
                name_prefix(name)
            );
        }
        for content_type in ["text/plain", "image/png", ""] {
            assert_eq!(
                type_page_at(&type_id(content_type), 3),
                type_page_path(content_type, 3)
            );
        }
        // A shard's rows are those whose first 12 bits are its number.
        for shard in [0u16, 1, 0x7ff, 0xffe, 0xfff] {
            let (start, end) = shard_bounds(Some(SUPPORT_TAG), shard);
            let range = (bound_slice(&start), bound_slice(&end));
            let inside = |bytes: &[u8; 32]| {
                let row = tagged(SUPPORT_TAG, bytes);
                <_ as std::ops::RangeBounds<[u8]>>::contains(&range, &row[..])
            };
            let mut low = [0u8; 32];
            low[0] = (shard >> 4) as u8;
            low[1] = ((shard & 0xf) << 4) as u8;
            let mut high = [0xffu8; 32];
            high[0] = low[0];
            high[1] = low[1] | 0x0f;
            assert!(inside(&low) && inside(&high), "{shard}");
            assert_eq!((shard_of(&low), shard_of(&high)), (shard, shard));
            if shard > 0 {
                let mut below = low;
                below[1] = below[1].wrapping_sub(1);
                if below[1] == 0xff {
                    below[0] -= 1;
                }
                assert!(!inside(&below), "{shard}");
            }
            if shard < 0xfff {
                let mut above = [0u8; 32];
                above[0] = high[0];
                above[1] = high[1].wrapping_add(1);
                if above[1] == 0 {
                    above[0] += 1;
                }
                assert!(!inside(&above), "{shard}");
            }
        }
    }

    /// `n` entries as a busy index might hold them: every payment field
    /// shown, names from a few thousand and content types from 20, and data
    /// maps of 300 bytes for the readable ones.
    fn synthetic(seeds: Range<u64>) -> Vec<ShardEntry> {
        seeds
            .map(|seed| {
                let time = 1_760_000_000 + seed * 30;
                ShardEntry {
                    entry: Entry {
                        listing: ListingFields {
                            address: hex::encode(address(seed)),
                            name: Some(format!("file-{}.bin", seed % 5_000)),
                            content_type: Some(format!("application/x-kind-{}", seed % 20)),
                            size: Some(seed * 977),
                            readable: seed % 10 < 7,
                            hidden: Vec::new(),
                            tx_hash: Some(format!("0x{}", hex::encode(address(seed ^ 1 << 62)))),
                            block_number: Some(80_000_000 + seed * 15),
                            block_timestamp: Some(time),
                            log_index: Some(seed % 300),
                            quote_hash: Some(format!("0x{}", hex::encode(address(seed ^ 1 << 63)))),
                            first_seen: None,
                            time,
                        },
                        check: CheckLevel::Verified,
                        decided_at: time + 60,
                    },
                    data_map: (seed % 10 < 7).then(|| hex::encode([seed as u8; 300])),
                }
            })
            .collect()
    }

    /// Publish `n` listings at once, as a first start would, then one new
    /// listing and one old one taken out; check what each costs, and what
    /// the store and the files take.
    fn size_and_time(n: u64) {
        let map = usize::try_from(n * 24 * 1024).unwrap() + TEST_MAP;
        let mut f = Fixture::with_map(map);
        let entries = synthetic(0..n);
        let started = Instant::now();
        let built = f.publish(&Publication {
            support: entries
                .iter()
                .map(|entry| support(&entry.entry.listing.address, 7))
                .collect(),
            changes: entries.into_iter().map(put).collect(),
            ..quiet(AT)
        });
        let build = started.elapsed();
        assert_eq!((built.seq, built.count), (n, n));
        // One new listing, the newest.
        let newest = synthetic(n..n + 1).remove(0);
        let started = Instant::now();
        let added = f.publish(&Publication {
            support: vec![support(&newest.entry.listing.address, 7)],
            changes: vec![put(newest)],
            ..quiet(AT + 60)
        });
        let add = started.elapsed();
        // One of the oldest taken out: its content type's pages after it
        // move.
        let started = Instant::now();
        let removed = f.publish(&Publication {
            changes: vec![remove(address(n / 100))],
            ..quiet(AT + 120)
        });
        let take_out = started.elapsed();
        let files = f.publisher.files_bytes();
        let store = f.store.size_bytes().unwrap();
        let per_listing = (files + store) / n;
        eprintln!(
            "{n} listings: built in {build:?} ({} files, {} MB); a new one in {add:?} ({} files, {} KB); \
             an old one out in {take_out:?} ({} files, {} KB); files {} MB, store {} MB: {per_listing} B a listing",
            built.files_written,
            built.bytes_written >> 20,
            added.files_written,
            added.bytes_written >> 10,
            removed.files_written,
            removed.bytes_written >> 10,
            files >> 20,
            store >> 20,
        );
        // Work follows what changed: a new listing writes its address and
        // name shards, its content type's last page and index, its time
        // page, the open feed segment, status.json, pages.json,
        // feed/index.json and head.json.
        assert!(added.files_written <= 12, "{added:?}");
        assert!(add < build / 10, "{add:?} against {build:?}");
        assert!(take_out < build / 4, "{take_out:?} against {build:?}");
        // The plan's estimate of the producer's whole disk is 11.5 KB a
        // listing; the published index is part of it.
        assert!(per_listing < 11_500, "{per_listing} B a listing");
    }

    #[test]
    fn size_and_time_at_a_hundred_thousand_listings() {
        size_and_time(100_000);
    }

    #[test]
    #[ignore = "writes about 6 GB and takes minutes: run it on its own, in release"]
    fn size_and_time_at_a_million_listings() {
        size_and_time(1_000_000);
    }
}
