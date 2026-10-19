//! Publishing the listings index as the files of `listings/v1/`, exactly as
//! `docs/listings-v1.md` specifies them (types and layout rules in
//! [`listings_v1`](super::listings_v1)).
//!
//! The [`Publisher`] keeps the published index in the producer's store, in
//! databases named [`PUBLISH`]`…`: each entry by address with its data map,
//! its place in key order, by name and by content type, each listed
//! address's support, the rejected and deferred listings, and the feed of
//! numbered changes with its epoch. Each cycle the producer hands it what
//! changed ([`Publication`]). The publisher numbers the changes in the feed
//! and writes the files they touch:
//!
//! - each file only when its bytes change, whole (written beside it, then
//!   renamed over it), with `.gz` and `.zst` copies of the same bytes;
//! - the files a change touches first, then `pages.json`,
//!   `feed/index.json`, and `head.json` last, so a file is written only
//!   after every file it names is in place;
//! - every prefix's shard files, empty or not;
//! - support files at most every
//!   [`SUPPORT_INTERVAL`](super::listings_v1::SUPPORT_INTERVAL);
//! - `status.json` every cycle, and `rejected.json` when it changes;
//! - time pages that `pages.json` no longer lists are deleted
//!   [`SUPERSEDED_KEPT`](super::listings_v1::SUPERSEDED_KEPT) later.
//!
//! There is no hide list: every listed entry is published.

use std::path::{Path, PathBuf};

use ant_listings::ListingKey;
use ant_protocol::XorName;
use heed::byteorder::BigEndian;
use heed::types::{Str, U64};
use heed::Database;

use super::listings_store::{store_error, ListingsStore};
use super::listings_v1::{new_epoch, RejectedEntry, RemoveReason, ShardEntry, Status, Support};
use crate::data::error::{Error, Result};

#[cfg(doc)]
use super::{listings_store::PUBLISH, listings_v1::Head};

/// The publisher's position in its feed: its epoch, as text.
pub const META_TEXT_DB: &str = "publish_meta_text";

/// The publisher's position in its feed: its latest record's number and the
/// count of entries.
pub const META_NUMBERS_DB: &str = "publish_meta_numbers";

/// The key of the epoch in [`META_TEXT_DB`].
const EPOCH: &str = "epoch";

/// The key of the latest record's number in [`META_NUMBERS_DB`].
const SEQ: &str = "seq";

/// The key of the number of entries in [`META_NUMBERS_DB`].
const COUNT: &str = "count";

/// What one cycle changed, for the [`Publisher`] to publish.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Publication {
    /// When the cycle (or the push it handled) began, in Unix seconds: the
    /// `at` of the feed records it makes.
    pub at: u64,
    /// Changes to the index, in the order they were decided; each becomes
    /// one record of the feed, numbered in this order.
    pub changes: Vec<IndexChange>,
    /// The support of listed addresses that changed, one per address. An
    /// address removed from the index loses its support with it.
    pub support: Vec<Support>,
    /// Changes to `rejected.json`: each address's latest rejection or
    /// deferral, or none once it is listed or no longer served.
    pub rejected: Vec<RejectedChange>,
    /// How the producer is doing, for `status.json`. The publisher fills in
    /// `epoch`, `seq`, `count` and `generated_at`, and
    /// `resources.files_bytes` where it is `None`; the rest is written as
    /// given.
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
    out_dir: PathBuf,
    store: ListingsStore,
    meta_text: Database<Str, Str>,
    meta_numbers: Database<Str, U64<BigEndian>>,
    epoch: String,
    seq: u64,
    count: u64,
}

impl Publisher {
    /// The publisher of the files in `out_dir` (the `listings/v1/`
    /// directory itself), keeping the published index in `store`. The
    /// first time, it starts a feed under a new epoch ([`new_epoch`]), with
    /// no records and no entries.
    ///
    /// # Errors
    ///
    /// If `out_dir` can't be created, or the store can't be read or
    /// written.
    pub fn open(out_dir: &Path, store: &ListingsStore) -> Result<Self> {
        std::fs::create_dir_all(out_dir).map_err(|e| {
            Error::Storage(format!(
                "could not create the listings directory {}: {e}",
                out_dir.display()
            ))
        })?;
        let meta_text: Database<Str, Str> = store.database(META_TEXT_DB)?;
        let meta_numbers: Database<Str, U64<BigEndian>> = store.database(META_NUMBERS_DB)?;
        let mut txn = store.env().write_txn().map_err(store_error)?;
        let epoch = match meta_text.get(&txn, EPOCH).map_err(store_error)? {
            Some(epoch) => epoch.to_string(),
            None => {
                let epoch = new_epoch();
                meta_text
                    .put(&mut txn, EPOCH, &epoch)
                    .map_err(store_error)?;
                epoch
            }
        };
        let seq = meta_numbers
            .get(&txn, SEQ)
            .map_err(store_error)?
            .unwrap_or(0);
        let count = meta_numbers
            .get(&txn, COUNT)
            .map_err(store_error)?
            .unwrap_or(0);
        txn.commit().map_err(store_error)?;
        Ok(Self {
            out_dir: out_dir.to_path_buf(),
            store: store.clone(),
            meta_text,
            meta_numbers,
            epoch,
            seq,
            count,
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
    /// If the store or a file can't be written.
    pub fn publish(&mut self, publication: &Publication) -> Result<Published> {
        let _ = (
            publication,
            &self.store,
            &self.meta_text,
            &self.meta_numbers,
        );
        todo!("number the changes and write the files of listings/v1")
    }

    /// The published entry for `address`, with its data map, if it is
    /// listed.
    ///
    /// # Errors
    ///
    /// If the store can't be read.
    pub fn entry(&self, address: &XorName) -> Result<Option<ShardEntry>> {
        let _ = address;
        todo!("read the published entry")
    }

    /// The directory the files are published in.
    #[must_use]
    pub fn out_dir(&self) -> &Path {
        &self.out_dir
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
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MAP: usize = 16 * 1024 * 1024;

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
}
